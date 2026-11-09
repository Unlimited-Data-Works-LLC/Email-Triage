"""Pin: CI on the self-hosted runner installs from hashed locks, not from PyPI unpinned (punch 511).

Why this exists. The unit job ran ``pip install -e '.[dev,encryption]'`` on the
self-hosted runner, which shares a host with production. ``requirements.lock``
does not compile the dev extra, so pytest, pytest-asyncio, pytest-xdist, httpx,
httpx2, filelock, anyio, markdown-it-py and sqlcipher3 resolved from PyPI at
whatever version was newest, with no hash. A hostile release of any of them
would run as the runner user on that host before any test asserts. The job now
installs ``requirements-dev.lock`` (written by scripts/regen-lock.sh alongside
``requirements.lock``) with ``--require-hashes``, then the project with
``--no-deps``.

INVARIANTS (count-agnostic, over every lock entry / every workflow job / every
``pip install`` command):
  D1  every package ``requirements.lock`` pins, ``requirements-dev.lock`` pins
      at the SAME version: the unit job tests what the image ships;
  D2  each CI lock's header compiled EXACTLY the extras the regen script names
      for it (the dev lock: ``EXTRAS`` plus ``DEV_EXTRAS``; the CI tools lock:
      ``CI_EXTRAS``, panel O F5; none missing, none added), so the lock and its
      generator agree;
  D3  each CI lock carries ``--only-binary :all:``, so the CI install never
      builds an sdist (the regen script resolves both that way);
  F1  every ``pip install`` in every workflow job, on ANY runner (punch 623/622,
      N-607 residuals a and b: it read self-hosted jobs only and excused ten
      unhashed bootstrap and extras installs by name), is one of: an install of
      hashed locks only (``--require-hashes`` and every ``-r`` file is a repo
      lock whose every entry carries a hash, with no other requirement on the
      line); or a ``--no-deps`` install of the local tree with no extras. There
      is no residual list: pip, setuptools, pip-audit and cyclonedx-bom come from
      requirements-ci-tools.lock, the e2e extra from requirements-dev.lock.
  F2  every command that fetches something without a pip install, is in
      ``_NON_PIP_FETCHES`` keyed on (workflow, job, exact command) with the
      reason hashing is impossible there or how the fetch is verified, and every
      entry still matches a live command. Editing an entry's command makes it a
      new violation. A fetch is ``<tool> install`` (``playwright install``,
      ``npm install``, ``apt-get install``, ...), a download (``curl``,
      ``wget``, so ``curl ... | sh`` too), or an installer with no ``install``
      word (``pip-sync``, ``uv sync``, ``uv pip sync``, ``easy_install``,
      ``npm ci``). Panel O F2: it saw only the first shape.
  C1  every package requirements-ci-tools.lock and requirements-dev.lock both
      pin, they pin at the SAME version, and the tools lock's pip is the image's
      pip (requirements-pip.txt): the scan installs the tools lock with
      ``--no-deps`` beside the dev lock, so a differing version would move an
      audited package, and CI would bootstrap a pip the image does not ship.
  F3  on ANY runner, no ``pip install`` names the ``encryption`` extra or
      ``sqlcipher3`` (or ``sqlcipher3-binary``): the SQLCipher binding CI tests
      comes only from the hashed dev lock, which must carry a hashed entry for it
      (panel-B DA C2). No residual exists for F3.
  R1  scripts/regen-lock.sh hands each resolve only the extra args
      ``lock_reader.route_regen_args`` routes to it: the image resolve the
      ``both`` list, the dev resolve ``both`` plus the dev-only list, the CI tools
      resolve the shared list (every arg that names no package, ``--upgrade``
      included, which reaches all three) plus the tools-only list. An upgrade of
      a package the image lock does
      not pin reaches the dev resolve alone (punch 629 fold, db F2a fix 6:
      ``-P pytest==9.0.3`` sent to both put pytest in the image lock), and one of
      a package in neither the image nor the dev lock reaches the CI tools
      resolve alone (panel O F4: ``-P pip-audit==2.11.0`` put pip-audit in the
      dev lock, and a dev-only ``-P pytest==`` reached the tools lock). Static
      over the script text, since CI cannot run podman; the routing itself is
      checked through the same CLI the script calls.

Hash-pinned (D-lock) properties shared with ``requirements.lock`` — every entry
hashed, ``--generate-hashes`` in the header, the ``# resolved-for:`` provenance
— are checked for EVERY repo-root lock by the N-545 pin, and the pyproject
floors by the N-542 pin. They are not re-implemented here (PD-5).

SCOPE CAVEAT. F1 and F2 read the ``run:`` text of workflow steps under
``.github/workflows`` only: a local composite action's steps
(``.github/actions/*/action.yml`` ``runs.steps[].run``) would go unseen (none exist
today). They do not
see a script a step calls that installs on its own, an action's own installs
(``setup-python``'s cache), an install inside a quoted shell string
(``sh -c "pip install ..."``, ``bash -c``: the quoted command is one token to the
tokenizer), or a fetch spelled with none of the words F2 names (``gh release
download``, ``git clone``, ``docker pull``, ``yarn``, ``pnpm``). F2 names a fetch; it
does not check that a named one is verified: that is the reason text, read by a
reviewer. The ``--no-deps`` local-tree allowance does not see the build
backend: ``pip install --no-deps -e .`` without ``--no-build-isolation`` still
fetches ``[build-system].requires`` (setuptools) into an isolated build env
unhashed. security.yml builds with the tools lock's hashed setuptools (panel O
F3); the unhashed fetch survives in tests.yml and e2e.yml (and, outside the
workflows, Containerfile.test). Those are register N-607 residuals.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys

import pytest

from _ci_requirement_cuts import derived_requirement_sources  # the one reader of a cut lock (G3)
from _pin_harness import _FULL_DEV_TREE, REPO_ROOT, load_repo_script, workflow_texts

#: THE lock parser (PD-5).
drift = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")

_LOCK = REPO_ROOT / "requirements.lock"
_DEV_LOCK = REPO_ROOT / "requirements-dev.lock"
_REGEN = REPO_ROOT / "scripts" / "regen-lock.sh"
_WORKFLOWS = REPO_ROOT / ".github" / "workflows"

_TOOLS_LOCK = REPO_ROOT / "requirements-ci-tools.lock"
#: The image's own hash-pinned pip (N-621); CI bootstraps the same version (C1).
_PIP_PIN = REPO_ROOT / "requirements-pip.txt"

# Fetches that do not go through a pip install, so no lock can hash them (F2).
# Keyed on (workflow, job, exact command); each says why hashing is impossible
# there, or how the fetched bytes are verified instead. Editing a command makes it
# a new violation; fixing one means deleting it.
_NON_PIP_FETCHES: dict[tuple[str, str, str], str] = {
    (".github/workflows/e2e.yml", "e2e", "python -m playwright install chromium"):
        "Playwright's browser download: a Chromium build the playwright package fetches from its "
        "own CDN, outside pip's hash model (not a pip install). The playwright wheel that runs it "
        "comes hashed from requirements-dev.lock and names the browser build it fetches",
    (".github/workflows/release.yml", "release-tarball-asset",
     "sudo apt-get install -y --no-install-recommends zstd"):
        "a distro package on the GitHub-hosted Ubuntu runner, from Ubuntu's archive, which apt "
        "verifies against the archive's signing keys; not a pip install, so no lock can hash it",
}
#: The one fetch F2 names in a workflow that does not ship (operator-attest.yml, an
#: operator-only gate per scripts/publish-allow.txt). It is not in _NON_PIP_FETCHES,
#: whose every entry must be live on the public mirror too; it is matched by
#: _is_the_crane_fallback and held live on the full dev tree by its own test.
_CRANE_FETCH = ("curl -fsSL -o /tmp/crane.tgz https://github.com/google/go-containerregistry/releases/"
                "download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz")


def _is_the_crane_fallback(fetch: tuple[str, str, str]) -> bool:
    """The crane fallback in operator-attest.yml, downloaded and then run: version and sha256
    pinned, verified by sha256sum -c before the tar is opened (panel O F1); the release's SLSA
    provenance is not verified. An edited command is a new violation."""
    workflow, job, command = fetch
    return workflow == ".github/workflows/operator-attest.yml" and job == "attest" and command == _CRANE_FETCH


#: The publisher's sha256 for _CRANE_FETCH's tarball (v0.22.1 checksums.txt).
_CRANE_SHA256 = "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0"


def _crane_check_violations(run: str) -> list[str]:
    """The excuse above names the download only; this reads the verification it relies on
    (panel O round 3 DA): `echo "<pinned hex>  /tmp/crane.tgz" | sha256sum -c -`, an
    `exit 1` arm, both BEFORE the `tar -xzf /tmp/crane.tgz` that opens it."""
    segs = [s for s in _segments(run) if s]

    def first(pred) -> int | None:
        return next((i for i, s in enumerate(segs) if pred(s)), None)

    check = first(lambda s: s[0] == "echo" and len(s) == 2 and s[1].split() == [_CRANE_SHA256, "/tmp/crane.tgz"])
    tar = first(lambda s: s[0] == "tar" and "/tmp/crane.tgz" in s)
    if tar is None:
        return ["no `tar` opens /tmp/crane.tgz: the reader is blind"]
    if check is None or check + 1 >= len(segs) or segs[check + 1][:3] != ["sha256sum", "-c", "-"]:
        return ["no `sha256sum -c` of /tmp/crane.tgz against the pinned sha256"]
    if check > tar:
        return ["the sha256 check runs after the tar opens /tmp/crane.tgz"]
    if not any(s[:2] == ["exit", "1"] for s in segs[check + 2 : tar]):
        return ["a failed sha256 check has no `exit 1` arm before the tar"]
    return []

# pip install options that consume the next token as their value.
_VALUE_OPTS = frozenset({
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "--root-user-action", "-t", "--target",
    "--prefix", "--root", "--platform", "--python-version", "--implementation", "--abi",
    "--only-binary", "--no-binary", "--progress-bar", "--cache-dir", "--src",
    "--upgrade-strategy", "--report", "--config-settings", "-C", "--global-option", "--log",
    "--trusted-host", "--proxy", "--retries", "--timeout", "--exists-action", "--cert",
    "--client-cert", "--use-feature", "--use-deprecated", "--python",
})
_LOCAL_TREE = frozenset({".", "./"})
_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\|")


# --- the dev lock against the prod lock and its generator -------------------------


def _all_pins(lock_text: str) -> dict[str, str | None]:
    """canonical name -> version for every entry, marker-gated or not."""
    locked = drift.parse_lock(lock_text, None)
    out: dict[str, str | None] = dict(locked.pins)
    # parse_lock(None) puts marker-gated entries in ``unevaluated`` without a
    # version; read their version from the raw line so they are compared too.
    for line in lock_text.splitlines():
        m = drift._REQ_RE.match(line.rstrip(" " + chr(92)))
        if m and drift.canonical(m.group("name")) not in out:
            out[drift.canonical(m.group("name"))] = m.group("version")
    return out


def _shared_pin_drift(prod_text: str, dev_text: str) -> list[str]:
    """D1."""
    prod, dev = _all_pins(prod_text), _all_pins(dev_text)
    return [
        f"{name}: requirements.lock pins {ver}, requirements-dev.lock {dev.get(name) or 'does not pin it'}"
        for name, ver in sorted(prod.items())
        if dev.get(name) != ver
    ]


def _regen_extras(regen_text: str, variables: tuple[str, ...] = ("EXTRAS", "DEV_EXTRAS")) -> frozenset[str]:
    """The extras the regen script compiles into the dev lock: EXTRAS + DEV_EXTRAS.
    ``("EXTRAS",)`` is what it compiles into the image lock (the one reader of both,
    also used by test_lock_pins_are_reachable_from_pyproject_pin.py)."""
    out: set[str] = set()
    for var in variables:
        m = re.search(rf'^{var}="([^"]*)"', regen_text, re.M)
        assert m, f"scripts/regen-lock.sh has no {var}= line; the scanner is blind"
        out.update(e.split("=", 1)[1] for e in m.group(1).split() if e.startswith("--extra="))
    return frozenset(out)


#: Each CI lock and the regen-script variables naming the extras it compiles (D2, D3).
#: Panel O F5: the check covered the dev lock only, so the tools lock's extras and
#: its ``--only-binary :all:`` were unpinned.
_HEADER_EXTRAS: dict[str, tuple[str, ...]] = {
    "requirements-dev.lock": ("EXTRAS", "DEV_EXTRAS"),
    "requirements-ci-tools.lock": ("CI_EXTRAS",),
}


def _header_violations(lock_name: str, lock_text: str, regen_text: str) -> list[str]:
    """D2, D3 for one CI lock."""
    out = []
    want, got = _regen_extras(regen_text, _HEADER_EXTRAS[lock_name]), drift.header_extras(lock_text)
    if want - got:
        out.append(f"{lock_name} never compiled extras {sorted(want - got)} that scripts/regen-lock.sh names")
    if got - want:
        out.append(f"{lock_name} compiled extras {sorted(got - want)} that scripts/regen-lock.sh does not name")
    body = [ln.strip() for ln in lock_text.splitlines() if ln.strip() and not ln.startswith("#")]
    if "--only-binary :all:" not in body:
        out.append(f"{lock_name} does not carry --only-binary :all:")
    return out


def _dev_header_violations(dev_text: str, regen_text: str) -> list[str]:
    return _header_violations("requirements-dev.lock", dev_text, regen_text)


# --- F1: the CI install fence -------------------------------------------------------


# `pip`, `pip3`, `pip3.12`, ... (also the `pip` of `python -m pip`); never `pip-audit`.
_PIP_LAUNCHER = re.compile(r"pip(\d[\d.]*)?")
# pip subcommands that are not `install`: a launcher followed by one of these is not an install.
_PIP_OTHER_COMMANDS = frozenset({
    "download", "uninstall", "freeze", "inspect", "list", "show", "check", "config", "search",
    "cache", "index", "wheel", "hash", "completion", "debug", "help", "lock",
})


def _segments(run: str):
    """The shell-tokenized segments of a step's ``run:`` text (continuations joined,
    comment lines dropped, split on ``&&``, ``||``, ``;`` and ``|``)."""
    for line in run.replace(chr(92) + chr(10), " ").splitlines():
        if line.lstrip().startswith("#"):
            continue
        for seg in _SEGMENT_SPLIT.split(line):
            try:
                yield shlex.split(seg, comments=True)
            except ValueError:
                yield seg.split()


def _install_index(toks: list[str], start: int) -> int | None:
    """Index of the ``install`` that the pip launcher at ``start - 1`` runs, or None.
    Global options may sit between them (``pip -q install``, ``pip --log f install``);
    an unknown word is read as an option's value and skipped, so an option this list
    does not know cannot hide an install (fail closed)."""
    j = start
    while j < len(toks):
        tok = toks[j]
        if tok == "install":
            return j
        if tok in _PIP_OTHER_COMMANDS:
            return None
        j += 2 if (tok in _VALUE_OPTS and "=" not in tok) else 1
    return None


def _is_pip_launcher(tok: str) -> bool:
    name = tok.rsplit("/", 1)[-1]
    # `python -mpip install` (the -m attached to its module) is the same launcher
    return bool(_PIP_LAUNCHER.fullmatch(name[2:] if name.startswith("-m") else name))


def _pip_install_commands(run: str) -> list[tuple[list[str], list[str]]]:
    """(tokens before ``install``, arguments after it) for every ``pip install`` in a
    step's ``run:`` text, one per shell segment."""
    found = []
    for toks in _segments(run):
        for i, tok in enumerate(toks):
            if _is_pip_launcher(tok):
                k = _install_index(toks, i + 1)
                if k is not None:
                    found.append((toks[:k], toks[k + 1 :]))
                    break
    return found


def _pip_installs(run: str) -> list[list[str]]:
    """The argument list of every ``pip install`` command in a step's ``run:`` text, a
    ``$RUNNER_TEMP`` requirement file read back to the repo lock it was cut from."""
    derived = derived_requirement_sources(run)
    return [[derived.get(a, a) for a in args] for _, args in _pip_install_commands(run)]


def _venv_dirs(run: str) -> set[str]:
    """Every directory a ``python -m venv <dir>`` in a step's ``run:`` text creates."""
    out = set()
    for toks in _segments(run):
        for i in range(len(toks) - 2):
            if toks[i] == "-m" and toks[i + 1] == "venv":
                out.update(t.rstrip("/") for t in toks[i + 2 :] if not t.startswith("-"))
                break
    return out


def _hashed_lock(name: str) -> bool:
    path = REPO_ROOT / name
    if path.parent != REPO_ROOT or not path.is_file():
        return False
    try:
        counts = drift.parse_lock(path.read_text(encoding="utf-8"), None).hash_counts
    except drift.LockParseError:
        return False  # not a lock at all (fail closed)
    return bool(counts) and all(n >= 1 for n in counts.values())


def _split_install_args(args: list[str]) -> tuple[set[str], list[str], list[str]]:
    """(flags, requirement files, specs incl. ``-e`` values) of one ``pip install``."""
    flags, reqfiles, specs = set(), [], []
    it = iter(args)
    for tok in it:
        if tok.startswith("--") and "=" in tok:
            opt, val = tok.split("=", 1)
            flags.add(opt)
            if opt == "--requirement":
                reqfiles.append(val)
            elif opt == "--editable":
                specs.append(val)
            continue
        if tok.startswith("-"):
            flags.add(tok)
            if tok in _VALUE_OPTS:
                val = next(it, "")
                if tok in ("-r", "--requirement"):
                    reqfiles.append(val)
                elif tok in ("-e", "--editable"):
                    specs.append(val)
            continue
        specs.append(tok)
    return flags, reqfiles, specs


def _install_is_safe(args: list[str]) -> bool:
    flags, reqfiles, specs = _split_install_args(args)
    if reqfiles and not specs:
        return "--require-hashes" in flags and all(_hashed_lock(f) for f in reqfiles)
    if specs and not reqfiles:
        return "--no-deps" in flags and all(s in _LOCAL_TREE for s in specs)
    return False


def _job_runs(workflow_texts: dict[str, str], *, self_hosted_only: bool = False):
    """(workflow, job, ``run:`` text) for every step of every job."""
    import yaml

    for name, text in sorted(workflow_texts.items()):
        jobs = (yaml.safe_load(text) or {}).get("jobs") or {}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on")
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            if self_hosted_only and "self-hosted" not in labels:
                continue
            for step in job.get("steps") or []:
                yield name, job_id, str(step.get("run", ""))


def _job_installs(workflow_texts: dict[str, str], *, self_hosted_only: bool):
    """(workflow, job, install args) for every ``pip install`` in every job."""
    for name, job_id, run in _job_runs(workflow_texts, self_hosted_only=self_hosted_only):
        for args in _pip_installs(run):
            yield name, job_id, args


def _unsafe_installs(workflow_texts: dict[str, str]) -> list[tuple[str, str, str]]:
    """F1: (workflow, job, ``pip install <args>``) for every unsafe install, on any runner."""
    return [
        (name, job_id, " ".join(["pip", "install", *args]))
        for name, job_id, args in _job_installs(workflow_texts, self_hosted_only=False)
        if not _install_is_safe(args)
    ]


# Commands that fetch with no ``install`` word (panel O F2), matched on a token's
# base name anywhere in the segment, so ``sudo curl`` and ``"$V/bin/pip-sync"`` count.
_FETCH_COMMANDS = frozenset({"curl", "wget", "pip-sync", "easy_install"})


def _is_fetch(toks: list[str]) -> bool:
    names = [t.rsplit("/", 1)[-1] for t in toks]
    if any(n in _FETCH_COMMANDS for n in names):
        return True
    # `uv sync` and `uv pip sync`: the `pip` token reads as a pip launcher, and F1
    # sees only `install`, so neither arm saw them before. `npm ci` installs with no
    # `install` word either (panel O round 2).
    for tool, sub in (("uv", "sync"), ("npm", "ci")):
        if tool in names and sub in names[names.index(tool) + 1 :]:
            return True
    return "install" in toks[1:] and not any(_is_pip_launcher(t) for t in toks)


def _non_pip_fetches(workflow_texts: dict[str, str]) -> list[tuple[str, str, str]]:
    """F2: (workflow, job, command) for every fetch that is not a pip install."""
    out = []
    for name, job_id, run in _job_runs(workflow_texts):
        for toks in _segments(run):
            if _is_fetch(toks):
                out.append((name, job_id, " ".join(toks)))
    return out


# --- F3: the SQLCipher binding comes only from a hashed lock, on ANY runner ---------
# Panel-B DA C2: CI installed the PyPI sqlcipher3 wheel unhashed through the
# `encryption` extra. requirements-dev.lock now carries it hashed and wheel-only,
# so no CI install on any runner (GitHub-hosted included, which F1 does not fence)
# may name the encryption extra or the binding itself.

_ENCRYPTION_EXTRA = "encryption"
_EXTRAS_RE = re.compile(r"\[([^\]]*)\]")


def _names_the_binding(spec: str) -> bool:
    if _ENCRYPTION_EXTRA in {x.strip().lower() for m in _EXTRAS_RE.finditer(spec) for x in m.group(1).split(",")}:
        return True
    return drift.canonical(re.split(r"[\[<>=!~;@ ]", spec, maxsplit=1)[0]).startswith("sqlcipher3")


def _unlocked_binding_installs(workflow_texts: dict[str, str]) -> list[tuple[str, str, str]]:
    """(workflow, job, ``pip install <args>``) for every install, on any runner, that
    takes the encryption extra or sqlcipher3 from anywhere but a hashed lock."""
    return [
        (name, job_id, " ".join(["pip", "install", *args]))
        for name, job_id, args in _job_installs(workflow_texts, self_hosted_only=False)
        if any(_names_the_binding(s) for s in _split_install_args(args)[2])
    ]


def _real_workflows() -> dict[str, str]:
    return workflow_texts(_WORKFLOWS)


def _texts():
    return (
        _LOCK.read_text(encoding="utf-8"),
        _DEV_LOCK.read_text(encoding="utf-8"),
        _REGEN.read_text(encoding="utf-8"),
    )


# --- the invariants on the real tree ------------------------------------------------


def test_d1_the_dev_lock_pins_every_prod_package_at_the_prod_version() -> None:
    prod, dev, _ = _texts()
    assert _all_pins(prod), "read no pins from requirements.lock; the parser is blind"
    assert _shared_pin_drift(prod, dev) == [], "Regenerate both locks with scripts/regen-lock.sh."


@pytest.mark.parametrize("lock_name", sorted(_HEADER_EXTRAS))
def test_d2_d3_each_ci_lock_matches_its_generator(lock_name) -> None:
    _, _, regen = _texts()
    text = (REPO_ROOT / lock_name).read_text(encoding="utf-8")
    assert drift.header_extras(text), f"read no extras from the {lock_name} header; the reader is blind"
    assert _header_violations(lock_name, text, regen) == [], "Regenerate the locks with scripts/regen-lock.sh."


def test_f1_every_pip_install_on_any_runner_is_hash_locked() -> None:
    workflows = _real_workflows()
    assert any(_pip_installs(t) for t in workflows.values()), "found no pip install in any workflow; the scanner is blind"
    assert _unsafe_installs(workflows) == [], (
        "a CI job installs from PyPI without hashes. Install a hashed lock with --require-hashes "
        "(requirements-dev.lock for test and e2e tooling, requirements-ci-tools.lock for pip, "
        "setuptools, pip-audit and cyclonedx-bom), then the project with --no-deps."
    )


def test_f2_every_non_pip_fetch_is_named_with_a_reason_and_every_entry_is_live() -> None:
    assert all(reason.strip() for reason in _NON_PIP_FETCHES.values())
    live = _non_pip_fetches(_real_workflows())
    assert [v for v in live if v not in _NON_PIP_FETCHES and not _is_the_crane_fallback(v)] == [], (
        "a CI step installs something outside pip. Install it from a hashed lock, or name it in "
        "_NON_PIP_FETCHES with the reason hashing is impossible there."
    )
    assert sorted(set(_NON_PIP_FETCHES) - set(live)) == [], (
        "a _NON_PIP_FETCHES command no longer runs; delete its entry")


@pytest.mark.skipif(not _FULL_DEV_TREE, reason="operator-attest.yml does not ship; the crane fallback "
                    "exists on the full dev tree only")
def test_f2_the_crane_fallback_is_live_and_an_edited_one_is_not_excused() -> None:
    crane = [v for v in _non_pip_fetches(_real_workflows()) if _is_the_crane_fallback(v)]
    assert len(crane) == 1, "the pinned crane fallback no longer runs; delete _CRANE_FETCH"
    workflow, job, command = crane[0]
    assert not _is_the_crane_fallback((workflow, job, command + " --insecure"))
    assert not _is_the_crane_fallback((workflow, job, command.replace("v0.22.1", "latest")))
    assert not _is_the_crane_fallback((workflow, "other-job", command))
    assert not _is_the_crane_fallback(("wf.yml", job, command))
    runs = [run for wf, j, run in _job_runs(_real_workflows()) if _is_the_crane_fallback((wf, j, _CRANE_FETCH))
            and _CRANE_FETCH in " ".join(" ".join(s) for s in _segments(run))]
    assert len(runs) == 1, "the step that downloads crane was not found"
    assert _crane_check_violations(runs[0]) == [], "the crane download is no longer verified before it runs"


_GOOD_CRANE_RUN = chr(10).join([
    "curl -fsSL -o /tmp/crane.tgz https://example.invalid/crane.tgz",
    f'echo "{_CRANE_SHA256}  /tmp/crane.tgz" | sha256sum -c - ' + chr(92),
    '  || { echo "mismatch" >&2; exit 1; }',
    "mkdir -p /tmp/crane && tar -xzf /tmp/crane.tgz -C /tmp/crane",
])


def test_teeth_the_crane_check_is_read_in_order() -> None:
    assert _crane_check_violations(_GOOD_CRANE_RUN) == []
    lines = _GOOD_CRANE_RUN.split(chr(10))
    deleted = chr(10).join([lines[0], lines[3]])
    moved = chr(10).join([lines[0], lines[3], lines[1], lines[2]])
    other_hex = _GOOD_CRANE_RUN.replace(_CRANE_SHA256, "1" * 64)
    no_exit = _GOOD_CRANE_RUN.replace("exit 1", "true")
    for bad in (deleted, moved, other_hex, no_exit):
        assert _crane_check_violations(bad), bad


def _cross_lock_drift(tools_text: str, dev_text: str) -> list[str]:
    """C1: packages both locks pin, at different versions."""
    tools, dev = _all_pins(tools_text), _all_pins(dev_text)
    return [
        f"{name}: requirements-ci-tools.lock pins {tools[name]}, requirements-dev.lock {dev[name]}"
        for name in sorted(set(tools) & set(dev))
        if tools[name] != dev[name]
    ]


def _image_pip(pip_pin_text: str) -> str | None:
    for line in pip_pin_text.splitlines():
        m = drift._REQ_RE.match(line.rstrip(" " + chr(92)))
        if m and drift.canonical(m.group("name")) == "pip":
            return m.group("version")
    return None


def test_c1_the_tools_lock_agrees_with_the_dev_lock_and_the_image_pip() -> None:
    tools = _TOOLS_LOCK.read_text(encoding="utf-8")
    _, dev, _ = _texts()
    pins = _all_pins(tools)
    assert {"pip", "setuptools", "pip-audit", "cyclonedx-bom"} <= set(pins), (
        f"requirements-ci-tools.lock lacks a CI tool; it pins {sorted(pins)}")
    assert set(pins) & set(_all_pins(dev)) - {"pip", "setuptools"}, (
        "the tools lock shares no package with the dev lock; the comparison would be vacuous")
    assert _cross_lock_drift(tools, dev) == [], "Regenerate the locks with scripts/regen-lock.sh."
    image_pip = _image_pip(_PIP_PIN.read_text(encoding="utf-8"))
    assert image_pip, "read no pip pin from requirements-pip.txt; the reader is blind"
    assert pins["pip"] == image_pip, (
        f"CI bootstraps pip {pins['pip']} from requirements-ci-tools.lock; the image ships {image_pip} "
        "(requirements-pip.txt). Raise both together.")


def test_f3_the_sqlcipher_binding_comes_only_from_a_hashed_lock_on_any_runner() -> None:
    _, dev, _ = _texts()
    locked = drift.parse_lock(dev, None)
    assert locked.hash_counts.get("sqlcipher3", 0) >= 1, (
        "requirements-dev.lock carries no hashed sqlcipher3 entry; the encryption extra has no "
        "hashed source and this property would hold vacuously")
    assert _unlocked_binding_installs(_real_workflows()) == [], (
        "a CI job installs the encryption extra or sqlcipher3 outside a hashed lock. Take it "
        "from requirements-dev.lock with --require-hashes, then the project with --no-deps.")


# --- teeth --------------------------------------------------------------------------

_NL = chr(10)


def _wf(run: str, runs_on: str = "[self-hosted, linux]") -> dict[str, str]:
    body = "jobs:" + _NL + "  j:" + _NL + f"    runs-on: {runs_on}" + _NL + "    steps:" + _NL
    body += "      - run: |" + _NL + "".join("          " + ln + _NL for ln in run.splitlines())
    return {"wf.yml": body}


def test_teeth_f1_the_old_unit_job_install_is_caught() -> None:
    old = "python -m pip install --upgrade pip" + _NL + "pip install -r requirements.lock" + _NL
    old += "pip install --no-deps -e ." + _NL + "pip install -e '.[dev,encryption]'"
    assert _unsafe_installs(_wf(old)) == [
        ("wf.yml", "j", "pip install --upgrade pip"),
        ("wf.yml", "j", "pip install -r requirements.lock"),
        ("wf.yml", "j", "pip install -e .[dev,encryption]"),
    ]


def test_teeth_f1_the_hashed_shapes_pass_and_their_near_misses_do_not() -> None:
    ok = "pip install --require-hashes -r requirements-dev.lock" + _NL + "pip install --no-deps -e ."
    assert _unsafe_installs(_wf(ok)) == []
    cont = '"$RUNNER_TEMP/v/bin/python" -m pip install --no-cache-dir ' + chr(92) + _NL
    cont += "  --require-hashes -r requirements.lock && echo done"
    assert _unsafe_installs(_wf(cont)) == [], "a continuation line or an && chain must not hide the flag"
    for bad in (
        "pip install -r requirements-dev.lock",  # no --require-hashes
        "pip install --require-hashes -r requirements-dev.lock pytest",  # a PyPI spec on the line
        "pip install --require-hashes -r no-such.lock",  # not a repo lock
        "pip install --require-hashes -r pyproject.toml",  # not a hashed lock
        "pip install -e .",  # local tree WITH dependency resolution
        "pip install --no-deps -e '.[dev]'",  # extras spec
        "pip3 install pytest",
        "true && pip install pytest",
    ):
        assert len(_unsafe_installs(_wf(bad))) == 1, bad


_CUT = "awk '/^packaging==/ {on=1} on {print}' requirements-ci-tools.lock > \"$RUNNER_TEMP/packaging.req\""
_TEMP_INSTALL = 'pip install --require-hashes --no-deps --only-binary :all: -r "$RUNNER_TEMP/packaging.req"'


def test_teeth_f1_a_temp_requirement_file_is_judged_as_the_lock_it_was_cut_from() -> None:
    # class AJ fold F2: the SME gate installs only `packaging`, cut from the hashed CI-tools lock.
    assert derived_requirement_sources(_CUT) == {"$RUNNER_TEMP/packaging.req": "requirements-ci-tools.lock"}
    assert _unsafe_installs(_wf(_CUT + _NL + _TEMP_INSTALL)) == []
    for bad in (
        _TEMP_INSTALL,  # no step cut it from a lock: an unknown file
        _CUT.replace("requirements-ci-tools.lock", "pyproject.toml") + _NL + _TEMP_INSTALL,  # cut from no lock
        _CUT.replace("requirements-ci-tools.lock", "no-such.lock") + _NL + _TEMP_INSTALL,  # not a repo lock
        "# " + _CUT + _NL + _TEMP_INSTALL,  # a comment cuts nothing
        _CUT + _NL + _TEMP_INSTALL.replace("--require-hashes ", ""),  # hash mode left implicit
        _CUT + _NL + _TEMP_INSTALL + " pytest",  # a PyPI spec on the line
    ):
        assert len(_unsafe_installs(_wf(bad))) == 1, bad


def test_teeth_f1_a_github_hosted_job_is_in_scope() -> None:
    # punch 623: F1 read self-hosted jobs only, so a hosted job could install anything.
    assert _unsafe_installs(_wf("pip install pytest", runs_on="ubuntu-latest")) == [
        ("wf.yml", "j", "pip install pytest")]


@pytest.mark.parametrize("bad", [
    "python -m pip install --upgrade pip",  # the pre-623 bootstrap, every workflow
    "python -m pip install --upgrade setuptools",
    "pip install pip-audit",
    "pip install cyclonedx-bom",
    "pip install -e '.[e2e]'",  # punch 622
    "pip install -r requirements.lock",  # hashed lock, but hash mode left implicit
])
def test_teeth_f1_each_pre_623_install_is_caught(bad) -> None:
    for runs_on in ("[self-hosted, linux]", "ubuntu-latest"):
        assert len(_unsafe_installs(_wf(bad, runs_on=runs_on))) == 1, (runs_on, bad)


def test_teeth_f2_a_non_pip_install_is_seen_and_an_edited_entry_is_new() -> None:
    for cmd in ("python -m playwright install chromium", "npm install left-pad",
                "sudo apt-get -y install curl", "playwright install --with-deps"):
        assert _non_pip_fetches(_wf(cmd)) == [("wf.yml", "j", cmd)], cmd
    for ok in ("pip install --require-hashes -r requirements-dev.lock", "echo done", "make test"):
        assert _non_pip_fetches(_wf(ok)) == [], ok
    for wf, job, cmd in _NON_PIP_FETCHES:
        edited = _non_pip_fetches({wf: _wf(cmd + " firefox")["wf.yml"].replace("  j:", f"  {job}:")})
        assert edited == [(wf, job, cmd + " firefox")] and edited[0] not in _NON_PIP_FETCHES, cmd


# Panel O F2: each shape fetched with no `install` word and passed F2 unseen.
@pytest.mark.parametrize("cmd, seen", [
    ("curl -fsSL -o /tmp/x.tgz https://example.invalid/x.tgz", "curl -fsSL -o /tmp/x.tgz https://example.invalid/x.tgz"),
    ("sudo curl -sSLO https://example.invalid/x", "sudo curl -sSLO https://example.invalid/x"),
    ("curl -sSL https://example.invalid/i.sh | sh", "curl -sSL https://example.invalid/i.sh"),
    ("wget -q https://example.invalid/x.tgz", "wget -q https://example.invalid/x.tgz"),
    ("pip-sync requirements.txt", "pip-sync requirements.txt"),
    ('"$V/bin/pip-sync" requirements.txt', "$V/bin/pip-sync requirements.txt"),
    ("uv sync --frozen", "uv sync --frozen"),
    ("uv pip sync requirements.txt", "uv pip sync requirements.txt"),
    ("easy_install evil", "easy_install evil"),
    ("npm ci", "npm ci"),
    ("npm ci --ignore-scripts", "npm ci --ignore-scripts"),
])
def test_teeth_f2_a_fetch_with_no_install_word_is_seen(cmd, seen) -> None:
    for runs_on in ("[self-hosted, linux]", "ubuntu-latest"):
        assert _non_pip_fetches(_wf(cmd, runs_on=runs_on)) == [("wf.yml", "j", seen)], (runs_on, cmd)


@pytest.mark.parametrize("ok", ["uv --version", "echo synced", "python -m pip download x", "make sync",
                                "npm --version", "make ci"])
def test_teeth_f2_the_widened_arm_does_not_read_other_words_as_fetches(ok) -> None:
    assert _non_pip_fetches(_wf(ok)) == [], ok


def test_teeth_c1_a_tools_pin_that_moves_an_audited_package_is_caught() -> None:
    tools = _TOOLS_LOCK.read_text(encoding="utf-8")
    _, dev, _ = _texts()
    shared = sorted(set(_all_pins(tools)) & set(_all_pins(dev)) - {"pip", "setuptools"})[0]
    ver = _all_pins(tools)[shared]
    entry = next(ln for ln in tools.splitlines()
                 if drift.canonical(re.split(r"[=\[ ;]", ln, maxsplit=1)[0]) == shared and "==" in ln)
    moved = tools.replace(entry, entry.replace(f"=={ver}", "==0.0.0.dev0"), 1)
    assert _cross_lock_drift(moved, dev) == [
        f"{shared}: requirements-ci-tools.lock pins 0.0.0.dev0, requirements-dev.lock {ver}"]
    assert _image_pip("pip==1.0 \\\n    --hash=sha256:" + "0" * 64 + "\n") == "1.0"


def test_teeth_d1_a_shared_pin_that_drifts_or_goes_missing_is_caught() -> None:
    prod, dev, _ = _texts()
    name, ver = next((n, v) for n, v in drift.parse_lock(prod, None).pins.items())
    entry = next(ln for ln in dev.splitlines() if drift.canonical(re.split(r"[=\[ ;]", ln, maxsplit=1)[0]) == name and "==" in ln)
    bumped = dev.replace(entry, entry.replace(f"=={ver}", "==0.0.0.dev0"), 1)
    assert _shared_pin_drift(prod, bumped) == [f"{name}: requirements.lock pins {ver}, requirements-dev.lock 0.0.0.dev0"]
    dropped = dev.replace(entry, "# dropped", 1)
    assert _shared_pin_drift(prod, dropped) == [f"{name}: requirements.lock pins {ver}, requirements-dev.lock does not pin it"]


def test_teeth_d2_d3_a_missing_extra_or_only_binary_is_caught() -> None:
    _, dev, regen = _texts()
    no_dev = dev.replace(" --extra=dev", "", 1)
    assert _dev_header_violations(no_dev, regen) == [
        "requirements-dev.lock never compiled extras ['dev'] that scripts/regen-lock.sh names"
    ]
    assert _dev_header_violations(dev.replace("--only-binary :all:", "", 1), regen) == [
        "requirements-dev.lock does not carry --only-binary :all:"
    ]


def test_teeth_d2_d3_the_tools_lock_header_is_checked_too() -> None:
    # Panel O F5: the header check read the dev lock only.
    _, _, regen = _texts()
    name = "requirements-ci-tools.lock"
    tools = _TOOLS_LOCK.read_text(encoding="utf-8")
    assert _header_violations(name, tools.replace(" --extra=ci", "", 1), regen) == [
        f"{name} never compiled extras ['ci'] that scripts/regen-lock.sh names"]
    assert _header_violations(name, tools.replace(" --extra=ci", " --extra=ci --extra=dev", 1), regen) == [
        f"{name} compiled extras ['dev'] that scripts/regen-lock.sh does not name"]
    assert _header_violations(name, tools.replace("--only-binary :all:", "", 1), regen) == [
        f"{name} does not carry --only-binary :all:"]


def test_teeth_a_yaml_workflow_is_read(tmp_path, monkeypatch) -> None:
    # db-sme panel D F-2: the workflow reader globbed only *.yml, so a .yaml
    # workflow escaped F1/F3.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "a.yml").write_text("jobs: {}\n", encoding="utf-8")
    (wf / "b.yaml").write_text("jobs: {}\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "_WORKFLOWS", wf)
    assert sorted(_real_workflows()) == [".github/workflows/a.yml", ".github/workflows/b.yaml"]


def test_teeth_d2_an_extra_the_generator_never_names_is_caught() -> None:
    # db-sme panel D F-3: D2 checked only want - got, so a header compiled with an
    # extra the generator does not name (keyring, say; e2e is named since punch 622) passed.
    _, dev, regen = _texts()
    widened = dev.replace(" --extra=dev", " --extra=dev --extra=keyring", 1)
    assert _dev_header_violations(widened, regen) == [
        "requirements-dev.lock compiled extras ['keyring'] that scripts/regen-lock.sh does not name"
    ]


# devils-advocate panel D FIX-1: each shape escaped F1/F3 when the tokenizer
# required `install` to be the token right after a bare `pip`/`pip3`.
@pytest.mark.parametrize("bad", [
    "pip -q install evil",
    "python -m pip --no-cache-dir install evil",
    "pip3.12 install evil",
    "python3 -m pip --log /tmp/l --disable-pip-version-check install evil",
    "python -mpip install evil",  # devils-advocate daD-fold1-1237: -m attached to its module
])
def test_teeth_f1_the_tokenizer_sees_options_before_install_and_versioned_pips(bad) -> None:
    assert len(_unsafe_installs(_wf(bad))) == 1, bad


def test_teeth_f3_the_tokenizer_sees_options_before_install() -> None:
    assert len(_unlocked_binding_installs(_wf("pip -q install -e .[encryption]", runs_on="ubuntu-latest"))) == 1


@pytest.mark.parametrize("ok", ["pip -q download evil", "pip-audit --strict", "pip-compile x", "pip --version"])
def test_teeth_the_tokenizer_does_not_read_other_pip_commands_as_installs(ok) -> None:
    assert _unsafe_installs(_wf(ok)) == [], ok


def test_teeth_f3_the_binding_outside_a_hashed_lock_is_caught_on_any_runner() -> None:
    ok = "pip install --require-hashes -r requirements-dev.lock" + _NL + "pip install --no-deps -e ."
    ok += _NL + "pip install -e '.[dev,e2e]'"
    assert _unlocked_binding_installs(_wf(ok)) == []
    for runs_on in ("[self-hosted, linux]", "ubuntu-latest"):
        for bad in (
            "pip install -e '.[dev,encryption]'",
            "pip install --no-deps -e '.[encryption]'",  # hashed nothing: the extra is still named
            "pip install 'email-triage[ Encryption ]'",
            "pip install sqlcipher3==0.6.3",
            "pip install sqlcipher3-binary",
            "pip install --require-hashes -r requirements-dev.lock && pip install sqlcipher3",
        ):
            assert len(_unlocked_binding_installs(_wf(bad, runs_on=runs_on))) == 1, (runs_on, bad)


# --- R1: regen-lock.sh routes its extra args per resolve (punch 629 fold) -----------
# The trim the container's /bin/sh runs before each compile, keyed on the lock it
# writes: the image compile keeps the first $nboth args (lock_reader's `both`), the
# dev compile the first $ndev (`both` plus `dev_only`), the CI tools compile the ones
# after $ndev (`shared` then `tools_only`; panel O F4: it took every arg).
def _trim(test: str) -> str:
    return f'n=$#; i=0 for a in "$@"; do i=$((i + 1)) {test} || set -- "$@" "$a" done shift "$n" '


_TRIMS = {
    "requirements.lock": _trim('[ "$i" -gt "$nboth" ]'),
    "requirements-dev.lock": _trim('[ "$i" -gt "$ndev" ]'),
    "requirements-ci-tools.lock": _trim('[ "$i" -le "$ndev" ]'),
}
_IMAGE_TRIM = _TRIMS["requirements.lock"]
_COMPILE_RE = re.compile(r'(?:PIP_ONLY_BINARY=\S+ )?pip-compile [^()]*?--output-file=([\w.-]+)')


def _regen_routing_violations(script: str) -> list[str]:
    code = _NL.join(ln for ln in script.splitlines() if not ln.lstrip().startswith("#"))
    flat = re.sub(r"\s+", " ", code)
    out: list[str] = []
    if 'scripts/lock_reader.py regen-args "$LOCK" "$DEV_LOCK" "$@"' not in flat:
        out.append("the extra args are not routed through `lock_reader.py regen-args` with both locks")
    if any("2>" in ln for ln in code.splitlines() if "lock_reader.py regen-args" in ln):
        out.append("the router's stderr is redirected, so the dev-only notice never reaches the operator")
    if '"$SEP" "${ROUTED[@]}"' not in flat or '"$SEP" "$@"' in flat:
        out.append("the container is handed the raw extra args, not the routed list")
    compiles = list(_COMPILE_RE.finditer(flat))
    if not any(m.group(1) == "requirements.lock" for m in compiles):
        out.append("no pip-compile writes requirements.lock: the scanner is blind")
    for m in compiles:
        lock, trim = m.group(1), _TRIMS.get(m.group(1))
        if trim is None:
            out.append(f"a pip-compile writes {lock}, which has no routed slice")
        elif not flat[: m.start()].endswith(trim):
            out.append(f"the pip-compile writing {lock} takes every extra arg, not only its routed slice")
    return out


def test_r1_regen_lock_hands_the_image_resolve_only_the_routed_args() -> None:
    assert _regen_routing_violations(_REGEN.read_text(encoding="utf-8")) == [], (
        "scripts/regen-lock.sh can send a dev-only --upgrade-package to the image resolve, "
        "which adds that package and its dependencies to requirements.lock")


def _route_texts() -> tuple[str, str, set[str], set[str], set[str]]:
    image_text, dev_text = _LOCK.read_text(encoding="utf-8"), _DEV_LOCK.read_text(encoding="utf-8")
    sets = [set(drift.parse_lock(t).hash_counts)
            for t in (image_text, dev_text, _TOOLS_LOCK.read_text(encoding="utf-8"))]
    return image_text, dev_text, *sets


def test_r1_a_dev_only_upgrade_never_reaches_the_image_resolve() -> None:
    image_text, dev_text, image, dev, _ = _route_texts()
    assert "pytest" in dev and "pytest" not in image, "precondition: pytest is a dev-only package"
    for args in (["--upgrade-package", "pytest==9.0.3"], ["-P", "pytest"], ["-Ppytest"],
                 ["--upgrade-package=pytest"]):
        assert drift.route_regen_args(args, image_text, dev_text) == ([], args, [], []), args
    # DA F2a trap (a): a SHARED package still goes to both; the dev resolve is
    # constrained to the image pins and could not move it alone.
    shared = sorted(image)[0]
    for args in (["-P", shared], ["--upgrade-package=" + shared.upper()]):
        assert drift.route_regen_args(args, image_text, dev_text) == (args, [], [], []), args
    assert drift.route_regen_args([], image_text, dev_text) == ([], [], [], [])
    assert drift.route_regen_args(["--upgrade", "-P", "pytest", "-P", shared], image_text, dev_text) == (
        ["--upgrade", "-P", shared], ["-P", "pytest"], ["--upgrade"], [])
    for bad in (["-P"], ["--upgrade-package="], ["-P", "==1.0"], ["--upgrade", "a" + _NL + "b"]):
        with pytest.raises(ValueError):
            drift.route_regen_args(bad, image_text, dev_text)


def test_r1_a_ci_tool_upgrade_reaches_the_ci_tools_resolve_alone() -> None:
    # Panel O F4: `-P pip-audit==2.11.0` routed dev-only, so it put pip-audit and its
    # dependencies in requirements-dev.lock, and the CI tools compile took every arg.
    image_text, dev_text, image, dev, tools = _route_texts()
    assert "pip-audit" in tools and "pip-audit" not in dev | image, "precondition: pip-audit is CI-tools-only"
    for args in (["-P", "pip-audit==2.11.0"], ["--upgrade-package=pip-audit"], ["-Pcyclonedx-bom"]):
        assert drift.route_regen_args(args, image_text, dev_text) == ([], [], [], args), args
    assert drift.route_regen_args(["--upgrade", "-P", "pytest", "-P", "pip-audit"], image_text, dev_text) == (
        ["--upgrade"], ["-P", "pytest"], ["--upgrade"], ["-P", "pip-audit"])
    # No dev lock yet (a first regen): every non-image upgrade reads as CI-tools-only.
    assert drift.route_regen_args(["-P", "pytest"], image_text, None) == ([], [], [], ["-P", "pytest"])


def test_r1_the_cli_the_script_calls_prints_the_routing(tmp_path) -> None:
    def cli(*args: str, dev_lock: str = str(_DEV_LOCK)) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "lock_reader.py"), "regen-args", str(_LOCK), dev_lock,
             *args],
            capture_output=True, text=True, timeout=60)

    ok = cli("--upgrade", "-P", "pytest", "-P", "pip-audit")
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.splitlines() == ["1", "3", "--upgrade", "-P", "pytest", "--upgrade", "-P", "pip-audit"]
    # Panel O round 2: an arg that names no package reaches EVERY compile, the CI tools
    # compile included, or a full refresh (`--upgrade`) leaves pip-audit and
    # cyclonedx-bom stale. The slices are the ones _TRIMS pins in the container script.
    nboth, ndev, *routed = ok.stdout.splitlines()
    slices = {"requirements.lock": routed[: int(nboth)], "requirements-dev.lock": routed[: int(ndev)],
              "requirements-ci-tools.lock": routed[int(ndev):]}
    assert set(slices) == set(_TRIMS)
    for lock, args in slices.items():
        assert "--upgrade" in args, (lock, args)
    assert slices["requirements-ci-tools.lock"] == ["--upgrade", "-P", "pip-audit"]
    assert cli().stdout.splitlines() == ["0", "0"], "a no-arg run must hand the container `0` twice"
    bad = cli("-P")
    assert bad.returncode != 0 and bad.stdout == "", "an unreadable upgrade must stop the regen"
    no_dev = cli("-P", "pytest", dev_lock=str(tmp_path / "absent.lock"))
    assert no_dev.returncode == 0 and no_dev.stdout.splitlines() == ["0", "0", "-P", "pytest"], no_dev.stderr
    # db F2a r2 L1: a typo of an image package routes away from the image resolve and
    # leaves the image lock unmoved; the regen names every such arg on stderr before
    # the container runs (the script's `$(...)` captures stdout only, so the line
    # reaches the operator). Since panel O F4 a typo is in neither lock, so it routes
    # to the CI tools resolve.
    typo = cli("--upgrade-package", "pyjwtt")
    assert typo.returncode == 0 and typo.stdout.splitlines() == ["0", "0", "--upgrade-package", "pyjwtt"]
    assert "regen-lock: CI tools resolve only: --upgrade-package pyjwtt" in typo.stderr, typo.stderr
    assert "regen-lock: dev resolve only: -P pytest" in cli("-P", "pytest").stderr
    image_pkg = cli("-P", sorted(drift.parse_lock(_LOCK.read_text(encoding="utf-8")).hash_counts)[0])
    assert "resolve only" not in image_pkg.stderr, "an image package must not be reported as skipping the image"
    assert "resolve only" not in cli().stderr


def test_teeth_r1_an_unrouted_compile_is_caught() -> None:
    real = _REGEN.read_text(encoding="utf-8")
    assert _regen_routing_violations(real) == []
    for broken in (
        real.replace('"${ROUTED[@]}"', '"$@"'),  # the pre-fold shape: raw args to the container
        real.replace('scripts/lock_reader.py regen-args "$LOCK" "$DEV_LOCK" "$@"', 'scripts/lock_reader.py "$LOCK"'),
        # panel O F4: the router not told the dev lock, so no arg could route tools-only
        real.replace('regen-args "$LOCK" "$DEV_LOCK" "$@"', 'regen-args "$LOCK" "$@"'),
        real.replace('[ "$i" -gt "$nboth" ] || set -- "$@" "$a"', 'set -- "$@" "$a"'),
        real.replace('[ "$i" -gt "$ndev" ] || set -- "$@" "$a"', 'set -- "$@" "$a"'),  # dev takes every arg
        real.replace('[ "$i" -le "$ndev" ] || set -- "$@" "$a"', 'set -- "$@" "$a"'),  # tools takes every arg
        real.replace('[ "$i" -le "$ndev" ]', '[ "$i" -gt "$ndev" ]'),  # tools takes the dev slice
        real + _NL + 'pip-compile --output-file=requirements.lock "$@" pyproject.toml' + _NL,
        real + _NL + 'pip-compile --output-file=requirements-ci-tools.lock "$@" pyproject.toml' + _NL,
        real + _NL + 'pip-compile --output-file=requirements-other.lock "$@" pyproject.toml' + _NL,
        real.replace('"$DEV_LOCK" "$@")"', '"$DEV_LOCK" "$@" 2>/dev/null)"'),  # the L1 notice silenced
    ):
        assert broken != real
        assert _regen_routing_violations(broken), broken[-200:]
    assert _regen_routing_violations("#!/bin/sh" + _NL) != [], "a script with no image compile is blind"
