"""Pin: ``requirements.lock`` describes the IMAGE: hashed, Linux, the Containerfile's Python (punch 549, N-545).

Why this exists. The lock used to be resolved on the Windows workstation under
Python 3.13 with no hashes, while the image is ``python:3.12-slim``. Two things
followed. pip installed the lock WITHOUT hash checking, so a substituted
artifact would install silently. And because a Windows resolve drops the
Linux-only ``uvloop`` (``uvicorn[standard]`` asks for it), the image build
resolved uvloop UNPINNED at build time: prod container e8749919 ran uvloop
0.22.1 on 2026-09-30, a version no file in the repo named. Hash-checking mode
turns that into a build failure, because pip refuses any requirement the lock
does not pin (measured on the deploy host for punch 549: the lock minus uvloop exits 1 with
"In --require-hashes mode, all requirements must have their versions pinned").

INVARIANTS (count-agnostic, over every entry / every FROM / every call site):
  P1  every lock entry carries at least one ``--hash=`` (pip turns hash-checking
      mode on for the whole file only then);
  P2  the header's recorded command contains ``--generate-hashes``;
  P3  the header's "with Python X.Y" equals the X.Y of EVERY ``FROM python:``
      in the Containerfile, and those FROMs agree with each other;
  P4  the ``# resolved-for:`` provenance line scripts/regen-lock.sh writes is
      present, says ``sys_platform=linux``, the same X.Y, and ``base=`` the
      Containerfile's first ``FROM python:`` image;
  P5  every ``.[a,b,...]`` extras spec a Containerfile ``pip install`` asks for
      is a subset of the extras the lock header compiled in;
  P6  every ``python-version:`` in .github/workflows/*.yml equals that X.Y, so
      CI tests the interpreter that ships;
  P7  EVERY repo-root lock is installed by a self-hosted job, alone, with
      ``--require-hashes`` and WITHOUT ``--no-deps``, into a venv that step just
      created (panel B1: the pre-push freshness guard skips on a push host
      unlike the lock's provenance, so without this job the deploy host deploy build is
      the lock's first install; db-sme panel D F-1: an install into the runner's
      persistent toolcache accepts a transitive an earlier job left there, so it
      cannot prove a lock complete).

All lock reading goes through scripts/lock_reader.py (PD-5), the SSOT the
N-542 pin uses and the monitoring system drift check re-exports.

PROXY vs OBJECT. P4 is a proxy: a line the regen script writes about where it
ran. The object-level guarantee is pip itself, in hash-checking mode, at the
image build and at every CI install. P1 and P2 make that mode certain; they do
not prove the lock resolves on Linux. The CI install and the image build do.

SCOPE CAVEAT. These pins see only what installs FROM the lock. They do not see
the unpinned ``pip install setuptools wheel`` in the sqlcipher3 build step, the
hash-pinned pip of ``requirements-pip.txt`` in the runtime stage (N-621), the CI
installs (every pip install of a lock is hash-locked since punch 623/622, pinned
by tests/test_punch511_ci_installs_are_hash_locked_pin.py; register N-607
residual (b), verbatim: What survives: the runner's bundled pip is the trust root
that enforces `--require-hashes` on the tools lock; and `pip install --no-deps -e .`
fetches setuptools unhashed for build isolation; `security.yml` closes it with
`--no-build-isolation` (panel O F3), and it survives in `tests.yml` and
`e2e.yml`.), or the runtime embedding installer (its own hash manifest).
P3 compares only ``Containerfile``: ``Containerfile.test`` also installs the
lock, but its ``FROM docker.io/library/python:3.14@sha256:...`` does not start with
``python:`` and is not compared (same X.Y today). A green P7 proves the job
EXISTS, not that it ran green; that is the CI verdict.
"""

from __future__ import annotations

import re
import sys

import pytest

from _pin_harness import (
    CONTAINERFILE,
    REPO_ROOT,
    dockerfile_instructions,
    load_repo_script,
    workflow_texts,
)

#: THE lock parser (PD-5).
drift = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")

_LOCK = REPO_ROOT / "requirements.lock"
#: Every lock at the repo root: requirements.lock (the image) and requirements-dev.lock
#: (the CI unit job, punch 511). P1-P4 hold for each; P5 and P7 are about the image lock.
_LOCKS = sorted(REPO_ROOT.glob("requirements*.lock"))
_WORKFLOWS = REPO_ROOT / ".github" / "workflows"

_FROM_PY_RE = re.compile(r"^python:(\d+\.\d+)")
_EXTRAS_SPEC_RE = re.compile(r"(?<![\w/])\.\[([^\]]+)\]")
_PYVER_RE = re.compile(r"^\s*python-version:\s*(.+?)\s*$", re.M)

_REGEN_HINT = "Regenerate with scripts/regen-lock.sh on a Linux podman host (it reads the base image from the Containerfile)."


def _python_froms(containerfile_text: str) -> list[str]:
    """Image refs of every ``FROM python:...`` instruction, in order."""
    refs = []
    for _line, instr in dockerfile_instructions(containerfile_text):
        parts = instr.split()
        if len(parts) >= 2 and parts[0].upper() == "FROM" and parts[1].startswith("python:"):
            refs.append(parts[1])
    return refs


def _image_python(containerfile_text: str) -> tuple[str | None, list[str]]:
    """(the one X.Y every ``FROM python:`` agrees on, problems)."""
    refs = _python_froms(containerfile_text)
    if not refs:
        return None, ["the Containerfile has no FROM python: instruction"]
    versions = {m.group(1) if (m := _FROM_PY_RE.match(r)) else r for r in refs}
    if len(versions) != 1:
        return None, [f"the Containerfile's FROM python: lines disagree: {refs}"]
    return versions.pop(), []


def _unhashed_entries(lock_text: str) -> list[str]:
    """P1: entries with no ``--hash=``, marker-gated or not."""
    locked = drift.parse_lock(lock_text, None)
    every = set(locked.pins) | set(locked.unevaluated) | set(locked.not_applicable)
    assert every == set(locked.hash_counts), "parse_lock lost an entry's hash count"
    return sorted(name for name, n in locked.hash_counts.items() if n < 1)


def _header_violations(lock_text: str, containerfile_text: str) -> list[str]:
    """P2, P3, P4: the header and the provenance line against the Containerfile."""
    out: list[str] = []
    if "--generate-hashes" not in drift.header_command(lock_text).split():
        out.append("the lock header's pip-compile command lacks --generate-hashes")
    want, problems = _image_python(containerfile_text)
    out.extend(problems)
    got = drift.header_python(lock_text)
    if want is not None and got != want:
        out.append(f"the lock header says Python {got}; the image is python:{want}")
    prov = drift.lock_provenance(lock_text)
    if prov is None:
        out.append("no '# resolved-for:' provenance line in the lock header: not written by scripts/regen-lock.sh")
        return out
    if prov.get("sys_platform") != "linux":
        out.append(f"the lock was resolved for sys_platform={prov.get('sys_platform')}, not linux")
    if want is not None and prov.get("python_version") != want:
        out.append(f"the lock was resolved under Python {prov.get('python_version')}; the image is python:{want}")
    froms = _python_froms(containerfile_text)
    if froms and prov.get("base") != froms[0]:
        out.append(f"the lock was resolved on base={prov.get('base')}; the Containerfile builds FROM {froms[0]}")
    return out


def _containerfile_extras(containerfile_text: str) -> list[tuple[int, frozenset[str]]]:
    """Every ``.[...]`` extras spec on a ``pip install`` RUN instruction."""
    specs = []
    for line, instr in dockerfile_instructions(containerfile_text):
        if instr.split(None, 1)[0].upper() != "RUN" or "pip install" not in instr:
            continue
        for m in _EXTRAS_SPEC_RE.finditer(instr):
            specs.append((line, frozenset(e.strip().lower() for e in m.group(1).split(",") if e.strip())))
    return specs


def _extras_violations(lock_text: str, containerfile_text: str) -> list[str]:
    """P5."""
    compiled = drift.header_extras(lock_text)
    return [
        f"Containerfile:{line} installs extras {sorted(extras - compiled)} the lock never compiled (lock has {sorted(compiled)})"
        for line, extras in _containerfile_extras(containerfile_text)
        if not extras <= compiled
    ]


def _ci_python_versions(workflow_texts: dict[str, str]) -> list[tuple[str, str]]:
    """(workflow, value) for every ``python-version:`` call site."""
    return [
        (name, m.group(1).strip().strip("'\""))
        for name, text in sorted(workflow_texts.items())
        for m in _PYVER_RE.finditer(text)
    ]


def _ci_violations(workflow_texts: dict[str, str], image_python: str) -> list[str]:
    """P6."""
    return [
        f"{name}: python-version {value!r} != the image's {image_python}"
        for name, value in _ci_python_versions(workflow_texts)
        if value != image_python
    ]


def _real():
    return _LOCK.read_text(encoding="utf-8"), CONTAINERFILE.read_text(encoding="utf-8")


def _real_workflows() -> dict[str, str]:
    return workflow_texts(_WORKFLOWS)


# --- the invariants on the real tree ----------------------------------------------


def test_every_repo_lock_is_in_scope() -> None:
    assert _LOCK in _LOCKS, "the lock glob missed requirements.lock; the scanner is blind"


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_p1_every_lock_entry_is_hashed(lock_path) -> None:
    assert _unhashed_entries(lock_path.read_text(encoding="utf-8")) == [], _REGEN_HINT


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_p2_p3_p4_the_lock_header_describes_the_image(lock_path) -> None:
    _, containerfile = _real()
    assert _header_violations(lock_path.read_text(encoding="utf-8"), containerfile) == [], _REGEN_HINT


def test_p5_containerfile_extras_are_compiled_into_the_lock() -> None:
    lock, containerfile = _real()
    assert _containerfile_extras(containerfile), (
        "found no .[extras] spec on any Containerfile pip install; the scanner is blind, not the Containerfile clean"
    )
    assert _extras_violations(lock, containerfile) == []


def test_p6_ci_runs_the_image_interpreter() -> None:
    _, containerfile = _real()
    image_python, problems = _image_python(containerfile)
    assert not problems, problems
    workflows = _real_workflows()
    assert _ci_python_versions(workflows), "found no python-version call site in .github/workflows; the scanner is blind"
    assert _ci_violations(workflows, image_python) == [], (
        "CI must test the interpreter the image ships. When the image's Python moves, move every "
        "python-version with it, and first confirm the self-hosted runner HAS that interpreter "
        "(pattern_ci_interpreter_need_not_equal_the_lock_generator: a version the runner lacks breaks the job)."
    )


# --- teeth: each must-sentence above, planted and caught --------------------------

_NL = chr(10)
_H = chr(92)


def _swap(text: str, old: str, new: str) -> str:
    assert old in text, f"teeth fixture drifted: {old!r} is no longer in the real file"
    return text.replace(old, new, 1)


def test_teeth_p1_an_appended_unhashed_entry_is_caught() -> None:
    lock, _ = _real()
    assert _unhashed_entries(lock + "plantedpkg==1.0" + _NL) == ["plantedpkg"]
    assert _unhashed_entries(lock + 'plantedwin==1.0 ; sys_platform == "win32"' + _NL) == ["plantedwin"]


def test_teeth_p1_one_entry_with_its_hashes_stripped_is_caught() -> None:
    lock, _ = _real()
    lines = lock.splitlines()
    first = next(i for i, ln in enumerate(lines) if ln and not ln.startswith("#") and not ln.startswith(" "))
    name = drift.canonical(re.split(r"[=\[ ;]", lines[first], maxsplit=1)[0])
    # Drop only this entry's continuation and its own hash lines; every other
    # entry keeps its hashes.
    out, skipping = [], False
    for i, ln in enumerate(lines):
        if i == first:
            out.append(ln.rstrip(" " + _H))
            skipping = True
            continue
        if skipping and ln.lstrip().startswith("--hash="):
            continue
        skipping = False
        out.append(ln)
    assert _unhashed_entries(_NL.join(out) + _NL) == [name]


def test_teeth_p2_a_header_without_generate_hashes_is_caught() -> None:
    lock, containerfile = _real()
    bad = _swap(lock, " --generate-hashes", "")
    assert _header_violations(bad, containerfile) == ["the lock header's pip-compile command lacks --generate-hashes"]


def test_teeth_p3_a_header_interpreter_other_than_the_image_is_caught() -> None:
    lock, containerfile = _real()
    want, _ = _image_python(containerfile)
    bad = _swap(lock, f"with Python {want}", "with Python 3.13")
    assert _header_violations(bad, containerfile) == [f"the lock header says Python 3.13; the image is python:{want}"]


def test_teeth_p3_containerfile_froms_that_disagree_are_caught() -> None:
    lock, containerfile = _real()
    froms = _python_froms(containerfile)
    assert len(froms) >= 2, "the teeth need two FROM python: stages to disagree"
    last = containerfile.rindex("FROM " + froms[-1])
    bad = containerfile[:last] + "FROM python:3.13-slim" + containerfile[last + len("FROM " + froms[-1]) :]
    got = _header_violations(lock, bad)
    assert any("disagree" in v for v in got), got


def test_teeth_p4_a_lock_without_provenance_is_caught() -> None:
    """The line a raw pip-compile run (bypassing regen-lock.sh) would lack."""
    lock, containerfile = _real()
    prov_line = next(ln for ln in lock.splitlines() if ln.startswith("# resolved-for:"))
    bad = _swap(lock, prov_line + _NL, "")
    assert _header_violations(bad, containerfile) == [
        "no '# resolved-for:' provenance line in the lock header: not written by scripts/regen-lock.sh"
    ]


def test_teeth_p4_a_windows_or_off_image_provenance_is_caught() -> None:
    lock, containerfile = _real()
    want, _ = _image_python(containerfile)
    base = _python_froms(containerfile)[0]
    win = _swap(lock, "sys_platform=linux", "sys_platform=win32")
    assert _header_violations(win, containerfile) == ["the lock was resolved for sys_platform=win32, not linux"]
    other_py = _swap(lock, f"python_version={want} ", "python_version=3.13 ")
    assert _header_violations(other_py, containerfile) == [
        f"the lock was resolved under Python 3.13; the image is python:{want}"
    ]
    other_base = _swap(lock, f"base={base}", "base=python:3.12-bookworm")
    assert _header_violations(other_base, containerfile) == [
        f"the lock was resolved on base=python:3.12-bookworm; the Containerfile builds FROM {base}"
    ]


def test_teeth_p4_a_provenance_line_below_the_header_does_not_count() -> None:
    """A hand-appended body comment is not the regen script's header line."""
    lock, containerfile = _real()
    prov_line = next(ln for ln in lock.splitlines() if ln.startswith("# resolved-for:"))
    moved = _swap(lock, prov_line + _NL, "") + prov_line + _NL
    assert any("no '# resolved-for:'" in v for v in _header_violations(moved, containerfile))


def test_teeth_p5_an_extra_the_lock_never_compiled_is_caught() -> None:
    lock, containerfile = _real()
    # Take the spec from the RUN instruction the scanner reads; the first
    # ``.[...]`` in the raw file is in a comment.
    instr = next(
        i
        for _line, i in dockerfile_instructions(containerfile)
        if i.split(None, 1)[0].upper() == "RUN" and "pip install" in i and _EXTRAS_SPEC_RE.search(i)
    )
    raw = _EXTRAS_SPEC_RE.search(instr).group(0)
    assert raw in containerfile
    got = _extras_violations(lock, containerfile.replace(raw, ".[keyfile,keyring]"))
    assert len(got) == 1 and "['keyring']" in got[0], got
    # good variant: a subset of the compiled extras is clean
    assert _extras_violations(lock, containerfile.replace(raw, ".[keyfile]")) == []


def test_teeth_p6_a_ci_interpreter_other_than_the_image_is_caught() -> None:
    _, containerfile = _real()
    image_python, _ = _image_python(containerfile)
    planted = {"wf.yml": "    with:" + _NL + '      python-version: "3.11"' + _NL}
    assert _ci_violations(planted, image_python) == [f"wf.yml: python-version '3.11' != the image's {image_python}"]
    matrix = {"wf.yml": "      python-version: ${{ matrix.python }}" + _NL}
    assert len(_ci_violations(matrix, image_python)) == 1, "a non-literal version cannot be verified and must not pass"
    assert _ci_violations({"wf.yml": f"      python-version: '{image_python}'" + _NL}, image_python) == []


# --- P7: every repo lock installs, hashed, into a FRESH venv on the runner ---------
# db-sme panel D F-1: the unit job installs requirements-dev.lock into the runner's
# persistent toolcache interpreter. pip's hash mode checks only what it downloads,
# so a transitive dependency a prior job left there is accepted, and a lock missing
# an entry passes on a warm runner (P1 and punch-511 D1 stay green too). Only an
# install into a venv created in the same step proves the lock is complete.

from _pin_harness import _FULL_DEV_TREE  # noqa: E402  (the one dev-tree detector, PD-5)
from test_punch511_ci_installs_are_hash_locked_pin import (  # noqa: E402  (the one pip tokenizer, PD-5)
    _pip_install_commands,
    _split_install_args,
    _venv_dirs,
)


def _fresh_venv_lock_installs(
    workflow_texts: dict[str, str], *, self_hosted_only: bool = False,
) -> dict[str, list[str]]:
    """lock file -> ``workflow:job`` for every step that creates a venv and installs
    that lock, alone, into it with ``--require-hashes`` and without ``--no-deps``.

    Punch 629 / N-614 (panel F db F-6): the hashed fresh-venv install is the
    property, and it holds on ANY runner, so the default arm is runner-agnostic and
    stays live on the public tree (its overlay runs ``ubuntu-latest``).
    ``self_hosted_only`` is the dev-tree arm: the same install on the self-hosted
    runner that builds the deploy image."""
    import yaml

    found: dict[str, list[str]] = {}
    for name, text in sorted(workflow_texts.items()):
        jobs = (yaml.safe_load(text) or {}).get("jobs") or {}
        for job_id, job in jobs.items():
            runs_on = job.get("runs-on") if isinstance(job, dict) else None
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            if self_hosted_only and "self-hosted" not in labels:
                continue
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                run = str(step.get("run", ""))
                venvs = _venv_dirs(run)
                for prefix, args in _pip_install_commands(run):
                    flags, reqfiles, specs = _split_install_args(args)
                    in_venv = any(t.startswith(v + "/") for t in prefix for v in venvs)
                    if in_venv and "--require-hashes" in flags and "--no-deps" not in flags and not specs:
                        for lock in reqfiles:
                            found.setdefault(lock, []).append(f"{name}:{job_id}")
    return found


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_p7_every_lock_installs_hashed_into_a_fresh_venv(lock_path) -> None:
    """LIVE on both trees: on the public mirror this is the only evidence that the
    shipped locks install hashed and complete (hipaa panel F §2-3: never a bare skip)."""
    assert _fresh_venv_lock_installs(_real_workflows()).get(lock_path.name), (
        f"no CI job installs {lock_path.name} with --require-hashes (and without "
        "--no-deps) into a venv it just created; an incomplete lock would pass on a warm "
        "interpreter"
    )


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_p7_the_fresh_venv_install_runs_on_the_self_hosted_runner(lock_path) -> None:
    if not _FULL_DEV_TREE:
        pytest.skip("public tree: its workflow overlay runs ubuntu-latest, so there is no "
                    "self-hosted job; the runner-agnostic P7 arm above still runs here")
    assert _fresh_venv_lock_installs(_real_workflows(), self_hosted_only=True).get(lock_path.name), (
        f"no self-hosted CI job installs {lock_path.name} with --require-hashes (and without "
        "--no-deps) into a venv it just created; the self-hosted deploy build would be the "
        "image lock's first install"
    )


def test_teeth_a_yaml_workflow_is_read(tmp_path, monkeypatch) -> None:
    # db-sme panel D F-2: the workflow reader globbed only *.yml, so a .yaml
    # workflow escaped P6 and P7.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "a.yml").write_text("jobs: {}\n", encoding="utf-8")
    (wf / "b.yaml").write_text("jobs: {}\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "_WORKFLOWS", wf)
    assert sorted(_real_workflows()) == [".github/workflows/a.yml", ".github/workflows/b.yaml"]


def _one_job(run: str, runs_on: str = "[self-hosted, linux]") -> dict[str, str]:
    body = "jobs:" + _NL + "  j:" + _NL + f"    runs-on: {runs_on}" + _NL + "    steps:" + _NL
    body += "      - run: |" + _NL + "".join("          " + ln + _NL for ln in run.splitlines())
    return {"wf.yml": body}


def test_teeth_p7_only_a_hashed_complete_install_into_a_fresh_venv_counts() -> None:
    venv = 'python -m venv "$RUNNER_TEMP/v"' + _NL
    fresh = venv + '"$RUNNER_TEMP/v/bin/python" -m pip install --require-hashes -r requirements-dev.lock'
    assert _fresh_venv_lock_installs(_one_job(fresh)) == {"requirements-dev.lock": ["wf.yml:j"]}
    for bad in (
        "pip install --require-hashes -r requirements-dev.lock",  # the persistent toolcache
        venv + "pip install --require-hashes -r requirements-dev.lock",  # venv made, not used
        fresh.replace("--require-hashes ", ""),
        fresh.replace("--require-hashes", "--require-hashes --no-deps"),
        fresh + " pytest",  # a requirement beside the lock
    ):
        assert _fresh_venv_lock_installs(_one_job(bad)) == {}, bad
        assert _fresh_venv_lock_installs(_one_job(bad), self_hosted_only=True) == {}, bad
    # Punch 629 / N-614: the runner-agnostic arm counts a GitHub-hosted job, the
    # self-hosted arm does not. The teeth plant their own workflow text (panel F db
    # F-6), so they run identically on the public tree, where no self-hosted job exists.
    hosted = _one_job(fresh, runs_on="ubuntu-latest")
    assert _fresh_venv_lock_installs(hosted) == {"requirements-dev.lock": ["wf.yml:j"]}
    assert _fresh_venv_lock_installs(hosted, self_hosted_only=True) == {}
    assert _fresh_venv_lock_installs(_one_job(fresh), self_hosted_only=True) == {
        "requirements-dev.lock": ["wf.yml:j"]}


def test_teeth_p7_each_property_breaking_edit_drops_the_real_job() -> None:
    """Punch 629 fold (hipaa F2a fix 6 = db fix 1): the planted teeth above prove the
    predicate on synthetic text; these prove the LIVE P7 counts each real job for the
    right reason, its actual multi-line install text. The two runner-agnostic edits run
    on both trees, over every job the default arm finds; the ``runs-on`` edit runs only
    where the self-hosted arm is live."""
    real = _real_workflows()
    found = _fresh_venv_lock_installs(real)
    assert found, "the default P7 arm found no real job, so these teeth would be vacuous"
    for lock, jobs in sorted(found.items()):
        for job in jobs:
            name = job.split(":", 1)[0]
            for edited in (
                real[name].replace("--require-hashes", ""),
                real[name].replace("--require-hashes", "--require-hashes --no-deps"),
            ):
                assert edited != real[name], job
                assert job not in _fresh_venv_lock_installs({**real, name: edited}).get(lock, []), (
                    f"{job} still counts for {lock} after a property-breaking edit")
    if _FULL_DEV_TREE:
        hosted_found = _fresh_venv_lock_installs(real, self_hosted_only=True)
        assert hosted_found, "the self-hosted P7 arm found no real job on the dev tree"
        for lock, jobs in sorted(hosted_found.items()):
            for job in jobs:
                name = job.split(":", 1)[0]
                # Any self-hosted label, not the operator's runner name (punch 617: a
                # host name in a shipped literal survives the publish sanitizer).
                edited = re.sub(r"runs-on: \[self-hosted, [^\]]+\]", "runs-on: ubuntu-latest", real[name])
                assert edited != real[name], f"{job}: no `runs-on: [self-hosted, ...]` line to edit"
                assert job not in _fresh_venv_lock_installs(
                    {**real, name: edited}, self_hosted_only=True).get(lock, []), (
                    f"{job} still counts as self-hosted for {lock} after its runs-on was rewritten")
