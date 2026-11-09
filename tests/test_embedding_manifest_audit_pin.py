"""Pin: the embedding runtime-deps manifest is dependency-audited (punch 555).

``scripts/embedding-bits-manifest.json`` is the SECOND dependency set the image
ships: the Containerfile COPYs it in and the admin Install button pip-installs
it into the PHI container. Until punch 555 nothing audited it — CI's pip-audit
read the environment built from ``requirements.lock`` only, so pillow 12.2.0
(13 CVEs), setuptools 81.0.0, torch 2.12.0+cpu and transformers 5.8.1 sat in
the manifest while "pip-audit is green".

What this file pins, and the bound of each:

1. VIEW COMPLETENESS (property over every entry, count-agnostic): the builder's
   ``--requirements-view`` carries a ``name==public-version`` requirement for
   EVERY wheel on EVERY arch of the real manifest, and no local version
   segment. The segment matters, measured 2026-09-30: pip-audit's PyPI service
   reports ``torch==2.12.0+cpu`` as "Dependency not found on PyPI and could not
   be audited" and EXITS 0 — a silent pass on the pin that carried
   PYSEC-2025-194. The view refuses when the arches disagree or list nothing.
2. PUBLISHER VERIFICATION (both arms, through ``regenerate`` itself): a wheel
   whose bytes match its publisher's published sha256 is written; one that
   does not is REFUSED before the manifest is written and its cache slot is
   removed. An unknown host, or a publisher that states no sha256, refuses.
3. AIR-GAP STAGING (both arms): ``stage_sideload_layout`` stages every wheel on
   every arch; the pre-555 walk (``manifest["wheels"]`` only) provably stages
   fewer on the real manifest; ``download-embedding-bits.sh`` calls it rather
   than walking the manifest itself.
4. WIRING — a PRESENCE pin, and it says so: ``run-pip-audit.sh`` audits the
   manifest the Containerfile COPYs, with ``--strict --no-deps --disable-pip``,
   runs the teeth leg over a fixture whose per-arch ``+cpu`` pin exercises the
   strip, and ``security.yml`` runs that script on push, PR and the nightly
   schedule without ``continue-on-error``. By itself it cannot see a guard
   wrapped around a call or a broken exit path (db-555 F1: ``exit 0``, the
   teeth branch's ``status=1`` removed and leg 1's ``|| true`` all stayed
   green here); section 5 covers that.
5. BEHAVIOUR, offline: the real script runs under bash with a stub
   ``pip-audit`` first on PATH. A failure in each leg (environment rc,
   environment JSON finding, an environment skip other than the pyproject-named
   editable dist, manifest rc, silent teeth, teeth missing a package) must make
   the script exit non-zero, and a clean run must exit 0. The stub records the
   ``-r`` file it received, so the manifest leg is proven to audit exactly
   ``requirements_view`` of the real manifest and the teeth leg exactly the
   fixture's. What the stub CANNOT show is that pip-audit itself still detects
   advisories; the teeth leg shows that, on every CI run, with the network.
6. SERVICES (punch 573, N-562): every leg, and every teeth run, goes once per
   vulnerability service in the script's ``SERVICES`` array, which must hold
   both ``pypi`` and ``osv``. Measured 2026-10-06: ``-s pypi`` stayed silent on
   mako 1.4.1 (CVE-2026-102991) while ``-s osv`` reported it. Static half: every
   ``pip-audit`` call in the script names ``-s "${service}"`` (a property over
   every call). Behaviour half: the stub records the service of each call, the
   leg sequence repeats once per service, and a failure under ONE service only
   (osv) still fails the script.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import shlex
import zipfile
from pathlib import Path

import pytest
import yaml

from _pin_harness import (
    REPO_ROOT, dockerfile_instructions, dockerfile_shell_text, dockerfile_stages, load_repo_script,
    workflow_texts,
)

BUILDER = load_repo_script("scripts/build-embedding-bits-manifest.py")
MANIFEST_PATH = REPO_ROOT / "scripts" / "embedding-bits-manifest.json"
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "run-pip-audit.sh"
DOWNLOAD_SCRIPT = REPO_ROOT / "scripts" / "download-embedding-bits.sh"
TEETH_REL = "tests/fixtures/manifest_audit_teeth.json"
TEETH_FIXTURE = REPO_ROOT / TEETH_REL
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"
CONTAINERFILE = REPO_ROOT / "Containerfile"


def _real_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _public(version: str) -> str:
    return str(version).split("+", 1)[0]


# ---------------------------------------------------------------------------
# 1. The requirements view
# ---------------------------------------------------------------------------

def test_view_covers_every_wheel_on_every_arch_of_the_real_manifest():
    manifest = _real_manifest()
    view = BUILDER.requirements_view(manifest)
    entries = list(BUILDER.iter_wheel_entries(manifest))
    assert entries, "the real manifest lists no wheels"
    missing = sorted({
        f"{BUILDER._norm_pkg(e['name'])}=={_public(e['version'])} [{arch or 'neutral'}]"
        for arch, e in entries
        if f"{BUILDER._norm_pkg(e['name'])}=={_public(e['version'])}" not in view
    })
    assert not missing, f"view omits: {missing}"
    assert not [r for r in view if "+" in r], "a local version segment reached the view"
    assert len(view) == len(set(view)), "duplicate requirement in the view"
    assert any(arch is not None for arch, _ in entries), (
        "the real manifest has no per-arch wheels, so this property cannot "
        "exercise the wheels_by_arch walk"
    )


def test_view_drops_the_local_segment_and_refuses_arch_disagreement():
    ok = {"wheels": [{"name": "Foo_Bar", "version": "1.0"}],
          "wheels_by_arch": {"x86_64": [{"name": "torch", "version": "2.13.0+cpu"}],
                             "aarch64": [{"name": "torch", "version": "2.13.0+cpu"}]}}
    assert BUILDER.requirements_view(ok) == ["foo-bar==1.0", "torch==2.13.0"]

    split = {"wheels": [],
             "wheels_by_arch": {"x86_64": [{"name": "torch", "version": "2.13.0+cpu"}],
                                "aarch64": [{"name": "torch", "version": "2.12.0+cpu"}]}}
    with pytest.raises(ValueError, match="different public versions"):
        BUILDER.requirements_view(split)
    with pytest.raises(ValueError, match="no wheels"):
        BUILDER.requirements_view({"wheels": [], "wheels_by_arch": {}})


def test_requirements_view_cli_is_offline(monkeypatch, capsys):
    def _no_network(*_a, **_k):
        raise AssertionError("--requirements-view touched the network")

    monkeypatch.setattr(BUILDER.urllib.request, "urlopen", _no_network)
    rc = BUILDER.main(["--output", str(MANIFEST_PATH), "--requirements-view"])
    out = capsys.readouterr().out.splitlines()
    assert rc == 0
    assert out == BUILDER.requirements_view(_real_manifest())


def test_requirements_view_cli_refuses_with_exit_2(tmp_path, capsys):
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps({"wheels": [], "wheels_by_arch": {}}), encoding="utf-8")
    assert BUILDER.main(["--output", str(bad), "--requirements-view"]) == 2
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# 2. Publisher verification, through regenerate()
# ---------------------------------------------------------------------------

def _tiny_wheel(name: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{name}-{version}.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        z.writestr(f"{name}/__init__.py", "")
    return buf.getvalue()


def _one_wheel_manifest(tmp_path: Path, filename: str, url: str) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({
        "wheels": [{"name": "fakepkg", "version": "1.0", "filename": filename,
                    "url": url, "sha256": "PLACEHOLDER", "size_bytes": 0}],
        "wheels_by_arch": {}, "models": [],
    }), encoding="utf-8")
    return path


def _stub_downloads(monkeypatch, payload: bytes, published: str):
    def fake_http_get(url, *, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest(), len(payload)

    monkeypatch.setattr(BUILDER, "_http_get", fake_http_get)
    monkeypatch.setattr(
        BUILDER, "_pypi_release_file",
        lambda name, version, filename: {"url": "unused", "digests": {"sha256": published}},
    )


@pytest.mark.parametrize("arm", ["publisher_matches", "publisher_differs"])
def test_regenerate_verifies_every_wheel_against_its_publisher(tmp_path, monkeypatch, arm):
    filename = "fakepkg-1.0-py3-none-any.whl"
    url = f"https://{BUILDER.PYPI_FILES_HOST}/packages/aa/bb/{filename}"
    manifest_path = _one_wheel_manifest(tmp_path, filename, url)
    before = manifest_path.read_text(encoding="utf-8")
    payload = _tiny_wheel("fakepkg", "1.0")
    real = hashlib.sha256(payload).hexdigest()
    published = real if arm == "publisher_matches" else "0" * 64
    _stub_downloads(monkeypatch, payload, published)
    cache = tmp_path / "cache"

    if arm == "publisher_matches":
        # Punch 569 D1: a run that changes the package set must classify it.
        BUILDER.regenerate(
            manifest_path, cache_dir=cache,
            set_change={"security_change": False},
        )
        written = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert written["wheels"][0]["sha256"] == real
        assert written["set_changes"][-1]["security_change"] is False
    else:
        with pytest.raises(RuntimeError, match="REFUSING .*publisher"):
            BUILDER.regenerate(manifest_path, cache_dir=cache)
        assert manifest_path.read_text(encoding="utf-8") == before, "refusal wrote the manifest"
        assert not BUILDER._cache_slot(cache, None, filename).exists(), (
            "the mismatching bytes stayed in the cache and would cache-hit on retry"
        )


def test_publisher_sha256_reads_the_pytorch_index_fragment(monkeypatch):
    filename = "torch-2.13.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl"
    digest = "ab" * 32
    html = (f'<a href="/whl/cpu/torch-2.13.0%2Bcpu-cp312-cp312-manylinux_2_28_aarch64.whl'
            f'#sha256={"cd" * 32}">x</a>'
            f'<a href="/whl/cpu/{filename.replace("+", "%2B")}#sha256={digest}">y</a>')
    seen = []

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        seen.append(req.full_url)
        return _Resp(html.encode())

    monkeypatch.setattr(BUILDER.urllib.request, "urlopen", fake_urlopen)
    entry = {"name": "torch", "version": "2.13.0+cpu", "filename": filename}
    url = f"https://{BUILDER.PYTORCH_INDEX_HOST}/whl/cpu/{filename.replace('+', '%2B')}"
    assert BUILDER._publisher_sha256(entry, url) == digest
    assert seen == [f"https://{BUILDER.PYTORCH_INDEX_HOST}/whl/cpu/torch/"]

    # Listed without a fragment: no published value, so refuse.
    html = f'<a href="/whl/cpu/{filename.replace("+", "%2B")}">y</a>'
    with pytest.raises(RuntimeError, match="states no sha256"):
        BUILDER._publisher_sha256(entry, url)


def test_publisher_sha256_refuses_an_unknown_host():
    entry = {"name": "x", "version": "1", "filename": "x-1-py3-none-any.whl"}
    with pytest.raises(RuntimeError, match="no publisher sha256 source"):
        BUILDER._publisher_sha256(entry, "https://mirror.example/x-1-py3-none-any.whl")


# ---------------------------------------------------------------------------
# 3. Air-gap staging
# ---------------------------------------------------------------------------

def test_stage_sideload_layout_stages_every_wheel_on_every_arch(tmp_path):
    manifest = {
        "wheels": [{"name": "a", "version": "1", "filename": "a-1-py3-none-any.whl"}],
        "wheels_by_arch": {
            "x86_64": [{"name": "b", "version": "1", "filename": "b-1-cp312-x86_64.whl"}],
            "aarch64": [{"name": "b", "version": "1", "filename": "b-1-cp312-aarch64.whl"}],
        },
        "models": [{"name": "m", "hf_cache_dir": "m_dir",
                    "files": [{"name": "1_Pooling/config.json"}]}],
    }
    cache, staging = tmp_path / "cache", tmp_path / "staging"
    for arch, e in BUILDER.iter_wheel_entries(manifest):
        slot = BUILDER._cache_slot(cache, arch, e["filename"])
        slot.parent.mkdir(parents=True, exist_ok=True)
        slot.write_bytes(e["filename"].encode())
    model_slot = BUILDER._cache_slot(cache / "m", None, "1_Pooling_config.json")
    model_slot.parent.mkdir(parents=True, exist_ok=True)
    model_slot.write_bytes(b"{}")

    assert BUILDER.stage_sideload_layout(manifest, cache, staging) == (3, 1)
    for _arch, e in BUILDER.iter_wheel_entries(manifest):
        assert (staging / "wheels" / e["filename"]).read_bytes() == e["filename"].encode()
    assert (staging / "hf-cache" / "m_dir" / "1_Pooling" / "config.json").exists()

    model_slot.unlink()
    with pytest.raises(FileNotFoundError, match="Missing in cache"):
        BUILDER.stage_sideload_layout(manifest, cache, tmp_path / "staging2")


def test_the_pre_555_walk_misses_per_arch_wheels_on_the_real_manifest():
    """Teeth for the property above: the old walk is measurably incomplete."""
    manifest = _real_manifest()
    old = {e["filename"] for e in manifest.get("wheels", [])}
    full = {e["filename"] for _arch, e in BUILDER.iter_wheel_entries(manifest)}
    assert old < full


def test_download_script_stages_through_the_builder():
    text = DOWNLOAD_SCRIPT.read_text(encoding="utf-8")
    assert "stage_sideload_layout(" in text
    assert 'manifest.get("wheels"' not in text, "the script walks the manifest itself again"


# ---------------------------------------------------------------------------
# 4. Wiring (presence)
# ---------------------------------------------------------------------------

def _script_code() -> str:
    return "\n".join(
        line for line in AUDIT_SCRIPT.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def _services(code: str | None = None) -> list[str]:
    m = re.search(r"^SERVICES=\(([^)]*)\)", code if code is not None else _script_code(), re.M)
    assert m, "run-pip-audit.sh has no SERVICES=(...) array"
    return m.group(1).split()


def _calls_without_a_service(code: str) -> list[str]:
    calls = [l.strip() for l in code.splitlines() if re.match(r"\s*pip-audit\s", l)]
    assert calls, "no pip-audit call found in run-pip-audit.sh"
    return [c for c in calls if '-s "${service}"' not in c]


def test_every_leg_runs_under_pypi_and_osv():
    code = _script_code()
    assert {"pypi", "osv"} <= set(_services(code)), _services(code)
    assert _calls_without_a_service(code) == []
    assert len(re.findall(r'for service in "\$\{SERVICES\[@\]\}"; do', code)) >= 2, (
        "the main legs and the --installed-set legs must each loop over SERVICES")


def test_services_pin_has_teeth():
    code = _script_code()
    assert _services(code.replace("SERVICES=(pypi osv)", "SERVICES=(pypi)")) == ["pypi"]
    assert not {"pypi", "osv"} <= set(_services(code.replace("SERVICES=(pypi osv)", "SERVICES=(pypi)")))
    dropped = code.replace('-r "${view}" -s "${service}"', '-r "${view}"', 1)
    assert _calls_without_a_service(dropped), "a pip-audit call without -s was not caught"


def test_audit_script_audits_the_manifest_the_image_ships():
    copies = [
        text for _line, text in dockerfile_instructions(CONTAINERFILE.read_text(encoding="utf-8"))
        if text.split()[0].upper() == "COPY" and text.split()[-1].endswith("/embedding-bits-manifest.json")
    ]
    assert len({c.split()[-2] for c in copies}) == 1, f"ambiguous manifest COPY: {copies}"
    source = copies[0].split()[-2]
    code = _script_code()
    assert f'EMBEDDING_MANIFEST="${{REPO_ROOT}}/{source}"' in code
    assert 'audit_manifest "${EMBEDDING_MANIFEST}"' in code
    assert "--requirements-view" in code


def test_audit_script_manifest_leg_is_strict_and_not_swallowed():
    code = _script_code()
    leg = re.search(r'pip-audit "\$\{WAIVERS\[@\]\}" -r "\$\{view\}"([^\n]*)', code)
    assert leg, "the manifest leg's pip-audit invocation is gone"
    for flag in ("--strict", "--no-deps", "--disable-pip"):
        assert flag in leg.group(1), f"manifest leg lost {flag}"
    assert "exec pip-audit" not in code, "exec would end the script before the manifest leg"
    assert not re.search(r"audit_manifest[^\n]*\|\|\s*true", code), "a leg's failure is swallowed"
    assert re.search(r'audit_manifest "\$\{EMBEDDING_MANIFEST\}"[^\n]*\|\|\s*status=1', code)


def test_teeth_fixture_exercises_the_arch_walk_and_the_local_segment():
    code = _script_code()
    assert f'TEETH_MANIFEST="${{REPO_ROOT}}/{TEETH_REL}"' in code
    assert 'audit_manifest "${TEETH_MANIFEST}"' in code
    fixture = json.loads(TEETH_FIXTURE.read_text(encoding="utf-8"))
    per_arch_local = [e for arch, e in BUILDER.iter_wheel_entries(fixture)
                      if arch is not None and "+" in str(e["version"])]
    assert per_arch_local, "the teeth fixture no longer exercises the +local strip on a per-arch pin"
    assert BUILDER.requirements_view(fixture), "empty teeth view"


def test_security_workflow_runs_the_audit_script_on_every_trigger():
    wf = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    triggers = wf.get("on", wf.get(True))  # PyYAML reads a bare `on:` key as True
    for trig in ("push", "pull_request", "schedule"):
        assert trig in triggers, f"security.yml no longer runs on {trig}"
    job = wf["jobs"]["vulnerability-scan"]
    assert not job.get("continue-on-error")
    runs = [s for s in job["steps"] if "run-pip-audit.sh" in str(s.get("run", ""))]
    assert runs, "vulnerability-scan no longer runs scripts/run-pip-audit.sh"
    for step in runs:
        assert not step.get("continue-on-error")
        assert "|| true" not in step["run"]


# ---------------------------------------------------------------------------
# 4b. Punch 516: the audited environment holds every extra CI executes
# ---------------------------------------------------------------------------
# Leg 1 audits the environment the vulnerability-scan job builds. Until punch
# 516 that was requirements.lock plus `--no-deps -e .`, while tests.yml ran
# `.[dev,encryption]` and e2e.yml `.[dev,e2e]` on the same runners, so those
# packages executed in CI with no CVE scan. The property, over every step of
# every workflow: each extra any `pip install` names is installed by a
# vulnerability-scan step that runs BEFORE the step calling run-pip-audit.sh.
# Derived from the workflows, never a hand-kept list of extra names.
# An extra arrives two ways: a local-tree spec `.[a,b]`, or a repo-root
# `-r requirements*.lock`, which installs the extras its pip-compile header
# compiled in (punch 511: tests.yml takes dev+encryption from
# requirements-dev.lock and names no extra at all). Both sides credit a lock by
# its header. Fail closed: a `-r` file CI runs that is not a readable repo lock
# is an executed set nobody can audit, so it never matches; on the audited side
# it credits nothing.
# SCOPE: `run:` text only (the punch-511 pin's tokenizer: continuations joined,
# shell comments dropped). An extra installed through an action's `with:` input
# or a script a step calls is not seen.

# One `pip install` tokenizer and one lock reader (PD-5): the punch-511 pin's.
from test_punch511_ci_installs_are_hash_locked_pin import _pip_installs, _split_install_args, drift  # noqa: E402

WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
_SPEC_EXTRAS = re.compile(r"\[([^\]]*)\]")
_LOCAL_TREE_SPEC = frozenset({".", "./"})
_REPO_LOCK = re.compile(r"requirements[^/\\]*\.lock")


def _shell_code(run: str) -> str:
    """A step's `run:` text with backslash continuations joined and comment lines dropped."""
    text = re.sub(r"\\\r?\n", " ", run)
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _lock_extras(reqfile: str) -> set[str] | None:
    """The extras a repo-root lock's header compiled in; None when the file is not a
    readable repo-root lock (each caller fails closed its own way)."""
    path = REPO_ROOT / reqfile
    if path.parent != REPO_ROOT or not _REPO_LOCK.fullmatch(path.name) or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        drift.parse_lock(text, None)
    except (OSError, UnicodeDecodeError, drift.LockParseError):
        return None
    return {x.lower() for x in drift.header_extras(text)}


def _run_extras(run: str, *, executed: bool = True) -> set[str]:
    out: set[str] = set()
    for args in _pip_installs(run):
        _, reqfiles, specs = _split_install_args(args)
        for spec in specs:
            if spec.split("[", 1)[0] in _LOCAL_TREE_SPEC:
                out |= {x.strip().lower() for m in _SPEC_EXTRAS.finditer(spec)
                        for x in m.group(1).split(",") if x.strip()}
        for f in reqfiles:
            extras = _lock_extras(f)
            if extras is not None:
                out |= extras
            elif executed:
                out.add(f"<-r {f}: not a readable repo lock>")
    return out


def _executed_extras(workflows: dict[str, dict]) -> set[str]:
    return {
        x
        for wf in workflows.values()
        for job in (wf.get("jobs") or {}).values()
        for step in job.get("steps") or []
        for x in _run_extras(str(step.get("run", "")))
    }


def _unaudited_extras(workflows: dict[str, dict], scan_job: dict) -> set[str]:
    executed = _executed_extras(workflows)
    audited: set[str] = set()
    for step in scan_job.get("steps") or []:
        run = str(step.get("run", ""))
        # the audit step is the one whose CODE calls the script; a comment
        # naming it (security.yml's install step has one) is not the call
        if "run-pip-audit.sh" in _shell_code(run):
            break
        audited |= _run_extras(run, executed=False)
    else:
        return executed | {"<no run-pip-audit.sh step>"}
    return executed - audited


def _real_workflows() -> dict[str, dict]:
    return {
        Path(rel).name: yaml.safe_load(text) or {}
        for rel, text in workflow_texts(WORKFLOWS_DIR).items()
    }


def test_every_extra_ci_executes_is_in_the_audited_environment():
    workflows = _real_workflows()
    assert "dev" in _executed_extras(workflows), (
        "no workflow pip-installs the dev extra any more, or the extras walk stopped matching; "
        "this property would hold vacuously")
    scan_job = workflows["security.yml"]["jobs"]["vulnerability-scan"]
    missing = _unaudited_extras(workflows, scan_job)
    assert not missing, (
        f"extras installed by a CI workflow but absent from the environment "
        f"run-pip-audit.sh audits: {sorted(missing)}")


# hipaa-sme panel D LOW: an extras install without --no-deps can move a
# lock-pinned package (unhashed), and the scan then audits a version the image
# does not ship (fail-OPEN). Property: every such install in the scan job, before
# the audit step, is followed by a `--require-hashes --no-deps -r <repo lock>`
# re-pin, so the audited environment holds the lock's versions again.


def _is_lock_repin(args: list[str]) -> bool:
    flags, reqfiles, specs = _split_install_args(args)
    return (bool(reqfiles) and not specs and {"--require-hashes", "--no-deps"} <= flags
            and all(_lock_extras(f) is not None for f in reqfiles))


def _extras_installs_left_unpinned(scan_job: dict) -> list[str]:
    cmds: list[list[str]] = []
    for step in scan_job.get("steps") or []:
        run = str(step.get("run", ""))
        if "run-pip-audit.sh" in _shell_code(run):
            break
        cmds.extend(_pip_installs(run))
    out = []
    for i, args in enumerate(cmds):
        flags, _, specs = _split_install_args(args)
        resolves_extras = "--no-deps" not in flags and any(
            "[" in s and s.split("[", 1)[0] in _LOCAL_TREE_SPEC for s in specs)
        if resolves_extras and not any(_is_lock_repin(later) for later in cmds[i + 1:]):
            out.append(" ".join(["pip", "install", *args]))
    return out


def test_the_audited_environment_is_re_pinned_to_the_lock_after_an_extras_install():
    scan_job = _real_workflows()["security.yml"]["jobs"]["vulnerability-scan"]
    assert _extras_installs_left_unpinned(scan_job) == [], (
        "an extras install in the scan job can move a lock-pinned package; re-install the lock "
        "with `pip install --require-hashes --no-deps -r requirements-dev.lock` before the audit")


def test_extras_repin_pin_has_teeth():
    audit = {"run": "./scripts/run-pip-audit.sh"}
    lock = {"run": "pip install --require-hashes -r requirements-dev.lock\npip install --no-deps -e ."}
    extras = {"run": "pip install -e '.[e2e]'"}
    repin = {"run": "pip install --require-hashes --no-deps -r requirements-dev.lock"}
    assert _extras_installs_left_unpinned({"steps": [lock, extras, audit]}) == ["pip install -e .[e2e]"]
    assert _extras_installs_left_unpinned({"steps": [lock, extras, repin, audit]}) == []
    # the re-pin must come after the extras install and before the audit
    assert _extras_installs_left_unpinned({"steps": [lock, repin, extras, audit]}) == ["pip install -e .[e2e]"]
    assert _extras_installs_left_unpinned({"steps": [lock, extras, audit, repin]}) == ["pip install -e .[e2e]"]
    # a re-pin without --no-deps, without hashes, or of a non-lock does not count
    for weak in ("pip install --require-hashes -r requirements-dev.lock",
                 "pip install --no-deps -r requirements-dev.lock",
                 "pip install --require-hashes --no-deps -r pyproject.toml"):
        assert _extras_installs_left_unpinned({"steps": [lock, extras, {"run": weak}, audit]}), weak


def test_unaudited_extras_pin_has_teeth():
    other = {"tests.yml": {"jobs": {"t": {"steps": [
        {"run": "pip install -r requirements.lock\npip install \\\n  -e '.[dev,encryption]'"}]}}}}
    audit = {"run": "./scripts/run-pip-audit.sh"}
    lock = {"run": "pip install -r requirements.lock\npip install --no-deps -e ."}
    # the pre-516 shape: lock only
    assert _unaudited_extras(other, {"steps": [lock, audit]}) == {"dev", "encryption"}
    # installed, but AFTER the audit step: order matters, not presence
    late = {"run": "pip install -e '.[dev,encryption]'"}
    assert _unaudited_extras(other, {"steps": [lock, audit, late]}) == {"dev", "encryption"}
    # a commented-out install installs nothing
    commented = {"run": "# pip install -e '.[dev,encryption]'"}
    assert _unaudited_extras(other, {"steps": [lock, commented, audit]}) == {"dev", "encryption"}
    # a partial install leaves the rest
    assert _unaudited_extras(other, {"steps": [lock, {"run": "pip install -e '.[dev]'"}, audit]}) == {"encryption"}
    # a scan that skips the lock CI installs leaves the lock's header extras unaudited
    assert _unaudited_extras(other, {"steps": [late, audit]}) == drift.header_extras(
        (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8"))
    # no audit step at all is never a pass
    assert _unaudited_extras(other, {"steps": [late]})
    # the fixed shape
    assert _unaudited_extras(other, {"steps": [lock, late, audit]}) == set()
    # an install step whose COMMENT names the audit script is still an install step
    noted = {"run": "# the image set is audited by run-pip-audit.sh --installed-set\n"
                    "pip install -e '.[dev,encryption]'"}
    assert _unaudited_extras(other, {"steps": [lock, noted, audit]}) == set()


def test_unaudited_extras_pin_credits_a_lock_by_its_header():
    # punch 511 shape: the unit job names no extra, it installs the dev lock
    unit = {"tests.yml": {"jobs": {"t": {"steps": [
        {"run": "pip install --require-hashes -r requirements-dev.lock\npip install --no-deps -e ."}]}}}}
    assert {"dev", "encryption"} <= _executed_extras(unit), "the lock's header extras went uncredited"
    audit = {"run": "./scripts/run-pip-audit.sh"}
    prod_only = {"run": "pip install -r requirements.lock\npip install --no-deps -e ."}
    # the dev lock's extras beyond the image lock's (dev, encryption, and e2e since punch 622)
    dev_only = _lock_extras("requirements-dev.lock") - _lock_extras("requirements.lock")
    assert {"dev", "encryption"} <= dev_only
    assert _unaudited_extras(unit, {"steps": [prod_only, audit]}) == dev_only
    dev_lock = {"run": "pip install --require-hashes -r requirements-dev.lock\npip install --no-deps -e ."}
    assert _unaudited_extras(unit, {"steps": [dev_lock, audit]}) == set()
    # a requirements file CI runs that is not a readable repo lock can never be audited
    odd = {"x.yml": {"jobs": {"t": {"steps": [{"run": "pip install --require-hashes -r no-such.lock"}]}}}}
    assert _unaudited_extras(odd, {"steps": [dev_lock, odd["x.yml"]["jobs"]["t"]["steps"][0], audit]}) == {
        "<-r no-such.lock: not a readable repo lock>"}
    # and on the audited side it credits nothing
    fake = {"run": "pip install -r pyproject.toml"}
    assert _unaudited_extras(unit, {"steps": [fake, audit]}) == _executed_extras(unit)
    # a third-party spec's extras are not the project's
    assert _run_extras("pip install 'uvicorn[standard]'") == set()
    # a $RUNNER_TEMP file cut from a repo lock (class AJ fold F2) is credited as that lock; one nothing cut is not
    cut = "awk '/^packaging==/ {on=1} on {print}' requirements-ci-tools.lock > \"$RUNNER_TEMP/packaging.req\"\n"
    temp_install = 'pip install --require-hashes --no-deps --only-binary :all: -r "$RUNNER_TEMP/packaging.req"'
    assert _run_extras(cut + temp_install) == _lock_extras("requirements-ci-tools.lock")
    assert _run_extras(temp_install) == {"<-r $RUNNER_TEMP/packaging.req: not a readable repo lock>"}


# ---------------------------------------------------------------------------
# 5. Behaviour of run-pip-audit.sh itself (offline, stub pip-audit on PATH)
# ---------------------------------------------------------------------------
# db-555 F1: the presence checks above stayed green under three mutations of
# the script's EXIT PATH (`exit 0`, the teeth branch's `status=1` removed,
# leg 1's `|| true`). These arms run the real script end to end against a stub
# that records every call, so each leg's failure must reach the exit status,
# and the stub proves which views the script actually handed to pip-audit.

import os
import shutil
import subprocess

BASH = shutil.which("bash")

_STUB = r"""#!/usr/bin/env bash
rfile=""; ofile=""; svc="none"
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[$i]}" in
    -r) rfile="${args[$((i+1))]}" ;;
    -o) ofile="${args[$((i+1))]}" ;;
    -s) svc="${args[$((i+1))]}" ;;
  esac
done
n=$(ls "$STUB_DIR" | grep -c '^call-.*\.kind$')
printf '%s\n' "$@" > "$STUB_DIR/call-$n.argv"
echo "$svc" > "$STUB_DIR/call-$n.svc"
# per-service override: <kind>.<svc>.rc / .rows win over <kind>.rc / .rows
pick() { if [ -f "$STUB_DIR/$1.$svc.$2" ]; then echo "$STUB_DIR/$1.$svc.$2"; else echo "$STUB_DIR/$1.$2"; fi; }
if [ -z "$rfile" ]; then
  kind=env
else
  cp "$rfile" "$STUB_DIR/call-$n.view"
  if grep -q '^pillow==9\.0\.0' "$rfile"; then kind=teeth
  elif grep -q '^pip==25\.0\.1' "$rfile"; then kind=iteeth
  elif grep -q '^zz-ref-sentinel==' "$rfile"; then kind=sentinel
  else kind=manifest; fi
fi
echo "$kind" > "$STUB_DIR/call-$n.kind"
case "$kind" in
  env) ej="$(pick env json)"
       if [ -n "$ofile" ] && [ -f "$ej" ]; then cat "$ej" > "$ofile"; fi
       exit "$(cat "$(pick env rc)")" ;;
  manifest) exit "$(cat "$(pick manifest rc)")" ;;
  sentinel) echo "zz-ref-sentinel 1.0 SENTINEL-1 2.0"; exit 1 ;;
  teeth) cat "$(pick teeth rows)"; exit "$(cat "$(pick teeth rc)")" ;;
  iteeth) cat "$(pick iteeth rows)"; exit "$(cat "$(pick iteeth rc)")" ;;
esac
"""

_EDITABLE_SELF = {"name": "email-triage", "skip_reason": "distribution marked as editable"}
_CLEAN_DEP = {"name": "fastapi", "version": "1.0", "vulns": []}
_TEETH_ALL = "pillow 9.0.0 PYSEC-2022-10 9.0.1\ntorch  2.12.0 PYSEC-2025-194 2.13.0\n"


def _run_audit(tmp_path, *, env_rc=0, env_deps=(_EDITABLE_SELF, _CLEAN_DEP),
               manifest_rc=0, teeth_rc=1, teeth_rows=_TEETH_ALL,
               iteeth_rc=1, iteeth_rows="pip 25.0.1 GHSA-4xh5-x5gv-qwph 26.2\n", args=(),
               osv=None, script=AUDIT_SCRIPT):
    """``osv``: overrides that apply under the osv service ONLY, as
    {"manifest_rc": 1, "teeth_rows": "", "env_deps": (...), ...}.
    ``script``: the run-pip-audit.sh to run (a temp repo's copy for the --ref arms)."""
    assert BASH, "bash is required to run scripts/run-pip-audit.sh (a skip would be an uninvoked control)"
    stub_dir, bin_dir = tmp_path / "stub", tmp_path / "bin"
    stub_dir.mkdir()
    bin_dir.mkdir()
    if env_deps is not None:
        (stub_dir / "env.json").write_text(
            json.dumps({"dependencies": list(env_deps), "fixes": []}), encoding="utf-8")
    (stub_dir / "env.rc").write_text(str(env_rc), encoding="utf-8")
    (stub_dir / "manifest.rc").write_text(str(manifest_rc), encoding="utf-8")
    (stub_dir / "teeth.rc").write_text(str(teeth_rc), encoding="utf-8")
    (stub_dir / "teeth.rows").write_text(teeth_rows, encoding="utf-8", newline="\n")
    (stub_dir / "iteeth.rc").write_text(str(iteeth_rc), encoding="utf-8")
    (stub_dir / "iteeth.rows").write_text(iteeth_rows, encoding="utf-8", newline="\n")
    for key, value in (osv or {}).items():
        if key == "env_deps":
            (stub_dir / "env.osv.json").write_text(
                json.dumps({"dependencies": list(value), "fixes": []}), encoding="utf-8")
        else:
            kind, what = key.rsplit("_", 1)
            (stub_dir / f"{kind}.osv.{what}").write_text(str(value), encoding="utf-8", newline="\n")
    stub = bin_dir / "pip-audit"
    stub.write_text(_STUB, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    env = dict(os.environ, STUB_DIR=stub_dir.as_posix(),
               PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    proc = subprocess.run([BASH, script.as_posix(), *args], env=env, capture_output=True,
                          text=True, timeout=300)
    calls = []
    for kind_file in sorted(stub_dir.glob("call-*.kind"), key=lambda p: int(p.stem.split("-")[1])):
        stem = kind_file.with_suffix("")
        view = stem.with_suffix(".view")
        calls.append({
            "kind": kind_file.read_text(encoding="utf-8").strip(),
            "svc": stem.with_suffix(".svc").read_text(encoding="utf-8").strip(),
            "argv": stem.with_suffix(".argv").read_text(encoding="utf-8").split("\n"),
            "view": view.read_text(encoding="utf-8").split() if view.exists() else None,
        })
    return proc, calls


def _legs(kinds: list[str]) -> list[str]:
    return kinds * len(_services())


def test_audit_script_pass_arm_and_the_views_pip_audit_received(tmp_path):
    proc, calls = _run_audit(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c["kind"] for c in calls] == _legs(["env", "manifest", "teeth"])
    assert [c["svc"] for c in calls] == [s for s in _services() for _ in range(3)], (
        "every leg must run once under each service, in SERVICES order")
    fixture = json.loads(TEETH_FIXTURE.read_text(encoding="utf-8"))
    for i in range(0, len(calls), 3):
        env_call, manifest_call, teeth_call = calls[i:i + 3]
        assert manifest_call["view"] == BUILDER.requirements_view(_real_manifest())
        assert teeth_call["view"] == BUILDER.requirements_view(fixture)
        for flag in ("--strict", "--no-deps", "--disable-pip"):
            assert flag in manifest_call["argv"] and flag in teeth_call["argv"]
        assert "--skip-editable" in env_call["argv"] and "json" in env_call["argv"]
        assert "--strict" not in env_call["argv"], (
            "--strict on leg 1 makes the project's own editable dist fatal (pip-audit 2.10.0)")


@pytest.mark.parametrize("arm, overrides, needle", [
    ("env_rc", {"env_rc": 1}, None),
    ("env_json_vuln", {"env_deps": (_EDITABLE_SELF, {"name": "x", "version": "1",
                                                     "vulns": [{"id": "PYSEC-1", "fix_versions": ["2"]}]})},
     "PYSEC-1"),
    ("env_unknown_skip", {"env_deps": (_EDITABLE_SELF, {"name": "torch", "skip_reason":
                                                        "Dependency not found on PyPI and could not be audited"})},
     "SKIPPED, NOT AUDITED: torch"),
    ("env_self_other_reason", {"env_deps": ({"name": "email-triage", "skip_reason":
                                             "Dependency not found on PyPI and could not be audited"},)},
     "SKIPPED, NOT AUDITED: email-triage"),
    ("env_editable_other_name", {"env_deps": ({"name": "not-the-project",
                                               "skip_reason": "distribution marked as editable"},)},
     "SKIPPED, NOT AUDITED: not-the-project"),
    ("env_no_json", {"env_deps": None}, "unreadable"),
    ("manifest_rc", {"manifest_rc": 1}, None),
    ("teeth_silent", {"teeth_rc": 0, "teeth_rows": ""}, "TEETH FAILED"),
    ("teeth_missing_torch", {"teeth_rc": 1, "teeth_rows": "pillow 9.0.0 PYSEC-2022-10 9.0.1\n"},
     "TEETH FAILED"),
    # Under the osv service ONLY: the pypi pass is clean, so these prove a
    # second-service failure reaches the exit status (punch 573).
    ("osv_env_vuln", {"osv": {"env_deps": (_EDITABLE_SELF, {
        "name": "mako", "version": "1.4.1",
        "vulns": [{"id": "CVE-2026-102991", "fix_versions": ["1.4.2"]}]})}}, "CVE-2026-102991"),
    ("osv_env_rc", {"osv": {"env_rc": 1}}, None),
    ("osv_manifest_rc", {"osv": {"manifest_rc": 1}}, None),
    ("osv_teeth_silent", {"osv": {"teeth_rc": 0, "teeth_rows": ""}}, "TEETH FAILED [osv]"),
])
def test_audit_script_fails_when_any_leg_fails(tmp_path, arm, overrides, needle):
    proc, calls = _run_audit(tmp_path, **overrides)
    assert proc.returncode != 0, f"{arm}: script exited 0\n{proc.stdout}\n{proc.stderr}"
    assert [c["kind"] for c in calls] == _legs(["env", "manifest", "teeth"]), "a leg did not run"
    if needle:
        assert needle in proc.stdout + proc.stderr, f"{arm}: {needle!r} not reported"


# ---------------------------------------------------------------------------
# 5b. `--locks` (the pre-push hook): audit the LOCKS, never the ambient environment
# ---------------------------------------------------------------------------
# 2026-10-17: pre-push ran the script bare, so on a workstation leg 1 audited the
# global interpreter (measured rc=1 on pillow, pypdf and pyjwt, none of which any lock
# pins): a guard on the wrong object. `--locks` replaces leg 1 with one audit per lock
# over a name==version view lock_reader derives; the manifest legs still run.

# CI tools lock (punch 623), dev lock, image lock, the image's pip pin (requirements-pip.txt, N-621),
# the builder's toolchain pin (requirements-build.txt, punch 775; cycle P db P3 MUST-1: it was audited
# by no leg), lock teeth, embedding, its teeth. The locks run in the shell glob's order.
_LOCK_LEGS = ["manifest", "manifest", "manifest", "manifest", "manifest", "iteeth", "manifest", "teeth"]


def _lock_pins(name: str) -> list[str]:
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    return [f"{pkg}=={ver}" for pkg, ver in sorted(drift.parse_lock(text, None).pins.items())]


def test_locks_mode_audits_each_lock_view_and_never_the_environment(tmp_path):
    proc, calls = _run_audit(tmp_path, args=("--locks",))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c["kind"] for c in calls] == _LOCK_LEGS * len(_services()), [c["kind"] for c in calls]
    for i in range(0, len(calls), len(_LOCK_LEGS)):
        tools, dev, image, pip_pin, build, lock_teeth, embedding, _ = calls[i:i + len(_LOCK_LEGS)]
        assert tools["view"] == _lock_pins("requirements-ci-tools.lock")
        assert dev["view"] == _lock_pins("requirements-dev.lock")
        assert image["view"] == _lock_pins("requirements.lock")
        assert pip_pin["view"] == _lock_pins("requirements-pip.txt") and pip_pin["view"][0].startswith("pip==")
        assert build["view"] == _lock_pins("requirements-build.txt")
        assert any(p.startswith("wheel==") for p in build["view"]), build["view"]
        assert lock_teeth["view"] == ["pip==25.0.1"], "the project line must be dropped from the teeth view"
        assert embedding["view"] == BUILDER.requirements_view(_real_manifest())
    for call in calls:
        for flag in ("--strict", "--no-deps", "--disable-pip"):
            assert flag in call["argv"], (call["kind"], flag)
        assert "--skip-editable" not in call["argv"], "an environment audit ran under --locks"


def test_locks_mode_fails_closed_on_an_entry_the_view_cannot_decide(tmp_path):
    lock = tmp_path / "requirements-x.lock"
    lock.write_text('pkg-b==2.0\npkg-a==1.0 ; sys_platform == "win32"\n', encoding="utf-8", newline="\n")
    proc, calls = _run_audit(tmp_path, args=("--locks", lock.as_posix()))
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "refusing a partial audit" in proc.stdout + proc.stderr
    assert [c["kind"] for c in calls] == ["iteeth", "manifest", "teeth"] * len(_services()), (
        "the lock that could not be viewed must reach the exit status without a pip-audit call")


def test_locks_mode_teeth_fail_when_the_rig_stops_detecting(tmp_path):
    proc, _ = _run_audit(tmp_path, args=("--locks",), iteeth_rc=0, iteeth_rows="")
    assert proc.returncode != 0
    assert "TEETH FAILED" in proc.stdout + proc.stderr


def test_locks_mode_refuses_a_lock_that_is_not_a_file(tmp_path):
    proc, calls = _run_audit(tmp_path, args=("--locks", (tmp_path / "nope.lock").as_posix()))
    assert proc.returncode == 2 and calls == [], proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# 5c. `--locks --ref <rev>` (the pre-push hook, backlog row 2): the COMMITTED locks
# ---------------------------------------------------------------------------
# 2026-10-25: a shepherd pushed feat/v020-punch-668 (filelock 4.2.1) from a checkout at old
# main (filelock 4.1.1) and the hook audited the checkout's locks: a false RED. The reverse
# is a false PASS. These arms run the script inside a throwaway git repo so the working tree
# and the commit can disagree, both ways.

_REF_REPO_FILES = (
    "scripts/run-pip-audit.sh", "scripts/lock_reader.py", "scripts/build-embedding-bits-manifest.py",
    "scripts/embedding-bits-manifest.json", "requirements-ci-tools.lock", "requirements-dev.lock",
    "requirements.lock", "requirements-pip.txt", "requirements-build.txt", "Containerfile",
    "pyproject.toml", "tests/fixtures/installed_set_teeth.txt", "tests/fixtures/manifest_audit_teeth.json",
)
_SENTINEL = "zz-ref-sentinel==1.0\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", repo.as_posix(), "-c", "user.name=t", "-c", "user.email=t@t",
                           "-c", "core.autocrlf=false", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _ref_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for rel in _REF_REPO_FILES:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / rel, repo / rel)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "clean")
    return repo


def test_ref_mode_ignores_a_dirty_working_tree_lock(tmp_path):
    """A vulnerable lock in the WORKING TREE must not change the verdict for a clean commit."""
    repo = _ref_repo(tmp_path)
    clean = (repo / "requirements.lock").read_text(encoding="utf-8")
    with (repo / "requirements.lock").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(_SENTINEL)
    proc, calls = _run_audit(tmp_path, args=("--locks", "--ref", "HEAD"), script=repo / "scripts" / "run-pip-audit.sh")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "sentinel" not in [c["kind"] for c in calls], "the working tree's lock reached pip-audit"
    assert [c["kind"] for c in calls] == _LOCK_LEGS * len(_services()), [c["kind"] for c in calls]
    image = calls[2]
    committed = [f"{p}=={v}" for p, v in sorted(drift.parse_lock(clean, None).pins.items())]
    assert image["view"] == committed
    sha = _git(repo, "rev-parse", "HEAD")
    assert f"lock {sha}:requirements.lock [" in proc.stdout, "the log must name the audited object as <rev>:<path>"


def test_ref_mode_fails_on_a_committed_lock_the_working_tree_hides(tmp_path):
    """A vulnerable lock in the COMMIT must fail even when the working tree is clean."""
    repo = _ref_repo(tmp_path)
    lock = repo / "requirements-dev.lock"
    clean = lock.read_text(encoding="utf-8")
    with lock.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(_SENTINEL)
    _git(repo, "commit", "-q", "-am", "vulnerable")
    lock.write_text(clean, encoding="utf-8", newline="\n")
    proc, calls = _run_audit(tmp_path, args=("--locks", "--ref", "HEAD"), script=repo / "scripts" / "run-pip-audit.sh")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "SENTINEL-1" in proc.stdout
    assert [c["kind"] for c in calls].count("sentinel") == len(_services())


@pytest.mark.parametrize("arm", ["not_a_commit", "missing_pip_pin"])
def test_ref_mode_fails_closed_when_the_commit_cannot_be_read(tmp_path, arm):
    repo = _ref_repo(tmp_path)
    ref = "no-such-ref"
    if arm == "missing_pip_pin":
        _git(repo, "rm", "-q", "requirements-pip.txt")
        _git(repo, "commit", "-q", "-m", "drop the pip pin")
        ref = "HEAD"
    proc, calls = _run_audit(tmp_path, args=("--locks", "--ref", ref), script=repo / "scripts" / "run-pip-audit.sh")
    assert proc.returncode == 2 and calls == [], proc.stdout + proc.stderr
    assert "nothing was audited" in proc.stderr


def test_ref_mode_audits_the_build_toolchain_pin_and_tolerates_a_ref_from_before_it(tmp_path):
    """Cycle P db P3 MUST-1: requirements-build.txt is a leg in --ref mode too. A commit from
    before punch 775 has no such file and no Containerfile that installs it: it is audited
    without it, and the log says so. A commit whose Containerfile installs it but which lacks
    the file is unreadable, exit 2 (a pin the build uses is never skipped silently)."""
    repo = _ref_repo(tmp_path)
    script = repo / "scripts" / "run-pip-audit.sh"
    proc, calls = _run_audit(tmp_path, args=("--locks", "--ref", "HEAD"), script=script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sha = _git(repo, "rev-parse", "HEAD")
    assert f"lock {sha}:requirements-build.txt [" in proc.stdout

    _git(repo, "rm", "-q", "requirements-build.txt")
    _git(repo, "commit", "-q", "-m", "file gone, Containerfile still installs it")
    (tmp_path / "b").mkdir()
    (tmp_path / "c").mkdir()
    proc, calls = _run_audit(tmp_path / "b", args=("--locks", "--ref", "HEAD"), script=script)
    assert proc.returncode == 2 and calls == [], proc.stdout + proc.stderr
    assert "nothing was audited" in proc.stderr

    cf = repo / "Containerfile"
    cf.write_text("\n".join(ln for ln in cf.read_text(encoding="utf-8").splitlines()
                            if "requirements-build" not in ln) + "\n", encoding="utf-8", newline="\n")
    _git(repo, "commit", "-q", "-am", "a pre-775 shape")
    proc, calls = _run_audit(tmp_path / "c", args=("--locks", "--ref", "HEAD"), script=script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pre775 = _LOCK_LEGS[:4] + _LOCK_LEGS[5:]  # the four locks, no build leg
    assert [c["kind"] for c in calls] == pre775 * len(_services()), [c["kind"] for c in calls]
    assert "predates the build toolchain pin" in proc.stdout


# The hook's own call (`"$SCRIPT" --locks`) is pinned in tests/test_pre_push_hook_audits_locks_pin.py, a
# stripped sibling: scripts/git-hooks/pre-push does not ship, so a shipped test may not read it.


# ---------------------------------------------------------------------------
# 6. DA-555-1: network-import acceptances are file-scoped and durable
# ---------------------------------------------------------------------------

def _wheel_with(path: Path, name: str, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name}-1.0.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
        for member, body in members.items():
            z.writestr(member, body)
    return path


def _audit_manifest(prior: dict | None) -> dict:
    m = {"wheels": [{"name": "netpkg", "version": "1.0",
                     "filename": "netpkg-1.0-py3-none-any.whl"}]}
    if prior is not None:
        m["regeneration_audit"] = prior
    return m


_CONTRIB_ONLY = {"netpkg/__init__.py": "import json\n",
                 "netpkg/contrib/tg.py": "from requests import Session\n"}
_CORE_TOO = dict(_CONTRIB_ONLY, **{"netpkg/core.py": "import requests\n"})


def _paths(tmp_path, members):
    whl = _wheel_with(tmp_path / "netpkg-1.0-py3-none-any.whl", "netpkg", members)
    return {(None, "netpkg-1.0-py3-none-any.whl"): whl}


def test_hits_are_recorded_per_file(tmp_path):
    whl = _wheel_with(tmp_path / "w.whl", "netpkg", _CORE_TOO)
    assert BUILDER._network_import_hits(whl) == [
        "netpkg/contrib/tg.py:requests", "netpkg/core.py:requests"]


def test_an_acceptance_is_carried_forward_and_may_be_restated(tmp_path):
    accepted = ["netpkg/contrib/tg.py:requests"]
    prior = {"package_set": ["netpkg"], "network_import_hits": {"netpkg": accepted},
             "accepted_network_imports": {"netpkg": accepted}}
    paths = _paths(tmp_path, _CONTRIB_ONLY)
    audit = BUILDER.record_regeneration_audit(_audit_manifest(json.loads(json.dumps(prior))), paths)
    assert audit["accepted_network_imports"] == {"netpkg": accepted}, "the next regeneration erased it"
    audit = BUILDER.record_regeneration_audit(
        _audit_manifest(json.loads(json.dumps(prior))), paths, accepted_network_imports=["netpkg"])
    assert audit["accepted_network_imports"] == {"netpkg": accepted}


def test_a_grown_file_level_hit_set_refuses_until_reaccepted(tmp_path):
    accepted = ["netpkg/contrib/tg.py:requests"]
    prior = {"package_set": ["netpkg"], "network_import_hits": {"netpkg": accepted},
             "accepted_network_imports": {"netpkg": accepted}}
    paths = _paths(tmp_path, _CORE_TOO)
    with pytest.raises(RuntimeError, match="GROWS"):
        BUILDER.record_regeneration_audit(_audit_manifest(json.loads(json.dumps(prior))), paths)
    audit = BUILDER.record_regeneration_audit(
        _audit_manifest(json.loads(json.dumps(prior))), paths, accepted_network_imports=["netpkg"])
    assert audit["accepted_network_imports"]["netpkg"] == [
        "netpkg/contrib/tg.py:requests", "netpkg/core.py:requests"]


def test_an_unaccepted_present_package_that_grows_refuses(tmp_path):
    prior = {"package_set": ["netpkg"],
             "network_import_hits": {"netpkg": ["netpkg/contrib/tg.py:requests"]}}
    with pytest.raises(RuntimeError, match="GROWS"):
        BUILDER.record_regeneration_audit(_audit_manifest(prior), _paths(tmp_path, _CORE_TOO))


def test_a_legacy_needle_record_migrates_but_does_not_cover_a_new_needle(tmp_path):
    prior = {"package_set": ["netpkg"], "network_import_hits": {"netpkg": ["requests"]},
             "accepted_network_imports": {"netpkg": ["requests"]}}
    audit = BUILDER.record_regeneration_audit(
        _audit_manifest(json.loads(json.dumps(prior))), _paths(tmp_path, _CORE_TOO))
    assert audit["accepted_network_imports"]["netpkg"] == [
        "netpkg/contrib/tg.py:requests", "netpkg/core.py:requests"]
    sock = dict(_CONTRIB_ONLY, **{"netpkg/net.py": "import socket\n"})
    (tmp_path / "s").mkdir()
    with pytest.raises(RuntimeError, match="GROWS"):
        BUILDER.record_regeneration_audit(
            _audit_manifest(json.loads(json.dumps(prior))), _paths(tmp_path / "s", sock))


def test_naming_a_package_nothing_asked_about_still_refuses(tmp_path):
    prior = {"package_set": ["netpkg"], "network_import_hits": {}, "accepted_network_imports": {}}
    with pytest.raises(RuntimeError, match="nothing asked for"):
        BUILDER.record_regeneration_audit(
            _audit_manifest(prior), _paths(tmp_path, {"netpkg/__init__.py": "import json\n"}),
            accepted_network_imports=["netpkg"])


def test_the_shipped_tqdm_acceptance_is_file_scoped_to_contrib():
    audit = _real_manifest()["regeneration_audit"]
    tqdm = audit["accepted_network_imports"]["tqdm"]
    assert tqdm and all(h.startswith("tqdm/contrib/") for h in tqdm), tqdm
    assert audit["network_import_hits"]["tqdm"] == tqdm


# ---------------------------------------------------------------------------
# 7. DA-555-2: the COMMITTED manifest is re-verified against the publishers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("arm", ["match", "mismatch", "unverifiable"])
def test_verify_publishers_both_arms(monkeypatch, arm):
    manifest = {"wheels": [{"name": "a", "version": "1", "filename": "a-1-py3-none-any.whl",
                            "url": f"https://{BUILDER.PYPI_FILES_HOST}/p/a-1-py3-none-any.whl",
                            "sha256": "ab" * 32}], "wheels_by_arch": {}}

    def fake(entry, url):
        if arm == "unverifiable":
            raise RuntimeError("index unreachable")
        return "ab" * 32 if arm == "match" else "cd" * 32

    monkeypatch.setattr(BUILDER, "_publisher_sha256", fake)
    problems = BUILDER.verify_publishers(manifest)
    assert (problems == []) == (arm == "match"), problems
    assert BUILDER.verify_publishers({"wheels": [], "wheels_by_arch": {}}), "empty must not pass"


def test_verify_publishers_cli_exit_status(monkeypatch, tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"wheels": [{"name": "a", "version": "1", "filename": "f",
                                            "url": "u", "sha256": "x"}]}), encoding="utf-8")
    monkeypatch.setattr(BUILDER, "_publisher_sha256", lambda e, u: "y" * 64)
    assert BUILDER.main(["--output", str(path), "--verify-publishers"]) == 1
    monkeypatch.setattr(BUILDER, "_publisher_sha256", lambda e, u: "x")
    assert BUILDER.main(["--output", str(path), "--verify-publishers"]) == 0


def test_security_workflow_verifies_the_committed_manifest_against_publishers():
    wf = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    job = wf["jobs"]["vulnerability-scan"]
    steps = [s for s in job["steps"] if "--verify-publishers" in str(s.get("run", ""))]
    assert steps, "no CI step re-verifies the committed manifest against its publishers"
    for step in steps:
        assert not step.get("continue-on-error") and "|| true" not in step["run"]
        assert "build-embedding-bits-manifest.py" in step["run"]


# ---------------------------------------------------------------------------
# 8. N-552: model files are pinned, pickle-free and publisher-verified
# ---------------------------------------------------------------------------

_REV = "a" * 40
_REPO = "org/model"


def _hf_url(path, rev=_REV):
    return f"https://huggingface.co/{_REPO}/resolve/{rev}/{path}"


@pytest.fixture
def hf_tree(monkeypatch):
    tree = {}
    monkeypatch.setattr(BUILDER, "_hf_tree", lambda repo, rev: tree)
    return tree


def test_every_shipped_model_file_is_pinned_and_pickle_free():
    for model in _real_manifest()["models"]:
        assert BUILDER._COMMIT_SHA.fullmatch(model["url"].rstrip("/").rsplit("/", 1)[-1])
        for f in model["files"]:
            m = BUILDER._HF_RESOLVE.match(f["url"])
            assert m and BUILDER._COMMIT_SHA.fullmatch(m["rev"]), f["url"]
            assert not f["name"].endswith((".bin", ".pt", ".pth", ".pkl", ".ckpt")), (
                f"{model['name']}/{f['name']}: a pickle-format weight file")
        assert any(f["name"] == "model.safetensors" for f in model["files"])


def test_a_mutable_ref_is_refused_before_any_download():
    with pytest.raises(RuntimeError, match="mutable ref"):
        BUILDER._hf_publisher_oid(_hf_url("model.safetensors", rev="main"))


@pytest.mark.parametrize("arm", ["lfs_match", "lfs_mismatch", "git_match", "git_mismatch"])
def test_verify_model_file_both_arms_for_lfs_and_git(tmp_path, hf_tree, arm):
    data = b'{"hidden_size": 384}'
    path = tmp_path / "f"
    path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    if arm.startswith("lfs"):
        hf_tree["f"] = {"path": "f", "lfs": {"oid": sha if arm == "lfs_match" else "0" * 64}}
    else:
        good = BUILDER._git_blob_sha1(data)
        hf_tree["f"] = {"path": "f", "oid": good if arm == "git_match" else "0" * 40}
    if arm.endswith("match") and not arm.endswith("mismatch"):
        BUILDER._verify_model_file(label="m/f", url=_hf_url("f"), sha256=sha, path=path)
        assert path.exists()
    else:
        with pytest.raises(RuntimeError, match="REFUSING m/f"):
            BUILDER._verify_model_file(label="m/f", url=_hf_url("f"), sha256=sha, path=path)
        assert not path.exists(), "the refused bytes stayed in the cache"


def test_git_blob_sha1_is_gits_object_id():
    # `git hash-object` of b"hello\n" — a fixed, published value.
    assert BUILDER._git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_verify_publishers_covers_model_files(hf_tree, monkeypatch):
    sha = "ab" * 32
    hf_tree["model.safetensors"] = {"path": "model.safetensors", "lfs": {"oid": sha}}
    monkeypatch.setattr(BUILDER, "_publisher_sha256", lambda e, u: e["sha256"])
    manifest = {"wheels": [{"name": "a", "version": "1", "filename": "a", "url": "u", "sha256": "x"}],
                "models": [{"name": "m", "files": [{"name": "model.safetensors",
                                                      "url": _hf_url("model.safetensors"),
                                                      "sha256": sha}]}]}
    assert BUILDER.verify_publishers(manifest) == []
    manifest["models"][0]["files"][0]["sha256"] = "cd" * 32
    assert BUILDER.verify_publishers(manifest)
    manifest["models"][0]["files"][0]["url"] = _hf_url("model.safetensors", rev="main")
    assert any("mutable ref" in p for p in BUILDER.verify_publishers(manifest))


# ---------------------------------------------------------------------------
# 9. N-553: the image's own pip — the Containerfile floor, and the
#    --installed-set audit mode the built-image leg calls
# ---------------------------------------------------------------------------

import re as _re

#: N-553 floored the image's pip at 26.2; N-621 (2026-10-20) made it a hash pin at 26.2.2,
#: the first release whose vendored certifi is outside GHSA-6q48-6c7w-9gw2.
_PIP_FLOOR = (26, 2, 2)
_PIP_PIN_FILE = REPO_ROOT / "requirements-pip.txt"


def test_runtime_stage_floors_pip_after_the_builder_copy_and_before_user():
    """The runtime stage installs pip from requirements-pip.txt in hash-checking mode,
    between the builder COPY and USER, and that file pins a version at or above the floor,
    every requirement line hashed."""
    stages = dict(dockerfile_stages(CONTAINERFILE.read_text(encoding="utf-8")))
    runtime = [text for _line, text in stages["runtime"]]
    copy_idx = max(i for i, t in enumerate(runtime) if t.upper().startswith("COPY --FROM=BUILDER"))
    user_idx = next(i for i, t in enumerate(runtime) if t.upper().startswith("USER "))
    installs = [
        i for i, t in enumerate(runtime) if t.upper().startswith("RUN ")
        and _re.search(r"-r\s+\S*requirements-pip\.txt\b", t) and "--require-hashes" in t
    ]
    assert installs, "the runtime stage no longer installs its hash-pinned pip (N-553, N-621)"
    assert any(copy_idx < i < user_idx for i in installs), (copy_idx, installs, user_idx)
    text = _PIP_PIN_FILE.read_text(encoding="utf-8")
    reqs = _re.findall(r"^(?!#)(\S+?)==(\S+?)\s*\\?\s*$((?:\s*--hash=sha256:[0-9a-f]{64}\s*\\?)*)", text, _re.M)
    assert [r[0] for r in reqs] == ["pip"], f"requirements-pip.txt must pin pip and only pip: {reqs}"
    version = tuple(int(x) for x in reqs[0][1].split("."))
    assert version >= _PIP_FLOOR, (version, _PIP_FLOOR)
    assert reqs[0][2].count("--hash=sha256:") >= 1, "the pip pin is not hashed"


# 9b. N-621 / panel J (J1 + DA-1): the system CA store drops exactly emSign ECC Root CA - G3
#     and AAA Certificate Services (its Sectigo cross-signs carry the compromised eMudhra keys),
#     and the build proves it by certificate content. The G3 fingerprint was taken from the G3
#     PEM in certifi 2026.05.20 (subject CN "emSign ECC Root CA - G3", parsed with
#     cryptography); both were re-derived 2026-10-21 from the DER of the files under
#     /usr/share/ca-certificates/mozilla/ inside python:3.12-slim (digest 2b4f19da…4ffe).
_G3_SHA256 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
_G3_CONF = "mozilla/emSign_ECC_Root_CA_-_G3.crt"
_AAA_SHA256 = "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"
_AAA_CONF = "mozilla/Comodo_AAA_Services_root.crt"
#: the roots that must stay trusted: the emSign roots certifi 2026.10.19 restored, and
#: USERTrust RSA (Sectigo's current root, which AAA's removal must not take with it).
_EMSIGN_KEEP = ("emSign_Root_CA_-_C1", "emSign_ECC_Root_CA_-_C3", "emSign_Root_CA_-_G1", "USERTrust")


#: Punch 652: the N-621 step as an AST, one (role, statement) per top-level statement, in
#: order. Assert messages and print arguments are free text and are NOT part of the shape,
#: but they must stay inert (_INERT_CALLS): a message runs only when its assert fails, so a
#: message that exits 0 would turn a failed check into a passing build.
_N621_SHAPE: tuple[tuple[str, str], ...] = (
    ("the imports", "import base64, glob, hashlib, os, re, subprocess"),
    ("the distrust map D (each SHA-256 bound to its conf entry)",
     f"D = {{{_G3_SHA256!r}: {_G3_CONF!r}, {_AAA_SHA256!r}: {_AAA_CONF!r}}}"),
    ("the bundle path B", "B = '/etc/ssl/certs/ca-certificates.crt'"),
    ("the conf path C", "C = '/etc/ca-certificates.conf'"),
    ("the shipped-certificate dir S (655)", "S = '/usr/share/ca-certificates/'"),
    ("the DER SHA-256 parser fps",
     "fps = lambda p: [hashlib.sha256(base64.b64decode(''.join(b.split()))).hexdigest() "
     "for b in re.findall('-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', "
     "open(p, errors='replace').read(), re.S)]"),
    ("the bundle read before anything changes", "pre = fps(B)"),
    ("the pre-size assert (the parser is not blind)", "assert len(pre) > 100"),
    ("the conf read", "lines = open(C).read().splitlines()"),
    ("the enabled test: one enabled conf line AND a shipped file (655)",
     "on = lambda f: lines.count(D[f]) == 1 and os.path.isfile(S + D[f])"),
    ("the J-F1 biconditional (a wrong fingerprint fails, never skips)",
     "assert all((f in pre) == on(f) for f in D)"),
    ("bad = the distrusted roots present", "bad = [D[f] for f in D if f in pre]"),
    ("the conf rewrite, only for the roots present",
     "bad and open(C, 'w').write(chr(10).join('!' + x if x in bad else x for x in lines) + chr(10))"),
    ("the --fresh rebuild, only for the roots present (653)",
     "bad and subprocess.run(['update-ca-certificates', '--fresh'], check=True)"),
    ("the already-absent notice", "[print() for f in D if f not in pre]"),
    ("the bundle read afterwards", "after = fps(B)"),
    ("the CApath scan of every file in /etc/ssl/certs (653)",
     "capath = [h for p in sorted(glob.glob('/etc/ssl/certs/*')) if os.path.isfile(p) for h in fps(p)]"),
    ("the certifi bundle path K (panel L DA-5)",
     "K = glob.glob('/usr/local/lib/python3*/site-packages/certifi/cacert.pem')"),
    ("the exactly-one-certifi-bundle assert", "assert len(K) == 1"),
    ("the certifi bundle read", "certifi = fps(K[0])"),
    ("the certifi size assert (the parser is not blind)", "assert len(certifi) > 100"),
    ("the absent-after assert over the bundle, the CApath files AND certifi",
     "assert not [f for f in D if f in after or f in capath or f in certifi]"),
    ("the post-size assert (the bundle is still full)", "assert len(after) > 100"),
    ("the closing print", "print()"),
)

#: The calls an assert message or a print argument may make: pure reads.
_INERT_CALLS = frozenset({"len", "lines.count", "os.path.isfile"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return "?"


def _free_text(tree: ast.AST) -> list[ast.AST]:
    """Every assert message and every print argument: the parts _N621_SHAPE ignores."""
    out: list[ast.AST] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assert) and n.msg is not None:
            out.append(n.msg)
        elif isinstance(n, ast.Call) and _dotted(n.func) == "print":
            out += n.args + [k.value for k in n.keywords]
    return out


def _strip_free_text(tree: ast.AST) -> ast.AST:
    for n in ast.walk(tree):
        if isinstance(n, ast.Assert):
            n.msg = None
        elif isinstance(n, ast.Call) and _dotted(n.func) == "print":
            n.args, n.keywords = [], []
    return tree


def _n621_body(instr: str) -> str | None:
    """The ``python -I -S -c`` program a RUN executes, or None if it is not exactly that.

    The instruction is joined as Docker joins it (:func:`dockerfile_shell_text`), then
    split as /bin/sh splits it. The body must hold no ``$``, backquote or backslash, so
    the shell passes it to Python byte for byte; anything chained after the command
    (``&& true``) makes it not exactly one ``python -I -S -c``. Panel L db D3(a): ``-I -S``
    is required because without it ``site`` runs every ``.pth`` in site-packages before
    the body, and one that exits 0 would pass the step unrun."""
    line = dockerfile_shell_text(instr)
    if not line.upper().startswith("RUN ") or any(c in line for c in "$`\\"):
        return None
    try:
        argv = shlex.split(line[4:])
    except ValueError:
        return None
    return argv[4] if len(argv) == 5 and argv[:4] == ["python", "-I", "-S", "-c"] else None


def _n621_ast_problems(body: str) -> list[str]:
    try:
        tree = ast.parse(body)
    except SyntaxError as e:
        return [f"the step's python -c body does not parse: {e}"]
    problems = [f"an assert message or print argument calls {_dotted(c.func)}(); only "
                f"{sorted(_INERT_CALLS)} may run there"
                for part in _free_text(tree) for c in ast.walk(part)
                if isinstance(c, ast.Call) and _dotted(c.func) not in _INERT_CALLS]
    problems += ["an assert message or print argument assigns, defines or awaits"
                 for part in _free_text(tree) for c in ast.walk(part)
                 if isinstance(c, (ast.NamedExpr, ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom))]
    got = [ast.dump(s) for s in _strip_free_text(tree).body]
    want = [ast.dump(s) for _role, src in _N621_SHAPE for s in ast.parse(src).body]
    roles = [role for role, _src in _N621_SHAPE]
    for i, (g, w) in enumerate(zip(got, want)):
        if g != w:
            problems.append(f"statement {i + 1} is not {roles[i]}: {ast.unparse(_strip_free_text(ast.parse(body)).body[i])!r}")
            break
    if len(got) < len(want):
        problems.append(f"the step stops before {roles[len(got)]} (a '#' in the body, or a dropped statement)")
    elif len(got) > len(want):
        problems.append(f"the step runs {len(got) - len(want)} statement(s) beyond its shape, "
                        "e.g. an unconditional present-before check")
    return problems


#: A runtime RUN after the distrust step must not touch packages or the trust store (654).
_TRUST_STORE_TOUCH = re.compile(r"\b(apt-get|apt|aptitude|dpkg)\b|ca-certificates|/etc/ssl|c_rehash|\brehash\b")


def _g3_problems(containerfile: str) -> list[str]:
    stage_list = dockerfile_stages(containerfile)
    stages = dict(stage_list)
    runtime = [text for _line, text in stages["runtime"]]
    # Panel L db D3(b): a SHELL instruction can turn the shell-form step into a no-op
    # (SHELL ["/bin/true", "-c"]); (c): a stage after runtime would escape the 654 check.
    early = [f"the runtime stage has a SHELL instruction ({t!r}); the G3 step must run under /bin/sh"
             for t in runtime if t.split(None, 1)[0].upper() == "SHELL"]
    if stage_list[-1][0] != "runtime":
        early.append(f"the runtime stage is not the last stage (the last is {stage_list[-1][0]!r}), "
                     "so the 654 check does not see every later RUN")
    copy_idx = max(i for i, t in enumerate(runtime) if t.upper().startswith("COPY --FROM=BUILDER"))
    user_idx = next(i for i, t in enumerate(runtime) if t.upper().startswith("USER "))
    runs = [(i, t) for i, t in enumerate(runtime) if t.upper().startswith("RUN ")]
    steps = [(i, t) for i, t in runs if "update-ca-certificates" in t]
    if not steps:
        return early + ["no runtime RUN rebuilds the system CA bundle (N-621)"]
    problems = early
    i, t = steps[0]
    if not copy_idx < i < user_idx:
        problems.append(f"the G3 step must run as root after the builder COPY ({copy_idx}) and before USER ({user_idx}); it is at {i}")
    # 654: the step is the last word on the trust store. Every package step comes before it,
    # and nothing after it in the runtime stage names a package tool or the store.
    problems += [f"runtime RUN {j} touches packages or the trust store after the G3 step ({i}); "
                 "the step must run after the last apt step (punch 654)"
                 for j, u in runs if j > i and _TRUST_STORE_TOUCH.search(u)]
    body = _n621_body(t)
    if body is None:
        problems.append("the G3 step is no longer exactly one shell-literal `python -I -S -c \"...\"`")
    else:
        problems += _n621_ast_problems(body)
    return problems


def test_runtime_stage_drops_the_g3_and_aaa_roots_by_content():
    assert _g3_problems(CONTAINERFILE.read_text(encoding="utf-8")) == []


_ON = "on = lambda f: lines.count(D[f]) == 1 and os.path.isfile(S + D[f]); "
_BICONDITIONAL = "assert all((f in pre) == on(f) for f in D)"
_ABSENT_AFTER = "assert not [f for f in D if f in after or f in capath or f in certifi], "


@pytest.mark.parametrize("old,new", [
    # 652: the shapes a text pin missed.
    ("after = fps(B); \\", "after = fps(B); # \\"),                                  # an inline '#'
    ("for f in D), ('N-621: a distrusted root must", "for f in D) or True, ('N-621: a distrusted root must"),
    ("pre = fps(B); \\", f"pre = fps(B); pre.index('{_G3_SHA256}'); \\"),            # respelled present-before
    ("pre = fps(B); \\", f"pre = fps(B); assert ('{_G3_SHA256}' in pre), 'x'; \\"),  # respelled present-before
    ("assert len(after) > 100, ('N-621: the system bundle is nearly empty', len(after))",
     "assert len(after) > 100, os._exit(0)"),                                         # a message that exits 0
    ("'already absent upstream')", "'already absent upstream', sys.exit(0))"),       # a print that exits 0
    ("'already absent upstream')", "'already absent upstream $HOME')"),               # shell expansion
    ("'certifi roots')\"", "'certifi roots')\" && true"),                            # chained after python
    # Panel L db D3(a): site (and every .pth) would run before the body.
    ("RUN python -I -S -c \"import base64", "RUN python -c \"import base64"),
    ("RUN python -I -S -c \"import base64", "RUN python -I -c \"import base64"),
    # Panel L DA-5: the certifi bundle.
    (_ABSENT_AFTER, "assert not [f for f in D if f in after or f in capath], "),      # certifi not checked
    ("assert len(certifi) > 100, ", "print(len(certifi)), "),                         # certifi parser could be blind
    ("assert len(K) == 1, ", "print(K), "),                                           # no exactly-one check
    ("site-packages/certifi/cacert.pem'", "site-packages/pip/_vendor/certifi/cacert.pem'"),  # the wrong certifi
    # 653 / 655.
    ("['update-ca-certificates', '--fresh']", "['update-ca-certificates']"),          # --fresh dropped
    (_ABSENT_AFTER, "assert not [f for f in D if f in after or f in certifi], "),     # CApath not scanned
    (_ON, "on = lambda f: lines.count(D[f]) == 1; "),                                 # stale-line shape fails again
    # The J-F1 shape (carried over from the text pin).
    (_ABSENT_AFTER, "print([f for f in D if f in after]), "),                         # absent-after dropped
    ("pre = fps(B); \\", "pre = fps(B); assert all(f in pre for f in D), 'x'; \\"),  # unconditional before-check
    ("assert len(pre) > 100, ", "print(len(pre)), "),                                 # the parser could be blind
    ("assert len(after) > 100, ", "print(len(after)), "),                             # an emptied bundle passes
    (_BICONDITIONAL, "assert all(on(f) for f in D)"),                                 # unconditional conf check
    (_BICONDITIONAL, "assert all(f not in pre or on(f) for f in D)"),                 # one-sided: a wrong fingerprint skips
    ("bad and open(C, 'w')", "open(C, 'w')"),                                         # unconditional rewrite
    ("'!' + x if x in bad", "x if x in bad"),                                         # nothing is disabled
    ("emSign_ECC_Root_CA_-_G3.crt'", "emSign_Root_CA_-_C1.crt'"),                     # the wrong root for G3
    (_G3_SHA256, "0" * 64),                                                           # a fingerprint that is not G3's
    (f", '{_AAA_SHA256}': '{_AAA_CONF}'", ""),                                        # AAA dropped from the distrust list
    (_AAA_SHA256, "0" * 64),                                                          # a fingerprint that is not AAA's
    ("Comodo_AAA_Services_root.crt'", "USERTrust_RSA_Certification_Authority.crt'"),  # the wrong root for AAA
    ("subprocess.run(['update-ca-certificates'", "subprocess.run(['true'"),           # no rebuild
], ids=["inline_hash", "or_true", "pre_index", "assert_in_pre", "msg_exits_0", "print_exits_0",
        "shell_expansion", "chained_command", "site_runs", "site_runs_without_I",
        "certifi_not_checked", "no_certifi_size", "no_one_certifi", "wrong_certifi", "no_fresh", "no_capath_scan", "stale_line_fails",
        "no_absent_after", "unconditional_before_check", "no_pre_size", "no_after_size",
        "unconditional_conf_check", "one_sided_conf_check", "unconditional_rewrite",
        "nothing_disabled", "wrong_root", "wrong_fingerprint", "aaa_dropped",
        "wrong_aaa_fingerprint", "wrong_aaa_root", "no_rebuild"])
def test_the_g3_pin_has_teeth(old, new):
    text = CONTAINERFILE.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    assert _g3_problems(text.replace(old, new)), f"the G3 pin missed: {old!r} -> {new!r}"


def test_the_g3_pin_sees_a_step_after_user():
    text = CONTAINERFILE.read_text(encoding="utf-8")
    assert _g3_problems(text.replace("RUN python -I -S -c \"import base64, glob, hashlib", "USER triage\nRUN python -I -S -c \"import base64, glob, hashlib", 1))


def test_the_g3_pin_refuses_a_shell_instruction_in_runtime():
    """Panel L db D3(b): SHELL ["/bin/true", "-c"] makes the shell-form step exit 0 unrun."""
    text = CONTAINERFILE.read_text(encoding="utf-8")
    step = "RUN python -I -S -c \"import base64, glob, hashlib"
    assert text.count(step) == 1
    assert _g3_problems(text.replace(step, 'SHELL ["/bin/true", "-c"]\n' + step))
    assert _g3_problems(text.replace("USER triage", 'SHELL ["/bin/sh", "-c"]\nUSER triage', 1))


def test_the_g3_pin_requires_runtime_to_be_the_last_stage():
    """Panel L db D3(c): a later stage escapes the 654 no-package-step-after check."""
    text = CONTAINERFILE.read_text(encoding="utf-8")
    assert _g3_problems(text + "\nFROM runtime AS later\nRUN apt-get update && apt-get install -y curl\n")


def test_the_g3_pin_sees_a_package_step_after_it():
    """654: an apt step (or a bare trust-store rebuild) after the distrust step fails the pin,
    and so does putting the distrust step back before the libssl3 install."""
    text = CONTAINERFILE.read_text(encoding="utf-8")
    anchor = "ENV HF_HOME=/app/data/runtime-deps/hf-cache"
    assert text.count(anchor) == 1
    for planted in ("RUN apt-get update && apt-get install -y --no-install-recommends curl",
                    "RUN dpkg --configure -a", "RUN update-ca-certificates"):
        assert _g3_problems(text.replace(anchor, planted + "\n" + anchor)), planted
    lines = text.splitlines(keepends=True)
    start = next(n for n, ln in enumerate(lines) if ln.startswith('RUN python -I -S -c "import base64, glob, hashlib'))
    end = next(n for n in range(start, len(lines)) if not lines[n].rstrip("\r\n").endswith("\\")) + 1
    moved = lines[:start] + lines[end:]
    at = next(n for n, ln in enumerate(moved)
              if ln.startswith("RUN apt-get update && \\") and "libssl3" in moved[n + 1])
    assert _g3_problems("".join(moved[:at] + lines[start:end] + moved[at:]))


def test_the_g3_pin_joins_continuations_the_way_docker_does():
    """652: with the harness's newline joints a '#' would hide one source row; Docker
    concatenates, so it hides every statement after it, and the pin parses that form."""
    instr = 'RUN python -I -S -c "a = 1; \\\nb = 2; # \\\nc = 3"'
    joined = dockerfile_instructions(instr)[0][1]
    assert len(ast.parse(_n621_body(joined)).body) == 2  # c = 3 is commented out
    assert "\n" not in dockerfile_shell_text(joined)


# ---- 652-655: the step's python logic, run against a fake certificate tree ----------------
#
# The image cannot be built on the workstation, so these run the Containerfile's own body
# (parsed from the file, not a copy) against a temp tree. Path constants are re-rooted and
# the two real fingerprints are swapped for those of fake roots (a real SHA-256 cannot be
# preimaged); everything else runs as written. `subprocess` is replaced at import by a fake
# `update-ca-certificates` that rebuilds the bundle from the enabled conf lines and, only
# with --fresh, wipes stale CApath files first. The real image build stays on the deploy host.

def _fake_pem(der: bytes) -> str:
    import base64
    return ("-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der).decode("ascii")
            + "-----END CERTIFICATE-----\n")


class _FakeStore:
    def __init__(self, root: Path, *, n_other: int = 110):
        self.root = root
        self.share = root / "usr/share/ca-certificates"
        self.certs = root / "etc/ssl/certs"
        self.conf = root / "etc/ca-certificates.conf"
        self.bundle = self.certs / "ca-certificates.crt"
        self.certifi = root / "usr/local/lib/python3.12/site-packages/certifi/cacert.pem"
        self.share.joinpath("mozilla").mkdir(parents=True)
        self.certs.mkdir(parents=True)
        self.certifi.parent.mkdir(parents=True)
        self.calls: list[list[str]] = []
        self.der = {name: f"fake root {name}".encode() for name in
                    [f"mozilla/Other_{k:03d}.crt" for k in range(n_other)] + [_G3_CONF, _AAA_CONF]}
        # certifi carries the other roots and never G3 or AAA (DA-5 measured 2026.10.19).
        self.write_certifi([e for e in self.der if e.startswith("mozilla/Other_")])

    def write_certifi(self, entries):
        self.certifi.write_text("".join(_fake_pem(self.der[e]) for e in entries), encoding="ascii")

    def fp(self, entry: str) -> str:
        return hashlib.sha256(self.der[entry]).hexdigest()

    def ship(self, entries):
        for e in entries:
            (self.share / e).write_text(_fake_pem(self.der[e]), encoding="ascii")

    def write_conf(self, lines):
        self.conf.write_text("\n".join(lines) + "\n", encoding="ascii")

    def rebuild(self, args) -> None:
        self.calls.append(list(args))
        if "--fresh" in args:
            for p in self.certs.iterdir():
                p.unlink()
        enabled = [ln for ln in self.conf.read_text(encoding="ascii").splitlines()
                   if ln and not ln.startswith(("!", "#")) and (self.share / ln).is_file()]
        for e in enabled:
            pem = (self.share / e).read_text(encoding="ascii")
            (self.certs / (Path(e).stem + ".pem")).write_text(pem, encoding="ascii")
            (self.certs / (self.fp(e)[:8] + ".0")).write_text(pem, encoding="ascii")
        self.bundle.write_text("".join((self.share / e).read_text(encoding="ascii") for e in enabled),
                               encoding="ascii")

    def run_step(self, body: str, *, fps: dict[str, str] | None = None) -> None:
        """exec the step against this tree; raises what the step raises."""
        import builtins
        import types
        swap = {_G3_SHA256: self.fp(_G3_CONF), _AAA_SHA256: self.fp(_AAA_CONF), **(fps or {})}
        root = self.root.as_posix()

        class _Reroot(ast.NodeTransformer):
            def visit_Constant(self, node):
                if isinstance(node.value, str):
                    if node.value.startswith(("/etc/", "/usr/share/", "/usr/local/")):
                        return ast.copy_location(ast.Constant(root + node.value), node)
                    if node.value in swap:
                        return ast.copy_location(ast.Constant(swap[node.value]), node)
                return node

        tree = ast.fix_missing_locations(_Reroot().visit(ast.parse(body)))
        fake = types.ModuleType("subprocess")
        fake.run = lambda args, check=False: self.rebuild(args)
        real_import = builtins.__import__

        def _import(name, *a, **k):
            return fake if name == "subprocess" else real_import(name, *a, **k)

        exec(compile(tree, "<N-621 step>", "exec"),
             {"__builtins__": {**vars(builtins), "__import__": _import}})


def _step_body(text: str | None = None) -> str:
    stages = dict(dockerfile_stages(text or CONTAINERFILE.read_text(encoding="utf-8")))
    body = _n621_body(next(t for _l, t in stages["runtime"] if "update-ca-certificates" in t))
    assert body is not None
    return body


def _store(tmp_path, *, g3=True, aaa=True, conf_extra=()):
    s = _FakeStore(tmp_path / "fs")
    others = [e for e in s.der if e.startswith("mozilla/Other_")]
    shipped = others + [e for e, on in ((_G3_CONF, g3), (_AAA_CONF, aaa)) if on]
    s.ship(shipped)
    s.write_conf(shipped + list(conf_extra))
    s.rebuild(["--fresh"])
    s.calls.clear()
    return s


def _distrusted_in_capath(s: _FakeStore) -> list[str]:
    bad = {s.fp(_G3_CONF), s.fp(_AAA_CONF)}
    return [p.name for p in s.certs.iterdir()
            if any(hashlib.sha256(_b64(b)).hexdigest() in bad
                   for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                                       p.read_text(encoding="ascii"), re.S))]


def _b64(block: str) -> bytes:
    import base64
    return base64.b64decode("".join(block.split()))


def test_step_logic_disables_both_roots_when_present(tmp_path):
    s = _store(tmp_path)
    assert len(_distrusted_in_capath(s)) == 5  # bundle + .pem + .0 for each root
    s.run_step(_step_body())
    assert s.calls == [["update-ca-certificates", "--fresh"]]
    conf = s.conf.read_text(encoding="ascii").splitlines()
    assert "!" + _G3_CONF in conf and "!" + _AAA_CONF in conf
    assert _distrusted_in_capath(s) == []


def test_step_logic_skips_a_root_already_gone_upstream(tmp_path, capsys):
    s = _store(tmp_path, g3=False, aaa=False)
    s.run_step(_step_body())
    assert s.calls == []
    assert capsys.readouterr().out.count("already absent upstream") == 2


def test_step_logic_passes_the_stale_enabled_line_shape(tmp_path):
    """655: upstream removed the .crt but left its conf line enabled (Debian #764296).
    The fixed step passes; the pre-655 predicate (conf line alone) fails the build."""
    s = _store(tmp_path, g3=False, conf_extra=(_G3_CONF,))
    assert not (s.share / _G3_CONF).exists()
    s.run_step(_step_body())
    old = _step_body().replace(" and os.path.isfile(S + D[f])", "")
    with pytest.raises(AssertionError, match="exactly when"):
        _store(tmp_path / "old", g3=False, conf_extra=(_G3_CONF,)).run_step(old)


def test_step_logic_fails_a_wrong_fingerprint(tmp_path):
    """The J-F1 guard survives 655: the root ships and is enabled, but D names other bytes."""
    s = _store(tmp_path)
    with pytest.raises(AssertionError, match="exactly when"):
        s.run_step(_step_body(), fps={_G3_SHA256: "0" * 64})
    assert s.calls == []


def test_step_logic_fails_when_the_rebuild_leaves_a_capath_link(tmp_path):
    """653 tooth: drop --fresh and the fake rebuild leaves the old .pem/.0 files; the
    bundle is clean, so only the CApath scan can fail the build."""
    no_fresh = _step_body().replace(", '--fresh'", "")
    s = _store(tmp_path)
    with pytest.raises(AssertionError, match="CApath"):
        s.run_step(no_fresh)
    assert s.calls == [["update-ca-certificates"]]
    assert _distrusted_in_capath(s) and not any(
        hashlib.sha256(_b64(b)).hexdigest() == s.fp(_G3_CONF)
        for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                            s.bundle.read_text(encoding="ascii"), re.S))


def test_step_logic_fails_when_certifi_carries_a_distrusted_root(tmp_path):
    """Panel L DA-5: the system store is clean but certifi (the httpx/requests store) is not."""
    s = _store(tmp_path)
    s.write_certifi([e for e in s.der if e.startswith("mozilla/Other_")] + [_G3_CONF])
    with pytest.raises(AssertionError, match="cacert.pem"):
        s.run_step(_step_body())


def test_step_logic_fails_without_exactly_one_certifi_bundle(tmp_path):
    s = _store(tmp_path)
    s.certifi.unlink()
    with pytest.raises(AssertionError, match="exactly one certifi bundle"):
        s.run_step(_step_body())


def test_step_logic_fails_a_blind_parser(tmp_path):
    s = _FakeStore(tmp_path / "fs", n_other=50)
    entries = list(s.der)
    s.ship(entries)
    s.write_conf(entries)
    s.rebuild(["--fresh"])
    with pytest.raises(AssertionError, match="too few roots"):
        s.run_step(_step_body())


def _freeze(tmp_path, text):
    path = tmp_path / "freeze.txt"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path.as_posix()


def test_installed_set_pass_arm_and_the_view_pip_audit_received(tmp_path):
    freeze = _freeze(tmp_path, "FastAPI==0.1\nemail-triage==0.2.0\ntorch==2.0.0+cpu\npip==26.2\n")
    proc, calls = _run_audit(tmp_path, args=("--installed-set", freeze))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c["kind"] for c in calls] == _legs(["manifest", "iteeth"])
    assert [c["svc"] for c in calls] == [s for s in _services() for _ in range(2)]
    for call in calls[::2]:
        assert call["view"] == ["fastapi==0.1", "torch==2.0.0", "pip==26.2"], (
            "the project line must be dropped (pyproject name) and the local segment stripped")
        for flag in ("--strict", "--no-deps", "--disable-pip"):
            assert flag in call["argv"]


@pytest.mark.parametrize("arm, overrides, text, needle", [
    ("finding", {"manifest_rc": 1}, "pip==25.0.1\n", None),
    ("teeth_silent", {"iteeth_rc": 0, "iteeth_rows": ""}, "pip==26.2\n", "TEETH FAILED"),
    ("osv_finding", {"osv": {"manifest_rc": 1}}, "pip==26.2\n", None),
    ("osv_teeth_silent", {"osv": {"iteeth_rc": 0, "iteeth_rows": ""}}, "pip==26.2\n", "TEETH FAILED [osv]"),
    ("unparseable", {}, "pip @ file:///x\n", "unparseable"),
    ("only_the_project", {}, "email-triage==0.2.0\n", "empty"),
])
def test_installed_set_fails_closed(tmp_path, arm, overrides, text, needle):
    proc, _calls = _run_audit(tmp_path, args=("--installed-set", _freeze(tmp_path, text)), **overrides)
    assert proc.returncode != 0, f"{arm}: exited 0\n{proc.stdout}\n{proc.stderr}"
    if needle:
        assert needle in proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# 10. N-553: the waiver list. The deploy.sh gate presence/order pins moved to
# tests/test_embedding_manifest_deploy_gate_pin.py (punch 519 / batch F): deploy.sh
# does not ship, so they are stripped there while this file stays on the mirror.
# ---------------------------------------------------------------------------


def _undocumented_waivers(script: str) -> list[str]:
    head = script[:script.index("WAIVERS=(")]
    body = script[script.index("WAIVERS=("):]
    body = body[:body.index(")") + 1]
    ids = _re.findall(r"--ignore-vuln=([A-Z0-9-]+)", body)
    return [i for i in ids if i not in head]


def test_every_waiver_is_documented_above_the_list():
    assert _undocumented_waivers(AUDIT_SCRIPT.read_text(encoding="utf-8")) == []
    assert _undocumented_waivers('# nothing\nWAIVERS=(\n "--ignore-vuln=CVE-1-2"\n)\n') == ["CVE-1-2"]
