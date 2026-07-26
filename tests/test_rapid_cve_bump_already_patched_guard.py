"""Defense-in-depth guard pin for `scripts/rapid-cve-bump.py`.

Locks the "already-patched" pre-`bump_lock()` check:

  - If the installed pin in `requirements.lock` is already at OR past the
    row's `fixed` version (per `packaging.version.Version` comparison), the
    tool MUST:
      * refuse to edit `requirements.lock`,
      * refuse to run any test / commit / push step,
      * print the exact "already-patched: …" one-liner (spec verbatim),
      * exit with code 5 (new code, distinct from 2/3/4).

  - If the installed pin is BELOW `fixed`, the guard passes and control
    flows into `bump_lock()` (which the tests mock).

  - If `requirements.lock` is missing, the guard fails CLOSED (Prime #8):
    exit non-zero, no lock edit, no commit.

Anchors: rapid-cve-notification-arc-design §4.5 (defense-in-depth),
project_style_guide Prime #8 (fail-closed), feedback_pre_push_ratchet_pin_sweep.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest import mock

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "rapid-cve-bump.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("rapid_cve_bump", str(_SCRIPT))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rcb = _load_module()


# --- canned enriched row (Class A, no HIPAA anchor) -------------------------

_BASE_CALLCHAIN = [
    "email_triage.web.app:register_start",
    "email_triage.webauthn.rp:_verify_attestation",
    "pyasn1.codec.der.decoder:decode",
]

CLASS_A_ROW = {
    "id": "GHSA-vvqm-mxpv-jvvw",
    "cve": "CVE-2026-59885",
    "package": "pyasn1",
    "installed_version": "0.6.1",
    "fixed": "0.6.2",
    "url": "https://github.com/advisories/GHSA-vvqm-mxpv-jvvw",
    "hash": "0a3b884e1234deadbeef5678",
    "class": "A",
    "hipaa_anchor": None,
    "reachable_at": [
        {
            "file": "src/email_triage/webauthn/rp.py",
            "line": 88,
            "callchain": list(_BASE_CALLCHAIN),
        }
    ],
}


# --- fixtures ---------------------------------------------------------------


def _write_lock(root: Path, body: str) -> Path:
    lock = root / "requirements.lock"
    lock.write_text(body, encoding="utf-8")
    return lock


@pytest.fixture
def repo_root(tmp_path, monkeypatch):
    """Point rapid-cve-bump at a scratch REPO_ROOT so the guard reads OUR lock."""
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    return tmp_path


# --- (1) already-patched → exit 5, no edit, no commit -----------------------


def test_already_patched_returns_exit_5_and_skips_all_side_effects(
    repo_root, capsys
):
    """installed_lock (0.9.0) >= fixed (0.6.2) → exit 5; no lock touch, no commit."""
    lock = _write_lock(
        repo_root,
        "acme==5.6.0\n"
        "pyasn1==0.9.0\n"          # already past the CVE fix
        "    # via email-triage (pyproject.toml)\n"
        "requests==2.32.0\n",
    )
    original_lock_bytes = lock.read_bytes()

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test") as vtest, \
         mock.patch.object(rcb, "run_ratchet_sweep") as sweep, \
         mock.patch.object(rcb, "git_commit") as gcommit:
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"]])

    assert rc == 5, f"expected exit 5 for already-patched row, got {rc}"
    bump.assert_not_called()
    vtest.assert_not_called()
    sweep.assert_not_called()
    gcommit.assert_not_called()
    # Lock file byte-identical — the guard did not rewrite it.
    assert lock.read_bytes() == original_lock_bytes

    out = capsys.readouterr().out
    # Byte-exact one-liner shape per spec.
    assert (
        "already-patched: pyasn1==0.9.0 already satisfies fix 0.6.2 "
        "— enricher likely false-positive; skipping bump; "
        "suggest running enricher lock-refresh"
    ) in out


def test_already_patched_at_exact_fixed_version_still_trips_guard(
    repo_root, capsys
):
    """installed_lock == fixed → guard trips (>=), no wasted churn commit."""
    _write_lock(repo_root, "pyasn1==0.6.2\n")

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb, "git_commit") as gcommit:
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"]])

    assert rc == 5
    bump.assert_not_called()
    gcommit.assert_not_called()
    out = capsys.readouterr().out
    assert "already-patched: pyasn1==0.6.2 already satisfies fix 0.6.2" in out


# --- (2) needs bump → guard passes, tool proceeds ---------------------------


def test_installed_below_fixed_lets_the_bump_flow_proceed(repo_root):
    """installed_lock (0.5.0) < fixed (0.6.2) → guard passes; bump + commit fire."""
    _write_lock(
        repo_root,
        "acme==5.6.0\n"
        "pyasn1==0.5.0\n"          # below fix — a real bump is warranted
        "    # via email-triage (pyproject.toml)\n",
    )

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test") as vtest, \
         mock.patch.object(rcb, "run_ratchet_sweep") as sweep, \
         mock.patch.object(rcb, "git_commit") as gcommit, \
         mock.patch.object(rcb, "_current_branch", return_value="feat/v0.2.0"):
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"]])

    assert rc == 0, "guard should pass when lock pin is below fix"
    bump.assert_called_once_with(CLASS_A_ROW, False)
    vtest.assert_called_once_with(False)
    sweep.assert_called_once_with(False)
    gcommit.assert_called_once()


def test_package_absent_from_lock_lets_flow_proceed(repo_root):
    """No pin present → guard has nothing to compare; bump proceeds."""
    _write_lock(repo_root, "acme==5.6.0\nrequests==2.32.0\n")

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb, "git_commit") as gcommit, \
         mock.patch.object(rcb, "_current_branch", return_value="feat/v0.2.0"):
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"]])

    assert rc == 0
    bump.assert_called_once()
    gcommit.assert_called_once()


# --- (3) missing lock → fail CLOSED (non-zero, no edit, no commit) ----------


def test_missing_requirements_lock_fails_closed(repo_root, capsys):
    """Prime #8: no requirements.lock → non-zero exit; no downstream side effects."""
    # Deliberately do NOT create the lock file.
    assert not (repo_root / "requirements.lock").exists()

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test") as vtest, \
         mock.patch.object(rcb, "run_ratchet_sweep") as sweep, \
         mock.patch.object(rcb, "git_commit") as gcommit:
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"]])

    assert rc != 0, "missing lock must fail CLOSED with non-zero exit"
    bump.assert_not_called()
    vtest.assert_not_called()
    sweep.assert_not_called()
    gcommit.assert_not_called()

    err = capsys.readouterr().err
    assert "requirements.lock missing" in err


# --- unit-level sanity on the parser + comparator ---------------------------


def test_parse_lock_pin_ignores_via_comment_lines(tmp_path):
    """The `# via …` continuation lines must NEVER match — they're indented."""
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "pyasn1==0.6.1\n"
        "    # via email-triage (pyproject.toml)\n"
        "    #   pyasn1  <-- this pretend-comment must NOT be picked up\n",
        encoding="utf-8",
    )
    assert rcb._parse_lock_pin(lock, "pyasn1") == "0.6.1"


def test_parse_lock_pin_strips_pep508_extras(tmp_path):
    """`pkg[extra]==ver` at column 0 still resolves to `pkg`."""
    lock = tmp_path / "requirements.lock"
    lock.write_text("uvicorn[standard]==0.32.0\n", encoding="utf-8")
    assert rcb._parse_lock_pin(lock, "uvicorn") == "0.32.0"


def test_check_already_patched_true_when_lock_ge_fixed(tmp_path, monkeypatch):
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    _write_lock(tmp_path, "pyasn1==0.6.5\n")
    already, ver = rcb.check_already_patched(CLASS_A_ROW)
    assert already is True
    assert ver == "0.6.5"


def test_check_already_patched_false_when_lock_below_fixed(tmp_path, monkeypatch):
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    _write_lock(tmp_path, "pyasn1==0.5.9\n")
    already, ver = rcb.check_already_patched(CLASS_A_ROW)
    assert already is False
    assert ver == "0.5.9"
