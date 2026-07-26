"""Pin per rapid-cve-notification-arc-design.md §4.5 (defense-in-depth).

Locks the `_require_fields()` guard in `scripts/rapid-cve-bump.py`:

  - Raw `row['fixed']` / `row['package']` / `row['hash']` accesses in
    `bump_lock()` and `compose_commit_message()` used to raise an
    uncaught `KeyError` when `--class=A` was forced on a row the
    enricher had shelved into Class B/C precisely BECAUSE a field was
    absent (e.g. Class C = no `fixed` yet). The `KeyError` escaped the
    `except BumpError` in `main()` and leaked a Python traceback
    instead of a clean exit=3.

  - `_require_fields(row, [...], context)` MUST raise `BumpError` on any
    missing field, naming which fields are missing and echoing the
    available keys.

  - `main()` MUST catch that `BumpError` and return **exit 3** (not
    traceback, not 0), matching the mid-flow-failure exit code shape.

Prime #8 (fail-CLOSED), project_style_guide, feedback_default_to_complete.
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


# --- unit-level: _require_fields ------------------------------------------


def test_all_fields_present_no_error():
    """Happy path: every named field present → returns None, raises nothing."""
    row = {"package": "pyasn1", "fixed": "0.6.2", "hash": "abc123"}
    # Should not raise.
    assert rcb._require_fields(row, ["package", "fixed", "hash"], "bump_lock") is None


def test_missing_package_raises():
    """A row without `package` triggers BumpError naming the missing field."""
    row = {"fixed": "0.6.2", "hash": "abc123"}
    with pytest.raises(rcb.BumpError) as exc:
        rcb._require_fields(row, ["package", "fixed", "hash"], "bump_lock")
    msg = str(exc.value)
    assert "package" in msg
    assert "bump_lock" in msg
    # Message must echo what IS available so operator can diagnose.
    assert "fixed" in msg or "hash" in msg


def test_missing_hash_raises():
    """A row without `hash` triggers BumpError naming the missing field."""
    row = {"package": "pyasn1", "fixed": "0.6.2"}
    with pytest.raises(rcb.BumpError) as exc:
        rcb._require_fields(row, ["package", "hash"], "compose_commit_message")
    msg = str(exc.value)
    assert "hash" in msg
    assert "compose_commit_message" in msg


def test_missing_multiple_fields_lists_all():
    """Every missing field must be surfaced — not just the first."""
    row = {"fixed": "0.6.2"}
    with pytest.raises(rcb.BumpError) as exc:
        rcb._require_fields(row, ["package", "fixed", "hash"], "bump_lock")
    msg = str(exc.value)
    assert "package" in msg
    assert "hash" in msg


# --- integration: bump_lock guards row shape ---------------------------------


def test_bump_lock_raises_bump_error_on_missing_fixed(monkeypatch, tmp_path):
    """Class-C row (no `fixed`) fed to `bump_lock` raises BumpError, not KeyError."""
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    (tmp_path / "requirements.lock").write_text("pyasn1==0.5.0\n", encoding="utf-8")
    row = {"package": "pyasn1", "hash": "abc123"}  # no `fixed`
    with pytest.raises(rcb.BumpError) as exc:
        rcb.bump_lock(row, dry_run=False)
    assert "fixed" in str(exc.value)
    assert "bump_lock" in str(exc.value)


def test_compose_commit_message_raises_bump_error_on_missing_package():
    """Missing `package` at compose time → BumpError, not KeyError."""
    row = {"fixed": "0.6.2", "hash": "abc123"}
    with pytest.raises(rcb.BumpError) as exc:
        rcb.compose_commit_message(row)
    assert "package" in str(exc.value)


# --- integration: main() catches BumpError and returns exit 3 ---------------


def test_class_A_override_on_missing_fixed_raises_bump_error(
    tmp_path, monkeypatch, capsys
):
    """--class=A on a Class-C row missing `fixed` → clean exit=3, no traceback."""
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    # Lock exists so the already-patched check doesn't trip on a missing file.
    (tmp_path / "requirements.lock").write_text("pyasn1==0.5.0\n", encoding="utf-8")

    # A row the enricher couldn't complete: no `fixed`. Operator forces --class=A.
    class_C_row_missing_fixed = {
        "id": "GHSA-xxxx",
        "cve": "CVE-2026-99999",
        "package": "pyasn1",
        "installed_version": "0.5.0",
        "url": "https://example.invalid",
        "hash": "deadbeefdeadbeef",
        "class": "C",  # enricher parked as C — because `fixed` is unknown
        # NOTE: no `fixed` key at all
    }

    with mock.patch.object(
        rcb, "fetch_enriched_row", return_value=class_C_row_missing_fixed
    ), mock.patch.object(rcb, "run_verified_test") as vtest, mock.patch.object(
        rcb, "run_ratchet_sweep"
    ) as sweep, mock.patch.object(
        rcb, "git_commit"
    ) as gcommit:
        rc = rcb.main(
            ["--hash", class_C_row_missing_fixed["hash"], "--class", "A"]
        )

    # Clean exit=3 shape (matches bump-flow BumpError path in main()).
    assert rc == 3, f"expected exit 3, got {rc}"
    # No side-effects after guard trips.
    vtest.assert_not_called()
    sweep.assert_not_called()
    gcommit.assert_not_called()

    # The stderr surface names the missing field so operator can act. The
    # context tag identifies which callsite guarded — `check_already_patched`
    # fires before `bump_lock` in main()'s flow, so either name is acceptable
    # as long as the missing field is surfaced.
    err = capsys.readouterr().err
    assert "fixed" in err
    assert ("bump_lock" in err) or ("check_already_patched" in err)


def test_class_A_override_on_missing_fixed_no_python_traceback(
    tmp_path, monkeypatch, capsys
):
    """The defect: raw `row['fixed']` KeyError USED to escape → traceback.

    Post-fix, `main()` catches the BumpError and returns exit 3 — no
    `Traceback (most recent call last):` reaches stderr.
    """
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    (tmp_path / "requirements.lock").write_text("pyasn1==0.5.0\n", encoding="utf-8")

    row = {
        "package": "pyasn1",
        "hash": "deadbeefdeadbeef",
        "class": "C",
        # no `fixed`
    }

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=row):
        rc = rcb.main(["--hash", row["hash"], "--class", "A"])

    captured = capsys.readouterr()
    assert rc == 3
    # A leaked traceback would carry these markers — must NOT be present.
    assert "Traceback" not in captured.err
    assert "KeyError" not in captured.err


def test_default_class_bc_flow_missing_fixed_returns_exit_3(
    tmp_path, monkeypatch, capsys
):
    """Class-C row (no --class override) → _print_class_bc_instructions is
    invoked, which internally calls compose_commit_message to render the
    drafted template. compose_commit_message now REQUIRES `fixed`; the
    resulting BumpError must be caught in main() → clean exit=3, no
    Python traceback (wf-2 C4 REFUTED regression).
    """
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    (tmp_path / "requirements.lock").write_text("pyasn1==0.5.0\n", encoding="utf-8")

    # Enricher-shelved Class C row: `fixed` legitimately unknown.
    class_C_row = {
        "id": "GHSA-yyyy",
        "cve": "CVE-2026-11111",
        "package": "pyasn1",
        "installed_version": "0.5.0",
        "url": "https://example.invalid",
        "hash": "deadbeefdeadbeef",
        "class": "C",
        # NO `fixed`, NO --class override — hit the default flow.
    }

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=class_C_row):
        rc = rcb.main(["--hash", class_C_row["hash"]])

    captured = capsys.readouterr()
    assert rc == 3, f"expected exit 3, got {rc}. stderr={captured.err!r}"
    # No Python traceback (the defect signature).
    assert "Traceback" not in captured.err
    assert "KeyError" not in captured.err
    # Missing field named on stderr for operator visibility.
    assert "fixed" in captured.err
    assert "compose_commit_message" in captured.err


# --- PEP 503 normalization: _parse_lock_pin --------------------------------


def test_pep503_lock_pin_matches_normalized_name(tmp_path):
    """`_parse_lock_pin` MUST PEP-503 normalize both the lock-line head AND
    the queried package name before compare.

    Without this, `pytest_cov==5.0.0` in requirements.lock never matches a
    query for `pytest-cov`, `_parse_lock_pin` returns None, and
    `check_already_patched` silently returns (False, None) — skipping the
    already-patched defense-in-depth guard on a name-form mismatch that is
    a routine distribution-spelling variant.
    """
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "pytest_cov==5.0.0\n"
        "Pyasn1==0.6.2\n"
        "some.weird_pkg==1.0.0\n",
        encoding="utf-8",
    )
    # underscore in lock -> hyphen in query
    assert rcb._parse_lock_pin(lock, "pytest-cov") == "5.0.0"
    # capitalized in lock -> lowercase in query
    assert rcb._parse_lock_pin(lock, "pyasn1") == "0.6.2"
    # mixed .+_ in lock -> hyphen in query
    assert rcb._parse_lock_pin(lock, "some-weird-pkg") == "1.0.0"
    # hyphen-form in lock (canonical) -> underscore query still matches
    lock2 = tmp_path / "req2.lock"
    lock2.write_text("pytest-cov==6.0.0\n", encoding="utf-8")
    assert rcb._parse_lock_pin(lock2, "pytest_cov") == "6.0.0"
    # negative: unrelated name still returns None
    assert rcb._parse_lock_pin(lock, "totally-different") is None


def test_pep503_norm_helper_shape():
    """`_norm_pkg` collapses runs of `-_.` to `-` + lowercases (PEP 503)."""
    assert rcb._norm_pkg("pytest-cov") == "pytest-cov"
    assert rcb._norm_pkg("pytest_cov") == "pytest-cov"
    assert rcb._norm_pkg("Pytest.Cov") == "pytest-cov"
    assert rcb._norm_pkg("some__weird..name") == "some-weird-name"
    assert rcb._norm_pkg("A") == "a"


def test_main_exit_3_when_row_missing_hash_and_forced_class_A(
    tmp_path, monkeypatch, capsys
):
    """A row missing `hash` (edge-case corrupt enrichment) also → clean exit 3."""
    monkeypatch.setattr(rcb, "REPO_ROOT", tmp_path)
    (tmp_path / "requirements.lock").write_text("pyasn1==0.5.0\n", encoding="utf-8")

    row = {
        "package": "pyasn1",
        "fixed": "0.6.2",
        "class": "A",
        # no `hash`
    }

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=row):
        # --hash is REQUIRED by argparse; supply any value — the guard reads
        # the row's own dict, not the CLI arg.
        rc = rcb.main(["--hash", "provided-cli-hash"])

    assert rc == 3
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "hash" in captured.err
