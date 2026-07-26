"""N-432 walresetbug Path-3 floor SSOT pin (2026-07-20).

Interprocedural pin per Prime Directive #1 (SSOT + count-agnostic structural
pin) + PD#2 (make the pin interprocedural). The floor SSOT is the constant
``SQLITE_WALRESETBUG_FIX_VERSION = (3, 51, 3)`` in ``db/_engine.py`` — this
pin enforces that (a) the running ``sqlcipher3.dbapi2.sqlite_version_info``
clears the floor at TEST-COLLECTION time IF the running env is a Path-3
baseline (so a regression WITHIN a Path-3 build fails the suite before it
reaches ship), and (b) no opener seam (``sqlite3.connect``, ``sqlcipher3.*
connect``, encryption-aware opener SSOT, dedicated / backup / migration
openers per PD#11) reintroduces a raw ``sqlite3.connect(...)`` alongside the
encrypted opener (the same anti-pattern ``test_n432_raw_sqlite_connect_pin.py``
closes on the sqlite arm — this pin extends the shape to catch the sqlcipher
arm regression under the new floor).

**Env-gate on the version-floor test (CI-red fix-forward 2026-07-20).**
CI's ubuntu-latest runner + local dev envs install ``sqlcipher3-binary`` from
pypi (currently vendoring SQLCipher 4.12 / SQLite 3.51.1 — PRE-Path-3). Only
the Path-3-built Container carries the source-rebuilt sqlcipher3 (SQLCipher
v4.17.0 / SQLite 3.53.3). SKIP the version-floor assertions when the running
sqlcipher3 is not a Path-3 build (env var ``EMAIL_TRIAGE_PATH3_BASELINE`` unset,
mirroring ``db/_engine.py::assert_cipher_version_floor``) — else this pin
would falsely halt every non-container test run. The opener-seam scan is
env-agnostic and runs unconditionally.

Reuses ``_pin_harness`` helpers per PD#6 — ``iter_src_files``, ``parse_module``,
``relpath`` — no hand-rolled walker or hand-rolled relpath chain per
``test_pin_harness_adoption`` (V3/V4/V5/V5-prime detectors).

Panel origin: db-sme MF-2 in workflow ``wqpqvcbj6`` (2026-07-20).
"""

from __future__ import annotations

import ast
import os

from _pin_harness import iter_src_files, parse_module, relpath

from email_triage.db._engine import SQLITE_WALRESETBUG_FIX_VERSION

# ---------------------------------------------------------------------------
# (a) sqlite_version_info floor — at TEST-collection / import time
#     (env-gated on Path-3 baseline; pypi-wheel envs SKIP cleanly)
# ---------------------------------------------------------------------------


def _is_path3_baseline_env() -> bool:
    """True when the running env is a Path-3-built container.

    Mirrors the ``EMAIL_TRIAGE_PATH3_BASELINE=1`` marker the Path-3
    Containerfile sets in the runtime stage. CI/local dev envs use
    pip-installed ``sqlcipher3-binary`` (pypi wheel vendoring a pre-Path-3
    SQLCipher) — the floor assertions don't apply there.
    """
    return os.environ.get("EMAIL_TRIAGE_PATH3_BASELINE") == "1"


def test_sqlcipher3_vendored_sqlite_clears_walresetbug_floor():
    """When running in a Path-3 baseline env, the sqlcipher3 binding must
    vendor SQLite >= 3.51.3 (walresetbug fix floor). The Path-3 Containerfile
    source-builds coleifer/sqlcipher3 against SQLCipher v4.17.0 (SQLite 3.53.3);
    this pin fails the suite the moment a Path-3-baseline env regresses onto
    a pre-fix vendored SQLite. Non-Path-3 envs (pypi-wheel sqlcipher3-binary
    on the CI runner) SKIP cleanly because they legitimately vendor an older
    SQLCipher and are NOT the target the walresetbug arc protects.
    """
    if not _is_path3_baseline_env():
        import pytest
        pytest.skip(
            "EMAIL_TRIAGE_PATH3_BASELINE unset — pre-Path-3 env "
            "(pypi sqlcipher3-binary vendors an older SQLCipher/SQLite by "
            "design; the Path-3 floor pin only applies inside the Container)"
        )

    try:
        import sqlcipher3.dbapi2 as _sqlcipher_dbapi
    except ImportError:
        import pytest
        pytest.skip("sqlcipher3 not installed in current environment")

    svi = _sqlcipher_dbapi.sqlite_version_info
    assert svi >= SQLITE_WALRESETBUG_FIX_VERSION, (
        f"N-432 Path-3 floor: sqlcipher3.dbapi2.sqlite_version={_sqlcipher_dbapi.sqlite_version} "
        f"< walresetbug fix floor {SQLITE_WALRESETBUG_FIX_VERSION}. "
        f"Path-3 rebuilds sqlcipher3 against SQLCipher v4.17.0 (SQLite 3.53.3); "
        f"a pre-fix vendored SQLite here means the amalgamation regressed or "
        f"the Containerfile source-build was bypassed."
    )


def test_sqlcipher3_vendored_sqlite_is_expected_path3_line():
    """Belt for the floor assertion above (Path-3 envs only): the Path-3
    baseline is SQLite 3.53.x specifically (SQLCipher v4.17.0 amalgamation).
    A silent bump to 3.54.x means the SQLCIPHER_SHA env pin was moved without
    updating this expectation — surface it as a test failure, not a runtime
    surprise. Non-Path-3 envs SKIP.
    """
    if not _is_path3_baseline_env():
        import pytest
        pytest.skip(
            "EMAIL_TRIAGE_PATH3_BASELINE unset — Path-3 expected-line pin skipped"
        )

    try:
        import sqlcipher3.dbapi2 as _sqlcipher_dbapi
    except ImportError:
        import pytest
        pytest.skip("sqlcipher3 not installed in current environment")

    svi = _sqlcipher_dbapi.sqlite_version_info
    assert svi[:2] == (3, 53), (
        f"N-432 Path-3 baseline expects SQLite 3.53.x (SQLCipher v4.17.0 "
        f"amalgamation), got {_sqlcipher_dbapi.sqlite_version}. Bump the "
        f"expected line here + update SQLCIPHER_SHA in the Containerfile "
        f"same commit if this is an intentional upstream bump."
    )


# ---------------------------------------------------------------------------
# (b) Interprocedural opener-seam scan — no raw sqlite3.connect alongside
# the encrypted opener SSOT (mirrors the sqlite-arm test_n432_raw_sqlite_
# connect_pin shape under the new post-fix floor). Env-agnostic.
# ---------------------------------------------------------------------------

# Encryption-aware opener SSOT modules — per PD#11 every dedicated / backup /
# migration connection inherits its key via this seam. Openers outside this
# allow-list are the drift class this pin catches.
_ALLOWED_ENCRYPTED_OPENER_FILES = {
    "db/_engine.py",       # _make_encrypted_conn SSOT
    "db/_migrate.py",      # migration opener mirrors _engine.py per PD#11 comment
}


def _resolves_to_sqlcipher3_connect(call: ast.Call) -> bool:
    """True iff the Call node is ``sqlcipher3.*connect(...)`` at the AST level."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "connect":
        val = func.value
        if isinstance(val, ast.Name) and val.id == "sqlcipher3":
            return True
        if (isinstance(val, ast.Attribute)
                and isinstance(val.value, ast.Name)
                and val.value.id == "sqlcipher3"):
            return True
    return False


def test_no_raw_sqlcipher3_connect_outside_engine_ssot():
    """Every ``sqlcipher3.*connect(...)`` call MUST live inside the
    encryption-aware opener SSOT (``db/_engine.py``) or the migration
    mirror (``db/_migrate.py`` — explicit PD#11 exception documented in
    _make_encrypted_conn comments). A raw sqlcipher3.connect elsewhere
    silently bypasses the boot contract, per-purpose key stamping, and
    the PRAGMA-sequence discipline the SSOT enforces.
    """
    violations: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel in _ALLOWED_ENCRYPTED_OPENER_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _resolves_to_sqlcipher3_connect(node):
                violations.append(f"{rel}:{node.lineno}")

    assert not violations, (
        "N-432 Path-3 pin: sqlcipher3 opener SSOT violated (Prime Directive "
        " + PD#2 interprocedural pin). Every sqlcipher3.connect must route "
        "through db/_engine.py::_make_encrypted_conn (or db/_migrate.py "
        "mirror). Offenders:\n  " + "\n  ".join(violations)
    )
