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
CI (the self-hosted the deploy host runner) installs the PyPI ``sqlcipher3`` manylinux
wheel (``sqlcipher ('4.12.0 community',)`` in the 2026-10-06 CI log — PRE-Path-3). Only
the Path-3-built Container carries the source-rebuilt sqlcipher3 (SQLCipher
v4.17.0 / SQLite 3.53.3). SKIP the version-floor assertions when the running
sqlcipher3 is not a Path-3 build (no baked ``/app/.path3-verified`` marker,
the gate ``db/_engine.py::assert_cipher_version_floor`` uses; punch 635) — else this pin
would falsely halt every non-container test run. The opener-seam scan is
env-agnostic and runs unconditionally.

Reuses ``_pin_harness`` helpers per PD#6 — ``iter_src_files``, ``parse_module``,
``relpath`` — no hand-rolled walker or hand-rolled relpath chain per
``test_pin_harness_adoption`` (V3/V4/V5/V5-prime detectors).

Panel origin: db-sme MF-2 in workflow ``wqpqvcbj6`` (2026-07-20).
"""

from __future__ import annotations

import ast

from _pin_harness import (
    REPO_ROOT,
    iter_src_files,
    load_repo_script,
    parse_module,
    relpath,
)

from email_triage.db._engine import PATH3_VERIFIED_MARKER, SQLITE_WALRESETBUG_FIX_VERSION

# ---------------------------------------------------------------------------
# (a) sqlite_version_info floor — at TEST-collection / import time
#     (env-gated on Path-3 baseline; pypi-wheel envs SKIP cleanly)
# ---------------------------------------------------------------------------


def _is_path3_baseline_env() -> bool:
    """True when the running env is a Path-3-built image.

    Punch 635: keyed on the image's own baked marker
    (``PATH3_VERIFIED_MARKER``, written by the Containerfile as the output of
    ``source_built.py verify``), the SAME gate ``assert_cipher_version_floor``
    uses. It used to read ``EMAIL_TRIAGE_PATH3_BASELINE``, which punch 547
    retired: the CLI refuses to start when it is set (rc 78), so nothing
    could set it and both arms below skipped everywhere, an uninvoked
    control. A marker cannot be typed, so these arms now run in every
    Path-3 image and skip only where the boot guard also stands down.
    """
    return PATH3_VERIFIED_MARKER.is_file()


def test_sqlcipher3_vendored_sqlite_clears_walresetbug_floor():
    """When running in a Path-3 baseline env, the sqlcipher3 binding must
    vendor SQLite >= 3.51.3 (walresetbug fix floor). The Path-3 Containerfile
    source-builds coleifer/sqlcipher3 against SQLCipher v4.17.0 (SQLite 3.53.3);
    this pin fails the suite the moment a Path-3-baseline env regresses onto
    a pre-fix vendored SQLite. Non-Path-3 envs (the pypi sqlcipher3 wheel
    on the CI runner) SKIP cleanly because they legitimately vendor an older
    SQLCipher and are NOT the target the walresetbug arc protects.
    """
    if not _is_path3_baseline_env():
        import pytest
        pytest.skip(
            f"{PATH3_VERIFIED_MARKER} absent — not a Path-3 image "
            "(the pypi sqlcipher3 wheel vendors an older SQLCipher/SQLite by "
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
            f"{PATH3_VERIFIED_MARKER} absent — Path-3 expected-line pin skipped"
        )

    try:
        import sqlcipher3.dbapi2 as _sqlcipher_dbapi
    except ImportError:
        import pytest
        pytest.skip("sqlcipher3 not installed in current environment")

    # Punch 635: compare against the DECLARED `c sqlite` version, not a
    # hardcoded line: source-built.pins is the one place a bump is made.
    sb = load_repo_script("scripts/source_built.py", "_et_source_built")
    declared = {c.name: c.version for c in sb.load(REPO_ROOT / sb.PINS_FILENAME)}
    assert _sqlcipher_dbapi.sqlite_version == declared["sqlite"], (
        f"N-432 Path-3: the image's sqlcipher3 runs SQLite "
        f"{_sqlcipher_dbapi.sqlite_version}, but source-built.pins declares "
        f"{declared['sqlite']}. The build's own verify should have stopped this."
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
        "#11 + PD#2 interprocedural pin). Every sqlcipher3.connect must route "
        "through db/_engine.py::_make_encrypted_conn (or db/_migrate.py "
        "mirror). Offenders:\n  " + "\n  ".join(violations)
    )
