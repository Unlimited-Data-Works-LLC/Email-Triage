"""N-432 walresetbug P1 boot-assert pin (2026-07-19).

Companion to ``test_n432_sqlite_walreset_p0_pin`` — verifies the P1
sensor that surfaces SQLite / SQLCipher version exposure at boot.

The sensor lives at ``db/_engine.py::assert_sqlite_walresetbug_floor``.
Non-fatal by design: the P0 mitigation (auto-checkpoint pin + serialized
checkpoint funnel) is what closes the actual race. This sensor exists so
a base-image bump or a SQLCipher-fork bump becomes visible immediately
instead of via an out-of-band CVE tracker — the exact class of drift the
2026-07-19 audit workflow surfaced late.

Verifies:
1. ``assert_sqlite_walresetbug_floor`` is defined + callable.
2. Return-shape contract (fields the /health surface + operator tools
   depend on).
3. ``SQLITE_WALRESETBUG_FIX_VERSION`` constant is (3, 51, 3).
4. Called in ``web/app.py`` lifespan.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module

from email_triage.db._engine import (
    SQLITE_WALRESETBUG_FIX_VERSION,
    assert_sqlite_walresetbug_floor,
)


def test_walresetbug_fix_version_constant_is_3_51_3():
    """The fix version is 3.51.3 (SQLite upstream 2026-03-13). Bumping
    or weakening this constant silently changes the exposure gate.
    """
    assert SQLITE_WALRESETBUG_FIX_VERSION == (3, 51, 3), (
        "N-432 P1: SQLITE_WALRESETBUG_FIX_VERSION must be (3, 51, 3) — "
        "the upstream SQLite fix release. Changing this without landing "
        "an equivalent SME-signed off ticket silently tunes the exposure "
        "boundary."
    )


def test_assert_sqlite_walresetbug_floor_returns_full_shape():
    """The sensor returns the fields the boot logger + /health surface
    + any operator-inspection tool depends on.
    """
    result = assert_sqlite_walresetbug_floor()
    required = {
        "floor",
        "stdlib_version",
        "sqlcipher_available",
        "sqlcipher_version",
        "stdlib_exposed",
        "sqlcipher_exposed",
        "exposed",
        "mitigations_active",
    }
    missing = required - set(result.keys())
    assert not missing, (
        f"N-432 P1: assert_sqlite_walresetbug_floor() return shape "
        f"missing fields: {sorted(missing)}. /health + operator tools "
        f"consume the full shape; removing a field silently degrades "
        f"observability of the walresetbug exposure state."
    )
    assert result["floor"] == "3.51.3"
    assert isinstance(result["exposed"], bool)
    assert isinstance(result["stdlib_exposed"], bool)
    # ``at`` is set by the caller (lifespan) to now_utc_iso() — sensor
    # itself returns None so the same helper is callable from both
    # boot and any offline probe.
    assert result.get("at") is None
    assert "wal_autocheckpoint" in result["mitigations_active"]
    assert "checkpoint_wal_truncate" in result["mitigations_active"]


def test_lifespan_wires_boot_assert():
    """``web/app.py`` lifespan MUST call ``assert_sqlite_walresetbug_floor``.

    Interprocedural pin: the sensor is useless if nothing runs it at boot.
    Verified by scanning ``web/app.py`` for the import + call site.
    """
    path = SRC_ROOT / "web/app.py"
    tree = parse_module(path)
    assert tree is not None, "Cannot parse web/app.py"

    imported = False
    called = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.endswith("db._engine"):
                for alias in node.names:
                    if alias.name == "assert_sqlite_walresetbug_floor":
                        imported = True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "assert_sqlite_walresetbug_floor":
                called = True
            if (isinstance(func, ast.Attribute)
                    and func.attr == "assert_sqlite_walresetbug_floor"):
                called = True

    assert imported, (
        "N-432 P1: web/app.py must import "
        "`assert_sqlite_walresetbug_floor` from db._engine."
    )
    assert called, (
        "N-432 P1: web/app.py must CALL "
        "`assert_sqlite_walresetbug_floor()` in the lifespan startup. "
        "Import-only defeats the whole sensor — a base-image bump "
        "goes unobserved."
    )
