"""N-432 walresetbug companion pin — raw ``sqlite3.connect`` sweep (2026-07-19).

The P0 mitigation (``PRAGMA wal_autocheckpoint = 0`` +
``checkpoint_wal_truncate`` under ``@db_write``) lives in the opener SSOT
``db/_engine.py::_apply_standard_pragmas``. Any raw ``sqlite3.connect(...)``
that skips the opener bypasses the PRAGMA sequence and re-opens the
walresetbug exposure — the exact interprocedural drift shape
``feedback_divergence_audit_and_ssot_pin`` calls out.

This pin bans raw ``sqlite3.connect(...)`` outside a small waived set:

* ``db/_engine.py`` — the opener SSOT module itself. Every raw call
  here is either INSIDE a documented opener (``_open_dedicated_conn``,
  ``open_dedicated_conn_readish``, ``create_engine_for_app`` plain
  creator) that calls ``_apply_standard_pragmas`` immediately after, OR
  is a read-only ``file:...?mode=ro`` handle that cannot fire an
  auto-checkpoint by construction.
* ``db/_migrate.py`` — migration primitives. Migrations run at
  boot before any writer exists, so no writer/checkpoint race is
  possible; the raw open is a deliberate pre-app tool.
* ``web/db.py`` — ``init_db`` chains through ``_bootstrap_schema``
  which calls ``_apply_standard_pragmas`` at db.py:889 (verified in
  the P0 audit walk 2026-07-19).

A NEW ``sqlite3.connect`` outside these three modules IS a drift bug
per this pin — the caller must route through ``open_dedicated_conn``
(the RW opener) or ``open_dedicated_conn_readish`` (the RO opener) so
every long-lived writable handle inherits ``wal_autocheckpoint = 0``.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_WAIVED_MODULES = {
    "db/_engine.py",      # opener SSOT module
    "db/_migrate.py",     # migration primitives (pre-app, no writer race)
    "web/db.py",          # init_db → _bootstrap_schema → _apply_standard_pragmas
}


def _iter_sqlite3_connect_calls(tree: ast.AST):
    """Yield lineno for every ``sqlite3.connect(...)`` call in ``tree``."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "connect"):
            continue
        # Match both ``sqlite3.connect`` and any aliased import (``import
        # sqlite3 as _sq; _sq.connect(...)``) — value.id is the module
        # binding name. Common cases: ``sqlite3.connect(...)``.
        if not isinstance(func.value, ast.Name):
            continue
        if func.value.id != "sqlite3":
            continue
        yield node.lineno


def test_no_raw_sqlite3_connect_outside_ssot():
    """Ban raw ``sqlite3.connect(...)`` outside the opener SSOT + waives.

    A new module that opens the app DB with ``sqlite3.connect(...)``
    directly instead of through ``open_dedicated_conn`` skips
    ``_apply_standard_pragmas`` and therefore skips
    ``PRAGMA wal_autocheckpoint = 0`` — re-exposing the walresetbug
    race on the shared WAL file.
    """
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_WAIVED_MODULES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno in _iter_sqlite3_connect_calls(tree):
            offenders.append(f"{rel}:{lineno}  sqlite3.connect(...)")
    assert not offenders, (
        "N-432 walresetbug companion: raw `sqlite3.connect(...)` outside "
        "the opener SSOT. Route through `open_dedicated_conn` (RW) or "
        "`open_dedicated_conn_readish` (RO) in `db/_engine.py` so every "
        "handle inherits `PRAGMA wal_autocheckpoint = 0` and the "
        "walresetbug checkpoint-race is not silently re-opened on the "
        "new caller.\n\nWaived modules: "
        + ", ".join(sorted(_SSOT_WAIVED_MODULES))
        + "\n\nOffenders:\n"
        + "\n".join(offenders)
    )
