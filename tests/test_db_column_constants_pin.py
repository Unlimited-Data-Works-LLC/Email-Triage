"""Pin: every ``*_COLUMNS`` constant in ``email_triage.db.columns`` equals its
table's live schema, in ``PRAGMA table_info`` order (style guide PD#1, PD#5).

The ``SELECT *`` fold (panel r15, db-sme MUST-1) replaced 54 star reads with
explicit column lists. Hand-typed copies of one table's columns would let a later
``ALTER TABLE ... ADD COLUMN`` silently miss every copy, so the lists live once in
``email_triage.db.columns`` and every site interpolates the constant. This pin is
the prevention half: it finds the constants by iterating the module (never a
hard-coded list, so a new constant is covered the moment it lands) and compares
each with the schema ``init_db(':memory:')`` builds. A column added to the schema
without the constant, a column dropped, or a reorder fails here.

Name rule: ``<TABLE>_COLUMNS`` with the table name upper-cased; the table is
derived from the name. ``flows`` also has its own DDL in the engine store
(``FlowStore``), so that schema is checked too.
"""

from __future__ import annotations

import sqlite3

from email_triage.db import columns as columns_mod
from email_triage.engine import store as engine_store
from email_triage.web.db import init_db

_SUFFIX = "_COLUMNS"


def _constants() -> dict[str, str]:
    """Every ``*_COLUMNS`` string in the columns module, keyed by table name."""
    return {
        name[: -len(_SUFFIX)].lower(): value
        for name, value in vars(columns_mod).items()
        if name.endswith(_SUFFIX) and isinstance(value, str)
    }


def _schema_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _mismatches(
    constants: dict[str, str], conn: sqlite3.Connection
) -> list[str]:
    """One line per constant that does not equal its table's schema."""
    bad = []
    for table, value in sorted(constants.items()):
        declared = [c.strip() for c in value.split(",")]
        live = _schema_columns(conn, table)
        if not live:
            bad.append(f"{table}: no such table in init_db schema")
        elif declared != live:
            bad.append(f"{table}: constant {declared} != schema {live}")
    return bad


def _web_conn() -> sqlite3.Connection:
    return init_db(":memory:")


def _flowstore_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(engine_store._FLOWS_DDL)
    return conn


def test_columns_module_is_not_empty():
    # Vacuity guard: a rename of the suffix or the module must not turn the
    # pin into a loop over nothing.
    assert len(_constants()) >= 1


def test_every_columns_constant_equals_the_live_schema():
    conn = _web_conn()
    try:
        assert _mismatches(_constants(), conn) == []
    finally:
        conn.close()


def test_flows_constant_equals_the_engine_store_schema():
    conn = _flowstore_conn()
    try:
        flows = {"flows": _constants()["flows"]}
        assert _mismatches(flows, conn) == []
    finally:
        conn.close()


def test_teeth_a_constant_missing_one_column_fails():
    conn = _web_conn()
    try:
        table, value = sorted(_constants().items())[0]
        cols = [c.strip() for c in value.split(",")]
        short = ", ".join(cols[:-1])
        bad = _mismatches({table: short}, conn)
        assert len(bad) == 1 and bad[0].startswith(f"{table}:")
    finally:
        conn.close()


def test_teeth_a_reordered_constant_fails():
    conn = _web_conn()
    try:
        table, value = sorted(_constants().items())[0]
        cols = [c.strip() for c in value.split(",")]
        swapped = ", ".join([cols[1], cols[0], *cols[2:]])
        assert len(_mismatches({table: swapped}, conn)) == 1
    finally:
        conn.close()


def test_teeth_an_unknown_table_fails():
    conn = _web_conn()
    try:
        bad = _mismatches({"no_such_table_xyz": "id"}, conn)
        assert bad == ["no_such_table_xyz: no such table in init_db schema"]
    finally:
        conn.close()
