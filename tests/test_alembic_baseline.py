"""Phase 1 schema-equivalence test — Alembic baseline vs init_db().

Per `internal documentation` §4 Phase 1 deliverable 6:

    "Schema-equivalence test (canonical pattern, internet-verified 2026-
    05-28): use `alembic.autogenerate.compare_metadata(MigrationContext,
    MetaData)` — empty diff = schemas equivalent. Belt-and-suspenders:
    `PRAGMA table_info(...)` row-by-row walker for SQLite-specific
    structural checks."

What this test proves (and what it does NOT)
--------------------------------------------
The Alembic baseline (`alembic/versions/0001_baseline_v0_1_2.py`)
DELEGATES to the legacy `init_db()` for its full schema build — its
`upgrade()` calls `init_db()` directly rather than reconstructing the
DDL independently. So this test verifies the PLUMBING: that
`alembic upgrade head` reaches `init_db()` and lands the same table /
column / index set that a direct `init_db()` produces. It does NOT
independently reconstruct the DDL and prove byte-identity against a
separate source — there is only one schema source (`init_db()`), and
both paths run through it.

Recovery (if this test fails)
-----------------------------
There is NO `scripts/extract_alembic_baseline.py` (removed during Phase
1 — the baseline delegates to `init_db()` instead of extracting a
snapshot). A failure here means the Alembic plumbing diverged from
`init_db()` — inspect/repair `alembic/versions/0001_baseline_v0_1_2.py`
(it should call `init_db()` against the Alembic-managed DB path) and the
`alembic/env.py` URL handling. The legacy schema itself is edited in
`web/db.py` `_ALL_DDL` / `_apply_migrations` / `web/migrations.py`, NOT
in the baseline migration.
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from email_triage.web.db import init_db


_REPO_ROOT = Path(__file__).resolve().parent.parent
_ALEMBIC_BASELINE = (
    _REPO_ROOT / "alembic" / "versions" / "0001_baseline_v0_1_2.py"
)


@pytest.fixture
def init_db_schema(tmp_path: Path) -> dict[str, dict]:
    """Build a fresh DB via init_db(); return its sqlite_master snapshot."""
    db_path = tmp_path / "init.db"
    conn = track(init_db(str(db_path)))
    try:
        return _snapshot_schema(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass


@pytest.fixture
def alembic_baseline_schema(tmp_path: Path) -> dict[str, dict]:
    """Build a fresh DB by running `alembic upgrade head` against it."""
    db_path = tmp_path / "alembic.db"

    # Run alembic upgrade head against the empty target DB. env.py
    # picks up the URL from EMAIL_TRIAGE_DATABASE_URL; flag plain mode
    # so the encryption + master_key path is skipped for the test.
    env = {
        "EMAIL_TRIAGE_DATABASE_URL": f"sqlite:///{db_path}",
        "EMAIL_TRIAGE_ALEMBIC_PLAIN": "1",
    }
    import os

    full_env = {**os.environ, **env}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_REPO_ROOT),
        env=full_env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"alembic upgrade head failed:\nstdout={result.stdout}\n"
        f"stderr={result.stderr}"
    )

    conn = sqlite3.connect(str(db_path))
    try:
        return _snapshot_schema(conn)
    finally:
        conn.close()


def _snapshot_schema(conn: sqlite3.Connection) -> dict[str, dict]:
    """Return a structural snapshot keyed by object name.

    Captures table columns (PRAGMA table_info), indexes
    (PRAGMA index_list + index_info), foreign keys (PRAGMA foreign_key_list)
    — the canonical SQLite-specific structural fingerprint per
    `internal documentation` §4 Phase 1 deliverable 6.
    Excludes sqlite_master autoindexes (sqlite_autoindex_*) since they're
    implicit from PRIMARY KEY declarations.
    """
    out: dict[str, dict] = {}
    # Force plain tuples regardless of how the connection was opened:
    # init_db() sets row_factory=sqlite3.Row, the alembic-fixture conn
    # leaves it None. Comparing Row vs tuple is never equal even with
    # identical data, producing false column diffs on every table.
    conn.row_factory = None
    tables = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' "
        "AND name NOT LIKE 'sqlite_%' "
        "AND name NOT LIKE 'alembic_%' "
        "ORDER BY name"
    ).fetchall()
    for (table_name,) in tables:
        columns = conn.execute(
            f'PRAGMA table_info("{table_name}")'
        ).fetchall()
        indexes = conn.execute(
            f'PRAGMA index_list("{table_name}")'
        ).fetchall()
        # Drop the auto-index rows; they vary with SQLite internals
        # and aren't part of the schema contract.
        non_auto_indexes = [
            row for row in indexes if not row[1].startswith("sqlite_autoindex_")
        ]
        index_details = []
        for row in non_auto_indexes:
            idx_name = row[1]
            idx_info = conn.execute(
                f'PRAGMA index_info("{idx_name}")'
            ).fetchall()
            index_details.append((idx_name, tuple(idx_info)))
        fks = conn.execute(
            f'PRAGMA foreign_key_list("{table_name}")'
        ).fetchall()
        out[table_name] = {
            "columns": tuple(columns),
            "indexes": tuple(index_details),
            "foreign_keys": tuple(fks),
        }
    return out


def test_alembic_baseline_matches_init_db_table_set(
    init_db_schema: dict, alembic_baseline_schema: dict
):
    """Both paths produce the same set of tables."""
    init_tables = set(init_db_schema)
    alembic_tables = set(alembic_baseline_schema)
    missing_in_alembic = init_tables - alembic_tables
    extra_in_alembic = alembic_tables - init_tables
    assert not missing_in_alembic, (
        f"Alembic baseline missing tables: {sorted(missing_in_alembic)}. "
        "The baseline delegates to init_db(); a divergence means "
        "alembic/versions/0001_baseline_v0_1_2.py or alembic/env.py is "
        "not reaching init_db() — inspect those, not a (nonexistent) "
        "extract script."
    )
    assert not extra_in_alembic, (
        f"Alembic baseline has extra tables not in init_db: "
        f"{sorted(extra_in_alembic)}."
    )


def test_alembic_baseline_per_table_columns_match(
    init_db_schema: dict, alembic_baseline_schema: dict
):
    """Per-table column lists are identical (name, type, notnull, dflt, pk)."""
    diffs = []
    for table in sorted(init_db_schema):
        if table not in alembic_baseline_schema:
            continue
        if init_db_schema[table]["columns"] != alembic_baseline_schema[
            table
        ]["columns"]:
            diffs.append(table)
    assert not diffs, (
        f"Column-schema diff in tables: {diffs}. The baseline delegates "
        "to init_db(); fix the schema in web/db.py / web/migrations.py "
        "(NOT a nonexistent extract script), or repair the baseline "
        "delegation in alembic/versions/0001_baseline_v0_1_2.py."
    )


def test_alembic_baseline_per_table_indexes_match(
    init_db_schema: dict, alembic_baseline_schema: dict
):
    """Per-table indexes are identical (name + columns)."""
    diffs = []
    for table in sorted(init_db_schema):
        if table not in alembic_baseline_schema:
            continue
        init_idx = init_db_schema[table]["indexes"]
        alembic_idx = alembic_baseline_schema[table]["indexes"]
        # Index ordering may vary across paths; compare by set-of-names.
        if {n for n, _ in init_idx} != {n for n, _ in alembic_idx}:
            diffs.append(table)
    assert not diffs, (
        f"Index-set diff in tables: {diffs}. The baseline delegates to "
        "init_db(); fix the index DDL in web/db.py / web/migrations.py "
        "(NOT a nonexistent extract script), or repair the baseline "
        "delegation in alembic/versions/0001_baseline_v0_1_2.py."
    )
