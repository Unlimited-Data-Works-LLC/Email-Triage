"""Tests for migration v35 — retry-queue consolidation.

v35 folds ``triage_retry_queue`` (v16) into ``watcher_retry_queue``
(v30): adds the ``failure_kind`` column, backfills live v16 rows, and
drops the v16 table.

Covers:
* v35 applies cleanly on top of v34.
* The ``failure_kind`` column exists after v35.
* Live v16 rows are backfilled as IMAP-origin pending rows carrying
  ``failure_kind='llm_unreachable'`` and their original attempt_count.
* ``triage_retry_queue`` is dropped.
* The backfill is idempotent across a re-run (no duplicate rows).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.web.migrations import run_migrations, schema_version


@pytest.fixture(autouse=True)
def _restore_migrations():
    """Snapshot + restore the module-level MIGRATIONS list.

    Tests here clip MIGRATIONS to stop at v34 so legacy rows can be
    seeded before v35 runs; restore the full list afterwards.
    """
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


def _conn_at_v34() -> sqlite3.Connection:
    """Return a fresh in-memory DB bootstrapped + migrated through v34.

    ``init_db`` lays the legacy base DDL then runs the numbered
    migrations. Clipping ``MIGRATIONS`` to ``<= 34`` before the
    ``init_db`` call stops the numbered framework at v34, so v35 is the
    single pending migration the tests then apply explicitly.
    """
    from email_triage.web.db import init_db

    saved = list(mig_mod.MIGRATIONS)
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(m for m in saved if m.version <= 34)
    try:
        c = init_db(":memory:")
    finally:
        mig_mod.MIGRATIONS.clear()
        mig_mod.MIGRATIONS.extend(saved)
    return c


def _seed_account(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (uid, "Mailbox", "imap", "{}", now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_legacy_row(
    conn: sqlite3.Connection, account_id: int, *, uid: int, attempts: int,
) -> None:
    """Insert a row into the v16 triage_retry_queue table."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO triage_retry_queue ("
        "  message_id, account_id, mailbox, uid, attempt_count, "
        "  next_attempt_at, last_error, last_error_type, "
        "  created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uid), account_id, "INBOX", str(uid), attempts,
            now, "ollama unreachable", "LLMBackendUnreachableError",
            now, now,
        ),
    )
    conn.commit()


class TestV35Apply:
    def test_v35_applies_on_top_of_v34(self):
        conn = _conn_at_v34()
        try:
            assert schema_version(conn) == 34
            applied = run_migrations(conn)
            assert 35 in applied
            # v35 applied; schema is at least 35 (later migrations —
            # v36+ — also run via run_migrations and advance it further).
            assert schema_version(conn) >= 35
        finally:
            conn.close()

    def test_failure_kind_column_added(self):
        conn = _conn_at_v34()
        try:
            run_migrations(conn)
            cols = {
                r[1]
                for r in conn.execute(
                    "PRAGMA table_info(watcher_retry_queue)"
                ).fetchall()
            }
            assert "failure_kind" in cols
        finally:
            conn.close()

    def test_triage_retry_queue_dropped(self):
        conn = _conn_at_v34()
        try:
            # v16 table exists before v35.
            assert conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='triage_retry_queue'"
            ).fetchone() is not None
            run_migrations(conn)
            # ...and is gone after.
            assert conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='triage_retry_queue'"
            ).fetchone() is None
        finally:
            conn.close()


class TestV35Backfill:
    def test_live_v16_rows_backfilled(self):
        conn = _conn_at_v34()
        try:
            account_id = _seed_account(conn)
            _seed_legacy_row(conn, account_id, uid=101, attempts=2)
            _seed_legacy_row(conn, account_id, uid=202, attempts=0)

            run_migrations(conn)

            rows = conn.execute(
                "SELECT account_id, provider_type, mailbox, uid, "
                "       uidvalidity, state, attempt_count, failure_kind "
                "FROM watcher_retry_queue ORDER BY uid"
            ).fetchall()
            assert len(rows) == 2

            r0 = dict(rows[0])
            assert r0["account_id"] == account_id
            assert r0["provider_type"] == "imap"
            assert r0["mailbox"] == "INBOX"
            assert r0["uid"] == 101
            assert r0["uidvalidity"] == 0  # sentinel for unknown epoch
            assert r0["state"] == "pending"
            assert r0["attempt_count"] == 2
            assert r0["failure_kind"] == "llm_unreachable"

            r1 = dict(rows[1])
            assert r1["uid"] == 202
            assert r1["attempt_count"] == 0
            assert r1["failure_kind"] == "llm_unreachable"
        finally:
            conn.close()

    def test_backfill_idempotent_on_rerun(self):
        """Re-running v35 against an already-migrated DB does not
        duplicate the backfilled rows (INSERT OR IGNORE on the v30
        UNIQUE partial index)."""
        conn = _conn_at_v34()
        try:
            account_id = _seed_account(conn)
            _seed_legacy_row(conn, account_id, uid=303, attempts=1)
            run_migrations(conn)
            count_after_first = conn.execute(
                "SELECT COUNT(*) FROM watcher_retry_queue"
            ).fetchone()[0]
            assert count_after_first == 1

            # Manually re-run the v35 body (the migration runner would
            # refuse — it tracks applied versions — so call the body
            # directly). It must not create a second row.
            v35 = next(m for m in mig_mod.MIGRATIONS if m.version == 35)
            v35.body(conn)
            conn.commit()
            count_after_second = conn.execute(
                "SELECT COUNT(*) FROM watcher_retry_queue"
            ).fetchone()[0]
            assert count_after_second == 1
        finally:
            conn.close()

    def test_no_v16_table_is_a_clean_noop(self):
        """A DB whose v16 table was already dropped (or never created)
        still applies v35 cleanly — the backfill skips."""
        conn = _conn_at_v34()
        try:
            conn.execute("DROP TABLE IF EXISTS triage_retry_queue")
            conn.commit()
            applied = run_migrations(conn)
            assert 35 in applied
            assert conn.execute(
                "SELECT COUNT(*) FROM watcher_retry_queue"
            ).fetchone()[0] == 0
        finally:
            conn.close()
