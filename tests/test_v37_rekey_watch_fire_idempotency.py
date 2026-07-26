"""Tests for migration v37 — re-key watch_fire_idempotency.

v37 rebuilds ``watch_fire_idempotency`` (created by v36) so its key
is the RFC 5322 Message-ID instead of the provider message id. The
provider id is, for an IMAP account, the mailbox-scoped UID — it
collides across folders and UIDVALIDITY epochs, which let
``fire_watches_for_message`` wrongly suppress a watch.

Covers:
* v37 applies cleanly on top of v36.
* After v37 the table is keyed (account_id, rfc_message_id, watch_id)
  — the ``rfc_message_id`` column exists, the old ``message_id``
  column does not.
* The fired-at index survives the rebuild.
* Any rows held under the old v36 key are discarded by the rebuild
  (the table is brand-new + unreleased — there is no data to keep,
  and a stale UID-keyed claim is exactly what  removes).
* v37 does not trip the migration checksum guard — v36's body is
  left byte-identical, so a DB that already ran v36 still boots.
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.web.migrations import run_migrations, schema_version


@pytest.fixture(autouse=True)
def _restore_migrations():
    """Snapshot + restore the module-level MIGRATIONS list.

    Tests here clip MIGRATIONS to stop at v36 so the v36-era schema
    can be inspected / seeded before v37 runs; restore afterwards.
    """
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


def _conn_at_v36() -> sqlite3.Connection:
    """Return a fresh in-memory DB bootstrapped + migrated through v36.

    Clipping ``MIGRATIONS`` to ``<= 36`` before the ``init_db`` call
    stops the numbered framework at v36, so v37 is the single pending
    migration the tests then apply explicitly.
    """
    from email_triage.web.db import init_db

    saved = list(mig_mod.MIGRATIONS)
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(m for m in saved if m.version <= 36)
    try:
        c = track(init_db(":memory:"))
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


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        r[1]
        for r in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


class TestV37Apply:
    def test_v37_applies_on_top_of_v36(self):
        conn = _conn_at_v36()
        try:
            assert schema_version(conn) == 36
            applied = run_migrations(conn)
            assert 37 in applied
            assert schema_version(conn) >= 37
        finally:
            conn.close()

    def test_v36_schema_uses_provider_message_id(self):
        """Precondition — the v36 table is keyed on ``message_id``."""
        conn = _conn_at_v36()
        try:
            cols = _table_columns(conn, "watch_fire_idempotency")
            assert "message_id" in cols
            assert "rfc_message_id" not in cols
        finally:
            conn.close()

    def test_v37_rekeys_on_rfc_message_id(self):
        """After v37 the table is keyed on ``rfc_message_id``; the
        old provider ``message_id`` column is gone."""
        conn = _conn_at_v36()
        try:
            run_migrations(conn)
            cols = _table_columns(conn, "watch_fire_idempotency")
            assert "rfc_message_id" in cols
            assert "message_id" not in cols
            # Full column set after the rebuild.
            assert cols == {
                "account_id", "rfc_message_id", "watch_id", "fired_at",
            }
        finally:
            conn.close()

    def test_v37_primary_key_is_account_rfc_watch(self):
        """The PRIMARY KEY is (account_id, rfc_message_id, watch_id) —
        the three pk columns each report a non-zero pk position."""
        conn = _conn_at_v36()
        try:
            run_migrations(conn)
            pk = {
                r[1]: r[5]  # name -> pk position
                for r in conn.execute(
                    "PRAGMA table_info(watch_fire_idempotency)"
                ).fetchall()
                if r[5]  # pk position > 0
            }
            assert set(pk) == {"account_id", "rfc_message_id", "watch_id"}
        finally:
            conn.close()

    def test_v37_keeps_fired_at_index(self):
        """The fired-at index survives the rebuild."""
        conn = _conn_at_v36()
        try:
            run_migrations(conn)
            idx = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' "
                    "AND tbl_name='watch_fire_idempotency'"
                ).fetchall()
            }
            assert "idx_watch_fire_idempotency_fired" in idx
        finally:
            conn.close()


class TestV37Rebuild:
    def test_old_key_rows_discarded_by_rebuild(self):
        """A row written under the old v36 (provider-id) key is
        discarded by the v37 DROP+CREATE rebuild. The table is
        brand-new + unreleased, so there is no real data to preserve,
        and a stale UID-keyed claim is exactly the  Bug 2 hazard.
        """
        conn = _conn_at_v36()
        try:
            account_id = _seed_account(conn)
            # Seed a v36-era row keyed on the provider message id.
            conn.execute(
                "INSERT INTO watch_fire_idempotency "
                "(account_id, message_id, watch_id, fired_at) "
                "VALUES (?, ?, ?, ?)",
                (account_id, "42", "w-1",
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            assert conn.execute(
                "SELECT COUNT(*) FROM watch_fire_idempotency"
            ).fetchone()[0] == 1

            run_migrations(conn)  # applies v37

            # The rebuilt table is empty — the stale row is gone.
            assert conn.execute(
                "SELECT COUNT(*) FROM watch_fire_idempotency"
            ).fetchone()[0] == 0
        finally:
            conn.close()

    def test_v37_table_accepts_rfc_keyed_claim(self):
        """The rebuilt table accepts an INSERT keyed on the RFC
        Message-ID and enforces the new PK (a duplicate is rejected).
        """
        conn = _conn_at_v36()
        try:
            account_id = _seed_account(conn)
            run_migrations(conn)  # applies v37
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO watch_fire_idempotency "
                "(account_id, rfc_message_id, watch_id, fired_at) "
                "VALUES (?, ?, ?, ?)",
                (account_id, "<abc@host>", "w-1", now),
            )
            conn.commit()
            # The same (account, rfc_message_id, watch) is a PK clash.
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO watch_fire_idempotency "
                    "(account_id, rfc_message_id, watch_id, fired_at) "
                    "VALUES (?, ?, ?, ?)",
                    (account_id, "<abc@host>", "w-1", now),
                )
        finally:
            conn.close()

    def test_v37_rerun_does_not_trip_checksum_guard(self):
        """Re-running the migration runner against a v37 DB is a clean
        no-op — neither v36 nor v37 trips the checksum guard. (v36's
        body was left byte-identical when  added v37, so a DB that
        already applied v36 still boots.)"""
        conn = _conn_at_v36()
        try:
            run_migrations(conn)  # applies v37
            assert schema_version(conn) >= 37
            # A second run must apply nothing and must NOT raise.
            applied_again = run_migrations(conn)
            assert applied_again == []
        finally:
            conn.close()
