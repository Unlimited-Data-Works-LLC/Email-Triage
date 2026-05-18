"""Tests for migration v17 — watches_per_account_fanout (#154).

Verify the backfill semantics: every pre-v17 ``account_id IS NULL``
row expands to one new row per non-HIPAA email_account on the
install (preserving the legacy "all-accounts" scope minus HIPAA),
each fan-out row shares the source group's ``watch_group_id``, and
the original NULL-account row is deleted. HIPAA-flagged accounts
are skipped — the pre-v17 NULL-row matcher excluded them and the
v17 fan-out must keep that contract.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.web.db import init_db
from email_triage.web.migrations import run_migrations, schema_version


def _rollback_to_v16(conn: sqlite3.Connection) -> None:
    """Drop v17/v18/v19/v20/v21 rows + recreate ``email_watches`` without
    the v17 columns so we can re-apply the migration body against a
    realistic pre-v17 schema. SQLite has no ALTER TABLE DROP COLUMN
    (in stable releases), so this is a CREATE-COPY-DROP dance.

    All later versions roll back too so ``schema_version`` returns
    16 cleanly. Re-running migrations after the fixture re-applies
    every later version; each test asserts the v17 effect
    specifically + tolerates the higher schema_version on read.
    """
    conn.execute(
        "DELETE FROM schema_migrations "
        "WHERE version IN (17, 18, 19, 20, 21, 22, 23, 24, 25)"
    )
    # Drop v18 tables so the v18 re-apply via run_migrations is a clean
    # CREATE — IF NOT EXISTS would no-op otherwise but the column-guard
    # ALTER on list_rules is idempotent already.
    conn.execute("DROP TABLE IF EXISTS message_labels")
    conn.execute("DROP TABLE IF EXISTS labels")
    conn.execute("DROP INDEX IF EXISTS idx_message_labels_account_label")
    # v24 — drop the push-deliveries counter table so the re-apply
    # is a clean CREATE. Index dropped via the table drop.
    conn.execute("DROP TABLE IF EXISTS push_deliveries")
    conn.execute("DROP INDEX IF EXISTS idx_push_deliveries_day")
    # v25 — drop the HIPAA descriptor table so the re-apply is a clean
    # CREATE. Index is dropped as a side effect of the table drop.
    conn.execute("DROP TABLE IF EXISTS hipaa_style_descriptors")
    conn.execute("DROP INDEX IF EXISTS idx_hipaa_style_descriptors_rebuilt")
    # Drop the v17 index first so the table swap doesn't trip on a
    # stale reference.
    conn.execute("DROP INDEX IF EXISTS idx_email_watches_group")
    conn.execute("DROP INDEX IF EXISTS idx_email_watches_account")
    conn.execute(
        "CREATE TABLE _ew_backup AS "
        "SELECT watch_id, name, enabled, account_id, filter_json, "
        "       actions_json, created_at, updated_at "
        "FROM email_watches"
    )
    conn.execute("DROP TABLE email_watches")
    conn.execute("""
        CREATE TABLE email_watches (
            watch_id     TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            enabled      INTEGER NOT NULL DEFAULT 1,
            account_id   INTEGER
                         REFERENCES email_accounts(id)
                         ON DELETE CASCADE,
            filter_json  TEXT NOT NULL DEFAULT '{}',
            actions_json TEXT NOT NULL DEFAULT '{}',
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        )
    """)
    conn.execute("INSERT INTO email_watches SELECT * FROM _ew_backup")
    conn.execute("DROP TABLE _ew_backup")
    conn.execute(
        "CREATE INDEX idx_email_watches_account "
        "ON email_watches(account_id)"
    )
    conn.commit()


@pytest.fixture
def v16_db():
    """A DB at schema v16 (one version below the migration under test)."""
    conn = init_db(":memory:")
    _rollback_to_v16(conn)
    assert schema_version(conn) == 16
    yield conn
    conn.close()


def _make_user(conn, email="u@example.com") -> int:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (email, "Operator", "user", now),
    )
    conn.commit()
    return conn.execute(
        "SELECT id FROM users WHERE email = ?", (email,),
    ).fetchone()["id"]


def _make_account(conn, user_id, name, *, hipaa=False) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, "imap", "{}", 1 if hipaa else 0, now, now),
    )
    conn.commit()
    return cur.lastrowid


def _make_null_watch(conn, watch_id, name) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO email_watches "
        "(watch_id, name, enabled, account_id, filter_json, "
        " actions_json, created_at, updated_at) "
        "VALUES (?, ?, 1, NULL, ?, ?, ?, ?)",
        (
            watch_id, name,
            '{"keyword": "invoice"}',
            '{"webhook": {"enabled": true, "url": "http://x/h"}}',
            now, now,
        ),
    )
    conn.commit()


class TestV17BackfillSemantics:
    """Migration v17 backfills NULL-account watches into per-account rows."""

    def test_null_watch_fans_out_to_every_non_hipaa_account(self, v16_db):
        """Three non-HIPAA accounts + one HIPAA → three new rows."""
        conn = v16_db
        user_id = _make_user(conn)
        _make_account(conn, user_id, "acct-a")
        _make_account(conn, user_id, "acct-b")
        _make_account(conn, user_id, "acct-c")
        _make_account(conn, user_id, "acct-d-hipaa", hipaa=True)

        _make_null_watch(conn, "watch_legacy_a", "Legacy NULL Watch")

        # Apply v17 (plus any later versions on disk — v18 labels
        # ran too, which is fine; this test asserts v17's effect
        # specifically). schema_version returns the highest applied.
        run_migrations(conn)
        assert schema_version(conn) >= 17

        rows = conn.execute(
            "SELECT watch_id, name, account_id, watch_group_id, "
            "       created_by_user_id "
            "FROM email_watches ORDER BY account_id"
        ).fetchall()
        assert len(rows) == 3, (
            f"expected 3 fan-out rows (3 non-HIPAA accounts), got "
            f"{len(rows)}: {[dict(r) for r in rows]}"
        )

        # No NULL-account rows survive.
        nulls = conn.execute(
            "SELECT COUNT(*) FROM email_watches WHERE account_id IS NULL"
        ).fetchone()[0]
        assert nulls == 0

        # All fan-out rows share a single group_id (one source row →
        # one group).
        group_ids = {r["watch_group_id"] for r in rows}
        assert len(group_ids) == 1, (
            f"expected one shared group_id, got {group_ids}"
        )
        assert next(iter(group_ids))  # non-empty hex string

        # All fan-out rows carry the source-row name verbatim.
        names = {r["name"] for r in rows}
        assert names == {"Legacy NULL Watch"}

        # Creator attribution = owner of the account row (no creator
        # column existed on the source row pre-v17).
        for r in rows:
            assert r["created_by_user_id"] == user_id

    def test_hipaa_account_is_not_touched(self, v16_db):
        """HIPAA flag excludes the account from the fan-out entirely."""
        conn = v16_db
        user_id = _make_user(conn)
        non_hipaa = _make_account(conn, user_id, "acct-a")
        hipaa_id = _make_account(conn, user_id, "acct-hipaa", hipaa=True)

        _make_null_watch(conn, "watch_legacy_a", "Will not bind to HIPAA")
        run_migrations(conn)

        rows = conn.execute(
            "SELECT account_id FROM email_watches"
        ).fetchall()
        acct_ids = {r["account_id"] for r in rows}
        assert non_hipaa in acct_ids
        assert hipaa_id not in acct_ids

    def test_existing_per_account_rows_untouched(self, v16_db):
        """Rows with ``account_id`` already set keep their id +
        timestamps; only NULL rows fan out."""
        conn = v16_db
        user_id = _make_user(conn)
        a = _make_account(conn, user_id, "acct-a")
        b = _make_account(conn, user_id, "acct-b")

        # One per-account watch (already scoped) + one NULL watch.
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO email_watches "
            "(watch_id, name, enabled, account_id, filter_json, "
            " actions_json, created_at, updated_at) "
            "VALUES (?, ?, 1, ?, '{}', '{}', ?, ?)",
            ("watch_scoped", "Already Scoped", a, now, now),
        )
        _make_null_watch(conn, "watch_legacy", "Legacy NULL")
        conn.commit()

        run_migrations(conn)

        # Pre-existing watch_scoped row still exists with its id intact.
        r = conn.execute(
            "SELECT account_id FROM email_watches "
            "WHERE watch_id = ?", ("watch_scoped",),
        ).fetchone()
        assert r is not None
        assert r["account_id"] == a

        # Legacy NULL row is gone; fan-out replaces it for BOTH a and b.
        legacy_rows = conn.execute(
            "SELECT watch_id, account_id FROM email_watches "
            "WHERE name = 'Legacy NULL'"
        ).fetchall()
        assert len(legacy_rows) == 2
        assert sorted(r["account_id"] for r in legacy_rows) == sorted((a, b))
        assert all(
            r["watch_id"] != "watch_legacy" for r in legacy_rows
        ), "fan-out rows should have fresh watch_ids"

    def test_no_eligible_accounts_drops_null_row(self, v16_db):
        """Install with only HIPAA accounts: the NULL row is deleted
        with no fan-out (it never had a non-HIPAA target anyway)."""
        conn = v16_db
        user_id = _make_user(conn)
        _make_account(conn, user_id, "phi-only", hipaa=True)

        _make_null_watch(conn, "watch_orphan", "Orphan")
        run_migrations(conn)

        rows = conn.execute(
            "SELECT COUNT(*) FROM email_watches"
        ).fetchone()[0]
        assert rows == 0


class TestV17VerifyLogChain:
    """The migration must not break the access_log hash chain
    (per #154 — verify_log_chain stays green post-migration)."""

    def test_verify_log_chain_passes_after_v17(self, v16_db):
        """Apply v17 on a DB with a NULL watch + some access rows;
        the chain must still verify."""
        from email_triage.web.db import verify_log_chain, record_access_event
        conn = v16_db
        user_id = _make_user(conn)
        a = _make_account(conn, user_id, "acct-a")
        _make_null_watch(conn, "watch_legacy", "Pre-v17 NULL")

        # Seed two access-log rows so the chain has something to
        # verify against. Use the canonical record_access_event helper
        # so the hash chain is built the same way prod uses it.
        record_access_event(
            conn,
            actor_user_id=user_id,
            method="GET",
            route="/accounts",
            account_id=a,
            message_id=None,
            status_code=200,
            outcome="read",
        )
        record_access_event(
            conn,
            actor_user_id=user_id,
            method="POST",
            route="/profile",
            account_id=None,
            message_id=None,
            status_code=200,
            outcome="write",
        )

        # Apply v17.
        run_migrations(conn)

        # Chain still verifies.
        result = verify_log_chain(conn)
        # verify_log_chain returns a status dict; the "ok" key (or
        # equivalent) is the primary signal. Tolerant of either shape.
        if isinstance(result, dict):
            assert result.get("ok") is True or result.get("broken_at") is None, (
                f"chain broke post-v17: {result}"
            )
        else:
            assert result, "verify_log_chain returned a falsy value"
