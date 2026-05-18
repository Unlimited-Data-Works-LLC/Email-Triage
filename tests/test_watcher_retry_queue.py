"""Tests for the watcher per-message retry queue (#175 R-A).

Covers:
* Migration v30 round-trip — table + indexes + CHECK constraints.
* The 7 web/db helpers: enqueue_retry, list_due_retries,
  mark_retry_done, mark_retry_dead, get_retry, list_retries_for_admin,
  count_recent_deads.
* PHI scrub on ``last_error_msg``.
* Idempotent re-enqueue (UNIQUE-partial index path).
* Dead-state transitions for all 5 dead_reason values.
* Privacy invariant: no plaintext token ever lands in last_error_msg.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.db import (
    WATCHER_RETRY_DEAD_REASONS,
    _scrub_watcher_retry_error_msg,
    count_recent_deads,
    enqueue_retry,
    get_retry,
    init_db,
    list_due_retries,
    list_retries_for_admin,
    mark_retry_dead,
    mark_retry_done,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    """Fresh in-memory DB with all migrations applied."""
    c = init_db(":memory:")
    yield c
    c.close()


@pytest.fixture
def account_id(conn: sqlite3.Connection) -> int:
    """Seed a user + account; return the account id."""
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


# ---------------------------------------------------------------------------
# Migration v30 round-trip
# ---------------------------------------------------------------------------

class TestMigrationV30:
    def test_table_exists(self, conn):
        row = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='watcher_retry_queue'"
        ).fetchone()
        assert row is not None

    def test_columns_present(self, conn):
        cols = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(watcher_retry_queue)"
            ).fetchall()
        }
        expected = {
            "id", "account_id", "provider_type",
            "mailbox", "uid", "uidvalidity",
            "gmail_msg_id", "o365_msg_id",
            "state", "attempt_count",
            "first_seen_at", "next_attempt_at",
            "last_error_class", "last_error_msg", "last_error_at",
            "resolved_at", "dead_reason", "created_at",
        }
        assert expected.issubset(cols)

    def test_state_check_constraint(self, conn, account_id):
        """The state column CHECK rejects bad values."""
        future = datetime.now(timezone.utc).isoformat()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, gmail_msg_id, state, "
                " next_attempt_at) "
                "VALUES (?, 'gmail', 'msgid', 'bogus', ?)",
                (account_id, future),
            )

    def test_provider_type_check_constraint(self, conn, account_id):
        future = datetime.now(timezone.utc).isoformat()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, gmail_msg_id, "
                " next_attempt_at) "
                "VALUES (?, 'pop3', 'msgid', ?)",
                (account_id, future),
            )

    def test_unique_partial_index_imap(self, conn, account_id):
        """Two pending IMAP rows with the same (mailbox, uid, uidvalidity)
        are blocked by the UNIQUE-partial index."""
        future = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, mailbox, uid, uidvalidity, "
            " next_attempt_at) "
            "VALUES (?, 'imap', 'INBOX', 100, 12345, ?)",
            (account_id, future),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, mailbox, uid, uidvalidity, "
                " next_attempt_at) "
                "VALUES (?, 'imap', 'INBOX', 100, 12345, ?)",
                (account_id, future),
            )
        conn.rollback()

    def test_unique_partial_index_gmail(self, conn, account_id):
        future = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, gmail_msg_id, next_attempt_at) "
            "VALUES (?, 'gmail', 'm1', ?)",
            (account_id, future),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, gmail_msg_id, next_attempt_at) "
                "VALUES (?, 'gmail', 'm1', ?)",
                (account_id, future),
            )
        conn.rollback()

    def test_unique_partial_index_o365(self, conn, account_id):
        future = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, o365_msg_id, next_attempt_at) "
            "VALUES (?, 'office365', 'o1', ?)",
            (account_id, future),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, o365_msg_id, next_attempt_at) "
                "VALUES (?, 'office365', 'o1', ?)",
                (account_id, future),
            )
        conn.rollback()

    def test_account_id_cascade_on_delete(self, conn, account_id):
        """Deleting the parent email_accounts row cascades to retries."""
        rid = enqueue_retry(
            conn, account_id=account_id,
            provider_type="gmail", gmail_msg_id="cascade-test",
            error_class="X", error_msg="x",
        )
        assert get_retry(conn, rid) is not None
        conn.execute(
            "DELETE FROM email_accounts WHERE id=?", (account_id,),
        )
        conn.commit()
        assert get_retry(conn, rid) is None


# ---------------------------------------------------------------------------
# enqueue_retry — addressing validation
# ---------------------------------------------------------------------------

class TestEnqueueValidation:
    def test_imap_requires_mailbox_uid_uidvalidity(self, conn, account_id):
        with pytest.raises(ValueError):
            enqueue_retry(
                conn, account_id=account_id, provider_type="imap",
                error_class="X",
            )
        with pytest.raises(ValueError):
            enqueue_retry(
                conn, account_id=account_id, provider_type="imap",
                mailbox="INBOX", uid=1,
                error_class="X",
            )

    def test_gmail_requires_gmail_msg_id(self, conn, account_id):
        with pytest.raises(ValueError):
            enqueue_retry(
                conn, account_id=account_id, provider_type="gmail",
                error_class="X",
            )

    def test_o365_requires_o365_msg_id(self, conn, account_id):
        with pytest.raises(ValueError):
            enqueue_retry(
                conn, account_id=account_id, provider_type="office365",
                error_class="X",
            )

    def test_unknown_provider_type_raises(self, conn, account_id):
        with pytest.raises(ValueError):
            enqueue_retry(
                conn, account_id=account_id, provider_type="pop3",
                error_class="X",
            )


# ---------------------------------------------------------------------------
# enqueue_retry — fresh insert
# ---------------------------------------------------------------------------

class TestEnqueueInsert:
    def test_imap_fresh_insert(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id,
            provider_type="imap",
            mailbox="INBOX", uid=83231, uidvalidity=42,
            error_class="asyncio.TimeoutError",
            error_msg="timed out",
        )
        row = get_retry(conn, rid)
        assert row is not None
        assert row["state"] == "pending"
        assert row["attempt_count"] == 0
        assert row["provider_type"] == "imap"
        assert row["mailbox"] == "INBOX"
        assert row["uid"] == 83231
        assert row["uidvalidity"] == 42
        assert row["gmail_msg_id"] is None
        assert row["o365_msg_id"] is None
        assert row["last_error_class"] == "asyncio.TimeoutError"
        assert row["last_error_msg"] == "timed out"

    def test_gmail_fresh_insert(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id,
            provider_type="gmail", gmail_msg_id="msg-123",
            error_class="HTTPError", error_msg="503",
        )
        row = get_retry(conn, rid)
        assert row["provider_type"] == "gmail"
        assert row["gmail_msg_id"] == "msg-123"
        assert row["mailbox"] is None
        assert row["uid"] is None
        assert row["uidvalidity"] is None

    def test_o365_fresh_insert(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id,
            provider_type="office365", o365_msg_id="o-msg-1",
            error_class="HTTPError", error_msg="503",
        )
        row = get_retry(conn, rid)
        assert row["provider_type"] == "office365"
        assert row["o365_msg_id"] == "o-msg-1"

    def test_first_enqueue_schedules_30s_out(self, conn, account_id):
        before = datetime.now(timezone.utc)
        rid = enqueue_retry(
            conn, account_id=account_id,
            provider_type="gmail", gmail_msg_id="m1",
            error_class="X", error_msg="x",
        )
        after = datetime.now(timezone.utc)
        row = get_retry(conn, rid)
        next_at = datetime.fromisoformat(row["next_attempt_at"])
        # First retry should be ~30s from now (the first
        # WATCHER_RETRY_SCHEDULE entry).
        assert before + timedelta(seconds=29) <= next_at <= (
            after + timedelta(seconds=31)
        )


# ---------------------------------------------------------------------------
# enqueue_retry — re-enqueue (duplicate addressing)
# ---------------------------------------------------------------------------

class TestEnqueueDedup:
    def test_duplicate_imap_bumps_attempt_count(self, conn, account_id):
        rid1 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=1,
            error_class="X", error_msg="x",
        )
        rid2 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=1,
            error_class="Y", error_msg="y",
        )
        assert rid1 == rid2
        row = get_retry(conn, rid1)
        assert row["attempt_count"] == 1
        assert row["last_error_class"] == "Y"
        assert row["last_error_msg"] == "y"

    def test_different_uid_creates_separate_row(self, conn, account_id):
        r1 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=1,
            error_class="X", error_msg="x",
        )
        r2 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=11, uidvalidity=1,
            error_class="X", error_msg="x",
        )
        assert r1 != r2

    def test_different_uidvalidity_creates_separate_row(self, conn, account_id):
        """Different UIDVALIDITY means the IMAP server renumbered.
        New row is correct — the old UID is now meaningless."""
        r1 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=1,
            error_class="X", error_msg="x",
        )
        r2 = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=2,
            error_class="X", error_msg="x",
        )
        assert r1 != r2

    def test_dead_row_resurrects_on_reenqueue(self, conn, account_id):
        """An identical message that already went to dead state can
        re-enqueue — sets state back to pending + clears terminal fields.
        Without this, a UNIQUE partial index would block re-enqueue
        forever after the first dead row."""
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="X", error_msg="x",
        )
        mark_retry_dead(conn, rid, reason="auth_revoked")
        rid2 = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="Y", error_msg="y",
        )
        assert rid == rid2
        row = get_retry(conn, rid)
        assert row["state"] == "pending"
        assert row["attempt_count"] == 0
        assert row["dead_reason"] is None
        assert row["resolved_at"] is None
        assert row["last_error_class"] == "Y"


# ---------------------------------------------------------------------------
# list_due_retries
# ---------------------------------------------------------------------------

class TestListDueRetries:
    def test_returns_pending_due_rows_only(self, conn, account_id):
        # Insert a row whose next_attempt_at is in the past.
        past = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        future = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        conn.executemany(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, gmail_msg_id, state, "
            " next_attempt_at) "
            "VALUES (?, 'gmail', ?, ?, ?)",
            [
                (account_id, "due-pending", "pending", past),
                (account_id, "future-pending", "pending", future),
                (account_id, "due-done", "done", past),
                (account_id, "due-dead", "dead", past),
            ],
        )
        conn.commit()
        rows = list_due_retries(conn, limit=10)
        gmail_ids = {r["gmail_msg_id"] for r in rows}
        assert gmail_ids == {"due-pending"}

    def test_limit_caps_result(self, conn, account_id):
        past = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        for i in range(5):
            conn.execute(
                "INSERT INTO watcher_retry_queue "
                "(account_id, provider_type, gmail_msg_id, state, "
                " next_attempt_at) "
                "VALUES (?, 'gmail', ?, 'pending', ?)",
                (account_id, f"msg-{i}", past),
            )
        conn.commit()
        rows = list_due_retries(conn, limit=3)
        assert len(rows) == 3

    def test_ordered_by_next_attempt_at(self, conn, account_id):
        """The longest-overdue row comes first."""
        now = datetime.now(timezone.utc)
        t1 = (now - timedelta(hours=2)).isoformat()
        t2 = (now - timedelta(hours=1)).isoformat()
        t3 = (now - timedelta(minutes=10)).isoformat()
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, gmail_msg_id, state, "
            " next_attempt_at) VALUES (?, 'gmail', 'c', 'pending', ?)",
            (account_id, t3),
        )
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, gmail_msg_id, state, "
            " next_attempt_at) VALUES (?, 'gmail', 'a', 'pending', ?)",
            (account_id, t1),
        )
        conn.execute(
            "INSERT INTO watcher_retry_queue "
            "(account_id, provider_type, gmail_msg_id, state, "
            " next_attempt_at) VALUES (?, 'gmail', 'b', 'pending', ?)",
            (account_id, t2),
        )
        conn.commit()
        rows = list_due_retries(conn, limit=10)
        ids = [r["gmail_msg_id"] for r in rows]
        assert ids == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# mark_retry_done / mark_retry_dead
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_mark_done_transitions_pending_to_done(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="X", error_msg="x",
        )
        mark_retry_done(conn, rid)
        row = get_retry(conn, rid)
        assert row["state"] == "done"
        assert row["resolved_at"] is not None

    def test_mark_done_is_idempotent_on_done_row(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="X", error_msg="x",
        )
        mark_retry_done(conn, rid)
        first_resolved = get_retry(conn, rid)["resolved_at"]
        # Second call: state stays done; resolved_at NOT advanced
        # (the UPDATE has a WHERE state='pending' guard).
        mark_retry_done(conn, rid)
        assert get_retry(conn, rid)["resolved_at"] == first_resolved

    @pytest.mark.parametrize("reason", [
        "max_attempts_exceeded",
        "uidvalidity_changed",
        "message_gone",
        "auth_revoked",
        "operator_abandoned",
    ])
    def test_mark_dead_all_valid_reasons(self, conn, account_id, reason):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id=f"m-{reason}",
            error_class="X", error_msg="x",
        )
        mark_retry_dead(conn, rid, reason=reason)
        row = get_retry(conn, rid)
        assert row["state"] == "dead"
        assert row["dead_reason"] == reason
        assert row["resolved_at"] is not None

    def test_mark_dead_rejects_invalid_reason(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="X", error_msg="x",
        )
        with pytest.raises(ValueError):
            mark_retry_dead(conn, rid, reason="invented_reason")

    def test_dead_reasons_constant_complete(self):
        """Catalog rule: keep WATCHER_RETRY_DEAD_REASONS aligned with
        the parametrized set above. If you add a reason, add it here."""
        assert WATCHER_RETRY_DEAD_REASONS == frozenset({
            "max_attempts_exceeded",
            "uidvalidity_changed",
            "message_gone",
            "auth_revoked",
            "operator_abandoned",
        })


# ---------------------------------------------------------------------------
# PHI scrub on last_error_msg
# ---------------------------------------------------------------------------

class TestPhiScrub:
    """The error message is PHI-scrubbed at the persistence boundary.

    HIPAA accounts may have provider error responses that incidentally
    carry PHI in dict-repr form. We strip token-shape keys and truncate
    to 500 chars regardless of the account's HIPAA flag — defence in
    depth.
    """

    def test_scrub_strips_access_token(self):
        msg = '{"access_token": "secret_value_123", "error": "invalid"}'
        scrubbed = _scrub_watcher_retry_error_msg(msg)
        assert "secret_value_123" not in scrubbed
        assert "[REDACTED]" in scrubbed
        assert "invalid" in scrubbed  # operator-debugging info preserved

    def test_scrub_strips_refresh_token(self):
        msg = "got refresh_token='abcdef123' from provider"
        scrubbed = _scrub_watcher_retry_error_msg(msg)
        assert "abcdef123" not in scrubbed

    def test_scrub_strips_api_key(self):
        msg = '{"api_key": "sk-prod-1234567890"}'
        scrubbed = _scrub_watcher_retry_error_msg(msg)
        assert "sk-prod-1234567890" not in scrubbed

    def test_scrub_strips_password(self):
        msg = '{"password": "p@ssw0rd"}'
        scrubbed = _scrub_watcher_retry_error_msg(msg)
        assert "p@ssw0rd" not in scrubbed

    def test_scrub_truncates_to_500_chars(self):
        msg = "x" * 5000
        scrubbed = _scrub_watcher_retry_error_msg(msg)
        assert len(scrubbed) <= 500
        assert scrubbed.endswith("...")

    def test_scrub_handles_none(self):
        assert _scrub_watcher_retry_error_msg(None) is None

    def test_enqueue_scrubs_at_persistence_boundary(self, conn, account_id):
        """Privacy invariant: nothing token-shaped EVER lands in the
        DB. Test the scrub fires through the public enqueue path."""
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="phi-test",
            error_class="OAuthError",
            error_msg='{"access_token": "leaked-secret-xyz"}',
        )
        row = get_retry(conn, rid)
        stored = row["last_error_msg"]
        # The leaked-secret-xyz value must not be in the DB.
        assert "leaked-secret-xyz" not in stored
        assert "[REDACTED]" in stored


# ---------------------------------------------------------------------------
# list_retries_for_admin
# ---------------------------------------------------------------------------

class TestListForAdmin:
    def test_filters_by_account(self, conn):
        # Two accounts.
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)", ("a@example.com", "A", "user", now),
        )
        uid = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, 'A1', 'imap', '{}', ?, ?)",
            (uid, now, now),
        )
        a1 = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, 'A2', 'gmail', '{}', ?, ?)",
            (uid, now, now),
        )
        a2 = int(cur.lastrowid)
        conn.commit()
        enqueue_retry(
            conn, account_id=a1, provider_type="gmail",
            gmail_msg_id="x", error_class="X", error_msg="x",
        )
        enqueue_retry(
            conn, account_id=a2, provider_type="gmail",
            gmail_msg_id="y", error_class="X", error_msg="x",
        )
        rows = list_retries_for_admin(conn, account_id=a1)
        assert len(rows) == 1
        assert rows[0]["account_id"] == a1

    def test_filters_by_state(self, conn, account_id):
        r1 = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m1", error_class="X", error_msg="x",
        )
        r2 = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="m2", error_class="X", error_msg="x",
        )
        mark_retry_done(conn, r1)
        pending = list_retries_for_admin(conn, state="pending")
        assert {r["id"] for r in pending} == {r2}
        done = list_retries_for_admin(conn, state="done")
        assert {r["id"] for r in done} == {r1}


# ---------------------------------------------------------------------------
# count_recent_deads
# ---------------------------------------------------------------------------

class TestCountRecentDeads:
    def test_counts_recent_dead_rows(self, conn, account_id):
        r1 = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="d1", error_class="X", error_msg="x",
        )
        r2 = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="d2", error_class="X", error_msg="x",
        )
        mark_retry_dead(conn, r1, reason="max_attempts_exceeded")
        mark_retry_dead(conn, r2, reason="auth_revoked")
        # Both within the default 24h window.
        assert count_recent_deads(conn) == 2
        assert count_recent_deads(conn, account_id=account_id) == 2

    def test_ignores_old_dead_rows(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="old", error_class="X", error_msg="x",
        )
        mark_retry_dead(conn, rid, reason="max_attempts_exceeded")
        # Backdate resolved_at to 48h ago.
        old = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).isoformat()
        conn.execute(
            "UPDATE watcher_retry_queue SET resolved_at=? WHERE id=?",
            (old, rid),
        )
        conn.commit()
        assert count_recent_deads(conn, since_hours=24) == 0
        # But a wider window catches it.
        assert count_recent_deads(conn, since_hours=72) == 1

    def test_excludes_non_dead_rows(self, conn, account_id):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="gmail",
            gmail_msg_id="alive", error_class="X", error_msg="x",
        )
        mark_retry_done(conn, rid)
        assert count_recent_deads(conn) == 0


# ---------------------------------------------------------------------------
# Schedule-exhaustion path
# ---------------------------------------------------------------------------

class TestScheduleExhaustion:
    def test_attempt_count_advances_per_enqueue(self, conn, account_id):
        """After 6 enqueues (the schedule length), attempt_count = 6."""
        for _ in range(7):
            enqueue_retry(
                conn, account_id=account_id, provider_type="gmail",
                gmail_msg_id="exhaust", error_class="X", error_msg="x",
            )
        row = conn.execute(
            "SELECT attempt_count FROM watcher_retry_queue "
            "WHERE gmail_msg_id='exhaust'"
        ).fetchone()
        assert row["attempt_count"] == 6
