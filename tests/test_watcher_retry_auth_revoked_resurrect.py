"""Behavior tests for :func:`resurrect_auth_revoked_retries` (N-386).

The SET half (``mark_retry_dead(reason='auth_revoked')`` at
``watcher_retry.py:175``) had no symmetric CLEAR on a provider-success path —
so a mid-outage frozen row stayed dead forever after the account recovered.

The fix routes the CLEAR through the ``record_provider_outcome`` funnel via
``_resurrect_auth_revoked_retries`` (app.py) → ``resurrect_auth_revoked_retries``
(db.py). These tests exercise the DB helper directly and assert:

* rows with ``dead_reason='auth_revoked'`` flip back to ``state='pending'``,
* rows with a different ``dead_reason`` are LEFT ALONE (terminal by design),
* rows for a DIFFERENT ``account_id`` are LEFT ALONE (per-account scope),
* pending rows are LEFT ALONE (no-op / idempotent).
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.db import (
    enqueue_retry,
    init_db,
    mark_retry_dead,
    resurrect_auth_revoked_retries,
)


# ---------------------------------------------------------------------------
# Fixtures — mirror test_watcher_retry_queue.py's setup.
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    """Fresh in-memory DB with all migrations applied."""
    c = track(init_db(":memory:"))
    yield c
    c.close()


def _seed_account(conn: sqlite3.Connection, email: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (email, "Op", "user", now),
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


@pytest.fixture
def account_id(conn: sqlite3.Connection) -> int:
    return _seed_account(conn, "op@example.com")


def _enqueue_and_mark_dead(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    uid: int,
    reason: str,
) -> int:
    retry_id = enqueue_retry(
        conn,
        account_id=account_id,
        provider_type="imap",
        mailbox="INBOX",
        uid=uid,
        uidvalidity=1,
        error_class="AUTHENTICATIONFAILED",
        error_msg="dead token",
    )
    mark_retry_dead(conn, retry_id, reason=reason)
    return retry_id


# ---------------------------------------------------------------------------
# Behavior
# ---------------------------------------------------------------------------

def _row(conn: sqlite3.Connection, retry_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT state, dead_reason, resolved_at, attempt_count "
        "FROM watcher_retry_queue WHERE id=?",
        (retry_id,),
    ).fetchone()
    assert row is not None, f"retry row {retry_id} vanished"
    return row


class TestResurrectAuthRevokedRetries:
    def test_flips_auth_revoked_dead_rows_back_to_pending(self, conn, account_id):
        a = _enqueue_and_mark_dead(conn, account_id, uid=101, reason="auth_revoked")
        b = _enqueue_and_mark_dead(conn, account_id, uid=102, reason="auth_revoked")
        # sanity
        assert _row(conn, a)["state"] == "dead"
        assert _row(conn, b)["state"] == "dead"

        n = resurrect_auth_revoked_retries(conn, account_id)
        assert n == 2

        for retry_id in (a, b):
            r = _row(conn, retry_id)
            assert r["state"] == "pending"
            assert r["dead_reason"] is None
            assert r["resolved_at"] is None
            assert r["attempt_count"] == 0

    def test_leaves_non_auth_revoked_dead_rows_alone(self, conn, account_id):
        # These 4 are terminal by design and MUST NOT be resurrected.
        # (message_expunged is included; the 5th, operator_abandoned, is
        # tested separately as it uses the same code path.)
        keep = [
            _enqueue_and_mark_dead(conn, account_id, uid=201, reason="max_attempts_exceeded"),
            _enqueue_and_mark_dead(conn, account_id, uid=202, reason="uidvalidity_changed"),
            _enqueue_and_mark_dead(conn, account_id, uid=203, reason="message_gone"),
            _enqueue_and_mark_dead(conn, account_id, uid=204, reason="message_expunged"),
        ]
        # and one auth_revoked row to prove the helper still fires on THAT
        revoked = _enqueue_and_mark_dead(
            conn, account_id, uid=205, reason="auth_revoked",
        )

        n = resurrect_auth_revoked_retries(conn, account_id)
        assert n == 1

        for retry_id in keep:
            r = _row(conn, retry_id)
            assert r["state"] == "dead", (
                f"row {retry_id} with terminal-by-design reason "
                f"{r['dead_reason']!r} was incorrectly resurrected"
            )
        assert _row(conn, revoked)["state"] == "pending"

    def test_leaves_other_account_rows_alone(self, conn, account_id):
        other = _seed_account(conn, "other@example.com")
        mine = _enqueue_and_mark_dead(
            conn, account_id, uid=301, reason="auth_revoked",
        )
        theirs = _enqueue_and_mark_dead(
            conn, other, uid=301, reason="auth_revoked",
        )
        assert mine != theirs

        n = resurrect_auth_revoked_retries(conn, account_id)
        assert n == 1

        assert _row(conn, mine)["state"] == "pending"
        assert _row(conn, theirs)["state"] == "dead"

    def test_leaves_pending_rows_alone_noop(self, conn, account_id):
        # A pending row for the same account is NOT touched (no dead_reason).
        pending = enqueue_retry(
            conn,
            account_id=account_id,
            provider_type="imap",
            mailbox="INBOX", uid=401, uidvalidity=1,
            error_class="OSError", error_msg="transient",
        )
        original = _row(conn, pending)

        n = resurrect_auth_revoked_retries(conn, account_id)
        assert n == 0

        current = _row(conn, pending)
        assert current["state"] == "pending"
        assert current["attempt_count"] == original["attempt_count"]

    def test_idempotent_second_call_is_noop(self, conn, account_id):
        _enqueue_and_mark_dead(
            conn, account_id, uid=501, reason="auth_revoked",
        )
        n1 = resurrect_auth_revoked_retries(conn, account_id)
        n2 = resurrect_auth_revoked_retries(conn, account_id)
        assert n1 == 1
        assert n2 == 0

    def test_operator_abandoned_stays_dead(self, conn, account_id):
        """operator_abandoned is terminal by design — an auth restore MUST NOT
        undo the operator's explicit abandonment."""
        row_id = _enqueue_and_mark_dead(
            conn, account_id, uid=601, reason="operator_abandoned",
        )
        n = resurrect_auth_revoked_retries(conn, account_id)
        assert n == 0
        r = _row(conn, row_id)
        assert r["state"] == "dead"
        assert r["dead_reason"] == "operator_abandoned"

    def test_resurrected_row_has_fresh_next_attempt_at(self, conn, account_id):
        # Batched SME panel fold (2026-07-10): tighten the upper bound from
        # `now + 1h` (which silently passed a `compute_next_attempt_at(999, …)`
        # regression that landed on the 1h tier of the schedule) to
        # `WATCHER_RETRY_SCHEDULE[0] + small clock-jitter tolerance`. The
        # resurrect helper is hard-wired to attempt-index 0 (db.py) — index 1
        # (2m), 2 (10m), or 3 (1h) would now fail the assertion loudly.
        from email_triage.retry_backoff import WATCHER_RETRY_SCHEDULE

        row_id = _enqueue_and_mark_dead(
            conn, account_id, uid=701, reason="auth_revoked",
        )
        before = datetime.now(timezone.utc)
        resurrect_auth_revoked_retries(conn, account_id)
        na = conn.execute(
            "SELECT next_attempt_at FROM watcher_retry_queue WHERE id=?",
            (row_id,),
        ).fetchone()[0]
        # next_attempt_at is written via to_utc_iso — parseable ISO with tz.
        parsed = datetime.fromisoformat(na)
        first_backoff = WATCHER_RETRY_SCHEDULE[0]
        assert parsed >= before - timedelta(seconds=5), (
            f"next_attempt_at {parsed} is older than expected — helper did "
            "not compute a fresh one"
        )
        # Upper bound: the resurrect helper calls
        # `compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)` which returns
        # ``now() + WATCHER_RETRY_SCHEDULE[0]``. Allow 5s tolerance for
        # internal clock advance between our `before` capture and the helper's
        # `now()` — a wider tolerance silently swallows an off-by-one that
        # picks the 2m / 10m / 1h tier of the schedule.
        assert parsed <= before + first_backoff + timedelta(seconds=5), (
            f"next_attempt_at {parsed} exceeds the first-backoff window "
            f"({first_backoff}) — helper is likely mis-parametrised to a "
            "later attempt-index of WATCHER_RETRY_SCHEDULE"
        )
