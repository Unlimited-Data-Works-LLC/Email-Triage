"""Tests for the durable triage retry queue (#149 Bundle A).

Covers the v16 migration round-trip + the enqueue / dequeue /
mark_succeeded / mark_terminal_failure surface + backoff math.
"""

from __future__ import annotations

import logging
import random
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.db import init_db
from email_triage.web.triage_retry_queue import (
    DEFAULT_BACKOFF_MINUTES,
    DEFAULT_MAX_ATTEMPTS,
    _compute_next_attempt_at,
    dequeue_ready,
    enqueue,
    mark_succeeded,
    mark_terminal_failure,
    queue_depth,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    # init_db sets up the legacy schema (settings, email_accounts,
    # ...) and then runs the numbered migration framework. v16 lands
    # at the end of that pipeline.
    c = init_db(":memory:")
    yield c
    c.close()


# ---------------------------------------------------------------------------
# Migration v16 round-trip
# ---------------------------------------------------------------------------

def test_v16_creates_triage_retry_queue(conn):
    """Migration v16 creates the table + index."""
    cur = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name = 'triage_retry_queue'"
    )
    assert cur.fetchone() is not None

    cur = conn.execute("PRAGMA table_info(triage_retry_queue)")
    cols = {row[1] for row in cur.fetchall()}
    assert {
        "id", "message_id", "account_id", "mailbox", "uid",
        "attempt_count", "next_attempt_at", "last_error",
        "last_error_type", "created_at", "updated_at",
    }.issubset(cols)

    # Index present.
    cur = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'index' AND name = 'idx_triage_retry_queue_ready'"
    )
    assert cur.fetchone() is not None


def test_v16_idempotent_rerun(conn):
    """Re-running migrations is a no-op once v16 is applied."""
    from email_triage.web.migrations import run_migrations
    second = run_migrations(conn)
    assert second == []
    # Sanity — table still there.
    conn.execute("SELECT id FROM triage_retry_queue").fetchall()


# ---------------------------------------------------------------------------
# enqueue / dequeue
# ---------------------------------------------------------------------------

def test_enqueue_first_time_creates_row(conn):
    err = ConnectionError("boom")
    row = enqueue(
        conn,
        message_id="abc",
        account_id=42,
        mailbox="INBOX",
        uid="123",
        error=err,
    )
    assert row["attempt_count"] == 0
    assert row["last_error_type"] == "ConnectionError"
    assert row["last_error"] == "boom"
    assert queue_depth(conn) == 1


def test_enqueue_second_time_bumps_attempt_and_extends_backoff(conn):
    err = ConnectionError("boom")
    row1 = enqueue(
        conn, message_id="abc", account_id=42,
        mailbox="INBOX", uid="123", error=err,
    )
    next_at_1 = row1["next_attempt_at"]

    err2 = ConnectionError("still bad")
    row2 = enqueue(
        conn, message_id="abc", account_id=42,
        mailbox="INBOX", uid="123", error=err2,
    )
    assert row2["attempt_count"] == 1
    # New backoff entry for attempt_count=1 is 2 minutes; first was
    # 1 minute. The new next_attempt_at should be later.
    assert row2["next_attempt_at"] > next_at_1
    assert row2["last_error"] == "still bad"
    # Still one row — UPDATE not INSERT.
    assert queue_depth(conn) == 1


def test_dequeue_ready_filters_by_next_attempt_at(conn):
    """Rows whose next_attempt_at is in the future are NOT returned."""
    enqueue(
        conn, message_id="m1", account_id=1, mailbox=None, uid=None,
        error=ConnectionError("x"),
    )
    # next_attempt_at is now+~1 minute → future, not ready.
    rows = dequeue_ready(conn, limit=10)
    assert rows == []

    # Force the row's next_attempt_at into the past so it shows up.
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    conn.execute(
        "UPDATE triage_retry_queue SET next_attempt_at = ?", (past,),
    )
    conn.commit()
    rows = dequeue_ready(conn, limit=10)
    assert len(rows) == 1
    assert rows[0]["message_id"] == "m1"


def test_dequeue_ready_filters_by_max_attempts(conn):
    """Rows whose attempt_count >= max_attempts are NOT returned."""
    enqueue(
        conn, message_id="m1", account_id=1, mailbox=None, uid=None,
        error=ConnectionError("x"),
    )
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    conn.execute(
        "UPDATE triage_retry_queue SET next_attempt_at = ?, attempt_count = ?",
        (past, DEFAULT_MAX_ATTEMPTS),
    )
    conn.commit()
    rows = dequeue_ready(conn, limit=10)
    assert rows == []

    # Bump max_attempts past the cap and the row is visible again.
    rows = dequeue_ready(conn, limit=10, max_attempts=DEFAULT_MAX_ATTEMPTS + 1)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# mark_succeeded / mark_terminal_failure
# ---------------------------------------------------------------------------

def test_mark_succeeded_deletes_row(conn):
    row = enqueue(
        conn, message_id="m1", account_id=1, mailbox=None, uid=None,
        error=ConnectionError("x"),
    )
    mark_succeeded(conn, row["id"])
    assert queue_depth(conn) == 0


def test_mark_terminal_failure_deletes_and_logs_error(conn, caplog):
    row = enqueue(
        conn, message_id="m1", account_id=1, mailbox=None, uid=None,
        error=ConnectionError("boom"),
    )
    with caplog.at_level(logging.ERROR, logger="email_triage.web.triage_retry_queue"):
        mark_terminal_failure(conn, row["id"], reason="max_attempts_exhausted")
    assert queue_depth(conn) == 0
    # Caller's ERROR record is present.
    assert any(
        "terminal failure" in r.message
        for r in caplog.records
    )


def test_mark_terminal_failure_idempotent_on_missing_row(conn):
    """Calling on a row that was already deleted is a no-op."""
    mark_terminal_failure(conn, 99999, reason="whatever")
    # No exception, no row.
    assert queue_depth(conn) == 0


# ---------------------------------------------------------------------------
# Backoff math
# ---------------------------------------------------------------------------

def test_backoff_schedule_is_eight_attempts_exponential():
    """Schedule has 8 entries; each is at least 1.5x the previous."""
    assert len(DEFAULT_BACKOFF_MINUTES) == 8
    for prev, nxt in zip(DEFAULT_BACKOFF_MINUTES, DEFAULT_BACKOFF_MINUTES[1:]):
        assert nxt >= prev  # monotonic non-decreasing


def test_backoff_jitter_within_ten_percent():
    """Repeatedly compute next_attempt_at for a fixed schedule index;
    the spread of returned minute counts stays inside ±10% of the
    base value."""
    base = DEFAULT_BACKOFF_MINUTES[3]  # 8 minutes
    rng = random.Random(42)
    samples: list[int] = []
    for _ in range(200):
        _, minutes = _compute_next_attempt_at(
            attempt_count=3, jitter_fraction=0.10, rng=rng,
        )
        samples.append(minutes)
    lo = min(samples)
    hi = max(samples)
    # Allow 1-minute integer-rounding slop.
    assert lo >= int(base * 0.9) - 1
    assert hi <= int(base * 1.1) + 1


def test_backoff_clamps_at_last_entry():
    """attempt_count past the schedule end uses the final schedule
    entry — not an out-of-bounds error."""
    _, minutes = _compute_next_attempt_at(
        attempt_count=999, jitter_fraction=0.0,
    )
    assert minutes == DEFAULT_BACKOFF_MINUTES[-1]
