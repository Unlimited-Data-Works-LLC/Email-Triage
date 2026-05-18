"""Tests for the style_distill_queue retry-with-backoff helpers (#152 S3).

Validates:

  * v27 migration creates the two tables + indexes.
  * ``enqueue_style_distill_retry`` increments attempt_count.
  * Exponential backoff schedule (1m / 5m / 30m / 2h / 12h / 1d / 3d / 7d).
  * ``scrubber_fail`` -> ``pause_style_distill_account`` halts retries.
  * ``claim_next_style_distill_queue_entry`` picks the oldest ready row.
  * ``style_distill_event_counts`` rolls 24h counters per outcome bucket.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

from email_triage.web.db import (
    STYLE_DISTILL_BACKOFF_SECONDS,
    STYLE_DISTILL_MAX_ATTEMPTS,
    _style_distill_compute_next_retry,
    claim_next_style_distill_queue_entry,
    clear_style_distill_queue_entry,
    enqueue_style_distill_retry,
    get_style_distill_queue_entry,
    init_db,
    list_paused_style_distill_accounts,
    pause_style_distill_account,
    record_style_distill_event,
    style_distill_event_counts,
    unpause_style_distill_account,
)


@pytest.fixture
def db() -> sqlite3.Connection:
    return init_db(":memory:")


def _seed_account(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    user_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, 1, ?, ?)",
        (user_id, "Mailbox", "imap", "{}", now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# Backoff schedule
# ---------------------------------------------------------------------------

class TestBackoffSchedule:
    def test_pinned_schedule_matches_spec(self):
        """The schedule is operator-locked at: 1m / 5m / 30m / 2h /
        12h / 1d / 3d / 7d (8 attempts). Any change requires explicit
        operator sign-off."""
        expected = (60, 300, 1800, 7200, 43200, 86400, 259200, 604800)
        assert STYLE_DISTILL_BACKOFF_SECONDS == expected
        assert STYLE_DISTILL_MAX_ATTEMPTS == 8

    def test_next_retry_at_attempt_1_is_1_minute_out(self):
        now = datetime.now(timezone.utc)
        next_retry = _style_distill_compute_next_retry(1, now=now)
        parsed = datetime.fromisoformat(next_retry)
        delta = (parsed - now).total_seconds()
        assert 59 <= delta <= 61

    def test_next_retry_at_final_attempt_is_7_days(self):
        now = datetime.now(timezone.utc)
        next_retry = _style_distill_compute_next_retry(8, now=now)
        parsed = datetime.fromisoformat(next_retry)
        delta = (parsed - now).total_seconds()
        # 7 days +/- 1s
        assert 7 * 86400 - 1 <= delta <= 7 * 86400 + 1

    def test_next_retry_at_beyond_final_returns_none(self):
        assert _style_distill_compute_next_retry(9) is None
        assert _style_distill_compute_next_retry(99) is None


# ---------------------------------------------------------------------------
# Enqueue / clear
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_enqueue_creates_row_with_attempt_1(self, db):
        aid = _seed_account(db)
        result = enqueue_style_distill_retry(
            db, account_id=aid, last_error="HTTPError",
        )
        assert result["attempt_count"] == 1
        assert result["next_retry_at"] is not None
        row = get_style_distill_queue_entry(db, account_id=aid)
        assert row["attempt_count"] == 1
        assert row["last_error"] == "HTTPError"
        assert row["paused"] == 0

    def test_enqueue_twice_increments_attempt(self, db):
        aid = _seed_account(db)
        enqueue_style_distill_retry(db, account_id=aid, last_error="x")
        enqueue_style_distill_retry(db, account_id=aid, last_error="y")
        row = get_style_distill_queue_entry(db, account_id=aid)
        assert row["attempt_count"] == 2
        assert row["last_error"] == "y"

    def test_paused_row_does_not_re_enqueue(self, db):
        """A paused row stays paused; enqueue is a no-op (no
        attempt_count bump, no next_retry_at set)."""
        aid = _seed_account(db)
        pause_style_distill_account(
            db, account_id=aid, last_error="scrubber_fail",
        )
        before = get_style_distill_queue_entry(db, account_id=aid)
        result = enqueue_style_distill_retry(
            db, account_id=aid, last_error="HTTPError",
        )
        assert result["paused"] is True
        after = get_style_distill_queue_entry(db, account_id=aid)
        # Attempt count unchanged.
        assert after["attempt_count"] == before["attempt_count"]
        assert after["paused"] == 1
        assert after["next_retry_at"] is None

    def test_clear_removes_entry(self, db):
        aid = _seed_account(db)
        enqueue_style_distill_retry(db, account_id=aid, last_error="x")
        assert get_style_distill_queue_entry(db, account_id=aid) is not None
        clear_style_distill_queue_entry(db, account_id=aid)
        assert get_style_distill_queue_entry(db, account_id=aid) is None

    def test_clear_idempotent(self, db):
        aid = _seed_account(db)
        clear_style_distill_queue_entry(db, account_id=aid)  # no row yet
        clear_style_distill_queue_entry(db, account_id=aid)  # still no row


# ---------------------------------------------------------------------------
# Pause / unpause
# ---------------------------------------------------------------------------

class TestPauseUnpause:
    def test_pause_sets_paused_flag_clears_next_retry(self, db):
        aid = _seed_account(db)
        enqueue_style_distill_retry(db, account_id=aid, last_error="x")
        pause_style_distill_account(
            db, account_id=aid, last_error="scrubber_fail",
        )
        row = get_style_distill_queue_entry(db, account_id=aid)
        assert row["paused"] == 1
        assert row["next_retry_at"] is None
        assert row["last_error"] == "scrubber_fail"

    def test_pause_on_missing_row_creates_one(self, db):
        aid = _seed_account(db)
        pause_style_distill_account(
            db, account_id=aid, last_error="scrubber_fail",
        )
        row = get_style_distill_queue_entry(db, account_id=aid)
        assert row is not None
        assert row["paused"] == 1

    def test_unpause_clears_paused_and_resets_attempts(self, db):
        aid = _seed_account(db)
        pause_style_distill_account(
            db, account_id=aid, last_error="scrubber_fail",
        )
        unpause_style_distill_account(db, account_id=aid)
        row = get_style_distill_queue_entry(db, account_id=aid)
        assert row["paused"] == 0
        assert row["attempt_count"] == 0
        assert row["last_error"] is None

    def test_list_paused_surfaces_account_name(self, db):
        aid = _seed_account(db)
        pause_style_distill_account(
            db, account_id=aid, last_error="scrubber_fail",
        )
        paused = list_paused_style_distill_accounts(db)
        assert len(paused) == 1
        assert paused[0]["account_id"] == aid
        assert paused[0]["account_name"] == "Mailbox"


# ---------------------------------------------------------------------------
# Worker claim
# ---------------------------------------------------------------------------

class TestClaim:
    def test_claim_skips_future_rows(self, db):
        """A row whose next_retry_at is in the future doesn't get
        claimed."""
        aid = _seed_account(db)
        enqueue_style_distill_retry(db, account_id=aid, last_error="x")
        # next_retry_at is 60s out for attempt 1.
        claimed = claim_next_style_distill_queue_entry(db)
        assert claimed is None

    def test_claim_picks_past_rows(self, db):
        aid = _seed_account(db)
        # Manually backdate next_retry_at to the past.
        db.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, 1, ?, ?, ?, 0, ?)",
            (
                aid, "2020-01-01T00:00:00+00:00", "x",
                "2020-01-01T00:00:00+00:00",
                "2020-01-01T00:00:00+00:00",
            ),
        )
        db.commit()
        claimed = claim_next_style_distill_queue_entry(db)
        assert claimed is not None
        assert claimed["account_id"] == aid

    def test_claim_skips_paused_rows(self, db):
        aid = _seed_account(db)
        # Paused row with a past next_retry_at.
        db.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, 1, ?, 'x', ?, 1, ?)",
            (
                aid, "2020-01-01T00:00:00+00:00",
                "2020-01-01T00:00:00+00:00",
                "2020-01-01T00:00:00+00:00",
            ),
        )
        db.commit()
        claimed = claim_next_style_distill_queue_entry(db)
        assert claimed is None


# ---------------------------------------------------------------------------
# 24h event counters
# ---------------------------------------------------------------------------

class TestEventCounters:
    def test_zero_counts_on_empty_table(self, db):
        out = style_distill_event_counts(db)
        assert out == {
            "local_24h": 0, "cloud_24h": 0,
            "failures_24h": 0, "scrubber_rejects_24h": 0,
            "total_24h": 0,
        }

    def test_buckets_by_outcome_and_was_cloud(self, db):
        aid = _seed_account(db)
        # 2 local successes + 1 cloud success + 1 backend_fail +
        # 1 scrubber_fail + 1 disabled (counted only in total).
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="ollama",
            was_cloud=False, outcome="success",
        )
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="ollama",
            was_cloud=False, outcome="success",
        )
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="azure_openai",
            was_cloud=True, outcome="success",
        )
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="azure_openai",
            was_cloud=True, outcome="backend_fail",
            error_class="HTTPError",
        )
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="azure_openai",
            was_cloud=True, outcome="scrubber_fail",
        )
        record_style_distill_event(
            db, account_id=aid, actor_user_id=None,
            backend_id=None, backend_type="ollama",
            was_cloud=False, outcome="disabled",
        )
        out = style_distill_event_counts(db)
        assert out["local_24h"] == 2
        assert out["cloud_24h"] == 1
        assert out["failures_24h"] == 1
        assert out["scrubber_rejects_24h"] == 1
        assert out["total_24h"] == 6

    def test_old_events_excluded_from_24h_window(self, db):
        aid = _seed_account(db)
        # Insert an event with ts = 30h ago.
        old_ts = (
            datetime.now(timezone.utc) - timedelta(hours=30)
        ).isoformat()
        db.execute(
            "INSERT INTO style_distill_events "
            "(ts, account_id, actor_user_id, backend_id, backend_type, "
            " was_cloud, outcome) "
            "VALUES (?, ?, NULL, NULL, 'ollama', 0, 'success')",
            (old_ts, aid),
        )
        db.commit()
        out = style_distill_event_counts(db)
        assert out["local_24h"] == 0
        assert out["total_24h"] == 0


# ---------------------------------------------------------------------------
# Migration shape (v27)
# ---------------------------------------------------------------------------

class TestMigrationV27Shape:
    def test_style_distill_events_table_columns(self, db):
        cols = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(style_distill_events)"
            ).fetchall()
        }
        for expected in (
            "id", "ts", "account_id", "actor_user_id", "backend_id",
            "backend_type", "was_cloud", "outcome", "latency_ms",
            "layer1_drops", "layer2_matches", "layer3_entities",
            "scrubber_degraded", "error_class",
        ):
            assert expected in cols, f"missing column {expected!r}"

    def test_style_distill_queue_table_columns(self, db):
        cols = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(style_distill_queue)"
            ).fetchall()
        }
        for expected in (
            "account_id", "attempt_count", "next_retry_at",
            "last_error", "last_attempt_at", "paused", "created_at",
        ):
            assert expected in cols, f"missing column {expected!r}"

    def test_indexes_exist(self, db):
        idx_events = {
            row["name"] for row in db.execute(
                "PRAGMA index_list(style_distill_events)"
            ).fetchall()
        }
        assert "idx_style_distill_events_ts" in idx_events
        assert "idx_style_distill_events_account" in idx_events
        idx_queue = {
            row["name"] for row in db.execute(
                "PRAGMA index_list(style_distill_queue)"
            ).fetchall()
        }
        assert "idx_style_distill_queue_ready" in idx_queue

    def test_v27_recorded_in_migration_log(self, db):
        from email_triage.web.migrations import applied_versions
        applied = applied_versions(db)
        assert 27 in applied
        assert applied[27]["name"] == "create_style_distill_audit_and_queue"
