"""Tests for the shared retry-backoff math (#175 R-A).

Covers :mod:`email_triage.retry_backoff` — both pre-canned schedules
+ the :func:`compute_next_attempt_at` helper. Pure math, no I/O.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from email_triage.retry_backoff import (
    STYLE_DISTILL_SCHEDULE,
    WATCHER_RETRY_SCHEDULE,
    compute_next_attempt_at,
    max_attempts,
)


# ---------------------------------------------------------------------------
# Pre-canned schedule shape
# ---------------------------------------------------------------------------

class TestSchedules:
    """The schedule constants are operator-locked. Any change here
    requires explicit sign-off because operators tune retry behaviour
    by reading these tuples."""

    def test_watcher_schedule_pinned(self):
        """Watcher per-message retry: 30s / 2m / 10m / 1h / 6h / 24h."""
        assert WATCHER_RETRY_SCHEDULE == (
            timedelta(seconds=30),
            timedelta(minutes=2),
            timedelta(minutes=10),
            timedelta(hours=1),
            timedelta(hours=6),
            timedelta(hours=24),
        )

    def test_watcher_schedule_six_attempts(self):
        assert max_attempts(WATCHER_RETRY_SCHEDULE) == 6

    def test_watcher_total_window_about_31h(self):
        total = sum(
            (td.total_seconds() for td in WATCHER_RETRY_SCHEDULE),
            0.0,
        )
        # 30 + 120 + 600 + 3600 + 21600 + 86400 = 112350s ~= 31.2h
        assert 31 * 3600 < total < 32 * 3600

    def test_style_distill_schedule_pinned(self):
        """HIPAA-distill retry: 1m / 5m / 30m / 2h / 12h / 1d / 3d / 7d."""
        assert STYLE_DISTILL_SCHEDULE == (
            timedelta(minutes=1),
            timedelta(minutes=5),
            timedelta(minutes=30),
            timedelta(hours=2),
            timedelta(hours=12),
            timedelta(days=1),
            timedelta(days=3),
            timedelta(days=7),
        )

    def test_style_distill_schedule_eight_attempts(self):
        assert max_attempts(STYLE_DISTILL_SCHEDULE) == 8


# ---------------------------------------------------------------------------
# compute_next_attempt_at semantics
# ---------------------------------------------------------------------------

class TestComputeNextAttemptAt:
    """Pure-math correctness of the schedule indexing.

    Per the contract: ``attempt_count`` is the number of FAILED
    attempts so far (0 = first enqueue, no retry has fired yet).
    The helper returns the timestamp of the NEXT retry, which uses
    ``schedule[attempt_count]``. Returns None when exhausted.
    """

    def test_first_enqueue_uses_first_schedule_entry(self):
        """attempt_count=0 → wait schedule[0] from now."""
        now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_attempt_at(
            0, WATCHER_RETRY_SCHEDULE, now=now,
        )
        assert nxt == now + timedelta(seconds=30)

    def test_attempt_count_indexes_schedule(self):
        """attempt_count=k → wait schedule[k] from now."""
        now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        for k in range(len(WATCHER_RETRY_SCHEDULE)):
            nxt = compute_next_attempt_at(
                k, WATCHER_RETRY_SCHEDULE, now=now,
            )
            assert nxt == now + WATCHER_RETRY_SCHEDULE[k]

    def test_exhausted_schedule_returns_none(self):
        """attempt_count >= len(schedule) → caller should mark dead."""
        assert compute_next_attempt_at(
            len(WATCHER_RETRY_SCHEDULE), WATCHER_RETRY_SCHEDULE,
        ) is None
        assert compute_next_attempt_at(
            99, WATCHER_RETRY_SCHEDULE,
        ) is None

    def test_negative_attempt_count_clamps_to_zero(self):
        """Defensive: negative count is treated as 0 (a fresh enqueue)."""
        now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_attempt_at(
            -1, WATCHER_RETRY_SCHEDULE, now=now,
        )
        assert nxt == now + WATCHER_RETRY_SCHEDULE[0]

    def test_now_defaults_to_utc_now(self):
        """Omit ``now`` → uses datetime.now(timezone.utc)."""
        before = datetime.now(timezone.utc)
        nxt = compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)
        after = datetime.now(timezone.utc)
        assert nxt is not None
        # The result must be within a tiny window of now + schedule[0].
        assert before + WATCHER_RETRY_SCHEDULE[0] <= nxt <= (
            after + WATCHER_RETRY_SCHEDULE[0]
        )

    def test_custom_schedule_support(self):
        """Helper works with any schedule tuple, not just the canned ones."""
        sched = (timedelta(seconds=5), timedelta(seconds=10))
        now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        assert compute_next_attempt_at(0, sched, now=now) == (
            now + timedelta(seconds=5)
        )
        assert compute_next_attempt_at(1, sched, now=now) == (
            now + timedelta(seconds=10)
        )
        assert compute_next_attempt_at(2, sched, now=now) is None

    def test_frozen_time_pinning(self):
        """Pinning ``now`` produces deterministic output for tests."""
        pinned = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_attempt_at(
            3, WATCHER_RETRY_SCHEDULE, now=pinned,
        )
        assert nxt == datetime(2020, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

    def test_empty_schedule_always_returns_none(self):
        """Edge case: empty schedule means no retries at all."""
        assert compute_next_attempt_at(0, ()) is None
        assert compute_next_attempt_at(5, ()) is None


# ---------------------------------------------------------------------------
# max_attempts helper
# ---------------------------------------------------------------------------

class TestMaxAttempts:
    def test_returns_length(self):
        assert max_attempts(()) == 0
        assert max_attempts((timedelta(seconds=1),)) == 1
        assert max_attempts(WATCHER_RETRY_SCHEDULE) == 6
        assert max_attempts(STYLE_DISTILL_SCHEDULE) == 8
