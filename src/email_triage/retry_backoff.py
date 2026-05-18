"""Shared exponential-backoff math for retry queues (#175 R-A).

Used by:
  * :mod:`email_triage.web.db` — ``_style_distill_compute_next_retry`` (M-3 / M-7
    HIPAA distill retry, schedule ``STYLE_DISTILL_SCHEDULE``).
  * :mod:`email_triage.web.app` — ``_watcher_retry_sweeper`` (per-message
    watcher retry, schedule ``WATCHER_RETRY_SCHEDULE``).

Single source of truth for :func:`compute_next_attempt_at` so the math
stays consistent + testable in isolation. Schedules live here too so
operator-facing audits ("how long until attempt 4?") only have one
file to read.

Privacy note
------------
This module is pure math + timedeltas. Nothing here touches PHI or
provider state. Safe to import from any layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------
#
# Each schedule is a tuple of timedeltas, one per attempt. Length
# determines max_attempts. After attempt N (0-indexed) fails, if the
# schedule has no entry at index N the caller transitions the row to
# terminal-failure state ("dead") rather than scheduling another retry.

#: Watcher per-message retry schedule (#175). Six attempts over ~31h:
#: 30s / 2m / 10m / 1h / 6h / 24h. Tuned for transient timeouts on
#: provider fetch — long enough to ride out an LLM/provider outage,
#: short enough to clear backlog before the next nightly cycle.
WATCHER_RETRY_SCHEDULE: tuple[timedelta, ...] = (
    timedelta(seconds=30),
    timedelta(minutes=2),
    timedelta(minutes=10),
    timedelta(hours=1),
    timedelta(hours=6),
    timedelta(hours=24),
)

#: HIPAA style-distill retry schedule (#152 phases 3-4 S3). Eight
#: attempts over ~10d: 1m / 5m / 30m / 2h / 12h / 1d / 3d / 7d. Tuned
#: for cloud-LLM transient failures where the operator may need a
#: day to fix the backend. Per operator directive: NO fallback-to-local
#: on cloud failure — retry the same backend.
STYLE_DISTILL_SCHEDULE: tuple[timedelta, ...] = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=12),
    timedelta(days=1),
    timedelta(days=3),
    timedelta(days=7),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_next_attempt_at(
    attempt_count: int,
    schedule: tuple[timedelta, ...],
    *,
    now: datetime | None = None,
) -> datetime | None:
    """Return the next attempt time after ``attempt_count`` failures.

    ``attempt_count`` is the number of FAILED attempts so far (0 for
    first enqueue, where the message has been seen but no retry has
    fired yet). Returns ``None`` if ``attempt_count >= len(schedule)``,
    meaning the caller should transition to state='dead' rather than
    schedule another retry.

    The math is pure — no I/O, no random jitter. Callers that need
    jitter add it on top of the returned timestamp; the watcher-retry
    queue intentionally skips jitter because the per-message stagger
    from provider arrival times already smears the load.

    Parameters
    ----------
    attempt_count
        Number of failed attempts so far. 0 = first enqueue. Negative
        values clamp to 0.
    schedule
        Tuple of timedeltas. Length defines the max attempts.
    now
        Override for the reference time (testing). Defaults to
        :func:`datetime.now(timezone.utc)`.
    """
    if attempt_count < 0:
        attempt_count = 0
    if attempt_count >= len(schedule):
        return None
    base = now or datetime.now(timezone.utc)
    return base + schedule[attempt_count]


def max_attempts(schedule: tuple[timedelta, ...]) -> int:
    """Return the maximum attempts supported by ``schedule``.

    Equivalent to ``len(schedule)``; provided as a named helper so
    call sites read as ``attempt_count >= max_attempts(SCHED)`` rather
    than ``>= len(SCHED)``."""
    return len(schedule)


__all__ = [
    "WATCHER_RETRY_SCHEDULE",
    "STYLE_DISTILL_SCHEDULE",
    "compute_next_attempt_at",
    "max_attempts",
]
