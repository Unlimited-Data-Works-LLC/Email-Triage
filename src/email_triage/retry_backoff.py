"""Shared exponential-backoff math for retry queues.

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

#: Watcher per-message retry schedule. Six attempts over ~31h:
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

#: ``watcher_retry_queue.failure_kind`` for a row whose classify step could not
#: reach the LLM backend. The drainer skips such rows while the LLM breaker is
#: open; the constants below give them their own delay and their own bound.
LLM_UNREACHABLE_KIND = "llm_unreachable"

#: Punch 593: the delay after an ``llm_unreachable`` failure, at EVERY attempt.
#: An LLM outage is one shared cause, not a per-message problem, so its failures
#: do not walk the schedule: before this, a row that failed its 5th attempt
#: during an outage was parked 6 h out, and IMAP rows were triaged 5 h 20 m
#: after the LLM came back. With a flat 10 min a row is due at most 10 min
#: (plus one drainer tick) after recovery. 10 min is two LLM-breaker TTLs
#: (300 s), so during an outage a row is retried about every other TTL lapse.
LLM_UNREACHABLE_RETRY_DELAY: timedelta = timedelta(minutes=10)

#: Punch 593: the bound on an ``llm_unreachable`` row, as wall-clock age from
#: ``first_seen_at`` (the current retry episode). A count bound cannot be used:
#: the flat delay means ~6 attempts would pass in under an hour of outage. The
#: value is the schedule's own span (31 h 12 m 30 s), the longest life the
#: count-based schedule ever gave a row, so the outage a row survives is unchanged.
LLM_UNREACHABLE_MAX_AGE: timedelta = sum(WATCHER_RETRY_SCHEDULE, timedelta())

#: HIPAA style-distill retry schedule. Eight
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


def watcher_retry_next_attempt_at(
    attempt_count: int,
    *,
    failure_kind: str | None,
    now: datetime | None = None,
) -> datetime:
    """When a ``watcher_retry_queue`` row that just failed is next due.

    ``attempt_count`` is the row's count AFTER this failure. ``failure_kind``
    is the kind of THIS failure, not the row's stored kind: an ordinary
    fetch failure on a row once stamped ``llm_unreachable`` still walks the
    schedule, so an IMAP outage does not become a 10-minute re-fetch loop.

    * ``llm_unreachable`` -> ``now + LLM_UNREACHABLE_RETRY_DELAY`` at every
      count (punch 593). Its bound is age, applied by the drainer through
      :func:`llm_unreachable_expired`.
    * anything else -> the schedule step; past the end of the schedule,
      ``now + schedule[-1]`` so the drainer's count cap transitions it.
    """
    base = now or datetime.now(timezone.utc)
    if failure_kind == LLM_UNREACHABLE_KIND:
        return base + LLM_UNREACHABLE_RETRY_DELAY
    nxt = compute_next_attempt_at(attempt_count, WATCHER_RETRY_SCHEDULE, now=base)
    return nxt if nxt is not None else base + WATCHER_RETRY_SCHEDULE[-1]


def llm_unreachable_expired(
    first_seen_at: str | None, *, now: datetime | None = None,
) -> bool | None:
    """True once an ``llm_unreachable`` row is older than
    :data:`LLM_UNREACHABLE_MAX_AGE`; None if ``first_seen_at`` cannot be read.

    ``first_seen_at`` comes from SQLite's ``datetime('now')`` default
    (``YYYY-MM-DD HH:MM:SS``, UTC, no offset); an ISO-8601 value with ``T``
    and an offset or ``Z`` is read too. A naive value is UTC. None tells the
    caller to fall back to the count bound, so an unreadable timestamp can
    never leave a row pending forever.
    """
    from email_triage._isotime import parse_iso_aware

    seen = parse_iso_aware(str(first_seen_at).strip() if first_seen_at else None)
    if seen is None:
        return None
    base = now or datetime.now(timezone.utc)
    return base - seen >= LLM_UNREACHABLE_MAX_AGE


__all__ = [
    "WATCHER_RETRY_SCHEDULE",
    "STYLE_DISTILL_SCHEDULE",
    "LLM_UNREACHABLE_KIND",
    "LLM_UNREACHABLE_RETRY_DELAY",
    "LLM_UNREACHABLE_MAX_AGE",
    "compute_next_attempt_at",
    "max_attempts",
    "watcher_retry_next_attempt_at",
    "llm_unreachable_expired",
]
