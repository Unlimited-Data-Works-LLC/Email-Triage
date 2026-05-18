"""Per-(account, UID) in-flight dedup gate (#114).

When a push delivery and a watcher / poll cycle fire on the same UID
within seconds, both can run the full triage pipeline before either
writes its row to ``triaged_messages``. The second cycle has been
observed landing with stub-shaped EmailMessage metadata (empty
sender / subject), classifying as the catch-all default, then
failing on the action chain because the first cycle already moved
the message — only after paying for fetch + classify + action.

The persistent ``triaged_messages`` (RFC Message-Id) gate is the
correct durable dedup, but it depends on a successful ``fetch_message``
returning a populated ``Message-Id`` header. Two near-simultaneous
fetches both see ``is_triaged() -> False`` because neither has
written its row yet; we get the race.

This module adds an in-process volatile set keyed on
``(account_id, uid)`` that any triage entry point can consult before
paying for the fetch. The first cycle adds the key; the second
cycle hits it and short-circuits with a structured "in_flight" skip.
The set is cleared in a ``finally`` block so a crashed cycle leaves
no zombie keys.

Volatile-by-design: a process restart wipes the set, which is the
correct recovery posture (after a restart we want to re-process
in-flight messages, not silently drop them). The persistent dedup
table catches anything that actually completed before the crash.

Why not Option A (persist BEFORE the action chain): persistence
before action means a crashed action chain leaves a "triaged" row
the operator now has to manually delete to retry. The volatile set
self-clears at process boundary; the persistent gate is reserved
for "successfully completed" semantics.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator


def _key(account_id: int, uid: str) -> tuple[int, str]:
    """Stable hashable key. Coerce to ``str`` so int / str UIDs
    don't produce two distinct entries for the same logical message.
    """
    return (int(account_id), str(uid))


def is_inflight(state: object, account_id: int, uid: str) -> bool:
    """Return True iff a triage cycle for this (account, UID) is
    already running in this process.

    ``state`` is ``app.state`` (or any object); the function lazily
    reads ``state.triage_inflight`` and returns False if absent. This
    keeps the helper drop-in safe for tests + entry points that
    haven't initialised the set yet.
    """
    bag = getattr(state, "triage_inflight", None)
    if bag is None:
        return False
    return _key(account_id, uid) in bag


def mark_inflight(state: object, account_id: int, uid: str) -> bool:
    """Atomically claim the (account, UID) slot.

    Returns True if this caller now owns the slot; False if another
    cycle has already claimed it. Lazily creates ``state.triage_inflight``
    on first use so the helper works even when the caller didn't
    pre-initialise the set.
    """
    bag = getattr(state, "triage_inflight", None)
    if bag is None:
        bag = set()
        try:
            state.triage_inflight = bag  # type: ignore[attr-defined]
        except AttributeError:
            # State object refused attribute set (frozen dataclass etc.).
            # Fall back to no-op semantics: report not-in-flight.
            return True
    k = _key(account_id, uid)
    if k in bag:
        return False
    bag.add(k)
    return True


def release_inflight(state: object, account_id: int, uid: str) -> None:
    """Release the (account, UID) slot. Safe to call when the slot
    was never claimed (idempotent ``discard``)."""
    bag = getattr(state, "triage_inflight", None)
    if bag is None:
        return
    bag.discard(_key(account_id, uid))


@contextmanager
def claim(state: object, account_id: int, uid: str) -> Iterator[bool]:
    """Context-manager wrapper around mark / release.

    Yields ``True`` when the caller owns the slot for this with-block;
    ``False`` when another cycle is already holding it. Always
    releases on exit (claimed or not — ``discard`` is idempotent).

    Usage::

        with claim(app.state, account_id, uid) as won:
            if not won:
                # Another concurrent cycle is mid-flight; short-circuit.
                continue
            ...  # the actual fetch / classify / act
    """
    won = mark_inflight(state, account_id, uid)
    try:
        yield won
    finally:
        if won:
            release_inflight(state, account_id, uid)
