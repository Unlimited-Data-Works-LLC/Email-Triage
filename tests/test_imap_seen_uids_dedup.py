"""Tests for #143 — IMAP IDLE seen-UID dedup uses a bounded FIFO.

The previous implementation kept ``seen_uids`` as a ``set`` and
pruned via ``set(list(seen_uids)[-500:])``. ``set`` has no insertion
order, so the slice picked an ARBITRARY 500 UIDs, not the most
recent. After a prune, recently-seen UIDs could be dropped while
ancient UIDs were retained — the next IDLE cycle would then re-yield
those dropped-but-recent UIDs as "new", causing silent duplicate
triage runs.

Replacement: ``collections.deque(maxlen=1000)`` for FIFO eviction +
parallel ``set`` for O(1) membership. ``_seen_uids_remember`` is the
single mutation path that keeps the two structures in lockstep.
"""

from __future__ import annotations

import collections

from email_triage.providers.imap import _seen_uids_remember


def _fresh(maxlen: int = 5) -> tuple[collections.deque[str], set[str]]:
    return collections.deque(maxlen=maxlen), set()


def test_oldest_uid_dropped_on_overflow():
    """When the deque is full, adding a new UID must evict the
    OLDEST entry (FIFO), not an arbitrary one as the old set-prune
    did."""
    q, s = _fresh(maxlen=3)
    for uid in ("1", "2", "3"):
        _seen_uids_remember(uid, q, s)
    assert list(q) == ["1", "2", "3"]
    assert s == {"1", "2", "3"}

    # Add "4" — the oldest, "1", must drop. Both structures must
    # stay in lockstep; the set drifting behind the deque is the
    # bug shape #143 was filed for.
    _seen_uids_remember("4", q, s)
    assert list(q) == ["2", "3", "4"]
    assert s == {"2", "3", "4"}, "set must drop the same UID as the deque"


def test_continued_overflow_keeps_window_recent():
    """Streaming many UIDs through a small window keeps the most
    recent ``maxlen`` entries (the property the old set-prune
    advertised but did not deliver)."""
    q, s = _fresh(maxlen=3)
    for uid in (str(i) for i in range(10)):
        _seen_uids_remember(uid, q, s)
    assert list(q) == ["7", "8", "9"]
    assert s == {"7", "8", "9"}


def test_duplicate_uid_is_no_op():
    """Re-presenting a known UID must NOT shuffle the FIFO order
    or grow the structures (the watch loop already gates on `uid not
    in seen` before calling, but defence in depth)."""
    q, s = _fresh(maxlen=3)
    for uid in ("1", "2", "3"):
        _seen_uids_remember(uid, q, s)
    pre_q = list(q)
    pre_s = set(s)

    _seen_uids_remember("2", q, s)
    assert list(q) == pre_q
    assert s == pre_s


def test_under_capacity_no_eviction():
    """Below maxlen, every add grows both structures by one — no
    evictions until the deque hits its cap."""
    q, s = _fresh(maxlen=10)
    for uid in (str(i) for i in range(5)):
        _seen_uids_remember(uid, q, s)
    assert list(q) == ["0", "1", "2", "3", "4"]
    assert s == {"0", "1", "2", "3", "4"}
    assert len(q) == 5
