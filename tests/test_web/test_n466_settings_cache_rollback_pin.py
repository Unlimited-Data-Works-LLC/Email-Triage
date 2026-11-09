"""N-466 — a rolled-back settings transaction must leave NO cached value.

Authored by devils-advocate 2026-09-12 as a DRAFT against the (then absent)
``*_txn`` conversion; landed WITH the conversion and re-pointed at the real
funnel (``db/audit.record_system_hipaa_flip``) instead of the draft's raw-SQL
stand-in. The raw shape is deliberately gone: it was there only because the
SSOT did not exist, and it is NOT an invitation to hand-roll a settings write
(see ``tests/test_n249_raw_settings_write_pin.py``).

Why this pin exists
===================
The conversion has a precondition that is easy to lose: **invalidation must
happen on EVERY exit edge from the transaction — commit AND rollback.**

``_settings_cache`` is process-wide, keyed by setting key alone, 60s TTL. All of
this runs on ONE connection with ``check_same_thread=False``, and
``get_setting`` is not ``@db_write``, so readers never take the write lock.
Python's sqlite3 defaults to SQLite's serialized threading mode: individual API
calls on a shared connection are mutex-guarded but TRANSACTIONS ARE NOT, so a
read landing inside an open transaction sees that transaction's uncommitted
writes and caches them.

Measured 2026-09-12 (two arms plus a no-race control):

    rollback + racing reader  : DB hipaa=True | cache serves hipaa=False
    rollback, no racing reader: DB hipaa=True | cache serves hipaa=True

The no-race arm isolates the racing READ as the cause — not invalidation
timing, because a cache miss populates on any read regardless of when the
writer invalidates. That is why "invalidate after COMMIT" is insufficient: on
rollback there is no commit, so it never runs.

Why this is N-464's own defect, not a new one
=============================================
A rolled-back INSERT leaves a cached VALUE for a key whose row does not exist.
``_get_runtime_settings`` then takes ``merged.update(saved)`` and the
row-absent branch — the entire N-464 fix — is never reached. The direction is
the unsafe one: the DISCARDED safeguard-disabling write is the one the cache
keeps, and it is read on the ingestion hot path transitively via ``_is_dry_run``
(``background_sweepers`` retry drainer, ``poll_ingestion`` per-account cycle,
``ingestion_push``, ``triage_classify``). Those are continuous background
tasks, so the window is a running poller overlapping a one-off admin save, not
an admin-vs-admin collision needing luck.

EVIDENCE CLASS, STATED: the in-transaction read is INJECTED (monkeypatched into
the emit step) rather than raced from a second thread. Threading changes WHEN
the read arrives, not WHAT it sees, so the sequential ordering here is faithful
in the dimension that determines the answer. It does NOT prove there is no
OTHER concurrency hazard on the shared connection.
"""
from __future__ import annotations

import pytest

from email_triage.db import audit as _audit
from email_triage.web.db import (
    delete_setting,
    get_setting,
    invalidate_setting_cache,
    set_setting,
)

_KEY = "runtime_settings"
_ON = {"dry_run": False, "log_level": "INFO", "hipaa": True}
_OFF = {"dry_run": False, "log_level": "INFO", "hipaa": False}


@pytest.fixture(autouse=True)
def _clean_settings_cache():
    invalidate_setting_cache(_KEY)
    yield
    invalidate_setting_cache(_KEY)


def _rolled_back_flip(db, value, *, racing_reader: bool):
    """Drive the REAL funnel and make its boundary emit fail.

    Returns what the in-transaction reader saw, or None when it did not run.
    The fault is injected at the emit step because that is the measured
    failure: ``_chain_insert`` is fail-closed on an HMAC-key gap, which is
    exactly the rotation window N-466 was found in.
    """
    seen: list = []
    real = _audit.record_hipaa_boundary_txn

    def _boom(conn, scope, direction, actor_id=None, reason=""):
        if racing_reader:
            # A reader landing INSIDE the open transaction (the ingestion hot
            # path via _is_dry_run). It populates the process-wide cache from
            # the UNCOMMITTED row.
            seen.append(get_setting(conn, _KEY))
        raise RuntimeError("simulated fail-closed chain (no HMAC key for version)")

    _audit.record_hipaa_boundary_txn = _boom
    try:
        with pytest.raises(RuntimeError):
            _audit.record_system_hipaa_flip(
                db,
                settings_key=_KEY,
                new_runtime=dict(value),
                direction="off",
                actor_id=None,
                reason="n466 pin",
            )
    finally:
        _audit.record_hipaa_boundary_txn = real
    return seen[0] if seen else None


def test_rolled_back_flip_leaves_no_phantom_in_the_settings_cache(db):
    """THE INVARIANT. RED until invalidation runs on the rollback edge."""
    set_setting(db, _KEY, dict(_ON))               # committed truth
    assert get_setting(db, _KEY)["hipaa"] is True

    _rolled_back_flip(db, _OFF, racing_reader=True)

    durable = db.execute(
        "SELECT value_json FROM settings WHERE key = ?", (_KEY,)
    ).fetchone()
    assert durable is not None and "true" in durable[0].lower()
    assert get_setting(db, _KEY)["hipaa"] is True, (
        "a rolled-back transaction left the DISCARDED value in the settings "
        "cache. Invalidate on every exit edge (finally:), not only after "
        "COMMIT — on rollback there is no commit, so an after-COMMIT "
        "invalidation never runs."
    )


def test_rolled_back_flip_leaves_no_phantom_row_for_an_absent_key(db):
    """The N-464 reopening: a phantom for a key that has NO row."""
    delete_setting(db, _KEY)
    invalidate_setting_cache(_KEY)
    assert get_setting(db, _KEY) is None

    _rolled_back_flip(db, _OFF, racing_reader=True)

    assert db.execute(
        "SELECT COUNT(*) FROM settings WHERE key = ?", (_KEY,)
    ).fetchone()[0] == 0
    assert get_setting(db, _KEY) is None, (
        "the cache reports a row that does not exist, so "
        "_get_runtime_settings never reaches its row-absent branch — the "
        "N-464 never-clobber fix is bypassed through the cache."
    )


def test_the_detector_has_teeth(db):
    """Mutation proof that INVOKES the helper the pins use.

    Not a re-implementation: a teeth test that hand-rolls the detection passes
    even when the real helper is dead, which is the failure this project keeps
    re-finding. Here the in-transaction read is the documented cause, so
    removing it must remove the phantom; if it does not, the helper is not
    exercising the mechanism these pins claim to cover.
    """
    set_setting(db, _KEY, dict(_ON))
    seen = _rolled_back_flip(db, _OFF, racing_reader=True)
    assert seen is not None and seen["hipaa"] is False, (
        "the in-transaction reader did not observe the uncommitted write — the "
        "helper is not reproducing the mechanism (read-your-own-writes on the "
        f"shared connection), so a green result above would be vacuous. Saw: {seen!r}"
    )

    invalidate_setting_cache(_KEY)
    _rolled_back_flip(db, _OFF, racing_reader=False)
    assert get_setting(db, _KEY)["hipaa"] is True, (
        "NEGATIVE CONTROL FAILED: with no in-transaction reader the cache "
        "should already agree with the durable row. If this fires, the phantom "
        "has a second cause and these pins are naming the wrong one."
    )


# ---------------------------------------------------------------------------
# N-513 — the residual db-sme F1 / hipaa 422-F3 found: the `finally:`
# invalidation NARROWS the rollback phantom, it does not close it.
#
# `get_setting` checks the cache under `_settings_cache_lock`, RELEASES it,
# runs the SELECT outside any lock, then RE-ACQUIRES to populate.
# `invalidate_setting_cache` is a `pop` — it removes what is present at that
# instant and cannot stop a populate already in flight. So:
#
#   1. an ingestion-path reader (`_is_dry_run` -> `_get_runtime_settings` ->
#      `get_setting`, on a threadpool worker sharing the app connection)
#      SELECTs and sees the funnel's UNCOMMITTED `hipaa: false`;
#   2. it is descheduled before its populate;
#   3. the boundary emit raises -> `conn.rollback()` -> durable row is `true`;
#   4. the funnel's `finally:` pops an EMPTY slot;
#   5. the reader resumes and writes `(hipaa=False, +60s)` into the cache.
#
# Net: durable `true`, `_get_runtime_settings` serving `false` for the TTL, on
# the ingestion hot path, while `triage_logging._hipaa_mode` stays at the
# pre-save ON — the two in-process authorities actively disagree. Direction
# UNSAFE: the safeguard is operationally OFF while the store says ON.
#
# The interleave below is DETERMINISTIC, not threaded: a connection proxy
# fires the rollback + invalidation between `get_setting`'s SELECT and its
# populate, which is exactly the ordering above. Threading changes WHEN the
# read arrives, not WHAT it sees. This drives the REAL `get_setting` — not a
# re-implementation — so it cannot pass against a dead helper.
# ---------------------------------------------------------------------------


class _DeschedulingConn:
    """Forwards to the real connection, running ``on_select`` once after the
    first ``execute`` returns — the point where the reader is descheduled."""

    def __init__(self, conn, on_select):
        self._conn = conn
        self._on_select = on_select
        self.fired = False

    def execute(self, *a, **k):
        cur = self._conn.execute(*a, **k)
        if not self.fired:
            self.fired = True
            self._on_select()
        return cur

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _read_across_a_rollback(db):
    """Run the F1 interleave. Returns what the descheduled reader SAW."""
    from email_triage.web.db import set_setting_txn

    set_setting_txn(db, _KEY, dict(_OFF))        # uncommitted HIPAA-off

    def _rollback_and_invalidate():
        db.rollback()                             # the funnel's except: edge
        invalidate_setting_cache(_KEY)            # the funnel's finally: edge

    proxy = _DeschedulingConn(db, _rollback_and_invalidate)
    seen = get_setting(proxy, _KEY)
    assert proxy.fired, "the interleave never ran — the proxy saw no SELECT"
    return seen


def test_a_reader_descheduled_across_the_rollback_cannot_publish_the_phantom(db):
    """THE N-513 INVARIANT. RED without the epoch counter.

    Proves the CACHE is not poisoned. It does NOT prove the descheduled reader
    itself got the post-rollback value — that reader's own SELECT genuinely
    saw the uncommitted row, and no design can retract a value already
    returned. What the epoch buys is that the stale value is not SHARED with
    every later caller for the full TTL.
    """
    set_setting(db, _KEY, dict(_ON))
    assert get_setting(db, _KEY)["hipaa"] is True

    _read_across_a_rollback(db)

    durable = db.execute(
        "SELECT value_json FROM settings WHERE key = ?", (_KEY,)
    ).fetchone()
    assert durable is not None and "true" in durable[0].lower(), (
        "setup failure: the rollback did not restore the durable row"
    )
    assert get_setting(db, _KEY)["hipaa"] is True, (
        "N-513: a reader descheduled between its SELECT and its cache populate "
        "republished the ROLLED-BACK `hipaa: false` with a fresh 60s TTL. The "
        "durable row says true, `_get_runtime_settings` serves false, and "
        "`triage_logging._hipaa_mode` stays ON — the safeguard is "
        "operationally off while the store says on, on the ingestion hot path "
        "via `_is_dry_run`. Invalidation must bump an epoch that a populate "
        "re-checks; a `pop` cannot stop a populate already in flight."
    )


def test_the_epoch_pin_has_teeth(db):
    """Mutation-shaped guard that INVOKES the real helper.

    If the descheduled reader did not actually observe the uncommitted value,
    the assertion above is vacuous — it would be asserting that a reader which
    saw `true` cached `true`.
    """
    set_setting(db, _KEY, dict(_ON))
    seen = _read_across_a_rollback(db)
    assert seen is not None and seen["hipaa"] is False, (
        "the descheduled reader did not observe the UNCOMMITTED hipaa=false, "
        f"so the invariant test above proves nothing. Saw: {seen!r}"
    )


def test_an_uncontended_read_still_populates_the_cache(db):
    """NEGATIVE CONTROL. The epoch check must refuse only RACED populates.

    A pin that closed the race by disabling the cache would pass the invariant
    above and silently cost every settings read a SELECT.
    """
    from email_triage.web import db as _wdb

    set_setting(db, _KEY, dict(_ON))
    invalidate_setting_cache(_KEY)
    assert _wdb._settings_cache.get(_KEY) is None

    assert get_setting(db, _KEY)["hipaa"] is True
    assert _wdb._settings_cache.get(_KEY) is not None, (
        "an UNRACED read did not populate the cache — the epoch check is "
        "refusing everything, which is not a fix, it is a disabled cache"
    )
