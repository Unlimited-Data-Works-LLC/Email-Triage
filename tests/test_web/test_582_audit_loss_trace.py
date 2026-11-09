"""Punch 582: every audit-write loss that no exception carries to the
``@db_write`` gap sentinel leaves exactly ONE chained ``audit_gap_events`` row.

Before punch 582 these losses were recorded only in ``log_entries``, which is
pruned (30 days by default), so a §164.312(b) completeness check older than a
few weeks could not see them. One test per loss class of
``et-v020-fresh/582-enumeration.md`` (L1, L3, L4, L5, L6, L7, L8, L11), plus
the no-false-positive control (L2: an outer cancel while the shielded inner
write still lands), the gap-on-gap decision (L10), and the PHI-free shape.

Lives under ``tests/test_web/`` so the root conftest's autouse HMAC-key
fixture is in scope (the gap chain stamps ``hmac-sha256-v1``).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
import sqlite3
import threading
import time

import pytest
from _db_tracking import track

from email_triage.db import audit as _audit
from email_triage.db._writer import (
    SqliteWriterThread,
    WriterStopped,
    _reset_writer_for_tests,
    set_writer,
)
from email_triage.db.audit import audit_emitter
from email_triage.web import _audit as wa
from email_triage.web.db import init_db
from email_triage.web.db_threadpool import db_call
from email_triage.web.db_writelock import db_write, get_write_lock

_ROUTE = "/api/v1/accounts/7/messages/msg-abc"
_DESC = f"access_log GET route={_ROUTE} status=200"


@db_write
@audit_emitter
def _record_phi_event(_conn, *, subject):  # pragma: no cover - sheds before body
    return subject


@db_write
@audit_emitter
def _record_phi_event_that_fails(_conn, *, subject):
    raise sqlite3.OperationalError("disk I/O error")


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    wa.register_audit_loss_sink(_audit.make_audit_loss_sink(c))
    yield c
    wa.register_audit_loss_sink(None)
    wa._INFLIGHT.clear()


@pytest.fixture(autouse=True)
def _clean_writer():
    _reset_writer_for_tests()
    yield
    _reset_writer_for_tests()


def _rows(conn):
    return [dict(r) for r in conn.execute(
        "SELECT helper_name, exc_type, exc_msg, original_args_redacted "
        "FROM audit_gap_events ORDER BY id"
    )]


def _loss_rows(conn):
    return [r for r in _rows(conn) if r["exc_type"] == "AuditWriteLost"]


def _assert_one(conn, msg, helper="record_access_event"):
    rows = _loss_rows(conn)
    assert len(rows) == 1, rows
    assert rows[0]["exc_msg"] == msg
    assert rows[0]["helper_name"] == helper
    assert rows[0]["original_args_redacted"] == "{}"
    assert _ROUTE not in repr(_rows(conn)), "a route path reached the gap chain"
    assert _audit.verify_gap_chain(conn)["intact"]


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)


async def test_cancelled_before_launch_records_one_row(conn):
    """L1: the fire-and-forget task is cancelled before its coroutine runs."""
    task = asyncio.create_task(wa.safe_audit_write_async(
        lambda: asyncio.sleep(0), description=_DESC,
        table="access_log", emitter="record_access_event",
    ))
    wa.attach_audit_done_callback(
        task, "access_audit_middleware",
        table="access_log", emitter="record_access_event",
    )
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle()
    _assert_one(conn, "cancelled_before_launch table=access_log count=1")


async def test_outer_cancel_while_inner_lands_records_nothing(conn):
    """L2 control: the shielded inner write still lands, so no row."""
    gate = asyncio.Event()
    landed: list[int] = []

    async def _inner():
        await gate.wait()
        landed.append(1)
        return 1

    task = asyncio.create_task(wa.safe_audit_write_async(
        _inner, description=_DESC, table="access_log",
        emitter="record_access_event",
    ))
    wa.attach_audit_done_callback(
        task, "access_audit_middleware",
        table="access_log", emitter="record_access_event",
    )
    await _settle()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    gate.set()
    await _settle()
    assert landed == [1]
    assert _loss_rows(conn) == []


async def test_inner_cancelled_records_one_row(conn):
    """L3: the inner write itself ends cancelled."""
    async def _inner():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await wa.safe_audit_write_async(
            _inner, description=_DESC, table="access_log",
            emitter="record_access_event",
        )
    await _settle()
    _assert_one(conn, "inner_cancelled table=access_log count=1 certainty=presumptive")


async def test_shutdown_drain_records_undrained_once(conn):
    """L4: a write still in flight at shutdown gets one row, and its later
    cancellation does not add a second."""
    gate = asyncio.Event()

    async def _inner():
        await gate.wait()

    task = asyncio.create_task(wa.safe_audit_write_async(
        _inner, description=_DESC, table="access_log",
        emitter="record_access_event",
    ))
    wa.attach_audit_done_callback(
        task, "access_audit_middleware",
        table="access_log", emitter="record_access_event",
    )
    await _settle()
    n = await wa.drain_inflight_audit_writes(0.05, pending=[task])
    assert n == 1
    inner = wa._LAUNCHED[task]
    task.cancel()
    inner.cancel()
    await _settle()
    _assert_one(conn, "shutdown_undrained table=mixed count=1 certainty=presumptive", helper="audit_write_loss")


async def test_shutdown_drain_counts_a_task_that_never_launched(conn):
    """L4: a pending fire-and-forget task that has not started its write."""
    blocker = asyncio.Event()

    async def _never_launches():
        await blocker.wait()

    task = asyncio.create_task(_never_launches())
    wa.attach_audit_done_callback(task, "access_audit_middleware", table="access_log")
    n = await wa.drain_inflight_audit_writes(0.05, pending=[task])
    assert n == 1
    task.cancel()
    await _settle()
    _assert_one(conn, "shutdown_undrained table=mixed count=1 certainty=presumptive", helper="audit_write_loss")


def test_drain_ignores_a_write_pending_on_another_loop(conn):
    """L4 control: a write left pending on an earlier loop (an earlier app
    instance in the same process) is not this shutdown's: no row, no wait."""
    other = asyncio.new_event_loop()
    stale = other.create_future()
    wa._INFLIGHT.add(stale)
    try:
        t0 = time.monotonic()
        n = asyncio.run(wa.drain_inflight_audit_writes(5.0))
        assert n == 0
        assert time.monotonic() - t0 < 2.0
        assert _loss_rows(conn) == []
    finally:
        wa._INFLIGHT.discard(stale)
        other.close()


async def test_writer_stopping_refuses_and_records_the_shed_row(conn):
    """L5: a write submitted after shutdown began is refused, never queued,
    and the existing shed path records it as itself."""
    writer = SqliteWriterThread(maxsize=4)
    writer.start()
    set_writer(writer)
    await writer.shutdown()
    # Bounded: without the refusal the write queues behind the consumed STOP
    # and its future never resolves, so the regression must fail, not hang.
    with pytest.raises(WriterStopped):
        await asyncio.wait_for(
            db_call(_record_phi_event, conn, subject="phi-x"), timeout=5,
        )
    rows = [r for r in _rows(conn) if r["helper_name"] == "_record_phi_event"]
    assert len(rows) == 1 and rows[0]["exc_type"] == "WriterStopped", rows
    assert "phi-x" not in repr(_rows(conn)), "a kwarg value reached the gap chain"
    assert _audit.verify_gap_chain(conn)["intact"]


@pytest.mark.audit_failure_expected(
    match='audit_write_loss:writer_queue_abandoned',
    count=1,
)
async def test_writer_queue_abandoned_is_never_silent(conn, monkeypatch, caplog):
    """L6 + L10: the worker is wedged past the join bound inside an item, so
    it holds the write lock (``_run`` wraps every item in ``with lock:``).
    The sink cannot take the lock, so the common L6 outcome is this
    gap-on-gap path: the ERROR names the class and the count, /health
    degrades, and no row is written. (The row arm needs the lock free within
    the sink's bound, which a worker wedged inside an item never leaves it.)"""
    wa.register_audit_loss_sink(_audit.make_audit_loss_sink(conn, lock_timeout=0.05))
    bumps = {"n": 0}
    wa.register_audit_failure_sink(lambda: bumps.__setitem__("n", bumps["n"] + 1))
    release = threading.Event()
    started = threading.Event()

    def _wedge():
        started.set()
        release.wait(5)

    writer = SqliteWriterThread(maxsize=8)
    monkeypatch.setattr(writer, "_JOIN_TIMEOUT_SECS", 0.05)
    writer.start()
    try:
        first = asyncio.ensure_future(writer.submit_write(_wedge))
        await asyncio.to_thread(started.wait, 5)
        queued = asyncio.ensure_future(writer.submit_write(lambda: None))
        await _settle()
        with caplog.at_level(logging.ERROR):
            await writer.shutdown()
        errors = [r.getMessage() for r in caplog.records if "loss_class=writer_queue_abandoned" in r.getMessage()]
        assert errors and "gap_exc=TimeoutError" in errors[0], errors
        assert "count=1" in errors[0], errors
        assert bumps["n"] == 1
        assert _loss_rows(conn) == []
    finally:
        wa.register_audit_failure_sink(None)
        release.set()
        await asyncio.gather(first, queued, return_exceptions=True)


def test_done_callback_swallow_records_one_row(conn, monkeypatch):
    """L7: the stash inside the done-callback raises."""
    def _boom(*a, **k):
        raise RuntimeError("stash failed")

    async def _main():
        async def _fails():
            raise ValueError("write failed")

        task = asyncio.create_task(_fails())
        wa.attach_audit_done_callback(
            task, "access_audit_middleware",
            table="access_log", emitter="record_access_event",
        )
        monkeypatch.setattr(wa, "_stash_last_audit_exc", _boom)
        await asyncio.gather(task, return_exceptions=True)
        await _settle()

    asyncio.run(_main())
    _assert_one(conn, "done_callback_swallow table=access_log count=1 certainty=presumptive")


@pytest.mark.audit_failure_expected(
    match='access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
    count=1,
)
def test_interrupted_sync_write_records_one_row(conn):
    """L8: a sync audit write interrupted by a BaseException."""
    def _w():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        wa.safe_audit_write(
            _w, description=_DESC, table="access_log",
            emitter="record_access_event",
        )
    _assert_one(conn, "interrupted_sync table=access_log count=1 certainty=presumptive")


@pytest.mark.audit_failure_expected(
    match='access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
    count=1,
)
def test_swallowed_failure_that_never_reached_an_emitter_records_one_row(conn):
    """L11: an Exception the SSOT swallows without any gap row behind it."""
    def _w():
        raise RuntimeError("dispatch failed before the emitter ran")

    assert wa.safe_audit_write(_w, description=_DESC, table="access_log") is None
    _assert_one(conn, "failed_unrecorded table=access_log count=1", helper="audit_write_loss")


@pytest.mark.audit_failure_expected(
    match='access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
    count=1,
)
def test_emitter_failure_keeps_exactly_its_sentinel_row(conn):
    """L11 control: a failure that passed through the @db_write sentinel is
    tagged, so the SSOT adds no second row."""
    result = wa.safe_audit_write(
        lambda: _record_phi_event_that_fails(conn, subject="phi-y"),
        description=_DESC,
    )
    assert result is None
    rows = _rows(conn)
    assert [r["helper_name"] for r in rows] == ["_record_phi_event_that_fails"]
    assert _loss_rows(conn) == []


@pytest.mark.audit_failure_expected(
    match='audit_write_loss:inner_cancelled',
    count=1,
)
def test_gap_on_gap_is_never_silent(caplog):
    """L10: the sink fails, so an ERROR names the loss class and the failure
    class, and /health's counter is bumped; nothing raises."""
    bumps = {"n": 0}
    wa.register_audit_failure_sink(lambda: bumps.__setitem__("n", bumps["n"] + 1))

    def _sink(*a):
        raise sqlite3.OperationalError("database is locked")

    wa.register_audit_loss_sink(_sink)
    try:
        with caplog.at_level(logging.ERROR):
            assert wa.record_audit_loss("inner_cancelled", table="access_log") is False
        msg = " ".join(r.getMessage() for r in caplog.records)
        assert "gap-on-gap" in msg and "loss_class=inner_cancelled" in msg
        assert "gap_exc=OperationalError" in msg
        assert bumps["n"] == 1
    finally:
        wa.register_audit_failure_sink(None)
        wa.register_audit_loss_sink(None)


def test_no_sink_logs_an_error_and_does_not_bump(caplog):
    """L10: a process without the web lifespan (CLI, tests) has no sink."""
    bumps = {"n": 0}
    wa.register_audit_failure_sink(lambda: bumps.__setitem__("n", bumps["n"] + 1))
    wa.register_audit_loss_sink(None)
    try:
        with caplog.at_level(logging.ERROR):
            assert wa.record_audit_loss("interrupted_sync") is False
        assert any("no loss sink registered" in r.getMessage() for r in caplog.records)
        assert bumps["n"] == 0
    finally:
        wa.register_audit_failure_sink(None)


# --- Panel B7 DB-1: the sink never commits a half-done write -------------


def _half_done_table(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS half_done (x TEXT)")
    conn.commit()


def _committed(conn, tag):
    """What a tag's row looks like once anything uncommitted is discarded."""
    if conn.in_transaction:
        conn.rollback()
    return [r[0] for r in conn.execute("SELECT x FROM half_done WHERE x = ?", (tag,))]


@pytest.mark.audit_failure_expected(
    match='access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
    count=1,
)
def test_l8_half_done_emitter_write_is_rolled_back_not_committed(conn):
    """DB-1(a)+(c): a BaseException inside an @db_write helper rolls its
    half-done INSERT back at the wrapper, so the L8 row that follows commits
    nothing of it."""
    _half_done_table(conn)

    @db_write
    def _interrupted(c):
        c.execute("INSERT INTO half_done VALUES ('L8-half')")
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        _interrupted(conn)
    assert not conn.in_transaction, "@db_write left the half-done write open"
    with pytest.raises(KeyboardInterrupt):
        wa.safe_audit_write(
            lambda: _interrupted(conn), description=_DESC,
            table="access_log", emitter="record_access_event",
        )
    assert _committed(conn, "L8-half") == []
    _assert_one(conn, "interrupted_sync table=access_log count=1 certainty=presumptive")


@pytest.mark.audit_failure_expected(
    match='access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
    count=1,
)
def test_l11_orphaned_residue_is_rolled_back_before_the_row(conn, caplog):
    """DB-1(b)+(c): a writer that is not @db_write leaves an open INSERT and
    raises. The sink takes a free lock, finds the residue, rolls it back with
    an ERROR, then records; the half row is never committed."""
    _half_done_table(conn)

    def _plain_writer_fails():
        conn.execute("INSERT INTO half_done VALUES ('L11-half')")
        raise RuntimeError("dispatch failed")

    with caplog.at_level(logging.ERROR):
        assert wa.safe_audit_write(
            _plain_writer_fails, description=_DESC, table="access_log",
        ) is None
    assert _committed(conn, "L11-half") == []
    assert any("discarded orphaned uncommitted writes" in r.getMessage()
               for r in caplog.records)
    _assert_one(conn, "failed_unrecorded table=access_log count=1",
                helper="audit_write_loss")


@pytest.mark.audit_failure_expected(
    match=(
        'access_log GET route=/api/v1/accounts/7/messages/msg-abc status=200',
        'audit_write_loss:failed_unrecorded',
    ),
    count=2,
)
def test_reentrant_caller_transaction_is_never_committed(conn, caplog):
    """DB-1(b)+(c): the caller holds the write lock with its own open
    transaction and a swallowed failure reaches the sink. The sink refuses
    without touching the connection: no gap row, the caller's transaction is
    still open (the caller can still roll it back), and the L10 path fires
    (ERROR + /health bump)."""
    _half_done_table(conn)
    bumps = {"n": 0}
    wa.register_audit_failure_sink(lambda: bumps.__setitem__("n", bumps["n"] + 1))

    def _fails():
        raise RuntimeError("emit failed")

    try:
        with get_write_lock():
            conn.execute("INSERT INTO half_done VALUES ('caller-half')")
            with caplog.at_level(logging.ERROR):
                assert wa.safe_audit_write(
                    _fails, description=_DESC, table="access_log",
                ) is None
            assert conn.in_transaction, "the sink touched the caller's transaction"
            conn.rollback()
    finally:
        wa.register_audit_failure_sink(None)
    assert _committed(conn, "caller-half") == []
    assert _loss_rows(conn) == []
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "gap-on-gap" in msg and "gap_exc=AuditLossDeferred" in msg
    assert bumps["n"] == 1


# --- Panel B7 DB-2: the L6 next-boot sentinel ----------------------------

_SENTINEL_RE = re.compile(
    r"writer_queue_abandoned count=\d+ \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00\n"
)


@pytest.mark.audit_failure_expected(
    match='audit_write_loss:writer_queue_abandoned',
    count=1,
)
async def test_writer_wedge_writes_the_sentinel_before_any_lock_wait(conn, tmp_path, monkeypatch):
    """L6: at the join timeout the sentinel is on disk BEFORE the sink is
    asked for the row (the sink sees it already there), and its content is
    PHI-free: class, count, UTC timestamp."""
    sentinel = tmp_path / wa.WRITER_ABANDONED_SENTINEL
    seen: list[bool] = []

    def _sink(*a, **k):
        seen.append(sentinel.exists())
        raise TimeoutError("write lock held by the wedged worker")

    wa.register_audit_loss_sink(_sink)
    release = threading.Event()
    started = threading.Event()

    def _wedge():
        started.set()
        release.wait(5)

    writer = SqliteWriterThread(maxsize=8)
    monkeypatch.setattr(writer, "_JOIN_TIMEOUT_SECS", 0.05)
    writer.start()
    try:
        first = asyncio.ensure_future(writer.submit_write(_wedge))
        await asyncio.to_thread(started.wait, 5)
        queued = asyncio.ensure_future(writer.submit_write(lambda: None))
        await _settle()
        await writer.shutdown(
            on_abandoned=functools.partial(wa.record_writer_abandoned, tmp_path),
        )
        assert seen == [True], "the sink ran before the sentinel was written"
        assert _SENTINEL_RE.fullmatch(sentinel.read_text(encoding="utf-8"))
        assert "count=1 " in sentinel.read_text(encoding="utf-8")
    finally:
        release.set()
        await asyncio.gather(first, queued, return_exceptions=True)


def test_in_process_row_lands_and_removes_the_sentinel(conn, tmp_path):
    """L6 with the lock free: the row lands, so the sentinel is accounted
    and removed (the next boot must not record it again)."""
    assert wa.record_writer_abandoned(tmp_path, 2) is True
    assert not (tmp_path / wa.WRITER_ABANDONED_SENTINEL).exists()
    _assert_one(conn, "writer_queue_abandoned table=db_writes count=2",
                helper="audit_write_loss")


def test_boot_replay_records_exactly_one_row_and_removes_the_sentinel(conn, tmp_path):
    sentinel = tmp_path / wa.WRITER_ABANDONED_SENTINEL
    sentinel.write_text(
        "writer_queue_abandoned count=3 2026-10-09T00:00:00+00:00\n", encoding="utf-8",
    )
    assert wa.replay_writer_abandoned_sentinel(tmp_path) is True
    assert not sentinel.exists()
    assert wa.replay_writer_abandoned_sentinel(tmp_path) is False
    # The replayed row keeps the ORIGINAL loss time, not only boot time.
    _assert_one(conn, "writer_queue_abandoned table=db_writes count=3 "
                      "lost_at=2026-10-09T00:00:00+00:00",
                helper="writer_abandoned_replay")


def test_unreplayed_sentinel_is_added_to_never_overwritten(conn, tmp_path):
    """DA fold-check: two failed shutdowns (7, then 3 abandoned) leave count=10
    and the FIRST loss time; the next shutdown with a working sink records the
    total once, with that loss time, and removes the file."""
    sentinel = tmp_path / wa.WRITER_ABANDONED_SENTINEL
    wa.register_audit_loss_sink(None)
    assert wa.record_writer_abandoned(tmp_path, 7) is False
    first = sentinel.read_text(encoding="utf-8")
    first_ts = first.split()[-1]
    assert wa.record_writer_abandoned(tmp_path, 3) is False
    second = sentinel.read_text(encoding="utf-8")
    assert second == f"writer_queue_abandoned count=10 {first_ts}\n", second
    assert _rows(conn) == []
    wa.register_audit_loss_sink(_audit.make_audit_loss_sink(conn))
    assert wa.record_writer_abandoned(tmp_path, 2) is True
    assert not sentinel.exists()
    _assert_one(conn, f"writer_queue_abandoned table=db_writes count=12 lost_at={first_ts}",
                helper="audit_write_loss")


def test_boot_with_no_sentinel_does_nothing(conn, tmp_path):
    assert wa.replay_writer_abandoned_sentinel(tmp_path) is False
    assert wa.replay_writer_abandoned_sentinel(None) is False
    assert _rows(conn) == []


def test_recorder_refuses_free_text(conn):
    """The row stays PHI-free by construction: only enum, identifier, count."""
    with pytest.raises(ValueError):
        _audit.record_audit_write_loss(conn, loss_class="made_up")
    with pytest.raises(ValueError):
        _audit.record_audit_write_loss(conn, loss_class="inner_cancelled", table=_ROUTE)
    with pytest.raises(ValueError):
        _audit.record_audit_write_loss(conn, loss_class="inner_cancelled", count=0)
    with pytest.raises(ValueError):
        _audit.record_audit_write_loss(
            conn, loss_class="writer_queue_abandoned", lost_at=_ROUTE,
        )
    assert _rows(conn) == []
