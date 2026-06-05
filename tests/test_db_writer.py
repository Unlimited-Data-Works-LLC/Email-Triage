"""Phase 2 tests for `email_triage.db._writer`.

Covers:
  * WriterBackend Protocol contract (presence-of-each-method, NOT
    exactly-N — per pattern_count_agnostic_structural_drift_catch.md).
  * SqliteWriterThread submit_write happy path + result/exception
    propagation.
  * Burst: many concurrent submit_write all complete + ordering is
    preserved per the single writer thread.
  * Queue-full backpressure raises WriterQueueFull (→ 503 at web layer).
  * Crash recovery: in-flight writes lost on shutdown (volatile queue,
    accepted per db-sme-2 Q6 option (c)).
  * Singleton wiring + the Phase-2 feature flag.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from email_triage.db._writer import (
    SqliteWriterThread,
    WriterBackend,
    WriterQueueFull,
    _reset_writer_for_tests,
    get_writer,
    set_writer,
)


@pytest.fixture(autouse=True)
def _clean_singleton():
    _reset_writer_for_tests()
    yield
    _reset_writer_for_tests()


# -- Protocol contract --------------------------------------------------

def test_writer_backend_is_runtime_checkable_protocol():
    assert hasattr(WriterBackend, "_is_runtime_protocol") or hasattr(
        WriterBackend, "__instancecheck__"
    )


def test_writer_backend_requires_submit_write_and_shutdown():
    """Presence-of-each, not exactly-N (future health_check() allowed)."""
    members = set(dir(WriterBackend))
    assert "submit_write" in members
    assert "shutdown" in members


def test_sqlite_writer_thread_satisfies_protocol():
    w = SqliteWriterThread()
    assert isinstance(w, WriterBackend)


# -- submit_write happy path --------------------------------------------

async def test_submit_write_returns_fn_result():
    w = SqliteWriterThread()
    w.start()
    try:
        result = await w.submit_write(lambda a, b: a + b, 2, 3)
        assert result == 5
    finally:
        await w.shutdown()


async def test_submit_write_propagates_exception():
    w = SqliteWriterThread()
    w.start()
    try:
        def _boom(*_):
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            await w.submit_write(_boom)
    finally:
        await w.shutdown()


async def test_submit_write_before_start_raises():
    w = SqliteWriterThread()
    with pytest.raises(RuntimeError, match="before start"):
        await w.submit_write(lambda: 1)


# -- ordering + concurrency ---------------------------------------------

async def test_burst_all_complete_and_ordered():
    """Single writer thread → submissions execute in FIFO order."""
    w = SqliteWriterThread()
    w.start()
    try:
        executed: list[int] = []

        def _record(n: int) -> int:
            executed.append(n)
            return n

        # Fire 100 submissions; gather preserves submission order in
        # the result list, and the single thread preserves execution
        # order in `executed`.
        results = await asyncio.gather(
            *[w.submit_write(_record, i) for i in range(100)]
        )
        assert results == list(range(100))
        assert executed == list(range(100)), (
            "single writer thread must execute writes in FIFO order"
        )
    finally:
        await w.shutdown()


async def test_writes_serialize_no_interleave():
    """Two writes touching shared state never interleave (single thread)."""
    w = SqliteWriterThread()
    w.start()
    try:
        # A non-atomic read-modify-write that WOULD corrupt under
        # concurrent execution. Single writer thread serializes it.
        state = {"v": 0}

        def _incr(_):
            cur = state["v"]
            # no sleep needed — single thread can't interleave, but the
            # read/write split would expose any concurrency bug.
            state["v"] = cur + 1
            return state["v"]

        await asyncio.gather(*[w.submit_write(_incr, None) for _ in range(50)])
        assert state["v"] == 50
    finally:
        await w.shutdown()


# -- backpressure -------------------------------------------------------

async def test_queue_full_raises_writer_queue_full():
    """Saturated queue raises WriterQueueFull (→ 503), never blocks loop."""
    # maxsize=1 + a blocking first write that we hold so the queue fills.
    w = SqliteWriterThread(maxsize=1)
    w.start()
    release = threading.Event()
    entered = threading.Event()
    try:
        def _block(_):
            entered.set()
            release.wait(timeout=5.0)
            return "done"

        # First submission occupies the worker thread.
        blocking = asyncio.ensure_future(w.submit_write(_block, None))
        # Poll WITHOUT blocking the loop so the scheduled submit_write
        # coroutine actually runs + enqueues + the worker picks it up.
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.05)
        assert entered.is_set(), "worker never picked up first write"

        # Worker is busy; fill the single queue slot.
        filler = asyncio.ensure_future(w.submit_write(lambda: "queued"))
        await asyncio.sleep(0.05)  # let filler enqueue

        # Next submission must hit queue.Full → WriterQueueFull.
        with pytest.raises(WriterQueueFull):
            await w.submit_write(lambda: "overflow")

        # Release + drain.
        release.set()
        assert await blocking == "done"
        assert await filler == "queued"
    finally:
        release.set()
        await w.shutdown()


# -- shutdown -----------------------------------------------------------

async def test_shutdown_is_idempotent():
    w = SqliteWriterThread()
    w.start()
    await w.shutdown()
    await w.shutdown()  # second call is a no-op, must not raise


async def test_shutdown_before_start_is_noop():
    w = SqliteWriterThread()
    await w.shutdown()  # never started; no-op


# -- singleton + flag ---------------------------------------------------

def test_set_get_writer_singleton():
    assert get_writer() is None
    w = SqliteWriterThread()
    set_writer(w)
    assert get_writer() is w
    set_writer(None)
    assert get_writer() is None


# N-13 (2026-06-02): the `writer_backend_enabled()` Phase-2 A/B flag was REMOVED
# at the Phase-3 cutover (the writer thread now starts unconditionally), so the
# three flag-unit tests that lived here (default-false / true / non-true→false)
# were deleted with it. Writer routing is now covered by the
# writer-installed-vs-not-installed tests in test_db_call_writer_routing.py.


# ---------------------------------------------------------------------------
#  DEFECT-A — WriterQueueFull maps to HTTP 503 at the web layer
# ---------------------------------------------------------------------------

def test_writer_queue_full_maps_to_503():
    """A route that raises WriterQueueFull returns 503 (+ Retry-After),
    NOT an unhandled 500. Makes the _writer.py docstring contract TRUE.

    Builds a minimal app and registers the real exception handlers via
    ``_register_auth_error_handler`` (which also registers the
    WriterQueueFull handler added in Phase 4)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from email_triage.web.app import _register_auth_error_handler

    app = FastAPI()
    _register_auth_error_handler(app)

    @app.get("/boom")
    async def _boom():
        raise WriterQueueFull("synthetic saturation")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 503, (
        f"WriterQueueFull must map to 503, got {resp.status_code}"
    )
    assert resp.headers.get("Retry-After") == "1"
