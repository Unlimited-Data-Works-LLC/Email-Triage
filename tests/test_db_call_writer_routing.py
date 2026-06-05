"""Phase 3 — db_call auto-routes @db_write helpers through the writer.

The Phase 3 cutover routes write helpers through the single-writer
thread WITHOUT editing any of the ~697 db_call call sites: the
@db_write decorator stamps `_et_is_db_write`, and db_call inspects that
tag. Writes go to the writer (when enabled + installed); reads stay on
the threadpool. This file proves that routing.
"""

from __future__ import annotations

import pytest

from email_triage.db._writer import (
    SqliteWriterThread,
    _reset_writer_for_tests,
    set_writer,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.db_writelock import db_write


@pytest.fixture(autouse=True)
def _clean_singleton():
    _reset_writer_for_tests()
    yield
    _reset_writer_for_tests()


def test_db_write_decorator_stamps_tag():
    @db_write
    def _w(conn, x):
        return x

    assert getattr(_w, "_et_is_db_write", False) is True


def test_read_helper_has_no_write_tag():
    def _r(conn):
        return 1

    assert getattr(_r, "_et_is_db_write", False) is False


async def test_db_call_routes_write_through_writer_when_enabled(monkeypatch):
    """A @db_write helper goes through the writer thread when enabled."""
    writer = SqliteWriterThread()
    writer.start()
    set_writer(writer)

    executed_on: dict[str, str] = {}

    @db_write
    def _w(_conn, val):
        import threading

        executed_on["thread"] = threading.current_thread().name
        return val * 2

    try:
        result = await db_call(_w, None, 21)
        assert result == 42
        # The writer thread has a distinctive name.
        assert executed_on["thread"] == "email-triage-db-writer", (
            "write helper should have executed on the dedicated writer "
            f"thread, not {executed_on['thread']!r}"
        )
    finally:
        await writer.shutdown()


async def test_db_call_uses_threadpool_when_no_writer_installed():
    """No writer installed → legacy RLock-via-threadpool path even for a
    @db_write helper. Post-N-13 the Phase-2 flag is gone, so routing is gated
    purely on whether a writer is installed (``get_writer() is not None``), not
    on ``EMAIL_TRIAGE_WRITER_BACKEND_ENABLED``."""
    set_writer(None)  # explicit: no writer installed → legacy fallback

    executed_on: dict[str, str] = {}

    @db_write
    def _w(_conn, val):
        import threading

        executed_on["thread"] = threading.current_thread().name
        return val

    result = await db_call(_w, None, 7)
    assert result == 7
    # NOT the writer thread — a default ThreadPoolExecutor worker.
    assert executed_on["thread"] != "email-triage-db-writer"


async def test_db_call_read_never_routes_to_writer(monkeypatch):
    """An untagged (read) helper stays on the threadpool even when on."""
    writer = SqliteWriterThread()
    writer.start()
    set_writer(writer)

    executed_on: dict[str, str] = {}

    def _r(_conn):  # NOT @db_write — a read
        import threading

        executed_on["thread"] = threading.current_thread().name
        return "read"

    try:
        result = await db_call(_r, None)
        assert result == "read"
        assert executed_on["thread"] != "email-triage-db-writer", (
            "read helper must NOT route through the writer thread"
        )
    finally:
        await writer.shutdown()


async def test_db_call_write_kwargs_forwarded(monkeypatch):
    """kwargs reach the helper through the writer path."""
    writer = SqliteWriterThread()
    writer.start()
    set_writer(writer)

    @db_write
    def _w(_conn, *, label):
        return f"got:{label}"

    try:
        result = await db_call(_w, None, label="hipaa")
        assert result == "got:hipaa"
    finally:
        await writer.shutdown()


async def test_db_call_write_no_writer_installed_falls_back():
    """No writer installed → legacy path (no crash). Post-N-13 there is no
    flag; routing is gated purely on a writer being installed."""
    set_writer(None)  # no writer installed

    @db_write
    def _w(_conn, v):
        return v

    result = await db_call(_w, None, 99)
    assert result == 99


# ---------------------------------------------------------------------------
#  DEFECT-B — a shed audit-emitter write is made VISIBLE (§164.312(b))
# ---------------------------------------------------------------------------


class _AlwaysFullWriter:
    """A writer whose submit_write always sheds (queue-full)."""

    async def submit_write(self, fn, *args, **kwargs):
        from email_triage.db._writer import WriterQueueFull

        raise WriterQueueFull("synthetic saturation for test")

    async def shutdown(self):
        return None


async def test_shed_audit_emitter_write_is_recorded_and_reraised(
    monkeypatch, caplog
):
    """When the writer sheds an @audit_emitter write, db_call records the
    shed (gap-event attempt + loud ERROR) AND re-raises WriterQueueFull so
    the web layer maps it to 503."""
    from email_triage.db._writer import WriterQueueFull

    set_writer(_AlwaysFullWriter())

    # A @db_write helper that is ALSO an audit emitter. The body never runs
    # (it sheds at the queue boundary) — assert that via the flag.
    body_ran = {"v": False}

    @db_write
    def _emit(_conn, payload):
        body_ran["v"] = True
        return payload

    _emit._is_audit_emitter = True  # type: ignore[attr-defined]

    # Stub _write_audit_gap_event so the test doesn't need a real DB/conn;
    # assert it was reached with the shed helper's name.
    from email_triage.db import audit as _audit

    gap_calls: list[dict] = []

    def _fake_gap(conn, *, helper_name, args, kwargs, exc):
        gap_calls.append(
            {"conn": conn, "helper_name": helper_name, "args": args}
        )

    monkeypatch.setattr(_audit, "_write_audit_gap_event", _fake_gap)

    # Pass a non-None first arg so _record_shed_audit_write's layer-1
    # (gap-event row) path is exercised (conn = args[0]).
    sentinel_conn = object()
    with caplog.at_level("ERROR"):
        with pytest.raises(WriterQueueFull):
            await db_call(_emit, sentinel_conn, "phi-row")

    assert body_ran["v"] is False, "shed write body must NOT have run"
    assert len(gap_calls) == 1, (
        f"gap-event write should have been attempted once; got {gap_calls!r}"
    )
    gc = gap_calls[0]
    assert gc["helper_name"] == "_emit"
    assert gc["conn"] is sentinel_conn
    # FULL args (conn-included) must reach _write_audit_gap_event so the
    # redaction layer's conn-first signature binding aligns.
    assert gc["args"] == (sentinel_conn, "phi-row"), (
        "the full args tuple (conn first) must be passed to "
        f"_write_audit_gap_event; got {gc['args']!r}"
    )
    # Layer-2 always-on loud ERROR names the shed emitter.
    assert any(
        "SHED an audit-emitter write" in r.message and "_emit" in r.message
        for r in caplog.records
    ), "expected the always-on loud shed ERROR naming the emitter"


async def test_shed_NON_audit_write_is_not_recorded_but_still_reraised(
    monkeypatch, caplog
):
    """A shed write that is NOT an audit emitter just re-raises — no
    gap-event machinery (that's only the §164.312(b) audit surface)."""
    from email_triage.db._writer import WriterQueueFull
    from email_triage.db import audit as _audit

    set_writer(_AlwaysFullWriter())

    gap_calls: list[str] = []
    monkeypatch.setattr(
        _audit, "_write_audit_gap_event",
        lambda *a, **k: gap_calls.append(k.get("helper_name")),
    )

    @db_write
    def _plain(_conn, v):
        return v

    with pytest.raises(WriterQueueFull):
        await db_call(_plain, object(), 1)

    assert gap_calls == [], (
        "a non-audit shed write must NOT trigger gap-event recording"
    )


async def test_real_saturation_sheds_audit_emitter_and_lands_gap_row(
    monkeypatch, caplog
):
    """End-to-end (db-sme-requested): a REAL saturated SqliteWriterThread
    sheds a @db_write @audit_emitter write dispatched via db_call, and:
      (i)   WriterQueueFull propagates (→ 503 at the web layer),
      (ii)  a REAL row lands in audit_gap_events (not a stub), naming the
            shed emitter (§164.312(b) visibility — EQM-06-equivalent),
      (iii) the Layer-2 loud ERROR fires.

    Uses a real in-memory DB conn (so audit_gap_events + the HMAC chain
    exist) and the maxsize=1 block-the-worker saturation scaffold from
    tests/test_db_writer.py::test_queue_full_raises_writer_queue_full.
    """
    import asyncio
    import threading

    from email_triage.db._writer import SqliteWriterThread, WriterQueueFull
    from email_triage.db.audit import audit_emitter
    from email_triage.web.db import init_db
    from email_triage.web.db_writelock import db_write


    # Real DB conn — the gap-event row will be written here (db_call's
    # _record_shed_audit_write takes conn = args[0]).
    conn = init_db(":memory:")

    writer = SqliteWriterThread(maxsize=1)
    writer.start()
    set_writer(writer)

    release = threading.Event()
    entered = threading.Event()

    # Real @db_write @audit_emitter helper. Its body never runs (it sheds
    # at the queue boundary); the gap-event records that it WOULD have.
    @db_write
    @audit_emitter
    def _record_phi_event(_conn, *, subject):
        return subject

    try:
        # 1) Occupy the single worker thread with a blocking write.
        def _block(_):
            entered.set()
            release.wait(timeout=5.0)
            return "blocking"

        blocking = asyncio.ensure_future(writer.submit_write(_block, None))
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.05)
        assert entered.is_set(), "worker never picked up the blocking write"

        # 2) Fill the single queue slot so the NEXT submit sheds.
        filler = asyncio.ensure_future(writer.submit_write(lambda: "queued"))
        await asyncio.sleep(0.05)

        # 3) Dispatch the audit-emitter write via db_call → must shed.
        with caplog.at_level("ERROR"):
            with pytest.raises(WriterQueueFull):
                await db_call(_record_phi_event, conn, subject="phi-subject")

        # (ii) A REAL audit_gap_events row landed for the shed emitter.
        rows = conn.execute(
            "SELECT helper_name, exc_type FROM audit_gap_events "
            "WHERE helper_name = ?",
            ("_record_phi_event",),
        ).fetchall()
        assert len(rows) == 1, (
            f"expected exactly one audit_gap_events row for the shed "
            f"emitter; got {len(rows)}"
        )
        assert rows[0]["exc_type"] == "WriterQueueFull"

        # (iii) Layer-2 loud ERROR fired naming the emitter.
        assert any(
            "SHED an audit-emitter write" in r.message
            and "_record_phi_event" in r.message
            for r in caplog.records
        ), "expected the always-on loud shed ERROR naming the emitter"

        # Release + drain the blocking/filler writes.
        release.set()
        assert await blocking == "blocking"
        assert await filler == "queued"
    finally:
        release.set()
        await writer.shutdown()
        conn.close()
