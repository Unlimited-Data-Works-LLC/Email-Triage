"""Punch 636: a clean stop leaves no WAL behind, and never drops an in-flight
audit write unrecorded.

Measured 2026-10-14 (scratch container, ``podman stop -t 60``): the -wal grew
from 41232 B to 49472 B across a clean stop, and the shutdown log read
``"WAL checkpoint (shutdown) fired", log: 0``. The final TRUNCATE ran on an
empty WAL, BEFORE the httpx drains, the writer stop and the log rows that
followed it. And the -wal survived the process because the app connection was
never the LAST connection: the audit-chain log handler, the single_flight lock
connection and the ACME job-state connection stayed open to process exit, so
SQLite's last-close checkpoint-and-delete (sqlite.org/wal.html, section 4)
never ran.

These tests boot the real lifespan on a file database and stop it:

* every connection opened on the database file during the run is closed, and
  the app connection closes LAST (its close is SQLite's last close, which
  checkpoints the remaining frames and deletes the -wal);
* the app connection's last statement is the final
  ``PRAGMA wal_checkpoint(TRUNCATE)`` (the writer drained before it);
* the -wal is absent (or empty) once the app has stopped, and the shutdown log
  rows written after the checkpoint are in the HMAC-chained ``log_entries``;
* an access-audit write still in flight at the stop is cancelled with a loss
  row recorded, once (part B).

The static twin is ``tests/test_636_shutdown_last_close_pin.py``.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from unittest.mock import patch

import pytest
from _db_tracking import track
from _portal_loop import _one_portal_loop

from email_triage.config import TriageConfig
from email_triage.web.app import create_app
from email_triage.web.db import init_db

_DB_NAME = "triage-636.db"
_CHECKPOINT_SQL = "PRAGMA wal_checkpoint(TRUNCATE)"


class _StubSecrets:
    def __init__(self):
        self._s: dict[str, str] = {}

    def get(self, k):
        return self._s.get(k)

    def set(self, k, v):
        self._s[k] = v

    def list_keys(self):
        return list(self._s.keys())


def _config(tmp_path):
    db_path = tmp_path / _DB_NAME
    config = TriageConfig()
    config.persistence.db_path = str(db_path)
    # Plaintext on purpose: the close order is opener-agnostic, and this test
    # leg has no sqlcipher3. The encrypted runtime proof is the scratch
    # container probe (design drawer for punch 636).
    config.persistence.encryption_enabled = False
    return config, db_path


def _run_app(config, during=None):
    """Boot the real lifespan, run ``during(client, app)``, stop it."""
    from fastapi.testclient import TestClient

    from email_triage import secrets as _secrets_mod

    with patch.object(
        _secrets_mod, "bootstrap_secrets_from_config",
        lambda conn, cfg, *, master_key=None: _StubSecrets(),
    ):
        app = create_app(config)
        with TestClient(app) as client:
            if during is not None:
                during(client, app)
    return app


class _ConnRecorder:
    """Records every connection opened on the test database file (whichever
    opener made it: count-agnostic), every statement each one executed, and the
    order of their first ``close()``."""

    def __init__(self) -> None:
        self.conns: list[sqlite3.Connection] = []
        self.statements: list[tuple[int, str]] = []
        self.closed_at: dict[int, int] = {}
        self._lock = threading.Lock()
        recorder = self

        class _RecordingConnection(sqlite3.Connection):
            def close(self) -> None:
                with recorder._lock:
                    recorder.closed_at.setdefault(id(self), len(recorder.closed_at))
                super().close()

        # ``apply_compatible_row_factory`` resolves Row from the class's module.
        _RecordingConnection.__module__ = "sqlite3"
        self._factory = _RecordingConnection

    def wrap(self, real_connect):
        def _connect(database, *args, **kwargs):
            if _DB_NAME not in str(database) or "factory" in kwargs:
                return real_connect(database, *args, **kwargs)
            conn = real_connect(database, *args, factory=self._factory, **kwargs)
            index = len(self.conns)
            self.conns.append(conn)
            conn.set_trace_callback(lambda sql, i=index: self._record(i, sql))
            return conn
        return _connect

    def _record(self, index: int, sql: str) -> None:
        with self._lock:
            self.statements.append((index, sql))

    def still_open(self) -> list[int]:
        out = []
        for i, conn in enumerate(self.conns):
            try:
                conn.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                continue  # closed
            out.append(i)
        return out


def test_a_clean_stop_closes_every_connection_and_the_app_connection_last(tmp_path, monkeypatch):
    config, db_path = _config(tmp_path)
    seed = track(init_db(str(db_path)))
    seed.close()

    recorder = _ConnRecorder()
    monkeypatch.setattr(sqlite3, "connect", recorder.wrap(sqlite3.connect))
    app = _run_app(config)
    monkeypatch.undo()

    assert len(recorder.conns) > 1, (
        "at most one connection recorded; the dedicated openers did not go "
        "through sqlite3.connect, so this test proves nothing about them")
    still_open = recorder.still_open()
    for i in still_open:
        recorder.conns[i].close()  # do not leak into later tests
    assert not still_open, (
        f"connections {still_open} of {len(recorder.conns)} on the database "
        f"file were still open after the app stopped; the app connection's "
        f"close was not the last close")

    main = app.state.db
    main_index = next(i for i, c in enumerate(recorder.conns) if c is main)
    assert recorder.closed_at[id(main)] == len(recorder.closed_at) - 1, (
        "a connection closed after the app connection; SQLite's last-close "
        "checkpoint ran on that one, or not at all")
    main_sql = [sql for i, sql in recorder.statements if i == main_index]
    assert main_sql[-1].strip().upper() == _CHECKPOINT_SQL.upper(), (
        f"the app connection's last statement was {main_sql[-1]!r}, not the "
        f"final WAL checkpoint; the writer did not drain before it")

    wal = tmp_path / f"{_DB_NAME}-wal"
    assert not wal.exists() or wal.stat().st_size == 0, (
        f"{wal.name} is {wal.stat().st_size} bytes after a clean stop")
    check = track(init_db(str(db_path)))
    assert check.execute(
        "SELECT COUNT(*) FROM log_entries WHERE message = 'Web UI stopped'"
    ).fetchone()[0] == 1, "the shutdown log row did not reach the audit chain"


def test_the_log_handler_closes_only_a_connection_it_owns(tmp_path):
    """``SQLiteLogHandler.close`` closes the dedicated connection
    ``add_sqlite_handler`` opened for it, and never a caller's."""
    from email_triage.triage_logging import SQLiteLogHandler

    owned = track(init_db(str(tmp_path / "owned.db")))
    theirs = track(init_db(str(tmp_path / "theirs.db")))
    SQLiteLogHandler(owned, owns_connection=True).close()
    SQLiteLogHandler(theirs).close()
    with pytest.raises(sqlite3.ProgrammingError):
        owned.execute("SELECT 1")
    theirs.execute("SELECT 1")  # still open
    handler = SQLiteLogHandler(owned, owns_connection=True)
    handler.close()
    handler.close()  # logging.shutdown() closes it again at exit


def test_remove_sqlite_handlers_detaches_and_closes(tmp_path):
    import logging

    from email_triage.triage_logging import add_sqlite_handler, remove_sqlite_handlers

    main = track(init_db(str(tmp_path / "main.db")))
    root = logging.getLogger("email_triage")
    before = list(root.handlers)
    add_sqlite_handler(main)
    added = [h for h in root.handlers if h not in before]
    assert added, "add_sqlite_handler attached no handler"
    assert remove_sqlite_handlers() >= 1
    assert not [h for h in root.handlers if h in added]
    with pytest.raises(sqlite3.ProgrammingError):
        added[0]._conn.execute("SELECT 1")
    main.execute("SELECT 1")  # the caller's connection stays open


# ---------------------------------------------------------------------------
# Part B: an in-flight access-audit write at a stop
# ---------------------------------------------------------------------------


def _loss_rows(conn):
    return [dict(r) for r in conn.execute(
        "SELECT helper_name, exc_type, exc_msg FROM audit_gap_events "
        "WHERE exc_type = 'AuditWriteLost' ORDER BY id")]


def test_a_stop_records_an_inflight_access_audit_write_it_cancels(tmp_path, monkeypatch):
    """The access-audit middleware's write is fire-and-forget. One still in
    flight at the stop is cancelled when the loop closes; the stop must record
    it as a loss first (``shutdown_undrained``, through the loss recorder SSOT),
    exactly once, so the cancellation is never a silent lost audit row
    (section 164.312(b))."""
    from email_triage.web import access_audit
    from email_triage.web import app as web_app

    config, db_path = _config(tmp_path)
    monkeypatch.setattr(web_app, "_AUDIT_SHUTDOWN_DRAIN_TIMEOUT_SECS", 0.2)

    real_db_call = access_audit._db_call
    started = threading.Event()

    async def _hold_the_access_write(fn, *args, **kwargs):
        if fn is access_audit._record_access_event:
            started.set()
            await asyncio.Event().wait()  # in flight until the stop cancels it
        return await real_db_call(fn, *args, **kwargs)

    monkeypatch.setattr(access_audit, "_db_call", _hold_the_access_write)
    tasks: list[asyncio.Task] = []

    def _during(client, app):
        # _run_app is inside ``with TestClient(app)``, so client.portal is already
        # the one loop and _one_portal_loop reuses it (punch 577 shape).
        with _one_portal_loop(client):
            client.get("/api/v1/accounts/1/messages")  # a PHI route, audited at any status
            assert started.wait(10), "the access-audit write never started"
            tasks.extend(app.state._audit_pending)

    _run_app(config, _during)

    assert tasks, "no access-audit task was registered"
    assert all(t.done() for t in tasks), "an audit task outlived the stop"
    assert any(t.cancelled() for t in tasks), (
        "the stop did not cancel the in-flight write; this test no longer "
        "exercises the cancellation it is about")
    check = track(init_db(str(db_path)))
    rows = _loss_rows(check)
    undrained = [r for r in rows if r["exc_msg"].startswith("shutdown_undrained")]
    assert len(undrained) == 1, rows
    assert "count=1" in undrained[0]["exc_msg"], rows
    assert not [r for r in rows if r["exc_msg"].startswith("inner_cancelled")], (
        f"the cancellation was recorded a second time: {rows}")


async def test_a_second_drain_does_not_count_an_accounted_write_again(tmp_path):
    """The lifespan sweeps the in-flight audit writes twice (punch 636): the
    bounded drain, then a zero-wait sweep after the writer stops. A write the
    first one recorded is not recorded again."""
    from email_triage.db import audit as _db_audit
    from email_triage.web import _audit as wa

    conn = track(init_db(":memory:"))
    wa.register_audit_loss_sink(_db_audit.make_audit_loss_sink(conn))
    gate = asyncio.Event()
    try:
        task = asyncio.create_task(wa.safe_audit_write_async(
            gate.wait, description="pin:636", table="access_log",
            emitter="record_access_event"))
        wa.attach_audit_done_callback(
            task, "access_audit_middleware", table="access_log",
            emitter="record_access_event")
        for _ in range(5):
            await asyncio.sleep(0)
        assert await wa.drain_inflight_audit_writes(0.05, pending=[task]) == 1
        assert await wa.drain_inflight_audit_writes(0, pending=[task]) == 0
        inner = wa._LAUNCHED[task]
        task.cancel()
        inner.cancel()
        for _ in range(5):
            await asyncio.sleep(0)
        assert [r["exc_msg"] for r in _loss_rows(conn)] == [
            "shutdown_undrained table=mixed count=1 certainty=presumptive"]
    finally:
        wa.register_audit_loss_sink(None)
        wa._INFLIGHT.clear()


class _WedgedWriter:
    """Reports a FAILED join (``shutdown()`` returns False), after another
    connection took the database write lock and an audit write was launched
    that only the post-join sweep can see (panel 636 r1 DA-1/db-1)."""

    def __init__(self, real, app, db_path) -> None:
        self.real, self.app, self.db_path = real, app, db_path
        self.blocker = None

    async def submit_write(self, fn, *args, **kwargs):
        return await self.real.submit_write(fn, *args, **kwargs)

    async def shutdown(self, on_abandoned=None):
        from email_triage.web import _audit as wa

        await self.real.shutdown()
        self.blocker = sqlite3.connect(str(self.db_path), timeout=0, isolation_level=None,
                                       check_same_thread=False)
        self.blocker.execute("BEGIN IMMEDIATE")  # holds the write lock
        task = asyncio.create_task(wa.safe_audit_write_async(
            asyncio.Event().wait, description="pin:636-wedge", table="access_log",
            emitter="record_access_event"))
        wa.attach_audit_done_callback(task, "pin:636-wedge", table="access_log",
                                      emitter="record_access_event")
        self.app.state._audit_pending.add(task)
        for _ in range(3):
            await asyncio.sleep(0)  # the inner write launches
        return False


def test_a_wedged_writer_stop_stays_in_the_envelope_and_leaves_a_sentinel(tmp_path):
    """A failed writer join (the writer holds the write lock): nothing more is
    written to the database, so no write waits out SQLite's 30 s busy timeout
    (log rows go to the console); the stop finishes inside the envelope; the
    post-join sweep's loss goes to the lock-free next-boot sentinel, which the
    next boot replays into exactly one row."""
    import time

    from email_triage.db._writer import WAL_SHUTDOWN_ENVELOPE_SECS, get_writer, set_writer
    from email_triage.web._audit import SHUTDOWN_UNDRAINED_SENTINEL

    config, db_path = _config(tmp_path)
    wedged: list[_WedgedWriter] = []

    def _during(client, app):
        wedged.append(_WedgedWriter(get_writer(), app, db_path))
        set_writer(wedged[0])

    start = [0.0]
    from fastapi.testclient import TestClient

    from email_triage import secrets as _secrets_mod

    with patch.object(_secrets_mod, "bootstrap_secrets_from_config",
                      lambda conn, cfg, *, master_key=None: _StubSecrets()):
        app = create_app(config)
        try:
            with TestClient(app) as client:
                _during(client, app)
                start[0] = time.monotonic()
            elapsed = time.monotonic() - start[0]
        finally:
            if wedged and wedged[0].blocker is not None:
                wedged[0].blocker.execute("ROLLBACK")
                wedged[0].blocker.close()

    assert elapsed < WAL_SHUTDOWN_ENVELOPE_SECS + 5, (
        f"the wedged-writer stop took {elapsed:.1f} s; a write after the failed "
        f"join waited on the write lock")
    sentinel = tmp_path / SHUTDOWN_UNDRAINED_SENTINEL
    assert sentinel.exists(), "the sweep's loss did not reach the lock-free sentinel"
    assert "shutdown_undrained count=1 " in sentinel.read_text(encoding="utf-8")

    _run_app(config)  # the next boot replays it
    assert not sentinel.exists(), "the next boot did not consume the sentinel"
    check = track(init_db(str(db_path)))
    replayed = [r["exc_msg"] for r in _loss_rows(check)
                if r["exc_msg"].startswith("shutdown_undrained")]
    assert len(replayed) == 1, replayed  # the original loss time rides along
    assert replayed[0].startswith("shutdown_undrained table=mixed count=1 lost_at=")
    assert replayed[0].endswith(" certainty=presumptive")


async def _cancel_mid_handler(path: str, db, *, cancel_msg=None, user=None):
    """Run the access-audit middleware on ``path`` with a handler that never
    returns, and cancel it mid-handler (uvicorn's graceful-shutdown bound
    cancels with ``cancel_msg``). Returns the app state the middleware used."""
    from starlette.datastructures import State
    from starlette.requests import Request

    from email_triage.web.access_audit import AccessAuditMiddleware

    async def _asgi(scope, receive, send):  # pragma: no cover - never reached
        return None

    class _App:
        state = State()

    _App.state.db = db
    _App.state._audit_pending = set()
    middleware = AccessAuditMiddleware(_asgi)
    request = Request({
        "type": "http", "method": "GET", "path": path, "raw_path": path.encode(),
        "root_path": "", "scheme": "http", "query_string": b"", "headers": [],
        "server": ("testserver", 80), "app": _App, "state": {"user": user},
    })
    in_handler = asyncio.Event()

    async def _call_next(_request):
        in_handler.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(middleware.dispatch(request, _call_next))
    await in_handler.wait()
    task.cancel(cancel_msg)
    with pytest.raises(asyncio.CancelledError):
        await task  # re-raised, never swallowed
    return _App.state


@pytest.mark.parametrize(("path", "cancel_msg", "expected_reason"), [
    ("/api/messages/m1", "Task cancelled, timeout graceful shutdown exceeded", "shutdown"),
    ("/api/messages/m1", None, "cancelled"),
    ("/static/app.css", None, None),
])
async def test_a_request_cancelled_mid_handler_writes_its_access_row(path, cancel_msg, expected_reason):
    """Panel 636 r1 hipaa H1 / DA-4: a PHI request cancelled before the
    response writes its OWN attributable access_log row (actor from
    ``request.state.user``, outcome ``cancelled``, the reason in ``detail``)
    through the same fire-and-forget path as a normal request, so the shutdown
    drain waits for it. No loss row: nothing was lost. A non-PHI request
    writes nothing. The predicate is the middleware's own ``_is_phi_path``."""
    import json

    from email_triage.db import audit as _db_audit
    from email_triage.web import _audit as wa
    from email_triage.web.access_audit import _is_phi_path

    assert _is_phi_path(path) is (expected_reason is not None)
    conn = track(init_db(":memory:"))
    # A real user: the emitter moves an unknown actor id out of the column
    # (into ``detail`` as ``stale_actor_user_id``).
    user_id = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("u636@test.com", "U", "user", "2026-10-16T00:00:00+00:00")).lastrowid
    conn.commit()
    wa.register_audit_loss_sink(_db_audit.make_audit_loss_sink(conn))
    try:
        state = await _cancel_mid_handler(path, conn, cancel_msg=cancel_msg, user={"id": user_id})
        for task in list(state._audit_pending):
            await asyncio.wait_for(asyncio.shield(task), timeout=5)
    finally:
        wa.register_audit_loss_sink(None)
    rows = [dict(r) for r in conn.execute(
        "SELECT actor_user_id, route, status_code, outcome, detail FROM access_log")]
    assert _loss_rows(conn) == []
    if expected_reason is None:
        assert rows == []
        return
    assert len(rows) == 1, rows
    assert rows[0]["actor_user_id"] == user_id, rows
    assert rows[0]["route"] == path
    assert rows[0]["outcome"] == "cancelled"
    assert json.loads(rows[0]["detail"]) == {"cancelled": expected_reason}


def test_measured_a_client_disconnect_does_not_cancel_call_next():
    """MEASUREMENT (panel 636 r1 hipaa H1): on the installed Starlette, a client
    disconnect during the handler does NOT cancel ``call_next`` under
    ``BaseHTTPMiddleware``: the handler completes and the normal post-response
    access row is written. So the cancel arm sees only task cancellation
    (uvicorn's graceful-shutdown bound, or loop teardown), never a plain
    disconnect. If a Starlette upgrade changes this, this test goes RED and the
    cancel arm's reasons need a ``client_disconnect`` case."""
    from starlette.middleware.base import BaseHTTPMiddleware

    seen: dict[str, str] = {}

    class _Probe(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            try:
                response = await call_next(request)
            except asyncio.CancelledError:
                seen["call_next"] = "cancelled"
                raise
            seen["call_next"] = "returned"
            return response

    async def _endpoint(scope, receive, send):
        await asyncio.sleep(0.3)
        seen["endpoint"] = "completed"
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def _receive():
        if messages:
            return messages.pop(0)
        await asyncio.sleep(0.05)
        return {"type": "http.disconnect"}

    async def _send(_message):
        return None

    scope = {"type": "http", "method": "GET", "path": "/x", "raw_path": b"/x",
             "root_path": "", "scheme": "http", "query_string": b"", "headers": [],
             "server": ("t.invalid", 80), "client": ("c", 1), "http_version": "1.1",
             "asgi": {"version": "3.0"}}
    asyncio.run(asyncio.wait_for(_Probe(_endpoint)(scope, _receive, _send), timeout=5))
    assert seen == {"endpoint": "completed", "call_next": "returned"}
