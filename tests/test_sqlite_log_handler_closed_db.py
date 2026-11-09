"""Tests for  — SQLiteLogHandler shutdown traceback suppression.

During container shutdown the audit-anchor flush closes the
sqlite3 connection. Any log calls landing AFTER that point would
raise ``sqlite3.ProgrammingError: Cannot operate on a closed database``
from the handler's ``emit()``, which Python's ``handleError`` then
prints to stderr as a full traceback. The audit row is already
expected to be lost at this point — the chain anchor covers
on-disk continuity. Just suppress the traceback noise and downgrade
to ``logging.lastResort`` so the message itself still reaches stderr
in the normal log format.
"""

from __future__ import annotations
from _db_tracking import track

import logging
import sqlite3
from unittest.mock import MagicMock

from email_triage.triage_logging import SQLiteLogHandler
from email_triage.web.db import init_db


def _make_record(msg: str = "shutdown ping") -> logging.LogRecord:
    return logging.LogRecord(
        name="email_triage.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )


def test_emit_swallows_closed_db_error_no_traceback(capsys):
    """Closed connection → no traceback escapes to stderr."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    # First emit primes the cache.
    handler.emit(_make_record("first"))
    capsys.readouterr()  # flush whatever lastResort wrote

    # Close the connection — subsequent emit hits ProgrammingError.
    conn.close()

    # Must not raise.
    handler.emit(_make_record("after-close"))

    captured = capsys.readouterr()
    # No traceback from handleError().
    assert "Traceback" not in captured.err
    assert "ProgrammingError" not in captured.err


def test_emit_resets_last_row_hash_on_closed_db():
    """The in-memory tail must be cleared so any subsequent emit
    re-syncs from a fresh connection."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))
    # Cache should be primed.
    assert handler._last_row_hash is not None

    conn.close()
    handler.emit(_make_record("after-close"))
    # Cache must be reset to the cold sentinel.
    assert handler._last_row_hash is None


def test_emit_falls_through_to_last_resort(monkeypatch):
    """When the DB is closed, the record is handed to
    ``logging.lastResort`` so it still surfaces somewhere."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))

    fake_last_resort = MagicMock()
    monkeypatch.setattr(logging, "lastResort", fake_last_resort)

    conn.close()
    handler.emit(_make_record("after-close"))

    fake_last_resort.handle.assert_called_once()
    args, _ = fake_last_resort.handle.call_args
    record = args[0]
    assert record.getMessage() == "after-close"


def test_emit_handles_lastresort_failure_gracefully(monkeypatch):
    """If even lastResort fails (stderr closed), nothing escapes."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))

    fake_last_resort = MagicMock()
    fake_last_resort.handle.side_effect = OSError("stderr is closed")
    monkeypatch.setattr(logging, "lastResort", fake_last_resort)

    conn.close()
    # Must not raise.
    handler.emit(_make_record("after-close"))


def test_emit_with_none_lastresort_is_safe(monkeypatch):
    """If ``logging.lastResort`` is None (some test isolations clear
    it), the closed-DB path still doesn't raise."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))

    monkeypatch.setattr(logging, "lastResort", None)

    conn.close()
    handler.emit(_make_record("after-close"))


def test_emit_other_db_errors_still_use_handle_error(monkeypatch):
    """Non-ProgrammingError sqlite3 errors should still go through
    the existing ``handleError`` path — only the closed-DB shape is
    suppressed."""
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))

    # Force the next INSERT to raise OperationalError instead.
    def _bad_execute(*_a, **_kw):
        raise sqlite3.OperationalError("locked")

    handler._conn = MagicMock()
    handler._conn.execute = _bad_execute

    fired = []
    monkeypatch.setattr(handler, "handleError", lambda r: fired.append(r))

    handler.emit(_make_record("locked-record"))
    assert len(fired) == 1
    # Cache reset on this error path too.
    assert handler._last_row_hash is None


# ---------------------------------------------------------------------------
#  — conditional lock contract (db-sme's -isolation property)
# ---------------------------------------------------------------------------
#
# The  design: file-backed deployments give the handler a DEDICATED
# connection and emit/flush MUST NOT acquire the process-wide DB write
# lock (that would couple deliberately-isolated logging to request-path
# db_call workers and gate a logging burst on every other writer). The
# in-memory test fallback shares ``app.state.db`` and DOES need the
# lock, since ``logging.Handler.lock`` does not serialise the handler
# against a concurrent db_call threadpool worker on the same connection.
#
# ``shares_app_connection`` flips between the two modes; ``_maybe_lock``
# yields under ``get_write_lock()`` only on the shared-connection path.
# These tests pin both halves of that contract.


def _lock_held_by_other_thread() -> bool:
    """Probe whether ``get_write_lock()`` is held by some OTHER thread.

    The lock is a reentrant RLock — the calling thread can always
    re-acquire it, so a same-thread non-blocking acquire tells us
    nothing. A SEPARATE thread doing ``acquire(blocking=False)`` only
    succeeds when no thread holds the lock; if the test thread (or
    any other) holds it, the probe's acquire fails and returns True.
    """
    import threading

    from email_triage.web.db_writelock import get_write_lock

    lock = get_write_lock()
    result: dict[str, bool] = {}

    def _probe() -> None:
        got = lock.acquire(blocking=False)
        result["held"] = not got
        if got:
            lock.release()

    t = threading.Thread(target=_probe)
    t.start()
    t.join()
    return result["held"]


def test_emit_takes_write_lock_when_shares_app_connection_true():
    """Shared-connection path (in-memory test fallback) MUST hold
    ``get_write_lock()`` for the duration of each DB touch in emit().
    """
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(
        conn, flush_interval=1, shares_app_connection=True,
    )

    observed: list[bool] = []
    real_execute = conn.execute

    def _instrumented(sql, *args, **kwargs):
        if "INSERT INTO log_entries" in sql:
            observed.append(_lock_held_by_other_thread())
        return real_execute(sql, *args, **kwargs)

    # sqlite3.Connection.execute is a read-only C slot — wrap the
    # connection in a tiny proxy and re-attach to the handler.
    class _Proxy:
        def __init__(self, real):
            object.__setattr__(self, "_real", real)

        def execute(self, sql, *args, **kwargs):
            return _instrumented(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._real, name)

    handler._conn = _Proxy(conn)
    handler.emit(_make_record("locked"))

    assert observed, "emit() never reached the INSERT"
    assert all(observed), (
        "shared-connection emit MUST hold get_write_lock() during the "
        "INSERT — _maybe_lock() did not engage on shares_app_connection=True"
    )


def test_emit_skips_write_lock_when_shares_app_connection_false():
    """Dedicated-connection path (production / ) MUST NOT hold the
    process-wide DB write lock during emit's DB touch. Locking it
    would couple isolated audit-log writes to every other writer on
    the request path — the exact coupling  isolated against.
    """
    conn = track(init_db(":memory:"))
    handler = SQLiteLogHandler(
        conn, flush_interval=1, shares_app_connection=False,
    )

    observed: list[bool] = []
    real_execute = conn.execute

    def _instrumented(sql, *args, **kwargs):
        if "INSERT INTO log_entries" in sql:
            observed.append(_lock_held_by_other_thread())
        return real_execute(sql, *args, **kwargs)

    class _Proxy:
        def __init__(self, real):
            object.__setattr__(self, "_real", real)

        def execute(self, sql, *args, **kwargs):
            return _instrumented(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._real, name)

    handler._conn = _Proxy(conn)
    handler.emit(_make_record("unlocked"))

    assert observed, "emit() never reached the INSERT"
    assert not any(observed), (
        "dedicated-connection emit MUST NOT hold get_write_lock() — "
        "_maybe_lock() leaked a lock acquire on shares_app_connection=False, "
        "breaking the #211 isolation property"
    )


def test_add_sqlite_handler_sets_flag_from_db_path():
    """``add_sqlite_handler`` decides ``shares_app_connection`` from
    whether the input connection is file-backed (False — dedicated
    conn is opened) or in-memory (True — the input conn is shared).
    The contract is what makes the  isolation actually happen on
    real installs.
    """
    from email_triage.triage_logging import add_sqlite_handler

    # In-memory DB → shares_app_connection must be True.
    root = logging.getLogger("email_triage")
    pre_existing = list(root.handlers)
    try:
        conn = track(init_db(":memory:"))
        add_sqlite_handler(conn)
        added = [h for h in root.handlers if h not in pre_existing]
        sqlite_handlers = [h for h in added if isinstance(h, SQLiteLogHandler)]
        assert sqlite_handlers, (
            "add_sqlite_handler did not register a SQLiteLogHandler"
        )
        handler = sqlite_handlers[-1]
        assert handler._shares_app_connection is True, (
            "in-memory DB → handler MUST have shares_app_connection=True"
        )
    finally:
        # Don't leave the handler attached for subsequent tests.
        for h in list(root.handlers):
            if h not in pre_existing:
                root.removeHandler(h)
