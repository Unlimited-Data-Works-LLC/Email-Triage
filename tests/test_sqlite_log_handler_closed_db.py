"""Tests for #148 — SQLiteLogHandler shutdown traceback suppression.

During container shutdown the audit-anchor flush (#131.1) closes the
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
    conn = init_db(":memory:")
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
    conn = init_db(":memory:")
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
    conn = init_db(":memory:")
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
    conn = init_db(":memory:")
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
    conn = init_db(":memory:")
    handler = SQLiteLogHandler(conn, flush_interval=1)
    handler.emit(_make_record("first"))

    monkeypatch.setattr(logging, "lastResort", None)

    conn.close()
    handler.emit(_make_record("after-close"))


def test_emit_other_db_errors_still_use_handle_error(monkeypatch):
    """Non-ProgrammingError sqlite3 errors should still go through
    the existing ``handleError`` path — only the closed-DB shape is
    suppressed."""
    conn = init_db(":memory:")
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
