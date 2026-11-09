"""N-182b (allow-list step 2, B2): a failed ``log_entries`` chain-row write in
``SQLiteLogHandler.emit`` bumps the /health audit-failure counter.

This is the enforcement for ``emit``'s entry on the swallow pin's
``_CHAIN_WRITER_ALLOW`` (tests/test_audit_emit_swallow_pin.py). ``emit`` is not
declared in ``_pin_harness.chain_writer_names()``: the bare name collides with
every ``logging.Handler.emit``, and the n543 witness net keys on the call name
(s2 panel MUST-B1). So no structural pin covers the two
``_bump_chain_write_failure()`` calls in ``emit``'s failure arms; this test does
(s2 panel B-M1 / M-B1 / MUST-B2).

Each failure arm is forced once:

* ``DB_PROGRAMMING_ERRORS``: the connection is closed (the  shutdown arm).
* generic ``Exception``: every ``execute`` and ``commit`` on the connection
  raises (the #239e arm; its salvage commit and its sentinel INSERT fail too).

Each arm must raise the counter by exactly 1 and must not re-enter the handler
(a log line from the failure path would come straight back into ``emit``, so a
persistent DB failure would recurse). The handler is attached to the root
logger while the arm runs, so any log line written on the failure path would
reach it and be counted.
"""
from __future__ import annotations

import logging

import pytest
from _db_tracking import track

from email_triage.triage_logging import SQLiteLogHandler
from email_triage.web import _audit  # noqa: F401  (the bump looks it up in sys.modules)
from email_triage.web.db import init_db


class _CountingHandler(SQLiteLogHandler):
    """Counts every entry into ``emit`` (a re-entry shows as a second call)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.emit_calls = 0

    def emit(self, record: logging.LogRecord) -> None:
        self.emit_calls += 1
        super().emit(record)


class _FailingConn:
    """A connection whose every execute and commit raises a non-programming
    error, so ``emit`` lands in its generic ``except Exception`` arm."""

    isolation_level = ""

    def execute(self, *_a, **_k):
        raise RuntimeError("forced chain-row write failure")

    def commit(self):
        raise RuntimeError("forced commit failure")

    def rollback(self):
        return None

    def close(self):
        return None


def _record(msg: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="email_triage.test_n182b", level=logging.INFO, pathname=__file__,
        lineno=0, msg=msg, args=(), exc_info=None,
    )


@pytest.fixture
def sink_hits():
    hits: list[int] = []
    _audit.register_audit_failure_sink(lambda: hits.append(1))
    try:
        yield hits
    finally:
        _audit.register_audit_failure_sink(None)


def _emit_attached(handler: _CountingHandler, record: logging.LogRecord) -> None:
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        handler.emit(record)
    finally:
        root.removeHandler(handler)


def test_programming_error_arm_bumps_the_counter_once(sink_hits, capsys):
    conn = track(init_db(":memory:"))
    handler = _CountingHandler(conn, flush_interval=1)
    handler.emit(_record("primes the chain tail"))
    assert sink_hits == [], "a successful chain-row write must not bump the counter"
    handler.emit_calls = 0

    conn.close()
    _emit_attached(handler, _record("after close"))
    capsys.readouterr()

    assert sink_hits == [1], (
        "the DB_PROGRAMMING_ERRORS arm of SQLiteLogHandler.emit must bump the "
        f"/health audit-failure counter exactly once; got {len(sink_hits)}"
    )
    assert handler.emit_calls == 1, (
        f"the failure path re-entered the handler ({handler.emit_calls} emit calls)"
    )


def test_generic_exception_arm_bumps_the_counter_once(sink_hits, capsys):
    handler = _CountingHandler(_FailingConn(), flush_interval=1)
    _emit_attached(handler, _record("insert fails"))
    capsys.readouterr()  # handleError's traceback

    assert sink_hits == [1], (
        "the generic Exception arm of SQLiteLogHandler.emit must bump the "
        f"/health audit-failure counter exactly once; got {len(sink_hits)}"
    )
    assert handler.emit_calls == 1, (
        f"the failure path re-entered the handler ({handler.emit_calls} emit calls)"
    )


def test_no_sink_registered_is_a_silent_no_op(capsys):
    _audit.register_audit_failure_sink(None)
    handler = _CountingHandler(_FailingConn(), flush_interval=1)
    handler.emit(_record("no sink"))  # must not raise
    capsys.readouterr()
    assert handler.emit_calls == 1
