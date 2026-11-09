"""Process-wide serialisation lock for SQLite write helpers.

Background
----------
The app holds ONE shared ``sqlite3.Connection`` (opened in
``web/db.py`` ``init_db`` with ``check_same_thread=False``) and hands
it to FlowStore, the SQLite log handler, ``acme_job_state``, and every
DB helper. The  async-DB migration wraps sync helpers in
``asyncio.to_thread`` (see ``db_threadpool.db_call``), so write
helpers now run GENUINELY CONCURRENTLY on threadpool worker threads
against that single connection.

``sqlite3`` transaction state is PER-CONNECTION, not per-thread.
Every write helper ends with a bare ``conn.commit()``. So worker A's
``commit()`` flushes worker B's half-built transaction, and a foreign
``ROLLBACK`` discards B's pending writes. Multi-statement helpers
partially commit; explicit ``BEGIN…COMMIT`` blocks raise
``OperationalError: cannot start a transaction within a transaction``;
the HIPAA log hash-chain breaks permanently when a foreign ROLLBACK
orphans the handler's cached row tail.

The fix
-------
``@db_write`` serialises every write helper end-to-end. While one
helper holds the lock no other write helper can touch the shared
connection — so a multi-statement unit (DELETE + N×INSERT + commit)
or an explicit ``BEGIN…COMMIT`` block runs atomically with respect to
every other writer. Read-only helpers stay unlocked: a reader on its
own statement sees a consistent snapshot under WAL.

Why an ``RLock``
----------------
Some write helpers call other write helpers (e.g. ``set_account_hipaa``
calls ``get_email_account``; ``prune_log_entries`` calls
``_capture_chain_anchor``). A plain ``Lock`` would self-deadlock the
moment a decorated helper invoked another decorated helper on the same
thread. ``threading.RLock`` lets the owning thread re-acquire freely;
the lock fully releases only when the outermost holder returns.

Exception safety
----------------
If a wrapped helper raises mid-transaction it must NOT leave an open
transaction for the next lock holder — the next ``BEGIN`` would then
raise "cannot start a transaction within a transaction". The decorator
rolls the connection back on any exception before re-raising, but only
when a transaction is actually open (``conn.in_transaction``) and only
when the connection is positionally discoverable in the call (first
arg or a ``conn``/``connection`` keyword). Helpers that own a
dedicated connection — the SQLite log handler, ``acme_job_state`` —
do NOT use this decorator; they own their commit/rollback scope.
"""

from __future__ import annotations

import functools
import logging

from email_triage.triage_logging import get_logger  # N-196b R21_4
import sqlite3
import threading
from typing import Any, Callable, TypeVar
from email_triage._dbapi_errors import DB_OPERATIONAL_ERRORS

_log = get_logger(__name__)  # N-196b R21_4

# Module-level reentrant lock. One lock for the whole process — the
# shared connection is a single resource, so a single mutex is the
# right granularity. RLock so a decorated helper calling another
# decorated helper on the same thread does not self-deadlock.
_write_lock = threading.RLock()

F = TypeVar("F", bound=Callable[..., Any])

# Connection types the rollback path recognises. ``sqlcipher3`` (the
# encrypted-at-rest driver, a pysqlite3 fork) ships its OWN ``Connection``
# class that is NOT a stdlib ``sqlite3.Connection`` subclass, so a stdlib-only
# isinstance check skipped the rollback on every encrypted install (punch 921,
# panel r17 db-sme SHOULD-B4).
_CONN_TYPES: tuple[type, ...] = (sqlite3.Connection,)
try:  # optional: plaintext installs and the workstation lack it
    import sqlcipher3.dbapi2 as _sqlcipher_dbapi2  # type: ignore[import-not-found]

    _CONN_TYPES = (sqlite3.Connection, _sqlcipher_dbapi2.Connection)
except ImportError:  # pragma: no cover - environment-dependent
    # Plaintext install: no sqlcipher3 connection can exist.
    _CONN_TYPES = (sqlite3.Connection,)
except OSError as _e:  # pragma: no cover - environment-dependent
    # The native SQLCipher library failed to load. Do not crash the web import
    # over it (the encrypted engine fails closed on its own open), but record
    # it: a failing @db_write would roll back stdlib connections only.
    _CONN_TYPES = (sqlite3.Connection,)
    _log.warning(
        "sqlcipher3 native library failed to load; @db_write rollback "
        "recognises stdlib connections only",
        error_class=type(_e).__name__,
    )


def get_write_lock() -> "threading.RLock":
    """Return the process-wide DB write lock.

    Exposed so non-decorator call sites (``FlowStore`` mutators, which
    are methods rather than module helpers) can serialise against the
    same lock with ``with get_write_lock(): ...``.
    """
    return _write_lock


def _find_connection(args: tuple, kwargs: dict) -> sqlite3.Connection | None:
    """Best-effort locate the ``sqlite3.Connection`` a helper writes.

    Write helpers in ``db.py`` take the connection as the first
    positional arg or as a ``conn`` / ``connection`` keyword. We only
    use this to roll back a dangling transaction on the exception
    path — if we can't find it we simply skip the rollback (the lock
    release still happens).
    """
    for value in args:
        if isinstance(value, _CONN_TYPES):
            return value
    for key in ("conn", "connection", "db"):
        value = kwargs.get(key)
        if isinstance(value, _CONN_TYPES):
            return value
    return None


def db_write(fn: F) -> F:
    """Serialise a SQLite write helper against every other writer.

    Acquires the process-wide write lock for the WHOLE duration of the
    wrapped call, so multi-statement units and explicit
    ``BEGIN…COMMIT`` blocks are atomic with respect to every other
    decorated helper. On an exception, rolls back any transaction the
    helper left open so the next lock holder starts clean.

    Apply to every helper whose body issues a write followed by
    ``commit()`` or an explicit ``BEGIN…COMMIT``. Do NOT apply to
    pure read-only helpers.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with _write_lock:
            try:
                return fn(*args, **kwargs)
            except BaseException as exc:
                # Punch 582 (DB-1, panel B7): the arm catches BaseException
                # so a KeyboardInterrupt / SystemExit / a CancelledError
                # raised into the helper also gets the step-1 and step-2
                # rollback below. Before, such an exception left the
                # helper's half-done transaction open, and the next commit
                # on this connection (any writer, or the audit-loss sink)
                # made it durable. The gap-event sentinel stays
                # Exception-only (the ``isinstance`` gate below): a
                # BaseException loss is recorded one layer out
                # (``safe_audit_write``'s ``interrupted_sync``, L8).
                #
                # ``exc`` is bound for the  D3 gap-event sentinel
                # below (so we can record the exception class + msg
                # against the failed audit-emitter call). The existing
                # rollback discipline below predates the bind and
                # does not reference ``exc`` directly — only the
                # gap-write does. The trailing ``raise`` re-raises
                # ``exc`` implicitly (bare ``raise`` in an except
                # block).
                #
                # A helper that raised mid-transaction must not leave
                # an open transaction for the next lock holder — the
                # next BEGIN would raise "cannot start a transaction
                # within a transaction".
                conn = _find_connection(args, kwargs)
                if conn is not None:
                    # Step 1: rollback when ``conn.in_transaction`` is
                    # truthy. Handles the common case where the
                    # driver's high-level (Python ``isolation_level``)
                    # transaction tracking knows we're mid-write.
                    try:
                        if conn.in_transaction:
                            conn.rollback()
                    except Exception as rollback_exc:
                        #  DA-refinement-2 — Step-1 rollback failed
                        # during recovery from another exception. The
                        # original raise is propagating; we do NOT
                        # re-raise here (the original exception is the
                        # one operators need to see). But silently
                        # swallowing this fails to distinguish
                        # operationally distinct cases — concurrent
                        # write from another thread = symptom that the
                        # writer-lock is incomplete; closed conn =
                        # noise; DB-corruption / disk-full =
                        # operationally critical. Log at ERROR so the
                        # distinction is visible without re-raising.
                        _log.error(
                            "db_write step-1 rollback failed during "
                            "recovery",
                            exc_info=rollback_exc,
                            extra={"_extra": {
                                "original_exception_in_progress": True,
                                "helper": fn.__name__,
                                "step": 1,
                            }},
                        )
                    # Step 2 — defensive explicit ROLLBACK
                    # even when ``in_transaction`` reports False.
                    # The driver's ``in_transaction`` reflects the
                    # high-level Python view; under contention /
                    # cursor-corruption cascades observed live on
                    # the test container (2026-05-25), a stepped-but-not-
                    # finalized statement can leave the C-level
                    # connection holding pending state that the
                    # next caller's BEGIN trips over with "cannot
                    # start a transaction within a transaction" or
                    # "another row available" / "column index out
                    # of range" (cursor-cache corruption). Issuing
                    # a no-arg ``ROLLBACK`` clears any such state.
                    # "cannot rollback - no transaction is active"
                    # is the expected success case for a clean
                    # connection — swallow that one silently.
                    try:
                        conn.execute("ROLLBACK")
                    except DB_OPERATIONAL_ERRORS:
                        # Benign — clean conn / no pending tx. This
                        # is the SUCCESS case for Step 2; do not log.
                        pass
                    except Exception as rollback_exc:
                        #  DA-refinement-2 — Step-2 ROLLBACK
                        # failed during recovery. Same rationale as
                        # Step 1: keep correctness (don't re-raise),
                        # but log at ERROR so the operationally-
                        # distinct failure modes (concurrent-use vs
                        # closed conn vs DB corruption) are visible.
                        _log.error(
                            "db_write step-2 rollback failed during "
                            "recovery",
                            exc_info=rollback_exc,
                            extra={"_extra": {
                                "original_exception_in_progress": True,
                                "helper": fn.__name__,
                                "step": 2,
                            }},
                        )
                    #  Deliverable 3 — gap-event sentinel for
                    # audit-emitter helpers. If ``fn`` is marked with
                    # ``@audit_emitter`` (set in ``db/audit.py``),
                    # the audit row never landed; write a chained
                    # ``audit_gap_events`` row so the operator has a
                    # §164.312(b) visible trace, and the row is
                    # §164.312(c)(1) tamper-evident via HMAC chain
                    # (EQM-05 — same key as ``log_entries`` chain).
                    #
                    # Best-effort: a failure to write the gap event
                    # must NEVER bury the original exception. Local
                    # import (avoids audit↔db_writelock cycle) +
                    # try/except wraps the whole call. If the
                    # gap-write itself fails we log at ERROR and
                    # swallow — the original exception below is the
                    # one operators need to see, the gap-on-gap log
                    # is the secondary signal.
                    if isinstance(exc, Exception) and getattr(
                        fn, "_is_audit_emitter", False,
                    ):
                        try:
                            from email_triage.db.audit import (
                                _write_audit_gap_event,
                            )
                            _write_audit_gap_event(
                                conn,
                                helper_name=fn.__name__,
                                args=args,
                                kwargs=kwargs,
                                exc=exc,
                            )
                            # Punch 582: tell the best-effort SSOT one layer
                            # out that this loss already has its row.
                            from email_triage.db.audit import (
                                mark_audit_gap_recorded,
                            )
                            mark_audit_gap_recorded(exc)
                        except Exception as gap_exc:
                            #  HOTFIX-4 — embed helper + both
                            # exception types IN the message string
                            # so the operator-route signal survives
                            # ``logging.lastResort`` (which strips
                            # ``extra`` structured fields).
                            # ``audit_emitter_error_type`` /
                            # ``gap_write_error_type`` names mirror
                            # the ``log_entries`` ``error_type`` suffix
                            # convention per hipaa-sme verdict
                            # 2026-05-25. Fields ALSO placed in
                            # ``extra`` for structured-JSON consumers
                            # (defense-in-depth).
                            _log.error(
                                "db_write audit_gap_event write "
                                "failed during recovery (gap-on-gap)"
                                ": helper=%s original_exc=%s "
                                "gap_exc=%s",
                                fn.__name__,
                                type(exc).__name__,
                                type(gap_exc).__name__,
                                exc_info=gap_exc,
                                extra={"_extra": {
                                    "original_exception_in_progress": True,
                                    "helper": fn.__name__,
                                    "audit_emitter_error_type":
                                        type(exc).__name__,
                                    "gap_write_error_type":
                                        type(gap_exc).__name__,
                                }},
                            )
                raise

    # v0.1.2 single-file encryption  Phase 3 — tag the wrapper so ``db_call`` can
    # auto-route write helpers through the single-writer thread when the
    # writer backend is enabled, WITHOUT touching any of the ~697 call
    # sites. The decorator is the chokepoint: every shared-connection
    # write helper already wears it, so one tag + one ``db_call`` branch
    # routes them all. Reads (untagged) stay on the threadpool.
    wrapper._et_is_db_write = True  # type: ignore[attr-defined]
    return wrapper  # type: ignore[return-value]


__all__ = ["db_write", "get_write_lock"]
