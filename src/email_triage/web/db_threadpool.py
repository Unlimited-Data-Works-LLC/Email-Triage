"""Async wrapper for sync DB helpers.

Background
----------
~150 async handlers across ``web/routers/ui.py`` (and the access-audit
middleware) perform direct synchronous ``sqlite3`` reads/writes on the
FastAPI event loop. SQLite holds the GIL for the duration of every
call; while one handler is mid-query, every other request on the same
worker is blocked behind it. With 30s ``/health`` polls and an
operator-facing dashboard, that turns into a measurable scalability
cliff.

The fix is plumbing-only: wrap the sync helper in ``asyncio.to_thread``
so the SQLite work happens off the event loop, and other handlers can
make progress while a slow query (large folder count, long
``MAX(created_at)`` scan, etc.) runs.

Usage
-----
At the call site, change::

    acct = get_email_account(db, account_id)

to::

    acct = await db_call(get_email_account, db, account_id)

The sync helper keeps its sync signature; the wrap lives at the call
site. This was a deliberate choice — see ``feedback_root_cause_scope.md``
for the partial-conversion rationale: the initial pass converted the
highest-traffic handlers (``/health``, ``/health/detail``, ``/dashboard``)
plus the access-audit middleware; the remainder of the handlers were
flagged in-code with ``# TODO  async-DB migration`` as the working
the backlog. **#200 (2026-05-20) closed the async-DB migration** — the
final tranche of 13 ``routers/ui/*.py`` modules was converted via the
same ``db_call`` pattern and the ``# TODO `` markers were removed.
This note is retained as design-history: the same wrap-at-snapshot
pattern applies to any handler introduced from here on.

Concurrency note
----------------
``asyncio.to_thread`` schedules the work on the default loop executor
(stdlib ``ThreadPoolExecutor``). The pool's max-workers default is
``min(32, os.cpu_count() + 4)``. The win is NOT parallel DB execution
— since  every dispatched call (read AND write) is serialised
through the one process-wide write lock (see the next section), so two
``db_call`` invocations never run their SQLite work concurrently. The
win is that the SQLite work happens OFF the event loop: a slow query
(large folder count, long ``MAX(created_at)`` scan) no longer freezes
the loop, so unrelated request handling — timers, other coroutines —
keeps making progress while the DB call waits its turn for the lock.
DB calls themselves queue; everything else on the loop does not.

SQLite + threading
------------------
The ``sqlite3`` connection objects we hand around were created with
``check_same_thread=False`` (see ``init_db``). SQLite the *engine* is
thread-safe, but the Python ``sqlite3`` **driver** is not: it rejects
two threads using one ``Connection`` object CONCURRENTLY — even for
two reads — with ``InterfaceError: bad parameter or other API
misuse``. ``check_same_thread=False`` only lifts the *same-thread*
assertion; it does not make concurrent use safe.

Concurrent-access serialisation
--------------------------------------
``#211`` added a process-wide write lock (``db_writelock``) but it is
writer-only by design — two concurrent *readers*, or a reader racing
a writer outside the lock, still collide on the shared connection.
The app keeps ONE shared ``sqlite3.Connection`` and SQLite is
single-writer anyway, so there is nothing to lose by serialising
*every* dispatched DB call through that same lock. ``db_call`` now
acquires ``db_writelock``'s RLock for the whole duration of each
dispatched call (read or write). Using the *same* ``RLock`` as
``@db_write`` is load-bearing: a ``@db_write``-decorated helper
invoked inside a ``db_call`` re-acquires the lock on the same thread
instead of self-deadlocking.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, TypeVar

from email_triage.web.db_writelock import get_write_lock

from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.db_threadpool")  # N-196b R21_4

T = TypeVar("T")


async def db_call(
    sync_fn: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run ``sync_fn(*args, **kwargs)`` in the default thread pool.

    Thin wrapper over ``asyncio.to_thread``. Exists as its own helper
    so call sites read intent-first ("this is a DB call, off the loop")
    rather than mechanism-first ("we're using a thread pool"). Future
    refactors that swap the underlying primitive (e.g. dedicated DB
    pool, ``aiosqlite``) only have to change this file.

    Parameters
    ----------
    sync_fn :
        The synchronous helper to run. Positional-only (note the ``/``)
        so passing it as a keyword to a wrapped helper is unambiguous.
    *args, **kwargs :
        Forwarded to ``sync_fn`` as-is.

    Returns
    -------
    Whatever ``sync_fn`` returns. Exceptions propagate normally —
    ``asyncio.to_thread`` re-raises in the awaiting coroutine.

    Concurrency
    -----------
    The dispatched call runs under the process-wide DB lock:
    the shared ``sqlite3.Connection`` cannot be used by two threads at
    once, so every read/write is serialised through that one RLock.
    The lock is acquired *inside* the worker thread (not on the event
    loop) so awaiting ``db_call`` never blocks the loop — it only
    queues behind other in-flight DB work.
    """
    # v0.1.2 single-file encryption  Phase 3 — auto-route write helpers through the
    # single-writer thread when the writer backend is enabled. Detection
    # is the ``_et_is_db_write`` tag the ``@db_write`` decorator stamps,
    # so NO call site changes: writes (tagged) go to the writer; reads
    # (untagged) stay on the threadpool, freeing it from lock contention.
    # @db_write helpers route through the single-writer thread whenever one is
    # installed. Post-N-13 (Phase-3 cutover) the writer is started unconditionally
    # at boot (web/app.py), so this is the production path. When NO writer is
    # installed (e.g. unit tests that don't start one), fall through to the legacy
    #  RLock-via-threadpool path unchanged.
    if getattr(sync_fn, "_et_is_db_write", False):
        from email_triage.db._writer import (
            get_writer,
            WriterQueueFull,
        )

        writer = get_writer()
        if writer is not None:
            try:
                return await writer.submit_write(sync_fn, *args, **kwargs)
            except WriterQueueFull as shed_exc:
                #  DEFECT-B (§164.312(b)) — a shed write never runs
                # ``sync_fn``, so the ``@db_write`` gap-event sentinel
                # (which fires only when the body RAISES) never fires.
                # For an audit-emitter that is a §164.312(b) Audit
                # Controls VISIBILITY HOLE: the audit row silently
                # never lands and nothing records that it was shed.
                # Make the shed VISIBLE before re-raising (the 503
                # mapping in web/app.py turns the re-raise into a
                # fast-loud 503 for the caller).
                if getattr(sync_fn, "_is_audit_emitter", False):
                    await _record_shed_audit_write(
                        sync_fn, args, kwargs, shed_exc=shed_exc,
                    )
                raise

    _lock = get_write_lock()

    def _run() -> T:
        with _lock:
            return sync_fn(*args, **kwargs)

    return await asyncio.to_thread(_run)


async def _record_shed_audit_write(
    sync_fn: Callable[..., Any], args: tuple, kwargs: dict,
    shed_exc: BaseException | None = None,
) -> None:
    """Make a queue-shed audit-emitter write VISIBLE.

    Closes the §164.312(b) Audit Controls visibility hole: when the
    writer queue sheds an ``@audit_emitter`` write, ``sync_fn`` never
    runs, so the ``@db_write`` gap-event sentinel (body-raises path)
    cannot fire. Without this, an audit row silently fails to land AND
    nothing records the shed.

    Two-layer, defense-in-depth:

      1. **Best-effort gap-event row.** Attempt
         :func:`email_triage.db.audit._write_audit_gap_event` against the
         shared connection (``args[0]`` for a ``@db_write`` helper —
         conn-first by contract). It runs UNDER the  write lock in a
         worker thread (NOT on the event loop) so it cannot race the
         writer thread on the shared ``sqlite3.Connection`` — the same
         serialization every other dispatched write uses. The gap-event
         write does NOT itself go back through the (saturated) writer
         queue, so it cannot recursively shed. If it raises (e.g. the
         connection itself is also unhealthy) it is swallowed — layer 2
         still fires.
      2. **Always-on loud structured ERROR.** Emitted unconditionally so
         the shed is visible to the §164.312(b) gap-monitor even if the
         row write in layer 1 fails. Helper + exception names are baked
         into the message string so the signal survives
         ``logging.lastResort`` (which strips ``extra`` fields), mirroring
         the  HOTFIX-4 convention in ``db_writelock``.
    """
    from email_triage.db._writer import WriterQueueFull, WriterStopped

    helper_name = getattr(sync_fn, "__name__", "<unknown>")
    conn = args[0] if args else None

    # Layer 1 — best-effort gap-event row, serialized under the write lock.
    if conn is not None:
        def _write_gap() -> None:
            from email_triage.db.audit import _write_audit_gap_event
            lock = get_write_lock()
            with lock:
                # Pass the FULL args tuple (conn included) — matching the
                # @db_write recovery-path sentinel in db_writelock. The
                # redaction layer binds args to the emitter's real
                # signature (conn-first), so stripping conn would
                # mis-align every positional field.
                _write_audit_gap_event(
                    conn,
                    helper_name=helper_name,
                    args=args,
                    kwargs=kwargs,
                    # Punch 582 (L5): a write refused because the writer is
                    # stopping is recorded as itself, not as a full queue.
                    exc=shed_exc if isinstance(shed_exc, WriterStopped)
                    else WriterQueueFull(
                        "audit-emitter write shed at writer-queue boundary "
                        "(queue saturated; body never ran)"
                    ),
                )
        try:
            await asyncio.to_thread(_write_gap)
            if shed_exc is not None:
                from email_triage.db.audit import mark_audit_gap_recorded
                mark_audit_gap_recorded(shed_exc)
        except Exception as gap_exc:  # noqa: BLE001 — must never bury the shed
            _log.error(
                "db_call shed audit-emitter write AND the gap-event row "
                "write failed (gap-on-gap): helper=%s gap_exc=%s. "
                "§164.312(b) audit row did not land and could not be "
                "recorded in audit_gap_events.",
                helper_name,
                type(gap_exc).__name__,
                exc_info=gap_exc,
            )

    # Layer 2 — always-on loud ERROR (guaranteed-visible signal).
    _log.error(
        "db_call SHED an audit-emitter write at the writer-queue boundary "
        "(queue saturated): helper=%s. The §164.312(b) audit row was NOT "
        "written; a gap-event row was attempted. Backpressure surfaces to "
        "the caller as HTTP 503.",
        helper_name,
        extra={"_extra": {
            "shed_audit_emitter": helper_name,
            "audit_gap_reason": "writer_queue_full",
        }},
    )


__all__ = ["db_call"]
