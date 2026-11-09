"""``WriterBackend`` Protocol + ``SqliteWriterThread``.

Codifies the v0.1.2 single-file encryption single-writer pattern as an explicit
abstraction. Today's write path already serializes every
write through one process-wide ``RLock`` dispatched via
``asyncio.to_thread`` onto the default ThreadPoolExecutor — i.e. we
ALREADY ship a single-writer serializer, just an implicit one where
the loser threads occupy threadpool workers while they block on the
lock. This module makes the serializer explicit + dedicated:

  * ONE writer thread owns the write submission queue.
  * The event loop posts ``(fn, args, future)`` and awaits the future;
    it never blocks on a worker waiting for the lock.
  * The default ThreadPoolExecutor is freed for genuinely-concurrent
    non-DB work (HTTP, file I/O in background tasks).

Why a Protocol
--------------
``WriterBackend`` is the v0.2.0  forward-compat seam. Phase 2 ships
``SqliteWriterThread``; the Postgres retrofit ships ``AsyncpgWriterPool``
implementing the SAME Protocol, so the ~696 ``db_call`` sites + 102+
``@db_write`` helpers (migrated in Phase 3) swap dialects with zero
callsite change. Per ``internal documentation`` §3 + §7.

Relationship to the legacy RLock (LOAD-BEARING — do not remove)
---------------------------------------------------------------
The writer thread serializes the writes that are DISPATCHED THROUGH
``db_call`` (the ~697 sites that route a ``@db_write``-tagged helper
through it). It does NOT own *all* SQLite writes: ~40 sites write via a
direct ``get_write_lock()`` block or a direct (non-``db_call``)
``@db_write`` invocation — CLI one-shots, ``FlowStore`` direct mutators,
the log handler's dedicated conn, lifespan-startup migrations. Those are
safe NOT by thread-confinement but by MUTUAL EXCLUSION: they share the
ONE  ``get_write_lock()`` RLock that the writer thread also acquires
around each call. The writer thread is therefore one participant in that
RLock, not a replacement for it.

Consequence: the  RLock is the LOAD-BEARING cross-thread write
serializer for the direct-call + lock-direct writers and MUST NOT be
removed in v0.1.2 OR v0.2.0 without FIRST migrating every one of those
~40 sites onto the writer backend. Treating the RLock as "redundant once
Phase 3 lands" is FALSE and would re-open the concurrent-shared-conn
corruption class Phase 0 closed.

``acquire_db_lock`` / ``single_flight._LOCK_CONN`` is a SEPARATE
primitive (cross-process advisory lease) and is untouched here.

§-anchors (inline §164.316(b)(1) per EQM-08):
    §164.312(b) Audit Controls — serialization removes writer-lock
        CONTENTION as a failure mode for audit-emitter writes (they
        queue instead of racing). It introduces a DIFFERENT failure
        mode: a saturated queue SHEDS the write at the ``submit_write``
        boundary BEFORE the body runs, so the ``@db_write`` gap-event
        sentinel (body-raises path) cannot fire. That hole is closed at
        the ``db_call`` shed point (``db_threadpool._record_shed_audit_
        write``): a shed audit-emitter write is recorded as a gap-event
        row + a loud structured ERROR so the §164.312(b) visibility is
        preserved. Net: contention-failure eliminated, shed-failure made
        visible.
    §164.308(a)(7)(ii)(B) — queue-full raises a fast-loud error that the
        web layer maps to HTTP 503 (``web/app.py`` ``WriterQueueFull``
        exception handler), not a silent drop.
"""

from __future__ import annotations

import asyncio
import logging

from email_triage._int_utils import parse_int_or_none  # N-219c/24 R23
from email_triage.triage_logging import get_logger  # N-196b R21_4
import os
import queue
import threading
from typing import Any, Callable, Protocol, runtime_checkable

logger = get_logger("email_triage.db._writer")  # N-196b R21_4

# The ONE shutdown envelope for the writer join and the lifespan's final WAL
# checkpoint (feedback_da_hedge_shutdown_timeout_desync: two literals for one
# coupled budget drift apart). ``SqliteWriterThread.shutdown`` joins the worker
# for this long; web/app.py's lifespan bounds the final checkpoint with it, and
# runs that checkpoint only when the join succeeded (punch 636). Both run in
# sequence, so the envelope costs twice this, inside the container StopTimeout
# (tests/test_636_shutdown_envelope_pin.py).
WAL_SHUTDOWN_ENVELOPE_SECS: float = 10.0

# Default queue depth ≈ 5 min of steady-state writes at ~30/sec. Tunable
# via env so an operator can widen it under a known burst profile.
_DEFAULT_QUEUE_MAXSIZE = 10000


def _resolve_queue_maxsize() -> int:
    raw = os.environ.get("EMAIL_TRIAGE_WRITER_QUEUE_MAXSIZE")
    if not raw:
        return _DEFAULT_QUEUE_MAXSIZE
    # N-219c/24 R23: parse_int_or_none SSOT; log a warning + fall back on
    # non-integer input (operator-facing signal that the env-var is malformed).
    val = parse_int_or_none(raw)
    if val is None:
        logger.warning(
            "Ignoring non-integer EMAIL_TRIAGE_WRITER_QUEUE_MAXSIZE; using default",
            extra={
                "error_msg": str(raw),
                "n": _DEFAULT_QUEUE_MAXSIZE,
            },
        )
        return _DEFAULT_QUEUE_MAXSIZE
    return val if val > 0 else _DEFAULT_QUEUE_MAXSIZE


class WriterQueueFull(RuntimeError):
    """Raised when the writer queue is saturated.

    The web layer maps this to ``HTTPException(503)`` — consistent with
    the  ``eff501b`` healthcheck-503-tolerance contract. Fail-loud,
    never a silent write drop (§164.308(a)(7)(ii)(B)).
    """


class WriterStopped(WriterQueueFull):
    """Raised when a write is submitted after :meth:`shutdown` began (punch
    582). The worker returns at its STOP sentinel, so a write queued behind it
    would never run and its future would never resolve. A subclass of
    :class:`WriterQueueFull` on purpose: ``db_call``'s existing shed handler
    then records the gap row for an audit emitter, and the web layer maps it
    to the same 503."""


@runtime_checkable
class WriterBackend(Protocol):
    """The write-submission seam.

    Implementations: ``SqliteWriterThread`` (v0.1.2) and the planned
    ``AsyncpgWriterPool`` (v0.2.0 ). The contract is presence-of-
    each-method (NOT exactly-N — a future ``health_check()`` must be
    addable without breaking the structural check, per
    ``pattern_count_agnostic_structural_drift_catch.md`` + DA-2 HEDGE-4).
    """

    async def submit_write(
        self, fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run ``fn(*args, **kwargs)`` on the writer + return its result."""
        ...

    async def shutdown(self) -> bool:
        """Drain + stop the writer. Idempotent. True when nothing is still
        running (punch 636: the final checkpoint runs only then)."""
        ...


class SqliteWriterThread:
    """Single dedicated thread for ``db_call``-dispatched SQLite writes.

    Serializes the writes routed to it via ``db_call`` (the ~697 tagged
    sites). It is NOT the sole writer: ~40 direct-``@db_write`` /
    direct-``get_write_lock()`` sites still write on their own threads
    (see the module docstring's "Relationship to the legacy RLock"). All
    of them — this thread included — share the ONE  RLock, so mutual
    exclusion (not thread-confinement) is what keeps the shared
    connection safe.

    The thread pulls ``(fn, args, kwargs, future, loop)`` tuples off a
    ``queue.Queue`` (thread-safe by stdlib contract), runs each under
    the  process-wide RLock, and resolves the awaiting coroutine's
    future via ``loop.call_soon_threadsafe``. ``queue.Queue`` is used
    (not ``asyncio.Queue``) because the consumer is a plain thread, not
    a coroutine — the async side is bridged with a per-call Future.
    """

    # How long shutdown() waits for the worker to drain (punch 582: what is
    # still queued after this is recorded as abandoned).
    _JOIN_TIMEOUT_SECS: float = WAL_SHUTDOWN_ENVELOPE_SECS

    # Sentinel pushed to wake the worker for a clean shutdown.
    _STOP = object()

    def __init__(self, maxsize: int | None = None) -> None:
        self._q: queue.Queue = queue.Queue(
            maxsize=maxsize if maxsize is not None else _resolve_queue_maxsize()
        )
        self._thread: threading.Thread | None = None
        self._started = False
        self._stopping = False

    # -- lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Start the writer thread. Idempotent."""
        if self._started:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="email-triage-db-writer",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        logger.info(
            "SqliteWriterThread started",
            extra={"_extra": {"queue_maxsize": self._q.maxsize}},
        )

    def _run(self) -> None:
        from email_triage.web.db_writelock import get_write_lock

        lock = get_write_lock()
        while True:
            item = self._q.get()
            if item is self._STOP:
                self._q.task_done()
                return
            fn, args, kwargs, fut, loop = item
            try:
                with lock:
                    result = fn(*args, **kwargs)
                loop.call_soon_threadsafe(_set_future_result, fut, result)
            except BaseException as exc:  # noqa: BLE001 - propagate ALL
                loop.call_soon_threadsafe(_set_future_exception, fut, exc)
            finally:
                self._q.task_done()

    async def shutdown(
        self, on_abandoned: "Callable[[int], Any] | None" = None,
    ) -> bool:
        """Signal the worker to drain + exit. Idempotent.

        ``on_abandoned(count)`` (punch 582, panel B7 DB-2) is called at a join
        timeout with writes still queued, before any lock wait. The web
        lifespan passes ``web/_audit.record_writer_abandoned``, which writes the
        next-boot sentinel and then tries the row. Without it (or if it
        raises), the loss is recorded in process, with the same 1 s bound.

        Returns True when the worker is no longer running, False when it
        outlived the join bound (punch 636: a wedged worker still holds the
        write lock, so the lifespan skips its final checkpoint)."""
        if not self._started:
            return True
        if self._stopping:
            return self._thread is None or not self._thread.is_alive()
        self._stopping = True
        # Best-effort enqueue of the stop sentinel; if the queue is
        # jammed, the daemon thread dies with the process anyway.
        stop_queued = False
        try:
            self._q.put_nowait(self._STOP)
            stop_queued = True
        except queue.Full:
            logger.warning(
                "SqliteWriterThread shutdown: queue full, relying on "
                "daemon-thread process-exit teardown"
            )
        if self._thread is not None:
            await asyncio.to_thread(self._thread.join, self._JOIN_TIMEOUT_SECS)
            if self._thread.is_alive():
                # Punch 582 (L6): the worker did not finish within the join
                # bound; the daemon thread dies with the process and takes
                # every write still queued with it. Record how many (all
                # writes, audit or not), through the loss recorder.
                # The STOP sentinel is still queued behind them; it is not
                # a write.
                abandoned = max(0, self._q.qsize() - (1 if stop_queued else 0))
                logger.error(
                    f"SqliteWriterThread shutdown: worker still running after "
                    f"the join bound; {abandoned} queued write(s) abandoned"
                )
                if abandoned:
                    from email_triage.web._audit import (
                        WRITER_ABANDONED_LOCK_TIMEOUT_SECS, record_audit_loss,
                    )
                    handled = False
                    if on_abandoned is not None:
                        try:
                            on_abandoned(abandoned)
                            handled = True
                        except Exception as cb_exc:  # noqa: BLE001
                            logger.error(
                                f"SqliteWriterThread shutdown: on_abandoned "
                                f"FAILED ({type(cb_exc).__name__}); recording "
                                f"in process"
                            )
                    if not handled:
                        record_audit_loss(
                            "writer_queue_abandoned", table="db_writes",
                            count=abandoned,
                            lock_timeout=WRITER_ABANDONED_LOCK_TIMEOUT_SECS,
                        )
                return False
        logger.info("SqliteWriterThread stopped")
        return True

    # -- submission ---------------------------------------------------

    async def submit_write(
        self, fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Enqueue ``fn(*args, **kwargs)`` for the writer thread; await result.

        Raises :class:`WriterQueueFull` immediately (does NOT block the
        event loop) when the queue is saturated — backpressure surfaces
        as a fast-loud 503 at the web layer.
        """
        if not self._started:
            raise RuntimeError(
                "SqliteWriterThread.submit_write called before start()"
            )
        if self._stopping:
            # Punch 582 (L5): never enqueue behind the STOP sentinel.
            raise WriterStopped(
                "DB writer is shutting down; write refused, never queued"
            )
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        try:
            self._q.put_nowait((fn, args, kwargs, fut, loop))
        except queue.Full as exc:
            raise WriterQueueFull(
                f"DB writer queue saturated (maxsize={self._q.maxsize}); "
                "shedding write to fail-loud rather than block the loop"
            ) from exc
        return await fut

    # -- observability ------------------------------------------------

    def queue_depth(self) -> int:
        """Current queue depth (for the bake-monitor + /health surface)."""
        return self._q.qsize()


def _set_future_result(fut: asyncio.Future, result: Any) -> None:
    if not fut.done():
        fut.set_result(result)


def _set_future_exception(fut: asyncio.Future, exc: BaseException) -> None:
    if not fut.done():
        fut.set_exception(exc)


# ---------------------------------------------------------------------------
# Process-wide singleton (wired by FastAPI lifespan; read by db_call_write)
# ---------------------------------------------------------------------------

_WRITER: WriterBackend | None = None


def set_writer(writer: WriterBackend | None) -> None:
    """Install (or clear) the process writer backend. Lifespan-owned."""
    global _WRITER
    _WRITER = writer


def get_writer() -> WriterBackend | None:
    """Return the installed writer backend, or None if not wired yet."""
    return _WRITER


# NOTE (N-13, 2026-06-02): the Phase-2 A/B flag `writer_backend_enabled()` /
# `EMAIL_TRIAGE_WRITER_BACKEND_ENABLED` was REMOVED at the Phase-3 cutover, as
# designed. The writer thread now starts unconditionally at boot (web/app.py)
# and db_call routes every @db_write through it whenever a writer is installed.
# Validated by a 43h clean encrypted+writer-on production soak.


def _reset_writer_for_tests() -> None:
    """Per-test teardown — clear the singleton so fixtures don't leak."""
    global _WRITER
    _WRITER = None
