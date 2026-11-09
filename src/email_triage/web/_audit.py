"""Best-effort audit-row writing.

An audit / access-event row is forensic metadata: losing one must never
break the request or auth flow that triggered it — but a failure
swallowed with no trace is invisible drift. :func:`safe_audit_write` is
the single home for that "run it, never raise, log on failure" policy.

Before this it was hand-rolled at five call sites (``auth.py`` ×2,
``login_guard.py`` ×2, ``csrf.py``) with two inconsistent failure
dispositions — ``auth.py`` logged a WARNING, the other three silently
``pass``-ed. The silent ``pass`` was the wrong half of that split: the
``login_guard`` / ``csrf`` comments both noted the failure *should* be
visible via /health's audit-failure drift counter but had no mechanism.
A WARNING log line is that mechanism, so this helper standardises all
five on log-on-failure.

Divergence census run17 #3 then found the same hand-rolled
``try: record_*_event(...) except: pass/log`` policy swallowing audit
emits at ~60 more sites across 27 files (the 3 emitter SSOTs
``record_hipaa_access_event`` / ``record_access_event`` /
``record_auth_event``, direct or via the ``db_call`` await-seam). All are
converged onto this SSOT; the disposition is pinned structurally by
``tests/test_audit_emit_swallow_pin.py`` (a swallowed emit must route
through ``safe_audit_write`` / ``safe_audit_write_async`` or be
allow-listed). The async sibling exists because the sync helper cannot
wrap an ``await``.
"""

from __future__ import annotations

import asyncio
import re
import time
import weakref
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable

from email_triage.triage_logging import get_logger

log = get_logger("web.audit")


# Punch 582: the durable record of an audit write lost without an exception
# reaching the @db_write gap sentinel. The web lifespan registers a sync sink
# (``db/audit.make_audit_loss_sink``) that writes one chained
# ``audit_gap_events`` row through the gap writer. Module-level indirection
# for the same reason as ``_audit_failure_sink``: this module has no
# connection of its own.
_audit_loss_sink: Callable[[str, str, int, "str | None"], None] | None = None

# In-flight shielded inner writes (``safe_audit_write_async``), the table and
# emitter each is for, the outer task that launched each, and the writes whose
# loss is already recorded (by the shutdown drain), so a later cancellation
# does not record it twice.
_INFLIGHT: "set[asyncio.Future]" = set()
_INFLIGHT_META: "weakref.WeakKeyDictionary[asyncio.Future, tuple[str, str | None]]" = (
    weakref.WeakKeyDictionary()
)
_LAUNCHED: "weakref.WeakKeyDictionary[asyncio.Task, asyncio.Future]" = (
    weakref.WeakKeyDictionary()
)
_ACCOUNTED: "weakref.WeakSet[asyncio.Future]" = weakref.WeakSet()


def register_audit_loss_sink(
    sink: Callable[[str, str, int, "str | None"], None] | None,
) -> None:
    """Punch 582: the web lifespan wires the durable loss recorder here."""
    global _audit_loss_sink
    _audit_loss_sink = sink


def record_audit_loss(
    loss_class: str, *, table: str = "unknown", count: int = 1,
    emitter: str | None = None, bump_on_failure: bool = True,
    lock_timeout: float | None = None, lost_at: str | None = None,
) -> bool:
    """Record ``count`` lost audit writes of ``loss_class`` as ONE chained
    ``audit_gap_events`` row (punch 582). Never raises an ``Exception``: it
    runs inside except-handlers and done-callbacks on the event loop.

    Fail closed means never silent. When the sink cannot write the row (the
    write lock is not free in time, the INSERT fails), the recorder logs an
    ERROR with the loss class and the failure class baked into the message (so
    it survives ``logging.lastResort``) and bumps the ``/health`` audit-failure
    counter so the drift check degrades. With NO sink registered (a process
    without the web lifespan, such as the CLI or a unit test, or a call after
    shutdown unwired it) it logs the same ERROR and does not bump: the web
    lifespan registers and unregisters both sinks together, so that case is
    never a running server. It does not retry: a retry loop on the shutdown
    path could hold the process open past its stop timeout and lose more rows
    than it saves. With no sink it leaves ``_LAST_AUDIT_EXC`` alone, so the
    stash keeps naming the original audit failure; a sink failure is stashed.
    ``bump_on_failure=False`` is for a caller that has
    already bumped the counter for this same failure. Returns True when the
    row was written."""
    sink = _audit_loss_sink
    if sink is None:
        try:
            log.error(
                f"audit write loss NOT recorded (no loss sink registered): "
                f"loss_class={loss_class} table={table} count={count}",
            )
        except Exception:
            pass
        return False
    try:
        # Optional keywords only when set: a tighter lock bound (the L6
        # shutdown path, panel B7 DB-2) and the original loss time (the
        # replayed L6 sentinel, DA fold-check).
        extra = {k: v for k, v in (
            ("lock_timeout", lock_timeout), ("lost_at", lost_at),
        ) if v is not None}
        sink(loss_class, table, count, emitter, **extra)
        return True
    except Exception as gap_exc:
        # The loss record itself failed: that is a swallowed audit failure,
        # stashed like the others (test_audit_last_exc_stash_pin).
        _stash_last_audit_exc(gap_exc, f"audit_write_loss:{loss_class}")
        try:
            log.error(
                f"audit write loss NOT recorded (gap-on-gap): "
                f"loss_class={loss_class} table={table} count={count} "
                f"gap_exc={type(gap_exc).__name__}",
            )
        except Exception:
            pass
        if bump_on_failure:
            _bump_failure_counter()
        return False


# Punch 582, panel B7 DB-2: the L6 trace that survives the process. A writer
# wedged inside an item holds the write lock, so the in-process row usually
# cannot be written, and the container's stop timeout can SIGKILL the process
# before even the ERROR is logged. So at the join timeout, BEFORE any lock
# wait, a sentinel file goes next to the DB; the next boot records the row
# from it and removes it.
WRITER_ABANDONED_SENTINEL = ".audit-writer-abandoned"
WRITER_ABANDONED_LOCK_TIMEOUT_SECS: float = 1.0
# Punch 636 fold (panel r1 DA-1/db-1): the shutdown sweep's loss after a FAILED
# writer join. The wedged writer holds the write lock, so the row goes to its
# own next-boot sentinel, lock-free, and is replayed at boot.
SHUTDOWN_UNDRAINED_SENTINEL = ".audit-shutdown-undrained"
#: loss class -> (sentinel file, table its row names, replay emitter).
_LOSS_SENTINELS: dict[str, tuple[str, str, str]] = {
    "writer_queue_abandoned": (WRITER_ABANDONED_SENTINEL, "db_writes", "writer_abandoned_replay"),
    "shutdown_undrained": (SHUTDOWN_UNDRAINED_SENTINEL, "mixed", "shutdown_undrained_replay"),
}
_SENTINEL_COUNT_RE = re.compile(r"\bcount=(\d+)\b")
_SENTINEL_TS_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?\+00:00")


def _parse_writer_abandoned_sentinel(text: str) -> "tuple[int, str | None]":
    """(count, original loss time) from a sentinel's text: 0 and None
    for a part that is missing."""
    m = _SENTINEL_COUNT_RE.search(text)
    ts = _SENTINEL_TS_RE.search(text)
    return (int(m.group(1)) if m else 0), (ts.group(0) if ts else None)


def record_writer_abandoned(
    data_dir: "Path | None", count: int, *,
    loss_class: str = "writer_queue_abandoned", try_row: bool = True,
) -> bool:
    """L6 at the writer's join timeout (the lifespan passes this to
    ``SqliteWriterThread.shutdown(on_abandoned=...)``). First, atomically
    write ``<data_dir>/.audit-writer-abandoned``. Then try the in-process row
    with a 1 s lock bound. If the row lands, remove the sentinel, since it is
    accounted. Never raises. Returns True when the in-process row was
    written.

    A sentinel an earlier shutdown left (its boot replay failed, so it was
    kept) is ADDED TO, never overwritten (DA fold-check, panel B7): the
    file and the row carry the total, and keep the earlier loss time.

    Punch 636 fold: ``loss_class="shutdown_undrained"`` writes that class's
    own sentinel (``_LOSS_SENTINELS``); ``try_row=False`` writes the sentinel
    only, for a stop whose writer is wedged and holds the write lock, where
    the in-process row could wait out SQLite's busy timeout."""
    sentinel_name, table, _emitter = _LOSS_SENTINELS[loss_class]
    sentinel = None
    total = int(count)
    lost_at = None
    if data_dir is not None:
        try:
            from email_triage._atomicio import atomic_write_text
            from email_triage._isotime import now_utc_iso
            sentinel = Path(data_dir) / sentinel_name
            prior = 0
            if sentinel.exists():
                try:
                    prior, lost_at = _parse_writer_abandoned_sentinel(
                        sentinel.read_text(encoding="utf-8"),
                    )
                    prior = max(prior, 1)
                except Exception:
                    prior = 1  # unreadable earlier sentinel: still one loss
            total = prior + int(count)
            # PHI-free by construction: a class name, an integer and a UTC
            # timestamp. This file is not a PHI store, so PD-11's
            # encryption-at-rest rule (which covers PHI stores) does not apply.
            atomic_write_text(
                sentinel,
                f"{loss_class} count={total} "
                f"{lost_at or now_utc_iso()}\n",
            )
        except Exception as exc:
            sentinel = None
            log.error(
                f"loss sentinel NOT written "
                f"({type(exc).__name__}): {loss_class} count={count}",
            )
    if not try_row:
        if sentinel is None:
            # No durable trace at all: the console line above, and /health.
            _bump_failure_counter()
        return False
    ok = record_audit_loss(
        loss_class, table=table, count=total,
        lock_timeout=WRITER_ABANDONED_LOCK_TIMEOUT_SECS, lost_at=lost_at,
    )
    if ok and sentinel is not None:
        _remove_writer_abandoned_sentinel(sentinel)
    return ok


def replay_writer_abandoned_sentinel(data_dir: "Path | None") -> bool:
    """At boot, right after the loss sink registers: for each loss sentinel
    the last shutdown left (``.audit-writer-abandoned``, and since punch 636
    ``.audit-shutdown-undrained``) whose in-process row never landed, record
    that row once, then remove the file. A file is kept when its row could not
    be written, so the next boot retries. Never raises. Returns True when a
    row was recorded."""
    if data_dir is None:
        return False
    recorded = False
    for loss_class, (name, table, emitter) in _LOSS_SENTINELS.items():
        sentinel = Path(data_dir) / name
        try:
            text = sentinel.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except Exception as exc:
            log.error(
                f"{loss_class} sentinel unreadable ({type(exc).__name__}); "
                f"left in place for the next boot",
            )
            continue
        count, lost_at = _parse_writer_abandoned_sentinel(text)
        if count < 1:
            log.error(
                f"{loss_class} sentinel has no usable count; recording count=1",
            )
            count = 1
        ok = record_audit_loss(
            loss_class, table=table, count=count,
            emitter=emitter, lost_at=lost_at,
        )
        if ok:
            _remove_writer_abandoned_sentinel(sentinel)
            recorded = True
    return recorded


def _remove_writer_abandoned_sentinel(sentinel: Path) -> None:
    try:
        sentinel.unlink(missing_ok=True)
    except Exception as exc:
        log.error(
            f"writer-abandoned sentinel NOT removed ({type(exc).__name__}); "
            f"the next boot will record writer_queue_abandoned again",
        )


def _record_unrecorded_failure(
    exc: BaseException, table: str, emitter: str | None,
) -> None:
    """Punch 582 (L11): an Exception the best-effort SSOT swallows has a
    durable row only if it passed through the ``@db_write`` sentinel (or the
     shed path), which tags it. One that never reached an emitter (raised
    while dispatching, or by a writer that is not an ``@audit_emitter``) gets
    its row here. The caller already bumped the counter for this failure."""
    try:
        from email_triage.db.audit import audit_gap_recorded
        already = audit_gap_recorded(exc)
    except Exception:
        # Cannot tell: record. A duplicate row beats a missing one.
        already = False
    if already:
        return
    record_audit_loss(
        "failed_unrecorded", table=table, emitter=emitter, bump_on_failure=False,
    )


def _inner_write_done(fut: "asyncio.Future") -> None:
    """Done-callback on every shielded inner write. A write that ended
    cancelled, or with a BaseException that is not an Exception, did not land
    and nothing else records it (an Exception reached the @db_write sentinel
    or the SSOT's WARNING). Runs on the loop: never raises."""
    try:
        _INFLIGHT.discard(fut)
        if fut in _ACCOUNTED:
            return
        if fut.cancelled():
            lost = True
        else:
            exc = fut.exception()
            lost = exc is not None and not isinstance(exc, Exception)
        if lost:
            table, emitter = _INFLIGHT_META.get(fut, ("unknown", None))
            record_audit_loss("inner_cancelled", table=table, emitter=emitter)
    except BaseException:
        pass


def _launch_inner_write(
    awrite: Callable[[], Awaitable[Any]], table: str, emitter: str | None,
) -> "asyncio.Future":
    """Start the inner write as its own future and track it (punch 582)."""
    inner = asyncio.ensure_future(awrite())
    _INFLIGHT.add(inner)
    _INFLIGHT_META[inner] = (table, emitter)
    inner.add_done_callback(_inner_write_done)
    task = asyncio.current_task()
    if task is not None:
        _LAUNCHED[task] = inner
    return inner


async def drain_inflight_audit_writes(
    timeout: float, pending: Iterable["asyncio.Future"] = (),
    record: "Callable[[int], Any] | None" = None,
) -> int:
    """Lifespan shutdown (punch 582): wait up to ``timeout`` seconds for every
    in-flight audit write, plus the fire-and-forget tasks in ``pending`` that
    have not launched their write yet. Whatever is still running then gets
    ONE ``shutdown_undrained`` row with its count, and is marked accounted so
    its later cancellation at loop close does not record it again. Returns
    that count. Call it while the loss sink and the connection are still up
    (the bounded drain also while the writer is, so the writes can land).

    Only writes on the running loop are this shutdown's: a write left pending
    on another loop (an earlier app instance in the same process, as under
    a test runner) can never complete here, and counting it would add a
    false row and a full ``timeout`` wait to every later shutdown."""
    loop = asyncio.get_running_loop()
    # Punch 636: the lifespan sweeps a second time after the writer stops; a
    # write an earlier drain already recorded is not counted again.
    writes: "set[asyncio.Future]" = {
        f for f in _INFLIGHT
        if not f.done() and f.get_loop() is loop and f not in _ACCOUNTED
    }
    outers = [
        t for t in pending
        if not t.done() and t not in _LAUNCHED and t.get_loop() is loop
        and t not in _ACCOUNTED
    ]
    waiting = writes | set(outers)
    if waiting:
        await asyncio.wait(waiting, timeout=timeout)
    left_writes = [f for f in writes if not f.done()]
    left_outers = [t for t in outers if not t.done() and t not in _LAUNCHED]
    for f in left_writes + left_outers:
        _ACCOUNTED.add(f)
    for t in outers:
        inner = _LAUNCHED.get(t)
        if inner is not None and not inner.done():
            _ACCOUNTED.add(inner)
            if inner not in left_writes:
                left_writes.append(inner)
    n = len(left_writes) + len(left_outers)
    if n:
        if record is not None:
            # Punch 636 fold: the lifespan passes the lock-free sentinel
            # recorder when the writer is wedged and holds the write lock.
            record(n)
        else:
            record_audit_loss("shutdown_undrained", table="mixed", count=n)
    return n


# N-192 R20_20: /health-visibility bump for safe_audit_write failures. Set
# by the web app's lifespan (`register_audit_failure_sink`) to a callback
# that increments `app.state.audit_failures`. Non-web callers (CLI, tests,
# background jobs before app boot) leave it as None — the failure is
# WARNING-logged as before but doesn't bump a counter that isn't wired up
# yet. Deliberate module-level indirection so the audit surface stays
# dependency-free of `fastapi.Request` / `starlette.applications.State`.
_audit_failure_sink: Callable[[], None] | None = None


# 2026-07-10 root-cause fix for test_access_audit drain-race escalation
# (feedback_fix_flaky_tests_dont_dismiss rule 5): the audit-write swallow
# was invisible to the test drain helper — a swallowed OperationalError /
# ProgrammingError transitioned the task to done=True with NO row landing,
# so the drain's task-set arm passed and the row-count arm burned the full
# timeout waiting for a row that would never come (15→30→45s escalation).
# Every swallow now stashes the exception here so tests can fail-fast with
# the real error class named. Best-effort observability only — production
# swallow semantics preserved: the WARNING log + counter bump are unchanged.
# Module-global works cleanly under xdist (each worker = own process).
_LAST_AUDIT_EXC: "tuple[Exception, str, float] | None" = None


def _stash_last_audit_exc(exc: Exception, description: str) -> None:
    """Stash the swallowed exception for post-hoc test observability.

    Best-effort: inner failures MUST NOT propagate (audit swallow semantics
    are preserved). See :data:`_LAST_AUDIT_EXC` docstring."""
    global _LAST_AUDIT_EXC
    try:
        _LAST_AUDIT_EXC = (exc, description, time.time())
    except Exception:  # pragma: no cover — never let observability break the swallow
        pass


def clear_last_audit_exc() -> None:
    """Reset the swallow stash — called from the test autouse fixture so
    a prior test's swallow doesn't false-trip the next test's drain."""
    global _LAST_AUDIT_EXC
    _LAST_AUDIT_EXC = None


def get_last_audit_exc() -> "tuple[Exception, str, float] | None":
    """Read-side accessor mirroring the stash — used by the drain helper."""
    return _LAST_AUDIT_EXC


def register_audit_failure_sink(sink: Callable[[], None] | None) -> None:
    """N-192 R20_20: web lifespan wires the app.state.audit_failures bump
    into safe_audit_write's failure path so /health can flip degraded on
    a swallowed audit-write failure (before N-192 it only landed in the
    WARNING log — invisible to the counter-based /health drift check)."""
    global _audit_failure_sink
    _audit_failure_sink = sink


def _bump_failure_counter() -> None:
    """Invoke the registered failure sink, swallowing any error (a failing
    sink must never turn an audit-write failure into a caller exception)."""
    sink = _audit_failure_sink
    if sink is None:
        return
    try:
        sink()
    except Exception:  # pragma: no cover — sink must be side-effect-safe
        pass


def safe_audit_write(
    write: Callable[[], Any], *, description: str,
    table: str = "unknown", emitter: str | None = None,
) -> Any:
    """Run a best-effort audit-table write; never let a failure escape.

    Parameters
    ----------
    write:
        A zero-argument callable that performs the actual insert —
        typically ``lambda: record_*_event(...)``. It is invoked
        synchronously; any exception it raises is caught here.
    description:
        A short human tag for the failure log line, e.g.
        ``"api_key_created key_id=42"`` or ``"login_web"``.

    Returns the write's own return value on success (e.g. the inserted
    audit-row id, for call sites that finalise it later via
    ``update_*_event``), or ``None`` on failure — the same value a
    hand-rolled ``try: id = emit() except: pass`` would have left bound.

    A failure is logged at WARNING (so a /health audit-failure drift
    check can see it) and swallowed — it never propagates to the caller.

     flaky-drain recurrence-4 fix (the backlog  — feedback_fix_
    flaky_tests_dont_dismiss): broadened to ``except BaseException``
    so a cancellation (``asyncio.CancelledError``, a ``BaseException``
    subclass since Python 3.8) STILL stashes onto ``_LAST_AUDIT_EXC``
    before propagating. Under the old ``except Exception``, cancel-
    during-write transitioned the fire-and-forget task to
    ``done()==True`` WITHOUT a fresh stash, so the drain-helper poll
    saw a task-set drain + row-count stuck + no fresh stash → the
    generic 10s "did not drain" AssertionError, no class named.
    Broadening + re-raising cooperative-cancel classes preserves
    propagation semantics while giving the drain-race pin a class
    name to fire on. Closes the CANCEL-DURING-AWAIT class only —
    the xdist_load starvation class (workflow finding: 4 vCPU runner
    + 4 xdist workers + sibling containers → loadavg 3.91) remains
    open and can still hit the generic timeout under load; that class
    is a distinct fix (retry-count on drain OR pin xdist -n 2 on
    the shared runner).
    """
    try:
        return write()
    except BaseException as exc:
        _stash_last_audit_exc(exc, description)  # 2026-07-10 drain-race fix
        # hipaa-sme F1: cooperative-cancel classes MUST NOT bump the
        # /health drift counter or emit at WARNING — test teardown +
        # graceful shutdown cancel in-flight fire-and-forget audit
        # tasks routinely, and pumping the counter would drown genuine
        # audit-write failures in shutdown noise. Stash stays
        # unconditional (drain-race pin still gets the class name).
        if isinstance(exc, Exception):
            log.warning(
                "audit_write_failed",
                audit=description,
                error=str(exc),
            )
            _bump_failure_counter()  # N-192 R20_20: /health-visible bump
            _record_unrecorded_failure(exc, table, emitter)
            return None
        #  recurrence-4 fix: cooperative-cancel classes
        # (asyncio.CancelledError, SystemExit, KeyboardInterrupt) are
        # BaseException-not-Exception; they MUST propagate so task
        # cancellation / interpreter shutdown works.
        log.debug(
            "audit_write_cancelled",
            audit=description,
            error_class=type(exc).__name__,
        )
        # Punch 582 (L8): the sync write did not return, and the @db_write
        # sentinel catches Exception only, so nothing else records it.
        record_audit_loss("interrupted_sync", table=table, emitter=emitter)
        raise


def attach_audit_done_callback(
    task, description: str, signal=None, *,
    table: str = "unknown", emitter: str | None = None,
) -> None:
    """the backlog  F1 (DA + db-sme convergent) — capture the
    fire-and-forget audit task's terminal outcome via a done-callback,
    NOT via the ``try/except`` inside ``safe_audit_write_async``.

    The try/except only sees exceptions that land DURING ``await
    awrite()``. If the event loop cancels the coroutine BEFORE it hits
    ``await`` (portal-loop teardown, supervisor cancel, task cancelled
    while still pending on the run queue), the except clause never
    runs — the task transitions to ``done()==True`` with
    ``cancelled()==True`` and NO stash on ``_LAST_AUDIT_EXC``. The
    drain-race pin then falls through to the generic 10s "did not
    drain" AssertionError with no class named — the exact recurrence-4
    shape.

    This callback runs on EVERY task-end mode (exception, cancellation,
    normal-return) and stashes ``task.exception()`` when present OR a
    synthesized ``CancelledError`` when ``task.cancelled()`` is True.
    Result-carrying tasks that returned normally do not stash — the
    ``safe_audit_write*`` sibling wrapping the awaitable already
    returned a real value.

    Idempotency: if ``safe_audit_write_async`` already stashed inside
    its ``except BaseException`` clause, this callback overwrites with
    the same-class stash — no drift.
    """
    def _cb(t) -> None:
        try:
            if t.cancelled():
                # Punch 582 (L1): cancelled before it launched its write
                # (no inner write registered for it) means the row was never
                # submitted. A launched write is watched by its own callback
                # (``_inner_write_done``); a drained one is already accounted.
                if t not in _LAUNCHED and t not in _ACCOUNTED:
                    record_audit_loss(
                        "cancelled_before_launch", table=table, emitter=emitter,
                    )
                _stash_last_audit_exc(
                    _AsyncCancelledMarker(description), description
                )
                return
            exc = t.exception()
            if exc is not None:
                _stash_last_audit_exc(exc, description)
        except BaseException as _cb_exc:
            # DA F2 (2026-07-11): callback runs on the portal loop;
            # MUST NOT raise there. But a silent swallow of a stash-
            # throw would mask real audit-write failures. Log at
            # WARNING via TriageLogger kwargs (PD#10 no positional
            # 2nd arg) so /health drift counters + operator logs see
            # the class name at least once.
            try:
                log.warning(
                    "audit_done_callback_swallow",
                    audit=description,
                    error_class=type(_cb_exc).__name__,
                    error=str(_cb_exc),
                )
            except BaseException:
                # If even the log fails, we DEFINITELY can't raise on
                # the portal loop. Give up + fall through to signal-
                # set so the drain helper still wakes.
                pass
            # Punch 582 (L7): the task's audit outcome is now unknown; the
            # log line above is pruned with log_entries, so leave a durable
            # row too (presumptive: the write may have landed).
            try:
                record_audit_loss(
                    "done_callback_swallow", table=table, emitter=emitter,
                )
            except BaseException:
                pass
        finally:
            # the backlog  (DA  F3 root-cause fix): fire the
            # optional test-side ``threading.Event`` so the drain
            # helper wakes on task completion instead of burning a
            # 20ms polling interval. Runs on the portal loop; guarded
            # so a signal misconfig can NEVER kill the audit-write
            # task's completion accounting. Idempotent — the drain
            # helper clears() the event before each wait.
            if signal is not None:
                try:
                    signal.set()
                except BaseException:
                    pass
    task.add_done_callback(_cb)


class _AsyncCancelledMarker(BaseException):
    """Placeholder BaseException used when
    :func:`attach_audit_done_callback` finds ``task.cancelled()==True``
    with no attached exception. Materializes the "task was cancelled
    before its except-clause could run" case so the drain-race pin
    can name a class (``_AsyncCancelledMarker``) instead of falling
    through to the generic timeout AssertionError."""

    def __init__(self, description: str) -> None:
        super().__init__(f"audit_write_cancelled:{description}")


async def safe_audit_write_async(
    awrite: Callable[[], Awaitable[Any]], *, description: str,
    table: str = "unknown", emitter: str | None = None,
) -> Any:
    """Async sibling of :func:`safe_audit_write` (census run17 #3).

    For best-effort audit writes dispatched OFF the event loop — the
    ``await db_call(record_*_event, …)`` seam (the sync SSOT cannot wrap an
    ``await``, which is why several call sites that *comment* "same policy as
    safe_audit_write" hand-rolled it after  moved the write onto db_call).
    Same policy: run it, never raise, log at WARNING on failure (so the
    /health audit-failure drift check sees the miss). ``awrite`` is a zero-arg
    awaitable-returning callable, typically ``lambda: db_call(record_*, …)``.

    Returns the awaited write's value on success (e.g. the inserted audit-row
    id, for sites that finalise it later), or ``None`` on failure.

     flaky-drain recurrence-4 fix — see :func:`safe_audit_write`
    docstring for the BaseException rationale. Same shape here: cancel
    of the fire-and-forget task under the middleware's
    ``asyncio.create_task(safe_audit_write_async(...))`` at
    ``web/access_audit.py:270`` transitions the task to
    ``done()==True`` on the portal loop; without a stash on
    ``_LAST_AUDIT_EXC`` the drain helper cannot name the class.

    Recurrence-10 fix (2026-07-16, test_access_audit.py:413 drain-race
    on 88a222ac CI): the inner ``awrite()`` is wrapped in
    :func:`asyncio.shield` so cancellation of the fire-and-forget
    wrapper task does NOT cancel the in-flight audit INSERT once it has
    been scheduled onto the ``db_call`` threadpool. The outer wrapper
    still raises ``CancelledError`` (propagation semantics unchanged for
    the loop's task-teardown accounting), but the shielded inner Task
    continues on the portal loop until the INSERT lands.

    Reach + framing (hipaa-sme + devils-advocate calibration, 2026-07-16):
    steady-state prod request handling was NOT affected — once the
    middleware returns and the response is served, the detached task
    owns its own lifecycle and nothing cancels it. The class this
    shield closes is the **restart / shutdown boundary**: uvicorn
    graceful shutdown (``timeout_graceful_shutdown``) sends
    ``CancelledError`` to still-in-flight fire-and-forget tasks;
    ``podman restart`` (the deploy host quadlet / the monitoring system drift-remediate handler)
    fires SIGTERM into the same window; ``./scripts/deploy.sh``
    container-cycle at deploy time hits the same boundary. Restart
    cadence in prod makes the boundary class non-trivial for
    §164.312(b) audit accounting; the xdist-under-load CI class was
    just the frequent reproducer (event-loop teardown between tests
    hits the same cancel path).

    Scoped-out arms (all covered by
    :func:`attach_audit_done_callback` → ``_AsyncCancelledMarker`` +
    the drain-race pin's fail-loud path, per
    §164.306(d)(3)(ii)(B) equivalent-measure):

    * **Pre-await cancel** — loop cancels the coroutine BEFORE it
      reaches ``await asyncio.shield(...)``; ``awrite()`` is never
      invoked, no inner Task exists to shield, row cannot land. Rare
      class (would need a cancel between ``create_task`` scheduling
      and coroutine entry).
    * **Event-loop teardown mid-shield** — ``loop.close()`` while the
      inner Task is still running (e.g. an aggressive shutdown with
      ``timeout_graceful_shutdown`` set to zero, or the pytest event
      loop being closed by a fixture teardown before the shielded
      Task completes). The inner Task IS cancelled in this path;
      shield only holds while the loop is alive. Distinct class from
      the boundary-cancel above; db-sme Q1 caveat.

    Both arms remain candidates for a future sync-in-thread fallback
    (see ``feedback_fix_flaky_tests_dont_dismiss``); scoped out of
    this fix as rare + observability-covered.

    Punch 582: both arms now leave a durable ``audit_gap_events`` row. The
    inner write is launched by :func:`_launch_inner_write`, which tracks it
    and attaches :func:`_inner_write_done`: an inner write that ends
    cancelled records ``inner_cancelled``. A pre-await cancel of a
    fire-and-forget task records ``cancelled_before_launch`` in
    :func:`attach_audit_done_callback`. No await separates ``try:`` from
    :func:`_launch_inner_write`, so a CancelledError cannot land here before
    the inner write exists; :func:`_on_outer_cancel`'s ``cancelled_before_launch``
    branch is reached only when launching the inner write itself raises a
    non-Exception BaseException (DA E-4, panel B7). An outer cancel while the
    shielded inner write is still running records nothing: that write usually
    lands, and if it does not, its own callback records it.
    """
    inner = None
    try:
        inner = _launch_inner_write(awrite, table, emitter)
        return await asyncio.shield(inner)
    except BaseException as exc:
        _stash_last_audit_exc(exc, description)  # 2026-07-10 drain-race fix
        # hipaa-sme F1 (mirror of sync sibling): cooperative-cancel
        # classes MUST NOT bump the drift counter / WARNING-log. Stash
        # unconditional; counter + WARNING gated on Exception; cancel
        # classes propagate via raise after a DEBUG log line for the
        # drain-race pin. Under the recurrence-10 shield fix above the
        # cancel no longer LOSES the row (the shielded inner Task
        # completes independently), so the "no drift bump on cancel"
        # rationale strengthens: cancel is now a non-event for
        # compliance accounting.
        if isinstance(exc, Exception):
            log.warning(
                "audit_write_failed",
                audit=description,
                error=str(exc),
            )
            _bump_failure_counter()  # N-192 R20_20: /health-visible bump
            _record_unrecorded_failure(exc, table, emitter)
            return None
        log.debug(
            "audit_write_cancelled_shielded",
            audit=description,
            error_class=type(exc).__name__,
        )
        _on_outer_cancel(inner, table, emitter)
        raise


def _on_outer_cancel(
    inner: "asyncio.Future | None", table: str, emitter: str | None,
) -> None:
    """Punch 582: the outer coroutine of :func:`safe_audit_write_async`
    ended with a non-Exception BaseException. With no inner write launched,
    the row was never submitted: record ``cancelled_before_launch``. That
    branch is reachable only when :func:`_launch_inner_write` itself raises
    one (``awrite()`` raising synchronously, say). A CancelledError cannot
    arrive before the launch, because no await precedes it (DA E-4, panel
    B7); a pre-start cancel of a fire-and-forget task is recorded by
    :func:`attach_audit_done_callback` instead. A launched inner write is
    left to :func:`_inner_write_done`, which records only a real loss."""
    if inner is None:
        task = asyncio.current_task()
        if task is not None:
            _ACCOUNTED.add(task)
        record_audit_loss("cancelled_before_launch", table=table, emitter=emitter)
