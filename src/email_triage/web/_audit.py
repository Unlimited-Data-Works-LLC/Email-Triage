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
import time
from typing import Any, Awaitable, Callable

from email_triage.triage_logging import get_logger

log = get_logger("web.audit")


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


def safe_audit_write(write: Callable[[], Any], *, description: str) -> Any:
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
        raise


def attach_audit_done_callback(
    task, description: str, signal=None,
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
    awrite: Callable[[], Awaitable[Any]], *, description: str
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
    """
    try:
        return await asyncio.shield(awrite())
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
            return None
        log.debug(
            "audit_write_cancelled_shielded",
            audit=description,
            error_class=type(exc).__name__,
        )
        raise
