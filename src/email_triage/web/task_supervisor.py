"""Background-task supervisor with crash detection + bounded restart.

The lifespan in ``app.py`` spawns six long-lived background tasks
(digest scheduler, Gmail push consumer, Gmail watch renewer,
unified poll loop, log prune, daily health email). The previous
shape — bare ``asyncio.create_task`` — meant any one of those
crashing logged an exception and then disappeared. ``/health``
couldn't tell. Operators noticed hours later when the symptom
reached a threshold (digests stopped arriving, watch tokens
expired, etc.).

This module provides ``TaskSupervisor``: a per-app registry that

* spawns each task with a name + factory (the factory lets us
  re-spawn on crash without reaching back into the original
  closure);
* records ``(state, crashes, last_crash_ts, last_crash_error_type,
  last_request_id)`` on each transition;
* re-spawns on failure with capped exponential backoff
  (configurable ``backoff_initial`` / ``backoff_max``);
* applies a circuit breaker — N crashes within a window →
  ``quarantined``; stops re-spawning, leaves the row in place so
  ``/health`` can report it and the operator can fix the bug
  before restarting the container;
* hands every supervised task body a fresh request_id (via
  ``new_request_context``) so its log lines are greppable end-to-end.

Stop semantics: ``stop_all()`` is shutdown-clean — cancels every
task, awaits up to ``stop_timeout_secs`` per task, then returns.
Hung tasks are logged but don't block shutdown.
"""

from __future__ import annotations

import asyncio
import logging
import random
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from email_triage.triage_logging import new_request_context


from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.task_supervisor")  # N-196b R21_4


# ---------------------------------------------------------------------------
# Configuration knobs (no external config; defaults match plan)
# ---------------------------------------------------------------------------

# Circuit-breaker window: how many crashes within how many seconds
# trip quarantine. 5 crashes in 10 minutes is "this task is broken,
# stop wasting cycles trying to restart it."
DEFAULT_QUARANTINE_AFTER_CRASHES = 5
DEFAULT_QUARANTINE_WINDOW_SECS = 600
# Punch 636: the bound on ``stop_all``, one term of the shutdown envelope that
# must fit inside the container's StopTimeout
# (tests/test_636_shutdown_envelope_pin.py sums every term).
SUPERVISOR_STOP_TIMEOUT_SECS: float = 3.0

#  — a ``supervised_interval_loop`` whose per-tick body fails on
# every tick stays ``status="running"`` forever (the supervisor only
# records ``crashed`` when the loop *coroutine* raises, and the loop's
# per-tick try/except deliberately never lets a tick failure through).
# This threshold is how many *consecutive* tick failures count as
# "this loop is broken" — surfaced via ``health_snapshot()`` so
# /health can degrade on it. A single transient failure must not flap
# the signal, hence "consecutive" + a threshold > 1.
DEFAULT_TICK_FAILURE_THRESHOLD = 3

#  — a tick that HANGS forever (never returns, never raises) is the
# blind spot the failure-count signal above cannot see: ``record_tick_
# result`` is only ever called *after* a tick completes, so a hung tick
# leaves ``last_tick_ts`` frozen and ``failing`` stuck at False — the
# loop reads healthy while it is in fact wedged. The fix is a staleness
# signal: a loop is "stale" when its last tick (or its start, before
# the first tick lands) is older than ``TICK_STALENESS_MULTIPLE`` × its
# interval. The multiple is generous so an ordinary slow tick or a long
# cron-anchored interval does not trip it. ``TICK_STALENESS_FLOOR_SECS``
# is a lower bound so a short-interval loop is not flagged for a single
# tick that ran a little long.
DEFAULT_TICK_STALENESS_MULTIPLE = 5.0
TICK_STALENESS_FLOOR_SECS = 120.0


# ---------------------------------------------------------------------------
# State records
# ---------------------------------------------------------------------------

CoroFactory = Callable[[], Awaitable[Any]]


@dataclass
class TickHealth:
    """Per-loop tick-health record for a ``supervised_interval_loop``.

     — the loop scaffolding swallows every per-tick exception so a
    single bad tick never kills the loop. The cost is that a loop whose
    *every* tick fails looks identical (``status="running"``) to a
    healthy one. This record is the missing signal: the loop updates it
    after each tick, and ``TaskSupervisor.health_snapshot()`` merges it
    into the per-task payload so /health can degrade on a sustained
    failure run.

    ``failing`` is True only once ``consecutive_failures`` reaches the
    threshold — so one transient hiccup does not flap the signal.

     — ``interval_secs`` and ``started_ts`` are recorded so
    ``stale`` can be computed: a tick that hangs forever never reaches
    ``record_tick_result``, so ``last_tick_ts`` alone cannot reveal a
    wedged loop. ``stale`` compares the freshness reference (the later
    of ``last_tick_ts`` and ``started_ts``) against the interval.
    """
    loop_name: str
    last_tick_ok: bool = True
    consecutive_failures: int = 0
    last_tick_ts: float | None = None
    last_tick_error_type: str | None = None
    total_ticks: int = 0
    total_tick_failures: int = 0
    failure_threshold: int = DEFAULT_TICK_FAILURE_THRESHOLD
    #  — staleness inputs. ``interval_secs`` is the loop's current
    # sleep cadence (the loop reports it; for a callable interval it is
    # the most recent computed value). ``started_ts`` is when the loop
    # registered — it bridges the warm-up window before the first tick.
    interval_secs: float | None = None
    started_ts: float | None = None
    staleness_multiple: float = DEFAULT_TICK_STALENESS_MULTIPLE

    @property
    def failing(self) -> bool:
        """True once consecutive failures reach the threshold."""
        return self.consecutive_failures >= self.failure_threshold

    def staleness_budget_secs(self) -> float | None:
        """How long since the last tick is still considered healthy.

        ``None`` when the interval is unknown (loop never reported one)
        — staleness cannot be judged, so it is not flagged.
        """
        if self.interval_secs is None:
            return None
        return max(
            self.interval_secs * self.staleness_multiple,
            TICK_STALENESS_FLOOR_SECS,
        )

    def seconds_since_tick(self, *, now: float | None = None) -> float | None:
        """Seconds since the freshness reference (last tick, or loop
        start before the first tick). ``None`` if neither is known."""
        ref = self.last_tick_ts
        if ref is None:
            ref = self.started_ts
        if ref is None:
            return None
        return (time.time() if now is None else now) - ref

    def is_stale(self, *, now: float | None = None) -> bool:
        """True when no tick has completed within the staleness budget
        — the signal a hung tick (which never calls
        ``record_tick_result``) would otherwise hide."""
        budget = self.staleness_budget_secs()
        if budget is None:
            return False
        since = self.seconds_since_tick(now=now)
        if since is None:
            return False
        return since > budget

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_tick_ok": self.last_tick_ok,
            "consecutive_failures": self.consecutive_failures,
            "last_tick_ts": self.last_tick_ts,
            "last_tick_error_type": self.last_tick_error_type,
            "total_ticks": self.total_ticks,
            "total_tick_failures": self.total_tick_failures,
            "failing": self.failing,
            "interval_secs": self.interval_secs,
            "seconds_since_tick": self.seconds_since_tick(),
            "staleness_budget_secs": self.staleness_budget_secs(),
            "stale": self.is_stale(),
        }


# Module-level registry of per-loop tick health, keyed by loop name.
# ``supervised_interval_loop`` writes here; ``TaskSupervisor.
# health_snapshot()`` reads here. A module global (rather than threading
# the supervisor through every ``supervised_interval_loop`` call site)
# keeps the ~15 existing callers untouched — the loop name is the join
# key and it already matches the supervised-task name 1:1.
_tick_health: dict[str, TickHealth] = {}


def mark_loop_started(
    loop_name: str,
    interval_secs: float | None,
    *,
    staleness_multiple: float = DEFAULT_TICK_STALENESS_MULTIPLE,
) -> TickHealth:
    """Register a ``supervised_interval_loop`` at startup.

     — records ``started_ts`` (so the staleness clock has a
    reference before the first tick completes) and the loop's
    ``interval_secs`` (so :meth:`TickHealth.is_stale` has a budget).
    Idempotent: re-registering an existing loop refreshes the interval
    but leaves the tick counters untouched.
    """
    th = _tick_health.get(loop_name)
    if th is None:
        th = TickHealth(loop_name=loop_name)
        _tick_health[loop_name] = th
    th.started_ts = time.time()
    th.interval_secs = interval_secs
    th.staleness_multiple = staleness_multiple
    return th


def record_tick_result(
    loop_name: str,
    ok: bool,
    *,
    error_type: str | None = None,
    failure_threshold: int = DEFAULT_TICK_FAILURE_THRESHOLD,
    interval_secs: float | None = None,
) -> TickHealth:
    """Record the outcome of one ``supervised_interval_loop`` tick.

    A successful tick clears ``consecutive_failures``; a failed tick
    increments it. Returns the live :class:`TickHealth` record so the
    caller can inspect ``failing`` without a second lookup.

     — ``interval_secs``, when supplied, refreshes the staleness
    budget input (a callable interval changes tick-to-tick).
    """
    th = _tick_health.get(loop_name)
    if th is None:
        th = TickHealth(loop_name=loop_name, failure_threshold=failure_threshold)
        _tick_health[loop_name] = th
    th.failure_threshold = failure_threshold
    if interval_secs is not None:
        th.interval_secs = interval_secs
    th.total_ticks += 1
    th.last_tick_ts = time.time()
    th.last_tick_ok = ok
    if ok:
        th.consecutive_failures = 0
        th.last_tick_error_type = None
    else:
        th.consecutive_failures += 1
        th.total_tick_failures += 1
        th.last_tick_error_type = error_type
    return th


def get_tick_health(loop_name: str) -> TickHealth | None:
    """Return the tick-health record for ``loop_name`` (or None)."""
    return _tick_health.get(loop_name)


@dataclass
class TaskState:
    """Per-task supervisor record. Read-only from outside the supervisor."""
    name: str
    status: str = "starting"  # starting | running | crashed | quarantined | stopped
    crashes: int = 0
    crash_history: list[float] = field(default_factory=list)
    last_crash_ts: float | None = None
    last_crash_error_type: str | None = None
    last_request_id: str | None = None
    started_at: float = field(default_factory=time.time)
    backoff_secs: float = 0.0
    # Set when task is permanently stopped (shutdown or quarantine).
    quarantined_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "crashes": self.crashes,
            # N-339 R31 (2026-07-04): ``last_crash_ts`` +
            # ``last_crash_error_type`` are HISTORIC DIAGNOSTIC fields —
            # never cleared on recovery per :meth:`_record_recovery`'s
            # documented rationale + the ``test_crash_triggers_respawn_
            # with_backoff`` contract. A consumer reading these fields
            # in isolation would see stale-looking values on a running
            # task; the authoritative "healthy now" signal is
            # ``status``. Downstream `/health` consumers MUST gate any
            # "task X failing" surface on ``status`` first.
            "last_crash_ts": self.last_crash_ts,
            "last_crash_error_type": self.last_crash_error_type,
            "last_request_id": self.last_request_id,
            "started_at": self.started_at,
            "backoff_secs": self.backoff_secs,
            "quarantined_reason": self.quarantined_reason,
        }


# ---------------------------------------------------------------------------
# Module-level backoff-math SSOT
# ---------------------------------------------------------------------------


def next_backoff_delay(current: float, *, factor: float = 2.0,
                       max_delay: float = 300.0,
                       min_step: float = 1.0) -> float:
    """N-228 R22: capped exponential-backoff step SSOT.

    Given the CURRENT delay, return the NEXT delay:
    ``min(max(current, min_step) * factor, max_delay)``. Used by
    long-lived retry loops that don't route through
    :class:`TaskSupervisor` (CLI push watcher, IMAP idle re-connect) —
    those loops previously in-lined the same
    `min(backoff * 2, max_backoff)` shape, so a factor change or a
    jitter addition drifted in exactly one loop. Route every backoff
    step through this SSOT.

    :class:`TaskSupervisor._compute_backoff` is a DIFFERENT signature
    (crash-count-driven, not step-driven); the two coexist by intent
    per PD#1 (one SSOT per concern-shape).

    **N-308 R30 (tranche  batch B DA fix-forward on N-228)**: DA
    panel flagged two live defects on the raw
    ``min(current * factor, max_delay)`` shape:

    1. ``current == 0`` (or any value below ``min_step``) → next delay
       stays 0/tiny forever → hot spin loop (thundering herd on any
       shared provider outage). Fix: ``min_step`` floor + a
       ``max(current, min_step)`` clamp so the geometric progression
       always starts above zero even if a caller re-uses a stale-zero
       ``current``.
    2. ``factor <= 1.0`` → no geometric growth → same hot-spin failure
       mode. Fix: ``ValueError`` on ``factor <= 1.0`` and on
       ``max_delay <= 0`` (fail-CLOSED at the caller boundary — a
       nonsense config should not silently degrade the retry loop).

    Callers pass a positive ``current`` (the previous tick's delay) or
    ``0`` to start; the ``min_step`` clamp makes both safe.
    """
    if factor <= 1.0:
        raise ValueError(
            f"next_backoff_delay: factor={factor!r} must be > 1.0 for "
            "geometric growth (factor <= 1 → no backoff, hot-spin)."
        )
    if max_delay <= 0:
        raise ValueError(
            f"next_backoff_delay: max_delay={max_delay!r} must be > 0."
        )
    return min(max(current, min_step) * factor, max_delay)


# ---------------------------------------------------------------------------
# TaskSupervisor
# ---------------------------------------------------------------------------

class TaskSupervisor:
    """Manages the lifecycle of named background tasks."""

    def __init__(
        self,
        *,
        backoff_initial: float = 5.0,
        backoff_max: float = 300.0,
        backoff_factor: float = 2.0,
        quarantine_after_crashes: int = DEFAULT_QUARANTINE_AFTER_CRASHES,
        quarantine_window_secs: int = DEFAULT_QUARANTINE_WINDOW_SECS,
        stop_timeout_secs: float = SUPERVISOR_STOP_TIMEOUT_SECS,
    ) -> None:
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._backoff_factor = backoff_factor
        self._quarantine_after_crashes = quarantine_after_crashes
        self._quarantine_window_secs = quarantine_window_secs
        self._stop_timeout_secs = stop_timeout_secs
        self._states: dict[str, TaskState] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._factories: dict[str, CoroFactory] = {}
        self._restart_on_failure: dict[str, bool] = {}
        self._stopping = False

    # -- spawn / supervise --

    def supervise(
        self,
        name: str,
        coro_factory: CoroFactory,
        *,
        restart_on_failure: bool = True,
    ) -> asyncio.Task:
        """Spawn ``coro_factory()`` as a supervised task named ``name``.

        Returns the underlying asyncio.Task for code paths that want a
        handle (e.g. tests). The supervisor tracks state regardless.

        Re-supervising a name whose task is still running raises —
        callers must stop it first. Re-supervising after a crash is
        normal: state persists, ``status`` flips back to ``running``.
        """
        if name in self._tasks and not self._tasks[name].done():
            raise RuntimeError(
                f"task {name!r} is already running; stop it before re-supervising"
            )

        self._factories[name] = coro_factory
        self._restart_on_failure[name] = restart_on_failure

        state = self._states.get(name)
        if state is None:
            state = TaskState(name=name)
            self._states[name] = state
        state.status = "starting"
        state.started_at = time.time()
        state.quarantined_reason = None

        task = asyncio.create_task(self._run_supervised(name), name=name)
        self._tasks[name] = task
        return task

    async def _run_supervised(self, name: str) -> None:
        """Wrapper around the user's coro that handles crashes + restart."""
        state = self._states[name]
        while True:
            factory = self._factories[name]
            with new_request_context(f"task.{name}") as rid:
                state.last_request_id = rid
                # N-270 R28: if we're restarting FROM the crashed
                # state (i.e. a prior tick recorded a crash + the
                # supervisor decided to retry), route the recovery
                # clear through the SSOT. Both edges (SET via
                # `_record_crash`, CLEAR via `_record_recovery`) go
                # through their own funnels — same PD#18 pattern as
                # the sibling `_mark_failing`/`_mark_recovered` in
                # watcher.py (N-49/N-246).
                if state.status == "crashed":
                    self._record_recovery(state)
                state.status = "running"
                try:
                    await factory()
                    # Coro returned cleanly. By default we treat that
                    # as "this task has finished" rather than a crash;
                    # set status accordingly and stop supervising.
                    state.status = "stopped"
                    return
                except asyncio.CancelledError:
                    # Shutdown-driven cancel — propagate without
                    # registering a crash.
                    state.status = "stopped"
                    raise
                except Exception as exc:
                    # Real crash. Record + decide whether to retry.
                    self._record_crash(state, exc)
                    if self._stopping:
                        return
                    if not self._restart_on_failure[name]:
                        return
                    if self._should_quarantine(state):
                        state.status = "quarantined"
                        state.quarantined_reason = (
                            f"{state.crashes} crashes in "
                            f"{self._quarantine_window_secs}s; supervisor "
                            f"stopped restarting. Last error: "
                            f"{state.last_crash_error_type}"
                        )
                        _log.error(
                            "task quarantined after repeated crashes",
                            extra={"_extra": {
                                "task": name,
                                "crashes": state.crashes,
                                "last_error_type": state.last_crash_error_type,
                            }},
                        )
                        return
                    # Backoff before re-spawning.
                    backoff = self._compute_backoff(state)
                    state.backoff_secs = backoff
                    _log.warning(
                        "task crashed; restart scheduled",
                        extra={"_extra": {
                            "task": name,
                            "error_type": state.last_crash_error_type,
                            "backoff_secs": backoff,
                            "crashes_in_window": len(state.crash_history),
                        }},
                    )

            # Sleep OUTSIDE the request context so the wait time isn't
            # tagged with the previous attempt's request_id.
            try:
                await asyncio.sleep(state.backoff_secs)
            except asyncio.CancelledError:
                state.status = "stopped"
                raise

    def _record_crash(self, state: TaskState, exc: BaseException) -> None:
        now = time.time()
        state.crashes += 1
        state.last_crash_ts = now
        state.last_crash_error_type = type(exc).__name__
        # Trim crash_history to the active window before appending so
        # the count reflects "crashes within the last quarantine_window".
        cutoff = now - self._quarantine_window_secs
        state.crash_history = [t for t in state.crash_history if t >= cutoff]
        state.crash_history.append(now)
        state.status = "crashed"

    def _record_recovery(self, state: TaskState) -> None:
        """N-270 R28 — PD#18 lifecycle-flag SSOT for the CLEAR edge on
        a recovering task. Sibling to :func:`_record_crash`. Called
        when a task that was previously ``"crashed"`` transitions back
        to ``"running"`` (the restart-after-crash path in
        :func:`_run_supervised`).

        Same lifecycle-tally-decay class as ``_mark_recovered`` in
        ``watcher.py`` (N-49/N-246) and ``record_message_result``
        success branch (N-257). Both edges (SET on crash, CLEAR on
        recovery) now flow through the same funnel — /health no
        longer advertises stale error kind + non-zero backoff on
        tasks that have been ``"running"`` for hours.

        Preserves ``crashes`` (lifetime counter) + ``crash_history``
        (rolling-window count) — those are load-bearing on the
        quarantine decision.

        N-303 R30 (CI-red fix-forward on N-270): keep
        ``last_crash_ts`` + ``last_crash_error_type`` HISTORIC (never
        cleared) so a recovering task can still be inspected for
        "what crashed last time" (the original test contract at
        `test_task_supervisor.py::test_crash_triggers_respawn_with_
        backoff`). `/health` should derive "healthy now" from
        ``status`` — the historic fields are for diagnostics.

        Clears only the CURRENT-FAILURE-STATE fields (``backoff_secs``,
        ``quarantined_reason``) which advertise stale severity if left
        set.

        N-339 R31 (2026-07-04 verify-don't-accept refuted-claim close):
        the 2026-07-03 trust-audit damage-report DA agent flagged this
        as a "set-broad/clear-narrow PD  lie" recommending
        expansion to a "4-field clear". Verification against HEAD
        REFUTES that recommendation:

        - The test contract at :func:`test_crash_triggers_respawn_with_backoff`
          (line 69) explicitly asserts ``last_crash_error_type ==
          "RuntimeError"`` AFTER two crashes + one clean recovery to
          ``status="stopped"``. A 4-field clear would break the
          documented contract.
        - The `/health` derived flags (``any_crashed_recently``,
          ``any_quarantined``) filter on ``status``, not on the
          historic diagnostic fields. There is no "STATUS FLAG" lie
          in the `/health` snapshot itself; the historic fields are
          exposed as diagnostics via ``to_dict()`` (see the
          "authoritative flag is ``status``" note in
          :meth:`TaskState.to_dict`).

        Anti-clear structural pin at
        ``tests/test_n339_task_supervisor_historic_fields_pin.py``
        enforces the docstring rationale: any future ``_record_recovery``
        that touches ``last_crash_ts``, ``last_crash_error_type``,
        ``crashes``, or ``crash_history`` fails the pin loudly + must
        route through a rename + a `/health` contract update."""
        state.backoff_secs = 0.0
        state.quarantined_reason = None

    def _should_quarantine(self, state: TaskState) -> bool:
        return len(state.crash_history) >= self._quarantine_after_crashes

    def _compute_backoff(self, state: TaskState) -> float:
        # Exponential within the window, capped at backoff_max. Using
        # in-window crash count keeps backoff bounded if crashes are
        # spaced far apart (rare flakes don't compound).
        n = max(1, len(state.crash_history))
        delay = self._backoff_initial * (self._backoff_factor ** (n - 1))
        return min(self._backoff_max, delay)

    # -- introspection --

    def health_snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe snapshot of every supervised task.

        Consumed by ``/health`` to report tasks block. Counts are
        derived (any_quarantined, any_crashed_recently, total_crashes,
        any_loop_tick_failing) so the endpoint doesn't have to compute
        them itself.

         — each task that runs as a ``supervised_interval_loop``
        also carries a ``tick_health`` sub-dict (merged from the
        module-level tick-health registry by matching loop name). The
        derived ``any_loop_tick_failing`` flag is True when at least
        one loop has hit its consecutive-failure threshold — a loop
        that is nominally ``status="running"`` but whose every tick
        fails. /health folds this into ``degraded``.

         — ``any_loop_tick_stale`` is the companion signal for the
        hung-tick blind spot: a tick that never returns never reaches
        ``record_tick_result``, so the failure counter cannot move. A
        loop is "stale" when its last tick (or its start, before the
        first tick) is older than a generous multiple of its interval.
        /health folds this into ``degraded`` too.
        """
        tasks = {n: s.to_dict() for n, s in self._states.items()}
        # Merge per-loop tick health onto the matching task record.
        for name, rec in tasks.items():
            th = _tick_health.get(name)
            if th is not None:
                rec["tick_health"] = th.to_dict()
        any_quarantined = any(
            s.status == "quarantined" for s in self._states.values()
        )
        any_crashed_recently = any(
            s.status == "crashed" for s in self._states.values()
        )
        total_crashes = sum(s.crashes for s in self._states.values())
        # A loop is "tick-failing" only once it has crossed the
        # consecutive-failure threshold — one transient hiccup does
        # not flip this.
        any_loop_tick_failing = any(
            th.failing for th in _tick_health.values()
        )
        # A loop is "tick-stale" when no tick has completed within its
        # staleness budget — the only signal a wedged (hung) tick
        # leaves, since it never records a result.
        any_loop_tick_stale = any(
            th.is_stale() for th in _tick_health.values()
        )
        return {
            "tasks": tasks,
            "any_quarantined": any_quarantined,
            "any_crashed_recently": any_crashed_recently,
            "total_crashes": total_crashes,
            "any_loop_tick_failing": any_loop_tick_failing,
            "any_loop_tick_stale": any_loop_tick_stale,
        }

    def get_state(self, name: str) -> TaskState | None:
        return self._states.get(name)

    def is_running(self, name: str) -> bool:
        task = self._tasks.get(name)
        return task is not None and not task.done()

    # -- shutdown --

    async def stop_all(self) -> None:
        """Cancel every supervised task; await up to stop_timeout_secs each.

        Hung tasks are logged but don't block shutdown — the caller
        (FastAPI lifespan) needs to return so systemd can move on.
        Sets ``self._stopping`` first so any in-flight crash-handler
        loop exits without re-spawning.

        Punch 636: the waits run CONCURRENTLY (the ``WatcherManager.stop_all``
        shape), so the whole stop costs one ``stop_timeout_secs`` whatever the
        task count. Awaited one after another, N hung tasks cost N times that
        (21 tasks x 3 s = 63 s, past the container's 60 s StopTimeout).
        """
        self._stopping = True
        names = list(self._tasks.keys())
        for name in names:
            task = self._tasks[name]
            if not task.done():
                task.cancel()
        results = await asyncio.gather(
            *(asyncio.wait_for(self._tasks[name], timeout=self._stop_timeout_secs)
              for name in names),
            return_exceptions=True,
        )
        for name, result in zip(names, results):
            # Cancellation (or any other exception) is the expected path.
            if isinstance(result, asyncio.TimeoutError):
                _log.warning(
                    "supervised task did not stop within timeout",
                    extra={"_extra": {
                        "task": name,
                        "timeout_secs": self._stop_timeout_secs,
                    }},
                )
            self._states[name].status = "stopped"


# ---------------------------------------------------------------------------
# Interval-loop helper
# ---------------------------------------------------------------------------


async def _run_leased_tick(
    loop_name: str,
    lease_name: str,
    conn: sqlite3.Connection,
    ttl_secs: float,
    tick: Callable[[], Awaitable[Any]],
) -> None:
    """Run ``tick`` only while holding the ``single_flight`` DB lock
    ``lease_name``. Another instance holding it → skip this tick.

    The lock is held for the tick's duration only — no renewal. That
    is the right model for the idempotent interval sweeps this drives:
    a crashed holder's lock auto-expires within a few ticks (the TTL),
    and the next tick on any instance simply runs. Leadership may move
    tick-to-tick; for an idempotent sweep that is harmless.
    """
    from email_triage.single_flight import (
        DbLockBusy, acquire_db_lock_async,
    )
    try:
        async with acquire_db_lock_async(
            conn, lease_name, ttl_secs=int(ttl_secs),
        ):
            await tick()
    except DbLockBusy:
        # Another instance owns the lease this tick — expected in a
        # multi-instance deployment, a no-op single-instance.
        _log.debug(
            "interval loop tick skipped — lease held elsewhere",
            extra={"_extra": {"loop": loop_name, "lease": lease_name}},
        )


async def supervised_interval_loop(
    name: str,
    interval_secs: float | Callable[[], float],
    tick: Callable[[], Awaitable[Any]],
    *,
    warmup_secs: float = 5.0,
    startup_jitter_secs: float = 0.0,
    lease_name: str | None = None,
    lease_conn: sqlite3.Connection | None = None,
    lease_ttl_secs: float | None = None,
) -> None:
    """Run ``tick`` every ``interval_secs`` forever, with the standard
    background-loop guards.

    ~15 background loops each hand-rolled the same skeleton — a warm-up
    delay, a ``while True`` with a per-tick ``try/except`` (re-raising
    ``CancelledError``, logging anything else), and a cancel-safe
    interval sleep. This is the single home for it: a loop function
    becomes just its per-tick body passed as ``tick``, and the result
    is handed to :meth:`TaskSupervisor.supervise` exactly as before
    (the supervisor still catches a crash of the loop scaffolding
    itself).

    ``interval_secs`` is normally a fixed number of seconds, but it may
    also be a zero-arg callable returning the seconds to sleep before
    the next tick — re-evaluated each cycle. That supports a
    cron-anchored cadence (sleep to the next HH:00 boundary rather than
    a fixed delay after the previous tick finished).

    Lease-gating: when ``lease_name`` is set, each tick runs
    only on the instance that can acquire the ``single_flight`` DB
    advisory lock of that name — see :func:`_run_leased_tick`. This is
    idempotent and a transparent no-op on a single-instance install;
    it is forward-prep for a multi-instance deployment where exactly
    one instance should run a given global sweep per tick. ``lease_conn``
    (the app DB connection) is required when ``lease_name`` is set.
    ``lease_ttl_secs`` defaults to ``max(interval_secs * 3, 60)`` for a
    fixed interval (3600 for a callable one) so a crashed holder's lock
    auto-expires within a few ticks.

    First-tick startup jitter: when ``startup_jitter_secs``
    is positive, the loop sleeps a uniform random interval in
    ``[0, startup_jitter_secs)`` BEFORE the ``warmup_secs`` delay. This
    staggers the first-tick across all loops so the ~14 background
    interval loops don't all hit ``@db_write`` writes within the same
    5-10s window after the warmup expires — the SQLite single-writer
    queue depth then exceeds the 30s ``busy_timeout``, producing a
    ``database is locked`` storm that Phase 3 closed the cursor-
    corruption cascade but cannot close (it's the engine-level wall).
    Each loop's jitter is drawn ONCE at process start; subsequent ticks
    follow the regular ``interval_secs`` cadence (jitter is NOT applied
    each cycle). Default 0.0 = backward-compatible no-op for callers
    that don't opt in.

    The ``acme_renewer`` previously used a manual ``await asyncio.sleep``
    BEFORE calling ``supervised_interval_loop`` to stagger past the
    o365 / gmail renewers. The ``startup_jitter_secs`` kwarg supersedes
    that pattern uniformly across every interval loop.
    """
    if lease_name is not None and lease_conn is None:
        raise ValueError(
            f"supervised_interval_loop({name!r}): lease_name set but "
            f"lease_conn is None"
        )

    #  Shape B — first-tick startup jitter. Applied BEFORE warmup
    # so the warmup window's purpose (let app finish lifespan
    # initialisation before any tick fires) is preserved; the jitter
    # simply spreads the post-warmup wave across a window. Use
    # ``random.uniform`` so the distribution is flat — every
    # millisecond in ``[0, N)`` is equally likely to be chosen, which
    # avoids the cluster-near-zero shape of an exponential or
    # half-normal draw.
    if startup_jitter_secs > 0:
        await asyncio.sleep(random.uniform(0, startup_jitter_secs))

    if warmup_secs > 0:
        await asyncio.sleep(warmup_secs)
    _log.info(
        "interval loop started",
        extra={"_extra": {
            "loop": name,
            "interval_secs": (
                "dynamic" if callable(interval_secs) else interval_secs
            ),
            "lease_name": lease_name,
        }},
    )

    if lease_ttl_secs:
        ttl = lease_ttl_secs
    elif callable(interval_secs):
        ttl = 3600.0
    else:
        ttl = max(interval_secs * 3, 60.0)

    #  — register the loop so the staleness clock has a reference
    # (``started_ts``) and a budget (``interval_secs``) before the
    # first tick lands. A fixed interval is recorded as-is; a callable
    # interval is seeded with its first computed value and then
    # refreshed each cycle via ``record_tick_result``.
    initial_interval = (
        interval_secs() if callable(interval_secs) else interval_secs
    )
    mark_loop_started(name, initial_interval)

    while True:
        #  — compute the next interval up front so it can refresh
        # the staleness budget on every tick-result record (a callable
        # interval changes cycle-to-cycle).
        delay = interval_secs() if callable(interval_secs) else interval_secs
        #  — rotate request_id PER TICK inside the supervised
        # interval loop. Pre-fix, ``_run_supervised`` bound
        # ``new_request_context`` ONCE per outer factory-restart
        # iteration (task_supervisor.py:423); an interval-loop
        # factory's inner ``while True: await sleep(interval)`` shared
        # that rid across every tick, so log lines from different
        # sweeps of ``sent-mail-capture-loop`` (and every other
        # long-running interval factory) collapsed under one
        # ``request_id`` and prod log-correlation broke across ticks.
        # A nested ``new_request_context`` here creates a stack
        # (contextvar-based), so the outer rid is preserved for the
        # crash-recovery path in ``_run_supervised`` while each tick
        # gets a fresh ``tick.<name>`` rid; the outer rid re-establishes
        # on ``__exit__``. the deploy host prod evidence 2026-07-10:
        # ``request_id=30a7d3ecac4c`` seen at 00:56, 02:01, 08:05,
        # 14:03 EDT across four separate ``sent-mail-capture-loop``
        # ticks. Bonus finding from the +#92 batched SME panel
        # (verdict 3a64dc7ce31befe1); the backlog .
        with new_request_context(f"tick.{name}"):
            try:
                if lease_name is not None:
                    await _run_leased_tick(
                        name, lease_name, lease_conn, ttl, tick,
                    )
                else:
                    await tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A per-tick failure must not kill the loop — log and carry
                # on to the next interval. (The supervisor's crash handling
                # is the safety net for a failure of the loop scaffolding,
                # which this except deliberately does not let through.)
                #
                #  — but a swallowed tick failure was previously
                # *invisible*: a loop whose every tick fails stays
                # ``status="running"`` and /health can't tell. Record the
                # outcome in the tick-health registry so a sustained
                # failure run surfaces (``any_loop_tick_failing`` →
                # /health ``degraded``). A single transient failure is
                # cleared by the next good tick before it crosses the
                # threshold, so the signal does not flap.
                th = record_tick_result(
                    name, ok=False, error_type=type(exc).__name__,
                    interval_secs=delay,
                )
                log_fn = _log.error if th.failing else _log.warning
                log_fn(
                    "interval loop tick failed",
                    extra={"_extra": {
                        "loop": name,
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:300],
                        "consecutive_failures": th.consecutive_failures,
                        "tick_failing": th.failing,
                    }},
                )
            else:
                # Clean tick — clear any prior consecutive-failure streak.
                record_tick_result(name, ok=True, interval_secs=delay)

        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise
