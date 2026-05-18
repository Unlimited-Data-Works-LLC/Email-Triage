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
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from email_triage.triage_logging import new_request_context


_log = logging.getLogger("email_triage.web.task_supervisor")


# ---------------------------------------------------------------------------
# Configuration knobs (no external config; defaults match plan)
# ---------------------------------------------------------------------------

# Circuit-breaker window: how many crashes within how many seconds
# trip quarantine. 5 crashes in 10 minutes is "this task is broken,
# stop wasting cycles trying to restart it."
DEFAULT_QUARANTINE_AFTER_CRASHES = 5
DEFAULT_QUARANTINE_WINDOW_SECS = 600


# ---------------------------------------------------------------------------
# State records
# ---------------------------------------------------------------------------

CoroFactory = Callable[[], Awaitable[Any]]


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
            "last_crash_ts": self.last_crash_ts,
            "last_crash_error_type": self.last_crash_error_type,
            "last_request_id": self.last_request_id,
            "started_at": self.started_at,
            "backoff_secs": self.backoff_secs,
            "quarantined_reason": self.quarantined_reason,
        }


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
        stop_timeout_secs: float = 3.0,
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
        derived (any_quarantined, any_crashed_recently, total_crashes)
        so the endpoint doesn't have to compute them itself.
        """
        tasks = {n: s.to_dict() for n, s in self._states.items()}
        any_quarantined = any(
            s.status == "quarantined" for s in self._states.values()
        )
        any_crashed_recently = any(
            s.status == "crashed" for s in self._states.values()
        )
        total_crashes = sum(s.crashes for s in self._states.values())
        return {
            "tasks": tasks,
            "any_quarantined": any_quarantined,
            "any_crashed_recently": any_crashed_recently,
            "total_crashes": total_crashes,
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
        """
        self._stopping = True
        names = list(self._tasks.keys())
        for name in names:
            task = self._tasks[name]
            if not task.done():
                task.cancel()
        for name in names:
            task = self._tasks[name]
            try:
                await asyncio.wait_for(task, timeout=self._stop_timeout_secs)
            except asyncio.TimeoutError:
                _log.warning(
                    "supervised task did not stop within timeout",
                    extra={"_extra": {
                        "task": name,
                        "timeout_secs": self._stop_timeout_secs,
                    }},
                )
            except (asyncio.CancelledError, Exception):
                # Cancellation is the expected path; swallow.
                pass
            self._states[name].status = "stopped"
