"""Tests for ``email_triage.web.task_supervisor.TaskSupervisor``.

Covers:
- Clean exit (coro returns) → status=stopped, no restart.
- Crash → status=crashed → respawned within backoff.
- N crashes in window → status=quarantined → no further restarts.
- Cancellation propagates without recording a crash.
- ``new_request_context`` wraps the body so log lines correlate.
- ``stop_all`` cancels every task within the timeout.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from email_triage.triage_logging import get_request_id
from email_triage.web.task_supervisor import TaskSupervisor


@pytest.mark.asyncio
async def test_clean_return_marks_stopped():
    sup = TaskSupervisor(backoff_initial=0.01, backoff_max=0.05)

    finished = asyncio.Event()

    async def short_lived():
        finished.set()
        return "done"

    sup.supervise("short", short_lived)
    await finished.wait()
    # Give the supervisor's wrapper a chance to register state.
    await asyncio.sleep(0.05)
    state = sup.get_state("short")
    assert state is not None
    assert state.status == "stopped"
    assert state.crashes == 0


@pytest.mark.asyncio
async def test_crash_triggers_respawn_with_backoff():
    sup = TaskSupervisor(
        backoff_initial=0.01,
        backoff_max=0.05,
        quarantine_after_crashes=10,  # high enough we don't quarantine
    )

    attempts = 0
    settled = asyncio.Event()

    async def flaky():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError(f"boom-{attempts}")
        # On the third attempt, succeed.
        settled.set()

    sup.supervise("flaky", flaky)
    await asyncio.wait_for(settled.wait(), timeout=2.0)
    await asyncio.sleep(0.1)  # let supervisor mark stopped
    state = sup.get_state("flaky")
    assert state is not None
    assert attempts == 3
    assert state.crashes == 2
    assert state.last_crash_error_type == "RuntimeError"
    assert state.status == "stopped"


@pytest.mark.asyncio
async def test_quarantine_after_repeated_crashes():
    sup = TaskSupervisor(
        backoff_initial=0.001,
        backoff_max=0.005,
        quarantine_after_crashes=3,
        quarantine_window_secs=60,
    )

    async def perma_broken():
        raise ValueError("always fails")

    sup.supervise("broken", perma_broken)
    # Wait for quarantine to take effect.
    for _ in range(200):
        state = sup.get_state("broken")
        if state and state.status == "quarantined":
            break
        await asyncio.sleep(0.01)
    state = sup.get_state("broken")
    assert state is not None
    assert state.status == "quarantined"
    assert state.crashes >= 3
    assert state.last_crash_error_type == "ValueError"
    assert "ValueError" in (state.quarantined_reason or "")


@pytest.mark.asyncio
async def test_cancellation_does_not_register_as_crash():
    sup = TaskSupervisor(backoff_initial=0.01)

    started = asyncio.Event()

    async def long_running():
        started.set()
        await asyncio.sleep(60)

    task = sup.supervise("long", long_running)
    await started.wait()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    state = sup.get_state("long")
    assert state is not None
    assert state.status == "stopped"
    assert state.crashes == 0
    assert state.last_crash_error_type is None


@pytest.mark.asyncio
async def test_request_id_set_inside_supervised_body():
    """The supervised coro runs inside new_request_context, so
    get_request_id() inside returns the supervisor-set ID."""
    sup = TaskSupervisor(backoff_initial=0.01)
    seen_id: list[str] = []
    done = asyncio.Event()

    async def body():
        seen_id.append(get_request_id())
        done.set()

    sup.supervise("rid", body)
    await asyncio.wait_for(done.wait(), timeout=1.0)
    await asyncio.sleep(0.05)
    assert len(seen_id) == 1
    assert seen_id[0]  # non-empty
    assert len(seen_id[0]) == 12  # uuid4 hex slice
    state = sup.get_state("rid")
    assert state is not None
    assert state.last_request_id == seen_id[0]


@pytest.mark.asyncio
async def test_request_id_changes_per_restart():
    """Each restart of a crashed task gets a fresh request_id, so
    the operator can tell crash N's logs apart from crash N+1's."""
    sup = TaskSupervisor(
        backoff_initial=0.01,
        backoff_max=0.05,
        quarantine_after_crashes=10,
    )
    seen_ids: list[str] = []

    async def flaky():
        seen_ids.append(get_request_id())
        if len(seen_ids) < 3:
            raise RuntimeError("retry")

    sup.supervise("flaky-rid", flaky)
    for _ in range(200):
        if len(seen_ids) >= 3:
            break
        await asyncio.sleep(0.01)
    assert len(seen_ids) == 3
    assert len(set(seen_ids)) == 3  # all distinct


@pytest.mark.asyncio
async def test_no_restart_when_restart_disabled():
    sup = TaskSupervisor(backoff_initial=0.01)

    attempts = 0

    async def flaky():
        nonlocal attempts
        attempts += 1
        raise RuntimeError("boom")

    sup.supervise("once", flaky, restart_on_failure=False)
    await asyncio.sleep(0.1)
    assert attempts == 1
    state = sup.get_state("once")
    assert state is not None
    assert state.status == "crashed"
    assert state.crashes == 1


@pytest.mark.asyncio
async def test_cannot_supervise_running_name():
    sup = TaskSupervisor(backoff_initial=0.01)

    started = asyncio.Event()

    async def long_running():
        started.set()
        await asyncio.sleep(60)

    sup.supervise("dup", long_running)
    await started.wait()
    with pytest.raises(RuntimeError, match="already running"):
        sup.supervise("dup", long_running)
    # Cleanup
    await sup.stop_all()


@pytest.mark.asyncio
async def test_stop_all_cancels_every_task():
    sup = TaskSupervisor(backoff_initial=0.01, stop_timeout_secs=0.5)

    starts = []

    async def task_a():
        starts.append("a")
        await asyncio.sleep(60)

    async def task_b():
        starts.append("b")
        await asyncio.sleep(60)

    sup.supervise("a", task_a)
    sup.supervise("b", task_b)
    # Wait for both to start.
    for _ in range(50):
        if len(starts) == 2:
            break
        await asyncio.sleep(0.01)
    await sup.stop_all()
    a_state = sup.get_state("a")
    b_state = sup.get_state("b")
    assert a_state is not None and a_state.status == "stopped"
    assert b_state is not None and b_state.status == "stopped"


@pytest.mark.asyncio
async def test_stop_all_logs_warning_on_hung_task(caplog):
    """A task that ignores cancel and exceeds stop_timeout should
    log a warning but not block shutdown."""
    sup = TaskSupervisor(backoff_initial=0.01, stop_timeout_secs=0.05)

    started = asyncio.Event()

    async def hung():
        started.set()
        # Catch cancellation and ignore it for a beat — simulates
        # a task that holds onto resources during cancel.
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            await asyncio.sleep(1.0)

    sup.supervise("hung", hung)
    await started.wait()
    with caplog.at_level(
        logging.WARNING, logger="email_triage.web.task_supervisor",
    ):
        await sup.stop_all()
    # Hung task got the warning logged; shutdown still completed.
    found = any(
        "did not stop within timeout" in r.getMessage()
        for r in caplog.records
    )
    assert found


@pytest.mark.asyncio
async def test_health_snapshot_shape():
    sup = TaskSupervisor(
        backoff_initial=0.001,
        quarantine_after_crashes=2,
    )

    async def perma_broken():
        raise ValueError("nope")

    async def short():
        return

    sup.supervise("broken", perma_broken)
    sup.supervise("ok", short)

    # Wait for the broken task to quarantine.
    for _ in range(200):
        s = sup.get_state("broken")
        if s and s.status == "quarantined":
            break
        await asyncio.sleep(0.01)

    snap = sup.health_snapshot()
    assert "tasks" in snap
    assert "broken" in snap["tasks"]
    assert "ok" in snap["tasks"]
    assert snap["any_quarantined"] is True
    assert snap["total_crashes"] >= 2
    #  — the aggregate tick-failure flag is always present.
    assert snap["any_loop_tick_failing"] is False


# ---------------------------------------------------------------------------
#  — supervised_interval_loop tick-failure tracking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_interval_loop_tick_failure_tracked(caplog):
    """A loop whose every tick raises must surface via the tick-health
    registry — it previously stayed silently ``status='running'``."""
    from email_triage.web.task_supervisor import (
        DEFAULT_TICK_FAILURE_THRESHOLD,
        get_tick_health,
        supervised_interval_loop,
        _tick_health,
    )

    loop_name = "test-perma-failing-loop"
    _tick_health.pop(loop_name, None)

    async def always_fails() -> None:
        raise RuntimeError("tick boom")

    task = asyncio.create_task(
        supervised_interval_loop(
            loop_name, 0.01, always_fails, warmup_secs=0,
        )
    )
    try:
        # Wait until the loop has crossed the failure threshold.
        for _ in range(500):
            th = get_tick_health(loop_name)
            if th is not None and th.failing:
                break
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    th = get_tick_health(loop_name)
    assert th is not None
    assert th.failing is True
    assert th.last_tick_ok is False
    assert th.consecutive_failures >= DEFAULT_TICK_FAILURE_THRESHOLD
    assert th.last_tick_error_type == "RuntimeError"
    assert th.total_tick_failures >= DEFAULT_TICK_FAILURE_THRESHOLD
    _tick_health.pop(loop_name, None)


@pytest.mark.asyncio
async def test_interval_loop_single_failure_does_not_flap():
    """One transient tick failure followed by a clean tick must NOT
    mark the loop failing — the signal only trips on a sustained run."""
    from email_triage.web.task_supervisor import (
        get_tick_health,
        supervised_interval_loop,
        _tick_health,
    )

    loop_name = "test-flaky-loop"
    _tick_health.pop(loop_name, None)

    calls = {"n": 0}

    async def fails_once_then_ok() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("one-off")
        # All later ticks succeed.

    task = asyncio.create_task(
        supervised_interval_loop(
            loop_name, 0.01, fails_once_then_ok, warmup_secs=0,
        )
    )
    try:
        # Let several ticks run — first fails, the rest succeed.
        for _ in range(500):
            if calls["n"] >= 4:
                break
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    th = get_tick_health(loop_name)
    assert th is not None
    # A clean tick cleared the single-failure streak.
    assert th.failing is False
    assert th.consecutive_failures == 0
    assert th.last_tick_ok is True
    # The historical total still records the one failure.
    assert th.total_tick_failures == 1
    _tick_health.pop(loop_name, None)


@pytest.mark.asyncio
async def test_health_snapshot_surfaces_tick_failing_loop():
    """A supervised task that is also a failing interval loop shows up
    in ``health_snapshot()`` with ``any_loop_tick_failing`` True and a
    ``tick_health`` sub-dict on its task record."""
    from email_triage.web.task_supervisor import (
        supervised_interval_loop,
        _tick_health,
    )

    loop_name = "snapshot-failing-loop"
    _tick_health.pop(loop_name, None)
    sup = TaskSupervisor(backoff_initial=0.01)

    async def always_fails() -> None:
        raise RuntimeError("snapshot boom")

    sup.supervise(
        loop_name,
        lambda: supervised_interval_loop(
            loop_name, 0.01, always_fails, warmup_secs=0,
        ),
    )
    try:
        for _ in range(500):
            snap = sup.health_snapshot()
            if snap["any_loop_tick_failing"]:
                break
            await asyncio.sleep(0.01)
    finally:
        await sup.stop_all()

    snap = sup.health_snapshot()
    assert snap["any_loop_tick_failing"] is True
    rec = snap["tasks"][loop_name]
    assert "tick_health" in rec
    assert rec["tick_health"]["failing"] is True
    assert rec["tick_health"]["last_tick_ok"] is False
    _tick_health.pop(loop_name, None)


# ---------------------------------------------------------------------------
#  — supervised_interval_loop hung-tick staleness signal
#
# A tick that fails RAISES, so ``record_tick_result`` runs and the
# failure counter moves (covered above). A tick that HANGS does
# neither — it never returns, never raises, never records a result.
# ``last_tick_ts`` freezes and ``failing`` stays False: the loop reads
# healthy while wedged. ``TickHealth.is_stale`` is the signal that
# catches it — no result recorded within a generous multiple of the
# interval.
# ---------------------------------------------------------------------------


def test_tick_health_is_stale_when_no_tick_within_budget():
    """A loop whose last tick is older than ``multiple × interval``
    reads stale; one within budget does not. ``now`` is injected so
    the check is deterministic — no wall-clock sleeps."""
    from email_triage.web.task_supervisor import (
        DEFAULT_TICK_STALENESS_MULTIPLE,
        TickHealth,
    )

    th = TickHealth(loop_name="staleness-unit", interval_secs=60.0)
    # Budget = 60 * DEFAULT_TICK_STALENESS_MULTIPLE (floored at 120s).
    budget = th.staleness_budget_secs()
    assert budget == 60.0 * DEFAULT_TICK_STALENESS_MULTIPLE

    th.last_tick_ts = 1000.0
    # Just inside the budget — healthy.
    assert th.is_stale(now=1000.0 + budget - 1) is False
    # Past the budget — a tick has not landed in too long; stale.
    assert th.is_stale(now=1000.0 + budget + 1) is True


def test_tick_health_staleness_floor_protects_short_intervals():
    """A very short interval must not be flagged stale for a single
    slightly-long tick — the floor is the lower bound on the budget."""
    from email_triage.web.task_supervisor import (
        TICK_STALENESS_FLOOR_SECS,
        TickHealth,
    )

    # interval * multiple would be tiny; the floor wins.
    th = TickHealth(loop_name="short-interval", interval_secs=1.0)
    assert th.staleness_budget_secs() == TICK_STALENESS_FLOOR_SECS

    th.last_tick_ts = 5000.0
    # A tick 30s ago is well inside the 120s floor — not stale.
    assert th.is_stale(now=5030.0) is False
    # Past the floor — stale.
    assert th.is_stale(now=5000.0 + TICK_STALENESS_FLOOR_SECS + 1) is True


def test_tick_health_unknown_interval_is_never_stale():
    """With no interval recorded the staleness budget is unknown — the
    loop is not flagged (failure-safe: do not invent a degradation)."""
    from email_triage.web.task_supervisor import TickHealth

    th = TickHealth(loop_name="no-interval")
    assert th.staleness_budget_secs() is None
    th.last_tick_ts = 0.0  # ancient
    assert th.is_stale(now=1e9) is False


def test_tick_health_staleness_clock_starts_at_loop_start():
    """Before the first tick lands, ``started_ts`` is the staleness
    reference — a loop that warms up but never ticks must still be
    detectable as stale."""
    from email_triage.web.task_supervisor import (
        TickHealth,
        mark_loop_started,
        _tick_health,
    )

    loop_name = "never-ticks"
    _tick_health.pop(loop_name, None)
    th = mark_loop_started(loop_name, interval_secs=60.0)
    assert th.last_tick_ts is None
    assert th.started_ts is not None
    budget = th.staleness_budget_secs()
    # No tick ever — measured from started_ts.
    assert th.is_stale(now=th.started_ts + budget - 1) is False
    assert th.is_stale(now=th.started_ts + budget + 1) is True
    _tick_health.pop(loop_name, None)


@pytest.mark.asyncio
async def test_interval_loop_registers_interval_for_staleness():
    """``supervised_interval_loop`` records its interval at start so the
    staleness budget exists before — and independent of — any tick."""
    from email_triage.web.task_supervisor import (
        get_tick_health,
        supervised_interval_loop,
        _tick_health,
    )

    loop_name = "interval-registered-loop"
    _tick_health.pop(loop_name, None)

    async def quick_tick() -> None:
        pass

    task = asyncio.create_task(
        supervised_interval_loop(
            loop_name, 30.0, quick_tick, warmup_secs=0,
        )
    )
    try:
        for _ in range(500):
            th = get_tick_health(loop_name)
            if th is not None and th.total_ticks >= 1:
                break
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    th = get_tick_health(loop_name)
    assert th is not None
    # The loop reported its interval — staleness can be judged.
    assert th.interval_secs == 30.0
    assert th.staleness_budget_secs() is not None
    # A loop that just ticked is not stale.
    assert th.is_stale() is False
    _tick_health.pop(loop_name, None)


@pytest.mark.asyncio
async def test_health_snapshot_surfaces_stale_loop():
    """``health_snapshot()`` sets ``any_loop_tick_stale`` when a loop's
    last tick is older than its staleness budget — the hung-tick
    signal /health folds into ``degraded``."""
    from email_triage.web.task_supervisor import (
        record_tick_result,
        _tick_health,
    )

    loop_name = "snapshot-stale-loop"
    _tick_health.pop(loop_name, None)
    sup = TaskSupervisor()
    # Register a supervised task record so the snapshot has the row.
    sup._states[loop_name] = sup._states.get(loop_name) or _make_state(
        loop_name,
    )

    # Record one tick, then back-date it well past the budget to
    # simulate a tick that hung and never recorded another result.
    th = record_tick_result(loop_name, ok=True, interval_secs=60.0)
    budget = th.staleness_budget_secs()
    th.last_tick_ts = th.last_tick_ts - budget - 10.0

    snap = sup.health_snapshot()
    assert snap["any_loop_tick_stale"] is True
    rec = snap["tasks"][loop_name]
    assert rec["tick_health"]["stale"] is True
    # A stale loop is NOT necessarily "failing" — the counters are
    # orthogonal signals (a hung tick never increments failures).
    assert rec["tick_health"]["failing"] is False
    _tick_health.pop(loop_name, None)


def _make_state(name: str):
    """Build a bare TaskState so a snapshot has a task row to merge
    tick-health onto (the supervisor normally creates this in
    ``supervise``)."""
    from email_triage.web.task_supervisor import TaskState
    return TaskState(name=name, status="running")
