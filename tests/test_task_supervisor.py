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
