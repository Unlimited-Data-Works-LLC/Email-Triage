"""Regression: the supervised-loop tick-health MODULE GLOBAL is reset
between tests.

2026-06-08 — ``web.task_supervisor._tick_health`` is a module-level dict
that ``supervised_interval_loop`` writes and
``TaskSupervisor.health_snapshot()`` reads (``any(th.is_stale() for th in
_tick_health.values())``). It is NOT per-supervisor state, so the per-test
fresh ``TaskSupervisor()`` does not reset it. A test that started a
supervised loop left a ``TickHealth`` behind; over a long full-suite run
its ``last_tick_ts`` aged past the staleness budget and a LATER test's
``/health/detail`` read ``any_loop_tick_stale=True`` → ``degraded`` →
HTTP 503, breaking every health-surface test that asserts
``status_code == 200`` (test_office365_push / test_openclaw /
test_retry_queue_health).

The fix is the autouse ``_reset_tick_health_registry`` in
``tests/conftest.py``. These two tests run in definition order in the same
file: the first leaves a stale entry; the second asserts the autouse reset
wiped it before the next test. If someone removes the reset, the second
test fails — the leak can't silently return.
"""

from __future__ import annotations

from email_triage.web import task_supervisor as ts
from email_triage.web.task_supervisor import TickHealth


def test_a_leave_a_stale_tick_health_entry():
    ts._tick_health["leaky-loop"] = TickHealth(
        loop_name="leaky-loop", interval_secs=1.0,
        started_ts=0.0, last_tick_ts=0.0,
    )
    # last_tick_ts at the epoch is wildly past any staleness budget.
    assert ts._tick_health["leaky-loop"].is_stale()


def test_b_registry_was_reset_before_this_test():
    assert "leaky-loop" not in ts._tick_health
    assert ts._tick_health == {}
