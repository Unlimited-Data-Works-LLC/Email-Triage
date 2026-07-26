"""N-270 R28 structural pin — TaskSupervisor PD#18 recovery-clear (2026-07-03).

Census R28 discovered MED (#3 TaskSupervisor per-task lifecycle
recovery-clear): the recovery site at `task_supervisor.py:387` flipped
`status='running'` on the restart-after-crash path but DIDN'T clear
`last_crash_ts` / `last_crash_error_type` / `backoff_secs` /
`quarantined_reason`. Consequence: `/health` advertised STALE error
kind + non-zero backoff on tasks that had been `running` for hours.

Same set-broad/clear-narrow class as N-49 (`_mark_recovered` in
watcher.py), N-246 (errors tally), N-257 (record_message_result
success), N-256 (record_gmail_watch_outcome).

N-270 fix: `TaskSupervisor._record_recovery(state)` sibling to
`_record_crash`; the wrapper coro at `_run_supervised` now calls it
when transitioning FROM `"crashed"` state (before setting `status =
"running"`).

WHAT IT PINS (anti-vacuity):

`_record_recovery` exists + textually references all 4 fields it must
clear; `_run_supervised` textually calls it on the
`"crashed" → "running"` transition.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_record_recovery_helper_present():
    """Anti-vacuity: `TaskSupervisor._record_recovery` textually
    clears the 4 crash-state fields census R28 flagged."""
    path = SRC_ROOT / "web" / "task_supervisor.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "def _record_recovery" in source, (
        "N-270 R28: `_record_recovery` sibling helper missing."
    )
    # Body must clear all 4 fields.
    idx = source.find("def _record_recovery")
    end = source.find("def ", idx + 1)
    body = source[idx:end]
    # N-303 R30 (CI-red fix-forward): only 2 current-failure-state
    # fields cleared on recovery. `last_crash_ts` +
    # `last_crash_error_type` are HISTORIC — a recovering task can
    # still be inspected for what crashed last time (the original
    # test contract).
    for field in ("backoff_secs", "quarantined_reason"):
        assert field in body, (
            f"N-270/N-303 R30 REGRESSION: `_record_recovery` no longer "
            f"references `{field}`. Both current-failure-state fields "
            "must clear on recovery per PD#18 lifecycle-flag SSOT."
        )


def test_run_supervised_calls_recovery_on_crashed_transition():
    """`_run_supervised` textually calls `_record_recovery` when
    transitioning from crashed → running. A refactor that drops the
    call re-opens the /health stale-error-kind gap."""
    path = SRC_ROOT / "web" / "task_supervisor.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    # Same-function scope: locate _run_supervised body + assert
    # `_record_recovery` is referenced inside a `state.status ==
    # "crashed"` guarded branch.
    idx = source.find("async def _run_supervised")
    assert idx >= 0
    end = source.find("async def ", idx + 1)
    if end < 0:
        end = source.find("def ", idx + 1)
    body = source[idx:end]
    assert 'state.status == "crashed"' in body, (
        "N-270 R28: _run_supervised no longer checks the "
        "crashed→running transition."
    )
    assert "self._record_recovery(state)" in body, (
        "N-270 R28 REGRESSION: _run_supervised no longer calls "
        "`self._record_recovery(state)` on the crashed→running "
        "transition. /health will re-advertise stale error kind + "
        "non-zero backoff on recovered tasks."
    )
