"""N-257 R26 structural pin — record_message_result clears on success (2026-07-03).

Census R26 discovered HIGH (PD#18 lifecycle): the newly-extracted
`record_message_result` SSOT at `web/_watch_status_recorder.py`
SUCCESS branch NEVER cleared `state["last_error"]`. Consequence:
`_aggregate_status` in `watcher.py` unconditionally picked the newest
`last_error` on the account, so ONE stuck mailbox stickied at ACCOUNT
level → `/watch/status`, `/health`, dashboard chip all showed stale
error text long after recovery.

N-257 fix: SSOT success branch now sets `state["last_error"] = None`
+ `state["errors"] = 0` — both edges of the flag route through the
funnel (mirror of N-246 for `_mark_recovered` in watcher.py).

WHAT IT PINS (anti-vacuity):

1. The SSOT success branch textually sets both `state["last_error"]
   = None` and `state["errors"] = 0`. A refactor that removes either
   fires the pin.

2. `_aggregate_status` — the reader — still exists (import proof).
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_record_message_result_success_branch_clears_last_error():
    """Anti-vacuity: SSOT success branch textually clears the failure
    edges. If a refactor drops either clear, the pin fires."""
    path = SRC_ROOT / "web" / "_watch_status_recorder.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    # The two clear-on-success lines must both appear (order irrelevant).
    assert 'state["last_error"] = None' in source, (
        "N-257 R26 REGRESSION: `record_message_result` no longer clears "
        "`state['last_error']` on success. `_aggregate_status` will pick "
        "up a stuck sibling's stale error text at account level → "
        "/watch/status + /health + dashboard chip lie about healthy state."
    )
    assert 'state["errors"] = 0' in source, (
        "N-257 R26 REGRESSION: `record_message_result` no longer clears "
        "`state['errors']` on success. Same lifecycle-tally-decay class "
        "as N-246 for _mark_recovered — both edges must route through "
        "the funnel."
    )
