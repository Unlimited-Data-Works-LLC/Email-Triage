"""N-246 R24 structural pin — WatcherManager errors tally symmetry (2026-07-03).

Census R24 discovered MED (WatcherManager `_mb_state['errors']` monotone):
`_mark_failing` at `web/watcher.py:565` incremented `st['errors']` on every
failing tick, but `_mark_recovered` at :582-585 cleared `failing_since`/
`last_error`/`last_attempt` and NOT `errors`. Consequence: the
`/watch/status` tally at :133 (`errors += int(s.get('errors', 0))`)
accumulated MONOTONICALLY across recoveries. Same set-broad/clear-narrow
shape N-49 fixed for `last_error`.

N-246 fix: `_mark_recovered` also resets `st["errors"] = 0` — both
edges (SET on failure via `_mark_failing`, CLEAR on success via
`_mark_recovered`) now flow through the same funnel.

WHAT IT PINS (anti-vacuity):

Both funnels textually mention `st["errors"]`, one incrementing and the
other clearing. If a refactor breaks the symmetry, the pin fires.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_watcher_errors_tally_is_symmetric():
    """Both `_mark_failing` and `_mark_recovered` must textually touch
    `st['errors']` — SET on the failing side, CLEAR on the recovery."""
    path = SRC_ROOT / "web" / "watcher.py"
    source = path.read_text(encoding="utf-8", errors="replace")

    # Locate _mark_failing + _mark_recovered function bodies (simple
    # textual scan: from `def <name>` to next `def ` at same-or-less
    # indent depth).
    def _fn_body(fn_name: str) -> str:
        idx = source.find(f"def {fn_name}(")
        assert idx >= 0, f"{fn_name} missing"
        # Find next `\n    def ` (method) or `\n\ndef ` (top-level).
        rest = source[idx:]
        end_a = rest.find("\n    def ", 1)
        end_b = rest.find("\n\ndef ", 1)
        end = min(x for x in (end_a, end_b, len(rest)) if x > 0)
        return rest[:end]

    fail_body = _fn_body("_mark_failing")
    recov_body = _fn_body("_mark_recovered")

    # Failing side must textually increment: either `+= 1` or `+ 1`.
    fail_touches_errors = 'st["errors"]' in fail_body
    fail_increments = fail_touches_errors and ("+ 1" in fail_body or "+= 1" in fail_body)
    assert fail_increments, (
        "N-246 R24: `_mark_failing` no longer increments "
        "`st['errors']`. The failing side must still SET (or increment)."
    )
    assert 'st["errors"]' in recov_body, (
        "N-246 R24 REGRESSION: `_mark_recovered` no longer touches "
        "`st['errors']`. The /watch/status tally will re-accumulate "
        "monotonically across recoveries — same set-broad/clear-narrow "
        "shape N-49 fixed for last_error."
    )
    # Must be a CLEAR (assignment to 0), not another increment.
    assert 'st["errors"] = 0' in recov_body, (
        "N-246 R24: `_mark_recovered` touches `st['errors']` but not "
        "as `= 0`. The recovery side must CLEAR the failure count."
    )
