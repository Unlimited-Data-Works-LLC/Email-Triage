"""N-240 R24 structural pin — triage_jobs requeue counter reset (2026-07-03).

Census R24 discovered HIGH class (triage_jobs requeue reset asymmetry):
`requeue_orphaned_triage_jobs` at `web/db.py:2273` only reset status,
started_at, last_progress_at — but its documented invariant at
`_load_processed_counts` (`db.py:2244`) DECLARED "requeue zeros
total_processed/skipped/errors so the resumed run pre-bumps from the
aggregate before walking new pages." Contradicted its own docstring.
Resume at `triage_runner_bulk.py:996` PRE-BUMPED from the aggregate,
DOUBLE-COUNTING on top of the still-present counters.

N-240 fix: `requeue_orphaned_triage_jobs` now zeros the 5 counters
(`total_processed`/`total_skipped`/`total_errors`/`total_cache_skipped`
/`total_seen`) in the same UPDATE.

N-427 R25 (census run22 D2): tuple widened to 6 = 5 counters + 1
zero-default lifecycle FLAG (`ceiling_hit`, v44). Same requeue funnel,
same PD#18 invariant — a SET-broad/CLEAR-narrow flag on the same row
whose only CLEAR edge is this requeue UPDATE.

WHAT IT PINS (count-agnostic, STRICT):

Any `UPDATE triage_jobs SET status = 'queued'` MUST also zero (or
overwrite) the counter columns AND zero-default lifecycle flag columns
declared in the docstring invariant. The pin scans for the SET-body
of the requeue statement and asserts each column appears with `= 0`
(or equivalent).

SCOPE CAVEAT: regex-scans SQL text; the resume path
(`UPDATE triage_jobs SET status = 'running' WHERE status = 'queued'`)
is a distinct concern (claim, not reset) and correctly does NOT match.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
)


# Match `UPDATE triage_jobs SET <SET-body> WHERE ...`
_UPDATE_TRIAGE_JOBS_RE = re.compile(
    r"UPDATE\s+triage_jobs\s+SET\s+([^;]+?)\s+WHERE\s+([^;]+)",
    re.IGNORECASE | re.DOTALL,
)

# Counters + zero-default lifecycle flags that MUST be zeroed at requeue time
# (per docstring invariant + PD#18 flag-clear-on-success). `ceiling_hit` added
# by N-427 (census run22 D2) — sibling zero-default flag on the same row whose
# SET path (topic_backscan.py:351-352) has no idempotent re-SET on a resumed
# run whose cache-warmed enumeration falls below the ceiling.
_RESET_COUNTERS = (
    "total_processed",
    "total_skipped",
    "total_errors",
    "total_cache_skipped",
    "total_seen",
    "ceiling_hit",
)


def test_requeue_orphaned_triage_jobs_zeros_counters():
    """Every `UPDATE triage_jobs SET status = 'queued'` MUST also zero
    the 5 counter columns + 1 zero-default lifecycle flag column."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        # Collect string constants + adjacent-concatenated constants in
        # `conn.execute(...)` calls.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for arg in node.args:
                if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                    continue
                sql = arg.value
                m = _UPDATE_TRIAGE_JOBS_RE.search(sql)
                if m is None:
                    continue
                set_body = m.group(1).lower()
                # This test only guards the REQUEUE shape:
                # `SET status = 'queued'`. The claim shape
                # `SET status = 'running' WHERE status = 'queued'` is
                # a distinct concern (claim, not reset).
                if not re.search(r"status\s*=\s*'queued'", set_body):
                    continue
                missing = [
                    c for c in _RESET_COUNTERS
                    if not re.search(rf"\b{c}\s*=\s*0\b", set_body)
                ]
                if missing:
                    offenders.append(
                        f"{rel}:{arg.lineno} — requeue missing "
                        f"reset of {missing}"
                    )
    assert not offenders, (
        "N-240 R24 + N-427 R25 triage_jobs requeue reset: `UPDATE "
        "triage_jobs SET status = 'queued'` must zero the docstring-"
        "invariant counters + zero-default lifecycle flags. Otherwise "
        "either (a) the resume path in `triage_runner_bulk.py::"
        "_resume_pre_bump` pre-bumps from the aggregate ON TOP of stale "
        "counters → DOUBLE-COUNT (N-240), OR (b) the `ceiling_hit` "
        "flag SET at `topic_backscan.py:351-352` has no CLEAR edge and "
        "leaves the amber \"narrow the window / re-run\" banner "
        "stuck on a completed row after a cache-warmed resume falls "
        "below the ceiling (N-427). Docstring invariant lives at "
        "`web/db.py::_load_processed_counts` and is now enforced.\n\n"
        + "\n".join(offenders)
    )
