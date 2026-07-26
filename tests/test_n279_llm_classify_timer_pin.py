"""N-279 R29 structural pin — LLM classify latency timer coverage (2026-07-03).

R29 census MED #4 (LLM classify latency timer): 3 direct `_chat_*`
calls from classify entry-points were NOT wrapped in the
`_metrics.timer("et_llm_classify_seconds", ...)` timer that the main
`classify` entry-point uses at `classify/base.py:643`. Retry paths in
particular silently doubled unmeasured latency.

N-279 wraps the 3 missing sites (`classify_safety_reporting`,
`classify_with_topics` first call, `classify_with_topics` retry) in
the same timer.

WHAT IT PINS (anti-vacuity):

Every direct `await self._chat_*(...)` call inside a classify entry-
point body MUST be inside a `_metrics.timer` `with`-block.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_classify_entrypoints_wrap_chat_in_timer():
    """Every direct `await self._chat_*(...)` call inside a classify
    entry-point body must appear textually within a `_metrics.timer`
    block. This is a heuristic string-scan — the classify body is
    small enough that the timer `with` opens shortly BEFORE the
    `await self._chat_*` line, and each `await self._chat_*` must
    have a preceding `_metrics.timer` inside its enclosing entry-
    point."""
    path = SRC_ROOT / "classify" / "base.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    lines = source.split("\n")

    # Locate the entry-point function boundaries (async def NAME ... :)
    entrypoints = (
        "classify_safety_reporting",
        "classify_with_topics",
    )
    for name in entrypoints:
        anchor = f"async def {name}"
        start = source.find(anchor)
        assert start >= 0, f"entry-point `{name}` missing"
        # Scope: until the next `async def` OR `def ` at column 4 (same class-body indent)
        end_a = source.find("\n    async def ", start + 1)
        end_b = source.find("\n    def ", start + 1)
        end = min(x for x in (end_a, end_b, len(source)) if x > 0)
        body = source[start:end]
        # For each `await self._chat_` in the body, the preceding 8
        # lines must include a `_metrics.timer(` opening.
        body_lines = body.split("\n")
        for i, ln in enumerate(body_lines):
            if "await self._chat_" not in ln:
                continue
            preceding = "\n".join(body_lines[max(0, i - 8):i])
            assert "_metrics.timer" in preceding, (
                f"N-279 R29 REGRESSION: `{name}` has an `await "
                f"self._chat_*` call at ~line {i} without a preceding "
                "`_metrics.timer(...)` context manager. Classify calls "
                "must be observability-wrapped so retry + fallback "
                "paths don't silently double unmeasured latency.\n\n"
                f"line: {ln.strip()}"
            )
