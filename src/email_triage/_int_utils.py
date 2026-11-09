"""Numeric coercion SSOTs (N-195 R20_19).

The pre-N-195 tree had TWO byte-identical `_coerce_int(value, *, default, lo, hi)`
copies (`actions/hipaa_style_distill.py:399` + `actions/style_profile.py:174`).
Consolidated here + re-exported so callers import the single implementation
and a future validation edit (e.g. rejecting NaN, or logging out-of-range
values as a metric) lives in ONE place.

`_safe_int` in `web/routers/ui/_shared.py` is a sibling (default-only, no
lo/hi bounds) — deliberately not merged; different UX contract (UI drops
invalid to 0, not to a caller-chosen default with clamp). If a future site
needs both semantics, factor `_int_utils.safe_int()` here + delegate.
"""
from __future__ import annotations

from typing import Any


def bounded_int(
    value: Any,
    *,
    default: int,
    lo: int | None = None,
    hi: int | None = None,
) -> int:
    """Coerce `value` to int, clamped to [lo, hi] when set. Returns `default`
    on any TypeError/ValueError (unparseable). Used across actions/ for
    knob-parsing where a bounded numeric range applies."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if lo is not None and n < lo:
        return lo
    if hi is not None and n > hi:
        return hi
    return n


def parse_int_or_none(value: Any) -> int | None:
    """N-219 R23 (2026-07-02): sentinel-None SSOT sibling of `bounded_int`.

    Coerce `value` to int; return None on any TypeError/ValueError
    (unparseable). Used at call sites that need the "int if parseable, else
    None" semantic — the shape `_int_utils.bounded_int` cannot express
    (bounded_int returns a caller-chosen default int, never None).

    Census R23 discover-phase found 7 sites tree-wide with the shape
    `try: n = int(x) except (TypeError, ValueError): return None` — those
    migrate to `return parse_int_or_none(x)` mechanically.

    Semantics are strict: an empty string, whitespace, decimal string, or
    None all return None. A bool coerces to its int (True→1, False→0)
    matching stdlib `int()` semantics."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
