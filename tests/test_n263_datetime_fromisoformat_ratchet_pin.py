"""N-263 R27 structural pin — datetime.fromisoformat SSOT growth-cap (2026-07-03).

Census R27 discovered HIGH #6 (`datetime.fromisoformat` bypass, 15
sites): the SSOT `_isotime.parse_iso` handles the trailing-Z form
(`2026-01-01T00:00:00Z` — Gmail's format) which bare
`datetime.fromisoformat` rejects with ValueError. R27 flagged
`integrations._hours_until` specifically: it parses Gmail watch
`expires_at`, migrations write Z-form via `now_utc_iso_z`, → ValueError
→ returns None → watch treated as no-expiry (regression class the R27
finding warned about).

N-263 fix: migrated `web/routers/integrations.py::_hours_until` to
`parse_iso`. STRICT growth-cap ratchet caps remaining sites at
baseline; per-file follow-up sweeps decrement.

WHAT IT PINS:

Total `datetime.fromisoformat(...)` call sites tree-wide outside
`_isotime.py` must be <= baseline. Note the pin does NOT count
`date.fromisoformat` — that's a distinct API (YMD-only, not
time-bearing) and the `_isotime.parse_iso` SSOT is timestamp-only.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_DATETIME_FROMISOFORMAT = 0  # 2026-07-07 N-263b R31 sweep close-out (3→0). All 3 sites migrated to `_isotime.parse_iso` / `parse_iso_date` SSOTs: baa_expiry.py:99 (parse_iso_date), cli.py:2521 (parse_iso), engine/store.py:371 (parse_iso via raising wrapper). Prior 2026-07-03 N-269d R28 baseline was 8→3.
_SSOT_FILES = {"_isotime.py"}


def _count_datetime_fromisoformat_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not isinstance(f, ast.Attribute):
            continue
        if f.attr != "fromisoformat":
            continue
        # Must be on the `datetime` class specifically — `date.fromisoformat`
        # is a different API (YMD-only, no Z-handling concern).
        recv = f.value
        if isinstance(recv, ast.Name) and recv.id == "datetime":
            n += 1
    return n


def test_datetime_fromisoformat_growth_cap():
    """Total `datetime.fromisoformat(...)` calls outside `_isotime.py`
    must be <= baseline. NEW hand-rolls must route through
    `_isotime.parse_iso` — it handles the trailing-Z form Gmail + other
    external APIs use."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_datetime_fromisoformat_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_DATETIME_FROMISOFORMAT, (
        f"N-263 R27 datetime.fromisoformat ratchet: total count "
        f"{total} > baseline {_MAX_DATETIME_FROMISOFORMAT}. NEW hand-"
        "rolls must route through `email_triage._isotime.parse_iso` "
        "— it handles the trailing-Z form external APIs write (Gmail's "
        "`2026-01-01T00:00:00Z` shape). Bare `datetime.fromisoformat` "
        "raises ValueError on that shape → silent None return where a "
        "watch expiry / audit ts / etc. should be honored.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file)
    )


def test_parse_iso_ssot_reachable():
    """Anti-vacuity: the SSOT must import."""
    from email_triage._isotime import parse_iso
    assert callable(parse_iso)
