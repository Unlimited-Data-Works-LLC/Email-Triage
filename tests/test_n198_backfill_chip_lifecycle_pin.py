"""N-198 R21_6 structural pin — backfill-chip set/clear symmetry.

Census run21 R21_6 finding: `mark_backfill_capped` sites SET the chip on
UIDVALIDITY reseed / BACKFILL_CAP hit but 1 of 5 sites (`poll_ingestion.py:790`
IMAP-poll UIDVALIDITY reseed) had NO corresponding `clear_backfill_capped`
on the eventual stable-recovery branch. The chip lied about state on the
fix path: an account that reseeded, was manually processed, and returned
to normal-poll operation stayed marked "cap hit" indefinitely — /health +
digest tooltips misled the operator.

Fix landed 2026-07-02: `poll_ingestion.py` post-successful `poll_once` path
now clears the chip via the SAME `_backfill_chip` funnel that sets it
(mirroring the run-14 failing_since set-broad/clear-narrow fix).

Pin: every source file that CALLS `mark_backfill_capped` MUST also CALL
`clear_backfill_capped` somewhere in the same file (set/clear symmetry —
either both edges route through the funnel or neither).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


def _has_call_to(tree: ast.AST, name: str) -> bool:
    """True if `tree` references `name` as a Call target (Name/Attribute)
    OR as an argument to `db_call(<name>, ...)` (the async off-loop pattern
    the backfill-chip helpers use — `db_call(mark_backfill_capped, db, aid,
    ...)`)."""
    for sub in ast.walk(tree):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        called = f.id if isinstance(f, ast.Name) else (
            f.attr if isinstance(f, ast.Attribute) else None)
        if called == name:
            return True
        # db_call(<name>, ...) — off-loop dispatch seam.
        if called in {"db_call", "db_call_async"} and sub.args:
            arg0 = sub.args[0]
            if isinstance(arg0, ast.Name) and arg0.id == name:
                return True
    return False


def test_backfill_chip_set_clear_file_symmetry():
    """Every source file with a `mark_backfill_capped(...)` call MUST also
    have a `clear_backfill_capped(...)` call — set-broad/clear-narrow is
    the exact set/clear-symmetry violation N-198 R21_6 remediates."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        if _has_call_to(tree, "mark_backfill_capped") and \
                not _has_call_to(tree, "clear_backfill_capped"):
            offenders.append(relpath(path))
    assert not offenders, (
        f"N-198 R21_6: source file(s) call `mark_backfill_capped` but "
        f"NEVER call `clear_backfill_capped`: {offenders}. Set-broad/"
        "clear-narrow — a chip that never clears on the recovery path "
        "lies about state indefinitely. Route the clear edge through the "
        "SAME `web/_backfill_chip` funnel that sets it."
    )


def test_pin_has_teeth():
    bad = ast.parse("""
def h(db, aid):
    await db_call(mark_backfill_capped, db, aid, kind='foo', window='...', recovered=0)
""")
    assert _has_call_to(bad, "mark_backfill_capped")
    assert not _has_call_to(bad, "clear_backfill_capped")

    good = ast.parse("""
def h(db, aid):
    await db_call(mark_backfill_capped, db, aid, kind='foo', window='...', recovered=0)
def h2(db, aid):
    await db_call(clear_backfill_capped, db, aid)
""")
    assert _has_call_to(good, "mark_backfill_capped")
    assert _has_call_to(good, "clear_backfill_capped")
