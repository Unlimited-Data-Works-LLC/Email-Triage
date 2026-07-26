"""N-211c R23 structural pin — backfill_capped source_mailbox required (2026-07-02).

Operator directive: belt-and-suspenders on the N-211 chip lifecycle.
N-211 landed the value-carries-source_mailbox pattern; the operator
approved adding a STRUCTURAL pin that BANS `mark_backfill_capped(...)`
or `clear_backfill_capped(...)` calls that DON'T pass `source_mailbox=`.

Why belt-and-suspenders: even though the storage KEY stays at account
level (per the design review — readers aggregate at account level, per
`WAITING-ON-OP.md` N-211b resolution), a caller that forgets
`source_mailbox=` reintroduces the pre-N-211 unscoped-chip regression
where a sibling mailbox's clear wipes the operator signal.

Waives:
- `web/_backfill_chip.py` — the SSOT def.
- test files — tests exercise the API with the un-scoped shape on purpose.

Pin scope: tree-wide `mark_backfill_capped` / `clear_backfill_capped`
call sites (BOTH via `db_call(fn, ...)` seam and inline) — MUST include
`source_mailbox=` kwarg.

Convergence at HEAD (2026-07-02): 5 mark + 3 clear sites all carry
`source_mailbox=`. STRICT-0 offenders.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_TARGET_FNS = {"mark_backfill_capped", "clear_backfill_capped"}
_SSOT_MODULE = "web/_backfill_chip.py"


def _has_source_mailbox_kwarg(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "source_mailbox":
            return True
    return False


def _find_call_offenders(tree: ast.AST) -> list[tuple[int, str]]:
    """Return `(lineno, fn_name)` for each mark/clear call site that
    does NOT pass source_mailbox= at HEAD."""
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        # Direct call: mark_backfill_capped(...)
        if isinstance(fn, ast.Name) and fn.id in _TARGET_FNS:
            if not _has_source_mailbox_kwarg(node):
                offenders.append((node.lineno, fn.id))
            continue
        # db_call(mark_backfill_capped, db, ..., source_mailbox=...)
        if isinstance(fn, ast.Name) and fn.id == "db_call" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Name) and first.id in _TARGET_FNS:
                if not _has_source_mailbox_kwarg(node):
                    offenders.append((node.lineno, f"db_call({first.id}, ...)"))
    return offenders


def test_backfill_capped_source_mailbox_required():
    """STRICT-0: every mark_backfill_capped / clear_backfill_capped call
    site tree-wide MUST pass source_mailbox= kwarg (via db_call seam OR
    direct call). Pin catches both a direct call and the db_call wrapping.
    Waives the SSOT def."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == _SSOT_MODULE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, fn_name in _find_call_offenders(tree):
            offenders.append(f"{rel}:{lineno}  {fn_name}(...) — missing source_mailbox=")
    assert not offenders, (
        "N-211c R23 STRICT: mark_backfill_capped / clear_backfill_capped "
        "call MUST pass source_mailbox= to preserve the mailbox-scope refuse "
        "invariant. A missing kwarg silently regresses to the pre-N-211 "
        "unscoped-chip class where sibling-mailbox clears wipe the operator "
        "signal.\n\n" + "\n".join(offenders)
    )
