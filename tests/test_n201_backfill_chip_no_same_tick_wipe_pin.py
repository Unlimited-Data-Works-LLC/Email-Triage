"""N-201 R22 structural pin — backfill chip: no same-tick SET-then-CLEAR
straight-line wipe (2026-07-02).

Census run22 R22_2 (HIGH — §164.502(a)(1) un-triaged-PHI-in-the-gap):
`watcher.py` set `mark_backfill_capped` on a UIDVALIDITY renumber then
unconditionally called `clear_backfill_capped` on the same watcher tick
(the post-IDLE-connect CLEAR fired regardless of whether SET fired). The
chip got wiped before the operator could see it — the ONLY signal for
"un-triaged mail in the gap" was silently defeated.

N-201 fix: `watcher.py` gates the CLEAR on a `_backfill_chip_set_this_tick`
flag. This pin banned the RE-INTRODUCTION of a same-tick wipe:

For every function that contains BOTH `mark_backfill_capped(...)` AND
`clear_backfill_capped(...)`:
- Either the two calls are in MUTUALLY EXCLUSIVE branches (one in `if`,
  the other in `else`; one on a code path that ends in `continue`/
  `return`/`raise` before the other could execute); OR
- The CLEAR is INSIDE an `if not <guard_variable>:` where <guard_variable>
  is set adjacent to the SET.

The pin approximates this by requiring: any `clear_backfill_capped(...)`
in a function that ALSO calls `mark_backfill_capped(...)` MUST be inside
one of:
  * an `if`/`elif` block whose test is a Name (guard variable), OR
  * an `else`/`elif else` block of an `if` whose body contains the SET,
    OR
  * the SET happens on a code path that terminates before the CLEAR
    (heuristic: SET is inside a block ending in `continue`/`return`).

Punch 854 (2026-11-04) removed the IDLE-connect clear this pin was born on.
The scan is not watcher-only: it covers every src file. Every src site calls
the mark and the scoped clear through `db_call(f, ...)`, and before punch 854
this pin matched direct calls only, so it saw no co-located pair at all (DA
MUST-2). It now finds the sites with the harness `call_sites` (direct, attribute
and hop call sites of a name) and refuses to pass vacuously: at least one
co-located pair must be checked. Today those
pairs are the two O365 resync sites, whose clear runs after the message loop
under `if walk_covered:` (a Name guard, rule (b)). The per-line waiver marker
had no user in src and was removed with it: there is no waiver.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT, assert_pin_has_teeth, call_sites, iter_files, outermost_enclosing_def, parse_module, relpath,
)


SET_FN = "mark_backfill_capped"
CLEAR_FN = "clear_backfill_capped"


def _guarded_by_if_not_name(tree: ast.AST, call: ast.Call) -> bool:
    """True if `call` is inside an `if <UnaryOp Not (Name)>:` body — the
    "clear only when SET didn't fire" pattern."""
    for parent in ast.walk(tree):
        if not isinstance(parent, ast.If):
            continue
        # Check body contains the call
        for stmt in parent.body:
            if any(descendant is call for descendant in ast.walk(stmt)):
                # test must be `not <Name>` OR just `<Name>` == False; either OK.
                t = parent.test
                if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
                    return True
                if isinstance(t, ast.Name):
                    # `if guard_var:` — the CLEAR should be `if not guard_var:` OR the
                    # SET should be inside an `if guard_var:` for XOR — accept both.
                    return True
    return False


def _in_else_of_set(tree: ast.AST, clear_call: ast.Call, set_call: ast.Call) -> bool:
    """True if `clear_call` is in the `orelse` of an `if` whose `body`
    contains `set_call` (or vice versa — mutually exclusive branches)."""
    for parent in ast.walk(tree):
        if not isinstance(parent, ast.If):
            continue
        body_has_set = any(descendant is set_call for stmt in parent.body for descendant in ast.walk(stmt))
        orelse_has_clear = any(descendant is clear_call for stmt in parent.orelse for descendant in ast.walk(stmt))
        if body_has_set and orelse_has_clear:
            return True
        body_has_clear = any(descendant is clear_call for stmt in parent.body for descendant in ast.walk(stmt))
        orelse_has_set = any(descendant is set_call for stmt in parent.orelse for descendant in ast.walk(stmt))
        if body_has_clear and orelse_has_set:
            return True
    return False


def _set_path_terminates_before_clear(func: ast.AST, set_call: ast.Call,
                                       clear_call: ast.Call) -> bool:
    """Heuristic: True if the block containing SET ends in
    `continue`/`return`/`raise`/`break` — the SET path cannot fall through
    to reach the CLEAR."""
    for block in ast.walk(func):
        if not hasattr(block, "body"):
            continue
        body = getattr(block, "body", None)
        if not isinstance(body, list):
            continue
        set_in_body = False
        for stmt in body:
            for descendant in ast.walk(stmt):
                if descendant is set_call:
                    set_in_body = True
                    break
            if set_in_body:
                break
        if not set_in_body:
            continue
        # Last statement in the SAME block that terminates path?
        for stmt in body[body.index(next(s for s in body if any(d is set_call for d in ast.walk(s)))):]:
            if isinstance(stmt, (ast.Continue, ast.Return, ast.Raise, ast.Break)):
                return True
    return False


def _scan(tree: ast.AST, label: str) -> tuple[list[str], int]:
    """(offenders, co-located pairs checked) for one module."""
    offenders: list[str] = []
    checked = 0
    set_calls = call_sites(tree, SET_FN)
    clear_calls = call_sites(tree, CLEAR_FN)
    if not (set_calls and clear_calls):
        return offenders, checked
    for clear in clear_calls:
        enc_fn = outermost_enclosing_def(clear)
        if enc_fn is None:
            continue
        # SETs in the same function?
        fn_sets = [s for s in set_calls if outermost_enclosing_def(s) is enc_fn]
        if not fn_sets:
            continue  # SET not co-located; no same-tick concern
        checked += 1
        # Check each condition. If ANY passes → safe.
        safe = False
        if _guarded_by_if_not_name(tree, clear):
            safe = True
        if not safe:
            for s in fn_sets:
                if _in_else_of_set(tree, clear, s):
                    safe = True; break
                if _set_path_terminates_before_clear(enc_fn, s, clear):
                    safe = True; break
        if not safe:
            offenders.append(
                f"{label}:{clear.lineno} — clear_backfill_capped in "
                f"function `{getattr(enc_fn, 'name', '<lambda>')}` shares straight-line "
                f"path with mark_backfill_capped at line(s) "
                f"{','.join(str(s.lineno) for s in fn_sets)}"
            )
    return offenders, checked


def test_no_same_tick_set_then_clear_wipe():
    """For every source file: every `clear_backfill_capped(...)` call in a
    function that ALSO contains `mark_backfill_capped(...)` MUST be either
    (a) mutually-exclusive with the SET via if/else, (b) guarded by an
    `if <name>:` / `if not <name>:`, or (c) the SET path terminates before
    the CLEAR can execute (continue/return/raise/break)."""
    offenders: list[str] = []
    checked = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        found, n = _scan(tree, relpath(path))
        offenders += found
        checked += n
    assert checked, (
        "N-201 pin checked no co-located mark/clear pair: it passes vacuously. "
        "The O365 resync sites hold one each; a scan that finds none is blind "
        "(a new dispatcher, or a call shape _find_calls does not resolve)."
    )
    assert not offenders, (
        "N-201 R22: same-tick SET-then-CLEAR wipe of backfill_capped chip. "
        "Wrap the CLEAR in `if not <guard_set_this_tick>:` or move it into "
        "the `else` of the reseed test so the operator's ONLY §164.502(a)(1) "
        "un-triaged-PHI-in-gap signal is not silently defeated.\n\n"
        + "\n".join(offenders)
    )


def test_n201_pin_has_teeth_through_the_db_call_hop():
    """The shape the src sites use: both calls through `db_call`. Unguarded
    it must be flagged; under `if walk_covered:` it must pass."""
    bad = (
        "async def tick(db, account_id, saturated):\n"
        "    if saturated:\n"
        "        await db_call(mark_backfill_capped, db, account_id)\n"
        "    await db_call(clear_backfill_capped, db, account_id)\n"
    )
    good = (
        "async def tick(db, account_id, saturated, walk_covered):\n"
        "    if saturated:\n"
        "        await db_call(mark_backfill_capped, db, account_id)\n"
        "    if walk_covered:\n"
        "        await db_call(clear_backfill_capped, db, account_id)\n"
    )
    assert_pin_has_teeth(lambda tree: _scan(tree, "<planted>")[0], bad, good)
