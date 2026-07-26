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

Waivable per file with an EOL `# n201-lifecycle-allowed: <reason>` on
the CLEAR call line.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


SET_FN = "mark_backfill_capped"
CLEAR_FN = "clear_backfill_capped"
_ALLOWED_MARKER = "n201-lifecycle-allowed"


def _find_calls(tree: ast.AST, name: str) -> list[ast.Call]:
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == name:
            hits.append(node)
        elif isinstance(fn, ast.Attribute) and fn.attr == name:
            hits.append(node)
    return hits


def _line_is_waived(source_lines: list[str], lineno: int) -> bool:
    if 1 <= lineno <= len(source_lines):
        return _ALLOWED_MARKER in source_lines[lineno - 1]
    return False


def _enclosing_function(tree: ast.AST, node: ast.AST) -> ast.AST | None:
    """Return the enclosing FunctionDef / AsyncFunctionDef for `node`, or
    None if the node is at module scope."""
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for descendant in ast.walk(func):
            if descendant is node:
                return func
    return None


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


def test_no_same_tick_set_then_clear_wipe():
    """For every source file: every `clear_backfill_capped(...)` call in a
    function that ALSO contains `mark_backfill_capped(...)` MUST be either
    (a) mutually-exclusive with the SET via if/else, (b) guarded by an
    `if <name>:` / `if not <name>:`, (c) waived per line, or (d) the SET
    path terminates before the CLEAR can execute (continue/return/raise/
    break)."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        set_calls = _find_calls(tree, SET_FN)
        clear_calls = _find_calls(tree, CLEAR_FN)
        if not (set_calls and clear_calls):
            continue
        for clear in clear_calls:
            if _line_is_waived(source_lines, clear.lineno):
                continue
            enc_fn = _enclosing_function(tree, clear)
            if enc_fn is None:
                continue
            # SETs in the same function?
            fn_sets = [s for s in set_calls if _enclosing_function(tree, s) is enc_fn]
            if not fn_sets:
                continue  # SET not co-located; no same-tick concern
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
                    f"{relpath(path)}:{clear.lineno} — clear_backfill_capped in "
                    f"function `{getattr(enc_fn, 'name', '<lambda>')}` shares straight-line "
                    f"path with mark_backfill_capped at line(s) "
                    f"{','.join(str(s.lineno) for s in fn_sets)}"
                )
    assert not offenders, (
        "N-201 R22: same-tick SET-then-CLEAR wipe of backfill_capped chip. "
        "Wrap the CLEAR in `if not <guard_set_this_tick>:` or move it into "
        "the `else` of the reseed test so the operator's ONLY §164.502(a)(1) "
        "un-triaged-PHI-in-gap signal is not silently defeated. Waive per "
        f"line with `# {_ALLOWED_MARKER}: <reason>` when both calls in a "
        "function are legit (e.g., testing helper).\n\n" + "\n".join(offenders)
    )
