""" — exception-chaining discipline pin.

`except X as e: raise Y(...)` without `from e` sets `__cause__=None`
and severs the traceback chain. Server-side debugging loses the
original exception, degrading incident-response.

This pin bans NEW instances of the shape. All 15 pre-#138 sites were
folded same-drive (2026-07-11) via a mechanical AST rewrite that
appended `from <exc-name>` to each raise's exc Call. Allow-list is
EMPTY at HEAD post-fold.

Prime Directive #6: routes through `_pin_harness.iter_src_files` +
`parse_module` + `relpath`.

Grounding: 2026-07-11 workflow post-#137 broader-hunt discovered
15 sites via `except X as e: raise Y(...)` AST match. llm-host
qwen3.6:35b classified 2 HIGH + 10 MED + 3 FALSE_POSITIVE-ish.
Verify-don't-accept: all HELPER_CALL sites in `agent_api.py`
(where `raise_api_error` returns an HTTPException) DO benefit from
`from e` — FastAPI's traceback logger honors the chain even though
the HTTP response is scrubbed (`raise_api_error.__doc__` at
`web/error_surface.py:38`).
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


def _is_unchained_raise_in_except(node: ast.ExceptHandler) -> list[int]:
    """Return line numbers of every `raise <Call>(...)` inside `node`
    that has no `from` cause. Only handlers with a bound exception name
    (`except X as e:`) are checked — bare `except:` handlers don't
    have a name to chain from."""
    if not node.name:
        return []
    hits: list[int] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Raise):
            continue
        if child.exc is None:
            # bare `raise` — re-raises current exception, chain intact.
            continue
        if child.cause is not None:
            continue
        if not isinstance(child.exc, ast.Call):
            # `raise MyException` (no call) — no chain to preserve
            # (no exception object with __cause__ semantics).
            continue
        hits.append(child.lineno)
    return hits


def test_no_unchained_raise_in_except_handler():
    """`except X as e: raise Y(...)` MUST include `from e` (or
    `from None` for intentional-scrub). All 15 pre-#138 sites were
    mechanically folded 2026-07-11; the allow-list is empty at HEAD."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            hits = _is_unchained_raise_in_except(node)
            if not hits:
                continue
            # enclosing_fn for the ExceptHandler
            fn_name = _enclosing_fn_for(node, tree)
            for ln in hits:
                offenders.append(f"{rel}:{ln} ({fn_name})")
    assert not offenders, (
        "#138 exception-chain: `raise <Exc>(...)` inside `except X "
        "as <name>:` without `from <name>` — server-side traceback "
        "loses `__cause__`. Fix: append ` from <name>` to the raise "
        "(or ` from None` if the chain must be scrubbed intentionally). "
        "There is no allow-list: a legit unchained raise needs one "
        "added here, keyed `(rel, enclosing_fn)`, with a "
        "justification and a VALK registration.\n\n" + "\n".join(offenders)
    )


def _enclosing_fn_for(node: ast.AST, tree: ast.Module) -> str:
    """The nearest enclosing function name for `node`, walking `tree`
    to find `FunctionDef`/`AsyncFunctionDef` bounding lines. Returns
    `<module>` if the node is at module scope (no enclosing fn)."""
    best: str = "<module>"
    best_line: int = -1
    for candidate in ast.walk(tree):
        if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        c_start = candidate.lineno
        c_end = getattr(candidate, "end_lineno", c_start) or c_start
        if c_start <= node.lineno <= c_end and c_start > best_line:
            best = candidate.name
            best_line = c_start
    return best
