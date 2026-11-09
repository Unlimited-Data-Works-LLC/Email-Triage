"""N-218 R23 structural pin — config-persist async-body seam (2026-07-02).

Census R23_6 flagged config-persist as a class: 34 direct `set_setting()`
calls across the tree; question was whether any of them sit in an ASYNC
web handler body without going through `db_call(_inner_sync_fn, ...)` —
which would be a threadpool-boundary defect (running SQLite writes on
the event loop thread).

DA-agent verdict (2026-07-02, per `feedback_you_have_the_con_protocol`
sub-sub-sharpening) said: build the precision detector NOW, don't defer
to run24; ship pin in the same session.

STRUCTURAL DETECTOR: for each `set_setting(...)` call site, walk UP the
AST to the innermost enclosing FunctionDef/AsyncFunctionDef. Classify:
- Case A (LEGIT wrapped): innermost is a sync `def _fn():` AND the
  enclosing outermost AsyncFunctionDef has `db_call(<_fn>, ...)`
  somewhere in its body. Callers pass the sync closure to the
  threadpool — canonical wrapping.
- Case B (SEAM MISS): innermost is an AsyncFunctionDef → direct
  async-body call to `set_setting()` runs SQLite write on the event
  loop thread. Ban.
- Case C (LEGIT sync-context): innermost is a sync FunctionDef with no
  enclosing async — synchronous batch job / CLI / test fixture. Fine.

Waives: `web/settings.py` + `web/db.py` (SSOT def sites) + `tests/`.

Convergence status at HEAD (2026-07-02 landing): 0 SEAM MISSES / 28
LEGIT sites. The pin is STRICT: any future add of an async-body direct
call FIRES.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, annotate_parents, enclosing_scope_chain, iter_files, parse_module, relpath


def _enclosing_defs(tree: ast.AST, node: ast.AST):
    annotate_parents(tree)
    for scope in enclosing_scope_chain(tree, node.lineno):
        if scope is not tree:
            yield scope


def _find_db_call_of(tree: ast.AST, target_fn_name: str) -> bool:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "db_call" and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == target_fn_name):
            continue
        return True
    return False


def _scan_seam_misses() -> list[str]:
    """Return `path:line in <async_fn_name>` for every set_setting call that
    sits directly in an async fn body (not wrapped in a sync inner-fn passed
    to db_call). Zero at HEAD."""
    _SSOT_FILES = {"web/db.py"}
    misses: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "set_setting"):
                continue
            enclosers = list(_enclosing_defs(tree, node))
            if not enclosers:
                continue
            innermost = enclosers[0]
            outermost_async: ast.AsyncFunctionDef | None = None
            for f in enclosers:
                if isinstance(f, ast.AsyncFunctionDef):
                    outermost_async = f
                    break
            # Case A — sync inner-fn passed to db_call at the outer async.
            if isinstance(innermost, ast.FunctionDef) and outermost_async:
                if _find_db_call_of(outermost_async, innermost.name):
                    continue
            # Case B — direct async-body call: SEAM MISS.
            if isinstance(innermost, ast.AsyncFunctionDef):
                misses.append(f"{rel}:{node.lineno} in async def {innermost.name}")
                continue
            # Case C — sync context, legit.
    return misses


def test_no_async_body_direct_set_setting():
    """DA-verdict STRICT baseline (2026-07-02): 0 async-body direct
    set_setting call sites tree-wide. Any regression fires."""
    misses = _scan_seam_misses()
    assert not misses, (
        "N-218 R23 SEAM MISS: `set_setting()` called directly in an async "
        "function body — this runs a SQLite write on the event loop thread. "
        "Wrap in a sync inner `def _fn(): ... set_setting(...);` and pass to "
        "`await db_call(_fn, ...)` (the canonical pattern at "
        "`web/routers/agent_api.py:507-518`).\n\n" + "\n".join(misses)
    )
