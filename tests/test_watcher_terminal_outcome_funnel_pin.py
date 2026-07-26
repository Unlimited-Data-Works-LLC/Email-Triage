"""the backlog  (Census v3 finding #4) — PD#18 pin.

Structural: every terminal exit in ``_watch_account`` (bare ``return``
OR ``break``, excluding nested ``FunctionDef``/``AsyncFunctionDef``/
``Lambda``) MUST be preceded by a ``record_mailbox_outcome(...)`` call
in the SAME lexical block (or in a wrapping ``try/finally`` that runs
before the exit). This enforces PD#18 SET-must-CLEAR: sibling exits at
:1525 (clean-connect) + :2055 (unsupported) + :2084 (Exception) already
called the funnel; before this pin, the account-not-found return
(:1396), the deactivate-mid-watch return (:1601), and the CancelledError
break (:2034) did not — ``/health watchers_failing_for()`` reported a
permanently-exited watcher as an active-failing watcher until process
restart.

Prime Directive #6: routes through the shared ``_pin_harness`` walker.

db-sme F1 + DA F2 (2026-07-11): known false-positive trap +
migration IOU. A ``try: return   finally: record_mailbox_outcome()``
shape would flag as an offender even though semantically correct —
the pin only checks SIBLINGS in the immediate parent block. If a
future census #4 tail lands the workflow's originally-proposed
try/finally restructure (single funnel call in the enclosing Try's
``finalbody`` covering all inner terminals), extend
``_collect_terminals_with_context`` to accept an enclosing-Try
``finalbody`` funnel call as satisfying the invariant. This narrow-
form pin is the PD#18 down-payment; the walker widening is the
restructure's migration IOU.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


_TARGET_FN = "_watch_account"


def _find_watch_account(tree: ast.Module) -> ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if node.name == _TARGET_FN:
                return node
    return None


def _preceding_stmts_have_funnel(block: list[ast.stmt], up_to_idx: int) -> bool:
    """Return True if any statement in ``block[:up_to_idx]`` contains a
    ``record_mailbox_outcome(...)`` call (bare Name or attribute)."""
    for stmt in block[:up_to_idx]:
        for sub in ast.walk(stmt):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if isinstance(func, ast.Name) and func.id == "record_mailbox_outcome":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "record_mailbox_outcome":
                return True
    return False


def _collect_terminals_with_context(
    node: ast.AST, parent_block: list[ast.stmt] | None,
    parent_idx: int, offenders: list[tuple[int, str]],
) -> None:
    """Walk ``_watch_account`` recursively; for each ``Return`` / ``Break``
    (excluding those inside nested Fn/Lambda), check that a
    ``record_mailbox_outcome`` call appeared earlier in the SAME
    statement block. Excludes exits inside except-handler shapes that
    were ALREADY covered by the pin's design intent (the existing
    :2055 unsupported + :2084 Exception sites call the funnel from
    within their except block).
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        if parent_block is not None:  # don't recurse into nested defs
            return
    if isinstance(node, (ast.Return, ast.Break)):
        if parent_block is not None:
            if not _preceding_stmts_have_funnel(parent_block, parent_idx):
                offenders.append((node.lineno, type(node).__name__))
    # Recurse into statement blocks + set the block context.
    for field, value in ast.iter_fields(node):
        if isinstance(value, list) and value and all(
            isinstance(v, ast.stmt) for v in value
        ):
            for i, stmt in enumerate(value):
                _collect_terminals_with_context(stmt, value, i, offenders)
        elif isinstance(value, ast.AST):
            # Non-statement-block child; pass through with the outer
            # block context (Return in an expression is impossible;
            # Break in a comprehension is caught by the parent's field
            # walk since comprehensions live inside statements).
            _collect_terminals_with_context(value, parent_block, parent_idx, offenders)


def test_every_watch_account_terminal_exit_routes_through_funnel():
    path = SRC_ROOT / "web" / "watcher.py"
    tree = parse_module(path)
    assert isinstance(tree, ast.Module)
    fn = _find_watch_account(tree)
    assert fn is not None, (
        f"{_TARGET_FN} not found in web/watcher.py — refactor renamed "
        "the coroutine. Update this pin's _TARGET_FN AND verify the "
        "new coroutine's terminal exits route through record_mailbox_"
        "outcome."
    )
    offenders: list[tuple[int, str]] = []
    for i, stmt in enumerate(fn.body):
        _collect_terminals_with_context(stmt, fn.body, i, offenders)
    assert not offenders, (
        "Watcher terminal exit(s) bypass record_mailbox_outcome — "
        "``/health watchers_failing_for()`` will report a permanently-"
        "exited watcher as active-failing until process restart "
        "(§164.312(b) audit-controls lifecycle + PD#18 SET-must-"
        "CLEAR):\n" +
        "\n".join(f"  watcher.py:{ln} {kind}" for ln, kind in offenders)
    )
