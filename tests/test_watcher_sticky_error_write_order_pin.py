"""the backlog  (Census v3 re-run finding #4) — write-order pin.

Structural: within ``_watch_account`` (web/watcher.py), a "sticky reason"
write ``<subscript>["last_error"] = <non-None>`` MUST NOT appear in a
statement block BEFORE a ``record_mailbox_outcome(..., None)`` call
UNLESS a later re-assignment of ``["last_error"]`` follows the funnel
call in the same block.

Why: ``_mark_recovered`` (the ``record_mailbox_outcome(..., None)`` branch)
sets ``st["last_error"] = None`` — PD#18 SET-broad/CLEAR-narrow fix
(:588). A permanent-terminal exit (account gone, provider unsupported)
that writes ``st["last_error"]`` BEFORE the funnel wipes it, leaving
``/watch/status`` reporting ``status="error"`` with an empty
``last_error`` — the sibling comment at :2100 explicitly warns
"Order matters: set it AFTER record_mailbox_outcome zeroed it".

My  fold (Census v3 first-run) landed the bug at :1394-1413 —
this pin's regression teeth.

Prime Directive #6: routes through the shared ``_pin_harness`` walker.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


_TARGET_FN = "_watch_account"
_STICKY_KEY = "last_error"


def _find_watch_account(tree: ast.Module) -> ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if node.name == _TARGET_FN:
                return node
    return None


def _is_last_error_write(stmt: ast.stmt) -> bool:
    """Return True if stmt is ``<something>["last_error"] = <non-None>``."""
    if not isinstance(stmt, ast.Assign):
        return False
    if len(stmt.targets) != 1:
        return False
    tgt = stmt.targets[0]
    if not isinstance(tgt, ast.Subscript):
        return False
    slc = tgt.slice
    if isinstance(slc, ast.Constant) and slc.value == _STICKY_KEY:
        pass
    else:
        return False
    if isinstance(stmt.value, ast.Constant) and stmt.value.value is None:
        return False
    return True


def _is_funnel_clear_call(stmt: ast.stmt) -> bool:
    """Return True if stmt calls ``record_mailbox_outcome(_, _, None)``
    (or ``... _, _, exc=None)``) — the CLEAR-path funnel invocation.
    """
    for sub in ast.walk(stmt):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name != "record_mailbox_outcome":
            continue
        for arg in sub.args:
            if isinstance(arg, ast.Constant) and arg.value is None:
                return True
        for kw in sub.keywords:
            if kw.arg in {"exc", "err", "error"} and isinstance(
                kw.value, ast.Constant
            ) and kw.value.value is None:
                return True
    return False


def _scan_block(
    block: list[ast.stmt], offenders: list[tuple[int, str]],
) -> None:
    for i, stmt in enumerate(block):
        if not _is_funnel_clear_call(stmt):
            continue
        for j in range(i):
            prev = block[j]
            if not _is_last_error_write(prev):
                continue
            reassigned_after = any(
                _is_last_error_write(later) for later in block[i + 1:]
            )
            if not reassigned_after:
                offenders.append((prev.lineno, "last_error-before-funnel-clear"))


def _walk_blocks(
    node: ast.AST, offenders: list[tuple[int, str]], recurse: bool = True,
) -> None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        if not recurse:
            return
    for field, value in ast.iter_fields(node):
        if isinstance(value, list) and value and all(
            isinstance(v, ast.stmt) for v in value
        ):
            _scan_block(value, offenders)
            for stmt in value:
                _walk_blocks(stmt, offenders, recurse=False)
        elif isinstance(value, ast.AST):
            _walk_blocks(value, offenders, recurse=False)


def test_no_sticky_last_error_write_before_funnel_clear():
    path = SRC_ROOT / "web" / "watcher.py"
    tree = parse_module(path)
    assert isinstance(tree, ast.Module)
    fn = _find_watch_account(tree)
    assert fn is not None, (
        f"{_TARGET_FN} not found in web/watcher.py — refactor renamed "
        "the coroutine. Update this pin's _TARGET_FN AND verify the "
        "new coroutine's sticky-reason writes still land AFTER the "
        "record_mailbox_outcome(None) funnel."
    )
    offenders: list[tuple[int, str]] = []
    _walk_blocks(fn, offenders, recurse=True)
    assert not offenders, (
        "Watcher sticky-reason write(s) land BEFORE the "
        "record_mailbox_outcome(None) funnel-clear — the funnel's "
        "_mark_recovered wipes last_error to None, leaving "
        "/watch/status with status=\"error\" and an empty "
        "last_error (PD#18 SET-broad/CLEAR-narrow — sibling comment "
        "at :2100 warns 'Order matters: set it AFTER "
        "record_mailbox_outcome zeroed it'):\n" +
        "\n".join(f"  watcher.py:{ln} {kind}" for ln, kind in offenders)
    )
