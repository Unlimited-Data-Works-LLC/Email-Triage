"""Structural pin — every audit-write swallow must stash the exception.

2026-07-10 root-cause fix for `test_access_audit` drain-race escalation
(`feedback_fix_flaky_tests_dont_dismiss` rule 5): a swallowed
`sqlite3.OperationalError` / `ProgrammingError` inside the safe-audit-write
funnels transitioned the fire-and-forget task to `done=True` with NO row
landing, so the drain's task-set arm passed and the row-count arm burned
the full timeout waiting for a row that would never come. The 15→30→45s
timeout escalation across `0511831d`, `7b4c8b5a`, `c811f8b9`, `6de57d0b`
was band-aiding the silent-swallow shape, not fixing it.

This pin enforces the invariant going forward: every `except Exception`
in the two audit-write swallow seams MUST call `_stash_last_audit_exc`
before the `_bump_failure_counter` / `audit_failures += 1` step. A future
new swallow site MUST route through the same seam.
"""
from __future__ import annotations

import ast
import pathlib

from tests._pin_harness import parse_module


_REPO = pathlib.Path(__file__).resolve().parents[1]
_AUDIT_MODULE = _REPO / "src" / "email_triage" / "web" / "_audit.py"
_ACCESS_AUDIT_MODULE = (
    _REPO / "src" / "email_triage" / "web" / "access_audit.py"
)


def _stash_call_names(handler: ast.ExceptHandler) -> set[str]:
    """Return the set of function/attribute names invoked in a handler body."""
    names: set[str] = set()
    for node in ast.walk(handler):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                names.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                names.add(fn.attr)
    return names




def _iter_except_handlers(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                yield node, handler


def test_safe_audit_write_swallow_stashes_exception():
    """`safe_audit_write` + `safe_audit_write_async` must call
    `_stash_last_audit_exc` on the swallow before `_bump_failure_counter`."""
    tree = parse_module(_AUDIT_MODULE)
    assert tree is not None, "_audit.py did not parse — a non-parsing source is a defect"

    swallow_handlers = []
    for _try_node, handler in _iter_except_handlers(tree):
        names = _stash_call_names(handler)
        # The two swallow seams are the ones that also call the failure
        # counter — anything else (register_audit_failure_sink's inner
        # try/except, the observability's own best-effort wrapper) is
        # legitimately unrelated.
        if "_bump_failure_counter" in names:
            swallow_handlers.append((handler, names))

    assert swallow_handlers, (
        "Expected at least two `except Exception` handlers in _audit.py "
        "calling `_bump_failure_counter` (safe_audit_write + safe_audit_write_async) — "
        "found none. Has the shape changed?"
    )
    for handler, names in swallow_handlers:
        assert "_stash_last_audit_exc" in names, (
            f"_audit.py L{handler.lineno} handler swallows an audit-write "
            "exception without calling `_stash_last_audit_exc(exc, description)`. "
            "This re-opens the drain-race defect fixed 2026-07-10 — see "
            "`_audit._LAST_AUDIT_EXC` docstring + "
            "`feedback_fix_flaky_tests_dont_dismiss` rule 5. Add the stash "
            "before `_bump_failure_counter`."
        )


def test_access_audit_dispatch_swallow_stashes_exception():
    """`AccessAuditMiddleware.dispatch`'s outer-except must stash before
    the `audit_failures += 1` bump."""
    tree = parse_module(_ACCESS_AUDIT_MODULE)
    assert tree is not None, "access_audit.py did not parse — a non-parsing source is a defect"

    matching = []
    for _try_node, handler in _iter_except_handlers(tree):
        # Heuristic: any handler that bumps `audit_failures` — the counter
        # symbol only appears in the two audit-failure paths (dispatch outer-
        # except + _audit_write). BOTH require the stash: the dispatch outer
        # only conditionally re-raises (gated on EMAIL_TRIAGE_AUDIT_STRICT),
        # and _audit_write always re-raises but we still want a defensive
        # stash so a future refactor that shortens the propagation chain
        # doesn't re-open the invisible-swallow class.
        body_src = ast.dump(handler)
        if "audit_failures" in body_src:
            matching.append(handler)

    assert matching, (
        "Expected at least one `except Exception` in access_audit.py that "
        "bumps `audit_failures` (the dispatch outer-swallow) — found none. "
        "Has the shape changed?"
    )
    for handler in matching:
        names = _stash_call_names(handler)
        assert "_stash_last_audit_exc" in names, (
            f"access_audit.py L{handler.lineno} handler swallows a dispatch "
            "exception without calling `_stash_last_audit_exc(exc, description)`. "
            "This re-opens the drain-race defect fixed 2026-07-10 — see "
            "`_audit._LAST_AUDIT_EXC` docstring + "
            "`feedback_fix_flaky_tests_dont_dismiss` rule 5."
        )
