"""N-185 R20_17 structural pin — LLM circuit-breaker MUST clear on success.

Census run20 R20_17: `translate_unreachable` context manager marks the backend
unhealthy on connect-class errors but NEVER clears on success. TTL-only
recovery (~300s) extended the drainer stale window during transient outages.
`clear_unhealthy` existed but was never called by the production code path
— only by `_reset_for_test`.

Fix landed 2026-07-01 in `llm_health.py::translate_unreachable`: on the
non-unreachable-exception path AND on the successful-yield path, invoke
`clear_unhealthy(backend_name)`.

Pin: verify the `translate_unreachable` body contains `clear_unhealthy(...)`
calls in BOTH the else-of-except path AND the general no-exception path.
Refactoring the body to remove either clear-on-success arm fails red.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


def _find_fn(tree: ast.AST, name: str):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _clear_unhealthy_calls_in_scope(node: ast.AST) -> int:
    """Count `clear_unhealthy(...)` calls anywhere under `node`."""
    n = 0
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                and sub.func.id == "clear_unhealthy":
            n += 1
    return n


def test_translate_unreachable_clears_on_success():
    """`translate_unreachable` context manager MUST call clear_unhealthy on
    the success paths (both no-exception AND non-unreachable-exception).
    N-185: TTL-only recovery is a stale-drainer-window regression."""
    tree = parse_module(SRC_ROOT / "llm_health.py")
    assert tree is not None
    fn = _find_fn(tree, "translate_unreachable")
    assert fn is not None, "translate_unreachable() vanished"
    # A conservative check: at least 2 clear_unhealthy calls in the body —
    # one for the non-unreachable-except path, one for the else-of-try
    # (successful yield). Refactoring either off = red.
    n = _clear_unhealthy_calls_in_scope(fn)
    assert n >= 2, (
        f"N-185 R20_17: translate_unreachable body has only {n} "
        "`clear_unhealthy(...)` call(s); MUST have at least 2 — one on the "
        "non-unreachable-exception recovery path and one on the successful "
        "yield's else clause. A single clear leaves one of the recovery "
        "arms as TTL-only (drainer stale window)."
    )


def test_pin_has_teeth():
    """Planted bad shape (missing clear_unhealthy in body) must fire."""
    bad = ast.parse("""
def translate_unreachable(backend_name):
    try:
        yield
    except Exception as e:
        raise
""")
    fn = _find_fn(bad, "translate_unreachable")
    assert fn is not None
    assert _clear_unhealthy_calls_in_scope(fn) < 2

    good = ast.parse("""
def translate_unreachable(backend_name):
    try:
        yield
    except Exception as e:
        clear_unhealthy(backend_name)
        raise
    else:
        clear_unhealthy(backend_name)
""")
    fn = _find_fn(good, "translate_unreachable")
    assert fn is not None
    assert _clear_unhealthy_calls_in_scope(fn) >= 2
