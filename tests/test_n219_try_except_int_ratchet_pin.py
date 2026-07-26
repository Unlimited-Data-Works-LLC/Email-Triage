"""N-219 R23 structural pin — try/except-int growth cap ratchet (2026-07-02).

Census R23 discover-phase (leira_discover.scan_try_int_valueerror) flagged
119 sites tree-wide with the `try: int(X) except (ValueError, TypeError):
...` shape. Two SSOTs exist (`_int_utils.bounded_int` bounded+default,
`web/routers/ui/_shared._safe_int` default-only-UI) but their API is
incomplete for the sentinel-None case (7 sites return None; needs a
`parse_int_or_none` SSOT sibling to migrate).

DA-agent verdict (2026-07-02): "DEFER-blindly FAILS. Ship count-agnostic
pin THIS cycle to CAP growth at 119; sub-class by handler-return shape;
file N-Y for API-widen + migration." Migration is deferred WITH BOUNDS,
not open-ended.

Sub-class distribution at HEAD (from structural walk):
- 58 assign-fallback (`try: x = int(y); except: x = default`) — mechanically
  migratable to `_safe_int(y, default)` when default is a literal int.
- 16 continue (loop-body swallow) — migratable to `bounded_int(y, default=None)`
  guarded with a truthy check.
- 15 pass (silent swallow) — migratable.
- 7 return-None — needs `parse_int_or_none` SSOT (API extension).
- 7 return-expr — case-by-case.
- 5 raise — LEGIT re-raise, keep.
- Other tiny buckets (2-4 sites).

RATCHET SEMANTICS: baseline = 119 at HEAD; decrements per migration commit
(N-178 pattern). Cannot regress upward — a NEW site added fires the pin
immediately.

Waives: `_int_utils.py` (SSOT def), `web/routers/ui/_shared.py` (sibling
SSOT def), tests.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_TRY_EXCEPT_INT = 10  # 2026-07-02 N-219c/47 R23: -1 more (wizard recipient_digest_send_at hour parse)
_SSOT_FILES = {"_int_utils.py", "web/routers/ui/_shared.py"}


def _is_register_decorated(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """N-219c/28 R23 hotfix: applied migrations are IMMUTABLE (incident
    2026-06-11). ANY function decorated with `@register(...)` is a frozen
    migration body — sweeps must EXCLUDE it from counting so we don't
    tempt an editor to migrate a site inside a v-body."""
    for dec in fn.decorator_list:
        # @register(...)
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "register":
            return True
        # @register (rare)
        if isinstance(dec, ast.Name) and dec.id == "register":
            return True
    return False


def _in_register_body(tree: ast.AST, target: ast.AST) -> bool:
    """True if `target` sits inside the body of any @register-decorated fn."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_register_decorated(fn):
            continue
        for sub in ast.walk(fn):
            if sub is target:
                return True
    return False


def _count_sites_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        has_int = any(
            isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
            and sub.func.id == "int"
            for stmt in node.body for sub in ast.walk(stmt)
        )
        if not has_int:
            continue
        # N-219c/28 R23 hotfix: EXCLUDE @register-decorated migration bodies
        # (frozen checksums — editing them breaks the app on the deploy host deploy).
        if _in_register_body(tree, node):
            continue
        for h in node.handlers:
            exc = h.type
            names = []
            if isinstance(exc, ast.Name):
                names = [exc.id]
            elif isinstance(exc, ast.Tuple):
                names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
            if "ValueError" in names or "TypeError" in names:
                n += 1
                break
    return n


def test_try_except_int_growth_cap():
    """Ratchet baseline: 119 at HEAD; decrement per migration commit."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_sites_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_TRY_EXCEPT_INT, (
        f"N-219 R23 ratchet: `try: int(X) except (ValueError, TypeError)` "
        f"count {total} > baseline {_MAX_TRY_EXCEPT_INT}. New hand-rolls "
        "must route through `_int_utils.bounded_int` (bounded+default), "
        "`web/routers/ui/_shared._safe_int` (default-only-UI), or the "
        "planned `parse_int_or_none` SSOT sibling. Sub-class first by "
        "handler return-shape (assign-fallback / continue / pass / "
        "return-None) then migrate mechanically per-shape.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file[:12])
    )
