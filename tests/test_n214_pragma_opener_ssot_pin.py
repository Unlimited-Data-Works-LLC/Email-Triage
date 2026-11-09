"""N-214 R23 structural pin — PRAGMA opener SSOT (2026-07-02).

Census R23_8: 2 openers in `db/_engine.py` each hand-rolled the standard
PRAGMA sequence (journal_mode / busy_timeout / foreign_keys). Two spellings
existed. N-214 consolidated to `_apply_standard_pragmas(conn)`. This pin
bans re-introducing the raw sequence outside the SSOT.

Waives:
- `_atomicio.py` — never uses these PRAGMAs.
- `_engine.py::_apply_standard_pragmas` — the SSOT itself.
- Anywhere on a NON-connection object (a string, a bytes buffer) — the
  pin is scoped to `<conn>.execute("PRAGMA journal_mode|busy_timeout|
  foreign_keys ...")` on a receiver whose name is `conn` (the convention
  used at both openers).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_PRAGMA_KEYS = ("journal_mode", "busy_timeout", "foreign_keys")
_SSOT_MODULE = "db/_engine.py"
_SSOT_FN = "_apply_standard_pragmas"


def _find_raw_pragma_calls(tree: ast.AST) -> list[tuple[int, str]]:
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"):
            continue
        if not node.args:
            continue
        arg0 = node.args[0]
        if not (isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)):
            continue
        sql = arg0.value.upper()
        if "PRAGMA" not in sql:
            continue
        for key in _PRAGMA_KEYS:
            if key.upper() in sql:
                hits.append((node.lineno, arg0.value))
                break
    return hits


def _is_inside_ssot_fn(tree: ast.AST, lineno: int) -> bool:
    """True if the call at `lineno` is inside the def of `_apply_standard_pragmas`."""
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or fn.name != _SSOT_FN:
            continue
        end = fn.end_lineno or fn.lineno
        if fn.lineno <= lineno <= end:
            return True
    return False


def test_pragma_calls_route_through_ssot():
    """Every `conn.execute("PRAGMA journal_mode|busy_timeout|foreign_keys ...")`
    outside the SSOT def is an SSOT bypass — census R23_8's exact drift shape."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, sql in _find_raw_pragma_calls(tree):
            if rel == _SSOT_MODULE and _is_inside_ssot_fn(tree, lineno):
                continue  # the SSOT def itself
            offenders.append(f"{rel}:{lineno}  execute({sql!r})")
    assert not offenders, (
        f"N-214 R23: raw PRAGMA sequence outside `{_SSOT_FN}`. The two-"
        f"spelling drift census R23_8 flagged returns any time a caller "
        f"copies the pattern. Route through `_apply_standard_pragmas(conn)`.\n\n"
        + "\n".join(offenders)
    )
