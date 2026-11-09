"""Audit dynamic-table INSERT — count-agnostic structural pin (census run15 ).

The chained audit-event tables (``log_entries`` + the per-event-type tables) are
HMAC-chained (§164.312(b)/(c)(1)). Every row MUST be inserted through the ONE
sanctioned writer ``db/audit.py::_chain_insert`` (which computes the chained
``row_hash`` before the INSERT). That writer builds its statement as an
f-string with an INTERPOLATED table name — ``f"INSERT INTO {table} (...)"`` —
because it serves every chained table. That dynamic-table shape is INVISIBLE to
the literal-SQL audit-emit pins (which key on ``INSERT INTO <literal>``): a
SECOND ``f"INSERT INTO {x}"`` writer added elsewhere in db/audit.py would
silently fork the HMAC chain and slip every existing net.

INVARIANT: within ``db/audit.py``, every f-string of the shape
``INSERT INTO {<interpolated-table>} …`` lives inside ``_chain_insert``. A
dynamic-table audit INSERT in any other function is a defect (route it through
``_chain_insert`` / the ``record_*`` emitter SSOTs, never a raw INSERT — PD#3).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, parse_module

_AUDIT = SRC_ROOT / "db" / "audit.py"
_SANCTIONED_FN = "_chain_insert"
_DYN_INSERT = re.compile(r"^\s*INSERT\s+INTO\s+\{\}", re.IGNORECASE)


def _fstring_skeleton(node: ast.JoinedStr) -> str:
    parts = []
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            parts.append("{}")
    return "".join(parts)


def _dynamic_table_insert_fstrings(tree: ast.AST) -> list[tuple[int, str]]:
    """f-strings of shape ``INSERT INTO {<dynamic-table>} …`` (table name is the
    FIRST interpolation right after INSERT INTO)."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            skel = _fstring_skeleton(node)
            if _DYN_INSERT.match(skel):
                out.append((node.lineno, skel))
    return out


def _enclosing_fn_name(tree: ast.AST, lineno: int) -> str | None:
    best, best_span = None, None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo, hi = n.lineno, getattr(n, "end_lineno", n.lineno)
            if lo <= lineno <= hi:
                span = hi - lo
                if best_span is None or span < best_span:
                    best, best_span = n.name, span
    return best


def test_dynamic_table_audit_insert_only_in_chain_insert():
    tree = parse_module(_AUDIT)
    offenders = []
    for lineno, _skel in _dynamic_table_insert_fstrings(tree):
        fn = _enclosing_fn_name(tree, lineno)
        if fn != _SANCTIONED_FN:
            offenders.append(f"db/audit.py::{fn}:{lineno}")
    assert not offenders, (
        "a dynamic-table `f\"INSERT INTO {table} …\"` lives outside "
        f"{_SANCTIONED_FN} in db/audit.py: {offenders}. The chained audit tables "
        "are HMAC-keyed — every row must be inserted via _chain_insert (which "
        "computes row_hash first), never a second raw dynamic-table INSERT that "
        "forks the chain and evades the literal-SQL emit pins (PD#3; run15 #18)."
    )


def test_ssot_actually_holds_the_dynamic_insert():
    """Anti-vacuity: _chain_insert must still carry exactly the dynamic-table
    INSERT this pin guards (else it is vacuously true)."""
    tree = parse_module(_AUDIT)
    found = _dynamic_table_insert_fstrings(tree)
    assert found, "no dynamic-table INSERT f-string found in db/audit.py at all"
    assert any(
        _enclosing_fn_name(tree, ln) == _SANCTIONED_FN for ln, _ in found
    ), f"{_SANCTIONED_FN} no longer holds the dynamic-table INSERT — pin vacuous"


def test_pin_has_teeth():
    # An f-string INSERT INTO {table} is detected...
    bad = ast.parse('sql = f"INSERT INTO {table} (a) VALUES (?)"\n')
    assert _dynamic_table_insert_fstrings(bad)
    # ...a literal-table INSERT is NOT (it's caught by the literal-SQL pins).
    ok = ast.parse('sql = "INSERT INTO log_entries (a) VALUES (?)"\n')
    assert not _dynamic_table_insert_fstrings(ok)
    # enclosing-fn resolution picks the innermost function.
    src = (
        "def outer():\n"
        "    def _chain_insert(table):\n"
        "        return f'INSERT INTO {table} (a) VALUES (?)'\n"
    )
    t = ast.parse(src)
    ln = _dynamic_table_insert_fstrings(t)[0][0]
    assert _enclosing_fn_name(t, ln) == "_chain_insert"
