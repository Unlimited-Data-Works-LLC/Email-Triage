"""-b preventative pin — no hardcoded ``timeout=`` literal on
``sqlite3.connect()`` / ``sqlcipher3.dbapi2.connect()`` calls.

Enforces the config-item SSOT (``PersistenceConfig.sqlite_busy_wait_secs``
+ ``sqlite_probe_timeout_secs`` → module-level constants in
``email_triage.db._engine``): every call site MUST pass the timeout as
a name / attribute / call expression, NOT a float / int literal. This
closes the drift-back-to-hardcoded regression the operator flagged
2026-07-11 ("hardcoding timeouts? thats not good").

Count-agnostic (PD#1): the assertion is a property over EVERY site
(``ast.walk`` over every ``.py`` under ``src/email_triage``), not
``len(sites) == N``.

Allow-list is DELIBERATELY SMALL:
* The SSOT declaration site itself (``db/_engine.py`` module-level
  constants + accessors — the ONE place a literal is legitimate).
* No other exceptions today; new exceptions require a documented
  reason in this file.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath


# The single legitimate home of literal timeout defaults: the
# module SSOT constants live here (any other float/int literal in a
# sqlite3.connect timeout= kwarg is a drift-back).
_SSOT_DECL_FILES = frozenset({
    "db/_engine.py",
})


def _is_sqlite_connect_call(node: ast.Call) -> bool:
    """True if ``node`` is ``sqlite3.connect(...)`` or
    ``sqlcipher3.dbapi2.connect(...)`` — the two connect entry points
    the config-item SSOT covers."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr != "connect":
        return False
    # sqlite3.connect(...)
    if isinstance(func.value, ast.Name) and func.value.id == "sqlite3":
        return True
    # sqlcipher3.dbapi2.connect(...)
    if isinstance(func.value, ast.Attribute) and func.value.attr == "dbapi2":
        inner = func.value.value
        if isinstance(inner, ast.Name) and inner.id == "sqlcipher3":
            return True
    return False


def _timeout_kwarg(node: ast.Call) -> ast.expr | None:
    for kw in node.keywords:
        if kw.arg == "timeout":
            return kw.value
    return None


def test_no_hardcoded_sqlite_timeout_literal():
    """A ``sqlite3.connect(..., timeout=<literal>)`` outside the SSOT
    declaration file is a drift-back to the pre-#149-b hardcoded
    behavior. Every non-SSOT call site must pass the value as a name
    (``_SQLITE_BUSY_WAIT_SECS``), attribute, or accessor call
    (``get_sqlite_busy_wait_secs()``).
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel in _SSOT_DECL_FILES:
            continue
        try:
            tree = parse_module(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_sqlite_connect_call(node):
                continue
            arg = _timeout_kwarg(node)
            if arg is None:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float)):
                offenders.append(f"{rel}:{node.lineno}  timeout={arg.value!r}")
    assert offenders == [], (
        "sqlite3.connect / sqlcipher3.dbapi2.connect called with a "
        "HARDCODED float/int ``timeout=`` literal. Route through the "
        "config-item SSOT (`PersistenceConfig.sqlite_busy_wait_secs` "
        "or `sqlite_probe_timeout_secs`) — read the module constant "
        "via `email_triage.db._engine.get_sqlite_busy_wait_secs()` "
        "(or `_probe_timeout_secs()`). See #149-b (2026-07-11) for "
        "the regression rationale.\n\n"
        + "\n".join(offenders)
    )
