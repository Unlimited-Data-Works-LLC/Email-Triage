"""N-342 R31 — HIPAA 0→1 cascade nested-BEGIN OperationalError close.

Phase-4 DA finding (2026-07-04, workflow `wf_1dcde854-2ae` bucket
``hipaa_adjacent``): ``set_account_hipaa`` opens the outer transaction
with ``conn.execute('BEGIN')``, then calls ``_hipaa_flip_on_cascade``
which invokes ``update_account_config_keys`` (a ``@db_write`` fn that
unconditionally did ``conn.execute('BEGIN IMMEDIATE')``). SQLite
raises ``sqlite3.OperationalError: cannot start a transaction within
a transaction`` on the nested BEGIN, the outer transaction rolls back,
the HIPAA flip is undone, and the boundary-event row never chains —
the very cascade path the N-262 fix was designed for silently fails.

Pre-existing pin (``test_n262_hipaa_flip_cascade_pin.py``) only
checked import + textual substring — never invoked the flip
end-to-end on a realistic account, so the runtime failure was never
triggered by tests. Per Prime Directive  (test the rendered VIEW,
not just model/DB/auth).

Fix (N-342 R31): ``update_account_config_keys`` now detects an
already-open outer transaction via ``conn.in_transaction`` and
elides its own BEGIN/COMMIT/ROLLBACK when nested.

This pin is a STRUCTURAL AST-shape check on the ``update_account_config_keys``
FunctionDef body: it must reference ``in_transaction`` at least once
AND its ``BEGIN IMMEDIATE`` execute must be guarded by an ``if not
nested`` (or equivalent) branch. Fails LOUD if a future refactor
drops the guard.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, parse_module


TARGET = SRC_ROOT / "db" / "accounts.py"


def _fn(name: str) -> ast.FunctionDef:
    tree = parse_module(TARGET)
    if tree is None:
        pytest.fail(f"parse_module returned None for {TARGET}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    pytest.fail(f"function `{name}` not found in db/accounts.py")


def test_update_account_config_keys_references_in_transaction():
    """N-342 pin: the fn body must reference ``in_transaction`` at
    least once — the marker of the nested-txn detection path. A
    future refactor that drops the guard breaks the HIPAA cascade
    silently; this pin fires loud.
    """
    fn = _fn("update_account_config_keys")
    # Either a direct attribute access (conn.in_transaction) or a
    # string-literal getattr fallback (getattr(conn, "in_transaction", …))
    # counts — both are the marker of the nested-txn detection path.
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Attribute) and sub.attr == "in_transaction":
            return
        if isinstance(sub, ast.Constant) and sub.value == "in_transaction":
            return
    pytest.fail(
        "update_account_config_keys no longer references "
        "``in_transaction`` — the N-342 nested-BEGIN elision guard "
        "is gone. Restore ``nested = bool(getattr(conn, 'in_transaction', "
        "False))`` or the HIPAA 0→1 cascade will raise "
        "``sqlite3.OperationalError: cannot start a transaction within "
        "a transaction`` on accounts with auto_scan_enabled=True or "
        "any calendar carrying the ``api`` role."
    )


def test_begin_immediate_is_guarded():
    """N-342 pin: the ``BEGIN IMMEDIATE`` call MUST be inside an
    ``if not nested:`` (or equivalent Not-guard) branch — a bare
    ``conn.execute('BEGIN IMMEDIATE')`` at fn scope reintroduces
    the nested-BEGIN OperationalError under the cascade.
    """
    fn = _fn("update_account_config_keys")
    for sub in ast.walk(fn):
        if not (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "execute"
            and len(sub.args) >= 1
            and isinstance(sub.args[0], ast.Constant)
            and isinstance(sub.args[0].value, str)
            and sub.args[0].value == "BEGIN IMMEDIATE"
        ):
            continue
        # Walk parents until we hit an If whose test looks like
        # ``not nested`` (UnaryOp Not on Name 'nested') OR the fn
        # boundary. Missing guard = failure.
        parent = getattr(sub, "_ph_parent", None)
        while parent is not None and parent is not fn:
            if isinstance(parent, ast.If):
                test = parent.test
                # ``if not nested:`` shape.
                if (
                    isinstance(test, ast.UnaryOp)
                    and isinstance(test.op, ast.Not)
                    and isinstance(test.operand, ast.Name)
                    and test.operand.id == "nested"
                ):
                    break
            parent = getattr(parent, "_ph_parent", None)
        else:
            pytest.fail(
                "update_account_config_keys' ``conn.execute('BEGIN "
                "IMMEDIATE')`` is not guarded by ``if not nested:``. "
                "N-342 regression — the nested-BEGIN elision was "
                "removed. HIPAA cascade will raise OperationalError."
            )


def test_hipaa_flip_on_cascade_calls_update_config_keys():
    """N-342 anti-vacuity companion: verify the cascade path still
    routes through ``update_account_config_keys`` — otherwise the
    pin above passes vacuously (there's no cascade call left to
    protect).
    """
    fn = _fn("_hipaa_flip_on_cascade")
    for sub in ast.walk(fn):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == "update_account_config_keys"
        ):
            return
    pytest.fail(
        "_hipaa_flip_on_cascade no longer calls "
        "``update_account_config_keys`` — the N-342 pin above is "
        "now vacuous. If the cascade was refactored to a different "
        "SSOT, update this anti-vacuity check to match."
    )
