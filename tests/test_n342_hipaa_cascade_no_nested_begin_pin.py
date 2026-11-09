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


# ---------------------------------------------------------------------------
# Punch 696: the N-342 rule, count-agnostic. Any src function that reads a
# caller-held transaction into a flag (``nested = ...in_transaction...``) leaves
# that transaction to the caller on EVERY edge: each of its own ``.commit()`` /
# ``.rollback()`` / ``execute("BEGIN|COMMIT|ROLLBACK ...")`` sits in the body of an
# ``if not <flag>:``. ``record_user_update`` guarded only its BEGIN and its
# not-found rollback, so its success commit and its except rollback ended a
# caller's transaction. SCOPE: a flag read through a helper, or a commit made by
# a called helper, is not seen. Plain and annotated assignments bind a flag; a
# walrus or tuple-unpack binding, ``with conn:`` and ``executescript`` are not
# read yet (panel AA SHOULD-A1 residual, filed by the lead).
# ---------------------------------------------------------------------------

import re  # noqa: E402

from _pin_harness import iter_src_files, parse_source, relpath  # noqa: E402

_TXN_SQL = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK|END)\b", re.I)


def _nested_flags(fn: ast.AST) -> set[str]:
    # A plain ``nested = ...`` and an annotated ``nested: bool = ...`` (panel AA
    # SHOULD-A1) both bind the flag.
    def targets(n):
        if isinstance(n, ast.Assign):
            return n.targets
        if isinstance(n, ast.AnnAssign) and n.value is not None:
            return [n.target]
        return []
    return {t.id for n in ast.walk(fn) for t in targets(n)
            if isinstance(t, ast.Name)
            and any(isinstance(s, ast.Constant) and s.value == "in_transaction"
                    or isinstance(s, ast.Attribute) and s.attr == "in_transaction"
                    for s in ast.walk(n.value))}


def _is_txn_control(call: ast.AST) -> bool:
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
        return False
    if call.func.attr in ("commit", "rollback"):
        return True
    return (call.func.attr == "execute" and call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and bool(_TXN_SQL.match(call.args[0].value)))


def _under_not_flag(node: ast.AST, fn: ast.AST, flags: set[str]) -> bool:
    child, parent = node, getattr(node, "_ph_parent", None)
    while parent is not None and parent is not fn:
        if (isinstance(parent, ast.If) and child in parent.body
                and isinstance(parent.test, ast.UnaryOp)
                and isinstance(parent.test.op, ast.Not)
                and isinstance(parent.test.operand, ast.Name)
                and parent.test.operand.id in flags):
            return True
        child, parent = parent, getattr(parent, "_ph_parent", None)
    return False


def _unguarded_txn_controls(modules) -> list[str]:
    out = []
    for rel, tree in modules:
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            flags = _nested_flags(fn)
            if not flags:
                continue
            out.extend(f"{rel}:{n.lineno} {fn.name}" for n in ast.walk(fn)
                       if _is_txn_control(n) and not _under_not_flag(n, fn, flags))
    return sorted(out)


def _src_modules():
    return [(relpath(p), t) for p in iter_src_files() for t in [parse_module(p)] if t]


def test_a_caller_held_transaction_is_never_ended_by_a_nested_funnel():
    modules = _src_modules()
    guarded = {fn.name for _rel, tree in modules for fn in ast.walk(tree)
               if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and _nested_flags(fn)}
    # Anti-vacuity: the two known nested-aware funnels are in the scanned set.
    assert {"update_account_config_keys", "record_user_update"} <= guarded, guarded
    offenders = _unguarded_txn_controls(modules)
    assert not offenders, (
        "A function that detects a caller-held transaction still commits / rolls "
        f"back / BEGINs it unguarded: {offenders}. Put each one under "
        "``if not nested:`` (N-342, punch 696): the caller owns its transaction.")


def test_the_nested_guard_pin_has_teeth():
    def run(src):
        return _unguarded_txn_controls([("m.py", parse_source(src))])

    bad = ("def f(conn):\n"
           "    nested = bool(getattr(conn, 'in_transaction', False))\n"
           "    if not nested:\n"
           "        conn.execute('BEGIN IMMEDIATE')\n"
           "    try:\n"
           "        conn.execute('UPDATE t SET x = 1')\n"
           "        conn.commit()\n"
           "    except Exception:\n"
           "        conn.rollback()\n"
           "        raise\n")
    assert run(bad) == ["m.py:7 f", "m.py:9 f"]
    good = bad.replace("        conn.commit()\n", "        if not nested:\n            conn.commit()\n") \
              .replace("        conn.rollback()\n", "        if not nested:\n            conn.rollback()\n")
    assert good != bad and run(good) == []
    # The ELSE branch of the guard is not guarded; nor is an unrelated flag.
    assert run(good.replace("    if not nested:\n        conn.execute('BEGIN IMMEDIATE')\n",
                            "    if not nested:\n        pass\n    else:\n"
                            "        conn.execute('BEGIN IMMEDIATE')\n")) == ["m.py:6 f"]
    assert run(bad.replace("in_transaction", "isolation_level")) == []
    assert run("def g(conn):\n    nested = conn.in_transaction\n"
               "    conn.execute('ROLLBACK')\n") == ["m.py:3 g"]
    # An annotated flag binds too (panel AA SHOULD-A1); a bare annotation does not.
    assert run("def h(conn):\n    nested: bool = conn.in_transaction\n"
               "    conn.commit()\n") == ["m.py:3 h"]
    assert run("def h(conn):\n    nested: bool = conn.in_transaction\n"
               "    if not nested:\n        conn.commit()\n") == []
    assert run("def h(conn):\n    nested: bool\n    conn.commit()\n") == []
