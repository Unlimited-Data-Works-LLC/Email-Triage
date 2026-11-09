"""N-275 R28 structural pin — no hard-delete on `email_accounts` (2026-07-03).

Operator design ruling 2026-07-03 (punch ): "No delete, ever. Mark
as disabled and hide from any picker not in the /admin section." A
hard `DELETE FROM email_accounts WHERE id = ?` cascade-destroys the
account's `hipaa_access_events` rows (`account_id ON DELETE CASCADE`
in the DDL at `db/audit.py:302`) — §164.312(b)/(c)(1) tamper-evident
audit destruction. Same defect class the  ruling forbade for
users, reached via the account door.

N-275 converts `delete_email_account` from a hard DELETE to a soft
`is_active=0` UPDATE. This pin catches ANY new site that
re-introduces the hard-delete shape.

WHAT IT PINS (STRICT-0):

Any string literal matching `DELETE FROM email_accounts` outside the
allow-list fires. There is no legitimate hard-delete path for
`email_accounts` under the operator ruling.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


def test_no_hard_delete_email_accounts():
    """STRICT-0: any `DELETE FROM email_accounts` string literal tree-
    wide fires. Convert to soft-deactivate via `set_account_active
    (conn, id, False)` — the operator ruling forbids hard-delete."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        # Skip docstring Expr nodes — docstrings that EXPLAIN the ban
        # naturally reference the forbidden shape (e.g. `db/accounts.py::
        # delete_email_account`'s new docstring documenting why the hard-
        # delete is gone). We want executable/data string literals only.
        docstring_ids: set[int] = set()
        for parent in ast.walk(tree):
            body = getattr(parent, "body", None)
            if not isinstance(body, list) or not body:
                continue
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstring_ids.add(id(first.value))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            if not isinstance(node.value, str):
                continue
            if id(node) in docstring_ids:
                continue
            s = node.value.lower()
            if "delete from email_accounts" in s:
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-275 R28 hard-delete on `email_accounts` re-introduced. "
        "Operator ruling 2026-07-03 (punch #71): no delete, ever. "
        "Soft-deactivate via `set_account_active(conn, id, False)` "
        "so the row + its `hipaa_access_events` audit history are "
        "retained.\n\n"
        + "\n".join(offenders)
    )


def test_delete_email_account_is_soft_deactivate():
    """Anti-vacuity: the `delete_email_account` primitive itself uses
    the UPDATE (soft) shape, not a DELETE."""
    from email_triage.db import accounts as accounts_mod
    import inspect
    src = inspect.getsource(accounts_mod.delete_email_account)
    assert "UPDATE email_accounts" in src and "is_active = 0" in src, (
        "N-275 R28 REGRESSION: `delete_email_account` no longer uses "
        "the soft-deactivate UPDATE shape. Operator ruling: hard-"
        "delete forbidden; this primitive MUST route through the "
        "`is_active=0` UPDATE."
    )
    assert "DELETE FROM email_accounts" not in src.upper(), (
        "N-275 R28 REGRESSION: `delete_email_account` re-introduced "
        "a `DELETE FROM email_accounts` — the exact escape hatch the "
        "operator ruling forbade."
    )
