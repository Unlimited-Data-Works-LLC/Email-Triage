"""Operator ruling 2026-06-19: a user is NEVER hard-deleted.

A ``DELETE FROM users`` (a) NULLs the actor link across the 9 tamper-evident
audit tables (their actor FK is ``ON DELETE SET NULL`` — breaking the
§164.312(c)(1) verify chain for that user's historical rows) AND (b) via the
user→email_accounts→audit cascade chain, deletes each account's
``hipaa_access_events`` (``account_id`` is ``ON DELETE CASCADE``) — wiping the
§164.312(b) PHI-access trail. The admin "Remove" actuator instead SOFT-DISABLES
the user and DEACTIVATES (not deletes) the accounts.

This is a count-agnostic AST pin: it scans ALL of src/ for an EXECUTABLE
``DELETE FROM users`` (an ``.execute("DELETE FROM users …")`` call), so a NEW
hard-delete path anywhere inherits the prohibition. Docstrings/comments
mentioning the SQL are not flagged (only ``Call`` nodes with a string-literal
first arg).
"""
from __future__ import annotations

import ast
import re

# NOTE (db-sme T1.3 review): known blind spots of this AST pin — variable-bound
# SQL (`q = "DELETE FROM users"; execute(q)`) and f-string SQL are not caught
# (the first arg must be a string Constant). Acceptable: this repo writes SQL as
# single-space string literals by convention and there is zero dynamic
# `DELETE FROM users` at HEAD. Whitespace is normalized below so a multi-space
# variant can't slip the needle. The SIBLING `DELETE FROM email_accounts` (which
# cascade-deletes hipaa_access_events) is INTENTIONALLY not banned here — its fix
# is ALSO banned now (operator ruled 2026-06-20: never delete accounts either —
# soft-deactivate + hide, N-108), EXCEPT in the kept-but-uncalled SSOT primitive
# db/accounts.py::delete_email_account (still re-exported + referenced by sibling
# pins; no actuator calls it anymore — the account-delete actuator soft-deactivates).


def _executable_delete_from(tree: ast.AST, table: str) -> list[int]:
    needle = f"delete from {table}"
    out: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("execute", "executescript", "executemany")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and needle in re.sub(r"\s+", " ", node.args[0].value.lower())
        ):
            out.append(node.lineno)
    return out


# The account-delete SSOT primitive is kept (re-exported + referenced by sibling
# pins) but is no longer CALLED by any actuator — so its own DELETE FROM
# email_accounts is the one allowed site; an actuator hard-deleting an account
# anywhere else trips the pin.
_EMAIL_ACCOUNTS_DELETE_ALLOW = {"db/accounts.py"}


def test_no_hard_delete_of_users_or_accounts_in_actuators():
    """Operator ruling: a user AND an account
    are NEVER hard-deleted — both soft-disable/deactivate. A hard delete NULLs the
    audit actor-chain AND cascade-deletes hipaa_access_events (§164.312(b)/(c)(1)).
    Count-agnostic: bans executable DELETE FROM users (anywhere) and DELETE FROM
    email_accounts (anywhere except the kept db/accounts.py primitive)."""
    from _pin_harness import walk_src
    bad: list[str] = []
    for _p, rel, tree in walk_src():
        for lineno in _executable_delete_from(tree, "users"):
            bad.append(f"src/email_triage/{rel}:{lineno} (DELETE FROM users)")
        if rel not in _EMAIL_ACCOUNTS_DELETE_ALLOW:
            for lineno in _executable_delete_from(tree, "email_accounts"):
                bad.append(
                    f"src/email_triage/{rel}:{lineno} (DELETE FROM email_accounts)"
                )
    assert not bad, (
        "hard DELETE of a user/account found — both are soft-disable/deactivate "
        "only (a hard delete NULLs the audit actor-chain AND cascade-deletes "
        f"hipaa_access_events): {bad}"
    )


# PD#2 (db-sme N-108): the SQL-needle pin above is BLIND to the helper seam — a
# router reverting to ``db_call(delete_email_account, db, id)`` (or a direct
# ``delete_email_account(db, id)``) hard-deletes the account (cascade-wiping
# hipaa_access_events) with NO literal ``DELETE FROM email_accounts`` in the
# router, so it would stay GREEN. Close the seam: the kept-but-uncalled primitive
# must have ZERO call sites outside its own def + the web/db.py re-export shim.
_DELETE_EMAIL_ACCOUNT_CALL_ALLOW = {
    "db/accounts.py",   # the def itself (+ any internal use)
    "web/db.py",        # the re-export shim
}


def _calls_to(tree: ast.AST, name: str) -> list[int]:
    """Line numbers where ``name`` is invoked — directly ``name(...)`` / a
    ``.name(...)`` attribute call, OR passed as the first positional to the
    ``db_call(name, ...)`` threadpool seam (PD#2 interprocedural reach)."""
    out: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if (isinstance(f, ast.Name) and f.id == name) or (
            isinstance(f, ast.Attribute) and f.attr == name
        ):
            out.append(node.lineno)
            continue
        if (
            isinstance(f, ast.Name) and f.id == "db_call"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == name
        ):
            out.append(node.lineno)
    return out


def test_no_call_to_delete_email_account_outside_primitive():
    """N-108 PD#2 — the account hard-delete primitive ``delete_email_account`` is
    KEPT (re-exported, referenced by sibling pins) but must be CALLED by nothing:
    a call cascade-deletes hipaa_access_events (§164.312(b)/(c)(1)). Interprocedural
    across the ``db_call(helper, …)`` seam so an actuator can't revert via the
    helper and stay green (the SQL-needle pin above is blind to that)."""
    from _pin_harness import walk_src
    bad: list[str] = []
    for _p, rel, tree in walk_src():
        if rel in _DELETE_EMAIL_ACCOUNT_CALL_ALLOW:
            continue
        for lineno in _calls_to(tree, "delete_email_account"):
            bad.append(
                f"src/email_triage/{rel}:{lineno} (calls delete_email_account)"
            )
    assert not bad, (
        "a call to delete_email_account found — the account-delete actuator must "
        "soft-deactivate (set_account_active False), never hard-delete (a hard "
        f"delete cascade-wipes hipaa_access_events): {bad}"
    )
