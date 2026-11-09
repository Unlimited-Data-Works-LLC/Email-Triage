"""Pin (panel T db S-R2-A2, 2026-10-25): every login-surface auth-event writer uses the
lockout prefix.

``login_guard`` counts only failure rows whose ``event_type`` starts with
``LOCKOUT_EVENT_PREFIX`` toward a login lockout, so the NAME of a login surface's failure
event is a security control. A future surface writing its failures as ``passkey_*``,
``sso_*`` or ``magic_link`` would silently stop counting: fail-OPEN on brute-force lockout.

INVARIANT (count-agnostic, PD-1): every ``record_auth_event`` / ``record_auth_event_txn``
call that is (a) anywhere in ``web/login_guard.py``, or (b) anywhere inside a function that
also calls ``check_login_allowed`` (nested defs and lambdas included), passes ``event_type=``
as a string literal, or an f-string whose leading literal part, that starts with
``LOCKOUT_EVENT_PREFIX``. A non-static ``event_type`` fails: the pin cannot prove it.

The prefix is imported from ``login_guard`` (the SSOT that also builds the SQL ``LIKE``),
never re-typed here (PD-5). Scope limit: a writer in a helper that a login handler calls,
outside the handler's own body, is not in (b); login_guard's own helpers are covered by (a).
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

from email_triage.web import login_guard
from email_triage.web.login_guard import LOCKOUT_EVENT_PREFIX

_WRITERS = frozenset({"record_auth_event", "record_auth_event_txn"})
_GUARD_MODULE = "web/login_guard.py"
_GATE = "check_login_allowed"


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _static_prefix(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        head = node.values[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return head.value
    return None


def scan(tree: ast.AST, rel: str) -> tuple[int, list[str]]:
    """Return (in-scope writer calls, violations) for one module."""
    roots: list[ast.AST] = [tree] if rel == _GUARD_MODULE else []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(c, ast.Call) and _call_name(c) == _GATE for c in ast.walk(fn)
        ):
            roots.append(fn)
    seen: set[int] = set()
    hits, bad = 0, []
    for root in roots:
        for c in ast.walk(root):
            if not isinstance(c, ast.Call) or _call_name(c) not in _WRITERS or id(c) in seen:
                continue
            seen.add(id(c))
            hits += 1
            et = next((k.value for k in c.keywords if k.arg == "event_type"), None)
            prefix = _static_prefix(et)
            if prefix is None or not prefix.startswith(LOCKOUT_EVENT_PREFIX):
                shown = ast.unparse(et) if et is not None else "<missing>"
                bad.append(f"{rel}:{c.lineno} event_type={shown}")
    return hits, bad


def test_every_login_surface_auth_event_uses_the_lockout_prefix():
    hits, bad = 0, []
    for _path, rel, tree in walk_src():
        h, b = scan(tree, rel)
        hits += h
        bad += b
    assert hits, "the scan found no login-surface writer: the net is broken, not clean"
    assert not bad, (
        f"login-surface auth events outside the lockout prefix {LOCKOUT_EVENT_PREFIX!r} "
        "would never count toward a login lockout:\n" + "\n".join(bad)
    )


def test_the_lockout_query_is_built_from_the_prefix():
    assert login_guard._LOCKOUT_EVENT_LIKE == LOCKOUT_EVENT_PREFIX.replace("_", "\\_") + "%"


def test_teeth_a_planted_passkey_failure_writer_is_caught():
    src = (
        "def passkey_login(db, email):\n"
        "    check_login_allowed(db, email=email, ip='1.2.3.4')\n"
        "    record_auth_event(db, event_type='passkey_auth', email=email, outcome='failure')\n"
    )
    hits, bad = scan(ast.parse(src), "web/routers/passkey.py")
    assert hits == 1 and len(bad) == 1 and "passkey_auth" in bad[0]


def test_teeth_static_prefix_forms_and_a_dynamic_name():
    src = (
        "def ok(db, surface):\n"
        "    check_login_allowed(db)\n"
        "    record_auth_event(db, event_type=f'login_{surface}', outcome='failure')\n"
        "    record_auth_event_txn(db, event_type='login_otp', outcome='failure')\n"
        "def dynamic(db, name):\n"
        "    check_login_allowed(db)\n"
        "    work = lambda: record_auth_event(db, event_type=name, outcome='failure')\n"
        "    return work\n"
        "def unrelated(db):\n"
        "    record_auth_event(db, event_type='dev_key_registered', outcome='success')\n"
    )
    hits, bad = scan(ast.parse(src), "web/x.py")
    assert hits == 3, "only writers in a function that calls the gate are in scope"
    assert len(bad) == 1 and "event_type=name" in bad[0]
