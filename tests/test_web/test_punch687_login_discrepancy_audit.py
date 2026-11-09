"""Punch 687: a VALID OTP for a missing or disabled user writes a chained
``auth_events`` row, and that row does not count toward a login lockout.

Before the fix the ``not_found`` and ``disabled`` exits of ``login_verify``
recorded nothing in ``auth_events`` (only a TriageLogger warning for the
disabled case), so a terminated user presenting a valid credential left no
tamper-evident record (§164.308(a)(5)(ii)(C), §164.308(a)(3)(ii)(C)).

The lockout counter (``login_guard._count_failures_since``) counts only rows
with ``outcome = 'failure'`` and a ``login_`` event type. These exits make no
guess, so their rows use a ``denied:`` outcome, the same lockout-neutral shape
as the ``denied:mfa_required`` sibling.
"""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone

from _pin_harness import SRC_ROOT, parse_module

from email_triage.web.auth import store_otp
from email_triage.web.login_guard import _count_failures_since

_CODE = "246810"


def _rows(db, email):
    return db.execute(
        "SELECT event_type, user_id, outcome FROM auth_events "
        "WHERE email = ? ORDER BY id", (email,),
    ).fetchall()


def _since():
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def test_valid_otp_for_missing_user_is_witnessed_and_lockout_neutral(client, db):
    email = "nobody-687@example.invalid"
    store_otp(db, email, _CODE)
    r = client.post("/login/verify", data={"email": email, "code": _CODE})
    assert r.status_code == 200
    assert "Account not found." in r.text
    rows = [tuple(x) for x in _rows(db, email)]
    assert rows == [("login_otp", None, "denied:user_not_found")], rows
    assert _count_failures_since(
        db, column="email", value=email, since_iso=_since()) == 0


def test_valid_otp_for_disabled_user_is_witnessed_and_lockout_neutral(
    client, db, regular_user,
):
    email = regular_user["email"]
    db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (regular_user["id"],))
    db.commit()
    store_otp(db, email, _CODE)
    r = client.post("/login/verify", data={"email": email, "code": _CODE})
    assert r.status_code == 200
    assert "Account disabled." in r.text
    rows = [tuple(x) for x in _rows(db, email)]
    assert rows == [("login_otp", regular_user["id"], "denied:account_disabled")], rows
    assert _count_failures_since(
        db, column="email", value=email, since_iso=_since()) == 0


def _login_verify_emits(tree):
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "login_verify")
    out = []
    for c in ast.walk(fn):
        if (isinstance(c, ast.Call) and getattr(c.func, "id", None) == "record_auth_event"):
            kw = {k.arg: k.value for k in c.keywords}
            out.append(kw["outcome"].value if isinstance(kw.get("outcome"), ast.Constant) else None)
    return out


def test_no_discrepancy_row_is_a_lockout_failure():
    """Structural half: every ``record_auth_event`` in ``login_verify`` names a
    literal outcome, and the two discrepancy outcomes are present and are not
    the counted ``failure`` value."""
    outcomes = _login_verify_emits(parse_module(SRC_ROOT / "web/routers/ui/users.py"))
    assert None not in outcomes, outcomes
    assert {"denied:user_not_found", "denied:account_disabled"} <= set(outcomes), outcomes
    assert "failure" not in outcomes
