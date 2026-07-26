"""last_login stamp at every successful-login terminus — count-agnostic
structural pin + behavioural tests (FIX C, PD#18 / N-49 observability).

Root cause: ``update_last_login`` was called only at the OTP-verify terminus
(``web/routers/ui/users.py``). Every other successful-login surface —
dev_keypair, WebAuthn, passkey, recovery_code, operator_recovery — never
stamped it, so HIPAA-preferred MFA users showed "Never" in the admin user
list.

Fix: call ``update_last_login`` inside the db_call closure of each success
terminus in ``web/routers/auth_keys.py``, alongside the existing
``record_auth_event(outcome="success")`` call.

Pin design: a per-closure AST check is complex given the nested-function
shape of auth_keys.py.  The structural invariant chosen here is:

  For every *login-success* ``record_auth_event`` call site (identified by
  a keyword ``outcome`` whose value equals ``"success"`` AND an
  ``event_type`` matching ``login_*``) in the two login router modules,
  there must be an ``update_last_login`` call within the SAME enclosing
  function definition.

This is the inter-procedural shape the task requires: the pin is keyed on
the *seam* (the closure that contains both the audit write and the stamp),
not the outer handler (which would be blind to closures that split the work).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, innermost_fn_at_lineno, parse_module, relpath

_SRC = SRC_ROOT
_AUTH_KEYS = _SRC / "web" / "routers" / "auth_keys.py"
_USERS_UI = _SRC / "web" / "routers" / "ui" / "users.py"

_LOGIN_MODULES = [_AUTH_KEYS, _USERS_UI]
_STAMP_FN = "update_last_login"
_AUDIT_FN = "record_auth_event"


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _enclosing_fn(node: ast.AST, tree: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The innermost function/async-function NODE containing *node* (by lineno),
    or None at module scope — delegates to the harness SSOT
    :func:`innermost_fn_at_lineno` (R5c: no re-rolled enclosing-fn walk)."""
    if not hasattr(node, "lineno"):
        return None
    return innermost_fn_at_lineno(tree, node.lineno)


def _calls_in_fn(fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
                 fn_name: str) -> list[ast.Call]:
    """Return all Call nodes inside *fn_node* whose callee name is *fn_name*."""
    out = []
    for n in ast.walk(fn_node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.attr if isinstance(f, ast.Attribute) else (
            f.id if isinstance(f, ast.Name) else "")
        if name == fn_name:
            out.append(n)
    return out


def _is_login_success_audit(call: ast.Call) -> bool:
    """True when *call* looks like ``record_auth_event(…, outcome="success",
    event_type="login_*")``.  Both keywords must be present as Constant strings.
    """
    outcome_ok = False
    event_ok = False
    for kw in call.keywords:
        if kw.arg == "outcome" and isinstance(kw.value, ast.Constant):
            if str(kw.value.value) == "success":
                outcome_ok = True
        if kw.arg == "event_type" and isinstance(kw.value, ast.Constant):
            if str(kw.value.value).startswith("login_"):
                event_ok = True
    return outcome_ok and event_ok


# ---------------------------------------------------------------------------
# Structural pin
# ---------------------------------------------------------------------------

def test_every_login_success_audit_has_update_last_login_in_same_closure():
    """Count-agnostic inter-procedural pin: for every
    ``record_auth_event(event_type="login_*", outcome="success")`` call site
    across the login router modules, ``update_last_login`` must also be called
    inside the same enclosing function/closure.

    A new login terminus that emits the audit event but forgets the stamp will
    fail this pin automatically — regardless of how many termini exist.
    """
    offenders = []
    for path in _LOGIN_MODULES:
        tree = parse_module(path)
        if tree is None:
            import pytest
            pytest.fail(
                f"{path} did not parse — a non-parsing src module is a "
                "defect this guard must surface, not skip"
            )
        rel = relpath(path, _SRC)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            callee = f.attr if isinstance(f, ast.Attribute) else (
                f.id if isinstance(f, ast.Name) else "")
            if callee != _AUDIT_FN:
                continue
            if not _is_login_success_audit(node):
                continue

            # Found a login-success audit call.  Check its enclosing closure.
            enc = _enclosing_fn(node, tree)
            if enc is None:
                # Module-level audit call — no enclosing function to check.
                offenders.append(
                    f"{rel}:{node.lineno} record_auth_event(success) at module scope"
                )
                continue
            stamp_calls = _calls_in_fn(enc, _STAMP_FN)
            if not stamp_calls:
                offenders.append(
                    f"{rel}:{node.lineno} record_auth_event(success) inside "
                    f"'{enc.name}' — no {_STAMP_FN} call in same closure"
                )

    assert not offenders, (
        "FIX C (PD#18): every successful-login terminus must call "
        f"``{_STAMP_FN}`` in the same enclosing closure as the "
        "``record_auth_event(outcome='success')`` audit call. "
        "HIPAA-preferred MFA users (WebAuthn/passkey/recovery) showed "
        "'Never' in the admin user list because their termini never "
        f"stamped last_login. Missing: {offenders}"
    )


def test_stamp_fn_exists_in_auth(
):
    """Guard: ``update_last_login`` is importable from ``web.auth``."""
    from email_triage.web.auth import update_last_login  # noqa: F401 (import test)


# ---------------------------------------------------------------------------
# Behavioural tests (requires a real db + app; use conftest fixtures)
# ---------------------------------------------------------------------------

class TestLastLoginStampTermini:
    """Behavioural: each login surface updates last_login on success."""

    def _get_last_login(self, db, email: str):
        row = db.execute(
            "SELECT last_login FROM users WHERE email = ?", (email,),
        ).fetchone()
        assert row is not None, f"User {email!r} not found"
        return row["last_login"]

    def test_otp_verify_stamps_last_login(self, client, db, regular_user):
        """Baseline: OTP path already stamped last_login (regression guard)."""
        from email_triage.web.auth import store_otp, generate_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)

        r = client.post("/login/verify", data={"email": email, "code": code})
        assert r.status_code in (200, 302, 303)

        ll = self._get_last_login(db, email)
        assert ll is not None, (
            "OTP verify must stamp last_login; regression in the baseline path."
        )

    def test_webauthn_finish_stamps_last_login(self, client, db, regular_user):
        """FIX C: WebAuthn finish stamps last_login (was: always 'Never').

        Stubs ``finish_authentication`` so we can drive the success path
        without real WebAuthn hardware.  The test verifies that
        ``update_last_login`` is called on the success branch by checking
        the DB value changed.
        """
        import json
        from unittest.mock import patch
        import email_triage.web.webauthn_auth as wa

        email = regular_user["email"]
        before = self._get_last_login(db, email)

        # Seed a hardware_key row so the active-key guard passes.
        db.execute(
            "INSERT INTO hardware_keys "
            "(user_id, credential_id, public_key, sign_count, nickname, created_at) "
            "VALUES (?, ?, ?, 0, 'test-key', datetime('now'))",
            (regular_user["id"], b"cred_bytes", b"pub_bytes"),
        )
        db.commit()

        # Configure webauthn rp_id so the route proceeds past its
        # `if not config.webauthn.rp_id: 503` gate — otherwise this last_login
        # guard SKIPS itself (vacuous pass) on any env without rp_id (CI/the deploy host).
        # "testserver" is the Starlette TestClient default host.
        client.app.state.config.webauthn.rp_id = "testserver"

        # Stub finish_authentication to return key_id=1 (success).
        with patch.object(wa, "finish_authentication", return_value=1):
            r = client.post(
                "/login/webauthn/finish",
                content=json.dumps({
                    "email": email,
                    "response": {"authenticatorData": "x", "signature": "y",
                                 "clientDataJSON": "z"},
                }),
                headers={"content-type": "application/json"},
            )

        # rp_id is configured above, so the route MUST proceed (never 503) — a
        # 503/skip here would make this guard vacuous (the whole point of the prune).
        assert r.status_code != 503, (
            "webauthn finish returned 503 despite rp_id configured — the "
            "last_login guard must not skip itself."
        )
        assert r.status_code == 200, (
            f"expected 200 on the stubbed-success path, got {r.status_code}"
        )
        after = self._get_last_login(db, email)
        assert after is not None, (
            "FIX C: WebAuthn finish must stamp last_login via update_last_login; "
            "last_login is still None after a successful assertion."
        )
        assert after != before or before is None, (
            "FIX C: WebAuthn finish must UPDATE last_login; "
            "value is unchanged from before the login."
        )
