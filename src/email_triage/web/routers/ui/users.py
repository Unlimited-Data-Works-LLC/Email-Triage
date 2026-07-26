"""Routes for the users concern.

Split out of the legacy `web/routers/ui.py`. Helpers
live in `_shared`; this file holds only the @router-decorated
handlers + handler-local helpers for this URL surface.
No behavior changes from pre-split — every handler body is
byte-for-byte identical.
"""
from __future__ import annotations

import asyncio
import email as email_mod
import email.policy
import email.utils
import json as json_mod
import os
import sqlite3
import time
from email_triage._isotime import now_utc_iso
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web._audit import safe_audit_write
from email_triage.web import settings_keys as _S
from email_triage.web.app import get_config, get_db, get_secrets, get_templates
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_otp,
    get_user_by_email,
    send_otp_email,
    set_session_cookie,
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (  # N-337: audit-XFF SSOT
    audit_forwarded_for,
    request_meta,
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    admin_gate_response,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._envbool import parse_bool
from email_triage._errfmt import fmt_exc
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.users")

router = APIRouter()


from . import _shared
# Snapshot every helper from _shared into this module's globals so
# handler bare-name references resolve. globals().update is used
# instead of `from _shared import *` because * skips underscore-
# prefixed names (which is most helpers).
globals().update({
    _n: _v for _n, _v in vars(_shared).items()
    if not _n.startswith('__')
})


def __getattr__(name):
    """Legacy install-singleton names + PEP-562 fallback to ``_shared``.

    Two roles folded into one module-level ``__getattr__`` (census
    wf_56d1585d 2026-07-09 D3 — SSOT self-shadowing fix; Python only
    honours the LAST ``__getattr__`` per module, so previously the
    install-singleton compat glue was dead code from an unnoticed second
    override):

    1. Route reads of legacy install-singleton names
       (``_install_google_oauth`` / ``_install_ingestion_config``) through
       the factory module. Code that did
       ``from email_triage.web.routers.ui import _install_ingestion_config``
       (test fixtures, future plugins) keeps working.
    2. Late-bound lookup on ``_shared`` — catches names added to
       ``_shared`` after this module's ``globals().update`` populated, plus
       names the package-level monkeypatch mirror writes onto ``_shared``
       after import.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    templates = get_templates(request)
    user = await db_call(get_current_user, request)  # 
    if user is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return await _render(templates, request, "login.html", {"step": "email"})


@router.post("/login/email", response_class=HTMLResponse)
async def login_email(request: Request, email: str = Form(...)):
    """Step 1: user submits email, we generate and store OTP.

    Fail-closed on disabled users: the SMTP send is skipped so no code
    ever reaches the inbox of a disabled account. The response is the
    same ``step=verify`` screen everyone else sees — we don't reveal
    whether the account exists or is disabled.

     — login_guard runs BEFORE the user lookup so a probing
    attacker can't use the unknown-email path as an enumeration
    oracle. Lockout response is identical regardless of whether
    the email exists; the unknown-email branch ALSO writes a
    failure row so the per-email + per-IP counters fire on
    nonexistent-account spray.
    """
    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  lockout gate — runs first. A locked email or IP gets the
    # generic verify-step screen (same shape as success) so the
    # response doesn't leak which counter tripped or whether the
    # account exists.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    skip_hw_picker = parse_bool(request.query_params.get("otp_fallback"))

    def _login_email_db_work() -> tuple[str, dict]:
        """/ — lockout gate + user lookup + (hardware-key
        check) + OTP store, all in ONE threadpool hop. Returns
        ``(kind, payload)``:
          - ("locked", {retry_min})  → step=email lockout screen
          - ("not_found", {})        → step=email not-found screen
          - ("disabled", {})         → step=verify (no OTP, no SMTP)
          - ("choose", {})           → step=choose hardware-key picker
          - ("otp", {code})          → handler sends SMTP then renders
        The OTP generation + store live inside this hop so the SMTP
        send below is the only thing the handler does on the loop.
        """
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked:
            record_login_lockout(
                db, surface="otp_request", email=email, ip=client_host,
                user_agent=user_agent, scope=locked.scope,
                threshold=locked.retry_after_secs,
            )
            retry_min = max(1, locked.retry_after_secs // 60)
            return "locked", {"retry_min": retry_min}

        user_ = get_user_by_email(db, email)
        user_disabled = bool(user_ and user_.get("disabled"))
        if user_ is None:
            # Failure row so the rate-limiter sees no-such-account
            # spraying. ``email`` is the operator-supplied input —
            # could be junk, but the COUNT is what matters.
            record_login_failure(
                db, surface="otp_request", email=email, ip=client_host,
                user_agent=user_agent, reason="account_not_found",
            )
            return "not_found", {}

        if user_disabled:
            return "disabled", {}

        #  — hardware-key picker. If the user has at least one
        # active passkey, render the choose-method step (touch
        # security key primary + send-OTP-instead fallback) WITHOUT
        # sending the OTP. User picks "OTP fallback" to fall through
        # into the existing path (posts back with otp_fallback=1).
        if not skip_hw_picker:
            from email_triage.web.db_auth_helpers import (
                user_has_active_hardware_key as _has_hw,
            )
            try:
                has_hw = _has_hw(db, user_["id"])
            except Exception:
                has_hw = False
            if has_hw:
                return "choose", {}

        code_ = generate_otp()
        store_otp(db, email, code_)
        return "otp", {"code": code_}

    kind, payload = await db_call(_login_email_db_work)
    if kind == "locked":
        retry_min = payload["retry_min"]
        return await _render(templates, request, "login.html", {
            "step": "email",
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })
    if kind == "not_found":
        return await _render(templates, request, "login.html", {
            "step": "email", "error": "No account found for that email.",
        })
    if kind == "disabled":
        # Don't generate or store an OTP. Don't call SMTP. Don't reveal
        # the account is disabled — present the same verify screen so
        # there's no account-state oracle for a probing attacker.
        log = get_logger("web.auth")
        log.warning("OTP delivery skipped: user disabled", email=email)
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
        })
    if kind == "choose":
        return await _render(templates, request, "login.html", {
            "step": "choose", "email": email,
        })

    code = payload["code"]

    # Send OTP via SMTP if configured, otherwise log it (dev mode).
    config = get_config(request)
    smtp = config.smtp

    if smtp.host:
        secrets = get_secrets(request)
        from email_triage.secrets import SecretsDecryptError, read_secret
        # A5: explicit decrypt-error handling — an unreadable secret store
        # (master-key mismatch) fails closed (no blank-password send).
        try:
            smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            get_logger("web.auth").error(
                "OTP login email aborted — SMTP password unreadable "
                "(corrupt secret row / master-key mismatch)",
                email=email,
            )
            return await _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
        try:
            # smtplib is blocking — run it off the event loop so the
            # login request doesn't stall every other request + the
            # watchers during the SMTP handshake.
            await asyncio.to_thread(
                send_otp_email,
                smtp_host=smtp.host,
                smtp_port=smtp.port,
                smtp_user=smtp.username,
                smtp_password=smtp_password,
                from_addr=smtp.from_addr,
                to_addr=email,
                code=code,
                use_tls=smtp.use_tls,
                from_name=smtp.from_name,
            )
        except Exception as exc:
            log = get_logger("web.auth")
            log.error("Failed to send OTP email", error=str(exc))
            return await _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
    else:
        # Dev mode — no SMTP configured, log the code. The `code` kwarg
        # was previously dropped by TriageLogger's structured extra-kwarg
        # filter, silently breaking the intended "grep container logs for
        # the OTP" dev bootstrap flow (surfaced 2026-07-21 during the
        #  wizard-Playwright arc — see
        # pattern_demo_wizard_playwright_torm). Inline it into the message
        # string so the emit is filter-proof. Safe: this branch fires ONLY
        # when SMTP is not configured (dev / bootstrap only); OTP codes
        # are not PHI.
        log = get_logger("web.auth")
        log.warning(
            "No SMTP configured — logging OTP (dev mode) code=%s" % code,
            email=email,
        )

    return await _render(templates, request, "login.html", {
        "step": "verify", "email": email,
    })


@router.post("/login/verify", response_class=HTMLResponse)
async def login_verify(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
):
    """Step 2: user submits the 6-digit code.

     — login_guard runs before verify_otp; a tipped counter
    refuses without consuming the OTP code. Bad-code attempts
    write a failure row into ``auth_events`` so the rolling
    window catches the next attempt.
    """
    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    def _login_verify_db_work() -> tuple[str, dict]:
        """/ — lockout gate + verify_otp + user lookup +
        update_last_login + audit, all in ONE threadpool hop. There
        are no network awaits between these calls, so the entire
        sequence is a single hop. Returns ``(kind, payload)``:
          - ("locked", {retry_min})  → step=verify lockout screen
          - ("invalid", {})          → step=verify bad-code screen
          - ("not_found", {})        → step=email account-not-found
          - ("disabled", {})         → step=email account-disabled
          - ("ok", {user})           → handler mints the session token
        """
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked:
            record_login_lockout(
                db, surface="otp", email=email, ip=client_host,
                user_agent=user_agent, scope=locked.scope,
                threshold=locked.retry_after_secs,
            )
            retry_min = max(1, locked.retry_after_secs // 60)
            return "locked", {"retry_min": retry_min}

        # OTP verification is the only path through this handler.
        # Other auth surfaces (admin-managed keypair at
        # /admin/dev-keys, per-user WebAuthn at
        # /profile/hardware-keys) are routed separately and never
        # short-circuit this code-shape check.
        if not verify_otp(db, email, code):
            #  — record the failure so the rolling window counts it.
            record_login_failure(
                db, surface="otp", email=email, ip=client_host,
                user_agent=user_agent, reason="invalid_code",
            )
            return "invalid", {}

        # Successful verification.
        user_ = get_user_by_email(db, email)
        if user_ is None:
            return "not_found", {}

        # Fail-closed: even with a valid OTP (or dev-bypass), a
        # disabled user cannot log in. Checked AFTER verify_otp so
        # the one-shot code is still consumed — a probing attacker
        # can't tell whether the account is disabled vs. code-wrong
        # based on retries.
        if user_.get("disabled"):
            return "disabled", {}

        # H-05 (Cycle 7) — §164.312(d) MFA enforcement gate. In
        # HIPAA mode, a user with any registered passkey OR
        # any unconsumed recovery code MUST authenticate via the
        # WebAuthn / recovery-code path. OTP-only login is the
        # non-MFA factor and is regulatorily insufficient for the
        # HIPAA-mode posture (UPGRADED from LOW to MEDIUM per OCR
        # posture + 2024-12 HHS NPRM). Mirrors the existing
        # "hardware_key_required" gate on the dev_keypair path
        # (auth_keys.py:542-548). Record the denial via
        # record_auth_event for §164.312(b) audit-trail; the OTP
        # code is still consumed so
        # repeated probing is rate-limited.
        from email_triage.web.mfa import is_mfa_required_for
        from email_triage.web.db import record_auth_event
        if is_mfa_required_for(db, user_):
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_otp",
                    email=email,
                    user_id=user_["id"],
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:mfa_required",
                ),
                description="auth_event login_otp outcome=denied:mfa_required",
            )
            return "mfa_required", {}

        update_last_login(db, email)

        # PR 9 / D4 — append-only auth audit. Record successful OTP
        # login alongside the existing update_last_login (which is
        # the admin UI's "last login" display column; this table is
        # the historical source of truth).
        # Audit-write failure must not block a valid login; the
        # operator detects drift via /health (safe_audit_write logs
        # an "audit_write_failed" WARNING and never raises).
        from email_triage.web.db import record_auth_event
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_otp",
                email=email,
                user_id=user_["id"],
                key_id=None,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
            ),
            description="auth_event login_otp outcome=success",
        )
        return "ok", {"user": user_}

    kind, payload = await db_call(_login_verify_db_work)
    if kind == "locked":
        retry_min = payload["retry_min"]
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })
    if kind == "invalid":
        return await _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": "Invalid or expired code. Please try again.",
        })
    if kind == "not_found":
        return await _render(templates, request, "login.html", {
            "step": "email", "error": "Account not found.",
        })
    if kind == "disabled":
        log = get_logger("web.auth")
        log.warning("Login blocked: user disabled", email=email)
        return await _render(templates, request, "login.html", {
            "step": "email",
            "error": "Account disabled. Contact admin.",
        })
    if kind == "mfa_required":
        # H-05 (Cycle 7) — HIPAA-mode MFA gate. User has registered
        # MFA credentials; OTP-only login is rejected. Redirect to
        # WebAuthn / passkey flow. No error-message disclosure of
        # the user's MFA enrollment state (prevents
        # enumerate-which-accounts-have-MFA probing).
        log = get_logger("web.auth")
        log.info(
            "OTP login refused: MFA required in HIPAA mode",
            email=email,
        )
        return RedirectResponse("/login/webauthn", status_code=303)

    user = payload["user"]

    # PR 10 / E — success-edge metric via the shared funnel (record_login_success).
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="otp")

    secret = get_session_secret(request)
    # H-05 (Cycle 7) — first-login bootstrap fix per DA-4 R-Surface-1
    # verify-don't-accept review 2026-05-24. If HIPAA mode is on
    # AND we reach this branch (NOT the mfa_required branch above),
    # the user has zero hardware_keys AND zero recovery_codes —
    # first-login bootstrap case per Q7 ("CLI operator-driven for
    # first admin + first-login automatic for subsequent users").
    # Stamp mfa_verified_at so require_auth doesn't infinite-loop
    # the user back to /login/webauthn when they have no passkey
    # to use. The OTP authentication IS the verified-identity proof
    # for the bootstrap window; the user can now reach
    # /profile/hardware-keys to enroll a passkey. record_auth_event
    # at the OTP-verify path already captures auth_source="otp"
    # for the audit-trail correlation.
    mfa_verified_at: int | None = None
    from email_triage.triage_logging import is_hipaa_mode
    if is_hipaa_mode():
        from email_triage.web.mfa import mfa_verified_now
        mfa_verified_at = mfa_verified_now()
    token = create_session_token(
        secret, email, user["role"],
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_at,
    )
    response = RedirectResponse("/dashboard", status_code=303)
    # PR 8 / D1 follow-up: cookie max_age tracks the effective
    # session TTL (HIPAA-aware) so the browser drops the cookie at
    # the same moment the server stops accepting it.
    set_session_cookie(response, token, request.app.state.config, request=request)
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: RequireUser):
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    templates = get_templates(request)
    users = await db_call(_users_page_snapshot, db)

    return await _render(templates, request, "users/manage.html", {
        "user": user,
        "users": users,
        "roles": [r.value for r in UserRole],
    })


@router.post("/users/create", response_class=HTMLResponse)
async def create_user(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    role: str = Form("user"),
    notify_email: str = Form(""),
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    now = now_utc_iso()
    #  R32 DA-fold R1 — canonicalise on write to match the read-side
    # SSOT (canonical_email); idempotent for ASCII, A-label for IDN.
    from email_triage.mail_headers import canonical_email
    email = canonical_email(email)

    def _create_user_snapshot(db, email, name, role, notify_email, now):
        """ phase 2 — dup-check + insert + commit in one hop.

        Returns "ok" | "active_dup" | "disabled_dup". A "removed" (offboarded)
        user is soft-disabled, not deleted, so its email lingers —
        distinguish that from a live duplicate so the admin gets an actionable
        recovery path (re-enable) instead of a bare "already exists" (R2).
        """
        if get_user_by_email(db, email) is not None:
            row = db.execute(
                "SELECT disabled FROM users WHERE email = ?", (email,)
            ).fetchone()
            return "disabled_dup" if (row and row["disabled"]) else "active_dup"
        db.execute(
            "INSERT INTO users (email, name, role, notify_email, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, name, role, notify_email or None, now),
        )
        db.commit()
        return "ok"

    result = await db_call(
        _create_user_snapshot, db, email, name, role, notify_email, now,
    )
    if result == "disabled_dup":
        return HTMLResponse(
            '<p class="error">That email belongs to a <strong>removed (disabled)</strong> '
            'user. User records are retained for the audit trail and are never deleted — '
            '<strong>re-enable</strong> them from the user list to restore the account, or '
            'use a different address.</p>',
            status_code=409,
        )
    if result == "active_dup":
        return HTMLResponse(
            '<p class="error">A user with that email already exists.</p>',
            status_code=409,
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/update", response_class=HTMLResponse)
async def update_user(
    request: Request,
    user_id: int,
    email: str = Form(""),
    name: str = Form(...),
    role: str = Form(...),
    notify_email: str = Form(""),
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    def _update_user_snapshot(db, user_id, email, name, role, notify_email):
        """ phase 2 — conflict check + update + commit in one hop.

         R32 DA-fold R1 — canonicalise the email before the conflict
        SELECT + INSERT so all three sides (dup-check, WHERE, stored form)
        share one normalisation (canonical_email SSOT).
        """
        if email:
            from email_triage.mail_headers import canonical_email
            email = canonical_email(email)
            existing = db.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (email, user_id),
            ).fetchone()
            if existing:
                return False
            # N-238 R24: bump session_epoch inline — role/email changes
            # invalidate existing session tokens per §164.312(a)(2)(iii).
            # A demoted admin's live cookie must lose authority
            # immediately, not on next login.
            db.execute(
                "UPDATE users SET email = ?, name = ?, role = ?, notify_email = ?, "
                "session_epoch = session_epoch + 1 WHERE id = ?",
                (email, name, role, notify_email or None, user_id),
            )
        else:
            db.execute(
                "UPDATE users SET name = ?, role = ?, notify_email = ?, "
                "session_epoch = session_epoch + 1 WHERE id = ?",  # N-238 R24
                (name, role, notify_email or None, user_id),
            )
        db.commit()
        return True

    success = await db_call(
        _update_user_snapshot, db, user_id, email, name, role, notify_email,
    )
    if not success:
        return HTMLResponse(
            '<p class="error">A user with that email already exists.</p>',
            status_code=409,
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/delete", response_class=HTMLResponse)
async def delete_user(
    request: Request,
    user_id: int,
):
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    def _delete_user_preflight(db, user_id, current_email):
        """ phase 2 — self-delete check + account_id enumeration.

        Returns (False, []) on self-delete (refuse).
        Returns (True, [account_id, ...]) on success — account IDs are
        collected BEFORE the user row is deleted so the funnel can purge
        watcher/secrets state; the actual DELETE happens in the async
        caller after the funnel runs.
        """
        target = db.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target and target["email"] == current_email:
            return False, []
        # Enumerate account_ids NOW (before the row is gone).
        from email_triage.db.accounts import list_email_accounts
        accounts = list_email_accounts(db, user_id=user_id, include_delegated=False)
        account_ids = [a["id"] for a in accounts]
        return True, account_ids

    ok, account_ids = await db_call(
        _delete_user_preflight, db, user_id, user["email"],
    )
    if not ok:
        return HTMLResponse(
            '<p class="error">Cannot delete your own account.</p>',
            status_code=400,
        )

    # L1 + L2 — purge watcher/secrets for EACH account owned by this user
    # BEFORE deleting the user row. The email_accounts rows CASCADE-delete with
    # the user (FK ON DELETE CASCADE), but settings + secrets_store have no FK,
    # and the watcher manager has no FK awareness. Fail CLOSED: if ANY account's
    # purge raises, do NOT delete the user — that would orphan that account's
    # credentials (§164.310(d)(2)(i)); the operator retries. Watcher-stop is
    # best-effort inside the funnel, so only a real purge failure trips this.
    from email_triage.db.accounts import purge_account_local_state
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    for acct_id in account_ids:
        try:
            if watcher_mgr is not None:
                await watcher_mgr.apply_account_deleted(
                    acct_id, actor_user_id=user["id"],
                )
            else:
                secrets = getattr(request.app.state, "secrets", None)
                await db_call(purge_account_local_state, db, acct_id, secrets)
        except Exception as _e:
            _log.error(
                "delete_user: local-state purge FAILED for account — aborting "
                "user delete to avoid orphaning stored credentials",
                user_id=user_id,
                account_id=acct_id,
                error=fmt_exc(_e),
            )
            return HTMLResponse(
                "Delete failed: an account's stored credentials could not be "
                "purged. The user was NOT deleted — please retry.",
                status_code=500,
            )

    def _offboard_user(db, user_id, account_ids, actor_user_id):
        """Offboard — NEVER hard-delete (operator ruling 2026-06-19, ).

        A ``DELETE FROM users`` would (a) NULL the actor link across the 9
        tamper-evident audit tables (their actor FK is ON DELETE SET NULL,
        breaking the §164.312(c)(1) verify chain) AND (b) cascade-delete each
        account's ``hipaa_access_events`` (``account_id`` is ON DELETE CASCADE)
        — wiping the §164.312(b) PHI-access trail. So we SOFT-DISABLE the user
        and DEACTIVATE (not delete) the accounts; credentials are already purged
        above. The user + account rows + all audit history are retained.

        NOTE: the direct account-delete actuator now ALSO soft-deactivates
        (operator ruled 2026-06-20: never delete accounts either — N-108), so
        BOTH the user and account offboard legs preserve the audit trail.
        """
        from email_triage.db.accounts import set_account_active
        from email_triage.db.audit import set_user_disabled
        for acct_id in account_ids:
            set_account_active(db, acct_id, False)
        set_user_disabled(
            db, user_id, True, actor_user_id=actor_user_id,
            reason="offboarded via admin Remove (soft-disable; row retained for audit)",
        )
        return True

    await db_call(_offboard_user, db, user_id, account_ids, user["id"])

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/disable", response_class=HTMLResponse)
async def disable_user(
    request: Request,
    user_id: int,
    reason: str = Form(""),
):
    """Disable a user — fail-closed kill switch.

    Admin-only. Self-disable is refused (don't lock the admin out of
    their own console). Flipping the flag is atomic with the audit-row
    write; on success any running IMAP-IDLE watchers for the user's
    accounts are stopped immediately.
    """
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    if user_id == user["id"]:
        return HTMLResponse(
            '<p class="error">Cannot disable your own account.</p>',
            status_code=400,
        )

    from email_triage.web.db import set_user_disabled

    def _disable_user_snapshot(db, user_id, actor_user_id, reason):
        """ phase 2 — target check + disable + audit row in one hop."""
        target = db.execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target is None:
            return None, False
        changed = set_user_disabled(
            db, user_id, True, actor_user_id=actor_user_id, reason=reason or "",
        )
        return dict(target), changed

    target, changed = await db_call(
        _disable_user_snapshot, db, user_id, user["id"], reason,
    )
    if target is None:
        return HTMLResponse("User not found", status_code=404)

    if changed:
        # Tear down any running watchers for this user (keeps the
        # persisted watch:<id> preference so re-enable restores).
        try:
            from email_triage.web.app import get_watcher_manager
            mgr = get_watcher_manager(request)
            await mgr.stop_for_user(user_id)
        except Exception as e:
            _log.warning("Failed to stop watchers for disabled user",
                         user_id=user_id, error=fmt_exc(e))
        _log.warning(
            "User disabled",
            actor=user["email"], target=target["email"], reason=reason or "",
        )

    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/enable", response_class=HTMLResponse)
async def enable_user(
    request: Request,
    user_id: int,
    reason: str = Form(""),
):
    """Re-enable a previously disabled user.

    Admin-only. The user's persisted watcher preferences are untouched
    by disable, so re-enabling does not by itself restart watchers —
    the user (or admin) re-flips the watch toggle on the account page.
    Kept explicit: we'd rather an admin reconfirm push wiring than
    silently resume it.
    """
    user = await db_call(get_current_user, request)  # 
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)

    from email_triage.web.db import set_user_disabled

    def _enable_user_snapshot(db, user_id, actor_user_id, reason):
        """ phase 2 — target check + enable + audit row in one hop."""
        target = db.execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target is None:
            return None, False
        changed = set_user_disabled(
            db, user_id, False, actor_user_id=actor_user_id, reason=reason or "",
        )
        return dict(target), changed

    target, changed = await db_call(
        _enable_user_snapshot, db, user_id, user["id"], reason,
    )
    if target is None:
        return HTMLResponse("User not found", status_code=404)

    if changed:
        _log.info(
            "User re-enabled",
            actor=user["email"], target=target["email"], reason=reason or "",
        )

    return RedirectResponse("/users", status_code=303)


# ---------------------------------------------------------------------------
# Classification lists
# ---------------------------------------------------------------------------

