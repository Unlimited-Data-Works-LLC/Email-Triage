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
from datetime import datetime, timezone
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
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
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.users")

router = APIRouter()


def __getattr__(name):
    """Route reads of legacy install-singleton names through the factory.

    The factory module now owns ``_install_google_oauth`` and
    ``_install_ingestion_config``. Code that did
    ``from email_triage.web.routers.ui import _install_ingestion_config``
    (e.g. test fixtures, future plugins) keeps working — PEP 562 lets
    us proxy module-level reads to the factory's current values.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")



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
    """PEP 562 fallback — late-bound lookup on _shared.

    Catches names added to `_shared` after this module's globals
    were populated, plus names that the package-level monkeypatch
    mirror writes onto `_shared` AFTER import.
    """
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
    client_host = (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")

    #  lockout gate — runs first. A locked email or IP gets the
    # generic verify-step screen (same shape as success) so the
    # response doesn't leak which counter tripped or whether the
    # account exists.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    skip_hw_picker = bool(
        request.query_params.get("otp_fallback") == "1"
    )

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
        # active hardware key, render the choose-method step (touch
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
        from email_triage.triage_logging import get_logger
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
        try:
            secrets = get_secrets(request)
            smtp_password = secrets.get("SMTP_PASSWORD") or ""
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
            from email_triage.triage_logging import get_logger
            log = get_logger("web.auth")
            log.error("Failed to send OTP email", error=str(exc))
            return await _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
    else:
        # Dev mode — no SMTP configured, log the code.
        from email_triage.triage_logging import get_logger
        log = get_logger("web.auth")
        log.warning("No SMTP configured — logging OTP (dev mode)", email=email, code=code)

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
    client_host = (request.client.host if request.client else None)
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
        # HIPAA mode, a user with any registered hardware key OR
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
            try:
                record_auth_event(
                    db,
                    event_type="login_otp",
                    email=email,
                    user_id=user_["id"],
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:mfa_required",
                )
            except Exception:
                pass
            return "mfa_required", {}

        update_last_login(db, email)

        # PR 9 / D4 — append-only auth audit. Record successful OTP
        # login alongside the existing update_last_login (which is
        # the admin UI's "last login" display column; this table is
        # the historical source of truth).
        try:
            from email_triage.web.db import record_auth_event
            record_auth_event(
                db,
                event_type="login_otp",
                email=email,
                user_id=user_["id"],
                key_id=None,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
            )
        except Exception:
            # Audit-write failure must not block a valid login. The
            # operator detects drift via /health (audit_failures-style
            # counter is filed for follow-up if this becomes a
            # problem).
            pass
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
        from email_triage.triage_logging import get_logger
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
        from email_triage.triage_logging import get_logger
        log = get_logger("web.auth")
        log.info(
            "OTP login refused: MFA required in HIPAA mode",
            email=email,
        )
        return RedirectResponse("/login/webauthn", status_code=303)

    user = payload["user"]

    # PR 10 / E — metrics counter. Bounded label cardinality (3
    # surfaces × 2 outcomes), so the registry stays tiny.
    try:
        from email_triage import metrics as metrics_mod
        metrics_mod.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface="otp", outcome="success")
    except Exception:
        pass

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
    set_session_cookie(response, token, request.app.state.config)
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
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

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
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    now = datetime.now(timezone.utc).isoformat()

    def _create_user_snapshot(db, email, name, role, notify_email, now):
        """ phase 2 — dup-check + insert + commit in one hop."""
        if get_user_by_email(db, email) is not None:
            return False
        db.execute(
            "INSERT INTO users (email, name, role, notify_email, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, name, role, notify_email or None, now),
        )
        db.commit()
        return True

    success = await db_call(
        _create_user_snapshot, db, email, name, role, notify_email, now,
    )
    if not success:
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
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    def _update_user_snapshot(db, user_id, email, name, role, notify_email):
        """ phase 2 — conflict check + update + commit in one hop."""
        if email:
            existing = db.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (email, user_id),
            ).fetchone()
            if existing:
                return False
            db.execute(
                "UPDATE users SET email = ?, name = ?, role = ?, notify_email = ? WHERE id = ?",
                (email, name, role, notify_email or None, user_id),
            )
        else:
            db.execute(
                "UPDATE users SET name = ?, role = ?, notify_email = ? WHERE id = ?",
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
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    def _delete_user_snapshot(db, user_id, current_email):
        """ phase 2 — self-delete check + delete + commit in one hop."""
        target = db.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if target and target["email"] == current_email:
            return False
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        return True

    success = await db_call(
        _delete_user_snapshot, db, user_id, user["email"],
    )
    if not success:
        return HTMLResponse(
            '<p class="error">Cannot delete your own account.</p>',
            status_code=400,
        )

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
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

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
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

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

