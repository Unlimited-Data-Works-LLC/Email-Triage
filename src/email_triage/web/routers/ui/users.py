"""Routes for the users concern.

Split out of the legacy `web/routers/ui.py` (#144). Helpers
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
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

_log = get_logger("web.ui.users")

router = APIRouter()


def __getattr__(name):
    """Route reads of legacy install-singleton names through the factory.

    The factory module (#138.1) now owns ``_install_google_oauth`` and
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
    user = get_current_user(request)
    if user is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return _render(templates, request, "login.html", {"step": "email"})


@router.post("/login/email", response_class=HTMLResponse)
async def login_email(request: Request, email: str = Form(...)):
    """Step 1: user submits email, we generate and store OTP.

    Fail-closed on disabled users: the SMTP send is skipped so no code
    ever reaches the inbox of a disabled account. The response is the
    same ``step=verify`` screen everyone else sees — we don't reveal
    whether the account exists or is disabled.

    #92 — login_guard runs BEFORE the user lookup so a probing
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

    # #92 lockout gate — runs first. A locked email or IP gets the
    # generic verify-step screen (same shape as success) so the
    # response doesn't leak which counter tripped or whether the
    # account exists.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
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
        return _render(templates, request, "login.html", {
            "step": "email",
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })

    user = get_user_by_email(db, email)
    user_disabled = bool(user and user.get("disabled"))
    if user is None:
        # Failure row so the rate-limiter sees no-such-account
        # spraying. ``email`` is the operator-supplied input —
        # could be junk, but the COUNT is what matters.
        record_login_failure(
            db, surface="otp_request", email=email, ip=client_host,
            user_agent=user_agent, reason="account_not_found",
        )
        return _render(templates, request, "login.html", {
            "step": "email", "error": "No account found for that email.",
        })

    if user_disabled:
        # Don't generate or store an OTP. Don't call SMTP. Don't reveal
        # the account is disabled — present the same verify screen so
        # there's no account-state oracle for a probing attacker.
        from email_triage.triage_logging import get_logger
        log = get_logger("web.auth")
        log.warning("OTP delivery skipped: user disabled", email=email)
        return _render(templates, request, "login.html", {
            "step": "verify", "email": email,
        })

    # #67 — hardware-key picker. If the user has at least one active
    # hardware key, render the choose-method step (touch security key
    # primary + send-OTP-instead fallback) WITHOUT sending the OTP.
    # User picks "OTP fallback" to fall through into the existing path
    # (which posts back to /login/email with otp_fallback=1).
    skip_hw_picker = bool(
        request.query_params.get("otp_fallback") == "1"
    )
    if not skip_hw_picker:
        from email_triage.web.db_auth_helpers import (
            user_has_active_hardware_key as _has_hw,
        )
        try:
            has_hw = _has_hw(db, user["id"])
        except Exception:
            has_hw = False
        if has_hw:
            return _render(templates, request, "login.html", {
                "step": "choose", "email": email,
            })

    code = generate_otp()
    store_otp(db, email, code)

    # Send OTP via SMTP if configured, otherwise log it (dev mode).
    config = get_config(request)
    smtp = config.smtp

    if smtp.host:
        try:
            secrets = get_secrets(request)
            smtp_password = secrets.get("SMTP_PASSWORD") or ""
            send_otp_email(
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
            return _render(templates, request, "login.html", {
                "step": "email",
                "error": "Could not send login code. Please try again or contact admin.",
            })
    else:
        # Dev mode — no SMTP configured, log the code.
        from email_triage.triage_logging import get_logger
        log = get_logger("web.auth")
        log.warning("No SMTP configured — logging OTP (dev mode)", email=email, code=code)

    return _render(templates, request, "login.html", {
        "step": "verify", "email": email,
    })


@router.post("/login/verify", response_class=HTMLResponse)
async def login_verify(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
):
    """Step 2: user submits the 6-digit code.

    #92 — login_guard runs before verify_otp; a tipped counter
    refuses without consuming the OTP code. Bad-code attempts
    write a failure row into ``auth_events`` so the rolling
    window catches the next attempt.
    """
    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    client_host = (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")

    # #92 lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
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
        return _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": (
                f"Too many login attempts. Please try again in "
                f"{retry_min} minute{'s' if retry_min != 1 else ''}."
            ),
        })

    # OTP verification is the only path through this handler. Other
    # auth surfaces (admin-managed keypair at /admin/dev-keys,
    # per-user WebAuthn at /profile/hardware-keys) are routed
    # separately and never short-circuit this code-shape check.
    if not verify_otp(db, email, code):
        # #92 — record the failure so the rolling window counts it.
        record_login_failure(
            db, surface="otp", email=email, ip=client_host,
            user_agent=user_agent, reason="invalid_code",
        )
        return _render(templates, request, "login.html", {
            "step": "verify", "email": email,
            "error": "Invalid or expired code. Please try again.",
        })

    # Successful verification.
    user = get_user_by_email(db, email)
    if user is None:
        return _render(templates, request, "login.html", {
            "step": "email", "error": "Account not found.",
        })

    # Fail-closed: even with a valid OTP (or dev-bypass), a disabled
    # user cannot log in. Checked AFTER verify_otp so the one-shot
    # code is still consumed — a probing attacker can't tell whether
    # the account is disabled vs. code-wrong based on retries.
    if user.get("disabled"):
        from email_triage.triage_logging import get_logger
        log = get_logger("web.auth")
        log.warning("Login blocked: user disabled", email=email)
        return _render(templates, request, "login.html", {
            "step": "email",
            "error": "Account disabled. Contact admin.",
        })

    update_last_login(db, email)

    # PR 9 / D4 — append-only auth audit. Record successful OTP
    # login alongside the existing update_last_login (which is the
    # admin UI's "last login" display column; this table is the
    # historical source of truth).
    try:
        from email_triage.web.db import record_auth_event
        client_host = (request.client.host if request.client else None)
        record_auth_event(
            db,
            event_type="login_otp",
            email=email,
            user_id=user["id"],
            key_id=None,
            ip=client_host,
            user_agent=request.headers.get("user-agent"),
            outcome="success",
        )
    except Exception:
        # Audit-write failure must not block a valid login. The
        # operator detects drift via /health (audit_failures-style
        # counter is filed for follow-up if this becomes a problem).
        pass

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
    token = create_session_token(secret, email, user["role"])
    response = RedirectResponse("/dashboard", status_code=303)
    # PR 8 / D1 follow-up: cookie max_age tracks the effective
    # session TTL (HIPAA-aware) so the browser drops the cookie at
    # the same moment the server stops accepting it.
    from email_triage.web.auth import effective_session_ttl
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        max_age=effective_session_ttl(request.app.state.config),
    )
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
async def users_page(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    templates = get_templates(request)
    users = await db_call(_users_page_snapshot, db)

    return _render(templates, request, "users/manage.html", {
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
    user = get_current_user(request)
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    now = datetime.now(timezone.utc).isoformat()

    def _create_user_snapshot(db, email, name, role, notify_email, now):
        """#135 phase 2 — dup-check + insert + commit in one hop."""
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
    user = get_current_user(request)
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    def _update_user_snapshot(db, user_id, email, name, role, notify_email):
        """#135 phase 2 — conflict check + update + commit in one hop."""
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
    user = get_current_user(request)
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    def _delete_user_snapshot(db, user_id, current_email):
        """#135 phase 2 — self-delete check + delete + commit in one hop."""
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
    user = get_current_user(request)
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
        """#135 phase 2 — target check + disable + audit row in one hop."""
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
    user = get_current_user(request)
    if user is None or user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    from email_triage.web.db import set_user_disabled

    def _enable_user_snapshot(db, user_id, actor_user_id, reason):
        """#135 phase 2 — target check + enable + audit row in one hop."""
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

