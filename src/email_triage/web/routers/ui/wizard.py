"""Routes for the wizard concern.

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

_log = get_logger("web.ui.wizard")

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


@router.get("/accounts/new", response_class=HTMLResponse)
async def wizard_step_dispatcher(
    request: Request,
    step: int = 1,
    account_id: int | None = None,
):
    """Single GET dispatcher for the wizard. Reads ?step=N and
    renders the matching template with the right context."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    db = get_db(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    # Step 1 doesn't need an account_id — it's the entry point.
    if step == 1:
        def _wizard_step1_assignable(db) -> list[dict] | None:
            """#135 phase 2 — admin-only assignable-users roster off
            the loop."""
            rows = db.execute(
                "SELECT id, email, name FROM users "
                "WHERE COALESCE(disabled, 0) = 0 "
                "ORDER BY COALESCE(NULLIF(name, ''), email)"
            ).fetchall()
            return [dict(r) for r in rows]

        assignable_users = None
        if is_admin:
            assignable_users = await db_call(_wizard_step1_assignable, db)
        return _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "assignable_users": assignable_users,
            "default_owner_id": user["id"],
        })

    # Steps 2-5 require a valid account_id the caller can manage.
    if not account_id:
        return RedirectResponse("/accounts/new?step=1", status_code=303)
    from email_triage.web.db import get_email_account

    def _wizard_acct_check(db, account_id, user) -> dict | None:
        """#135 phase 2 — fetch + can-manage-check in one threadpool hop."""
        acct = get_email_account(db, account_id)
        if acct is None or not can_manage_account(db, user, acct):
            return None
        return acct

    acct = await db_call(_wizard_acct_check, db, account_id, user)
    if acct is None:
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    # Skip-step heuristics — computed every render so the progress
    # strip stays consistent with the operator's evolving config.
    # If the operator lands on a step that's been auto-skipped, we
    # 303 through it to the next live step (with a query-string
    # marker so the next page knows we just skipped through).
    skipped_steps = await db_call(_wizard_skipped_steps, db, user, acct)
    if step == 3 and 3 in skipped_steps:
        # Even on a skip we still need to lay down the default
        # push/poll config so the account isn't left in a half-built
        # state. _apply_step3_defaults handles the persistence.
        _watcher_mgr = (
            request.app.state.watcher_manager
            if hasattr(request.app.state, "watcher_manager") else None
        )

        def _step3_skip_writes(db, acct, account_id, watcher_mgr):
            _apply_step3_defaults(db, watcher_mgr, acct)
            _record_wizard_step(db, account_id, 3)

        await db_call(
            _step3_skip_writes, db, acct, account_id, _watcher_mgr,
        )
        target_step = 5 if 4 in skipped_steps else 4
        return RedirectResponse(
            f"/accounts/new?step={target_step}&account_id={account_id}",
            status_code=303,
        )
    if step == 4 and 4 in skipped_steps:
        await db_call(_record_wizard_step, db, account_id, 4)
        return RedirectResponse(
            f"/accounts/new?step=5&account_id={account_id}",
            status_code=303,
        )

    if step == 2:
        return _render(templates, request, "account_wizard/step2.html", {
            "user": user, "acct": acct,
            "skipped_steps": skipped_steps,
        })
    if step == 3:
        # push_blocked_reason calculation mirrors the edit form:
        # Gmail needs the install topic + flow-done state.
        push_blocked_reason = ""
        push_enabled_default = True
        if acct["provider_type"] == "gmail_api":
            config = get_config(request)
            from email_triage.web.db import get_setting
            flow_done = await db_call(
                get_setting, db, _S.gmail_oauth_flow(account_id),
            ) == "web"
            topic_configured = bool(config.push.gmail_topic_name)
            if not flow_done:
                push_blocked_reason = (
                    "Sign-in with Google not yet finished. Push will "
                    "turn on once that lands; you can leave this checked."
                )
            elif not topic_configured:
                push_blocked_reason = (
                    "Push notifications aren't configured for this "
                    "install yet — leave this off; mail still arrives "
                    "via the safety poll."
                )
        elif acct["provider_type"] == "office365":
            push_blocked_reason = (
                "Microsoft real-time push isn't available yet — leave "
                "off; the safety poll picks up new mail."
            )
            push_enabled_default = False

        # Pick up the wizard:auth-completed banner if Gmail OAuth
        # callback redirected back here.
        auth_success = bool(
            request.query_params.get("auth") == "ok"
        )
        return _render(templates, request, "account_wizard/step3.html", {
            "user": user, "acct": acct,
            "push_blocked_reason": push_blocked_reason,
            "push_enabled_default": push_enabled_default,
            "auth_success": auth_success,
            "skipped_steps": skipped_steps,
        })
    if step == 4:
        def _wizard_step4_snapshot(db, account_id, user) -> list[dict]:
            """#135 phase 2 — copy-from candidate accounts in one
            threadpool hop."""
            from email_triage.web.db import list_email_accounts
            all_accts = list_email_accounts(db)
            other_accounts = []
            for a in all_accts:
                if a["id"] == account_id:
                    continue
                if not can_manage_account(db, user, a):
                    continue
                try:
                    n = db.execute(
                        "SELECT COUNT(*) FROM account_routes WHERE account_id = ?",
                        (a["id"],),
                    ).fetchone()[0]
                except Exception:
                    n = 0
                if n > 0:
                    other_accounts.append({
                        "id": a["id"],
                        "name": a["name"],
                        "provider_type": a["provider_type"],
                        "route_count": n,
                    })
            return other_accounts

        other_accounts = await db_call(
            _wizard_step4_snapshot, db, account_id, user,
        )
        return _render(templates, request, "account_wizard/step4.html", {
            "user": user, "acct": acct,
            "other_accounts": other_accounts,
            "skipped_steps": skipped_steps,
        })
    if step == 5:
        def _wizard_step5_snapshot(db, user_id) -> dict:
            """#135 phase 2 — categories + escalation prefs in one hop."""
            from email_triage.web.db import (
                list_categories, get_user_escalation_categories,
            )
            return {
                "categories": list_categories(
                    db, user_id=user_id, scope="all",
                ),
                "escalation_categories": get_user_escalation_categories(
                    db, user_id,
                ),
            }

        snap = await db_call(_wizard_step5_snapshot, db, user["id"])
        return _render(templates, request, "account_wizard/step5.html", {
            "user": user, "acct": acct,
            "categories": snap["categories"],
            "escalation_categories": snap["escalation_categories"],
            "account_email": acct.get("email_address", ""),
            "skipped_steps": skipped_steps,
        })

    return RedirectResponse("/accounts/new?step=1", status_code=303)


@router.post("/accounts/new/step1", response_class=HTMLResponse)
async def wizard_step1_submit(request: Request):
    """Create the account row + redirect to step 2."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    is_admin = user["role"] == "admin"
    templates = get_templates(request)

    name = (form.get("name") or "").strip()
    ptype = form.get("provider_type", "imap")

    if not name:
        return _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "name": name, "provider_type": ptype,
            "error": "Account name is required.",
            "default_owner_id": user["id"],
        })
    if ptype not in _PROVIDER_TYPES:
        return _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "name": name,
            "error": f"Unknown provider type: {ptype}",
            "default_owner_id": user["id"],
        })

    if is_admin and form.get("user_id"):
        owner_id = int(form["user_id"])
    else:
        owner_id = user["id"]

    # Minimal config — provider-specific fields land in step 2.
    # is_active=False so the half-configured stub does not get polled
    # by watchers / pollers / triage workers between step 1 and step 5
    # finish (item #120). Step-5 submit flips it to True via
    # ``set_account_active``. Background pollers already gate on
    # ``is_active`` (six call sites in app.py + ui.py), so the flag
    # suppresses "missing credentials" / "not authenticated" error
    # spam that fired between steps and triggered Nagios alerts on
    # the homelab monitoring path.
    from email_triage.triage_logging import is_hipaa_mode
    from email_triage.web.db import create_email_account
    hipaa_flag = None
    if not is_hipaa_mode():
        hipaa_flag = False  # operator can flip on edit page later

    def _wizard_step1_create_snapshot(db, owner_id, name, ptype, hipaa_flag):
        """#135 phase 2 — account create + wizard-progress marker in
        one threadpool hop."""
        aid = create_email_account(
            db, owner_id, name, ptype, {},
            hipaa=hipaa_flag, is_active=False,
        )
        _record_wizard_step(db, aid, 1)
        return aid

    account_id = await db_call(
        _wizard_step1_create_snapshot, db, owner_id, name, ptype, hipaa_flag,
    )

    return RedirectResponse(
        f"/accounts/new?step=2&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step2-imap", response_class=HTMLResponse)
async def wizard_step2_imap(request: Request):
    """IMAP creds save + watch start prep. Redirect to step 3."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    account_id = int(form.get("account_id") or 0)
    from email_triage.web.db import get_email_account
    # #135 phase 3 — DB-before-network: wrap in db_call so the SQLite
    # read happens off the event loop. Subsequent provider work is
    # network-dominated; the threadpool hop here is the win.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None or not can_manage_account(db, user, acct):
        return RedirectResponse("/accounts/new?step=1", status_code=303)
    if acct["provider_type"] != "imap":
        return RedirectResponse(
            f"/accounts/new?step=2&account_id={account_id}",
            status_code=303,
        )

    # Build the patch dict; pre-validate before persisting so error
    # rendering can show the unsaved state.
    host = (form.get("host") or "").strip()
    username = (form.get("username") or "").strip()
    try:
        port = int(form.get("port") or 993)
    except (TypeError, ValueError):
        port = 993
    use_ssl = "use_ssl" in form

    if not host or not username:
        # Surface the in-flight values in the form re-render even
        # though they're not persisted (operator hasn't completed
        # the entry yet).
        preview = dict(acct.get("config") or {})
        preview.update({"host": host, "port": port,
                        "username": username, "use_ssl": use_ssl})
        return _render(templates, request, "account_wizard/step2.html", {
            "user": user, "acct": {**acct, "config": preview},
            "error": "Host and username are required.",
        })

    # Adjacent helper #137 — atomic read-modify-write that
    # preserves any unrelated config keys + emits a structured-log
    # entry of which keys changed. Replaces 7-line dict-patch idiom.
    from email_triage.web.db import update_account_config_keys
    update_account_config_keys(
        db, account_id,
        host=host, port=port, username=username, use_ssl=use_ssl,
    )
    pw = form.get("password", "")
    if pw:
        secrets.set(_secret_key_for_account(account_id, "imap"), pw)

    _record_wizard_step(db, account_id, 2)
    return RedirectResponse(
        f"/accounts/new?step=3&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step2-o365", response_class=HTMLResponse)
async def wizard_step2_o365(request: Request):
    """O365 client creds save. Redirect to step 3.

    Note: full Microsoft device-code flow lands separately;
    this wizard step captures the app-registration creds and
    persists them so the next step's poll attempt has what it
    needs. Production flow would interleave a device-code prompt
    here; deferred to follow-up.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    account_id = int(form.get("account_id") or 0)
    from email_triage.web.db import get_email_account
    # #135 phase 3 — DB-before-network.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None or not can_manage_account(db, user, acct):
        return RedirectResponse("/accounts/new?step=1", status_code=303)
    if acct["provider_type"] != "office365":
        return RedirectResponse(
            f"/accounts/new?step=2&account_id={account_id}",
            status_code=303,
        )

    # Post-2026-05-10: per-account client_id / tenant_id / client_secret
    # lifted to install-level (Office365OAuthConfig). The only end-user
    # choice on this step is personal-MSA vs org tenant.
    is_personal_msa = "is_personal_msa" in form

    # Adjacent helper #137 — atomic read-modify-write per key.
    from email_triage.web.db import update_account_config_keys
    update_account_config_keys(
        db, account_id, is_personal_msa=is_personal_msa,
    )

    _record_wizard_step(db, account_id, 2)
    return RedirectResponse(
        f"/accounts/new?step=3&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step3", response_class=HTMLResponse)
async def wizard_step3_submit(request: Request):
    """Save push/poll, register the watcher, redirect to step 4.

    For IMAP: registers the IDLE watcher via WatcherManager.start().
    For Gmail: watch was already auto-started by the OAuth callback
    (sub-B). For O365: push not yet implemented; poll registration
    only.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    from email_triage.web.db import get_email_account
    account_id = int(form.get("account_id") or 0)
    # #135 phase 3 — DB-before-network (watcher start below).
    acct = await db_call(get_email_account, db, account_id)
    if acct is None or not can_manage_account(db, user, acct):
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    push_enabled = "push_enabled" in form
    poll_enabled = "poll_enabled" in form
    raw_iv = (form.get("poll_interval_minutes") or "").strip()
    try:
        from email_triage.web.db import clamp_poll_interval_minutes
        poll_interval_minutes = clamp_poll_interval_minutes(
            int(raw_iv) if raw_iv else 60,
        )
    except (TypeError, ValueError):
        poll_interval_minutes = 60

    # Adjacent helper #137 — atomic read-modify-write per key.
    from email_triage.web.db import update_account_config_keys
    update_account_config_keys(
        db, account_id,
        push_enabled=push_enabled,
        poll_enabled=poll_enabled,
        poll_interval_minutes=poll_interval_minutes,
    )

    # Auto-start watcher (IMAP IDLE; Gmail watch already started in
    # OAuth callback per sub-B). Failure is non-fatal; surfaced as
    # a banner on next step.
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    if watcher_mgr is not None and push_enabled:
        try:
            await watcher_mgr.start(account_id)
        except Exception as e:
            _log.warning(
                "Wizard step 3: watcher start failed (non-fatal)",
                account_id=account_id, error=fmt_exc(e),
            )

    _record_wizard_step(db, account_id, 3)
    return RedirectResponse(
        f"/accounts/new?step=4&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step4", response_class=HTMLResponse)
async def wizard_step4_submit(request: Request):
    """Optionally copy routes from another account. Redirect to step 5."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    from email_triage.web.db import get_email_account
    account_id = int(form.get("account_id") or 0)
    # #135 phase 3 — both fetches wrapped (route copy below is a separate hop).
    acct = await db_call(get_email_account, db, account_id)
    if acct is None or not can_manage_account(db, user, acct):
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    route_source = (form.get("route_source") or "fresh").strip()
    if route_source.startswith("copy:"):
        try:
            source_id = int(route_source.split(":", 1)[1])
        except (TypeError, ValueError):
            source_id = 0
        if source_id and source_id != account_id:
            source_acct = await db_call(get_email_account, db, source_id)
            if (
                source_acct is not None
                and can_manage_account(db, user, source_acct)
            ):
                # Copy account_routes rows from source → target.
                # Best-effort; per-row failure is logged + skipped.
                try:
                    src_rows = db.execute(
                        "SELECT category_slug, action_name, "
                        "       config_json, sort_order "
                        "FROM account_routes WHERE account_id = ? "
                        "ORDER BY sort_order",
                        (source_id,),
                    ).fetchall()
                    for r in src_rows:
                        try:
                            db.execute(
                                "INSERT INTO account_routes "
                                "(account_id, category_slug, action_name, "
                                " config_json, sort_order) "
                                "VALUES (?, ?, ?, ?, ?)",
                                (account_id, r["category_slug"],
                                 r["action_name"], r["config_json"],
                                 r["sort_order"]),
                            )
                        except Exception as e:
                            _log.warning(
                                "Wizard step 4: route copy row failed",
                                src=source_id, dst=account_id,
                                error=fmt_exc(e),
                            )
                    db.commit()
                except Exception as e:
                    _log.warning(
                        "Wizard step 4: route copy failed",
                        src=source_id, dst=account_id, error=fmt_exc(e),
                    )

    _record_wizard_step(db, account_id, 4)
    return RedirectResponse(
        f"/accounts/new?step=5&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step5", response_class=HTMLResponse)
async def wizard_step5_submit(request: Request):
    """Save digest + escalation prefs. Redirect to /dashboard with success."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    form = await request.form()
    db = get_db(request)
    from email_triage.web.db import (
        get_email_account,
        set_user_escalation_categories, list_categories,
    )
    account_id = int(form.get("account_id") or 0)
    # #135 phase 3 — DB-before-(potential)-network in this handler.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None or not can_manage_account(db, user, acct):
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    # Recipient digest — persists to account config_json.
    recipient_digest_enabled = "recipient_digest_enabled" in form
    raw_send_at = (form.get("recipient_digest_send_at") or "").strip()
    if raw_send_at and len(raw_send_at) == 5 and raw_send_at.endswith(":10"):
        try:
            h = int(raw_send_at.split(":")[0])
            recipient_digest_send_at = (
                f"{h:02d}:10" if 0 <= h <= 23 else "08:10"
            )
        except (TypeError, ValueError):
            recipient_digest_send_at = "08:10"
    else:
        recipient_digest_send_at = "08:10"

    # Adjacent helper #137 — atomic read-modify-write per key.
    from email_triage.web.db import update_account_config_keys
    update_account_config_keys(
        db, account_id,
        recipient_digest_enabled=recipient_digest_enabled,
        recipient_digest_send_at=recipient_digest_send_at,
    )

    # Escalation prefs — per-user, applies across all their accounts.
    cats = list_categories(db, user_id=user["id"], scope="all")
    selected = [
        c["slug"] for c in cats if f"escalate_{c['slug']}" in form
    ]
    try:
        set_user_escalation_categories(db, user["id"], selected)
    except Exception as e:
        _log.warning(
            "Wizard step 5: escalation prefs save failed",
            user_id=user["id"], error=fmt_exc(e),
        )

    # Wizard complete — clear the resume marker so the Resume banner
    # stops showing on the edit page.
    _clear_wizard_step(db, account_id)

    # #120: flip the account to is_active=True now that every step
    # has been touched. Step 1 created the row with is_active=False
    # so background pollers / watchers would not fire on the half-
    # configured stub between steps. With provider auth + watch +
    # categories all complete, the account is ready to triage.
    from email_triage.web.db import set_account_active
    set_account_active(db, account_id, True)

    # Build the success banner. HIPAA-mode installs get a reminder
    # that the per-account HIPAA flag can be flipped on the edit
    # page (the wizard doesn't expose that toggle to keep the flow
    # focused on first-time setup).
    from email_triage.triage_logging import is_hipaa_mode
    success_msg = (
        f"Account '{acct['name']}' is set up and watching for new mail."
    )
    if is_hipaa_mode():
        success_msg += (
            " HIPAA mode is on for this install — the account owner "
            "can adjust the per-account HIPAA flag on the edit page."
        )

    from urllib.parse import quote
    return RedirectResponse(
        f"/accounts?success={quote(success_msg)}",
        status_code=303,
    )


