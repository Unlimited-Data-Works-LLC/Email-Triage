"""Routes for the wizard concern.

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
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (
    is_admin as _is_admin,  # N-222h R22 SSOT alias (local `is_admin` shadows callable)
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.wizard")

router = APIRouter()


def _wizard_fetch_and_auth(db, user, account_id):
    """/ — account fetch + can-manage check in one threadpool
    hop. Returns ``(acct, can_manage)``; ``acct`` is ``None`` when the
    row does not exist. Shared by every wizard step so the read +
    permission check are a single thread crossing.
    """
    from email_triage.web.db import get_email_account
    acct = get_email_account(db, account_id)
    if acct is None:
        return None, False
    return acct, can_manage_account(db, user, acct)


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


@router.get("/accounts/new", response_class=HTMLResponse)
async def wizard_step_dispatcher(
    request: Request,
    user: RequireUser,
    step: int = 1,
    account_id: int | None = None,
):
    """Single GET dispatcher for the wizard. Reads ?step=N and
    renders the matching template with the right context."""
    db = get_db(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")

    # Step 1 doesn't need an account_id — it's the entry point.
    if step == 1:
        def _wizard_step1_assignable(db) -> list[dict] | None:
            """ phase 2 — admin-only assignable-users roster off
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
        return await _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "assignable_users": assignable_users,
            "default_owner_id": user["id"],
        })

    # Steps 2-5 require a valid account_id the caller can manage.
    if not account_id:
        return RedirectResponse("/accounts/new?step=1", status_code=303)
    from email_triage.web.db import get_email_account

    def _wizard_acct_check(db, account_id, user) -> dict | None:
        """ phase 2 — fetch + can-manage-check in one threadpool hop."""
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
        return await _render(templates, request, "account_wizard/step2.html", {
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
        return await _render(templates, request, "account_wizard/step3.html", {
            "user": user, "acct": acct,
            "push_blocked_reason": push_blocked_reason,
            "push_enabled_default": push_enabled_default,
            "auth_success": auth_success,
            "skipped_steps": skipped_steps,
        })
    if step == 4:
        def _wizard_step4_snapshot(db, account_id, user) -> list[dict]:
            """ phase 2 — copy-from candidate accounts in one
            threadpool hop."""
            from email_triage.web.db import list_email_accounts
            # N-109: copy-from picker (step 4 radios) — a human picks a source
            # account to clone settings from; a deactivated one is a footgun.
            all_accts = list_email_accounts(db, active_only=True)
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
        return await _render(templates, request, "account_wizard/step4.html", {
            "user": user, "acct": acct,
            "other_accounts": other_accounts,
            "skipped_steps": skipped_steps,
        })
    if step == 5:
        def _wizard_step5_snapshot(db, user_id) -> dict:
            """ phase 2 — categories + escalation prefs in one hop."""
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
        # census run17  — alias the SSOT off the "account_email" context key.
        from email_triage.db.accounts import account_email as account_email_ssot
        return await _render(templates, request, "account_wizard/step5.html", {
            "user": user, "acct": acct,
            "categories": snap["categories"],
            "escalation_categories": snap["escalation_categories"],
            # census run17  — account_email SSOT, not the open-coded key.
            # (acct here IS loader-built via get_email_account, so the
            # resolved value is identical; the SSOT call removes the bypass
            # and is robust if the source ever changes.)
            "account_email": account_email_ssot(acct),
            "skipped_steps": skipped_steps,
        })

    return RedirectResponse("/accounts/new?step=1", status_code=303)


@router.post("/accounts/new/step1", response_class=HTMLResponse)
async def wizard_step1_submit(request: Request, user: RequireUser):
    """Create the account row + redirect to step 2."""
    form = await request.form()
    db = get_db(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")
    templates = get_templates(request)

    name = (form.get("name") or "").strip()
    ptype = form.get("provider_type", "imap")

    if not name:
        return await _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "name": name, "provider_type": ptype,
            "error": "Account name is required.",
            "default_owner_id": user["id"],
        })
    if ptype not in _PROVIDER_TYPES:
        return await _render(templates, request, "account_wizard/step1.html", {
            "user": user, "is_admin": is_admin,
            "name": name,
            "error": f"Unknown provider type: {ptype}",
            "default_owner_id": user["id"],
        })

    if is_admin and form.get("user_id"):
        owner_id = _safe_int(form["user_id"], user["id"])
    else:
        owner_id = user["id"]

    # Minimal config — provider-specific fields land in step 2.
    # is_active=False so the half-configured stub does not get polled
    # by watchers / pollers / triage workers between step 1 and step 5
    # finish (item ). Step-5 submit flips it to True via
    # ``set_account_active``. Background pollers already gate on
    # ``is_active`` (six call sites in app.py + ui.py), so the flag
    # suppresses "missing credentials" / "not authenticated" error
    # spam that fired between steps and triggered the monitoring system alerts on
    # the homelab monitoring path.
    from email_triage.triage_logging import is_hipaa_mode
    from email_triage.web.db import create_email_account
    hipaa_flag = None
    if not is_hipaa_mode():
        hipaa_flag = False  # operator can flip on edit page later

    def _wizard_step1_create_snapshot(db, owner_id, name, ptype, hipaa_flag):
        """ phase 2 — account create + wizard-progress marker in
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
async def wizard_step2_imap(request: Request, user: RequireUser):
    """IMAP creds save + watch start prep. Redirect to step 3."""
    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    account_id = _safe_int(form.get("account_id"), 0)
    # / — DB-before-network: fetch + can-manage in one hop.
    acct, can_manage = await db_call(
        _wizard_fetch_and_auth, db, user, account_id,
    )
    if acct is None or not can_manage:
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
        port = _safe_int(form.get("port"), 993)
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
        return await _render(templates, request, "account_wizard/step2.html", {
            "user": user, "acct": {**acct, "config": preview},
            "error": "Host and username are required.",
        })

    pw = form.get("password", "")

    def _step2_imap_db_work() -> None:
        """/ — config-key write + secret store + wizard-step
        marker in one threadpool hop.
        """
        # Adjacent helper  — atomic read-modify-write that
        # preserves any unrelated config keys + emits a structured-log
        # entry of which keys changed. Replaces 7-line dict-patch idiom.
        from email_triage.web.db import update_account_config_keys
        from email_triage.web.routers._secret_write import set_secret_if_changed
        update_account_config_keys(
            db, account_id,
            host=host, port=port, username=username, use_ssl=use_ssl,
        )
        # Blank preserves (nothing to store yet on a fresh account); routes
        # through the _secret_write SSOT and pairs with the readonly-until-
        # focus password field so a password-manager can't autofill the
        # operator's login password into the IMAP app-password slot.
        set_secret_if_changed(
            secrets, _secret_key_for_account(account_id, "imap"), pw,
        )
        _record_wizard_step(db, account_id, 2)

    await db_call(_step2_imap_db_work)
    return RedirectResponse(
        f"/accounts/new?step=3&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step2-o365", response_class=HTMLResponse)
async def wizard_step2_o365(request: Request, user: RequireUser):
    """O365 client creds save. Redirect to step 3.

    Note: full Microsoft device-code flow lands separately;
    this wizard step captures the app-registration creds and
    persists them so the next step's poll attempt has what it
    needs. Production flow would interleave a device-code prompt
    here; deferred to follow-up.
    """

    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    account_id = _safe_int(form.get("account_id"), 0)
    # / — DB-before-network: fetch + can-manage in one hop.
    acct, can_manage = await db_call(
        _wizard_fetch_and_auth, db, user, account_id,
    )
    if acct is None or not can_manage:
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

    def _step2_o365_db_work() -> None:
        """/ — config-key write + wizard-step marker in one
        threadpool hop.
        """
        # Adjacent helper  — atomic read-modify-write per key.
        from email_triage.web.db import update_account_config_keys
        update_account_config_keys(
            db, account_id, is_personal_msa=is_personal_msa,
        )
        _record_wizard_step(db, account_id, 2)

    await db_call(_step2_o365_db_work)
    return RedirectResponse(
        f"/accounts/new?step=3&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step3", response_class=HTMLResponse)
async def wizard_step3_submit(request: Request, user: RequireUser):
    """Save push/poll, register the watcher, redirect to step 4.

    For IMAP: registers the IDLE watcher via WatcherManager.start().
    For Gmail: watch was already auto-started by the OAuth callback
    (sub-B). For O365: push not yet implemented; poll registration
    only.
    """
    form = await request.form()
    db = get_db(request)
    account_id = _safe_int(form.get("account_id"), 0)
    # / — DB-before-network (watcher start below).
    acct, can_manage = await db_call(
        _wizard_fetch_and_auth, db, user, account_id,
    )
    if acct is None or not can_manage:
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    push_enabled = "push_enabled" in form
    poll_enabled = "poll_enabled" in form
    raw_iv = (form.get("poll_interval_minutes") or "").strip()
    # N-219c/27 R23: parse_int_or_none SSOT; malformed input → 60min default.
    from email_triage.web.db import clamp_poll_interval_minutes
    _iv = parse_int_or_none(raw_iv) if raw_iv else 60
    poll_interval_minutes = clamp_poll_interval_minutes(_iv if _iv is not None else 60)

    # Adjacent helper  — atomic read-modify-write per key.
    # / — config write off the loop, before the watcher start.
    from email_triage.web.db import update_account_config_keys
    await db_call(
        update_account_config_keys,
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

    await db_call(_record_wizard_step, db, account_id, 3)
    return RedirectResponse(
        f"/accounts/new?step=4&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step4", response_class=HTMLResponse)
async def wizard_step4_submit(request: Request, user: RequireUser):
    """Optionally copy routes from another account. Redirect to step 5."""
    form = await request.form()
    db = get_db(request)
    account_id = _safe_int(form.get("account_id"), 0)
    # / — fetch + can-manage in one hop.
    acct, can_manage = await db_call(
        _wizard_fetch_and_auth, db, user, account_id,
    )
    if acct is None or not can_manage:
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    route_source = (form.get("route_source") or "fresh").strip()

    def _step4_db_work() -> None:
        """/ — optional route-copy (source fetch + permission
        check + per-row INSERT loop) + wizard-step marker, ALL in one
        threadpool hop. The N-row copy loop is one thread crossing.
        """
        from email_triage.web.db import get_email_account
        if route_source.startswith("copy:"):
            source_id = bounded_int(  # N-219c R23: SSOT
                route_source.split(":", 1)[1], default=0,
            )
            if source_id and source_id != account_id:
                source_acct = get_email_account(db, source_id)
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
                                    "(account_id, category_slug, "
                                    " action_name, config_json, "
                                    " sort_order) "
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
                            src=source_id, dst=account_id,
                            error=fmt_exc(e),
                        )

        _record_wizard_step(db, account_id, 4)

    await db_call(_step4_db_work)
    return RedirectResponse(
        f"/accounts/new?step=5&account_id={account_id}",
        status_code=303,
    )


@router.post("/accounts/new/step5", response_class=HTMLResponse)
async def wizard_step5_submit(request: Request, user: RequireUser):
    """Save digest + escalation prefs. Redirect to /dashboard with success."""
    form = await request.form()
    db = get_db(request)
    account_id = _safe_int(form.get("account_id"), 0)
    # / — fetch + can-manage in one hop.
    acct, can_manage = await db_call(
        _wizard_fetch_and_auth, db, user, account_id,
    )
    if acct is None or not can_manage:
        return RedirectResponse("/accounts/new?step=1", status_code=303)

    # Recipient digest — persists to account config_json.
    recipient_digest_enabled = "recipient_digest_enabled" in form
    raw_send_at = (form.get("recipient_digest_send_at") or "").strip()
    if raw_send_at and len(raw_send_at) == 5 and raw_send_at.endswith(":10"):
        # N-219c/47 R23: parse_int_or_none + explicit fallback preserves the
        # "invalid hour" vs "hour-out-of-range" collapse to "08:10".
        h = parse_int_or_none(raw_send_at.split(":")[0])
        if h is not None and 0 <= h <= 23:
            recipient_digest_send_at = f"{h:02d}:10"
        else:
            recipient_digest_send_at = "08:10"
    else:
        recipient_digest_send_at = "08:10"

    # The set of escalate-checkbox keys present in the posted form.
    # Snapshotted on the loop so the threadpool helper only does DB
    # work (form membership is needed to compute ``selected``).
    escalate_keys = {
        k for k in form.keys() if str(k).startswith("escalate_")
    }

    def _step5_db_work() -> None:
        """/ — config write + escalation-prefs read+write +
        wizard-step clear + activate, ALL in one threadpool hop. No
        network sits between these calls.
        """
        # Adjacent helper  — atomic read-modify-write per key.
        from email_triage.web.db import (
            update_account_config_keys,
            set_user_escalation_categories, list_categories,
            set_account_active,
        )
        update_account_config_keys(
            db, account_id,
            recipient_digest_enabled=recipient_digest_enabled,
            recipient_digest_send_at=recipient_digest_send_at,
        )

        # Escalation prefs — per-user, applies across all accounts.
        cats = list_categories(db, user_id=user["id"], scope="all")
        selected = [
            c["slug"] for c in cats
            if f"escalate_{c['slug']}" in escalate_keys
        ]
        try:
            set_user_escalation_categories(db, user["id"], selected)
        except Exception as e:
            _log.warning(
                "Wizard step 5: escalation prefs save failed",
                user_id=user["id"], error=fmt_exc(e),
            )

        # Wizard complete — clear the resume marker so the Resume
        # banner stops showing on the edit page.
        _clear_wizard_step(db, account_id)

        # : flip the account to is_active=True now that every step
        # has been touched. Step 1 created the row with is_active=False
        # so background pollers / watchers would not fire on the half-
        # configured stub between steps. With provider auth + watch +
        # categories all complete, the account is ready to triage.
        set_account_active(db, account_id, True)

    await db_call(_step5_db_work)

    # Loop-5 census: ingestion ACTUATORS (WatcherManager.start, the push
    # consumers, both renewers) now fail-closed on ``is_active``. Step 3
    # attempted ``watcher_mgr.start()`` while the row was still
    # is_active=False (the step-1 stub state), so that start is now
    # (correctly) refused. Activation is the right moment to start
    # ingestion — route it through the same funnel the edit-save handler
    # uses so the account begins watching/polling immediately, without
    # waiting for restore_from_settings on the next process restart.
    # Non-fatal: a start failure surfaces on the dashboard chip, same as
    # the old step-3 try/except.
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    if watcher_mgr is not None:
        try:
            await watcher_mgr.apply_account_active_state(account_id, True)
        except Exception as e:
            _log.warning(
                "Wizard step 5: ingestion start failed (non-fatal)",
                account_id=account_id, error=fmt_exc(e),
            )

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

    # N-232b R25 (post-N-232 Arm-A widen): route through the flash-key
    # SSOT `msg_qs`. Pre-fix, the wizard used `success=` — a bespoke
    # key with no reader-side decode (`read_flash` handles `msg`/`err`
    # only), so the destination `/accounts` page silently dropped the
    # success message.
    from email_triage.web.routers._redirect import msg_qs
    return RedirectResponse(
        f"/accounts?{msg_qs(success_msg)}",
        status_code=303,
    )


