"""Routes for the digests concern.

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

_log = get_logger("web.ui.digests")

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


@router.post("/accounts/{account_id}/digest/schedule/add", response_class=HTMLResponse)
async def digest_schedule_add(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Add a new digest schedule for an account."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    form = await request.form()
    local_time = form.get("schedule_time", "07:00")
    category = form.get("category", "newsletters")
    tz_offset = int(form.get("tz_offset", "0"))
    format_prompt = form.get("format_prompt", "").strip()

    # #63 — scheduled-digest parity with on-demand. All optional;
    # legacy schedules with missing fields use on-demand defaults.
    source_folder = form.get("source_folder", "").strip()
    search_filter = form.get("search_filter", "today").strip() or "today"
    html_template = form.get("html_template", "")
    recipient_mode = form.get("recipient_mode", "back_to_account").strip() or "back_to_account"
    recipient_custom = form.get("recipient_custom", "").strip()
    delete_originals = form.get("delete_originals") == "1"
    try:
        limit = int(form.get("limit", "25"))
    except (TypeError, ValueError):
        limit = 25

    # #72 — cadence + days-of-week. cadence='daily' is the legacy
    # default. cadence='weekly' requires at least one weekday checked.
    cadence, days_of_week = _parse_cadence_form(form)

    # Convert local time to UTC for storage.
    time_utc = _local_time_to_utc(local_time, tz_offset)

    new_entry = {
        "time_utc": time_utc,
        "category": category,
        "enabled": True,
        "format_prompt": format_prompt,
        "source_folder": source_folder,
        "search_filter": search_filter,
        "html_template": html_template,
        "recipient_mode": recipient_mode,
        "recipient_custom": recipient_custom,
        "limit": limit,
        "delete_originals": delete_originals,
        "cadence": cadence,
        "days_of_week": days_of_week,
    }

    schedules = await db_call(
        _digest_schedule_add_snapshot, db, account_id, new_entry,
    )
    return _render_digest_schedules(templates, request, acct, schedules)


@router.post("/accounts/{account_id}/digest/toggle/{idx}", response_class=HTMLResponse)
async def digest_schedule_toggle(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Toggle a digest schedule on/off."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    schedules = await db_call(
        _digest_schedule_toggle_snapshot, db, account_id, idx,
    )
    return _render_digest_schedules(templates, request, acct, schedules)


@router.post("/accounts/{account_id}/digest/reschedule/{idx}", response_class=HTMLResponse)
async def digest_schedule_reschedule(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Change the time of an existing digest schedule.

    Accepts the new local time + the browser's UTC offset and stores the
    corresponding UTC time.  Category and format_prompt are preserved.
    """
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    form = await request.form()
    local_time = form.get("schedule_time", "").strip()
    tz_offset = int(form.get("tz_offset", "0"))

    if not local_time or ":" not in local_time:
        schedules = await db_call(_load_digest_schedules, db, account_id)
        return _render_digest_schedules(
            templates, request, acct, schedules,
            flash_msg="Invalid time.",
        )

    new_utc = _local_time_to_utc(local_time, tz_offset)

    status, schedules = await db_call(
        _digest_schedule_reschedule_snapshot, db, account_id, idx, new_utc,
    )
    if status == "not_found":
        return HTMLResponse("Schedule not found", status_code=404)
    if status == "collision":
        return _render_digest_schedules(
            templates, request, acct, schedules,
            flash_msg="Another schedule already runs at that time for this category.",
        )

    _log.info(
        "Digest rescheduled",
        account=acct["name"],
        idx=idx,
        new_time_utc=new_utc,
    )
    return _render_digest_schedules(
        templates, request, acct, schedules,
        flash_msg=f"Rescheduled to {local_time} (local).",
    )


@router.get("/accounts/{account_id}/digest/edit/{idx}", response_class=HTMLResponse)
async def digest_schedule_edit_form(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Render the edit form for one schedule (HTMX swap target)."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    snap = await db_call(
        _digest_schedule_edit_form_snapshot, db, account_id, idx,
        acct.get("user_id"),
    )
    if snap is None:
        return HTMLResponse("Schedule not found", status_code=404)

    return _render(templates, request, "accounts/_digest_schedule_edit.html", {
        "acct": acct,
        "sched": snap["sched"],
        "idx": idx,
        "categories": snap["categories"],
    })


@router.post("/accounts/{account_id}/digest/edit/{idx}", response_class=HTMLResponse)
async def digest_schedule_edit_save(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Persist edits to one schedule. Mirrors digest_schedule_add field set."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    form = await request.form()
    local_time = form.get("schedule_time", "07:00")
    tz_offset = int(form.get("tz_offset", "0"))
    new_utc = _local_time_to_utc(local_time, tz_offset)

    try:
        limit = int(form.get("limit", "25"))
    except (TypeError, ValueError):
        limit = 25

    cadence, days_of_week = _parse_cadence_form(form)

    new_entry_partial = {
        "time_utc": new_utc,
        "category": form.get("category", "newsletters"),
        "format_prompt": form.get("format_prompt", "").strip(),
        "source_folder": form.get("source_folder", "").strip(),
        "search_filter": form.get("search_filter", "today").strip() or "today",
        "html_template": form.get("html_template", ""),
        "recipient_mode": form.get("recipient_mode", "back_to_account").strip() or "back_to_account",
        "recipient_custom": form.get("recipient_custom", "").strip(),
        "limit": limit,
        "delete_originals": form.get("delete_originals") == "1",
        "cadence": cadence,
        "days_of_week": days_of_week,
    }

    status, schedules = await db_call(
        _digest_schedule_edit_save_snapshot, db, account_id, idx, new_entry_partial,
    )
    if status == "not_found":
        return HTMLResponse("Schedule not found", status_code=404)
    _log.info(
        "Digest schedule edited",
        account=acct.get("name", ""), idx=idx,
        time_utc=new_utc, category=schedules[idx]["category"],
        cadence=cadence, days_of_week=days_of_week,
    )
    return _render_digest_schedules(
        templates, request, acct, schedules,
        flash_msg="Schedule updated.",
    )


@router.get("/accounts/{account_id}/digest/schedules", response_class=HTMLResponse)
async def digest_schedules_render(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Re-render the schedules table (HTMX target for the edit-form Cancel button)."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    schedules = await db_call(_load_digest_schedules, db, account_id)
    return _render_digest_schedules(templates, request, acct, schedules)


@router.post("/accounts/{account_id}/digest/run/{idx}", response_class=HTMLResponse)
async def digest_schedule_run_now(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Trigger a digest schedule to run immediately (out of band).

    Spawns the digest task in the background so the HTTP response returns
    quickly; the user sees the draft appear in their mailbox when the LLM
    and provider round-trips finish.
    """
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)
    config = get_config(request)

    schedules = await db_call(_load_digest_schedules, db, account_id)
    if not (0 <= idx < len(schedules)):
        return HTMLResponse("Schedule not found", status_code=404)

    schedule = schedules[idx]

    # Fire-and-forget — the scheduler function is async and self-contained.
    from email_triage.web.app import _run_scheduled_digest
    asyncio.create_task(
        _run_scheduled_digest(db, config, secrets, acct, schedule),
        name=f"digest-run-now-{account_id}-{idx}",
    )

    _log.info(
        "Digest run-now triggered",
        account=acct["name"], category=schedule.get("category"),
    )
    flash = (
        f"Digest started for '{schedule.get('category')}'. "
        "Check your Inbox in a moment."
    )
    return _render_digest_schedules(templates, request, acct, schedules, flash_msg=flash)


@router.delete("/accounts/{account_id}/digest/schedule/{idx}", response_class=HTMLResponse)
async def digest_schedule_delete(
    request: Request, account_id: int, idx: int,
    owned: OwnedAccount,
):
    """Delete a digest schedule."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    schedules = await db_call(
        _digest_schedule_delete_snapshot, db, account_id, idx,
    )
    return _render_digest_schedules(templates, request, acct, schedules)


@router.post("/accounts/{account_id}/digest/save-config", response_class=HTMLResponse)
async def digest_save_config(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Save digest format preferences for an account (Advanced section)."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    is_admin = user["role"] == "admin"

    from email_triage.web.db import set_setting

    form = await request.form()
    config = {
        "format_prompt": form.get("format_prompt", ""),
        "delete_originals": form.get("delete_originals") == "1",
    }
    # #135 phase 2 — settings write off the loop.
    await db_call(set_setting, db, _S.digest(account_id), config)

    return HTMLResponse(
        '<small style="color:var(--pico-ins-color);">Digest preferences saved.</small>'
    )


@router.post("/accounts/{account_id}/digest/generate", response_class=HTMLResponse)
async def digest_generate(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Generate a newsletter digest for an account."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    from email_triage.web.db import list_account_routes

    form = await request.form()
    category = form.get("category", "newsletters")
    source_folder = form.get("source_folder", "").strip()
    format_prompt = form.get("format_prompt", "")
    delete_originals = form.get("delete_originals") == "1"
    # Dry-run flag inverts the default: submitting the form means
    # "generate + deliver" unless this box is checked. Preview shows
    # either way; delivery is gated on NOT dry_run.
    dry_run = form.get("dry_run") == "1"
    deliver = not dry_run
    recipient_mode = form.get("recipient_mode", "back_to_account")
    recipient_custom = form.get("recipient_custom", "").strip()
    limit = int(form.get("limit", "25"))
    # Search filter — preset dropdown. Operator picks via the form.
    # Default to "today" (the pre-2026-04-23 behavior) so an accidental
    # submit doesn't silently widen scope. Presets map to specific IMAP
    # / Gmail search criteria.
    search_filter = form.get("search_filter", "today")
    # Custom HTML template for the digest body. If empty, the default
    # minimal template from digest.py is used. Textarea renders the
    # default pre-filled so the user can review + edit.
    html_template = form.get("html_template", "")

    # Find the source folder from the route if not explicitly specified.
    # #135 phase 3 — DB read happens before the digest LLM/SMTP work below.
    if not source_folder:
        routes = await db_call(list_account_routes, db, account_id)
        for r in routes:
            if r["category"] == category:
                for a in r.get("actions", []):
                    act_name = a.get("action", "")
                    if act_name == "move":
                        cfg = a.get("config", {})
                        fm = cfg.get("folder_map", {})
                        source_folder = fm.get(category, "")
                        break

    try:
        provider = _create_provider_from_account(acct, secrets)

        # Select the source folder if specified, otherwise search INBOX.
        # Gmail doesn't have folders per se — labels do the job. If the
        # provider doesn't support select_folder (Gmail), the label is
        # added to the search query below instead.
        _folder_selected = False
        if source_folder and hasattr(provider, "select_folder"):
            try:
                await provider.select_folder(source_folder)
                _folder_selected = True
            except Exception as _sel_err:
                _log.warning(
                    "Digest: select_folder failed, falling back to default mailbox",
                    account=acct.get("name", ""),
                    source_folder=source_folder,
                    error=str(_sel_err),
                )

        # Build IMAP-style query from the preset dropdown. IMAP providers
        # pass these verbatim; Gmail API translates is:unread / SINCE ...
        # into Gmail's q= syntax separately (see provider.search).
        from datetime import date, timedelta
        _today = date.today().strftime("%d-%b-%Y")
        if search_filter == "unread_week":
            _week_ago = (date.today() - timedelta(days=7)).strftime("%d-%b-%Y")
            query = f"UNSEEN SINCE {_week_ago}"
        elif search_filter == "unread_today":
            query = f"UNSEEN SINCE {_today}"
        else:
            # Default: "today" — whatever arrived today, read or unread.
            query = f"SINCE {_today}"

        # Gmail has no folder select — pin the source folder as a
        # label in the query itself so the scope matches. Safe even
        # if the provider's translator later remaps the rest (Gmail
        # label: syntax passes through unchanged).
        if source_folder and not _folder_selected:
            # Quote labels containing spaces.
            _label = source_folder
            if " " in _label:
                _label = f'"{_label}"'
            query = f"label:{_label} {query}"

        _log.info(
            "Digest search", account=acct.get("name", ""), category=category,
            source_folder=source_folder or "<auto>",
            folder_selected=_folder_selected,
            search_filter=search_filter, query=query,
        )
        uids = await provider.search(query, limit=limit)
        _log.info(
            "Digest search result", account=acct.get("name", ""),
            query=query, uid_count=len(uids),
        )

        if not uids:
            await provider.close()
            return _render(templates, request, "accounts/_digest_result.html", {
                "no_messages": True,
            })

        # Fetch all messages.
        from email_triage.triage_logging import is_account_hipaa
        _hipaa = is_account_hipaa(acct)
        messages = []
        for uid in uids:
            try:
                msg = await provider.fetch_message(uid)
                msg.hipaa = _hipaa
                messages.append(msg)
            except Exception as e:
                _log.warning("Failed to fetch message for digest",
                             uid=uid, error=fmt_exc(e))

        if not messages:
            await provider.close()
            return _render(templates, request, "accounts/_digest_result.html", {
                "no_messages": True,
            })

        # Build the classifier for article extraction.
        config = get_config(request)
        classifier = _build_classifier_from_config(config)

        # Generate the digest.
        from email_triage.actions.digest import generate_digest
        digest_html, article_count, source_count = await generate_digest(
            provider, classifier, messages,
            delete_originals=delete_originals,
            signature_template=config.summary_email.signature,
            category=category,
            account=acct.get("name", ""),
            html_template=html_template,
        )

        # Deliver the digest if requested. Prefer inbox delivery (appears
        # as unread mail); fall back to draft creation when the provider
        # doesn't support inbox delivery.
        draft_created = False
        draft_folder = ""
        if deliver and article_count > 0:
            from datetime import datetime as _datetime
            from email_triage.mail_headers import (
                X_EMAIL_TRIAGE_HEADER, build_triage_header,
            )
            from email_triage.triage_logging import is_account_hipaa
            from email_triage.actions.digest import _category_title
            # Subject shape: "Your Daily Newsletter Digest — Thursday,
            # April 23, 2026". Local tz to match the date_str in the
            # body. %d gives zero-padded day which is fine across every
            # mail client we've tested (Apple Mail, Gmail web/mobile,
            # Thunderbird, Outlook).
            _now = _datetime.now().astimezone()
            subject = (
                f"Your Daily {_category_title(category)} Digest \u2014 "
                f"{_now.strftime('%A, %B %d, %Y')}"
            )
            # Resolve recipient (HIPAA-aware, server-side enforced).
            _hipaa_flag = is_account_hipaa(acct)
            destination, eff_mode, _warn = _resolve_digest_recipient(
                acct, user.get("email", ""), recipient_mode, recipient_custom,
                hipaa=_hipaa_flag,
            )
            if _warn:
                _log.warning(
                    "Digest recipient down-shifted",
                    account=acct.get("name", ""),
                    requested_mode=recipient_mode,
                    effective_mode=eff_mode,
                    reason=_warn,
                )

            _digest_headers = {
                X_EMAIL_TRIAGE_HEADER: build_triage_header(
                    "digest",
                    category=category,
                    account=acct.get("name", ""),
                    hipaa=_hipaa_flag,
                ),
            }

            # From-header routing: system-generated digests use the
            # configured SMTP identity (triage system), NOT the
            # mailbox owner. If SMTP isn't configured, leave provider
            # default (mailbox's own address) — better than a header
            # that won't clear SPF.
            config = get_config(request)
            _smtp = getattr(config, "smtp", None)
            _from_addr = getattr(_smtp, "from_addr", "") if _smtp else ""
            _from_name = getattr(_smtp, "from_name", "") if _smtp else ""
            _reply_to = user.get("email", "") or None

            _mechanism = "none"
            try:
                if eff_mode == "back_to_account":
                    # Land directly in the source mailbox. The cosmetic
                    # To: header the user sees = the mailbox's own addr.
                    if hasattr(provider, "deliver_to_inbox"):
                        await provider.deliver_to_inbox(
                            to=[destination], subject=subject, body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        draft_created = True
                        draft_folder = "Inbox"
                        _mechanism = "deliver_to_inbox"
                    else:
                        await provider.create_draft(
                            to=[destination], subject=subject, body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        draft_created = True
                        draft_folder = "Drafts"
                        _mechanism = "create_draft"
                else:
                    # External recipient — use SMTP if configured,
                    # else fall back to a draft in the source account.
                    if _from_addr and _smtp and getattr(_smtp, "host", ""):
                        from email_triage.web.auth import smtp_send_digest
                        secrets = get_secrets(request)
                        _pw = secrets.get("SMTP_PASSWORD") or ""
                        smtp_send_digest(
                            smtp_host=_smtp.host,
                            smtp_port=_smtp.port,
                            smtp_user=_smtp.username,
                            smtp_password=_pw,
                            from_addr=_from_addr,
                            from_name=_from_name,
                            to_addr=destination,
                            reply_to=_reply_to or "",
                            subject=subject,
                            html_body=digest_html,
                            use_tls=_smtp.use_tls,
                            extra_headers=_digest_headers,
                        )
                        draft_created = True
                        draft_folder = "SMTP"
                        _mechanism = "smtp"
                    else:
                        # SMTP not configured — best we can do is drop
                        # a draft in the source mailbox, addressed to
                        # the external recipient. The operator reviews
                        # it and sends by hand.
                        await provider.create_draft(
                            to=[destination], subject=subject, body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        draft_created = True
                        draft_folder = "Drafts"
                        _mechanism = "create_draft"
            except NotImplementedError:
                try:
                    await provider.create_draft(
                        to=[destination], subject=subject, body=digest_html,
                        extra_headers=_digest_headers,
                        from_addr=_from_addr or None,
                        from_name=_from_name or None,
                        reply_to=_reply_to,
                    )
                    draft_created = True
                    draft_folder = "Drafts"
                    _mechanism = "create_draft"
                except Exception as e:
                    _log.warning("Digest delivery failed (draft fallback)", error=fmt_exc(e))
            except Exception as e:
                _log.warning("Digest delivery failed", error=fmt_exc(e))

            if draft_created:
                _log.info(
                    "Digest delivered",
                    account=acct.get("name", ""),
                    category=category,
                    recipient_mode=eff_mode,
                    recipient=destination,
                    destination_folder=draft_folder,
                    mechanism=_mechanism,
                    subject=subject,
                    article_count=article_count,
                    source_count=source_count,
                    provider=getattr(provider, "name", ""),
                )

        await provider.close()

        # Save config for next time.
        from email_triage.web.db import set_setting
        set_setting(db, _S.digest(account_id), {
            "format_prompt": format_prompt,
            "delete_originals": delete_originals,
            "category": category,
            "search_filter": search_filter,
            "html_template": html_template,
            "recipient_mode": recipient_mode,
            "recipient_custom": recipient_custom,
        })

        return _render(templates, request, "accounts/_digest_result.html", {
            "digest_html": digest_html,
            "article_count": article_count,
            "source_count": source_count,
            "message_count": len(messages),
            "draft_created": draft_created,
            "draft_folder": draft_folder,
            "deleted_originals": delete_originals,
        })

    except Exception as e:
        _log.error("Digest generation failed", error=fmt_exc(e))
        return _render(templates, request, "accounts/_digest_result.html", {
            "error": fmt_exc(e),
        })


# ---------------------------------------------------------------------------
# IMAP IDLE Watch — start / stop / status
# ---------------------------------------------------------------------------

