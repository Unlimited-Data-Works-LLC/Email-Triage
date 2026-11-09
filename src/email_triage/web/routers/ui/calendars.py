"""Routes for the calendars concern.

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
from email_triage.web._flash import scrub_exc  # N-179 R21_2 SSOT
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
from email_triage.web._audit import safe_audit_write
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import parse_int_or_none  # N-219c/39 R23

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.calendars")

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


@router.post("/accounts/{account_id}/calendar/disable", response_class=HTMLResponse)
async def calendar_disable(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Clear the calendar_enabled flag. Refresh token retains its scope."""
    #  phase 2 — OwnedAccount dep collapses preamble.
    # .7 — set_bool_setting is the canonical {"enabled": bool} write.
    user, acct, db, secrets = owned

    def _disable_db_work() -> str:
        """/ — flag write + chip re-render in one threadpool hop."""
        from email_triage.web.db import set_bool_setting
        set_bool_setting(db, _S.calendar_enabled(account_id), False)
        return _render_calendar_chip(db, acct)

    return HTMLResponse(await db_call(_disable_db_work))


# ---------------------------------------------------------------------------
# Calendar discovery + role-assignment table
# ---------------------------------------------------------------------------

# ─── AUDIENCE — calendar-section render helpers ─────────────
# Functions below emit HTML that HTMX-swaps into the account-edit
# Integrations tab. Audience for that page is END-USER (account
# owner / delegate / admin doing operator-side work). The
# audience-comment block at the top of templates/accounts/_edit.html
# is the contract; route-handler responses inherit it.
#
# COPY RULES (mirror feedback_audience_per_page.md):
#   - No protocol jargon (RFC numbers, ISO 8601, OData, "language
#     model"). Plain English; "AI" not "LLM".
#   - Tooltips lead with a concrete example, not an abstract
#     definition.
#   - No admin-only paths in user copy. Disabled controls speak
#     via their disabled state.
# ─────────────────────────────────────────────────────────────


@router.post(
    "/accounts/{account_id}/calendars/discover",
    response_class=HTMLResponse,
)
async def calendars_discover(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Fetch the account's calendarList from the provider, merge
    with stored selections, render the editor table for HTMX
    swap-in. No persistence — the table's Save button writes."""
    from email_triage.web.calendars import normalize_calendars

    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned

    config = get_config(request)
    google_oauth = getattr(config, "google_oauth", None)
    # db kwarg lets IMAP accounts with a configured surrogate fall
    # through to the surrogate's provider.
    # / — surrogate resolution does a SQLite read; off the loop.
    provider = await db_call(
        _create_calendar_provider_from_account,
        acct, secrets, google_oauth=google_oauth, db=db,
    )
    if provider is None:
        if acct.get("provider_type") == "imap":
            msg = (
                "This IMAP account has no calendar of its own. "
                "Pick a calendar surrogate above (an account whose "
                "provider exposes calendars) to use its calendar list."
            )
        else:
            msg = "This account's provider doesn't expose calendars."
        return HTMLResponse(_render_calendars_table(
            account_id, [], error=msg,
        ))

    try:
        try:
            discovered = await provider.list_calendars()
        finally:
            try:
                await provider.close()
            except Exception as _swallow_exc:
                _log.debug(
                    "provider/probe close failed (best-effort teardown)",
                    error=fmt_exc(_swallow_exc),
                )
    except Exception as e:
        _log.error(
            "Calendar discovery failed",
            account_id=account_id, error=fmt_exc(e),
        )
        # N-179 R21_2 (2026-07-02): scrub exception via _flash SSOT before
        # the helper renders it. Calendar discovery errors can carry OAuth
        # provider-error content.
        return HTMLResponse(_render_calendars_table(
            account_id, [], error=scrub_exc(e, purpose='provider'),
        ))

    stored = (acct.get("config") or {}).get("calendars") or []
    merged = normalize_calendars(stored, discovered)
    from email_triage.triage_logging import is_account_hipaa
    return HTMLResponse(_render_calendars_table(
        account_id, merged, hipaa=is_account_hipaa(acct),
    ))


@router.post(
    "/accounts/{account_id}/calendars/save",
    response_class=HTMLResponse,
)
async def calendars_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Persist the operator's calendar selections + role flags
    into ``email_accounts.config_json["calendars"]``."""
    from email_triage.web.calendars import parse_calendars_form
    from email_triage.web.db import update_account_config_keys

    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned

    form = await request.form()
    discovered_ids = [
        s.strip() for s in str(
            form.get("discovered_ids") or ""
        ).split(",") if s.strip()
    ]
    if not discovered_ids:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "No calendars to save — refresh the calendar list "
            "first.</small>"
        )

    # Pull display-meta from the stored row when possible so the
    # persisted entry preserves summary / primary / access_role
    # without a re-discover round-trip. Operator who Refreshes
    # then Saves immediately gets the freshest meta; operator who
    # Saves stale data keeps last-known meta.
    stored = (acct.get("config") or {}).get("calendars") or []
    discovered_meta: dict[str, dict] = {}
    for entry in stored:
        if not isinstance(entry, dict):
            continue
        cid = entry.get("id")
        if cid:
            discovered_meta[str(cid)] = {
                "summary": entry.get("summary"),
                "primary": entry.get("primary"),
                "access_role": entry.get("access_role"),
            }

    from email_triage.triage_logging import is_account_hipaa
    calendars = parse_calendars_form(
        list(form.multi_items()) if hasattr(form, "multi_items")
        else [(k, v) for k, v in form.items()],
        discovered_ids=discovered_ids,
        discovered_meta=discovered_meta,
        hipaa=is_account_hipaa(acct),
    )

    # Persist into the account's config_json under the
    # ``calendars`` key. Other config keys are preserved by
    # ``update_account_config_keys`` (atomic read-modify-write,
    # adjacent-keys-untouched).
    await db_call(
        update_account_config_keys, db, account_id, calendars=calendars,
    )

    n_enabled = sum(1 for c in calendars if c.get("enabled"))
    return HTMLResponse(
        "<small style='color:var(--pico-ins-color);'>"
        f"✓ Saved. {n_enabled} calendar"
        f"{'s' if n_enabled != 1 else ''} selected.</small>"
    )


@router.post(
    "/accounts/{account_id}/calendar/surrogate",
    response_class=HTMLResponse,
)
async def calendar_surrogate_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Persist an account's calendar-surrogate selection.

    Available to every account type — operator may want to route
    calendar ops on a Gmail mailbox through a different Gmail
    account, not just IMAP-with-no-calendar. The surrogate is
    another account (gmail_api or office365) owned by the same
    user; calendar ops on this account then use the surrogate's
    provider + this account's own role assignments.

    Form field: ``surrogate_account_id`` — int, or empty string
    to clear. Empty / unowned / wrong-provider IDs reject before
    persisting; the resolver in calendars.py is the authoritative
    check.
    """
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.web.db import update_account_config_keys

    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned

    form = await request.form()
    raw = (form.get("surrogate_account_id") or "").strip()

    # HIPAA accounts are self-only — refuse any surrogate
    # selection (set OR unchanged-but-tried). Mirrors the
    # digest recipient-mismatch guard. Audit-log the refusal
    # via record_access_event so the access log carries a
    # trace of the attempt.
    from email_triage.triage_logging import is_account_hipaa
    if raw and is_account_hipaa(acct):
        def _hipaa_refusal_audit() -> None:
            """/ — best-effort refusal audit row off the loop."""
            from email_triage.web.db import record_access_event
            safe_audit_write(
                lambda: record_access_event(
                    db,
                    actor_user_id=user.get("id"),
                    method="POST",
                    route="/accounts/{id}/calendar/surrogate",
                    account_id=account_id,
                    message_id=None,
                    status_code=403,
                    outcome="surrogate_hipaa_refused",
                    detail=(
                        f"hipaa_account=yes attempted_surrogate={raw} "
                        "reason=hipaa_self_only"
                    ),
                ),
                description=f"surrogate_hipaa_refused account_id={account_id} status=403",
                table="access_log",
                emitter="record_access_event",
            )

        await db_call(_hipaa_refusal_audit)
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "HIPAA-flagged accounts are locked to their own "
            "calendar. Surrogating to another account would "
            "bridge PHI across accounts; refused.</small>"
        )

    if not raw:
        # Clear the surrogate. Stored ``calendars`` role assignments
        # stay put — operator may want them back if they re-pick
        # the same surrogate later. ``None`` patch tells
        # ``update_account_config_keys`` to delete the key.
        await db_call(
            update_account_config_keys,
            db, account_id, calendar_surrogate_account_id=None,
        )
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "Calendar surrogate cleared. This IMAP account has "
            "no calendar until you pick a new one.</small>"
        )
    sid = parse_int_or_none(raw)  # N-219c/39 R23: SSOT
    if sid is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Invalid surrogate selection.</small>"
        )

    # Defense-in-depth via resolve_surrogate_account: enforces
    # same-owner + provider-type whitelist. We temporarily wire
    # the candidate ID into the account's config so the resolver
    # walks the same path the live factory will.
    candidate_acct = dict(acct)
    candidate_acct["config"] = {
        **(acct.get("config") or {}),
        "calendar_surrogate_account_id": sid,
    }

    def _surrogate_save_db_work() -> dict | None:
        """/ — surrogate resolution + (on success) the
        config-key write in one threadpool hop. Returns the resolved
        surrogate dict, or ``None`` when it failed validation (no
        write performed in that case).
        """
        surrogate_ = resolve_surrogate_account(db, candidate_acct)
        if surrogate_ is None:
            return None
        update_account_config_keys(
            db, account_id, calendar_surrogate_account_id=sid,
        )
        return surrogate_

    surrogate = await db_call(_surrogate_save_db_work)
    if surrogate is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "That account isn't a valid calendar surrogate. "
            "Surrogates must be Gmail or Office 365 accounts "
            "owned by you.</small>"
        )
    import html as _h
    return HTMLResponse(
        "<small style='color:var(--pico-ins-color);'>"
        f"✓ Surrogate set to "
        f"<strong>{_h.escape(surrogate.get('name') or '')}</strong>. "
        "Hit Refresh calendars to see what's available.</small>"
    )


# ---------------------------------------------------------------------------
# Outbound-webhook per-account quiet-hours / pause editor
# ---------------------------------------------------------------------------

