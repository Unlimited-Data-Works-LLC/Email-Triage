"""Routes for the outbound-webhook concern.

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
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.webhook")

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


@router.get("/accounts/{account_id}/webhook/editor", response_class=HTMLResponse)
async def webhook_editor_fragment(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Return the inline form for editing outbound-webhook quiet-hours / pause."""
    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned

    from email_triage.web.events import get_webhook_quiet_settings

    s = await db_call(get_webhook_quiet_settings, db, account_id)
    enabled_chk = "checked" if s["enabled"] else ""
    paused_chk = "checked" if s["paused"] else ""
    # N-83 (root-cause-scope): start_utc/end_utc are stored raw from a form
    # with no HH:MM validation; in this `value="..."` attribute context an
    # unescaped value like `"><script>` breaks out. The escape is INLINE at
    # each interpolation site (NOT a pre-escaped var) so the N-83
    # attribute-context pin re-flags a reverted bare `{start_v}` — vars stay
    # raw on purpose. quote=True neutralises double-quotes too.
    import html as _html
    start_v = s["start_utc"] or ""
    end_v = s["end_utc"] or ""
    return HTMLResponse(
        f'<form hx-put="/accounts/{account_id}/webhook/quiet-hours"'
        f' hx-target="#webhook-cell-{account_id}" hx-swap="innerHTML"'
        f' style="display:inline-flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">'
        f'<label style="margin:0;"><input type="checkbox" name="enabled" {enabled_chk}> on</label>'
        f'<label style="margin:0;"><input type="checkbox" name="paused" {paused_chk}> pause</label>'
        f'<label style="margin:0;font-size:0.8rem;">quiet '
        f'<input type="time" name="start_utc" value="{_html.escape(start_v, quote=True)}" style="width:6.5rem;padding:0.1rem;margin:0;font-size:0.8rem;"></label>'
        f'<label style="margin:0;font-size:0.8rem;">→ '
        f'<input type="time" name="end_utc" value="{_html.escape(end_v, quote=True)}" style="width:6.5rem;padding:0.1rem;margin:0;font-size:0.8rem;"></label>'
        f'<button type="submit" class="outline" style="padding:0.1rem 0.4rem;margin:0;font-size:0.8rem;">Save</button>'
        f'<button type="button" class="outline secondary" style="padding:0.1rem 0.4rem;margin:0;font-size:0.8rem;"'
        f' hx-get="/accounts/{account_id}/webhook/chip"'
        f' hx-target="#webhook-cell-{account_id}" hx-swap="innerHTML">Cancel</button>'
        f'</form>'
    )


@router.get("/accounts/{account_id}/webhook/chip", response_class=HTMLResponse)
async def webhook_chip_fragment(
    request: Request, account_id: int, owned: OwnedAccount,
):
    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    chip = await db_call(_render_webhook_chip, db, account_id)
    return HTMLResponse(chip)


@router.put("/accounts/{account_id}/webhook/quiet-hours", response_class=HTMLResponse)
async def webhook_quiet_hours_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned

    form = await request.form()
    # Form must be snapshotted on the loop before handing to the pool.
    form_dict = {
        "enabled": "enabled" in form,
        "paused": "paused" in form,
        "start_utc": form.get("start_utc"),
        "end_utc": form.get("end_utc"),
    }
    chip = await db_call(
        _webhook_quiet_save_snapshot, db, account_id, form_dict,
    )
    return HTMLResponse(chip)


# ---------------------------------------------------------------------------
# Email watches UI
# ---------------------------------------------------------------------------
#
# Per-account watches list lives on /accounts/{id}/edit?tab=watches.
# Each watch has its own editor page (mirrors the digest editor
# pattern) at /accounts/{id}/watches/{watch_id}/edit and a
# sibling save POST at /accounts/{id}/watches/{watch_id}/save.
# Test fire + delete are HTMX-driven from the panel.


