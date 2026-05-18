"""Routes for the openclaw concern.

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

_log = get_logger("web.ui.openclaw")

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


@router.get("/accounts/{account_id}/openclaw/editor", response_class=HTMLResponse)
async def openclaw_editor_fragment(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Return the inline form for editing OpenClaw quiet-hours / pause."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned

    from email_triage.web.events import get_openclaw_quiet_settings

    s = await db_call(get_openclaw_quiet_settings, db, account_id)
    enabled_chk = "checked" if s["enabled"] else ""
    paused_chk = "checked" if s["paused"] else ""
    start_v = s["start_utc"] or ""
    end_v = s["end_utc"] or ""
    return HTMLResponse(
        f'<form hx-put="/accounts/{account_id}/openclaw/quiet-hours"'
        f' hx-target="#openclaw-cell-{account_id}" hx-swap="innerHTML"'
        f' style="display:inline-flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">'
        f'<label style="margin:0;"><input type="checkbox" name="enabled" {enabled_chk}> on</label>'
        f'<label style="margin:0;"><input type="checkbox" name="paused" {paused_chk}> pause</label>'
        f'<label style="margin:0;font-size:0.8rem;">quiet '
        f'<input type="time" name="start_utc" value="{start_v}" style="width:6.5rem;padding:0.1rem;margin:0;font-size:0.8rem;"></label>'
        f'<label style="margin:0;font-size:0.8rem;">→ '
        f'<input type="time" name="end_utc" value="{end_v}" style="width:6.5rem;padding:0.1rem;margin:0;font-size:0.8rem;"></label>'
        f'<button type="submit" class="outline" style="padding:0.1rem 0.4rem;margin:0;font-size:0.8rem;">Save</button>'
        f'<button type="button" class="outline secondary" style="padding:0.1rem 0.4rem;margin:0;font-size:0.8rem;"'
        f' hx-get="/accounts/{account_id}/openclaw/chip"'
        f' hx-target="#openclaw-cell-{account_id}" hx-swap="innerHTML">Cancel</button>'
        f'</form>'
    )


@router.get("/accounts/{account_id}/openclaw/chip", response_class=HTMLResponse)
async def openclaw_chip_fragment(
    request: Request, account_id: int, owned: OwnedAccount,
):
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    chip = await db_call(_render_openclaw_chip, db, account_id)
    return HTMLResponse(chip)


@router.put("/accounts/{account_id}/openclaw/quiet-hours", response_class=HTMLResponse)
async def openclaw_quiet_hours_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    # #137 phase 2 — OwnedAccount dep collapses preamble.
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
        _openclaw_quiet_save_snapshot, db, account_id, form_dict,
    )
    return HTMLResponse(chip)


# ---------------------------------------------------------------------------
# Email watches UI (#100)
# ---------------------------------------------------------------------------
#
# Per-account watches list lives on /accounts/{id}/edit?tab=watches.
# Each watch has its own editor page (mirrors the digest editor
# pattern) at /accounts/{id}/watches/{watch_id}/edit and a
# sibling save POST at /accounts/{id}/watches/{watch_id}/save.
# Test fire + delete are HTMX-driven from the panel.


