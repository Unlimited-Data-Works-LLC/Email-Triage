"""Routes for the accounts concern.

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

from email_triage.web._flash import scrub_exc  # N-179 R21_2 sub-3 SSOT
from email_triage.web.error_html import error_chip

from email_triage._isotime import to_utc_iso
from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_administer_account, can_manage_account
from email_triage.web import settings_keys as _S
from email_triage.mail_headers import canonical_email  # N-346 partial 4 R31
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
    RequireUser,
    RequireUserFragment,
    get_session_secret,
    is_admin as _is_admin,  # N-222g R22 SSOT — local var `is_admin` shadows the callable, so import under alias
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT
from email_triage._int_utils import parse_int_or_none  # N-219c R23

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.accounts")

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


# ---------------------------------------------------------------------------
#  Wave 2-α I6 — per-account style-learning backend selector helper.
# ---------------------------------------------------------------------------

def _build_ai_backend_selector_context(
    db, acct: dict,
) -> tuple[list[dict], str]:
    """Return the dropdown options + status-chip string for one account.

    Pure-DB helper so the route handler stays lean. Filter:

      * **HIPAA account (per-account flag OR system mode):** only
        ``enabled=1 AND baa_certified=1 AND baa_expires_at > today``.
        These are the only backends the admin has confirmed are
        legally allowed to handle PHI.
      * **Non-HIPAA account:** ``enabled=1`` — every enabled row, BAA
        certified or not.

    Status chip describes the SELECTED backend (or the install
    default when the FK is NULL). Plain-English copy per
    `feedback_audience_per_page.md` — no admin-path mentions, no
    protocol jargon.
    """
    from datetime import date

    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import (
        get_account_style_learning_backend,
        list_ai_backends,
    )

    is_hipaa = is_account_hipaa(acct)
    today_iso = date.today().isoformat()
    rows = list_ai_backends(db, enabled_only=True)
    options: list[dict] = []
    for r in rows:
        if is_hipaa:
            if not r.get("baa_certified"):
                continue
            exp = r.get("baa_expires_at")
            if not exp or str(exp) <= today_iso:
                continue
        options.append({
            "id": r["id"],
            "name": r["name"],
            "type": r["type"],
            "baa_certified": bool(r.get("baa_certified")),
            "baa_expires_at": r.get("baa_expires_at"),
        })

    # Chip describing the currently-selected backend.
    selected_id = acct.get("style_learning_backend_id")
    if selected_id is None:
        chip = "Using the install default (local)."
    else:
        sel = get_account_style_learning_backend(db, acct["id"])
        if sel is None:
            chip = (
                "Selected backend no longer exists; using the install "
                "default."
            )
        else:
            sel_exp = sel.get("baa_expires_at")
            if sel.get("baa_certified") and sel_exp:
                # N-263b R31 fromisoformat sweep — route through
                # `_isotime.parse_iso_date` SSOT (returns None on
                # unparseable, behavior-preserving vs prior try/except).
                from email_triage._isotime import parse_iso_date
                sel_d = parse_iso_date(sel_exp)
                if sel_d is None:
                    # Unparseable expiry — fall back to the "in force"
                    # copy (same posture as the pre-N-263b try/except).
                    chip = f"Vendor agreement in force until {sel_exp}."
                else:
                    days = (sel_d - date.today()).days
                    if days < 0:
                        chip = (
                            f"Vendor agreement expired on {sel_exp} — "
                            "this account uses the install default "
                            "until the admin renews."
                        )
                    elif days <= 7:
                        chip = (
                            f"Vendor agreement expires in {days} days "
                            f"({sel_exp}) — renew soon."
                        )
                    else:
                        chip = f"Vendor agreement in force until {sel_exp}."
            elif sel.get("baa_certified"):
                chip = "Vendor agreement in force (no expiry set)."
            else:
                chip = "No vendor agreement on file (non-HIPAA only)."
    return options, chip


@router.get("/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request, user: RequireUser):
    templates = get_templates(request)
    #  phase 2 — wrap-at-snapshot: build the entire context off the
    # event loop so concurrent /health polls + other operator surfaces
    # don't serialise behind the per-account chip enrichment.
    ctx = await db_call(_build_accounts_page_snapshot, request, user)
    return await _render(templates, request, "accounts/manage.html", ctx)


@router.get("/accounts/form-fields", response_class=HTMLResponse)
async def accounts_form_fields(
    request: Request, user: RequireUserFragment, provider_type: str = "imap",
):
    """Return provider-specific form fields fragment (HTMX swap)."""
    if provider_type not in _PROVIDER_TYPES:
        return HTMLResponse("Unknown provider type", status_code=400)

    templates = get_templates(request)
    config = get_config(request)
    return await _render(templates, request, f"accounts/_fields_{provider_type}.html", {
        "public_url": getattr(config.push, "public_url", "").rstrip("/"),
    })


@router.get(
    "/accounts/{account_id}/auth-status",
    response_class=HTMLResponse,
)
async def accounts_auth_status(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Polling endpoint used by the wizard's step-2 panel to detect
    when the operator's external-browser sign-in has landed.

    Returns:
        HTMX-friendly fragment. When `?wizard=1` is set and the
        account is authenticated, we return an out-of-band redirect
        directive (`HX-Redirect: /accounts/new?step=3&...`) so the
        polling panel auto-advances the wizard to the next step.
        Otherwise we return the same waiting strip + a 200 status,
        and HTMX swaps it back over itself for the next poll cycle.
    """
    #  phase 2 — OwnedAccount dep collapses the
    # get_user/get_db/get_account/can_manage preamble.
    user, acct, db, secrets = owned

    is_authenticated = _account_authenticated(db, secrets, acct)
    is_wizard = bool(request.query_params.get("wizard"))

    if is_authenticated and is_wizard:
        # HX-Redirect tells HTMX to do a full-page navigation —
        # cleanest way to break the polling loop and land on the
        # next wizard step.
        target = f"/accounts/new?step=3&account_id={account_id}&auth=ok"
        resp = HTMLResponse(
            '<article style="padding:0.75rem 1rem;border-left:3px solid var(--pico-ins-color);">'
            '<small><strong>&#10003; Signed in.</strong> '
            'Moving on to the next step…</small>'
            '</article>'
        )
        resp.headers["HX-Redirect"] = target
        return resp

    if is_authenticated:
        # Non-wizard caller (e.g. a future use of this endpoint from
        # the edit page): tell them auth is in place; they can
        # decide what to render.
        return HTMLResponse(
            '<article id="auth-poll-panel" '
            'style="padding:0.75rem 1rem;border-left:3px solid var(--pico-ins-color);">'
            '<small><strong>&#10003; Signed in.</strong></small>'
            '</article>'
        )

    # Still waiting — re-emit the same polling strip; HTMX swaps
    # outerHTML so the hx-trigger keeps firing.
    poll_attrs = (
        f' hx-get="/accounts/{account_id}/auth-status?wizard=1"'
        ' hx-trigger="every 3s"'
        ' hx-swap="outerHTML"'
    ) if is_wizard else ""
    return HTMLResponse(
        f'<article id="auth-poll-panel"{poll_attrs} '
        'style="margin-top:1.25rem;padding:0.75rem 1rem;'
        'border-left:3px solid var(--pico-muted-border-color);">'
        '<small style="color:var(--pico-muted-color);">'
        'Waiting for sign-in… After you approve in your browser, '
        'this page moves on to the next step on its own.'
        '</small>'
        '</article>'
    )


@router.post("/accounts/create", response_class=HTMLResponse)
async def accounts_create(request: Request, user: RequireUserFragment):
    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")

    name = form.get("name", "").strip()
    ptype = form.get("provider_type", "imap")

    if ptype not in _PROVIDER_TYPES:
        return RedirectResponse("/accounts", status_code=303)

    # Admin can assign to any user; regular users own their own accounts.
    if is_admin and form.get("user_id"):
        owner_id = _safe_int(form["user_id"], user["id"])
    else:
        owner_id = user["id"]

    config = _extract_provider_config(form, ptype)

    # Enforce IMAP multi-mailbox cap at create time too — same ceiling
    # applies whether the operator adds or edits. Redirect back with
    # the error surfaced in the ?error= query param since the create
    # form lives on the accounts list page and we don't have an inline
    # error target here.
    if ptype == "imap":
        from email_triage.config import get_max_mailboxes_per_account
        app_config = get_config(request)
        cap = get_max_mailboxes_per_account(app_config)
        selected = list(config.get("mailboxes") or [])
        if len(selected) > cap:
            # N-232 R22 Arm A: route through the flash-key SSOT so a
            # future rename of `error=` doesn't decouple this writer from
            # the flash-reader.
            from email_triage.web.routers._redirect import err_qs
            return RedirectResponse(
                f"/accounts?{err_qs(f'Too many folders selected ({len(selected)} > cap of {cap}). Most IMAP servers limit concurrent connections per user.')}",
                status_code=303,
            )

    # Per-account HIPAA flag. When system HIPAA is on, the create helper
    # sticky-inherits the flag regardless; otherwise the admin opts in
    # via the form checkbox.
    from email_triage.triage_logging import is_hipaa_mode
    hipaa_flag = None
    if not is_hipaa_mode():
        hipaa_flag = "hipaa" in form

    from email_triage.web.db import create_email_account, set_bool_setting

    def _account_create_db_work() -> int:
        """/ — account row create + calendar opt-in flag +
        provider-secret store in one threadpool hop. Returns the new
        account id.
        """
        new_id = create_email_account(
            db, owner_id, name, ptype, config, hipaa=hipaa_flag,
        )
        # Calendar opt-in at create time (B2) — same wiring as edit.
        if (
            ptype in ("gmail_api", "office365")
            and config.get("calendar_opted_in")
        ):
            set_bool_setting(db, _S.calendar_enabled(new_id), True)
        # Save password/secret now that we have the account ID.
        _save_provider_secret(form, ptype, new_id, secrets)
        return new_id

    account_id = await db_call(_account_create_db_work)

    # Item #23a: auto-activate watcher after a successful connection
    # test. Opt-in via the "Start watching for new mail right away"
    # checkbox (default-checked in the template). Provider-aware:
    # IMAP gets a real IDLE watcher; Gmail in poll mode is a no-op
    # because WatcherManager.start raises on gmail_api; Office 365
    # currently has no inline probe, so we skip quietly.
    flash_success = "Account added."
    flash_error = ""
    if "start_watch" in form:
        #  phase 2 — table-driven dispatch. Each ptype's
        # post_create_start_watch returns ``(success_msg, error_msg)``;
        # exactly one is non-empty (or both empty for O365 where no
        # action runs).
        from email_triage.web.db import get_email_account
        from email_triage.providers.dispatcher import get_dispatch
        from email_triage.web.app import get_watcher_manager
        fresh_acct = await db_call(get_email_account, db, account_id)
        try:
            mgr = get_watcher_manager(request)
        except Exception:
            mgr = None
        disp = get_dispatch(ptype)
        if disp is not None and mgr is not None:
            ok_msg, err_msg = await disp.post_create_start_watch(
                mgr, request, fresh_acct, secrets,
            )
            if ok_msg:
                flash_success = ok_msg
            if err_msg:
                flash_error = err_msg
        # Unknown ptype or unavailable manager → fall through with the
        # default "Account added." flash. office365 returns ("", "")
        # by design (device-code auth needed first).

    from urllib.parse import urlencode
    params = {}
    if flash_success:
        params["success"] = flash_success
    if flash_error:
        params["error"] = flash_error
    qs = ("?" + urlencode(params)) if params else ""
    return RedirectResponse(f"/accounts{qs}", status_code=303)


@router.get("/accounts/{account_id}/edit", response_class=HTMLResponse)
async def accounts_edit_form(
    request: Request, account_id: int, owned: OwnedAccount,
):
    #  — ``OwnedAccount`` collapses the get_current_user → get_db
    # → get_secrets → get_email_account → can_manage_account preamble
    # into one Annotated dep. Raises HTTPException 401 / 404 / 403
    # with the same shape the inline preamble used (the global error
    # handler renders the operator-facing page or JSON).
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")

    from email_triage.triage_logging import (
        is_account_hipaa, is_account_hipaa_locked,
    )

    #  phase 2 — pre-provider DB snapshot (chips + delegates +
    # grantable users + digest configs + watches + wizard-resume).
    pre = await db_call(
        _accounts_edit_pre_provider, request, db, secrets, user, acct,
    )

    # IMAP: try live folder discovery so the edit form can render a
    # checkbox list. On failure (auth not saved yet, host unreachable,
    # provider optional-dep missing) we silently pass ``folder_options
    # = None`` and the template falls back to a comma-separated text
    # input. Never block the edit flow on a network probe.
    folder_options: list[str] | None = None
    # 2026-05-14 — Drafts-folder candidates for the dropdown on the
    # IMAP edit form. Filtered subset of the live folder list to
    # entries containing "drafts" (case-insensitive). Empty list
    # when the probe fails — template degrades to a single
    # "(auto-detect)" option without crashing.
    drafts_folder_candidates: list[str] = []
    if acct["provider_type"] == "imap":
        try:
            probe_provider = _create_provider_from_account(acct, secrets)
            all_folders = await probe_provider.list_folders()
            await probe_provider.close()
            from email_triage.web.db import get_visible_folders
            folder_options = await db_call(
                get_visible_folders, db, account_id, all_folders,
            )
            # Substring match on "drafts" — covers ``Drafts``,
            # ``INBOX.Drafts``, ``INBOX/Drafts``, the localized
            # ``Brouillons`` variants are NOT covered (they don't
            # contain "drafts"); operator-facing copy on the
            # template mentions the auto-detect fallback for those
            # cases.
            drafts_folder_candidates = sorted(
                f for f in (all_folders or [])
                if isinstance(f, str) and "drafts" in f.lower()
            )
        except Exception:
            folder_options = None
            drafts_folder_candidates = []

    # Tab selection via ?tab=<slug>; default = provider.
    #  retired the per-account "watches" tab; if a legacy bookmark
    # still passes ?tab=watches we silently land on the default tab so
    # the operator sees a working page rather than a 404.
    valid_tabs = {
        "provider", "watch", "digests",
        "integrations", "delegates",
    }
    tab = (request.query_params.get("tab") or "provider").strip()
    if tab not in valid_tabs:
        tab = "provider"

    #  — hide the OpenClaw chip when no webhook targets are
    # configured at the install level. The chip's controls (pause /
    # quiet hours / off) only do anything if there's a target to
    # gate, so showing them with no destination is misleading.
    config = request.app.state.config
    has_webhooks = bool(getattr(config, "webhooks", None) or [])

    delegates = pre["delegates"]
    grantable_users = pre["grantable_users"]
    digest_configs = pre["digest_configs"]
    watches = pre["watches"]
    wizard_resume_step = pre["wizard_resume_step"]
    wizard_resume_step_label = ""
    if wizard_resume_step:
        _resume_labels = {
            1: "Step 1 — Provider",
            2: "Step 2 — Sign in",
            3: "Step 3 — Real-time mail watch",
            4: "Step 4 — Categories",
            5: "Step 5 — Daily summary",
        }
        wizard_resume_step_label = _resume_labels.get(
            wizard_resume_step, f"Step {wizard_resume_step}",
        )

    #  Wave 2-α I6 — per-account style-learning backend selector.
    # Dropdown options filter on the account's HIPAA posture:
    #   * HIPAA account / system HIPAA mode:
    #       enabled=1 AND baa_certified=1 AND baa_expires_at > today
    #   * Non-HIPAA:
    #       enabled=1
    # The status-chip string is rendered server-side so the template
    # can read it without a second DB round-trip.
    from email_triage.triage_logging import is_hipaa_mode
    #  — _build_ai_backend_selector_context reads the shared
    # connection (the ai_backends list); dispatch it off the event
    # loop through db_call.
    ai_backend_options, ai_backend_selected_chip = (
        await db_call(_build_ai_backend_selector_context, db, acct)
    )

    ctx = {
        "acct": acct, "is_admin": is_admin, "user": user,
        "account_locked": is_account_hipaa_locked(acct),
        "account_effective_hipaa": is_account_hipaa(acct),
        "folder_options": folder_options,
        "drafts_folder_candidates": drafts_folder_candidates,
        "delegates": delegates,
        "grantable_users": grantable_users,
        "active_tab": tab,
        "digest_configs": digest_configs,
        "watches": watches,
        "has_webhooks": has_webhooks,
        "wizard_resume_step": wizard_resume_step,
        "wizard_resume_step_label": wizard_resume_step_label,
        "ai_backend_options": ai_backend_options,
        "ai_backend_selected_chip": ai_backend_selected_chip,
        "hipaa_mode": is_hipaa_mode(),
    }
    # HTMX swaps the bare partial into the row on the manage page.
    # Direct browser GET (no HX-Request header) gets the full-page
    # wrapper so base.html (nav + Pico CSS + theme) renders.
    if _shared.is_htmx(request):
        return await _render(templates, request, "accounts/_edit.html", ctx)
    return await _render(templates, request, "accounts/edit_page.html", ctx)


@router.get("/accounts/{account_id}/row", response_class=HTMLResponse)
async def accounts_row(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Return a single row fragment (for cancel from edit mode).

    #239g — gated by ``OwnedAccount`` (not the bare
    ``RequireUserFragment``): the row snapshot enriches with
    provider, HIPAA flag, watcher state, BAA chip and
    ``has_password``/``has_secret``. Without an ownership gate any
    authenticated user could fetch any account's enriched metadata
    (IDOR). ``OwnedAccount`` raises 401/404/403 before the body runs,
    mirroring the sibling ``accounts_edit_form`` handler.
    """
    user, _acct, _db, _secrets = owned
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")

    # OwnedAccount already proved the account exists + is manageable;
    # re-fetch through the enricher for the chip-bearing snapshot the
    # row template needs.
    acct = await db_call(_accounts_row_snapshot, request, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)

    return await _render(templates, request, "accounts/_row.html", {
        "acct": acct, "is_admin": is_admin,
    })


@router.post(
    "/accounts/{account_id}/backfill-capped/dismiss",
    response_class=HTMLResponse,
)
async def accounts_backfill_capped_dismiss(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """ — dismiss the bounded-backfill-saturation chip.

    The operator acknowledges the cursor-expiry gap (typically after
    running a whole-mailbox triage to backfill the missed messages).
    Gated by ``OwnedAccount`` so only a manager of THIS account can
    clear its chip. Returns an empty body — the row's HTMX swap
    (``hx-target=#backfill-chip-<id>``, ``hx-swap=outerHTML``) removes
    the chip in place.

    The dismiss is AUDITED (§164.312(b)): clearing the chip without a
    trail would turn a *known* un-triage gap into a silent one. The
    access-log row records who acknowledged the gap, when, and the
    recovered/cap counts the chip carried — so a later review can see
    the gap was acknowledged (and by whom) rather than simply vanished.
    """
    from email_triage.web._backfill_chip import (
        get_backfill_capped, clear_backfill_capped,
    )
    from email_triage.web.db import record_access_event
    user, _acct, db, _secrets = owned

    def _dismiss_work():
        chip = get_backfill_capped(db, account_id) or {}
        detail = (
            "backfill_capped dismissed "
            f"(kind={chip.get('kind', '?')} "
            f"recovered={chip.get('recovered', '?')} "
            f"cap={chip.get('cap', '?')} "
            f"window={chip.get('window', '?')})"
        )
        # census run17 #3 — route the best-effort audit write through the SSOT
        # web._audit.safe_audit_write: a failure is LOGGED (visible to /health's
        # audit-failure drift check), never silently dropped. The prior comment
        # claimed the access-audit middleware also logs this POST — FALSE at HEAD
        # (backfill-capped is not a PHI route, so this is the ONLY access_log
        # write for it; a bare `except: pass` made the miss totally invisible).
        from email_triage.web._audit import safe_audit_write
        safe_audit_write(
            lambda: record_access_event(
                db, actor_user_id=user.get("id"), method="POST",
                route=f"/accounts/{account_id}/backfill-capped/dismiss",
                account_id=account_id, message_id=None,
                status_code=200, outcome="ok", detail=detail,
            ),
            description=f"backfill_capped_dismiss account_id={account_id}",
        )
        # N-211c R23: operator-initiated dismiss — cross-scope clear is
        # intentional (user clicks "dismiss" regardless of which mailbox
        # raised it). Pass explicit `source_mailbox=None` to declare the
        # cross-scope intent + satisfy the N-211c pin.
        clear_backfill_capped(db, account_id, source_mailbox=None)

    await db_call(_dismiss_work)
    return HTMLResponse("")


@router.post(
    "/accounts/{account_id}/recipient-digest/send-now",
    response_class=HTMLResponse,
)
async def recipient_digest_send_now(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Operator-triggered test send of the per-recipient daily digest.

    Bypasses the scheduler's HH:10 fire-time check + the
    23-hour idempotence window so the operator can verify the
    digest renders + delivers as expected. Same code path as the
    scheduled send (rendering, SMTP, audit row); only the firing
    decision differs.

    Returns a small inline HTML fragment for HTMX swap-in next to
    the button.
    """
    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)

    smtp = config.smtp
    if not smtp.host:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "SMTP not configured. Configure SMTP on /config "
            "first.</small>"
        )

    # Resolve via the account_email SSOT (census run17 ) so IMAP accounts
    # (config["username"]) work alongside Gmail / O365 (config["account"]).
    # Open-coding the lookup here was the bug operators reported as
    # "Account has no email address" on every IMAP-backed account.
    from email_triage.db.accounts import account_email
    to_addr = account_email(acct)
    if not to_addr:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Account has no email address. Save the account first.</small>"
        )

    from datetime import datetime, timezone, timedelta
    from email_triage.actions.recipient_digest import (
        gather_digest_rows, send_recipient_digest, mark_sent,
    )
    from email_triage.triage_logging import account_hipaa_effective

    now_utc = datetime.now(timezone.utc)
    since_iso = to_utc_iso(now_utc - timedelta(hours=24))
    #  — gather_digest_rows reads the shared connection; dispatch
    # it off the event loop through db_call.
    rows = await db_call(
        gather_digest_rows,
        db, account_id=account_id, since_iso=since_iso,
    )
    if not rows:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "No triage activity in the last 24 hours; "
            "nothing to send.</small>"
        )

    hipaa = account_hipaa_effective(account=acct)

    from email_triage.secrets import SecretsDecryptError, read_secret
    # A5: explicit decrypt-error handling — an unreadable secret store
    # (master-key mismatch) must fail closed, not blank-password send.
    try:
        smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
    except SecretsDecryptError:
        _log.error(
            "Recipient digest test-send aborted — SMTP password unreadable "
            "(corrupt secret row / master-key mismatch)",
            account_id=account_id,
        )
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Send failed: secret store unreadable (master-key mismatch)</small>"
        )
    try:
        await asyncio.to_thread(
            send_recipient_digest,
            smtp_host=smtp.host,
            smtp_port=smtp.port,
            smtp_user=smtp.username,
            smtp_password=smtp_password,
            from_addr=smtp.from_addr,
            from_name=smtp.from_name,
            to_addr=to_addr,
            account_name=acct.get("name", ""),
            rows=rows,
            hipaa=hipaa,
            use_tls=smtp.use_tls,
            fallback_dt_iso=to_utc_iso(now_utc),
        )
        def _digest_sent_db_work() -> None:
            """/ — last-sent stamp + audit row in one hop,
            after the SMTP send above.
            """
            # Stamp last_sent so the scheduler's idempotence guard
            # picks up the manual send too — no surprise duplicate at
            # the next HH:10 firing within 23h.
            mark_sent(db, account_id, now_utc, len(rows))
            # Audit row mirroring the scheduler's path.
            # census run17 #3 — route the access_log row through the SSOT
            # web._audit.safe_audit_write so an emit failure is LOGGED (visible
            # to /health's audit-failure drift check), never silently dropped
            # (was a bare `except Exception: pass`).
            from email_triage.web.db import record_access_event
            from email_triage.web._audit import safe_audit_write
            safe_audit_write(
                lambda: record_access_event(
                    db,
                    actor_user_id=user["id"],
                    method="POST",
                    route=(
                        f"/accounts/{account_id}"
                        "/recipient-digest/send-now"
                    ),
                    account_id=account_id,
                    message_id=None,
                    status_code=200,
                    outcome="recipient_digest_sent",
                    detail=(
                        # to_addr deliberately EXCLUDED — db/audit contract:
                        # account_id is the column, never an email in a detail
                        # string (mirrors the scheduled sender, digest.py:696).
                        f"row_count={len(rows)} hipaa={hipaa} manual=true"
                    ),
                ),
                description=(
                    f"recipient_digest_sent manual access_log "
                    f"account_id={account_id}"
                ),
            )
            # N-73 / §164.312(b) — a HIPAA recipient-digest send is a PHI
            # EXFILTRATION; it must write a hipaa_access_events row (not just
            # access_log), exactly as the scheduled sender does (digest.py:683).
            # Operator-initiated, so the actor is the triggering user. Its OWN
            # try/except (db-sme run15 #8) so an access_log write failure cannot
            # SUPPRESS the §164.312(b) row, and a recurring failure is VISIBLE
            # (warning) — fail-soft parity with the scheduled sender (digest.py:692).
            if hipaa:
                # census run17 #3 — route the §164.312(b) PHI-access row through
                # the SSOT (safe_audit_write): preserves the N-125 fail-soft (an
                # access_log failure can't suppress this row; a failure here is
                # LOGGED, not silent) but via the ONE audit-failure funnel so
                # /health's drift check sees it uniformly (was an ad-hoc warning).
                from email_triage.web.db import record_hipaa_access_event
                from email_triage.web._audit import safe_audit_write
                safe_audit_write(
                    lambda: record_hipaa_access_event(
                        db,
                        user["id"],
                        int(account_id),
                        "recipient_digest_sent",
                        "ok",
                        f"row_count={len(rows)} manual=true",
                    ),
                    description=(
                        f"recipient_digest_sent manual hipaa account_id={account_id}"
                    ),
                )

        await db_call(_digest_sent_db_work)
        import html as _html
        # N-83: to_addr is a DB-stored email address; escape before HTML interpolation.
        return HTMLResponse(
            "<small style='color:var(--pico-ins-color);'>"
            f"&#10003; Sent {len(rows)} row digest to "
            f"<code>{_html.escape(to_addr)}</code></small>"
        )
    except Exception as e:
        _log.error(
            "Recipient digest test-send failed",
            account_id=account_id, error=fmt_exc(e),
        )
        return HTMLResponse(
            error_chip(e, prefix='Send failed: ', purpose='provider')  # N-179 SSOT
        )


@router.post(
    "/accounts/{account_id}/digests/new",
    response_class=HTMLResponse,
)
async def digest_create_stub(
    request: Request, account_id: int, ctx: OwnedAccountOrLogin,
):
    """Add a fresh ``custom`` digest config + redirect to its editor.

    The editor renders against a stub DigestConfig that gets a
    new id minted by ``upsert_digest_config`` on first save. We
    don't persist on this route — saves a wasted row when the
    operator clicks Cancel.
    """
    #  phase 2 — OwnedAccountOrLogin keeps the redirect-to-/login
    # UX for full-page nav targets while collapsing the rest of the
    # preamble. Anon → 303 to /login; non-owner → HTTPException 403.
    if isinstance(ctx, RedirectResponse):
        return ctx
    user, acct, db, secrets = ctx
    return RedirectResponse(
        f"/accounts/{account_id}/digests/new/edit",
        status_code=303,
    )


async def _digest_label_options(db, secrets, acct) -> list[dict]:
    """Discovered provider labels for the digest label-filter picker.

    Thin wrapper over :func:`list_provider_labels_for_account`. That helper
    does **no** auth/HIPAA gating — the ACCESS BOUNDARY is the control: the
    caller resolves ``acct`` via ``OwnedAccountOrLogin`` (can_manage_account),
    so only an authorized manager of THIS account reaches it. There is
    intentionally NO is_account_hipaa gate (removed 2026-06-06 per the
    §160.103 use-vs-disclosure SME ruling — surfacing an account's own
    labels to its authorized manager is an intra-entity USE, not a
    disclosure; owner self-access is §164.502(b)(2)-exempt). Retained
    defense-in-depth: the helper never logs label names. See
    reference_labels_phi_use_vs_disclosure_2026-06-06. The extra try/except
    is belt-and-braces so a provider round-trip hiccup can never 500 the
    digest editor; the picker just degrades to the free-text override.

    IMAP gate: for IMAP the provider-label helper returns FOLDER names,
    which the digest's folders picker already covers — and the digest
    ``tags`` filter is about IMAP keywords/flags (not enumerable), NOT
    folders. So we only surface the label multi-select for Gmail / O365,
    where the provider labels ARE the tags. IMAP keeps the free-text
    keyword override.
    """
    if not acct or acct.get("provider_type") == "imap":
        return []
    from email_triage.providers.provider_labels import (
        list_provider_labels_for_account,
    )
    try:
        return await list_provider_labels_for_account(
            db=db, secrets=secrets, account_id=int(acct["id"]),
        )
    except Exception:  # noqa: BLE001 — never let label discovery break the editor
        return []


@router.get(
    "/accounts/{account_id}/digests/new/edit",
    response_class=HTMLResponse,
)
async def digest_editor_new(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Editor for a not-yet-saved digest. ``dcfg.id`` empty until
    first save mints one in ``upsert_digest_config``."""
    #  phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)
    labels = await _digest_label_options(db, secrets, acct)
    ctx = _digest_editor_context(
        db, request, account_id, dcfg=None, provider_labels=labels,
    )
    ctx["user"] = user
    return await _render(templates, request, "accounts/_digest_editor.html", ctx)


@router.get(
    "/accounts/{account_id}/digests/{digest_id}/edit",
    response_class=HTMLResponse,
)
async def digest_editor(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccountOrLogin,
):
    """Editor for an existing digest — preset OR custom.

    Preset id resolves to a read-only-ish view (operator can flip
    enable + send-time only; the rest of the form is locked).
    Custom digests get the full filter palette + advanced field.
    """
    from email_triage.actions.digest_configs import (
        PRESET_ID, get_digest_config,
    )
    #  phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)

    dcfg = await db_call(get_digest_config, db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse("Digest not found", status_code=404)
    labels = await _digest_label_options(db, secrets, acct)
    ctx = _digest_editor_context(
        db, request, account_id, dcfg=dcfg, provider_labels=labels,
    )
    ctx["user"] = user
    ctx["is_preset"] = (dcfg.id == PRESET_ID)
    return await _render(templates, request, "accounts/_digest_editor.html", ctx)


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/save",
    response_class=HTMLResponse,
)
async def digest_save(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccountOrLogin,
):
    """Upsert one digest config from the editor form.

    On validation error: re-renders the editor with inline error
    messages so the operator stays in context. On success:
    303-redirects to /accounts/{id}/edit?tab=digests so the
    summary list reflects the change.

    ``digest_id`` of literal ``new`` mints a fresh id on save —
    matches the ``digest_editor_new`` GET handler shape.
    """
    from email_triage.actions.digest_configs import (
        PRESET_ID, get_digest_config, upsert_digest_config, validate,
    )
    #  phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)

    form = await request.form()
    target_id = "" if digest_id == "new" else digest_id
    cfg = _extract_digest_config_from_form(form, existing_id=target_id)

    # Preset is name-locked; the editor renders the name field
    # disabled but defensive normalisation here covers any
    # tampered submission. Kind likewise enforced.
    if cfg.id == PRESET_ID:
        cfg.kind = "preset_daily_activity"
        cfg.name = "Daily Activity"

    errors = validate(cfg)
    if errors:
        labels = await _digest_label_options(db, secrets, acct)
        ctx = await db_call(
            _digest_editor_context, db, request, account_id, dcfg=cfg,
            provider_labels=labels,
        )
        ctx["user"] = user
        ctx["is_preset"] = (cfg.id == PRESET_ID)
        ctx["errors"] = errors
        return await _render(
            templates, request, "accounts/_digest_editor.html", ctx,
        )

    await db_call(upsert_digest_config, db, account_id, cfg)
    return RedirectResponse(
        f"/accounts/{account_id}/edit?tab=digests", status_code=303,
    )


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/delete",
    response_class=HTMLResponse,
)
async def digest_delete(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccountOrLogin,
):
    """Delete one custom digest config. Refuses preset deletion."""
    from email_triage.actions.digest_configs import (
        PRESET_ID, delete_digest_config,
    )
    #  phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    if digest_id == PRESET_ID:
        return HTMLResponse(
            "Cannot delete the preset digest.", status_code=400,
        )
    #  — delete_digest_config writes the shared connection;
    # dispatch it off the event loop through db_call.
    await db_call(delete_digest_config, db, account_id, digest_id)
    return RedirectResponse(
        f"/accounts/{account_id}/edit?tab=digests", status_code=303,
    )


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/test-send",
    response_class=HTMLResponse,
)
async def digest_test_send(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccount,
):
    """Operator-triggered test send of one digest config.

    Bypasses the scheduler's fire-time + idempotence gates so the
    operator can verify the digest renders + delivers as
    expected. Same code path as the scheduled send (resolve
    window → gather → filter → render → SMTP → audit row); only
    the firing decision differs.

    Returns a small inline HTML fragment for HTMX swap-in next
    to the per-card button. Mirrors the legacy
    ``/recipient-digest/send-now`` shape — operators get the
    same UX whether they're testing the preset or a custom
    digest.
    """
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _fire_one_digest

    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)
    smtp = config.smtp
    if not smtp.host:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "SMTP not configured.</small>"
        )
    # census run17  — account_email SSOT, not the open-coded key.
    from email_triage.db.accounts import account_email
    to_addr = account_email(acct)
    if not to_addr:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Account has no email address. Save the account first."
            "</small>"
        )
    dcfg = await db_call(get_digest_config, db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    from email_triage.triage_logging import account_hipaa_effective
    hipaa = account_hipaa_effective(account=acct)
    now_utc = datetime.now(timezone.utc)
    try:
        rows_sent = await _fire_one_digest(
            db=db, secrets=secrets, smtp=smtp,
            acct=acct, dcfg=dcfg, hipaa=hipaa,
            now_utc=now_utc,
            last_sent=None,  # bypass idempotence on test send
            to_addr=to_addr,
            config=config,
            is_test_send=True,
        )
        # Three outcome paths — give the operator honest copy for
        # each rather than always rendering "✓ Sent" (the bug:
        # an empty-window short-circuit returned silently and
        # the route lied about delivery).
        if rows_sent == 0:
            msg = (
                "No matching messages in the selected window — "
                "nothing was sent. Adjust the Cover or filter "
                "settings, save, and try Send test now again."
            )
            return HTMLResponse(
                "<small style='color:var(--pico-muted-color);'>"
                f"{msg}</small>"
            )
        # Newsletter formats run an AI extraction step per source
        # message — wall time can stretch into minutes for a busy
        # mailbox. The operator already waited for that work to
        # finish (the await above blocks until SMTP-accept). Make
        # the success copy reflect what just happened so the
        # operator knows the email is on the wire, not "queued."
        # User-facing copy avoids developer jargon (no
        # "language-model", no "system log") per the audience
        # comment block on the template.
        is_newsletter = dcfg.format.render_as in (
            "newsletter", "newsletter_classic",
        )
        import html as _html
        # N-83: to_addr is a DB-stored email address; escape before HTML interpolation.
        _to_esc = _html.escape(to_addr)
        if is_newsletter:
            msg = (
                f"✓ Sent to {_to_esc} ({rows_sent} message"
                f"{'s' if rows_sent != 1 else ''}). "
                "Newsletter formats can take a minute or two to "
                "build — if the email doesn't arrive shortly, "
                "try Send test now again."
            )
        else:
            msg = (
                f"✓ Sent to {_to_esc} ({rows_sent} message"
                f"{'s' if rows_sent != 1 else ''})"
            )
        return HTMLResponse(
            f"<small style='color:var(--pico-ins-color);'>{msg}</small>"
        )
    except Exception as e:
        _log.error(
            "Digest test-send failed",
            account_id=account_id, digest_id=digest_id,
            error=fmt_exc(e),
        )
        return HTMLResponse(
            error_chip(e, prefix='Send failed: ', purpose='provider')  # N-179 SSOT
        )


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/candidates",
    response_class=HTMLResponse,
)
async def digest_candidates(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccount,
):
    """Cheap dry-run: list the messages the digest WOULD include
    given its current window + filter, without rendering the email
    or running the LLM article extractor.

    Reuses ``_filter_digest_candidates`` (the same row-gather +
    filter step ``_fire_one_digest`` runs internally) so the table
    is bit-identical to what would be sent. Sub-100ms typical;
    cost is one DB read of triage_runs rows.

    Doubles as an ETA gauge for newsletter formats. Each source
    in the candidate list runs ~30-90s of LLM extraction during a
    real send, so a list of 22 sources = ~10-30 min preview / send
    wall time. Operator can decide whether to wait for the full
    Preview or just trust the structured shape.

     reachability — pages the FULL match set (apply_cap=False), so
    every match is reachable, not just the first ``max_rows`` that would
    send. NOTE: this is a live dry-run, NOT a stable snapshot — the
    candidate set is recomputed on every page turn, so if mail arrives
    between "Show matches" and a "load older" click the total can shift.
    That's tolerable for a preview (no persistence consequence); the
    actual SEND path (``_render_digest_payload``) still caps at
    ``max_rows`` via the default ``apply_cap=True``.
    """
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _filter_digest_candidates
    from email_triage.web._pagination import page_window, clamp_offset

    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)
    dcfg = await db_call(get_digest_config, db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    #  reachability — the pager hx-POSTs this endpoint with the
    # offset (form data). Default 0 on the first "Show matches" click.
    form = await request.form()
    raw_offset = form.get("offset")

    now_utc = datetime.now(timezone.utc)
    try:
        #  — _filter_digest_candidates does a synchronous DB read on
        # the shared connection; route it through db_call so it runs off
        # the event loop under the process-wide DB lock. apply_cap=False
        # returns the FULL filtered set so the dry-run can page through
        # EVERY match, not just the first max_rows that would send.
        all_rows, total_matched = await db_call(
            _filter_digest_candidates,
            db=db, acct=acct, dcfg=dcfg,
            now_utc=now_utc, last_sent=None, apply_cap=False,
        )
    except Exception as e:
        _log.error(
            "Digest candidates failed",
            account_id=account_id, digest_id=digest_id,
            error=fmt_exc(e),
        )
        return HTMLResponse(
            error_chip(e, prefix='Candidate lookup failed: ', purpose='misc')  # N-179 SSOT
        )

    if total_matched == 0:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "No matching messages in the selected window. "
            "Adjust the Cover or filter settings, save, and try "
            "Show matches again.</small>"
        )

    # Page size = the digest's row limit (so page 1 == exactly what
    # would send); default to 50 if unset. Pages reveal the rest.
    max_rows = int(getattr(dcfg.format, "max_rows", 0) or 0)
    page_size = max_rows if max_rows > 0 else 50
    off = clamp_offset(raw_offset, page_size, total_matched)
    rows = all_rows[off:off + page_size]
    win = page_window(
        total=total_matched, offset=off, limit=page_size, shown=len(rows),
    )

    # ETA hint for newsletter formats (other formats render < 1s).
    is_newsletter = dcfg.format.render_as in (
        "newsletter", "newsletter_classic",
    )
    eta_line = ""
    if is_newsletter:
        low_min = max(1, (total_matched * 30) // 60)
        high_min = max(1, (total_matched * 90) // 60)
        eta_line = (
            f" Newsletter render uses AI to summarize each "
            f"source — estimated wait if you Preview or Send: "
            f"~{low_min}–{high_min} minutes."
        )

    # When more matched than the digest will actually send, say which
    # ones send (the newest max_rows) so paging beyond isn't confusing.
    send_note = ""
    if max_rows and total_matched > max_rows:
        send_note = (
            f"The newest {max_rows} of these will actually send; raise "
            f"this digest's row limit to send more. The rest are shown "
            f"here for reference."
        )

    # HIPAA display policy — N-172 threaded a viewer-INDEPENDENT display-min
    # gate; the follow-on owner-self-preview design point (operator ruling
    # 2026-07-01 = viewer-AWARE) unredacts sender + subject when the ACTOR IS
    # THE ACCOUNT OWNER (they authored the mail into their own mailbox — no
    # min-necessary rationale for hiding their OWN PHI from themselves). A
    # managing NON-OWNER still sees [redacted] (§164.502(b)/§164.514(d)(1)).
    # actor≠owner is the separate AUDIT gate (db/audit.py:1116) — decoupled.
    # The DELIVERED digest (recipient_digest.render_html, to the authorized
    # recipient) is a SEPARATE surface and out of scope here.
    from email_triage.triage_logging import account_hipaa_effective
    effective_hipaa = account_hipaa_effective(account=acct)
    viewer_is_owner = user["id"] == acct["user_id"]

    return await _render(templates, request, "accounts/_digest_candidates.html", {
        "rows": rows,
        "win": win,
        "eta_line": eta_line,
        "send_note": send_note,
        "effective_hipaa": effective_hipaa,
        "viewer_is_owner": viewer_is_owner,
        "cand_url": str(request.url.path),
        # The pager re-targets its own [data-cand-wrap] wrapper (relative),
        # so it works under BOTH the preset (#recipient-digest-result-N) and
        # custom (#digest-result-<id>) result containers — no per-digest
        # target id needed (live Playwright review, 2026-06-12).
    })


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/preview",
    response_class=HTMLResponse,
)
async def digest_preview(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccount,
):
    """Render the digest's email body without SMTP-sending it.

    Same render path as ``_fire_one_digest`` (resolve window →
    gather → filter → render) minus the SMTP call + state writes.
    For newsletter formats this still pays the LLM extraction
    cost — the operator gets to SEE the rendered article cards
    before committing to a real send. For table / grouped /
    plain_list formats it's near-instant.

    Returns the rendered HTML wrapped in an iframe ``srcdoc``
    so the digest's CSS doesn't fight the editor page's CSS.
    Subject line + row count surface above the iframe.
    """
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _render_digest_payload

    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)
    dcfg = await db_call(get_digest_config, db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    from email_triage.triage_logging import account_hipaa_effective
    hipaa = account_hipaa_effective(account=acct)
    now_utc = datetime.now(timezone.utc)
    try:
        (
            subject, html_body, _plain, rows, total_matched,
        ) = await _render_digest_payload(
            db=db, secrets=secrets, acct=acct, dcfg=dcfg,
            hipaa=hipaa, now_utc=now_utc, last_sent=None,
            config=config,
            # N-174 + owner-self-preview design point (operator ruling
            # 2026-07-01 = viewer-AWARE): this preview is reachable by a
            # managing NON-OWNER (OwnedAccount→can_manage_account), so the
            # digest BODY's sender + subject must be display-min-redacted
            # for a NON-owner — but the OWNER viewing THEIR OWN preview
            # sees verbatim (no min-necessary rationale for hiding their
            # own PHI from themselves; matches the sibling
            # _digest_candidates gate). ``hipaa`` here is the viewer-
            # INDEPENDENT account_hipaa_effective account flag; combined
            # with the actor==owner check → the viewer-AWARE display gate.
            # The DELIVERED send (_fire_one_digest) omits redact_pii →
            # verbatim to the account's own authorized mailbox.
            redact_pii=hipaa and user["id"] != acct["user_id"],
        )
    except Exception as e:
        _log.error(
            "Digest preview failed",
            account_id=account_id, digest_id=digest_id,
            error=fmt_exc(e),
        )
        return HTMLResponse(
            error_chip(e, prefix='Preview failed: ', purpose='misc')  # N-179 SSOT
        )

    if not rows:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "No matching messages in the selected window — "
            "nothing to preview. Adjust the Cover or filter "
            "settings, save, and try Preview again.</small>"
        )

    # Subject line for the preset path is empty here; the legacy
    # default ("Triage Digest — <acct> (<N> classified)") fires
    # inside send_recipient_digest, so we synthesize the same
    # shape for the preview header.
    if not subject:
        subject = (
            f"Triage Digest — {acct.get('name', '')} "
            f"({len(rows)} classified)"
        )

    import html as _html
    n = len(rows)
    #  — preview reflects the same max_rows cap; show the gap so
    # the operator knows the rendered body is the capped subset.
    omitted = max(0, total_matched - n)
    cap_note = ""
    if omitted:
        # int() wraps mark these as numeric for the N-83 styled-fragment pin.
        cap_note = (
            f" <span style='color:var(--pico-del-color);'>"
            f"({int(total_matched)} matched — {int(omitted)} omitted by the "
            f"row limit; an in-body notice tells the recipient.)"
            f"</span>"
        )
    # iframe srcdoc sandboxes the digest's own styles. Use double
    # quotes around srcdoc + escape the HTML content for safety.
    iframe_src = _html.escape(html_body, quote=True)
    return HTMLResponse(
        "<div style='font-size:0.85em;'>"
        "<p style='margin:0.3rem 0;'>"
        "<strong>Preview — not sent.</strong> "
        f"Subject: <code>{_html.escape(subject)}</code> · "
        f"{n} message{'s' if n != 1 else ''} included.{cap_note}"
        "</p>"
        f"<iframe srcdoc=\"{iframe_src}\" "
        "style='width:100%;height:600px;border:1px solid "
        "var(--pico-muted-border-color);background:white;'>"
        "</iframe></div>"
    )


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/validate-query",
    response_class=HTMLResponse,
)
async def digest_validate_query(
    request: Request, account_id: int, digest_id: str,
    owned: OwnedAccount,
):
    """Dry-run the operator's advanced provider query.

    Hands the raw string to ``provider.search()`` with limit=1
    (cheap), returns a small inline HTML fragment for HTMX swap
    next to the input. On syntax error: surfaces the provider's
    own error message so operators can fix the query without
    hunting through logs.
    """
    #  phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned

    form = await request.form()
    raw = (form.get("advanced") or "").strip()
    if not raw:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "(advanced field is empty — dropdowns above apply)</small>"
        )

    try:
        provider = _create_provider_from_account(acct, secrets)
        ids = await provider.search(raw, limit=1)
        return HTMLResponse(
            "<small style='color:var(--pico-ins-color);'>"
            f"✓ syntax ok — sample match: "
            f"{len(ids)} message{'s' if len(ids) != 1 else ''} (limit 1)"
            "</small>"
        )
    except Exception as e:
        return HTMLResponse(
            error_chip(e, prefix='✗ ', purpose='misc')  # N-179 SSOT
        )


@router.post("/accounts/{account_id}/save", response_class=HTMLResponse)
async def accounts_save_post(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Plain-HTML POST form-submit handler for the edit page.

    Reuses the PUT handler's logic, but redirects on success rather
    than returning a row partial. Lets the edit form work as a
    full-page workflow without HTMX. Errors that the PUT path
    surfaces as inline-rendered partials still render here — the
    operator stays on the edit page until the form is valid.

    On clean save: redirect back to the same edit-page tab the
    operator submitted from (``?tab=<active_tab>`` carried via a
    hidden form field). Operators were getting bounced to
    ``/accounts`` after a Save and losing tab context — particularly
    bad for the Watch + Push tab where they often save folder picks
    and then want to keep adjusting push/poll knobs. Falls back to
    ``/accounts/{id}/edit`` (provider tab) if the form didn't carry
    a tab — preserves the "stay on the edit page" intent for
    callers that don't know about tabs.
    """
    # Read the hidden ``active_tab`` field BEFORE delegating to
    # accounts_update, since that handler consumes the form-stream.
    # FastAPI's Request.form() caches so it's safe to call twice,
    # but pulling it here keeps the redirect logic self-contained.
    form = await request.form()
    active_tab = (form.get("active_tab") or "").strip()
    response = await accounts_update(request, account_id, owned)
    # accounts_update returns either an HTMLResponse with the row /
    # error partial (status 200/4xx) OR raises. On a clean save we
    # want a 303 redirect back to the edit page on the active tab.
    # Heuristic: status_code == 200 AND no inline error means success.
    if isinstance(response, HTMLResponse) and response.status_code == 200:
        body_text = (response.body or b"").decode("utf-8", errors="ignore")
        # Inline errors render banners with these classes; presence
        # = stay on edit page. Absence = redirect.
        if "mailbox_cap_error" not in body_text and "hipaa_error" not in body_text:
            target = f"/accounts/{account_id}/edit"
            if active_tab:
                target = f"{target}?tab={active_tab}"
            return RedirectResponse(target, status_code=303)
    return response


@router.put("/accounts/{account_id}", response_class=HTMLResponse)
async def accounts_update(
    request: Request, account_id: int, owned: OwnedAccount,
):
    #  — preamble collapsed to ``OwnedAccount``. The save-POST
    # sibling forwards its own ``owned`` tuple so the dep runs once
    # per request, not twice. Local imports below stay narrow to keep
    # cherry-pick locality tight against parallel-agent edits in the
    # same file (Bundles C / G / L all touch ui.py too).
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")

    from email_triage.web.db import get_email_account, update_email_account

    form = await request.form()
    name = form.get("name", "").strip()
    ptype = form.get("provider_type", acct["provider_type"])
    is_active = "is_active" in form

    # Pass the existing config so blank password/secret fields on the
    # edit form preserve the stored value instead of wiping it. Without
    # this, editing an account and hitting Save (without re-typing the
    # client_secret password field) erases the secret and the next
    # token refresh fails with "client_secret is missing".
    existing_config = acct["config"] or {}
    config = _extract_provider_config(form, ptype, existing=existing_config)

    # IMAP: enforce the install-wide mailbox cap. Fail-fast with a form
    # error rather than silently truncating — surface the limit so the
    # operator can decide which folders matter. The cap exists because
    # one IDLE watcher = one concurrent TCP/TLS connection, and most
    # IMAP servers limit concurrent per-user connections.
    if ptype == "imap":
        from email_triage.config import get_max_mailboxes_per_account
        from email_triage.web.app import get_watcher_manager as _gwm
        app_config = get_config(request)
        cap = get_max_mailboxes_per_account(app_config)
        selected = list(config.get("mailboxes") or [])
        if len(selected) > cap:
            # Re-render the edit form with the error message.
            try:
                wm = _gwm(request)
            except Exception:
                wm = None

            def _mailbox_cap_render_snapshot() -> list[dict]:
                """/ — enrich + delegates read for the cap-error
                re-render, in one threadpool hop.
                """
                from email_triage.web.db import list_account_delegates
                _enrich_account(acct, secrets)
                _enrich_account_chips(
                    acct, db, secrets, watcher_mgr=wm,
                    config=request.app.state.config,
                )
                return list_account_delegates(db, account_id)

            delegates = await db_call(_mailbox_cap_render_snapshot)
            return await _render(templates, request, "accounts/_edit.html", {
                "acct": acct, "is_admin": is_admin, "user": user,
                "delegates": delegates,
                "mailbox_cap_error": (
                    f"Too many folders selected ({len(selected)} > cap of {cap}). "
                    "Most IMAP servers limit concurrent connections per user — "
                    "pick fewer folders or raise "
                    "``provider.imap.max_mailboxes_per_account`` in the YAML config."
                ),
            })

    # / — this edit-save handler is a long synchronous SQLite
    # block with no ``await`` interleaved until the watcher-bounce far
    # below. Each contiguous DB sub-block is wrapped via db_call so it
    # runs off the event loop. (One giant nested helper would require
    # re-indenting ~300 lines of branchy code — wrapping each coherent
    # sub-block is the lower-risk, behaviour-preserving conversion.)
    def _update_account_row_db_work() -> None:
        update_email_account(db, account_id, name, ptype, config, is_active)

        # Sync the preset digest config from the legacy form fields.
        # Phase 4 of the multi-digest refactor moved the source of
        # truth to ``digest_configs:<id>`` storage; we still accept
        # the legacy ``recipient_digest_enabled`` /
        # ``recipient_digest_send_at`` form fields (no UI churn for
        # the operator's existing toggle) but mirror them into the
        # preset config so the new sender path picks them up. Custom
        # digests are managed via the Phase 6 editor; not touched here.
        try:
            from email_triage.actions.digest_configs import (
                PRESET_ID, get_digest_config, upsert_digest_config,
            )
            preset = get_digest_config(db, account_id, PRESET_ID)
            if preset is not None:
                preset.enabled = bool(
                    config.get("recipient_digest_enabled", False)
                )
                preset.schedule.time_local = (
                    config.get("recipient_digest_send_at") or "08:10"
                )
                upsert_digest_config(db, account_id, preset)
        except Exception as e:
            # Sync is best-effort — the legacy fields still drive the
            # Phase 4 migration on first read, and the preset config
            # is always re-derivable from them. Log + move on.
            # N-323 R30 (task ): nested `from ... import fmt_exc`
            # REMOVED — module-level import at :57 is authoritative.
            # Same defect class as N-269b + N-319.
            _log.warning(
                "digest preset sync failed",
                account_id=account_id, error=fmt_exc(e),
            )

    await db_call(_update_account_row_db_work)

    # Calendar opt-in wiring (B2):
    # - gmail_api: the checkbox sets ``calendar_opted_in`` in the account
    #   config; the effective ``calendar_enabled`` flag follows whichever
    #   scope set the OAuth flow actually requested. Unchecking + re-auth
    #   strips calendar from the refresh token, flipping the flag OFF.
    #   If the user unchecks but doesn't re-authenticate, the token still
    #   carries calendar scope — clear the effective flag anyway, because
    #   the user's intent is "off". A re-auth will then sync the token.
    # - office365: MSAL handles consent lazily; the flag is all that
    #   matters. Sync it directly from the checkbox.
    from email_triage.web.db import set_bool_setting
    if ptype in ("gmail_api", "office365"):
        await db_call(
            set_bool_setting,
            db, _S.calendar_enabled(account_id),
            bool(config.get("calendar_opted_in", False)),
        )

    # Per-account HIPAA flag. Runs through set_account_hipaa so the
    # lock rule is enforced + a boundary event is recorded on flip.
    # The form only contains the checkbox when the field was rendered
    # editable; if it's absent the user toggled-off or the field was
    # disabled. Determine intent by presence of a hidden "hipaa_submitted"
    # marker emitted by the edit template whenever the field is editable.
    from email_triage.web.app import get_watcher_manager
    try:
        watcher_mgr = get_watcher_manager(request)
    except Exception:
        watcher_mgr = None

    #  — HIPAA flag flip is owner-or-admin only. Delegates
    # explicitly can NOT change the flag (blast-radius op: toggling
    # off downgrades audit posture for an account that may carry
    # PHI). Skip the whole block when a delegate posts the form —
    # the rest of the save still applies. (2026-06-11: the inlined
    # owner-or-admin decision now routes through the
    # can_administer_account SSOT — the no-delegate sensitive-op gate.)
    _hipaa_owner_or_admin = can_administer_account(db, user, acct)
    if "hipaa_submitted" in form and _hipaa_owner_or_admin:
        desired = "hipaa" in form
        # 2026-05-11 — capture pre-save HIPAA state so we can detect a
        # 0→1 flip after the set. The AI-learns toggle is auto-off'd
        # when an account becomes HIPAA so future renders reflect the
        # explicit OFF state until the operator manually re-enables it.
        was_hipaa = bool(acct.get("hipaa"))

        def _hipaa_flag_db_work() -> tuple[str, dict | None]:
            """/ — HIPAA flag set + (on 0→1 flip) the AI-learns
            auto-off, in one hop. Returns ("permission_error", acct)
            when the lock guard rejects, else ("ok", None).
            """
            try:
                from email_triage.web.db import set_account_hipaa
                set_account_hipaa(
                    db, account_id, desired, actor_id=user["id"],
                )
            except PermissionError as e:
                # Lock violation — surface inline, don't 500. Re-fetch
                # + enrich here so the handler can render off-thread.
                bad_acct = get_email_account(db, account_id)
                _enrich_account(bad_acct, secrets)
                _enrich_account_chips(
                    bad_acct, db, secrets, watcher_mgr=watcher_mgr,
                    config=request.app.state.config,
                )
                bad_acct = dict(bad_acct or {})
                #  (Census v3 re-run error-surface HIGH): route the
                # PermissionError through `scrub_exc` (form purpose —
                # informational, PHI-shape strip only). The lock guard's
                # hardcoded message ("Cannot unset HIPAA flag …") has no
                # PHI today but a future guard revision could — the
                # SSOT closes the class.
                bad_acct["_hipaa_error"] = scrub_exc(e, purpose="form")
                return "permission_error", bad_acct
            # Auto-off on flip 0→1: when an account becomes HIPAA, force
            # the AI-learns toggle off so future renders reflect the
            # explicit OFF state. Operator can re-enable it manually
            # once the M-1+M-2 opt-in is in place. Per operator: "if
            # the account flips on hipaa, disable until checked
            # manually again." INFO log carries account_id + actor.
            if desired and not was_hipaa:
                try:
                    from email_triage.web.db import (
                        set_rag_sent_index_enabled,
                    )
                    set_rag_sent_index_enabled(
                        db, account_id, enabled=False,
                    )
                    _log.info(
                        "AI-learns toggle auto-disabled on HIPAA flip",
                        account_id=account_id,
                        actor_user_id=user["id"],
                    )
                except Exception as auto_off_err:
                    # Auto-off is defence in depth — the M-4 path
                    # itself short-circuits HIPAA accounts. Log +
                    # continue rather than break the save.
                    _log.warning(
                        "AI-learns auto-off on HIPAA flip failed",
                        account_id=account_id,
                        error=fmt_exc(auto_off_err),
                    )
            return "ok", None

        _hipaa_kind, _hipaa_acct = await db_call(_hipaa_flag_db_work)
        if _hipaa_kind == "permission_error":
            return await _render(templates, request, "accounts/_row.html", {
                "acct": _hipaa_acct, "is_admin": is_admin,
                "hipaa_error": _hipaa_acct.get("_hipaa_error", ""),
            })

    # Save password/secret if provided.
    await db_call(_save_provider_secret, form, ptype, account_id, secrets)

    #  Wave 2-α I6 — per-account style-learning backend FK.
    # Form field is ``style_learning_backend_id`` (HTML select);
    # empty / unset value means "fall through to install default".
    # The dropdown was filtered server-side to enforce the HIPAA gate
    # at render time, but defence-in-depth: re-check on save and
    # refuse a HIPAA account selecting a backend that doesn't meet
    # the BAA-current invariant.
    def _style_backend_db_work() -> None:
        """/ — per-account style-learning backend FK select:
        validate + HIPAA gate + audit + write, all in one threadpool
        hop. Only invoked when the form carries the field.
        """
        from email_triage.web.db import (
            get_ai_backend,
            record_hipaa_access_event,
            set_account_style_learning_backend,
        )
        from email_triage.web._audit import safe_audit_write
        raw_bid = (form.get("style_learning_backend_id") or "").strip()
        new_bid: int | None
        if raw_bid:
            new_bid = parse_int_or_none(raw_bid)  # N-219c R23: SSOT
        else:
            new_bid = None

        # Refresh acct snapshot to read the freshly-applied HIPAA flag.
        from email_triage.triage_logging import is_account_hipaa
        cur_acct = get_email_account(db, account_id)
        accept = True
        if new_bid is not None:
            backend = get_ai_backend(db, new_bid)
            if backend is None:
                accept = False
            else:
                # HIPAA gate — match the dropdown filter so a stale
                # cached page (or a hand-crafted POST) can't bypass.
                if is_account_hipaa(cur_acct):
                    # Census N-63 — route this selector gate through the SAME
                    # BAA-validity SSOT the runtime load_backend chokepoint
                    # uses (was an inline hand-roll → drift surface). Boundary
                    # is preserved at the date granularity: the SSOT refuses
                    # when expiry <= today, matching the prior string compare.
                    # (Edge: a stored expiry WITH a time component — e.g.
                    # '2026-06-10T15:00' — was allowed by the old string
                    # compare on the expiry day but is now parsed-to-date and
                    # refused; the change is in the safer fail-closed direction.)
                    from email_triage.baa_expiry import (
                        is_backend_baa_valid_for_phi,
                    )
                    if (
                        not backend.get("enabled")
                        or not is_backend_baa_valid_for_phi(
                            baa_certified=backend.get("baa_certified"),
                            baa_expires_at=backend.get("baa_expires_at"),
                        )
                    ):
                        accept = False
                        # census run17 #3 — route through the safe_audit_write
                        # SSOT so an emit failure is LOGGED to /health's
                        # audit-failure drift counter (was a swallowing
                        # `except Exception` that only warned ad-hoc).
                        safe_audit_write(
                            lambda: record_hipaa_access_event(
                                db,
                                actor_user_id=user["id"],
                                account_id=account_id,
                                operation=(
                                    "style_learning_backend_selection_refused"
                                ),
                                outcome="refused_baa_invariant",
                                detail=(
                                    f"backend_id={new_bid} "
                                    f"baa_certified={backend.get('baa_certified')} "
                                    f"baa_expires_at={backend.get('baa_expires_at')} "
                                    f"enabled={backend.get('enabled')}"
                                ),
                            ),
                            description=(
                                "style_learning_backend_selection_refused "
                                f"account_id={account_id} backend_id={new_bid}"
                            ),
                        )
                elif not backend.get("enabled"):
                    accept = False
        if accept:
            set_account_style_learning_backend(db, account_id, new_bid)
            # Audit row for HIPAA accounts so the auditor sees who
            # selected what + when, with the BAA state captured at
            # selection time.
            if is_account_hipaa(cur_acct):
                # census run17 #3 — route both emits through safe_audit_write so
                # an emit failure reaches /health's audit-failure drift counter.
                # The try/except is KEPT: it still guards the get_ai_backend read
                # in the else-branch (a non-emit statement).
                try:
                    if new_bid is None:
                        safe_audit_write(
                            lambda: record_hipaa_access_event(
                                db,
                                actor_user_id=user["id"],
                                account_id=account_id,
                                operation="style_learning_backend_set",
                                outcome="install_default",
                                detail="cleared FK",
                            ),
                            description=(
                                "style_learning_backend_set cleared "
                                f"account_id={account_id}"
                            ),
                        )
                    else:
                        b = get_ai_backend(db, new_bid)
                        safe_audit_write(
                            lambda: record_hipaa_access_event(
                                db,
                                actor_user_id=user["id"],
                                account_id=account_id,
                                operation="style_learning_backend_set",
                                outcome="ok",
                                detail=(
                                    f"backend_id={new_bid} "
                                    f"name={b['name']!r} "
                                    f"baa_certified={b.get('baa_certified')} "
                                    f"baa_expires_at={b.get('baa_expires_at')}"
                                ),
                            ),
                            description=(
                                "style_learning_backend_set "
                                f"account_id={account_id} backend_id={new_bid}"
                            ),
                        )
                except Exception as audit_err:
                    _log.warning(
                        "style_learning_backend audit row failed",
                        account_id=account_id,
                        error=fmt_exc(audit_err),
                    )

    if "style_learning_backend_id" in form:
        await db_call(_style_backend_db_work)

    #  Phase 2 — M-1+M-2 HIPAA opt-in (per-account).
    # The checkbox is rendered ONLY for HIPAA-flagged accounts AND only
    # for the account owner (the ``{% if acct.hipaa and user.id ==
    # acct.user_id %}`` gate in accounts/_edit.html); for non-HIPAA
    # accounts the M-1+M-2 path is always on, so the setting is
    # irrelevant and we don't write a row. For HIPAA accounts:
    #   * checkbox present  → opt-in ON
    #   * checkbox absent   → opt-in OFF (operator unchecked)
    # Default is OFF (no row in settings = is_style_knobs_hipaa_allow
    # returns False). HIPAA-flag flipping happens earlier in this
    # handler; read the freshly-applied flag rather than the pre-save
    # snapshot so a flip-to-non-HIPAA in the same save doesn't leave a
    # stale opt-in row behind.
    #
    # OWNER-ONLY: per  phase 2 + feedback_hipaa_actor_owner_gate.md,
    # the M-1+M-2 opt-in is the operator's own §164.502(a)
    # self-disclosure ack — admin / delegate cannot tick it on behalf
    # of the account owner. A non-owner POST that carries the field
    # gets a silent refuse + a hipaa_access_events audit row recording
    # the refused attempt. The HIPAA flag flip above (owner-or-admin)
    # is a separate decision: admin can flip the policy bit, but only
    # the data subject can opt their own knobs in.
    from email_triage.web.account_scope import is_account_owner
    _is_owner = is_account_owner(acct, user["id"])

    def _m1m2_optin_db_work() -> None:
        """/ — re-read account + (HIPAA) M-1+M-2 opt-in write +
        audit, all in one threadpool hop.
        """
        from email_triage.triage_logging import is_account_hipaa as _iah_m1m2
        cur_acct = get_email_account(db, account_id)
        # N-81: is_account_hipaa folds system flag (system-HIPAA install
        # with cur_acct["hipaa"]=0 still triggers the opt-in gate).
        if cur_acct and _iah_m1m2(cur_acct):
            if _is_owner:
                from email_triage.web.db import (
                    record_hipaa_access_event,
                    set_style_knobs_hipaa_allow,
                )
                from email_triage.web._audit import safe_audit_write
                desired_optin = ("style_knobs_hipaa_allow" in form)
                set_style_knobs_hipaa_allow(
                    db, account_id,
                    enabled=desired_optin,
                )
                # Audit the owner-self tick (§164.502(a) carve-out
                # doesn't waive the audit trail). Outcome key is the
                # final state so the auditor can read "who set the
                # flag to what + when" off a single row.
                # census run17 #3 — route through safe_audit_write so an emit
                # failure reaches /health's audit-failure drift counter (was a
                # swallowing `except Exception` that only warned ad-hoc).
                safe_audit_write(
                    lambda: record_hipaa_access_event(
                        db,
                        actor_user_id=user["id"],
                        account_id=account_id,
                        operation="style_knobs_hipaa_allow_set",
                        outcome="ok",
                        detail=(
                            "enabled" if desired_optin else "disabled"
                        ),
                    ),
                    description=(
                        "style_knobs_hipaa_allow_set "
                        f"account_id={account_id}"
                    ),
                )
            elif "style_knobs_hipaa_allow" in form:
                # Non-owner POSTed the opt-in field on a HIPAA account
                # they don't own. Silently refuse (no setting write)
                # but record the attempt — the audit row is the
                # paper trail.
                from email_triage.web.db import record_hipaa_access_event
                from email_triage.web._audit import safe_audit_write
                _log.info(
                    "style_knobs_hipaa_allow tick refused — actor != owner",
                    account_id=account_id,
                    actor_user_id=user["id"],
                    owner_user_id=acct["user_id"],
                )
                # census run17 #3 — route through safe_audit_write so an emit
                # failure reaches /health's audit-failure drift counter (was a
                # swallowing `except Exception` that only warned ad-hoc).
                safe_audit_write(
                    lambda: record_hipaa_access_event(
                        db,
                        actor_user_id=user["id"],
                        account_id=account_id,
                        operation="style_knobs_hipaa_allow_set",
                        outcome="refused_non_owner",
                        detail="actor != owner; owner-only opt-in",
                    ),
                    description=(
                        "style_knobs_hipaa_allow_set refused_non_owner "
                        f"account_id={account_id}"
                    ),
                )

    await db_call(_m1m2_optin_db_work)

    # is_active lifecycle transition (Loop-5 census). An account going
    # active→inactive must TEAR DOWN live ingestion (cancel IDLE/poll
    # tasks + leave push registrations dormant behind the actuator gates),
    # and inactive→active must RESTART it. This is a DIFFERENT shape from
    # the config-change bounce below (which stops-then-unconditionally-
    # starts): a deactivation must NOT restart. So we route the is_active
    # edge through the dedicated funnel FIRST, and only fall through to
    # the config-change bounce when the account is (and stays) active —
    # never double-acting. ``acct`` here is the pre-update row from the
    # OwnedAccount dep, so ``acct["is_active"]`` is the OLD value.
    old_is_active = bool(acct.get("is_active", True))
    is_active_changed = old_is_active != bool(is_active)
    if watcher_mgr is not None and is_active_changed:
        try:
            await watcher_mgr.apply_account_active_state(
                account_id, bool(is_active),
            )
            _log.info(
                "Account active-state applied after edit",
                account_id=account_id, active=bool(is_active),
            )
        except Exception as e:
            _log.warning(
                "apply_account_active_state failed",
                account_id=account_id, active=bool(is_active),
                error=fmt_exc(e),
            )

    # Watcher bounce: if either the push/poll flags, the poll cadence,
    # or (for IMAP) the mailbox list changed, tear down and re-start
    # so the change takes effect without a service restart. This is
    # the same pattern #9 established for mailbox changes, now
    # generalised to the three new ingestion knobs.
    #
    # Skip the bounce when the is_active edge already handled this save:
    #   * active→inactive — the funnel just stopped everything; a bounce
    #     would stop-then-start (start is refused by the is_active gate,
    #     but it's wasteful + confusing).
    #   * inactive→active — the funnel just (re)started per the config;
    #     re-bouncing immediately would needlessly cancel + restart.
    # When is_active is unchanged-and-active, a config-flag change still
    # bounces normally. When unchanged-and-inactive, the account isn't
    # running anyway and the funnel didn't fire — the bounce's own start
    # is refused by the is_active gate, so it's a harmless no-op; we let
    # the existing predicate run unchanged for that case.
    if watcher_mgr is not None and not is_active_changed:
        bounce = False
        reason = ""
        old_cfg = existing_config or {}
        new_cfg = config or {}
        if bool(old_cfg.get("push_enabled", True)) != bool(
            new_cfg.get("push_enabled", True),
        ):
            bounce = True
            reason = "push_enabled flag changed"
        elif bool(old_cfg.get("poll_enabled", True)) != bool(
            new_cfg.get("poll_enabled", True),
        ):
            bounce = True
            reason = "poll_enabled flag changed"
        elif int(old_cfg.get("poll_interval_minutes", 60)) != int(
            new_cfg.get("poll_interval_minutes", 60),
        ):
            bounce = True
            reason = "poll_interval_minutes changed"
        elif ptype == "imap":
            from email_triage.web.db import _account_mailboxes
            old_mbs = sorted(_account_mailboxes(old_cfg))
            new_mbs = sorted(_account_mailboxes(new_cfg))
            if old_mbs != new_mbs:
                bounce = True
                reason = "mailbox list changed"

        if bounce:
            try:
                await watcher_mgr.stop(account_id, persist=False)
                await watcher_mgr.start(account_id)
                _log.info(
                    "Watcher bounced after account edit",
                    account_id=account_id, reason=reason,
                )
            except Exception as e:
                _log.warning(
                    "Watcher bounce failed",
                    account_id=account_id, reason=reason, error=fmt_exc(e),
                )

    def _account_row_render_snapshot() -> dict:
        """/ — re-fetch + enrich for the row re-render, in one
        threadpool hop.
        """
        acct_ = get_email_account(db, account_id)
        _enrich_account(acct_, secrets)
        _enrich_account_chips(
            acct_, db, secrets, watcher_mgr=watcher_mgr,
            config=request.app.state.config,
        )
        return acct_

    acct = await db_call(_account_row_render_snapshot)
    return await _render(templates, request, "accounts/_row.html", {
        "acct": acct, "is_admin": is_admin,
    })


@router.post("/accounts/{account_id}/delegates/add", response_class=HTMLResponse)
async def accounts_delegate_add(
    request: Request, account_id: int, user: RequireUserFragment,
):
    """Grant a user delegate access to this account. Owner-or-admin only.

    Form fields:
        user_email: email of the user to grant access to (must exist).
    """
    db = get_db(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")
    from email_triage.web.db import (
        get_email_account, add_account_delegate, list_account_delegates,
    )
    #  phase 3 — DB-before-(form-parse-and-write).
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)
    # Owner-or-admin only — delegates can't grant further delegation.
    # (2026-06-11: routed through the can_administer_account SSOT.)
    if not can_administer_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)
    form = await request.form()
    # Hybrid grant UX: admin dropdown posts user_id; owner free-text
    # posts user_email. Honour either.
    target_user_id = (form.get("user_id") or "").strip()
    target_email = canonical_email(form.get("user_email") or "")
    if not target_email and not target_user_id:
        return HTMLResponse("missing user_id or user_email",
                            status_code=400)

    #  — fold every shared-connection touch (target-user lookup,
    # the @db_write add_account_delegate helper, the post-write
    # delegate-list + grantable-users re-render reads) into one
    # threadpool hop so none of it runs on the event-loop thread.
    def _delegate_add_db_work() -> dict:
        """ — resolve target user, grant the delegate, build the
        re-render context. Runs entirely off-loop under the DB lock.
        """
        # Refresh grantable_users for re-render. Inline (not a nested
        # db_call) — it shares this closure's threadpool hop + lock.
        def _grantable():
            if is_admin:
                rows = db.execute(
                    "SELECT id, email, name FROM users WHERE id != ? "
                    "ORDER BY COALESCE(NULLIF(name, ''), email)",
                    (acct["user_id"],),
                ).fetchall()
                return [dict(r) for r in rows]
            return None

        target = None
        if target_user_id:
            try:
                target = db.execute(
                    "SELECT id, email, name FROM users WHERE id = ?",
                    (int(target_user_id),),
                ).fetchone()
            except (ValueError, TypeError):
                target = None
        if target is None and target_email:
            target = db.execute(
                "SELECT id, email, name FROM users WHERE LOWER(email) = ?",
                (target_email,),
            ).fetchone()

        if target is None:
            identifier = (
                form.get("user_email") or form.get("user_id") or ""
            ).strip()
            return {
                "acct": acct,
                "delegates": list_account_delegates(db, account_id),
                "error": f"No user found matching '{identifier}'",
                "is_admin": is_admin,
                "user": user,
                "grantable_users": _grantable(),
            }
        try:
            added = add_account_delegate(
                db, account_id, target["id"], granted_by=user["id"],
            )
        except ValueError as e:
            return {
                "acct": acct,
                "delegates": list_account_delegates(db, account_id),
                "error": scrub_exc(e, purpose="misc"),  # N-179 R21_2
                "is_admin": is_admin,
                "user": user,
                "grantable_users": _grantable(),
            }
        if added:
            _log.info(
                "Account delegate granted",
                account_id=account_id, account_name=acct.get("name", ""),
                target_user_id=target["id"], target_email=target["email"],
                granted_by=user["id"],
            )
        return {
            "acct": acct,
            "delegates": list_account_delegates(db, account_id),
            "is_admin": is_admin,
            "user": user,
            "grantable_users": _grantable(),
        }

    ctx = await db_call(_delegate_add_db_work)
    return await _render(templates, request, "accounts/_delegates.html", ctx)


@router.delete(
    "/accounts/{account_id}/delegates/{user_id}",
    response_class=HTMLResponse,
)
async def accounts_delegate_remove(
    request: Request, account_id: int, user_id: int,
    user: RequireUserFragment,
):
    """Revoke a delegate. Owner-or-admin only."""
    db = get_db(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")
    from email_triage.web.db import (
        get_email_account, remove_account_delegate, list_account_delegates,
    )
    #  phase 3 — DB-before-write.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)
    # Owner-or-admin only — delegates can't revoke delegation.
    # (2026-06-11: routed through the can_administer_account SSOT.)
    if not can_administer_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)
    #  — fold the @db_write remove_account_delegate helper plus the
    # post-write delegate-list + grantable-users re-render reads into a
    # single threadpool hop; none of it runs on the event-loop thread.
    def _delegate_remove_db_work() -> dict:
        if remove_account_delegate(db, account_id, user_id):
            _log.info(
                "Account delegate revoked",
                account_id=account_id, account_name=acct.get("name", ""),
                target_user_id=user_id, revoked_by=user["id"],
            )
        grantable = None
        if is_admin:
            rows = db.execute(
                "SELECT id, email, name FROM users WHERE id != ? "
                "ORDER BY COALESCE(NULLIF(name, ''), email)",
                (acct["user_id"],),
            ).fetchall()
            grantable = [dict(r) for r in rows]
        return {
            "acct": acct,
            "delegates": list_account_delegates(db, account_id),
            "is_admin": is_admin,
            "user": user,
            "grantable_users": grantable,
        }

    ctx = await db_call(_delegate_remove_db_work)
    return await _render(templates, request, "accounts/_delegates.html", ctx)


@router.post("/accounts/{account_id}/aliases/add", response_class=HTMLResponse)
async def accounts_alias_add(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Add an additional address to an account.

    Owner / delegate / admin can add (same gate as the main account
    save). The submitted address is validated for RFC shape and
    de-duplication before write; on validation failure the partial
    re-renders with an inline error message above the table.
    """
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")
    from email_triage.web.db import (
        AliasValidationError,
        account_email,
        get_email_account,
        normalize_aliases,
        update_email_account_aliases,
    )

    form = await request.form()
    new_address = canonical_email(form.get("address") or "")
    new_label = (form.get("label") or "").strip()

    existing = list(acct.get("aliases") or [])
    proposed = list(existing) + [{"address": new_address, "label": new_label}]
    primary = account_email(acct)

    try:
        cleaned = normalize_aliases(proposed, primary=primary)
    except AliasValidationError as e:
        return await _render(templates, request, "accounts/_aliases.html", {
            "acct": acct, "user": user, "is_admin": is_admin,
            "alias_error": str(e),
        })

    #  phase 2 — write off the loop.
    await db_call(update_email_account_aliases, db, account_id, cleaned)
    _log.info(
        "Account alias added",
        account_id=account_id, address=new_address,
        actor_user_id=user["id"],
    )
    acct = await db_call(get_email_account, db, account_id)
    return await _render(templates, request, "accounts/_aliases.html", {
        "acct": acct, "user": user, "is_admin": is_admin,
    })


@router.post(
    "/accounts/{account_id}/aliases/remove",
    response_class=HTMLResponse,
)
async def accounts_alias_remove(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Remove an additional address from an account.

    Body field: ``address`` — the alias to drop. Idempotent: a remove
    request for an address that isn't present re-renders the same
    partial with no change.
    """
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin")
    from email_triage.web.db import (
        get_email_account,
        update_email_account_aliases,
    )

    form = await request.form()
    target = canonical_email(form.get("address") or "")
    existing = list(acct.get("aliases") or [])
    # Census wf_56d1585d 2026-07-09  — §164.312(a)(1) actuator fix:
    # BOTH sides of the compare must go through `canonical_email` so an
    # IDN alias (`Name <a@münchen.de>`) or a display-wrapped alias
    # (`John <john@x.com>`) matches its stored form. Previously the
    # target used `canonical_email` but the stored side used
    # `.strip().lower()` — the two normalisations diverge on IDN /
    # display-wrapped aliases and revoke silently no-op'd (fail-
    # forward-OPEN on a HIPAA-scoped permission op).
    kept = [
        e for e in existing
        if canonical_email(str((e or {}).get("address") or "")) != target
    ]
    if len(kept) != len(existing):
        def _alias_remove_snapshot(db, account_id, kept):
            """ phase 2 — write + re-fetch in one threadpool hop."""
            update_email_account_aliases(db, account_id, kept)
            return get_email_account(db, account_id)

        acct = await db_call(_alias_remove_snapshot, db, account_id, kept)
        _log.info(
            "Account alias removed",
            account_id=account_id, address=target,
            actor_user_id=user["id"],
        )
    return await _render(templates, request, "accounts/_aliases.html", {
        "acct": acct, "user": user, "is_admin": is_admin,
    })


@router.delete("/accounts/{account_id}", response_class=HTMLResponse)
async def accounts_delete(
    request: Request, account_id: int, user: RequireUserFragment,
):
    db = get_db(request)

    from email_triage.web.db import get_email_account

    def _accounts_delete_snapshot(db, account_id):
        """ phase 2 — fetch + auth check ONLY in one hop.

        Returns ('ok', acct) | ('not_found', None) | ('forbidden', None).
        The actual DELETE is done AFTER the watcher/purge funnel in the
        async caller so that watcher teardown + secrets purge happen
        before the row is gone (the purge funnel reads the account for
        the watch preference; it also needs the id to build secret keys).

        Account deletion is owner-or-admin only — a delegate must NOT be
        able to destroy the account (2026-06-11: routed through the
        can_administer_account SSOT; ``user`` is captured from the route).
        """
        acct = get_email_account(db, account_id)
        if acct is None:
            return "not_found", None
        if not can_administer_account(db, user, acct):
            return "forbidden", None
        return "ok", acct

    status, _acct = await db_call(
        _accounts_delete_snapshot, db, account_id,
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    # L1 + L2 — tear down the live watcher + PURGE settings/secrets BEFORE the
    # row delete (apply_account_deleted: best-effort watcher stop + the
    # §164.310(d)(2)(i) credential purge; clears the watch:{id} preference).
    # Fail CLOSED: if the purge raises, do NOT delete the row — that would
    # orphan the credentials in secrets_store (the very defect this fixes); the
    # operator retries. Watcher-stop is best-effort inside the funnel, so only
    # a real purge failure trips this gate.
    from email_triage.db.accounts import purge_account_local_state
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    try:
        if watcher_mgr is not None:
            await watcher_mgr.apply_account_deleted(
                account_id, actor_user_id=user["id"],
            )
        else:
            # No watcher manager (test / lifespan-off) — run the purge directly.
            secrets = getattr(request.app.state, "secrets", None)
            await db_call(purge_account_local_state, db, account_id, secrets)
    except Exception as _e:
        _log.error(
            "accounts_delete: local-state purge FAILED — aborting delete to "
            "avoid orphaning stored credentials",
            account_id=account_id,
            error=fmt_exc(_e),
        )
        return HTMLResponse(
            "Delete failed: stored credentials could not be purged. The "
            "account was NOT deleted — please retry.",
            status_code=500,
        )

    # Soft-deactivate, NEVER hard-delete (operator ruling 2026-06-20, N-108): a
    # DELETE FROM email_accounts cascade-deletes the account's hipaa_access_events
    # (account_id ON DELETE CASCADE) — the SAME §164.312(b)/(c)(1) audit
    # destruction the  ruling forbade for users. Credentials are purged above
    # (§164.310(d)(2)(i) disposal); the row + ALL audit history are RETAINED.
    from email_triage.db.accounts import set_account_active
    await db_call(set_account_active, db, account_id, False)

    # Re-render the row in its deactivated state (the admin keeps managing it,
    # like a disabled user — it does not vanish).
    templates = get_templates(request)
    secrets = getattr(request.app.state, "secrets", None)
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)
    is_admin = _is_admin(user)  # N-222g R22 (was: user["role"] == "admin") — RequireUserFragment is never None

    def _deactivated_row_snapshot() -> dict | None:
        a = get_email_account(db, account_id)
        if a is None:  # narrow post-commit race — never under the no-hard-delete invariant
            return None
        _enrich_account(a, secrets)
        _enrich_account_chips(
            a, db, secrets, watcher_mgr=watcher_mgr,
            config=request.app.state.config,
        )
        return a

    acct2 = await db_call(_deactivated_row_snapshot)
    if acct2 is None:
        return HTMLResponse("")  # row already gone — blank it (no 500)
    return await _render(templates, request, "accounts/_row.html", {
        "acct": acct2, "user": user, "is_admin": is_admin,
    })


@router.post("/accounts/{account_id}/test", response_class=HTMLResponse)
async def accounts_test(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Test an account's connection using its saved config + secrets."""
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, secrets = owned

    ok, msg = await _test_account_connection(acct, secrets)

    if ok:
        # A successful connection test proves the credential is alive → clear
        # any prior auth_stale chip. The Test action was one of the two sites
        # the canary explicitly named as a missing clear (the other was the
        # push consumer). Census 2026-06-09 #1. (Test FAILURE is shown to the
        # operator directly, so it does not need to set the chip — the
        # continuous poll/push paths own the SET edge.)
        from email_triage.web.app import record_provider_outcome
        await db_call(record_provider_outcome, db, acct, None)

    # 23b nudge: when Test succeeds but real-time watch is off, point the
    # user at the Start button so they don't have to hunt for it. Gmail
    # API in poll mode has its own cadence already — skip the nudge there
    # (the Start button on that provider raises NotImplementedError).
    if ok:
        from email_triage.web.app import get_watcher_manager
        try:
            mgr = get_watcher_manager(request)
            watching = mgr.is_running(account_id)
        except Exception:
            watching = False

        ptype = acct["provider_type"]
        if not watching and ptype == "imap":
            msg += (
                '<div style="margin-top:0.35rem;">'
                '<small>⏩ Real-time watch is not running. '
                f'<a href="#" hx-post="/accounts/{account_id}/watch/start"'
                f' hx-target="#test-result-{account_id}"'
                f' hx-swap="innerHTML">Start it now →</a>'
                '</small></div>'
            )
        elif not watching and ptype == "gmail_api":
            from email_triage.web.db import get_gmail_watch
            #  phase 3 — DB read after the network test() above; the
            # threadpool hop here lets a concurrent request progress while
            # the gmail_watch row is read.
            watch = await db_call(get_gmail_watch, db, account_id)
            if not watch or not (watch.get("topic_name") or "").strip():
                msg += (
                    '<div style="margin-top:0.35rem;">'
                    '<small>⏩ Gmail is running in poll mode. '
                    'Configure push on the Routes page for instant delivery.'
                    '</small></div>'
                )

    return HTMLResponse(msg)


# ---------------------------------------------------------------------------
# Gmail API OAuth — authorization-code flow (web callback + manual paste)
#
# Two paths for the same flow:
#
# - Web callback (primary): Google redirects to
#   ``<public_url>/oauth/google/callback`` after consent. Requires a
#   "Web application" OAuth client + the redirect URI registered in
#   GCP. Push notifications already require a public URL, so production
#   installs land here naturally.
#
# - Manual paste (fallback / troubleshooting): Google redirects to the
#   loopback URL ``http://127.0.0.1:1/`` which the user's browser
#   fails to load. The URL with ``?code=…`` is still in the address
#   bar; the user pastes it back. Works with a "Desktop" OAuth client,
#   no public URL, no client_secret.
#
# Both paths converge on ``exchange_code_for_tokens`` to obtain the
# refresh token, then store it in DbSecrets the same way.
# ---------------------------------------------------------------------------

# Manual-paste loopback URI — Google requires registering this exact
# string when using a Desktop client. The port is intentionally low
# and unlikely to ever have a listener; the redirect always fails to
# load, which is the whole point.
@router.get("/accounts/{account_id}/folders", response_class=HTMLResponse)
async def accounts_folders(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """List available folders/labels for an account (JSON fragment or HTML)."""
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, _, secrets = owned

    try:
        provider = _create_provider_from_account(acct, secrets)
        folders = await provider.list_folders()
        await provider.close()
    except NotImplementedError:
        folders = []
    except Exception as e:
        return HTMLResponse(
            error_chip(e, prefix='Error listing folders: ')
        )

    # Return as JSON if requested via Accept header, else HTML options.
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        from fastapi.responses import JSONResponse
        return JSONResponse({"folders": folders})

    # Return as <option> elements for a <select>. A8 (SME DA): escape the
    # IMAP folder name — a hostile/compromised mail server can return a
    # folder named ``"><script>…`` that would break out of the option and
    # execute in the operator's authenticated, PHI-bearing admin session.
    import html as _html
    options_html = "\n".join(
        f'<option value="{_html.escape(f)}">{_html.escape(f)}</option>'
        for f in folders
    )
    return HTMLResponse(options_html)


@router.post("/accounts/{account_id}/folders/create", response_class=HTMLResponse)
async def accounts_folder_create(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Create a new folder on the account's mail server."""
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, _, secrets = owned

    form = await request.form()
    folder_name = form.get("folder", "").strip()
    parent = form.get("parent", "").strip()

    if not folder_name:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">Folder name is required.</small>'
        )

    # Build full path: if a parent is selected, join with separator.
    if parent:
        # Detect separator from parent name.
        sep = "/" if "/" in parent else "."
        full_path = f"{parent}{sep}{folder_name}"
    else:
        full_path = folder_name

    try:
        provider = _create_provider_from_account(acct, secrets)
        await provider.create_folder(full_path)
        await provider.close()
    except NotImplementedError:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">Provider does not support folder creation.</small>'
        )
    except Exception as e:
        return HTMLResponse(
            error_chip(e, prefix='Error: ')
        )

    # N-277 R29: fresh folder just landed → invalidate the 5-min-TTL
    # provider-labels cache so the response's "Available in the move-
    # folder picker now" line is TRUTHFUL. Without this, the picker
    # served stale (pre-create) labels for up to 5 min — the LIVE UX
    # defect the R29 census flagged.
    try:
        from email_triage.providers.provider_labels import (
            invalidate_cache_for_account,
        )
        invalidate_cache_for_account(int(account_id))
    except Exception:
        pass

    # Emit a hidden marker (#et-new-folder data-name="<full_path>")
    # so the routes-table JS can append a new option to every per-row
    # move-folder dropdown without a page reload. The chip itself
    # remains the visible success message.
    import html as _html
    safe_name = _html.escape(full_path)
    return HTMLResponse(
        f'<small style="color:var(--pico-ins-color);">'
        f'&#x2713; Folder <code>{safe_name}</code> created. '
        f'Available in the move-folder picker now.</small>'
        f'<span id="et-new-folder" hidden data-name="{safe_name}"></span>'
    )


# ---------------------------------------------------------------------------
# Account routes (category → action mappings per account)
# ---------------------------------------------------------------------------

@router.get("/accounts/{account_id}/folders/prefs", response_class=HTMLResponse)
async def accounts_folder_prefs_page(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Show the folder subscription page — check/uncheck folders to show in dropdowns.

    Migrated to ``OwnedAccountOrLogin`` — full-page
    navigation target keeps redirect-to-/login UX for anonymous users.
    """
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)

    from email_triage.web.db import get_folder_prefs

    # Fetch the full folder list from the server.
    all_folders: list[str] = []
    error = ""
    try:
        provider = _create_provider_from_account(acct, secrets)
        all_folders = await provider.list_folders()
        await provider.close()
    except Exception as e:
        #  tail — provider errors from IMAP/OAuth may echo secret
        # fragments (OAuth WWW-Authenticate: Bearer error_description
        # can leak client-secret fragments + tokens per HIPAA-SME
        # N-179). DB-SME F1 on 2026-07-11 batched panel: use
        # ``purpose='provider'`` (SENSITIVE — takes the fail-closed
        # generic-message branch of scrub_exc). The raw exception is
        # already captured privileged-side via the log below.
        _log.warning(
            "list_folders failed",
            extra={"error": str(e), "account_id": account_id},
        )
        error = f"Could not list folders: {scrub_exc(e, purpose='provider')}"

    #  phase 2 — folder-prefs read off the loop.
    prefs = await db_call(get_folder_prefs, db, account_id)
    folder_included = {}
    for f in all_folders:
        folder_included[f] = prefs.get(f, True)

    tree = _build_folder_tree(all_folders)

    return await _render(templates, request, "accounts/folder_prefs.html", {
        "user": user,
        "acct": acct,
        "tree": tree,
        "folder_included": folder_included,
        "total_folders": len(all_folders),
        "error": error,
    })


@router.post("/accounts/{account_id}/folders/prefs", response_class=HTMLResponse)
async def accounts_folder_prefs_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Save folder include/exclude preferences."""
    #  — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned

    from email_triage.web.db import save_folder_prefs

    form = await request.form()
    # The form sends all folder paths as hidden inputs,
    # and the checked ones also come as "included" list values.
    all_folder_paths = form.getlist("all_folders")
    included_paths = set(form.getlist("included"))

    prefs = {}
    for path in all_folder_paths:
        prefs[path] = path in included_paths

    #  phase 2 — write off the loop.
    await db_call(save_folder_prefs, db, account_id, prefs)

    # Redirect back to routes page with a success flash.
    from starlette.responses import RedirectResponse as _Redirect
    return _Redirect(
        f"/accounts/{account_id}/routes?folder_msg="
        f"{len(included_paths)}+of+{len(all_folder_paths)}+folders+visible",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Newsletter Digest — Multi-Schedule Management
# ---------------------------------------------------------------------------


