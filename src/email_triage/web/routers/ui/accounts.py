"""Routes for the accounts concern.

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

_log = get_logger("web.ui.accounts")

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


# ---------------------------------------------------------------------------
# #169 Wave 2-α I6 — per-account style-learning backend selector helper.
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
                try:
                    sel_d = date.fromisoformat(str(sel_exp)[:10])
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
                except (TypeError, ValueError):
                    chip = f"Vendor agreement in force until {sel_exp}."
            elif sel.get("baa_certified"):
                chip = "Vendor agreement in force (no expiry set)."
            else:
                chip = "No vendor agreement on file (non-HIPAA only)."
    return options, chip


@router.get("/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    templates = get_templates(request)
    # #135 phase 2 — wrap-at-snapshot: build the entire context off the
    # event loop so concurrent /health polls + other operator surfaces
    # don't serialise behind the per-account chip enrichment.
    ctx = await db_call(_build_accounts_page_snapshot, request, user)
    return _render(templates, request, "accounts/manage.html", ctx)


@router.get("/accounts/form-fields", response_class=HTMLResponse)
async def accounts_form_fields(request: Request, provider_type: str = "imap"):
    """Return provider-specific form fields fragment (HTMX swap)."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    if provider_type not in _PROVIDER_TYPES:
        return HTMLResponse("Unknown provider type", status_code=400)

    templates = get_templates(request)
    config = get_config(request)
    return _render(templates, request, f"accounts/_fields_{provider_type}.html", {
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
    # #137 phase 2 — OwnedAccount dep collapses the
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
async def accounts_create(request: Request):
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    form = await request.form()
    db = get_db(request)
    secrets = get_secrets(request)
    is_admin = user["role"] == "admin"

    name = form.get("name", "").strip()
    ptype = form.get("provider_type", "imap")

    if ptype not in _PROVIDER_TYPES:
        return RedirectResponse("/accounts", status_code=303)

    # Admin can assign to any user; regular users own their own accounts.
    if is_admin and form.get("user_id"):
        owner_id = int(form["user_id"])
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
            from urllib.parse import urlencode
            params = urlencode({
                "error": (
                    f"Too many folders selected ({len(selected)} > cap of {cap}). "
                    "Most IMAP servers limit concurrent connections per user."
                ),
            })
            return RedirectResponse(f"/accounts?{params}", status_code=303)

    # Per-account HIPAA flag. When system HIPAA is on, the create helper
    # sticky-inherits the flag regardless; otherwise the admin opts in
    # via the form checkbox.
    from email_triage.triage_logging import is_hipaa_mode
    hipaa_flag = None
    if not is_hipaa_mode():
        hipaa_flag = "hipaa" in form

    from email_triage.web.db import create_email_account, set_bool_setting
    account_id = create_email_account(
        db, owner_id, name, ptype, config, hipaa=hipaa_flag,
    )

    # Calendar opt-in at create time (B2) — same wiring as edit.
    if ptype in ("gmail_api", "office365") and config.get("calendar_opted_in"):
        set_bool_setting(db, _S.calendar_enabled(account_id), True)

    # Save password/secret now that we have the account ID.
    _save_provider_secret(form, ptype, account_id, secrets)

    # Item #23a: auto-activate watcher after a successful connection
    # test. Opt-in via the "Start watching for new mail right away"
    # checkbox (default-checked in the template). Provider-aware:
    # IMAP gets a real IDLE watcher; Gmail in poll mode is a no-op
    # because WatcherManager.start raises on gmail_api; Office 365
    # currently has no inline probe, so we skip quietly.
    flash_success = "Account added."
    flash_error = ""
    if "start_watch" in form:
        # #138 phase 2 — table-driven dispatch. Each ptype's
        # post_create_start_watch returns ``(success_msg, error_msg)``;
        # exactly one is non-empty (or both empty for O365 where no
        # action runs).
        from email_triage.web.db import get_email_account
        from email_triage.providers.dispatcher import get_dispatch
        from email_triage.web.app import get_watcher_manager
        fresh_acct = get_email_account(db, account_id)
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
    # #137 — ``OwnedAccount`` collapses the get_current_user → get_db
    # → get_secrets → get_email_account → can_manage_account preamble
    # into one Annotated dep. Raises HTTPException 401 / 404 / 403
    # with the same shape the inline preamble used (the global error
    # handler renders the operator-facing page or JSON).
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    from email_triage.triage_logging import (
        is_account_hipaa, is_account_hipaa_locked,
    )

    # #135 phase 2 — pre-provider DB snapshot (chips + delegates +
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
    # #154 retired the per-account "watches" tab; if a legacy bookmark
    # still passes ?tab=watches we silently land on the default tab so
    # the operator sees a working page rather than a 404.
    valid_tabs = {
        "provider", "watch", "digests",
        "integrations", "delegates",
    }
    tab = (request.query_params.get("tab") or "provider").strip()
    if tab not in valid_tabs:
        tab = "provider"

    # #96 — hide the OpenClaw chip when no webhook targets are
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

    # #169 Wave 2-α I6 — per-account style-learning backend selector.
    # Dropdown options filter on the account's HIPAA posture:
    #   * HIPAA account / system HIPAA mode:
    #       enabled=1 AND baa_certified=1 AND baa_expires_at > today
    #   * Non-HIPAA:
    #       enabled=1
    # The status-chip string is rendered server-side so the template
    # can read it without a second DB round-trip.
    from email_triage.triage_logging import is_hipaa_mode
    ai_backend_options, ai_backend_selected_chip = (
        _build_ai_backend_selector_context(db, acct)
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
    if request.headers.get("HX-Request") == "true":
        return _render(templates, request, "accounts/_edit.html", ctx)
    return _render(templates, request, "accounts/edit_page.html", ctx)


@router.get("/accounts/{account_id}/row", response_class=HTMLResponse)
async def accounts_row(request: Request, account_id: int):
    """Return a single row fragment (for cancel from edit mode)."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    acct = await db_call(_accounts_row_snapshot, request, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)

    return _render(templates, request, "accounts/_row.html", {
        "acct": acct, "is_admin": is_admin,
    })


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
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)

    smtp = config.smtp
    if not smtp.host:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "SMTP not configured. Configure SMTP on /config "
            "first.</small>"
        )

    # Resolve via the helper so IMAP accounts (config["username"])
    # work alongside Gmail / O365 (config["account"]). Open-coding
    # the lookup here was the bug operators reported as
    # "Account has no email address" on every IMAP-backed account.
    to_addr = (acct.get("email_address") or "").strip()
    if not to_addr:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Account has no email address. Save the account first.</small>"
        )

    from datetime import datetime, timezone, timedelta
    from email_triage.actions.recipient_digest import (
        gather_digest_rows, send_recipient_digest, mark_sent,
    )
    from email_triage.triage_logging import is_hipaa_mode

    now_utc = datetime.now(timezone.utc)
    since_iso = (now_utc - timedelta(hours=24)).isoformat()
    rows = gather_digest_rows(
        db, account_id=account_id, since_iso=since_iso,
    )
    if not rows:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "No triage activity in the last 24 hours; "
            "nothing to send.</small>"
        )

    hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))

    try:
        smtp_password = secrets.get("SMTP_PASSWORD") or ""
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
            fallback_dt_iso=now_utc.isoformat(),
        )
        # Stamp last_sent so the scheduler's idempotence guard
        # picks up the manual send too — no surprise duplicate at
        # the next HH:10 firing within 23h.
        mark_sent(db, account_id, now_utc, len(rows))
        # Audit row mirroring the scheduler's path.
        try:
            from email_triage.web.db import record_access_event
            record_access_event(
                db,
                actor_user_id=user["id"],
                method="POST",
                route=f"/accounts/{account_id}/recipient-digest/send-now",
                account_id=account_id,
                message_id=None,
                status_code=200,
                outcome="recipient_digest_sent",
                detail=(
                    f"row_count={len(rows)} hipaa={hipaa} "
                    f"to={to_addr} manual=true"
                ),
            )
        except Exception:
            pass
        return HTMLResponse(
            "<small style='color:var(--pico-ins-color);'>"
            f"&#10003; Sent {len(rows)} row digest to "
            f"<code>{to_addr}</code></small>"
        )
    except Exception as e:
        _log.error(
            "Recipient digest test-send failed",
            account_id=account_id, error=fmt_exc(e),
        )
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            f"Send failed: {fmt_exc(e)}</small>"
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
    # #137 phase 2 — OwnedAccountOrLogin keeps the redirect-to-/login
    # UX for full-page nav targets while collapsing the rest of the
    # preamble. Anon → 303 to /login; non-owner → HTTPException 403.
    if isinstance(ctx, RedirectResponse):
        return ctx
    user, acct, db, secrets = ctx
    return RedirectResponse(
        f"/accounts/{account_id}/digests/new/edit",
        status_code=303,
    )


@router.get(
    "/accounts/{account_id}/digests/new/edit",
    response_class=HTMLResponse,
)
async def digest_editor_new(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Editor for a not-yet-saved digest. ``dcfg.id`` empty until
    first save mints one in ``upsert_digest_config``."""
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)
    ctx = _digest_editor_context(db, request, account_id, dcfg=None)
    ctx["user"] = user
    return _render(templates, request, "accounts/_digest_editor.html", ctx)


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
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)

    dcfg = get_digest_config(db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse("Digest not found", status_code=404)
    ctx = _digest_editor_context(db, request, account_id, dcfg=dcfg)
    ctx["user"] = user
    ctx["is_preset"] = (dcfg.id == PRESET_ID)
    return _render(templates, request, "accounts/_digest_editor.html", ctx)


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
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
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
        ctx = _digest_editor_context(db, request, account_id, dcfg=cfg)
        ctx["user"] = user
        ctx["is_preset"] = (cfg.id == PRESET_ID)
        ctx["errors"] = errors
        return _render(
            templates, request, "accounts/_digest_editor.html", ctx,
        )

    upsert_digest_config(db, account_id, cfg)
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
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    if digest_id == PRESET_ID:
        return HTMLResponse(
            "Cannot delete the preset digest.", status_code=400,
        )
    delete_digest_config(db, account_id, digest_id)
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
    from datetime import datetime, timezone
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _fire_one_digest

    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)
    smtp = config.smtp
    if not smtp.host:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "SMTP not configured.</small>"
        )
    to_addr = (acct.get("email_address") or "").strip()
    if not to_addr:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Account has no email address. Save the account first."
            "</small>"
        )
    dcfg = get_digest_config(db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    from email_triage.triage_logging import is_hipaa_mode
    hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))
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
        if is_newsletter:
            msg = (
                f"✓ Sent to {to_addr} ({rows_sent} message"
                f"{'s' if rows_sent != 1 else ''}). "
                "Newsletter formats can take a minute or two to "
                "build — if the email doesn't arrive shortly, "
                "try Send test now again."
            )
        else:
            msg = (
                f"✓ Sent to {to_addr} ({rows_sent} message"
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
            "<small style='color:var(--pico-del-color);'>"
            f"Send failed: {fmt_exc(e)}</small>"
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
    """
    from datetime import datetime, timezone
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _filter_digest_candidates

    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    dcfg = get_digest_config(db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    now_utc = datetime.now(timezone.utc)
    try:
        rows = _filter_digest_candidates(
            db=db, acct=acct, dcfg=dcfg,
            now_utc=now_utc, last_sent=None,
        )
    except Exception as e:
        _log.error(
            "Digest candidates failed",
            account_id=account_id, digest_id=digest_id,
            error=fmt_exc(e),
        )
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            f"Candidate lookup failed: {fmt_exc(e)}</small>"
        )

    n = len(rows)
    if n == 0:
        return HTMLResponse(
            "<small style='color:var(--pico-muted-color);'>"
            "No matching messages in the selected window. "
            "Adjust the Cover or filter settings, save, and try "
            "Show matches again.</small>"
        )

    # ETA hint for newsletter formats. Other formats render in
    # under a second so the hint is irrelevant.
    is_newsletter = dcfg.format.render_as in (
        "newsletter", "newsletter_classic",
    )
    eta_line = ""
    if is_newsletter:
        # ~30-90s per source — give the range so the operator
        # can plan around it.
        low_min = max(1, (n * 30) // 60)
        high_min = max(1, (n * 90) // 60)
        eta_line = (
            f" Newsletter render uses AI to summarize each "
            f"source — estimated wait if you Preview or Send: "
            f"~{low_min}–{high_min} minutes."
        )

    # Build a small table — keep it scannable, no body preview.
    import html as _html
    parts = [
        "<div style='font-size:0.85em;'>",
        f"<p style='margin:0.3rem 0;'><strong>{n} message"
        f"{'s' if n != 1 else ''}</strong> would be included."
        f"{eta_line}</p>",
        "<table style='font-size:0.85em;'>",
        "<thead><tr>"
        "<th>When</th><th>Sender</th>"
        "<th>Subject</th><th>Category</th>"
        "</tr></thead><tbody>",
    ]
    for r in rows:
        parts.append(
            "<tr>"
            f"<td>{_html.escape(str(r.get('date') or '—'))[:16]}</td>"
            f"<td>{_html.escape(str(r.get('sender') or '—'))}</td>"
            f"<td>{_html.escape(str(r.get('subject') or '—'))}</td>"
            f"<td>{_html.escape(str(r.get('category') or '—'))}</td>"
            "</tr>"
        )
    parts.append("</tbody></table></div>")
    return HTMLResponse("".join(parts))


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
    from datetime import datetime, timezone
    from email_triage.actions.digest_configs import (
        get_digest_config,
    )
    from email_triage.web.app import _render_digest_payload

    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    config = get_config(request)
    dcfg = get_digest_config(db, account_id, digest_id)
    if dcfg is None:
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            "Digest not found.</small>", status_code=404,
        )

    from email_triage.triage_logging import is_hipaa_mode
    hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))
    now_utc = datetime.now(timezone.utc)
    try:
        subject, html_body, _plain, rows = await _render_digest_payload(
            db=db, secrets=secrets, acct=acct, dcfg=dcfg,
            hipaa=hipaa, now_utc=now_utc, last_sent=None,
            config=config,
        )
    except Exception as e:
        _log.error(
            "Digest preview failed",
            account_id=account_id, digest_id=digest_id,
            error=fmt_exc(e),
        )
        return HTMLResponse(
            "<small style='color:var(--pico-del-color);'>"
            f"Preview failed: {fmt_exc(e)}</small>"
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
    # iframe srcdoc sandboxes the digest's own styles. Use double
    # quotes around srcdoc + escape the HTML content for safety.
    iframe_src = _html.escape(html_body, quote=True)
    return HTMLResponse(
        "<div style='font-size:0.85em;'>"
        "<p style='margin:0.3rem 0;'>"
        "<strong>Preview — not sent.</strong> "
        f"Subject: <code>{_html.escape(subject)}</code> · "
        f"{n} message{'s' if n != 1 else ''} included."
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
    # #137 phase 2 — OwnedAccount dep collapses preamble.
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
            "<small style='color:var(--pico-del-color);'>"
            f"✗ {fmt_exc(e)}</small>"
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
    # #137 — preamble collapsed to ``OwnedAccount``. The save-POST
    # sibling forwards its own ``owned`` tuple so the dep runs once
    # per request, not twice. Local imports below stay narrow to keep
    # cherry-pick locality tight against parallel-agent edits in the
    # same file (Bundles C / G / L all touch ui.py too).
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

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
            _enrich_account(acct, secrets)
            try:
                wm = _gwm(request)
            except Exception:
                wm = None
            _enrich_account_chips(acct, db, secrets, watcher_mgr=wm, config=request.app.state.config)
            from email_triage.web.db import list_account_delegates
            return _render(templates, request, "accounts/_edit.html", {
                "acct": acct, "is_admin": is_admin, "user": user,
                "delegates": list_account_delegates(db, account_id),
                "mailbox_cap_error": (
                    f"Too many folders selected ({len(selected)} > cap of {cap}). "
                    "Most IMAP servers limit concurrent connections per user — "
                    "pick fewer folders or raise "
                    "``provider.imap.max_mailboxes_per_account`` in the YAML config."
                ),
            })

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
            preset.enabled = bool(config.get("recipient_digest_enabled", False))
            preset.schedule.time_local = (
                config.get("recipient_digest_send_at") or "08:10"
            )
            upsert_digest_config(db, account_id, preset)
    except Exception as e:
        # Sync is best-effort — the legacy fields still drive the
        # Phase 4 migration on first read, and the preset config
        # is always re-derivable from them. Log + move on.
        from email_triage._errfmt import fmt_exc
        _log.warning(
            "digest preset sync failed",
            account_id=account_id, error=fmt_exc(e),
        )

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
        set_bool_setting(
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

    # #50 — HIPAA flag flip is owner-or-admin only. Delegates
    # explicitly can NOT change the flag (blast-radius op: toggling
    # off downgrades audit posture for an account that may carry
    # PHI). Skip the whole block when a delegate posts the form —
    # the rest of the save still applies.
    _hipaa_owner_or_admin = (
        acct["user_id"] == user["id"] or is_admin
    )
    if "hipaa_submitted" in form and _hipaa_owner_or_admin:
        desired = "hipaa" in form
        # 2026-05-11 — capture pre-save HIPAA state so we can detect a
        # 0→1 flip after the set. The AI-learns toggle is auto-off'd
        # when an account becomes HIPAA so future renders reflect the
        # explicit OFF state until the operator manually re-enables it.
        was_hipaa = bool(acct.get("hipaa"))
        try:
            from email_triage.web.db import set_account_hipaa
            set_account_hipaa(db, account_id, desired, actor_id=user["id"])
        except PermissionError as e:
            # Lock violation — surface inline, don't 500.
            acct = get_email_account(db, account_id)
            _enrich_account(acct, secrets)
            _enrich_account_chips(acct, db, secrets, watcher_mgr=watcher_mgr, config=request.app.state.config)
            return _render(templates, request, "accounts/_row.html", {
                "acct": acct, "is_admin": is_admin,
                "hipaa_error": str(e),
            })
        # Auto-off on flip 0→1: when an account becomes HIPAA, force
        # the AI-learns toggle off so future renders reflect the
        # explicit OFF state. Operator can re-enable it manually once
        # the M-1+M-2 opt-in is in place. Per operator: "if the
        # account flips on hipaa, disable until checked manually
        # again." INFO log carries account_id + actor for audit.
        if desired and not was_hipaa:
            try:
                from email_triage.web.db import set_rag_sent_index_enabled
                set_rag_sent_index_enabled(
                    db, account_id, enabled=False,
                )
                _log.info(
                    "AI-learns toggle auto-disabled on HIPAA flip",
                    account_id=account_id,
                    actor_user_id=user["id"],
                )
            except Exception as auto_off_err:
                # Auto-off is defence in depth — the M-4 path itself
                # short-circuits HIPAA accounts. Log + continue rather
                # than break the save.
                _log.warning(
                    "AI-learns auto-off on HIPAA flip failed",
                    account_id=account_id,
                    error=fmt_exc(auto_off_err),
                )

    # Save password/secret if provided.
    _save_provider_secret(form, ptype, account_id, secrets)

    # #169 Wave 2-α I6 — per-account style-learning backend FK.
    # Form field is ``style_learning_backend_id`` (HTML select);
    # empty / unset value means "fall through to install default".
    # The dropdown was filtered server-side to enforce the HIPAA gate
    # at render time, but defence-in-depth: re-check on save and
    # refuse a HIPAA account selecting a backend that doesn't meet
    # the BAA-current invariant.
    if "style_learning_backend_id" in form:
        from email_triage.web.db import (
            get_ai_backend,
            record_hipaa_access_event,
            set_account_style_learning_backend,
        )
        raw_bid = (form.get("style_learning_backend_id") or "").strip()
        new_bid: int | None
        if raw_bid:
            try:
                new_bid = int(raw_bid)
            except (TypeError, ValueError):
                new_bid = None
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
                    from datetime import date
                    if (
                        not backend.get("baa_certified")
                        or not backend.get("baa_expires_at")
                        or str(backend["baa_expires_at"])
                            <= date.today().isoformat()
                        or not backend.get("enabled")
                    ):
                        accept = False
                        try:
                            record_hipaa_access_event(
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
                            )
                        except Exception as audit_err:
                            _log.warning(
                                "style_learning_backend refused-audit "
                                "failed",
                                account_id=account_id,
                                error=fmt_exc(audit_err),
                            )
                elif not backend.get("enabled"):
                    accept = False
        if accept:
            set_account_style_learning_backend(db, account_id, new_bid)
            # Audit row for HIPAA accounts so the auditor sees who
            # selected what + when, with the BAA state captured at
            # selection time.
            if is_account_hipaa(cur_acct):
                try:
                    if new_bid is None:
                        record_hipaa_access_event(
                            db,
                            actor_user_id=user["id"],
                            account_id=account_id,
                            operation="style_learning_backend_set",
                            outcome="install_default",
                            detail="cleared FK",
                        )
                    else:
                        b = get_ai_backend(db, new_bid)
                        record_hipaa_access_event(
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
                        )
                except Exception as audit_err:
                    _log.warning(
                        "style_learning_backend audit row failed",
                        account_id=account_id,
                        error=fmt_exc(audit_err),
                    )

    # #152 Phase 2 — M-1+M-2 HIPAA opt-in (per-account).
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
    # OWNER-ONLY: per #152 phase 2 + feedback_hipaa_actor_owner_gate.md,
    # the M-1+M-2 opt-in is the operator's own §164.502(a)
    # self-disclosure ack — admin / delegate cannot tick it on behalf
    # of the account owner. A non-owner POST that carries the field
    # gets a silent refuse + a hipaa_access_events audit row recording
    # the refused attempt. The HIPAA flag flip above (owner-or-admin)
    # is a separate decision: admin can flip the policy bit, but only
    # the data subject can opt their own knobs in.
    _is_owner = acct["user_id"] == user["id"]
    cur_acct = get_email_account(db, account_id)
    if cur_acct and bool(cur_acct.get("hipaa")):
        if _is_owner:
            from email_triage.web.db import (
                record_hipaa_access_event,
                set_style_knobs_hipaa_allow,
            )
            desired_optin = ("style_knobs_hipaa_allow" in form)
            set_style_knobs_hipaa_allow(
                db, account_id,
                enabled=desired_optin,
            )
            # Audit the owner-self tick (§164.502(a) carve-out
            # doesn't waive the audit trail). Outcome key is the
            # final state so the auditor can read "who set the flag
            # to what + when" off a single row.
            try:
                record_hipaa_access_event(
                    db,
                    actor_user_id=user["id"],
                    account_id=account_id,
                    operation="style_knobs_hipaa_allow_set",
                    outcome="ok",
                    detail=(
                        "enabled" if desired_optin else "disabled"
                    ),
                )
            except Exception as audit_err:
                _log.warning(
                    "style_knobs_hipaa_allow audit row failed",
                    account_id=account_id,
                    error=fmt_exc(audit_err),
                )
        elif "style_knobs_hipaa_allow" in form:
            # Non-owner POSTed the opt-in field on a HIPAA account
            # they don't own. Silently refuse (no setting write)
            # but record the attempt — the audit row is the
            # paper trail.
            from email_triage.web.db import record_hipaa_access_event
            _log.info(
                "style_knobs_hipaa_allow tick refused — actor != owner",
                account_id=account_id,
                actor_user_id=user["id"],
                owner_user_id=acct["user_id"],
            )
            try:
                record_hipaa_access_event(
                    db,
                    actor_user_id=user["id"],
                    account_id=account_id,
                    operation="style_knobs_hipaa_allow_set",
                    outcome="refused_non_owner",
                    detail="actor != owner; owner-only opt-in",
                )
            except Exception as audit_err:
                _log.warning(
                    "style_knobs_hipaa_allow refused-audit failed",
                    account_id=account_id,
                    error=fmt_exc(audit_err),
                )

    # Watcher bounce: if either the push/poll flags, the poll cadence,
    # or (for IMAP) the mailbox list changed, tear down and re-start
    # so the change takes effect without a service restart. This is
    # the same pattern #9 established for mailbox changes, now
    # generalised to the three new ingestion knobs.
    if watcher_mgr is not None:
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

    acct = get_email_account(db, account_id)
    _enrich_account(acct, secrets)
    _enrich_account_chips(acct, db, secrets, watcher_mgr=watcher_mgr, config=request.app.state.config)
    return _render(templates, request, "accounts/_row.html", {
        "acct": acct, "is_admin": is_admin,
    })


@router.post("/accounts/{account_id}/delegates/add", response_class=HTMLResponse)
async def accounts_delegate_add(
    request: Request, account_id: int,
):
    """Grant a user delegate access to this account. Owner-or-admin only.

    Form fields:
        user_email: email of the user to grant access to (must exist).
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)
    db = get_db(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"
    from email_triage.web.db import (
        get_email_account, add_account_delegate, list_account_delegates,
    )
    # #135 phase 3 — DB-before-(form-parse-and-write).
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)
    # Owner-or-admin only — delegates can't grant further delegation.
    if acct["user_id"] != user["id"] and not is_admin:
        return HTMLResponse("Forbidden", status_code=403)
    form = await request.form()
    # Hybrid grant UX: admin dropdown posts user_id; owner free-text
    # posts user_email. Honour either.
    target = None
    target_user_id = (form.get("user_id") or "").strip()
    if target_user_id:
        try:
            target = db.execute(
                "SELECT id, email, name FROM users WHERE id = ?",
                (int(target_user_id),),
            ).fetchone()
        except (ValueError, TypeError):
            target = None
    if target is None:
        target_email = (form.get("user_email") or "").strip().lower()
        if not target_email and not target_user_id:
            return HTMLResponse("missing user_id or user_email",
                                status_code=400)
        if target_email:
            target = db.execute(
                "SELECT id, email, name FROM users WHERE LOWER(email) = ?",
                (target_email,),
            ).fetchone()

    # Refresh grantable_users for re-render after error.
    def _grantable():
        if is_admin:
            rows = db.execute(
                "SELECT id, email, name FROM users WHERE id != ? "
                "ORDER BY COALESCE(NULLIF(name, ''), email)",
                (acct["user_id"],),
            ).fetchall()
            return [dict(r) for r in rows]
        return None

    if target is None:
        identifier = (form.get("user_email") or form.get("user_id") or "").strip()
        return _render(templates, request, "accounts/_delegates.html", {
            "acct": acct,
            "delegates": list_account_delegates(db, account_id),
            "error": f"No user found matching '{identifier}'",
            "is_admin": is_admin,
            "user": user,
            "grantable_users": _grantable(),
        })
    try:
        added = add_account_delegate(
            db, account_id, target["id"], granted_by=user["id"],
        )
    except ValueError as e:
        return _render(templates, request, "accounts/_delegates.html", {
            "acct": acct,
            "delegates": list_account_delegates(db, account_id),
            "error": fmt_exc(e),
            "is_admin": is_admin,
            "user": user,
            "grantable_users": _grantable(),
        })
    if added:
        _log.info(
            "Account delegate granted",
            account_id=account_id, account_name=acct.get("name", ""),
            target_user_id=target["id"], target_email=target["email"],
            granted_by=user["id"],
        )
    return _render(templates, request, "accounts/_delegates.html", {
        "acct": acct,
        "delegates": list_account_delegates(db, account_id),
        "is_admin": is_admin,
        "user": user,
        "grantable_users": _grantable(),
    })


@router.delete(
    "/accounts/{account_id}/delegates/{user_id}",
    response_class=HTMLResponse,
)
async def accounts_delegate_remove(
    request: Request, account_id: int, user_id: int,
):
    """Revoke a delegate. Owner-or-admin only."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)
    db = get_db(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"
    from email_triage.web.db import (
        get_email_account, remove_account_delegate, list_account_delegates,
    )
    # #135 phase 3 — DB-before-write.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Not found", status_code=404)
    if acct["user_id"] != user["id"] and not is_admin:
        return HTMLResponse("Forbidden", status_code=403)
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
    return _render(templates, request, "accounts/_delegates.html", {
        "acct": acct,
        "delegates": list_account_delegates(db, account_id),
        "is_admin": is_admin,
        "user": user,
        "grantable_users": grantable,
    })


@router.post("/accounts/{account_id}/aliases/add", response_class=HTMLResponse)
async def accounts_alias_add(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Add an additional address to an account (#106).

    Owner / delegate / admin can add (same gate as the main account
    save). The submitted address is validated for RFC shape and
    de-duplication before write; on validation failure the partial
    re-renders with an inline error message above the table.
    """
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"
    from email_triage.web.db import (
        AliasValidationError,
        account_email,
        get_email_account,
        normalize_aliases,
        update_email_account_aliases,
    )

    form = await request.form()
    new_address = (form.get("address") or "").strip().lower()
    new_label = (form.get("label") or "").strip()

    existing = list(acct.get("aliases") or [])
    proposed = list(existing) + [{"address": new_address, "label": new_label}]
    primary = account_email(acct)

    try:
        cleaned = normalize_aliases(proposed, primary=primary)
    except AliasValidationError as e:
        return _render(templates, request, "accounts/_aliases.html", {
            "acct": acct, "user": user, "is_admin": is_admin,
            "alias_error": str(e),
        })

    # #135 phase 2 — write off the loop.
    await db_call(update_email_account_aliases, db, account_id, cleaned)
    _log.info(
        "Account alias added",
        account_id=account_id, address=new_address,
        actor_user_id=user["id"],
    )
    acct = await db_call(get_email_account, db, account_id)
    return _render(templates, request, "accounts/_aliases.html", {
        "acct": acct, "user": user, "is_admin": is_admin,
    })


@router.post(
    "/accounts/{account_id}/aliases/remove",
    response_class=HTMLResponse,
)
async def accounts_alias_remove(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Remove an additional address from an account (#106).

    Body field: ``address`` — the alias to drop. Idempotent: a remove
    request for an address that isn't present re-renders the same
    partial with no change.
    """
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"
    from email_triage.web.db import (
        get_email_account,
        update_email_account_aliases,
    )

    form = await request.form()
    target = (form.get("address") or "").strip().lower()
    existing = list(acct.get("aliases") or [])
    kept = [
        e for e in existing
        if str((e or {}).get("address") or "").strip().lower() != target
    ]
    if len(kept) != len(existing):
        def _alias_remove_snapshot(db, account_id, kept):
            """#135 phase 2 — write + re-fetch in one threadpool hop."""
            update_email_account_aliases(db, account_id, kept)
            return get_email_account(db, account_id)

        acct = await db_call(_alias_remove_snapshot, db, account_id, kept)
        _log.info(
            "Account alias removed",
            account_id=account_id, address=target,
            actor_user_id=user["id"],
        )
    return _render(templates, request, "accounts/_aliases.html", {
        "acct": acct, "user": user, "is_admin": is_admin,
    })


@router.delete("/accounts/{account_id}", response_class=HTMLResponse)
async def accounts_delete(request: Request, account_id: int):
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    is_admin = user["role"] == "admin"

    from email_triage.web.db import get_email_account, delete_email_account

    def _accounts_delete_snapshot(db, account_id, user_id, is_admin):
        """#135 phase 2 — fetch + auth check + delete in one hop. Returns
        ('ok' | 'not_found' | 'forbidden')."""
        acct = get_email_account(db, account_id)
        if acct is None:
            return "not_found"
        if acct["user_id"] != user_id and not is_admin:
            return "forbidden"
        delete_email_account(db, account_id)
        return "ok"

    status = await db_call(
        _accounts_delete_snapshot, db, account_id, user["id"], is_admin,
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    return HTMLResponse("")  # Remove the row from DOM


@router.post("/accounts/{account_id}/test", response_class=HTMLResponse)
async def accounts_test(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Test an account's connection using its saved config + secrets."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, secrets = owned
    is_admin = user["role"] == "admin"

    ok, msg = await _test_account_connection(acct, secrets)

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
            # #135 phase 3 — DB read after the network test() above; the
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
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, _, secrets = owned
    is_admin = user["role"] == "admin"

    try:
        provider = _create_provider_from_account(acct, secrets)
        folders = await provider.list_folders()
        await provider.close()
    except NotImplementedError:
        folders = []
    except Exception as e:
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">Error listing folders: {e}</small>'
        )

    # Return as JSON if requested via Accept header, else HTML options.
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        from fastapi.responses import JSONResponse
        return JSONResponse({"folders": folders})

    # Return as <option> elements for a <select>.
    html = "\n".join(
        f'<option value="{f}">{f}</option>' for f in folders
    )
    return HTMLResponse(html)


@router.post("/accounts/{account_id}/folders/create", response_class=HTMLResponse)
async def accounts_folder_create(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Create a new folder on the account's mail server."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, _, secrets = owned
    is_admin = user["role"] == "admin"

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
            f'<small style="color:var(--pico-del-color);">Error: {e}</small>'
        )

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

    Migrated to ``OwnedAccountOrLogin`` (#137 phase 2) — full-page
    navigation target keeps redirect-to-/login UX for anonymous users.
    """
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    from email_triage.web.db import get_folder_prefs

    # Fetch the full folder list from the server.
    all_folders: list[str] = []
    error = ""
    try:
        provider = _create_provider_from_account(acct, secrets)
        all_folders = await provider.list_folders()
        await provider.close()
    except Exception as e:
        error = f"Could not list folders: {e}"

    # #135 phase 2 — folder-prefs read off the loop.
    prefs = await db_call(get_folder_prefs, db, account_id)
    folder_included = {}
    for f in all_folders:
        folder_included[f] = prefs.get(f, True)

    tree = _build_folder_tree(all_folders)

    return _render(templates, request, "accounts/folder_prefs.html", {
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
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    is_admin = user["role"] == "admin"

    from email_triage.web.db import save_folder_prefs

    form = await request.form()
    # The form sends all folder paths as hidden inputs,
    # and the checked ones also come as "included" list values.
    all_folder_paths = form.getlist("all_folders")
    included_paths = set(form.getlist("included"))

    prefs = {}
    for path in all_folder_paths:
        prefs[path] = path in included_paths

    # #135 phase 2 — write off the loop.
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


