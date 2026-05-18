"""Routes for the push concern.

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

_log = get_logger("web.ui.push")

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


@router.post("/accounts/{account_id}/gmail-api/watch/start", response_class=HTMLResponse)
async def gmail_api_watch_start(
    request: Request, account_id: int, owned: OwnedGmailApiAccount,
):
    """Register a Gmail Pub/Sub watch for the account."""
    # #137 phase 2 — ``OwnedGmailApiAccount`` enforces auth + provider gate.
    user, acct, db, secrets = owned
    config = get_config(request)
    is_admin = user["role"] == "admin"

    from email_triage.web.db import upsert_gmail_watch

    topic = config.push.gmail_topic_name
    if not topic:
        # Defense-in-depth: chip should already disable the button when
        # the topic isn't configured, but a rapid double-click or stale
        # page can still hit this. Hide the admin path from non-admin
        # users -- they can't act on it and shouldn't be told it exists.
        is_admin = user.get("role") == "admin"
        if is_admin:
            msg = (
                'Gmail push topic is not configured. Set it on '
                '<a href="/admin/integrations">/admin/integrations</a> first.'
            )
        else:
            msg = "Push isn’t enabled for this install yet."
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">{msg}</small>'
        )

    from email_triage.providers.gmail_api import GmailApiProvider, GmailApiError
    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, GmailApiProvider):
        return HTMLResponse("Not a Gmail-native account", status_code=400)

    try:
        data = await provider.register_watch(topic)
    except GmailApiError as e:
        try:
            await provider.close()
        except Exception:
            pass
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">Failed to register watch: {e}</small>'
        )

    try:
        await provider.close()
    except Exception:
        pass

    exp_ms = int(data.get("expiration", 0))
    if exp_ms:
        exp_iso = datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc).isoformat()
    else:
        from datetime import timedelta
        exp_iso = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    email_address = (acct.get("config") or {}).get("account", "")
    if not email_address:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Account is missing the Gmail address — save the account first.</small>'
        )

    upsert_gmail_watch(
        db,
        account_id=account_id,
        email_address=email_address,
        topic_name=topic,
        history_id=str(data.get("historyId") or "0"),
        expires_at=exp_iso,
    )

    from email_triage.web.db import get_gmail_watch
    return HTMLResponse(_render_gmail_watch_chip(get_gmail_watch(db, account_id)))


@router.post("/accounts/{account_id}/gmail-api/watch/stop", response_class=HTMLResponse)
async def gmail_api_watch_stop(
    request: Request, account_id: int, owned: OwnedGmailApiAccount,
):
    """Unregister the Gmail watch and drop the local row."""
    # #137 phase 2 — ``OwnedGmailApiAccount`` enforces auth + provider gate.
    user, acct, db, secrets = owned
    is_admin = user["role"] == "admin"

    from email_triage.web.db import delete_gmail_watch

    from email_triage.providers.gmail_api import GmailApiProvider
    provider = _create_provider_from_account(acct, secrets)
    if isinstance(provider, GmailApiProvider):
        try:
            await provider.stop_watch()
        except Exception as e:
            log.warning("stop_watch API call failed; dropping row anyway", error=fmt_exc(e))
        finally:
            try:
                await provider.close()
            except Exception:
                pass

    delete_gmail_watch(db, account_id)
    return HTMLResponse(_render_gmail_watch_start_button(account_id))


# ---------------------------------------------------------------------------
# Office 365 / Microsoft Graph push subscription lifecycle (F-1)
#
# Sister of the Gmail watch start/stop pair above. Per-account UI on
# the account-edit page lets the owner / delegate / admin start or
# stop a Microsoft Graph webhook subscription so new mail flows
# through /webhooks/office365 instead of waiting for the next poll.
# Cron-driven renewer (F-2) is a separate follow-up; this handler
# creates a subscription with Graph's max ~3-day window and the
# operator (or that future renewer) is responsible for refreshing it.
# ---------------------------------------------------------------------------


@router.post("/accounts/{account_id}/o365-push/start", response_class=HTMLResponse)
async def office365_push_start(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Create a Microsoft Graph webhook subscription for this account.

    Auth gate: admin OR account owner OR delegate (``can_manage_account``).
    Audit row written under ``o365_push_start`` regardless of outcome
    so a failed start (Graph 5xx, missing public_url, etc.) is visible
    in the audit trail. Redirects back to the integrations tab.
    """
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned

    from email_triage.web.db import (
        record_auth_event,
        upsert_o365_subscription,
    )

    if acct["provider_type"] != "office365":
        return HTMLResponse("Wrong provider type", status_code=400)

    webhook_url, client_state = _o365_subscription_create_args(
        request, account_id,
    )
    if not webhook_url:
        try:
            record_auth_event(
                db,
                event_type="o365_push_start",
                email=user.get("email", ""),
                user_id=user.get("id"),
                outcome="failure",
                detail="public_url_unset",
            )
        except Exception:
            pass
        # Redirect with a short error string so the operator sees
        # something rather than a blank page. Admin path NOT mentioned
        # per the no-admin-path rule for end-user copy.
        return RedirectResponse(
            f"/accounts/{account_id}/edit?tab=integrations"
            f"&o365_err=public_url_unset",
            status_code=303,
        )
    if not client_state:
        # #132 — secret-store write failed during auto-generate.
        # Refuse to register a subscription whose deliveries we
        # can't verify; Graph would happily push us notifications
        # we'd then 401 on every time.
        try:
            record_auth_event(
                db,
                event_type="o365_push_start",
                email=user.get("email", ""),
                user_id=user.get("id"),
                outcome="failure",
                detail="clientstate_persist_failed",
            )
        except Exception:
            pass
        return RedirectResponse(
            f"/accounts/{account_id}/edit?tab=integrations"
            f"&o365_err=clientstate_persist_failed",
            status_code=303,
        )

    from email_triage.providers.office365 import Office365Provider

    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, Office365Provider):
        return HTMLResponse("Not an Office 365 account", status_code=400)

    try:
        try:
            data = await provider.create_subscription(
                webhook_url=webhook_url,
                client_state=client_state,
            )
        finally:
            try:
                await provider.close()
            except Exception:
                pass
    except Exception as e:
        _log.error(
            "Office 365 push start failed",
            account_id=account_id,
            error=fmt_exc(e),
        )
        try:
            record_auth_event(
                db,
                event_type="o365_push_start",
                email=user.get("email", ""),
                user_id=user.get("id"),
                outcome="failure",
                detail=str(e)[:200],
            )
        except Exception:
            pass
        return RedirectResponse(
            f"/accounts/{account_id}/edit?tab=integrations"
            f"&o365_err=create_failed",
            status_code=303,
        )

    sub_id = (data.get("id") or "").strip()
    expiration_iso = data.get("expirationDateTime") or ""
    if expiration_iso and expiration_iso.endswith("Z"):
        expiration_iso = expiration_iso[:-1] + "+00:00"
    if not sub_id or not expiration_iso:
        try:
            record_auth_event(
                db,
                event_type="o365_push_start",
                email=user.get("email", ""),
                user_id=user.get("id"),
                outcome="failure",
                detail="malformed_response",
            )
        except Exception:
            pass
        return RedirectResponse(
            f"/accounts/{account_id}/edit?tab=integrations"
            f"&o365_err=malformed_response",
            status_code=303,
        )

    upsert_o365_subscription(
        db,
        account_id=account_id,
        subscription_id=sub_id,
        expiration_at=expiration_iso,
    )
    try:
        record_auth_event(
            db,
            event_type="o365_push_start",
            email=user.get("email", ""),
            user_id=user.get("id"),
            outcome="success",
            detail=f"account_id={account_id}",
        )
    except Exception:
        pass
    _log.info(
        "Office 365 push started",
        actor=user.get("email"),
        account_id=account_id,
        subscription_id=sub_id,
    )
    return RedirectResponse(
        f"/accounts/{account_id}/edit?tab=integrations",
        status_code=303,
    )


@router.post("/accounts/{account_id}/o365-push/stop", response_class=HTMLResponse)
async def office365_push_stop(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Delete the Microsoft Graph webhook subscription for this account.

    Drops the local ``office365_subscriptions`` row regardless of
    whether the remote DELETE call succeeds — a cron renewer or
    operator can recreate later if needed; we never leave a stale
    DB row blocking a Start retry.
    """
    # #137 phase 2 — OwnedAccountOrLogin: anon → 303 /login.
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned

    from email_triage.web.db import (
        delete_o365_subscription,
        get_o365_subscription,
        record_auth_event,
    )

    if acct["provider_type"] != "office365":
        return HTMLResponse("Wrong provider type", status_code=400)

    sub_row = get_o365_subscription(db, account_id)
    sub_id = (sub_row or {}).get("subscription_id") or ""

    if sub_id:
        from email_triage.providers.office365 import Office365Provider
        provider = _create_provider_from_account(acct, secrets)
        if isinstance(provider, Office365Provider):
            try:
                try:
                    await provider.delete_subscription(sub_id)
                except Exception as e:
                    _log.warning(
                        "Office 365 delete_subscription API call failed; "
                        "dropping local row anyway",
                        account_id=account_id,
                        subscription_id=sub_id,
                        error=fmt_exc(e),
                    )
            finally:
                try:
                    await provider.close()
                except Exception:
                    pass

    delete_o365_subscription(db, account_id)
    try:
        record_auth_event(
            db,
            event_type="o365_push_stop",
            email=user.get("email", ""),
            user_id=user.get("id"),
            outcome="success",
            detail=f"account_id={account_id}",
        )
    except Exception:
        pass
    _log.info(
        "Office 365 push stopped",
        actor=user.get("email"),
        account_id=account_id,
        subscription_id=sub_id,
    )
    return RedirectResponse(
        f"/accounts/{account_id}/edit?tab=integrations",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Office 365 / Microsoft Graph credential PROBE (#126)
#
# Pre-flight verifier exposed on the account-edit Integrations tab.
# Operator clicks "Probe my config", we call Graph's /me with the
# saved tenant + client + secret combo, and return a green / red chip
# with a translated AADSTS one-liner on failure. Highest-impact UX win
# in the O365 setup flow — feedback in seconds instead of waiting for
# a real push delivery and trawling logs.
# ---------------------------------------------------------------------------


# Subset of AADSTS codes we translate inline. Microsoft publishes
# hundreds; these are the ones operators actually hit during the
# "first-time Graph connection" path (everything else falls through
# to the verbatim Graph error message). Translations are plain
# English — no protocol jargon, no bare AADSTS code as the headline.
# Per the audience header on the touched templates: medium tech-skill
# (operators registering an Azure app), so concrete recipe hints over
# abstract definitions.
@router.post("/accounts/{account_id}/o365/probe", response_class=HTMLResponse)
async def office365_probe(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Validate the saved O365 credentials by calling Graph's /me.

    Returns an HTMX-targeted chip the operator's edit page swaps in
    place of the probe-result container. Success = green chip with the
    signed-in user's address. Failure = red chip with a translated
    AADSTS one-liner if the error text carries one (verbatim Graph
    error otherwise).

    Auth gate: ``OwnedAccount`` (admin OR account owner OR delegate).
    """
    user, acct, db, secrets = owned
    if acct["provider_type"] != "office365":
        return HTMLResponse(
            _render_o365_probe_chip_failure(
                "This account isn't an Office 365 account, so there's "
                "nothing to probe."
            ),
            status_code=400,
        )

    # Build the provider through the existing factory shim — same path
    # the push-start handler uses. Reuses _create_provider_from_account
    # so the probe goes through OAuthHttpRequester / GraphError just
    # like every other Graph call (per the code-reuse mandate).
    try:
        provider = _create_provider_from_account(acct, secrets)
    except ImportError:
        return HTMLResponse(
            _render_o365_probe_chip_failure(
                "The Office 365 provider isn't installed on this "
                "server. Install email-triage's office365 extra and "
                "restart."
            ),
            status_code=200,
        )
    except Exception as exc:
        return HTMLResponse(
            _render_o365_probe_chip_failure(
                f"Couldn't build the Microsoft Graph client: "
                f"{fmt_exc(exc)}"
            ),
            status_code=200,
        )

    from email_triage.providers.office365 import (
        GraphError,
        Office365Provider,
    )

    if not isinstance(provider, Office365Provider):
        try:
            await provider.close()
        except Exception:
            pass
        return HTMLResponse(
            _render_o365_probe_chip_failure(
                "Built provider isn't an Office 365 client — check "
                "the account's provider type."
            ),
            status_code=400,
        )

    chip_html = ""
    chip_status = 200
    try:
        try:
            data = await provider._request("GET", "/me")
        finally:
            try:
                await provider.close()
            except Exception:
                pass
    except GraphError as ge:
        # Graph response carried an error body. Pull a string out of
        # whichever shape Graph used (dict vs str) and translate.
        err_text = ""
        if isinstance(ge.error, dict):
            err = ge.error.get("error") or {}
            if isinstance(err, dict):
                err_text = (
                    err.get("message")
                    or ge.error.get("error_description")
                    or str(ge.error)
                )
            else:
                err_text = str(ge.error)
        else:
            err_text = str(ge.error)
        code, msg = _aadsts_translate(err_text)
        # #121-A — pass account_id so the Explain-this-error
        # button's HIPAA actor!=owner gate fires for this account
        # and the AI prompt includes the operator-readable
        # account name.
        chip_html = _render_o365_probe_chip_failure(
            msg, code=code, account_id=account_id,
        )
        chip_status = 200
    except Exception as exc:
        # MSAL / RuntimeError out of acquire_token — this is where
        # AADSTS codes typically surface (msal embeds them in
        # error_description). Fall through to the same translator.
        code, msg = _aadsts_translate(fmt_exc(exc))
        chip_html = _render_o365_probe_chip_failure(
            msg, code=code, account_id=account_id,
        )
        chip_status = 200
    else:
        # /me returns userPrincipalName + mail; either is fine for
        # the chip subtitle. Prefer mail (operator-readable address)
        # but fall back to UPN if mail is unset (newer tenants
        # sometimes leave mail blank for license-restricted users).
        signed_in = ""
        if isinstance(data, dict):
            signed_in = (
                data.get("mail")
                or data.get("userPrincipalName")
                or data.get("displayName")
                or ""
            )
        chip_html = _render_o365_probe_chip_success(account_id, signed_in)
        _log.info(
            "Office 365 probe succeeded",
            actor=user.get("email"),
            account_id=account_id,
        )

    return HTMLResponse(chip_html, status_code=chip_status)


# ---------------------------------------------------------------------------
# Calendar enable / disable + provider factory
# ---------------------------------------------------------------------------

# #154 retired the per-account /accounts/{id}/watches/{...} UI routes.
# The match-and-fire watch editor now lives at /profile/watches with a
# multi-account picker; the OpenClaw API (/api/openclaw/accounts/.../watches)
# still owns the JSON CRUD surface for programmatic clients.
#
# Legacy bookmarks for /accounts/{id}/watches/new and
# /accounts/{id}/watches/{watch_id}/edit redirect to the new surface
# so a stale browser tab doesn't 404 mid-session.


@router.get("/accounts/{account_id}/watches/new", response_class=HTMLResponse)
async def watch_new_page_legacy_redirect(
    request: Request, account_id: int,
):
    return RedirectResponse("/profile/watches", status_code=303)


@router.get(
    "/accounts/{account_id}/watches/{watch_id}/edit",
    response_class=HTMLResponse,
)
async def watch_edit_page_legacy_redirect(
    request: Request, account_id: int, watch_id: str,
):
    return RedirectResponse("/profile/watches", status_code=303)


# ---------------------------------------------------------------------------
# Admin /admin/watches — cross-account list (admin only)
# ---------------------------------------------------------------------------


@router.post("/accounts/{account_id}/watch/start", response_class=HTMLResponse)
async def watch_start(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Start real-time watching for an account.

    Dispatches on ``provider_type``:

    * ``imap`` — starts an IMAP IDLE watcher task via WatcherManager.
    * ``gmail_api`` — no IDLE generator; Gmail uses Pub/Sub push
      (register_watch + /webhooks/gmail) or the B3 history-poll loop.
      The route returns a friendly status without calling into the
      generator path, which would otherwise raise NotImplementedError
      and loop forever on WatcherManager's reconnect backoff.
    * ``office365`` — Graph webhooks (subscription-based); also not
      a generator. Same treatment as gmail_api.
    """
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    from email_triage.web.app import get_watcher_manager
    mgr = get_watcher_manager(request)
    ptype = acct["provider_type"]

    # Non-IMAP providers don't have a per-account IDLE generator —
    # delivery is webhook-based (Gmail Pub/Sub, Graph subscriptions)
    # and the server-wide B3 poller handles missed-push catch-up.
    if ptype == "gmail_api":
        msg, status = _gmail_api_watch_start_status(request, db, account_id)
        return _render(templates, request, "accounts/_watch_status.html", {
            "acct": acct,
            "watch_status": status,
            "watch_msg": msg,
            **_get_hwm_context(db, account_id),
        })

    if ptype == "office365":
        msg = (
            "Office 365 uses Microsoft Graph webhooks, not a persistent "
            "connection. Configure a Graph subscription for real-time "
            "delivery; the server-side poller handles catch-up."
        )
        status = {
            "status": "unsupported",
            "processed": 0,
            "errors": 0,
            "last_message": None,
            "last_error": None,
            "started_at": None,
        }
        return _render(templates, request, "accounts/_watch_status.html", {
            "acct": acct,
            "watch_status": status,
            "watch_msg": msg,
            **_get_hwm_context(db, account_id),
        })

    # IMAP (and anything else that grows an IDLE generator) goes through
    # the WatcherManager.
    msg = await mgr.start(account_id)
    status = mgr.status(account_id)

    return _render(templates, request, "accounts/_watch_status.html", {
        "acct": acct,
        "watch_status": status,
        "watch_msg": msg,
        **_get_hwm_context(db, account_id),
    })


@router.post("/accounts/{account_id}/watch/stop", response_class=HTMLResponse)
async def watch_stop(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Stop IMAP IDLE watching for an account."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    from email_triage.web.app import get_watcher_manager
    mgr = get_watcher_manager(request)
    msg = await mgr.stop(account_id)
    status = mgr.status(account_id)

    hwm_ctx = await db_call(_get_hwm_context, db, account_id)

    return _render(templates, request, "accounts/_watch_status.html", {
        "acct": acct,
        "watch_status": status,
        "watch_msg": msg,
        **hwm_ctx,
    })


@router.get("/accounts/{account_id}/watch/status", response_class=HTMLResponse)
async def watch_status(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Get current watch status for an account (HTMX poll)."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    from email_triage.web.app import get_watcher_manager
    mgr = get_watcher_manager(request)
    status = mgr.status(account_id)

    # #135 phase 2 — HWM context off the loop. /watch/status is HTMX-
    # polled every few seconds — keeping its DB reads on the threadpool
    # is critical so a slow disk doesn't serialise other handlers.
    hwm_ctx = await db_call(_get_hwm_context, db, account_id)

    return _render(templates, request, "accounts/_watch_status.html", {
        "acct": acct,
        "watch_status": status,
        **hwm_ctx,
    })


@router.post("/accounts/{account_id}/watch/reset-hwm", response_class=HTMLResponse)
async def watch_reset_hwm(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Reset the high-water mark so the watcher reprocesses from scratch."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)

    def _watch_reset_hwm_snapshot(db, account_id: int, acct_cfg: dict) -> dict:
        """#135 phase 2 — delete every HWM key + read fresh hwm context
        in one threadpool hop."""
        from email_triage.web.db import delete_setting, _account_mailboxes
        delete_setting(db, _S.watch_hwm(account_id))
        for mb in _account_mailboxes(acct_cfg):
            delete_setting(db, _S.watch_hwm_mailbox(account_id, mb))
        return _get_hwm_context(db, account_id)

    hwm_ctx = await db_call(
        _watch_reset_hwm_snapshot, db, account_id, acct.get("config") or {},
    )

    from email_triage.web.app import get_watcher_manager
    mgr = get_watcher_manager(request)
    status = mgr.status(account_id)

    return _render(templates, request, "accounts/_watch_status.html", {
        "acct": acct,
        "watch_status": status,
        "watch_msg": "High-water mark reset. Next watch start will process all unseen messages.",
        **hwm_ctx,
    })


@router.post("/accounts/{account_id}/watch/set-hwm-current", response_class=HTMLResponse)
async def watch_set_hwm_current(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Connect to the mailbox, grab the latest UID, and set it as the HWM."""
    # #137 phase 2 — OwnedAccount dep collapses preamble.
    user, acct, db, secrets = owned
    templates = get_templates(request)
    from email_triage.web.db import set_setting

    # Connect to each configured mailbox in turn, grab the latest UID,
    # and set it as the per-mailbox HWM. UIDs are per-mailbox so a
    # single-connection approach isn't correct here. We close between
    # folders to avoid leaving a zombie IDLE socket on the server.
    from email_triage.web.app import get_watcher_manager
    from email_triage.web.db import _account_mailboxes
    mailboxes = _account_mailboxes((acct.get("config") or {}))
    results: list[tuple[str, int]] = []
    failures: list[tuple[str, str]] = []
    for mb in mailboxes:
        try:
            provider = _create_provider_from_account(
                acct, secrets, mailbox_override=mb,
            )
            latest_uid = await provider.get_latest_uid()
            await provider.close()
            results.append((mb, int(latest_uid)))
        except Exception as e:
            failures.append((mb, fmt_exc(e)))

    if not results and failures:
        # Every mailbox failed — surface the first error verbatim.
        mb, err = failures[0]
        mgr = get_watcher_manager(request)
        status = mgr.status(account_id)
        hwm_ctx = await db_call(_get_hwm_context, db, account_id)
        return _render(templates, request, "accounts/_watch_status.html", {
            "acct": acct,
            "watch_status": status,
            "watch_msg": f"Failed to connect to {mb}: {err}",
            **hwm_ctx,
        })

    def _watch_set_hwm_current_snapshot(
        db, account_id: int, results: list[tuple[str, int]],
    ) -> tuple[int, dict]:
        """#135 phase 2 — bundle every settings write + the hwm-context
        re-read into one threadpool hop."""
        from datetime import datetime, timezone as _tz
        set_count = 0
        for mb, latest_uid in results:
            if latest_uid > 0:
                set_setting(db, _S.watch_hwm_mailbox(account_id, mb), {
                    "uid": latest_uid,
                    "updated_at": datetime.now(_tz.utc).isoformat(),
                })
                set_count += 1
        if results:
            primary_uid = next(
                (uid for mb, uid in results if mb == "INBOX"),
                results[0][1],
            )
            if primary_uid > 0:
                set_setting(db, _S.watch_hwm(account_id), {
                    "uid": primary_uid,
                    "updated_at": datetime.now(_tz.utc).isoformat(),
                })
        return set_count, _get_hwm_context(db, account_id)

    set_count, hwm_ctx = await db_call(
        _watch_set_hwm_current_snapshot, db, account_id, results,
    )

    if set_count == 0:
        msg = "Mailbox appears empty — no UID to set."
    elif set_count == 1:
        mb, uid = next((m, u) for m, u in results if u > 0)
        msg = f"High-water mark set to UID {uid} on {mb} (current latest)."
    else:
        msg = f"High-water mark set on {set_count} mailboxes (each at current latest)."

    mgr = get_watcher_manager(request)
    status = mgr.status(account_id)

    return _render(templates, request, "accounts/_watch_status.html", {
        "acct": acct,
        "watch_status": status,
        "watch_msg": msg,
        **hwm_ctx,
    })


# ---------------------------------------------------------------------------
# Run Triage (web-driven triage per account)
# ---------------------------------------------------------------------------

