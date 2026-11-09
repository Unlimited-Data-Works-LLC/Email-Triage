"""Routes for the oauth concern.

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

import html
from email_triage.web.error_html import error_article, error_chip

from email_triage._isotime import parse_iso_aware, to_utc_iso
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
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.oauth")

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


@router.post("/accounts/{account_id}/gmail-api/auth/start", response_class=HTMLResponse)
async def gmail_api_auth_start(
    request: Request, account_id: int, owned: OwnedGmailApiAccount,
):
    """Web-callback path: build Google auth URL with the public callback.

    Returns an HTMX fragment with a single "Open Google" link. Google
    redirects to ``/oauth/google/callback`` on success; no further UI
    interaction is needed in this panel.
    """
    #  phase 2 — ``OwnedGmailApiAccount`` enforces auth + provider gate.
    user, acct, db, secrets = owned

    config = get_config(request)
    client_id = config.google_oauth.web_client_id
    if not client_id:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Primary client credentials not configured. '
            'Enter them on the <a href="/config">Config page</a>.</small>'
        )
    callback_url = _public_callback_url(request)
    if not callback_url:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'No <code>push.public_url</code> configured. Use the Fallback flow, '
            'or set the public URL on the <a href="/config">Config page</a>.</small>'
        )

    scopes = _scopes_for_account(acct)
    wants_calendar = (acct["config"] or {}).get("calendar_opted_in", False)

    from email_triage.providers.gmail_api import build_auth_url
    state_tok = _oauth_state_serializer(request).dumps({
        "acct": account_id,
        "uid": user["id"],
        "calendar": bool(wants_calendar),
    })
    url = build_auth_url(
        client_id=client_id,
        redirect_uri=callback_url,
        state=state_tok,
        scopes=scopes,
        login_hint=(acct["config"] or {}).get("account", ""),
    )
    return HTMLResponse(
        f'<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.75rem 1rem;">'
        f'<p><strong>Step 1.</strong> Click below to authorize in Google.</p>'
        f'<p><a href="{html.escape(url, quote=True)}" target="_blank" role="button">Open Google sign-in</a></p>'
        f'<p><strong>Step 2.</strong> After approving, Google redirects back here automatically. '
        f'Refresh the Accounts page to see the new ✓ Authenticated chip.</p>'
        f'</article>'
    )


@router.post("/accounts/{account_id}/gmail-api/auth/start-manual", response_class=HTMLResponse)
async def gmail_api_auth_start_manual(
    request: Request, account_id: int, owned: OwnedGmailApiAccount,
):
    """Manual-paste path: build auth URL with loopback redirect.

    Returns the URL plus a paste box for the user to drop the redirect
    URL (or just the code) into. No public URL needed; works with a
    Desktop OAuth client.
    """
    #  phase 2 — ``OwnedGmailApiAccount`` enforces auth + provider gate.
    user, acct, db, secrets = owned

    config = get_config(request)
    client_id = config.google_oauth.desktop_client_id
    if not client_id:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Fallback (Desktop) client credentials not configured. '
            'Enter them on the <a href="/config">Config page</a>.</small>'
        )

    scopes = _scopes_for_account(acct)
    wants_calendar = (acct["config"] or {}).get("calendar_opted_in", False)

    from email_triage.providers.gmail_api import build_auth_url
    state_tok = _oauth_state_serializer(request).dumps({
        "acct": account_id,
        "uid": user["id"],
        "calendar": bool(wants_calendar),
    })
    url = build_auth_url(
        client_id=client_id,
        redirect_uri=_MANUAL_REDIRECT_URI,
        state=state_tok,
        scopes=scopes,
        login_hint=(acct["config"] or {}).get("account", ""),
    )
    # Keep the state token cached so the complete-manual handler can
    # accept either: (a) a paste containing it, or (b) just the bare
    # code with no state (gog-style tolerance).
    _gmail_auth_state(request)[account_id] = {"state": state_tok}
    return HTMLResponse(
        f'<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.75rem 1rem;">'
        f'<p><strong>Step 1.</strong> Open this URL in a browser and approve:</p>'
        f'<p style="font-family:var(--pico-font-family-monospace);font-size:0.8rem;'
        f' word-break:break-all;background:var(--pico-card-background-color);padding:0.5rem;">'
        f'<a href="{html.escape(url, quote=True)}" target="_blank">{html.escape(url)}</a></p>'
        f'<p><strong>Step 2.</strong> Your browser will fail to load <code>http://127.0.0.1:1/...</code> '
        f'— that is expected. Copy the URL from the address bar (or just the <code>code</code> value) '
        f'and paste it below.</p>'
        f'<form hx-post="/accounts/{html.escape(str(account_id))}/gmail-api/auth/complete-manual"'
        f' hx-target="#gmail-api-auth-panel" hx-swap="innerHTML">'
        f'<label>Pasted redirect URL or code'
        f'<input type="text" name="pasted" required placeholder="http://127.0.0.1:1/?code=..." autocomplete="off">'
        f'</label>'
        f'<button type="submit">Complete authentication</button>'
        f'</form>'
        f'</article>'
    )


@router.post("/accounts/{account_id}/gmail-api/auth/complete-manual", response_class=HTMLResponse)
async def gmail_api_auth_complete_manual(
    request: Request, account_id: int, owned: OwnedGmailApiAccount,
):
    """Take the pasted redirect URL/code from the manual flow and finish auth."""
    #  phase 2 — ``OwnedGmailApiAccount`` enforces auth + provider gate.
    user, acct, db, secrets = owned

    form = await request.form()
    pasted = (form.get("pasted") or "").strip()
    from email_triage.providers.gmail_api import (
        exchange_code_for_tokens, extract_code_from_pasted, GmailAuthError,
    )
    code, _state_from_url = extract_code_from_pasted(pasted)
    if not code:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Could not find a <code>code</code> in what you pasted.</small>'
        )

    config = get_config(request)
    client_id = config.google_oauth.desktop_client_id
    client_secret = config.google_oauth.desktop_client_secret
    if not client_id or not client_secret:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Fallback (Desktop) client credentials not configured. '
            'Enter them on the <a href="/config">Config page</a>.</small>'
        )
    try:
        token_payload = await exchange_code_for_tokens(
            client_id=client_id,
            code=code,
            redirect_uri=_MANUAL_REDIRECT_URI,
            client_secret=client_secret,
        )
    except GmailAuthError as e:
        return HTMLResponse(
            error_chip(e, prefix='Auth failed: ')
        )

    refresh_token = token_payload.get("refresh_token", "")
    if not refresh_token:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Google did not return a refresh token. Revoke the app in '
            '<a href="https://myaccount.google.com/permissions" target="_blank">account permissions</a> '
            'and re-authenticate.</small>'
        )
    def _complete_manual_db_work() -> None:
        """/ — token store + setting writes + auth-stale clear
        in one threadpool hop, after the network token exchange above.
        """
        sk = _secret_key_for_account(account_id, "gmail_api")
        if sk:
            secrets.set(sk, refresh_token)
            # N-271 R28: fresh OAuth credentials just landed →
            # invalidate the provider-labels cache so the picker
            # doesn't serve labels derived under the OLD (revoked or
            # rotated) credentials for up to 5 min.
            try:
                from email_triage.providers.provider_labels import (
                    invalidate_cache_for_account,
                )
                invalidate_cache_for_account(int(account_id))
            except Exception as _n271_e:  # N-294 R30 (HIPAA-SME follow-up)
                # Best-effort still, but the failure is now observable —
                # a broken invalidator SSOT (e.g. new required arg) previously
                # silently deleted the invalidation across all 4 sites.
                from email_triage.triage_logging import get_logger as _gl
                _gl(__name__).debug(
                    "provider_labels invalidate best-effort failed",
                    extra={"error": type(_n271_e).__name__, "account_id": account_id},
                )

        # Sync calendar_enabled with the account's current opt-in,
        # since the scopes we just asked Google for were derived from
        # it.
        from email_triage.web.db import set_bool_setting, set_setting
        wants_calendar = bool(
            (acct["config"] or {}).get("calendar_opted_in")
        )
        set_bool_setting(
            db, _S.calendar_enabled(account_id), wants_calendar,
        )

        # Stamp the OAuth flow type. This handler is the Desktop /
        # manual-paste finish; tokens are usable for read+classify but
        # don't unlock Start Push (operator-named separation: Primary
        # -- push-enabled is the path that enables push).
        set_setting(db, _S.gmail_oauth_flow(account_id), "manual")

        # Clear auth-stale flag immediately on successful re-auth so
        # the banner / chip disappears without waiting for the next
        # poll cycle to confirm.
        from email_triage.web.app import _clear_auth_stale
        _clear_auth_stale(db, account_id)

    await db_call(_complete_manual_db_work)

    _gmail_auth_state(request).pop(account_id, None)
    # OOB-swap the stale-auth banner area on the edit page with a
    # green success banner; primary swap target gets the inline
    # confirmation underneath the auth controls. Operator sees both
    # at once without a page reload.
    return HTMLResponse(
        f'<div id="auth-stale-banner-{html.escape(str(account_id), quote=True)}" hx-swap-oob="true">'
        f'<article style="border-left:3px solid var(--pico-ins-color);'
        f'background:var(--pico-card-background-color, transparent);'
        f'padding:0.6rem 0.9rem;margin:0 0 0.75rem 0;">'
        f'<strong>&#10003; Re-authenticated successfully.</strong>'
        f'<p style="margin:0.3rem 0 0;font-size:0.9rem;color:var(--pico-muted-color);">'
        f'The previous warning has been cleared. '
        f'Triage and watchers will resume on the next cycle.'
        f'</p></article></div>'
        f'<small style="color:var(--pico-ins-color);">&#10003; Authenticated — refresh token stored.</small>'
    )


# ---------------------------------------------------------------------------
# /oauth/google/callback — single endpoint that handles both Gmail and
# Calendar web-callback completions, demuxed via the signed `state`.
# ---------------------------------------------------------------------------

@router.get("/oauth/google/callback", response_class=HTMLResponse)
async def oauth_google_callback(request: Request):
    """Handle the redirect Google sends after web-callback consent.

    Verifies the signed state token, looks up the account, exchanges
    the code for tokens, stores the refresh token. For calendar
    enablement, also flips the ``calendar_enabled`` setting.
    """
    user = await db_call(get_current_user, request)  # 
    if user is None:
        # The OAuth round-trip can take a couple of minutes — the
        # session may have expired. Surface an actionable error rather
        # than a silent redirect.
        return HTMLResponse(
            '<article style="max-width:40rem;margin:2rem auto;padding:1rem;">'
            'Your session expired during authentication. '
            '<a href="/login">Log in</a> and re-run the Authenticate flow.'
            '</article>',
            status_code=401,
        )

    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error", "")
    if error:
        return HTMLResponse(
            f'<article style="max-width:40rem;margin:2rem auto;padding:1rem;'
            f'border-left:3px solid var(--pico-del-color);">'
            f'<strong>Google returned an error:</strong> {html.escape(error)}'
            f'<p><a href="/accounts">Back to accounts</a></p>'
            f'</article>',
            status_code=400,
        )
    if not code or not state:
        return HTMLResponse("Missing code or state", status_code=400)

    from itsdangerous import BadSignature, SignatureExpired
    serializer = _oauth_state_serializer(request)
    try:
        payload = serializer.loads(state, max_age=600)
    except SignatureExpired:
        return HTMLResponse("State expired — re-run the Authenticate flow.", status_code=400)
    except BadSignature:
        return HTMLResponse("Invalid state.", status_code=400)
    if not isinstance(payload, dict):
        return HTMLResponse("Invalid state shape.", status_code=400)

    # NOTE: ``payload`` is the itsdangerous-signed STATE TOKEN we
    # issued (verified above via ``serializer.loads`` — a tampered ``acct`` fails the
    # signature and never reaches here), NOT inbound request input. So this is OUT of
    # the request-int-parse class (test_safe_int_request_parse_pin) and stays a bare
    # ``int()`` — a signed value we control, effectively safe.
    account_id = int(payload.get("acct", 0))
    # B2: state flag carries whether calendar scope was in the request.
    # Older states (pre-B2) used a ``purpose`` string — fall back to
    # that for in-flight redirects at upgrade time.
    wants_calendar = bool(
        payload.get("calendar", payload.get("purpose") == "calendar")
    )

    db = get_db(request)
    secrets = get_secrets(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")
    from email_triage.web.db import (
        get_email_account, set_bool_setting, set_setting,
    )

    def _callback_account_snapshot() -> tuple[dict | None, bool]:
        """/ — account fetch + can-manage check in one hop."""
        acct_ = get_email_account(db, account_id)
        if acct_ is None:
            return None, False
        return acct_, can_manage_account(db, user, acct_)

    acct, can_manage = await db_call(_callback_account_snapshot)
    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not can_manage:
        return HTMLResponse("Forbidden", status_code=403)

    config = get_config(request)
    client_id = config.google_oauth.web_client_id
    client_secret = config.google_oauth.web_client_secret
    callback_url = _public_callback_url(request)
    if not callback_url:
        return HTMLResponse("public_url not configured", status_code=400)
    if not client_id or not client_secret:
        return HTMLResponse(
            "Primary (Web app) client credentials not configured on /config",
            status_code=400,
        )

    from email_triage.providers.gmail_api import exchange_code_for_tokens, GmailAuthError
    try:
        token_payload = await exchange_code_for_tokens(
            client_id=client_id,
            code=code,
            redirect_uri=callback_url,
            client_secret=client_secret,
        )
    except GmailAuthError as e:
        # N-179 R21_2 (2026-07-02): route via error_article SSOT
        # (auto-scrubs Exception via scrub_exc + html-escapes). The
        # "Back to accounts" link is a fixed pico-styled call-to-action
        # — kept out of the SSOT (which is generic) and appended here.
        body = error_article(e, heading="Token exchange failed", purpose="provider")
        body += '<p><a href="/accounts">Back to accounts</a></p>'
        return HTMLResponse(body, status_code=400)
    refresh_token = token_payload.get("refresh_token", "")
    if not refresh_token:
        return HTMLResponse(
            '<article style="max-width:40rem;margin:2rem auto;padding:1rem;'
            'border-left:3px solid var(--pico-del-color);">'
            '<strong>No refresh token returned.</strong> '
            'Revoke the app in <a href="https://myaccount.google.com/permissions">Google Account Permissions</a> '
            'and re-authenticate so Google issues a fresh refresh token.'
            '<p><a href="/accounts">Back to accounts</a></p>'
            '</article>',
            status_code=400,
        )

    def _callback_token_db_work() -> None:
        """/ — token store + flow stamp + calendar flag +
        auth-stale clear in one threadpool hop, after the network
        token exchange above.
        """
        sk = _secret_key_for_account(account_id, "gmail_api")
        if sk:
            secrets.set(sk, refresh_token)
            # N-271 R28: fresh OAuth credentials just landed →
            # invalidate the provider-labels cache. Sibling of the
            # manual-code completion above.
            try:
                from email_triage.providers.provider_labels import (
                    invalidate_cache_for_account,
                )
                invalidate_cache_for_account(int(account_id))
            except Exception as _n271_e:  # N-294 R30 (HIPAA-SME follow-up)
                # Best-effort still, but the failure is now observable —
                # a broken invalidator SSOT (e.g. new required arg) previously
                # silently deleted the invalidation across all 4 sites.
                from email_triage.triage_logging import get_logger as _gl
                _gl(__name__).debug(
                    "provider_labels invalidate best-effort failed",
                    extra={"error": type(_n271_e).__name__, "account_id": account_id},
                )

        # Stamp the OAuth flow type. This handler is the Web-app /
        # Primary -- push-enabled callback; tokens unlock Start Push.
        # Render layer reads gmail_oauth_flow:<id> on the chip path.
        set_setting(db, _S.gmail_oauth_flow(account_id), "web")

        # Calendar enablement tracks the scope set the new token
        # carries. Unchecking the opt-in and re-authenticating strips
        # calendar scope, so we flip the flag either way to stay
        # in sync.
        set_bool_setting(
            db, _S.calendar_enabled(account_id), wants_calendar,
        )

        # Clear auth-stale flag immediately on successful re-auth so
        # the banner / chip disappears without waiting for the next
        # poll.
        from email_triage.web.app import _clear_auth_stale
        _clear_auth_stale(db, account_id)

    await db_call(_callback_token_db_work)

    #  sub-B — auto-chain OAuth → watch start. When the install
    # has Pub/Sub configured AND push is enabled on the account
    # AND no watch is currently live, fire watch-start automatically
    # so the operator doesn't have to return to the edit page and
    # click another button. Failure is non-fatal: the OAuth itself
    # succeeded; surface the watch failure as a banner the operator
    # can act on without blocking access to the account.
    auto_watch_msg = ""
    auto_watch_error = ""
    try:
        push_topic = config.push.gmail_topic_name
        push_enabled = bool(
            (acct.get("config") or {}).get("push_enabled", True),
        )
        # Don't double-fire if a real (non-poll-mode) watch already
        # exists with a future expires_at.
        from email_triage.web.db import get_gmail_watch
        from email_triage.web.gmail_watch_status import is_gmail_watch_live
        existing_watch = await db_call(get_gmail_watch, db, account_id)
        # N-263d R28 SSOT — topic-non-empty + future-expiry predicate.
        watch_already_live = is_gmail_watch_live(existing_watch)
        if (
            push_topic and push_enabled
            and not watch_already_live
            and acct.get("provider_type") == "gmail_api"
        ):
            from email_triage.providers.gmail_api import GmailApiProvider
            provider = await db_call(
                _create_provider_from_account, acct, secrets,
            )
            if isinstance(provider, GmailApiProvider):
                try:
                    data = await provider.register_watch(push_topic)
                    from datetime import timedelta
                    # /run18 : ``data`` is the Gmail register_watch API
                    # RESPONSE — a malformed ``expiration`` must not raise an
                    # uncaught ValueError → 500 (external-API robustness). Coerce
                    # via the _safe_int SSOT, not a bare int().
                    exp_ms = _shared._safe_int(data.get("expiration"), 0)
                    now_iso = datetime.now(timezone.utc)
                    exp_iso = (
                        to_utc_iso(datetime.fromtimestamp(
                            exp_ms / 1000, tz=timezone.utc,
                        ))
                        if exp_ms
                        else to_utc_iso(now_iso + timedelta(days=7))
                    )
                    history_id = str(data.get("historyId") or "")
                    cfg_email = (
                        acct.get("config") or {}
                    ).get("account", "")
                    profile = await provider.get_profile()
                    profile_email = str(
                        profile.get("emailAddress", ""),
                    ).strip()
                    new_email = (
                        profile_email or cfg_email or ""
                    ).strip()
                    if new_email:
                        from email_triage.web.db import upsert_gmail_watch
                        await db_call(
                            upsert_gmail_watch,
                            db,
                            account_id=account_id,
                            email_address=new_email,
                            topic_name=push_topic,
                            history_id=history_id,
                            expires_at=exp_iso,
                        )
                        auto_watch_msg = (
                            "Push watch started automatically; "
                            "real-time delivery is live."
                        )
                    else:
                        auto_watch_error = (
                            "Auth complete but couldn't resolve the "
                            "Gmail address to register the watch. "
                            "Click Start watch on the account page."
                        )
                finally:
                    try:
                        await provider.close()
                    except Exception as _swallow_exc:
                        _log.debug(
                            "provider/probe close failed (best-effort teardown)",
                            error=fmt_exc(_swallow_exc),
                        )
    except Exception as exc:
        auto_watch_error = (
            f"Auth complete; watch start failed: {fmt_exc(exc)}. "
            "Click Start watch on the account page to retry."
        )
        # Census run23 #1 — before this the OAuth-callback auto-start-watch
        # failure was DOUBLY narrow: neither the auth_stale sibling
        # (record_provider_outcome) nor the lifecycle SSOT SET half
        # (record_gmail_watch_outcome) fired, so /health saw a green watch
        # while the callback banner showed the only surface for the failure.
        # Wire both so a failed auto-start is visible in the same places as
        # every other push-consumer / manual-restart failure branch.
        try:
            from email_triage.web.app import record_provider_outcome
            await db_call(record_provider_outcome, db, acct, exc)
        except Exception as _swallow_exc:
            _log.error(
                "oauth callback: record_provider_outcome failed; auth_stale state may be missing",
                exc_info=_swallow_exc,
            )
        try:
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=account_id, error_text=fmt_exc(exc),
            )
        except Exception as watch_exc:
            _log.error(
                "gmail_watches errored-status write failed on OAuth auto-watch",
                account_id=account_id, exc_info=watch_exc,
            )

    auto_banner = ""
    if auto_watch_msg:
        # auto_watch_msg is a server-constructed string literal — no escape needed.
        auto_banner = (
            '<p style="margin-top:0.5rem;color:var(--pico-ins-color);">'
            f'&#10003; {auto_watch_msg}</p>'
        )
    elif auto_watch_error:
        # N-83: auto_watch_error may contain fmt_exc(exc) — escape before HTML
        # interpolation to prevent reflected-XSS from provider/exception text.
        auto_banner = (
            '<p style="margin-top:0.5rem;color:var(--pico-del-color);">'
            f'&#9888; {html.escape(auto_watch_error)}</p>'
        )

    return HTMLResponse(
        '<article style="max-width:40rem;margin:2rem auto;padding:1rem;'
        'border-left:3px solid var(--pico-ins-color);">'
        '<strong>&#10003; Authenticated.</strong> Refresh token stored. '
        f'{auto_banner}'
        '<p><a href="/accounts">Back to accounts</a></p>'
        '</article>'
    )


# ---------------------------------------------------------------------------
# Gmail Pub/Sub watch lifecycle
# ---------------------------------------------------------------------------

