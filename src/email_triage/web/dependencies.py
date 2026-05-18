"""FastAPI dependency injection for authentication and authorization.

Provides:
    - ``get_current_user`` — extracts session from cookie or Bearer token
    - ``require_role(*roles)`` — factory that builds a dependency requiring
      the current user to have one of the specified roles
    - ``OwnedAccount`` (#137) — Annotated tuple dep that combines the
      ``get_current_user → get_db → get_secrets → get_email_account →
      can_manage_account`` preamble repeated 80+ times in
      ``routers/ui.py``. Raises HTTPException 401 / 404 / 403 with
      a consistent JSON body; the global error handler renders the
      operator-facing HTML or JSON wrapper depending on Accept.
    - ``OwnedAccountOrLogin`` (#137 phase 2) — sibling that returns a
      303 ``RedirectResponse`` to ``/login`` for anonymous users
      instead of raising 401. Use this for full-page navigation
      targets (GET pages + redirect-style POSTs) where the operator
      UX is "session expired → land on /login", not "opaque 401". The
      handler must check ``isinstance(ctx, RedirectResponse)`` before
      unpacking the tuple — see the call-site pattern below.
    - ``OwnedAccountForProvider(ptype)`` — sibling that additionally
      enforces a specific ``provider_type`` (replaces the local
      ``_verify_account_owner`` in ``routers/ui.py`` for the
      ``gmail_api``-only paths).

OwnedAccountOrLogin call-site pattern::

    async def wizard_step1(
        account_id: int, ctx: OwnedAccountOrLogin,
    ):
        if isinstance(ctx, RedirectResponse):
            return ctx  # 303 → /login (anon user)
        user, acct, db, secrets = ctx
        ...

This is more verbose than the ``OwnedAccount`` shape but matches the
redirect-to-login UX. Non-owner / not-found still raise 403 / 404 —
the only divergence is the anon path (RedirectResponse vs
HTTPException 401).

API endpoints (``/api/``) accept both session cookies and Bearer token
API keys.  The Bearer token is checked first.
"""

from __future__ import annotations

import secrets
import sqlite3
from typing import Annotated, Any

from fastapi import Cookie, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from email_triage.engine.models import UserRole
from email_triage.secrets import SecretsProvider
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    get_user_by_email,
    verify_api_key,
    verify_session_token,
)

# Module-level fallback ONLY for tests / contexts that haven't run
# the full lifespan. Production sets app.state.session_secret from
# the secrets store in app.py lifespan; that path is what every real
# request reads. The fallback exists so unit tests that build a bare
# FastAPI app without going through the lifespan don't crash.
_session_secret: str = ""


def get_session_secret(request: Request) -> str:
    """Return the session signing secret.

    Production path: ``app.state.session_secret`` is set during
    lifespan from the secrets-store value (minted on first run + then
    persisted, so it survives container restarts -- no more
    everyone-kicked-out on every deploy). PR 9 follow-up.

    Test fallback: when the lifespan didn't run (bare FastAPI app
    in unit tests), use a one-time random module-level secret. That
    path was the production path pre-PR-9 and was the bug -- every
    container restart regenerated it and invalidated every existing
    session cookie.
    """
    global _session_secret
    secret = getattr(request.app.state, "session_secret", None)
    if secret:
        return secret
    if not _session_secret:
        _session_secret = secrets.token_hex(32)
    return _session_secret


def _check_bearer_token(request: Request) -> dict[str, Any] | None:
    """Check for a Bearer token in the Authorization header.

    Returns a user dict (with ``auth_method='api_key'``) or None.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]  # Strip "Bearer " prefix.
    if not token:
        return None

    db = request.app.state.db
    return verify_api_key(db, token)


def get_current_user(request: Request) -> dict[str, Any] | None:
    """Extract the current user from Bearer token or session cookie.

    Checks Bearer token first (for API clients), then session cookie
    (for browser users).  Returns a user dict or None.
    """
    # Try Bearer token first (API key auth).
    user = _check_bearer_token(request)
    if user is not None:
        return user

    # Fall back to session cookie.
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    secret = get_session_secret(request)
    # Effective TTL honours HIPAA mode (auto-cap to
    # hipaa_session_ttl_secs when on).
    from email_triage.web.auth import effective_session_ttl
    config = getattr(request.app.state, "config", None)
    max_age = effective_session_ttl(config) if config else None
    session_data = (
        verify_session_token(secret, token, max_age=max_age)
        if max_age is not None
        else verify_session_token(secret, token)
    )
    if session_data is None:
        return None

    db = request.app.state.db
    user = get_user_by_email(db, session_data["email"])
    if user is None:
        return None
    # Fail-closed: a disabled user is invisible to every protected route.
    # Rechecked on every request (no caching) so a mid-session disable
    # takes effect immediately.
    if user.get("disabled"):
        return None
    return user


def require_auth(request: Request) -> dict[str, Any]:
    """Dependency that requires an authenticated user.

    Raises HTTP 401 for API requests, redirects to /login for UI requests.
    """
    user = get_current_user(request)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="Not authenticated")
        from fastapi.responses import RedirectResponse
        raise HTTPException(
            status_code=303,
            headers={"Location": "/login"},
        )
    return user


def require_role(*roles: str):
    """Factory returning a dependency that requires one of the given roles.

    Usage::

        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
        async def admin_page(...): ...
    """

    def _dependency(request: Request) -> dict[str, Any]:
        user = require_auth(request)
        if user["role"] not in roles:
            if request.url.path.startswith("/api/"):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _dependency


# ---------------------------------------------------------------------------
# #137 — OwnedAccount dependency.
#
# Replaces the 7-line preamble repeated across 80+ handlers in
# ``routers/ui.py``::
#
#     user = get_current_user(request)
#     if user is None:
#         return HTMLResponse("Unauthorized", status_code=401)
#     db = get_db(request)
#     secrets = get_secrets(request)
#     from email_triage.web.db import get_email_account
#     acct = get_email_account(db, account_id)
#     if acct is None:
#         return HTMLResponse("Not found", status_code=404)
#     if not can_manage_account(db, user, acct):
#         return HTMLResponse("Forbidden", status_code=403)
#
# Migrated handlers do::
#
#     async def edit_account(
#         request: Request, account_id: int,
#         owned: OwnedAccount,
#     ):
#         user, acct, db, secrets = owned
#         ...
#
# HIPAA §164.312(b) audit row: handled by ``AccessAuditMiddleware``
# (web/access_audit.py) which fires on every PHI-path request
# regardless of which dep ran. The dep does NOT call
# ``record_access_event`` — that would double-count. Per
# ``feedback_hipaa_actor_owner_gate.md`` the actor!=owner gate is
# already enforced by the existing audit middleware on the
# request scope.
#
# Error shape: HTTPException with a string ``detail``. The global
# 401/403/404 handlers in app.py decide HTML vs JSON based on the
# Accept header — UI handlers used to inline an HTMLResponse, but
# raising the exception lets the global handler centralize the
# render so future surface changes don't need 80+ touch sites.
# ---------------------------------------------------------------------------


def _require_owned_account(
    request: Request,
    account_id: int,
) -> tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider]:
    """Extract (user, account, db, secrets) for ``account_id`` and
    enforce the owner / delegate / admin authz gate.

    Raises
    ------
    HTTPException 401:
        No authenticated user.
    HTTPException 404:
        Account does not exist.
    HTTPException 403:
        User cannot manage this account (not owner, not admin,
        not a delegate).
    """
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    db: sqlite3.Connection = request.app.state.db
    secrets_provider: SecretsProvider = request.app.state.secrets
    # Lazy import: web.db imports trigger the full schema-helper
    # graph; keeping it local to the dep avoids a top-level cycle
    # if dependencies.py is ever pulled into a non-web context.
    from email_triage.web.db import can_manage_account, get_email_account
    acct = get_email_account(db, account_id)
    if acct is None:
        raise HTTPException(status_code=404, detail="Not found")
    if not can_manage_account(db, user, acct):
        raise HTTPException(status_code=403, detail="Forbidden")
    return user, acct, db, secrets_provider


# Annotated alias for handler signatures.
#
# Usage::
#
#     async def handler(
#         request: Request, account_id: int,
#         owned: OwnedAccount,
#     ):
#         user, acct, db, secrets = owned
OwnedAccount = Annotated[
    tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider],
    Depends(_require_owned_account),
]


def OwnedAccountForProvider(provider_type: str):
    """Sibling factory that additionally enforces a specific provider_type.

    Replaces the ``_verify_account_owner`` helper in
    ``routers/ui.py:6678`` for the ``gmail_api``-only paths.
    Raises HTTPException 400 ("Wrong provider type") when the
    account exists + is owned but is a different provider — same
    error shape the local helper used.

    Usage::

        GmailApiAccount = OwnedAccountForProvider("gmail_api")

        async def handler(
            request: Request, account_id: int,
            owned: Annotated[..., Depends(GmailApiAccount)],
        ):
            user, acct, db, secrets = owned
    """

    def _dep(
        request: Request, account_id: int,
    ) -> tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider]:
        result = _require_owned_account(request, account_id)
        _, acct, _, _ = result
        if acct["provider_type"] != provider_type:
            raise HTTPException(
                status_code=400,
                detail=f"Wrong provider type (expected {provider_type})",
            )
        return result

    return _dep


# Pre-built aliases for the common provider-gated case (matches the
# ``OwnedAccount`` Annotated-alias shape so call sites can use it
# directly without constructing a Depends each time).
OwnedGmailApiAccount = Annotated[
    tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider],
    Depends(OwnedAccountForProvider("gmail_api")),
]


# ---------------------------------------------------------------------------
# #137 phase 2 — OwnedAccountOrLogin sibling.
#
# The base ``OwnedAccount`` dep raises HTTPException 401 on missing auth,
# which is correct for HTMX-fragment endpoints (the global handler renders
# the proper operator surface). For full-page navigation targets — wizard
# steps, GET pages that the operator lands on directly, redirect-style
# POSTs that complete by 303-ing back to a page — a 401 produces a worse
# UX than the rest of the auth-expiry surface (which lands them on /login).
# This sibling returns a 303 ``RedirectResponse("/login")`` instead.
#
# Shares ``_require_owned_account`` for the lookup + owner / delegate /
# admin gate; only the anon path diverges.
#
# Handlers that use this dep MUST check ``isinstance(ctx,
# RedirectResponse)`` before unpacking, since FastAPI returns the
# RedirectResponse object as the dep's value (not a raised exception).
# ---------------------------------------------------------------------------


def _require_owned_account_or_login(
    request: Request,
    account_id: int,
) -> (
    tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider]
    | RedirectResponse
):
    """Like ``_require_owned_account`` but anon → 303 to /login.

    Returns
    -------
    tuple[user, acct, db, secrets]
        On the happy path (auth + owner / admin / delegate).
    RedirectResponse
        303 to ``/login`` for anonymous users — the handler is
        expected to return this directly.

    Raises
    ------
    HTTPException 404:
        Account does not exist (authenticated user, missing acct).
    HTTPException 403:
        User cannot manage this account.

    Note: only the anon path diverges from ``_require_owned_account``.
    Reusing the helper keeps a single canonical implementation of the
    account lookup + owner gate; future changes (HIPAA tightening,
    audit row mechanics) only need to change one site.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    # Authenticated path: identical to _require_owned_account from
    # this point. Calling the helper would re-fetch get_current_user
    # (cheap but redundant) — inline the rest to avoid the round-trip.
    db: sqlite3.Connection = request.app.state.db
    secrets_provider: SecretsProvider = request.app.state.secrets
    from email_triage.web.db import can_manage_account, get_email_account
    acct = get_email_account(db, account_id)
    if acct is None:
        raise HTTPException(status_code=404, detail="Not found")
    if not can_manage_account(db, user, acct):
        raise HTTPException(status_code=403, detail="Forbidden")
    return user, acct, db, secrets_provider


# Annotated alias for handler signatures.
#
# Usage::
#
#     async def handler(
#         request: Request, account_id: int,
#         ctx: OwnedAccountOrLogin,
#     ):
#         if isinstance(ctx, RedirectResponse):
#             return ctx
#         user, acct, db, secrets = ctx
OwnedAccountOrLogin = Annotated[
    tuple[dict[str, Any], dict[str, Any], sqlite3.Connection, SecretsProvider]
    | RedirectResponse,
    Depends(_require_owned_account_or_login),
]
