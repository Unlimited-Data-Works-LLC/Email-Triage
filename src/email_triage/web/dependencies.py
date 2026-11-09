"""FastAPI dependency injection for authentication and authorization.

Provides:
    - ``get_current_user`` — extracts session from cookie or Bearer token
    - ``require_role(*roles)`` — factory that builds a dependency requiring
      the current user to have one of the specified roles
    - ``OwnedAccount`` — Annotated tuple dep that combines the
      ``get_current_user → get_db → get_secrets → get_email_account →
      can_manage_account`` preamble repeated 80+ times in
      ``routers/ui.py``. Raises HTTPException 401 / 404 / 403 with
      a consistent JSON body; the global error handler renders the
      operator-facing HTML or JSON wrapper depending on Accept.
    - ``OwnedAccountOrLogin`` — sibling that returns a
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

import dataclasses
import secrets
import sqlite3
from typing import Annotated, Any

from fastapi import Cookie, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from email_triage.engine.models import UserRole
from email_triage.secrets import SecretsProvider
from email_triage._secret_keys import SESSION_SECRET_KEY  # N-231 R22 stored-secret-key SSOT
from email_triage.web.error_surface import raise_api_error  #  tranche 5 R32
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


@dataclasses.dataclass(frozen=True, slots=True)
class RequestMeta:
    """N-187 R20_12: (host, ua) SSOT return type for `request_meta`.

    `host` is always a string (empty on unknown, NEVER None), so callsites
    at authz boundaries (e.g. `_ops_token_authorized`) get consistent
    semantics without a per-site `... if request.client else ""` /
    `... else None` fork. `ua` follows the same rule.

    ``@dataclass(frozen=True)`` (not ``NamedTuple``) per DA N-187 must-fix #6:
    prevents 2-tuple unpackers (`host, ua = request_meta(r)`) from breaking
    silently on a future field-3 addition — callers MUST address by name.
    """
    host: str
    ua: str


def request_meta(request: Request) -> RequestMeta:
    """SSOT for reading client host + user-agent off a FastAPI Request.

    Before N-187 R20_12 the tree hand-rolled `request.client.host if
    request.client else None` (~14 sites), `.scope.get("client")[0] if _c
    else ""` (health.py:1197 — the authz boundary), and
    `request.headers.get("user-agent")` (~9 sites) with drifting fallback
    conventions (None vs "" vs missing). The scope-form `""` fallback fed
    `_ops_token_authorized`; a divergence between fallback conventions is
    an authz-boundary drift shape.

    ONE reader. Every caller gets `RequestMeta(host, ua)` with `host` and
    `ua` guaranteed non-None (empty string on unknown). Pinned by
    `test_n187_request_meta_ssot_pin.py`.

    **Semantics (DA + db-sme N-187 must-fix — read before consuming):**

    * ``host`` is the SOCKET PEER address (from ``request.client.host``
      OR the raw ASGI scope's ``("host", port)`` tuple). It is NEVER
      ``X-Forwarded-For`` — a proxy in front of email-triage means the
      value seen here is the PROXY's IP, not the end user's. If a
      future proxy deploy needs X-F-F trust, add an EXPLICIT SSOT
      (`request_forwarded_for(request)`) — do NOT quietly widen this
      one's semantics (that would silently invalidate the loopback gate
      in ``_ops_token_authorized``).
    * ``host == ""`` means "unknown peer" (no ASGI client info). It is
      NEVER a valid authorization identity — callers at authz boundaries
      (loopback allowlists, per-IP RBAC) MUST treat ``""`` as
      "reject" / "fail-closed", per PD#8. The strict pin
      ``test_loopback_hosts_never_include_empty_string`` structurally
      forbids ``""`` from ``_LOOPBACK_HOSTS`` (hipaa-sme must-fix).
    * ``ua`` is the raw ``User-Agent`` header value (or ``""``). It is
      operator-facing metadata, not an authorization signal.
    """
    # request.client is the parsed form (a `starlette.datastructures.Address`
    # namedtuple with `.host` + `.port`). If missing, fall back to the raw
    # scope (`("host", port)` tuple) — the shape health.py:1197 was reading.
    if request.client is not None:
        host = request.client.host or ""
    else:
        _c = request.scope.get("client") if hasattr(request, "scope") else None
        host = (_c[0] if _c else "") or ""
    ua = request.headers.get("user-agent") or ""
    return RequestMeta(host=host, ua=ua)


def request_forwarded_for(
    request: "Request",
    trusted_proxies: list[str],
) -> RequestMeta:
    """N-321 R30 (task  tranche  DA follow-up — operator-approved
    2026-07-03): §164.312(b) audit-identity SSOT that CONSUMES the
    ``X-Forwarded-For`` header when the direct-connect peer is a
    KNOWN, TRUSTED reverse proxy.

    Explicit sibling of :func:`request_meta` per the design note in
    `request_meta`'s docstring — DO NOT quietly widen `request_meta`
    (that would silently invalidate the loopback gate in
    `_ops_token_authorized`). Callers on the audit path (record_
    hipaa_access_event / record_auth_event / etc.) MIGRATE to this
    SSOT; every other caller stays on `request_meta`.

    **Semantics (BINDING — read before consuming):**

    * ``trusted_proxies`` is a list of CIDR strings from
      `config.audit.trusted_proxies`. Empty list = current behavior
      (ignore XFF, return the raw peer identical to `request_meta`).
    * The direct-connect peer (`request.client.host`) is matched
      against every CIDR. If ANY match → trust the XFF header.
    * When trusted, walk `X-Forwarded-For` from RIGHTMOST to leftmost
      and return the first entry whose IP is NOT in a trusted CIDR
      (that's the true client; leftmost entries are earlier hops
      whose trust we can't verify). If every entry is trusted →
      return the leftmost (originator claim).
    * When NOT trusted → return the direct peer. XFF is a client-
      controllable header; unauthenticated XFF is spoofable identity.
    * ``host == ""`` still means "unknown peer"; still MUST fail
      closed at authz boundaries per PD#8.
    """
    import ipaddress

    # N-324 R30 (CI-red fix-forward on N-321): the N-187 ratchet
    # pinned `request.client.host` + `.headers.get("user-agent")` to
    # a fixed baseline. My original `request_forwarded_for` hand-
    # rolled both reads (an SSOT violation). Delegate to
    # `request_meta` instead — the SSOT was designed for exactly
    # this and the ratchet stays clean.
    _base = request_meta(request)
    peer_host = _base.host
    ua = _base.ua

    def _in_trusted_cidr(ip_str: str) -> bool:
        if not ip_str or not trusted_proxies:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for cidr in trusted_proxies:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                # Malformed CIDR in config — treat as no-match so a
                # broken config fails CLOSED (raw peer used).
                continue
        return False

    if not _in_trusted_cidr(peer_host):
        return RequestMeta(host=peer_host, ua=ua)

    # Direct peer is trusted → consume XFF (rightmost-first walk).
    xff_raw = request.headers.get("x-forwarded-for", "") or ""
    if not xff_raw:
        return RequestMeta(host=peer_host, ua=ua)
    entries = [e.strip() for e in xff_raw.split(",") if e.strip()]
    if not entries:
        return RequestMeta(host=peer_host, ua=ua)

    for entry in reversed(entries):
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            continue
        if not _in_trusted_cidr(entry):
            return RequestMeta(host=entry, ua=ua)

    # Every XFF entry was trusted → return the leftmost (originator
    # claim per the standard XFF walk).
    # N-337: fail-CLOSED on all-malformed. Trust-audit Phase 2 DA flagged:
    # if EVERY entry is either trusted OR malformed, the pre-N-337 code
    # returned entries[0] even when that string was non-IP (a client-
    # controllable header writing a raw non-IP shape into audit rows).
    # If entries[0] itself doesn't parse as an IP, fall back to peer_host —
    # never write a raw non-IP string as audit actor.
    try:
        ipaddress.ip_address(entries[0])
    except ValueError:
        return RequestMeta(host=peer_host, ua=ua)
    return RequestMeta(host=entries[0], ua=ua)


def audit_forwarded_for(request: "Request") -> RequestMeta:
    """N-337: audit-path convenience wrapper on :func:`request_forwarded_for`.

    Pulls ``trusted_proxies`` from ``request.app.state.config.audit`` so
    callers on the audit path (record_hipaa_access_event / record_auth_event
    / record_api_key_event bookends) don't need to plumb ``config`` through.
    N-321 shipped the primitive but Phase 2 DA + hipaa-sme + db-sme all
    flagged that the ~14 audit-emit call sites remained on ``request_meta``,
    so every audit row on the deploy host still recorded the podman NAT peer (127.0.0.1)
    instead of the real client. This wrapper closes that migration path with
    a zero-config-at-callsite API.

    Fail-soft: on any lookup miss (`app.state.config` unset, `audit`
    attribute missing, config not fully initialized in a test harness),
    falls back to an empty trusted-proxies list = raw peer identity via
    :func:`request_forwarded_for` (which itself matches
    :func:`request_meta` when the list is empty). Same posture as
    ``request_meta`` at that point — never worse.
    """
    trusted: list[str] = []
    try:
        cfg = request.app.state.config  # type: ignore[union-attr]
    except AttributeError:
        cfg = None
    if cfg is not None:
        trusted = list(getattr(getattr(cfg, "audit", None), "trusted_proxies", []) or [])
    return request_forwarded_for(request, trusted)


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
    secret = getattr(request.app.state, SESSION_SECRET_KEY, None)
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
    user = verify_api_key(db, token)
    if user is None:
        #  — a Bearer credential that resolved to nobody: unknown, expired,
        # owner disabled, or an unreadable expiry (verify_api_key's WARNING/INFO
        # lines say which). It used to leave no audit trace at all.
        _audit_bearer_refusal(
            request,
            event_type="api_key_auth",
            reason="key_not_accepted",
            # N-337 audit SSOT: the real client when the operator configured the
            # proxy CIDR (``audit.trusted_proxies``), the raw peer until then.
            # Behind an unlisted proxy every client still shares one budget.
            source=f"unknown_key:{audit_forwarded_for(request).host}",
        )
    return user


#: The CLOSED set of reasons a Bearer / route-fence refusal row may carry in its
#: ``denied:<reason>`` outcome (punch 420, DA S2). A literal, so the closed set
#: is a code fact the login-failure route pin can read, not a comment: any other
#: reason is recorded as ``unclassified``. ``audit_rate_capped`` is assigned by
#: :func:`_audit_bearer_refusal` itself for the cap-notice row; the rest are the
#: ``ScopeRefused`` reasons and the unknown-key refusal.
_BEARER_REFUSAL_REASONS = frozenset({
    "key_not_accepted",
    "role_not_allowed_on_route",
    "api_only_role_web_session",
    "api_key_out_of_scope",
    "audit_rate_capped",
})


def _audit_bearer_refusal(
    request: Request,
    *,
    event_type: str,
    reason: str,
    source: str,
    detail: str | None = None,
    user: dict[str, Any] | None = None,
) -> None:
    """Record a refused Bearer/principal attempt through the ``record_auth_event``
    emitter SSOT (PD#3: never a raw INSERT), BOUNDED per source.

    Best-effort by the same rule as every other auth-failure row
    (``safe_audit_write``): the request has already been refused, so a lost audit
    row is a degraded condition, not a reason to change the answer. The cap
    (:func:`_route_scope.refusal_audit_decision`) exists because the refusal rate
    is whoever-holds-the-token's to choose and each row is a commit on the one
    serialized writer. Once per request: ``AccessAuditMiddleware`` re-resolves the
    principal, and a second call must not write a second row.
    """
    if getattr(request.state, "bearer_refusal_audited", False):
        return
    request.state.bearer_refusal_audited = True
    if reason not in _BEARER_REFUSAL_REASONS:
        reason = "unclassified"
    from email_triage.web._route_scope import (
        REFUSAL_AUDIT_OVERFLOW_SOURCE,
        refusal_audit_verdict,
        refusal_route_label,
    )
    verdict = refusal_audit_verdict(source)
    if verdict.decision == "skip":
        return
    if verdict.decision == "capped":
        reason = "audit_rate_capped"
        detail = ("further refusals from this source in this window are not "
                  "written as rows; their count is carried on this source's "
                  "next audit row, or logged in one WARNING when the window "
                  "ends with no further refusal")
        if verdict.source == REFUSAL_AUDIT_OVERFLOW_SOURCE:
            detail += ("; this source is the shared overflow for every unknown-key "
                       "source past the tracking bound")
    elif detail is None:
        detail = refusal_route_label(request)
    if verdict.suppressed:
        detail = f"{detail} suppressed={verdict.suppressed}"
    db = getattr(request.app.state, "db", None)
    if db is None:              # pragma: no cover — a bare app in a unit test
        return
    meta = audit_forwarded_for(request)
    from email_triage.web._audit import safe_audit_write
    from email_triage.web.db import record_auth_event
    safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type=event_type,
            email=(user or {}).get("email") or "",
            user_id=(user or {}).get("id"),
            key_id=(user or {}).get("api_key_id"),
            ip=meta.host,
            user_agent=meta.ua,
            outcome=f"denied:{reason}",
            detail=detail,
        ),
        description=event_type,
        table="auth_events",
        emitter="record_auth_event",
    )


def _fence_or_403(request: Request, user: dict[str, Any]) -> dict[str, Any]:
    """ — apply the route-scope / principal fences, or raise 403.

    THE seam. Both fences are evaluated here, for a principal resolved by EITHER
    auth method, because this function is the only thing the app's two auth shapes
    share: 181 of 310 routes take an auth dependency in their signature, and the
    other 129 — including the whole ``/api/v1/*`` surface and ``/health/detail`` —
    resolve the principal inside the handler body instead. A fence written as a
    ``Depends(...)`` would be blind to those 129. Enforcing here means a route
    added later inherits the fence without its author knowing the feature exists
    (PD#2, held by construction).

    403, not 401: the caller IS authenticated, just not authorised for this route,
    so a ``/login`` redirect would not help. This mirrors ``require_role``'s
    reasoning.

    A principal with an unscoped key and an unrestricted role — every principal
    that exists today — takes two frozenset lookups and is returned unchanged.
    """
    from email_triage.web._route_scope import ScopeRefused, check_principal_fences
    try:
        check_principal_fences(request, user)
    except ScopeRefused as refused:
        # §164.312(b) attribution. The principal is KNOWN here — it resolved,
        # then the fence refused it — and if we simply raise, that identity is
        # lost: `AccessAuditMiddleware` runs after `call_next`, finds no user, and
        # calls `get_current_user` again, which raises again into its
        # `except Exception: pass`, so a REFUSED access on a PHI path would be
        # recorded with `actor_user_id = NULL`, i.e. as coming from nobody.
        # Stamp the id under a name NOTHING treats as an authenticated principal
        # (deliberately not `request.state.user`), for the audit path only.
        request.state.fenced_principal_id = user.get("id")
        #  — the refusal itself is a record: a scoped credential used
        # off-scope is a stronger signal than a bad key (design 420 item 6).
        _audit_bearer_refusal(
            request,
            event_type=("api_key_scope" if refused.reason == "api_key_out_of_scope"
                        else "role_route_fence"),
            reason=refused.reason,
            source=(f"key:{user.get('api_key_id')}" if user.get("api_key_id") is not None
                    else f"user:{user.get('id')}"),
            user=user,
        )
        raise raise_api_error(
            "Insufficient permissions", status_code=403, purpose="misc",
        ) from refused
    return user


def get_current_user(request: Request) -> dict[str, Any] | None:
    """Extract the current user from Bearer token or session cookie.

    Checks Bearer token first (for API clients), then session cookie
    (for browser users).  Returns a user dict or None.

     — raises ``HTTPException(403)`` (never returns None) when the resolved
    principal is fenced off this route: a scoped api key used outside its scope, or
    a role whose allowlist excludes the route. Returning None there would read as
    "anonymous" and send a browser to ``/login``, hiding an authorisation refusal
    behind an authentication one.
    """
    # Try Bearer token first (API key auth).
    user = _check_bearer_token(request)
    if user is not None:
        return _fence_or_403(request, user)

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
    #  — per-user session-epoch revocation. The token carries the
    # epoch it was minted under; the user's current epoch is bumped by
    # disable-user + the "sign out all sessions" control. A stale epoch
    # means this session was revoked — reject it even though the
    # signature + TTL are still valid. A pre-#205 token decodes as
    # epoch 0 and matches a never-revoked user (also epoch 0).
    if int(session_data.get("epoch", 0)) != int(user.get("session_epoch", 0)):
        return None
    # H-05 (Cycle 7) — surface the session's mfa_verified_at claim so
    # `require_auth` (below) can route a pre-cutover session through
    # the hard-cutover MFA step-up flow. Attach to the returned dict
    # rather than fetching it elsewhere; keeps the middleware lookup
    # cheap (one session-data parse per request, not two).
    user = dict(user)
    user["_session_mfa_verified_at"] = session_data.get("mfa_verified_at")
    #  — the READ edge of the API-only-role predicate whose WRITE edge is
    # `auth.create_session_token`. Both edges, one predicate (R42): a cookie
    # minted before the role existed, or by any path that bypassed the mint
    # funnel, is still refused here.
    return _fence_or_403(request, user)


def require_auth(request: Request) -> dict[str, Any]:
    """Dependency that requires an authenticated user.

    Raises HTTP 401 for API requests, redirects to /login for UI requests.

    H-05 (Cycle 7): in HIPAA mode, a session lacking the
    ``mfa_verified_at`` claim is treated as un-MFA'd — the user
    is redirected to /login/webauthn (UI) or 401'd with a
    ``mfa_required`` error (API). Hard cutover per Q6: pre-cutover
    sessions (minted before HIPAA was flipped on) are NOT
    grandfathered.

    Bearer-token (API key) auth is exempt from the MFA gate because
    API keys are already a §164.312(d)-class second factor that the
    operator explicitly issued; their threat model is the same
    "out-of-band-provisioned credential" the WebAuthn surface uses.
    """
    user = get_current_user(request)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise raise_api_error("Not authenticated", status_code=401, purpose="misc")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/login"},
        )
    # H-05 (Cycle 7) — hard-cutover MFA step-up gate. The Bearer
    # token path stamps `email` from the api_keys row but not the
    # session claim, so detect Bearer-auth by the absence of the
    # `_session_mfa_verified_at` key (only present when
    # `get_current_user` resolved via the cookie path).
    if "_session_mfa_verified_at" in user:
        from email_triage.web.mfa import session_needs_mfa_step_up
        session_view = {
            "mfa_verified_at": user.get("_session_mfa_verified_at"),
        }
        if session_needs_mfa_step_up(session_view):
            if request.url.path.startswith("/api/"):
                raise raise_api_error(
                    "mfa_required", status_code=401, purpose="misc",
                )
            raise HTTPException(
                status_code=303,
                headers={"Location": "/login/webauthn"},
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
            # 403 is correct for both API and UI callers — the user IS
            # authenticated (require_auth passed), just not authorised,
            # so a /login redirect would not help. The former
            # api-vs-ui branch raised an identical 403 on both arms.
            raise raise_api_error(
                "Insufficient permissions", status_code=403, purpose="misc",
            )
        return user

    return _dependency


def require_admin_ui(request: Request) -> tuple[dict[str, Any] | None, Any]:
    """UI admin gate, the ``(user, error_response)`` tuple shape — the SSOT that
    the 8 byte-identical ``_require_admin`` / ``_require_admin_user`` copies
    across the UI routers (auth_keys, backup, integrations, tls_csr,
    ai_backends_crud, embedding_install, retry_queue, _shared) collapse to
    (divergence census 2026-06-09 #3).

    Returns ``(user, None)`` for an authenticated admin; ``(None,
    RedirectResponse("/login", 303))`` for an anonymous user; ``(None,
    HTMLResponse("Forbidden", 403))`` for an authenticated non-admin. The caller
    does ``user, err = require_admin_ui(request)`` then ``if err: return err``.

    Distinct from ``require_role("admin")`` (the ``Depends`` factory that RAISES
    a 403) on purpose: the UI callers want a redirect-to-login for anon + an HTML
    Forbidden body, returned inline — not an exception. The ``api.py`` router
    keeps its own exception-style gate (API contract: 401/403, never a /login
    redirect), so it is intentionally NOT routed through this.
    """
    from fastapi.responses import HTMLResponse
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    err = admin_gate_response(user)
    if err is not None:
        return None, err
    return user, None


def is_admin(user: dict[str, Any] | None) -> bool:
    """The admin-ROLE boolean SSOT (divergence census R22 HIGH #4, 2026-07-02).

    Prior to N-222 the role predicate `user.get("role") == "admin"` was
    duplicated across 60+ Python sites and 6 Jinja `user.role` reads. The
    existing gate SSOTs `admin_gate_response` + `assert_admin` covered only
    the "return 403 / raise" branches; conditional logic that needs a bare
    bool (e.g. "hide the delete button unless admin", "log admin-only field
    if is_admin") had no funnel — so the raw comparison drifted into the
    domain-gate SSOTs (`can_manage_account`, `can_modify_owned_resource`,
    `is_list_*_by`), extending the drift INTO the security domain.

    Fail-closed on: `None` user, missing `role` key, `role` non-string.
    """
    if not user:
        return False
    role = user.get("role")
    return isinstance(role, str) and role == "admin"


def is_health_ro(user: dict[str, Any] | None) -> bool:
    """The ``health_ro`` machine-role boolean (punch , N-536). Same fail-closed
    shape as :func:`is_admin`: ``None`` user, missing ``role`` or a non-string
    role is False. The ROUTE allowlist for this role is enforced at the auth seam
    (``_route_scope``), not here; a handler uses this only to widen an
    ``is_admin`` gate to the routes the allowlist already names."""
    if not user:
        return False
    role = user.get("role")
    return isinstance(role, str) and role == UserRole.HEALTH_RO.value


def admin_gate_response(user: dict[str, Any] | None) -> Any | None:
    """The admin-ROLE gate predicate SSOT (divergence census run12): returns an
    ``HTMLResponse("Forbidden", 403)`` for an authenticated NON-admin user, else
    ``None``. Shared by :func:`require_admin_ui` (after its auth-check) AND the UI
    handlers that already hold an authenticated ``user: RequireUser`` — those need
    only the admin-role half, not the anon redirect, and several lack ``request``
    in scope. Collapses the ~16 inline ``if user["role"] != "admin": return
    HTMLResponse("Forbidden", 403)`` copies to ONE predicate; pinned by
    ``tests/test_admin_gate_ssot_pin.py`` (no raw inline copy in a UI router)."""
    from fastapi.responses import HTMLResponse
    # N-222 R22: fold onto the boolean SSOT.
    if not is_admin(user):
        return HTMLResponse("Forbidden", status_code=403)
    return None


def assert_admin(user: dict[str, Any] | None) -> None:
    """The admin-ROLE gate for the API/raise contract (divergence census run12) —
    the RAISE-twin of :func:`admin_gate_response`. Given an ALREADY-authenticated
    ``user``, raises ``HTTPException(403)`` if the user is not an admin (or is
    None/role-less, fail-closed), else returns ``None``.

    Distinct from :func:`admin_gate_response` (which *returns* an HTMLResponse for
    the UI/redirect contract) only in the response mechanism — same role predicate.
    It is the role-only half kept SEPARATE from auth on purpose: callers that
    interleave work between auth and the role check (e.g. ``webhook._require_user``
    runs ``enforce_rate_limit`` first) call ``user = <auth>(...)`` then
    ``assert_admin(user)`` without losing that step. ``api.py::_require_admin``
    (the auth+admin combo, dispatched via ``db_call`` 8×) routes its role-check
    through this. Pinned by ``tests/test_admin_gate_ssot_pin.py`` (no raw inline
    ``role != "admin" -> raise/return 403`` in api.py/webhook.py)."""
    # N-222 R22: fold onto the boolean SSOT.
    if not is_admin(user):
        raise raise_api_error("Insufficient permissions", status_code=403, purpose="misc")


# ---------------------------------------------------------------------------
#  — RequireUser dependency.
#
# The auth-gate triad — ``get_current_user(request)`` + ``if user is
# None`` + a redirect-or-401 return — was copy-pasted ~84× across the
# UI routers. Two shapes:
#
#   RequireUser          anon → 303 redirect to /login. Full-page nav
#                        targets (GET pages, redirect-style POSTs).
#                        Reuses ``require_auth``, which already raises
#                        ``HTTPException(303, Location=/login)`` for
#                        non-``/api`` paths.
#   RequireUserFragment  anon → ``HTTPException`` 401. HTMX-fragment
#                        endpoints, where a 303 would swap a partial
#                        for a whole login page.
#
# Both yield the user dict on the happy path, so the handler
# signature is ``user: RequireUser`` with no isinstance check — the
# anon case is a raised exception the global handler renders.
#
# Sibling to ``OwnedAccount``: that dep additionally resolves +
# authz-checks an ``account_id``; ``RequireUser`` is the bare
# "just need a logged-in user" gate.
# ---------------------------------------------------------------------------


def _require_user_fragment(request: Request) -> dict[str, Any]:
    """Return the current user, or raise ``HTTPException`` 401.

    The HTMX-fragment sibling of ``RequireUser``: a fragment endpoint
    that 303-redirected an anonymous request would swap a small
    partial for a whole login page. The global 401 handler renders
    the right surface instead.
    """
    user = get_current_user(request)
    if user is None:
        raise raise_api_error("Unauthorized", status_code=401, purpose="misc")
    return user


# Annotated aliases for handler signatures.
#
# Usage::
#
#     async def settings_page(request: Request, user: RequireUser):
#         ...                       # full-page: anon → 303 /login
#
#     async def stats_fragment(request: Request, user: RequireUserFragment):
#         ...                       # HTMX partial: anon → 401
RequireUser = Annotated[dict[str, Any], Depends(require_auth)]
RequireUserFragment = Annotated[
    dict[str, Any], Depends(_require_user_fragment),
]


# ---------------------------------------------------------------------------
#  — OwnedAccount dependency.
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
        raise raise_api_error("Unauthorized", status_code=401, purpose="misc")
    db: sqlite3.Connection = request.app.state.db
    secrets_provider: SecretsProvider = request.app.state.secrets
    # Lazy import: web.db imports trigger the full schema-helper
    # graph; keeping it local to the dep avoids a top-level cycle
    # if dependencies.py is ever pulled into a non-web context.
    from email_triage.web.db import can_manage_account, get_email_account
    acct = get_email_account(db, account_id)
    if acct is None:
        raise raise_api_error("Not found", status_code=404, purpose="misc")
    if not can_manage_account(db, user, acct):
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
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
            raise raise_api_error(
                f"Wrong provider type (expected {provider_type})",
                status_code=400, purpose="misc",
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
#  phase 2 — OwnedAccountOrLogin sibling.
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
        raise raise_api_error("Not found", status_code=404, purpose="misc")
    if not can_manage_account(db, user, acct):
        raise raise_api_error("Forbidden", status_code=403, purpose="misc")
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
