"""CSRF token validation (PR 8 / D1).

Session-cookie auth alone is vulnerable to cross-site forgeries: any
malicious page the user visits can issue a POST/DELETE against this
deployment using the user's existing cookie. Same-origin policy
prevents reading the response, but it does NOT prevent the request
from being made — and any state-changing handler that doesn't
validate origin will perform the action.

The defense is a double-submit token: server mints a value, sets it
as a non-HttpOnly cookie (so JavaScript on the same origin can read
it), AND requires the client to echo it back as either an
``X-CSRF-Token`` header or a hidden form field on every state-
changing request. A cross-origin attacker can't read the cookie
(SameSite + cross-origin restrictions), so they can't echo it,
so the server rejects.

Token format: ``itsdangerous.URLSafeTimedSerializer`` of
``hash(session_token)`` with a CSRF-specific salt. Bound to the
specific session via the hash so a token leaked from session A can't
authorise a request on session B. Lifetime matches the session
(re-mint on every login), but the timed serializer rejects tokens
older than ``CSRF_MAX_AGE``.

Enforcement: ``CsrfMiddleware`` honours ``app.state.csrf_enforce``
(default True as of , 2026-05-10). When True, violations return
HTTP 403. When False (operator opt-out via ``tls.csrf_enforce`` in
YAML or the /admin/security toggle — one store, the env override was
removed 2026-09-12), violations log + bump
``app.state.csrf_rejects`` but the request proceeds. Operator may
flip the flag after
verifying via the counter that no real-traffic forms are missing
the token.

Exempt paths:
* ``/health``                   — unauthenticated, idempotent.
* ``/webhooks/*``               — provider-signed (Gmail Pub/Sub,
                                  Office365 Graph) — origin auth
                                  via the signature, not cookie.
* ``/api/oauth/*/callback``     — OAuth redirect targets; the
                                  state parameter is the CSRF token
                                  for that flow.
* ``/login/*``                  — session not yet established.
* ``GET / HEAD / OPTIONS``      — RFC 7231 safe methods.
"""

from __future__ import annotations
from email_triage._errfmt import fmt_exc
from email_triage._secret_keys import SESSION_SECRET_KEY  # N-231 R22 stored-secret-key SSOT

import hashlib
import logging

from email_triage.triage_logging import get_logger  # N-196b R21_4
import os
import re
import threading
from collections import Counter
from typing import Iterable
from urllib.parse import parse_qs

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


_log = get_logger("email_triage.web.csrf")  # N-196b R21_4


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Cookie name uses __Host- prefix when serving HTTPS so the browser
# enforces "must be Secure, must be Path=/, must NOT have Domain"
# rules — extra defense against cookie shadowing. We set both names
# to keep the dev / HTTP path working without browsers rejecting.
CSRF_COOKIE_NAME = "et_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"

# Salt for the itsdangerous serializer — separate from the session
# salt so leaking a session token doesn't trivially mint a CSRF.
_CSRF_SALT = "email-triage-csrf"

# Token max age (24h). Session lifetime is longer, but a stale token
# still rejected forces a fresh mint and limits replay window.
CSRF_MAX_AGE = 24 * 3600

# Exempt path prefixes — methods that bypass the check entirely.
_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/health",
    "/webhooks/",
    "/api/oauth/",
    "/login",   # /login/email, /login/verify, /login/dev-keypair, etc.
)

# Methods that DO require a token. Everything else (GET / HEAD /
# OPTIONS) is RFC 7231 safe and skipped.
_GUARDED_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# ---------------------------------------------------------------------------
# CSRF reject tracker — a PROCESS-GLOBAL "what still needs a token" log.
#
# The per-app ``app.state.csrf_rejects`` counter resets with each app instance
# (i.e. every test), so it can't give a cross-test view. This module-level tally
# survives the whole PROCESS, keyed by a NORMALIZED route shape (numeric path
# segments → ``:id``), so it is BOUNDED (a finite set of route shapes), PHI-SAFE
# (no body, no query, numeric ids redacted), and groups by FORM. Its purpose is
# the CSRF-test-enforcement migration: run the suite, read
# :func:`csrf_reject_report` (a pytest session hook prints it) to see which
# forms POST without a token under soft-launch = the migration to-do; the set
# shrinks as tests adopt the token-injecting client. CAVEATS: (1) this is
# MIGRATION PROGRESS, not csrf COVERAGE — a route already token-injecting or
# with no csrf test at all never appears; (2) under ``pytest-xdist`` it is
# PER-WORKER (each worker is its own process), not a unified suite-wide tally;
# (3) the ``:id`` redaction is numeric-only (fine for this app's integer-id
# routes — a future non-numeric PHI-bearing path segment would NOT be redacted).
# In production (enforce=ON) it doubles as a by-route view of actual CSRF
# rejections.
# ---------------------------------------------------------------------------

_CSRF_REJECT_TRACKER: "Counter[str]" = Counter()
_CSRF_TRACKER_LOCK = threading.Lock()
_ROUTE_ID_RE = re.compile(r"/\d+(?=/|$)")


def _normalize_route(method: str, path: str) -> str:
    """``(POST, /accounts/5/save)`` → ``POST /accounts/:id/save`` — a bounded,
    PHI-safe route SHAPE (numeric segments redacted, no query/body)."""
    return f"{method} {_ROUTE_ID_RE.sub('/:id', path)}"


def record_csrf_reject(method: str, path: str, *, enforced: bool) -> None:
    """Accumulate one CSRF reject / would-reject into the process-global tally,
    keyed by ``<outcome> <route-shape>`` (outcome = ``rejected`` when enforced,
    ``would-reject`` under soft-launch)."""
    key = (
        ("rejected " if enforced else "would-reject ")
        + _normalize_route(method, path)
    )
    with _CSRF_TRACKER_LOCK:
        _CSRF_REJECT_TRACKER[key] += 1


def csrf_reject_report() -> dict[str, int]:
    """The process-global CSRF reject / would-reject tally by route shape — the
    'what still needs a token' view for the test-enforcement migration (and a
    by-route CSRF-rejection view in production)."""
    with _CSRF_TRACKER_LOCK:
        return dict(_CSRF_REJECT_TRACKER)


def reset_csrf_reject_tracker() -> None:
    """Clear the process-global tally (test isolation / a fresh migration run)."""
    with _CSRF_TRACKER_LOCK:
        _CSRF_REJECT_TRACKER.clear()


# ---------------------------------------------------------------------------
# Mint / verify
# ---------------------------------------------------------------------------

def _hash_session(session_token: str) -> str:
    """Stable hash of the session token used to bind a CSRF token to
    a specific session. SHA-256 truncated to 16 hex chars."""
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:16]


#  — serializer cache. URLSafeTimedSerializer is a pure function
# of (secret_key, salt): the salt is the _CSRF_SALT constant and the
# secret_key is app.state.session_secret, stable for the process.
# Rebuilding it on every mint (per form render) and every verify (per
# guarded request) was pure overhead — memoise by secret_key. The
# cache is effectively one entry; secret_key only changes on a
# master-key rotation.
_serializer_cache: dict[str, URLSafeTimedSerializer] = {}


def _get_serializer(secret_key: str) -> URLSafeTimedSerializer:
    """Return a cached CSRF serializer for ``secret_key``."""
    s = _serializer_cache.get(secret_key)
    if s is None:
        s = URLSafeTimedSerializer(secret_key, salt=_CSRF_SALT)
        _serializer_cache[secret_key] = s
    return s


def mint_csrf_token(secret_key: str, session_token: str) -> str:
    """Create a signed CSRF token bound to ``session_token``."""
    s = _get_serializer(secret_key)
    return s.dumps({"sid": _hash_session(session_token)})


def attach_csrf_cookie(
    response: Response,
    token: str,
    *,
    secure: bool = True,
    max_age: int = CSRF_MAX_AGE,
) -> None:
    """Attach a pre-minted CSRF token as a Set-Cookie on ``response``.

    Caller is responsible for minting the token via
    ``mint_csrf_token`` AND -- when the endpoint also returns the
    token in the body (the /api/csrf-token shape) -- handing the SAME
    token to the body. Splitting mint from attach prevents the prior
    "mutate-then-discard" anti-pattern where a placeholder response
    was created, mutated by a helper, then thrown away while the
    caller emitted a DIFFERENT response inheriting stale headers
    (caused ERR_CONTENT_LENGTH_MISMATCH on /api/csrf-token).

    Cookie is intentionally NOT HttpOnly -- JS on the same origin
    must be able to read it to echo back as the X-CSRF-Token header.
    SameSite=Strict prevents cross-origin requests from carrying it
    at all, which is the entire defense.
    """
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=False,    # JS reads it; HttpOnly would defeat the purpose
        secure=secure,     # set False in dev/HTTP listener; True in prod  # n200-secure-ssot-allowed: attach_csrf_cookie is the CSRF SSOT; `secure` param is the seam; every caller (api.py) passes an is_request_https()-derived value per N-200
        samesite="strict",
        path="/",
    )


def verify_csrf_token(
    secret_key: str, token: str, session_token: str,
    *, max_age: int = CSRF_MAX_AGE,
) -> bool:
    """Verify ``token`` was minted for ``session_token`` and is fresh.

    Returns True/False, never raises. Failure modes:
    * Bad signature (token tampered or wrong secret).
    * Expired (older than ``max_age``).
    * Wrong session binding (sid mismatch).
    """
    if not token:
        return False
    s = _get_serializer(secret_key)
    try:
        payload = s.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return False
    expected = _hash_session(session_token)
    return isinstance(payload, dict) and payload.get("sid") == expected


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

def _is_exempt_path(
    path: str, extra_prefixes: tuple[str, ...] = (),
) -> bool:
    """Check whether ``path`` is exempt from CSRF validation.

    Always-on prefixes from ``_EXEMPT_PREFIXES`` plus the
    operator-defined ``extra_prefixes`` (passed via
    ``app.state.csrf_extra_exempt_prefixes`` from
    ``config.tls.csrf_exempt_prefixes``).
    """
    if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
        return True
    return any(p and path.startswith(p) for p in extra_prefixes)


# ASGI body-buffer cap. Bodies larger than this are not buffered for
# form-field inspection -- header-only path applies. Aligns with
# typical multipart upload limits; a 1MB form post is already
# pathological. Files (multipart/form-data) skip the form-field
# parse entirely regardless of size.
_BODY_BUFFER_CAP = 1024 * 1024  # 1 MB


def _parse_cookie_header(raw: str) -> dict[str, str]:
    """Parse a Cookie request header into a name->value map.

    Pure-ASGI middleware doesn't have Starlette's Request.cookies
    helper available without constructing a Request object. We only
    need a couple of names; a straightforward parse is cheap.
    """
    out: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        out[name.strip()] = value.strip()
    return out


class CsrfMiddleware:
    """Validate the CSRF token on state-changing requests.

    Pure-ASGI middleware (NOT BaseHTTPMiddleware) so we can read the
    request body once for form-field inspection and replay it to the
    downstream handler unchanged. This closes the form-body gap:
    plain HTML forms can include a hidden ``csrf_token`` field and
    have it validated without each call site converting to fetch.

    Body-read shape:
      * Header-only path: if ``X-CSRF-Token`` header is present, no
        body read. Cheap.
      * Form-field path: if header is missing AND content-type is
        ``application/x-www-form-urlencoded``, read the body, parse
        form, look for the configured field name, then replay the
        body bytes to the downstream app via a wrapped receive
        callable. Multipart bodies are NOT parsed (heavier; would
        need streaming parser); they fall through to header-only.
      * Bodies above ``_BODY_BUFFER_CAP`` skip parse entirely —
        protects against memory pressure from a malicious large POST.

    Reads ``app.state.csrf_enforce`` to decide whether to reject
    (True) or only log + count (False). Counter on
    ``app.state.csrf_rejects`` surfaces in /health.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Non-HTTP scopes (lifespan, websocket) pass through unchanged.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope["method"].upper()
        path = scope.get("path", "") or ""

        # Operator-defined extra exemptions. Reads from
        # app.state at request time so a /admin/security save can
        # take effect without a restart, mirroring csrf_enforce.
        extra_exempt = tuple(
            getattr(scope["app"].state, "csrf_extra_exempt_prefixes", []) or [],
        )
        if method not in _GUARDED_METHODS or _is_exempt_path(path, extra_exempt):
            await self.app(scope, receive, send)
            return

        # Build a name->bytes header map for cheap lookups. Headers
        # are a list of (name, value) byte-tuples in ASGI scope.
        headers: dict[bytes, bytes] = {}
        for name, value in scope.get("headers", []):
            # Last-write-wins for duplicates is fine for cookie /
            # x-csrf-token / content-type — none should appear twice.
            headers[name.lower()] = value

        # Session cookie -- no session means unauthenticated; downstream
        # handler will deal with auth, no point rejecting CSRF here.
        from email_triage.web.auth import SESSION_COOKIE_NAME
        cookie_raw = headers.get(b"cookie", b"").decode("latin-1")
        cookies = _parse_cookie_header(cookie_raw) if cookie_raw else {}
        session_token = cookies.get(SESSION_COOKIE_NAME, "")
        if not session_token:
            await self.app(scope, receive, send)
            return

        # Header check first.
        token = headers.get(CSRF_HEADER_NAME.lower().encode("latin-1"), b"").decode("latin-1")

        # Form-field fallback: only if header is missing AND the body
        # is form-urlencoded. Read + buffer + parse + replay.
        buffered_body: bytes | None = None
        body_too_large = False
        if not token:
            content_type = headers.get(b"content-type", b"").decode("latin-1").lower()
            if "application/x-www-form-urlencoded" in content_type:
                buffered_body = b""
                more_body = True
                while more_body:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        # Unexpected message type; pass through.
                        more_body = False
                        continue
                    chunk = message.get("body", b"") or b""
                    if len(buffered_body) + len(chunk) > _BODY_BUFFER_CAP:
                        body_too_large = True
                        # Drain the rest so receive() doesn't deadlock,
                        # but we won't parse it. The replay path below
                        # is skipped for oversize bodies.
                        more_body = message.get("more_body", False)
                        while more_body:
                            m = await receive()
                            if m["type"] != "http.request":
                                break
                            more_body = m.get("more_body", False)
                        break
                    buffered_body += chunk
                    more_body = message.get("more_body", False)
                if not body_too_large and buffered_body:
                    try:
                        parsed = parse_qs(
                            buffered_body.decode("utf-8", errors="replace"),
                            keep_blank_values=True,
                        )
                        field_value = parsed.get(CSRF_FORM_FIELD, [""])[0]
                        if field_value:
                            token = field_value
                    except Exception as _swallow_exc:
                        # Parse failure: leave token empty; will reject
                        # below or proceed under soft-launch.
                        _log.debug(
                            "csrf form-body parse failed; token left empty",
                            error=fmt_exc(_swallow_exc),
                        )

                #  — oversize-body short-circuit. If the body
                # blew past _BODY_BUFFER_CAP and we still have no
                # token (no X-CSRF-Token header, no parseable form
                # field), the only fallthrough was passing the
                # already-drained ``receive`` to the downstream app.
                # That hangs the handler (no body chunks left to
                # deliver) and skips CSRF enforcement on a request
                # we already KNOW is over the cap. Reject 413 here
                # before either failure mode bites. Behaviour for
                # oversize bodies WITH a valid header token is
                # unchanged: header check above set ``token``
                # before this block ran.
                if body_too_large and not token:
                    _log.warning(
                        "CSRF: oversize form body without token rejected (413)",
                        extra={"_extra": {
                            "path": path,
                            "method": method,
                            "cap_bytes": _BODY_BUFFER_CAP,
                        }},
                    )
                    response = JSONResponse(
                        {"error": "request body too large"},
                        status_code=413,
                    )
                    await response(scope, receive, send)
                    return

        secret_key = getattr(scope["app"].state, SESSION_SECRET_KEY, "")
        valid = bool(secret_key) and verify_csrf_token(
            secret_key, token, session_token,
        )

        if not valid:
            state = scope["app"].state
            state.csrf_rejects = int(getattr(state, "csrf_rejects", 0)) + 1
            # Default True:  flipped the install-wide default to
            # enforce. The runtime fallback mirrors so a missing
            # attribute (e.g. test fixture skipping lifespan) reflects
            # the production posture, not the legacy soft-launch one.
            enforce = bool(getattr(state, "csrf_enforce", True))
            # Process-global by-route tally (the migration "what needs a token"
            # log — survives the whole test run, unlike the per-app counter).
            record_csrf_reject(method, path, enforced=enforce)
            _log.warning(
                "CSRF token evaluated",
                extra={"_extra": {
                    "outcome": "rejected" if enforce else "would-reject (soft-launch)",
                    "path": path,
                    "method": method,
                    "enforce": enforce,
                    "had_token": bool(token),
                    "body_buffered": buffered_body is not None,
                    "body_too_large": body_too_large,
                }},
            )
            #  item 3 — append a structured access_log row so the
            # admin UI can answer "which paths are tripping the
            # counter?" without grepping log_entries. Outcome name
            # distinguishes soft-launch (would-have-rejected; the
            # request still proceeded) from enforce (actually 403'd).
            from email_triage.web._audit import safe_audit_write_async
            from email_triage.web.db import record_access_event
            from email_triage.web.db_threadpool import db_call
            #  — record_access_event is @db_write; calling it
            # synchronously here ran the insert (and lock acquisition)
            # on the event-loop thread inside the ASGI middleware.
            # Route it through db_call so the write happens off-loop.
            # Audit-write failure must not block the request flow — the
            # structured log line above already records the rejection;
            # we log the audit miss so /health can see drift, then
            # swallow it (same policy as safe_audit_write).
            db = getattr(state, "db", None)
            if db is not None:
                await safe_audit_write_async(
                    lambda: db_call(
                        record_access_event,
                        db,
                        actor_user_id=None,
                        method=method,
                        route=path,
                        account_id=None,
                        message_id=None,
                        status_code=403 if enforce else 0,
                        outcome=(
                            "csrf_rejected" if enforce
                            else "csrf_would_reject"
                        ),
                        detail=(
                            f"had_token={bool(token)} "
                            f"body_buffered={buffered_body is not None} "
                            f"body_too_large={body_too_large}"
                        ),
                    ),
                    description="csrf_rejection",
                    table="access_log",
                    emitter="record_access_event",
                )
            if enforce:
                response = JSONResponse(
                    {"error": "csrf_token_invalid"},
                    status_code=403,
                )
                await response(scope, receive, send)
                return

        # Forward to downstream. If we read the body for form-field
        # inspection, replay it via a wrapped receive callable; else
        # pass through the original.
        if buffered_body is not None and not body_too_large:
            replayed = False

            async def replay_receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {
                        "type": "http.request",
                        "body": buffered_body,
                        "more_body": False,
                    }
                # After the buffered body is delivered, fall through to
                # the real receive in case the framework asks again
                # (e.g. on disconnect).
                return await receive()

            await self.app(scope, replay_receive, send)
        else:
            await self.app(scope, receive, send)



# ---------------------------------------------------------------------------
# Jinja helper — server-side csrf_token field render
# ---------------------------------------------------------------------------

def csrf_input(request) -> object:
    """Render a hidden csrf_token input pre-populated with a freshly
    minted token bound to the current session.

    Eliminates the race in static/csrf.js where a plain HTML form
    can submit before the JS shim's /api/csrf-token fetch resolves
    (or when the fetch fails silently) — the cached token is empty,
    the submit-capture listener has nothing to inject, the request
    goes through without a token, and the middleware emits a
    "CSRF token would-reject (soft-launch)" line. Server-rendering
    the field closes that gap: every plain form ships with a valid
    token in the body from the first byte. JS shim becomes fallback
    only (its existing logic at csrf.js:150 skips injection when a
    csrf_token field is already present).

    Usage in a Jinja template:

        <form method="post" action="...">
            {{ csrf_input(request) }}
            ...
        </form>

    Anonymous requests (no session cookie) get an empty-value input —
    the field is still present so JS doesn't try to inject a second
    one, but it carries no token. Anonymous requests don't hit the
    CSRF guard anyway (middleware short-circuits at line 276 when
    session_token is empty), so the empty value is harmless.

    Markup import is local to avoid module-import dependency on
    markupsafe for non-template callers of this module.
    """
    from markupsafe import Markup

    #  — reuse a token already minted for THIS request. A page
    # with several forms calls csrf_input() once per form, but one
    # session-bound token is valid for all of them (the token is a
    # session-scoped double-submit value, not a per-form nonce).
    cached = getattr(getattr(request, "state", None), "_csrf_token", None)
    if cached is not None:
        return Markup(
            f'<input type="hidden" name="csrf_token" value="{cached}">'
        )

    try:
        from email_triage.web.auth import SESSION_COOKIE_NAME
        session_token = request.cookies.get(SESSION_COOKIE_NAME, "") or ""
        secret_key = getattr(request.app.state, SESSION_SECRET_KEY, "") or ""
    except Exception:
        # Templates render in many contexts; never raise.
        session_token = ""
        secret_key = ""

    if session_token and secret_key:
        token = mint_csrf_token(secret_key, session_token)
    else:
        token = ""

    # Cache on request.state so sibling forms in the same render
    # reuse it. Best-effort — some render contexts pass a non-Request.
    try:
        request.state._csrf_token = token
    except Exception as _swallow_exc:
        _log.debug(
            "csrf token not cached on request.state (non-Request render context)",
            error=fmt_exc(_swallow_exc),
        )

    return Markup(
        f'<input type="hidden" name="csrf_token" value="{token}">'
    )
