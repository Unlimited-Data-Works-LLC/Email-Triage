"""Auth-surface routes (#67): dev-keypair admin + login,
WebAuthn registration + login, and ACME diagnostic test buttons.

Lives in its own router so the existing 7000-line ``ui.py`` doesn't
grow further. Mounted alongside ``ui_router`` in
``email_triage.web.app.create_app``.

Three URL groupings:

* ``/admin/dev-keys`` (admin-only): list / add / revoke dev-keypair
  registrations.
* ``/admin/acme-status`` (admin-only): on-disk cert metadata, last
  renewal log, granular DNS-01 test buttons (reachability, TSIG
  auth, publish + verify, full cycle), manual issue-now buttons
  (staging vs production directory).
* ``/login/dev-keypair`` and ``/login/webauthn/{begin,finish}``:
  the new login flows. Email-then-touch becomes the default for any
  user with a registered hardware key; OTP remains the fallback.
* ``/profile/hardware-keys`` (per-user): self-service WebAuthn
  registration + revoke.

Security gates per route are documented inline. The
``hardware-key-wins`` rule (dev-keypair logins are denied for any
user with at least one active hardware_keys row) is enforced
server-side at ``/login/dev-keypair`` verify time.
"""

from __future__ import annotations

import base64
import json
import secrets as _secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from email_triage.triage_logging import get_logger
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE,
    create_session_token,
    get_user_by_email,
)
from email_triage.web.dependencies import get_current_user
from email_triage.web.db_auth_helpers import (
    add_dev_key as db_add_dev_key,
    find_dev_key_by_fingerprint,
    is_dev_key_active,
    list_acme_renewal_log,
    list_dev_keys,
    list_hardware_keys,
    mark_dev_key_used,
    revoke_dev_key as db_revoke_dev_key,
    revoke_hardware_key as db_revoke_hardware_key,
    user_has_active_hardware_key,
)
from email_triage.web import dev_keypair as dk
from email_triage.web import webauthn_auth as wa
from email_triage.web import acme_renewer as acme_mod
from email_triage._errfmt import fmt_exc


log = get_logger("web.auth_keys")
router = APIRouter()


_DEV_KEYPAIR_CHALLENGE_COOKIE = "et_devkp_challenge"
_PASSKEY_CHALLENGE_COOKIE = "et_passkey_challenge"
_DEV_KEYPAIR_CHALLENGE_TTL = 120  # seconds


def _get_db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


def _get_templates(request: Request):
    return request.app.state.templates


def _get_config(request: Request):
    return request.app.state.config


def _get_secrets(request: Request):
    return request.app.state.secrets


def _render(request: Request, name: str, context: dict[str, Any] | None = None):
    """Wrapper matching ui.py's `_render` semantics: injects user +
    hipaa_mode template globals so base templates render
    consistently."""
    from email_triage.web.routers.ui import _render as _render_ui
    return _render_ui(_get_templates(request), request, name, context or {})


def _allowed_webauthn_origins(request: Request, config) -> list[str]:
    """Return the list of origins acceptable for WebAuthn verify.

    The browser sends the literal ``scheme://host[:port]`` it loaded the
    page from in ``clientDataJSON.origin``; the verify call must accept
    that exact string. A static config field can't cover all of:

      * Direct listener on a non-default port (``:8081``)
      * Reverse-proxy fronted on :443 (bare hostname)
      * Operator switching between the two without re-issuing keys

    So we build the list at request time:

      1. The configured ``webauthn.origin`` (always included, gives
         the operator an explicit override).
      2. The request's ``Origin`` header IF its hostname matches
         ``rp_id`` -- defense against an attacker injecting an Origin
         header that points at their own domain. The library still
         enforces signature + RP-id; this is belt-and-braces.

    Returns a de-duplicated list. The webauthn library's
    ``expected_origin`` accepts ``Union[str, List[str]]``.
    """
    rp_id = (config.webauthn.rp_id or "").strip().lower()
    out: list[str] = []
    cfg = (config.webauthn.origin or "").strip()
    if cfg:
        out.append(cfg)
    req_origin = (request.headers.get("origin") or "").strip()
    if req_origin and rp_id:
        # Cheap parse: scheme://host[:port], no path. Compare host only.
        try:
            from urllib.parse import urlparse
            p = urlparse(req_origin)
            if p.hostname and p.hostname.lower() == rp_id:
                if req_origin not in out:
                    out.append(req_origin)
        except Exception:
            pass
    return out or [cfg]  # never empty -- fall back to config even if blank


def _require_admin(request: Request):
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _require_login(request: Request):
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    return user, None


# ---------------------------------------------------------------------------
# /admin/dev-keys (admin only)
# ---------------------------------------------------------------------------

@router.get("/admin/dev-keys", response_class=HTMLResponse)
async def admin_dev_keys_legacy(request: Request):
    """Legacy URL — Dev keys is now folded into the Security tab on
    /config (alongside the Compliance & Security card grid).

    303-redirect preserves bookmarks + log links + the owner_filter
    query param so existing per-owner shortcuts survive the bounce.
    Auth gate runs FIRST so anonymous users still bounce to /login
    and non-admin users still get 403 — preserves the pre-refactor
    contract that ``follow_redirects=False`` tests pin against.
    """
    user, err = _require_admin(request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=security{tail}", status_code=303,
    )


def build_dev_keys_context(request: Request, user: dict) -> dict:
    """Build the context dict the Security tab's Dev keys section
    needs. Lifted out of the (now-redirect) legacy /admin/dev-keys
    handler so the unified /config route can render the same
    listing under ?tab=security."""
    db = _get_db(request)
    all_keys = list_dev_keys(db)
    now_iso = datetime.now(timezone.utc).isoformat()
    for k in all_keys:
        k["active"] = is_dev_key_active(k, now_iso)

    # Build owner list across creators (created_by_user_id +
    # created_by_email + created_by_name joined by list_dev_keys).
    # Style matches /accounts: "name (email)" if name present, else
    # email, else "User #N". No "Me" alias.
    seen_owners: dict[int, dict] = {}
    for k in all_keys:
        oid = k.get("created_by_user_id")
        if oid is None or oid in seen_owners:
            continue
        email = k.get("created_by_email") or ""
        name = k.get("created_by_name") or ""
        if name and email:
            label = f"{name} ({email})"
        else:
            label = name or email or f"User #{oid}"
        seen_owners[oid] = {"id": oid, "label": label}
    visible_owners = sorted(
        seen_owners.values(), key=lambda x: x["label"].lower(),
    )

    raw_filter = (request.query_params.get("owner_filter") or "").strip()
    if raw_filter == "all":
        owner_filter_value: int | str = "all"
        keys = all_keys
    else:
        try:
            candidate = int(raw_filter) if raw_filter else user["id"]
        except (TypeError, ValueError):
            candidate = user["id"]
        valid = {o["id"] for o in visible_owners}
        if visible_owners and candidate not in valid:
            candidate = user["id"]
        owner_filter_value = candidate
        keys = [
            k for k in all_keys
            if k.get("created_by_user_id") == candidate
        ]

    return {
        "keys": keys,
        "visible_owners": visible_owners,
        "owner_filter": owner_filter_value,
    }


@router.post("/admin/dev-keys/add", response_class=HTMLResponse)
async def admin_dev_keys_add(
    request: Request,
    name: str = Form(...),
    public_key: str = Form(...),
    ttl: str = Form("1w"),
    email_allowlist: str = Form(""),
):
    """Add a dev-keypair registration.

    ``ttl`` is one of '1d' / '1w' / '2w' (UI dropdown). ``email_allowlist``
    is a comma-separated list of emails the key may log in as.
    """
    user, err = _require_admin(request)
    if err:
        return err
    db = _get_db(request)

    # Parse + validate the public key.
    try:
        parsed = dk.parse_ssh_ed25519_pubkey(public_key)
    except dk.DevKeyParseError as e:
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f'Invalid key: {e}</small>',
            status_code=400,
        )
    fp = dk.fingerprint(parsed)

    # TTL → expires_at.
    ttl_map = {"1d": 1, "1w": 7, "2w": 14}
    days = ttl_map.get(ttl, 7)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=days)
    ).isoformat()

    # Email allowlist. Validate every email matches a real user — keeps
    # admin from typo'ing an address that nobody can actually use.
    emails = [e.strip().lower() for e in email_allowlist.split(",") if e.strip()]
    if not emails:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Email allowlist required (comma-separated).</small>',
            status_code=400,
        )
    for em in emails:
        if get_user_by_email(db, em) is None:
            return HTMLResponse(
                f'<small style="color:var(--pico-del-color);">'
                f"Allowlist email {em!r} doesn't match a known user.</small>",
                status_code=400,
            )

    try:
        new_id = db_add_dev_key(
            db, name=name, public_key=public_key.strip(),
            fingerprint=fp, email_allowlist=emails,
            created_by_user_id=user["id"], expires_at=expires_at,
        )
    except sqlite3.IntegrityError:
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f'Fingerprint already registered: {fp}. '
            f'Revoke the existing entry first.</small>',
            status_code=409,
        )

    log.info(
        "Dev key registered",
        key_id=new_id, fingerprint=fp, name=name,
        actor_user_id=user["id"], allowlist=emails, ttl=ttl,
    )
    # Redirect to the Security tab on /config (legacy /admin/dev-keys
    # 303-bounces here anyway, but bypass the extra hop on success).
    return RedirectResponse("/config?tab=security", status_code=303)


@router.post("/admin/dev-keys/{key_id}/revoke", response_class=HTMLResponse)
async def admin_dev_keys_revoke(request: Request, key_id: int):
    user, err = _require_admin(request)
    if err:
        return err
    db = _get_db(request)
    ok = db_revoke_dev_key(db, key_id, user["id"])
    if ok:
        log.info("Dev key revoked", key_id=key_id, actor_user_id=user["id"])
    return RedirectResponse("/config?tab=security", status_code=303)


# ---------------------------------------------------------------------------
# /login/dev-keypair (challenge-response login)
# ---------------------------------------------------------------------------

@router.get("/login/dev-keypair", response_class=HTMLResponse)
async def login_dev_keypair_page(request: Request):
    """Render the dev-keypair login form. Sets a fresh challenge
    cookie so the operator's CLI / paste-in client can sign it."""
    challenge = dk.generate_login_challenge()
    challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii")
    response = _render(request, "login_dev_keypair.html", {
        "challenge": challenge_b64,
    })
    response.set_cookie(
        _DEV_KEYPAIR_CHALLENGE_COOKIE, challenge_b64,
        max_age=_DEV_KEYPAIR_CHALLENGE_TTL,
        httponly=True, samesite="lax", secure=False,
    )
    return response


@router.post("/login/dev-keypair", response_class=HTMLResponse)
async def login_dev_keypair_verify(
    request: Request,
    email: str = Form(...),
    signature: str = Form(...),
    fingerprint: str = Form(""),
    public_key: str = Form(""),
):
    """Verify a dev-keypair signature. Mints a session on success.

    Two equivalent identification paths so the browser-side signer
    works without WebCrypto's secure-context-only ``subtle.digest``:

    * ``fingerprint`` — operator (or the manual-paste form) supplies
      the precomputed ``SHA256:<b64>`` string that matches what was
      stored on /admin/dev-keys.
    * ``public_key`` — base64url-encoded 32-byte ed25519 public key.
      Server computes the same fingerprint from it via the existing
      ``dev_keypair.fingerprint()`` helper. Lets the in-browser
      signer skip ``crypto.subtle.digest`` (which is unavailable
      over plain HTTP).

    Hardware-key-wins rule: if the user has any active hardware_keys
    row, this path is closed for that email. OTP path remains
    available regardless.

    #92 — login_guard runs FIRST so a brute-force attacker can't
    use the signature-verify side-channel for fingerprint /
    public-key oracle queries. Per-email + per-ip counters are
    shared with the OTP and WebAuthn surfaces — a sustained
    brute-force across multiple surfaces against the same
    email/IP still trips the gate.
    """
    db = _get_db(request)
    config = _get_config(request)
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # #92 lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
    try:
        check_login_allowed(
            db, email=email, ip=client_host, config=config,
        )
    except LoginLocked as locked:
        record_login_lockout(
            db, surface="dev_keypair", email=email, ip=client_host,
            user_agent=user_agent, scope=locked.scope,
            threshold=locked.retry_after_secs,
        )
        retry_min = max(1, locked.retry_after_secs // 60)
        return HTMLResponse(
            f"Too many login attempts. Try again in {retry_min} "
            f"minute{'s' if retry_min != 1 else ''}.",
            status_code=429,
            headers={"Retry-After": str(locked.retry_after_secs)},
        )

    # Pull challenge from cookie. Single-use — clear cookie on response.
    challenge_b64 = request.cookies.get(_DEV_KEYPAIR_CHALLENGE_COOKIE, "")
    if not challenge_b64:
        return HTMLResponse(
            "Login challenge expired. Reload the page.",
            status_code=400,
        )
    try:
        # Restore base64 padding.
        pad = "=" * (-len(challenge_b64) % 4)
        challenge = base64.urlsafe_b64decode(challenge_b64 + pad)
    except Exception:
        return HTMLResponse("Invalid challenge cookie.", status_code=400)

    # Parse signature (operator sends url-safe base64).
    try:
        pad = "=" * (-len(signature) % 4)
        sig_bytes = base64.urlsafe_b64decode(signature + pad)
    except Exception:
        return HTMLResponse("Invalid signature encoding.", status_code=400)

    # Resolve fingerprint: operator may supply it directly OR pass
    # the raw public key (browser path that can't compute SHA-256).
    if not fingerprint and public_key:
        try:
            pad = "=" * (-len(public_key) % 4)
            pub_bytes = base64.urlsafe_b64decode(public_key + pad)
        except Exception:
            return HTMLResponse("Invalid public_key encoding.", status_code=400)
        if len(pub_bytes) != 32:
            return HTMLResponse(
                f"public_key must be 32 bytes; got {len(pub_bytes)}.",
                status_code=400,
            )
        # Build the OpenSSH wire blob the server side normally
        # fingerprints (matches dev_keypair.parse_ssh_ed25519_pubkey
        # output) and reuse the same SHA-256 helper. Avoids a
        # parallel implementation drifting from the registration
        # path's fingerprint computation.
        import struct
        blob = (
            struct.pack(">I", 11) + b"ssh-ed25519"
            + struct.pack(">I", 32) + pub_bytes
        )
        # Compose a ParsedDevKey by hand — fingerprint() needs the
        # blob attribute and nothing else.
        from types import SimpleNamespace
        fingerprint = dk.fingerprint(SimpleNamespace(blob=blob))
    if not fingerprint:
        return HTMLResponse(
            "Either fingerprint or public_key must be supplied.",
            status_code=400,
        )

    # Look up the registered key.
    row = find_dev_key_by_fingerprint(db, fingerprint)
    if row is None:
        log.warning(
            "Dev-keypair login: unknown fingerprint",
            fingerprint=fingerprint, email=email,
        )
        record_login_failure(
            db, surface="dev_keypair", email=email, ip=client_host,
            user_agent=user_agent, reason="unknown_fingerprint",
        )
        return HTMLResponse(
            "Unknown or revoked key.", status_code=403,
        )
    now_iso = datetime.now(timezone.utc).isoformat()
    if not is_dev_key_active(row, now_iso):
        log.warning(
            "Dev-keypair login: key inactive",
            key_id=row["id"], email=email,
            revoked_at=row.get("revoked_at"),
            expires_at=row.get("expires_at"),
        )
        record_login_failure(
            db, surface="dev_keypair", email=email, ip=client_host,
            user_agent=user_agent, reason="key_inactive",
            key_id=row["id"],
        )
        return HTMLResponse("Key is revoked or expired.", status_code=403)

    # Email allowlist enforcement.
    email_l = email.strip().lower()
    if email_l not in [e.lower() for e in row.get("email_allowlist", [])]:
        log.warning(
            "Dev-keypair login: email not in allowlist",
            key_id=row["id"], email=email_l,
        )
        record_login_failure(
            db, surface="dev_keypair", email=email_l, ip=client_host,
            user_agent=user_agent, reason="email_not_in_allowlist",
            key_id=row["id"],
        )
        return HTMLResponse(
            "This key is not allowlisted for that email.",
            status_code=403,
        )

    # User exists?
    user = get_user_by_email(db, email_l)
    if user is None:
        record_login_failure(
            db, surface="dev_keypair", email=email_l, ip=client_host,
            user_agent=user_agent, reason="account_not_found",
        )
        return HTMLResponse("Account not found.", status_code=404)
    if user.get("disabled"):
        record_login_failure(
            db, surface="dev_keypair", email=email_l, ip=client_host,
            user_agent=user_agent, reason="account_disabled",
            user_id=user["id"],
        )
        return HTMLResponse("Account disabled.", status_code=403)

    # Hardware-key-wins rule.
    if user_has_active_hardware_key(db, user["id"]):
        log.info(
            "Dev-keypair login refused: hardware key registered",
            email=email_l, user_id=user["id"], key_id=row["id"],
        )
        record_login_failure(
            db, surface="dev_keypair", email=email_l, ip=client_host,
            user_agent=user_agent, reason="hardware_key_required",
            user_id=user["id"], key_id=row["id"],
        )
        return HTMLResponse(
            "This account has a hardware key registered. Use your "
            "hardware key or OTP fallback to log in.",
            status_code=403,
        )

    # Verify signature against challenge.
    try:
        parsed = dk.parse_ssh_ed25519_pubkey(row["public_key"])
    except dk.DevKeyParseError:
        log.error(
            "Dev-keypair login: stored public_key unparseable",
            key_id=row["id"],
        )
        return HTMLResponse("Server-side key parse error.", status_code=500)
    if not dk.verify_signature(parsed, challenge, sig_bytes):
        log.warning(
            "Dev-keypair login: signature invalid",
            key_id=row["id"], email=email_l,
        )
        record_login_failure(
            db, surface="dev_keypair", email=email_l, ip=client_host,
            user_agent=user_agent, reason="signature_invalid",
            user_id=user["id"], key_id=row["id"],
        )
        return HTMLResponse("Invalid signature.", status_code=403)

    # All checks pass: mint session, stamp last_used_at on the key.
    client_ip = request.client.host if request.client else ""
    mark_dev_key_used(db, row["id"], email=email_l, ip=client_ip)
    # PR 9 / D4 — append-only audit row, parallel to the
    # mark_dev_key_used overwrite (which feeds the admin UI's
    # "last used" display). This row preserves history.
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type="login_dev_keypair",
            email=email_l,
            user_id=user["id"],
            key_id=row["id"],
            ip=client_ip or None,
            user_agent=request.headers.get("user-agent"),
            outcome="success",
        )
    except Exception:
        pass
    # PR 10 / E — metrics counter.
    try:
        from email_triage import metrics as metrics_mod
        metrics_mod.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface="dev_keypair", outcome="success")
    except Exception:
        pass
    from email_triage.web.dependencies import get_session_secret
    secret = get_session_secret(request)
    token = create_session_token(
        secret, user["email"], user["role"],
        auth_source="dev_keypair", auth_key_id=row["id"],
    )
    log.info(
        "Dev-keypair login successful",
        key_id=row["id"], user_id=user["id"], email=email_l,
        client_ip=client_ip,
    )
    response = RedirectResponse("/dashboard", status_code=303)
    from email_triage.web.auth import effective_session_ttl
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=effective_session_ttl(request.app.state.config),
        httponly=True, samesite="lax",
    )
    response.delete_cookie(_DEV_KEYPAIR_CHALLENGE_COOKIE)
    return response


# ---------------------------------------------------------------------------
# /login/webauthn — hardware-key login
# ---------------------------------------------------------------------------

@router.post("/login/webauthn/begin", response_class=JSONResponse)
async def login_webauthn_begin(request: Request, email: str = Form(...)):
    """Step 1 of WebAuthn login: return assertion options for the
    browser to feed into navigator.credentials.get()."""
    db = _get_db(request)
    config = _get_config(request)
    user = get_user_by_email(db, email.strip().lower())
    if user is None or user.get("disabled"):
        # Don't leak account existence — generic error.
        return JSONResponse(
            {"error": "no_credential"}, status_code=404,
        )
    if not user_has_active_hardware_key(db, user["id"]):
        return JSONResponse(
            {"error": "no_credential"}, status_code=404,
        )
    try:
        opts_json = wa.begin_authentication(
            db,
            user_id=user["id"],
            email=user["email"],
            rp_id=config.webauthn.rp_id,
            require_user_verification=(
                config.webauthn.require_user_verification_for_admin
                and user.get("role") == "admin"
            ),
        )
    except wa.WebAuthnConfigError as e:
        return JSONResponse({"error": fmt_exc(e)}, status_code=503)
    except wa.WebAuthnAuthError as e:
        return JSONResponse({"error": fmt_exc(e)}, status_code=400)
    return JSONResponse(json.loads(opts_json))


@router.post("/login/webauthn/finish", response_class=JSONResponse)
async def login_webauthn_finish(request: Request):
    """Step 2 of WebAuthn login: verify assertion + mint session.

    #92 — login_guard runs before assertion verify so brute-force
    against the assertion path is throttled identically to the
    OTP + dev-keypair surfaces.
    """
    db = _get_db(request)
    config = _get_config(request)
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    response_data = body.get("response")
    if not email or not response_data:
        return JSONResponse({"error": "bad_request"}, status_code=400)
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # #92 lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
    try:
        check_login_allowed(
            db, email=email, ip=client_host, config=config,
        )
    except LoginLocked as locked:
        record_login_lockout(
            db, surface="webauthn", email=email, ip=client_host,
            user_agent=user_agent, scope=locked.scope,
            threshold=locked.retry_after_secs,
        )
        return JSONResponse(
            {"error": "rate_limited",
             "retry_after_secs": locked.retry_after_secs},
            status_code=429,
            headers={"Retry-After": str(locked.retry_after_secs)},
        )

    user = get_user_by_email(db, email)
    if user is None or user.get("disabled"):
        # Don't leak account state — generic error AND a failure
        # row so the rate-limiter still counts the probe.
        record_login_failure(
            db, surface="webauthn", email=email, ip=client_host,
            user_agent=user_agent,
            reason="no_account_or_disabled",
        )
        return JSONResponse({"error": "no_credential"}, status_code=404)
    try:
        key_id = wa.finish_authentication(
            db,
            user_id=user["id"],
            rp_id=config.webauthn.rp_id,
            origin=_allowed_webauthn_origins(request, config),
            response_json=response_data,
        )
    except wa.WebAuthnAuthError as e:
        log.warning("WebAuthn login: assertion verify failed",
                    email=email, error=fmt_exc(e))
        record_login_failure(
            db, surface="webauthn", email=email, ip=client_host,
            user_agent=user_agent, reason="verify_failed",
            user_id=user["id"],
        )
        return JSONResponse({"error": "verify_failed"}, status_code=403)
    # PR 9 / D4 — append-only audit. WebAuthn finish_authentication
    # already updates hardware_keys.last_used_at internally; this
    # row preserves history.
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type="login_webauthn",
            email=email,
            user_id=user["id"],
            key_id=key_id,
            ip=(request.client.host if request.client else None),
            user_agent=request.headers.get("user-agent"),
            outcome="success",
        )
    except Exception:
        pass
    # PR 10 / E — metrics counter.
    try:
        from email_triage import metrics as metrics_mod
        metrics_mod.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface="webauthn", outcome="success")
    except Exception:
        pass
    from email_triage.web.dependencies import get_session_secret
    secret = get_session_secret(request)
    token = create_session_token(
        secret, user["email"], user["role"],
        auth_source="webauthn", auth_key_id=key_id,
    )
    response = JSONResponse({"ok": True, "redirect": "/dashboard"})
    from email_triage.web.auth import effective_session_ttl
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=effective_session_ttl(request.app.state.config),
        httponly=True, samesite="lax",
    )
    log.info(
        "WebAuthn login successful",
        user_id=user["id"], email=email, key_id=key_id,
    )
    return response


# ---------------------------------------------------------------------------
# /login/webauthn/passkey — discoverable-credential conditional UI flow
# ---------------------------------------------------------------------------
#
# Same crypto as the per-user "email -> touch your security key" flow, but
# the user doesn't pre-supply email. Browser autofill picks the passkey,
# returns the credential's userHandle; we resolve the user from that.
# Challenge lives in a short-lived cookie -- no user_id at begin time.

@router.post("/login/webauthn/passkey/begin", response_class=JSONResponse)
async def login_passkey_begin(request: Request):
    """Step 1 of passkey login: return discoverable-credential
    assertion options + stash the challenge in a signed cookie."""
    config = _get_config(request)
    if not config.webauthn.rp_id:
        return JSONResponse(
            {"error": "webauthn_not_configured"}, status_code=503,
        )
    options_json, challenge = wa.begin_passkey_authentication(
        rp_id=config.webauthn.rp_id,
    )
    # Stash the challenge for the finish step. itsdangerous-signed
    # so a tampered cookie can't smuggle a chosen-challenge.
    import base64 as _b64
    from itsdangerous import URLSafeSerializer
    secret = getattr(request.app.state, "session_secret", "") or ""
    if not secret:
        return JSONResponse(
            {"error": "csrf_unconfigured"}, status_code=500,
        )
    s = URLSafeSerializer(secret, salt="email-triage-passkey-challenge")
    cookie_val = s.dumps(_b64.urlsafe_b64encode(challenge).decode("ascii"))
    https = bool(getattr(getattr(config, "tls", None), "enabled", False))
    resp = JSONResponse({"options": json.loads(options_json)})
    resp.set_cookie(
        _PASSKEY_CHALLENGE_COOKIE,
        cookie_val,
        max_age=300,            # 5 min
        httponly=True,          # only server reads it
        secure=https,
        samesite="strict",
        path="/",
    )
    return resp


@router.post("/login/webauthn/passkey/finish", response_class=JSONResponse)
async def login_passkey_finish(request: Request):
    """Step 2 of passkey login: read challenge from cookie, verify
    assertion, resolve user from credential, mint session.

    #92 — IP-only guard (passkey doesn't carry email upfront).
    The per-email guard fires later if user resolution succeeds
    AND the assertion fails.
    """
    db = _get_db(request)
    config = _get_config(request)
    body = await request.json()
    response_data = body.get("response")
    if not response_data:
        return JSONResponse({"error": "bad_request"}, status_code=400)
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # #92 IP-only lockout gate (no email yet at this point).
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
    try:
        check_login_allowed(
            db, email=None, ip=client_host, config=config,
        )
    except LoginLocked as locked:
        record_login_lockout(
            db, surface="passkey", email=None, ip=client_host,
            user_agent=user_agent, scope=locked.scope,
            threshold=locked.retry_after_secs,
        )
        return JSONResponse(
            {"error": "rate_limited",
             "retry_after_secs": locked.retry_after_secs},
            status_code=429,
            headers={"Retry-After": str(locked.retry_after_secs)},
        )

    cookie_val = request.cookies.get(_PASSKEY_CHALLENGE_COOKIE, "")
    if not cookie_val:
        return JSONResponse(
            {"error": "no_active_challenge"}, status_code=400,
        )
    import base64 as _b64
    from itsdangerous import URLSafeSerializer, BadSignature
    secret = getattr(request.app.state, "session_secret", "") or ""
    s = URLSafeSerializer(secret, salt="email-triage-passkey-challenge")
    try:
        challenge_b64 = s.loads(cookie_val)
        challenge = _b64.urlsafe_b64decode(challenge_b64)
    except (BadSignature, ValueError, Exception):
        return JSONResponse(
            {"error": "challenge_invalid"}, status_code=400,
        )

    try:
        user_id, key_id = wa.finish_passkey_authentication(
            db,
            rp_id=config.webauthn.rp_id,
            origin=_allowed_webauthn_origins(request, config),
            response_json=response_data,
            challenge=challenge,
        )
    except wa.WebAuthnAuthError as e:
        log.warning(
            "Passkey login: assertion verify failed", error=fmt_exc(e),
        )
        record_login_failure(
            db, surface="passkey", email=None, ip=client_host,
            user_agent=user_agent, reason="verify_failed",
        )
        return JSONResponse({"error": "verify_failed"}, status_code=403)

    # Look up the resolved user. No dedicated by-id helper exists;
    # one-line query is fine.
    row = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,),
    ).fetchone()
    user = dict(row) if row else None
    if user is None or user.get("disabled"):
        record_login_failure(
            db, surface="passkey",
            email=(row["email"] if row else None),
            ip=client_host, user_agent=user_agent,
            reason="user_inactive",
            user_id=user_id, key_id=key_id,
        )
        return JSONResponse({"error": "user_inactive"}, status_code=403)

    # Append-only audit + metric counter (mirrors the existing
    # webauthn login site).
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type="login_webauthn",
            email=user["email"],
            user_id=user["id"],
            key_id=key_id,
            ip=(request.client.host if request.client else None),
            user_agent=request.headers.get("user-agent"),
            outcome="success",
            detail="passkey",
        )
    except Exception:
        pass
    try:
        from email_triage import metrics as metrics_mod
        metrics_mod.counter(
            "et_auth_attempts_total",
            "Login attempts by surface and outcome.",
        ).inc(surface="passkey", outcome="success")
    except Exception:
        pass

    from email_triage.web.dependencies import get_session_secret
    sess_secret = get_session_secret(request)
    token = create_session_token(
        sess_secret, user["email"], user["role"],
        auth_source="webauthn", auth_key_id=key_id,
    )
    from email_triage.web.auth import effective_session_ttl
    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    resp.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=effective_session_ttl(request.app.state.config),
        httponly=True, samesite="lax",
    )
    resp.delete_cookie(_PASSKEY_CHALLENGE_COOKIE)
    log.info(
        "Passkey login successful",
        user_id=user["id"], email=user["email"], key_id=key_id,
    )
    return resp


# ---------------------------------------------------------------------------
# /profile/hardware-keys — per-user self-service
# ---------------------------------------------------------------------------

@router.get("/profile/hardware-keys", response_class=HTMLResponse)
async def profile_hardware_keys_page(request: Request):
    """Hardware keys page.

    Regular user: lists their own keys only — no filter.
    Admin: lists their own keys by default, with a Filter by Owner
    dropdown (Me / each owner / All Users) so they can see any
    user's keys from one page. Same pattern as /accounts.
    """
    user, err = _require_login(request)
    if err:
        return err
    db = _get_db(request)
    is_admin = user["role"] == "admin"

    raw_filter = (request.query_params.get("owner_filter") or "").strip()
    if not is_admin:
        # Non-admins always see only their own keys; no filter.
        keys = list_hardware_keys(
            db, user["id"], include_revoked=True,
        )
        visible_owners = []
        owner_filter_value: int | str = user["id"]
    else:
        all_keys = list_hardware_keys(db, None, include_revoked=True)
        # Build owner list across all keys (admins see everyone).
        # Style matches /accounts: "name (email)" if name present,
        # else email, else "User #N". No "Me" alias.
        seen_owners: dict[int, dict] = {}
        for k in all_keys:
            oid = k.get("user_id")
            if oid is None or oid in seen_owners:
                continue
            email = k.get("owner_email") or ""
            name = k.get("owner_name") or ""
            if name and email:
                label = f"{name} ({email})"
            else:
                label = name or email or f"User #{oid}"
            seen_owners[oid] = {"id": oid, "label": label}
        visible_owners = sorted(
            seen_owners.values(), key=lambda x: x["label"].lower(),
        )
        # Default filter = current user; "all" returns everything.
        if raw_filter == "all":
            owner_filter_value = "all"
            keys = all_keys
        else:
            try:
                candidate = (
                    int(raw_filter) if raw_filter else user["id"]
                )
            except (TypeError, ValueError):
                candidate = user["id"]
            valid = {o["id"] for o in visible_owners}
            if candidate not in valid:
                candidate = user["id"]
            owner_filter_value = candidate
            keys = [k for k in all_keys if k.get("user_id") == candidate]
    return _render(request, "profile/hardware_keys.html", {
        "user": user, "keys": keys,
        "is_admin": is_admin,
        "visible_owners": visible_owners,
        "owner_filter": owner_filter_value,
    })


@router.post("/profile/hardware-keys/register/begin", response_class=JSONResponse)
async def profile_hw_register_begin(request: Request):
    user, err = _require_login(request)
    if err:
        return err
    db = _get_db(request)
    config = _get_config(request)
    try:
        opts_json = wa.begin_registration(
            db, user=user,
            rp_id=config.webauthn.rp_id, rp_name=config.webauthn.rp_name,
            require_user_verification=(
                config.webauthn.require_user_verification_for_admin
                and user.get("role") == "admin"
            ),
        )
    except wa.WebAuthnConfigError as e:
        return JSONResponse({"error": fmt_exc(e)}, status_code=503)
    return JSONResponse(json.loads(opts_json))


@router.post("/profile/hardware-keys/register/finish", response_class=JSONResponse)
async def profile_hw_register_finish(request: Request):
    user, err = _require_login(request)
    if err:
        return err
    db = _get_db(request)
    config = _get_config(request)
    body = await request.json()
    nickname = (body.get("nickname") or "").strip()
    response_data = body.get("response")
    if not nickname or not response_data:
        return JSONResponse({"error": "bad_request"}, status_code=400)
    try:
        new_id = wa.finish_registration(
            db, user=user,
            rp_id=config.webauthn.rp_id,
            origin=_allowed_webauthn_origins(request, config),
            response_json=response_data, nickname=nickname,
        )
    except wa.WebAuthnAuthError as e:
        log.warning("WebAuthn register: verify failed",
                    user_id=user["id"], error=fmt_exc(e))
        return JSONResponse({"error": "verify_failed"}, status_code=400)
    log.info(
        "Hardware key registered",
        user_id=user["id"], key_id=new_id, nickname=nickname,
    )
    return JSONResponse({"ok": True, "key_id": new_id})


@router.post("/profile/hardware-keys/{key_id}/revoke", response_class=HTMLResponse)
async def profile_hw_revoke(request: Request, key_id: int):
    user, err = _require_login(request)
    if err:
        return err
    db = _get_db(request)
    # Verify the key belongs to this user before revoking.
    rows = list_hardware_keys(db, user["id"], include_revoked=True)
    if not any(r["id"] == key_id for r in rows):
        return HTMLResponse("Not found", status_code=404)
    if db_revoke_hardware_key(db, key_id):
        log.info("Hardware key revoked",
                 user_id=user["id"], key_id=key_id)
    return RedirectResponse("/profile/hardware-keys", status_code=303)


# ---------------------------------------------------------------------------
# /admin/acme-status — cert metadata + DNS-01 test buttons + issue-now
# ---------------------------------------------------------------------------

@router.get("/admin/acme-status", response_class=HTMLResponse)
async def admin_acme_status_page(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    db = _get_db(request)
    config = _get_config(request)
    secrets = _get_secrets(request)
    cert_dir = (
        config.tls.cert_dir
        or str(getattr(request.app.state, "data_dir", "./data") + "/certs")
    )
    renewer = acme_mod.AcmeRenewer(
        cfg=config.tls.acme, cert_dir=cert_dir,
        secrets_store=secrets, db=db,
    )
    cert_meta = renewer.cert_metadata()
    log_rows = list_acme_renewal_log(db, limit=20)
    # #81 -- listener restart pending chip. True when the operator hit
    # Save with a new tls.enabled value but the running uvicorn
    # listener is still on the old protocol. Persists across page
    # reloads (unlike the old query-param banner which evaporated
    # the second the operator clicked any internal link). Auto-
    # clears on the next process restart.
    from email_triage.web.app import is_listener_restart_pending
    listener_restart_pending = is_listener_restart_pending(request.app)
    boot_mode = getattr(request.app.state, "tls_boot_mode", None)
    return _render(request, "admin/acme_status.html", {
        "user": user,
        "config": config.tls.acme,
        "tls": config.tls,
        "rfc": config.tls.acme.rfc2136,
        "webauthn": config.webauthn,
        "auth": getattr(config, "auth", None),
        "cert_meta": cert_meta,
        "log_rows": log_rows,
        "cert_dir": cert_dir,
        "listener_restart_pending": listener_restart_pending,
        "listener_boot_mode": boot_mode,
    })


def _resolve_renewer(request: Request) -> acme_mod.AcmeRenewer:
    db = _get_db(request)
    config = _get_config(request)
    secrets = _get_secrets(request)
    cert_dir = (
        config.tls.cert_dir
        or str(getattr(request.app.state, "data_dir", "./data") + "/certs")
    )
    return acme_mod.AcmeRenewer(
        cfg=config.tls.acme, cert_dir=cert_dir,
        secrets_store=secrets, db=db,
    )


@router.post("/admin/acme-status/test/dns-reach", response_class=JSONResponse)
async def admin_acme_test_dns_reach(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    result = acme_mod.test_dns_reachability(config.tls.acme)
    return JSONResponse({
        "name": result.name, "ok": result.ok,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail, "error": result.error,
    })


@router.post("/admin/acme-status/test/tsig", response_class=JSONResponse)
async def admin_acme_test_tsig(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = secrets.get(config.tls.acme.rfc2136.tsig_secret_ref) or ""
    result = acme_mod.test_tsig_authentication(config.tls.acme, tsig)
    return JSONResponse({
        "name": result.name, "ok": result.ok,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail, "error": result.error,
    })


@router.post("/admin/acme-status/test/publish", response_class=JSONResponse)
async def admin_acme_test_publish(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = secrets.get(config.tls.acme.rfc2136.tsig_secret_ref) or ""
    result = acme_mod.test_publish_record(config.tls.acme, tsig)
    return JSONResponse({
        "name": result.name, "ok": result.ok,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail, "error": result.error,
    })


@router.post("/admin/acme-status/test/full-cycle", response_class=JSONResponse)
async def admin_acme_test_full_cycle(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = secrets.get(config.tls.acme.rfc2136.tsig_secret_ref) or ""
    result = acme_mod.test_full_dns01_cycle(config.tls.acme, tsig)
    return JSONResponse(result.to_dict())


@router.post("/admin/acme-status/save", response_class=HTMLResponse)
async def admin_acme_save(
    request: Request,
    enabled: str = Form("0"),
    directory_url: str = Form(""),
    account_email: str = Form(""),
    domains: str = Form(""),
    challenge: str = Form("dns-01"),
    renewal_threshold_days: str = Form("30"),
    check_interval_hours: str = Form("24"),
    pre_validation_grace_secs: str = Form("30"),
    validation_retries: str = Form("5"),
    validation_retry_delay_secs: str = Form("60"),
    caa_enforce: str = Form("0"),
    dns_provider: str = Form("rfc2136"),
    rfc_nameserver: str = Form(""),
    rfc_nameserver_port: str = Form("53"),
    rfc_tsig_key_name: str = Form(""),
    rfc_tsig_algorithm: str = Form("hmac-sha256"),
    rfc_tsig_secret_ref: str = Form("acme_tsig_secret"),
    rfc_update_zone: str = Form(""),
    rfc_tsig_secret_value: str = Form(""),
    rfc_public_resolvers: str = Form(""),
    rfc_public_propagation_timeout_secs: str = Form("1800"),
    rfc_public_propagation_interval_secs: str = Form("15"),
    webauthn_rp_id: str = Form(""),
    webauthn_rp_name: str = Form("Email Triage"),
    webauthn_origin: str = Form(""),
    tls_enabled: str = Form("0"),
    tls_cert_dir: str = Form(""),
):
    """Persist tls.acme + webauthn config from the admin UI.

    Edits the in-memory ``config`` AND writes back to YAML so the
    next process boot reads the same values. TSIG secret is written
    to the secrets store, never YAML.
    """
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)

    # Listener mode is an explicit operator decision now: form has its
    # own checkbox + cert_dir field. Stays decoupled from ACME enable,
    # so the operator can configure / test renewal without auto-flipping
    # the listener and breaking external HTTP probes.
    cert_dir_clean = (tls_cert_dir or "").strip()
    if cert_dir_clean:
        config.tls.cert_dir = cert_dir_clean
    # Server-side gate: refuse to enable HTTPS if there's no cert on
    # disk. Defense in depth — UI disables the checkbox in this state,
    # but a hand-crafted POST or a stale cached page must not be able
    # to flip the listener into a state where the bind fails.
    requested_https = (
        tls_enabled == "1" or tls_enabled == "on" or tls_enabled == "true"
    )
    # #81 -- listener mode flip detection. uvicorn doesn't switch
    # protocols mid-process; an http<->https flip writes to YAML +
    # in-memory config but the live socket is unchanged until the
    # service restarts. Capture pre-state so the redirect can surface
    # a "restart required" banner.
    pre_listener_https = bool(getattr(config.tls, "enabled", False))
    if requested_https:
        from pathlib import Path
        effective_cert_dir = (
            config.tls.cert_dir
            or str(getattr(request.app.state, "data_dir", "./data") + "/certs")
        )
        crt_path = Path(effective_cert_dir) / "server.crt"
        if not crt_path.exists():
            return RedirectResponse(
                "/admin/acme-status?err="
                "Cannot enable HTTPS: no server.crt on disk. "
                "Issue a cert (Issue Now) or place one at "
                f"{crt_path} first.",
                status_code=303,
            )
        config.tls.enabled = True
    else:
        config.tls.enabled = False
    listener_flipped = pre_listener_https != bool(config.tls.enabled)

    a = config.tls.acme
    a.enabled = (enabled == "1" or enabled == "on" or enabled == "true")
    a.directory_url = directory_url.strip() or a.directory_url
    a.account_email = account_email.strip()
    a.domains = [d.strip() for d in domains.split(",") if d.strip()]
    a.challenge = (challenge or "dns-01").strip()
    try:
        a.renewal_threshold_days = int(renewal_threshold_days)
    except (TypeError, ValueError):
        pass
    try:
        a.check_interval_hours = int(check_interval_hours)
    except (TypeError, ValueError):
        pass
    try:
        a.pre_validation_grace_secs = max(0, int(pre_validation_grace_secs))
    except (TypeError, ValueError):
        pass
    try:
        a.validation_retries = max(0, int(validation_retries))
    except (TypeError, ValueError):
        pass
    try:
        a.validation_retry_delay_secs = max(1, int(validation_retry_delay_secs))
    except (TypeError, ValueError):
        pass
    a.caa_enforce = (
        caa_enforce == "1" or caa_enforce == "on" or caa_enforce == "true"
    )
    a.dns_provider = (dns_provider or "rfc2136").strip()
    rfc = a.rfc2136
    rfc.nameserver = rfc_nameserver.strip()
    try:
        rfc.nameserver_port = int(rfc_nameserver_port)
    except (TypeError, ValueError):
        pass
    rfc.tsig_key_name = rfc_tsig_key_name.strip()
    rfc.tsig_algorithm = (rfc_tsig_algorithm or "hmac-sha256").strip()
    rfc.tsig_secret_ref = (rfc_tsig_secret_ref or "acme_tsig_secret").strip()
    rfc.update_zone = rfc_update_zone.strip()

    resolvers_raw = (rfc_public_resolvers or "").strip()
    if resolvers_raw:
        rfc.public_resolvers = [
            s.strip() for s in resolvers_raw.split(",") if s.strip()
        ] or ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    else:
        rfc.public_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    try:
        rfc.public_propagation_timeout_secs = max(
            60, int(rfc_public_propagation_timeout_secs)
        )
    except (TypeError, ValueError):
        pass
    try:
        rfc.public_propagation_interval_secs = max(
            2, int(rfc_public_propagation_interval_secs)
        )
    except (TypeError, ValueError):
        pass

    # If a TSIG secret value is supplied, write it into the secrets
    # store under the configured ref-key. Empty value leaves any
    # existing stored secret intact.
    if rfc_tsig_secret_value.strip():
        secrets.set(rfc.tsig_secret_ref, rfc_tsig_secret_value.strip())

    config.webauthn.rp_id = webauthn_rp_id.strip()
    config.webauthn.rp_name = (webauthn_rp_name or "Email Triage").strip()
    config.webauthn.origin = webauthn_origin.strip()

    # Persist to YAML.
    save_error = None
    try:
        from email_triage.web.routers.ui import _write_config_yaml
        _write_config_yaml(config)
    except Exception as e:
        save_error = f"Settings applied in memory but YAML write failed: {e}"
        log.error("ACME config YAML write failed", exc_info=e)

    log.info("ACME config saved", actor_user_id=user["id"],
             domains=a.domains, dns_provider=a.dns_provider,
             tsig_secret_set=bool(rfc_tsig_secret_value.strip()),
             listener_flipped=listener_flipped)

    # Return to the status page; query string surfaces a save flash.
    # (#81) -- the listener-flip restart prompt no longer rides the
    # query string. It now lives on the page itself via the persistent
    # ``listener_restart_pending`` chip rendered from
    # ``app.state.tls_boot_mode`` vs the saved value. The chip
    # survives page reloads + nav-away-and-back without depending
    # on a redirect param.
    if save_error:
        qs = f"err={save_error[:100]}"
    else:
        qs = "saved=1"
    return RedirectResponse(f"/admin/acme-status?{qs}", status_code=303)


@router.post("/admin/acme-status/issue", response_class=JSONResponse)
async def admin_acme_issue_now(
    request: Request,
    directory: str = Form("staging"),
):
    """Manually trigger a cert issuance.

    ``directory`` ∈ {'staging', 'production'} — UI button is two
    explicit options so a single click can't accidentally hit prod
    and burn the LE production rate limit (5 certs / week / domain).
    """
    user, err = _require_admin(request)
    if err:
        return err
    config = _get_config(request)
    if directory == "production":
        directory_url = config.tls.acme.directory_url
    else:
        directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    renewer = _resolve_renewer(request)
    from email_triage.single_flight import SingleFlightBusy
    try:
        # PR 4 / B1 — single-flight guarded so a manual click during
        # the 24h tick can't double-order.
        meta = await renewer.issue_now_async(directory_url=directory_url)
        return JSONResponse({
            "ok": True, "directory": directory, "cert": meta,
        })
    except SingleFlightBusy as e:
        return JSONResponse({
            "ok": False,
            "error": (
                "Issuance already in progress. The 24h background "
                "tick or another admin click is mid-flight; retry "
                "after it completes (worst case: a few minutes)."
            ),
        }, status_code=409, headers=e.headers)
    except Exception as e:
        log.error("ACME manual issue failed", exc_info=e,
                  directory=directory)
        return JSONResponse({
            "ok": False, "error": f"{type(e).__name__}: {e}",
        }, status_code=500)


@router.post("/admin/acme-status/cancel", response_class=JSONResponse)
async def admin_acme_cancel(request: Request):
    """Operator-driven cancel for an in-flight ACME issuance.

    Punch-list #103. Flips ``cancel_requested=1`` on the
    ``acme_jobs`` row; the worker thread checks the flag at each
    retry-loop boundary and transitions to the ``cancelled``
    terminal phase via ``finish_failure(kind="cancelled")``.

    Idempotent: cancelling an already-cancelled or terminal job is
    a no-op (returns ok=true with cancelled=false).

    Admin-only. The persisted row tracks ``actor_user_id`` (who
    started the issuance); the cancel endpoint requires admin role
    so any admin can abort -- matching how triage_jobs cancel
    delegates to the manage-account check (admin or owner).
    """
    user, err = _require_admin(request)
    if err:
        return err
    from email_triage.web import acme_job_state
    job_id_form = None
    try:
        form = await request.form()
        job_id_form = form.get("job_id")
    except Exception:
        job_id_form = None
    snap = acme_job_state.current_state()
    job_id = job_id_form or snap.get("job_id")
    flipped = acme_job_state.request_cancel(job_id)
    return JSONResponse({
        "ok": True,
        "cancelled": flipped,
        "job_id": job_id,
        "phase": acme_job_state.current_state().get("phase"),
    })


@router.get("/admin/acme-status/job", response_class=JSONResponse)
async def admin_acme_job_status(request: Request):
    """Return the current ACME issuance job state for live re-attach.

    #75 -- the page polls this endpoint on load (and every few seconds
    while a job is in flight) so a refresh / nav-away-and-back doesn't
    lose the live timer. State lives in process memory only; a worker-
    thread restart abandons both the cert and the view, so no stronger
    persistence is needed.

    Returns a JSON dict with phase, attempt counts, started_at,
    elapsed_secs, last_error, per-domain visibility map. ``in_flight``
    is the simple polling-stop signal -- when False, the page can
    stop polling and render the terminal state once.
    """
    user, err = _require_admin(request)
    if err:
        return err
    from email_triage.web import acme_job_state
    return JSONResponse(acme_job_state.current_state())


@router.post("/admin/system/restart", response_class=HTMLResponse)
async def admin_system_restart(request: Request):
    """Exit the running process so systemd respawns the container.

    #81 -- listener-mode flips don't take effect until the uvicorn
    process restarts; this endpoint gives the operator a one-click
    way to trigger that without ssh-ing to the host.

    Admin-only. Schedules a delayed exit (5s) so the response can
    flush back to the operator's browser before the process dies.
    Relies on systemd Restart=always (or equivalent) -- if the unit
    isn't configured for auto-respawn, the operator will need to
    start it manually.

    Audit: writes an auth_events row before the timer fires so the
    intent is captured even if the restart somehow doesn't recover.
    """
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    client_host = (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db, event_type="system_restart", email=user.get("email", ""),
            user_id=user["id"], ip=client_host, user_agent=user_agent,
            outcome="success",
            detail="admin-initiated restart via /admin/system/restart",
        )
    except Exception:
        pass

    log.warning(
        "Admin-initiated process restart", actor_user_id=user["id"],
    )

    # Schedule the exit on a thread so this handler can return its
    # response. 5s gives the redirect + browser render time to land
    # before the socket goes away.
    import threading
    import os
    import time as _time

    def _exit_after_grace() -> None:
        _time.sleep(5)
        # os._exit skips atexit handlers; that's intentional -- we
        # want a hard process replace, not a graceful shutdown that
        # might hang on in-flight requests.
        os._exit(0)

    threading.Thread(
        target=_exit_after_grace, daemon=True, name="admin-restart-grace",
    ).start()

    # Return a small holding page so the operator sees confirmation.
    # Page auto-refreshes after 12s -- by that time the new process
    # should be back up if systemd is configured correctly.
    return HTMLResponse(
        """<!DOCTYPE html>
<html><head>
  <title>Restarting — Email Triage</title>
  <meta http-equiv="refresh" content="12;url=/admin/acme-status">
  <style>
    body { font-family: system-ui, sans-serif; padding: 2rem;
           max-width: 36rem; margin: 0 auto; }
    h2 { color: #b45309; }
  </style>
</head><body>
  <h2>Restarting…</h2>
  <p>The service has been asked to exit; systemd will respawn it
     within ~5 seconds. This page will reload in 12 seconds.</p>
  <p>If the page does not come back, run on the host:</p>
  <pre>sudo systemctl restart email-triage</pre>
  <p>(If the unit is not configured for Restart=always, the service
     stayed down and needs an explicit start.)</p>
</body></html>""",
        status_code=200,
    )
