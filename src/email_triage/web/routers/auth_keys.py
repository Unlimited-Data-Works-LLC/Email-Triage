"""Auth-surface routes: dev-keypair admin + login,
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
  user with a registered passkey; OTP remains the fallback.
* ``/profile/hardware-keys`` (per-user): self-service WebAuthn
  registration + revoke.

Security gates per route are documented inline. The
``hardware-key-wins`` rule (dev-keypair logins are denied for any
user with at least one active hardware_keys row) is enforced
server-side at ``/login/dev-keypair`` verify time.
"""

from __future__ import annotations

from email_triage.secrets import read_secret

import base64
import json
import secrets as _secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from email_triage._isotime import now_utc_iso, to_utc_iso
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from email_triage.web.error_html import error_chip
from email_triage.web.routers._redirect import err_qs
from email_triage._envbool import parse_bool

from email_triage.triage_logging import get_logger
from email_triage.web.auth import (
    SESSION_MAX_AGE,
    create_session_token,
    get_user_by_email,
    set_session_cookie,
    update_last_login,
)
from email_triage.web.dependencies import (  # N-222d R22 + N-337 (audit-XFF)
    audit_forwarded_for,
    get_current_user,
    is_admin,
    request_meta,
)
from email_triage.web.routers._json import parse_json_body  # N-233 R22 JSON body SSOT
from email_triage.web.error_surface import api_error_response  #  tranche 2 R32
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
from email_triage.web.db_threadpool import db_call
from email_triage.web._audit import safe_audit_write, safe_audit_write_async
from email_triage._errfmt import fmt_exc, scrub_class_error_for_persist, scrub_error_for_persist
from email_triage._int_utils import bounded_int  # N-219c/5 R23


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


async def _render(request: Request, name: str, context: dict[str, Any] | None = None):
    """Wrapper matching ui.py's `_render` semantics: injects user +
    hipaa_mode template globals so base templates render
    consistently.

     / Option B — ``async`` because the shared ``_render`` it
    delegates to is async (auto-injected admin banners read the
    shared connection off-loop). Callers ``await`` the wrapper.
    """
    from email_triage.web.routers.ui import _render as _render_ui
    return await _render_ui(_get_templates(request), request, name, context or {})


def _allowed_webauthn_origins(request: Request, config) -> list[str]:
    """Return the list of origins acceptable for WebAuthn verify.

    The browser sends the literal ``scheme://host[:port]`` it loaded the
    page from in ``clientDataJSON.origin``; the verify call must accept
    that exact string. A static config field can't cover all of:

      * Direct listener on a non-default port (``:8080``)
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


# Census 2026-06-09 #3: byte-identical UI admin gate → the dependencies SSOT.
from email_triage.web.dependencies import require_admin_ui as _require_admin
from email_triage._secret_keys import SESSION_SECRET_KEY  # N-231 R22 stored-secret-key SSOT


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
    user, err = await db_call(_require_admin, request)
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
    now_iso = now_utc_iso()
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
        # N-219c/38 R23: bounded_int SSOT — default=user["id"] on non-numeric.
        candidate = bounded_int(raw_filter, default=user["id"]) if raw_filter else user["id"]
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    db = _get_db(request)

    # Parse + validate the public key.
    try:
        parsed = dk.parse_ssh_ed25519_pubkey(public_key)
    except dk.DevKeyParseError as e:
        return HTMLResponse(
            error_chip(e, prefix='Invalid key: '),
            status_code=400,
        )
    fp = dk.fingerprint(parsed)

    # TTL → expires_at.
    ttl_map = {"1d": 1, "1w": 7, "2w": 14}
    days = ttl_map.get(ttl, 7)
    expires_at = to_utc_iso(
        datetime.now(timezone.utc) + timedelta(days=days)
    )

    # Email allowlist. Validate every email matches a real user — keeps
    # admin from typo'ing an address that nobody can actually use.
    from email_triage.mail_headers import canonical_email  # N-346 partial 5 R31
    emails = [canonical_email(e) for e in email_allowlist.split(",") if e.strip()]
    if not emails:
        return HTMLResponse(
            '<small style="color:var(--pico-del-color);">'
            'Email allowlist required (comma-separated).</small>',
            status_code=400,
        )

    def _validate_and_add(db, emails, name, public_key, fp, user_id, expires_at):
        # ASYNC-DB: allowlist-email validation + dev-key insert in
        # one off-loop hop.
        for em in emails:
            if get_user_by_email(db, em) is None:
                return "bad_email", em
        try:
            new_id_ = db_add_dev_key(
                db, name=name, public_key=public_key,
                fingerprint=fp, email_allowlist=emails,
                created_by_user_id=user_id, expires_at=expires_at,
            )
        except sqlite3.IntegrityError:
            return "dup", None
        return "ok", new_id_

    outcome, payload = await db_call(
        _validate_and_add, db, emails, name, public_key.strip(),
        fp, user["id"], expires_at,
    )
    if outcome == "bad_email":
        # N-83: payload is a form-submitted allowlist email; repr() escapes
        # quotes but NOT angle brackets (the N-68 mechanism) — a crafted
        # email with <script>/<img onerror> would reflect into this admin
        # PHI-session response. Escape the repr so angle brackets/quotes are
        # neutralised while keeping the readable quoting.
        import html as _html
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f"Allowlist email {_html.escape(repr(payload))} "
            f"doesn't match a known user.</small>",
            status_code=400,
        )
    if outcome == "dup":
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f'Fingerprint already registered: {_html.escape(str(fp))}. '
            f'Revoke the existing entry first.</small>',
            status_code=409,
        )
    new_id = payload

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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    db = _get_db(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))

    def _revoke_dev_key(db, key_id, actor):
        # ASYNC-DB: revoke + HMAC audit-event in one off-loop hop.
        if not db_revoke_dev_key(db, key_id, actor["id"]):
            return False
        # N-121 — credential revocation is an access-termination event
        # (§164.312(b)+(c)(1)). Record it on the tamper-evident audit chain,
        # not just the structured log. Degraded-but-proceed on an audit-write
        # failure (the @audit_emitter gap-event durably records the miss).
        from email_triage.web.db import record_auth_event
        safe_audit_write(
            lambda: record_auth_event(
                db, event_type="dev_key_revoked",
                email=actor.get("email") or "", user_id=actor["id"],
                key_id=key_id, ip=client_host, outcome="success",
                detail="admin revoke",
            ),
            description=f"dev_key_revoked key_id={key_id}",
        )
        return True

    ok = await db_call(_revoke_dev_key, db, key_id, user)
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
    #  tail — route through the `_base64url` SSOT.
    from email_triage._base64url import b64encode_urlsafe
    challenge_b64 = b64encode_urlsafe(challenge, strip_padding=True).decode("ascii")
    response = await _render(request, "login_dev_keypair.html", {
        "challenge": challenge_b64,
    })
    # N-197 R21_3: derive Secure flag from EITHER the request's URL scheme
    # (set by Starlette from X-Forwarded-Proto when ProxyHeadersMiddleware
    # is wired — the reverse-proxy + plain-HTTP-upstream common case) OR
    # config.tls.enabled (direct-TLS case). DA must-fix (2026-07-02): the
    # config.tls.enabled-alone signal misses the nginx→uvicorn HTTPS
    # termination topology. Fall-closed default: if either signal says
    # HTTPS, mark Secure. Pre-fix hardcoded `secure=False` shipped the
    # dev-keypair challenge cookie un-Secure on prod HTTPS — a same-site
    # downgrade attack could read it.
    config = _get_config(request)
    # N-383 R32 (2026-07-10 post-deploy census wf_69674c7e-c67): route
    # Secure via the SSOT `_cookies.is_request_https`. The prior inline
    # formula `(scheme == "https") or bool(config.tls.enabled)` byte-mirrored
    # the SSOT logic but bypassed it — a copy on the anti-drift surface,
    # AND invisible to the N-200 pin due to a module-scope `ssot_names`
    # walk that collided with line 931's own `https = is_request_https(...)`
    # assign (fixed same-commit).
    from email_triage.web._cookies import is_request_https
    https = is_request_https(request, config)
    response.set_cookie(
        _DEV_KEYPAIR_CHALLENGE_COOKIE, challenge_b64,
        max_age=_DEV_KEYPAIR_CHALLENGE_TTL,
        httponly=True, samesite="lax", secure=https,
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

     — login_guard runs FIRST so a brute-force attacker can't
    use the signature-verify side-channel for fingerprint /
    public-key oracle queries. Per-email + per-ip counters are
    shared with the OTP and WebAuthn surfaces — a sustained
    brute-force across multiple surfaces against the same
    email/IP still trips the gate.
    """
    db = _get_db(request)
    config = _get_config(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    def _lockout_gate(db, email, client_host, config, user_agent):
        # ASYNC-DB: lockout-counter read + (on lock) lockout write
        # in one off-loop hop.
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
            return None
        except LoginLocked as locked_:
            record_login_lockout(
                db, surface="dev_keypair", email=email, ip=client_host,
                user_agent=user_agent, scope=locked_.scope,
                threshold=locked_.retry_after_secs,
            )
            return locked_

    locked = await db_call(
        _lockout_gate, db, email, client_host, config, user_agent,
    )
    if locked is not None:
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
    #  tail — route pad-restore + decode through the `_base64url` SSOT
    # at all 3 hand-rolled sites in this handler.
    from email_triage._base64url import b64decode_permissive
    try:
        challenge = b64decode_permissive(challenge_b64, urlsafe=True)
    except Exception:
        return HTMLResponse("Invalid challenge cookie.", status_code=400)

    # Parse signature (operator sends url-safe base64).
    try:
        sig_bytes = b64decode_permissive(signature, urlsafe=True)
    except Exception:
        return HTMLResponse("Invalid signature encoding.", status_code=400)

    # Resolve fingerprint: operator may supply it directly OR pass
    # the raw public key (browser path that can't compute SHA-256).
    if not fingerprint and public_key:
        try:
            pub_bytes = b64decode_permissive(public_key, urlsafe=True)
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

    # ASYNC-DB: the whole dev-keypair verify — key lookup, all
    # validation reads, every failure-record write, the success-path
    # mark_dev_key_used + record_auth_event — runs in ONE off-loop hop.
    # The signature crypto (parse/verify) is short pure-CPU work and is
    # included so the handler never bounces between loop and threadpool
    # mid-verify.
    # N-253 R25: canonical-email SSOT.
    from email_triage.mail_headers import canonical_email
    email_l = canonical_email(email)
    client_ip = audit_forwarded_for(request).host  # N-337: XFF-aware SSOT (§164.312(b))

    def _verify_dev_keypair(db):
        from email_triage.web.db import record_auth_event
        row = find_dev_key_by_fingerprint(db, fingerprint)
        if row is None:
            record_login_failure(
                db, surface="dev_keypair", email=email, ip=client_host,
                user_agent=user_agent, reason="unknown_fingerprint",
            )
            return ("unknown_fingerprint", None, None)
        now_iso_ = now_utc_iso()
        if not is_dev_key_active(row, now_iso_):
            record_login_failure(
                db, surface="dev_keypair", email=email, ip=client_host,
                user_agent=user_agent, reason="key_inactive",
                key_id=row["id"],
            )
            return ("key_inactive", row, None)
        #  R32 — canonical_email on BOTH sides so an IDN allowlist entry
        # matches an IDN input; stored form is already canonical (line 292)
        # so this is defensive symmetric normalisation at the compare point.
        if email_l not in [canonical_email(e) for e in row.get("email_allowlist", [])]:
            record_login_failure(
                db, surface="dev_keypair", email=email_l, ip=client_host,
                user_agent=user_agent, reason="email_not_in_allowlist",
                key_id=row["id"],
            )
            return ("email_not_in_allowlist", row, None)
        user_ = get_user_by_email(db, email_l)
        if user_ is None:
            record_login_failure(
                db, surface="dev_keypair", email=email_l, ip=client_host,
                user_agent=user_agent, reason="account_not_found",
            )
            return ("account_not_found", row, None)
        if user_.get("disabled"):
            record_login_failure(
                db, surface="dev_keypair", email=email_l, ip=client_host,
                user_agent=user_agent, reason="account_disabled",
                user_id=user_["id"],
            )
            return ("account_disabled", row, user_)
        if user_has_active_hardware_key(db, user_["id"]):
            record_login_failure(
                db, surface="dev_keypair", email=email_l, ip=client_host,
                user_agent=user_agent, reason="hardware_key_required",
                user_id=user_["id"], key_id=row["id"],
            )
            return ("hardware_key_required", row, user_)
        # Verify signature against challenge (pure-CPU; kept in the
        # worker so the verify is one atomic off-loop unit).
        try:
            parsed_ = dk.parse_ssh_ed25519_pubkey(row["public_key"])
        except dk.DevKeyParseError:
            return ("parse_error", row, user_)
        if not dk.verify_signature(parsed_, challenge, sig_bytes):
            record_login_failure(
                db, surface="dev_keypair", email=email_l, ip=client_host,
                user_agent=user_agent, reason="signature_invalid",
                user_id=user_["id"], key_id=row["id"],
            )
            return ("signature_invalid", row, user_)
        # All checks pass: stamp last_used_at + append-only audit row.
        mark_dev_key_used(db, row["id"], email=email_l, ip=client_ip)
        # FIX C — stamp last_login on every successful-login terminus (PD#18
        # observability: dev_keypair was the only surface missing the stamp;
        # WebAuthn/passkey/recovery paths are fixed in their own closures below).
        try:
            update_last_login(db, email_l)
        except Exception:
            pass
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_dev_keypair",
                email=email_l,
                user_id=user_["id"],
                key_id=row["id"],
                ip=client_ip or None,
                user_agent=user_agent,
                outcome="success",
            ),
            description=f"login_dev_keypair user_id={user_['id']} key_id={row['id']}",
        )
        return ("ok", row, user_)

    outcome, row, user = await db_call(_verify_dev_keypair, db)
    if outcome == "unknown_fingerprint":
        log.warning(
            "Dev-keypair login: unknown fingerprint",
            fingerprint=fingerprint, email=email,
        )
        return HTMLResponse("Unknown or revoked key.", status_code=403)
    if outcome == "key_inactive":
        log.warning(
            "Dev-keypair login: key inactive",
            key_id=row["id"], email=email,
            revoked_at=row.get("revoked_at"),
            expires_at=row.get("expires_at"),
        )
        return HTMLResponse("Key is revoked or expired.", status_code=403)
    if outcome == "email_not_in_allowlist":
        log.warning(
            "Dev-keypair login: email not in allowlist",
            key_id=row["id"], email=email_l,
        )
        return HTMLResponse(
            "This key is not allowlisted for that email.",
            status_code=403,
        )
    if outcome == "account_not_found":
        return HTMLResponse("Account not found.", status_code=404)
    if outcome == "account_disabled":
        return HTMLResponse("Account disabled.", status_code=403)
    if outcome == "hardware_key_required":
        log.info(
            "Dev-keypair login refused: passkey registered",
            email=email_l, user_id=user["id"], key_id=row["id"],
        )
        return HTMLResponse(
            "This account has a passkey registered. Use your "
            "passkey or OTP fallback to log in.",
            status_code=403,
        )
    if outcome == "parse_error":
        log.error(
            "Dev-keypair login: stored public_key unparseable",
            key_id=row["id"],
        )
        return HTMLResponse("Server-side key parse error.", status_code=500)
    if outcome == "signature_invalid":
        log.warning(
            "Dev-keypair login: signature invalid",
            key_id=row["id"], email=email_l,
        )
        return HTMLResponse("Invalid signature.", status_code=403)

    # PR 10 / E — success-edge metric via the shared funnel (record_login_success).
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="dev_keypair")
    from email_triage.web.dependencies import get_session_secret
    secret = get_session_secret(request)
    token = create_session_token(
        secret, user["email"], user["role"],
        auth_source="dev_keypair", auth_key_id=row["id"],
        session_epoch=int(user.get("session_epoch", 0)),
    )
    log.info(
        "Dev-keypair login successful",
        key_id=row["id"], user_id=user["id"], email=email_l,
        client_ip=client_ip,
    )
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, token, request.app.state.config, request=request)
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

    def _begin(db, email, config):
        # ASYNC-DB: user lookup + hardware-key check + challenge
        # store in one off-loop hop.
        # N-253 R25: canonical-email SSOT.
        from email_triage.mail_headers import canonical_email
        user_ = get_user_by_email(db, canonical_email(email))
        if user_ is None or user_.get("disabled"):
            return ("no_credential", None)
        if not user_has_active_hardware_key(db, user_["id"]):
            return ("no_credential", None)
        try:
            opts_json_ = wa.begin_authentication(
                db,
                user_id=user_["id"],
                email=user_["email"],
                rp_id=config.webauthn.rp_id,
                require_user_verification=(
                    config.webauthn.require_user_verification_for_admin
                    and user_.get("role") == "admin"
                ),
            )
        except wa.WebAuthnConfigError as e_:
            return ("config_error", fmt_exc(e_))
        except wa.WebAuthnAuthError as e_:
            return ("auth_error", fmt_exc(e_))
        return ("ok", opts_json_)

    outcome, payload = await db_call(_begin, db, email, config)
    if outcome == "no_credential":
        # Don't leak account existence — generic error.
        return api_error_response("no_credential", status_code=404, purpose="misc")
    if outcome == "config_error":
        return api_error_response(payload, status_code=503, purpose="auth")
    if outcome == "auth_error":
        return api_error_response(payload, status_code=400, purpose="auth")
    return JSONResponse(json.loads(payload))


@router.post("/login/webauthn/finish", response_class=JSONResponse)
async def login_webauthn_finish(request: Request):
    """Step 2 of WebAuthn login: verify assertion + mint session.

     — login_guard runs before assertion verify so brute-force
    against the assertion path is throttled identically to the
    OTP + dev-keypair surfaces.
    """
    db = _get_db(request)
    config = _get_config(request)
    body = await parse_json_body(request)  # N-233 R22 SSOT (400 on malformed, not 500)
    #  R32 (census wf_56d1585d 2026-07-09) — §164.312(a)(1) authenticator
    # input MUST canonicalise (stdlib IDNA-2003 + lowercase; see mail_headers.py:249),
    # not just .strip().lower()
    # — otherwise an IDN alias (`user@münchen.de`) fails to match the canonical
    # form stored at ingest (line 292 pattern) and legit users can't log in.
    from email_triage.mail_headers import canonical_email
    email = canonical_email(body.get("email") or "")
    response_data = body.get("response")
    if not email or not response_data:
        return api_error_response("bad_request", status_code=400, purpose="misc")
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  lockout gate.
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
    # Pure (config + request headers, no DB) — compute before the hop.
    allowed_origins = _allowed_webauthn_origins(request, config)

    # ASYNC-DB: lockout gate + user lookup + assertion verify +
    # failure/success writes, all in ONE off-loop hop.
    def _verify_webauthn(db):
        from email_triage.web.db import record_auth_event
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked_:
            record_login_lockout(
                db, surface="webauthn", email=email, ip=client_host,
                user_agent=user_agent, scope=locked_.scope,
                threshold=locked_.retry_after_secs,
            )
            return ("locked", locked_.retry_after_secs, None, None)
        user_ = get_user_by_email(db, email)
        if user_ is None or user_.get("disabled"):
            # Don't leak account state — generic error AND a failure
            # row so the rate-limiter still counts the probe.
            record_login_failure(
                db, surface="webauthn", email=email, ip=client_host,
                user_agent=user_agent,
                reason="no_account_or_disabled",
            )
            return ("no_credential", None, None, None)
        try:
            key_id_ = wa.finish_authentication(
                db,
                user_id=user_["id"],
                rp_id=config.webauthn.rp_id,
                origin=allowed_origins,
                response_json=response_data,
            )
        except wa.WebAuthnAuthError as e_:
            record_login_failure(
                db, surface="webauthn", email=email, ip=client_host,
                user_agent=user_agent, reason="verify_failed",
                user_id=user_["id"],
            )
            return ("verify_failed", fmt_exc(e_), user_, None)
        # PR 9 / D4 — append-only audit. WebAuthn finish_authentication
        # already updates hardware_keys.last_used_at internally; this
        # row preserves history.
        # FIX C — stamp last_login at the WebAuthn success terminus.
        try:
            update_last_login(db, user_["email"])
        except Exception:
            pass
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_webauthn",
                email=email,
                user_id=user_["id"],
                key_id=key_id_,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
            ),
            description=f"login_webauthn user_id={user_['id']} key_id={key_id_}",
        )
        return ("ok", None, user_, key_id_)

    outcome, extra, user, key_id = await db_call(_verify_webauthn, db)
    if outcome == "locked":
        return JSONResponse(
            {"error": "rate_limited", "retry_after_secs": extra},
            status_code=429,
            headers={"Retry-After": str(extra)},
        )
    if outcome == "no_credential":
        return api_error_response("no_credential", status_code=404, purpose="misc")
    if outcome == "verify_failed":
        log.warning("WebAuthn login: assertion verify failed",
                    email=email, error=extra)
        return api_error_response("verify_failed", status_code=403, purpose="misc")
    # PR 10 / E — success-edge metric via the shared funnel (record_login_success).
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="webauthn")
    from email_triage.web.dependencies import get_session_secret
    from email_triage.web.mfa import mfa_verified_now
    secret = get_session_secret(request)
    # H-05 (Cycle 7) — WebAuthn login stamps mfa_verified_at so the
    # HIPAA-mode hard-cutover middleware accepts the session without
    # forcing a step-up.
    token = create_session_token(
        secret, user["email"], user["role"],
        auth_source="webauthn", auth_key_id=key_id,
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_now(),
    )
    response = JSONResponse({"ok": True, "redirect": "/dashboard"})
    set_session_cookie(response, token, request.app.state.config, request=request)
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
    secret = getattr(request.app.state, SESSION_SECRET_KEY, "") or ""
    if not secret:
        return JSONResponse(
            {"error": "csrf_unconfigured"}, status_code=500,
        )
    s = URLSafeSerializer(secret, salt="email-triage-passkey-challenge")
    cookie_val = s.dumps(_b64.urlsafe_b64encode(challenge).decode("ascii"))
    # N-200 R22 (2026-07-02): route Secure via the _cookies SSOT (nginx-front topology).
    from email_triage.web._cookies import is_request_https
    https = is_request_https(request, config)
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

     — IP-only guard (passkey doesn't carry email upfront).
    The per-email guard fires later if user resolution succeeds
    AND the assertion fails.
    """
    db = _get_db(request)
    config = _get_config(request)
    body = await parse_json_body(request)  # N-233 R22 SSOT (400 on malformed, not 500)
    response_data = body.get("response")
    if not response_data:
        return api_error_response("bad_request", status_code=400, purpose="misc")
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    #  IP-only lockout gate (no email yet at this point).
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )

    def _passkey_lockout_gate(db):
        # ASYNC-DB: lockout-counter read + (on lock) write off-loop.
        try:
            check_login_allowed(
                db, email=None, ip=client_host, config=config,
            )
            return None
        except LoginLocked as locked_:
            record_login_lockout(
                db, surface="passkey", email=None, ip=client_host,
                user_agent=user_agent, scope=locked_.scope,
                threshold=locked_.retry_after_secs,
            )
            return locked_

    locked = await db_call(_passkey_lockout_gate, db)
    if locked is not None:
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
    secret = getattr(request.app.state, SESSION_SECRET_KEY, "") or ""
    s = URLSafeSerializer(secret, salt="email-triage-passkey-challenge")
    try:
        challenge_b64 = s.loads(cookie_val)
        challenge = _b64.urlsafe_b64decode(challenge_b64)
    except (BadSignature, ValueError, Exception):
        return JSONResponse(
            {"error": "challenge_invalid"}, status_code=400,
        )

    # Pure (config + request headers, no DB) — compute before the hop.
    allowed_origins = _allowed_webauthn_origins(request, config)

    # ASYNC-DB: passkey assertion verify + user resolution +
    # failure/success writes, all in ONE off-loop hop.
    def _verify_passkey(db):
        from email_triage.web.db import record_auth_event
        try:
            user_id_, key_id_ = wa.finish_passkey_authentication(
                db,
                rp_id=config.webauthn.rp_id,
                origin=allowed_origins,
                response_json=response_data,
                challenge=challenge,
            )
        except wa.WebAuthnAuthError as e_:
            record_login_failure(
                db, surface="passkey", email=None, ip=client_host,
                user_agent=user_agent, reason="verify_failed",
            )
            return ("verify_failed", fmt_exc(e_), None, None)
        # Look up the resolved user. No dedicated by-id helper exists;
        # one-line query is fine.
        row_ = db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id_,),
        ).fetchone()
        user_ = dict(row_) if row_ else None
        if user_ is None or user_.get("disabled"):
            record_login_failure(
                db, surface="passkey",
                email=(row_["email"] if row_ else None),
                ip=client_host, user_agent=user_agent,
                reason="user_inactive",
                user_id=user_id_, key_id=key_id_,
            )
            return ("user_inactive", None, user_, key_id_)
        # Append-only audit (mirrors the existing webauthn login site).
        # FIX C — stamp last_login at the passkey success terminus.
        try:
            update_last_login(db, user_["email"])
        except Exception:
            pass
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_webauthn",
                email=user_["email"],
                user_id=user_["id"],
                key_id=key_id_,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
                detail="passkey",
            ),
            description=f"login_webauthn passkey user_id={user_['id']} key_id={key_id_}",
        )
        return ("ok", None, user_, key_id_)

    outcome, extra, user, key_id = await db_call(_verify_passkey, db)
    if outcome == "verify_failed":
        log.warning(
            "Passkey login: assertion verify failed", error=extra,
        )
        return api_error_response("verify_failed", status_code=403, purpose="misc")
    if outcome == "user_inactive":
        return api_error_response("user_inactive", status_code=403, purpose="misc")

    # PR 10 / E — success-edge metric via the shared funnel (record_login_success).
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="passkey")

    from email_triage.web.dependencies import get_session_secret
    from email_triage.web.mfa import mfa_verified_now
    sess_secret = get_session_secret(request)
    # H-05 (Cycle 7) — passkey login stamps mfa_verified_at so the
    # HIPAA-mode hard-cutover middleware accepts the session.
    token = create_session_token(
        sess_secret, user["email"], user["role"],
        auth_source="webauthn", auth_key_id=key_id,
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_now(),
    )
    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    set_session_cookie(resp, token, request.app.state.config, request=request)
    resp.delete_cookie(_PASSKEY_CHALLENGE_COOKIE)
    log.info(
        "Passkey login successful",
        user_id=user["id"], email=user["email"], key_id=key_id,
    )
    return resp


# ---------------------------------------------------------------------------
# /profile/hardware-keys — per-user self-service
# ---------------------------------------------------------------------------

@router.get("/profile/hardware-keys")
async def profile_hardware_keys_page(request: Request):
    """Legacy URL — Passkeys folded into the consolidated Security
    tab (2026-06-07). 303-redirect to /profile/security so bookmarks,
    the admin "Open /profile/hardware-keys" buttons, and the HIPAA-mode
    enrollment path keep resolving.

    The login gate runs first (anonymous → /login), preserving the
    pre-consolidation auth-gate contract before the redirect fires. The
    ``?owner_filter=`` admin filter is forwarded so a filtered deep link
    survives the bounce. The register/revoke action endpoints below stay
    put — the Register/Revoke controls on the Security page target them.
    """
    user, err = await db_call(_require_login, request)
    if err:
        return err
    raw_filter = (request.query_params.get("owner_filter") or "").strip()
    target = "/profile/security"
    if raw_filter:
        from urllib.parse import urlencode
        target = f"{target}?{urlencode({'owner_filter': raw_filter})}"
    return RedirectResponse(target, status_code=303)


@router.post("/profile/hardware-keys/register/begin", response_class=JSONResponse)
async def profile_hw_register_begin(request: Request):
    user, err = await db_call(_require_login, request)
    if err:
        return err
    db = _get_db(request)
    config = _get_config(request)

    def _begin_reg(db):
        # ASYNC-DB: WebAuthn registration-begin (challenge store)
        # off the loop.
        try:
            return ("ok", wa.begin_registration(
                db, user=user,
                rp_id=config.webauthn.rp_id,
                rp_name=config.webauthn.rp_name,
                require_user_verification=(
                    config.webauthn.require_user_verification_for_admin
                    and is_admin(user)  # N-222d R22
                ),
            ))
        except wa.WebAuthnConfigError as e_:
            return ("config_error", fmt_exc(e_))

    outcome, payload = await db_call(_begin_reg, db)
    if outcome == "config_error":
        return api_error_response(payload, status_code=503, purpose="auth")
    return JSONResponse(json.loads(payload))


@router.post("/profile/hardware-keys/register/finish", response_class=JSONResponse)
async def profile_hw_register_finish(request: Request):
    user, err = await db_call(_require_login, request)
    if err:
        return err
    db = _get_db(request)
    config = _get_config(request)
    body = await parse_json_body(request)  # N-233 R22 SSOT (400 on malformed, not 500)
    nickname = (body.get("nickname") or "").strip()
    response_data = body.get("response")
    if not nickname or not response_data:
        return api_error_response("bad_request", status_code=400, purpose="misc")
    allowed_origins = _allowed_webauthn_origins(request, config)

    def _finish_reg(db):
        # ASYNC-DB: WebAuthn registration-finish (verify + key
        # insert) off the loop.
        try:
            return ("ok", wa.finish_registration(
                db, user=user,
                rp_id=config.webauthn.rp_id,
                origin=allowed_origins,
                response_json=response_data, nickname=nickname,
            ))
        except wa.WebAuthnAuthError as e_:
            return ("verify_failed", fmt_exc(e_))

    outcome, payload = await db_call(_finish_reg, db)
    if outcome == "verify_failed":
        log.warning("WebAuthn register: verify failed",
                    user_id=user["id"], error=payload)
        return api_error_response("verify_failed", status_code=400, purpose="misc")
    new_id = payload
    log.info(
        "Passkey registered",
        user_id=user["id"], key_id=new_id, nickname=nickname,
    )
    return JSONResponse({"ok": True, "key_id": new_id})


@router.post("/profile/hardware-keys/{key_id}/revoke", response_class=HTMLResponse)
async def profile_hw_revoke(request: Request, key_id: int):
    user, err = await db_call(_require_login, request)
    if err:
        return err
    db = _get_db(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))

    def _revoke_hw_key(db, actor, key_id):
        # ASYNC-DB: ownership read + key revoke + HMAC audit in one hop.
        # Verify the key belongs to this user before revoking.
        rows = list_hardware_keys(db, actor["id"], include_revoked=True)
        if not any(r["id"] == key_id for r in rows):
            return "not_found"
        if not db_revoke_hardware_key(db, key_id):
            return "noop"
        # N-121 — record the access-termination event on the tamper-evident
        # audit chain (§164.312(b)+(c)(1)), degraded-but-proceed on failure.
        from email_triage.web.db import record_auth_event
        safe_audit_write(
            lambda: record_auth_event(
                db, event_type="hardware_key_revoked",
                email=actor.get("email") or "", user_id=actor["id"],
                key_id=key_id, ip=client_host, outcome="success",
            ),
            description=f"hardware_key_revoked key_id={key_id}",
        )
        return "revoked"

    outcome = await db_call(_revoke_hw_key, db, user, key_id)
    if outcome == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if outcome == "revoked":
        log.info("Passkey revoked",
                 user_id=user["id"], key_id=key_id)
    return RedirectResponse("/profile/hardware-keys", status_code=303)


# ---------------------------------------------------------------------------
# /auth/mfa/recovery — H-05 (Cycle 7) recovery-code + operator-recovery
# token consume. Sibling of /login/webauthn/passkey/finish but uses a
# printable one-time code instead of a WebAuthn assertion.
# ---------------------------------------------------------------------------
#
# Two consume modes share this endpoint by the shape of the submitted
# payload:
#   - {"email": "...", "code": "<12-hex>"} → recovery_codes consume
#   - {"token": "<32-hex>"} → operator_recovery_keys consume
#
# Both mint a session token with `mfa_verified_at` stamped so the
# HIPAA-mode hard-cutover middleware accepts the session.
#
# The operator-recovery path does NOT require email because the token
# self-resolves the target_user_id (the issuing CLI captured it at
# token-creation time). The recovery_codes path requires email because
# the codes are scoped per-user and we'd otherwise have to scan every
# user's code-hash table (worse rate-limit shape).

@router.post("/auth/mfa/recovery", response_class=JSONResponse)
async def auth_mfa_recovery(request: Request):
    """H-05 Cycle 7 — consume a recovery code or operator-recovery token.

    Per Q5 design: printable single-use codes (user-driven) + operator-
    key recovery (last-resort, hand-delivered). Both mint a session
    with the `mfa_verified_at` claim so the HIPAA-mode hard-cutover
    middleware (`mfa.session_needs_mfa_step_up`) accepts the session.

    Per H-03 §164.312(b) audit-trail discipline: success + denial both
    emit a `record_auth_event` row (event_type "login_recovery_code"
    or "login_operator_recovery") so the §164.316 trail captures the
    fallback-flow use.

    Rate-limited via the existing  `login_guard` precedent — the
    consume path is bracketed by `check_login_allowed` / `record_login_failure`
    on the recovery-code path. Operator-recovery tokens are NOT
    rate-limited at the per-target-user shape because they're
    single-use + short-TTL by construction (24h default).
    """
    db = _get_db(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")
    body = await parse_json_body(request)  # N-233 R22 SSOT (400 on malformed, not 500)

    token = (body.get("token") or "").strip()
    #  R32 — canonical_email at input (see 772 comment).
    from email_triage.mail_headers import canonical_email
    email = canonical_email(body.get("email") or "")
    code = (body.get("code") or "").strip()

    if token:
        return await _consume_operator_recovery(
            request, db, token=token,
            client_host=client_host, user_agent=user_agent,
        )
    if email and code:
        return await _consume_recovery_code(
            request, db, email=email, code=code,
            client_host=client_host, user_agent=user_agent,
        )
    return api_error_response("bad_request", status_code=400, purpose="misc")


async def _consume_operator_recovery(
    request: Request,
    db: sqlite3.Connection,
    *,
    token: str,
    client_host: str | None,
    user_agent: str | None,
) -> JSONResponse:
    """Operator-issued recovery-token consume path. Resolves
    target_user from the token itself; mints session with
    mfa_verified_at."""
    from email_triage.web.mfa import (
        consume_operator_recovery_token,
        mfa_verified_now,
    )
    from email_triage.web.db import record_auth_event

    def _consume(db) -> tuple[str, dict | None]:
        target_user_id = consume_operator_recovery_token(db, token=token)
        if target_user_id is None:
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_operator_recovery",
                    email="(token)",
                    user_id=None,
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:token_invalid_or_expired",
                ),
                description="login_operator_recovery outcome=denied:token_invalid_or_expired",
            )
            return ("invalid", None)
        # Resolve the user row for session minting.
        row = db.execute(
            "SELECT id, email, role, session_epoch, disabled "
            "FROM users WHERE id = ?",
            (target_user_id,),
        ).fetchone()
        if row is None or row["disabled"]:
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="login_operator_recovery",
                    email=row["email"] if row else "(unknown)",
                    user_id=target_user_id,
                    key_id=None,
                    ip=client_host,
                    user_agent=user_agent,
                    outcome="denied:user_disabled_or_missing",
                ),
                description=f"login_operator_recovery outcome=denied:user_disabled_or_missing user_id={target_user_id}",
            )
            return ("user_invalid", None)
        # FIX C — stamp last_login at the operator-recovery success terminus.
        try:
            update_last_login(db, row["email"])
        except Exception:
            pass
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_operator_recovery",
                email=row["email"],
                user_id=target_user_id,
                key_id=None,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
            ),
            description=f"login_operator_recovery outcome=success user_id={target_user_id}",
        )
        return ("ok", dict(row))

    outcome, user = await db_call(_consume, db)
    if outcome == "invalid":
        return api_error_response("invalid_token", status_code=403, purpose="misc")
    if outcome == "user_invalid":
        return JSONResponse(
            {"error": "user_invalid"}, status_code=403,
        )

    from email_triage.web.dependencies import get_session_secret
    sess_secret = get_session_secret(request)
    sess_token = create_session_token(
        sess_secret, user["email"], user["role"],
        auth_source="operator_recovery",
        auth_key_id=None,
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_now(),
    )
    resp = JSONResponse({
        "ok": True,
        # Operator-recovery is the explicit "re-enroll your passkey"
        # path: redirect the user to the hardware-keys profile page
        # where they can register a fresh credential.
        "redirect": "/profile/hardware-keys",
    })
    set_session_cookie(resp, sess_token, request.app.state.config, request=request)
    log.info(
        "Operator-recovery login successful",
        user_id=user["id"], email=user["email"],
    )
    return resp


async def _consume_recovery_code(
    request: Request,
    db: sqlite3.Connection,
    *,
    email: str,
    code: str,
    client_host: str | None,
    user_agent: str | None,
) -> JSONResponse:
    """User-driven recovery-code consume path. Requires email +
    plaintext code; consumes the matching unused row; mints
    mfa_verified_at session."""
    from email_triage.web.login_guard import (
        check_login_allowed, record_login_failure, record_login_lockout,
        LoginLocked,
    )
    from email_triage.web.mfa import (
        consume_recovery_code,
        mfa_verified_now,
    )
    from email_triage.web.db import record_auth_event

    def _consume(db) -> tuple[str, dict | None, Any]:
        config = _get_config(request)
        try:
            check_login_allowed(
                db, email=email, ip=client_host, config=config,
            )
        except LoginLocked as locked:
            record_login_lockout(
                db, surface="recovery_code", email=email,
                ip=client_host, user_agent=user_agent,
                scope=locked.scope,
                threshold=locked.retry_after_secs,
            )
            return ("locked", None, locked.retry_after_secs)
        user_ = get_user_by_email(db, email)
        if user_ is None or user_.get("disabled"):
            record_login_failure(
                db, surface="recovery_code", email=email,
                ip=client_host, user_agent=user_agent,
                reason="no_account_or_disabled",
            )
            return ("invalid", None, None)
        if not consume_recovery_code(db, user_id=user_["id"], code=code):
            record_login_failure(
                db, surface="recovery_code", email=email,
                ip=client_host, user_agent=user_agent,
                reason="code_invalid_or_used",
                user_id=user_["id"],
            )
            return ("invalid", None, None)
        # FIX C — stamp last_login at the recovery-code success terminus.
        try:
            update_last_login(db, email)
        except Exception:
            pass
        safe_audit_write(
            lambda: record_auth_event(
                db,
                event_type="login_recovery_code",
                email=email,
                user_id=user_["id"],
                key_id=None,
                ip=client_host,
                user_agent=user_agent,
                outcome="success",
            ),
            description=f"login_recovery_code user_id={user_['id']} outcome=success",
        )
        return ("ok", user_, None)

    outcome, user, locked_secs = await db_call(_consume, db)
    if outcome == "locked":
        return JSONResponse(
            {"error": "rate_limited", "retry_after_secs": locked_secs},
            status_code=429,
            headers={"Retry-After": str(locked_secs)},
        )
    if outcome == "invalid":
        return api_error_response("invalid", status_code=403, purpose="misc")

    # Success-edge metric via the shared funnel — the recovery_code surface's
    # success was previously UNCOUNTED (census run15 #6 gap: it incremented the
    # FAILURE metric via record_login_failure but never the success metric);
    # now symmetric with its failure edge.
    from email_triage.web.login_guard import record_login_success
    record_login_success(surface="recovery_code")

    from email_triage.web.dependencies import get_session_secret
    sess_secret = get_session_secret(request)
    sess_token = create_session_token(
        sess_secret, user["email"], user["role"],
        auth_source="recovery_code",
        auth_key_id=None,
        session_epoch=int(user.get("session_epoch", 0)),
        mfa_verified_at=mfa_verified_now(),
    )
    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    set_session_cookie(resp, sess_token, request.app.state.config, request=request)
    log.info(
        "Recovery-code login successful",
        user_id=user["id"], email=user["email"],
    )
    return resp


# ---------------------------------------------------------------------------
# /admin/acme-status — cert metadata + DNS-01 test buttons + issue-now
# ---------------------------------------------------------------------------

@router.get("/admin/acme-status", response_class=HTMLResponse)
async def admin_acme_status_page(request: Request):
    user, err = await db_call(_require_admin, request)
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
    # ASYNC-DB: ACME renewal-log read off the loop.
    log_rows = await db_call(list_acme_renewal_log, db, limit=20)
    #  -- listener restart pending chip. True when the operator hit
    # Save with a new tls.enabled value but the running uvicorn
    # listener is still on the old protocol. Persists across page
    # reloads (unlike the old query-param banner which evaporated
    # the second the operator clicked any internal link). Auto-
    # clears on the next process restart.
    from email_triage.web.app import is_listener_restart_pending
    listener_restart_pending = is_listener_restart_pending(request.app)
    boot_mode = getattr(request.app.state, "tls_boot_mode", None)
    return await _render(request, "admin/acme_status.html", {
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
    user, err = await db_call(_require_admin, request)
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = read_secret(secrets, config.tls.acme.rfc2136.tsig_secret_ref) or ""
    result = acme_mod.test_tsig_authentication(config.tls.acme, tsig)
    return JSONResponse({
        "name": result.name, "ok": result.ok,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail, "error": result.error,
    })


@router.post("/admin/acme-status/test/publish", response_class=JSONResponse)
async def admin_acme_test_publish(request: Request):
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = read_secret(secrets, config.tls.acme.rfc2136.tsig_secret_ref) or ""
    result = acme_mod.test_publish_record(config.tls.acme, tsig)
    return JSONResponse({
        "name": result.name, "ok": result.ok,
        "elapsed_ms": result.elapsed_ms,
        "detail": result.detail, "error": result.error,
    })


@router.post("/admin/acme-status/test/full-cycle", response_class=JSONResponse)
async def admin_acme_test_full_cycle(request: Request):
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    config = _get_config(request)
    secrets = _get_secrets(request)
    tsig = read_secret(secrets, config.tls.acme.rfc2136.tsig_secret_ref) or ""
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
    user, err = await db_call(_require_admin, request)
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
    requested_https = parse_bool(tls_enabled)
    #  -- listener mode flip detection. uvicorn doesn't switch
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
            crt_err = (
                "Cannot enable HTTPS: no server.crt on disk. "
                "Issue a cert (Issue Now) or place one at "
                f"{crt_path} first."
            )
            return RedirectResponse(
                f"/admin/acme-status?{err_qs(crt_err)}",
                status_code=303,
            )
        config.tls.enabled = True
    else:
        config.tls.enabled = False
    listener_flipped = pre_listener_https != bool(config.tls.enabled)

    a = config.tls.acme
    a.enabled = parse_bool(enabled)
    a.directory_url = directory_url.strip() or a.directory_url
    a.account_email = account_email.strip()
    a.domains = [d.strip() for d in domains.split(",") if d.strip()]
    a.challenge = (challenge or "dns-01").strip()
    # N-219c/5 R23: SSOT routing — bounded_int(x, default=prior, lo=N) preserves
    # the prior-value-on-failure semantics + folds in the max()-clamp bound.
    a.renewal_threshold_days = bounded_int(
        renewal_threshold_days, default=a.renewal_threshold_days,
    )
    a.check_interval_hours = bounded_int(
        check_interval_hours, default=a.check_interval_hours,
    )
    a.pre_validation_grace_secs = bounded_int(
        pre_validation_grace_secs, default=a.pre_validation_grace_secs, lo=0,
    )
    a.validation_retries = bounded_int(
        validation_retries, default=a.validation_retries, lo=0,
    )
    a.validation_retry_delay_secs = bounded_int(
        validation_retry_delay_secs, default=a.validation_retry_delay_secs, lo=1,
    )
    a.caa_enforce = parse_bool(caa_enforce)
    a.dns_provider = (dns_provider or "rfc2136").strip()
    rfc = a.rfc2136
    rfc.nameserver = rfc_nameserver.strip()
    rfc.nameserver_port = bounded_int(  # N-219c/5 R23: SSOT
        rfc_nameserver_port, default=rfc.nameserver_port,
    )
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
    rfc.public_propagation_timeout_secs = bounded_int(  # N-219c/5 R23: SSOT
        rfc_public_propagation_timeout_secs,
        default=rfc.public_propagation_timeout_secs, lo=60,
    )
    rfc.public_propagation_interval_secs = bounded_int(  # N-219c/5 R23: SSOT
        rfc_public_propagation_interval_secs,
        default=rfc.public_propagation_interval_secs, lo=2,
    )

    # TSIG secret: a blank submit PRESERVES the stored value (an empty save
    # does NOT zero it). Routes through the _secret_write SSOT (never-clobber-
    # on-blank) like every other credential write — pairs with the readonly-
    # until-focus field so a password-manager can't autofill it at page load
    # and silently overwrite the renewer's TSIG key. See the 2026-06-08
    # save-clobber incident.
    from email_triage.web.routers._secret_write import set_secret_if_changed
    set_secret_if_changed(
        secrets, rfc.tsig_secret_ref, rfc_tsig_secret_value.strip(),
    )

    config.webauthn.rp_id = webauthn_rp_id.strip()
    config.webauthn.rp_name = (webauthn_rp_name or "Email Triage").strip()
    config.webauthn.origin = webauthn_origin.strip()

    # Persist to YAML.
    save_error = None
    try:
        from email_triage.web.routers.ui import _write_config_yaml
        _write_config_yaml(config)
    except Exception as e:
        #  tail — same class as admin.py:830, integrations.py:693.
        # ACME config write failure previously echoed raw exception str
        # into URL flash message.
        from email_triage.web._flash import scrub_exc
        save_error = (
            "Settings applied in memory but YAML write failed: "
            f"{scrub_exc(e, purpose='form')}"
        )
        log.error("ACME config YAML write failed", exc_info=e)

    log.info("ACME config saved", actor_user_id=user["id"],
             domains=a.domains, dns_provider=a.dns_provider,
             tsig_secret_set=bool(rfc_tsig_secret_value.strip()),
             listener_flipped=listener_flipped)

    # Return to the status page; query string surfaces a save flash.
    # -- the listener-flip restart prompt no longer rides the
    # query string. It now lives on the page itself via the persistent
    # ``listener_restart_pending`` chip rendered from
    # ``app.state.tls_boot_mode`` vs the saved value. The chip
    # survives page reloads + nav-away-and-back without depending
    # on a redirect param.
    if save_error:
        qs = err_qs(save_error[:100])
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    config = _get_config(request)
    if directory == "production":
        directory_url = config.tls.acme.directory_url
    else:
        # N-230 R22 — route through the config SSOT so a fork can override
        # the staging endpoint via YAML `tls.acme.staging_directory_url`.
        directory_url = config.tls.acme.staging_directory_url
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
            "ok": False, "error": scrub_class_error_for_persist(e),
        }, status_code=500)


@router.post("/admin/acme-status/cancel", response_class=JSONResponse)
async def admin_acme_cancel(request: Request):
    """Operator-driven cancel for an in-flight ACME issuance.

    the backlog . Flips ``cancel_requested=1`` on the
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
    user, err = await db_call(_require_admin, request)
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

     -- the page polls this endpoint on load (and every few seconds
    while a job is in flight) so a refresh / nav-away-and-back doesn't
    lose the live timer. State lives in process memory only; a worker-
    thread restart abandons both the cert and the view, so no stronger
    persistence is needed.

    Returns a JSON dict with phase, attempt counts, started_at,
    elapsed_secs, last_error, per-domain visibility map. ``in_flight``
    is the simple polling-stop signal -- when False, the page can
    stop polling and render the terminal state once.
    """
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    from email_triage.web import acme_job_state
    return JSONResponse(acme_job_state.current_state())


@router.post("/admin/system/restart", response_class=HTMLResponse)
async def admin_system_restart(request: Request):
    """Exit the running process so systemd respawns the container.

     -- listener-mode flips don't take effect until the uvicorn
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err

    db = _get_db(request)
    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")
    from email_triage.web.db import record_auth_event
    # ASYNC-DB: restart audit-event write off the loop.
    await safe_audit_write_async(
        lambda: db_call(
            record_auth_event,
            db, event_type="system_restart", email=user.get("email", ""),
            user_id=user["id"], ip=client_host, user_agent=user_agent,
            outcome="success",
            detail="admin-initiated restart via /admin/system/restart",
        ),
        description=f"system_restart user_id={user['id']}",
    )

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
