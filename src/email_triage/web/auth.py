"""Passwordless email OTP authentication.

Flow:
    1. User enters email address
    2. System generates 6-digit code (10-minute expiry), stores hash in SQLite
    3. System sends code via SMTP
    4. User enters code
    5. On success, signed session cookie is set

Session: ``itsdangerous.URLSafeTimedSerializer`` encoding email + role.
"""

from __future__ import annotations

import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from email_triage._isotime import now_utc_iso, parse_iso, parse_iso_aware, to_utc_iso
from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger
from email_triage.web.db_writelock import db_write, get_write_lock
from email_triage._dbapi_errors import DB_ERRORS

log = get_logger("web.auth")

# OTP settings
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10

# Session settings
SESSION_COOKIE_NAME = "et_session"


def effective_session_ttl(config: Any) -> int:
    """Return the session TTL (seconds) honouring HIPAA mode.

    Reads ``config.auth.session_ttl_secs`` for the operator pick;
    when ``is_hipaa_mode()`` is on, takes the min of that and
    ``config.auth.hipaa_session_ttl_secs``. The HIPAA cap was
    already clamped to ``HIPAA_TTL_HARD_CEILING_SECS`` at YAML
    load time, so a hand-edited YAML can't slip past the project's
    standing rule.

    Falls back to ``SESSION_MAX_AGE`` (7 days) when ``config`` lacks
    an ``auth`` block -- preserves pre-PR behaviour for installs
    that haven't migrated their YAML yet.
    """
    from email_triage.triage_logging import is_hipaa_mode
    auth = getattr(config, "auth", None)
    if auth is None:
        return SESSION_MAX_AGE
    base = int(getattr(auth, "session_ttl_secs", SESSION_MAX_AGE))
    if is_hipaa_mode():
        cap = int(getattr(auth, "hipaa_session_ttl_secs", 900))
        return min(base, cap)
    return base
SESSION_MAX_AGE = 86400 * 7  # 7 days


def set_session_cookie(response: Any, token: str, config: Any, request: Any = None) -> None:
    """Attach the session cookie to ``response`` — the single place
    its flags are defined.

    Was copy-pasted at four login sites (OTP, dev-keypair, WebAuthn,
    passkey). The drift cost a missing ``Secure`` flag: on a TLS
    install the session token — the highest-value credential — could
    ride a plaintext request. ``Secure`` is now gated on
    ``config.tls.enabled``, the same signal the CSRF and challenge
    cookies already use, so a fifth login path cannot silently forget
    it.

    HttpOnly (JS cannot read the token) and SameSite=lax (the session
    must survive a top-level cross-site navigation back into the app,
    unlike the SameSite=strict CSRF cookie) are the established
    posture — unchanged; only the absent Secure flag is fixed.
    """
    # N-200 R22 (2026-07-02): route Secure decision through the _cookies SSOT
    # so the reverse-proxy topology (nginx-front) is captured (via
    # request.url.scheme=='https') alongside the direct-uvicorn HTTPS listener
    # (via config.tls.enabled). Callers pre-N-200 that don't pass `request`
    # degrade cleanly to the config.tls.enabled-only path (byte-identical to
    # the pre-fix behavior — new callers pass `request` to get the widened
    # coverage).
    from email_triage.web._cookies import is_request_https
    secure = is_request_https(request, config)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=effective_session_ttl(config),
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def _hash_code(code: str) -> str:
    """SHA-256 hash of an OTP code (routes through the credential-hash SSOT)."""
    from email_triage.web._credhash import hash_credential
    return hash_credential(code)


# ---------------------------------------------------------------------------
# OTP generation and verification
# ---------------------------------------------------------------------------

def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP code."""
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


@db_write
def store_otp(conn: sqlite3.Connection, email: str, code: str) -> None:
    """Store a hashed OTP code in the database.

    Invalidates any existing unused codes for the same email first.

     — ``@db_write`` serialises the UPDATE + INSERT + commit on the
    process-wide write lock so the two statements commit atomically
    with respect to every other writer on the shared connection.
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=OTP_EXPIRY_MINUTES)

    # Mark existing unused codes as used (prevents replay).
    conn.execute(
        "UPDATE otp_codes SET used = 1 WHERE email = ? AND used = 0",
        (email,),
    )

    conn.execute(
        "INSERT INTO otp_codes (email, code_hash, expires_at, used) VALUES (?, ?, ?, 0)",
        (email, _hash_code(code), to_utc_iso(expires)),
    )
    conn.commit()


@db_write
def verify_otp(conn: sqlite3.Connection, email: str, code: str) -> bool:
    """Verify an OTP code.  Returns True on success, False otherwise.

    On success the code is marked as used.

     — ``@db_write`` serialises the SELECT + UPDATE + commit so the
    mark-as-used write cannot race another writer on the shared
    connection.
    """
    now = datetime.now(timezone.utc)
    code_hash = _hash_code(code)

    row = conn.execute(
        """SELECT id, expires_at FROM otp_codes
           WHERE email = ? AND code_hash = ? AND used = 0
           ORDER BY id DESC LIMIT 1""",
        (email, code_hash),
    ).fetchone()

    if row is None:
        log.info("OTP verification failed: no matching code", email=email)
        return False

    # Census N-65 — route through the parse_iso SSOT, never raw fromisoformat:
    # a corrupt/unparseable expires_at on this OTP-verify path used to raise
    # ValueError and 500 the login. parse_iso returns None on bad input → treat
    # as expired/invalid (FAIL CLOSED — refuse the code), same as a real expiry.
    # N-357 R31 (2026-07-05 trust-repair fix-forward — SSOT collapse of
    # the N-302 assume-UTC-on-naive shim). Was 3 lines of inline
    # `parse_iso` + `if tzinfo is None: replace(tzinfo=utc)`; now one
    # `parse_iso_aware` call. Behaviour identical (None on unparseable,
    # naive stamped UTC, aware returned as-is).
    expires = parse_iso_aware(row["expires_at"])
    if expires is None or now > expires:
        log.info(
            "OTP verification failed: code expired or invalid expiry",
            email=email,
        )
        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        return False

    # Mark as used.
    conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()

    log.info("OTP verified", email=email)
    return True


@db_write
def cleanup_expired_otps(conn: sqlite3.Connection) -> int:
    """Remove expired OTP codes.  Returns count deleted.

     — ``@db_write`` serialises the DELETE + commit on the shared
    connection's write lock.
    """
    now = now_utc_iso()
    cursor = conn.execute(
        "DELETE FROM otp_codes WHERE expires_at < ? OR used = 1",
        (now,),
    )
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Session management (signed cookies via itsdangerous)
# ---------------------------------------------------------------------------

def _get_serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="email-triage-session")


def create_session_token(
    secret_key: str,
    email: str,
    role: str,
    *,
    auth_source: str = "otp",
    auth_key_id: int | None = None,
    session_epoch: int = 0,
    mfa_verified_at: int | None = None,
) -> str:
    """Create a signed session token.

    ``auth_source`` ∈ {``otp``, ``dev_keypair``, ``webauthn``,
    ``recovery_code``, ``operator_recovery``} stamps the auth path
    that minted this session into the cookie payload. Echoed into
    ``access_log`` on every authenticated request so an auditor can
    answer "how did this session get in?" without consulting external
    state. Old tokens (pre-#67) without this field decode as
    ``auth_source="otp"`` for back-compat.

    ``auth_key_id`` is the corresponding ``dev_keys.id`` or
    ``hardware_keys.id`` (or None for OTP). Lets the audit trail
    name the specific credential used, not just the path.

    ``session_epoch`` is the user's ``users.session_epoch`` at
    sign-in time. :func:`dependencies.get_current_user` rejects a
    token whose stamped epoch is older than the user's current epoch,
    so bumping the epoch (disable-user, "sign out all sessions")
    revokes every outstanding session for that user.

    ``mfa_verified_at`` (H-05, Cycle 7) is the epoch-seconds at which
    a multi-factor verification (WebAuthn / recovery_code /
    operator_recovery) succeeded for this session. Sessions minted
    via OTP / dev_keypair leave this field None. The HIPAA-mode
    hard-cutover middleware (``mfa.session_needs_mfa_step_up``)
    rejects any session lacking this claim when HIPAA mode is on —
    forcing pre-cutover sessions through an MFA step-up. Per Q6
    design: hard cutover, no grandfather.

     — refuses an ``_route_scope.API_ONLY_ROLES`` role (``health_ro``).
    THIS is the "cannot log in through the web session path" gate, and it lives
    here because this is the ONE session-minting funnel: every login surface —
    OTP (``routers/ui/users.py``), WebAuthn begin/finish, passkey, recovery-code
    and admin dev-keypair (``routers/auth_keys.py``, 5 call sites) — passes
    through it. Gating the four handlers instead would be a four-site predicate,
    i.e. the R5 drift shape. ``web/app.py`` maps the raised
    :class:`~email_triage.web._route_scope.SessionMintRefused` to a 403 so the
    refusal reads as policy, not as a crash. The cookie READ path in
    ``dependencies.get_current_user`` re-checks the same predicate — both edges
    through one funnel (R42).
    """
    from email_triage.web._route_scope import (
        SessionMintRefused,
        role_may_hold_web_session,
    )
    if not role_may_hold_web_session(role):
        raise SessionMintRefused(
            f"role {role!r} is API-only and may not hold a web session"
        )
    s = _get_serializer(secret_key)
    payload: dict[str, Any] = {"email": email, "role": role}
    # Only include the new fields when non-default to keep the cookie
    # bytes small for the OTP common case (and to make back-compat
    # round-trip identical).
    if auth_source and auth_source != "otp":
        payload["auth_source"] = auth_source
    if auth_key_id is not None:
        payload["auth_key_id"] = int(auth_key_id)
    if session_epoch:
        payload["epoch"] = int(session_epoch)
    if mfa_verified_at is not None:
        payload["mfa_verified_at"] = int(mfa_verified_at)
    return s.dumps(payload)


def verify_session_token(
    secret_key: str,
    token: str,
    max_age: int = SESSION_MAX_AGE,
) -> dict[str, Any] | None:
    """Verify a session token.

    Returns ``{"email", "role", "auth_source", "auth_key_id", "epoch",
    "mfa_verified_at"}`` on success or None on failure.
    ``auth_source`` defaults to ``"otp"`` for tokens minted before
    ; ``epoch`` defaults to ``0`` for tokens minted before ;
    ``mfa_verified_at`` defaults to ``None`` for tokens minted before
    H-05 (back-compat — pre-existing sessions remain valid; the new
    fields populate only on next sign-in. The HIPAA-mode hard-cutover
    middleware fires step-up on None for these).
    """
    s = _get_serializer(secret_key)
    try:
        data = s.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("auth_source", "otp")
    data.setdefault("auth_key_id", None)
    data.setdefault("epoch", 0)
    data.setdefault("mfa_verified_at", None)
    return data


# ---------------------------------------------------------------------------
# User lookup
# ---------------------------------------------------------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> dict[str, Any] | None:
    """Look up a user by email.  Returns a dict or None.

    Includes ``disabled`` / ``disabled_at`` so every auth path can
    enforce the fail-closed kill-switch without a second query, and
    ``session_epoch`` so the user-loader can reject a session
    token whose stamped epoch is stale.

     — this read runs on the *shared* ``app.state.db`` connection
    from ``get_current_user`` on the event-loop thread for every
    authenticated request, i.e. OUTSIDE ``db_call``. The shared
    connection cannot be touched by two threads at once, so the
    SELECT is serialised through the process-wide DB lock. The lock is
    an ``RLock``: callers already inside ``db_call`` (which holds the
    same lock) re-acquire it on the same thread without deadlock.

     R32 (census wf_56d1585d 2026-07-09 DA-fold R1) — canonicalise
    the lookup key at the READ SSOT so any caller passing a raw
    ``.strip().lower()`` form OR a display-wrapped input still finds
    the row (write paths were also fixed same-drive; this is the
    symmetric read-side).
    """
    from email_triage.mail_headers import canonical_email
    email = canonical_email(email)
    with get_write_lock():
        row = conn.execute(
            "SELECT id, email, name, role, notify_email, created_at, last_login, "
            "disabled, disabled_at, session_epoch FROM users WHERE email = ?",
            (email,),
        )
        result = row.fetchone()
    if result is None:
        return None
    return dict(result)


@db_write
def update_last_login(conn: sqlite3.Connection, email: str) -> None:
    """Update the user's last_login timestamp.

     — runs on the shared connection (the OTP-login path calls it
    directly, and ``@db_write`` also covers it when it lands on a
    threadpool worker via ``db_call``). The decorator serialises the
    UPDATE + commit on the process-wide write lock.

     R32 — canonicalise the WHERE-clause key to match the
    canonicalised storage form (see :func:`get_user_by_email`).
    """
    update_last_login_txn(conn, email)
    conn.commit()


def update_last_login_txn(conn: sqlite3.Connection, email: str) -> None:
    """TXN-AWARE twin of :func:`update_last_login`; no commit (N-520 step 2)."""
    from email_triage.mail_headers import canonical_email
    email = canonical_email(email)
    now = now_utc_iso()
    conn.execute("UPDATE users SET last_login = ? WHERE email = ?", (now, email))


def classify_otp(
    conn: sqlite3.Connection, email: str, code: str,
) -> tuple[str, int | None]:
    """READ-ONLY half of :func:`verify_otp` (N-520 step 2).

    Returns ``("none", None)`` when no unused code matches, ``("expired",
    id)`` for a matching code past (or with an unparseable) expiry, and
    ``("valid", id)`` otherwise. Writes nothing: the burn is the caller's
    (:func:`burn_otp_txn` inside the witnessed success unit, or
    :func:`burn_otp` for the tightening burn of an expired code)."""
    row = conn.execute(
        """SELECT id, expires_at FROM otp_codes
           WHERE email = ? AND code_hash = ? AND used = 0
           ORDER BY id DESC LIMIT 1""",
        (email, _hash_code(code)),
    ).fetchone()
    if row is None:
        log.info("OTP verification failed: no matching code", email=email)
        return "none", None
    # Census N-65 / N-357: parse_iso_aware SSOT; None (unparseable) is
    # treated as expired (FAIL CLOSED), same as verify_otp.
    expires = parse_iso_aware(row["expires_at"])
    if expires is None or datetime.now(timezone.utc) > expires:
        log.info(
            "OTP verification failed: code expired or invalid expiry",
            email=email,
        )
        return "expired", int(row["id"])
    return "valid", int(row["id"])


def burn_otp_txn(conn: sqlite3.Connection, otp_id: int) -> bool:
    """Mark one OTP used; no commit (N-520 step 2). True only when THIS call
    burned it (``used = 0`` guard), so two racing verifies cannot both win."""
    cur = conn.execute(
        "UPDATE otp_codes SET used = 1 WHERE id = ? AND used = 0", (int(otp_id),),
    )
    return cur.rowcount > 0


@db_write
def burn_otp(conn: sqlite3.Connection, otp_id: int) -> bool:
    """Own-commit form of :func:`burn_otp_txn`: the TIGHTENING burn (an expired
    or refused code), which never depends on audit-chain health."""
    burned = burn_otp_txn(conn, otp_id)
    conn.commit()
    return burned


# ---------------------------------------------------------------------------
# Email delivery (SMTP)
# ---------------------------------------------------------------------------

def format_from_header(from_addr: str, from_name: str | None = None) -> str:
    """Compose an RFC-5322 ``From:`` value — delegates to the mail_headers SSOT
    (divergence census 2026-06-09 #5), which additionally strips CR/LF from the
    display name (header-injection defense). Kept as a re-export so existing
    ``from web.auth import format_from_header`` callers (recipient_digest,
    daily_health) are unchanged."""
    from email_triage.mail_headers import format_from_header as _ssot
    return _ssot(from_addr, from_name)


def send_otp_email(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_addr: str,
    to_addr: str,
    code: str,
    use_tls: bool = True,
    from_name: str = "",
) -> None:
    """Send an OTP code via SMTP.

    Thin wrapper around the generic ``send_simple_smtp_email``
    helper at ``web.smtp_send``: this function owns the OTP-specific
    subject + body templates and the ``triage_source="otp"`` stamp
    that loop-prevention checks for.
    """
    from email_triage.web.smtp_send import send_simple_smtp_email
    send_simple_smtp_email(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_password=smtp_password,
        from_addr=from_addr,
        to_addr=to_addr,
        subject=f"Email Triage Login Code: {code}",
        body=(
            f"Your login code is: {code}\n\n"
            f"This code expires in {OTP_EXPIRY_MINUTES} minutes.\n"
            f"If you did not request this, ignore this email."
        ),
        use_tls=use_tls,
        from_name=from_name,
        triage_source="otp",
    )
    log.info("OTP email sent", to=to_addr)


def smtp_send_digest(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_addr: str,
    from_name: str,
    to_addr: str,
    reply_to: str,
    subject: str,
    html_body: str,
    use_tls: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> None:
    """Send a system-generated HTML digest via SMTP.

    Shape mirrors ``send_otp_email`` — deliberate: same auth envelope,
    same From quoting, same loop-prevention stamp slot (via
    ``extra_headers``). The digest path uses this when the chosen
    recipient is not the source mailbox (so ``deliver_to_inbox`` isn't
    an option).
    """
    import email.mime.multipart
    import email.mime.text
    import email.utils
    import re

    # N-272 R28: route through the MIME envelope SSOT.
    from email_triage.web._mime_builder import build_alternative_message
    from email_triage.engine.html_text import strip_tags
    plain = strip_tags(html_body)
    _hdrs = dict(extra_headers) if extra_headers else {}
    if reply_to:
        _hdrs["Reply-To"] = reply_to
    msg = build_alternative_message(
        subject=subject,
        from_addr=from_addr,
        from_name=from_name,
        to=to_addr,
        plain_body=plain,
        html_body=html_body,
        source_tag="auth_email",
        extra_headers=_hdrs or None,
    )

    # Census 2026-06-09 #2: route through the smtplib-transport SSOT.
    from email_triage.web.smtp_send import send_smtp_message
    send_smtp_message(
        msg, smtp_host=smtp_host, smtp_port=smtp_port,
        smtp_user=smtp_user, smtp_password=smtp_password, use_tls=use_tls,
    )

    log.info("Digest email sent via SMTP", to=to_addr, subject=subject)


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "et_"  # Prefix for easy identification.


def generate_api_key() -> str:
    """Generate a new API key with a recognisable prefix."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """SHA-256 hash of an API key for storage (credential-hash SSOT)."""
    from email_triage.web._credhash import hash_credential
    return hash_credential(key)


class ApiKeyGrantError(RuntimeError):
    """:func:`store_api_key` refused the grant: its insert or its witness
    failed and was rolled back, so no key exists. A caller catches this type
    and never returns or prints the raw key (fail closed, panel P F5)."""


class ApiKeyRevokeError(RuntimeError):
    """:func:`delete_api_key` refused the revocation: its delete or its
    ``api_key_revoked`` witness failed and was rolled back, so the key still
    exists and still authenticates (punch 689). A caller catches this type and
    tells the operator the key was NOT revoked, so they can retry."""


def _record_api_key_witness_gap(
    conn: sqlite3.Connection,
    exc: BaseException,
    *,
    helper_name: str = "store_api_key",
    event: str = "api_key_created",
) -> None:
    """One ``audit_gap_events`` row for an api-key grant or revocation whose
    witness failed (panel P F4, punch 689). The caller holds the write lock
    (``@db_write``) and has rolled back. Best effort: a failed gap write is
    logged and never masks ``exc``."""
    try:
        from email_triage.db.audit import mark_audit_gap_recorded, record_audit_write_loss
        record_audit_write_loss(
            conn, loss_class="failed_unrecorded", table="api_key_events",
            helper_name=helper_name,
        )
        mark_audit_gap_recorded(exc)
    except Exception as gap_exc:
        log.error(
            "api_key witness failed AND its gap row failed",
            event=event,
            witness_error=type(exc).__name__,
            gap_error=fmt_exc(gap_exc, with_class=True),
        )


@db_write
def store_api_key(
    conn: sqlite3.Connection,
    key_hash: str,
    name: str,
    user_id: int,
    expires_at: str | None = None,
    *,
    scope: str | None = None,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    source: str = "unknown",
) -> int:
    """Store a hashed API key and emit a lifecycle audit entry.

     — ``@db_write`` serialises the INSERT + commit + the nested
    ``record_api_key_event`` audit write as one unit on the shared
    connection's write lock.

    Returns the key ID. The raw token is NEVER logged or persisted in
    the audit trail — only ``key_id`` is recorded as the correlation
    handle.

    Audit context (``actor_user_id``, ``actor_email``, ``source``) is
    keyword-only so callers must opt into providing it. A grant with
    neither ``actor_user_id`` nor ``actor_email`` is REFUSED with
    ``ApiKeyEventUnattributed`` (punch 710, register N-644): no key is
    minted without an actor named in the chained witness.

    Punch 627 (N-611): the ``api_keys`` row and its ``api_key_created``
    witness go through ONE transaction (``record_api_key_event_txn``, the
    N-520 shape), so a failed witness (``_chain_insert`` is fail-closed on an
    HMAC-key gap, Directive 12) refuses the mint and raises instead of leaving
    a key nobody can see was granted (fail CLOSED, PD#8). The structured log
    line fires only after the commit.

     — ``scope`` is the serialized ``api_keys.scope`` JSON (or None for an
    unscoped, full-principal key). Where it is recorded, stated precisely,
    because the obvious answer is wrong:

    * ``api_keys.scope`` — the live authoritative state, surfaced by
      ``apikey list`` so an operator can audit what they issued.
    * the ``api_key_created`` structured log line below. **Which sink that
      reaches depends on the PROCESS.** ``SQLiteLogHandler`` (the HMAC-chained
      ``log_entries`` writer, ) is attached by ``add_sqlite_handler``, and
      the ONLY caller is the server lifespan in ``web/app.py`` — ``setup_logging``
      itself attaches console + optional file handlers and nothing else. So from
      the **server** (the UI and API mint paths) this line lands in the chained
      table; from the **CLI** it reaches stderr/file only. Do not read this line
      as tamper-evidence on the CLI path.
    * therefore, for the CLI path, the tamper-evident record is the
      ``@_cli_audit("apikey")`` row: ``_emit_cli_audit_event`` routes through the
      ``record_cli_admin_op`` ``@db_write`` + ``@audit_emitter`` SSOT into the
      ``log_entries`` chain, and ``scope`` / ``expires_days`` were added to its
      ``_SAFE_ARG_KEYS`` allowlist in this change so they actually appear (the
      allowlist drops anything unlisted). Note that emitter is **HIPAA-gated** —
      it early-returns when ``logging.hipaa`` is off — so on a non-HIPAA install
      the CLI mint has no chained record of its scope. the deploy host runs HIPAA mode on.
    * **NOT** ``api_key_events``. That table is chain-hashed over the DECLARED
      tuple ``_AUDIT_CHAIN_CANONICAL_FIELDS["api_key_events"]``
      (``db/audit.py``), so adding ``scope`` to it would change the RECOMPUTED
      row_hash of every historical row and break §164.312(c) re-verification —
      the trap documented in ``db/audit.py`` for ``hipaa_access_events``. The
      lifecycle event itself still routes through the ``record_api_key_event``
      emitter SSOT unchanged (PD#3); no raw INSERT is added anywhere.

    A route scope is a list of code-defined HTTP route strings: no PHI, no
    Safe-Harbor identifier, so it is safe in a log field (R30).
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "an API-key grant requires a transaction-capable (non-autocommit) "
            "connection so the api_keys insert + its chained api_key_events "
            "witness are atomic; got isolation_level=None (autocommit)"
        )
    from email_triage.db.audit import record_api_key_event_txn
    now = now_utc_iso()
    try:
        cursor = conn.execute(
            "INSERT INTO api_keys (key_hash, name, user_id, created_at, expires_at, scope) VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, name, user_id, now, expires_at, scope),
        )
        new_id = cursor.lastrowid
    except Exception as exc:
        # A refused business write: nothing was granted and no witness was
        # due, so no gap row (panel P F4).
        conn.rollback()
        raise ApiKeyGrantError(str(exc)) from exc
    try:
        record_api_key_event_txn(
            conn,
            event="api_key_created",
            key_id=new_id,
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            name=name,
            expires_at=expires_at,
            source=source,
            actor_email=actor_email,
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        # Panel P F4 (punch 627): the WITNESS failed, so the grant is refused
        # and its audit row is lost. Leave the gap trace, as @audit_emitter
        # does for the dev-key funnel, then re-raise (fail closed).
        err = ApiKeyGrantError(str(exc))
        _record_api_key_witness_gap(conn, err)
        raise err from exc

    # Look up target email for the log line. Best-effort — auth must
    # not fail if the user row was deleted between calls.
    target_email: str | None = None
    try:
        row = conn.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if row is not None:
            target_email = row["email"]
    except DB_ERRORS as _swallow_exc:
        log.warning(
            "api-key audit target-email lookup failed",
            error=fmt_exc(_swallow_exc),
        )

    log.info(
        "api_key_created",
        event="api_key_created",
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        key_id=new_id,
        target_user_id=user_id,
        target_email=target_email,
        name=name,
        expires_at=expires_at,
        scope=scope,
        source=source,
    )

    return new_id


@db_write
def verify_api_key(conn: sqlite3.Connection, key: str) -> dict[str, Any] | None:
    """Verify an API key and return the associated user, or None.

    Updates ``last_used_at`` on success.  Rejects expired keys.  Rejects
    keys whose owning user is ``disabled`` — the disable flag is a
    fail-closed kill-switch that must block API access even if the key
    is otherwise valid.  Blocked attempts are logged for audit.

     — this helper both READS (the JOIN lookup) and WRITES (the
    ``last_used_at`` UPDATE) on the *shared* ``app.state.db``
    connection, and runs on the event-loop thread for every Bearer-
    authenticated request via ``get_current_user`` → ``_check_bearer_token``
    — i.e. OUTSIDE ``db_call``. ``@db_write`` serialises the whole
    SELECT + UPDATE + commit on the process-wide write lock so it
    cannot race a ``db_call`` worker on the same connection. The lock
    is reentrant, so calls dispatched through ``db_call`` (which also
    holds it) do not self-deadlock.
    """
    key_hash = hash_api_key(key)
    row = conn.execute(
        """SELECT ak.id AS key_id, ak.user_id, ak.name AS key_name,
                  ak.expires_at, ak.scope AS key_scope,
                  u.email, u.name, u.role, u.disabled
           FROM api_keys ak
           JOIN users u ON u.id = ak.user_id
           WHERE ak.key_hash = ?""",
        (key_hash,),
    ).fetchone()

    if row is None:
        return None

    # Check expiry. Census N-65 — parse_iso SSOT, never raw fromisoformat:
    # a corrupt expires_at used to 500 every bearer-token check. None (bad /
    # unparseable) → FAIL CLOSED (reject the key), same as an elapsed expiry.
    if row["expires_at"]:
        # N-357 R31 (2026-07-05 SSOT collapse). See docstring at
        # `_isotime.parse_iso_aware` and companion site above at ~L169.
        expires = parse_iso_aware(row["expires_at"])
        if expires is None or datetime.now(timezone.utc) > expires:
            log.info("API key expired or invalid expiry", key_name=row["key_name"])
            return None

    # Fail-closed: a disabled user's keys never authenticate.
    if row["disabled"]:
        log.warning(
            "API key auth blocked: user disabled",
            key_name=row["key_name"],
            user_email=row["email"],
        )
        return None

    # Update last_used_at.
    now = now_utc_iso()
    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["key_id"]))
    conn.commit()

    return {
        "id": row["user_id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "auth_method": "api_key",
        "key_name": row["key_name"],
        "api_key_id": row["key_id"],
        #  — the RAW stored scope column, carried to the seam that owns the
        # decision. Deliberately un-parsed here: this helper resolves IDENTITY,
        # `web/_route_scope.check_principal_fences` decides AUTHORITY, and it is
        # the one that holds the request's method + path. NULL = unscoped =
        # pre-#420 full-principal behaviour.
        "api_key_scope": row["key_scope"],
    }


def list_api_keys(conn: sqlite3.Connection, user_id: int | None = None) -> list[dict[str, Any]]:
    """List API keys. If user_id is given, filter to that user.

     — ``scope`` is selected because an operator who cannot SEE the scope they
    issued cannot audit the credential; the column would otherwise be a fence
    nobody can read.
    """
    if user_id is not None:
        rows = conn.execute(
            """SELECT ak.id, ak.name, ak.user_id, u.email, u.name AS user_name, ak.created_at, ak.last_used_at, ak.expires_at, ak.scope
               FROM api_keys ak JOIN users u ON u.id = ak.user_id
               WHERE ak.user_id = ? ORDER BY ak.id""",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT ak.id, ak.name, ak.user_id, u.email, u.name AS user_name, ak.created_at, ak.last_used_at, ak.expires_at, ak.scope
               FROM api_keys ak JOIN users u ON u.id = ak.user_id
               ORDER BY ak.id""",
        ).fetchall()
    return [dict(r) for r in rows]


@db_write
def delete_api_key(
    conn: sqlite3.Connection,
    key_id: int,
    *,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    source: str = "unknown",
    emergency_reason: str | None = None,
    cli_principal: str | None = None,
) -> bool:
    """Delete an API key by ID and emit a lifecycle audit entry.

    Punch 709: ``emergency_reason`` (a code from ``EMERGENCY_REVOKE_REASONS``)
    is the explicit emergency flag. Unset, nothing below changes. Set, a
    failure of the WITNESS phase alone (the DELETE already succeeded) commits
    the delete without its witness and calls ``record_emergency_revoke`` (a gap
    row, a CRITICAL line, the ``/health`` marker); a healthy chain takes the
    normal path and writes no gap row. Only an enabled admin, or the host CLI
    (no user id, ``source="cli"``), may pass the flag: anyone else gets
    ``EmergencyRevokeRefused`` from ``check_emergency_actor``, the flag branch's
    first statement, and nothing is written (no delete, no row, no marker).
    The gap row's actor is built by the funnel from ``actor_user_id`` and, for
    the host CLI only, ``cli_principal``: never a caller-supplied label.

     — ``@db_write`` serialises the SELECT + DELETE + the
    ``api_key_revoked`` witness + commit as one unit on the shared
    connection's write lock.

    Returns True if a row was deleted. Audit context is keyword-only;
    see ``store_api_key`` for the schema rationale.

    The audit row in ``api_key_events`` survives the deletion of the
    underlying ``api_keys`` row (no FK on ``key_id``) so revocations
    remain auditable indefinitely.

    Punch 689 (an N-520 member until now): the DELETE and its
    ``api_key_revoked`` witness go through ONE transaction
    (``record_api_key_event_txn``), the revocation edge of
    :func:`store_api_key`. A failed witness rolls the delete back, leaves the
    gap row and raises :class:`ApiKeyRevokeError` (fail CLOSED on the record,
    PD#8): a key is never gone without its chained witness, and the caller
    tells the operator the key is still live. The structured log line fires
    only after the commit. Deleting a key that does not exist is a no-op: no
    write, no row.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "an API-key revocation requires a transaction-capable "
            "(non-autocommit) connection so the api_keys delete + its chained "
            "api_key_events witness are atomic; got isolation_level=None "
            "(autocommit)"
        )
    from email_triage.db.audit import (
        check_emergency_actor,
        check_emergency_reason,
        record_api_key_event_txn,
        record_emergency_revoke,
    )
    if emergency_reason is not None:
        check_emergency_actor(conn, actor_user_id, source)
        check_emergency_reason(emergency_reason)
    try:
        # Capture target+name BEFORE delete — once the row is gone we
        # can't recover those for the audit entry.
        row = conn.execute(
            "SELECT user_id, name, expires_at FROM api_keys WHERE id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            # Deleting a non-existent key is a no-op, not an event.
            return False
        target_user_id: int | None = row["user_id"]
        name: str = row["name"] or ""
        expires_at: str | None = row["expires_at"]
        cursor = conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        if cursor.rowcount == 0:
            conn.rollback()
            return False
    except Exception as exc:
        # A refused business write: nothing was revoked and no witness was
        # due, so no gap row (the store_api_key panel P F4 shape).
        conn.rollback()
        raise ApiKeyRevokeError(str(exc)) from exc
    witness_failure: Exception | None = None
    try:
        record_api_key_event_txn(
            conn,
            event="api_key_revoked",
            key_id=key_id,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            name=name,
            expires_at=expires_at,
            source=source,
            actor_email=actor_email,
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        if emergency_reason is None:
            # The WITNESS failed, so the revocation is refused and the key
            # stays. Leave the gap trace, then re-raise (fail closed).
            err = ApiKeyRevokeError(str(exc))
            _record_api_key_witness_gap(
                conn, err, helper_name="delete_api_key", event="api_key_revoked",
            )
            raise err from exc
        # Punch 709: the witness phase failed under the explicit emergency
        # flag. The rollback undid the delete; redo ONLY the delete and commit.
        witness_failure = exc
        try:
            conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
            conn.commit()
        except Exception as redo_exc:
            conn.rollback()
            raise ApiKeyRevokeError(str(redo_exc)) from redo_exc
    if witness_failure is not None:
        record_emergency_revoke(
            conn, kind="api_key", target_id=key_id,
            actor_user_id=actor_user_id, cli_principal=cli_principal,
            reason=emergency_reason, witness_exc=witness_failure,
        )

    log.info(
        "api_key_revoked",
        event="api_key_revoked",
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        key_id=key_id,
        target_user_id=target_user_id,
        name=name,
        expires_at=expires_at,
        source=source,
    )
    return True
