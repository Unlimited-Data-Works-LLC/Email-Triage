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

import hashlib
import hmac
import secrets
import sqlite3
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from email_triage.triage_logging import get_logger

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


def _hash_code(code: str) -> str:
    """SHA-256 hash of an OTP code."""
    return hashlib.sha256(code.encode()).hexdigest()


# ---------------------------------------------------------------------------
# OTP generation and verification
# ---------------------------------------------------------------------------

def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP code."""
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def store_otp(conn: sqlite3.Connection, email: str, code: str) -> None:
    """Store a hashed OTP code in the database.

    Invalidates any existing unused codes for the same email first.
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
        (email, _hash_code(code), expires.isoformat()),
    )
    conn.commit()


def verify_otp(conn: sqlite3.Connection, email: str, code: str) -> bool:
    """Verify an OTP code.  Returns True on success, False otherwise.

    On success the code is marked as used.
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

    expires = datetime.fromisoformat(row["expires_at"])
    if now > expires:
        log.info("OTP verification failed: code expired", email=email)
        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        return False

    # Mark as used.
    conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()

    log.info("OTP verified", email=email)
    return True


def cleanup_expired_otps(conn: sqlite3.Connection) -> int:
    """Remove expired OTP codes.  Returns count deleted."""
    now = datetime.now(timezone.utc).isoformat()
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
) -> str:
    """Create a signed session token.

    ``auth_source`` ∈ {``otp``, ``dev_keypair``, ``webauthn``} stamps
    the auth path that minted this session into the cookie payload.
    Echoed into ``access_log`` on every authenticated request so an
    auditor can answer "how did this session get in?" without
    consulting external state. Old tokens (pre-#67) without this
    field decode as ``auth_source="otp"`` for back-compat.

    ``auth_key_id`` is the corresponding ``dev_keys.id`` or
    ``hardware_keys.id`` (or None for OTP). Lets the audit trail
    name the specific credential used, not just the path.
    """
    s = _get_serializer(secret_key)
    payload: dict[str, Any] = {"email": email, "role": role}
    # Only include the new fields when non-default to keep the cookie
    # bytes small for the OTP common case (and to make back-compat
    # round-trip identical).
    if auth_source and auth_source != "otp":
        payload["auth_source"] = auth_source
    if auth_key_id is not None:
        payload["auth_key_id"] = int(auth_key_id)
    return s.dumps(payload)


def verify_session_token(
    secret_key: str,
    token: str,
    max_age: int = SESSION_MAX_AGE,
) -> dict[str, Any] | None:
    """Verify a session token.

    Returns ``{"email", "role", "auth_source", "auth_key_id"}`` on
    success or None on failure. ``auth_source`` defaults to
    ``"otp"`` for tokens minted before #67 (back-compat —
    pre-existing sessions remain valid; the new fields populate
    only on next sign-in via a new auth path).
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
    return data


# ---------------------------------------------------------------------------
# User lookup
# ---------------------------------------------------------------------------

def get_user_by_email(conn: sqlite3.Connection, email: str) -> dict[str, Any] | None:
    """Look up a user by email.  Returns a dict or None.

    Includes ``disabled`` / ``disabled_at`` so every auth path can
    enforce the fail-closed kill-switch without a second query.
    """
    row = conn.execute(
        "SELECT id, email, name, role, notify_email, created_at, last_login, "
        "disabled, disabled_at FROM users WHERE email = ?",
        (email,),
    )
    result = row.fetchone()
    if result is None:
        return None
    return dict(result)


def update_last_login(conn: sqlite3.Connection, email: str) -> None:
    """Update the user's last_login timestamp."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE users SET last_login = ? WHERE email = ?", (now, email))
    conn.commit()


# ---------------------------------------------------------------------------
# Email delivery (SMTP)
# ---------------------------------------------------------------------------

def format_from_header(from_addr: str, from_name: str | None = None) -> str:
    """Compose an RFC-5322 ``From:`` value.

    With a display name, emit ``"Display Name" <addr@example.com>``.
    With an empty name, fall back to the bare address so operators who
    don't care about branding see no change.  Double-quotes inside the
    name are escaped so a malformed operator input can't break parsing.
    """
    if not from_name:
        return from_addr
    safe_name = from_name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{safe_name}" <{from_addr}>'


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

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = format_from_header(from_addr, from_name)
    msg["To"] = to_addr
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Date"] = email.utils.formatdate(localtime=True)
    if extra_headers:
        for key, value in extra_headers.items():
            msg[key] = value

    # Plain-text fallback (strip tags, collapse whitespace).
    plain = re.sub(r"<[^>]+>", "", html_body)
    plain = re.sub(r"\s+", " ", plain).strip()
    msg.attach(email.mime.text.MIMEText(plain, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if use_tls:
            server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)

    log.info("Digest email sent via SMTP", to=to_addr, subject=subject)


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "et_"  # Prefix for easy identification.


def generate_api_key() -> str:
    """Generate a new API key with a recognisable prefix."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """SHA-256 hash of an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def store_api_key(
    conn: sqlite3.Connection,
    key_hash: str,
    name: str,
    user_id: int,
    expires_at: str | None = None,
    *,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    source: str = "unknown",
) -> int:
    """Store a hashed API key and emit a lifecycle audit entry.

    Returns the key ID. The raw token is NEVER logged or persisted in
    the audit trail — only ``key_id`` is recorded as the correlation
    handle.

    Audit context (``actor_user_id``, ``actor_email``, ``source``) is
    keyword-only so callers must opt into providing it. When omitted
    the entry is still emitted with NULL actor fields and a
    ``source="unknown"`` marker — that way an unaudited mint shows up
    in the trail rather than disappearing silently.

    The audit-table insert is wrapped in try/except so a failure there
    cannot block the actual key creation. The structured log line
    always fires regardless.
    """
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO api_keys (key_hash, name, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (key_hash, name, user_id, now, expires_at),
    )
    conn.commit()
    new_id = cursor.lastrowid

    # Look up target email for the log line. Best-effort — auth must
    # not fail if the user row was deleted between calls.
    target_email: str | None = None
    try:
        row = conn.execute(
            "SELECT email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if row is not None:
            target_email = row["email"]
    except sqlite3.Error:
        pass

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
        source=source,
    )

    # Persist to the audit table. A failure here is logged but does
    # NOT block the mint — the key is already in api_keys.
    try:
        from email_triage.web.db import record_api_key_event
        record_api_key_event(
            conn,
            event="api_key_created",
            key_id=new_id,
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            name=name,
            expires_at=expires_at,
            source=source,
        )
    except Exception as exc:
        log.warning(
            "api_key_event_audit_insert_failed",
            event="api_key_created",
            key_id=new_id,
            error=str(exc),
        )

    return new_id


def verify_api_key(conn: sqlite3.Connection, key: str) -> dict[str, Any] | None:
    """Verify an API key and return the associated user, or None.

    Updates ``last_used_at`` on success.  Rejects expired keys.  Rejects
    keys whose owning user is ``disabled`` — the disable flag is a
    fail-closed kill-switch that must block API access even if the key
    is otherwise valid.  Blocked attempts are logged for audit.
    """
    key_hash = hash_api_key(key)
    row = conn.execute(
        """SELECT ak.id AS key_id, ak.user_id, ak.name AS key_name,
                  ak.expires_at, u.email, u.name, u.role, u.disabled
           FROM api_keys ak
           JOIN users u ON u.id = ak.user_id
           WHERE ak.key_hash = ?""",
        (key_hash,),
    ).fetchone()

    if row is None:
        return None

    # Check expiry.
    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires:
            log.info("API key expired", key_name=row["key_name"])
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
    now = datetime.now(timezone.utc).isoformat()
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
    }


def list_api_keys(conn: sqlite3.Connection, user_id: int | None = None) -> list[dict[str, Any]]:
    """List API keys. If user_id is given, filter to that user."""
    if user_id is not None:
        rows = conn.execute(
            """SELECT ak.id, ak.name, ak.user_id, u.email, u.name AS user_name, ak.created_at, ak.last_used_at, ak.expires_at
               FROM api_keys ak JOIN users u ON u.id = ak.user_id
               WHERE ak.user_id = ? ORDER BY ak.id""",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT ak.id, ak.name, ak.user_id, u.email, u.name AS user_name, ak.created_at, ak.last_used_at, ak.expires_at
               FROM api_keys ak JOIN users u ON u.id = ak.user_id
               ORDER BY ak.id""",
        ).fetchall()
    return [dict(r) for r in rows]


def delete_api_key(
    conn: sqlite3.Connection,
    key_id: int,
    *,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    source: str = "unknown",
) -> bool:
    """Delete an API key by ID and emit a lifecycle audit entry.

    Returns True if a row was deleted. Audit context is keyword-only;
    see ``store_api_key`` for the schema rationale.

    The audit row in ``api_key_events`` survives the deletion of the
    underlying ``api_keys`` row (no FK on ``key_id``) so revocations
    remain auditable indefinitely.
    """
    # Capture target+name BEFORE delete — once the row is gone we
    # can't recover those for the audit entry.
    target_user_id: int | None = None
    name: str = ""
    expires_at: str | None = None
    try:
        row = conn.execute(
            "SELECT user_id, name, expires_at FROM api_keys WHERE id = ?",
            (key_id,),
        ).fetchone()
        if row is not None:
            target_user_id = row["user_id"]
            name = row["name"] or ""
            expires_at = row["expires_at"]
    except sqlite3.Error:
        pass

    cursor = conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    conn.commit()
    deleted = cursor.rowcount > 0

    # Only emit the audit entry if a row actually existed; deleting a
    # non-existent key is a no-op, not an event worth recording.
    if not deleted:
        return False

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

    try:
        from email_triage.web.db import record_api_key_event
        record_api_key_event(
            conn,
            event="api_key_revoked",
            key_id=key_id,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            name=name,
            expires_at=expires_at,
            source=source,
        )
    except Exception as exc:
        log.warning(
            "api_key_event_audit_insert_failed",
            event="api_key_revoked",
            key_id=key_id,
            error=str(exc),
        )

    return True
