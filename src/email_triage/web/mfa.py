"""H-05 — MFA enforcement helpers + recovery-code flows (Cycle 7).

Closes the H-05 finding (§164.312(d) Authentication — UPGRADED from
LOW to MEDIUM per OCR posture + 2024-12 HHS NPRM proposing MFA as a
Required spec). Per `internal documentation` §4.1 H-05 row:
WebAuthn passkey required in HIPAA mode (no email-OTP fallback, no
grace period for the single-tenant target).

Disposition shape: **standard strict-implementation** per Cycle 7
Exp F pre-classify (confirmed by lead). NOT a new EQM-NN; §164.312(d)
is the canonical mechanism, and this module closes the GATE that
makes WebAuthn Required-enforced under HIPAA mode.

Scope (Cycle 7 re-scope per lead-confirmed audit-pattern catch — the
original dispatch's "build new WebAuthn module" was struck because
`webauthn>=2.0` + `src/email_triage/web/webauthn_auth.py` already
shipped under ):

  1. **Recovery codes** (printable single-use) — generate at
     enrollment, consume at /auth/mfa/recovery, hashed at rest via
     SHA-256 (mirrors the `otp_codes` precedent at
     `email_triage.web.auth._hash_code`). Default 10 codes per
     code-set (matches AWS / GitHub's lower bound).
  2. **Operator-recovery tokens** (last-resort recovery) — operator
     issues via `user reset-mfa <target>` CLI; printed to stdout
     ONCE; 24h TTL default; single-use; hashed at rest.
  3. **HIPAA-mode enforcement predicate** — `is_mfa_required_for(user)`
     decides whether MFA is required for a given login at this
     install: True iff (HIPAA mode is on AND the user has at least
     one active hardware_keys row OR has at least one unconsumed
     recovery_codes row OR the operator is performing an enrollment
     bootstrap). Mirrors the precedent at
     `auth_keys.py:542-548` "hardware_key_required" gate.
  4. **Session claim helper** — `mint_session_with_mfa_claim` extends
     `auth.create_session_token` with `mfa_verified_at: int` (epoch
     seconds) so the hard-cutover middleware can detect a session
     that was minted via OTP-only path in HIPAA mode.
  5. **Hard-cutover middleware predicate** — `session_needs_mfa_step_up`
     decides whether an authenticated session lacks the `mfa_verified_at`
     claim under HIPAA mode (= operator flipped HIPAA mode mid-session,
     OR user authenticated via a non-MFA surface). Caller (middleware
     wrapper around `get_current_user`) issues 303 to /login/mfa.

Read-only by default at the lookup layer; writes guarded by
`@db_write` for the @write_lock + commit discipline.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from email_triage.web.db_writelock import db_write


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECOVERY_CODE_COUNT_DEFAULT = 10
"""Default count per code-set. Matches the AWS / GitHub lower-bound
shape (AWS uses 10; GitHub uses 16). Operator can override at CLI
invocation time via ``--count N``; 10 is the sweet spot between
"enough for several recovery events" and "printable on one line"."""

RECOVERY_CODE_BYTES = 6
"""Per-code entropy. 6 bytes = 48 bits = 281T candidates. Encoded as
12 hex characters ≈ "a3f9b2c8e1d4" shape. Single-use + rate-limited
at consume time, so brute-force cost is bounded by the consume-path
rate limiter."""

OPERATOR_RECOVERY_TOKEN_BYTES = 16
"""Operator-key recovery tokens. 16 bytes = 128 bits = 2^128 candidates.
Used as a last-resort recovery mechanism — operator hand-delivers
out-of-band — so the token must be unguessable even on a leaked
channel. 32-char hex output."""

OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT = 86400
"""24h TTL default per design Q3 resolution. Single-use recovery
should be short-lived; an operator-issued token that's leaked but
unused has a bounded blast radius of one day. Operator override at
CLI invocation time via ``--ttl-secs N`` is supported but capped at
7 days (606800 secs) to keep the regulatory-defensibility footprint
small — anything longer should be a fresh `reset-mfa` call."""

OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP = 604800
"""7-day hard cap on operator-recovery token TTL. Beyond this, the
operator should issue a fresh token rather than extending one. Per
DA hedge-check on recovery-code-vs-operator-key overlap: keeping the
operator-recovery surface short-lived ensures it cannot be confused
with the printable recovery codes (long-lived until used)."""


# ---------------------------------------------------------------------------
# Hashing — mirrors the OTP / api_keys precedent in
# email_triage.web.auth._hash_code (SHA-256 hex). Recovery codes are
# higher entropy than 6-digit OTPs, so SHA-256 (vs bcrypt / PBKDF2) is
# acceptable: brute-force cost = 2^48 (recovery codes) or 2^128
# (operator-recovery tokens) preimage, both exceed the practical
# attack-cost ceiling without per-row work-factor.
# ---------------------------------------------------------------------------

def _hash_code(code: str) -> str:
    """SHA-256 hex of a recovery code or operator-recovery token.

    Identical mechanism to ``email_triage.web.auth._hash_code`` —
    duplicated by-name to keep the import surface narrow + because
    H-05 is the only caller of this hash today.
    """
    return hashlib.sha256(code.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Recovery codes (printable single-use)
# ---------------------------------------------------------------------------

def _generate_recovery_code() -> str:
    """One recovery code in printable hex form (12 chars).

    Operator prints a code-set physically; user keeps the printed
    sheet in a safe location (offline / off-host). Per Q5 design:
    printable + single-use is the canonical UX shape; matches the
    GitHub / AWS / Google recovery-code precedent.
    """
    return secrets.token_hex(RECOVERY_CODE_BYTES)


@db_write
def issue_recovery_codes(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    count: int = RECOVERY_CODE_COUNT_DEFAULT,
) -> list[str]:
    """Generate + store a new code-set; return the plaintext list ONCE.

    Caller (CLI `user enroll-mfa`) prints the returned list to stdout
    and warns the operator that this is the only opportunity to capture
    the plaintext. Subsequent reads of ``recovery_codes`` return only
    the hash + used_at flag.

    Per design Q2 resolution: default 10 codes (AWS / GitHub lower
    bound). Operator can request more via CLI ``--count`` override
    (e.g., for an enterprise install with multiple operators sharing
    one account).

    Idempotency-by-design: each call APPENDS a fresh code-set rather
    than replacing the prior one. An operator who re-runs enroll-mfa
    gets a NEW set of unused codes; the old set's unused codes remain
    valid until the user consumes or the user is reset via reset-mfa.
    Caller policy can revoke prior unused codes by passing
    ``replace_existing=True`` to a (future) revoke helper; not landed
    in v1 because the operator-discovery surface is the print-time
    warning, not a database constraint.
    """
    if count <= 0:
        raise ValueError(f"count must be > 0; got {count}")
    if count > 100:
        # Practical cap — no operator legitimately needs >100 codes
        # in one set, and the upper bound protects against operator-
        # typo at CLI.
        raise ValueError(f"count must be <= 100; got {count}")
    now = datetime.now(timezone.utc).isoformat()
    plaintexts: list[str] = []
    for _ in range(count):
        code = _generate_recovery_code()
        plaintexts.append(code)
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, created_at) "
            "VALUES (?, ?, ?)",
            (user_id, _hash_code(code), now),
        )
    conn.commit()
    return plaintexts


@db_write
def consume_recovery_code(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    code: str,
) -> bool:
    """Mark a recovery code as used. Returns True on first valid use,
    False on (unknown code / already-used code / wrong user).

    Per Q5 design: single-use. The first valid presentation succeeds
    + stamps ``used_at``; subsequent attempts return False so the
    caller (recovery endpoint) emits ``record_auth_event`` outcome
    ``"denied:recovery_code_already_used"``.

    Constant-time-ish: SHA-256 hash + EXACT-match SELECT (not LIKE).
    Caller is responsible for rate-limiting per the  login_guard
    precedent so brute-force is bounded.
    """
    now = datetime.now(timezone.utc).isoformat()
    h = _hash_code(code)
    row = conn.execute(
        "SELECT id, used_at FROM recovery_codes "
        "WHERE user_id = ? AND code_hash = ?",
        (user_id, h),
    ).fetchone()
    if row is None:
        return False
    if row["used_at"] is not None:
        return False
    conn.execute(
        "UPDATE recovery_codes SET used_at = ? WHERE id = ?",
        (now, row["id"]),
    )
    conn.commit()
    return True


def count_active_recovery_codes(
    conn: sqlite3.Connection,
    user_id: int,
) -> int:
    """Return the count of unused recovery codes for the user.

    Used by the MFA-enforcement predicate ``is_mfa_required_for`` to
    decide whether the user has any recovery surface to fall back on.
    A user with zero unused codes AND zero active hardware_keys is
    eligible for first-login WebAuthn enrollment (per Q7); otherwise
    the MFA gate fires.
    """
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM recovery_codes "
        "WHERE user_id = ? AND used_at IS NULL",
        (user_id,),
    ).fetchone()
    return int(row["c"]) if row else 0


# ---------------------------------------------------------------------------
# Operator-recovery tokens (last-resort)
# ---------------------------------------------------------------------------

def _generate_operator_recovery_token() -> str:
    """One operator-recovery token in printable hex form (32 chars).

    128 bits of entropy. Operator hand-delivers to the target user
    out-of-band (e.g., phone call, in-person handoff). 24h TTL default
    per design Q3 resolution.
    """
    return secrets.token_hex(OPERATOR_RECOVERY_TOKEN_BYTES)


@db_write
def issue_operator_recovery_token(
    conn: sqlite3.Connection,
    *,
    target_user_id: int,
    operator_user_id: int | None,
    ttl_secs: int = OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT,
) -> str:
    """Generate + store a one-time operator-recovery token; return the
    plaintext ONCE.

    Caller (CLI `user reset-mfa`) prints the returned token to stdout
    and warns the operator that this is the only opportunity to capture
    the plaintext. The target user consumes the token at
    ``POST /auth/mfa/recovery`` — that endpoint marks ``used_at`` +
    mints a session with the ``mfa_verified_at`` claim + redirects
    the user to enroll a new passkey.

    Args:
        target_user_id: the user whose MFA is being reset.
        operator_user_id: the admin actor performing the reset. ``None``
            when invoked from the CLI without an operator-user mapping
            (the CLI actor environment is captured separately in
            ``log_entries`` via the H-03-auto wrapper).
        ttl_secs: token TTL in seconds. Default 24h; hard-capped at 7d
            per ``OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP``.

    Raises:
        ValueError: ``ttl_secs`` is non-positive or exceeds the 7d cap.
    """
    if ttl_secs <= 0:
        raise ValueError(f"ttl_secs must be > 0; got {ttl_secs}")
    if ttl_secs > OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP:
        raise ValueError(
            f"ttl_secs must be <= {OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP} "
            f"(7d); got {ttl_secs}. Issue a fresh `user reset-mfa` "
            f"call rather than extending a single token."
        )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_secs)
    token = _generate_operator_recovery_token()
    conn.execute(
        "INSERT INTO operator_recovery_keys "
        "(target_user_id, operator_user_id, token_hash, "
        " created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            target_user_id,
            operator_user_id,
            _hash_code(token),
            now.isoformat(),
            expires_at.isoformat(),
        ),
    )
    conn.commit()
    return token


@db_write
def consume_operator_recovery_token(
    conn: sqlite3.Connection,
    *,
    token: str,
) -> int | None:
    """Mark an operator-recovery token as used + return the target_user_id.

    Returns:
        target_user_id on first valid use; None on (unknown token /
        already-used / expired).

    Per design Q3 resolution: 24h TTL default + single-use. Expired
    tokens are NOT auto-cleaned by this helper — a separate prune
    job (or operator-driven cleanup) sweeps the table; for v1 the
    table is small enough that prune cadence is operator-discretionary.
    """
    now = datetime.now(timezone.utc).isoformat()
    h = _hash_code(token)
    row = conn.execute(
        "SELECT id, target_user_id, expires_at, used_at "
        "FROM operator_recovery_keys WHERE token_hash = ?",
        (h,),
    ).fetchone()
    if row is None:
        return None
    if row["used_at"] is not None:
        return None
    if row["expires_at"] < now:
        return None
    conn.execute(
        "UPDATE operator_recovery_keys SET used_at = ? WHERE id = ?",
        (now, row["id"]),
    )
    conn.commit()
    return int(row["target_user_id"])


# ---------------------------------------------------------------------------
# MFA-enforcement predicate — the §164.312(d) gate
# ---------------------------------------------------------------------------

def is_mfa_required_for(
    conn: sqlite3.Connection,
    user: dict[str, Any],
) -> bool:
    """Return True if HIPAA mode is on AND the user has any MFA
    credential registered.

    The decision is composed of three observations:

    1. **HIPAA mode** — process-global toggle via
       ``email_triage.triage_logging.is_hipaa_mode``. Outside HIPAA
       mode this helper is always False (matches H-02a G1' +
       H-04-flag scoping discipline per medical-scope §2 principle 1).
    2. **At least one active hardware_keys row** OR
    3. **At least one unconsumed recovery_codes row**.

    The (2 OR 3) condition mirrors the existing
    ``user_has_active_hardware_key`` predicate at
    ``auth_keys.py:542-548`` "hardware_key_required" gate, EXTENDED
    so users mid-bootstrap (operator just issued recovery codes,
    user hasn't enrolled a passkey yet) don't get locked out.

    A first-login user in HIPAA mode with no credentials AND no
    recovery codes gets ``is_mfa_required_for=False`` here — that's
    by design: the caller routes them to the WebAuthn-first-login
    enrollment flow per Q7. The hard-cutover middleware
    (``session_needs_mfa_step_up``) still requires a non-OTP session
    for them to access protected routes.
    """
    from email_triage.triage_logging import is_hipaa_mode
    if not is_hipaa_mode():
        return False
    # Late-bind to avoid an import cycle (db_auth_helpers → web.db → ...)
    from email_triage.web.db_auth_helpers import user_has_active_hardware_key
    if user_has_active_hardware_key(conn, int(user["id"])):
        return True
    if count_active_recovery_codes(conn, int(user["id"])) > 0:
        return True
    return False


# ---------------------------------------------------------------------------
# Session-claim helpers — extend create_session_token with mfa_verified_at
# ---------------------------------------------------------------------------

def mfa_verified_now() -> int:
    """Return the current UTC epoch-seconds value for stamping
    ``mfa_verified_at`` on a session token."""
    return int(datetime.now(timezone.utc).timestamp())


def session_needs_mfa_step_up(
    session_data: dict[str, Any] | None,
) -> bool:
    """True if HIPAA mode is on AND the session lacks an
    ``mfa_verified_at`` claim.

    The hard-cutover middleware wraps ``get_current_user`` and calls
    this; on True it issues a 303 to /login/mfa. Per Q6 design:
    pre-cutover sessions (minted before HIPAA was flipped on) lack
    the claim → next request requires MFA step-up; they are NOT
    grandfathered.

    Non-HIPAA mode: always False (the claim doesn't exist outside
    HIPAA scope, and OTP / dev-keypair / non-MFA paths are valid).
    """
    from email_triage.triage_logging import is_hipaa_mode
    if not is_hipaa_mode():
        return False
    if not session_data:
        # No session at all — `require_auth` handles via /login
        # redirect; this helper only fires on authenticated requests.
        return False
    mfa_at = session_data.get("mfa_verified_at")
    if mfa_at is None:
        return True
    # Future hook: a TTL check could expire a stale MFA-verify claim,
    # forcing periodic re-verification. Not landed in v1 — the session
    # cookie's own TTL (HIPAA-aware via effective_session_ttl) governs
    # the step-up cadence implicitly.
    return False
