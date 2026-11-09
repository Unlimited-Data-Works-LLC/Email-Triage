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

import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from email_triage._isotime import now_utc_iso, to_utc_iso
from typing import Any

from email_triage.triage_logging import get_logger
from email_triage.web.db_writelock import db_write

log = get_logger("web.mfa")


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
rate limiter (#92 login_guard precedent extends here)."""

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

    Routes through the credential-hash SSOT
    (``email_triage.web._credhash.hash_credential``) — was a by-name duplicate
    of ``auth._hash_code``; census run14 #1 collapsed both onto the one
    definition so a future KDF migration can't desync hash from verify.
    """
    from email_triage.web._credhash import hash_credential
    return hash_credential(code)


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


class RecoveryIssueError(RuntimeError):
    """A recovery-code set or an operator-recovery token was NOT issued: its
    insert or its audit witness failed and was rolled back, so no secret exists.
    A caller catches this type and never prints a code or a token (fail closed,
    punch 668, the ``ApiKeyGrantError`` shape of punch 627)."""


def _witness_lost(
    conn: sqlite3.Connection,
    exc: BaseException,
    *,
    helper_name: str,
) -> RecoveryIssueError:
    """Roll back an issue whose audit WITNESS failed; return the typed error to
    raise. The grant is refused and its audit row is lost, so one
    ``audit_gap_events`` row is left (panel P F4). A refused INSERT is a refused
    business write with no witness due, so the writers roll that one back inline
    and leave no gap row; this helper commits the gap row, so it is only ever
    called AFTER the witness (the N-520 commit-before-witness ratchet). The
    caller holds the write lock (``@db_write``). Best effort: a failed gap write
    is logged and never masks ``exc``. Nothing here reads a code or a token."""
    conn.rollback()
    err = RecoveryIssueError(str(exc))
    try:
        from email_triage.db.audit import mark_audit_gap_recorded, record_audit_write_loss
        record_audit_write_loss(
            conn, loss_class="failed_unrecorded", table="auth_events",
            helper_name=helper_name,
        )
        mark_audit_gap_recorded(err)
    except Exception as gap_exc:
        log.error(
            "recovery issue witness failed AND its gap row failed",
            helper=helper_name,
            witness_error=type(exc).__name__,
            gap_error=type(gap_exc).__name__,
        )
    return err


def _require_attributed_transactional_grant(
    conn: sqlite3.Connection, actor_email: str, *, helper_name: str,
) -> None:
    """Refuse a grant BEFORE any INSERT unless it can be witnessed whole (punch
    668, panel R). Two preconditions, each fail CLOSED (PD#8):

    * ``actor_email`` is non-blank: the witness's ``email`` is the ACTOR, and an
      unattributed grant row must never look like a complete record (it used to
      write ``"unknown"``). ``ValueError``: a caller bug, not a runtime refusal.
    * ``conn`` is not autocommit (``isolation_level=None``): there every INSERT
      commits at once and the rollback is a no-op, so a failed witness would
      leave an unwitnessed credential row (the guard every ``db/audit.py``
      grant funnel carries). :class:`RecoveryIssueError`: nothing is issued.
    """
    if not isinstance(actor_email, str) or not actor_email.strip():
        raise ValueError(
            f"{helper_name} requires a non-blank actor_email: the grant "
            f"witness records WHO issued the credential"
        )
    if conn.isolation_level is None:
        raise RecoveryIssueError(
            f"{helper_name} requires a transaction-capable (non-autocommit) "
            f"connection so the credential insert + its chained auth_events "
            f"witness are atomic; got isolation_level=None (autocommit)"
        )


@db_write
def issue_recovery_codes(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    count: int = RECOVERY_CODE_COUNT_DEFAULT,
    actor_email: str,
    source: str = "unknown",
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
    _require_attributed_transactional_grant(
        conn, actor_email, helper_name="issue_recovery_codes",
    )
    if count <= 0:
        raise ValueError(f"count must be > 0; got {count}")
    if count > 100:
        # Practical cap — no operator legitimately needs >100 codes
        # in one set, and the upper bound protects against operator-
        # typo at CLI.
        raise ValueError(f"count must be <= 100; got {count}")
    # Punch 668: issuing recovery codes is a credential grant (§164.312(b)). The
    # code rows and their ``recovery_codes_issued`` witness commit in ONE
    # transaction (``record_auth_event_txn``, the N-520 shape), so a failed
    # witness rolls the codes back and raises: no code is returned or shown
    # (fail CLOSED, PD#8). The event binds the subject (``user_id`` = the target
    # user) and the count in ``detail``; ``email`` is the actor. It carries NO
    # code and NO hash: the codes are 48-bit, so a hash would be brute-forceable.
    now = now_utc_iso()
    plaintexts: list[str] = []
    try:
        for _ in range(count):
            code = _generate_recovery_code()
            plaintexts.append(code)
            conn.execute(
                "INSERT INTO recovery_codes (user_id, code_hash, created_at) "
                "VALUES (?, ?, ?)",
                (user_id, _hash_code(code), now),
            )
    except Exception as exc:
        # A refused insert: nothing was granted and no witness was due, so no
        # gap row (and no committing helper before the witness, N-520).
        conn.rollback()
        raise RecoveryIssueError(str(exc)) from exc
    try:
        from email_triage.db.audit import record_auth_event_txn
        record_auth_event_txn(
            conn, event_type="recovery_codes_issued",
            email=actor_email, user_id=user_id,
            outcome="success", detail=f"count={count} source={source}",
        )
        conn.commit()
    except Exception as exc:
        raise _witness_lost(conn, exc, helper_name="issue_recovery_codes") from exc
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
    now = now_utc_iso()
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


def lookup_recovery_code(
    conn: sqlite3.Connection, *, user_id: int, code: str,
) -> int | None:
    """READ-ONLY half of :func:`consume_recovery_code` (N-520 step 2): the id of
    the matching UNUSED code, else None. The burn is
    :func:`burn_recovery_code_txn`, inside the caller's witnessed unit."""
    row = conn.execute(
        "SELECT id, used_at FROM recovery_codes "
        "WHERE user_id = ? AND code_hash = ?",
        (user_id, _hash_code(code)),
    ).fetchone()
    if row is None or row["used_at"] is not None:
        return None
    return int(row["id"])


def burn_recovery_code_txn(conn: sqlite3.Connection, code_id: int) -> bool:
    """Stamp one recovery code used; no commit (N-520 step 2). True only when
    THIS call burned it (``used_at IS NULL`` guard), so two racing consumes
    cannot both mint a session."""
    cur = conn.execute(
        "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
        (now_utc_iso(), int(code_id)),
    )
    return cur.rowcount > 0


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
    actor_email: str,
    source: str = "unknown",
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
    _require_attributed_transactional_grant(
        conn, actor_email, helper_name="issue_operator_recovery_token",
    )
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
    # Punch 668: the break-glass token is a credential grant (§164.312(b)), and
    # a break-glass credential raises the bar, not lowers it. The key row and its
    # ``operator_recovery_key_issued`` witness commit in ONE transaction
    # (``record_auth_event_txn``, the N-520 shape), so a failed witness rolls the
    # key back and raises: the token is never returned or shown (fail CLOSED,
    # PD#8). The event binds the new key id (``key_id``) and the target user
    # (``user_id``); ``email`` is the actor. It carries NO token and NO hash.
    token = _generate_operator_recovery_token()
    try:
        cursor = conn.execute(
            "INSERT INTO operator_recovery_keys "
            "(target_user_id, operator_user_id, token_hash, "
            " created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                target_user_id,
                operator_user_id,
                _hash_code(token),
                to_utc_iso(now),
                to_utc_iso(expires_at),
            ),
        )
        new_id = cursor.lastrowid
    except Exception as exc:
        # A refused insert: nothing was granted and no witness was due, so no
        # gap row (and no committing helper before the witness, N-520).
        conn.rollback()
        raise RecoveryIssueError(str(exc)) from exc
    try:
        from email_triage.db.audit import record_auth_event_txn
        record_auth_event_txn(
            conn, event_type="operator_recovery_key_issued",
            email=actor_email, user_id=target_user_id,
            key_id=new_id, outcome="success",
            detail=(f"operator_user_id={operator_user_id} "
                    f"ttl_secs={ttl_secs} source={source}"),
        )
        conn.commit()
    except Exception as exc:
        raise _witness_lost(
            conn, exc, helper_name="issue_operator_recovery_token",
        ) from exc
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
    now = now_utc_iso()
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


def lookup_operator_recovery_token(
    conn: sqlite3.Connection, *, token: str,
) -> tuple[int, int] | None:
    """READ-ONLY half of :func:`consume_operator_recovery_token` (N-520 step 2):
    ``(token_row_id, target_user_id)`` for an unused, unexpired token, else
    None. Same checks, no write."""
    now = now_utc_iso()
    row = conn.execute(
        "SELECT id, target_user_id, expires_at, used_at "
        "FROM operator_recovery_keys WHERE token_hash = ?",
        (_hash_code(token),),
    ).fetchone()
    if row is None or row["used_at"] is not None or row["expires_at"] < now:
        return None
    return int(row["id"]), int(row["target_user_id"])


def burn_operator_recovery_token_txn(conn: sqlite3.Connection, row_id: int) -> bool:
    """Stamp one operator-recovery token used; no commit (N-520 step 2). True
    only when THIS call burned it (``used_at IS NULL`` guard)."""
    cur = conn.execute(
        "UPDATE operator_recovery_keys SET used_at = ? "
        "WHERE id = ? AND used_at IS NULL",
        (now_utc_iso(), int(row_id)),
    )
    return cur.rowcount > 0


@db_write
def burn_operator_recovery_token(conn: sqlite3.Connection, row_id: int) -> bool:
    """Own-commit form of :func:`burn_operator_recovery_token_txn`: the
    TIGHTENING burn of a token that is refused (its user is disabled or gone),
    which never depends on audit-chain health."""
    burned = burn_operator_recovery_token_txn(conn, row_id)
    conn.commit()
    return burned


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
