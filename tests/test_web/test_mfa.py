"""Tests for H-05 — MFA enforcement + recovery flows (Cycle 7).

Closes the H-05 finding (§164.312(d) Authentication — UPGRADED from
LOW to MEDIUM per OCR posture + 2024-12 HHS NPRM). Per the Cycle 7
re-scope confirmed by lead at handoff: WebAuthn machinery already
exists under  (`webauthn_auth.py` + `hardware_keys` table + 7
endpoints); this test suite covers the NEW surfaces the H-05 GATE
adds:

  1. Recovery-code issue + consume (single-use, hashed at rest)
  2. Operator-recovery token issue + consume (24h TTL, single-use)
  3. `is_mfa_required_for` predicate (HIPAA-mode + credential check)
  4. Session `mfa_verified_at` claim + `session_needs_mfa_step_up`
  5. HIPAA-mode OTP-login gate (`mfa_required` branch at login_verify)
  6. CLI `user enroll-mfa` + `user reset-mfa` flows
  7. Non-HIPAA pass-through (no enforcement, no claim required)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import email_triage.triage_logging as _triage_logging
from email_triage.web.auth import (
    create_session_token,
    verify_session_token,
)
from email_triage.web.db import init_db
from email_triage.web.mfa import (
    OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP,
    OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT,
    RECOVERY_CODE_COUNT_DEFAULT,
    consume_operator_recovery_token,
    consume_recovery_code,
    count_active_recovery_codes,
    is_mfa_required_for,
    issue_operator_recovery_token,
    issue_recovery_codes,
    mfa_verified_now,
    session_needs_mfa_step_up,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh in-memory DB + seeded test user. HIPAA mode default OFF."""
    conn = init_db(":memory:")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            "alice@example.com", "Alice", "admin",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def user(db):
    row = db.execute(
        "SELECT id, email, role FROM users WHERE email = ?",
        ("alice@example.com",),
    ).fetchone()
    return dict(row)


@pytest.fixture
def hipaa_on():
    """Set process-global HIPAA mode ON. Autouse conftest fixture
    restores after each test."""
    _triage_logging._hipaa_mode = True
    yield


@pytest.fixture
def hipaa_off():
    """Set process-global HIPAA mode OFF explicitly (some tests
    expect the predicate to be False regardless of credentials)."""
    _triage_logging._hipaa_mode = False
    yield


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

class TestRecoveryCodes:
    def test_issue_default_count(self, db, user):
        codes = issue_recovery_codes(db, user_id=user["id"])
        assert len(codes) == RECOVERY_CODE_COUNT_DEFAULT
        # All codes unique.
        assert len(set(codes)) == RECOVERY_CODE_COUNT_DEFAULT
        # All are 12-char hex strings.
        for c in codes:
            assert len(c) == 12
            int(c, 16)  # raises if not hex

    def test_issue_custom_count(self, db, user):
        codes = issue_recovery_codes(db, user_id=user["id"], count=5)
        assert len(codes) == 5

    def test_issue_zero_raises(self, db, user):
        with pytest.raises(ValueError, match="count must be > 0"):
            issue_recovery_codes(db, user_id=user["id"], count=0)

    def test_issue_over_cap_raises(self, db, user):
        with pytest.raises(ValueError, match="count must be <= 100"):
            issue_recovery_codes(db, user_id=user["id"], count=101)

    def test_consume_valid_code_succeeds_once(self, db, user):
        codes = issue_recovery_codes(db, user_id=user["id"], count=3)
        assert consume_recovery_code(
            db, user_id=user["id"], code=codes[0],
        ) is True
        # Second consume of the SAME code returns False (single-use).
        assert consume_recovery_code(
            db, user_id=user["id"], code=codes[0],
        ) is False

    def test_consume_wrong_user(self, db, user):
        codes = issue_recovery_codes(db, user_id=user["id"], count=1)
        # Different user_id, same plaintext code → fail.
        assert consume_recovery_code(
            db, user_id=user["id"] + 999, code=codes[0],
        ) is False

    def test_consume_unknown_code(self, db, user):
        issue_recovery_codes(db, user_id=user["id"], count=1)
        assert consume_recovery_code(
            db, user_id=user["id"], code="ffffffffffff",
        ) is False

    def test_count_active(self, db, user):
        codes = issue_recovery_codes(db, user_id=user["id"], count=5)
        assert count_active_recovery_codes(db, user["id"]) == 5
        consume_recovery_code(db, user_id=user["id"], code=codes[0])
        assert count_active_recovery_codes(db, user["id"]) == 4
        consume_recovery_code(db, user_id=user["id"], code=codes[1])
        assert count_active_recovery_codes(db, user["id"]) == 3

    def test_codes_hashed_at_rest(self, db, user):
        """Verify plaintext is NEVER stored — only SHA-256 hashes."""
        codes = issue_recovery_codes(db, user_id=user["id"], count=2)
        rows = db.execute(
            "SELECT code_hash FROM recovery_codes WHERE user_id = ?",
            (user["id"],),
        ).fetchall()
        for r in rows:
            # Stored hash is 64-char hex (SHA-256), NOT the plaintext.
            assert len(r["code_hash"]) == 64
            assert r["code_hash"] not in codes


# ---------------------------------------------------------------------------
# Operator-recovery tokens
# ---------------------------------------------------------------------------

class TestOperatorRecoveryTokens:
    def test_issue_returns_plaintext_once(self, db, user):
        token = issue_operator_recovery_token(
            db,
            target_user_id=user["id"],
            operator_user_id=None,
        )
        assert len(token) == 32  # 16 bytes = 32 hex chars
        int(token, 16)  # is hex

    def test_consume_valid_token(self, db, user):
        token = issue_operator_recovery_token(
            db, target_user_id=user["id"], operator_user_id=None,
        )
        target_id = consume_operator_recovery_token(db, token=token)
        assert target_id == user["id"]

    def test_consume_single_use(self, db, user):
        token = issue_operator_recovery_token(
            db, target_user_id=user["id"], operator_user_id=None,
        )
        assert consume_operator_recovery_token(db, token=token) == user["id"]
        # Second consume → None.
        assert consume_operator_recovery_token(db, token=token) is None

    def test_consume_unknown_token(self, db):
        assert consume_operator_recovery_token(
            db, token="f" * 32,
        ) is None

    def test_consume_expired_token(self, db, user):
        token = issue_operator_recovery_token(
            db, target_user_id=user["id"], operator_user_id=None,
            ttl_secs=60,
        )
        # Force-expire the token.
        past = (
            datetime.now(timezone.utc) - timedelta(seconds=120)
        ).isoformat()
        db.execute(
            "UPDATE operator_recovery_keys SET expires_at = ? WHERE token_hash IS NOT NULL",
            (past,),
        )
        db.commit()
        assert consume_operator_recovery_token(db, token=token) is None

    def test_default_ttl_is_24h(self, db, user):
        before = datetime.now(timezone.utc)
        issue_operator_recovery_token(
            db, target_user_id=user["id"], operator_user_id=None,
        )
        row = db.execute(
            "SELECT created_at, expires_at FROM operator_recovery_keys "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        created = datetime.fromisoformat(row["created_at"])
        expires = datetime.fromisoformat(row["expires_at"])
        delta_secs = (expires - created).total_seconds()
        # Within 1s of the documented default.
        assert abs(delta_secs - OPERATOR_RECOVERY_TOKEN_TTL_SECS_DEFAULT) < 1

    def test_ttl_cap_enforced(self, db, user):
        with pytest.raises(ValueError, match="must be <="):
            issue_operator_recovery_token(
                db, target_user_id=user["id"], operator_user_id=None,
                ttl_secs=OPERATOR_RECOVERY_TOKEN_TTL_SECS_CAP + 1,
            )

    def test_ttl_zero_raises(self, db, user):
        with pytest.raises(ValueError, match="must be > 0"):
            issue_operator_recovery_token(
                db, target_user_id=user["id"], operator_user_id=None,
                ttl_secs=0,
            )

    def test_token_hashed_at_rest(self, db, user):
        token = issue_operator_recovery_token(
            db, target_user_id=user["id"], operator_user_id=None,
        )
        row = db.execute(
            "SELECT token_hash FROM operator_recovery_keys "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert len(row["token_hash"]) == 64  # SHA-256 hex
        assert row["token_hash"] != token


# ---------------------------------------------------------------------------
# is_mfa_required_for predicate
# ---------------------------------------------------------------------------

class TestMfaRequiredPredicate:
    def test_non_hipaa_mode_is_false(self, db, user, hipaa_off):
        """Outside HIPAA mode, predicate is always False, even when
        the user has registered credentials (matches the medical-scope
        §2 principle 1 HIPAA-scope discipline)."""
        issue_recovery_codes(db, user_id=user["id"], count=1)
        assert is_mfa_required_for(db, user) is False

    def test_hipaa_mode_no_credentials_is_false(self, db, user, hipaa_on):
        """HIPAA mode + no credentials → first-login enrollment path
        (predicate False; caller routes to enrollment per Q7)."""
        assert is_mfa_required_for(db, user) is False

    def test_hipaa_mode_with_recovery_codes_is_true(
        self, db, user, hipaa_on,
    ):
        """HIPAA + at least one unconsumed recovery code → MFA required."""
        issue_recovery_codes(db, user_id=user["id"], count=1)
        assert is_mfa_required_for(db, user) is True

    def test_hipaa_mode_consumed_all_codes_is_false(
        self, db, user, hipaa_on,
    ):
        """When ALL codes are consumed, the predicate falls back to
        first-login-enrollment shape (no credentials available)."""
        codes = issue_recovery_codes(db, user_id=user["id"], count=2)
        consume_recovery_code(db, user_id=user["id"], code=codes[0])
        consume_recovery_code(db, user_id=user["id"], code=codes[1])
        # No active hardware key + zero unused codes → first-login
        # path. Operator should re-issue codes if user is in this
        # state without a passkey.
        assert is_mfa_required_for(db, user) is False


# ---------------------------------------------------------------------------
# Session mfa_verified_at claim
# ---------------------------------------------------------------------------

class TestSessionMfaClaim:
    SECRET = "test-session-secret-mfa"

    def test_create_session_with_claim(self):
        ts = mfa_verified_now()
        token = create_session_token(
            self.SECRET, "alice@example.com", "admin",
            mfa_verified_at=ts,
        )
        data = verify_session_token(self.SECRET, token)
        assert data is not None
        assert data["mfa_verified_at"] == ts

    def test_create_session_without_claim_defaults_none(self):
        token = create_session_token(
            self.SECRET, "alice@example.com", "admin",
        )
        data = verify_session_token(self.SECRET, token)
        assert data is not None
        assert data["mfa_verified_at"] is None

    def test_step_up_needed_when_hipaa_on_and_no_claim(self, hipaa_on):
        session = {"email": "alice", "mfa_verified_at": None}
        assert session_needs_mfa_step_up(session) is True

    def test_step_up_not_needed_when_hipaa_off(self, hipaa_off):
        session = {"email": "alice", "mfa_verified_at": None}
        assert session_needs_mfa_step_up(session) is False

    def test_step_up_not_needed_when_claim_present(self, hipaa_on):
        session = {
            "email": "alice",
            "mfa_verified_at": mfa_verified_now(),
        }
        assert session_needs_mfa_step_up(session) is False

    def test_step_up_not_needed_when_no_session(self, hipaa_on):
        """No session at all — require_auth handles the missing-session
        case; this helper short-circuits to avoid an unhelpful step-up
        redirect on the login screen itself."""
        assert session_needs_mfa_step_up(None) is False
        assert session_needs_mfa_step_up({}) is False

    def test_first_login_bootstrap_session_has_claim(self, hipaa_on):
        """DA-4 R-Surface-1 verify-don't-accept review 2026-05-24
        regression-pin: HIPAA-mode + first-login bootstrap (user has
        zero hardware_keys + zero recovery_codes) must produce a
        session with mfa_verified_at stamped so require_auth doesn't
        infinite-loop the user to /login/webauthn when they have no
        passkey to use yet.

        login_verify at users.py:466-487 stamps mfa_verified_now()
        when is_hipaa_mode() is True at OTP-login success (the
        mfa_required branch already redirected the credentialed-user
        case). The OTP auth IS the verified-identity proof for the
        bootstrap window; /profile/hardware-keys is now reachable for
        enrollment.

        Without this fix: user lands on /dashboard → step-up needed
        → 303 to /login/webauthn → no passkey → lockout. With fix:
        session carries claim → step-up not needed → user reaches
        /profile/hardware-keys to enroll.
        """
        bootstrap_session = {
            "email": "alice",
            "mfa_verified_at": mfa_verified_now(),
        }
        # Bootstrap session must NOT trigger step-up loop
        assert session_needs_mfa_step_up(bootstrap_session) is False


# ---------------------------------------------------------------------------
# Auth_source on recovery flows
# ---------------------------------------------------------------------------

class TestAuthSourceStamps:
    def test_recovery_code_auth_source(self):
        token = create_session_token(
            "secret", "alice@example.com", "admin",
            auth_source="recovery_code",
            mfa_verified_at=mfa_verified_now(),
        )
        data = verify_session_token("secret", token)
        assert data["auth_source"] == "recovery_code"
        assert data["mfa_verified_at"] is not None

    def test_operator_recovery_auth_source(self):
        token = create_session_token(
            "secret", "alice@example.com", "admin",
            auth_source="operator_recovery",
            mfa_verified_at=mfa_verified_now(),
        )
        data = verify_session_token("secret", token)
        assert data["auth_source"] == "operator_recovery"
        assert data["mfa_verified_at"] is not None
