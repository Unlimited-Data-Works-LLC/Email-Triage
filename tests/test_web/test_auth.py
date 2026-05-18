"""Tests for the email OTP auth module."""

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    cleanup_expired_otps,
    create_session_token,
    generate_otp,
    get_user_by_email,
    store_otp,
    update_last_login,
    verify_otp,
    verify_session_token,
)
from email_triage.web.db import init_db


@pytest.fixture
def db():
    conn = init_db(":memory:")
    # Seed a user.
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("alice@example.com", "Alice", "admin", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return conn


class TestOTPGeneration:
    def test_otp_length(self):
        code = generate_otp()
        assert len(code) == 6

    def test_otp_all_digits(self):
        code = generate_otp()
        assert code.isdigit()

    def test_otp_uniqueness(self):
        codes = {generate_otp() for _ in range(50)}
        assert len(codes) > 1


class TestOTPStorage:
    def test_store_and_verify(self, db):
        code = "123456"
        store_otp(db, "alice@example.com", code)
        assert verify_otp(db, "alice@example.com", code) is True

    def test_wrong_code(self, db):
        store_otp(db, "alice@example.com", "123456")
        assert verify_otp(db, "alice@example.com", "654321") is False

    def test_wrong_email(self, db):
        store_otp(db, "alice@example.com", "123456")
        assert verify_otp(db, "bob@example.com", "123456") is False

    def test_code_used_only_once(self, db):
        code = "123456"
        store_otp(db, "alice@example.com", code)
        assert verify_otp(db, "alice@example.com", code) is True
        assert verify_otp(db, "alice@example.com", code) is False

    def test_expired_code(self, db):
        code = "123456"
        store_otp(db, "alice@example.com", code)
        # Manually expire the code.
        db.execute(
            "UPDATE otp_codes SET expires_at = ?",
            ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),),
        )
        db.commit()
        assert verify_otp(db, "alice@example.com", code) is False

    def test_new_otp_invalidates_old(self, db):
        store_otp(db, "alice@example.com", "111111")
        store_otp(db, "alice@example.com", "222222")
        # Old code should be invalidated.
        assert verify_otp(db, "alice@example.com", "111111") is False
        assert verify_otp(db, "alice@example.com", "222222") is True

    def test_cleanup_expired(self, db):
        store_otp(db, "alice@example.com", "123456")
        db.execute(
            "UPDATE otp_codes SET expires_at = ?",
            ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),),
        )
        db.commit()
        removed = cleanup_expired_otps(db)
        assert removed == 1
        count = db.execute("SELECT COUNT(*) as cnt FROM otp_codes").fetchone()["cnt"]
        assert count == 0


class TestSessionTokens:
    def test_create_and_verify(self):
        secret = "test-secret-key-for-signing"
        token = create_session_token(secret, "alice@example.com", "admin")
        data = verify_session_token(secret, token)
        assert data is not None
        assert data["email"] == "alice@example.com"
        assert data["role"] == "admin"

    def test_wrong_secret(self):
        token = create_session_token("secret-1", "a@b.com", "user")
        assert verify_session_token("secret-2", token) is None

    def test_expired_token(self):
        secret = "test-secret"
        token = create_session_token(secret, "a@b.com", "user")
        # max_age=-1 forces expiry even within the same second.
        assert verify_session_token(secret, token, max_age=-1) is None

    def test_tampered_token(self):
        secret = "test-secret"
        token = create_session_token(secret, "a@b.com", "user")
        tampered = token[:-4] + "XXXX"
        assert verify_session_token(secret, tampered) is None


class TestUserLookup:
    def test_find_existing_user(self, db):
        user = get_user_by_email(db, "alice@example.com")
        assert user is not None
        assert user["name"] == "Alice"
        assert user["role"] == "admin"

    def test_missing_user(self, db):
        assert get_user_by_email(db, "nobody@example.com") is None

    def test_update_last_login(self, db):
        assert get_user_by_email(db, "alice@example.com")["last_login"] is None
        update_last_login(db, "alice@example.com")
        user = get_user_by_email(db, "alice@example.com")
        assert user["last_login"] is not None
