"""Tests for the login_guard module + its wiring at the OTP / WebAuthn /
dev-keypair / passkey login surfaces (#92)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.config import AuthConfig, TriageConfig
from email_triage.web.db import init_db as _init_db, record_auth_event
from email_triage.web.login_guard import (
    LoginLocked,
    check_login_allowed,
    record_login_failure,
    record_login_lockout,
)


@pytest.fixture(name="guard_db")
def _guard_db():
    """Fresh in-memory DB independent of the conftest ``db`` fixture
    so unit-level guard tests don't pull in app/client wiring."""
    return _init_db(":memory:")


@pytest.fixture
def config_default():
    cfg = TriageConfig()
    cfg.auth = AuthConfig()
    return cfg


@pytest.fixture
def config_aggressive():
    """Tight thresholds so tests don't have to spam 30+ rows."""
    cfg = TriageConfig()
    cfg.auth = AuthConfig(
        login_per_email_max=3,
        login_per_email_window_secs=60,
        login_per_ip_max=5,
        login_per_ip_window_secs=60,
    )
    return cfg


class TestCheckLoginAllowed:
    def test_no_failures_allows(self, guard_db, config_default):
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_default,
        )

    def test_per_email_under_threshold(self, guard_db, config_aggressive):
        for _ in range(2):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_aggressive,
        )

    def test_per_email_at_threshold_locks(self, guard_db, config_aggressive):
        for _ in range(3):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email="alice@example.com", ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "email"
        assert exc.value.retry_after_secs == 60

    def test_per_email_lowercase_normalized(
        self, guard_db, config_aggressive,
    ):
        # Failures recorded under lowercase form; lookup with mixed
        # case still trips.
        for _ in range(3):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        with pytest.raises(LoginLocked):
            check_login_allowed(
                guard_db, email="Alice@Example.COM", ip=None,
                config=config_aggressive,
            )

    def test_per_ip_at_threshold_locks(self, guard_db, config_aggressive):
        for i in range(5):
            record_auth_event(
                guard_db, event_type="login_otp",
                email=f"u{i}@example.com",
                ip="1.2.3.4", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email="never-seen@example.com", ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "ip"

    def test_window_expiry_releases_lock(
        self, guard_db, config_aggressive,
    ):
        old_ts = (
            datetime.now(timezone.utc) - timedelta(seconds=120)
        ).isoformat()
        for _ in range(3):
            guard_db.execute(
                "INSERT INTO auth_events "
                "(ts, event_type, email, outcome) "
                "VALUES (?, 'login_otp', 'alice@example.com', 'failure')",
                (old_ts,),
            )
        guard_db.commit()
        check_login_allowed(
            guard_db, email="alice@example.com", ip=None,
            config=config_aggressive,
        )

    def test_success_rows_not_counted(self, guard_db, config_aggressive):
        for _ in range(10):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="1.2.3.4", outcome="success",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_aggressive,
        )

    def test_max_zero_disables_email_scope(self, guard_db):
        cfg = TriageConfig()
        cfg.auth = AuthConfig(
            login_per_email_max=0,
            login_per_ip_max=5,
            login_per_email_window_secs=60,
            login_per_ip_window_secs=60,
        )
        for _ in range(100):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip=None, config=cfg,
        )

    def test_email_none_skips_email_check(
        self, guard_db, config_aggressive,
    ):
        # Passkey path: email=None — only IP guard applies.
        for _ in range(10):
            record_auth_event(
                guard_db, event_type="login_passkey",
                email="alice@example.com",
                ip="1.2.3.4", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email=None, ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "ip"


class TestRecordLoginFailure:
    def test_writes_failure_row(self, guard_db):
        record_login_failure(
            guard_db, surface="otp", email="alice@example.com",
            ip="1.2.3.4", user_agent="curl/8", reason="invalid_code",
        )
        row = guard_db.execute(
            "SELECT event_type, email, ip, outcome, detail "
            "FROM auth_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["event_type"] == "login_otp"
        assert row["email"] == "alice@example.com"
        assert row["ip"] == "1.2.3.4"
        assert row["outcome"] == "failure"
        assert row["detail"] == "invalid_code"


class TestRecordLoginLockout:
    def test_writes_lockout_row(self, guard_db):
        record_login_lockout(
            guard_db, surface="otp", email="alice@example.com",
            ip="1.2.3.4", user_agent="curl/8",
            scope="email", threshold=600,
        )
        row = guard_db.execute(
            "SELECT event_type, email, outcome, detail "
            "FROM auth_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["event_type"] == "login_lockout"
        assert row["email"] == "alice@example.com"
        assert row["outcome"] == "failure"
        assert "scope=email" in row["detail"]
        assert "threshold=600" in row["detail"]


class TestVerifyEndpointGuard:
    """End-to-end: POST /login/verify must lock after threshold."""

    def test_three_invalid_codes_locks_email(
        self, client, db, regular_user,
    ):
        # Tighten thresholds on the live config the app is using.
        db_app = client.app.state.config
        db_app.auth.login_per_email_max = 3
        db_app.auth.login_per_email_window_secs = 60
        db_app.auth.login_per_ip_max = 100
        db_app.auth.login_per_ip_window_secs = 60

        # Use the conftest regular_user; verify_otp will reject
        # without a stored code, writing a failure row each time.
        email = regular_user["email"]

        for _ in range(3):
            r = client.post(
                "/login/verify",
                data={"email": email, "code": "000000"},
            )
            assert r.status_code == 200

        # 4th attempt — guard trips before verify_otp runs.
        r = client.post(
            "/login/verify",
            data={"email": email, "code": "000000"},
        )
        assert r.status_code == 200
        assert "Too many login attempts" in r.text

        # Lockout audit row landed.
        n = db.execute(
            "SELECT COUNT(*) FROM auth_events "
            "WHERE event_type='login_lockout'"
        ).fetchone()[0]
        assert n >= 1

    def test_max_zero_admin_disables_guard(
        self, client, db, regular_user,
    ):
        db_app = client.app.state.config
        db_app.auth.login_per_email_max = 0
        db_app.auth.login_per_ip_max = 0

        email = regular_user["email"]
        # 20 attempts, no lockout text ever surfaces.
        for _ in range(20):
            r = client.post(
                "/login/verify",
                data={"email": email, "code": "000000"},
            )
            assert "Too many login attempts" not in r.text

        n = db.execute(
            "SELECT COUNT(*) FROM auth_events "
            "WHERE event_type='login_lockout'"
        ).fetchone()[0]
        assert n == 0
