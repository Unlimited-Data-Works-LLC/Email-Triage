"""Tests for the disable-user fail-closed kill switch.

Covers every enforcement point — login, OTP delivery, API-key bearer
auth, watcher lifecycle, and triage pipeline — plus the admin-only
route wiring (self-disable forbidden, non-admin refused) and the
audit-event recording.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    generate_api_key,
    hash_api_key,
    store_api_key,
    store_otp,
    verify_api_key,
)
from email_triage.web.db import (
    is_user_disabled,
    list_user_status_events,
    set_user_disabled,
)


# ---------------------------------------------------------------------------
# db-layer helpers
# ---------------------------------------------------------------------------

class TestDbHelpers:
    def test_is_user_disabled_defaults_false(self, db, regular_user):
        assert is_user_disabled(db, regular_user["id"]) is False

    def test_is_user_disabled_after_flip(self, db, regular_user, admin_user):
        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])
        assert is_user_disabled(db, regular_user["id"]) is True

    def test_set_user_disabled_idempotent(self, db, regular_user, admin_user):
        # First flip: changed.
        changed = set_user_disabled(
            db, regular_user["id"], True, actor_user_id=admin_user["id"],
        )
        assert changed is True
        # Same state: no change, no new event.
        changed = set_user_disabled(
            db, regular_user["id"], True, actor_user_id=admin_user["id"],
        )
        assert changed is False
        events = list_user_status_events(db, target_user_id=regular_user["id"])
        assert len(events) == 1

    def test_missing_user_is_treated_as_disabled(self, db):
        # Fail-closed for deleted / non-existent users.
        assert is_user_disabled(db, 999_999) is True


# ---------------------------------------------------------------------------
# 1. Login — disabled user cannot log in
# ---------------------------------------------------------------------------

class TestDisabledLogin:
    def test_disabled_user_cannot_log_in(self, client, db, regular_user, admin_user):
        """Disabled user + correct OTP -> login rejected, no session cookie."""
        set_user_disabled(
            db, regular_user["id"], True, actor_user_id=admin_user["id"],
            reason="security incident",
        )
        # Even if an OTP row exists (e.g. stored before disable), verify fails.
        store_otp(db, regular_user["email"], "123456")
        resp = client.post(
            "/login/verify",
            data={"email": regular_user["email"], "code": "123456"},
            follow_redirects=False,
        )
        # Either verification blocked pre-code (200 with error) or a post-
        # verify disable block (200 with error). No session cookie either way.
        assert resp.status_code == 200
        assert SESSION_COOKIE_NAME not in resp.cookies
        assert "disabled" in resp.text.lower() or "invalid" in resp.text.lower()

    def test_session_cookie_rejects_disabled_user(self, client, db, regular_user, admin_user, user_cookies):
        """Pre-existing session cookies stop working the moment the user is disabled."""
        # Cookie worked fine before disable.
        resp = client.get("/dashboard", cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 200

        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])

        # Same cookie now redirects to /login (auth failed).
        resp = client.get("/dashboard", cookies=user_cookies, follow_redirects=False)
        assert resp.status_code in (303, 307, 401)
        if resp.status_code == 303:
            assert "/login" in resp.headers.get("location", "")


# ---------------------------------------------------------------------------
# 2. OTP — delivery silently skipped, no info leak
# ---------------------------------------------------------------------------

class TestDisabledOtpSkipped:
    def test_disabled_user_otp_skipped_silently(self, client, db, regular_user, admin_user):
        """No SMTP call and no new OTP row when the user is disabled."""
        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])

        # Spike SMTP config so the live send path would normally fire.
        client.app.state.config.smtp.host = "smtp.example.com"
        client.app.state.config.smtp.port = 587
        client.app.state.config.smtp.from_addr = "no-reply@example.com"

        with patch("email_triage.web.routers.ui.send_otp_email") as mock_send:
            resp = client.post(
                "/login/email",
                data={"email": regular_user["email"]},
            )
            assert resp.status_code == 200
            # SMTP never called.
            mock_send.assert_not_called()

        # Response does NOT reveal "disabled" — same verify screen a real
        # user would see, so account state can't be probed.
        assert "disabled" not in resp.text.lower()
        assert "no account" not in resp.text.lower()

        # No OTP row was persisted either.
        count = db.execute(
            "SELECT COUNT(*) AS cnt FROM otp_codes WHERE email = ?",
            (regular_user["email"],),
        ).fetchone()["cnt"]
        assert count == 0


# ---------------------------------------------------------------------------
# 3. API key bearer auth — rejected for disabled user
# ---------------------------------------------------------------------------

class TestDisabledApiKey:
    def test_disabled_user_api_key_rejected(self, db, regular_user, admin_user):
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "test", regular_user["id"])

        # Works before disable.
        assert verify_api_key(db, raw_key) is not None

        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])

        # Now the key rejects — even though the key row is valid and
        # not expired.
        assert verify_api_key(db, raw_key) is None

    def test_disabled_user_api_key_rejected_via_http(self, client, db, regular_user, admin_user):
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "test", regular_user["id"])
        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])
        resp = client.get(
            "/api/openclaw/accounts",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4. Watcher — stopped mid-flight when user is disabled
# ---------------------------------------------------------------------------

class TestDisabledWatchers:
    @pytest.mark.asyncio
    async def test_disabled_user_account_watcher_stopped(
        self, app, db, regular_user, admin_user,
    ):
        """stop_for_user() tears down every running watcher owned by the user."""
        import asyncio
        mgr = app.state.watcher_manager

        # Create a fake account owned by the user.
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (regular_user["id"], "acct-1", "imap", "{}", now, now),
        )
        acct_id = cur.lastrowid
        db.commit()

        async def _never():
            while True:
                await asyncio.sleep(10)

        fake_task = asyncio.create_task(_never())
        mgr._tasks[(acct_id, "INBOX")] = fake_task
        mgr._mb_state[(acct_id, "INBOX")] = {"status": "watching"}
        assert mgr.is_running(acct_id) is True

        stopped = await mgr.stop_for_user(regular_user["id"])
        assert acct_id in stopped
        assert mgr.is_running(acct_id) is False

    @pytest.mark.asyncio
    async def test_watcher_start_refused_for_disabled_user(
        self, app, db, regular_user, admin_user,
    ):
        """WatcherManager.start() refuses when the owner is disabled."""
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (regular_user["id"], "acct-1", "imap", "{}", now, now),
        )
        acct_id = cur.lastrowid
        db.commit()

        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])

        msg = await app.state.watcher_manager.start(acct_id)
        assert "disabled" in msg.lower()
        assert app.state.watcher_manager.is_running(acct_id) is False


# ---------------------------------------------------------------------------
# 5. Triage pipeline — skip disabled user's accounts
# ---------------------------------------------------------------------------

class TestDisabledTriage:
    @pytest.mark.asyncio
    async def test_disabled_user_account_skipped_in_scheduled_triage(
        self, app, db, regular_user, admin_user,
    ):
        """run_triage() refuses when the owning user is disabled.

        Covers every trigger — ``scheduled``, ``manual``, ``api``,
        ``watch``, ``push`` — because they all route through this one
        entry point.
        """
        from email_triage.web.triage_runner import run_triage

        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (regular_user["id"], "acct-1", "imap", "{}", now, now),
        )
        acct_id = cur.lastrowid
        db.commit()

        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])

        from email_triage.web.db import get_email_account
        acct = get_email_account(db, acct_id)

        run = await run_triage(
            db, app.state.config, app.state.secrets, acct,
            query="is:unread", limit=5,
            actor_user_id=None, trigger="scheduled",
        )
        assert run.get("error") == "user_disabled"
        assert run["total_messages"] == 0

    def test_manual_triage_blocked_via_http(self, client, db, regular_user, admin_user, user_cookies):
        """Manual UI triage for a disabled user hits the same guard."""
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (regular_user["id"], "acct-1", "imap", "{}", now, now),
        )
        acct_id = cur.lastrowid
        db.commit()
        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])
        # Session cookie is invalidated for disabled users — request lands
        # on auth-unauthorized rather than the route body.
        resp = client.post(
            "/triage/run",
            data={"account_id": acct_id, "limit": 5, "query": "is:unread"},
            cookies=user_cookies,
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 6. Audit events
# ---------------------------------------------------------------------------

class TestAuditEvents:
    def test_user_status_event_recorded_on_disable_and_enable(
        self, db, regular_user, admin_user,
    ):
        set_user_disabled(
            db, regular_user["id"], True, actor_user_id=admin_user["id"],
            reason="offboarding",
        )
        set_user_disabled(
            db, regular_user["id"], False, actor_user_id=admin_user["id"],
            reason="rehired",
        )
        events = list_user_status_events(db, target_user_id=regular_user["id"])
        # Newest-first ordering.
        assert len(events) == 2
        assert events[0]["event"] == "enabled"
        assert events[0]["reason"] == "rehired"
        assert events[0]["actor_user_id"] == admin_user["id"]
        assert events[1]["event"] == "disabled"
        assert events[1]["reason"] == "offboarding"


# ---------------------------------------------------------------------------
# 7/8. Route-level admin controls
# ---------------------------------------------------------------------------

class TestAdminRoutes:
    def test_admin_cannot_self_disable(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            f"/users/{admin_user['id']}/disable",
            cookies=admin_cookies,
            data={"reason": "oops"},
        )
        assert resp.status_code == 400
        # Unchanged.
        assert is_user_disabled(db, admin_user["id"]) is False

    def test_non_admin_cannot_disable_other_user(
        self, client, db, regular_user, admin_user, user_cookies,
    ):
        resp = client.post(
            f"/users/{admin_user['id']}/disable",
            cookies=user_cookies,
            data={"reason": "nope"},
        )
        assert resp.status_code == 403
        assert is_user_disabled(db, admin_user["id"]) is False

    def test_admin_can_disable_and_reenable_user(
        self, client, db, regular_user, admin_user, admin_cookies,
    ):
        resp = client.post(
            f"/users/{regular_user['id']}/disable",
            cookies=admin_cookies,
            data={"reason": "test"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert is_user_disabled(db, regular_user["id"]) is True

        resp = client.post(
            f"/users/{regular_user['id']}/enable",
            cookies=admin_cookies,
            data={"reason": "cleared"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert is_user_disabled(db, regular_user["id"]) is False


# ---------------------------------------------------------------------------
# 9. Re-enable restores login
# ---------------------------------------------------------------------------

class TestDisabledUserReEnabled:
    def test_disabled_user_re_enabled_can_log_in_again(
        self, client, db, regular_user, admin_user,
    ):
        set_user_disabled(db, regular_user["id"], True, actor_user_id=admin_user["id"])
        set_user_disabled(db, regular_user["id"], False, actor_user_id=admin_user["id"])

        code = "987654"
        store_otp(db, regular_user["email"], code)
        resp = client.post(
            "/login/verify",
            data={"email": regular_user["email"], "code": code},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert SESSION_COOKIE_NAME in resp.cookies
