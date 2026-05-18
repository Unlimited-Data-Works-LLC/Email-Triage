"""Tests for email accounts CRUD."""

import pytest


class TestAccountsUI:
    def test_accounts_page_loads(self, client, admin_cookies):
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Email Accounts" in resp.text

    def test_accounts_page_requires_auth(self, client):
        resp = client.get("/accounts", follow_redirects=False)
        assert resp.status_code == 303

    def test_regular_user_sees_accounts(self, client, user_cookies):
        resp = client.get("/accounts", cookies=user_cookies)
        assert resp.status_code == 200
        # Regular user should NOT see the Owner column
        assert "Owner" not in resp.text

    def test_admin_sees_owner_column(self, client, admin_cookies):
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Owner" in resp.text

    def test_create_imap_account(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/create", data={
            "name": "Test IMAP",
            "provider_type": "imap",
            "user_id": str(admin_user["id"]),
            "host": "mail.example.com",
            "port": "993",
            "username": "test@example.com",
            "password": "secret123",
            "mailbox": "INBOX",
            "use_ssl": "1",
        }, cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303

        # Verify it shows up in the list.
        resp2 = client.get("/accounts", cookies=admin_cookies)
        assert "Test IMAP" in resp2.text
        assert "mail.example.com" in resp2.text

    def test_create_gmail_account(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/create", data={
            "name": "Personal Gmail",
            "provider_type": "gmail_api",
            "user_id": str(admin_user["id"]),
            "account": "me@gmail.com",
            "client_id": "abc-123.apps.googleusercontent.com",
        }, cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303

        resp2 = client.get("/accounts", cookies=admin_cookies)
        assert "Personal Gmail" in resp2.text
        assert "me@gmail.com" in resp2.text

    def test_create_office365_account(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/create", data={
            "name": "Work O365",
            "provider_type": "office365",
            "user_id": str(admin_user["id"]),
            "client_id": "abc-123",
            "tenant_id": "myorg",
        }, cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303

        resp2 = client.get("/accounts", cookies=admin_cookies)
        assert "Work O365" in resp2.text

    def test_edit_form_loads(self, client, admin_cookies, db, admin_user):
        from email_triage.web.db import create_email_account
        aid = create_email_account(db, admin_user["id"], "Edit Me", "imap", {"host": "x.com"})

        resp = client.get(f"/accounts/{aid}/edit", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Edit Me" in resp.text

    def test_update_account(self, client, admin_cookies, db, admin_user):
        from email_triage.web.db import create_email_account
        aid = create_email_account(db, admin_user["id"], "Old Name", "imap", {"host": "old.com"})

        resp = client.put(f"/accounts/{aid}", data={
            "name": "New Name",
            "provider_type": "imap",
            "host": "new.com",
            "port": "993",
            "username": "u@new.com",
            "mailbox": "INBOX",
            "use_ssl": "1",
            "is_active": "1",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert "New Name" in resp.text
        assert "new.com" in resp.text

    def test_edit_gmail_account_does_not_store_client_creds(
        self, client, admin_cookies, db, admin_user,
    ):
        """B1: OAuth client_id/client_secret are install-level now;
        the account form no longer carries them. Editing a Gmail
        account must leave any per-account copies scrubbed."""
        from email_triage.web.db import create_email_account, get_email_account
        aid = create_email_account(
            db, admin_user["id"], "Gmail Test", "gmail_api",
            {"account": "me@gmail.com"},
        )
        resp = client.put(f"/accounts/{aid}", data={
            "name": "Gmail Test Renamed",
            "provider_type": "gmail_api",
            "account": "me@gmail.com",
            "is_active": "1",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        acct = get_email_account(db, aid)
        assert "client_id" not in acct["config"]
        assert "client_secret" not in acct["config"]
        assert acct["name"] == "Gmail Test Renamed"

    def test_gmail_form_fields_have_no_client_creds(self, client, admin_cookies):
        """B1: client_id and client_secret inputs should not appear on
        the Gmail account form — they live on /config now."""
        resp = client.get("/accounts/form-fields?provider_type=gmail_api", cookies=admin_cookies)
        assert resp.status_code == 200
        # The form should still have the account email field.
        assert 'name="account"' in resp.text
        # But not client credentials.
        assert 'name="client_id"' not in resp.text
        assert 'name="client_secret"' not in resp.text

    def test_delete_account(self, client, admin_cookies, db, admin_user):
        from email_triage.web.db import create_email_account
        aid = create_email_account(db, admin_user["id"], "Delete Me", "imap", {"host": "x.com"})

        resp = client.delete(f"/accounts/{aid}", cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.text == ""

    def test_regular_user_cannot_edit_others_account(self, client, user_cookies, db, admin_user):
        from email_triage.web.db import create_email_account
        aid = create_email_account(db, admin_user["id"], "Admin Account", "imap", {"host": "x.com"})

        resp = client.get(f"/accounts/{aid}/edit", cookies=user_cookies)
        assert resp.status_code == 403

    def test_regular_user_can_create_own(self, client, user_cookies, regular_user):
        resp = client.post("/accounts/create", data={
            "name": "My IMAP",
            "provider_type": "imap",
            "host": "mail.me.com",
            "port": "993",
            "username": "me@me.com",
            "mailbox": "INBOX",
            "use_ssl": "1",
        }, cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303

    def test_form_fields_fragment(self, client, admin_cookies):
        for ptype in ("imap", "gmail_api", "office365"):
            resp = client.get(f"/accounts/form-fields?provider_type={ptype}", cookies=admin_cookies)
            assert resp.status_code == 200
            assert "<fieldset>" in resp.text

    def test_row_cancel(self, client, admin_cookies, db, admin_user):
        from email_triage.web.db import create_email_account
        aid = create_email_account(db, admin_user["id"], "Row Test", "imap", {"host": "x.com"})

        resp = client.get(f"/accounts/{aid}/row", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Row Test" in resp.text


class TestGmailPushWatchEndpoints:
    """Accounts page endpoints that register/unregister Gmail watches."""

    def _make_gmail_account(self, db, admin_user):
        from email_triage.web.db import create_email_account
        return create_email_account(
            db, admin_user["id"], "G", "gmail_api",
            {"account": "user@gmail.com", "client_id": "cid"},
        )

    def test_start_requires_topic_configured(self, client, admin_cookies, db, admin_user):
        aid = self._make_gmail_account(db, admin_user)
        # No push.gmail_topic_name configured → hint back. As of
        # 2026-04-29 the admin-only message points at /admin/integrations
        # rather than the legacy /config + literal-key surface.
        resp = client.post(f"/accounts/{aid}/gmail-api/watch/start", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "/admin/integrations" in resp.text

    def test_start_registers_watch_and_persists_row(
        self, client, admin_cookies, db, admin_user,
    ):
        from unittest.mock import AsyncMock, patch
        from email_triage.providers.gmail_api import GmailApiProvider

        aid = self._make_gmail_account(db, admin_user)
        client.app.state.config.push.gmail_topic_name = "projects/test/topics/push"

        fake = GmailApiProvider(client_id="cid", refresh_token="rt")
        fake.register_watch = AsyncMock(return_value={
            "historyId": "1000",
            "expiration": 1_800_000_000_000,  # arbitrary future epoch ms
        })
        fake.close = AsyncMock()
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake,
        ):
            resp = client.post(
                f"/accounts/{aid}/gmail-api/watch/start",
                cookies=admin_cookies,
            )
        assert resp.status_code == 200
        assert "Push active" in resp.text

        from email_triage.web.db import get_gmail_watch
        row = get_gmail_watch(db, aid)
        assert row is not None
        assert row["history_id"] == "1000"
        assert row["email_address"] == "user@gmail.com"

    def test_stop_deletes_row(self, client, admin_cookies, db, admin_user):
        from unittest.mock import AsyncMock, patch
        from email_triage.providers.gmail_api import GmailApiProvider
        from email_triage.web.db import (
            upsert_gmail_watch, get_gmail_watch,
        )
        from datetime import datetime, timedelta, timezone

        aid = self._make_gmail_account(db, admin_user)
        upsert_gmail_watch(
            db, account_id=aid, email_address="user@gmail.com",
            topic_name="projects/test/topics/push", history_id="100",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=5)).isoformat(),
        )

        fake = GmailApiProvider(client_id="cid", refresh_token="rt")
        fake.stop_watch = AsyncMock()
        fake.close = AsyncMock()
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake,
        ):
            resp = client.post(
                f"/accounts/{aid}/gmail-api/watch/stop",
                cookies=admin_cookies,
            )
        assert resp.status_code == 200
        assert "Push off" in resp.text
        assert get_gmail_watch(db, aid) is None
        fake.stop_watch.assert_awaited_once()


class TestAccountsTestButtonFactoryWiring:
    """#20: the Test button on gmail_api accounts must resolve OAuth
    client creds via the install-level GoogleOAuthConfig, not from
    per-account config (which is empty since B1).
    """

    def _make_gmail_account(self, db, admin_user):
        from email_triage.web.db import create_email_account
        return create_email_account(
            db, admin_user["id"], "G20", "gmail_api",
            {"account": "user@gmail.com"},  # no client_id here (B1)
        )

    def test_accounts_test_gmail_api_uses_install_oauth(
        self, client, admin_cookies, db, admin_user,
    ):
        """Test button for gmail_api accounts goes through the provider
        factory so install-level OAuth creds are used, not an empty
        per-account client_id."""
        from unittest.mock import AsyncMock, patch
        from email_triage.providers.gmail_api import GmailApiProvider

        aid = self._make_gmail_account(db, admin_user)
        # Authenticated — refresh-token present in the secrets store.
        from email_triage.web.routers.ui import _secret_key_for_account
        sk = _secret_key_for_account(aid, "gmail_api")
        client.app.state.secrets.set(sk, "refresh-token-value")

        fake = GmailApiProvider(client_id="install-cid", refresh_token="rt")
        fake.list_labels = AsyncMock(return_value=[
            {"id": "INBOX", "name": "INBOX"},
            {"id": "SPAM", "name": "SPAM"},
        ])
        fake.close = AsyncMock()
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake,
        ) as factory:
            resp = client.post(
                f"/accounts/{aid}/test", cookies=admin_cookies,
            )
        assert resp.status_code == 200
        # Success body — no "client_id not configured" message leaked.
        assert "Connected" in resp.text
        assert "2 labels" in resp.text
        assert "client_id not configured" not in resp.text
        factory.assert_called_once()

    def test_accounts_test_gmail_api_not_authenticated_hint(
        self, client, admin_cookies, db, admin_user,
    ):
        """If no refresh token is stored, Test returns the usual hint —
        and does NOT try to construct a provider with empty creds."""
        aid = self._make_gmail_account(db, admin_user)
        resp = client.post(f"/accounts/{aid}/test", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Not authenticated" in resp.text


class TestAccountHipaaFlag:
    """Per-account HIPAA flag with sticky inheritance and lock enforcement."""

    def _reset_system(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_flag_defaults_off_when_system_off(self, db, admin_user):
        self._reset_system()
        from email_triage.web.db import create_email_account, get_email_account
        aid = create_email_account(db, admin_user["id"], "A", "imap", {})
        acct = get_email_account(db, aid)
        assert acct["hipaa"] == 0
        assert acct["created_under_system_hipaa"] == 0

    def test_sticky_inheritance_when_system_on(self, db, admin_user):
        self._reset_system()
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            from email_triage.web.db import create_email_account, get_email_account
            aid = create_email_account(db, admin_user["id"], "B", "imap", {})
            acct = get_email_account(db, aid)
            assert acct["hipaa"] == 1
            assert acct["created_under_system_hipaa"] == 1
        finally:
            self._reset_system()

    def test_explicit_hipaa_override(self, db, admin_user):
        self._reset_system()
        from email_triage.web.db import create_email_account, get_email_account
        aid = create_email_account(
            db, admin_user["id"], "C", "imap", {}, hipaa=True,
        )
        acct = get_email_account(db, aid)
        assert acct["hipaa"] == 1
        # Not created under system HIPAA — so NOT locked.
        assert acct["created_under_system_hipaa"] == 0

    def test_set_account_hipaa_records_boundary_event(self, db, admin_user):
        self._reset_system()
        from email_triage.web.db import (
            create_email_account, list_hipaa_boundary_events, set_account_hipaa,
        )
        aid = create_email_account(db, admin_user["id"], "D", "imap", {})
        set_account_hipaa(db, aid, True, actor_id=admin_user["id"])
        events = list_hipaa_boundary_events(db)
        assert any(
            e["scope"] == f"account:{aid}" and e["direction"] == "on"
            for e in events
        )

    def test_cannot_unset_when_locked(self, db, admin_user):
        self._reset_system()
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            from email_triage.web.db import create_email_account, set_account_hipaa
            aid = create_email_account(db, admin_user["id"], "E", "imap", {})
            with pytest.raises(PermissionError):
                set_account_hipaa(db, aid, False, actor_id=admin_user["id"])
        finally:
            self._reset_system()

    def test_can_unset_after_system_flag_off(self, db, admin_user):
        self._reset_system()
        from email_triage import triage_logging
        from email_triage.web.db import (
            create_email_account, set_account_hipaa, get_email_account,
        )
        # Create while system HIPAA was on.
        triage_logging._hipaa_mode = True
        try:
            aid = create_email_account(db, admin_user["id"], "F", "imap", {})
        finally:
            self._reset_system()
        # System flag now off — should be unlockable.
        set_account_hipaa(db, aid, False, actor_id=admin_user["id"])
        acct = get_email_account(db, aid)
        assert acct["hipaa"] == 0

    def test_row_shows_hipaa_chip(self, client, admin_cookies, db, admin_user):
        self._reset_system()
        from email_triage.web.db import create_email_account
        aid = create_email_account(
            db, admin_user["id"], "Chip Test", "imap", {}, hipaa=True,
        )
        resp = client.get(f"/accounts/{aid}/row", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "HIPAA" in resp.text
        # Lock glyph 🔐 only when system HIPAA is on AND created under it.
        # Here system is off and flag is explicit — the plain lock, not locked.

    def test_edit_form_disables_checkbox_when_locked(
        self, client, admin_cookies, db, admin_user,
    ):
        self._reset_system()
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            from email_triage.web.db import create_email_account
            aid = create_email_account(db, admin_user["id"], "Locked", "imap", {})
            resp = client.get(f"/accounts/{aid}/edit", cookies=admin_cookies)
            assert resp.status_code == 200
            # Checkbox is present, disabled, and checked.
            assert 'name="hipaa"' in resp.text
            assert "disabled" in resp.text
            assert "auto-flagged" in resp.text
        finally:
            self._reset_system()


class TestConfigSystemHipaaBoundary:
    """Flipping the system HIPAA flag records a boundary event.

    The toggle moved from ``/config/save`` to ``/admin/security/save`` in
    commit 6bb172b (``/config/save`` now preserves the existing DB
    value so a non-security-page submit can't zero it out). Test
    updated to target the canonical surface.
    """

    def _reset_system(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_save_flip_records_boundary(self, client, admin_cookies, db):
        self._reset_system()
        # Pre-condition: system HIPAA is off.
        resp = client.post(
            "/admin/security/save",
            data={
                "hipaa": "1",  # flipping on
                "auth_session_ttl_secs": "86400",
                "auth_hipaa_session_ttl_secs": "900",
            },
            cookies=admin_cookies,
        )
        # Either 200 OK or redirected (depends on implementation; 200 is fine).
        assert resp.status_code in (200, 303)

        from email_triage.web.db import list_hipaa_boundary_events
        events = list_hipaa_boundary_events(db)
        assert any(
            e["scope"] == "system" and e["direction"] == "on"
            for e in events
        )
        # Cleanup — leave system off for other tests.
        self._reset_system()


# ---------------------------------------------------------------------------
# Item #19 — admin owner filter on /accounts
# ---------------------------------------------------------------------------

class TestAccountsOwnerFilter:
    """Admin can scope the /accounts list to one owner via ?owner=<id>."""

    def _make_two_owners(self, db, admin_user, regular_user):
        from email_triage.web.db import create_email_account
        a1 = create_email_account(
            db, admin_user["id"], "ADMIN_ACCT", "imap", {"host": "a.example.com"},
        )
        a2 = create_email_account(
            db, regular_user["id"], "USER_ACCT", "imap", {"host": "u.example.com"},
        )
        return a1, a2

    def test_accounts_page_admin_default_is_self(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        """Bare /accounts for an admin defaults to their own accounts.
        Admin must pass ?owner=all to see every user's accounts."""
        self._make_two_owners(db, admin_user, regular_user)
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "ADMIN_ACCT" in resp.text
        assert "USER_ACCT" not in resp.text
        assert 'name="owner"' in resp.text
        assert "Showing 1 of 2 accounts" in resp.text

    def test_accounts_page_admin_owner_filter_all(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        """?owner=all explicitly shows every user's accounts."""
        self._make_two_owners(db, admin_user, regular_user)
        resp = client.get("/accounts?owner=all", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "ADMIN_ACCT" in resp.text
        assert "USER_ACCT" in resp.text
        assert 'name="owner"' in resp.text
        assert "Showing 2 of 2 accounts" in resp.text

    def test_accounts_page_admin_owner_filter_specific_user(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        self._make_two_owners(db, admin_user, regular_user)
        resp = client.get(
            f"/accounts?owner={regular_user['id']}", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "USER_ACCT" in resp.text
        assert "ADMIN_ACCT" not in resp.text
        assert "Showing 1 of 2 accounts" in resp.text

    def test_accounts_page_user_filter_does_not_apply_to_non_admin(
        self, client, user_cookies, db, admin_user, regular_user,
    ):
        """Regular users are always scoped to their own accounts,
        regardless of an attempted ?owner=<other_user> query param."""
        self._make_two_owners(db, admin_user, regular_user)
        # Try to spoof as the admin owner — must be ignored.
        resp = client.get(
            f"/accounts?owner={admin_user['id']}", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "USER_ACCT" in resp.text
        assert "ADMIN_ACCT" not in resp.text
        # Non-admin shouldn't even see the filter select.
        assert 'name="owner"' not in resp.text

    def test_accounts_page_admin_invalid_owner_falls_back_to_all(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        self._make_two_owners(db, admin_user, regular_user)
        resp = client.get("/accounts?owner=notanumber", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "ADMIN_ACCT" in resp.text
        assert "USER_ACCT" in resp.text


# ---------------------------------------------------------------------------
# Item #23a — auto-activate watcher after adding an account
# ---------------------------------------------------------------------------

class TestAccountsCreateStartWatch:
    """The Add-account form has a default-checked "Start watching" box."""

    def test_accounts_create_with_start_watch_imap_starts_idle(
        self, client, admin_cookies, admin_user, monkeypatch,
    ):
        """IMAP path: connection test passes → WatcherManager.start runs."""
        from email_triage.web.routers import ui as ui_mod

        async def fake_test(acct, secrets):
            return True, '<small>Connected. 5 messages in INBOX.</small>'
        monkeypatch.setattr(ui_mod, "_test_account_connection", fake_test)

        started_ids: list[int] = []

        async def fake_start(self, account_id):
            started_ids.append(account_id)
            # Mimic the real method persisting the setting.
            from email_triage.web.db import set_setting
            set_setting(self.app.state.db, f"watch:{account_id}", {"enabled": True})
            return "Watching started"

        from email_triage.web.app import WatcherManager
        monkeypatch.setattr(WatcherManager, "start", fake_start)

        resp = client.post(
            "/accounts/create",
            data={
                "name": "Watchable", "provider_type": "imap",
                "user_id": str(admin_user["id"]),
                "host": "mail.example.com", "port": "993",
                "username": "me@x.com", "password": "pw",
                "mailbox": "INBOX", "use_ssl": "1",
                "start_watch": "1",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        assert started_ids, "WatcherManager.start was not called"

    def test_accounts_create_with_start_watch_gmail_poll_does_not_call_idle(
        self, client, admin_cookies, admin_user, monkeypatch,
    ):
        """Gmail-in-poll-mode: start_watch must NOT invoke WatcherManager.start
        (the provider raises NotImplementedError through PushCapable check)."""
        called: list[int] = []

        from email_triage.web.app import WatcherManager

        async def fake_start(self, account_id):
            called.append(account_id)
            return "should not be reached"

        monkeypatch.setattr(WatcherManager, "start", fake_start)

        resp = client.post(
            "/accounts/create",
            data={
                "name": "Gmail PollMode", "provider_type": "gmail_api",
                "user_id": str(admin_user["id"]),
                "account": "me@gmail.com",
                "start_watch": "1",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        assert called == []

    def test_accounts_create_with_start_watch_unchecked_skips_activation(
        self, client, admin_cookies, admin_user, monkeypatch,
    ):
        from email_triage.web.app import WatcherManager

        called: list[int] = []

        async def fake_start(self, account_id):
            called.append(account_id)
            return "Watching started"

        monkeypatch.setattr(WatcherManager, "start", fake_start)

        resp = client.post(
            "/accounts/create",
            data={
                "name": "NoWatch", "provider_type": "imap",
                "user_id": str(admin_user["id"]),
                "host": "mail.example.com", "port": "993",
                "username": "me@x.com", "password": "pw",
                "mailbox": "INBOX", "use_ssl": "1",
                # start_watch deliberately absent.
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        assert called == []

    def test_accounts_create_test_fails_account_still_created_watcher_skipped(
        self, client, admin_cookies, admin_user, db, monkeypatch,
    ):
        """Connection test fails → account row exists, watcher not started,
        and the redirect carries an error banner."""
        from email_triage.web.routers import ui as ui_mod
        from email_triage.web.app import WatcherManager
        from email_triage.web.db import list_email_accounts

        async def fake_test(acct, secrets):
            return False, '<small>Failed: auth rejected</small>'

        monkeypatch.setattr(ui_mod, "_test_account_connection", fake_test)

        called: list[int] = []

        async def fake_start(self, account_id):
            called.append(account_id)
            return "nope"

        monkeypatch.setattr(WatcherManager, "start", fake_start)

        resp = client.post(
            "/accounts/create",
            data={
                "name": "BadCreds", "provider_type": "imap",
                "user_id": str(admin_user["id"]),
                "host": "mail.example.com", "port": "993",
                "username": "me@x.com", "password": "pw",
                "mailbox": "INBOX", "use_ssl": "1",
                "start_watch": "1",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        # Redirect target carries error banner.
        assert "error=" in resp.headers["location"]
        # Account was still persisted.
        accts = list_email_accounts(db)
        assert any(a["name"] == "BadCreds" for a in accts)
        assert called == []


# ---------------------------------------------------------------------------
# Item #23b — nudge after successful Test when watcher is off
# ---------------------------------------------------------------------------

class TestAccountsTestNudge:
    """/accounts/{id}/test appends a "Start watching" nudge when watch off."""

    def _make_imap(self, db, admin_user):
        from email_triage.web.db import create_email_account
        return create_email_account(
            db, admin_user["id"], "N", "imap",
            {
                "host": "mail.example.com", "port": 993,
                "username": "me@x.com", "use_ssl": True, "mailbox": "INBOX",
            },
        )

    def test_accounts_test_nudges_when_watcher_off(
        self, client, admin_cookies, admin_user, db, monkeypatch,
    ):
        from email_triage.web.routers import ui as ui_mod
        aid = self._make_imap(db, admin_user)

        async def fake_test(acct, secrets):
            return True, '<small>Connected. 42 messages in INBOX.</small>'

        monkeypatch.setattr(ui_mod, "_test_account_connection", fake_test)

        resp = client.post(f"/accounts/{aid}/test", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Connected. 42 messages" in resp.text
        assert "Real-time watch is not running" in resp.text
        assert f'/accounts/{aid}/watch/start' in resp.text

    def test_accounts_test_no_nudge_when_watcher_on(
        self, client, admin_cookies, admin_user, db, monkeypatch,
    ):
        from email_triage.web.routers import ui as ui_mod
        from email_triage.web.app import WatcherManager

        aid = self._make_imap(db, admin_user)

        async def fake_test(acct, secrets):
            return True, '<small>Connected. 42 messages in INBOX.</small>'

        monkeypatch.setattr(ui_mod, "_test_account_connection", fake_test)

        def fake_running(self, account_id):
            return True

        monkeypatch.setattr(WatcherManager, "is_running", fake_running)

        resp = client.post(f"/accounts/{aid}/test", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Connected. 42 messages" in resp.text
        assert "Real-time watch is not running" not in resp.text
