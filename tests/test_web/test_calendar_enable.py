"""Tests for the calendar enable/disable lifecycle (post-B2).

B2 collapsed the standalone /calendar/enable* endpoints into a single
opt-in checkbox on the account edit form, which flips the
``calendar_enabled:{id}`` setting directly and is honoured by the
unified Gmail Authenticate flow on the next auth round-trip.
"""

import json
from datetime import datetime, timezone

import pytest


def _make_account(db, user_id, ptype="gmail_api", *, name="G", config=None, hipaa=0):
    now = datetime.now(timezone.utc).isoformat()
    cfg = config or {"account": "me@gmail.com"}
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, ptype, json.dumps(cfg), hipaa, now, now),
    )
    db.commit()
    return cur.lastrowid


def _seed_install_oauth(app):
    app.state.config.google_oauth.web_client_id = "web-cid.apps.googleusercontent.com"
    app.state.config.google_oauth.web_client_secret = "GOCSPX-web"
    app.state.config.google_oauth.desktop_client_id = "desk-cid.apps.googleusercontent.com"
    app.state.config.google_oauth.desktop_client_secret = "GOCSPX-desk"


class TestCalendarOptIn:
    """Edit-form checkbox flips the calendar_enabled flag."""

    def test_opt_in_on_update_sets_flag(self, client, db, admin_cookies, admin_user):
        """Checking the box and saving enables calendar for the account."""
        aid = _make_account(db, admin_user["id"])
        resp = client.put(f"/accounts/{aid}", data={
            "name": "G", "provider_type": "gmail_api",
            "account": "me@gmail.com",
            "calendar_opted_in": "1",
            "is_active": "1",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        from email_triage.web.db import get_setting, get_email_account
        assert get_setting(db, f"calendar_enabled:{aid}") == {"enabled": True}
        # Opt-in persists on the account config so the auth flow can
        # request the union of scopes on the next Authenticate click.
        acct = get_email_account(db, aid)
        assert acct["config"]["calendar_opted_in"] is True

    def test_opt_out_on_update_clears_flag(self, client, db, admin_cookies, admin_user):
        """Unchecking the box clears the flag (intent wins — even if the
        refresh token still has calendar scope until next re-auth)."""
        from email_triage.web.db import set_setting, get_setting
        aid = _make_account(db, admin_user["id"],
                            config={"account": "me@gmail.com", "calendar_opted_in": True})
        set_setting(db, f"calendar_enabled:{aid}", {"enabled": True})
        resp = client.put(f"/accounts/{aid}", data={
            "name": "G", "provider_type": "gmail_api",
            "account": "me@gmail.com",
            # calendar_opted_in deliberately omitted
            "is_active": "1",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert get_setting(db, f"calendar_enabled:{aid}") == {"enabled": False}

    def test_opt_in_on_create_sets_flag(self, client, db, admin_cookies, admin_user):
        """Calendar opt-in at create time flips the flag once the
        account row exists."""
        resp = client.post("/accounts/create", data={
            "name": "NewG", "provider_type": "gmail_api",
            "user_id": str(admin_user["id"]),
            "account": "new@gmail.com",
            "calendar_opted_in": "1",
        }, cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303
        from email_triage.web.db import list_email_accounts, get_setting
        rows = list_email_accounts(db)
        new_ids = [r["id"] for r in rows if r["name"] == "NewG"]
        assert len(new_ids) == 1
        assert get_setting(db, f"calendar_enabled:{new_ids[0]}") == {"enabled": True}

    def test_office365_opt_in_also_flips_flag(self, client, db, admin_cookies, admin_user):
        """O365 calendar is policy-only (MSAL handles consent lazily),
        so the checkbox directly controls the flag."""
        aid = _make_account(db, admin_user["id"], ptype="office365",
                            config={"client_id": "x", "tenant_id": "common"})
        resp = client.put(f"/accounts/{aid}", data={
            "name": "G", "provider_type": "office365",
            "client_id": "x", "tenant_id": "common",
            "calendar_opted_in": "1",
            "is_active": "1",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        from email_triage.web.db import get_setting
        assert get_setting(db, f"calendar_enabled:{aid}") == {"enabled": True}


class TestUnifiedAuthScopes:
    """The single Authenticate flow honours calendar_opted_in."""

    def test_auth_start_includes_calendar_scope_when_opted_in(
        self, client, db, admin_cookies, admin_user,
    ):
        aid = _make_account(
            db, admin_user["id"],
            config={"account": "me@gmail.com", "calendar_opted_in": True},
        )
        _seed_install_oauth(client.app)
        client.app.state.config.push.public_url = "https://test.example.com"
        try:
            resp = client.post(
                f"/accounts/{aid}/gmail-api/auth/start", cookies=admin_cookies,
            )
            assert resp.status_code == 200
            # Calendar scope is in the request URL when opted in.
            assert "calendar" in resp.text
            assert "accounts.google.com/o/oauth2/v2/auth" in resp.text
        finally:
            client.app.state.config.push.public_url = ""

    def test_auth_start_omits_calendar_scope_when_not_opted_in(
        self, client, db, admin_cookies, admin_user,
    ):
        aid = _make_account(
            db, admin_user["id"],
            config={"account": "me@gmail.com"},  # no calendar opt-in
        )
        _seed_install_oauth(client.app)
        client.app.state.config.push.public_url = "https://test.example.com"
        try:
            resp = client.post(
                f"/accounts/{aid}/gmail-api/auth/start", cookies=admin_cookies,
            )
            assert resp.status_code == 200
            # No calendar scope in the request URL.
            assert "calendar" not in resp.text
        finally:
            client.app.state.config.push.public_url = ""

    def test_manual_paste_start_includes_calendar_scope_when_opted_in(
        self, client, db, admin_cookies, admin_user,
    ):
        aid = _make_account(
            db, admin_user["id"],
            config={"account": "me@gmail.com", "calendar_opted_in": True},
        )
        _seed_install_oauth(client.app)
        resp = client.post(
            f"/accounts/{aid}/gmail-api/auth/start-manual", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "127.0.0.1%3A1" in resp.text
        assert "calendar" in resp.text


class TestCalendarDisable:
    def test_disable_endpoint_still_clears_flag(
        self, client, db, admin_cookies, admin_user,
    ):
        """The /calendar/disable HTMX endpoint stays for admin 'turn
        this off right now' without going through the edit form."""
        from email_triage.web.db import set_setting, get_setting
        aid = _make_account(db, admin_user["id"])
        set_setting(db, f"calendar_enabled:{aid}", {"enabled": True})
        resp = client.post(
            f"/accounts/{aid}/calendar/disable", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert get_setting(db, f"calendar_enabled:{aid}") == {"enabled": False}


class TestRemovedEndpoints:
    """B2 removed /calendar/enable, /calendar/enable-manual, and
    /calendar/enable-manual/complete — they should 404 now."""

    @pytest.mark.parametrize("path", [
        "/calendar/enable",
        "/calendar/enable-manual",
        "/calendar/enable-manual/complete",
    ])
    def test_removed_endpoint_404s(
        self, client, db, admin_cookies, admin_user, path,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{aid}{path}", cookies=admin_cookies)
        assert resp.status_code == 404
