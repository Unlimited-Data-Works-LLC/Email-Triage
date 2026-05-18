"""UI routes for API key management on the Accounts page.

The HTML-rendering routes at ``/accounts/api-keys`` sit alongside the
existing JSON ``/api/keys`` endpoints (which stay for programmatic
access). Both share the same db helpers so behaviour is consistent."""


class TestApiKeysPage:
    def test_requires_auth(self, client):
        resp = client.get("/accounts/api-keys", follow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]

    def test_admin_sees_all_users_keys(
        self, client, db, admin_cookies, admin_user, regular_user,
    ):
        from email_triage.web.auth import (
            generate_api_key, hash_api_key, store_api_key,
        )
        # Key owned by the regular user.
        store_api_key(db, hash_api_key(generate_api_key()), "other-user-key",
                      regular_user["id"])
        # Key owned by the admin.
        store_api_key(db, hash_api_key(generate_api_key()), "admin-own-key",
                      admin_user["id"])
        resp = client.get("/accounts/api-keys", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "other-user-key" in resp.text
        assert "admin-own-key" in resp.text

    def test_regular_user_sees_only_own(
        self, client, db, user_cookies, admin_user, regular_user,
    ):
        from email_triage.web.auth import (
            generate_api_key, hash_api_key, store_api_key,
        )
        store_api_key(db, hash_api_key(generate_api_key()), "admin-only",
                      admin_user["id"])
        store_api_key(db, hash_api_key(generate_api_key()), "user-own",
                      regular_user["id"])
        resp = client.get("/accounts/api-keys", cookies=user_cookies)
        assert resp.status_code == 200
        assert "user-own" in resp.text
        assert "admin-only" not in resp.text


class TestApiKeyCreateRoute:
    def test_create_returns_raw_key_once(
        self, client, db, admin_cookies, admin_user,
    ):
        resp = client.post("/accounts/api-keys", data={
            "name": "smoke",
            "user_email": admin_user["email"],
            "alias": "smoke-alias",
            "expires": "never",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        # Key is shown once in the response body for the user to copy.
        assert "et_" in resp.text

        # And it's stored hashed in the DB, not in plaintext.
        from email_triage.web.auth import list_api_keys
        keys = list_api_keys(db, user_id=admin_user["id"])
        assert len(keys) == 1
        assert keys[0]["name"] == "smoke"

    def test_success_panel_shows_agent_instructions(
        self, client, admin_cookies, admin_user,
    ):
        """The token-creation response includes the exact sentence the
        user should paste into their AI assistant's chat."""
        resp = client.post("/accounts/api-keys", data={
            "name": "for-agent",
            "user_email": admin_user["email"],
            "alias": "alice",
            "expires": "never",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert "email-triage-api register-me" in resp.text
        assert "--as alice" in resp.text
        assert "--token et_" in resp.text
        # Paste-into-chat helper block is present.
        assert "word for word" in resp.text

    def test_alias_defaults_to_email_prefix_when_blank(
        self, client, admin_cookies, admin_user,
    ):
        """Empty alias falls back to the email's local-part, lowercased."""
        resp = client.post("/accounts/api-keys", data={
            "name": "no-alias",
            "user_email": admin_user["email"],
            "alias": "",
            "expires": "never",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        expected_prefix = admin_user["email"].split("@", 1)[0].lower()
        assert f"--as {expected_prefix}" in resp.text

    def test_alias_sanitised_when_unsafe(
        self, client, admin_cookies, admin_user,
    ):
        """Alias with shell-unsafe chars is reset to the email prefix
        rather than trusted verbatim."""
        resp = client.post("/accounts/api-keys", data={
            "name": "bad-alias",
            "user_email": admin_user["email"],
            "alias": "alice; rm -rf /",
            "expires": "never",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert "rm -rf" not in resp.text
        assert "; " not in resp.text.split("email-triage-api")[1]

    def test_name_required(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/api-keys", data={
            "name": "",
            "user_email": admin_user["email"],
            "expires": "never",
        }, cookies=admin_cookies)
        assert resp.status_code == 400

    def test_regular_user_cannot_create_for_other_user(
        self, client, user_cookies, admin_user,
    ):
        resp = client.post("/accounts/api-keys", data={
            "name": "sneaky",
            "user_email": admin_user["email"],
            "expires": "never",
        }, cookies=user_cookies)
        assert resp.status_code == 403

    def test_expires_relative_day_offset(
        self, client, db, admin_cookies, admin_user,
    ):
        """A '30d' expires choice sets expires_at ~30 days in the future."""
        from datetime import datetime, timezone
        from email_triage.web.auth import list_api_keys
        resp = client.post("/accounts/api-keys", data={
            "name": "timed",
            "user_email": admin_user["email"],
            "expires": "30d",
        }, cookies=admin_cookies)
        assert resp.status_code == 200

        keys = list_api_keys(db, user_id=admin_user["id"])
        expires_at = datetime.fromisoformat(keys[0]["expires_at"])
        delta = expires_at - datetime.now(timezone.utc)
        # Sloppy but sufficient: somewhere in 29.5–30.5 days.
        assert 29 * 86400 < delta.total_seconds() < 31 * 86400


class TestApiKeyDeleteRoute:
    def test_delete_own_key(self, client, db, admin_cookies, admin_user):
        from email_triage.web.auth import (
            generate_api_key, hash_api_key, store_api_key, list_api_keys,
        )
        kid = store_api_key(
            db, hash_api_key(generate_api_key()), "dead", admin_user["id"],
        )
        resp = client.delete(f"/accounts/api-keys/{kid}", cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.text == ""
        assert list_api_keys(db, user_id=admin_user["id"]) == []

    def test_regular_user_cannot_delete_admins_key(
        self, client, db, user_cookies, admin_user,
    ):
        from email_triage.web.auth import (
            generate_api_key, hash_api_key, store_api_key,
        )
        kid = store_api_key(
            db, hash_api_key(generate_api_key()), "admins", admin_user["id"],
        )
        resp = client.delete(f"/accounts/api-keys/{kid}", cookies=user_cookies)
        assert resp.status_code == 403

    def test_delete_missing_returns_404(self, client, admin_cookies):
        resp = client.delete("/accounts/api-keys/99999", cookies=admin_cookies)
        assert resp.status_code == 404


class TestAccountsPageLinksToApiKeys:
    def test_api_keys_tab_visible_on_accounts(self, client, admin_cookies):
        """API Keys (Access Tokens) is reached via the My Settings tab
        strip rendered on /accounts. The dedicated Access-Tokens
        button on /accounts was removed when API Keys became a tab —
        having both made the cluster nav inconsistent (per Alex's
        2026-05-05 nav reorg ask: "API Keys belongs under My Settings
        as a tab. Should NOT have a button on the account page")."""
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'href="/accounts/api-keys"' in resp.text
        assert "API Keys" in resp.text

    def test_api_keys_page_uses_plain_language(self, client, admin_cookies):
        """The page is non-admin surface — no jargon (no /api/openclaw/*,
        no 'bearer tokens', no HTTP references)."""
        resp = client.get("/accounts/api-keys", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "/api/openclaw" not in resp.text
        assert "bearer token" not in resp.text.lower()
        # H3 reads "API Keys (Access Tokens)" so both terms surface.
        assert "Access Tokens" in resp.text
