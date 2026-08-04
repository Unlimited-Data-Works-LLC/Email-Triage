"""Tests for the consolidated "Security" tab (2026-06-07).

Three previously-scattered surfaces folded onto a single
``/profile/security`` page:

  * the "Sign out all sessions" button that used to render in
    the My Settings page header — and therefore on EVERY tab;
  * the standalone Passkeys page (``/profile/hardware-keys``);
  * the standalone API Keys page (``/accounts/api-keys`` GET).

The two legacy GET URLs now 303-redirect to ``/profile/security`` (auth
gate first, so anonymous users still bounce to /login). The mint/revoke
action endpoints keep their original paths.

Mirrors the ``/config`` tab-consolidation test pattern in
``test_config_tabs.py``.
"""

from __future__ import annotations

from email_triage.web.auth import SESSION_COOKIE_NAME


class TestSecurityPageRender:
    """``/profile/security`` renders all three sections."""

    def test_requires_auth(self, client):
        resp = client.get("/profile/security", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers.get("location", "")

    def test_renders_all_three_sections(self, client, admin_cookies):
        resp = client.get("/profile/security", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # 1. Account security — sign out all sessions.
        assert "Sign out all sessions" in body
        assert 'action="/profile/sign-out-all"' in body
        # 2. Passkeys.
        assert "Passkeys" in body
        assert "Touch your passkey to register" in body
        # 3. API access tokens.
        assert "API Keys (Access Tokens)" in body
        assert "Create a token" in body

    def test_regular_user_renders(self, client, user_cookies):
        """Non-admin users get the page too (their own keys/tokens)."""
        resp = client.get("/profile/security", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Sign out all sessions" in resp.text

    def test_security_tab_marked_active(self, client, admin_cookies):
        """The tab strip renders a Security tab and marks it active."""
        resp = client.get("/profile/security", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        assert 'href="/profile/security"' in body
        # Active tab carries the bold rule.
        import re
        compact = re.sub(r"\s+", " ", body)
        assert re.search(
            r"font-weight:600;.{0,250}Security", compact,
        ) is not None


class TestSignOutMovedOffProfileHeader:
    """The sign-out button no longer renders on the other My Settings
    tabs — it moved off the page header into the Security tab."""

    def test_not_on_notifications_tab(self, client, admin_cookies):
        resp = client.get("/profile?tab=notifications", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Sign out all sessions" not in resp.text

    def test_not_on_topic_digest_tab(self, client, admin_cookies):
        resp = client.get("/profile?tab=topic-digest", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Sign out all sessions" not in resp.text


class TestLegacyRedirects:
    """The two standalone pages 303-redirect to /profile/security."""

    def _admin(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )

    def test_api_keys_legacy_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/accounts/api-keys", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/profile/security"

    def test_hardware_keys_legacy_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/profile/hardware-keys", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/profile/security"

    def test_hardware_keys_forwards_owner_filter(
        self, client, admin_cookies,
    ):
        """The admin owner-filter query survives the bounce so a
        filtered deep link still lands filtered."""
        self._admin(client, admin_cookies)
        r = client.get(
            "/profile/hardware-keys?owner_filter=all",
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "owner_filter=all" in r.headers["location"]
        assert r.headers["location"].startswith("/profile/security")

    def test_legacy_redirect_auth_gate_anonymous(self, client):
        """Anonymous users hit the auth gate BEFORE the redirect — they
        bounce to /login, not to the Security page."""
        for url in ("/accounts/api-keys", "/profile/hardware-keys"):
            r = client.get(url, follow_redirects=False)
            assert r.status_code in (302, 303)
            assert "/login" in r.headers.get("location", "")
