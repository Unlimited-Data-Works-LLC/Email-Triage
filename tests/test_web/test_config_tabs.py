"""Tests for the /config tab-consolidation refactor (2026-05-13).

The legacy /admin/integrations + /admin/tls + /admin/backup +
/admin/dev-keys + /admin/compliance-security pages collapsed onto a
single /config?tab=<slug> page with a tab strip. The legacy URLs all
303-redirect to the matching tab so bookmarks + tests + log links
keep resolving.

Two test classes:

  * ``TestLegacyAdminRedirects`` — every legacy URL returns 303 to
    the right ``/config?tab=<slug>`` target. Auth gate runs BEFORE
    the redirect so anonymous users still bounce to /login and
    non-admin users still get 403 (preserves the pre-refactor
    contract that follow_redirects=False tests pin against).
  * ``TestConfigTabRender`` — each ``/config?tab=<slug>`` renders
    the expected tab body content.
"""

from __future__ import annotations

from email_triage.web.auth import SESSION_COOKIE_NAME


# ---------------------------------------------------------------------------
# Legacy → tab redirects
# ---------------------------------------------------------------------------


class TestLegacyAdminRedirects:
    """The five legacy admin URLs 303-redirect to the matching
    /config tab. Test runs as admin so we exercise the redirect path
    (not the auth-gate-bounce path)."""

    def _admin(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )

    def test_old_integrations_url_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/admin/integrations", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/config?tab=integrations"

    def test_old_tls_url_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/admin/tls", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/config?tab=tls"

    def test_old_backup_url_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/admin/backup", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/config?tab=backup"

    def test_old_dev_keys_url_redirects(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/admin/dev-keys", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/config?tab=security"

    def test_old_compliance_security_url_redirects(
        self, client, admin_cookies,
    ):
        self._admin(client, admin_cookies)
        r = client.get(
            "/admin/compliance-security", follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/config?tab=security"

    def test_old_integrations_preserves_query(
        self, client, admin_cookies,
    ):
        """Query strings (e.g. ?saved=1 from the legacy save handler's
        old redirect target) are forwarded so the flash message
        survives the bounce."""
        self._admin(client, admin_cookies)
        r = client.get(
            "/admin/integrations?saved=1", follow_redirects=False,
        )
        assert r.status_code == 303
        assert "saved=1" in r.headers["location"]
        assert "tab=integrations" in r.headers["location"]

    def test_redirect_auth_gate_anonymous(self, client):
        """Anonymous users hit the auth gate BEFORE the redirect runs —
        they bounce to /login, not to the tab page. Preserves the
        pre-refactor contract pinned by existing tests."""
        r = client.get("/admin/integrations", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers.get("location", "")

    def test_redirect_auth_gate_non_admin(self, client, user_cookies):
        """Non-admin users get 403 before the redirect runs."""
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        r = client.get("/admin/integrations", follow_redirects=False)
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Tab body renders
# ---------------------------------------------------------------------------


class TestConfigTabRender:
    """Each ``/config?tab=<slug>`` renders the expected tab body."""

    def _admin(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )

    def test_default_tab_is_general(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config")
        assert r.status_code == 200
        body = r.text
        # General tab content markers.
        assert "Runtime Settings" in body
        assert "Classifier" in body
        assert 'name="dry_run"' in body
        # Tab strip is rendered.
        assert 'href="/config?tab=integrations"' in body
        assert 'href="/config?tab=security"' in body

    def test_tab_general_explicit(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=general")
        assert r.status_code == 200
        assert "Runtime Settings" in r.text

    def test_tab_integrations_renders(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=integrations")
        assert r.status_code == 200
        body = r.text
        # Integrations tab content markers.
        assert "Google OAuth" in body
        assert "Office 365 OAuth" in body
        assert "Gmail Pub/Sub" in body
        assert 'name="google_oauth_web_client_id"' in body
        assert 'name="public_url"' in body

    def test_tab_tls_renders(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=tls")
        assert r.status_code == 200
        body = r.text
        # TLS card grid content markers.
        assert "TLS configuration" in body
        assert "ACME" in body
        assert "Manual CSR" in body
        assert 'href="/admin/acme-status"' in body
        assert 'href="/admin/tls/csr"' in body

    def test_tab_backup_renders(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=backup")
        assert r.status_code == 200
        body = r.text
        # Backup tab content markers.
        assert "Backup &amp; Restore" in body or "Backup & Restore" in body
        assert 'action="/admin/backup/export-full"' in body
        assert 'action="/admin/backup/export-key"' in body

    def test_tab_security_renders(self, client, admin_cookies):
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=security")
        assert r.status_code == 200
        body = r.text
        # Security tab carries both the Compliance & Security card grid
        # AND the Dev keys section (merged from /admin/compliance-security
        # + /admin/dev-keys).
        assert "Compliance &amp; Security" in body or "Compliance & Security" in body
        assert "HIPAA mode" in body
        assert "Developer keypairs" in body
        assert 'action="/admin/dev-keys/add"' in body

    def test_unknown_tab_falls_back_to_general(
        self, client, admin_cookies,
    ):
        """Unknown ?tab= silently falls back to general so a stale
        bookmark / typo doesn't 404."""
        self._admin(client, admin_cookies)
        r = client.get("/config?tab=does-not-exist")
        assert r.status_code == 200
        assert "Runtime Settings" in r.text

    def test_tab_strip_marks_active(self, client, admin_cookies):
        """Active tab gets the bold-styled treatment via the
        ``font-weight:600`` rule in _config_tabs.html. The non-active
        tabs render the ``muted-color`` rule, so the active tab is
        the one with ``font-weight:600`` somewhere in its <a>."""
        self._admin(client, admin_cookies)
        # Render two different tabs and check that font-weight:600
        # appears in one and not at the same offset in the other —
        # the active-tab style only fires for the tab the page
        # is currently on.
        r_int = client.get("/config?tab=integrations").text
        r_sec = client.get("/config?tab=security").text
        # font-weight:600 appears for the active tab in both pages.
        assert "font-weight:600" in r_int
        assert "font-weight:600" in r_sec
        # And the tab strip is identical in shape, so the only thing
        # that differs is which slug's <a> gets the active rule.
        # Sanity check: integrations page mentions the integrations
        # slug in an active context (close to font-weight:600); the
        # security page does not.
        import re
        # Compact whitespace so the regex below is forgiving.
        compact_int = re.sub(r"\s+", " ", r_int)
        compact_sec = re.sub(r"\s+", " ", r_sec)
        # The active-tab rule shape is roughly:
        #   ...font-weight:600;margin-bottom:-1px;">  ...  <slug-label>
        # We look for the integrations slug appearing within ~250
        # chars after the font-weight:600 occurrence (only happens on
        # the integrations page).
        pat = re.compile(r"font-weight:600;.{0,250}Integrations", re.DOTALL)
        assert pat.search(compact_int) is not None
        # Same probe on the security page should NOT match (security
        # is the active slug there, not integrations).
        assert pat.search(compact_sec) is None

    def test_admin_only_tab_render(self, client):
        """Anonymous users still bounce to /login on /config."""
        r = client.get("/config", follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers["location"]

    def test_admin_only_tab_render_non_admin(self, client, user_cookies):
        """Non-admin users get 403 on /config regardless of tab."""
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        r = client.get("/config?tab=integrations")
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Admin top-nav trim
# ---------------------------------------------------------------------------


class TestAdminSubmenuTrim:
    """Admin top-nav submenu drops the standalone-page entries that
    are now /config tabs. Keeps: Users / Config / Stats / Backup /
    Logs (operator-approved list 2026-05-13)."""

    def test_submenu_keeps_required_entries(
        self, client, admin_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        r = client.get("/dashboard")
        assert r.status_code == 200
        body = r.text
        # The five required submenu entries.
        for href, label in [
            ("/users", "Users"),
            ("/config", "Config"),
            ("/admin/stats", "Stats"),
            ("/logs", "Logs"),
        ]:
            assert f'href="{href}"' in body, f"missing {label} link"
        # Backup is /config?tab=backup so it lives inside the tab
        # strip AND retains its top-level entry per the operator
        # spec.
        assert 'href="/config?tab=backup"' in body

    def test_submenu_drops_legacy_entries(
        self, client, admin_cookies,
    ):
        """Standalone TLS / Compliance & Security / Integrations /
        Dev keys submenu links are removed — those surfaces live
        inside the /config tab strip now."""
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        r = client.get("/dashboard")
        assert r.status_code == 200
        body = r.text
        # The nav <ul class="submenu"> block should not carry these.
        # Look at base.html submenu specifically — the submenu block
        # is everything between '<ul class="submenu">' and '</ul>'
        # following the admin menu trigger.
        import re
        # Pull the submenu block (the dropdown attached to "Admin").
        m = re.search(
            r'<ul class="submenu">(.*?)</ul>', body, re.DOTALL,
        )
        assert m is not None, "Admin submenu not found"
        submenu = m.group(1)
        # Legacy standalone entries should be gone from the dropdown.
        assert 'href="/admin/tls"' not in submenu
        assert 'href="/admin/compliance-security"' not in submenu
        assert 'href="/admin/integrations"' not in submenu
        assert 'href="/admin/dev-keys"' not in submenu
