"""/config — version + schema-compat banner (#125 partial).

Smoke-tests:

* banner renders for admin on /config (default = General tab)
* banner hidden for non-admin (403)
* status data-attribute reflects the gathered status
"""

from __future__ import annotations


class TestVersionBannerAdmin:
    def test_banner_renders_for_admin_on_default_tab(
        self, client, admin_cookies,
    ):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Banner element + the status data-attribute.
        assert 'id="version-banner"' in body
        assert "data-status=" in body
        # App version is named on the banner (test fixture sets
        # app.state.version = "testsha1" but the banner reads the
        # python package __version__ which is "0.1.0").
        assert "0.1.0" in body
        # Update-flow hint copy is present.
        assert "scripts/deploy.sh" in body

    def test_banner_hidden_for_nonadmin(
        self, client, user_cookies,
    ):
        resp = client.get("/config", cookies=user_cookies)
        # Non-admin gets a 403 on /config -- so the banner is
        # implicitly hidden because the whole page is.
        assert resp.status_code == 403
        assert 'id="version-banner"' not in resp.text

    def test_banner_hidden_when_unauthenticated(self, client):
        resp = client.get("/config", follow_redirects=False)
        # Redirects to /login when no session cookie.
        assert resp.status_code in (303, 307)

    def test_banner_status_attribute_known_value(
        self, client, admin_cookies,
    ):
        """The data-status attribute is one of the known status
        constants. Lets the test future-proof against changes to the
        copy without re-asserting wording."""
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        known = (
            'data-status="up_to_date"',
            'data-status="update_available"',
            'data-status="incompatible_rollback"',
            'data-status="downgrade_not_supported"',
        )
        assert any(s in body for s in known), (
            "expected one of the four known data-status values; "
            "got banner body without any -- did the status enum "
            "change without the template?"
        )
