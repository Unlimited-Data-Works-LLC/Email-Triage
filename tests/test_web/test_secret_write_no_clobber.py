"""Behavioural regression guard for the 2026-06-08 OAuth save-clobber.

Reproduces the exact incident at the HTTP boundary: saving the Integrations
form with the OAuth credential fields blank (operator only wanted to set the
SearXNG URL) MUST NOT destroy the stored Google/O365 client credentials, and
an autofilled login-password in a Google secret field MUST be rejected
(visibly), not stored.

Companion to the structural pins
``tests/test_no_unguarded_secret_write.py`` (no form-derived secrets.set) and
``tests/test_credential_inputs_hardened.py`` (no bare password field). Those
prove the *shape*; this proves the *runtime contract*.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME


_WEB_ID = "GOOGLE_OAUTH_WEB_CLIENT_ID"
_WEB_SECRET = "GOOGLE_OAUTH_WEB_CLIENT_SECRET"
_O365_SECRET = "O365_OAUTH_CLIENT_SECRET"


def _min_form(**overrides):
    """A minimal valid Integrations save form — only the push fields the
    operator would touch. Every credential field defaults to blank, exactly
    like the incident save (operator set the SearXNG URL, nothing else)."""
    data = {
        "public_url": "https://host.example.ts.invalid",
        "gmail_topic_name": "projects/p/topics/t",
        "gmail_subscription_sa_email": "x@y.iam.gserviceaccount.com",
        "gmail_audience": "https://host.example.ts.invalid",
        "web_search_searxng_url": "https://searx.example.ts.invalid",
    }
    data.update(overrides)
    return data


def _login(client, admin_cookies):
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])


class TestIntegrationsSaveNeverClobbers:
    def test_blank_oauth_fields_preserve_stored_secrets(
        self, client, admin_cookies, app,
    ):
        """The incident: save with OAuth fields blank → stored Google/O365
        client secrets + the Web client id are UNCHANGED."""
        secrets = app.state.secrets
        secrets.set(_WEB_ID, "914575-real.apps.googleusercontent.com")
        secrets.set(_WEB_SECRET, "GOCSPX-realwebsecret")
        secrets.set(_O365_SECRET, "azure-real-secret")
        _login(client, admin_cookies)
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            resp = client.post(
                "/admin/integrations/save",
                data=_min_form(),  # all OAuth fields blank
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # Nothing clobbered.
        assert secrets.get(_WEB_ID) == "914575-real.apps.googleusercontent.com"
        assert secrets.get(_WEB_SECRET) == "GOCSPX-realwebsecret"
        assert secrets.get(_O365_SECRET) == "azure-real-secret"
        # Success redirect (no rejection), not an error.
        assert "saved=1" in resp.headers["location"]

    def test_autofilled_login_password_in_google_secret_is_rejected(
        self, client, admin_cookies, app,
    ):
        """A non-GOCSPX- value (the autofilled login password vector) is
        REJECTED: stored secret unchanged AND the redirect surfaces it."""
        secrets = app.state.secrets
        secrets.set(_WEB_SECRET, "GOCSPX-realwebsecret")
        _login(client, admin_cookies)
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            resp = client.post(
                "/admin/integrations/save",
                # The exact autofill shape from the incident: a saved login
                # password, not a Google client secret.
                data=_min_form(google_oauth_web_client_secret='.2"1'),
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # Rejected, not stored.
        assert secrets.get(_WEB_SECRET) == "GOCSPX-realwebsecret"
        # Operator sees it — never silent.
        assert "err=" in resp.headers["location"]

    def test_valid_google_secret_is_written(
        self, client, admin_cookies, app,
    ):
        """A real GOCSPX- secret IS accepted, stored, and mirrored to config
        so the change takes effect without a restart."""
        secrets = app.state.secrets
        secrets.set(_WEB_SECRET, "GOCSPX-old")
        _login(client, admin_cookies)
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            resp = client.post(
                "/admin/integrations/save",
                data=_min_form(
                    google_oauth_web_client_secret="GOCSPX-brandnewsecret",
                ),
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert secrets.get(_WEB_SECRET) == "GOCSPX-brandnewsecret"
        assert app.state.config.google_oauth.web_client_secret == (
            "GOCSPX-brandnewsecret"
        )
        assert "saved=1" in resp.headers["location"]

    def test_blank_client_id_preserves_stored_id(
        self, client, admin_cookies, app,
    ):
        """Shape-B fix: an emptied client-id field PRESERVES the stored id
        (no more unconditional clobber)."""
        secrets = app.state.secrets
        secrets.set(_WEB_ID, "914575-real.apps.googleusercontent.com")
        _login(client, admin_cookies)
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            client.post(
                "/admin/integrations/save",
                data=_min_form(google_oauth_web_client_id=""),
                follow_redirects=False,
            )
        assert secrets.get(_WEB_ID) == "914575-real.apps.googleusercontent.com"

    def test_new_client_id_is_written(
        self, client, admin_cookies, app,
    ):
        """A non-blank client-id is still written normally (the fix only
        changes blank behaviour, not the happy path)."""
        secrets = app.state.secrets
        secrets.set(_WEB_ID, "old-id.apps.googleusercontent.com")
        _login(client, admin_cookies)
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            client.post(
                "/admin/integrations/save",
                data=_min_form(
                    google_oauth_web_client_id="new-id.apps.googleusercontent.com",
                ),
                follow_redirects=False,
            )
        assert secrets.get(_WEB_ID) == "new-id.apps.googleusercontent.com"
        assert app.state.config.google_oauth.web_client_id == (
            "new-id.apps.googleusercontent.com"
        )
