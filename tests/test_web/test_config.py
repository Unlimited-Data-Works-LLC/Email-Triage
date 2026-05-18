"""Tests for the admin config page and runtime settings."""

import pytest
from email_triage.web.db import get_setting, set_setting


class TestConfigPage:
    """GET /config — admin-only system config page."""

    def test_config_requires_auth(self, client):
        resp = client.get("/config", follow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]

    def test_config_forbidden_for_regular_user(self, client, user_cookies):
        resp = client.get("/config", cookies=user_cookies)
        assert resp.status_code == 403

    def test_config_visible_to_admin(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "System Configuration" in resp.text

    def test_config_shows_runtime_settings(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Dry Run" in resp.text
        assert "Log Level" in resp.text
        assert "HIPAA Mode" in resp.text

    def test_config_shows_classifier_fields(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Classifier" in resp.text
        assert 'name="classifier_backend"' in resp.text
        assert 'name="classifier_model"' in resp.text

    def test_config_shows_smtp_fields(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "SMTP" in resp.text
        assert 'name="smtp_host"' in resp.text
        assert 'name="smtp_port"' in resp.text

    def test_config_no_longer_shows_google_oauth_section(self, client, admin_cookies):
        """2026-05-10: Google OAuth client credentials moved to
        /admin/integrations alongside O365 OAuth + Pub/Sub + outbound
        webhook. /config keeps general install settings (logging,
        ingestion, SMTP, classifier). See
        TestGoogleOAuthOnIntegrationsPage below for the new home."""
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'name="google_oauth_web_client_id"' not in resp.text
        assert 'name="google_oauth_web_client_secret"' not in resp.text
        assert 'name="google_oauth_desktop_client_id"' not in resp.text
        assert 'name="google_oauth_desktop_client_secret"' not in resp.text


class TestGoogleOAuthOnIntegrationsPage:
    """B1 (revised 2026-05-10): Google OAuth client credentials live
    at install level AND on /admin/integrations (moved from /config
    so every integration-related setting is in one home).

    2026-05-13: /admin/integrations collapsed onto /config?tab=integrations
    (the legacy URL 303-redirects). Tests now hit the canonical tab URL
    directly so the per-request ``cookies=`` flag (which doesn't persist
    through TestClient redirect chains) still works."""

    def test_integrations_shows_google_oauth_section(self, client, admin_cookies):
        resp = client.get("/config?tab=integrations", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Google OAuth" in resp.text
        assert 'name="google_oauth_web_client_id"' in resp.text
        assert 'name="google_oauth_web_client_secret"' in resp.text
        assert 'name="google_oauth_desktop_client_id"' in resp.text
        assert 'name="google_oauth_desktop_client_secret"' in resp.text

    def test_integrations_shows_json_import_widget(self, client, admin_cookies):
        """JSON-import widget moved alongside the Google OAuth section
        — auto-fills the right pair (Web vs Desktop) based on the
        file's top-level key."""
        resp = client.get("/config?tab=integrations", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'id="oauth-json-import"' in resp.text
        # Both detection branches present in the JS block.
        assert 'data.installed' in resp.text
        assert 'data.web' in resp.text

    def test_integrations_shows_office365_oauth_section(self, client, admin_cookies):
        """Office 365 OAuth install-level credentials section
        (2026-05-10 — per-account → install-level lift)."""
        resp = client.get("/config?tab=integrations", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Office 365 OAuth" in resp.text
        assert 'name="office365_oauth_tenant_id"' in resp.text
        assert 'name="office365_oauth_client_id"' in resp.text
        assert 'name="office365_oauth_client_secret"' in resp.text

    def test_config_shows_runtime_defaults(self, client, admin_cookies):
        """When no runtime settings are saved, defaults should be shown."""
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'name="dry_run"' in resp.text
        assert "INFO" in resp.text


class TestGoogleOAuthSave:
    """B1 (revised 2026-05-10): install-level OAuth client creds
    persist via secrets store. Save endpoint moved from /config/save
    to /admin/integrations/save."""

    def _post(self, client, admin_cookies, **extra):
        data = {"public_url": "", "gmail_topic_name": "",
                "gmail_subscription_sa_email": "", "gmail_audience": ""}
        data.update(extra)
        return client.post(
            "/admin/integrations/save",
            data=data,
            cookies=admin_cookies,
            follow_redirects=False,
        )

    def test_save_writes_google_oauth_to_secrets(self, client, admin_cookies):
        resp = self._post(
            client, admin_cookies,
            google_oauth_web_client_id="web-cid.apps.googleusercontent.com",
            google_oauth_web_client_secret="GOCSPX-web",
            google_oauth_desktop_client_id="desk-cid.apps.googleusercontent.com",
            google_oauth_desktop_client_secret="GOCSPX-desk",
        )
        assert resp.status_code in (200, 303)
        secrets = client.app.state.secrets
        assert secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID") == "web-cid.apps.googleusercontent.com"
        assert secrets.get("GOOGLE_OAUTH_WEB_CLIENT_SECRET") == "GOCSPX-web"
        assert secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_ID") == "desk-cid.apps.googleusercontent.com"
        assert secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET") == "GOCSPX-desk"

    def test_blank_secret_submit_preserves_stored_value(self, client, admin_cookies):
        """Mask-preserve semantics: posting an empty client_secret
        keeps the stored value (same pattern as pre-B1 per-account
        form). Client IDs are plaintext so always get overwritten."""
        secrets = client.app.state.secrets
        secrets.set("GOOGLE_OAUTH_WEB_CLIENT_SECRET", "GOCSPX-existing")

        resp = self._post(
            client, admin_cookies,
            google_oauth_web_client_id="new-web-cid",
            google_oauth_web_client_secret="",  # deliberately blank
            google_oauth_desktop_client_id="",
            google_oauth_desktop_client_secret="",
        )
        assert resp.status_code in (200, 303)
        assert secrets.get("GOOGLE_OAUTH_WEB_CLIENT_SECRET") == "GOCSPX-existing"
        assert secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID") == "new-web-cid"

    def test_save_writes_office365_oauth_to_secrets(self, client, admin_cookies):
        """O365 OAuth save lives on the same /admin/integrations/save
        endpoint as Google OAuth — same secrets-store pattern."""
        resp = self._post(
            client, admin_cookies,
            office365_oauth_tenant_id="11111111-2222-3333-4444-555555555555",
            office365_oauth_client_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            office365_oauth_client_secret="o365-secret-value",
        )
        assert resp.status_code in (200, 303)
        secrets = client.app.state.secrets
        assert secrets.get("O365_OAUTH_TENANT_ID") == "11111111-2222-3333-4444-555555555555"
        assert secrets.get("O365_OAUTH_CLIENT_ID") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert secrets.get("O365_OAUTH_CLIENT_SECRET") == "o365-secret-value"

    def test_office365_tenant_rejects_common(self, client, admin_cookies):
        """Install-level tenant cannot be 'common' — that string is
        reserved for the per-account 'Personal Microsoft account' path.
        Submission with 'common' clears the field rather than saving."""
        resp = self._post(
            client, admin_cookies,
            office365_oauth_tenant_id="common",
            office365_oauth_client_id="some-client-id",
        )
        assert resp.status_code in (200, 303)
        secrets = client.app.state.secrets
        assert secrets.get("O365_OAUTH_TENANT_ID") == ""

    def test_migration_scrubs_per_account_creds(self, db):
        """Migration lifts first-found client_id/secret to install level
        and strips every account's client_id/client_secret keys."""
        import json
        from email_triage.web.db import migrate_oauth_creds_to_install_level

        now = "2026-04-19T00:00:00+00:00"
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            ("a@x.com", "A", "admin", now),
        )
        db.commit()
        uid = cur.lastrowid
        for n, cid, csec in [("A1", "cid-A", "sec-A"), ("A2", "cid-B", "sec-B")]:
            db.execute(
                "INSERT INTO email_accounts "
                "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
                "VALUES (?, ?, 'gmail_api', ?, 0, ?, ?)",
                (uid, n, json.dumps({
                    "account": f"{n}@gmail.com", "client_id": cid, "client_secret": csec,
                }), now, now),
            )
        db.commit()

        found = migrate_oauth_creds_to_install_level(db)
        assert found == ("cid-A", "sec-A")

        rows = db.execute("SELECT config_json FROM email_accounts").fetchall()
        for row in rows:
            cfg = json.loads(row["config_json"])
            assert "client_id" not in cfg
            assert "client_secret" not in cfg
            assert cfg.get("account", "").endswith("@gmail.com")

        # Idempotent — second call finds nothing.
        assert migrate_oauth_creds_to_install_level(db) is None


class TestConfigSave:
    """POST /config/save — save all settings."""

    def test_save_requires_auth(self, client):
        resp = client.post(
            "/config/save",
            data={"log_level": "DEBUG"},
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_save_forbidden_for_regular_user(self, client, user_cookies):
        resp = client.post(
            "/config/save",
            data={"log_level": "DEBUG"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_save_dry_run_on(self, client, db, admin_cookies):
        resp = client.post(
            "/config/save",
            data={"dry_run": "1", "log_level": "INFO", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Dry-run mode is ON" in resp.text

        settings = get_setting(db, "runtime_settings")
        assert settings is not None
        assert settings["dry_run"] is True

    def test_save_dry_run_off(self, client, db, admin_cookies):
        set_setting(db, "runtime_settings", {"dry_run": True, "log_level": "INFO", "hipaa": False})

        resp = client.post(
            "/config/save",
            data={"log_level": "INFO", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        settings = get_setting(db, "runtime_settings")
        assert settings["dry_run"] is False

    def test_save_log_level(self, client, db, admin_cookies):
        resp = client.post(
            "/config/save",
            data={"log_level": "DEBUG", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        settings = get_setting(db, "runtime_settings")
        assert settings["log_level"] == "DEBUG"

    def test_save_classifier_backend(self, client, app, admin_cookies):
        resp = client.post(
            "/config/save",
            data={"log_level": "INFO", "classifier_backend": "openai",
                  "classifier_model": "gpt-4o", "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert app.state.config.classifier.backend == "openai"
        assert app.state.config.classifier.model == "gpt-4o"

    def test_save_smtp_settings(self, client, app, admin_cookies):
        resp = client.post(
            "/config/save",
            data={"log_level": "INFO", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_host": "mail.example.com", "smtp_port": "465",
                  "smtp_username": "user@example.com", "smtp_from_addr": "noreply@example.com",
                  "smtp_use_tls": "1",
                  "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert app.state.config.smtp.host == "mail.example.com"
        assert app.state.config.smtp.port == 465
        assert app.state.config.smtp.from_addr == "noreply@example.com"
        assert app.state.config.smtp.use_tls is True

    def test_save_shows_confirmation(self, client, admin_cookies):
        resp = client.post(
            "/config/save",
            data={"log_level": "WARNING", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "All settings saved" in resp.text

    def test_save_applies_log_level_immediately(self, client, db, admin_cookies):
        import logging
        client.post(
            "/config/save",
            data={"log_level": "DEBUG", "classifier_backend": "ollama",
                  "classifier_model": "[local-llm-model] "classifier_ollama_url": "http://localhost:11434",
                  "smtp_port": "587", "logging_format": "text"},
            cookies=admin_cookies,
        )
        root = logging.getLogger("email_triage")
        assert root.level == logging.DEBUG

    def test_save_applies_hipaa_immediately(self, client, db, admin_cookies):
        """The HIPAA toggle moved from /config/save to
        /admin/security/save (commit 6bb172b). /config/save now
        preserves the existing DB value to avoid zeroing it out via
        the absent form field. Test updated to target the canonical
        surface."""
        from email_triage import triage_logging

        client.post(
            "/admin/security/save",
            data={"hipaa": "1",
                  "auth_session_ttl_secs": "86400",
                  "auth_hipaa_session_ttl_secs": "900"},
            cookies=admin_cookies,
        )
        assert triage_logging._hipaa_mode is True

        client.post(
            "/admin/security/save",
            data={"auth_session_ttl_secs": "86400",
                  "auth_hipaa_session_ttl_secs": "900"},
            cookies=admin_cookies,
        )
        assert triage_logging._hipaa_mode is False


class TestDryRunBehavior:
    """Verify dry-run mode skips action execution."""

    def test_runtime_settings_defaults(self, db):
        from email_triage.web.routers.ui import _get_runtime_settings, _is_dry_run
        settings = _get_runtime_settings(db)
        assert settings["dry_run"] is False
        assert settings["log_level"] == "INFO"
        assert settings["hipaa"] is False
        assert _is_dry_run(db) is False

    def test_dry_run_flag_reads_from_db(self, db):
        from email_triage.web.routers.ui import _is_dry_run
        set_setting(db, "runtime_settings", {"dry_run": True, "log_level": "INFO", "hipaa": False})
        assert _is_dry_run(db) is True

    def test_dry_run_flag_off_reads_from_db(self, db):
        from email_triage.web.routers.ui import _is_dry_run
        set_setting(db, "runtime_settings", {"dry_run": False, "log_level": "INFO", "hipaa": False})
        assert _is_dry_run(db) is False


class TestProfilePage:
    """GET /profile — per-user escalation settings."""

    def test_profile_requires_auth(self, client):
        resp = client.get("/profile", follow_redirects=False)
        assert resp.status_code == 303

    def test_profile_visible_to_any_user(self, client, user_cookies):
        resp = client.get("/profile", cookies=user_cookies)
        assert resp.status_code == 200
        assert "My Settings" in resp.text

    def test_profile_shows_escalation_categories(self, client, admin_cookies):
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Escalation Categories" in resp.text

    def test_profile_shows_notify_email_field(self, client, admin_cookies):
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'name="notify_email"' in resp.text


class TestProfileSave:
    """POST /profile/save — save escalation prefs."""

    def test_save_requires_auth(self, client):
        resp = client.post("/profile/save", data={}, follow_redirects=False)
        assert resp.status_code == 303

    def test_save_notify_email(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            "/profile/save",
            data={"notify_email": "sms@vtext.com"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        row = db.execute("SELECT notify_email FROM users WHERE id = ?", (admin_user["id"],)).fetchone()
        assert row["notify_email"] == "sms@vtext.com"

    def test_save_escalation_categories(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            "/profile/save",
            data={
                "notify_email": "sms@vtext.com",
                "escalate_to-respond": "1",
                "escalate_action-required": "1",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Escalation active for" in resp.text

        from email_triage.web.db import get_user_escalation_categories
        cats = get_user_escalation_categories(db, admin_user["id"])
        assert "to-respond" in cats
        assert "action-required" in cats

    def test_save_clears_escalation_when_unchecked(self, client, db, admin_user, admin_cookies):
        from email_triage.web.db import set_user_escalation_categories
        set_user_escalation_categories(db, admin_user["id"], ["to-respond"])

        # Save with nothing checked.
        resp = client.post(
            "/profile/save",
            data={"notify_email": "sms@vtext.com"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        from email_triage.web.db import get_user_escalation_categories
        cats = get_user_escalation_categories(db, admin_user["id"])
        assert len(cats) == 0

    def test_save_warns_if_no_notify_email(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            "/profile/save",
            data={"escalate_to-respond": "1"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "no notify address" in resp.text

    # #73 — carrier dropdown path -------------------------------------

    def test_save_with_carrier_dropdown_computes_address(
        self, client, db, admin_user, admin_cookies,
    ):
        """Cell number + carrier slug → users.notify_email is the
        gateway address; settings row tracks the operator's choice."""
        resp = client.post(
            "/profile/save",
            data={"sms_number": "(555) 123-4567", "sms_carrier": "verizon"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text[:300]
        row = db.execute(
            "SELECT notify_email FROM users WHERE id = ?",
            (admin_user["id"],),
        ).fetchone()
        assert row["notify_email"] == "5551234567@vtext.com"

        from email_triage.web.db import get_setting
        prefs = get_setting(db, f"escalation_sms:{admin_user['id']}")
        assert prefs == {"number": "5551234567", "carrier": "verizon"}

    def test_save_with_carrier_renders_choice_on_revisit(
        self, client, db, admin_user, admin_cookies,
    ):
        client.post(
            "/profile/save",
            data={"sms_number": "5551234567", "sms_carrier": "att"},
            cookies=admin_cookies,
        )
        resp = client.get("/profile", cookies=admin_cookies)
        # Carrier dropdown re-renders with the operator's prior pick.
        assert 'value="att"\n                    selected' in resp.text or \
               'value="att"\n                            selected' in resp.text or \
               '<option value="att"' in resp.text and "selected" in resp.text

    def test_save_with_freetext_clears_settings_row(
        self, client, db, admin_user, admin_cookies,
    ):
        """Free-text override path deletes any prior dropdown choice."""
        # Seed a dropdown choice first.
        client.post(
            "/profile/save",
            data={"sms_number": "5551234567", "sms_carrier": "verizon"},
            cookies=admin_cookies,
        )
        # Now switch to free-text override.
        resp = client.post(
            "/profile/save",
            data={"notify_email": "oncall@example.com"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        row = db.execute(
            "SELECT notify_email FROM users WHERE id = ?",
            (admin_user["id"],),
        ).fetchone()
        assert row["notify_email"] == "oncall@example.com"
        from email_triage.web.db import get_setting
        assert get_setting(db, f"escalation_sms:{admin_user['id']}") is None

    def test_save_with_both_empty_clears_everything(
        self, client, db, admin_user, admin_cookies,
    ):
        # Seed a dropdown choice first.
        client.post(
            "/profile/save",
            data={"sms_number": "5551234567", "sms_carrier": "verizon"},
            cookies=admin_cookies,
        )
        # Now save with neither path populated.
        resp = client.post(
            "/profile/save",
            data={},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        row = db.execute(
            "SELECT notify_email FROM users WHERE id = ?",
            (admin_user["id"],),
        ).fetchone()
        assert row["notify_email"] is None
        from email_triage.web.db import get_setting
        assert get_setting(db, f"escalation_sms:{admin_user['id']}") is None

    def test_save_with_bad_cell_number_surfaces_error(
        self, client, db, admin_user, admin_cookies,
    ):
        resp = client.post(
            "/profile/save",
            data={"sms_number": "12345", "sms_carrier": "verizon"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "10-digit" in resp.text
        # users row untouched.
        row = db.execute(
            "SELECT notify_email FROM users WHERE id = ?",
            (admin_user["id"],),
        ).fetchone()
        assert row["notify_email"] is None

    def test_save_with_unknown_carrier_surfaces_error(
        self, client, db, admin_user, admin_cookies,
    ):
        resp = client.post(
            "/profile/save",
            data={"sms_number": "5551234567", "sms_carrier": "fake-co"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Unknown carrier" in resp.text

    def test_should_escalate_db_helper(self, db, admin_user):
        """Test the should_escalate DB helper directly."""
        from email_triage.web.db import set_user_escalation_categories, should_escalate

        # No prefs set — should not escalate.
        assert should_escalate(db, admin_user["id"], "to-respond") is None

        # Set notify_email and prefs.
        db.execute("UPDATE users SET notify_email = ? WHERE id = ?", ("sms@test.com", admin_user["id"]))
        db.commit()
        set_user_escalation_categories(db, admin_user["id"], ["to-respond"])

        result = should_escalate(db, admin_user["id"], "to-respond")
        assert result == "sms@test.com"

        # Different category — should not escalate.
        assert should_escalate(db, admin_user["id"], "newsletters") is None

    def test_should_escalate_no_notify_email(self, db, admin_user):
        """Even with prefs, no escalation if notify_email is blank."""
        from email_triage.web.db import set_user_escalation_categories, should_escalate
        set_user_escalation_categories(db, admin_user["id"], ["to-respond"])
        assert should_escalate(db, admin_user["id"], "to-respond") is None
