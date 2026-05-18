"""/config — install-wide anti-AI style guide round-trip."""

from __future__ import annotations


class TestGlobalAntiAiStyleGuide:
    def test_section_renders_on_config_page(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Section heading + textarea name are both rendered.
        assert "Anti-AI style guide" in body
        assert 'name="anti_ai_style_guide_global"' in body

    def test_save_round_trip_persists_global(
        self, client, admin_cookies, db,
    ):
        text = (
            "Never start with 'Certainly!' or 'Of course'. "
            "Never use em-dashes for narrative pause."
        )
        # Build the form payload — /config/save also reads the other
        # required form fields (classifier_backend, ingestion intervals,
        # smtp_*); the handler tolerates missing fields by falling back
        # to the existing config values, so a minimal POST that names
        # only the new field still works for this test surface.
        resp = client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": text,
                # Required-ish round-trip values so the form doesn't
                # clobber unrelated config with empty strings.
                "log_level": "INFO",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 200, resp.text

        # Helper round-trip from the DB.
        from email_triage.web.db import get_global_anti_ai_style_guide
        stored = get_global_anti_ai_style_guide(db)
        assert "Never start with 'Certainly!'" in stored
        assert "em-dashes" in stored

        # Re-GET reflects the saved value.
        resp2 = client.get("/config", cookies=admin_cookies)
        assert resp2.status_code == 200
        assert "Never start with" in resp2.text

    def test_save_strips_whitespace(self, client, admin_cookies, db):
        client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": "  trim me  \n",
                "log_level": "INFO",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_global_anti_ai_style_guide
        assert get_global_anti_ai_style_guide(db) == "trim me"

    def test_long_text_capped_at_max_len(self, client, admin_cookies, db):
        client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": "x" * 10000,
                "log_level": "INFO",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import (
            ANTI_AI_STYLE_GUIDE_MAX_LEN,
            get_global_anti_ai_style_guide,
        )
        stored = get_global_anti_ai_style_guide(db)
        assert len(stored) <= ANTI_AI_STYLE_GUIDE_MAX_LEN

    def test_clear_field_persists_empty(self, client, admin_cookies, db):
        # First save some text.
        client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": "some text",
                "log_level": "INFO",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_global_anti_ai_style_guide
        assert get_global_anti_ai_style_guide(db) == "some text"

        # Now clear it.
        client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": "",
                "log_level": "INFO",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert get_global_anti_ai_style_guide(db) == ""

    def test_non_admin_user_cannot_save(self, client, user_cookies, db):
        resp = client.post(
            "/config/save",
            data={
                "anti_ai_style_guide_global": "ATTEMPT_BY_USER",
                "log_level": "INFO",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        # 403 for non-admin; DB must remain untouched.
        assert resp.status_code in (303, 403)
        from email_triage.web.db import get_global_anti_ai_style_guide
        assert "ATTEMPT_BY_USER" not in get_global_anti_ai_style_guide(db)


class TestHelpers:
    """Helper round-trip exercised directly (no HTTP)."""

    def test_get_default_empty(self, db):
        from email_triage.web.db import get_global_anti_ai_style_guide
        assert get_global_anti_ai_style_guide(db) == ""

    def test_set_then_get(self, db):
        from email_triage.web.db import (
            get_global_anti_ai_style_guide,
            set_global_anti_ai_style_guide,
        )
        set_global_anti_ai_style_guide(db, "ban Certainly!")
        assert get_global_anti_ai_style_guide(db) == "ban Certainly!"

    def test_set_strips_and_overwrites(self, db):
        from email_triage.web.db import (
            get_global_anti_ai_style_guide,
            set_global_anti_ai_style_guide,
        )
        set_global_anti_ai_style_guide(db, "v1")
        set_global_anti_ai_style_guide(db, "  v2  ")
        assert get_global_anti_ai_style_guide(db) == "v2"
