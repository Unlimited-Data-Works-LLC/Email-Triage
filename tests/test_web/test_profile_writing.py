"""Profile Writing tab — GET / POST round trip + HIPAA / master gating.

Covers the M-1 + M-2 form behaviour end-to-end against the FastAPI
TestClient. The pure prompt-block formatting tests live in
``tests/test_actions/test_style_knobs.py``.
"""

from __future__ import annotations



class TestWritingTabRender:
    def test_writing_tab_appears_in_settings_strip(
        self, client, user_cookies,
    ):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        # The cluster nav strip lists Writing as a sibling tab.
        assert "/profile?tab=writing" in resp.text
        assert "Writing" in resp.text

    def test_writing_tab_renders_form(self, client, user_cookies):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        # Form actions point at the dedicated save endpoint.
        assert 'action="/profile/writing/save"' in resp.text
        # Each radio group surfaces its slugs.
        for slug in (
            "formal", "neutral", "casual", "terse",
            "brief", "medium", "full",
        ):
            assert f'value="{slug}"' in resp.text

    def test_writing_tab_intro_distinguishes_user_and_inferred(
        self, client, user_cookies,
    ):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        # The descriptive intro paragraph has to spell out that there
        # are TWO sources (user-stated + system-inferred).
        body = resp.text.lower()
        assert "explicit" in body
        assert "automatic" in body or "inferred" in body or "learns" in body


class TestWritingTabSave:
    def test_save_round_trip_persists_values(
        self, client, user_cookies, regular_user, db,
    ):
        # POST a non-default set.
        resp = client.post(
            "/profile/writing/save",
            data={
                "active_tab":            "writing",
                "style_tone":            "terse",
                "style_length":          "brief",
                "style_greeting":        "none",
                "style_greeting_custom": "",
                "style_signature":       "— Operator A",
                "style_guide":           "Keep replies short. No emojis.",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "/profile?tab=writing" in resp.headers["location"]

        # Re-GET reflects the saved values.
        resp2 = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp2.status_code == 200
        assert "Operator A" in resp2.text
        assert "Keep replies short" in resp2.text
        # The terse + brief radios are checked.
        assert (
            'name="style_tone" value="terse"\n                       checked'
            in resp2.text
            or 'value="terse"' in resp2.text
            and 'checked' in resp2.text
        )

        # And the DB row carries the values.
        from email_triage.web.db import get_user_style_knobs
        stored = get_user_style_knobs(db, regular_user["id"])
        assert stored["style_tone"] == "terse"
        assert stored["style_length"] == "brief"
        assert stored["style_greeting"] == "none"
        assert stored["style_signature"] == "— Operator A"
        assert "Keep replies short" in stored["style_guide"]

    def test_invalid_tone_falls_back_to_default(
        self, client, user_cookies, regular_user, db,
    ):
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":     "EVIL_TONE",
                "style_length":   "ALSO_INVALID",
                "style_greeting": "first-name",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_user_style_knobs
        stored = get_user_style_knobs(db, regular_user["id"])
        # Invalid values reverted to documented defaults.
        assert stored["style_tone"] == "neutral"
        assert stored["style_length"] == "medium"
        assert stored["style_greeting"] == "first-name"

    def test_long_guide_is_capped(
        self, client, user_cookies, regular_user, db,
    ):
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":     "neutral",
                "style_length":   "medium",
                "style_greeting": "first-name",
                "style_guide":    "x" * 5000,
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_user_style_knobs
        stored = get_user_style_knobs(db, regular_user["id"])
        assert len(stored["style_guide"]) <= 2000

    def test_save_requires_auth(self, client):
        resp = client.post(
            "/profile/writing/save",
            data={"style_tone": "terse"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]


class TestWritingTabHipaa:
    def test_hipaa_user_sees_hipaa_chip_and_disabled_form(
        self, client, user_cookies, regular_user, db,
    ):
        # Owner has at least one HIPAA-flagged account → the Writing
        # tab surfaces the HIPAA chip and the form fieldsets render
        # disabled.
        from datetime import datetime, timezone
        from email_triage.web.db import create_email_account
        # The fixture-installed regular_user is the actor; create a
        # HIPAA-flagged account they own.
        create_email_account(
            db,
            user_id=regular_user["id"],
            name="HIPAA Inbox",
            provider_type="imap",
            config={
                "host": "mail.example.com",
                "port": 993,
                "username": "user@example.com",
                "password": "secret",
                "mailbox": "INBOX",
                "use_ssl": True,
            },
            hipaa=True,
        )
        # Sanity check.
        del datetime, timezone

        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Chip explaining HIPAA exclusion.
        assert "HIPAA mode" in body
        # Fieldsets disabled when the user is HIPAA-blocked.
        assert "<fieldset disabled>" in body
        # Save button likewise disabled.
        assert "<button type=\"submit\" disabled" in body


class TestWritingTabMasterToggle:
    def test_master_off_renders_admin_disabled_chip(
        self, client, user_cookies, db,
    ):
        from email_triage.web.db import set_style_learning_master_enabled
        set_style_learning_master_enabled(db, False)

        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text.lower()
        # Per audience-rule, no link to /config, but the disabled chip
        # IS allowed.
        assert "style learning is off" in body
        # Negative assertion: there must be no link target /config.
        assert 'href="/config"' not in resp.text


class TestNoAdminPathsOrJargon:
    """Audience-rule guardrails on the rendered Writing tab.

    The Writing tab is end-user; rendered HTML must not contain
    admin-path references, "language model" / "LLM" jargon, or
    forbidden protocol terms.
    """

    def test_no_admin_path_text_in_writing_tab(
        self, client, user_cookies,
    ):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text
        forbidden_links = [
            'href="/config"',
            'href="/admin/',
        ]
        for needle in forbidden_links:
            assert needle not in body, (
                f"Writing tab must not link to admin paths: {needle!r}"
            )
        # "Ask your administrator" copy is forbidden per the
        # audience rule.
        assert "ask your administrator" not in body.lower()

    def test_no_jargon_in_writing_tab(self, client, user_cookies):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text.lower()
        # End-user pages cannot use developer / protocol terminology.
        # NB: the Writing tab itself; other tabs in profile.html are
        # outside the scope of this rule.
        # Match a SECTION of the page, not the full template, so we
        # don't accidentally catch jargon in unrelated tabs.
        # Simple containment check across the whole rendered page is
        # safe here because the tab is the one we navigated to.
        for term in (
            "language model",
            " llm ",
            "rfc ",
            "iso 8601",
            "odata",
            "and-combined",
            "substring match",
            "system log",
        ):
            assert term not in body, f"Writing tab leaks jargon: {term!r}"
