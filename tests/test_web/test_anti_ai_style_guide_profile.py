"""/profile?tab=writing — per-user anti-AI style guide round-trip."""

from __future__ import annotations


class TestPerUserAntiAiGuideRender:
    def test_section_renders_in_writing_tab(
        self, client, user_cookies,
    ):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Section heading + textarea name + checkbox name.
        assert "Things the AI should never do" in body
        assert 'name="anti_ai_style_guide_user"' in body
        assert 'name="anti_ai_style_guide_disable_global"' in body

    def test_tooltip_uses_generic_placeholders_no_real_names(
        self, client, user_cookies,
    ):
        """Audience-per-page rule: end-user template must not leak
        customer local-parts or real names — generic placeholders only.
        Pin a specific case where the operator might be tempted to put
        a real-sounding example."""
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        body = resp.text.lower()
        # The local-parts catalogued by the privacy invariant for
        # customer names. None should appear in the rendered tooltip /
        # placeholder copy.
        for name in (
            "user", "claforest", "alice",
            "family-member", "friend",
        ):
            assert name not in body, (
                f"Generic-placeholder rule: real name {name!r} leaked"
            )


class TestPerUserAntiAiGuideSave:
    def test_save_round_trip_persists_user_text(
        self, client, user_cookies, regular_user, db,
    ):
        text = (
            "Never start with 'Certainly!' or 'Of course'. "
            "Avoid em-dashes for narrative pause."
        )
        resp = client.post(
            "/profile/writing/save",
            data={
                "active_tab":             "writing",
                "style_tone":             "neutral",
                "style_length":           "medium",
                "style_greeting":         "first-name",
                "anti_ai_style_guide_user": text,
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        from email_triage.web.db import get_user_anti_ai_style_guide
        stored, disable = get_user_anti_ai_style_guide(
            db, regular_user["id"],
        )
        assert "Certainly!" in stored
        assert "em-dashes" in stored
        assert disable is False

        # Re-GET reflects the saved values in the form.
        resp2 = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp2.status_code == 200
        assert "Certainly!" in resp2.text

    def test_disable_global_flag_persists(
        self, client, user_cookies, regular_user, db,
    ):
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":                       "neutral",
                "style_length":                     "medium",
                "style_greeting":                   "first-name",
                "anti_ai_style_guide_user":         "my own rules only",
                "anti_ai_style_guide_disable_global": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_user_anti_ai_style_guide
        text, disable = get_user_anti_ai_style_guide(db, regular_user["id"])
        assert text == "my own rules only"
        assert disable is True

        # The checkbox is rendered as checked on re-GET.
        resp2 = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp2.status_code == 200
        # The hidden input/checkbox carries the value attribute + a
        # ``checked`` flag in the template.
        body = resp2.text
        assert 'name="anti_ai_style_guide_disable_global"' in body
        # Find the input line and verify the ``checked`` rendering near it.
        idx = body.find('name="anti_ai_style_guide_disable_global"')
        assert idx > 0
        # Look ±200 chars for the ``checked`` token.
        window = body[max(0, idx - 200): idx + 200]
        assert "checked" in window

    def test_unchecking_clears_disable_flag(
        self, client, user_cookies, regular_user, db,
    ):
        # First set the flag.
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":                       "neutral",
                "style_length":                     "medium",
                "style_greeting":                   "first-name",
                "anti_ai_style_guide_disable_global": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_user_anti_ai_style_guide
        _, disable = get_user_anti_ai_style_guide(db, regular_user["id"])
        assert disable is True

        # Now clear it (the checkbox is simply absent from the POST).
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":     "neutral",
                "style_length":   "medium",
                "style_greeting": "first-name",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        _, disable = get_user_anti_ai_style_guide(db, regular_user["id"])
        assert disable is False

    def test_long_text_capped(
        self, client, user_cookies, regular_user, db,
    ):
        client.post(
            "/profile/writing/save",
            data={
                "style_tone":               "neutral",
                "style_length":             "medium",
                "style_greeting":           "first-name",
                "anti_ai_style_guide_user": "x" * 10000,
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import (
            ANTI_AI_STYLE_GUIDE_MAX_LEN,
            get_user_anti_ai_style_guide,
        )
        text, _ = get_user_anti_ai_style_guide(db, regular_user["id"])
        assert len(text) <= ANTI_AI_STYLE_GUIDE_MAX_LEN

    def test_save_requires_auth(self, client):
        resp = client.post(
            "/profile/writing/save",
            data={"anti_ai_style_guide_user": "anon attempt"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]


class TestCsrfFieldPresent:
    """The Writing tab form must carry a server-side csrf_input()
    invocation (covered by the broader regression test, but pinned
    here so a future template-rewrite that drops it on the anti-AI
    fieldset fails this file)."""

    def test_csrf_token_field_in_writing_form(self, client, user_cookies):
        resp = client.get("/profile?tab=writing", cookies=user_cookies)
        assert resp.status_code == 200
        assert 'name="csrf_token"' in resp.text
