"""#161 item 3 — /config Style learning admin section.

Covers:

  * GET /config renders the new section with current values.
  * POST /config/save round-trips both inputs through the helpers.
  * Out-of-range submissions clamp to the documented bounds.
"""

from __future__ import annotations

from email_triage.web.db import (
    get_style_learning_capture_interval_hours,
    get_style_learning_mine_limit_default,
    set_style_learning_capture_interval_hours,
    set_style_learning_mine_limit_default,
    STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS,
    STYLE_LEARNING_MINE_LIMIT_MAX,
)


class TestSectionRenders:
    def test_admin_sees_style_learning_section(
        self, client, admin_cookies,
    ):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Style learning" in resp.text
        assert 'name="style_learning_capture_interval_hours"' in resp.text
        assert 'name="style_learning_mine_limit_default"' in resp.text

    def test_section_shows_current_values(
        self, client, admin_cookies, db,
    ):
        set_style_learning_capture_interval_hours(db, 12)
        set_style_learning_mine_limit_default(db, 80)
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        # Inputs reflect saved values.
        assert 'value="12"' in resp.text
        assert 'value="80"' in resp.text

    def test_section_hidden_from_non_admin(
        self, client, user_cookies,
    ):
        resp = client.get("/config", cookies=user_cookies)
        # Regular users get 403 on /config entirely; the section is
        # never exposed.
        assert resp.status_code == 403


class TestSave:
    def _post_save(self, client, admin_cookies, **extras):
        # The /config/save handler reads dozens of fields; pass an
        # empty form + just the two new fields. Everything else
        # defaults to the existing config / runtime values (the
        # handler is built to no-op missing fields, not to clobber).
        data = {
            "style_learning_capture_interval_hours": "18",
            "style_learning_mine_limit_default": "120",
        }
        data.update(extras)
        return client.post(
            "/config/save",
            data=data,
            cookies=admin_cookies,
        )

    def test_save_persists_cadence_and_mine_limit(
        self, client, admin_cookies, db,
    ):
        resp = self._post_save(client, admin_cookies)
        assert resp.status_code in (200, 303)
        assert get_style_learning_capture_interval_hours(db) == 18
        assert get_style_learning_mine_limit_default(db) == 120

    def test_save_clamps_out_of_range_inputs(
        self, client, admin_cookies, db,
    ):
        resp = self._post_save(
            client, admin_cookies,
            style_learning_capture_interval_hours="9999",
            style_learning_mine_limit_default="9999",
        )
        assert resp.status_code in (200, 303)
        assert (
            get_style_learning_capture_interval_hours(db)
            == STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS
        )
        assert (
            get_style_learning_mine_limit_default(db)
            == STYLE_LEARNING_MINE_LIMIT_MAX
        )

    def test_blank_input_does_not_clobber(
        self, client, admin_cookies, db,
    ):
        set_style_learning_capture_interval_hours(db, 24)
        set_style_learning_mine_limit_default(db, 150)
        resp = self._post_save(
            client, admin_cookies,
            style_learning_capture_interval_hours="",
            style_learning_mine_limit_default="",
        )
        assert resp.status_code in (200, 303)
        # Blank inputs leave the existing values in place.
        assert get_style_learning_capture_interval_hours(db) == 24
        assert get_style_learning_mine_limit_default(db) == 150
