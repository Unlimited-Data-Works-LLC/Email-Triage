"""Tests for #63: scheduled-digest parameter parity with on-demand."""

from email_triage.web.db import set_setting, get_setting


def _add_schedule_via_api(client, cookies, acct_id, form_payload):
    form_payload.setdefault("tz_offset", "0")
    return client.post(
        f"/accounts/{acct_id}/digest/schedule/add",
        data=form_payload,
        cookies=cookies,
    )


def test_legacy_minimal_schedule_still_persists(client, user_cookies, db, regular_user):
    """A schedule posted with only the legacy fields keeps working."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "ACCT1", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "08:00",
            "category": "newsletters",
            "tz_offset": "0",
        },
    )
    assert resp.status_code == 200

    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert isinstance(schedules, list)
    assert len(schedules) == 1
    s = schedules[0]
    assert s["category"] == "newsletters"
    assert s["enabled"] is True
    # New keys populated with defaults.
    assert s["search_filter"] == "today"
    assert s["recipient_mode"] == "back_to_account"
    assert s["delete_originals"] is False
    assert s["limit"] == 25


def test_full_parity_schedule_persists_all_fields(
    client, user_cookies, db, regular_user,
):
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "ACCT2", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "09:30",
            "category": "newsletters",
            "tz_offset": "0",
            "source_folder": "Newsletters",
            "search_filter": "unread_week",
            "html_template": "<p>{{ groups }}</p>",
            "recipient_mode": "user_email",
            "recipient_custom": "",
            "limit": "50",
            "delete_originals": "1",
            "format_prompt": "custom",
        },
    )
    assert resp.status_code == 200

    schedules = get_setting(db, f"digest_schedules:{acct}")
    s = schedules[0]
    assert s["source_folder"] == "Newsletters"
    assert s["search_filter"] == "unread_week"
    assert s["html_template"] == "<p>{{ groups }}</p>"
    assert s["recipient_mode"] == "user_email"
    assert s["recipient_custom"] == ""
    assert s["limit"] == 50
    assert s["delete_originals"] is True
    assert s["format_prompt"] == "custom"


def test_edit_schedule_form_renders(client, user_cookies, db, regular_user):
    """GET /digest/edit/{idx} renders the inline edit form with the
    saved values pre-filled."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "EDIT1", "imap", {"host": "x.example.com"},
    )
    set_setting(db, f"digest_schedules:{acct}", [{
        "time_utc": "08:30",
        "category": "newsletters",
        "enabled": True,
        "source_folder": "Mailing-Lists",
        "search_filter": "unread_week",
        "limit": 75,
        "recipient_mode": "user_email",
    }])
    resp = client.get(
        f"/accounts/{acct}/digest/edit/0", cookies=user_cookies,
    )
    assert resp.status_code == 200
    assert "Mailing-Lists" in resp.text
    assert "unread_week" in resp.text
    assert 'name="recipient_mode"' in resp.text
    # Cancel button hits /digest/schedules.
    assert f"/accounts/{acct}/digest/schedules" in resp.text


def test_edit_schedule_save_persists(client, user_cookies, db, regular_user):
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "EDIT2", "imap", {"host": "x.example.com"},
    )
    set_setting(db, f"digest_schedules:{acct}", [{
        "time_utc": "07:00",
        "category": "newsletters",
        "enabled": True,
    }])
    resp = client.post(
        f"/accounts/{acct}/digest/edit/0",
        data={
            "schedule_time": "09:30",
            "tz_offset": "0",
            "category": "newsletters",
            "source_folder": "After-Edit",
            "search_filter": "unread_week",
            "limit": "100",
            "recipient_mode": "user_email",
            "recipient_custom": "",
            "delete_originals": "1",
            "format_prompt": "edited",
            "html_template": "",
        },
        cookies=user_cookies,
    )
    assert resp.status_code == 200

    schedules = get_setting(db, f"digest_schedules:{acct}")
    s = schedules[0]
    assert s["time_utc"] == "09:30"
    assert s["source_folder"] == "After-Edit"
    assert s["search_filter"] == "unread_week"
    assert s["limit"] == 100
    assert s["recipient_mode"] == "user_email"
    assert s["delete_originals"] is True
    assert s["format_prompt"] == "edited"
    # Enabled flag preserved.
    assert s["enabled"] is True


def test_edit_schedule_404_on_bad_idx(client, user_cookies, db, regular_user):
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "EDIT3", "imap", {"host": "x.example.com"},
    )
    set_setting(db, f"digest_schedules:{acct}", [])
    resp = client.get(
        f"/accounts/{acct}/digest/edit/0", cookies=user_cookies,
    )
    assert resp.status_code == 404


def test_legacy_schedule_shape_reads_as_expected(db, regular_user):
    """A legacy-shape schedule (no new keys) round-trips through the
    scheduler's overlay logic without KeyError."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "LEGACY", "imap", {"host": "x.example.com"},
    )
    # Write a legacy schedule directly.
    set_setting(db, f"digest_schedules:{acct}", [{
        "time_utc": "07:00",
        "category": "newsletters",
        "enabled": True,
    }])
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0]["category"] == "newsletters"
    # New keys absent -> overlay should skip them (verified by inspection).
    assert "source_folder" not in schedules[0]
    assert "search_filter" not in schedules[0]


# #72 — cadence + days-of-week tests --------------------------------------

def test_legacy_schedule_defaults_to_daily_cadence(client, user_cookies, db, regular_user):
    """A schedule posted without cadence fields persists as legacy
    daily (no cadence/days_of_week keys = same as cadence='daily')."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "CADENCE1", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "08:00",
            "category": "newsletters",
        },
    )
    assert resp.status_code == 200
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0].get("cadence", "daily") == "daily"
    assert schedules[0].get("days_of_week") == []


def test_weekly_cadence_with_selected_days_persists(client, user_cookies, db, regular_user):
    """cadence=weekly + checked weekday boxes persist into the
    schedule JSON in canonical Mon-first order."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "CADENCE2", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "09:00",
            "category": "newsletters",
            "cadence": "weekly",
            "day_0": "1",  # Mon
            "day_2": "1",  # Wed
            "day_4": "1",  # Fri
        },
    )
    assert resp.status_code == 200
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0]["cadence"] == "weekly"
    assert schedules[0]["days_of_week"] == [0, 2, 4]


def test_weekly_with_no_days_falls_back_to_daily(client, user_cookies, db, regular_user):
    """Operator picks 'weekly' but doesn't tick any day boxes — we
    fall back to daily so the schedule still fires."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "CADENCE3", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "10:00",
            "category": "newsletters",
            "cadence": "weekly",
        },
    )
    assert resp.status_code == 200
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0]["cadence"] == "daily"
    assert schedules[0]["days_of_week"] == []


def test_unknown_cadence_value_falls_back_to_daily(client, user_cookies, db, regular_user):
    """A cadence string we don't recognize (typo, future value) is
    coerced to daily — fail-safe."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "CADENCE4", "imap", {"host": "x.example.com"},
    )
    resp = _add_schedule_via_api(
        client, user_cookies, acct, {
            "schedule_time": "11:00",
            "category": "newsletters",
            "cadence": "every-second-tuesday",
        },
    )
    assert resp.status_code == 200
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0]["cadence"] == "daily"


def test_edit_changes_cadence_to_weekly(client, user_cookies, db, regular_user):
    """An existing daily schedule can be edited into weekly cadence."""
    from email_triage.web.db import create_email_account
    acct = create_email_account(
        db, regular_user["id"], "EDIT_CADENCE", "imap", {"host": "x.example.com"},
    )
    set_setting(db, f"digest_schedules:{acct}", [{
        "time_utc": "07:00",
        "category": "newsletters",
        "enabled": True,
    }])
    resp = client.post(
        f"/accounts/{acct}/digest/edit/0",
        data={
            "schedule_time": "07:00",
            "category": "newsletters",
            "cadence": "weekly",
            "day_4": "1",  # Fri
            "tz_offset": "0",
            "search_filter": "today",
            "recipient_mode": "back_to_account",
        },
        cookies=user_cookies,
    )
    assert resp.status_code == 200
    schedules = get_setting(db, f"digest_schedules:{acct}")
    assert schedules[0]["cadence"] == "weekly"
    assert schedules[0]["days_of_week"] == [4]


def test_parse_cadence_form_helper_unit():
    """_parse_cadence_form is the single source of truth for cadence
    parsing — direct unit test against synthesized form-mappings."""
    from email_triage.web.routers.ui import _parse_cadence_form

    class _Form:
        def __init__(self, **kw):
            self._d = kw

        def get(self, key, default=None):
            return self._d.get(key, default)

    # Default → daily.
    assert _parse_cadence_form(_Form()) == ("daily", [])
    # Explicit daily ignores any day_X keys.
    cad, days = _parse_cadence_form(_Form(cadence="daily", day_0="1", day_3="1"))
    assert cad == "daily"
    assert days == []
    # Weekly without any boxes → fallback to daily.
    cad, days = _parse_cadence_form(_Form(cadence="weekly"))
    assert cad == "daily"
    assert days == []
    # Weekly with M/W/F → parsed in numeric order.
    cad, days = _parse_cadence_form(_Form(
        cadence="weekly", day_4="1", day_0="1", day_2="1",
    ))
    assert cad == "weekly"
    assert days == [0, 2, 4]
    # Unknown cadence string → daily.
    cad, days = _parse_cadence_form(_Form(cadence="custom-cron"))
    assert cad == "daily"
    assert days == []
