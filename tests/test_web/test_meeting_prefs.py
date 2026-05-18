"""Tests for the per-user meeting-preferences profile section."""

import os

import pytest


def _login(client, admin_cookies):
    return admin_cookies


class TestProfileTimezoneDropdown:
    """Item #13 — default tz from $TZ + full IANA list, America/* first."""

    def test_profile_default_timezone_uses_env_tz(
        self, client, admin_cookies, admin_user, monkeypatch,
    ):
        """Fresh user with no saved prefs gets $TZ in the rendered input."""
        monkeypatch.setenv("TZ", "America/Detroit")
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        # Locate the timezone input specifically.
        import re
        # Find the <input ... name="timezone" ...> element and capture its value.
        match = re.search(
            r'<input[^>]*name="timezone"[^>]*>', resp.text,
        )
        assert match is not None, "timezone input not found in rendered HTML"
        tag = match.group(0)
        val = re.search(r'value="([^"]*)"', tag)
        assert val is not None, f"no value attr in tag: {tag!r}"
        assert val.group(1) == "America/Detroit", (
            f"expected America/Detroit, got {val.group(1)!r}; full tag: {tag!r}"
        )

    def test_profile_default_timezone_falls_back_to_utc_when_no_env(
        self, client, admin_cookies, admin_user, monkeypatch,
    ):
        """With TZ unset, a fresh user sees UTC pre-selected."""
        monkeypatch.delenv("TZ", raising=False)
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        import re
        match = re.search(
            r'<input[^>]*name="timezone"[^>]*value="([^"]*)"', resp.text,
        )
        assert match is not None
        assert match.group(1) == "UTC"

    def test_profile_timezone_dropdown_includes_full_iana_list(
        self, client, admin_cookies, admin_user,
    ):
        """The <datalist> is populated from zoneinfo, not just 9 hardcoded entries."""
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        # Extract the tz-list datalist contents.
        import re
        block = re.search(
            r'<datalist id="tz-list">(.*?)</datalist>', resp.text, re.DOTALL,
        )
        assert block is not None, "tz-list datalist not rendered"
        options = re.findall(r'<option value="([^"]+)"', block.group(1))
        # Full IANA list is ~450 entries. Allow slack — just check > 100.
        assert len(options) > 100, (
            f"expected full IANA list, got only {len(options)} options"
        )
        # Spot-check a few entries from different regions.
        assert "America/Detroit" in options
        assert "Europe/Berlin" in options
        assert "Asia/Tokyo" in options
        assert "UTC" in options

    def test_profile_timezone_dropdown_orders_america_first(
        self, client, admin_cookies, admin_user,
    ):
        """America/* zones come before other regions in the dropdown."""
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        import re
        block = re.search(
            r'<datalist id="tz-list">(.*?)</datalist>', resp.text, re.DOTALL,
        )
        assert block is not None
        options = re.findall(r'<option value="([^"]+)"', block.group(1))
        # First entry should start with America/.
        assert options[0].startswith("America/"), (
            f"first entry is {options[0]!r}, expected America/*"
        )
        # Find the boundary — last America/ entry and first non-America/*.
        first_non_america = next(
            (i for i, z in enumerate(options) if not z.startswith("America/")),
            None,
        )
        assert first_non_america is not None
        # Every entry before the boundary must be America/*.
        for z in options[:first_non_america]:
            assert z.startswith("America/"), f"{z!r} leaked into America/* block"
        # No America/* entries appear after the boundary.
        for z in options[first_non_america:]:
            assert not z.startswith("America/"), (
                f"{z!r} appears after non-America/* zones"
            )


class TestProfileMeetingPrefs:
    def test_profile_renders_meeting_prefs_section(
        self, client, admin_cookies, admin_user,
    ):
        resp = client.get("/profile", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Meeting-Request Intercept" in resp.text
        # Default length is 30 minutes.
        assert "30 minutes" in resp.text

    def test_save_persists(self, client, db, admin_cookies, admin_user):
        resp = client.post(
            "/profile/meeting-prefs",
            data={
                "default_length_minutes": "60",
                "suggestion_count": "4",
                "business_hours_start": "08:00",
                "business_hours_end": "18:00",
                "skip_weekends": "1",
                "search_horizon_days": "7",
                "minimum_lead_time_hours": "12",
                "timezone": "America/Chicago",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        from email_triage.web.db import get_meeting_prefs
        prefs = get_meeting_prefs(db, admin_user["id"])
        assert prefs["default_length_minutes"] == 60
        assert prefs["suggestion_count"] == 4
        assert prefs["business_hours_start"] == "08:00"
        assert prefs["business_hours_end"] == "18:00"
        assert prefs["timezone"] == "America/Chicago"
        assert prefs["search_horizon_days"] == 7

    def test_invalid_length_clamped_to_default(
        self, client, db, admin_cookies, admin_user,
    ):
        client.post(
            "/profile/meeting-prefs",
            data={
                "default_length_minutes": "999",  # not in dropdown
                "suggestion_count": "3",
                "business_hours_start": "09:00",
                "business_hours_end": "17:00",
                "timezone": "UTC",
                "search_horizon_days": "14",
                "minimum_lead_time_hours": "24",
            },
            cookies=admin_cookies,
        )
        from email_triage.web.db import get_meeting_prefs
        prefs = get_meeting_prefs(db, admin_user["id"])
        # Server clamps to a sane default (30 min).
        assert prefs["default_length_minutes"] == 30


class TestWorkingHoursRoundTrip:
    def test_working_hours_dataclass_round_trip(self):
        from email_triage.engine.models import (
            MeetingPreferences, OutOfOfficeOverride, WorkingHours,
        )
        from datetime import datetime, timezone
        prefs = MeetingPreferences(
            default_length_minutes=60,
            working_hours=WorkingHours(
                mon=[("09:00", "12:00"), ("13:00", "17:00")],
                tue=[("09:00", "17:00")],
                wed=[], thu=[], fri=[],
                sat=[], sun=[],
            ),
            ooo_override=OutOfOfficeOverride(
                enabled=True,
                start=datetime(2026, 4, 25, 0, 0, tzinfo=timezone.utc),
                end=datetime(2026, 4, 27, 0, 0, tzinfo=timezone.utc),
                note="long weekend",
            ),
        )
        round_tripped = MeetingPreferences.from_dict(prefs.to_dict())
        assert round_tripped.working_hours.mon == [("09:00", "12:00"), ("13:00", "17:00")]
        assert round_tripped.working_hours.wed == []
        assert round_tripped.ooo_override.enabled is True
        assert round_tripped.ooo_override.note == "long weekend"
        assert round_tripped.ooo_override.start == datetime(
            2026, 4, 25, tzinfo=timezone.utc,
        )

    def test_partial_working_hours_dict_safe(self):
        from email_triage.engine.models import WorkingHours
        wh = WorkingHours.from_dict({
            "mon": [["09:00", "17:00"]],
            "tue": "garbage",  # wrong type
            "wed": [["09:00"]],  # bad pair
        })
        assert wh.mon == [("09:00", "17:00")]
        assert wh.tue == []
        assert wh.wed == []


class TestProfileFormPersist:
    def test_save_persists_per_day_intervals_with_lunch(
        self, client, db, admin_cookies, admin_user,
    ):
        client.post(
            "/profile/meeting-prefs",
            data={
                "default_length_minutes": "30",
                "suggestion_count": "3",
                "business_hours_start": "09:00",
                "business_hours_end": "17:00",
                "skip_weekends": "1",
                "search_horizon_days": "14",
                "minimum_lead_time_hours": "24",
                "timezone": "UTC",
                # Mon: lunch break.
                "wh_mon_start_0": "09:00", "wh_mon_end_0": "12:00",
                "wh_mon_start_1": "13:00", "wh_mon_end_1": "17:00",
                # Tue: single block.
                "wh_tue_start_0": "09:00", "wh_tue_end_0": "17:00",
                # Wed–Sun left blank.
                "ooo_enabled": "1",
                "ooo_note": "Conference",
                "ooo_start": "2026-04-25T00:00",
                "ooo_end": "2026-04-27T00:00",
            },
            cookies=admin_cookies,
        )
        from email_triage.web.db import get_meeting_prefs
        prefs = get_meeting_prefs(db, admin_user["id"])
        assert prefs["working_hours"]["mon"] == [
            ["09:00", "12:00"], ["13:00", "17:00"],
        ]
        assert prefs["working_hours"]["tue"] == [["09:00", "17:00"]]
        assert prefs["working_hours"]["wed"] == []
        assert prefs["ooo_override"]["enabled"] is True
        assert prefs["ooo_override"]["note"] == "Conference"

    def test_group_apply_weekdays(self, client, db, admin_cookies, admin_user):
        resp = client.post(
            "/profile/meeting-prefs/group-apply",
            data={"scope": "weekdays", "start": "08:00", "end": "16:00"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        from email_triage.web.db import get_meeting_prefs
        wh = get_meeting_prefs(db, admin_user["id"])["working_hours"]
        assert wh["mon"] == [["08:00", "16:00"]]
        assert wh["fri"] == [["08:00", "16:00"]]
        assert wh["sat"] == []  # untouched

    def test_group_apply_weekend(self, client, db, admin_cookies, admin_user):
        client.post(
            "/profile/meeting-prefs/group-apply",
            data={"scope": "weekend", "start": "10:00", "end": "14:00"},
            cookies=admin_cookies,
        )
        from email_triage.web.db import get_meeting_prefs
        wh = get_meeting_prefs(db, admin_user["id"])["working_hours"]
        assert wh["sat"] == [["10:00", "14:00"]]
        assert wh["sun"] == [["10:00", "14:00"]]
        # Mon-Fri untouched (defaults).
        assert wh["mon"] == [["09:00", "17:00"]]


class TestMeetingPrefsTabPreservation:
    """Bug fix: Save Meeting Preferences and Quick set Apply must
    redirect back to ?tab=meeting, not the default ?tab=notifications.

    Regression scope:
    - profile.html has TWO separate <form>s (outer /profile/save +
      meeting-prefs form inside the meeting tab pane).
    - The outer form had a hidden active_tab field; the meeting-prefs
      form did not. Both POST handlers (profile_meeting_prefs_save +
      profile_meeting_prefs_group_apply) call _resolve_profile_tab,
      which falls through to "notifications" when the form lacks
      active_tab and the request URL has no ?tab= query param.
    - Fix: hidden <input name="active_tab" value="meeting"> inside
      the meeting-prefs form.
    """

    def test_meeting_prefs_form_carries_active_tab_field(
        self, client, admin_cookies,
    ):
        """The rendered meeting tab must include the hidden input that
        survives a POST round-trip."""
        resp = client.get("/profile?tab=meeting", cookies=admin_cookies)
        assert resp.status_code == 200
        html = resp.text
        # Hidden field exists and points at the meeting tab.
        assert (
            'name="active_tab" value="meeting"' in html
            or "name='active_tab' value='meeting'" in html
        ), "meeting-prefs form missing active_tab=meeting hidden field"

    def test_save_redirects_back_to_meeting_tab(
        self, client, admin_cookies,
    ):
        resp = client.post(
            "/profile/meeting-prefs",
            data={
                "active_tab": "meeting",
                "default_length_minutes": "30",
                "suggestion_count": "3",
                "business_hours_start": "09:00",
                "business_hours_end": "17:00",
                "timezone": "UTC",
                "search_horizon_days": "14",
                "minimum_lead_time_hours": "24",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/profile?tab=meeting"

    def test_group_apply_redirects_back_to_meeting_tab(
        self, client, admin_cookies,
    ):
        """Quick set Apply button — formaction=group-apply — must
        also land on the meeting tab."""
        resp = client.post(
            "/profile/meeting-prefs/group-apply",
            data={
                "active_tab": "meeting",
                "scope": "weekdays",
                "start": "08:00",
                "end": "16:00",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/profile?tab=meeting"

    def test_save_without_active_tab_falls_back_to_notifications(
        self, client, admin_cookies,
    ):
        """Defense-in-depth: when active_tab is missing AND no ?tab=
        query param, _resolve_profile_tab still falls through to
        notifications — that's expected behaviour for direct API
        callers that don't go through the form. The fix is that the
        form ALWAYS carries the field; this test pins the resolver
        contract so a future "default to meeting" change doesn't
        accidentally land."""
        resp = client.post(
            "/profile/meeting-prefs/group-apply",
            data={"scope": "weekdays", "start": "08:00", "end": "16:00"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/profile?tab=notifications"
