"""Tests for the free-slot finder."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from email_triage.engine.availability import find_free_slots
from email_triage.engine.models import CalendarEvent


def _ev(start: datetime, end: datetime, **kw) -> CalendarEvent:
    return CalendarEvent(
        event_id=kw.get("id", f"{int(start.timestamp())}"),
        summary=kw.get("summary", "busy"),
        start=start, end=end,
        all_day=kw.get("all_day", False),
        status=kw.get("status", "confirmed"),
        transparency=kw.get("transparency", "opaque"),
    )


def _utc(y, m, d, hh=0, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=timezone.utc)


# Anchor a Monday (2026-04-20 is a Monday) to keep tests deterministic.
MONDAY = _utc(2026, 4, 20)


def test_empty_calendar_fills_n_slots():
    horizon_start = MONDAY.replace(hour=8)
    horizon_end = MONDAY + timedelta(days=1)
    slots = find_free_slots(
        events=[],
        horizon_start=horizon_start,
        horizon_end=horizon_end,
        length_minutes=30, count=3,
    )
    assert len(slots) == 3
    # First slot is at 09:00 (business hours start).
    assert slots[0][0] == _utc(2026, 4, 20, 9, 0)
    assert slots[0][1] == _utc(2026, 4, 20, 9, 30)
    assert slots[1][0] == _utc(2026, 4, 20, 9, 30)


def test_single_conflict_splits_the_day():
    busy = [_ev(_utc(2026, 4, 20, 10, 0), _utc(2026, 4, 20, 11, 0))]
    slots = find_free_slots(
        events=busy,
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=60, count=4,
    )
    starts = [s[0] for s in slots]
    assert _utc(2026, 4, 20, 9, 0) in starts
    # 10:00-11:00 is busy, next available 60-min slot starts at 11:00.
    assert _utc(2026, 4, 20, 11, 0) in starts
    # No slot overlaps the conflict.
    for start, end in slots:
        assert not (start < _utc(2026, 4, 20, 11, 0) and end > _utc(2026, 4, 20, 10, 0))


def test_all_day_event_blocks_full_day():
    busy = [_ev(MONDAY, MONDAY + timedelta(days=1), all_day=True)]
    # Tuesday should still have free slots.
    slots = find_free_slots(
        events=busy,
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=2),
        length_minutes=30, count=2,
    )
    assert len(slots) == 2
    # All slots fall on Tuesday.
    for start, _end in slots:
        assert start.date() == (MONDAY + timedelta(days=1)).date()


def test_skip_weekends_jumps_to_monday():
    # Horizon starts on Saturday 2026-04-18.
    sat = _utc(2026, 4, 18, 9, 0)
    horizon_end = sat + timedelta(days=4)
    slots = find_free_slots(
        events=[],
        horizon_start=sat,
        horizon_end=horizon_end,
        length_minutes=30, count=2,
        skip_weekends=True,
    )
    assert all(s[0].weekday() < 5 for s in slots)
    assert slots[0][0].date() == MONDAY.date()


def test_no_skip_weekends():
    sat = _utc(2026, 4, 18, 9, 0)
    horizon_end = sat + timedelta(days=2)
    slots = find_free_slots(
        events=[],
        horizon_start=sat,
        horizon_end=horizon_end,
        length_minutes=30, count=2,
        skip_weekends=False,
    )
    assert slots[0][0].date() == sat.date()


def test_horizon_cutoff():
    # Horizon ends right after one slot fits.
    slots = find_free_slots(
        events=[],
        horizon_start=MONDAY.replace(hour=9),
        horizon_end=MONDAY.replace(hour=9, minute=45),
        length_minutes=30, count=10,
    )
    assert len(slots) == 1


def test_lead_time_floor_via_horizon_start():
    # Caller pre-computes the lead time and bumps horizon_start.
    cursor = MONDAY.replace(hour=14, minute=15)
    slots = find_free_slots(
        events=[],
        horizon_start=cursor,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=30, count=2,
    )
    assert slots[0][0] >= cursor
    assert slots[0][0] == cursor


def test_zero_count_returns_empty():
    slots = find_free_slots(
        events=[],
        horizon_start=MONDAY.replace(hour=9),
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=30, count=0,
    )
    assert slots == []


def test_cancelled_events_ignored():
    busy = [
        _ev(_utc(2026, 4, 20, 10, 0), _utc(2026, 4, 20, 11, 0),
            status="cancelled"),
    ]
    slots = find_free_slots(
        events=busy,
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=60, count=8,
    )
    # If the cancelled event were honoured, 10:00 would be busy. Verify
    # 10:00 IS in the slot list — meaning we ignored the cancellation.
    starts = [s[0] for s in slots]
    assert _utc(2026, 4, 20, 10, 0) in starts


def test_business_hours_in_user_timezone():
    # User is in America/Los_Angeles (UTC-7 with DST in April).
    # Their 09:00 local == 16:00 UTC on a weekday.
    horizon_start = _utc(2026, 4, 20, 0, 0)
    horizon_end = horizon_start + timedelta(days=1)
    slots = find_free_slots(
        events=[],
        horizon_start=horizon_start,
        horizon_end=horizon_end,
        length_minutes=60, count=1,
        timezone_name="America/Los_Angeles",
    )
    assert len(slots) == 1
    # 09:00 PT == 16:00 UTC (DST).
    assert slots[0][0] == _utc(2026, 4, 20, 16, 0)


# ---------------------------------------------------------------------------
# Per-weekday WorkingHours (Phase 5)
# ---------------------------------------------------------------------------

from email_triage.engine.models import WorkingHours


def test_working_hours_single_window_per_day():
    wh = WorkingHours(
        mon=[("10:00", "12:00")],
        tue=[("09:00", "17:00")],
        wed=[], thu=[], fri=[],
        sat=[], sun=[],
    )
    slots = find_free_slots(
        events=[],
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=2),
        length_minutes=30, count=10,
        working_hours=wh,
    )
    # Mon: 10:00-12:00 → 4 slots; Tue: 09:00-17:00 → 16 slots.
    assert len(slots) == 10  # capped by count
    assert slots[0][0] == _utc(2026, 4, 20, 10, 0)
    assert slots[3][1] == _utc(2026, 4, 20, 12, 0)
    # 5th slot starts on Tuesday at 09:00.
    assert slots[4][0] == _utc(2026, 4, 21, 9, 0)


def test_working_hours_lunch_break_blocks_crossing_slot():
    # 09:00-12:00 and 13:00-17:00 — no slot crosses 12:00-13:00.
    wh = WorkingHours(
        mon=[("09:00", "12:00"), ("13:00", "17:00")],
        tue=[], wed=[], thu=[], fri=[], sat=[], sun=[],
    )
    slots = find_free_slots(
        events=[],
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=60, count=20,
        working_hours=wh,
    )
    # 3 morning slots (09, 10, 11) + 4 afternoon (13, 14, 15, 16) = 7.
    assert len(slots) == 7
    starts = [s[0] for s in slots]
    # No slot starts at 12:00 (would cross break).
    assert _utc(2026, 4, 20, 12, 0) not in starts
    # 13:00 is the first afternoon slot.
    assert _utc(2026, 4, 20, 13, 0) in starts


def test_working_hours_skip_weekend_via_empty_lists():
    wh = WorkingHours(
        mon=[("09:00", "10:00")],
        tue=[], wed=[], thu=[], fri=[],
        sat=[("09:00", "17:00")],  # Sat is on
        sun=[],
    )
    # Horizon: Saturday → Sunday.
    sat = _utc(2026, 4, 18, 0, 0)
    slots = find_free_slots(
        events=[],
        horizon_start=sat,
        horizon_end=sat + timedelta(days=1),
        length_minutes=60, count=20,
        working_hours=wh,
    )
    # Saturday: 09:00-17:00 → 8 slots.
    assert len(slots) == 8


def test_working_hours_ooo_event_blocks_overlap():
    wh = WorkingHours(
        mon=[("09:00", "17:00")],
        tue=[], wed=[], thu=[], fri=[], sat=[], sun=[],
    )
    busy = [_ev(_utc(2026, 4, 20, 11, 0), _utc(2026, 4, 20, 13, 0))]
    slots = find_free_slots(
        events=busy,
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=60, count=20,
        working_hours=wh,
    )
    starts = [s[0] for s in slots]
    # 11:00 and 12:00 should be blocked.
    assert _utc(2026, 4, 20, 11, 0) not in starts
    assert _utc(2026, 4, 20, 12, 0) not in starts
    # Resumes at 13:00.
    assert _utc(2026, 4, 20, 13, 0) in starts


def test_working_hours_legacy_path_when_none():
    # Confirm the legacy single-window + skip_weekends path is unchanged.
    slots = find_free_slots(
        events=[],
        horizon_start=MONDAY,
        horizon_end=MONDAY + timedelta(days=1),
        length_minutes=30, count=2,
        working_hours=None,  # explicit
        business_hours_start="09:00",
        business_hours_end="10:00",
        skip_weekends=True,
    )
    assert len(slots) == 2
    assert slots[0][0] == _utc(2026, 4, 20, 9, 0)


# ---------------------------------------------------------------------------
# 2026-05-14 — one-per-day spread (suggestion_days knob)
# ---------------------------------------------------------------------------


class TestOnePerDaySpread:
    """``days_window`` enables one-per-day mode: pick the EARLIEST
    free slot in each working day, walk up to ``days_window`` days,
    return up to ``count`` slots. Replaces the legacy contiguous-
    fill that returned three back-to-back morning slots on a quiet
    calendar."""

    def test_three_over_five_empty_calendar(self):
        """3 suggestions over 5 days, empty calendar → 3 slots from
        3 distinct working days, each at 09:00."""
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=3,
            days_window=5,
        )
        assert len(slots) == 3
        # Each slot's date should be distinct.
        dates = [s[0].date() for s in slots]
        assert len(set(dates)) == 3
        # Each at 09:00 local UTC (test default).
        for s, _ in slots:
            assert s.hour == 9 and s.minute == 0
        # Sequential working days: Mon, Tue, Wed.
        assert dates[0] == MONDAY.date()
        assert dates[1] == (MONDAY + timedelta(days=1)).date()
        assert dates[2] == (MONDAY + timedelta(days=2)).date()

    def test_four_over_three_distributes_multi_slot_days(self):
        """4 suggestions over 3 days → 2/1/1 split on Mon/Tue/Wed."""
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=4,
            days_window=3,
        )
        assert len(slots) == 4
        dates = [s[0].date() for s in slots]
        # 3 distinct days, total 4 slots.
        assert len(set(dates)) == 3
        # First day gets 2 slots (ceil(4/3)=2), subsequent days 1 each.
        from collections import Counter
        counts = Counter(dates)
        assert counts[MONDAY.date()] == 2
        assert counts[(MONDAY + timedelta(days=1)).date()] == 1
        assert counts[(MONDAY + timedelta(days=2)).date()] == 1

    def test_five_over_three_distributes_two_two_one(self):
        """5 suggestions over 3 days → 2/2/1 split."""
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=5,
            days_window=3,
        )
        assert len(slots) == 5
        from collections import Counter
        dates = [s[0].date() for s in slots]
        counts = Counter(dates)
        assert counts[MONDAY.date()] == 2
        assert counts[(MONDAY + timedelta(days=1)).date()] == 2
        assert counts[(MONDAY + timedelta(days=2)).date()] == 1

    def test_busy_day_skipped_doesnt_burn_quota(self):
        """Fully-busy day does NOT burn a productive-day quota.
        2026-05-14 redesign: the walk advances past busy days
        without counting them, so '3 over 2 with Mon busy' still
        returns 3 slots from Tue+Wed (2+1 or similar split)."""
        # Block all of Mon 09:00–17:00.
        busy = [_ev(_utc(2026, 4, 20, 9, 0), _utc(2026, 4, 20, 17, 0))]
        slots = find_free_slots(
            events=busy,
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=3,
            days_window=2,
        )
        # Mon yields 0, advances past. Tue + Wed = 2 productive days.
        # 3 slots distributed 2/1 across Tue/Wed (ceil(3/2)=2 first).
        assert len(slots) == 3
        dates = [s[0].date() for s in slots]
        from collections import Counter
        counts = Counter(dates)
        # Mon should NOT appear.
        assert MONDAY.date() not in counts
        # Tue + Wed are productive.
        assert counts[(MONDAY + timedelta(days=1)).date()] == 2
        assert counts[(MONDAY + timedelta(days=2)).date()] == 1

    def test_weekends_skipped_dont_burn_quota(self):
        """Sat/Sun (default skip_weekends=True) shouldn't count
        against days_window. 5 days from Fri should reach the NEXT
        Friday (Fri/Mon/Tue/Wed/Thu)."""
        FRIDAY = _utc(2026, 4, 24)
        slots = find_free_slots(
            events=[],
            horizon_start=FRIDAY,
            horizon_end=FRIDAY + timedelta(days=14),
            length_minutes=30, count=5,
            days_window=5,
        )
        assert len(slots) == 5
        dates = [s[0].date() for s in slots]
        # Should be Fri 4-24, Mon 4-27, Tue 4-28, Wed 4-29, Thu 4-30.
        assert dates[0] == FRIDAY.date()
        assert dates[1] == (FRIDAY + timedelta(days=3)).date()  # Mon
        assert dates[4] == (FRIDAY + timedelta(days=6)).date()  # Thu

    def test_working_hours_off_days_dont_burn_quota(self):
        """The WorkingHours matrix marks off-days with ``[]`` per
        weekday. Days with empty intervals are skipped without
        burning a productive-day quota slot. Cross-check: a 3-day
        quota starting on Friday with Sat/Sun off should pull
        Fri/Mon/Tue (3 productive days), not Fri/Sat/Sun."""
        from email_triage.engine.models import WorkingHours
        wh = WorkingHours(
            mon=[("09:00", "17:00")], tue=[("09:00", "17:00")],
            wed=[("09:00", "17:00")], thu=[("09:00", "17:00")],
            fri=[("09:00", "17:00")],
            sat=[], sun=[],  # Off-days
        )
        FRIDAY = _utc(2026, 4, 24)
        slots = find_free_slots(
            events=[],
            horizon_start=FRIDAY,
            horizon_end=FRIDAY + timedelta(days=14),
            length_minutes=30, count=3,
            days_window=3,
            working_hours=wh,
        )
        assert len(slots) == 3
        dates = [s[0].date() for s in slots]
        # Fri/Mon/Tue — Sat/Sun bypassed without burning quota.
        assert dates[0] == FRIDAY.date()
        assert dates[1] == (FRIDAY + timedelta(days=3)).date()
        assert dates[2] == (FRIDAY + timedelta(days=4)).date()

    def test_transparent_event_doesnt_block_slot(self):
        """``transparency == "transparent"`` events appear on the
        calendar but DON'T block free/busy. Birthday + reminder
        events on contact-derived calendars come back transparent
        from Google; ``showAs == "free"`` from MS Graph maps to
        transparent. Operator-symptom (2026-05-14): a Monday
        all-day "(redacted personal event)" event blanked the whole day
        from suggestions even though it has no real busy time."""
        # Two events on Monday: a transparent all-day birthday +
        # an opaque 10:30-11:30 actual meeting. Expect slots BEFORE
        # 10:30 to be free.
        birthday = _ev(
            _utc(2026, 4, 20, 0, 0), _utc(2026, 4, 21, 0, 0),
            all_day=True, transparency="transparent",
            summary="(redacted personal event)",
        )
        meeting = _ev(
            _utc(2026, 4, 20, 10, 30), _utc(2026, 4, 20, 11, 30),
            transparency="opaque", summary="Real meeting",
        )
        slots = find_free_slots(
            events=[birthday, meeting],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=1),
            length_minutes=30, count=3,
        )
        # Birthday is transparent → doesn't block.
        # Meeting is opaque → blocks 10:30-11:30.
        # 09:00, 09:30, 10:00 should all be free.
        assert len(slots) == 3
        assert slots[0][0] == _utc(2026, 4, 20, 9, 0)
        assert slots[1][0] == _utc(2026, 4, 20, 9, 30)
        assert slots[2][0] == _utc(2026, 4, 20, 10, 0)

    def test_opaque_all_day_event_still_blocks(self):
        """An all-day event WITHOUT ``transparency="transparent"``
        (default opaque) still blocks the whole day, same as before
        cycle 11. Distinguishes "marked free/transparent" from
        "actually busy all day."""
        busy_all_day = _ev(
            _utc(2026, 4, 20, 0, 0), _utc(2026, 4, 21, 0, 0),
            all_day=True,  # transparency defaults to opaque
        )
        slots = find_free_slots(
            events=[busy_all_day],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=2),
            length_minutes=30, count=2,
        )
        # Mon entirely blocked. Tue 09:00 + 09:30 are free.
        assert len(slots) == 2
        assert slots[0][0] == _utc(2026, 4, 21, 9, 0)
        assert slots[1][0] == _utc(2026, 4, 21, 9, 30)

    def test_all_day_event_blocks_correct_local_day(self):
        """All-day event with ``date: "2026-04-21"`` (UTC-midnight
        per Google API spec) must block 2026-04-21 in the USER'S
        local timezone, NOT shift back by the timezone offset.

        Operator-symptom 2026-05-14: (redacted personal event) stored as
        ``date: "2026-05-19"`` (Tue) blanked Mon 5/18 from
        suggestions because the pre-fix code did
        ``.astimezone(America/Detroit).date()`` → ``2026-05-18 20:00
        EDT`` → ``.date() == May 18``. The fix reads the date
        AS-IS from start.date() and anchors the busy block in the
        viewer's timezone so it covers the right calendar day.
        """
        # Reproduce the bug: opaque all-day event stored as Tue
        # UTC-midnight. Viewer in America/Detroit. The block should
        # cover Tue 05-21 local, NOT bleed into Mon 05-20.
        tue_all_day = _ev(
            _utc(2026, 4, 21, 0, 0),  # 2026-04-21 00:00 UTC
            _utc(2026, 4, 22, 0, 0),  # exclusive
            all_day=True,  # default opaque → blocks
        )
        # Look at Mon 04-20 — should have free slots; pre-fix this
        # day got blocked because the all-day event "leaked" back.
        slots = find_free_slots(
            events=[tue_all_day],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=2),
            length_minutes=30, count=2,
            timezone_name="America/Detroit",
        )
        assert len(slots) == 2
        # Both slots should be on Monday (Tue is correctly blocked).
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("America/Detroit")
        for s, _ in slots:
            assert s.astimezone(tz).date() == datetime(
                2026, 4, 20, tzinfo=tz,
            ).date()

    def test_mid_week_off_day_in_matrix_doesnt_burn_quota(self):
        """If the operator marks a weekday as off (e.g. Wed = []
        for a 4-day work week), that day is skipped just like
        Sat/Sun. days_window=3 starting Mon with Wed off reaches
        Mon/Tue/Thu (3 productive days), skipping Wed."""
        from email_triage.engine.models import WorkingHours
        wh = WorkingHours(
            mon=[("09:00", "17:00")], tue=[("09:00", "17:00")],
            wed=[],  # operator's mid-week off day
            thu=[("09:00", "17:00")], fri=[("09:00", "17:00")],
            sat=[], sun=[],
        )
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=3,
            days_window=3,
            working_hours=wh,
        )
        assert len(slots) == 3
        dates = [s[0].date() for s in slots]
        # Mon/Tue/Thu — Wed bypassed.
        assert dates[0] == MONDAY.date()
        assert dates[1] == (MONDAY + timedelta(days=1)).date()  # Tue
        assert dates[2] == (MONDAY + timedelta(days=3)).date()  # Thu
        # Wed (MONDAY + 2 days) must NOT appear.
        assert (MONDAY + timedelta(days=2)).date() not in dates

    def test_first_free_slot_skips_morning_meeting(self):
        """When the earliest morning slot is blocked, pick the next
        free slot in the SAME day (then advance to next day)."""
        # Block Mon 09:00–10:00; expect first slot to be 10:00.
        busy = [_ev(_utc(2026, 4, 20, 9, 0), _utc(2026, 4, 20, 10, 0))]
        slots = find_free_slots(
            events=busy,
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=2,
            days_window=2,
        )
        assert len(slots) == 2
        # Mon's slot starts at 10:00.
        assert slots[0][0] == _utc(2026, 4, 20, 10, 0)
        # Tue's slot starts at 09:00 (next day, earliest).
        assert slots[1][0] == _utc(2026, 4, 21, 9, 0)

    def test_legacy_packed_mode_when_no_days_window(self):
        """``days_window=None`` (or omitted) returns the legacy
        contiguous-fill behaviour for back-compat."""
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=3,
            # days_window not passed → legacy mode
        )
        # All 3 from Monday — legacy contiguous-fill.
        assert len(slots) == 3
        for s, _ in slots:
            assert s.date() == MONDAY.date()

    def test_days_window_zero_returns_empty(self):
        """days_window=0 is the empty-quota case → no slots."""
        slots = find_free_slots(
            events=[],
            horizon_start=MONDAY,
            horizon_end=MONDAY + timedelta(days=14),
            length_minutes=30, count=3,
            days_window=0,
        )
        # Operator-facing the form bounds this to 1+; defensive
        # zero still returns empty without crashing.
        assert slots == []
