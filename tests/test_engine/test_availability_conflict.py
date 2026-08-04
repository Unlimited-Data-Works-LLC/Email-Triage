"""N-291 R30 unit tests for check_availability_conflict (row 67 seam)."""
from __future__ import annotations

from datetime import datetime, timezone

from email_triage.engine.availability import check_availability_conflict
from email_triage.engine.models import CalendarEvent


def _mk(start, end, event_id="x", summary="m"):
    return CalendarEvent(event_id=event_id, summary=summary, start=start, end=end)


def test_clear_no_conflict():
    inv_s = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)  # Wed 10am UTC
    inv_e = datetime(2026, 7, 8, 11, 0, tzinfo=timezone.utc)
    r = check_availability_conflict(inv_s, inv_e, [])
    assert r["conflict"] is False
    assert r["reason"] == "clear"
    assert r["overlapping_events"] == []


def test_event_overlap():
    inv_s = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)
    inv_e = datetime(2026, 7, 8, 11, 0, tzinfo=timezone.utc)
    ev = _mk(datetime(2026, 7, 8, 10, 30, tzinfo=timezone.utc),
             datetime(2026, 7, 8, 11, 30, tzinfo=timezone.utc))
    r = check_availability_conflict(inv_s, inv_e, [ev])
    assert r["conflict"] is True
    assert r["reason"] == "event_overlap"
    assert len(r["overlapping_events"]) == 1


def test_adjacent_no_overlap():
    """Half-open: event ending at inv_start is NOT overlapping."""
    inv_s = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)
    inv_e = datetime(2026, 7, 8, 11, 0, tzinfo=timezone.utc)
    ev = _mk(datetime(2026, 7, 8, 9, 0, tzinfo=timezone.utc),
             datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc))
    r = check_availability_conflict(inv_s, inv_e, [ev])
    assert r["conflict"] is False
    assert r["reason"] == "clear"


def test_weekend_skip():
    """Saturday 10am is outside working hours when skip_weekends=True."""
    inv_s = datetime(2026, 7, 11, 10, 0, tzinfo=timezone.utc)  # Sat
    inv_e = datetime(2026, 7, 11, 11, 0, tzinfo=timezone.utc)
    r = check_availability_conflict(inv_s, inv_e, [])
    assert r["conflict"] is True
    assert r["reason"] == "weekend"


def test_outside_business_hours():
    inv_s = datetime(2026, 7, 8, 20, 0, tzinfo=timezone.utc)  # Wed 8pm
    inv_e = datetime(2026, 7, 8, 21, 0, tzinfo=timezone.utc)
    r = check_availability_conflict(inv_s, inv_e, [])
    assert r["conflict"] is True
    assert r["reason"] == "outside_hours"


def test_weekend_allowed_when_skip_off():
    """skip_weekends=False + hours 00:00-23:59 → Sat 10am is clear."""
    inv_s = datetime(2026, 7, 11, 10, 0, tzinfo=timezone.utc)
    inv_e = datetime(2026, 7, 11, 11, 0, tzinfo=timezone.utc)
    r = check_availability_conflict(
        inv_s, inv_e, [],
        business_hours_start="00:00", business_hours_end="23:59",
        skip_weekends=False,
    )
    assert r["conflict"] is False, r
