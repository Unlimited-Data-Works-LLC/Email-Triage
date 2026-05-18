"""Free-slot finder for the meeting-request intercept.

Pure function: given a list of busy ``CalendarEvent`` instances and a
horizon, return up to ``count`` non-overlapping free slots of the
requested length, earliest first, that fall inside the user's
business hours and (optionally) skip weekends.

No I/O, no provider coupling — easy to unit-test.
"""

from __future__ import annotations

import math
from datetime import date, datetime, time, timedelta, timezone
from typing import Iterable
from zoneinfo import ZoneInfo

from email_triage.engine.models import CalendarEvent, WorkingHours


def _parse_hhmm(s: str, default_h: int, default_m: int) -> time:
    try:
        h, m = s.split(":")
        return time(int(h), int(m))
    except Exception:
        return time(default_h, default_m)


def _to_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _merge_busy(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    """Sort + merge overlapping/adjacent busy intervals."""
    if not intervals:
        return []
    sorted_intervals = sorted(intervals, key=lambda x: x[0])
    merged: list[tuple[datetime, datetime]] = [sorted_intervals[0]]
    for start, end in sorted_intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _day_windows(
    day: date,
    tz,
    *,
    working_hours: WorkingHours | None,
    business_hours_start: str,
    business_hours_end: str,
    skip_weekends: bool,
) -> list[tuple[datetime, datetime]]:
    """Return the day's availability windows in UTC.

    With ``working_hours``: returns one (start, end) per interval the
    user configured for that weekday; an empty list means the day is
    off (lunch breaks become two windows). Without: falls back to the
    legacy single business-hours window plus weekend-skip.
    """
    if working_hours is not None:
        intervals = working_hours.for_weekday(day.weekday())
        out: list[tuple[datetime, datetime]] = []
        for start_str, end_str in intervals:
            s = _parse_hhmm(start_str, 0, 0)
            e = _parse_hhmm(end_str, 0, 0)
            if e <= s:
                continue
            ws = datetime.combine(day, s, tzinfo=tz).astimezone(timezone.utc)
            we = datetime.combine(day, e, tzinfo=tz).astimezone(timezone.utc)
            out.append((ws, we))
        return out

    # Legacy single-window path.
    if skip_weekends and day.weekday() >= 5:
        return []
    bh_start_t = _parse_hhmm(business_hours_start, 9, 0)
    bh_end_t = _parse_hhmm(business_hours_end, 17, 0)
    if bh_end_t <= bh_start_t:
        return []
    ws = datetime.combine(day, bh_start_t, tzinfo=tz).astimezone(timezone.utc)
    we = datetime.combine(day, bh_end_t, tzinfo=tz).astimezone(timezone.utc)
    return [(ws, we)]


def find_free_slots(
    events: Iterable[CalendarEvent],
    horizon_start: datetime,
    horizon_end: datetime,
    length_minutes: int,
    count: int,
    *,
    working_hours: WorkingHours | None = None,
    business_hours_start: str = "09:00",
    business_hours_end: str = "17:00",
    skip_weekends: bool = True,
    timezone_name: str = "UTC",
    days_window: int | None = None,
) -> list[tuple[datetime, datetime]]:
    """Return up to ``count`` free slots of the requested length.

    All returned datetimes are tz-aware in UTC. Day windowing
    operates in the user's ``timezone_name``.

    Two windowing modes:

    - When ``working_hours`` is supplied (recommended), each day's
      availability is derived from the per-weekday intervals.
      Multiple intervals (lunch breaks) are honoured. ``skip_weekends``
      and ``business_hours_*`` are ignored in this mode — set
      ``working_hours.sat == [] and .sun == []`` for weekend skip.
    - When ``working_hours`` is None, falls back to the legacy
      single business-hours window plus ``skip_weekends`` flag.

    A slot is "free" when it sits inside one of the day's availability
    windows and doesn't overlap any event in ``events``. All-day
    events block the entire local day. Cancelled events are ignored.

    2026-05-14 — ``days_window`` controls slot spread:

      * ``None`` (legacy): pack contiguous slots inside each day
        until ``count`` is reached, then return. Suggestions are
        often all from the same morning when the calendar's quiet.
      * positive integer (recommended): spread mode. Distribute
        ``count`` slots across up to ``days_window`` distinct days
        that have free time. Per-day quota is
        ``ceil(remaining_count / remaining_productive_days)`` —
        adapts as the walk progresses so the slot total reaches
        ``count`` when possible without artificially pinning a
        one-slot-per-day cap.

        Examples (empty calendar, Mon-Fri working hours):
          * ``count=3, days_window=5`` → 1 slot each Mon/Tue/Wed
          * ``count=4, days_window=3`` → 2 slots Mon, 1 Tue, 1 Wed
          * ``count=5, days_window=3`` → 2 Mon, 2 Tue, 1 Wed

        Fully-booked days DON'T burn a quota day — the algorithm
        walks past them and only counts days where it actually
        found a slot. This lets ``4 over 3`` mean "4 slots over
        the first 3 productive days from today" rather than
        "4 slots within whichever 3-day stretch starts next."
    """
    if count <= 0 or length_minutes <= 0:
        return []
    try:
        tz = ZoneInfo(timezone_name)
    except Exception:
        tz = ZoneInfo("UTC")

    horizon_start = _to_aware_utc(horizon_start)
    horizon_end = _to_aware_utc(horizon_end)
    if horizon_end <= horizon_start:
        return []

    # Build busy intervals (UTC). Treat all-day events as blocking the
    # full local day, converted to UTC.
    busy: list[tuple[datetime, datetime]] = []
    for e in events:
        if not e or e.start is None or e.end is None:
            continue
        if str(e.status).lower() == "cancelled":
            continue
        # 2026-05-14 — "transparent" events (Google's "show as free",
        # MS Graph showAs=="free", contact-derived birthdays,
        # reminders) appear on the calendar but DON'T block. Skip
        # them when computing busy intervals so a Monday birthday
        # or an all-day reminder doesn't blank the whole day's
        # meeting suggestions.
        if str(getattr(e, "transparency", "opaque")).lower() == "transparent":
            continue
        if e.all_day:
            # 2026-05-14 — Google/Graph all-day events come back as
            # ``{"date": "YYYY-MM-DD"}`` with no timezone. The
            # provider normaliser stores them as the UTC-midnight of
            # the date AS-WRITTEN (e.g. ``2026-05-19 00:00 UTC``).
            # The DATE portion is the event's LOCAL day per the API
            # spec — the calendar UI shows it on that day regardless
            # of viewer timezone. Pre-fix this code did
            # ``.astimezone(tz).date()`` which shifted UTC-midnight
            # BACK by the offset (UTC-4 → 2026-05-18 20:00 EDT →
            # date() == May 18), producing a busy-block on the wrong
            # day. Operator-symptom: (redacted personal event) (stored as
            # date "2026-05-19") landed on Mon 5/18 in the slot
            # finder, blanking Monday from meeting suggestions.
            # Fix: read the date AS-IS from the start datetime; only
            # then anchor the busy block in the user's local tz so
            # the start/end pair covers the right calendar day.
            local_day = e.start.date()
            day_start_local = datetime.combine(local_day, time.min, tzinfo=tz)
            day_end_local = day_start_local + timedelta(days=1)
            busy.append((day_start_local.astimezone(timezone.utc),
                         day_end_local.astimezone(timezone.utc)))
        else:
            busy.append((_to_aware_utc(e.start), _to_aware_utc(e.end)))

    busy = _merge_busy(busy)

    slot_delta = timedelta(minutes=length_minutes)
    out: list[tuple[datetime, datetime]] = []

    cursor_local = horizon_start.astimezone(tz)
    end_local = horizon_end.astimezone(tz)
    day = cursor_local.date()

    # 2026-05-14 — spread mode. ``days_window is not None`` flips
    # spread on; ``days_window`` caps the number of distinct
    # PRODUCTIVE days (days that actually yielded a slot). Days that
    # are fully booked don't count — the walk continues past them.
    # Per-day quota is computed dynamically as
    # ``ceil(remaining_count / remaining_productive_days)`` so the
    # total reaches ``count`` even when ``count > days_window``.
    one_per_day = days_window is not None
    candidate_days_with_slots = 0

    while True:
        day_local_start = datetime.combine(day, time.min, tzinfo=tz)
        if day_local_start >= end_local:
            break

        windows = _day_windows(
            day, tz,
            working_hours=working_hours,
            business_hours_start=business_hours_start,
            business_hours_end=business_hours_end,
            skip_weekends=skip_weekends,
        )
        if not windows:
            day += timedelta(days=1)
            continue

        # Productive-day quota check. days_window=0 (defensive) and
        # quota-exhausted both short-circuit here.
        if one_per_day:
            remaining_days = (
                days_window - candidate_days_with_slots  # type: ignore[operator]
            )
            if remaining_days <= 0:
                break
            remaining_count = count - len(out)
            if remaining_count <= 0:
                break
            # ceil-division: when remaining_count doesn't divide
            # evenly the first days carry the extra slot (e.g.
            # 4 over 3 → 2/1/1, 5 over 3 → 2/2/1). Adapts each
            # day because the remaining_days denominator shrinks
            # only on days that actually yielded a slot.
            per_day_quota = math.ceil(
                remaining_count / remaining_days,
            )
        else:
            per_day_quota = count  # legacy effectively unbounded

        # Slot count for THIS day so we know whether to advance
        # candidate_days_with_slots after walking the windows.
        day_slots_added = 0

        # Walk each interval; the slot finder resets per-interval so
        # a lunch-break gap doesn't yield a slot that crosses it.
        for raw_ws, raw_we in windows:
            window_start = max(raw_ws, horizon_start)
            window_end = min(raw_we, horizon_end)
            if window_end <= window_start:
                continue

            cursor = window_start
            relevant = [
                (max(b[0], window_start), min(b[1], window_end))
                for b in busy
                if b[0] < window_end and b[1] > window_start
            ]
            relevant.sort()

            for b_start, b_end in relevant:
                while cursor + slot_delta <= b_start:
                    out.append((cursor, cursor + slot_delta))
                    if len(out) >= count:
                        return out
                    day_slots_added += 1
                    if one_per_day and day_slots_added >= per_day_quota:
                        break
                    cursor = cursor + slot_delta
                if (
                    one_per_day
                    and day_slots_added >= per_day_quota
                ):
                    break
                cursor = max(cursor, b_end)

            if one_per_day and day_slots_added >= per_day_quota:
                break

            while cursor + slot_delta <= window_end:
                out.append((cursor, cursor + slot_delta))
                if len(out) >= count:
                    return out
                day_slots_added += 1
                if one_per_day and day_slots_added >= per_day_quota:
                    break
                cursor = cursor + slot_delta

            if one_per_day and day_slots_added >= per_day_quota:
                break

        # Days with at least one slot count against days_window;
        # fully-booked days don't (they're still walked, just don't
        # advance the productive-day counter).
        if one_per_day and day_slots_added > 0:
            candidate_days_with_slots += 1

        day += timedelta(days=1)

    return out
