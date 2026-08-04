"""iCalendar (RFC 5545) parsing helpers.

Used by the email providers to surface ``text/calendar`` attachments
as structured data, and by the invite-reply actions to construct
iMIP-compliant `METHOD=REPLY` payloads when no calendar API is
available.
"""

from __future__ import annotations

import logging

from email_triage._int_utils import bounded_int  # N-219c/44 R23
from email_triage.triage_logging import get_logger  # N-196b R21_4
from datetime import date, datetime, time, timezone
from typing import Any

try:
    from icalendar import Calendar, Event, vCalAddress, vText
    HAS_ICAL = True
except ImportError:
    HAS_ICAL = False
    Calendar = Event = vCalAddress = vText = None  # type: ignore[assignment]

logger = get_logger("email_triage.engine.ics")  # N-196b R21_4


def _to_utc(value: Any) -> datetime | None:
    """Coerce an icalendar date/datetime into a tz-aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, date):
        # All-day event boundary — treat as UTC midnight.
        return datetime.combine(value, time.min, tzinfo=timezone.utc)
    return None


def _attendee_dict(att: Any) -> dict[str, Any]:
    """Best-effort flatten of an icalendar ATTENDEE property."""
    raw = str(att) if att is not None else ""
    email_addr = raw.replace("mailto:", "").replace("MAILTO:", "")
    params = getattr(att, "params", {}) if att is not None else {}
    return {
        "email": email_addr,
        "name": str(params.get("CN", "")) if params else "",
        "response_status": str(params.get("PARTSTAT", "needs-action")).lower() if params else "needs-action",
        "role": str(params.get("ROLE", "REQ-PARTICIPANT")) if params else "REQ-PARTICIPANT",
    }


def parse_ics(blob: bytes | str) -> dict[str, Any] | None:
    """Parse the first VEVENT out of an iCalendar payload.

    Returns ``None`` on any parse failure or if no VEVENT is present.
    On success, returns a flat dict::

        {
            "uid": str,
            "summary": str,
            "description": str,
            "location": str,
            "start": datetime | None,    # tz-aware UTC
            "end": datetime | None,      # tz-aware UTC
            "all_day": bool,
            "organizer": str,            # email address
            "attendees": list[dict],     # {email, name, response_status, role}
            "method": str,               # REQUEST | REPLY | CANCEL | "" (component-only)
            "sequence": int,
        }

    Tolerates missing fields. Multi-VEVENT calendars: first wins —
    callers needing the full set should re-parse the raw blob.
    """
    if not HAS_ICAL:
        logger.warning("icalendar not installed; ICS parsing disabled")
        return None
    if not blob:
        return None
    try:
        cal = Calendar.from_ical(blob)
    except Exception as e:
        logger.debug(
            "ICS parse failed",
            extra={"error_type": type(e).__name__, "error_msg": str(e)},
        )
        return None

    # Component-level METHOD lives on the top-level Calendar.
    method = ""
    try:
        method = str(cal.get("METHOD") or "").upper()
    except Exception:
        method = ""

    for component in cal.walk("VEVENT"):
        try:
            uid = str(component.get("UID") or "")
            summary = str(component.get("SUMMARY") or "")
            description = str(component.get("DESCRIPTION") or "")
            location = str(component.get("LOCATION") or "")

            dtstart_prop = component.get("DTSTART")
            dtend_prop = component.get("DTEND")

            start_val = dtstart_prop.dt if dtstart_prop is not None else None
            end_val = dtend_prop.dt if dtend_prop is not None else None

            # All-day events are represented as `date` (no time component)
            # — the icalendar lib hands them back as date objects.
            all_day = isinstance(start_val, date) and not isinstance(start_val, datetime)

            start_dt = _to_utc(start_val)
            end_dt = _to_utc(end_val)

            organizer_prop = component.get("ORGANIZER")
            organizer = ""
            if organizer_prop is not None:
                organizer = str(organizer_prop).replace("mailto:", "").replace("MAILTO:", "")

            attendees_prop = component.get("ATTENDEE", [])
            if not isinstance(attendees_prop, list):
                attendees_prop = [attendees_prop]
            attendees = [_attendee_dict(a) for a in attendees_prop]

            sequence_raw = component.get("SEQUENCE")
            sequence = bounded_int(sequence_raw, default=0) if sequence_raw is not None else 0  # N-219c/44 R23: SSOT

            return {
                "uid": uid,
                "summary": summary,
                "description": description,
                "location": location,
                "start": start_dt,
                "end": end_dt,
                "all_day": all_day,
                "organizer": organizer,
                "attendees": attendees,
                "method": method,
                "sequence": sequence,
            }
        except Exception as e:
            logger.debug(
                "VEVENT parse failed",
                extra={"error_type": type(e).__name__, "error_msg": str(e)},
            )
            continue

    return None


def build_imip_reply(
    *,
    original_uid: str,
    organizer_email: str,
    attendee_email: str,
    attendee_name: str = "",
    partstat: str = "ACCEPTED",
    summary: str = "",
    sequence: int = 0,
    method: str = "REPLY",
) -> bytes:
    """Build an iMIP-compliant `METHOD=REPLY` calendar payload.

    Used by the invite-reply actions when the user hasn't enabled the
    calendar API; the bytes can be attached to a draft as
    ``Content-Type: text/calendar; method=REPLY`` so the recipient's
    calendar client recognises it as the user's response.

    ``partstat`` is one of ``ACCEPTED``, ``DECLINED``, ``TENTATIVE``.
    """
    if not HAS_ICAL:
        raise RuntimeError("icalendar not installed; cannot build iMIP reply")

    cal = Calendar()
    cal.add("PRODID", "-//Email Triage//iMIP Reply//EN")
    cal.add("VERSION", "2.0")
    cal.add("METHOD", method)

    event = Event()
    event.add("UID", original_uid)
    event.add("DTSTAMP", datetime.now(timezone.utc))
    event.add("SEQUENCE", sequence)
    if summary:
        event.add("SUMMARY", summary)

    if organizer_email:
        organizer = vCalAddress(f"MAILTO:{organizer_email}")
        event.add("ORGANIZER", organizer)

    attendee = vCalAddress(f"MAILTO:{attendee_email}")
    attendee.params["PARTSTAT"] = vText(partstat.upper())
    attendee.params["RSVP"] = vText("FALSE")
    if attendee_name:
        attendee.params["CN"] = vText(attendee_name)
    event.add("ATTENDEE", attendee, encode=0)

    cal.add_component(event)
    return cal.to_ical()


def build_clock_ics(
    *,
    uid: str,
    label: str,
    deadline_at: str | None,
    deep_link: str = "",
    lead_minutes: int = 1440,
) -> bytes | None:
    """Build a PHI-FREE VEVENT (+ VALARM) for a regulatory-clock deadline.

    The always-on ``.ics``-in-email baseline + the direct-write payload. An
    all-day event on the deadline's date; ``SUMMARY`` = the clock LABEL (non-PHI
    policy metadata, the def title); ``DESCRIPTION`` = an advisory line + the
    in-app deep-link. **SCRUB-AT-WRITE** (the ``.ics`` is readable by any
    calendar app / webhook receiver / digest): NO ``case_ref``, NO ``raw_deadline_
    phrase``, NO trigger-email subject/sender/body. A ``VALARM`` fires
    ``lead_minutes`` before. Returns the ``.ics`` bytes, or ``None`` when
    icalendar is unavailable or the deadline is unparseable."""
    if not HAS_ICAL or not deadline_at:
        return None
    from datetime import timedelta

    from email_triage._isotime import parse_iso
    dl = parse_iso(deadline_at)
    if dl is None:
        return None
    from icalendar import Alarm

    cal = Calendar()
    cal.add("PRODID", "-//Email Triage//Regulatory Clock//EN")
    cal.add("VERSION", "2.0")

    event = Event()
    event.add("UID", uid)
    event.add("DTSTAMP", datetime.now(timezone.utc))
    event.add("SUMMARY", f"Regulatory deadline: {label}")
    desc = (
        "Reminder based on your configured policy — verify against your SOP. "
        "Advisory, not an official record."
    )
    if deep_link:
        desc += f"\n{deep_link}"
    event.add("DESCRIPTION", desc)
    # All-day event on the deadline's date (the regulator's local day boundary
    # is pinned upstream; here we use the derived UTC deadline's date).
    event.add("DTSTART", dl.date())
    event.add("DTEND", (dl + timedelta(days=1)).date())

    alarm = Alarm()
    alarm.add("ACTION", "DISPLAY")
    alarm.add("DESCRIPTION", f"Regulatory deadline: {label}")
    alarm.add("TRIGGER", timedelta(minutes=-int(lead_minutes)))
    event.add_component(alarm)

    cal.add_component(event)
    return cal.to_ical()
