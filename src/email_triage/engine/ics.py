"""iCalendar (RFC 5545) parsing helpers.

Used by the email providers to surface ``text/calendar`` attachments
as structured data, and by the invite-reply actions to construct
iMIP-compliant `METHOD=REPLY` payloads when no calendar API is
available.
"""

from __future__ import annotations

import logging
import re

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


#: RFC 5545 section 3.3.8: the valid range for an "integer" is -2147483648 to 2147483647. A
#: SEQUENCE is a revision counter, never negative; anything above the range is not a revision.
_MAX_SEQUENCE = 2**31 - 1

# Characters that make a CAL-ADDRESS unusable as ONE mailbox: every C0/C1 control (CR, LF, TAB, NUL,
# DEL, NEL), the Unicode line/paragraph separators, whitespace, and the address-list / display-name
# delimiters. A bare CR survives icalendar's parse (probe 2026-11-02, 7.3.0), and an address list
# ("a@x, b@x") would address a second recipient.
_ADDRESS_REFUSED = re.compile(r"[\x00-\x20\x7f-\x9f  ,;<>\"\\]")


def _cal_address_email(value: Any) -> str:
    """The mailbox of an ORGANIZER / ATTENDEE CAL-ADDRESS, or ``""`` when it is not one safe mailbox.

    The ONE funnel for every address ``parse_ics`` returns (punch 774, PD-5/PD-8): REFUSE a value
    that carries a control character or a list delimiter, never strip it, because a stripped CR
    can join two lines into a different address. ``""`` is the fail-closed answer: ``invite.py``
    falls back to the message sender, and an attendee with no address is dropped."""
    raw = str(value) if value is not None else ""
    addr = re.sub(r"^mailto:", "", raw, flags=re.IGNORECASE)  # no .strip(): a trailing CR must be refused, not eaten
    return "" if _ADDRESS_REFUSED.search(addr) else addr


def attendee_mailboxes(entries: Any) -> list[str]:
    """The safe mailbox of each ``{"email": ...}`` entry in an attendee list; an entry that is not
    one safe mailbox is dropped (punch 823, the API-supplied twin of the 774 ICS source).

    The funnel for every attendee a calendar write sends to Google or Graph. A caller that must
    not invite fewer people than it was asked to compares the length with its input and refuses."""
    if not isinstance(entries, list):
        return []
    return [
        addr for entry in entries if isinstance(entry, dict) and isinstance(entry.get("email"), str)
        and (addr := _cal_address_email(entry["email"]))
    ]


def native_attendees_safe(entries: Any) -> bool:
    """True when a provider-shaped ``attendees`` value names only safe mailboxes (punch 823).

    A calendar PATCH body is forwarded as the provider's own JSON, so the list keeps its Google
    (``email``) or Graph (``emailAddress.address``) shape. Every address-bearing key an entry
    carries must be a string the funnel returns unchanged: a ``mailto:`` prefix is refused here,
    not stripped, because the value is forwarded as given. An empty list is safe (it clears the
    attendees); a value that is not a list is not."""
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        nested = entry.get("emailAddress")
        values = [entry["email"]] if "email" in entry else []
        if nested is not None:
            if not isinstance(nested, dict) or "address" not in nested:
                return False
            values.append(nested["address"])
        if not values or any(not isinstance(v, str) or _cal_address_email(v) != v or not v for v in values):
            return False
    return True


def _attendee_dict(att: Any) -> dict[str, Any] | None:
    """Best-effort flatten of an icalendar ATTENDEE property; ``None`` when its address is refused."""
    email_addr = _cal_address_email(att)
    if not email_addr:
        return None
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
            organizer = _cal_address_email(organizer_prop) if organizer_prop is not None else ""

            attendees_prop = component.get("ATTENDEE", [])
            if not isinstance(attendees_prop, list):
                attendees_prop = [attendees_prop]
            attendees = [d for d in (_attendee_dict(a) for a in attendees_prop) if d is not None]

            sequence_raw = component.get("SEQUENCE")
            sequence = (
                bounded_int(sequence_raw, default=0, lo=0, hi=_MAX_SEQUENCE)  # N-219c/44 R23: SSOT
                if sequence_raw is not None else 0
            )

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
