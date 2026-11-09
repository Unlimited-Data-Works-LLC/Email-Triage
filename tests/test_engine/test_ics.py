"""Tests for the iCalendar parsing helper."""

from datetime import datetime, timezone

import pytest

from email_triage.engine.ics import build_imip_reply, parse_ics


def _ics(extra_props: str = "", method: str = "REQUEST") -> bytes:
    return (
        f"BEGIN:VCALENDAR\r\n"
        f"VERSION:2.0\r\n"
        f"PRODID:-//Test//Test//EN\r\n"
        f"METHOD:{method}\r\n"
        f"BEGIN:VEVENT\r\n"
        f"UID:test-uid-12345@example.com\r\n"
        f"SUMMARY:Quarterly review\r\n"
        f"DTSTART:20260420T140000Z\r\n"
        f"DTEND:20260420T150000Z\r\n"
        f"LOCATION:Boardroom A\r\n"
        f"ORGANIZER:mailto:boss@company.com\r\n"
        f"ATTENDEE;CN=Alice;PARTSTAT=NEEDS-ACTION:mailto:alice@company.com\r\n"
        f"ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@company.com\r\n"
        f"SEQUENCE:0\r\n"
        f"{extra_props}"
        f"END:VEVENT\r\n"
        f"END:VCALENDAR\r\n"
    ).encode()


def test_parse_basic_invite():
    out = parse_ics(_ics())
    assert out is not None
    assert out["uid"] == "test-uid-12345@example.com"
    assert out["summary"] == "Quarterly review"
    assert out["location"] == "Boardroom A"
    assert out["organizer"] == "boss@company.com"
    assert out["start"] == datetime(2026, 4, 20, 14, 0, tzinfo=timezone.utc)
    assert out["end"] == datetime(2026, 4, 20, 15, 0, tzinfo=timezone.utc)
    assert out["all_day"] is False
    assert out["method"] == "REQUEST"
    assert out["sequence"] == 0
    assert len(out["attendees"]) == 2
    emails = [a["email"] for a in out["attendees"]]
    assert "alice@company.com" in emails
    assert "bob@company.com" in emails


def test_parse_method_reply():
    out = parse_ics(_ics(method="REPLY"))
    assert out is not None
    assert out["method"] == "REPLY"


def test_parse_all_day():
    blob = (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Test//EN\r\n"
        "BEGIN:VEVENT\r\n"
        "UID:allday@x.com\r\n"
        "SUMMARY:Holiday\r\n"
        "DTSTART;VALUE=DATE:20260704\r\n"
        "DTEND;VALUE=DATE:20260705\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    ).encode()
    out = parse_ics(blob)
    assert out is not None
    assert out["all_day"] is True
    assert out["start"] == datetime(2026, 7, 4, 0, 0, tzinfo=timezone.utc)


def test_parse_malformed_returns_none():
    assert parse_ics(b"this is not iCalendar") is None
    assert parse_ics(b"") is None


def test_parse_multi_vevent_first_wins():
    blob = (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Test//EN\r\n"
        "BEGIN:VEVENT\r\n"
        "UID:first@x.com\r\n"
        "SUMMARY:First\r\n"
        "DTSTART:20260420T140000Z\r\n"
        "DTEND:20260420T150000Z\r\n"
        "END:VEVENT\r\n"
        "BEGIN:VEVENT\r\n"
        "UID:second@x.com\r\n"
        "SUMMARY:Second\r\n"
        "DTSTART:20260421T140000Z\r\n"
        "DTEND:20260421T150000Z\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    ).encode()
    out = parse_ics(blob)
    assert out is not None
    assert out["uid"] == "first@x.com"


def test_build_imip_reply_carries_partstat():
    payload = build_imip_reply(
        original_uid="abc@x.com",
        organizer_email="boss@company.com",
        attendee_email="me@me.com",
        attendee_name="Me",
        partstat="DECLINED",
        summary="Sync",
    )
    text = payload.decode("utf-8")
    assert "METHOD:REPLY" in text
    assert "PARTSTAT=DECLINED" in text
    assert "MAILTO:me@me.com".lower() in text.lower()
    assert "abc@x.com" in text
    # Re-parse it; should round-trip cleanly.
    parsed = parse_ics(payload)
    assert parsed is not None
    assert parsed["uid"] == "abc@x.com"
    assert parsed["method"] == "REPLY"
    assert parsed["attendees"][0]["response_status"] == "declined"


# --- punch 442: behaviour of the paths the suite skipped across the icalendar
# --- 7.1.2 -> 7.3.0 bump (differential run, 26 inputs, one difference: TZID).

_HEAD = (
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\n"
    "UID:u1@x\r\nSUMMARY:S\r\n"
)
_TAIL = "END:VEVENT\r\nEND:VCALENDAR\r\n"


def _vevent(props: str) -> bytes:
    return (_HEAD + props + _TAIL).encode()


def test_parse_tzid_event_converts_to_utc_with_dst():
    out = parse_ics(_vevent(
        "DTSTART;TZID=America/New_York:20260420T100000\r\n"
        "DTEND;TZID=America/New_York:20260420T110000\r\n"
    ))
    assert out is not None
    # April is EDT (UTC-4): 10:00 local is 14:00Z.
    assert out["start"] == datetime(2026, 4, 20, 14, 0, tzinfo=timezone.utc)
    assert out["end"] == datetime(2026, 4, 20, 15, 0, tzinfo=timezone.utc)
    assert out["all_day"] is False


def test_parse_globally_unique_tzid_resolves_the_zone_not_utc():
    """icalendar 7.1.2 read a /vendor/Europe/Berlin TZID as UTC (10:00Z, two
    hours wrong); 7.3.0 strips the vendor prefix and warns. Berlin is CEST
    (UTC+2) in April, so 10:00 local is 08:00Z."""
    from icalendar.error import GloballyUniqueTZIDGuessed

    with pytest.warns(GloballyUniqueTZIDGuessed):
        out = parse_ics(_vevent(
            "DTSTART;TZID=/freeassociation.sourceforge.net/Europe/Berlin:20260420T100000\r\n"
        ))
    assert out is not None
    assert out["start"] == datetime(2026, 4, 20, 8, 0, tzinfo=timezone.utc)


def test_parse_attendee_params_are_flattened_with_quoted_cn():
    out = parse_ics(_vevent(
        "DTSTART:20260420T140000Z\r\n"
        'ATTENDEE;CN="Doe, Jane";PARTSTAT=TENTATIVE;ROLE=OPT-PARTICIPANT:mailto:jane@x.org\r\n'
    ))
    assert out is not None
    assert out["attendees"] == [{
        "email": "jane@x.org",
        "name": "Doe, Jane",
        "response_status": "tentative",
        "role": "OPT-PARTICIPANT",
    }]


def test_parse_unfolds_and_unescapes_text_values():
    out = parse_ics(_vevent(
        "DTSTART:20260420T140000Z\r\n"
        "DESCRIPTION:" + "A" * 70 + "\r\n " + "B" * 70 + "\r\n"
        "LOCATION:Room\\, 5\\; north\r\n"
    ))
    assert out is not None
    assert out["description"] == "A" * 70 + "B" * 70
    assert out["location"] == "Room, 5; north"


def test_parse_organizer_scheme_is_stripped_case_insensitively():
    out = parse_ics(_vevent("DTSTART:20260420T140000Z\r\nORGANIZER;CN=Boss:MAILTO:boss@x.org\r\n"))
    assert out is not None
    assert out["organizer"] == "boss@x.org"


def test_parse_non_numeric_sequence_defaults_to_zero_and_numeric_is_kept():
    assert parse_ics(_vevent("DTSTART:20260420T140000Z\r\nSEQUENCE:abc\r\n"))["sequence"] == 0
    assert parse_ics(_vevent("DTSTART:20260420T140000Z\r\nSEQUENCE:5\r\n"))["sequence"] == 5


def test_parse_unparseable_dtstart_is_rejected_not_half_filled():
    assert parse_ics(_vevent("DTSTART:garbage\r\n")) is None
