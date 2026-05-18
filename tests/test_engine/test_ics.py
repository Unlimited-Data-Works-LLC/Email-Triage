"""Tests for the iCalendar parsing helper."""

from datetime import datetime, timezone

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
