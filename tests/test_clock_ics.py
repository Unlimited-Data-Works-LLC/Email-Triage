""" P4e — the PHI-free regulatory-clock .ics builder."""
from __future__ import annotations

from datetime import datetime, timezone

from email_triage.engine.ics import build_clock_ics, parse_ics


def test_build_clock_ics_is_phi_free_valid_and_alarmed():
    ics = build_clock_ics(
        uid="clock-1@email-triage",
        label="IRB/HRPO unanticipated-problem report",
        deadline_at="2026-06-15T00:00:00+00:00",
        deep_link="https://triage.example/clocks",
        lead_minutes=1440,
    )
    assert ics is not None
    # unfold RFC5545 line-folding (CRLF + space continuation) before substring
    # checks, else long lines (DESCRIPTION) split mid-phrase.
    text = ics.decode()
    unfolded = text.replace("\r\n ", "").replace("\r\n\t", "")
    assert "BEGIN:VEVENT" in text and "BEGIN:VALARM" in text
    assert "IRB/HRPO unanticipated-problem report" in unfolded   # label (non-PHI)
    assert "verify against your SOP" in unfolded                 # advisory copy
    assert "TRIGGER:-PT24H" in text or "TRIGGER:-P1D" in text  # 1440-min lead
    # SCRUB-AT-WRITE: no PHI grouping key / deadline phrase leaks into the .ics
    assert "case_ref" not in unfolded.lower()
    assert "raw_deadline_phrase" not in unfolded.lower()
    # valid .ics — round-trips through the existing parser, and the parse
    # yields the REAL fields (punch 442: `is not None` passes on a parser that
    # returns an empty shell, which is what a silent icalendar behaviour change
    # would look like).
    parsed = parse_ics(ics)
    assert parsed is not None
    assert parsed["uid"] == "clock-1@email-triage"
    assert parsed["summary"] == "Regulatory deadline: IRB/HRPO unanticipated-problem report"
    assert parsed["all_day"] is True
    # all-day boundary: the deadline's date at UTC midnight, DTEND the day after
    assert parsed["start"] == datetime(2026, 6, 15, tzinfo=timezone.utc)
    assert parsed["end"] == datetime(2026, 6, 16, tzinfo=timezone.utc)
    assert "verify against your SOP" in parsed["description"]
    assert parsed["description"].endswith("\nhttps://triage.example/clocks")
    # PHI-free by construction: no attendee, organizer or location rides along
    assert parsed["attendees"] == []
    assert parsed["organizer"] == ""
    assert parsed["location"] == ""
    assert parsed["method"] == ""
    assert parsed["sequence"] == 0


def test_build_clock_ics_none_on_bad_deadline():
    assert build_clock_ics(uid="x", label="L", deadline_at=None) is None
    assert build_clock_ics(uid="x", label="L", deadline_at="not-a-date") is None
