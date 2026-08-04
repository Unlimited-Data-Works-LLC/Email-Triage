""" P4f — direct calendar-write (the second calendar channel beyond the .ics).

Covers the v48 idempotency column, the never-clobber stamp, the sweep
notification carrying account_id + calendar_written, and the async writer's
PHI-free event construction + idempotency-skip + no-provider-skip + fail-OPEN.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from email_triage.db.regulatory_clock import (
    create_clock_candidate,
    mark_clock_calendar_written,
    sweep_regulatory_clocks,
)
from email_triage.web.background_sweepers import _write_clock_events_to_calendars
from email_triage.web.db import create_email_account


def _seed(db, user_id, *, deadline_at="2026-06-20T00:00:00+00:00", ptype="office365"):
    aid = create_email_account(
        db, user_id=user_id, name="O365 mailbox",
        provider_type=ptype, config={"account": "pi@site.example"},
        hipaa=True,
    )
    did = db.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        db, def_id=did, account_id=aid, case_ref="CASE-1",
        responsibility="i_submit",
    )
    db.execute(
        "UPDATE regulatory_clock_instance SET deadline_at=?, state='running' "
        "WHERE id=?", (deadline_at, iid),
    )
    db.commit()
    return aid, iid


# --- DB layer ---------------------------------------------------------------

def test_migration_v48_adds_calendar_written_at(db):
    cols = {
        r[1] for r in
        db.execute("PRAGMA table_info(regulatory_clock_instance)").fetchall()
    }
    assert "calendar_written_at" in cols


def test_mark_calendar_written_is_never_clobber(db, regular_user):
    _aid, iid = _seed(db, regular_user["id"])
    mark_clock_calendar_written(db, iid, when="2026-06-15T01:00:00+00:00")
    first = db.execute(
        "SELECT calendar_written_at FROM regulatory_clock_instance WHERE id=?",
        (iid,),
    ).fetchone()[0]
    assert first == "2026-06-15T01:00:00+00:00"
    # a second mark must NOT clobber the first stamp (one event per clock)
    mark_clock_calendar_written(db, iid, when="2026-06-15T09:00:00+00:00")
    second = db.execute(
        "SELECT calendar_written_at FROM regulatory_clock_instance WHERE id=?",
        (iid,),
    ).fetchone()[0]
    assert second == "2026-06-15T01:00:00+00:00"  # unchanged


def test_sweep_notification_carries_account_id_and_calendar_written(db, regular_user):
    # an OVERDUE escalating clock breaches → escalates → emits a notification
    aid, _iid = _seed(db, regular_user["id"], deadline_at="2020-01-01T00:00:00+00:00")
    res = sweep_regulatory_clocks(db)
    notes = res["notifications"]
    assert notes, "an overdue escalating clock should escalate"
    n = notes[0]
    assert n["account_id"] == aid
    assert n["calendar_written"] is False


# --- async writer -----------------------------------------------------------

def _note(**over):
    base = {
        "instance_id": 5, "account_id": 9, "label": "IRB report",
        "deadline_at": "2026-06-20T00:00:00+00:00", "state": "breached",
        "calendar_written": False,
    }
    base.update(over)
    return base


def _app():
    return SimpleNamespace(state=SimpleNamespace(db=object(), secrets=None))


async def test_calendar_write_builds_phi_free_event_and_marks():
    created = {}

    async def _create_event(event, calendar_id=None):
        created["event"] = event
        return "evt-1"

    async def _close():
        pass

    provider = SimpleNamespace(create_event=_create_event, close=_close)
    marked = []
    with patch(
        "email_triage.web.background_sweepers._resolve_clock_calendar_provider",
        lambda *a, **k: provider,
    ), patch(
        "email_triage.db.regulatory_clock.mark_clock_calendar_written",
        lambda conn, iid, **k: marked.append(iid),
    ):
        await _write_clock_events_to_calendars(_app(), [_note()])
    ev = created["event"]
    assert ev.summary == "Regulatory deadline: IRB report"
    assert ev.all_day is False                          # timed marker AT the deadline
    assert ev.start is not None and ev.start.isoformat().startswith("2026-06-20")
    assert ev.transparency == "transparent"             # free marker, not a busy block
    assert ev.description == "" and ev.location == ""   # PHI-free: label only
    assert marked == [5]                                # stamped once


# --- REAL provider serialization (the boundary the mocked writer test hides) --

def _phi_free_timed_event():
    from datetime import datetime, timezone
    from email_triage.engine.models import CalendarEvent
    return CalendarEvent(
        event_id="", summary="Regulatory deadline: IRB report",
        start=datetime(2026, 6, 20, 14, 30, tzinfo=timezone.utc),
        end=datetime(2026, 6, 20, 15, 0, tzinfo=timezone.utc),
        all_day=False, transparency="transparent",
    )


def test_gmail_serialize_emits_timed_free_event():
    from email_triage.providers.gmail_calendar import GoogleCalendarProvider
    p = GoogleCalendarProvider(
        account="x", client_id="", client_secret="", refresh_token="",
    )
    body = p._serialize(_phi_free_timed_event())
    assert body["summary"] == "Regulatory deadline: IRB report"
    assert body["start"]["dateTime"].startswith("2026-06-20T14:30")  # timed, UTC
    assert "date" not in body["start"]                  # NOT all-day (no smear bug)
    assert body["transparency"] == "transparent"        # free marker reaches the wire
    assert body["description"] == "" and body["location"] == ""  # PHI-free


def test_office365_serialize_emits_timed_free_event():
    # _serialize is pure (uses only the event), but the O365 provider's __init__
    # needs the optional msal dep — call the real method UNBOUND so the contract
    # test runs without the extra. Still exercises the REAL wire serialization.
    from email_triage.providers.office365_calendar import Office365CalendarProvider
    body = Office365CalendarProvider._serialize(object(), _phi_free_timed_event())
    assert body["subject"] == "Regulatory deadline: IRB report"
    assert body["start"]["dateTime"].startswith("2026-06-20T14:30")  # timed
    assert body.get("isAllDay") is not True             # NOT all-day (no UTC-smear bug)
    assert body["showAs"] == "free"                     # free marker reaches the wire
    assert body["body"]["content"] == ""                # PHI-free description


async def test_calendar_write_skips_already_written():
    resolved = []
    with patch(
        "email_triage.web.background_sweepers._resolve_clock_calendar_provider",
        lambda *a, **k: resolved.append(1),
    ):
        await _write_clock_events_to_calendars(
            _app(), [_note(calendar_written=True)]
        )
    assert resolved == []  # an already-written clock never resolves a provider


async def test_calendar_write_skips_when_no_provider():
    marked = []
    with patch(
        "email_triage.web.background_sweepers._resolve_clock_calendar_provider",
        lambda *a, **k: None,  # IMAP / calendar-disabled / HIPAA-surrogate-refused
    ), patch(
        "email_triage.db.regulatory_clock.mark_clock_calendar_written",
        lambda *a, **k: marked.append(1),
    ):
        await _write_clock_events_to_calendars(_app(), [_note()])
    assert marked == []  # nothing written, nothing marked → .ics is the channel


async def test_calendar_write_fail_open_on_provider_error():
    async def _boom(event, calendar_id=None):
        raise RuntimeError("graph 500")

    async def _close():
        pass

    provider = SimpleNamespace(create_event=_boom, close=_close)
    marked = []
    with patch(
        "email_triage.web.background_sweepers._resolve_clock_calendar_provider",
        lambda *a, **k: provider,
    ), patch(
        "email_triage.db.regulatory_clock.mark_clock_calendar_written",
        lambda *a, **k: marked.append(1),
    ):
        # must NOT raise (the .ics already delivered)
        await _write_clock_events_to_calendars(_app(), [_note()])
    assert marked == []  # not marked → next sweep retries the write
