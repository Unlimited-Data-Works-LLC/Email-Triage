""" Phase 4b — per-install working-day calendar pins.

working_day clocks (the IRB headline) arm against the operator-configured
holiday set + working week; a wrong set would chain a false breach, so it is
never guessed (decision #3). calendar_day clocks are unaffected.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.db.regulatory_clock import (
    WorkingDayCalendar,
    _add_working_days,
    _compute_deadline,
    confirm_reportable,
    create_clock_candidate,
    get_clock_instance,
    working_day_calendar_from_config,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


def _count_working_days(start, end, cal):
    n, d = 0, start
    while d < end:
        d += timedelta(days=1)
        if cal.is_working_day(d.date()):
            n += 1
    return n


def test_add_working_days_skips_weekends():
    cal = WorkingDayCalendar()  # Mon–Fri, no holidays
    start = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
    res = _add_working_days(start, 5, cal)
    assert cal.is_working_day(res.date())
    assert _count_working_days(start, res, cal) == 5  # exactly 5 working days
    assert res.hour == 9  # time-of-day preserved


def test_add_working_days_skips_configured_holiday():
    no_hol = WorkingDayCalendar()
    start = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
    base = _add_working_days(start, 5, no_hol)
    # mark the first working day after start a holiday → result shifts +1 working day
    first = start
    while True:
        first += timedelta(days=1)
        if no_hol.is_working_day(first.date()):
            break
    hol_cal = WorkingDayCalendar(holidays=frozenset({first.date().isoformat()}))
    shifted = _add_working_days(start, 5, hol_cal)
    assert shifted > base  # the holiday pushed the deadline out


def test_compute_deadline_working_day_needs_calendar():
    anchor = "2026-06-01T00:00:00+00:00"
    # no calendar → working_day NOT computable (won't arm a wrong deadline)
    assert _compute_deadline(anchor, 5, "working_day", calendar=None) is None
    # with calendar → computed
    d = _compute_deadline(anchor, 5, "working_day", calendar=WorkingDayCalendar())
    assert d is not None
    # calendar_day is unaffected by the calendar
    assert _compute_deadline(anchor, 7, "calendar_day").startswith("2026-06-08")


def test_calendar_from_config_duck_typed():
    class _RC:
        working_day_holidays = ["2026-07-03"]
        working_week = [0, 1, 2, 3]  # Mon–Thu

    class _Cfg:
        regulatory_clock = _RC()

    cal = working_day_calendar_from_config(_Cfg())
    assert "2026-07-03" in cal.holidays
    assert cal.working_weekdays == frozenset({0, 1, 2, 3})


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


def _working_day_def(conn):
    conn.execute(
        "INSERT INTO regulatory_clock_def "
        "(code, regime, citation, title, severity_class, clock_kind, "
        " duration_value, duration_unit, clock_start_kind, escalation_lead_pcts,"
        " created_at) VALUES "
        "('WD_TEST','INTERNAL','SOP','t','internal','escalating',5,"
        " 'working_day','on_determination','[80]','now')"
    )
    return conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='WD_TEST'"
    ).fetchone()[0]


def _account(conn):
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    return create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=True,
    )


def test_working_day_clock_arms_only_with_a_calendar(conn):
    aid, did = _account(conn), _working_day_def(conn)
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    # i_submit + escalating working_day, but NO calendar → stays candidate
    iid = create_clock_candidate(conn, def_id=did, account_id=aid,
                                 case_ref="C1", responsibility="i_submit")
    assert confirm_reportable(conn, instance_id=iid, actor_user_id=uid) == \
        "candidate"
    assert get_clock_instance(conn, iid)["deadline_at"] is None
    # WITH a calendar → arms running with a working-day deadline
    iid2 = create_clock_candidate(conn, def_id=did, account_id=aid,
                                  case_ref="C2", responsibility="i_submit")
    state = confirm_reportable(
        conn, instance_id=iid2, actor_user_id=uid,
        determination_at="2026-06-01T00:00:00+00:00",
        calendar=WorkingDayCalendar(),
    )
    assert state == "running"
    assert get_clock_instance(conn, iid2)["deadline_at"] is not None
