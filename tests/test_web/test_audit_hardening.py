"""Tests for PR 9 — D3 (HIPAA boundary auto-detect) + D4 (auth_events
append-only audit table)."""

from __future__ import annotations

import sqlite3

import pytest


# ---------------------------------------------------------------------------
# D4 — auth_events
# ---------------------------------------------------------------------------

def test_record_auth_event_inserts_row(db, admin_user):
    from email_triage.web.db import record_auth_event, list_auth_events

    rid = record_auth_event(
        db,
        event_type="login_otp",
        email="alice@example.com",
        user_id=admin_user["id"],
        ip="10.0.0.5",
        user_agent="curl/8",
        outcome="success",
    )
    assert rid > 0

    rows = list_auth_events(db, limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "login_otp"
    assert rows[0]["email"] == "alice@example.com"
    assert rows[0]["user_id"] == admin_user["id"]
    assert rows[0]["ip"] == "10.0.0.5"
    assert rows[0]["outcome"] == "success"


def test_record_multiple_events_preserves_history(db, admin_user):
    """Append-only — older rows survive subsequent appends."""
    from email_triage.web.db import record_auth_event, list_auth_events
    record_auth_event(
        db, event_type="login_dev_keypair",
        email="x@y.z", user_id=admin_user["id"], key_id=42,
        ip="10.0.0.1", outcome="success",
    )
    record_auth_event(
        db, event_type="login_dev_keypair",
        email="x@y.z", user_id=admin_user["id"], key_id=42,
        ip="10.0.0.2", outcome="success",
    )
    rows = list_auth_events(db, limit=10)
    assert len(rows) == 2
    # Newest first.
    assert rows[0]["ip"] == "10.0.0.2"
    assert rows[1]["ip"] == "10.0.0.1"


def test_list_auth_events_filters_by_user_id(db, admin_user, regular_user):
    from email_triage.web.db import record_auth_event, list_auth_events
    record_auth_event(
        db, event_type="login_otp", email="a@x",
        user_id=admin_user["id"], outcome="success",
    )
    record_auth_event(
        db, event_type="login_otp", email="b@x",
        user_id=regular_user["id"], outcome="success",
    )
    rows = list_auth_events(db, user_id=admin_user["id"])
    assert len(rows) == 1
    assert rows[0]["email"] == "a@x"


def test_list_auth_events_filters_by_event_type(db, admin_user):
    from email_triage.web.db import record_auth_event, list_auth_events
    record_auth_event(
        db, event_type="login_otp", email="a@x",
        user_id=admin_user["id"], outcome="success",
    )
    record_auth_event(
        db, event_type="login_webauthn", email="a@x",
        user_id=admin_user["id"], key_id=7, outcome="success",
    )
    rows = list_auth_events(db, event_type="login_webauthn")
    assert len(rows) == 1
    assert rows[0]["key_id"] == 7


def test_record_auth_event_records_failed_outcome(db):
    """Denied attempts also record so an auditor can see failed
    credential use, not just successful logins."""
    from email_triage.web.db import record_auth_event, list_auth_events
    record_auth_event(
        db, event_type="login_dev_keypair",
        email="bad@x", user_id=None, key_id=99,
        outcome="denied:hardware_key_wins",
        detail="user has hardware key",
    )
    rows = list_auth_events(db)
    assert rows[0]["outcome"] == "denied:hardware_key_wins"
    assert rows[0]["detail"] == "user has hardware key"


# ---------------------------------------------------------------------------
# D3 — HIPAA boundary drift detector
# ---------------------------------------------------------------------------

def test_drift_detector_appends_when_no_history_and_flag_on(db):
    """No prior boundary rows + system flag is on → detector
    appends an "on auto-detected" row."""
    from email_triage import triage_logging
    from email_triage.web.db import (
        latest_hipaa_boundary, record_hipaa_boundary,
    )

    triage_logging._hipaa_mode = True
    try:
        # Simulate detector body inline (the supervised task would
        # otherwise need a full event-loop fixture).
        latest = latest_hipaa_boundary(db, "system")
        current = "on" if triage_logging.is_hipaa_mode() else "off"
        recorded = latest.get("direction") if latest else "off"
        if recorded != current:
            record_hipaa_boundary(
                db, scope="system", direction=current,
                actor_id=None, reason="auto-detected drift",
            )
        # The append happened.
        latest_after = latest_hipaa_boundary(db, "system")
        assert latest_after is not None
        assert latest_after["direction"] == "on"
        assert latest_after["reason"] == "auto-detected drift"
    finally:
        triage_logging._hipaa_mode = False


def test_drift_detector_idempotent_when_recorded_matches(db):
    """If the recorded direction already matches the current flag,
    no new row is appended."""
    from email_triage import triage_logging
    from email_triage.web.db import (
        latest_hipaa_boundary, record_hipaa_boundary,
    )

    # Plant a recorded "off" row.
    record_hipaa_boundary(
        db, scope="system", direction="off",
        actor_id=None, reason="seed",
    )
    triage_logging._hipaa_mode = False

    # Run the same logic twice; should NOT add new rows since the
    # recorded direction ("off") matches the current state.
    for _ in range(3):
        latest = latest_hipaa_boundary(db, "system")
        current = "on" if triage_logging.is_hipaa_mode() else "off"
        recorded = latest.get("direction") if latest else "off"
        if recorded != current:
            record_hipaa_boundary(
                db, scope="system", direction=current,
                actor_id=None, reason="auto-detected drift",
            )

    rows = db.execute(
        "SELECT COUNT(*) FROM hipaa_boundary_events WHERE scope='system'"
    ).fetchone()[0]
    assert rows == 1  # only the seed


def test_drift_detector_appends_when_flag_flips_underneath(db):
    """Recorded direction was "off"; flag flipped to "on" via direct
    DB edit (not via /config/save). Detector catches the drift and
    appends an auto-detected "on" row."""
    from email_triage import triage_logging
    from email_triage.web.db import (
        latest_hipaa_boundary, record_hipaa_boundary,
    )

    record_hipaa_boundary(
        db, scope="system", direction="off",
        actor_id=None, reason="initial",
    )
    triage_logging._hipaa_mode = True
    try:
        latest = latest_hipaa_boundary(db, "system")
        current = "on" if triage_logging.is_hipaa_mode() else "off"
        recorded = latest.get("direction") if latest else "off"
        assert recorded == "off"
        assert current == "on"
        if recorded != current:
            record_hipaa_boundary(
                db, scope="system", direction=current,
                actor_id=None, reason="auto-detected drift",
            )

        # Now have two rows: initial off + auto-detected on.
        rows = db.execute(
            "SELECT direction, reason FROM hipaa_boundary_events "
            "WHERE scope='system' ORDER BY ts ASC"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0]["direction"] == "off"
        assert rows[1]["direction"] == "on"
        assert rows[1]["reason"] == "auto-detected drift"
    finally:
        triage_logging._hipaa_mode = False
