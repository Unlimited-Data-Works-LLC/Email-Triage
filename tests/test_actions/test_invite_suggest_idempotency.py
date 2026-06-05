""" — idempotency bookend for invite + suggest_meeting_times.

The consolidated retry drainer re-runs the FULL triage path, which
re-runs ACTIONS. Re-acting is safe ONLY if every action is idempotent.
Before  ``invite`` and ``suggest_meeting_times`` called
``create_draft`` (and ``invite`` also ``respond_to_invite``)
unconditionally — a retry-queue re-run created a SECOND draft / RSVP.
These tests prove a re-run with the same (account, message) skips.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.actions.invite import AcceptInviteAction
from email_triage.actions.suggest_meeting_times import (
    SuggestMeetingTimesAction,
)
from email_triage.engine.models import (
    ActionResult, Attachment, Classification, EmailMessage,
    FlowState, FlowStatus,
)
from email_triage.web.db import init_db, create_email_account


@pytest.fixture
def idem_db(tmp_path):
    """Fully-migrated DB carrying the v34 action_idempotency table."""
    conn = init_db(tmp_path / "idem.db")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('pi@example.com', 'PI', 'admin', ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.commit()
    yield conn
    conn.close()


def _account(conn) -> int:
    return create_email_account(
        conn, user_id=1, name="acct", provider_type="imap",
        config={"host": "imap.example.com"},
    )


def _durable_flow(conn, account_id: int, flow_id: str = "f1") -> FlowState:
    """A flow whose state_bag carries db + account_id — so the
    idempotency helpers take the DURABLE action_idempotency path that
    survives across a fresh FlowState (as the retry drainer builds)."""
    return FlowState(
        flow_id=flow_id, provider="imap", message_id="m1",
        status=FlowStatus.ACTING,
        state_bag={"db": conn, "account_id": account_id},
    )


def _msg_with_rfc(rfc_id="<msg-1@example.com>", attachments=None) -> EmailMessage:
    return EmailMessage(
        message_id="m1", provider="imap",
        sender="Alice <alice@example.com>",
        recipients=["op@example.com"],
        subject="Meeting", body_text="Got 30 min next week?",
        date=datetime.now(timezone.utc),
        headers={"Message-ID": rfc_id},
        attachments=attachments or [],
    )


def _classification(category="meeting-request") -> Classification:
    return Classification(category=category, confidence=0.9, reason="t")


# ---------------------------------------------------------------------------
# suggest_meeting_times
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suggest_meeting_times_no_double_draft(idem_db):
    """A second run of suggest_meeting_times for the same (account,
    message) — as the retry drainer produces — must NOT create a
    second draft."""
    acct = _account(idem_db)

    cal = MagicMock()
    cal.list_events = AsyncMock(return_value=[])
    provider = MagicMock()
    provider.create_draft = AsyncMock(return_value="draft-1")

    prefs = {
        "default_length_minutes": 30, "suggestion_count": 3,
        "business_hours_start": "09:00", "business_hours_end": "17:00",
        "skip_weekends": True, "search_horizon_days": 14,
        "minimum_lead_time_hours": 0, "timezone": "UTC",
    }
    msg = _msg_with_rfc()
    action = SuggestMeetingTimesAction()

    # First run — fresh FlowState — creates the draft.
    flow_a = _durable_flow(idem_db, acct, flow_id="flowA")
    flow_a.state_bag["calendar_provider"] = cal
    flow_a.state_bag["meeting_prefs"] = prefs
    out1 = await action.execute(flow_a, msg, _classification(), provider)
    assert out1.result == ActionResult.COMPLETED
    assert provider.create_draft.call_count == 1

    # Second run — DIFFERENT FlowState (drainer re-run) — must skip.
    flow_b = _durable_flow(idem_db, acct, flow_id="flowB")
    flow_b.state_bag["calendar_provider"] = cal
    flow_b.state_bag["meeting_prefs"] = prefs
    out2 = await action.execute(flow_b, msg, _classification(), provider)
    assert out2.result == ActionResult.SKIPPED
    assert out2.data["skipped_idempotent"] is True
    assert out2.data["previous_external_id"] == "draft-1"
    # CRITICAL — create_draft NOT called a second time.
    assert provider.create_draft.call_count == 1


# ---------------------------------------------------------------------------
# invite (calendar-API path + iMIP draft fallback)
# ---------------------------------------------------------------------------

def _invite_message() -> EmailMessage:
    """A message carrying a parsed text/calendar invite attachment."""
    att = Attachment(
        filename="invite.ics",
        content_type="text/calendar",
        size_bytes=100,
        parsed={
            "uid": "ical-uid-123",
            "organizer": "boss@example.com",
            "summary": "Sync",
            "sequence": 0,
        },
    )
    return _msg_with_rfc(attachments=[att])


@pytest.mark.asyncio
async def test_invite_calendar_path_no_double_rsvp(idem_db):
    """A second run of accept_invite via the calendar-API path must NOT
    double-RSVP."""
    acct = _account(idem_db)

    cal = MagicMock()
    event = MagicMock()
    event.event_id = "evt-1"
    event.calendar_id = "primary"
    cal.get_event_by_uid = AsyncMock(return_value=event)
    cal.respond_to_invite = AsyncMock(return_value=None)
    provider = MagicMock()

    msg = _invite_message()
    action = AcceptInviteAction()

    flow_a = _durable_flow(idem_db, acct, flow_id="flowA")
    flow_a.state_bag["calendar_provider"] = cal
    out1 = await action.execute(flow_a, msg, _classification(), provider)
    assert out1.result == ActionResult.COMPLETED
    assert out1.data["path"] == "calendar_api"
    assert cal.respond_to_invite.call_count == 1

    flow_b = _durable_flow(idem_db, acct, flow_id="flowB")
    flow_b.state_bag["calendar_provider"] = cal
    out2 = await action.execute(flow_b, msg, _classification(), provider)
    assert out2.result == ActionResult.SKIPPED
    assert out2.data["skipped_idempotent"] is True
    # CRITICAL — respond_to_invite NOT called a second time.
    assert cal.respond_to_invite.call_count == 1


@pytest.mark.asyncio
async def test_invite_imip_draft_path_no_double_draft(idem_db):
    """A second run of accept_invite via the iMIP-draft fallback (no
    calendar provider) must NOT create a second draft."""
    acct = _account(idem_db)

    provider = MagicMock()
    provider.create_draft = AsyncMock(return_value="draft-imip-1")

    msg = _invite_message()
    action = AcceptInviteAction()

    # No calendar_provider in the bag → iMIP draft fallback.
    flow_a = _durable_flow(idem_db, acct, flow_id="flowA")
    out1 = await action.execute(flow_a, msg, _classification(), provider)
    assert out1.result == ActionResult.COMPLETED
    assert out1.data["path"] == "imip_draft"
    assert provider.create_draft.call_count == 1

    flow_b = _durable_flow(idem_db, acct, flow_id="flowB")
    out2 = await action.execute(flow_b, msg, _classification(), provider)
    assert out2.result == ActionResult.SKIPPED
    # CRITICAL — create_draft NOT called a second time.
    assert provider.create_draft.call_count == 1
