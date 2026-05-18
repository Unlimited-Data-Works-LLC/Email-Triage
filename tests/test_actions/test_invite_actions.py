"""Tests for the meeting-invite reply actions (accept/decline/tentative)."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.actions.invite import (
    AcceptInviteAction,
    DeclineInviteAction,
    TentativeInviteAction,
)
from email_triage.engine.models import (
    ActionResult,
    Attachment,
    CalendarEvent,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)


def _msg_with_invite():
    parsed = {
        "uid": "abc@x.com",
        "summary": "Sync",
        "organizer": "boss@x.com",
        "sequence": 0,
    }
    att = Attachment(
        filename="invite.ics", content_type="text/calendar",
        size_bytes=200, data=b"BEGIN:VCALENDAR...", parsed=parsed,
    )
    return EmailMessage(
        message_id="m1", provider="gmail_api",
        sender="boss@x.com", recipients=["me@me.com"],
        subject="Quarterly review", body_text="(see attached)",
        date=datetime.now(timezone.utc),
        attachments=[att],
    )


def _classification():
    return Classification(category="meetings", confidence=0.9, reason="invite")


def _flow(**bag):
    return FlowState(
        flow_id="f1", message_id="m1", provider="gmail_api",
        status=FlowStatus.ACTING, state_bag=bag,
    )


class TestCalendarApiPath:
    async def test_accept_via_calendar(self):
        cal = MagicMock()
        cal.get_event_by_uid = AsyncMock(return_value=CalendarEvent(
            event_id="ev1", summary="Sync",
        ))
        cal.respond_to_invite = AsyncMock(return_value=None)
        provider = MagicMock()
        action = AcceptInviteAction()
        out = await action.execute(
            _flow(calendar_provider=cal, self_email="me@me.com"),
            _msg_with_invite(), _classification(), provider,
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["path"] == "calendar_api"
        assert out.data["event_id"] == "ev1"
        cal.respond_to_invite.assert_awaited_once_with("ev1", "accepted")

    async def test_decline_partstat(self):
        cal = MagicMock()
        cal.get_event_by_uid = AsyncMock(return_value=CalendarEvent(event_id="ev1"))
        cal.respond_to_invite = AsyncMock(return_value=None)
        provider = MagicMock()
        await DeclineInviteAction().execute(
            _flow(calendar_provider=cal, self_email="me@me.com"),
            _msg_with_invite(), _classification(), provider,
        )
        cal.respond_to_invite.assert_awaited_once_with("ev1", "declined")

    async def test_tentative_partstat(self):
        cal = MagicMock()
        cal.get_event_by_uid = AsyncMock(return_value=CalendarEvent(event_id="ev1"))
        cal.respond_to_invite = AsyncMock(return_value=None)
        provider = MagicMock()
        await TentativeInviteAction().execute(
            _flow(calendar_provider=cal, self_email="me@me.com"),
            _msg_with_invite(), _classification(), provider,
        )
        cal.respond_to_invite.assert_awaited_once_with("ev1", "tentative")


class TestFallback:
    async def test_no_calendar_drafts_imip_reply(self):
        provider = MagicMock()
        provider.create_draft = AsyncMock(return_value="draft-1")
        out = await AcceptInviteAction().execute(
            _flow(calendar_provider=None, self_email="me@me.com"),
            _msg_with_invite(), _classification(), provider,
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["path"] == "imip_draft"
        assert out.data["draft_id"] == "draft-1"
        # The body should carry an iCal block with PARTSTAT=ACCEPTED.
        call = provider.create_draft.call_args
        body = call.kwargs["body"]
        assert "ACCEPTED" in body
        assert "BEGIN:VCALENDAR" in body

    async def test_no_attachment_skipped(self):
        provider = MagicMock()
        msg = EmailMessage(
            message_id="m1", provider="gmail_api",
            sender="x@y.com", recipients=[], subject="Hi",
            body_text="", date=datetime.now(timezone.utc),
        )
        out = await AcceptInviteAction().execute(
            _flow(), msg, _classification(), provider,
        )
        assert out.result == ActionResult.SKIPPED

    async def test_calendar_lookup_miss_falls_back_to_draft(self):
        cal = MagicMock()
        cal.get_event_by_uid = AsyncMock(return_value=None)  # not found
        provider = MagicMock()
        provider.create_draft = AsyncMock(return_value="draft-2")
        out = await AcceptInviteAction().execute(
            _flow(calendar_provider=cal, self_email="me@me.com"),
            _msg_with_invite(), _classification(), provider,
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["path"] == "imip_draft"
