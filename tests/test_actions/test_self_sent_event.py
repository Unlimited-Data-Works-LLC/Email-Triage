"""Tests for the self-sent event triage action (#107)."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.actions.self_sent_event import (
    SelfSentEventAction,
    _extract_address,
    _extract_event_time,
    _extract_location,
    _strip_reply_prefix,
)
from email_triage.engine.models import (
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)


# ---------------------------------------------------------------------------
# Fixtures (no real PII per project rules)
# ---------------------------------------------------------------------------

OWNER = "user@example.com"
ALIAS = "user.alias@example.com"


def _msg(*, sender=OWNER, subject="Coffee Tuesday 3pm",
         body="Coffee Tuesday 3pm at Test Cafe", headers=None):
    return EmailMessage(
        message_id="m1",
        provider="gmail_api",
        sender=sender,
        recipients=[OWNER],
        subject=subject,
        body_text=body,
        date=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc),
        headers=headers or {},
        hipaa=False,
    )


def _classification():
    return Classification(
        category="self-event", confidence=0.85, reason="self-sent note",
    )


def _flow(**state_bag):
    bag = {
        "account_addresses": [OWNER, ALIAS],
        "self_schedule_calendar_id": "cal-self",
        "calendar_provider": _make_cal_provider(),
        "account_id": 1,
        "account": {"id": 1, "user_id": 10, "hipaa": 0, "name": "Test"},
        "account_hipaa": False,
        "calendar_surrogate_active": False,
    }
    bag.update(state_bag)
    return FlowState(
        flow_id="f1", message_id="m1", provider="gmail_api",
        status=FlowStatus.ACTING, state_bag=bag,
    )


def _make_cal_provider(create_id="ev-new"):
    cal = MagicMock()
    cal.create_event = AsyncMock(return_value=create_id)
    return cal


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

class TestExtractAddress:
    def test_displayname_wrapped(self):
        assert _extract_address("Operator A <op@example.com>") == "op@example.com"

    def test_bare_address(self):
        assert _extract_address("op@example.com") == "op@example.com"

    def test_case_folded(self):
        assert _extract_address("OP@Example.COM") == "op@example.com"

    def test_empty(self):
        assert _extract_address("") == ""


class TestStripReplyPrefix:
    def test_re(self):
        assert _strip_reply_prefix("Re: Coffee") == "Coffee"

    def test_fwd(self):
        assert _strip_reply_prefix("Fwd: Coffee") == "Coffee"

    def test_chained(self):
        assert _strip_reply_prefix("Re: Re: Coffee") == "Coffee"

    def test_case_insensitive(self):
        assert _strip_reply_prefix("RE: Coffee") == "Coffee"


class TestExtractEventTime:
    NOW = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)  # Monday 9am UTC

    def test_iso_date_time(self):
        # 2026-06-01 14:00 UTC
        out = _extract_event_time("Meet 2026-06-01 14:00", now=self.NOW)
        assert out == datetime(2026, 6, 1, 14, 0, tzinfo=timezone.utc)

    def test_iso_date_pm(self):
        out = _extract_event_time("Meet 2026-06-02 2pm", now=self.NOW)
        assert out == datetime(2026, 6, 2, 14, 0, tzinfo=timezone.utc)

    def test_weekday_pm(self):
        # Monday Now -> "Tuesday 3pm" -> next day
        out = _extract_event_time("Coffee Tuesday 3pm", now=self.NOW)
        assert out == datetime(2026, 6, 2, 15, 0, tzinfo=timezone.utc)

    def test_month_day(self):
        out = _extract_event_time("Reminder June 5 10am", now=self.NOW)
        assert out == datetime(2026, 6, 5, 10, 0, tzinfo=timezone.utc)

    def test_no_time_returns_none(self):
        assert _extract_event_time("Just a thought", now=self.NOW) is None

    def test_ambiguous_bare_number_rejected(self):
        # "3" with no AM/PM and no minutes — too vague
        assert _extract_event_time("Tuesday 3", now=self.NOW) is None


class TestExtractLocation:
    def test_location_line(self):
        assert _extract_location("Location: Test Cafe") == "Test Cafe"

    def test_where_line(self):
        assert _extract_location("Where: Test Cafe Downtown") == "Test Cafe Downtown"

    def test_zoom_url(self):
        out = _extract_location("Join: https://zoom.us/j/12345")
        assert "zoom.us" in out

    def test_no_match(self):
        assert _extract_location("Just text") == ""


# ---------------------------------------------------------------------------
# Action tests — gates
# ---------------------------------------------------------------------------

class TestActionGates:
    async def test_self_sent_writes_event(self):
        cal = _make_cal_provider("ev-1")
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["calendar_write"] == "ok"
        assert out.data["event_id"] == "ev-1"
        cal.create_event.assert_awaited_once()
        # The kwarg goes to the right calendar.
        kwargs = cal.create_event.call_args.kwargs
        assert kwargs["calendar_id"] == "cal-self"

    async def test_alias_match_fires(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(sender=ALIAS),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["calendar_write"] == "ok"

    async def test_displayname_wrapper_matches(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(sender=f"Operator A <{OWNER}>"),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.COMPLETED

    async def test_stranger_sender_skipped(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(sender="stranger@example.com"),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "sender_not_self"
        cal.create_event.assert_not_called()

    async def test_hipaa_account_skipped(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(
                calendar_provider=cal,
                account={"id": 1, "user_id": 10, "hipaa": 1},
                account_hipaa=True,
            ),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "hipaa_account"
        cal.create_event.assert_not_called()

    async def test_hipaa_message_flag_skipped(self):
        cal = _make_cal_provider()
        msg = _msg()
        msg.hipaa = True
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            msg,
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "hipaa_account"

    async def test_no_self_schedule_calendar_skipped(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal, self_schedule_calendar_id=None),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "no_self_schedule_calendar"

    async def test_x_email_triage_header_skipped(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(headers={"X-Email-Triage": "digest; version=test"}),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "x_email_triage_header"

    async def test_cross_account_surrogate_skipped(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal, calendar_surrogate_active=True),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "cross_account_surrogate"
        cal.create_event.assert_not_called()

    async def test_no_calendar_provider_skipped(self):
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=None),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "calendar_not_enabled"


# ---------------------------------------------------------------------------
# Parse-failure path
# ---------------------------------------------------------------------------

class TestParseFailure:
    async def test_no_parseable_time_skips_calendar_write(self):
        cal = _make_cal_provider()
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(subject="Random thought", body="Just a note"),
            _classification(),
            MagicMock(),
        )
        # Action still COMPLETES (we logged the row) but the calendar
        # write itself did not happen.
        assert out.result == ActionResult.COMPLETED
        assert out.data["calendar_write"] == "skipped"
        assert out.data["reason"] == "no_parseable_time"
        cal.create_event.assert_not_called()


# ---------------------------------------------------------------------------
# Provider error paths
# ---------------------------------------------------------------------------

class TestProviderErrors:
    async def test_create_event_unsupported_skips(self):
        cal = MagicMock()
        cal.create_event = AsyncMock(side_effect=NotImplementedError())
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "provider_create_event_unsupported"

    async def test_generic_error_fails(self):
        cal = MagicMock()
        cal.create_event = AsyncMock(side_effect=RuntimeError("boom"))
        out = await SelfSentEventAction().execute(
            _flow(calendar_provider=cal),
            _msg(),
            _classification(),
            MagicMock(),
        )
        assert out.result == ActionResult.FAILED
        assert "create_event_error" in (out.error or "")
