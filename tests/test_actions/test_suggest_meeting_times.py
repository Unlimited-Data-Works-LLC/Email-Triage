"""Tests for the suggest_meeting_times action."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
from email_triage.engine.models import (
    ActionResult, CalendarEvent, Classification, EmailMessage,
    FlowState, FlowStatus,
)


def _msg(**kw):
    defaults = dict(
        message_id="m1", provider="gmail_api",
        sender="Alice Sender <alice@x.com>",
        recipients=["me@me.com"],
        subject="Quick chat next week?",
        body_text="Got 30 min next week?",
        date=datetime.now(timezone.utc),
    )
    defaults.update(kw)
    return EmailMessage(**defaults)


def _flow(**bag):
    return FlowState(
        flow_id="f1", message_id="m1", provider="gmail_api",
        status=FlowStatus.ACTING, state_bag=bag,
    )


def _classification():
    return Classification(category="meeting-request", confidence=0.9, reason="t")


class TestHappyPath:
    async def test_drafts_with_n_slots(self):
        cal = MagicMock()
        cal.list_events = AsyncMock(return_value=[])
        provider = MagicMock()
        provider.create_draft = AsyncMock(return_value="draft-1")

        out = await SuggestMeetingTimesAction().execute(
            _flow(
                calendar_provider=cal,
                meeting_prefs={
                    "default_length_minutes": 30,
                    "suggestion_count": 3,
                    "business_hours_start": "09:00",
                    "business_hours_end": "17:00",
                    "skip_weekends": True,
                    "search_horizon_days": 14,
                    "minimum_lead_time_hours": 0,
                    "timezone": "UTC",
                },
            ),
            _msg(), _classification(), provider,
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["draft_id"] == "draft-1"
        assert len(out.data["slots"]) == 3
        body = provider.create_draft.call_args.kwargs["body"]
        assert "Alice" in body  # greeting includes sender name
        assert body.count("•") == 3


class TestEdgeCases:
    async def test_calendar_not_enabled_skipped(self):
        provider = MagicMock()
        out = await SuggestMeetingTimesAction().execute(
            _flow(),  # no calendar_provider
            _msg(), _classification(), provider,
        )
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "calendar_not_enabled"

    async def test_scope_error_fails(self):
        from email_triage.providers.calendar_base import CalendarScopeError
        cal = MagicMock()
        cal.list_events = AsyncMock(side_effect=CalendarScopeError("g"))
        provider = MagicMock()
        out = await SuggestMeetingTimesAction().execute(
            _flow(calendar_provider=cal),
            _msg(), _classification(), provider,
        )
        assert out.result == ActionResult.FAILED
        assert "calendar_scope_missing" in (out.error or "")

    async def test_hipaa_redacts_sender_name(self):
        cal = MagicMock()
        cal.list_events = AsyncMock(return_value=[])
        provider = MagicMock()
        provider.create_draft = AsyncMock(return_value="d")
        msg = _msg()
        msg.hipaa = True
        await SuggestMeetingTimesAction().execute(
            _flow(calendar_provider=cal, meeting_prefs={"timezone": "UTC"}),
            msg, _classification(), provider,
        )
        body = provider.create_draft.call_args.kwargs["body"]
        # Sender's first name not in the body (HIPAA redaction).
        assert "Alice" not in body
        assert body.startswith("Hi —")

    async def test_no_slots_apologetic_body(self):
        # Calendar full-blocks the entire 14-day horizon.
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        busy = [CalendarEvent(
            event_id="x", summary="busy",
            start=now, end=now + timedelta(days=30),
            all_day=False,
        )]
        cal = MagicMock()
        cal.list_events = AsyncMock(return_value=busy)
        provider = MagicMock()
        provider.create_draft = AsyncMock(return_value="d")
        out = await SuggestMeetingTimesAction().execute(
            _flow(calendar_provider=cal, meeting_prefs={"timezone": "UTC"}),
            _msg(), _classification(), provider,
        )
        assert out.result == ActionResult.COMPLETED
        body = provider.create_draft.call_args.kwargs["body"]
        assert "don't have any open windows" in body


# ---------------------------------------------------------------------------
# inject_meeting_intercept helper — auto-fire wiring at the routing
# boundary. Tested separately from the action's own execute() path
# because it's a pure function and used at five call sites.
# ---------------------------------------------------------------------------

class TestInjectMeetingIntercept:
    def test_off_category_passthrough(self):
        """Non meeting-request categories are returned unchanged."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [{"action": "move", "config": {"folder_map": {}}}]
        out = inject_meeting_intercept(
            defs, "system-alerts",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert out == defs

    def test_no_calendar_passthrough(self):
        """Calendar not wired → no auto-inject."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [{"action": "draft_reply", "config": {}}]
        out = inject_meeting_intercept(
            defs, "meeting-request",
            calendar_wired=False, has_meeting_prefs=True,
        )
        assert out == defs

    def test_no_prefs_passthrough(self):
        """Meeting prefs missing → no auto-inject."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [{"action": "draft_reply", "config": {}}]
        out = inject_meeting_intercept(
            defs, "meeting-request",
            calendar_wired=True, has_meeting_prefs=False,
        )
        assert out == defs

    def test_auto_inject_replaces_draft_reply(self):
        """Auto-inject prepends suggest_meeting_times AND removes
        draft_reply (avoids two competing drafts)."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [
            {"action": "draft_reply", "config": {}},
            {"action": "label", "config": {}},
        ]
        out = inject_meeting_intercept(
            defs, "meeting-request",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert out == [
            {"action": "suggest_meeting_times", "config": {}},
            {"action": "label", "config": {}},
        ]

    def test_auto_inject_preserves_non_draft_actions(self):
        """move / label / notify / add-label survive the inject."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [
            {"action": "move", "config": {"folder_map": {"meeting-request": "Meetings"}}},
            {"action": "notify", "config": {}},
            {"action": "add-label", "config": {"label_slugs": ["work"]}},
        ]
        out = inject_meeting_intercept(
            defs, "meeting-request",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert out[0] == {"action": "suggest_meeting_times", "config": {}}
        assert out[1:] == defs

    def test_no_double_fire_when_already_present(self):
        """Operator explicitly added suggest_meeting_times → return
        unchanged. No double-fire, no draft_reply removal."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        defs = [
            {"action": "suggest_meeting_times", "config": {}},
            {"action": "draft_reply", "config": {}},  # explicit; honour it
        ]
        out = inject_meeting_intercept(
            defs, "meeting-request",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert out == defs

    def test_empty_route_still_injects(self):
        """No route at all for meeting-request → intercept still
        fires. Matches the UI's "automatic" promise."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        out = inject_meeting_intercept(
            [], "meeting-request",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert out == [{"action": "suggest_meeting_times", "config": {}}]

    def test_does_not_mutate_input(self):
        """Helper returns a new list when it triggers."""
        from email_triage.actions.suggest_meeting_times import (
            inject_meeting_intercept,
        )
        original = [{"action": "draft_reply", "config": {}}]
        snapshot = list(original)
        _ = inject_meeting_intercept(
            original, "meeting-request",
            calendar_wired=True, has_meeting_prefs=True,
        )
        assert original == snapshot


# ---------------------------------------------------------------------------
# 2026-05-14 — operator-facing timezone label rendering
# ---------------------------------------------------------------------------


class TestFormatTzLabel:
    """``_format_tz_label`` renders the operator's IANA timezone as
    ``EDT (UTC-4)`` instead of ``America/Detroit``. Must follow DST:
    a slot in May (EDT) and a slot in January (EST) on the same IANA
    zone get DIFFERENT labels."""

    def test_eastern_us_summer_is_edt_utc_minus_4(self):
        from email_triage.actions.suggest_meeting_times import _format_tz_label
        from zoneinfo import ZoneInfo
        # Mid-May = DST in effect on America/Detroit → EDT, UTC-4.
        local = datetime(2026, 5, 15, 9, 0, tzinfo=ZoneInfo("America/Detroit"))
        label = _format_tz_label(local, "America/Detroit")
        assert label == "EDT (UTC-4)"

    def test_eastern_us_winter_is_est_utc_minus_5(self):
        from email_triage.actions.suggest_meeting_times import _format_tz_label
        from zoneinfo import ZoneInfo
        # Mid-January = no DST → EST, UTC-5.
        local = datetime(2026, 1, 15, 9, 0, tzinfo=ZoneInfo("America/Detroit"))
        label = _format_tz_label(local, "America/Detroit")
        assert label == "EST (UTC-5)"

    def test_utc_zone_no_dst(self):
        from email_triage.actions.suggest_meeting_times import _format_tz_label
        from zoneinfo import ZoneInfo
        local = datetime(2026, 5, 15, 9, 0, tzinfo=ZoneInfo("UTC"))
        label = _format_tz_label(local, "UTC")
        assert label == "UTC (UTC+0)"

    def test_half_hour_offset_zone(self):
        """India Standard Time = UTC+5:30. Fractional-hour offsets
        render as ``IST (UTC+5:30)``, not ``UTC+5`` (rounded) or
        ``UTC+5.5`` (decimal)."""
        from email_triage.actions.suggest_meeting_times import _format_tz_label
        from zoneinfo import ZoneInfo
        local = datetime(2026, 5, 15, 9, 0, tzinfo=ZoneInfo("Asia/Kolkata"))
        label = _format_tz_label(local, "Asia/Kolkata")
        assert label == "IST (UTC+5:30)"

    def test_dst_transition_in_horizon(self):
        """A horizon that spans the autumn DST end gets correct
        per-slot labels: pre-transition slots = EDT, post = EST."""
        from email_triage.actions.suggest_meeting_times import _format_tz_label
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("America/Detroit")
        # 2026 fall-back: 2 AM on first Sunday of November.
        # Nov 1, 2026 is a Sunday. Before 2 AM = EDT, after = EST.
        pre = datetime(2026, 11, 1, 1, 0, tzinfo=tz)
        post = datetime(2026, 11, 2, 9, 0, tzinfo=tz)
        assert _format_tz_label(pre, "America/Detroit") == "EDT (UTC-4)"
        assert _format_tz_label(post, "America/Detroit") == "EST (UTC-5)"
