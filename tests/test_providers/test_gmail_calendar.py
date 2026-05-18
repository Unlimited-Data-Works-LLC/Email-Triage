"""Tests for the Google Calendar provider."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.engine.models import CalendarEvent
from email_triage.providers.calendar_base import CalendarScopeError
from email_triage.providers.gmail_api import GmailApiError
from email_triage.providers.gmail_calendar import GoogleCalendarProvider


def _make_provider(**kwargs):
    defaults = {
        "account": "me@gmail.com",
        "client_id": "test-client",
        "refresh_token": "rt",
    }
    defaults.update(kwargs)
    p = GoogleCalendarProvider(**defaults)
    p._access_token = "at"
    p._access_token_expires_at = 9_999_999_999.0
    return p


def _mock_resp(data=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = json.dumps(data).encode() if data is not None else b""
    resp.json.return_value = data if data is not None else {}
    resp.text = json.dumps(data) if data else ""
    return resp


class TestList:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_list_events_basic(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "items": [
                {
                    "id": "ev1",
                    "summary": "Standup",
                    "iCalUID": "uid-1@google.com",
                    "start": {"dateTime": "2026-04-20T09:00:00Z"},
                    "end": {"dateTime": "2026-04-20T09:30:00Z"},
                    "organizer": {"email": "boss@x.com"},
                    "attendees": [
                        {"email": "me@gmail.com", "responseStatus": "accepted"},
                    ],
                    "status": "confirmed",
                },
            ],
        }))
        out = await provider.list_events(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 4, 21, tzinfo=timezone.utc),
        )
        assert len(out) == 1
        assert out[0].event_id == "ev1"
        assert out[0].summary == "Standup"
        assert out[0].start == datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc)
        assert out[0].all_day is False
        assert out[0].ical_uid == "uid-1@google.com"

    async def test_list_events_all_day(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "items": [
                {
                    "id": "ev2",
                    "summary": "Holiday",
                    "start": {"date": "2026-07-04"},
                    "end": {"date": "2026-07-05"},
                },
            ],
        }))
        out = await provider.list_events(
            datetime(2026, 7, 1, tzinfo=timezone.utc),
            datetime(2026, 7, 10, tzinfo=timezone.utc),
        )
        assert out[0].all_day is True
        assert out[0].start == datetime(2026, 7, 4, 0, 0, tzinfo=timezone.utc)

    async def test_list_events_pagination(self, provider):
        responses = [
            _mock_resp({
                "items": [{"id": "ev1", "summary": "a",
                           "start": {"dateTime": "2026-04-20T09:00:00Z"},
                           "end": {"dateTime": "2026-04-20T09:30:00Z"}}],
                "nextPageToken": "page2",
            }),
            _mock_resp({
                "items": [{"id": "ev2", "summary": "b",
                           "start": {"dateTime": "2026-04-20T10:00:00Z"},
                           "end": {"dateTime": "2026-04-20T10:30:00Z"}}],
            }),
        ]

        async def fake_request(*a, **kw):
            return responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        out = await provider.list_events(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 4, 21, tzinfo=timezone.utc),
        )
        assert [e.event_id for e in out] == ["ev1", "ev2"]

    async def test_scope_error_on_403(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 403, "message": "Insufficient Permissions"}},
            status=403,
        ))
        with pytest.raises(CalendarScopeError):
            await provider.list_events(
                datetime(2026, 4, 20, tzinfo=timezone.utc),
                datetime(2026, 4, 21, tzinfo=timezone.utc),
            )

    async def test_401_triggers_refresh_and_retry(self, provider):
        responses = [
            _mock_resp({"error": {"message": "Invalid token"}}, status=401),
            _mock_resp({"items": []}),
        ]

        async def fake_request(*a, **kw):
            return responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        provider._refresh_access_token = AsyncMock(return_value="new-token")
        out = await provider.list_events(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 4, 21, tzinfo=timezone.utc),
        )
        assert out == []
        provider._refresh_access_token.assert_called_once()


class TestOoo:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_list_ooo_passes_event_types(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "items": [{
                "id": "ooo-1", "summary": "OOO",
                "start": {"date": "2026-04-25"},
                "end": {"date": "2026-04-28"},
            }],
        }))
        out = await provider.list_ooo(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 5, 1, tzinfo=timezone.utc),
        )
        assert len(out) == 1
        assert out[0].event_id == "ooo-1"
        params = provider._http.request.call_args.kwargs["params"]
        assert params["eventTypes"] == "outOfOffice"


class TestGet:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_get_event(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "id": "ev1", "summary": "x",
            "start": {"dateTime": "2026-04-20T09:00:00Z"},
            "end": {"dateTime": "2026-04-20T09:30:00Z"},
        }))
        ev = await provider.get_event("ev1")
        assert ev.event_id == "ev1"

    async def test_get_event_by_uid_returns_first(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "items": [
                {"id": "ev1", "summary": "x",
                 "start": {"dateTime": "2026-04-20T09:00:00Z"},
                 "end": {"dateTime": "2026-04-20T09:30:00Z"}},
            ],
        }))
        ev = await provider.get_event_by_uid("uid-1@google.com")
        assert ev is not None
        assert ev.event_id == "ev1"

    async def test_get_event_by_uid_empty(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({"items": []}))
        ev = await provider.get_event_by_uid("missing@x.com")
        assert ev is None


class TestWrite:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_create_event(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({"id": "new-1"}))
        ev = CalendarEvent(
            event_id="", summary="Sync",
            start=datetime(2026, 4, 21, 14, tzinfo=timezone.utc),
            end=datetime(2026, 4, 21, 14, 30, tzinfo=timezone.utc),
        )
        new_id = await provider.create_event(ev)
        assert new_id == "new-1"

    async def test_delete_event(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(None, status=204))
        await provider.delete_event("ev1")
        call = provider._http.request.call_args
        assert call.args[0] == "DELETE"

    async def test_respond_to_invite_patches_attendee(self, provider):
        # First call: GET event.
        # Second call: PATCH event with updated attendees.
        get_resp = _mock_resp({
            "id": "ev1", "summary": "x",
            "start": {"dateTime": "2026-04-20T09:00:00Z"},
            "end": {"dateTime": "2026-04-20T09:30:00Z"},
            "attendees": [
                {"email": "boss@x.com", "responseStatus": "accepted"},
                {"email": "me@gmail.com", "responseStatus": "needsAction"},
            ],
        })
        patch_resp = _mock_resp({"id": "ev1"})
        responses = [get_resp, patch_resp]

        async def fake_request(*a, **kw):
            return responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        await provider.respond_to_invite("ev1", "accepted")
        # Assert the second call was the PATCH with our attendee accepted.
        last_call = provider._http.request.call_args
        assert last_call.args[0] == "PATCH"
        attendees = last_call.kwargs["json"]["attendees"]
        me = [a for a in attendees if a["email"].lower() == "me@gmail.com"][0]
        assert me["responseStatus"] == "accepted"
