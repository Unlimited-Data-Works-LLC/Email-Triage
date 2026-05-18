"""Tests for the Office 365 (Graph) calendar provider."""

import json
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Same MSAL stub as the existing O365 tests use.
_mock_msal = MagicMock()
_mock_msal.SerializableTokenCache = MagicMock
_mock_msal.PublicClientApplication = MagicMock
_mock_msal.ConfidentialClientApplication = MagicMock


@pytest.fixture(autouse=True)
def _inject_msal():
    with patch.dict(sys.modules, {"msal": _mock_msal}):
        import email_triage.providers.office365 as o365_mod
        o365_mod.HAS_MSAL = True
        yield


def _mock_resp(data=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = json.dumps(data).encode() if data is not None else b""
    resp.json.return_value = data if data is not None else {}
    resp.text = json.dumps(data) if data else ""
    return resp


def _make_provider():
    from email_triage.providers.office365_calendar import Office365CalendarProvider
    p = Office365CalendarProvider(
        client_id="cid", tenant_id="tid",
        token_cache_path="/tmp/cache.json",
    )
    # Bypass MSAL acquire_token; pretend we already have an http client.
    p._mail.acquire_token = AsyncMock(return_value="at")
    return p


class TestList:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        # Pre-set the http client so request goes straight through.
        p._http = AsyncMock()
        p._http.headers = {}
        return p

    async def test_list_events_basic(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "value": [{
                "id": "ev1",
                "subject": "Sync",
                "start": {"dateTime": "2026-04-20T09:00:00.0000000",
                          "timeZone": "UTC"},
                "end": {"dateTime": "2026-04-20T09:30:00.0000000",
                        "timeZone": "UTC"},
                "isAllDay": False,
                "organizer": {"emailAddress": {"address": "boss@x.com"}},
                "iCalUId": "uid-1@graph",
            }],
        }))
        out = await provider.list_events(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 4, 21, tzinfo=timezone.utc),
        )
        assert len(out) == 1
        assert out[0].event_id == "ev1"
        assert out[0].summary == "Sync"
        assert out[0].ical_uid == "uid-1@graph"

    async def test_list_events_all_day(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "value": [{
                "id": "ev2", "subject": "Off",
                "start": {"dateTime": "2026-07-04T00:00:00.0000000"},
                "end": {"dateTime": "2026-07-05T00:00:00.0000000"},
                "isAllDay": True,
            }],
        }))
        out = await provider.list_events(
            datetime(2026, 7, 1, tzinfo=timezone.utc),
            datetime(2026, 7, 10, tzinfo=timezone.utc),
        )
        assert out[0].all_day is True

    async def test_scope_error_on_403(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": "AccessDenied",
                       "message": "Insufficient privileges to complete the operation."}},
            status=403,
        ))
        from email_triage.providers.calendar_base import CalendarScopeError
        with pytest.raises(CalendarScopeError):
            await provider.list_events(
                datetime(2026, 4, 20, tzinfo=timezone.utc),
                datetime(2026, 4, 21, tzinfo=timezone.utc),
            )

    async def test_401_triggers_refresh(self, provider):
        responses = [
            _mock_resp({"error": {"message": "expired"}}, status=401),
            _mock_resp({"value": []}),
        ]

        async def fake_request(*a, **kw):
            return responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        out = await provider.list_events(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 4, 21, tzinfo=timezone.utc),
        )
        assert out == []
        # acquire_token should have been called twice: once on first
        # client build (in tests we pre-built it, so 0), then on the
        # 401 retry (1). Just assert >= 1.
        assert provider._mail.acquire_token.await_count >= 1


class TestOoo:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        p._http.headers = {}
        return p

    async def test_list_ooo_uses_show_as_filter(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "value": [{
                "id": "ooo-1", "subject": "Out",
                "start": {"dateTime": "2026-04-25T00:00:00.0000000"},
                "end": {"dateTime": "2026-04-28T00:00:00.0000000"},
            }],
        }))
        out = await provider.list_ooo(
            datetime(2026, 4, 20, tzinfo=timezone.utc),
            datetime(2026, 5, 1, tzinfo=timezone.utc),
        )
        assert len(out) == 1
        params = provider._http.request.call_args.kwargs["params"]
        assert params["$filter"] == "showAs eq 'oof'"


class TestRespond:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        p._http.headers = {}
        return p

    async def test_accept(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(None, status=202))
        await provider.respond_to_invite("ev1", "accepted")
        call = provider._http.request.call_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/accept")
        assert call.kwargs["json"] == {"sendResponse": True}

    async def test_decline(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(None, status=202))
        await provider.respond_to_invite("ev1", "declined")
        assert provider._http.request.call_args.args[1].endswith("/decline")

    async def test_tentative(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(None, status=202))
        await provider.respond_to_invite("ev1", "tentative")
        assert provider._http.request.call_args.args[1].endswith("/tentativelyAccept")

    async def test_invalid_response_raises(self, provider):
        with pytest.raises(ValueError):
            await provider.respond_to_invite("ev1", "maybe-later")
