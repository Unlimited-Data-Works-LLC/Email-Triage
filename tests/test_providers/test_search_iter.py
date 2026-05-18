"""Provider-level unit tests for the bulk-triage ``search_iter`` API (#101).

The runner in ``triage_runner_bulk.py`` consumes ``provider.search_iter``
to walk a mailbox in operator-controllable batches with cursor-based
resume. These tests cover the three concrete providers (Gmail, Office
365, IMAP) at the unit level — paging across multiple batches,
clean termination on no-more-pages, and (IMAP only) reconnect on
transient failure between chunks.

Higher-level integration tests for the runner itself live in
``tests/test_web/test_bulk_triage.py``; this file isolates the provider
plumbing so a regression in pageToken / nextLink / chunking shows up
without dragging the rest of the queue machinery in.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Gmail — pageToken loop
# ---------------------------------------------------------------------------


def _gmail_provider():
    from email_triage.providers.gmail_api import GmailApiProvider

    p = GmailApiProvider(
        account="user@example.com",
        client_id="cid.apps.googleusercontent.com",
        refresh_token="rt-test",
    )
    # Skip the OAuth round-trip.
    p._access_token = "access-token-xyz"
    p._access_token_expires_at = 9_999_999_999.0
    p._http = AsyncMock()
    return p


def _gmail_resp(data, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


class TestGmailSearchIter:
    """Cover Gmail's ``users.messages.list`` ``pageToken`` loop."""

    async def test_paginates_across_three_batches(self):
        """Three responses; the third has no nextPageToken."""
        provider = _gmail_provider()
        responses = [
            _gmail_resp(
                {"messages": [{"id": "a1"}, {"id": "a2"}], "nextPageToken": "tok1"}
            ),
            _gmail_resp(
                {"messages": [{"id": "b1"}, {"id": "b2"}], "nextPageToken": "tok2"}
            ),
            _gmail_resp(
                # Final page — no nextPageToken.
                {"messages": [{"id": "c1"}]}
            ),
        ]
        provider._http.request = AsyncMock(side_effect=responses)

        seen: list[tuple[list[str], str | None]] = []
        async for batch, cursor in provider.search_iter("is:unread"):
            seen.append((list(batch), cursor))

        assert seen == [
            (["a1", "a2"], "tok1"),
            (["b1", "b2"], "tok2"),
            (["c1"], None),
        ]
        # Three pages requested. The second + third should carry the
        # pageToken from the previous response.
        calls = provider._http.request.call_args_list
        assert len(calls) == 3
        assert "pageToken" not in calls[0].kwargs["params"]
        assert calls[1].kwargs["params"]["pageToken"] == "tok1"
        assert calls[2].kwargs["params"]["pageToken"] == "tok2"

    async def test_terminates_cleanly_on_first_empty_page(self):
        """No nextPageToken on the very first response = single yield + return."""
        provider = _gmail_provider()
        provider._http.request = AsyncMock(
            return_value=_gmail_resp(
                {"messages": [{"id": "only1"}, {"id": "only2"}]}
            )
        )

        seen = [pair async for pair in provider.search_iter("is:unread")]
        assert seen == [(["only1", "only2"], None)]
        assert provider._http.request.call_count == 1

    async def test_terminates_when_response_has_no_messages_at_all(self):
        """Empty mailbox: provider yields nothing and returns cleanly."""
        provider = _gmail_provider()
        provider._http.request = AsyncMock(
            return_value=_gmail_resp({})  # no "messages" key, no token
        )

        seen = [pair async for pair in provider.search_iter("is:unread")]
        assert seen == []

    async def test_caps_batch_size_at_500(self):
        """Google docs cap maxResults at 500; over-sized callers clamp."""
        provider = _gmail_provider()
        provider._http.request = AsyncMock(
            return_value=_gmail_resp({"messages": [{"id": "x1"}]})
        )

        async for _b, _c in provider.search_iter("", batch_size=2000):
            pass

        params = provider._http.request.call_args_list[0].kwargs["params"]
        assert params["maxResults"] == "500"

    async def test_resume_cursor_seeds_first_pagetoken(self):
        """Resume after crash: caller passes the last persisted pageToken."""
        provider = _gmail_provider()
        provider._http.request = AsyncMock(
            return_value=_gmail_resp({"messages": [{"id": "r1"}]})
        )

        async for _b, _c in provider.search_iter(
            "is:unread", resume_cursor="resume-tok-9"
        ):
            pass

        first_call = provider._http.request.call_args_list[0]
        assert first_call.kwargs["params"]["pageToken"] == "resume-tok-9"


# ---------------------------------------------------------------------------
# Office 365 — @odata.nextLink loop
# ---------------------------------------------------------------------------


_mock_msal = MagicMock()
_mock_msal.SerializableTokenCache = MagicMock
_mock_msal.PublicClientApplication = MagicMock
_mock_msal.ConfidentialClientApplication = MagicMock


@pytest.fixture(autouse=False)
def _inject_msal():
    with patch.dict(sys.modules, {"msal": _mock_msal}):
        import email_triage.providers.office365 as o365_mod
        o365_mod.HAS_MSAL = True
        yield


def _o365_provider():
    from email_triage.providers.office365 import Office365Provider

    p = Office365Provider(
        client_id="cid",
        tenant_id="tid",
        token_cache_path="/tmp/cache.json",
    )
    p._http = AsyncMock()
    # Phase-2 (#138 phase 2): _request now calls acquire_token per
    # request and uses ``client.request(method, ...)``. Stub both so
    # verb-keyed mocks (provider._http.get = ...) keep working.
    p.acquire_token = AsyncMock(return_value="test-token")

    async def _dispatch(method, path, **kwargs):
        verb_mock = getattr(p._http, method.lower())
        forward_kwargs = dict(kwargs)
        forward_kwargs.pop("headers", None)
        if method.upper() in ("GET", "DELETE"):
            forward_kwargs.pop("json", None)
            return await verb_mock(path, **forward_kwargs)
        forward_kwargs.pop("params", None)
        return await verb_mock(path, **forward_kwargs)

    p._http.request = AsyncMock(side_effect=_dispatch)
    return p


def _o365_resp(data, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


class TestOffice365SearchIter:
    """Cover Microsoft Graph's ``@odata.nextLink`` loop."""

    async def test_paginates_across_three_batches(self, _inject_msal):
        provider = _o365_provider()
        next1 = "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=ABC"
        next2 = "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=DEF"
        responses = [
            _o365_resp(
                {"value": [{"id": "a1"}, {"id": "a2"}], "@odata.nextLink": next1}
            ),
            _o365_resp(
                {"value": [{"id": "b1"}], "@odata.nextLink": next2}
            ),
            _o365_resp({"value": [{"id": "c1"}, {"id": "c2"}]}),
        ]
        provider._http.get = AsyncMock(side_effect=responses)

        seen = [pair async for pair in provider.search_iter("ALL")]
        assert seen == [
            (["a1", "a2"], next1),
            (["b1"], next2),
            (["c1", "c2"], None),
        ]
        # First call uses path + params; subsequent calls use the
        # absolute nextLink with no separate params (preserves
        # Graph-encoded $skiptoken).
        calls = provider._http.get.call_args_list
        assert len(calls) == 3
        first_params = calls[0].kwargs.get("params") or {}
        assert first_params.get("$top") == "500"
        # Subsequent calls hit the absolute nextLink URL.
        assert calls[1].args[0] == next1
        assert calls[2].args[0] == next2

    async def test_terminates_when_no_nextlink(self, _inject_msal):
        provider = _o365_provider()
        provider._http.get = AsyncMock(
            return_value=_o365_resp({"value": [{"id": "x1"}]})
        )
        seen = [pair async for pair in provider.search_iter("ALL")]
        assert seen == [(["x1"], None)]
        assert provider._http.get.call_count == 1

    async def test_caps_batch_size_at_1000(self, _inject_msal):
        """Graph caps individual collection page sizes at 1000."""
        provider = _o365_provider()
        provider._http.get = AsyncMock(
            return_value=_o365_resp({"value": [{"id": "x1"}]})
        )

        async for _b, _c in provider.search_iter("ALL", batch_size=5000):
            pass

        params = provider._http.get.call_args_list[0].kwargs["params"]
        assert params["$top"] == "1000"

    async def test_resume_cursor_seeds_first_request(self, _inject_msal):
        """Resume picks up at the persisted nextLink directly."""
        provider = _o365_provider()
        resume = (
            "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=resume-XYZ"
        )
        provider._http.get = AsyncMock(
            return_value=_o365_resp({"value": [{"id": "r1"}]})
        )

        async for _b, _c in provider.search_iter("ALL", resume_cursor=resume):
            pass

        first_call = provider._http.get.call_args_list[0]
        # When resume_cursor is set, the first GET goes to the absolute URL.
        assert first_call.args[0] == resume


# ---------------------------------------------------------------------------
# IMAP — single SEARCH chunked in code; reconnect-on-failure tested via the
# blocking-backed search resilience path that wraps SEARCH.
# ---------------------------------------------------------------------------


_mock_aioimaplib = MagicMock()
_mock_aioimaplib.IMAP4_SSL = MagicMock
_mock_aioimaplib.IMAP4 = MagicMock
_mock_aioimaplib.Abort = type("Abort", (Exception,), {})
_mock_aioimaplib.CommandTimeout = type("CommandTimeout", (Exception,), {})


@pytest.fixture(autouse=False)
def _inject_aioimaplib():
    with patch.dict(sys.modules, {"aioimaplib": _mock_aioimaplib}):
        import email_triage.providers.imap as imap_mod
        imap_mod.HAS_AIOIMAPLIB = True
        yield


def _imap_provider():
    from email_triage.providers.imap import ImapProvider

    return ImapProvider(
        host="mail.example.com",
        username="user@example.com",
        password="secret",
    )


class TestImapSearchIter:
    """Cover IMAP SEARCH-then-chunk + cursor splice."""

    async def test_chunks_into_three_batches(self, _inject_aioimaplib):
        """One SEARCH returning N UIDs → ceil(N/batch_size) chunks."""
        provider = _imap_provider()

        # Stub _connect + _search_in_current_mailbox so the test
        # doesn't need a real aioimaplib client.
        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            # 25 UIDs, ascending order out of the stub.
            return [str(uid) for uid in range(1, 26)]

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        seen = [
            pair async for pair in provider.search_iter(
                "ALL", batch_size=10,
            )
        ]
        # 25 UIDs in chunks of 10 = batches of 10, 10, 5.
        assert [len(batch) for batch, _c in seen] == [10, 10, 5]
        # Cursor after each batch = max UID in that batch.
        assert [c for _b, c in seen] == ["10", "20", "25"]

    async def test_terminates_cleanly_on_empty_search(self, _inject_aioimaplib):
        """Empty mailbox → no yields, generator returns immediately."""
        provider = _imap_provider()

        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            return []

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        seen = [pair async for pair in provider.search_iter("ALL")]
        assert seen == []

    async def test_resume_cursor_splices_uid_clause(self, _inject_aioimaplib):
        """Resume after crash: cursor splices into the SEARCH criteria."""
        provider = _imap_provider()

        captured_query: dict = {}

        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            captured_query["q"] = q
            return ["100", "101", "102"]

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        seen = [
            pair async for pair in provider.search_iter(
                "UNSEEN", batch_size=10, resume_cursor="42",
            )
        ]
        # The cursor splices in as ``UID <cursor+1>:*``.
        assert "UID 43:*" in captured_query["q"]
        assert "UNSEEN" in captured_query["q"]
        # All matching UIDs returned in one chunk (3 < batch_size).
        assert seen == [(["100", "101", "102"], "102")]

    async def test_bad_cursor_falls_through_to_fresh_walk(
        self, _inject_aioimaplib,
    ):
        """A malformed cursor doesn't break the walk; runs without it."""
        provider = _imap_provider()

        captured_query: dict = {}

        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            captured_query["q"] = q
            return ["1", "2"]

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        async for _b, _c in provider.search_iter(
            "UNSEEN", resume_cursor="not-an-int",
        ):
            pass

        # No UID clause spliced in — runs as if cursor wasn't passed.
        assert "UID " not in captured_query["q"]
        assert "UNSEEN" in captured_query["q"]

    async def test_uids_sorted_ascending_so_cursor_is_high_water_mark(
        self, _inject_aioimaplib,
    ):
        """``_search_in_current_mailbox`` returns most-recent-first; the
        iter sorts ascending so each batch's last UID is the high-water
        mark for resume."""
        provider = _imap_provider()

        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            # Out-of-order UIDs simulating the helper's reverse-order
            # output.
            return ["5", "1", "9", "3", "7"]

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        seen = [
            pair async for pair in provider.search_iter(
                "ALL", batch_size=2,
            )
        ]
        # Sorted ascending: [1, 3, 5, 7, 9] — chunked 2/2/1.
        assert [batch for batch, _c in seen] == [
            ["1", "3"], ["5", "7"], ["9"],
        ]
        # Cursors are the trailing UID of each chunk.
        assert [c for _b, c in seen] == ["3", "7", "9"]


class TestImapReconnectAcrossChunks:
    """Long-running bulk runs may drop the IMAP connection mid-walk.

    The current ``search_iter`` calls ``_connect()`` once and then
    runs SEARCH; chunking happens in code over the result list, so
    reconnects between chunks aren't relevant within one yield. But
    a resumed run (after a crash) re-enters search_iter, calls
    ``_connect()`` afresh — that's the path that exercises the
    reconnect machinery. This test verifies a fresh ``_connect()``
    call per ``search_iter`` invocation.
    """

    async def test_each_search_iter_invocation_calls_connect(
        self, _inject_aioimaplib,
    ):
        provider = _imap_provider()

        connect_calls: list[None] = []

        async def _fake_connect():
            connect_calls.append(None)
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            return ["1"]

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        # First walk.
        async for _ in provider.search_iter("ALL"):
            pass
        # Second walk (simulates resume after crash).
        async for _ in provider.search_iter("ALL", resume_cursor="0"):
            pass

        assert len(connect_calls) == 2

    async def test_search_failure_propagates_so_runner_can_retry(
        self, _inject_aioimaplib,
    ):
        """If SEARCH itself raises (e.g. dropped TCP), the generator
        propagates so the runner can mark the batch errored and the
        next requeue+resume re-walks under the cursor."""
        provider = _imap_provider()

        async def _fake_connect():
            return MagicMock()

        async def _fake_search(client, q, limit, filter):
            raise ConnectionResetError("connection lost")

        provider._connect = _fake_connect
        provider._search_in_current_mailbox = _fake_search

        with pytest.raises(ConnectionResetError):
            async for _ in provider.search_iter("ALL"):
                pass


# ---------------------------------------------------------------------------
# Base / default — providers that don't override search_iter yield nothing.
# ---------------------------------------------------------------------------


class TestBaseSearchIterDefault:
    """The base class supplies a no-op default so providers that
    don't implement bulk paging cleanly skip the bulk runner without
    crashing it. Verified here independently of the concrete impls."""

    async def test_default_yields_nothing(self):
        from email_triage.providers.base import EmailProvider

        class StubProvider(EmailProvider):
            @property
            def name(self) -> str:
                return "stub"

            async def search(self, query="", limit=50, filter=None):
                return []

            async def fetch_message(self, message_id):
                raise NotImplementedError

            async def move_message(self, message_id, folder, *, create=True):
                raise NotImplementedError

            async def set_flag(self, message_id, flag, value=True):
                raise NotImplementedError

            async def close(self):
                pass

        seen = [pair async for pair in StubProvider().search_iter("")]
        assert seen == []
