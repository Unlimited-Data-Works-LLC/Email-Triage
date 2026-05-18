"""Tests for the Office 365 / Microsoft Graph provider with mocked MSAL + httpx."""

import json
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest


def _bridge_request_to_verb_mocks(http_mock):
    """Install a ``_http.request`` shim that dispatches to per-verb mocks.

    Pre-#138-phase-2, ``Office365Provider._request`` called
    ``client.get(...)`` / ``client.post(...)`` etc directly. The phase-2
    refactor lifted the request body onto :func:`oauth_request`, which
    uses ``client.request(method, ...)``. The verb-specific mocks the
    existing tests install (``provider._http.get = AsyncMock(...)``)
    don't auto-route through the new entrypoint — without this shim
    every legacy test would fail with "AsyncMock has no attribute
    request".

    This is a test-side bridge, not a production indirection — the
    production ``oauth_request`` only ever calls ``client.request``.
    """
    async def _dispatch(method, path, **kwargs):
        verb = method.lower()
        verb_mock = getattr(http_mock, verb)
        # Replicate httpx-shaped per-verb call signatures: GET/DELETE
        # take ``params``; POST/PATCH take ``json``. Strip headers
        # since legacy tests don't assert on them.
        forward_kwargs = dict(kwargs)
        forward_kwargs.pop("headers", None)
        if verb in ("get", "delete"):
            forward_kwargs.pop("json", None)
            return await verb_mock(path, **forward_kwargs)
        if verb in ("post", "patch"):
            forward_kwargs.pop("params", None)
            return await verb_mock(path, **forward_kwargs)
        return await verb_mock(path, **forward_kwargs)

    http_mock.request = AsyncMock(side_effect=_dispatch)

# ---------------------------------------------------------------------------
# Mock msal so we can import the provider without the real package.
# ---------------------------------------------------------------------------

_mock_msal = MagicMock()
_mock_msal.SerializableTokenCache = MagicMock
_mock_msal.PublicClientApplication = MagicMock
_mock_msal.ConfidentialClientApplication = MagicMock


@pytest.fixture(autouse=True)
def _inject_msal():
    """Inject a mock msal into sys.modules for all tests."""
    with patch.dict(sys.modules, {"msal": _mock_msal}):
        import email_triage.providers.office365 as o365_mod
        o365_mod.HAS_MSAL = True
        yield


def _make_provider(**kwargs):
    """Create an Office365Provider with defaults."""
    from email_triage.providers.office365 import Office365Provider

    defaults = {
        "client_id": "test-client-id",
        "tenant_id": "test-tenant-id",
        "token_cache_path": "/tmp/test_cache.json",
    }
    defaults.update(kwargs)
    return Office365Provider(**defaults)


def _mock_graph_response(data: dict | list | None = None, status: int = 200):
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data if data is not None else {}
    resp.text = json.dumps(data) if data else ""
    return resp


class TestNormalise:
    """Test normalisation of Graph API message resources."""

    def test_basic_message(self):
        from email_triage.providers.office365 import Office365Provider
        provider = _make_provider()

        data = {
            "id": "msg-1",
            "subject": "Test Subject",
            "from": {
                "emailAddress": {
                    "name": "Alice Sender",
                    "address": "alice@example.com",
                }
            },
            "toRecipients": [
                {"emailAddress": {"address": "bob@example.com"}},
                {"emailAddress": {"address": "carol@example.com"}},
            ],
            "body": {"contentType": "text", "content": "Hello, world!"},
            "receivedDateTime": "2026-04-14T10:30:00Z",
            "categories": ["Important"],
            "conversationId": "conv-1",
        }

        msg = provider._normalise(data, "msg-1")
        assert msg.message_id == "msg-1"
        assert msg.provider == "office365"
        assert "alice@example.com" in msg.sender
        assert "Alice Sender" in msg.sender
        assert msg.recipients == ["bob@example.com", "carol@example.com"]
        assert msg.subject == "Test Subject"
        assert msg.body_text == "Hello, world!"
        assert msg.thread_id == "conv-1"
        assert msg.labels == ["Important"]
        assert msg.date.year == 2026

    def test_html_body_stripped(self):
        provider = _make_provider()
        data = {
            "id": "msg-2",
            "subject": "HTML Email",
            "from": {"emailAddress": {"address": "sender@test.com"}},
            "toRecipients": [],
            "body": {
                "contentType": "html",
                "content": "<html><body><p>Hello</p><br/><p>World</p></body></html>",
            },
            "receivedDateTime": "2026-04-14T12:00:00Z",
        }

        msg = provider._normalise(data, "msg-2")
        assert "Hello" in msg.body_text
        assert "World" in msg.body_text
        assert "<" not in msg.body_text

    def test_body_preview_fallback(self):
        provider = _make_provider()
        data = {
            "id": "msg-3",
            "subject": "Preview Only",
            "from": {"emailAddress": {"address": "sender@test.com"}},
            "toRecipients": [],
            "body": {"contentType": "text", "content": ""},
            "bodyPreview": "This is the preview text",
            "receivedDateTime": "2026-04-14T12:00:00Z",
        }

        msg = provider._normalise(data, "msg-3")
        assert msg.body_text == "This is the preview text"

    def test_no_sender_name(self):
        provider = _make_provider()
        data = {
            "id": "msg-4",
            "subject": "No Name",
            "from": {"emailAddress": {"address": "noname@test.com"}},
            "toRecipients": [],
            "body": {"contentType": "text", "content": "Body"},
        }

        msg = provider._normalise(data, "msg-4")
        assert msg.sender == "noname@test.com"

    def test_missing_date(self):
        provider = _make_provider()
        data = {
            "id": "msg-5",
            "subject": "No Date",
            "from": {"emailAddress": {"address": "sender@test.com"}},
            "toRecipients": [],
            "body": {"contentType": "text", "content": "Body"},
        }

        msg = provider._normalise(data, "msg-5")
        # Falls back to now().
        assert msg.date.year >= 2026


class TestQueryTranslation:
    """Test query translation to OData filters."""

    def test_is_unread(self):
        from email_triage.providers.office365 import Office365Provider
        assert Office365Provider._translate_query("is:unread") == "isRead eq false"

    def test_is_unread_with_extra(self):
        from email_triage.providers.office365 import Office365Provider
        result = Office365Provider._translate_query("is:unread importance eq 'high'")
        assert result == "isRead eq false and importance eq 'high'"

    def test_from_query(self):
        from email_triage.providers.office365 import Office365Provider
        result = Office365Provider._translate_query("from:boss@company.com")
        assert "boss@company.com" in result
        assert "from/emailAddress/address" in result

    def test_odata_passthrough(self):
        from email_triage.providers.office365 import Office365Provider
        q = "importance eq 'high' and isRead eq false"
        assert Office365Provider._translate_query(q) == q

    def test_freetext_returns_empty(self):
        from email_triage.providers.office365 import Office365Provider
        # Free-text queries should return empty (trigger $search).
        assert Office365Provider._translate_query("quarterly report") == ""


class TestStripHtml:
    def test_basic_strip(self):
        from email_triage.providers.office365 import Office365Provider
        html = "<p>Hello</p><br/><p>World</p>"
        text = Office365Provider._strip_html(html)
        assert "Hello" in text
        assert "World" in text
        assert "<" not in text

    def test_complex_html(self):
        from email_triage.providers.office365 import Office365Provider
        html = '<div style="color:red"><a href="url">Link</a> text</div>'
        text = Office365Provider._strip_html(html)
        assert "Link" in text
        assert "text" in text
        assert "<" not in text


class TestGraphAPI:
    """Test Graph API calls with mocked httpx."""

    @pytest.fixture
    def provider(self):
        p = _make_provider()
        # Pre-set a mock HTTP client to skip auth.
        p._http = AsyncMock()
        # Phase-2 (#138 phase 2): _request now calls
        # ``acquire_token`` per request and uses
        # ``client.request(method, ...)``. Stub both so verb-keyed
        # mocks attached by tests continue to work.
        p.acquire_token = AsyncMock(return_value="test-token")
        _bridge_request_to_verb_mocks(p._http)
        return p

    async def test_search_unread(self, provider):
        provider._http.get = AsyncMock(return_value=_mock_graph_response(
            {"value": [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}]}
        ))

        result = await provider.search("is:unread", limit=10)
        assert result == ["m1", "m2", "m3"]

        # Verify the call used $filter.
        call_kwargs = provider._http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("$filter") == "isRead eq false"

    async def test_search_freetext(self, provider):
        provider._http.get = AsyncMock(return_value=_mock_graph_response(
            {"value": [{"id": "m1"}]}
        ))

        result = await provider.search("quarterly report", limit=5)
        assert result == ["m1"]

        call_kwargs = provider._http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "$search" in params

    async def test_search_empty(self, provider):
        provider._http.get = AsyncMock(return_value=_mock_graph_response(
            {"value": []}
        ))

        result = await provider.search("is:unread")
        assert result == []

    async def test_fetch_message(self, provider):
        msg_data = {
            "id": "msg-1",
            "subject": "Test",
            "from": {"emailAddress": {"name": "Alice", "address": "alice@test.com"}},
            "toRecipients": [{"emailAddress": {"address": "bob@test.com"}}],
            "body": {"contentType": "text", "content": "Hello"},
            "receivedDateTime": "2026-04-14T10:00:00Z",
            "categories": [],
            "conversationId": "conv-1",
        }
        provider._http.get = AsyncMock(return_value=_mock_graph_response(msg_data))

        msg = await provider.fetch_message("msg-1")
        assert msg.message_id == "msg-1"
        assert msg.provider == "office365"
        assert "alice@test.com" in msg.sender
        assert msg.subject == "Test"
        assert msg.body_text == "Hello"

    async def test_create_draft(self, provider):
        provider._http.post = AsyncMock(return_value=_mock_graph_response(
            {"id": "draft-1", "isDraft": True}
        ))

        draft_id = await provider.create_draft(
            ["bob@test.com"], "Subject", "Body text"
        )
        assert draft_id == "draft-1"

        call_args = provider._http.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert payload["subject"] == "Subject"
        assert payload["toRecipients"][0]["emailAddress"]["address"] == "bob@test.com"

    async def test_create_draft_with_thread(self, provider):
        provider._http.post = AsyncMock(return_value=_mock_graph_response(
            {"id": "draft-2"}
        ))

        await provider.create_draft(
            ["bob@test.com"], "Re: Test", "Reply", thread_id="conv-1"
        )

        call_args = provider._http.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert payload["conversationId"] == "conv-1"

    async def test_apply_label(self, provider):
        # First call: GET current categories.
        get_resp = _mock_graph_response({"categories": ["Existing"]})
        # Second call: PATCH with updated categories.
        patch_resp = _mock_graph_response(None, status=200)

        provider._http.get = AsyncMock(return_value=get_resp)
        provider._http.patch = AsyncMock(return_value=patch_resp)

        await provider.apply_label("msg-1", "NewLabel")

        # Verify PATCH was called with both labels.
        call_args = provider._http.patch.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert "Existing" in payload["categories"]
        assert "NewLabel" in payload["categories"]

    async def test_apply_label_already_exists(self, provider):
        get_resp = _mock_graph_response({"categories": ["AlreadyThere"]})
        provider._http.get = AsyncMock(return_value=get_resp)
        provider._http.patch = AsyncMock()

        await provider.apply_label("msg-1", "AlreadyThere")

        # PATCH should NOT be called since label already exists.
        provider._http.patch.assert_not_called()

    async def test_list_labels(self, provider):
        provider._http.get = AsyncMock(return_value=_mock_graph_response({
            "value": [
                {"id": "cat-1", "displayName": "Red Category"},
                {"id": "cat-2", "displayName": "Blue Category"},
            ]
        }))

        labels = await provider.list_labels()
        assert len(labels) == 2
        assert labels[0]["name"] == "Red Category"

    async def test_list_folders_flat(self, provider):
        """Top-level mailFolders with no children → sorted displayNames."""
        provider._http.get = AsyncMock(return_value=_mock_graph_response({
            "value": [
                {"id": "f1", "displayName": "Inbox", "childFolderCount": 0},
                {"id": "f2", "displayName": "Sent Items", "childFolderCount": 0},
                {"id": "f3", "displayName": "Drafts", "childFolderCount": 0},
            ]
        }))
        names = await provider.list_folders()
        # Sorted by Python's default string ordering.
        assert names == ["Drafts", "Inbox", "Sent Items"]

    async def test_list_folders_with_children(self, provider):
        """childFolderCount > 0 triggers /childFolders walk; results merge."""
        responses = [
            # Root /me/mailFolders
            _mock_graph_response({
                "value": [
                    {"id": "f1", "displayName": "Inbox", "childFolderCount": 2},
                    {"id": "f2", "displayName": "Sent Items", "childFolderCount": 0},
                ],
            }),
            # /me/mailFolders/f1/childFolders
            _mock_graph_response({
                "value": [
                    {"id": "c1", "displayName": "Receipts", "childFolderCount": 0},
                    {"id": "c2", "displayName": "Travel", "childFolderCount": 0},
                ],
            }),
        ]
        provider._http.get = AsyncMock(side_effect=responses)
        names = await provider.list_folders()
        assert names == ["Inbox", "Receipts", "Sent Items", "Travel"]
        # Two GETs: root + childFolders for f1.
        assert provider._http.get.call_count == 2

    async def test_list_folders_pagination(self, provider):
        """Graph's @odata.nextLink is followed; absolute URL routed verbatim."""
        next_url = (
            "https://graph.microsoft.com/v1.0/me/mailFolders"
            "?$skiptoken=abc123"
        )
        responses = [
            _mock_graph_response({
                "value": [
                    {"id": "f1", "displayName": "Inbox", "childFolderCount": 0},
                ],
                "@odata.nextLink": next_url,
            }),
            _mock_graph_response({
                "value": [
                    {"id": "f2", "displayName": "Archive", "childFolderCount": 0},
                ],
            }),
        ]
        provider._http.get = AsyncMock(side_effect=responses)
        names = await provider.list_folders()
        assert names == ["Archive", "Inbox"]

    async def test_list_folders_fetch_failure_keeps_partial(self, provider):
        """Branch fetch failure logs + skips; collected names returned."""
        from email_triage.providers.office365 import GraphError
        responses = [
            _mock_graph_response({
                "value": [
                    {"id": "f1", "displayName": "Inbox", "childFolderCount": 1},
                    {"id": "f2", "displayName": "Sent Items", "childFolderCount": 0},
                ],
            }),
            # Child walk for f1 errors — should not crash the whole list.
            _mock_graph_response(
                {"error": {"code": "ErrorItemNotFound", "message": "gone"}},
                status=404,
            ),
        ]
        provider._http.get = AsyncMock(side_effect=responses)
        names = await provider.list_folders()
        # Root names survive; child branch lost.
        assert "Inbox" in names
        assert "Sent Items" in names

    async def test_archive(self, provider):
        provider._http.post = AsyncMock(return_value=_mock_graph_response(
            {"id": "msg-1"}
        ))

        await provider.archive("msg-1")
        call_args = provider._http.post.call_args
        path = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        # Verify the move endpoint was used.
        assert "move" in str(path) or "move" in str(call_args)

    async def test_mark_read(self, provider):
        provider._http.patch = AsyncMock(return_value=_mock_graph_response(
            {"id": "msg-1", "isRead": True}
        ))

        await provider.mark_read("msg-1")
        call_args = provider._http.patch.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert payload["isRead"] is True

    async def test_graph_error(self, provider):
        from email_triage.providers.office365 import GraphError
        error_resp = _mock_graph_response(
            {"error": {"code": "ErrorItemNotFound", "message": "Not found"}},
            status=404,
        )
        provider._http.get = AsyncMock(return_value=error_resp)

        with pytest.raises(GraphError) as exc_info:
            await provider.fetch_message("bad-id")

        assert exc_info.value.status == 404

    async def test_token_refresh_on_401(self, provider):
        """Test that 401 triggers a token refresh and retry."""
        # First call returns 401, second returns success.
        resp_401 = _mock_graph_response({"error": {"message": "Unauthorized"}}, status=401)
        resp_ok = _mock_graph_response({"value": [{"id": "m1"}]})

        call_count = 0

        async def mock_get(path, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return resp_401
            return resp_ok

        provider._http.get = mock_get
        provider._http.headers = {"Authorization": "Bearer old-token"}

        # Mock acquire_token for refresh.
        provider.acquire_token = AsyncMock(return_value="new-token")

        result = await provider.search("is:unread")
        assert result == ["m1"]
        assert call_count == 2
        # Phase-2 (#138 phase 2): acquire_token is invoked per request
        # (warming the bearer for that call) AND again on 401-refresh.
        # Pre-phase-2 only the refresh call counted because the initial
        # bearer rode on the persistent client.headers.
        assert provider.acquire_token.call_count == 2


class TestSubscriptions:
    """Test Graph webhook subscription management."""

    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        p.acquire_token = AsyncMock(return_value="test-token")
        _bridge_request_to_verb_mocks(p._http)
        return p

    async def test_create_subscription(self, provider):
        provider._http.post = AsyncMock(return_value=_mock_graph_response({
            "id": "sub-1",
            "resource": "me/mailFolders('Inbox')/messages",
            "changeType": "created",
            "expirationDateTime": "2026-04-17T10:00:00.0000000Z",
        }))

        result = await provider.create_subscription(
            webhook_url="https://host.tailnet.ts.net/webhooks/graph",
            client_state="secret123",
        )
        assert result["id"] == "sub-1"

        call_args = provider._http.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert payload["notificationUrl"] == "https://host.tailnet.ts.net/webhooks/graph"
        assert payload["clientState"] == "secret123"
        assert payload["resource"] == "me/mailFolders('Inbox')/messages"
        assert payload["changeType"] == "created"

    async def test_renew_subscription(self, provider):
        provider._http.patch = AsyncMock(return_value=_mock_graph_response({
            "id": "sub-1",
            "expirationDateTime": "2026-04-20T10:00:00.0000000Z",
        }))

        result = await provider.renew_subscription("sub-1")
        assert result["id"] == "sub-1"

    async def test_delete_subscription(self, provider):
        provider._http.delete = AsyncMock(return_value=_mock_graph_response(
            None, status=204
        ))

        await provider.delete_subscription("sub-1")
        provider._http.delete.assert_called_once()

    async def test_watch_not_implemented(self):
        provider = _make_provider()
        with pytest.raises(NotImplementedError, match="webhooks"):
            async for _ in provider.watch():
                pass


class TestProviderMeta:
    """Test provider properties and lifecycle."""

    def test_name(self):
        provider = _make_provider()
        assert provider.name == "office365"

    async def test_close(self, tmp_path):
        provider = _make_provider(token_cache_path=str(tmp_path / "cache.json"))
        mock_http = AsyncMock()
        provider._http = mock_http
        provider._cache = MagicMock()
        provider._cache.has_state_changed = True
        provider._cache.serialize.return_value = '{"cache": true}'

        await provider.close()

        mock_http.aclose.assert_called_once()
        assert provider._http is None
        # Cache should have been written.
        assert (tmp_path / "cache.json").exists()

    async def test_close_no_client(self):
        provider = _make_provider()
        await provider.close()  # Should not raise.


class TestAuth:
    """Test MSAL authentication flows."""

    def test_msal_not_installed(self):
        """Verify ImportError when msal is missing."""
        import email_triage.providers.office365 as o365_mod
        original = o365_mod.HAS_MSAL
        try:
            o365_mod.HAS_MSAL = False
            with pytest.raises(ImportError, match="msal"):
                from email_triage.providers.office365 import Office365Provider
                Office365Provider()
        finally:
            o365_mod.HAS_MSAL = original

    async def test_acquire_token_silent(self):
        """Test silent token acquisition from cached account."""
        provider = _make_provider()

        mock_app = MagicMock()
        mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
        mock_app.acquire_token_silent.return_value = {
            "access_token": "cached-token-123"
        }
        provider._app = mock_app

        mock_cache = MagicMock()
        mock_cache.has_state_changed = False
        provider._cache = mock_cache

        token = await provider.acquire_token()
        assert token == "cached-token-123"
        mock_app.acquire_token_silent.assert_called_once()

    async def test_acquire_token_client_credentials(self):
        """Test client credentials flow for confidential app."""
        provider = _make_provider(client_secret="secret-value")

        mock_app = MagicMock()
        mock_app.get_accounts.return_value = []
        mock_app.acquire_token_for_client.return_value = {
            "access_token": "client-cred-token"
        }
        provider._app = mock_app

        mock_cache = MagicMock()
        mock_cache.has_state_changed = False
        provider._cache = mock_cache

        token = await provider.acquire_token()
        assert token == "client-cred-token"

    async def test_acquire_token_client_credentials_failure(self):
        provider = _make_provider(client_secret="secret-value")

        mock_app = MagicMock()
        mock_app.get_accounts.return_value = []
        mock_app.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Bad credentials",
        }
        provider._app = mock_app

        mock_cache = MagicMock()
        mock_cache.has_state_changed = False
        provider._cache = mock_cache

        with pytest.raises(RuntimeError, match="Bad credentials"):
            await provider.acquire_token()

    async def test_device_code_flow(self, tmp_path):
        """Test device code flow when no cached tokens."""
        provider = _make_provider(token_cache_path=str(tmp_path / "cache.json"))

        mock_app = MagicMock()
        mock_app.get_accounts.return_value = []
        mock_app.initiate_device_flow.return_value = {
            "user_code": "ABCD1234",
            "verification_uri": "https://login.microsoftonline.com/common/oauth2/deviceauth",
            "message": "Go to https://... and enter code ABCD1234",
        }
        mock_app.acquire_token_by_device_flow.return_value = {
            "access_token": "device-flow-token"
        }
        provider._app = mock_app

        mock_cache = MagicMock()
        mock_cache.has_state_changed = True
        mock_cache.serialize.return_value = '{"tokens": true}'
        provider._cache = mock_cache

        with patch("builtins.print"):  # Suppress console output.
            token = await provider.acquire_token()

        assert token == "device-flow-token"
        mock_app.initiate_device_flow.assert_called_once()
        mock_app.acquire_token_by_device_flow.assert_called_once()
        # Token cache should have been saved.
        assert (tmp_path / "cache.json").exists()

    async def test_device_code_flow_failure(self):
        provider = _make_provider()

        mock_app = MagicMock()
        mock_app.get_accounts.return_value = []
        mock_app.initiate_device_flow.return_value = {
            "error_description": "Application not found",
        }
        provider._app = mock_app

        mock_cache = MagicMock()
        provider._cache = mock_cache

        with pytest.raises(RuntimeError, match="Device code flow failed"):
            await provider.acquire_token()


class TestCLIIntegration:
    """Test that the CLI wires up the Office 365 provider."""

    def test_create_provider_office365(self):
        """Verify _create_provider creates an Office365Provider."""
        from email_triage.config import TriageConfig, ProviderConfig

        config = TriageConfig(
            provider=ProviderConfig(
                type="office365",
                office365={
                    "client_id": "test-id",
                    "tenant_id": "test-tenant",
                    "token_cache_path": "/tmp/test_cache.json",
                },
            )
        )

        from email_triage.cli import _create_provider
        provider = _create_provider(config)
        assert provider.name == "office365"
        assert provider._client_id == "test-id"
        assert provider._tenant_id == "test-tenant"
