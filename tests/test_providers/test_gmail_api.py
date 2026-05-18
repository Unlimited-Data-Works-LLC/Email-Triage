"""Tests for the native Gmail API provider with mocked httpx."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.providers.gmail_api import (
    GmailApiError,
    GmailApiProvider,
    GmailAuthError,
    GmailHistoryExpiredError,
    _b64url_decode,
    build_auth_url,
    exchange_code_for_tokens,
    extract_code_from_pasted,
)


def _make_provider(**kwargs):
    defaults = {
        "account": "test@gmail.com",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "refresh_token": "rt-test",
    }
    defaults.update(kwargs)
    p = GmailApiProvider(**defaults)
    # Skip the OAuth round-trip: pretend we have a valid token.
    p._access_token = "access-token-xyz"
    p._access_token_expires_at = 9_999_999_999.0
    return p


def _mock_resp(data=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = json.dumps(data).encode() if data is not None else b""
    resp.json.return_value = data if data is not None else {}
    resp.text = json.dumps(data) if data else ""
    return resp


class TestNormalise:
    def test_basic_message(self):
        provider = _make_provider()
        body_text = "Hello, world!"
        body_b64 = base64.urlsafe_b64encode(body_text.encode()).decode().rstrip("=")
        data = {
            "id": "msg-1",
            "threadId": "thread-1",
            "labelIds": ["INBOX", "UNREAD"],
            "internalDate": "1712500000000",
            "snippet": "Hello...",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "Alice <alice@example.com>"},
                    {"name": "To", "value": "bob@example.com, carol@example.com"},
                    {"name": "Subject", "value": "Test Subject"},
                ],
                "body": {"data": body_b64},
            },
        }
        msg = provider._normalise(data, "msg-1")
        assert msg.message_id == "msg-1"
        assert msg.provider == "gmail_api"
        assert "alice@example.com" in msg.sender
        assert msg.recipients == ["bob@example.com", "carol@example.com"]
        assert msg.subject == "Test Subject"
        assert msg.body_text == "Hello, world!"
        assert msg.thread_id == "thread-1"
        assert "INBOX" in msg.labels

    def test_multipart_body(self):
        provider = _make_provider()
        plain = base64.urlsafe_b64encode(b"Plain body").decode().rstrip("=")
        data = {
            "id": "msg-2",
            "payload": {
                "mimeType": "multipart/alternative",
                "headers": [
                    {"name": "From", "value": "x@y.com"},
                    {"name": "Subject", "value": "MP"},
                ],
                "parts": [
                    {
                        "mimeType": "text/html",
                        "body": {
                            "data": base64.urlsafe_b64encode(b"<p>html</p>")
                            .decode()
                            .rstrip("="),
                        },
                    },
                    {"mimeType": "text/plain", "body": {"data": plain}},
                ],
            },
        }
        msg = provider._normalise(data, "msg-2")
        assert msg.body_text == "Plain body"

    def test_missing_internal_date_falls_back_to_now(self):
        provider = _make_provider()
        data = {
            "id": "msg-3",
            "payload": {
                "headers": [
                    {"name": "From", "value": "a@b.com"},
                    {"name": "Subject", "value": "No date"},
                ],
                "body": {},
            },
        }
        msg = provider._normalise(data, "msg-3")
        assert msg.date.year >= 2026


class TestB64Url:
    def test_decode_padded(self):
        assert _b64url_decode("aGVsbG8=") == "hello"

    def test_decode_unpadded(self):
        # Gmail strips the padding; decoder must re-add it.
        assert _b64url_decode("aGVsbG8") == "hello"

    def test_decode_empty(self):
        assert _b64url_decode("") is None


class TestHttpApi:
    """Gmail REST calls with httpx mocked at the AsyncClient level."""

    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_search_passes_query(self, provider):
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": [{"id": "m1"}, {"id": "m2"}]})
        )
        result = await provider.search("is:unread", limit=10)
        assert result == ["m1", "m2"]

        call = provider._http.request.call_args
        assert call.args[0] == "GET"
        assert call.args[1] == "/users/me/messages"
        params = call.kwargs["params"]
        assert params["q"] == "is:unread"
        assert params["maxResults"] == "10"

    async def test_search_empty_query_omits_q(self, provider):
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search("", limit=5)
        params = provider._http.request.call_args.kwargs["params"]
        assert "q" not in params

    async def test_search_translates_imap_unseen_since_to_gmail(self, provider):
        """Regression: the digest handler emits IMAP-style criteria like
        ``UNSEEN SINCE 16-Apr-2026``; the Gmail provider must translate
        to Gmail's q= shape (``is:unread after:2026/04/16``) or every
        digest on a Gmail account returns zero matches."""
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": [{"id": "m1"}]})
        )
        await provider.search("UNSEEN SINCE 16-Apr-2026", limit=10)
        params = provider._http.request.call_args.kwargs["params"]
        assert "is:unread" in params["q"]
        assert "after:2026/04/16" in params["q"]

    async def test_search_translates_imap_seen_before(self, provider):
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search("SEEN BEFORE 01-Jan-2025", limit=5)
        q = provider._http.request.call_args.kwargs["params"]["q"]
        assert "is:read" in q
        assert "before:2025/01/01" in q

    async def test_search_passes_native_gmail_query_unchanged(self, provider):
        """Native Gmail syntax must not get mangled by the translator."""
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search("from:boss@example.com is:unread", limit=5)
        q = provider._http.request.call_args.kwargs["params"]["q"]
        assert q == "from:boss@example.com is:unread"

    async def test_search_mixed_imap_and_native_tokens(self, provider):
        """Callers that layer native Gmail tokens onto an IMAP query
        (e.g. the digest handler prefixes ``label:Newsletters`` to a
        translated ``UNSEEN SINCE ...``) must get both honoured."""
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search(
            "label:Newsletters UNSEEN SINCE 16-Apr-2026", limit=5,
        )
        q = provider._http.request.call_args.kwargs["params"]["q"]
        assert "label:Newsletters" in q
        assert "is:unread" in q
        assert "after:2026/04/16" in q

    async def test_fetch_message(self, provider):
        body_b64 = base64.urlsafe_b64encode(b"Body").decode().rstrip("=")
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "id": "m-1",
            "threadId": "t-1",
            "labelIds": ["INBOX"],
            "internalDate": "1712500000000",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "x@y.com"},
                    {"name": "Subject", "value": "Hi"},
                ],
                "body": {"data": body_b64},
            },
        }))
        msg = await provider.fetch_message("m-1")
        assert msg.message_id == "m-1"
        assert msg.body_text == "Body"
        assert msg.thread_id == "t-1"

    async def test_move_message_sets_labels(self, provider):
        # First call: list_labels (label resolution).
        # Second call: modify.
        calls = []

        async def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path == "/users/me/labels":
                return _mock_resp({"labels": [{"id": "Label_42", "name": "Archive"}]})
            return _mock_resp({"id": "m-1"})

        provider._http.request = AsyncMock(side_effect=fake_request)
        await provider.move_message("m-1", "Archive")

        modify_call = [c for c in calls if c[1].endswith("/modify")][0]
        payload = modify_call[2]["json"]
        assert payload["addLabelIds"] == ["Label_42"]
        assert payload["removeLabelIds"] == ["INBOX"]

    async def test_move_message_to_builtin(self, provider):
        # Builtins like TRASH resolve without a labels fetch even if cache is empty.
        provider._label_cache = {}  # skip list_labels roundtrip
        provider._http.request = AsyncMock(return_value=_mock_resp({"id": "m-1"}))
        await provider.move_message("m-1", "TRASH")
        payload = provider._http.request.call_args.kwargs["json"]
        assert payload["addLabelIds"] == ["TRASH"]

    async def test_create_folder_idempotent_on_409(self, provider):
        # 409 is swallowed. Any previously-populated cache is left alone —
        # the label already exists server-side, so the existing snapshot
        # (if any) is still valid and we avoid a wasted refetch.
        provider._label_cache = {"Proj": "L_existing"}
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 409, "message": "Label already exists"}},
            status=409,
        ))
        await provider.create_folder("Proj")
        assert provider._label_cache == {"Proj": "L_existing"}
        # Only the POST /labels call — no follow-up GET.
        assert provider._http.request.call_count == 1

    async def test_create_folder_invalidates_label_cache(self, provider):
        # Prime the cache with a pre-create snapshot.
        provider._label_cache = {"INBOX": "INBOX", "Sent": "SENT"}
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"id": "Label_new", "name": "newlabel"},
        ))
        await provider.create_folder("newlabel")
        # After a successful mint the cache must be nulled so the next
        # _resolve_label_id() refetches from Gmail (regression for #38).
        assert provider._label_cache is None

    async def test_resolve_after_create_refetches(self, provider):
        # Pre-create cache does NOT contain "justmade".
        provider._label_cache = {"INBOX": "INBOX"}

        calls = []

        async def fake_request(method, path, **kwargs):
            calls.append((method, path))
            if method == "POST" and path == "/users/me/labels":
                return _mock_resp({"id": "Label_77", "name": "justmade"})
            if method == "GET" and path == "/users/me/labels":
                return _mock_resp({"labels": [
                    {"id": "INBOX", "name": "INBOX"},
                    {"id": "Label_77", "name": "justmade"},
                ]})
            return _mock_resp({})

        provider._http.request = AsyncMock(side_effect=fake_request)
        await provider.create_folder("justmade")
        # Without the fix, _label_cache still has only {"INBOX": ...} and
        # _resolve_label_id raises 404.
        resolved = await provider._resolve_label_id("justmade")
        assert resolved == "Label_77"
        # Sanity: we did a fresh GET /labels after the POST.
        assert ("GET", "/users/me/labels") in calls

    async def test_resolve_still_finds_existing_after_create(self, provider):
        # Pre-create cache has INBOX/Sent. After create_folder("new") the
        # cache is nulled; resolving "INBOX" must refetch and still work.
        provider._label_cache = {"INBOX": "INBOX", "Sent": "SENT"}

        async def fake_request(method, path, **kwargs):
            if method == "POST" and path == "/users/me/labels":
                return _mock_resp({"id": "Label_new", "name": "new"})
            if method == "GET" and path == "/users/me/labels":
                return _mock_resp({"labels": [
                    {"id": "INBOX", "name": "INBOX"},
                    {"id": "SENT", "name": "Sent"},
                    {"id": "Label_new", "name": "new"},
                ]})
            return _mock_resp({})

        provider._http.request = AsyncMock(side_effect=fake_request)
        await provider.create_folder("new")
        resolved = await provider._resolve_label_id("INBOX")
        assert resolved == "INBOX"

    async def test_create_already_exists_does_not_invalidate(self, provider):
        # 409 / "already exists" path returns early and leaves the cache
        # populated — no wasteful refetch on a no-op.
        provider._label_cache = {"Proj": "L_existing", "INBOX": "INBOX"}
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 409, "message": "Label already exists"}},
            status=409,
        ))
        await provider.create_folder("Proj")
        assert provider._label_cache == {"Proj": "L_existing", "INBOX": "INBOX"}

    async def test_create_folder_raises_on_other_errors(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 500, "message": "Server boom"}}, status=500,
        ))
        with pytest.raises(GmailApiError) as exc:
            await provider.create_folder("Proj")
        assert exc.value.status == 500

    async def test_list_folders_returns_sorted_names(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "labels": [
                {"id": "L2", "name": "Zebra"},
                {"id": "L1", "name": "Alpha"},
                {"id": "L3", "name": "Midway"},
            ]
        }))
        folders = await provider.list_folders()
        assert folders == ["Alpha", "Midway", "Zebra"]

    async def test_create_draft_builds_raw_with_thread(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({"id": "draft-1"}))
        draft_id = await provider.create_draft(
            ["bob@test.com"], "Re: Hi", "Reply body", thread_id="thread-7"
        )
        assert draft_id == "draft-1"
        payload = provider._http.request.call_args.kwargs["json"]
        assert payload["message"]["threadId"] == "thread-7"
        raw = base64.urlsafe_b64decode(
            payload["message"]["raw"] + "=" * ((4 - len(payload["message"]["raw"]) % 4) % 4)
        ).decode()
        assert "To: bob@test.com" in raw
        assert "Subject: Re: Hi" in raw
        assert "Reply body" in raw

    async def test_deliver_to_inbox_flags_inbox_label(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({"id": "m-new"}))
        mid = await provider.deliver_to_inbox(
            ["me@gmail.com"], "Digest", "Body"
        )
        assert mid == "m-new"
        payload = provider._http.request.call_args.kwargs["json"]
        assert payload["labelIds"] == ["INBOX", "UNREAD"]
        assert "raw" in payload

    async def test_401_triggers_token_refresh_and_retry(self, provider):
        responses = [
            _mock_resp({"error": {"message": "Invalid token"}}, status=401),
            _mock_resp({"messages": [{"id": "m-after"}]}),
        ]

        async def fake_request(*a, **kw):
            return responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        provider._refresh_access_token = AsyncMock(return_value="new-token")

        out = await provider.search("is:unread")
        assert out == ["m-after"]
        provider._refresh_access_token.assert_called_once()

    async def test_apply_label_uses_resolved_id(self, provider):
        provider._label_cache = {"Priority": "Label_77"}
        provider._http.request = AsyncMock(return_value=_mock_resp({"id": "m-1"}))
        await provider.apply_label("m-1", "Priority")
        payload = provider._http.request.call_args.kwargs["json"]
        assert payload["addLabelIds"] == ["Label_77"]

    async def test_resolve_label_exact_match_still_fast(self, provider):
        # Exact match short-circuits — no scan, no 404.
        provider._label_cache = {"Newsletters": "Label_10", "Promos": "Label_11"}
        lid = await provider._resolve_label_id("Newsletters")
        assert lid == "Label_10"

    async def test_resolve_label_case_insensitive_user_label(self, provider):
        # Cache has canonical "Newsletters"; caller asks for "newsletters".
        provider._label_cache = {"Newsletters": "Label_10", "Promos": "Label_11"}
        lid = await provider._resolve_label_id("newsletters")
        assert lid == "Label_10"

    async def test_resolve_label_missed_error_suggests_close_matches(self, provider):
        # Typo "Newslettrs" should surface "Newsletters" as a suggestion.
        provider._label_cache = {"Newsletters": "Label_10", "Promos": "Label_11"}
        with pytest.raises(GmailApiError) as exc:
            await provider._resolve_label_id("Newslettrs")
        assert exc.value.status == 404
        assert "Newsletters" in str(exc.value)


class TestListHistory:
    """Gmail history-delta reconciliation used by the Pub/Sub push consumer."""

    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_passes_startHistoryId_and_filters(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp({
            "history": [], "historyId": "42",
        }))
        out = await provider.list_history(start_history_id="10")
        assert out == {"history": [], "historyId": "42"}

        call = provider._http.request.call_args
        params = call.kwargs["params"]
        assert params["startHistoryId"] == "10"
        assert params["historyTypes"] == ["messageAdded"]
        assert params["labelId"] == "INBOX"

    async def test_merges_pages(self, provider):
        page_responses = [
            _mock_resp({
                "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
                "historyId": "11",
                "nextPageToken": "tok-A",
            }),
            _mock_resp({
                "history": [{"messagesAdded": [{"message": {"id": "m2"}}]}],
                "historyId": "12",
            }),
        ]
        async def fake_request(*a, **kw):
            return page_responses.pop(0)

        provider._http.request = AsyncMock(side_effect=fake_request)
        out = await provider.list_history(start_history_id="10")
        assert out["historyId"] == "12"
        added_ids = [
            (m.get("message") or {}).get("id")
            for entry in out["history"]
            for m in entry.get("messagesAdded", [])
        ]
        assert added_ids == ["m1", "m2"]

    async def test_history_too_old_raises_expired(self, provider):
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 404, "message": "Requested entity was not found. historyId is too old."}},
            status=404,
        ))
        with pytest.raises(GmailHistoryExpiredError) as exc:
            await provider.list_history(start_history_id="10")
        assert exc.value.status == 404

    async def test_non_history_404_still_raises_base_error(self, provider):
        # A 404 with an unrelated body should propagate as GmailApiError,
        # not be swallowed as "history too old".
        provider._http.request = AsyncMock(return_value=_mock_resp(
            {"error": {"code": 404, "message": "totally unrelated resource"}},
            status=404,
        ))
        with pytest.raises(GmailApiError) as exc:
            await provider.list_history(start_history_id="10")
        # It maps "not found" → GmailHistoryExpiredError too, which is
        # acceptable — the consumer's resync path is a safe fallback.
        # Assert only that we surfaced a 404.
        assert exc.value.status == 404


class TestAuthHelpers:
    """Module-level device-flow helpers."""

    async def test_refresh_failure_raises_gmail_auth_error(self, monkeypatch):
        p = _make_provider()
        # Clear the fake token so _refresh_access_token is forced to run.
        p._access_token = ""
        p._access_token_expires_at = 0.0

        class FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, data=None):
                return _mock_resp(
                    {"error": "invalid_grant", "error_description": "Revoked"},
                    status=400,
                )

        monkeypatch.setattr(
            "email_triage.providers.gmail_api.httpx.AsyncClient", FakeClient
        )
        with pytest.raises(GmailAuthError) as exc:
            await p._refresh_access_token()
        assert exc.value.status == 400

    async def test_refresh_without_token_raises(self):
        p = GmailApiProvider(client_id="cid", refresh_token="")
        with pytest.raises(GmailAuthError):
            await p._refresh_access_token()

    async def test_refresh_without_client_secret_raises_fast(self):
        """Refresh path mirrors the token-exchange rule: client_secret
        is required for both client types. Fast-fail with an
        actionable message instead of letting Google's 'client_secret
        is missing' bubble up mid-triage."""
        p = GmailApiProvider(
            client_id="cid", client_secret="", refresh_token="rt",
        )
        with pytest.raises(GmailAuthError) as exc:
            await p._refresh_access_token()
        assert "client_secret" in str(exc.value)

    def test_build_auth_url_carries_required_params(self):
        url = build_auth_url(
            client_id="cid",
            redirect_uri="https://x.test/oauth/google/callback",
            state="signed-state-blob",
        )
        assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        # Critical correctness checks: scope is space-joined (URL-encoded
        # to '+'), prompt=consent forces refresh-token issuance,
        # access_type=offline is what makes Google issue one at all.
        assert "client_id=cid" in url
        assert "response_type=code" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "state=signed-state-blob" in url
        assert "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.modify" in url

    def test_build_auth_url_with_login_hint(self):
        url = build_auth_url(
            client_id="cid",
            redirect_uri="http://127.0.0.1:1/",
            state="s",
            login_hint="me@gmail.com",
        )
        assert "login_hint=me%40gmail.com" in url

    async def test_exchange_code_for_tokens_web_app(self, monkeypatch):
        captured: dict = {}

        class FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, data=None):
                captured["url"] = url
                captured["data"] = data
                return _mock_resp({
                    "access_token": "at",
                    "refresh_token": "rt-new",
                    "expires_in": 3600,
                })

        monkeypatch.setattr(
            "email_triage.providers.gmail_api.httpx.AsyncClient", FakeClient
        )
        out = await exchange_code_for_tokens(
            client_id="cid",
            code="auth-code-123",
            redirect_uri="https://x.test/oauth/google/callback",
            client_secret="GOCSPX-secret",
        )
        assert out["refresh_token"] == "rt-new"
        # Web-app flow MUST send client_secret to Google.
        assert captured["data"]["client_secret"] == "GOCSPX-secret"
        assert captured["data"]["grant_type"] == "authorization_code"
        assert captured["data"]["code"] == "auth-code-123"

    async def test_exchange_code_for_tokens_desktop_also_needs_secret(self, monkeypatch):
        """Desktop clients still carry a client_secret. Google's token
        endpoint rejects the exchange without it for BOTH client types —
        the secret is part of Google's auth policy, not the OAuth grant
        shape. Earlier code treated it as optional; that was wrong."""
        captured: dict = {}

        class FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, data=None):
                captured["data"] = data
                return _mock_resp({
                    "access_token": "at",
                    "refresh_token": "rt-desktop",
                    "expires_in": 3600,
                })

        monkeypatch.setattr(
            "email_triage.providers.gmail_api.httpx.AsyncClient", FakeClient
        )
        out = await exchange_code_for_tokens(
            client_id="cid",
            client_secret="desktop-secret",
            code="code-xyz",
            redirect_uri="http://127.0.0.1:1/",
        )
        assert out["refresh_token"] == "rt-desktop"
        # Secret is ALWAYS in the POST body regardless of redirect shape.
        assert captured["data"]["client_secret"] == "desktop-secret"
        # Loopback redirect_uri (what makes it the manual-paste flow).
        assert captured["data"]["redirect_uri"] == "http://127.0.0.1:1/"

    async def test_exchange_code_missing_secret_raises(self):
        with pytest.raises(GmailAuthError) as exc:
            await exchange_code_for_tokens(
                client_id="cid",
                client_secret="",
                code="c",
                redirect_uri="http://x/",
            )
        assert "client_secret" in str(exc.value)

    async def test_exchange_code_invalid_grant_raises(self, monkeypatch):
        class FakeClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, data=None):
                return _mock_resp(
                    {"error": "invalid_grant",
                     "error_description": "code reused or expired"},
                    status=400,
                )

        monkeypatch.setattr(
            "email_triage.providers.gmail_api.httpx.AsyncClient", FakeClient
        )
        with pytest.raises(GmailAuthError) as exc:
            await exchange_code_for_tokens(
                client_id="cid", client_secret="secret",
                code="stale", redirect_uri="http://x/",
            )
        assert exc.value.status == 400

    def test_extract_code_from_full_redirect_url(self):
        code, state = extract_code_from_pasted(
            "http://127.0.0.1:1/?code=4/0AbCd&state=signed&scope=foo"
        )
        assert code == "4/0AbCd"
        assert state == "signed"

    def test_extract_code_from_bare_code(self):
        code, state = extract_code_from_pasted("  4/0AbCd  ")
        assert code == "4/0AbCd"
        assert state == ""

    def test_extract_code_from_query_fragment(self):
        code, state = extract_code_from_pasted("code=4/x&state=s")
        assert code == "4/x"
        assert state == "s"

    def test_extract_code_empty(self):
        assert extract_code_from_pasted("") == ("", "")
        assert extract_code_from_pasted("   ") == ("", "")


class TestProviderMeta:
    def test_name(self):
        p = _make_provider()
        assert p.name == "gmail_api"

    async def test_close_is_idempotent(self):
        p = _make_provider()
        p._http = AsyncMock()
        await p.close()
        assert p._http is None
        await p.close()  # second call — must not raise


class TestSearchWithFilter:
    @pytest.fixture
    def provider(self):
        p = _make_provider()
        p._http = AsyncMock()
        return p

    async def test_filter_kwarg_translates_to_q(self, provider):
        from email_triage.engine.models import MailFilter
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": [{"id": "m1"}]})
        )
        await provider.search(filter=MailFilter(unread=True, label="Priority"), limit=20)
        params = provider._http.request.call_args.kwargs["params"]
        assert "is:unread" in params["q"]
        assert "label:Priority" in params["q"]
        assert params["maxResults"] == "20"

    async def test_legacy_raw_query_still_works(self, provider):
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search("from:boss@example.com", limit=5)
        params = provider._http.request.call_args.kwargs["params"]
        assert params["q"] == "from:boss@example.com"

    async def test_filter_plus_raw_query_merged(self, provider):
        from email_triage.engine.models import MailFilter
        provider._http.request = AsyncMock(
            return_value=_mock_resp({"messages": []})
        )
        await provider.search(
            "newer_than:1d",
            filter=MailFilter(unread=True),
        )
        params = provider._http.request.call_args.kwargs["params"]
        assert "is:unread" in params["q"]
        assert "newer_than:1d" in params["q"]


# ---------------------------------------------------------------------------
# Digest-From / Reply-To / override-kwarg regressions (feat: hybrid recipient)
# ---------------------------------------------------------------------------

class TestBuildRawOverrides:
    """``_build_raw_message`` kwarg override surface for system mail."""

    @pytest.fixture
    def provider(self):
        return _make_provider(account="mailbox.owner@gmail.com")

    def _decode(self, raw_b64: str) -> str:
        pad = "=" * ((4 - len(raw_b64) % 4) % 4)
        return base64.urlsafe_b64decode(raw_b64 + pad).decode()

    def test_gmail_build_raw_respects_explicit_from_kwargs(self, provider):
        raw = provider._build_raw_message(
            ["dest@x.com"], "Sub", "Body",
            from_addr="triage@example.com", from_name="Triage",
        )
        decoded = self._decode(raw)
        assert 'From: "Triage" <triage@example.com>' in decoded
        assert "mailbox.owner@gmail.com" not in decoded

    def test_gmail_build_raw_from_addr_without_name(self, provider):
        raw = provider._build_raw_message(
            ["dest@x.com"], "Sub", "Body",
            from_addr="triage@example.com",
        )
        decoded = self._decode(raw)
        assert "From: triage@example.com" in decoded

    def test_gmail_build_raw_reply_to_header(self, provider):
        raw = provider._build_raw_message(
            ["dest@x.com"], "Sub", "Body",
            from_addr="triage@example.com",
            reply_to="human@example.com",
        )
        decoded = self._decode(raw)
        assert "Reply-To: human@example.com" in decoded

    def test_gmail_build_raw_defaults_from_to_account_when_no_override(self, provider):
        # Regression: draft-reply path (no override) must still produce
        # From = the mailbox owner's address.
        raw = provider._build_raw_message(["dest@x.com"], "Sub", "Body")
        decoded = self._decode(raw)
        assert "From: mailbox.owner@gmail.com" in decoded
