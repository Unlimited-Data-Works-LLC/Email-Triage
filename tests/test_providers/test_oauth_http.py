"""Tests for the shared OAuth HTTP requester (#138 phase 2).

The Gmail + O365 ``_request`` bodies were lifted onto ``oauth_request``
in phase 2. These tests pin the contract:

- happy-path: bearer attached per request via ``attach_auth``, JSON body
  parsed and returned;
- 401 retry: refresh callback fires once, retry uses the new token;
- 4xx/5xx: provider-supplied ``error_factory`` is invoked.

The Gmail + O365 round-trip tests cover the SAME 401-refresh flow at
the integration level (``test_token_refresh_on_401`` in test_office365,
``test_refresh_lock`` in test_oauth_refresh_lock); this file pins the
helper itself in isolation so a future provider can rely on the same
shape without re-discovering the contract.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.providers._oauth_http import oauth_request


def _mock_resp(data=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = json.dumps(data).encode() if data is not None else b""
    resp.json.return_value = data if data is not None else {}
    resp.text = json.dumps(data) if data else ""
    return resp


class _ProviderError(Exception):
    """Stand-in for GmailApiError / GraphError — any raisable shape."""

    def __init__(self, status, body, path):
        self.status = status
        self.body = body
        self.path = path
        super().__init__(f"{status} {body} {path}")


@pytest.mark.asyncio
async def test_oauth_request_happy_path_attaches_bearer():
    """Default attach_auth places ``Authorization: Bearer <token>``
    into the per-request headers dict."""
    captured = {}

    async def fake_request(method, path, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["headers"] = kwargs.get("headers", {})
        return _mock_resp({"ok": True})

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock()
    body = await oauth_request(
        client=client, method="GET", path="/foo",
        initial_token="tok-1",
        refresh_token=refresh,
        error_factory=_ProviderError,
    )
    assert body == {"ok": True}
    assert captured["headers"]["Authorization"] == "Bearer tok-1"
    refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth_request_401_triggers_one_refresh_then_retries():
    """A 401 on the first try fires ``refresh_token`` once and retries
    with the new bearer."""
    seen_tokens = []

    async def fake_request(method, path, **kwargs):
        seen_tokens.append(kwargs["headers"]["Authorization"])
        if len(seen_tokens) == 1:
            return _mock_resp({"error": "expired"}, status=401)
        return _mock_resp({"ok": True})

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock(return_value="tok-2")
    body = await oauth_request(
        client=client, method="GET", path="/foo",
        initial_token="tok-1",
        refresh_token=refresh,
        error_factory=_ProviderError,
    )
    assert body == {"ok": True}
    assert seen_tokens == ["Bearer tok-1", "Bearer tok-2"]
    refresh.assert_awaited_once()


@pytest.mark.asyncio
async def test_oauth_request_double_401_raises_via_error_factory():
    """When refresh + retry STILL yields 401, the provider's error
    factory is invoked with status=401 + path."""
    async def fake_request(method, path, **kwargs):
        return _mock_resp({"error": "still bad"}, status=401)

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock(return_value="tok-2")
    with pytest.raises(_ProviderError) as exc_info:
        await oauth_request(
            client=client, method="GET", path="/forbidden",
            initial_token="tok-1",
            refresh_token=refresh,
            error_factory=_ProviderError,
        )
    assert exc_info.value.status == 401


@pytest.mark.asyncio
async def test_oauth_request_4xx_raises_typed_error():
    """A non-401 4xx raises immediately via error_factory; no refresh."""
    async def fake_request(method, path, **kwargs):
        return _mock_resp({"error": "not found"}, status=404)

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock()
    with pytest.raises(_ProviderError) as exc_info:
        await oauth_request(
            client=client, method="GET", path="/missing",
            initial_token="tok-1",
            refresh_token=refresh,
            error_factory=_ProviderError,
        )
    assert exc_info.value.status == 404
    refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth_request_204_returns_sentinel():
    """A 204 No Content returns ``on_204_returns`` (default None)."""
    async def fake_request(method, path, **kwargs):
        return _mock_resp(None, status=204)

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    body = await oauth_request(
        client=client, method="DELETE", path="/x",
        initial_token="tok-1",
        refresh_token=AsyncMock(),
        error_factory=_ProviderError,
    )
    assert body is None


@pytest.mark.asyncio
async def test_oauth_request_custom_attach_auth_dialect():
    """A caller-supplied ``attach_auth`` controls the header dialect."""
    captured = {}

    async def fake_request(method, path, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _mock_resp({"ok": True})

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    def custom_attach(headers, token):
        # Intentionally weird shape — proves the callable was honoured.
        headers["X-Custom-Auth"] = f"::{token}::"
        return headers

    await oauth_request(
        client=client, method="GET", path="/foo",
        initial_token="tok-1",
        refresh_token=AsyncMock(),
        error_factory=_ProviderError,
        attach_auth=custom_attach,
    )
    assert captured["headers"].get("X-Custom-Auth") == "::tok-1::"
    # Default Authorization header should NOT be present (custom dialect).
    assert "Authorization" not in captured["headers"]


@pytest.mark.asyncio
async def test_oauth_request_extra_headers_merged():
    captured = {}

    async def fake_request(method, path, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _mock_resp({"ok": True})

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    await oauth_request(
        client=client, method="POST", path="/foo",
        initial_token="tok-1",
        refresh_token=AsyncMock(),
        error_factory=_ProviderError,
        extra_headers={"X-Trace": "abc123"},
        json_data={"hello": "world"},
    )
    assert captured["headers"].get("X-Trace") == "abc123"
    assert captured["headers"]["Authorization"] == "Bearer tok-1"
