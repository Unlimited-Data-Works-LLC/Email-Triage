"""Tests for the OAuth refresh-lock guard (#142).

When N concurrent API calls all observe an expired access token, only
ONE should fire the token-exchange request to Google. The remaining
N-1 should re-read the cached token after the lock releases.

The test runs two coroutines simultaneously — both observe the
expired token, both call ``_refresh_access_token``. With the lock,
exactly one POST to ``OAUTH_TOKEN_URL`` fires; without it, two would.

Same shape applies to ``_get_client`` for both Gmail and O365 — two
concurrent cold-path callers must not each construct their own
``httpx.AsyncClient`` (orphaning the loser's connection pool).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from email_triage.providers.gmail_api import (
    GmailApiProvider,
    OAUTH_TOKEN_URL,
)


def _ok_token_response(token: str = "fresh-token", expires_in: int = 3600):
    """Mimic an httpx Response with a successful token exchange body."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "access_token": token,
        "expires_in": expires_in,
    }
    resp.text = json.dumps(resp.json.return_value)
    return resp


@pytest.mark.asyncio
async def test_concurrent_refresh_only_one_post(monkeypatch):
    """Two concurrent _refresh_access_token calls → one network POST."""
    provider = GmailApiProvider(
        account="alice@example.com",
        client_id="cid",
        client_secret="secret",
        refresh_token="rt-old",
    )
    # Force the cached-token check to miss.
    provider._access_token = ""
    provider._access_token_expires_at = 0.0

    call_count = 0
    refresh_started = asyncio.Event()
    release_first = asyncio.Event()

    class _SerialisingClient:
        """httpx.AsyncClient stand-in.

        The first ``post`` call blocks on ``release_first`` so the
        second concurrent caller has time to enter ``_refresh_access_token``,
        observe the lock held, queue, and (post-lock-release) re-check
        the cached-token short-circuit. With the lock in place we
        expect call_count == 1 — the second waiter sees the cache
        warm and returns without a second POST.
        """

        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            nonlocal call_count
            call_count += 1
            assert url == OAUTH_TOKEN_URL
            refresh_started.set()
            await release_first.wait()
            return _ok_token_response("fresh-token")

    import email_triage.providers.gmail_api as gmod
    monkeypatch.setattr(gmod.httpx, "AsyncClient", _SerialisingClient)

    # Spawn two refresh calls concurrently.
    task_a = asyncio.create_task(provider._refresh_access_token())
    # Wait for task_a to be inside the lock + the POST to be in flight.
    await refresh_started.wait()
    task_b = asyncio.create_task(provider._refresh_access_token())
    # Give task_b a tick to reach the lock.
    await asyncio.sleep(0)

    # Release the in-flight POST so task_a can complete.
    release_first.set()
    tok_a, tok_b = await asyncio.gather(task_a, task_b)

    assert call_count == 1, "lock failed to coalesce concurrent refresh"
    assert tok_a == "fresh-token"
    assert tok_b == "fresh-token"
    assert provider._access_token == "fresh-token"


@pytest.mark.asyncio
async def test_get_client_concurrent_does_not_orphan(monkeypatch):
    """Two concurrent _get_client calls → one httpx.AsyncClient ever
    constructed (the second sees the cache warm)."""
    provider = GmailApiProvider(
        account="alice@example.com",
        client_id="cid",
        client_secret="secret",
        refresh_token="rt",
    )

    construct_count = 0

    class _CountingClient:
        def __init__(self, *a, **k):
            nonlocal construct_count
            construct_count += 1
            self.base_url = k.get("base_url")

        async def aclose(self):
            pass

    import email_triage.providers.gmail_api as gmod
    monkeypatch.setattr(gmod.httpx, "AsyncClient", _CountingClient)

    a, b = await asyncio.gather(
        provider._get_client(),
        provider._get_client(),
    )
    assert construct_count == 1
    assert a is b
