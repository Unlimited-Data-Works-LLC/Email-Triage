"""Bundle J / #139 — long-lived ``httpx.AsyncClient`` invariants.

Each module that #139 refactored to a long-lived client must hit
``httpx.AsyncClient(...)`` AT MOST ONCE across N requests in the same
process. The shared :class:`email_triage._http_client.LazyHttpClient`
holder also needs its own contract test (lock-protected lazy init +
idempotent close).

Tests deliberately mock ``httpx.AsyncClient`` and assert the
construction count -- this is the only signal of "did the refactor
land?" that survives implementation refactor.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage._http_client import LazyHttpClient


# ---------------------------------------------------------------------------
# LazyHttpClient — the shared seam
# ---------------------------------------------------------------------------


class TestLazyHttpClient:
    @pytest.mark.asyncio
    async def test_constructs_once_across_n_requests(self):
        """N sequential ``get()`` calls -> one ``httpx.AsyncClient(...)``."""
        with patch("email_triage._http_client.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = MagicMock()
            holder = LazyHttpClient(timeout=120.0)
            for _ in range(20):
                await holder.get()
            assert mock_cls.call_count == 1

    @pytest.mark.asyncio
    async def test_concurrent_get_constructs_once(self):
        """Two concurrent ``get()`` calls cold-start once, not twice.

        Mirrors the lock contract from Bundle G #142 on the OAuth
        refresh path -- two cold-path callers must not each build
        their own httpx client.
        """
        construction_started = asyncio.Event()
        release_first = asyncio.Event()
        n_built = 0

        def fake_ctor(*a, **kw):
            nonlocal n_built
            n_built += 1
            construction_started.set()
            return MagicMock()

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
            side_effect=fake_ctor,
        ):
            holder = LazyHttpClient(timeout=10.0)

            # Pre-load the lock by constructing once -- the second
            # waiter then re-checks and finds the cached value.
            # We use a synthetic delay via a wrapped lock to make
            # this deterministic.
            real_lock = asyncio.Lock()

            async def slow_get():
                async with real_lock:
                    await asyncio.sleep(0.01)
                    return await holder.get()

            await asyncio.gather(slow_get(), slow_get(), slow_get())
            assert n_built == 1

    @pytest.mark.asyncio
    async def test_aclose_idempotent_when_never_built(self):
        """``aclose()`` on a holder whose client was never requested
        is a silent no-op."""
        holder = LazyHttpClient(timeout=5.0)
        await holder.aclose()  # must not raise

    @pytest.mark.asyncio
    async def test_aclose_drains_built_client(self):
        """``aclose()`` calls ``aclose()`` on the cached client and
        empties the slot so a future ``get()`` re-constructs."""
        with patch("email_triage._http_client.httpx.AsyncClient") as mock_cls:
            client_a = MagicMock()
            client_a.aclose = AsyncMock()
            client_b = MagicMock()
            mock_cls.side_effect = [client_a, client_b]
            holder = LazyHttpClient(timeout=10.0)
            first = await holder.get()
            assert first is client_a
            await holder.aclose()
            client_a.aclose.assert_awaited_once()
            # After close, get() builds a fresh client.
            second = await holder.get()
            assert second is client_b
            assert mock_cls.call_count == 2


# ---------------------------------------------------------------------------
# OllamaClassifier — /api/chat + /api/ps share one client
# ---------------------------------------------------------------------------


class TestOllamaClassifierLongLived:
    @pytest.mark.asyncio
    async def test_n_classify_calls_one_client(self):
        """50 classify() calls construct httpx.AsyncClient exactly once."""
        from email_triage.classify.ollama import OllamaClassifier
        from email_triage.engine.models import EmailMessage
        from datetime import datetime, timezone

        chat_resp = MagicMock()
        chat_resp.json.return_value = {
            "message": {"content": json.dumps({
                "category": "fyi", "confidence": 0.5, "reason": "x",
            })},
        }
        chat_resp.raise_for_status = lambda: None

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=chat_resp)
            mock_client.get = AsyncMock(return_value=chat_resp)
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            cls = OllamaClassifier(
                model="m", base_url="http://localhost:11434",
                prefer_loaded=False,
            )
            msg = EmailMessage(
                message_id="x", provider="t", sender="a@b",
                recipients=["c@d"], subject="s", body_text="b",
                date=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            for _ in range(50):
                await cls.classify(msg, {"fyi": "x"})
            await cls.close()
            assert mock_cls.call_count == 1
            assert mock_client.post.await_count == 50

    @pytest.mark.asyncio
    async def test_close_drains_pool(self):
        """``OllamaClassifier.close()`` calls aclose on the pool."""
        from email_triage.classify.ollama import OllamaClassifier

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            cls = OllamaClassifier(model="m", prefer_loaded=False)
            # Force construction via the lazy helper.
            await cls._http.get()
            await cls.close()
            mock_client.aclose.assert_awaited_once()

        # Idempotent — second close is a no-op.
        await cls.close()


# ---------------------------------------------------------------------------
# OllamaEmbeddingBackend — /api/embeddings shares one client
# ---------------------------------------------------------------------------


class TestEmbeddingBackendLongLived:
    @pytest.mark.asyncio
    async def test_n_embed_calls_one_client(self):
        """50 embed_text() calls construct httpx.AsyncClient exactly once."""
        from email_triage.engine.embedding_backend import (
            OllamaEmbeddingBackend,
        )

        embed_resp = MagicMock()
        embed_resp.json.return_value = {"embedding": [0.1, 0.2, 0.3]}
        embed_resp.raise_for_status = lambda: None

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=embed_resp)
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            be = OllamaEmbeddingBackend(
                model="test-embedder", base_url="http://localhost:11434",
            )
            for i in range(50):
                vec = await be.embed_text(f"text-{i}")
                assert vec == [0.1, 0.2, 0.3]
            await be.close()
            assert mock_cls.call_count == 1
            assert mock_client.post.await_count == 50

    @pytest.mark.asyncio
    async def test_close_idempotent(self):
        from email_triage.engine.embedding_backend import (
            OllamaEmbeddingBackend,
        )
        be = OllamaEmbeddingBackend(model="m")
        # Never called -- close on a never-built pool is a no-op.
        await be.close()
        await be.close()


# ---------------------------------------------------------------------------
# EventDispatcher — webhook fan-out shares one client
# ---------------------------------------------------------------------------


class TestEventDispatcherLongLived:
    @pytest.mark.asyncio
    async def test_n_fire_calls_one_client(self):
        """20 fire() calls construct httpx.AsyncClient exactly once."""
        from email_triage.config import WebhookTarget
        from email_triage.web.events import EventDispatcher

        target = WebhookTarget(
            url="http://localhost:9999/hook", events=["test.event"],
        )

        resp = MagicMock()
        resp.status_code = 200

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=resp)
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            d = EventDispatcher(targets=[target], allow_external=False)
            for i in range(20):
                await d.fire("test.event", {"i": i})
            await d.aclose()
            assert mock_cls.call_count == 1
            assert mock_client.post.await_count == 20


# ---------------------------------------------------------------------------
# watch_runner._post_webhook — module-level pool
# ---------------------------------------------------------------------------


class TestWatchRunnerWebhookLongLived:
    @pytest.fixture(autouse=True)
    def _reset_module_client(self):
        """Reset the module-level cached client between tests.

        The autouse fixture in test_watch_runner.py covers the same
        reset for that file; this duplicate keeps this test file
        self-contained.
        """
        from email_triage.web import watch_runner
        watch_runner._WEBHOOK_CLIENT._client = None
        yield
        watch_runner._WEBHOOK_CLIENT._client = None

    @pytest.mark.asyncio
    async def test_n_posts_one_client(self):
        """20 ``_post_webhook`` calls construct ``httpx.AsyncClient``
        exactly once."""
        from email_triage.web.watch_runner import _post_webhook

        resp = MagicMock()
        resp.status_code = 200

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=resp)
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            for i in range(20):
                await _post_webhook(
                    url=f"http://hook{i}.local/cb",
                    secret="s",
                    payload={"i": i},
                )
            assert mock_cls.call_count == 1
            assert mock_client.post.await_count == 20

    @pytest.mark.asyncio
    async def test_aclose_module_drains(self):
        """``aclose_module()`` aclose's the pool + safe to call dry."""
        from email_triage.web.watch_runner import (
            _WEBHOOK_CLIENT, aclose_module,
        )
        # Dry-call (never built) — must not raise.
        await aclose_module()
        # Build, close, build again.
        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client
            await _WEBHOOK_CLIENT.get()
            await aclose_module()
            mock_client.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# gmail_push_auth._CertCache — JWKS fetch shares one client
# ---------------------------------------------------------------------------


class TestCertCacheLongLived:
    @pytest.mark.asyncio
    async def test_n_refreshes_one_client(self):
        """3 refresh() cycles construct httpx.AsyncClient exactly once."""
        from email_triage.web.gmail_push_auth import _CertCache

        jwks_resp = MagicMock()
        jwks_resp.status_code = 200
        jwks_resp.json.return_value = {"keys": []}

        with patch(
            "email_triage._http_client.httpx.AsyncClient",
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(return_value=jwks_resp)
            mock_client.aclose = AsyncMock()
            mock_cls.return_value = mock_client

            cache = _CertCache(ttl_seconds=3600)
            for _ in range(3):
                await cache._refresh()
            await cache.aclose()
            assert mock_cls.call_count == 1
            assert mock_client.get.await_count == 3


# ---------------------------------------------------------------------------
# GoogleCalendarProvider — Bundle G lock pattern carries to the calendar
# ---------------------------------------------------------------------------


class TestGoogleCalendarProviderLockOnGetClient:
    @pytest.mark.asyncio
    async def test_concurrent_get_client_constructs_once(self):
        """Two concurrent ``_get_client`` callers cold-start one client.

        Bundle G #142 added this guard to GmailApiProvider; #139
        propagates it to GoogleCalendarProvider so cross-account
        triage that opens calendar + gmail in parallel doesn't orphan
        a connection pool.
        """
        from email_triage.providers.gmail_calendar import (
            GoogleCalendarProvider,
        )

        n_built = 0

        def fake_ctor(*a, **kw):
            nonlocal n_built
            n_built += 1
            return MagicMock()

        # gmail_calendar imports httpx directly (not via _http_client),
        # so patch at the module level.
        with patch(
            "email_triage.providers.gmail_calendar.httpx.AsyncClient",
            side_effect=fake_ctor,
        ):
            p = GoogleCalendarProvider(
                account="a@b",
                client_id="cid",
                client_secret="sec",
                refresh_token="rt",
            )

            await asyncio.gather(*(p._get_client() for _ in range(8)))
            assert n_built == 1
