"""Lazy-init / lock-protected ``httpx.AsyncClient`` holder.

Standardises the pattern that Gmail / O365 providers introduced
(:mod:`email_triage.providers._oauth_http`) for the rest of the
HTTP call sites that today open a fresh client per request:

* :class:`email_triage.classify.ollama.OllamaClassifier`
  (LLM /api/chat, one call per classified message)
* :class:`email_triage.engine.embedding_backend.OllamaEmbeddingBackend`
  (one call per RAG-indexed message + every draft-reply retrieval)
* :class:`email_triage.web.events.EventDispatcher`
  (one call per webhook target per dispatched event)
* :func:`email_triage.web.watch_runner._post_webhook`
  (one call per matched watch fire)
* :class:`email_triage.web.gmail_push_auth._CertCache`
  (cold path on Gmail push deliveries; one fetch per kid rotation)
* :class:`email_triage.providers.gmail_calendar.GoogleCalendarProvider`
  (already had ``_get_client``; this class adds the lock that the
  Gmail provider got via Bundle G #142)

Per-request handshake on TLS endpoints costs 50-200 ms; #139 collapses
that into a single long-lived pool per call site.

Why a class rather than scattering ``self._http`` + ``self._lock`` on
each owner: the pattern is mechanical (lazy init, double-check, close
on shutdown) and lives in five different modules with five different
constructors. A single class ``LazyHttpClient`` lets each owner
compose one attribute and forward ``close()`` -- new sites pick it up
without thinking about the lock dance.

The :func:`refresh_lock_for` seam in ``providers/_oauth_http.py``
keeps its own existence -- it ALSO guards token-refresh state, not
just client construction, and the providers reuse the same lock for
both. This module is for sites that don't have an OAuth refresh
path, just a hot HTTP endpoint.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx


class LazyHttpClient:
    """Holds a lazily-constructed :class:`httpx.AsyncClient` with a
    per-instance ``asyncio.Lock`` to serialise the construction.

    Usage::

        class OllamaClassifier:
            def __init__(self, ..., timeout: float = 120.0):
                self._http = LazyHttpClient(timeout=timeout)

            async def classify(self, ...):
                client = await self._http.get()
                resp = await client.post("/api/chat", json=payload)

            async def close(self) -> None:
                await self._http.aclose()

    The lock is created lazily on first ``get()`` so the holder is
    safe to instantiate before an event loop exists (matches the
    reasoning in :func:`providers._oauth_http.refresh_lock_for`).

    Constructor kwargs are forwarded verbatim to
    :class:`httpx.AsyncClient` -- ``base_url``, ``timeout``,
    ``headers``, etc. all pass through.
    """

    def __init__(self, **client_kwargs: Any) -> None:
        self._client_kwargs = client_kwargs
        self._client: httpx.AsyncClient | None = None
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def get(self) -> httpx.AsyncClient:
        """Return the cached client, constructing it on first call.

        Wrapped in a per-instance lock so two concurrent coroutines
        observing ``self._client is None`` don't both build clients
        and orphan one of the connection pools (the same race the
        Gmail / O365 providers already guarded via Bundle G #142).
        """
        if self._client is not None:
            return self._client
        async with self._get_lock():
            if self._client is None:
                self._client = httpx.AsyncClient(**self._client_kwargs)
            return self._client

    async def aclose(self) -> None:
        """Drain the client. Idempotent -- safe to call from a
        shutdown hook even if the client was never built."""
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None


__all__ = ["LazyHttpClient"]
