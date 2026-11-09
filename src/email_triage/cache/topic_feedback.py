"""Optional Redis mirror for a Topic's learned sender feedback signals.

STRICTLY OPTIONAL — same contract as the classification cache
(:mod:`email_triage.cache.classification`), operator-confirmed 2026-06-12 "if
it's available I want to use it, but do not want to *Require* it":

* **Never required.** Empty Redis URL ⇒ the install-level singleton is ``None``
  and every accessor degrades to the SQLite ``topic_feedback`` table, which is
  the SOLE source of truth. The whole feature works with NO Redis configured.
* **Use-if-present.** A non-empty URL ⇒ the per-Topic ``{sender: vote}`` dict is
  mirrored to Redis so the matcher's per-match read can skip SQLite. The DB is
  still authoritative; Redis is a read-through cache that a write invalidates.
* **Fail-open.** Redis unreachable / the ``redis`` package missing / any client
  error ⇒ open a short circuit-breaker and fall back to the DB. NEVER raises
  into the matcher — a Redis problem can never break (or block) Topic matching.

Reuses the operator's existing ``RedisCacheConfig.url`` (the same URL the
classification cache + persistent counters use — no second field to manage).
Keys: ``et:topicfb:{topic_id}`` holding a JSON ``{sender: vote}`` map, TTL'd.
Values are sender addresses — operator curation, same class as the at-rest
``topic_feedback`` rows + ``list_rules`` patterns (NOT a fresh PHI surface);
Redis lives on the operator's audited LAN per the cache's deployment note.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

# run17 / — shared Redis-subsystem SSOT: the ``from_url`` factory + the ONE
# fallback circuit-breaker (de-duplicated from this module's old local copy).
from email_triage.cache._redis import RedisFallbackBreaker, build_redis_client
from email_triage.triage_logging import get_logger  # N-196b R21_4

logger = get_logger("email_triage.cache.topic_feedback")  # N-196b R21_4

#: Key prefix — lets an operator share a Redis DB with other services.
_KEY_PREFIX = "et:topicfb:"

#: Default TTL for a mirrored Topic-signal map. A vote INVALIDATES the key, so
#: the TTL is only a backstop against a missed invalidation (a crash between the
#: DB write and the DEL) — generous, since the DB is always correct.
_DEFAULT_TTL_SECS = 3600


def _key(topic_id: int) -> str:
    return f"{_KEY_PREFIX}{int(topic_id)}"


class TopicFeedbackCache:
    """Optional Redis read-through mirror of per-Topic learned sender signals.

    Construct with an empty ``url`` (or via :func:`build_feedback_cache_from_config`
    returning ``None``) to disable. Every method is no-op / DB-fallback safe when
    disabled, the breaker is open, or the client can't be built — it NEVER raises.
    """

    def __init__(self, url: str = "", default_ttl_secs: int = _DEFAULT_TTL_SECS,
                 breaker_ttl_secs: int = 60) -> None:
        self._url = (url or "").strip()
        self._default_ttl = int(default_ttl_secs)
        self._breaker_ttl = int(breaker_ttl_secs)
        self._breaker = RedisFallbackBreaker(ttl_secs=self._breaker_ttl)
        self._client: Any = None
        self._client_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """True only when a non-empty Redis URL is configured (opt-in)."""
        return bool(self._url)

    # -- lazy connect (never raises) ---------------------------------------
    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is not None:
                return self._client
            # run17  — build through the Redis-subsystem factory SSOT, which
            # owns the canonical ``from_url`` params. ``ImportError`` (optional
            # ``cache`` extra missing) stays DISTINCT from a connection-build
            # error so each keeps its own operator log + breaker reason.
            try:
                client = build_redis_client(self._url)
            except ImportError as exc:
                logger.warning(
                    "Topic-feedback cache: redis package not installed "
                    "(pip install email-triage[cache]); mirror disabled, "
                    "the DB stays the source of truth",
                )
                self._open_breaker(f"import error: {exc}")
                return None
            except Exception as exc:  # noqa: BLE001 — redis raises misc types
                logger.warning(
                    "Topic-feedback cache: client init failed; mirror "
                    "disabled for this breaker window (DB fallback)",
                )
                self._open_breaker(f"init error: {exc}")
                return None
            self._client = client
            return self._client

    # -- breaker ------------------------------------------------------------
    def _breaker_open(self) -> bool:
        return self._breaker.is_open()

    def _open_breaker(self, reason: str) -> None:
        self._breaker.trip(reason)
        self._client = None  # rebuild on next attempt

    # -- sync surface (tests / CLI) ----------------------------------------
    def get_signals(self, topic_id: int) -> dict[str, int] | None:
        """The mirrored ``{sender: vote}`` map, or ``None`` on miss / disabled /
        breaker-open / any error (caller then reads the DB)."""
        if not self.enabled or self._breaker_open():
            return None
        client = self._get_client()
        if client is None:
            return None
        try:
            raw = client.get(_key(topic_id))
        except Exception as exc:  # noqa: BLE001
            self._open_breaker(f"get error: {exc}")
            return None
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return {str(k): int(v) for k, v in data.items()}
        except (TypeError, ValueError):
            return None  # corrupt value — treat as a miss, DB is authoritative

    def put_signals(self, topic_id: int, signals: dict[str, int]) -> None:
        """Mirror the DB-authoritative map to Redis (best-effort, never raises)."""
        if not self.enabled or self._breaker_open():
            return
        client = self._get_client()
        if client is None:
            return
        try:
            client.set(
                _key(topic_id),
                json.dumps({str(k): int(v) for k, v in (signals or {}).items()}),
                ex=self._default_ttl,
            )
        except Exception as exc:  # noqa: BLE001
            self._open_breaker(f"set error: {exc}")

    def invalidate(self, topic_id: int) -> None:
        """Drop the mirror for a Topic after a vote (the DB just changed)."""
        if not self.enabled or self._breaker_open():
            return
        client = self._get_client()
        if client is None:
            return
        try:
            client.delete(_key(topic_id))
        except Exception as exc:  # noqa: BLE001
            self._open_breaker(f"del error: {exc}")

    # -- async mirrors (web/matcher callers MUST use these) ----------------
    # The redis client is sync; a stuck Redis on the 2s socket_timeout would
    # block the event loop, so async callers dispatch off-loop (mirrors the
    # classification cache's a* contract).
    async def aget_signals(self, topic_id: int) -> dict[str, int] | None:
        if not self.enabled or self._breaker_open():
            return None
        return await asyncio.to_thread(self.get_signals, topic_id)

    async def aput_signals(self, topic_id: int, signals: dict[str, int]) -> None:
        if not self.enabled or self._breaker_open():
            return
        await asyncio.to_thread(self.put_signals, topic_id, signals)

    async def ainvalidate(self, topic_id: int) -> None:
        if not self.enabled or self._breaker_open():
            return
        await asyncio.to_thread(self.invalidate, topic_id)


def build_feedback_cache_from_config(redis_cache_cfg: Any) -> "TopicFeedbackCache | None":
    """Construct from the operator's ``RedisCacheConfig`` (the SAME URL the
    classification cache uses). Returns ``None`` when the URL is empty — the
    operator hasn't opted in, so the feature stays DB-only."""
    if redis_cache_cfg is None:
        return None
    url = (getattr(redis_cache_cfg, "url", "") or "").strip()
    if not url:
        return None
    return TopicFeedbackCache(url=url)


# ---------------------------------------------------------------------------
# Install-level singleton — set from web/app.py lifespan (None = disabled).
# ---------------------------------------------------------------------------
_install_topic_feedback_cache: "TopicFeedbackCache | None" = None


def set_install_topic_feedback_cache(cache: "TopicFeedbackCache | None") -> None:
    """Register the install-level mirror singleton (``None`` = disabled)."""
    global _install_topic_feedback_cache
    _install_topic_feedback_cache = cache


def get_install_topic_feedback_cache() -> "TopicFeedbackCache | None":
    """Return the install mirror singleton, or ``None`` when unset/disabled."""
    return _install_topic_feedback_cache


async def load_topic_sender_signals(db: Any, topic_id: int) -> dict[str, int]:
    """Cache-aware read of a Topic's learned sender signals.

    Checks the OPTIONAL Redis mirror first; on a hit returns it. On a miss /
    disabled / unreachable, reads the SQLite ``topic_feedback`` table (the
    source of truth) and populates the mirror. The matcher's three callers
    (Preview, back-scan, live) use THIS instead of the bare DB read so the
    optional mirror is the only thing that changes between "Redis off" and
    "Redis on" — the result is identical either way.
    """
    from email_triage.actions.topic_configs import get_topic_sender_signals
    from email_triage.web.db_threadpool import db_call

    cache = get_install_topic_feedback_cache()
    if cache is not None and cache.enabled:
        cached = await cache.aget_signals(int(topic_id))
        if cached is not None:
            return cached
    sigs = await db_call(get_topic_sender_signals, db, int(topic_id))
    if cache is not None and cache.enabled:
        await cache.aput_signals(int(topic_id), sigs)
    return sigs


def invalidate_topic_feedback_cache(topic_id: int) -> None:
    """Sync invalidate after a DB vote write (best-effort; no-op when disabled)."""
    cache = get_install_topic_feedback_cache()
    if cache is not None and cache.enabled:
        cache.invalidate(int(topic_id))
