"""Best-effort Redis-backed counter persistence.

Process-local counters reset on every container restart. For
operators who deploy frequently, that erases the long-horizon
hit-ratio + tuning signal that justifies the cache / embedding-
chain knobs.

This module provides a thin Redis backend that mirrors counter
increments via ``HINCRBY``. Process-local counters STAY the
source of truth for the live snapshot (zero new Redis hops on
the hot read path); the Redis side just accumulates across
restarts so /admin/stats can show "since process start" AND
"lifetime" side-by-side.

Architecture
============

* :class:`RedisCounterBackend` — lazy client + best-effort
  ``incr`` / ``fetch`` / ``reset``. Silent on Redis-side failure
  so a counter blip can't crash the classifier hot path.
* :func:`get_install_counter_backend` / :func:`set_install_counter_backend`
  — module-level singleton, mirrors the cache module's
  install-singleton pattern.
* Per-module counter classes (``_Counters`` in
  ``cache/classification.py``, ``_BackendMetrics`` in
  ``engine/embedding_backend.py``) call into this backend on
  every ``incr_*`` method. Cost per call: ~0.5ms LAN
  round-trip; ignored when the backend isn't installed.

Key shape
=========

``{prefix}{namespace}`` is a Redis HASH. Fields are the counter
names. Operator points the URL at the same Redis the cache
uses; URLs are LAN-only by policy.

Lifetime reset
==============

Per-namespace ``reset`` is exposed for the admin "Reset lifetime
counters" button. Soft-flush (HDEL specific fields) avoids
collateral damage to other namespaces sharing the same DB.

Privacy
=======

Stored values are integers only. No PHI / sender / subject /
body content. Reset semantics are explicit operator action;
nothing in the counter values requires HIPAA carve-out.
"""

from __future__ import annotations

from typing import Any

# run17 / — the Redis-subsystem SSOT: the ``from_url`` factory + the ONE
# shared fallback circuit-breaker. Before run17 this module was the 3rd Redis
# consumer with NO breaker — a dead Redis re-paid the full 2 s socket timeout on
# EVERY counter bump, no backoff. ``_redis`` imports nothing from ``email_triage``
# (a leaf), so it can't cycle with the ``cache → persistent_counters`` edge.
from email_triage.cache._redis import RedisFallbackBreaker, build_redis_client
from email_triage._int_utils import parse_int_or_none  # N-219c/10 R23
from email_triage.triage_logging import get_logger

log = get_logger("engine.persistent_counters")


_DEFAULT_KEY_PREFIX = "et:counters:"


class RedisCounterBackend:
    """Best-effort Redis-backed counter persistence.

    Lazy connection — the first ``incr`` / ``fetch`` opens the
    client. Every method is a no-op on Redis-side failure (logs at
    DEBUG; the process-local counter the caller already incremented
    stays accurate).
    """

    def __init__(
        self,
        url: str = "",
        key_prefix: str = _DEFAULT_KEY_PREFIX,
        *,
        breaker_ttl_secs: int = 60,
    ) -> None:
        self._url = (url or "").strip()
        self._prefix = key_prefix
        self._client: Any = None
        # run17  — the missing consumer now carries the SHARED fallback
        # breaker. After a Redis command fails the breaker opens for
        # ``breaker_ttl_secs`` and every subsequent incr/fetch/reset
        # short-circuits, so a dead Redis is no longer re-hammered (re-paying
        # the 2 s socket timeout) on every counter bump.
        self._breaker = RedisFallbackBreaker(ttl_secs=int(breaker_ttl_secs))

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._url:
            return None
        # run17  — build through the Redis-subsystem factory SSOT. An
        # ``ImportError`` (no optional ``cache`` extra) is a permanent process
        # condition — but a failed ``import redis`` re-runs the import finder
        # (a filesystem scan, NOT a cached dict lookup) on every call, so TRIP
        # the breaker to latch it into the TTL back-off window instead of
        # re-attempting per incr/fetch/reset (DA run17 ). A from_url build
        # error likewise trips so we don't re-attempt it every call.
        try:
            self._client = build_redis_client(self._url)
        except ImportError as exc:
            self._breaker.trip(f"import: {exc}")
            return None
        except Exception as exc:  # noqa: BLE001
            # ``log`` is a TriageLogger (msg-only; no printf args — style-guide
            # PD#10), so the dynamic value goes in an f-string, not a %s arg.
            log.debug(f"persistent counter backend init failed: {exc}")
            self._breaker.trip(f"init: {exc}")
            self._client = None
        return self._client

    def _key(self, namespace: str) -> str:
        return f"{self._prefix}{namespace}"

    def incr(self, namespace: str, field: str, by: int = 1) -> None:
        """``HINCRBY`` ``{prefix}{namespace} {field} {by}``.

        Silent on failure — the process-local counter the caller
        already incremented stays the live source of truth.
        """
        if not self.enabled or self._breaker.is_open():
            return
        client = self._get_client()
        if client is None:
            return
        try:
            client.hincrby(self._key(namespace), field, by)
        except Exception as exc:  # noqa: BLE001
            # TriageLogger is msg-only (PD#10) — f-string, not %s positional args.
            log.debug(
                f"persistent counter incr failed: {namespace}.{field} += {by} ({exc})"
            )
            # run17  — back off so a dead Redis isn't re-hammered (re-paying
            # the socket timeout) on every subsequent counter bump.
            self._breaker.trip(f"incr: {exc}")
            self._client = None

    def fetch(self, namespace: str) -> dict[str, int]:
        """``HGETALL`` returning ``{field: int}``. Empty on failure."""
        if not self.enabled or self._breaker.is_open():
            return {}
        client = self._get_client()
        if client is None:
            return {}
        try:
            raw = client.hgetall(self._key(namespace)) or {}
        except Exception as exc:  # noqa: BLE001
            log.debug(f"persistent counter fetch failed: {namespace} ({exc})")
            self._breaker.trip(f"fetch: {exc}")
            self._client = None
            return {}
        out: dict[str, int] = {}
        for k, v in raw.items():
            _iv = parse_int_or_none(v)  # N-219c/10 R23: SSOT
            if _iv is not None:
                out[str(k)] = _iv
        return out

    def reset(self, namespace: str) -> int:
        """Delete the namespace's HASH. Returns 1 on delete, 0 on miss
        or failure (best-effort; caller bumps a process-local "last
        reset" flag if they need to surface the action timestamp)."""
        if not self.enabled or self._breaker.is_open():
            return 0
        client = self._get_client()
        if client is None:
            return 0
        try:
            return int(client.delete(self._key(namespace)) or 0)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"persistent counter reset failed: {namespace} ({exc})")
            self._breaker.trip(f"reset: {exc}")
            self._client = None
            return 0

    def close(self) -> None:
        """Drop the Redis client. Idempotent."""
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Install-level singleton (mirrors the cache module pattern)
# ---------------------------------------------------------------------------

_install_counter_backend: RedisCounterBackend | None = None


def set_install_counter_backend(
    backend: RedisCounterBackend | None,
) -> None:
    """Replace the install-level backend. ``None`` disables
    persistence (process-local counters keep working)."""
    global _install_counter_backend
    _install_counter_backend = backend


def get_install_counter_backend() -> RedisCounterBackend | None:
    """Return the install-level backend, or None when no Redis is wired."""
    return _install_counter_backend


def build_counter_backend_from_config(
    redis_cache_cfg: Any,
) -> RedisCounterBackend | None:
    """Construct from the same RedisCacheConfig the cache uses.

    Operators get persistence "for free" by enabling the cache —
    no second URL field to manage. When the cache section is OFF
    (empty URL), persistence is OFF too; process-local counters
    keep working unchanged.
    """
    if redis_cache_cfg is None:
        return None
    url = (getattr(redis_cache_cfg, "url", "") or "").strip()
    if not url:
        return None
    return RedisCounterBackend(url=url)


__all__ = [
    "RedisCounterBackend",
    "set_install_counter_backend",
    "get_install_counter_backend",
    "build_counter_backend_from_config",
]
