"""Best-effort Redis-backed counter persistence (#2026-05-13).

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
    ) -> None:
        self._url = (url or "").strip()
        self._prefix = key_prefix
        self._client: Any = None

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._url:
            return None
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            self._client = redis.Redis.from_url(
                self._url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("persistent counter backend init failed: %s", exc)
            self._client = None
        return self._client

    def _key(self, namespace: str) -> str:
        return f"{self._prefix}{namespace}"

    def incr(self, namespace: str, field: str, by: int = 1) -> None:
        """``HINCRBY`` ``{prefix}{namespace} {field} {by}``.

        Silent on failure — the process-local counter the caller
        already incremented stays the live source of truth.
        """
        if not self.enabled:
            return
        client = self._get_client()
        if client is None:
            return
        try:
            client.hincrby(self._key(namespace), field, by)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "persistent counter incr failed: %s.%s += %d (%s)",
                namespace, field, by, exc,
            )

    def fetch(self, namespace: str) -> dict[str, int]:
        """``HGETALL`` returning ``{field: int}``. Empty on failure."""
        if not self.enabled:
            return {}
        client = self._get_client()
        if client is None:
            return {}
        try:
            raw = client.hgetall(self._key(namespace)) or {}
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "persistent counter fetch failed: %s (%s)",
                namespace, exc,
            )
            return {}
        out: dict[str, int] = {}
        for k, v in raw.items():
            try:
                out[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        return out

    def reset(self, namespace: str) -> int:
        """Delete the namespace's HASH. Returns 1 on delete, 0 on miss
        or failure (best-effort; caller bumps a process-local "last
        reset" flag if they need to surface the action timestamp)."""
        if not self.enabled:
            return 0
        client = self._get_client()
        if client is None:
            return 0
        try:
            return int(client.delete(self._key(namespace)) or 0)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "persistent counter reset failed: %s (%s)",
                namespace, exc,
            )
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
