"""In-memory token-bucket rate limiter for the OpenClaw API.

Single-instance only — when we scale horizontally this becomes a
Redis-backed bucket. The bucket interface stays the same.

Each API key gets its own bucket sized to ``rate_per_min`` tokens with
a refill rate of ``rate_per_min / 60`` tokens/second. ``rate_per_min=0``
disables the limiter (useful for local dev and tests).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import HTTPException, Request


# #145.1 — eviction window for idle buckets. A bucket whose key has
# not been seen for this many seconds AND has refilled to capacity is
# safe to drop; the next ``allow`` for that key reconstructs it at
# full capacity, so eviction is observably equivalent to "never seen".
# One hour balances: long enough that a normal traffic ebb (lunch,
# overnight) doesn't churn entries, short enough that a rotating-IP
# attack can't pin unbounded RAM.
_IDLE_EVICT_SECS = 3600.0


class TokenBucket:
    """Per-key token bucket. Thread-safe via an asyncio Lock."""

    def __init__(self, rate_per_min: int = 60):
        self._rate = rate_per_min
        self._capacity = rate_per_min
        self._refill_per_sec = rate_per_min / 60.0 if rate_per_min > 0 else 0.0
        self._buckets: dict[Any, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    @property
    def disabled(self) -> bool:
        return self._rate <= 0

    async def allow(self, key: Any) -> tuple[bool, float]:
        """Take one token from ``key``'s bucket.

        Returns ``(allowed, retry_after_seconds)``. ``retry_after`` is
        only meaningful when ``allowed`` is False.
        """
        if self.disabled:
            return True, 0.0

        async with self._lock:
            now = time.monotonic()
            tokens, last = self._buckets.get(key, (float(self._capacity), now))
            # Refill since last access.
            tokens = min(
                float(self._capacity),
                tokens + (now - last) * self._refill_per_sec,
            )
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                # #145.1 — opportunistic GC of idle buckets. Each
                # ``allow`` call makes one cheap pass over the dict
                # to evict entries that are simultaneously (a) at
                # full capacity (so the eviction is observably
                # equivalent to never-seen) and (b) have not been
                # touched for ``_IDLE_EVICT_SECS``. Without this,
                # every distinct key (typically a remote IP) leaves a
                # permanent footprint and memory grows unbounded.
                self._evict_idle(now)
                return True, 0.0
            # Compute wait time until one token is available.
            deficit = 1.0 - tokens
            retry = deficit / self._refill_per_sec if self._refill_per_sec > 0 else 60.0
            self._buckets[key] = (tokens, now)
            return False, retry

    def _evict_idle(self, now: float) -> None:
        """Drop buckets that are at capacity AND idle for >1 h.

        Called from ``allow`` under the lock, so no extra synchronisation.
        Materialises the eviction list before mutating to keep the
        iteration safe across Python versions. Capacity floor uses a
        small epsilon below ``_capacity`` so floating-point drift in
        the refill formula doesn't pin a bucket that's effectively
        full.
        """
        if not self._buckets:
            return
        capacity = float(self._capacity)
        cutoff = now - _IDLE_EVICT_SECS
        to_drop = [
            k for k, (tokens, last) in self._buckets.items()
            if last < cutoff and tokens >= capacity - 1e-6
        ]
        for k in to_drop:
            self._buckets.pop(k, None)

    def reset(self, key: Any | None = None) -> None:
        """Test helper: clear one or all buckets."""
        if key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(key, None)


def get_rate_limiter(request: Request) -> TokenBucket:
    """Return the process-wide rate limiter, creating it on first use."""
    bucket = getattr(request.app.state, "openclaw_rate_limit", None)
    if bucket is None:
        config = getattr(request.app.state, "config", None)
        rate = 60
        if config is not None:
            rate = getattr(config.push, "openclaw_rate_limit_per_minute", 60)
        bucket = TokenBucket(rate_per_min=rate)
        request.app.state.openclaw_rate_limit = bucket
    return bucket


async def enforce_rate_limit(request: Request, key: Any) -> None:
    """Raise 429 if ``key`` is over its quota."""
    bucket = get_rate_limiter(request)
    allowed, retry = await bucket.allow(key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="rate_limited",
            headers={"Retry-After": str(max(1, int(retry)))},
        )
