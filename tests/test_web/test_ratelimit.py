"""Tests for the in-memory token-bucket rate limiter."""

import asyncio

import pytest

from email_triage.web.ratelimit import TokenBucket


async def test_allows_up_to_capacity_then_blocks():
    bucket = TokenBucket(rate_per_min=3)
    # 3 requests should pass, 4th blocks.
    for _ in range(3):
        ok, _ = await bucket.allow("k")
        assert ok
    ok, retry = await bucket.allow("k")
    assert not ok
    assert retry > 0


async def test_per_key_isolation():
    bucket = TokenBucket(rate_per_min=2)
    for _ in range(2):
        assert (await bucket.allow("a"))[0]
    # "a" should be empty now, but "b" still has its full bucket.
    blocked, _ = await bucket.allow("a")
    assert not blocked
    for _ in range(2):
        assert (await bucket.allow("b"))[0]


async def test_disabled_always_allows():
    bucket = TokenBucket(rate_per_min=0)
    for _ in range(50):
        ok, _ = await bucket.allow("k")
        assert ok


async def test_refills_over_time():
    # 60/min = 1 token per second. Sleeping 1s should give us another.
    bucket = TokenBucket(rate_per_min=60)
    for _ in range(60):
        await bucket.allow("k")
    blocked, _ = await bucket.allow("k")
    assert not blocked
    await asyncio.sleep(1.05)
    ok, _ = await bucket.allow("k")
    assert ok


# ---------------------------------------------------------------------------
# #145.1 — idle-bucket eviction
# ---------------------------------------------------------------------------


async def test_idle_bucket_evicted_after_two_hours(monkeypatch):
    """A bucket that has refilled to capacity AND not been touched
    for the eviction window (>1 h) must be dropped on the next
    ``allow`` call. Without eviction, every distinct key (typically
    a remote IP) leaves a permanent footprint."""
    bucket = TokenBucket(rate_per_min=60)

    # Seed a real entry for "old_ip" via a normal allow.
    ok, _ = await bucket.allow("old_ip")
    assert ok
    assert "old_ip" in bucket._buckets

    # Backdate "old_ip" by 2 hours AND restore tokens to capacity to
    # simulate "fully refilled but idle". The eviction predicate
    # requires both conditions — half-full idle buckets stay so
    # we don't lose retry-after state from a still-cooling-off bucket.
    import time as _time
    bucket._buckets["old_ip"] = (
        float(bucket._capacity),
        _time.monotonic() - 7200,
    )

    # Trigger eviction by hitting any other key (eviction runs as
    # part of every successful allow under the lock).
    ok, _ = await bucket.allow("fresh_ip")
    assert ok
    assert "old_ip" not in bucket._buckets, (
        "idle bucket at capacity should have been evicted"
    )
    assert "fresh_ip" in bucket._buckets


async def test_eviction_does_not_drop_active_buckets():
    """A bucket that is recently active (or below capacity) must
    NOT be evicted even when other ``allow`` calls run the eviction
    pass."""
    bucket = TokenBucket(rate_per_min=10)

    # Drain "throttled_ip" so its tokens are below capacity. Eviction
    # must NOT drop it — the bucket carries throttle state we still
    # owe to the next request from that key.
    for _ in range(10):
        await bucket.allow("throttled_ip")
    blocked, _ = await bucket.allow("throttled_ip")
    assert not blocked

    # Many calls from another key — each runs the eviction pass.
    for _ in range(20):
        await bucket.allow("active_ip")

    # Throttled bucket survives even though it's old, because it's
    # below capacity (the eviction predicate requires capacity-full).
    assert "throttled_ip" in bucket._buckets


async def test_eviction_does_not_drop_recently_full_buckets():
    """A bucket that is full AND recently seen must NOT be evicted."""
    bucket = TokenBucket(rate_per_min=60)

    # Seed both keys with a recent allow.
    await bucket.allow("recent")
    await bucket.allow("other")

    # Trigger eviction passes.
    for _ in range(5):
        await bucket.allow("other")

    assert "recent" in bucket._buckets, (
        "recently-touched bucket must not be evicted"
    )
