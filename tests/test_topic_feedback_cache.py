""" v3 — the OPTIONAL Redis mirror for Topic feedback signals.

Operator-confirmed 2026-06-12: "if it's available I want to use it, but do not
want to *Require* it." These pin the contract:

  * DISABLED (empty URL) — every accessor is a safe no-op / None; the feature
    works entirely on the DB.
  * USE-IF-PRESENT — a configured mirror round-trips the {sender: vote} map.
  * FAIL-OPEN — an unreachable Redis NEVER raises; it degrades (breaker opens)
    and the caller falls back to the DB.
"""

from __future__ import annotations

import pytest

from email_triage.cache.topic_feedback import (
    TopicFeedbackCache,
    build_feedback_cache_from_config,
    get_install_topic_feedback_cache,
    invalidate_topic_feedback_cache,
    set_install_topic_feedback_cache,
)


class _FakeRedis:
    def __init__(self):
        self.store: dict = {}
    def get(self, k):
        return self.store.get(k)
    def set(self, k, v, ex=None):
        self.store[k] = v
    def delete(self, k):
        self.store.pop(k, None)


class _BrokenRedis:
    def get(self, k):
        raise ConnectionError("unreachable")
    def set(self, k, v, ex=None):
        raise ConnectionError("unreachable")
    def delete(self, k):
        raise ConnectionError("unreachable")


class TestNeverRequired:
    def test_empty_url_disables_everything_no_raise(self):
        c = TopicFeedbackCache(url="")
        assert c.enabled is False
        assert c.get_signals(1) is None      # caller reads the DB
        c.put_signals(1, {"a@b.com": -1})    # no-op, no raise
        c.invalidate(1)                       # no-op, no raise

    def test_build_from_config_none_when_no_url(self):
        assert build_feedback_cache_from_config(None) is None

        class _Cfg:
            url = ""
        assert build_feedback_cache_from_config(_Cfg()) is None

        class _Cfg2:
            url = "redis://localhost:6379/0"
        c = build_feedback_cache_from_config(_Cfg2())
        assert c is not None and c.enabled is True

    def test_install_singleton_defaults_disabled(self):
        # The global helper is None unless app.py opts in.
        prev = get_install_topic_feedback_cache()
        try:
            set_install_topic_feedback_cache(None)
            assert get_install_topic_feedback_cache() is None
            # invalidate is a safe no-op when disabled.
            invalidate_topic_feedback_cache(5)
        finally:
            set_install_topic_feedback_cache(prev)


class TestUseIfPresent:
    def test_roundtrip_and_invalidate(self):
        c = TopicFeedbackCache(url="redis://x")
        c._client = _FakeRedis()              # inject a working fake
        c.put_signals(7, {"fred@x.com": -1, "ben@y.com": 1})
        assert c.get_signals(7) == {"fred@x.com": -1, "ben@y.com": 1}
        c.invalidate(7)
        assert c.get_signals(7) is None       # miss after invalidate → DB

    def test_corrupt_value_is_a_miss(self):
        c = TopicFeedbackCache(url="redis://x")
        fake = _FakeRedis()
        fake.store["et:topicfb:7"] = "{not json"
        c._client = fake
        assert c.get_signals(7) is None       # corrupt → miss, DB authoritative


class TestFailOpen:
    def test_unreachable_never_raises_and_opens_breaker(self):
        c = TopicFeedbackCache(url="redis://x")
        c._client = _BrokenRedis()
        assert c.get_signals(7) is None       # degrade, no raise
        assert c._breaker_open() is True      # breaker tripped on the error
        # Further calls short-circuit on the open breaker (still no raise).
        c.put_signals(7, {"a@b.com": -1})
        c.invalidate(7)

    async def test_async_mirrors_degrade_too(self):
        c = TopicFeedbackCache(url="redis://x")
        c._client = _BrokenRedis()
        assert await c.aget_signals(7) is None
        await c.aput_signals(7, {"a@b.com": -1})
        await c.ainvalidate(7)
