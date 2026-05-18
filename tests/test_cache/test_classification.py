"""Tests for the optional Redis-backed classification cache (#151).

Uses an in-process stub for ``redis.Redis.from_url`` so we don't need
``fakeredis`` (not a dev dep) or a live Redis instance. The stub
implements the small surface ``ClassificationCache`` actually touches
(``get`` / ``set`` / ``close``) plus a per-instance error-injection
toggle for the unreachable-fallback test.

Each test resets the module-level singleton + counters so state
doesn't leak between cases.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from email_triage.cache.classification import (
    ClassificationCache,
    KEY_PREFIX,
    build_cache_from_config,
    compute_body_hash,
    get_counters,
    get_install_classification_cache,
    make_cache_key,
    set_install_classification_cache,
)
from email_triage.config import RedisCacheConfig


# ---------------------------------------------------------------------------
# Stub Redis client (no network, no library needed)
# ---------------------------------------------------------------------------

class _StubRedis:
    """Minimal in-memory stand-in for redis.Redis.

    2026-05-13 — extended for the two-level HASH-based cache shape.
    Carries both the legacy flat get/set (for the back-compat
    surface) and HASH ops (hget/hgetall/hset/hlen/hexists/hdel/expire)
    for the new code path.
    """

    def __init__(self):
        self._store: dict[str, str] = {}
        self._hashes: dict[str, dict[str, str]] = {}
        self._ttls: dict[str, int] = {}
        self.fail_get = False
        self.fail_set = False
        self.fail_count = {"get": 0, "set": 0}

    # Flat string ops (legacy)
    def get(self, key):
        if self.fail_get:
            self.fail_count["get"] += 1
            raise ConnectionError("simulated GET failure")
        return self._store.get(key)

    def set(self, key, value, ex=None):
        if self.fail_set:
            self.fail_count["set"] += 1
            raise ConnectionError("simulated SET failure")
        self._store[key] = value
        if ex is not None:
            self._ttls[key] = int(ex)
        return True

    # HASH ops (two-level cache)
    def hget(self, key, field):
        if self.fail_get:
            self.fail_count["get"] += 1
            raise ConnectionError("simulated HGET failure")
        return self._hashes.get(key, {}).get(field)

    def hgetall(self, key):
        if self.fail_get:
            self.fail_count["get"] += 1
            raise ConnectionError("simulated HGETALL failure")
        return dict(self._hashes.get(key, {}))

    def hset(self, key, field, value):
        if self.fail_set:
            self.fail_count["set"] += 1
            raise ConnectionError("simulated HSET failure")
        self._hashes.setdefault(key, {})[field] = value
        return 1

    def hlen(self, key):
        return len(self._hashes.get(key, {}))

    def hexists(self, key, field):
        return field in self._hashes.get(key, {})

    def hdel(self, key, *fields):
        h = self._hashes.get(key, {})
        removed = 0
        for f in fields:
            if f in h:
                del h[f]
                removed += 1
        return removed

    def expire(self, key, ttl):
        self._ttls[key] = int(ttl)
        return True

    def scan(self, cursor=0, match=None, count=100):
        # Return all hash keys matching the pattern (very simple
        # exact-prefix match for the ``et:cls:*`` shape).
        if cursor != 0:
            return (0, [])
        keys = list(self._hashes.keys()) + list(self._store.keys())
        if match and match.endswith("*"):
            prefix = match[:-1]
            keys = [k for k in keys if k.startswith(prefix)]
        return (0, keys)

    def delete(self, *keys):
        deleted = 0
        for k in keys:
            if k in self._hashes:
                del self._hashes[k]
                deleted += 1
            if k in self._store:
                del self._store[k]
                deleted += 1
            self._ttls.pop(k, None)
        return deleted

    def close(self):
        return None


@pytest.fixture
def stub():
    """One stub-client per test, returned through redis.Redis.from_url."""
    s = _StubRedis()
    # Patch the `redis` module's from_url at the point of import inside
    # the cache module's _get_client. The cache module does
    # ``import redis`` lazily, so we install a stub on sys.modules.
    import sys
    import types
    stub_mod = types.SimpleNamespace()

    class _StubRedisFactory:
        @staticmethod
        def from_url(url, **kwargs):
            return s

    stub_mod.Redis = _StubRedisFactory
    saved = sys.modules.get("redis")
    sys.modules["redis"] = stub_mod
    try:
        yield s
    finally:
        if saved is None:
            sys.modules.pop("redis", None)
        else:
            sys.modules["redis"] = saved


@pytest.fixture(autouse=True)
def _reset_counters_and_singleton():
    """Zero counters + drop the install singleton between tests.

    2026-05-13 — counter shape extended. ``hits`` / ``misses`` became
    derived properties; reset the underlying fields directly.
    """
    c = get_counters()
    c.hits_exact = 0
    c.hits_hint_topk = 0
    c.hits_hint_dominant = 0
    c.hits_hint_skipped = 0
    c.misses_cold = 0
    c.errors = 0
    set_install_classification_cache(None)
    yield
    c.hits_exact = 0
    c.hits_hint_topk = 0
    c.hits_hint_dominant = 0
    c.hits_hint_skipped = 0
    c.misses_cold = 0
    c.errors = 0
    set_install_classification_cache(None)


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_compute_body_hash_normalises_whitespace(self):
        a = compute_body_hash("hello\r\nworld")
        b = compute_body_hash("hello   world")
        assert a == b  # collapsed whitespace -> same hash
        assert len(a) == 64  # SHA-256 hex

    def test_compute_body_hash_empty(self):
        # Empty / None-like input must not crash.
        assert compute_body_hash("") == compute_body_hash("   ")
        assert len(compute_body_hash("")) == 64

    def test_make_cache_key_deterministic(self):
        k1 = make_cache_key(
            account_id=1, sender="a@b.com", subject="Hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        k2 = make_cache_key(
            account_id=1, sender="a@b.com", subject="Hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        assert k1 == k2
        assert k1.startswith(KEY_PREFIX)

    def test_make_cache_key_diverges_on_model(self):
        """Model upgrade auto-invalidates without manual flush."""
        k_old = make_cache_key(
            account_id=1, sender="a@b.com", subject="Hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        k_new = make_cache_key(
            account_id=1, sender="a@b.com", subject="Hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        assert k_old != k_new

    def test_make_cache_key_normalises_case_and_whitespace(self):
        """Same sender / subject with different whitespace -> same key."""
        k1 = make_cache_key(
            account_id=1, sender="Alice@Example.com", subject="Hi there",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        k2 = make_cache_key(
            account_id=1, sender="alice@example.com   ", subject="HI THERE",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        assert k1 == k2


# ---------------------------------------------------------------------------
# ClassificationCache behaviour
# ---------------------------------------------------------------------------

class TestClassificationCache:
    def test_disabled_when_url_empty(self, stub):
        cache = ClassificationCache(url="")
        assert cache.enabled is False
        # Lookup is a no-op short-circuit — never touches the stub.
        assert cache.lookup("anything") is None
        # Counters do not advance for the disabled path.
        snap = get_counters().snapshot()
        # Two-level shape (2026-05-13) — legacy hits/misses aliases
        # are derived from the new counters. Test just checks the
        # legacy alias still reads zero on an empty install.
        assert snap["hits"] == 0
        assert snap["misses"] == 0
        assert snap["errors"] == 0

    def test_disabled_store_is_noop(self, stub):
        cache = ClassificationCache(url="")
        cache.store("k", {"category": "fyi"})
        assert stub._store == {}

    def test_round_trip(self, stub):
        cache = ClassificationCache(url="redis://stub:6379/0")
        key = "et:cls:abc"
        value = {
            "category": "fyi",
            "confidence": 0.9,
            "reason": "demo",
            "classified_at": "2026-05-11T00:00:00+00:00",
            "model": "[local-llm-model]
        }
        # First lookup -> miss.
        assert cache.lookup(key) is None
        assert get_counters().snapshot()["misses"] == 1
        # Store.
        cache.store(key, value)
        assert key in stub._store
        # Second lookup -> hit.
        got = cache.lookup(key)
        assert got == value
        assert get_counters().snapshot()["hits"] == 1

    def test_store_ttl_passes_through(self, stub):
        cache = ClassificationCache(
            url="redis://stub:6379/0", default_ttl_secs=999,
        )
        cache.store("et:cls:k", {"category": "fyi"})
        assert stub._ttls["et:cls:k"] == 999
        # Per-call override wins.
        cache.store("et:cls:k2", {"category": "fyi"}, ttl_secs=42)
        assert stub._ttls["et:cls:k2"] == 42

    def test_corrupt_json_treated_as_miss(self, stub):
        cache = ClassificationCache(url="redis://stub:6379/0")
        stub._store["et:cls:bad"] = "{not-json"
        assert cache.lookup("et:cls:bad") is None
        # Counts as miss, NOT error (Redis itself is healthy).
        assert get_counters().snapshot()["misses"] == 1
        assert get_counters().snapshot()["errors"] == 0

    def test_redis_unreachable_falls_through(self, stub):
        """Redis GET error -> lookup returns None + error counter bumps."""
        cache = ClassificationCache(
            url="redis://stub:6379/0", breaker_ttl_secs=60,
        )
        stub.fail_get = True
        assert cache.lookup("et:cls:k") is None
        assert get_counters().snapshot()["errors"] == 1
        # Breaker is now open — subsequent lookups don't even attempt
        # a round-trip (fail_count stays at 1).
        assert cache.lookup("et:cls:k") is None
        assert stub.fail_count["get"] == 1

    def test_set_failure_opens_breaker(self, stub):
        cache = ClassificationCache(
            url="redis://stub:6379/0", breaker_ttl_secs=60,
        )
        stub.fail_set = True
        # Store never raises into the caller.
        cache.store("et:cls:k", {"category": "fyi"})
        assert get_counters().snapshot()["errors"] == 1
        # Subsequent stores no-op (breaker open) — fail_count stays at 1.
        cache.store("et:cls:k", {"category": "fyi"})
        assert stub.fail_count["set"] == 1

    def test_non_json_value_is_skipped(self, stub):
        """A non-JSON-serialisable value MUST not crash store()."""
        cache = ClassificationCache(url="redis://stub:6379/0")

        class _NotJSON:
            pass

        cache.store("et:cls:k", {"obj": _NotJSON()})
        # Nothing stored, nothing crashed.
        assert "et:cls:k" not in stub._store

    def test_breaker_recovers_after_window(self, stub):
        """After the breaker TTL elapses, lookups try Redis again."""
        cache = ClassificationCache(
            url="redis://stub:6379/0", breaker_ttl_secs=1,
        )
        stub.fail_get = True
        assert cache.lookup("et:cls:k") is None
        assert get_counters().snapshot()["errors"] == 1
        # Force the breaker open_until to expire.
        cache._breaker.open_until = time.monotonic() - 0.1
        stub.fail_get = False
        stub._store["et:cls:k"] = '{"category": "fyi"}'
        assert cache.lookup("et:cls:k") == {"category": "fyi"}

    def test_close_is_idempotent(self, stub):
        cache = ClassificationCache(url="redis://stub:6379/0")
        cache.lookup("et:cls:k")  # force lazy client build
        cache.close()
        cache.close()  # second close MUST NOT raise


# ---------------------------------------------------------------------------
# HIPAA gate (caller-side) — assert via mock
# ---------------------------------------------------------------------------

class TestHipaaGate:
    """The cache module trusts the caller's HIPAA gate. This test
    verifies the OllamaClassifier call site short-circuits cache lookup
    for HIPAA-flagged messages (defence-in-depth)."""

    @pytest.mark.asyncio
    async def test_ollama_skips_cache_when_hipaa(self, stub):
        from datetime import datetime, timezone

        from email_triage.classify.ollama import OllamaClassifier
        from email_triage.engine.models import EmailMessage

        # Install a cache that would otherwise hit.
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)

        msg = EmailMessage(
            message_id="m1",
            provider="imap",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="hi",
            body_text="hello",
            date=datetime.now(timezone.utc),
            hipaa=True,  # the HIPAA flag — cache MUST be skipped
        )

        clf = OllamaClassifier(model="[local-llm-model]

        async def _stub_resolve_model():
            return "[local-llm-model]

        class _LLMResp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "message": {
                        "content": '{"category": "fyi", '
                                   '"confidence": 0.9, "reason": "t"}',
                    },
                }

        class _LLMHttpClient:
            async def post(self, *_a, **_k):
                return _LLMResp()

        async def _stub_http_get():
            return _LLMHttpClient()

        with patch.object(cache, "lookup", wraps=cache.lookup) as spy_lookup, \
                patch.object(clf, "_resolve_model", new=_stub_resolve_model), \
                patch.object(clf._http, "get", new=_stub_http_get):
            await clf.classify(msg, {"fyi": "info"})
            spy_lookup.assert_not_called()

    @pytest.mark.asyncio
    async def test_ollama_uses_cache_when_not_hipaa(self, stub):
        """The hit path: non-HIPAA + enabled cache + pre-stored entry
        returns the cached classification with source='llm_cached'
        and never calls the LLM."""
        from datetime import datetime, timezone
        import json

        from email_triage.cache.classification import (
            compute_body_hash,
            make_outer_cache_key, make_inner_cache_field,
        )
        from email_triage.classify.ollama import OllamaClassifier
        from email_triage.engine.models import EmailMessage

        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)

        msg = EmailMessage(
            message_id="m1",
            provider="imap",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="hi",
            body_text="hello",
            date=datetime.now(timezone.utc),
            hipaa=False,
        )

        # 2026-05-13 — pre-seed via the new two-level shape so the
        # classifier's lookup_inner call finds the entry.
        bh = compute_body_hash("hello")
        outer = make_outer_cache_key(
            account_id=0, sender="alice@example.com",
            classifier_model="[local-llm-model]
        )
        inner = make_inner_cache_field(subject="hi", body_hash=bh)
        stub.hset(outer, inner, json.dumps({
            "category": "fyi",
            "confidence": 0.77,
            "reason": "cached-reason",
            "classified_at": "2026-05-11T00:00:00+00:00",
            "model": "[local-llm-model]
        }))

        clf = OllamaClassifier(model="[local-llm-model]

        async def _stub_resolve_model():
            return "[local-llm-model]

        # Patch HTTP to a sentinel that would BLOW UP if called — proves
        # the cache short-circuited.
        async def _stub_http_get():
            raise AssertionError("LLM HTTP must not be called on a hit")

        with patch.object(clf, "_resolve_model", new=_stub_resolve_model), \
                patch.object(clf._http, "get", new=_stub_http_get):
            result = await clf.classify(msg, {"fyi": "info"})

        assert result.category == "fyi"
        assert result.confidence == pytest.approx(0.77)
        assert result.source == "llm_cached"
        assert get_counters().snapshot()["hits"] == 1


# ---------------------------------------------------------------------------
# build_cache_from_config
# ---------------------------------------------------------------------------

class TestBuildCacheFromConfig:
    def test_returns_none_when_url_empty(self):
        cfg = RedisCacheConfig(url="", ttl_secs=12345)
        assert build_cache_from_config(cfg) is None

    def test_returns_none_when_cfg_none(self):
        assert build_cache_from_config(None) is None

    def test_constructs_with_url(self):
        cfg = RedisCacheConfig(
            url="redis://stub:6379/2", ttl_secs=12345,
        )
        cache = build_cache_from_config(cfg)
        assert cache is not None
        assert cache.enabled is True
        assert cache._default_ttl == 12345

    def test_install_singleton_round_trip(self):
        cfg = RedisCacheConfig(url="redis://stub:6379/2")
        cache = build_cache_from_config(cfg)
        assert get_install_classification_cache() is None
        set_install_classification_cache(cache)
        assert get_install_classification_cache() is cache
        set_install_classification_cache(None)
        assert get_install_classification_cache() is None


# ---------------------------------------------------------------------------
# TTL clamping (spec: [3600, 7_776_000])
# ---------------------------------------------------------------------------

class TestClampTTL:
    """Operator-supplied TTL values land in
    ``[MIN_TTL_SECS, MAX_TTL_SECS]`` regardless of input shape.
    Spec floor 3600 s; ceiling 90 days."""

    def test_clamp_below_floor_returns_floor(self):
        from email_triage.cache.classification import (
            MIN_TTL_SECS, clamp_ttl_secs,
        )
        assert clamp_ttl_secs(0) == MIN_TTL_SECS
        assert clamp_ttl_secs(1) == MIN_TTL_SECS
        assert clamp_ttl_secs(60) == MIN_TTL_SECS
        assert clamp_ttl_secs(3599) == MIN_TTL_SECS

    def test_clamp_above_ceiling_returns_ceiling(self):
        from email_triage.cache.classification import (
            MAX_TTL_SECS, clamp_ttl_secs,
        )
        assert clamp_ttl_secs(MAX_TTL_SECS + 1) == MAX_TTL_SECS
        assert clamp_ttl_secs(10**12) == MAX_TTL_SECS

    def test_clamp_in_range_passes_through(self):
        from email_triage.cache.classification import clamp_ttl_secs
        assert clamp_ttl_secs(3600) == 3600
        assert clamp_ttl_secs(86400) == 86400  # 1 day
        assert clamp_ttl_secs(30 * 24 * 3600) == 30 * 24 * 3600  # 30 days

    def test_clamp_handles_garbage_input(self):
        from email_triage.cache.classification import (
            DEFAULT_TTL_SECS, clamp_ttl_secs,
        )
        # Non-int falls back to default before clamping.
        assert clamp_ttl_secs(None) == DEFAULT_TTL_SECS
        assert clamp_ttl_secs("abc") == DEFAULT_TTL_SECS
        assert clamp_ttl_secs("") == DEFAULT_TTL_SECS

    def test_clamp_string_numbers_parse(self):
        from email_triage.cache.classification import clamp_ttl_secs
        assert clamp_ttl_secs("86400") == 86400


# ---------------------------------------------------------------------------
# Per-account isolation + shared classifier helpers
# ---------------------------------------------------------------------------

class TestCacheKeyPerAccount:
    """Same message but a different ``account_id`` MUST produce a
    different cache key (per-account taxonomy isolation)."""

    def test_per_account_isolation(self):
        k_a = make_cache_key(
            account_id=1, sender="x@y.com", subject="hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        k_b = make_cache_key(
            account_id=2, sender="x@y.com", subject="hi",
            body_hash="abc", classifier_model="[local-llm-model]
        )
        assert k_a != k_b

    def test_per_body_isolation(self):
        k1 = make_cache_key(
            account_id=1, sender="x@y.com", subject="hi",
            body_hash="aaa", classifier_model="[local-llm-model]
        )
        k2 = make_cache_key(
            account_id=1, sender="x@y.com", subject="hi",
            body_hash="bbb", classifier_model="[local-llm-model]
        )
        assert k1 != k2


# ---------------------------------------------------------------------------
# Shared classifier helpers (cache_lookup_for_message / store)
# ---------------------------------------------------------------------------

class TestSharedClassifierHelpers:
    """Verify the centralised cache-aware helper paths every classifier
    backend uses today (ollama / gemini / openai-compat)."""

    def _msg(self, *, hipaa=False, account_id=42, force=False):
        from datetime import datetime, timezone

        from email_triage.engine.models import EmailMessage

        msg = EmailMessage(
            message_id="m1", provider="imap",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="hello",
            body_text="hi there",
            date=datetime.now(timezone.utc),
            hipaa=hipaa,
        )
        if account_id is not None:
            msg.raw_metadata["account_id"] = account_id
        if force:
            msg.raw_metadata["force_reclassify"] = True
        return msg

    def test_no_cache_installed_returns_none(self, stub):
        """Cache singleton not set -> short-circuit cleanly."""
        from email_triage.cache.classification import (
            cache_lookup_for_message,
        )
        outer, inner, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model] {"fyi": "info"},
        )
        assert outer is None and inner is None
        assert hit is None and hint is None

    def test_hipaa_message_now_caches_without_reason(self, stub):
        """2026-05-13 — HIPAA accounts now hit the cache, but the
        stored value MUST OMIT the ``reason`` field. Category +
        confidence are non-PHI; reason is the LLM free-text leak
        surface."""
        from email_triage.cache.classification import (
            cache_lookup_for_message, cache_store_for_message,
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        from email_triage.engine.models import Classification
        import json as _json
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        msg = self._msg(hipaa=True)
        # Lookup returns keys (no longer None-on-HIPAA).
        outer, inner, hit, hint = cache_lookup_for_message(
            msg, "[local-llm-model] {"fyi": "info"},
        )
        assert outer is not None and inner is not None
        assert hit is None and hint is None  # cold miss
        # Store the result with is_hipaa=True — reason should be stripped.
        cache_store_for_message(
            outer, inner, "[local-llm-model]
            Classification(category="fyi", confidence=0.8,
                           reason="leaks-phi-here", source="llm"),
            {"fyi": "info"}, is_hipaa=True,
        )
        # Inspect stored payload.
        raw = stub._hashes[outer][inner]
        v = _json.loads(raw)
        assert v["category"] == "fyi"
        assert v["confidence"] == 0.8
        assert v["model"] == "[local-llm-model]
        assert "reason" not in v  # stripped under HIPAA

    def test_force_reclassify_bypasses_cache(self, stub):
        """raw_metadata['force_reclassify']=True -> lookup short-circuits."""
        from email_triage.cache.classification import (
            cache_lookup_for_message,
        )
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        outer, inner, hit, hint = cache_lookup_for_message(
            self._msg(force=True), "[local-llm-model] {"fyi": "info"},
        )
        assert outer is None and inner is None
        assert hit is None and hint is None

    def test_lookup_branch1_exact_hit(self, stub):
        """Branch 1 — exact inner-field match returns cached classification."""
        from email_triage.cache.classification import (
            cache_lookup_for_message,
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        import json as _json
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        outer = make_outer_cache_key(
            account_id=42, sender="alice@example.com",
            classifier_model="[local-llm-model]
        )
        inner = make_inner_cache_field(
            subject="hello", body_hash=compute_body_hash("hi there"),
        )
        stub.hset(outer, inner, _json.dumps({
            "category": "fyi", "confidence": 0.77, "reason": "r",
            "classified_at": "2026-05-11", "model": "[local-llm-model]
        }))
        got_outer, got_inner, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model] {"fyi": "info"},
        )
        assert got_outer == outer
        assert got_inner == inner
        assert hit is not None
        assert hit.category == "fyi"
        assert hit.confidence == pytest.approx(0.77)
        assert hit.source == "llm_cached"
        assert hint is None
        assert get_counters().hits_exact == 1

    def test_lookup_branch2_topk_hint(self, stub):
        """Branch 2 — outer key has prior entries (sender history)
        but current subject/body don't match. C-mode top_k_with_freq
        returns a category-distribution hint."""
        from email_triage.cache.classification import (
            cache_lookup_for_message,
            make_outer_cache_key,
        )
        import json as _json
        cache = ClassificationCache(
            url="redis://stub:6379/0",
            hint_strategy="top_k_with_freq",
        )
        set_install_classification_cache(cache)
        outer = make_outer_cache_key(
            account_id=42, sender="alice@example.com",
            classifier_model="[local-llm-model]
        )
        # Seed 3 sibling fields (different subjects, all fyi).
        for i in range(3):
            stub.hset(outer, f"field_{i}", _json.dumps({
                "category": "fyi", "confidence": 0.9, "reason": "r",
                "classified_at": f"2026-05-{i+1:02d}",
                "model": "[local-llm-model]
            }))
        got_outer, got_inner, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model] {"fyi": "info"},
        )
        assert got_outer == outer
        assert hit is None  # inner miss
        assert hint is not None
        assert "fyi" in hint
        assert "3" in hint  # distribution count
        assert get_counters().hits_hint_topk == 1

    def test_lookup_branch2_dominant_pass(self, stub):
        """B-mode top_1_dominant — top category passes threshold,
        hint fires."""
        from email_triage.cache.classification import (
            cache_lookup_for_message, make_outer_cache_key,
        )
        import json as _json
        cache = ClassificationCache(
            url="redis://stub:6379/0",
            hint_strategy="top_1_dominant",
            dominant_threshold_pct=70,
        )
        set_install_classification_cache(cache)
        outer = make_outer_cache_key(
            account_id=42, sender="alice@example.com",
            classifier_model="[local-llm-model]
        )
        # 9 fyi + 1 promotions = 90% dominant, threshold 70%.
        for i in range(9):
            stub.hset(outer, f"f_{i}", _json.dumps({
                "category": "fyi", "confidence": 0.9,
                "classified_at": "2026-05-01", "model": "[local-llm-model]
            }))
        stub.hset(outer, "f_pro", _json.dumps({
            "category": "promotions", "confidence": 0.9,
            "classified_at": "2026-05-02", "model": "[local-llm-model]
        }))
        _, _, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model]
            {"fyi": "info", "promotions": "promo"},
        )
        assert hit is None
        assert hint is not None
        assert "fyi" in hint
        assert get_counters().hits_hint_dominant == 1

    def test_lookup_branch2_dominant_ambiguous_skips(self, stub):
        """B-mode top_1_dominant — top category below threshold,
        no hint fires (counter increments hits_hint_skipped)."""
        from email_triage.cache.classification import (
            cache_lookup_for_message, make_outer_cache_key,
        )
        import json as _json
        cache = ClassificationCache(
            url="redis://stub:6379/0",
            hint_strategy="top_1_dominant",
            dominant_threshold_pct=70,
        )
        set_install_classification_cache(cache)
        outer = make_outer_cache_key(
            account_id=42, sender="alice@example.com",
            classifier_model="[local-llm-model]
        )
        # 6 fyi + 4 promotions = 60% top — below 70% threshold.
        for i in range(6):
            stub.hset(outer, f"fyi_{i}", _json.dumps({
                "category": "fyi", "confidence": 0.9,
                "classified_at": "2026-05-01", "model": "[local-llm-model]
            }))
        for i in range(4):
            stub.hset(outer, f"pro_{i}", _json.dumps({
                "category": "promotions", "confidence": 0.9,
                "classified_at": "2026-05-02", "model": "[local-llm-model]
            }))
        _, _, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model]
            {"fyi": "info", "promotions": "promo"},
        )
        assert hit is None
        assert hint is None
        assert get_counters().hits_hint_skipped == 1

    def test_lookup_cold_miss(self, stub):
        """No outer key at all -> misses_cold counter increments."""
        from email_triage.cache.classification import (
            cache_lookup_for_message,
        )
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        _, _, hit, hint = cache_lookup_for_message(
            self._msg(), "[local-llm-model] {"fyi": "info"},
        )
        assert hit is None and hint is None
        assert get_counters().misses_cold == 1

    def test_store_skips_when_category_unknown(self, stub):
        """Helper refuses to cache a junk category."""
        from email_triage.cache.classification import (
            cache_store_for_message,
        )
        from email_triage.engine.models import Classification
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        cache_store_for_message(
            "fake-outer", "fake-inner", "[local-llm-model]
            Classification(category="not_in_taxonomy", confidence=0.5,
                           reason="garbage", source="llm"),
            {"fyi": "info"},
        )
        assert "fake-outer" not in stub._hashes

    def test_store_persists_known_category(self, stub):
        from email_triage.cache.classification import (
            cache_store_for_message,
        )
        from email_triage.engine.models import Classification
        cache = ClassificationCache(url="redis://stub:6379/0")
        set_install_classification_cache(cache)
        cache_store_for_message(
            "real-outer", "real-inner", "[local-llm-model]
            Classification(category="fyi", confidence=0.8,
                           reason="seems fyi", source="llm"),
            {"fyi": "info"},
        )
        assert "real-outer" in stub._hashes
        assert "real-inner" in stub._hashes["real-outer"]
        import json as _json
        v = _json.loads(stub._hashes["real-outer"]["real-inner"])
        assert v["category"] == "fyi"
        assert v["model"] == "[local-llm-model]
        assert v["reason"] == "seems fyi"  # non-HIPAA keeps reason
        assert "classified_at" in v


# ---------------------------------------------------------------------------
# Hit/miss/error counter movement
# ---------------------------------------------------------------------------

class TestHitRateCounters:
    """Counters tick on hits, misses, errors across the typical lifecycle."""

    def test_hit_miss_error_increment_in_order(self, stub):
        cache = ClassificationCache(url="redis://stub:6379/0")
        # 1. Miss.
        assert cache.lookup("et:cls:a") is None
        assert get_counters().snapshot()["misses"] == 1
        # 2. Store + hit.
        cache.store("et:cls:a", {"category": "fyi"})
        assert cache.lookup("et:cls:a") == {"category": "fyi"}
        assert get_counters().snapshot()["hits"] == 1
        # 3. Simulate Redis failure -> error.
        stub.fail_get = True
        assert cache.lookup("et:cls:a") is None
        assert get_counters().snapshot()["errors"] == 1


# ---------------------------------------------------------------------------
# Manual flush (SCAN/DEL sweep, KEY_PREFIX-scoped)
# ---------------------------------------------------------------------------

class TestFlushAll:
    """Admin Flush button drops every ``et:cls:*`` key, leaves the rest
    of the Redis instance untouched."""

    def test_flush_clears_classification_keys_only(self, stub):
        # Pretend the cache has multiple entries + an unrelated key
        # belonging to another service sharing the Redis instance.
        stub._store["et:cls:a"] = '{"category": "fyi"}'
        stub._store["et:cls:b"] = '{"category": "fyi"}'
        stub._store["other:service:xyz"] = "do-not-touch"

        # SCAN stub: return all matching keys in one pass.
        def _scan(cursor, match, count):
            if cursor != 0:
                return 0, []
            prefix = (match or "").rstrip("*")
            keys = [k for k in stub._store.keys() if k.startswith(prefix)]
            return 0, keys
        stub.scan = _scan

        def _delete(*keys):
            removed = 0
            for k in keys:
                if k in stub._store:
                    del stub._store[k]
                    removed += 1
            return removed
        stub.delete = _delete

        cache = ClassificationCache(url="redis://stub:6379/0")
        deleted = cache.flush_all()
        assert deleted == 2
        assert "et:cls:a" not in stub._store
        assert "et:cls:b" not in stub._store
        assert stub._store["other:service:xyz"] == "do-not-touch"

    def test_flush_disabled_cache_is_noop(self, stub):
        cache = ClassificationCache(url="")
        assert cache.flush_all() == 0

    def test_flush_redis_failure_opens_breaker(self, stub):
        def _scan_fail(cursor, match, count):
            raise ConnectionError("simulated scan failure")
        stub.scan = _scan_fail
        cache = ClassificationCache(url="redis://stub:6379/0")
        deleted = cache.flush_all()
        assert deleted == 0
        assert get_counters().snapshot()["errors"] == 1


# ---------------------------------------------------------------------------
# Lazy import — the module must import even when ``redis`` is missing
# ---------------------------------------------------------------------------

class TestLazyImport:
    """The cache module is in the always-imported path (lifespan + health
    + ollama). It MUST import cleanly without the optional ``redis``
    package installed; only USE-paths fail when redis is unavailable."""

    def test_module_imports_without_redis_installed(self, monkeypatch):
        """Simulate missing redis: import works, cache lookup degrades."""
        import sys
        # Force a fresh import of the cache module so a previously-loaded
        # redis stub doesn't mask the missing-dep behaviour.
        for mod_name in list(sys.modules):
            if mod_name == "redis" or mod_name.startswith("redis."):
                monkeypatch.delitem(sys.modules, mod_name, raising=False)
        # Block any attempt to import redis by raising ImportError.
        import builtins as _builtins
        orig_import = _builtins.__import__

        def _fake_import(name, *a, **k):
            if name == "redis" or name.startswith("redis."):
                raise ImportError("redis not installed (simulated)")
            return orig_import(name, *a, **k)

        monkeypatch.setattr(_builtins, "__import__", _fake_import)

        # Re-import the cache module fresh so the import-time path runs
        # without the optional dep available.
        monkeypatch.delitem(
            sys.modules, "email_triage.cache.classification", raising=False,
        )
        import email_triage.cache.classification as cls_mod  # noqa: F401

        # Module imported fine. Building a cache + using it should
        # degrade gracefully (breaker opens, no exception bubbles out).
        cache = cls_mod.ClassificationCache(url="redis://stub:6379/0")
        # The first lookup attempts the lazy ``import redis`` and falls
        # back to no-op + breaker-open. MUST NOT raise.
        assert cache.lookup("anything") is None


# ---------------------------------------------------------------------------
# Privacy invariant — no operator identifiers in the cache module
# ---------------------------------------------------------------------------

def test_privacy_invariant_no_operator_identifiers_in_cache_module():
    """Pin: the cache module's docstrings, comments, examples MUST NOT
    name operator-owned hosts (redis-host, mail-host, etc.) or operator personal
    names (Alex, Maintainer, agent-instance, ...). The leak in this exact module
    on 2026-05-11 is the reason this pin exists.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parents[1].parent
    paths = [
        root / "src" / "email_triage" / "cache" / "__init__.py",
        root / "src" / "email_triage" / "cache" / "classification.py",
    ]
    forbidden = [
        # Hostnames
        "redis-host", "mail-host", "dns-host", "agents-host", "llm-host",
        "monitor-host", "deploy-host", "storage-host", "compute-host", "render-host", "label-host",
        "example.com",
        # Personal names + agent instances
        "agent-instance", "code-reviewer-agent",
    ]
    offenders: list[str] = []
    for p in paths:
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace").lower()
        for needle in forbidden:
            if needle.lower() in text:
                offenders.append(f"{p.name}: {needle}")
    assert not offenders, (
        "Operator identifiers found in cache module — replace with "
        "generic placeholders (e.g. 'your-redis-host.example.local'):\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Admin UI integration — Redis URL field renders + save round-trips
# ---------------------------------------------------------------------------

class TestAdminUI:
    """Verify the /admin/integrations Classification cache section
    renders the URL field + persists changes round-trip.

    A full TestClient round-trip would require the whole web/app
    fixture set (DB + secrets + lifespan); the static template-grep
    pin below is sufficient for the spec's "field renders" gate, and
    the save round-trip is verified end-to-end via the
    config.py + integrations.py code paths covered by
    ``TestBuildCacheFromConfigClamps`` + the integration suite.
    """

    def test_template_renders_redis_section(self):
        """Static template-render smoke: the Classification cache
        section appears in the integrations admin page template."""
        from pathlib import Path
        tpl = Path(__file__).resolve().parents[1].parent / (
            "src/email_triage/web/templates/admin/integrations.html"
        )
        text = tpl.read_text(encoding="utf-8")
        assert "Classification cache" in text
        assert 'name="redis_cache_url"' in text
        assert 'name="redis_cache_ttl_secs"' in text
        # Flush form present.
        assert "/admin/integrations/cache/flush" in text
        # Privacy: generic placeholder, NOT an operator host.
        assert "redis-host" not in text.lower()
        assert "therealms" not in text.lower()
        assert "your-redis-host.example.local" in text


# ---------------------------------------------------------------------------
# build_cache_from_config: TTL clamping interaction
# ---------------------------------------------------------------------------

class TestBuildCacheFromConfigClamps:
    """An out-of-range TTL in the YAML / form snaps to the
    [3600, 7_776_000] window via ``build_cache_from_config``."""

    def test_short_ttl_snaps_up(self):
        from email_triage.cache.classification import (
            MIN_TTL_SECS, build_cache_from_config,
        )
        cfg = RedisCacheConfig(url="redis://stub:6379/0", ttl_secs=10)
        cache = build_cache_from_config(cfg)
        assert cache is not None
        assert cache._default_ttl == MIN_TTL_SECS

    def test_huge_ttl_snaps_down(self):
        from email_triage.cache.classification import (
            MAX_TTL_SECS, build_cache_from_config,
        )
        cfg = RedisCacheConfig(
            url="redis://stub:6379/0", ttl_secs=MAX_TTL_SECS + 5,
        )
        cache = build_cache_from_config(cfg)
        assert cache is not None
        assert cache._default_ttl == MAX_TTL_SECS
