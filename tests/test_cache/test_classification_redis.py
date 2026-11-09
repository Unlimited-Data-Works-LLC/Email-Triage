"""Real-Redis integration tests for ClassificationCache.store_inner.

``store_inner``'s LRU eviction runs as a server-side Lua ``EVAL`` so the
read-scan-evict-write is atomic and the O(N) field scan stays in-Redis.
The unit suite (``test_classification.py``) uses an in-process stub
that cannot run Lua — it exercises a Python re-implementation. This
file exercises the *real* script against a live Redis, which is the
only place the atomicity guarantee can actually be proven.

Guarded — skips cleanly unless the ``redis`` client lib is importable
AND a Redis answers at ``$EMAIL_TRIAGE_TEST_REDIS_URL``. A plain
``pytest tests/`` on a box without Redis skips this file entirely;
Redis is NOT a hard test dependency.

Run it::

    EMAIL_TRIAGE_TEST_REDIS_URL=redis://host:6379/15 \\
        pytest tests/test_cache/test_classification_redis.py

Point the URL at a throwaway DB index — the fixture flushes the
classification keyspace between tests.
"""

from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

_REDIS_URL = os.environ.get("EMAIL_TRIAGE_TEST_REDIS_URL", "")

pytestmark = pytest.mark.allow_outbound_network(
    reason="manual integration test: talks to the live Redis named by "
           "$EMAIL_TRIAGE_TEST_REDIS_URL, and skips when that is unset")


def _redis_or_skip():
    """Skip the test cleanly unless a usable Redis is reachable."""
    if not _REDIS_URL:
        pytest.skip("EMAIL_TRIAGE_TEST_REDIS_URL not set")
    # run17  — this reachability probe was the realised 4th fork of the
    # ``from_url`` params (``socket_timeout=5``, no connect-timeout / decode).
    # It now builds through the factory SSOT, passing the more-tolerant 5 s
    # probe timeout as an EXPLICIT override (the factory supplies the canonical
    # decode/connect-timeout params), so the param set can no longer drift here.
    from email_triage.cache._redis import build_redis_client
    try:
        client = build_redis_client(_REDIS_URL, socket_timeout=5)
        client.ping()
    except ImportError:
        pytest.skip("redis client library not installed")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at {_REDIS_URL}: {exc}")
    return client


@pytest.fixture
def cache():
    """A ClassificationCache pointed at the test Redis; flushed after."""
    _redis_or_skip()
    from email_triage.cache.classification import ClassificationCache
    c = ClassificationCache(url=_REDIS_URL)
    assert c.enabled
    yield c
    try:
        c.flush_all()
    except Exception:  # noqa: BLE001
        pass
    c.close()


def _entry(ts_iso: str, category: str = "fyi") -> dict:
    """A minimal cache value carrying the classified_at LRU key."""
    return {
        "category": category,
        "confidence": 0.5,
        "reason": "test",
        "classified_at": ts_iso,
        "model": "test-model",
    }


_BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ts(**delta) -> str:
    return (_BASE + timedelta(**delta)).isoformat()


def test_store_inner_writes_and_sets_ttl(cache):
    """The EVAL path writes the field and (re)sets the hash TTL."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cache.store_inner(key, "f1", _entry(_ts(minutes=0)), ttl_secs=1234, cap=250)
    client = cache._get_client()
    assert client.hexists(key, "f1")
    ttl = client.ttl(key)
    assert 0 < ttl <= 1234


def test_store_inner_evicts_oldest_at_cap(cache):
    """At cap, inserting a new field evicts the oldest by classified_at."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cap = 5
    for i in range(cap):
        cache.store_inner(key, f"f{i}", _entry(_ts(minutes=i)), cap=cap)
    client = cache._get_client()
    assert client.hlen(key) == cap

    cache.store_inner(key, "f-new", _entry(_ts(minutes=99)), cap=cap)

    assert client.hlen(key) == cap          # cap held
    assert not client.hexists(key, "f0")    # oldest evicted
    assert client.hexists(key, "f-new")     # new field stored
    assert client.hexists(key, "f4")        # a recent field survived


def test_store_inner_overwrite_at_cap_does_not_evict(cache):
    """Overwriting an existing field at cap must not evict anything —
    an overwrite doesn't grow the hash."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cap = 5
    for i in range(cap):
        cache.store_inner(key, f"f{i}", _entry(_ts(minutes=i)), cap=cap)
    client = cache._get_client()

    cache.store_inner(key, "f2", _entry(_ts(minutes=500)), cap=cap)

    assert client.hlen(key) == cap
    assert client.hexists(key, "f0")  # nothing evicted on an overwrite


def test_store_inner_cap_holds_under_concurrency(cache):
    """The eviction is atomic: N threads inserting distinct new fields
    into an at-cap hash leave it at exactly cap. The pre-#202
    non-atomic hlen/hgetall/hdel/hset path raced and overshot the cap.
    """
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cap = 20
    for i in range(cap):
        cache.store_inner(key, f"seed{i}", _entry(_ts(seconds=i)), cap=cap)
    client = cache._get_client()
    assert client.hlen(key) == cap

    n = 40
    barrier = threading.Barrier(n)
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            barrier.wait(timeout=10)
            cache.store_inner(
                key, f"c{idx}", _entry(_ts(minutes=idx + 1)), cap=cap,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not errors, f"worker errors: {errors}"
    # Exactly cap — the atomic EVAL kept every concurrent store from
    # racing the size check.
    assert client.hlen(key) == cap


# ---------------------------------------------------------------------------
# Companion {category:count} distribution hash
# ---------------------------------------------------------------------------

def test_dist_tracks_category_counts(cache):
    """The companion <key>:dist hash reflects the stored categories,
    and carries its own TTL."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    for i in range(5):
        cache.store_inner(
            key, f"r{i}", _entry(_ts(minutes=i), "to-respond"), cap=128,
        )
    for i in range(3):
        cache.store_inner(
            key, f"n{i}", _entry(_ts(minutes=20 + i), "newsletters"),
            cap=128,
        )
    assert cache.fetch_category_distribution(key) == {
        "to-respond": 5, "newsletters": 3,
    }
    client = cache._get_client()
    assert client.ttl(key + ":dist") > 0


def test_dist_decremented_on_eviction(cache):
    """Evicting the oldest field decrements that field's category in
    the dist hash."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cap = 3
    for i in range(cap):
        cache.store_inner(key, f"f{i}", _entry(_ts(minutes=i), "fyi"), cap=cap)
    assert cache.fetch_category_distribution(key) == {"fyi": 3}
    # New field, newer ts, different category — evicts the oldest 'fyi'.
    cache.store_inner(
        key, "n0", _entry(_ts(minutes=99), "newsletters"), cap=cap,
    )
    assert cache.fetch_category_distribution(key) == {
        "fyi": 2, "newsletters": 1,
    }


def test_dist_adjusted_on_category_changed_overwrite(cache):
    """Overwriting a field with a different category moves the count."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cache.store_inner(key, "f0", _entry(_ts(minutes=0), "fyi"), cap=128)
    assert cache.fetch_category_distribution(key) == {"fyi": 1}
    cache.store_inner(key, "f0", _entry(_ts(minutes=1), "newsletters"), cap=128)
    # fyi decremented to 0 (row dropped); newsletters added.
    assert cache.fetch_category_distribution(key) == {"newsletters": 1}


def test_dist_unchanged_on_same_category_overwrite(cache):
    """Overwriting a field with the same category leaves the dist alone."""
    key = f"et:cls:test:{uuid.uuid4().hex}"
    cache.store_inner(key, "f0", _entry(_ts(minutes=0), "fyi"), cap=128)
    cache.store_inner(key, "f0", _entry(_ts(minutes=5), "fyi"), cap=128)
    assert cache.fetch_category_distribution(key) == {"fyi": 1}
