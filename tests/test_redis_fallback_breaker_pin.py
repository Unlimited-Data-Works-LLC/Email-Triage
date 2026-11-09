"""Pin for the Redis fallback-breaker SSOT + its TTL-recovery intent (run17  + ).

 — De-duplication. The fallback circuit-breaker for the optional Redis
consumers was TWO byte-identical ``_BreakerState`` copies (``cache/classification.py``
+ ``cache/topic_feedback.py``), and a THIRD consumer (``engine/persistent_counters.py``)
had NO breaker at all — so a dead Redis re-paid the full 2 s socket timeout on every
counter bump, with no backoff. The breaker is now ONE class,
``email_triage.cache._redis.RedisFallbackBreaker``, composed by all three consumers.

The structural pin is a PROPERTY over EVERY ``*.py`` under ``src/email_triage``
(not ``len == 1``): every "breaker-state" class — fingerprinted STRUCTURALLY by a
class-level ``open_until`` field (the monotonic deadline that DEFINES the breaker),
so a renamed clone is still caught — MUST live in the SSOT module ``cache/_redis.py``.
A runtime check then proves all three consumers COMPOSE that one class (the
persistent-counters consumer being the run17  payoff: it had none before).

 — Pin the intent (DECISION: pin, do not add a clear-on-success edge). The census
flagged that the Redis breaker, unlike funneled siblings (``auth_stale`` /
``failing_since``), has NO ``clear`` wired to a success edge — recovery rides the
TTL only. This is DELIBERATE and structurally correct, not a gap: while the breaker
is OPEN every Redis-touching method short-circuits to its safe fallback WITHOUT a
round-trip, so there is NO in-window success edge to clear from (you can never have
a success while open because you never call Redis while open). A clear-on-success
hook would be dead code. Recovery is therefore bounded by the SHORT (60 s default)
TTL and self-heals: the first call after the deadline retries — succeed → stays
closed, fail → re-trips. These tests LOCK that contract so the absence-of-clear is
documented, not silent.
"""
from __future__ import annotations

import ast
import time

from _pin_harness import parse_module, parse_source, relpath, walk_src

from email_triage.cache._redis import RedisFallbackBreaker

# The SRC-relative path of the ONE module allowed to DEFINE a breaker-state class.
_SSOT = "cache/_redis.py"


def _breaker_state_classes(tree: ast.AST) -> list[str]:
    """Names of ClassDefs carrying the breaker-state fingerprint: a class-level
    ``open_until`` field (annotated or plain assignment). STRUCTURAL, not by
    name — a re-rolled ``class _Fuse: open_until = 0.0`` is caught just as the old
    ``_BreakerState`` was. (``llm_health._UnhealthyEntry`` uses
    ``unhealthy_since/until``, a different shape, so it is correctly NOT matched —
    that sibling breaker is deliberately separate.)"""
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            names: list[str] = []
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                names = [stmt.target.id]
            elif isinstance(stmt, ast.Assign):
                names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            if "open_until" in names:
                out.append(node.name)
                break
    return out


def _breaker_state_class_sites() -> dict[str, list[str]]:
    """SRC-relative path -> [classname, ...] for every breaker-state class def."""
    out: dict[str, list[str]] = {}
    for _path, rel, tree in walk_src():
        names = _breaker_state_classes(tree)
        if names:
            out[rel] = names
    return out


# ---  — single breaker-state class def ----------------------------------

def test_single_breaker_state_class_lives_in_ssot():
    """Every breaker-state class (``open_until`` fingerprint) lives in the SSOT
    module — no duplicate ``_BreakerState`` re-fork in a consumer."""
    sites = _breaker_state_class_sites()
    offenders = {rel: names for rel, names in sites.items() if rel != _SSOT}
    assert not offenders, (
        "Breaker-state class(es) defined outside the Redis-breaker SSOT "
        f"({_SSOT}): {offenders}. The fallback circuit-breaker is ONE class — "
        "email_triage.cache._redis.RedisFallbackBreaker. Compose it (a "
        "``self._breaker = RedisFallbackBreaker(ttl_secs=…)`` field); do not "
        "re-roll a local ``_BreakerState`` (the two copies WILL drift)."
    )
    # Non-vacuity: the SSOT really defines exactly the one breaker-state class.
    assert sites.get(_SSOT) == ["RedisFallbackBreaker"], (
        f"{_SSOT} must define exactly the RedisFallbackBreaker breaker-state "
        f"class; found {sites.get(_SSOT)!r}. The pin would be vacuous otherwise."
    )


def test_all_three_consumers_compose_the_shared_breaker():
    """The run17  payoff: all THREE optional Redis consumers — including the
    previously breaker-LESS persistent-counter backend — now hold the ONE shared
    ``RedisFallbackBreaker`` (composed, not a local re-roll)."""
    from email_triage.cache.classification import ClassificationCache
    from email_triage.cache.topic_feedback import TopicFeedbackCache
    from email_triage.engine.persistent_counters import RedisCounterBackend

    for ctor in (
        lambda: ClassificationCache(url="redis://x.invalid"),
        lambda: TopicFeedbackCache(url="redis://x.invalid"),
        lambda: RedisCounterBackend(url="redis://x.invalid"),
    ):
        consumer = ctor()
        assert isinstance(consumer._breaker, RedisFallbackBreaker), (
            f"{type(consumer).__name__} does not compose the shared "
            "RedisFallbackBreaker — it must, so the breaker policy lives in ONE place."
        )


def test_dedup_pin_has_teeth():
    """A planted duplicate / renamed-clone breaker-state class IS detected;
    a class without the fingerprint is NOT."""
    dup = parse_source(
        "from dataclasses import dataclass\n"
        "@dataclass\nclass _BreakerState:\n    open_until: float = 0.0\n    last_reason: str = ''\n"
    )
    assert _breaker_state_classes(dup) == ["_BreakerState"]
    # Renamed clone still carrying open_until (structural, not name-based) is caught.
    clone = parse_source("class _Fuse:\n    open_until = 0.0\n")
    assert _breaker_state_classes(clone) == ["_Fuse"]
    # The llm_health sibling shape (unhealthy_since/until, no open_until) is NOT matched.
    sibling = parse_source(
        "from dataclasses import dataclass\n@dataclass\nclass _UnhealthyEntry:\n"
        "    unhealthy_since: float = 0.0\n    unhealthy_until: float = 0.0\n"
    )
    assert _breaker_state_classes(sibling) == []
    # A plain class is clean.
    assert _breaker_state_classes(parse_source("class Foo:\n    x = 1\n")) == []


# --- behaviour preservation (de-dup must not re-policy the breaker) ---------

def test_breaker_trip_and_is_open_policy_preserved():
    """``trip`` opens for exactly ``ttl_secs`` monotonic seconds; ``is_open`` is
    True only while the deadline is in the future; the reason is stored truncated
    to 200 chars — the exact policy de-duplicated from the two ``_BreakerState``
    copies."""
    b = RedisFallbackBreaker(ttl_secs=60)
    assert b.is_open() is False                    # starts closed
    before = time.monotonic()
    b.trip("redis unreachable")
    assert b.is_open() is True                      # open after a trip
    assert b.last_reason == "redis unreachable"
    assert before + 60 <= b.open_until <= time.monotonic() + 60
    # Reason is truncated to 200 chars (the [:200] from the old copies).
    b.trip("x" * 500)
    assert len(b.last_reason) == 200


# ---  — TTL-only recovery is deliberate (pin the intent) -----------------

def test_recovery_is_ttl_only_no_explicit_clear():
    """Recovery rides the TTL alone — ``is_open`` transitions True→False purely by
    the monotonic clock, with NO explicit clear/reset call. This documents the
    deliberate asymmetry vs the funneled ``clear_unhealthy`` siblings (run17 )."""
    b = RedisFallbackBreaker(ttl_secs=0.05)
    b.trip("transient blip")
    assert b.is_open() is True
    time.sleep(0.06)
    assert b.is_open() is False                     # self-healed by TTL, nothing cleared it


def test_open_breaker_short_circuits_all_redis_io():
    """WHY no clear-on-success is needed: while the breaker is open, every
    Redis-touching cache method short-circuits to its fallback WITHOUT touching
    the client — so there is no in-window success edge to clear from."""
    from email_triage.cache.classification import ClassificationCache

    class _Boom:
        def __getattr__(self, _name):
            raise AssertionError("Redis client touched while breaker is open")

    c = ClassificationCache(url="redis://x.invalid", breaker_ttl_secs=60)
    c._client = _Boom()
    c._breaker.trip("simulated outage")
    assert c._breaker.is_open()
    # Each path returns its safe fallback without a single client attribute access.
    assert c.lookup("k") is None
    assert c.lookup_inner("outer", "inner") is None
    assert c.fetch_category_distribution("outer") == {}


def test_persistent_counters_back_off_not_hammer():
    """run17  payoff, locked: after a Redis command fails, the persistent-
    counter backend trips its breaker and subsequent bumps short-circuit — it no
    longer re-pays the socket timeout on every call (the no-breaker behaviour)."""
    from email_triage.engine.persistent_counters import RedisCounterBackend

    calls = {"n": 0}

    class _DeadRedis:
        def hincrby(self, *a, **k):
            calls["n"] += 1
            raise ConnectionError("redis down")

    be = RedisCounterBackend(url="redis://x.invalid", breaker_ttl_secs=60)
    be._client = _DeadRedis()
    be.incr("ns", "f")                  # first bump hits Redis, fails -> trips breaker
    assert calls["n"] == 1
    assert be._breaker.is_open()
    be.incr("ns", "f")                  # subsequent bumps short-circuit — no re-hammer
    be.incr("ns", "f")
    assert calls["n"] == 1              # still 1: backed off, not re-paying the timeout
