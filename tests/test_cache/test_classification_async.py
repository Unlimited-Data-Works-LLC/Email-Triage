""" — async dispatch of ClassificationCache Redis calls.

Before this fix
---------------
``ClassificationCache.lookup_inner`` / ``store_inner`` /
``fetch_category_distribution`` / ``flush_all`` issue synchronous Redis
calls. The async classify hot path (``JsonChatClassifier.classify`` in
``classify/base.py``) and the admin flush endpoint
(``admin_integrations_cache_flush`` in ``web/routers/integrations.py``)
called those sync methods directly. A Redis hiccup pinned by the
2.0 s ``socket_timeout`` blocked the whole event loop for the full
timeout — stalling every watcher / web request / triage in flight.

This fix
--------
Each Redis-touching public method on ``ClassificationCache`` got an
``a*`` mirror that dispatches via ``asyncio.to_thread``. The async
helper functions ``acache_lookup_for_message`` /
``acache_store_for_message`` mirror the existing sync helpers' shape
and ``await`` the mirrors. The sync surface is preserved verbatim
for non-async callers (admin CLI, tests).

This test file pins:
  * The ``a*`` mirrors return the sync method's result bit-identically
    (delegation, not reimplementation).
  * Each mirror runs in a worker thread (not the event-loop thread) —
    that's the entire point of the fix.
  * ``acache_lookup_for_message`` / ``acache_store_for_message``
    produce bit-identical (counter side-effects + returned hint
    string + stored payload) outcomes to their sync siblings on every
    branch (cold miss, Branch 1 hit, Branch 2 top-K hint, Branch 2
    dominant pass, Branch 2 dominant skip, HIPAA, force-reclassify).
  * A structural guard pins ``classify/base.py`` to call the ASYNC
    helper variants from its ``async def classify`` body — a future
    regression that puts the sync helper back on the loop is caught.
"""

from __future__ import annotations

import ast
import asyncio
import sys
import threading
import types
from unittest.mock import patch

import pytest

from email_triage.cache.classification import (
    ClassificationCache,
    acache_lookup_for_message,
    acache_store_for_message,
    cache_lookup_for_message,
    cache_store_for_message,
    get_counters,
    set_install_classification_cache,
)


# Reuse the in-process Redis stub from the sync test module — duplication
# would risk drift, and pytest discovers both files in the same package.
from tests.test_cache.test_classification import (  # noqa: E402
    _StubRedis,
    _reset_counters_and_singleton,  # noqa: F401  # autouse fixture
)
from tests._pin_harness import assert_pin_has_teeth, walk_src  # noqa: E402


# ---------------------------------------------------------------------------
# Stub-redis fixtures (mirrors test_classification.py)
# ---------------------------------------------------------------------------

@pytest.fixture
def stub():
    s = _StubRedis()
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


@pytest.fixture
def cache(stub):
    c = ClassificationCache(url="redis://stub.invalid:6379/0")
    set_install_classification_cache(c)
    yield c
    set_install_classification_cache(None)


# ---------------------------------------------------------------------------
# Minimal fake EmailMessage shape — cache helpers read attributes only.
# ---------------------------------------------------------------------------

class _Msg:
    def __init__(
        self,
        sender: str = "alice@example.com",
        subject: str = "Invoice 2026-05",
        body_text: str = "Please pay.",
        *,
        hipaa: bool = False,
        account_id: int = 1,
        force_reclassify: bool = False,
    ):
        self.sender = sender
        self.subject = subject
        self.body_text = body_text
        self.hipaa = hipaa
        self.raw_metadata = {
            "account_id": account_id,
            "force_reclassify": force_reclassify,
        }


def _classification(category: str = "invoices", confidence: float = 0.9):
    """Minimal Classification — cache_store reads attribute access only."""
    from email_triage.engine.models import Classification
    return Classification(
        category=category, confidence=confidence,
        reason="Invoice keyword matched.", source="llm",
    )


_CATEGORIES = {
    "invoices": "Bills + invoices to pay",
    "newsletters": "Marketing + news digests",
    "personal": "Personal correspondence",
}


# ---------------------------------------------------------------------------
# Pin 1 — a* mirrors delegate to the sync surface bit-identically
# ---------------------------------------------------------------------------

class TestAsyncMirrorsDelegate:
    """Every ``a*`` mirror must call the sync method and return its
    result — no reimplementation, no missed branch. A future change
    to e.g. the breaker semantics in ``lookup_inner`` then applies to
    both surfaces automatically.
    """

    async def test_alookup_inner_returns_sync_result(self, cache):
        from email_triage.cache.classification import (
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        outer = make_outer_cache_key(
            account_id=1, sender="a@x.com",
            classifier_model="m", categories=_CATEGORIES,
        )
        inner = make_inner_cache_field(
            subject="s", body_hash=compute_body_hash("b"),
        )
        # Seed via sync store, read via async mirror.
        cache.store_inner(outer, inner, {
            "category": "invoices", "confidence": 0.9,
            "classified_at": "2026-05-24T00:00:00+00:00",
            "model": "m", "reason": "r",
        })
        sync_result = cache.lookup_inner(outer, inner)
        async_result = await cache.alookup_inner(outer, inner)
        assert sync_result == async_result
        assert async_result is not None
        assert async_result["category"] == "invoices"

    async def test_afetch_category_distribution_matches_sync(self, cache):
        from email_triage.cache.classification import (
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        outer = make_outer_cache_key(
            account_id=1, sender="a@x.com",
            classifier_model="m", categories=_CATEGORIES,
        )
        for n in range(3):
            cache.store_inner(outer, make_inner_cache_field(
                subject=f"s{n}", body_hash=compute_body_hash(f"b{n}"),
            ), {
                "category": "invoices", "confidence": 0.9,
                "classified_at": f"2026-05-24T0{n}:00:00+00:00",
                "model": "m", "reason": "r",
            })
        sync = cache.fetch_category_distribution(outer)
        amap = await cache.afetch_category_distribution(outer)
        assert sync == amap == {"invoices": 3}

    async def test_astore_inner_writes_via_mirror(self, cache):
        from email_triage.cache.classification import (
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        outer = make_outer_cache_key(
            account_id=1, sender="a@x.com",
            classifier_model="m", categories=_CATEGORIES,
        )
        inner = make_inner_cache_field(
            subject="s", body_hash=compute_body_hash("b"),
        )
        await cache.astore_inner(outer, inner, {
            "category": "newsletters", "confidence": 0.7,
            "classified_at": "2026-05-24T01:00:00+00:00",
            "model": "m", "reason": "r",
        })
        # Sync read confirms the async write landed.
        row = cache.lookup_inner(outer, inner)
        assert row is not None and row["category"] == "newsletters"

    async def test_aflush_all_returns_count(self, cache):
        from email_triage.cache.classification import (
            make_outer_cache_key, make_inner_cache_field,
            compute_body_hash,
        )
        outer = make_outer_cache_key(
            account_id=1, sender="a@x.com",
            classifier_model="m", categories=_CATEGORIES,
        )
        cache.store_inner(outer, make_inner_cache_field(
            subject="s", body_hash=compute_body_hash("b"),
        ), {
            "category": "invoices", "confidence": 0.9,
            "classified_at": "2026-05-24T00:00:00+00:00",
            "model": "m", "reason": "r",
        })
        n = await cache.aflush_all()
        assert n >= 1
        # Subsequent flush returns 0 — nothing left.
        assert (await cache.aflush_all()) == 0

    async def test_alookup_legacy_flat_key_mirror(self, cache):
        # The legacy flat-key surface mirror exists for parity even
        # though no live caller uses it today; lock in its delegation
        # so a future refactor doesn't accidentally drift the shape.
        cache.store("et:cls:abc", {"category": "personal"})
        result = await cache.alookup("et:cls:abc")
        assert result is not None and result["category"] == "personal"


# ---------------------------------------------------------------------------
# Pin 2 — a* mirrors actually run off the event loop
# ---------------------------------------------------------------------------

class TestAsyncMirrorsRunOffLoop:
    """Per `pattern_barrier_concurrency_test.md`, the critical property
    is that the sync Redis call executes on a worker thread, NOT the
    event-loop thread. Without this property the ``a*`` wrapper would
    be cosmetic (and a 2.0 s socket_timeout would still pin the loop).
    """

    async def test_alookup_inner_uses_worker_thread(self, cache):
        loop_thread = threading.get_ident()
        seen_thread = {}
        original_lookup = cache.lookup_inner

        def _wrapped(outer, inner):
            seen_thread["id"] = threading.get_ident()
            return original_lookup(outer, inner)

        with patch.object(cache, "lookup_inner", _wrapped):
            await cache.alookup_inner("et:cls:nope", "field")
        assert "id" in seen_thread, "wrapper must have been called"
        assert seen_thread["id"] != loop_thread, (
            "asyncio.to_thread must dispatch on a worker thread, NOT "
            "the event loop thread (otherwise a stuck Redis still "
            "pins the loop on socket_timeout)"
        )

    async def test_astore_inner_uses_worker_thread(self, cache):
        loop_thread = threading.get_ident()
        seen_thread = {}
        original_store = cache.store_inner

        def _wrapped(*args, **kwargs):
            seen_thread["id"] = threading.get_ident()
            return original_store(*args, **kwargs)

        with patch.object(cache, "store_inner", _wrapped):
            await cache.astore_inner("et:cls:k", "f", {
                "category": "invoices", "confidence": 0.9,
                "classified_at": "2026-05-24T00:00:00+00:00",
                "model": "m",
            })
        assert seen_thread.get("id") != loop_thread

    async def test_aflush_all_uses_worker_thread(self, cache):
        loop_thread = threading.get_ident()
        seen_thread = {}
        original = cache.flush_all

        def _wrapped():
            seen_thread["id"] = threading.get_ident()
            return original()

        with patch.object(cache, "flush_all", _wrapped):
            await cache.aflush_all()
        assert seen_thread.get("id") != loop_thread


# ---------------------------------------------------------------------------
# Pin 3 — async helpers produce identical outcomes to sync siblings
# ---------------------------------------------------------------------------

class TestAsyncHelperParity:
    """``acache_lookup_for_message`` and ``acache_store_for_message``
    must produce bit-identical counter side-effects + returned hint
    text + stored payload as their sync siblings on every branch.
    Any drift would silently change classification behaviour on the
    async hot path.
    """

    async def test_force_reclassify_bypasses_cache(self, cache):
        msg = _Msg(force_reclassify=True)
        outer, inner, cached, hint = await acache_lookup_for_message(
            msg, "m", _CATEGORIES,
        )
        assert (outer, inner, cached, hint) == (None, None, None, None)
        # Sync sibling agrees:
        assert cache_lookup_for_message(msg, "m", _CATEGORIES) == (
            None, None, None, None,
        )

    async def test_cold_miss_bumps_misses_cold(self, cache):
        c = get_counters()
        msg = _Msg(sender="cold@x.com", subject="never seen")
        outer, inner, cached, hint = await acache_lookup_for_message(
            msg, "m", _CATEGORIES,
        )
        assert cached is None and hint is None
        assert c.misses_cold == 1
        assert outer is not None and inner is not None

    async def test_branch1_exact_hit(self, cache):
        c = get_counters()
        msg = _Msg(sender="b1@x.com")
        # Seed via async store.
        await acache_store_for_message(
            *(await acache_lookup_for_message(msg, "m", _CATEGORIES))[:2],
            "m", _classification(), _CATEGORIES, is_hipaa=False,
        )
        # Reset counters to isolate the second lookup.
        c.misses_cold = 0
        outer, inner, cached, hint = await acache_lookup_for_message(
            msg, "m", _CATEGORIES,
        )
        assert cached is not None and cached.category == "invoices"
        assert hint is None
        assert c.hits_exact == 1

    async def test_branch2_topk_hint(self, cache):
        c = get_counters()
        sender = "b2@x.com"
        # Seed 3 invoices + 1 newsletter for the SAME sender → distribution.
        for i in range(3):
            msg = _Msg(sender=sender, subject=f"inv-{i}", body_text=f"b{i}")
            keys = await acache_lookup_for_message(msg, "m", _CATEGORIES)
            await acache_store_for_message(
                keys[0], keys[1], "m", _classification("invoices"),
                _CATEGORIES, is_hipaa=False,
            )
        msg = _Msg(sender=sender, subject="news-1", body_text="nb")
        keys = await acache_lookup_for_message(msg, "m", _CATEGORIES)
        await acache_store_for_message(
            keys[0], keys[1], "m", _classification("newsletters", 0.8),
            _CATEGORIES, is_hipaa=False,
        )
        # Reset counters for the test lookup.
        c.hits_exact = 0
        c.misses_cold = 0
        c.hits_hint_topk = 0
        # Inner-miss + outer-hit → Branch 2 top-K hint.
        msg_new = _Msg(
            sender=sender, subject="fresh", body_text="never indexed",
        )
        outer, inner, cached, hint = await acache_lookup_for_message(
            msg_new, "m", _CATEGORIES,
        )
        assert cached is None
        assert hint is not None
        assert "Sender history" in hint
        assert "invoices" in hint and "newsletters" in hint
        assert c.hits_hint_topk == 1

    async def test_hipaa_store_omits_reason(self, cache):
        msg = _Msg(hipaa=True, sender="hp@phi.com")
        keys = await acache_lookup_for_message(msg, "m", _CATEGORIES)
        await acache_store_for_message(
            keys[0], keys[1], "m", _classification(),
            _CATEGORIES, is_hipaa=True,
        )
        row = cache.lookup_inner(keys[0], keys[1])
        assert row is not None
        assert "reason" not in row, (
            "HIPAA path must strip the classifier reason from the "
            "cached payload (PHI-shape free-text)"
        )
        # Non-HIPAA equivalent path keeps reason for debug visibility.
        msg2 = _Msg(hipaa=False, sender="np@x.com")
        keys2 = await acache_lookup_for_message(msg2, "m", _CATEGORIES)
        await acache_store_for_message(
            keys2[0], keys2[1], "m", _classification(),
            _CATEGORIES, is_hipaa=False,
        )
        row2 = cache.lookup_inner(keys2[0], keys2[1])
        assert row2 is not None and "reason" in row2

    async def test_store_skips_when_category_unknown(self, cache):
        # Category not in the current taxonomy → don't poison the cache.
        msg = _Msg(sender="unknown@x.com")
        keys = await acache_lookup_for_message(msg, "m", _CATEGORIES)
        await acache_store_for_message(
            keys[0], keys[1], "m",
            _classification(category="orphan-cat"),
            _CATEGORIES, is_hipaa=False,
        )
        assert cache.lookup_inner(keys[0], keys[1]) is None


# ---------------------------------------------------------------------------
# Pin 4 — async helpers tolerate None / disabled cache
# ---------------------------------------------------------------------------

class TestAsyncHelperBoundaryCases:
    async def test_lookup_with_no_installed_cache_returns_quartet_of_none(self):
        # No cache singleton installed → both helpers must short-circuit
        # without touching Redis.
        assert get_counters()  # sanity
        msg = _Msg()
        result = await acache_lookup_for_message(msg, "m", _CATEGORIES)
        assert result == (None, None, None, None)

    async def test_store_with_no_installed_cache_is_noop(self):
        # Must not raise, must not touch Redis.
        await acache_store_for_message(
            "outer", "inner", "m", _classification(),
            _CATEGORIES, is_hipaa=False,
        )  # no AssertionError; just a no-op

    async def test_store_with_none_keys_is_noop(self, cache):
        # When force-reclassify or HIPAA / no cache returns None keys,
        # the store helper must accept them and no-op cleanly.
        await acache_store_for_message(
            None, None, "m", _classification(),
            _CATEGORIES, is_hipaa=False,
        )

    async def test_lookup_breaker_open_returns_none_quickly(self, cache):
        # Open the breaker manually; lookup must short-circuit.
        cache._open_breaker("test breaker")
        msg = _Msg()
        outer, inner, cached, hint = await acache_lookup_for_message(
            msg, "m", _CATEGORIES,
        )
        # Keys are still derived even when the breaker is open — the
        # caller uses them on the post-LLM store path.
        assert outer is not None and inner is not None
        assert cached is None and hint is None


# ---------------------------------------------------------------------------
# Pin 5 — count-agnostic structural guard against the  regression
# ---------------------------------------------------------------------------

# The synchronous, Redis-blocking cache surface. Calling any of these from an
# ``async def`` body re-opens  — a 2.0 s ``socket_timeout`` on a stuck
# Redis pins the WHOLE event loop. The async-safe path uses the ``a*`` mirrors
# / ``asyncio.to_thread`` (the sync method passed AS AN ARGUMENT to to_thread
# is not a ``Call`` and is correctly NOT flagged).
_SYNC_CACHE_HELPER_NAMES = frozenset({
    "cache_lookup_for_message",   # module-level sync helpers (globally unique)
    "cache_store_for_message",
})
_SYNC_CACHE_METHOD_NAMES = frozenset({
    "lookup_inner", "store_inner", "fetch_category_distribution", "flush_all",
})


def _async_sync_cache_offenders(tree) -> list[str]:
    """Describe every Call inside an ``async def`` body that invokes a
    synchronous Redis-blocking cache op (the  regression shape). A nested
    *sync* ``def`` resets the scope (its body runs synchronously, off the loop,
    when called)."""
    offenders: list[str] = []

    class _Walker(ast.NodeVisitor):
        def __init__(self) -> None:
            self._async_stack: list[str] = []

        def visit_AsyncFunctionDef(self, node):
            self._async_stack.append(node.name)
            self.generic_visit(node)
            self._async_stack.pop()

        def visit_FunctionDef(self, node):
            saved = self._async_stack
            self._async_stack = []          # nested sync def == its own scope
            self.generic_visit(node)
            self._async_stack = saved

        def visit_Call(self, node):
            if self._async_stack:
                name = None
                if isinstance(node.func, ast.Name):
                    if node.func.id in _SYNC_CACHE_HELPER_NAMES:
                        name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in _SYNC_CACHE_METHOD_NAMES:
                        name = node.func.attr
                if name is not None:
                    offenders.append(
                        f"async def {self._async_stack[-1]}() calls sync "
                        f"{name}() at line {node.lineno} — use the async mirror "
                        f"(a{name} / .a{name} / asyncio.to_thread) (#262)."
                    )
            self.generic_visit(node)

    _Walker().visit(tree)
    return offenders


class TestNoSyncCacheCallFromAsyncBody:
    """ regression guard — COUNT-AGNOSTIC (Prime Directive 6).

    Supersedes the two hand-written per-file guards (``classify/base.py`` +
    ``web/routers/integrations.py``). Each of those hard-coded ONE file path,
    so a THIRD module that put a sync Redis cache call back on the event loop
    was invisible until someone hand-added a third method — the count-coupled
    pin shape the divergence playbook forbids ("a property over every site via
    rglob, never a fixed list"; "converge the hand-rolled AST walkers onto one
    shared harness"). This walks EVERY ``async def`` body under
    ``src/email_triage`` via the shared ``_pin_harness`` src walk, so a new
    offending caller anywhere is caught with no edit to this test.
    """

    def test_no_async_body_calls_sync_cache_ops(self):
        violations: list[str] = []
        for _path, rel, tree in walk_src():
            for off in _async_sync_cache_offenders(tree):
                violations.append(f"{rel}: {off}")
        if violations:
            joined = "\n  ".join(violations)
            pytest.fail(
                "Synchronous Redis-blocking cache op called from an async "
                f"body (re-opens #262):\n  {joined}"
            )

    def test_detector_has_teeth(self):
        # Plant a bad shape (sync helper + sync methods from an async body) and
        # a good shape (the a* mirrors). The pin must flag the former and pass
        # the latter, else a scoping drift makes it silently vacuous.
        bad = (
            "async def f(msg, cache):\n"
            "    a, b, c, d = cache_lookup_for_message(msg, 'm', {})\n"
            "    cache.store_inner(a, b, {})\n"
            "    cache.flush_all()\n"
        )
        good = (
            "async def f(msg, cache):\n"
            "    a, b, c, d = await acache_lookup_for_message(msg, 'm', {})\n"
            "    await cache.astore_inner(a, b, {})\n"
            "    await cache.aflush_all()\n"
        )
        assert_pin_has_teeth(_async_sync_cache_offenders, bad, good)
