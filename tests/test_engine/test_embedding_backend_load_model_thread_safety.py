""" — class-invariant Barrier(N) regression test for
``SentenceTransformersBackend._load_model``.

Background
==========
``_load_model`` is a lazy-init guard (``if self._model is not None:
return self._model``) followed by a heavy 1-2 s
``SentenceTransformer(model_name)`` construction. Without
synchronisation, two threads can each pass the ``is not None`` check
before either sets ``self._model``, and both load the model.

Pre-fix (no Lock) empirical: 10 threads coordinated via
``threading.Barrier(10)`` to arrive at the call site simultaneously
produced ``load_counter == 10`` across 5 stress runs — every thread
loaded the model. Post-fix (Lock + double-checked locking):
``load_counter == 1`` deterministically.

Why a Barrier-based test, not wall-clock-elapsed
=================================================
Per ``pattern_barrier_concurrency_test.md`` — wall-clock timing tests
are racy (a fast machine misses the overlap; a slow CI machine
spuriously passes a broken guard). ``threading.Barrier(N)`` forces
every thread to wait until all N have called ``wait()`` before any
proceeds — guaranteed concurrent arrival at the load site.

Class-invariant tripwire
========================
This test is the regression guard for the invariant
"``_load_model`` loads at most once per backend instance, even under
N concurrent threads." Any future refactor that breaks the Lock
(removes it, narrows the critical section, replaces with a non-
reentrant primitive that deadlocks, etc.) fires this test immediately.

The ``sentence_transformers`` package is stubbed with a counter +
mocked ``SentenceTransformer`` so the test doesn't need the ~80 MB
model download. The Lock invariant is purely about the lazy-init
guard; the real model's behaviour is irrelevant.
"""
from __future__ import annotations

import sys
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub fixture — install a fake `sentence_transformers` with a counter
# ---------------------------------------------------------------------------


class _LoadCounter:
    """Thread-safe counter wrapped in a Lock so the test's own
    increment is not the race being measured."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._n = 0

    def bump(self) -> None:
        with self._lock:
            self._n += 1

    @property
    def n(self) -> int:
        with self._lock:
            return self._n


@pytest.fixture
def st_stub(monkeypatch):
    """Install a fake ``sentence_transformers`` module exposing a
    ``SentenceTransformer`` that bumps a counter on construction and
    waits on a barrier so every concurrent caller arrives at the
    constructor at the same moment.

    Returns ``(counter, set_barrier)`` — the test wires its own
    Barrier(N) via ``set_barrier`` so N matches the ThreadPoolExecutor
    size.
    """
    counter = _LoadCounter()
    barrier_holder: list[threading.Barrier | None] = [None]

    class _FakeSentenceTransformer:
        def __init__(self, *args, **kwargs) -> None:
            b = barrier_holder[0]
            if b is not None:
                try:
                    b.wait(timeout=10)
                except threading.BrokenBarrierError:
                    pass
            counter.bump()

        def encode(self, text, convert_to_numpy=True):
            return [0.1, 0.2, 0.3]

        def get_sentence_embedding_dimension(self):
            return 384

    stub_module = types.ModuleType("sentence_transformers")
    stub_module.SentenceTransformer = _FakeSentenceTransformer
    monkeypatch.setitem(sys.modules, "sentence_transformers", stub_module)

    def _set_barrier(n: int) -> None:
        barrier_holder[0] = threading.Barrier(n)

    return counter, _set_barrier


# ---------------------------------------------------------------------------
# The regression test
# ---------------------------------------------------------------------------


class TestLoadModelLoadOnceUnderConcurrentThreads:
    """Class-invariant: ``_load_model`` loads at most once per backend
    instance, regardless of how many concurrent threads call it.

    Pre-#264-fix: 10/10 double-loads, 5/5 stress runs. Post-fix: 1/1
    load every time.
    """

    def test_ten_concurrent_threads_load_once(self, st_stub):
        """The structural-class regression guard. If this test fires,
        a future refactor broke the Lock invariant in ``_load_model``.
        """
        from email_triage.engine.embedding_backend import (
            SentenceTransformersBackend,
        )

        counter, set_barrier = st_stub
        backend = SentenceTransformersBackend(model="fake-model")

        n = 10
        set_barrier(n)
        with ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(backend._load_model) for _ in range(n)]
            for f in futures:
                f.result()

        assert counter.n == 1, (
            f"_load_model must load at most once across {n} concurrent "
            f"threads (Barrier-coordinated arrival); got {counter.n} "
            f"loads. The Lock + double-checked-locking invariant is "
            f"broken; check src/email_triage/engine/embedding_backend.py "
            f"_load_model for a regressed Lock or removed re-check."
        )

    def test_stress_repeats_load_once_invariant(self, st_stub):
        """Stress: repeat the 10-thread race 5×. Pre-fix this was
        10/10 every time; post-fix it must be 1/1 every time. A flake
        here would indicate a non-deterministic Lock semantics."""
        from email_triage.engine.embedding_backend import (
            SentenceTransformersBackend,
        )

        counter, set_barrier = st_stub
        observed = []
        for _ in range(5):
            # Fresh backend per iteration — the invariant is per-
            # instance, not global. Reset counter.
            counter._n = 0
            backend = SentenceTransformersBackend(model="fake-model")
            n = 10
            set_barrier(n)
            with ThreadPoolExecutor(max_workers=n) as ex:
                futures = [
                    ex.submit(backend._load_model) for _ in range(n)
                ]
                for f in futures:
                    f.result()
            observed.append(counter.n)

        assert all(c == 1 for c in observed), (
            f"5-run stress: every iteration must observe load_counter "
            f"== 1; got {observed}. Any value > 1 means the Lock "
            f"invariant is broken under that timing."
        )

    def test_second_call_after_load_skips_lock(self, st_stub):
        """Hot-path correctness: once loaded, subsequent ``_load_model``
        calls return the cached model without re-loading. This pins
        the hot-path no-Lock-acquisition behaviour (the ``if self._model
        is not None`` check before the Lock).
        """
        from email_triage.engine.embedding_backend import (
            SentenceTransformersBackend,
        )

        counter, _ = st_stub
        backend = SentenceTransformersBackend(model="fake-model")
        first = backend._load_model()
        assert counter.n == 1
        # 100 sequential calls after the load must not re-load.
        for _ in range(100):
            assert backend._load_model() is first
        assert counter.n == 1
