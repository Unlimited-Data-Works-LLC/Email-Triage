"""Regression tests for  + style_profile companion — parallel LLM hot path.

Pre-#273 the digest extractor walked messages sequentially:

    for msg in messages:
        articles = await extract_articles(classifier, msg)
        groups[sender_key].articles.extend(articles)

For 20-50 messages at 1-3 s per LLM round-trip that was 20-150 s of
wall-clock per digest. The fix wraps each ``extract_articles`` call in
an ``asyncio.Semaphore``-bounded ``asyncio.gather`` so up to
``_DIGEST_EXTRACT_CONCURRENCY`` (5) calls execute concurrently.

The same wrap shape was applied to ``extract_style_profiles_per_alias``
in ``actions/style_profile.py`` (audit-pattern-before-fix catch:
structurally identical sequential-await loop over LLM round-trips for
each sender alias bucket).

These tests pin:
* the parallelism shape — N>1 concurrent calls when N messages with
  ``N <= _DIGEST_EXTRACT_CONCURRENCY``
* the Semaphore cap — never more than ``_DIGEST_EXTRACT_CONCURRENCY``
  concurrent calls in flight at once, even with many messages
* the companion site (style_profile) shows the same shape

We use ``asyncio.Event`` + a running counter rather than wall-clock
elapsed-time assertions (per ``pattern_barrier_concurrency_test.md``)
— wall-clock is flaky on CI; an exact peak-concurrency count is
deterministic.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from email_triage.actions.digest import (
    _DIGEST_EXTRACT_CONCURRENCY,
    generate_digest,
)
from email_triage.engine.models import EmailMessage


@dataclass
class _ConcurrencyProbe:
    """Tracks peak + currently-in-flight concurrent calls.

    A test's mock ``extract_articles`` increments ``in_flight`` on
    entry, takes the peak when it crosses the previous high-water,
    awaits an event (held by the test), and decrements on exit.
    """
    in_flight: int = 0
    peak: int = 0
    release: asyncio.Event = None
    enter_event: asyncio.Event = None  # signaled when first call enters
    total_calls: int = 0


def _make_msg(i: int, hipaa: bool = False) -> EmailMessage:
    return EmailMessage(
        message_id=f"m-{i}",
        provider="test",
        sender=f"sender-{i % 3}@news.example",
        recipients=["me@example.com"],
        subject=f"Newsletter {i}",
        body_text=f"Body {i}",
        date=datetime(2026, 5, 24, 12, 0, tzinfo=timezone.utc),
    )


class _StubClassifier:
    """Minimal classifier stub — generate_digest only calls extract_articles
    which is monkeypatched to the probe; classifier is unused but
    required by signature."""
    pass


@pytest.fixture
def probe():
    return _ConcurrencyProbe(
        release=asyncio.Event(),
        enter_event=asyncio.Event(),
    )


@pytest.fixture
def mocked_extract(monkeypatch, probe):
    """Replace ``extract_articles`` with a probe that tracks
    concurrency. Each call increments the counter, awaits the test's
    release signal, then decrements."""
    async def _fake_extract(classifier, msg):
        probe.total_calls += 1
        probe.in_flight += 1
        probe.peak = max(probe.peak, probe.in_flight)
        if not probe.enter_event.is_set():
            probe.enter_event.set()
        try:
            await probe.release.wait()
        finally:
            probe.in_flight -= 1
        # Return one article per message — keeps the digest renderer happy.
        return [{"headline": f"h-{msg.message_id}", "summary": "s", "url": None}]

    import email_triage.actions.digest as digest_mod
    monkeypatch.setattr(digest_mod, "extract_articles", _fake_extract)
    return probe


class TestParallelExtractShape:
    """Pin the  parallelism contract on ``generate_digest``."""

    @pytest.mark.asyncio
    async def test_two_messages_run_concurrently(self, mocked_extract):
        """With 2 messages (under the cap of 5), both extract_articles
        calls must be in-flight simultaneously. Pre-fix this was
        impossible — the second call awaited the first to complete."""
        messages = [_make_msg(0), _make_msg(1)]

        # Kick off the digest, then release the probe once both calls
        # are demonstrably in flight (peak=2). If we never reach
        # peak=2 within the deadline, the test fails with a timeout.
        digest_task = asyncio.create_task(
            generate_digest(
                messages=messages,
                classifier=_StubClassifier(),
                provider=None,
                category="news",
            ),
        )

        # Wait for both calls to be in flight.
        try:
            async with asyncio.timeout(5.0):
                while mocked_extract.peak < 2:
                    await asyncio.sleep(0.01)
        except TimeoutError:
            mocked_extract.release.set()
            await digest_task
            raise AssertionError(
                f"never reached peak=2; saw peak={mocked_extract.peak}, "
                f"total_calls={mocked_extract.total_calls}. Pre-#273 "
                f"shape would deadlock here."
            )

        mocked_extract.release.set()
        await digest_task
        assert mocked_extract.peak == 2
        assert mocked_extract.total_calls == 2

    @pytest.mark.asyncio
    async def test_concurrency_capped_at_semaphore(self, mocked_extract):
        """With (cap + 3) messages, peak concurrency must be exactly
        the Semaphore cap — never higher. Documents the bounded-
        concurrency contract."""
        cap = _DIGEST_EXTRACT_CONCURRENCY
        n = cap + 3
        messages = [_make_msg(i) for i in range(n)]

        digest_task = asyncio.create_task(
            generate_digest(
                messages=messages,
                classifier=_StubClassifier(),
                provider=None,
                category="news",
            ),
        )

        # Wait for the cap to be saturated.
        try:
            async with asyncio.timeout(5.0):
                while mocked_extract.peak < cap:
                    await asyncio.sleep(0.01)
        except TimeoutError:
            mocked_extract.release.set()
            await digest_task
            raise AssertionError(
                f"never reached cap={cap}; peak={mocked_extract.peak}"
            )

        # Hold the release closed a bit longer so any over-cap call
        # would have time to land. peak must NOT exceed cap.
        await asyncio.sleep(0.1)
        assert mocked_extract.peak == cap, (
            f"Semaphore breach: peak={mocked_extract.peak} > cap={cap}"
        )

        mocked_extract.release.set()
        await digest_task
        # Every message got extracted exactly once.
        assert mocked_extract.total_calls == n

    @pytest.mark.asyncio
    async def test_no_messages_no_calls(self, mocked_extract):
        """Empty input → no gather, no calls, no crash."""
        await generate_digest(
            messages=[],
            classifier=_StubClassifier(),
            provider=None,
            category="news",
        )
        assert mocked_extract.total_calls == 0
        assert mocked_extract.peak == 0


class TestStyleProfileCompanion:
    """The companion site at ``extract_style_profiles_per_alias`` got
    the same fix. Mirror-shape regression: peak concurrency >1 with
    multiple alias buckets."""

    @pytest.mark.asyncio
    async def test_aliases_distilled_concurrently(self, monkeypatch):
        """Two distinct sender aliases → two concurrent
        ``extract_style_profile`` calls. Pre-fix shape would have
        peak=1 (sequential per-bucket)."""
        from email_triage.actions import style_profile

        in_flight = 0
        peak = 0
        release = asyncio.Event()

        async def _fake_distill(msgs, classifier, **kw):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await release.wait()
            finally:
                in_flight -= 1
            return style_profile.StyleProfile(sample_count=1)

        monkeypatch.setattr(
            style_profile, "extract_style_profile", _fake_distill,
        )

        messages = [
            _make_msg(0),  # sender-0
            _make_msg(1),  # sender-1
            _make_msg(2),  # sender-2  → 3 distinct aliases per _make_msg
        ]

        task = asyncio.create_task(
            style_profile.extract_style_profiles_per_alias(
                messages, classifier=_StubClassifier(),
            ),
        )

        try:
            async with asyncio.timeout(5.0):
                while peak < 2:
                    await asyncio.sleep(0.01)
        except TimeoutError:
            release.set()
            await task
            raise AssertionError(
                f"style_profile companion did not parallelize: peak={peak}"
            )

        release.set()
        await task
        assert peak >= 2, (
            "style_profile.extract_style_profiles_per_alias should "
            "have peak>=2 concurrent calls with 3 alias buckets"
        )
