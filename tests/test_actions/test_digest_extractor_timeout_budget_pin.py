""" pin — digest extractor per-call timeout (the deploy host prod 2026-07-10 evidence).

``asyncio.wait_for`` around each ``classifier.complete(prompt)`` call inside
``extract_articles``. A single stalled Ollama response can't stall its
extract slot; the existing except handler catches ``asyncio.TimeoutError``
and falls back to a single-article snippet stub. Combined with the
``_DIGEST_EXTRACT_CONCURRENCY = 5`` semaphore, worst-case wall-clock is
bounded at ``ceil(N/5) * per_call`` regardless of how slow Ollama gets — no
separate total-budget wrap is needed (that shape was considered + refuted
by devils-advocate 2026-07-11 batched SME panel: a wall-clock ceiling with
`wait_for(gather)` cancels in-flight completed extracts, discarding usable
partials for a use-case where the digest renders fine with any subset).

Pre-#91 the digest run for 20+ ReadTimeout-per-slot msgs took ~8 min wall-
clock (log evidence 2026-07-10 07:52-08:00 EDT, request_id=4150becaf209).
Post-#91: worst-case per slot is bounded by ``_DIGEST_EXTRACT_PER_CALL_TIMEOUT``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from email_triage.actions.digest import (
    _DIGEST_EXTRACT_PER_CALL_TIMEOUT,
    extract_articles,
)
from email_triage.engine.models import EmailMessage


@dataclass
class _SlowClassifier:
    """Stub classifier whose ``complete`` sleeps ``delay`` seconds and only
    THEN returns a valid JSON-array response. Simulates a stuck Ollama."""
    delay: float
    is_local: bool = True

    async def complete(self, prompt: str) -> str:
        await asyncio.sleep(self.delay)
        return '[{"headline": "H", "summary": "s", "url": null}]'


def _make_msg(i: int, hipaa: bool = False) -> EmailMessage:
    msg = EmailMessage(
        message_id=f"m-{i}",
        provider="test",
        sender=f"sender-{i}@news.example",
        recipients=["me@example.com"],
        subject=f"Newsletter {i}",
        body_text=f"Body {i}",
        date=datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc),
    )
    msg.hipaa = hipaa
    return msg


class TestPerCallTimeoutBudget:
    """``extract_articles`` per-call ``asyncio.wait_for`` around
    ``classifier.complete``. A single stalled call falls back to the
    snippet stub — it does NOT propagate ``TimeoutError`` up."""

    @pytest.mark.asyncio
    async def test_slow_classifier_falls_back_to_snippet(self, monkeypatch):
        """When ``classifier.complete`` outruns the per-call timeout,
        ``extract_articles`` catches the ``TimeoutError`` via its existing
        except handler and returns the single-article fallback (contract:
        digest still renders, just without extracted articles)."""
        # Tiny per-call budget so the test is fast — sleep 1.0s vs 0.1s budget.
        monkeypatch.setattr(
            "email_triage.actions.digest._DIGEST_EXTRACT_PER_CALL_TIMEOUT",
            0.1,
        )
        classifier = _SlowClassifier(delay=1.0)
        msg = _make_msg(0)

        articles = await extract_articles(classifier, msg)

        # Fallback path returns exactly one stub article (see digest.py
        # except block — treat-whole-email-as-one-article shape).
        assert len(articles) == 1, (
            f"expected 1 fallback article, got {len(articles)}"
        )
        # Fallback headline is the message subject (per digest.py except body).
        assert articles[0].headline == msg.subject

    @pytest.mark.asyncio
    async def test_fast_classifier_returns_parsed_articles(self, monkeypatch):
        """Sanity: with the per-call budget wide enough, the classifier
        response is parsed normally and the extracted article is returned."""
        monkeypatch.setattr(
            "email_triage.actions.digest._DIGEST_EXTRACT_PER_CALL_TIMEOUT",
            5.0,
        )
        classifier = _SlowClassifier(delay=0.01)
        msg = _make_msg(0)

        articles = await extract_articles(classifier, msg)

        assert len(articles) == 1
        assert articles[0].headline == "H"


class TestConstantsAreReasonable:
    """Structural pin (Prime Directive 1 in the style guide): the module-
    level per-call timeout is positive + non-trivial."""

    def test_per_call_budget_positive(self):
        assert _DIGEST_EXTRACT_PER_CALL_TIMEOUT > 0

    def test_per_call_budget_at_least_five_seconds(self):
        """A per-call budget under 5s would cut off legitimate Ollama
        qwen3.6 extract responses (2-8s median). Structural pin — if
        this trips, the tuning knob has been mis-configured."""
        assert _DIGEST_EXTRACT_PER_CALL_TIMEOUT >= 5.0
