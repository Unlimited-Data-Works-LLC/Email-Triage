"""Walk — Topic matcher band/K orchestration (match_topics_for_message) — Actions sketch .

Feature: ``email_triage.actions.topic_matcher.match_topics_for_message`` — the
orchestrator between the deterministic Stage-0 pre-filter and the LLM
topic-match seam (``classify_with_topics_safe``, owned by the classify layer).
It runs the committed §4.1 band/K pipeline and returns the classifier's MATCHED
verdicts. It is pure orchestration: no DB, no network, no body reads.

This walk drives it end-to-end with a MOCK classifier (no live Ollama):

  * single-call band (≤ K Topics) → a matched verdict is returned;
  * a matched=False verdict → no hit (fail-closed on the match);
  * a classifier that RAISES → fail-open to ``[]`` (a flaky GPU degrades the
    digest, never core triage, §4.4);
  * two-stage band (> K Topics) → coarse shortlist → rerank → matched verdict.

On "PHI-hide on non-owner": the matcher has NO requester/owner axis — the
non-owner PHI gate lives at the SURFACE layer (``gather_live_topic_hits`` / the
preview route's ``is_manageable`` intersection), not here. That is asserted as
a positive owner-agnostic invariant (a passing test), NOT an xfail — there is
no unimplemented matcher surface to xfail against.
"""

from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.e2e


def _topic(tid, name, subjects=None, details=""):
    return {
        "id": tid,
        "name": name,
        "subjects": subjects or [f"subject{tid}"],
        "details": details,
        "selected_account_ids": [],
        "retention_days": 90,
    }


def _verdict(topic_id, *, matched=True, confidence=0.9, reason_terms=("study",)):
    return {
        "topic_id": topic_id,
        "matched": matched,
        "confidence": confidence,
        "reason_terms": list(reason_terms),
    }


class _MockClassifier:
    """Duck-typed stand-in for the classify layer's topic-match seam.

    Records every ``topic_block`` it was handed (so a test can assert the
    two-stage path made both a coarse and a rerank call) and returns a
    ``TopicMatchResult``-shaped object carrying the configured verdicts.
    """

    def __init__(self, verdicts=None, *, raise_on_call=False):
        self.blocks: list[str] = []
        self._verdicts = list(verdicts or [])
        self._raise = raise_on_call

    async def classify_with_topics_safe(
        self, message, categories, list_hints, *, topic_block, model=None,
    ):
        self.blocks.append(topic_block)
        if self._raise:
            raise RuntimeError("classifier exploded")
        return SimpleNamespace(topic_verdicts=list(self._verdicts))


_MSG = SimpleNamespace(headers={"Subject": "study update", "From": "pi@lab.test"})
_CATS = {"work": "Work-related mail"}


from tests.e2e.walk._helpers import sync_run_in_thread

# Tests are SYNC ``def`` and drive the async product function via
# ``sync_run_in_thread(coro)`` — see _helpers.py::sync_run_in_thread for the
# full "outer loop is reachable on the main thread" story. Neither
# ``asyncio.run(coro)`` nor ``async def test + await`` works reliably in the
# full walk suite (both hit different flavors of the "another loop is
# running" RuntimeError once several fixtures have executed).


def test_match_single_call_hit():
    """PRIMARY — ≤ K Topics take the single precise call; a matched verdict
    comes back as a hit."""
    from email_triage.actions.topic_matcher import match_topics_for_message

    topics = [_topic(1, "A"), _topic(2, "B")]
    clf = _MockClassifier([_verdict(1, matched=True)])
    out = sync_run_in_thread(
        match_topics_for_message(_MSG, topics, clf, categories=_CATS)
    )
    assert len(out) == 1
    assert (out[0]["topic_id"] if isinstance(out[0], dict) else out[0].topic_id) == 1
    assert len(clf.blocks) == 1, "single-call band must make exactly one classify call"


def test_match_miss_returns_empty():
    """A matched=False verdict is NOT a hit — fail-closed on the match (a
    fabricated hit is a false PHI surface; a missing match is a no-op)."""
    from email_triage.actions.topic_matcher import match_topics_for_message

    topics = [_topic(1, "A")]
    clf = _MockClassifier([_verdict(1, matched=False)])
    out = sync_run_in_thread(
        match_topics_for_message(_MSG, topics, clf, categories=_CATS)
    )
    assert out == []


def test_match_classifier_raises_fails_open_empty():
    """FAIL-OPEN (§4.4) — a classifier that raises degrades the Topic match to
    ``[]`` and NEVER propagates: core triage is decoupled from a GPU fault."""
    from email_triage.actions.topic_matcher import match_topics_for_message

    topics = [_topic(1, "A")]
    clf = _MockClassifier(raise_on_call=True)
    out = sync_run_in_thread(
        match_topics_for_message(_MSG, topics, clf, categories=_CATS)
    )
    assert out == []


def test_match_two_stage_above_k():
    """> K Topics take the two-stage path: a coarse card pass produces a
    shortlist, then a rerank pass over full Details returns the matched
    verdict. BOTH classify stages fire."""
    from email_triage.actions.topic_matcher import match_topics_for_message, K

    topics = [_topic(i, f"T{i}") for i in range(1, K + 3)]  # K+2 > K
    # The lowest stringified topic_id sorts first at score 0 → candidate[0]==1.
    clf = _MockClassifier([_verdict(1, matched=True)])
    out = sync_run_in_thread(
        match_topics_for_message(_MSG, topics, clf, categories=_CATS)
    )
    assert len(out) == 1
    assert (out[0]["topic_id"] if isinstance(out[0], dict) else out[0].topic_id) == 1
    assert len(clf.blocks) == 2, (
        f"two-stage band must make a coarse AND a rerank call, made {len(clf.blocks)}"
    )


def test_matcher_has_no_owner_or_actor_axis():
    """POSITIVE INVARIANT — the matcher exposes no requester/owner parameter,
    so 'PHI-hide on non-owner' is structurally NOT its job (it lives at the
    surface layer). This documents the boundary; it is not an xfail because
    there is no unimplemented matcher surface."""
    from email_triage.actions import topic_matcher

    params = set(inspect.signature(topic_matcher.match_topics_for_message).parameters)
    owner_axis = params & {
        "actor", "owner", "requester", "user", "requester_id", "actor_user_id",
    }
    assert not owner_axis, (
        f"matcher unexpectedly grew an owner/actor axis {owner_axis}; the "
        "non-owner PHI gate belongs at the surface layer, not the matcher."
    )
