"""Walk — Topic-digest Stage-0 pre-filter (rank / admit / keyword_match) — Actions sketch .

Feature: ``email_triage.actions.topic_prefilter`` — the deterministic,
config-derived Stage-0 that RANKS a user's active Topics against an inbound
email's cheap header/keyword signals and applies the band/K admission policy.
Its load-bearing guarantee (design §4.1): it is a *prioritizer, never a recall
gate*. Below the always-on band ``B`` every Topic is ADMITTED regardless of
signal — a keyword-free miss is **score 0, not exclusion** — so ``|C| = 0`` is
structurally impossible.

This walk exercises the public surface end-to-end (pure logic — no DB, no
network, no PHI):

  * ``admit`` below the band admits EVERY Topic (the partition invariant holds;
    a keyword-free Topic scores 0 but is never rejected);
  * a registry-id match (``NCT\\d{8}``) ranks its Topic first;
  * ``admit`` above the band still admits everything (all cards + top-K
    Details), partition invariant intact;
  * ``keyword_match`` returns the operator's OWN chip verbatim on a hit, and
    soft-fails to ``[]`` for a config-less Topic (missing-topic) or a miss —
    the Preview MATCH-layer "reject" that is distinct from the always-admit
    prioritizer.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


def _topic(tid, name, subjects=None, details=""):
    """A minimal TopicConfig-shaped dict (the module reads dict OR dataclass)."""
    return {
        "id": tid,
        "name": name,
        "subjects": subjects or [],
        "details": details,
        "selected_account_ids": [],
        "retention_days": 90,
    }


def test_admit_below_band_admits_every_topic_none_rejected():
    """PRIMARY — below the band NOTHING is dropped: full_details + cards cover
    every candidate, the registry-id Topic ranks first, and the keyword-free
    Topic is still admitted at score 0 (never rejected)."""
    from email_triage.actions.topic_prefilter import admit

    topics = [
        _topic(1, "Estrogen study", subjects=["NCT00000419"]),
        _topic(2, "Lupus cohort", subjects=["lupus"]),
        _topic(3, "Finance", subjects=["quarterly finance report"]),
    ]
    headers = {
        "Subject": "Weekly digest for NCT00000419",
        "From": "alerts@clinicaltrials.gov",
    }
    a = admit(topics, headers, [])

    assert not a.above_band, "3 topics is at/below the band B=12"
    # Partition invariant — the structural |C| != 0 guarantee.
    assert len(a.full_details) + len(a.cards) == len(a.candidates) == 3
    # The registry-id Topic ranks first with a positive score.
    assert a.candidates[0].topic_id == 1
    assert a.candidates[0].score > 0
    # A keyword-free Topic is score 0 but STILL admitted (not rejected).
    zero = [c for c in a.candidates if c.score == 0]
    assert zero, "expected at least one zero-score candidate that is still admitted"
    ids = {t["id"] for t in topics}
    assert all(c.topic_id in ids for c in a.candidates)


def test_rank_candidates_registry_id_ranks_first():
    """A configured NCT id hit is the strongest cheap signal — its Topic sorts
    first and the matched-evidence carries the id (the user's own public term)."""
    from email_triage.actions.topic_prefilter import rank_candidates, _W_REGISTRY

    topics = [
        _topic(10, "Trial A", subjects=["NCT00000419"]),
        _topic(11, "Trial B", subjects=["diabetes"]),
    ]
    ranked = rank_candidates(topics, {"Subject": "results posted for NCT00000419"}, [])

    assert len(ranked) == 2, "every active Topic must appear (ranked, not filtered)"
    assert ranked[0].topic_id == 10
    assert ranked[0].score >= _W_REGISTRY
    assert "NCT00000419" in ranked[0].matched_terms


def test_admit_above_band_all_cards_plus_topk_details():
    """Above the band EVERY Topic is still admitted (as a card); the top-K
    additionally get full Details. The partition invariant holds unchanged."""
    from email_triage.actions.topic_prefilter import admit, B, K

    topics = [_topic(i, f"Topic {i}", subjects=[f"subject{i}"]) for i in range(1, B + 3)]
    a = admit(topics, {"Subject": "nothing in particular"}, [])

    assert a.above_band, f"{len(topics)} topics must exceed the band B={B}"
    assert len(a.full_details) == K
    assert len(a.cards) == len(topics) - K
    assert len(a.full_details) + len(a.cards) == len(a.candidates) == len(topics)


def test_keyword_match_hit_returns_chip_verbatim():
    """A Subject-chip hit surfaces the operator's OWN chip verbatim (the
    why-matched evidence — never a body quote)."""
    from email_triage.actions.topic_prefilter import keyword_match

    topic = _topic(20, "SELENA", subjects=["SELENA lupus"])
    headers = {"Subject": "SELENA cohort enrollment update", "From": "pi@nyulangone.org"}
    hits = keyword_match(topic, headers, [])

    assert hits, "expected a keyword hit on the SELENA subject chip"
    assert any("SELENA" in h or "lupus" in h.lower() for h in hits), hits


def test_keyword_match_missing_topic_soft_fail():
    """A config-less Topic never raises and never fabricates a hit; a real
    Topic the email misses is a clean no-hit (the Preview MATCH-layer reject)."""
    from email_triage.actions.topic_prefilter import keyword_match

    empty = _topic(21, "", subjects=[], details="")
    assert keyword_match(empty, {"Subject": "anything at all"}, []) == []

    topic = _topic(22, "Oncology", subjects=["glioblastoma"])
    assert keyword_match(topic, {"Subject": "quarterly newsletter"}, []) == []
