""" Topic matcher orchestration — the band/K policy over one classify call.

This module is the **orchestrator** that sits between the deterministic
Stage-0 pre-filter (:mod:`email_triage.actions.topic_prefilter`) and the
LLM that actually decides whether a message matches a Topic
(``classify_with_topics`` — **owned by the classify layer**, not here). Its
single public entry point :func:`match_topics_for_message` runs the committed
pipeline from the design doc (``internal documentation``
§4.1) and returns the per-Topic verdicts the classifier produced.

What it does NOT do
-------------------
- It does **not** implement ``classify_with_topics`` — that is the classify
  layer's job (the prompt assembly + Ollama call + JSON parse). This module
  only *calls* it (as a method on the injected ``classifier``), passing the
  pre-filter's admission decision (which Topics get full Details vs compact
  cards) and the stage.
- It does **not** read message bodies, hit the network, or touch the DB. It is
  pure orchestration over the pre-filter's :class:`Candidate` ranking + the
  classifier's verdicts. The back-scan job (:mod:`email_triage.jobs.topic_backscan`)
  is the only thing that persists hits.
- It uses **no embedding signal** — the pre-filter is config-keyword/IDF only
  (design N17). No vector is introduced here.

The committed band logic (design §4.1)
--------------------------------------
Given the user's active Topics ranked by the cheap pre-filter:

- **|full-Details candidates| ≤ K (=6) → ONE call** at ``stage='single'`` with
  the top-K Topics inlined as full :class:`TopicDetail`. One precise LLM pass,
  one set of verdicts.
- **> K → two-stage fallback.** ``stage='coarse'`` carries **all** admitted
  Topics as compact :class:`TopicCard`\\s (the pre-filter never drops a Topic
  below the always-on band, so the coarse pass is the recall floor); the
  classifier returns a coarse shortlist ``S`` (the matched verdicts). Then ONE
  ``stage='rerank'`` call re-scores **only** ``S`` with full Details — the
  precise verdicts.

**Fail-open (design §4.4).** A classifier that raises, times out, or returns
garbled output yields **no verdicts** (an empty list) and **never** propagates
the exception — a flaky GPU degrades the Topic digest, it never breaks core
triage. A missing/garbled verdict ⇒ no hit (fail-closed on the *match*: a
missing match is a no-op; a fabricated one is a false PHI surface).
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Sequence

from email_triage.actions.topic_prefilter import (
    K,
    Candidate,
    TopicSignalIndex,
    derive_card_terms,
    rank_candidates,
)
from email_triage.triage_logging import get_logger  # N-196b R21_4

log = get_logger("email_triage.actions.topic_matcher")  # N-196b R21_4


# ---------------------------------------------------------------------------
# Building the classify-layer inputs from the pre-filter's Candidates.
#
# TopicCard / TopicDetail are OWNED by the classify layer (classify/prompts.py)
# — they are thin, render-only carriers of the operator's OWN public config
# text. We import them lazily inside the builders so this module imports
# cleanly even while the classify-layer build is in flight (parallel build),
# and so a test using a MOCK classifier need not pull the classify stack at
# all when it injects its own card/detail shapes.
# ---------------------------------------------------------------------------

def _topic_lookup(active_topics: Sequence[Any]) -> dict[Any, Any]:
    """Map a Candidate's ``topic_id`` back to its source TopicConfig-shaped
    object, so :func:`derive_card_terms` / Detail-building can read the
    Topic's Subject chips + Details.

    The pre-filter stamps ``Candidate.topic_id`` from the same ``_topic_id``
    resolution the index uses (``id`` / ``topic_id`` / ``name`` / enumerate
    index), so we replicate that key here to join the two sides.
    """
    from email_triage.actions.topic_prefilter import _topic_id

    out: dict[Any, Any] = {}
    for i, topic in enumerate(active_topics):
        out[_topic_id(topic, i)] = topic
    return out


def _scrub_card_text(*values: Any) -> bool:
    """ C-V1.1 / §4.4 — fail-CLOSED PHI scan over compact-card text.

    The coarse-pass cards carry the Topic ``name`` + derived ``terms`` (the
    operator's OWN public Subject/Details words). Those strings enter the
    LLM context, so they go through the SAME m-series HIPAA-18 pre-egress
    catalogue the save-time gate uses (``phi_scrubber._layer2_scan_string``)
    BEFORE a card is built.

    Returns ``True`` when the text is clean (safe to send) and ``False`` when
    it MUST be dropped — fail-CLOSED in both senses: a PHI-pattern trip OR a
    scrubber that raises ⇒ ``False`` (drop the card). Per §4.4 a dropped card
    is a no-op (a missing match never harms); a leaky one is a false PHI
    surface, so the strictest direction is "don't send it."
    """
    try:
        # Reuse the SAME Topic-text PHI scan the save-time gate uses
        # (``topic_configs._scan_topic_phi`` — m-series identifier catalogue,
        # NCT-masked, medical-vocab excluded) so the LLM-context gate and the
        # at-rest gate share one definition of "PHI in Topic text."
        from email_triage.actions.topic_configs import _scan_topic_phi
        for v in values:
            if not v:
                continue
            if _scan_topic_phi(str(v)):
                return False
        return True
    except Exception as exc:  # noqa: BLE001 — fail-closed on internal error
        log.warning(
            "topic_matcher: card PHI scrub raised; dropping card (fail-closed)",
            extra={"_extra": {"error_type": type(exc).__name__}},
        )
        return False


def _build_card(cand: Candidate, topic: Any, corpus: Sequence[Any]):
    """Build a classify-layer :class:`TopicCard` for one Candidate, or ``None``
    when its text trips the V1 PHI gate (fail-closed; §4.4 / C-V1.1).

    Card terms come from :func:`derive_card_terms` (highest-IDF over the
    user's other Topics as corpus) — the design's fix for "Stage-A cards drop
    a true positive" (§4.1). We prefer the Candidate's already-derived
    ``card_terms`` (the index computed them with the right IDF corpus); only
    fall back to a fresh ``derive_card_terms`` when they are absent.

    Before the card is emitted, its name + terms are scrubbed through the
    m-series HIPAA-18 catalogue (:func:`_scrub_card_text`). A trip — or a
    scrubber error — drops the card (returns ``None``); the caller filters
    ``None`` out so leaky text never reaches the LLM context.
    """
    from email_triage.classify.prompts import TopicCard

    terms = cand.card_terms
    if not terms and topic is not None:
        terms = derive_card_terms(topic, corpus=corpus)
    terms = tuple(terms)
    if not _scrub_card_text(cand.name, *terms):
        return None
    return TopicCard(topic_id=cand.topic_id, name=cand.name, terms=terms)


def _build_detail(cand: Candidate, topic: Any):
    """Build a classify-layer :class:`TopicDetail` from the TopicConfig fields,
    or ``None`` when its text trips the V1 PHI gate (fail-closed; C-V1.1).

    Subjects + Details are the operator's OWN public config text — never a body
    quote. Reads the documented ``TopicConfig`` fields via the pre-filter's
    field accessor so it works on a dataclass, a Mapping, or a duck-typed
    object alike.

    Defense-in-depth: at-rest Details/Subjects should already be clean (the
    save-time gate in ``topic_configs.upsert_topic`` is fail-closed), but the
    full-Details block is the richest free-text egress, so it is re-scrubbed
    through the SAME m-series catalogue right before it enters the LLM
    context. A trip — or a scrubber error — drops the Detail (returns
    ``None``), which the caller filters out (a missing match is a no-op,
    §4.4).
    """
    from email_triage.actions.topic_prefilter import _field, _subjects
    from email_triage.classify.prompts import TopicDetail

    subjects: tuple[str, ...] = ()
    details = ""
    if topic is not None:
        subjects = tuple(_subjects(topic))
        details = str(_field(topic, "details", "") or "")
    if not _scrub_card_text(cand.name, details, *subjects):
        return None
    return TopicDetail(
        topic_id=cand.topic_id,
        name=cand.name,
        subjects=subjects,
        details=details,
    )


# ---------------------------------------------------------------------------
# Verdict normalisation — the classifier returns TopicVerdict-shaped objects;
# we read them duck-typed so a MOCK classifier (tests) and the real
# classify-layer TopicVerdict are both accepted.
# ---------------------------------------------------------------------------

def _verdict_topic_id(v: Any) -> Any:
    return getattr(v, "topic_id", None) if not isinstance(v, dict) else v.get("topic_id")


def _verdict_matched(v: Any) -> bool:
    matched = (
        v.get("matched") if isinstance(v, dict) else getattr(v, "matched", None)
    )
    # Fail-CLOSED on an absent flag (operator 2026-06-15): a verdict that does
    # not explicitly assert ``matched`` is NOT a hit. The real classify layer
    # always emits a bool (``_parse_topic_verdicts`` → ``bool(get("matched",
    # False))``), so this only bites a malformed verdict / a thin mock — for
    # which fabricating a PHI surface is the wrong default (§4.4: a missing match
    # is a no-op, a fabricated one is a false surface). ``bool(None)`` is False,
    # so the coercion below already encodes the fail-closed default; this matches
    # the classify-layer parse rather than diverging from it.
    return bool(matched)


def _matched_verdicts(verdicts: Iterable[Any]) -> list[Any]:
    """Filter to the verdicts the classifier marked matched (the shortlist S in
    the two-stage path; the final hit set in the single-call path).

    NOTE: the matcher does NOT apply a confidence floor — every matched verdict
    is PERSISTED with its confidence, and the digest confidence floor is applied
    at SURFACE time in :func:`topic_configs.gather_live_topic_hits` (operator
    2026-06-15: keep the floor reversible — a floor-dropped hit must still be
    recoverable by lowering the floor, which a match-time drop + the
    ``study_match_cache`` matched=0 row would make permanent). The persisted
    ``topic_hits.confidence`` is the one number the surface floor reads."""
    return [v for v in (verdicts or []) if _verdict_matched(v)]


def _build_topic_block(
    stage: str,
    *,
    topic_cards: Sequence[Any] | None,
    topic_details: Sequence[Any] | None,
) -> str:
    """Render the BLOCK-2 ``topic_block`` suffix for ``stage``.

    The classify layer owns ONE topic-match prompt shape: BLOCK 1 (the shared,
    cacheable ``[system + email]`` prefix) + a per-stage ``topic_block`` suffix.
    The matcher (this module) renders that suffix from the pre-filter's
    admission decision and hands it across the seam:

    * ``stage='coarse'`` → :func:`build_topic_card_block` over ALL admitted
      Topics' compact cards (the recall floor — over-admit, §4.1).
    * ``stage='single'`` / ``stage='rerank'`` → :func:`build_topic_detail_block`
      over the top-K (single) / shortlist (rerank) Topics' full Details.

    Imported lazily so this module loads cleanly even while the classify-layer
    build is in flight (parallel build) and so a contract test can stub the
    transport without pulling extra stacks.
    """
    from email_triage.classify.prompts import (
        build_topic_card_block,
        build_topic_detail_block,
    )

    if stage == "coarse":
        return build_topic_card_block(list(topic_cards or []))
    # single / rerank both send full Details.
    return build_topic_detail_block(list(topic_details or []))


async def _safe_classify_with_topics(
    classifier: Any,
    message: Any,
    *,
    categories: dict[str, str] | None,
    list_hints: Any,
    topic_cards: Sequence[Any] | None,
    topic_details: Sequence[Any] | None,
    stage: str,
    model: str | None = None,
) -> list[Any]:
    """Call the classify layer's topic-match seam and return its verdict list.

    Reconciled onto the classify layer's ACTUAL interface ( seam-mismatch
    fix): the real method is the fail-open async wrapper

        ``async classify_with_topics_safe(message, categories, list_hints, *,
        topic_block: str, model=None) -> TopicMatchResult``

    so this matcher (a) assembles the per-stage ``topic_block`` suffix via the
    prompts helpers, (b) ``await``\\s the SAFE wrapper (which already owns the
    §4.4 fail-open — it never raises on a topic/parse miss), and (c) reads
    ``result.topic_verdicts``. We no longer pass the old
    ``topic_cards=/topic_details=/stage=`` kwargs (they were never the real
    signature — the un-awaited mismatch was the production bug: a coroutine
    swallowed as zero verdicts).

    Still defends in depth: should the wrapper itself raise (it is not supposed
    to), we fail open to ``[]`` here too — a flaky GPU degrades the Topic
    digest, never core triage (§4.4).
    """
    block = _build_topic_block(
        stage, topic_cards=topic_cards, topic_details=topic_details,
    )
    try:
        result = await classifier.classify_with_topics_safe(
            message,
            categories or {},
            list_hints,
            topic_block=block,
            model=model,
        )
    except Exception as exc:  # noqa: BLE001 — defence in depth (§4.4)
        log.warning(
            "topic_matcher: classify_with_topics_safe raised; dropping verdicts",
            extra={"_extra": {"stage": stage, "error_type": type(exc).__name__}},
        )
        return []

    if result is None:
        return []
    # The SAFE wrapper returns a TopicMatchResult carrying the verdict array.
    # Stay duck-typed (bare list / dict / object) so a minimal mock and the
    # real TopicMatchResult are both accepted.
    if isinstance(result, list):
        return result
    verdicts = getattr(result, "topic_verdicts", None)
    if verdicts is None and isinstance(result, dict):
        verdicts = result.get("topic_verdicts")
    return list(verdicts or [])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def match_topics_for_message(
    message: Any,
    active_topics: Sequence[Any],
    classifier: Any,
    *,
    body_keywords: Iterable[str] | None = None,
    k: int = K,
    categories: dict[str, str] | None = None,
    list_hints: Any = None,
) -> list[Any]:
    """Match one message against the user's active Topics; return verdicts.

    Runs the committed §4.1 pipeline:

    1. **Stage 0 (cheap, deterministic).** :func:`rank_candidates` ranks every
       active Topic against the message's cheap header + ``body_keywords``
       signals. This NEVER drops a Topic below the band — it only orders and
       picks which top-``k`` get full Details.
    2. **Band decision.** Let the top-``k`` ranked Topics be the full-Details
       candidates. If the number of admitted Topics is ``≤ k`` → ONE
       ``stage='single'`` call with those Topics inlined as full Details. If
       ``> k`` → ``stage='coarse'`` over ALL admitted Topics as cards →
       shortlist ``S`` (matched verdicts) → ONE ``stage='rerank'`` call over
       full Details of only ``S``.
    3. **Return** the matched verdicts (the things the caller turns into
       ``topic_hits``).

    ``message`` is the provider-normalised :class:`EmailMessage` (or any object
    exposing ``.headers``); the pre-filter reads only its headers +
    ``body_keywords`` (cheap signals the caller already extracted). ``classifier``
    is any object exposing the classify layer's ACTUAL topic-match seam —
    ``async classify_with_topics_safe(message, categories, list_hints, *,
    topic_block: str, model=None) -> TopicMatchResult`` — the real classify
    layer in production, a mock in tests. This is an **async** coroutine: the
    seam is awaited (the earlier sync call was the  production bug — an
    un-awaited coroutine swallowed as zero verdicts).

    ``categories`` / ``list_hints`` are the SAME taxonomy + hints the message's
    normal classify pass used. **Pass them explicitly** — the topic-match call
    re-classifies the message, and its taxonomy gate
    (``classify_with_topics``) drops every verdict (fail-open) when the parsed
    category is not in ``categories``. The production classifier never carries
    ``.categories`` (categories are a classify *argument*, not an attribute), so
    omitting them resolves to ``{}`` and silently yields ZERO verdicts on every
    real path — the  categories-threading bug. When omitted, they fall back
    to the classifier's own ``.categories`` / ``.list_hints`` only for a mock
    that stamps them.

    This returns EVERY matched verdict (with its confidence) — the digest
    confidence floor is NOT applied here. It is applied at SURFACE time in
    :func:`topic_configs.gather_live_topic_hits`, reading the persisted
    ``topic_hits.confidence``, so the floor stays reversible (operator
    2026-06-15).

    **Fail-open:** the SAFE wrapper never raises on a topic/parse miss, and this
    orchestrator additionally fails open to ``[]`` on any unexpected raise — so
    core triage is decoupled from a Topic-match failure (§4.4).
    """
    topics = list(active_topics or [])
    if not topics:
        return []

    headers = getattr(message, "headers", None) or {}

    # Stage 0 — rank (never drops below the band; |C| == len(active)).
    index = TopicSignalIndex.build(topics)
    candidates = rank_candidates(
        topics, headers, body_keywords, index=index,
    )
    if not candidates:
        return []

    lookup = _topic_lookup(topics)
    #  categories-threading fix — the taxonomy gate inside
    # ``classify_with_topics`` rejects (fail-open → ZERO verdicts) any
    # category not in ``categories``. The production classifier
    # (``_build_classifier_from_config``) carries NO ``.categories``
    # attribute — every real classify passes them as a CALL ARG — so the
    # classifier-resolution fallback yields ``{}`` and the gate fails every
    # match open. Callers therefore pass the REAL ``categories`` (and
    # ``list_hints``) explicitly; the classifier-resolution path remains
    # only for a duck-typed mock that stamps ``.categories`` itself.
    categories = (
        categories if categories is not None
        else _resolve_categories(classifier)
    )
    list_hints = (
        list_hints if list_hints is not None
        else _resolve_list_hints(message, classifier)
    )

    # The top-k ranked Topics are the full-Details candidates; the rest would
    # be cards. The band test is on how many full-Details candidates there are
    # — i.e. whether the whole admitted set fits in a single precise call.
    full_details_candidates = candidates[:k]

    if len(candidates) <= k:
        # ≤ K → ONE precise call. Inline full Details of every candidate.
        #  C-V1.1 — _build_detail returns None for a Detail whose text
        # trips the V1 PHI gate (fail-closed); drop those so no leaky full
        # Details block reaches the LLM context.
        details = [
            d for d in (
                _build_detail(c, lookup.get(c.topic_id))
                for c in full_details_candidates
            )
            if d is not None
        ]
        if not details:
            # Every candidate's Details were dropped by the PHI gate — no
            # safe payload to send, so no verdicts (fail-closed no-op).
            return []
        verdicts = await _safe_classify_with_topics(
            classifier, message,
            categories=categories, list_hints=list_hints,
            topic_cards=None, topic_details=details, stage="single",
        )
        return _matched_verdicts(verdicts)

    # > K → two-stage. Stage A (coarse): ALL admitted Topics as cards.
    #  C-V1.1 — _build_card returns None for a card whose text trips the
    # V1 PHI gate (fail-closed); filter those out so no leaky compact card
    # reaches the LLM context. A dropped card is a recall no-op (§4.4).
    cards = []
    for c in candidates:
        topic = lookup.get(c.topic_id)
        corpus = [t for tid, t in lookup.items() if tid != c.topic_id]
        card = _build_card(c, topic, corpus)
        if card is not None:
            cards.append(card)

    coarse_verdicts = await _safe_classify_with_topics(
        classifier, message,
        categories=categories, list_hints=list_hints,
        topic_cards=cards, topic_details=None, stage="coarse",
    )
    shortlist = _matched_verdicts(coarse_verdicts)
    if not shortlist:
        return []

    # Stage B (rerank): full Details of ONLY the shortlist S.
    shortlist_ids = {_verdict_topic_id(v) for v in shortlist}
    shortlist_candidates = [c for c in candidates if c.topic_id in shortlist_ids]
    #  C-V1.1 — drop any shortlist Detail whose text trips the V1 PHI gate
    # (fail-closed) before the rerank call.
    rerank_details = [
        d for d in (
            _build_detail(c, lookup.get(c.topic_id))
            for c in shortlist_candidates
        )
        if d is not None
    ]
    if not rerank_details:
        # Shortlist ids didn't map to any candidate (defensive) OR every
        # shortlist Detail was dropped by the PHI gate — the coarse verdicts
        # are the best we safely have; return the matched ones.
        return shortlist

    rerank_verdicts = await _safe_classify_with_topics(
        classifier, message,
        categories=categories, list_hints=list_hints,
        topic_cards=None, topic_details=rerank_details, stage="rerank",
    )
    return _matched_verdicts(rerank_verdicts)


# ---------------------------------------------------------------------------
# Resolving the classify-pass context (categories + list hints).
#
# The topic match rides the SAME classify pass that already runs on the
# message (design §1), so categories + list_hints are the same inputs the
# normal classify uses. We read them off the classifier when it exposes them
# (the back-scan job wires them through), and tolerate their absence — the
# Topic block is a pure suffix, so an empty categories dict still yields a
# usable match prompt.
# ---------------------------------------------------------------------------

def _resolve_categories(classifier: Any) -> dict[str, str]:
    cats = getattr(classifier, "categories", None)
    if isinstance(cats, dict):
        return cats
    return {}


def _resolve_list_hints(message: Any, classifier: Any) -> Any:
    # An explicit per-call hint set off the message (set by the caller) wins;
    # else the classifier's own default; else None.
    hints = getattr(message, "list_hints", None)
    if hints is not None:
        return hints
    return getattr(classifier, "list_hints", None)


__all__ = [
    "match_topics_for_message",
]
