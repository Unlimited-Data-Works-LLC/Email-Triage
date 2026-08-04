""" Topic-digest recall harness — the §4.7 "Farm Animals" mechanism.

Design doc ``internal documentation`` §4.7 commits to
a recall-calibration harness: a labelled corpus of synthetic, non-PHI emails
crossed with arbitrary Topics (incl. deliberately non-medical ones like
"Farm Animals" / "dirt bikes", per design R9 "pattern-match anything you
want — maybe Farm Animals — and see if it finds it"), spanning the hard
failure modes:

  * **oblique** — the email is about the Topic but never names it directly;
  * **no-identifier** — no registry id / sponsor / list-id signal at all;
  * **unknown-sender** — a From domain the operator never configured;
  * **paraphrase** — the Topic vocabulary appears only as a synonym.

The harness has TWO measurement layers:

  1. **Deterministic pre-filter recall (RUNS IN CI).** The Stage-0 pre-filter
     (:mod:`email_triage.actions.topic_prefilter`) is a *prioritizer*, never
     a recall gate — below the always-on band ``B`` it ADMITS every active
     Topic regardless of signal. So "pre-filter recall" = fraction of the
     corpus's true (email, Topic) matches whose Topic the pre-filter ADMITS
     for that email. Below ``B`` this is **1.0 by construction** — every
     Topic is admitted, so every true match is admitted, INCLUDING the
     oblique / no-identifier / unknown-sender / paraphrase rows that score 0.
     This is the headline guarantee the harness exists to pin: a cheap-signal
     miss is *score 0, not exclusion*. **This part runs in CI** — pure logic,
     no LLM, no network.

  2. **Live end-to-end recall (MANUAL INTEGRATION, skip-marked).** The
     ``≥0.95`` recall gate is a property of the *whole* pipeline (pre-filter
     → real LLM coarse/precise pass). It can only be measured against a live
     matcher (Ollama on llm-host), so it **cannot run in CI**. It is gated on
     ``EMAIL_TRIAGE_TEST_OLLAMA_URL`` and skips cleanly when unset. The
     harness STRUCTURE it uses (corpus + labels + the recall computation) is
     the same one the CI tests exercise — only the *matcher* is swapped from
     "admit-all pre-filter" to "real LLM".

No PHI anywhere — the corpus is goats, dirt bikes, sourdough, and clinical-
trial registry ids that are public lookup identifiers, never patient data.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import pytest

from email_triage.actions.topic_prefilter import (
    B,
    admit,
    rank_candidates,
)


# ---------------------------------------------------------------------------
# Corpus model — a labelled synthetic email + the failure mode it probes.
# ---------------------------------------------------------------------------

# Failure modes from design §4.7. Each labelled match carries the mode it is
# designed to stress so a future recall regression can be attributed.
MODE_OBLIQUE = "oblique"            # about the Topic, never names it
MODE_NO_IDENTIFIER = "no_identifier"   # zero registry/sponsor/list-id signal
MODE_UNKNOWN_SENDER = "unknown_sender"  # From a domain the operator never set
MODE_PARAPHRASE = "paraphrase"     # Topic vocab only as a synonym
MODE_DIRECT = "direct"             # the easy case (strong signal) — baseline

FAILURE_MODES = frozenset({
    MODE_OBLIQUE, MODE_NO_IDENTIFIER, MODE_UNKNOWN_SENDER, MODE_PARAPHRASE,
})


@dataclass(frozen=True)
class Email:
    """One synthetic, non-PHI email in the corpus."""

    eid: str
    headers: dict
    body_keywords: tuple[str, ...] = ()
    # The set of Topic names this email TRULY belongs to (ground truth).
    true_topics: frozenset = field(default_factory=frozenset)
    # For each true topic, the failure mode this row is designed to probe.
    modes: dict = field(default_factory=dict)


def _topic(name, subjects, details="", account_ids=(1,), tid=None):
    """A TopicConfig-shaped dict — the pre-filter accepts dicts or objects."""
    d = {
        "name": name,
        "subjects": list(subjects),
        "details": details,
        "selected_account_ids": list(account_ids),
    }
    if tid is not None:
        d["id"] = tid
    return d


# ---------------------------------------------------------------------------
# The arbitrary, non-medical Topics (design R9) + a couple of study Topics so
# the corpus also exercises registry-id signals. Names double as ground-truth
# labels — the pre-filter stamps Candidate.topic_id from the Topic's name when
# no explicit id is present (we use names as ids for readability).
# ---------------------------------------------------------------------------

def build_topics() -> list[dict]:
    return [
        _topic(
            "Farm Animals",
            subjects=["goats", "alpacas", "chickens"],
            details="livestock husbandry, pasture rotation, barn",
            tid="Farm Animals",
        ),
        _topic(
            "Dirt Bikes",
            subjects=["motocross", "enduro", "two-stroke"],
            details="trail riding, knobby tyres, suspension",
            tid="Dirt Bikes",
        ),
        _topic(
            "Sourdough",
            subjects=["sourdough", "levain"],
            details="bread baking, hydration, fermentation, starter",
            tid="Sourdough",
        ),
        _topic(
            "SELENA Lupus Study",
            subjects=["SELENA", "lupus", "estrogen"],
            details="NCT00000419 NYU Langone, autoimmune cohort",
            tid="SELENA Lupus Study",
        ),
    ]


def _h(*, frm="", subject="", list_id="", message_id=""):
    h = {}
    if frm:
        h["From"] = frm
    if subject:
        h["Subject"] = subject
    if list_id:
        h["List-Id"] = list_id
    if message_id:
        h["Message-ID"] = message_id
    return h


def build_corpus() -> list[Email]:
    """A labelled synthetic corpus spanning the §4.7 failure modes.

    Every true match is annotated with the failure mode it is designed to
    probe. Several rows deliberately carry NO cheap signal for their true
    Topic (score 0) — those are the rows the always-on band must still admit.
    """
    return [
        # --- DIRECT (strong signal — the easy baseline) -------------------
        Email(
            eid="e-direct-farm",
            headers=_h(
                frm="alerts@farm.example",
                subject="Weekly goats and alpacas barn update",
            ),
            body_keywords=("goats", "pasture"),
            true_topics=frozenset({"Farm Animals"}),
            modes={"Farm Animals": MODE_DIRECT},
        ),
        Email(
            eid="e-direct-study",
            headers=_h(
                frm="registry@clinicaltrials.gov",
                subject="Update on NCT00000419 enrollment",
                message_id="<nct@clinicaltrials.gov>",
            ),
            true_topics=frozenset({"SELENA Lupus Study"}),
            modes={"SELENA Lupus Study": MODE_DIRECT},
        ),
        # --- OBLIQUE (about the Topic, never names it) --------------------
        Email(
            eid="e-oblique-farm",
            headers=_h(
                frm="newsletter@unrelated-host.example",
                subject="Notes from the homestead this autumn",
            ),
            # talks around it: "the herd", "the meadow" — no Topic term
            # (deliberately scores 0 for Farm Animals on cheap signal)
            body_keywords=("herd", "meadow", "springtime"),
            true_topics=frozenset({"Farm Animals"}),
            modes={"Farm Animals": MODE_OBLIQUE},
        ),
        # --- NO-IDENTIFIER (zero registry/sponsor/list-id) ----------------
        Email(
            eid="e-noid-bikes",
            headers=_h(
                frm="someone@webmail.example",
                subject="Saturday plans?",
            ),
            body_keywords=("ride", "trail"),
            true_topics=frozenset({"Dirt Bikes"}),
            modes={"Dirt Bikes": MODE_NO_IDENTIFIER},
        ),
        # --- UNKNOWN-SENDER (From a domain never configured) --------------
        Email(
            eid="e-unknown-study",
            headers=_h(
                frm="random@nobody-knows.example",
                subject="lupus cohort logistics",
            ),
            body_keywords=("lupus",),
            true_topics=frozenset({"SELENA Lupus Study"}),
            modes={"SELENA Lupus Study": MODE_UNKNOWN_SENDER},
        ),
        # --- PARAPHRASE (Topic vocab only as a synonym) -------------------
        Email(
            eid="e-paraphrase-bread",
            headers=_h(
                frm="baker@unrelated.example",
                subject="my wild-yeast loaf finally rose",
            ),
            # "wild yeast" / "loaf" paraphrase "sourdough" / "levain"
            body_keywords=("wild-yeast", "loaf"),
            true_topics=frozenset({"Sourdough"}),
            modes={"Sourdough": MODE_PARAPHRASE},
        ),
        # --- A TRUE NEGATIVE (matches no Topic) — recall denominator guard -
        Email(
            eid="e-negative",
            headers=_h(
                frm="billing@utility.example",
                subject="Your statement is ready",
            ),
            body_keywords=("invoice", "kilowatt"),
            true_topics=frozenset(),
            modes={},
        ),
    ]


# ---------------------------------------------------------------------------
# The recall mechanism — generic over a "matcher" that, given (email, topics),
# returns the SET OF TOPIC NAMES it ADMITS for that email. The deterministic
# pre-filter and (manually) the live LLM both plug into this same computation.
# ---------------------------------------------------------------------------

def prefilter_admitted(email: Email, topics: list[dict], *, band: int = B) -> set:
    """The set of Topic names the deterministic pre-filter ADMITS for ``email``.

    Below/at the band, ``admit`` returns EVERY active Topic (full_details +
    cards partition the whole candidate set) — so admitted == all topic names.
    Above the band, every Topic is still admitted (as cards); admitted is
    still the whole set. The pre-filter never drops on a cheap-signal miss.
    """
    decision = admit(topics, email.headers, email.body_keywords, band=band)
    admitted = decision.full_details + decision.cards
    return {c.topic_id for c in admitted}


def compute_recall(corpus: list[Email], topics: list[dict], matcher) -> float:
    """Pre-filter recall = (#true matches admitted) / (#true matches).

    ``matcher(email, topics) -> set[topic_name]`` is the admit function. A
    corpus with zero true matches returns 1.0 (vacuously) — guarded by the
    caller's assertion that the corpus actually carries true matches.
    """
    admitted_true = 0
    total_true = 0
    for email in corpus:
        admitted = matcher(email, topics)
        for t in email.true_topics:
            total_true += 1
            if t in admitted:
                admitted_true += 1
    if total_true == 0:
        return 1.0
    return admitted_true / total_true


def recall_by_mode(corpus: list[Email], topics: list[dict], matcher) -> dict:
    """Recall broken down per failure mode (oblique / no_identifier / …)."""
    hit: dict = {}
    tot: dict = {}
    for email in corpus:
        admitted = matcher(email, topics)
        for t in email.true_topics:
            mode = email.modes.get(t, MODE_DIRECT)
            tot[mode] = tot.get(mode, 0) + 1
            if t in admitted:
                hit[mode] = hit.get(mode, 0) + 1
    return {m: hit.get(m, 0) / tot[m] for m in tot}


# ===========================================================================
# CI tests — deterministic pre-filter recall + the always-on band mechanism.
# ===========================================================================


class TestHarnessStructure:
    """The corpus + label structure is well-formed (guards the recall math
    against a corpus that silently lost its true matches)."""

    def test_corpus_has_true_matches_across_every_failure_mode(self):
        corpus = build_corpus()
        modes_seen = set()
        total_true = 0
        for email in corpus:
            total_true += len(email.true_topics)
            modes_seen.update(email.modes.values())
        assert total_true >= 6, "corpus must carry enough true matches to measure"
        # Every §4.7 failure mode is represented.
        assert FAILURE_MODES <= modes_seen, (
            f"corpus is missing failure mode(s) {FAILURE_MODES - modes_seen}"
        )

    def test_corpus_has_a_true_negative(self):
        """At least one email matches no Topic — so 'admit all' below the band
        is exercised against a row that genuinely should not match (the LLM,
        not the pre-filter, is what rejects it later)."""
        corpus = build_corpus()
        assert any(not e.true_topics for e in corpus)

    def test_topic_count_is_below_the_band(self):
        """The corpus's Topic set sits below ``B`` — so the always-on band is
        the regime under test (admit-all). If a future edit pushes the Topic
        count over ``B`` this test flags that the band-regime assertion below
        no longer holds for this fixture."""
        assert len(build_topics()) <= B


class TestDeterministicPrefilterRecall:
    """Below the band, the pre-filter admits every true match — recall 1.0
    by construction, INCLUDING the score-0 failure-mode rows."""

    def test_overall_prefilter_recall_is_one_below_band(self):
        topics = build_topics()
        corpus = build_corpus()
        assert len(topics) <= B  # regime guard
        recall = compute_recall(corpus, topics, prefilter_admitted)
        assert recall == 1.0, (
            f"below the always-on band B={B} the pre-filter must admit EVERY "
            f"true match (a cheap-signal miss is score 0, not exclusion); "
            f"got recall={recall}"
        )

    def test_recall_is_one_for_each_failure_mode(self):
        """Per-mode: oblique / no-identifier / unknown-sender / paraphrase all
        recall 1.0 below the band — these are exactly the rows that score 0 on
        cheap signal yet must still be admitted."""
        topics = build_topics()
        corpus = build_corpus()
        by_mode = recall_by_mode(corpus, topics, prefilter_admitted)
        for mode in FAILURE_MODES:
            assert by_mode.get(mode) == 1.0, (
                f"failure mode {mode!r} lost a true match below the band "
                f"(recall={by_mode.get(mode)}); the always-on band is broken"
            )

    def test_score_zero_rows_are_still_admitted(self):
        """Directly assert the mechanism: a row that scores 0 for its true
        Topic (no cheap signal at all) is STILL in the admitted set. This is
        the structural guarantee that |C| = 0 is impossible below the band."""
        topics = build_topics()
        # The oblique farm email scores 0 for "Farm Animals" (no Topic term,
        # unknown sender, no registry id).
        oblique = next(e for e in build_corpus() if e.eid == "e-oblique-farm")
        ranked = rank_candidates(topics, oblique.headers, oblique.body_keywords)
        farm = next(c for c in ranked if c.topic_id == "Farm Animals")
        assert farm.score == 0.0, (
            "fixture sanity: the oblique row should score 0 for Farm Animals "
            "(if it scored > 0 the test isn't exercising the score-0 path)"
        )
        # …yet it is admitted.
        admitted = prefilter_admitted(oblique, topics)
        assert "Farm Animals" in admitted, (
            "a score-0 true match must still be admitted below the band"
        )

    def test_admission_partitions_the_whole_candidate_set(self):
        """full_details + cards together cover EVERY active Topic for every
        email — nothing is dropped, in either band regime."""
        topics = build_topics()
        for email in build_corpus():
            decision = admit(topics, email.headers, email.body_keywords)
            covered = {c.topic_id for c in decision.full_details}
            covered |= {c.topic_id for c in decision.cards}
            all_topic_ids = {t["id"] for t in topics}
            assert covered == all_topic_ids, (
                f"email {email.eid}: admitted set {covered} != all topics "
                f"{all_topic_ids}"
            )


class TestAlwaysOnBandMechanism:
    """Pin the band mechanism directly: at/below ``B`` Topics, EVERY Topic is
    admitted regardless of signal; the recall floor is structural."""

    def test_admit_returns_all_topics_below_band(self):
        topics = build_topics()  # 4 topics, well below B
        # An email with a signal that hits ONLY one Topic.
        email = Email(
            eid="probe",
            headers=_h(subject="goats"),  # hits Farm Animals only
            true_topics=frozenset({"Farm Animals"}),
        )
        decision = admit(topics, email.headers, email.body_keywords)
        admitted = {c.topic_id for c in decision.full_details + decision.cards}
        assert admitted == {t["id"] for t in topics}, (
            "below the band, a single-Topic signal must still admit ALL Topics"
        )

    def test_synthetic_recall_one_when_count_below_band(self):
        """Construct N topics for N < B with an email that matches NONE of
        their signals; recall is 1.0 because every topic is admitted."""
        topics = [
            _topic(f"T{i}", subjects=[f"term{i}"], tid=f"T{i}")
            for i in range(B - 1)  # strictly below the band
        ]
        # An email whose signals hit no topic.
        email = Email(
            eid="nohit",
            headers=_h(subject="completely unrelated content"),
            true_topics=frozenset(t["id"] for t in topics),  # pretend all true
        )
        recall = compute_recall([email], topics, prefilter_admitted)
        assert recall == 1.0

    def test_above_band_still_admits_all_as_cards(self):
        """Even ABOVE the band, every Topic is admitted (as a card) — the
        pre-filter overflow is over-admit, never a silent drop (§4.1)."""
        topics = [
            _topic(f"T{i}", subjects=[f"term{i}"], tid=f"T{i}")
            for i in range(B + 5)  # over the band
        ]
        email = Email(
            eid="probe",
            headers=_h(subject="term3"),  # hits exactly one
            true_topics=frozenset(t["id"] for t in topics),
        )
        decision = admit(topics, email.headers, email.body_keywords)
        assert decision.above_band is True
        admitted = {c.topic_id for c in decision.full_details + decision.cards}
        assert admitted == {t["id"] for t in topics}, (
            "above the band every Topic must still be admitted (as a card)"
        )
        recall = compute_recall([email], topics, prefilter_admitted)
        assert recall == 1.0


# ===========================================================================
# MANUAL INTEGRATION — live-LLM end-to-end recall ≥ 0.95 against Ollama/llm-host.
#
# This CANNOT run in CI: it needs a live matcher (the real LLM coarse/precise
# pass), which is non-deterministic + network-bound. It is gated on
# ``EMAIL_TRIAGE_TEST_OLLAMA_URL`` and skips cleanly when unset — exactly the
# pattern the real-Redis integration test uses
# (``tests/test_cache/test_classification_redis.py``).
#
# Run it (the MODEL is auto-detected from what's resident on the Ollama host —
# i.e. what prod actually serves — so you usually only pass the URL;
# EMAIL_TRIAGE_TEST_OLLAMA_MODEL is an optional explicit override)::
#
#     EMAIL_TRIAGE_TEST_OLLAMA_URL=http://llm-host:11434 \
#         pytest tests/test_topic_recall_harness.py -k live_llm
#
# The harness STRUCTURE (corpus + labels + compute_recall) is shared with the
# CI tests above — only the matcher is swapped for the real pipeline.
# ===========================================================================

_OLLAMA_URL = os.environ.get("EMAIL_TRIAGE_TEST_OLLAMA_URL", "")
_OLLAMA_MODEL = os.environ.get("EMAIL_TRIAGE_TEST_OLLAMA_MODEL", "")

#: The §4.7 acceptance gate. The live end-to-end recall over the labelled
#: corpus must meet or beat this to ship the calibration.
RECALL_GATE = 0.95


def _resolve_ollama_model(url: str) -> str:
    """Determine the model to test against DYNAMICALLY when the env doesn't pin
    one (feedback_dynamic_over_hardcoding — don't hardcode a model that drifts
    when the prod model changes): prefer what is RESIDENT on the Ollama instance
    (``/api/ps`` — the model prod keeps warm + actively serves), else the first
    AVAILABLE tag (``/api/tags``). Returns ``""`` if neither is reachable / both
    empty (the caller then skips)."""
    import json
    import urllib.request

    base = url.rstrip("/")
    for path in ("/api/ps", "/api/tags"):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as resp:
                models = json.load(resp).get("models") or []
        except Exception:
            continue
        if models:
            # /api/ps and /api/tags entries both carry "model" (and "name").
            name = models[0].get("model") or models[0].get("name") or ""
            if name:
                return name
    return ""


def _live_matcher_or_skip() -> str:
    """Skip cleanly unless a live Ollama matcher is reachable; RETURN the model
    to test against.

    The model is resolved DYNAMICALLY from the running Ollama (what's resident —
    i.e. what prod actually serves) when ``EMAIL_TRIAGE_TEST_OLLAMA_MODEL`` is
    not pinned, so the calibration always tests the REAL deployed model and
    never a hardcoded literal that goes stale (feedback_dynamic_over_hardcoding;
    the env var stays an explicit override). Mirrors ``_redis_or_skip`` in the
    real-Redis integration test: a plain ``pytest tests/`` on a box without a
    live LLM skips this entirely — the LLM is NOT a hard test dependency.
    """
    if not _OLLAMA_URL:
        pytest.skip(
            "EMAIL_TRIAGE_TEST_OLLAMA_URL not set — live-LLM recall is a "
            "MANUAL integration test (needs Ollama on llm-host); the "
            "deterministic pre-filter recall in this file runs in CI instead"
        )
    model = _OLLAMA_MODEL or _resolve_ollama_model(_OLLAMA_URL)
    if not model:
        pytest.skip(
            f"no Ollama model resident/available at {_OLLAMA_URL} and "
            "EMAIL_TRIAGE_TEST_OLLAMA_MODEL not set — cannot determine a model"
        )
    return model


# NOTE: gated purely via ``skipif`` (no bare ``@pytest.mark.integration`` — the
# marker is unregistered in this repo and would only emit a PytestUnknownMark
# warning; the env-var skip is the real gate, matching the real-Redis
# integration test's pattern).
@pytest.mark.skipif(
    not _OLLAMA_URL,
    reason=(
        "live-LLM end-to-end recall (>=0.95) is a MANUAL integration test — "
        "set EMAIL_TRIAGE_TEST_OLLAMA_URL to run against a live Ollama/llm-host; "
        "CI exercises the deterministic pre-filter recall + band mechanism"
    ),
)
class TestLiveLlmRecallManualIntegration:
    """End-to-end recall against a REAL Ollama matcher — manual only."""

    async def test_live_llm_recall_meets_gate(self):
        """The whole pipeline (pre-filter → real LLM verdicts) must admit
        ≥ RECALL_GATE of the labelled corpus's true matches.

        Builds a real classifier pointed at the test Ollama, runs the REAL
        ``match_topics_for_message`` per (email, topic), and feeds the result
        into the SAME ``compute_recall`` the CI tests use — only the matcher
        is live."""
        model = _live_matcher_or_skip()

        from email_triage.actions.topic_matcher import match_topics_for_message
        from email_triage.actions.topic_configs import TopicConfig
        from email_triage.classify.ollama import OllamaClassifier  # type: ignore

        topics_dicts = build_topics()
        # Hydrate into TopicConfig objects with stable ids for the live path.
        topics = [
            TopicConfig(
                id=i + 1,
                user_id=1,
                name=t["name"],
                subjects=t["subjects"],
                details=t["details"],
                selected_account_ids=[1],
            )
            for i, t in enumerate(topics_dicts)
        ]
        name_by_id = {t.id: t.name for t in topics}

        classifier = OllamaClassifier(
            base_url=_OLLAMA_URL, model=model,
        )

        from datetime import datetime, timezone

        from email_triage.engine.models import EmailMessage

        def _live_msg(email: Email) -> EmailMessage:
            # A REAL EmailMessage, not an ad-hoc stub: the classify path reads
            # .sender / .subject / .recipients / .date / .body_text
            # (build_email_block) + .headers (self-origin check). An incomplete
            # stub raised AttributeError on .sender, so the matcher fell open to
            # "no verdicts" (correct fail-closed-on-match) and the harness
            # measured a FALSE recall 0.000 — a test-double bug, not the LLM.
            h = dict(email.headers)
            return EmailMessage(
                message_id=h.get("Message-ID", email.eid),
                provider="imap",
                sender=h.get("From", ""),
                recipients=["pi@lab.example"],
                subject=h.get("Subject", ""),
                body_text=" ".join(email.body_keywords),
                date=datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc),
                headers=h,
            )

        async def _live_matcher_async(email: Email) -> set:
            msg = _live_msg(email)
            verdicts = await match_topics_for_message(
                msg, topics, classifier,
                body_keywords=email.body_keywords,
                # Thread the taxonomy EXPLICITLY (the  categories-threading
                # contract): the topic-match re-classifies, and its taxonomy
                # gate drops EVERY verdict (fail-open) if the parsed category
                # isn't in `categories`. Prod callers pass the user's real
                # categories; the OllamaClassifier carries none, so omitting
                # them resolves to {} -> zero verdicts. Any realistic taxonomy
                # works for the recall measurement (we score topic_verdicts,
                # not the chosen category).
                categories={
                    "to-respond": "Emails that need a reply from you",
                    "fyi": "Informational, no action needed",
                    "newsletters": "Subscriptions and recurring content",
                    "comments": "Mentions, comments, notifications from tools",
                },
            )
            out = set()
            for v in verdicts or ():
                tid = getattr(v, "topic_id", None)
                out.add(name_by_id.get(tid, tid))
            return out

        corpus = build_corpus()

        # LLM matching is NON-DETERMINISTIC: on this 6-true-match corpus a single
        # borderline flip drops recall from 1.000 to 0.833 (the only value below
        # the gate the corpus can even reach), so ONE pass is a noisy estimator
        # of the true recall. Gate on the MEDIAN of a few passes — a faithful
        # estimate that is robust to ONE flip but NOT to a real >=2/N regression.
        # (Manual integration; each pass costs LLM round-trips, so N is small +
        # env-tunable.) Measured 2026-06-11 on qwen3.6:35b: 3/3 passes = 1.000.
        import statistics

        passes = int(os.environ.get("EMAIL_TRIAGE_TEST_RECALL_PASSES", "3"))
        per_pass: list[float] = []
        miss_log: dict = {}
        for _p in range(passes):
            admitted_true = total_true = 0
            for email in corpus:
                admitted = await _live_matcher_async(email)
                for t in email.true_topics:
                    total_true += 1
                    if t in admitted:
                        admitted_true += 1
                    else:
                        mode = email.modes.get(t, MODE_DIRECT)
                        key = (email.eid, t, mode)
                        miss_log[key] = miss_log.get(key, 0) + 1
            per_pass.append(admitted_true / total_true if total_true else 1.0)

        median_recall = statistics.median(per_pass)
        print(
            f"\n[#33 recall gate] model={model} passes={passes} "
            f"per_pass={[round(r, 3) for r in per_pass]} "
            f"median={median_recall:.3f} gate={RECALL_GATE}"
        )
        if miss_log:
            print(
                "[#33 recall gate] misses (eid,topic,mode -> #passes): "
                + "; ".join(
                    f"{k}->{n}" for k, n in
                    sorted(miss_log.items(), key=lambda kv: -kv[1])
                )
            )
        assert median_recall >= RECALL_GATE, (
            f"live end-to-end MEDIAN recall {median_recall:.3f} over {passes} "
            f"passes {[round(r, 3) for r in per_pass]} < gate {RECALL_GATE}; the "
            f"§4.7 calibration does not pass on model {model!r}. "
            f"Per-mode misses: "
            + "; ".join(f"{k}x{n}" for k, n in miss_log.items())
        )
