"""Tests for the  Topic-digest deterministic Stage-0 pre-filter.

Pure logic — NO PHI (arbitrary non-medical Topics per design R9: "pattern-match
anything you want — maybe Farm Animals — and see if it finds it"), NO network,
NO database. Proves the four contract properties from design doc §4.1:

  (a) below-band admits ALL Topics regardless of signal — the recall-floor
      guarantee: an email matching NO signal still admits every Topic, so
      |C| = 0 is structurally impossible (the headline test);
  (b) ranking orders by signal strength;
  (c) NCT / EudraCT / ISRCTN registry-id detection;
  (d) above-band still admits ALL Topics as cards (rank only picks which
      top-K get full Details).
"""

from __future__ import annotations

import pytest

from email_triage.actions.topic_prefilter import (
    B,
    K,
    Admission,
    Candidate,
    TopicSignalIndex,
    admit,
    derive_card_terms,
    extract_registry_ids,
    keyword_match,
    rank_candidates,
)


# ---------------------------------------------------------------------------
# Helpers — TopicConfig-shaped dicts (we depend only on the documented fields:
# name, subjects[list], details, selected_account_ids). No topic_configs
# import; the module accepts dicts OR objects.
# ---------------------------------------------------------------------------

def topic(name, subjects, details="", account_ids=(1,), tid=None):
    """A TopicConfig-shaped dict using only the documented fields."""
    d = {
        "name": name,
        "subjects": list(subjects),
        "details": details,
        "selected_account_ids": list(account_ids),
    }
    if tid is not None:
        d["id"] = tid
    return d


def headers(*, frm="", subject="", list_id="", message_id=""):
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


# A small set of arbitrary, non-medical Topics (design R9 — Farm Animals etc.).
def _farm_topics(n):
    pool = [
        topic("Farm Animals", ["Goats"], "alpine dairy goats and pygmy goats", tid=1),
        topic("Beekeeping", ["Apiary"], "langstroth hive honey bees", tid=2),
        topic("Vintage Tractors", ["John Deere"], "restoring antique tractors", tid=3),
        topic("Sourdough", ["Bread"], "wild yeast starter hydration", tid=4),
        topic("Astronomy Club", ["Telescopes"], "dobsonian reflector messier", tid=5),
        topic("Trail Running", ["Ultramarathon"], "vert elevation gels", tid=6),
        topic("Cheese Aging", ["Caves"], "affinage humidity rind", tid=7),
        topic("Woodworking", ["Joinery"], "dovetail mortise tenon", tid=8),
        topic("Birdwatching", ["Warblers"], "migration binoculars plumage", tid=9),
        topic("Home Brewing", ["IPA"], "hops malt fermentation", tid=10),
        topic("Pottery", ["Glazes"], "kiln cone reduction firing", tid=11),
        topic("Gardening", ["Tomatoes"], "heirloom compost trellis", tid=12),
        topic("Cycling", ["Gravel"], "tubeless drivetrain cassette", tid=13),
        topic("Chess Club", ["Openings"], "sicilian endgame blunder", tid=14),
    ]
    return pool[:n]


# ---------------------------------------------------------------------------
# (a) THE RECALL-FLOOR TEST — |C| = 0 is impossible below the band.
# ---------------------------------------------------------------------------

def test_recall_floor_below_band_admits_all_topics_on_zero_signal():
    """HEADLINE: an email that matches NO signal of ANY Topic still admits
    every active Topic below the band — |C| = 0 is structurally impossible.

    This is the fix for the vet's "unguarded recall floor" blocker (§4.1):
    the pre-filter ORDERS, it never DROPS, while active-Topic count <= B.
    """
    topics = _farm_topics(5)            # well below B = 12
    assert len(topics) <= B

    # An email that hits NONE of the Topics' signals — unknown sender, an
    # off-topic subject, an off-topic body keyword. The "oblique, keyword-free,
    # unknown-sender" case the design names (the SAE report analog).
    em = headers(
        frm="Totally Unrelated <stranger@nowhere.invalid>",
        subject="Lunch plans for Thursday",
    )

    ranked = rank_candidates(topics, em, cheap_body_keywords=["lunch", "thursday"])

    # Every Topic appears in the ranked output ...
    assert len(ranked) == len(topics)
    # ... every score is exactly 0 (nothing matched) ...
    assert all(c.score == 0.0 for c in ranked)
    # ... and yet NONE is excluded: the candidate set is the whole active set.
    assert {c.topic_id for c in ranked} == {t["id"] for t in topics}

    # The admission policy confirms |C| = 0 is impossible: full_details + cards
    # partition the full active set, nothing dropped.
    a = admit(topics, em, cheap_body_keywords=["lunch", "thursday"])
    assert isinstance(a, Admission)
    assert a.above_band is False
    admitted = a.full_details + a.cards
    assert len(admitted) == len(topics)
    assert {c.topic_id for c in admitted} == {t["id"] for t in topics}
    # top-K get full Details, the remainder are cards (here 5 <= K so all
    # are full Details, zero cards) — but admitted total is still the full set.
    assert len(a.full_details) == min(K, len(topics))
    assert len(a.cards) == max(0, len(topics) - K)


def test_recall_floor_holds_at_exactly_the_band():
    """Exactly B active Topics is still "below/at band" — all admitted."""
    topics = _farm_topics(B)
    assert len(topics) == B
    em = headers(frm="x@unknown.invalid", subject="nothing relevant here")
    a = admit(topics, em)
    assert a.above_band is False
    assert len(a.full_details) + len(a.cards) == B  # |C| = B, not 0


def test_signal_match_does_not_change_the_floor_below_band():
    """Below the band, a Topic that DOES match and one that does NOT are BOTH
    admitted — the match only changes ORDER, never membership."""
    topics = _farm_topics(4)
    # Email strongly matches "Beekeeping" only.
    em = headers(frm="news@apiary.example.org",
                 subject="Apiary honey harvest — langstroth hive tips")
    a = admit(topics, em, cheap_body_keywords=["hive", "honey", "bees"])
    admitted_ids = {c.topic_id for c in a.full_details + a.cards}
    assert admitted_ids == {t["id"] for t in topics}      # all 4 admitted
    # The matched Topic ranks first ...
    assert a.candidates[0].name == "Beekeeping"
    assert a.candidates[0].score > 0
    # ... and the unmatched Topics are present at score 0, not excluded.
    assert any(c.score == 0.0 for c in a.candidates)


# ---------------------------------------------------------------------------
# (b) Ranking orders by signal strength.
# ---------------------------------------------------------------------------

def test_ranking_orders_by_signal_strength():
    """A Topic with more / stronger signal hits ranks above a weaker one,
    which ranks above a no-signal Topic."""
    topics = [
        topic("Beekeeping", ["Apiary", "Langstroth"],
              "honey bees hive from news@apiary.example.org", account_ids=(1,), tid="bee"),
        topic("Gardening", ["Tomatoes"], "heirloom tomato compost", tid="garden"),
        topic("Chess", ["Openings"], "sicilian endgame", tid="chess"),
    ]
    # Email: from the beekeeping domain (strong) + subject keyword for bees,
    # plus a single weak gardening keyword, nothing for chess.
    em = headers(
        frm="alerts@apiary.example.org",
        subject="Langstroth hive honey — and a note on tomato companion planting",
    )
    ranked = rank_candidates(topics, em, cheap_body_keywords=["honey", "tomato"])

    names = [c.name for c in ranked]
    assert names[0] == "Beekeeping"      # domain + multiple keyword hits
    assert names[1] == "Gardening"       # one weak keyword hit
    assert names[2] == "Chess"           # no hit -> score 0, ranks last
    # Scores are monotonically non-increasing.
    scores = [c.score for c in ranked]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[1] > scores[2] == 0.0
    # why-matched evidence is the user's own public terms (not the body).
    assert any("apiary.example.org" == t or "honey" in t or "hive" in t
               for t in ranked[0].matched_terms)


def test_ranking_is_deterministic_on_ties():
    """Equal-score Topics break ties by topic_id — a stable, reproducible
    order so the top-K Details cut is not flaky."""
    topics = [
        topic("Z Topic", ["zzz"], "", tid="z"),
        topic("A Topic", ["aaa"], "", tid="a"),
        topic("M Topic", ["mmm"], "", tid="m"),
    ]
    em = headers(subject="nothing matches any of these")
    r1 = [c.topic_id for c in rank_candidates(topics, em)]
    r2 = [c.topic_id for c in rank_candidates(topics, em)]
    assert r1 == r2 == ["a", "m", "z"]   # all score 0, ordered by id


# ---------------------------------------------------------------------------
# (c) NCT / EudraCT / ISRCTN registry-id detection.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Update on NCT00000419 enrollment", {"NCT00000419"}),
    ("see study nct12345678 please", {"NCT12345678"}),        # case-insensitive
    ("EudraCT 2004-001234-12 amendment", {"2004-001234-12"}),
    ("Registered as ISRCTN12345678", {"ISRCTN12345678"}),
    ("isrctn87654321", {"ISRCTN87654321"}),                   # case-insensitive
    ("both NCT00000419 and ISRCTN12345678", {"NCT00000419", "ISRCTN12345678"}),
    ("no identifiers here at all", set()),
    ("NCT1234 too short, not a match", set()),                # wrong digit count
])
def test_extract_registry_ids(text, expected):
    assert extract_registry_ids(text) == expected


def test_registry_id_match_scores_and_is_evidence():
    """A configured registry id that appears in an email Subject is a strong
    signal and surfaces as why-matched evidence."""
    topics = [
        topic("SELENA study", ["SELENA"],
              "Safety of Estrogens in Lupus — NCT00000419", tid="selena"),
        topic("Other study", ["OTHER"], "EudraCT 2099-009999-99", tid="other"),
    ]
    idx = TopicSignalIndex.build(topics)
    # the index harvested the registry ids from operator config
    selena_sig = next(s for s in idx.signals if s.topic_id == "selena")
    assert "NCT00000419" in selena_sig.registry_ids

    em = headers(subject="Re: NCT00000419 site monitoring visit")
    ranked = rank_candidates(topics, em, index=idx)
    top = ranked[0]
    assert top.topic_id == "selena"
    assert top.score > 0
    assert "NCT00000419" in top.matched_terms


def test_eudract_and_isrctn_match_via_index():
    topics = [
        topic("EU trial", ["EUTrial"], "registered EudraCT 2004-001234-12", tid="eu"),
        topic("ISRCTN trial", ["UKTrial"], "ISRCTN12345678 in the UK", tid="uk"),
    ]
    a_eu = admit(topics, headers(subject="2004-001234-12 protocol amendment"))
    assert a_eu.candidates[0].topic_id == "eu"
    assert a_eu.candidates[0].score > 0

    a_uk = admit(topics, headers(subject="news for ISRCTN12345678"))
    assert a_uk.candidates[0].topic_id == "uk"
    assert a_uk.candidates[0].score > 0


# ---------------------------------------------------------------------------
# (d) Above the band, ALL Topics are still admitted (as cards).
# ---------------------------------------------------------------------------

def test_above_band_admits_all_as_cards():
    """> B active Topics: every Topic is STILL admitted (none dropped on a
    cheap-signal miss); the rank only decides which top-K get full Details and
    the rest become compact cards."""
    topics = _farm_topics(14)            # > B = 12
    assert len(topics) > B

    # An email matching nothing — the hostile recall case at scale.
    em = headers(frm="x@unknown.invalid", subject="completely unrelated memo")
    a = admit(topics, em)

    assert a.above_band is True
    # EVERY Topic admitted: full_details + cards == the whole active set.
    admitted = a.full_details + a.cards
    assert len(admitted) == len(topics)
    assert {c.topic_id for c in admitted} == {t["id"] for t in topics}
    # top-K get full Details; the remainder (still admitted) are cards.
    assert len(a.full_details) == K
    assert len(a.cards) == len(topics) - K
    # Cards carry derived card terms so the LLM-coarse pass has signal even
    # without full Details (auto-augment-from-Details, §4.1).
    assert all(isinstance(c.card_terms, tuple) for c in a.cards)


def test_above_band_rank_picks_which_get_full_details():
    """Above the band, a strongly-matching Topic is promoted into the
    full-Details slice even though all Topics remain admitted."""
    topics = _farm_topics(14)
    # Make the email match "Chess Club" (tid=14) strongly via its keyword.
    em = headers(subject="Sicilian opening blunder — endgame study",
                 frm="x@unknown.invalid")
    a = admit(topics, em, cheap_body_keywords=["sicilian", "endgame", "blunder"])
    assert a.above_band is True
    # Chess Club is promoted to full Details (top of the rank).
    full_ids = {c.topic_id for c in a.full_details}
    assert 14 in full_ids
    assert a.candidates[0].name == "Chess Club"
    # but NOTHING is dropped — the count invariant still holds.
    assert len(a.full_details) + len(a.cards) == len(topics)


# ---------------------------------------------------------------------------
# derive_card_terms — top-IDF, augmented from Details, registry-front-loaded.
# ---------------------------------------------------------------------------

def test_derive_card_terms_pulls_from_details_not_just_subjects():
    """Card terms include high-IDF Details terms, not only the operator's
    hand-picked Subject chip."""
    t = topic("SELENA", ["SELENA"],
              "estrogen lupus erythematosus hormone replacement", tid="s")
    terms = derive_card_terms(t)
    assert "selena" in terms                       # the chip/acronym
    # at least one distinctive Details term made it onto the card
    assert any(term in terms for term in ("estrogen", "lupus", "erythematosus", "hormone"))
    assert len(terms) <= 8


def test_derive_card_terms_front_loads_registry_ids():
    t = topic("Trial", ["MyStudy"], "details mention NCT00000419 prominently", tid="x")
    terms = derive_card_terms(t)
    assert "nct00000419" in terms
    # registry id is front-loaded (high signal)
    assert terms[0] == "nct00000419"


def test_idf_discriminates_shared_terms():
    """A term shared across many Topics ranks LOWER than a term unique to one,
    so a card surfaces the Topic's distinctive vocabulary."""
    shared = "weekly newsletter announcement"
    topics = [
        topic("Lupus research", ["Lupus"], f"{shared} lupus estrogen", tid="a"),
        topic("Beekeeping", ["Bees"], f"{shared} hive honey", tid="b"),
        topic("Gardening", ["Garden"], f"{shared} tomato compost", tid="c"),
    ]
    idx = TopicSignalIndex.build(topics)
    lupus = next(s for s in idx.signals if s.topic_id == "a")
    # the distinctive term outranks the shared boilerplate on the card.
    # NB: card terms are STEMMED ("lupus" -> "lupu", "newsletter" -> "newslett")
    # — the same stemming an inbound email's tokens get, so they still match.
    assert "lupu" in lupus.card_terms
    assert "newslett" in lupus.card_terms
    assert lupus.card_terms.index("lupu") < lupus.card_terms.index("newslett")


# ---------------------------------------------------------------------------
# Cross-cutting invariant — len(candidates) == len(active) at EVERY count.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 3, 6, 12, 13, 14])
def test_candidate_count_equals_active_count_at_all_sizes(n):
    """The structural |C| != 0 guarantee across the band boundary: the ranked
    candidate list always equals the active-Topic count — never fewer."""
    topics = _farm_topics(n)
    em = headers(frm="x@unknown.invalid", subject="no signal at all")
    ranked = rank_candidates(topics, em)
    assert len(ranked) == n
    a = admit(topics, em)
    assert len(a.full_details) + len(a.cards) == n
    assert len(a.candidates) == n


# ---------------------------------------------------------------------------
# keyword_match — the PRECISION Preview matcher (operator 2026-06-12)
# ---------------------------------------------------------------------------

class TestKeywordMatchPrecision:
    """The Preview keyword match must be PRECISION-oriented — match the
    operator's DELIBERATE Subject chips + structural signals (registry IDs,
    domains, List-Ids, sponsors), NEVER the Details free-text token bag. The
    bug it fixes: tokenizing Details prose into single words made every common
    word ("call", "free", "ai", "has", "open", "store") an OR-signal that
    matched every newsletter (operator-reported flood)."""

    def test_matches_subject_chip_back_to_readable_term(self):
        t = topic("T", ["MemPalace"], details="releases and assorted notes")
        assert keyword_match(
            t, {"Subject": "[MemPalace/mempalace] Release v3.3.5"}
        ) == ["MemPalace"]

    def test_does_not_match_details_prose_common_words(self):
        # Details prose mentions common words; a message hitting ONLY those
        # must NOT match (the exact flood the operator saw).
        t = topic("T", ["MemPalace"],
                  details="AI software, free calls, open store, has memory, design")
        for subj in (
            "Final call: Special offers end soon",
            "Make a Splash This Summer With Your AI Skills",
            "The free dumplings won't be free forever",
            "FINAL HOURS to save 40% on Ultra Open Earbuds!",
            "This Kitchen Scale Has a Wireless Screen",
        ):
            assert keyword_match(t, {"Subject": subj}) == [], subj

    def test_matches_registry_id_structural_signal(self):
        t = topic("T", ["lupus cohort"], details="tracking NCT00000419")
        out = keyword_match(t, {"Subject": "Update on NCT00000419 enrollment"})
        assert "NCT00000419" in out

    def test_no_subject_chips_yields_no_keyword_hit(self):
        # A Details-only Topic ⇒ the cheap Preview (Subject-driven) returns
        # nothing; the LLM "Test Details" step covers Details-only Topics.
        t = topic("T", [], details="AI and software and models and search")
        assert keyword_match(t, {"Subject": "New AI model released"}) == []

    def test_empty_headers_no_crash(self):
        t = topic("T", ["MemPalace"], details="")
        assert keyword_match(t, {}) == []
        assert keyword_match(t, None) == []
