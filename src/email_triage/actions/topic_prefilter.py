""" Topic-digest deterministic Stage-0 pre-filter.

A *prioritizer*, never a recall gate. This module builds a per-user
:class:`TopicSignalIndex` from **operator-configured signals only** and ranks
the user's active Topics against an inbound email's cheap signals (headers +
already-extracted body keywords). It does **not** decide whether a Topic
matches — that is the LLM's job inside the primary classify pass
(``engine/flow.py``). All this module decides is **order** and, above the
always-on band, **which Topics get full Details vs a compact card**.

The single load-bearing guarantee (design doc §4.1):

    The pre-filter orders Topics; it never drops them while the user's
    active-Topic count is <= the always-on band ``B`` (committed ``B = 12``).
    Below ``B``, every active Topic is admitted regardless of signal — so an
    oblique, keyword-free, unknown-sender study email is ALWAYS seen by the
    LLM. ``|C| = 0`` is structurally impossible for a user with <= ``B``
    active Topics.

Above ``B`` the LLM-coarse pass becomes the recall floor: ALL Topics are still
admitted, but as compact CARDS (name + a few terms); the cheap score only sets
card *order* and picks which top-``K`` get full Details. Nothing is dropped on
a cheap-signal miss at any count — a miss is **score 0, not exclusion**.

Provenance discipline (design doc §4.3): every signal in the index is a
deterministic restatement of operator-typed Topic config — sender domains /
list-IDs the operator wrote, registry identifiers found in Subject/Details,
sponsor/CRO names, condition keywords from ``subjects`` + ``details``. The
pre-filter learns **nothing** from message bodies. There is no
``sender -> Topic`` affinity store; keeping the index config-derived keeps the
"PHI-free signals" claim true by construction. **No embedding signal** is used
(design doc N17): this is keyword / IDF only, deliberately, so no future
contributor re-wires the  e5 embedder in and reintroduces a vector + a
differently-gated egress path.

This module depends only on the documented ``TopicConfig`` *fields*
(``name``, ``subjects`` list, ``details``, ``selected_account_ids``). It does
**not** import ``topic_configs`` or any DB code — it operates on a
TopicConfig-shaped object or a plain dict, so it stays pure logic, testable
with no PHI, no network, and no database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from math import log
from typing import Any, Iterable, Mapping, Sequence


# ---------------------------------------------------------------------------
# Module constants — the band and K are part of the public contract (§4.1).
# ---------------------------------------------------------------------------

#: Always-on recall band. At or below ``B`` active Topics, EVERY Topic is
#: admitted regardless of signal — the pre-filter only orders, never drops.
#: ``|C| = 0`` is impossible below the band. Committed at 12 (design §4.1);
#: if the §4.7 recall calibration measures < 0.95 the band stays mandatory at
#: the measured count, so this lives as a constant the caller can read.
B = 12

#: The count of Topics whose **full Details** are inlined into the classify
#: call. ``1 <= full-Details candidates <= K`` -> single precise call; ``> K``
#: -> two-stage card/shortlist fallback. Committed Phase-1 start of 6 (fits a
#: ``num_ctx`` of ``MIN_RECOMMENDED_NUM_CTX`` with the email + decode headroom);
#: the final value is a §4.5 calibration, not an open guess. NB : ``num_ctx``
#: is now an operator-pinnable setting (``config.classifier.num_ctx``) — K=6
#: assumes >= ``MIN_RECOMMENDED_NUM_CTX`` headroom, so pinning a SMALLER context
#: can front-truncate the prompt; the classifier + admin Save log a WARN and the
#: recommended default is inherit.
K = 6

#:  — the smallest ``num_ctx`` under which the K full-Details inline above no
#: longer fits with email + decode headroom. Pinning ``config.classifier.num_ctx``
#: below this risks SILENT front-truncation of the topic-match prompt (input-side,
#: NOT caught by the  output ``done_reason`` guard — the same fall-open-to-zero-
#: verdicts class as  / the 2026-06-14 parse fix). The classifier logs a WARN at
#: init and the admin Save logs a WARN when a sub-floor value is submitted; the
#: recommended default is inherit (the deployed qwen3.x loads at >= this). This is
#: the SINGLE source for the floor — import it, never restate 8192 elsewhere.
MIN_RECOMMENDED_NUM_CTX = 8192

#: Number of auto-derived (highest-IDF) terms put on a compact Topic card.
#: A card is "name + a few terms"; the design names "3-5" hand-picked terms
#: but :func:`derive_card_terms` augments from Details so cards do not under-
#: represent a Topic (closing the vet's "Stage-A cards drop a positive"
#: hazard). 8 keeps a 40-card Stage-A prompt bounded (§4.5 risk 6).
CARD_TERM_COUNT = 8


# ---------------------------------------------------------------------------
# Registry-identifier patterns (operator-configured signals, §4.1 / §3c).
#
# These are matched against the operator's Subject + Details text to harvest
# study identifiers as high-precision signals, and against inbound email
# Subject lines / Message-IDs as candidate evidence. Anchored, normalised
# upper-case. IND/IDE are deliberately ABSENT — they are not public-lookup
# identifiers (design §3c) and must never be treated as signals.
# ---------------------------------------------------------------------------

#: ClinicalTrials.gov primary registry id, e.g. ``NCT00000419``.
NCT_RE = re.compile(r"\bNCT\d{8}\b", re.IGNORECASE)
#: EU Clinical Trials Register id, e.g. ``2004-001234-12``.
EUDRACT_RE = re.compile(r"\b\d{4}-\d{6}-\d{2}\b")
#: ISRCTN registry id, e.g. ``ISRCTN12345678``.
ISRCTN_RE = re.compile(r"\bISRCTN\d{8}\b", re.IGNORECASE)

_REGISTRY_PATTERNS = (NCT_RE, EUDRACT_RE, ISRCTN_RE)


def extract_registry_ids(text: str) -> set[str]:
    """Return every clinical-registry identifier in ``text`` (normalised).

    Recognises NCT (``NCT\\d{8}``), EudraCT (``\\d{4}-\\d{6}-\\d{2}``) and
    ISRCTN (``ISRCTN\\d{8}``). Identifiers are upper-cased so an inbound
    ``nct00000419`` matches a configured ``NCT00000419``. Used both to seed an
    operator Topic's signals (from Subject/Details) and to scan an inbound
    email's headers for the same identifiers.
    """
    if not text:
        return set()
    out: set[str] = set()
    for pat in _REGISTRY_PATTERNS:
        for m in pat.finditer(text):
            out.add(m.group(0).upper())
    return out


# ---------------------------------------------------------------------------
# Lightweight, dependency-free tokenisation + stemming.
#
# Deliberately NOT NLTK / a heavy stemmer: the design wants a pure-logic,
# config-derived pre-filter (§4.1). A small suffix-stripper collapses the
# obvious inflections (plurals, -ing/-ed/-ation) so "estrogens" in a Subject
# chip OR-matches "estrogen" in an email keyword. Over-stemming is harmless
# here: the index is a *prioritizer*, false collisions only re-order, and the
# always-on band guarantees nothing is dropped (§4.1).
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z0-9]+(?:'[a-z]+)?")

# Common English function words — dropped before they become signal terms so
# "study of lupus" contributes "lupus", not "of"/"the". Small on purpose; a
# stray content word slipping through only adds a weak signal, never drops one.
_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with",
    "at", "by", "from", "as", "is", "are", "was", "were", "be", "been",
    "this", "that", "these", "those", "it", "its", "into", "over", "under",
    "study", "trial", "patient", "patients", "subject", "subjects", "site",
    "sites", "report", "reports", "data", "new", "update", "re", "fwd",
})


def _stem(token: str) -> str:
    """Collapse the obvious English inflections to a shared root.

    Order matters — strip the longest matching suffix first. This is a coarse
    Porter-lite stripper, not a linguistic stemmer; it exists only so that the
    operator's "estrogens" and the email's "estrogen" land on the same key.
    """
    t = token
    for suf in ("ational", "ization", "ization", "iveness", "fulness",
                "ousness", "ation", " izer", "ised", "ized", "ising",
                "izing", "ment", "ness", "tion", "sion", "ies", "ing",
                "ers", "est", "ed", "es", "ly", "er", "s"):
        if t.endswith(suf) and len(t) - len(suf) >= 3:
            base = t[: -len(suf)]
            # restore a plural-collapsed "y" (studies -> studi -> study-ish);
            # cheap heuristic, only needs to be self-consistent.
            if suf == "ies":
                base += "y"
            return base
    return t


def _tokens(text: str) -> list[str]:
    """Lower-case, split into word tokens, drop stopwords, stem.

    Empty / ``None`` text yields an empty list. Pure: no provider, no DB.
    """
    if not text:
        return []
    out: list[str] = []
    for raw in _WORD_RE.findall(text.lower()):
        if raw in _STOPWORDS or len(raw) < 2:
            continue
        stemmed = _stem(raw)
        if stemmed and stemmed not in _STOPWORDS:
            out.append(stemmed)
    return out


# ---------------------------------------------------------------------------
# Subject-chip synonym expansion (§4.1: "Subject chips expanded to
# acronym/full/sponsor synonyms").
#
# A study Subject chip is often an acronym ("SELENA"), a full name ("Safety of
# Estrogens in Lupus Erythematosus National Assessment"), or a sponsor ("NYU
# Langone"). Each chip is expanded into its own term-set so a match on ANY of
# the synonyms scores the Topic. We cannot know the canonical mapping (it is
# operator free-text), so the expansion is structural: the chip's own tokens
# PLUS a derived acronym from a multi-word chip, and a chip that is itself an
# all-caps acronym is kept verbatim as a single high-value term.
# ---------------------------------------------------------------------------

def _expand_chip(chip: str) -> set[str]:
    """Expand one Subject chip into its set of matchable (stemmed) terms.

    - A multi-word chip contributes each of its content tokens AND an acronym
      built from their initials (>= 2 words) — so "Safety of Estrogens in
      Lupus" yields ``{safeti, estrogen, lupus, sel}``-style terms plus the
      whole-token set, letting an email that says only "SELENA" or only
      "lupus" both score.
    - A single all-caps token (an acronym like ``SELENA``) is kept verbatim,
      lower-cased, as one term (acronyms do not stem usefully).
    """
    if not chip or not chip.strip():
        return set()
    raw_words = _WORD_RE.findall(chip.lower())
    terms: set[str] = set(_tokens(chip))
    # Acronym from the content words' initials (skip stopwords so "Safety of
    # Estrogens in Lupus" -> "sel", matching a SELENA-style acronym).
    content = [w for w in raw_words if w not in _STOPWORDS and len(w) >= 2]
    if len(content) >= 2:
        acronym = "".join(w[0] for w in content)
        if len(acronym) >= 2:
            terms.add(acronym)
    # An all-caps single token in the ORIGINAL chip is an acronym — keep it.
    stripped = chip.strip()
    if " " not in stripped and stripped.isupper() and len(stripped) >= 2:
        terms.add(stripped.lower())
    return {t for t in terms if t}


# ---------------------------------------------------------------------------
# Reading TopicConfig-shaped inputs without importing topic_configs.
# ---------------------------------------------------------------------------

def _field(topic: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a TopicConfig-shaped object OR a plain dict.

    Lets this module stay decoupled from ``actions/topic_configs.py`` (owned by
    another agent): callers may pass a dataclass instance, a Mapping, or any
    duck-typed object exposing the documented fields.
    """
    if isinstance(topic, Mapping):
        return topic.get(name, default)
    return getattr(topic, name, default)


def _subjects(topic: Any) -> list[str]:
    """The Topic's Subject chips as a clean list of non-empty strings."""
    subs = _field(topic, "subjects", None)
    if subs is None:
        # tolerate a singular "subject" string for robustness
        single = _field(topic, "subject", None)
        subs = [single] if single else []
    if isinstance(subs, str):
        subs = [subs]
    return [str(s) for s in subs if s and str(s).strip()]


def _topic_id(topic: Any, fallback: int) -> Any:
    """A stable identifier for the Topic; falls back to enumerate index."""
    for key in ("id", "topic_id"):
        val = _field(topic, key, None)
        if val is not None:
            return val
    name = _field(topic, "name", None)
    return name if name else fallback


# ---------------------------------------------------------------------------
# Per-Topic signal set + the user-scoped index.
# ---------------------------------------------------------------------------

@dataclass
class TopicSignals:
    """The deterministic, config-derived signal bundle for ONE Topic.

    Every field is a restatement of operator-typed config (§4.3) — no body
    learning, no embedding. ``keyword_terms`` are stemmed; ``domains`` /
    ``list_ids`` / ``registry_ids`` are normalised lower/upper case for
    case-insensitive OR-matching.
    """

    topic_id: Any
    name: str
    keyword_terms: frozenset[str] = field(default_factory=frozenset)
    domains: frozenset[str] = field(default_factory=frozenset)
    list_ids: frozenset[str] = field(default_factory=frozenset)
    registry_ids: frozenset[str] = field(default_factory=frozenset)
    sponsor_terms: frozenset[str] = field(default_factory=frozenset)
    card_terms: tuple[str, ...] = ()


# Heuristics for harvesting operator-typed sender domains / list-IDs out of the
# free-text Details blob (the operator may type "from alerts@clinicaltrials.gov"
# or "list-id: trials.example.org"). Config-derived, never body-derived.
_DOMAIN_IN_TEXT_RE = re.compile(
    r"[a-z0-9][a-z0-9._%+-]*@([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE
)
_BARE_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE
)
_LIST_ID_HINT_RE = re.compile(
    r"list[-_ ]?id[:\s]+<?([a-z0-9][a-z0-9._-]*\.[a-z]{2,})>?", re.IGNORECASE
)

# Sponsor/CRO cue words: a capitalised phrase ending in one of these is treated
# as a sponsor/CRO name signal. Structural, not a hard-coded vendor list.
_SPONSOR_CUES = (
    "pharma", "pharmaceutical", "pharmaceuticals", "therapeutics",
    "biosciences", "biotech", "laboratories", "labs", "institute",
    "university", "hospital", "health", "oncology", "sciences", "cro",
    "research", "langone", "genentech", "novartis", "pfizer", "roche",
)


def _harvest_config_signals(subjects: Sequence[str], details: str) -> dict:
    """Pull every deterministic signal out of one Topic's operator config.

    Returns a dict of frozensets: ``keyword_terms``, ``domains``,
    ``list_ids``, ``registry_ids``, ``sponsor_terms``. Pure string work —
    no DB, no network, no body.
    """
    joined = " ".join(subjects) + " " + (details or "")

    # Registry IDs from BOTH subjects and details.
    registry_ids = extract_registry_ids(joined)

    # Sender domains the operator typed (explicit ``user@domain`` first, then
    # bare domains in the details). Subject chips are study names, not hosts —
    # domains come from Details only, where an operator would paste a sender.
    domains: set[str] = set()
    for m in _DOMAIN_IN_TEXT_RE.finditer(details or ""):
        domains.add(m.group(1).lower())
    for m in _BARE_DOMAIN_RE.finditer(details or ""):
        dom = m.group(1).lower()
        # avoid catching a registry-ish token or a stemmed word; require a TLD
        if "." in dom and not dom[0].isdigit():
            domains.add(dom)

    # List-IDs (operator typed "list-id: ...").
    list_ids: set[str] = set()
    for m in _LIST_ID_HINT_RE.finditer(details or ""):
        list_ids.add(m.group(1).lower())

    # Sponsor / CRO names: a token adjacent to a sponsor cue word.
    sponsor_terms: set[str] = set()
    low = joined.lower()
    for cue in _SPONSOR_CUES:
        if cue in low:
            sponsor_terms.add(_stem(cue))

    # Condition / study keywords from Subject chips (expanded to synonyms) +
    # Details. Domains and registry IDs are excluded from the keyword bag (they
    # are matched structurally), so a domain like "clinicaltrials.gov" does not
    # also leak in as the keyword "clinicaltrial".
    keyword_terms: set[str] = set()
    for chip in subjects:
        keyword_terms |= _expand_chip(chip)
    keyword_terms |= set(_tokens(details or ""))
    # strip any tokens that are really part of a harvested domain
    domain_tokens = set()
    for dom in domains:
        domain_tokens |= set(_tokens(dom.replace(".", " ")))
    keyword_terms -= domain_tokens

    return {
        "keyword_terms": frozenset(keyword_terms),
        "domains": frozenset(domains),
        "list_ids": frozenset(list_ids),
        "registry_ids": frozenset(registry_ids),
        "sponsor_terms": frozenset(sponsor_terms),
    }


def derive_card_terms(topic: Any, *, corpus: Sequence[Any] | None = None,
                      limit: int = CARD_TERM_COUNT) -> tuple[str, ...]:
    """Return the top-IDF terms for this Topic's compact card.

    The card is "name + a few terms" used in the Stage-A coarse prompt when the
    user is above the band. The design's fix for "Stage-A cards drop a true
    positive" (§4.1 / §4.5 risk 2) is that card terms are **auto-augmented from
    Details** — not just the operator's hand-picked 3-5 — and weighted by
    **inverse document frequency** so a term that distinguishes THIS Topic from
    the user's other Topics ranks above a term every Topic shares.

    ``corpus`` is the user's other active Topics (for the IDF denominator). When
    omitted, IDF degenerates to raw term frequency within this Topic, which
    still surfaces the Topic's own most-repeated condition/sponsor terms — so a
    single-Topic user still gets sensible cards.

    Registry IDs and sponsor terms are pinned to the FRONT of the card (highest
    signal value), then the highest-IDF keyword terms fill the remainder.
    """
    subjects = _subjects(topic)
    details = _field(topic, "details", "") or ""
    sig = _harvest_config_signals(subjects, details)

    # Document frequency across the corpus (how many OTHER Topics use a term).
    corpus = list(corpus or [])
    n_docs = max(len(corpus), 1)
    doc_freq: dict[str, int] = {}
    for other in corpus:
        o_terms = _harvest_config_signals(
            _subjects(other), _field(other, "details", "") or ""
        )["keyword_terms"]
        for term in set(o_terms):
            doc_freq[term] = doc_freq.get(term, 0) + 1

    # Term frequency within THIS Topic.
    tf: dict[str, int] = {}
    for t in _tokens(" ".join(subjects) + " " + details):
        tf[t] = tf.get(t, 0) + 1
    # Subject-chip terms get a tf boost — an operator chip is a stronger signal
    # than a Details mention.
    for chip in subjects:
        for t in _expand_chip(chip):
            tf[t] = tf.get(t, 0) + 2

    def idf(term: str) -> float:
        # smoothed idf; rarer-across-Topics -> higher
        return log((n_docs + 1) / (doc_freq.get(term, 0) + 1)) + 1.0

    scored = sorted(
        ((t, tf[t] * idf(t)) for t in tf),
        key=lambda kv: (-kv[1], kv[0]),
    )

    # Front-load the high-signal structural terms (registry ids, sponsors),
    # then fill with IDF-ranked keywords, de-duplicated, capped at ``limit``.
    card: list[str] = []
    for rid in sorted(sig["registry_ids"]):
        if rid.lower() not in card:
            card.append(rid.lower())
    for sp in sorted(sig["sponsor_terms"]):
        if sp not in card:
            card.append(sp)
    for term, _score in scored:
        if len(card) >= limit:
            break
        if term not in card:
            card.append(term)
    return tuple(card[:limit])


@dataclass
class TopicSignalIndex:
    """Per-user index of every active Topic's config-derived signals.

    Build once per ingest batch (cheap — pure string work over the user's own
    Topic configs) and reuse across the batch's emails. Holds no PHI, no body
    data, no embedding.
    """

    signals: list[TopicSignals]

    @classmethod
    def build(cls, active_topics: Sequence[Any]) -> "TopicSignalIndex":
        """Build the index from a list of TopicConfig-shaped objects/dicts.

        Each Topic's card terms are derived with the OTHER active Topics as the
        IDF corpus, so the cards are discriminative across the user's set.
        """
        topics = list(active_topics)
        sigs: list[TopicSignals] = []
        for i, topic in enumerate(topics):
            subjects = _subjects(topic)
            details = _field(topic, "details", "") or ""
            harvested = _harvest_config_signals(subjects, details)
            corpus = [t for j, t in enumerate(topics) if j != i]
            sigs.append(
                TopicSignals(
                    topic_id=_topic_id(topic, i),
                    name=str(_field(topic, "name", "") or ""),
                    keyword_terms=harvested["keyword_terms"],
                    domains=harvested["domains"],
                    list_ids=harvested["list_ids"],
                    registry_ids=harvested["registry_ids"],
                    sponsor_terms=harvested["sponsor_terms"],
                    card_terms=derive_card_terms(topic, corpus=corpus),
                )
            )
        return cls(signals=sigs)


# ---------------------------------------------------------------------------
# Scoring one email against one Topic's signals.
# ---------------------------------------------------------------------------

def _header(headers: Mapping[str, str] | None, *names: str) -> str:
    """Case-insensitive multi-name header lookup; '' when absent."""
    if not headers:
        return ""
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    for n in names:
        v = lowered.get(n.lower())
        if v:
            return v
    return ""


def _domain_of(addr: str) -> str:
    """Extract the bare domain from a From/Sender header value."""
    if not addr:
        return ""
    m = _DOMAIN_IN_TEXT_RE.search(addr)
    if m:
        return m.group(1).lower()
    # bare "Name <host.tld>" without an @ — last resort
    m2 = _BARE_DOMAIN_RE.search(addr)
    return m2.group(1).lower() if m2 else ""


# Signal weights — registry-id and exact-domain are the strongest signals; a
# keyword OR-hit is weaker; sponsor is in between. These set ORDER only (the
# always-on band means score never gates admission below B), so the exact
# magnitudes are a tuning knob, not a correctness boundary.
_W_REGISTRY = 10.0
_W_DOMAIN = 6.0
_W_LIST_ID = 6.0
_W_SPONSOR = 3.0
_W_KEYWORD = 1.0


@dataclass
class Candidate:
    """One ranked (Topic, score) result from :func:`rank_candidates`.

    ``matched_terms`` is the why-matched evidence (the user's OWN public
    Subject/Details terms the email hit, design §3d / R6) — safe to surface
    because it is the operator's public text, never the email body.
    ``score == 0`` means "no cheap signal fired" — that is **not** exclusion;
    below the band the Topic is still admitted, the score only orders.
    """

    topic_id: Any
    name: str
    score: float
    matched_terms: tuple[str, ...]
    card_terms: tuple[str, ...]


def _score_one(sig: TopicSignals, *, from_domain: str, list_id: str,
               header_blob: str, email_registry_ids: set[str],
               body_keyword_terms: set[str]) -> tuple[float, list[str]]:
    """Score one Topic's signals against one email's cheap signals.

    OR-matched, never AND (§4.1): any single hit contributes; a miss on every
    signal yields ``(0.0, [])`` — score 0, **not** exclusion. Returns the score
    and the list of matched evidence terms (de-duplicated, stable order).
    """
    score = 0.0
    matched: list[str] = []

    # Registry IDs (strongest, exact).
    for rid in sorted(sig.registry_ids):
        if rid in email_registry_ids:
            score += _W_REGISTRY
            matched.append(rid)

    # Sender domain (substring/suffix match: an email from
    # "alerts.clinicaltrials.gov" matches a configured "clinicaltrials.gov").
    for dom in sorted(sig.domains):
        if from_domain and (from_domain == dom or from_domain.endswith("." + dom)):
            score += _W_DOMAIN
            matched.append(dom)

    # List-Id header.
    li = list_id.lower()
    for lid in sorted(sig.list_ids):
        if lid and lid in li:
            score += _W_LIST_ID
            matched.append(lid)

    # Sponsor / CRO terms anywhere in the header blob or body keywords.
    blob_terms = set(_tokens(header_blob)) | body_keyword_terms
    for sp in sorted(sig.sponsor_terms):
        if sp in blob_terms:
            score += _W_SPONSOR
            matched.append(sp)

    # Condition / study keywords — OR over the union of header tokens and the
    # cheap body keywords the caller already extracted.
    candidate_terms = blob_terms
    for kw in sorted(sig.keyword_terms):
        if kw in candidate_terms:
            score += _W_KEYWORD
            if kw not in matched:
                matched.append(kw)

    # de-dup preserving order
    seen: set[str] = set()
    deduped = [t for t in matched if not (t in seen or seen.add(t))]
    return score, deduped


def rank_candidates(
    active_topics: Sequence[Any],
    email_headers: Mapping[str, str] | None,
    cheap_body_keywords: Iterable[str] | None = None,
    *,
    index: TopicSignalIndex | None = None,
) -> list[Candidate]:
    """Rank a user's active Topics against one email's cheap signals.

    Returns a list of :class:`Candidate` in descending score order — a RANKED
    list, **not** a filtered one. EVERY active Topic appears in the result;
    a Topic that matched no signal gets ``score == 0`` and sorts last, but is
    never dropped. This is the structural guarantee that ``|C| = 0`` is
    impossible: ``len(rank_candidates(...)) == len(active_topics)`` always.

    ``email_headers`` is a plain mapping (``From`` / ``Subject`` / ``List-Id``
    / ``Message-ID`` ...) — case-insensitive. ``cheap_body_keywords`` are the
    body terms the caller already extracted upstream (this module reads no body
    itself). ``index`` may be supplied to reuse a pre-built
    :class:`TopicSignalIndex` across a batch; otherwise one is built here.

    Ties (equal score) break by lower stringified ``topic_id`` for a stable,
    deterministic order — important so the top-``K`` Details cut is reproducible
    (§4.5) and tests are not flaky.
    """
    idx = index or TopicSignalIndex.build(active_topics)

    subject = _header(email_headers, "Subject")
    from_hdr = _header(email_headers, "From", "Sender", "Reply-To")
    list_id = _header(email_headers, "List-Id", "List-ID")
    msg_id = _header(email_headers, "Message-ID", "Message-Id")
    from_domain = _domain_of(from_hdr)
    header_blob = " ".join((subject, from_hdr, list_id))
    email_registry_ids = extract_registry_ids(
        " ".join((subject, msg_id, header_blob))
    )
    body_terms = set()
    for kw in (cheap_body_keywords or ()):
        body_terms |= set(_tokens(str(kw)))

    out: list[Candidate] = []
    for sig in idx.signals:
        score, matched = _score_one(
            sig,
            from_domain=from_domain,
            list_id=list_id,
            header_blob=header_blob,
            email_registry_ids=email_registry_ids,
            body_keyword_terms=body_terms,
        )
        out.append(
            Candidate(
                topic_id=sig.topic_id,
                name=sig.name,
                score=score,
                matched_terms=tuple(matched),
                card_terms=sig.card_terms,
            )
        )

    out.sort(key=lambda c: (-c.score, str(c.topic_id)))
    return out


def keyword_match(
    topic: Any,
    email_headers: Mapping[str, str] | None,
    cheap_body_keywords: Iterable[str] | None = None,
) -> list[str]:
    """Step-1 Preview keyword filter (operator 2026-06-12): deterministic,
    NO-LLM, config-derived — does this ONE message hit this ONE Topic's
    cheap signals? Returns the **readable** matched terms (the operator's own
    Subject chips, plus any structural signals — sender domain / List-Id /
    registry id — verbatim). An empty list means "no keyword hit".

    Same inputs as :func:`rank_candidates` / ``match_topics_for_message`` (the
    message's ``.headers`` mapping + the already-extracted ``body_keywords``),
    so it drops into the preview fetch loop identically.

    Why this exists: the Preview used to run the LLM matcher over only the
    first N messages per account (the ``_TOPIC_PREVIEW_PER_ACCOUNT`` cap), so a
    message filed in a non-INBOX folder on a busy mailbox was never even
    looked at — the operator's mempalace mail in ``Tech/GitHub`` was starved.
    This wraps the SAME ``rank_candidates`` scorer the ingest path uses, so the
    "why it matched" evidence is identical, but as a cheap pass that can run
    over the WHOLE "how far back" window without an LLM call. The LLM is then
    spent only on these candidates by the on-demand "Test Details" step.

    **PRECISION over recall (operator 2026-06-12).** Matches ONLY the Topic's
    DELIBERATE signals — Subject chips (expanded to synonyms/acronyms) plus the
    structural signals harvested from Details (registry IDs, sender domains,
    List-Ids, sponsor cue terms). It deliberately does NOT match the Details
    free-text token bag. :func:`rank_candidates` tokenizes the WHOLE Details
    prose into an always-on OR-set so the LLM-ingest prioritizer never drops a
    Topic (§4.1) — but used as a Preview MATCH decision that made every common
    Details word ("call", "free", "ai", "has", "store", "open") match every
    newsletter (operator-reported flood). The cheap Preview answers "does this
    hit my Subject terms?"; the FULL Details are tested by the LLM in the
    on-demand "Test Details" step. Returns the readable matched terms (Subject
    chips + structural signals, verbatim) or [] for no hit.
    """
    subjects = _subjects(topic)
    details = _field(topic, "details", "") or ""
    sig = _harvest_config_signals(subjects, details)

    headers = email_headers or {}
    subject = headers.get("Subject") or headers.get("subject") or ""
    sender = headers.get("From") or headers.get("from") or ""
    list_id_hdr = (headers.get("List-Id") or headers.get("list-id") or "")

    # Message signal surface: SUBJECT tokens + the cheap body keywords the
    # caller already extracted (stemmed). Headers-only preview ⇒ body kws empty.
    msg_tokens: set[str] = set(_tokens(subject))
    for kw in (cheap_body_keywords or ()):
        msg_tokens |= set(_tokens(str(kw)))
    hay = (subject + " " + sender + " " + list_id_hdr).lower()

    readable: list[str] = []
    seen: set[str] = set()

    def _add(term: str) -> None:
        key = term.lower()
        if key and key not in seen:
            readable.append(term)
            seen.add(key)

    # 1) Subject-chip hits — the operator's deliberate terms. Map the stemmed
    #    hit back to the ORIGINAL chip so the evidence is the user's own words.
    for chip in subjects:
        exp = {s for s in _expand_chip(chip) if len(s) >= 2 and s not in _STOPWORDS}
        if exp & msg_tokens:
            _add(chip)

    # 2) Structural signals — high-precision, matched as substrings/tokens (they
    #    do not tokenize like prose). Registry IDs + domains + List-Ids against
    #    the raw subject/sender/List-Id header; sponsor terms against tokens.
    for rid in sig["registry_ids"]:
        if rid.lower() in hay:
            _add(rid)
    for dom in sig["domains"]:
        if dom.lower() in hay:
            _add(dom)
    for lid in sig["list_ids"]:
        if lid.lower() in hay:
            _add(lid)
    for sp in sig["sponsor_terms"]:
        if sp in msg_tokens:
            _add(sp)

    return readable


# ---------------------------------------------------------------------------
# Admission — the band/K policy on top of the ranking (§4.1).
# ---------------------------------------------------------------------------

@dataclass
class Admission:
    """The pre-filter's full decision for one email.

    - ``full_details`` — Topics whose **full Details** are inlined into the
      classify call (top-ranked, up to ``K``).
    - ``cards`` — Topics admitted as **compact cards** (name + card terms).
    - ``candidates`` — the complete ranked list (every active Topic).

    The recall-floor invariant holds on this object: ``full_details + cards``
    together cover **every** candidate when ``len(active) <= B`` (band) and also
    when ``len(active) > B`` (all admitted as cards). In neither regime is any
    Topic excluded by a cheap-signal miss — so::

        len(full_details) + len(cards) == len(candidates) == len(active_topics)

    is invariant, and ``|C| = 0`` is impossible.
    """

    candidates: list[Candidate]
    full_details: list[Candidate]
    cards: list[Candidate]
    above_band: bool


def admit(
    active_topics: Sequence[Any],
    email_headers: Mapping[str, str] | None,
    cheap_body_keywords: Iterable[str] | None = None,
    *,
    index: TopicSignalIndex | None = None,
    band: int = B,
    k: int = K,
) -> Admission:
    """Apply the band/K admission policy on top of :func:`rank_candidates`.

    Below/at the band (``len(active) <= band``): EVERY Topic is admitted.
    The top-``k`` by rank get full Details; the rest are admitted as cards —
    nothing is dropped (the only job below the band is full-Details vs card).

    Above the band (``len(active) > band``): EVERY Topic is still admitted, but
    as a compact CARD; the top-``k`` additionally get full Details. The cheap
    score only sets order and which top-``k`` get Details — no Topic is excluded
    from the LLM by a cheap-signal miss (overflow handling beyond the LLM-coarse
    pass is the caller's back-scan net, §4.4 — never a silent drop here).

    In both regimes ``full_details + cards`` partition the full candidate set,
    so ``|C| = 0`` is structurally impossible.
    """
    candidates = rank_candidates(
        active_topics, email_headers, cheap_body_keywords, index=index
    )
    above_band = len(candidates) > band

    full_details = candidates[:k]
    cards = candidates[k:]
    return Admission(
        candidates=candidates,
        full_details=full_details,
        cards=cards,
        above_band=above_band,
    )


__all__ = [
    "B",
    "K",
    "CARD_TERM_COUNT",
    "NCT_RE",
    "EUDRACT_RE",
    "ISRCTN_RE",
    "extract_registry_ids",
    "derive_card_terms",
    "TopicSignals",
    "TopicSignalIndex",
    "Candidate",
    "rank_candidates",
    "Admission",
    "admit",
]
