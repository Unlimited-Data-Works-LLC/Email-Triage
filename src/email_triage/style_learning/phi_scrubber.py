"""Layered PHI scrubber for the HIPAA describe-and-discard pipeline (#152 S2).

Three layers, applied in order. Any layer detecting PHI in a field that
must not contain PHI marks the whole descriptor as failing — the caller
discards the descriptor and audits the rejection.

Why three layers + not one
==========================

The single-layer defense is brittle: a regex that catches everything
HHS classifies as PHI either over-matches (false-positives kill legit
style words) or under-matches (a phrase like "John from accounting"
slips through a strict "two-capitalised-words separated by 'from'"
pattern). Defense-in-depth makes each layer narrow + composable:

  1. **Layer 1 — Schema enforcement.** The descriptor has a fixed
     closed-vocabulary schema (``tone`` is one of a 5-bucket enum,
     ``formality_level`` is 1-5, etc.). The LLM is constrained at API
     level via ``response_format={"type": "json_schema", ...}``. If
     the LLM ignores the schema and writes free text into a closed-
     enum field, layer 1 catches the violation (value is outside the
     enum). Length caps on the only-free-text-ish field
     (``greeting_style`` / ``signoff_style`` are short phrases, capped)
     also live here.
  2. **Layer 2 — HIPAA-18-identifier regex matcher.** The full set
     of 18 identifiers from the HHS Safe Harbor De-Identification
     Standard (45 CFR §164.514(b)(2)): names, geographic subdivisions
     smaller than state, all elements of dates except year, phone
     numbers, fax numbers, email addresses, SSNs, MRNs, health-plan
     beneficiary numbers, account numbers, certificate/license numbers,
     vehicle identifiers, device identifiers, web URLs, IP addresses,
     biometric identifiers, full-face photographs (URL hint),
     distinguishing identifiers. Patterns target the *shape* of each
     identifier — over-broad by design.
  3. **Layer 3 — NER post-check.** If ``presidio_analyzer`` (or
     ``spacy``) is installed, run NER on every field's string value
     + flag any ``PERSON`` / ``LOCATION`` / ``DATE_TIME`` /
     ``MEDICAL_RECORD_NUMBER`` / ``US_SSN`` entity. The NER pass
     catches identifiers the regex misses (e.g. a non-US phone format
     the regex doesn't know; a person name without a comma/honorific
     prefix). When the NER lib isn't available, layer 3 is skipped
     + the scrubber sets ``degraded=True`` so the audit row records
     the degradation. The Wave 1 pyproject.toml does NOT install
     presidio/spacy by default; layer 3 ALWAYS degrades in the
     default install. That's intentional — the operator can opt in
     by installing the optional dep, but the default is "regex
     scrubber + log the degradation" rather than "missing dep crashes
     the distill path".

Output contract
===============

:func:`scrub_descriptor` returns a :class:`ScrubResult` carrying:

  * ``passed`` — True when the descriptor is safe to persist.
  * ``scrubbed_descriptor`` — the descriptor dict with any phrase-list
    entries that hit a PHI pattern removed. Other fields are untouched
    (closed-enum fields have already been coerced).
  * ``layer1_fields_dropped`` — list of field-names where the layer-1
    schema check fired (value snapped to default or string truncated).
  * ``layer2_matches`` — list of ``(field, label)`` tuples for every
    HIPAA-18 regex match. The matched text is NEVER stored in the
    result; only the label and the field where it fired.
  * ``layer3_entities`` — list of ``(field, entity_type)`` tuples for
    every NER entity flagged. -1 (sentinel) when layer 3 was skipped.
  * ``degraded`` — True when layer 3 was skipped because the NER lib
    is not installed.

A descriptor fails (``passed=False``) when:

  * ANY layer-2 match fires on a non-phrase field (tone, formality,
    length_bucket, greeting_style, signoff_style, etc.) — the LLM
    violated the structured-output contract, the descriptor is unsafe.
  * ANY layer-3 entity fires on a non-phrase field, for the same reason.

The ``common_phrases`` field is the *intended* free-text surface — any
PHI hit in a single phrase drops that phrase + keeps the rest. A
layer-1 schema violation on the phrase list (e.g. the LLM returned a
string instead of a list) drops the whole list.

This scrubber is the LAST line of defense before persistence. The
in-prompt instructions (see :mod:`distill_hipaa.DISTILL_PROMPT`) are
the FIRST line; the closed-enum schema is the SECOND. If both
upstream defenses fail at once, the scrubber is what stops the leak
from landing in storage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("email_triage.style_learning.phi_scrubber")


# ---------------------------------------------------------------------------
# Layer 1 — schema enforcement helpers
# ---------------------------------------------------------------------------

#: Hard cap on the character length of any single descriptor string
#: field (besides the phrase list). The LLM is asked for short style
#: markers; anything longer is treated as a contract violation.
LAYER1_MAX_FIELD_CHARS = 80

#: Closed-vocabulary enums for the structured-output schema. These
#: mirror the buckets in :mod:`email_triage.actions.hipaa_style_distill`
#: + extend with the M-3 phase 3-4 schema fields the operator listed
#: in the Wave 2-β task spec.
SCHEMA_ENUMS: dict[str, tuple[str, ...]] = {
    "tone": ("terse", "casual", "neutral", "professional", "formal"),
    "formality_level": ("1", "2", "3", "4", "5"),
    "greeting_style": (
        "none",
        "hi_first_name",
        "hello_first_name",
        "hey",
        "formal_dear",
        "good_morning",
    ),
    "signoff_style": (
        "none",
        "thanks",
        "thanks_first_name",
        "best",
        "sincerely",
        "cheers",
    ),
    "sentence_length_pref": ("short", "medium", "long"),
    "vocabulary_register": (
        "plain",
        "professional",
        "technical",
        "academic",
    ),
}

#: Numeric range fields: ``(min, max)`` inclusive.
SCHEMA_NUMERIC_RANGES: dict[str, tuple[int, int]] = {
    "paragraph_count_typical": (1, 10),
}

#: Cap on common_phrases list length and per-entry length.
MAX_COMMON_PHRASES = 8
MAX_PHRASE_LENGTH = 60


# ---------------------------------------------------------------------------
# Layer 2 — HIPAA-18-identifier regex matcher
# ---------------------------------------------------------------------------

# Map labels to (description, compiled regex). Descriptions are for
# operator-visible audit detail (label only ever appears in audit rows;
# matched text never escapes the scrubber).
#
# The HHS Safe Harbor list (45 CFR §164.514(b)(2)):
#   (A)  Names
#   (B)  Geographic subdivisions smaller than state
#   (C)  All elements of dates (except year)
#   (D)  Telephone numbers
#   (E)  Fax numbers
#   (F)  Email addresses
#   (G)  Social Security numbers
#   (H)  Medical record numbers
#   (I)  Health plan beneficiary numbers
#   (J)  Account numbers
#   (K)  Certificate/license numbers
#   (L)  Vehicle identifiers and serial numbers
#   (M)  Device identifiers and serial numbers
#   (N)  Web URLs
#   (O)  Internet Protocol addresses
#   (P)  Biometric identifiers (URL/filename hint)
#   (Q)  Full-face photographs (URL/filename hint)
#   (R)  Other unique identifying numbers / characteristics

PHI_REGEX_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # (A) Names — honorific prefix + capitalised token
    (
        "name_honorific",
        "name with honorific prefix (Mr/Mrs/Ms/Dr/etc + Capitalised)",
        re.compile(
            r"\b(?:Mr|Mrs|Ms|Mx|Dr|Prof|Rev|Sr|Jr|Sir|Dame|Lord|Lady)"
            r"\.?\s+[A-Z][a-zA-Z'\-]+\b"
        ),
    ),
    # (A) Names — given-name + family-name (two capitalised tokens) is
    # too broad for free style text, but the descriptor fields are NOT
    # supposed to carry free text. A two-cap-token pattern flags the
    # leak shape ("John Smith") in supposedly-closed-enum fields.
    (
        "name_two_caps",
        "two consecutive capitalised tokens (possible full name)",
        re.compile(
            r"\b[A-Z][a-zA-Z'\-]+\s+[A-Z][a-zA-Z'\-]+\b"
        ),
    ),
    # (B) Geographic — street address with a directional or street type
    (
        "street_address",
        "numeric prefix + street-type suffix (Street/Ave/Rd/Blvd/etc)",
        re.compile(
            r"\b\d+\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|"
            r"Drive|Dr|Lane|Ln|Court|Ct|Place|Pl|Highway|Hwy|"
            r"Way|Terrace|Ter|Circle|Cir|Square|Sq)\b",
            re.IGNORECASE,
        ),
    ),
    # (B) Geographic — ZIP code (5-digit or ZIP+4)
    (
        "zip_code",
        "ZIP code (5-digit or ZIP+4)",
        re.compile(r"\b\d{5}(?:-\d{4})?\b"),
    ),
    # (C) Dates — slash/dash separated dates
    (
        "date_slash_dash",
        "date with slash/dash separators (M/D/Y or D-M-Y)",
        re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
    ),
    # (C) Dates — written month + day
    (
        "date_month_day",
        "month-name + day-of-month",
        re.compile(
            r"\b(?:January|February|March|April|May|June|July|August|"
            r"September|October|November|December|"
            r"Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)"
            r"\.?\s+\d{1,2}(?:st|nd|rd|th)?\b",
            re.IGNORECASE,
        ),
    ),
    # (C) Dates — 4-digit year alone in style fields is suspicious
    (
        "year_four_digit",
        "isolated 4-digit year (1900-2099)",
        re.compile(r"\b(?:19|20)\d{2}\b"),
    ),
    # (D) Telephone numbers — US formats
    (
        "phone_us_dashed",
        "phone (US format XXX-XXX-XXXX)",
        re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),
    ),
    (
        "phone_parens",
        "phone (parenthesised area code)",
        re.compile(r"\(\d{3}\)\s*\d{3}[-.\s]\d{4}"),
    ),
    (
        "phone_intl",
        "phone (international +N prefix)",
        re.compile(r"\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}"),
    ),
    # (F) Email addresses
    (
        "email_address",
        "RFC-822-ish email address",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    # (G) Social Security numbers
    (
        "ssn_dashed",
        "SSN (XXX-XX-XXXX)",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    # (H) Medical record numbers — long digit runs (regex over-broad
    # but a style descriptor should never carry any long digit run)
    (
        "mrn_or_id_long_digits",
        "long digit run (6+ contiguous digits — MRN/account/license)",
        re.compile(r"\b\d{6,}\b"),
    ),
    # (J/K/L/M) Account/license/vehicle/device — alphanumeric IDs
    # (mix of letters + digits, 6+ chars). Style markers should not
    # contain these.
    (
        "alphanumeric_id",
        "alphanumeric identifier (6+ chars mixing letters + digits)",
        re.compile(r"\b(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Za-z])"
                   r"[A-Za-z0-9-]{6,}\b"),
    ),
    # (N) Web URLs — http(s)://… or www.… style markers should NEVER
    # contain a URL.
    (
        "web_url",
        "web URL (http/https/www-prefixed)",
        re.compile(
            r"\b(?:https?://|www\.)\S+",
            re.IGNORECASE,
        ),
    ),
    # (O) IP addresses — IPv4 dotted-quad + IPv6 (loose)
    (
        "ipv4_address",
        "IPv4 dotted-quad",
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    ),
    (
        "ipv6_address",
        "IPv6 colon-separated hextets (loose)",
        re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"),
    ),
    # (P/Q) Biometric / face-photo — URL/filename hint
    (
        "image_filename",
        "image filename hint (.jpg/.png/.heic/.tiff)",
        re.compile(
            r"\b[A-Za-z0-9_\-]+\.(?:jpg|jpeg|png|heic|heif|tiff|tif|bmp|gif)\b",
            re.IGNORECASE,
        ),
    ),
    # (R) Other unique identifiers — medical terms that should NEVER
    # appear in a style descriptor (defense-in-depth)
    (
        "medical_term",
        "medical/insurance terminology",
        re.compile(
            r"\b(?:patient|diagnosis|diagnosed|prescription|prescribed|"
            r"dosage|mg|mcg|ml|MRN|EHR|EMR|HIPAA|PHI|"
            r"chart|appointment|surgery|symptom|treatment|therapy|"
            r"medication|insurance|copay|deductible|claim|provider|"
            r"clinic|hospital|admitted|discharge|biopsy|specimen)s?\b",
            re.IGNORECASE,
        ),
    ),
)


def _layer2_scan_string(value: str) -> list[str]:
    """Scan a single string for HIPAA-18 regex matches.

    Returns the list of pattern labels that fired. Never returns the
    matched text — the audit row gets labels only.
    """
    fired: list[str] = []
    for label, _desc, pattern in PHI_REGEX_PATTERNS:
        if pattern.search(value):
            fired.append(label)
    return fired


# ---------------------------------------------------------------------------
# Layer 3 — optional NER post-check
# ---------------------------------------------------------------------------

#: Entity types that the NER pass treats as PHI. Mirrors presidio's
#: built-in catalog; spacy's default catalog is a subset (PERSON,
#: GPE/LOC, DATE) — the helper falls back gracefully.
NER_BLOCKED_ENTITY_TYPES = frozenset({
    "PERSON",
    "LOCATION",
    "LOC",
    "GPE",
    "DATE_TIME",
    "DATE",
    "TIME",
    "MEDICAL_RECORD_NUMBER",
    "US_SSN",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
})


def _load_ner_analyzer() -> Any | None:
    """Return a callable that takes a string and yields entity type
    names, or None when no NER library is installed.

    Tries presidio_analyzer first (richer + HIPAA-aware), then spacy
    (broader baseline coverage). Failing both returns None — layer 3
    skips + the caller sets ``degraded=True`` on the result.
    """
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore
        engine = AnalyzerEngine()

        def _analyze(text: str) -> list[str]:
            results = engine.analyze(text=text, language="en")
            return [r.entity_type for r in results]

        return _analyze
    except Exception:
        pass

    try:
        import spacy  # type: ignore

        # Use the small English model; callers can swap via env if
        # they need a different one. If the model isn't downloaded
        # this raises and we fall through to None.
        nlp = spacy.load("en_core_web_sm")

        def _analyze_spacy(text: str) -> list[str]:
            doc = nlp(text)
            return [ent.label_ for ent in doc.ents]

        return _analyze_spacy
    except Exception:
        return None


def _layer3_scan_string(
    value: str, analyzer: Any | None,
) -> list[str]:
    """Run the NER analyzer over ``value`` and return PHI-relevant
    entity-type names.

    Returns ``[]`` when no analyzer is loaded — the caller distinguishes
    via the ``degraded`` flag, not via the empty list.
    """
    if analyzer is None or not isinstance(value, str) or not value:
        return []
    try:
        entities = analyzer(value)
    except Exception:
        # NER libraries occasionally raise on malformed input. Log
        # + treat as no-entity-found (defense in depth — the regex
        # layer is still in place).
        logger.warning(
            "phi_scrubber: NER analyzer raised, treating as no-match",
            exc_info=True,
        )
        return []
    return [
        e for e in entities if e in NER_BLOCKED_ENTITY_TYPES
    ]


# ---------------------------------------------------------------------------
# Public result type + entry point
# ---------------------------------------------------------------------------

@dataclass
class ScrubResult:
    """Outcome of a 3-layer scrub pass over a descriptor.

    See module docstring for the per-layer contract. The result is
    safe to log + audit — it contains NO matched text, only counts +
    field names + entity-type labels.
    """

    passed: bool
    scrubbed_descriptor: dict[str, Any]
    layer1_fields_dropped: list[str] = field(default_factory=list)
    layer2_matches: list[tuple[str, str]] = field(default_factory=list)
    layer3_entities: list[tuple[str, str]] = field(default_factory=list)
    degraded: bool = False

    @property
    def layer1_drop_count(self) -> int:
        return len(self.layer1_fields_dropped)

    @property
    def layer2_match_count(self) -> int:
        return len(self.layer2_matches)

    @property
    def layer3_entity_count(self) -> int:
        return len(self.layer3_entities)


# Fields that must NOT carry free-text PHI (any layer-2/-3 hit on these
# fails the whole descriptor). ``common_phrases`` is the only intentional
# free-text surface; hits there drop the offending phrase, not the
# whole descriptor.
_NON_PHRASE_FIELDS = (
    "tone",
    "formality_level",
    "greeting_style",
    "signoff_style",
    "sentence_length_pref",
    "vocabulary_register",
    "paragraph_count_typical",
)


def scrub_descriptor(
    descriptor: dict[str, Any],
    *,
    skip_ner: bool = False,
) -> ScrubResult:
    """Run the 3-layer PHI scrubber over ``descriptor``.

    Parameters
    ----------
    descriptor:
        The raw dict parsed from the LLM JSON response. Untrusted —
        the LLM may have violated the structured-output schema.
    skip_ner:
        Test hook: skip layer 3 even when the NER lib is installed.
        Production callers leave this at the default (False).

    Returns
    -------
    :class:`ScrubResult`. See class docstring for field semantics.
    """
    if not isinstance(descriptor, dict):
        # Whole-payload contract violation. Layer-1 drop, descriptor
        # discarded.
        return ScrubResult(
            passed=False,
            scrubbed_descriptor={},
            layer1_fields_dropped=["<root>"],
            degraded=False,
        )

    # ---- Layer 1: schema enforcement -----------------------------------
    layer1_drops: list[str] = []
    cleaned: dict[str, Any] = {}

    for field_name, allowed in SCHEMA_ENUMS.items():
        raw = descriptor.get(field_name)
        if raw is None:
            # Field absent — flag as drop (LLM ignored the schema) +
            # fill with the first enum value (safest default).
            layer1_drops.append(field_name)
            cleaned[field_name] = allowed[0]
            continue
        # Coerce to string for comparison; the schema may carry
        # integers (formality_level=3) which JSON returns as int.
        cand = str(raw).strip().lower()
        # Compare against lower-cased enum entries to be case-tolerant.
        matched: str | None = None
        for ok in allowed:
            if cand == ok.lower():
                matched = ok
                break
        if matched is None:
            layer1_drops.append(field_name)
            cleaned[field_name] = allowed[0]
        else:
            cleaned[field_name] = matched

    for field_name, (lo, hi) in SCHEMA_NUMERIC_RANGES.items():
        raw = descriptor.get(field_name)
        try:
            n = int(raw) if raw is not None else None
        except (TypeError, ValueError):
            n = None
        if n is None or n < lo or n > hi:
            layer1_drops.append(field_name)
            cleaned[field_name] = lo
        else:
            cleaned[field_name] = n

    # common_phrases — the only intentional free-text surface.
    raw_phrases = descriptor.get("common_phrases")
    if not isinstance(raw_phrases, list):
        layer1_drops.append("common_phrases")
        raw_phrases = []
    safe_phrases: list[str] = []
    for item in raw_phrases:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s:
            continue
        if len(s) > MAX_PHRASE_LENGTH:
            s = s[:MAX_PHRASE_LENGTH]
        safe_phrases.append(s)
        if len(safe_phrases) >= MAX_COMMON_PHRASES:
            break
    cleaned["common_phrases"] = safe_phrases

    # ---- Layer 2: regex scan -------------------------------------------
    layer2_matches: list[tuple[str, str]] = []

    # Non-phrase fields: any hit fails the descriptor.
    structural_fail = False
    for field_name in _NON_PHRASE_FIELDS:
        if field_name not in cleaned:
            continue
        val = cleaned[field_name]
        # Numeric range fields produce ints; stringify for the scan.
        val_str = str(val) if val is not None else ""
        for label in _layer2_scan_string(val_str):
            layer2_matches.append((field_name, label))
            structural_fail = True

    # Phrase list: per-phrase scan; PHI-matched phrases drop, no
    # structural fail.
    filtered_phrases: list[str] = []
    for ph in cleaned.get("common_phrases", []):
        hits = _layer2_scan_string(ph)
        if hits:
            for label in hits:
                layer2_matches.append(("common_phrases", label))
        else:
            filtered_phrases.append(ph)
    cleaned["common_phrases"] = filtered_phrases

    # ---- Layer 3: NER post-check ---------------------------------------
    layer3_entities: list[tuple[str, str]] = []
    degraded = False

    analyzer = None if skip_ner else _load_ner_analyzer()
    if analyzer is None:
        degraded = True
    else:
        for field_name in _NON_PHRASE_FIELDS:
            if field_name not in cleaned:
                continue
            val_str = str(cleaned[field_name]) if cleaned[field_name] is not None else ""
            for ent_type in _layer3_scan_string(val_str, analyzer):
                layer3_entities.append((field_name, ent_type))
                structural_fail = True
        # Scan filtered phrases too — a phrase NER spotted as a person/
        # location after layer-2 missed it should fail the descriptor
        # (the descriptor's contract is no PHI, even in the phrase
        # list, after the full layered pass).
        clean_phrases: list[str] = []
        for ph in cleaned.get("common_phrases", []):
            ent_types = _layer3_scan_string(ph, analyzer)
            if ent_types:
                for et in ent_types:
                    layer3_entities.append(("common_phrases", et))
            else:
                clean_phrases.append(ph)
        cleaned["common_phrases"] = clean_phrases

    passed = not structural_fail

    return ScrubResult(
        passed=passed,
        scrubbed_descriptor=cleaned if passed else {},
        layer1_fields_dropped=layer1_drops,
        layer2_matches=layer2_matches,
        layer3_entities=layer3_entities,
        degraded=degraded,
    )
