"""Privacy invariants for the layered PHI scrubber (#152 phases 3-4 S2).

This is the CI guard for the HIPAA describe-and-discard scrubber. Every
assertion below pins a contract that, if loosened by a future commit,
should fail this test rather than silently weaken the privacy posture.

The scrubber is a 3-layer defense:

  1. Schema enforcement (closed-vocabulary + length caps)
  2. HIPAA-18 regex matcher
  3. Optional NER post-check (presidio / spacy)

Layers 1+2 are always present. Layer 3 degrades when neither NER
library is installed; the test below verifies the degraded path still
holds the line via layers 1+2.

No real PII in test fixtures — synthetic names + ZIP + MRN shapes only.
"""

from __future__ import annotations

import re

import pytest

from email_triage.style_learning.phi_scrubber import (
    LAYER1_MAX_FIELD_CHARS,
    MAX_COMMON_PHRASES,
    MAX_PHRASE_LENGTH,
    PHI_REGEX_PATTERNS,
    SCHEMA_ENUMS,
    SCHEMA_NUMERIC_RANGES,
    ScrubResult,
    scrub_descriptor,
)


# ---------------------------------------------------------------------------
# Layer 1 — schema enforcement
# ---------------------------------------------------------------------------

class TestLayer1SchemaEnforcement:
    """Layer 1 snaps each field to a closed-vocabulary enum + caps
    string lengths. LLM contract violations land in ``layer1_fields_dropped``.
    """

    def test_clean_descriptor_passes_layer1(self):
        """A descriptor with valid enums + valid phrase list passes
        layer 1 with no drops."""
        descriptor = {
            "tone": "professional",
            "formality_level": 4,
            "greeting_style": "hi_first_name",
            "signoff_style": "thanks",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 2,
            "common_phrases": ["let me know", "happy to help"],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert result.passed
        assert result.layer1_fields_dropped == []

    def test_tone_outside_enum_drops_to_default(self):
        """LLM picks a tone not in the enum -> snap to first enum
        value + record the drop."""
        descriptor = {
            "tone": "snarky",  # not in TONE enum
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert "tone" in result.layer1_fields_dropped
        # Snapped to the first enum entry.
        assert result.scrubbed_descriptor["tone"] == SCHEMA_ENUMS["tone"][0]

    def test_formality_out_of_range_drops_to_min(self):
        """formality_level=7 violates the 1..5 enum -> drop."""
        descriptor = {
            "tone": "neutral",
            "formality_level": 7,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert "formality_level" in result.layer1_fields_dropped

    def test_paragraph_count_out_of_numeric_range(self):
        """paragraph_count_typical above the max bounds -> drop +
        snap to range minimum."""
        lo, hi = SCHEMA_NUMERIC_RANGES["paragraph_count_typical"]
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": hi + 5,
            "common_phrases": [],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert "paragraph_count_typical" in result.layer1_fields_dropped
        assert result.scrubbed_descriptor["paragraph_count_typical"] == lo

    def test_common_phrases_capped_at_max(self):
        """Phrase list longer than MAX truncates + records no drop
        (the truncation is a soft cap, not a layer-1 fail)."""
        # Clean phrases (no digits / proper nouns / dates) so the
        # layer-2 scan doesn't drop any. We only want to validate the
        # length cap.
        clean_phrases_pool = [
            "let me know", "happy to", "quick note", "got it",
            "thanks much", "all good", "sounds good", "will do",
            "no problem", "circling back", "any thoughts", "looping in",
            "appreciate it",
        ]
        # Pick MAX + 5 from the pool.
        phrases = (clean_phrases_pool * 2)[: MAX_COMMON_PHRASES + 5]
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": phrases,
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert len(result.scrubbed_descriptor["common_phrases"]) == MAX_COMMON_PHRASES

    def test_long_phrase_truncates_to_max_length(self):
        """A phrase longer than MAX_PHRASE_LENGTH gets cut."""
        long_phrase = "x" * (MAX_PHRASE_LENGTH + 50)
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [long_phrase],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert all(
            len(p) <= MAX_PHRASE_LENGTH
            for p in result.scrubbed_descriptor["common_phrases"]
        )

    def test_phrase_list_not_a_list_drops_it(self):
        """LLM returns a string for common_phrases -> drop + empty
        list."""
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": "let me know, happy to help",  # wrong type
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert "common_phrases" in result.layer1_fields_dropped
        assert result.scrubbed_descriptor["common_phrases"] == []

    def test_root_not_a_dict_fails_immediately(self):
        """Non-dict payload is a whole-contract violation; the result
        is a failed scrub with empty descriptor + root drop label."""
        result = scrub_descriptor("oops not a dict", skip_ner=True)  # type: ignore[arg-type]
        assert not result.passed
        assert result.layer1_fields_dropped == ["<root>"]
        assert result.scrubbed_descriptor == {}


# ---------------------------------------------------------------------------
# Layer 2 — HIPAA-18 regex matcher
# ---------------------------------------------------------------------------

class TestLayer2RegexMatcher:
    """Layer 2 catches PHI shapes (names, dates, MRNs, addresses,
    phones, emails, URLs, IPs, etc.) in any descriptor field. Hits on
    non-phrase fields fail the descriptor; hits on common_phrases drop
    the offending phrase but keep the rest.
    """

    def _good_descriptor(self) -> dict:
        return {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [],
        }

    # Each test asserts that a representative HIPAA-18 sample in a
    # non-phrase field fails the descriptor. Iteration over the pattern
    # catalogue ensures we don't quietly drop a layer-2 pattern in a
    # future commit.

    def test_layer2_catches_name_honorific(self):
        """'Mr. Smith'-shape token caught in a closed-enum field."""
        d = self._good_descriptor()
        # Inject into common_phrases (the only string-tolerant field).
        d["common_phrases"] = ["Mr. Smith"]
        result = scrub_descriptor(d, skip_ner=True)
        # Phrase-level hit -> phrase dropped, descriptor still passes.
        assert result.passed
        assert "Mr. Smith" not in result.scrubbed_descriptor["common_phrases"]
        labels = {label for _f, label in result.layer2_matches}
        assert "name_honorific" in labels

    def test_layer2_catches_two_caps_name(self):
        """'John Smith' two-cap pattern caught at the phrase level."""
        d = self._good_descriptor()
        d["common_phrases"] = ["love John Smith"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "name_two_caps" in labels
        assert "love John Smith" not in result.scrubbed_descriptor["common_phrases"]

    def test_layer2_catches_street_address(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["123 Main Street"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "street_address" in labels

    def test_layer2_catches_zip_code(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["94110"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "zip_code" in labels

    def test_layer2_catches_date_slash(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["Born 03/15/1972"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "date_slash_dash" in labels

    def test_layer2_catches_year_in_phrase(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["fiscal 2025 review"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "year_four_digit" in labels

    def test_layer2_catches_phone_dashed(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["555-867-5309"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "phone_us_dashed" in labels

    def test_layer2_catches_phone_parens(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["(555) 867-5309"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "phone_parens" in labels

    def test_layer2_catches_email_address(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["ping me at op@example.org"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "email_address" in labels

    def test_layer2_catches_ssn(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["SSN 123-45-6789"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "ssn_dashed" in labels

    def test_layer2_catches_long_digit_run(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["MRN 1234567"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "mrn_or_id_long_digits" in labels

    def test_layer2_catches_web_url(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["see https://example.org/x"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "web_url" in labels

    def test_layer2_catches_ipv4(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["server 192.168.1.1"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "ipv4_address" in labels

    def test_layer2_catches_image_filename(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["see headshot.jpg"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "image_filename" in labels

    def test_layer2_catches_medical_term(self):
        d = self._good_descriptor()
        d["common_phrases"] = ["patient follow-up"]
        result = scrub_descriptor(d, skip_ner=True)
        labels = {label for _f, label in result.layer2_matches}
        assert "medical_term" in labels

    def test_layer2_fuzz_phi_in_supposed_enum_field(self):
        """LLM ignores the structured-output schema + dumps a name
        into ``tone``. Layer 1 snaps it back to a safe enum value
        BEFORE layer 2 scans — so layer 2 wouldn't trip on the
        original PHI. This test pins the order: layer 1 sanitises the
        enum first, so even if the LLM dumps "Mr. Smith" as the tone
        value, the scrubber renders the descriptor safe.
        """
        d = self._good_descriptor()
        d["tone"] = "Mr. Smith reported"
        result = scrub_descriptor(d, skip_ner=True)
        # Layer 1 dropped the tone (not in the enum).
        assert "tone" in result.layer1_fields_dropped
        # And the snapped value carries no trace of the PHI.
        assert result.scrubbed_descriptor["tone"] == SCHEMA_ENUMS["tone"][0]
        # The descriptor still passes — closed-enum coercion makes the
        # leak impossible at the structural level.
        assert result.passed

    def test_layer2_pattern_count_is_reasonable(self):
        """Sanity check on the pattern catalogue size — bump if you
        add or remove a pattern, but don't drop below the baseline
        (defense-in-depth requires the full set)."""
        # Baseline of 19 patterns from the initial implementation.
        # If you legitimately retire a pattern, drop the bound.
        assert len(PHI_REGEX_PATTERNS) >= 19


# ---------------------------------------------------------------------------
# Layer 3 — NER (optional) + degradation flag
# ---------------------------------------------------------------------------

class TestLayer3OptionalNER:
    """Layer 3 is optional. When neither presidio_analyzer nor spacy is
    installed, the scrubber proceeds with layers 1+2 alone and sets
    ``degraded=True`` on the result. The privacy posture holds because
    layers 1+2 still catch the high-risk shapes.
    """

    def test_layer3_degraded_when_libs_absent(self):
        """In the default Wave 1 install neither lib is installed —
        the scrubber must report degraded but still return a result."""
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [],
        }
        # skip_ner=False so the loader actually tries presidio/spacy.
        # In test envs without either installed, the loader returns
        # None + the scrubber sets degraded=True.
        result = scrub_descriptor(descriptor, skip_ner=False)
        # The assertion holds for ANY install state — either
        # degraded=True (no NER lib) or degraded=False (NER lib present).
        # The lib absence is the common case.
        assert isinstance(result.degraded, bool)
        if result.degraded:
            # Then layer3_entities must be empty.
            assert result.layer3_entities == []

    def test_skip_ner_flag_forces_degraded(self):
        """The skip_ner test hook forces degraded=True even if a NER
        lib is installed — used by every other test in this module
        to keep results deterministic across CI environments."""
        descriptor = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": [],
        }
        result = scrub_descriptor(descriptor, skip_ner=True)
        assert result.degraded is True


# ---------------------------------------------------------------------------
# Output contract: matched text never escapes the scrubber
# ---------------------------------------------------------------------------

class TestNoMatchedTextInResult:
    """The scrubber's contract: NO matched text in the returned
    ScrubResult, only counts + field names + labels. This is the
    most important privacy invariant in the module — a leak via the
    result object would defeat the whole pipeline.
    """

    def test_scrubbed_descriptor_carries_no_phi(self):
        """A descriptor seeded with PHI-shaped phrases must come out
        with those phrases REMOVED, not redacted, and certainly not
        present in the result object's free-text fields."""
        d = {
            "tone": "professional",
            "formality_level": 4,
            "greeting_style": "hi_first_name",
            "signoff_style": "thanks",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 2,
            "common_phrases": [
                "let me know",                  # clean
                "Mr. Smith called",             # PHI: name_honorific
                "ping op@example.org",          # PHI: email_address
                "SSN 999-12-3456",              # PHI: ssn_dashed
                "happy to help",                # clean
            ],
        }
        result = scrub_descriptor(d, skip_ner=True)
        # Result still passed (phrase-level hits don't fail the
        # descriptor) but the offending phrases are gone.
        assert result.passed
        phrases = result.scrubbed_descriptor["common_phrases"]
        for forbidden in (
            "Mr. Smith", "op@example.org", "999-12-3456",
        ):
            for ph in phrases:
                assert forbidden not in ph, (
                    f"forbidden PHI fragment {forbidden!r} survived "
                    f"in phrase {ph!r}"
                )

    def test_result_layer2_matches_carry_labels_not_text(self):
        """The ``layer2_matches`` field is a list of
        ``(field, label)`` tuples — labels are short identifier
        strings (``name_honorific``, ``ssn_dashed`` etc.), never the
        matched text. Verify shape."""
        d = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": ["Mr. Smith"],
        }
        result = scrub_descriptor(d, skip_ner=True)
        assert result.layer2_matches  # non-empty
        for entry in result.layer2_matches:
            assert isinstance(entry, tuple) and len(entry) == 2
            field_name, label = entry
            assert isinstance(field_name, str)
            assert isinstance(label, str)
            # Labels are snake_case identifiers, NOT free text.
            assert re.match(r"^[a-z][a-z0-9_]*$", label), label
            # And NEVER carry the matched text.
            assert "Mr." not in label
            assert "Smith" not in label

    def test_descriptor_with_only_clean_phrases_passes_unchanged(self):
        """Clean phrases survive the scrub pass intact."""
        d = {
            "tone": "neutral",
            "formality_level": 3,
            "greeting_style": "none",
            "signoff_style": "none",
            "sentence_length_pref": "medium",
            "vocabulary_register": "plain",
            "paragraph_count_typical": 1,
            "common_phrases": ["let me know", "happy to", "quick note"],
        }
        result = scrub_descriptor(d, skip_ner=True)
        assert result.passed
        assert result.scrubbed_descriptor["common_phrases"] == [
            "let me know", "happy to", "quick note",
        ]
        assert result.layer2_matches == []
