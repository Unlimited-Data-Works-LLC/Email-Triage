"""Recovery paths for ``_parse_llm_json`` — the 2026-06-14 "rtx 5090 founders"
topic-match parse-failure class.

qwen3.x under Ollama ``format: json`` intermittently emits a JSON object that
strict ``json.loads`` rejects WITHOUT ``done_reason='length'`` (so the 
truncation guard cannot see it): either a RAW control char inside a string, or
the stop token mid-object (an unterminated string / an object cut before its
``}``). Confirmed empirically on qwen3.6:35b / Ollama 0.30.8 (a num_predict cut
DOES report ``length`` there — so the prod failure was not a token-cap cut).

The hardened parser recovers the completed fields instead of dropping every
topic verdict — a degradation, never a core-triage failure (§4.4). These tests
pin each recovery path; ``tests/test_classify/test_ollama.py::TestParseLlmJson``
pins the unchanged well-formed + trailing-junk behaviour.
"""
from __future__ import annotations

import pytest

from email_triage.classify.ollama import (
    _decode_first_object,
    _parse_llm_json,
    _salvage_incomplete_json_object,
)


class TestControlCharRecovery:
    def test_raw_newline_in_reason_recovers_full_object(self):
        # A literal newline inside a string makes strict json.loads raise; the
        # object is otherwise complete, so strict=False recovers it INTACT —
        # topic_verdicts included (the whole point: no verdict loss here).
        text = (
            '{"category": "promotions", "confidence": 0.9, '
            '"reason": "line one\nline two", '
            '"topic_verdicts": [{"topic_id": 1, "matched": true, '
            '"confidence": 0.8, "reason_terms": ["rtx"]}]}'
        )
        out = _parse_llm_json(text)
        assert out["category"] == "promotions"
        assert "line one" in out["reason"]
        assert out["topic_verdicts"][0]["reason_terms"] == ["rtx"]

    def test_raw_tab_in_reason(self):
        text = '{"category": "fyi", "confidence": 0.5, "reason": "a\tb"}'
        assert _parse_llm_json(text)["reason"] == "a\tb"


class TestTruncatedObjectRecovery:
    def test_unterminated_reason_string_recovers_prior_fields(self):
        # The EXACT prod shape: model stopped mid-reason (no closing quote/brace,
        # done_reason='stop'). Recover category+confidence and the partial reason.
        text = (
            '{"category": "promotions", "confidence": 0.95, '
            '"reason": "The email is an eBay notification alerting the user to '
            'new listings for a saved search item, which functions as a '
            'promotional or marketing mes'
        )
        out = _parse_llm_json(text)
        assert out["category"] == "promotions"
        assert out["confidence"] == 0.95
        assert out["reason"].startswith("The email is an eBay")

    def test_object_cut_right_after_complete_field_with_dangling_comma(self):
        text = '{"category": "updates", "confidence": 0.7, "reason": "done",'
        out = _parse_llm_json(text)
        assert out["category"] == "updates"
        assert out["reason"] == "done"

    def test_truncated_number_drops_partial_field_keeps_rest(self):
        # confidence cut mid-number -> that field is dropped, category survives.
        text = '{"category": "promotions", "confidence": 0.'
        out = _parse_llm_json(text)
        assert out["category"] == "promotions"

    def test_complete_verdicts_then_cut_preserves_verdicts(self):
        text = (
            '{"category": "other", "confidence": 0.9, "reason": "x", '
            '"topic_verdicts": [{"topic_id": 1, "matched": true, '
            '"confidence": 0.9, "reason_terms": ["lupus"]}], "extra'
        )
        out = _parse_llm_json(text)
        assert out["topic_verdicts"][0]["reason_terms"] == ["lupus"]

    def test_cut_inside_verdicts_array_recovers_outer_fields(self):
        text = (
            '{"category": "other", "confidence": 0.9, "reason": "x", '
            '"topic_verdicts": [{"topic_id": 1, "matched": tr'
        )
        out = _parse_llm_json(text)
        assert out["category"] == "other"
        assert isinstance(out.get("topic_verdicts", []), list)

    def test_trailing_partial_verdict_string_recovered_via_synthetic_close(self):
        # A complete first verdict, then a SECOND verdict cut inside its trailing
        # reason_terms string. The synthetic-close path (longest-prefix) recovers
        # BOTH verdicts — the partial second one with its in-progress term — so
        # the digest keeps real matches it would otherwise drop wholesale, and
        # _parse_topic_verdicts gets a clean, accept-able entry (db-sme NIT).
        text = (
            '{"category": "other", "confidence": 0.9, "reason": "x", '
            '"topic_verdicts": [{"topic_id": 1, "matched": true, '
            '"confidence": 0.9, "reason_terms": ["lupus"]}, '
            '{"topic_id": 2, "matched": true, "confidence": 0.7, '
            '"reason_terms": ["nephritis'
        )
        out = _parse_llm_json(text)
        ids = [v["topic_id"] for v in out["topic_verdicts"]]
        assert ids == [1, 2]
        assert out["topic_verdicts"][1]["reason_terms"] == ["nephritis"]


class TestNoFalsePositives:
    def test_bare_open_brace_is_unrecoverable(self):
        # '{' salvages only to '{}' (empty) -> rejected -> raises -> triggers
        # the caller's bounded retry rather than a silent empty classification.
        with pytest.raises(ValueError):
            _parse_llm_json("{")

    def test_no_brace_raises_unchanged(self):
        with pytest.raises(ValueError, match="No JSON object found"):
            _parse_llm_json("no json here at all")

    def test_well_formed_unchanged(self):
        text = '{"category": "fyi", "confidence": 0.6, "reason": "ok"}'
        assert _parse_llm_json(text)["category"] == "fyi"

    def test_strict_path_wins_for_trailing_stray_brace(self):
        # raw_decode strict stops at the first complete value -> stray '}' ignored
        # (unchanged 2026-06-08 behaviour; salvage never runs here).
        text = '{"category": "a", "confidence": 0.5, "reason": "r"}}'
        assert _parse_llm_json(text)["category"] == "a"

    def test_unterminated_object_with_escaped_quotes_in_reason(self):
        # reason contains properly-escaped quotes; object missing its '}'.
        text = '{"category": "a", "reason": "she said \\"hi\\""'
        out = _parse_llm_json(text)
        assert out["category"] == "a"
        assert out["reason"] == 'she said "hi"'

    def test_diagnostic_message_is_structural_only(self):
        # The raised message must NOT leak free-text content (PHI-safe): only a
        # length + the 40-char skeleton head (before any reason text).
        unrecoverable = '{"cat'  # unterminated key -> nothing recoverable
        with pytest.raises(ValueError) as ei:
            _parse_llm_json(unrecoverable)
        assert "len=" in str(ei.value)


class TestHelpersDirect:
    def test_salvage_returns_none_for_empty_object(self):
        assert _salvage_incomplete_json_object("{}", 0) is None

    def test_decode_first_object_strict_first(self):
        assert _decode_first_object('{"a": 1}', 0) == ({"a": 1}, "strict")

    def test_decode_first_object_lenient_tier_for_control_char(self):
        # raw newline inside a string -> strict fails, strict=False (lenient) wins.
        obj, tier = _decode_first_object('{"a": "x\ny"}', 0)
        assert obj == {"a": "x\ny"}
        assert tier == "lenient"

    def test_decode_first_object_salvage_tier_for_truncation(self):
        obj, tier = _decode_first_object('{"a": "x", "b": 1', 0)
        assert obj == {"a": "x", "b": 1}
        assert tier == "salvage"

    def test_decode_first_object_unrecoverable_returns_none(self):
        assert _decode_first_object('{"k', 0) == (None, None)


class TestStructuredOutputSchemas:
    """N-93 F2: the Ollama ``format``-schema constants that grammar-constrain
    the model to valid JSON (the source-side fix; salvage above is the
    backstop). Adopted after 15/15 clean validation on qwen3.6:35b / 0.30.8."""

    def test_classify_schema_shape(self):
        from email_triage.classify.ollama import _CLASSIFY_JSON_SCHEMA as s
        assert s["type"] == "object"
        assert s["required"] == ["category", "confidence", "reason"]
        assert set(s["properties"]) == {"category", "confidence", "reason"}

    def test_topic_match_schema_shape(self):
        from email_triage.classify.ollama import _TOPIC_MATCH_JSON_SCHEMA as s
        assert s["type"] == "object"
        # topic_verdicts is a property but OPTIONAL (not in required) — the model
        # omits it on no-match and the §4.4 path reads it via .get().
        assert "topic_verdicts" in s["properties"]
        assert "topic_verdicts" not in s["required"]
        item = s["properties"]["topic_verdicts"]["items"]
        assert item["required"] == ["topic_id", "matched"]
