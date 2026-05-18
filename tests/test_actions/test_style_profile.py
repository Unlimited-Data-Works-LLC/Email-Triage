"""Tests for ``actions.style_profile`` (M-3 — derived style distillation).

Scope: extract → structured profile, prompt-block formatting, and the
settings-table round-trip via :func:`get_style_profile` /
:func:`set_style_profile`. The classifier is mocked; no network IO.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.style_profile import (
    DISTILLATION_PROMPT,
    StyleProfile,
    _build_corpus_block,
    _parse_profile_json,
    _strip_quoted,
    extract_style_profile,
    format_profile_for_prompt,
)
from email_triage.engine.models import EmailMessage


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _msg(body: str, *, uid: str = "u1") -> EmailMessage:
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="me@example.com",
        recipients=["other@example.com"],
        subject="Re: hello",
        body_text=body,
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )


_GOOD_LLM_JSON = {
    "greeting": "Hi {name},",
    "signoff": "Thanks,\nCraig",
    "formality": 2,
    "avg_sentence_length": 9,
    "signature": "— Alex\nCraig L.",
    "phrases_used": ["let me know", "happy to", "quick note"],
    "phrases_avoided": ["I hope this email finds you well"],
    "persona_summary": "Direct and friendly; short sentences; no boilerplate.",
}


# ---------------------------------------------------------------------------
# StyleProfile dataclass
# ---------------------------------------------------------------------------

class TestStyleProfileDataclass:
    def test_round_trip(self):
        p = StyleProfile.from_dict(_GOOD_LLM_JSON)
        d = p.to_dict()
        # Sample_count / model_used carry across.
        assert d["greeting"] == "Hi {name},"
        assert d["signoff"] == "Thanks,\nCraig"
        assert d["formality"] == 2
        assert d["phrases_used"] == ["let me know", "happy to", "quick note"]

    def test_from_dict_tolerates_garbage(self):
        # Junk shouldn't crash construction.
        p = StyleProfile.from_dict(
            {"formality": "not-a-number", "phrases_used": "string-not-list"},
        )
        assert p.formality == 3  # default
        assert p.phrases_used == []

    def test_formality_is_clamped(self):
        # 1-5 range; values out of bounds clamp.
        assert StyleProfile.from_dict({"formality": 99}).formality == 5
        assert StyleProfile.from_dict({"formality": -3}).formality == 1

    def test_from_dict_handles_non_dict(self):
        assert StyleProfile.from_dict("nope").greeting == ""
        assert StyleProfile.from_dict(None).greeting == ""


# ---------------------------------------------------------------------------
# Quote stripping + corpus assembly
# ---------------------------------------------------------------------------

class TestStripQuoted:
    def test_strips_on_wrote_header(self):
        body = (
            "Sounds good, thanks.\n\n"
            "On Mon, May 1, 2026 at 10:00 AM, Alice <alice@x.com> wrote:\n"
            "> Hi there\n"
            "> Are you free?"
        )
        out = _strip_quoted(body)
        assert "Sounds good" in out
        assert "Alice" not in out
        assert ">" not in out

    def test_strips_lines_starting_with_quote(self):
        body = "My answer is yes.\n> previous\n> previous2"
        assert _strip_quoted(body) == "My answer is yes."

    def test_empty_returns_empty(self):
        assert _strip_quoted("") == ""


class TestBuildCorpusBlock:
    def test_drops_empty_after_stripping(self):
        msgs = [
            _msg("> just a quote\n> nothing original", uid="a"),
            _msg("Sure thing — happy to help.", uid="b"),
        ]
        corpus, count = _build_corpus_block(msgs)
        assert count == 1
        assert "happy to help" in corpus

    def test_truncates_long_messages(self):
        long_body = "word " * 1000
        corpus, count = _build_corpus_block([_msg(long_body)])
        assert count == 1
        assert "[truncated]" in corpus

    def test_separator_between_messages(self):
        corpus, count = _build_corpus_block(
            [_msg("first reply", uid="a"), _msg("second reply", uid="b")],
        )
        assert count == 2
        assert "---" in corpus


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

class TestParseProfileJson:
    def test_plain_json(self):
        assert _parse_profile_json('{"greeting": "Hi"}') == {"greeting": "Hi"}

    def test_with_code_fences(self):
        wrapped = "```json\n" + json.dumps(_GOOD_LLM_JSON) + "\n```"
        assert _parse_profile_json(wrapped)["greeting"] == "Hi {name},"

    def test_with_leading_chatter(self):
        text = "Sure, here is the profile:\n" + json.dumps(_GOOD_LLM_JSON)
        assert _parse_profile_json(text)["formality"] == 2

    def test_invalid_returns_empty(self):
        assert _parse_profile_json("not json at all") == {}
        assert _parse_profile_json("") == {}


# ---------------------------------------------------------------------------
# extract_style_profile (the public entrypoint)
# ---------------------------------------------------------------------------

class TestExtractStyleProfile:
    @pytest.mark.asyncio
    async def test_happy_path_assembles_structured_profile(self):
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps(_GOOD_LLM_JSON)
        # mock model attribute — the action records this for audit.
        classifier.model = "qwen2.5:7b"

        msgs = [
            _msg("Sure — happy to help on that.", uid="a"),
            _msg("Quick note: we shipped it Tuesday.", uid="b"),
            _msg("Let me know what you decide.", uid="c"),
        ]
        profile = await extract_style_profile(msgs, classifier)

        # Structured shape, every M-3 key present.
        assert profile.greeting == "Hi {name},"
        assert profile.signoff == "Thanks,\nCraig"
        assert profile.formality == 2
        assert profile.avg_sentence_length == 9
        assert profile.signature.startswith("— Alex")
        assert "let me know" in profile.phrases_used
        assert "I hope this email finds you well" in profile.phrases_avoided
        assert profile.persona_summary
        # Metadata the LLM doesn't see is overridden by the caller.
        assert profile.sample_count == 3
        assert profile.model_used == "qwen2.5:7b"

        # Confirm the classifier got the actual prompt template — the
        # corpus injection point is load-bearing for future M-5
        # consumers.
        called_prompt = classifier.complete.call_args[0][0]
        assert "USER WRITING STYLE" not in called_prompt  # that's M-5's render
        assert "JSON object" in called_prompt
        assert "happy to help on that" in called_prompt
        assert "Quick note" in called_prompt

    @pytest.mark.asyncio
    async def test_empty_corpus_returns_empty_profile(self):
        classifier = AsyncMock()
        classifier.model = "qwen2.5:7b"
        profile = await extract_style_profile([], classifier)
        assert profile.sample_count == 0
        assert profile.greeting == ""
        # Should NOT have called the LLM with no input.
        classifier.complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_llm_failure_degrades_to_default_profile(self):
        classifier = AsyncMock()
        classifier.model = "qwen2.5:7b"
        classifier.complete.side_effect = RuntimeError("ollama down")
        profile = await extract_style_profile(
            [_msg("real reply", uid="a")], classifier,
        )
        # Empty profile but sample_count + model_used survive — the
        # operator can see the build attempt happened.
        assert profile.sample_count == 1
        assert profile.greeting == ""
        assert profile.model_used == "qwen2.5:7b"

    @pytest.mark.asyncio
    async def test_classifier_without_complete_returns_default(self):
        classifier = AsyncMock()
        classifier.model = "fallback-only"
        classifier.complete.side_effect = NotImplementedError()
        profile = await extract_style_profile(
            [_msg("real reply", uid="a")], classifier,
        )
        assert profile.sample_count == 1
        assert profile.persona_summary == ""

    @pytest.mark.asyncio
    async def test_unparseable_json_uses_defaults(self):
        classifier = AsyncMock()
        classifier.model = "qwen2.5:7b"
        classifier.complete.return_value = "the LLM forgot how to JSON"
        profile = await extract_style_profile(
            [_msg("real reply", uid="a")], classifier,
        )
        assert profile.sample_count == 1
        assert profile.greeting == ""


# ---------------------------------------------------------------------------
# format_profile_for_prompt (the M-5 hand-off shape)
# ---------------------------------------------------------------------------

class TestFormatProfileForPrompt:
    def test_full_profile_renders_all_lines(self):
        profile = StyleProfile.from_dict(_GOOD_LLM_JSON)
        profile.sample_count = 12
        block = format_profile_for_prompt(profile)

        assert block.startswith("[USER WRITING STYLE]")
        assert block.endswith("[END USER WRITING STYLE]")
        assert "Persona: Direct and friendly" in block
        assert "Formality: 2/5 (casual)" in block
        assert "Typical greeting: Hi {name}," in block
        # Multi-line signoff collapses for prompt compactness.
        assert "Typical sign-off: Thanks, / Alex" in block
        assert "Average sentence length: ~9 words" in block
        assert '"let me know"' in block
        assert '"I hope this email finds you well"' in block

    def test_empty_profile_returns_empty_string(self):
        # Untouched defaults — the M-5 caller can branch on "" vs not.
        profile = StyleProfile()
        assert format_profile_for_prompt(profile) == ""

    def test_partial_profile_omits_unknown_fields(self):
        # Persona summary alone is enough to render a useful block.
        profile = StyleProfile(
            persona_summary="Terse and direct. No pleasantries.",
            formality=1,
            sample_count=5,
        )
        block = format_profile_for_prompt(profile)
        assert "Persona:" in block
        assert "Formality: 1/5 (terse)" in block
        # No phrases / signature / signoff / greeting → not in block.
        assert "Typical greeting" not in block
        assert "Phrases" not in block
        assert "Signature" not in block


# ---------------------------------------------------------------------------
# Settings-table persistence round-trip
# ---------------------------------------------------------------------------

class TestStyleProfilePersistence:
    def test_round_trip_through_settings_table(self, tmp_path):
        from email_triage.web.db import (
            delete_style_profile, get_style_profile,
            init_db, set_style_profile,
        )

        db_path = tmp_path / "triage.db"
        conn = init_db(str(db_path))

        # Pre-existing read returns None.
        assert get_style_profile(conn, account_id=42) is None

        profile = StyleProfile.from_dict(_GOOD_LLM_JSON)
        profile.sample_count = 7
        profile.model_used = "qwen2.5:7b"
        set_style_profile(conn, 42, profile.to_dict())

        loaded = get_style_profile(conn, 42)
        assert loaded is not None
        # Fields make the round trip.
        assert loaded["greeting"] == "Hi {name},"
        assert loaded["sample_count"] == 7
        assert loaded["model_used"] == "qwen2.5:7b"

        # Rehydrate via from_dict — should produce a profile equal
        # to the stored one.
        rehydrated = StyleProfile.from_dict(loaded)
        assert rehydrated.persona_summary == profile.persona_summary
        assert rehydrated.formality == profile.formality
        assert rehydrated.phrases_used == profile.phrases_used

        # Per-account isolation — a different account returns None.
        assert get_style_profile(conn, 99) is None

        # Deletion clears the row.
        assert delete_style_profile(conn, 42) is True
        assert get_style_profile(conn, 42) is None
        # Idempotent — second delete reports no-op.
        assert delete_style_profile(conn, 42) is False
