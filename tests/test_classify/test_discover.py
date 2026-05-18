"""Tests for category discovery prompt building."""

from datetime import datetime, timezone

from email_triage.classify.discover import (
    build_consolidation_prompt,
    build_discover_prompt,
)
from email_triage.engine.models import EmailMessage


def _make_email(**overrides) -> EmailMessage:
    defaults = dict(
        message_id="m1",
        provider="test",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Hello",
        body_text="This is the body.",
        date=datetime(2026, 4, 14, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


class TestBuildDiscoverPrompt:
    """Tests for build_discover_prompt()."""

    def test_contains_email_content(self):
        msg = _make_email(subject="Invoice #1234", sender="billing@acme.com")
        prompt = build_discover_prompt(msg)
        assert "Invoice #1234" in prompt
        assert "billing@acme.com" in prompt

    def test_contains_json_format_instructions(self):
        prompt = build_discover_prompt(_make_email())
        assert '"category"' in prompt
        assert '"description"' in prompt

    def test_no_predefined_categories(self):
        prompt = build_discover_prompt(_make_email())
        assert "Do not use predefined categories" in prompt

    def test_injection_guard_present(self):
        prompt = build_discover_prompt(_make_email())
        assert "EMAIL DATA ONLY" in prompt

    def test_slug_format_instructions(self):
        prompt = build_discover_prompt(_make_email())
        assert "lowercase" in prompt
        assert "hyphens" in prompt


class TestBuildConsolidationPrompt:
    """Tests for build_consolidation_prompt()."""

    def test_includes_raw_suggestions(self):
        raw = [
            {"category": "billing", "description": "Bills", "count": 5, "examples": ["Invoice 1"]},
            {"category": "news", "description": "News emails", "count": 3, "examples": ["Daily digest"]},
        ]
        prompt = build_consolidation_prompt(raw, {})
        assert "billing" in prompt
        assert "news" in prompt
        assert "5x" in prompt
        assert "3x" in prompt

    def test_includes_existing_categories(self):
        raw = [{"category": "billing", "description": "Bills", "count": 2, "examples": []}]
        existing = {"invoices": "Bills and receipts", "to-respond": "Needs a reply"}
        prompt = build_consolidation_prompt(raw, existing)
        assert "invoices" in prompt
        assert "to-respond" in prompt
        assert "Bills and receipts" in prompt

    def test_empty_existing_categories(self):
        raw = [{"category": "billing", "description": "Bills", "count": 2, "examples": []}]
        prompt = build_consolidation_prompt(raw, {})
        assert "(none configured)" in prompt

    def test_includes_examples(self):
        raw = [{"category": "billing", "description": "Bills", "count": 2,
                "examples": ["Invoice A", "Receipt B", "Statement C", "Bill D"]}]
        prompt = build_consolidation_prompt(raw, {})
        # Only first 3 examples are included.
        assert "Invoice A" in prompt
        assert "Receipt B" in prompt
        assert "Statement C" in prompt
        assert "Bill D" not in prompt

    def test_merge_instructions(self):
        raw = [{"category": "billing", "description": "Bills", "count": 1, "examples": []}]
        prompt = build_consolidation_prompt(raw, {})
        assert "Merge synonyms" in prompt
        assert "is_new" in prompt
        assert "merged_from" in prompt

    def test_json_array_format(self):
        raw = [{"category": "billing", "description": "Bills", "count": 1, "examples": []}]
        prompt = build_consolidation_prompt(raw, {})
        assert "JSON array" in prompt

    def test_category_limit(self):
        raw = [{"category": "billing", "description": "Bills", "count": 1, "examples": []}]
        prompt = build_consolidation_prompt(raw, {})
        assert "15" in prompt  # "no more than ~15 categories"
