"""Tests for the newsletter digest generator."""

import json
from datetime import datetime, timezone

import pytest

from email_triage.actions.digest import (
    Article,
    DEFAULT_FORMAT_PROMPT,
    SenderGroup,
    _extract_sender_name,
    _parse_json_array,
    build_digest_html,
    extract_articles,
    generate_digest,
)
from email_triage.engine.models import EmailMessage


def _make_message(
    sender="Techpresso <news@techpresso.com>",
    subject="Daily Tech News",
    body="Article 1: AI breakthrough. Article 2: New chip released.",
    uid="100",
    links=None,
) -> EmailMessage:
    if links is None:
        links = [
            ("AI Breakthrough", "https://example.com/ai"),
            ("New Chip", "https://example.com/chip"),
        ]
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender=sender,
        recipients=["user@test.com"],
        subject=subject,
        body_text=body,
        date=datetime.now(timezone.utc),
        links=links,
    )


class TestSenderNameExtraction:
    def test_display_name(self):
        assert _extract_sender_name("Techpresso <news@techpresso.com>") == "Techpresso"

    def test_quoted_name(self):
        assert _extract_sender_name('"The Morning Brew" <team@morningbrew.com>') == "The Morning Brew"

    def test_email_only_generic_local(self):
        # Generic local part → use domain name.
        assert _extract_sender_name("newsletter@techcrunch.com") == "Techcrunch"

    def test_email_only_specific_local(self):
        assert _extract_sender_name("ben.thompson@stratechery.com") == "Ben Thompson"

    def test_noreply(self):
        assert _extract_sender_name("noreply@substack.com") == "Substack"

    def test_plain_string(self):
        assert _extract_sender_name("Some Sender") == "Some Sender"


class TestParseJsonArray:
    def test_simple_array(self):
        result = _parse_json_array('[{"headline": "Test", "summary": "Desc"}]')
        assert len(result) == 1
        assert result[0]["headline"] == "Test"

    def test_with_code_fences(self):
        text = '```json\n[{"headline": "Test", "summary": "Desc"}]\n```'
        result = _parse_json_array(text)
        assert len(result) == 1

    def test_single_object(self):
        result = _parse_json_array('{"headline": "Test", "summary": "Desc"}')
        assert len(result) == 1

    def test_empty_array(self):
        assert _parse_json_array("[]") == []

    def test_no_json(self):
        assert _parse_json_array("no json here") == []


class TestExtractArticles:
    @pytest.mark.asyncio
    async def test_successful_extraction(self):
        """Mock classifier returns valid JSON articles."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "AI Breakthrough", "summary": "Major advance in LLMs.", "url": "https://example.com/ai"},
            {"headline": "New Chip", "summary": "Intel releases new chip.", "url": None},
        ])

        msg = _make_message()
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 2
        assert articles[0].headline == "AI Breakthrough"
        assert articles[0].url == "https://example.com/ai"
        assert articles[1].headline == "New Chip"
        assert articles[1].url is None

    @pytest.mark.asyncio
    async def test_extraction_with_fences(self):
        """Classifier wraps JSON in markdown fences."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = (
            '```json\n[{"headline": "Test", "summary": "A test.", "url": null}]\n```'
        )

        msg = _make_message()
        articles = await extract_articles(classifier, msg)
        assert len(articles) == 1
        assert articles[0].headline == "Test"

    @pytest.mark.asyncio
    async def test_extraction_failure_fallback(self):
        """On failure, falls back to treating email as one article."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.side_effect = RuntimeError("LLM down")

        msg = _make_message(subject="Newsletter", body="Some content here.")
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 1
        assert articles[0].headline == "Newsletter"
        assert "Some content" in articles[0].summary

    @pytest.mark.asyncio
    async def test_extraction_empty_array(self):
        """Classifier returns empty array."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = "[]"

        msg = _make_message()
        articles = await extract_articles(classifier, msg)
        assert articles == []

    @pytest.mark.asyncio
    async def test_url_constrained_to_known_links(self):
        """LLM-returned URL not in the message's links set is dropped."""
        import json
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "Fake", "summary": "x",
             "url": "https://evil.com/hallucinated"},
        ])
        msg = _make_message(
            links=[("Real Link", "https://real.com/a")],
        )
        articles = await extract_articles(classifier, msg)
        assert len(articles) == 1
        assert articles[0].url is None  # hallucinated URL dropped

    @pytest.mark.asyncio
    async def test_hipaa_msg_skips_external_classifier(self):
        """HIPAA-flagged msg + non-local classifier -> subject-only fallback,
        classifier.complete never called."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.is_local = False
        classifier.complete = AsyncMock()

        msg = _make_message(subject="PHI Subject")
        msg.hipaa = True
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 1
        assert articles[0].headline == "PHI Subject"
        assert articles[0].url is None
        classifier.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_hipaa_msg_allowed_on_local_classifier(self):
        """HIPAA-flagged msg + local classifier -> normal extraction runs."""
        import json
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.is_local = True
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        msg = _make_message()
        msg.hipaa = True
        articles = await extract_articles(classifier, msg)
        classifier.complete.assert_called_once()
        assert articles[0].headline == "H"


class TestBuildDigestHtml:
    def test_basic_digest(self):
        groups = {
            "news@techpresso.com": SenderGroup(
                sender_name="Techpresso",
                sender_email="news@techpresso.com",
                articles=[
                    Article("AI Update", "Big news in AI.", "https://example.com/ai"),
                    Article("Chip News", "New chip released.", None),
                ],
            ),
        }
        html = build_digest_html(groups, "Tuesday, April 15, 2026")

        # Minimal template — intro line + bold group name + <ul>.
        # Big <h2>Newsletter Digest</h2> header is gone.
        assert "Here is your daily digest" in html
        assert "newsletters" in html
        assert "<strong>Techpresso</strong>" in html
        assert "AI Update" in html
        assert "Chip News" in html
        assert "https://example.com/ai" in html
        assert "Read more" in html

    def test_multiple_senders(self):
        groups = {
            "a@test.com": SenderGroup(
                sender_name="Alpha",
                sender_email="a@test.com",
                articles=[Article("Art1", "Sum1", None)],
            ),
            "b@test.com": SenderGroup(
                sender_name="Beta",
                sender_email="b@test.com",
                articles=[Article("Art2", "Sum2", None)],
            ),
        }
        html = build_digest_html(groups, "Today")
        assert "<strong>Alpha</strong>" in html
        assert "<strong>Beta</strong>" in html

    def test_empty_groups(self):
        html = build_digest_html({}, "Today")
        assert "No newsletters found" in html

    def test_html_escaping(self):
        groups = {
            "x@test.com": SenderGroup(
                sender_name="Test <Script>",
                sender_email="x@test.com",
                articles=[Article("Headline & More", "Summary <b>bold</b>", None)],
            ),
        }
        html = build_digest_html(groups, "Today")
        assert "&lt;Script&gt;" in html
        assert "&amp; More" in html
        assert "&lt;b&gt;" in html


class TestGenerateDigest:
    @pytest.mark.asyncio
    async def test_generate_basic(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "Article 1", "summary": "Summary 1.", "url": "https://ex.com/1"},
        ])

        provider = AsyncMock()
        messages = [_make_message(), _make_message(sender="Other <other@test.com>", uid="101")]

        html, article_count, source_count = await generate_digest(
            provider, classifier, messages,
        )

        assert article_count == 2  # 1 per message.
        assert source_count == 2
        assert "Article 1" in html
        assert "Here is your daily digest" in html

    @pytest.mark.asyncio
    async def test_generate_with_delete(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])

        provider = AsyncMock()
        messages = [_make_message()]

        await generate_digest(provider, classifier, messages, delete_originals=True)

        provider.archive.assert_called_once_with("100")

    @pytest.mark.asyncio
    async def test_generate_empty_messages(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        provider = AsyncMock()

        html, article_count, source_count = await generate_digest(
            provider, classifier, [],
        )

        assert article_count == 0
        assert "No newsletters found" in html


class TestDefaultFormatPrompt:
    def test_default_prompt_exists(self):
        assert "Group articles" in DEFAULT_FORMAT_PROMPT
        assert "sender" in DEFAULT_FORMAT_PROMPT
        assert "Read more" in DEFAULT_FORMAT_PROMPT


# ---------------------------------------------------------------------------
# Signature (#33 scope correction — signature lives on newsletter digest,
# not on the daily admin health email).
# ---------------------------------------------------------------------------

class TestDigestSignature:
    def _groups_with_one_article(self) -> dict:
        from email_triage.actions.digest import SenderGroup, Article
        return {
            "news@techpresso.com": SenderGroup(
                sender_name="Techpresso",
                sender_email="news@techpresso.com",
                articles=[Article(headline="AI news", summary="Stuff happened.")],
            ),
        }

    def test_digest_renders_default_signature_with_category_substituted(self):
        from email_triage.config import TriageConfig
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text, render_signature,
        )
        cfg = TriageConfig()
        signature = render_signature(
            cfg.summary_email.signature, category="Tech",
        )
        assert signature == "Sent by your email-triage Tech Digest 🗞️"

        html_out = build_digest_html(
            self._groups_with_one_article(), "Monday, April 22, 2026",
            signature=signature,
        )
        text_out = build_digest_text(
            self._groups_with_one_article(), "Monday, April 22, 2026",
            signature=signature,
        )
        assert "Sent by your email-triage Tech Digest" in html_out
        assert "Sent by your email-triage Tech Digest" in text_out

    def test_digest_signature_respects_config_override(self):
        from email_triage.actions.digest import (
            build_digest_html, render_signature,
        )
        override = "— curated by {category} bot"
        rendered = render_signature(override, category="Newsletters")
        html_out = build_digest_html(
            self._groups_with_one_article(), "today", signature=rendered,
        )
        assert "curated by Newsletters bot" in html_out

    def test_digest_signature_category_placeholder_tolerant_of_missing_values(self):
        from email_triage.actions.digest import render_signature
        # Reserved-for-later placeholders must pass through unchanged.
        out = render_signature(
            "{category} · {account} · {date} · {unknown}",
            category="Tech",
        )
        assert out == "Tech ·  ·  · {unknown}"

    def test_digest_signature_appears_in_both_html_and_text(self):
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text,
        )
        sig = "Sent by your email-triage Newsletters Digest"
        groups = self._groups_with_one_article()
        html_out = build_digest_html(groups, "today", signature=sig)
        text_out = build_digest_text(groups, "today", signature=sig)
        assert sig in html_out
        assert sig in text_out
        # Text version uses the standard sig-separator convention.
        assert "--" in text_out

    def test_digest_signature_absent_when_template_blank(self):
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text,
        )
        groups = self._groups_with_one_article()
        html_out = build_digest_html(groups, "today", signature="")
        text_out = build_digest_text(groups, "today", signature="")
        assert "email-triage" not in html_out
        assert "email-triage" not in text_out

    @pytest.mark.asyncio
    async def test_generate_digest_applies_signature_template(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        provider = AsyncMock()

        msg = _make_message()
        html_out, articles, sources = await generate_digest(
            provider, classifier, [msg], delete_originals=False,
            signature_template="Sent by your email-triage {category} Digest",
            category="Tech",
        )
        assert articles == 1
        assert "Sent by your email-triage Tech Digest" in html_out

    def test_digest_name_surfaces_in_compact_template(self):
        """Operator-typed DigestConfig.name renders at the top of
        the compact / default newsletter template so the recipient
        knows which digest sent the email when an account has
        multiple custom digests against different filters."""
        from email_triage.actions.digest import build_digest_html
        groups = self._groups_with_one_article()
        html_out = build_digest_html(
            groups, "today", signature="",
            digest_name="AI Newsletters",
        )
        assert "AI Newsletters" in html_out

    def test_digest_name_blank_omits_heading_compact(self):
        """No name → no h2 prefix (back-compat for callers that
        don't thread digest_name)."""
        from email_triage.actions.digest import build_digest_html
        groups = self._groups_with_one_article()
        html_out = build_digest_html(
            groups, "today", signature="", digest_name="",
        )
        # default DEFAULT_DIGEST_TEMPLATE only renders the h2 when
        # digest_name is truthy
        assert "<h2" not in html_out

    @pytest.mark.asyncio
    async def test_generate_digest_without_signature_template(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        provider = AsyncMock()

        msg = _make_message()
        html_out, _, _ = await generate_digest(
            provider, classifier, [msg], delete_originals=False,
        )
        assert "Sent by your email-triage" not in html_out
