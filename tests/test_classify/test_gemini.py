"""Tests for the Gemini classifier with mocked HTTP responses."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from email_triage.classify.gemini import GeminiClassifier
from email_triage.engine.models import EmailMessage, ListHint, RuleType


_CATEGORIES = {
    "to-respond": "Emails that need a reply",
    "invoices": "Bills and receipts",
    "fyi": "Informational",
}


def _make_email(**overrides) -> EmailMessage:
    defaults = dict(
        message_id="m1",
        provider="test",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Test",
        body_text="Body.",
        date=datetime(2026, 4, 14, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


def _gemini_response(category: str, confidence: float, reason: str) -> dict:
    """Build a mock Gemini generateContent response."""
    content = json.dumps({
        "category": category,
        "confidence": confidence,
        "reason": reason,
    })
    return {
        "candidates": [{
            "content": {
                "parts": [{"text": content}],
                "role": "model",
            },
            "finishReason": "STOP",
        }],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 20,
        },
    }


class TestGeminiClassifier:
    @pytest.fixture
    def classifier(self):
        return GeminiClassifier(
            model="gemini-2.0-flash",
            api_key="test-api-key",
        )

    async def test_basic_classification(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("to-respond", 0.92, "Needs reply.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await classifier.classify(_make_email(), _CATEGORIES)

        assert result.category == "to-respond"
        assert result.confidence == 0.92
        assert result.reason == "Needs reply."
        assert result.source == "llm"

    async def test_correct_endpoint(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("fyi", 0.7, "Info.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        url = call_args[0][0]
        assert "gemini-2.0-flash" in url
        assert "generateContent" in url

    async def test_api_key_in_params(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("fyi", 0.6, "FYI.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        params = call_args.kwargs.get("params", {})
        assert params["key"] == "test-api-key"

    async def test_system_instruction_in_payload(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("invoices", 0.85, "Bill.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json", {})
        assert "systemInstruction" in payload
        assert "contents" in payload
        assert payload["generationConfig"]["responseMimeType"] == "application/json"

    async def test_confidence_clamped(self, classifier):
        """Confidence values outside [0, 1] are clamped."""
        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("fyi", 1.5, "Very confident.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await classifier.classify(_make_email(), _CATEGORIES)

        assert result.confidence == 1.0

    async def test_with_list_hints(self, classifier):
        """List hints are passed to the prompt builder."""
        hints = [
            ListHint(category="invoices", rule_type=RuleType.SENDER,
                     pattern="billing@company.com", list_name="Billing"),
        ]

        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("invoices", 0.95, "Billing email.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await classifier.classify(
                _make_email(sender="billing@company.com"),
                _CATEGORIES,
                list_hints=hints,
            )

        assert result.category == "invoices"

    async def test_no_api_key(self):
        """Classifier works without API key (params should be empty)."""
        classifier = GeminiClassifier(model="gemini-2.0-flash")

        mock_resp = Mock()
        mock_resp.json.return_value = _gemini_response("fyi", 0.7, "Info.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        params = call_args.kwargs.get("params", {})
        assert "key" not in params

    async def test_empty_response(self, classifier):
        """Empty candidate list raises ValueError from _parse_llm_json."""
        mock_resp = Mock()
        mock_resp.json.return_value = {"candidates": []}
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.gemini.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with pytest.raises(ValueError, match="No JSON object"):
                await classifier.classify(_make_email(), _CATEGORIES)


class TestExtractText:
    def test_normal_response(self):
        body = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello!"}],
                    "role": "model",
                },
            }],
        }
        assert GeminiClassifier._extract_text(body) == "Hello!"

    def test_empty_candidates(self):
        assert GeminiClassifier._extract_text({"candidates": []}) == ""

    def test_no_candidates_key(self):
        assert GeminiClassifier._extract_text({}) == ""

    def test_empty_parts(self):
        body = {"candidates": [{"content": {"parts": []}}]}
        assert GeminiClassifier._extract_text(body) == ""


class TestCLIIntegration:
    def test_gemini_backend_creates_classifier(self):
        from email_triage.config import TriageConfig, ClassifierConfig
        from email_triage.cli import _create_classifier

        config = TriageConfig(
            classifier=ClassifierConfig(
                backend="gemini",
                gemini_model="gemini-2.5-pro",
            )
        )
        classifier = _create_classifier(config)
        assert isinstance(classifier, GeminiClassifier)
        assert classifier._model == "gemini-2.5-pro"

    def test_gemini_default_model(self):
        from email_triage.config import TriageConfig, ClassifierConfig
        from email_triage.cli import _create_classifier

        config = TriageConfig(
            classifier=ClassifierConfig(backend="gemini")
        )
        classifier = _create_classifier(config)
        assert classifier._model == "gemini-2.0-flash"
