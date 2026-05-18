"""Tests for the OpenAI-compatible classifier with mocked HTTP responses."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from email_triage.classify.openai_compat import OpenAICompatClassifier
from email_triage.engine.models import EmailMessage


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


def _openai_response(category: str, confidence: float, reason: str) -> dict:
    content = json.dumps({
        "category": category,
        "confidence": confidence,
        "reason": reason,
    })
    return {
        "id": "chatcmpl-test",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
    }


class TestOpenAICompatClassifier:
    @pytest.fixture
    def classifier(self):
        return OpenAICompatClassifier(
            base_url="https://api.example.com/v1",
            model="gpt-4o",
            api_key="sk-test-key",
        )

    async def test_basic_classification(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _openai_response("to-respond", 0.88, "Needs reply.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.openai_compat.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await classifier.classify(_make_email(), _CATEGORIES)

        assert result.category == "to-respond"
        assert result.confidence == 0.88
        assert result.source == "llm"

    async def test_sends_auth_header(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _openai_response("fyi", 0.7, "Info.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.openai_compat.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        headers = call_args.kwargs.get("headers", {})
        assert headers["Authorization"] == "Bearer sk-test-key"

    async def test_correct_endpoint(self, classifier):
        mock_resp = Mock()
        mock_resp.json.return_value = _openai_response("fyi", 0.7, "Info.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.openai_compat.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert url == "https://api.example.com/v1/chat/completions"

    async def test_extra_headers(self):
        classifier = OpenAICompatClassifier(
            base_url="https://my-resource.openai.azure.com",
            model="my-deployment",
            api_key="azure-key",
            extra_headers={"api-version": "2024-02-15"},
        )

        mock_resp = Mock()
        mock_resp.json.return_value = _openai_response("invoices", 0.9, "Bill.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.openai_compat.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await classifier.classify(_make_email(), _CATEGORIES)

        call_args = mock_client.post.call_args
        headers = call_args.kwargs.get("headers", {})
        assert headers["api-version"] == "2024-02-15"
        assert headers["Authorization"] == "Bearer azure-key"

    async def test_no_api_key(self):
        classifier = OpenAICompatClassifier(
            base_url="http://localhost:8000/v1",
        )

        mock_resp = Mock()
        mock_resp.json.return_value = _openai_response("fyi", 0.6, "Local.")
        mock_resp.raise_for_status = lambda: None

        with patch("email_triage.classify.openai_compat.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await classifier.classify(_make_email(), _CATEGORIES)

        assert result.category == "fyi"
        call_args = mock_client.post.call_args
        headers = call_args.kwargs.get("headers", {})
        assert "Authorization" not in headers
