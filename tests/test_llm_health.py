"""Tests for the LLM-backend circuit breaker."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from email_triage.classify.gemini import GeminiClassifier
from email_triage.classify.ollama import OllamaClassifier
from email_triage.classify.openai_compat import OpenAICompatClassifier
from email_triage.engine.models import EmailMessage
from email_triage.llm_health import (
    LLMBackendUnreachableError,
    _reset_for_test,
    clear_unhealthy,
    health_status,
    host_port_from_url,
    is_healthy,
    is_unreachable_error,
    set_unhealthy,
    translate_unreachable,
)


@pytest.fixture(autouse=True)
def fresh_state():
    _reset_for_test()
    yield
    _reset_for_test()


# ---------------------------------------------------------------------------
# set_unhealthy / is_healthy / TTL
# ---------------------------------------------------------------------------

def test_default_state_is_healthy():
    assert is_healthy("ollama") is True
    assert health_status("ollama")["healthy"] is True


def test_set_unhealthy_marks_unhealthy_until_ttl_expires():
    set_unhealthy("ollama", ttl_seconds=300, reason="connection refused")
    assert is_healthy("ollama") is False
    s = health_status("ollama")
    assert s["healthy"] is False
    assert s["reason"] == "connection refused"
    assert s["remaining_seconds"] is not None and s["remaining_seconds"] > 0


def test_ttl_expiry_evicts_entry():
    set_unhealthy("ollama", ttl_seconds=0.01, reason="x")
    time.sleep(0.05)
    assert is_healthy("ollama") is True


def test_clear_unhealthy_immediately_recovers():
    set_unhealthy("ollama", ttl_seconds=300, reason="x")
    assert is_healthy("ollama") is False
    clear_unhealthy("ollama")
    assert is_healthy("ollama") is True


def test_repeated_set_unhealthy_preserves_unhealthy_since():
    """The 'unhealthy since' wall clock should not jump every retry —
    it locks at the first failure so the operator sees a stable
    'unreachable since 14:32' banner."""
    set_unhealthy("ollama", ttl_seconds=300, reason="first")
    s1 = health_status("ollama")
    time.sleep(0.05)
    set_unhealthy("ollama", ttl_seconds=300, reason="second")
    s2 = health_status("ollama")
    # unhealthy_since stays put; reason updates.
    assert s1["unhealthy_since"] == s2["unhealthy_since"]
    assert s2["reason"] == "second"


# ---------------------------------------------------------------------------
# is_unreachable_error
# ---------------------------------------------------------------------------

def test_is_unreachable_recognises_httpx_connect_error():
    exc = httpx.ConnectError("All connection attempts failed")
    assert is_unreachable_error(exc) is True


def test_is_unreachable_recognises_message_substring():
    exc = RuntimeError("All connection attempts failed")
    assert is_unreachable_error(exc) is True


def test_is_unreachable_does_not_match_decode_error():
    """JSON decode + 500 + classifier-internal errors should NOT
    trip the breaker — those mean the backend is up but acting up."""
    exc = ValueError("Could not parse JSON from LLM response")
    assert is_unreachable_error(exc) is False


def test_is_unreachable_recognises_503_502_504():
    """A 503/502/504 from the LLM endpoint is a WHOLE-BACKEND 'service
    unavailable' signal (Ollama 503 = overloaded / OOM / queue-full), so it
    SHOULD trip the breaker + be tagged llm_unreachable — unlike a 500/4xx."""
    req = httpx.Request("POST", "http://llm-host.example.invalid:11434/api/chat")
    for code in (502, 503, 504):
        try:
            httpx.Response(code, request=req).raise_for_status()
        except httpx.HTTPStatusError as exc:
            assert is_unreachable_error(exc) is True, code


def test_is_unreachable_does_not_match_500():
    """A 500 stays a PER-MESSAGE error (the specific request misbehaved),
    NOT 'unreachable' — must not trip the breaker."""
    req = httpx.Request("POST", "http://llm-host.example.invalid:11434/api/chat")
    try:
        httpx.Response(500, request=req).raise_for_status()
    except httpx.HTTPStatusError as exc:
        assert is_unreachable_error(exc) is False


def test_is_unreachable_503_substring_in_wrapped_runtime_error():
    """Safety net at the real prod shape: the 503 that enqueued the
    message_gone retries arrived re-wrapped as RuntimeError("Server error
    '503 Service Unavailable' for url ...") — still recognised."""
    exc = RuntimeError(
        "Server error '503 Service Unavailable' for url "
        "'http://llm-host.example.invalid:11434/api/chat'"
    )
    assert is_unreachable_error(exc) is True


def test_is_unreachable_httpstatus_with_none_response_is_safe():
    """getattr-safety (db-sme NICE-TO-HAVE): an HTTPStatusError whose
    ``.response`` is None must NOT crash the status_code extraction — the
    nested getattr yields None, None not in (502,503,504), returns False."""
    exc = httpx.HTTPStatusError(
        "boom", request=httpx.Request("POST", "http://x.invalid:11434/api/chat"),
        response=None,
    )
    assert is_unreachable_error(exc) is False


def test_host_port_parsing():
    h, p = host_port_from_url("http://llm-host.example.invalid:11434/api/chat")
    assert h == "llm-host.example.invalid"
    assert p == 11434

    h, p = host_port_from_url("")
    assert (h, p) == ("", 0)


# ---------------------------------------------------------------------------
# Probe path: classify wraps + trips the breaker
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classify_raises_typed_error_and_trips_breaker(monkeypatch):
    """When httpx raises ConnectError inside Ollama.classify, the
    wrapper sets the unhealthy flag AND re-raises a typed
    LLMBackendUnreachableError carrying host + port."""
    classifier = OllamaClassifier(
        model="qwen3.5:35b",
        base_url="http://llm-host.invalid:11434",
        prefer_loaded=False,
    )

    # Build a minimal EmailMessage. Avoid touching the engine module's
    # constructor signature too tightly — use whatever required
    # fields it has.
    msg = EmailMessage(
        message_id="m1",
        provider="imap",
        sender="from@example.com",
        recipients=["to@example.com"],
        subject="hi",
        body_text="hello",
        date=datetime(2026, 5, 10, 12, 0, tzinfo=timezone.utc),
    )

    class _BombClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *_a, **_kw):
            raise httpx.ConnectError("All connection attempts failed")

    def _client_factory(*_a, **_kw):
        return _BombClient()

    with patch.object(httpx, "AsyncClient", _client_factory):
        with pytest.raises(LLMBackendUnreachableError) as exc_info:
            await classifier.classify(msg, {"to-respond": "x"}, None)

    err = exc_info.value
    assert err.backend == "ollama"
    assert err.host == "llm-host.invalid"
    assert err.port == 11434
    # Message follows the spec format. Backend is lowercase ("ollama")
    # in the canonical id; the dashboard banner template capitalises
    # for display.
    assert str(err) == "ollama unreachable: llm-host.invalid:11434"

    # Breaker is now open.
    assert is_healthy("ollama") is False


@pytest.mark.asyncio
async def test_classify_does_not_trip_breaker_on_decode_error(monkeypatch):
    """Backend returns 200 but bad JSON → does NOT trip breaker."""
    classifier = OllamaClassifier(
        model="qwen3.5:35b",
        base_url="http://llm-host.invalid:11434",
        prefer_loaded=False,
    )

    msg = EmailMessage(
        message_id="m1",
        provider="imap",
        sender="from@example.com",
        recipients=["to@example.com"],
        subject="hi",
        body_text="hello",
        date=datetime(2026, 5, 10, 12, 0, tzinfo=timezone.utc),
    )

    class _GarbageClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, *_a, **_kw):
            class _Resp:
                status_code = 200
                def json(self):
                    return {"message": {"content": "not-json-at-all"}}
                def raise_for_status(self):
                    return None
            return _Resp()

    def _client_factory(*_a, **_kw):
        return _GarbageClient()

    with patch.object(httpx, "AsyncClient", _client_factory):
        with pytest.raises(Exception):
            # ValueError from _parse_llm_json — NOT an unreachable
            # error.
            await classifier.classify(msg, {"to-respond": "x"}, None)

    # Breaker stays closed.
    assert is_healthy("ollama") is True


# ---------------------------------------------------------------------------
#  — shared translate_unreachable helper
# ---------------------------------------------------------------------------

class TestTranslateUnreachable:
    """The shared circuit-breaker translation helper — used by every
    HTTP classifier backend (Ollama, OpenAI-compatible, Gemini)."""

    def test_connect_error_trips_breaker_and_raises_typed(self):
        with pytest.raises(LLMBackendUnreachableError) as ei:
            with translate_unreachable(
                "openai", "https://api.openai.invalid/v1", default_port=443,
            ):
                raise httpx.ConnectError("All connection attempts failed")
        err = ei.value
        assert err.backend == "openai"
        assert err.host == "api.openai.invalid"
        assert err.port == 443
        assert is_healthy("openai") is False

    def test_decode_error_passes_through_breaker_closed(self):
        """A non-connect error (parse / 500) propagates unchanged and
        does NOT trip the breaker."""
        with pytest.raises(ValueError):
            with translate_unreachable(
                "gemini", "https://x.invalid/v1beta", default_port=443,
            ):
                raise ValueError("could not parse JSON")
        assert is_healthy("gemini") is True

    def test_success_path_no_breaker_change(self):
        with translate_unreachable(
            "openai", "https://api.openai.invalid/v1", default_port=443,
        ):
            pass
        assert is_healthy("openai") is True

    def test_connection_refused_substring_trips_breaker(self):
        with pytest.raises(LLMBackendUnreachableError):
            with translate_unreachable(
                "gemini", "https://x.invalid/v1beta", default_port=443,
            ):
                raise RuntimeError("Connection refused")
        assert is_healthy("gemini") is False

    def test_503_trips_breaker_and_raises_typed(self):
        """A 503 from the LLM endpoint inside translate_unreachable trips the
        breaker + raises the typed error, so the message is PARKED as
        llm_unreachable rather than retried per-message into a message_gone
        tail (the prod bug fixed 2026-06-19)."""
        req = httpx.Request("POST", "http://llm-host.example.invalid:11434/api/chat")
        with pytest.raises(LLMBackendUnreachableError):
            with translate_unreachable(
                "ollama", "http://llm-host.example.invalid:11434", default_port=11434,
            ):
                httpx.Response(503, request=req).raise_for_status()
        assert is_healthy("ollama") is False

    def test_500_passes_through_breaker_closed(self):
        """A 500 stays per-message: it propagates unchanged and leaves the
        breaker closed (only 503/502/504 are whole-backend signals)."""
        req = httpx.Request("POST", "http://x.invalid:11434/api/chat")
        with pytest.raises(httpx.HTTPStatusError):
            with translate_unreachable(
                "openai", "https://api.openai.invalid/v1", default_port=443,
            ):
                httpx.Response(500, request=req).raise_for_status()
        assert is_healthy("openai") is True


def _stub_http_bomb(classifier):
    """Swap the classifier's pooled client for one whose .post() raises
    a connect error — mirrors the test_openai_compat / test_gemini
    _mock_http stub shape."""
    bomb = AsyncMock()
    bomb.post.side_effect = httpx.ConnectError("All connection attempts failed")
    classifier._http = SimpleNamespace(
        get=AsyncMock(return_value=bomb),
        aclose=AsyncMock(),
    )


def _email():
    return EmailMessage(
        message_id="m1",
        provider="imap",
        sender="from@example.com",
        recipients=["to@example.com"],
        subject="hi",
        body_text="hello",
        date=datetime(2026, 5, 21, 12, 0, tzinfo=timezone.utc),
    )


class TestCloudClassifierBreaker:
    """ — the cloud classifiers (OpenAI-compatible, Gemini) now
    translate a transport error into the circuit breaker, keyed per
    backend, exactly as Ollama has since ."""

    async def test_openai_compat_classify_trips_openai_breaker(self):
        classifier = OpenAICompatClassifier(
            base_url="https://api.openai.invalid/v1",
            model="gpt-4o",
            api_key="sk-test",
        )
        _stub_http_bomb(classifier)
        with pytest.raises(LLMBackendUnreachableError) as ei:
            await classifier.classify(_email(), {"to-respond": "x"}, None)
        assert ei.value.backend == "openai"
        # Breaker keyed "openai" — matches config.classifier.backend.
        assert is_healthy("openai") is False
        # Ollama's breaker is untouched.
        assert is_healthy("ollama") is True

    async def test_openai_compat_complete_trips_openai_breaker(self):
        classifier = OpenAICompatClassifier(
            base_url="https://api.openai.invalid/v1",
            model="gpt-4o",
            api_key="sk-test",
        )
        _stub_http_bomb(classifier)
        with pytest.raises(LLMBackendUnreachableError):
            await classifier.complete("explain this")
        assert is_healthy("openai") is False

    async def test_gemini_classify_trips_gemini_breaker(self):
        classifier = GeminiClassifier(
            model="gemini-2.0-flash", api_key="test-key",
        )
        _stub_http_bomb(classifier)
        with pytest.raises(LLMBackendUnreachableError) as ei:
            await classifier.classify(_email(), {"to-respond": "x"}, None)
        assert ei.value.backend == "gemini"
        assert is_healthy("gemini") is False
        assert is_healthy("ollama") is True

    async def test_openai_compat_decode_error_does_not_trip_breaker(self):
        """A 200 with unparseable JSON must NOT trip the breaker."""
        classifier = OpenAICompatClassifier(
            base_url="https://api.openai.invalid/v1",
            model="gpt-4o",
            api_key="sk-test",
        )
        mock_resp = Mock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "not-json"}}],
        }
        mock_resp.raise_for_status = lambda: None
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        classifier._http = SimpleNamespace(
            get=AsyncMock(return_value=mock_client),
            aclose=AsyncMock(),
        )
        with pytest.raises(ValueError):
            await classifier.classify(_email(), {"to-respond": "x"}, None)
        assert is_healthy("openai") is True
