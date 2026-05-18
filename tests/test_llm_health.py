"""Tests for the LLM-backend circuit breaker (#149 Bundle B)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import patch

import httpx
import pytest

from email_triage.classify.ollama import OllamaClassifier
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


def test_host_port_parsing():
    h, p = host_port_from_url("http://llm-host.home:11434/api/chat")
    assert h == "llm-host.home"
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
        model="[local-llm-model]
        base_url="http://llm-host:11434",
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
    assert err.host == "llm-host"
    assert err.port == 11434
    # Message follows the spec format. Backend is lowercase ("ollama")
    # in the canonical id; the dashboard banner template capitalises
    # for display.
    assert str(err) == "ollama unreachable: llm-host:11434"

    # Breaker is now open.
    assert is_healthy("ollama") is False


@pytest.mark.asyncio
async def test_classify_does_not_trip_breaker_on_decode_error(monkeypatch):
    """Backend returns 200 but bad JSON → does NOT trip breaker."""
    classifier = OllamaClassifier(
        model="[local-llm-model]
        base_url="http://llm-host:11434",
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
