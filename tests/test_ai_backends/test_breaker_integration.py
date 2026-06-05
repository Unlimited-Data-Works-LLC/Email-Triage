"""Circuit-breaker regression coverage for the ai_backends adapters.

Cycle 2's  wrapped the ``chat_complete`` POST in each of the three
cloud adapters (``openai_direct``, ``gemini_adapter``, ``azure_openai``)
in :func:`email_triage.llm_health.translate_unreachable` — the shared
LLM circuit breaker — but shipped ZERO test coverage for that wrap.

These tests close that gap. For each adapter:

* a connect-class failure (``httpx.ConnectError``) on the pooled
  client's ``post`` MUST surface as a typed
  :class:`LLMBackendUnreachableError` AND flip the breaker
  (``is_healthy(<key>)`` False afterward);
* a 4xx/5xx-shaped failure (``httpx.HTTPStatusError``) MUST NOT trip
  the breaker — those mean the backend is up but misbehaving and the
  per-message error path handles them.

Breaker key per adapter (verified against the adapter source):

* ``openai_direct`` → ``"openai"``
* ``gemini_adapter`` → ``"gemini"``
* ``azure_openai``   → ``"openai"``  (Azure speaks the OpenAI API; its
  breaker is keyed ``"openai"`` so the ``is_healthy`` gate — which only
  ever resolves ``ollama``/``openai``/``gemini`` — can actually see it).

HTTP is mocked end-to-end; no real network calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from email_triage.ai_backends.azure_openai import AzureOpenAIAdapter
from email_triage.ai_backends.gemini_adapter import GeminiAdapter
from email_triage.ai_backends.openai_direct import OpenAIAdapter
from email_triage.llm_health import (
    LLMBackendUnreachableError,
    _reset_for_test,
    is_healthy,
)


@pytest.fixture(autouse=True)
def fresh_breaker_state():
    """Every test starts and ends with an empty breaker registry — a
    leaked unhealthy entry would silently false-pass a later test."""
    _reset_for_test()
    yield
    _reset_for_test()


def _patch_post_raising(exc: BaseException):
    """Patch the pooled ``LazyHttpClient`` so ``.get()`` yields a mock
    client whose ``.post()`` raises ``exc``."""
    mock_client = AsyncMock()
    mock_client.post.side_effect = exc
    return patch(
        "email_triage._http_client.LazyHttpClient.get",
        new=AsyncMock(return_value=mock_client),
    )


def _http_status_error() -> httpx.HTTPStatusError:
    """Construct a real ``httpx.HTTPStatusError`` for a 500 response.

    ``is_unreachable_error`` must classify this as NOT-unreachable:
    ``HTTPStatusError`` is a backend-is-up-but-misbehaving signal, the
    polar opposite of a connect failure. It is also a subclass of
    ``httpx.HTTPError`` — which is exactly why the (b) ``getattr``
    fallback was dangerous.
    """
    request = httpx.Request("POST", "https://example.invalid/v1/x")
    response = httpx.Response(500, request=request)
    return httpx.HTTPStatusError(
        "500 Server Error", request=request, response=response,
    )


# ---------------------------------------------------------------------------
# Parametrised adapter matrix: (id, adapter-factory, breaker-key)
# ---------------------------------------------------------------------------

def _make_openai() -> OpenAIAdapter:
    return OpenAIAdapter(
        endpoint="https://api.openai.com/v1", api_key="sk-test",
    )


def _make_gemini() -> GeminiAdapter:
    return GeminiAdapter(
        endpoint="https://generativelanguage.googleapis.com/v1beta",
        api_key="gem-test-key",
    )


def _make_azure() -> AzureOpenAIAdapter:
    return AzureOpenAIAdapter(
        endpoint="https://my-resource.openai.azure.com",
        api_key="az-test-key",
        deployment="my-deployment",
    )


_ADAPTER_MATRIX = [
    pytest.param(_make_openai, "openai", id="openai_direct"),
    pytest.param(_make_gemini, "gemini", id="gemini_adapter"),
    # Azure speaks the OpenAI API — its breaker is keyed "openai".
    pytest.param(_make_azure, "openai", id="azure_openai"),
]


# ---------------------------------------------------------------------------
# (a) ConnectError trips the breaker
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("make_adapter, breaker_key", _ADAPTER_MATRIX)
async def test_connect_error_trips_breaker(make_adapter, breaker_key):
    """A ``httpx.ConnectError`` on the POST must:

    (a) surface as a typed ``LLMBackendUnreachableError``;
    (b) flip the breaker — ``is_healthy(<key>)`` returns False after.
    """
    adapter = make_adapter()
    # Sanity: the breaker starts healthy (the autouse fixture cleared it).
    assert is_healthy(breaker_key) is True

    with _patch_post_raising(httpx.ConnectError("All connection attempts failed")):
        with pytest.raises(LLMBackendUnreachableError) as ei:
            await adapter.chat_complete([{"role": "user", "content": "hi"}])

    # (a) the typed exception carries the breaker key as its backend.
    assert ei.value.backend == breaker_key
    # (b) the breaker is now tripped for that key.
    assert is_healthy(breaker_key) is False


# ---------------------------------------------------------------------------
# (b) HTTPStatusError (4xx/5xx) does NOT trip the breaker
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("make_adapter, breaker_key", _ADAPTER_MATRIX)
async def test_http_status_error_does_not_trip_breaker(
    make_adapter, breaker_key,
):
    """A ``httpx.HTTPStatusError`` (the 4xx/5xx shape) must propagate
    UNCHANGED through ``translate_unreachable`` and must NOT flip the
    breaker — a misbehaving-but-reachable backend is not "unreachable".

    This is the paired negative control to
    :func:`test_connect_error_trips_breaker`: it proves the breaker wrap
    is selective, not a blanket catch-all that would wrongly gate the
    backend on any error.
    """
    adapter = make_adapter()
    assert is_healthy(breaker_key) is True

    with _patch_post_raising(_http_status_error()):
        # The status error propagates verbatim — translate_unreachable
        # re-raises non-connect exceptions unchanged.
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.chat_complete([{"role": "user", "content": "hi"}])

    # The breaker stayed healthy — a 4xx/5xx must never gate the backend.
    assert is_healthy(breaker_key) is True


async def test_azure_breaker_key_is_openai_not_azure():
    """Pin the deliberate Azure breaker-key choice: Azure keys its
    breaker ``"openai"``, NOT ``"azure_openai"``.

    The ``is_healthy`` gate resolves ``config.classifier.backend``,
    which only ever yields ``ollama``/``openai``/``gemini``. An Azure
    install configures ``classifier.backend = "openai"`` because Azure
    speaks the OpenAI chat-completions API; a breaker keyed
    ``"azure_openai"`` would be invisible to the gate. This test fails
    if a refactor ever re-keys the Azure breaker.
    """
    adapter = _make_azure()
    with _patch_post_raising(httpx.ConnectError("connection refused")):
        with pytest.raises(LLMBackendUnreachableError):
            await adapter.chat_complete([{"role": "user", "content": "hi"}])
    # The "openai"-keyed breaker tripped; an "azure_openai" key did not.
    assert is_healthy("openai") is False
    assert is_healthy("azure_openai") is True
