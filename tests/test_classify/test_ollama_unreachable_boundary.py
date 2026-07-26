"""Boundary test: a REAL Ollama 5xx must surface as ``LLMBackendUnreachableError``.

Why this file exists — the recurring "mock-the-boundary-not-the-seam" trap.

The ``f4fbb21`` fix made a 503/502/504 from Ollama a *whole-backend* unreachable
signal (trip the circuit breaker, park the message) instead of a per-message
error (retry in place → the ``message_gone`` tail). Two existing test layers each
covered HALF of that path and **nothing connected them**:

* ``tests/test_llm_health.py`` builds ``httpx.HTTPStatusError`` BY HAND and asserts
  ``is_unreachable_error(...) is True`` — the matcher in isolation (the *seam*).
* Every test in ``tests/test_classify/test_ollama.py`` does
  ``mock_resp.raise_for_status = lambda: None`` with ``status_code = 200`` — so the
  classify suite **never produces a real 5xx** and never runs the real
  ``raise_for_status() -> HTTPStatusError`` the fix depends on (the *boundary* is
  stubbed away).

So nothing proved the claim that actually matters: *the real classify client, on a
real 503, raises an exception that the matcher catches and that*
``translate_unreachable`` *converts into* ``LLMBackendUnreachableError`` *+ a
tripped breaker*. These tests close that gap.

They run locally with no GPU / no real Ollama: ``httpx.MockTransport`` fakes ONLY
the socket. The real ``httpx.AsyncClient``, real ``resp.raise_for_status()``, real
``httpx.HTTPStatusError``, real ``translate_unreachable`` context manager, and real
``is_unreachable_error`` / ``set_unhealthy`` all execute.
"""
from __future__ import annotations

import httpx
import pytest

from email_triage import llm_health
from email_triage.classify.ollama import OllamaClassifier
from email_triage.llm_health import LLMBackendUnreachableError


class _MockHttpHolder:
    """Stand-in for ``LazyHttpClient``: hands back a MockTransport-backed client.

    ``OllamaClassifier._chat`` reaches the network via ``await self._http.get()``
    (see ``classify/ollama.py``); swapping ``_http`` for this holder routes the
    real ``httpx.AsyncClient`` through a fake transport without touching the
    classifier's own code path.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def get(self) -> httpx.AsyncClient:
        return self._client

    async def aclose(self) -> None:
        await self._client.aclose()


def _classifier_returning(status: int) -> tuple[OllamaClassifier, httpx.AsyncClient]:
    """An ``OllamaClassifier`` whose every HTTP call gets ``status`` back.

    The handler returns a REAL ``httpx.Response`` so the classifier's own
    ``resp.raise_for_status()`` raises a REAL ``httpx.HTTPStatusError`` — the
    behavior the by-hand unit tests could only simulate.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        # _chat only hits /api/chat; the body mirrors httpx's own status text so
        # the substring backstop ("503 service unavailable") is exercised too.
        text = {
            502: "502 Bad Gateway",
            503: "503 Service Unavailable",
            504: "504 Gateway Timeout",
            500: "500 Internal Server Error",
        }.get(status, f"{status} error")
        return httpx.Response(status, text=text)

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    clf = OllamaClassifier(model="qwen3.6:35b", base_url="http://localhost:11434")
    clf._http = _MockHttpHolder(client)  # type: ignore[assignment]
    return clf, client


@pytest.fixture(autouse=True)
def _reset_breaker():
    """The circuit breaker is process-global ``_STATE``; reset both edges so this
    file can neither inherit a tripped breaker nor leak one into the suite
    (feedback_fix_flaky_tests — shared state is the classic order-dependent flake).
    """
    llm_health._reset_for_test()
    yield
    llm_health._reset_for_test()


@pytest.mark.parametrize("status", [503, 502, 504])
async def test_chat_5xx_is_unreachable_and_trips_breaker(status):
    """A real 503/502/504 → ``LLMBackendUnreachableError`` + the breaker trips.

    This is the end-to-end assertion behind ``f4fbb21``: the message is now
    park-able as ``llm_unreachable`` instead of retried in place. Pre-fix,
    ``is_unreachable_error`` returned False for any 5xx, so the raw
    ``HTTPStatusError`` propagated as a per-message error and the breaker stayed
    closed — this test would have FAILED on both assertions.
    """
    clf, client = _classifier_returning(status)
    try:
        with pytest.raises(LLMBackendUnreachableError):
            await clf._chat("system", "user", "qwen3.6:35b")
        # The whole backend is now parked for the TTL — the watcher's is_healthy
        # gate will hold off triage instead of hammering per-message retries.
        assert llm_health.is_healthy("ollama") is False
    finally:
        await client.aclose()


async def test_chat_500_stays_per_message_and_breaker_stays_closed():
    """A genuine 500 (model/inference error) is NOT whole-backend-unreachable.

    It must propagate as the raw ``httpx.HTTPStatusError`` (the per-message retry
    path) and leave the breaker CLOSED — proving the fix did not over-broaden to
    "any 5xx trips the breaker", which would wrongly park real per-request faults.
    """
    clf, client = _classifier_returning(500)
    try:
        with pytest.raises(httpx.HTTPStatusError) as ei:
            await clf._chat("system", "user", "qwen3.6:35b")
        assert ei.value.response.status_code == 500
        assert llm_health.is_healthy("ollama") is True  # breaker NOT tripped
    finally:
        await client.aclose()
