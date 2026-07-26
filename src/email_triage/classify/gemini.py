"""Google Gemini LLM backend for email classification.

Uses the Gemini REST API (``/v1beta/models/{model}:generateContent``)
via httpx.  Requires an API key from Google AI Studio or Vertex AI.

Install with::

    pip install email-triage[gemini]

Note: The ``google-generativeai`` package is listed as an optional
dependency but this implementation uses httpx directly against the
REST API for consistency with the other backends and to avoid the
heavy SDK dependency.
"""

from __future__ import annotations

import logging
from typing import Any

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.classify.base import JsonChatClassifier
from email_triage.llm_truncation import warn_if_llm_truncated

logger = get_logger("email_triage.classify.gemini")  # N-196b R21_4

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiResponseError(RuntimeError):
    """Gemini returned a response with no usable text content.

    Raised when a ``generateContent`` reply is malformed (no
    candidates / parts) or the model declined to answer — a safety
    block, a recitation stop, an empty finish. Previously
    :meth:`GeminiClassifier._extract_text` returned ``""`` in all of
    these cases, which surfaced downstream as an opaque JSON
    parse failure that gave no hint the real cause was a safety block.
    """


class GeminiClassifier(JsonChatClassifier):
    """Classify emails via the Google Gemini API.

    Parameters
    ----------
    model:
        Gemini model name (e.g. ``gemini-2.0-flash``, ``gemini-2.5-pro``).
    api_key:
        Google AI Studio API key.
    base_url:
        API base URL.  Override for Vertex AI or custom endpoints.
    timeout:
        Request timeout in seconds.
    """

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        api_key: str = "",
        base_url: str = GEMINI_BASE,
        timeout: float = 120.0,
    ):
        self._model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        #  — one long-lived pooled client per classifier instance.
        # The classifier is rebuilt per triage batch and reused for
        # every message in that batch, so pooling collapses N
        # per-message TLS handshakes into one. Mirrors OllamaClassifier.
        self._http = LazyHttpClient(intent=Intent.LLM_PHI, timeout=timeout)
        # Gemini is always external — Google's hosted endpoint, no
        # local mode. is_local stays False, gating BAA-required for
        # HIPAA accounts at classify time.
        self.is_local = False

    async def close(self) -> None:
        """Drain the pooled HTTP client. Idempotent — safe from a
        shutdown hook even if no request was ever issued."""
        await self._http.aclose()

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue a Gemini ``generateContent`` request; return raw text.

        ``model`` is the configured model (Gemini does not override
        :meth:`_resolve_model`); it is interpolated into the endpoint
        path. HIPAA-flagged accounts are already blocked by the BAA
        gate before they reach Gemini.

         — the POST is wrapped in the shared circuit-breaker helper
        :func:`llm_health.translate_unreachable`. A dead Gemini
        endpoint (connection refused / network blip) now trips the
        ``"gemini"`` breaker and re-raises a typed
        ``LLMBackendUnreachableError`` — same posture Ollama has had
        since . Keyed ``"gemini"`` to match the configured
        ``classifier.backend`` the ``is_healthy`` gate resolves.
        """
        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "systemInstruction": {
                "parts": [{"text": system_prompt}],
            },
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 256,
                "responseMimeType": "application/json",
            },
        }

        url = f"{self._base_url}/models/{model}:generateContent"
        params: dict[str, str] = {}
        if self._api_key:
            params["key"] = self._api_key

        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "gemini", self._base_url, default_port=443,
        ):
            client = await self._http.get()
            resp = await client.post(url, json=payload, params=params)
            resp.raise_for_status()

        body = resp.json()
        #  silent-truncation guard (shared SSOT) — finishReason==MAX_TOKENS.
        warn_if_llm_truncated(
            body, family="gemini", model=str(getattr(self, "_model", "") or ""),
            context="classify", logger=logger,
        )
        return self._extract_text(body)

    async def complete(self, prompt: str) -> str:
        """Raw text completion via the Gemini ``generateContent`` endpoint.

        Mirrors :meth:`OpenAICompatClassifier.complete` — the digest
        generator and the error-explain feature call ``complete`` for
        free-form output. Without this override a Gemini install raised
        ``NotImplementedError`` the moment either feature ran.

        No ``responseMimeType`` is set (raw text, not JSON) and the
        output budget is raised to 2048 tokens to match the other
        backends' completion path.

         — the POST is wrapped in the shared circuit-breaker helper
        :func:`llm_health.translate_unreachable`, matching :meth:`_chat`.
        Before  only ``_chat`` (the classify path) was wrapped; a
        dead Gemini endpoint hit through ``complete`` (digest generator,
        error-explain) raised a raw ``httpx.ConnectError`` and never
        tripped the breaker. Keyed ``"gemini"`` to match the configured
        ``classifier.backend`` the ``is_healthy`` gate resolves.
        """
        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 2048,
            },
        }

        url = f"{self._base_url}/models/{self._model}:generateContent"
        params: dict[str, str] = {}
        if self._api_key:
            params["key"] = self._api_key

        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "gemini", self._base_url, default_port=443,
        ):
            client = await self._http.get()
            resp = await client.post(url, json=payload, params=params)
            resp.raise_for_status()

        body = resp.json()
        warn_if_llm_truncated(
            body, family="gemini", model=str(getattr(self, "_model", "") or ""),
            context="complete", logger=logger,
        )
        return self._extract_text(body).strip()

    @staticmethod
    def _extract_text(body: dict[str, Any]) -> str:
        """Extract the text content from a Gemini generateContent response.

        Raises :class:`GeminiResponseError` when the response carries
        no usable text — a malformed reply, or a safety / recitation
        block. Surfacing a typed error lets the caller's
        per-message error path report the real cause instead of an
        opaque downstream JSON-parse failure on an empty string.
        """
        candidates = body.get("candidates", [])
        if not candidates:
            # A safety block at the prompt level returns no candidates
            # but does carry a ``promptFeedback.blockReason``.
            reason = (
                body.get("promptFeedback", {}).get("blockReason")
                or "no candidates in response"
            )
            raise GeminiResponseError(
                f"Gemini returned no usable text: {reason}"
            )
        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        if not parts:
            # A per-candidate block / non-STOP finish (SAFETY,
            # RECITATION, MAX_TOKENS with no text) lands here.
            finish = candidate.get("finishReason", "unknown")
            raise GeminiResponseError(
                f"Gemini returned no text content (finishReason="
                f"{finish})"
            )
        text = parts[0].get("text", "")
        if not text:
            raise GeminiResponseError(
                "Gemini returned an empty text part"
            )
        return text
