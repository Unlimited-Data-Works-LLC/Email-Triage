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

import json
import logging
from typing import Any

import httpx

from email_triage.classify.base import Classifier
from email_triage.classify.ollama import _parse_llm_json
from email_triage.classify.prompts import build_system_prompt, build_user_prompt
from email_triage.engine.models import Classification, EmailMessage, ListHint

logger = logging.getLogger("email_triage.classify.gemini")

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiClassifier(Classifier):
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
        # Gemini is always external — Google's hosted endpoint, no
        # local mode. is_local stays False, gating BAA-required for
        # HIPAA accounts at classify time.
        self.is_local = False

    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

        # #151 — optional Redis cache. HIPAA-flagged accounts already
        # blocked by the BAA gate before they reach Gemini, but the
        # helper carries the HIPAA short-circuit anyway as defence-in-
        # depth. Cache key includes the model so a model upgrade
        # auto-invalidates.
        # 2026-05-13 two-level cache lookup.
        outer_key: str | None = None
        inner_field: str | None = None
        hint_text: str | None = None
        try:
            from email_triage.cache.classification import (
                cache_lookup_for_message,
            )
            outer_key, inner_field, cache_entry, hint_text = (
                cache_lookup_for_message(
                    message, self._model, categories,
                )
            )
            if cache_entry is not None:
                logger.info("Classification cache hit (cache_hit=True)")
                return cache_entry
        except Exception as e:
            logger.debug("Classification cache lookup error: %s", e)

        if hint_text:
            system_prompt = (
                f"[SENDER HISTORY HINT] {hint_text}\n\n{system_prompt}"
            )

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

        url = f"{self._base_url}/models/{self._model}:generateContent"
        params: dict[str, str] = {}
        if self._api_key:
            params["key"] = self._api_key

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, json=payload, params=params)
            resp.raise_for_status()

        body = resp.json()
        raw_text = self._extract_text(body)
        logger.debug("Gemini raw response", extra={"raw": raw_text[:500]})

        parsed = _parse_llm_json(raw_text)

        category = parsed.get("category", "")
        if category not in categories:
            logger.warning(
                "LLM returned unknown category '%s', treating as low confidence",
                category,
            )

        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        reason = parsed.get("reason", "")

        result = Classification(
            category=category,
            confidence=confidence,
            reason=reason,
            source="llm",
        )

        # 2026-05-13 — best-effort two-level store; HIPAA strip handled
        # inside the helper.
        try:
            from email_triage.cache.classification import (
                cache_store_for_message,
            )
            cache_store_for_message(
                outer_key, inner_field, self._model, result, categories,
                is_hipaa=bool(getattr(message, "hipaa", False)),
            )
        except Exception as e:
            logger.debug("Classification cache store error: %s", e)

        return result

    @staticmethod
    def _extract_text(body: dict[str, Any]) -> str:
        """Extract the text content from a Gemini generateContent response."""
        candidates = body.get("candidates", [])
        if not candidates:
            return ""
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            return ""
        return parts[0].get("text", "")
