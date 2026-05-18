"""OpenAI-compatible LLM backend for email classification.

Works with Azure OpenAI, OpenAI, and any endpoint that implements the
OpenAI chat completions API (e.g. vLLM, LM Studio, text-generation-webui).
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

logger = logging.getLogger("email_triage.classify.openai_compat")


class OpenAICompatClassifier(Classifier):
    """Classify emails via any OpenAI-compatible chat completions endpoint.

    Parameters
    ----------
    base_url:
        The API base (e.g. ``https://api.openai.com/v1`` or an Azure
        endpoint like ``https://my-resource.openai.azure.com/openai/deployments/my-model``).
    model:
        Model name to request (ignored by some providers).
    api_key:
        Bearer token.  For Azure this is the resource key.
    timeout:
        Request timeout in seconds.
    extra_headers:
        Additional headers (e.g. ``api-version`` for Azure).
    """

    def __init__(
        self,
        base_url: str,
        model: str = "",
        api_key: str = "",
        timeout: float = 120.0,
        extra_headers: dict[str, str] | None = None,
        local_url_suffixes: list[str] | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout
        self._extra_headers = extra_headers or {}
        # OpenAI-compatible endpoint can be local (LiteLLM proxy on
        # the homelab) or external (api.openai.com). Classify the
        # configured URL so HIPAA gating fails closed when external.
        # Operator-defined "treat-as-local" suffixes come from
        # config.tls.local_url_suffixes; the source tree carries no
        # operator-specific suffix.
        from email_triage.classify.base import _is_local_host
        self.is_local = _is_local_host(
            self._base_url, extra_suffixes=tuple(local_url_suffixes or ()),
        )

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        headers.update(self._extra_headers)
        return headers

    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

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
                    message, self._model or "openai-compat", categories,
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
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 256,
        }
        if self._model:
            payload["model"] = self._model

        # Some providers support response_format for guaranteed JSON.
        payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._build_headers(),
                json=payload,
            )
            resp.raise_for_status()

        body = resp.json()
        raw_text = (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        logger.debug("OpenAI-compat raw response", extra={"raw": raw_text[:500]})

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
                outer_key, inner_field,
                self._model or "openai-compat", result, categories,
                is_hipaa=bool(getattr(message, "hipaa", False)),
            )
        except Exception as e:
            logger.debug("Classification cache store error: %s", e)

        return result

    async def complete(self, prompt: str) -> str:
        """Raw text completion via OpenAI-compatible chat endpoint."""
        payload: dict[str, Any] = {
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 2048,
        }
        if self._model:
            payload["model"] = self._model

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._build_headers(),
                json=payload,
            )
            resp.raise_for_status()

        body = resp.json()
        return (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        ).strip()
