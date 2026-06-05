"""OpenAI-compatible LLM backend for email classification.

Works with Azure OpenAI, OpenAI, and any endpoint that implements the
OpenAI chat completions API (e.g. vLLM, LM Studio, text-generation-webui).
"""

from __future__ import annotations

from typing import Any

from email_triage._http_client import LazyHttpClient
from email_triage.classify.base import JsonChatClassifier


class OpenAICompatClassifier(JsonChatClassifier):
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
        #  — one long-lived pooled client per classifier instance.
        # The classifier is rebuilt per triage batch and reused for
        # every message in that batch, so pooling collapses N
        # per-message TLS handshakes into one. Mirrors OllamaClassifier.
        self._http = LazyHttpClient(timeout=timeout)
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

    async def close(self) -> None:
        """Drain the pooled HTTP client. Idempotent — safe from a
        shutdown hook even if no request was ever issued."""
        await self._http.aclose()

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        headers.update(self._extra_headers)
        return headers

    async def _resolve_model(self) -> str:
        # The classification-cache key. Some self-hosted endpoints
        # ignore the model field, so an empty configured model still
        # needs a stable, non-empty cache key — fall back to a literal
        # (mirrors the pre-refactor behaviour). The request payload
        # itself uses ``self._model`` directly (see :meth:`_chat`) and
        # omits the field entirely when it is empty.
        return self._model or "openai-compat"

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue an OpenAI-compatible ``/chat/completions`` request.

        ``model`` is the cache key from :meth:`_resolve_model`; the
        payload uses ``self._model`` directly so an empty configured
        model omits the field rather than sending the cache-key
        placeholder to the endpoint.

         — the POST is wrapped in the shared circuit-breaker helper
        :func:`llm_health.translate_unreachable`. A dead OpenAI-
        compatible endpoint (connection refused / network blip) now
        trips the ``"openai"`` breaker and re-raises a typed
        ``LLMBackendUnreachableError`` — same posture Ollama has had
        since . Keyed ``"openai"`` to match the configured
        ``classifier.backend`` the ``is_healthy`` gate resolves.
        """
        payload: dict[str, Any] = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 256,
            # Some providers support response_format for guaranteed JSON.
            "response_format": {"type": "json_object"},
        }
        if self._model:
            payload["model"] = self._model

        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "openai", self._base_url, default_port=443,
        ):
            client = await self._http.get()
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
        )

    async def complete(self, prompt: str) -> str:
        """Raw text completion via OpenAI-compatible chat endpoint.

         — same shared circuit-breaker wrap as :meth:`_chat`.
        """
        payload: dict[str, Any] = {
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 2048,
        }
        if self._model:
            payload["model"] = self._model

        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "openai", self._base_url, default_port=443,
        ):
            client = await self._http.get()
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
