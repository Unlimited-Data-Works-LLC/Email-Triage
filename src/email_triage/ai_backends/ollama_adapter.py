"""Ollama backend adapter — thin wrapper around the existing client.

The pre-#169 Ollama integration lives in
:class:`email_triage.classify.ollama.OllamaClassifier`. That class
already carries the long-lived httpx client, the ``prefer_loaded``
model-resolution heuristic, the circuit-breaker integration with
:mod:`email_triage.llm_health`, and the <think>-tag stripping for
[local-llm-model] output. Re-implementing any of that here would duplicate the
gnarly bits without changing behaviour.

This adapter wraps a single :class:`OllamaClassifier` instance and
exposes the :class:`BackendAdapter` contract on top of its
:meth:`OllamaClassifier.complete` method. The classifier's
``complete`` already accepts a single user prompt and returns
de-think-tagged text — close enough that we just stitch the
``messages`` list into a single string for now. A future evolution
can split into a real ``/api/chat`` multi-message POST; today's
single-prompt path is what every existing caller uses.

When the classifier migrates to consume :func:`load_backend` (deferred
to a follow-up worktree), this adapter becomes the only Ollama
integration point and the classify-side wrapper becomes a thin shim
on top of it.
"""

from __future__ import annotations

from typing import Any

from email_triage.ai_backends.base import BackendAdapter


# Default install-wide Ollama configuration when load_backend(None, ...)
# is called. Mirrors classify.ollama.OllamaClassifier defaults — keep
# in sync if those defaults change.
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "[local-llm-model]


class OllamaAdapter(BackendAdapter):
    """:class:`BackendAdapter` over the local-or-LAN Ollama REST API.

    Constructs an :class:`OllamaClassifier` under the hood; all the
    HTTP plumbing + retry + model-resolution logic comes from there
    untouched. ``api_key`` is accepted-and-ignored — Ollama installs
    don't use bearer tokens (LAN-only by default), but the loader
    passes the kwarg uniformly across all adapter types.
    """

    backend_type = "ollama"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        model: str | None = None,
        api_key: str | None = None,  # noqa: ARG002 — accepted for uniform loader signature
        local_url_suffixes: list[str] | None = None,
        **_: Any,
    ) -> None:
        # Lazy import keeps the classify package out of the import
        # graph for callers that only need other adapter types.
        from email_triage.classify.ollama import OllamaClassifier

        self._client = OllamaClassifier(
            model=model or DEFAULT_OLLAMA_MODEL,
            base_url=endpoint or DEFAULT_OLLAMA_BASE_URL,
            local_url_suffixes=list(local_url_suffixes or ()),
        )
        # is_local mirrors the wrapped classifier so the BAA gate sees
        # the same answer regardless of which surface it inspects.
        self.is_local = self._client.is_local

    async def chat_complete(
        self,
        messages: list[dict[str, str]],
        *,
        response_format: str | dict[str, Any] | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        # Stitch messages into a single prompt for the existing
        # OllamaClassifier.complete() path. System messages prepend
        # with an explicit marker so the model treats them as
        # instructions rather than user content — matches what
        # classify/prompts.py already does for the classifier path.
        prompt = _messages_to_single_prompt(messages)
        # response_format and max_tokens are not currently honoured
        # here — the underlying complete() uses a fixed num_predict
        # ceiling (see classify.ollama for the rationale). Wave 2 +
        # the classifier-migration follow-up can extend complete()
        # to accept these without changing this adapter's surface.
        _ = response_format
        _ = max_tokens
        _ = kwargs
        return await self._client.complete(prompt)

    async def close(self) -> None:
        await self._client.close()


def _messages_to_single_prompt(messages: list[dict[str, str]]) -> str:
    """Collapse a chat-format messages list into a single prompt string.

    Best-effort stitching for the legacy ``complete()`` shape. System
    messages prepend with an explicit ``[SYSTEM]`` marker; user/
    assistant turns get role-prefixed lines separated by blank lines.
    Sufficient for the existing single-system-plus-single-user pattern
    every caller uses today.
    """
    parts: list[str] = []
    for m in messages:
        role = (m.get("role") or "").strip().lower()
        content = m.get("content") or ""
        if not content:
            continue
        if role == "system":
            parts.append(f"[SYSTEM]\n{content}")
        elif role == "assistant":
            parts.append(f"[ASSISTANT]\n{content}")
        else:
            # user / unknown — fall through as user content.
            parts.append(content)
    return "\n\n".join(parts).strip()
