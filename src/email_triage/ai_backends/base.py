"""Abstract base class for AI backend adapters.

Today's classifier hierarchy (``classify/base.py::Classifier``) is
classification-specific — its abstract method is ``classify(message,
categories, list_hints)``. The pluggable concept is the same, but
the surface is wrong for non-classification consumers (style-learning
distill, error-explain, future RAG/embeddings). This module formalises
the **chat-completion** surface that every classifier already wraps
internally (``OllamaClassifier.complete``, ``OpenAICompatClassifier``
calling ``/v1/chat/completions``, ``GeminiClassifier`` posting
``generateContent``), so callers outside ``classify/`` can reach LLM
inference without going through a classifier shell.

Contract
--------
:meth:`BackendAdapter.chat_complete` takes a list of
``{role, content}`` messages and returns a raw string. Backends that
support structured output expose it via ``response_format`` (OpenAI
JSON-mode shape — the most portable). Caller-supplied ``max_tokens``
caps the response budget; if omitted, the adapter picks a sensible
default for its provider.

:meth:`BackendAdapter.embed` is optional and raises
``NotImplementedError`` by default. The first consumer (Wave 3 RAG
extension) will subclass concretely; today's adapters don't need it.

Why this is **not** the existing :class:`Classifier` ABC
-------------------------------------------------------
``Classifier`` shaped the prompt internally (``build_system_prompt`` /
``build_user_prompt``). The backend adapter is one layer lower —
caller supplies the assembled messages, the adapter is dumb HTTP
plumbing + provider-shape mapping. The classifier path can migrate
to use a backend adapter under the hood without changing its public
shape; that re-home work is deferred.

HIPAA + key handling
--------------------
The adapter instance is the only object that holds the plaintext
API key. The loader (:func:`email_triage.ai_backends.loader.load_backend`)
fetches the key from :class:`DbSecrets` and hands it to ``__init__``;
the caller never sees it. Adapters MUST NOT log keys, return them
from any method, or expose them via ``repr``. The standing
``_TOKEN_KEYS`` log-scrub discipline applies if a future adapter
needs to log redacted headers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BackendError(Exception):
    """Base class for AI-backend loader / adapter errors."""


class BackendNotFoundError(BackendError):
    """Raised by :func:`load_backend` when the requested id is absent."""


class BackendDisabledError(BackendError):
    """Raised by :func:`load_backend` when the backend row is disabled.

    The selector UI already filters to ``enabled=1`` so this is a
    consistency check / belt-and-braces — operator can clear an FK
    elsewhere then disable the backend before that FK is cleaned up;
    the loader fails closed rather than silently routing to a
    disabled vendor.
    """


class BackendAdapter(ABC):
    """A single LLM backend instance, ready to receive chat-completion
    requests.

    Subclass and implement :meth:`chat_complete`. Override :attr:`is_local`
    when the adapter targets a local-only endpoint (used by the HIPAA
    BAA gate). Override :meth:`embed` for backends that support it.
    """

    # Surface mirrors classify.base.Classifier.is_local for HIPAA gate
    # compatibility — Wave 2 wires baa_gate.py to consume both shapes.
    is_local: bool = False

    # Stable identifier (matches the ``ai_backends.type`` enum). Set on
    # the subclass; loader uses it for logging / debug surfacing.
    backend_type: str = ""

    @abstractmethod
    async def chat_complete(
        self,
        messages: list[dict[str, str]],
        *,
        response_format: str | dict[str, Any] | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        """Run a chat-completion request and return the raw assistant text.

        Parameters
        ----------
        messages:
            List of ``{"role": <"system"|"user"|"assistant">, "content":
            <str>}`` dicts. Role + content are the only universally-
            supported keys; provider-specific extensions (e.g. OpenAI
            ``name`` / ``tool_call_id``) go through ``**kwargs`` and
            are dropped by adapters that don't understand them.
        response_format:
            Hint to the provider about expected output shape. The
            portable values are:
              * ``None`` — free-form text (default)
              * ``"json"`` — request JSON output (OpenAI-style
                ``{"type": "json_object"}``; Ollama ``format: "json"``;
                Gemini ``responseMimeType: "application/json"``)
              * a dict — passed through to the provider untouched (for
                adapters that need provider-specific structured-output
                schemas; not portable).
        max_tokens:
            Cap on response length. Backend interprets in its native
            unit (Ollama ``num_predict``, OpenAI ``max_tokens``,
            Gemini ``maxOutputTokens``). When ``None`` the adapter
            picks its default (typically 8192 — see
            ``OllamaClassifier.complete``).
        **kwargs:
            Forward-compatibility escape hatch for provider-specific
            options (temperature, top_p, etc.). Adapters MAY honour
            ``temperature`` consistently; everything else is best-
            effort.

        Returns
        -------
        The raw assistant text. Adapters strip <think>...</think>
        blocks ([local-llm-model]) and markdown code fences before returning
        when ``response_format='json'`` is in effect.

        Raises
        ------
        ``LLMBackendUnreachableError`` from
        :mod:`email_triage.llm_health` when the provider endpoint is
        unreachable (circuit-breaker integration). Other provider
        errors propagate as-is — callers wrap as they see fit.
        """

    async def embed(self, text: str) -> list[float]:
        """Compute an embedding vector for ``text``.

        Optional; the default raises ``NotImplementedError``. Adapters
        whose provider supports embeddings (Ollama via
        ``/api/embeddings``; OpenAI via ``/v1/embeddings``; Gemini
        via ``embedContent``) override.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support embed()"
        )

    async def close(self) -> None:
        """Drain any long-lived resources. Idempotent.

        Default no-op; adapters holding an httpx client override.
        """


class NotImplementedAdapter(BackendAdapter):
    """Placeholder adapter for a registered ``type`` that has no
    concrete subclass yet.

    The :data:`BACKEND_TYPES` registry maps every enum value in the
    CHECK constraint to a class so the loader never raises
    ``KeyError`` on a row that lookups by type. When the operator
    creates a row whose ``type`` doesn't yet have a concrete adapter
    subclass, the loader returns one of these — and the first
    :meth:`chat_complete` call fails fast with a clear message.

    Subclasses are registered in :data:`BACKEND_TYPES` with a class
    attribute ``backend_type`` matching the enum value. Wave 1-B /
    Wave 1-C / future work swap the registry entry to a concrete
    adapter (no source-rewrite anywhere else).
    """

    def __init__(self, *, backend_type: str = "", **_: Any) -> None:
        # Accept-and-ignore the loader's kwargs so a NotImplementedAdapter
        # subclass slots into the registry without a custom __init__.
        self.backend_type = backend_type or type(self).backend_type

    async def chat_complete(
        self,
        messages: list[dict[str, str]],
        *,
        response_format: str | dict[str, Any] | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        raise NotImplementedError(
            f"AI backend type {self.backend_type!r} has no concrete "
            f"adapter registered yet. The schema accepts this type "
            f"(see ai_backends CHECK constraint) so a later wave can "
            f"land the adapter without a migration; until then, do "
            f"not select this backend type for any account."
        )
