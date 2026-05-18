"""Pluggable AI backend adapters for classifier + style-learning paths.

Public surface
==============
This package formalises the implicit pluggable-backend pattern that
already existed across ``classify/ollama.py``, ``classify/openai_compat.py``,
and ``classify/gemini.py``. The new contract:

  * :class:`BackendAdapter` — the ABC concrete subclasses implement.
    Minimal API (``chat_complete`` + optional ``embed``).
  * :func:`load_backend` — factory that instantiates the right adapter
    from an ``ai_backends`` DB row (or returns the install-default
    Ollama adapter when called with ``None``).
  * :data:`BACKEND_TYPES` — the registry mapping the SQL ``type`` enum
    (``ollama`` / ``openai`` / ``azure_openai`` / ``gemini``) to its
    adapter class.

Concrete adapters shipped today
-------------------------------
  * :class:`OllamaAdapter` — local Ollama default (W1-A).
  * :class:`AzureOpenAIAdapter` — Azure OpenAI Service (W1-B). Carries
    a :class:`Classifier`-compatible :class:`AzureOpenAIClassifier`
    shim so the existing classifier path can use it without waiting
    for the loader migration.
  * :class:`OpenAIAdapter` — OpenAI direct + OpenAI-compatible
    endpoints (LiteLLM proxy, vLLM, LM Studio, etc.). Ships with the
    :class:`OpenAIClassifier` shim (#171-A).
  * :class:`GeminiAdapter` — Google Gemini via the AI Studio REST
    surface (Vertex AI works with a custom endpoint). Ships with the
    :class:`GeminiClassifierShim` shim (#171-A).

Classifier-path migration
-------------------------
``_build_classifier_from_config`` (in
``web/routers/ui/_shared.py``) is still the routing point for the
classifier path. Migrating it to consume :func:`load_backend` based
on per-account context is deferred to a follow-up — the adapter
foundation is in place, so the migration can land without further
schema changes.
"""

from __future__ import annotations

from email_triage.ai_backends.azure_openai import (
    AzureOpenAIAdapter,
    AzureOpenAIAuthError,
    AzureOpenAIClassifier,
    AzureOpenAIError,
)
from email_triage.ai_backends.base import (
    BackendAdapter,
    BackendDisabledError,
    BackendError,
    BackendNotFoundError,
    NotImplementedAdapter,
)
from email_triage.ai_backends.gemini_adapter import (
    GeminiAdapter,
    GeminiAuthError,
    GeminiClassifierShim,
    GeminiError,
)
from email_triage.ai_backends.loader import load_backend
from email_triage.ai_backends.openai_direct import (
    OpenAIAdapter,
    OpenAIAuthError,
    OpenAIClassifier,
    OpenAIError,
)
from email_triage.ai_backends.registry import BACKEND_TYPES, register_backend

__all__ = [
    "BackendAdapter",
    "BackendError",
    "BackendNotFoundError",
    "BackendDisabledError",
    "NotImplementedAdapter",
    "BACKEND_TYPES",
    "register_backend",
    "load_backend",
    # Concrete adapters
    "AzureOpenAIAdapter",
    "AzureOpenAIAuthError",
    "AzureOpenAIError",
    "AzureOpenAIClassifier",
    "OpenAIAdapter",
    "OpenAIAuthError",
    "OpenAIError",
    "OpenAIClassifier",
    "GeminiAdapter",
    "GeminiAuthError",
    "GeminiError",
    "GeminiClassifierShim",
]
