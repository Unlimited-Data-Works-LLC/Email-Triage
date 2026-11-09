"""OpenAI direct + OpenAI-compatible adapter.

Sibling to :class:`email_triage.ai_backends.azure_openai.AzureOpenAIAdapter`.
Wraps the same OpenAI ``/v1/chat/completions`` API surface that the
pre-existing :class:`email_triage.classify.openai_compat.OpenAICompatClassifier`
has talked to since the project's first multi-backend cycle, but exposes
the W1-A :class:`BackendAdapter` canonical contract
(``chat_complete(messages, *, response_format, max_tokens, **kwargs)``).

Why a free-standing class
-------------------------
The existing classifier is a :class:`Classifier`-ABC subclass — its
public surface is ``classify(message, categories, list_hints)``. That
shape is wrong for non-classification consumers (style-learning distill,
error-explain, future RAG). The new W1-A ABC sits one layer lower,
just doing HTTP plumbing + provider-shape mapping.

This module mirrors the canonical pattern set by
``ai_backends/azure_openai.py``:

* :class:`OpenAIAdapter` — :class:`BackendAdapter` subclass with
  ``chat_complete``.
* :class:`OpenAIClassifier` — :class:`Classifier`-ABC shim composing
  :class:`OpenAIAdapter`, so the existing classifier path can use it
  without waiting for :func:`load_backend` migration.
* :class:`OpenAIError` + :class:`OpenAIAuthError` — error classes with
  the defensive ``_TOKEN_KEYS`` body-scrub at construction time.

File name
---------
``openai_direct.py`` — not ``openai.py`` — because the latter would
collide with the ``openai`` SDK package, which an operator may have
installed themselves (this project declares no ``openai`` extra since
punch 489, 2026-10-18).
A relative ``from openai import …`` inside this file would silently
target ourselves rather than the SDK, and adapter consumers would get
the wrong import.

Public OpenAI vs OpenAI-compatible
----------------------------------
The same HTTP surface works against:

* api.openai.com (public OpenAI)
* LiteLLM proxy on the homelab (local-LAN deployment)
* vLLM, LM Studio, text-generation-webui (self-hosted)

The adapter classifies its endpoint as local-or-not via the canonical
:func:`email_triage.classify.base._is_local_host` helper — same logic
the pre-existing OpenAI-compat classifier uses. This drives the HIPAA
BAA gate: a public-OpenAI deployment is external (``is_local=False``)
and requires a BAA before HIPAA traffic reaches it; a self-hosted LAN
endpoint is local (``is_local=True``) and the gate stays open.

Privacy
-------
The adapter never logs the api_key, never round-trips it through
templates, and scrubs token-shape keys out of any error body before
incorporating it into the exception message ( hardening pattern,
mirroring :class:`GmailApiError` + :class:`AzureOpenAIError`).
"""

from __future__ import annotations

import logging
from typing import Any
from email_triage._secret_scrub import strip_url_query_secrets as _strip_sensitive_query_params

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.classify.base import JsonChatClassifier

logger = get_logger("email_triage.ai_backends.openai_direct")  # N-196b R21_4

# Default OpenAI public endpoint. Operators self-hosting LiteLLM /
# vLLM / LM Studio / text-generation-webui override via the
# ``ai_backends.endpoint`` column.
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"

# Default model when an ``ai_backends`` row leaves ``model`` empty.
# ``gpt-4o-mini`` is the current cost/quality sweet-spot for short
# classification prompts as of 2026-05; operators picking a different
# tier override via the row.
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"

# Conservative default request timeout. Mirrors the Azure adapter +
# the existing OpenAI-compat classifier (120 s absorbs occasional
# cold-start on self-hosted endpoints scaling from zero).
DEFAULT_TIMEOUT = 120.0


class OpenAIError(Exception):
    """Raised when an OpenAI API call returns an error.

    Defensive token-shape scrub at construction time (mirrors the
    :class:`AzureOpenAIError` pattern, which mirrors :class:`GmailApiError`
    from commit ``2de45ea`` / ). The fallback ``str(body)`` path is
    reachable when an upstream proxy injects a non-OpenAI response or
    when a future refactor returns the wrong dict shape — in either
    case, if a token-bearing field ever lands in the response dict,
    plaintext leakage through the exception message (and from there,
    through every log handler that captures ``exc_info``) is the
    worst-case outcome. Scrub before stringifying so the leak surface
    is closed at the earliest point.

    Reuses the canonical :data:`TriageLogger._TOKEN_KEYS` frozenset
    rather than inlining a duplicate list — single source of truth.
    """

    def __init__(self, status: int, body: Any, url: str = ""):
        self.status = status
        self.body = body
        self.url = url
        if isinstance(body, dict):
            # Defensive scrub — drop any key whose name matches the
            # canonical token-key frozenset before stringification can
            # surface its value. Local import avoids a top-level
            # circular: triage_logging is imported widely and we want
            # to keep the ai_backends package import-cheap.
            from email_triage.triage_logging import TriageLogger
            _token_keys = TriageLogger._TOKEN_KEYS
            safe_body = {
                k: v for k, v in body.items() if k.lower() not in _token_keys
            }
            err = body.get("error", {})
            if isinstance(err, dict):
                # OpenAI's chat-completions error shape:
                #   {"error": {"message": "...", "type": "...",
                #              "param": null, "code": "..."}}
                msg = err.get("message", str(safe_body))
            else:
                # Some OpenAI-compatible proxies (LiteLLM in some modes,
                # vLLM in error paths) return the error as a top-level
                # string instead of a nested object.
                msg = body.get("error_description") or str(err) or str(safe_body)
        else:
            msg = str(body)
        # Strip sensitive query params if any leaked into the URL
        # (defence-in-depth — current call sites never include the key
        # in the URL, but a future refactor that hand-builds the URL
        # could).
        clean_url = _strip_sensitive_query_params(url) if url else url
        super().__init__(f"OpenAI {status}: {msg} ({clean_url})")


class OpenAIAuthError(OpenAIError):
    """Raised when OpenAI rejects the api_key (401 / 403)."""


from email_triage.ai_backends.base import BackendAdapter, meter_chat_complete


class OpenAIAdapter(BackendAdapter):
    """W1-A :class:`BackendAdapter` over OpenAI ``/v1/chat/completions``.

    Targets both public OpenAI (api.openai.com) and any OpenAI-
    compatible endpoint (LiteLLM proxy, vLLM, LM Studio, etc.). The
    HIPAA BAA gate posture comes from :attr:`is_local`, computed via
    :func:`_is_local_host` against the configured endpoint:

    * api.openai.com → ``is_local=False`` → BAA required
    * http://localhost:* or LAN host → ``is_local=True`` → gate open

    Parameters
    ----------
    endpoint:
        Base URL. Defaults to :data:`DEFAULT_OPENAI_BASE_URL`. For
        OpenAI-compatible servers, point at the ``/v1`` root (e.g.
        ``https://litellm.home.lan/v1``, ``http://localhost:8000/v1``).
        Trailing slash optional; the constructor normalises.
    api_key:
        Bearer token. For public OpenAI this is the ``sk-...`` key.
        Self-hosted proxies may accept any value or none.
    model:
        Model name. Defaults to :data:`DEFAULT_OPENAI_MODEL`.
        Some proxy backends ignore this (vLLM serves whatever model
        is loaded); pass-through unchanged.
    default_temperature, default_max_tokens:
        Per-call defaults; individual ``chat_complete`` calls override.
    timeout:
        Request timeout in seconds.
    local_url_suffixes:
        Operator-defined "treat-as-local" hostname suffixes (sourced
        from ``config.tls.local_url_suffixes``). The base helper
        already recognises ``localhost`` / RFC1918 / ``.local``;
        this extends with operator-specific suffixes like
        ``.home.lan`` / ``.internal.example``.
    """

    backend_type = "openai"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
        local_url_suffixes: list[str] | None = None,
        **_: Any,
    ) -> None:
        # Empty endpoint falls through to the public OpenAI default —
        # makes the loader path forgiving (an ``ai_backends`` row with
        # NULL ``endpoint`` for the public service is reasonable).
        self._endpoint = (endpoint or DEFAULT_OPENAI_BASE_URL).rstrip("/")
        # api_key may legitimately be empty during config validation +
        # for some self-hosted proxies that don't require auth. The
        # loader catches the public-OpenAI empty-key case upstream; the
        # adapter itself does NOT enforce non-empty at construction
        # because that would break LAN proxies that accept anonymous
        # traffic.
        self._api_key = api_key or ""
        self._model = model or DEFAULT_OPENAI_MODEL
        self._default_temperature = default_temperature
        self._default_max_tokens = default_max_tokens
        self._timeout = timeout
        #  — one long-lived pooled httpx client per adapter
        # instance, reused across every chat_complete() call instead of
        # a fresh AsyncClient (TLS handshake) per call. Mirrors the
        # classify/* cloud classifiers and OllamaClassifier.
        self._http = LazyHttpClient(intent=Intent.LLM_PHI, timeout=timeout)

        # HIPAA gate posture mirrors classify.openai_compat — local
        # endpoints (localhost / RFC1918 / .local / operator-defined
        # suffixes) pass the gate; public OpenAI does not.
        from email_triage.classify.base import _is_local_host
        self.is_local = _is_local_host(
            self._endpoint,
            extra_suffixes=tuple(local_url_suffixes or ()),
        )

    async def close(self) -> None:
        """Drain the pooled HTTP client (BackendAdapter.close override)."""
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Canonical W1-A method
    # ------------------------------------------------------------------

    @meter_chat_complete  # N-194b R21_9: et_llm_chat_seconds metric
    async def chat_complete(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> str:
        """Run an OpenAI chat-completion. Canonical adapter entry.

        Parameters
        ----------
        messages:
            OpenAI-style chat messages:
            ``[{"role": ..., "content": ...}, ...]``. Must be non-empty;
            passing an empty list raises :class:`ValueError` BEFORE any
            HTTP call (saves a round-trip on an obvious caller bug).
        response_format:
            Pass-through ``response_format``. Two OpenAI-supported shapes:

            * ``{"type": "json_object"}`` — guaranteed JSON-object reply.
            * ``{"type": "json_schema", "json_schema": {...}}`` — strict
              schema-mode (gpt-4o + later).

            Pass-through unchanged; the adapter doesn't normalise the
            shape — callers know what they want.
        max_tokens, temperature:
            Per-call overrides for the adapter defaults.
        **kwargs:
            Additional OpenAI body fields (``top_p``, ``frequency_penalty``,
            ``presence_penalty``, ``seed``, ``stop``, ``user``).
            Pass-through to the request body.

        Returns
        -------
        str
            The model's reply content (``choices[0].message.content``).
            When ``response_format`` requested JSON, the returned string
            is valid JSON per OpenAI's guarantee; callers parse via
            ``json.loads`` (the adapter does NOT parse — keeping
            structured-vs-text behaviour transparent to the W1-A loader).

        Raises
        ------
        ValueError
            ``messages`` is empty.
        OpenAIAuthError
            OpenAI returned 401 / 403.
        OpenAIError
            Any other 4xx / 5xx, or a 2xx with no usable content.
        """
        if not messages:
            raise ValueError(
                "chat_complete() requires at least one message; "
                "empty messages list is a caller bug — OpenAI would 400 "
                "the request and we'd burn a round-trip"
            )

        url = f"{self._endpoint}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        body: dict[str, Any] = {
            "messages": messages,
            "model": self._model,
            "temperature": (
                temperature
                if temperature is not None
                else self._default_temperature
            ),
            "max_tokens": (
                max_tokens
                if max_tokens is not None
                else self._default_max_tokens
            ),
        }
        if response_format is not None:
            body["response_format"] = response_format
        # Pass-through additional OpenAI body fields. Filter out keys
        # we already set so a caller-supplied ``messages`` (mistaken
        # double-set) doesn't clobber the validated list. Also protects
        # ``model`` from kwargs override (adapter's configured model
        # wins).
        for k, v in kwargs.items():
            if k in body:
                continue
            body[k] = v

        #  — wrap the POST in the shared circuit-breaker helper, the
        # same translation  added to classify/openai_compat.py. A
        # dead OpenAI-compatible endpoint (connection refused / network
        # blip) now trips the breaker and re-raises a typed
        # LLMBackendUnreachableError instead of a raw httpx.ConnectError.
        # Keyed "openai" to match the configured classifier.backend the
        # is_healthy gate resolves ("ollama"/"openai"/"gemini") — a key
        # the gate never sees can never gate. A 4xx/5xx is NOT a connect
        # failure, so the raise_for_status-equivalent status check below
        # stays OUTSIDE the wrapper: those mean the backend is up but
        # misbehaving and must not flip the breaker.
        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "openai", self._endpoint, default_port=443,
        ):
            client = await self._http.get()
            resp = await client.post(url, headers=headers, json=body)

        if resp.status_code >= 400:
            try:
                err_body: Any = resp.json()
            except Exception:
                err_body = resp.text or ""
            if resp.status_code in (401, 403):
                raise OpenAIAuthError(resp.status_code, err_body, url)
            raise OpenAIError(resp.status_code, err_body, url)

        try:
            payload = resp.json()
        except Exception as e:
            raise OpenAIError(
                resp.status_code,
                f"Non-JSON response body: {e}",
                url,
            ) from e

        choices = payload.get("choices") or []
        if not choices:
            # 2xx with no content is most commonly a content-filter or
            # safety-guardrail trip on certain proxies. Surface as an
            # error so the caller doesn't silently get an empty
            # classification.
            raise OpenAIError(
                resp.status_code,
                payload,
                url,
            )
        #  silent-truncation guard (shared SSOT) — a max_tokens cut yields
        # invalid JSON for a classify / a mid-word cut for complete.
        from email_triage.llm_truncation import warn_if_llm_truncated
        warn_if_llm_truncated(
            payload, family="openai", model=str(payload.get("model") or ""),
            context="chat_complete", logger=logger,
        )
        content = (
            choices[0].get("message", {}).get("content")
            or ""
        )
        return content

    # ------------------------------------------------------------------
    # Compatibility aliases — let the W1-A loader and the existing
    # classifier path both dispatch by the name they each prefer.
    # ------------------------------------------------------------------

    async def complete(self, prompt: str, **kwargs: Any) -> str:
        """Raw single-prompt completion. Convenience over chat_complete.

        Wraps a single-message user-role call. Matches the
        :class:`Classifier.complete` shape so the existing classifier
        path can use the adapter without a shim.
        """
        return await self.chat_complete(
            [{"role": "user", "content": prompt}],
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Introspection — useful for the admin UI + loader's config-
    # validation step.
    # ------------------------------------------------------------------

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def model(self) -> str:
        return self._model


# ---------------------------------------------------------------------------
# Classifier-ABC shim — bridges OpenAIAdapter to the existing
# classify/flow path. Keep it close to the adapter so callers find both
# in one module; the import surface is :mod:`email_triage.ai_backends`.
# ---------------------------------------------------------------------------


class OpenAIClassifier(JsonChatClassifier):
    """:class:`JsonChatClassifier` subclass wrapping :class:`OpenAIAdapter`.

    The existing flow engine calls ``classifier.classify(message, ...)``;
    that whole body — prompt build, two-level classification-cache
    lookup, sender-history hint, JSON parse, out-of-taxonomy
    :class:`ValueError`, cache store — lives once on
    :class:`JsonChatClassifier`. This shim implements only the two
    per-backend hooks:

    * :meth:`_resolve_model` — the cache key + request model name.
    * :meth:`_chat` — issue one chat request via the W1-A adapter.

    Subclassing the shared base (rather than re-implementing
    ``classify``) means the out-of-taxonomy guard fires here too: a
    model returning a category no route matches raises instead of
    silently producing a no-op :class:`Classification`.
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
        local_url_suffixes: list[str] | None = None,
    ):
        self._adapter = OpenAIAdapter(
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            default_temperature=default_temperature,
            default_max_tokens=default_max_tokens,
            timeout=timeout,
            local_url_suffixes=local_url_suffixes,
        )
        # ``_model`` is the classification-cache key the shared base
        # passes to the cache + to :meth:`_chat`. Non-empty fallback
        # mirrors the pre-refactor ``model_key = self._adapter.model or
        # "openai"`` behaviour so an empty configured model still keys
        # the cache stably.
        self._model = self._adapter.model or "openai"
        # Surface :attr:`is_local` on the shim so the HIPAA gate sees
        # the same answer regardless of which surface it inspects.
        self.is_local = self._adapter.is_local

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue one chat request via the W1-A adapter; return raw text.

        ``model`` is the cache key from :meth:`_resolve_model`; the
        adapter uses its own configured model for the request payload,
        so the placeholder cache key never reaches the endpoint.
        """
        return await self._adapter.chat_complete(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )

    async def complete(self, prompt: str) -> str:
        """Raw completion via the underlying adapter."""
        return await self._adapter.complete(
            prompt, max_tokens=2048,
        )

    async def close(self) -> None:
        """Drain the adapter's pooled HTTP client. Idempotent."""
        await self._adapter.close()
