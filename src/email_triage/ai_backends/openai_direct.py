"""OpenAI direct + OpenAI-compatible adapter (#171-A).

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
  the defensive ``_TOKEN_KEYS`` body-scrub at construction time
  (#168 hardening, identical pattern to :class:`AzureOpenAIError`).

File name
---------
``openai_direct.py`` — not ``openai.py`` — because the latter would
collide with the optional ``openai`` SDK package, which an operator may
have installed (it's in ``pyproject.toml`` ``[project.optional-dependencies]``).
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
incorporating it into the exception message (#168 hardening pattern,
mirroring :class:`GmailApiError` + :class:`AzureOpenAIError`).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("email_triage.ai_backends.openai_direct")

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
    from commit ``2de45ea`` / #168). The fallback ``str(body)`` path is
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


def _strip_sensitive_query_params(url: str) -> str:
    """Remove ``api-key`` / ``key`` / ``token`` / ``access_token`` /
    ``code`` query params from URL.

    Belt-and-suspenders: today the adapter never puts the key in the
    URL (it goes in the ``Authorization: Bearer`` header), but
    third-party OpenAI samples sometimes show ``?api-key=...`` patterns;
    a future refactor that copy-pastes from one of those samples would
    introduce a leak. Strip at error-render time so a leaked URL can't
    surface plaintext in logs.
    """
    if not url or "?" not in url:
        return url
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    sensitive = {"api-key", "key", "token", "access_token", "code"}
    pairs = []
    for raw in parts.query.split("&"):
        if not raw:
            continue
        k, _, _v = raw.partition("=")
        if k.lower() in sensitive:
            pairs.append(f"{k}=REDACTED")
        else:
            pairs.append(raw)
    new_query = "&".join(pairs)
    return f"{parts.scheme}://{parts.netloc}{parts.path}" + (
        f"?{new_query}" if new_query else ""
    )


from email_triage.ai_backends.base import BackendAdapter


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

        # HIPAA gate posture mirrors classify.openai_compat — local
        # endpoints (localhost / RFC1918 / .local / operator-defined
        # suffixes) pass the gate; public OpenAI does not.
        from email_triage.classify.base import _is_local_host
        self.is_local = _is_local_host(
            self._endpoint,
            extra_suffixes=tuple(local_url_suffixes or ()),
        )

    # ------------------------------------------------------------------
    # Canonical W1-A method
    # ------------------------------------------------------------------

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

        async with httpx.AsyncClient(timeout=self._timeout) as client:
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


def _build_openai_classifier_imports():
    """Local import helper.

    The classify package depends on the engine.models module, which in
    turn pulls in a sizeable bit of the SQLite layer. Defer those
    imports to first-use so ``import email_triage.ai_backends`` stays
    cheap (e.g. for an admin UI that lists backends without ever
    calling them).
    """
    from email_triage.classify.base import Classifier
    from email_triage.classify.ollama import _parse_llm_json
    from email_triage.classify.prompts import (
        build_system_prompt, build_user_prompt,
    )
    from email_triage.engine.models import (
        Classification, EmailMessage, ListHint,
    )
    return (
        Classifier, _parse_llm_json, build_system_prompt,
        build_user_prompt, Classification, EmailMessage, ListHint,
    )


class OpenAIClassifier:
    """:class:`Classifier`-ABC-compatible wrapper around :class:`OpenAIAdapter`.

    The existing flow engine calls ``classifier.classify(message, ...)``;
    this shim adapts to that surface while delegating the HTTP work to
    the canonical adapter. Same prompt builders + same response parser
    as the existing :class:`OpenAICompatClassifier` — diverges only at
    the HTTP-call seam, which now routes through the W1-A adapter.

    The class is built without inheriting from :class:`Classifier`
    because the ABC + prompt helpers are imported lazily (see
    :func:`_build_openai_classifier_imports`). This costs one extra
    method call but keeps ``import email_triage.ai_backends`` cheap.
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
        # Surface :attr:`is_local` on the shim so the HIPAA gate sees
        # the same answer regardless of which surface it inspects.
        self.is_local = self._adapter.is_local

    async def classify(self, message, categories, list_hints=None):
        # Lazy import — keeps cold-import path light.
        (
            _Classifier, _parse_llm_json, build_system_prompt,
            build_user_prompt, Classification, _EmailMessage, _ListHint,
        ) = _build_openai_classifier_imports()

        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

        # 2026-05-13 two-level cache lookup — same pattern as the
        # OpenAI-compat / Gemini / Ollama / Azure classifiers. Best-
        # effort; any cache failure falls through to a live call.
        outer_key: str | None = None
        inner_field: str | None = None
        hint_text: str | None = None
        try:
            from email_triage.cache.classification import (
                cache_lookup_for_message,
            )
            model_key = self._adapter.model or "openai"
            outer_key, inner_field, cache_entry, hint_text = (
                cache_lookup_for_message(message, model_key, categories)
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

        raw = await self._adapter.chat_complete(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        parsed = _parse_llm_json(raw)

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

        try:
            from email_triage.cache.classification import (
                cache_store_for_message,
            )
            model_key = self._adapter.model or "openai"
            cache_store_for_message(
                outer_key, inner_field, model_key, result, categories,
                is_hipaa=bool(getattr(message, "hipaa", False)),
            )
        except Exception as e:
            logger.debug("Classification cache store error: %s", e)

        return result

    async def complete(self, prompt: str) -> str:
        """Raw completion via the underlying adapter."""
        return await self._adapter.complete(
            prompt, max_tokens=2048,
        )
