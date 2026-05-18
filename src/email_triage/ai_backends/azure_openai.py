"""Azure OpenAI Service adapter.

Sibling to :class:`email_triage.classify.openai_compat.OpenAICompatClassifier`
— same OpenAI chat-completions API shape, different auth + URL plumbing:

* Endpoint:    ``https://{resource}.openai.azure.com``
* Path:        ``/openai/deployments/{deployment}/chat/completions``
* Query param: ``api-version=YYYY-MM-DD``
* Header:      ``api-key: <key>``           (NOT ``Authorization: Bearer``)

Why a free-standing class
-------------------------
``OpenAICompatClassifier`` already classifies Azure traffic correctly via
``extra_headers={"api-version": "..."}`` and a hand-built ``base_url``.
But (a) it bolts auth onto the same ``Authorization: Bearer`` header that
public OpenAI uses, which Azure rejects with 401; (b) it bakes the api-
version into headers when it belongs in the query string per Azure's
canonical client; and (c) the W1-A ``BackendAdapter`` ABC wants a
``chat_complete(messages, *, response_format, max_tokens, **kwargs)``
canonical method that the OpenAI-compat class predates.

This class fixes all three and exposes the W1-A canonical surface.
W1-A's loader can dispatch to ``chat_complete()`` by name; the existing
classifier path can dispatch to ``classify()`` / ``complete()`` via
``AzureOpenAIClassifier`` (the ``Classifier``-ABC shim sibling at the
bottom of this file).

HTTP transport choice — httpx, not the openai SDK
-------------------------------------------------
The codebase's established pattern is raw httpx (see Ollama, Gemini,
OpenAI-compat, embedding-backend). ``openai`` is an OPTIONAL
dependency (``pyproject.toml`` ``[project.optional-dependencies]``); a
fresh install does not have it. Mirror that pattern for portability +
to keep the cold-import surface small.

api-version choice — 2024-10-21
-------------------------------
``2024-10-21`` is the current ``api-version=current`` GA stable for the
``/chat/completions`` surface as of 2026-05 (Azure's recommended-stable
rolls forward roughly each quarter). Picks structured-output (json_schema)
support up so #152 phases 3-4 can plumb the describe-and-discard schema
through. Operators can override via the ``ai_backends`` row.

Privacy
-------
The adapter never logs the api_key, never round-trips it through
templates, and scrubs token-shape keys out of any error body before
incorporating it into the exception message (#168 hardening pattern,
mirroring ``GmailApiError``).
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("email_triage.ai_backends.azure_openai")

# Default api-version. Operator can override via the ``ai_backends``
# row; this constant is the "what shipped when this adapter was
# authored" value, used when the caller passes ``api_version=None``.
# 2024-10-21 is the GA stable as of 2026-05 — includes structured
# response_format=json_schema support, which #152 phases 3-4 needs.
DEFAULT_API_VERSION = "2024-10-21"

# Conservative default request timeout. Azure latency P99 is typically
# under 30 s for short prompts; 120 s mirrors the Ollama / OpenAI-compat
# default and absorbs the occasional cold start on a deployment that
# scales-from-zero.
DEFAULT_TIMEOUT = 120.0


class AzureOpenAIError(Exception):
    """Raised when an Azure OpenAI API call returns an error.

    Defensive token-shape scrub at construction time (mirrors the
    ``GmailApiError`` hardening from commit ``2de45ea`` / #168). The
    fallback ``str(body)`` path is reachable when Azure returns a 200
    with an unexpected body or when an upstream proxy injects a
    non-Azure response — in either case, if a token-bearing field ever
    ends up in the response dict, plaintext leakage through the
    exception message (and from there, through every log handler that
    captures ``exc_info``) is the worst-case outcome. Scrub before
    stringifying so the leak surface is closed at the earliest point.

    Reuses the canonical ``TriageLogger._TOKEN_KEYS`` frozenset rather
    than inlining a duplicate list — single source of truth.
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
                # Azure's chat-completions error shape:
                #   {"error": {"message": "...", "code": "...", "type": "..."}}
                msg = err.get("message", str(safe_body))
            else:
                # Some Azure endpoints (content-filter, throttle) return
                # {"error": "...", "error_description": "..."}.
                msg = body.get("error_description") or str(err) or str(safe_body)
        else:
            msg = str(body)
        # Strip the api-key query param from the URL if it ever leaked
        # in (defence-in-depth — current call sites never include the
        # key in the URL, but a future refactor that hand-builds the
        # URL could).
        clean_url = _strip_sensitive_query_params(url) if url else url
        super().__init__(f"Azure OpenAI {status}: {msg} ({clean_url})")


class AzureOpenAIAuthError(AzureOpenAIError):
    """Raised when Azure rejects the api-key (401 / 403)."""


def _strip_sensitive_query_params(url: str) -> str:
    """Remove ``api-key`` / ``key`` / ``token`` query params from URL.

    Belt-and-suspenders: today the adapter never puts the key in the
    URL (it goes in the ``api-key`` header), but third-party Azure
    samples sometimes show ``?api-key=...`` patterns; a future
    refactor that copy-pastes from one of those samples would
    introduce a leak. Strip at error-render time so a leaked URL
    can't surface plaintext in logs.
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


class AzureOpenAIAdapter(BackendAdapter):
    """Standalone Azure OpenAI adapter — W1-A ``BackendAdapter`` shape.

    This class is intentionally NOT a subclass of
    :class:`email_triage.classify.base.Classifier`. It IS a subclass
    of :class:`email_triage.ai_backends.base.BackendAdapter` — the
    canonical ABC that ``load_backend`` dispatches against:

    * W1-A canonical: ``chat_complete(messages, *, response_format,
      max_tokens, **kwargs) -> str | dict``
    * Existing classifier: ``classify()`` + ``complete()`` are provided
      by the :class:`AzureOpenAIClassifier` sibling at the bottom of
      this module, which composes an ``AzureOpenAIAdapter`` and adapts
      to the ``Classifier`` ABC.

    Parameters
    ----------
    endpoint:
        Azure resource endpoint, e.g.
        ``https://my-resource.openai.azure.com/``. Trailing slash
        optional; the constructor normalises.
    api_key:
        Azure resource key. Fetched from the secrets store at adapter
        construction time by the loader. Never logged, never round-
        tripped through templates.
    deployment:
        Azure deployment name (NOT the underlying model name; one
        deployment maps to one model). Required.
    api_version:
        Azure ``api-version`` query param. Defaults to
        :data:`DEFAULT_API_VERSION`. Operators wanting a newer GA
        version override here; older versions degrade structured-
        output support.
    model:
        Optional underlying model name. Azure ignores ``model`` in the
        request body (the deployment selects the model), but the
        ``ai_backends`` row carries both so the admin UI can show the
        underlying model. Default empty string.
    default_temperature, default_max_tokens:
        Per-call defaults; individual ``chat_complete`` calls can
        override.
    timeout:
        Request timeout in seconds.
    """

    # The classifier path uses ``is_local`` to fail-closed on HIPAA
    # content when the configured backend is external. Azure OpenAI
    # is always external — Microsoft's hosted endpoint, even in BAA-
    # enabled tenants. ``is_local`` stays False; the BAA gate
    # elsewhere in the codebase opens the door for HIPAA traffic
    # once a signed BAA is on file. Same posture as Gemini.
    is_local: bool = False

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str | None = None,
        model: str = "",
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        if not endpoint:
            raise ValueError("Azure OpenAI adapter requires a non-empty endpoint")
        if not deployment:
            raise ValueError(
                "Azure OpenAI adapter requires a non-empty deployment name "
                "(Azure deployment != model; the deployment is the named "
                "instance in the Azure portal that maps to a model)"
            )
        # api_key may legitimately be empty during config validation —
        # the loader catches the empty case and raises at construction
        # time, but for a unit-test path we allow construction and
        # fail at first HTTP call.
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._deployment = deployment
        self._api_version = api_version or DEFAULT_API_VERSION
        self._model = model
        self._default_temperature = default_temperature
        self._default_max_tokens = default_max_tokens
        self._timeout = timeout

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
        """Run an Azure OpenAI chat-completion. Canonical adapter entry.

        Parameters
        ----------
        messages:
            OpenAI-style chat messages: ``[{"role": ..., "content": ...}, ...]``.
            Must be non-empty; passing an empty list raises ``ValueError``
            BEFORE any HTTP call (saves an Azure round-trip on an obvious
            caller bug).
        response_format:
            Pass-through ``response_format``. Two Azure-supported shapes:

            * ``{"type": "json_object"}`` — guaranteed JSON-object reply.
            * ``{"type": "json_schema", "json_schema": {...}}`` — strict
              schema-mode. Requires ``api_version >= 2024-08-01-preview``;
              the default :data:`DEFAULT_API_VERSION` supports it.

            Pass-through unchanged; this adapter doesn't normalise the
            shape — callers know what they want.
        max_tokens, temperature:
            Per-call overrides for the adapter defaults.
        **kwargs:
            Additional OpenAI body fields (``top_p``, ``frequency_penalty``,
            ``seed``, ``stop``, ``user``). Pass-through to the request body.

        Returns
        -------
        str
            The model's reply content (``choices[0].message.content``).
            When ``response_format`` requested JSON, the returned string
            is valid JSON per Azure's guarantee; callers parse via
            ``json.loads`` (the adapter does NOT parse — keeping
            structured-vs-text behaviour transparent to the W1-A loader).

        Raises
        ------
        ValueError
            ``messages`` is empty, or ``api_key`` is empty at call time.
        AzureOpenAIAuthError
            Azure returned 401 / 403.
        AzureOpenAIError
            Any other 4xx / 5xx, or a 2xx with no usable content.
        """
        if not messages:
            raise ValueError(
                "chat_complete() requires at least one message; "
                "empty messages list is a caller bug — Azure would 400 "
                "the request and we'd burn a round-trip"
            )
        if not self._api_key:
            raise ValueError(
                "Azure OpenAI api_key is empty — the loader should have "
                "raised at construction; refusing to make an unauthenticated "
                "call to a hosted service"
            )

        url = (
            f"{self._endpoint}/openai/deployments/"
            f"{self._deployment}/chat/completions"
        )
        params = {"api-version": self._api_version}
        headers = {
            "Content-Type": "application/json",
            "api-key": self._api_key,
        }

        body: dict[str, Any] = {
            "messages": messages,
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
        # Azure ignores ``model`` (deployment selects the model) but
        # passing it through keeps OpenAI-tooling compatibility for
        # any caller that introspects what was sent.
        if self._model:
            body["model"] = self._model
        # Pass-through additional OpenAI body fields. Filter out keys
        # we already set so a caller-supplied ``messages`` (mistaken
        # double-set) doesn't clobber the validated list.
        for k, v in kwargs.items():
            if k in body:
                continue
            body[k] = v

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url, params=params, headers=headers, json=body,
            )

        if resp.status_code >= 400:
            try:
                err_body: Any = resp.json()
            except Exception:
                err_body = resp.text or ""
            if resp.status_code in (401, 403):
                raise AzureOpenAIAuthError(resp.status_code, err_body, url)
            raise AzureOpenAIError(resp.status_code, err_body, url)

        try:
            payload = resp.json()
        except Exception as e:
            raise AzureOpenAIError(
                resp.status_code,
                f"Non-JSON response body: {e}",
                url,
            ) from e

        choices = payload.get("choices") or []
        if not choices:
            # 2xx with no content is a content-filter trip on Azure
            # (response_filter_results carries the detail). Surface as
            # an error so the caller doesn't silently get an empty
            # classification.
            raise AzureOpenAIError(
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
    # classifier path both dispatch by name they each prefer.
    # ------------------------------------------------------------------

    async def complete(self, prompt: str, **kwargs: Any) -> str:
        """Raw single-prompt completion. Convenience over chat_complete.

        Wraps a single-message user-role call. Matches the
        ``Classifier.complete`` shape so the existing classifier path
        can use the adapter without a shim.
        """
        return await self.chat_complete(
            [{"role": "user", "content": prompt}],
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Introspection — useful for the admin UI and for the W1-A loader's
    # config-validation step (sanity-check the deployment / api-version
    # before the first request fires).
    # ------------------------------------------------------------------

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def deployment(self) -> str:
        return self._deployment

    @property
    def api_version(self) -> str:
        return self._api_version

    @property
    def model(self) -> str:
        """Underlying model name (informational; Azure ignores it)."""
        return self._model


# ---------------------------------------------------------------------------
# Classifier-ABC shim — bridges AzureOpenAIAdapter to the existing
# classify/flow path. Keep it close to the adapter so callers find both
# in one module; the import surface is :mod:`email_triage.ai_backends`.
# ---------------------------------------------------------------------------


def _build_azure_classifier_imports():
    """Local import helper.

    The classify package depends on the engine.models module, which
    in turn pulls in a sizeable bit of the SQLite layer. Defer those
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


class AzureOpenAIClassifier:
    """Classifier-ABC-compatible wrapper around :class:`AzureOpenAIAdapter`.

    The existing flow engine calls ``classifier.classify(message, ...)``;
    this shim adapts to that surface while delegating the HTTP work to
    the canonical adapter. Same prompt builders + same response parser
    as ``OpenAICompatClassifier`` — diverges only at the HTTP layer.

    The class is constructed dynamically because the parent
    ``Classifier`` ABC and prompt helpers are imported lazily (see
    :func:`_build_azure_classifier_imports`). This costs one extra
    method call but keeps ``import email_triage.ai_backends`` cheap.
    """

    is_local: bool = False

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str | None = None,
        model: str = "",
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self._adapter = AzureOpenAIAdapter(
            endpoint=endpoint,
            api_key=api_key,
            deployment=deployment,
            api_version=api_version,
            model=model,
            default_temperature=default_temperature,
            default_max_tokens=default_max_tokens,
            timeout=timeout,
        )

    async def classify(self, message, categories, list_hints=None):
        # Lazy import — keeps cold-import path light.
        (
            _Classifier, _parse_llm_json, build_system_prompt,
            build_user_prompt, Classification, _EmailMessage, _ListHint,
        ) = _build_azure_classifier_imports()

        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

        # 2026-05-13 two-level cache lookup — same pattern as the
        # OpenAI-compat / Gemini / Ollama classifiers. Best-effort;
        # any cache failure falls through to a live call.
        outer_key: str | None = None
        inner_field: str | None = None
        hint_text: str | None = None
        try:
            from email_triage.cache.classification import (
                cache_lookup_for_message,
            )
            model_key = self._adapter.model or self._adapter.deployment
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
            model_key = self._adapter.model or self._adapter.deployment
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
