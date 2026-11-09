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
OpenAI-compat, embedding-backend). The ``openai`` SDK is not a
dependency of this project (its ``openai`` extra was removed in punch
489, 2026-10-18); nothing imports it. Mirror that pattern for
portability + to keep the cold-import surface small.

api-version choice — 2024-10-21
-------------------------------
``2024-10-21`` is the current ``api-version=current`` GA stable for the
``/chat/completions`` surface as of 2026-05 (Azure's recommended-stable
rolls forward roughly each quarter). Picks structured-output (json_schema)
support up so  phases 3-4 can plumb the describe-and-discard schema
through. Operators can override via the ``ai_backends`` row.

Privacy
-------
The adapter never logs the api_key, never round-trips it through
templates, and scrubs token-shape keys out of any error body before
incorporating it into the exception message ( hardening pattern,
mirroring ``GmailApiError``).
"""

from __future__ import annotations

import json
import logging
from typing import Any
from email_triage._secret_scrub import strip_url_query_secrets as _strip_sensitive_query_params

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.classify.base import JsonChatClassifier

logger = get_logger("email_triage.ai_backends.azure_openai")  # N-196b R21_4

# Default api-version. Operator can override via the ``ai_backends``
# row; this constant is the "what shipped when this adapter was
# authored" value, used when the caller passes ``api_version=None``.
# 2024-10-21 is the GA stable as of 2026-05 — includes structured
# response_format=json_schema support, which  phases 3-4 needs.
DEFAULT_API_VERSION = "2024-10-21"

# Conservative default request timeout. Azure latency P99 is typically
# under 30 s for short prompts; 120 s mirrors the Ollama / OpenAI-compat
# default and absorbs the occasional cold start on a deployment that
# scales-from-zero.
DEFAULT_TIMEOUT = 120.0


class AzureOpenAIError(Exception):
    """Raised when an Azure OpenAI API call returns an error.

    Defensive token-shape scrub at construction time (mirrors the
    ``GmailApiError`` hardening from commit ``2de45ea`` / ). The
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


from email_triage.ai_backends.base import BackendAdapter, meter_chat_complete


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
        #  — one long-lived pooled httpx client per adapter
        # instance, reused across every chat_complete() call instead of
        # a fresh AsyncClient (TLS handshake) per call. Mirrors the
        # classify/* cloud classifiers and OllamaClassifier.
        self._http = LazyHttpClient(intent=Intent.LLM_PHI, timeout=timeout)

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

        #  — wrap the POST in the shared circuit-breaker helper, the
        # same translation  added to classify/openai_compat.py. A
        # dead Azure endpoint (connection refused / network blip) now
        # trips the breaker and re-raises a typed
        # LLMBackendUnreachableError instead of a raw httpx.ConnectError.
        #
        # Breaker key — deliberately "openai", NOT "azure_openai":
        # the is_healthy gate resolves config.classifier.backend, which
        # only ever yields "ollama"/"openai"/"gemini" (see
        # _build_classifier_from_config). An Azure install configures
        # classifier.backend = "openai" because Azure speaks the OpenAI
        # chat-completions API; an "azure_openai" key would trip a
        # breaker the gate can never see, so a tripped Azure breaker
        # would be silently ignored. Keying "openai" keeps the breaker
        # visible to the gate. Mirrors classify/openai_compat.py, which
        # also keys "openai" for Azure-via-OpenAI-compat traffic.
        #
        # A 4xx/5xx is NOT a connect failure, so the status check below
        # stays OUTSIDE the wrapper: those mean the backend is up but
        # misbehaving and must not flip the breaker.
        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "openai", self._endpoint, default_port=443,
        ):
            client = await self._http.get()
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
        #  silent-truncation guard (shared SSOT).
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


class AzureOpenAIClassifier(JsonChatClassifier):
    """:class:`JsonChatClassifier` subclass wrapping :class:`AzureOpenAIAdapter`.

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

    Azure is always external — Microsoft's hosted endpoint — so
    :attr:`is_local` stays False; the BAA gate elsewhere opens the
    door for HIPAA traffic once a signed BAA is on file.
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
        # ``_model`` is the classification-cache key the shared base
        # passes to the cache + to :meth:`_chat`. Azure ignores the
        # request-body model (the deployment selects it), so the cache
        # key falls back to the deployment name — matching the
        # pre-refactor ``model_key = self._adapter.model or
        # self._adapter.deployment`` behaviour.
        self._model = self._adapter.model or self._adapter.deployment

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue one chat request via the W1-A adapter; return raw text.

        ``model`` is the cache key from :meth:`_resolve_model`; the
        adapter routes to its configured Azure deployment, so the
        cache key never reaches the endpoint.
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
