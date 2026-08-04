"""Google Gemini adapter.

Sibling to :class:`email_triage.ai_backends.azure_openai.AzureOpenAIAdapter`
and :class:`email_triage.ai_backends.openai_direct.OpenAIAdapter`. Talks
the Google REST ``generateContent`` surface — same endpoint shape that
the pre-existing :class:`email_triage.classify.gemini.GeminiClassifier`
uses, but exposed via the W1-A :class:`BackendAdapter` canonical contract
(``chat_complete(messages, *, response_format, max_tokens, **kwargs)``).

Why a free-standing class
-------------------------
:class:`GeminiClassifier` shapes the prompt internally and returns a
:class:`Classification`. The W1-A ABC sits one layer lower — caller
supplies the assembled messages, adapter does the HTTP plumbing + the
OpenAI-style → Gemini-style ``contents``/``systemInstruction``
translation, returns a string.

This module mirrors the canonical pattern set by
``ai_backends/azure_openai.py``:

* :class:`GeminiAdapter` — :class:`BackendAdapter` subclass with
  ``chat_complete``.
* :class:`GeminiClassifierShim` — :class:`Classifier`-ABC shim that
  composes :class:`GeminiAdapter`, so the existing classifier path
  can use the adapter without waiting for :func:`load_backend`
  migration.
* :class:`GeminiError` + :class:`GeminiAuthError` — error classes
  with defensive :data:`_TOKEN_KEYS` body-scrub at construction time.

File name
---------
``gemini_adapter.py`` rather than ``gemini.py`` — keeps parallel naming
with ``azure_openai.py`` / ``openai_direct.py`` / ``ollama_adapter.py``,
and avoids shadowing the existing classifier module
``classify/gemini.py`` in tooling that does prefix matching.

Endpoint
--------
Google AI Studio + Vertex AI both expose ``/v1beta/models/{model}:generateContent``.
Default endpoint is ``https://generativelanguage.googleapis.com/v1beta``
(Google AI Studio); operators on Vertex override via the
``ai_backends.endpoint`` column.

Privacy
-------
Gemini's auth is via the ``?key=…`` query parameter (not a header).
The adapter never logs the api_key, never round-trips it through
templates, and scrubs token-shape keys out of any error body before
incorporating it into the exception message. Belt-and-suspenders:
the api-key query param is stripped from URLs in rendered exception
messages too.
"""

from __future__ import annotations

import logging
from typing import Any
from email_triage._secret_scrub import strip_url_query_secrets as _strip_sensitive_query_params

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.classify.base import JsonChatClassifier

logger = get_logger("email_triage.ai_backends.gemini_adapter")  # N-196b R21_4

# Default Gemini AI Studio endpoint. Operators on Vertex AI override
# via the ``ai_backends.endpoint`` column to the project-scoped Vertex
# REST URL.
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

# Default model. ``gemini-2.0-flash`` is the cost/quality sweet-spot
# for short classification prompts as of 2026-05; operators picking a
# different tier (``gemini-2.5-pro``, ``gemini-2.5-flash``, etc.)
# override via the row.
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"

# Conservative default request timeout. Mirrors the Azure + OpenAI +
# Ollama defaults (120 s).
DEFAULT_TIMEOUT = 120.0


class GeminiError(Exception):
    """Raised when a Gemini API call returns an error.

    Defensive token-shape scrub at construction time. Mirrors the
    :class:`AzureOpenAIError` / :class:`OpenAIError` pattern, which in
    turn mirrors :class:`GmailApiError` from commit ``2de45ea`` / .
    The fallback ``str(body)`` path is reachable when an upstream
    proxy injects a non-Gemini response or when Google's edge returns
    a token-bearing error body — in either case, if a token-bearing
    field ever lands in the response dict, plaintext leakage through
    the exception message (and from there, through every log handler
    that captures ``exc_info``) is the worst-case outcome. Scrub
    before stringifying so the leak surface is closed at the earliest
    point.

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
                # Gemini's REST error shape:
                #   {"error": {"code": 400, "message": "...",
                #              "status": "INVALID_ARGUMENT"}}
                msg = err.get("message", str(safe_body))
            else:
                msg = body.get("error_description") or str(err) or str(safe_body)
        else:
            msg = str(body)
        # Strip sensitive query params if any leaked into the URL.
        # Gemini's auth is via ``?key=…`` so this is NOT defence-in-
        # depth here — it actively protects every real call. Apply
        # before stringifying so the rendered exception never carries
        # the plaintext.
        clean_url = _strip_sensitive_query_params(url) if url else url
        super().__init__(f"Gemini {status}: {msg} ({clean_url})")


class GeminiAuthError(GeminiError):
    """Raised when Gemini rejects the api_key (401 / 403).

    Google AI Studio actually returns 400 INVALID_ARGUMENT with
    "API key not valid" for a bad key (the auth model is per-key,
    not per-token) — but Vertex AI uses 401/403 for IAM violations.
    Cover both paths by checking the status code in
    :meth:`GeminiAdapter.chat_complete`.
    """


from email_triage.ai_backends.base import BackendAdapter, meter_chat_complete


class GeminiAdapter(BackendAdapter):
    """W1-A :class:`BackendAdapter` over Google Gemini ``generateContent``.

    Targets Google AI Studio (default) + Vertex AI (via custom
    endpoint). Gemini is always external — Google's hosted endpoint,
    even in Workspace + BAA tenants — so :attr:`is_local` stays
    False; the BAA gate elsewhere in the codebase opens the door for
    HIPAA traffic once a signed BAA is on file. Same posture as Azure.

    Parameters
    ----------
    endpoint:
        Gemini REST base, e.g.
        ``https://generativelanguage.googleapis.com/v1beta`` (Google AI
        Studio) or the project-scoped Vertex AI URL. Defaults to
        :data:`DEFAULT_GEMINI_BASE_URL`. Trailing slash optional; the
        constructor normalises.
    api_key:
        Google AI Studio API key (or Vertex AI access token, depending
        on the endpoint). Fetched from the secrets store at adapter
        construction time by the loader. Never logged, never round-
        tripped through templates.
    model:
        Gemini model name (e.g. ``gemini-2.0-flash``, ``gemini-2.5-pro``).
        Defaults to :data:`DEFAULT_GEMINI_MODEL`.
    default_temperature, default_max_tokens:
        Per-call defaults; individual ``chat_complete`` calls override.
    timeout:
        Request timeout in seconds.
    """

    # Same HIPAA posture as Azure — always external; the BAA gate
    # elsewhere opens the door for HIPAA traffic once a signed BAA
    # is on file. ``is_local`` stays False at every install.
    is_local: bool = False

    backend_type = "gemini"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
        local_url_suffixes: list[str] | None = None,  # noqa: ARG002 — accepted for uniform loader signature
        **_: Any,
    ) -> None:
        # Empty endpoint falls through to the public Google AI Studio
        # default — makes the loader path forgiving (an ``ai_backends``
        # row with NULL ``endpoint`` for the Google AI Studio service
        # is reasonable).
        self._endpoint = (endpoint or DEFAULT_GEMINI_BASE_URL).rstrip("/")
        # api_key may legitimately be empty during config validation —
        # the loader catches the empty case and raises at construction
        # time, but for a unit-test path we allow construction and
        # fail at first HTTP call.
        self._api_key = api_key or ""
        self._model = model or DEFAULT_GEMINI_MODEL
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
        response_format: dict[str, Any] | str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        **kwargs: Any,
    ) -> str:
        """Run a Gemini ``generateContent`` request. Canonical adapter entry.

        Internally translates the OpenAI-style messages list into
        Gemini's ``contents`` / ``systemInstruction`` shape (see
        :func:`_messages_to_gemini_contents`). System messages collapse
        into the single ``systemInstruction`` field; user/assistant
        turns go into ``contents`` with ``role=user``/``role=model``.

        Parameters
        ----------
        messages:
            OpenAI-style chat messages:
            ``[{"role": ..., "content": ...}, ...]``. Must be non-empty;
            passing an empty list raises :class:`ValueError` BEFORE
            any HTTP call.
        response_format:
            Two portable values:

            * ``None`` — free-form text (default)
            * ``"json"`` or a dict with ``{"type": "json_object"}`` —
              sets ``generationConfig.responseMimeType =
              "application/json"`` (Gemini's structured-output knob).
            * a dict with ``{"type": "json_schema", "json_schema":
              {"schema": ...}}`` — Gemini accepts response schemas via
              ``generationConfig.responseSchema``; the adapter unwraps
              the OpenAI shape and forwards the inner schema.
        max_tokens:
            Per-call override for ``maxOutputTokens``. Defaults to
            :attr:`_default_max_tokens` when omitted.
        temperature:
            Per-call override.
        **kwargs:
            Additional Gemini ``generationConfig`` entries (``topP``,
            ``topK``, ``stopSequences``, etc.). Pass-through under the
            ``generationConfig`` key.

        Returns
        -------
        str
            The model's reply text (``candidates[0].content.parts[0].text``).
            When ``response_format`` requested JSON, the returned string
            is valid JSON per Gemini's guarantee; callers parse via
            ``json.loads`` (the adapter does NOT parse — keeping
            structured-vs-text behaviour transparent to the W1-A loader).

        Raises
        ------
        ValueError
            ``messages`` is empty, or ``api_key`` is empty at call time.
        GeminiAuthError
            Gemini returned 401 / 403, or a 400 with "API key not
            valid" (Google AI Studio's auth-failure shape).
        GeminiError
            Any other 4xx / 5xx, or a 2xx with no usable content.
        """
        if not messages:
            raise ValueError(
                "chat_complete() requires at least one message; "
                "empty messages list is a caller bug — Gemini would 400 "
                "the request and we'd burn a round-trip"
            )
        if not self._api_key:
            raise ValueError(
                "Gemini api_key is empty — the loader should have "
                "raised at construction; refusing to make an "
                "unauthenticated call to a hosted service"
            )

        url = f"{self._endpoint}/models/{self._model}:generateContent"
        params = {"key": self._api_key}
        headers = {"Content-Type": "application/json"}

        system_instruction, contents = _messages_to_gemini_contents(messages)

        generation_config: dict[str, Any] = {
            "temperature": (
                temperature
                if temperature is not None
                else self._default_temperature
            ),
            "maxOutputTokens": (
                max_tokens
                if max_tokens is not None
                else self._default_max_tokens
            ),
        }
        # Translate response_format to Gemini's generationConfig knobs.
        if response_format is not None:
            self._apply_response_format(generation_config, response_format)
        # Pass-through additional generationConfig fields (topP, topK,
        # stopSequences). Filter out keys we already set so kwargs
        # cannot clobber the validated config.
        for k, v in kwargs.items():
            if k in generation_config:
                continue
            generation_config[k] = v

        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": generation_config,
        }
        if system_instruction is not None:
            body["systemInstruction"] = system_instruction

        #  — wrap the POST in the shared circuit-breaker helper, the
        # same translation  added to classify/gemini.py. A dead
        # Gemini endpoint (connection refused / network blip) now trips
        # the breaker and re-raises a typed LLMBackendUnreachableError
        # instead of a raw httpx.ConnectError. Keyed "gemini" to match
        # the configured classifier.backend the is_healthy gate resolves
        # ("ollama"/"openai"/"gemini") — a key the gate never sees can
        # never gate. A 4xx/5xx is NOT a connect failure, so the status
        # check below stays OUTSIDE the wrapper: those mean the backend
        # is up but misbehaving and must not flip the breaker.
        from email_triage.llm_health import translate_unreachable
        with translate_unreachable(
            "gemini", self._endpoint, default_port=443,
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
            # Google AI Studio returns 400 with status="INVALID_ARGUMENT"
            # and message containing "API key not valid" for bad keys;
            # Vertex AI uses 401/403 for IAM violations. Treat both as
            # auth errors so the caller can distinguish wiring problems
            # from transient failures.
            is_auth = resp.status_code in (401, 403)
            if not is_auth and isinstance(err_body, dict):
                msg = (
                    err_body.get("error", {}).get("message", "")
                    if isinstance(err_body.get("error"), dict)
                    else ""
                )
                if "API key not valid" in msg or "API_KEY_INVALID" in msg:
                    is_auth = True
            if is_auth:
                raise GeminiAuthError(resp.status_code, err_body, url)
            raise GeminiError(resp.status_code, err_body, url)

        try:
            payload = resp.json()
        except Exception as e:
            raise GeminiError(
                resp.status_code,
                f"Non-JSON response body: {e}",
                url,
            ) from e

        #  silent-truncation guard (shared SSOT) — finishReason==MAX_TOKENS
        # means a cut response (invalid JSON for a classify, mid-word for text).
        from email_triage.llm_truncation import warn_if_llm_truncated
        warn_if_llm_truncated(
            payload, family="gemini", model=str(getattr(self, "_model", "") or ""),
            context="chat_complete", logger=logger,
        )
        text = _extract_gemini_text(payload)
        if not text:
            # 2xx with no candidate text is most commonly a safety-
            # filter trip on Gemini (``promptFeedback.blockReason``).
            # Surface as an error so the caller doesn't silently get
            # an empty classification.
            raise GeminiError(
                resp.status_code,
                payload,
                url,
            )
        return text

    @staticmethod
    def _apply_response_format(
        generation_config: dict[str, Any],
        response_format: dict[str, Any] | str,
    ) -> None:
        """Translate a portable response_format into Gemini's knobs.

        Mutates ``generation_config`` in place.
        """
        if response_format == "json":
            generation_config["responseMimeType"] = "application/json"
            return
        if not isinstance(response_format, dict):
            return
        type_ = response_format.get("type")
        if type_ == "json_object":
            generation_config["responseMimeType"] = "application/json"
        elif type_ == "json_schema":
            generation_config["responseMimeType"] = "application/json"
            # OpenAI-style json_schema nests under
            # ``json_schema.schema``; Gemini accepts a bare schema via
            # ``responseSchema``. Unwrap when possible; otherwise pass
            # the value through (operator may have supplied a raw
            # Gemini schema).
            inner = response_format.get("json_schema") or {}
            schema = inner.get("schema") if isinstance(inner, dict) else None
            if schema is not None:
                generation_config["responseSchema"] = schema
        # Any other shape: caller knows what they want, pass-through
        # the raw value under responseMimeType+responseSchema keys if
        # they look like Gemini-native shapes.
        elif "responseSchema" in response_format:
            generation_config["responseSchema"] = response_format["responseSchema"]
            if "responseMimeType" in response_format:
                generation_config["responseMimeType"] = (
                    response_format["responseMimeType"]
                )

    # ------------------------------------------------------------------
    # Compatibility aliases — let the W1-A loader and the existing
    # classifier path both dispatch by name they each prefer.
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


def _messages_to_gemini_contents(
    messages: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Translate OpenAI-style messages into Gemini's ``contents`` +
    ``systemInstruction`` shape.

    Returns
    -------
    ``(system_instruction_or_none, contents_list)``

    Mapping rules:
      * ``role=system`` → folded into ``systemInstruction``. Multiple
        system turns concatenate with double-newline separators (rare
        in practice; the classifier path uses one system message).
      * ``role=user`` → ``{"role": "user", "parts": [{"text": ...}]}``
      * ``role=assistant`` → ``{"role": "model", "parts":
        [{"text": ...}]}`` (Gemini calls this role "model", not
        "assistant").
      * unknown roles → treated as user (defensive; existing classifier
        paths never produce these).
      * empty-content messages → skipped (they would only confuse the
        model).
    """
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for m in messages:
        role = (m.get("role") or "").strip().lower()
        content = m.get("content") or ""
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
        elif role == "assistant":
            contents.append({
                "role": "model",
                "parts": [{"text": content}],
            })
        else:
            # user or unknown
            contents.append({
                "role": "user",
                "parts": [{"text": content}],
            })

    system_instruction: dict[str, Any] | None
    if system_parts:
        system_instruction = {
            "parts": [{"text": "\n\n".join(system_parts)}],
        }
    else:
        system_instruction = None

    return system_instruction, contents


def _extract_gemini_text(body: dict[str, Any]) -> str:
    """Extract the assistant text from a Gemini generateContent response.

    Defensive: every step in the chain can be missing on a safety-
    filter trip or a malformed response; treat each as "no text",
    return empty string so the caller can decide how to handle it.

    Mirrors :meth:`email_triage.classify.gemini.GeminiClassifier._extract_text`.
    """
    candidates = body.get("candidates", [])
    if not candidates:
        return ""
    content = candidates[0].get("content", {})
    parts = content.get("parts", [])
    if not parts:
        return ""
    return parts[0].get("text", "") or ""


# ---------------------------------------------------------------------------
# Classifier-ABC shim — bridges GeminiAdapter to the existing
# classify/flow path. Keep it close to the adapter so callers find both
# in one module; the import surface is :mod:`email_triage.ai_backends`.
# ---------------------------------------------------------------------------


class GeminiClassifierShim(JsonChatClassifier):
    """:class:`JsonChatClassifier` subclass wrapping :class:`GeminiAdapter`.

    Suffix ``Shim`` to disambiguate from the pre-existing
    :class:`email_triage.classify.gemini.GeminiClassifier`, which is
    the legacy ABC-direct subclass.

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

    # Mirrors :attr:`GeminiAdapter.is_local` — Gemini is always
    # external; the BAA gate opens HIPAA traffic once a BAA is on file.
    is_local: bool = False

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        default_temperature: float = 0.3,
        default_max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self._adapter = GeminiAdapter(
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            default_temperature=default_temperature,
            default_max_tokens=default_max_tokens,
            timeout=timeout,
        )
        # ``_model`` is the classification-cache key the shared base
        # passes to the cache + to :meth:`_chat`. GeminiAdapter always
        # carries a non-empty model (defaults to DEFAULT_GEMINI_MODEL).
        self._model = self._adapter.model

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue one chat request via the W1-A adapter; return raw text.

        ``model`` is the cache key from :meth:`_resolve_model`; the
        adapter interpolates its own configured model into the
        ``generateContent`` endpoint path.
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
