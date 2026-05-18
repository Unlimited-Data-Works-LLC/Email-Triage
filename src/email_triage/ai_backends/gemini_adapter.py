"""Google Gemini adapter (#171-A).

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
  with defensive :data:`_TOKEN_KEYS` body-scrub at construction time
  (#168 hardening, identical pattern to :class:`AzureOpenAIError`).

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
messages too (#168 hardening pattern + :func:`_strip_sensitive_query_params`).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("email_triage.ai_backends.gemini_adapter")

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
    turn mirrors :class:`GmailApiError` from commit ``2de45ea`` / #168.
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


def _strip_sensitive_query_params(url: str) -> str:
    """Remove ``key`` / ``api-key`` / ``token`` / ``access_token`` /
    ``code`` query params from URL.

    For Gemini this is NOT defence-in-depth — Gemini's auth IS the
    ``?key=…`` query parameter, so every real call carries the
    plaintext key in the URL. Applying the scrub to URL strings used
    in rendered exception messages (and in any log line that captures
    the URL) is the primary safeguard against the key leaking via
    exception traces.
    """
    if not url or "?" not in url:
        return url
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    sensitive = {"key", "api-key", "token", "access_token", "code"}
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

    # ------------------------------------------------------------------
    # Canonical W1-A method
    # ------------------------------------------------------------------

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

        async with httpx.AsyncClient(timeout=self._timeout) as client:
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


def _build_gemini_classifier_imports():
    """Local import helper (lazy — keeps ai_backends import cheap)."""
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


class GeminiClassifierShim:
    """:class:`Classifier`-ABC-compatible wrapper around :class:`GeminiAdapter`.

    Suffix ``Shim`` to disambiguate from the pre-existing
    :class:`email_triage.classify.gemini.GeminiClassifier`, which is
    the legacy ABC-direct subclass. The W1-A pattern wraps the adapter
    rather than re-implementing HTTP — same prompt builders + same
    response parser as the existing classifier, but the HTTP-call seam
    routes through the adapter.

    The class is built without inheriting from :class:`Classifier`
    because the ABC + prompt helpers are imported lazily (see
    :func:`_build_gemini_classifier_imports`). This costs one extra
    method call but keeps ``import email_triage.ai_backends`` cheap.
    """

    # Mirrors :attr:`GeminiAdapter.is_local`.
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

    async def classify(self, message, categories, list_hints=None):
        # Lazy import — keeps cold-import path light.
        (
            _Classifier, _parse_llm_json, build_system_prompt,
            build_user_prompt, Classification, _EmailMessage, _ListHint,
        ) = _build_gemini_classifier_imports()

        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

        # 2026-05-13 two-level cache lookup. Best-effort; any cache
        # failure falls through to a live call.
        outer_key: str | None = None
        inner_field: str | None = None
        hint_text: str | None = None
        try:
            from email_triage.cache.classification import (
                cache_lookup_for_message,
            )
            outer_key, inner_field, cache_entry, hint_text = (
                cache_lookup_for_message(
                    message, self._adapter.model, categories,
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
            cache_store_for_message(
                outer_key, inner_field,
                self._adapter.model, result, categories,
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
