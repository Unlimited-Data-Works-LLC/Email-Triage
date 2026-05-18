"""Ollama LLM backend for email classification.

Uses the Ollama REST API (``/api/chat``) via httpx.  This is the default
backend — typical deployment runs a quantised mid-sized model (qwen, llama,
mistral) on a single-GPU LAN host.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from email_triage._http_client import LazyHttpClient
from email_triage.classify.base import Classifier
from email_triage.classify.prompts import build_system_prompt, build_user_prompt
from email_triage.engine.models import Classification, EmailMessage, ListHint

logger = logging.getLogger("email_triage.classify.ollama")


def _strip_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks from [local-llm-model]-style reasoning output.

    Three cases:

      * Balanced ``<think>...</think>`` blocks — stripped wholesale via
        the non-greedy regex.
      * Truncated mid-thinking — the response was cut before the
        model emitted ``</think>`` (Ollama ``done_reason: "length"``
        with an unclosed open tag). Without intervention the caller
        renders the raw "<think>reasoning..." text as if it were the
        answer. We drop everything from ``<think>`` onward as a last
        resort. The caller has already logged the truncation warning
        upstream; this just keeps the on-screen output clean.
      * No tags — passthrough.
    """
    import re
    # Balanced pairs first.
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Unclosed opening tag (truncation safety net).
    open_idx = cleaned.find("<think>")
    if open_idx != -1 and "</think>" not in cleaned[open_idx:]:
        cleaned = cleaned[:open_idx]
    return cleaned.strip()


def _parse_llm_json(text: str) -> dict[str, Any]:
    """Extract a JSON object from LLM output.

    Handles common quirks: [local-llm-model] <think> tags, markdown fences,
    trailing text after the object, leading whitespace.
    """
    # Strip thinking blocks first ([local-llm-model] wraps reasoning in <think> tags).
    cleaned = _strip_think_tags(text).strip()

    # Strip markdown code fences if present.
    if cleaned.startswith("```"):
        # Remove opening fence (```json or ```)
        first_newline = cleaned.index("\n")
        cleaned = cleaned[first_newline + 1:]
        if "```" in cleaned:
            cleaned = cleaned[:cleaned.rindex("```")]
        cleaned = cleaned.strip()

    # Find the first { and last } to extract the JSON object.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in LLM response: {text[:200]}")

    return json.loads(cleaned[start:end + 1])


_LOADED_CACHE_TTL_SECONDS = 30


class OllamaClassifier(Classifier):
    """Classify emails via the Ollama REST API.

    When ``prefer_loaded`` is True (default), each call probes
    ``/api/ps`` and uses whatever model is already resident in VRAM —
    falling back to the configured ``model`` when nothing is loaded.
    Prevents "configured model can't load because GPU is full of a
    different model" 500s in homelab setups, and absorbs version
    drift ([local-llm-model] → [local-llm-model]) without a config chase.

    The /api/ps result is cached for 30 s per instance so we don't
    add an HTTP round trip to every classification.
    """

    def __init__(
        self,
        model: str = "[local-llm-model]
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
        prefer_loaded: bool = True,
        local_url_suffixes: list[str] | None = None,
    ):
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._prefer_loaded = prefer_loaded
        self._loaded_cache: tuple[float, str | None] = (0.0, None)
        # Long-lived httpx client for /api/chat + /api/ps + /api/embeddings.
        # Per-call ``timeout=`` overrides on the probe path keep the
        # 5 s probe budget without standing up a second client (#139).
        self._http = LazyHttpClient(timeout=self._timeout)
        # Ollama is usable as local OR as a remote hosted service.
        # Classify the configured URL so HIPAA-sensitive actions can
        # fail-closed when pointed at a public endpoint. Operator-
        # defined "treat-as-local" suffixes come from
        # config.tls.local_url_suffixes; the source tree carries no
        # operator-specific suffix.
        from email_triage.classify.base import _is_local_host
        self.is_local = _is_local_host(
            self._base_url, extra_suffixes=tuple(local_url_suffixes or ()),
        )

    async def _resolve_model(self) -> str:
        """Return the model name to use for the next call.

        When ``prefer_loaded`` is False, always returns the configured
        model. Otherwise checks ``/api/ps`` (cached 30 s) and returns
        the first resident model it finds; falls back to configured
        model on any error or empty response.
        """
        if not self._prefer_loaded:
            return self._model

        now = time.monotonic()
        cached_at, cached_name = self._loaded_cache
        if cached_name is not None and (now - cached_at) < _LOADED_CACHE_TTL_SECONDS:
            return cached_name

        resolved = self._model
        try:
            client = await self._http.get()
            resp = await client.get(
                f"{self._base_url}/api/ps", timeout=5.0,
            )
            if resp.status_code == 200:
                models = (resp.json() or {}).get("models", [])
                if models:
                    # Pick the first loaded model. Ollama returns
                    # them in activity order; for a homelab with
                    # one GPU there's usually only one anyway.
                    name = models[0].get("name", "") or models[0].get("model", "")
                    if name:
                        resolved = name
                        if name != self._model:
                            logger.info(
                                "Ollama: using already-loaded model '%s' "
                                "instead of configured '%s'",
                                name, self._model,
                            )
        except Exception as e:
            # Probe is best-effort — any failure falls back to the
            # configured model and the /api/chat call itself will
            # surface a real error if there's a server problem.
            logger.debug("Ollama /api/ps probe failed: %s", e)

        self._loaded_cache = (now, resolved)
        return resolved

    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)

        model = await self._resolve_model()

        # 2026-05-13 two-level cache lookup. Returns:
        #   (outer_key, inner_field, cached_classification, hint_text)
        # - cached_classification non-None → Branch 1 (skip LLM, return cache)
        # - hint_text non-None → Branch 2 (prepend hint, run LLM)
        # - both None → cold miss (run LLM uninformed)
        outer_key: str | None = None
        inner_field: str | None = None
        cache_entry: Classification | None = None
        hint_text: str | None = None
        try:
            from email_triage.cache.classification import (
                cache_lookup_for_message,
            )
            outer_key, inner_field, cache_entry, hint_text = (
                cache_lookup_for_message(
                    message, model, categories,
                )
            )
            if cache_entry is not None:
                logger.info("Classification cache hit (cache_hit=True)")
            elif hint_text is not None:
                logger.info(
                    "Classification cache hint fired (cache_hit=False); "
                    "biasing LLM with sender history",
                )
        except Exception as e:
            logger.debug("Classification cache lookup error: %s", e)

        if cache_entry is not None:
            return cache_entry

        # Prepend the cache-history hint to the system prompt when
        # Branch 2 fired. Keeps the prompt builder (list_hints) path
        # untouched — hint is a literal pre-rendered sentence.
        if hint_text:
            system_prompt = (
                f"[SENDER HISTORY HINT] {hint_text}\n\n{system_prompt}"
            )

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "think": False,  # Disable thinking for [local-llm-model]+ models (Ollama API)
            "options": {
                "temperature": 0.3,
                "num_predict": 256,
            },
        }

        # #149 Bundle B — circuit breaker + typed-exception wrapping
        # layered on top of J's long-lived AsyncClient (#139).
        # Connect-class errors (Ollama down, network blip) trip the
        # breaker via ``set_unhealthy`` and re-raise as
        # ``LLMBackendUnreachableError`` so the watcher / push
        # consumer / poll loop can distinguish "infrastructure
        # weather" from a genuine classifier error.
        from email_triage.llm_health import (
            LLMBackendUnreachableError, set_unhealthy,
            is_unreachable_error, host_port_from_url,
        )
        try:
            client = await self._http.get()
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
        except Exception as exc:
            if is_unreachable_error(exc):
                host, port = host_port_from_url(
                    self._base_url, default_port=11434,
                )
                set_unhealthy(
                    "ollama", ttl_seconds=300, reason=str(exc)[:200],
                )
                raise LLMBackendUnreachableError(
                    "ollama", host, port, original=exc,
                ) from exc
            raise

        body = resp.json()
        raw_text = body.get("message", {}).get("content", "")
        logger.debug("Ollama raw response", extra={"raw": raw_text[:500]})

        parsed = _parse_llm_json(raw_text)

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

        # 2026-05-13 — best-effort store via two-level shape.
        # ``is_hipaa`` strips the ``reason`` field at store time so
        # HIPAA-flagged accounts can cache safely (category + confidence
        # are non-PHI). No-ops on (None, None) outer/inner pair.
        try:
            from email_triage.cache.classification import (
                cache_store_for_message,
            )
            cache_store_for_message(
                outer_key, inner_field, model, result, categories,
                is_hipaa=bool(getattr(message, "hipaa", False)),
            )
        except Exception as e:
            logger.debug("Classification cache store error: %s", e)

        return result

    async def complete(self, prompt: str) -> str:
        """Raw text completion via Ollama /api/chat.

        ``num_predict`` ceiling is generous (8192) because the
        ``think: False`` flag is template-dependent — [local-llm-model] stock
        templates emit ``<think>...</think>`` reasoning regardless,
        and that reasoning bites into the same generation budget the
        actual answer needs. With a tight 2048-token cap the
        explain-this-error path (#121-A) was hitting truncation in
        production: the screenshot operator caught on 2026-05-12
        showed an explanation cut mid-word at "provider's serve"
        — Ollama returned ``done_reason: "length"`` and the post-
        ``</think>`` content was already eating most of the budget.
        8192 is plenty for a 4-6 sentence explanation plus whatever
        chain-of-thought leaks; the upper bound matters only when
        the backend would otherwise truncate.
        """
        model = await self._resolve_model()
        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 8192,
            },
        }

        # #149 + #139 — circuit breaker layered on long-lived client.
        from email_triage.llm_health import (
            LLMBackendUnreachableError, set_unhealthy,
            is_unreachable_error, host_port_from_url,
        )
        try:
            client = await self._http.get()
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
        except Exception as exc:
            if is_unreachable_error(exc):
                host, port = host_port_from_url(
                    self._base_url, default_port=11434,
                )
                set_unhealthy(
                    "ollama", ttl_seconds=300, reason=str(exc)[:200],
                )
                raise LLMBackendUnreachableError(
                    "ollama", host, port, original=exc,
                ) from exc
            raise

        body = resp.json()
        raw_text = body.get("message", {}).get("content", "")
        done_reason = body.get("done_reason") or ""
        if done_reason and done_reason != "stop":
            # ``length`` = hit num_predict before EOS; ``load`` /
            # ``unload`` = model swap mid-call. Either way the
            # caller should know the answer is incomplete so they
            # can decide between bumping the cap and falling back.
            logger.warning(
                "Ollama complete() did not finish cleanly",
                extra={"_extra": {
                    "done_reason": done_reason,
                    "model": model,
                    "raw_len": len(raw_text),
                }},
            )
        # Strip [local-llm-model] thinking tags if present.
        return _strip_think_tags(raw_text).strip()

    async def close(self) -> None:
        """Drain the long-lived httpx client. Idempotent."""
        await self._http.aclose()
