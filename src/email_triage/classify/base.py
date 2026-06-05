"""Abstract classifier interface for email triage.

All LLM backends implement this interface so the flow engine can classify
emails without knowing which backend is in use.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from email_triage.engine.models import Classification, EmailMessage, ListHint

#  sites 3/4 — hoisted from function-local to module-level. DA-verified
# 2026-05-28 these are NOT cycle-locked: cache/classification.py imports zero
# email_triage.classify modules (only engine.persistent_counters at module
# top + a late Classification type inside a function body), so there is no
# import cycle to break. The function-local form was historical, not
# load-bearing. (Sites 1+2 — _parse_llm_json + prompts at classify() body —
# STAY local: classify/ollama.py imports JsonChatClassifier from this module
# = a real A<->B cycle.)
from email_triage.cache.classification import (
    acache_lookup_for_message,
    acache_store_for_message,
)

logger = logging.getLogger("email_triage.classify")


def _is_local_host(
    url: str, *, extra_suffixes: list[str] | tuple[str, ...] = (),
) -> bool:
    """Return True if ``url`` points to a local-only destination.

    Used by the HIPAA safety gate: external LLM endpoints must not
    receive PHI unless a Business Associate Agreement is in place
    (enforced elsewhere).

    Always-on signals (no config needed):
      * localhost / 127.0.0.1 / ::1
      * RFC1918 private IPv4 (10/8, 172.16/12, 192.168/16)
      * .local mDNS suffix

    Operator-extensible: ``extra_suffixes`` adds operator-defined
    "treat-as-local" hostname suffixes (e.g. ``.home.lan``,
    ``.internal.example``). Sourced from
    ``config.tls.local_url_suffixes``; the source tree carries no
    operator-specific suffix.
    """
    if not url:
        return False
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith(".local"):
        return True
    for suffix in extra_suffixes:
        s = (suffix or "").lower().strip()
        if s and host.endswith(s):
            return True
    # RFC1918 private IPv4.
    if host.startswith("10.") or host.startswith("192.168."):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


class Classifier(ABC):
    """Classify an email message into a triage category."""

    # Subclasses set this to True when their endpoint is local-only.
    # Used by actions that must fail-closed on HIPAA content when the
    # configured classifier is external (pre-BAA-gate).
    is_local: bool = False

    @abstractmethod
    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        """Classify a single email.

        Parameters
        ----------
        message:
            The normalised email to classify.
        categories:
            Mapping of category slug to human description.  The LLM prompt
            is built dynamically from this dict.
        list_hints:
            Optional hints from user/global classification lists.  These are
            injected into the prompt as context, **not** hard overrides
            (unless the hint has ``skip_ai=True``).

        Returns
        -------
        Classification with category, confidence, reason, and source.
        """

    async def complete(self, prompt: str) -> str:
        """Raw text completion for non-classification tasks.

        Used by the digest generator to extract articles from newsletters,
        and by any other feature needing free-form LLM output.

        The default raises ``NotImplementedError``.  Backends that support
        raw completion (Ollama, OpenAI, Gemini) override this.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support raw completion")


class JsonChatClassifier(Classifier):
    """Template-method base for the HTTP chat-completion classifiers.

    The Ollama, OpenAI-compatible and Gemini backends shared a verbatim
    ~50-line :meth:`classify` body — build the prompt, run the two-level
    classification-cache lookup, prepend the sender-history hint, parse
    the JSON the model returns into a :class:`Classification`, then store
    the result back to the cache. Only the request itself (payload shape,
    endpoint, headers, transport-error handling) differed per backend.
    That body now lives here once; subclasses implement two hooks:

    * :meth:`_resolve_model` — the model name for this call. It is BOTH
      the classification-cache key and the value handed to :meth:`_chat`.
      The default returns ``self._model``; Ollama overrides it for
      prefer-loaded (resident-model) resolution.
    * :meth:`_chat` — issue one chat request and return the raw model
      text. The subclass owns the payload, endpoint, headers and any
      transport-error wrapping (e.g. Ollama's circuit breaker raising
      ``LLMBackendUnreachableError`` — which MUST propagate to the
      watcher / push / poll callers, so :meth:`classify` never catches
      around :meth:`_chat`).

    Subclasses set ``self._model`` in ``__init__``.
    """

    #: Configured model name; subclasses set this in __init__.
    _model: str = ""

    async def _resolve_model(self) -> str:
        """Return the model name for the next call (cache key + request).

        Default: the configured model. Ollama overrides this to probe
        ``/api/ps`` and prefer whatever model is already resident.
        """
        return self._model

    @abstractmethod
    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue one chat request; return the raw (unparsed) model text.

        ``model`` is the value :meth:`_resolve_model` produced. The
        subclass owns the endpoint, headers, payload shape and any
        transport-error translation.
        """

    async def classify(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None = None,
    ) -> Classification:
        from email_triage.classify.ollama import _parse_llm_json
        from email_triage.classify.prompts import (
            build_system_prompt, build_user_prompt,
        )

        system_prompt = build_system_prompt(categories, list_hints)
        user_prompt = build_user_prompt(message)
        model = await self._resolve_model()

        # Two-level classification-cache lookup. cache_entry non-None →
        # return it, skip the LLM (Branch 1). hint_text non-None → a
        # cold inner miss carrying sender history; prepend it to bias
        # the LLM (Branch 2). Both None → uninformed cold miss.
        outer_key: str | None = None
        inner_field: str | None = None
        cache_entry: Classification | None = None
        hint_text: str | None = None
        try:
            #  — async helper dispatches Redis calls off the event
            # loop. The sync `cache_lookup_for_message` is still
            # available for non-async callers (admin tooling, tests).
            # Import hoisted to module level.
            outer_key, inner_field, cache_entry, hint_text = (
                await acache_lookup_for_message(
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

        if hint_text:
            system_prompt = (
                f"[SENDER HISTORY HINT] {hint_text}\n\n{system_prompt}"
            )

        raw_text = await self._chat(system_prompt, user_prompt, model)
        logger.debug("LLM raw response", extra={"raw": raw_text[:500]})

        parsed = _parse_llm_json(raw_text)
        category = parsed.get("category", "")
        if category not in categories:
            #  — an unknown / empty category is a classification
            # FAILURE, not a low-confidence valid result. A
            # Classification carrying a category no route matches would
            # silently no-op the message — no actions, no error
            # surfaced. Raise instead so the caller's per-message error
            # path (retry queue → terminal-failure ERROR log) makes the
            # miss visible. Consistent with the ValueError that
            # _parse_llm_json already raises on unparseable output.
            raise ValueError(
                f"LLM returned a category outside the taxonomy: "
                f"{category!r}"
            )
        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
        result = Classification(
            category=category,
            confidence=confidence,
            reason=parsed.get("reason", ""),
            source="llm",
        )

        # Best-effort two-level store; the HIPAA reason-strip happens
        # inside the helper. No-ops on a (None, None) key pair. 
        # — dispatched off the event loop via the async helper so a
        # stuck Redis can't pin the loop on socket_timeout (2.0s).
        try:
            # acache_store_for_message hoisted to module level.
            await acache_store_for_message(
                outer_key, inner_field, model, result, categories,
                is_hipaa=bool(getattr(message, "hipaa", False)),
            )
        except Exception as e:
            logger.debug("Classification cache store error: %s", e)

        return result
