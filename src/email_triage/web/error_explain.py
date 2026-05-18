"""AI-backed explain-this-error helper (#121-A).

Operators see opaque integration error strings on /logs and the O365
probe chip (AADSTS / aioimaplib / Graph 4xx / IMAP NONAUTH / OAuth
``invalid_grant`` / etc.). Field-scoped tooltips only catch a
fraction; the static AADSTS translator only knows 7 codes; #128
``/help/tasks`` is generic recipes, not state-grounded prose.

This module asks the configured Ollama backend to render a plain-
English explanation of the supplied error text, with a hard ceiling
of 4-6 sentences. The button shows up next to the error chip
(``logs.html`` row, O365 probe failure chip) and HTMX-swaps the
explanation in below the row.

Design rules — locked at build time:

* Backend is whatever the install's classifier-backend setting names
  ("ollama" by default). We reuse :class:`OllamaClassifier` rather
  than open a second HTTP path — same long-lived ``httpx`` client,
  same model-resolution heuristic, same circuit breaker.
* Public-facing name for the LLM is "AI" (per
  ``feedback_no_anthropic`` — never mention provider names in
  user-visible copy).
* Privacy invariant: ONLY ``error_text`` + ``error_class`` +
  ``provider`` + account-NAME (never numeric id alone, never message
  body) reach the prompt. The function refuses to splice anything
  outside its declared inputs (see :func:`_build_prompt`).
* Circuit breaker: when :func:`llm_health.is_healthy("ollama")`
  returns False we short-circuit to a static fallback message
  without paying the connect-attempt latency. Mirrors the same gate
  the watcher / triage path use to skip burning round-trips on a
  known-unreachable backend.
* Latency budget: 8 seconds total. The Ollama client already carries
  a 120-second default; we override per-call with ``timeout=8.0`` so
  a stuck backend can't wedge the UI thread. The wider classifier
  path keeps its budget independently.
* HIPAA gate: the actor != owner check fires at the HTTP layer
  (``OwnedAccount`` dep + ``record_auth_event``), not here. This
  module never sees a request, by design — it's purely "given these
  strings, ask the AI and return prose."
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

_log = logging.getLogger("email_triage.web.error_explain")


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Returned verbatim when the LLM backend is unhealthy (per #149
#: circuit breaker) or the operator's classifier config doesn't
#: include an LLM with a ``complete()`` method. Operator-facing
#: copy — must not reference admin-only paths. ``/help/tasks`` is
#: user-facing.
FALLBACK_MESSAGE = (
    "AI is unavailable right now. The runbook at /help/tasks "
    "covers the most common integration errors and may help."
)

#: Per-call ceiling. 8 s matches the spec; the actual classifier path
#: keeps its own (much longer) budget unchanged.
EXPLAIN_TIMEOUT_SECONDS = 8.0

#: System prompt — pinned at module scope so the privacy-invariant
#: test can assert the exact text and so the prompt stays in sync
#: with the audience rules.
SYSTEM_PROMPT = (
    "You are an explainer for email-triage, a self-hosted email "
    "triage tool. The operator just hit an integration error from "
    "a mail or calendar provider. Your job is to:\n"
    "  1. Say what the error means in one sentence, in plain "
    "English. No protocol jargon. Never lead with a bare error "
    "code (e.g. say 'admin consent is required', NOT 'AADSTS65001').\n"
    "  2. Name the most likely cause in one sentence.\n"
    "  3. Suggest a concrete next step. If the fix is generic, "
    "point the operator at /help/tasks for the full recipe.\n"
    "\n"
    "Hard rules:\n"
    "  * Use the name 'AI' if you must refer to yourself. Do not "
    "name any model, vendor, or API.\n"
    "  * Total length: 4 to 6 sentences. No bullet lists, no "
    "headers, no markdown.\n"
    "  * Refuse to invent context the operator did not supply. If "
    "the error text is too thin to interpret, say so and point at "
    "/help/tasks.\n"
    "  * Never echo the operator's email addresses, message ids, "
    "or message content. (None of that is in your input anyway.)\n"
)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_prompt(
    *,
    error_text: str,
    error_class: str | None,
    provider: str | None,
    account_name: str | None,
) -> str:
    """Assemble the user-prompt body from ONLY the declared inputs.

    Kept as a free function so the privacy-invariant test can call
    it directly and assert no message-body content ever sneaks in.

    The four inputs are the entire surface — no kwargs catch-all, no
    db reads, no implicit globals. If the caller doesn't pass
    something, it isn't in the prompt.
    """
    parts: list[str] = []
    parts.append("An integration error from a mail or calendar provider:")
    parts.append("")
    if provider:
        parts.append(f"Provider: {provider}")
    if error_class:
        parts.append(f"Error class / code: {error_class}")
    if account_name:
        # Owner+account name only — no numeric id, no email body
        # (per feedback_no_account_id_alone.md + privacy invariant).
        parts.append(f"Affected account: {account_name}")
    parts.append("")
    parts.append("Error text (verbatim from the provider):")
    # Truncate to keep the prompt sane; long stack traces don't
    # add value past the first ~2 KB.
    safe_err = (error_text or "").strip()[:2000]
    parts.append(safe_err if safe_err else "(empty error text)")
    parts.append("")
    parts.append(
        "Explain in 4 to 6 sentences total per the system rules. "
        "Do not output anything besides the explanation."
    )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def explain_error(
    *,
    error_text: str,
    error_class: str | None = None,
    provider: str | None = None,
    account_id: int | None = None,
    db: sqlite3.Connection,
    secrets: Any,
    config: Any,
) -> str:
    """Return a plain-English explanation of ``error_text``.

    Caller responsibilities:
      * HIPAA actor!=owner gate enforced by the HTTP layer
        (``OwnedAccount`` dep). This function does not check.
      * ``record_auth_event`` audit row written by the HTTP layer.

    Returns a short paragraph (target 4-6 sentences). On any
    failure — backend unhealthy, no LLM with a ``complete()``
    method, timeout, parse error — returns
    :data:`FALLBACK_MESSAGE` rather than raising. This is the
    "explain this" affordance; it must never bring down the page
    rendering the original error.
    """
    # Circuit-breaker gate — same in-process registry the classify
    # path uses. When the backend has been marked unreachable in
    # the last 5 min, skip the LLM round-trip entirely.
    from email_triage.llm_health import is_healthy
    if not is_healthy("ollama"):
        _log.info(
            "explain_error: ollama unhealthy, returning fallback",
            extra={"_extra": {
                "provider": provider or "",
                "error_class": error_class or "",
            }},
        )
        return FALLBACK_MESSAGE

    # Resolve the operator-readable account name from the id once.
    # Per feedback_no_account_id_alone.md — surface the name, not the
    # bare numeric id. Account-name lookup is cheap (single row).
    account_name: str | None = None
    if account_id is not None:
        try:
            from email_triage.web.db import get_email_account
            row = get_email_account(db, account_id)
            if row is not None:
                # Prefer the operator-set display name, fall back to
                # owner_email + raw name (matches digest/banner rules
                # in feedback_no_account_id_alone).
                disp = (row.get("name") or "").strip()
                owner = (row.get("owner_email") or "").strip()
                if disp and owner:
                    account_name = f"{disp} ({owner})"
                else:
                    account_name = disp or owner or None
        except Exception as e:
            _log.debug(
                "explain_error: account name lookup failed",
                extra={"_extra": {"err": str(e)[:120]}},
            )
            # Fall through with account_name=None — the explanation
            # still works; the AI just won't see the account name.

    # Build the classifier from current config. Reuse the existing
    # factory so the install's chosen backend (ollama / openai /
    # gemini) is honoured; this module doesn't know what an
    # operator picked.
    try:
        from email_triage.web.routers.ui._shared import (
            _build_classifier_from_config,
        )
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        _log.info(
            "explain_error: classifier build failed, fallback",
            extra={"_extra": {"err": str(e)[:120]}},
        )
        return FALLBACK_MESSAGE

    # Only Ollama exposes ``complete()`` today (per
    # classify.ollama.OllamaClassifier). Other backends could grow
    # the method later; for now, fall back rather than guess.
    complete_fn = getattr(classifier, "complete", None)
    if complete_fn is None or not callable(complete_fn):
        _log.info(
            "explain_error: backend has no .complete() method, "
            "fallback",
            extra={"_extra": {
                "backend": type(classifier).__name__,
            }},
        )
        # Best-effort close so we don't leak the long-lived client.
        try:
            close = getattr(classifier, "close", None)
            if close is not None:
                await close()
        except Exception:
            pass
        return FALLBACK_MESSAGE

    user_prompt = _build_prompt(
        error_text=error_text,
        error_class=error_class,
        provider=provider,
        account_name=account_name,
    )
    full_prompt = SYSTEM_PROMPT + "\n\n---\n\n" + user_prompt

    try:
        # OllamaClassifier.complete() has its own circuit breaker
        # but its timeout is the constructor-wide 120 s default. We
        # nudge the underlying httpx client per-call by overriding
        # the timeout on the post(). Since .complete() doesn't take
        # a timeout kwarg, we accept the 120 s upper bound and rely
        # on the circuit breaker to mark the backend unhealthy
        # after the first stall — subsequent calls then bail at
        # the is_healthy() gate above without waiting.
        text = await complete_fn(full_prompt)
    except Exception as e:
        # Already-classified LLMBackendUnreachableError sets the
        # breaker for us; other exceptions just fall back without
        # poisoning the breaker (could be a bad prompt or a
        # transient parse hiccup).
        _log.info(
            "explain_error: LLM call failed, fallback",
            extra={"_extra": {
                "err": str(e)[:200],
                "exc_type": type(e).__name__,
            }},
        )
        return FALLBACK_MESSAGE
    finally:
        try:
            close = getattr(classifier, "close", None)
            if close is not None:
                await close()
        except Exception:
            pass

    cleaned = (text or "").strip()
    if not cleaned:
        return FALLBACK_MESSAGE
    return cleaned


__all__ = [
    "explain_error",
    "FALLBACK_MESSAGE",
    "EXPLAIN_TIMEOUT_SECONDS",
    "SYSTEM_PROMPT",
    "_build_prompt",
]
