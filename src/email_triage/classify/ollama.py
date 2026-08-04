"""Ollama LLM backend for email classification.

Uses the Ollama REST API (``/api/chat``) via httpx.  This is the default
backend — typical deployment runs a quantised mid-sized model (qwen, llama,
mistral) on a single-GPU LAN host.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.classify.base import JsonChatClassifier

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.classify.ollama")  # N-196b R21_4


def _warn_if_truncated(body: Any, model: str, *, context: str) -> bool:
    """Surface a non-clean Ollama finish — the silent-truncation guard.

    Delegates to the cross-backend SSOT :func:`llm_truncation.warn_if_llm_truncated`
    (``family='ollama'`` → checks ``done_reason``). Kept as a thin local wrapper
    so the three Ollama call sites (``_chat`` / ``_chat_topics`` / ``complete``)
    keep their existing signature; the truncation logic itself lives in ONE place
    (the count-agnostic pin asserts every backend routes through it).
    """
    from email_triage.llm_truncation import warn_if_llm_truncated
    return warn_if_llm_truncated(
        body, family="ollama", model=model, context=context, logger=logger,
    )


def _strip_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks from Qwen3-style reasoning output.

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


def _salvage_incomplete_json_object(s: str, start: int) -> dict[str, Any] | None:
    """Best-effort recovery of a TRUNCATED / premature-stop JSON object.

    qwen3.x under Ollama ``format: json`` intermittently emits the stop token
    mid-object — an unterminated string, or an object cut before its closing
    brace — and (UNLIKE a ``num_predict`` cap, which Ollama 0.30.8 reports as
    ``done_reason: length``) reports ``done_reason: stop``, so the 
    truncation guard never fires and strict ``raw_decode`` raises. This is the
    2026-06-14 ``rtx 5090 founders`` topic-match parse-failure class: a long
    HTML promo body → the model free-runs the ``reason`` and stops mid-value.
    Recovering the fields that DID complete is strictly better than dropping
    every verdict — the digest keeps the category/confidence/reason already paid
    for (and any ``topic_verdicts`` that finished before the cut).

    Strategy: scan from ``start`` recording every structural boundary (a closed
    string, a complete number/keyword, an opened/closed container) with the
    bracket stack at that point. Then, longest prefix first, truncate to the
    boundary, drop a dangling comma, append the closers the stack needs, and let
    ``json.loads`` (the oracle) validate. A boundary that lands after a KEY
    (``{"reason"``) simply fails to parse and is skipped — no key/value
    bookkeeping needed. An unterminated trailing string is also tried with a
    synthetic closing quote so its partial text survives. Returns the recovered
    dict, or None when nothing parses.
    """
    boundaries: list[tuple[int, tuple[str, ...]]] = []
    stack: list[str] = []
    in_str = False
    esc = False
    i, n = start, len(s)
    while i < n:
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
                boundaries.append((i + 1, tuple(stack)))  # value/key string closed
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch in "{[":
            stack.append(ch)
            boundaries.append((i + 1, tuple(stack)))  # empty container is closeable
            i += 1
            continue
        if ch in "}]":
            if stack:
                stack.pop()
            boundaries.append((i + 1, tuple(stack)))
            i += 1
            continue
        if ch == "-" or ch.isdigit():
            j = i + 1
            while j < n and (s[j].isdigit() or s[j] in "+-.eE"):
                j += 1
            boundaries.append((j, tuple(stack)))  # may over-include a cut number; loads filters
            i = j
            continue
        matched_lit = False
        for lit in ("true", "false", "null"):
            if s.startswith(lit, i):
                i += len(lit)
                boundaries.append((i, tuple(stack)))
                matched_lit = True
                break
        if not matched_lit:
            i += 1  # whitespace / comma / colon — not a safe truncation point itself

    # Longest-first candidates. A still-open trailing string is closed
    # synthetically first (preserves the most text); then every recorded
    # boundary from longest to shortest.
    candidates: list[tuple[int, tuple[str, ...], bool]] = []
    if in_str:
        candidates.append((n, tuple(stack), True))
    candidates.extend((end, stk, False) for end, stk in reversed(boundaries))
    for end, stk, close_str in candidates:
        frag = s[start:end]
        if close_str:
            frag = frag.rstrip("\\") + '"'  # a dangling backslash would eat the quote
        frag = frag.rstrip()
        if frag.endswith(","):
            frag = frag[:-1].rstrip()
        cand = frag + "".join("}" if c == "{" else "]" for c in reversed(stk))
        try:
            obj = json.loads(cand, strict=False)
        except json.JSONDecodeError:
            continue
        # Require a NON-empty dict: a bare "{" salvages to "{}" which carries no
        # recovered signal — better to return None so the caller's bounded retry
        # re-rolls than to silently hand back an empty classification.
        if isinstance(obj, dict) and obj:
            return obj
    return None


def _decode_first_object(
    cleaned: str, start: int,
) -> tuple[dict[str, Any] | None, str | None]:
    """Decode the first JSON object at ``start`` — strict, then tolerant.

    Returns ``(obj, tier)`` where ``tier`` names the pass that resolved it, so
    the caller can METER non-strict recoveries (N-93: a rising salvage rate is
    the canary that the source-side ``format``-schema is degrading even while
    the digest stays green). Three escalating passes:

      1. ``"strict"`` — ``raw_decode`` STRICT; tolerates trailing junk (a stray
         ``}`` / a second object / trailing prose) by stopping at the end of the
         first complete value. Every well-formed response (and the qwen3.6
         stray-``}`` shape, 2026-06-08).
      2. ``"lenient"`` — ``raw_decode`` with ``strict=False``; tolerates RAW
         control chars (newline / tab / etc.) inside a string that strict
         ``json.loads`` rejects even though the object is otherwise complete —
         recovers the FULL object (``topic_verdicts`` included).
      3. ``"salvage"`` — recover the completed fields of a truncated /
         premature-stop object (:func:`_salvage_incomplete_json_object`).

    ``(None, None)`` only when even salvage finds nothing parseable.
    """
    try:
        obj, _ = json.JSONDecoder().raw_decode(cleaned, start)
        if isinstance(obj, dict):
            return obj, "strict"
    except json.JSONDecodeError:
        pass
    try:
        obj, _ = json.JSONDecoder(strict=False).raw_decode(cleaned, start)
        if isinstance(obj, dict):
            return obj, "lenient"
    except json.JSONDecodeError:
        pass
    salvaged = _salvage_incomplete_json_object(cleaned, start)
    return (salvaged, "salvage") if salvaged is not None else (None, None)


def _debug_capture_enabled() -> bool:
    """N-372 (2026-07-05): opt-in classify parse-failure diagnostic surface.

    Default OFF — the raise sites below deliberately log LENGTH ONLY to avoid
    echoing email-derived model prose into log_entries (hipaa-sme,
    §164.312(b)/§164.502(b) — see the docblocks at those raise sites).

    When the operator flips ``ET_CLASSIFY_DEBUG_CAPTURE=1`` on a specific
    install, we ADD a single ``logger.warning`` with the pre-strip raw
    response head so post-hoc RCA is possible on a stuck retry row
    (``max_attempts_exceeded`` w/ no other signal). The raise itself and
    its message are UNCHANGED — existing tests + retry-queue rows keep the
    same shape; the debug log rides ADJACENT to the error. the deploy host-only knob;
    the medical-researcher reuse leaves it unset → identical to today.
    """
    # A9-pin: string→bool parse routes through the _envbool SSOT.
    from email_triage._envbool import env_bool
    return env_bool("ET_CLASSIFY_DEBUG_CAPTURE", default=False)


def _scrub_debug_head(text: str, limit: int = 400) -> str:
    """PHI/secret-scrub a bounded head of a raw LLM response for the debug
    capture log. Routes through the persisted-error SSOT
    :func:`~email_triage._errfmt.scrub_error_for_persist` — the same funnel
    every ``last_error`` field uses — so an accidentally-echoed email
    address / mailbox path / token in the model's reasoning gets redacted
    before it lands in ``log_entries`` (hipaa-sme §164.502(b) minimum-
    necessary + §164.312(b) audit-log secret hygiene). Empty in → empty
    out; a scrubber miss is at worst a bounded 400-char surface, but the
    scrub SSOT is the same one the audit chain trusts.
    """
    from email_triage._errfmt import scrub_error_for_persist
    scrubbed = scrub_error_for_persist(text, max_len=limit)
    return scrubbed or ""


def _parse_llm_json_tiered(text: str) -> tuple[dict[str, Any], str]:
    """:func:`_parse_llm_json` + the recovery TIER that resolved it.

    Returns ``(obj, tier)`` (``tier`` ∈ ``strict`` / ``lenient`` / ``salvage``)
    so the topic-match path can METER non-strict recoveries — a rising
    salvage/lenient rate is the canary that the source-side ``format``-schema is
    degrading even while the digest stays green (N-93 ``salvage_recovered``).
    Raises identically to :func:`_parse_llm_json` when nothing parses.
    """
    # Strip thinking blocks first (Qwen3 wraps reasoning in <think> tags).
    cleaned = _strip_think_tags(text).strip()

    # Strip markdown code fences if present.
    if cleaned.startswith("```"):
        # Remove opening fence (```json or ```)
        first_newline = cleaned.index("\n")
        cleaned = cleaned[first_newline + 1:]
        if "```" in cleaned:
            cleaned = cleaned[:cleaned.rindex("```")]
        cleaned = cleaned.strip()

    start = cleaned.find("{")
    if start == -1:
        # N-372 (2026-07-05) — salvage-first, strip-second fallback. Prior
        # order (strip <think> then look for `{`) DELETES a truncated-
        # mid-``<think>`` response before salvage can see it. On the
        # 2026-07-05 FedEx incident the model spent all 256 tokens INSIDE
        # `<think>` with no closing tag; strip emptied everything → no `{`
        # → hard raise. Now: if cleaned is empty of braces, look for `{`
        # in the RAW (pre-strip) text and route to the salvage decoder.
        # Recovers the case where the answer BEGAN before the model got
        # side-tracked into `<think>`, or where a `{...` prefix survived
        # inside the reasoning block. Bounded — salvage still returns None
        # on non-recoverable garbage and we fall through to the same raise.
        raw_start = text.find("{")
        if raw_start != -1:
            salvaged = _salvage_incomplete_json_object(text, raw_start)
            if salvaged is not None:
                return salvaged, "salvage"
        # No JSON object at all (pure prose / refusal). The head here would be
        # raw model prose — which on the topic-match path can echo email-derived
        # content — so log LENGTH ONLY (no head). Same PHI-in-logs leak class as
        # the unparseable branch below (hipaa-sme, §164.312(b)/§164.502(b)):
        # both content-free, fixed in one change (root-cause-scope).
        #
        # N-372 OPT-IN post-hoc diagnostic. When
        # ``ET_CLASSIFY_DEBUG_CAPTURE=1`` the operator gets ONE warning row
        # with the PHI/secret-scrubbed pre-strip raw head (bounded 400
        # chars) so a stuck retry row's failure mode is inspectable AFTER
        # THE FACT. Off by default. Log row rides ADJACENT to the raise
        # (same request_id via TriageLogger contextvar) — the ValueError
        # message + retry-queue write are unchanged.
        if _debug_capture_enabled():
            logger.warning(
                "classify_parse_fail_debug: no brace in cleaned response",
                extra={
                    "raw_len": len(text),
                    "raw_head_scrubbed": _scrub_debug_head(text),
                    "cleaned_len": len(cleaned),
                    "path": "no-brace",
                },
            )
        raise ValueError(
            f"No JSON object found in LLM response (len={len(text)})"
        )
    obj, tier = _decode_first_object(cleaned, start)
    if obj is None or tier is None:
        # Structural diagnostic ONLY (no model content → PHI-safe for the
        # medical-researcher reuse): the 40-char head is the *post-strip* JSON
        # skeleton from the first '{' (e.g. `{"category": "promotions", ...`) —
        # operator-taxonomy slug + a float, before any free-text reason — plus
        # the total length. NOT raw `text[:40]` (which could carry a leading
        # think/prose fragment).
        if _debug_capture_enabled():
            logger.warning(
                "classify_parse_fail_debug: no parseable object",
                extra={
                    "raw_len": len(text),
                    "raw_head_scrubbed": _scrub_debug_head(text),
                    "cleaned_head_scrubbed": _scrub_debug_head(
                        cleaned[start:start + 400],
                    ),
                    "path": "no-parseable",
                },
            )
        raise ValueError(
            f"No parseable JSON object in LLM response "
            f"(len={len(text)}, head={cleaned[start:start + 40]!r})"
        )
    return obj, tier


def _parse_llm_json(text: str) -> dict[str, Any]:
    """Extract a JSON object from LLM output. (Public; discards the parse tier —
    use :func:`_parse_llm_json_tiered` when the caller meters salvage usage.)

    Handles common quirks: Qwen3 <think> tags, markdown fences, trailing text
    after the object, leading whitespace — and, via :func:`_decode_first_object`,
    RAW control chars in strings and TRUNCATED / premature-stop objects (the
    qwen3.x ``format: json`` ``done_reason: stop`` corruption the  guard
    can't see). Recovering the completed fields beats dropping every verdict
    on the digest-side topic-match path (§4.4 fail-open is a degradation, never
    a core-triage failure).
    """
    return _parse_llm_json_tiered(text)[0]


# Ollama structured-output JSON schemas (N-93, 2026-06-14). Passing a JSON
# Schema object in ``format`` (vs the free-form ``"json"`` mode) grammar-
# CONSTRAINS the model to emit schema-conforming JSON — the SOURCE-side fix for
# the topic-match parse miss (qwen3.x under ``format:"json"`` free-ran the
# ``reason`` and stopped mid-object, ``done_reason='stop'``). Validated 15/15
# clean + no slowdown (~1.8s) on qwen3.6:35b / Ollama 0.30.8 (2026-06-14). The
# parser salvage/``strict=False`` (`_decode_first_object`) STAYS as the
# defense-in-depth backstop — layered defense, never a single point — for
# backends/models that don't honor ``format``-schema (the medical-researcher
# reuse may run a different LLM). Stage A and Stage B both send the SAME schema
# (both via ``_chat_topics``), so the §4.2.3 byte-identical-options
# prefix-cache invariant is preserved.
_CLASSIFY_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {"type": "string"},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["category", "confidence", "reason"],
}

_TOPIC_MATCH_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {"type": "string"},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
        "topic_verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    # PERMISSIVE by design (DA N-93): the system treats topic_id
                    # as OPAQUE (TopicVerdict.topic_id is `object`;
                    # _parse_topic_verdicts never asserts int), and the
                    # medical-researcher reuse may key Topics by string/UUID.
                    # Grammar-FORCING `integer` here would manufacture the very
                    # malformation this fix kills on any non-int id — match the
                    # opaque contract, never narrow it.
                    "topic_id": {"type": ["integer", "string"]},
                    "matched": {"type": "boolean"},
                    "confidence": {"type": "number"},
                    "reason_terms": {
                        "type": "array", "items": {"type": "string"},
                    },
                },
                "required": ["topic_id", "matched"],
            },
        },
    },
    # topic_verdicts stays OPTIONAL (not in required) — the model omits it when
    # nothing matches, and the §4.4 path reads it via .get() with a default.
    "required": ["category", "confidence", "reason"],
}


_LOADED_CACHE_TTL_SECONDS = 30


def _is_embedding_model(name: str, markers: tuple[str, ...]) -> bool:
    """True if ``name`` looks like an embedding-only model.

    Ollama ``/api/ps`` exposes ``details.family``, but an embedding
    model like ``qwen3-embedding:0.6b`` reports family ``qwen3`` —
    indistinguishable from the ``qwen3.x`` chat models — so family
    cannot separate them. The model **name** is the only reliable
    in-band signal (``/api/ps`` carries no ``capabilities`` field), so
    we match a case-insensitive substring against the configured
    ``markers`` (default ``("embed",)``, which covers
    ``qwen3-embedding`` and ``nomic-embed-text``).
    """
    low = name.lower()
    return any(mk in low for mk in markers)


#  — capability/resource error signatures that a DIFFERENT model on
# the SAME Ollama can actually satisfy. These are the ONLY errors the
# classifier fails over on. Everything else — transient rate-limit /
# 5xx, decode errors, generic failures — re-raises so the per-message
# retry queue handles it IN PLACE, rather than silently serving a
# different (possibly worse) model and writing a misleading audit row.
_FAILOVER_SIGNATURES = (
    "does not support generate",
    "does not support chat",
    "does not support",
    "out of memory",
    "requires more system memory",
    "failed to load model",
    "unable to load model",
    "cannot load",
    "model not found",
    "no such model",
    "try pulling it first",
)


def _is_failover_eligible(exc: Exception) -> bool:
    """True if ``exc`` is a model-specific capability/resource failure a
    backup model could satisfy (embedding-only 400 "does not support
    generate", OOM / VRAM, model-not-installed). Transient (429 / 5xx)
    and generic errors are NOT eligible — those retry in place.

    ``raise_for_status`` produces an ``httpx.HTTPStatusError`` whose
    ``str()`` is generic ("Client error '400'…"), so the actual Ollama
    message lives in ``exc.response.text`` — we scan both.
    """
    parts = [str(exc).lower()]
    resp = getattr(exc, "response", None)
    if resp is not None:
        try:
            parts.append((resp.text or "").lower())
        except Exception:
            pass
    blob = " ".join(parts)
    return any(sig in blob for sig in _FAILOVER_SIGNATURES)


@dataclass
class OllamaModelInfo:
    """One installed Ollama model + the facts the admin picker shows.

    Populated by :meth:`OllamaClassifier.list_models` from ``/api/tags``
    (installed set + size / family / quant / params), ``/api/show``
    (capabilities + context length), and ``/api/ps`` (resident set).
    ``chat_capable`` is the / guard surfaced to the UI: a model
    whose ``capabilities`` lack ``"completion"`` cannot serve
    ``/api/chat`` and is flagged invalid for a classifier slot.
    """

    name: str
    capabilities: tuple[str, ...] = ()
    chat_capable: bool = True
    embedding_only: bool = False
    parameter_size: str = ""
    quantization: str = ""
    context_length: int | None = None
    family: str = ""
    size_bytes: int | None = None
    resident: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "capabilities": list(self.capabilities),
            "chat_capable": self.chat_capable,
            "embedding_only": self.embedding_only,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
            "context_length": self.context_length,
            "family": self.family,
            "size_bytes": self.size_bytes,
            "resident": self.resident,
        }


#  Phase-3 Stage-B — grammar-constrained schema for the safety-reporting
# determination (mirrors the N-93 format-schema posture; salvage in
# _parse_llm_json stays the backstop for non-conforming backends).
_SAFETY_REPORTABLE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_regulatory_clock": {"type": "boolean"},
        "confidence": {"type": "number"},
        "report_class": {
            "type": "string",
            "enum": ["fatal_lt", "other_serious", "irb_up", "none"],
        },
        "clock_anchor": {
            "type": "string",
            "enum": ["on_receipt", "on_awareness", "on_determination", "unknown"],
        },
        "extracted_phrase": {"type": "string"},
        "assertion": {
            "type": "string",
            "enum": ["asserted", "hypothetical", "negated", "historical"],
        },
    },
    "required": [
        "is_regulatory_clock", "confidence", "report_class", "assertion",
    ],
}


class OllamaClassifier(JsonChatClassifier):
    """Classify emails via the Ollama REST API.

    When ``prefer_loaded`` is True (default), each call probes
    ``/api/ps`` and uses whatever chat model is already resident in
    VRAM — skipping any resident embedding-only model, which
    cannot serve ``/api/chat`` — and falling back to the configured
    ``model`` when nothing usable is loaded. Prevents "configured
    model can't load because GPU is full of a different model" 500s in
    homelab setups, and absorbs version drift (qwen3.5 → qwen3.6)
    without a config chase.

    The /api/ps result is cached for 30 s per instance so we don't
    add an HTTP round trip to every classification.
    """

    def __init__(
        self,
        model: str = "qwen3.5:35b",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
        prefer_loaded: bool = True,
        local_url_suffixes: list[str] | None = None,
        prefer_loaded_skip_embeddings: bool = True,
        embedding_name_markers: list[str] | None = None,
        backup_models: list[str] | None = None,
        num_ctx: int | None = None,
        ollama_think: bool | None = None,
        ollama_no_think_marker: bool = False,
        ollama_probe_timeout_secs: float = 5.0,
        ollama_admin_timeout_secs: float = 10.0,
        ollama_keep_alive: str | int = "10m",
    ):
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        # -a — probe (/api/ps + /api/show, hot-path cached) and admin
        # (/api/tags, cold model enumeration) budgets. Config-driven per
        # feedback_dynamic_over_hardcoding; defaults preserve prior
        # hardcoded values.
        self._probe_timeout = float(ollama_probe_timeout_secs)
        self._admin_timeout = float(ollama_admin_timeout_secs)
        # N-431 (2026-07-19) — Ollama `keep_alive` payload option, threaded
        # through every /api/chat + /api/embeddings site via the shared
        # SSOT :mod:`email_triage._ollama_reuse`. Config-driven default so
        # a per-deployment YAML override reaches every wire site uniformly;
        # bounded generous default ("10m") preserves prior behavior at
        # the 2 sites that already hardcoded that value. Accept ``str``
        # (Ollama's native form: "10m", "1h", "-1") or ``int`` seconds.
        self._keep_alive: str | int = ollama_keep_alive
        self._prefer_loaded = prefer_loaded
        #  — when ``prefer_loaded`` picks a resident model, skip any
        # embedding-only model: it 400s ("does not support generate")
        # on the ``/api/chat`` path. Detected by case-insensitive
        # name-substring match because ``/api/ps`` carries no
        # capabilities field (family is ambiguous: qwen3-embedding
        # reports family ``qwen3``). Default on; markers default to
        # ``["embed"]`` (covers qwen3-embedding, nomic-embed-text).
        self._skip_embeddings = prefer_loaded_skip_embeddings
        self._embed_markers = tuple(
            m.lower() for m in (embedding_name_markers or ["embed"])
        )
        #  — ordered capability/resource fallback models. On a
        # ``_chat`` capability/resource failure (NOT unreachable — the
        # circuit breaker owns availability) the classifier retries the
        # next model in this list. All are models on the SAME endpoint,
        # so no BAA boundary is crossed.
        self._backup_models = [m for m in (backup_models or []) if m]
        #  — operator-pinned Ollama context window. None = omit the option
        # (inherit the model's loaded default). When set it is injected into the
        # options dict of EVERY call via :meth:`_options`, so the two 
        # topic-match stages read the SAME value and the §4.2.3 byte-identical-
        # options invariant holds. Reject bool / non-positive defensively.
        self._num_ctx = (
            num_ctx
            if isinstance(num_ctx, int)
            and not isinstance(num_ctx, bool)
            and num_ctx > 0
            else None
        )
        #  (SME MUST) — a pinned num_ctx below the topic-match floor risks
        # SILENT front-truncation of the  prompt (K full Topic Details + the
        # email). That input-side truncation is NOT caught by the  output
        # done_reason guard, so it would fall open to ZERO verdicts unseen. Warn
        # don't clamp (a deliberately-constrained deployment is the operator's
        # call) — but make the degraded config operator-visible in the running
        # system (the WARN rides the health/error digest). Lazy import: the
        # floor lives where K does, no module cycle.
        if self._num_ctx is not None:
            from email_triage.actions.topic_prefilter import (
                MIN_RECOMMENDED_NUM_CTX,
            )
            if self._num_ctx < MIN_RECOMMENDED_NUM_CTX:
                logger.warning(
                    "Pinned num_ctx is below the recommended floor: the "
                    " topic-match prompt can be front-truncated to fit, "
                    "silently dropping verdicts (input-side truncation is NOT "
                    "caught by the  output done_reason guard). Leave the "
                    "admin Context-window field blank to inherit the model "
                    "default.",
                    extra={
                        "num_ctx": self._num_ctx,
                        "floor": MIN_RECOMMENDED_NUM_CTX,
                    },
                )
        # N-378 (2026-07-08) — Ollama ``think`` payload option as a
        # CONFIG KNOB (never hardcoded — see ClassifierConfig docblock for
        # the ~4-6× perf story + the Ollama bug #15260 fix chain).
        # Type-guard defensively: reject anything that isn't literal True /
        # False / None, so a stray string ``"false"`` from YAML can't
        # silently downgrade thinking control (would collapse to a truthy
        # non-bool at the payload site).
        self._think: bool | None = ollama_think if (
            ollama_think is None or isinstance(ollama_think, bool)
        ) else None
        # N-378 belt-and-braces — Qwen3 `/no_think` end-of-user-message
        # marker. Independent of the ``think`` payload option (some Qwen3
        # tokenizer templates honour the marker even without the payload
        # option). Uniformly appended to every /api/chat prompt when set.
        self._no_think_marker: bool = bool(ollama_no_think_marker)
        # / — cache the parsed /api/show payload per model
        # (capabilities + model_info are static per model tag), so the
        # resolve-path embedding guard and the admin model picker each
        # cost at most one /api/show round trip per distinct model.
        self._show_cache: dict[str, dict] = {}
        self._loaded_cache: tuple[float, str | None] = (0.0, None)
        # Long-lived httpx client for /api/chat + /api/ps + /api/embeddings.
        # Per-call ``timeout=`` overrides on the probe path keep the
        # 5 s probe budget without standing up a second client.
        self._http = LazyHttpClient(intent=Intent.LLM_PHI, timeout=self._timeout)
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

    def _options(self, num_predict: int) -> dict:
        """The Ollama ``options`` dict shared by every call.

        ``num_ctx`` is injected ONLY when the operator pinned one — otherwise
        omitted, so the model's loaded default applies (today's behaviour).
        Because BOTH  topic-match stages build their options through this
        ONE helper with the SAME ``self._num_ctx``, the §4.2.3 byte-identical-
        options prefix-cache invariant is preserved. ``num_predict`` varies per
        call-site but is a generation cap, never a prefill / KV-prefix
        parameter, so it does not perturb the warm prefix.
        """
        opts: dict = {"temperature": 0.3, "num_predict": num_predict}
        if self._num_ctx is not None:
            opts["num_ctx"] = self._num_ctx
        return opts

    def _payload_think_extras(self) -> dict:
        """N-378 — the SSOT for the Ollama ``think`` payload option (top-level
        payload key, NOT inside ``options`` — its inclusion or absence does
        NOT perturb the byte-identical ``options`` prefix-cache invariant
        §4.2.3 relies on). Returns an empty dict when the operator hasn't
        set the knob (``None``); returns ``{"think": True/False}`` when
        explicitly set. Every ``/api/chat`` payload in this classifier
        spreads this via ``**self._payload_think_extras()`` so a new chat
        entry point cannot silently reintroduce hardcoded thinking control
        (the count-agnostic pin ``test_ollama_think_knob_ssot`` enforces
        the shape at every ``/api/chat`` callsite).
        """
        if self._think is None:
            return {}
        return {"think": self._think}

    def _maybe_append_no_think(self, text: str) -> str:
        """N-378 belt-and-braces — append ``/no_think`` marker to a user-side
        prompt when the operator has enabled it. Qwen3-family models honour
        the marker independent of the ``think`` payload option (some
        Qwen3 chat templates recognize it even when ``think`` is unset).
        Uniformly applied to every ``/api/chat`` user prompt this classifier
        emits (SSOT). Non-op when the knob is off.
        """
        if not self._no_think_marker:
            return text
        return f"{text}\n\n/no_think"

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
            # N-431 (2026-07-19 DA panel MF-1) — /api/ps probe now routes
            # through the shared SSOT ``_ollama_reuse.probe`` so this
            # method + ``merge_reuse_options`` (which the .post below
            # relies on) share ONE per-base_url probe cache. Prior code
            # kept its own /api/ps GET at this seam — two independent 30s
            # caches probing the same endpoint = PD-5/6 SSOT violation.
            # ``self._loaded_cache`` (the CHOSEN-MODEL pick cache below)
            # remains — it memoizes the ``_is_embedding_only`` iteration
            # RESULT, downstream of the shared probe. The `client` we
            # hold here is the LazyHttpClient shared with the payload
            # POSTs; passing it into the SSOT ensures the probe uses the
            # same transport (no per-caller ephemeral client).
            from email_triage._ollama_reuse import probe as _shared_probe
            rows_by_name = await _shared_probe(
                self._base_url, client, timeout=self._probe_timeout,
            )
            if rows_by_name:
                # Preserve activity order: Python dict iteration order
                # is insertion order (3.7+), and the SSOT inserts in
                # /api/ps response order.
                models = list(rows_by_name.values())
                # Pick the first resident model that can actually chat.
                # Ollama returns models in activity order; for a homelab
                # with one shared GPU there's usually only one — but an
                # embedding model (e.g. qwen3-embedding:0.6b from the
                # graphiti memory miner sharing llm-host's Ollama) can land
                # as models[0] and would 400 on /api/chat ("does not
                # support generate"). Skip embedding-only models —
                # detected authoritatively via the /api/show
                # ``capabilities`` array, with a name-substring fallback
                # when /api/show can't answer — and fall back to the
                # configured chat model when only embedders (or nothing)
                # are resident.
                chat_name = None
                for m in models:
                    name = m.get("name", "") or m.get("model", "")
                    if not name:
                        continue
                    if self._skip_embeddings and await self._is_embedding_only(
                        client, name,
                    ):
                        logger.debug(
                            "Ollama: skipping resident embedding model for chat path",
                            extra={"model_name": name},
                        )
                        continue
                    chat_name = name
                    break
                if chat_name:
                    resolved = chat_name
                    if chat_name != self._model:
                        logger.info(
                            "Ollama: using already-loaded model instead of configured",
                            extra={"model_name": chat_name, "provider": self._model},
                        )
                elif models:
                    # Something was resident but it was all embedder(s) —
                    # log at INFO so the configured-model cold-load is
                    # greppable ("why did it bring up 35b").
                    logger.info(
                        "Ollama: only embedding model(s) resident; "
                        "using configured '%s'", self._model,
                    )
        except Exception as e:
            # Probe is best-effort — any failure falls back to the
            # configured model and the /api/chat call itself will
            # surface a real error if there's a server problem.
            logger.debug(
                "Ollama /api/ps probe failed",
                extra={"error_type": type(e).__name__, "error_msg": str(e)},
            )

        self._loaded_cache = (now, resolved)
        return resolved

    async def _fetch_show(self, client: Any, name: str) -> dict | None:
        """Return the parsed ``/api/show`` payload for ``name`` (cached).

        Authoritative source for a model's ``capabilities`` and
        ``model_info`` (context length, ). ``/api/ps`` exposes no
        capabilities, and ``details.family`` is ambiguous
        (``qwen3-embedding`` reports family ``qwen3``, same as the chat
        models), so ``/api/show`` is the only reliable signal. Cached
        forever per model tag — capabilities + architecture are static —
        so the resolve guard and the admin picker share one round trip
        per model.

        Returns ``None`` (uncached) when ``/api/show`` can't answer:
        non-200, unparseable, or no ``capabilities`` field (Ollama
        predating it). A transient failure isn't pinned, so the caller
        falls back to the name heuristic and re-probes next time.
        Fail-open: never raises.
        """
        cached = self._show_cache.get(name)
        if cached is not None:
            return cached
        try:
            resp = await client.post(
                f"{self._base_url}/api/show",
                json={"model": name},
                timeout=self._probe_timeout,
            )
            if resp.status_code == 200:
                data = resp.json() or {}
                # Only authoritative when capabilities is present —
                # older Ollama omits it, in which case we don't cache
                # and the caller uses the name heuristic.
                if data.get("capabilities"):
                    self._show_cache[name] = data
                    return data
        except Exception as e:
            logger.debug(
                "Ollama /api/show probe failed",
                extra={"model_name": name, "error_type": type(e).__name__, "error_msg": str(e)},
            )
        return None

    async def _is_embedding_only(self, client: Any, name: str) -> bool:
        """True if resident model ``name`` cannot serve ``/api/chat``.

        Authoritative via ``/api/show`` ``capabilities`` (embedding-only
        == lacks ``"completion"``); falls back to the configurable
        name-substring heuristic (:func:`_is_embedding_model`) when
        ``/api/show`` can't answer. Fail-open — any error degrades to
        the heuristic, never raises.
        """
        show = await self._fetch_show(client, name)
        if show is None:
            return _is_embedding_model(name, self._embed_markers)
        caps = show.get("capabilities") or []
        # A model that lists both "embedding" and "completion" CAN chat.
        return "completion" not in caps

    @staticmethod
    def _context_length_from_show(show: dict) -> int | None:
        """Pull context length out of an ``/api/show`` ``model_info``.

        Ollama keys it by architecture, e.g.
        ``model_info["qwen3.context_length"]`` — scan for any
        ``*.context_length`` int rather than guessing the arch prefix.
        """
        info = show.get("model_info") or {}
        for key, val in info.items():
            if key.endswith(".context_length") and isinstance(val, int):
                return val
        return None

    async def list_models(self) -> "list[OllamaModelInfo]":
        """Enumerate installed Ollama models + the facts the admin
        picker shows.

        ``/api/tags`` (installed set + size / family / quant / params)
        enriched with ``/api/show`` (capabilities + context length,
        cached via :meth:`_fetch_show`) and ``/api/ps`` (resident set).
        Best-effort: returns ``[]`` on any ``/api/tags`` failure so the
        picker degrades to the free-text field. This is an admin-probe
        path (operator clicks "fetch models"), NOT the classification
        hot path.
        """
        client = await self._http.get()
        try:
            resp = await client.get(
                f"{self._base_url}/api/tags", timeout=self._admin_timeout,
            )
            if resp.status_code != 200:
                return []
            installed = (resp.json() or {}).get("models", []) or []
        except Exception as e:
            logger.debug(
                "Ollama /api/tags probe failed",
                extra={"error_type": type(e).__name__, "error_msg": str(e)},
            )
            return []

        resident: set[str] = set()
        try:
            ps = await client.get(f"{self._base_url}/api/ps", timeout=self._probe_timeout)
            if ps.status_code == 200:
                for m in (ps.json() or {}).get("models", []) or []:
                    n = m.get("name") or m.get("model") or ""
                    if n:
                        resident.add(n)
        except Exception as e:
            logger.debug(
                "Ollama /api/ps probe failed during list",
                extra={"error_type": type(e).__name__, "error_msg": str(e)},
            )

        out: list[OllamaModelInfo] = []
        for m in installed:
            name = m.get("name") or m.get("model") or ""
            if not name:
                continue
            details = m.get("details") or {}
            show = await self._fetch_show(client, name)
            caps = tuple((show or {}).get("capabilities") or ())
            ctx = self._context_length_from_show(show) if show else None
            if caps:
                chat_capable = "completion" in caps
                embedding_only = (not chat_capable) and ("embedding" in caps)
            else:
                # /api/show couldn't tell us — fall back to the name
                # heuristic for the chat/embedding flag (same call the
                # resolve guard makes), without asserting capabilities.
                embedding_only = _is_embedding_model(
                    name, self._embed_markers,
                )
                chat_capable = not embedding_only
            size = m.get("size")
            out.append(OllamaModelInfo(
                name=name,
                capabilities=caps,
                chat_capable=chat_capable,
                embedding_only=embedding_only,
                parameter_size=str(details.get("parameter_size") or ""),
                quantization=str(details.get("quantization_level") or ""),
                context_length=ctx,
                family=str(details.get("family") or ""),
                size_bytes=size if isinstance(size, int) else None,
                resident=name in resident,
            ))
        return out

    async def _chat(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> str:
        """Issue an Ollama ``/api/chat`` request; return the raw text.

         Bundle B /  — the POST is wrapped in the shared
        circuit-breaker helper :func:`llm_health.translate_unreachable`:
        connect-class errors (Ollama down, network blip) trip the
        breaker via ``set_unhealthy`` and re-raise as
        ``LLMBackendUnreachableError`` so the watcher / push consumer /
        poll loop can distinguish "infrastructure weather" from a
        genuine classifier error. It MUST propagate —
        :meth:`JsonChatClassifier.classify` never catches around this.
        """
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": self._maybe_append_no_think(user_prompt)},
            ],
            "stream": False,
            # N-93: grammar-constrained structured output (was free-form
            # "json"); salvage in _parse_llm_json stays as the backstop.
            "format": _CLASSIFY_JSON_SCHEMA,
            # N-378 (2026-07-08) — `think` is now a CONFIG KNOB
            # (``classifier.ollama_think``) surfaced via
            # ``_payload_think_extras()`` at the bottom of this dict. Story:
            # N-372 (2026-07-05) REMOVED `think: False` because Ollama bug
            # #15260 broke grammar-mask application when combined with
            # `format=<json-schema>` — the format mask deferred until an
            # end-of-thinking token that never fired, so the schema was
            # silently dropped and the model emitted markdown prose. That
            # bug was CLOSED via Ollama PRs #15678 + #15392 (merged
            # 2026-04-21, shipped in Ollama 0.31.1 released 2026-06-30);
            # llm-host runs 0.31.1. But leaving thinking uncontrolled means
            # reasoning models (qwen3.6:35b) burn the full `num_predict`
            # budget on hidden reasoning tokens before emitting JSON —
            # production 2026-07-07/08 showed recurring
            # `finish_reason=length, raw_len=0` empty responses (silent
            # quality-loss on the topic-match verdicts). The operator's
            # environment-specific decision (`think: False` for this
            # deployment) belongs in the config, not baked in code — a
            # separate deployment on an older Ollama might legitimately
            # need to leave it unset until they upgrade.
            #
            # N-378 raised the `num_predict` cap 2048 → 4096. Rationale:
            # even with `think: False` set, a Qwen3 stock template can
            # still emit `<think>…</think>` blocks (the ``/no_think``
            # marker knob is the second defence). 4096 gives the reasoning
            # pass headroom to close and the answer to fit. Trade:
            # proportionally longer worst-case latency (dominated by the
            # reasoning-mode overhead when it's on — the `think: False`
            # knob is what actually cuts latency).
            "options": self._options(4096),
            **self._payload_think_extras(),
        }

        from email_triage.llm_health import translate_unreachable
        from email_triage._ollama_reuse import merge_reuse_options
        with translate_unreachable(
            "ollama", self._base_url, default_port=11434,
        ):
            client = await self._http.get()
            # N-431 (2026-07-19) — SSOT injects ``keep_alive`` (mandatory
            # wire field per ``feedback_always_set_ollama_keep_alive_
            # explicitly``) + mirrors loaded ``num_ctx`` when the caller
            # hasn't pinned one. Caller-set values are preserved — never
            # perturbs the §4.2.3 byte-identical-options invariant.
            await merge_reuse_options(
                payload, self._base_url, model, client,
                default_keep_alive=self._keep_alive,
                timeout=self._probe_timeout,
            )
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()

        body = resp.json()
        #  silent-truncation guard: a 256-token cut yields invalid JSON →
        # the classify parse falls open. Surface it (don't fail — the parser's
        # own fallback still runs; this just makes the truncation visible).
        _warn_if_truncated(body, model, context="classify")
        return body.get("message", {}).get("content", "")

    async def _chat_topics(self, prompt: str, model: str) -> str:
        """ — issue the topic-match ``/api/chat`` request (design §4.2).

        Differs from :meth:`_chat` in exactly the ways §4.2 mandates and in NO
        other way:

        * **Single leading message.** The whole prompt (BLOCK 1 shared prefix
          + BLOCK 2 Topic suffix) is ONE ``user`` message, so the shared
          ``[system + email]`` prefix is byte-identical across Stage A and
          Stage B and Ollama's prefix KV cache covers it — only the Topic
          suffix re-prefills. (The system/user split :meth:`_chat` uses cannot
          give a byte-identical prefix the suffix swaps cleanly off.)
        * **``keep_alive: "10m"``** pins the model resident between Stage A and
          Stage B so the warm prefix survives the gap (§4.2.3).
        * **Options built by the shared :meth:`_options` helper** — Stage A and
          Stage B both call ``self._options(2048)`` with the SAME
          ``self._num_ctx``,
          so they send a byte-identical ``options`` dict. A divergent per-stage
          num_ctx/option shift would be a full cache miss (§4.2.3); routing both
          stages through one helper makes that impossible.

        The JSON-output instruction that also asks for ``topic_verdicts`` lives
        in the prompt (BLOCK 1, built by ``prompts.build_topic_match_prompt``),
        not here — this method only carries it to Ollama.

        Wrapped in the SAME circuit-breaker helper as :meth:`_chat`: a
        connect-class failure re-raises ``LLMBackendUnreachableError`` and
        propagates (the whole backend is down; topic-match cannot mask that).
        Every other error surfaces to
        :meth:`JsonChatClassifier.classify_with_topics`, which falls open.
        """
        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": self._maybe_append_no_think(prompt)},
            ],
            "stream": False,
            # N-93: grammar-constrained structured output (was free-form
            # "json") — the source-side fix for the mid-object stop; salvage in
            # _parse_llm_json stays as the backstop. BOTH stages send this SAME
            # schema, so the §4.2.3 byte-identical-options invariant holds.
            "format": _TOPIC_MATCH_JSON_SCHEMA,
            # N-378 (2026-07-08): `think` is now a CONFIG KNOB
            # (``classifier.ollama_think``) — see docblock on ``_chat``
            # above for the full N-372 → N-378 story + Ollama bug #15260
            # closure chain. Applied uniformly across every /api/chat
            # payload via ``_payload_think_extras()`` at the bottom of this
            # dict (top-level payload option, NOT inside ``options`` — the
            # byte-identical-options prefix-cache invariant §4.2.3 relies
            # on is unaffected because both stages read the SAME knob).
            # ``/no_think`` marker (belt-and-braces companion knob) is
            # applied inside the user-message content above — again the
            # SAME value across both stages, so BLOCK-1 stays byte-identical.
            # N-431 (2026-07-19) — was hardcoded "10m"; now sourced from
            # ``ollama_keep_alive`` config knob (SSOT). SSOT ``merge_reuse_
            # options`` below PRESERVES this caller-set value (never
            # downgrades a Forever pin ``-1`` — the caller wins).
            "keep_alive": self._keep_alive,
            #  — the topic-match ``topic_verdicts`` array scales with the
            # user's Topic count, so the bare-classify 256-token budget TRUNCATED
            # multi-Topic JSON → invalid JSON → fall-open to ZERO verdicts,
            # SILENTLY (the digest showed no matches with no signal). Raise to a
            # verdict-appropriate ceiling. The §4.2.3 prefix-cache invariant is
            # unaffected: it requires Stage-A and Stage-B to send a byte-identical
            # ``options`` dict, and BOTH stages go through THIS method, so they
            # stay identical; ``num_predict`` is a generation limit, NOT a
            # prefill/``num_ctx`` parameter, so it never perturbs the KV prefix.
            # N-378 (2026-07-08) raised 2048 → 4096 for the reasoning-mode
            # headroom — see the ``_chat`` docblock above for the rationale
            # (Qwen3 stock templates emit `<think>…</think>` even with
            # `think: False`; 4096 gives both the reasoning pass and the
            # verdict JSON room to fit).
            "options": self._options(4096),
            **self._payload_think_extras(),
        }

        from email_triage.llm_health import translate_unreachable
        from email_triage._ollama_reuse import merge_reuse_options
        with translate_unreachable(
            "ollama", self._base_url, default_port=11434,
        ):
            client = await self._http.get()
            # N-431 (2026-07-19) — SSOT preserves the caller-set
            # ``keep_alive`` above (byte-identical-options prefix-cache
            # invariant §4.2.3 unaffected — both stages share the 30s
            # cache and read the SAME loaded-model params).
            await merge_reuse_options(
                payload, self._base_url, model, client,
                default_keep_alive=self._keep_alive,
                timeout=self._probe_timeout,
            )
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()

        body = resp.json()
        #  silent-truncation guard — the worst case here: a multi-Topic
        # user's ``topic_verdicts`` array overruns num_predict, the JSON is cut,
        # and the parse falls open to ZERO verdicts (the digest silently shows
        # no matches). The bumped num_predict above makes this rare; the guard
        # makes it never silent.
        _warn_if_truncated(body, model, context="topic-match")
        return body.get("message", {}).get("content", "")

    async def _chat_safety(self, prompt: str, model: str) -> str:
        """ Stage-B — issue the safety-reporting determination ``/api/chat``
        request. Single ``user`` message + the grammar-constrained
        ``_SAFETY_REPORTABLE_JSON_SCHEMA`` (same N-93 format-schema posture as
        ``_chat_topics``); options via the shared ``_options`` helper. Wrapped in
        the same circuit-breaker — a connect-class failure re-raises
        ``LLMBackendUnreachableError``; the caller
        (``classify_safety_reporting``) falls open on any other error."""
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": self._maybe_append_no_think(prompt)}],
            "stream": False,
            "format": _SAFETY_REPORTABLE_JSON_SCHEMA,
            # N-378 (2026-07-08): `think` is a CONFIG KNOB
            # (``classifier.ollama_think``) — full story on ``_chat``
            # above. ``/no_think`` marker (belt-and-braces) applied
            # to the user content above via ``_maybe_append_no_think``.
            # N-431 (2026-07-19) — was hardcoded "10m"; now sourced from
            # ``ollama_keep_alive`` config knob (SSOT). SSOT ``merge_reuse_
            # options`` below PRESERVES this caller-set value.
            "keep_alive": self._keep_alive,
            # N-378 raised 512 → 1024. Safety verdicts are compact, but
            # with `think: False` NOT set the reasoning pass can still burn
            # much of the budget on qwen3.6:35b before emitting the JSON.
            # 1024 covers the reasoning pass plus the small safety-schema
            # verdict; the operator's `ollama_think: False` knob is what
            # actually cuts the reasoning-pass cost.
            "options": self._options(1024),
            **self._payload_think_extras(),
        }
        from email_triage.llm_health import translate_unreachable
        from email_triage._ollama_reuse import merge_reuse_options
        with translate_unreachable(
            "ollama", self._base_url, default_port=11434,
        ):
            client = await self._http.get()
            # N-431 (2026-07-19) — SSOT preserves the caller-set
            # ``keep_alive`` above.
            await merge_reuse_options(
                payload, self._base_url, model, client,
                default_keep_alive=self._keep_alive,
                timeout=self._probe_timeout,
            )
            resp = await client.post(
                f"{self._base_url}/api/chat", json=payload,
            )
            resp.raise_for_status()
        body = resp.json()
        _warn_if_truncated(body, model, context="safety-report")
        return body.get("message", {}).get("content", "")

    async def complete(self, prompt: str) -> str:
        """Raw text completion via Ollama /api/chat.

        #44b/ — backed by the SAME bounded backup-model failover as
        :meth:`classify`: on a CAPABILITY/RESOURCE failure of the resolved model
        (won't load / OOM / embedding-only 400) each configured backup is tried
        in order (all on the SAME endpoint — no BAA boundary crossed); an
        ``LLMBackendUnreachableError`` propagates unchanged (the whole backend is
        down → the circuit breaker owns it). The per-attempt request body + the
        8192 ``num_predict`` ceiling rationale live in :meth:`_complete_once`.
        """
        model = await self._resolve_model()
        _served, text = await self._resilient_over_models(
            model,
            lambda m: self._complete_once(prompt, m),
            context="style-complete",
        )
        # N-372 (2026-07-05): belt-and-suspenders — with `think:false`
        # removed (Ollama bug #15260), qwen3 stock templates emit
        # `<think>...</think>` reasoning. Ollama 0.30+ ROUTES that to
        # ``message.thinking`` and only the post-thinking content into
        # ``message.content`` (which ``_complete_once`` returns), so
        # callers should already see clean text on the happy path. If a
        # future Ollama release or a different model routes the tags
        # into ``content`` instead, this strip catches it. Same helper
        # the parse-tier funnel already uses on ``_chat`` output —
        # every raw-completion caller (digest, style-profile, HIPAA
        # style distill, error-explain, action-guide) now gets a
        # think-tag-free string SSOT.
        return _strip_think_tags(text)

    async def _complete_once(self, prompt: str, model: str) -> str:
        """One Ollama /api/chat completion attempt against ``model`` — the inner
        call :meth:`_resilient_over_models` drives for the style-learning path.

        ``num_predict`` ceiling is generous (8192) because the ``think: False``
        flag is template-dependent — Qwen3 stock templates emit
        ``<think>...</think>`` reasoning regardless, and that reasoning bites
        into the same generation budget the actual answer needs. With a tight
        2048-token cap the explain-this-error path was hitting
        truncation in production: the screenshot operator caught on 2026-05-12
        showed an explanation cut mid-word at "provider's serve" — Ollama
        returned ``done_reason: "length"`` and the post-``</think>`` content was
        already eating most of the budget. 8192 is plenty for a 4-6 sentence
        explanation plus whatever chain-of-thought leaks.
        """
        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": self._maybe_append_no_think(prompt)},
            ],
            "stream": False,
            # N-378 (2026-07-08): `think` is a CONFIG KNOB
            # (``classifier.ollama_think``) — full story on ``_chat`` above.
            # 8192 ``num_predict`` ceiling stays (explain-this-error /
            # style-learning completions are wordier than a classify
            # verdict); the operator's `ollama_think: False` knob is what
            # actually caps reasoning-pass cost. ``/no_think`` marker
            # (belt-and-braces) applied to the user content above.
            "options": self._options(8192),
            **self._payload_think_extras(),
        }

        #  +  +  — shared circuit-breaker helper layered on
        # the long-lived client (same translation as _chat()).
        from email_triage.llm_health import translate_unreachable
        from email_triage._ollama_reuse import merge_reuse_options
        with translate_unreachable(
            "ollama", self._base_url, default_port=11434,
        ):
            client = await self._http.get()
            # N-431 (2026-07-19) — SSOT injects ``keep_alive`` (mandatory
            # wire field). The completion path was previously missing it —
            # Ollama's default "5m" would evict a Forever-pinned model
            # every 5 min silently.
            await merge_reuse_options(
                payload, self._base_url, model, client,
                default_keep_alive=self._keep_alive,
                timeout=self._probe_timeout,
            )
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()

        body = resp.json()
        raw_text = body.get("message", {}).get("content", "")
        #  silent-truncation guard — the ONE shared check. complete()'s 8192
        # ceiling makes a trip rare; when it does the answer is cut (the -A
        # 2026-05-12 "provider's serve" incident).
        _warn_if_truncated(body, model, context="complete")
        # Strip Qwen3 thinking tags if present.
        return _strip_think_tags(raw_text).strip()

    async def _resilient_over_models(
        self,
        primary_model: str,
        attempt: "Callable[[str], Awaitable[str]]",
        *,
        context: str,
    ) -> tuple[str, str]:
        """/ — the ONE backup-model failover loop, shared by the classify
        (``_chat``) path and the style-learning ``complete()`` path (PD#5: one
        failover SSOT, never two mirrored copies).

        Try ``primary_model``, then each configured backup model on a
        CAPABILITY/RESOURCE failure (``_is_failover_eligible`` — won't load, OOM,
        embedding-only 400); return ``(served_model, text)``. NEVER failover
        across an ``LLMBackendUnreachableError`` (all candidates share one
        endpoint → the whole backend is down → the circuit breaker owns it). A
        transient (429/5xx) / decode / generic error re-raises IN PLACE (retry
        queue), never a silent model swap. ``attempt(model)`` issues one request
        against ``model``; ``context`` is the log label ('classify' /
        'style-complete').
        """
        from email_triage.llm_health import LLMBackendUnreachableError

        if not self._backup_models:
            return primary_model, await attempt(primary_model)

        candidates = [primary_model] + [
            m for m in self._backup_models if m != primary_model
        ]
        last_exc: Exception | None = None
        for idx, cand in enumerate(candidates):
            try:
                text = await attempt(cand)
                if idx > 0:
                    logger.warning(
                        "Ollama: primary model failed; served by backup",
                        extra={
                            "context": context,
                            "provider": primary_model,
                            "name": cand,
                            "error_type": type(last_exc).__name__ if last_exc else "?",
                        },
                    )
                return cand, text
            except LLMBackendUnreachableError:
                # All candidates share one endpoint — unreachable means the
                # whole backend is down. Let the circuit breaker own it; never
                # failover across an unreachable backend.
                raise
            except Exception as exc:
                if not _is_failover_eligible(exc):
                    # Transient (429 / 5xx), decode, or generic error — retry IN
                    # PLACE via the retry queue. Do NOT silently serve a
                    # different model (and do NOT mislabel a transient blip as a
                    # capability failover in audit).
                    raise
                if idx == len(candidates) - 1:
                    raise  # eligible, but no candidates left to try
                logger.warning(
                    "Ollama: model hit a capability/resource error; trying backup",
                    extra={
                        "context": context,
                        "name": cand,
                        "error_type": type(exc).__name__,
                        "error_msg": str(exc)[:160],
                        "provider": candidates[idx + 1],
                    },
                )
                last_exc = exc
        # The loop always returns or raises; keeps type-checkers happy.
        raise last_exc if last_exc else RuntimeError(
            "no candidate models to run with"
        )

    async def _chat_resilient(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> tuple[str, str]:
        """ — try the primary ``model``, then each configured backup model
        on a CAPABILITY/RESOURCE failure; return ``(served_model, raw_text)``.

        Delegates to the shared :meth:`_resilient_over_models` loop (PD#5: ONE
        failover SSOT for classify + the style-learning ``complete()`` path —
        the two were a mirrored copy waiting to drift). ``LLMBackendUnreachable
        Error`` is NOT failed over (every candidate shares the endpoint, so
        unreachable means the whole backend is down — the circuit breaker's
        job); only model-specific capability/resource errors (embedding-only
        400, won't-load / OOM) fail over to a different model on the same box.
        """
        return await self._resilient_over_models(
            model,
            lambda m: self._chat(system_prompt, user_prompt, m),
            context="classify",
        )

    async def close(self) -> None:
        """Drain the long-lived httpx client. Idempotent."""
        await self._http.aclose()
