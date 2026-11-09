"""Abstract classifier interface for email triage.

All LLM backends implement this interface so the flow engine can classify
emails without knowing which backend is in use.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

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

from email_triage.triage_logging import account_hipaa_effective, get_logger  # N-196b R21_4
logger = get_logger("email_triage.classify")  # N-196b R21_4

#:  §4.4 DECOUPLE (2026-06-11). On the TOPIC-MATCH path the LLM free-forms a
#: core ``category`` that ignores the configured taxonomy (live logs: 225
#: off-taxonomy / 2h on the topic-match prompt vs 0 on core classify) — but the
#: core category is INCIDENTAL here: every consumer (back-scan / ephemeral
#: preview / live triage_one) reads only ``topic_verdicts``, never
#: ``classification.category``. An off-taxonomy category therefore must NOT
#: discard the verdicts (it did, via a raise → fail-open-drop → "topic digest
#: finds no matches"). When off-taxonomy we emit THIS neutral sentinel category
#: and keep the verdicts. It is inert: no consumer routes/persists it.
TOPIC_MATCH_OFFTAXONOMY_CATEGORY = "__offtaxonomy__"


class _TopicMatchCounters:
    """Topic-match parse-failure + retry-outcome counters (N-93, 2026-06-14).

    The bounded retry in :meth:`classify_with_topics` masks the SYMPTOM — the
    digest usually still gets verdicts — so without a counter the underlying
    qwen3.x ``format``-JSON malformation RATE (= how often the §4.4 fail-open
    valve opens) is only recoverable by grepping logs. These surface it as a
    number for ``/health`` (the devils-advocate N-93 NIT: "how often is the
    valve opening should be a number, not a log-grep"). Same process-local +
    best-effort-Redis-mirror shape as the classification-cache counters; values
    are pure integers — NO PHI / sender / subject / body (the
    ``persistent_counters`` privacy contract).
    """

    _PERSIST_NAMESPACE = "topic_match"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.parse_retried = 0          # 1st parse failed past salvage -> retried
        self.retry_recovered = 0        # the retry returned parseable JSON
        self.retry_failed_dropped = 0   # both failed -> fell open, verdicts dropped
        # The CANARY (DA N-93): a parse that needed lenient/salvage past STRICT
        # (incl. on the first try, where parse_retried stays 0). A rising rate
        # here = the source-side format-schema is silently degrading while the
        # digest stays green — invisible to parse_retried alone.
        self.salvage_recovered = 0

    def _mirror(self, field: str) -> None:
        # Best-effort HINCRBY to the install-level Redis backend (lifetime
        # accrual across restarts). Lazy import + swallow-all: a counter blip
        # must never break a classify.
        try:
            from email_triage.engine.persistent_counters import (
                get_install_counter_backend,
            )
            be = get_install_counter_backend()
            if be is not None:
                be.incr(self._PERSIST_NAMESPACE, field)
        except Exception:  # noqa: BLE001
            pass
        # N-385 (2026-07-10 wf_69674c7e-c67, HIGH) — Prometheus SSOT mirror.
        # Every `incr(field)` also lands on `et_topic_match_outcomes_total{
        # outcome=field}` so /metrics carries the parse-failure signal the
        # census flagged as invisible. Fail-open (the funnel already swallows).
        try:
            from email_triage.metrics import emit_topic_match_outcome
            emit_topic_match_outcome(field)
        except Exception:  # noqa: BLE001
            pass

    def incr(self, field: str) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + 1)
        self._mirror(field)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "parse_retried": self.parse_retried,
                "retry_recovered": self.retry_recovered,
                "retry_failed_dropped": self.retry_failed_dropped,
                "salvage_recovered": self.salvage_recovered,
            }


_topic_match_counters = _TopicMatchCounters()


def get_topic_match_counters() -> _TopicMatchCounters:
    """Process-level topic-match counter singleton (N-93)."""
    return _topic_match_counters


# ---------------------------------------------------------------------------
#  Topic-digest match result (design doc §4.2 / §4.4)
# ---------------------------------------------------------------------------


@dataclass
class TopicVerdict:
    """One LLM verdict on whether an email concerns a single research Topic.

    Parsed from the OPTIONAL ``topic_verdicts`` array the model emits on the
    topic-match path. ``reason_terms`` are which of the Topic's OWN listed
    terms matched — the operator's public text, **never** a quote of the email
    body (PHI-safety, §4.3 / R6). A garbled or absent array yields an empty
    verdict list (fail-open); the core classification still lands.
    """

    topic_id: object
    matched: bool
    confidence: float = 0.0
    reason_terms: tuple[str, ...] = ()


@dataclass
class TopicMatchResult:
    """The combined result of :meth:`classify_with_topics`.

    ``classification`` is the same :class:`Classification` the bare
    :meth:`classify` would have produced. ``topic_verdicts`` is the
    best-effort, fail-open list of per-Topic verdicts — **empty** whenever the
    topic-match parse failed, the model omitted the array, or any error/timeout
    hit (design §4.4: topic-match failure is decoupled from classify failure;
    a missing verdict is a no-op, never a raise).
    """

    classification: Classification
    topic_verdicts: list[TopicVerdict] = field(default_factory=list)


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
    # Census 2026-06-09: delegate to the hardened destination-locality SSOT.
    # This PHI→LLM BAA gate (§164.502(e) egress control) was a string-prefix
    # RFC1918 copy that fail-OPENed on a hostname like "10.evil.com" → PHI could
    # egress to an EXTERNAL host the gate believed was local. _netloc classifies
    # private IPs via the ipaddress module, so a hostname can't masquerade.
    from email_triage._netloc import is_local_destination
    return is_local_destination(url, extra_suffixes=tuple(extra_suffixes or ()))


def _parse_topic_verdicts(raw: object) -> list[TopicVerdict]:
    """Parse the OPTIONAL ``topic_verdicts`` array into typed verdicts.

     fail-open (design §4.4): a non-list ``raw`` (absent / wrong shape)
    yields ``[]``; a single malformed entry is skipped, not fatal. Every entry
    needs a ``topic_id``; ``matched`` is coerced to bool, ``confidence`` clamped
    to ``[0,1]``, and ``reason_terms`` kept as a tuple of strings (these are the
    Topic's own public terms, never a body quote — the prompt instructs the
    model accordingly; we do not, and cannot, re-validate against the body).
    """
    if not isinstance(raw, list):
        return []
    out: list[TopicVerdict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if "topic_id" not in entry or entry.get("topic_id") is None:
            continue
        try:
            conf = float(entry.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        terms_raw = entry.get("reason_terms") or []
        if isinstance(terms_raw, str):
            terms_raw = [terms_raw]
        reason_terms = tuple(
            str(t) for t in terms_raw if isinstance(t, (str, int, float))
        )
        out.append(
            TopicVerdict(
                topic_id=entry.get("topic_id"),
                matched=bool(entry.get("matched", False)),
                confidence=conf,
                reason_terms=reason_terms,
            )
        )
    return out


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

    async def _chat_resilient(
        self, system_prompt: str, user_prompt: str, model: str,
    ) -> tuple[str, str]:
        """Return ``(served_model, raw_text)``.

        Default: a single :meth:`_chat` attempt on ``model``. Subclasses
        may try configured backup models on a capability/resource
        failure and return whichever model actually served, so
        :meth:`classify` can stamp provenance and the dispatch layer can
        audit a failover. Availability failures
        (``LLMBackendUnreachableError``) are NOT failed over — the
        circuit breaker owns those — so they propagate unchanged.
        """
        text = await self._chat(system_prompt, user_prompt, model)
        return model, text

    async def _chat_topics(self, prompt: str, model: str) -> str:
        """Issue one topic-match chat request; return the raw model text.

         — the topic-match path (design §4.2) sends ONE assembled prompt
        string as the single leading message (NOT the system/user split that
        :meth:`_chat` uses), so the shared ``[system + email]`` prefix is
        byte-identical across Stage A and Stage B and only the Topic suffix
        re-prefills. The subclass owns the payload — and per §4.2.3 MUST pin
        ``keep_alive: "10m"`` and INHERIT the existing :meth:`_chat` options
        (no divergent ``num_ctx``), with Stage-A and Stage-B option dicts
        byte-identical.

        The default raises ``NotImplementedError``; HTTP chat backends that
        support the topic-match path (Ollama) override it. The caller
        (:meth:`classify_with_topics`) catches any error and falls open.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support topic-match classify"
        )

    async def _chat_safety(self, prompt: str, model: str) -> str:
        """ Stage-B hook — issue the safety-reporting determination chat and
        return the raw model text. Default raises; Ollama overrides. The caller
        (:meth:`classify_safety_reporting`) falls open on any non-transport
        error."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support safety-reporting classify"
        )

    async def classify_safety_reporting(
        self, message: EmailMessage, *, model: str | None = None,
    ):
        """ Stage-B — determine whether an email ASSERTS a current safety-
        reporting obligation. Returns a
        :class:`~email_triage.classify.safety_detect.SafetyVerdict`.

        A transport failure (whole backend down) PROPAGATES
        (``LLMBackendUnreachableError``) — the orchestrator handles it like any
        backend outage. A parse / other failure falls open to an UNPARSEABLE
        verdict (``parse_ok=False``).

        NOTE — the caller is NOT recall-safe, despite what this docstring said
        until 2026-09-17. ``safety_detect.detect_regulatory_clock`` treats
        ``parse_ok=False`` as NOT confirmed and returns None, so a Stage-B parse
        failure DROPS a possible safety deadline. That drop is the DOCUMENTED
        disposition, not an oversight: HIPAA register row N-97 records it as a
        deliberate, signed-off choice — drop rather than fabricate a candidate.
        This note only stops the docstring promising a recall-safety the code
        never implemented. Revisiting the disposition is a behaviour change,
        held out of the v0.2.0 freeze and tracked as N-476 (punch ).

        Watching it: the only DEDICATED trace is one WARNING,
        ``"safety-detect: Stage-B unparseable on a Stage-A hit"``. A counter
        does move 1:1 on this same path — the ``finally`` below emits
        ``emit_llm_outcome("classify", backend, "parse_failed")`` — but it is
        NOT a usable Stage-B alarm: ``et_llm_classify_total`` is labelled by
        backend+outcome only, ``metrics.py`` freezes ``_LLM_OPS`` at
        classify/chat/embed so this path shares ``op="classify"`` with the main
        one, and that path has its own nonzero malformation rate (see the note
        at module top). Watch the log line, not the counter.

        Reads the body (the documented minimum-necessary read for the
        assertion/ConText filter)."""
        from email_triage.classify.ollama import _parse_llm_json_tiered
        from email_triage.classify.prompts import build_safety_prompt
        from email_triage.classify.safety_detect import SafetyVerdict

        prompt = build_safety_prompt(message)
        if model is None:
            model = await self._resolve_model()
        # N-279 R29: wrap the LLM call in the classify latency timer
        # (same shape as the `classify` entry-point at line 643). Was
        # a missing site — one of 3 R29 flagged (INFO metric
        # completeness — bare fail-open call had no latency observability).
        # N-384 (2026-07-10 wf_69674c7e-c67, HIGH): route BOTH the success and
        # every failure edge through ``emit_llm_outcome`` — the timer records
        # p50/p95/p99 but was blind to failure rate.
        from email_triage import metrics as _metrics
        from email_triage.classify.baa_gate import _backend_for_classifier
        backend = _backend_for_classifier(self)
        outcome = "transport_error"  # default; overridden as we make progress
        try:
            with _metrics.timer(
                "et_llm_classify_seconds",
                backend=backend,
            ):
                raw = await self._chat_safety(prompt, model)
            try:
                parsed, _tier = _parse_llm_json_tiered(raw, log_ref={"message_id": getattr(message, "message_id", None), "provider": getattr(message, "provider", None)})
            except Exception:
                outcome = "parse_failed"
                return SafetyVerdict.unparseable()
            outcome = "success"
            return SafetyVerdict.from_parsed(parsed)
        finally:
            _metrics.emit_llm_outcome("classify", backend, outcome)

    async def classify_with_topics(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None,
        *,
        topic_block: str,
        model: str | None = None,
    ) -> TopicMatchResult:
        """Classify an email AND match it against the user's research Topics.

         INTERFACE CONTRACT (design §4.2 / §4.4):

        * Builds ONE prompt string via
          :func:`~email_triage.classify.prompts.build_topic_match_prompt`
          (BLOCK 1 shared prefix + ``topic_block`` suffix), issues a single
          :meth:`_chat_topics` call, and parses BOTH the classification object
          AND the OPTIONAL ``topic_verdicts`` array from one response.
        * **Fail-open on the topic side, decoupled from classify.** On ANY
          topic-parse miss / timeout / error, the verdicts are dropped, the
          event logged, and the bare :class:`Classification` returned alone —
          this method NEVER raises because of topic-match trouble (§4.4: a
          flaky GPU degrades the digest, never core triage).
        * The classification object is parsed as :meth:`classify` does, but —
          UNLIKE :meth:`classify` — an off-taxonomy core category is NOT a
          failure here (§4.4 decouple, 2026-06-11). The core category is
          incidental on the topic-match path (consumers read only
          ``topic_verdicts``), so an off-taxonomy category yields a neutral
          SENTINEL classification and the verdicts are KEPT. Only a transport
          failure (propagates) or a JSON-parse failure (drops) still yields no
          verdicts.

        ``topic_block`` is the BLOCK-2 suffix the caller renders (cards for
        Stage A, details for single-call / Stage-B rerank). ``model`` defaults
        to :meth:`_resolve_model`; passing it lets a Stage-B rerank pin the
        SAME model Stage A actually used (so the shortlist stays valid — §4.4).

        This method does NOT touch the classification cache: the topic-match
        prompt is a different prefix than the cached bare-classify prompt, and
        mixing them would poison the two-level cache. Topic-match is a
        digest-side path, not the hot classify cache path.
        """
        from email_triage.classify.ollama import _parse_llm_json_tiered
        from email_triage.classify.prompts import build_topic_match_prompt

        prompt = build_topic_match_prompt(
            message, categories, list_hints, topic_block,
        )
        if model is None:
            model = await self._resolve_model()

        # A transport / availability failure (circuit breaker) is NOT a
        # topic-match failure — it means the whole backend is down, which the
        # bare classify path would surface too. We do not swallow it here; the
        # caller decides whether to retry the whole message. Everything ELSE
        # (parse, garbled JSON, bad category, unexpected error) falls open to
        # an empty-verdict result so the digest never crashes core triage.
        # N-279 R29: wrap the LLM call in the classify latency timer
        # (same shape as `classify` at line 643). Missing site — the
        # topic-match call had no observability.
        # N-384 (2026-07-10 wf_69674c7e-c67, HIGH): route the success and every
        # failure edge through ``emit_llm_outcome`` — the timer records latency
        # but was blind to the parse-retry / parse-fail rate. Semantics —
        # PER-WHOLE-CALL (batched SME panel fold): exactly ONE emit per full
        # ``classify_with_topics`` call:
        #   * first attempt parse OK → ``"success"``
        #   * first attempt parse fail then retry parse OK → ``"parse_retry"``
        #   * every attempt unparseable → ``"parse_failed"`` (at the retry
        #     terminal — the first-attempt parse fail is silent because the
        #     retry immediately follows and its outcome represents the call)
        #   * transport error at either attempt → ``"transport_error"``
        #     (re-raised)
        # This matches every other timer site in the file, and keeps
        # ``sum(rate(et_llm_classify_total))`` equal to the per-call rate —
        # dashboards computed against the histogram's ``_count`` on the same
        # ``backend`` label join 1:1 with attempt count (the histogram records
        # per-attempt latency; the counter records per-call outcome).
        from email_triage import metrics as _metrics
        from email_triage.classify.baa_gate import _backend_for_classifier
        backend = _backend_for_classifier(self)
        try:
            with _metrics.timer(
                "et_llm_classify_seconds",
                backend=backend,
            ):
                raw_text = await self._chat_topics(prompt, model)
        except Exception:
            _metrics.emit_llm_outcome("classify", backend, "transport_error")
            raise
        logger.debug(
            "Topic-match LLM raw response", extra={"raw_len": len(raw_text)},
        )

        try:
            parsed, _tier = _parse_llm_json_tiered(raw_text, log_ref={"message_id": getattr(message, "message_id", None), "provider": getattr(message, "provider", None)})
            if _tier != "strict":
                # First-try recovery via lenient/salvage — the digest still got
                # its verdicts, but the model produced non-strict JSON: the
                # canary that the source-side format-schema is degrading.
                get_topic_match_counters().incr("salvage_recovered")
            _metrics.emit_llm_outcome("classify", backend, "success")
        except Exception as first_err:
            # The hardened parser (_decode_first_object) already salvages
            # control-char and truncated/premature-stop objects; reaching here
            # means the response was unrecoverable. The failure is intermittent
            # and content-specific (qwen3.x stops mid-object under format:json —
            # done_reason='stop', so the  truncation guard can't see it; the
            # 2026-06-14 'rtx 5090' eBay-promo class), so ONE re-roll at
            # temperature 0.3 almost always returns clean JSON. This is the
            # digest-side path only and a transport failure re-raises from
            # _chat_topics BEFORE here (a backend outage is never retried as a
            # parse failure) — so the retry is bounded at exactly one extra
            # call. The warning still fires on EACH miss (len only, no content →
            # PHI-safe) so the underlying rate stays observable, not masked.
            # NOTE: no pre-retry `emit_llm_outcome("classify", ..., "parse_failed")`
            # here — the retry-terminal emit at the bottom of this except block
            # speaks for the whole call (per-call semantics, batched SME panel
            # fold). Emitting BOTH pre-retry AND retry-terminal would inflate
            # `rate(parse_failed)` by every recovered retry and break the
            # per-call ratio dashboards Prometheus operators build against
            # `sum(et_llm_classify_total)`.
            logger.warning(
                "Topic-match parse failed; retrying once",
                extra={
                    "bytes": len(raw_text or ""),
                    "error_type": type(first_err).__name__,
                    "error_msg": str(first_err),
                },
            )
            get_topic_match_counters().incr("parse_retried")
            # N-279 R29: retry LLM call also under the timer — the retry
            # is real work + doubles the latency; observability must
            # capture BOTH the first attempt AND the retry so operators
            # see the true tail.
            try:
                with _metrics.timer(
                    "et_llm_classify_seconds",
                    backend=backend,
                ):
                    raw_text = await self._chat_topics(prompt, model)
            except Exception:
                _metrics.emit_llm_outcome("classify", backend, "transport_error")
                raise
            try:
                parsed, _rtier = _parse_llm_json_tiered(raw_text, log_ref={"message_id": getattr(message, "message_id", None), "provider": getattr(message, "provider", None)})
                get_topic_match_counters().incr("retry_recovered")
                if _rtier != "strict":
                    get_topic_match_counters().incr("salvage_recovered")
                _metrics.emit_llm_outcome("classify", backend, "parse_retry")
            except Exception as second_err:
                _metrics.emit_llm_outcome("classify", backend, "parse_failed")
                get_topic_match_counters().incr("retry_failed_dropped")
                logger.warning(
                    "Topic-match parse failed after retry; dropping verdicts, no classify",
                    extra={
                        "bytes": len(raw_text or ""),
                        "error_type": type(second_err).__name__,
                        "error_msg": str(second_err),
                    },
                )
                raise

        # Parse the classification object (same shape as classify()).
        # §4.4 DECOUPLE (2026-06-11): an off-taxonomy core category is NOT a
        # topic-match failure. The core category is incidental on this path —
        # consumers read only ``topic_verdicts`` — and the LLM free-forms
        # generic core slugs on the topic-match prompt (logs: 225 off-taxonomy
        # / 2h vs 0 on core classify), so the old ``raise`` discarded EVERY
        # verdict ("topic digest finds no matches"). Keep the verdicts; emit a
        # neutral SENTINEL category when off-taxonomy. A transport failure still
        # propagates (it never reaches here); a JSON-parse failure still drops
        # (handled above) — only the off-taxonomy case changes.
        category = parsed.get("category", "")
        if category not in categories:
            logger.info(
                "Topic-match: core category outside taxonomy; keeping verdicts with a neutral sentinel "
                "(off-taxonomy is expected on the topic-match prompt; the core category is unused here)",
                extra={"category": category},
            )
            classification = Classification(
                category=TOPIC_MATCH_OFFTAXONOMY_CATEGORY,
                confidence=0.0,
                reason=parsed.get("reason", ""),
                source="llm",
                served_model=model,
            )
        else:
            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))
            classification = Classification(
                category=category,
                confidence=confidence,
                reason=parsed.get("reason", ""),
                source="llm",
                served_model=model,
            )

        # Parse the OPTIONAL topic_verdicts array — fail-open per verdict so a
        # single malformed entry never sinks the whole list. Reached in BOTH
        # branches now (the off-taxonomy case no longer raises past it).
        verdicts = _parse_topic_verdicts(parsed.get("topic_verdicts"))
        return TopicMatchResult(
            classification=classification, topic_verdicts=verdicts,
        )

    async def classify_with_topics_safe(
        self,
        message: EmailMessage,
        categories: dict[str, str],
        list_hints: list[ListHint] | None,
        *,
        topic_block: str,
        model: str | None = None,
        fallback: Classification | None = None,
    ) -> TopicMatchResult:
        """Fail-open wrapper around :meth:`classify_with_topics`.

         §4.4 — the topic-match path must NEVER raise into the classify
        retry queue. :meth:`classify_with_topics` raises on a topic/parse miss
        (so the failure is visible to the test + this wrapper); this wrapper is
        the production entry point that swallows that raise and returns the
        classification alone. If ``fallback`` is supplied (the bare classify()
        result the caller already has), it is returned with empty verdicts; if
        not, the wrapper re-derives the classification via :meth:`classify`,
        and only if THAT also fails does it propagate (a genuine core-classify
        failure, not a topic-match one).
        """
        try:
            return await self.classify_with_topics(
                message, categories, list_hints,
                topic_block=topic_block, model=model,
            )
        except Exception as e:
            logger.warning(
                "Topic-match classify failed; falling open to core "
                "classify-only (no verdicts): %s", e,
            )
            if fallback is not None:
                return TopicMatchResult(
                    classification=fallback, topic_verdicts=[],
                )
            classification = await self.classify(
                message, categories, list_hints,
            )
            return TopicMatchResult(
                classification=classification, topic_verdicts=[],
            )

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
            logger.debug(
                "Classification cache lookup error",
                extra={"error_type": type(e).__name__, "error_msg": str(e)},
            )

        if cache_entry is not None:
            return cache_entry

        if hint_text:
            # NOT fenced as untrusted DATA on purpose. ``hint_text`` is built
            # by ``_hint_from_distribution`` purely from category SLUGS filtered
            # to ``cat in categories`` (the operator's OWN configured category
            # set) + integer counts — it carries no email body / subject /
            # sender string. It is the same trust class as the (intentionally
            # unfenced) categories block in the system prompt, so it rides in
            # the instruction region. An SME pass (2026-06-08) initially flagged
            # this as an untrusted surface off the "SENDER HISTORY" label;
            # tracing the source refuted that — recorded here so it isn't
            # re-flagged.
            system_prompt = (
                f"[SENDER HISTORY HINT] {hint_text}\n\n{system_prompt}"
            )

        # run17 #9 — hot-path LLM-call latency/count metric. The classify hot
        # path (the module's raison d'être) previously emitted ZERO metrics, so
        # a latency creep / rising-failure-rate on the model call was invisible
        # to /metrics. Time ONLY the model call. PD#8: telemetry is a
        # non-decisional side-effect — ``metrics.timer`` is fail-open (it
        # swallows any registry error around the wrapped body) and the backend
        # label reuses the _backend_for_classifier SSOT (a pure string op on the
        # class name → bounded enum: ollama / openaicompat / gemini), so
        # observability can NEVER break a classify.
        # N-384 (2026-07-10 wf_69674c7e-c67, HIGH): route both the success and
        # every failure edge through ``emit_llm_outcome`` — the timer records
        # latency but was blind to failure rate on the hot-path. The default
        # ``outcome = "transport_error"`` covers the bubble-through case where
        # ``_chat_resilient`` raises before we get past the ``with`` block.
        from email_triage import metrics as _metrics
        from email_triage.classify.baa_gate import _backend_for_classifier
        backend = _backend_for_classifier(self)
        outcome = "transport_error"
        try:
            with _metrics.timer(
                "et_llm_classify_seconds", backend=backend,
            ):
                served_model, raw_text = await self._chat_resilient(
                    system_prompt, user_prompt, model,
                )
            logger.debug("LLM raw response", extra={"raw_len": len(raw_text)})

            try:
                parsed = _parse_llm_json(raw_text, log_ref={"message_id": getattr(message, "message_id", None), "provider": getattr(message, "provider", None)})
            except Exception:
                outcome = "parse_failed"
                raise
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
                outcome = "off_taxonomy"
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
                served_model=served_model,
                failover_from=(model if served_model != model else None),
            )
            outcome = "success"

            # Best-effort two-level store; the HIPAA reason-strip happens
            # inside the helper. No-ops on a (None, None) key pair. 
            # — dispatched off the event loop via the async helper so a
            # stuck Redis can't pin the loop on socket_timeout (2.0s).
            try:
                # acache_store_for_message hoisted to module level.
                # Punch 601: the effective-HIPAA SSOT, not the raw stamp. The
                # Test Classify paste and the back-scan fallback reach here with
                # an unstamped message (default False), which cached the LLM
                # reason under a system-HIPAA install.
                await acache_store_for_message(
                    outer_key, inner_field, model, result, categories,
                    is_hipaa=account_hipaa_effective(message=message),
                )
            except Exception as e:
                logger.debug(
                    "Classification cache store error",
                    extra={"error_type": type(e).__name__, "error_msg": str(e)},
                )

            return result
        finally:
            _metrics.emit_llm_outcome("classify", backend, outcome)
