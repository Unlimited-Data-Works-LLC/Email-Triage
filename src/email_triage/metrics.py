"""In-process Prometheus-format metrics registry.

PR 10 / E. /health is binary — a degradation that doesn't cross a
threshold (LLM p99 latency creeping from 3s to 12s, classifier
timeouts at 2% rising over weeks) produces no signal until something
actually breaks. This module is the wedge: a tiny in-process
registry of counters + histograms, rendered at ``GET /metrics`` in
the standard Prometheus text format. No external dependency — the
operator can scrape with curl or point an external Prometheus at
the endpoint later.

Design choices:

* **No external prometheus_client dep.** The text format is small
  and stable; reimplementing the rendering is ~30 LOC. Avoids a
  new runtime dep, lets us match the project's "no PHI in logs"
  scrubbing policy in the same shape as ``triage_logging``.

* **Labels-as-kwargs convention.** Mirrors ``TriageLogger.info``:

      metrics.counter("triage_runs_total").inc(category="invoices",
                                                outcome="completed")
      with metrics.timer("llm_requests", backend="ollama"):
          ...

* **Sliding-window histogram.** A 60-bucket fixed-size deque per
  histogram bounds memory regardless of traffic; percentile (p50 /
  p95 / p99) computed lazily on render. Operator gets enough signal
  for "latency creep" without paying for a full HDR-histogram
  implementation.

* **Cardinality discipline.** ``request_id`` is NEVER a label.
  Labels are bounded enums (provider, backend, outcome, category).
  Unbounded label values explode the registry's memory.

* **Thread/loop safety.** Counters are protected by a small
  threading.Lock; histograms by the same. The hot path is one
  attribute lookup + one int increment, so contention is minimal
  for any realistic single-instance deployment.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Iterator


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

class _Counter:
    """One named counter; per-label-set cell stored in a dict."""

    def __init__(self, name: str, help_text: str = "") -> None:
        self.name = name
        self.help_text = help_text
        self._cells: dict[tuple[tuple[str, str], ...], int] = {}
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
        # Sort keys so {k1: v, k2: w} and {k2: w, k1: v} hit same cell.
        return tuple(sorted(labels.items()))

    def inc(self, amount: int = 1, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._cells[key] = self._cells.get(key, 0) + int(amount)

    def value(self, **labels: str) -> int:
        return self._cells.get(self._key(labels), 0)

    def cells(self) -> dict[tuple[tuple[str, str], ...], int]:
        with self._lock:
            return dict(self._cells)

    def reset(self) -> None:
        with self._lock:
            self._cells.clear()


# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

class _Histogram:
    """Sliding-window observation set; render emits sum / count / p50 / p95 / p99."""

    _WINDOW = 1024  # max observations per label set

    def __init__(self, name: str, help_text: str = "") -> None:
        self.name = name
        self.help_text = help_text
        self._cells: dict[
            tuple[tuple[str, str], ...], deque[float]
        ] = {}
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
        return tuple(sorted(labels.items()))

    def observe(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            buf = self._cells.get(key)
            if buf is None:
                buf = deque(maxlen=self._WINDOW)
                self._cells[key] = buf
            buf.append(float(value))

    def cells(self) -> dict[tuple[tuple[str, str], ...], list[float]]:
        with self._lock:
            return {k: list(v) for k, v in self._cells.items()}

    def reset(self) -> None:
        with self._lock:
            self._cells.clear()


# ---------------------------------------------------------------------------
# Registry — module singleton
# ---------------------------------------------------------------------------

_counters: dict[str, _Counter] = {}
_histograms: dict[str, _Histogram] = {}
_registry_lock = threading.Lock()


def counter(name: str, help_text: str = "") -> _Counter:
    """Get-or-create a counter. Idempotent registration."""
    with _registry_lock:
        c = _counters.get(name)
        if c is None:
            c = _Counter(name, help_text)
            _counters[name] = c
        return c


def histogram(name: str, help_text: str = "") -> _Histogram:
    """Get-or-create a histogram. Idempotent registration."""
    with _registry_lock:
        h = _histograms.get(name)
        if h is None:
            h = _Histogram(name, help_text)
            _histograms[name] = h
        return h


@contextmanager
def timer(histogram_name: str, **labels: str) -> Iterator[None]:
    """Context manager that records elapsed wall-time into a histogram cell.

    Telemetry is a non-decisional side-effect (project PD#8): recording must
    NEVER break the wrapped body. Both the get-or-create and the observe are
    best-effort — any registry error is swallowed (fail-open) — so a metrics
    fault can't take down a hot path that wraps its work in a ``timer`` (the
    LLM classify call, run17 #9). The happy path is unchanged: the elapsed
    observation still lands on every normal call.
    """
    t0 = time.perf_counter()
    try:
        h: _Histogram | None = histogram(histogram_name)
    except Exception:  # pragma: no cover — get-or-create is lock + dict
        h = None
    try:
        yield
    finally:
        if h is not None:
            try:
                h.observe(time.perf_counter() - t0, **labels)
            except Exception:  # pragma: no cover — observe is lock + deque
                pass


def reset_all() -> None:
    """Test helper: clear every registered counter + histogram."""
    with _registry_lock:
        for c in _counters.values():
            c.reset()
        for h in _histograms.values():
            h.reset()


# ---------------------------------------------------------------------------
# LLM outcome counter twin funnel (N-384 — divergence census 2026-07-10,
# wf_69674c7e-c67, HIGH)
# ---------------------------------------------------------------------------
#
# The ~7 ``metrics.timer('et_llm_*_seconds', backend=...)`` wrappers across
# ``classify/base.py``, ``ai_backends/base.py``, ``engine/embedding_backend.py``
# and ``cli.py`` recorded latency but NEVER a paired outcome counter — so
# ``/metrics`` scrapes saw p50/p95/p99 for the LLM hot path but no failure-
# rate signal. A slow degradation (JSON parse rate falling from 99% to 90%,
# transport_error trickling in) was invisible to Prometheus / Grafana that
# ``metrics.py``'s own docstring courts.
#
# ``emit_llm_outcome`` is the funnel every timer body routes both its success
# edge and every failure edge through. Sibling of the ``record_login_success``/
# ``record_login_failure`` funnels in ``web/login_guard.py`` — Prime Directive
# 18 (SET/CLEAR through ONE funnel; the pin's interprocedural AST walk keeps
# hand-rolled counter calls from creeping back onto the timer sites).
#
# The interprocedural structural pin lives at
# ``tests/test_llm_timer_outcome_counter_pin.py``.
_LLM_OUTCOMES: frozenset[str] = frozenset({
    "success",           # LLM call returned parseable, on-taxonomy
    "parse_retry",       # first attempt unparseable, retry produced a parse
                         #   (call-level: represents a whole call that
                         #   recovered via retry — not a first-attempt outcome)
    "parse_failed",      # call ended without a parse (a single-attempt path
                         #   whose one attempt was unparseable, OR the retry
                         #   path whose retry ALSO failed) — verdict dropped
    "off_taxonomy",      # parseable JSON but the label was rejected by
                         #   downstream validation (raise ValueError etc.)
    "transport_error",   # HTTP / network / timeout / circuit breaker — the
                         #   LLM call itself failed before parsing
})
_LLM_OPS: frozenset[str] = frozenset({"classify", "chat", "embed"})


def emit_llm_outcome(op: str, backend: str, outcome: str) -> None:
    """Bump the outcome-counter twin for an ``et_llm_<op>_seconds`` timer.

    ``op`` — one of :data:`_LLM_OPS`, matching the timer's histogram suffix.
    ``backend`` — the model backend the timer wrapped (``"ollama"``, an
    ``OpenAIBackend`` name, etc.), same value used for the timer's
    ``backend=`` label so the two metrics join.
    ``outcome`` — one of :data:`_LLM_OUTCOMES`. An unknown value coerces to
    ``"transport_error"`` (fail-safe classification: never lose a signal by
    silently dropping it).

    Semantics — **PER-WHOLE-CALL**. Exactly one emit per full LLM call at
    the call's terminal outcome. Call sites that retry internally
    (``classify_with_topics``) collapse the retry sequence into a single
    call-level outcome:

      * first attempt parse OK → ``"success"``
      * first attempt parse fail then retry parse OK → ``"parse_retry"``
      * every attempt unparseable → ``"parse_failed"``
      * parseable but off-taxonomy → ``"off_taxonomy"``
      * transport fault at any attempt → ``"transport_error"``

    This keeps ``sum(rate(et_llm_<op>_total))`` equal to the per-call rate.
    The paired histogram (``et_llm_<op>_seconds``) records **per-attempt**
    latency samples (one observation per timer opening), so a retry
    contributes 2 histogram samples but 1 counter emit — dashboards
    computing ``rate(<outcome>) / rate(<total>)`` operate on per-call
    ratios, and ``histogram_count / counter_total`` yields the
    average-attempts-per-call.

    Fail-open per the same discipline as :func:`timer`: any registry hiccup
    is swallowed so a metrics fault can't take down a hot classify / embed
    path. The happy path is one dict get + one int increment.

    Callers MUST route BOTH the success edge (``outcome="success"``) and every
    failure edge (``parse_retry`` / ``parse_failed`` / ``off_taxonomy`` /
    ``transport_error``) through this funnel. The pin
    ``test_llm_timer_outcome_counter_pin.py`` walks the AST for
    ``with metrics.timer('et_llm_*_seconds', ...):`` blocks and refuses a body
    that does not reach ``emit_llm_outcome(...)`` on every terminal path.
    """
    if outcome not in _LLM_OUTCOMES:
        outcome = "transport_error"
    if op not in _LLM_OPS:
        # An unknown op is a caller bug, not a metric to invent — return
        # silently so the LLM call proceeds; the pin catches the typo at CI.
        return
    try:
        counter(
            f"et_llm_{op}_total",
            "LLM outcomes by backend and outcome (twin of "
            f"et_llm_{op}_seconds histogram).",
        ).inc(backend=str(backend), outcome=outcome)
    except Exception:  # pragma: no cover — get-or-create is lock + dict
        pass


# ---------------------------------------------------------------------------
# Counter-registry SSOT funnels (N-385 — divergence census 2026-07-10,
# wf_69674c7e-c67, HIGH)
# ---------------------------------------------------------------------------
#
# Before this change, the codebase carried FOUR independent counter registries
# for one intent ("per-event tally, labels-as-kwargs enum") and each callsite
# picked arbitrarily:
#
#   * ``email_triage.metrics`` singleton (→ ``/metrics``, Prometheus text
#     — the DOCUMENTED external-scrape surface),
#   * ``app.state.metrics`` dict (→ ``/health/detail``, admin/stats.html),
#   * ``persistent_counters`` Redis backend (→ install-lifetime totals),
#   * ``get_topic_match_counters`` (→ ``/health/detail`` topic block).
#
# An operator watching ``/metrics`` saw LLM latency but no webhook rate,
# no topic-match failure rate, no triage-runner throughput. The picked
# canonical is ``email_triage.metrics`` (Prometheus text = external
# operator-visible surface). The auxiliary registries STAY (they own
# distinct render surfaces — /health/detail JSON, install-lifetime totals)
# but every callsite that bumps one of them now ALSO mirrors to the
# singleton through a thin funnel:
#
#   * ``emit_webhook_event(kind)``   — the ``_inc_counter`` funnel in
#     ``web/routers/webhooks.py`` calls this on every webhook receipt.
#     Bumps ``et_webhook_events_total{kind=…}``.
#   * ``emit_topic_match_outcome(outcome)`` — the ``_TopicMatchCounters``
#     instance in ``classify/base.py`` calls this on every ``incr(...)``.
#     Bumps ``et_topic_match_outcomes_total{outcome=…}``.
#   * ``et_triage_runs_total{trigger, outcome}`` — the ``run_triage`` wrapper
#     in ``web/triage_runner.py`` bumps this DIRECTLY at the terminal (the
#     hot-path was carrying zero counters before — the "invisible triage
#     runner" the census called out).
#
# The interprocedural structural pin lives at
# ``tests/test_counter_registry_ssot_pin.py``.

def emit_webhook_event(kind: str) -> None:
    """Bump ``et_webhook_events_total{kind=<kind>}`` on the Prometheus SSOT.

    Called from ``web/routers/webhooks.py::_inc_counter`` — the single funnel
    every webhook counter caller already routes through — so all ~N sites get
    the singleton mirror without a per-site edit and the divergence pin has
    ONE interprocedural anchor to check.

    Fail-open per the same discipline as :func:`timer` — a metrics fault
    cannot take down the webhook receive path.
    """
    try:
        counter(
            "et_webhook_events_total",
            "Webhook events by kind (Prometheus mirror of "
            "app.state.metrics + persistent_counters['webhooks']).",
        ).inc(kind=str(kind))
    except Exception:  # pragma: no cover — get-or-create is lock + dict
        pass


def emit_topic_match_outcome(outcome: str) -> None:
    """Bump ``et_topic_match_outcomes_total{outcome=<outcome>}`` on the Prometheus SSOT.

    Called from ``classify/base.py::_TopicMatchCounters.incr`` — the single
    funnel every topic-match counter caller already routes through — so
    ``salvage_recovered`` / ``parse_retried`` / ``retry_recovered`` /
    ``retry_failed_dropped`` (and any future outcome) each get their singleton
    mirror without a per-site edit.

    Fail-open — a metrics fault cannot take down a topic-match parse path.
    """
    try:
        counter(
            "et_topic_match_outcomes_total",
            "Topic-match parse outcomes (Prometheus mirror of the in-memory "
            "get_topic_match_counters() dict rendered on /health/detail).",
        ).inc(outcome=str(outcome))
    except Exception:  # pragma: no cover — get-or-create is lock + dict
        pass


# ---------------------------------------------------------------------------
# Prometheus text rendering
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(round(q * (len(sorted_values) - 1)))
    return sorted_values[idx]


def _render_labels(labels_tuple: tuple[tuple[str, str], ...]) -> str:
    if not labels_tuple:
        return ""
    parts = [f'{k}="{_escape(v)}"' for k, v in labels_tuple]
    return "{" + ",".join(parts) + "}"


def _escape(s: str) -> str:
    return (
        str(s)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def render_text() -> str:
    """Produce the Prometheus text exposition format for every
    registered metric. Stable ordering (counters before histograms,
    alphabetical within each section) so a reader can diff over time.
    """
    out: list[str] = []

    with _registry_lock:
        c_items = sorted(_counters.items())
        h_items = sorted(_histograms.items())

    for name, c in c_items:
        if c.help_text:
            out.append(f"# HELP {name} {c.help_text}")
        out.append(f"# TYPE {name} counter")
        cells = c.cells()
        if not cells:
            out.append(f"{name} 0")
        else:
            for labels_tuple, val in sorted(cells.items()):
                out.append(f"{name}{_render_labels(labels_tuple)} {val}")

    for name, h in h_items:
        if h.help_text:
            out.append(f"# HELP {name} {h.help_text}")
        out.append(f"# TYPE {name} summary")
        cells = h.cells()
        if not cells:
            out.append(f"{name}_count 0")
            out.append(f"{name}_sum 0.0")
        else:
            for labels_tuple, values in sorted(cells.items()):
                ls = _render_labels(labels_tuple)
                count = len(values)
                total = sum(values)
                sv = sorted(values)
                p50 = _percentile(sv, 0.50)
                p95 = _percentile(sv, 0.95)
                p99 = _percentile(sv, 0.99)
                # Count + sum follow Prometheus summary convention.
                out.append(f"{name}_count{ls} {count}")
                out.append(f"{name}_sum{ls} {total:.6f}")
                # Quantiles encoded as separate label.
                # Render as <name>{...,quantile="0.95"} value
                base = labels_tuple
                for q, v in (("0.5", p50), ("0.95", p95), ("0.99", p99)):
                    extra = base + (("quantile", q),)
                    out.append(f"{name}{_render_labels(extra)} {v:.6f}")

    return "\n".join(out) + "\n"
