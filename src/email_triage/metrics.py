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
    """Context manager that records elapsed wall-time into a
    histogram cell."""
    h = histogram(histogram_name)
    t0 = time.perf_counter()
    try:
        yield
    finally:
        h.observe(time.perf_counter() - t0, **labels)


def reset_all() -> None:
    """Test helper: clear every registered counter + histogram."""
    with _registry_lock:
        for c in _counters.values():
            c.reset()
        for h in _histograms.values():
            h.reset()


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
