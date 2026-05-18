"""Tests for ``email_triage.metrics`` registry + render + endpoint."""

from __future__ import annotations

import time

import pytest

from email_triage import metrics as metrics_mod


@pytest.fixture(autouse=True)
def _reset_registry():
    """Each test starts with a clean registry."""
    metrics_mod.reset_all()
    yield
    metrics_mod.reset_all()


# ---------------------------------------------------------------------------
# Counter
# ---------------------------------------------------------------------------

def test_counter_default_zero():
    c = metrics_mod.counter("test_counter")
    assert c.value() == 0


def test_counter_inc_unlabeled():
    c = metrics_mod.counter("widgets_total")
    c.inc()
    c.inc(amount=5)
    assert c.value() == 6


def test_counter_inc_with_labels():
    c = metrics_mod.counter("auth_total")
    c.inc(surface="otp", outcome="success")
    c.inc(surface="otp", outcome="success")
    c.inc(surface="webauthn", outcome="success")
    assert c.value(surface="otp", outcome="success") == 2
    assert c.value(surface="webauthn", outcome="success") == 1
    assert c.value(surface="dev_keypair", outcome="success") == 0


def test_counter_label_order_independent():
    c = metrics_mod.counter("orderless_total")
    c.inc(a="x", b="y")
    c.inc(b="y", a="x")
    assert c.value(a="x", b="y") == 2


def test_counter_idempotent_registration():
    c1 = metrics_mod.counter("repeated")
    c2 = metrics_mod.counter("repeated")
    assert c1 is c2


# ---------------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------------

def test_histogram_observe():
    h = metrics_mod.histogram("latency_secs")
    h.observe(0.1, backend="ollama")
    h.observe(0.2, backend="ollama")
    h.observe(0.3, backend="ollama")
    cells = h.cells()
    assert len(cells) == 1
    values = next(iter(cells.values()))
    assert sorted(values) == [0.1, 0.2, 0.3]


def test_histogram_window_caps_observations():
    h = metrics_mod.histogram("capped")
    for i in range(2000):
        h.observe(float(i), kind="big")
    values = list(h.cells().values())[0]
    assert len(values) == metrics_mod._Histogram._WINDOW
    # Most recent observations win on a deque(maxlen=...).
    assert values[-1] == 1999.0


def test_timer_records_elapsed():
    h_name = "task_duration_secs"
    with metrics_mod.timer(h_name, kind="test"):
        time.sleep(0.01)
    h = metrics_mod.histogram(h_name)
    cells = h.cells()
    assert len(cells) == 1
    values = next(iter(cells.values()))
    assert values[0] >= 0.005  # sleep slack varies but >=5ms is safe


# ---------------------------------------------------------------------------
# render_text
# ---------------------------------------------------------------------------

def test_render_emits_help_and_type_lines():
    metrics_mod.counter(
        "doc_test_total", help_text="counter for the docstring sample",
    ).inc(label="x")
    out = metrics_mod.render_text()
    assert "# HELP doc_test_total counter for the docstring sample" in out
    assert "# TYPE doc_test_total counter" in out
    assert 'doc_test_total{label="x"} 1' in out


def test_render_empty_counter_emits_zero_line():
    metrics_mod.counter("empty_total")
    out = metrics_mod.render_text()
    assert "empty_total 0" in out


def test_render_histogram_quantiles():
    h = metrics_mod.histogram("hist_test")
    for v in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
        h.observe(v, q="x")
    out = metrics_mod.render_text()
    assert "hist_test_count" in out
    assert "hist_test_sum" in out
    assert 'quantile="0.5"' in out
    assert 'quantile="0.95"' in out
    assert 'quantile="0.99"' in out


def test_render_label_value_escaping():
    metrics_mod.counter("escapy").inc(text='hello "world"\nnewline')
    out = metrics_mod.render_text()
    assert "hello \\\"world\\\"\\nnewline" in out


# Endpoint integration tests live in tests/test_web/test_metrics_endpoint.py
# where the client / db / app fixtures are visible.
