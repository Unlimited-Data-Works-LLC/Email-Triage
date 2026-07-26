"""Behavior tests for :func:`email_triage.metrics.emit_llm_outcome` (N-384).

The funnel is the outcome-counter twin of the ``et_llm_*_seconds`` histogram
family. These tests exercise the funnel directly and assert:

* every registered outcome lands on its own labelled counter cell,
* an unknown ``outcome`` string coerces to ``"transport_error"`` (fail-safe
  classification: never lose a signal by silently dropping it),
* an unknown ``op`` short-circuits without registering a phantom counter,
* the funnel fails open — a registry hiccup does not propagate.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from email_triage import metrics


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Test isolation — clear the module singleton before AND after each
    test so counter state does not leak across the file."""
    metrics.reset_all()
    yield
    metrics.reset_all()


class TestEmitLlmOutcomeHappyPath:
    def test_success_lands_on_labelled_cell(self):
        metrics.emit_llm_outcome("classify", "ollama", "success")
        c = metrics.counter("et_llm_classify_total")
        assert c.value(backend="ollama", outcome="success") == 1

    def test_each_outcome_gets_its_own_cell(self):
        for outcome in ("success", "parse_retry", "parse_failed",
                        "off_taxonomy", "transport_error"):
            metrics.emit_llm_outcome("classify", "ollama", outcome)
        c = metrics.counter("et_llm_classify_total")
        for outcome in ("success", "parse_retry", "parse_failed",
                        "off_taxonomy", "transport_error"):
            assert c.value(backend="ollama", outcome=outcome) == 1, (
                f"outcome {outcome!r} did not land on its own cell"
            )

    def test_each_op_gets_its_own_counter(self):
        for op in ("classify", "chat", "embed"):
            metrics.emit_llm_outcome(op, "ollama", "success")
            c = metrics.counter(f"et_llm_{op}_total")
            assert c.value(backend="ollama", outcome="success") == 1

    def test_repeated_emit_increments(self):
        for _ in range(3):
            metrics.emit_llm_outcome("chat", "ollama", "success")
        c = metrics.counter("et_llm_chat_total")
        assert c.value(backend="ollama", outcome="success") == 3

    def test_different_backends_are_distinct_cells(self):
        metrics.emit_llm_outcome("embed", "ollama", "success")
        metrics.emit_llm_outcome("embed", "openai", "success")
        c = metrics.counter("et_llm_embed_total")
        assert c.value(backend="ollama", outcome="success") == 1
        assert c.value(backend="openai", outcome="success") == 1


class TestEmitLlmOutcomeCoercion:
    def test_unknown_outcome_coerces_to_transport_error(self):
        metrics.emit_llm_outcome("classify", "ollama", "mystery_outcome_2027")
        c = metrics.counter("et_llm_classify_total")
        assert c.value(backend="ollama", outcome="transport_error") == 1
        assert c.value(backend="ollama", outcome="mystery_outcome_2027") == 0

    def test_unknown_op_silent_noop(self):
        # An unknown op is a caller typo — do NOT invent a phantom counter.
        metrics.emit_llm_outcome("mysterious_op", "ollama", "success")
        # A cell for et_llm_mysterious_op_total must NOT have been created.
        # Snapshot: the module-level _counters dict has no such entry.
        assert "et_llm_mysterious_op_total" not in metrics._counters

    def test_unknown_op_does_not_touch_known_counters(self):
        metrics.emit_llm_outcome("classify", "ollama", "success")  # baseline
        metrics.emit_llm_outcome("mysterious_op", "ollama", "success")  # noop
        c = metrics.counter("et_llm_classify_total")
        # The baseline is unchanged — an unknown-op call must not spill
        # to the wrong counter.
        assert c.value(backend="ollama", outcome="success") == 1


class TestEmitLlmOutcomeFailOpen:
    def test_registry_error_does_not_propagate(self):
        """Fail-open contract (per docstring): a metrics fault cannot take
        down a hot LLM path."""

        class _Explode:
            def inc(self, **_kw):
                raise RuntimeError("registry blew up")

        with patch.object(metrics, "counter", return_value=_Explode()):
            # Must NOT raise.
            metrics.emit_llm_outcome("classify", "ollama", "success")

    def test_returns_none(self):
        """The funnel is a fire-and-forget side effect — return None
        (test-guards against a caller starting to depend on a value)."""
        assert metrics.emit_llm_outcome("classify", "ollama", "success") is None


class TestVocabularySSOT:
    def test_all_outcome_labels_are_the_documented_set(self):
        # SSOT introspection guard: if a future edit adds or removes an
        # outcome from _LLM_OUTCOMES, this test fails to force an audit of
        # the count-agnostic pin's `_LLM_OUTCOMES` mirror.
        assert metrics._LLM_OUTCOMES == frozenset({
            "success", "parse_retry", "parse_failed",
            "off_taxonomy", "transport_error",
        })

    def test_all_op_labels_are_the_documented_set(self):
        assert metrics._LLM_OPS == frozenset({"classify", "chat", "embed"})
