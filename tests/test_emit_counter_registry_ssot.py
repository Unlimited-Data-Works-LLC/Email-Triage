"""Behavior tests for the N-385 counter-registry SSOT funnels
(:func:`emit_webhook_event`, :func:`emit_topic_match_outcome`) and the
``et_triage_runs_total`` decorator wrapper on :func:`run_triage`.

Verifies:
* the funnels bump the correct Prometheus-mirror counter cell,
* the mirror callsites (``_inc_counter``, ``_TopicMatchCounters._mirror``)
  do fire the funnel when invoked end-to-end,
* the ``_emit_triage_run_outcome_metric`` decorator emits
  ``et_triage_runs_total`` with the correct trigger + outcome labels.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from email_triage import metrics


@pytest.fixture(autouse=True)
def _isolate_registry():
    metrics.reset_all()
    yield
    metrics.reset_all()


# ---------------------------------------------------------------------------
# Funnel behavior
# ---------------------------------------------------------------------------

class TestEmitWebhookEvent:
    def test_bumps_labelled_cell(self):
        metrics.emit_webhook_event("gmail_push")
        c = metrics.counter("et_webhook_events_total")
        assert c.value(kind="gmail_push") == 1

    def test_repeated_calls_accumulate(self):
        for _ in range(3):
            metrics.emit_webhook_event("o365_change")
        c = metrics.counter("et_webhook_events_total")
        assert c.value(kind="o365_change") == 3

    def test_distinct_kinds_are_distinct_cells(self):
        metrics.emit_webhook_event("a")
        metrics.emit_webhook_event("b")
        c = metrics.counter("et_webhook_events_total")
        assert c.value(kind="a") == 1
        assert c.value(kind="b") == 1

    def test_fail_open_on_registry_error(self):
        """A metrics fault MUST NOT propagate — the webhook receive path is
        never blocked by observability."""
        from unittest.mock import patch

        class _Explode:
            def inc(self, **_kw):
                raise RuntimeError("registry blew up")

        with patch.object(metrics, "counter", return_value=_Explode()):
            metrics.emit_webhook_event("gmail_push")  # must not raise


class TestEmitTopicMatchOutcome:
    def test_bumps_labelled_cell(self):
        metrics.emit_topic_match_outcome("salvage_recovered")
        c = metrics.counter("et_topic_match_outcomes_total")
        assert c.value(outcome="salvage_recovered") == 1

    def test_each_outcome_gets_its_own_cell(self):
        for outcome in ("parse_retried", "retry_recovered",
                        "retry_failed_dropped", "salvage_recovered"):
            metrics.emit_topic_match_outcome(outcome)
        c = metrics.counter("et_topic_match_outcomes_total")
        for outcome in ("parse_retried", "retry_recovered",
                        "retry_failed_dropped", "salvage_recovered"):
            assert c.value(outcome=outcome) == 1


# ---------------------------------------------------------------------------
# End-to-end wire — the callsite funnels DO invoke the mirrors.
# ---------------------------------------------------------------------------

class TestTopicMatchCountersMirror:
    def test_incr_fires_prometheus_mirror(self):
        """``_TopicMatchCounters.incr(field)`` MUST bump both its own in-memory
        counter AND ``et_topic_match_outcomes_total{outcome=field}`` on the
        Prometheus SSOT."""
        from email_triage.classify.base import get_topic_match_counters
        tm = get_topic_match_counters()
        # Baseline snapshot — a fresh test-isolated registry has no cell yet.
        assert metrics.counter("et_topic_match_outcomes_total").value(
            outcome="parse_retried"
        ) == 0
        tm.incr("parse_retried")
        c = metrics.counter("et_topic_match_outcomes_total")
        assert c.value(outcome="parse_retried") == 1

    def test_all_four_documented_fields_mirror(self):
        from email_triage.classify.base import get_topic_match_counters
        tm = get_topic_match_counters()
        # Zero the in-memory counters so the parametrized-style loop is clean.
        tm.parse_retried = 0
        tm.retry_recovered = 0
        tm.retry_failed_dropped = 0
        tm.salvage_recovered = 0
        for field in ("parse_retried", "retry_recovered",
                      "retry_failed_dropped", "salvage_recovered"):
            tm.incr(field)
        c = metrics.counter("et_topic_match_outcomes_total")
        for field in ("parse_retried", "retry_recovered",
                      "retry_failed_dropped", "salvage_recovered"):
            assert c.value(outcome=field) == 1


class TestWebhooksIncCounterMirror:
    def test_inc_counter_fires_prometheus_mirror(self):
        """``_inc_counter(request, key)`` MUST bump ``et_webhook_events_total
        {kind=key}`` in addition to the process-local ``app.state.metrics``
        dict and the Redis mirror."""
        from email_triage.web.routers.webhooks import _inc_counter

        req = MagicMock()
        req.app.state.metrics = {}

        _inc_counter(req, "gmail_push")
        assert req.app.state.metrics == {"gmail_push": 1}

        c = metrics.counter("et_webhook_events_total")
        assert c.value(kind="gmail_push") == 1


class TestRunTriageOutcomeDecorator:
    def test_decorator_emits_et_triage_runs_total_success(self):
        """The wrapper MUST bump ``et_triage_runs_total{trigger, outcome}``
        with ``outcome='success'`` when the wrapped fn returns a
        TriageRunResult with no ``error`` key."""
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult(run_id="r1", elapsed_secs=0.1)

        asyncio.run(_fake_run(trigger="manual"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="manual", outcome="success") == 1

    def test_decorator_emits_error_outcome_on_error_key(self):
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult(run_id="", error="user_disabled")

        asyncio.run(_fake_run(trigger="api"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="api", outcome="user_disabled") == 1
        assert c.value(trigger="api", outcome="success") == 0

    def test_decorator_emits_on_exception(self):
        """The wrapper is a fail-CLOSED observer: an exception in the wrapped
        run still fires the metric with ``outcome='error'``, then re-raises."""
        from email_triage.web.triage_runner import _emit_triage_run_outcome_metric

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            raise RuntimeError("blew up")

        with pytest.raises(RuntimeError, match="blew up"):
            asyncio.run(_fake_run(trigger="scheduled"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="scheduled", outcome="error") == 1

    def test_decorator_default_trigger_is_manual(self):
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult()

        asyncio.run(_fake_run())
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="manual", outcome="success") == 1

    def test_metrics_fault_does_not_hide_the_result(self):
        """Fail-open observability: even if the counter registry throws, the
        wrapped fn's return value must still bubble through."""
        from unittest.mock import patch
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult(run_id="ok")

        class _Explode:
            def inc(self, **_kw):
                raise RuntimeError("registry blew up")

        with patch.object(metrics, "counter", return_value=_Explode()):
            result = asyncio.run(_fake_run(trigger="manual"))
        assert result["run_id"] == "ok"

    def test_decorator_fail_closed_on_non_dict_return(self):
        """N-385 batched SME panel fold — a wrapped fn returning None (or any
        object without `.get`) is a CONTRACT BUG, not a healthy run. Classify
        as `outcome='error'` (fail-CLOSED per feedback_just_be_honest), NOT
        `outcome='success'`."""
        from email_triage.web.triage_runner import _emit_triage_run_outcome_metric

        @_emit_triage_run_outcome_metric
        async def _fake_run_returns_none(**kw):
            return None

        asyncio.run(_fake_run_returns_none(trigger="watch"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="watch", outcome="error") == 1
        assert c.value(trigger="watch", outcome="success") == 0

    def test_decorator_bare_object_return_fails_closed(self):
        """Same fail-CLOSED discipline for a bare object without .get."""
        from email_triage.web.triage_runner import _emit_triage_run_outcome_metric

        class _WrongShape:  # no .get method
            pass

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return _WrongShape()

        asyncio.run(_fake_run(trigger="api"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="api", outcome="error") == 1
        assert c.value(trigger="api", outcome="success") == 0

    def test_decorator_coerces_unknown_error_slug_to_error_other(self):
        """N-385 batched SME panel fold — an unknown error slug (not in
        _TRIAGE_OUTCOMES) MUST NOT flow onto the Prometheus label. It coerces
        to `error_other` — the fail-safe sentinel (mirrors emit_llm_outcome's
        transport_error coerce)."""
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult(error="some_future_slug_2027")

        asyncio.run(_fake_run(trigger="manual"))
        c = metrics.counter("et_triage_runs_total")
        assert c.value(trigger="manual", outcome="error_other") == 1
        assert c.value(trigger="manual", outcome="some_future_slug_2027") == 0

    def test_decorator_bounded_vocab_documented_slugs_pass_through(self):
        """Every slug in _TRIAGE_OUTCOMES passes through the coerce
        UN-transformed — the fail-safe only fires on unknowns."""
        from email_triage.web.triage_runner import (
            TriageRunResult, _emit_triage_run_outcome_metric, _TRIAGE_OUTCOMES,
        )

        @_emit_triage_run_outcome_metric
        async def _fake_run(**kw):
            return TriageRunResult(error=kw.get("_stub_error"))

        # error='' (empty) → 'success' via the `or 'success'` fallback
        # error=<slug> in _TRIAGE_OUTCOMES → slug preserved
        # error='success' would collide (kwarg gets stripped by 'or') — cover the real slugs.
        for slug in ("user_disabled", "no_categories",
                     "provider_error", "classifier_error", "baa_required"):
            asyncio.run(_fake_run(trigger="manual", _stub_error=slug))
        c = metrics.counter("et_triage_runs_total")
        for slug in ("user_disabled", "no_categories",
                     "provider_error", "classifier_error", "baa_required"):
            assert c.value(trigger="manual", outcome=slug) == 1, (
                f"documented slug {slug!r} did not pass through the coerce"
            )
        # error_other should NOT have fired for any of these.
        assert c.value(trigger="manual", outcome="error_other") == 0
