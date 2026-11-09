"""SSOT for the ``et_triage_runs_total`` Prometheus counter emit.

Extracted per Census v3 re-run  (MED): before this module, the
counter was emitted ONLY from the ``_emit_triage_run_outcome_metric``
decorator wrapping :func:`email_triage.web.triage_runner.run_triage`.
The other seven terminal triage paths (bulk, o365-poll, imap-poll,
gmail-push, o365-push, imap-watch, topic-backscan) never bumped the
counter → the Prometheus ``et_triage_runs_total`` metric read as
"only interactive UI/API triage runs happen", which is a factually
wrong observability story.

This module holds ONE emit helper reused by:
- The ``_emit_triage_run_outcome_metric`` decorator (triage_runner.py).
- :func:`email_triage.web.events.complete_triage_run` (bulk / poll SSOT).
- Follow-up drives folding the 4 hand-rolled push/watch/backscan sites
  onto :func:`complete_triage_run` (per Census v3 run19 D3).

Prime Directive #1: the SSOT ships with its count-agnostic structural
pin the same change (``tests/test_triage_run_counter_ssot_pin.py``).

Prime Directive #5 (bounded-vocab): a Prometheus counter's label
vocabulary MUST be bounded — otherwise a runaway trigger string blows
the label-cardinality budget. Both ``trigger`` and ``outcome`` are
coerced to a known frozenset here so callers can't drift the
vocabulary.
"""
from __future__ import annotations


#  tail (db-sme flag on the 2026-07-11 batched-panel) — hoisted from the
# inline per-call literal so a count-agnostic AST pin
# (``tests/test_triage_run_trigger_vocab_pin.py``) can walk the src tree and
# refuse any ``trigger=<literal>`` argument passed to
# :func:`complete_triage_run` or :func:`emit_triage_run_outcome_metric` that
# is not in the sanctioned set. Same pattern as
# :data:`triage_runner._TRIAGE_OUTCOMES` — bounded Prometheus label-
# cardinality. The 8 kinds cover every terminal triage path today:
# ``manual`` (fail-safe coercion, and interactive UI ad-hoc), ``api``
# (external ingest), ``watch`` (IMAP IDLE), ``push`` (Gmail + O365 push
# webhooks), ``scheduled`` (cron/quartz), ``poll`` (IMAP + O365 polling),
# ``bulk`` (bulk-sweep runner), ``backscan`` (topic-backscan job).
_TRIAGE_TRIGGERS: frozenset[str] = frozenset({
    "manual", "api", "watch", "push",
    "scheduled", "poll", "bulk", "backscan",
})


def emit_triage_run_outcome_metric(*, trigger: str, outcome: str) -> None:
    """Bump ``et_triage_runs_total{trigger, outcome}`` once.

    Fail-open: a metrics registry hiccup MUST NOT take down an ingest
    loop. Both label values are coerced to bounded vocabularies to
    prevent Prometheus label-cardinality bombs — the outcome
    vocabulary lives in :data:`triage_runner._TRIAGE_OUTCOMES` (the
    SSOT pinned by ``tests/test_triage_run_outcome_ssot_pin.py``);
    it is imported at call time to avoid a circular module load and
    to keep this module a pure import-side-effect-free metrics leaf.
    The trigger vocabulary lives in the module-level
    :data:`_TRIAGE_TRIGGERS` frozenset (SSOT pinned by
    ``tests/test_triage_run_trigger_vocab_pin.py``).
    """
    from email_triage.web.triage_runner import _TRIAGE_OUTCOMES
    trig = str(trigger) if str(trigger) in _TRIAGE_TRIGGERS else "manual"
    out = str(outcome) if str(outcome) in _TRIAGE_OUTCOMES else "error_other"
    try:
        from email_triage import metrics as _metrics
        _metrics.counter(
            "et_triage_runs_total",
            "Triage run outcomes by trigger and outcome.",
        ).inc(trigger=trig, outcome=out)
    except Exception:
        pass
