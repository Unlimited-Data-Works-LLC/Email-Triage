"""the backlog  (Census v3 re-run counter-emission MED) — SSOT pin.

Structural: the ``et_triage_runs_total`` Prometheus counter's ``.inc(...)``
call may appear in EXACTLY ONE module — ``web/_triage_metrics.py`` —
the SSOT emit funnel. Every other terminal triage path routes through
:func:`emit_triage_run_outcome_metric`.

Before this pin, ``triage_runner._emit_triage_run_outcome_metric``
inlined its own ``.counter(...).inc(...)`` call. Adding the same emit
at :func:`complete_triage_run` (bulk / poll / imap-poll terminal
SSOT) created a 2-site duplication with the trigger/outcome
vocabulary drifting independently. This pin freezes ONE emit-shape
so a future label change lands once.

Also enforces the bounded-vocab guard by refusing to close a class
whose ``trigger`` frozenset drifts from
:data:`_TRIAGE_METRIC_TRIGGERS` (label-cardinality bomb prevention).

Prime Directive #6: routes through the shared ``_pin_harness`` walker.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_METRIC_NAME = "et_triage_runs_total"
_SSOT_RELPATH = "web/_triage_metrics.py"


def _string_literal_of(expr: ast.AST) -> str | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    return None


def _is_forbidden_counter_inc(node: ast.AST) -> bool:
    """Return True if this AST node is a
    ``<something>.counter("et_triage_runs_total", ...).inc(...)`` chain.
    """
    if not isinstance(node, ast.Call):
        return False
    outer_func = node.func
    if not isinstance(outer_func, ast.Attribute) or outer_func.attr != "inc":
        return False
    inner = outer_func.value
    if not isinstance(inner, ast.Call):
        return False
    inner_func = inner.func
    if not isinstance(inner_func, ast.Attribute) or inner_func.attr != "counter":
        return False
    if not inner.args:
        return False
    name = _string_literal_of(inner.args[0])
    return name == _METRIC_NAME


def test_et_triage_runs_total_inc_only_in_ssot():
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_RELPATH:
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_forbidden_counter_inc(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        f"Census  counter-SSOT: `{_METRIC_NAME}` counter `.inc(...)` "
        f"landed OUTSIDE the SSOT `{_SSOT_RELPATH}::emit_triage_run_"
        "outcome_metric`. Route through the SSOT so a label-vocabulary "
        "or emit-shape change lands once, not per-site:\n\n" +
        "\n".join(offenders)
    )
