""" tail — trigger-vocabulary structural pin (db-sme flag on the
2026-07-11 batched-panel for the counter-emit convergence drive).

The Prometheus counter ``et_triage_runs_total{trigger, outcome}`` is
label-cardinality-bounded on BOTH axes so a runaway string can't blow
up the Prometheus TSDB. The outcome axis is enforced by
``triage_runner._TRIAGE_OUTCOMES`` + ``test_triage_run_outcome_ssot_pin.py``.
This pin enforces the SAME for the trigger axis: every literal
``trigger=<str>`` kwarg passed to either

  * :func:`email_triage.web.events.complete_triage_run`
  * :func:`email_triage.web.\
    _triage_metrics.emit_triage_run_outcome_metric`

must be a member of :data:`email_triage.web._triage_metrics._TRIAGE_TRIGGERS`
(``{"manual", "api", "watch", "push", "scheduled", "poll", "bulk",
"backscan"}``). A caller passing an unsanctioned literal like
``trigger="cron_job_v2"`` would ship a NEW cardinality axis the moment
its terminal ran — the runtime coercion in ``emit_triage_run_outcome_metric``
would silently map it to ``"manual"``, forever losing observability on
the intended new kind. Better to fail at CI: either the new kind is
sanctioned (add it to the SSOT set + this pin still passes) or the
literal is a typo/drift (caller edits).

Prime Directive #1: SSOT ships with count-agnostic structural pin same
change. This is that pin.

Prime Directive #6: routes through the shared ``_pin_harness`` walker.

Scope: only STRING-LITERAL trigger kwargs are checked. A dynamic
expression (``trigger=trigger_var``, ``trigger=some_call()``) is out
of scope — the runtime coercion catches it — but the pin's `TODO`
in the docstring names this deliberate residual so future widening
is documented.
"""
from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, relpath

# Direct-import the ONE runtime SSOT (DA F4 verdict on 2026-07-11 batched
# panel, echoing the ``SECRETS_SSOT_HOME`` hoist that just landed in the
# prior commit ``98fddb33``): a pin-local mirror + mirror-check would
# re-introduce the exact drift class PD #5/#6/#7 exist to eliminate. One
# frozenset, one home, no mirror-check needed — a maintainer widening the
# runtime SSOT automatically widens the pin.
from email_triage.web._triage_metrics import _TRIAGE_TRIGGERS as _SANCTIONED_TRIGGERS


# The two SSOT entry-points that accept ``trigger=`` as a keyword arg.
# Any call to either one anywhere in ``src/email_triage/**`` is a
# candidate. The pin refuses when the kwarg VALUE is a string literal
# not in :data:`_SANCTIONED_TRIGGERS`.
_TARGET_FUNCS: frozenset[str] = frozenset({
    "complete_triage_run",
    "emit_triage_run_outcome_metric",
})


def _iter_target_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # Match either a bare ``complete_triage_run(...)`` or a
        # ``module.complete_triage_run(...)`` attribute call — both live
        # inside `src/email_triage` so no upstream aliasing concern.
        if isinstance(f, ast.Name) and f.id in _TARGET_FUNCS:
            yield node
        elif isinstance(f, ast.Attribute) and f.attr in _TARGET_FUNCS:
            yield node


def _trigger_kwarg_literal(call: ast.Call) -> tuple[bool, str | None]:
    """Return (has_literal_trigger, literal_value). ``has_literal_trigger``
    is False when the ``trigger=`` kwarg is dynamic (out of pin scope) or
    absent. When True, ``literal_value`` is the string constant."""
    for kw in call.keywords:
        if kw.arg != "trigger":
            continue
        v = kw.value
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return True, v.value
        return False, None
    return False, None


def test_trigger_kwargs_use_sanctioned_vocab_only():
    """No caller may pass a ``trigger=<literal>`` outside the SSOT set."""
    offenders: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        rel = relpath(path)
        # Exempt the SSOT home itself (the coercion-source of truth).
        if rel.endswith("web/_triage_metrics.py"):
            continue
        for call in _iter_target_calls(tree):
            has_lit, val = _trigger_kwarg_literal(call)
            if not has_lit:
                continue
            if val not in _SANCTIONED_TRIGGERS:
                fn = getattr(call.func, "attr", None) or getattr(
                    call.func, "id", "?",
                )
                offenders.append(
                    f"{rel}:{call.lineno}  {fn}(trigger={val!r}, ...)"
                )
    assert not offenders, (
        " tail trigger-vocab pin: every literal `trigger=<str>` kwarg "
        "passed to `complete_triage_run(...)` or "
        "`emit_triage_run_outcome_metric(...)` must be a member of the "
        "SSOT `_TRIAGE_TRIGGERS` set "
        f"({sorted(_SANCTIONED_TRIGGERS)}) — the runtime coerces unknown "
        "triggers to 'manual', silently losing the new-kind observability "
        "you probably intended. Add the kind to `_TRIAGE_TRIGGERS` (+ this "
        "pin's mirror) if it is a legit new terminal; fix the typo/drift "
        "otherwise.\n\n" + "\n".join(offenders)
    )


# Note: no mirror-check test needed. Per DA F4 on the 2026-07-11 batched
# panel: the pin uses ``from email_triage.web._triage_metrics import
# _TRIAGE_TRIGGERS as _SANCTIONED_TRIGGERS`` at module top so there IS
# only one SSOT constant — no local literal to drift from the runtime.
# A widening of the runtime SSOT automatically widens the pin. This is
# the shape ``SECRETS_SSOT_HOME`` landed in commit ``98fddb33`` (2026-07-11
# batched-panel drive  + ); repeating the mirror-with-check
# pattern here would re-open the exact class those commits closed.


# ---------------------------------------------------------------------------
#  (DA F3 + DB-SME follow-up from  batched panel) — widen the
# trigger-vocab pin to also flag NON-LITERAL ``trigger=<expr>`` kwargs.
#
# The literal-only pin above catches the class of drift the DB-SME follow-
# up flagged as "acceptable now with runtime-coercion safety net" — but per
# DA F3, a future refactor piping ``trigger`` through a config or CLI arg
# dodges the pin entirely, and the runtime coercion silently loses the
# new-kind observability the caller intended. This second test extends
# structural coverage: any ``trigger=<Name|Attribute|Call>`` (dynamic-
# expr) kwarg passed to the target SSOT funcs is an offender unless the
# ``(rel, lineno)`` is in the opt-in allow-list below.
#
# The allow-list is SEEDED EMPTY at HEAD — all callers at the time of this
# widening (2026-07-11 landing on top of ``1508d3d0``) pass string
# literals. If a future legit dynamic use case arrives (e.g. a config-
# driven trigger for an admin-configurable ingest pipeline), the caller
# adds an entry AND justifies it with a comment. Same shape as
# ``test_new_run_id_ssot_pin.py::_NAMED_DEVIATIONS``.
# ---------------------------------------------------------------------------


#  (2026-07-11) name-anchored migration: `(rel, enclosing_fn)` shape
# survives unrelated line shifts. `enclosing_fn` is the harness SSOT
# (R38, `_pin_harness:164`).
_ALLOW_NON_LITERAL_TRIGGER_SITES: frozenset[tuple[str, str]] = frozenset({
    # web/events.py::complete_triage_run — the SSOT itself; the
    # ``trigger`` value is a function parameter passed through from the
    # sanctioned-literal caller above. The SSOT is the routing point
    # where the literal-vs-dynamic distinction collapses; a literal
    # check at the SSOT body would require the SSOT to hard-code a
    # per-terminal switch which is anti-SSOT.
    ("web/events.py", "complete_triage_run"),
    # web/triage_runner.py::_wrapped — inside the closure of the
    # ``_emit_triage_run_outcome_metric`` decorator; the ``trigger``
    # value is the decorated function's param passed through. Same
    # shape as complete_triage_run — SSOT-internal dispatch.
    ("web/triage_runner.py", "_wrapped"),
})


def _trigger_kwarg_is_dynamic(call: ast.Call) -> bool:
    """True when the ``trigger=`` kwarg is a NON-LITERAL expression (Name,
    Attribute, Call, BinOp, IfExp, ...) — i.e. the value is not
    statically resolvable to a string constant at parse time. Callers that
    pass a f-string, `.format`, `str(x)`, or a variable-bound trigger all
    match here."""
    for kw in call.keywords:
        if kw.arg != "trigger":
            continue
        v = kw.value
        # A Constant string is the LITERAL case handled by the sanctioned-
        # vocab check above; anything else is dynamic-expr.
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return False
        return True
    return False


def test_trigger_kwargs_reject_non_literal_exprs():
    """No caller may pass a NON-LITERAL ``trigger=<expr>`` kwarg to a
    trigger-emitting SSOT. Runtime coercion (`_triage_metrics.py:63`)
    silently maps unknown triggers to ``"manual"``, so a dynamic-expr
    caller that intended to ship a new kind loses the observability.
    Route through the sanctioned-vocab literal, or add a
    ``(rel, lineno)`` allow-list entry with a justification comment."""
    offenders: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        rel = relpath(path)
        if rel.endswith("web/_triage_metrics.py"):
            continue
        for call in _iter_target_calls(tree):
            if not _trigger_kwarg_is_dynamic(call):
                continue
            key = (rel, enclosing_fn(call))
            if key in _ALLOW_NON_LITERAL_TRIGGER_SITES:
                continue
            fn = getattr(call.func, "attr", None) or getattr(
                call.func, "id", "?",
            )
            offenders.append(
                f"{rel}:{call.lineno}  {fn}(trigger=<non-literal expr>, ...)"
            )
    assert not offenders, (
        " trigger-vocab widening: a dynamic-expr `trigger=` kwarg "
        "silently loses new-kind observability via the runtime "
        "'manual' coercion. Pass a sanctioned literal from "
        f"{sorted(_SANCTIONED_TRIGGERS)}. If a legit dynamic use case "
        "exists, add `(rel, enclosing_fn)` to `_ALLOW_NON_LITERAL_TRIGGER_SITES` "
        "with a justification comment.\n\n" + "\n".join(offenders)
    )
