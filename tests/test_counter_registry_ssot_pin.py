"""Counter-registry SSOT — count-agnostic structural pin
(N-385, divergence census wf_69674c7e-c67 2026-07-10, HIGH).

Before this landing, the codebase carried FOUR independent counter registries
for one intent ("per-event tally, labels-as-kwargs enum") — the
``email_triage.metrics`` singleton (→ ``/metrics``), the ``app.state.metrics``
dict (→ ``/health/detail``), ``persistent_counters`` Redis (→ install-lifetime
totals), and ``get_topic_match_counters`` (→ ``/health/detail`` topic block)
— and each callsite picked arbitrarily. An operator watching ``/metrics``
saw LLM latency but NO webhook rate, no topic-match failure rate, no
triage-runner throughput. The core ``web/triage_runner.py`` hot path emitted
ZERO counters of any kind.

The fix picks ``email_triage.metrics`` (Prometheus text format — the
documented external-scrape surface) as canonical and mirrors the three
auxiliary registries through thin funnels:

  * ``_inc_counter`` (``web/routers/webhooks.py``) mirrors via
    ``emit_webhook_event(kind)``.
  * ``_TopicMatchCounters._mirror`` (``classify/base.py``) mirrors via
    ``emit_topic_match_outcome(outcome)``.
  * ``run_triage`` (``web/triage_runner.py``) is wrapped by
    ``_emit_triage_run_outcome_metric`` so every terminal exit bumps
    ``et_triage_runs_total{trigger, outcome}``.

This pin locks in the mirror discipline. If a future edit removes any of the
three mirrors, the pin catches it.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src  # N-350 R31

_WEBHOOKS_MODULE = SRC_ROOT / "web" / "routers" / "webhooks.py"
_CLASSIFY_MODULE = SRC_ROOT / "classify" / "base.py"
_TRIAGE_RUNNER_MODULE = SRC_ROOT / "web" / "triage_runner.py"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _top_level_fn(tree: ast.AST, name: str):
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _class_method(tree: ast.AST, cls_name: str, method_name: str):
    for n in tree.body:
        if isinstance(n, ast.ClassDef) and n.name == cls_name:
            for m in n.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == method_name:
                    return m
    return None


def _body_references_name(node: ast.AST, names: set[str]) -> bool:
    """Return True iff the subtree ``node`` mentions any of ``names`` as a
    Name (``foo``), Attribute (``x.foo``), OR string constant (``"foo"``,
    e.g. the metric-name argument to ``counter(...)``)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in names:
            return True
        if isinstance(n, ast.Attribute) and n.attr in names:
            return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in names:
            return True
    return False


def _decorated_by(fn: ast.FunctionDef | ast.AsyncFunctionDef, decorator_name: str) -> bool:
    for d in fn.decorator_list:
        if isinstance(d, ast.Name) and d.id == decorator_name:
            return True
        if isinstance(d, ast.Attribute) and d.attr == decorator_name:
            return True
        # Handle @decorator(args) form
        if isinstance(d, ast.Call):
            f = d.func
            if isinstance(f, ast.Name) and f.id == decorator_name:
                return True
            if isinstance(f, ast.Attribute) and f.attr == decorator_name:
                return True
    return False


# --------------------------------------------------------------------------
# Invariant 1 — webhooks._inc_counter mirrors via emit_webhook_event.
# --------------------------------------------------------------------------
def test_inc_counter_mirrors_to_metrics_ssot():
    tree = parse_module(_WEBHOOKS_MODULE); assert tree is not None  # N-350 R31
    fn = _top_level_fn(tree, "_inc_counter")
    assert fn is not None, (
        "web/routers/webhooks.py::_inc_counter missing — the funnel every "
        "webhook counter caller already routes through. If it was renamed, "
        "update this pin AND `emit_webhook_event`'s call site."
    )
    assert _body_references_name(fn, {"emit_webhook_event"}), (
        "web/routers/webhooks.py::_inc_counter no longer references "
        "`emit_webhook_event` — the Prometheus SSOT mirror (N-385) has been "
        "removed and /metrics is once again blind to webhook rate. Restore "
        "the `from email_triage.metrics import emit_webhook_event; "
        "emit_webhook_event(key)` mirror at the bottom of the funnel."
    )


# --------------------------------------------------------------------------
# Invariant 2 — _TopicMatchCounters._mirror bumps the SSOT counter.
# --------------------------------------------------------------------------
def test_topic_match_counters_mirror_hits_metrics_ssot():
    tree = parse_module(_CLASSIFY_MODULE); assert tree is not None  # N-350 R31
    fn = _class_method(tree, "_TopicMatchCounters", "_mirror")
    assert fn is not None, (
        "classify/base.py::_TopicMatchCounters._mirror missing — the funnel "
        "every topic-match counter callsite already routes through. If the "
        "class was renamed, update this pin AND `emit_topic_match_outcome`'s "
        "call site."
    )
    assert _body_references_name(fn, {"emit_topic_match_outcome"}), (
        "classify/base.py::_TopicMatchCounters._mirror no longer references "
        "`emit_topic_match_outcome` — the Prometheus SSOT mirror (N-385) has "
        "been removed and /metrics is once again blind to topic-match parse "
        "outcomes. Restore the `from email_triage.metrics import "
        "emit_topic_match_outcome; emit_topic_match_outcome(field)` mirror."
    )


# --------------------------------------------------------------------------
# Invariant 3 — run_triage is decorated by the outcome-metric wrapper.
# --------------------------------------------------------------------------
def test_run_triage_wrapped_by_outcome_metric_decorator():
    tree = parse_module(_TRIAGE_RUNNER_MODULE); assert tree is not None  # N-350 R31
    fn = _top_level_fn(tree, "run_triage")
    assert fn is not None, "web/triage_runner.py::run_triage missing"
    assert _decorated_by(fn, "_emit_triage_run_outcome_metric") or _body_references_name(
        fn, {"et_triage_runs_total"}
    ), (
        "web/triage_runner.py::run_triage is no longer decorated by "
        "`_emit_triage_run_outcome_metric` and does not reference the "
        "`et_triage_runs_total` counter directly — the N-385 mirror that "
        "made the core triage-runner path visible to /metrics has been "
        "removed. Restore the decorator OR wire the counter at every "
        "terminal."
    )


def test_outcome_metric_decorator_still_declared():
    """Guard the pin itself: the decorator MUST still exist in the module,
    else Invariant 3 is vacuously satisfied by a bogus decorator name."""
    tree = parse_module(_TRIAGE_RUNNER_MODULE); assert tree is not None
    dec = _top_level_fn(tree, "_emit_triage_run_outcome_metric")
    assert dec is not None, (
        "the `_emit_triage_run_outcome_metric` decorator was removed from "
        "web/triage_runner.py — the wrapper that emits et_triage_runs_total "
        "on every terminal exit is gone. Restore it."
    )


# --------------------------------------------------------------------------
# Teeth — the pin catches a planted regression.
# --------------------------------------------------------------------------
def test_pin_teeth_inc_counter_missing_mirror(tmp_path):
    """Simulate a _inc_counter with the Prometheus mirror removed."""
    bad = tmp_path / "webhooks_no_mirror.py"
    bad.write_text(
        "def _inc_counter(request, key):\n"
        "    _inc_counter_local(request, key)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fn = _top_level_fn(tree, "_inc_counter")
    assert fn is not None
    assert not _body_references_name(fn, {"emit_webhook_event"})


def test_pin_teeth_inc_counter_with_mirror_passes(tmp_path):
    ok = tmp_path / "webhooks_with_mirror.py"
    ok.write_text(
        "def _inc_counter(request, key):\n"
        "    _inc_counter_local(request, key)\n"
        "    from email_triage.metrics import emit_webhook_event\n"
        "    emit_webhook_event(key)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = _top_level_fn(tree, "_inc_counter")
    assert fn is not None
    assert _body_references_name(fn, {"emit_webhook_event"})


def test_pin_teeth_topic_match_mirror_removed(tmp_path):
    bad = tmp_path / "classify_no_mirror.py"
    bad.write_text(
        "class _TopicMatchCounters:\n"
        "    def _mirror(self, field):\n"
        "        pass  # Prometheus mirror removed\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fn = _class_method(tree, "_TopicMatchCounters", "_mirror")
    assert fn is not None
    assert not _body_references_name(fn, {"emit_topic_match_outcome"})


def test_pin_teeth_topic_match_mirror_present_passes(tmp_path):
    ok = tmp_path / "classify_with_mirror.py"
    ok.write_text(
        "class _TopicMatchCounters:\n"
        "    def _mirror(self, field):\n"
        "        from email_triage.metrics import emit_topic_match_outcome\n"
        "        emit_topic_match_outcome(field)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = _class_method(tree, "_TopicMatchCounters", "_mirror")
    assert fn is not None
    assert _body_references_name(fn, {"emit_topic_match_outcome"})


def test_pin_teeth_run_triage_undecorated(tmp_path):
    bad = tmp_path / "triage_undecorated.py"
    bad.write_text(
        "async def run_triage(db, config, secrets, acct, **kw):\n"
        "    return TriageRunResult()\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fn = _top_level_fn(tree, "run_triage")
    assert fn is not None
    assert not _decorated_by(fn, "_emit_triage_run_outcome_metric")
    assert not _body_references_name(fn, {"et_triage_runs_total"})


def test_pin_teeth_run_triage_decorated_passes(tmp_path):
    ok = tmp_path / "triage_decorated.py"
    ok.write_text(
        "@_emit_triage_run_outcome_metric\n"
        "async def run_triage(db, config, secrets, acct, **kw):\n"
        "    return TriageRunResult()\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = _top_level_fn(tree, "run_triage")
    assert fn is not None
    assert _decorated_by(fn, "_emit_triage_run_outcome_metric")


def test_pin_teeth_run_triage_direct_counter_call_passes(tmp_path):
    """The pin accepts an alternative wire where run_triage directly names the
    canonical counter (in case the decorator pattern is refactored later)."""
    ok = tmp_path / "triage_direct.py"
    ok.write_text(
        "async def run_triage(db, config, secrets, acct, **kw):\n"
        "    _metrics.counter('et_triage_runs_total').inc(\n"
        "        trigger='manual', outcome='success')\n"
        "    return TriageRunResult()\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = _top_level_fn(tree, "run_triage")
    assert fn is not None
    assert _body_references_name(fn, {"et_triage_runs_total"})
