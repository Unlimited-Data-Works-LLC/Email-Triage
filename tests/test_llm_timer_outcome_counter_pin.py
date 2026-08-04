"""LLM ``metrics.timer`` outcome-counter twin — count-agnostic structural pin
(N-384, divergence census wf_69674c7e-c67 2026-07-10, HIGH).

Before this pin, the ~7 ``with metrics.timer('et_llm_*_seconds', ...):`` wrappers
across ``classify/base.py``, ``ai_backends/base.py``, ``engine/embedding_backend.py``
and ``cli.py`` recorded p50/p95/p99 latency but NEVER emitted a paired outcome
counter — so ``/metrics`` scrapes saw latency but no failure-rate signal. A slow
degradation (JSON parse rate falling from 99% to 90%, transport_error trickling
in) was invisible to Prometheus / Grafana that ``metrics.py`` itself courts (line
6-10 of the module docstring).

The fix routes both the success and every failure edge through
``metrics.emit_llm_outcome(op, backend, outcome)``. This pin locks in the
symmetry:

  * **Invariant 1** — every function that opens a
    ``with metrics.timer('et_llm_*_seconds', ...):`` block also references
    ``emit_llm_outcome`` somewhere in its body (Name/Attribute walk). A timer
    site without a matching outcome emit is the exact defect this pin exists
    to catch.
  * **Invariant 2** — every ``metrics.timer('et_llm_*_seconds', ...)`` name
    literal is registered — the histogram basename (``et_llm_<op>_seconds``)
    maps to a known ``op`` in :data:`_LLM_OPS`.
  * **Invariant 3** — the outcome-vocabulary SSOT (``_LLM_OUTCOMES``,
    ``_LLM_OPS``) lives only in ``metrics.py``. A re-inlined tuple/list/set of
    outcome literals ≥2 outside the SSOT is a divergence-in-waiting.

Teeth-tests confirm each invariant catches a planted regression.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src  # N-350 R31

_METRICS_MODULE = SRC_ROOT / "metrics.py"

# Kept in sync with ``_LLM_OPS`` in ``src/email_triage/metrics.py`` — Invariant 3
# guards drift from the SSOT.
_LLM_OPS = frozenset({"classify", "chat", "embed"})

# Kept in sync with ``_LLM_OUTCOMES`` in ``src/email_triage/metrics.py``.
_LLM_OUTCOMES = frozenset({
    "success", "parse_retry", "parse_failed", "off_taxonomy", "transport_error",
})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _is_llm_timer_call(n: ast.AST) -> tuple[bool, str | None]:
    """Return (True, histogram_name) if ``n`` is a ``metrics.timer('et_llm_*_seconds', ...)``
    Call, else (False, None). Accepts both bare-name (``timer(...)``) and
    attribute (``_metrics.timer(...)``, ``metrics.timer(...)``) forms."""
    if not isinstance(n, ast.Call):
        return (False, None)
    f = n.func
    fname = (
        f.attr if isinstance(f, ast.Attribute)
        else f.id if isinstance(f, ast.Name)
        else None
    )
    if fname != "timer":
        return (False, None)
    if not n.args:
        return (False, None)
    a0 = n.args[0]
    if not (isinstance(a0, ast.Constant) and isinstance(a0.value, str)):
        return (False, None)
    name = a0.value
    if not (name.startswith("et_llm_") and name.endswith("_seconds")):
        return (False, None)
    return (True, name)


def _histogram_op(name: str) -> str | None:
    """Extract the ``op`` label from ``et_llm_<op>_seconds``."""
    if not (name.startswith("et_llm_") and name.endswith("_seconds")):
        return None
    return name[len("et_llm_"):-len("_seconds")]


def _function_defs_containing_llm_timer(tree: ast.AST):
    """Yield ``(node, hist_name)`` for every ``FunctionDef``/``AsyncFunctionDef``
    that OPENS a ``with metrics.timer('et_llm_*_seconds', ...):`` inside it.
    A function that DOES NOT open the timer but is a caller of one that does
    is out of scope — the pin's target is the site that ownership of the
    outcome emit belongs to."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for c in ast.walk(node):
            if isinstance(c, ast.With):
                for item in c.items:
                    ok, hist = _is_llm_timer_call(item.context_expr)
                    if ok:
                        yield (node, hist)
                        break


def _fn_references_emit(node: ast.AST) -> bool:
    """Return True iff the function body references ``emit_llm_outcome`` at
    least once (Name or Attribute). Doesn't require reachability on every
    exit path — this is the coarser "any-mention" check that catches an
    entirely un-wired timer; the semantic per-path check lives in the
    behaviour tests."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id == "emit_llm_outcome":
            return True
        if isinstance(n, ast.Attribute) and n.attr == "emit_llm_outcome":
            return True
    return False


# --------------------------------------------------------------------------
# Invariant 1 — every enclosing function that opens an LLM timer also
# references emit_llm_outcome.
# --------------------------------------------------------------------------
def test_every_llm_timer_site_references_emit_outcome():
    offenders: list[str] = []
    for p, rel, tree in walk_src():
        for fn, hist in _function_defs_containing_llm_timer(tree):
            if not _fn_references_emit(fn):
                offenders.append(f"{rel}::{fn.name}:{fn.lineno} (timer={hist!r})")
    assert not offenders, (
        "an LLM `metrics.timer('et_llm_*_seconds', ...)` site does NOT reach "
        f"`emit_llm_outcome` inside its enclosing function: {offenders}. "
        "Wire the success edge (`emit_llm_outcome(op, backend, 'success')`) "
        "and every failure edge (`parse_failed` / `parse_retry` / "
        "`off_taxonomy` / `transport_error`) through the SSOT funnel in "
        "`src/email_triage/metrics.py`. The pattern is the try/finally +"
        " default-to-transport_error scaffold used at "
        "classify/base.py::classify."
    )


# --------------------------------------------------------------------------
# Invariant 2 — every timer histogram basename maps to a registered `op`.
# --------------------------------------------------------------------------
def test_every_llm_timer_histogram_op_registered():
    offenders: list[str] = []
    for p, rel, tree in walk_src():
        for n in ast.walk(tree):
            ok, hist = _is_llm_timer_call(n)
            if not ok:
                continue
            op = _histogram_op(hist)
            if op not in _LLM_OPS:
                offenders.append(f"{rel}:{n.lineno} timer={hist!r} op={op!r}")
    assert not offenders, (
        "an LLM `metrics.timer` histogram basename does not map to a "
        f"registered op in `_LLM_OPS`: {offenders}. Register the op in "
        "`src/email_triage/metrics.py::_LLM_OPS` (its counter twin will use "
        "the same op label), or rename the histogram to match an existing op."
    )


# --------------------------------------------------------------------------
# Invariant 3 — the outcome vocabulary is SSOT'd.
# A collection literal with >=2 outcome strings outside metrics.py IS a
# re-inlined vocabulary — the divergence this pin guards.
# --------------------------------------------------------------------------
def _outcome_collection_lines(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            count = sum(
                1 for e in n.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
                and e.value in _LLM_OUTCOMES
            )
            if count >= 2:
                out.append(n.lineno)
    return out


def test_outcome_vocabulary_only_in_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if p == _METRICS_MODULE:
            continue
        locs = _outcome_collection_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "an LLM-outcome collection literal was re-inlined outside "
        "`src/email_triage/metrics.py` — the divergence this pin guards: "
        f"{offenders}. Import `_LLM_OUTCOMES` from the SSOT instead of copying."
    )


def test_ssot_actually_holds_the_outcome_vocab():
    """Guard the pin itself: the SSOT MUST still carry the vocabulary, else
    invariant 3 is vacuously true."""
    tree = parse_module(_METRICS_MODULE); assert tree is not None  # N-350 R31
    locs = _outcome_collection_lines(tree)
    assert locs, "the outcome vocabulary vanished from metrics.py"


# --------------------------------------------------------------------------
# Teeth — the pin catches a planted regression.
# --------------------------------------------------------------------------
def test_pin_teeth_invariant1_timer_without_emit(tmp_path):
    """A function that opens an LLM timer but does NOT call emit_llm_outcome
    is caught."""
    bad = tmp_path / "bad_wire.py"
    bad.write_text(
        "async def classify(self, prompt):\n"
        "    with _metrics.timer('et_llm_classify_seconds', backend='x'):\n"
        "        return await self._chat(prompt)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fns = list(_function_defs_containing_llm_timer(tree))
    assert fns and not _fn_references_emit(fns[0][0])


def test_pin_teeth_invariant1_timer_with_emit_passes(tmp_path):
    ok = tmp_path / "ok_wire.py"
    ok.write_text(
        "async def classify(self, prompt):\n"
        "    outcome = 'transport_error'\n"
        "    try:\n"
        "        with _metrics.timer('et_llm_classify_seconds', backend='x'):\n"
        "            r = await self._chat(prompt)\n"
        "        outcome = 'success'\n"
        "        return r\n"
        "    finally:\n"
        "        _metrics.emit_llm_outcome('classify', 'x', outcome)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fns = list(_function_defs_containing_llm_timer(tree))
    assert fns and _fn_references_emit(fns[0][0])


def test_pin_teeth_invariant2_unregistered_op(tmp_path):
    bad = tmp_path / "bad_op.py"
    bad.write_text(
        "def scrape():\n"
        "    with _metrics.timer('et_llm_translate_seconds', backend='x'):\n"
        "        pass\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    hits: list[str] = []
    for n in ast.walk(tree):
        ok, hist = _is_llm_timer_call(n)
        if ok:
            op = _histogram_op(hist)
            if op not in _LLM_OPS:
                hits.append(hist)
    assert "et_llm_translate_seconds" in hits


def test_pin_teeth_invariant2_registered_op_passes(tmp_path):
    ok = tmp_path / "ok_op.py"
    ok.write_text(
        "def scrape():\n"
        "    with _metrics.timer('et_llm_chat_seconds', backend='x'):\n"
        "        pass\n"
        "    _metrics.emit_llm_outcome('chat', 'x', 'success')\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    hits: list[str] = []
    for n in ast.walk(tree):
        ok, hist = _is_llm_timer_call(n)
        if ok:
            hits.append(hist)
    assert hits == ["et_llm_chat_seconds"]
    op = _histogram_op(hits[0])
    assert op in _LLM_OPS


def test_pin_teeth_invariant3_reinlined_vocab(tmp_path):
    bad = tmp_path / "bad_vocab.py"
    bad.write_text(
        "OUTCOMES = ('success', 'transport_error', 'parse_failed')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _outcome_collection_lines(tree)


def test_pin_teeth_invariant3_single_literal_is_ok(tmp_path):
    """A lone outcome literal (e.g. a single call site emitting 'success') is
    NOT a re-inlined vocabulary — only a collection with >=2 strings is."""
    ok = tmp_path / "ok_vocab.py"
    ok.write_text(
        "def f():\n"
        "    emit_llm_outcome('classify', 'ollama', 'success')\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _outcome_collection_lines(tree)


# --------------------------------------------------------------------------
# Guard — the pin's own scope walk cannot vacuously report zero timer sites
# (that would let a full regression pass silently). Verify the pin at least
# sees the SSOT-adjacent sites at HEAD.
# --------------------------------------------------------------------------
def test_pin_scope_actually_finds_llm_timer_sites():
    seen = 0
    for _p, _rel, tree in walk_src():
        for _n, _ in _function_defs_containing_llm_timer(tree):
            seen += 1
    assert seen >= 5, (
        f"the pin walked src/ and found only {seen} enclosing function(s) "
        "opening an LLM timer — expected >=5 (safety_detect, "
        "classify_with_topics, classify hot-path, chat decorator, embed "
        "backend, embed CLI). A too-low count means the pin's timer-detection "
        "regressed and is vacuously true. Investigate `_is_llm_timer_call`."
    )
