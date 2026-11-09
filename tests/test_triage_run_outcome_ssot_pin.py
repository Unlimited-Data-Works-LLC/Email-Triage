"""``et_triage_runs_total`` outcome-label vocabulary — count-agnostic
structural pin (N-385, batched SME panel fold 2026-07-10, HIGH).

The ``_emit_triage_run_outcome_metric`` decorator on ``run_triage`` in
``web/triage_runner.py`` bumps ``et_triage_runs_total{trigger, outcome}`` on
every terminal exit. The ``outcome`` label reads from
``TriageRunResult.error`` — an unbounded string field would be a Prometheus
label-cardinality bomb (every distinct error slug that ever appears becomes
a permanent counter series, growing the TSDB + /metrics scrape size for the
install's lifetime — Prime Directive 5: an unbounded value flowing into a
bounded surface is CIDI drift).

The batched SME panel (2026-07-10) flagged this as a must-fold. The fix
bounds the vocabulary via a module-scope ``_TRIAGE_OUTCOMES`` frozenset +
runtime coerce-unknown-to-``"error_other"`` in the decorator wrapper. This
pin locks in the discipline:

  * **Invariant 1** — every ``TriageRunResult(..., error=<constant str>)``
    construction site in ``web/triage_runner.py`` uses a slug in
    ``_TRIAGE_OUTCOMES``. Prevents a new hardcoded error slug from creeping
    onto the metric without a matching frozenset entry.
  * **Invariant 2** — ``_TRIAGE_OUTCOMES`` lives only in
    ``web/triage_runner.py`` (no re-inlined mirror elsewhere in src/).

The self-guard test asserts the scope walk finds ≥5 construction sites — a
too-low count would let a regression that stripped every literal slug pass
vacuously (mirrors the N-384 scope-count guard pattern).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, walk_src  # N-350 R31

_TRIAGE_RUNNER_MODULE = SRC_ROOT / "web" / "triage_runner.py"

# Kept in sync with ``_TRIAGE_OUTCOMES`` in
# ``src/email_triage/web/triage_runner.py`` — Invariant 2 guards drift.
_TRIAGE_OUTCOMES = frozenset({
    "success",
    "error",
    "error_other",
    "user_disabled",
    "no_categories",
    "provider_error",
    "classifier_error",
    "baa_required",
})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _triage_run_result_error_literals(tree: ast.AST) -> list[tuple[str, int]]:
    """Yield ``(slug, lineno)`` for every ``TriageRunResult(..., error='literal', ...)``
    Call in the module. A non-string ``error`` value (e.g. ``error=fmt_exc(e)``)
    is NOT a bounded literal — it would fail the pin at CI IF the vocab shape
    check flagged runtime values, but the pin's scope is COMPILE-TIME literals
    (the bounded-enum discipline). A runtime value flowing to ``.get('error')``
    is caught at the decorator's ``_TRIAGE_OUTCOMES`` coerce (Invariant 3 —
    behavior-tested)."""
    out: list[tuple[str, int]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.id if isinstance(f, ast.Name) else (
            f.attr if isinstance(f, ast.Attribute) else "")
        if name != "TriageRunResult":
            continue
        for kw in n.keywords:
            if kw.arg != "error":
                continue
            v = kw.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append((v.value, n.lineno))
    return out


def _outcome_collection_lines(tree: ast.AST) -> list[int]:
    """Line numbers of list/tuple/set/frozenset literals holding >=2 outcome
    strings — a re-inlined mirror of the vocabulary."""
    out: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            count = sum(
                1 for e in n.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
                and e.value in _TRIAGE_OUTCOMES
            )
            if count >= 2:
                out.append(n.lineno)
    return out


# --------------------------------------------------------------------------
# Invariant 1 — every TriageRunResult(error=<literal>) uses a bounded slug.
# --------------------------------------------------------------------------
def test_every_triage_run_result_error_literal_registered():
    tree = parse_module(_TRIAGE_RUNNER_MODULE); assert tree is not None  # N-350 R31
    literals = _triage_run_result_error_literals(tree)
    unregistered = [
        f"{slug!r} at line {lineno}"
        for (slug, lineno) in literals
        if slug not in _TRIAGE_OUTCOMES
    ]
    assert not unregistered, (
        "TriageRunResult was constructed with an `error=<literal>` value not "
        f"in _TRIAGE_OUTCOMES: {unregistered}. Add the slug to "
        "`web/triage_runner.py::_TRIAGE_OUTCOMES` (Prometheus label "
        "cardinality is a permanent commitment — the frozenset IS the SSOT), "
        "OR route the error through the decorator's runtime coerce and "
        "leave the literal out of the AST scan by making it a fresh "
        "computed value."
    )


# --------------------------------------------------------------------------
# Invariant 2 — the vocabulary lives only in triage_runner.py.
# --------------------------------------------------------------------------
def test_outcome_vocabulary_only_in_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if p == _TRIAGE_RUNNER_MODULE:
            continue
        locs = _outcome_collection_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "A _TRIAGE_OUTCOMES-shaped collection literal was re-inlined outside "
        "`web/triage_runner.py` — the divergence this pin guards: "
        f"{offenders}. Import `_TRIAGE_OUTCOMES` from the SSOT instead of "
        "copying the vocabulary."
    )


def test_ssot_actually_holds_the_vocabulary():
    """Guard the pin itself: the SSOT MUST still carry the vocabulary."""
    tree = parse_module(_TRIAGE_RUNNER_MODULE); assert tree is not None
    locs = _outcome_collection_lines(tree)
    assert locs, "the _TRIAGE_OUTCOMES vocabulary vanished from triage_runner.py"


# --------------------------------------------------------------------------
# Scope-count guard — a regression that strips every error literal would let
# Invariant 1 pass vacuously. Assert we find ≥5 sites.
# --------------------------------------------------------------------------
def test_pin_scope_actually_finds_triage_run_result_sites():
    tree = parse_module(_TRIAGE_RUNNER_MODULE); assert tree is not None
    literals = _triage_run_result_error_literals(tree)
    assert len(literals) >= 5, (
        f"the pin walked triage_runner.py and found only {len(literals)} "
        "TriageRunResult(error=<literal>) construction site(s) — expected "
        ">=5 (user_disabled, no_categories, provider_error, classifier_error, "
        "baa_required). A too-low count means the pin's detector regressed "
        "and is vacuously true. Investigate `_triage_run_result_error_literals`."
    )


# --------------------------------------------------------------------------
# Teeth — the pin catches a planted regression.
# --------------------------------------------------------------------------
def test_pin_teeth_invariant1_unregistered_slug(tmp_path):
    bad = tmp_path / "bad_slug.py"
    bad.write_text(
        "def r():\n"
        "    return TriageRunResult(error='mystery_slug_2027')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    lits = _triage_run_result_error_literals(tree)
    assert ("mystery_slug_2027", 2) in lits
    assert "mystery_slug_2027" not in _TRIAGE_OUTCOMES


def test_pin_teeth_invariant1_registered_slug_passes(tmp_path):
    ok = tmp_path / "ok_slug.py"
    ok.write_text(
        "def r():\n"
        "    return TriageRunResult(error='user_disabled')\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    lits = _triage_run_result_error_literals(tree)
    assert lits == [("user_disabled", 2)]
    assert all(slug in _TRIAGE_OUTCOMES for slug, _ in lits)


def test_pin_teeth_invariant1_ignores_non_string_error(tmp_path):
    """A dynamic error value (fmt_exc(e)) is NOT a bounded literal — the pin
    only flags string constants. Runtime coerce (Invariant 3, behavior-tested)
    catches the label-cardinality risk at emit time."""
    ok = tmp_path / "dynamic.py"
    ok.write_text(
        "def r(exc):\n"
        "    return TriageRunResult(error=str(exc))\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    lits = _triage_run_result_error_literals(tree)
    assert lits == [], (
        "the pin flagged a dynamic error= value — it should only inspect "
        "string constants"
    )


def test_pin_teeth_invariant2_reinlined_vocab(tmp_path):
    bad = tmp_path / "reinlined.py"
    bad.write_text(
        "OUTCOMES = ('user_disabled', 'no_categories', 'provider_error')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _outcome_collection_lines(tree)


def test_pin_teeth_invariant2_single_literal_is_ok(tmp_path):
    """A lone slug literal (a single call site's argument) is NOT a re-inlined
    vocabulary."""
    ok = tmp_path / "single.py"
    ok.write_text(
        "def r():\n"
        "    return TriageRunResult(error='user_disabled')\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _outcome_collection_lines(tree)
