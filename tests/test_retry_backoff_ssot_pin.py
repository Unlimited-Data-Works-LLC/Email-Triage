"""SSOT declaration-side pin for `retry_backoff.py::compute_next_attempt_at`.

Punch  (Drive-4). The SSOT: `src/email_triage/retry_backoff.py` defines the
attempt-count → next-attempt-time math + the two schedule tuples
(`WATCHER_RETRY_SCHEDULE`, `STYLE_DISTILL_SCHEDULE`). A hand-rolled twin in
`web/db.py::_style_distill_compute_next_retry` or `web/app.py::_watcher_retry_sweeper`
would silently diverge — the operator-audit surface ("how long until attempt N?")
depends on ONE definition. §3 registry row co-lands with this pin.

Pin covers three drift classes (count-agnostic AST, PD#6 shared harness):

  1. Function uniqueness — `compute_next_attempt_at` is defined at MODULE SCOPE
     ONLY in `retry_backoff.py`. A forked twin (in `web/db.py`, `web/app.py`,
     anywhere else) would silently diverge on the arithmetic. Module-scope-only
     gate (per db-sme Drive-2 non-blocking note #3): a nested inner-fn same-name
     wouldn't count as a competing SSOT twin.
  2. Schedule constant uniqueness — the two schedule tuple assignments
     (`WATCHER_RETRY_SCHEDULE = (...)`, `STYLE_DISTILL_SCHEDULE = (...)`) exist
     only in `retry_backoff.py`. A forked copy in a consumer would silently
     alter the retry cadence.
  3. Behavioural anti-vacuity — the SSOT's math produces the expected result
     for both schedules across the full attempt-count range (0..len-1 → offset;
     >= len → None; negative clamps to 0). If the pin's AST scan passes but the
     SSOT's math is broken, this test fails — the pin proves it wraps the real
     behaviour, not a stub.
"""
from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone

import pytest

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)

SSOT_PATH = "retry_backoff.py"
SSOT_FN = "compute_next_attempt_at"
SSOT_SCHEDULES = ("WATCHER_RETRY_SCHEDULE", "STYLE_DISTILL_SCHEDULE")


def _module_scope_fndefs(tree: ast.AST, name: str) -> list[ast.AST]:
    """Return every module-scope FunctionDef/AsyncFunctionDef named `name`.
    Module scope = direct child of `tree` (an `ast.Module`), NOT nested inside
    another function/class (db-sme note #3 — nested inner-fn same-name is not
    a competing SSOT twin)."""
    if not isinstance(tree, ast.Module):
        return []
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            out.append(node)
    return out


def _module_scope_assign_names(tree: ast.AST) -> set[str]:
    """Return every module-scope Assign target-Name.id."""
    if not isinstance(tree, ast.Module):
        return set()
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    return out


def test_compute_next_attempt_at_defined_only_in_ssot():
    """The `compute_next_attempt_at` module-scope FunctionDef exists only in
    `retry_backoff.py`. A hand-rolled twin anywhere else in src is a defect."""
    twins: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == SSOT_PATH:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        if _module_scope_fndefs(tree, SSOT_FN):
            twins.append(rel)
    assert not twins, (
        f"`{SSOT_FN}` defined at module scope outside {SSOT_PATH}: {twins}. "
        "Route callers through `retry_backoff.compute_next_attempt_at` "
        "instead of forking the arithmetic."
    )


def test_ssot_module_actually_declares_compute_next_attempt_at():
    """Anti-vacuity: the SSOT module itself DOES declare
    `compute_next_attempt_at` at module scope. If the fn is later renamed or
    moved without updating this pin, the uniqueness test above passes
    vacuously — this test fails first, so a rename cannot silently break the
    pin."""
    tree = parse_module(SRC_ROOT / SSOT_PATH)
    assert tree is not None, f"{SSOT_PATH} did not parse"
    fns = _module_scope_fndefs(tree, SSOT_FN)
    assert len(fns) == 1, (
        f"expected exactly one module-scope `def {SSOT_FN}` in {SSOT_PATH}, "
        f"found {len(fns)}"
    )


def test_schedule_constants_defined_only_in_ssot():
    """The two schedule constants (`WATCHER_RETRY_SCHEDULE`,
    `STYLE_DISTILL_SCHEDULE`) exist only in `retry_backoff.py`. A forked copy
    (rebinding either name) in a consumer would silently alter retry cadence."""
    for sched in SSOT_SCHEDULES:
        forkers: list[str] = []
        for path in iter_src_files():
            rel = relpath(path)
            if rel == SSOT_PATH:
                continue
            tree = parse_module(path)
            if tree is None:
                continue
            if sched in _module_scope_assign_names(tree):
                forkers.append(rel)
        assert not forkers, (
            f"schedule constant `{sched}` re-assigned outside {SSOT_PATH}: "
            f"{forkers}. Import it from `retry_backoff` instead of rebinding."
        )


def test_ssot_module_declares_both_schedules():
    """Anti-vacuity: the SSOT module actually assigns both schedule names at
    module scope (otherwise the uniqueness test above passes vacuously)."""
    tree = parse_module(SRC_ROOT / SSOT_PATH)
    assert tree is not None
    assigns = _module_scope_assign_names(tree)
    for sched in SSOT_SCHEDULES:
        assert sched in assigns, (
            f"expected module-scope assignment of `{sched}` in {SSOT_PATH}"
        )


def test_compute_next_attempt_at_behaviour():
    """Behavioural anti-vacuity: the SSOT arithmetic produces the expected
    result for both schedules across the attempt-count range (0..len-1 → base
    + schedule[i]; >= len → None; negative clamps to 0). Proves the pin
    wraps the REAL behaviour, not a broken stub."""
    from email_triage.retry_backoff import (
        STYLE_DISTILL_SCHEDULE,
        WATCHER_RETRY_SCHEDULE,
        compute_next_attempt_at,
    )
    base = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    for sched in (WATCHER_RETRY_SCHEDULE, STYLE_DISTILL_SCHEDULE):
        for i in range(len(sched)):
            got = compute_next_attempt_at(i, sched, now=base)
            assert got == base + sched[i], (
                f"schedule mismatch at attempt={i}: got {got} want {base + sched[i]}"
            )
        assert compute_next_attempt_at(len(sched), sched, now=base) is None
        assert compute_next_attempt_at(-1, sched, now=base) == base + sched[0]


def test_pin_has_teeth_planted_twin_flagged():
    """Teeth: a planted `def compute_next_attempt_at(` at module scope in a
    synthetic tree IS flagged by the same detector — proves the detector
    can fire on a real forked twin, not a stub that never triggers."""
    bad = "def compute_next_attempt_at(n, sched, *, now=None):\n    return now\n"
    tree = parse_source(bad)
    assert _module_scope_fndefs(tree, SSOT_FN), "detector missed a planted twin"


def test_pin_has_teeth_planted_schedule_reassign_flagged():
    """Teeth: a planted module-scope assignment of `WATCHER_RETRY_SCHEDULE`
    IS flagged — proves the constant-uniqueness detector fires on a real
    forked copy."""
    bad = "WATCHER_RETRY_SCHEDULE = (1, 2, 3)\n"
    tree = parse_source(bad)
    assert "WATCHER_RETRY_SCHEDULE" in _module_scope_assign_names(tree)


def test_pin_ignores_nested_same_name():
    """Anti-false-positive: a `def compute_next_attempt_at` nested inside
    another function is NOT a competing SSOT twin (db-sme Drive-2 note #3:
    module-scope only). Detector must ignore it."""
    good = (
        "def wrapper():\n"
        "    def compute_next_attempt_at(n, sched, *, now=None):\n"
        "        return now\n"
        "    return compute_next_attempt_at\n"
    )
    tree = parse_source(good)
    assert not _module_scope_fndefs(tree, SSOT_FN), (
        "detector false-positive: nested same-name def counted as twin"
    )
