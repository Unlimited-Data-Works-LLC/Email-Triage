"""Structural pin (post-drive -tail-2 fix at 7a8be9ef): forbid the
LEGACY task-set-only `_drain_audit_writes(app)` call shape in tests.

What this defends
-----------------
The `_drain_audit_writes` helper at `tests/test_web/test_access_audit.py`
takes optional `db` + `expected_delta` + `before` kwargs — when passed,
the drainer waits for the DB row-count to grow by `expected_delta` above
`before`. That is the CORRECT liveness signal under CI load per the
drainer's own HISTORY docstring:

  "task-set membership is the WRONG liveness signal; the actual
   assertion is row-count."

The task-set-only signature `_drain_audit_writes(app)` (single positional
arg = the app) returns immediately when the pending set is seen as `{}`.
Under CI load the middleware's `asyncio.create_task` may not have
registered the task on `app.state._audit_pending` YET by the time the
test thread polls — set seen as {} → drain returns → row hasn't landed
→ `list_access_events(db, limit=1)[0]` IndexErrors on empty list.

The 7b5b4c8a fix-forward migrated most call sites but MISSED
`tests/test_web/test_access_audit.py:407` — the CI-red on `de050c40` +
`0c711005`. This pin closes the class going forward: every call to
`_drain_audit_writes(app)` MUST pass `db=` + either `expected_delta=`
OR `before=`.

Count-agnostic + meta-pin clean
-------------------------------
Property over every ast.Call to `_drain_audit_writes`, no `len==N`.
Walk routed through `_pin_harness.iter_files` (tests-tree) + `parse_module`.

Allow-list
----------
`_ALLOWED_LEGACY_CALLS` = () — the drainer's own def-site + the
docstring example (if any) are naturally exempt because they're not
Call nodes to the function name; the pin only fires on actual invocation.
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import iter_files, parse_module, relpath


_TESTS_ROOT = Path(__file__).resolve().parent

_ALLOWED_LEGACY_CALLS: set[tuple[str, int]] = set()


def test_no_legacy_drain_audit_writes_call_shape():
    """Every `_drain_audit_writes(<app>)` call MUST also pass `db=` +
    either `expected_delta=` OR `before=` — the row-count arm.
    Task-set-only drain is WRONG per the drainer's HISTORY docstring."""
    offenders: list[str] = []
    for py in iter_files(_TESTS_ROOT, "test_*.py"):
        tree = parse_module(py)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            called = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if called != "_drain_audit_writes":
                continue
            kw_names = {k.arg for k in node.keywords}
            # Row-count arm requires `db` + at least one of {expected_delta, before}.
            if "db" in kw_names and (kw_names & {"expected_delta", "before"}):
                continue
            rel = relpath(py, base=_TESTS_ROOT.parent)
            if (rel, node.lineno) in _ALLOWED_LEGACY_CALLS:
                continue
            offenders.append(f"{rel}:{node.lineno}  _drain_audit_writes(...) kwargs={sorted(kw_names)}")
    if offenders:
        raise AssertionError(
            "-tail REGRESSION: `_drain_audit_writes(app)` legacy "
            "task-set-only shape re-introduced. Pass `db=` + either "
            "`expected_delta=` or `before=` so the drainer waits for the "
            "DB row-count to grow (the correct liveness signal per the "
            "drainer's HISTORY docstring). CI will flake IndexError on "
            "`list_access_events(db)[0]` under load. Offenders:\n  "
            + "\n  ".join(offenders)
        )


def _is_bad_call(node: ast.Call) -> bool:
    """Duplicate the pin's predicate for teeth-test locality."""
    f = node.func
    called = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
    if called != "_drain_audit_writes":
        return False
    kw_names = {k.arg for k in node.keywords}
    return not ("db" in kw_names and (kw_names & {"expected_delta", "before"}))


def test_pin_has_teeth():
    """Detector flags planted bad shapes and passes clean ones."""
    from _pin_harness import parse_source
    bad_single_arg = "_drain_audit_writes(app)\n"
    bad_db_no_arm = "_drain_audit_writes(app, db=db)\n"
    good_expected_delta = "_drain_audit_writes(app, db=db, expected_delta=1)\n"
    good_before = "_drain_audit_writes(app, db=db, before=42)\n"
    good_both = "_drain_audit_writes(app, db=db, expected_delta=1, before=42)\n"
    for src in (bad_single_arg, bad_db_no_arm):
        tree = parse_source(src)
        hits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_bad_call(n)]
        assert hits, f"pin missed a planted bad shape: {src!r}"
    for src in (good_expected_delta, good_before, good_both):
        tree = parse_source(src)
        hits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_bad_call(n)]
        assert not hits, f"pin false-flagged clean shape: {src!r}"
