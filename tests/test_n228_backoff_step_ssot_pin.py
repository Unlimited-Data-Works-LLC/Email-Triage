"""N-228 R22 structural pin — backoff-step math SSOT (2026-07-02).

Census R22 discovered class (MED — "exponential-backoff math", 5 forks
incl. newly-found `task_supervisor._compute_backoff`). Verify-don't-accept
at HEAD (2026-07-02): 2 step-shaped inline dups (`backoff = min(backoff *
<lit>, <max>)`) at `cli.py::process_push` + `web/watcher.py`. The class
`TaskSupervisor._compute_backoff` is a DIFFERENT signature (crash-count-
driven, method-scoped) and correctly stays; see the module-level SSOT
docstring in `task_supervisor.py::next_backoff_delay`.

WHAT IT PINS (count-agnostic, tree-wide):

Any assignment of the shape `<name> = min(<name> * <literal-numeric>,
<Any>)` where the target name contains "backoff" is a raw inline dup of
the SSOT and fires the pin. Waives: `web/task_supervisor.py` (the SSOT).

Adoption at HEAD: both `cli.py` + `watcher.py` route through
`next_backoff_delay(current, *, factor, max_delay)`.

SCOPE CAVEAT: doesn't match derived-var shapes (`<x> = min(<x> * <var>,
<max>)`). Extend when a new drift shape surfaces.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILES = {"web/task_supervisor.py"}


def _is_backoff_step_dup(node: ast.AST) -> bool:
    """True if `node` is `<name> = min(<name> * <numeric-lit>, <Any>)`
    where the target-name contains 'backoff'."""
    if not isinstance(node, ast.Assign):
        return False
    if len(node.targets) != 1:
        return False
    tgt = node.targets[0]
    if not isinstance(tgt, ast.Name):
        return False
    if "backoff" not in tgt.id.lower():
        return False
    val = node.value
    if not (isinstance(val, ast.Call)
            and isinstance(val.func, ast.Name)
            and val.func.id == "min"):
        return False
    if len(val.args) < 2:
        return False
    step = val.args[0]
    if not (isinstance(step, ast.BinOp) and isinstance(step.op, ast.Mult)):
        return False
    if not (isinstance(step.left, ast.Name) and step.left.id == tgt.id):
        return False
    if not (isinstance(step.right, ast.Constant)
            and isinstance(step.right.value, (int, float))):
        return False
    return True


def test_no_inline_backoff_step_dup_outside_ssot():
    """Every `<backoff> = min(<backoff> * <lit>, <max>)` outside the SSOT
    fires. Route through `task_supervisor.next_backoff_delay`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if _is_backoff_step_dup(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-228 R22 backoff-step SSOT: raw `<backoff> = min(<backoff> * "
        "<lit>, <max>)` outside `web/task_supervisor.py`. Route through "
        "`next_backoff_delay(current, *, factor, max_delay)` so a jitter "
        "addition or a factor change lands in ONE place.\n\n"
        + "\n".join(offenders)
    )


def test_ssot_is_reachable():
    """Anti-vacuity: `next_backoff_delay` must import + return the
    documented `min(current*factor, max_delay)`."""
    from email_triage.web.task_supervisor import next_backoff_delay
    assert callable(next_backoff_delay)
    # Sanity math: 5.0 * 2.0 = 10.0, capped at 100 → 10.0.
    assert next_backoff_delay(5.0, factor=2.0, max_delay=100.0) == 10.0
    # Cap applies: 60.0 * 2.0 = 120.0, capped at 100 → 100.0.
    assert next_backoff_delay(60.0, factor=2.0, max_delay=100.0) == 100.0
