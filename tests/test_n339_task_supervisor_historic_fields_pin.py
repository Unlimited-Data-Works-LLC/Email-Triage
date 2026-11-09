"""N-339 R31 — anti-clear structural pin on task_supervisor recovery.

The 2026-07-03 trust-audit damage report's DA agent flagged
``_record_recovery`` as a PD  "set-broad/clear-narrow lie" —
recommending expansion from the current 2-field clear (``backoff_secs``
+ ``quarantined_reason``) to a 4-field clear that also nulls
``last_crash_ts`` + ``last_crash_error_type``.

Verify-don't-accept walk 2026-07-04 REFUTES that recommendation:

1. **Test contract at HEAD:**
   :func:`tests.test_task_supervisor.test_crash_triggers_respawn_with_backoff`
   line 69 asserts ``state.last_crash_error_type == "RuntimeError"``
   AFTER two crashes + one clean recovery to ``status="stopped"``.
   A 4-field clear would break the documented contract.

2. **Docstring rationale at N-303 R30 + N-339 R31:**
   ``last_crash_ts`` + ``last_crash_error_type`` are HISTORIC
   DIAGNOSTIC fields, not status flags. ``/health`` derives
   ``any_crashed_recently`` / ``any_quarantined`` from ``status``, not
   from the historic fields.

3. **``TaskState.to_dict`` contract:**
   downstream ``/health`` consumers MUST gate any "task X failing"
   surface on ``status`` first — the docstring at the ``to_dict``
   emission of these fields spells that out.

This pin ENFORCES the N-303/N-339 design against a future refactor:
any change that adds one of the 4 historic-field assignments inside
``_record_recovery`` FAILS. The correct path for that change is:
(1) rename the field(s) to ``current_*`` (breaking the historic
contract explicitly), (2) update ``TaskState.to_dict`` + the
``/health`` contract, (3) update the test contract at
``test_crash_triggers_respawn_with_backoff``, (4) SME-review the
`/health` breakage.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, parse_module


# N-341 R31 (2026-07-04 CI-red fix-forward on 7f108327): route through
# ``_pin_harness`` per the pin-harness-adoption meta-pin (census run15
# #3). This pin was hand-rolling ``Path(__file__).resolve().parent.parent``
# — same class as the N-338 pin regression the same CI failure surfaced.
TARGET = SRC_ROOT / "web" / "task_supervisor.py"


# Fields that ``_record_crash`` sets and that the N-303 R30 + N-339 R31
# design explicitly PRESERVES across recovery for diagnostic value.
_HISTORIC_FIELDS_NOT_CLEARED_ON_RECOVERY = frozenset({
    "last_crash_ts",
    "last_crash_error_type",
    "crashes",
    "crash_history",
})


def _record_recovery_fn() -> ast.FunctionDef:
    tree = parse_module(TARGET)
    if tree is None:
        pytest.fail(f"parse_module returned None for {TARGET}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_record_recovery":
            return node
    pytest.fail("_record_recovery not found in task_supervisor.py — renamed?")


def _record_crash_fn() -> ast.FunctionDef:
    tree = parse_module(TARGET)
    if tree is None:
        pytest.fail(f"parse_module returned None for {TARGET}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_record_crash":
            return node
    pytest.fail("_record_crash not found in task_supervisor.py — renamed?")


def _assigned_state_attributes(fn: ast.FunctionDef) -> set[str]:
    """Return the set of attribute names assigned to ``state.<attr>`` in
    the given function body. Also walks nested If / Try blocks.
    """
    out: set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):
            for target in sub.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "state"
                ):
                    out.add(target.attr)
        elif isinstance(sub, ast.AugAssign):
            target = sub.target
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "state"
            ):
                out.add(target.attr)
    return out


def test_record_recovery_does_not_clear_historic_fields():
    """N-339 anti-clear pin. Enforce the N-303 R30 + N-339 R31 design:
    ``_record_recovery`` MUST NOT assign to any of the historic
    diagnostic fields. If a future change wants to (e.g. because
    `/health` semantics changed), it must go through the rename +
    contract-update path documented in the module docstring.
    """
    fn = _record_recovery_fn()
    assigned = _assigned_state_attributes(fn)
    violations = assigned & _HISTORIC_FIELDS_NOT_CLEARED_ON_RECOVERY
    if violations:
        pytest.fail(
            f"_record_recovery assigns to historic field(s) "
            f"{sorted(violations)!r}. Per N-303 R30 + N-339 R31, these "
            f"are HISTORIC DIAGNOSTIC fields never cleared on recovery. "
            f"A future change that legitimately needs to clear them "
            f"must first: (1) rename to `current_*` (breaks historic "
            f"contract explicitly), (2) update TaskState.to_dict + "
            f"`/health` docs, (3) update the "
            f"`test_crash_triggers_respawn_with_backoff` contract, "
            f"(4) SME-review the /health breakage. This pin has NO "
            f"escape hatch — the rename IS the escape hatch."
        )


def test_record_crash_still_sets_historic_fields():
    """N-339 companion pin. ``_record_crash`` MUST still SET the
    historic fields. If a future refactor stops setting them, the
    diagnostic contract silently breaks — `/health` diagnostics show
    None for tasks that HAVE crashed. Enforces symmetry with the
    anti-clear pin above.
    """
    fn = _record_crash_fn()
    assigned = _assigned_state_attributes(fn)
    missing = _HISTORIC_FIELDS_NOT_CLEARED_ON_RECOVERY - assigned
    if missing:
        pytest.fail(
            f"_record_crash no longer assigns to historic field(s) "
            f"{sorted(missing)!r}. The diagnostic contract requires "
            f"these to be SET on every crash so `/health` and downstream "
            f"consumers can inspect 'what crashed last time'. Restore "
            f"the assignments or rename the fields per the "
            f"`_record_recovery` docstring's escape-hatch path."
        )
