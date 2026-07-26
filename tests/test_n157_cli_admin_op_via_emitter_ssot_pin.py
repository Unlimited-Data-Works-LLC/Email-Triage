"""N-157 structural pin — CLI admin-op routes via emitter SSOT (2026-07-09).

Alex-directed close per AskUserQuestion 2026-07-08 ("Fail-loud with
recovery flag").  Pre-N-157 ``cli.py::_emit_cli_audit_event`` wrote
directly through ``insert_log_entry`` — a raw chain-primitive that
bypasses the ``@audit_emitter`` gap-event sentinel (audit_gap_events,
per  Deliverable 3).  A ``@db_write`` rollback on a SQLITE_MISUSE
inside the CLI-op emit path had NO tamper-evident record → §164.312(b)
Audit Controls gap.

N-157 routes the write through the new ``record_cli_admin_op`` emitter
in ``db/audit.py`` (``@db_write`` + ``@audit_emitter``).  This pin is
count-agnostic + interprocedural in scope: any direct call to
``insert_log_entry`` from ``cli.py`` fails the pin.  The ONLY legitimate
``insert_log_entry`` call remains inside ``record_cli_admin_op`` in
``db/audit.py`` — that's the emitter SSOT and is out of this pin's
scope.

WHAT IT PINS (count-agnostic, structural):

Every ``Call`` in ``src/email_triage/cli.py`` whose func-name is
``insert_log_entry`` fails.  Comment / string mentions are ignored
(AST walk over ``ast.Call`` only).  Anti-vacuity: the emitter SSOT
symbol ``record_cli_admin_op`` MUST exist in ``db/audit.py`` — a
missing symbol means the refactor was half-landed and the pin would
pass by regression.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath


_CLI_MODULE_REL = "cli.py"
_FORBIDDEN_CALL_NAME = "insert_log_entry"


def _iter_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _call_target_name(call: ast.Call) -> str | None:
    """Return the callable's simple name — supports ``Name`` and
    ``Attribute`` (``mod.insert_log_entry(...)``)."""
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def test_cli_admin_op_no_direct_insert_log_entry():
    """No direct ``insert_log_entry`` call in ``src/email_triage/cli.py``.

    Regression-guard for the N-157 fail-loud closure — a resurfaced
    direct call would silently degrade the H-03-auto path to the pre-
    N-157 posture that lacks the audit_gap_events sentinel on emit
    failure.
    """
    # The audit-op SSOT lives at the top-level package's cli.py — a
    # direct SRC_ROOT-relative lookup (no rglob) is precise + routes
    # through the harness canonical root per PD #6.
    target = SRC_ROOT / _CLI_MODULE_REL
    assert target.exists(), (
        "N-157 pin harness: could not locate src/email_triage/cli.py "
        f"at {target} — did the package layout change?"
    )
    tree = parse_module(target)
    assert tree is not None, f"N-157 pin: cli.py failed to parse ({target})"
    hits = [
        c for c in _iter_calls(tree)
        if _call_target_name(c) == _FORBIDDEN_CALL_NAME
    ]
    assert not hits, (
        f"N-157 CLI admin-op SSOT: cli.py has {len(hits)} direct "
        f"`{_FORBIDDEN_CALL_NAME}(...)` call(s) — route through "
        "`record_cli_admin_op` in db/audit.py so a write failure fires "
        "the audit_gap_events sentinel per §164.312(b).\n\n"
        + "\n".join(
            f"  {relpath(target)}:{c.lineno}: {ast.unparse(c.func)}(...)"
            for c in hits
        )
    )


def test_cli_admin_op_emitter_exists():
    """Anti-vacuity: ``record_cli_admin_op`` MUST exist in ``db/audit.py``.

    A missing symbol means the refactor was half-landed and the ratchet
    above would pass by regression.
    """
    audit_path = SRC_ROOT / "db" / "audit.py"
    assert audit_path.exists(), (
        "N-157 pin harness: could not locate src/email_triage/db/audit.py "
        f"at {audit_path}"
    )
    tree = parse_module(audit_path)
    assert tree is not None, (
        f"N-157 anti-vacuity: db/audit.py failed to parse ({audit_path})"
    )
    fn_names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert "record_cli_admin_op" in fn_names, (
        "N-157 anti-vacuity: `record_cli_admin_op` emitter MUST exist in "
        "db/audit.py — a missing symbol means the pin above is vacuous."
    )


def test_cli_audit_gate_closed_exception_exists():
    """Anti-vacuity: ``CliAuditGateClosed`` exception MUST exist in
    ``cli.py`` — it is the typed marker the fail-loud gate raises.
    """
    target = SRC_ROOT / "cli.py"
    assert target.exists(), (
        "N-157 anti-vacuity: could not locate src/email_triage/cli.py "
        f"at {target}"
    )
    tree = parse_module(target)
    class_names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    assert "CliAuditGateClosed" in class_names, (
        "N-157 anti-vacuity: `CliAuditGateClosed` exception MUST exist "
        "in cli.py — the fail-loud actuator + the decorator's "
        "propagation path both name it."
    )
