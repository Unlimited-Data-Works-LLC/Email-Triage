"""N-359 R31 — fire_notification leak-refused audit-log is UNCONDITIONAL.

Trust-repair fix-forward per PHASE2 #meta hipaa-sme + db-sme + the backlog
 (TASK ). Pre-N-359: refusal audit-emit was gated on
``is_hipaa=True`` AND passed ``None`` as the conn positional to
``record_hipaa_access_event`` via ``db_call(record_..., None, ...)``,
which AttributeError'd and was silently swallowed by
``safe_audit_write_async``. Net effect: audit row NEVER landed AND the
emit only ran on caller-supplied is_hipaa. N-359 replaces the broken
duplicate emit with an UNCONDITIONAL WARNING log line that routes
through ``SQLiteLogHandler`` → HMAC-chained ``log_entries`` (§164.312(b)
+ §164.312(c)(1)).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


_TARGET = SRC_ROOT / "web" / "events.py"


def _fire_notification_fn() -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = parse_module(_TARGET)
    assert tree is not None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "fire_notification":
            return node
    raise AssertionError("fire_notification not found in web/events.py")


def test_no_conditional_is_hipaa_gate_around_audit_emit():
    """N-359 anti-vacuity: `fire_notification` MUST NOT gate any audit
    emitter call (record_*_event / safe_audit_write*) on `is_hipaa`.
    The refusal must always land in log_entries via the WARNING log
    line's SQLiteLogHandler route.
    """
    fn = _fire_notification_fn()
    # Walk If nodes whose test is `is_hipaa` (bare Name reference).
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.If):
            continue
        if not (isinstance(sub.test, ast.Name) and sub.test.id == "is_hipaa"):
            continue
        # Check the body for any Call to an audit emitter name.
        for inner in ast.walk(sub):
            if isinstance(inner, ast.Call):
                # Resolve the callee's rightmost name for the check.
                fname = None
                if isinstance(inner.func, ast.Name):
                    fname = inner.func.id
                elif isinstance(inner.func, ast.Attribute):
                    fname = inner.func.attr
                if fname and (
                    fname.startswith("record_")
                    or fname.startswith("safe_audit_write")
                    or fname == "db_call"
                    and _emits_audit(inner)
                ):
                    raise AssertionError(
                        "N-359 REGRESSION: `fire_notification` gates an "
                        f"audit emitter ({fname}) inside an `if is_hipaa:` "
                        "block. §164.312(b) requires the refusal event to "
                        "land unconditionally. Route the emit via the "
                        "WARNING log line at module scope (which reaches "
                        "SQLiteLogHandler → HMAC-chained log_entries)."
                    )


def _emits_audit(call: ast.Call) -> bool:
    """True if `db_call(record_..., ...)` is emitting an audit row."""
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.Name):
        return first.id.startswith("record_")
    if isinstance(first, ast.Attribute):
        return first.attr.startswith("record_")
    return False


def test_leak_refused_path_still_emits_warning_log():
    """Anti-vacuity: the refusal path in fire_notification MUST still
    log at WARNING (the audit-of-record). Deleting the log line would
    silently drop the §164.312(b) trail entirely."""
    fn = _fire_notification_fn()
    src = ast.unparse(fn)
    assert "logger.warning" in src, (
        "N-359 REGRESSION: `fire_notification` no longer calls "
        "`logger.warning(...)` — the WARNING log line IS the "
        "§164.312(b) audit trail via SQLiteLogHandler → log_entries. "
        "Restoring the record_*_event emitter without a working "
        "conn is not a substitute (it's the class N-359 closed)."
    )
    assert "payload leak refused" in src, (
        "N-359: log message text 'payload leak refused' missing. This "
        "is the audit-of-record; changing it silently changes the "
        "grep-and-alert contract downstream ops rely on."
    )
