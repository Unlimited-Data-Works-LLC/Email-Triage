"""N-204 R22 structural pin — every `Action.execute` MUST emit
`record_idempotent_done` on non-error return paths (2026-07-02).

Census run22 R22_7 (MED — /flows-surface + provider-idempotency contract):
`AddLabelAction.execute` at `actions/add_label.py:258` returned COMPLETED
without emitting `record_idempotent_done`, so /flows didn't record that
the action ran + a bulk crash-recovery re-drive re-hit the provider API
per label. N-204 landed the stamp; this pin ensures every Action
subclass in `actions/` includes it (or is on the exempt list).

Structural check: every `class <X>(Action)` (or a subclass via
`_InviteResponseBase`) whose module contains an `execute` method MUST
either (a) call `record_idempotent_done` somewhere in the module, or
(b) be listed in `_EXEMPT`. The pin is FILE-scoped (not method-scoped)
because Actions often route through helper functions that stamp on
behalf of the caller.

Waivable per file via `_EXEMPT` with a reason.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


ACTIONS_DIR = SRC_ROOT / "actions"
STAMP_FN = "record_idempotent_done"
ACTION_BASE_NAMES = {"Action", "_InviteResponseBase"}  # subclasses of Action

_EXEMPT: dict[str, str] = {
    # base.py itself DEFINES the Action ABC + `record_idempotent_done`
    # helper; it does not implement an Action.
    "actions/base.py": "defines the Action ABC + the stamp helper",
    # (add more here if a legitimate exempt Action ships — e.g. a
    # side-effect-free query action.)
}


def _defines_action_subclass(tree: ast.AST) -> list[str]:
    """Return class names in `tree` that subclass any of `ACTION_BASE_NAMES`."""
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name in ACTION_BASE_NAMES:
                hits.append(node.name)
                break
    return hits


def _file_calls_stamp(tree: ast.AST) -> bool:
    """True if the module contains a Call to `record_idempotent_done` at any
    depth (attribute or Name form)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == STAMP_FN:
            return True
        if isinstance(fn, ast.Attribute) and fn.attr == STAMP_FN:
            return True
    return False


def _file_has_execute_method(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "execute":
            return True
    return False


def test_every_action_subclass_stamps_idempotency():
    """For every source file in `src/email_triage/actions/` that defines
    a subclass of `Action` (or `_InviteResponseBase`) AND an `execute`
    method: the module MUST contain a Call to `record_idempotent_done`."""
    missing: list[str] = []
    for path in iter_files(ACTIONS_DIR):
        rel = relpath(path)
        if rel in _EXEMPT:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        action_subclasses = _defines_action_subclass(tree)
        if not action_subclasses:
            continue  # not an Action module
        if not _file_has_execute_method(tree):
            continue  # abstract-only or intermediate — nothing to stamp
        if not _file_calls_stamp(tree):
            missing.append(f"{rel}  (classes: {', '.join(action_subclasses)})")
    assert not missing, (
        "N-204 R22: Action subclass missing `record_idempotent_done` "
        "stamp — /flows will not record that this action ran + a "
        "crash-recovery re-drive will re-hit the provider API. Add "
        "`await record_idempotent_done(flow, message, self.name, "
        "external_id=<stable-id>)` on the COMPLETED return path. Waive "
        "via `_EXEMPT` in this pin file with a reason.\n\n"
        + "\n".join(missing)
    )
