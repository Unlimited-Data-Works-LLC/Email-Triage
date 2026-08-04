""" v0.2.0 — ``record_mailbox_outcome`` sticky_error kwarg pin.

The lifecycle funnel signature is
``record_mailbox_outcome(account_id, mailbox, *, sticky_error)``:
``sticky_error`` is KEYWORD-ONLY so every call reads self-documenting
— SET-failing vs CLEAR-to-healthy is visible AT the call site rather
than depending on the reader knowing "positional 3rd arg is the
exception".

This pin structurally bans calls that pass a 3rd positional argument
(or more), which would either be a caller regression to the
pre-refactor shape or a hand-rolled bypass of the SSOT convention.
Positional ``account_id`` and ``mailbox`` remain allowed by convention.

Grounding: DA-115 F1 recommendation on the 2026-07-11 batched panel
(kwarg refactor); HIPAA-SME concurred deferring to v0.2.0 in-scope.
Prime Directive #1 down-payment: SSOT ships its count-agnostic
structural pin same-change.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


def _is_record_mailbox_outcome_call(node: ast.AST) -> bool:
    """Return True if `node` is a call to ``record_mailbox_outcome``.

    Accepts either bare ``record_mailbox_outcome(...)`` or attribute
    access like ``manager.record_mailbox_outcome(...)`` /
    ``wm.record_mailbox_outcome(...)`` / ``self.record_mailbox_outcome(...)``.
    """
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    if isinstance(fn, ast.Name) and fn.id == "record_mailbox_outcome":
        return True
    if isinstance(fn, ast.Attribute) and fn.attr == "record_mailbox_outcome":
        return True
    return False


def test_no_positional_third_arg_to_record_mailbox_outcome():
    """ — reject ``record_mailbox_outcome(account_id, mailbox, <exc>)``.

    The 3rd argument MUST be passed via ``sticky_error=`` kwarg. Two
    positional args (``account_id, mailbox``) are the SSOT-canonical
    shape; adding a 3rd positional re-introduces the pre-refactor
    ambiguity that DA-115 flagged.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if not _is_record_mailbox_outcome_call(node):
                continue
            if len(node.args) >= 3:
                offenders.append(
                    f"{rel}:{node.lineno}  record_mailbox_outcome(...) "
                    f"with {len(node.args)} positional args — pass the "
                    "outcome via ``sticky_error=<exc-or-None>`` kwarg"
                )
    assert not offenders, (
        " sticky_error kwarg SSOT: positional 3rd argument to "
        "``record_mailbox_outcome`` — the outcome MUST be passed via "
        "``sticky_error=`` kwarg for self-documenting SET-vs-CLEAR "
        "lifecycle semantics. Fix by rewriting the call:\n\n"
        "  manager.record_mailbox_outcome(account_id, mailbox, e)\n"
        "  →\n"
        "  manager.record_mailbox_outcome(\n"
        "      account_id, mailbox, sticky_error=e,\n"
        "  )\n\n" +
        "\n".join(offenders)
    )
