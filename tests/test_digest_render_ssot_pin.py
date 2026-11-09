"""run18  — the digest reason/datetime cell helpers have ONE definition.

``_render_reason`` and ``_format_datetime`` were byte-identical duplicates in
``actions/recipient_digest.py`` (the SSOT) and ``actions/digest_render.py``. The
reason duplicate's standard-mode truncation could drift from the SSOT's, and the
datetime duplicate mirrored a ``%Y-%m-%d %H:%M`` form the "Show matches" template
had diverged from (an inline ISO ``[:16]`` slice that leaked the ``T`` separator).
``digest_render`` now imports both from the SSOT.

This pin keeps the dedup: it bans a second ``FunctionDef`` (or ``AsyncFunctionDef``)
named ``_render_reason`` / ``_format_datetime`` anywhere under ``src/email_triage``
except the SSOT module. Count-agnostic (every src file, every def via the shared
``_pin_harness`` walk) — a re-introduced copy fails loud. An IMPORT of the name, or
the ``format_digest_datetime`` alias assignment, is not a ``FunctionDef`` and is
deliberately allowed.
"""
from __future__ import annotations

import ast

from _pin_harness import assert_pin_has_teeth, walk_src

#: The SSOT home for both helpers (SRC_ROOT-relative, forward-slash).
SSOT_MODULE = "actions/recipient_digest.py"

#: The cell helpers whose definition must live ONLY in the SSOT module.
GUARDED_NAMES = frozenset({"_render_reason", "_format_datetime"})


def _guarded_defs_in_tree(tree: ast.AST) -> set[str]:
    """Names in :data:`GUARDED_NAMES` that ``tree`` DEFINES as a function."""
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in GUARDED_NAMES
    }


def _offenders() -> dict[str, set[str]]:
    """``relpath -> guarded def names`` for every src module that is NOT the SSOT."""
    out: dict[str, set[str]] = {}
    for _path, rel, tree in walk_src():
        if rel == SSOT_MODULE:
            continue
        names = _guarded_defs_in_tree(tree)
        if names:
            out[rel] = names
    return out


def test_no_duplicate_reason_or_datetime_helper():
    offenders = _offenders()
    assert not offenders, (
        "run18 #17 — _render_reason / _format_datetime must be DEFINED only in "
        f"{SSOT_MODULE} (import them elsewhere). Duplicate definition(s): {offenders}"
    )


def test_ssot_module_actually_defines_both():
    """Affirmative — the SSOT module DOES define both helpers, so the pin is
    guarding a real single home rather than passing vacuously because the names
    were removed everywhere."""
    found: set[str] = set()
    for _path, rel, tree in walk_src():
        if rel == SSOT_MODULE:
            found = _guarded_defs_in_tree(tree)
            break
    assert found == set(GUARDED_NAMES), (
        f"{SSOT_MODULE} must define exactly {set(GUARDED_NAMES)}; found {found}"
    )


def test_pin_has_teeth():
    bad = "def _render_reason(entry, hipaa):\n    return 'dup'\n"
    good = (
        "from x import _render_reason\n"
        "def render(entry):\n"
        "    return _render_reason(entry, False)\n"
    )
    assert_pin_has_teeth(
        lambda tree: bool(_guarded_defs_in_tree(tree)), bad, good,
    )
