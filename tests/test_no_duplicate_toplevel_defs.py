"""Structural pin (census wf_56d1585d 2026-07-09 — HIGH #2, discovered class D3):
NO module-scope duplicate top-level defs across ``src/email_triage``.

What this defends
-----------------
The SSOT self-shadowing class. A second module-level ``def foo(...)`` overrides
the first at Python name level; if BOTH are decorated ``@router.get(<path>)``
the first-registered route wins at HTTP time but the SECOND ``def`` wins at
import time — split-brain false-confidence: unit tests calling ``foo(...)`` by
name exercise the SECOND body, HTTP calls to ``<path>`` exercise the FIRST.

Concrete HEAD evidence at census time:
- ``_isotime.py`` declared ``to_utc_iso_z`` twice — the SSOT source itself
  violates Prime Directive #6.
- ``agent_api.py`` double-registered 4 FastAPI endpoints
  (``bulk_mail_list``/``bulk_mail_list_full``/``bulk_mail_fetch``/
  ``bulk_calendar_fetch``) — the exact shape.
- 13 files across ``web/routers/ui/`` re-declare ``__getattr__`` twice; the
  first (install-singleton compat glue) is dead code from the second override.

Count-agnostic
--------------
Per ``pattern_count_agnostic_structural_drift_catch.md`` — asserts a PROPERTY
over every module (no name repeats at module scope), not a count. A new
double-def added tomorrow trips the same shape.

Scope + allowlist
-----------------
Scoped to ``src/email_triage/**/*.py`` via the shared harness. Only MODULE-SCOPE
``FunctionDef`` / ``AsyncFunctionDef`` are counted — nested defs, class
methods, and closure defs are legal to shadow. ``@typing.overload`` /
``@overload`` stubs are ALLOWED to share a name with each other and with the
single non-overload impl (that is the typing-overload contract). No other
same-name dup is legitimate at module scope.

``_ALLOWED_DUPLICATE_TOPLEVEL_DEFS`` is the explicit, documented set of
``(relpath, funcname)`` exemptions. Empty at build time: after the same-commit
fix every real duplicate is removed. An entry must carry a one-line
justification comment on the same line.

Meta-drift guarantee (PD#7)
---------------------------
Routes the walk through ``_pin_harness.iter_src_files`` + ``parse_module`` +
``relpath`` so the pin cannot drift in its scoping (per the run15 meta-pin
covenant). The teeth test proves the detector actually flags a planted dup.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath, parse_source


# (relpath, funcname) exemptions. Empty at build time; add ONLY with a one-line
# justification on the same line documenting WHY the module-scope dup is legit.
_ALLOWED_DUPLICATE_TOPLEVEL_DEFS: set[tuple[str, str]] = set()


def _is_overload_decorator(d: ast.expr) -> bool:
    """True if decorator ``d`` is ``@overload`` / ``@typing.overload``.

    Bare ``ast.Name`` (``@overload``) or ``ast.Attribute``
    (``@typing.overload``, ``@t.overload``). The typing-overload contract lets
    multiple stubs share a name with each other and with the impl — that is
    the ONE class of legal module-scope dup we tolerate.
    """
    name = (d.id if isinstance(d, ast.Name)
            else d.attr if isinstance(d, ast.Attribute) else None)
    return name == "overload"


def _iter_module_toplevel_defs(tree: ast.AST):
    """Yield every module-scope ``FunctionDef`` / ``AsyncFunctionDef``.

    ``tree.body`` only — nested/class-body defs are NOT module-scope name
    bindings so shadowing them is legal (a class method / a closure def).
    """
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _find_duplicates(tree: ast.AST) -> dict[str, list[int]]:
    """Return ``{funcname: [lineno, lineno, ...]}`` for every module-scope name
    that appears more than once, excluding ``@overload`` stubs.

    A name whose defs are ALL ``@overload``-decorated except at most one impl
    is legal (the typing contract). Every other repeat is a violation.
    """
    by_name: dict[str, list[tuple[int, bool]]] = {}
    for node in _iter_module_toplevel_defs(tree):
        is_overload = any(_is_overload_decorator(d) for d in node.decorator_list)
        by_name.setdefault(node.name, []).append((node.lineno, is_overload))
    dupes: dict[str, list[int]] = {}
    for name, occurrences in by_name.items():
        if len(occurrences) <= 1:
            continue
        non_overload = [ln for ln, ov in occurrences if not ov]
        if len(non_overload) > 1:
            dupes[name] = [ln for ln, _ in occurrences]
    return dupes


def _scan_src() -> list[tuple[str, str, list[int]]]:
    """Repo-wide scan. Returns ``[(relpath, funcname, [linenos, ...]), ...]``
    for every dup that is NOT on the allow-list, sorted for deterministic
    output."""
    violations: list[tuple[str, str, list[int]]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for name, linenos in sorted(_find_duplicates(tree).items()):
            if (rp, name) in _ALLOWED_DUPLICATE_TOPLEVEL_DEFS:
                continue
            violations.append((rp, name, linenos))
    return violations


def test_no_duplicate_toplevel_defs():
    """No module-scope duplicate top-level ``def`` / ``async def`` in src.

    Failure prints ``relpath:linenos funcname`` per violation so a maintainer
    can jump straight to the split-brain site.
    """
    violations = _scan_src()
    if violations:
        lines = [
            f"  {rp}:{','.join(str(ln) for ln in linenos)} — {name}"
            for rp, name, linenos in violations
        ]
        raise AssertionError(
            "Duplicate top-level def(s) at module scope in src/email_triage — "
            "the SSOT self-shadowing class (census wf_56d1585d finding D3):\n"
            + "\n".join(lines)
        )


def test_pin_has_teeth():
    """Detector flags a planted bad shape and passes a clean shape."""
    bad = (
        "def foo():\n"
        "    return 1\n"
        "\n"
        "def foo():\n"
        "    return 2\n"
    )
    good = (
        "def foo():\n"
        "    return 1\n"
        "\n"
        "def bar():\n"
        "    return 2\n"
    )
    assert _find_duplicates(parse_source(bad)), "pin missed a planted dup"
    assert not _find_duplicates(parse_source(good)), "pin flagged a clean module"


def test_overload_dups_are_legal():
    """``@overload`` stubs sharing a name with each other + one impl is legal
    per the typing-overload contract; the pin does NOT flag them."""
    src = (
        "from typing import overload\n"
        "\n"
        "@overload\n"
        "def f(x: int) -> int: ...\n"
        "\n"
        "@overload\n"
        "def f(x: str) -> str: ...\n"
        "\n"
        "def f(x):\n"
        "    return x\n"
    )
    assert not _find_duplicates(parse_source(src)), "pin false-flagged @overload"


def test_allow_list_is_grounded():
    """Every ``_ALLOWED_DUPLICATE_TOPLEVEL_DEFS`` entry must correspond to a
    real dup at HEAD — a stale exemption silently widens the net. Empty at
    build time; this stays a sanity check as the set grows."""
    if not _ALLOWED_DUPLICATE_TOPLEVEL_DEFS:
        return
    live_dups: set[tuple[str, str]] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for name in _find_duplicates(tree):
            live_dups.add((rp, name))
    stale = _ALLOWED_DUPLICATE_TOPLEVEL_DEFS - live_dups
    assert not stale, (
        f"Stale _ALLOWED_DUPLICATE_TOPLEVEL_DEFS entries (no matching HEAD "
        f"dup — delete): {sorted(stale)}"
    )
