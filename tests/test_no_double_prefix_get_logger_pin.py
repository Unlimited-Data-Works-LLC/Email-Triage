"""Structural pin — ``get_logger("...")`` call sites must not double-prefix.

BINDING invariant enforced by this pin
--------------------------------------

Every ``email_triage.triage_logging.get_logger(name)`` call site MUST be
representable such that the emitted logger name is single-prefix — i.e.
``email_triage.<X>``, never ``email_triage.email_triage.<X>``.

Why the pin exists
------------------

The SSOT lives at ``src/email_triage/triage_logging.py:get_logger`` (see
its docstring). Prior to this pin, ``get_logger`` unconditionally prepended
``email_triage.`` to whatever the caller passed. A well-meaning
standardization pass tagged ``# N-196b R21_4`` then rewrote ~24 call sites
from short-form (``"actions.move"``) to fully-qualified form
(``"email_triage.actions.move"``), which produced double-prefixed logger
names — ``email_triage.email_triage.actions.move`` — in production.

The 2026-07-12 fix made ``get_logger`` idempotent (strip a leading
``email_triage.`` if present) via a module-level SSOT helper
``_normalize_logger_name``. Both call conventions now emit a single-prefix
logger name at RUNTIME. This pin closes the loop at BUILD time: it walks
every call site's literal argument through the SAME normalization helper
(imported, not mirrored) and asserts the resulting logger name is
single-prefix.

Prime Directive coverage
------------------------

* PD-1: The SSOT ships its count-agnostic structural pin in the same change.
* PD-2: Interprocedural — the walker enumerates every ``get_logger`` call
  in ``src/email_triage/**/*.py`` via ``walk_src`` (which handles ``ast.walk``
  + ``rglob`` under the shared harness), not per-file and not ``len(X)==N``.
* PD-6: The pin obeys the SSOT rule too — it imports
  ``_normalize_logger_name`` from ``triage_logging`` (single-copy transform)
  AND routes its file/AST walk through ``_pin_harness.walk_src`` (single-copy
  walker). No re-rolled SRC_ROOT / rglob / ast.parse — meta-pins
  ``test_pin_harness_adoption.py`` enforce this.
"""

from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, walk_src

from email_triage.triage_logging import (
    _LOGGER_NAMESPACE_PREFIX,
    _normalize_logger_name,
)


def _is_get_logger_call(node: ast.Call) -> bool:
    """True when ``node`` is a call to ``get_logger`` — direct or attribute."""
    func = node.func
    if isinstance(func, ast.Name) and func.id == "get_logger":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "get_logger":
        return True
    return False


def _first_positional_literal(node: ast.Call) -> str | None:
    """Return the first positional arg's str literal, or None if not literal.

    ``get_logger(__name__)`` (a Name, not a Constant) yields None — safe by
    module semantics; nothing to check. Only string-literal call sites are
    scanned.
    """
    if not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _scan():
    """Walk the tree, return violations as (relpath, lineno, literal, emitted).

    A violation is a call site whose literal, when passed through the SSOT
    normalization, produces a name that CONTAINS ``email_triage.email_triage.``
    — the double-prefix pathology this pin exists to prevent — OR whose
    literal is empty (a call site typo).
    """
    violations = []
    double = f"{_LOGGER_NAMESPACE_PREFIX}{_LOGGER_NAMESPACE_PREFIX}"

    for path, relpath, tree in walk_src():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_get_logger_call(node):
                continue
            literal = _first_positional_literal(node)
            if literal is None:
                continue
            emitted = _normalize_logger_name(literal)
            if double in emitted or literal == "":
                violations.append((relpath, node.lineno, literal, emitted))
    return violations


def test_no_double_prefix_get_logger_call_sites() -> None:
    """No ``get_logger("...")`` literal produces a double-prefixed name."""
    violations = _scan()
    if violations:
        lines = [
            f"src/email_triage/{relpath}:{ln}  "
            f"get_logger({literal!r}) -> {emitted!r}"
            for relpath, ln, literal, emitted in violations
        ]
        pytest.fail(
            "get_logger() call sites produced a double-prefixed logger name "
            "(SSOT drift — see docstring). Offenders:\n  "
            + "\n  ".join(lines)
        )


def test_pin_scan_finds_call_sites() -> None:
    """Sanity self-check: the walker actually reaches ``get_logger`` calls.

    A silent-zero scanner is the worst kind of pin (Prime Directive #7 —
    census the censusers). If the walker returns 0 total call sites, the
    import path or the ``_is_get_logger_call`` matcher has drifted and this
    pin is asleep. Assert we see >= 20 literal-arg call sites — the actual
    ~24 N-196b sites plus the handful of short-form ones — with a comfortable
    floor to survive small refactors.
    """
    total_literal_calls = 0
    for path, relpath, tree in walk_src():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_get_logger_call(node):
                if _first_positional_literal(node) is not None:
                    total_literal_calls += 1
    assert total_literal_calls >= 20, (
        f"get_logger() call-site scan reached only {total_literal_calls} "
        f"literal-arg call sites under {SRC_ROOT} — the walker or the "
        f"matcher has drifted."
    )
