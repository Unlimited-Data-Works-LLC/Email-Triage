"""Structural pin — Prime Directive #5: canonical defer idioms live in ONE
file (``scripts/hooks/_defer_phrases.py``). Scans ``scripts/hooks/*.py`` and
``scripts/git-hooks/*`` for hand-rolled copies of canonical phrase literals.

Prevents the CIDI drift caught by the DA review on ``11f991be``:
  * F1 — ``_scope_da.py::scope_cosign`` had ~11 canonical phrases hand-rolled
    inline in its Rule 2 prompt, ON THE DRIVE ESTABLISHING THE SSOT. Fixed in
    same commit by importing ``HUMAN_LABELS``. This pin makes the same class
    of drift structurally impossible.

Design decisions:
  * Scan is substring-based (case-insensitive) — no full regex parity with
    ``_defer_phrases::_PATTERNS``, but the tight-idiom probes are
    discriminative enough that a real duplicate list will fail the pin.
  * The pin is COUNT-AGNOSTIC (per Prime Directive #1) — every scanned file
    is asserted phrase-free, regardless of how many hooks exist.
  * Only ``scripts/hooks/_defer_phrases.py`` is allowed to hold the literals;
    everything else must import.
  * Test files are exempt (self-referentially they must carry the phrases as
    string literals to exercise detection).
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import iter_files, parse_module

REPO = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO / "scripts" / "hooks"
GIT_HOOKS_DIR = REPO / "scripts" / "git-hooks"
SSOT_FILE = HOOKS_DIR / "_defer_phrases.py"

# Discriminative substrings — short, high-signal fragments of canonical
# idioms. Chosen so a normal English sentence in a hook does NOT trip (e.g.
# a bare "defer" or "next" would over-fire; "follow-on drive" or "todo:
# defer" only appear when someone is naming a canonical idiom).
_PROBES = [
    "follow-on drive",
    "waiting on op",         # matches "waiting on op" / "waiting on operator"
    "todo: defer",
    "fixme: defer",
    "not worsened by this feature",
    "out of scope for this drive",
    "punted to",
    "parked for",
    "revisit in",
    "left for next",
    "pre-existing",           # part of "pre-existing … documented as follow-on"
]


def _iter_scan_files():
    """Yield the files to scan: hook source + git-hook shell scripts.
    Excludes the SSOT file itself (only allowed home for the literals).

    Routes ALL walks through ``_pin_harness.iter_files`` per meta-pin R5b —
    the WALK boilerplate lives in ONE place. The pin harness's ``iter_files``
    accepts an arbitrary ``root`` + ``pattern``, which is the exact seam this
    non-src-tree walker needs.
    """
    if HOOKS_DIR.exists():
        for p in iter_files(HOOKS_DIR, "*.py"):
            if p.resolve() == SSOT_FILE.resolve():
                continue
            yield p
    if GIT_HOOKS_DIR.exists():
        for p in iter_files(GIT_HOOKS_DIR, "*"):
            if p.is_file():
                yield p


def _iter_structural_string_literals(tree: ast.AST):
    """Yield every ``ast.Constant(str)`` node whose closest structural
    parent is an ``ast.List``, ``ast.Tuple``, ``ast.Set``, or ``ast.Dict``
    (i.e. the phrase appears in an actual list/tuple/set/dict literal that
    would be a hand-rolled COPY of the SSOT). Prose in comments, docstrings,
    error messages, log lines, or plain assignment RHS is NOT structural
    and does not fire — those are legitimate prose, not a mirrored data
    structure.

    Batch-panel MEDIUM #6 fold (2026-07-22): the original pin was
    substring-only and false-positived on a legitimate prose comment
    (``defer_gate.py:593``); the SSOT-owner-adjacent file was tripping
    its own pin. Restricting scan to structural literal bodies preserves
    the recurrence-shape catch (11f991be F1: ``_scope_da.py`` Rule 2
    prompt with a hand-rolled ~11-phrase list) without over-firing on
    prose.
    """
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if not isinstance(node, ast.Dict):
                continue
        # Dicts: check both keys and values that are string constants.
        if isinstance(node, ast.Dict):
            for kv in list(node.keys) + list(node.values):
                if isinstance(kv, ast.Constant) and isinstance(kv.value, str):
                    yield kv
            continue
        # Lists / tuples / sets: check element constants.
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                yield elt


def _scan_py_file_for_structural_hand_rolls(path: Path) -> list[str]:
    """Structural scan for .py files — probe substrings only in list /
    tuple / set / dict-literal string elements. Returns list of probe
    strings found.

    Routes through ``_pin_harness.parse_module`` per N-224 R22 / N-251 R25
    — the harness owns the read-then-parse combo so a syntax/io error in
    one src file does not abort the walk.
    """
    tree = parse_module(path)
    if tree is None:
        return []
    found: list[str] = []
    for lit in _iter_structural_string_literals(tree):
        low = lit.value.lower()
        for probe in _PROBES:
            if probe in low:
                found.append(probe)
    # de-dup while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for p in found:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _scan_shell_file_for_hand_rolls(path: Path) -> list[str]:
    """Substring scan for non-.py hook files (shell scripts under
    ``git-hooks/``) — shell has no AST parity here; substring is the
    only practical shape and hand-rolled canonical-phrase lists in a
    shell script are still the recurrence class."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return []
    return [probe for probe in _PROBES if probe in text]


def test_no_hand_rolled_defer_phrase_lists():
    """Every scanned hook file MUST be free of canonical defer-idiom
    literals INSIDE structural list/tuple/set/dict bodies. Hand-rolled
    COPIES of the SSOT phrase list re-open Prime Directive #5 CIDI drift.
    Prose comments / docstrings / log messages that happen to name a
    canonical idiom in flowing English are NOT the recurrence shape."""
    violations: list[str] = []
    for path in _iter_scan_files():
        if path.suffix == ".py":
            found = _scan_py_file_for_structural_hand_rolls(path)
        else:
            found = _scan_shell_file_for_hand_rolls(path)
        for probe in found:
            violations.append(
                f"{path.relative_to(REPO)}: hand-rolled canonical idiom "
                f"{probe!r} in a list/tuple/set/dict literal — import "
                f"from _defer_phrases instead"
            )
    assert not violations, (
        "Prime Directive #5 pin: canonical defer idioms must live only in "
        "scripts/hooks/_defer_phrases.py. Hand-rolled copies found:\n  "
        + "\n  ".join(violations)
    )


def test_ssot_file_contains_probes():
    """Sanity — the SSOT file itself MUST contain the probes we scan for,
    otherwise the pin is testing nothing (probes drifted from the SSOT)."""
    text = SSOT_FILE.read_text(encoding="utf-8", errors="replace").lower()
    missing = [p for p in _PROBES if p not in text]
    # Some probes are partial-string forms (e.g. "waiting on op" as a
    # substring of the pattern's regex "waiting\s+on\s+op(?:erator)?"). We
    # only require that a majority appear so the pin remains a real check
    # even if the SSOT re-shapes its regex escapes. If more than half go
    # missing, the probe list has drifted from the SSOT and needs an update.
    assert len(missing) <= len(_PROBES) // 2, (
        f"Probes drifted from SSOT — {len(missing)} of {len(_PROBES)} probes "
        f"not present in _defer_phrases.py: {missing}"
    )


def test_human_labels_alignment_pin():
    """Prime Directive #1 pin — HUMAN_LABELS must be aligned index-by-index
    with _PATTERNS (the runtime assert in _defer_phrases.py enforces this;
    the pin makes the invariant testable in CI)."""
    import sys
    sys.path.insert(0, str(HOOKS_DIR))
    from _defer_phrases import HUMAN_LABELS, _PATTERNS
    assert len(HUMAN_LABELS) == len(_PATTERNS), (
        f"HUMAN_LABELS ({len(HUMAN_LABELS)}) drifted from _PATTERNS "
        f"({len(_PATTERNS)}) — pair every new pattern with a label"
    )


def test_canonical_shapes_ssot_wired():
    """DA-F3 pin (46b4f107 batch panel) — CANONICAL_SHAPES lives ONLY in
    _defer_phrases; every downstream consumer imports from it.

    Asserts:
      (a) _defer_phrases.CANONICAL_SHAPES exists and matches the 9-element
          canonical enum shipped in the SSOT.
      (b) SHAPE_ACTIONS keys (router) ⊂ CANONICAL_SHAPES.
      (c) _ELIGIBLE_SHAPES (safe-context) ⊂ CANONICAL_SHAPES.
      (d) KNOWN_SHAPES (weights aggregator) is the CANONICAL_SHAPES tuple.
    Fork-catches: agent introduces a private shape list that drifts.
    """
    import sys
    sys.path.insert(0, str(HOOKS_DIR))
    from _defer_phrases import CANONICAL_SHAPES
    from _defer_shape_router import SHAPE_ACTIONS
    from _defer_safe_context import _ELIGIBLE_SHAPES
    from _defer_phrase_weights import KNOWN_SHAPES
    expected = {
        "hard-defer", "tracked-work", "waiting-op", "todo-marker",
        "blocked-on", "wip", "meta-doc", "false-positive", "error",
    }
    assert set(CANONICAL_SHAPES) == expected, (
        f"CANONICAL_SHAPES drifted from expected 9-element enum: "
        f"got {sorted(CANONICAL_SHAPES)}"
    )
    router_extra = set(SHAPE_ACTIONS) - set(CANONICAL_SHAPES)
    assert not router_extra, (
        f"SHAPE_ACTIONS re-forked shape names outside SSOT: {sorted(router_extra)}"
    )
    eligible_extra = set(_ELIGIBLE_SHAPES) - set(CANONICAL_SHAPES)
    assert not eligible_extra, (
        f"_ELIGIBLE_SHAPES re-forked shape names outside SSOT: {sorted(eligible_extra)}"
    )
    assert tuple(KNOWN_SHAPES) == tuple(CANONICAL_SHAPES), (
        "KNOWN_SHAPES (weights) diverged from CANONICAL_SHAPES SSOT — "
        "should be `from _defer_phrases import CANONICAL_SHAPES as KNOWN_SHAPES`"
    )


def test_sweep_patterns_ssot_wired():
    """Drive-2 SSOT pin: leira_defer_sweep.py MUST import SWEEP_PATTERNS from
    _defer_phrases (not hand-roll). Guards against re-forking the broad-net
    pattern list (Prime Directive #5).

    Test asserts:
      (a) The sweep source contains an import of SWEEP_PATTERNS.
      (b) The sweep source contains NO literal ``DEFER_PATTERNS = [`` (which
          is how the pre-Drive-2 hand-rolled list looked).
      (c) Runtime shape: leira_defer_sweep.DEFER_PATTERNS is the same object
          (or equal-length) as _defer_phrases.SWEEP_PATTERNS.
    """
    import sys
    sweep_src = (REPO / "scripts" / "leira_defer_sweep.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "from _defer_phrases import SWEEP_PATTERNS" in sweep_src, (
        "leira_defer_sweep.py must import SWEEP_PATTERNS from _defer_phrases "
        "(SSOT wire — Drive-2 of bridge arc)"
    )
    assert "DEFER_PATTERNS = [" not in sweep_src, (
        "leira_defer_sweep.py contains a re-forked DEFER_PATTERNS literal — "
        "delete it and use the SSOT import"
    )
    sys.path.insert(0, str(HOOKS_DIR))
    sys.path.insert(0, str(REPO / "scripts"))
    from _defer_phrases import SWEEP_PATTERNS
    import leira_defer_sweep as _sweep
    # db-sme F-DB1 (11f991be batch panel): identity assertion, not len-equality.
    # Length-only misses the Python last-def-wins fork mode (an author who
    # re-binds ``DEFER_PATTERNS = [...]`` AFTER the SSOT import with the same
    # count would slip a length-only pin). Identity check is Prime-Directive-#2
    # compliant (keyed on the seam reference, not a derived count).
    assert _sweep.DEFER_PATTERNS is SWEEP_PATTERNS, (
        "sweep DEFER_PATTERNS is not the SSOT reference — likely re-bound "
        "after the import (Prime Directive #5 violation)"
    )
