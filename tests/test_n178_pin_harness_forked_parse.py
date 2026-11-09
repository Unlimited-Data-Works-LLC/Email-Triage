"""N-178 pin — no forked ``ast.parse`` in pin files that already import ``_pin_harness``.

Census run20 R20_3: 197 raw ``ast.parse(x.read_text())`` fork sites (my structural walker;
census claimed 93 — 2× under-count per §7#1). HIPAA-load-bearing pins (audit_phi_access,
config_store_disjoint, n113 BAA, runtime_settings_hipaa_gate) silently fail-OPEN on
``enclosing_fn`` when they fork the parse call and skip ``annotate_parents``.

This pin does NOT force every one of the 197 test files to migrate today — that's the
adoption sweep (separate follow-up work). It closes the tighter defect: files that ALREADY
import ``_pin_harness`` MUST use ``parse_module`` (which calls annotate_parents inside), not
a bare ``ast.parse``. Half-adopted files are the specific failure mode
(``enclosing_fn`` returns ``"<module>"`` silently because ``parent`` links weren't set).

Non-goal: pinning bare ``ast.parse`` in files that don't yet import the harness at all.
Those files are covered by ``test_every_py_source_walker_uses_the_harness`` (adoption pin)
and the adoption sweep — this pin catches the HARDER-to-see partial-adoption drift.
"""
from __future__ import annotations

import ast
from pathlib import Path

# N-178 R21_1 meta-fix (2026-07-02): route the tests-tree walk through the
# harness `iter_files` instead of a raw `TESTS.rglob` — the pin protecting
# HIPAA pins from partial-adoption drift itself must not fork the walk
# (PD#6 — pins obey the SSOT rule too).
from _pin_harness import iter_files as _iter_files, parse_module

TESTS = Path(__file__).resolve().parents[1] / "tests"


def _imports_harness(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, (ast.ImportFrom,)) and n.module and "_pin_harness" in n.module:
            return True
        if isinstance(n, ast.Import):
            for a in n.names:
                if "_pin_harness" in a.name:
                    return True
    return False


def _ast_module_names(tree: ast.AST) -> set[str]:
    """Return every local name bound to the `ast` stdlib module — catches
    `import ast`, `import ast as _ast`, and any alias (DA must-fix)."""
    names = {"ast"}  # default; may be shadowed but that's caller's problem
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "ast":
                    names.add(a.asname or a.name)
    return names


def _finds_bare_ast_parse(tree: ast.AST) -> list[int]:
    """Widened per DA must-fix — catch `ast.parse` under any alias, e.g.
    `import ast as _ast; _ast.parse(...)`."""
    receivers = _ast_module_names(tree)
    hits = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "parse":
                v = n.func.value
                if isinstance(v, ast.Name) and v.id in receivers:
                    hits.append(n.lineno)
    return hits


# RATCHET BASELINE (2026-07-01, run20 R20_3 / N-178). The census surfaced 197 raw
# fork sites; a strict 0-tolerance pin would red-flag the entire suite (~349 hits
# under this stricter partial-adoption predicate) and block all commits. The
# adoption sweep is separately tracked as follow-up work; THIS pin blocks NEW
# drift by asserting the count does not grow. Migrations DECREMENT this baseline
# — the goal is to reach 0 and remove the ratchet.
_MAX_BARE_AST_PARSE_HITS = 0  # STRICT-0 (2026-07-09 post-drive-full-census sweep landed the last file-reading site; N-178 file-reading class fully closed — see the "N-178-tranche" commit chain)

# HIPAA-load-bearing pins — STRICT-0 per hipaa-sme must-fix (2026-07-01). These
# pins enforce §164.312(b) / §164.502(e) BAA / access-gate integrity. Silent
# `enclosing_fn`->'<module>' collapse on their walkers = the same pin-present-
# pin-blind trap N-134/PD#5 already cost us. Zero forked-parse tolerance.
_HIPAA_STRICT_PINS = {
    "test_audit_phi_access_pin.py",       # §164.312(b) audit integrity
    "test_config_store_disjoint_pin.py",  # §164.312(a) config-store boundary
    "test_n113_topic_backscan_baa_gate.py",  # §164.502(e) BAA gate
    "test_runtime_settings_hipaa_gate.py",   # §164.312(a)(2)(iv) HIPAA runtime gate
}


def test_no_bare_ast_parse_growth_in_files_that_import_harness():
    """Ratchet: hit count must not exceed the run20 baseline. New offenders fail
    the pin; migrations DECREMENT the baseline in the SAME commit that removes
    the sites (a commit-coupled baseline — not a distant-author decrement-please
    trap, per db-sme + DA must-fix). Reach 0 => flip to strict `assert not offenders`."""
    offenders: list[str] = []
    hipaa_offenders: list[str] = []
    for py in _iter_files(TESTS, "test_*.py"):
        rel = py.name
        tree = parse_module(py)
        if tree is None:
            continue
        if not _imports_harness(tree):
            continue
        # Skip synthetic-string parses (teeth tests) — a bare ast.parse on a
        # local `src`/`bad`/`ok` string constant doesn't touch a file and can't
        # collapse enclosing_fn on real code. We match by argument shape: a
        # `.read_text(...)` call means "reading a file", the concerning shape.
        lines = _finds_file_reading_ast_parse(tree)
        for ln in lines:
            entry = f"{py.relative_to(TESTS.parent)}:{ln}"
            offenders.append(entry)
            if rel in _HIPAA_STRICT_PINS:
                hipaa_offenders.append(entry)

    # HIPAA-load-bearing pin files: strict-0 (hipaa-sme must-fix).
    assert not hipaa_offenders, (
        "N-178 STRICT-0 CARVE-OUT VIOLATED — a HIPAA-load-bearing pin still "
        "forks `ast.parse(<file>.read_text())` instead of using `parse_module(...)` "
        "from the harness. These pins enforce §164.312(b)/§164.502(e)/access-gate "
        "integrity; a silent enclosing_fn->'<module>' collapse is the pin-present-"
        "pin-blind trap. Migrate NOW (see hipaa-sme N-178 must-fix):\n  "
        + "\n  ".join(hipaa_offenders)
    )

    n = len(offenders)
    assert n <= _MAX_BARE_AST_PARSE_HITS, (
        f"N-178 partial-harness-adoption drift GREW to {n} hits "
        f"(baseline {_MAX_BARE_AST_PARSE_HITS}). A file that imports _pin_harness now ALSO "
        f"hand-rolls ast.parse(<file>.read_text()), skipping annotate_parents → enclosing_fn "
        f"returns '<module>' silently. Use parse_module(...) from the harness. There is no "
        f"allow-list; a legit exception needs one, with a real reason. If it's a real regression, fix. "
        f"If it's migration progress (count went DOWN), decrement _MAX_BARE_AST_PARSE_HITS "
        f"IN THE SAME COMMIT that removed the sites (commit-coupled baseline — do NOT let a "
        f"future distant PR eat the red)."
    )


def _finds_file_reading_ast_parse(tree: ast.AST) -> list[int]:
    """Refine per db-sme must-fix: only flag `ast.parse(...)` whose argument
    contains a `.read_text(...)` call (i.e. reading a real source file). A
    synthetic string parse (teeth test) doesn't create the enclosing_fn hazard."""
    receivers = _ast_module_names(tree)
    hits = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        if n.func.attr != "parse":
            continue
        v = n.func.value
        if not (isinstance(v, ast.Name) and v.id in receivers):
            continue
        # Check the argument for a .read_text(...) descendant.
        if n.args and any(
            isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "read_text"
            for sub in ast.walk(n.args[0])
        ):
            hits.append(n.lineno)
    return hits


def test_pin_has_teeth():
    """Verify the file-reading detector fires on a bad shape + the alias-widening."""
    bad = """
from tests._pin_harness import parse_module, SRC_ROOT
import ast as _ast

def some_pin():
    for p in SRC_ROOT.rglob("*.py"):
        tree = _ast.parse(p.read_text())  # BAD: bypasses annotate_parents AND uses alias
"""
    tree = ast.parse(bad)
    assert _imports_harness(tree), "teeth: bad source must import harness"
    hits = _finds_file_reading_ast_parse(tree)
    assert hits, "teeth: file-reading detector must catch aliased `_ast.parse(read_text())`"

    # Synthetic-string parses are NOT flagged (teeth-test parses on constants).
    ok = """
from tests._pin_harness import SRC_ROOT
import ast

def teeth():
    bad = ast.parse("def f(): pass")  # synthetic string, no file
"""
    tree_ok = ast.parse(ok)
    hits_ok = _finds_file_reading_ast_parse(tree_ok)
    assert not hits_ok, "teeth: synthetic-string parse must NOT be flagged"
