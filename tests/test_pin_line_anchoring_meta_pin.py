""" meta-pin — ban NEW line-anchored `(rel, lineno)` allow-lists in
pin files.

Line-anchored allow-lists (`_BASELINE_ALLOW: frozenset[tuple[str, int]]`
/ `_NAMED_DEVIATIONS: dict[tuple[str, int], str]`) CIDI-drift when
unrelated code changes shift the target line. This session hit the
trap THREE times on THREE separate pin files before the structural
migration to name-anchored `(rel, enclosing_fn)` shape via
`_pin_harness.enclosing_fn` (R38 SSOT).

This meta-pin locks in the discipline: any NEW `frozenset({(str,
int), ...})` literal introduced in `tests/**/*.py` is a violation.
Author routes through `enclosing_fn` (R38) or, when class-scoped
disambiguation is needed, `enclosing_qualified_name` (R38b).

Feedback drawer: `feedback_divergence_audit_and_ssot_pin` — this pin
is the meta-enforcement of that rule.

Allow-list: empty at HEAD. The 4 pre-#137 line-anchored allow-lists
were all migrated same-drive (test_wall_clock_hm_labeling_pin,
test_new_run_id_ssot_pin, test_base64url_ssot_pin,
test_triage_run_trigger_vocab_pin). Any future line-anchored
allow-list needs a documented justification + explicit allow-list
entry here.

Prime Directive #6: routes through `_pin_harness.iter_files` +
`relpath`. No hand-rolled walker.
"""
from __future__ import annotations

import ast
from pathlib import Path

from _pin_harness import iter_files, parse_module, relpath  # noqa: F401 (relpath used in future extension)

_TESTS_ROOT = Path(__file__).resolve().parent

# Allow-list is empty at HEAD post-#137 migration. Any documented
# future line-anchored allow-list needs to be enumerated here with
# a comment explaining why name-anchoring is impossible for the
# class (e.g. the site is genuinely OUTSIDE any function scope — a
# module-scope literal — and cannot be pinned by fn name).
_ALLOWED_LINE_ANCHORED: frozenset[str] = frozenset()


def _has_line_anchored_str_int_literal(tree: ast.Module) -> list[int]:
    """Return line numbers of every `frozenset({(str, int), ...})`
    literal AND every `dict[tuple[str, int], ...]` literal in `tree`."""
    hits: list[int] = []

    # frozenset({("...", <int>), ...})
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "frozenset" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Set):
                    for elt in first.elts:
                        if _is_str_int_tuple(elt):
                            hits.append(node.lineno)
                            break

    # dict literal `{("...", <int>): <value>, ...}` — the shape
    # `test_new_run_id_ssot_pin.py::_NAMED_DEVIATIONS` used pre-#137.
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is None:
                    continue
                if _is_str_int_tuple(key):
                    hits.append(node.lineno)
                    break

    return hits


def _is_str_int_tuple(node: ast.AST) -> bool:
    """True if `node` is a `("some str literal", <int literal>)` tuple."""
    if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
        return False
    a, b = node.elts
    if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
        return False
    if not (isinstance(b, ast.Constant) and isinstance(b.value, int)):
        return False
    return True


def test_no_new_line_anchored_allow_list_in_tests():
    """Ban NEW `frozenset({(str, int)})` / `{(str, int): _}` literals
    in `tests/**/*.py`. Use `(rel, enclosing_fn)` via
    `_pin_harness.enclosing_fn` (R38 SSOT) instead — survives
    unrelated line shifts."""
    offenders: list[str] = []
    for path in iter_files(_TESTS_ROOT, "*.py"):
        rel = relpath(path, _TESTS_ROOT)
        if rel == "test_pin_line_anchoring_meta_pin.py":
            # The meta-pin itself. Skip its own walker.
            continue
        if rel in _ALLOWED_LINE_ANCHORED:
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        hits = _has_line_anchored_str_int_literal(tree)
        for line in hits:
            offenders.append(f"tests/{rel}:{line}")
    assert not offenders, (
        " meta-pin: NEW line-anchored `(rel, lineno)` allow-list "
        "in a tests/ file. Line-anchored allow-lists CIDI-drift on "
        "unrelated code changes; use `(rel, enclosing_fn(node))` via "
        "the harness SSOT (`_pin_harness.enclosing_fn`, R38). If "
        "class-scoped disambiguation is needed, use "
        "`enclosing_qualified_name` (R38b). If the pinned site is "
        "genuinely module-scope, add the test file's basename to "
        "`_ALLOWED_LINE_ANCHORED` here with a comment.\n\n"
        + "\n".join(offenders)
    )
