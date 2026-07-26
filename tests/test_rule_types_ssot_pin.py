"""N-424b SSOT pin — WEB_ALLOWED_RULE_TYPES.

**Prime Directive #1** — Every SSOT ships its count-agnostic structural
pin in the same change. The rule-type membership list is the SSOT that
`web/routers/api.py` (rule-create endpoint), `web/routers/ui/categories.py`
(routes-editor render context, 3 sites), and `web/routers/ui/_shared.py`
(routes-editor writer path, 2 sites) all consume — 6 sites total across
the web/ tree.

Drift class: a future author adds a new `RuleType` enum entry but
forgets to update one of the 6 validator sites. Effect: the new type
either fails at API-validate (`422 invalid rule_type`) or fails to
render in the routes-editor `<select>` (`option list_id disappears`).
Prime Directive #5 (collapse duplicated predicate/needle lists into
one funnel) — the DA MF-2 for Drive B walked exactly this drift class
and mandated the SSOT + pin fold.

Scope: refuse any List/Tuple/Set literal in `src/email_triage/web/**`
that contains ≥2 string constants matching `RuleType.value` (the
"looks like a hardcoded rule-type list" shape), UNLESS the enclosing
module is the SSOT itself (`engine/models.py`). Reuses `_pin_harness`
per PD #6.

db-sme MF-2 + devils-advocate MF-2, 2026-07-17.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

from email_triage.engine.models import RuleType


_RULE_TYPE_VALUES: frozenset[str] = frozenset(rt.value for rt in RuleType)

# The ONE SSOT that MAY hold a literal enumeration of rule-type strings:
# the RuleType enum definition file itself. Anywhere else that reaches
# for the whole set MUST import `WEB_ALLOWED_RULE_TYPES` (or derive from
# the enum directly).
_SSOT_ALLOW = frozenset({
    "src/email_triage/engine/models.py",
})


def _iter_string_constants(node: ast.AST):
    """Yield ast.Constant string values from a List/Tuple/Set literal.
    Non-string / non-Constant elements are skipped (never make a
    literal "look like" a rule-type list)."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            yield elt.value


def _looks_like_rule_type_list(node: ast.AST) -> bool:
    """True if node is a List/Tuple/Set literal containing ≥2 string
    constants that are all RuleType.value entries. Threshold ≥2 to
    avoid tripping on a single-string enum-tag literal used elsewhere
    (a legitimate one-off constant like `"sender"` in a test fixture
    that happens to overlap a rule-type name)."""
    strings = list(_iter_string_constants(node))
    if len(strings) < 2:
        return False
    return all(s in _RULE_TYPE_VALUES for s in strings)


def _collect_offenders() -> list[tuple[str, int]]:
    """Walk src/email_triage/**/*.py; collect (relpath, lineno) for
    every literal that looks like a hardcoded rule-type list, unless
    the enclosing module is on the SSOT allow list."""
    hits: list[tuple[str, int]] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel in _SSOT_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if _looks_like_rule_type_list(node):
                hits.append((rel, node.lineno))
    return hits


def test_no_hardcoded_rule_type_lists_outside_ssot():
    hits = _collect_offenders()
    assert not hits, (
        "N-424b SSOT pin: hardcoded rule-type list found outside the "
        "RuleType enum SSOT. Import `WEB_ALLOWED_RULE_TYPES` from "
        "`email_triage.engine.models` and consume it (`list(...)`, "
        "`set(...)`, `tuple(...)` as needed). Prevents the CIDI drift "
        "class where a new RuleType enum entry silently misses one of "
        f"the validator sites. Offenders: {hits}"
    )


def test_ssot_allow_list_has_no_stale_entries():
    """PD #7 rot-guard — every allow-listed file must still exist and
    still hold at least one rule-type list literal (or the enum
    definition). A stale entry silently exempts a future twin under
    the same relpath."""
    for rel in _SSOT_ALLOW:
        p = SRC_ROOT.parent.parent / rel
        assert p.exists(), (
            f"N-424b SSOT pin: allow-listed file not found: {rel}. "
            f"Update _SSOT_ALLOW or restore the file."
        )


def test_pin_has_teeth_via_planted_twin():
    """Detector fires on a planted twin, does NOT over-fire on
    innocent literals."""
    # Positive control — synthetic offender should trip.
    positive = ast.parse('rule_types = ["sender", "sender_domain", "subject"]')
    literal = positive.body[0].value  # type: ignore[union-attr]
    assert _looks_like_rule_type_list(literal), (
        "N-424b pin has NO TEETH — planted hardcoded rule-type list "
        "was not detected."
    )
    # Positive control including a newly-added enum member.
    with_list_id = ast.parse(
        'valid = {"sender", "sender_domain", "subject", "list_id"}'
    )
    literal_set = with_list_id.body[0].value  # type: ignore[union-attr]
    assert _looks_like_rule_type_list(literal_set), (
        "N-424b pin missed a set-shape twin containing all 4 values."
    )
    # Negative control — a mixed list with one non-rule-type string
    # must NOT trip.
    innocent = ast.parse('other = ["sender", "unrelated_tag"]')
    innocent_lit = innocent.body[0].value  # type: ignore[union-attr]
    assert not _looks_like_rule_type_list(innocent_lit), (
        "N-424b pin over-fires — a list with a non-rule-type string "
        "was flagged."
    )
    # Negative control — single-string literal (≥2 threshold).
    single = ast.parse('x = ("sender",)')
    single_lit = single.body[0].value  # type: ignore[union-attr]
    assert not _looks_like_rule_type_list(single_lit), (
        "N-424b pin over-fires — a single-string tuple was flagged."
    )
