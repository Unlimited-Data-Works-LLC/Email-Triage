"""N-424 SSOT pin — ACME challenge-type dispatcher.

**Prime Directive #1** — Every SSOT ships its count-agnostic structural
pin in the same change. This pin covers the "which challenge type does
the renewer speak?" dispatcher, whose sole SSOT is the single-line
picker inside ``AcmeRenewer.issue_now`` in ``web/acme_renewer.py``:

    for c in authz.body.challenges:
        if c.typ == self.cfg.challenge:
            challenge = c
            break

Drift class: a future author hand-rolls a second `c.typ == "dns-01"` /
`c.typ == "http-01"` compare somewhere else (e.g., a helper for a
DIFFERENT ingress path, a diagnostic tool, a debug script), which
silently works under one challenge type + breaks under the other.
Prime Directive #5 (collapse duplicated predicate/needle lists into
one funnel) — this pin catches the SECOND copy at PR time, before it
ships.

Scope: refuse any `Compare` AST node whose left is an `Attribute`
`.typ` and whose right is a string constant `"dns-01"` OR `"http-01"`,
across the entire `src/` tree — with a single allow-list entry for
the SSOT line. The pin is count-agnostic per PD #1 and reuses the
shared `_pin_harness` per PD #6.

db-sme NTH-2, 2026-07-17.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath


_ACME_CHALLENGE_STRINGS = frozenset({"dns-01", "http-01"})


def _is_challenge_typ_compare(node: ast.AST) -> bool:
    """True when `node` is a Compare whose left is `<x>.typ` and whose
    right is a string constant `"dns-01"` or `"http-01"`.
    """
    if not isinstance(node, ast.Compare):
        return False
    if not isinstance(node.left, ast.Attribute):
        return False
    if node.left.attr != "typ":
        return False
    if len(node.comparators) != 1:
        return False
    right = node.comparators[0]
    if not isinstance(right, ast.Constant):
        return False
    return right.value in _ACME_CHALLENGE_STRINGS


def _collect_dispatch_sites() -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if _is_challenge_typ_compare(node):
                hits.append((relpath(path), node.lineno))
    return hits


# The SSOT dispatcher at AcmeRenewer.issue_now uses `c.typ == self.cfg.challenge`
# (a config-driven compare against a variable, NOT a string literal). So NO
# source file under src/ should hold a `c.typ == "dns-01"|"http-01"` literal.
# The absence of an allow-list is intentional and correct: it makes the pin
# a hard-refusal for the literal shape.


def test_acme_challenge_dispatcher_is_config_driven_no_literal_compare():
    hits = _collect_dispatch_sites()
    assert not hits, (
        "N-424 SSOT pin: `c.typ == 'dns-01'|'http-01'` compare found in "
        "src/. The SSOT dispatch at AcmeRenewer.issue_now is config-driven "
        "(`c.typ == self.cfg.challenge`); any string-literal compare "
        "hardcodes ONE challenge type + silently misbehaves under the other. "
        f"Offenders: {hits}. Route the compare through self.cfg.challenge, "
        "or thread the challenge type in as a parameter."
    )


def test_ssot_dispatcher_has_teeth_via_planted_twin():
    """Confirm the pin actually fires when a twin is planted. Uses a
    synthetic AST tree that mimics a hand-rolled compare — proves the
    detector is not vacuous."""
    synthetic = ast.parse('if c.typ == "dns-01":\n    pass\n')
    if_node = synthetic.body[0]
    compare = if_node.test  # type: ignore[union-attr]
    assert _is_challenge_typ_compare(compare), (
        "N-424 pin has NO TEETH — the detector missed a hand-rolled "
        "`c.typ == 'dns-01'` compare. Fix the detector before shipping."
    )

    synthetic_http = ast.parse('if c.typ == "http-01":\n    pass\n')
    if_node_http = synthetic_http.body[0]
    compare_http = if_node_http.test  # type: ignore[union-attr]
    assert _is_challenge_typ_compare(compare_http), (
        "N-424 pin has NO TEETH on http-01 shape."
    )

    # Negative control: a compare that isn't `.typ == "dns-01"|"http-01"`
    # must NOT trip the detector.
    innocent = ast.parse('if c.foo == "dns-01":\n    pass\n')
    innocent_cmp = innocent.body[0].test  # type: ignore[union-attr]
    assert not _is_challenge_typ_compare(innocent_cmp), (
        "N-424 pin over-fires — non-`.typ` attribute compare shouldn't trip."
    )

    unrelated_val = ast.parse('if c.typ == "sni-01":\n    pass\n')
    unrelated_cmp = unrelated_val.body[0].test  # type: ignore[union-attr]
    assert not _is_challenge_typ_compare(unrelated_cmp), (
        "N-424 pin over-fires — non-ACME string compare shouldn't trip."
    )
