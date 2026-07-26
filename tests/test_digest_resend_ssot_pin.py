"""Digest resend-interval SSOT pin (divergence census run15 #1).

The digest duplicate-suppression window — "don't re-send within
``MIN_RESEND_INTERVAL_HOURS``" — is the ``actions.digest_resend`` SSOT: ONE
constant + ONE elapsed-window check (``resend_too_soon``) that normalizes BOTH
operands to aware-UTC. Two copies had drifted three ways: a DUPLICATED ``= 23``
constant (recipient_digest + digest_filter) and OPPOSITE-operand tz-normalization
(recipient_digest normalized only ``last_dt``, digest_filter only ``now`` — so each
RAISED ``TypeError`` on the naive/aware input the other handled, on a LIVE
delivery-suppression control), plus recipient_digest bypassed ``parse_iso`` with a
raw ``datetime.fromisoformat``.

This pin keeps them converged (count-agnostic over ``actions/``):
  (1) ``MIN_RESEND_INTERVAL_HOURS = <literal>`` may be assigned ONLY in
      ``digest_resend.py`` — every other module imports it (no second copy to drift).
  (2) NO hand-rolled resend-window check (``… < MIN_RESEND_INTERVAL_HOURS``
      ``Compare``) outside the SSOT — callers route the elapsed check through
      ``resend_too_soon`` (which owns the both-operands-aware-UTC normalization).

NET BOUNDARY (db-sme + DA review): property (2) keys on the NAMED constant. A future
drift that hand-rolls ``elapsed < 23`` with a BARE literal (or inlines
``.total_seconds()/3600`` against a different threshold var) slips this net —
ACCEPTED, because ``23`` is a ubiquitous hour-of-day literal (``0 <= h <= 23``
appears all over the codebase) so a bare-literal ban would false-positive broadly.
The named-constant pin covers the ACTUAL drift that occurred; a green pin here is
NOT "resend-window drift is impossible" (layered defense — the census backstops).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, parse_source, relpath

_SSOT_REL = "actions/digest_resend.py"
_CONST = "MIN_RESEND_INTERVAL_HOURS"


def _literal_const_assigns(tree: ast.AST) -> list[int]:
    """Lines where ``MIN_RESEND_INTERVAL_HOURS`` is assigned a numeric LITERAL
    (a second source-of-truth copy). An ``import`` of the name is NOT an assign."""
    out: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, (int, float)):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == _CONST:
                    out.append(n.lineno)
    return out


def _interval_compares(tree: ast.AST) -> list[int]:
    """Lines of a ``Compare`` that uses ``MIN_RESEND_INTERVAL_HOURS`` as an operand
    — the hand-rolled ``elapsed < MIN_RESEND_INTERVAL_HOURS`` resend-window check
    that must instead route through ``resend_too_soon``."""
    out: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            for x in [n.left, *n.comparators]:
                if isinstance(x, ast.Name) and x.id == _CONST:
                    out.append(n.lineno)
                    break
    return out


def test_resend_interval_constant_has_single_definition():
    offenders: list[str] = []
    for p in iter_src_files("actions"):
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders += [f"{rel}:{ln}" for ln in _literal_const_assigns(tree)]
    assert not offenders, (
        f"{_CONST} is assigned a numeric literal OUTSIDE the digest_resend SSOT "
        f"(a second copy that WILL drift — census run15 #1): {offenders}. Import it "
        "from email_triage.actions.digest_resend instead."
    )


def test_resend_window_check_only_in_ssot():
    offenders: list[str] = []
    for p in iter_src_files("actions"):
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders += [f"{rel}:{ln}" for ln in _interval_compares(tree)]
    assert not offenders, (
        f"a hand-rolled resend-window check (`… < {_CONST}`) appears OUTSIDE the "
        f"digest_resend SSOT: {offenders}. Use resend_too_soon(last_sent_iso, now) "
        "— it owns the both-operands-aware-UTC normalization that prevents the "
        "naive/aware TypeError (census run15 #1)."
    )
    # Anti-vacuity: the SSOT must actually DEFINE the funnel + the constant, else
    # both properties pass vacuously.
    ssot = parse_module(SRC_ROOT / _SSOT_REL)
    assert ssot is not None
    assert _literal_const_assigns(ssot), "digest_resend SSOT no longer defines the constant — pin vacuous"
    fn_names = {n.name for n in ast.walk(ssot) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "resend_too_soon" in fn_names, "digest_resend SSOT lost resend_too_soon — pin vacuous"


def test_pin_has_teeth():
    # A second literal constant IS flagged; an import is NOT.
    assert _literal_const_assigns(parse_source(f"{_CONST} = 23\n")) == [1]
    assert _literal_const_assigns(parse_source(f"from m import {_CONST}\n")) == []
    # A hand-rolled window Compare IS flagged (either operand order).
    assert _interval_compares(parse_source(f"x = elapsed < {_CONST}\n")) == [1]
    assert _interval_compares(parse_source(f"x = {_CONST} > elapsed\n")) == [1]
    # The funnel call is NOT flagged.
    assert _interval_compares(parse_source("x = resend_too_soon(a, b)\n")) == []
