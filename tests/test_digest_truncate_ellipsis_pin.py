"""run18  — digest-family truncations use the truncate() ellipsis SSOT.

The digest family carried ad-hoc ``text[:n] + "…"`` slice-arithmetic truncations
that had drifted in the ELLIPSIS GLYPH — ``actions/digest.py`` used the ASCII
``"..."`` while ``actions/digest_render.py`` used the Unicode ``"…"`` (and the
table link-cap had a stale ``-3`` left from the 3-char ASCII form). They now
route through ``email_triage._textfmt.truncate`` (one glyph, one length
convention).

This pin is a LIGHT, count-agnostic lint: in the three digest-family modules it
bans the ad-hoc shape — a string-``+``/``+=`` whose added operand is an ellipsis
literal (``"…"`` or ``"..."``) — so a re-introduced inline truncation (especially
an ASCII ``"..."`` one) fails loud.

SCOPE CAVEAT (honest): scoped to the three digest-family modules ONLY. ~20 more
ad-hoc truncations live in ``cli.py`` (owned by the #6 env-token work) and
``cache/_redis.py``; routing those is a documented follow-on, NOT enforced here.
This is a consistency lint, not a correctness guarantee — it proves the glyph
goes through the SSOT, not that the chosen ``n`` is right. A descriptive marker
string that merely CONTAINS dots (e.g. ``"[...truncated...]"``) is not an
ellipsis literal and is intentionally not flagged.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, assert_pin_has_teeth, parse_module, parse_source

#: The digest-family modules this lint scopes to (SRC_ROOT-relative).
DIGEST_FAMILY = (
    "actions/digest.py",
    "actions/digest_render.py",
    "actions/recipient_digest.py",
)

#: Literal strings treated as a truncation ellipsis — both the Unicode glyph and
#: the ASCII three-dot form. The point of the SSOT is that NEITHER appears as an
#: inline slice-add tail anymore (they go through ``truncate``).
_ELLIPSIS_LITERALS = frozenset({"…", "..."})


def _is_ellipsis_const(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in _ELLIPSIS_LITERALS
    )


def _adhoc_ellipsis_truncations(tree: ast.AST) -> list[int]:
    """Line numbers of ad-hoc ellipsis-truncation shapes in ``tree``:
    ``<expr> + "<ellipsis>"`` / ``"<ellipsis>" + <expr>`` and ``x += "<ellipsis>"``.
    """
    hits: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if _is_ellipsis_const(node.left) or _is_ellipsis_const(node.right):
                hits.append(getattr(node, "lineno", 0))
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if _is_ellipsis_const(node.value):
                hits.append(getattr(node, "lineno", 0))
    return hits


def test_digest_family_truncations_route_through_ssot():
    offenders: dict[str, list[int]] = {}
    for rel in DIGEST_FAMILY:
        tree = parse_module(SRC_ROOT / rel)
        assert tree is not None, f"could not parse {rel}"
        lines = _adhoc_ellipsis_truncations(tree)
        if lines:
            offenders[rel] = lines
    assert not offenders, (
        "run18 #18 — digest-family ellipsis truncations must route through "
        "email_triage._textfmt.truncate, not an inline slice + ellipsis literal. "
        f"Ad-hoc shape(s) found (module -> line numbers): {offenders}"
    )


def test_pin_has_teeth():
    bad_ascii = "def f(x):\n    return x[:5] + '...'\n"
    good = (
        "from email_triage._textfmt import truncate\n"
        "def f(x):\n    return truncate(x, 5)\n"
    )
    assert_pin_has_teeth(
        lambda tree: bool(_adhoc_ellipsis_truncations(tree)), bad_ascii, good,
    )
    # The Unicode glyph is caught too — not just the ASCII outlier.
    assert _adhoc_ellipsis_truncations(parse_source("y = a[:3] + '…'\n"))
    # A descriptive marker that merely contains dots is NOT flagged.
    assert not _adhoc_ellipsis_truncations(
        parse_source("y = a[:3] + '\\n[...cut...]'\n")
    )
