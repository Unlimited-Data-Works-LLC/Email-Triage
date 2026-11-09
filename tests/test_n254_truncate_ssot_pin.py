"""N-254 R25 structural pin — truncate SSOT bypass (2026-07-03).

Census R25 discovered MED #8 (truncate SSOT bypass): 12 sites drift-
mixed ASCII `...` and Unicode `…` for the same semantic — proof the
class is actively drifting.

N-254 fix: migrated 2 sites (`_secret_scrub.py:80`,
`web/routers/ui/_shared.py:1433`) to `_textfmt.truncate`. Left
`web/routers/agent_api.py:1883` — that site does a word-boundary
`rfind(" ", 0, n)` cut BEFORE the ellipsis, which the SSOT doesn't
support (it hard-cuts at `n - len(ellipsis)`). Allow-listed with the
reason.

WHAT IT PINS (structural, STRICT):

Any `<expr>[:<N>] + ('...'|'…')` (a Subscript-Slice + string
concatenation with a bare ellipsis literal) outside `_textfmt.py`
fires. Migration = `truncate(<expr>, <N>, ellipsis="...")`.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    enclosing_qualified_name,
    iter_files,
    parse_module,
    relpath,
)


_SSOT_FILES = {"_textfmt.py"}

_ELLIPSIS_LITERALS = frozenset({"...", "…"})

# Sites that legitimately hand-roll the truncate shape because their
# cut semantics differ from the SSOT (word-boundary rfind before the
# ellipsis, byte-length-based cuts, etc.). Add with a reason.
#
# N-341c R31 (2026-07-04): migrated from (path, lineno) to
# (path, enclosing_qualified_name) via the shared harness helper.
# Drift lineage on this pin: 1883 → 1887 after N-323 removed a nested
# import at :832 (N-330 R30 CI-red fix-forward). PD #1 line-number
# keying is guaranteed to re-drift on any edit above the site;
# fn-scope keying survives line shifts. Same migration pattern as
# N-341b applied to the N-260 pin.
_ALLOW: frozenset[tuple[str, str]] = frozenset({
    # web/routers/agent_api.py :: _collapse_snippet — cuts at the last
    # word-boundary via `rfind(" ", 0, n)` before appending `…`. SSOT
    # `_textfmt.truncate` hard-cuts at `n - len(ellipsis)` (no
    # word-boundary awareness), so migrating would degrade the
    # readable "sentence-ish" preview shape. Word-boundary semantics
    # documented + preserved.
    ("web/routers/agent_api.py", "_collapse_snippet"),
})


def test_no_raw_slice_plus_ellipsis_outside_ssot():
    """STRICT tree-wide: `<expr>[:N] + ('...'|'…')` outside `_textfmt.py`
    routes through `truncate(<expr>, N, ellipsis=...)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
                continue
            left, right = node.left, node.right
            # LHS must be a Subscript with a Slice.
            if not (isinstance(left, ast.Subscript)
                    and isinstance(left.slice, ast.Slice)):
                continue
            # RHS must be a bare ellipsis literal.
            if not (isinstance(right, ast.Constant)
                    and isinstance(right.value, str)
                    and right.value in _ELLIPSIS_LITERALS):
                continue
            qname = enclosing_qualified_name(node)
            if (rel, qname) in _ALLOW:
                continue
            offenders.append(
                f"{rel}:{node.lineno} ({qname})  <slice>[:N] + {right.value!r}"
            )
    assert not offenders, (
        "N-254 R25 truncate SSOT bypass: raw `<expr>[:N] + ('...'|'…')` "
        "shape outside `_textfmt.py`. Route through "
        "`truncate(<expr>, N, ellipsis='...')` — the SSOT owns the "
        "`n - len(ellipsis)` arithmetic + preserves EXACTLY N chars. "
        "If your site needs word-boundary or byte-length cut semantics "
        "the SSOT doesn't support, add "
        "``(relpath, enclosing_qualified_name)`` to `_ALLOW` with a "
        "reason (fn-scope keying survives line shifts; PD #1 count-"
        "agnostic).\n\n"
        + "\n".join(offenders)
    )
