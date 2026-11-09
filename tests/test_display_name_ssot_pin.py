"""Sender display-name extraction SSOT pin (divergence census run13 ).

Pulling the DISPLAY NAME out of a From header (``"Alice" <a@b>`` -> ``Alice``)
was hand-rolled as ``sender.split("<")[0].strip().strip('"')`` in 4+ places
(digest, escalate, email_watches, watch_runner) — drifted on quote-stripping
(``.strip('"')`` vs ``.strip('"').strip("'")``) and a fragile parse.
``mail_headers.extract_display_name`` is the SSOT (the complement of
``extract_bare_address``); each caller keeps its own per-surface fallback.

Count-agnostic property: the ``…split("<")[0]`` display-name idiom must NOT
appear outside the SSOT module — every consumer calls ``extract_display_name``.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

_SSOT_REL = "mail_headers.py"


def _split_before_bracket_lines(tree: ast.AST) -> list:
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Subscript)
                and isinstance(n.slice, ast.Constant) and n.slice.value == 0):
            continue
        call = n.value
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "split" and call.args
                and isinstance(call.args[0], ast.Constant)
                and call.args[0].value == "<"):
            out.append(getattr(n, "lineno", "?"))
    return out


def test_no_rerolled_display_name_split_outside_ssot():
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        hits = _split_before_bracket_lines(tree)
        if hits:
            offenders.append(f"{rel}:{hits}")
    assert not offenders, (
        "A re-rolled display-name extraction (`sender.split(\"<\")[0]`) appears "
        f"outside the SSOT mail_headers.py: {offenders}. Call "
        "email_triage.mail_headers.extract_display_name(sender) instead — the "
        "copies drifted on quote-stripping (census run13 #11)."
    )


def test_ssot_extract_display_name_behaviour():
    from email_triage.mail_headers import extract_display_name
    assert extract_display_name('"Alice Smith" <a@b>') == "Alice Smith"
    assert extract_display_name("Alice <a@b>") == "Alice"
    assert extract_display_name("'Quoted' <a@b>") == "Quoted"  # strips single quotes too
    assert extract_display_name("a@b.com") == ""   # bare address -> caller's fallback
    assert extract_display_name("<a@b>") == ""      # empty display name
    assert extract_display_name("") == ""
    assert extract_display_name(None) == ""


def test_pin_has_teeth():
    bad = ast.parse('name = sender.split("<")[0].strip()\n')
    assert _split_before_bracket_lines(bad), "missed a split('<')[0] display-name idiom"
    ok = ast.parse('from email_triage.mail_headers import extract_display_name\n')
    assert not _split_before_bracket_lines(ok), "flagged a plain import"
    unrelated = ast.parse('first = path.split("/")[0]\n')
    assert not _split_before_bracket_lines(unrelated), "flagged a non-bracket split"
