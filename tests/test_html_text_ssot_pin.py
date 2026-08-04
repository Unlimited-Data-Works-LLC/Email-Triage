"""HTML→text SSOT + no-ad-hoc-tag-strip pin.

"Render an HTML body to text" lives in ONE place — ``engine/html_text.py``
(``html_to_text`` / ``html_to_text_with_links`` / ``strip_tags``), which drops
``<script>``/``<style>`` CONTENT (the census / leak class). Ad-hoc
``re.sub(r"<[^>]+>", "")`` strippers scattered across providers/web only removed
TAGS — leaking JS/CSS text into downstream consumers — and drifted into three
parallel renderers. They were converged onto the SSOT; this pin (a property over
every src file, not ``len(X)==N``) keeps the bare tag-strip sentinel out of live
code except the SSOT module so it can't creep back.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src

SSOT_REL = "engine/html_text.py"
#: The distinctive bare HTML tag-strip regex. A re-inlined ad-hoc HTML→text
#: stripper uses this literal; nothing else has a reason to carry it as code.
_SENTINEL = "<[^>]+>"


def _has_constant(tree: ast.AST, needle: str) -> list[int]:
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and n.value == needle
    ]


def test_bare_tag_strip_only_in_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if relpath(p) == SSOT_REL:
            continue  # the SSOT's _regex_fallback legitimately uses it
        if _has_constant(tree, _SENTINEL):
            offenders.append(f"{relpath(p)}:{_has_constant(tree, _SENTINEL)}")
    assert not offenders, (
        f"bare HTML tag-strip regex {_SENTINEL!r} outside the SSOT: {offenders}. "
        "Call email_triage.engine.html_text.html_to_text (body render) or "
        "strip_tags (one-liner) — they also drop <script>/<style> content."
    )


def test_ssot_still_carries_the_sentinel():
    """Guard against a rename that would make the pin vacuous: the SSOT's
    regex fallback must still hold the sentinel."""
    found = [
        relpath(p) for p, rel, tree in walk_src()
        if relpath(p) == SSOT_REL and _has_constant(tree, _SENTINEL)
    ]
    assert found == [SSOT_REL], (
        "the html_text SSOT no longer carries the tag-strip sentinel — the pin "
        "would be vacuous; check engine/html_text.py:_regex_fallback."
    )


def test_converged_sites_delegate_to_ssot():
    """The six former ad-hoc strippers now reference the SSOT funnel."""
    for rel in (
        "providers/gmail_api.py", "web/routers/agent_api.py", "web/digest.py",
        "providers/imap.py", "web/auth.py", "providers/dispatcher.py",
    ):
        txt = (SRC_ROOT / rel).read_text(encoding="utf-8")
        assert "html_to_text" in txt or "strip_tags" in txt, (
            f"{rel} no longer delegates HTML→text to the engine.html_text SSOT"
        )


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text('import re\nx = re.sub(r"<[^>]+>", "", body)\n', encoding="utf-8")
    tree = parse_module(bad); assert tree is not None
    assert _has_constant(tree, _SENTINEL)


def test_pin_comment_not_flagged(tmp_path):
    """A comment mentioning the old idiom must NOT trip the pin."""
    ok = tmp_path / "p.py"
    ok.write_text(
        "# was re.sub(r'<[^>]+>', '') — now html_to_text\n"
        "from email_triage.engine.html_text import html_to_text\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _has_constant(tree, _SENTINEL)
