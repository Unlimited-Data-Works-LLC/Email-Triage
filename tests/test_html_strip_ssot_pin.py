"""HTML→text strip SSOT pin (divergence census 2026-06-09, findings /).

A bare ``re.sub(r"<[^>]+>", ...)`` removes HTML *tags* but leaves the *content*
of ``<script>``/``<style>`` blocks intact. When that runs on **inbound, untrusted
email HTML** the leaked JS/CSS flows into the classifier-LLM input (a §164.308
(a)(1)(ii)(B) minimum-necessary / prompt-injection surface). The O365 provider
(``_strip_html``) and the paste path dumped inbound HTML this way, bypassing the
SSOT ``engine/html_text.html_to_text_with_links``, which skips script/style via
an HTMLParser ``_skip_depth``.

This pin bans the bare tag-strip idiom **except** in an allow-listed set of
sites that operate on TRUSTED, locally-generated content (outbound message
plain-text alternatives we compose) or are the SSOT's own internals. A new bare
strip — especially on an inbound path — must route through
``html_to_text_with_links`` (or justify itself in the allow-list with a reason).

Count-agnostic: a property over every ``re.sub`` call, not ``len(...) == N``.

SCOPE NOTE: this pin targets the bare ``<[^>]+>`` tag-strip IDIOM. Two *full*
parser-based HTML→text implementations still coexist with the SSOT —
``providers/gmail_api._html_to_text_fallback`` and
``web/routers/agent_api._html_to_text`` (``_HTMLStripper``). Both already drop
script/style and both operate on trusted/already-stripped input (gmail outbound
compose; the webhook API on ``msg.body_text`` that is already SSOT-stripped via
``providers/_normalize``) — NOT a live leak. They are a *separate* CIDI class
("multiple full HTML→text impls") tracked as a follow-up convergence (route both
through the SSOT, delete the locals); this idiom-pin does not — and is not meant
to — catch them.
"""

from __future__ import annotations

import ast

from _pin_harness import parse_module, relpath, walk_src

# Repo-relative paths permitted to use a bare ``<[^>]+>`` tag-strip, each with
# the reason it does NOT feed inbound/untrusted HTML to the strip:
_ALLOWED = {
    # The SSOT's own last-ditch fallback (now also drops <script>/<style>
    # blocks before stripping tags).
    "engine/html_text.py",
}


def _bare_tag_strip_lines(tree: ast.AST) -> list[int]:
    """Lines with ``<re>.sub("<[^>]+>", ...)`` — the tag-strip idiom."""
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "sub" and n.args):
            first = n.args[0]
            if (isinstance(first, ast.Constant) and isinstance(first.value, str)
                    and "<[^>]+>" in first.value):
                out.append(n.lineno)
    return out


def test_no_bare_html_tag_strip_outside_allowlist():
    offenders = []
    for _p, rel, tree in walk_src():
        if rel in _ALLOWED:
            continue
        locs = _bare_tag_strip_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "a bare re.sub(r'<[^>]+>', ...) HTML tag-strip outside the trusted "
        f"allow-list: {offenders}. It leaves <script>/<style> CONTENT intact; on "
        "an inbound/untrusted path that bleeds JS/CSS into the classifier LLM "
        "(census #12/#15). Route through "
        "email_triage.engine.html_text.html_to_text_with_links (skips "
        "script/style), or add the site to the allow-list with a reason if it "
        "only strips trusted, locally-generated HTML."
    )


# --------------------------------------------------------------------------
# Behavioural teeth — the SSOT (and its fallback) must DROP script/style content.
# --------------------------------------------------------------------------
def test_ssot_drops_script_and_style_content():
    from email_triage.engine.html_text import html_to_text_with_links
    out = html_to_text_with_links(
        "<style>.x{color:red}</style><script>steal()</script><p>hello</p>"
    )
    assert "hello" in out
    assert "steal" not in out and "color:red" not in out


def test_regex_fallback_drops_script_and_style_content():
    from email_triage.engine.html_text import _regex_fallback
    out = _regex_fallback(
        "<style>.x{color:red}</style><script>steal()</script><p>hello</p>"
    )
    assert "hello" in out
    assert "steal" not in out and "color:red" not in out


def test_regex_fallback_drops_unclosed_script_style():
    """db-sme + DA hardening: an UNCLOSED <script>/<style> (no end tag) must
    not leak its tail through the fallback either."""
    from email_triage.engine.html_text import _regex_fallback
    assert "steal" not in _regex_fallback("<p>ok</p><script>steal_me()")
    assert "color:red" not in _regex_fallback("<style>.x{color:red}")


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "import re\n"
        "def strip(h):\n"
        "    return re.sub(r'<[^>]+>', ' ', h)\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _bare_tag_strip_lines(tree)


def test_pin_ignores_non_tag_sub(tmp_path):
    ok = tmp_path / "p.py"
    ok.write_text(
        "import re\n"
        "def collapse(s):\n"
        "    return re.sub(r'\\\\s+', ' ', s)\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _bare_tag_strip_lines(tree)
