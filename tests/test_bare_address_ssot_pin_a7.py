"""A7 (divergence census 2026-06-09) — bare-address extraction SSOT pin.

``EmailMessage.sender`` carries a raw ``From:`` header — usually
``"Display Name" <user@host>``. Pulling the bare ``user@host`` out of it
was hand-rolled in 5 places, each subtly different:

  * the ``s[s.index("<")+1 : s.index(">")]`` first-bracket slice — produced
    garbage when the display name itself contained ``>`` (and was the
    documented production bug: ``"CTOx" <news@email.ctox.com>`` matched as
    ``email.ctox.com>`` so the rule never fired);
  * a ``parseaddr``-based variant;
  * a ``split()[-1].strip("<>")`` last-token grab;
  * an account-bucket normaliser (also drops Gmail ``+suffix``).

The single authority is ``mail_headers.extract_bare_address`` (the
``<([^>]+)>`` regex; lower-cased). It feeds the salted per-contact HIPAA
recipient hash, so its output is behaviour-frozen.

This **count-agnostic** pin asserts the STRUCTURAL invariant: no module
under ``src/email_triage`` extracts a bare address by hand — neither via
``email.utils.parseaddr`` nor via the ``<``-bracket index/find slice —
outside the SSOT module. New code that re-rolls either idiom fails here
regardless of site count. (The display-NAME extractors — ``split("<")[0]``
— are a DIFFERENT class, not covered here.)
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

_ALLOWED = {"mail_headers.py"}

_BRACKET_CONSTS = {"<", ">"}
_SLICE_METHODS = {"index", "find", "rfind"}


def _is_angle_strip_call(node: ast.AST) -> bool:
    """The combined ``x.strip("<>")`` bare-address fallback idiom A7
    deleted (``s.split()[-1].strip("<>").lower()``). SME DA-#2: the pin
    must catch the exact idiom A7 removed, not just the slice.

    Deliberately scoped to the COMBINED ``strip`` with BOTH brackets — the
    Message-ID bracket normalization (``rfc_message_id.lstrip("<").rstrip(">")``
    in per_contact_hipaa) uses SEPARATE ``lstrip``/``rstrip`` and is a
    different operation; matching only ``strip("<>")`` keeps it out."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "strip"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return False
    arg = node.args[0].value
    return "<" in arg and ">" in arg


def _is_bracket_finder_call(node: ast.AST) -> bool:
    """``x.index("<")`` / ``x.find(">")`` / ``x.rfind("<")`` — a call that
    locates an angle bracket (the address-slice idiom)."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _SLICE_METHODS
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in _BRACKET_CONSTS
    )


def _is_parseaddr_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    return (isinstance(f, ast.Name) and f.id == "parseaddr") or (
        isinstance(f, ast.Attribute) and f.attr == "parseaddr"
    )


_RE_METHODS = {
    "compile", "search", "match", "fullmatch", "findall", "finditer",
    "sub", "subn", "split",
}


def _is_angle_capture_regex_call(node: ast.AST) -> bool:
    """A ``re.compile``/``re.search``/… call whose pattern literal captures the
    address out FROM BETWEEN angle brackets (``<(...)>`` — the SSOT's OWN idiom,
    e.g. ``re.compile(r"<([^>]+)>")``). Re-rolling the SSOT regex is the A7
    divergence in regex form (census run12 #9 — ``_FEEDBACK_ADDR_RE``).

    Scoped to a string literal passed to a ``re`` method (so a docstring or
    comment that merely MENTIONS ``<([^>]+)>`` — e.g. in ``classify/hints.py``
    or the SSOT's own docstring — is NOT a call arg and not flagged). Matches
    the SSOT shape + close variants (``<(.+?)>`` / ``<([^>]*)>``) via the
    ``<(`` … ``)>`` capture-between-brackets signature."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _RE_METHODS
    ):
        return False
    return any(
        isinstance(a, ast.Constant)
        and isinstance(a.value, str)
        and "<(" in a.value
        and ")>" in a.value
        for a in node.args
    )


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        if path.name in _ALLOWED:
            continue
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        rel = relpath(path)
        for node in ast.walk(tree):
            if _is_parseaddr_call(node):
                violations.append(f"{rel}:{node.lineno} (parseaddr — use extract_bare_address)")
            elif _is_angle_capture_regex_call(node):
                violations.append(
                    f"{rel}:{node.lineno} (re-rolled <(...)> address-capture regex "
                    f"— use extract_bare_address)"
                )
            elif _is_angle_strip_call(node):
                violations.append(
                    f"{rel}:{node.lineno} (strip(\"<>\") bare-address idiom — "
                    f"use extract_bare_address)"
                )
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
                if any(
                    _is_bracket_finder_call(sub)
                    for bound in (node.slice.lower, node.slice.upper)
                    if bound is not None
                    for sub in ast.walk(bound)
                ):
                    violations.append(
                        f"{rel}:{node.lineno} (angle-bracket index/find slice — "
                        f"use extract_bare_address)"
                    )
    return violations


def test_no_hand_rolled_bare_address_extraction():
    """Every bare-address extraction goes through
    ``mail_headers.extract_bare_address``. A hit re-rolled the idiom —
    replace it with the SSOT call."""
    violations = _find_violations()
    assert violations == [], (
        "Hand-rolled bare-address extraction (A7 divergence) at:\n  "
        + "\n  ".join(violations)
        + "\nUse mail_headers.extract_bare_address(sender)."
    )


def test_pin_has_teeth(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def f(s):\n"
        "    a = s[s.index('<') + 1 : s.index('>')]\n"
        "    _n, b = parseaddr(s)\n"
        "    return a, b\n",
        encoding="utf-8",
    )
    tree = parse_module(planted); assert tree is not None
    parse_hits = [n for n in ast.walk(tree) if _is_parseaddr_call(n)]
    slice_hits = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice)
        and any(
            _is_bracket_finder_call(sub)
            for bound in (n.slice.lower, n.slice.upper) if bound is not None
            for sub in ast.walk(bound)
        )
    ]
    assert parse_hits, "pin missed a planted parseaddr"
    assert slice_hits, "pin missed a planted bracket-slice"

    # The deleted strip("<>") fallback idiom must also be caught (DA-#2)...
    strip_planted = ast.parse("def g(s):\n    return s.split()[-1].strip('<>').lower()\n")
    assert any(_is_angle_strip_call(n) for n in ast.walk(strip_planted)), \
        "pin missed the planted strip('<>') address idiom"
    # ...but the separate Message-ID lstrip/rstrip bracket-normalization
    # must NOT be flagged (per_contact_hipaa:299 shape).
    msgid_norm = ast.parse("def h(m):\n    return m.lstrip('<').rstrip('>')\n")
    assert not any(_is_angle_strip_call(n) for n in ast.walk(msgid_norm)), \
        "Message-ID lstrip/rstrip must not be flagged as address extraction"

    # The re-rolled <(...)> address-capture regex (census run12 #9) must be caught.
    regex_planted = ast.parse('import re\n_R = re.compile(r"<([^>]+)>")\n')
    assert any(_is_angle_capture_regex_call(n) for n in ast.walk(regex_planted)), \
        "pin missed the planted <(...)> address-capture regex re-roll"
    # ...a docstring/comment that merely MENTIONS the regex is not a call arg.
    doc_planted = ast.parse('def d():\n    """uses the <([^>]+)> regex"""\n    return 1\n')
    assert not any(_is_angle_capture_regex_call(n) for n in ast.walk(doc_planted)), \
        "a docstring mention of the regex must not be flagged"
    # ...and a non-capture angle-bracket regex (no <(...)> capture idiom) is fine.
    other_planted = ast.parse('import re\n_X = re.compile(r"foo<bar>baz")\n')
    assert not any(_is_angle_capture_regex_call(n) for n in ast.walk(other_planted)), \
        "a non-address angle-bracket regex must not be flagged"


def test_extract_bare_address_behaviour():
    """The SSOT resolves the shapes the hand-rolled variants got wrong —
    and its output is frozen (it feeds the per-contact HIPAA hash)."""
    from email_triage.mail_headers import _extract_addr, extract_bare_address

    assert _extract_addr is extract_bare_address  # back-compat alias

    # Display-name form, all casings folded.
    assert extract_bare_address('"CTOx" <news@email.ctox.com>') == "news@email.ctox.com"
    assert extract_bare_address("Alice <A@B.COM>") == "a@b.com"
    # Bare address passes through (lower-cased).
    assert extract_bare_address("plain@x.io") == "plain@x.io"
    # The display-name-contains-'>' case the index/find slice broke.
    assert extract_bare_address('"A > B" <real@x.io>') == "real@x.io"
    # Empty / junk.
    assert extract_bare_address("") == ""
    assert extract_bare_address(None) == ""


def test_normalise_from_address_superset_unchanged():
    """`accounts.normalise_from_address` builds on the SSOT but keeps its
    Gmail +suffix canonicalization — behaviour must be unchanged."""
    from email_triage.db.accounts import normalise_from_address

    assert normalise_from_address('"Display Name" <Sam+work@Example.Tld>') == "sam@example.tld"
    assert normalise_from_address("alice@example.com") == "alice@example.com"
    assert normalise_from_address(None) == ""
    assert normalise_from_address("Bob <bob+news@x.io>") == "bob@x.io"
    # SME DA-#4 known edge: a display name containing an unescaped '<'
    # (pathological; RFC 5322 requires it quoted; providers normalize it
    # away). The first-bracket SSOT degrades vs the old last-bracket rfind,
    # but the failure is GRACEFUL — returns a str (no crash), and a wrong
    # per-alias bucket falls back to the account profile. Pin the
    # no-crash + str contract, NOT the exact degraded value.
    edge = normalise_from_address('"a<b" <real@x.io>')
    assert isinstance(edge, str)  # graceful, no exception
