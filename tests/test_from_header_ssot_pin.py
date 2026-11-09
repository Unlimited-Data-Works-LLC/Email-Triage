"""From-header build SSOT pin (divergence census 2026-06-09 class #5).

The ``"Display Name" <addr>`` From-header build (quote-escape the name, wrap in
``<addr>``) was hand-rolled in 5 places — ``web/auth``, ``web/smtp_send``,
``providers/gmail_api``, ``providers/imap`` ×2 — and NONE stripped CR/LF, so a
display name containing a bare ``\\r``/``\\n`` could inject extra mail headers
(weakest-variant: the system had no CR/LF defense). They now route through one
SSOT ``mail_headers.format_from_header`` which strips control characters.

Count-agnostic: the distinctive From-header BUILD f-string shape
``f'"{name}" <{addr}>'`` must appear nowhere outside the SSOT module. (The bare
quote-escape ``.replace('"', '\\"')`` is NOT a usable sentinel — verify-don't-
accept found it is generic: metrics-label escaping, IMAP mailbox quoting,
hx-vals JSON escaping all use it without building a From header.)
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT as SRC, parse_module, walk_src  # N-350 R31

SSOT_REL = "mail_headers.py"


def _from_build_fstring_lines(tree: ast.AST) -> list[int]:
    """Lines with a From-header BUILD f-string — a JoinedStr whose literal parts
    contain ``" <`` (the ``"name" <addr>`` shape) and end at ``>``. Distinctive
    to From-header building; does NOT match a generic quote-escape."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            lits = "".join(
                v.value for v in n.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if '" <' in lits and lits.rstrip().endswith(">"):
                out.append(n.lineno)
    return out


def test_from_build_fstring_only_in_ssot():
    offenders = []
    for _p, rel, tree in walk_src():
        if rel == SSOT_REL:
            continue
        locs = _from_build_fstring_lines(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        'Hand-rolled From-header build f-string ("name" <addr>) outside '
        f"mail_headers.py (no old copy stripped CR/LF → header injection): "
        f"{offenders}. Call mail_headers.format_from_header(from_addr, from_name)."
    )


def test_ssot_defines_format_from_header():
    tree = parse_module(SRC / "mail_headers.py"); assert tree is not None  # N-350 R31
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "format_from_header" in names


def test_consumers_delegate():
    """The known senders/providers reference the SSOT (not a re-roll).

    N-303 R30 (CI-red fix-forward): accepts EITHER a direct
    `format_from_header` call OR routing through
    `build_alternative_message` (which internally calls the SSOT via
    N-272c MIME envelope migration). Both are SSOT-routed; the pin
    should track the intent (all From-header formatting funnels
    through the SSOT), not the specific import shape."""
    for rel in ("web/auth.py", "web/smtp_send.py",
                "providers/gmail_api.py", "providers/imap.py"):
        src = (SRC / rel).read_text(encoding="utf-8")
        assert ("format_from_header" in src
                or "build_alternative_message" in src), (
            f"{rel} no longer uses the From-header SSOT "
            "(directly OR via build_alternative_message)"
        )


def test_ssot_strips_crlf_injection():
    from email_triage.mail_headers import format_from_header as F
    # The fix: a CR/LF in the display name can't inject a header.
    out = F("a@b.com", "Evil\r\nBcc: victim@x.com")
    assert "\r" not in out and "\n" not in out
    assert out == '"Evil Bcc: victim@x.com" <a@b.com>'
    # Valid names byte-identical to the old escaping; empty → bare addr.
    assert F("a@b.com", "Alice") == '"Alice" <a@b.com>'
    assert F("a@b.com", "") == "a@b.com"
    assert F("a@b.com", None) == "a@b.com"


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        'def build(from_addr, name):\n'
        '    return f\'"{name}" <{from_addr}>\'\n',
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _from_build_fstring_lines(tree)


def test_pin_does_not_flag_generic_quote_escape(tmp_path):
    """A generic quote-escape that does NOT build a From header (metrics label,
    IMAP mailbox quote, hx-vals JSON) must NOT be flagged — the pin targets the
    From-build shape, not the escape idiom."""
    ok = tmp_path / "p.py"
    ok.write_text(
        'def esc(s):\n'
        '    return s.replace("\\\\", "\\\\\\\\").replace(\'"\', \'\\\\"\')\n'
        'def imap_quote(folder):\n'
        '    e = folder.replace(\'"\', \'\\\\"\')\n'
        '    return f\'"{e}"\'\n',
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _from_build_fstring_lines(tree)
