"""Subject reply-prefix SSOT pin (divergence census run13 ).

Stripping leading ``Re:`` / ``Fwd:`` / ``Fw:`` from a subject was hand-rolled in
two places (``actions/self_sent_event.py`` self-sent dedup +
``cache/classification.py`` cache-key normalisation), with the regex drifted
(``(?:re|fwd?|fw)`` vs ``(?:re|fwd|fw)`` — equivalent today, but a future prefix
added to ONE would fragment the other's dedup/cache key). ``mail_headers``
(``strip_reply_prefix`` / ``SUBJECT_REPLY_PREFIX_RE``) is the SSOT.

Count-agnostic property: the reply-prefix alternation signature ``(?:re|fw…``
must NOT appear in a regex literal outside the SSOT module — every consumer
calls ``strip_reply_prefix``.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

_SSOT_REL = "mail_headers.py"
#: A non-capturing group beginning ``re|fw`` — the Re:/Fw:/Fwd: matcher idiom.
_SIG = "(?:re|fw"


def _reply_prefix_literals(tree: ast.AST) -> list:
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Constant) and isinstance(n.value, str)
                and _SIG in n.value.lower()):
            out.append(getattr(n, "lineno", "?"))
    return out


def test_no_rerolled_subject_reply_prefix_regex():
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        hits = _reply_prefix_literals(tree)
        if hits:
            offenders.append(f"{rel}:{hits}")
    assert not offenders, (
        "A re-rolled subject reply-prefix regex (the `(?:re|fw…` Re:/Fwd: "
        f"matcher) appears outside the SSOT mail_headers.py: {offenders}. Call "
        "email_triage.mail_headers.strip_reply_prefix(subject) instead of "
        "compiling the alternation — two copies WILL drift (census run13 )."
    )


def test_ssot_strip_reply_prefix_behaviour():
    from email_triage.mail_headers import strip_reply_prefix
    assert strip_reply_prefix("Re: Fwd: Re: Lunch") == "Lunch"
    assert strip_reply_prefix("FW: hi") == "hi"
    assert strip_reply_prefix("fwd: hi") == "hi"
    assert strip_reply_prefix("no prefix") == "no prefix"
    assert strip_reply_prefix("") == ""
    assert strip_reply_prefix(None) == ""


def test_pin_has_teeth():
    bad = ast.parse('R = re.compile(r"^\\\\s*(?:re|fwd?|fw)\\\\s*:\\\\s*")\n')
    assert _reply_prefix_literals(bad), "missed a re-rolled reply-prefix regex"
    ok = ast.parse('from email_triage.mail_headers import strip_reply_prefix\n')
    assert not _reply_prefix_literals(ok), "flagged a plain import"
    unrelated = ast.parse('R = re.compile(r"(?:foo|bar)")\n')
    assert not _reply_prefix_literals(unrelated), "flagged an unrelated regex"
