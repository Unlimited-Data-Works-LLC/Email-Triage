""" -- `smtplib.SMTP(...)` construction SSOT pin.

Every outbound SMTP connection MUST be constructed inside
`email_triage.web.smtp_send` -- the SSOT that (a) applies the
egress-allowlist netloc guard, (b) times out, (c) runs the
`starttls` handshake per the project's policy.

Grounding: pre-existing docstring at
`web/smtp_send.py:67` explicitly names this as "The single place
`smtplib.SMTP(...)` is constructed (divergence census...)".
Companion to  httpx.AsyncClient SSOT-adoption pin -- same
shape.

Prime Directive #6: routes through `_pin_harness`. Name-anchored per
 R38.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_SSOT_HOME = "web/smtp_send.py"


def _is_smtp_construction(node: ast.AST) -> bool:
    """Match `smtplib.SMTP(...)` or `smtplib.SMTP_SSL(...)`."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr not in ("SMTP", "SMTP_SSL"):
        return False
    v = node.func.value
    return isinstance(v, ast.Name) and v.id == "smtplib"


def test_no_smtp_construction_outside_ssot():
    """Every `smtplib.SMTP(...)` / `smtplib.SMTP_SSL(...)` MUST live
    in `email_triage.web.smtp_send`."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_HOME):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_smtp_construction(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        " smtp SSOT: `smtplib.SMTP(...)` / `SMTP_SSL(...)` "
        "construction outside `email_triage.web.smtp_send`. Route "
        "through the SSOT for egress-allowlist netloc guard + "
        "timeout + starttls policy.\n\n"
        + "\n".join(offenders)
    )
