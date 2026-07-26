""" -- `imaplib.IMAP4(_SSL)?` / `aioimaplib.IMAP4(_SSL)?` SSOT pin.

Every IMAP client construction MUST live in
`email_triage.providers.imap_fetch_transport` -- the SSOT that
applies the egress-allowlist netloc guard + SSL context posture.
Grounding: pre-existing docstring at
`providers/imap_fetch_transport.py:9` explicitly names this file as
the wrapper "chokepoint" for raw `imaplib.IMAP4(_SSL)` /
`aioimaplib.IMAP4(_SSL)` construction.

Companion to  httpx.AsyncClient +  smtplib.SMTP pins --
same pattern.

Prime Directive #6: routes through `_pin_harness`.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_SSOT_HOME = "providers/imap_fetch_transport.py"

_IMAP_CLASSES: frozenset[str] = frozenset({"IMAP4", "IMAP4_SSL"})
_IMAP_MODULES: frozenset[str] = frozenset({"imaplib", "aioimaplib"})


def _is_imap_construction(node: ast.AST) -> bool:
    """Match `imaplib.IMAP4(...)`, `imaplib.IMAP4_SSL(...)`,
    `aioimaplib.IMAP4(...)`, or `aioimaplib.IMAP4_SSL(...)`."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr not in _IMAP_CLASSES:
        return False
    v = node.func.value
    return isinstance(v, ast.Name) and v.id in _IMAP_MODULES


def test_no_imap_construction_outside_ssot():
    """Every raw IMAP client construction MUST live in
    `email_triage.providers.imap_fetch_transport`."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_HOME):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if _is_imap_construction(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        " imap SSOT: `imaplib.IMAP4(...)` / `imaplib.IMAP4_SSL(...)` / "
        "`aioimaplib.IMAP4(...)` / `aioimaplib.IMAP4_SSL(...)` outside "
        "`email_triage.providers.imap_fetch_transport`. Route through "
        "the SSOT for egress netloc guard + SSL context posture.\n\n"
        + "\n".join(offenders)
    )
