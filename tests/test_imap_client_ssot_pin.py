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

from _pin_harness import assert_pin_has_teeth, iter_src_files, parse_module, relpath


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
        "#146 imap SSOT: `imaplib.IMAP4(...)` / `imaplib.IMAP4_SSL(...)` / "
        "`aioimaplib.IMAP4(...)` / `aioimaplib.IMAP4_SSL(...)` outside "
        "`email_triage.providers.imap_fetch_transport`. Route through "
        "the SSOT for egress netloc guard + SSL context posture.\n\n"
        + "\n".join(offenders)
    )


# t20 (2026-10-26): the greeting wait is part of the same SSOT. A bare
# ``client.wait_hello_from_server()`` restarts aioimaplib's full timeout after the
# handshake wait already spent it (10 s + 10 s for an unreachable server), and it
# never sees a connection task that already failed. Every greeting wait goes
# through ``imap_fetch_transport.aioimaplib_wait_hello``, which shares one budget.

def _hello_waits(tree: ast.AST) -> list[int]:
    return [node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "wait_hello_from_server"]


def test_no_greeting_wait_outside_ssot():
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_HOME):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        offenders += [f"{rel}:{line}" for line in _hello_waits(tree)]
    assert not offenders, (
        "`.wait_hello_from_server()` outside `email_triage.providers.imap_fetch_transport`. "
        "Wait for the IMAP greeting with `aioimaplib_wait_hello(client, started=...)` so the "
        "connect and the greeting share one timeout:\n\n" + "\n".join(offenders)
    )


def test_greeting_wait_detector_has_teeth():
    assert_pin_has_teeth(
        _hello_waits,
        bad_source="async def f(c):\n    await c._client.wait_hello_from_server()\n",
        good_source="async def f(c, t):\n    await aioimaplib_wait_hello(c, started=t)\n",
    )
