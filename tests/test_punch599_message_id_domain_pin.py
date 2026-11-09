"""Punch 599 — structural pin: no outbound Message-Id is minted with a reverse-DNS domain.

Invariants over EVERY ``src/email_triage`` module (count-agnostic):

A. Every ``make_msgid`` call — bare, aliased (``from email.utils import
   make_msgid as m``) or as an attribute (``email.utils.make_msgid`` /
   ``<x>.make_msgid``) — passes a domain (``domain=`` or a second positional).
   Without one, ``make_msgid`` calls ``socket.getfqdn()``.
B. ``make_msgid`` is called only in ``mail_headers.py`` (``make_message_id`` is
   the SSOT); every other module mints through it.

SCOPE CAVEAT: a ``getattr(email.utils, "make_msgid")`` lookup or a callable
passed around as a value is not followed. ``smtplib``'s EHLO default
(``local_hostname=None`` -> ``getfqdn()``) is a separate egress of the host name
and is NOT covered here (residual; see the punch 599 report).
"""
from __future__ import annotations

import ast

from _pin_harness import assert_pin_has_teeth, iter_src_files, parse_module, relpath

_SSOT_HOME = "mail_headers.py"


def _msgid_names(tree: ast.AST) -> set[str]:
    names = {"make_msgid"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "make_msgid" and a.asname:
                    names.add(a.asname)
    return names


def _msgid_calls(tree: ast.AST):
    names = _msgid_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if (isinstance(f, ast.Name) and f.id in names) or (
                isinstance(f, ast.Attribute) and f.attr == "make_msgid"):
            yield node


def msgid_without_domain(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for call in _msgid_calls(tree):
        has_domain = any(kw.arg == "domain" for kw in call.keywords) or len(call.args) >= 2
        if not has_domain:
            out.append(call.lineno)
    return out


def test_every_make_msgid_call_passes_a_domain():
    bad: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        bad += [f"{relpath(path)}:{ln}" for ln in msgid_without_domain(tree)]
    assert not bad, (
        "make_msgid() without a domain calls socket.getfqdn() (reverse DNS on "
        f"the event loop + internal FQDN in the Message-Id), punch 599: {bad}"
    )


def test_message_ids_are_minted_only_through_the_ssot():
    bad: list[str] = []
    seen_home = False
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        calls = list(_msgid_calls(tree))
        if relpath(path) == _SSOT_HOME:
            seen_home = bool(calls)
            continue
        bad += [f"{relpath(path)}:{c.lineno}" for c in calls]
    assert seen_home, "rig: mail_headers.make_message_id no longer calls make_msgid"
    assert not bad, (
        "Message-Id minted outside mail_headers.make_message_id (punch 599): "
        f"{bad}"
    )


def test_pin_has_teeth():
    assert_pin_has_teeth(
        msgid_without_domain,
        "import email.utils\nmsg['Message-Id'] = email.utils.make_msgid()\n",
        "import email.utils\nmsg['Message-Id'] = email.utils.make_msgid(domain=d)\n",
    )
    assert_pin_has_teeth(
        msgid_without_domain,
        "from email.utils import make_msgid as mk\nx = mk(idstring='a')\n",
        "from email.utils import make_msgid as mk\nx = mk('a', 'example.org')\n",
    )
