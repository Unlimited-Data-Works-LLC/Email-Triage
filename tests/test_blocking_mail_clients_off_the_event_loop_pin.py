"""Cycle P db P1-1: a blocking mail client never runs on the event loop.

``providers/dispatcher._imap_test_connection`` was an ``async def`` that opened a stdlib
``imaplib`` session (connect, TLS, LOGIN, SELECT, LOGOUT) on the loop thread, so one slow
or stalled IMAP server froze every request the process was serving for up to a socket
timeout per step. The probe body now runs in ``asyncio.to_thread``
(``_imap_probe_blocking``).

  * BEHAVIOUR: while the probe's connect blocks, the loop still runs a callback (the
    fake connect waits for an Event only the loop can set).
  * STRUCTURAL (count-agnostic, every file under src/email_triage): no call that opens a
    BLOCKING mail session (``imap_connect`` and the stdlib ``imaplib`` / ``smtplib``
    client classes) sits directly in the body of an ``async def``. A ``lambda`` or a
    nested ``def`` is a boundary: its body runs wherever it is handed (``to_thread``).
    ``aioimaplib`` is the async client and is not on the list.
"""

from __future__ import annotations

import ast
import asyncio
import threading

from _pin_harness import assert_pin_has_teeth, enclosing_callable, walk_src

_BLOCKING_FUNCS = frozenset({"imap_connect"})
_BLOCKING_CLASSES = {"imaplib": frozenset({"IMAP4", "IMAP4_SSL", "IMAP4_stream"}),
                     "smtplib": frozenset({"SMTP", "SMTP_SSL", "LMTP"})}


def _is_blocking_open(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _BLOCKING_FUNCS
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.attr in _BLOCKING_CLASSES.get(func.value.id, frozenset())
    return False


def blocking_opens_on_the_loop(tree: ast.AST) -> list[tuple[str, int]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_blocking_open(node):
            scope = enclosing_callable(node)
            if isinstance(scope, ast.AsyncFunctionDef):
                found.append((scope.name, node.lineno))
    return found


def test_no_blocking_mail_session_opens_inside_an_async_def():
    found, sites = [], 0
    for _path, relpath, tree in walk_src():
        sites += sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_blocking_open(n))
        found += [f"{relpath}:{line} ({fn})" for fn, line in blocking_opens_on_the_loop(tree)]
    assert sites, "the net found no blocking mail-client call at all: the detector is blind"
    assert not found, (
        "a blocking imaplib/smtplib session opened on the event loop; move it into a sync "
        "helper run through asyncio.to_thread (cycle P db P1-1):\n  " + "\n  ".join(found))


def test_the_pin_has_teeth():
    bad = ("import imaplib\nasync def probe(h):\n    c = imaplib.IMAP4_SSL(h)\n    c.logout()\n")
    good = ("import asyncio, imaplib\n"
            "def _probe(h):\n    c = imaplib.IMAP4_SSL(h)\n    c.logout()\n"
            "async def probe(h):\n    return await asyncio.to_thread(_probe, h)\n"
            "async def probe2(h):\n    return await asyncio.to_thread(lambda: imap_connect(h, 993))\n")
    assert_pin_has_teeth(blocking_opens_on_the_loop, bad, good)
    assert_pin_has_teeth(blocking_opens_on_the_loop,
                         "async def p(h):\n    return imap_connect(h, 993)\n")
    assert not blocking_opens_on_the_loop(ast.parse(
        "import aioimaplib\nasync def p(h):\n    return aioimaplib.IMAP4_SSL(host=h)\n"))


def test_the_imap_probe_does_not_hold_the_event_loop(monkeypatch):
    """The fake connect blocks until the LOOP sets an Event. On the loop thread it waits
    out its own 3 s and reports that the loop never ran; on a worker thread the loop sets
    the Event at once."""
    import email_triage.providers.imap_fetch_transport as transport
    import email_triage.secrets as secrets_mod
    from email_triage.providers.dispatcher import _imap_test_connection

    release, seen = threading.Event(), {}

    def fake_connect(host, port, **kw):
        seen["loop_ran"] = release.wait(3)
        raise OSError("probe refused (test)")

    monkeypatch.setattr(transport, "imap_connect", fake_connect)
    monkeypatch.setattr(secrets_mod, "read_secret", lambda s, k: "pw")
    acct = {"provider_type": "imap", "id": 1,
            "config": {"host": "mail.invalid", "port": 993, "username": "u"}}

    async def go():
        task = asyncio.create_task(_imap_test_connection(acct, object()))
        await asyncio.sleep(0.05)
        release.set()
        return await task

    ok, msg = asyncio.run(go())
    assert ok is False and "probe refused" in msg
    assert seen.get("loop_ran") is True, "the IMAP probe blocked the event loop"
