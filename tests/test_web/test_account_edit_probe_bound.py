"""t20: the IMAP edit page's live folder probe is bounded by ONE connect budget.

``accounts_edit_form`` lists the account's folders live and falls back to a text input when
that fails ("Never block the edit flow on a network probe"). Against a server that accepts
the TCP connection and then never answers, the probe used to wait out the handshake wait
(``tls.tls_connect_async``) and then a fresh full greeting wait (``providers/imap.py``
``_connect``): 10 s + 10 s per render in production. The server here is a loopback socket that
listens and never reads, so the TLS handshake hangs exactly like a black-holed host.
"""

from __future__ import annotations

import socket
import time

import pytest

_BUDGET_S = 1.0


@pytest.fixture
def black_hole_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(8)  # the kernel completes the TCP handshake; nobody ever answers
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def test_edit_page_renders_within_one_budget_against_a_silent_server(
        client, admin_cookies, db, admin_user, black_hole_port, monkeypatch):
    import aioimaplib

    from email_triage.web.db import create_email_account

    # The budget the transport reads (panel M T7). The client's own greeting timeout keeps
    # its 10 s default, so a second full wait would show up as ~11 s.
    monkeypatch.setattr(aioimaplib.IMAP4, "TIMEOUT_SECONDS", _BUDGET_S)
    aid = create_email_account(db, admin_user["id"], "Silent Server", "imap",
                               {"host": "127.0.0.1", "port": black_hole_port})

    started = time.monotonic()
    resp = client.get(f"/accounts/{aid}/edit", cookies=admin_cookies)
    elapsed = time.monotonic() - started

    assert resp.status_code == 200
    assert "Silent Server" in resp.text
    assert elapsed < _BUDGET_S + 4.0, f"edit page took {elapsed:.1f} s for a {_BUDGET_S} s budget"


def test_render_probe_bound_degrades_to_the_text_input(
        client, admin_cookies, db, admin_user, black_hole_port, monkeypatch):
    """t20 render-probe bound: the page probe is bounded below the IMAP budget (the
    watcher's 10 s), and on the bound the page falls back exactly as on any probe
    failure: no folder checkbox list."""
    from email_triage.providers import render_probe
    from email_triage.web.db import create_email_account

    bound = 0.5
    monkeypatch.setattr(render_probe, "RENDER_PROBE_TIMEOUT_S", bound)  # the SSOT's own home
    aid = create_email_account(db, admin_user["id"], "Silent Server", "imap",
                               {"host": "127.0.0.1", "port": black_hole_port})

    started = time.monotonic()
    resp = client.get(f"/accounts/{aid}/edit?tab=watch", cookies=admin_cookies)
    elapsed = time.monotonic() - started

    assert resp.status_code == 200
    assert 'type="checkbox" name="mailboxes"' not in resp.text
    assert elapsed < bound + 3.0, f"edit page took {elapsed:.1f} s for a {bound} s render bound"
