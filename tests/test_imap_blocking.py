"""Tests for ``providers.imap_blocking`` — the stdlib-imaplib body-fetch
fallback that bypasses aioimaplib's broken parser.

These tests stub out ``imaplib.IMAP4_SSL`` / ``imaplib.IMAP4`` so we
exercise the code paths without a live IMAP server. End-to-end
verification against a real server is done via the post-deploy
reproduce against ``/api/openclaw/accounts/{id}/bulk/mail``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


from email_triage.providers.imap_blocking import (  # noqa: E402
    _blocking_fetch,
    fetch_message_blocking,
)


def _stub_imap4_ssl_class(
    *,
    login_typ: str = "OK",
    select_typ: str = "OK",
    fetch_typ: str = "OK",
    fetch_data: list | None = None,
):
    """Return a class that, when instantiated, yields a mock client
    with the given canned responses on login/select/uid/logout.
    """
    if fetch_data is None:
        fetch_data = [
            (b"1 (UID 99 BODY[HEADER] {123}", b"From: a@b\r\nSubject: hi\r\n\r\n"),
            b" FLAGS (\\Seen))",
        ]

    def _factory(host, port):
        client = MagicMock()
        client.login = MagicMock(return_value=(login_typ, [b""]))
        client.select = MagicMock(return_value=(select_typ, [b"1"]))
        client.uid = MagicMock(return_value=(fetch_typ, fetch_data))
        client.logout = MagicMock()
        return client

    return _factory


def test_blocking_fetch_extracts_bytes_and_flags():
    factory = _stub_imap4_ssl_class()
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        raw_bytes, flags = _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=True,
        )

    assert b"From: a@b" in raw_bytes
    assert b"Subject: hi" in raw_bytes
    assert flags == [r"\Seen"]


def test_blocking_fetch_uses_body_peek_header_when_headers_only():
    captured = {}

    def _factory(host, port):
        client = MagicMock()
        client.login = MagicMock(return_value=("OK", [b""]))
        client.select = MagicMock(return_value=("OK", [b"1"]))

        def _uid(*args):
            captured["section"] = args[-1]
            return ("OK", [
                (b"1 (UID 99 BODY[HEADER] {0}", b""),
                b" FLAGS ())",
            ])
        client.uid = _uid
        client.logout = MagicMock()
        return client

    with patch("imaplib.IMAP4_SSL", side_effect=_factory):
        _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=True,
        )
    assert captured["section"] == "(BODY.PEEK[HEADER] FLAGS)"

    captured.clear()
    with patch("imaplib.IMAP4_SSL", side_effect=_factory):
        _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=False,
        )
    assert captured["section"] == "(BODY.PEEK[] FLAGS)"


def test_blocking_fetch_strips_recent_flag():
    factory = _stub_imap4_ssl_class(
        fetch_data=[
            (b"1 (UID 99 BODY[HEADER] {12}", b"X: y\r\n\r\n"),
            b" FLAGS (\\Seen \\Recent \\Flagged))",
        ],
    )
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        _, flags = _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=True,
        )

    # \Recent is session-only per RFC 3501 § 2.3.2 — strip it so it
    # doesn't pollute downstream "set of persistent labels" checks.
    assert r"\Seen" in flags
    assert r"\Flagged" in flags
    assert r"\Recent" not in flags


def test_blocking_fetch_raises_on_login_failure():
    factory = _stub_imap4_ssl_class(login_typ="NO")
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        with pytest.raises(RuntimeError, match="LOGIN refused"):
            _blocking_fetch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uid="99", headers_only=True,
            )


def test_blocking_fetch_raises_on_select_failure():
    factory = _stub_imap4_ssl_class(select_typ="NO")
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        with pytest.raises(RuntimeError, match="SELECT"):
            _blocking_fetch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uid="99", headers_only=True,
            )


def test_blocking_fetch_raises_on_fetch_failure():
    factory = _stub_imap4_ssl_class(fetch_typ="BAD")
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        with pytest.raises(RuntimeError, match="UID FETCH 99 failed"):
            _blocking_fetch(
                host="imap.test", port=993, use_ssl=True,
                username="u", password="p", mailbox="INBOX",
                uid="99", headers_only=True,
            )


def test_blocking_fetch_uses_imap4_when_ssl_disabled():
    factory_ssl = _stub_imap4_ssl_class()
    factory_plain = _stub_imap4_ssl_class()
    with patch("imaplib.IMAP4_SSL", side_effect=factory_ssl) as ssl_mock, \
         patch("imaplib.IMAP4", side_effect=factory_plain) as plain_mock:
        _blocking_fetch(
            host="imap.test", port=143, use_ssl=False,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=True,
        )
    assert plain_mock.call_count == 1
    assert ssl_mock.call_count == 0


def test_blocking_fetch_quotes_mailbox_with_whitespace():
    """Mailbox names with spaces (or other non-atom chars) must be
    quoted on the wire — stdlib imaplib doesn't auto-quote."""
    captured = {}

    def _factory(host, port):
        client = MagicMock()
        client.login = MagicMock(return_value=("OK", [b""]))

        def _select(mailbox, readonly=False):
            captured["mailbox"] = mailbox
            captured["readonly"] = readonly
            return ("OK", [b"1"])
        client.select = _select
        client.uid = MagicMock(return_value=("OK", [
            (b"1 (UID 1 BODY[HEADER] {0}", b""),
            b" FLAGS ())",
        ]))
        client.logout = MagicMock()
        return client

    with patch("imaplib.IMAP4_SSL", side_effect=_factory):
        _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p",
            mailbox="System.Backup Status",
            uid="1", headers_only=True,
        )

    # Quoted (whitespace forces quoting).
    assert captured["mailbox"] == '"System.Backup Status"'
    assert captured["readonly"] is True


def test_blocking_fetch_leaves_atom_safe_mailbox_bare():
    """Pure atom-safe names (INBOX, INBOX.System, etc.) skip
    quoting — bare form is valid + matches existing wire shape."""
    captured = {}

    def _factory(host, port):
        client = MagicMock()
        client.login = MagicMock(return_value=("OK", [b""]))

        def _select(mailbox, readonly=False):
            captured["mailbox"] = mailbox
            return ("OK", [b"1"])
        client.select = _select
        client.uid = MagicMock(return_value=("OK", [
            (b"1 (UID 1 BODY[HEADER] {0}", b""),
            b" FLAGS ())",
        ]))
        client.logout = MagicMock()
        return client

    with patch("imaplib.IMAP4_SSL", side_effect=_factory):
        _blocking_fetch(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p",
            mailbox="INBOX.System",
            uid="1", headers_only=True,
        )

    assert captured["mailbox"] == "INBOX.System"


@pytest.mark.asyncio
async def test_async_wrapper_runs_blocking_in_thread():
    """``fetch_message_blocking`` adapts the sync helper into an
    awaitable via ``asyncio.to_thread``."""
    factory = _stub_imap4_ssl_class()
    with patch("imaplib.IMAP4_SSL", side_effect=factory):
        raw_bytes, flags = await fetch_message_blocking(
            host="imap.test", port=993, use_ssl=True,
            username="u", password="p", mailbox="INBOX",
            uid="99", headers_only=True,
        )

    assert b"From: a@b" in raw_bytes
    assert flags == [r"\Seen"]
