"""Tests for IMAP provider resilience around the upstream aioimaplib bug.

Layer 3 of the mitigation routes ``ImapProvider.fetch_message`` through
the stdlib-imaplib blocking backend (``providers.imap_blocking``) via
``asyncio.to_thread``. Tests here mock that backend so we cover:

1. ``headers_only`` toggles BODY.PEEK[HEADER] vs BODY.PEEK[].
2. Body / link / attachment fields are empty when ``headers_only=True``.
3. Path C: a single retry on ``aioimaplib.Abort`` /
   ``aioimaplib.CommandTimeout`` from the blocking backend, on a fresh
   connection (``_reset_client_after_parser_error`` runs between
   attempts). Second failure surfaces.
4. ``_reset_client_after_parser_error`` is a no-op when there's no
   cached aioimaplib client (the IDLE / search path may never have
   opened one yet).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


aioimaplib = pytest.importorskip("aioimaplib")

from email_triage.providers.imap import ImapProvider  # noqa: E402


_HEADER_ONLY_RAW = (
    b"From: \"Test Sender\" <sender@example.test>\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: Plain header subject\r\n"
    b"Date: Wed, 1 May 2026 05:08:24 +0000\r\n"
    b"Message-ID: <abc123@example.test>\r\n"
    b"\r\n"
)


_FULL_BODY_RAW = (
    _HEADER_ONLY_RAW
    + b"Content-Type: text/plain; charset=utf-8\r\n"
    + b"\r\n"
    + b"Body content with (parens) and stray ) characters.\r\n"
)


# ---------------------------------------------------------------------------
# Headers-only fast path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_message_headers_only_dispatches_with_flag_set():
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )

    fake_blocking = AsyncMock(return_value=(_HEADER_ONLY_RAW, [r"\Seen"]))
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        msg = await provider.fetch_message("99", headers_only=True)

    fake_blocking.assert_awaited_once()
    kwargs = fake_blocking.await_args.kwargs
    assert kwargs["headers_only"] is True
    assert kwargs["uid"] == "99"
    assert kwargs["host"] == "imap.test"

    # Metadata populated from the parsed RFC 5322 block.
    assert "sender@example.test" in msg.sender
    assert msg.subject == "Plain header subject"
    assert msg.date is not None

    # Body / links / attachments left empty by design.
    assert msg.body_text == ""
    assert msg.body_html == ""
    assert msg.links == []
    assert msg.attachments == []


@pytest.mark.asyncio
async def test_fetch_message_default_dispatches_full_body():
    """Default (no kwarg) keeps body content in the returned message."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )

    fake_blocking = AsyncMock(return_value=(_FULL_BODY_RAW, [r"\Seen"]))
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        msg = await provider.fetch_message("99")

    kwargs = fake_blocking.await_args.kwargs
    assert kwargs["headers_only"] is False
    assert "Body content" in msg.body_text


# ---------------------------------------------------------------------------
# Path C: retry-once on aioimaplib-shaped errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_once_on_abort_succeeds_on_second_attempt():
    """One Abort, then success — caller sees the success."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )
    provider._reset_client_after_parser_error = AsyncMock()

    fake_blocking = AsyncMock(side_effect=[
        aioimaplib.Abort("first try blew up"),
        (_FULL_BODY_RAW, [r"\Seen"]),
    ])
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        msg = await provider.fetch_message("99")

    assert fake_blocking.await_count == 2
    provider._reset_client_after_parser_error.assert_awaited_once()
    assert "Body content" in msg.body_text


@pytest.mark.asyncio
async def test_retry_once_on_command_timeout_succeeds_on_second_attempt():
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )
    provider._reset_client_after_parser_error = AsyncMock()

    fake_command = MagicMock()
    fake_command.__str__ = lambda self: "XXX UID FETCH 99"

    fake_blocking = AsyncMock(side_effect=[
        aioimaplib.CommandTimeout(fake_command),
        (_FULL_BODY_RAW, [r"\Seen"]),
    ])
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        msg = await provider.fetch_message("99")

    assert fake_blocking.await_count == 2
    assert msg.subject == "Plain header subject"


@pytest.mark.asyncio
async def test_second_failure_surfaces_to_caller():
    """Two consecutive Aborts: caller sees the second exception."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )
    provider._reset_client_after_parser_error = AsyncMock()

    fake_blocking = AsyncMock(side_effect=[
        aioimaplib.Abort("first"),
        aioimaplib.Abort("second"),
    ])
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        with pytest.raises(aioimaplib.Abort, match="second"):
            await provider.fetch_message("99")

    assert fake_blocking.await_count == 2
    provider._reset_client_after_parser_error.assert_awaited_once()


@pytest.mark.asyncio
async def test_non_aioimaplib_error_does_not_retry():
    """A generic RuntimeError (e.g. LOGIN refused) is not a parser
    issue — no retry, surface directly so the caller can decide."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )
    provider._reset_client_after_parser_error = AsyncMock()

    fake_blocking = AsyncMock(side_effect=RuntimeError("LOGIN refused"))
    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        fake_blocking,
    ):
        with pytest.raises(RuntimeError, match="LOGIN refused"):
            await provider.fetch_message("99")

    assert fake_blocking.await_count == 1
    provider._reset_client_after_parser_error.assert_not_awaited()


# ---------------------------------------------------------------------------
# Reset helper — covers IDLE / search path that DOES still use aioimaplib
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_client_safe_when_no_client():
    """Reset on an unconnected provider is a no-op, doesn't raise."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )
    assert provider._client is None
    await provider._reset_client_after_parser_error()
    assert provider._client is None


@pytest.mark.asyncio
async def test_reset_client_closes_aioimaplib_client_when_present():
    """An aioimaplib client cached from a prior IDLE / search call gets
    torn down + nulled."""
    provider = ImapProvider(
        host="imap.test", username="u", password="p",
    )

    bad_client = MagicMock()
    bad_client.logout = AsyncMock()
    provider._client = bad_client

    await provider._reset_client_after_parser_error()

    assert provider._client is None
    bad_client.logout.assert_awaited_once()
