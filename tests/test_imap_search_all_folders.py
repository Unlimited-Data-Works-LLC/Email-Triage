"""Tests for cross-folder IMAP search (``filter.folder == '*'``).

Layer 3 of the aioimaplib mitigation routes the cross-folder path
through ``providers/imap_blocking.search_all_folders_blocking`` —
stdlib imaplib in ``asyncio.to_thread`` rather than aioimaplib —
because the same parser defects affecting fetch also affect SEARCH
across folder hierarchies. Tests here mock that backend.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


aioimaplib = pytest.importorskip("aioimaplib")

from email_triage.providers.imap import ImapProvider  # noqa: E402


def _make_provider(**kwargs):
    return ImapProvider(
        host="imap.test",
        username="u",
        password="p",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# search_all_folders → blocking backend
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_all_folders_dispatches_to_blocking_backend():
    """search_all_folders calls into providers.imap_blocking and
    returns its [(folder, uid), ...] output unchanged."""
    from email_triage.engine.models import MailFilter

    provider = _make_provider()

    fake_pairs = [
        ("INBOX", "100"),
        ("Archive", "200"),
        ("System", "300"),
    ]
    fake_blocking = AsyncMock(return_value=fake_pairs)

    with patch(
        "email_triage.providers.imap_blocking.search_all_folders_blocking",
        fake_blocking,
    ):
        result = await provider.search_all_folders(
            "", limit=10, filter=MailFilter(from_addr="x@y", folder="*"),
        )

    assert result == fake_pairs
    # Filter must be passed with folder stripped (the loop picks the
    # mailbox; filter only carries the remaining criteria).
    fake_blocking.assert_awaited_once()
    kwargs = fake_blocking.await_args.kwargs
    # Translator should have built FROM "x@y" — folder=None at this layer.
    assert "FROM" in kwargs["criteria"]
    assert "x@y" in kwargs["criteria"]


@pytest.mark.asyncio
async def test_search_all_folders_falls_back_on_backend_error():
    """If the blocking backend raises, the provider falls back to a
    single-folder search against the configured default mailbox so
    callers never see a hard failure for a transient cross-folder
    glitch."""
    from email_triage.engine.models import MailFilter

    provider = _make_provider(mailbox="INBOX")

    fake_blocking = AsyncMock(
        side_effect=RuntimeError("backend connection refused"),
    )

    with patch(
        "email_triage.providers.imap_blocking.search_all_folders_blocking",
        fake_blocking,
    ), patch.object(
        provider, "_search_in_current_mailbox",
        AsyncMock(return_value=["50", "51"]),
    ), patch.object(
        provider, "_connect", AsyncMock(return_value=object()),
    ):
        result = await provider.search_all_folders(
            "", limit=10, filter=MailFilter(from_addr="x@y", folder="*"),
        )

    assert result == [("INBOX", "50"), ("INBOX", "51")]


@pytest.mark.asyncio
async def test_search_wildcard_folder_dispatches_to_all_folders():
    """``filter.folder == '*'`` → search() returns flat UIDs from
    search_all_folders for backwards compat with single-folder
    callers. The bulk endpoints dispatch differently to keep
    folder-of-origin."""
    from email_triage.engine.models import MailFilter

    provider = _make_provider()

    fake_pairs = [("INBOX", "100"), ("Archive", "200")]
    with patch.object(
        provider, "search_all_folders",
        AsyncMock(return_value=fake_pairs),
    ), patch.object(
        provider, "_connect", AsyncMock(return_value=object()),
    ):
        uids = await provider.search(
            "", limit=10, filter=MailFilter(folder="*"),
        )

    assert uids == ["100", "200"]


@pytest.mark.asyncio
async def test_fetch_message_honors_folder_override():
    """fetch_message(folder=X) sends X as the mailbox to the stdlib
    backend, not the provider's default."""
    provider = _make_provider(mailbox="INBOX")

    raw = (
        b"From: a@b\r\nSubject: hi\r\nDate: Mon, 14 Apr 2026 10:30:00 +0000\r\n"
        b"\r\n"
    )
    captured = {}

    async def _fake_blocking(**kw):
        captured.update(kw)
        return raw, [r"\Seen"]

    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        _fake_blocking,
    ):
        await provider.fetch_message(
            "100", headers_only=True, folder="Archive",
        )

    assert captured["mailbox"] == "Archive"
    assert captured["uid"] == "100"


@pytest.mark.asyncio
async def test_fetch_message_default_uses_provider_mailbox():
    """No folder kwarg → default mailbox from __init__."""
    provider = _make_provider(mailbox="INBOX")

    raw = (
        b"From: a@b\r\nSubject: hi\r\nDate: Mon, 14 Apr 2026 10:30:00 +0000\r\n"
        b"\r\n"
    )
    captured = {}

    async def _fake_blocking(**kw):
        captured.update(kw)
        return raw, []

    with patch(
        "email_triage.providers.imap_blocking.fetch_message_blocking",
        _fake_blocking,
    ):
        await provider.fetch_message("100", headers_only=True)

    assert captured["mailbox"] == "INBOX"
