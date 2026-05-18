"""Tests for the IMAP provider with mocked aioimaplib."""

import email.policy
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Mock aioimaplib so we can import the provider without the real package.
# ---------------------------------------------------------------------------

_mock_aioimaplib = MagicMock()
_mock_aioimaplib.IMAP4_SSL = MagicMock
_mock_aioimaplib.IMAP4 = MagicMock
# Real exception classes so try/except in the provider works under
# this module-level mock — the provider catches Abort / CommandTimeout
# from the fetch path and a MagicMock isn't a BaseException subclass.
_mock_aioimaplib.Abort = type("Abort", (Exception,), {})
_mock_aioimaplib.CommandTimeout = type("CommandTimeout", (Exception,), {})


@pytest.fixture(autouse=True)
def _inject_aioimaplib():
    """Inject a mock aioimaplib into sys.modules for all tests."""
    with patch.dict(sys.modules, {"aioimaplib": _mock_aioimaplib}):
        # Force re-evaluation of HAS_AIOIMAPLIB.
        import email_triage.providers.imap as imap_mod
        imap_mod.HAS_AIOIMAPLIB = True
        yield


def _make_raw_email(
    sender="alice@example.com",
    to="bob@example.com",
    subject="Test Subject",
    body="Hello, world!",
    date="Mon, 14 Apr 2026 10:30:00 +0000",
) -> bytes:
    """Build a minimal RFC 822 email as bytes."""
    return (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


def _make_provider(**kwargs):
    """Create an ImapProvider with a mocked client."""
    from email_triage.providers.imap import ImapProvider

    provider = ImapProvider(
        host="mail.example.com",
        username="user@example.com",
        password="secret",
        **kwargs,
    )
    return provider


def _mock_client():
    """Create a mock IMAP client with async methods."""
    client = AsyncMock()
    client.wait_hello_from_server = AsyncMock()
    client.login = AsyncMock()
    client.select = AsyncMock()
    client.logout = AsyncMock()
    client.uid = AsyncMock()
    client.search = AsyncMock()
    client.fetch = AsyncMock()
    client.list = AsyncMock()
    client.create = AsyncMock()
    client.expunge = AsyncMock()
    client.idle_start = AsyncMock()
    client.idle_done = MagicMock()
    client.wait_server_push = AsyncMock()
    # #147 — pre-flight auth check reads ``get_state`` synchronously.
    # Default to AUTH so existing tests can ignore the new path; tests
    # that exercise NONAUTH / LOGOUT recovery override this.
    client.get_state = MagicMock(return_value="AUTH")
    return client


class TestImapProvider:
    def test_name(self):
        provider = _make_provider()
        assert provider.name == "imap"

    @pytest.mark.asyncio
    async def test_search_unseen(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        # search returns sequence numbers.
        client.search.return_value = ("OK", [b"1 2 3"])
        # fetch returns UIDs for the limited set (2 most recent).
        client.fetch.return_value = ("OK", [
            b"3 FETCH (UID 103)",
            b"2 FETCH (UID 102)",
        ])

        uids = await provider.search("is:unread", limit=2)
        client.search.assert_called_once_with("UNSEEN")
        # Reversed (most recent first), limited to 2, UIDs fetched.
        assert uids == ["103", "102"]

    @pytest.mark.asyncio
    async def test_search_custom_query(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        client.search.return_value = ("OK", [b"5"])
        client.fetch.return_value = ("OK", [b"5 FETCH (UID 200)"])

        uids = await provider.search("FROM boss@example.com")
        client.search.assert_called_once_with("FROM boss@example.com")
        assert uids == ["200"]

    @pytest.mark.asyncio
    async def test_search_failure(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        client.search.return_value = ("NO", [b""])
        uids = await provider.search("UNSEEN")
        assert uids == []

    @pytest.mark.asyncio
    async def test_fetch_message(self):
        """fetch_message routes through stdlib imaplib (Layer 3) —
        mock the blocking backend rather than the aioimaplib client.
        See ``providers/imap_blocking.py`` for the rationale."""
        from unittest.mock import patch as _patch
        provider = _make_provider()

        raw = _make_raw_email()
        with _patch(
            "email_triage.providers.imap_blocking.fetch_message_blocking",
            AsyncMock(return_value=(raw, [r"\Seen"])),
        ):
            msg = await provider.fetch_message("42")
        assert msg.message_id == "42"
        assert msg.provider == "imap"
        assert "alice@example.com" in msg.sender
        assert msg.subject == "Test Subject"
        assert "Hello, world!" in msg.body_text

    @pytest.mark.asyncio
    async def test_fetch_message_multipart(self):
        from unittest.mock import patch as _patch
        provider = _make_provider()

        raw = (
            b"From: sender@test.com\r\n"
            b"To: rcpt@test.com\r\n"
            b"Subject: Multipart\r\n"
            b"Date: Mon, 14 Apr 2026 10:30:00 +0000\r\n"
            b"Content-Type: multipart/alternative; boundary=bound123\r\n"
            b"\r\n"
            b"--bound123\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Plain text body\r\n"
            b"--bound123\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"\r\n"
            b"<p>HTML body</p>\r\n"
            b"--bound123--\r\n"
        )
        with _patch(
            "email_triage.providers.imap_blocking.fetch_message_blocking",
            AsyncMock(return_value=(raw, [])),
        ):
            msg = await provider.fetch_message("99")
        assert "Plain text body" in msg.body_text

    @pytest.mark.asyncio
    async def test_fetch_message_populates_wire_headers(self):
        """Regression: ImapProvider.fetch_message must copy all wire
        headers into EmailMessage.headers so downstream code (loop-
        prevention skip, List-Id routing, etc.) can read them.
        Live-observed bug: OTP emails with X-Email-Triage: otp got
        re-triaged by the watcher because this dict was empty."""
        from unittest.mock import patch as _patch
        provider = _make_provider()

        raw = (
            b"From: loopback@example.com\r\n"
            b"To: watched@example.com\r\n"
            b"Subject: Email Triage Login Code: 483997\r\n"
            b"Date: Mon, 14 Apr 2026 10:30:00 +0000\r\n"
            b"X-Email-Triage: otp; version=abc123; generated=2026-04-23T12:00:00-04:00\r\n"
            b"List-Id: newsletters.example.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Your login code is 483997.\r\n"
        )
        with _patch(
            "email_triage.providers.imap_blocking.fetch_message_blocking",
            AsyncMock(return_value=(raw, [])),
        ):
            msg = await provider.fetch_message("99")
        # Case-preserving, exact-key lookup should return the stamp.
        assert "X-Email-Triage" in msg.headers
        assert msg.headers["X-Email-Triage"].startswith("otp;")
        assert msg.headers["List-Id"] == "newsletters.example.com"
        # Standard fields still populate.
        assert msg.sender.endswith("loopback@example.com>") or "loopback@example.com" in msg.sender
        assert "Login Code" in msg.subject

    @pytest.mark.asyncio
    async def test_fetch_failure(self):
        """A protocol-level failure surfaces from the stdlib backend
        as a RuntimeError — caller sees it directly (no Path C retry
        because it's not an aioimaplib-shaped exception)."""
        from unittest.mock import patch as _patch
        provider = _make_provider()
        with _patch(
            "email_triage.providers.imap_blocking.fetch_message_blocking",
            AsyncMock(side_effect=RuntimeError("IMAP UID FETCH bad failed: NO")),
        ):
            with pytest.raises(RuntimeError, match="FETCH"):
                await provider.fetch_message("bad")

    @pytest.mark.asyncio
    async def test_apply_label_flag(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        await provider.apply_label("42", "\\Flagged")
        client.uid.assert_called_once_with("store", "42", "+FLAGS", "(\\Flagged)")

    @pytest.mark.asyncio
    async def test_apply_label_folder(self):
        provider = _make_provider()
        client = _mock_client()
        # apply_label now reads (result, _data) from the COPY call so
        # it can detect TRYCREATE / [NO] and auto-create on miss.
        client.uid.return_value = ("OK", [b""])
        provider._client = client

        await provider.apply_label("42", "Important")
        client.uid.assert_called_once_with("copy", "42", "Important")

    @pytest.mark.asyncio
    async def test_apply_label_folder_auto_creates_when_missing(self):
        """COPY returns NO → CREATE then retry COPY. Pattern matches
        Gmail's label auto-create — operators don't pre-provision
        folders for every category."""
        provider = _make_provider()
        client = _mock_client()
        # First COPY fails, CREATE succeeds, second COPY succeeds.
        client.uid.side_effect = [("NO", [b"[TRYCREATE]"]), ("OK", [b""])]
        client.create.return_value = ("OK", [b""])
        provider._client = client

        await provider.apply_label("42", "Notifications")
        # Two COPY calls + one CREATE.
        assert client.uid.call_count == 2
        client.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_folder_surfaces_server_no_reason(self):
        """Dovecot rejects CREATE with a tagged-response reason
        (e.g. ``NO [ALREADYEXISTS] Mailbox already exists``).
        Discarding the response data loses the diagnostic. The
        RuntimeError must include the server's reason so the operator
        sees WHY without enabling debug logs."""
        provider = _make_provider()
        client = _mock_client()
        client.create.return_value = (
            "NO", [b"[ALREADYEXISTS] Mailbox already exists"],
        )
        provider._client = client

        import pytest as _pt
        with _pt.raises(RuntimeError) as ei:
            await provider.create_folder("Important")
        msg = str(ei.value)
        assert "Important" in msg
        assert "NO" in msg
        assert "ALREADYEXISTS" in msg

    @pytest.mark.asyncio
    async def test_create_folder_handles_empty_response_data(self):
        """If the server returns NO with no payload, the error still
        names the folder and the result code; no IndexError."""
        provider = _make_provider()
        client = _mock_client()
        client.create.return_value = ("NO", [])
        provider._client = client

        import pytest as _pt
        with _pt.raises(RuntimeError) as ei:
            await provider.create_folder("Important")
        msg = str(ei.value)
        assert "Important" in msg
        assert "NO" in msg

    @pytest.mark.asyncio
    async def test_move_message_failure_carries_initial_copy_reason(self):
        """When the initial COPY fails AND the auto-create also fails,
        the surfaced RuntimeError must include both rejections so the
        operator can distinguish "folder doesn't exist + CREATE
        denied" from "folder exists but COPY denied"."""
        provider = _make_provider()
        client = _mock_client()
        client.uid.return_value = (
            "NO", [b"[TRYCREATE] Mailbox doesn't exist"],
        )
        client.create.return_value = (
            "NO", [b"Permission denied to create mailbox"],
        )
        provider._client = client

        import pytest as _pt
        with _pt.raises(RuntimeError) as ei:
            await provider.move_message("11178", "Important")
        msg = str(ei.value)
        assert "Important" in msg
        assert "11178" in msg
        # Initial-COPY reason carried through.
        assert "TRYCREATE" in msg or "doesn't exist" in msg.lower()
        # Auto-create reason carried through.
        assert "Permission denied" in msg

    @pytest.mark.asyncio
    async def test_close(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        await provider.close()
        client.logout.assert_called_once()
        assert provider._client is None

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self):
        provider = _make_provider()
        await provider.close()  # Should not raise.


    @pytest.mark.asyncio
    async def test_peek_recent_uids(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        client.search.return_value = ("OK", [b"1 2 3 4 5"])
        client.fetch.return_value = ("OK", [
            b'5 FETCH (UID 500 INTERNALDATE "16-Apr-2026 14:00:00 -0400")',
            b'4 FETCH (UID 400 INTERNALDATE "15-Apr-2026 10:00:00 -0400")',
            b'3 FETCH (UID 300 INTERNALDATE "14-Apr-2026 08:00:00 -0400")',
        ])

        pairs = await provider.peek_recent_uids("ALL", max_per_folder=3)
        assert len(pairs) == 3
        assert pairs[0] == ("500", "16-Apr-2026 14:00:00 -0400")
        assert pairs[1] == ("400", "15-Apr-2026 10:00:00 -0400")
        assert pairs[2] == ("300", "14-Apr-2026 08:00:00 -0400")

    @pytest.mark.asyncio
    async def test_peek_recent_uids_empty(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        client.search.return_value = ("OK", [b""])
        pairs = await provider.peek_recent_uids("ALL")
        assert pairs == []

    @pytest.mark.asyncio
    async def test_peek_recent_uids_search_failure(self):
        provider = _make_provider()
        client = _mock_client()
        provider._client = client

        client.search.return_value = ("NO", [b"Search failed"])
        pairs = await provider.peek_recent_uids("ALL")
        assert pairs == []


class TestQueryTranslation:
    def test_is_unread(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._translate_query("is:unread") == "UNSEEN"

    def test_is_unread_with_more(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._translate_query("is:unread SINCE 14-Apr-2026") == "UNSEEN SINCE 14-Apr-2026"

    def test_passthrough(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._translate_query("FROM boss@co.com") == "FROM boss@co.com"


class TestHelpers:
    def test_extract_body_plain(self):
        from email_triage.providers.imap import ImapProvider
        import email as email_mod
        raw = _make_raw_email(body="Simple body")
        msg = email_mod.message_from_bytes(raw, policy=email.policy.default)
        assert "Simple body" in ImapProvider._extract_body(msg)

    def test_parse_date(self):
        from email_triage.providers.imap import ImapProvider
        dt = ImapProvider._parse_date("Mon, 14 Apr 2026 10:30:00 +0000")
        assert dt.year == 2026
        assert dt.month == 4
        assert dt.tzinfo is not None

    def test_parse_date_empty(self):
        from email_triage.providers.imap import ImapProvider
        dt = ImapProvider._parse_date("")
        assert dt.year >= 2026  # Falls back to now()

    def test_extract_flags(self):
        from email_triage.providers.imap import ImapProvider
        data = [b"1 (FLAGS (\\Seen \\Flagged) RFC822 {123})"]
        flags = ImapProvider._extract_flags(data)
        assert "\\Seen" in flags
        assert "\\Flagged" in flags

    def test_quote_mailbox_simple(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._quote_mailbox("INBOX") == "INBOX"
        assert ImapProvider._quote_mailbox("Archives.2025") == "Archives.2025"

    def test_quote_mailbox_with_space(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._quote_mailbox("Express Scripts") == '"Express Scripts"'
        assert ImapProvider._quote_mailbox("UofM Health") == '"UofM Health"'

    def test_quote_mailbox_already_quoted(self):
        from email_triage.providers.imap import ImapProvider
        assert ImapProvider._quote_mailbox('"Already Quoted"') == '"Already Quoted"'

    def test_quote_mailbox_with_quote_char(self):
        from email_triage.providers.imap import ImapProvider
        # Embedded quote must be escaped.
        assert ImapProvider._quote_mailbox('Folder "X"') == '"Folder \\"X\\""'


# ---------------------------------------------------------------------------
# Draft folder discovery (RFC 6154 SPECIAL-USE first, name fallback second)
# ---------------------------------------------------------------------------

class TestCreateDraftFolderDiscovery:
    """Verify create_draft picks the right Drafts folder.

    Earlier discovery loop matched name "drafts" AND the SPECIAL-USE
    flag NOT in the line -- which SKIPPED the canonical RFC-6154
    folder and fell through to the hardcoded `INBOX.Drafts` default.
    On servers where the actual folder is just "Drafts" (no INBOX
    namespace prefix), the APPEND failed with NO. Discovery now
    prefers the SPECIAL-USE flag, falls back to name match.
    """

    @pytest.mark.asyncio
    async def test_picks_special_use_flagged_folder(self):
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\HasNoChildren) "." "INBOX"',
            b'(\Drafts \HasNoChildren) "." "Drafts"',
            b'(\Sent \HasNoChildren) "." "Sent"',
        ]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["recipient@example.com"], subject="Re: hi", body="hi back",
        )
        # Verify APPEND target was the SPECIAL-USE-flagged folder, not
        # the INBOX.Drafts default.
        assert client.append.call_count == 1
        kwargs = client.append.call_args.kwargs
        assert kwargs["mailbox"] == "Drafts"

    @pytest.mark.asyncio
    async def test_special_use_flag_on_namespaced_folder(self):
        """Dovecot-style: SPECIAL-USE flag on `INBOX.Drafts` (with
        namespace prefix). Discovery should still pick that name."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\HasNoChildren) "." "INBOX"',
            b'(\Drafts \HasNoChildren) "." "INBOX.Drafts"',
        ]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        kwargs = client.append.call_args.kwargs
        assert kwargs["mailbox"] == "INBOX.Drafts"

    @pytest.mark.asyncio
    async def test_falls_back_to_name_when_no_special_use(self):
        """Legacy server with no SPECIAL-USE flag emission. Name match
        finds the Drafts folder."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\HasNoChildren) "." "INBOX"',
            b'(\HasNoChildren) "." "Drafts"',
            b'(\HasNoChildren) "." "Sent"',
        ]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        kwargs = client.append.call_args.kwargs
        assert kwargs["mailbox"] == "Drafts"

    @pytest.mark.asyncio
    async def test_falls_back_to_inbox_drafts_when_no_match(self):
        """Empty LIST or no Drafts folder -> hardcoded default."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\HasNoChildren) "." "INBOX"',
        ]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        kwargs = client.append.call_args.kwargs
        assert kwargs["mailbox"] == "INBOX.Drafts"

    @pytest.mark.asyncio
    async def test_special_use_takes_precedence_over_namesake(self):
        """Both `Drafts` (no flag) and `Drafts (Old)` (no flag) and a
        SPECIAL-USE-flagged folder coexist. The flagged one wins."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\HasNoChildren) "." "Drafts (Old)"',
            b'(\Drafts \HasNoChildren) "." "Drafts"',
        ]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        kwargs = client.append.call_args.kwargs
        assert kwargs["mailbox"] == "Drafts"

    @pytest.mark.asyncio
    async def test_create_called_before_append(self):
        """Discovered folder gets an idempotent CREATE before APPEND.
        Some IMAP servers reject APPEND when the target doesn't
        exist (rather than auto-creating); the CREATE closes that
        gap. CREATE returning NO (folder already exists) is fine —
        we only fail the operation on APPEND failure."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\Drafts \HasNoChildren) "." "Drafts"',
        ]))
        client.create = AsyncMock(return_value=("NO", [b"Mailbox already exists"]))
        client.append = AsyncMock(return_value=("OK", [b"APPEND completed"]))
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        # CREATE was called once, with the discovered folder.
        client.create.assert_awaited_once()
        create_kwargs = client.create.call_args
        # Quoted mailbox name passed to CREATE.
        assert create_kwargs.args[0].strip('"') == "Drafts"
        # APPEND fired after CREATE and succeeded.
        client.append.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_falls_back_to_alternate_folder_on_append_no(self):
        """First APPEND to discovered folder returns NO; provider
        retries against the alternate name (INBOX-prefix flip) and
        succeeds. Covers Dovecot installs whose namespace prefix
        doesn't match what SPECIAL-USE returned."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\Drafts \HasNoChildren) "." "INBOX.Drafts"',
        ]))
        client.create = AsyncMock(return_value=("OK", []))
        # First APPEND to INBOX.Drafts returns NO; second to Drafts
        # returns OK.
        client.append = AsyncMock(side_effect=[
            ("NO", [b"Mailbox does not exist"]),
            ("OK", [b"APPEND completed"]),
        ])
        provider._client = client

        await provider.create_draft(
            to=["x@y.com"], subject="s", body="b",
        )
        assert client.append.await_count == 2
        first_call = client.append.await_args_list[0]
        second_call = client.append.await_args_list[1]
        assert first_call.kwargs["mailbox"] == "INBOX.Drafts"
        assert second_call.kwargs["mailbox"] == "Drafts"

    @pytest.mark.asyncio
    async def test_both_folder_attempts_failing_raises(self):
        """If both the discovered name AND the alternate-prefix
        attempt return NO, we surface a RuntimeError (no silent
        success). Provider doesn't pretend it created a draft when
        nothing landed in any folder."""
        provider = _make_provider()
        client = _mock_client()
        client.list = AsyncMock(return_value=("OK", [
            b'(\Drafts \HasNoChildren) "." "INBOX.Drafts"',
        ]))
        client.create = AsyncMock(return_value=("OK", []))
        client.append = AsyncMock(side_effect=[
            ("NO", [b"Mailbox does not exist"]),
            ("NO", [b"Permission denied"]),
        ])
        provider._client = client

        import pytest as _pytest
        with _pytest.raises(RuntimeError) as exc_info:
            await provider.create_draft(
                to=["x@y.com"], subject="s", body="b",
            )
        assert "APPEND" in str(exc_info.value)
