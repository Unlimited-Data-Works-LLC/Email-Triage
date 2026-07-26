"""the backlog  (2026-07-12): LIST SPECIAL-USE Sent auto-detect for IMAP.

`sent_mail_capture` + `hipaa_sent_counter` now auto-detect the IMAP Sent
folder via `providers/sent_folder.py::find_sent_folder` (RFC 6154
SPECIAL-USE probe + name fallback against Sent / INBOX.Sent / Sent
Items / Sent Messages) when the operator has not configured explicit
`sent_folders`.  Closes the N-390 caller-side skip class — the loops no
longer no-op on IMAP-no-config; they detect a Sent folder, then sweep
it.

Coverage focus: the auto-detect BRANCH itself.  Full end-to-end coverage
(a fake ImapProvider hitting a fake IMAP server through the aioimaplib
transport) lives in `tests/test_providers/test_imap.py`; here we mock
the SSOT + the provider so the tests exercise the wire without needing
a live IMAP server.

The three shapes covered per sibling loop:
    1. IMAP + no `sent_folders`  → `find_sent_folder` is awaited, the
       detected folder is threaded into a per-folder search with
       `MailFilter(folder=...)`.
    2. IMAP + explicit `sent_folders` → auto-detect is BYPASSED (the
       operator's config wins); the configured folder is searched.
    3. Non-IMAP provider + no `sent_folders` → auto-detect is NOT
       called; the existing bare-string `"in:sent"` fallback fires
       (honored natively by Gmail-API / O365).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
from email_triage.providers.imap import ImapProvider

from tests.test_actions.test_hipaa_sent_counter import (
    _FakeSecrets,
    _make_db as _make_db_hsc,
    _seed_account as _seed_account_hsc,
)
from tests.test_actions.test_sent_mail_capture import (
    _make_db as _make_db_smc,
    _make_index,
    _seed_account as _seed_account_smc,
)


def _fake_imap_provider(search_result=None):
    """AsyncMock that satisfies `isinstance(x, ImapProvider)` via `spec=`
    and returns the given `search_result` from its async `.search`.
    """
    provider = AsyncMock(spec=ImapProvider)
    provider.search.return_value = list(search_result or [])
    return provider


def _fake_non_imap_provider():
    """Bare AsyncMock — `isinstance(x, ImapProvider)` is False so the
    auto-detect branch is skipped and the non-IMAP fallback fires.
    """
    provider = AsyncMock()
    provider.search.return_value = []
    return provider


_FIND_SENT_FOLDER = "email_triage.providers.sent_folder.find_sent_folder"


class TestSentMailCaptureAutoDetect:
    async def test_imap_no_config_calls_find_sent_folder_and_uses_result(self):
        conn = _make_db_smc()
        acct_id = _seed_account_smc(conn)
        idx = _make_index(conn, acct_id)
        provider = _fake_imap_provider()
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=provider, sent_mail_index=idx,
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 1
        assert mocked_find.await_args.args[0] is provider
        provider.search.assert_awaited()
        first_call = provider.search.await_args_list[0]
        assert first_call.args[0] == "in:sent"
        assert first_call.args[1] == 10
        assert "filter" in first_call.kwargs
        assert first_call.kwargs["filter"].folder == "Sent"

    async def test_imap_explicit_sent_folders_bypass_auto_detect(self):
        conn = _make_db_smc()
        acct_id = _seed_account_smc(conn)
        idx = _make_index(conn, acct_id)
        provider = _fake_imap_provider()
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=provider, sent_mail_index=idx,
            sent_folders=["Custom-Sent"],
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="AUTO-Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 0
        first_call = provider.search.await_args_list[0]
        assert first_call.kwargs["filter"].folder == "Custom-Sent"

    async def test_non_imap_no_auto_detect_falls_back_to_bare_search(self):
        conn = _make_db_smc()
        acct_id = _seed_account_smc(conn)
        idx = _make_index(conn, acct_id)
        provider = _fake_non_imap_provider()
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=provider, sent_mail_index=idx,
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="SHOULD-NOT-BE-CALLED"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 0
        provider.search.assert_awaited_once()
        call = provider.search.await_args_list[0]
        assert call.args[0] == "in:sent"
        assert call.args[1] == 10
        assert "filter" not in call.kwargs


class TestSentMailCaptureAutoDetectMemoization:
    """the backlog  — memoize the N-402 auto-detected folder across
    scans within a single loop instance's lifetime."""

    async def test_find_sent_folder_awaited_once_across_scans(self):
        conn = _make_db_smc()
        acct_id = _seed_account_smc(conn)
        idx = _make_index(conn, acct_id)
        provider = _fake_imap_provider()
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=provider, sent_mail_index=idx,
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)
            await loop.scan_recent(limit=10)
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 1, (
            f"find_sent_folder should be awaited exactly ONCE across "
            f"multiple scan_recent() calls on the same loop instance; "
            f"got {mocked_find.await_count} awaits (memoization broken)."
        )
        # All three scans used the same auto-detected folder.
        assert provider.search.await_count >= 3
        for call in provider.search.await_args_list:
            assert call.kwargs["filter"].folder == "Sent"


class TestHipaaSentCounterAutoDetect:
    async def test_imap_no_config_calls_find_sent_folder_and_uses_result(self):
        conn = _make_db_hsc()
        acct_id = _seed_account_hsc(conn)
        provider = _fake_imap_provider()
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 1
        assert mocked_find.await_args.args[0] is provider
        provider.search.assert_awaited()
        first_call = provider.search.await_args_list[0]
        assert first_call.args[0] == "in:sent"
        assert first_call.args[1] == 10
        assert "filter" in first_call.kwargs
        assert first_call.kwargs["filter"].folder == "Sent"

    async def test_imap_explicit_sent_folders_bypass_auto_detect(self):
        conn = _make_db_hsc()
        acct_id = _seed_account_hsc(conn)
        provider = _fake_imap_provider()
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
            sent_folders=["INBOX.Custom"],
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="AUTO-Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 0
        first_call = provider.search.await_args_list[0]
        assert first_call.kwargs["filter"].folder == "INBOX.Custom"

    async def test_non_imap_no_auto_detect_falls_back_to_bare_search(self):
        conn = _make_db_hsc()
        acct_id = _seed_account_hsc(conn)
        provider = _fake_non_imap_provider()
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="SHOULD-NOT-BE-CALLED"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 0
        provider.search.assert_awaited_once()
        call = provider.search.await_args_list[0]
        assert call.args[0] == "in:sent"
        assert call.args[1] == 10
        assert "filter" not in call.kwargs


class TestHipaaSentCounterAutoDetectMemoization:
    async def test_find_sent_folder_awaited_once_across_scans(self):
        conn = _make_db_hsc()
        acct_id = _seed_account_hsc(conn)
        provider = _fake_imap_provider()
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
            sent_folders=None,
        )

        with patch(
            _FIND_SENT_FOLDER, new=AsyncMock(return_value="Sent"),
        ) as mocked_find:
            await loop.scan_recent(limit=10)
            await loop.scan_recent(limit=10)
            await loop.scan_recent(limit=10)

        assert mocked_find.await_count == 1, (
            f"find_sent_folder should be awaited exactly ONCE across "
            f"multiple scan_recent() calls on the same loop instance; "
            f"got {mocked_find.await_count} awaits (memoization broken)."
        )
        assert provider.search.await_count >= 3
        for call in provider.search.await_args_list:
            assert call.kwargs["filter"].folder == "Sent"
