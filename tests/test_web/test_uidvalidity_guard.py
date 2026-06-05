"""Tests for the IMAP UIDVALIDITY guard on mailbox high-water marks.

A change in a mailbox's UIDVALIDITY resets the server-side UID space —
a stored high-water mark's UID then refers to nothing, and trusting it
would silently drop every new message whose reused UID <= the stale
mark.
"""

from __future__ import annotations

import pytest

from email_triage.providers.imap import ImapProvider
from email_triage.web.app import _resolve_hwm_with_uidvalidity


class TestParseUidvalidity:
    def test_found_in_bytes_lines(self):
        data = [b"* OK [UIDVALIDITY 1234567890] UIDs valid", b"* 5 EXISTS"]
        assert ImapProvider._parse_uidvalidity(data) == 1234567890

    def test_found_in_str_lines(self):
        assert ImapProvider._parse_uidvalidity(
            ["* OK [UIDVALIDITY 42] ready"]
        ) == 42

    def test_absent(self):
        assert ImapProvider._parse_uidvalidity([b"* 5 EXISTS"]) is None

    def test_empty_or_none(self):
        assert ImapProvider._parse_uidvalidity(None) is None
        assert ImapProvider._parse_uidvalidity([]) is None


class _FakeProvider:
    def __init__(self, uidvalidity):
        self._uv = uidvalidity

    async def get_uidvalidity(self):
        return self._uv


class TestResolveHwmWithUidvalidity:
    @pytest.mark.asyncio
    async def test_mismatch_resets_to_zero(self):
        """A bumped UIDVALIDITY invalidates the stored UID space."""
        uid, live = await _resolve_hwm_with_uidvalidity(
            _FakeProvider(999), 1, "INBOX",
            {"uid": 500, "uidvalidity": 111},
        )
        assert uid == 0
        assert live == 999

    @pytest.mark.asyncio
    async def test_match_keeps_stored_uid(self):
        uid, live = await _resolve_hwm_with_uidvalidity(
            _FakeProvider(999), 1, "INBOX",
            {"uid": 500, "uidvalidity": 999},
        )
        assert uid == 500
        assert live == 999

    @pytest.mark.asyncio
    async def test_legacy_hwm_without_uidvalidity_no_reset(self):
        """An HWM dict written before  has no uidvalidity — it must
        not be mistaken for a mismatch."""
        uid, _ = await _resolve_hwm_with_uidvalidity(
            _FakeProvider(999), 1, "INBOX", {"uid": 500},
        )
        assert uid == 500

    @pytest.mark.asyncio
    async def test_provider_without_get_uidvalidity_no_reset(self):
        """Gmail/O365 providers don't expose UIDVALIDITY."""
        class _NoUv:
            pass

        uid, live = await _resolve_hwm_with_uidvalidity(
            _NoUv(), 1, "INBOX", {"uid": 500, "uidvalidity": 111},
        )
        assert uid == 500
        assert live is None

    @pytest.mark.asyncio
    async def test_get_uidvalidity_failure_skips_guard(self):
        """If the live UIDVALIDITY can't be read, keep the stored UID."""
        class _Boom:
            async def get_uidvalidity(self):
                raise ConnectionError("network down")

        uid, live = await _resolve_hwm_with_uidvalidity(
            _Boom(), 1, "INBOX", {"uid": 500, "uidvalidity": 111},
        )
        assert uid == 500
        assert live is None

    @pytest.mark.asyncio
    async def test_fresh_mailbox_returns_zero(self):
        uid, _ = await _resolve_hwm_with_uidvalidity(
            _FakeProvider(999), 1, "INBOX", None,
        )
        assert uid == 0
