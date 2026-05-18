"""Tests for the abstract provider interface defaults."""

import pytest

from email_triage.providers.base import EmailProvider, PushCapable


class DummyProvider(EmailProvider):
    """Minimal concrete provider for testing defaults."""

    @property
    def name(self) -> str:
        return "dummy"

    async def search(self, query: str, limit: int = 50) -> list[str]:
        return []

    async def fetch_message(self, message_id: str):
        raise NotImplementedError


class TestProviderDefaults:
    async def test_create_draft_raises(self):
        p = DummyProvider()
        with pytest.raises(NotImplementedError, match="dummy"):
            await p.create_draft(["a@b.com"], "subject", "body")

    async def test_apply_label_raises(self):
        p = DummyProvider()
        with pytest.raises(NotImplementedError, match="dummy"):
            await p.apply_label("msg-1", "IMPORTANT")

    async def test_list_labels_raises(self):
        p = DummyProvider()
        with pytest.raises(NotImplementedError, match="dummy"):
            await p.list_labels()

    async def test_archive_raises(self):
        p = DummyProvider()
        with pytest.raises(NotImplementedError, match="dummy"):
            await p.archive("msg-1")

    async def test_close_is_noop(self):
        p = DummyProvider()
        await p.close()  # Should not raise.
