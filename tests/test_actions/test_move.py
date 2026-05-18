"""Tests for the MoveAction."""

import pytest

from email_triage.actions.move import MoveAction
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)


class _MockProvider:
    """Minimal mock email provider for testing move operations."""

    def __init__(self):
        self.moved: list[tuple[str, str]] = []
        self.created_folders: list[str] = []
        self._name = "mock"
        self.raise_on_move: Exception | None = None
        self.raise_on_create: Exception | None = None
        self.support_move = True
        self.support_create = True

    @property
    def name(self) -> str:
        return self._name

    async def create_folder(self, folder: str) -> None:
        if not self.support_create:
            raise NotImplementedError("No folder creation")
        if self.raise_on_create:
            raise self.raise_on_create
        self.created_folders.append(folder)

    async def move_message(self, message_id: str, folder: str) -> None:
        if not self.support_move:
            raise NotImplementedError("No move support")
        if self.raise_on_move:
            raise self.raise_on_move
        self.moved.append((message_id, folder))


def _make_flow() -> FlowState:
    return FlowState(
        flow_id="test-flow-1",
        message_id="uid-123",
        provider="mock",
        status=FlowStatus.ACTING,
    )


def _make_message() -> EmailMessage:
    from datetime import datetime, timezone
    return EmailMessage(
        message_id="uid-123",
        provider="mock",
        sender="sender@test.com",
        recipients=["me@test.com"],
        subject="Test",
        body_text="Hello",
        date=datetime.now(timezone.utc),
    )


def _make_classification(category: str = "invoices") -> Classification:
    return Classification(
        category=category,
        confidence=0.9,
        reason="test",
    )


@pytest.fixture
def action():
    return MoveAction()


class TestMoveAction:
    """Test MoveAction execution."""

    @pytest.mark.asyncio
    async def test_name(self, action):
        assert action.name == "move"

    @pytest.mark.asyncio
    async def test_move_with_folder_map(self, action):
        provider = _MockProvider()
        config = {
            "folder_map": {
                "invoices": "INBOX.Triage.Invoices",
                "newsletters": "INBOX.Triage.Newsletters",
            },
        }
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.COMPLETED
        assert provider.moved == [("uid-123", "INBOX.Triage.Invoices")]
        assert output.data["folder"] == "INBOX.Triage.Invoices"

    @pytest.mark.asyncio
    async def test_auto_create_folder(self, action):
        provider = _MockProvider()
        config = {
            "folder_map": {"invoices": "INBOX.New.Folder"},
            "auto_create": True,
        }
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.COMPLETED
        assert "INBOX.New.Folder" in provider.created_folders
        assert provider.moved == [("uid-123", "INBOX.New.Folder")]

    @pytest.mark.asyncio
    async def test_auto_create_disabled(self, action):
        provider = _MockProvider()
        config = {
            "folder_map": {"invoices": "INBOX.Folder"},
            "auto_create": False,
        }
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.COMPLETED
        assert provider.created_folders == []  # No folder creation.
        assert provider.moved == [("uid-123", "INBOX.Folder")]

    @pytest.mark.asyncio
    async def test_no_mapping_skips(self, action):
        provider = _MockProvider()
        config = {
            "folder_map": {"other": "INBOX.Other"},
        }
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.SKIPPED
        assert provider.moved == []

    @pytest.mark.asyncio
    async def test_empty_config_skips(self, action):
        provider = _MockProvider()
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, None,
        )
        assert output.result == ActionResult.SKIPPED

    @pytest.mark.asyncio
    async def test_provider_no_move_support(self, action):
        provider = _MockProvider()
        provider.support_move = False
        config = {"folder_map": {"invoices": "INBOX.Inv"}}
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.SKIPPED
        assert "does not support" in output.data.get("reason", "")

    @pytest.mark.asyncio
    async def test_move_error(self, action):
        provider = _MockProvider()
        provider.raise_on_move = RuntimeError("Connection lost")
        config = {"folder_map": {"invoices": "INBOX.Inv"}}
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.FAILED
        assert "Connection lost" in (output.error or "")

    @pytest.mark.asyncio
    async def test_create_folder_error_ignored(self, action):
        """If folder creation fails (e.g. already exists), move continues."""
        provider = _MockProvider()
        provider.raise_on_create = RuntimeError("Already exists")
        config = {
            "folder_map": {"invoices": "INBOX.Inv"},
            "auto_create": True,
        }
        output = await action.execute(
            _make_flow(), _make_message(), _make_classification("invoices"),
            provider, config,
        )
        assert output.result == ActionResult.COMPLETED
        assert provider.moved == [("uid-123", "INBOX.Inv")]
