"""Shared test fixtures."""

from datetime import datetime, timezone

import pytest

from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.engine.store import FlowStore


@pytest.fixture
def memory_store() -> FlowStore:
    """FlowStore backed by in-memory SQLite."""
    return FlowStore(":memory:")


@pytest.fixture
def sample_email() -> EmailMessage:
    return EmailMessage(
        message_id="msg-001",
        provider="gmail_api",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Q3 budget review",
        body_text="Please review the attached budget spreadsheet.",
        date=datetime(2026, 4, 14, 10, 30, tzinfo=timezone.utc),
        labels=["INBOX"],
    )


@pytest.fixture
def sample_classification() -> Classification:
    return Classification(
        category="action-required",
        confidence=0.92,
        reason="Email requests a review action with deadline context.",
    )
