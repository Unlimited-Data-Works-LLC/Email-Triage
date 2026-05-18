"""Tests for PR 6 / C2 — action idempotency keys.

Covers the helpers in actions/base.py + per-action behaviour for
draft_reply (most painful — duplicates drafts on retry), move,
escalate, notify, and label (audit-only).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.actions.base import (
    _compute_idempotency_key,
    check_idempotent_already_done,
    record_idempotent_done,
)
from email_triage.actions.draft_reply import DraftReplyAction
from email_triage.actions.escalate import EscalateAction
from email_triage.actions.label import LabelAction
from email_triage.actions.move import MoveAction
from email_triage.actions.notify import NotifyAction
from email_triage.engine.models import (
    ActionResult, Classification, EmailMessage, FlowState, FlowStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(flow_id: str = "f1") -> FlowState:
    return FlowState(
        flow_id=flow_id,
        provider="imap",
        message_id="m1",
        status=FlowStatus.ACTING,
        state_bag={},
    )


def _make_message(message_id: str = "m1") -> EmailMessage:
    return EmailMessage(
        message_id=message_id,
        provider="imap",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="hello",
        body_text="body",
        date=datetime.now(timezone.utc),
        thread_id=None,
        headers={},
    )


def _make_classification() -> Classification:
    return Classification(
        category="invoices", confidence=0.9, reason="test rule",
    )


# ---------------------------------------------------------------------------
# Helper-level
# ---------------------------------------------------------------------------

def test_compute_idempotency_key_is_stable():
    a = _compute_idempotency_key("f1", "draft_reply", "m1")
    b = _compute_idempotency_key("f1", "draft_reply", "m1")
    assert a == b
    # Different inputs → different keys.
    assert a != _compute_idempotency_key("f2", "draft_reply", "m1")
    assert a != _compute_idempotency_key("f1", "move", "m1")
    assert a != _compute_idempotency_key("f1", "draft_reply", "m2")


def test_check_returns_none_on_first_run():
    flow = _make_flow()
    msg = _make_message()
    assert check_idempotent_already_done(flow, msg, "draft_reply") is None


def test_record_then_check_returns_skipped():
    flow = _make_flow()
    msg = _make_message()
    record_idempotent_done(
        flow, msg, "draft_reply", external_id="draft-123",
    )
    out = check_idempotent_already_done(flow, msg, "draft_reply")
    assert out is not None
    assert out.result == ActionResult.SKIPPED
    assert out.data["skipped_idempotent"] is True
    assert out.data["previous_external_id"] == "draft-123"


def test_record_action_results_structure():
    flow = _make_flow()
    msg = _make_message()
    record_idempotent_done(
        flow, msg, "move", external_id="Archive",
    )
    bag = flow.state_bag
    assert "action_results" in bag
    assert "move" in bag["action_results"]
    entry = bag["action_results"]["move"]
    assert entry["idempotency_key"] == _compute_idempotency_key(
        "f1", "move", "m1",
    )
    assert entry["external_id"] == "Archive"
    assert entry["completed_at"]


def test_check_with_stale_key_returns_none():
    """If the recorded key was for a DIFFERENT flow/action/message,
    the check returns None so the action runs fresh."""
    flow = _make_flow("f1")
    msg = _make_message("m1")
    flow.state_bag = {
        "action_results": {
            "draft_reply": {
                "idempotency_key": "deadbeef" * 8,  # bogus key
                "external_id": None,
                "completed_at": "old",
            }
        }
    }
    assert check_idempotent_already_done(flow, msg, "draft_reply") is None


# ---------------------------------------------------------------------------
# DraftReplyAction (the painful case)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_draft_reply_records_on_first_run():
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()

    provider = MagicMock()
    provider.create_draft = AsyncMock(return_value="draft-abc")
    provider.name = "imap"

    action = DraftReplyAction()
    out = await action.execute(flow, msg, cls, provider)
    assert out.result == ActionResult.COMPLETED
    assert provider.create_draft.call_count == 1
    # Recorded with external_id matching the draft id returned.
    entry = flow.state_bag["action_results"]["draft_reply"]
    assert entry["external_id"] == "draft-abc"


@pytest.mark.asyncio
async def test_draft_reply_skips_on_retry():
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()

    provider = MagicMock()
    provider.create_draft = AsyncMock(return_value="draft-abc")
    provider.name = "imap"

    action = DraftReplyAction()
    # First run: creates draft.
    await action.execute(flow, msg, cls, provider)
    # Second run: skips. CRITICAL — provider must not be called twice.
    out2 = await action.execute(flow, msg, cls, provider)
    assert out2.result == ActionResult.SKIPPED
    assert out2.data["skipped_idempotent"] is True
    assert out2.data["previous_external_id"] == "draft-abc"
    assert provider.create_draft.call_count == 1  # NOT 2


# ---------------------------------------------------------------------------
# MoveAction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_move_skips_on_retry():
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()

    provider = MagicMock()
    provider.move_message = AsyncMock(return_value=None)
    provider.list_folders = AsyncMock(return_value=["Archive"])
    provider.create_folder = AsyncMock(return_value=None)
    provider.name = "imap"

    action = MoveAction()
    cfg = {"folder_map": {"invoices": "Archive"}, "auto_create": True}

    out1 = await action.execute(flow, msg, cls, provider, config=cfg)
    assert out1.result == ActionResult.COMPLETED
    out2 = await action.execute(flow, msg, cls, provider, config=cfg)
    assert out2.result == ActionResult.SKIPPED
    assert provider.move_message.call_count == 1


# ---------------------------------------------------------------------------
# EscalateAction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_escalate_skips_on_retry(monkeypatch):
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()

    smtp_cfg = MagicMock()
    smtp_cfg.host = "smtp.example.com"
    smtp_cfg.port = 587
    smtp_cfg.username = "u"
    smtp_cfg.from_addr = "from@example.com"
    smtp_cfg.from_name = "Triage"
    smtp_cfg.use_tls = True

    secrets = MagicMock()
    secrets.get.return_value = "pwd"

    flow.state_bag = {
        "smtp_config": smtp_cfg,
        "secrets": secrets,
        "notify_email": "5551234567@vtext.com",
    }

    provider = MagicMock()
    provider.name = "imap"

    sent_calls = {"n": 0}

    def fake_send(**kwargs):
        sent_calls["n"] += 1

    monkeypatch.setattr(
        "email_triage.web.smtp_send.send_simple_smtp_email",
        fake_send,
    )

    action = EscalateAction()
    out1 = await action.execute(flow, msg, cls, provider)
    assert out1.result == ActionResult.COMPLETED
    out2 = await action.execute(flow, msg, cls, provider)
    assert out2.result == ActionResult.SKIPPED
    assert sent_calls["n"] == 1  # SMS NOT sent twice


# ---------------------------------------------------------------------------
# NotifyAction (log-only; records for audit)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_notify_records_and_skips_on_retry():
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()
    provider = MagicMock()
    provider.name = "imap"

    action = NotifyAction()
    out1 = await action.execute(flow, msg, cls, provider)
    assert out1.result == ActionResult.COMPLETED
    out2 = await action.execute(flow, msg, cls, provider)
    assert out2.result == ActionResult.SKIPPED


# ---------------------------------------------------------------------------
# LabelAction (provider-idempotent; records for audit only)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_label_records_audit_entry():
    flow = _make_flow()
    msg = _make_message()
    cls = _make_classification()

    provider = MagicMock()
    provider.apply_label = AsyncMock(return_value=None)
    provider.name = "imap"

    action = LabelAction()
    out = await action.execute(flow, msg, cls, provider)
    assert out.result == ActionResult.COMPLETED
    # Even though label is provider-idempotent, the audit row was
    # written — operators should see the same shape for every action.
    assert "label" in flow.state_bag.get("action_results", {})
    entry = flow.state_bag["action_results"]["label"]
    assert entry["external_id"] == "invoices"
