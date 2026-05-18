"""Tests for individual action implementations."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.draft_reply import DraftReplyAction
from email_triage.actions.escalate import (
    EscalateAction,
    _extract_display_name,
    _extract_first_name,
)
from email_triage.actions.label import LabelAction
from email_triage.actions.notify import NotifyAction
from email_triage.config import LoggingConfig
from email_triage.engine.models import (
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.triage_logging import setup_logging


def _make_flow(**overrides) -> FlowState:
    defaults = dict(
        flow_id="f-1",
        message_id="m-1",
        provider="test",
        status=FlowStatus.ACTING,
    )
    defaults.update(overrides)
    return FlowState(**defaults)


def _make_message(**overrides) -> EmailMessage:
    defaults = dict(
        message_id="m-1",
        provider="test",
        sender="Dr. Jane Smith <jane@hospital.org>",
        recipients=["user@example.com"],
        subject="Lab results for review",
        body_text="Patient labs attached.",
        date=datetime(2026, 4, 14, 14, 30, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


def _make_classification(**overrides) -> Classification:
    defaults = dict(
        category="to-respond",
        confidence=0.92,
        reason="Email requests a review.",
    )
    defaults.update(overrides)
    return Classification(**defaults)


def _make_provider(**overrides):
    provider = AsyncMock()
    provider.name = "test_provider"
    return provider


class TestNotifyAction:
    def setup_method(self):
        setup_logging(LoggingConfig(hipaa=False))

    async def test_standard_mode(self):
        action = NotifyAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), _make_provider(),
        )
        assert result.result == ActionResult.COMPLETED
        notif = result.data["notification"]
        assert "sender" in notif
        assert "subject" in notif
        assert notif["category"] == "to-respond"

    async def test_hipaa_mode(self):
        setup_logging(LoggingConfig(hipaa=True))
        action = NotifyAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), _make_provider(),
        )
        notif = result.data["notification"]
        assert "sender" not in notif
        assert "subject" not in notif
        assert notif["category"] == "to-respond"
        assert "timestamp" in notif
        # Reset.
        setup_logging(LoggingConfig(hipaa=False))


class TestLabelAction:
    async def test_applies_label(self):
        provider = _make_provider()
        action = LabelAction()
        result = await action.execute(
            _make_flow(), _make_message(),
            _make_classification(category="invoices"),
            provider,
        )
        assert result.result == ActionResult.COMPLETED
        assert result.data["label"] == "invoices"
        provider.apply_label.assert_called_once()

    async def test_label_prefix(self):
        provider = _make_provider()
        action = LabelAction()
        result = await action.execute(
            _make_flow(), _make_message(),
            _make_classification(category="invoices"),
            provider,
            config={"label_prefix": "triage"},
        )
        assert result.data["label"] == "triage/invoices"

    async def test_skips_if_unsupported(self):
        provider = _make_provider()
        provider.apply_label.side_effect = NotImplementedError("no labels")
        action = LabelAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), provider,
        )
        assert result.result == ActionResult.SKIPPED

    async def test_failure_log_includes_diagnostic_extras(self, caplog):
        """Regression: a label failure must log flow_id + message_id +
        provider + category + label + sender + subject (non-HIPAA)
        so an operator can correlate the error to an account, message,
        and route without cross-referencing extra log lines."""
        import logging as _log
        provider = _make_provider()
        provider.name = "gmail_api"
        provider.apply_label.side_effect = RuntimeError(
            "Gmail API 404: Label not found: notifications ()"
        )
        action = LabelAction()
        msg = _make_message(
            message_id="uid-82543",
            sender="shipment-tracking@amazon.com",
            subject="Shipped: Breville BSV600PSS Joule",
        )
        with caplog.at_level(_log.ERROR, logger="email_triage.actions.label"):
            result = await action.execute(
                _make_flow(flow_id="flow-abc"),
                msg,
                _make_classification(category="notifications"),
                provider,
            )
        assert result.result == ActionResult.FAILED
        err_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(err_records) == 1
        r = err_records[0]
        assert r.flow_id == "flow-abc"
        assert r.message_id == "uid-82543"
        assert r.provider == "gmail_api"
        assert r.category == "notifications"
        assert r.label == "notifications"
        # Non-HIPAA message → sender + subject included.
        assert r.sender == "shipment-tracking@amazon.com"
        assert "Shipped" in r.subject

    async def test_failure_log_redacts_sender_subject_on_hipaa(self, caplog):
        import logging as _log
        provider = _make_provider()
        provider.apply_label.side_effect = RuntimeError("nope")
        action = LabelAction()
        msg = _make_message(
            sender="patient@example.com", subject="lab results",
        )
        msg.hipaa = True
        with caplog.at_level(_log.ERROR, logger="email_triage.actions.label"):
            await action.execute(
                _make_flow(), msg, _make_classification(), provider,
            )
        r = [r for r in caplog.records if r.levelname == "ERROR"][0]
        assert not hasattr(r, "sender") or r.sender is None
        assert not hasattr(r, "subject") or r.subject is None
        # message_id still present — not PHI.
        assert r.message_id is not None


class TestDraftReplyAction:
    async def test_creates_draft(self):
        provider = _make_provider()
        provider.create_draft.return_value = "draft-123"
        action = DraftReplyAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), provider,
        )
        assert result.result == ActionResult.COMPLETED
        assert result.data["draft_id"] == "draft-123"
        provider.create_draft.assert_called_once()

    async def test_skips_if_unsupported(self):
        provider = _make_provider()
        provider.create_draft.side_effect = NotImplementedError("no drafts")
        action = DraftReplyAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), provider,
        )
        assert result.result == ActionResult.SKIPPED

    async def test_fails_on_error(self):
        provider = _make_provider()
        provider.create_draft.side_effect = RuntimeError("API error")
        action = DraftReplyAction()
        result = await action.execute(
            _make_flow(), _make_message(), _make_classification(), provider,
        )
        assert result.result == ActionResult.FAILED
        assert "API error" in result.error


class TestExtractNames:
    def test_display_name_with_angle_brackets(self):
        assert _extract_display_name("Dr. Jane Smith <jane@hospital.org>") == "Dr. Jane Smith"

    def test_display_name_plain_email(self):
        assert _extract_display_name("jane@hospital.org") == "jane"

    def test_first_name_with_title(self):
        assert _extract_first_name("Dr. Jane Smith <jane@hospital.org>") == "Jane"

    def test_first_name_plain_email(self):
        assert _extract_first_name("jane@hospital.org") == "jane"

    def test_first_name_no_title(self):
        assert _extract_first_name("Alice Bob <alice@example.com>") == "Alice"


class _FakeSmtpConfig:
    """Test stub mirroring the SmtpConfig dataclass surface the
    escalate action actually reads."""
    host = "smtp.test.example"
    port = 587
    username = "user"
    from_addr = "noreply@test.example"
    from_name = "Email Triage"
    use_tls = True


class _FakeSecrets:
    def __init__(self, password: str = "fake-pw"):
        self._password = password

    def get(self, key):
        if key == "SMTP_PASSWORD":
            return self._password
        return None


def _state_bag_with_smtp(notify_email: str | None = None) -> dict:
    """Build a state_bag that has the SMTP context the escalate
    action expects after the #73 wiring. Mirrors what app.py /
    triage_runner.py stash."""
    bag = {
        "smtp_config": _FakeSmtpConfig(),
        "secrets": _FakeSecrets(),
    }
    if notify_email:
        bag["notify_email"] = notify_email
    return bag


class TestEscalateAction:
    def setup_method(self):
        setup_logging(LoggingConfig(hipaa=False))

    async def test_standard_mode_sends_via_smtp(self, monkeypatch):
        """Standard mode + SMTP configured: the action calls
        send_simple_smtp_email with the standard-mode notification
        text as the subject."""
        sent: list[dict] = []

        def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            fake_send,
        )
        action = EscalateAction()
        flow = _make_flow(state_bag=_state_bag_with_smtp("5551234@vtext.com"))
        result = await action.execute(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        assert result.result == ActionResult.COMPLETED
        notif = result.data["notification"]
        assert notif["mode"] == "standard"
        # Category prefix in the URGENT marker so the recipient can
        # prioritise on lock-screen preview.
        assert notif["text"].startswith("URGENT [to-respond]:")
        assert "Dr. Jane Smith" in notif["text"]
        assert "Lab results for review" in notif["text"]
        # SMTP send was invoked with the right shape.
        assert len(sent) == 1
        assert sent[0]["to_addr"] == "5551234@vtext.com"
        assert sent[0]["subject"] == notif["text"]
        assert sent[0]["triage_source"] == "escalation"

    async def test_hipaa_mode_strips_subject_and_sender_via_system_flag(
        self, monkeypatch,
    ):
        """System HIPAA flag (is_hipaa_mode) → metadata-only
        notification text reaches the SMTP body."""
        setup_logging(LoggingConfig(hipaa=True))
        sent: list[dict] = []
        monkeypatch.setattr(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            lambda **kw: sent.append(kw),
        )
        action = EscalateAction()
        flow = _make_flow(state_bag=_state_bag_with_smtp("5551234@vtext.com"))
        result = await action.execute(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        notif = result.data["notification"]
        assert notif["mode"] == "hipaa"
        # HIPAA payload: category + first name + timestamp. Subject
        # / display name / domain still suppressed.
        assert notif["text"].startswith("URGENT [to-respond]:")
        assert "Jane" in notif["text"]
        assert "Lab results" not in notif["text"]
        assert "hospital.org" not in notif["text"]
        # The SMTP subject is exactly the scrubbed notification text.
        assert len(sent) == 1
        assert sent[0]["subject"] == notif["text"]
        assert "Lab results" not in sent[0]["subject"]
        assert "Lab results" not in sent[0]["body"]
        # Reset global state.
        setup_logging(LoggingConfig(hipaa=False))

    async def test_hipaa_mode_strips_subject_via_per_account_flag(
        self, monkeypatch,
    ):
        """Per-account HIPAA flag (message.hipaa=True) with system
        flag OFF still triggers the metadata-only branch — proves
        the OR in escalate.py:122 fires from the message side too."""
        # Confirm system-level HIPAA is OFF for this test.
        setup_logging(LoggingConfig(hipaa=False))
        sent: list[dict] = []
        monkeypatch.setattr(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            lambda **kw: sent.append(kw),
        )
        action = EscalateAction()
        flow = _make_flow(state_bag=_state_bag_with_smtp("5551234@vtext.com"))
        msg = _make_message()
        msg.hipaa = True  # per-account flag propagated onto the message
        result = await action.execute(
            flow, msg, _make_classification(), _make_provider(),
        )
        notif = result.data["notification"]
        assert notif["mode"] == "hipaa"
        assert "Lab results" not in notif["text"]
        # Defense-in-depth: SMTP body never carries the subject.
        assert len(sent) == 1
        assert "Lab results" not in sent[0]["subject"]
        assert "Lab results" not in sent[0]["body"]

    async def test_skips_without_notify_email(self):
        action = EscalateAction()
        result = await action.execute(
            _make_flow(state_bag=_state_bag_with_smtp()),
            _make_message(), _make_classification(), _make_provider(),
        )
        assert result.result == ActionResult.SKIPPED

    async def test_notify_email_from_config(self, monkeypatch):
        sent: list[dict] = []
        monkeypatch.setattr(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            lambda **kw: sent.append(kw),
        )
        action = EscalateAction()
        result = await action.execute(
            _make_flow(state_bag=_state_bag_with_smtp()),
            _make_message(), _make_classification(), _make_provider(),
            config={"notify_email": "sms@gateway.com"},
        )
        assert result.result == ActionResult.COMPLETED
        assert result.data["notify_email"] == "sms@gateway.com"
        assert len(sent) == 1
        assert sent[0]["to_addr"] == "sms@gateway.com"

    async def test_skip_when_smtp_not_configured(self, monkeypatch):
        """smtp_config missing or empty host → SKIPPED. Notification
        text still computed for audit; nothing sent."""
        action = EscalateAction()
        flow = _make_flow(state_bag={"notify_email": "x@y.com"})  # no smtp_config
        result = await action.execute(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        assert result.result == ActionResult.SKIPPED
        assert "smtp not configured" in result.data["reason"]

    async def test_send_error_returns_failed(self, monkeypatch):
        """SMTP raise → FAILED outcome with error string in result."""
        def boom(**kw):
            raise ConnectionRefusedError("smtp.test.example: connection refused")

        monkeypatch.setattr(
            "email_triage.web.smtp_send.send_simple_smtp_email", boom,
        )
        action = EscalateAction()
        flow = _make_flow(state_bag=_state_bag_with_smtp("x@y.com"))
        result = await action.execute(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        assert result.result == ActionResult.FAILED
        assert "ConnectionRefusedError" in result.error
        assert "connection refused" in result.error
