"""Tests for core data models."""

from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
    VALID_TRANSITIONS,
)


class TestFlowTransitions:
    def test_created_can_go_to_fetched(self):
        flow = FlowState(
            flow_id="f1", message_id="m1", provider="test",
            status=FlowStatus.CREATED,
        )
        assert flow.can_transition_to(FlowStatus.FETCHED) is True

    def test_created_cannot_go_to_finished(self):
        flow = FlowState(
            flow_id="f1", message_id="m1", provider="test",
            status=FlowStatus.CREATED,
        )
        assert flow.can_transition_to(FlowStatus.FINISHED) is False

    def test_any_state_can_fail(self):
        for status in FlowStatus:
            if status in (FlowStatus.FINISHED, FlowStatus.FAILED):
                continue
            assert FlowStatus.FAILED in VALID_TRANSITIONS[status]

    def test_terminal_states_have_no_transitions(self):
        assert VALID_TRANSITIONS[FlowStatus.FINISHED] == set()
        assert VALID_TRANSITIONS[FlowStatus.FAILED] == set()

    def test_waiting_resumes_to_acting(self):
        flow = FlowState(
            flow_id="f1", message_id="m1", provider="test",
            status=FlowStatus.WAITING,
        )
        assert flow.can_transition_to(FlowStatus.ACTING) is True


class TestEmailMessageLogRepr:
    def test_standard_mode_includes_phi(self, sample_email: EmailMessage):
        rep = sample_email.log_repr(hipaa=False)
        assert "sender" in rep
        assert "subject" in rep
        assert rep["sender"] == "alice@example.com"

    def test_hipaa_mode_strips_phi(self, sample_email: EmailMessage):
        rep = sample_email.log_repr(hipaa=True)
        assert "sender" not in rep
        assert "subject" not in rep
        assert "recipients" not in rep
        assert "message_id" in rep
        assert "provider" in rep


class TestClassificationLogRepr:
    def test_standard_includes_reason(self, sample_classification: Classification):
        rep = sample_classification.log_repr(hipaa=False)
        assert "reason" in rep
        assert rep["category"] == "action-required"

    def test_hipaa_strips_reason(self, sample_classification: Classification):
        rep = sample_classification.log_repr(hipaa=True)
        assert "reason" not in rep
        assert rep["category"] == "action-required"
        assert rep["confidence"] == 0.92


class TestEmailMessageHipaaField:
    """EmailMessage carries the resolved HIPAA state from fetch time."""

    def _make(self, **overrides):
        from datetime import datetime, timezone
        defaults = dict(
            message_id="m1",
            provider="test",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="Hello",
            body_text="Body",
            date=datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc),
        )
        defaults.update(overrides)
        return EmailMessage(**defaults)

    def test_default_is_false(self):
        msg = self._make()
        assert msg.hipaa is False

    def test_can_be_set_explicitly(self):
        msg = self._make(hipaa=True)
        assert msg.hipaa is True

    def test_can_be_mutated(self):
        msg = self._make()
        msg.hipaa = True
        assert msg.hipaa is True
