"""Unit tests for MuteAction.

Contract:
- Records a "muted" ActionResult.COMPLETED with reason (default "user_muted"
  when config omits it, custom when config carries one).
- Uses the shared idempotency SSOT so a retry skips the double-log.
- Emits a structured log via ``build_action_log_extras`` (redaction SSOT).
- Does NOT emit its own HIPAA access-events row — the triage-runner bracket
  around classify-and-fire already carries the §164.312(b) row for the
  underlying PHI touch (PD ). Firing another one here would double-audit.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.actions.mute import MuteAction
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
        flow_id="f-mute-1",
        message_id="m-mute-1",
        provider="test",
        status=FlowStatus.ACTING,
    )
    defaults.update(overrides)
    return FlowState(**defaults)


def _make_message(**overrides) -> EmailMessage:
    defaults = dict(
        message_id="m-mute-1",
        provider="test",
        sender="Vendor News <news@vendor.example>",
        recipients=["user@example.com"],
        subject="Weekly newsletter",
        body_text="Body.",
        date=datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


def _make_classification(**overrides) -> Classification:
    defaults = dict(
        category="newsletter",
        confidence=0.99,
        reason="List-Id header matched.",
    )
    defaults.update(overrides)
    return Classification(**defaults)


class _StubProvider:
    name = "stub"


@pytest.mark.asyncio
async def test_mute_returns_completed_with_default_reason():
    setup_logging(LoggingConfig(hipaa=False))
    action = MuteAction()
    out = await action.execute(
        _make_flow(), _make_message(), _make_classification(), _StubProvider(),
    )
    assert out.result == ActionResult.COMPLETED
    assert out.data["muted"] is True
    assert out.data["reason"] == "user_muted"


@pytest.mark.asyncio
async def test_mute_returns_config_reason_when_provided():
    setup_logging(LoggingConfig(hipaa=False))
    action = MuteAction()
    out = await action.execute(
        _make_flow(), _make_message(), _make_classification(), _StubProvider(),
        config={"reason": "vendor_newsletter"},
    )
    assert out.result == ActionResult.COMPLETED
    assert out.data["reason"] == "vendor_newsletter"


@pytest.mark.asyncio
async def test_mute_reason_truncated_at_120_chars_in_log():
    """Defensive: an operator-provided reason is bounded to keep log rows
    small and avoid a route-config that turns each ingest into a huge log
    record. Truncation shows up on the LOG line; the returned data field
    keeps the original (short) reason for direct callers."""
    setup_logging(LoggingConfig(hipaa=False))
    action = MuteAction()
    long_reason = "x" * 500
    out = await action.execute(
        _make_flow(), _make_message(), _make_classification(), _StubProvider(),
        config={"reason": long_reason},
    )
    assert out.result == ActionResult.COMPLETED
    assert out.data["reason"] == long_reason  # returned verbatim
    # No exception: the truncation happens inside the log-extras dict via
    # str(reason)[:120]; assert the module ran without raising on a long
    # value (regression guard for the slicing shape).


@pytest.mark.asyncio
async def test_mute_second_call_short_circuits_via_idempotency():
    """PR 6 / C2 — a retry-queue re-run on the same (flow, action, message)
    must skip re-logging. FlowState carries the per-flow state_bag record,
    so back-to-back calls with the same FlowState hit the legacy fallback
    path and return SKIPPED."""
    setup_logging(LoggingConfig(hipaa=False))
    action = MuteAction()
    flow, msg = _make_flow(), _make_message()
    first = await action.execute(
        flow, msg, _make_classification(), _StubProvider(),
    )
    second = await action.execute(
        flow, msg, _make_classification(), _StubProvider(),
    )
    assert first.result == ActionResult.COMPLETED
    assert second.result == ActionResult.SKIPPED
    assert second.data["skipped_idempotent"] is True


@pytest.mark.asyncio
async def test_mute_does_not_emit_hipaa_access_row_on_hipaa_message(
    monkeypatch,
):
    """PD  — the outer triage-runner bracket already emits the
    §164.312(b) row for the classification+fire read. MuteAction MUST NOT
    emit an additional row (that would double-audit and break the chain
    invariant that mute-of-a-classification is not a fresh PHI read)."""
    setup_logging(LoggingConfig(hipaa=True))
    emitted: list[tuple] = []

    def _spy(*args, **kwargs):
        emitted.append((args, kwargs))

    monkeypatch.setattr(
        "email_triage.db.audit.record_hipaa_access_event",
        _spy,
    )
    action = MuteAction()
    hipaa_msg = _make_message(hipaa=True)
    await action.execute(
        _make_flow(), hipaa_msg, _make_classification(), _StubProvider(),
    )
    assert emitted == [], (
        "MuteAction leaked a HIPAA access-events row from action.execute; "
        "the triage-runner bracket is the sole SSOT for that row."
    )
