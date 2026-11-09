"""N-74 (L8-4) — REAL FlowEngine DB-write integration test.

This is the test that would have caught the vacuous N-74 fix. The
original behavioural tests set ``flow.state_bag["account_hipaa"]``
MANUALLY (testing the read, not the integration — the mock-the-seam
trap, pattern_parallel_build_mock_the_boundary_not_the_seam). Nothing
on the real FlowEngine DB-write path set that key, so per-account
redaction NEVER fired and a per-account-HIPAA mailbox with the global
``is_hipaa_mode()`` OFF still wrote cleartext PHI ``reason`` to
``flows.classification_json`` at rest.

These tests drive the ACTUAL engine path:
  provider.fetch_message() -> EmailMessage(hipaa=...) -> engine.classify()
  -> store.update_flow() -> _capture_baseline() -> _cls_to_json()
and then read the PERSISTED ``classification_json`` straight from the
SQLite row — never touching ``state_bag`` by hand.

Wiring under test: engine/flow.py ``classify()`` stamps
``flow.state_bag["account_hipaa"] = bool(message.hipaa)`` before the
first ``update_flow``. ``message.hipaa`` is the provider-resolved
per-account flag (engine/models.py: system_hipaa OR account.hipaa).

GLOBAL is_hipaa_mode() is patched OFF in every test so the ONLY thing
that can drive redaction is the per-account flag — isolating the exact
L8-4 leak surface.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.actions.registry import ActionRegistry
from email_triage.config import TriageConfig
from email_triage.engine.flow import FlowEngine
from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowStatus,
)
from email_triage.engine.store import FlowStore

from _db_tracking import track

# The PHI-bearing free-text the classifier emits. If redaction fires it
# must NOT appear in the persisted classification_json.
_PHI_REASON = "Patient John Doe MRN 11223344 lab results attached — oncology."


def _make_message(*, hipaa: bool, msg_id: str = "m-phi-1") -> EmailMessage:
    return EmailMessage(
        message_id=msg_id,
        provider="test",
        sender="clinic@example.com",
        recipients=["doctor@example.com"],
        subject="Lab results",
        body_text="See attached.",
        date=datetime(2026, 4, 14, 12, 0, tzinfo=timezone.utc),
        hipaa=hipaa,  # provider-resolved per-account flag (the value N-74 needs)
    )


def _make_classification() -> Classification:
    return Classification(
        category="medical",
        confidence=0.95,
        reason=_PHI_REASON,
        source="llm",
    )


def _build_engine(store: FlowStore, *, message: EmailMessage) -> FlowEngine:
    provider = AsyncMock()
    provider.name = "test"
    provider.search.return_value = [message.message_id]
    provider.fetch_message.return_value = message

    classifier = AsyncMock()
    classifier.classify.return_value = _make_classification()

    config = TriageConfig()
    config.routes = {}

    return FlowEngine(
        store=store,
        provider=provider,
        classifier=classifier,
        config=config,
        registry=ActionRegistry(),
    )


def _read_persisted_classification_json(store: FlowStore, flow_id: str) -> dict:
    """Read the raw persisted classification_json column straight from SQLite.

    Deliberately bypasses the FlowState model / _cls_from_json so we
    assert on what actually LANDED AT REST, not a re-hydrated object.
    """
    row = store._conn.execute(
        "SELECT classification_json FROM flows WHERE flow_id = ?",
        (flow_id,),
    ).fetchone()
    assert row is not None, f"no flow row for {flow_id}"
    raw = row["classification_json"]
    assert raw is not None, "classification_json is NULL — classification never persisted"
    return json.loads(raw)


@pytest.mark.asyncio
async def test_per_account_hipaa_redacts_reason_at_rest_global_off():
    """THE L8-4 regression guard.

    A per-account-HIPAA message (message.hipaa=True) classified with the
    GLOBAL is_hipaa_mode() OFF must persist reason="" in the on-disk
    classification_json. Drives the real classify() -> update_flow path;
    never sets state_bag by hand.
    """
    store = track(FlowStore(":memory:"))
    message = _make_message(hipaa=True)
    engine = _build_engine(store, message=message)

    # Global HIPAA mode OFF — the ONLY thing that can drive redaction is
    # the per-account flag carried on message.hipaa.
    with patch("email_triage.triage_logging.is_hipaa_mode", return_value=False):
        flows = await engine.ingest("is:unread")
        assert len(flows) == 1
        flow = flows[0]
        flow = await engine.process_flow(flow)

    persisted = _read_persisted_classification_json(store, flow.flow_id)
    assert persisted["category"] == "medical", "non-PHI fields must survive"
    assert persisted["reason"] == "", (
        "PER-ACCOUNT HIPAA LEAK: reason persisted cleartext to "
        f"classification_json with global mode OFF. Got: {persisted['reason']!r}. "
        "The per-account redaction did not fire on the real FlowEngine path — "
        "classify() must stamp state_bag['account_hipaa']=bool(message.hipaa)."
    )
    assert _PHI_REASON not in json.dumps(persisted), (
        "PHI substring leaked into the persisted classification_json"
    )


@pytest.mark.asyncio
async def test_non_hipaa_message_preserves_reason_at_rest_global_off():
    """Control: a non-HIPAA message with global mode OFF must PRESERVE the
    reason at rest (proves the redaction is gated, not unconditional)."""
    store = track(FlowStore(":memory:"))
    message = _make_message(hipaa=False)
    engine = _build_engine(store, message=message)

    with patch("email_triage.triage_logging.is_hipaa_mode", return_value=False):
        flows = await engine.ingest("is:unread")
        flow = flows[0]
        flow = await engine.process_flow(flow)

    persisted = _read_persisted_classification_json(store, flow.flow_id)
    assert persisted["reason"] == _PHI_REASON, (
        "non-HIPAA + global-off must preserve the reason — redaction over-fired"
    )


@pytest.mark.asyncio
async def test_global_hipaa_on_redacts_even_for_non_hipaa_message():
    """Control: global is_hipaa_mode() ON redacts regardless of the
    per-account flag (most-restrictive wins — the additive gate)."""
    store = track(FlowStore(":memory:"))
    message = _make_message(hipaa=False)
    engine = _build_engine(store, message=message)

    with patch("email_triage.triage_logging.is_hipaa_mode", return_value=True):
        flows = await engine.ingest("is:unread")
        flow = flows[0]
        flow = await engine.process_flow(flow)

    persisted = _read_persisted_classification_json(store, flow.flow_id)
    assert persisted["reason"] == "", (
        "global HIPAA mode ON must redact regardless of per-account flag"
    )


@pytest.mark.asyncio
async def test_state_bag_account_hipaa_actually_persisted_on_real_path():
    """Prove the value PROPAGATES on the real path (not just that
    redaction happened): the persisted state_bag_json must carry
    account_hipaa=True after the real classify() runs — confirming the
    wiring set it, not the test.
    """
    store = track(FlowStore(":memory:"))
    message = _make_message(hipaa=True)
    engine = _build_engine(store, message=message)

    with patch("email_triage.triage_logging.is_hipaa_mode", return_value=False):
        flows = await engine.ingest("is:unread")
        flow = flows[0]
        flow = await engine.process_flow(flow)

    row = store._conn.execute(
        "SELECT state_bag_json FROM flows WHERE flow_id = ?",
        (flow.flow_id,),
    ).fetchone()
    state_bag = json.loads(row["state_bag_json"])
    assert state_bag.get("account_hipaa") is True, (
        "classify() did not persist state_bag['account_hipaa']=True on the "
        f"real FlowEngine path; got state_bag={state_bag!r}. This is the seam "
        "the manual-set behavioural tests masked."
    )


@pytest.mark.asyncio
async def test_resume_at_fetched_still_redacts():
    """Resume-safety: a flow that re-enters process_flow already at FETCHED
    (crash-recovery) re-fetches the message and must STILL redact — the
    stamp lives in classify(), which runs on every classification write.
    """
    store = track(FlowStore(":memory:"))
    message = _make_message(hipaa=True)
    engine = _build_engine(store, message=message)

    with patch("email_triage.triage_logging.is_hipaa_mode", return_value=False):
        # Create + advance to FETCHED WITHOUT classifying, then drop the
        # in-memory flow and reload from DB (simulating a fresh process
        # picking up a persisted FETCHED flow).
        flows = await engine.ingest("is:unread")
        flow = flows[0]
        flow, _msg = await engine.fetch(flow)
        assert flow.status == FlowStatus.FETCHED

        reloaded = store.get_flow(flow.flow_id)
        assert reloaded.status == FlowStatus.FETCHED
        # account_hipaa is NOT yet set at FETCHED (classify hasn't run) —
        # this is exactly the resume case that must still redact.
        assert "account_hipaa" not in reloaded.state_bag

        reloaded = await engine.process_flow(reloaded)

    persisted = _read_persisted_classification_json(store, flow.flow_id)
    assert persisted["reason"] == "", (
        "resume-at-FETCHED did not redact — the stamp must be in classify(), "
        "not only in fetch()"
    )
