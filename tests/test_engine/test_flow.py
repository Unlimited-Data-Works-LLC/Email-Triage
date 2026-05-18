"""Tests for the FlowEngine orchestrator."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.base import Action
from email_triage.actions.registry import ActionRegistry
from email_triage.config import ClassifierConfig, RouteConfig, TriageConfig
from email_triage.engine.flow import FlowEngine
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.engine.store import FlowStore


def _make_message(msg_id: str = "m-1") -> EmailMessage:
    return EmailMessage(
        message_id=msg_id,
        provider="test",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Test subject",
        body_text="Test body.",
        date=datetime(2026, 4, 14, 12, 0, tzinfo=timezone.utc),
    )


def _make_classification(category: str = "invoices") -> Classification:
    return Classification(
        category=category,
        confidence=0.9,
        reason="Test classification.",
    )


class CompletingAction(Action):
    """Action that always completes."""

    def __init__(self, action_name: str = "test_action"):
        self._name = action_name
        self.call_count = 0

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, flow, message, classification, provider, config=None):
        self.call_count += 1
        return ActionOutput(result=ActionResult.COMPLETED)


class WaitingAction(Action):
    """Action that always waits."""

    @property
    def name(self) -> str:
        return "waiting_action"

    async def execute(self, flow, message, classification, provider, config=None):
        return ActionOutput(
            result=ActionResult.WAITING,
            data={"waiting_for": "approval"},
        )


class FailingAction(Action):
    """Action that always fails."""

    @property
    def name(self) -> str:
        return "failing_action"

    async def execute(self, flow, message, classification, provider, config=None):
        return ActionOutput(
            result=ActionResult.FAILED,
            error="Something went wrong",
        )


def _build_engine(
    store: FlowStore,
    provider: AsyncMock | None = None,
    classifier: AsyncMock | None = None,
    actions: list[Action] | None = None,
    routes: dict[str, RouteConfig] | None = None,
) -> FlowEngine:
    if provider is None:
        provider = AsyncMock()
        provider.name = "test"
        provider.search.return_value = ["m-1", "m-2"]
        provider.fetch_message.return_value = _make_message()

    if classifier is None:
        classifier = AsyncMock()
        classifier.classify.return_value = _make_classification()

    registry = ActionRegistry()
    for action in (actions or []):
        registry.register(action)

    config = TriageConfig()
    config.routes = routes or {}

    return FlowEngine(
        store=store,
        provider=provider,
        classifier=classifier,
        config=config,
        registry=registry,
    )


class TestIngest:
    async def test_creates_flows_for_new_messages(self, memory_store):
        engine = _build_engine(memory_store)
        flows = await engine.ingest("is:unread", limit=10)
        assert len(flows) == 2
        assert all(f.status == FlowStatus.CREATED for f in flows)

    async def test_deduplicates_existing(self, memory_store):
        engine = _build_engine(memory_store)
        await engine.ingest("is:unread")
        # Second ingest should not create new flows.
        flows2 = await engine.ingest("is:unread")
        assert len(flows2) == 0

    async def test_passes_query_to_provider(self, memory_store):
        provider = AsyncMock()
        provider.name = "test"
        provider.search.return_value = []
        engine = _build_engine(memory_store, provider=provider)
        await engine.ingest("from:boss@company.com", limit=5)
        provider.search.assert_called_once_with("from:boss@company.com", 5)


class TestFetch:
    async def test_advances_to_fetched(self, memory_store):
        engine = _build_engine(memory_store)
        flow = memory_store.create_flow("m-1", "test")
        flow, message = await engine.fetch(flow)
        assert flow.status == FlowStatus.FETCHED
        assert message.message_id == "m-1"


class TestClassify:
    async def test_advances_to_classified(self, memory_store):
        engine = _build_engine(memory_store)
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.FETCHED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow, classification = await engine.classify(flow, _make_message())
        assert flow.status == FlowStatus.CLASSIFIED
        assert classification.category == "invoices"
        assert flow.classification is not None


class TestRouteAndAct:
    async def test_completes_with_actions(self, memory_store):
        action = CompletingAction("notify")
        engine = _build_engine(
            memory_store,
            actions=[action],
            routes={"invoices": RouteConfig(actions=["notify"])},
        )
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.CLASSIFIED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow = await engine.route_and_act(flow, _make_message(), _make_classification())
        assert flow.status == FlowStatus.FINISHED
        assert "notify" in flow.actions_completed
        assert action.call_count == 1

    async def test_multiple_actions(self, memory_store):
        a1 = CompletingAction("notify")
        a2 = CompletingAction("label")
        engine = _build_engine(
            memory_store,
            actions=[a1, a2],
            routes={"invoices": RouteConfig(actions=["notify", "label"])},
        )
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.CLASSIFIED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow = await engine.route_and_act(flow, _make_message(), _make_classification())
        assert flow.status == FlowStatus.FINISHED
        assert flow.actions_completed == ["notify", "label"]

    async def test_waiting_action_parks_flow(self, memory_store):
        action = WaitingAction()
        engine = _build_engine(
            memory_store,
            actions=[action],
            routes={"invoices": RouteConfig(actions=["waiting_action"])},
        )
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.CLASSIFIED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow = await engine.route_and_act(flow, _make_message(), _make_classification())
        assert flow.status == FlowStatus.WAITING
        assert flow.state_bag.get("waiting_for") == "approval"

    async def test_failing_action_fails_flow(self, memory_store):
        action = FailingAction()
        engine = _build_engine(
            memory_store,
            actions=[action],
            routes={"invoices": RouteConfig(actions=["failing_action"])},
        )
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.CLASSIFIED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow = await engine.route_and_act(flow, _make_message(), _make_classification())
        assert flow.status == FlowStatus.FAILED
        assert "failing_action" in flow.error

    async def test_no_route_finishes_immediately(self, memory_store):
        engine = _build_engine(memory_store)
        flow = memory_store.create_flow("m-1", "test")
        flow.status = FlowStatus.CLASSIFIED
        flow = memory_store.update_flow(flow, expected_revision=0)

        flow = await engine.route_and_act(flow, _make_message(), _make_classification())
        assert flow.status == FlowStatus.FINISHED


class TestProcessFlow:
    async def test_full_lifecycle(self, memory_store):
        action = CompletingAction("notify")
        engine = _build_engine(
            memory_store,
            actions=[action],
            routes={"invoices": RouteConfig(actions=["notify"])},
        )
        flow = memory_store.create_flow("m-1", "test")
        flow = await engine.process_flow(flow)
        assert flow.status == FlowStatus.FINISHED
        assert "notify" in flow.actions_completed

    async def test_handles_exception(self, memory_store):
        provider = AsyncMock()
        provider.name = "test"
        provider.fetch_message.side_effect = RuntimeError("Network error")
        engine = _build_engine(memory_store, provider=provider)
        flow = memory_store.create_flow("m-1", "test")
        flow = await engine.process_flow(flow)
        assert flow.status == FlowStatus.FAILED
        assert "Network error" in flow.error


class TestRunCycle:
    async def test_processes_all_new(self, memory_store):
        action = CompletingAction("notify")
        engine = _build_engine(
            memory_store,
            actions=[action],
            routes={"invoices": RouteConfig(actions=["notify"])},
        )
        results = await engine.run_cycle("is:unread", limit=10)
        assert len(results) == 2
        assert all(r.status == FlowStatus.FINISHED for r in results)
