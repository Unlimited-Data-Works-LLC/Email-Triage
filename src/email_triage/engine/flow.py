"""Flow engine orchestrator — drives emails through the triage pipeline.

The FlowEngine ties together providers, classifiers, list hints, and
actions into a complete lifecycle:

    ingest -> fetch -> classify -> route -> act -> finish/wait/fail
"""

from __future__ import annotations

import logging
import time
from typing import Any, Sequence

from email_triage.actions.registry import ActionRegistry, Router
from email_triage.classify.base import Classifier
from email_triage.classify.hints import collect_hints, find_skip_ai_hint
from email_triage.config import TriageConfig
from email_triage.engine.models import (
    ActionResult,
    Classification,
    ClassificationList,
    EmailMessage,
    FlowState,
    FlowStatus,
    ListRule,
)
from email_triage.engine.store import FlowStore
from email_triage.providers.base import EmailProvider
from email_triage.triage_logging import get_logger

log = get_logger("engine.flow")


class FlowEngine:
    """Orchestrates the email triage pipeline.

    Parameters
    ----------
    store:
        Persistence layer for flow state.
    provider:
        Email provider for fetching messages and performing actions.
    classifier:
        LLM backend for classification.
    config:
        Full triage configuration.
    registry:
        Action registry with all available actions.
    classification_lists:
        All classification lists (personal + global) to consider.
    rules_by_list:
        Mapping from list ID to its rules.
    """

    def __init__(
        self,
        store: FlowStore,
        provider: EmailProvider,
        classifier: Classifier,
        config: TriageConfig,
        registry: ActionRegistry,
        classification_lists: Sequence[ClassificationList] | None = None,
        rules_by_list: dict[int, list[ListRule]] | None = None,
    ):
        self._store = store
        self._provider = provider
        self._classifier = classifier
        self._config = config
        self._registry = registry
        self._router = Router(config.routes, registry)
        self._lists = list(classification_lists or [])
        self._rules = rules_by_list or {}

    # -- Pipeline stages ------------------------------------------------------

    async def ingest(self, query: str, limit: int = 50) -> list[FlowState]:
        """Search for messages and create flows for new ones."""
        log.info("Ingesting", query=query, limit=limit)

        message_ids = await self._provider.search(query, limit)
        log.info("Found messages", count=len(message_ids))

        flows = []
        for msg_id in message_ids:
            flow, created = self._store.get_or_create_flow(msg_id, self._provider.name)
            if created:
                flows.append(flow)
                log.debug("Created flow", flow_id=flow.flow_id, message_id=msg_id)
            else:
                log.debug("Flow exists", flow_id=flow.flow_id, message_id=msg_id)

        log.info("Ingested new flows", count=len(flows))
        return flows

    async def fetch(self, flow: FlowState) -> tuple[FlowState, EmailMessage]:
        """Fetch the message content and advance the flow to FETCHED."""
        message = await self._provider.fetch_message(flow.message_id)

        flow.status = FlowStatus.FETCHED
        flow = self._store.update_flow(flow, expected_revision=flow.revision)
        log.info("Fetched", flow_id=flow.flow_id)
        return flow, message

    async def classify(
        self, flow: FlowState, message: EmailMessage
    ) -> tuple[FlowState, Classification]:
        """Classify the message and advance the flow to CLASSIFIED."""
        flow.status = FlowStatus.CLASSIFYING
        flow = self._store.update_flow(flow, expected_revision=flow.revision)

        # Collect list hints.
        hints = collect_hints(message, self._lists, self._rules)

        # Check for skip_ai hint.
        skip_hint = find_skip_ai_hint(hints)
        if skip_hint:
            classification = Classification(
                category=skip_hint.category,
                confidence=1.0,
                reason=f"Matched skip_ai rule: {skip_hint.rule_type.value} '{skip_hint.pattern}'",
                source="list_rule",
            )
            log.info(
                "Classified via skip_ai rule",
                flow_id=flow.flow_id,
                category=classification.category,
            )
        else:
            start = time.monotonic()
            classification = await self._classifier.classify(
                message,
                self._config.classifier.categories,
                list_hints=hints or None,
            )
            elapsed = time.monotonic() - start
            log.info(
                "Classified via LLM",
                flow_id=flow.flow_id,
                category=classification.category,
                confidence=classification.confidence,
                elapsed_ms=round(elapsed * 1000),
            )

        flow.status = FlowStatus.CLASSIFIED
        flow.classification = classification
        flow = self._store.update_flow(flow, expected_revision=flow.revision)
        return flow, classification

    async def route_and_act(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
    ) -> FlowState:
        """Resolve actions for the category and execute them."""
        flow.status = FlowStatus.ROUTING
        flow = self._store.update_flow(flow, expected_revision=flow.revision)

        actions = self._router.resolve(classification.category)
        flow.actions_pending = [a.name for a in actions]

        flow.status = FlowStatus.ACTING
        flow = self._store.update_flow(flow, expected_revision=flow.revision)

        for action in actions:
            log.info(
                "Executing action",
                flow_id=flow.flow_id,
                action=action.name,
            )
            output = await action.execute(
                flow, message, classification, self._provider,
            )

            flow.actions_pending = [
                a for a in flow.actions_pending if a != action.name
            ]
            flow.actions_completed.append(action.name)

            if output.result == ActionResult.WAITING:
                flow.status = FlowStatus.WAITING
                flow.state_bag.update(output.data)
                flow = self._store.update_flow(flow, expected_revision=flow.revision)
                log.info(
                    "Flow waiting",
                    flow_id=flow.flow_id,
                    action=action.name,
                )
                return flow

            if output.result == ActionResult.FAILED:
                flow.status = FlowStatus.FAILED
                flow.error = f"Action '{action.name}' failed: {output.error}"
                flow = self._store.update_flow(flow, expected_revision=flow.revision)
                log.error(
                    "Action failed",
                    flow_id=flow.flow_id,
                    action=action.name,
                    error=output.error,
                )
                return flow

        # All actions completed.
        flow.status = FlowStatus.FINISHED
        flow = self._store.update_flow(flow, expected_revision=flow.revision)
        log.info("Flow finished", flow_id=flow.flow_id)
        return flow

    # -- Full cycle -----------------------------------------------------------

    async def process_flow(self, flow: FlowState) -> FlowState:
        """Run a single flow through the full pipeline.

        Picks up from whatever state the flow is currently in.
        """
        try:
            message: EmailMessage | None = None

            if flow.status == FlowStatus.CREATED:
                flow, message = await self.fetch(flow)

            if flow.status == FlowStatus.FETCHED:
                if message is None:
                    message = await self._provider.fetch_message(flow.message_id)
                flow, classification = await self.classify(flow, message)
            else:
                classification = flow.classification

            if flow.status == FlowStatus.CLASSIFIED and classification:
                if message is None:
                    message = await self._provider.fetch_message(flow.message_id)
                flow = await self.route_and_act(flow, message, classification)

            return flow

        except Exception as e:
            log.error(
                "Flow failed",
                flow_id=flow.flow_id,
                exc_info=True,
            )
            flow.status = FlowStatus.FAILED
            flow.error = str(e)
            try:
                flow = self._store.update_flow(flow, expected_revision=flow.revision)
            except Exception:
                pass  # Best-effort persistence of failure state.
            return flow

    async def run_cycle(
        self,
        query: str = "is:unread",
        limit: int = 50,
    ) -> list[FlowState]:
        """Ingest new messages and process all pending flows."""
        flows = await self.ingest(query, limit)
        results = []
        for flow in flows:
            result = await self.process_flow(flow)
            results.append(result)
        return results
