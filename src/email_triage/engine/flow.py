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

    async def aclose(self) -> None:
        """Close the engine's owned async clients (provider + classifier) in the
        CURRENT event loop.

        N-132: the CLI ``cmd_run`` / polling ``cmd_watch`` / ``_cmd_watch_push``
        build an engine and never closed it, leaking the provider's AND the
        classifier's lazily-created ``httpx.AsyncClient`` (the  leak family —
        the engine-owned sibling of N-131's CLI-direct provider close). MUST be
        awaited INSIDE the work ``asyncio.run`` (the clients are created there).
        Best-effort + log-not-raise per  (never masks the caller's result);
        each close is guarded so one failure can't block the other. Idempotent
        for the httpx-backed providers (their ``close`` nulls the client).
        """
        for resource, obj in (
            ("provider", self._provider),
            ("classifier", self._classifier),
        ):
            close = getattr(obj, "close", None)
            if not callable(close):
                continue
            try:
                await close()
            except Exception as e:  # : log the WHY, never raise out of teardown
                log.warning(
                    "engine resource close failed", resource=resource, error=repr(e),
                )

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
        # N-74 (L8-4) — stamp the per-account-resolved HIPAA flag onto
        # state_bag BEFORE any update_flow serializes classification_json.
        # ``message.hipaa`` is the provider-resolved per-account value
        # (system_hipaa OR account.hipaa, engine/models.py). ``_cls_to_json``
        # (via _capture_baseline) reads ``state_bag["account_hipaa"]`` to
        # decide whether ``Classification.reason`` (PHI free-text) is
        # redacted at rest. classify() is the ONLY method that writes
        # classification_json (line below sets flow.classification), and it
        # always holds the fetched message — so this is the precise,
        # resume-safe point: a flow re-entering here at FETCHED on
        # crash-recovery re-fetches the message and re-stamps. Stamping it
        # here also persists the flag into state_bag_json, so a later
        # reload carries it. Without this set, the per-account gate was
        # vacuous on the FlowEngine DB-write path — nothing else ever set
        # this key (the web triage_one path uses a different dict and does
        # NOT write classification_json).
        flow.state_bag["account_hipaa"] = bool(message.hipaa)

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
            # N-113 — HIPAA + BAA egress gate (shared SSOT, §164.308(b)(1)). The
            # CLI FlowEngine (`email-triage run`/`watch`) classifies via the
            # global-config classifier with NO run-level gate (unlike the web
            # run_triage), so a HIPAA message on an external non-BAA'd classifier
            # would egress PHI at the classify below. Fail CLOSED first — raise the
            # established BackendBAARequiredError (the except handler marks the flow
            # FAILED, persists the reason, no PHI egress, no retry). No-op for the
            # common local / BAA-acked classifier (baa_block_status → None).
            if bool(getattr(message, "hipaa", False)):
                from email_triage.classify.baa_gate import baa_block_status
                from email_triage.ai_backends.base import BackendBAARequiredError
                # N-113: CLI FlowEngine is single-threaded with a sync FlowStore
                # (no web event loop) — same property the sibling
                # self._store.update_flow touches in this method already rely on.
                _blk = baa_block_status(self._store._conn, self._classifier, True)  # async-db-ok (N-113): CLI single-thread, sync store
                if _blk is not None:
                    raise BackendBAARequiredError(
                        f"HIPAA account: classifier {_blk.get('backend')} @ "
                        f"{_blk.get('host') or '?'} is not BAA-acked — refusing to "
                        "classify (no PHI egress, N-113). Acknowledge a BAA on "
                        "/config or switch to a local Ollama."
                    )
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
            #  — a backup model served because the configured primary
            # could not: write ONE tamper-evident failover-audit row.
            # Only fires on the rare failover path.
            if classification.failover_from and classification.served_model:
                self._record_model_failover_audit(flow, classification)

        flow.status = FlowStatus.CLASSIFIED
        flow.classification = classification
        flow = self._store.update_flow(flow, expected_revision=flow.revision)
        return flow, classification

    def _record_model_failover_audit(
        self,
        flow: FlowState,
        classification: Classification,
    ) -> None:
        """ — emit a tamper-evident failover-audit row.

        Emitted through the STANDARD logging path so the
        ``SQLiteLogHandler`` persists it to the ``log_entries`` HMAC
        chain WITH its cached chain-tail intact. Writing ``log_entries``
        out-of-band (e.g. ``insert_log_entry`` on a foreign connection)
        would FORK the chain — the handler caches the last row hash on
        its instance and would not see the out-of-band row. The handler
        owns the DB write + write-lock (same path as the "Classified via
        LLM" line above). Best-effort — never breaks classification.
        Carries model names + flow/message ids only — NO email content
        (PHI). Only fires on the rare failover path.
        """
        try:
            log.warning(
                "Classification model failover",
                event="model_failover",
                failed_model=classification.failover_from,
                served_model=classification.served_model,
                flow_id=flow.flow_id,
                message_id=flow.message_id,
            )
        except Exception as e:  # pragma: no cover - audit is best-effort
            log.warning(
                "model-failover audit emit failed",
                flow_id=flow.flow_id,
                error=str(e),
            )

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

            #  — Persist actions_completed after every successful action
            # body, not just on terminal exits. A crash mid-loop (between
            # action N succeeding and action N+1 starting) would otherwise
            # leave the DB with the segment's actions_completed=[], and a
            # crash-recovery rerun would re-execute action N. Per-action
            # idempotency (`record_idempotent_done`, watch-fire , the
            # naturally-idempotent label/move surfaces) keeps the re-run a
            # no-op today, but the structural fix is to persist progress
            # before yielding the loop. The Action-idempotency class
            # invariant (see tests/test_actions/test_action_idempotency_invariant.py)
            # is the paired guarantee that holds this rating at MED — without
            # it a future non-idempotent action silently re-opens HIGH
            # exposure. The terminal WAITING/FAILED/FINISHED branches below
            # still persist their status transition; this is just an
            # additional per-iteration checkpoint of progress.
            flow = self._store.update_flow(
                flow, expected_revision=flow.revision,
            )

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
                # census run13 #2 — output.error is the action's raw str(e),
                # which on a mail/IMAP action can echo a recipient address or
                # mailbox path (PHI) / a token (secret). flows.error is a
                # persisted, operator-facing column → scrub BOTH legs.
                from email_triage._errfmt import scrub_error_for_persist
                flow.error = scrub_error_for_persist(
                    f"Action '{action.name}' failed: {output.error}"
                )
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
            # N-42: flow.error persists into the `flows` PHI table; e wraps
            # mail/IMAP ops whose text can carry an address/mailbox path.
            from email_triage._errfmt import scrub_error_for_persist
            flow.error = scrub_error_for_persist(e)
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
