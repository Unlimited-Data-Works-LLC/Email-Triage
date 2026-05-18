"""Notification action — metadata-only alerts.

In standard mode: sender + subject + category.
In HIPAA mode: category + timestamp only.
Email body content is NEVER included in notifications regardless of mode.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from email_triage.actions.base import Action
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider
from email_triage.triage_logging import is_hipaa_mode

logger = logging.getLogger("email_triage.actions.notify")


class NotifyAction(Action):
    """Log a notification about a classified email.

    This is the simplest notification path — it logs the notification
    payload.  In a full deployment, this would also push to a notification
    channel (webhook, Slack, etc.).
    """

    @property
    def name(self) -> str:
        return "notify"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        # PR 6 / C2 — pure log-only action today, but record for
        # audit consistency so the same surface answers "did this
        # run?" for every action. If a future revision adds an
        # external side effect (e.g. webhook fan-out), the guard
        # is already in place.
        from email_triage.actions.base import (
            check_idempotent_already_done, record_idempotent_done,
        )
        prior = check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            return prior

        notification = self._build_notification(flow, message, classification)
        logger.info(
            "Notification: %s",
            notification.get("summary", ""),
            extra={"flow_id": flow.flow_id},
        )
        record_idempotent_done(flow, message, self.name)
        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={"notification": notification},
        )

    def _build_notification(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).isoformat()

        # Read HIPAA state from the message itself (which was stamped
        # at fetch time to reflect BOTH the system flag and this
        # specific account's per-account flag). Falls back to the
        # global flag if the message wasn't tagged.
        hipaa = getattr(message, "hipaa", False) or is_hipaa_mode()
        if hipaa:
            return {
                "flow_id": flow.flow_id,
                "category": classification.category,
                "timestamp": ts,
                "summary": f"[{classification.category}] at {ts}",
            }

        return {
            "flow_id": flow.flow_id,
            "sender": message.sender,
            "subject": message.subject,
            "category": classification.category,
            "timestamp": ts,
            "summary": (
                f"[{classification.category}] "
                f"from {message.sender}: {message.subject}"
            ),
        }
