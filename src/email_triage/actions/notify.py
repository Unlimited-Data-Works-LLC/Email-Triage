"""Notification action — metadata-only alerts.

In standard mode: sender + subject + category.
In HIPAA mode: category + timestamp only.
Email body content is NEVER included in notifications regardless of mode.
"""

from __future__ import annotations

import logging
from email_triage._isotime import now_utc_iso
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
from email_triage.triage_logging import account_hipaa_effective

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.actions.notify")  # N-196b R21_4


class NotifyAction(Action):
    """Log a notification about a classified email + fan out over webhooks.

    Two-stage delivery, both HIPAA-safe by construction (the payload
    ``_build_notification`` produces is already metadata-only in HIPAA
    mode; the body is NEVER included in either stage):

    1. The application log is the **durable receipt** — always written,
       even if webhook fan-out is disabled or the delivery fails.
    2. The redacted payload is then best-effort fanned out via
       :func:`email_triage.web.events.fire_notification` (N-276 R28) to
       the operator-configured Outbound event webhooks system, which
       HMAC-signs each POST and honours the deny-by-default external-URL
       egress gate. A fan-out failure is logged as a warning and never
       breaks the flow.

    The POST body is Email Triage's own envelope
    (``{"event", "timestamp", "data": {...}}``, canonical JSON, HMAC-signed
    per target). There is NO per-target body templating today —
    Slack/PagerDuty/Opsgenie each require their own top-level shape
    (Slack ``text``/``blocks``; PagerDuty Events v2 ``routing_key`` +
    ``event_action`` + ``payload.summary``; Opsgenie ``GenieKey`` header),
    so a direct POST to any of those services' native endpoints would
    fail (400 invalid_payload / 401 / etc.). The supported architecture
    is relay-shaped: the operator points the webhook at a small reshaper
    (n8n / a lambda / an OpenClaw skill) that verifies the HMAC
    signature and translates the envelope into the destination's native
    shape. That's what the HMAC exists for.
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
        # PR 6 / C2 — idempotency-guarded so the same surface answers
        # "did this run?" for every action. Webhook fan-out below
        # (N-276 R28) makes the guard load-bearing: a re-driven flow
        # must not double-POST to the configured webhook targets.
        from email_triage.actions.base import (
            check_idempotent_already_done, record_idempotent_done,
        )
        prior = await check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            return prior

        notification = self._build_notification(flow, message, classification)
        logger.info(
            "Notification dispatched",
            extra={"flow_id": flow.flow_id},
        )
        # N-276 R28: fire the redacted-by-construction notification over
        # the operator-configured webhook targets (row 77 closure).
        # `_build_notification` already produced the HIPAA-safe metadata-
        # only shape when the message is HIPAA-tagged (matches the SMS-
        # escalate route). Best-effort — a webhook failure never breaks
        # the flow (the log line above is the durable receipt).
        try:
            from email_triage.web.events import fire_notification
            hipaa = account_hipaa_effective(message=message)
            await fire_notification(notification, is_hipaa=hipaa)
        except Exception as _e:
            logger.warning(
                "NotifyAction webhook dispatch failed",
                extra={"flow_id": flow.flow_id, "error": type(_e).__name__},
            )
        await record_idempotent_done(flow, message, self.name)
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
        ts = now_utc_iso()

        # D1 fix (2026-07-16, DA-F1 close-out): source account_id from the
        # state_bag SSOT (same shape as actions/add_label.py:165,
        # actions/regulatory_clock.py:102, actions/self_sent_event.py:492,
        # actions/base.py:121). fire_notification (web/events.py:682) reads
        # payload.get("account_id") to route per-account webhook targets;
        # before this fix _build_notification omitted the key, every notify
        # dispatched with acct_id=None, and every account-scoped
        # WebhookTarget was silently filtered out at events.py:230-232 —
        # scoped-webhook per-account routing shipped DOA. Key is ALWAYS
        # present now; None is legitimate for genuine broadcasts (kill-
        # switch, health ping) and routes correctly to wildcard-only per
        # the DA-F2 broadcast semantic.
        account_id = (flow.state_bag or {}).get("account_id")

        # Read HIPAA state from the message itself (which was stamped
        # at fetch time to reflect BOTH the system flag and this
        # specific account's per-account flag). Falls back to the
        # global flag if the message wasn't tagged.
        hipaa = account_hipaa_effective(message=message)
        if hipaa:
            return {
                "flow_id": flow.flow_id,
                "account_id": account_id,
                "category": classification.category,
                "timestamp": ts,
                "summary": f"[{classification.category}] at {ts}",
            }

        return {
            "flow_id": flow.flow_id,
            "account_id": account_id,
            "sender": message.sender,
            "subject": message.subject,
            "category": classification.category,
            "timestamp": ts,
            "summary": (
                f"[{classification.category}] "
                f"from {message.sender}: {message.subject}"
            ),
        }
