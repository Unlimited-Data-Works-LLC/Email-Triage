"""Notification action — metadata-only alerts.

In standard mode: sender + subject + category.
In HIPAA mode (``account_hipaa_effective``: install flag, account flag, or
message stamp): category + timestamp only.
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

    Two-stage delivery; the body is NEVER included in either stage:

    1. The application log is the **durable receipt** — always written,
       even if webhook fan-out is disabled or the delivery fails.
    2. The payload is then best-effort fanned out to the operator-configured
       Outbound event webhooks, through one of two doors in
       :mod:`email_triage.web.events` chosen by one
       ``account_hipaa_effective`` decision (account row + message stamp):

       * HIPAA → a metadata-only payload (category, timestamp, flow_id,
         account_id) to ``fire_notification`` (N-276 R28), which refuses
         any content-bearing key regardless of the caller.
       * Standard → a payload with sender + subject to
         ``fire_standard_notification`` (punch 608), which re-checks HIPAA
         through the same SSOT at the actuator and hands anything it
         cannot verify as standard back to ``fire_notification``.

       Both HMAC-sign each POST and honour the deny-by-default external-URL
       egress gate. A fan-out failure is logged as a warning and never
       breaks the flow.

    Per-target body shapes (N-419, landed 2026-07-15 in ``b04d1019``):
    each webhook target has a ``target_type`` (``custom``, ``slack``,
    ``pagerduty``, ``opsgenie``, ``discord``, ``teams``; registry
    ``web/_webhook_target_types.py::TARGET_TYPES``) and an optional
    ``body_template``. ``web/_webhook_template.py::render_for_target``
    reshapes Email Triage's envelope into the destination's native body
    and the HMAC signs the rendered bytes; ``custom`` with no template
    sends the canonical envelope unchanged. For a HIPAA-effective
    notification the reshaper ignores the operator's template and emits
    only ``{event, category, timestamp, flow_id}`` (the HIPAA lock).
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

        # One HIPAA decision for this notification, from the account-
        # effective SSOT over BOTH the account row and the message stamp
        # (punch 608: the message stamp alone missed a HIPAA account whose
        # message was not stamped). It picks the payload shape and the door.
        account = (flow.state_bag or {}).get("account")
        hipaa = account_hipaa_effective(account=account, message=message)
        notification = self._build_notification(
            flow, message, classification, hipaa=hipaa,
        )
        logger.info(
            "Notification dispatched",
            extra={"flow_id": flow.flow_id},
        )
        # N-276 R28: fire the notification over the operator-configured
        # webhook targets (row 77 closure). Best-effort — a webhook failure
        # never breaks the flow (the log line above is the durable receipt).
        #
        # Two doors (punch 608). HIPAA → the metadata-only payload goes to
        # `fire_notification`, which refuses any content-bearing key. Standard
        # → the sender/subject payload goes to `fire_standard_notification`,
        # which re-asks the SSOT at the actuator and hands anything it cannot
        # verify as standard back to the strict door (refused + audited).
        # Before this, standard payloads went to the strict door and were
        # refused on every call.
        try:
            from email_triage.web.events import (
                fire_notification, fire_standard_notification,
            )
            if hipaa:
                await fire_notification(notification, is_hipaa=True)
            else:
                await fire_standard_notification(
                    notification, account=account, message=message,
                )
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
        *,
        hipaa: bool | None = None,
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

        # `execute` passes the one decision it made. A direct caller that
        # passes nothing gets the same SSOT over the flow's account row and
        # the message stamp (most-restrictive-wins).
        if hipaa is None:
            hipaa = account_hipaa_effective(
                account=(flow.state_bag or {}).get("account"), message=message,
            )
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
