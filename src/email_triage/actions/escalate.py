"""Escalation action — urgent notification via secondary email (SMS gateway).

Sends a minimal notification to the user's configured notify_email address
(intended for email-to-SMS bridges like carrier gateways).

Standard mode: category + sender display name + subject + timestamp.
HIPAA mode:    category + sender first name + timestamp.
No body, no flow IDs, no links — just enough to identify the message and
its priority.
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

logger = logging.getLogger("email_triage.actions.escalate")


def _extract_display_name(sender: str) -> str:
    """Extract a display name from an email address.

    "Dr. Jane Smith <jane@hospital.org>" -> "Dr. Jane Smith"
    "jane@hospital.org" -> "jane"
    """
    if "<" in sender:
        return sender.split("<")[0].strip().strip('"')
    return sender.split("@")[0]


def _extract_first_name(sender: str) -> str:
    """Extract just the first name from a sender string.

    "Dr. Jane Smith <jane@hospital.org>" -> "Jane"
    "jane@hospital.org" -> "jane"
    """
    display = _extract_display_name(sender)
    parts = display.split()
    # Skip common prefixes.
    prefixes = {"dr.", "mr.", "mrs.", "ms.", "prof."}
    for part in parts:
        if part.lower() not in prefixes:
            return part
    return parts[-1] if parts else display


class EscalateAction(Action):
    """Send an urgent notification to a secondary email address.

    This action is typically triggered for urgent categories like
    ``to-respond`` and ``action-required``.  The actual email sending
    is stubbed for now — it logs the notification payload and stores it
    in the action output.  Full SMTP delivery is added in Phase 6.
    """

    @property
    def name(self) -> str:
        return "escalate"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        # PR 6 / C2 — guard against duplicate SMS / pager alerts on
        # flow retry. The carrier gateway will happily deliver a
        # second SMS for the same message; operator gets paged twice.
        from email_triage.actions.base import (
            check_idempotent_already_done, record_idempotent_done,
        )
        prior = check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            return prior

        # Check for notify_email in flow state_bag or config.
        notify_email = (
            (config or {}).get("notify_email")
            or flow.state_bag.get("notify_email")
        )
        if not notify_email:
            logger.info(
                "No notify_email configured, skipping escalation",
                extra={"flow_id": flow.flow_id},
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "No notify_email configured"},
            )

        notification = self._build_notification(message, classification)

        logger.info(
            "Escalation: %s -> %s",
            notification["text"],
            notify_email,
            extra={"flow_id": flow.flow_id},
        )

        # Pull SMTP context from flow.state_bag (stashed at flow
        # construction time by the watcher / triage runner). Same
        # pattern that surfaces account_id / owner there. If absent
        # or incomplete, skip the send rather than fail the flow —
        # the operator may have escalation configured but no SMTP
        # relay yet, and we shouldn't break their pipeline.
        smtp_cfg = (flow.state_bag or {}).get("smtp_config")
        secrets = (flow.state_bag or {}).get("secrets")
        if smtp_cfg is None or not getattr(smtp_cfg, "host", ""):
            logger.warning(
                "Escalation: SMTP not configured; alert logged only",
                extra={"flow_id": flow.flow_id, "notify_email": notify_email},
            )
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={
                    "reason": "smtp not configured",
                    "notify_email": notify_email,
                    "notification": notification,
                },
            )

        # The notification text was scrubbed by _build_notification:
        # in HIPAA mode (per-account `message.hipaa` flag OR system
        # `is_hipaa_mode()`) it's first-name + timestamp only; in
        # standard mode it adds display name + subject. No body
        # content reaches this path regardless.
        try:
            from email_triage.web.smtp_send import send_simple_smtp_email
            smtp_password = ""
            if secrets is not None:
                try:
                    smtp_password = secrets.get("SMTP_PASSWORD") or ""
                except Exception:
                    smtp_password = ""
            send_simple_smtp_email(
                smtp_host=smtp_cfg.host,
                smtp_port=smtp_cfg.port,
                smtp_user=smtp_cfg.username,
                smtp_password=smtp_password,
                from_addr=smtp_cfg.from_addr,
                to_addr=notify_email,
                # Carrier email-to-SMS gateways concat subject + body
                # into the SMS payload; using the alert text as the
                # subject ensures the operator sees it on lock-screen
                # preview without having to open the message.
                subject=notification["text"],
                body="Open your inbox to review.",
                use_tls=smtp_cfg.use_tls,
                from_name=smtp_cfg.from_name,
                triage_source="escalation",
            )
        except Exception as e:
            logger.error(
                "Escalation SMTP send failed",
                exc_info=e,
                extra={"flow_id": flow.flow_id, "notify_email": notify_email},
            )
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"{type(e).__name__}: {e}",
                data={
                    "notify_email": notify_email,
                    "notification": notification,
                },
            )

        record_idempotent_done(
            flow, message, self.name, external_id=notify_email,
        )
        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={
                "notify_email": notify_email,
                "notification": notification,
            },
        )

    def _build_notification(
        self,
        message: EmailMessage,
        classification: Classification,
    ) -> dict[str, str]:
        ts = datetime.now(timezone.utc).strftime("%H:%M")

        # Category tag at the front so the recipient can prioritise on
        # lock-screen preview without opening the message. Empty / None
        # category falls back to the bare URGENT marker (rare; the
        # classifier always emits a category).
        category = (getattr(classification, "category", "") or "").strip()
        prefix = f"URGENT [{category}]" if category else "URGENT"

        # Per-message HIPAA state (set at fetch time from account flag
        # OR system flag). Falls back to the global flag if the message
        # wasn't tagged — defensive for legacy call paths.
        hipaa = getattr(message, "hipaa", False) or is_hipaa_mode()
        if hipaa:
            # HIPAA payload: prefix + first-name + timestamp. No
            # subject (might be PHI). No display name (might leak
            # provider identity beyond the covered entity boundary).
            first_name = _extract_first_name(message.sender)
            text = f"{prefix}: New email from {first_name} at {ts}"
            return {"text": text, "mode": "hipaa"}

        # Standard payload: prefix + sender display name + subject +
        # timestamp. SMS gateways concat subject + body; the entire
        # alert reads as one line on lock-screen preview.
        display_name = _extract_display_name(message.sender)
        text = (
            f"{prefix}: New email from {display_name} — "
            f"\"{message.subject}\" at {ts}"
        )
        return {"text": text, "mode": "standard"}
