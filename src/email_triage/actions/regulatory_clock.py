"""Start-regulatory-clock action — operator-configured clock creation.

When mail is routed to a category carrying this action, it creates a regulatory
clock CANDIDATE — the operator-driven "propose" step, the human-configured
complement to content detection. Config (per route):

    routes:
      safety-reports:
        actions: [clock]
        clock:
          template: IRB_AWARENESS        # which seeded regulatory def (code)
          responsibility: i_submit       # i_submit | sponsor_submits | unknown

The clock lands as a candidate on ``/clocks``; a human confirms it (propose-then-
confirm) to arm the deadline + escalation ladder. The template + responsibility
come from the ROUTE config — out-of-band operator config, the ONLY sanctioned
source of ``responsibility`` per N-96 — NOT content detection, so there is no
false-positive risk and ``i_submit`` is legitimate here.
"""
from __future__ import annotations

import logging
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.actions.base import (
    Action,
    build_action_log_extras,
    check_idempotent_already_done,
    record_idempotent_done,
)
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider

logger = get_logger("email_triage.actions.regulatory_clock")  # N-196b R21_4

_RESPONSIBILITIES = ("i_submit", "sponsor_submits", "unknown")


def _received_iso(message: EmailMessage) -> str | None:
    """The mail's received instant as ISO (the on_receipt anchor); None if absent."""
    d = getattr(message, "date", None)
    if d is None:
        return None
    if isinstance(d, str):
        return d
    try:
        return d.isoformat()
    except Exception:
        return None


class RegulatoryClockAction(Action):
    """Start a regulatory-clock candidate for mail routed to this category."""

    @property
    def name(self) -> str:
        return "clock"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        config = config or {}
        template = str(config.get("template") or "").strip()
        responsibility = str(config.get("responsibility") or "unknown").strip()
        if responsibility not in _RESPONSIBILITIES:
            responsibility = "unknown"

        def _extras(**more: Any) -> dict[str, Any]:
            return build_action_log_extras(
                flow, message, classification, provider,
                template=template, **more,
            )

        if not template:
            logger.info("clock: no template configured, skipping", extra=_extras())
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "no regulatory template configured"},
            )

        # Don't re-create on a retry / re-run of the SAME message.
        prior = await check_idempotent_already_done(flow, message, self.name)
        if prior is not None:
            return prior

        state_bag = flow.state_bag or {}
        db = state_bag.get("db")
        secrets = state_bag.get("secrets")
        account_id = state_bag.get("account_id")
        if db is None or account_id is None:
            # No DB/account in scope (a bare FlowEngine path) — can't persist a clock.
            logger.info("clock: no db/account in flow state, skipping", extra=_extras())
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "no db/account context"},
            )

        from email_triage.classify.safety_detect import (
            create_clock_candidate_from_route,
        )
        from email_triage.web.db_threadpool import db_call

        # The candidate INSERT + case_ref keyed-hash touch conn + secrets — hop
        # OFF the event loop (db_call runs it under the  writer RLock; F1).
        try:
            instance_id = await db_call(
                create_clock_candidate_from_route,
                db, secrets,
                def_code=template,
                account_id=int(account_id),
                subject=getattr(message, "subject", None),
                body=getattr(message, "body_text", None),
                message_id=getattr(message, "message_id", None),
                received_at=_received_iso(message),
                responsibility=responsibility,
            )
        except Exception as e:
            logger.error("clock: candidate creation failed", exc_info=e, extra=_extras())
            return ActionOutput(result=ActionResult.FAILED, error=fmt_exc(e))

        await record_idempotent_done(flow, message, self.name)
        if instance_id is None:
            # def unknown/disabled OR a clock already tracks this case → no-op.
            logger.info("clock: already tracked or template unavailable", extra=_extras())
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "already tracked or template disabled"},
            )
        logger.info("clock: candidate created", extra=_extras(instance_id=instance_id))
        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={"instance_id": instance_id, "template": template},
        )
