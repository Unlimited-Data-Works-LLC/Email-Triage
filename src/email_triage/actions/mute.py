"""Mute action — post-classification marker that records user's intent to
silence a matching route.

Semantic
--------
``MuteAction`` is a POST-CLASSIFICATION marker. The message is still
classified, still HIPAA-audited by the triage-runner bracket (per PD 
+ ``record_hipaa_access_event`` at the outer read boundary), and still
persisted. What ``MuteAction`` adds is an explicit, auditable "user
chose to silence this pattern" record — the log line + idempotent
marker + ``muted=True`` in the action-result data.

Suppression semantics are USER CONFIG, not encoded here: to skip
``notify`` / ``draft_reply`` / ``escalate`` for a category, the
operator simply omits those actions from the route (or ticks only
``mute``). This lets ``mute`` compose with other actions when the
operator wants "silence downstream but still label / move" (a common
newsletter shape).

HIPAA-safety
------------
No additional PHI is read; no additional HIPAA audit-events row is
emitted. The classification-and-fire bracket at ``triage_runner`` /
``triage_runner_bulk`` / ``topic_backscan`` already carries the
required §164.312(b) row for the underlying PHI touch. The structured
log emitted here goes through :func:`build_action_log_extras`, which
redacts ``sender`` / ``subject`` on HIPAA-flagged messages. So the
mute-intent is auditable via the log sink AND does not create a
double-audit row.

Extensibility — ``reason`` config field
---------------------------------------
The optional ``reason`` config field on ``execute()`` (``config={"reason":
"..."}``) is honored + bounded at 120 chars in the log record. It is NOT
surfaced in the routes-editor UI today — an operator using the editor
gets the default ``"user_muted"`` reason. Callers wiring MuteAction via
route-config JSON (or a future editor input) may set a custom reason to
distinguish mute categories in the log sink ("vendor_newsletter",
"noisy_listserv", etc.). db-sme NTH 2026-07-17 acknowledged; the field
is retained as an extensibility surface, not dropped, because the
audience-per-page editor tooltip already reads as complete without it
and adding a config input for a marker action would be premature UI
polish.

Idempotency
-----------
Uses the shared ``check_idempotent_already_done`` /
``record_idempotent_done`` helpers, keyed on
``(account_id, rfc_message_id, action_name)`` via the durable
``action_idempotency`` table. A retry-queue re-run or
container restart won't re-log a second mute marker for the same
message.
"""

from __future__ import annotations

from typing import Any

from email_triage.actions.base import (
    Action, build_action_log_extras,
    check_idempotent_already_done, record_idempotent_done,
)
from email_triage.engine.models import (
    ActionOutput, ActionResult, Classification, EmailMessage, FlowState,
)
from email_triage.providers.base import EmailProvider
from email_triage.triage_logging import get_logger

logger = get_logger("email_triage.actions.mute")


class MuteAction(Action):
    """Record an explicit "user chose to mute this route" marker.

    See module docstring for semantic + HIPAA-safety rationale.
    """

    @property
    def name(self) -> str:
        return "mute"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        prior = await check_idempotent_already_done(
            flow, message, self.name,
        )
        if prior is not None:
            return prior

        reason = (config or {}).get("reason") or "user_muted"

        logger.info(
            "Mute applied — auditable marker of user's silence-intent "
            "for this route",
            extra=build_action_log_extras(
                flow, message, classification, provider,
                mute_reason=str(reason)[:120],
            ),
        )

        await record_idempotent_done(flow, message, self.name)
        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={"muted": True, "reason": reason},
        )
