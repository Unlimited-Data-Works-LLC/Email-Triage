"""Meeting-invite reply actions.

Three actions — accept, decline, tentative — that respond to an
incoming `text/calendar` invite. Preferred path mutates the user's
calendar via the calendar provider; the calendar service then
notifies the organizer. Fallback path (calendar not enabled)
constructs an iMIP `METHOD=REPLY` payload and creates a draft via
the email provider — never sends.
"""

from __future__ import annotations

import logging
from typing import Any

from email_triage.actions.base import (
    Action,
    check_idempotent_already_done,
    record_idempotent_done,
)
from email_triage.engine.ics import build_imip_reply
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider
from email_triage.providers.calendar_base import (
    CalendarProvider,
    CalendarScopeError,
)
from email_triage.triage_logging import get_logger

# census run17 #1 — TriageLogger (``get_logger``), NOT raw ``logging.getLogger``,
# so the _PHI_KEYS scrubber strips PHI on the console/file leg too (the HMAC
# ``log_entries`` sink is independently allowlisted by ``redact_persisted_extra``).
# The ``reason=`` field below is a calendar-respond error string (PHI-adjacent).
log = get_logger("actions.invite")


def _find_invite_attachment(message: EmailMessage) -> Any:
    for att in message.attachments or []:
        if (att.content_type or "").lower().startswith("text/calendar"):
            return att
    return None


async def _respond_via_calendar(
    cal: CalendarProvider, uid: str, response: str,
) -> tuple[bool, str]:
    """Try to map the iCal UID to a calendar event and respond.

    Returns ``(success, detail)``. ``detail`` is the event id on
    success, or an error string on failure.
    """
    try:
        event = await cal.get_event_by_uid(uid)
    except Exception as e:
        return False, f"lookup_error: {e}"
    if event is None:
        return False, "event_not_found"
    try:
        #  — answer the invite on the calendar the event was
        # actually found on, not the provider's default calendar.
        await cal.respond_to_invite(
            event.event_id, response, calendar_id=event.calendar_id,
        )
    except Exception as e:
        return False, f"respond_error: {e}"
    return True, event.event_id


async def _draft_imip_fallback(
    provider: EmailProvider,
    message: EmailMessage,
    invite_parsed: dict[str, Any],
    response: str,
    self_email: str,
) -> str:
    """Create an iMIP-reply draft via the email provider; return draft_id."""
    partstat_map = {
        "accepted": "ACCEPTED",
        "declined": "DECLINED",
        "tentative": "TENTATIVE",
    }
    partstat = partstat_map.get(response, "ACCEPTED")
    blob = build_imip_reply(
        original_uid=invite_parsed.get("uid", ""),
        organizer_email=invite_parsed.get("organizer", ""),
        attendee_email=self_email,
        partstat=partstat,
        summary=invite_parsed.get("summary", ""),
        sequence=int(invite_parsed.get("sequence", 0) or 0),
    )
    body_text = (
        f"[email-triage] iMIP {partstat} reply to: "
        f"{invite_parsed.get('summary', '(no subject)')}\n\n"
        "Open this draft, attach the inline calendar payload listed "
        "below if your client does not auto-include it, and send.\n\n"
        f"--- BEGIN VCALENDAR ---\n{blob.decode('utf-8', errors='replace')}\n"
        "--- END VCALENDAR ---\n"
    )
    organizer = invite_parsed.get("organizer", "") or message.sender
    # 2026-05-13 — In-Reply-To must be the RFC 5322 Message-Id
    # header value (``<hash@domain>``), NOT the provider-specific
    # message_id (which is the IMAP UID for IMAP messages). A6
    # (census 2026-06-09): the message-level SSOT is exactly this
    # header-then-provider-id shape (all header casings).
    from email_triage.mail_headers import get_message_rfc_id
    _rfc_id = get_message_rfc_id(message)
    draft_id = await provider.create_draft(
        to=[organizer],
        subject=f"Re: {message.subject}" if message.subject else "Re: Meeting invite",
        body=body_text,
        in_reply_to=_rfc_id,
        thread_id=message.thread_id,
    )
    return draft_id


class _InviteResponseBase(Action):
    """Shared logic for the three invite-reply actions."""

    response: str = "accepted"  # subclasses override

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        #  — guard the side effects. Both branches below mutate
        # external state: the calendar-API path RSVPs on the user's
        # calendar, the fallback path creates an iMIP-reply draft. The
        # retry-queue drainer re-runs the whole triage path, so without
        # this guard a re-run double-RSVPs or creates a second draft.
        # The skip path leaves the prior calendar response / draft
        # intact.
        prior = await check_idempotent_already_done(flow, message, self.name)
        if prior is not None:
            log.info(
                "Invite reply already applied for this message; skipping",
                flow_id=flow.flow_id,
                response=self.response,
                previous_external_id=prior.data.get("previous_external_id"),
            )
            return prior

        att = _find_invite_attachment(message)
        if att is None or not att.parsed:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "no_invite_attachment"},
            )
        parsed = att.parsed

        # The action receives the email provider; the calendar provider
        # (if any) lives on flow.state_bag where the runner / webhook receiver
        # stash it before invoking actions. None → fallback to draft.
        state_bag = getattr(flow, "state_bag", None)
        cal: CalendarProvider | None = None
        if isinstance(state_bag, dict):
            cal = state_bag.get("calendar_provider")

        # Self email for iMIP reply — also stashed by the runner.
        self_email = ""
        if isinstance(state_bag, dict):
            self_email = state_bag.get("self_email", "") or ""

        if cal is not None:
            success, detail = await _respond_via_calendar(
                cal, parsed.get("uid", ""), self.response,
            )
            if success:
                #  — record the calendar event id so a retry-queue
                # re-run skips instead of double-RSVPing.
                await record_idempotent_done(
                    flow, message, self.name,
                    external_id=str(detail) if detail else None,
                )
                return ActionOutput(
                    result=ActionResult.COMPLETED,
                    data={"path": "calendar_api", "event_id": detail,
                          "response": self.response},
                )
            # Scope error or lookup miss → fall through to draft path.
            log.info(
                "Calendar respond failed; falling back to iMIP draft",
                reason=detail,
                uid=parsed.get("uid", ""),
            )

        try:
            draft_id = await _draft_imip_fallback(
                provider, message, parsed, self.response, self_email,
            )
        except CalendarScopeError as e:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"calendar_scope_missing: {e}",
            )
        except Exception as e:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"imip_draft_error: {e}",
            )

        #  — record the draft id so a retry-queue re-run skips
        # instead of drafting a duplicate iMIP reply.
        await record_idempotent_done(
            flow, message, self.name,
            external_id=str(draft_id) if draft_id is not None else None,
        )
        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={"path": "imip_draft", "draft_id": draft_id,
                  "response": self.response},
        )


class AcceptInviteAction(_InviteResponseBase):
    response = "accepted"

    @property
    def name(self) -> str:
        return "accept_invite"


class DeclineInviteAction(_InviteResponseBase):
    response = "declined"

    @property
    def name(self) -> str:
        return "decline_invite"


class TentativeInviteAction(_InviteResponseBase):
    response = "tentative"

    @property
    def name(self) -> str:
        return "tentative_invite"
