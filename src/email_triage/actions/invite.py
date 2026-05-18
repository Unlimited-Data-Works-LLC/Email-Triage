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

from email_triage.actions.base import Action
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

log = logging.getLogger("email_triage.actions.invite")


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
        await cal.respond_to_invite(event.event_id, response)
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
    # message_id (which is the IMAP UID for IMAP messages).
    from email_triage.mail_headers import get_rfc_message_id
    _rfc_id = (
        get_rfc_message_id(message.headers) or message.message_id
    )
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
        att = _find_invite_attachment(message)
        if att is None or not att.parsed:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "no_invite_attachment"},
            )
        parsed = att.parsed

        # The action receives the email provider; the calendar provider
        # (if any) lives on flow.state_bag where the runner / OpenClaw
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
                return ActionOutput(
                    result=ActionResult.COMPLETED,
                    data={"path": "calendar_api", "event_id": detail,
                          "response": self.response},
                )
            # Scope error or lookup miss → fall through to draft path.
            log.info(
                "Calendar respond failed; falling back to iMIP draft",
                extra={"reason": detail, "uid": parsed.get("uid", "")},
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
