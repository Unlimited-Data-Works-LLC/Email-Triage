"""Meeting-request intercept: draft a reply listing free slots.

When the classifier categorises an email as ``meeting-request``
(prose-only ask, no `.ics` attached), this action reads the user's
calendar, computes the next *N* free windows of length *L* in
business hours, and creates a draft reply listing them. Never sends.

Per-user preferences (length, count, business hours, weekend skip,
horizon, lead time, timezone) live in the ``settings`` table keyed
on ``meeting_prefs:{user_id}`` and are loaded by the runner / API
endpoint and stashed on ``flow.state_bag`` before this action runs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from email_triage.actions.base import Action
from email_triage._errfmt import fmt_exc
from email_triage.engine.availability import find_free_slots
from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    MeetingPreferences,
)
from email_triage.providers.base import EmailProvider
from email_triage.providers.calendar_base import (
    CalendarProvider,
    CalendarScopeError,
)

log = logging.getLogger("email_triage.actions.suggest_meeting_times")


def _format_tz_label(local_dt: datetime, tz_name_fallback: str) -> str:
    """Render the slot's timezone as ``EDT (UTC-4)`` instead of the
    IANA name.

    Uses the slot's OWN ``utcoffset()`` + ``strftime('%Z')`` so a
    slot that crosses the DST boundary picks up the correct
    abbreviation + offset for that specific slot (e.g. a meeting
    suggested for early November after DST ends shows ``EST
    (UTC-5)``, not ``EDT`` — even when the operator's prefs are
    set in May during EDT).

    Falls back to the bare IANA name when ``%Z`` returns empty
    (some non-DST regions on some platforms) or when offset
    resolution fails. Single source of truth for the operator-
    facing meeting-suggestion body.
    """
    abbrev = local_dt.strftime("%Z").strip()
    offset = local_dt.utcoffset()
    if offset is None:
        return abbrev or tz_name_fallback

    total_min = int(offset.total_seconds() // 60)
    sign = "+" if total_min >= 0 else "-"
    h = abs(total_min) // 60
    m = abs(total_min) % 60
    if m:
        offset_str = f"UTC{sign}{h}:{m:02d}"
    else:
        offset_str = f"UTC{sign}{h}"

    if abbrev:
        return f"{abbrev} ({offset_str})"
    # Some zones don't have a short abbreviation on this platform —
    # render the IANA name + offset so the operator still sees
    # something parseable.
    return f"{tz_name_fallback} ({offset_str})"


def _format_slot(start: datetime, end: datetime, tz_name: str) -> str:
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")
    s_local = start.astimezone(tz)
    e_local = end.astimezone(tz)
    # Friday, April 18 — 09:00–09:30 EDT (UTC-4)
    tz_label = _format_tz_label(s_local, tz_name)
    return (
        f"{s_local.strftime('%A, %B %d')} — "
        f"{s_local.strftime('%H:%M')}–{e_local.strftime('%H:%M')} {tz_label}"
    )


def _build_body(
    slots: list[tuple[datetime, datetime]],
    tz_name: str,
    *,
    redact_sender: bool,
    sender_name: str,
) -> str:
    if not slots:
        return (
            "Thanks for reaching out — unfortunately I don't have any "
            "open windows in the next two weeks during business hours. "
            "Could you suggest a few times that work on your end?"
        )
    greeting = "Hi —" if redact_sender else f"Hi {sender_name or 'there'} —"
    lines = [
        greeting,
        "",
        "Thanks for reaching out. Here are a few times that work on my end:",
        "",
    ]
    for s, e in slots:
        lines.append(f"  • {_format_slot(s, e, tz_name)}")
    lines.append("")
    lines.append("Let me know which of these works, and I'll send an invite.")
    lines.append("")
    return "\n".join(lines)


class SuggestMeetingTimesAction(Action):
    """Draft a reply listing free calendar windows."""

    @property
    def name(self) -> str:
        return "suggest_meeting_times"

    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        state_bag = getattr(flow, "state_bag", None)
        cal: CalendarProvider | None = None
        prefs_raw: dict[str, Any] | None = None
        if isinstance(state_bag, dict):
            cal = state_bag.get("calendar_provider")
            prefs_raw = state_bag.get("meeting_prefs")

        if cal is None:
            return ActionOutput(
                result=ActionResult.SKIPPED,
                data={"reason": "calendar_not_enabled"},
            )

        prefs = MeetingPreferences.from_dict(prefs_raw)

        now = datetime.now(timezone.utc)
        horizon_start = now + timedelta(hours=prefs.minimum_lead_time_hours)
        horizon_end = now + timedelta(days=prefs.search_horizon_days)

        try:
            events = await cal.list_events(
                horizon_start, horizon_end, limit=500,
            )
        except CalendarScopeError as e:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"calendar_scope_missing: {e}",
            )
        except Exception as e:
            log.error("Calendar list_events failed", extra={"error": fmt_exc(e)})
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"calendar_error: {fmt_exc(e)}",
            )

        slots = find_free_slots(
            events,
            horizon_start, horizon_end,
            length_minutes=prefs.default_length_minutes,
            count=prefs.suggestion_count,
            business_hours_start=prefs.business_hours_start,
            business_hours_end=prefs.business_hours_end,
            skip_weekends=prefs.skip_weekends,
            timezone_name=prefs.timezone,
            # 2026-05-14 — one-per-day spread (operator preference,
            # see MeetingPreferences.suggestion_days). Single
            # earliest free slot per working day, capped at
            # suggestion_days candidate days. Walking off the legacy
            # contiguous-fill algorithm that produced three back-
            # to-back morning slots when the calendar was quiet.
            days_window=prefs.suggestion_days,
            working_hours=(
                prefs.working_hours
                if prefs.working_hours is not None
                else None
            ),
        )

        body = _build_body(
            slots, prefs.timezone,
            redact_sender=bool(message.hipaa),
            sender_name=_first_name_from_addr(message.sender),
        )

        # 2026-05-13 — In-Reply-To must be the RFC 5322 Message-Id
        # header value (``<hash@domain>``), NOT the provider-specific
        # message_id (which is the IMAP UID for IMAP messages).
        # ``get_rfc_message_id`` extracts the original header from
        # the parsed mail; falls back to the wire message_id so
        # Gmail / O365 messages (where the two are the same)
        # continue working unchanged.
        from email_triage.mail_headers import get_rfc_message_id
        _rfc_id = get_rfc_message_id(message.headers) or message.message_id
        try:
            draft_id = await provider.create_draft(
                to=[message.sender],
                subject=f"Re: {message.subject}" if message.subject else "Re: Meeting request",
                body=body,
                in_reply_to=_rfc_id,
                thread_id=message.thread_id,
            )
        except Exception as e:
            return ActionOutput(
                result=ActionResult.FAILED,
                error=f"draft_error: {e}",
            )

        return ActionOutput(
            result=ActionResult.COMPLETED,
            data={
                "draft_id": draft_id,
                "slots": [(s.isoformat(), e.isoformat()) for s, e in slots],
                "length_minutes": prefs.default_length_minutes,
                "timezone": prefs.timezone,
            },
        )


def _first_name_from_addr(addr: str) -> str:
    """Extract a human-readable first name from a 'Name <email>' string."""
    if not addr:
        return ""
    if "<" in addr:
        name = addr.split("<", 1)[0].strip().strip('"').strip("'")
        if name:
            return name.split()[0]
    return ""


# Constant naming the action's own slug so callers don't hard-code
# the string at multiple sites.
SUGGEST_MEETING_TIMES_ACTION = "suggest_meeting_times"

# Default category that triggers the intercept. The action itself
# does the calendar work; this constant pins which classification
# the auto-injection fires on.
MEETING_REQUEST_CATEGORY = "meeting-request"


def inject_meeting_intercept(
    action_defs: list[dict],
    category: str,
    *,
    calendar_wired: bool,
    has_meeting_prefs: bool,
) -> list[dict]:
    """Return a (possibly modified) action list with the meeting-
    request intercept inserted when appropriate.

    Operator-side promise from the UI ("Meeting-Request Intercept"
    section on the profile page): when an incoming email is
    categorised ``meeting-request``, the calendar-aware intercept
    fires automatically — it doesn't require a manual route entry.
    This function lives at the boundary between "route from DB" and
    "action loop" so every consumer (IDLE watcher, push consumers,
    poll loop, manual triage) gets the same auto-inject behaviour
    from a single source of truth.

    Triggering predicate (all must be true):
      * ``category == MEETING_REQUEST_CATEGORY``
      * ``calendar_wired`` — the per-account calendar provider was
        successfully constructed at flow setup
      * ``has_meeting_prefs`` — the owner has saved meeting-intercept
        preferences (the action's docstring requires them on
        ``flow.state_bag``)

    When triggered:
      * If ``suggest_meeting_times`` is already in ``action_defs``
        the user has explicitly configured it (via the routes
        picker, expanded 2026-05-13 to expose it). Return
        unchanged — no double-fire.
      * Otherwise, prepend ``{"action": "suggest_meeting_times",
        "config": {}}`` AND filter out any ``draft_reply`` entry
        from the list. Two competing drafts for the same message
        is worse than either alone; the calendar-aware draft is
        the more useful one when calendar is wired.

    When the predicate is false, return ``action_defs`` unchanged.

    The function never mutates its input list — always returns a
    new list (or the same one) so callers can rely on identity
    semantics for "did the intercept fire?" comparisons.
    """
    if (
        category != MEETING_REQUEST_CATEGORY
        or not calendar_wired
        or not has_meeting_prefs
    ):
        return action_defs

    # Already in the list — operator-configured, respect their pick.
    if any(
        (a or {}).get("action") == SUGGEST_MEETING_TIMES_ACTION
        for a in action_defs
    ):
        return action_defs

    # Prepend intercept, drop draft_reply (would produce two
    # competing drafts). Other actions (move / label / notify /
    # add-label) survive untouched.
    pruned = [
        a for a in action_defs
        if (a or {}).get("action") != "draft_reply"
    ]
    return [
        {"action": SUGGEST_MEETING_TIMES_ACTION, "config": {}},
        *pruned,
    ]
