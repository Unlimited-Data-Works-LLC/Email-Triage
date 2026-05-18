"""Abstract calendar provider interface.

Symmetric with :class:`email_triage.providers.base.EmailProvider`. Not
all email providers have a sibling calendar (IMAP doesn't), so the
calendar shape lives in its own ABC instead of bloating the email
interface with NotImplementedError stubs.

Concrete implementations: ``GoogleCalendarProvider`` (Gmail accounts)
and ``Office365CalendarProvider`` (Graph accounts) — both share the
OAuth refresh token of their email-side sibling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from email_triage.engine.models import CalendarEvent


class CalendarProvider(ABC):
    """Abstract calendar provider.

    Mutation methods raise ``NotImplementedError`` by default so a
    read-only provider can opt in partially. The concrete providers
    in this codebase implement everything.
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def list_events(
        self,
        time_min: datetime,
        time_max: datetime,
        limit: int = 250,
    ) -> list[CalendarEvent]:
        """Return events whose timeframe overlaps ``[time_min, time_max)``.

        Datetimes are tz-aware UTC. Implementations follow pagination
        until ``limit`` is reached or the provider runs out of results.
        """

    @abstractmethod
    async def get_event(self, event_id: str) -> CalendarEvent: ...

    async def list_ooo(
        self,
        time_min: datetime,
        time_max: datetime,
    ) -> list[CalendarEvent]:
        """Return out-of-office events overlapping the window.

        Default body is a no-op (empty list) so providers that don't
        distinguish OOO from regular busy events still satisfy the
        interface. Concrete providers override to query the
        calendar-native OOO type (Google `eventType=outOfOffice`,
        Graph `showAs eq 'oof'`).
        """
        return []

    async def get_event_by_uid(self, uid: str) -> CalendarEvent | None:
        """Look up an event by its iCalendar UID.

        Returns None if no match. Used by invite-reply actions to map
        the UID from a `text/calendar` attachment to the calendar's
        own event id.
        """
        raise NotImplementedError

    async def create_event(
        self, event: CalendarEvent,
        *, calendar_id: str | None = None,
    ) -> str:
        """Create an event; return its id.

        ``calendar_id`` overrides the provider's default calendar
        (mirrors the per-call override on ``list_events`` /
        ``get_event``). The self-sent event triage path (#107) uses
        this to write to the operator-picked ``self_schedule``
        calendar without instantiating a new provider per call.
        Providers without a write-side calendar (IMAP, CalDAV-stub)
        keep raising ``NotImplementedError``.
        """
        raise NotImplementedError

    async def update_event(
        self, event_id: str, partial: dict[str, Any],
        *, calendar_id: str | None = None,
    ) -> None:
        """Patch the named event with the supplied fields."""
        raise NotImplementedError

    async def delete_event(
        self, event_id: str,
        *, calendar_id: str | None = None,
    ) -> None:
        """Cancel / remove the named event."""
        raise NotImplementedError

    async def respond_to_invite(self, event_id: str, response: str) -> None:
        """Set our attendee response on an existing event.

        ``response`` is one of ``"accepted"``, ``"declined"``,
        ``"tentative"``. The calendar service notifies the organizer
        on our behalf — we never send mail directly.
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Release any open connections / clients."""


class CalendarScopeError(Exception):
    """Raised when the OAuth token lacks the calendar scope.

    Callers should surface a re-authentication prompt rather than
    treating this like a generic API error — the user needs to
    re-grant consent for the wider scope.
    """

    def __init__(self, provider: str = "", message: str = ""):
        self.provider = provider
        super().__init__(message or f"calendar scope missing for {provider}")
