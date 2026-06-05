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

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

import httpx

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
        ``get_event``). The self-sent event triage path uses
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

    async def respond_to_invite(
        self, event_id: str, response: str,
        *, calendar_id: str | None = None,
    ) -> None:
        """Set our attendee response on an existing event.

        ``response`` is one of ``"accepted"``, ``"declined"``,
        ``"tentative"``. ``calendar_id`` overrides the provider's
        default calendar — mirrors the per-call override on the other
        mutation methods, so an invite on a non-primary calendar is
        answered on the right calendar. The calendar service notifies
        the organizer on our behalf — we never send mail directly.
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


class _CalendarHttpMixin:
    """Shared HTTP plumbing for the OAuth calendar providers.

    :class:`~email_triage.providers.gmail_calendar.GoogleCalendarProvider`
    and
    :class:`~email_triage.providers.office365_calendar.Office365CalendarProvider`
    talk to different APIs (Google Calendar v3 vs Microsoft Graph), but
    their HTTP request lifecycle is identical: a lazily-built long-lived
    ``httpx`` client behind a per-instance refresh lock, and a request
    method that retries once on 401, maps an insufficient-scope 401/403
    to :class:`CalendarScopeError`, and raises a provider-specific
    transport error otherwise.

    That skeleton lived in two hand-maintained copies — the divergence
    is exactly what let the O365 side miss the cold-path refresh lock
    until  hand-ported it. Mixed in once, the lock and the
    error-mapping can no longer drift.

    A concrete provider mixes this in *before* :class:`CalendarProvider`
    and supplies:

    * instance attributes ``_http`` (``httpx.AsyncClient | None``) and
      ``_timeout`` (float), set in ``__init__``;
    * :meth:`_build_client` — construct the httpx client;
    * :meth:`_on_unauthorized` — refresh credentials in place after a
      401, before the retry;
    * :meth:`_http_error` — the provider's transport-error exception;
    * optionally :meth:`_auth_headers` — a per-request ``Authorization``
      header (Google); the default returns ``None`` for providers that
      carry the header on the client itself (Graph);
    * class attributes ``_scope_error_keywords`` and ``_provider_label``.
    """

    #: Substrings that, in a 401/403 body, mean "re-auth for a wider
    #: scope" rather than a generic failure.
    _scope_error_keywords: tuple[str, ...] = ()
    #: Provider tag carried on a raised :class:`CalendarScopeError`.
    _provider_label: str = ""

    # -- hooks the concrete provider supplies ---------------------------

    async def _build_client(self) -> httpx.AsyncClient:
        """Construct the long-lived ``httpx.AsyncClient``."""
        raise NotImplementedError

    async def _auth_headers(self) -> dict[str, str] | None:
        """Per-request ``Authorization`` header.

        Default ``None`` — for providers (Graph) whose client already
        carries the header. Google overrides this because its token
        rotates and is applied per request.
        """
        return None

    async def _on_unauthorized(self, client: httpx.AsyncClient) -> None:
        """Refresh credentials after a 401, before the single retry."""
        raise NotImplementedError

    def _http_error(self, status: int, body: Any, path: str) -> Exception:
        """Return the provider's transport-error exception (unraised)."""
        raise NotImplementedError

    # -- shared plumbing ------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the long-lived httpx client under the per-instance
        refresh lock.

        The lock stops two concurrent cold-path callers from each
        observing ``self._http is None`` and both building a client —
        the loser's connection pool would be orphaned.
        """
        if self._http is not None:
            return self._http
        from email_triage.providers._oauth_http import refresh_lock_for
        async with refresh_lock_for(self):
            if self._http is None:
                self._http = await self._build_client()
            return self._http

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
    ) -> Any:
        """Issue one calendar API request; retry once on 401.

        A 401/403 carrying an insufficient-scope signal raises
        :class:`CalendarScopeError` so the UI can prompt a re-auth; any
        other ``>= 400`` raises the provider's transport error. A 204 /
        empty body yields ``None``; otherwise the decoded JSON (falling
        back to raw text).
        """
        client = await self._get_client()
        for attempt in range(2):
            resp = await client.request(
                method, path, params=params, json=json_data,
                headers=await self._auth_headers(),
            )
            if resp.status_code == 401 and attempt == 0:
                await self._on_unauthorized(client)
                continue

            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                body_str = (
                    json.dumps(body) if isinstance(body, dict) else str(body)
                ).lower()
                if resp.status_code in (401, 403) and any(
                    kw in body_str for kw in self._scope_error_keywords
                ):
                    raise CalendarScopeError(self._provider_label, str(body))
                raise self._http_error(resp.status_code, body, path)

            if resp.status_code == 204 or not resp.content:
                return None
            try:
                return resp.json()
            except Exception:
                return resp.text

        raise self._http_error(401, "Auth failed after refresh", path)

    async def close(self) -> None:
        """Close the long-lived httpx client. Idempotent."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None
