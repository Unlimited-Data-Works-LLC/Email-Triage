"""Google Calendar API provider.

Shares the OAuth refresh token of the matching ``GmailApiProvider``
account; the calendar scope is added to the token via the re-auth
device-code flow on the Accounts page. Talks to
``https://www.googleapis.com/calendar/v3`` directly with ``httpx`` —
same shape as the Gmail provider, no ``google-api-python-client``
dependency.

Read-mostly today. ``create_event`` / ``update_event`` /
``delete_event`` / ``respond_to_invite`` are implemented but operate
on single-occurrence events only — recurring-event series-wide edits
are deferred to a later phase.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import date, datetime, time as dt_time, timezone
from typing import Any

import httpx

from email_triage.engine.models import CalendarEvent
from email_triage.providers.calendar_base import (
    CalendarProvider,
    CalendarScopeError,
)
from email_triage.providers._oauth_http import refresh_lock_for
from email_triage.providers.gmail_api import (
    OAUTH_TOKEN_URL,
    GmailApiError,
    GmailAuthError,
)

logger = logging.getLogger("email_triage.providers.gmail_calendar")

CAL_BASE = "https://www.googleapis.com/calendar/v3"


class GoogleCalendarProvider(CalendarProvider):
    """Google Calendar API client.

    Constructed with the same OAuth material as ``GmailApiProvider`` —
    the calendar scope must already be on the refresh token, which the
    ``/accounts/{id}/calendar/enable`` UI flow takes care of.
    """

    def __init__(
        self,
        account: str = "",
        client_id: str = "",
        client_secret: str = "",
        refresh_token: str = "",
        calendar_id: str = "primary",
        timeout: float = 30.0,
    ):
        self._account = account
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._calendar_id = calendar_id
        self._timeout = timeout
        self._access_token: str = ""
        self._access_token_expires_at: float = 0.0
        self._http: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "google_calendar"

    # ------------------------------------------------------------------
    # OAuth — mirrors the Gmail provider's pattern
    # ------------------------------------------------------------------

    async def _refresh_access_token(self) -> str:
        """Same shape as GmailApiProvider._refresh_access_token —
        client_secret is required for both Web and Desktop clients.

        Wrapped in the per-instance refresh lock (#142 / #139) so
        concurrent 401-retry callers don't fire N parallel token
        exchanges at Google. The cached-token re-check inside the
        critical section short-circuits the second through Nth
        caller once the winner has refreshed.
        """
        async with refresh_lock_for(self):
            # Re-check inside the lock — another coroutine that won the
            # race may have already refreshed.
            if (
                self._access_token
                and time.time() < self._access_token_expires_at
            ):
                return self._access_token

            if not self._refresh_token:
                raise GmailAuthError(401, "No refresh token — calendar not enabled")
            if not self._client_id:
                raise GmailAuthError(400, "client_id not configured")
            if not self._client_secret:
                raise GmailAuthError(
                    400,
                    "client_secret not configured — edit the account and re-enter "
                    "the OAuth client secret in the account form",
                )

            data: dict[str, str] = {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
                "grant_type": "refresh_token",
            }

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(OAUTH_TOKEN_URL, data=data)

            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                raise GmailAuthError(resp.status_code, body, OAUTH_TOKEN_URL)

            payload = resp.json()
            token = payload.get("access_token", "")
            if not token:
                raise GmailAuthError(500, "Token response missing access_token", OAUTH_TOKEN_URL)
            expires_in = int(payload.get("expires_in", 3600))
            self._access_token = token
            self._access_token_expires_at = time.time() + expires_in - 60
            return token

    async def _ensure_token(self) -> str:
        if self._access_token and time.time() < self._access_token_expires_at:
            return self._access_token
        return await self._refresh_access_token()

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the long-lived httpx client.

        Wrapped in the per-instance refresh lock (#139 / #142) so two
        concurrent cold-path callers don't both observe ``self._http
        is None`` and each construct their own client — the second
        would overwrite the first and orphan a live connection pool.
        Mirrors :meth:`GmailApiProvider._get_client`.
        """
        if self._http is not None:
            return self._http
        async with refresh_lock_for(self):
            if self._http is None:
                self._http = httpx.AsyncClient(
                    base_url=CAL_BASE, timeout=self._timeout,
                )
            return self._http

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
    ) -> Any:
        client = await self._get_client()
        token = await self._ensure_token()
        for attempt in range(2):
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.request(
                method, path, params=params, json=json_data, headers=headers,
            )
            if resp.status_code == 401 and attempt == 0:
                token = await self._refresh_access_token()
                continue

            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                # Map insufficient-scope errors so the UI can prompt re-auth.
                body_str = (
                    json.dumps(body) if isinstance(body, dict) else str(body)
                ).lower()
                if resp.status_code in (401, 403) and (
                    "insufficient" in body_str
                    or "scope" in body_str
                    or "permission" in body_str
                ):
                    raise CalendarScopeError("google_calendar", str(body))
                raise GmailApiError(resp.status_code, body, path)

            if resp.status_code == 204 or not resp.content:
                return None
            try:
                return resp.json()
            except Exception:
                return resp.text

        raise GmailApiError(401, "Auth failed after refresh", path)

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _parse_endpoint(self, raw: dict[str, Any]) -> tuple[datetime | None, bool]:
        """Return ``(utc_datetime, all_day)`` from a Google start/end dict."""
        if not raw:
            return None, False
        if "dateTime" in raw:
            try:
                dt = datetime.fromisoformat(raw["dateTime"].replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc), False
            except Exception:
                return None, False
        if "date" in raw:
            try:
                d = date.fromisoformat(raw["date"])
                return datetime.combine(d, dt_time.min, tzinfo=timezone.utc), True
            except Exception:
                return None, True
        return None, False

    def _normalise(
        self, raw: dict[str, Any],
        *, calendar_id: str | None = None,
    ) -> CalendarEvent:
        start_dt, all_day_start = self._parse_endpoint(raw.get("start") or {})
        end_dt, _ = self._parse_endpoint(raw.get("end") or {})
        organizer = ""
        org = raw.get("organizer") or {}
        if isinstance(org, dict):
            organizer = org.get("email", "")
        attendees: list[dict[str, Any]] = []
        for a in raw.get("attendees", []) or []:
            if not isinstance(a, dict):
                continue
            attendees.append({
                "email": a.get("email", ""),
                "name": a.get("displayName", ""),
                "response_status": a.get("responseStatus", "needsAction"),
            })
        # When a per-call calendar_id override was used (multi-
        # calendar listing under #105), tag the event with the
        # actual queried calendar id so consumers can group /
        # filter by calendar. Default falls back to the
        # constructor's _calendar_id for legacy single-calendar
        # callers.
        cid_for_event = (
            calendar_id if calendar_id is not None
            else self._calendar_id
        )
        # 2026-05-14 — Google Calendar's "transparency" field marks
        # events as "transparent" (show as free) or "opaque" (block).
        # Default per API spec is "opaque." Contact-derived calendars
        # (birthdays) + reminders typically come back as "transparent."
        # The slot finder skips transparent events so they don't blank
        # out the day for meeting suggestions.
        transparency = (raw.get("transparency") or "opaque").lower()
        return CalendarEvent(
            event_id=raw.get("id", ""),
            calendar_id=cid_for_event,
            summary=raw.get("summary", ""),
            description=raw.get("description", ""),
            location=raw.get("location", ""),
            start=start_dt,
            end=end_dt,
            all_day=all_day_start,
            organizer=organizer,
            attendees=attendees,
            status=raw.get("status", "confirmed"),
            transparency=transparency,
            provider=self.name,
            ical_uid=raw.get("iCalUID", ""),
            raw_metadata={"htmlLink": raw.get("htmlLink", "")},
        )

    # ------------------------------------------------------------------
    # Calendar discovery (calendarList)
    # ------------------------------------------------------------------

    async def list_calendars(self) -> list[dict[str, Any]]:
        """Fetch the OAuth user's full calendarList.

        Returns one dict per visible calendar:

            {
                "id":      "<calendar id, e.g. user@domain or *@group...>",
                "summary": "<display name>",
                "primary": <bool — Google sets True on the user's own primary>,
                "access_role": "<owner|writer|reader|freeBusyReader>",
            }

        ``calendarList`` returns calendars the OAuth user has access
        to — their own + every shared calendar that's been added to
        their list. Read-only feeds (holidays, public calendars) are
        included; the caller's UI logic decides which roles make
        sense for each (e.g. ``self_schedule`` makes no sense for a
        read-only feed; the UI checks ``access_role`` to disable
        write-targeting role checkboxes).

        Pages through ``nextPageToken`` until the listing terminates.
        Calendars on most Google accounts return in one page; the
        loop is defensive against multi-page accounts (typical
        Workspace operators with hundreds of shared resources).
        """
        results: list[dict[str, Any]] = []
        page_token: str | None = None
        # Defensive cap — 50 pages * 250 calendars = 12,500. Above
        # that, something's wrong with the auth.
        for _ in range(50):
            params: dict[str, Any] = {"maxResults": 250}
            if page_token:
                params["pageToken"] = page_token
            data = await self._request(
                "GET", "/users/me/calendarList", params=params,
            ) or {}
            for item in data.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                cid = item.get("id", "")
                if not cid:
                    continue
                results.append({
                    "id": cid,
                    "summary": (
                        item.get("summaryOverride")
                        or item.get("summary")
                        or cid
                    ),
                    "primary": bool(item.get("primary", False)),
                    "access_role": item.get("accessRole", "reader"),
                })
            page_token = data.get("nextPageToken") or None
            if not page_token:
                break
        return results

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def list_events(
        self,
        time_min: datetime,
        time_max: datetime,
        limit: int = 250,
        *,
        calendar_id: str | None = None,
    ) -> list[CalendarEvent]:
        # Per-call override lets multi-calendar consumers (#105
        # ``api`` / ``listings`` roles) iterate the operator's
        # opted-in calendars without instantiating a new provider
        # per ID. Default falls back to the constructor value so
        # legacy single-calendar callers stay unchanged.
        cid = calendar_id or self._calendar_id
        path = f"/calendars/{cid}/events"
        params: dict[str, Any] = {
            "timeMin": time_min.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "timeMax": time_max.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "singleEvents": "true",
            "orderBy": "startTime",
            "maxResults": str(min(limit, 250)),
        }
        out: list[CalendarEvent] = []
        page_token: str | None = None
        while True:
            if page_token:
                params["pageToken"] = page_token
            data = await self._request("GET", path, params=params)
            if not isinstance(data, dict):
                break
            for raw in data.get("items", []) or []:
                if not isinstance(raw, dict):
                    continue
                out.append(self._normalise(raw, calendar_id=cid))
                if len(out) >= limit:
                    return out
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return out

    async def list_ooo(
        self,
        time_min: datetime,
        time_max: datetime,
        *,
        calendar_id: str | None = None,
    ) -> list[CalendarEvent]:
        """Return Google Calendar events flagged as out-of-office.

        Filters server-side via ``eventTypes=outOfOffice``.
        ``calendar_id`` override per #105.
        """
        cid = calendar_id or self._calendar_id
        path = f"/calendars/{cid}/events"
        params: dict[str, Any] = {
            "timeMin": time_min.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "timeMax": time_max.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "singleEvents": "true",
            "orderBy": "startTime",
            "eventTypes": "outOfOffice",
        }
        out: list[CalendarEvent] = []
        page_token: str | None = None
        while True:
            if page_token:
                params["pageToken"] = page_token
            data = await self._request("GET", path, params=params)
            if not isinstance(data, dict):
                break
            for raw in data.get("items", []) or []:
                if isinstance(raw, dict):
                    out.append(self._normalise(raw, calendar_id=cid))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return out

    async def get_event(
        self, event_id: str, *, calendar_id: str | None = None,
    ) -> CalendarEvent:
        cid = calendar_id or self._calendar_id
        data = await self._request(
            "GET", f"/calendars/{cid}/events/{event_id}",
        )
        if not isinstance(data, dict):
            raise GmailApiError(500, f"Unexpected response for {event_id}")
        return self._normalise(data, calendar_id=cid)

    async def get_event_by_uid(
        self, uid: str, *, calendar_id: str | None = None,
    ) -> CalendarEvent | None:
        if not uid:
            return None
        cid = calendar_id or self._calendar_id
        path = f"/calendars/{cid}/events"
        data = await self._request(
            "GET", path, params={"iCalUID": uid, "singleEvents": "true"},
        )
        items = (data or {}).get("items") if isinstance(data, dict) else None
        if not items:
            return None
        return self._normalise(items[0], calendar_id=cid)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def _serialize(self, event: CalendarEvent) -> dict[str, Any]:
        body: dict[str, Any] = {
            "summary": event.summary,
            "description": event.description,
            "location": event.location,
        }
        if event.start:
            if event.all_day:
                body["start"] = {"date": event.start.date().isoformat()}
                body["end"] = {"date": (event.end or event.start).date().isoformat()}
            else:
                body["start"] = {
                    "dateTime": event.start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                }
                if event.end:
                    body["end"] = {
                        "dateTime": event.end.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    }
        if event.attendees:
            body["attendees"] = [
                {"email": a.get("email", "")} for a in event.attendees if a.get("email")
            ]
        return body

    async def create_event(
        self, event: CalendarEvent,
        *, calendar_id: str | None = None,
    ) -> str:
        # Per-call override mirrors list_events / get_event under #105.
        # Self-sent event triage path (#107) writes to the
        # operator-picked self_schedule calendar via this kwarg.
        cid = calendar_id or self._calendar_id
        data = await self._request(
            "POST",
            f"/calendars/{cid}/events",
            json_data=self._serialize(event),
        )
        if isinstance(data, dict):
            return data.get("id", "")
        return ""

    async def update_event(
        self, event_id: str, partial: dict[str, Any],
        *, calendar_id: str | None = None,
    ) -> None:
        cid = calendar_id or self._calendar_id
        await self._request(
            "PATCH",
            f"/calendars/{cid}/events/{event_id}",
            json_data=partial,
        )

    async def delete_event(
        self, event_id: str,
        *, calendar_id: str | None = None,
    ) -> None:
        cid = calendar_id or self._calendar_id
        await self._request(
            "DELETE",
            f"/calendars/{cid}/events/{event_id}",
        )

    async def respond_to_invite(self, event_id: str, response: str) -> None:
        """Update our attendee record on an event.

        Google Calendar doesn't have a dedicated "respond" endpoint —
        we PATCH the event with our attendee entry's responseStatus
        flipped, and ``sendUpdates=externalOnly`` tells Google to
        notify the organizer (and external attendees) but not loop
        the change back to us.
        """
        status_map = {
            "accepted": "accepted",
            "declined": "declined",
            "tentative": "tentative",
        }
        new_status = status_map.get(response.lower())
        if not new_status:
            raise ValueError(f"Unsupported response: {response!r}")
        # Read the event so we can find our attendee row.
        event = await self.get_event(event_id)
        my_email = (self._account or "").lower()
        attendees: list[dict[str, Any]] = []
        found = False
        for a in event.attendees:
            email = (a.get("email") or "").lower()
            if email == my_email:
                attendees.append({
                    "email": a.get("email", ""),
                    "responseStatus": new_status,
                })
                found = True
            else:
                attendees.append({
                    "email": a.get("email", ""),
                    "responseStatus": a.get("response_status", "needsAction"),
                })
        if not found and my_email:
            attendees.append({"email": my_email, "responseStatus": new_status})
        await self._request(
            "PATCH",
            f"/calendars/{self._calendar_id}/events/{event_id}",
            params={"sendUpdates": "externalOnly"},
            json_data={"attendees": attendees},
        )

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
