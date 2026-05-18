"""Microsoft Graph calendar provider.

Pairs with :class:`email_triage.providers.office365.Office365Provider` —
shares the MSAL token cache file so calendar requests reuse the
mail-side OAuth identity. The ``Calendars.ReadWrite`` scope must
already be on the account's token, which the per-account "Enable
Calendar" device-code flow takes care of.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, time as dt_time, timezone
from typing import Any

import httpx

from email_triage.engine.models import CalendarEvent
from email_triage.providers.calendar_base import (
    CalendarProvider,
    CalendarScopeError,
)
from email_triage.providers.office365 import (
    GRAPH_BASE,
    GraphError,
    Office365Provider,
)

logger = logging.getLogger("email_triage.providers.office365_calendar")


class Office365CalendarProvider(CalendarProvider):
    """Graph calendar client.

    Wraps an ``Office365Provider`` for token acquisition — we don't
    re-implement MSAL device flow, we lean on the same MSAL app the
    mail provider uses.
    """

    def __init__(
        self,
        client_id: str = "",
        tenant_id: str = "common",
        client_secret: str = "",
        token_cache_path: str = "./data/msal_cache.json",
        scopes: list[str] | None = None,
        timeout: float = 30.0,
    ):
        # Reuse the MSAL token-acquire machinery from the mail provider.
        from email_triage.providers.office365 import (
            CALENDAR_SCOPES, DEFAULT_SCOPES,
        )
        scopes = scopes or list(DEFAULT_SCOPES) + list(CALENDAR_SCOPES)
        self._mail = Office365Provider(
            client_id=client_id,
            tenant_id=tenant_id,
            client_secret=client_secret,
            token_cache_path=token_cache_path,
            scopes=scopes,
        )
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "office365_calendar"

    # ------------------------------------------------------------------
    # Auth + HTTP plumbing — mirrors the mail provider's _get_client
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is not None:
            return self._http
        token = await self._mail.acquire_token()
        self._http = httpx.AsyncClient(
            base_url=GRAPH_BASE,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self._timeout,
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
        for attempt in range(2):
            resp = await client.request(
                method, path, params=params, json=json_data,
            )
            if resp.status_code == 401 and attempt == 0:
                # Refresh the token and rebuild the client.
                token = await self._mail.acquire_token()
                client.headers["Authorization"] = f"Bearer {token}"
                continue

            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                body_str = (
                    json.dumps(body) if isinstance(body, dict) else str(body)
                ).lower()
                if resp.status_code in (401, 403) and (
                    "scope" in body_str
                    or "permission" in body_str
                    or "privilege" in body_str
                    or "consent" in body_str
                    or "accessdenied" in body_str
                ):
                    raise CalendarScopeError("office365_calendar", str(body))
                raise GraphError(resp.status_code, body, path)

            if resp.status_code == 204 or not resp.content:
                return None
            try:
                return resp.json()
            except Exception:
                return resp.text

        raise GraphError(401, "Failed after token refresh", path)

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _parse_endpoint(self, raw: dict[str, Any]) -> tuple[datetime | None, bool]:
        if not raw:
            return None, False
        dt_str = raw.get("dateTime")
        is_all_day = False
        if dt_str:
            try:
                dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    # Graph returns all-day-event endpoints without
                    # a timezone offset; treat as UTC midnight.
                    dt = dt.replace(tzinfo=timezone.utc)
                    is_all_day = True
                return dt.astimezone(timezone.utc), is_all_day
            except Exception:
                return None, False
        return None, False

    def _normalise(self, raw: dict[str, Any]) -> CalendarEvent:
        start_dt, _ = self._parse_endpoint(raw.get("start") or {})
        end_dt, _ = self._parse_endpoint(raw.get("end") or {})
        all_day = bool(raw.get("isAllDay", False))
        organizer = ""
        org = raw.get("organizer") or {}
        if isinstance(org, dict):
            ea = org.get("emailAddress") or {}
            organizer = ea.get("address", "")
        attendees: list[dict[str, Any]] = []
        for a in raw.get("attendees", []) or []:
            ea = (a or {}).get("emailAddress") or {}
            status = (a or {}).get("status") or {}
            attendees.append({
                "email": ea.get("address", ""),
                "name": ea.get("name", ""),
                "response_status": status.get("response", "none"),
            })
        # 2026-05-14 — Microsoft Graph's ``showAs`` carries the
        # free/tentative/busy state. Map to the unified
        # ``transparency`` field: "free" => transparent (don't block
        # meeting suggestions); anything else (busy / tentative /
        # workingElsewhere / oof / unknown) => opaque (default block).
        # Same semantic as Google Calendar's transparency field; the
        # slot finder treats transparent events as non-blocking.
        show_as = (raw.get("showAs") or "busy").lower()
        transparency = "transparent" if show_as == "free" else "opaque"
        return CalendarEvent(
            event_id=raw.get("id", ""),
            calendar_id="primary",
            summary=raw.get("subject", ""),
            description=(raw.get("body") or {}).get("content", ""),
            location=(raw.get("location") or {}).get("displayName", ""),
            start=start_dt,
            end=end_dt,
            all_day=all_day,
            organizer=organizer,
            attendees=attendees,
            status="cancelled" if raw.get("isCancelled") else "confirmed",
            transparency=transparency,
            provider=self.name,
            ical_uid=raw.get("iCalUId", ""),
            raw_metadata={"webLink": raw.get("webLink", "")},
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def list_events(
        self,
        time_min: datetime,
        time_max: datetime,
        limit: int = 250,
    ) -> list[CalendarEvent]:
        params = {
            "startDateTime": time_min.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "endDateTime": time_max.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "$top": str(min(limit, 250)),
            "$orderby": "start/dateTime",
        }
        out: list[CalendarEvent] = []
        url = "/me/calendarView"
        while True:
            data = await self._request("GET", url, params=params)
            if not isinstance(data, dict):
                break
            for raw in data.get("value", []) or []:
                if not isinstance(raw, dict):
                    continue
                out.append(self._normalise(raw))
                if len(out) >= limit:
                    return out
            next_link = data.get("@odata.nextLink")
            if not next_link:
                break
            # Graph hands back the full URL; strip the base + reset params.
            url = next_link.replace(GRAPH_BASE, "")
            params = None  # already encoded in next_link
        return out

    async def list_ooo(
        self,
        time_min: datetime,
        time_max: datetime,
    ) -> list[CalendarEvent]:
        """Return Graph events flagged as out-of-office (showAs == 'oof')."""
        params = {
            "startDateTime": time_min.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "endDateTime": time_max.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "$filter": "showAs eq 'oof'",
            "$top": "250",
            "$orderby": "start/dateTime",
        }
        data = await self._request("GET", "/me/calendarView", params=params)
        out: list[CalendarEvent] = []
        if isinstance(data, dict):
            for raw in data.get("value", []) or []:
                if isinstance(raw, dict):
                    out.append(self._normalise(raw))
        return out

    async def get_event(self, event_id: str) -> CalendarEvent:
        data = await self._request("GET", f"/me/events/{event_id}")
        if not isinstance(data, dict):
            raise GraphError(500, f"Unexpected response for {event_id}")
        return self._normalise(data)

    async def get_event_by_uid(self, uid: str) -> CalendarEvent | None:
        if not uid:
            return None
        # Graph spells it iCalUId.
        data = await self._request(
            "GET", "/me/events",
            params={"$filter": f"iCalUId eq '{uid}'", "$top": "1"},
        )
        items = (data or {}).get("value") if isinstance(data, dict) else None
        if not items:
            return None
        return self._normalise(items[0])

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def _serialize(self, event: CalendarEvent) -> dict[str, Any]:
        body: dict[str, Any] = {
            "subject": event.summary,
            "body": {"contentType": "text", "content": event.description},
        }
        if event.location:
            body["location"] = {"displayName": event.location}
        if event.start:
            body["start"] = {
                "dateTime": event.start.astimezone(timezone.utc).isoformat().replace("+00:00", ""),
                "timeZone": "UTC",
            }
        if event.end:
            body["end"] = {
                "dateTime": event.end.astimezone(timezone.utc).isoformat().replace("+00:00", ""),
                "timeZone": "UTC",
            }
        if event.all_day:
            body["isAllDay"] = True
        if event.attendees:
            body["attendees"] = [
                {
                    "emailAddress": {"address": a.get("email", "")},
                    "type": "required",
                }
                for a in event.attendees
                if a.get("email")
            ]
        return body

    async def create_event(
        self, event: CalendarEvent,
        *, calendar_id: str | None = None,
    ) -> str:
        # Per-call override for the self-sent event triage path
        # (#107). Graph addresses non-default calendars at
        # ``/me/calendars/{id}/events``; default (no calendar_id)
        # posts to ``/me/events`` which targets the operator's
        # default calendar.
        if calendar_id and calendar_id not in ("primary", ""):
            path = f"/me/calendars/{calendar_id}/events"
        else:
            path = "/me/events"
        data = await self._request("POST", path, json_data=self._serialize(event))
        if isinstance(data, dict):
            return data.get("id", "")
        return ""

    async def update_event(
        self, event_id: str, partial: dict[str, Any],
        *, calendar_id: str | None = None,
    ) -> None:
        # Graph routes by event id; calendar_id accepted for
        # API symmetry but not required (event ids are global).
        await self._request("PATCH", f"/me/events/{event_id}", json_data=partial)

    async def delete_event(
        self, event_id: str,
        *, calendar_id: str | None = None,
    ) -> None:
        await self._request("DELETE", f"/me/events/{event_id}")

    async def respond_to_invite(self, event_id: str, response: str) -> None:
        verb_map = {
            "accepted": "accept",
            "declined": "decline",
            "tentative": "tentativelyAccept",
        }
        verb = verb_map.get(response.lower())
        if not verb:
            raise ValueError(f"Unsupported response: {response!r}")
        await self._request(
            "POST",
            f"/me/events/{event_id}/{verb}",
            json_data={"sendResponse": True},
        )

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        # Mail-side close handles the cache flush.
        try:
            await self._mail.close()
        except Exception:
            pass
