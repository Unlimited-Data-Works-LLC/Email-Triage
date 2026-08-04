"""Microsoft Graph calendar provider.

Pairs with :class:`email_triage.providers.office365.Office365Provider` —
shares the MSAL token cache file so calendar requests reuse the
mail-side OAuth identity. The ``Calendars.ReadWrite`` scope must
already be on the account's token, which the per-account "Enable
Calendar" device-code flow takes care of.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, time as dt_time, timezone
from typing import Any

import httpx

from email_triage._egress import Intent, egress_async_client
from email_triage._isotime import parse_iso, to_utc_iso_z, to_utc_iso_no_suffix
from email_triage.engine.models import CalendarEvent
from email_triage.providers.calendar_base import (
    CalendarProvider,
    _CalendarHttpMixin,
)
from email_triage.providers.office365 import (
    GRAPH_BASE,
    GraphError,
    Office365Provider,
)

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.providers.office365_calendar")  # N-196b R21_4


def _iana_tz_name(dt: datetime) -> str | None:
    """N-289 R30 — best-effort IANA timezone name for an aware datetime.

    MS Graph accepts IANA names (`America/New_York`) or Windows names
    (`Eastern Standard Time`) for the `timeZone` field. Returns the
    tzinfo's key attribute (Python 3.9+ ZoneInfo carries `.key`), or
    the UTC offset abbreviation as a fallback. Returns None if dt is
    naive (caller must fall back to UTC).
    """
    if dt.tzinfo is None:
        return None
    # ZoneInfo carries `.key`; pytz carries `.zone`; datetime.timezone
    # returns an offset name like `UTC+05:00`.
    for attr in ("key", "zone"):
        val = getattr(dt.tzinfo, attr, None)
        if isinstance(val, str) and val:
            return val
    name = dt.tzname()
    if name and "UTC" in name.upper():
        return "UTC"
    return name or None


class Office365CalendarProvider(_CalendarHttpMixin, CalendarProvider):
    """Graph calendar client.

    Wraps an ``Office365Provider`` for token acquisition — we don't
    re-implement MSAL device flow, we lean on the same MSAL app the
    mail provider uses.

    HTTP plumbing (``_get_client`` / ``_request``) comes from
    :class:`_CalendarHttpMixin`; this class supplies the Graph-specific
    hooks below.
    """

    _scope_error_keywords = (
        "scope", "permission", "privilege", "consent", "accessdenied",
    )
    _provider_label = "office365_calendar"

    def __init__(
        self,
        client_id: str = "",
        tenant_id: str = "common",
        client_secret: str = "",
        # N-202 R22 (2026-07-02): NO DEFAULT — see office365.py::__init__
        # for the full rationale. Shared-singleton path pooled OAuth
        # refresh tokens across accounts (§164.310(d)(2)(i)); now required.
        token_cache_path: str = "",
        username: str = "",
        scopes: list[str] | None = None,
        timeout: float = 30.0,
    ):
        # N-202: fail-closed on missing token_cache_path (see office365.py).
        if not token_cache_path:
            raise ValueError(
                "Office365CalendarProvider: token_cache_path is REQUIRED "
                "(pre-N-202 shared-singleton default). Route through "
                "providers.factory.msal_cache_path_for_account(account_id)."
            )
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
            username=username,
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

    # -- _CalendarHttpMixin hooks --------------------------------------

    async def _build_client(self) -> httpx.AsyncClient:
        # Graph's bearer token is stable for the client's lifetime, so
        # bake it onto the client; _on_unauthorized rotates it in place.
        token = await self._mail.acquire_token()
        return egress_async_client(
            intent=Intent.PROVIDER_API,
            base_url=GRAPH_BASE,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self._timeout,
        )

    async def _on_unauthorized(self, client: httpx.AsyncClient) -> None:
        token = await self._mail.acquire_token()
        client.headers["Authorization"] = f"Bearer {token}"

    def _http_error(self, status: int, body: Any, path: str) -> Exception:
        return GraphError(status, body, path)

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _parse_endpoint(self, raw: dict[str, Any]) -> tuple[datetime | None, bool]:
        if not raw:
            return None, False
        dt_str = raw.get("dateTime")
        is_all_day = False
        if dt_str:
            dt = parse_iso(dt_str)
            if dt is None:
                return None, False
            if dt.tzinfo is None:
                # Graph returns all-day-event endpoints without
                # a timezone offset; treat as UTC midnight. This branch
                # ALSO carries the is_all_day signal — do NOT collapse
                # to parse_iso_aware (which would erase the signal). See
                # trust-audit db-sme verdict on N-357b tranche 4 REJECT.
                dt = dt.replace(tzinfo=timezone.utc)
                is_all_day = True
            return dt.astimezone(timezone.utc), is_all_day
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
            "startDateTime": to_utc_iso_z(time_min),
            "endDateTime": to_utc_iso_z(time_max),
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
            "startDateTime": to_utc_iso_z(time_min),
            "endDateTime": to_utc_iso_z(time_max),
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
        # N-289 R30 (row 65): all-day events must NOT be UTC-anchored.
        # Serialize the LOCAL date-at-midnight with the event's tzinfo
        # name (falling back to UTC if the caller didn't set tz) —
        # otherwise an all-day event renders on the wrong day for
        # viewers in a non-UTC timezone. Timed events keep the UTC
        # normalization.
        if event.all_day:
            if event.start:
                start_local = event.start
                tz_name = _iana_tz_name(start_local) or "UTC"
                body["start"] = {
                    "dateTime": start_local.strftime("%Y-%m-%dT00:00:00"),
                    "timeZone": tz_name,
                }
            if event.end:
                end_local = event.end
                tz_name = _iana_tz_name(end_local) or "UTC"
                body["end"] = {
                    "dateTime": end_local.strftime("%Y-%m-%dT00:00:00"),
                    "timeZone": tz_name,
                }
            body["isAllDay"] = True
        else:
            if event.start:
                body["start"] = {
                    "dateTime": to_utc_iso_no_suffix(event.start),
                    "timeZone": "UTC",
                }
            if event.end:
                body["end"] = {
                    "dateTime": to_utc_iso_no_suffix(event.end),
                    "timeZone": "UTC",
                }
        # "transparent" = show as FREE (doesn't block the day) — used for
        # reminders / deadline markers. Graph's field is showAs; default "opaque"
        # sends nothing (Graph's own default is busy), so existing callers are
        # unaffected.
        if event.transparency == "transparent":
            body["showAs"] = "free"
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
        #. Graph addresses non-default calendars at
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

    async def respond_to_invite(
        self, event_id: str, response: str,
        *, calendar_id: str | None = None,
    ) -> None:
        # Graph routes by global event id; calendar_id is accepted for
        # API symmetry with the other mutation methods but not needed
        # in the path.
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
        # _CalendarHttpMixin.close() drops the httpx client; the
        # mail-side close additionally flushes the MSAL token cache.
        await super().close()
        try:
            await self._mail.close()
        except Exception:
            pass
