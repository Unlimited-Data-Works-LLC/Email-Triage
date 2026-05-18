"""OpenClaw-agent-facing JSON API.

Bearer-token authenticated. Sibling to ``/api/*`` so the HIPAA hard-off
and rate-limit policy that's specific to agent-driven access lives in
one file.

Every endpoint that targets a single account routes through
:func:`_require_openclaw_account` which:

1. Resolves the user from the bearer token (or session cookie — the
   underlying ``get_current_user`` accepts both, but in practice this
   is a token-only surface).
2. Verifies ownership (or admin).
3. **Refuses HIPAA-flagged accounts with 403.** PHI never leaves via
   this path.
4. Enforces a per-key token-bucket rate limit.
"""

from __future__ import annotations

import html.parser
import json
import re
import unicodedata
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from email_triage.triage_logging import get_logger, is_account_hipaa
from email_triage.web.dependencies import get_current_user
from email_triage.web.ratelimit import enforce_rate_limit
from email_triage._errfmt import fmt_exc

log = get_logger("web.routers.openclaw")

router = APIRouter(prefix="/api/openclaw", tags=["openclaw"])


# ---------------------------------------------------------------------------
# Auth + HIPAA gate
# ---------------------------------------------------------------------------

async def _require_user(request: Request) -> dict:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Rate-limit by API-key id when present, falling back to user id.
    rate_key = user.get("api_key_id") or f"user:{user['id']}"
    await enforce_rate_limit(request, rate_key)
    return user


def _scope_to_user(db, user: dict, acct: dict | None) -> bool:
    """OpenClaw-specific account scope: True iff ``user`` is the owner
    OR a registered delegate. Admin role does NOT bypass -- agent
    tokens carry operator intent, not role privilege. Cross-user
    visibility stays in the web UI.
    """
    if not user or not acct:
        return False
    if acct.get("user_id") == user.get("id"):
        return True
    from email_triage.web.db import is_account_delegate
    return is_account_delegate(db, acct["id"], user["id"])


async def _require_openclaw_account(
    request: Request, account_id: int,
) -> tuple[dict, dict]:
    """Resolve user + account, enforcing ownership and HIPAA hard-off."""
    user = await _require_user(request)
    db = request.app.state.db
    from email_triage.web.db import get_email_account

    acct = get_email_account(db, account_id)
    if acct is None:
        raise HTTPException(status_code=404, detail="account_not_found")
    if not _scope_to_user(db, user, acct):
        raise HTTPException(status_code=403, detail="not_owner")
    if is_account_hipaa(acct):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "hipaa_blocked",
                "message": "OpenClaw cannot access HIPAA-flagged accounts",
            },
        )
    return user, acct


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class TriageRequest(BaseModel):
    query: str = "is:unread"
    limit: int = 5


class LabelRequest(BaseModel):
    label: str


class MoveRequest(BaseModel):
    folder: str


class DraftRequest(BaseModel):
    to: list[str]
    subject: str
    body: str
    in_reply_to: str | None = None
    thread_id: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
async def openclaw_health(request: Request):
    """Install-wide health snapshot for agent / monitoring callers.

    Admin-token only. Returns the same payload as ``/health/detail``
    (operator-facing detail: tasks block, ingestion counts, watchers,
    audit_failures, csrf_rejects, schema_version, version) but
    accepts a bearer token instead of a session cookie -- so an
    agent caller, Nagios, or any other unattended client can
    scrape it without going through the web-UI auth flow.

    Returns 503 (with the body) when degraded; same status-code
    semantics as /health and /health/detail. Non-admin tokens get
    403; this endpoint is intentionally NOT scoped per-user (the
    payload is install-level operational state, not per-account).
    """
    user = await _require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="admin role required for install-wide health",
        )
    from email_triage.web.routers.health import _compute_health_detail
    body, degraded = await _compute_health_detail(request)
    if degraded:
        from fastapi.responses import JSONResponse
        return JSONResponse(body, status_code=503)
    return body


@router.get("/accounts")
async def list_accounts(request: Request):
    user = await _require_user(request)
    db = request.app.state.db
    from email_triage.web.db import list_email_accounts
    from email_triage.web.events import get_openclaw_quiet_settings
    # Strict per-user scope. ``list_email_accounts(user_id=...)``
    # returns owner + delegate rows. Admin role does NOT bypass --
    # OpenClaw token represents operator intent, not role privilege.
    accts = list_email_accounts(db, user_id=user["id"])
    out = []
    for acct in accts:
        if is_account_hipaa(acct):
            continue
        out.append({
            "id": acct["id"],
            "name": acct["name"],
            "provider_type": acct["provider_type"],
            "is_active": bool(acct.get("is_active", True)),
            "quiet_hours": get_openclaw_quiet_settings(db, acct["id"]),
        })
    return {"accounts": out}


@router.get("/accounts/{account_id}/messages")
async def list_messages(
    request: Request,
    account_id: int,
    q: str = Query("is:unread"),
    limit: int = Query(20, ge=1, le=100),
):
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)
    try:
        ids = await provider.search(q, limit)
    except Exception as e:
        try:
            await provider.close()
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=f"provider_error: {e}")
    try:
        await provider.close()
    except Exception:
        pass
    return {"account_id": account_id, "query": q, "message_ids": ids}


@router.get("/accounts/{account_id}/messages/{message_id}")
async def get_message(request: Request, account_id: int, message_id: str):
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            msg = await provider.fetch_message(message_id)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
    finally:
        try:
            await provider.close()
        except Exception:
            pass
    return {
        "message_id": msg.message_id,
        "thread_id": msg.thread_id,
        "sender": msg.sender,
        "recipients": msg.recipients,
        "subject": msg.subject,
        "body_text": msg.body_text,
        "date": msg.date.isoformat() if msg.date else None,
        "labels": msg.labels,
        "headers": msg.headers,
    }


@router.post("/accounts/{account_id}/triage")
async def run_account_triage(
    request: Request, account_id: int, body: TriageRequest = Body(...),
):
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    config = request.app.state.config
    secrets = request.app.state.secrets

    from email_triage.web.triage_runner import run_triage
    from email_triage.web.events import fire_triage_completed

    run = await run_triage(
        db, config, secrets, acct,
        query=body.query, limit=body.limit,
        actor_user_id=user["id"], trigger="api",
    )

    if run.get("error"):
        raise HTTPException(
            status_code=503,
            detail={"error": run["error"], "messages": run["errors"]},
        )

    # Best-effort outbound webhook emit.
    dispatcher = getattr(request.app.state, "event_dispatcher", None)
    if dispatcher is not None:
        try:
            await fire_triage_completed(
                dispatcher, db, config, acct, run, trigger="api",
            )
        except Exception as e:
            log.warning("triage.completed dispatch failed", error=fmt_exc(e))

    return {
        "run_id": run["run_id"],
        "account_id": run["account_id"],
        "account_name": run["account_name"],
        "query": run["query"],
        "total_messages": run["total_messages"],
        "results": run["results"],
        "errors": run["errors"],
        "elapsed_secs": run["elapsed_secs"],
        "trigger": "api",
    }


async def _provider_op(
    request: Request, account_id: int, message_id: str, op,
):
    """Helper: open provider, run an async closure, close cleanly."""
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            return await op(provider)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
    finally:
        try:
            await provider.close()
        except Exception:
            pass


@router.post("/accounts/{account_id}/messages/{message_id}/label")
async def apply_label(
    request: Request, account_id: int, message_id: str,
    body: LabelRequest = Body(...),
):
    async def _op(provider):
        await provider.apply_label(message_id, body.label)
        return {"status": "ok", "label": body.label, "message_id": message_id}
    return await _provider_op(request, account_id, message_id, _op)


@router.post("/accounts/{account_id}/messages/{message_id}/move")
async def move_message(
    request: Request, account_id: int, message_id: str,
    body: MoveRequest = Body(...),
):
    async def _op(provider):
        await provider.move_message(message_id, body.folder)
        return {"status": "ok", "folder": body.folder, "message_id": message_id}
    return await _provider_op(request, account_id, message_id, _op)


@router.post("/accounts/{account_id}/messages/{message_id}/archive")
async def archive_message(
    request: Request, account_id: int, message_id: str,
):
    async def _op(provider):
        await provider.archive(message_id)
        return {"status": "ok", "message_id": message_id}
    return await _provider_op(request, account_id, message_id, _op)


@router.post("/accounts/{account_id}/messages/{message_id}/draft")
async def create_draft(
    request: Request, account_id: int, message_id: str,
    body: DraftRequest = Body(...),
):
    async def _op(provider):
        # message_id is currently informational — providers don't need
        # the original to build a draft, but we keep it in the path so
        # OpenClaw's URL semantics line up with the rest of the surface.
        draft_id = await provider.create_draft(
            body.to, body.subject, body.body,
            in_reply_to=body.in_reply_to,
            thread_id=body.thread_id,
        )
        return {"status": "ok", "draft_id": draft_id}
    return await _provider_op(request, account_id, message_id, _op)


@router.get("/runs")
async def list_runs(
    request: Request,
    account_id: int | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    user = await _require_user(request)
    db = request.app.state.db
    from email_triage.web.db import list_triage_runs, get_email_account

    rows = list_triage_runs(db, account_id=account_id, limit=limit)
    out = []
    for r in rows:
        acct = get_email_account(db, r["account_id"])
        # Hide HIPAA-flagged accounts and other users' accounts.
        # Strict scope: admin role does NOT bypass.
        if acct is None:
            continue
        if not _scope_to_user(db, user, acct):
            continue
        if is_account_hipaa(acct):
            continue
        out.append({
            "id": r["id"],
            "account_id": r["account_id"],
            "account_name": r.get("account_name", ""),
            "query": r.get("query", ""),
            "total_messages": r.get("total_messages", 0),
            "elapsed_secs": r.get("elapsed_secs"),
            "started_at": r.get("started_at"),
        })
    return {"runs": out}


@router.put("/accounts/{account_id}/quiet-hours")
async def set_quiet_hours(
    request: Request, account_id: int, body: dict = Body(...),
):
    """Configure the per-account OpenClaw webhook gate.

    Body: ``{"enabled": bool?, "paused": bool?, "start_utc": "HH:MM"?, "end_utc": "HH:MM"?}``.
    Missing fields are left at their previous value.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    from email_triage.web.db import get_setting, set_setting
    from email_triage.web.settings_keys import openclaw_quiet
    current = get_setting(db, openclaw_quiet(account_id)) or {}
    for key in ("enabled", "paused", "start_utc", "end_utc"):
        if key in body:
            current[key] = body[key]
    set_setting(db, openclaw_quiet(account_id), current)
    return {"status": "ok", "settings": current}


# ---------------------------------------------------------------------------
# Calendar endpoints (HIPAA-blocked via _require_openclaw_account)
# ---------------------------------------------------------------------------

class CalendarEventBody(BaseModel):
    summary: str
    description: str = ""
    location: str = ""
    start: str  # ISO 8601
    end: str    # ISO 8601
    all_day: bool = False
    attendees: list[dict[str, Any]] = []


class RespondBody(BaseModel):
    response: str  # accepted | declined | tentative


# Default timezone for accounts that haven't set one explicitly.
# Backfill migration v6 stamps this on every existing row, but the
# helper still falls back here for the in-memory belt-and-braces
# case (test fixtures, partially-migrated rows).
_DEFAULT_ACCOUNT_TZ = "America/Detroit"


def _resolve_account_tz(acct: dict | None) -> str:
    """Return the IANA tz string the account renders calendar
    events in. Falls back to the install default; never returns
    UTC implicitly (per punch-list #109 — UTC times must not leak
    to human consumers)."""
    if not acct:
        return _DEFAULT_ACCOUNT_TZ
    cfg = acct.get("config") or {}
    tz = (cfg.get("tz") or "").strip() if isinstance(cfg, dict) else ""
    return tz or _DEFAULT_ACCOUNT_TZ


def _format_local_time(dt) -> str:
    """12-hour AM/PM with no leading zero on the hour, uppercase
    AM/PM, space separator. Midnight = ``12:00 AM``, noon = ``12:00 PM``.
    Format chosen to match the operator-side render template so the
    LLM does pure string substitution. Implemented manually because
    ``%-I`` (no-pad hour) is platform-dependent (works on glibc, not
    on Windows)."""
    hour_24 = dt.hour
    minute = dt.minute
    period = "AM" if hour_24 < 12 else "PM"
    hour_12 = hour_24 % 12
    if hour_12 == 0:
        hour_12 = 12
    return f"{hour_12}:{minute:02d} {period}"


def _local_render_fields(ev, acct: dict | None) -> dict[str, Any]:
    """Compute the per-event local-tz render fields documented in
    punch-list #109. Returns a dict with all nine new keys; on any
    failure (missing zone, unknown IANA name, naive datetimes that
    can't be localised) returns the same keys with ``None`` values
    so consumers can still substitute without KeyErrors."""
    from datetime import timezone as _tz
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:  # pragma: no cover — stdlib since 3.9
        return {
            "start_local": None, "end_local": None,
            "start_local_date": None, "start_local_weekday": None,
            "start_local_time": None, "end_local_time": None,
            "all_day_local_label": None,
            "tz": _resolve_account_tz(acct), "tz_abbrev": None,
        }

    tz_name = _resolve_account_tz(acct)
    try:
        zone = ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        zone = ZoneInfo(_DEFAULT_ACCOUNT_TZ)
        tz_name = _DEFAULT_ACCOUNT_TZ

    start = getattr(ev, "start", None)
    end = getattr(ev, "end", None)
    all_day = bool(getattr(ev, "all_day", False))

    def _to_local(dt):
        if dt is None:
            return None
        # Naive datetimes from upstream providers → assume UTC.
        # Calendar events always carry an offset in practice, but
        # belt-and-braces.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz.utc)
        return dt.astimezone(zone)

    s_loc = _to_local(start)
    e_loc = _to_local(end)

    if all_day:
        # Per spec: time fields null, label literal "All day".
        return {
            "start_local": s_loc.isoformat() if s_loc else None,
            "end_local": e_loc.isoformat() if e_loc else None,
            "start_local_date": (
                s_loc.strftime("%Y-%m-%d") if s_loc else None
            ),
            "start_local_weekday": (
                s_loc.strftime("%A") if s_loc else None
            ),
            "start_local_time": None,
            "end_local_time": None,
            "all_day_local_label": "All day",
            "tz": tz_name,
            "tz_abbrev": s_loc.strftime("%Z") if s_loc else None,
        }

    return {
        "start_local": s_loc.isoformat() if s_loc else None,
        "end_local": e_loc.isoformat() if e_loc else None,
        "start_local_date": (
            s_loc.strftime("%Y-%m-%d") if s_loc else None
        ),
        "start_local_weekday": (
            s_loc.strftime("%A") if s_loc else None
        ),
        "start_local_time": _format_local_time(s_loc) if s_loc else None,
        "end_local_time": _format_local_time(e_loc) if e_loc else None,
        "all_day_local_label": None,
        "tz": tz_name,
        "tz_abbrev": s_loc.strftime("%Z") if s_loc else None,
    }


def _serialize_event(ev, acct: dict | None = None) -> dict[str, Any]:
    """Serialise a CalendarEvent for the openclaw API.

    The ``acct`` argument is the email_accounts row whose timezone
    the local-render fields are computed against. Optional for
    legacy callers (existing UTC ``start`` / ``end`` fields are
    unaffected by its absence; the new ``*_local*`` fields fall
    back to the install default tz when ``acct`` is None)."""
    payload = {
        "event_id": ev.event_id,
        "calendar_id": ev.calendar_id,
        "summary": ev.summary,
        "description": ev.description,
        "location": ev.location,
        "start": ev.start.isoformat() if ev.start else None,
        "end": ev.end.isoformat() if ev.end else None,
        "all_day": ev.all_day,
        "organizer": ev.organizer,
        "attendees": ev.attendees,
        "status": ev.status,
        "ical_uid": ev.ical_uid,
    }
    payload.update(_local_render_fields(ev, acct))
    return payload


async def _open_calendar(request: Request, acct: dict):
    """Resolve a CalendarProvider for ``acct`` or raise 400.

    When the account has a calendar surrogate configured, the
    surrogate's ``calendar_enabled`` flag governs — otherwise an
    IMAP-with-surrogate account can never pass this gate even
    after the operator wires it up.
    """
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.web.db import is_calendar_enabled
    db = request.app.state.db
    secrets = request.app.state.secrets
    # Resolve which account's enablement flag actually applies:
    # the surrogate's if one is set + valid, otherwise the
    # account's own.
    surrogate = resolve_surrogate_account(db, acct)
    flag_acct_id = (surrogate or acct)["id"]
    if not is_calendar_enabled(db, flag_acct_id):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "calendar_not_enabled",
                "message": (
                    "Enable Calendar on the surrogate account "
                    "from the Accounts page first."
                    if surrogate else
                    "Enable Calendar on this account from the "
                    "Accounts page first."
                ),
            },
        )
    from email_triage.web.routers.ui import _create_calendar_provider_from_account
    # Pass db so the surrogate-account path resolves on IMAP
    # accounts (#105 phase 1A++).
    cal = _create_calendar_provider_from_account(acct, secrets, db=db)
    if cal is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "calendar_not_supported",
                "message": "Provider type does not have a calendar implementation.",
            },
        )
    return cal


async def _calendar_op(request: Request, account_id: int, op):
    """Helper: open calendar provider, run async closure, close cleanly.

    The closure receives ``(cal, acct)`` so consumers can read
    per-account calendar role assignments (#105) — e.g. iterate
    the calendars the operator opted into for the ``api`` role
    rather than always querying the implicit primary.
    """
    from email_triage.providers.calendar_base import CalendarScopeError
    user, acct = await _require_openclaw_account(request, account_id)
    cal = await _open_calendar(request, acct)
    try:
        try:
            return await op(cal, acct)
        except CalendarScopeError as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "calendar_scope_missing",
                    "message": str(e),
                },
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=f"calendar_provider_error: {e}",
            )
    finally:
        try:
            await cal.close()
        except Exception:
            pass


@router.get("/accounts/{account_id}/calendar/events")
async def calendar_list(
    request: Request, account_id: int,
    time_min: str = Query(..., description="ISO 8601 UTC"),
    time_max: str = Query(..., description="ISO 8601 UTC"),
    limit: int = Query(50, ge=1, le=250),
):
    from datetime import datetime
    try:
        tmin = datetime.fromisoformat(time_min.replace("Z", "+00:00"))
        tmax = datetime.fromisoformat(time_max.replace("Z", "+00:00"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"bad_iso_datetime: {e}")

    async def _op(cal, acct):
        # Iterate the calendars the operator opted into for the
        # ``api`` role. Empty list => fall back to the surrogate's
        # role list when a surrogate is configured (operator who
        # set roles on the surrogate shouldn't also have to mirror
        # them on every consumer account that surrogates to it).
        # Still empty after that => legacy account; use the
        # provider's implicit primary calendar.
        from email_triage.web.calendars import (
            calendars_with_role, resolve_surrogate_account,
        )

        # Determine which account holds the canonical role +
        # display-name data: the surrogate when one is set, else
        # the consumer itself.
        db = request.app.state.db
        role_acct = (
            resolve_surrogate_account(db, acct) or acct
        )

        # Build an id -> display-name map so events can carry a
        # human-readable calendar_summary alongside the calendar_id.
        # Operator's display_name override wins (lets a calendar
        # named "user@gmail.com" — Google's convention for the
        # primary calendar — render as something friendlier).
        # Falls back to the discovered summary, then the id.
        from email_triage.web.calendars import calendar_display_label
        _cal_summary: dict[str, str] = {}
        for c in (role_acct.get("config") or {}).get("calendars") or []:
            if isinstance(c, dict):
                cid = str(c.get("id") or "")
                if cid:
                    _cal_summary[cid] = calendar_display_label(c)

        cal_ids = calendars_with_role(role_acct, "api")
        if cal_ids:
            collected = []
            for cid in cal_ids:
                try:
                    chunk = await cal.list_events(
                        tmin, tmax, limit=limit, calendar_id=cid,
                    )
                except Exception as e:
                    # One calendar failing (deleted, scope
                    # missing for this id) shouldn't take down
                    # the whole listing — log + skip.
                    import logging
                    logging.getLogger(__name__).warning(
                        "calendar_list per-id failed: id=%s err=%s",
                        cid, e,
                    )
                    continue
                collected.extend(chunk)
            # Dedupe by event identity. Operators often opt into
            # multiple calendars that share events (Google's
            # "Family" + "Birthdays" pulling from the same source,
            # invitee-on-multiple-calendars cases). Without dedup
            # the same event renders once per calendar it appears
            # on.
            #
            # Three-tier match — the strongest available wins:
            #   1. ical_uid (cross-calendar stable when both ends
            #      are Google + the event was originally invited
            #      OR cross-account-shared)
            #   2. event_id (same-calendar replay protection)
            #   3. (start_iso, end_iso, summary) — catches the case
            #      where the operator has the SAME event copied to
            #      two calendars manually (no shared ical_uid;
            #      different event_ids; same title + time block).
            #      Common when a shared event ("Soccer practice Mon")
            #      lives on two operators' calendars via separate
            #      copies — distinct ical_uid + id.
            seen_uid: set[str] = set()
            seen_eid: set[str] = set()
            seen_tuple: set[tuple[str, str, str]] = set()
            deduped: list = []
            for ev in collected:
                uid = getattr(ev, "ical_uid", "") or ""
                eid = getattr(ev, "event_id", "") or ""
                start = getattr(ev, "start", None)
                end = getattr(ev, "end", None)
                summary = getattr(ev, "summary", "") or ""
                tup = (
                    start.isoformat() if start else "",
                    end.isoformat() if end else "",
                    summary.strip(),
                )
                if uid and uid in seen_uid:
                    continue
                if eid and eid in seen_eid:
                    continue
                # Tuple dedup only when summary is non-empty —
                # otherwise back-to-back nameless slots collapse
                # into one (the all-day "(no title)" case).
                if summary.strip() and tup in seen_tuple:
                    continue
                if uid:
                    seen_uid.add(uid)
                if eid:
                    seen_eid.add(eid)
                if summary.strip():
                    seen_tuple.add(tup)
                deduped.append(ev)
            # Sort by start ascending; respect overall limit.
            deduped.sort(
                key=lambda ev: (
                    ev.start.isoformat()
                    if getattr(ev, "start", None) else ""
                ),
            )
            events = deduped[:limit]
        else:
            events = await cal.list_events(tmin, tmax, limit=limit)

        # Enrich each event with the calendar's display name so
        # the assistant has a readable label without a separate
        # calendarList round-trip.
        out = []
        for ev in events:
            payload = _serialize_event(ev, acct)
            cid = payload.get("calendar_id") or ""
            payload["calendar_summary"] = _cal_summary.get(cid, "")
            out.append(payload)
        return {"events": out}
    return await _calendar_op(request, account_id, _op)


@router.get("/accounts/{account_id}/calendar/events/{event_id}")
async def calendar_get(
    request: Request, account_id: int, event_id: str,
):
    async def _op(cal, _acct):
        ev = await cal.get_event(event_id)
        return _serialize_event(ev, _acct)
    return await _calendar_op(request, account_id, _op)


@router.post("/accounts/{account_id}/calendar/events")
async def calendar_create(
    request: Request, account_id: int, body: CalendarEventBody = Body(...),
):
    from datetime import datetime
    from email_triage.engine.models import CalendarEvent
    try:
        start = datetime.fromisoformat(body.start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(body.end.replace("Z", "+00:00"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"bad_iso_datetime: {e}")
    ev = CalendarEvent(
        event_id="",
        summary=body.summary,
        description=body.description,
        location=body.location,
        start=start,
        end=end,
        all_day=body.all_day,
        attendees=body.attendees or [],
    )

    async def _op(cal, _acct):
        new_id = await cal.create_event(ev)
        return {"status": "ok", "event_id": new_id}
    return await _calendar_op(request, account_id, _op)


@router.patch("/accounts/{account_id}/calendar/events/{event_id}")
async def calendar_update(
    request: Request, account_id: int, event_id: str,
    body: dict = Body(...),
):
    if not isinstance(body, dict) or not body:
        raise HTTPException(status_code=400, detail="empty_partial")

    async def _op(cal, _acct):
        await cal.update_event(event_id, body)
        return {"status": "ok"}
    return await _calendar_op(request, account_id, _op)


@router.delete("/accounts/{account_id}/calendar/events/{event_id}")
async def calendar_delete(
    request: Request, account_id: int, event_id: str,
):
    async def _op(cal, _acct):
        await cal.delete_event(event_id)
        return {"status": "ok"}
    return await _calendar_op(request, account_id, _op)


@router.post("/accounts/{account_id}/calendar/events/{event_id}/respond")
async def calendar_respond(
    request: Request, account_id: int, event_id: str,
    body: RespondBody = Body(...),
):
    if body.response.lower() not in ("accepted", "declined", "tentative"):
        raise HTTPException(
            status_code=400,
            detail="response must be one of: accepted, declined, tentative",
        )

    async def _op(cal, _acct):
        await cal.respond_to_invite(event_id, body.response.lower())
        return {"status": "ok", "response": body.response.lower()}
    return await _calendar_op(request, account_id, _op)


# ---------------------------------------------------------------------------
# Bulk mail operations + structured search (Phase 5)
# ---------------------------------------------------------------------------

class BulkOperationBody(BaseModel):
    operation: str
    args: dict[str, Any] = {}
    message_ids: list[str] | None = None
    filter: dict[str, Any] | None = None
    limit: int = 50


def _bulk_max(request: Request) -> int:
    config = getattr(request.app.state, "config", None)
    if config is None:
        return 100
    return int(getattr(config.push, "bulk_max_batch_size", 100) or 0)


@router.get("/accounts/{account_id}/mail/search")
async def mail_search(
    request: Request, account_id: int,
    unread: bool | None = Query(None),
    label: str | None = Query(None),
    folder: str | None = Query(None),
    from_addr: str | None = Query(None, alias="from"),
    to_addr: str | None = Query(None, alias="to"),
    subject: str | None = Query(None),
    after: str | None = Query(None),
    before: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(20, ge=1, le=250),
):
    """Structured mail search.

    Each filter field is optional; combine freely. ``q`` is an
    optional raw provider-syntax string appended to the structured
    filter when present (Gmail) or used as the fallback when no
    structured field is set (IMAP / Graph).
    """
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    filter_dict = {
        "unread": unread, "label": label, "folder": folder,
        "from": from_addr, "to": to_addr, "subject": subject,
        "after": after, "before": before,
    }
    mfilter = MailFilter.from_dict(
        {k: v for k, v in filter_dict.items() if v is not None}
    )

    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            ids = await provider.search(q or "", limit, filter=mfilter)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "message_ids": ids,
        "limit": limit,
        "used_filter": mfilter.to_dict(),
    }


# ---------------------------------------------------------------------------
# Bulk namespace migration (item #31)
#
# Originally the bulk-write endpoints lived under ``/mail/bulk`` and
# ``/calendar/bulk-respond`` while the bulk-read endpoints were minted
# under a tidier ``/bulk/*`` prefix. Callers (skill script, external
# integrations) now see two inconsistent layouts.
#
# Phase 1 + 2 (this commit): expose canonical ``/bulk/mail/write`` and
# ``/bulk/calendar/respond`` as aliases for the legacy paths. Both paths
# resolve to the same handler. Legacy paths additionally stamp
# ``Deprecated`` / ``Sunset`` / ``Link`` response headers so clients can
# migrate on their own schedule.
#
# Phase 3 (not now): drop legacy paths after the sunset date
# (2027-01-01). Until then BOTH continue to work.
# ---------------------------------------------------------------------------

_BULK_SUNSET = "2027-01-01"

_LEGACY_SUCCESSOR = {
    "mail/bulk": "bulk/mail/write",
    "calendar/bulk-respond": "bulk/calendar/respond",
}


def _stamp_deprecated(
    response: Response, request: Request, account_id: int, legacy_tail: str,
) -> None:
    """Mark a legacy-path response with standard deprecation metadata.

    RFC 8594 (``Sunset``) + RFC 9745 (``Deprecation``) — successor-version
    link points at the canonical equivalent. Callers still get the real
    response body; only headers change. No-op for the canonical path.
    """
    successor = _LEGACY_SUCCESSOR[legacy_tail]
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = _BULK_SUNSET
    response.headers["Link"] = (
        f'</api/openclaw/accounts/{account_id}/{successor}>; '
        'rel="successor-version"'
    )


def _is_legacy_path(request: Request, legacy_tail: str) -> bool:
    """True iff this request came in on the legacy URL.

    We rely on the request path rather than a route flag because FastAPI
    dispatches stacked ``@router.post(...)`` decorators through the same
    handler without telling us which decorator matched.
    """
    return request.url.path.endswith("/" + legacy_tail)


@router.post("/accounts/{account_id}/mail/bulk")
@router.post("/accounts/{account_id}/bulk/mail/write")
async def mail_bulk(
    request: Request,
    response: Response,
    account_id: int,
    body: BulkOperationBody = Body(...),
):
    """Apply one operation across many messages; per-item results.

    Provide either ``message_ids`` (explicit) or ``filter`` (which the
    server resolves into ids via search, capped by ``limit``). Sending
    both is 400.

    Canonical path: ``/accounts/{id}/bulk/mail/write``. Legacy
    ``/accounts/{id}/mail/bulk`` continues to work but responses carry
    ``Deprecation`` / ``Sunset`` headers pointing at the canonical path.
    """
    if _is_legacy_path(request, "mail/bulk"):
        _stamp_deprecated(response, request, account_id, "mail/bulk")
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets

    from email_triage.web.bulk import bulk_apply, validate_operation
    err = validate_operation(body.operation, body.args)
    if err:
        raise HTTPException(status_code=400, detail=err)

    if body.message_ids and body.filter:
        raise HTTPException(
            status_code=400,
            detail="provide either message_ids OR filter, not both",
        )
    if not body.message_ids and not body.filter:
        raise HTTPException(
            status_code=400,
            detail="message_ids or filter required",
        )

    cap = _bulk_max(request)
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    provider = _create_provider_from_account(acct, secrets)
    try:
        ids = body.message_ids or []
        if body.filter is not None:
            mfilter = MailFilter.from_dict(body.filter)
            try:
                ids = await provider.search(
                    "", min(body.limit, cap or body.limit), filter=mfilter,
                )
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"provider_error: {e}")

        if cap and len(ids) > cap:
            raise HTTPException(
                status_code=400,
                detail=f"batch_too_large: {len(ids)} > cap {cap}",
            )

        result = await bulk_apply(
            provider, body.operation, body.args or {}, ids,
        )
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return result.to_dict()


# ---------------------------------------------------------------------------
# Bulk reads — mail (list-with-summaries / fetch-by-ids / list-with-bodies)
# and calendar (fetch-by-ids).
#
# All four sit under /accounts/{id}/bulk/* and are bounded by
# push.bulk_max_batch_size like the other bulk endpoints. Per-item
# failures don't abort the whole call — agents need predictable
# semantics when one of N message_ids has been deleted out from
# under them.
# ---------------------------------------------------------------------------

_SNIPPET_LEN = 200

# Cheap heuristic for "is this body HTML?" — provider-agnostic since
# the EmailMessage abstraction collapses HTML and plain into a single
# body_text field. Avoids running the parser on plain emails (most
# transactional + newsletter mail is HTML; person-to-person mail is
# usually plain).
_HTML_HINTS = ("<html", "<body", "<!doctype", "<head", "<div", "<table", "<p>")


class _HTMLStripper(html.parser.HTMLParser):
    """Collect raw text from an HTML body with tags stripped, entities
    decoded, and structure preserved via newlines on block elements.

    Note: ``<script>`` / ``<style>`` blocks are NOT handled here — they
    must be regex-stripped from the input *before* feeding the parser.
    Real-world HTML emails frequently have unbalanced tags inside those
    blocks (extra ``</script>`` from MSO conditionals, mid-string ``<``
    tokens etc.), and a counter-based "in-drop-element" approach gets
    poisoned: a missing close-tag leaves the counter > 0 and zeroes
    every subsequent ``handle_data`` call. Regex preprocessing dodges
    the whole class of failure.
    """
    _BLOCK_ELEMENTS = {
        "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
        "blockquote", "pre", "section", "article", "header", "footer",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._BLOCK_ELEMENTS:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._BLOCK_ELEMENTS:
            self._parts.append("\n")

    def handle_data(self, data):
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


# Drop script + style blocks (and their contents) before tag-stripping.
# Greedy + DOTALL so a missing closing tag still consumes the whole
# tail rather than poisoning the structural parse downstream.
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1\s*>",
    flags=re.DOTALL | re.IGNORECASE,
)
# Fallback: if a script/style tag was never closed at all, drop from
# the open tag through end of document. Better to lose the tail than
# ship megabytes of CSS as "snippet".
_UNCLOSED_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)\b[^>]*>.*",
    flags=re.DOTALL | re.IGNORECASE,
)
# Drop HTML/XML comments — they're occasionally enormous (MSO
# conditionals, build-system fingerprints) and never user-visible.
_COMMENT_RE = re.compile(r"<!--.*?-->", flags=re.DOTALL)


def _html_to_text(body: str) -> str:
    """Drop HTML tags + entities, return readable plain text.

    No-op when the body doesn't look like HTML — saves the parse cost
    on the common plain-text case. The ``_HTML_HINTS`` heuristic is
    deliberately permissive (match if the body contains *any* of a
    handful of common opening tags, case-insensitive).
    """
    if not body:
        return body
    head = body[:1024].lower()
    if not any(h in head for h in _HTML_HINTS):
        return body
    # Preprocess: drop comments + script/style blocks (matched first
    # in their well-formed shape, then any leftover unclosed
    # script/style is dropped to end-of-string).
    cleaned = _COMMENT_RE.sub("", body)
    cleaned = _SCRIPT_STYLE_RE.sub("", cleaned)
    cleaned = _UNCLOSED_SCRIPT_STYLE_RE.sub("", cleaned)

    parser = _HTMLStripper()
    try:
        parser.feed(cleaned)
        text = parser.get_text()
    except Exception:
        # On any parse failure, fall back to the raw body — better
        # than 500ing the whole bulk request because of one weird
        # email.
        return body
    # Collapse leading/trailing whitespace per line, then drop runs
    # of blank lines down to one. Keeps paragraph structure visible
    # while preventing the dozens of empty lines HTML parsers tend
    # to leave behind.
    lines = [ln.strip() for ln in text.splitlines()]
    collapsed: list[str] = []
    last_blank = False
    for ln in lines:
        if ln:
            collapsed.append(ln)
            last_blank = False
        elif not last_blank:
            collapsed.append("")
            last_blank = True
    return "\n".join(collapsed).strip()


def _strip_zero_width(text: str) -> str:
    """Strip Unicode Cf (Format) + Mn (Non-spacing mark) chars used as
    invisible spacers in marketing email. Snippet-only — full body
    preserves all chars."""
    return "".join(
        c for c in text
        if unicodedata.category(c) not in ("Cf", "Mn")
    )


def _summarise_message(msg) -> dict[str, Any]:
    """Build the bulk-mail summary shape from an EmailMessage.

    Compact (no body_text). Adds:
    - ``snippet``: first ~200 chars of body, whitespace-collapsed.
      HTML is stripped first so summaries stay readable when the
      provider returns the HTML part. Zero-width Unicode (Cf/Mn) is
      also stripped — marketing mail (eBay et al.) pads the visible
      budget with hundreds of invisibility spacers that otherwise
      eat the snippet without showing anything.
    - ``unread``: True when the provider's UNREAD label is present.
    - ``has_attachment``: True iff at least one attachment is on the
      message (text/calendar parts count, since they show up as
      Attachment entries — see Phase 4).
    """
    body_text = _html_to_text(msg.body_text or "")
    # Whitespace collapse for snippet — newlines + tabs to single space —
    # keeps the preview legible at fixed width. Strip zero-width marks
    # BEFORE truncation so they don't pad the budget. Full-body emission
    # (_full_message) does NOT call _strip_zero_width — those chars are
    # real content if someone's actually reading the body.
    snippet = _strip_zero_width(" ".join(body_text.split()))[:_SNIPPET_LEN]
    labels = msg.labels or []
    return {
        "message_id": msg.message_id,
        "thread_id": msg.thread_id,
        "sender": msg.sender,
        "recipients": msg.recipients,
        "subject": msg.subject,
        "date": msg.date.isoformat() if msg.date else None,
        "labels": labels,
        "snippet": snippet,
        "unread": "UNREAD" in labels,
        "has_attachment": bool(getattr(msg, "attachments", None)),
    }


def _full_message(msg) -> dict[str, Any]:
    """Summary fields + the full body. Used by /bulk/mail/full.

    ``body_text`` is HTML-stripped (same pass as the snippet) so
    agents summarising newsletters or extracting receipt totals get
    readable text instead of raw markup. ``snippet`` is dropped to
    avoid duplication.

    The single-message ``GET /messages/{id}`` endpoint stays raw —
    if a caller picked one specific message and wants the full body,
    they may want the original HTML for rendering or extraction.
    Bulk reads default to clean text because that's the documented
    "for-the-LLM" path.
    """
    out = _summarise_message(msg)
    out.pop("snippet", None)
    out["body_text"] = _html_to_text(msg.body_text or "")
    return out


async def _fetch_messages_bulk(
    provider,
    message_ids: list,
    *,
    include_body: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fan out per-id fetches concurrently. Returns
    (success_summaries, errors). Errors are kept SEPARATE from
    successes so callers can render them differently — agents
    summarising a list shouldn't have to filter by ``status``.

    When ``include_body`` is False the per-id fetch is allowed to
    skip the body — providers that support a cheaper headers-only
    mode (currently IMAP, to dodge upstream issue #118) will use it.
    Providers without such a mode ignore the kwarg and return the
    full message; the summary projection drops the body anyway.

    ``message_ids`` accepts two shapes:

    - ``list[str]`` — plain UIDs. Each fetched against the
      provider's default mailbox.
    - ``list[tuple[folder, uid]]`` — folder-tagged UIDs. Each
      fetched with ``folder=`` plumbed through so IMAP's
      mailbox-scoped UIDs resolve correctly. Returned by the
      cross-folder search path (``filter.folder == '*'``).
    """
    import asyncio
    shape = _full_message if include_body else _summarise_message
    headers_only = not include_body

    async def _one(item):
        if isinstance(item, tuple):
            folder, mid = item
        else:
            folder, mid = None, item
        try:
            msg = await provider.fetch_message(
                mid, headers_only=headers_only, folder=folder,
            )
            return ("ok", shape(msg))
        except Exception as e:
            return ("err", {"message_id": mid, "error": fmt_exc(e)})

    results = await asyncio.gather(*(_one(it) for it in message_ids))
    successes = [r[1] for r in results if r[0] == "ok"]
    errors = [r[1] for r in results if r[0] == "err"]
    return successes, errors


async def _search_dispatch(
    provider, q: str, limit: int, mfilter,
) -> list:
    """Search dispatcher: cross-folder vs single-folder.

    Returns the shape that ``_fetch_messages_bulk`` expects:
    ``list[str]`` for single-folder searches, ``list[tuple[folder,
    uid]]`` for ``filter.folder == '*'``. Providers without
    folder-scoped IDs (Gmail, Office 365) bypass the wildcard branch
    transparently — :meth:`ImapProvider.search_all_folders` is the
    only implementation; for other providers the wildcard reduces
    to "no folder filter" via the existing ``search`` path.
    """
    folder = getattr(mfilter, "folder", None)
    if folder in ("*", "ALL") and hasattr(provider, "search_all_folders"):
        return await provider.search_all_folders(q, limit, filter=mfilter)
    if folder in ("*", "ALL"):
        # Non-IMAP providers: drop the wildcard, search globally.
        try:
            from copy import copy as _copy
            mfilter = _copy(mfilter)
            mfilter.folder = None  # type: ignore[attr-defined]
        except Exception:
            pass
    return await provider.search(q, limit, filter=mfilter)


@router.get("/accounts/{account_id}/bulk/mail")
async def bulk_mail_list(
    request: Request, account_id: int,
    unread: bool | None = Query(None),
    label: str | None = Query(None),
    folder: str | None = Query(None),
    from_addr: str | None = Query(None, alias="from"),
    to_addr: str | None = Query(None, alias="to"),
    subject: str | None = Query(None),
    after: str | None = Query(None),
    before: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(5, ge=1, le=250),
):
    """Search + summarise in one round trip — closes the N+1 loop
    that ``/mail/search`` + per-id ``/messages/{id}`` opened up.

    Same MailFilter DSL as ``/mail/search``; response shape is a list
    of summary objects (no body_text — use ``/bulk/mail/full`` for
    that). Default ``limit`` is 5 — agents should only ask for more
    when the user explicitly requests a specific quantity. Bounded by
    ``push.bulk_max_batch_size``.

    ``folder`` accepts:

    - omitted / null → search the account's default mailbox
      (typically INBOX)
    - a specific mailbox name → search just that folder
    - ``*`` or ``ALL`` → search every mailbox the account can
      list, merging matches across folders. Required for
      sender-keyed lookups when triage may have moved matches out
      of INBOX into category folders. IMAP UIDs are mailbox-scoped
      (RFC 3501 § 2.3.1.1) so the bulk fetch keeps the
      folder-of-origin alongside each UID internally — callers see
      the same flat ``messages`` array. Gmail and Office 365
      providers ignore the wildcard (their IDs are global).
    """
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    filter_dict = {
        "unread": unread, "label": label, "folder": folder,
        "from": from_addr, "to": to_addr, "subject": subject,
        "after": after, "before": before,
    }
    mfilter = MailFilter.from_dict(
        {k: v for k, v in filter_dict.items() if v is not None}
    )

    cap = _bulk_max(request)
    effective_limit = min(limit, cap or limit)

    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            ids = await _search_dispatch(
                provider, q or "", effective_limit, mfilter,
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
        messages, errors = await _fetch_messages_bulk(
            provider, ids, include_body=False,
        )
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "messages": messages,
        "errors": errors,
        "limit": effective_limit,
        "used_filter": mfilter.to_dict(),
    }


@router.get("/accounts/{account_id}/bulk/mail/full")
async def bulk_mail_list_full(
    request: Request, account_id: int,
    unread: bool | None = Query(None),
    label: str | None = Query(None),
    folder: str | None = Query(None),
    from_addr: str | None = Query(None, alias="from"),
    to_addr: str | None = Query(None, alias="to"),
    subject: str | None = Query(None),
    after: str | None = Query(None),
    before: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(5, ge=1, le=50),
):
    """Same shape as ``/bulk/mail`` but each message includes
    ``body_text`` (HTML-stripped). Cap is tighter (``le=50``) —
    bodies can be large, and the response grows with both N and
    per-message length. Default ``limit`` is 5; bump it explicitly
    only when the user asks for a specific quantity. Use only when
    you actually need bodies — summaries are usually enough.

    ``folder=*`` searches across every mailbox the account can list
    — useful for sender-keyed lookups when triage may have moved
    matches out of INBOX into category folders. See ``/bulk/mail``
    for the same wildcard semantics."""
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    filter_dict = {
        "unread": unread, "label": label, "folder": folder,
        "from": from_addr, "to": to_addr, "subject": subject,
        "after": after, "before": before,
    }
    mfilter = MailFilter.from_dict(
        {k: v for k, v in filter_dict.items() if v is not None}
    )

    cap = _bulk_max(request)
    effective_limit = min(limit, cap or limit)

    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            ids = await _search_dispatch(
                provider, q or "", effective_limit, mfilter,
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
        messages, errors = await _fetch_messages_bulk(
            provider, ids, include_body=True,
        )
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "messages": messages,
        "errors": errors,
        "limit": effective_limit,
        "used_filter": mfilter.to_dict(),
    }


class BulkMailFetchBody(BaseModel):
    """Input to ``POST /bulk/mail/fetch`` — explicit message IDs.

    ``message_ids`` defaults to an empty list so that
    ``json={}`` returns a clean ``400 message_ids required`` instead of
    a Pydantic 422. Caller-facing 400 is more useful than the schema
    validation error.
    """
    message_ids: list[str] = []


@router.post("/accounts/{account_id}/bulk/mail/fetch")
async def bulk_mail_fetch(
    request: Request, account_id: int,
    body: BulkMailFetchBody = Body(...),
):
    """Fetch summaries for an explicit list of message IDs.

    Symmetric to ``/bulk/mail`` for the case where the agent already
    has IDs (e.g. from a prior search) and just needs metadata. No
    filter; no provider search. Bounded by
    ``push.bulk_max_batch_size`` — exceeding the cap is a 400 with
    ``"exceeds cap"`` in the detail.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.web.routers.ui import _create_provider_from_account

    if not body.message_ids:
        raise HTTPException(status_code=400, detail="message_ids required")
    cap = _bulk_max(request)
    if cap and len(body.message_ids) > cap:
        raise HTTPException(
            status_code=400,
            detail=f"batch exceeds cap: {len(body.message_ids)} > {cap}",
        )

    provider = _create_provider_from_account(acct, secrets)
    try:
        messages, errors = await _fetch_messages_bulk(
            provider, body.message_ids, include_body=False,
        )
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "requested": len(body.message_ids),
        "messages": messages,
        "errors": errors,
    }


class BulkCalendarFetchBody(BaseModel):
    """Input to ``POST /bulk/calendar/fetch`` — explicit event IDs.

    Same defaults pattern as ``BulkMailFetchBody`` so an empty body
    returns a 400 ``event_ids required`` rather than a Pydantic 422.
    """
    event_ids: list[str] = []


def _shape_calendar_event(ev, acct: dict | None = None) -> dict[str, Any]:
    """Normalise either a CalendarEvent or a plain dict into the
    response shape. Dict pass-through lets tests stub get_event with
    a literal without juggling CalendarEvent imports.

    ``acct`` carries the per-account timezone used for the local-
    render fields (#109). Dict-shaped stubs pass through verbatim
    so they can opt into the local fields explicitly when they
    care about them; the bulk-fetch path emits a CalendarEvent so
    enrichment runs there."""
    if isinstance(ev, dict):
        return ev
    payload = {
        "event_id": ev.event_id,
        "calendar_id": ev.calendar_id,
        "summary": ev.summary,
        "description": ev.description,
        "location": ev.location,
        "start": ev.start.isoformat() if ev.start else None,
        "end": ev.end.isoformat() if ev.end else None,
        "all_day": ev.all_day,
        "organizer": ev.organizer,
        "attendees": ev.attendees,
        "status": ev.status,
        "ical_uid": ev.ical_uid,
    }
    payload.update(_local_render_fields(ev, acct))
    return payload


@router.post("/accounts/{account_id}/bulk/calendar/fetch")
async def bulk_calendar_fetch(
    request: Request, account_id: int,
    body: BulkCalendarFetchBody = Body(...),
):
    """Fetch event objects for an explicit list of event IDs.

    Calendar events are compact enough that there's no separate
    summary shape — this returns the same dict ``calendar-get`` does,
    once per id, in one round trip. Per-item errors surface in
    ``errors`` (separate from the success ``events`` array). Bounded
    by ``push.bulk_max_batch_size``.
    """
    user, acct = await _require_openclaw_account(request, account_id)

    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids required")
    cap = _bulk_max(request)
    if cap and len(body.event_ids) > cap:
        raise HTTPException(
            status_code=400,
            detail=f"batch exceeds cap: {len(body.event_ids)} > {cap}",
        )

    cal = await _open_calendar(request, acct)

    async def _one(eid: str):
        try:
            ev = await cal.get_event(eid)
            return ("ok", _shape_calendar_event(ev, acct))
        except Exception as e:
            return ("err", {"event_id": eid, "error": fmt_exc(e)})

    import asyncio
    try:
        results = await asyncio.gather(*(_one(eid) for eid in body.event_ids))
    finally:
        try:
            await cal.close()
        except Exception:
            pass

    successes = [r[1] for r in results if r[0] == "ok"]
    errors = [r[1] for r in results if r[0] == "err"]

    return {
        "account_id": account_id,
        "requested": len(body.event_ids),
        "events": successes,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Calendar bulk: free-slots + bulk-respond
# ---------------------------------------------------------------------------

class BulkRespondItem(BaseModel):
    event_id: str
    response: str


class BulkRespondBody(BaseModel):
    responses: list[BulkRespondItem]


@router.get("/accounts/{account_id}/calendar/free-slots")
async def calendar_free_slots(
    request: Request, account_id: int,
    length: int = Query(30, ge=5, le=480),
    count: int = Query(5, ge=1, le=50),
    time_min: str | None = Query(None),
    time_max: str | None = Query(None),
):
    """Return the next N free slots respecting the user's working hours.

    Layers in calendar OOO via :meth:`CalendarProvider.list_ooo` plus
    the user's manual ``ooo_override`` from MeetingPreferences. Times
    in the response are tz-aware UTC ISO strings.
    """
    from datetime import datetime, timedelta, timezone
    from email_triage.engine.availability import find_free_slots
    from email_triage.engine.models import (
        CalendarEvent, MeetingPreferences,
    )
    from email_triage.web.db import get_meeting_prefs

    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    cal = await _open_calendar(request, acct)
    prefs = MeetingPreferences.from_dict(get_meeting_prefs(db, acct["user_id"]))

    now = datetime.now(timezone.utc)
    try:
        h_start = (
            datetime.fromisoformat(time_min.replace("Z", "+00:00"))
            if time_min else now + timedelta(hours=prefs.minimum_lead_time_hours)
        )
        h_end = (
            datetime.fromisoformat(time_max.replace("Z", "+00:00"))
            if time_max else now + timedelta(days=prefs.search_horizon_days)
        )
    except Exception as e:
        try:
            await cal.close()
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f"bad_iso_datetime: {e}")

    try:
        try:
            events = await cal.list_events(h_start, h_end, limit=500)
            ooo = await cal.list_ooo(h_start, h_end)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"calendar_error: {e}")
    finally:
        try:
            await cal.close()
        except Exception:
            pass

    # Build the busy event list: regular events + OOO events + manual override.
    all_busy: list[CalendarEvent] = list(events)
    # Some providers' list_ooo may overlap with list_events — dedupe by id.
    seen_ids = {ev.event_id for ev in events if ev.event_id}
    for ev in ooo:
        if ev.event_id and ev.event_id in seen_ids:
            continue
        all_busy.append(ev)
    if prefs.ooo_override.enabled and prefs.ooo_override.start and prefs.ooo_override.end:
        all_busy.append(CalendarEvent(
            event_id="manual-ooo",
            summary=prefs.ooo_override.note or "Out-of-Office (manual override)",
            start=prefs.ooo_override.start,
            end=prefs.ooo_override.end,
        ))

    slots = find_free_slots(
        all_busy, h_start, h_end,
        length_minutes=length, count=count,
        working_hours=prefs.working_hours,
        business_hours_start=prefs.business_hours_start,
        business_hours_end=prefs.business_hours_end,
        skip_weekends=prefs.skip_weekends,
        timezone_name=prefs.timezone,
    )
    return {
        "account_id": account_id,
        "length_minutes": length,
        "timezone": prefs.timezone,
        "slots": [[s.isoformat(), e.isoformat()] for s, e in slots],
    }


@router.post("/accounts/{account_id}/calendar/bulk-respond")
@router.post("/accounts/{account_id}/bulk/calendar/respond")
async def calendar_bulk_respond(
    request: Request,
    response: Response,
    account_id: int,
    body: BulkRespondBody = Body(...),
):
    """Apply RSVP responses to many events; per-item results.

    Canonical path: ``/accounts/{id}/bulk/calendar/respond``. Legacy
    ``/accounts/{id}/calendar/bulk-respond`` continues to work but
    responses carry ``Deprecation`` / ``Sunset`` headers pointing at the
    canonical path.
    """
    if _is_legacy_path(request, "calendar/bulk-respond"):
        _stamp_deprecated(response, request, account_id, "calendar/bulk-respond")
    if not body.responses:
        raise HTTPException(status_code=400, detail="empty_responses")
    cap = _bulk_max(request)
    if cap and len(body.responses) > cap:
        raise HTTPException(
            status_code=400,
            detail=f"batch_too_large: {len(body.responses)} > cap {cap}",
        )

    user, acct = await _require_openclaw_account(request, account_id)
    cal = await _open_calendar(request, acct)
    from email_triage.engine.models import BulkItemResult, BulkResult
    import time as _time
    t0 = _time.time()
    items: list[BulkItemResult] = []
    try:
        for entry in body.responses:
            resp_lower = entry.response.lower()
            if resp_lower not in ("accepted", "declined", "tentative"):
                items.append(BulkItemResult(
                    message_id=entry.event_id, status="error",
                    error=f"bad_response: {entry.response!r}",
                ))
                continue
            try:
                await cal.respond_to_invite(entry.event_id, resp_lower)
                items.append(BulkItemResult(
                    message_id=entry.event_id, status="ok",
                    data={"response": resp_lower},
                ))
            except Exception as e:
                items.append(BulkItemResult(
                    message_id=entry.event_id, status="error", error=fmt_exc(e),
                ))
    finally:
        try:
            await cal.close()
        except Exception:
            pass

    succeeded = sum(1 for it in items if it.status == "ok")
    failed = sum(1 for it in items if it.status == "error")
    return BulkResult(
        requested=len(body.responses),
        succeeded=succeeded, failed=failed,
        items=items, elapsed_secs=_time.time() - t0,
    ).to_dict()


# ---------------------------------------------------------------------------
# Bulk reads (mail + calendar)
#
# Closes the N+1 hallucination vector: "list 5 unread with sender + subject"
# previously required 1 mail-search + 5 mail-get calls, which the agent
# couldn't batch (exec preflight blocks shell loops). When any of those
# individual calls ENOENT'd or returned unexpected shape, models tended to
# confabulate. These endpoints return the summary / full shape in one call.
#
# Design choices:
#  - /bulk/mail       : filter in, summary out. Closes the common "list" case.
#  - /bulk/mail/fetch : explicit ids in, summary out. For callers that
#                       already have ids from a prior search and just want
#                       metadata.
#  - /bulk/mail/full  : filter in, full body_text out. Only when the agent
#                       needs to read bodies (summarise a newsletter, etc.).
#                       Payloads are big; honour the cap.
#  - /bulk/calendar/fetch : ids in, event metadata out. Symmetric to mail/fetch.
# ---------------------------------------------------------------------------


def _collapse_snippet(body_text: str, n: int = 200) -> str:
    """First ~n chars of body_text, whitespace-collapsed, trimmed."""
    if not body_text:
        return ""
    collapsed = " ".join(body_text.split())
    if len(collapsed) <= n:
        return collapsed
    # Cut at a word boundary close to n so we don't split words.
    cut = collapsed.rfind(" ", 0, n)
    if cut < int(n * 0.7):  # no reasonable boundary — hard-cut at n
        cut = n
    return collapsed[:cut] + "…"


def _message_summary(msg: Any) -> dict:
    """Metadata-only view of an EmailMessage, for bulk-read responses.

    Keeps the payload bounded (no body_text). ``unread`` is derived
    from the Gmail-style ``UNREAD`` label when the provider propagates
    it; providers that don't set labels leave it False.
    """
    labels = list(msg.labels or [])
    return {
        "message_id": msg.message_id,
        "thread_id": msg.thread_id,
        "sender": msg.sender,
        "recipients": list(msg.recipients or []),
        "subject": msg.subject,
        "date": msg.date.isoformat() if msg.date else None,
        "labels": labels,
        "snippet": _collapse_snippet(msg.body_text or ""),
        "unread": any(lbl.upper() == "UNREAD" for lbl in labels),
        "has_attachment": bool(msg.attachments),
    }


def _message_full(msg: Any) -> dict:
    """Full message incl. body_text. Shape matches /messages/{id} for
    consistency; no snippet (redundant when body_text is present)."""
    labels = list(msg.labels or [])
    return {
        "message_id": msg.message_id,
        "thread_id": msg.thread_id,
        "sender": msg.sender,
        "recipients": list(msg.recipients or []),
        "subject": msg.subject,
        "body_text": msg.body_text,
        "date": msg.date.isoformat() if msg.date else None,
        "labels": labels,
        "headers": msg.headers,
        "unread": any(lbl.upper() == "UNREAD" for lbl in labels),
        "has_attachment": bool(msg.attachments),
    }


class _BulkFetchIds(BaseModel):
    """POST body for /bulk/*/fetch endpoints."""
    message_ids: list[str] | None = None  # used by mail/fetch
    event_ids: list[str] | None = None    # used by calendar/fetch


async def _fetch_messages(
    provider, ids: list[str], *, shape: str,
) -> tuple[list[dict], list[dict]]:
    """Fetch each id sequentially, coerce to ``shape`` (summary|full).

    Errors on individual ids don't abort the whole call — they collect
    into the ``errors`` array. Returns (messages, errors).
    """
    messages: list[dict] = []
    errors: list[dict] = []
    shaper = _message_summary if shape == "summary" else _message_full
    for mid in ids:
        try:
            msg = await provider.fetch_message(mid)
        except Exception as e:
            errors.append({"message_id": mid, "error": fmt_exc(e)})
            continue
        messages.append(shaper(msg))
    return messages, errors


@router.get("/accounts/{account_id}/bulk/mail")
async def bulk_mail_list(
    request: Request, account_id: int,
    unread: bool | None = Query(None),
    label: str | None = Query(None),
    folder: str | None = Query(None),
    from_addr: str | None = Query(None, alias="from"),
    to_addr: str | None = Query(None, alias="to"),
    subject: str | None = Query(None),
    after: str | None = Query(None),
    before: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    """Search + summary metadata in one call.

    Same filter DSL as ``/mail/search``. Returns a ``messages`` array
    with ``sender``, ``subject``, ``date``, ``labels``, ``snippet``,
    etc. — everything the agent needs to render a list without looping
    ``mail-get`` per id.

    Hard-capped by ``push.bulk_max_batch_size``.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    filter_dict = {
        "unread": unread, "label": label, "folder": folder,
        "from": from_addr, "to": to_addr, "subject": subject,
        "after": after, "before": before,
    }
    mfilter = MailFilter.from_dict(
        {k: v for k, v in filter_dict.items() if v is not None}
    )
    cap = _bulk_max(request)
    effective = min(limit, cap) if cap else limit

    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            ids = await provider.search(q or "", effective, filter=mfilter)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
        messages, errors = await _fetch_messages(provider, ids, shape="summary")
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "messages": messages,
        "errors": errors,
        "used_filter": mfilter.to_dict(),
        "limit": effective,
    }


@router.post("/accounts/{account_id}/bulk/mail/fetch")
async def bulk_mail_fetch(
    request: Request, account_id: int, body: _BulkFetchIds = Body(...),
):
    """Fetch summaries for an explicit list of message_ids in one call.

    Per-id errors collected into ``errors``; successful fetches into
    ``messages``. Capped by ``push.bulk_max_batch_size``.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    if not body.message_ids:
        raise HTTPException(status_code=400, detail="message_ids required")
    cap = _bulk_max(request)
    if cap and len(body.message_ids) > cap:
        raise HTTPException(
            status_code=400,
            detail=f"batch size {len(body.message_ids)} exceeds cap {cap}",
        )

    secrets = request.app.state.secrets
    from email_triage.web.routers.ui import _create_provider_from_account
    provider = _create_provider_from_account(acct, secrets)
    try:
        messages, errors = await _fetch_messages(
            provider, body.message_ids, shape="summary",
        )
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "messages": messages,
        "errors": errors,
        "requested": len(body.message_ids),
    }


@router.get("/accounts/{account_id}/bulk/mail/full")
async def bulk_mail_list_full(
    request: Request, account_id: int,
    unread: bool | None = Query(None),
    label: str | None = Query(None),
    folder: str | None = Query(None),
    from_addr: str | None = Query(None, alias="from"),
    to_addr: str | None = Query(None, alias="to"),
    subject: str | None = Query(None),
    after: str | None = Query(None),
    before: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(10, ge=1, le=50),
):
    """Like ``/bulk/mail`` but the response includes full ``body_text``.

    Use when the agent needs to read bodies (summarise a newsletter,
    extract an order total, etc.). Payloads are large — the default
    limit is tighter (10, max 50) than the summary endpoint.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    secrets = request.app.state.secrets
    from email_triage.engine.models import MailFilter
    from email_triage.web.routers.ui import _create_provider_from_account

    filter_dict = {
        "unread": unread, "label": label, "folder": folder,
        "from": from_addr, "to": to_addr, "subject": subject,
        "after": after, "before": before,
    }
    mfilter = MailFilter.from_dict(
        {k: v for k, v in filter_dict.items() if v is not None}
    )
    # A separate, tighter cap for full-body reads so one call can't
    # blow out the agent's context window with a huge newsletter dump.
    cap = min(_bulk_max(request) or 50, 50)
    effective = min(limit, cap)

    provider = _create_provider_from_account(acct, secrets)
    try:
        try:
            ids = await provider.search(q or "", effective, filter=mfilter)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"provider_error: {e}")
        messages, errors = await _fetch_messages(provider, ids, shape="full")
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "messages": messages,
        "errors": errors,
        "used_filter": mfilter.to_dict(),
        "limit": effective,
    }


@router.post("/accounts/{account_id}/bulk/calendar/fetch")
async def bulk_calendar_fetch(
    request: Request, account_id: int, body: _BulkFetchIds = Body(...),
):
    """Fetch calendar events by a list of event_ids in one call.

    Per-id errors collected into ``errors``; successful events into
    ``events``. Capped by ``push.bulk_max_batch_size``.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids required")
    cap = _bulk_max(request)
    if cap and len(body.event_ids) > cap:
        raise HTTPException(
            status_code=400,
            detail=f"batch size {len(body.event_ids)} exceeds cap {cap}",
        )

    cal = await _open_calendar(request, acct)
    events: list[dict] = []
    errors: list[dict] = []
    try:
        for eid in body.event_ids:
            try:
                ev = await cal.get_event(eid)
            except Exception as e:
                errors.append({"event_id": eid, "error": fmt_exc(e)})
                continue
            # Mirror the shape of GET /calendar/events/{id} — just the
            # structured dict the provider returns.
            events.append(
                ev if isinstance(ev, dict) else getattr(ev, "to_dict", lambda: {})()
            )
    finally:
        try:
            await cal.close()
        except Exception:
            pass

    return {
        "account_id": account_id,
        "events": events,
        "errors": errors,
        "requested": len(body.event_ids),
    }


# ---------------------------------------------------------------------------
# Multi-digest CRUD (Phase 8)
# ---------------------------------------------------------------------------
#
# OpenClaw API surface for the per-account digest config list.
# Lets agents enumerate, create, edit, delete, dry-run-validate,
# and test-send per-account digests without going through the
# operator-facing /accounts/{id}/edit?tab=digests UI.
#
# Storage + validation + render dispatch live in the
# ``email_triage.actions.digest_*`` modules; these handlers are
# thin JSON wrappers + token-auth + permission gating.

from email_triage.actions import digest_configs as _dc  # noqa: E402


def _digest_to_api(cfg) -> dict:
    """Project a DigestConfig into the API JSON shape. Identical
    to the storage to_dict — kept as a helper so the API surface
    can diverge later without touching storage callers."""
    return _dc.to_dict(cfg)


@router.get("/accounts/{account_id}/digests")
async def openclaw_digests_list(request: Request, account_id: int):
    """Enumerate digest configs for one account.

    Preset (always present) appears first. Custom digests follow
    in stored order. Migration runs on first read — agents
    talking to a freshly-deployed install don't have to know
    about the legacy ``recipient_digest_enabled`` flag.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    configs = _dc.list_digest_configs(db, account_id)
    return {
        "account_id": account_id,
        "digests": [_digest_to_api(c) for c in configs],
    }


@router.post("/accounts/{account_id}/digests")
async def openclaw_digests_create(request: Request, account_id: int):
    """Create one custom digest config.

    Body is the same dict shape as ``GET`` returns (without
    ``id``). ``id`` is server-minted; ``kind`` is forced to
    ``custom`` (preset is fixed and not creatable). Validation
    errors return HTTP 400 with the error list.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )
    body = dict(body)
    body.pop("id", None)  # server-minted
    body["kind"] = "custom"  # API never creates a preset
    cfg = _dc.from_dict(body)
    errors = _dc.validate(cfg)
    if errors:
        raise HTTPException(
            status_code=400, detail={"errors": errors},
        )
    saved = _dc.upsert_digest_config(db, account_id, cfg)
    return _digest_to_api(saved)


@router.patch("/accounts/{account_id}/digests/{digest_id}")
async def openclaw_digests_update(
    request: Request, account_id: int, digest_id: str,
):
    """Partial update — body keys overlay the stored config.

    Preset entry accepts only ``enabled`` + ``schedule.time_local``
    (kind / name / format / filter / window are server-locked
    for the preset). Custom entries accept any field.
    Validation errors return HTTP 400.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )

    existing = _dc.get_digest_config(db, account_id, digest_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="digest not found")

    # Overlay stored shape with body keys, then re-hydrate. Lets
    # the caller send a partial dict (e.g. just ``{"enabled": false}``)
    # without re-sending the full schema.
    merged = _dc.to_dict(existing)
    if digest_id == _dc.PRESET_ID:
        # Preset only accepts a constrained subset; ignore other keys.
        if "enabled" in body:
            merged["enabled"] = bool(body["enabled"])
        if isinstance(body.get("schedule"), dict):
            sched = dict(merged.get("schedule") or {})
            if "time_local" in body["schedule"]:
                sched["time_local"] = str(body["schedule"]["time_local"])
            merged["schedule"] = sched
    else:
        for k, v in body.items():
            if k in ("id", "kind"):
                continue
            merged[k] = v
        merged["kind"] = "custom"

    cfg = _dc.from_dict(merged)
    cfg.id = digest_id
    errors = _dc.validate(cfg)
    if errors:
        raise HTTPException(
            status_code=400, detail={"errors": errors},
        )
    saved = _dc.upsert_digest_config(db, account_id, cfg)
    return _digest_to_api(saved)


@router.delete("/accounts/{account_id}/digests/{digest_id}")
async def openclaw_digests_delete(
    request: Request, account_id: int, digest_id: str,
):
    """Delete one custom digest. Refuses preset (returns 400)."""
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    if digest_id == _dc.PRESET_ID:
        raise HTTPException(
            status_code=400, detail="cannot delete the preset digest",
        )
    removed = _dc.delete_digest_config(db, account_id, digest_id)
    if not removed:
        raise HTTPException(status_code=404, detail="digest not found")
    return {"ok": True, "deleted_id": digest_id}


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/validate-query",
)
async def openclaw_digests_validate_query(
    request: Request, account_id: int, digest_id: str,
):
    """Dry-run an advanced provider query.

    Body: ``{"advanced": "<raw query>"}``. Hands the string to
    ``provider.search()`` with limit=1. Returns
    ``{"ok": true, "match_count": N}`` on success or
    ``{"ok": false, "error": "<provider-side error>"}`` on a
    syntax / auth / network failure. Non-2xx HTTP only on
    auth / permission failures, NOT on a malformed query — the
    operator's mistake comes back as ``ok: false`` with the
    provider's own diagnostic.
    """
    from email_triage.web.routers.ui import (
        _create_provider_from_account,
    )
    user, acct = await _require_openclaw_account(request, account_id)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )
    raw = (body.get("advanced") or "").strip()
    if not raw:
        return {
            "ok": True, "match_count": 0,
            "note": "advanced field empty; structured filter would apply",
        }
    secrets = request.app.state.secrets
    try:
        provider = _create_provider_from_account(acct, secrets)
        ids = await provider.search(raw, limit=1)
        return {"ok": True, "match_count": len(ids)}
    except Exception as e:
        return {"ok": False, "error": fmt_exc(e)}


@router.post(
    "/accounts/{account_id}/digests/{digest_id}/test-send",
)
async def openclaw_digests_test_send(
    request: Request, account_id: int, digest_id: str,
):
    """Operator-triggered test send via the API.

    Bypasses the scheduler's fire-time + idempotence gates,
    same shape as the UI surface
    ``/accounts/{id}/digests/{digest_id}/test-send``. Returns
    JSON with the row count + recipient + render-format echo so
    agents can confirm the digest fired.
    """
    from datetime import datetime, timezone
    from email_triage.web.app import _fire_one_digest

    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    secrets = request.app.state.secrets
    config = request.app.state.config
    smtp = config.smtp
    if not smtp.host:
        raise HTTPException(
            status_code=503, detail="SMTP not configured",
        )
    to_addr = (acct.get("email_address") or "").strip()
    if not to_addr:
        raise HTTPException(
            status_code=400,
            detail="account has no email address",
        )
    dcfg = _dc.get_digest_config(db, account_id, digest_id)
    if dcfg is None:
        raise HTTPException(
            status_code=404, detail="digest not found",
        )
    from email_triage.triage_logging import is_hipaa_mode
    hipaa = is_hipaa_mode() or bool(acct.get("hipaa", False))
    now_utc = datetime.now(timezone.utc)
    try:
        await _fire_one_digest(
            db=db, secrets=secrets, smtp=smtp,
            acct=acct, dcfg=dcfg, hipaa=hipaa,
            now_utc=now_utc, last_sent=None, to_addr=to_addr,
        )
        return {
            "ok": True,
            "digest_id": digest_id,
            "to": to_addr,
            "kind": dcfg.kind,
            "render_as": dcfg.format.render_as,
        }
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"send_failed: {fmt_exc(e)}",
        )


# ---------------------------------------------------------------------------
# Email watches CRUD (#100)
# ---------------------------------------------------------------------------
#
# Mirrors the digest CRUD shape: GET list / POST create / PATCH update /
# DELETE / POST test-fire. Per-watch HMAC secret is stored in the
# secrets provider under ``watch_<id>_hmac`` — minted on create,
# rotatable via PATCH (no, actually: delete + recreate; we don't
# support secret rotation through this surface).
#
# The all-accounts cross-account watch is created with
# ``account_id = null`` in the body. The endpoint is still under
# ``/accounts/{account_id}/watches`` — the path scopes the LIST view
# (per-account-or-all-applicable union) and the create/update permission
# (operator must own the account they're touching). To list every watch
# install-wide, an admin uses ``/admin/watches`` (UI surface) or scopes
# the OpenClaw query per account.

from email_triage.web import email_watches as _watches  # noqa: E402


def _watch_to_api(w) -> dict:
    """Project an EmailWatch dataclass into the API JSON shape."""
    return _watches.to_dict(w)


@router.get("/accounts/{account_id}/watches")
async def openclaw_watches_list(request: Request, account_id: int):
    """Enumerate watches scoped to one account.

    Returns per-account watches AND the all-accounts watches (the
    ``account_id IS NULL`` rows), since both apply when mail lands on
    this account. HIPAA-flagged accounts get the per-account list
    only — all-scope watches are excluded for the same reason the
    fire pipeline excludes them.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    rows = _watches.list_watches(
        db,
        account_id=account_id,
        include_all_accounts=not is_account_hipaa(acct),
    )
    return {
        "account_id": account_id,
        "watches": [_watch_to_api(w) for w in rows],
    }


@router.post("/accounts/{account_id}/watches")
async def openclaw_watches_create(request: Request, account_id: int):
    """Create one watch.

    Body fields:
      ``name`` (required), ``enabled`` (default true), ``account_id``
      (defaults to the path-scoped account; pass ``null`` to make this
      an all-accounts watch), ``filter`` dict, ``actions`` dict.

    HMAC secret is minted server-side and stored under
    ``watch_<id>_hmac`` in the secrets provider; the secret VALUE is
    NOT returned in the response (the operator queries the secrets
    store / config endpoint to retrieve it for the receiver side).
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    secrets = request.app.state.secrets
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )
    body = dict(body)
    body.pop("watch_id", None)
    body.pop("id", None)
    # Default scope to the path account; explicit null means all-accounts.
    if "account_id" not in body:
        body["account_id"] = account_id

    w = _watches.from_dict(body)
    errors = _watches.validate(w)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    saved = _watches.upsert_watch(db, w)

    # Mint HMAC secret if absent.
    try:
        existing = secrets.get(_watches.hmac_secret_key(saved.watch_id))
    except Exception:
        existing = None
    if not existing:
        import secrets as _stdlib_secrets
        try:
            secrets.set(
                _watches.hmac_secret_key(saved.watch_id),
                _stdlib_secrets.token_urlsafe(32),
            )
        except Exception:
            # Read-only secrets backends won't permit set(); the watch
            # still exists, but the receiver won't be able to verify
            # signatures. Log nothing identifying — backend type only.
            log.warning(
                "watch HMAC secret store failed",
                watch_id=saved.watch_id,
            )
    return _watch_to_api(saved)


@router.patch("/accounts/{account_id}/watches/{watch_id}")
async def openclaw_watches_update(
    request: Request, account_id: int, watch_id: str,
):
    """Partial update — body keys overlay the stored watch."""
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )
    existing = _watches.get_watch(db, watch_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="watch not found")

    merged = _watches.to_dict(existing)
    for k, v in body.items():
        if k in ("watch_id", "id", "created_at", "updated_at"):
            continue
        merged[k] = v
    w = _watches.from_dict(merged)
    w.watch_id = watch_id
    errors = _watches.validate(w)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    saved = _watches.upsert_watch(db, w)
    return _watch_to_api(saved)


@router.delete("/accounts/{account_id}/watches/{watch_id}")
async def openclaw_watches_delete(
    request: Request, account_id: int, watch_id: str,
):
    """Remove a watch + its HMAC secret."""
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    secrets = request.app.state.secrets
    existing = _watches.get_watch(db, watch_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="watch not found")
    removed = _watches.delete_watch(db, watch_id)
    if not removed:
        raise HTTPException(status_code=404, detail="watch not found")
    try:
        # Best-effort secret cleanup. Secrets backends without a delete
        # primitive will leave a dangling key — harmless, the lookup
        # never finds a matching watch_id again.
        if hasattr(secrets, "delete"):
            secrets.delete(_watches.hmac_secret_key(watch_id))
    except Exception:
        pass
    return {"ok": True, "deleted_id": watch_id}


@router.post("/accounts/{account_id}/watches/{watch_id}/test-fire")
async def openclaw_watches_test_fire(
    request: Request, account_id: int, watch_id: str,
):
    """Fire the watch's actions against a synthetic envelope.

    Used by the UI Test button + as an OpenClaw smoke test. Does NOT
    consult the matcher — the operator already picked this watch
    explicitly. The synthetic envelope shape:

        sender   = "Test Sender <test@example.com>"
        subject  = "Watch test fire"
        category = "test"

    Returns the same dict shape as the real fire path so the operator
    UI can render escalate + webhook results inline.
    """
    user, acct = await _require_openclaw_account(request, account_id)
    db = request.app.state.db
    secrets = request.app.state.secrets
    config = request.app.state.config

    existing = _watches.get_watch(db, watch_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="watch not found")

    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    sender = str(body.get("sender") or "Test Sender <test@example.com>")
    subject = str(body.get("subject") or "Watch test fire")
    category = str(body.get("category") or "test")

    from email_triage.web.watch_runner import fire_one_watch
    result = await fire_one_watch(
        db=db, config=config, secrets=secrets,
        watch=existing, account=acct,
        sender=sender, subject=subject, body_text="",
        category=category, message_id="",
        actor_user_id=user.get("id"),
    )
    return {"ok": True, "result": result}
