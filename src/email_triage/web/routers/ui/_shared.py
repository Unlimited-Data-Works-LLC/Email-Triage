"""Cross-concern helpers + module-level state for web.routers.ui.

Split out of `web/routers/ui.py` (#144). Helpers + the module
prelude (imports, constants, _log, the APIRouter singleton)
live HERE so each concern file's `globals().update(vars(_shared))`
recreates the bare-name namespace handlers were originally
written against. No behavior changes from the pre-split file.

Patchable helpers — `_test_account_connection`,
`_create_provider_from_account`, `_build_classifier_from_config`,
`_get_categories_from_db`, etc. — live here. Tests do
`mock.patch("email_triage.web.routers.ui._foo")`; the package
__init__.py re-exports `_foo` from this module AND installs a
`__setattr__` mirror that propagates patches to every concern
submodule that snapshotted the name into its globals.
"""
from __future__ import annotations

import asyncio
import email as email_mod
import email.policy
import email.utils
import json as json_mod
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web import settings_keys as _S
from email_triage.web.app import get_config, get_db, get_secrets, get_templates
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_otp,
    get_user_by_email,
    send_otp_email,
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

_log = get_logger("web.ui")

router = APIRouter()


def __getattr__(name):
    """Route reads of legacy install-singleton names through the factory.

    The factory module (#138.1) now owns ``_install_google_oauth`` and
    ``_install_ingestion_config``. Code that did
    ``from email_triage.web.routers.ui import _install_ingestion_config``
    (e.g. test fixtures, future plugins) keeps working — PEP 562 lets
    us proxy module-level reads to the factory's current values.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _triage_preset_to_query(preset: str, freeform: str) -> str:
    """Map the #61 Search Query dropdown preset to an IMAP SEARCH query.

    The Gmail provider's translator converts IMAP-style queries to
    Gmail ``q=`` at search time, so callers only need to emit IMAP
    syntax here. ``other`` passes ``freeform`` through unchanged
    (legacy default when the textbox is empty: ``UNSEEN``).
    """
    from datetime import date, timedelta

    today = date.today().strftime("%d-%b-%Y")
    week_ago = (date.today() - timedelta(days=7)).strftime("%d-%b-%Y")
    month_ago = (date.today() - timedelta(days=30)).strftime("%d-%b-%Y")

    mapping = {
        "unread_today": f"UNSEEN SINCE {today}",
        "unread_week": f"UNSEEN SINCE {week_ago}",
        "unread_month": f"UNSEEN SINCE {month_ago}",
        "unread": "UNSEEN",
        "all_today": f"SINCE {today}",
        "all_week": f"SINCE {week_ago}",
        "all_month": f"SINCE {month_ago}",
        "all": "ALL",
    }
    if preset == "other":
        return freeform or "UNSEEN"
    if preset in mapping:
        return mapping[preset]
    # Legacy callers (no preset + populated query text) get the text.
    if freeform:
        return freeform
    return "UNSEEN"


def _get_categories_from_db(db, user_id: int | None = None) -> dict[str, str]:
    """Read categories as {slug: description}. When ``user_id`` is
    supplied, personal categories for that user are unioned on top of
    system categories (user override wins on collision)."""
    from email_triage.web.db import get_categories_dict
    return get_categories_dict(db, user_id=user_id)


def _tag_message_hipaa(message, account: dict):
    """Stamp message.hipaa based on the owning account's resolved state.

    Providers don't know about accounts (they only know their own
    config), so every call site that fetches a message for a specific
    account must tag the result here. Downstream actions read
    ``message.hipaa`` instead of calling ``is_hipaa_mode()`` so the
    right per-account decision is made rather than a global one.
    """
    if message is None or account is None:
        return message
    from email_triage.triage_logging import is_account_hipaa
    try:
        message.hipaa = is_account_hipaa(account)
    except AttributeError:
        # EmailMessage is a frozen dataclass in some configurations;
        # fall back to replace() semantics if direct assignment fails.
        pass
    return message


def _render(templates, request, name, context=None):
    """Render a template using the Starlette 1.0 API.

    Auto-injects:
      - ``hipaa_mode`` — true when system HIPAA mode is on. Drives
        the login badge, lock glyph, and per-account chip rules.
      - ``baa_banner`` — admin-only BAA-expiry banner ctx (see
        :func:`_inject_baa_banner_ctx`). The partial template
        ``admin/_baa_expiry_banner.html`` rendered from ``base.html``
        guards on ``baa_banner is defined and ... severity != silent``
        so non-admin / silent / off renders emit nothing.
    Silent fallback to False if state isn't available (e.g. in tests).
    """
    ctx = context or {}
    if "hipaa_mode" not in ctx:
        try:
            from email_triage.triage_logging import is_hipaa_mode
            ctx["hipaa_mode"] = is_hipaa_mode()
        except Exception:
            ctx["hipaa_mode"] = False
    if "google_oauth" not in ctx:
        try:
            ctx["google_oauth"] = request.app.state.config.google_oauth
        except Exception:
            ctx["google_oauth"] = None
    if "office365_oauth" not in ctx:
        try:
            ctx["office365_oauth"] = request.app.state.config.office365_oauth
        except Exception:
            ctx["office365_oauth"] = None
    if "ingestion_config" not in ctx:
        try:
            ctx["ingestion_config"] = request.app.state.config.ingestion
        except Exception:
            ctx["ingestion_config"] = None
    # #171-D — universal admin BAA-expiry banner. Computed here so every
    # admin page picks it up without per-handler boilerplate; gated so
    # the user-facing surface never carries admin-only copy (per the
    # no-admin-path-in-user-copy rule).
    if "baa_banner" not in ctx:
        ctx["baa_banner"] = _inject_baa_banner_ctx(request, ctx.get("user"))
    # #175 R-B — universal admin retry-queue threshold banner. Same
    # admin-only gate + admin-path-rule shape. Renders a section when
    # ≥3 dead rows in 24h on any single account OR ≥5 install-wide in
    # 24h. Non-admin renders + clean-state admin renders see ``None``
    # and the partial short-circuits to zero markup.
    if "retry_queue_banner" not in ctx:
        ctx["retry_queue_banner"] = _inject_retry_queue_banner_ctx(
            request, ctx.get("user"),
        )
    return templates.TemplateResponse(request, name, context=ctx)


def _inject_retry_queue_banner_ctx(
    request: Request, user: dict | None,
) -> dict | None:
    """Build the retry-queue threshold banner context for an admin
    render. Returns ``None`` for non-admin / empty-queue / failure.

    Threshold logic mirrors the daily-health email section:

      * Install-wide: ≥5 ``state='dead'`` rows in last 24h.
      * Per-account: any account with ≥3 deads in 24h, with a
        breakdown of dead_reason counts.

    Either condition fires the banner. Both can fire at once
    (template renders both bullet families).

    Failure-safe: if R-A's helpers aren't on the import path yet,
    or the DB read throws, we return ``None`` so admin pages still
    render cleanly. The /health/detail endpoint surfaces the
    failure separately (Nagios-pollable).
    """
    if user is None:
        try:
            from email_triage.web.dependencies import get_current_user
            user = get_current_user(request)
        except Exception:
            user = None
    if user is None or user.get("role") != "admin":
        return None
    db = getattr(request.app.state, "db", None)
    if db is None:
        return None
    try:
        from email_triage.web.daily_health import (
            gather_retry_deads_section,
        )
        section = gather_retry_deads_section(db)
    except Exception:
        return None
    if section is None:
        return None
    return section


def _inject_baa_banner_ctx(
    request: Request, user: dict | None,
) -> dict | None:
    """Build the BAA-expiry banner context for an admin render.

    Returns one of:
      * a banner-shape dict (per ``baa_expiry.build_banner_context``)
        when the caller is an admin AND the install has at least one
        HIPAA-flagged account (or system HIPAA mode is on) AND there's
        anything in scope to surface,
      * ``None`` in every other case (anonymous, non-admin, HIPAA-
        disabled install with no HIPAA accounts, sweeper hasn't run
        yet, cache malformed, exception thrown).

    The partial template ``admin/_baa_expiry_banner.html`` skips the
    render block on ``not baa_banner`` or ``severity == "silent"`` so
    ``None`` and silent banners both produce zero markup.

    Data source preference order:
      1. ``app.state.baa_expiry_status`` (populated hourly by
         ``_baa_expiry_sweeper`` in app.py). Free — in-memory read.
      2. Live ``build_banner_context(db)`` fallback when the cache is
         missing (first-boot before the sweeper's first tick). Costs
         one SELECT + bucket math; acceptable on a per-admin-page
         render, and only fires until the sweeper warms the cache.

    Stale-sweep policy: silent fail. The hourly sweeper sets the cache
    on every successful run; if the sweep raises, the cache holds the
    LAST successful summary. Bucket math is day-resolution so 1-25 hour
    staleness is invisible to operators. /health/detail surfaces a
    Nagios-pollable failure signal separately.
    """
    if user is None:
        # Try to resolve at render time — most handlers pass `user` in
        # ctx but some (login pages, public help) don't. We can still
        # render the banner if the request carries a session.
        try:
            from email_triage.web.dependencies import get_current_user
            user = get_current_user(request)
        except Exception:
            user = None
    if user is None or user.get("role") != "admin":
        return None

    # HIPAA-disabled install gate. Only render the banner when at least
    # one account is HIPAA-flagged OR system HIPAA mode is on. On a
    # plain non-HIPAA install the BAA gate is irrelevant.
    try:
        from email_triage.triage_logging import is_hipaa_mode
        if not is_hipaa_mode():
            db = getattr(request.app.state, "db", None)
            if db is None:
                return None
            row = db.execute(
                "SELECT 1 FROM email_accounts WHERE hipaa = 1 LIMIT 1"
            ).fetchone()
            if row is None:
                return None
    except Exception:
        return None

    # Cache read first; live fallback only when cache is empty.
    try:
        from email_triage.baa_expiry import (
            banner_from_cached_status,
            build_banner_context,
        )
        cached = getattr(request.app.state, "baa_expiry_status", None)
        banner = banner_from_cached_status(cached)
        if banner is None:
            # Cache cold (pre-sweeper-tick). Compute live.
            db = getattr(request.app.state, "db", None)
            if db is None:
                return None
            banner = build_banner_context(db)
        return banner
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PWA service worker (#94)
# ---------------------------------------------------------------------------
#
# The SW file lives in /static/ for distribution but the browser only
# scopes a service worker to URLs under the path it was served from.
# To control all of /* (so the install heuristic fires app-wide and
# any future scope-aware logic sees every navigation), the SW must be
# served from the site root with the ``Service-Worker-Allowed: /``
# header. StaticFiles can't customise headers per file, so a thin
# route handler reads the on-disk file and returns it with the right
# content-type + scope header. No auth required — the SW must be
# fetchable from the login page too, otherwise the install prompt
# never appears for first-time users.
def _dashboard_health_chips(request: Request, db) -> dict:
    """Build the admin health-chip strip.

    Reuses ``gather_health_state`` so the dashboard and the daily
    health email agree on "what's happening right now". Also derives
    the Gateway-uptime chip from ``app.state.started_at`` (monotonic
    seconds), the "Last triage run" chip from ``MAX(created_at)``,
    and counts disconnected watchers (>15 min or status in
    error/reconnecting/disconnected).
    """
    from datetime import datetime, timedelta, timezone

    chips: dict = {
        "gateway": {"ok": True, "label": "Up"},
        "watchers": {"ok": True, "connected": 0, "total": 0, "disconnected": []},
        "last_run": {"ok": True, "label": "No runs yet", "iso": None},
        "errors": {"ok": True, "count": 0, "label": "0 errors"},
        # #66 — O365 Graph subscription chip (sibling of gmail_push).
        # ``ok=True + total=0`` is the "no O365 accounts subscribed"
        # baseline; the template can hide the chip in that case.
        "office365_push": {
            "ok": True, "total": 0, "active": 0, "expiring": 0, "errored": 0,
            "label": "Push off",
        },
    }

    # ---- Gateway uptime ---------------------------------------------
    try:
        started = getattr(request.app.state, "started_at", None)
        if started is not None:
            uptime_s = max(0.0, time.monotonic() - started)
            if uptime_s < 60:
                label = "Restarted just now"
                ok = False
            elif uptime_s < 180:
                label = f"Restarted {int(uptime_s / 60)}m ago"
                ok = False
            elif uptime_s < 3600:
                label = f"Up {int(uptime_s / 60)}m"
                ok = True
            elif uptime_s < 86400:
                label = f"Up {int(uptime_s / 3600)}h"
                ok = True
            else:
                label = f"Up {int(uptime_s / 86400)}d"
                ok = True
            chips["gateway"] = {"ok": ok, "label": label}
    except Exception:
        pass

    # ---- Watchers ---------------------------------------------------
    # Single source of truth: WatcherManager.account_states(db).
    # Aggregate per provider (option C — primary mode wins, sums = total).
    # Also keep the per-account list around for "show me which account"
    # drill-downs.
    try:
        wm = getattr(request.app.state, "watcher_manager", None)
        if wm is not None:
            try:
                acct_states = wm.account_states(db)
            except Exception:
                acct_states = []

            providers: dict[str, dict] = {}
            alerts: list[dict] = []
            for s in acct_states:
                p = s.get("provider", "unknown")
                b = providers.setdefault(p, {
                    "total": 0, "push": 0, "poll": 0,
                    "uncovered": 0, "push_plus_poll": 0,
                    "accounts": [],
                })
                b["total"] += 1
                primary = s.get("primary", "none")
                if primary == "push":
                    b["push"] += 1
                elif primary == "poll":
                    b["poll"] += 1
                else:
                    b["uncovered"] += 1
                if s.get("mode") == "push+poll":
                    b["push_plus_poll"] += 1
                b["accounts"].append({
                    "account_id":   s["account_id"],
                    "account_name": s["account_name"],
                    "owner":        s["owner"],
                    "mode":         s["mode"],
                    "primary":      primary,
                    "push_detail":  s["push"]["detail"],
                    "poll_detail":  (
                        f"poll fresh, last {s['poll']['last_tick']}"
                        if s["poll"]["fresh"]
                        else (
                            "poll enrolled, no tick yet"
                            if s["poll"]["enrolled"]
                            else "poll off"
                        )
                    ),
                    "alert":        s["alert"],
                })
                if s.get("alert"):
                    alerts.append({
                        "account_id":   s["account_id"],
                        "account_name": s["account_name"],
                        "owner":        s["owner"],
                        "alert":        s["alert"],
                    })

            # Process-level (not per-account).
            try:
                mb_total, mb_watching = wm.mailbox_counts()
            except Exception:
                mb_total, mb_watching = 0, 0
            try:
                poll_reg, poll_fresh = wm.poll_counts()
            except Exception:
                poll_reg, poll_fresh = 0, 0

            chips["watchers"] = {
                "ok": not alerts,
                "providers":    providers,
                "alerts":       alerts,
                # Process-level counters surfaced separately so the
                # template can show "5/5 folders watching" without
                # walking every account.
                "mailboxes": {"total": mb_total, "connected": mb_watching},
                "poll":      {"registered": poll_reg, "fresh": poll_fresh},
            }
    except Exception:
        pass

    # ---- Last triage run --------------------------------------------
    try:
        row = db.execute(
            "SELECT MAX(created_at) AS mx FROM triage_runs"
        ).fetchone()
        mx = row["mx"] if row else None
        if mx:
            try:
                dt = datetime.fromisoformat(mx)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = datetime.now(timezone.utc) - dt
                age_s = age.total_seconds()
                if age_s < 120:
                    label = "just now"
                    ok = True
                elif age_s < 3600:
                    label = f"{int(age_s / 60)} minutes ago"
                    ok = True
                elif age_s < 86400:
                    label = f"{int(age_s / 3600)} hours ago"
                    ok = age_s < 6 * 3600
                else:
                    label = f"{int(age_s / 86400)} days ago"
                    ok = False
                chips["last_run"] = {"ok": ok, "label": label, "iso": mx}
            except Exception:
                chips["last_run"] = {"ok": True, "label": mx[:16], "iso": mx}
    except Exception:
        pass

    # ---- Errors (24h) -----------------------------------------------
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        row = db.execute(
            "SELECT COUNT(*) AS cnt FROM log_entries "
            "WHERE level = 'ERROR' AND ts >= ?",
            (since,),
        ).fetchone()
        cnt = int(row["cnt"]) if row else 0
        chips["errors"] = {
            "ok": cnt == 0,
            "count": cnt,
            "label": f"{cnt} error{'s' if cnt != 1 else ''} (24h)",
        }
    except Exception:
        pass

    # ---- O365 Graph push (#66) --------------------------------------
    # Same chip-shape pattern as the existing Gmail Pub/Sub line.
    # Surfaces: total / active / expiring_in_24h / errored.
    try:
        from email_triage.web.db import list_o365_subscriptions
        rows = list_o365_subscriptions(db)
        total = len(rows)
        active = 0
        expiring = 0
        errored = 0
        now_dt = datetime.now(timezone.utc)
        soon_dt = now_dt + timedelta(hours=24)
        for r in rows:
            status = (r.get("status") or "").strip()
            try:
                exp = datetime.fromisoformat(
                    str(r.get("expiration_at", "")).replace("Z", "+00:00")
                )
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
            except Exception:
                exp = None
            if status == "errored" or exp is None or exp <= now_dt:
                errored += 1
                continue
            active += 1
            if exp <= soon_dt:
                expiring += 1
        if total == 0:
            chips["office365_push"] = {
                "ok": True, "total": 0, "active": 0,
                "expiring": 0, "errored": 0,
                "label": "Push off",
            }
        elif errored > 0:
            chips["office365_push"] = {
                "ok": False, "total": total, "active": active,
                "expiring": expiring, "errored": errored,
                "label": (
                    f"⚠ Push expired ({errored}/{total})"
                    if errored == total
                    else f"⚠ {errored} of {total} expired"
                ),
            }
        else:
            chips["office365_push"] = {
                "ok": True, "total": total, "active": active,
                "expiring": expiring, "errored": 0,
                "label": (
                    f"📡 Push active ({active}/{total})"
                    if active < total or expiring
                    else "📡 Push active"
                ),
            }
    except Exception:
        pass

    return chips


def _current_user_quiet_hours(db, user: dict) -> dict | None:
    """Return ``{'until_local': 'HH:MM'}`` if user is currently in quiet hours.

    The dashboard exposes a "Quiet until HH:MM" chip. Quiet hours are
    read from the user's meeting prefs' working_hours — outside any
    configured window for the current weekday counts as quiet. We only
    show the chip when there's a concrete "end time" to display;
    empty-all-day or fully-covered days return None.
    """
    try:
        from email_triage.web.db import get_meeting_prefs
        from email_triage.engine.models import MeetingPreferences
        prefs = MeetingPreferences.from_dict(get_meeting_prefs(db, user["id"]))
    except Exception:
        return None

    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(prefs.timezone or "UTC")
    except Exception:
        from datetime import timezone as _tz
        tz = _tz.utc

    now_local = datetime.now(tz)
    weekday = now_local.weekday()
    try:
        intervals = prefs.working_hours.for_weekday(weekday)
    except Exception:
        intervals = []
    cur = now_local.strftime("%H:%M")

    # If inside any interval, not quiet.
    for start, end in intervals:
        if start <= cur < end:
            return None

    # Find next interval today; if none, not shown (too vague).
    next_start: str | None = None
    for start, _end in intervals:
        if cur < start and (next_start is None or start < next_start):
            next_start = start
    if next_start is None:
        return None
    return {"until_local": next_start}


def _build_dashboard_context(request: Request, user: dict) -> dict:
    """Synchronous body of the dashboard build. #135: wrapped via
    ``db_call`` from the async handler so all the DB reads (getting-
    started checklist, recent runs, quiet hours, health chips, watcher
    banner) run on the threadpool instead of the event loop.

    Returns the full ``ctx`` dict ready to hand to the template.
    """
    from email_triage.web.db import (
        get_dashboard_getting_started,
        get_recent_triage_runs_for_user,
        list_email_accounts,
    )

    db = get_db(request)
    is_admin = user["role"] == "admin"

    ctx: dict = {
        "user": user,
        "is_admin": is_admin,
        "getting_started": get_dashboard_getting_started(db, user),
        "recent_runs": get_recent_triage_runs_for_user(db, user["id"], limit=5),
        "quiet_hours": _current_user_quiet_hours(db, user),
    }

    if is_admin:
        ctx["health_chips"] = _dashboard_health_chips(request, db)
    else:
        ctx["health_chips"] = None

    # Watcher banner: show when any owned account's watcher has been
    # disconnected > 15 min. Admins see any account's banner.
    banner: dict | None = None
    try:
        wm = getattr(request.app.state, "watcher_manager", None)
        if wm is not None:
            if is_admin:
                _accts = list_email_accounts(db)
            else:
                _accts = list_email_accounts(db, user_id=user["id"])
            owned_ids = {a["id"] for a in _accts}
            _name_by_id = {a["id"]: a.get("name", "") for a in _accts}
            _owner_by_id = {
                a["id"]: (a.get("owner_name") or a.get("owner_email", ""))
                for a in _accts
            }
            from datetime import timedelta as _td
            cutoff = datetime.now(timezone.utc) - _td(minutes=15)
            stuck: list[dict] = []
            for acct_id, s in wm.all_statuses().items():
                if acct_id not in owned_ids:
                    continue
                status = s.get("status", "unknown")
                started_at = s.get("started_at")
                if status not in {"reconnecting", "error", "disconnected"}:
                    continue
                bad_since: datetime | None = None
                if started_at:
                    try:
                        bad_since = datetime.fromisoformat(started_at)
                        if bad_since.tzinfo is None:
                            bad_since = bad_since.replace(tzinfo=timezone.utc)
                    except Exception:
                        bad_since = None
                if bad_since is None or bad_since < cutoff:
                    stuck.append({
                        "account_id": acct_id,
                        "account_name": _name_by_id.get(acct_id, ""),
                        "owner": _owner_by_id.get(acct_id, ""),
                        "status": status,
                    })
            if stuck:
                banner = {"stuck": stuck}
    except Exception:
        banner = None
    ctx["watcher_banner"] = banner

    # #149 — LLM-backend health banner. End-user visible. Shows
    # whichever of three states applies:
    #   * healthy (no banner)
    #   * unhealthy + maintenance window (calm copy: "back at HH:MM")
    #   * unhealthy + no window (alert copy: "retrying in N minutes")
    # The banner reads from the in-process circuit-breaker cache
    # (``email_triage.llm_health.health_status``) plus the configured
    # maintenance windows. Queue depth comes from the durable
    # retry queue.
    llm_banner: dict | None = None
    try:
        from email_triage.llm_health import health_status as _llm_status
        cfg = request.app.state.config
        backend_name = getattr(cfg.classifier, "backend", "ollama")
        status = _llm_status(backend_name)
        if not status["healthy"]:
            from email_triage.llm_maintenance import (
                MaintenanceWindow, active_window_for,
            )
            windows_cfg = list(getattr(
                cfg, "llm_maintenance_windows", []
            ) or [])
            rt_windows = [
                MaintenanceWindow(
                    host=w.host, cron=w.cron,
                    duration_minutes=w.duration_minutes,
                    backend=w.backend,
                ) for w in windows_cfg
            ]
            active = active_window_for(backend_name, rt_windows)
            from email_triage.web.triage_retry_queue import queue_depth
            try:
                depth = queue_depth(db)
            except Exception:
                depth = 0
            llm_banner = {
                "backend": backend_name,
                "remaining_minutes": int(
                    (status["remaining_seconds"] or 0) // 60
                ),
                "queued": depth,
                "maintenance_window": (
                    {
                        "host": active.window.host,
                        "ends_at_local_hm": active.ends_at.strftime(
                            "%H:%M UTC"
                        ),
                    } if active is not None else None
                ),
            }
    except Exception:
        llm_banner = None
    ctx["llm_banner"] = llm_banner

    return ctx


def _admin_stats_snapshot(db, request: Request, window: str) -> dict:
    """#135 phase 2 — every read for /admin/stats in one threadpool hop.

    Bundles volume / perf / category / account / error rate plus the
    watcher-state mapping (which itself does an account roster fetch).
    The watcher_manager poll is in-memory dict access; safe to do
    inside the threadpool body.
    """
    from datetime import timedelta
    from email_triage.web.db import (
        count_triage_messages_in_window,
        triage_performance_per_message,
        triage_category_counts,
        triage_account_breakdown,
        triage_error_rate,
        list_email_accounts,
    )

    windows = {
        "1h":  timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d":  timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = windows.get(window, windows["24h"])
    if window not in windows:
        window = "24h"

    now = datetime.now(timezone.utc)
    since_iso = (now - delta).isoformat()

    volume = {
        "window": count_triage_messages_in_window(db, since_iso=since_iso),
        "hour": count_triage_messages_in_window(
            db, since_iso=(now - timedelta(hours=1)).isoformat(),
        ),
        "day": count_triage_messages_in_window(
            db, since_iso=(now - timedelta(hours=24)).isoformat(),
        ),
        "week": count_triage_messages_in_window(
            db, since_iso=(now - timedelta(days=7)).isoformat(),
        ),
        "month": count_triage_messages_in_window(
            db, since_iso=(now - timedelta(days=30)).isoformat(),
        ),
    }

    perf = triage_performance_per_message(db, since_iso=since_iso)
    cats = triage_category_counts(db, since_iso=since_iso)
    accounts_breakdown = triage_account_breakdown(db, since_iso=since_iso)
    err_rate = triage_error_rate(db, since_iso=since_iso)

    watcher_states: list[dict] = []
    try:
        wm = getattr(request.app.state, "watcher_manager", None)
        if wm is not None:
            accounts_by_id = {
                a["id"]: a for a in list_email_accounts(db)
            }
            for acct_id, s in wm.all_statuses().items():
                acct = accounts_by_id.get(acct_id, {})
                watcher_states.append({
                    "account_id": acct_id,
                    "account_name": acct.get("name", ""),
                    "status": s.get("status", "unknown"),
                    "processed": s.get("processed", 0),
                    "errors": s.get("errors", 0),
                    "started_at": s.get("started_at"),
                })
    except Exception:
        pass

    pubsub_configured = False
    try:
        pubsub_configured = bool(
            request.app.state.config.push.gmail_topic_name
        )
    except Exception:
        pass

    # #166 — Push-delivery rollup. Reads the persisted per-(account,
    # provider, day) counter table that the Gmail + O365 webhooks
    # write into on every successful queue.put_nowait. Empty list
    # when the table is empty / unreachable; template renders an
    # "awaiting deliveries" line in that case.
    push_deliveries: list[dict] = []
    push_deliveries_by_day: dict[str, dict[str, int]] = {}
    push_deliveries_days: list[str] = []
    try:
        from email_triage.web.db import get_push_deliveries_window
        push_deliveries = get_push_deliveries_window(db, days=14)
    except Exception:
        push_deliveries = []
    # Re-shape for the template into a per-day rollup:
    #   { "YYYY-MM-DD": {"gmail": N, "office365": M, "total": N+M} }
    # The template needs both the per-day totals (top row) and the
    # per-(account, provider) breakdown rows underneath. Keep both
    # surfaces in one pass.
    for r in push_deliveries:
        day = r["day"]
        slot = push_deliveries_by_day.setdefault(
            day, {"gmail": 0, "office365": 0, "total": 0},
        )
        prov = r["provider"]
        slot[prov] = slot.get(prov, 0) + r["count"]
        slot["total"] += r["count"]
    push_deliveries_days = sorted(
        push_deliveries_by_day.keys(), reverse=True,
    )

    return {
        "window": window,
        "windows": list(windows.keys()),
        "since_iso": since_iso,
        "volume": volume,
        "perf": perf,
        "category_counts": cats,
        "account_breakdown": accounts_breakdown,
        "error_rate": err_rate,
        "watcher_states": watcher_states,
        "pubsub_configured": pubsub_configured,
        "push_deliveries": push_deliveries,
        "push_deliveries_by_day": push_deliveries_by_day,
        "push_deliveries_days": push_deliveries_days,
    }


def _logs_page_snapshot(
    db, level_filter: str | None, offset: int, query: str | None,
) -> dict:
    """#135 phase 2 — log entries + boundary events + account map in one
    threadpool hop."""
    from email_triage.web.db import (
        list_log_entries, list_hipaa_boundary_events, list_email_accounts,
    )
    entries = list_log_entries(
        db, limit=200, level=level_filter, offset=offset, query=query,
    )
    accounts_by_id = {a["id"]: a for a in list_email_accounts(db)}

    rows: list[dict] = []
    if entries:
        oldest = entries[-1].get("ts", "")
        boundaries = list_hipaa_boundary_events(db, since=oldest, limit=200)
        boundary_idx = 0
        for e in entries:
            while (boundary_idx < len(boundaries)
                   and boundaries[boundary_idx]["ts"] > e.get("ts", "")):
                rows.append({**boundaries[boundary_idx], "_kind": "boundary"})
                boundary_idx += 1
            rows.append({**e, "_kind": "log"})
        while boundary_idx < len(boundaries):
            rows.append({**boundaries[boundary_idx], "_kind": "boundary"})
            boundary_idx += 1

    return {"entries": entries, "rows": rows, "accounts_by_id": accounts_by_id}


def _compliance_page_snapshot(db, app_state) -> dict:
    """#135 phase 2 — every read for /compliance in one threadpool hop.

    The page joins seven different tables to assemble the audit view;
    the prior loop fired off a fresh DB hit for every account in the
    boundary lookup. With the GROUP-BY query (#134.3) plus this wrap
    we get a single hop that finishes the whole snapshot.
    """
    from email_triage.web.db import (
        list_email_accounts, list_hipaa_boundary_events, latest_hipaa_boundary,
        latest_hipaa_boundaries_for_accounts,
        list_hipaa_access_events, list_api_key_events, list_discover_runs,
        list_access_events, verify_log_chain,
    )
    from email_triage.triage_logging import (
        is_hipaa_mode, is_account_hipaa, is_account_hipaa_locked,
    )
    import json as _json_decode

    accounts = list_email_accounts(db)
    boundaries_by_scope = latest_hipaa_boundaries_for_accounts(db)
    system_on = is_hipaa_mode()
    rows = []
    for acct in accounts:
        last_event = boundaries_by_scope.get(f"account:{acct['id']}")
        rows.append({
            **acct,
            "effective_hipaa": is_account_hipaa(acct),
            "locked": is_account_hipaa_locked(acct),
            "last_event": last_event,
        })

    recent_events = list_hipaa_boundary_events(db, limit=50)
    system_last = latest_hipaa_boundary(db, "system")
    access_events = list_hipaa_access_events(db, limit=100)
    api_key_events = list_api_key_events(db, limit=100)
    discover_runs_rows = list_discover_runs(db, limit=100)
    for r in discover_runs_rows:
        try:
            r["folders_list"] = _json_decode.loads(r.get("folders") or "[]")
        except (ValueError, TypeError):
            r["folders_list"] = []

    stats = {
        "total": len(rows),
        "per_account_flagged": sum(1 for r in rows if r["hipaa"]),
        "effective_on": sum(1 for r in rows if r["effective_hipaa"]),
    }

    generic_access_events = list_access_events(db, limit=100)
    log_chain = verify_log_chain(db, app_state=app_state)

    return {
        "system_hipaa": system_on,
        "system_last_event": system_last,
        "accounts": rows,
        "recent_events": recent_events,
        "access_events": access_events,
        "api_key_events": api_key_events,
        "discover_runs": discover_runs_rows,
        "generic_access_events": generic_access_events,
        "log_chain": log_chain,
        "stats": stats,
    }


def _users_page_snapshot(db) -> list[dict]:
    """#135 phase 2 — users-list fetch off the loop."""
    rows = db.execute(
        "SELECT id, email, name, role, notify_email, created_at, last_login, "
        "disabled, disabled_at FROM users ORDER BY id"
    ).fetchall()
    return [dict(u) for u in rows]


def _get_lists_for_user(db, user) -> tuple[list[dict], list[dict]]:
    """Return (personal_lists, global_lists) with their rules.

    #129 — each rule dict carries ``adds_labels_list`` (the JSON
    string in ``list_rules.adds_labels`` parsed to a list[str]) so
    the template can render label chips without a Jinja JSON
    filter. Empty / NULL collapses to []. Raw column stays in the
    dict as ``adds_labels`` for round-trip on edit.
    """
    import json as _json

    personal = db.execute(
        """SELECT cl.*, u.email as owner_email FROM classification_lists cl
           LEFT JOIN users u ON cl.owner_id = u.id
           WHERE cl.owner_id = ? ORDER BY cl.id""",
        (user["id"],),
    ).fetchall()
    global_lists = db.execute(
        """SELECT cl.*, u.email as owner_email FROM classification_lists cl
           LEFT JOIN users u ON cl.owner_id = u.id
           WHERE cl.is_global = 1 ORDER BY cl.id""",
    ).fetchall()

    def _enrich(rows):
        result = []
        for row in rows:
            d = dict(row)
            rules = db.execute(
                "SELECT * FROM list_rules WHERE list_id = ? ORDER BY id",
                (d["id"],),
            ).fetchall()
            rules_out = []
            for r in rules:
                r_dict = dict(r)
                raw = r_dict.get("adds_labels")
                if raw:
                    try:
                        parsed = _json.loads(raw)
                        if isinstance(parsed, list):
                            r_dict["adds_labels_list"] = [
                                str(s) for s in parsed
                            ]
                        else:
                            r_dict["adds_labels_list"] = []
                    except Exception:
                        r_dict["adds_labels_list"] = []
                else:
                    r_dict["adds_labels_list"] = []
                # #163 — provider_labels parsed to the same shape the
                # edit-form snapshot delivers (entries carry a
                # pre-computed _key for the picker checkbox).
                r_dict["provider_labels_list"] = _parse_provider_labels(
                    r_dict.get("provider_labels"),
                )
                rules_out.append(r_dict)
            d["rules"] = rules_out
            result.append(d)
        return result

    return _enrich(personal), _enrich(global_lists)


# ---------------------------------------------------------------------------
# Profile / My Settings (per-user escalation prefs)
# ---------------------------------------------------------------------------

def _ordered_timezones() -> list[str]:
    """Full IANA timezone list, America/* first, then other regions, then bare names (UTC).

    Rendered into the timezone <datalist> so users can type-to-filter
    the full ~450-entry tz database rather than a hardcoded handful.
    """
    zones = sorted(available_timezones())
    return (
        [z for z in zones if z.startswith("America/")]
        + [z for z in zones if not z.startswith("America/") and "/" in z]
        + [z for z in zones if "/" not in z]
    )


def _load_meeting_prefs_with_default_tz(db, user_id):
    """Load MeetingPreferences for a user, defaulting timezone to $TZ on a fresh record.

    A user with no saved meeting_prefs (or a stored dict that lacks a
    "timezone" entry) is presented with the container's configured
    timezone rather than the dataclass default of "UTC".
    """
    from email_triage.web.db import get_meeting_prefs
    from email_triage.engine.models import MeetingPreferences

    raw = get_meeting_prefs(db, user_id)
    prefs = MeetingPreferences.from_dict(raw)
    stored_tz = raw.get("timezone") if isinstance(raw, dict) else None
    if not stored_tz:
        prefs.timezone = os.environ.get("TZ", "UTC") or "UTC"
    return prefs


_PROFILE_TABS = ("notifications", "categories", "meeting", "writing")


def _resolve_profile_tab(
    request: Request, form: dict | None = None,
) -> str:
    """Pick the active profile tab from form > query > default.

    POST handlers carry the active tab in a hidden form field
    (``active_tab`` — wired by ``profile.html`` line 21) so a Save
    can re-render the same tab the operator submitted from. GETs
    use the ``?tab=<slug>`` URL param. Falls back to "notifications"
    when neither is set or the value isn't on the allowlist.
    """
    candidate = ""
    if form is not None:
        candidate = (form.get("active_tab") or "").strip()
    if not candidate:
        candidate = (request.query_params.get("tab") or "").strip()
    if candidate not in _PROFILE_TABS:
        candidate = "notifications"
    return candidate


def _writing_tab_context(db, user: dict) -> dict:
    """Build the per-render context for the Profile Writing tab.

    Returns:
      knobs                       — user's stored style knob dict
      writing_master_enabled      — install-wide master toggle state
      writing_hipaa_blocked       — True if any of this user's accounts
                                    are HIPAA-flagged (the form goes
                                    disabled with a chip explaining why;
                                    saving still works for non-HIPAA
                                    accounts but the form helps the user
                                    understand the HIPAA exclusion
                                    up-front).
      anti_ai_user_text           — user's per-user anti-AI guide string
      anti_ai_user_disable_global — flag: user opted to skip the
                                    install-wide anti-AI guide
    """
    from email_triage.web.db import (
        get_user_anti_ai_style_guide,
        get_user_style_knobs,
        is_style_learning_master_enabled,
        list_email_accounts,
    )
    from email_triage.triage_logging import is_account_hipaa, is_hipaa_mode

    knobs = get_user_style_knobs(db, user["id"])
    master_enabled = is_style_learning_master_enabled(db)
    anti_ai_user_text, anti_ai_user_disable_global = (
        get_user_anti_ai_style_guide(db, user["id"])
    )

    # System-HIPAA always counts as blocked. Otherwise, surface the
    # block when the user owns or delegates an account that is itself
    # HIPAA-flagged — the chip explains "your knobs won't apply to
    # those accounts" without disabling the save (so non-HIPAA
    # accounts still benefit).
    hipaa_blocked = bool(is_hipaa_mode())
    if not hipaa_blocked:
        try:
            for acct in list_email_accounts(db, user_id=user["id"]):
                if is_account_hipaa(acct):
                    hipaa_blocked = True
                    break
        except Exception:
            # Defensive — if account listing errors we'd rather render
            # the form than 500 the page.
            pass

    return {
        "knobs": knobs,
        "writing_master_enabled": master_enabled,
        "writing_hipaa_blocked": hipaa_blocked,
        "anti_ai_user_text": anti_ai_user_text,
        "anti_ai_user_disable_global": anti_ai_user_disable_global,
    }


def _profile_page_snapshot(db, user) -> dict:
    """#135 phase 2 — every profile-page DB read in one threadpool hop.

    Pulls categories (system + personal), escalation prefs, meeting
    prefs, SMS prefs, and the writing-tab context. Snapshots collapse
    five-six round-trips into one.
    """
    from email_triage.web.db import (
        list_categories, get_user_escalation_categories,
        get_setting, MAX_PERSONAL_CATEGORIES_PER_USER,
    )
    categories = list_categories(db, user_id=user["id"])
    personal_categories = list_categories(
        db, user_id=user["id"], scope="personal",
    )
    escalation_categories = get_user_escalation_categories(db, user["id"])
    meeting_prefs = _load_meeting_prefs_with_default_tz(db, user["id"])
    sms_prefs = get_setting(db, _S.escalation_sms(user["id"])) or {}
    writing_ctx = _writing_tab_context(db, user)
    return {
        "categories": categories,
        "personal_categories": personal_categories,
        "personal_cap": MAX_PERSONAL_CATEGORIES_PER_USER,
        "escalation_categories": escalation_categories,
        "meeting_prefs": meeting_prefs,
        "sms_prefs": sms_prefs,
        "writing_ctx": writing_ctx,
    }


_ESCALATION_TEST_RL_KEY = "escalation_test_last_send"
_ESCALATION_TEST_RL_WINDOW_SEC = 60


def _test_send_chip_html(
    *,
    state: str,
    when_local: str = "",
    error: str = "",
) -> str:
    """Render the inline result chip for the Test Now button.

    Plain language only — see the audience-per-page rule. No SMTP /
    relay / protocol vocabulary in user-visible copy.

    ``state`` is one of:
      * ``ok``         — message dispatched
      * ``rate_limit`` — second tap within the cooldown window
      * ``no_address`` — defense-in-depth path (button shouldn't render)
      * ``no_category`` — no Escalation Categories ticked
      * ``error``      — send failed; ``error`` carries truncated detail
    """
    # HTML-escape any caller-supplied / exception-derived strings before
    # interpolating into the chip markup. The SMTPException message is
    # server-controlled but technically untrusted (relay returns it),
    # and the timestamp is generated locally, but we escape both
    # defensively so this helper is safe to interpolate without a
    # template engine.
    from html import escape as _esc

    # Truncate any error string to ~80 chars for the chip; full string
    # already lives in the audit row's detail blob.
    err_short = error.strip()
    if len(err_short) > 80:
        err_short = err_short[:77] + "..."

    if state == "ok":
        return (
            '<span style="color:var(--pico-ins-color);">'
            '✓ Sent at {when} — check your phone within 60s'
            '</span>'
        ).format(when=_esc(when_local))
    if state == "rate_limit":
        return (
            '<span style="color:var(--pico-muted-color);">'
            '✗ Please wait a minute before sending another test'
            '</span>'
        )
    if state == "no_address":
        return (
            '<span style="color:var(--pico-del-color);">'
            '✗ No notification address configured'
            '</span>'
        )
    if state == "no_category":
        return (
            '<span style="color:var(--pico-del-color);">'
            '✗ Pick at least one Escalation Category below, then save, '
            'then test'
            '</span>'
        )
    # error
    return (
        '<span style="color:var(--pico-del-color);">'
        '✗ Sender rejected: {err}'
        '</span>'
    ).format(err=_esc(err_short or "unknown error"))


def _short_iso(value: str | None) -> str:
    """Slice the seconds off an ISO-8601 string for friendlier display."""
    if not value or not isinstance(value, str):
        return ""
    return value[:19].replace("T", " ")


def _resolve_managed_accounts(db, user: dict) -> list[dict]:
    """Return the accounts ``user`` may view style data for.

    Order: user's own accounts first, then accounts they're a delegate
    on. Admins are surfaced their own accounts only — admin-side
    review of someone else's data goes through a separate
    administrative path that does not exist in this UI yet (a future
    /admin/users/<id>/style-data lives outside the user-facing
    /profile namespace).
    """
    from email_triage.web.db import list_email_accounts
    rows = list_email_accounts(db, user_id=user["id"])
    return rows


def _build_style_data_entry(
    db,
    acct: dict,
    *,
    actor_user_id: int,
    is_admin_view: bool = False,
) -> dict:
    """Assemble the per-account dict the template renders."""
    from email_triage.web.db import (
        get_style_profile,
        get_sent_mail_index_summary,
        get_captured_pair_count,
    )

    raw_profile = get_style_profile(db, acct["id"])
    profile_present = raw_profile is not None and isinstance(raw_profile, dict)
    profile_built_at = ""
    profile_char_count = 0
    profile_sample_count = 0
    profile_preview = ""
    profile_full = ""
    if profile_present:
        # The persisted profile dict may be a hand-edited row or a
        # rehydrated StyleProfile.to_dict() — be tolerant of either.
        # Prefer a structured persona_summary field; fall back to a
        # JSON-serialised view of the dict for the size + preview.
        import json as _json
        try:
            serialised = _json.dumps(raw_profile, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            serialised = ""
        # Pretty-printed view for the in-page <details> expand. Sort
        # keys so the operator sees a stable shape across renders +
        # indent=2 so deeply-nested structured fields read at a glance.
        try:
            profile_full = _json.dumps(
                raw_profile, ensure_ascii=False,
                sort_keys=True, indent=2,
            )
        except (TypeError, ValueError):
            profile_full = serialised
        profile_char_count = len(serialised)
        profile_sample_count = int(raw_profile.get("sample_count") or 0)
        # Built-at is captured at distillation time, not stored on the
        # profile dict by M-3 (it lives in settings.updated_at). Pull
        # it from the settings table directly so the user can see when
        # the summary last refreshed.
        try:
            row = db.execute(
                "SELECT updated_at FROM settings WHERE key = ?",
                (_S.style_profile(acct["id"]),),
            ).fetchone()
            if row is not None:
                profile_built_at = (
                    row["updated_at"] if hasattr(row, "keys") else row[0]
                ) or ""
        except Exception:
            profile_built_at = ""
        # 200-char preview from persona_summary if present, else from
        # the serialised JSON. We deliberately do NOT show the full
        # raw profile inline — the export endpoint is where the user
        # downloads the complete blob.
        persona = str(raw_profile.get("persona_summary") or "")
        if persona:
            profile_preview = persona[:200]
        else:
            profile_preview = serialised[:200]

    index_summary = get_sent_mail_index_summary(db, acct["id"])
    captured_count = get_captured_pair_count(db, acct["id"])

    # Sample subjects display: under HIPAA, redact in the on-screen
    # view (the export endpoint redacts on its own path).
    if acct.get("hipaa"):
        sample_display: list[str] = []
    else:
        sample_display = list(index_summary.get("sample_subjects") or [])

    # #157 — the Preview / Mine-now buttons need to know whether M-3
    # can fire on this account. For non-HIPAA accounts the source-mail
    # read is unconditionally allowed; for HIPAA-flagged accounts the
    # path requires the per-account ``style_knobs_hipaa_allow`` opt-in
    # (#152 phase 2). Without that opt-in the button renders disabled
    # with a chip explaining how to enable it.
    from email_triage.web.db import (
        is_style_knobs_hipaa_allow,
        is_rag_sent_index_enabled,
    )
    is_hipaa_acct = bool(acct.get("hipaa"))
    m1m2_hipaa_allow = (
        is_style_knobs_hipaa_allow(db, acct["id"])
        if is_hipaa_acct else False
    )
    # Disabled when HIPAA + not opted in. Owner can flip the opt-in
    # on the account's settings tab (the "Your writing-style
    # preferences on this HIPAA account" toggle in /accounts/<id>/edit
    # Integrations section). Non-HIPAA accounts are always enabled.
    mine_disabled = is_hipaa_acct and not m1m2_hipaa_allow

    # 2026-05-11 — AI-learns toggle relocated onto the per-account row.
    # Resolved value reflects #157 HIPAA-aware defaults: non-HIPAA →
    # default ON, HIPAA → default OFF. ``rag_toggle_disabled`` follows
    # the same opt-in gate as the mine button: a HIPAA-flagged account
    # without the M-1+M-2 opt-in can't engage the toggle until the
    # operator opts in on the account-edit page.
    rag_enabled_resolved = is_rag_sent_index_enabled(db, acct["id"], account=acct)
    rag_toggle_disabled = is_hipaa_acct and not m1m2_hipaa_allow

    # #161 item 2 — "Auto-scan on schedule" per-account checkbox.
    # HIPAA-aware default (OFF for HIPAA, ON for non-HIPAA) handled
    # inside :func:`is_auto_scan_enabled_for_account`; the disabled
    # gate matches the AI-learns toggle (HIPAA-without-opt-in renders
    # disabled because the underlying capture loop already short-
    # circuits those accounts, so flipping the checkbox would be a
    # no-op + confuse the operator).
    from email_triage.web.db import (
        is_auto_scan_enabled_for_account,
        resolve_account_mine_limit,
        get_style_learning_mine_limit_default,
    )
    auto_scan_enabled_resolved = is_auto_scan_enabled_for_account(acct)
    auto_scan_toggle_disabled = is_hipaa_acct and not m1m2_hipaa_allow

    # #161 item 4 — per-account "Messages to mine" override + the
    # resolved value the page uses for placeholder display. The
    # explicit override on ``config_json["mine_limit_override"]``
    # surfaces as ``mine_limit_override_value`` (empty string when
    # unset so the input renders blank + the placeholder shows the
    # install default). The resolved value is what the mine-now /
    # preview path will actually run with right now.
    acct_cfg_for_limit = acct.get("config") or {}
    _raw_override = acct_cfg_for_limit.get("mine_limit_override")
    if _raw_override is None or _raw_override == "":
        mine_limit_override_value = ""
    else:
        try:
            mine_limit_override_value = int(_raw_override)
        except (TypeError, ValueError):
            mine_limit_override_value = ""
    mine_limit_install_default = get_style_learning_mine_limit_default(db)
    mine_limit_resolved = resolve_account_mine_limit(db, acct)

    # 2026-05-11 — Sent-folder override (per-account config_json key).
    # Now a list of folder names (one or more sent-like folders the
    # operator wants the AI to fan learning across). Coerce the stored
    # value via ``normalize_sent_folder_override`` so legacy scalar
    # strings (pre-v19) read as a single-element list. The picker uses
    # this list to mark previously-selected entries as ``selected``.
    from email_triage.providers.sent_folder import (
        normalize_sent_folder_override,
    )
    acct_config = acct.get("config") or {}
    sent_folder_override_list = normalize_sent_folder_override(
        acct_config.get("sent_folder_override"),
    )
    # Synthetic preview — matches what ``find_sent_folder`` returns for
    # the provider type when SPECIAL-USE / well-known lookups succeed.
    # IMAP previews as "Sent" (the modal default); the live discovery
    # path runs against the actual mail server when the page-level
    # async decorator adds ``sent_folder_candidates`` on top of this
    # entry.
    ptype = acct.get("provider_type", "")
    if "gmail" in ptype.lower():
        sent_folder_discovered = "SENT"
    elif "office365" in ptype.lower() or "o365" in ptype.lower():
        sent_folder_discovered = "sentitems"
    else:
        sent_folder_discovered = "Sent"

    # Punch list #162 — alias-aware learning. Two surfaces feed the
    # template: ``alias_mode_enabled`` drives the per-account toggle
    # checkbox; ``alias_entries`` is a list of per-alias descriptor
    # rows (from_address + last-built + sample count + preview) the
    # picker renders when the toggle is on. ``alias_addresses`` is the
    # declared address list (primary + configured aliases) and is
    # always non-empty (primary is always present once the account
    # has been saved). The toggle is gated by the same HIPAA opt-in
    # as the AI-learns checkbox — partitioning still reads source mail.
    from email_triage.web.db import (
        account_addresses,
        is_alias_mode_enabled_for_account,
        list_account_style_per_alias,
    )
    declared_addresses = sorted(account_addresses(acct))
    # Show the toggle only when there are 2+ addresses on the account.
    # A single-address account has nothing to partition; rendering the
    # checkbox would just confuse the operator.
    alias_picker_available = len(declared_addresses) >= 2
    alias_mode_enabled = (
        is_alias_mode_enabled_for_account(db, acct["id"])
        if alias_picker_available else False
    )
    # ``alias_toggle_disabled`` mirrors ``rag_toggle_disabled``: the
    # HIPAA opt-in gate applies because partitioning reads From-headers
    # off source mail. Same chip text shape.
    alias_toggle_disabled = is_hipaa_acct and not m1m2_hipaa_allow
    alias_rows_raw = (
        list_account_style_per_alias(db, acct["id"])
        if alias_picker_available else []
    )
    # Render-shape: each row gets a short preview + sample count + a
    # last-built ISO timestamp shortened for display. 2026-05-13 —
    # operator caught that the page-wide "Writing-style summary"
    # section showed only the account-wide descriptor; per-alias
    # descriptors had no full-text surface. Each entry now carries
    # ``descriptor_full`` (pretty-printed JSON) + ``char_count`` so
    # the per-alias picker can render a per-row "Show full summary"
    # expand alongside the account-wide one.
    import json as _json
    alias_entries: list[dict] = []
    for r in alias_rows_raw:
        desc = r.get("descriptor") or {}
        persona = str(desc.get("persona_summary") or "").strip()
        preview = persona[:200] if persona else ""
        try:
            descriptor_full = _json.dumps(
                desc, ensure_ascii=False,
                sort_keys=True, indent=2,
            )
        except (TypeError, ValueError):
            descriptor_full = ""
        try:
            char_count = len(_json.dumps(
                desc, ensure_ascii=False, sort_keys=True,
            ))
        except (TypeError, ValueError):
            char_count = 0
        alias_entries.append({
            "from_address": r.get("from_address") or "",
            "sample_count": int(r.get("sample_count") or 0),
            "updated_at_short": _short_iso(r.get("updated_at") or ""),
            "preview": preview,
            "descriptor_full": descriptor_full,
            "char_count": char_count,
            "is_primary": (
                (r.get("from_address") or "") == (
                    declared_addresses[0] if declared_addresses else ""
                )
            ),
        })

    return {
        "account": acct,
        "is_delegate": bool(acct.get("is_delegate")),
        "is_admin_view": is_admin_view,
        "has_profile": profile_present,
        "profile_built_at_short": _short_iso(profile_built_at),
        "profile_char_count": profile_char_count,
        "profile_full": profile_full,
        "profile_sample_count": profile_sample_count,
        "profile_preview": profile_preview,
        "index_summary": index_summary,
        "index_oldest_short": _short_iso(index_summary.get("oldest")),
        "index_newest_short": _short_iso(index_summary.get("newest")),
        "sample_subjects_display": sample_display,
        "captured_pair_count": captured_count,
        "action_msg": None,
        "action_err": None,
        # #157 — buttons render disabled when M-3 can't fire. The chip
        # explains why so the operator doesn't think the button broke.
        "mine_button_disabled": mine_disabled,
        "mine_disabled_reason": (
            "HIPAA account — turn on \"Your writing-style preferences "
            "on this HIPAA account\" on the account's settings tab to "
            "enable previewing or mining."
            if mine_disabled else ""
        ),
        "m1m2_hipaa_allow": m1m2_hipaa_allow,
        # 2026-05-11 — relocated AI-learns toggle + sent-folder override.
        # ``sent_folder_override_list`` is the post-v19 list shape that
        # the multi-select picker consumes. ``sent_folder_candidates``
        # is populated by the async page handler after this sync
        # snapshot returns (it needs a live provider probe). The empty
        # default here keeps render code safe if the decorator hop is
        # skipped (e.g. cli render path).
        "rag_enabled_resolved": rag_enabled_resolved,
        "rag_toggle_disabled": rag_toggle_disabled,
        "sent_folder_override_list": sent_folder_override_list,
        "sent_folder_discovered": sent_folder_discovered,
        "sent_folder_candidates": [],
        # #161 item 2 + 4
        "auto_scan_enabled_resolved": auto_scan_enabled_resolved,
        "auto_scan_toggle_disabled": auto_scan_toggle_disabled,
        "mine_limit_override_value": mine_limit_override_value,
        "mine_limit_install_default": mine_limit_install_default,
        "mine_limit_resolved": mine_limit_resolved,
        # Punch list #162 — alias-aware learning. ``alias_addresses``
        # is the declared list (primary first); ``alias_entries`` is
        # the per-alias descriptor rows the picker renders.
        "alias_picker_available": alias_picker_available,
        "alias_mode_enabled": alias_mode_enabled,
        "alias_toggle_disabled": alias_toggle_disabled,
        "alias_addresses": declared_addresses,
        "alias_entries": alias_entries,
    }


def _record_style_data_audit(
    db,
    *,
    event_type: str,
    actor_user_id: int,
    actor_email: str,
    account_id: int,
    outcome: str,
    detail: str | None = None,
) -> None:
    """Write the auth_events row for an M-8 action.

    Audit failure is degrade-not-deny: log a warning and keep going.
    Mirrors the discover-run + hipaa-access-event policy in this file.
    """
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type=event_type,
            email=actor_email or "",
            user_id=actor_user_id,
            outcome=outcome,
            detail=(
                f"account_id={account_id}"
                + (f"; {detail}" if detail else "")
            ),
        )
    except Exception as e:
        _log.warning(
            "M-8 style-data audit row failed",
            event_type=event_type,
            account_id=account_id,
            error=fmt_exc(e),
        )


def _record_style_data_hipaa_access(
    db,
    *,
    actor_user_id: int,
    account: dict,
    operation: str,
    outcome: str = "ok",
) -> None:
    """Write a hipaa_access_events row when actor != owner on a HIPAA acct.

    Per feedback_hipaa_actor_owner_gate.md — the gate fires only when:

      account.hipaa is True
      AND actor_user_id != account.user_id

    Owner-self-access is a §164.502(a) self-disclosure carve-out and
    is NOT recorded in hipaa_access_events (the auth_events row above
    captures user-initiated actions for the operator audit lens).
    """
    try:
        from email_triage.triage_logging import is_account_hipaa
        if not is_account_hipaa(account):
            return
        if account.get("user_id") == actor_user_id:
            return
        from email_triage.web.db import record_hipaa_access_event
        record_hipaa_access_event(
            db, actor_user_id, account["id"], operation, outcome=outcome,
        )
    except Exception as e:
        _log.warning(
            "M-8 HIPAA access audit row failed",
            account_id=account.get("id"),
            operation=operation,
            error=fmt_exc(e),
        )


def _resolve_style_data_account(
    db, user: dict, account_id_raw: str | None,
) -> tuple[dict | None, str | None]:
    """Validate ``account_id`` against the user's manageable accounts.

    Returns ``(account_dict, error_message)``. Either the account is
    returned (and error is None) or the account is None and the
    message is the human-readable reason — used by the route handlers
    to render an error inline rather than 404'ing the whole page.
    """
    try:
        account_id = int(account_id_raw) if account_id_raw else 0
    except (TypeError, ValueError):
        return None, "Invalid account id."
    if account_id <= 0:
        return None, "Account id required."

    accts = _resolve_managed_accounts(db, user)
    for a in accts:
        if a["id"] == account_id:
            return a, None
    return None, "You don't have access to that account."


def _profile_style_data_snapshot(db, user) -> dict:
    """#135 phase 2 — every per-account style-data read in one
    threadpool hop.

    #161 additions:
      * ``capture_interval_hours`` — live admin-set cadence for the
        banner at the top of the page.
      * ``mine_limit_install_default`` — install-wide mine-now default,
        surfaced in the per-account placeholder.
      * ``inline_limit_ceiling`` — the cutoff above which the inline
        mine-now path hands off to a bulk job; used by the template
        to label the per-account input.
    """
    from email_triage.web.db import (
        is_style_learning_master_enabled,
        get_style_learning_capture_interval_hours,
        get_style_learning_mine_limit_default,
        STYLE_LEARNING_INLINE_LIMIT_CEILING,
    )
    accounts_raw = _resolve_managed_accounts(db, user)
    entries = [
        _build_style_data_entry(
            db, a, actor_user_id=user["id"],
            is_admin_view=(
                user.get("role") == "admin"
                and a.get("user_id") != user["id"]
            ),
        )
        for a in accounts_raw
    ]
    return {
        "accounts": entries,
        "master_enabled": is_style_learning_master_enabled(db),
        "capture_interval_hours": (
            get_style_learning_capture_interval_hours(db)
        ),
        "mine_limit_install_default": (
            get_style_learning_mine_limit_default(db)
        ),
        "inline_limit_ceiling": STYLE_LEARNING_INLINE_LIMIT_CEILING,
    }


def resolve_embedding_gate(
    *,
    live_backend_type: str | None,
    configured_backend_type: str | None,
    fallback_backend_type: str | None = None,
) -> dict:
    """Compute the embedding-runtime gate for style-learning UIs.

    Returns a dict with three keys:
      * ``required``: True when the configured backend needs a
        runtime install or a reachable remote endpoint.
      * ``ready``:    True when the gate is satisfied.
      * ``reason``:   End-user copy explaining what's blocking; empty
                      when nothing is blocking.

    Per ``feedback_no_admin_path_in_user_copy``: the copy mentions
    "the AI Backends config page" by name but does NOT include the
    literal ``/config?tab=ai_backends`` URL. The disabled state
    communicates that admin action is needed without giving end
    users a clickable admin path.

    Four cases:
      1. ``configured_backend_type == "sentence_transformers"`` AND
         the runtime is importable (or already loaded live) → ready.
      2. ``configured_backend_type == "sentence_transformers"`` AND
         the runtime is NOT importable AND ``fallback_backend_type``
         names a non-empty fallback (typically ``ollama``) → ready.
         ``FallbackEmbeddingBackend`` catches the primary's
         ``ImportError`` on the first ``embed_text`` call and
         routes to the backup, so the subsystem is functionally
         available — just slower per-call than the in-process MiniLM
         primary would be. Per-call latency is acceptable; blocking
         the entire feature is not.
      3. ``configured_backend_type == "sentence_transformers"`` AND
         no runtime AND no fallback → block; admin must install the
         bits (or wire a fallback in YAML).
      4. ``configured_backend_type == "ollama"`` → ready; live-call
         failures surface via the FallbackEmbeddingBackend wrapper.
         (A future improvement is a synchronous probe against the
         configured URL; deferred so this gate stays cheap.)
      5. Backend unset / empty → block; reason directs the admin to
         configure a backend.

    The ``live_backend_type == "fallback"`` short-circuit on case 1
    is a defense: when the running process has already constructed
    the FallbackEmbeddingBackend wrapper successfully, the subsystem
    IS loaded regardless of whether the local primary can fire on a
    given call.

    Inputs are intentionally string-typed (not dependent on app
    state directly) so this helper can be unit-tested without a
    FastAPI app.

    2026-05-18: the ``fallback_backend_type`` parameter was added
    after operator observation that a configured ollama fallback on
    a primary=sentence_transformers install was being ignored — the
    gate blocked style-learning UI even though the subsystem worked
    via fallback. Callers MUST pass ``fallback_backend_type`` when
    a fallback section exists in YAML; default to ``None`` preserves
    pre-2026-05-18 behavior for any caller that doesn't know about
    fallback chains.
    """
    btype = (configured_backend_type or "").strip().lower()
    fb_btype = (fallback_backend_type or "").strip().lower()

    if not btype:
        return {
            "required": True,
            "ready": False,
            "reason": (
                "Style learning is disabled. Configure an embedding "
                "backend on the AI Backends config page."
            ),
        }

    if btype == "sentence_transformers":
        # Live backend = sentence_transformers reaching this function
        # means the runtime IS importable (the live backend wouldn't
        # have loaded otherwise). If only the configured-type is
        # sentence_transformers but no live backend loaded, the
        # runtime probe is the truth.
        try:
            from email_triage.embedding_bits import is_runtime_ready
            ready = bool(is_runtime_ready())
        except Exception:  # noqa: BLE001
            ready = False
        # When the live backend already loaded sentence_transformers
        # OR a fallback-chain wrapper (which subsumes the primary +
        # backup pair), we know the subsystem is functionally
        # available regardless of the cached runtime probe.
        if live_backend_type in ("sentence_transformers", "fallback"):
            ready = True
        if not ready:
            # 2026-05-18: configured fallback rescues a not-installed
            # primary. The FallbackEmbeddingBackend wrapper routes
            # the call to the backup when primary raises, so the
            # subsystem remains available. Block ONLY when there's
            # no fallback to fall through to.
            if fb_btype:
                return {"required": True, "ready": True, "reason": ""}
            return {
                "required": True,
                "ready": False,
                "reason": (
                    "This feature requires the local embedding "
                    "backend. Install it from the AI Backends config "
                    "page."
                ),
            }
        return {"required": True, "ready": True, "reason": ""}

    if btype == "ollama":
        return {"required": True, "ready": True, "reason": ""}

    return {
        "required": True,
        "ready": False,
        "reason": (
            "Style learning is disabled. The configured embedding "
            "backend is not recognised — check the AI Backends "
            "config page."
        ),
    }


def _build_rules_page_snapshot(db, user: dict) -> dict:
    """#135 phase 2 — lists + categories in one threadpool hop.

    /rules pulls personal-and-global lists plus the categories list
    (rendered as the type-ahead in the inline-add-rule controls).
    Both are independent reads that previously serialised on the loop.

    #129 — also include the labels catalog so the "Also adds labels"
    multi-select on the rule form can render the available slugs.

    2026-05-17 fix: categories MUST be fetched user-scoped so the
    "Suggested Category" dropdown surfaces the operator's personal
    categories alongside the system set. The pre-fix unscoped call
    (``_get_categories_from_db(db)``) only returned ``user_id IS
    NULL`` rows — personal categories defined via the Categories
    management page were silently filtered from the rules dropdown.
    """
    from email_triage.web.db import list_labels
    personal, global_lists = _get_lists_for_user(db, user)
    cats = _get_categories_from_db(db, user_id=user["id"])
    all_labels = list_labels(db)
    return {
        "personal_lists": personal,
        "global_lists": global_lists,
        "categories": cats,
        "all_labels": all_labels,
    }


def _create_list_snapshot(
    db, name, category, owner_id, is_global, rule_type, pattern, skip_ai,
    adds_labels=None, provider_labels=None,
) -> bool:
    """#135 phase 2 — list insert + optional first-rule insert + commit
    in one threadpool hop. Returns is_global flag for the redirect.

    ``adds_labels`` (#129) is a list of label slugs attached to the
    first rule (if a first rule is created). Persisted as a JSON
    array string in ``list_rules.adds_labels``. None / empty list
    omit the column write.

    ``provider_labels`` (#163) is a list of
    ``{"account_id": int, "label_slug": str}`` dicts persisted as a
    JSON array string in ``list_rules.provider_labels``. None /
    empty list writes NULL.
    """
    import json as _json
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
        (name, category, owner_id, int(is_global), now),
    )
    new_list_id = db.execute(
        "SELECT last_insert_rowid() AS id"
    ).fetchone()["id"]
    pattern_clean = (pattern or "").strip()
    if pattern_clean:
        rt = rule_type if rule_type in (
            "sender", "sender_domain", "subject"
        ) else "sender"
        labels_json = (
            _json.dumps(list(adds_labels))
            if adds_labels else None
        )
        provider_labels_json = (
            _json.dumps(list(provider_labels))
            if provider_labels else None
        )
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
            "adds_labels, provider_labels, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_list_id, rt, pattern_clean, int(skip_ai == "1"),
             labels_json, provider_labels_json, now),
        )
    db.commit()
    return is_global


def _delete_list_snapshot(
    db, list_id: int, user_id: int, user_role: str,
) -> tuple[str, bool]:
    """#135 phase 2 — auth check + delete + commit in one hop. Returns
    ('ok' | 'not_found' | 'forbidden', is_global)."""
    row = db.execute(
        "SELECT owner_id, is_global FROM classification_lists WHERE id = ?",
        (list_id,),
    ).fetchone()
    if row is None:
        return "not_found", False
    if row["owner_id"] != user_id and user_role != "admin":
        return "forbidden", False
    db.execute(
        "DELETE FROM classification_lists WHERE id = ?", (list_id,),
    )
    db.commit()
    return "ok", bool(row["is_global"])


def _add_rule_snapshot(
    db, list_id, rule_type, pattern, skip_ai, user_id, user_role,
    adds_labels=None, provider_labels=None,
) -> tuple[str, bool]:
    """#135 phase 2 — auth check + insert + commit in one threadpool
    hop. Returns ('ok' | 'not_found' | 'forbidden', is_global).

    ``adds_labels`` (#129) — list of label slugs persisted as a JSON
    array string in ``list_rules.adds_labels``. Additive — labels
    fire alongside the category, not in place of it.

    ``provider_labels`` (#163) — list of
    ``{"account_id": int, "label_slug": str}`` dicts persisted as a
    JSON array string in ``list_rules.provider_labels``. Per-account
    scope; only entries whose account_id matches the message's
    account fire at apply time.
    """
    import json as _json
    row = db.execute(
        "SELECT owner_id, is_global FROM classification_lists WHERE id = ?",
        (list_id,),
    ).fetchone()
    if row is None:
        return "not_found", False
    if row["owner_id"] != user_id and user_role not in ("admin", "power_user"):
        return "forbidden", False
    now = datetime.now(timezone.utc).isoformat()
    labels_json = (
        _json.dumps(list(adds_labels))
        if adds_labels else None
    )
    provider_labels_json = (
        _json.dumps(list(provider_labels))
        if provider_labels else None
    )
    db.execute(
        "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
        "adds_labels, provider_labels, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (list_id, rule_type, pattern, int(skip_ai == "1"),
         labels_json, provider_labels_json, now),
    )
    db.commit()
    return "ok", bool(row["is_global"])


def _delete_rule_snapshot(
    db, list_id, rule_id, user_id, user_role,
) -> tuple[str, bool]:
    """#135 phase 2 — auth check + delete + commit in one hop."""
    row = db.execute(
        "SELECT owner_id, is_global FROM classification_lists WHERE id = ?",
        (list_id,),
    ).fetchone()
    if row is None:
        return "not_found", False
    if row["owner_id"] != user_id and user_role not in ("admin", "power_user"):
        return "forbidden", False
    db.execute(
        "DELETE FROM list_rules WHERE id = ? AND list_id = ?",
        (rule_id, list_id),
    )
    db.commit()
    return "ok", bool(row["is_global"])


def _get_rule_snapshot(
    db, list_id: int, rule_id: int, user_id: int, user_role: str,
):
    """#160 — fetch a single rule (with owner auth + adds_labels
    parsed back into a list) in one threadpool hop. Returns
    ('ok', rule_dict, list_row) | ('not_found', None, None) |
    ('forbidden', None, None).

    #163 — also parses ``provider_labels`` JSON into a list of
    ``{"account_id", "label_slug", "_key"}`` dicts so the rule-editor
    template can compare against the checkbox values in O(1) without
    a Jinja JSON filter. ``_key`` is the form-value form
    ``<account_id>:<label_slug>`` that the picker emits.
    """
    import json as _json
    list_row = db.execute(
        "SELECT id, owner_id, is_global FROM classification_lists WHERE id = ?",
        (list_id,),
    ).fetchone()
    if list_row is None:
        return "not_found", None, None
    if list_row["owner_id"] != user_id and user_role not in ("admin", "power_user"):
        return "forbidden", None, None
    # SELECT * is cheap here and tolerates pre-v22 schemas (the column
    # access is wrapped in a presence check below).
    rule_row = db.execute(
        "SELECT * FROM list_rules WHERE id = ? AND list_id = ?",
        (rule_id, list_id),
    ).fetchone()
    if rule_row is None:
        return "not_found", None, None
    rule = dict(rule_row)
    raw = rule.pop("adds_labels", None)
    try:
        rule["adds_labels_list"] = (
            _json.loads(raw) if raw else []
        )
    except Exception:
        rule["adds_labels_list"] = []
    raw_pl = rule.pop("provider_labels", None)
    rule["provider_labels_list"] = _parse_provider_labels(raw_pl)
    return "ok", rule, dict(list_row)


def _parse_provider_labels(raw) -> list[dict]:
    """Helper — parse the ``list_rules.provider_labels`` JSON string
    into the template-ready shape.

    Each output entry has:
      * ``account_id`` — int
      * ``label_slug`` — str
      * ``_key``       — ``<account_id>:<label_slug>`` (the form value
                          emitted by the picker checkbox)

    Malformed entries (missing keys, wrong types) are silently dropped
    so a half-written column doesn't crash the page render.
    """
    import json as _json
    if not raw:
        return []
    try:
        parsed = _json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    out: list[dict] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        aid = entry.get("account_id")
        slug = entry.get("label_slug")
        if not isinstance(aid, int) or not isinstance(slug, str):
            continue
        if not slug:
            continue
        out.append({
            "account_id": aid,
            "label_slug": slug,
            "_key": f"{aid}:{slug}",
        })
    return out


def _save_rule_snapshot(
    db, list_id: int, rule_id: int, rule_type: str, pattern: str,
    skip_ai: str, user_id: int, user_role: str,
    adds_labels=None, provider_labels=None,
) -> tuple[str, dict | None, dict | None]:
    """#160 — update an existing rule in-place. Auth-checks the
    owning list, validates rule_type, persists the same shape the
    create + add-rule paths persist (adds_labels JSON), and returns
    the freshly-loaded rule + list rows for the row partial render.

    #163 — also persists the new ``provider_labels`` JSON column
    (per-account provider-native label assignments).

    Returns ('ok', rule, list_row) | ('not_found', None, None) |
    ('forbidden', None, None).
    """
    import json as _json
    list_row = db.execute(
        "SELECT id, owner_id, is_global FROM classification_lists WHERE id = ?",
        (list_id,),
    ).fetchone()
    if list_row is None:
        return "not_found", None, None
    if list_row["owner_id"] != user_id and user_role not in ("admin", "power_user"):
        return "forbidden", None, None
    rule_row = db.execute(
        "SELECT id FROM list_rules WHERE id = ? AND list_id = ?",
        (rule_id, list_id),
    ).fetchone()
    if rule_row is None:
        return "not_found", None, None
    rt = rule_type if rule_type in (
        "sender", "sender_domain", "subject"
    ) else "sender"
    labels_json = (
        _json.dumps(list(adds_labels))
        if adds_labels else None
    )
    provider_labels_json = (
        _json.dumps(list(provider_labels))
        if provider_labels else None
    )
    db.execute(
        "UPDATE list_rules SET rule_type = ?, pattern = ?, "
        "skip_ai = ?, adds_labels = ?, provider_labels = ? "
        "WHERE id = ? AND list_id = ?",
        (rt, pattern.strip(), int(skip_ai == "1"),
         labels_json, provider_labels_json, rule_id, list_id),
    )
    db.commit()
    # Re-fetch + parse the same shape the page snapshot delivers.
    updated = db.execute(
        "SELECT * FROM list_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    rule = dict(updated)
    raw = rule.pop("adds_labels", None)
    try:
        rule["adds_labels_list"] = (
            _json.loads(raw) if raw else []
        )
    except Exception:
        rule["adds_labels_list"] = []
    raw_pl = rule.pop("provider_labels", None)
    rule["provider_labels_list"] = _parse_provider_labels(raw_pl)
    return "ok", rule, dict(list_row)


def _require_admin_user(request: Request):
    """Return user dict or raise redirect/403."""
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _build_categories_page_snapshot(db, scope: str) -> dict:
    """#135 phase 2 — categories list + owner map in one threadpool hop."""
    from email_triage.web.db import list_categories
    if scope not in ("all", "system", "personal"):
        scope = "all"
    if scope == "system":
        cats = list_categories(db, scope="system")
    elif scope == "personal":
        rows = db.execute(
            "SELECT id, user_id, slug, description, sort_order FROM categories "
            "WHERE user_id IS NOT NULL ORDER BY sort_order, id"
        ).fetchall()
        cats = [dict(r) for r in rows]
    else:
        rows = db.execute(
            "SELECT id, user_id, slug, description, sort_order FROM categories "
            "ORDER BY user_id IS NOT NULL, sort_order, id"
        ).fetchall()
        cats = [dict(r) for r in rows]

    owners_by_id: dict[int, dict] = {}
    user_rows = db.execute(
        "SELECT id, email, name FROM users"
    ).fetchall()
    for u in user_rows:
        owners_by_id[u["id"]] = dict(u)

    return {"categories": cats, "scope": scope, "owners_by_id": owners_by_id}


def _categories_create_snapshot(
    db, slug: str, description: str,
) -> tuple[bool, list]:
    """#135 phase 2 — create + list in one threadpool hop. Returns
    (success, categories_list)."""
    from email_triage.web.db import list_categories, create_category
    success = True
    try:
        create_category(db, slug, description)
    except Exception:
        success = False
    return success, list_categories(db)


def _categories_update_snapshot(
    db, cat_id: int, slug: str, description: str,
) -> dict | None:
    """#135 phase 2 — write + read-back in one threadpool hop."""
    from email_triage.web.db import update_category, get_category
    update_category(db, cat_id, slug, description)
    return get_category(db, cat_id)


def _personal_category_create_snapshot(
    db, slug: str, description: str, user_id: int,
) -> tuple[str, list]:
    """#135 phase 2 — create + list in one threadpool hop. Returns
    (error_msg, personal_categories)."""
    from email_triage.web.db import create_category, list_categories
    error = ""
    try:
        create_category(db, slug, description, user_id=user_id)
    except ValueError as e:
        error = str(e)
    except Exception:
        error = f"Category '{slug}' already exists for your account."
    personal_categories = list_categories(
        db, user_id=user_id, scope="personal",
    )
    return error, personal_categories


def _personal_category_delete_snapshot(
    db, cat_id: int, user_id: int,
) -> tuple[str, list]:
    """#135 phase 2 — fetch + auth check + delete + re-list in one
    threadpool hop. Returns ('ok' | 'forbidden', personal_categories)."""
    from email_triage.web.db import (
        get_category, delete_category, list_categories,
    )
    cat = get_category(db, cat_id)
    if cat is None or cat.get("user_id") != user_id:
        return "forbidden", []
    delete_category(db, cat_id)
    personal_categories = list_categories(
        db, user_id=user_id, scope="personal",
    )
    return "ok", personal_categories


def _categories_demote_form_snapshot(
    db, cat_id: int,
) -> tuple[str, dict | None, list]:
    """#135 phase 2 — fetch + user-roster in one threadpool hop.
    Returns ('ok' | 'not_found' | 'not_system', cat, users)."""
    from email_triage.web.db import get_category
    cat = get_category(db, cat_id)
    if cat is None:
        return "not_found", None, []
    if cat.get("user_id") is not None:
        return "not_system", cat, []
    user_rows = db.execute(
        "SELECT id, email, name FROM users "
        "ORDER BY COALESCE(NULLIF(name, ''), email)"
    ).fetchall()
    return "ok", cat, [dict(u) for u in user_rows]


_PROVIDER_TYPES = {"imap", "gmail_api", "office365"}


def _secret_key_for_account(account_id: int, provider_type: str) -> str | None:
    """Return the secrets-store key name for an account's password/secret.

    Delegates to :func:`providers.traits.secret_key_for_account`
    (#138.2). Kept under the old name so the 7+ call sites in this
    module continue to work without churn.
    """
    from email_triage.providers.traits import secret_key_for_account
    return secret_key_for_account(account_id, provider_type)


def _enrich_account(acct: dict, secrets) -> dict:
    """Add has_password / has_secret flags without exposing actual values."""
    sk = _secret_key_for_account(acct["id"], acct["provider_type"])
    if sk and secrets:
        val = secrets.get(sk)
        if acct["provider_type"] == "imap":
            acct["has_password"] = bool(val)
        elif acct["provider_type"] == "office365":
            acct["has_secret"] = bool(val)
        elif acct["provider_type"] == "gmail_api":
            acct["has_refresh_token"] = bool(val)
    return acct


def _build_accounts_page_snapshot(request: Request, user: dict) -> dict:
    """#135 phase 2 — single threadpool snapshot for /accounts.

    Bundles every sync DB read on the page (users list, account roster,
    enrichment chips that hit settings + secrets) so the operator-facing
    list page doesn't serialise behind any one slow query.
    """
    db = get_db(request)
    secrets = get_secrets(request)
    is_admin = user["role"] == "admin"

    from email_triage.web.app import get_request_accounts, get_watcher_manager

    owner_param_raw = request.query_params.get("owner")
    owner_param = (owner_param_raw or "").strip()
    selected_owner: int | str = "all"
    all_users: list[dict] = []
    if is_admin:
        all_users = db.execute(
            "SELECT id, email, name FROM users ORDER BY email"
        ).fetchall()
        all_users = [dict(u) for u in all_users]
        total_accounts = len(get_request_accounts(request))
        if owner_param_raw is None:
            selected_owner = user["id"]
            accounts = get_request_accounts(request, user_id=user["id"])
        elif owner_param == "all":
            accounts = get_request_accounts(request)
            selected_owner = "all"
        else:
            try:
                selected_owner = int(owner_param)
                accounts = get_request_accounts(
                    request, user_id=selected_owner,
                )
            except ValueError:
                accounts = get_request_accounts(request)
                selected_owner = "all"
    else:
        accounts = get_request_accounts(request, user_id=user["id"])
        total_accounts = len(accounts)

    try:
        watcher_mgr = get_watcher_manager(request)
    except Exception:
        watcher_mgr = None

    for acct in accounts:
        _enrich_account(acct, secrets)
        _enrich_account_chips(
            acct, db, secrets, watcher_mgr=watcher_mgr,
            config=request.app.state.config,
        )

    flash_success = request.query_params.get("success") or ""
    flash_error = request.query_params.get("error") or ""

    return {
        "user": user,
        "accounts": accounts,
        "is_admin": is_admin,
        "all_users": all_users,
        "selected_owner": selected_owner,
        "total_accounts": total_accounts,
        "shown_accounts": len(accounts),
        "success": flash_success,
        "error": flash_error,
    }


def _api_keys_page_snapshot(db, user: dict) -> dict:
    """#135 phase 2 — keys + users in one threadpool hop."""
    from email_triage.web.auth import list_api_keys
    is_admin = user["role"] == "admin"
    if is_admin:
        keys = list_api_keys(db)
        all_users = db.execute(
            "SELECT id, email, name FROM users ORDER BY email"
        ).fetchall()
        all_users = [dict(u) for u in all_users]
    else:
        keys = list_api_keys(db, user_id=user["id"])
        all_users = []
    return {"keys": keys, "all_users": all_users, "is_admin": is_admin}


def _extract_provider_config(
    form, ptype: str, existing: dict | None = None,
) -> dict[str, Any]:
    """Extract non-secret config fields from form data by provider type.

    ``existing`` is the current stored config; we use it to preserve
    fields the form didn't submit (e.g. a blank password field keeps
    the stored secret, a missing ``push_enabled`` doesn't silently
    clobber it unless the form was actually rendered with the checkbox
    present — see the ``__ingestion_fields_present`` marker).
    """
    existing = existing or {}
    # 2026-05-13 — start from the existing config dict so fields the
    # edit form doesn't expose (``sent_folder_override``,
    # ``calendars``, ``calendar_surrogate_account_id``, ``tz``,
    # ``recipient_digest_*``, per-provider extras) survive a Save.
    # Long-standing latent bug: previous implementation built a fresh
    # dict + only set what the form carried, silently wiping every
    # other key on every Save. Operator caught it 2026-05-13 when
    # adding the new ``email_address`` field cleared their
    # ``sent_folder_override = ['Sent Items', 'Sent']`` selection.
    # The form fields below still take precedence — this just
    # establishes a defensible default for keys the form omits.
    config: dict[str, Any] = dict(existing)
    if ptype == "imap":
        config["host"] = form.get("host", "")
        config["port"] = int(form.get("port", 993))
        config["username"] = form.get("username", "")
        # 2026-05-13 — separate "Your email address" field on the
        # IMAP edit form. The LOGIN username on many IMAP servers
        # (Dovecot with a default domain, Cyrus with virtual hosts)
        # is bare (``you``) — not the operator's actual sending
        # address (``you@example.com``). Without this field,
        # ``account_email`` returns the bare LOGIN, alias-mode
        # bucketing never matches the real From: header, and
        # style-mining drops every message into the "unknown
        # alias" pile. Empty value falls through to the username
        # legacy path in ``account_email``.
        config["email_address"] = form.get("email_address", "").strip()
        # 2026-05-13 — operator override for the Drafts folder
        # (see _fields_imap.html for the operator-facing copy).
        # Empty string = "auto-detect"; trimmed so a stray space
        # doesn't break the equality check against the server's
        # exact folder name.
        config["drafts_folder"] = form.get("drafts_folder", "").strip()
        config["use_ssl"] = "use_ssl" in form
        # Multi-mailbox: the edit form submits a ``mailboxes[]`` field
        # (one value per checkbox). Starlette exposes that as
        # ``form.getlist("mailboxes")``. Fall back to the legacy single
        # ``mailbox`` field for the add-account form which hasn't been
        # migrated yet, and finally to a comma-separated text field for
        # the folder-discovery-failed path.
        mailboxes: list[str] = []
        if hasattr(form, "getlist"):
            mailboxes = [m for m in form.getlist("mailboxes") if m]
        if not mailboxes:
            csv = form.get("mailboxes_csv", "").strip()
            if csv:
                mailboxes = [m.strip() for m in csv.split(",") if m.strip()]
        if not mailboxes:
            single = form.get("mailbox", "").strip()
            if single:
                mailboxes = [single]
        if not mailboxes:
            # Preserve the existing selection if the form submitted none
            # (e.g. the fields_imap fragment stayed on the legacy
            # mailbox-only shape). Default to INBOX for a fresh account.
            mailboxes = list(existing.get("mailboxes") or []) or ["INBOX"]
        # De-dup while preserving order.
        seen = set()
        deduped = []
        for m in mailboxes:
            if m in seen:
                continue
            seen.add(m)
            deduped.append(m)
        config["mailboxes"] = deduped
        # Forward-compat shim: keep the legacy ``mailbox`` key in sync
        # with mailboxes[0] so any code path still reading the old key
        # gets the primary folder. Plan to drop this write once all
        # readers have migrated.
        config["mailbox"] = deduped[0]
    elif ptype == "gmail_api":
        config["account"] = form.get("account", "")
        # Calendar opt-in: if checked, the single Authenticate flow
        # appends CALENDAR_SCOPES to the OAuth request. Stored as a
        # bool in the account config so the scope-union helper can
        # read it at auth time.
        config["calendar_opted_in"] = "calendar_opted_in" in form
        # Per-account poll cadence override (B3). Blank → server
        # default wins. Stored in minutes; bounds enforced by the
        # history_poll_loop, not here, because the "valid range"
        # depends on the account's current mode (push vs poll) and
        # the loop is the authority on which mode the account is in.
        override_raw = (form.get("poll_interval_override") or "").strip()
        if override_raw:
            try:
                config["poll_interval_override"] = int(override_raw)
            except ValueError:
                pass  # Silently drop malformed; UI shows blank.
    elif ptype == "office365":
        config["is_personal_msa"] = "is_personal_msa" in form
        config["calendar_opted_in"] = "calendar_opted_in" in form
        # Belt-and-braces scrub of legacy per-account OAuth keys —
        # the DB migration (migrate_o365_creds_to_install_level) does
        # the bulk lift at startup, but a hand-edited config_json or
        # an unmigrated row could still carry these.
        config.pop("client_id", None)
        config.pop("tenant_id", None)
        config.pop("client_secret", None)

    # ── Unified push + poll knobs (all providers) ──
    # The edit form always includes a hidden ``__ingestion_fields_present``
    # marker when the Real-Time Watch section is rendered, so a user
    # unchecking a checkbox is distinguishable from the section not
    # being present on the form at all (add-account flow).
    if "__ingestion_fields_present" in form:
        config["push_enabled"] = "push_enabled" in form
        config["poll_enabled"] = "poll_enabled" in form
        raw_iv = (form.get("poll_interval_minutes") or "").strip()
        if raw_iv:
            try:
                from email_triage.web.db import clamp_poll_interval_minutes
                config["poll_interval_minutes"] = clamp_poll_interval_minutes(
                    int(raw_iv),
                )
            except (TypeError, ValueError):
                # Fall through to existing value or default.
                if "poll_interval_minutes" in existing:
                    config["poll_interval_minutes"] = existing[
                        "poll_interval_minutes"
                    ]
                else:
                    config["poll_interval_minutes"] = 60
        else:
            # Blank — keep existing or default to 60.
            if "poll_interval_minutes" in existing:
                config["poll_interval_minutes"] = existing[
                    "poll_interval_minutes"
                ]
            else:
                config["poll_interval_minutes"] = 60
    else:
        # Preserve whatever's already stored; the back-compat shim will
        # synthesize defaults on the next read if nothing's there.
        for k in ("push_enabled", "poll_enabled", "poll_interval_minutes"):
            if k in existing:
                config[k] = existing[k]

    # ── Recipient daily-digest knobs (all providers) ──
    # Toggle + send-time on the same form; checkbox absent means
    # opt-out, not "not on form" (the fieldset is always rendered
    # in the edit template).
    config["recipient_digest_enabled"] = (
        "recipient_digest_enabled" in form
    )
    raw_send_at = (
        form.get("recipient_digest_send_at") or ""
    ).strip()
    # Validate: must be HH:10 in [00,23]. Drop anything else; the
    # scheduler tick refuses to fire on a malformed value anyway,
    # but stamping a clean value keeps the YAML round-trip readable.
    if raw_send_at and len(raw_send_at) == 5 and raw_send_at.endswith(":10"):
        try:
            h = int(raw_send_at.split(":")[0])
            if 0 <= h <= 23:
                config["recipient_digest_send_at"] = f"{h:02d}:10"
            else:
                config["recipient_digest_send_at"] = "08:10"
        except (TypeError, ValueError):
            config["recipient_digest_send_at"] = "08:10"
    else:
        # Preserve existing if present; default to 08:10.
        config["recipient_digest_send_at"] = existing.get(
            "recipient_digest_send_at", "08:10",
        )

    # Preserve config keys owned by dedicated endpoints — the main
    # account-save form doesn't render fields for them, so leaving
    # them out of ``config`` here would silently clobber them on
    # every Save. Each key has its own POST handler that writes it:
    #
    #   calendars                       <- /calendars/save
    #   calendar_surrogate_account_id   <- /calendar/surrogate
    #
    # Add new dedicated-endpoint keys to this list when they ship
    # so the main Save button stays a no-op against them.
    for preserved_key in (
        "calendars",
        "calendar_surrogate_account_id",
    ):
        if preserved_key in existing:
            config[preserved_key] = existing[preserved_key]

    # ── M-7 per-contact style-layering sub-toggle ──────────────
    # Read from the integrations-tab checkbox. Checkbox absent ⇒
    # operator unchecked it (or the form was rendered with the
    # field disabled because the account is HIPAA). Checkbox
    # present + value=1 ⇒ on. The integrations tab is always
    # rendered on the edit form; treat absence as opt-out.
    #
    # We only persist the flag when the parent M-4 RAG section is
    # rendered on the form (it is rendered for every account that
    # passes the HIPAA gate). For HIPAA accounts the input is
    # disabled in the template -- the form won't carry the field
    # at all, so we preserve whatever was previously stored
    # (defence in depth: even though the SentMailIndex helper
    # short-circuits HIPAA, leaving stale config alone avoids a
    # silent flip if the account is later un-HIPAA'd).
    if "rag_sent_index_enabled" in form or "style_learning_per_contact_enabled" in form:
        config["style_learning_per_contact_enabled"] = (
            "style_learning_per_contact_enabled" in form
        )
    elif "style_learning_per_contact_enabled" in existing:
        config["style_learning_per_contact_enabled"] = existing[
            "style_learning_per_contact_enabled"
        ]

    # ── Per-account timezone (#109) ─────────────────────────────
    # IANA zone string used for the calendar API's pre-rendered
    # local-time fields. Validate against zoneinfo; fall back to
    # the existing stored value, then to America/Detroit (the
    # backfill-migration default). Never default to UTC — UTC
    # times are not meant for the human-render path.
    raw_tz = (form.get("tz") or "").strip()
    chosen_tz = None
    if raw_tz:
        try:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
            try:
                ZoneInfo(raw_tz)
                chosen_tz = raw_tz
            except ZoneInfoNotFoundError:
                chosen_tz = None
        except ImportError:  # pragma: no cover — stdlib since 3.9
            chosen_tz = raw_tz
    if chosen_tz is None:
        chosen_tz = existing.get("tz") or "America/Detroit"
    config["tz"] = chosen_tz

    return config


def _save_provider_secret(form, ptype: str, account_id: int, secrets) -> None:
    """Store password/secret from form into the secrets provider.

    Migrated to traits-driven dispatch (#138.2): the per-provider
    form-field name + secret key shape live on ``ProviderTraits``,
    so this fn collapses the original IMAP / O365 if-branches to
    a single registry lookup. Gmail's traits entry has
    ``secret_form_field=None`` because the refresh token is set by
    the OAuth callback, not a form submission.
    """
    from email_triage.providers.traits import get_traits
    traits = get_traits(ptype)
    if traits is None or not traits.secret_form_field:
        return
    val = form.get(traits.secret_form_field, "")
    if val:
        secrets.set(_secret_key_for_account(account_id, ptype), val)


# ---------------------------------------------------------------------------
# #95 sub-A — account-setup wizard (auto-chained flow)
#
# Five-step linear flow at /accounts/new?step=N replacing the
# Save → Back → Save → Back loop on the previous edit-page-driven
# add flow. Each step submits to a dedicated POST handler that does
# its work and redirects to the next step's GET. State carried via
# URL query params + hidden form fields; resume state lives in a
# settings-table row keyed `account_state:<id>:wizard_step` so a
# returning operator can pick up where they left off via a banner
# rendered on the account edit page.
#
# Skip-step heuristics — when an operator's choices make a step
# trivial we redirect through it, marking it on the progress strip:
#   * Step 3 skipped when only the inbox is selectable AND OAuth
#     scopes are at default (push reduces to "off" / "poll only").
#   * Step 4 skipped when the account inherits the install's default
#     category set AND the user has zero personal categories.
#
# Auth completion polling — Gmail OAuth + O365 device-code flow are
# asynchronous external-browser handshakes. The step 2 panel polls
# /accounts/{id}/auth-status every 3 seconds via HTMX hx-trigger and
# auto-advances when the status flips to authenticated.
#
# OAuth callback step-resume: when sub-B's /oauth/google/callback
# sees a wizard step in its state payload, it redirects to
# /accounts/new?step=3&account_id=… instead of rendering the bare
# success banner. The auto-watch-start sub-B logic still fires;
# the wizard step 3 page renders the post-auth confirmation +
# push/poll knobs.
# ---------------------------------------------------------------------------


def _wizard_step_setting_key(account_id: int) -> str:
    """Settings-table key that records the latest wizard step the
    operator landed on. Cleared when the wizard completes; presence
    drives the Resume-setup banner on the edit page."""
    return f"account_state:{account_id}:wizard_step"


def _record_wizard_step(db, account_id: int, step: int) -> None:
    """Stamp the latest wizard step the operator reached.

    Best-effort: failure is logged + swallowed so a settings-table
    glitch doesn't break the wizard's main flow.
    """
    try:
        from email_triage.web.db import set_setting
        set_setting(db, _wizard_step_setting_key(account_id), {"step": step})
    except Exception as e:  # pragma: no cover — defensive
        _log.warning(
            "Wizard step record failed (non-fatal)",
            account_id=account_id, step=step, error=fmt_exc(e),
        )


def _clear_wizard_step(db, account_id: int) -> None:
    """Clear the resume-state row when the operator finishes the
    wizard. After this the Resume banner stops showing on the
    account edit page."""
    try:
        from email_triage.web.db import delete_setting
        delete_setting(db, _wizard_step_setting_key(account_id))
    except Exception as e:  # pragma: no cover — defensive
        _log.warning(
            "Wizard step clear failed (non-fatal)",
            account_id=account_id, error=fmt_exc(e),
        )


def _wizard_resume_step(db, account_id: int) -> int | None:
    """Return the resume step int, or None if the wizard isn't in
    progress for this account."""
    from email_triage.web.db import get_setting
    raw = get_setting(db, _wizard_step_setting_key(account_id))
    if not raw:
        return None
    if isinstance(raw, dict):
        try:
            n = int(raw.get("step", 0))
        except (TypeError, ValueError):
            return None
        if 1 <= n <= 5:
            return n
    return None


def _account_has_default_oauth_scopes(acct: dict) -> bool:
    """Step-3 skip heuristic helper: the account is at the default
    OAuth scope set when no extras (calendar, etc.) were opted in.

    Delegates to :func:`providers.traits.has_default_scopes`
    (#138.5 — wizard helper roll-up).
    """
    from email_triage.providers.traits import has_default_scopes
    return has_default_scopes(acct)


def _account_only_inbox_selectable(acct: dict) -> bool:
    """Step-3 skip heuristic helper: True when the account's folder
    set is so trivial there's nothing to configure beyond INBOX.

    Delegates to :func:`providers.traits.inbox_only` (#138.5).
    """
    from email_triage.providers.traits import inbox_only
    return inbox_only(acct)


def _should_skip_step3(acct: dict) -> bool:
    """Auto-skip step 3 when the operator has no real choice to make.

    Trigger: only INBOX is a watch candidate AND OAuth scopes are
    at the default. We redirect through the step and mark it on the
    progress strip with the "skipped — defaults applied" chip.
    """
    return (
        _account_only_inbox_selectable(acct)
        and _account_has_default_oauth_scopes(acct)
    )


def _user_has_default_category_set(db, user_id: int) -> bool:
    """Step-4 skip heuristic helper: True when the user has zero
    personal categories — they're inheriting the install's default
    set wholesale, so the wizard's category-customisation step has
    nothing for them to do."""
    from email_triage.web.db import list_categories
    personal = list_categories(db, user_id=user_id, scope="personal")
    return len(personal) == 0


def _should_skip_step4(db, user, account_id: int) -> bool:
    """Auto-skip step 4 when the user has no personal categories AND
    no other accounts they could copy routes from.

    Both conditions matter: even with zero personal cats, an existing
    account with routes is a useful starting point we don't want to
    silently bypass.
    """
    if not _user_has_default_category_set(db, user["id"]):
        return False
    # If the user has any other manageable account with routes, the
    # copy-from radios are meaningful — don't skip.
    from email_triage.web.db import list_email_accounts
    try:
        for a in list_email_accounts(db):
            if a["id"] == account_id:
                continue
            if not can_manage_account(db, user, a):
                continue
            n = db.execute(
                "SELECT COUNT(*) FROM account_routes WHERE account_id = ?",
                (a["id"],),
            ).fetchone()[0]
            if n > 0:
                return False
    except Exception:
        return False
    return True


def _wizard_skipped_steps(db, user, acct: dict) -> list[int]:
    """Return the list of step ints the wizard auto-skipped for this
    account, used by the progress strip to render struck-through
    chips. Computed on every render so the strip stays in sync with
    the operator's evolving config."""
    skipped: list[int] = []
    if _should_skip_step3(acct):
        skipped.append(3)
    if _should_skip_step4(db, user, acct["id"]):
        skipped.append(4)
    return skipped


def _account_authenticated(db, secrets, acct: dict) -> bool:
    """Best-effort 'auth complete?' check used by the step-2 polling
    endpoint to decide when to auto-advance the operator.

    Delegates to :func:`providers.traits.is_authenticated` (#138.5).
    The ``db`` arg is preserved for call-site compat — the trait
    only needs ``secrets`` + ``acct``, but a future ``last_seen``
    timestamp could fold in via the db handle without churning
    every caller.
    """
    from email_triage.providers.traits import is_authenticated
    return is_authenticated(secrets, acct)


def _apply_step3_defaults(db, watcher_mgr, acct: dict) -> None:
    """Persist sensible defaults when the wizard auto-skips step 3.

    Default config: push_enabled=True (unless the provider blocks),
    poll_enabled=True, poll_interval_minutes=60. Mirrors the form's
    own defaults so a skipped step matches what the operator would
    have submitted on the typical Next click.
    """
    from email_triage.web.db import update_email_account_config
    config = dict(acct.get("config") or {})
    # O365 defaults push off (push not yet available).
    if acct.get("provider_type") == "office365":
        config.setdefault("push_enabled", False)
    else:
        config.setdefault("push_enabled", True)
    config.setdefault("poll_enabled", True)
    config.setdefault("poll_interval_minutes", 60)
    try:
        update_email_account_config(db, acct["id"], config)
    except Exception as e:  # pragma: no cover — defensive
        _log.warning(
            "Wizard step-3 default-apply failed (non-fatal)",
            account_id=acct["id"], error=fmt_exc(e),
        )


def _accounts_edit_pre_provider(
    request: Request, db, secrets, user: dict, acct: dict,
) -> dict:
    """#135 phase 2 — chip enrichment + delegates + grantable users +
    digest configs + watches + wizard-resume detection bundled into one
    threadpool hop. Runs BEFORE the optional provider folder probe so
    the network-bound call doesn't block the DB reads."""
    from email_triage.web.app import get_watcher_manager
    from email_triage.web.db import list_account_delegates
    from email_triage.web.email_watches import list_watches
    from email_triage.actions.digest_configs import list_digest_configs
    from email_triage.triage_logging import is_account_hipaa

    is_admin = user["role"] == "admin"
    account_id = acct["id"]

    _enrich_account(acct, secrets)
    try:
        watcher_mgr = get_watcher_manager(request)
    except Exception:
        watcher_mgr = None
    _enrich_account_chips(
        acct, db, secrets, watcher_mgr=watcher_mgr,
        config=request.app.state.config,
    )

    delegates = list_account_delegates(db, account_id)

    grantable_users: list[dict] | None = None
    if is_admin:
        rows = db.execute(
            "SELECT id, email, name FROM users "
            "WHERE id != ? "
            "ORDER BY COALESCE(NULLIF(name, ''), email)",
            (acct["user_id"],),
        ).fetchall()
        grantable_users = [dict(r) for r in rows]

    digest_configs = list_digest_configs(db, account_id)
    watches = list_watches(
        db, account_id=account_id,
        include_all_accounts=not is_account_hipaa(acct),
    )

    wizard_resume_step = _wizard_resume_step(db, account_id)
    return {
        "delegates": delegates,
        "grantable_users": grantable_users,
        "digest_configs": digest_configs,
        "watches": watches,
        "wizard_resume_step": wizard_resume_step,
    }


def _accounts_row_snapshot(request: Request, account_id: int) -> dict | None:
    """#135 phase 2 — fetch + enrich in one threadpool hop."""
    from email_triage.web.db import get_email_account
    db = get_db(request)
    secrets = get_secrets(request)
    acct = get_email_account(db, account_id)
    if acct is None:
        return None
    _enrich_account(acct, secrets)
    from email_triage.web.app import get_watcher_manager
    try:
        watcher_mgr = get_watcher_manager(request)
    except Exception:
        watcher_mgr = None
    _enrich_account_chips(
        acct, db, secrets, watcher_mgr=watcher_mgr,
        config=request.app.state.config,
    )
    return acct


def _csv_split(raw: str | None) -> list[str]:
    """Split a comma-or-newline-separated form field into a clean
    list of strings. Empty entries dropped; whitespace stripped."""
    if not raw:
        return []
    items: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        s = chunk.strip()
        if s:
            items.append(s)
    return items


def _extract_digest_config_from_form(
    form, existing_id: str = "",
):
    """Build a ``DigestConfig`` from a save-form submission.

    Used by the editor save handler. Reads the same field names
    rendered by ``accounts/_digest_editor.html``. Validation is
    the caller's job — this just shapes the dataclass.
    """
    from email_triage.actions.digest_configs import (
        DigestColumn, DigestConfig, DigestFilter, DigestFormat,
        DigestSchedule, DigestWindow, _default_columns,
    )

    cfg = DigestConfig(
        id=existing_id or (form.get("id") or "").strip(),
        kind="custom",
        name=(form.get("name") or "").strip(),
        enabled=("enabled" in form),
    )
    cfg.schedule = DigestSchedule(
        cadence=(form.get("cadence") or "daily").strip(),
        time_local=(form.get("time_local") or "08:10").strip(),
        days_of_week=[
            int(d) for d in form.getlist("days_of_week")
            if str(d).isdigit() and 0 <= int(d) <= 6
        ],
    )
    cfg.window = DigestWindow(
        kind=(form.get("window_kind") or "rolling_24h").strip(),
        custom_start_iso=(form.get("window_custom_start") or "").strip(),
        custom_end_iso=(form.get("window_custom_end") or "").strip(),
    )
    has_att_raw = (form.get("has_attachment") or "").strip()
    has_att: bool | None = None
    if has_att_raw == "yes":
        has_att = True
    elif has_att_raw == "no":
        has_att = False
    cfg.filter = DigestFilter(
        read_state=(form.get("read_state") or "any").strip(),
        folders=form.getlist("folders") or _csv_split(
            form.get("folders_csv"),
        ),
        categories=form.getlist("categories"),
        tags=_csv_split(form.get("tags_csv")),
        from_addr=(form.get("from_addr") or "").strip(),
        subject=(form.get("subject") or "").strip(),
        list_id=(form.get("list_id") or "").strip(),
        has_attachment=has_att,
        actions=form.getlist("actions"),
        advanced=(form.get("advanced") or "").strip(),
    )
    # Form posts parallel arrays for the columns config. Zip
    # them, drop empty slots (where the operator left the key
    # blank), keep the rest in order. If the operator wiped all
    # columns, fall back to the default set so a table render
    # never goes out empty.
    keys = form.getlist("columns_key")
    labels = form.getlist("columns_label")
    priorities = form.getlist("columns_sort_priority")
    directions = form.getlist("columns_sort_direction")
    columns: list = []
    for i, key in enumerate(keys):
        key = (key or "").strip()
        if not key:
            continue
        try:
            prio = int(priorities[i]) if i < len(priorities) else 0
        except (TypeError, ValueError):
            prio = 0
        direction = (
            (directions[i] or "desc").strip()
            if i < len(directions) else "desc"
        )
        label = (
            (labels[i] or "").strip()
            if i < len(labels) else ""
        )
        columns.append(DigestColumn(
            key=key, label=label,
            sort_priority=max(0, prio),
            sort_direction=direction,
        ))
    if not columns:
        columns = _default_columns()
    # html_template normalization: if the submitted text exactly
    # matches the built-in default for the chosen render_as,
    # persist empty string. The textarea is prefilled with the
    # matching default as a starting point — most operators won't
    # edit it. Storing empty in that case lets future default
    # upgrades flow through; storing the verbatim default would
    # freeze the operator on whatever shipped at first save.
    _render_as = (form.get("render_as") or "table").strip()
    _html_template_submitted = str(form.get("html_template") or "")
    _html_template = _html_template_submitted.strip()
    if _html_template:
        from email_triage.actions.digest import (
            DEFAULT_DIGEST_TEMPLATE,
        )
        from email_triage.actions.digest_render import (
            _CLASSIC_NEWSLETTER_TEMPLATE,
        )
        if (
            _render_as == "newsletter_classic"
            and _html_template == _CLASSIC_NEWSLETTER_TEMPLATE.strip()
        ):
            _html_template = ""
        elif (
            _render_as == "newsletter"
            and _html_template == DEFAULT_DIGEST_TEMPLATE.strip()
        ):
            _html_template = ""

    cfg.format = DigestFormat(
        render_as=_render_as,
        group_by=(form.get("group_by") or "category").strip(),
        include_body_preview=("include_body_preview" in form),
        max_rows=int(form.get("max_rows") or 50),
        columns=columns,
        html_template=_html_template,
    )
    return cfg


def _digest_editor_context(db, request, account_id: int, dcfg=None):
    """Common context bundle for rendering the digest editor.

    ``dcfg`` is the config under edit — None means brand-new
    digest the operator hasn't named yet (form blank).
    """
    from email_triage.actions.digest_configs import (
        ACTION_KEYS, CADENCES, COLUMN_KEYS, GROUP_BYS, READ_STATES,
        RENDER_AS, SORT_DIRECTIONS, WINDOW_KINDS, DigestConfig,
    )
    from email_triage.web.db import (
        get_email_account, list_categories,
    )

    acct = get_email_account(db, account_id)
    if dcfg is None:
        dcfg = DigestConfig(kind="custom", name="", enabled=True)

    # Folder options (best-effort — IMAP-only). Reuses the same
    # helper used by the Provider+Auth tab.
    folder_options: list[str] = []
    try:
        if acct and acct.get("provider_type") == "imap":
            folders_setting = (
                acct.get("config") or {}
            ).get("discovered_folders") or []
            if isinstance(folders_setting, list):
                folder_options = [str(f) for f in folders_setting]
    except Exception:
        folder_options = []

    categories = (
        list_categories(db, user_id=acct["user_id"]) if acct else []
    )

    # Default Jinja templates for the newsletter formats — paste-
    # ready starting points operators can edit in the HTML
    # template textarea. Pulled from the same module the renderer
    # uses, so the operator's "Reset to default" matches what
    # ships with no override.
    from email_triage.actions.digest import DEFAULT_DIGEST_TEMPLATE
    from email_triage.actions.digest_render import (
        _CLASSIC_NEWSLETTER_TEMPLATE,
    )

    return {
        "acct": acct,
        "dcfg": dcfg,
        "folder_options": folder_options,
        "categories": categories,
        "enums": {
            "cadences": CADENCES,
            "window_kinds": WINDOW_KINDS,
            "read_states": READ_STATES,
            "render_as": RENDER_AS,
            "group_bys": GROUP_BYS,
            "action_keys": ACTION_KEYS,
            "column_keys": COLUMN_KEYS,
            "sort_directions": SORT_DIRECTIONS,
        },
        "default_newsletter_template": DEFAULT_DIGEST_TEMPLATE,
        "default_newsletter_classic_template": (
            _CLASSIC_NEWSLETTER_TEMPLATE
        ),
        "errors": [],
    }


async def _test_account_connection(
    acct: dict, secrets,
) -> tuple[bool, str]:
    """Run a connection test for an account. Returns (ok, message_html).

    ``message_html`` is the same inline HTML fragment the Test button
    shows — success or failure. Pulled out so accounts_create can run
    the exact same probe before flipping the watcher on.
    """
    # #138 phase 2 — table-driven dispatch via ProviderDispatcher.
    # The per-ptype probe shapes (IMAP4_SSL login, Gmail list_labels,
    # O365 device-code deferral) live in providers/dispatcher.py.
    from email_triage.providers.dispatcher import get_dispatch
    ptype = acct["provider_type"]
    disp = get_dispatch(ptype)
    if disp is None:
        return False, '<small>Unknown provider type.</small>'
    return await disp.test_connection(acct, secrets)


_MANUAL_REDIRECT_URI = "http://127.0.0.1:1/"


def _oauth_state_serializer(request: Request):
    """Sign / verify the OAuth state token using the session secret."""
    from itsdangerous import URLSafeTimedSerializer
    secret = getattr(request.app.state, "session_secret", "") or "dev-secret"
    return URLSafeTimedSerializer(secret, salt="oauth-state-v1")


def _gmail_auth_state(request: Request) -> dict:
    """Per-process scratch space for in-flight manual-paste flows."""
    state = getattr(request.app.state, "gmail_api_auth", None)
    if state is None:
        state = {}
        request.app.state.gmail_api_auth = state
    return state


def _public_callback_url(request: Request) -> str:
    """Build the registered redirect URI from PushConfig.public_url."""
    cfg = get_config(request)
    base = (getattr(cfg.push, "public_url", "") or "").rstrip("/")
    return f"{base}/oauth/google/callback" if base else ""


# #137 phase 2 — ``_verify_account_owner`` deleted; the three gmail-api
# auth handlers below now use ``OwnedGmailApiAccount`` (Annotated alias
# from web/dependencies.py) which raises HTTPException 401 / 404 / 403 /
# 400 in the same shape the helper used to return as HTMLResponse.


def _render_gmail_push_status_label(watch: dict | None) -> str:
    """Display-only push status for the Accounts row (no buttons)."""
    if watch is None:
        return '<span style="color:var(--pico-muted-color);white-space:nowrap;">Push off</span>'
    # B3: poll-mode accounts have a synthetic watch row (empty topic,
    # epoch expires_at) to hold the history cursor. These are not
    # "push on".
    topic = (watch.get("topic_name") or "").strip()
    try:
        expires = datetime.fromisoformat(str(watch.get("expires_at", "")).replace("Z", "+00:00"))
    except Exception:
        expires = None
    if not topic or (expires is not None and expires <= datetime.now(timezone.utc)):
        return '<span style="color:var(--pico-muted-color);white-space:nowrap;">Push off</span>'
    remaining = expires - datetime.now(timezone.utc)
    days = max(0, remaining.days)
    sub = f' <small style="color:var(--pico-muted-color);">(expires in {days}d)</small>'
    return (
        f'<span style="color:var(--pico-ins-color);white-space:nowrap;">🔔 Push on</span>{sub}'
    )


def _render_cadence_status_label(acct: dict, watch: dict | None, ingestion) -> str:
    """Display-only ingestion-cadence chip.

    Reads the new unified ``push_enabled`` / ``poll_enabled`` /
    ``poll_interval_minutes`` from the account config (the DB
    back-compat shim materialises these on read). Legacy B3 keys
    (``poll_interval_override``) are consulted as a secondary fallback
    so a freshly-upgraded install doesn't show a blank chip before any
    account has been saved through the new form.
    """
    cfg = acct.get("config") or {}
    push_on = bool(cfg.get("push_enabled", True))
    poll_on = bool(cfg.get("poll_enabled", True))
    iv = cfg.get("poll_interval_minutes")
    if not isinstance(iv, int):
        legacy = cfg.get("poll_interval_override")
        if isinstance(legacy, int):
            iv = legacy
        elif ingestion is not None:
            iv = int(getattr(ingestion, "default_poll_interval_minutes", 60))
        else:
            iv = 60

    # For Gmail: distinguish "push configured but expired" so the chip
    # can show a warning state rather than a clean "push on".
    push_healthy = push_on
    if push_on and watch is not None:
        topic = (watch.get("topic_name") or "").strip()
        try:
            exp = datetime.fromisoformat(
                str(watch.get("expires_at", "")).replace("Z", "+00:00")
            )
            if topic and exp > datetime.now(timezone.utc):
                push_healthy = True
            elif topic:
                push_healthy = False  # configured but expired
        except Exception:
            pass

    if not push_on and not poll_on:
        return (
            '<span style="color:var(--pico-muted-color);white-space:nowrap;" '
            'title="Ingestion disabled">⏸ Disabled</span>'
        )
    if push_on and poll_on:
        if push_healthy:
            return (
                f'<span style="color:var(--pico-ins-color);white-space:nowrap;" '
                f'title="Push active · safety poll every {iv}min">'
                f'✓ Push + {iv}min poll</span>'
            )
        return (
            f'<span style="color:var(--pico-color-amber-500);white-space:nowrap;" '
            f'title="Push configured but unhealthy · polling every {iv}min">'
            f'⚠ Push down · {iv}min poll</span>'
        )
    if push_on:
        return (
            f'<span style="color:var(--pico-ins-color);white-space:nowrap;" '
            f'title="Push only">'
            f'🔔 Push</span>'
        )
    return (
        f'<span style="color:var(--pico-muted-color);white-space:nowrap;" '
        f'title="Poll only every {iv}min">'
        f'ℹ Poll {iv}min</span>'
    )


def _render_openclaw_status_label(db, account_id: int) -> str:
    """Display-only OpenClaw status (no buttons)."""
    from email_triage.web.events import get_openclaw_quiet_settings
    s = get_openclaw_quiet_settings(db, account_id)
    if s["paused"]:
        return '<span style="color:var(--pico-color-amber-500);white-space:nowrap;">⏸ OpenClaw paused</span>'
    if not s["enabled"]:
        return '<span style="color:var(--pico-muted-color);white-space:nowrap;">OpenClaw off</span>'
    if s["start_utc"] and s["end_utc"]:
        return (
            f'<span style="color:var(--pico-ins-color);white-space:nowrap;">📡 OpenClaw on</span>'
            f' <small style="color:var(--pico-muted-color);white-space:nowrap;">'
            f'(quiet {s["start_utc"]}–{s["end_utc"]} UTC)</small>'
        )
    return '<span style="color:var(--pico-ins-color);white-space:nowrap;">📡 OpenClaw on</span>'


def _render_calendar_status_label(db, acct: dict) -> str:
    """Display-only calendar status (no buttons)."""
    from email_triage.web.db import is_calendar_enabled
    ptype = acct["provider_type"]
    if ptype not in ("gmail_api", "office365"):
        return '<span style="color:var(--pico-muted-color);white-space:nowrap;">Calendar n/a</span>'
    if is_calendar_enabled(db, acct["id"]):
        return '<span style="color:var(--pico-ins-color);white-space:nowrap;">📅 Calendar on</span>'
    return '<span style="color:var(--pico-muted-color);white-space:nowrap;">📅 Calendar off</span>'


def _enrich_account_chips(
    acct: dict, db, secrets, watcher_mgr=None, config=None,
) -> None:
    """Populate both interactive chips (with buttons, for the edit panel)
    and display-only status labels (for the row) on ``acct``.

    Centralised so the four endpoints that render rows (manage page,
    cancel-from-edit, save, hipaa-error fallback) all stay in sync.

    ``config`` is optional for back-compat; when provided, the gmail-push
    Start button can disable itself with a clear pointer-to-auth message
    if the account hasn't completed the push-enabled OAuth flow yet, or
    a neutral "push not enabled for this install" message if the topic
    isn't configured. Old callers that don't pass config render the
    chip in its enabled-by-default form (matches prior behaviour).
    """
    from email_triage.web.db import get_gmail_watch
    # #152 Phase 2 — surface the M-1+M-2 HIPAA opt-in flag so the
    # edit template can render its checkbox state. Read fails fall
    # back to False (the privacy-safe default per the audit runbook).
    try:
        from email_triage.web.db import is_style_knobs_hipaa_allow
        acct["style_knobs_hipaa_allow"] = is_style_knobs_hipaa_allow(
            db, acct["id"],
        )
    except Exception:
        acct["style_knobs_hipaa_allow"] = False
    if watcher_mgr is not None:
        try:
            acct["watch_active"] = watcher_mgr.is_running(acct["id"])
        except Exception:
            acct["watch_active"] = False
        # #52 — per-mailbox watch state. WatcherManager.status() returns
        # a "mailboxes" list with per-(account, mailbox) status. Surface
        # it on the row so an aggregate "Watching" doesn't paint over
        # one mailbox whose IDLE dropped while the others stay up.
        acct["watch_mailboxes"] = []
        try:
            st = watcher_mgr.status(acct["id"]) or {}
            mbs = st.get("mailboxes") or []
            if isinstance(mbs, list):
                acct["watch_mailboxes"] = [
                    {"mailbox": m.get("mailbox", ""),
                     "status": m.get("status", "stopped")}
                    for m in mbs
                    if isinstance(m, dict)
                ]
        except Exception:
            pass
    else:
        acct["watch_active"] = False
        acct["watch_mailboxes"] = []
    watch = None
    if acct["provider_type"] == "gmail_api":
        watch = get_gmail_watch(db, acct["id"])
        # Synthetic poll-mode watch rows (empty topic, epoch expiry)
        # should not surface a "push chip" in the edit panel — treat
        # them as no-watch for UI purposes.
        topic = (watch.get("topic_name") if watch else "") or ""
        try:
            exp = datetime.fromisoformat(
                str((watch or {}).get("expires_at", "")).replace("Z", "+00:00")
            )
        except Exception:
            exp = None
        is_active_push = bool(watch and topic.strip()
                              and exp is not None and exp > datetime.now(timezone.utc))
        # Prereqs for the user-facing Start Push button:
        #
        # 1. The account completed the Web-app ("Primary -- push-enabled")
        #    OAuth flow, NOT the Desktop manual-paste flow. Both grant
        #    gmail.modify scope, but gating on the flow type enforces a
        #    clean operator mental model: "Primary push-enabled is the
        #    button that enables push." Tracked via the
        #    gmail_oauth_flow:<id> setting stamped in each callback.
        # 2. The install has push.gmail_topic_name configured.
        #
        # An active gmail_watches row with a non-empty topic_name is
        # back-compat evidence that the Web-app flow was completed at
        # some point -- pre-2026-04-29 accounts may not have the
        # gmail_oauth_flow setting yet, but if their watch is healthy,
        # they got there via the right flow.
        from email_triage.web.db import get_setting
        oauth_flow = get_setting(db, _S.gmail_oauth_flow(acct["id"])) or ""
        push_enabled_flow = (oauth_flow == "web") or is_active_push
        topic_configured = bool(
            config is not None
            and (getattr(getattr(config, "push", None), "gmail_topic_name", "") or "").strip()
        )
        # Surface both flags to the template: drives the Real-Time
        # Watch / Push checkbox state in addition to the Start Push
        # chip below it. Same gate, two surfaces.
        acct["push_enabled_flow_done"] = push_enabled_flow
        acct["gmail_topic_configured"] = topic_configured
        acct["gmail_push_chip"] = (
            _render_gmail_watch_chip(watch) if is_active_push
            else _render_gmail_watch_start_button(
                acct["id"],
                has_refresh_token=push_enabled_flow,
                topic_configured=topic_configured,
            )
        )
        acct["gmail_push_status"] = _render_gmail_push_status_label(watch)
        # B3: expose the current ingestion mode to the edit form so the
        # override field placeholder shows the right default.
        acct["ingestion_mode"] = "push" if is_active_push else "poll"

    # Office 365 push chip — sister of the gmail_push_chip. Populated
    # on every render; the edit template only surfaces it when the
    # account is an O365 account. F-1: per-account Start/Stop buttons.
    if acct["provider_type"] == "office365":
        from email_triage.web.db import get_o365_subscription
        try:
            sub_row = get_o365_subscription(db, acct["id"])
        except Exception:
            sub_row = None
        acct["o365_push_chip"] = _render_o365_push_chip(sub_row, acct["id"])
    else:
        acct["o365_push_chip"] = ""

    # Cadence chip surfaces push + poll state for every provider (new
    # unified model). Legacy B3 gmail-only chip replaced; the data source
    # is account.config.{push,poll}_enabled plus the gmail_watches row
    # for distinguishing healthy vs expired push on Gmail.
    acct["cadence_status"] = _render_cadence_status_label(
        acct, watch, _get_install_ingestion_config(),
    )
    acct["openclaw_chip"] = _render_openclaw_chip(db, acct["id"])
    acct["openclaw_status"] = _render_openclaw_status_label(db, acct["id"])
    acct["calendar_chip"] = _render_calendar_chip(db, acct)
    acct["calendar_status"] = _render_calendar_status_label(db, acct)
    # Pre-rendered calendar-selection table (#105) — uses the
    # account's stored ``config.calendars`` list. Empty list
    # collapses to the "no calendars selected yet" placeholder
    # in the template; otherwise the table renders inline so
    # operators see their saved state without hitting Refresh.
    from email_triage.triage_logging import is_account_hipaa as _iah
    acct["calendars_table"] = _render_calendars_table(
        acct["id"],
        (acct.get("config") or {}).get("calendars") or [],
        hipaa=_iah(acct),
    )
    # Surrogate dropdown (#105 phase 1A++) — IMAP accounts have
    # no native calendar; operator picks another account
    # (gmail_api / office365 owned by the same user) whose provider
    # supplies the calendarList. Pre-rendered here so the editor
    # template can drop it in without DB queries on every render.
    # Surrogate picker available to every account type — operator
    # may want to route calendar ops on a Gmail mailbox through
    # a different Gmail account, not just IMAP-with-no-calendar.
    acct["calendar_surrogate_picker"] = (
        _render_calendar_surrogate_picker(db, acct)
    )

    # Stale-auth flag — set by the unified-poll error handler when
    # an OAuth refresh fails ("Token has been expired or revoked")
    # or an IMAP/Graph auth call returns AUTHENTICATIONFAILED. The
    # row template surfaces a re-auth chip so the operator notices
    # without scanning logs.
    try:
        from email_triage.web.db import get_setting
        acct["auth_stale"] = get_setting(db, _S.auth_stale(acct["id"]))
    except Exception:
        acct["auth_stale"] = None


def _render_gmail_watch_chip(watch: dict | None) -> str:
    """Return the HTMX fragment shown in the row's push-status cell."""
    account_id = watch["account_id"] if watch else 0
    if watch is None:
        # Account has no active watch — render the Start button (caller
        # supplies account_id via the surrounding row's context).
        return (
            '<span style="color:var(--pico-muted-color);">Push off</span>'
        )
    try:
        expires = datetime.fromisoformat(watch["expires_at"].replace("Z", "+00:00"))
        remaining = expires - datetime.now(timezone.utc)
        days = max(0, remaining.days)
        sub = f'expires in {days}d'
    except Exception:
        sub = ''
    return (
        f'<span style="color:var(--pico-ins-color);">🔔 Push active</span>'
        f' <small style="color:var(--pico-muted-color);">{sub}</small>'
        f' <button type="button" class="outline secondary"'
        f' style="padding:0.1rem 0.4rem;margin-left:0.4rem;font-size:0.8rem;"'
        f' hx-post="/accounts/{account_id}/gmail-api/watch/stop"'
        f' hx-target="#gmail-push-cell-{account_id}"'
        f' hx-swap="innerHTML"'
        f' hx-confirm="Stop push notifications for this account?">Stop</button>'
    )


def _render_gmail_watch_start_button(
    account_id: int, *,
    has_refresh_token: bool = True,
    topic_configured: bool = True,
) -> str:
    """Render the "Start Push" button for the per-account chip.

    Three states:

    * No refresh token yet — Start Push is disabled with a pointer to
      the "Primary -- push-enabled" auth button. Account owners
      themselves see this if they only completed the manual-paste
      fallback flow (which doesn't grant the scope set push needs).
    * Topic not configured — Start Push disabled with a neutral
      "push not yet enabled for this install" message. We deliberately
      don't surface the admin config path here — non-admin users
      can't act on it, and admins know where it lives.
    * Both prereqs met — Start Push enabled.
    """
    btn_base_style = (
        'padding:0.1rem 0.4rem;margin-left:0.4rem;font-size:0.8rem;'
    )
    label = '<span style="color:var(--pico-muted-color);">Push off</span>'
    if not has_refresh_token:
        return (
            f'{label}'
            f' <button type="button" class="outline secondary" disabled'
            f' style="{btn_base_style}"'
            f' title="Authenticate this account first.">Start Push</button>'
            f' <small style="color:var(--pico-muted-color);">'
            f'Use <strong>Primary &mdash; push-enabled</strong> above to '
            f'authenticate first.</small>'
        )
    if not topic_configured:
        return (
            f'{label}'
            f' <button type="button" class="outline secondary" disabled'
            f' style="{btn_base_style}"'
            f' title="Push is not enabled for this install yet.">Start Push</button>'
            f' <small style="color:var(--pico-muted-color);">'
            f'Push isn&rsquo;t enabled for this install yet.</small>'
        )
    return (
        f'{label}'
        f' <button type="button" class="outline secondary"'
        f' style="{btn_base_style}"'
        f' hx-post="/accounts/{account_id}/gmail-api/watch/start"'
        f' hx-target="#gmail-push-cell-{account_id}"'
        f' hx-swap="innerHTML">Start Push</button>'
    )


def _render_o365_push_chip(sub: dict | None, account_id: int) -> str:
    """Render the per-account Office 365 push status chip.

    States:
      * No row -> "Push: OFF" + Start button.
      * Active row -> "Push: ON" + expiration hint + Stop button.

    Mirrors the Gmail-side chip's button-driven HTMX swap so the
    integrations panel stays consistent across providers. The form
    target is the surrounding ``#o365-push-cell-<id>`` div populated
    by the edit template.
    """
    btn_base_style = (
        'padding:0.1rem 0.4rem;margin-left:0.4rem;font-size:0.8rem;'
    )
    if sub is None:
        return (
            '<span style="color:var(--pico-muted-color);">Push: OFF</span>'
            f' <form method="post"'
            f' action="/accounts/{account_id}/o365-push/start"'
            f' style="display:inline;margin:0;">'
            f' <button type="submit" class="outline secondary"'
            f' style="{btn_base_style}">Start Push</button>'
            f' </form>'
        )
    sub_id = (sub.get("subscription_id") or "").strip()
    expires_iso = sub.get("expiration_at") or ""
    sub_text = ""
    try:
        exp = datetime.fromisoformat(str(expires_iso).replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp - now
        if remaining.total_seconds() <= 0:
            sub_text = ' <small style="color:var(--pico-del-color);">expired</small>'
        else:
            hours = int(remaining.total_seconds() // 3600)
            if hours >= 24:
                sub_text = (
                    f' <small style="color:var(--pico-muted-color);">'
                    f'expires in {hours // 24}d</small>'
                )
            else:
                sub_text = (
                    f' <small style="color:var(--pico-muted-color);">'
                    f'expires in {max(hours, 0)}h</small>'
                )
    except Exception:
        pass
    safe_sub = sub_id[:36] if sub_id else "(unknown)"
    return (
        f'<span style="color:var(--pico-ins-color);">🔔 Push: ON</span>'
        f'{sub_text}'
        f' <small style="color:var(--pico-muted-color);">'
        f'subscription <code>{safe_sub}</code></small>'
        f' <form method="post"'
        f' action="/accounts/{account_id}/o365-push/stop"'
        f' style="display:inline;margin:0;"'
        f' onsubmit="return confirm(\'Stop push delivery for this account?\')">'
        f' <button type="submit" class="outline secondary"'
        f' style="{btn_base_style}">Stop Push</button>'
        f' </form>'
    )


def _o365_subscription_create_args(request: Request, account_id: int) -> tuple[str, str]:
    """Resolve (webhook_url, client_state) for a Graph subscription create.

    Webhook URL is derived from ``config.push.public_url`` + the
    canonical ``/webhooks/office365`` path. The legacy ``/webhooks/graph``
    alias still works for back-compat but new subscriptions register
    against the canonical path.

    ``client_state`` is the per-subscription HMAC secret Graph echoes
    on every push. Resolution order:

    1. Per-account secret ``office365_clientstate:<account_id>``.
    2. Install-wide secret ``office365_clientstate``.
    3. **Auto-generate** a fresh 32-byte URL-safe value and store it
       under the per-account key.

    Step 3 closes #132: previous behaviour returned the empty string
    when neither secret was set, which the receiver then treated as
    "skip the HMAC compare entirely". Anyone who learned the
    subscriptionId could POST to /webhooks/office365 and queue triage
    work for that account. Generating + persisting a fresh secret at
    registration time means the receiver always has something to
    compare against, and the no-secret-stored path no longer exists.
    """
    import secrets as _stdlib_secrets

    config = get_config(request)
    secrets = get_secrets(request)
    base = ""
    try:
        base = (getattr(getattr(config, "push", None), "public_url", "") or "").strip()
    except Exception:
        base = ""
    base = base.rstrip("/")
    webhook_url = f"{base}/webhooks/office365" if base else ""
    client_state = ""
    try:
        per_acct = secrets.get(_S.office365_clientstate(account_id))
        if per_acct:
            client_state = str(per_acct)
        else:
            install = secrets.get("office365_clientstate")
            if install:
                client_state = str(install)
    except Exception:
        client_state = ""
    if not client_state:
        # Auto-generate. 32 random URL-safe bytes ≈ 43 ASCII chars,
        # within Graph's 128-char clientState limit. Store under the
        # per-account key so a future Stop+Start round-trips the same
        # value, and the install-wide secret stays untouched.
        client_state = _stdlib_secrets.token_urlsafe(32)
        try:
            secrets.set(
                _S.office365_clientstate(account_id), client_state,
            )
        except Exception:
            # Storage failure is fatal for the security model — without
            # the stored value the receiver cannot verify deliveries.
            # Surface as empty so the caller's downstream
            # ``not webhook_url`` guard still works (treats this as a
            # config failure, redirects with an error chip).
            client_state = ""
    return webhook_url, client_state


_AADSTS_TRANSLATIONS: dict[str, str] = {
    "AADSTS50011": (
        "Reply URL mismatch — make sure your Azure App Registration "
        "has email-triage's redirect URI listed under Authentication "
        "→ Redirect URIs."
    ),
    "AADSTS65001": (
        "Admin consent needed — your tenant requires an administrator "
        "to grant the requested permissions before you can sign in. "
        "Open the Azure App Registration → API permissions → "
        "Grant admin consent."
    ),
    "AADSTS70011": (
        "Invalid scope — the client requested a permission your app "
        "registration doesn't have. Add Mail.Read + Mail.ReadWrite "
        "+ offline_access on the API permissions tab."
    ),
    "AADSTS700016": (
        "Application not found — the Client ID doesn't match any app "
        "in this tenant. Check the Application (client) ID on the "
        "App Registration's Overview page and that you're using the "
        "right Tenant ID."
    ),
    "AADSTS7000215": (
        "Invalid client secret — the secret value Microsoft accepted "
        "doesn't match the one in this app. Generate a new secret "
        "under Certificates & secrets and paste the secret VALUE "
        "(not the secret ID) here."
    ),
    "AADSTS7000222": (
        "Client secret expired — generate a new one under "
        "Certificates & secrets and paste the new secret value here."
    ),
    "AADSTS90002": (
        "Tenant not found — the Tenant ID doesn't match any "
        "Microsoft tenant. Use 'common' for personal accounts, "
        "'organizations' for any work account, or your tenant's "
        "GUID from Microsoft Entra ID → Overview."
    ),
}


def _aadsts_translate(error_text: str) -> tuple[str | None, str]:
    """Translate an AADSTS-prefixed error into an English one-liner.

    Returns ``(code, message)`` where:
      * ``code`` is the matched AADSTS code (e.g. "AADSTS50011") or
        None if the input doesn't carry one.
      * ``message`` is the translated one-liner if the code is in
        our table, otherwise the verbatim error text trimmed to a
        sensible length so the chip doesn't blow up the layout.

    Per the punch-list spec: never surface the bare AADSTS code as
    the headline. The code rides along as a reference for operators
    who Google it; the English sentence does the explaining.
    """
    import re as _re

    if not error_text:
        return None, "Microsoft rejected the sign-in request."
    # Match AADSTS<digits> at any position. msal embeds the code in
    # the error_description like "AADSTS65001: The user or admin has
    # not consented..." while httpx/Graph errors put it inside JSON.
    match = _re.search(r"AADSTS\d+", error_text)
    if not match:
        # Trim verbatim error to keep the chip compact.
        verbatim = error_text.strip().splitlines()[0][:280]
        return None, verbatim
    code = match.group(0)
    if code in _AADSTS_TRANSLATIONS:
        return code, _AADSTS_TRANSLATIONS[code]
    # Unknown AADSTS code — fall back to the verbatim message but
    # keep the code visible.
    verbatim = error_text.strip().splitlines()[0][:280]
    return code, verbatim


def _render_o365_probe_chip_success(account_id: int, signed_in_as: str) -> str:
    """Green chip rendered after a successful /me probe.

    The macro-emitted tooltip (``m.help`` shape: ``<span
    data-tooltip=...>``) carries the diagnostic the spec requires —
    no inline ``title=`` attribute (per pattern_tooltip_singleton_engine.md
    rule). Since this is server-rendered HTML inserted via HTMX
    swap, we hand-roll the same shape the macro emits."""
    from markupsafe import escape

    safe_addr = escape(signed_in_as or "(no address returned)")
    diag = (
        "This means Azure accepted your tenant + client + secret "
        "+ scopes. The next step is enabling push subscriptions "
        "on the Push tab."
    )
    return (
        f'<span style="color:var(--pico-ins-color);font-weight:600;">'
        f'✓ O365 credentials valid'
        f'</span>'
        f' <small>signed in as <code>{safe_addr}</code></small>'
        f' <span data-tooltip="{escape(diag)}" data-placement="bottom"'
        f' role="img" aria-label="Help: {escape(diag)}" tabindex="0"'
        f' style="cursor:help;margin-left:0.35rem;font-size:0.85em;'
        f'color:var(--pico-muted-color);vertical-align:middle;">'
        f'ℹ️</span>'
    )


def _render_o365_probe_chip_failure(
    message: str, *, code: str | None = None,
    account_id: int | None = None,
) -> str:
    """Red chip rendered on a failed /me probe.

    Same hand-rolled tooltip shape as the success chip — see comment
    there for why we don't import the Jinja macro here.

    #121-A — when a code is present we also emit an "Explain this
    error" button beside the chip. The static AADSTS table only
    knows 7 codes; the AI picks up the slack for everything else
    (and adds context the static one-liner can't, like "Tenant ID
    is set to 'common' but this code only fires on single-tenant
    apps"). Per the standing rule the button label is descriptive
    text, never just an icon. The example tooltip is concrete.
    """
    from markupsafe import escape

    safe_msg = escape(message or "Sign-in failed.")
    code_chip = ""
    if code:
        code_chip = (
            f' <small style="color:var(--pico-muted-color);">'
            f'(<code>{escape(code)}</code>)</small>'
        )
    # Explain-this-error affordance. The result container is sibling
    # to the chip so the chip itself doesn't reflow when the AI reply
    # arrives. Container id is account-scoped so multiple probes on
    # different account-edit tabs don't trip over each other.
    explain_block = ""
    if message:
        aid_kv = ""
        if account_id is not None:
            aid_kv = f', "account_id": "{int(account_id)}"'
        tooltip = (
            "Asks the AI what this Microsoft sign-in error means "
            "in plain English. Example: an AADSTS50158 row (which "
            "we don't translate inline) becomes 'External MFA was "
            "required but not satisfied; reauthenticate with the "
            "second factor.' Useful when the static AADSTS table "
            "above returns Unknown."
        )
        result_id = (
            f"explain-result-probe-{account_id}"
            if account_id is not None
            else "explain-result-probe-anon"
        )
        spinner_id = result_id + "-spin"
        # Use a literal {"key": "val"} JSON for hx-vals. Strings are
        # the escaped message + provider literal. error_text needs
        # newlines collapsed (hx-vals JSON parser is strict).
        err_text_attr = (
            (message or "")
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', ' ')
            .replace('\r', ' ')
        )
        code_attr = escape(code or "")
        explain_block = (
            f' <button type="button"'
            f' hx-post="/explain-error"'
            f' hx-target="#{result_id}"'
            f' hx-swap="innerHTML"'
            f' hx-indicator="#{spinner_id}"'
            f' hx-vals=\'{{"error_text": "{escape(err_text_attr)}", '
            f'"error_class": "{code_attr}", '
            f'"provider": "office365"{aid_kv}}}\''
            f' class="outline"'
            f' style="padding:0.05rem 0.45rem;font-size:0.7rem;'
            f'margin-left:0.35rem;line-height:1.4;min-height:0;'
            f'color:var(--pico-color);'
            f'border-color:var(--pico-muted-border-color);">'
            f'Explain this error</button>'
            f'<small id="{spinner_id}" class="htmx-indicator"'
            f' style="color:var(--pico-muted-color);font-size:0.75rem;'
            f'margin-left:0.25rem;">asking AI…</small>'
            f' <span data-tooltip="{escape(tooltip)}" data-placement="bottom"'
            f' role="img" aria-label="Help: {escape(tooltip)}" tabindex="0"'
            f' style="cursor:help;margin-left:0.25rem;font-size:0.85em;'
            f'color:var(--pico-muted-color);vertical-align:middle;">ℹ️</span>'
            f'<div id="{result_id}" style="display:block;"></div>'
        )
    return (
        f'<span style="color:var(--pico-del-color);font-weight:600;">'
        f'✗ O365 sign-in failed'
        f'</span>'
        f'{code_chip}'
        f'{explain_block}'
        f' <p style="margin:0.25rem 0 0;font-size:0.9em;'
        f'color:var(--pico-del-color);">{safe_msg}</p>'
    )


def _render_calendar_chip(db, acct: dict) -> str:
    """Inline chip rendering Calendar enable/disable state for an account.

    Hidden upstream for HIPAA accounts (the row template gates on
    ``acct.hipaa`` + system flag). Both Gmail-native and Office 365
    accounts get the chip; other provider types render a "n/a".
    """
    from email_triage.web.db import get_setting
    aid = acct["id"]
    ptype = acct["provider_type"]
    if ptype not in ("gmail_api", "office365"):
        return '<span style="color:var(--pico-muted-color);">Calendar n/a</span>'
    from email_triage.web.db import is_calendar_enabled
    enabled = is_calendar_enabled(db, aid)
    if enabled:
        return '<span style="color:var(--pico-ins-color);">📅 Calendar on</span>'
    # Opt-in now lives in the account edit form; the single
    # Authenticate button on that form requests the union of scopes.
    return (
        '<span style="color:var(--pico-muted-color);">📅 Calendar off</span>'
        ' <small style="color:var(--pico-muted-color);">'
        '(opt in via Edit)</small>'
    )


def _create_calendar_provider_from_account(
    acct: dict, secrets, google_oauth=None, office365_oauth=None, *, db=None,
):
    """Build a CalendarProvider from an email_accounts row.

    Resolution order:

      1. If a surrogate is configured + valid, build the provider
         from the SURROGATE's credentials. Surrogate wins regardless
         of the account's own provider type — operator who runs
         multiple Gmail mailboxes through a single Calendar identity
         relies on this path.
      2. Otherwise, build from the account's own provider if it
         supports calendars (gmail_api / office365).
      3. Otherwise return None (e.g. IMAP with no surrogate).

    ``google_oauth`` is the install-level ``GoogleOAuthConfig``; the
    calendar provider uses the same client pair the account
    originally authenticated with. We don't currently persist which
    pair (Web vs Desktop) the account chose, so default to Web for
    now — fine since Google accepts either client on token refresh
    as long as the secret matches.

    ``db`` is required when the account might have a surrogate
    configured; pass ``None`` to skip surrogate resolution and use
    the account's own credentials only.
    """
    cfg = acct.get("config") or {}
    if db is not None:
        from email_triage.web.calendars import resolve_surrogate_account
        surrogate = resolve_surrogate_account(db, acct)
        if surrogate is not None:
            # Recurse with db=None so the surrogate's OWN surrogate
            # (if any) is ignored. Defense against A->B->A cycles
            # if config corruption ever points two accounts at
            # each other; one hop is the contract.
            return _create_calendar_provider_from_account(
                surrogate, secrets,
                google_oauth=google_oauth,
                office365_oauth=office365_oauth, db=None,
            )
    ptype = acct.get("provider_type")
    if ptype == "gmail_api":
        from email_triage.providers.gmail_calendar import GoogleCalendarProvider
        sk = _secret_key_for_account(acct["id"], "gmail_api")
        refresh_token = secrets.get(sk) if sk else ""
        go = _resolve_google_oauth(google_oauth)
        client_id = go.web_client_id if go else ""
        client_secret = go.web_client_secret if go else ""
        if not client_id and go:
            # Fall back to Desktop pair when Web slot is empty.
            client_id = go.desktop_client_id
            client_secret = go.desktop_client_secret
        return GoogleCalendarProvider(
            account=cfg.get("account", ""),
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token or "",
        )
    if ptype == "office365":
        from email_triage.providers.office365_calendar import Office365CalendarProvider
        # Same install-level resolution path as the mail provider
        # factory (factory.py:office365 branch). Per-account
        # is_personal_msa flag routes tenant to "common" or the
        # install's configured org tenant.
        install = _resolve_office365_oauth(office365_oauth)
        client_id = install.client_id if install else ""
        client_secret = install.client_secret if install else ""
        is_personal = bool(cfg.get("is_personal_msa", False))
        tenant_id = "common" if is_personal else (install.tenant_id if install else "")
        return Office365CalendarProvider(
            client_id=client_id,
            tenant_id=tenant_id or "common",
            client_secret=client_secret or "",
            token_cache_path=cfg.get("token_cache_path", "./data/msal_cache.json"),
        )
    return None


def _help_span(text: str) -> str:
    """Mirror of the Jinja ``m.help`` macro for Python-rendered
    HTML — emits the same ``<span data-tooltip>`` hook the
    body-scope tooltip engine catches at hover/focus time.
    Audience copy lives one place across the editor: same text
    shape (plain English, lead with an example), same trigger
    icon, same singleton-engine positioning.
    """
    import html as _h
    safe = _h.escape(text, quote=True)
    return (
        f'<span data-tooltip="{safe}" data-placement="bottom" '
        f'role="img" aria-label="Help: {safe}" tabindex="0" '
        f'style="cursor:help;margin-left:0.35rem;font-size:0.85em;'
        f'color:var(--pico-muted-color);vertical-align:middle;">'
        f'ℹ️</span>'
    )


def _render_calendar_surrogate_picker(db, acct: dict) -> str:
    """Dropdown letting an operator route this account's calendar
    ops through another account's provider. Lists every other
    account owned by the same user with a calendar-capable
    provider (gmail_api / office365). Empty option clears.

    HIPAA-flagged accounts cannot surrogate at all (PHI must
    stay self-only). For those accounts the picker renders as
    a locked notice instead of a dropdown.
    """
    import html as _h
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import list_email_accounts
    from email_triage.web.calendars import get_surrogate_account_id

    if is_account_hipaa(acct):
        return (
            "<div style='margin:0.4rem 0;font-size:0.85em;'>"
            "<small style='color:var(--pico-muted-color);'>"
            "🔒 This account is HIPAA-flagged. Calendar must "
            "stay self-only — surrogating to another account "
            "is blocked because it would bridge PHI across "
            "accounts."
            "</small>"
            "</div>"
        )

    user_id = acct.get("user_id")
    account_id = acct["id"]
    candidates: list[dict] = []
    try:
        for c in list_email_accounts(db) or []:
            if c.get("user_id") != user_id:
                continue
            if c.get("id") == account_id:
                continue  # can't surrogate to self
            if c.get("provider_type") not in ("gmail_api", "office365"):
                continue
            # HIPAA targets are off-limits regardless of source.
            # Filter at render time so the dropdown never shows
            # a HIPAA option; resolver-side refusal is the
            # authoritative gate.
            if is_account_hipaa(c):
                continue
            candidates.append(c)
    except Exception:
        candidates = []

    current_sid = get_surrogate_account_id(acct)
    # Self-name on the empty-value option so the operator knows
    # which account they're configuring without scrolling — the
    # dropdown row is otherwise context-free.
    self_name = acct.get("name") or ""
    self_addr = acct.get("email_address") or ""
    self_label = self_name + (
        f" <{self_addr}>" if self_addr else ""
    )
    self_label = self_label.strip() or f"#{acct.get('id')}"
    if acct.get("provider_type") in ("gmail_api", "office365"):
        empty_label = (
            f"— Use {self_label}'s own calendar —"
        )
    else:
        empty_label = (
            f"— None (no calendar for {self_label}) —"
        )
    options = [
        '<option value="">'
        f"{_h.escape(empty_label)}"
        '</option>'
    ]
    for c in candidates:
        cid = c.get("id")
        name = c.get("name") or f"#{cid}"
        addr = c.get("email_address") or ""
        label = f"{name}" + (f" <{addr}>" if addr else "")
        sel = " selected" if cid == current_sid else ""
        options.append(
            f"<option value='{cid}'{sel}>"
            f"{_h.escape(label)}</option>"
        )

    if not candidates:
        # No suitable target accounts — render nothing rather than
        # an empty dropdown that the operator can't act on.
        return ""

    # Different help copy depending on whether this account has
    # a native calendar. Both versions lead with an example per
    # the audience-comment rules in feedback_audience_per_page.
    has_native = acct.get("provider_type") in (
        "gmail_api", "office365",
    )
    if has_native:
        help_text = (
            "Optional. Send this account's calendar work to a "
            "different account's calendar instead of its own. "
            "Example: you have a work mailbox and a personal "
            "mailbox but only one calendar you actually live "
            "in — point both mailboxes at that one calendar so "
            "every meeting + reminder lands in the same place."
        )
        page_blurb = (
            "This account has its own calendar. Leave the picker "
            "below empty to use it. Pick a different account if "
            "you'd rather route everything through one shared "
            "calendar."
        )
    else:
        help_text = (
            "This mailbox has no calendar of its own (it talks "
            "plain mail only). Pick another of your accounts so "
            "this mailbox can read + write events on its calendar. "
            "Example: an IMAP mailbox at your domain pointed at "
            "your main Google account so meeting requests still "
            "get conflict-checked."
        )
        page_blurb = (
            "This mailbox has no calendar of its own — pick "
            "another of your accounts to lend it one. Without "
            "this, calendar features (conflict check, event "
            "listings, the assistant API) stay off for this "
            "mailbox."
        )
    options_html = "".join(options)
    label_help = _help_span(help_text)
    import html as _h

    return (
        "<div style='margin:0.4rem 0;font-size:0.85em;'>"
        "<small style='color:var(--pico-muted-color);"
        "display:block;margin-bottom:0.3rem;'>"
        f"{_h.escape(page_blurb)}"
        "</small>"
        "<form "
        f"hx-post='/accounts/{account_id}/calendar/surrogate' "
        f"hx-target='#calendar-surrogate-result-{account_id}' "
        "hx-swap='innerHTML' "
        "style='display:flex;align-items:center;gap:0.4rem;"
        "flex-wrap:wrap;'>"
        "<label style='margin:0;font-weight:normal;'>"
        f"Use calendar from:{label_help}</label>"
        f"<select name='surrogate_account_id' "
        "style='margin:0;padding:0.2rem 0.4rem;font-size:0.85em;'>"
        f"{options_html}"
        "</select>"
        "<button type='submit' class='outline' "
        "style='padding:0.2rem 0.6rem;font-size:0.85em;margin:0;"
        "min-height:1.7rem;line-height:1.4;'>Save</button>"
        "<span "
        f"id='calendar-surrogate-result-{account_id}' "
        "style='font-size:0.85em;'></span>"
        "</form>"
        "</div>"
    )


def _render_calendars_table(
    account_id: int, calendars: list[dict], *,
    error: str = "",
    hipaa: bool = False,
) -> str:
    """Render the discovered-calendars table for HTMX swap-in.

    Mirrors the IMAP folder-selector pattern: one row per
    discovered calendar, opt-in checkbox + role checkboxes (one
    radio for the single-pick ``self_schedule`` role). Rows
    rendered by Python rather than Jinja since the surrounding
    integrations panel is plain HTML — keeps the markup local
    + lets the discover route swap a single fragment.

    ``hipaa=True`` disables the role checkboxes for any role in
    HIPAA_RESTRICTED_ROLES (currently ``api``) so PHI never
    reaches the external assistant surface. Server-side parser
    enforces the same rule on save; UI gate is a UX hint, not
    the gate.
    """
    import html as _h
    from email_triage.web.calendars import HIPAA_RESTRICTED_ROLES
    api_blocked = hipaa and "api" in HIPAA_RESTRICTED_ROLES
    if error:
        return (
            "<small style='color:var(--pico-del-color);'>"
            f"Calendar discovery failed: {_h.escape(error)}</small>"
        )
    if not calendars:
        return (
            "<small style='color:var(--pico-muted-color);'>"
            "No calendars visible to this account. Make sure the "
            "calendar OAuth scope is granted, then try Refresh "
            "again.</small>"
        )

    # Single pick across rows for self_schedule.
    self_schedule_pick = ""
    for c in calendars:
        if (c.get("roles") or {}).get("self_schedule"):
            self_schedule_pick = c["id"]
            break

    rows: list[str] = []
    for c in calendars:
        cid = c.get("id", "")
        summary = c.get("summary", cid)
        primary = bool(c.get("primary"))
        access_role = c.get("access_role", "reader")
        # Read-only feeds (holiday calendars, public feeds) can't
        # accept event writes, so disable the self-schedule radio
        # for those. Read roles (meetings/listings/api) stay
        # available since those just READ events.
        can_write = access_role in ("owner", "writer")
        enabled = bool(c.get("enabled"))
        roles = c.get("roles") or {}
        cid_esc = _h.escape(cid, quote=True)
        summary_esc = _h.escape(summary)
        display_name = str(c.get("display_name") or "")
        display_esc = _h.escape(display_name, quote=True)
        star = " ★" if primary else ""
        ro_marker = (
            " <small style='color:var(--pico-muted-color);'>"
            "(read-only)</small>"
        ) if not can_write else ""
        # Disable role checkboxes when the row isn't opted in.
        # JS toggles disabled state on the master checkbox change;
        # initial render uses Python state so the page lands
        # consistent without JS firing.
        disabled_attr = "" if enabled else " disabled"
        self_disabled_attr = (
            "" if (enabled and can_write) else " disabled"
        )
        rows.append(
            "<tr>"
            f"<td>{summary_esc}{star}{ro_marker}<br>"
            f"<small style='color:var(--pico-muted-color);"
            f"font-size:0.75em;'>{cid_esc}</small></td>"
            f"<td><input type='text' name='cal_display_name[{cid_esc}]'"
            f" value='{display_esc}'"
            f" placeholder='{summary_esc}'"
            f" style='width:100%;padding:0.15rem 0.35rem;"
            f"font-size:0.85em;'></td>"
            f"<td><input type='checkbox' name='cal_enabled[{cid_esc}]'"
            f" value='1'"
            f" data-cal-id='{cid_esc}'"
            f" onchange='etCalendarToggleRow(this)'"
            f"{' checked' if enabled else ''}></td>"
            f"<td><input type='checkbox' name='cal_role_meetings[{cid_esc}]'"
            f" value='1'"
            f"{' checked' if roles.get('meetings') else ''}{disabled_attr}></td>"
            f"<td><input type='checkbox' name='cal_role_listings[{cid_esc}]'"
            f" value='1'"
            f"{' checked' if roles.get('listings') else ''}{disabled_attr}></td>"
            f"<td><input type='checkbox' name='cal_role_api[{cid_esc}]'"
            f" value='1'"
            f"{' checked' if (roles.get('api') and not api_blocked) else ''}"
            f"{' disabled' if api_blocked else disabled_attr}></td>"
            f"<td><input type='radio' name='cal_role_self_schedule'"
            f" value='{cid_esc}'"
            f"{' checked' if self_schedule_pick == cid else ''}"
            f"{self_disabled_attr}></td>"
            "</tr>"
        )

    # Hidden field carrying the discovered IDs so the save
    # handler knows which rows the form is allowed to reference.
    discovered_ids = ",".join(c.get("id", "") for c in calendars)
    discovered_ids_esc = _h.escape(discovered_ids, quote=True)

    # Per-column tooltips. Each leads with a concrete example
    # so the operator gets the use case before the definition.
    display_help = _help_span(
        "Friendly name for this calendar in API + assistant "
        "replies. Optional. Leave blank to use the calendar's "
        "own name from Google. Example: a primary calendar named "
        "you@gmail.com renders nicer as \"Personal\" or "
        "\"Family\" — type whatever you want; the assistant uses "
        "this label."
    )
    use_help = _help_span(
        "Tick the box to engage this calendar. Untick a row to "
        "ignore that calendar entirely. Example: leave a shared "
        "team calendar unticked if you don't want its events "
        "showing up in your triage at all."
    )
    meetings_help = _help_span(
        "Calendars to scan for conflicts when an incoming meeting "
        "request arrives. Example: pick your main work calendar "
        "so back-to-back meeting invites surface as conflicts "
        "before you accept."
    )
    listings_help = _help_span(
        "Calendars read for event roll-ups (digests, "
        "\"what's on my schedule\" summaries, free/busy lookups). "
        "Example: pick a Family calendar to include family "
        "events in your morning schedule summary."
    )
    api_help = _help_span(
        "Calendars exposed to the assistant API (voice / chat "
        "assistants that ask about your schedule). Example: "
        "leave a private calendar unchecked so the assistant "
        "can't mention its events."
        + (
            " 🔒 Blocked on HIPAA-flagged accounts — the "
            "assistant surface lacks the PHI controls the rest "
            "of the pipeline applies."
            if api_blocked else ""
        )
    )
    self_help = _help_span(
        "The single calendar that gets new events when an email "
        "looks like a self-scheduled note (you emailed yourself "
        "a meeting reminder). Example: pick your personal "
        "calendar so a \"lunch with Bob 12:30\" note-to-self "
        "lands there. Only one calendar can carry this role."
    )

    return (
        "<div style='font-size:0.85em;'>"
        # Lead-in copy on the page so operators see the rules
        # without having to hover every column header.
        "<small style='color:var(--pico-muted-color);"
        "display:block;margin-bottom:0.3rem;'>"
        "Tick <strong>Use this calendar</strong> on every "
        "calendar you want this account to engage with. The "
        "role columns light up once a row is in use — pick the "
        "ones that fit. <strong>Self Schedule</strong> is "
        "single-pick (one calendar across the whole account)."
        "</small>"
        f"<form id='calendars-form-{account_id}' "
        f"hx-post='/accounts/{account_id}/calendars/save' "
        f"hx-target='#calendars-result-{account_id}' "
        f"hx-swap='innerHTML'>"
        f"<input type='hidden' name='discovered_ids' "
        f"value='{discovered_ids_esc}'>"
        "<table style='font-size:0.85em;width:100%;'>"
        "<thead><tr>"
        "<th style='text-align:left;'>Calendar</th>"
        f"<th style='text-align:left;'>Display name{display_help}</th>"
        f"<th>Use this calendar{use_help}</th>"
        f"<th>Meetings{meetings_help}</th>"
        f"<th>Include in Event Listings{listings_help}</th>"
        f"<th>Include in API Listings{api_help}</th>"
        f"<th>Self Schedule{self_help}</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "<button type='submit' class='outline' "
        "style='padding:0.25rem 0.7rem;font-size:0.85em;margin:0;"
        "min-height:1.9rem;line-height:1.4;'>"
        "Save calendar selection</button>"
        f"<span id='calendars-result-{account_id}' "
        "style='margin-left:0.6rem;'></span>"
        "</form>"
        # JS: toggle role-checkbox disabled state when the row's
        # master checkbox flips. Single-pick radio disabled too.
        "<script>"
        "function etCalendarToggleRow(box){"
        "var tr=box.closest('tr');"
        "var inputs=tr.querySelectorAll("
        "\"input[type=checkbox]:not([data-cal-id]), "
        "input[type=radio]\");"
        "inputs.forEach(function(i){i.disabled=!box.checked;"
        "if(!box.checked){i.checked=false;}});}"
        "</script>"
        "</div>"
    )


def _render_openclaw_chip(db, account_id: int) -> str:
    """Inline chip describing the OpenClaw webhook gate for an account."""
    from email_triage.web.events import get_openclaw_quiet_settings
    s = get_openclaw_quiet_settings(db, account_id)
    if s["paused"]:
        label = '<span style="color:var(--pico-color-amber-500);">⏸ OpenClaw paused</span>'
    elif not s["enabled"]:
        label = '<span style="color:var(--pico-muted-color);">OpenClaw off</span>'
    elif s["start_utc"] and s["end_utc"]:
        label = (
            f'<span style="color:var(--pico-ins-color);">📡 OpenClaw on</span>'
            f' <small style="color:var(--pico-muted-color);">'
            f'(quiet {s["start_utc"]}–{s["end_utc"]} UTC)</small>'
        )
    else:
        label = '<span style="color:var(--pico-ins-color);">📡 OpenClaw on</span>'
    return (
        f'{label}'
        f' <button type="button" class="outline secondary"'
        f' style="padding:0.1rem 0.4rem;margin-left:0.4rem;font-size:0.8rem;"'
        f' hx-get="/accounts/{account_id}/openclaw/editor"'
        f' hx-target="#openclaw-cell-{account_id}"'
        f' hx-swap="innerHTML">Edit</button>'
    )


def _openclaw_quiet_save_snapshot(
    db, account_id: int, form_dict: dict,
) -> str:
    """#135 phase 2 — read existing settings, apply form patch, write
    back, render chip — all in one threadpool hop."""
    from email_triage.web.db import get_setting, set_setting
    current = get_setting(db, _S.openclaw_quiet(account_id)) or {}
    current["enabled"] = bool(form_dict.get("enabled"))
    current["paused"] = bool(form_dict.get("paused"))
    current["start_utc"] = (form_dict.get("start_utc") or "").strip()
    current["end_utc"] = (form_dict.get("end_utc") or "").strip()
    set_setting(db, _S.openclaw_quiet(account_id), current)
    return _render_openclaw_chip(db, account_id)


def _parse_watch_form(form, default_account_id: int | None = None):
    """Hydrate an EmailWatch (filter + actions + name + enabled) from
    posted form fields.

    Post-#154 the form has no ``account_id`` field — the new
    /profile/watches editor sends a multi-select ``account_ids[]``
    that the route handler iterates to fan out rows. ``account_id``
    on the returned watch is set to ``default_account_id`` (None on
    new groups). The route handler overwrites it before each
    upsert_watch call.

    Legacy ``all_accounts`` field, if posted by a stale browser
    cache, is silently ignored — the multi-select replaces it.
    """
    from email_triage.web.email_watches import (
        EmailWatch, WatchActions, WatchFilter,
        EscalateAction, WebhookAction,
    )
    # Belt-and-braces: drop the legacy all_accounts field if a stale
    # browser cache POSTs it. The multi-select is the source of truth.
    _ = form.get("all_accounts")
    return EmailWatch(
        watch_id="",
        name=(form.get("name") or "").strip(),
        enabled=("enabled" in form),
        account_id=default_account_id,
        filter=WatchFilter(
            from_addr=(form.get("from_addr") or "").strip(),
            from_domain=(form.get("from_domain") or "").strip(),
            subject_contains=(form.get("subject_contains") or "").strip(),
            keyword=(form.get("keyword") or "").strip(),
            advanced=(form.get("advanced") or "").strip(),
        ),
        actions=WatchActions(
            escalate=EscalateAction(
                enabled=("escalate_enabled" in form),
                notify_email=(
                    form.get("escalate_notify_email") or ""
                ).strip(),
            ),
            webhook=WebhookAction(
                enabled=("webhook_enabled" in form),
                url=(form.get("webhook_url") or "").strip(),
            ),
        ),
    )


def _build_admin_watches_snapshot(db) -> list[dict]:
    """#135 phase 2 — every watch + account roster + label decoration in
    one threadpool hop."""
    from email_triage.web.email_watches import list_watches
    from email_triage.web.db import list_email_accounts
    rows = list_watches(db)
    accounts_by_id = {a["id"]: a for a in list_email_accounts(db)}
    items: list[dict] = []
    for w in rows:
        acct = accounts_by_id.get(w.account_id) if w.account_id else None
        if w.account_id is None:
            scope_label = "All accounts"
        elif acct is None:
            scope_label = f"(missing account, id {w.account_id})"
        else:
            scope_label = (
                f"{acct.get('name') or 'Account'} (id {w.account_id})"
            )
        items.append({"w": w, "scope_label": scope_label})
    return items


def _parse_raw_email(raw_text: str) -> EmailMessage:
    """Parse a raw email string (with headers) into an EmailMessage."""
    msg = email_mod.message_from_string(raw_text, policy=email_mod.policy.default)

    # Extract sender.
    sender = ""
    from_hdr = msg.get("From", "")
    if from_hdr:
        _name, addr = email.utils.parseaddr(str(from_hdr))
        sender = addr or str(from_hdr)

    # Extract recipients.
    recipients: list[str] = []
    for hdr_name in ("To", "Cc"):
        hdr_val = msg.get(hdr_name, "")
        if hdr_val:
            addrs = email.utils.getaddresses([str(hdr_val)])
            recipients.extend(addr for _name, addr in addrs if addr)

    # Subject.
    subject = str(msg.get("Subject", ""))

    # Date.
    date_str = msg.get("Date", "")
    date_dt = datetime.now(timezone.utc)
    if date_str:
        parsed_date = email.utils.parsedate_to_datetime(str(date_str))
        if parsed_date:
            date_dt = parsed_date

    # Body (prefer plain text).
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_content()
                if isinstance(payload, str):
                    body_text = payload
                    break
        # Fallback to HTML if no plain text.
        if not body_text:
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/html":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        body_text = payload
                        break
    else:
        payload = msg.get_content()
        if isinstance(payload, str):
            body_text = payload

    # Collect headers.
    headers: dict[str, str] = {}
    for key in msg.keys():
        headers[key] = str(msg[key])

    # Generate a message ID.
    message_id = str(msg.get("Message-ID", "")) or f"classify-test-{int(time.time())}"

    return EmailMessage(
        message_id=message_id,
        provider="paste",
        sender=sender,
        recipients=recipients,
        subject=subject,
        body_text=body_text,
        date=date_dt,
        headers=headers,
    )


def _collect_list_hints_for_message(
    db,
    message: EmailMessage,
    *,
    lists=None,
    rules_by_list=None,
) -> list:
    """Collect matching list hints for a single message.

    #134.1 — when called inside a triage loop, pass pre-loaded
    ``lists`` + ``rules_by_list`` (built once per run via
    :func:`_load_all_list_hints`) so this function is pure
    in-memory matching, no DB round-trips. Single-message callers
    (the ``/classify/test`` route) can omit both kwargs and the
    function falls back to the per-call fetch path for backward
    compatibility.
    """
    from email_triage.classify.hints import collect_hints

    if lists is None or rules_by_list is None:
        lists, rules_by_list = _load_all_list_hints(db)
    return collect_hints(message, lists, rules_by_list)


# ---------------------------------------------------------------------------
# Provider factory (from DB account config + secrets)
#
# Lifted to ``email_triage.providers.factory`` (#138.1). The setters and
# resolvers below are thin re-export shims so existing imports keep
# working — both for in-tree callers (``web/app.py``, ``cli.py``) and
# for any external code that imported these names directly. The
# install-level singletons themselves now live on the factory module.
# ---------------------------------------------------------------------------

from email_triage.providers.factory import (  # noqa: E402
    set_install_google_oauth,
    set_install_office365_oauth,
    set_install_ingestion_config,
    _resolve_google_oauth,
    _resolve_office365_oauth,
    build_provider as _create_provider_from_account,
)
from email_triage.providers import factory as _provider_factory  # noqa: E402


# Module-level proxies that read the canonical singletons living on the
# factory module. Kept as properties-on-globals via __getattr__ would be
# nicer, but these are dotted-name imports in places — the shim has to
# be a plain attribute. We expose them as module functions instead.
def _get_install_google_oauth():
    return _provider_factory._install_google_oauth


def _get_install_ingestion_config():
    return _provider_factory._install_ingestion_config


# Back-compat module-level names. These are READ at request-time by
# helpers like the ``_install_ingestion_config`` reference at line 11350,
# so they must reflect the current factory-module value, not the value
# at import time. Defined as module-level descriptors via __getattr__
# (PEP 562) so any access reads through to the factory module.


def _scopes_for_account(acct: dict) -> list[str]:
    """Return the OAuth scopes the account has opted into.

    Centralised so every Authenticate path requests the same union and
    no caller accidentally strips scopes from a re-auth. Always includes
    DEFAULT_SCOPES (Gmail read/modify — the account's reason for
    existing); appends CALENDAR_SCOPES when ``calendar_opted_in`` is set.
    """
    from email_triage.providers.gmail_api import DEFAULT_SCOPES, CALENDAR_SCOPES
    scopes = list(DEFAULT_SCOPES)
    if (acct.get("config") or {}).get("calendar_opted_in"):
        scopes.extend(CALENDAR_SCOPES)
    return scopes


async def _probe_missing_labels(
    provider, targets: list[str],
) -> list[str]:
    """Return targets that don't currently exist on the provider.

    Used by route-save to pre-warn ("will auto-create X on first
    matching email") so the operator sees deferred work explicitly.
    Best-effort — caller wraps in try/except, treats any failure as
    "no missing" (the apply-time auto-create still handles it).
    """
    if not targets:
        return []
    # Fetch the live label/folder list once; compare in-memory.
    try:
        labels = await provider.list_labels()
        names = {l.get("name", "") for l in labels if isinstance(l, dict)}
        names |= {l.get("id", "") for l in labels if isinstance(l, dict)}
    except NotImplementedError:
        # Providers without label-listing fall back to folder list.
        try:
            folders = await provider.list_folders()
        except Exception:
            return []
        names = set(folders)
    except Exception:
        return []
    missing: list[str] = []
    builtins = {
        "INBOX", "SENT", "DRAFT", "TRASH", "SPAM", "STARRED",
        "IMPORTANT", "UNREAD", "CHAT",
    }
    for t in targets:
        if t.upper() in builtins:
            continue
        # Case-insensitive match — Gmail's UI lists them with original
        # casing but the API accepts either.
        if t in names:
            continue
        if any(n.lower() == t.lower() for n in names):
            continue
        missing.append(t)
    return missing


# ``_create_provider_from_account`` is re-exported as an alias of
# ``email_triage.providers.factory.build_provider`` (#138.1) — see the
# import block higher in this file.


# ---------------------------------------------------------------------------
# Folder listing per account
# ---------------------------------------------------------------------------

def _routes_pre_provider_snapshot(db, user: dict, acct: dict) -> dict:
    """#135 phase 2 — DB reads that don't depend on the live folder
    list. Routes table + per-user categories are independent of the
    network-bound folder fetch, so they go on the threadpool first."""
    from email_triage.web.db import list_account_routes
    account_id = acct["id"]
    routes = list_account_routes(db, account_id)
    categories = _get_categories_from_db(db, user_id=acct.get("user_id"))
    return {"routes": routes, "categories": categories}


def _routes_post_provider_snapshot(
    db, account_id: int, all_folders: list[str],
) -> dict:
    """#135 phase 2 — DB-side filter of all_folders + folder-prefs read
    bundled into one threadpool hop after the provider call returns."""
    from email_triage.web.db import get_visible_folders, get_folder_prefs
    folders = get_visible_folders(db, account_id, all_folders)
    prefs = get_folder_prefs(db, account_id)
    excluded_count = sum(1 for inc in prefs.values() if not inc)
    return {"folders": folders, "excluded_count": excluded_count}


async def _build_routes_context(
    request: Request,
    db,
    secrets,
    user: dict,
    acct: dict,
) -> dict:
    """Shared context builder for the routes-table partial.

    Used by both the per-account routes page (/accounts/{id}/routes)
    and the top-level picker page (/routes?account_id=N). Builds
    the context dict the body partial _routes_body.html needs. The
    callers wrap it with their own page chrome (tab strip vs.
    account dropdown).
    """
    account_id = acct["id"]
    pre = await db_call(_routes_pre_provider_snapshot, db, user, acct)

    # Try to list folders for the folder picker.
    all_folders: list[str] = []
    folders: list[str] = []
    excluded_count = 0
    try:
        provider = _create_provider_from_account(acct, secrets)
        all_folders = await provider.list_folders()
        await provider.close()
        post = await db_call(
            _routes_post_provider_snapshot, db, account_id, all_folders,
        )
        folders = post["folders"]
        excluded_count = post["excluded_count"]
    except Exception:
        # Folder listing may not be available for all providers.
        # Still need folder-prefs for the excluded-count chip even
        # without a live list.
        try:
            from email_triage.web.db import get_folder_prefs
            prefs = await db_call(get_folder_prefs, db, account_id)
            excluded_count = sum(1 for inc in prefs.values() if not inc)
        except Exception:
            pass

    routes_by_cat = {r["category"]: r for r in pre["routes"]}

    folder_msg = request.query_params.get("folder_msg", "")

    # #163 follow-up — surface this account's provider-native labels
    # so the route editor's `label` and `add-label` actions can pick
    # one or more by name instead of defaulting to the classification
    # category. The helper returns [] for IMAP / HIPAA /
    # unauthenticated accounts (each fail-soft); the template renders
    # the picker only when the list is non-empty.
    provider_labels_for_account: list[dict] = []
    try:
        from email_triage.providers.provider_labels import (
            list_provider_labels_for_account,
        )
        provider_labels_for_account = await list_provider_labels_for_account(
            db=db, secrets=secrets, account_id=account_id,
        )
    except Exception:
        provider_labels_for_account = []

    # Each route's existing label-action config may already carry a
    # ``labels`` list (set via this picker on a prior save). Surface
    # the current selection per category so the template can mark
    # those options selected.
    selected_labels_by_cat: dict[str, list[str]] = {}
    for r in pre["routes"]:
        cat = r.get("category", "")
        for a in r.get("actions", []) or []:
            if a.get("action") != "label":
                continue
            cfg = a.get("config") or {}
            labels = cfg.get("labels") or []
            if isinstance(labels, list):
                selected_labels_by_cat[cat] = [
                    str(s) for s in labels if isinstance(s, str)
                ]

    # #129 tail — install-wide INTERNAL label catalog for the
    # routes-editor "add-label" picker (sibling to the provider-
    # native picker above). The two surfaces are complementary:
    # internal labels are install-local DB rows on /labels,
    # provider-native labels live on the upstream account. Both
    # apply at fire time. Empty list when the labels table hasn't
    # been seeded yet; the template falls back to a "create one
    # on /labels first" hint.
    try:
        from email_triage.web.db import list_labels
        all_labels = await db_call(list_labels, db)
    except Exception:
        all_labels = []

    return {
        "user": user,
        "acct": acct,
        "categories": pre["categories"],
        "routes_by_cat": routes_by_cat,
        "folders": folders,
        "all_folder_count": len(all_folders),
        "excluded_count": excluded_count,
        # #129 tail — order matters: existing routes editor renders
        # checkboxes in this order. Append ``add-label`` rather than
        # interleaving so saved routes from before this change keep
        # the same visual layout for the existing actions.
        "available_actions": [
            # 2026-05-13 — ``suggest_meeting_times`` added so operators
            # can explicitly route meeting-request → calendar-aware
            # draft. ALSO fires automatically (see
            # actions/suggest_meeting_times.py:inject_meeting_intercept)
            # when calendar + meeting prefs are wired, so most
            # operators never need to pick it; the explicit option is
            # for installs that want it on a different category or
            # alongside other actions (move, label, notify).
            "move", "label", "notify", "draft_reply",
            "suggest_meeting_times", "add-label",
        ],
        "all_labels": all_labels,
        "folder_msg": folder_msg,
        "provider_labels_for_account": provider_labels_for_account,
        "selected_labels_by_cat": selected_labels_by_cat,
    }


def _set_last_routes_account_id(db, user_id: int, account_id: int) -> None:
    """Persist the user's most-recent routes-edit target so the
    top-level /routes page defaults to it. Stored as a settings row
    under ``last_routes_account_id:<user_id>`` for portability —
    matches the existing get_setting / set_setting pattern."""
    from email_triage.web.db import set_setting
    set_setting(
        db, _S.last_routes_account_id(user_id),
        {"account_id": account_id},
    )


def _get_last_routes_account_id(db, user_id: int) -> int | None:
    """Inverse of _set_last_routes_account_id. Returns None when
    unset or malformed."""
    from email_triage.web.db import get_setting
    val = get_setting(db, _S.last_routes_account_id(user_id))
    if not isinstance(val, dict):
        return None
    aid = val.get("account_id")
    if isinstance(aid, int):
        return aid
    return None


def _build_folder_tree(folders: list[str], separator: str = ".") -> list[dict]:
    """Build a hierarchical tree from a flat list of folder paths.

    Returns a list of dicts like:
    [{"name": "INBOX", "path": "INBOX", "children": [
        {"name": "Triage", "path": "INBOX.Triage", "children": [...]},
    ]}]
    """
    root: list[dict] = []
    node_map: dict[str, dict] = {}

    for folder in sorted(folders):
        parts = folder.split(separator)
        for i in range(len(parts)):
            path = separator.join(parts[: i + 1])
            if path not in node_map:
                node = {"name": parts[i], "path": path, "children": []}
                node_map[path] = node
                if i == 0:
                    root.append(node)
                else:
                    parent_path = separator.join(parts[:i])
                    if parent_path in node_map:
                        node_map[parent_path]["children"].append(node)
                    else:
                        root.append(node)
    return root


def _account_mailbox_address(acct: dict) -> str:
    """Best-guess external address for an account's own mailbox.

    Used to build the ``To:`` header when we're delivering a digest
    back to the source mailbox. The "OAuth login identity" (e.g. the
    Google sign-in email) is NOT always the mailbox's own address —
    a user can sign into Google with one account and connect a
    different Gmail. We prefer, in order:

    1. ``config.account`` — set explicitly by the OAuth connect flow
       when it calls ``get_profile()``.
    2. ``config.username`` — the IMAP login name, which on most
       servers IS the mailbox address.
    3. ``acct["name"]`` — operator-chosen display name; last resort.

    Returns an empty string if nothing plausible is available.
    """
    cfg = acct.get("config") or {}
    for key in ("account", "username"):
        v = cfg.get(key) or ""
        if v and "@" in v:
            return v
    # Fall back to any non-empty value even without '@' — better than nothing.
    for key in ("account", "username"):
        v = cfg.get(key) or ""
        if v:
            return v
    return acct.get("name", "") or ""


# Simple RFC-5321-shape check for operator-supplied recipient addresses.
_EMAIL_RE = __import__("re").compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _resolve_digest_recipient(
    acct: dict,
    user_email: str,
    recipient_mode: str,
    recipient_custom: str,
    *,
    hipaa: bool,
) -> tuple[str, str, str]:
    """Pick the digest destination, honouring HIPAA server-side.

    Returns ``(destination, effective_mode, warning)`` where
    ``warning`` is a log-worthy reason string (empty on normal paths).

    A HIPAA-flagged account is LOCKED to ``back_to_account`` here
    regardless of what the form submitted — that's the server-side
    guard matching the UI lock. The warning string surfaces that fact
    so the audit trail shows a down-shifted recipient mode with a
    reason, not a silent override.
    """
    mode = recipient_mode or "back_to_account"
    warning = ""
    if hipaa and mode != "back_to_account":
        warning = (
            "HIPAA-flagged account forced back_to_account "
            f"(requested={mode})"
        )
        mode = "back_to_account"

    if mode == "user_email":
        dest = (user_email or "").strip()
        if not dest:
            warning = warning or "user_email empty; falling back to back_to_account"
            mode = "back_to_account"
    elif mode == "other":
        dest = (recipient_custom or "").strip()
        if not _EMAIL_RE.match(dest):
            warning = warning or f"recipient_custom invalid ({dest!r}); falling back"
            mode = "back_to_account"

    if mode == "back_to_account":
        dest = _account_mailbox_address(acct)

    return dest, mode, warning


def _load_digest_schedules(db, account_id: int) -> list[dict]:
    """Load digest schedules for an account.

    Handles backward-compat: migrates old single-schedule format
    (``digest:{id}``) into the new list format (``digest_schedules:{id}``).
    """
    from email_triage.web.db import get_setting, set_setting

    schedules = get_setting(db, _S.digest_schedules(account_id))
    if schedules is not None:
        return schedules

    # Migrate legacy single-schedule format.
    old_cfg = get_setting(db, _S.digest(account_id)) or {}
    if old_cfg.get("schedule_enabled"):
        schedules = [{
            "time_utc": old_cfg.get("schedule_time", "07:00"),
            "category": old_cfg.get("category", "newsletters"),
            "enabled": True,
        }]
    else:
        schedules = []

    # Persist the migrated format so we only do this once.
    set_setting(db, _S.digest_schedules(account_id), schedules)
    return schedules


def _save_digest_schedules(db, account_id: int, schedules: list[dict]) -> None:
    """Persist digest schedules for an account."""
    from email_triage.web.db import set_setting
    set_setting(db, _S.digest_schedules(account_id), schedules)


def _render_digest_schedules(templates, request, acct, schedules, flash_msg: str = ""):
    """Render the digest schedules partial for HTMX swap.

    ``flash_msg`` is an optional one-shot notice shown above the table
    (used after Run Now so the user sees confirmation).
    """
    return _render(templates, request, "accounts/_digest_schedules.html", {
        "acct": acct,
        "digest_schedules": schedules,
        "flash_msg": flash_msg,
    })


def _local_time_to_utc(local_time: str, tz_offset_minutes: int) -> str:
    """Convert a local HH:MM time to UTC using a timezone offset.

    ``tz_offset_minutes`` follows JavaScript's ``getTimezoneOffset()``
    convention: positive = behind UTC (e.g., EST = +300).
    """
    parts = local_time.split(":")
    h, m = int(parts[0]), int(parts[1])
    total_minutes = h * 60 + m + tz_offset_minutes  # Add offset to get UTC
    total_minutes %= 1440  # Wrap around midnight
    return f"{total_minutes // 60:02d}:{total_minutes % 60:02d}"


# #72 — Cadence helpers. ``daily`` is the legacy default; ``weekly``
# fires only on selected weekdays. Weekday encoding follows Python's
# datetime convention (Monday=0 .. Sunday=6) so the scheduler can
# call ``.weekday()`` directly without a lookup table.
DIGEST_CADENCE_OPTIONS = ("daily", "weekly")
DIGEST_DAYS_OF_WEEK = (
    (0, "Mon"), (1, "Tue"), (2, "Wed"), (3, "Thu"),
    (4, "Fri"), (5, "Sat"), (6, "Sun"),
)


def _parse_cadence_form(form) -> tuple[str, list[int]]:
    """Read ``cadence`` + ``day_<n>`` checkboxes off a digest-form
    submission. Returns ``("daily", [])`` for the legacy default,
    or ``("weekly", [<int days>])`` when the operator picked weekly
    + at least one weekday box. ``weekly`` with zero days falls back
    to ``daily`` (the operator-friendly interpretation: "you didn't
    pick any days, so we'll fire every day until you do")."""
    raw = (form.get("cadence") or "daily").strip().lower()
    cadence = raw if raw in DIGEST_CADENCE_OPTIONS else "daily"
    days: list[int] = []
    if cadence == "weekly":
        for d, _label in DIGEST_DAYS_OF_WEEK:
            if form.get(f"day_{d}") == "1":
                days.append(d)
        if not days:
            # No weekdays checked → fall back to daily so the schedule
            # still fires.
            cadence = "daily"
            days = []
    return cadence, days


def _digest_schedule_add_snapshot(
    db, account_id: int, new_entry: dict,
) -> list[dict]:
    """#135 phase 2 — load + dedup-check + append + save in one threadpool
    hop. Returns the resulting schedules list."""
    schedules = _load_digest_schedules(db, account_id)
    for s in schedules:
        if (s["time_utc"] == new_entry["time_utc"]
                and s["category"] == new_entry["category"]
                and s.get("cadence", "daily") == new_entry["cadence"]
                and (s.get("days_of_week") or []) == new_entry["days_of_week"]):
            return schedules  # duplicate — no change
    schedules.append(new_entry)
    _save_digest_schedules(db, account_id, schedules)
    return schedules


def _digest_schedule_toggle_snapshot(
    db, account_id: int, idx: int,
) -> list[dict]:
    """#135 phase 2 — load + toggle + save in one threadpool hop."""
    schedules = _load_digest_schedules(db, account_id)
    if 0 <= idx < len(schedules):
        schedules[idx]["enabled"] = not schedules[idx]["enabled"]
        _save_digest_schedules(db, account_id, schedules)
    return schedules


def _digest_schedule_reschedule_snapshot(
    db, account_id: int, idx: int, new_utc: str,
) -> tuple[str, list[dict]]:
    """#135 phase 2 — load + collision-check + write in one threadpool
    hop. Returns ('ok' | 'not_found' | 'collision', schedules)."""
    schedules = _load_digest_schedules(db, account_id)
    if not (0 <= idx < len(schedules)):
        return "not_found", schedules
    for i, s in enumerate(schedules):
        if i == idx:
            continue
        if s["time_utc"] == new_utc and s["category"] == schedules[idx]["category"]:
            return "collision", schedules
    schedules[idx]["time_utc"] = new_utc
    _save_digest_schedules(db, account_id, schedules)
    return "ok", schedules


def _digest_schedule_edit_form_snapshot(
    db, account_id: int, idx: int, owner_id: int | None,
) -> dict | None:
    """#135 phase 2 — schedules + categories in one threadpool hop."""
    schedules = _load_digest_schedules(db, account_id)
    if not (0 <= idx < len(schedules)):
        return None
    cats = _get_categories_from_db(db, user_id=owner_id)
    return {"sched": schedules[idx], "categories": cats}


def _digest_schedule_edit_save_snapshot(
    db, account_id: int, idx: int, new_entry_partial: dict,
) -> tuple[str, list[dict]]:
    """#135 phase 2 — load + range-check + write in one threadpool hop.
    `new_entry_partial` is the operator-supplied portion (no ``enabled``)
    so we can preserve the previous ``enabled`` value."""
    schedules = _load_digest_schedules(db, account_id)
    if not (0 <= idx < len(schedules)):
        return "not_found", schedules
    new_entry = {
        **new_entry_partial,
        "enabled": schedules[idx].get("enabled", True),
    }
    schedules[idx] = new_entry
    _save_digest_schedules(db, account_id, schedules)
    return "ok", schedules


def _digest_schedule_delete_snapshot(
    db, account_id: int, idx: int,
) -> list[dict]:
    """#135 phase 2 — load + remove + save in one threadpool hop."""
    schedules = _load_digest_schedules(db, account_id)
    if 0 <= idx < len(schedules):
        schedules.pop(idx)
        _save_digest_schedules(db, account_id, schedules)
    return schedules


def _get_hwm_context(db, account_id: int) -> dict:
    """Return high-water mark template context for a watcher status fragment.

    Multi-mailbox note: an account may now carry one HWM per folder. For
    the compact status panel we surface the INBOX HWM (the common case)
    plus a count of additional mailboxes with a mark. Full per-mailbox
    breakdown is available via the aggregate ``mailboxes`` list in
    ``WatcherManager.status()``.
    """
    from email_triage.web.db import (
        get_setting, get_email_account, _account_mailboxes,
    )
    acct = get_email_account(db, account_id)
    mbs = _account_mailboxes((acct or {}).get("config") or {})
    # Primary HWM = INBOX if the account watches it, else the first listed.
    primary = "INBOX" if "INBOX" in mbs else (mbs[0] if mbs else "INBOX")

    # Prefer the new per-mailbox key; fall back to legacy per-account
    # key so existing installs and existing tests that seed the legacy
    # shape continue to render.
    new_key = _S.watch_hwm_mailbox(account_id, primary)
    hwm_data = get_setting(db, new_key)
    if hwm_data is None:
        hwm_data = get_setting(db, _S.watch_hwm(account_id))

    other_with_hwm = 0
    for mb in mbs:
        if mb == primary:
            continue
        if get_setting(db, _S.watch_hwm_mailbox(account_id, mb)):
            other_with_hwm += 1

    if hwm_data:
        return {
            "hwm_uid": hwm_data.get("uid", 0),
            "hwm_updated": hwm_data.get("updated_at", ""),
            "hwm_mailbox": primary,
            "hwm_other_mailboxes": other_with_hwm,
        }
    return {
        "hwm_uid": 0,
        "hwm_updated": "",
        "hwm_mailbox": primary,
        "hwm_other_mailboxes": other_with_hwm,
    }


def _gmail_api_watch_start_status(
    request: Request, db, account_id: int,
) -> tuple[str, dict]:
    """Return (msg, status_dict) for Gmail API accounts on /watch/start.

    Describes what ingestion mode the account is already in — push (via
    Pub/Sub watch) or poll (B3 history-poll loop) — without trying to
    spin up an IDLE watcher. The poll interval is resolved from the
    install-level IngestionConfig with any per-account override.
    """
    from email_triage.web.db import get_gmail_watch, get_email_account

    acct = get_email_account(db, account_id)
    watch = get_gmail_watch(db, account_id) if acct else None

    # Determine mode exactly like _render_cadence_status_label.
    mode = "poll"
    days_remaining = 0
    if watch:
        topic = (watch.get("topic_name") or "").strip()
        try:
            exp = datetime.fromisoformat(
                str(watch.get("expires_at", "")).replace("Z", "+00:00")
            )
            if topic and exp > datetime.now(timezone.utc):
                mode = "push"
                days_remaining = max(0, (exp - datetime.now(timezone.utc)).days)
        except Exception:
            pass

    # Resolve poll interval (mins) the same way the B3 loop does.
    ingestion = _get_install_ingestion_config()
    override = (acct.get("config") or {}).get("poll_interval_override") if acct else None
    if isinstance(override, int):
        interval_min = override
    elif ingestion is not None:
        interval_min = (
            ingestion.push_poll_interval_min if mode == "push"
            else ingestion.poll_poll_interval_min
        )
    else:
        interval_min = 10

    if mode == "push":
        msg = (
            f"Gmail push: active. Watch expires in {days_remaining} "
            f"day{'s' if days_remaining != 1 else ''} (auto-renewed daily). "
            f"Safety-net poll every {interval_min} min."
        )
        status_name = "push-active"
    else:
        msg = (
            f"Polling Gmail every {interval_min} min for new messages. "
            f"Configure Gmail Pub/Sub on the Config page for sub-second delivery."
        )
        status_name = "polling"

    status = {
        "status": status_name,
        "processed": 0,
        "errors": 0,
        "last_message": None,
        "last_error": None,
        "started_at": None,
    }
    return msg, status


def _triage_page_snapshot(
    db, user: dict, owner_filter_q: str | None,
) -> dict:
    """#135 phase 2 — accounts + recent bulk-triage jobs in one
    threadpool hop. The owner-filter logic is pure (no DB), so we keep
    it inside the hop to land a single coherent ctx dict."""
    from email_triage.web.db import (
        list_email_accounts, list_triage_jobs, list_labels,
    )

    is_admin = user["role"] == "admin"
    if is_admin:
        all_accounts = list_email_accounts(db)
    else:
        all_accounts = list_email_accounts(db, user_id=user["id"])

    visible_owners = _build_visible_owners(all_accounts, user)
    owner_filter, accounts = _apply_owner_filter(
        all_accounts, owner_filter_q, user["id"], visible_owners,
    )

    visible_account_ids = {a["id"] for a in accounts}
    recent_jobs_all = (
        list_triage_jobs(db, limit=10) if visible_account_ids else []
    )
    recent_jobs = [
        j for j in recent_jobs_all
        if j["account_id"] in visible_account_ids
    ]
    accounts_by_id = {a["id"]: a for a in accounts}

    # #129 — labels surface as a filter on the Triage form. Carry the
    # full catalog (operator picks one slug). Empty list = no filter
    # control rendered, matching the bulk-tag toolbar's gate.
    all_labels = list_labels(db)

    return {
        "all_labels": all_labels,
        "accounts": accounts,
        "visible_owners": visible_owners,
        "owner_filter": owner_filter,
        "recent_jobs": recent_jobs,
        "accounts_by_id": accounts_by_id,
        "all_labels": all_labels,
    }


def _build_visible_owners(
    accounts: list[dict], user: dict,
) -> list[dict]:
    """Return [{id, label}] one entry per distinct owner across the
    visible accounts. Empty list if all accounts share the current
    user as owner (filter is suppressed in that case).

    Style matches /accounts (manage.html): ``"name (email)"`` if name
    present, else email, else ``"User #N"``. No "Me" alias — every
    owner appears under their own name. Sorted alphabetically.
    """
    owners_seen: dict[int, dict] = {}
    for a in accounts:
        oid = a.get("user_id")
        if oid is None or oid in owners_seen:
            continue
        email = a.get("owner_email") or ""
        name = a.get("owner_name") or ""
        if name and email:
            label = f"{name} ({email})"
        else:
            label = name or email or f"User #{oid}"
        owners_seen[oid] = {"id": oid, "label": label}
    if len(owners_seen) <= 1:
        return []
    return sorted(
        owners_seen.values(), key=lambda x: x["label"].lower(),
    )


def _apply_owner_filter(
    accounts: list[dict], raw_filter: str | None,
    current_user_id: int, visible_owners: list[dict],
) -> tuple[int | str, list[dict]]:
    """Pick the active owner filter + filter accounts.

    Default = current user. ``raw_filter`` of "all" returns the
    unfiltered list. Any other value parses as an integer user_id
    that must be in ``visible_owners``; falls back to current user
    on bad input.
    """
    if not visible_owners:
        return current_user_id, accounts
    valid_ids = {o["id"] for o in visible_owners}
    if raw_filter == "all":
        return "all", accounts
    try:
        candidate = int(raw_filter) if raw_filter else current_user_id
    except (TypeError, ValueError):
        candidate = current_user_id
    if candidate not in valid_ids:
        candidate = current_user_id
    return candidate, [a for a in accounts if a.get("user_id") == candidate]


def _job_eta_secs(job: dict) -> int | None:
    """Best-guess ETA in seconds based on observed throughput + rate.

    Computed at progress-page render time. Returns None when there's
    not enough signal (no started_at, no progress yet, no provider
    page count). The runner doesn't know total_seen up-front because
    paged search streams — total_seen grows as batches arrive."""
    if not job.get("started_at"):
        return None
    seen = int(job.get("total_seen") or 0)
    processed = int(job.get("total_processed") or 0)
    if seen <= processed or processed == 0:
        return None
    from datetime import datetime, timezone
    try:
        started = datetime.fromisoformat(job["started_at"])
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    elapsed = (now - started).total_seconds()
    if elapsed <= 0:
        return None
    rate_obs = processed / elapsed  # msg/sec achieved so far
    if rate_obs <= 0:
        return None
    remaining = seen - processed
    return int(remaining / rate_obs)


def _discover_page_snapshot(
    db, user: dict, owner_filter_q: str | None,
) -> dict:
    """#135 phase 2 — accounts list + visible-owners filter in one
    threadpool hop."""
    from email_triage.web.db import list_email_accounts
    is_admin = user["role"] == "admin"
    if is_admin:
        all_accounts = list_email_accounts(db)
    else:
        all_accounts = list_email_accounts(db, user_id=user["id"])

    visible_owners = _build_visible_owners(all_accounts, user)
    owner_filter, accounts = _apply_owner_filter(
        all_accounts, owner_filter_q, user["id"], visible_owners,
    )
    return {
        "accounts": accounts,
        "visible_owners": visible_owners,
        "owner_filter": owner_filter,
    }


def _parse_llm_json_or_array(text: str):
    """Extract a JSON object or array from LLM output.

    Extends _parse_llm_json to also handle top-level JSON arrays.
    """
    from email_triage.classify.ollama import _strip_think_tags
    import json as _json

    cleaned = _strip_think_tags(text).strip()

    # Strip markdown code fences if present.
    if cleaned.startswith("```"):
        first_newline = cleaned.index("\n")
        cleaned = cleaned[first_newline + 1:]
        if "```" in cleaned:
            cleaned = cleaned[:cleaned.rindex("```")]
        cleaned = cleaned.strip()

    # Try array first, then object.
    arr_start = cleaned.find("[")
    obj_start = cleaned.find("{")

    if arr_start != -1 and (obj_start == -1 or arr_start < obj_start):
        # Looks like an array.
        end = cleaned.rfind("]")
        if end > arr_start:
            return _json.loads(cleaned[arr_start:end + 1])

    if obj_start != -1:
        end = cleaned.rfind("}")
        if end > obj_start:
            return _json.loads(cleaned[obj_start:end + 1])

    raise ValueError(f"No JSON found in LLM response: {text[:200]}")


def _build_classifier_from_config(config):
    """Create a classifier instance from the global config."""
    backend = config.classifier.backend
    local_suffixes = list(getattr(config.tls, "local_url_suffixes", []) or [])
    if backend == "ollama":
        from email_triage.classify.ollama import OllamaClassifier
        return OllamaClassifier(
            model=config.classifier.model,
            base_url=config.classifier.ollama_url,
            prefer_loaded=config.classifier.prefer_loaded,
            local_url_suffixes=local_suffixes,
        )
    elif backend == "openai":
        from email_triage.classify.openai_compat import OpenAICompatClassifier
        return OpenAICompatClassifier(
            base_url=config.classifier.openai_base_url,
            model=config.classifier.openai_model,
            local_url_suffixes=local_suffixes,
        )
    elif backend == "gemini":
        from email_triage.classify.gemini import GeminiClassifier
        return GeminiClassifier(
            model=config.classifier.gemini_model or "gemini-2.0-flash",
        )
    else:
        raise ValueError(f"Unknown classifier backend: {backend}")


def _load_all_list_hints(db):
    """Load all classification lists and rules from the DB.

    #134.1 — issues exactly TWO queries (lists, then a single
    ``list_rules`` SELECT bucketed by ``list_id`` in Python),
    replacing the prior 1 + N pattern (one rules-SELECT per list).
    Returns ``(lists, rules_by_list)`` so callers can pass the pair
    into :func:`_collect_list_hints_for_message` for in-loop use.
    """
    from email_triage.engine.models import ClassificationList, ListRule, RuleType

    rows = db.execute(
        "SELECT id, name, category, owner_id, is_global FROM classification_lists"
    ).fetchall()

    lists: list[ClassificationList] = []
    rules_by_list: dict[int, list[ListRule]] = {}
    if not rows:
        return lists, rules_by_list

    for row in rows:
        lists.append(ClassificationList(
            id=row["id"],
            name=row["name"],
            category=row["category"],
            owner_id=row["owner_id"],
            is_global=bool(row["is_global"]),
        ))
        rules_by_list[row["id"]] = []

    # Single bulk fetch over every rule, then bucket by list_id in Python.
    # Avoids the N-list × per-list SELECT pattern that triggered the bug.
    rule_rows = db.execute(
        "SELECT id, list_id, rule_type, pattern, skip_ai FROM list_rules"
    ).fetchall()
    for r in rule_rows:
        bucket = rules_by_list.get(r["list_id"])
        if bucket is None:
            # Orphan rule (list_id with no parent in classification_lists).
            # Skip — collect_hints would never reach it anyway.
            continue
        bucket.append(ListRule(
            id=r["id"],
            list_id=r["list_id"],
            rule_type=RuleType(r["rule_type"]),
            pattern=r["pattern"],
            skip_ai=bool(r["skip_ai"]),
        ))

    return lists, rules_by_list


# ---------------------------------------------------------------------------
# Runtime settings helpers
# ---------------------------------------------------------------------------

_RUNTIME_SETTINGS_KEY = "runtime_settings"

_RUNTIME_DEFAULTS = {
    "dry_run": False,
    "log_level": "INFO",
    "hipaa": False,
    # #101 — bulk whole-mailbox triage knobs. Deployment-specific
    # because they depend on the local LLM backend's hardware
    # throughput + the provider rate limits the install operates
    # under. Conservative defaults: 1 concurrent message at a time,
    # 30 messages per minute. Operator tunes upward on /config
    # after watching real-world LLM throughput.
    "bulk_triage_rate_msg_per_min": 30,
    "bulk_triage_concurrency": 1,
    # #145.2 — operator-tunable burst depth for the per-job
    # ``TokenBucket``. Default 1 keeps the legacy "single-step at the
    # configured cadence" behaviour so an upgrade preserves observed
    # throughput. Tuning higher lets the first N messages of a job
    # fire back-to-back before the rate-limit cadence kicks in,
    # smoothing cold starts on big sweeps.
    "bulk_triage_burst": 1,
}

# Hard ceilings enforced by the /config save handler. Concurrency is
# capped at 8 (operator stated 2026-05-06 — higher values risk
# overrunning a single-GPU LLM box's parallel-request budget); rate
# is capped at 600/min (10/sec) which is already faster than any
# realistic local LLM.
BULK_TRIAGE_RATE_MIN = 1
BULK_TRIAGE_RATE_MAX = 600
BULK_TRIAGE_CONCURRENCY_MIN = 1
BULK_TRIAGE_CONCURRENCY_MAX = 8
# #145.2 — burst floor of 1 keeps the legacy single-step behaviour;
# a 100-token ceiling is well above any realistic warm-up need (the
# bucket would empty in seconds at the configured rate either way).
BULK_TRIAGE_BURST_MIN = 1
BULK_TRIAGE_BURST_MAX = 100


def _get_runtime_settings(db) -> dict:
    """Return runtime settings dict, falling back to defaults."""
    from email_triage.web.db import get_setting
    saved = get_setting(db, _RUNTIME_SETTINGS_KEY)
    if saved is None:
        return dict(_RUNTIME_DEFAULTS)
    merged = dict(_RUNTIME_DEFAULTS)
    merged.update(saved)
    return merged


def _is_dry_run(db) -> bool:
    """Quick check: is dry-run mode currently enabled?"""
    return _get_runtime_settings(db).get("dry_run", False)


def _apply_runtime_settings(settings: dict) -> None:
    """Push runtime overrides into the running process (logging, HIPAA)."""
    import logging as stdlib_logging
    from email_triage import triage_logging

    # Update log level on the root email_triage logger.
    level_name = settings.get("log_level", "INFO").upper()
    root = stdlib_logging.getLogger("email_triage")
    root.setLevel(getattr(stdlib_logging, level_name, stdlib_logging.INFO))

    # Update HIPAA mode flag.
    triage_logging._hipaa_mode = settings.get("hipaa", False)


# ---------------------------------------------------------------------------
# Admin Config page
# ---------------------------------------------------------------------------

def _config_page_snapshot(db, config) -> dict:
    """#135 phase 2 — runtime + BAA mirror + anti-AI install-wide guide
    in one threadpool hop.

    #161 — also includes the two style-learning admin knobs
    (auto-scan cadence, default mine size) + the inline-handoff
    ceiling so the section's copy stays in sync with the helper
    used by the inline mine path."""
    runtime = _get_runtime_settings(db)
    baa_status = None
    try:
        cls = _build_classifier_from_config(config)
        from email_triage.classify.baa_gate import classifier_baa_status
        baa_status = classifier_baa_status(db, cls)
    except Exception:
        pass
    try:
        from email_triage.web.db import get_global_anti_ai_style_guide
        anti_ai_global = get_global_anti_ai_style_guide(db)
    except Exception:
        anti_ai_global = ""
    try:
        from email_triage.web.db import (
            get_style_learning_capture_interval_hours,
            get_style_learning_mine_limit_default,
            STYLE_LEARNING_INLINE_LIMIT_CEILING,
        )
        style_capture_hours = get_style_learning_capture_interval_hours(db)
        style_mine_limit = get_style_learning_mine_limit_default(db)
        inline_limit_ceiling = STYLE_LEARNING_INLINE_LIMIT_CEILING
    except Exception:
        style_capture_hours = 6
        style_mine_limit = 50
        inline_limit_ceiling = 50
    return {
        "runtime": runtime,
        "classifier_baa_status": baa_status,
        "anti_ai_style_guide_global": anti_ai_global,
        "style_learning_capture_interval_hours": style_capture_hours,
        "style_learning_mine_limit_default": style_mine_limit,
        "inline_limit_ceiling": inline_limit_ceiling,
    }


def _admin_security_snapshot(db, config) -> dict:
    """#135 phase 2 — BAA mirror + CSRF reject counters + top-paths in one
    threadpool hop. Touches access_log + (fallback) log_entries; both are
    DB reads."""
    baa_status = None
    try:
        cls = _build_classifier_from_config(config)
        from email_triage.classify.baa_gate import classifier_baa_status
        baa_status = classifier_baa_status(db, cls)
    except Exception:
        pass

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    cutoff_24h = (now - timedelta(hours=24)).isoformat()
    cutoff_7d = (now - timedelta(days=7)).isoformat()
    rejects_24h = 0
    rejects_7d = 0
    try:
        rejects_24h = int(db.execute(
            "SELECT COUNT(*) FROM access_log "
            "WHERE outcome IN ('csrf_would_reject','csrf_rejected') "
            "AND ts >= ?",
            (cutoff_24h,),
        ).fetchone()[0])
        rejects_7d = int(db.execute(
            "SELECT COUNT(*) FROM access_log "
            "WHERE outcome IN ('csrf_would_reject','csrf_rejected') "
            "AND ts >= ?",
            (cutoff_7d,),
        ).fetchone()[0])
    except Exception:
        try:
            rejects_24h = int(db.execute(
                "SELECT COUNT(*) FROM log_entries "
                "WHERE logger='email_triage.web.csrf' "
                "AND message LIKE 'CSRF token%' AND created_at >= ?",
                (cutoff_24h,),
            ).fetchone()[0])
            rejects_7d = int(db.execute(
                "SELECT COUNT(*) FROM log_entries "
                "WHERE logger='email_triage.web.csrf' "
                "AND message LIKE 'CSRF token%' AND created_at >= ?",
                (cutoff_7d,),
            ).fetchone()[0])
        except Exception:
            pass

    top_paths_24h: list[tuple[str, int]] = []
    try:
        rows = db.execute(
            "SELECT route, COUNT(*) AS n FROM access_log "
            "WHERE outcome IN ('csrf_would_reject','csrf_rejected') "
            "AND ts >= ? "
            "GROUP BY route ORDER BY n DESC LIMIT 5",
            (cutoff_24h,),
        ).fetchall()
        top_paths_24h = [(r["route"], int(r["n"])) for r in rows]
    except Exception:
        pass

    return {
        "baa_status": baa_status,
        "rejects_24h": rejects_24h,
        "rejects_7d": rejects_7d,
        "top_paths_24h": top_paths_24h,
    }


def _write_config_yaml(config) -> None:
    """Write the current config back to the YAML file it was loaded from."""
    import yaml
    from pathlib import Path

    # Find the config file (same search order as load_config).
    search_paths = [
        Path("./email-triage.yaml"),
        Path("./config/email-triage.yaml"),
        Path.home() / ".config" / "email-triage" / "config.yaml",
    ]
    target = None
    for p in search_paths:
        if p.exists():
            target = p
            break

    if target is None:
        raise FileNotFoundError("No config YAML file found to update")

    # Build the YAML structure.
    data: dict = {}

    # Provider — preserve as-is from the existing file to avoid losing nested dicts.
    try:
        with open(target) as f:
            existing = yaml.safe_load(f) or {}
        if "provider" in existing:
            data["provider"] = existing["provider"]
    except Exception:
        pass

    # Classifier
    data["classifier"] = {
        "backend": config.classifier.backend,
        "model": config.classifier.model,
        "ollama_url": config.classifier.ollama_url,
    }
    if config.classifier.openai_base_url:
        data["classifier"]["openai_base_url"] = config.classifier.openai_base_url
    if config.classifier.openai_model:
        data["classifier"]["openai_model"] = config.classifier.openai_model
    if config.classifier.gemini_model:
        data["classifier"]["gemini_model"] = config.classifier.gemini_model
    if config.classifier.categories:
        data["classifier"]["categories"] = dict(config.classifier.categories)

    # Routes — preserve from existing file.
    if "routes" in existing:
        data["routes"] = existing["routes"]

    # SMTP
    data["smtp"] = {
        "host": config.smtp.host,
        "port": config.smtp.port,
        "username": config.smtp.username,
        "from_addr": config.smtp.from_addr,
        "from_name": config.smtp.from_name,
        "use_tls": config.smtp.use_tls,
    }

    # Health email (#27) + summary signature (#33).
    # CR-2c — ``recipients`` is intentionally NOT written to the
    # ``health_email`` block here. The canonical destination is the
    # sibling ``admin_email`` block below. Legacy recipients are
    # preserved on read (via :func:`resolve_admin_recipients`) only
    # until the next Save, which writes the empty list and the new
    # ``admin_email.recipients`` instead.
    data["health_email"] = {
        "enabled": config.health_email.enabled,
        "recipients": list(config.health_email.recipients),
        "send_at": config.health_email.send_at,
        "include_health": config.health_email.include_health,
        "include_watchers": config.health_email.include_watchers,
        "include_triage": config.health_email.include_triage,
        "include_errors": config.health_email.include_errors,
        "include_hipaa_events": config.health_email.include_hipaa_events,
        "include_api_key_events": config.health_email.include_api_key_events,
        "include_pubsub": config.health_email.include_pubsub,
        "include_update_available": config.health_email.include_update_available,
        "quiet_mode": config.health_email.quiet_mode,
        "error_rate_threshold_pct": config.health_email.error_rate_threshold_pct,
    }
    # CR-2c — canonical admin-notification destination. Same list
    # serves daily health digest + update-failed alerts + future
    # admin-targeted channels.
    data["admin_email"] = {
        "recipients": list(config.admin_email.recipients),
        "release_check_url": config.admin_email.release_check_url,
    }
    data["summary_email"] = {
        "signature": config.summary_email.signature,
    }

    # Escalation
    data["escalation"] = {
        "enabled": config.escalation.enabled,
        "categories": config.escalation.categories,
    }

    # Logging — emit every dataclass field so a future change to
    # retention / hipaa / etc. round-trips through Save without
    # silently reverting on next reload.
    data["logging"] = {
        "level": config.logging.level,
        "format": config.logging.format,
        "hipaa": config.logging.hipaa,
        "retention_days": config.logging.retention_days,
        "max_rows": config.logging.max_rows,
    }
    if config.logging.file:
        data["logging"]["file"] = config.logging.file

    # Secrets — preserve from existing.
    data["secrets"] = {
        "backend": config.secrets.backend,
        "keyfile_path": config.secrets.keyfile_path,
    }

    # Persistence
    data["persistence"] = {
        "db_path": config.persistence.db_path,
    }

    # Ingestion cadence. Bounds are class-level constants (never need
    # to round-trip YAML). Legacy push_/poll_poll_interval_min fields
    # are preserved so operators with those in their existing YAML
    # don't lose them on Save.
    data["ingestion"] = {
        "default_poll_interval_minutes": config.ingestion.default_poll_interval_minutes,
        "push_poll_interval_min": config.ingestion.push_poll_interval_min,
        "poll_poll_interval_min": config.ingestion.poll_poll_interval_min,
    }

    # TLS + ACME (#67). Round-trip the cert_dir + acme block so the
    # /admin/acme-status edit form can persist nameserver / TSIG /
    # domains without operator-side YAML editing.
    tls_block: dict[str, Any] = {}
    if config.tls.cert_dir:
        tls_block["cert_dir"] = config.tls.cert_dir
    # Always emit so save round-trips (omitting on False would let
    # the loader's fallback flip the listener mode unexpectedly).
    tls_block["enabled"] = bool(config.tls.enabled)
    tls_block["csrf_enforce"] = bool(getattr(config.tls, "csrf_enforce", False))
    # #82 item 4 — operator-defined CSRF exempt path prefixes.
    # Round-trip preserves the operator's list verbatim. Empty
    # list omitted (no harm in absence; default state).
    csrf_exempt = list(
        getattr(config.tls, "csrf_exempt_prefixes", []) or [],
    )
    if csrf_exempt:
        tls_block["csrf_exempt_prefixes"] = csrf_exempt
    # Operator-extensible local-host suffix list. Source tree carries
    # no operator-specific suffix; the operator declares their internal
    # DNS suffix(es) here so webhook / LLM-backend dispatch will treat
    # them as local. Round-trip preserves the list verbatim.
    suffixes = list(getattr(config.tls, "local_url_suffixes", []) or [])
    if suffixes:
        tls_block["local_url_suffixes"] = suffixes
    a = config.tls.acme
    if a.enabled or a.account_email or a.domains or a.rfc2136.nameserver:
        acme_block: dict[str, Any] = {
            "enabled": a.enabled,
            "directory_url": a.directory_url,
            "account_email": a.account_email,
            "domains": list(a.domains),
            "challenge": a.challenge,
            "renewal_threshold_days": a.renewal_threshold_days,
            "check_interval_hours": a.check_interval_hours,
            "pre_validation_grace_secs": a.pre_validation_grace_secs,
            "validation_retries": a.validation_retries,
            "validation_retry_delay_secs": a.validation_retry_delay_secs,
            "validation_retry_backoff": a.validation_retry_backoff,
            "caa_enforce": a.caa_enforce,
            "dns_provider": a.dns_provider,
        }
        rfc = a.rfc2136
        if (rfc.nameserver or rfc.tsig_key_name or rfc.update_zone):
            acme_block["rfc2136"] = {
                "nameserver": rfc.nameserver,
                "nameserver_port": rfc.nameserver_port,
                "tsig_key_name": rfc.tsig_key_name,
                "tsig_algorithm": rfc.tsig_algorithm,
                "tsig_secret_ref": rfc.tsig_secret_ref,
                "update_zone": rfc.update_zone,
                "public_resolvers": list(rfc.public_resolvers),
                "public_propagation_timeout_secs": rfc.public_propagation_timeout_secs,
                "public_propagation_interval_secs": rfc.public_propagation_interval_secs,
                "public_propagation_split_horizon_wait_secs": getattr(
                    rfc, "public_propagation_split_horizon_wait_secs", 600,
                ),
            }
        tls_block["acme"] = acme_block
    if tls_block:
        data["tls"] = tls_block

    # Auth / session TTL (#67 follow-up). Always written so the
    # round-trip is lossless even when the operator never touches
    # the dropdown (defaults survive). HIPAA cap is clamped at LOAD
    # time, not write time -- the writer just emits whatever the
    # in-memory config says, and the loader enforces the ceiling on
    # the way back in. Avoids the silent-clamp surprise where a
    # written value disagrees with the loaded value.
    data["auth"] = {
        "session_ttl_secs": int(getattr(
            getattr(config, "auth", None), "session_ttl_secs", 86400,
        )),
        "hipaa_session_ttl_secs": int(getattr(
            getattr(config, "auth", None), "hipaa_session_ttl_secs", 900,
        )),
        # #92 login rate-limit tunables. Always emit so operator
        # /admin/security saves round-trip through YAML losslessly.
        "login_per_email_max": int(getattr(
            getattr(config, "auth", None), "login_per_email_max", 10,
        )),
        "login_per_email_window_secs": int(getattr(
            getattr(config, "auth", None),
            "login_per_email_window_secs", 600,
        )),
        "login_per_ip_max": int(getattr(
            getattr(config, "auth", None), "login_per_ip_max", 30,
        )),
        "login_per_ip_window_secs": int(getattr(
            getattr(config, "auth", None),
            "login_per_ip_window_secs", 600,
        )),
    }

    # WebAuthn (#67). rp_id locked once registered — written here so
    # operator can configure via /admin/acme-status without editing
    # YAML by hand on the host.
    w = config.webauthn
    if w.rp_id or w.origin or w.rp_name != "Email Triage":
        data["webauthn"] = {
            "rp_id": w.rp_id,
            "rp_name": w.rp_name,
            "origin": w.origin,
            "require_user_verification_for_admin":
                w.require_user_verification_for_admin,
        }

    # Push (Gmail Pub/Sub + OpenClaw API). Always emit the four Gmail
    # Pub/Sub knobs so the /admin/integrations save round-trips through
    # YAML losslessly. Emitting unconditionally avoids the silent-revert
    # surprise where a save of empty strings disappears on next reload
    # (loader fills the defaults right back in -- we want the operator's
    # "" pick to stick if they want push off).
    p = config.push
    push_block: dict[str, Any] = {
        "listen_port": int(getattr(p, "listen_port", 8080)),
        "public_url": p.public_url,
        "gmail_topic_name": p.gmail_topic_name,
        "gmail_subscription_sa_email": p.gmail_subscription_sa_email,
        "gmail_audience": p.gmail_audience,
    }
    # OpenClaw / bulk knobs — preserve only when set away from default to
    # keep the YAML diff readable.
    if not getattr(p, "openclaw_webhook_enabled", True):
        push_block["openclaw_webhook_enabled"] = False
    rl = int(getattr(p, "openclaw_rate_limit_per_minute", 60))
    if rl != 60:
        push_block["openclaw_rate_limit_per_minute"] = rl
    bs = int(getattr(p, "bulk_max_batch_size", 100))
    if bs != 100:
        push_block["bulk_max_batch_size"] = bs
    data["push"] = push_block

    # #151 — Classification cache. Only emit when the operator has
    # configured a URL; defaults are absent from YAML so a fresh
    # config file stays minimal.
    rc = getattr(config, "redis_cache", None)
    if rc is not None and (rc.url or "").strip():
        data["redis_cache"] = {
            "url": rc.url.strip(),
            "ttl_secs": int(rc.ttl_secs),
            # New 2026-05-13 tuning knobs — round-trip so the admin
            # /config?tab=ai_backends save doesn't silently revert on
            # next load. Emit unconditionally so non-default values
            # stick + default values stay legible in the YAML diff.
            "inner_cap_per_sender": int(
                getattr(rc, "inner_cap_per_sender", 250),
            ),
            "hint_strategy": str(
                getattr(rc, "hint_strategy", "top_k_with_freq"),
            ),
            "dominant_threshold_pct": int(
                getattr(rc, "dominant_threshold_pct", 70),
            ),
        }

    # Embedding backend (M-4 / M-5). Round-trip the primary + optional
    # fallback so the admin /config/ai-backends save doesn't silently
    # revert on next load. Only emit when the operator has configured
    # something — absence stays the canonical "disabled" signal.
    emb = getattr(config, "embedding", None)
    if emb is not None and (emb.backend or "").strip():
        emb_block: dict[str, Any] = {
            "backend": emb.backend,
            "model_name": emb.model_name,
            "ollama_url": emb.ollama_url,
        }
        fb = getattr(emb, "fallback", None)
        if fb is not None and (fb.backend or "").strip():
            fb_block: dict[str, Any] = {
                "backend": fb.backend,
                "model_name": fb.model_name,
            }
            if (fb.ollama_url or "").strip():
                fb_block["ollama_url"] = fb.ollama_url
            emb_block["fallback"] = fb_block
        data["embedding"] = emb_block

    with open(target, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Daily health email — "Send now" (#27)
# ---------------------------------------------------------------------------

