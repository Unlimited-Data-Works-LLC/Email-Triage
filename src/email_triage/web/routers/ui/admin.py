"""Routes for the admin concern.

Split out of the legacy `web/routers/ui.py`. Helpers
live in `_shared`; this file holds only the @router-decorated
handlers + handler-local helpers for this URL surface.
No behavior changes from pre-split — every handler body is
byte-for-byte identical.
"""
from __future__ import annotations

import asyncio
import email as email_mod
import email.policy
import email.utils
import json as json_mod
import os
import sqlite3

from email_triage._envbool import parse_bool
from email_triage.ai_backends.ollama_adapter import DEFAULT_OLLAMA_BASE_URL  # N-268 R27 hardcode-audit
import time
from datetime import datetime, timezone
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web.routers._redirect import err_qs
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
from email_triage.web._audit import safe_audit_write
from email_triage.web.dependencies import (
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    RequireUserFragment,
    admin_gate_response,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.admin")

router = APIRouter()


from . import _shared
# Snapshot every helper from _shared into this module's globals so
# handler bare-name references resolve. globals().update is used
# instead of `from _shared import *` because * skips underscore-
# prefixed names (which is most helpers).
globals().update({
    _n: _v for _n, _v in vars(_shared).items()
    if not _n.startswith('__')
})


def __getattr__(name):
    """Legacy install-singleton names + PEP-562 fallback to ``_shared``.

    Two roles folded into one module-level ``__getattr__`` (census
    wf_56d1585d 2026-07-09 D3 — SSOT self-shadowing fix; Python only
    honours the LAST ``__getattr__`` per module, so previously the
    install-singleton compat glue was dead code from an unnoticed second
    override):

    1. Route reads of legacy install-singleton names
       (``_install_google_oauth`` / ``_install_ingestion_config``) through
       the factory module. Code that did
       ``from email_triage.web.routers.ui import _install_ingestion_config``
       (test fixtures, future plugins) keeps working.
    2. Late-bound lookup on ``_shared`` — catches names added to
       ``_shared`` after this module's ``globals().update`` populated, plus
       names the package-level monkeypatch mirror writes onto ``_shared``
       after import.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


@router.get("/sw.js")
async def service_worker():
    from fastapi.responses import Response
    from email_triage.web.app import _STATIC_DIR

    sw_path = _STATIC_DIR / "sw.js"
    body = sw_path.read_bytes()
    return Response(
        content=body,
        media_type="application/javascript",
        headers={
            # Widen the SW's scope to the site root. Without this
            # header the browser refuses to register a /sw.js worker
            # against scope ``/`` because the SW file lives at the
            # root path itself; the header is the canonical opt-in.
            "Service-Worker-Allowed": "/",
            # Keep the SW fresh — operators tweaking sw.js shouldn't
            # have to wait for a 24h cache expiry to propagate.
            "Cache-Control": "no-cache",
        },
    )


# ---------------------------------------------------------------------------
# PWA offline shell
# ---------------------------------------------------------------------------

@router.get("/offline", response_class=HTMLResponse)
async def offline_shell(request: Request):
    """Static offline shell for the installed PWA.

    The service worker is intentionally pass-through (no caching of
    PHI-bearing pages — the SW cache is persistent and tab-shared, so
    caching /dashboard would leak inbox content across browser
    profiles). When the device is offline the browser falls back to
    its built-in error page; this route exists so an end user can
    bookmark or be redirected to a branded "you're offline" notice
    that explains what to do, without exposing any account data.

    Unauthenticated by design — the page renders no user-specific
    content and must be reachable when no session cookie is present.
    """
    templates = get_templates(request)
    return await _render(templates, request, "offline.html", {})


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def root(request: Request, user: RequireUser):
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/clocks", response_class=HTMLResponse)
async def regulatory_clocks_page(request: Request, user: RequireUser):
    """ — the user's regulatory deadline clocks (label + days-left + state),
    scoped to their own accounts (owner self-access). HIPAA-minimal; advisory."""
    templates = get_templates(request)
    db = get_db(request)

    def _build():
        from email_triage.db.regulatory_clock import list_compliance_clocks
        return list_compliance_clocks(db, user_id=user["id"])

    clocks = await db_call(_build)
    return await _render(templates, request, "regulatory_clocks.html", {
        "user": user, "clocks": clocks,
    })


@router.post("/clocks/{instance_id}/{action}", response_class=HTMLResponse)
async def clock_disposition(
    instance_id: int, action: str, request: Request, user: RequireUserFragment,
):
    """ — a human disposition on ONE clock (confirm / ack / submit / dismiss).

    PD#9 ACTUATOR gate: the clock's account MUST be owned by the requester (a
    user cannot act on another user's clock by POSTing its id). Returns the
    refreshed ``#clocks-table`` fragment (HTMX outerHTML swap). A state-machine
    refusal (terminal / write-once) re-renders the current state, never 500s."""
    templates = get_templates(request)
    db = get_db(request)
    config = request.app.state.config

    def _act():
        from email_triage.db.regulatory_clock import (
            ack_clock, confirm_reportable, dismiss_clock,
            list_compliance_clocks, submit_clock, user_owns_clock_account,
            working_day_calendar_from_config,
        )
        if not user_owns_clock_account(db, user["id"], instance_id):
            return None  # PD#9 — refuse before any write
        try:
            if action == "confirm":
                confirm_reportable(
                    db, instance_id=instance_id, actor_user_id=user["id"],
                    calendar=working_day_calendar_from_config(config),
                )
            elif action == "ack":
                ack_clock(db, instance_id=instance_id, actor_user_id=user["id"])
            elif action == "submit":
                submit_clock(
                    db, instance_id=instance_id, actor_user_id=user["id"],
                )
            elif action == "dismiss":
                dismiss_clock(
                    db, instance_id=instance_id, actor_user_id=user["id"],
                )
            else:
                return None  # unknown action
        except Exception:
            pass  # state-machine refusal → re-render current state, no 500
        return list_compliance_clocks(db, user_id=user["id"])

    clocks = await db_call(_act)
    if clocks is None:
        return HTMLResponse("Not permitted.", status_code=403)
    return await _render(templates, request, "_clocks_table.html", {
        "user": user, "clocks": clocks,
    })


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: RequireUser):
    templates = get_templates(request)

    # : dashboard build is read-heavy (getting-started, recent runs,
    # health-chip rollup, watcher-banner account fetch). Run the whole
    # build off the event loop so concurrent /health polls + other
    # operator surfaces don't serialise behind it.
    ctx = await db_call(_build_dashboard_context, request, user)

    return await _render(templates, request, "dashboard.html", ctx)


@router.post("/dashboard/dismiss-step", response_class=HTMLResponse)
async def dashboard_dismiss_step(request: Request, user: RequireUserFragment):
    """Mark a getting-started checklist step as dismissed for the user."""
    db = get_db(request)
    form = await request.form()
    step_id = (form.get("step_id") or "").strip()
    if not step_id:
        return HTMLResponse("Missing step_id", status_code=400)

    from email_triage.web.db import (
        get_dashboard_dismissed_steps, set_dashboard_dismissed_steps,
    )

    def _dismiss_step_db_work() -> None:
        """/ — read current dismissed set + append + write,
        all in one threadpool hop.
        """
        current = get_dashboard_dismissed_steps(db, user["id"])
        if step_id not in current:
            current.append(step_id)
            set_dashboard_dismissed_steps(db, user["id"], current)

    await db_call(_dismiss_step_db_work)
    # HTMX: swap out with an empty fragment (card disappears).
    return HTMLResponse("")


@router.get("/admin/stats", response_class=HTMLResponse)
async def admin_stats_page(request: Request):
    """Dedicated admin stats page — volume, performance, classification, health.

    Every stat that used to live on the dashboard got migrated here so
    the dashboard can focus on orientation. Default window is last 24h;
    the dropdown bumps to 1h / 7d / 30d.
    """
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    templates = get_templates(request)
    db = get_db(request)
    window = (request.query_params.get("window") or "24h").lower()

    snap = await db_call(_admin_stats_snapshot, db, request, window)

    # 2026-05-13 — pull the same health-detail payload the JSON
    # endpoint serves so /admin/stats can render every operational
    # signal (csrf_rejects, audit_failures, classification cache
    # counters, schema_version, version, uptime, supervised-task
    # state, ingestion rollup). Single function call so the two
    # surfaces never drift.
    from email_triage.web.routers.health import _compute_health_detail
    try:
        health_payload, _degraded = await _compute_health_detail(request)
    except Exception as e:
        _log.warning(
            "admin_stats: health snapshot failed; rendering without it",
            error=fmt_exc(e),
        )
        health_payload = {}

    return await _render(templates, request, "admin/stats.html", {
        "user": user,
        **snap,
        "health": health_payload,
    })


# ---------------------------------------------------------------------------
# System log viewer (admin only)
# ---------------------------------------------------------------------------

@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: RequireUser):
    """Admin log viewer showing recent log entries from SQLite."""
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    templates = get_templates(request)

    level_filter = request.query_params.get("level", "").upper() or None
    offset = _safe_int(request.query_params.get("offset"), 0)
    # Free-text search — matches message + logger + extras (JSON blob).
    query = (request.query_params.get("q") or "").strip() or None

    snap = await db_call(
        _logs_page_snapshot, db, level_filter, offset, query,
    )

    return await _render(templates, request, "logs.html", {
        "user": user,
        "entries": snap["entries"],
        "rows": snap["rows"],
        "level_filter": level_filter,
        "offset": offset,
        "query": query or "",
        "accounts_by_id": snap["accounts_by_id"],
    })


# ---------------------------------------------------------------------------
# Compliance / HIPAA overview (admin only)
# ---------------------------------------------------------------------------

@router.get("/admin/tls", response_class=HTMLResponse)
async def admin_tls_legacy(request: Request):
    """Legacy URL — TLS hub is now a tab on /config.

    303-redirect preserves bookmarks + log links. The ACME / CSR /
    Tailscale / self-signed sub-pages keep their own URLs and are
    linked from the tab body. Auth gate runs FIRST so anonymous
    users still bounce to /login and non-admin users still get 403 —
    preserves the pre-refactor contract that
    ``follow_redirects=False`` tests pin against.
    """
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=tls{tail}", status_code=303,
    )


@router.get("/admin/compliance-security", response_class=HTMLResponse)
async def admin_compliance_security_legacy(request: Request):
    """Legacy URL — Compliance & Security hub is now folded into
    the Security tab on /config (alongside Dev keys).

    303-redirect preserves bookmarks + log links. The underlying
    /admin/security + /compliance pages keep their own URLs and
    are linked from the tab body's card grid. Auth gate runs FIRST
    so anonymous users still bounce to /login and non-admin users
    still get 403.
    """
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=security{tail}", status_code=303,
    )


@router.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request):
    """Admin spot-check of HIPAA state across every account + system.

    Shows: system HIPAA flag, per-account breakdown with lock state,
    recent boundary events. Used for audits.
    """
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    #  reachability — each audit table pages independently via its own
    # offset query param so paging one doesn't reset the others.
    qp = request.query_params
    offsets = {
        "access_events": qp.get("access_offset"),
        "api_key_events": qp.get("apikey_offset"),
        "discover_runs": qp.get("discover_offset"),
        "generic_access_events": qp.get("generic_offset"),
        "recent_events": qp.get("boundary_offset"),
    }
    snap = await db_call(
        _compliance_page_snapshot, db, request.app.state, offsets,
    )

    return await _render(templates, request, "compliance.html", {
        "user": user,
        **snap,
    })


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@router.get("/admin/watches", response_class=HTMLResponse)
async def admin_watches_page(request: Request):
    """List every watch across every account on the install."""
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err
    db = get_db(request)
    items = await db_call(_build_admin_watches_snapshot, db)
    templates = get_templates(request)
    return await _render(
        templates, request, "admin/watches.html",
        {"items": items, "user": user},
    )


# ---------------------------------------------------------------------------
# Classify test page (admin only)
# ---------------------------------------------------------------------------

_CONFIG_TAB_SLUGS = (
    "general", "integrations", "ai_backends",
    "tls", "backup", "security",
)


@router.get("/config", response_class=HTMLResponse)
async def config_page(request: Request, user: RequireUser):
    """Unified admin configuration page (admin only).

    Five tabs collapse the legacy /config + /admin/integrations +
    /admin/tls + /admin/backup + /admin/dev-keys +
    /admin/compliance-security pages onto a single /config?tab=<slug>
    page. The legacy URLs 303-redirect here so bookmarks + tests +
    log links keep resolving.

    Tab slug is read from ``?tab=`` (default ``general``); unknown
    slugs silently fall back to ``general``. Each tab body owns its
    own context-build helper:

      general      -> ``_config_page_snapshot`` (this module)
      integrations -> ``integrations.build_integrations_context``
      tls          -> none (static card grid)
      backup       -> ``backup.build_backup_context``
      security     -> ``auth_keys.build_dev_keys_context``
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    tab = (request.query_params.get("tab") or "general").strip().lower()
    if tab not in _CONFIG_TAB_SLUGS:
        tab = "general"

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    # -D — ``baa_banner`` is auto-injected by ``_shared._render``
    # for admin users (canonical source). Removed from per-handler ctx
    # so the banner has a single source of truth across every admin
    # page (not just /config + /config/ai-backends).
    ctx: dict = {
        "user": user,
        "config": config,
        "active": tab,
    }

    if tab == "general":
        snap = await db_call(_config_page_snapshot, db, config)
        #  partial — schema-compat version banner. Lives on the
        # General tab so the admin sees it on every visit to /config.
        # gather_version_status reads its three numbers cheaply (one
        # read-only DB query for db_schema_version; the rest is in
        # the source); safe to call on every page render.
        version_status = None
        try:
            from email_triage.version import gather_version_status
            #  — gather_version_status opens a SQLite connection
            # and runs a schema-version read; dispatch it off the
            # event loop through db_call so the blocking I/O does not
            # stall the loop.
            version_status = await db_call(
                gather_version_status, config.persistence.db_path,
            )
        except Exception:
            # Banner is informational; never break /config on the
            # version helper failing. The other tabs work unchanged.
            version_status = None
        ctx.update({
            "runtime": snap["runtime"],
            "classifier_baa_status": snap["classifier_baa_status"],
            "anti_ai_style_guide_global": snap["anti_ai_style_guide_global"],
            #  — style-learning admin knobs surfaced in the new
            # Style learning section of /config General tab.
            "style_learning_capture_interval_hours": snap.get(
                "style_learning_capture_interval_hours", 6,
            ),
            "style_learning_mine_limit_default": snap.get(
                "style_learning_mine_limit_default", 50,
            ),
            "inline_limit_ceiling": snap.get("inline_limit_ceiling", 50),
            "version_status": version_status,
            "save_msg": None,
            "save_error": None,
        })
    elif tab == "integrations":
        from email_triage.web.routers.integrations import (
            build_integrations_context,
        )
        ctx.update(await db_call(build_integrations_context, request))
    elif tab == "ai_backends":
        # Admin-only — surfaces the embedding + classifier backend
        # config (primary + optional fallback) that's otherwise
        # YAML-only. Audience: admin operator; technical terms OK on
        # this admin path.
        emb = getattr(config, "embedding", None)
        fb = getattr(emb, "fallback", None) if emb is not None else None
        # Classification cache tuning knobs (2026-05-13 two-level
        # refactor). Surfaced on this admin tab so operators can
        # tune the hint strategy + cap without YAML editing.
        rc = getattr(config, "redis_cache", None)
        cache_metrics: dict = {}
        try:
            from email_triage.cache.classification import (
                get_install_classification_cache, get_counters,
            )
            _live_cache = get_install_classification_cache()
            cache_metrics = get_counters().snapshot()
            cache_metrics["enabled"] = bool(
                _live_cache is not None and _live_cache.enabled,
            )
        except Exception:
            cache_metrics = {}
        ctx.update({
            "embedding_backend": getattr(emb, "backend", "") if emb else "",
            "embedding_model_name": getattr(emb, "model_name", "") if emb else "",
            "embedding_ollama_url": getattr(
                emb, "ollama_url", DEFAULT_OLLAMA_BASE_URL,
            ) if emb else DEFAULT_OLLAMA_BASE_URL,
            "fallback_backend": getattr(fb, "backend", "") if fb else "",
            "fallback_model_name": getattr(fb, "model_name", "") if fb else "",
            "fallback_ollama_url": getattr(fb, "ollama_url", "") if fb else "",
            "classifier_backend": getattr(
                config.classifier, "backend", "",
            ),
            "classifier_model": getattr(config.classifier, "model", ""),
            "classifier_ollama_url": getattr(
                config.classifier, "ollama_url",
                DEFAULT_OLLAMA_BASE_URL,
            ),
            # Live backend that actually loaded at boot — surfaces
            # "what's running RIGHT NOW" vs "what YAML says".
            "live_embedding_backend_type": getattr(
                getattr(request.app.state, "embedding_backend", None),
                "backend_type", None,
            ),
            "live_embedding_model": getattr(
                request.app.state, "embedding_model", "",
            ),
            # Live per-call metrics from the embedding backend
            # (calls / errors / avg latency / fallback fires).
            # Empty dict when no backend configured. Template
            # renders only the fields that exist so primary-only +
            # fallback-chain layouts both work.
            "live_embedding_metrics": (
                _emb.metrics()
                if (
                    _emb := getattr(
                        request.app.state, "embedding_backend", None,
                    )
                ) is not None and hasattr(_emb, "metrics")
                else {}
            ),
            "cache_redis_url": (
                getattr(rc, "url", "") if rc else ""
            ),
            "cache_ttl_secs": (
                int(getattr(rc, "ttl_secs", 2592000)) if rc else 2592000
            ),
            "cache_inner_cap_per_sender": (
                int(getattr(rc, "inner_cap_per_sender", 250)) if rc else 250
            ),
            "cache_hint_strategy": (
                str(getattr(rc, "hint_strategy", "top_k_with_freq"))
                if rc else "top_k_with_freq"
            ),
            "cache_dominant_threshold_pct": (
                int(getattr(rc, "dominant_threshold_pct", 70)) if rc else 70
            ),
            "cache_metrics": cache_metrics,
            "save_msg": request.query_params.get("save_msg", ""),
            "save_error": request.query_params.get("save_error", ""),
        })
        #  — lazy-install state for the local embedding stack.
        # The card sits between the "Currently running" + metrics
        # blocks; the template uses HTMX self-polling on in-flight
        # states. Defensive try: an unmigrated DB (somehow) renders
        # the tab without the install card rather than 500-ing.
        try:
            from email_triage.embedding_bits import (
                get_install_status, is_runtime_ready,
            )
            #  — get_install_status reads the shared connection;
            # dispatch it off the event loop through db_call.
            install_state = await db_call(get_install_status, db)
            manifest_sha = install_state.get("manifest_sha256") or ""
            ctx.update({
                "install_state": install_state,
                "install_manifest_sha_short": manifest_sha[:12] if manifest_sha else "",
                "install_runtime_ready": is_runtime_ready(),
            })
        except Exception:
            ctx.update({
                "install_state": None,
                "install_manifest_sha_short": "",
                "install_runtime_ready": False,
            })
    elif tab == "backup":
        from email_triage.web.routers.backup import build_backup_context
        ctx.update(build_backup_context(request))
    elif tab == "security":
        from email_triage.web.routers.auth_keys import (
            build_dev_keys_context,
        )
        ctx.update(await db_call(build_dev_keys_context, request, user))
    # tab == "tls": no extra context needed — static card grid.

    return await _render(templates, request, "config.html", ctx)


# ---------------------------------------------------------------------------
# /admin/security — auth-policy + compliance knobs (HIPAA + CSRF + session TTL)
# ---------------------------------------------------------------------------

@router.get("/admin/security", response_class=HTMLResponse)
async def admin_security_page(request: Request, user: RequireUser):
    """Security & compliance settings page.

    Single landing page for everything an auditor cares about that
    isn't tied directly to the certificate. HIPAA toggle, session
    TTL (HIPAA-capped), CSRF enforce, and a read-only mirror of the
    classifier BAA acknowledgments (managed on /config alongside the
    LLM picker).
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    snap = await db_call(_admin_security_snapshot, db, config)

    return await _render(templates, request, "admin/security.html", {
        "user": user,
        "auth": getattr(config, "auth", None),
        "tls_csrf_enforce": bool(
            getattr(config.tls, "csrf_enforce", False)
        ),
        "csrf_rejects": int(
            getattr(request.app.state, "csrf_rejects", 0)
        ),
        "csrf_rejects_24h": snap["rejects_24h"],
        "csrf_rejects_7d": snap["rejects_7d"],
        "csrf_top_paths_24h": snap["top_paths_24h"],
        "csrf_exempt_prefixes": list(
            getattr(config.tls, "csrf_exempt_prefixes", []) or [],
        ),
        "audit_failures": int(
            getattr(request.app.state, "audit_failures", 0)
        ),
        "baa_status": snap["baa_status"],
    })


@router.post("/admin/security/save", response_class=HTMLResponse)
async def admin_security_save(request: Request, user: RequireUser):
    """Persist HIPAA toggle + CSRF enforce + session TTL.

    HIPAA flip records a hipaa_boundary_events row (mirrors the
    /config/save behaviour) so the audit trail captures the
    transition. The boundary detector supervised task (PR 9 / D3)
    additionally guards against direct-DB-edit drift.
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    form = await request.form()

    # HIPAA flip — same logic as /config/save, kept consistent so a
    # boundary event is always recorded regardless of which page the
    # operator used.
    from email_triage.triage_logging import is_hipaa_mode as _was_hipaa
    pre_hipaa = _was_hipaa()
    hipaa_flag = "hipaa" in form

    def _security_save_hipaa_db_work() -> None:
        """/ — runtime-settings read + write + (on flip) the
        boundary-event row, all in one threadpool hop. The pure-Python
        _apply_runtime_settings is folded in too — it has no I/O.
        """
        runtime = _get_runtime_settings(db)
        new_runtime = dict(runtime)
        new_runtime["hipaa"] = hipaa_flag
        from email_triage.web.db import set_setting
        set_setting(db, _RUNTIME_SETTINGS_KEY, new_runtime)
        # Bundle E5  / Q4 — admin_security_save is the CANONICAL
        # HIPAA off-ramp and the ONLY source location that should pass
        # allow_hipaa_change=True. The Sub-check D test at
        # tests/test_web/test_runtime_settings_hipaa_gate.py enforces
        # "exactly one call site"; copy-pasting this kwarg into a new
        # caller fires that test immediately.
        _apply_runtime_settings(new_runtime, allow_hipaa_change=True)
        if pre_hipaa != new_runtime["hipaa"]:
            from email_triage.web.db import record_hipaa_boundary
            direction = "on" if new_runtime["hipaa"] else "off"
            record_hipaa_boundary(
                db, "system", direction,
                actor_id=user["id"],
                reason="security page toggle",
            )
            _log.warning(
                "System HIPAA mode changed",
                direction=direction, actor=user["email"],
            )

    await db_call(_security_save_hipaa_db_work)

    # CSRF enforce — live update on app.state so the change takes
    # effect immediately without a restart (unlike tls.enabled).
    csrf_enforce = parse_bool(form.get("tls_csrf_enforce"))
    config.tls.csrf_enforce = csrf_enforce
    request.app.state.csrf_enforce = csrf_enforce

    #  item 4 — operator-defined CSRF exempt path prefixes.
    # Form field is a newline-separated textarea; each line that
    # starts with '/' becomes an entry. Empty / non-/-prefixed lines
    # silently dropped (matches the YAML-loader contract). Refresh
    # app.state so the middleware picks up the new list immediately.
    raw = form.get("csrf_exempt_prefixes", "") or ""
    parsed: list[str] = []
    for line in str(raw).splitlines():
        line = line.strip()
        if line and line.startswith("/"):
            parsed.append(line)
    config.tls.csrf_exempt_prefixes = parsed
    request.app.state.csrf_extra_exempt_prefixes = list(parsed)

    # Session TTL — operator pick + HIPAA cap. Hard ceiling enforced
    # by AuthConfig.HIPAA_TTL_HARD_CEILING_SECS regardless of input.
    from email_triage.config import AuthConfig
    if not hasattr(config, "auth") or config.auth is None:
        config.auth = AuthConfig()
    #  — request ints via the _safe_int SSOT (non-numeric => never a 500).
    # The fallback is the CURRENT config value, so a non-numeric submit leaves
    # the setting UNCHANGED — exactly the prior except-pass: the post-parse
    # membership/clamp re-applies the already-valid current value as a no-op.
    # The .get default preserves the missing-field behavior (documented default).
    ttl = _safe_int(
        form.get("auth_session_ttl_secs", "86400"), config.auth.session_ttl_secs)
    if ttl in (900, 1800, 3600, 86400, 604800, 1209600):
        config.auth.session_ttl_secs = ttl
    hipaa_ttl = _safe_int(
        form.get("auth_hipaa_session_ttl_secs", "900"),
        config.auth.hipaa_session_ttl_secs)
    config.auth.hipaa_session_ttl_secs = min(
        hipaa_ttl, AuthConfig.HIPAA_TTL_HARD_CEILING_SECS,
    )

    #  login rate-limit tunables. Sane-range clamps mirror the
    # YAML loader so an operator can't wedge themselves out of the
    # login surface with a typo. ``max=0`` is the documented kill
    # switch (rate-limit off for that scope) and is preserved.
    v = _safe_int(
        form.get("login_per_email_max", "10"), config.auth.login_per_email_max)
    config.auth.login_per_email_max = max(0, v)
    v = _safe_int(
        form.get("login_per_email_window_secs", "600"),
        config.auth.login_per_email_window_secs)
    config.auth.login_per_email_window_secs = max(60, min(86400, v))
    v = _safe_int(
        form.get("login_per_ip_max", "30"), config.auth.login_per_ip_max)
    config.auth.login_per_ip_max = max(0, v)
    v = _safe_int(
        form.get("login_per_ip_window_secs", "600"),
        config.auth.login_per_ip_window_secs)
    config.auth.login_per_ip_window_secs = max(60, min(86400, v))

    # Persist YAML.
    save_error = None
    try:
        _write_config_yaml(config)
    except Exception as e:
        #  tail — route through scrub_exc so raw exception __str__
        # (which may echo PHI or lock-guard internals) never lands in the
        # user-facing URL query redirect. Same class as  accounts.py:
        # 1685 down-payment fold.
        from email_triage.web._flash import scrub_exc
        save_error = f"YAML write failed: {scrub_exc(e, purpose='form')}"
        _log.error("Security config YAML write failed", exc_info=e)

    qs = "saved=1" if not save_error else err_qs(save_error[:100])
    return RedirectResponse(
        f"/admin/security?{qs}", status_code=303,
    )


@router.post("/config/baa-ack", response_class=HTMLResponse)
async def config_baa_ack(request: Request, user: RequireUserFragment):
    """Toggle BAA acknowledgment for the (backend, host) tuple.

    Admin-only. Persisted via the BAA gate module; the gate itself
    is consulted at classify time on every HIPAA-flagged message.
    Acknowledgments are scoped to the exact (backend, host) tuple,
    so swapping vendors revokes consent automatically.
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    form = await request.form()
    backend = (form.get("backend") or "").strip()
    host = (form.get("host") or "").strip()
    acked = parse_bool(form.get("acked"))

    if not backend or not host:
        return HTMLResponse("Missing backend or host", status_code=400)

    from email_triage.classify.baa_gate import (
        set_baa_ack, revoke_baa_ack, classifier_baa_status,
    )
    from email_triage.web.db import (
        unpause_baa_paused_style_distill_accounts,
        unpause_baa_paused_style_distill_contacts,
        record_auth_event,
    )
    import json as _json

    def _baa_ack_db_work() -> dict:
        """/ — ack write/revoke + baa-status re-read in one
        threadpool hop. Returns the fresh classifier BAA status dict.
        """
        if acked:
            # the backlog  (Census v3 finding #1) — Prime Directive
            #  CLEAR side. `pause_style_distill_(account|contact)`
            # SET at BackendBAARequiredError previously had NO reachable
            # CLEAR path in src/; a BAA-lapsed mailbox was PARKED
            # permanently + the per-account HIPAA overlay degraded to
            # the global scrubber. §164.308(b)(1) BAA-gate lifecycle /
            # PD#18 SET-must-CLEAR. BAA re-ACK is the operator's
            # re-certification event: every row paused for a BAA
            # reason is now eligible to resume. Retry queue re-checks
            # BAA state on the next tick, so a stale ACK re-pauses
            # within one tick interval (not "no window"; bounded to
            # the retry cadence).
            #
            # db-sme F1 (atomicity): unpauses run BEFORE ``set_baa_ack``
            # (three ``@db_write`` closures, each self-commits). Under
            # a mid-sequence process death, the fail-forward posture
            # leaves rows unpaused with the ACK not written; the retry
            # gate re-raises ``BackendBAARequiredError`` on the very
            # next tick + re-pauses the rows with the same
            # ``baa_required:`` prefix, so the next ACK attempt cleanly
            # replays the sequence. Failing after ``set_baa_ack`` in
            # the original ordering left the exact permanent-park
            # bug this fix is meant to close.
            acct_unpaused = unpause_baa_paused_style_distill_accounts(db)
            cont_unpaused = unpause_baa_paused_style_distill_contacts(db)
            set_baa_ack(db, backend, host, user_id=user["id"])
            # PD#3 (audit-emit SSOT): the ACK is an auth-adjacent
            # posture event whose audit surface is the HMAC-chained
            # ``auth_events`` row, not ``_log``. Counts land in
            # ``detail`` for the operator + reviewer.
            record_auth_event(
                db,
                event_type="baa_ack",
                email=user["email"],
                user_id=user["id"],
                outcome="success",
                detail=_json.dumps({
                    "backend": backend,
                    "host": host,
                    "baa_paused_accounts_unpaused": acct_unpaused,
                    "baa_paused_contacts_unpaused": cont_unpaused,
                }),
            )
            _log.info(
                "BAA acknowledged",
                backend=backend, host=host, by_user_id=user["id"],
                baa_paused_accounts_unpaused=acct_unpaused,
                baa_paused_contacts_unpaused=cont_unpaused,
            )
        else:
            revoke_baa_ack(db, backend, host)
            record_auth_event(
                db,
                event_type="baa_ack_revoke",
                email=user["email"],
                user_id=user["id"],
                outcome="success",
                detail=_json.dumps({"backend": backend, "host": host}),
            )
            _log.info(
                "BAA acknowledgment revoked",
                backend=backend, host=host, by_user_id=user["id"],
            )
        # Re-render the chip with the new state.
        cls = _build_classifier_from_config(config)
        return classifier_baa_status(db, cls)

    baa_status = await db_call(_baa_ack_db_work)
    return await _render(templates, request, "config/_baa_chip.html", {
        "classifier_baa_status": baa_status,
    })


@router.post("/config/save", response_class=HTMLResponse)
async def config_save(request: Request, user: RequireUser):
    """Save all settings (admin only)."""
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    form = await request.form()

    # ── Runtime settings (DB-persisted) ──
    #  — read-clamp-write is one atomic critical section. Two admins
    # saving /config at once previously interleaved: each read the
    # runtime blob in its own db_call, then each wrote in a separate
    # one, so the second write clobbered the first on the WHOLE blob
    # (last-writer-wins, including fields the loser never touched —
    # e.g. the absent-field ``hipaa`` preserve). The read, the clamp,
    # and the write now happen inside a single db_call while holding
    # the process-wide DB write lock, so a concurrent save is
    # serialised against this one end-to-end.
    #
    # Raw form values are parsed up front (no I/O); only the
    # read-clamp-write touches the DB.
    raw_dry_run = "dry_run" in form
    raw_log_level = form.get("log_level", "INFO")
    raw_bulk_rate = form.get("bulk_triage_rate_msg_per_min", "")
    raw_bulk_conc = form.get("bulk_triage_concurrency", "")
    raw_bulk_burst = form.get("bulk_triage_burst", "")

    def _save_runtime_settings_atomic() -> dict:
        """/.2/ — clamp the bulk knobs against the CURRENT
        saved values and persist, all under the write lock so the
        read-modify-write is atomic w.r.t. any other writer. Returns
        the persisted runtime blob so the handler can render it.

        Out-of-range or non-numeric input falls back to the saved
        value (don't clobber on bad parse). HIPAA mode is managed on
        /admin/security; the absent form field must preserve the
        existing DB value, not zero it.
        """
        from email_triage.web.db import set_setting
        from email_triage.web.db_writelock import get_write_lock

        with get_write_lock():
            existing_runtime = _get_runtime_settings(db)
            # N-219c/18 R23: SSOT bounded_int with nested default int() —
            # parse the fallback ONCE outside the SSOT call for clarity.
            _bulk_rate_default = int(existing_runtime.get(
                "bulk_triage_rate_msg_per_min",
                _RUNTIME_DEFAULTS["bulk_triage_rate_msg_per_min"],
            ))
            bulk_rate = bounded_int(raw_bulk_rate or 0, default=_bulk_rate_default)
            bulk_rate = max(
                BULK_TRIAGE_RATE_MIN, min(BULK_TRIAGE_RATE_MAX, bulk_rate),
            )
            _bulk_conc_default = int(existing_runtime.get(
                "bulk_triage_concurrency",
                _RUNTIME_DEFAULTS["bulk_triage_concurrency"],
            ))
            bulk_conc = bounded_int(raw_bulk_conc or 0, default=_bulk_conc_default)
            bulk_conc = max(
                BULK_TRIAGE_CONCURRENCY_MIN,
                min(BULK_TRIAGE_CONCURRENCY_MAX, bulk_conc),
            )
            _bulk_burst_default = int(existing_runtime.get(
                "bulk_triage_burst",
                _RUNTIME_DEFAULTS["bulk_triage_burst"],
            ))
            bulk_burst = bounded_int(raw_bulk_burst or 0, default=_bulk_burst_default)
            bulk_burst = max(
                BULK_TRIAGE_BURST_MIN,
                min(BULK_TRIAGE_BURST_MAX, bulk_burst),
            )

            new_runtime = {
                "dry_run": raw_dry_run,
                "log_level": raw_log_level,
                # HIPAA managed on /admin/security; preserve the DB
                # value read inside this same locked section.
                "hipaa": bool(existing_runtime.get("hipaa", False)),
                "bulk_triage_rate_msg_per_min": bulk_rate,
                "bulk_triage_concurrency": bulk_conc,
                "bulk_triage_burst": bulk_burst,
            }
            set_setting(db, _RUNTIME_SETTINGS_KEY, new_runtime)
        # _apply_runtime_settings is pure-Python (no I/O); run it
        # after releasing the lock with the just-persisted blob.
        _apply_runtime_settings(new_runtime)
        return new_runtime

    new_runtime = await db_call(_save_runtime_settings_atomic)

    # ── Classifier settings (in-memory + YAML) ──
    # the backlog  sibling (DA panel F2 same-drive closure) — capture
    # the pre-change (backend, model) tuple so we can detect an operator
    # classifier swap. On any change, bulk-unpause every ``scrubber_fail``
    # row: the comment at ``distill_hipaa.py:650`` says "retrying a leaky
    # LLM won't help" — a NEW LLM is exactly the recovery event. The
    # retry queue re-tries with the new backend on the next tick + re-
    # pauses if the new scrubber still fails (bounded to one tick).
    # §164.308(a)(1)(ii)(D) posture change; PD#18 SET-must-CLEAR.
    _classifier_prev = (
        (config.classifier.backend or ""),
        (config.classifier.model or ""),
    )
    config.classifier.backend = form.get("classifier_backend", config.classifier.backend)
    config.classifier.model = form.get("classifier_model", config.classifier.model).strip()
    #  — ordered backup models (comma-separated from the picker).
    _classifier_backups = form.get("classifier_backup_models", "")
    config.classifier.backup_models = [
        m.strip() for m in _classifier_backups.split(",") if m.strip()
    ]
    config.classifier.ollama_url = form.get("classifier_ollama_url", config.classifier.ollama_url).strip()
    #  — pinned Ollama context window (blank = inherit the model default).
    _num_ctx_raw = (form.get("classifier_num_ctx") or "").strip()
    config.classifier.num_ctx = (
        int(_num_ctx_raw) if _num_ctx_raw.isdigit() and int(_num_ctx_raw) > 0 else None
    )
    #  (SME MUST) — a sub-floor pin silently degrades topic-match (front-
    # truncated prompt). Warn at Save so the operator sees it in the running
    # system, don't clamp their deliberate choice. Floor imported from its one
    # source (no restated 8192).
    if config.classifier.num_ctx is not None:
        from email_triage.actions.topic_prefilter import MIN_RECOMMENDED_NUM_CTX
        if config.classifier.num_ctx < MIN_RECOMMENDED_NUM_CTX:
            _log.warning(
                "Admin pinned a sub-floor classifier num_ctx",
                num_ctx=config.classifier.num_ctx,
                recommended_floor=MIN_RECOMMENDED_NUM_CTX,
                impact="topic-match prompt may front-truncate; verdicts "
                       "silently dropped (not caught by the  guard)",
            )
    # N-378 (2026-07-08) — Ollama ``think`` payload option (CONFIG KNOB).
    # Tri-state: "" = model default (None); "false" = disable; "true" =
    # force. Route through the A9 SSOT `parse_bool_tristate` — it returns
    # None for empty / unrecognized / defer tokens and a real bool for
    # explicit "true" / "false" (case-insensitive), so a typo can't
    # silently downgrade the operator's intent AND we don't hand-roll
    # form-bool parsing (test_no_hand_rolled_bool_parsing pin).
    from email_triage._envbool import parse_bool_tristate
    config.classifier.ollama_think = parse_bool_tristate(
        form.get("classifier_ollama_think"),
    )
    # N-378 — /no_think marker checkbox (Qwen3 belt-and-braces). Checkbox
    # presence semantic: unchecked = key omitted, checked = key present.
    # This is the standard HTML form idiom + is what other checkboxes in
    # this function already use (see `smtp_use_tls`, `health_email_
    # enabled`, ...). Not a hand-rolled bool parse — it's a set-membership
    # test on the form's key set, so the A9 pin doesn't apply.
    config.classifier.ollama_no_think_marker = (
        "classifier_ollama_no_think_marker" in form
    )
    # N-431 (2026-07-19) — Ollama ``keep_alive`` payload option, threaded
    # SSOT to every /api/chat + /api/embeddings site. Route through the
    # shared validator ``_ollama_reuse.is_valid_keep_alive`` so the form
    # parse and the YAML parse reject bad shapes uniformly (DA panel MF-3,
    # 2026-07-19). Empty/whitespace falls back to the ClassifierConfig
    # default so a Save with a blank field can't silently disable the pin.
    # A bad shape (e.g. "1o" — letter O for minute) is REJECTED here so it
    # never reaches Ollama, which would 400 and fall back to its silent
    # 5m default — the exact recurrence class this drive is closing.
    _keep_alive_raw = form.get(
        "classifier_ollama_keep_alive", "",
    ).strip()
    if _keep_alive_raw:
        from email_triage._ollama_reuse import is_valid_keep_alive
        if is_valid_keep_alive(_keep_alive_raw):
            config.classifier.ollama_keep_alive = _keep_alive_raw
        # else: silently keep the prior value; the admin template's
        # placeholder / value attribute shows what's currently in
        # effect, so an operator who fat-fingered a typo sees on next
        # render that nothing changed. (An explicit form-level error
        # surface is a follow-on UX drive.)
    config.classifier.openai_base_url = form.get("classifier_openai_base_url", "").strip()
    config.classifier.openai_model = form.get("classifier_openai_model", "").strip()
    config.classifier.gemini_model = form.get("classifier_gemini_model", "").strip()

    # the backlog  sibling (DA panel F2 same-drive closure) —
    # scrubber_fail sub-shape PD#18 CLEAR seam. Comment at
    # ``distill_hipaa.py:650`` says "retrying a leaky LLM won't help":
    # the operator changing the classifier backend / model is exactly
    # the recovery event. When (backend, model) is not the same tuple
    # we captured pre-save, bulk-unpause every scrubber_fail-paused
    # row so the retry queue re-tries with the new classifier on the
    # next tick. If the new one still leaks, the retry-tick re-pauses
    # (bounded to one tick interval). §164.308(a)(1)(ii)(D) posture
    # change + PD#18 SET-must-CLEAR.
    _classifier_new = (
        (config.classifier.backend or ""),
        (config.classifier.model or ""),
    )
    if _classifier_new != _classifier_prev:
        from email_triage.web.db import (
            unpause_scrubber_fail_style_distill_accounts,
            unpause_scrubber_fail_style_distill_contacts,
            record_auth_event,
        )
        import json as _json_sf

        def _classifier_change_clear() -> tuple[int, int]:
            _acct_n = unpause_scrubber_fail_style_distill_accounts(db)
            _cont_n = unpause_scrubber_fail_style_distill_contacts(db)
            record_auth_event(
                db,
                event_type="classifier_config_changed",
                email=user["email"],
                user_id=user["id"],
                outcome="success",
                detail=_json_sf.dumps({
                    "prev_backend": _classifier_prev[0],
                    "new_backend": _classifier_new[0],
                    "prev_model": _classifier_prev[1],
                    "new_model": _classifier_new[1],
                    "scrubber_fail_accounts_unpaused": _acct_n,
                    "scrubber_fail_contacts_unpaused": _cont_n,
                }),
            )
            return _acct_n, _cont_n

        _sf_acct_n, _sf_cont_n = await db_call(_classifier_change_clear)
        _log.info(
            "Classifier config changed — scrubber_fail rows released",
            prev_backend=_classifier_prev[0],
            new_backend=_classifier_new[0],
            prev_model=_classifier_prev[1],
            new_model=_classifier_new[1],
            scrubber_fail_accounts_unpaused=_sf_acct_n,
            scrubber_fail_contacts_unpaused=_sf_cont_n,
        )

    # ── SMTP settings (in-memory + YAML) ──
    config.smtp.host = form.get("smtp_host", config.smtp.host).strip()
    config.smtp.port = _safe_int(form.get("smtp_port"), config.smtp.port)
    config.smtp.username = form.get("smtp_username", config.smtp.username).strip()
    config.smtp.from_addr = form.get("smtp_from_addr", config.smtp.from_addr).strip()
    config.smtp.from_name = form.get("smtp_from_name", config.smtp.from_name).strip()
    config.smtp.use_tls = "smtp_use_tls" in form

    # ── Daily health + Admin email recipients (CR-2c) + summary sig ──
    config.health_email.enabled = "health_email_enabled" in form
    # CR-2c rename. Canonical field is ``admin_email_recipients`` now.
    # The legacy ``health_email_recipients`` field is honoured as a
    # fallback for clients posting the old form (cached page, future
    # rollback path) so an in-flight rename doesn't clear the operator's
    # list. Old YAML still loads via the read-fallback in
    # ``resolve_admin_recipients``; new edits write to admin_email only.
    _recips_raw = (
        form.get("admin_email_recipients", "")
        or form.get("health_email_recipients", "")
    ).strip()
    config.admin_email.recipients = [
        r.strip() for r in _recips_raw.split(",") if r.strip()
    ]
    # Clear the legacy field on Save so the YAML round-trip doesn't
    # keep two stale copies. The deprecation warning fires once on the
    # next read; after the deprecation cycle this branch can be deleted.
    config.health_email.recipients = []
    _release_url_raw = form.get(
        "admin_email_release_check_url", "",
    ).strip()
    if _release_url_raw:
        config.admin_email.release_check_url = _release_url_raw
    config.health_email.send_at = form.get(
        "health_email_send_at", config.health_email.send_at,
    ).strip() or "07:15"
    config.health_email.include_health = "health_email_include_health" in form
    config.health_email.include_watchers = "health_email_include_watchers" in form
    config.health_email.include_triage = "health_email_include_triage" in form
    config.health_email.include_errors = "health_email_include_errors" in form
    config.health_email.include_hipaa_events = "health_email_include_hipaa_events" in form
    config.health_email.include_api_key_events = "health_email_include_api_key_events" in form
    config.health_email.include_pubsub = "health_email_include_pubsub" in form
    config.health_email.include_update_available = (
        "health_email_include_update_available" in form
    )
    config.health_email.quiet_mode = "health_email_quiet_mode" in form
    config.health_email.error_rate_threshold_pct = _safe_int(  # 
        form.get("health_email_error_rate_threshold_pct"), 0)
    _sig = form.get("summary_email_signature", "").strip()
    if _sig:
        config.summary_email.signature = _sig

    # ── Logging format (in-memory + YAML) ──
    config.logging.format = form.get("logging_format", config.logging.format)

    # ── Anti-AI style guide (install-wide) ──
    # Operator-typed list of AI mannerisms the draft-reply LLM should
    # AVOID. Stored in the settings table (NOT the YAML config) because
    # it's user-facing copy that the admin tunes from the UI without
    # restarting. Cap length defensively at the registered max.
    from email_triage.web.db import (
        ANTI_AI_STYLE_GUIDE_MAX_LEN,
        set_global_anti_ai_style_guide,
    )
    _anti_ai_global_raw = (
        form.get("anti_ai_style_guide_global") or ""
    ).strip()[:ANTI_AI_STYLE_GUIDE_MAX_LEN]
    await db_call(set_global_anti_ai_style_guide, db, _anti_ai_global_raw)

    # Google OAuth + Office 365 OAuth install-level credentials moved
    # to /admin/integrations on 2026-05-10 — see
    # web/routers/integrations.py:admin_integrations_save for the
    # current save path. Form fields ignored here in case an older
    # client submits them; they will not write to secrets store
    # from this handler.

    # ── Ingestion cadence — clamped to the dataclass bounds ──
    def _clamp(val: int, lo: int, hi: int, step: int) -> int:
        val = max(lo, min(hi, val))
        # Snap to step grid so the DB never holds a value the HTML form
        # can't re-display exactly.
        return lo + round((val - lo) / step) * step

    # New unified server-wide default (60 min, range 10–240, step 10).
    default_iv = _safe_int(  # 
        form.get("ingestion_default_poll_interval_minutes"),
        config.ingestion.default_poll_interval_minutes)
    config.ingestion.default_poll_interval_minutes = _clamp(
        default_iv,
        config.ingestion.POLL_MIN,
        config.ingestion.POLL_MAX,
        config.ingestion.POLL_STEP,
    )

    # Legacy B3 cadence fields — kept for YAML round-trip compatibility
    # so an operator who still has these in their YAML doesn't lose
    # them on Save. No longer drives the loop.
    push_iv = _safe_int(  # 
        form.get("ingestion_push_poll_interval_min"),
        config.ingestion.push_poll_interval_min)
    poll_iv = _safe_int(  # 
        form.get("ingestion_poll_poll_interval_min"),
        config.ingestion.poll_poll_interval_min)
    config.ingestion.push_poll_interval_min = _clamp(
        push_iv, config.ingestion.PUSH_MIN, config.ingestion.PUSH_MAX, config.ingestion.STEP,
    )
    config.ingestion.poll_poll_interval_min = _clamp(
        poll_iv, config.ingestion.POLL_MIN, config.ingestion.POLL_MAX, config.ingestion.STEP,
    )

    # ── Style learning — auto-scan cadence + default mine size ──
    # Persisted in the ``settings`` table (DB), not the YAML config —
    # both are install-wide operator knobs that the admin tunes
    # without needing to touch the YAML. The helper clamps to the
    # documented ranges so a typo can't wedge the loop.
    from email_triage.web.db import (
        set_style_learning_capture_interval_hours,
        set_style_learning_mine_limit_default,
        get_style_learning_capture_interval_hours,
        get_style_learning_mine_limit_default,
        STYLE_LEARNING_INLINE_LIMIT_CEILING,
    )
    _cadence_hours = _safe_int(  # 
        form.get("style_learning_capture_interval_hours"), 0)
    if _cadence_hours > 0:
        await db_call(
            set_style_learning_capture_interval_hours,
            db, _cadence_hours,
        )
    _mine_limit = _safe_int(  # 
        form.get("style_learning_mine_limit_default"), 0)
    if _mine_limit > 0:
        await db_call(
            set_style_learning_mine_limit_default, db, _mine_limit,
        )

    # ── Write updated config back to YAML ──
    save_error = None
    try:
        _write_config_yaml(config)
    except Exception as e:
        #  tail — route through scrub_exc for the same reason as
        # the sibling site at :830.
        from email_triage.web._flash import scrub_exc
        save_error = (
            "Settings applied in memory but failed to write YAML: "
            f"{scrub_exc(e, purpose='form')}"
        )
        _log.error("Failed to write config YAML", error=fmt_exc(e))

    msg = "All settings saved."
    if new_runtime["dry_run"]:
        msg += " Dry-run mode is ON — actions will be logged but not executed."
    _log.info("Config updated", dry_run=new_runtime["dry_run"],
              classifier_backend=config.classifier.backend,
              classifier_model=config.classifier.model)

    # / — the two style-learning re-reads for the render off
    # the loop in one hop.
    def _style_learning_render_reads() -> tuple[int, int]:
        return (
            get_style_learning_capture_interval_hours(db),
            get_style_learning_mine_limit_default(db),
        )

    _sl_cadence, _sl_mine = await db_call(_style_learning_render_reads)

    return await _render(templates, request, "config.html", {
        "user": user,
        "config": config,
        "runtime": new_runtime,
        "anti_ai_style_guide_global": _anti_ai_global_raw,
        "style_learning_capture_interval_hours": _sl_cadence,
        "style_learning_mine_limit_default": _sl_mine,
        "inline_limit_ceiling": STYLE_LEARNING_INLINE_LIMIT_CEILING,
        "save_msg": msg,
        "save_error": save_error,
        # Stay on the General tab after a save. Both /config/save and
        # /config/health-email/send-now render inline (no redirect) so
        # the flash message lives in the response body; setting active
        # keeps the tab strip + body in sync with what the operator
        # was looking at.
        "active": "general",
    })


@router.post("/config/ai-backends/save", response_class=HTMLResponse)
async def config_ai_backends_save(request: Request, user: RequireUser):
    """Persist the AI backend config (embedding primary + fallback).

    Writes to the in-memory ``app.state.config`` (so subsequent /config
    reads round-trip the new values) and to the YAML file (so the next
    container restart picks them up). Does NOT hot-reload the running
    embedding backend — that lives in ``app.state.embedding_backend``
    and is constructed once at boot. The save-message banner tells
    the operator to restart.
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    config = get_config(request)
    form = await request.form()

    from email_triage.config import EmbeddingConfig, EmbeddingFallbackConfig
    if not hasattr(config, "embedding") or config.embedding is None:
        config.embedding = EmbeddingConfig()

    emb = config.embedding
    #  — capture the model BEFORE overwrite so we can detect a
    # change. Switching the embedding model re-stamps every FUTURE
    # write (embedding_stamp), but the existing sent_mail_index vectors
    # keep the OLD stamp and silently stop matching retrieval (recall
    # collapses to ~0 with no error) until they are re-embedded. So a
    # model change MUST (a) be explicitly confirmed by the operator and
    # (b) auto-enqueue a reindex. See AskUserQuestion 2026-06-06: the
    # operator chose confirm-gate + auto-reindex.
    old_model = (emb.model_name or "").strip()
    # D-A2 (2am audit 2026-06-07): snapshot the backend BEFORE overwrite so
    # a backend-TYPE swap (e.g. ollama -> sentence_transformers at the same
    # model name) is detectable — previously only the model NAME was
    # compared, so a same-name backend swap produced NO reindex and served
    # stale cross-embedding-space vectors silently.
    old_backend = (emb.backend or "").strip().lower()

    emb.backend = (form.get("embedding_backend") or "").strip().lower()
    new_model = (form.get("embedding_model_name") or "").strip()
    emb.ollama_url = (
        form.get("embedding_ollama_url") or DEFAULT_OLLAMA_BASE_URL
    ).strip()

    # A change that needs a reindex is detected via needs_reindex (the
    # function the  design specified for exactly this) — it covers BOTH
    # the model name AND the backend_type. Dimension isn't cheaply derivable
    # at save time, so it's omitted (misses safely — never trips on absence).
    # Only matters when retrieval is actually active (a backend selected).
    from email_triage.jobs.embedding_reindex import needs_reindex
    embedding_changed = bool(emb.backend and new_model and needs_reindex(
        current_backend={"backend_type": old_backend, "model": old_model},
        target_backend={"backend_type": emb.backend, "model": new_model},
    ))
    confirmed = parse_bool(form.get("embedding_reindex_confirm"))

    save_msg = ""
    save_error = ""

    if embedding_changed and not confirmed:
        # Defence in depth behind the client-side confirm dialog: never
        # silently swap the model/backend (which zeroes out recall) without
        # the operator acknowledging the reindex. Revert BOTH model AND
        # backend so a non-JS / programmatic submit can't break retrieval
        # unnoticed (D-A2: a backend swap is gated the same as a model swap).
        emb.model_name = old_model
        emb.backend = old_backend
        embedding_changed = False
        save_error = (
            "Embedding model/backend change needs reindex confirmation — "
            "left unchanged. Re-save and confirm the reindex prompt."
        )
    else:
        emb.model_name = new_model

    if not hasattr(emb, "fallback") or emb.fallback is None:
        emb.fallback = EmbeddingFallbackConfig()
    fb = emb.fallback
    fb.backend = (form.get("fallback_backend") or "").strip().lower()
    fb.model_name = (form.get("fallback_model_name") or "").strip()
    fb.ollama_url = (form.get("fallback_ollama_url") or "").strip()

    # Classification cache tuning (operator-policy 2026-05-13) lives
    # on the Integrations tab's save handler, not here. AI Backends
    # save scopes to LLM-side config (embedding primary + fallback)
    # only.

    if not save_error:
        try:
            from email_triage.web.routers.ui import _write_config_yaml
            _write_config_yaml(config)
            save_msg = "Settings saved."
        except Exception as e:
            #  tail — `fmt_exc(e)[:200]` TRUNCATES but does NOT SCRUB
            # (PHI / secret shapes survive under 200 chars). Route through
            # scrub_exc. DB-SME N1 (2026-07-11): scrub_exc already caps at
            # 200 (`_flash.py:112` `return s[:200] or f"{purpose} operation
            # failed"`), so the outer `[:200]` slice is redundant. Drop it.
            # DA F4 (2026-07-11 batched panel): the sibling sites at :830
            # + :1304 carry a privileged _log.error(..., exc_info=e) for
            # the debug sink. This site was missing it — the scrub_exc
            # replacement removed the only diagnostic path. Add the log
            # to preserve debuggability.
            from email_triage.web._flash import scrub_exc
            _log.error("AI backends YAML write failed", exc_info=e)
            save_error = scrub_exc(e, purpose="form")

    #  — on a CONFIRMED model change, audit it + auto-enqueue a
    # background reindex for every active account so the new
    # write-stamp and the retrieve-filter-stamp converge. Gated on
    # is_runtime_ready: if the embedding runtime isn't installed the
    # worker can't run the jobs (they'd fail on every row) and there
    # are no live vectors to re-embed yet — so we audit + tell the
    # operator instead of queuing doomed jobs.
    if embedding_changed and not save_error:
        db = get_db(request)

        def _reindex_all_db_work() -> int:
            from email_triage.embedding_bits import is_runtime_ready
            from email_triage.db.accounts import list_email_accounts
            from email_triage.jobs.embedding_reindex import (
                supersede_or_enqueue_reindex,
            )
            from email_triage.web.db import record_auth_event

            ready = is_runtime_ready()
            enqueued = 0
            if ready:
                #  (N-91a) — pin the NEW target so the per-account funnel can
                # SUPERSEDE a now-stale in-flight job (the worker's cancel-check
                # stops it) instead of the old D-A3 skip-if-in-flight dedupe,
                # which stranded an account at its start-time stamp when the
                # model changed mid-run.
                new_target = {"backend_type": emb.backend, "model": new_model}
                for acct in list_email_accounts(db, user_id=None):
                    if not acct.get("is_active"):
                        continue
                    aid = int(acct["id"])
                    outcome = supersede_or_enqueue_reindex(
                        db, account_id=aid,
                        actor_user_id=user.get("id"), target=new_target,
                    )
                    if outcome in ("enqueued", "superseded"):
                        enqueued += 1
            # Audit the model/backend swap through the chain-safe auth-event
            # writer (NOT a direct insert_log_entry, which forks the
            # HMAC chain). Mirrors embedding_install._audit. Best-effort
            # via the safe_audit_write SSOT (run17 #3): a swallowed emit
            # failure stays visible to /health's audit-failure drift
            # counter instead of a hand-rolled log-and-continue.
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="embedding_model_change",
                    email=user.get("email", "") or "",
                    user_id=user.get("id"),
                    outcome="success",
                    detail=(
                        f"embedding {old_backend or '(none)'}/{old_model!r} "
                        f"-> {emb.backend}/{new_model!r}; reindex enqueued "
                        f"for {enqueued} active account(s); "
                        f"runtime_ready={ready}"
                    ),
                ),
                description="embedding_model_change",
            )
            return enqueued if ready else -1

        try:
            enqueued = await db_call(_reindex_all_db_work)
        except Exception as e:  # noqa: BLE001
            # Config saved but the reindex couldn't be queued — surface
            # it loudly: retrieval is now broken until a manual reindex.
            save_msg = ""
            save_error = (
                f"Settings saved, but auto-reindex enqueue FAILED "
                f"({fmt_exc(e)[:120]}). Recall is degraded until you "
                f"reindex each account manually."
            )
            enqueued = None

        if enqueued is not None:
            if enqueued >= 0:
                save_msg = (
                    f"Settings saved. Embedding model changed to "
                    f"{new_model!r}; reindexing {enqueued} active "
                    f"account(s) in the background."
                )
            else:
                save_msg = (
                    f"Settings saved. Embedding model changed to "
                    f"{new_model!r}, but the embedding runtime is not "
                    f"installed yet — reindex will run once it is."
                )

    # Redirect with msg in query so the page surfaces feedback.
    from urllib.parse import urlencode
    qs = {"tab": "ai_backends"}
    if save_msg:
        qs["save_msg"] = save_msg
    if save_error:
        qs["save_error"] = save_error
    return RedirectResponse(
        f"/config?{urlencode(qs)}", status_code=303,
    )


@router.post("/config/health-email/send-now", response_class=HTMLResponse)
async def health_email_send_now(request: Request, user: RequireUser):
    """Fire the daily health digest on demand (admin only).

    Uses the same codepath as the background scheduler — just with
    ``force=True`` so ``quiet_mode`` doesn't suppress a test send when
    the day is boringly healthy.
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    secrets = get_secrets(request)
    templates = get_templates(request)
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)

    from email_triage.web.daily_health import send_daily_health_email

    def _health_send_db_work() -> tuple[bool, str, dict]:
        """/ — the daily-health send (DB reads + SMTP) plus the
        runtime-settings re-read, all off the event loop in one hop.
        """
        sent_, reason_ = send_daily_health_email(
            db, config, secrets, watcher_mgr, force=True,
        )
        return sent_, reason_, _get_runtime_settings(db)

    sent, reason, runtime = await db_call(_health_send_db_work)
    msg = f"Daily health email: {reason}" if sent else f"Not sent — {reason}"
    return await _render(templates, request, "config.html", {
        "user": user,
        "config": config,
        "runtime": runtime,
        "save_msg": msg if sent else None,
        "save_error": msg if not sent else None,
        # Health email is in the General tab (Health Email section).
        "active": "general",
    })


# ---------------------------------------------------------------------------
# -A — Explain-this-error endpoint
#
# HTMX-driven button on /logs (per-error chip) and on the O365 probe
# failure chip. Submits the verbatim error string + provider/class
# context, returns an HTML chip with a plain-English AI explanation.
# Backend reuse: OllamaClassifier.complete() via error_explain module;
# no new HTTP path to the LLM. Privacy invariant enforced inside
# error_explain._build_prompt (which is unit-tested directly).
# ---------------------------------------------------------------------------

@router.post("/explain-error", response_class=HTMLResponse)
async def explain_error_endpoint(request: Request, user: RequireUserFragment):
    """Render an AI-generated plain-English explanation of an
    integration error string.

    Admin-only. Form fields:
      * ``error_text`` (required) — the verbatim error message
      * ``error_class`` (optional) — e.g. ``AADSTS65001`` or
        ``invalid_grant``
      * ``provider`` (optional) — operator-supplied context label
        such as ``office365`` / ``gmail_api`` / ``imap``
      * ``account_id`` (optional) — when present, used to surface
        the owner+account_name in the prompt AND to apply the
        HIPAA actor!=owner audit gate.

    Per :mod:`feedback_hipaa_actor_owner_gate`: when ``account_id``
    is given, the actor must be able to manage the account (owner /
    admin / delegate) — same gate ``OwnedAccount`` enforces on the
    account-edit / probe surface. Without an account_id we just
    require admin role (errors are operator-facing).
    """
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    config = get_config(request)
    secrets = get_secrets(request)
    form = await request.form()

    error_text = (form.get("error_text") or "").strip()
    if not error_text:
        return HTMLResponse(
            '<span style="color:var(--pico-muted-color);">'
            'No error text supplied — nothing to explain.</span>',
            status_code=400,
        )
    error_class = (form.get("error_class") or "").strip() or None
    provider = (form.get("provider") or "").strip() or None

    account_id: int | None = None
    raw_aid = (form.get("account_id") or "").strip()
    if raw_aid:
        account_id = parse_int_or_none(raw_aid)  # N-219c R23: SSOT

    # HIPAA gate when an account is named — actor must manage it.
    if account_id is not None:
        from email_triage.web.db import (
            can_manage_account, get_email_account,
        )

        def _explain_hipaa_gate() -> tuple[bool, bool]:
            """/ — fetch + can-manage check in one hop. Returns
            ``(exists, can_manage)``.
            """
            acct = get_email_account(db, account_id)
            if acct is None:
                return False, False
            return True, can_manage_account(db, user, acct)

        exists, can_manage = await db_call(_explain_hipaa_gate)
        if not exists:
            return HTMLResponse("Account not found", status_code=404)
        if not can_manage:
            return HTMLResponse("Forbidden", status_code=403)

    # Audit row so the operator can see the AI was consulted. Detail
    # carries the error_class + provider for cross-row correlation
    # but NEVER the raw error_text (could include partial PHI in
    # exotic provider responses).
    def _explain_audit_db_work() -> None:
        """/ — best-effort explain_error audit row off the loop."""
        try:
            from email_triage.web.db import record_auth_event
            detail_parts = []
            if provider:
                detail_parts.append(f"provider={provider}")
            if error_class:
                detail_parts.append(f"class={error_class}")
            if account_id is not None:
                detail_parts.append(f"account_id={account_id}")
            # Best-effort via the safe_audit_write SSOT (run17 #3): a
            # swallowed emit failure stays visible to /health's audit-
            # failure drift counter. The enclosing try is kept because it
            # also guards the import + detail_parts build above.
            safe_audit_write(
                lambda: record_auth_event(
                    db,
                    event_type="explain_error",
                    email=user.get("email", ""),
                    user_id=user.get("id"),
                    outcome="success",
                    detail=", ".join(detail_parts) or None,
                ),
                description="explain_error",
            )
        except Exception as e:
            _log.warning(
                "explain_error: audit write failed (continuing)",
                error=fmt_exc(e),
            )

    await db_call(_explain_audit_db_work)

    from email_triage.web.error_explain import explain_error
    explanation = await explain_error(
        error_text=error_text,
        error_class=error_class,
        provider=provider,
        account_id=account_id,
        db=db,
        secrets=secrets,
        config=config,
    )

    # Render the chip. Plain HTML — HTMX swap target on the caller.
    # We use server-side escape via markupsafe to keep the
    # explanation safe even if the model produces stray HTML.
    from markupsafe import escape
    safe = escape(explanation)
    # Operator caught 2026-05-12: chip text was clipping mid-word at
    # the visible viewport edge. Root cause: the chip didn't carry
    # ``overflow-wrap`` or ``word-break``, and ``max-width: 100%``
    # was implicit (block element) but absent from the inline style.
    # Long tokens (URLs, paths, no-space sequences) escaped the
    # parent <td> width and the row's wrapper (.logs-table-wrap)
    # scrolled horizontally instead of the text wrapping. Adding the
    # three properties below forces wrap-anywhere on every chip.
    # 2026-05-12 third attempt at the chip-width fix. Prior fix used
    # ``max-width: 100%`` inline — that's "100% of the parent cell",
    # and the parent <td> has no width cap, so the cell auto-sized
    # to whatever was widest in the row (sender pills + extras pre
    # block) and the chip happily spread to that width. Inline beat
    # the stylesheet's viewport-relative cap because inline >
    # stylesheet specificity. The chip text then ran off the right
    # of the visible viewport — exactly what operator screenshotted.
    #
    # Fix: chip max-width is now viewport-relative inline so cell
    # width is irrelevant. ``min(70ch, calc(100vw - 8rem))`` caps
    # the chip at ~700px on a typical viewport, smaller on narrow
    # screens. Text wraps inside the cap regardless of how wide the
    # containing table cell becomes.
    return HTMLResponse(
        f'<div class="explain-chip" style="margin:0.4rem 0 0.6rem 0;'
        f'padding:0.5rem 0.75rem;font-size:0.85em;line-height:1.45;'
        f'background:var(--pico-code-background-color);'
        f'border-left:3px solid var(--pico-primary);'
        f'border-radius:3px;color:var(--pico-color);'
        f'display:block;'
        f'max-width:min(70ch, calc(100vw - 8rem));'
        f'box-sizing:border-box;'
        f'overflow-wrap:anywhere;word-break:break-word;'
        f'white-space:normal;">'
        f'<strong style="font-size:0.8em;color:var(--pico-muted-color);'
        f'letter-spacing:0.05em;">AI explanation</strong><br>'
        f'{safe}</div>',
        status_code=200,
    )
