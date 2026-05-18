"""Routes for the admin concern.

Split out of the legacy `web/routers/ui.py` (#144). Helpers
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

_log = get_logger("web.ui.admin")

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
    """PEP 562 fallback — late-bound lookup on _shared.

    Catches names added to `_shared` after this module's globals
    were populated, plus names that the package-level monkeypatch
    mirror writes onto `_shared` AFTER import.
    """
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
# PWA offline shell (#124)
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
    return _render(templates, request, "offline.html", {})


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    templates = get_templates(request)

    # #135: dashboard build is read-heavy (getting-started, recent runs,
    # health-chip rollup, watcher-banner account fetch). Run the whole
    # build off the event loop so concurrent /health polls + other
    # operator surfaces don't serialise behind it.
    ctx = await db_call(_build_dashboard_context, request, user)

    return _render(templates, request, "dashboard.html", ctx)


@router.post("/dashboard/dismiss-step", response_class=HTMLResponse)
async def dashboard_dismiss_step(request: Request):
    """Mark a getting-started checklist step as dismissed for the user."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)
    db = get_db(request)
    form = await request.form()
    step_id = (form.get("step_id") or "").strip()
    if not step_id:
        return HTMLResponse("Missing step_id", status_code=400)

    from email_triage.web.db import (
        get_dashboard_dismissed_steps, set_dashboard_dismissed_steps,
    )
    current = get_dashboard_dismissed_steps(db, user["id"])
    if step_id not in current:
        current.append(step_id)
        set_dashboard_dismissed_steps(db, user["id"], current)
    # HTMX: swap out with an empty fragment (card disappears).
    return HTMLResponse("")


@router.get("/admin/stats", response_class=HTMLResponse)
async def admin_stats_page(request: Request):
    """Dedicated admin stats page — volume, performance, classification, health.

    Every stat that used to live on the dashboard got migrated here so
    the dashboard can focus on orientation. Default window is last 24h;
    the dropdown bumps to 1h / 7d / 30d.
    """
    user, err = _require_admin_user(request)
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

    return _render(templates, request, "admin/stats.html", {
        "user": user,
        **snap,
        "health": health_payload,
    })


# ---------------------------------------------------------------------------
# System log viewer (admin only)
# ---------------------------------------------------------------------------

@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Admin log viewer showing recent log entries from SQLite."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    templates = get_templates(request)

    level_filter = request.query_params.get("level", "").upper() or None
    offset = int(request.query_params.get("offset", "0"))
    # Free-text search — matches message + logger + extras (JSON blob).
    query = (request.query_params.get("q") or "").strip() or None

    snap = await db_call(
        _logs_page_snapshot, db, level_filter, offset, query,
    )

    return _render(templates, request, "logs.html", {
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
    user, err = _require_admin_user(request)
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
    user, err = _require_admin_user(request)
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
    user, err = _require_admin_user(request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    snap = await db_call(_compliance_page_snapshot, db, request.app.state)

    return _render(templates, request, "compliance.html", {
        "user": user,
        **snap,
    })


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@router.get("/admin/watches", response_class=HTMLResponse)
async def admin_watches_page(request: Request):
    """List every watch across every account on the install."""
    user, err = _require_admin_user(request)
    if err:
        return err
    db = get_db(request)
    items = await db_call(_build_admin_watches_snapshot, db)
    templates = get_templates(request)
    return _render(
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
async def config_page(request: Request):
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
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    tab = (request.query_params.get("tab") or "general").strip().lower()
    if tab not in _CONFIG_TAB_SLUGS:
        tab = "general"

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    # #171-D — ``baa_banner`` is auto-injected by ``_shared._render``
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
        # #125 partial — schema-compat version banner. Lives on the
        # General tab so the admin sees it on every visit to /config.
        # gather_version_status reads its three numbers cheaply (one
        # read-only DB query for db_schema_version; the rest is in
        # the source); safe to call on every page render.
        version_status = None
        try:
            from email_triage.version import gather_version_status
            version_status = gather_version_status(
                config.persistence.db_path,
            )
        except Exception:
            # Banner is informational; never break /config on the
            # version helper failing. The other tabs work unchanged.
            version_status = None
        ctx.update({
            "runtime": snap["runtime"],
            "classifier_baa_status": snap["classifier_baa_status"],
            "anti_ai_style_guide_global": snap["anti_ai_style_guide_global"],
            # #161 — style-learning admin knobs surfaced in the new
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
                emb, "ollama_url", "http://localhost:11434",
            ) if emb else "http://localhost:11434",
            "fallback_backend": getattr(fb, "backend", "") if fb else "",
            "fallback_model_name": getattr(fb, "model_name", "") if fb else "",
            "fallback_ollama_url": getattr(fb, "ollama_url", "") if fb else "",
            "classifier_backend": getattr(
                config.classifier, "backend", "",
            ),
            "classifier_model": getattr(config.classifier, "model", ""),
            "classifier_ollama_url": getattr(
                config.classifier, "ollama_url",
                "http://localhost:11434",
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
        # #180 — lazy-install state for the local embedding stack.
        # The card sits between the "Currently running" + metrics
        # blocks; the template uses HTMX self-polling on in-flight
        # states. Defensive try: an unmigrated DB (somehow) renders
        # the tab without the install card rather than 500-ing.
        try:
            from email_triage.embedding_bits import (
                get_install_status, is_runtime_ready,
            )
            install_state = get_install_status(db)
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

    return _render(templates, request, "config.html", ctx)


# ---------------------------------------------------------------------------
# /admin/security — auth-policy + compliance knobs (HIPAA + CSRF + session TTL)
# ---------------------------------------------------------------------------

@router.get("/admin/security", response_class=HTMLResponse)
async def admin_security_page(request: Request):
    """Security & compliance settings page.

    Single landing page for everything an auditor cares about that
    isn't tied directly to the certificate. HIPAA toggle, session
    TTL (HIPAA-capped), CSRF enforce, and a read-only mirror of the
    classifier BAA acknowledgments (managed on /config alongside the
    LLM picker).
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    snap = await db_call(_admin_security_snapshot, db, config)

    return _render(templates, request, "admin/security.html", {
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
async def admin_security_save(request: Request):
    """Persist HIPAA toggle + CSRF enforce + session TTL.

    HIPAA flip records a hipaa_boundary_events row (mirrors the
    /config/save behaviour) so the audit trail captures the
    transition. The boundary detector supervised task (PR 9 / D3)
    additionally guards against direct-DB-edit drift.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    config = get_config(request)
    form = await request.form()

    # HIPAA flip — same logic as /config/save, kept consistent so a
    # boundary event is always recorded regardless of which page the
    # operator used.
    from email_triage.triage_logging import is_hipaa_mode as _was_hipaa
    pre_hipaa = _was_hipaa()
    runtime = _get_runtime_settings(db)
    new_runtime = dict(runtime)
    new_runtime["hipaa"] = "hipaa" in form
    from email_triage.web.db import set_setting
    set_setting(db, _RUNTIME_SETTINGS_KEY, new_runtime)
    _apply_runtime_settings(new_runtime)
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

    # CSRF enforce — live update on app.state so the change takes
    # effect immediately without a restart (unlike tls.enabled).
    csrf_enforce = (
        form.get("tls_csrf_enforce") in ("1", "on", "true")
    )
    config.tls.csrf_enforce = csrf_enforce
    request.app.state.csrf_enforce = csrf_enforce

    # #82 item 4 — operator-defined CSRF exempt path prefixes.
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
    try:
        ttl = int(form.get("auth_session_ttl_secs", "86400"))
        if ttl in (900, 1800, 3600, 86400, 604800, 1209600):
            config.auth.session_ttl_secs = ttl
    except (TypeError, ValueError):
        pass
    try:
        hipaa_ttl = int(form.get("auth_hipaa_session_ttl_secs", "900"))
        config.auth.hipaa_session_ttl_secs = min(
            hipaa_ttl, AuthConfig.HIPAA_TTL_HARD_CEILING_SECS,
        )
    except (TypeError, ValueError):
        pass

    # #92 login rate-limit tunables. Sane-range clamps mirror the
    # YAML loader so an operator can't wedge themselves out of the
    # login surface with a typo. ``max=0`` is the documented kill
    # switch (rate-limit off for that scope) and is preserved.
    try:
        v = int(form.get("login_per_email_max", "10"))
        config.auth.login_per_email_max = max(0, v)
    except (TypeError, ValueError):
        pass
    try:
        v = int(form.get("login_per_email_window_secs", "600"))
        config.auth.login_per_email_window_secs = max(60, min(86400, v))
    except (TypeError, ValueError):
        pass
    try:
        v = int(form.get("login_per_ip_max", "30"))
        config.auth.login_per_ip_max = max(0, v)
    except (TypeError, ValueError):
        pass
    try:
        v = int(form.get("login_per_ip_window_secs", "600"))
        config.auth.login_per_ip_window_secs = max(60, min(86400, v))
    except (TypeError, ValueError):
        pass

    # Persist YAML.
    save_error = None
    try:
        _write_config_yaml(config)
    except Exception as e:
        save_error = f"YAML write failed: {e}"
        _log.error("Security config YAML write failed", exc_info=e)

    qs = "saved=1" if not save_error else f"err={save_error[:100]}"
    return RedirectResponse(
        f"/admin/security?{qs}", status_code=303,
    )


@router.post("/config/baa-ack", response_class=HTMLResponse)
async def config_baa_ack(request: Request):
    """Toggle BAA acknowledgment for the (backend, host) tuple (#59).

    Admin-only. Persisted via the BAA gate module; the gate itself
    is consulted at classify time on every HIPAA-flagged message.
    Acknowledgments are scoped to the exact (backend, host) tuple,
    so swapping vendors revokes consent automatically.
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)
    form = await request.form()
    backend = (form.get("backend") or "").strip()
    host = (form.get("host") or "").strip()
    acked = form.get("acked") == "1"

    if not backend or not host:
        return HTMLResponse("Missing backend or host", status_code=400)

    from email_triage.classify.baa_gate import (
        set_baa_ack, revoke_baa_ack, classifier_baa_status,
    )
    if acked:
        set_baa_ack(db, backend, host, user_id=user["id"])
        _log.info(
            "BAA acknowledged",
            backend=backend, host=host, by_user_id=user["id"],
        )
    else:
        revoke_baa_ack(db, backend, host)
        _log.info(
            "BAA acknowledgment revoked",
            backend=backend, host=host, by_user_id=user["id"],
        )

    # Re-render the chip with the new state.
    cls = _build_classifier_from_config(config)
    baa_status = classifier_baa_status(db, cls)
    return _render(templates, request, "config/_baa_chip.html", {
        "classifier_baa_status": baa_status,
    })


@router.post("/config/save", response_class=HTMLResponse)
async def config_save(request: Request):
    """Save all settings (admin only)."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    config = get_config(request)
    templates = get_templates(request)

    form = await request.form()

    # ── Runtime settings (DB-persisted) ──
    # HIPAA mode is now managed on /admin/security; this page renders
    # a read-only mirror. Preserve the existing DB value here so a
    # /config save can't zero it out via the absent form field.
    existing_runtime = _get_runtime_settings(db)
    # #101 — bulk triage knobs. Clamped to the documented min/max
    # ceilings; out-of-range or non-numeric input falls back to the
    # current saved value (don't clobber on bad parse).
    try:
        bulk_rate = int(form.get("bulk_triage_rate_msg_per_min", "") or 0)
    except (TypeError, ValueError):
        bulk_rate = int(existing_runtime.get(
            "bulk_triage_rate_msg_per_min",
            _RUNTIME_DEFAULTS["bulk_triage_rate_msg_per_min"],
        ))
    bulk_rate = max(BULK_TRIAGE_RATE_MIN, min(BULK_TRIAGE_RATE_MAX, bulk_rate))
    try:
        bulk_conc = int(form.get("bulk_triage_concurrency", "") or 0)
    except (TypeError, ValueError):
        bulk_conc = int(existing_runtime.get(
            "bulk_triage_concurrency",
            _RUNTIME_DEFAULTS["bulk_triage_concurrency"],
        ))
    bulk_conc = max(
        BULK_TRIAGE_CONCURRENCY_MIN,
        min(BULK_TRIAGE_CONCURRENCY_MAX, bulk_conc),
    )
    # #145.2 — burst depth, same clamp pattern (out-of-range / bad
    # parse falls back to the saved value rather than zeroing it out).
    try:
        bulk_burst = int(form.get("bulk_triage_burst", "") or 0)
    except (TypeError, ValueError):
        bulk_burst = int(existing_runtime.get(
            "bulk_triage_burst",
            _RUNTIME_DEFAULTS["bulk_triage_burst"],
        ))
    bulk_burst = max(
        BULK_TRIAGE_BURST_MIN,
        min(BULK_TRIAGE_BURST_MAX, bulk_burst),
    )

    new_runtime = {
        "dry_run": "dry_run" in form,
        "log_level": form.get("log_level", "INFO"),
        "hipaa": bool(existing_runtime.get("hipaa", False)),
        "bulk_triage_rate_msg_per_min": bulk_rate,
        "bulk_triage_concurrency": bulk_conc,
        "bulk_triage_burst": bulk_burst,
    }

    from email_triage.web.db import set_setting
    set_setting(db, _RUNTIME_SETTINGS_KEY, new_runtime)
    _apply_runtime_settings(new_runtime)

    # ── Classifier settings (in-memory + YAML) ──
    config.classifier.backend = form.get("classifier_backend", config.classifier.backend)
    config.classifier.model = form.get("classifier_model", config.classifier.model).strip()
    config.classifier.ollama_url = form.get("classifier_ollama_url", config.classifier.ollama_url).strip()
    config.classifier.openai_base_url = form.get("classifier_openai_base_url", "").strip()
    config.classifier.openai_model = form.get("classifier_openai_model", "").strip()
    config.classifier.gemini_model = form.get("classifier_gemini_model", "").strip()

    # ── SMTP settings (in-memory + YAML) ──
    config.smtp.host = form.get("smtp_host", config.smtp.host).strip()
    config.smtp.port = int(form.get("smtp_port", config.smtp.port) or 587)
    config.smtp.username = form.get("smtp_username", config.smtp.username).strip()
    config.smtp.from_addr = form.get("smtp_from_addr", config.smtp.from_addr).strip()
    config.smtp.from_name = form.get("smtp_from_name", config.smtp.from_name).strip()
    config.smtp.use_tls = "smtp_use_tls" in form

    # ── Daily health (#27) + Admin email recipients (CR-2c) + summary sig (#33) ──
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
    try:
        config.health_email.error_rate_threshold_pct = int(
            form.get("health_email_error_rate_threshold_pct", 0) or 0,
        )
    except (TypeError, ValueError):
        config.health_email.error_rate_threshold_pct = 0
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
    set_global_anti_ai_style_guide(db, _anti_ai_global_raw)

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
    try:
        default_iv = int(form.get(
            "ingestion_default_poll_interval_minutes",
            config.ingestion.default_poll_interval_minutes,
        ))
    except (TypeError, ValueError):
        default_iv = config.ingestion.default_poll_interval_minutes
    config.ingestion.default_poll_interval_minutes = _clamp(
        default_iv,
        config.ingestion.POLL_MIN,
        config.ingestion.POLL_MAX,
        config.ingestion.POLL_STEP,
    )

    # Legacy B3 cadence fields — kept for YAML round-trip compatibility
    # so an operator who still has these in their YAML doesn't lose
    # them on Save. No longer drives the loop.
    try:
        push_iv = int(form.get("ingestion_push_poll_interval_min",
                              config.ingestion.push_poll_interval_min))
    except (TypeError, ValueError):
        push_iv = config.ingestion.push_poll_interval_min
    try:
        poll_iv = int(form.get("ingestion_poll_poll_interval_min",
                              config.ingestion.poll_poll_interval_min))
    except (TypeError, ValueError):
        poll_iv = config.ingestion.poll_poll_interval_min
    config.ingestion.push_poll_interval_min = _clamp(
        push_iv, config.ingestion.PUSH_MIN, config.ingestion.PUSH_MAX, config.ingestion.STEP,
    )
    config.ingestion.poll_poll_interval_min = _clamp(
        poll_iv, config.ingestion.POLL_MIN, config.ingestion.POLL_MAX, config.ingestion.STEP,
    )

    # ── Style learning — auto-scan cadence + default mine size (#161) ──
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
    try:
        _cadence_hours = int(
            form.get("style_learning_capture_interval_hours") or 0
        )
        if _cadence_hours > 0:
            set_style_learning_capture_interval_hours(db, _cadence_hours)
    except (TypeError, ValueError):
        pass
    try:
        _mine_limit = int(
            form.get("style_learning_mine_limit_default") or 0
        )
        if _mine_limit > 0:
            set_style_learning_mine_limit_default(db, _mine_limit)
    except (TypeError, ValueError):
        pass

    # ── Write updated config back to YAML ──
    save_error = None
    try:
        _write_config_yaml(config)
    except Exception as e:
        save_error = f"Settings applied in memory but failed to write YAML: {e}"
        _log.error("Failed to write config YAML", error=fmt_exc(e))

    msg = "All settings saved."
    if new_runtime["dry_run"]:
        msg += " Dry-run mode is ON — actions will be logged but not executed."
    _log.info("Config updated", dry_run=new_runtime["dry_run"],
              classifier_backend=config.classifier.backend,
              classifier_model=config.classifier.model)

    return _render(templates, request, "config.html", {
        "user": user,
        "config": config,
        "runtime": new_runtime,
        "anti_ai_style_guide_global": _anti_ai_global_raw,
        "style_learning_capture_interval_hours": (
            get_style_learning_capture_interval_hours(db)
        ),
        "style_learning_mine_limit_default": (
            get_style_learning_mine_limit_default(db)
        ),
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
async def config_ai_backends_save(request: Request):
    """Persist the AI backend config (embedding primary + fallback).

    Writes to the in-memory ``app.state.config`` (so subsequent /config
    reads round-trip the new values) and to the YAML file (so the next
    container restart picks them up). Does NOT hot-reload the running
    embedding backend — that lives in ``app.state.embedding_backend``
    and is constructed once at boot. The save-message banner tells
    the operator to restart.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    config = get_config(request)
    form = await request.form()

    from email_triage.config import EmbeddingConfig, EmbeddingFallbackConfig
    if not hasattr(config, "embedding") or config.embedding is None:
        config.embedding = EmbeddingConfig()

    emb = config.embedding
    emb.backend = (form.get("embedding_backend") or "").strip().lower()
    emb.model_name = (form.get("embedding_model_name") or "").strip()
    emb.ollama_url = (
        form.get("embedding_ollama_url") or "http://localhost:11434"
    ).strip()

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

    save_msg = ""
    save_error = ""
    try:
        from email_triage.web.routers.ui import _write_config_yaml
        _write_config_yaml(config)
        save_msg = "Settings saved."
    except Exception as e:
        save_error = fmt_exc(e)[:200]

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
async def health_email_send_now(request: Request):
    """Fire the daily health digest on demand (admin only).

    Uses the same codepath as the background scheduler — just with
    ``force=True`` so ``quiet_mode`` doesn't suppress a test send when
    the day is boringly healthy.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    config = get_config(request)
    secrets = get_secrets(request)
    templates = get_templates(request)
    watcher_mgr = getattr(request.app.state, "watcher_manager", None)

    from email_triage.web.daily_health import send_daily_health_email
    sent, reason = send_daily_health_email(
        db, config, secrets, watcher_mgr, force=True,
    )

    msg = f"Daily health email: {reason}" if sent else f"Not sent — {reason}"
    runtime = _get_runtime_settings(db)
    return _render(templates, request, "config.html", {
        "user": user,
        "config": config,
        "runtime": runtime,
        "save_msg": msg if sent else None,
        "save_error": msg if not sent else None,
        # Health email is in the General tab (Health Email section).
        "active": "general",
    })


# ---------------------------------------------------------------------------
# #121-A — Explain-this-error endpoint
#
# HTMX-driven button on /logs (per-error chip) and on the O365 probe
# failure chip. Submits the verbatim error string + provider/class
# context, returns an HTML chip with a plain-English AI explanation.
# Backend reuse: OllamaClassifier.complete() via error_explain module;
# no new HTTP path to the LLM. Privacy invariant enforced inside
# error_explain._build_prompt (which is unit-tested directly).
# ---------------------------------------------------------------------------

@router.post("/explain-error", response_class=HTMLResponse)
async def explain_error_endpoint(request: Request):
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
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)
    if user["role"] != "admin":
        return HTMLResponse("Forbidden", status_code=403)

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
        try:
            account_id = int(raw_aid)
        except ValueError:
            account_id = None

    # HIPAA gate when an account is named — actor must manage it.
    if account_id is not None:
        from email_triage.web.db import (
            can_manage_account, get_email_account,
        )
        acct = get_email_account(db, account_id)
        if acct is None:
            return HTMLResponse("Account not found", status_code=404)
        if not can_manage_account(db, user, acct):
            return HTMLResponse("Forbidden", status_code=403)

    # Audit row so the operator can see the AI was consulted. Detail
    # carries the error_class + provider for cross-row correlation
    # but NEVER the raw error_text (could include partial PHI in
    # exotic provider responses).
    try:
        from email_triage.web.db import record_auth_event
        detail_parts = []
        if provider:
            detail_parts.append(f"provider={provider}")
        if error_class:
            detail_parts.append(f"class={error_class}")
        if account_id is not None:
            detail_parts.append(f"account_id={account_id}")
        record_auth_event(
            db,
            event_type="explain_error",
            email=user.get("email", ""),
            user_id=user.get("id"),
            outcome="success",
            detail=", ".join(detail_parts) or None,
        )
    except Exception as e:
        _log.warning(
            "explain_error: audit write failed (continuing)",
            error=fmt_exc(e),
        )

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
