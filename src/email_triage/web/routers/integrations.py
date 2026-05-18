"""External-integrations admin surface.

Currently houses Gmail Pub/Sub push configuration + per-account watch
status. Future home for any additional external-trigger integrations
(Office365 Graph push hardening, generic webhook receivers, etc.) so
they don't bloat the existing /admin/security or /admin/acme-status
pages, which are scoped tightly to compliance + certificate concerns.

Design parallels the /admin/security page (`web/routers/ui.py`):

* GET ``/admin/integrations``   — render the form populated from
  ``config.push`` + ``gmail_watches`` rows.
* POST ``/admin/integrations/save`` — persist the four push.* keys
  via the shared ``_write_config_yaml`` helper.
* POST ``/admin/integrations/<account_id>/renew-watch`` — call
  ``provider.register_watch(topic)`` synchronously and update the
  ``gmail_watches`` row, replacing the prior SQL-nuke + restart
  workflow.

All three are admin-only. The save handler reuses the proven
``_write_config_yaml`` round-trip from ``ui.py`` so push.* values
land in the same YAML the rest of the app loads from.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from email_triage.triage_logging import get_logger
from email_triage.web.dependencies import get_current_user
from email_triage._errfmt import fmt_exc

log = get_logger("web.integrations")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


def _get_config(request: Request):
    return request.app.state.config


def _get_secrets(request: Request):
    return request.app.state.secrets


def _get_templates(request: Request):
    return request.app.state.templates


def _render(request: Request, name: str, ctx: dict[str, Any] | None = None):
    """Match the ui.py / auth_keys.py render wrapper so base-template
    globals (user, hipaa_mode) get injected consistently."""
    from email_triage.web.routers.ui import _render as _render_ui
    return _render_ui(_get_templates(request), request, name, ctx or {})


def _require_admin(request: Request):
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _hours_until(expires_at_iso: str) -> float | None:
    """Hours from now until ``expires_at_iso``; negative if past.

    Returns None for missing / unparseable / sentinel epoch values
    (the synthetic poll-mode rows carry ``1970-01-01T00:00:00+00:00``
    so they're effectively "no real watch yet").
    """
    if not expires_at_iso:
        return None
    try:
        dt = datetime.fromisoformat(expires_at_iso)
    except (TypeError, ValueError):
        return None
    if dt.year < 2000:  # epoch sentinel — not a real watch
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).total_seconds() / 3600.0


def _watch_status(hours_until: float | None, topic_name: str) -> str:
    """Map hours-until-expiry + topic configuration to a UI bucket.

    * ``unconfigured`` — synthetic placeholder row (no real watch
      ever issued).
    * ``expired`` — past expiration.
    * ``stale`` — under 4 hours; renew now.
    * ``renewable`` — under 24 hours; renewer will pick it up soon.
    * ``healthy`` — more than 24 hours runway.
    """
    if not topic_name or hours_until is None:
        return "unconfigured"
    if hours_until <= 0:
        return "expired"
    if hours_until < 4:
        return "stale"
    if hours_until < 24:
        return "renewable"
    return "healthy"


def _o365_subscriptions_with_account_metadata(
    db: sqlite3.Connection,
) -> list[dict]:
    """Join ``office365_subscriptions`` with the owning account row so
    the admin table can render account name + owner without N+1 queries.

    Mirrors ``_gmail_watches_with_account_metadata`` for the Gmail
    Pub/Sub side. Output rows carry:

    * ``account_id`` + ``account_name`` (operator-set label) +
      ``account_label`` ("name (id N)" — never bare "Account #N").
    * ``owner_email`` + ``owner_name`` (the owning user).
    * ``subscription_id`` + ``expiration_at`` + ``status`` +
      ``last_notification_at`` + ``error_count`` + ``error_last``.
    * ``hours_until_expiry`` + ``status_bucket`` (renderable hint).

    The Microsoft Graph subscription resource is the standard mail
    push subscription; the admin table uses a fixed display string
    (``Inbox messages``) since every row points at the same Graph
    resource.
    """
    rows = db.execute(
        "SELECT os.*, "
        "       ea.name AS account_name, "
        "       ea.user_id, "
        "       u.email AS owner_email, "
        "       u.name  AS owner_name "
        "FROM office365_subscriptions os "
        "LEFT JOIN email_accounts ea ON ea.id = os.account_id "
        "LEFT JOIN users u ON u.id = ea.user_id "
        "ORDER BY u.email, os.account_id",
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        aid = d.get("account_id")
        name = (d.get("account_name") or "").strip()
        if name and aid is not None:
            d["account_label"] = f"{name} (id {aid})"
        elif aid is not None:
            d["account_label"] = f"id {aid}"
        else:
            d["account_label"] = "(unknown account)"
        h = _hours_until(d.get("expiration_at") or "")
        d["hours_until_expiry"] = h
        # Status bucket — renderer-friendly label. Reuse the gmail
        # bucket's vocabulary; Graph subscriptions max ~3 days so
        # the 24h cutoff is still meaningful.
        if h is None:
            d["status_bucket"] = (d.get("status") or "unknown")
        elif h <= 0:
            d["status_bucket"] = "expired"
        elif h < 4:
            d["status_bucket"] = "stale"
        elif h < 24:
            d["status_bucket"] = "renewable"
        else:
            d["status_bucket"] = "healthy"
        out.append(d)
    return out


def _gmail_watches_with_account_metadata(db: sqlite3.Connection) -> list[dict]:
    """Join ``gmail_watches`` with the owning account row so the UI can
    render owner email + account name without N+1 queries.

    ``email_accounts.name`` is the operator-supplied label for the
    account (e.g. "personal Gmail"); ``users.name`` is the user's
    display name. Both columns are literally named ``name`` in their
    own tables, so we alias to disambiguate.

    Read-time fallback for ``email_address``: when the gmail_watches
    row is blank (legacy registration before the write-time fallback
    landed), fill from ``account.config["account"]``. Avoids the
    "blank Account column" bug for stale rows -- operator can then
    re-register via the Renew button to refresh the row, but the UI
    is no longer misleading in the interim.
    """
    import json as _json
    rows = db.execute(
        "SELECT gw.*, "
        "       ea.name AS account_name, "
        "       ea.config_json AS account_config_json, "
        "       ea.user_id, "
        "       u.email AS owner_email, "
        "       u.name  AS owner_name "
        "FROM gmail_watches gw "
        "LEFT JOIN email_accounts ea ON ea.id = gw.account_id "
        "LEFT JOIN users u ON u.id = ea.user_id "
        "ORDER BY u.email, gw.email_address",
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        if not (d.get("email_address") or "").strip():
            cfg_raw = d.get("account_config_json") or "{}"
            try:
                cfg = _json.loads(cfg_raw) if isinstance(cfg_raw, str) else (cfg_raw or {})
            except (ValueError, TypeError):
                cfg = {}
            fallback = (cfg.get("account") or "").strip()
            if fallback:
                d["email_address"] = fallback
                d["email_address_from_fallback"] = True
        # Strip the raw JSON before handing to the template -- it's not
        # rendered and just bloats the dict.
        d.pop("account_config_json", None)
        h = _hours_until(d.get("expires_at") or "")
        d["hours_until_expiry"] = h
        d["status"] = _watch_status(h, d.get("topic_name") or "")
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Page render
# ---------------------------------------------------------------------------

@router.get("/admin/integrations", response_class=HTMLResponse)
async def admin_integrations_legacy(request: Request):
    """Legacy URL — Integrations is now a tab on /config.

    303-redirect preserves bookmarks, log links, and any test using
    the old path (TestClient follows redirects by default).
    Per-query-string ``saved=1`` / ``err=...`` are forwarded so the
    save handler's redirect target still surfaces its flash message.

    Auth gate runs FIRST so anonymous users still bounce to /login
    and non-admin users still get 403 — preserves the pre-refactor
    contract that ``follow_redirects=False`` tests pin against.
    """
    user, err = _require_admin(request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=integrations{tail}", status_code=303,
    )


def build_integrations_context(request: Request) -> dict:
    """Build the context dict the Integrations tab body needs.

    Lifted out of the (now-redirect) legacy ``/admin/integrations``
    handler so the unified ``/config`` route can render the same body
    under the ``?tab=integrations`` branch without duplicating the
    snapshot logic.
    """

    db = _get_db(request)
    config = _get_config(request)
    push = config.push
    watches = _gmail_watches_with_account_metadata(db)
    o365_subscriptions = _o365_subscriptions_with_account_metadata(db)

    # The webhook URL is push.public_url + the static webhook path.
    # We surface the full URL as a copy-paste hint so operators don't
    # have to remember to append /webhooks/gmail when configuring the
    # gcloud subscription.
    webhook_url = (
        (push.public_url or "").rstrip("/") + "/webhooks/gmail"
        if push.public_url else ""
    )
    # Sister hint for the Office 365 sister table — same construction
    # rule, different path. Operators wiring up a Microsoft Graph
    # subscription paste this into the ``notificationUrl`` field.
    o365_webhook_url = (
        (push.public_url or "").rstrip("/") + "/webhooks/office365"
        if push.public_url else ""
    )

    # Outbound webhook destination (OpenClaw integration). v1 supports
    # a single target via UI; advanced multi-target setups still edit
    # YAML directly. The WebhookTarget at index 0 is the canonical
    # OpenClaw destination — its secret lives in the secrets store
    # under the key named by secret_key (default OPENCLAW_WEBHOOK_SECRET).
    webhooks = list(getattr(config, "webhooks", []) or [])
    outbound_target = webhooks[0] if webhooks else None
    secrets_provider = _get_secrets(request)
    outbound_secret_set = False
    if outbound_target and outbound_target.secret_key:
        try:
            outbound_secret_set = bool(
                secrets_provider.get(outbound_target.secret_key) or ""
            )
        except Exception:
            outbound_secret_set = False
    webhooks_allow_external = bool(getattr(config, "webhooks_allow_external", False))

    # Classification cache section context — extended 2026-05-13
    # for the two-level cache (inner cap + hint strategy + threshold).
    redis_cache_cfg = getattr(config, "redis_cache", None)
    redis_cache_url = (
        (getattr(redis_cache_cfg, "url", "") or "").strip()
        if redis_cache_cfg is not None else ""
    )
    redis_cache_ttl = int(
        getattr(redis_cache_cfg, "ttl_secs", 30 * 24 * 3600)
        if redis_cache_cfg is not None else 30 * 24 * 3600,
    )
    redis_cache_inner_cap = int(
        getattr(redis_cache_cfg, "inner_cap_per_sender", 250)
        if redis_cache_cfg is not None else 250,
    )
    redis_cache_hint_strategy = str(
        getattr(redis_cache_cfg, "hint_strategy", "top_k_with_freq")
        if redis_cache_cfg is not None else "top_k_with_freq",
    )
    redis_cache_dom_pct = int(
        getattr(redis_cache_cfg, "dominant_threshold_pct", 70)
        if redis_cache_cfg is not None else 70,
    )
    # Surface the per-process counters so the operator can sanity-check
    # that the cache is doing useful work without opening /health/detail.
    try:
        from email_triage.cache.classification import get_counters
        redis_cache_counters = get_counters().snapshot()
    except Exception:
        redis_cache_counters = {
            "hits": 0, "misses": 0, "errors": 0,
            "hits_exact": 0, "hits_hint_topk": 0,
            "hits_hint_dominant": 0, "hits_hint_skipped": 0,
            "misses_cold": 0,
        }
    # 2026-05-13 — lifetime counters (Redis-persisted). Resets only
    # via the explicit admin Reset button below. Empty dict when no
    # persistent backend wired (cache URL absent).
    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend,
        )
        _be = get_install_counter_backend()
        redis_cache_counters_lifetime = (
            _be.fetch("classification_cache") if _be is not None else {}
        )
        embedding_counters_lifetime = {
            "ollama": _be.fetch("embedding:ollama") if _be else {},
            "sentence_transformers": (
                _be.fetch("embedding:sentence_transformers")
                if _be else {}
            ),
            "fallback": _be.fetch("embedding:fallback") if _be else {},
        }
        webhook_counters_lifetime = (
            _be.fetch("webhooks") if _be is not None else {}
        )
    except Exception:
        redis_cache_counters_lifetime = {}
        embedding_counters_lifetime = {}
        webhook_counters_lifetime = {}
    # Known event-type catalogue rendered as checkboxes. Stable list;
    # add new events here when the codebase grows them.
    known_events = [
        ("triage.completed", "Triage completed", "Fires after a triage run finishes. Carries run_id, account_id, account_name, query, total_messages, results_count, errors_count, elapsed_secs, trigger. No message content (no sender, no subject, no body), in any mode. HIPAA-flagged accounts hard-skip emit even before the dispatcher gate."),
        ("flow.classified", "Flow classified", "Fires when the classifier returns a category. Pre-route firing — used for downstream consumers that want raw classifier output. Metadata-only payload."),
    ]

    return {
        "config": config,
        "push": push,
        "watches": watches,
        "o365_subscriptions": o365_subscriptions,
        "webhook_url": webhook_url,
        "o365_webhook_url": o365_webhook_url,
        "outbound_target": outbound_target,
        "outbound_secret_set": outbound_secret_set,
        "outbound_events_subscribed": (
            set(outbound_target.events) if outbound_target else set()
        ),
        "outbound_event_catalogue": known_events,
        "webhooks_allow_external": webhooks_allow_external,
        "redis_cache_url": redis_cache_url,
        "redis_cache_ttl": redis_cache_ttl,
        "redis_cache_inner_cap": redis_cache_inner_cap,
        "redis_cache_hint_strategy": redis_cache_hint_strategy,
        "redis_cache_dom_pct": redis_cache_dom_pct,
        "redis_cache_counters": redis_cache_counters,
        "redis_cache_counters_lifetime": redis_cache_counters_lifetime,
        "embedding_counters_lifetime": embedding_counters_lifetime,
        "webhook_counters_lifetime": webhook_counters_lifetime,
        "saved": request.query_params.get("saved") == "1",
        "renewed": request.query_params.get("renewed") or "",
        "err": request.query_params.get("err") or "",
        # #151 — flush button result. ``flushed`` is the int count
        # when the previous POST succeeded; ``flush_err`` is the
        # human-readable error string when it failed.
        "flushed": (
            int(request.query_params.get("flushed", "0") or 0)
            if request.query_params.get("flushed") else None
        ),
        "flush_err": request.query_params.get("flush_err") or "",
        # 2026-05-13 — lifetime-counter reset result (admin button).
        "reset_ok": request.query_params.get("reset_ok") or "",
        "reset_err": request.query_params.get("reset_err") or "",
    }


# ---------------------------------------------------------------------------
# Save handler
# ---------------------------------------------------------------------------

@router.post("/admin/integrations/save", response_class=HTMLResponse)
async def admin_integrations_save(request: Request):
    """Persist the four ``push.*`` keys into the YAML config.

    Inputs are normalized:

    * URLs trimmed, trailing-slash stripped (audience binding fails on
      a stray trailing slash).
    * Topic name trimmed; the wire format is
      ``projects/<proj>/topics/<topic>``.
    * SA email lowercased.

    No live in-memory mutation here -- the supervised renewer reads
    ``config.push.gmail_topic_name`` on every sweep, so values picked
    up on next sweep without restart.
    """
    user, err = _require_admin(request)
    if err:
        return err

    config = _get_config(request)
    form = await request.form()

    def _clean_url(s: str) -> str:
        s = (s or "").strip().rstrip("/")
        return s

    config.push.public_url = _clean_url(form.get("public_url", ""))
    config.push.gmail_topic_name = (form.get("gmail_topic_name", "") or "").strip()
    config.push.gmail_subscription_sa_email = (
        (form.get("gmail_subscription_sa_email", "") or "").strip().lower()
    )
    # Audience defaults to public_url when blank -- explicit empty
    # string is a valid choice (the webhook validator falls back to
    # public_url if audience is empty).
    config.push.gmail_audience = _clean_url(form.get("gmail_audience", ""))

    # ── Google OAuth install-level client credentials ──
    # Moved from /config/save to here on 2026-05-10 so every
    # integration-related setting lives on one admin page.
    # Blank-secret submit preserves the stored value; plaintext IDs
    # always write what's posted.
    secrets = _get_secrets(request)
    config.google_oauth.web_client_id = form.get("google_oauth_web_client_id", "").strip()
    secrets.set("GOOGLE_OAUTH_WEB_CLIENT_ID", config.google_oauth.web_client_id)
    _web_secret_posted = form.get("google_oauth_web_client_secret", "")
    if _web_secret_posted:
        config.google_oauth.web_client_secret = _web_secret_posted
        secrets.set("GOOGLE_OAUTH_WEB_CLIENT_SECRET", _web_secret_posted)

    config.google_oauth.desktop_client_id = form.get("google_oauth_desktop_client_id", "").strip()
    secrets.set("GOOGLE_OAUTH_DESKTOP_CLIENT_ID", config.google_oauth.desktop_client_id)
    _desk_secret_posted = form.get("google_oauth_desktop_client_secret", "")
    if _desk_secret_posted:
        config.google_oauth.desktop_client_secret = _desk_secret_posted
        secrets.set("GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET", _desk_secret_posted)

    # ── Office 365 OAuth install-level credentials ──
    # Single Azure app registration shared across every O365 account on
    # this install. Per-account is_personal_msa flag routes tenant at
    # runtime — "common" if personal, else the install tenant_id below.
    # Moved from /config/save to here on 2026-05-10 alongside Google
    # OAuth so every integration-related setting lives on one admin
    # page.
    _o365_tenant_posted = form.get("office365_oauth_tenant_id", "").strip()
    if _o365_tenant_posted.lower() == "common":
        # "common" is reserved for the per-account "Personal Microsoft
        # account" checkbox path. Don't let the install-level field
        # claim it — that would silently break the org-tenant routing
        # for every non-personal account.
        config.office365_oauth.tenant_id = ""
        secrets.set("O365_OAUTH_TENANT_ID", "")
    else:
        config.office365_oauth.tenant_id = _o365_tenant_posted
        secrets.set("O365_OAUTH_TENANT_ID", _o365_tenant_posted)
    config.office365_oauth.client_id = form.get("office365_oauth_client_id", "").strip()
    secrets.set("O365_OAUTH_CLIENT_ID", config.office365_oauth.client_id)
    _o365_secret_posted = form.get("office365_oauth_client_secret", "")
    if _o365_secret_posted:
        config.office365_oauth.client_secret = _o365_secret_posted
        secrets.set("O365_OAUTH_CLIENT_SECRET", _o365_secret_posted)

    # ── Outbound webhook destination (OpenClaw) ──
    # v1: single target. The form posts:
    #   outbound_webhook_url       — the destination URL (empty clears)
    #   outbound_webhook_event_<n> — checkbox per known event name
    #   outbound_webhook_secret    — secret VALUE (empty preserves stored)
    #   webhooks_allow_external    — checkbox: allow public-internet URLs
    from email_triage.config import WebhookTarget
    out_url = _clean_url(form.get("outbound_webhook_url", ""))
    selected_events: list[str] = []
    for fkey in form.keys():
        if fkey.startswith("outbound_webhook_event_") and form.get(fkey):
            event_name = fkey[len("outbound_webhook_event_"):]
            if event_name:
                selected_events.append(event_name)
    selected_events = sorted(set(selected_events))
    secret_key_name = "OPENCLAW_WEBHOOK_SECRET"
    if out_url:
        # Build / refresh the single canonical target.
        config.webhooks = [
            WebhookTarget(
                url=out_url,
                events=selected_events,
                secret_key=secret_key_name,
            )
        ]
    else:
        # Empty URL clears the destination entirely.
        config.webhooks = []
    config.webhooks_allow_external = "webhooks_allow_external" in form
    # Secret is mask-preserve: empty submit keeps the stored value.
    posted_secret = form.get("outbound_webhook_secret", "")
    if posted_secret:
        secrets.set(secret_key_name, posted_secret)

    # ── #151 — Classification cache (optional Redis) ──
    # URL empty = OFF (default). TTL clamped to the supported window
    # [3600, 7_776_000] = 1 hour to 90 days; anything outside snaps
    # to the nearest bound rather than rejecting the save.
    from email_triage.config import RedisCacheConfig
    from email_triage.cache.classification import (
        build_cache_from_config, clamp_ttl_secs,
        set_install_classification_cache,
    )
    rc_url = (form.get("redis_cache_url", "") or "").strip()
    rc_ttl = clamp_ttl_secs(form.get("redis_cache_ttl_secs"))
    # 2026-05-13 two-level cache knobs. Out-of-range / non-numeric
    # falls back to the default.
    try:
        rc_inner_cap = max(
            1, min(10000, int(form.get("redis_cache_inner_cap") or 250)),
        )
    except (TypeError, ValueError):
        rc_inner_cap = 250
    rc_strategy = (
        form.get("redis_cache_hint_strategy") or "top_k_with_freq"
    ).strip().lower()
    if rc_strategy not in ("top_k_with_freq", "top_1_dominant"):
        rc_strategy = "top_k_with_freq"
    try:
        rc_dom_pct = max(
            50, min(100, int(form.get("redis_cache_dom_pct") or 70)),
        )
    except (TypeError, ValueError):
        rc_dom_pct = 70
    config.redis_cache = RedisCacheConfig(
        url=rc_url, ttl_secs=rc_ttl,
        inner_cap_per_sender=rc_inner_cap,
        hint_strategy=rc_strategy,
        dominant_threshold_pct=rc_dom_pct,
    )
    # Swap the install-level singleton so the change takes effect
    # without restart. Old singleton (if any) is dropped — its lazy
    # client closes on next GC.
    try:
        set_install_classification_cache(
            build_cache_from_config(config.redis_cache),
        )
    except Exception as e:
        log.warning(
            "Classification cache install-swap failed",
            error=fmt_exc(e),
        )

    # 2026-05-13 — swap the persistent-counter backend too. Same
    # Redis URL the cache uses; empty URL = persistence OFF.
    try:
        from email_triage.engine.persistent_counters import (
            build_counter_backend_from_config,
            set_install_counter_backend,
        )
        set_install_counter_backend(
            build_counter_backend_from_config(config.redis_cache),
        )
    except Exception as e:
        log.warning(
            "Persistent counter backend swap failed",
            error=fmt_exc(e),
        )

    save_error = None
    try:
        from email_triage.web.routers.ui import _write_config_yaml
        _write_config_yaml(config)
    except Exception as e:
        save_error = f"YAML write failed: {e}"
        log.error("Integrations YAML write failed", error=fmt_exc(e))

    log.info(
        "Push config saved",
        actor=user["email"],
        public_url=config.push.public_url,
        topic=config.push.gmail_topic_name,
    )

    qs = "saved=1" if not save_error else f"err={save_error[:120]}"
    # Redirect to the new /config tab home — legacy /admin/integrations
    # GET 303-bounces here anyway, but bypass the extra hop on success.
    return RedirectResponse(
        f"/config?tab=integrations&{qs}", status_code=303,
    )


# ---------------------------------------------------------------------------
# Renew-now (per account)
# ---------------------------------------------------------------------------

@router.post(
    "/admin/integrations/{account_id}/renew-watch",
    response_class=JSONResponse,
)
async def admin_integrations_renew_watch(account_id: int, request: Request):
    """Force-renew a single Gmail account's watch right now.

    Replaces the SQL-nuke + container-restart workflow that used to be
    the only way to upgrade a synthetic poll-mode placeholder row to a
    real watch. Calls ``provider.register_watch(topic)`` synchronously
    and updates the ``gmail_watches`` row.

    Returns JSON for the UI's inline button (no full-page navigation).
    """
    user, err = _require_admin(request)
    if err:
        if isinstance(err, RedirectResponse):
            return JSONResponse({"error": "auth_required"}, status_code=401)
        return JSONResponse({"error": "forbidden"}, status_code=403)

    db = _get_db(request)
    config = _get_config(request)
    secrets = _get_secrets(request)

    topic = config.push.gmail_topic_name
    if not topic:
        return JSONResponse(
            {"error": "topic_unset",
             "message": "Set push.gmail_topic_name first."},
            status_code=400,
        )

    from email_triage.web.db import get_email_account, upsert_gmail_watch
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account

    acct = get_email_account(db, account_id)
    if acct is None:
        return JSONResponse(
            {"error": "account_not_found"}, status_code=404,
        )
    if acct.get("provider_type") != "gmail_api":
        return JSONResponse(
            {"error": "not_gmail",
             "message": "Account is not a Gmail API account."},
            status_code=400,
        )

    # Resolve email_address. The email_accounts table stores it inside
    # config_json["account"], not as a top-level column. Prefer the
    # live profile (canonical source) and fall back to config so a
    # transient API-down doesn't lose the field. The synthetic poll-
    # mode placeholder rows stamped by the unified-poll-loop already
    # carry the right email, so we also fall back to whatever's there.
    cfg_email = (acct.get("config") or {}).get("account", "")
    profile_email = ""
    try:
        provider = _create_provider_from_account(acct, secrets)
        if not isinstance(provider, GmailApiProvider):
            return JSONResponse(
                {"error": "provider_build_failed"}, status_code=500,
            )
        try:
            # Capture the live profile email FIRST -- if register_watch
            # fails, we still want this for diagnostics; if it succeeds
            # we want the canonical address on the watch row.
            try:
                profile = await provider.get_profile()
                profile_email = str(profile.get("emailAddress", ""))
            except Exception as e:
                log.warning(
                    "Profile fetch failed during renew (non-fatal)",
                    account_id=account_id, error=fmt_exc(e),
                )
            data = await provider.register_watch(topic)
        finally:
            try:
                await provider.close()
            except Exception:
                pass
    except Exception as e:
        log.error(
            "Manual watch renewal failed",
            account_id=account_id, error=fmt_exc(e),
        )
        return JSONResponse(
            {"error": "renew_failed", "message": str(e)},
            status_code=500,
        )

    from datetime import timedelta
    exp_ms = int(data.get("expiration", 0))
    now = datetime.now(timezone.utc)
    exp_iso = (
        datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc).isoformat()
        if exp_ms else (now + timedelta(days=7)).isoformat()
    )
    history_id = str(data.get("historyId") or "")

    # Fall back through profile -> config -> existing watch row, in that
    # order. Existing-watch fallback covers the case where get_profile
    # transiently fails AND the account row was saved before the
    # email/account field migration.
    from email_triage.web.db import get_gmail_watch
    existing = get_gmail_watch(db, account_id)
    existing_email = (existing or {}).get("email_address") or ""
    email_address = profile_email or cfg_email or existing_email
    if not email_address:
        return JSONResponse(
            {"error": "missing_email_address",
             "message": "Could not resolve the Gmail address for this "
                        "account. Re-save the account or re-authenticate."},
            status_code=400,
        )

    upsert_gmail_watch(
        db,
        account_id=account_id,
        email_address=email_address,
        topic_name=topic,
        history_id=history_id,
        expires_at=exp_iso,
    )
    log.info(
        "Manual watch renewal succeeded",
        actor=user["email"],
        account_id=account_id,
        new_expires_at=exp_iso,
    )
    return JSONResponse({
        "ok": True,
        "expires_at": exp_iso,
        "history_id": history_id,
    })


# ---------------------------------------------------------------------------
# #151 — Classification cache flush
# ---------------------------------------------------------------------------

@router.post(
    "/admin/integrations/cache/flush",
    response_class=HTMLResponse,
)
async def admin_integrations_cache_flush(request: Request):
    """Drop every classification-cache key (``et:cls:*``).

    Admin-only + CSRF-protected. The cache itself does the SCAN/DEL
    sweep so we don't load the whole keyspace into Python at once.
    Other services sharing the same Redis instance keep their keys.

    Redirects back to ``/admin/integrations`` with the result count
    (or error string) in the querystring; the page renders a small
    confirmation block on the next GET.
    """
    user, err = _require_admin(request)
    if err:
        return err

    try:
        from email_triage.cache.classification import (
            get_install_classification_cache,
        )
        cache = get_install_classification_cache()
        if cache is None or not cache.enabled:
            return RedirectResponse(
                "/admin/integrations?flush_err="
                "Cache+is+not+configured.",
                status_code=303,
            )
        deleted = cache.flush_all()
    except Exception as e:
        log.error("Classification cache flush failed", error=fmt_exc(e))
        msg = str(e)[:120].replace(" ", "+")
        return RedirectResponse(
            f"/admin/integrations?flush_err={msg}",
            status_code=303,
        )

    log.info(
        "Classification cache flushed via admin action",
        actor=user["email"],
        deleted=deleted,
    )
    return RedirectResponse(
        f"/admin/integrations?flushed={int(deleted)}",
        status_code=303,
    )


@router.post(
    "/admin/integrations/counters/reset",
    response_class=HTMLResponse,
)
async def admin_integrations_counters_reset(request: Request):
    """Reset lifetime (Redis-persisted) counters per namespace.

    Process-local counters keep accumulating from where they are
    — they reset only on container restart. This endpoint just
    nukes the corresponding Redis HASH.

    Form field ``namespace`` selects which slice to flush:
      classification_cache | embedding:ollama |
      embedding:sentence_transformers | embedding:fallback |
      webhooks | all

    Admin-only + CSRF-protected.
    """
    user, err = _require_admin(request)
    if err:
        return err

    form = await request.form()
    namespace = (form.get("namespace") or "").strip().lower()
    valid = {
        "classification_cache",
        "embedding:ollama",
        "embedding:sentence_transformers",
        "embedding:fallback",
        "webhooks",
        "all",
    }
    if namespace not in valid:
        return RedirectResponse(
            "/admin/integrations?reset_err=invalid+namespace",
            status_code=303,
        )

    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend,
        )
        be = get_install_counter_backend()
        if be is None:
            return RedirectResponse(
                "/admin/integrations?reset_err="
                "Persistent+counters+not+configured.",
                status_code=303,
            )
        targets = (
            [
                "classification_cache",
                "embedding:ollama",
                "embedding:sentence_transformers",
                "embedding:fallback",
                "webhooks",
            ]
            if namespace == "all" else [namespace]
        )
        deleted = sum(be.reset(ns) for ns in targets)
    except Exception as e:
        log.error("Lifetime counter reset failed", error=fmt_exc(e))
        msg = str(e)[:120].replace(" ", "+")
        return RedirectResponse(
            f"/admin/integrations?reset_err={msg}",
            status_code=303,
        )

    log.info(
        "Lifetime counters reset via admin action",
        actor=user["email"],
        namespace=namespace,
        keys_deleted=deleted,
    )
    return RedirectResponse(
        f"/admin/integrations?reset_ok={namespace}",
        status_code=303,
    )
