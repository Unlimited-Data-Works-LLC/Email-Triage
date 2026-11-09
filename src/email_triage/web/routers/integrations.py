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
from email_triage.web.db_threadpool import db_call
from email_triage.web._flash import scrub_exc  # N-179 R20_1 sub-4
from email_triage.web.error_surface import api_error_response  #  tranche 1 R32
from email_triage.web.routers._redirect import err_qs, qs, read_flash
from email_triage._errfmt import fmt_exc
from email_triage.web.routers.ui._shared import _safe_int  # N-282 R29
from email_triage._isotime import to_utc_iso

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


async def _render(request: Request, name: str, ctx: dict[str, Any] | None = None):
    """Match the ui.py / auth_keys.py render wrapper so base-template
    globals (user, hipaa_mode) get injected consistently.

     / Option B — ``async`` because the shared ``_render`` is async
    (auto-injected admin banners read the shared connection off-loop);
    callers ``await`` the wrapper."""
    from email_triage.web.routers.ui import _render as _render_ui
    return await _render_ui(_get_templates(request), request, name, ctx or {})


# Census 2026-06-09 #3: byte-identical UI admin gate → the dependencies SSOT.
from email_triage.web.dependencies import require_admin_ui as _require_admin


def _hours_until(expires_at_iso: str) -> float | None:
    """Hours from now until ``expires_at_iso``; negative if past.

    Returns None for missing / unparseable / sentinel epoch values
    (the synthetic poll-mode rows carry ``1970-01-01T00:00:00+00:00``
    so they're effectively "no real watch yet").
    """
    # N-263 R27 + N-357b R31 (2026-07-06 baseline shrink): parse_iso_aware
    # is the parse_iso composite that also stamps UTC on naive results —
    # handles the trailing-Z form Gmail emits AND the assume-UTC posture.
    from email_triage._isotime import parse_iso_aware
    dt = parse_iso_aware(expires_at_iso)
    if dt is None:
        return None
    if dt.year < 2000:  # epoch sentinel — not a real watch
        return None
    now = datetime.now(timezone.utc)
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
    from email_triage.db._helpers import load_json_col
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
            # census  SSOT — corrupt account_config_json → {}. The column
            # is TEXT (ea.config_json AS account_config_json), so cfg_raw is
            # always a str here (dict(Row) over TEXT); load_json_col never
            # raises and degrades a corrupt blob to {}.
            cfg = load_json_col(cfg_raw, default={})
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=integrations{tail}", status_code=303,
    )


_OUTBOUND_TARGET_TYPE_ORDER = (
    "custom", "slack", "pagerduty", "opsgenie", "discord", "teams",
)


def _build_outbound_target_type_options() -> list[dict[str, Any]]:
    """Return the wizard dropdown option list for the outbound-webhook
    target-type picker (Drive C of task  / N-419).

    Sourced from ``web/_webhook_target_types.TARGET_TYPES`` — the SSOT
    registry — so a new target-type addition surfaces in the admin UI
    without a second edit here. Ordered so the pre-existing default
    (``custom``) is first and matches the wire-shape docs.
    """
    from email_triage.web._webhook_target_types import TARGET_TYPES
    out: list[dict[str, Any]] = []
    for key in _OUTBOUND_TARGET_TYPE_ORDER:
        entry = TARGET_TYPES.get(key)
        if entry is None:
            continue
        out.append({
            "key": key,
            "label": entry["label"],
            "url_shape_hint": entry.get("url_shape_hint") or "",
            "default_template": entry.get("default_template") or "",
            "docs_url": entry.get("docs_url") or "",
            "required_fields": entry.get("required_fields") or [],
        })
    return out


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

    #  Internet Search — optional self-hosted SearXNG host (settings table).
    from email_triage.web.db import get_web_search_searxng_url
    web_search_searxng_url = get_web_search_searxng_url(db) or ""

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

    # Outbound webhook destination (any receiver — OpenClaw, Slack, an
    # in-house automation, ...). v1 supports
    # a single target via UI; advanced multi-target setups still edit
    # YAML directly. The WebhookTarget at index 0 is the canonical
    # The webhook destination — its secret lives in the secrets store
    # under the key named by secret_key (default OPENCLAW_WEBHOOK_SECRET).
    webhooks = list(getattr(config, "webhooks", []) or [])
    outbound_target = webhooks[0] if webhooks else None
    secrets_provider = _get_secrets(request)
    outbound_secret_set = False
    outbound_secret_unreadable = False
    if outbound_target and outbound_target.secret_key:
        from email_triage.secrets import SecretsDecryptError, read_secret
        try:
            outbound_secret_set = bool(
                read_secret(secrets_provider, outbound_target.secret_key) or ""
            )
        except SecretsDecryptError:
            # A5 / SME finding DA-2 — the row EXISTS but won't decrypt
            # (corrupt / master-key mismatch). This is a THIRD state, not
            # "set" and not "unset": "leave blank to keep" would tell the
            # operator to KEEP a broken secret while deliveries silently
            # drop. Surface it as a distinct unreadable state + log.
            log.error(
                "Outbound webhook secret unreadable — corrupt row or "
                "master-key mismatch; HMAC-signed deliveries are being "
                "dropped. Check the secrets master key.",
                secret_key=outbound_target.secret_key,
            )
            outbound_secret_set = True
            outbound_secret_unreadable = True
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
        }
        webhook_counters_lifetime = (
            _be.fetch("webhooks") if _be is not None else {}
        )
    except Exception:
        redis_cache_counters_lifetime = {}
        embedding_counters_lifetime = {}
        webhook_counters_lifetime = {}
    # Known event-type catalogue rendered as checkboxes. Sourced from
    # the ONE outbound-event registry (`_KNOWN_OUTBOUND_EVENTS` below) —
    # a new event type added to the registry surfaces automatically
    # here + in the preview sample dropdown + in the preview endpoint's
    # sample envelope table (Prime Directive #5, no mirrored predicate
    # lists — SME-panel 2026-07-15 DA PD-N-CIDI fold).
    known_events = [
        (entry["name"], entry["label"], entry["desc"])
        for entry in _KNOWN_OUTBOUND_EVENTS
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
        "outbound_secret_unreadable": outbound_secret_unreadable,
        "outbound_events_subscribed": (
            set(outbound_target.events) if outbound_target else set()
        ),
        "outbound_event_catalogue": known_events,
        # Drive C — per-target body-templating wizard (v0.2.0 headline
        # release-blocking, N-419 §4.35). The dropdown surfaces the 5
        # built-in target-type shapes (Slack + PagerDuty + Opsgenie +
        # Discord + Teams) + a "Custom" passthrough; the textarea
        # exposes the raw operator template for advanced edits.
        "outbound_target_types": _build_outbound_target_type_options(),
        "outbound_selected_target_type": (
            getattr(outbound_target, "target_type", "custom") or "custom"
            if outbound_target else "custom"
        ),
        "outbound_body_template": (
            getattr(outbound_target, "body_template", None) or ""
            if outbound_target else ""
        ),
        "outbound_account_id": (
            getattr(outbound_target, "account_id", None) or ""
            if outbound_target else ""
        ),
        "webhooks_allow_external": webhooks_allow_external,
        "web_search_searxng_url": web_search_searxng_url,
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
        "err": read_flash(request)[1] or "",
        #  — flush button result. ``flushed`` is the int count
        # when the previous POST succeeded; ``flush_err`` is the
        # human-readable error string when it failed.
        # N-282 R29: route through the `_safe_int` SSOT (was walrus-
        # inside-IfExp with an `.isdigit()` gate — safe today but drift-
        # risky; the SSOT owns the parse-with-fallback contract).
        "flushed": _safe_int(request.query_params.get("flushed"), default=None),
        "flush_err": request.query_params.get("flush_err") or "",
        # 2026-05-13 — lifetime-counter reset result (admin button).
        "reset_ok": request.query_params.get("reset_ok") or "",
        "reset_err": request.query_params.get("reset_err") or "",
    }


# ---------------------------------------------------------------------------
# Outbound-webhook body-template LIVE PREVIEW (task )
# ---------------------------------------------------------------------------
#
# The preview reuses the exact ``render_for_target`` SSOT that fires
# production emit (Prime Directive #1: SSOT reuse over mirrored logic).
# Task  decision: server-side render via HTMX — NOT a client-side
# Mustache/Handlebars lib. Rationale: our server-side renderer is
# substitution-only (no sections, no logic, no helpers); a real
# Mustache/Handlebars client would let an operator craft a template
# that renders in preview but strips/breaks on the wire — a WYSIWYG
# divergence trap. HTMX pipes bytes-for-bytes what production emits.
#
# Sample envelopes are canned demo strings only — no real PHI, no
# real endpoint credentials. The preview endpoint refuses the same
# ``{{secret}}`` shape parse-time refuses so preview matches production
# behavior (SME-panel 2026-07-15 DA-F1 belt+suspenders posture).

# SME-panel 2026-07-15 DA PD-N-CIDI fold — the outbound-event registry
# is ONE list of dicts. Adding an event = one entry here. Consumers:
# * ``build_integrations_context.known_events`` — event checkbox list.
# * ``_PREVIEW_SAMPLE_ENVELOPES`` — preview sample-event dropdown +
#   sample envelope table for the wizard live preview (task ).
# Two-list drift (checkbox-only event silently rendering an unrelated
# sample envelope in preview) is prevented by construction.
_DEMO_ENVELOPE_DATA: dict[str, Any] = {
    "flow_id": "flow-DEMO-abc123",
    "category": "sample-category",
    "subject": "Sample subject line",
    "sender": "sample-sender@example.com",
    "summary": "Sample triage summary.",
    "pd_routing_key": "SAMPLE-PD-ROUTING-KEY",
    "timestamp": "2026-01-15T14:29:58Z",
}

_KNOWN_OUTBOUND_EVENTS: list[dict[str, Any]] = [
    {
        "name": "triage.completed",
        "label": "Triage completed",
        "desc": (
            "Fires after a triage run finishes. Carries run_id, account_id, "
            "account_name, query, total_messages, results_count, errors_count, "
            "elapsed_secs, trigger. No message content (no sender, no subject, "
            "no body), in any mode. HIPAA-flagged accounts hard-skip emit "
            "even before the dispatcher gate."
        ),
    },
    {
        "name": "flow.classified",
        "label": "Flow classified",
        "desc": (
            "Fires when the classifier returns a category. Pre-route firing — "
            "used for downstream consumers that want raw classifier output. "
            "Metadata-only payload."
        ),
    },
]

_PREVIEW_SAMPLE_ENVELOPES: dict[str, dict[str, Any]] = {
    entry["name"]: {
        "event": entry["name"],
        "timestamp": "2026-01-15T14:30:00Z",
        "data": dict(_DEMO_ENVELOPE_DATA),
    }
    for entry in _KNOWN_OUTBOUND_EVENTS
}


class _PreviewTarget:
    """Duck-typed :class:`WebhookTarget` for the preview render path.

    ``render_for_target`` reads ``target_type`` + ``body_template``
    only — a full :class:`WebhookTarget` construction would drag URL
    validation into the preview path, but preview does not fire the
    wire so URL is not relevant. Keep the seam narrow.
    """
    __slots__ = ("target_type", "body_template", "url")

    def __init__(self, target_type: str, body_template: str | None):
        self.target_type = target_type
        self.body_template = body_template
        self.url = ""  # HIPAA-lock netloc log path is bypassed on preview


# SME-panel 2026-07-15 DA PD-N-operator-mistake fold (task  close-
# out; the backlog row 415 folded same-drive per feedback_dont_over_defer):
# static-scan the operator template's ``{{path.to.field}}`` bindings and
# compare against the target-type's ``required_fields`` list — surface
# missing bindings inline so the operator sees "your template does not
# reference: pd_routing_key" at wizard-write time instead of at first
# prod fire (where RequiredFieldMissing fail-closes the delivery). Only
# meaningful for an operator OVERRIDE — the built-in default templates
# reference every required field by design.
import re as _re_preview
_PATH_BINDING_RE = _re_preview.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _unreferenced_required_fields(
    body_template: str, target_type: str,
) -> list[str]:
    """Return the ``data.<name>`` required fields the operator template
    does NOT reference. Returns ``[]`` when no override is present (the
    default template references every required field by construction).
    """
    if not body_template:
        return []
    from email_triage.web._webhook_target_types import TARGET_TYPES
    entry = TARGET_TYPES.get(target_type) or {}
    required = list(entry.get("required_fields") or [])
    if not required:
        return []
    referenced_paths = {
        m.group(1) for m in _PATH_BINDING_RE.finditer(body_template)
    }
    return [
        name for name in required
        if f"data.{name}" not in referenced_paths
    ]


async def _resolve_live_envelope(
    request: Request, user: dict, form_account_id: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    """The wizard target's last real envelope, or ``(None, banner text)``.

    Punch 414. Order: look up the stored envelope, run the read-side HIPAA gate
    (:func:`live_refusal_reason`), witness the render, only then hand the
    envelope back. Every refusal returns ``None`` so the caller renders the
    canned envelope; a failed witness is a refusal too (PD#8, no witness, no
    live view). The scopes handed to the gate are the one stored with the
    envelope, the saved target's, and the client-supplied form value: the
    strictest wins, and each is intersected with the requester's manageable set
    inside the gate (PD#9).
    """
    from email_triage._int_utils import parse_int_or_none
    from email_triage.db.audit import record_webhook_preview_live_render
    from email_triage.web._audit import safe_audit_write_async
    from email_triage.web._webhook_live_envelope import (
        live_refusal_reason,
        webhook_target_identity,
    )

    config = _get_config(request)
    store = getattr(request.app.state, "last_envelope_per_target", None)
    if store is None or not config.webhooks:
        return None, "No live event yet: no outbound webhook target is configured."
    entry = store.last_fire(0)
    if entry is None:
        return None, (
            "No live event yet: this target has not fired since the server "
            "last started. Showing the canned demo."
        )
    envelope = entry["envelope"]
    db = _get_db(request)
    # A scope of None or "" is a WILDCARD target; a form that omits the field
    # adds no scope of its own (the stored and saved scopes still apply).
    scopes = [
        entry.get("account_id"),
        getattr(config.webhooks[0], "account_id", None),
    ]
    if form_account_id is not None:
        scopes.append(str(form_account_id))
    # PD#9 + punch 414: the gate also gets the account the stored fire itself
    # carried (a wildcard target's own scope says nothing about it) and the
    # identity of the target it fired at, which must be the one configured now.
    reason = await db_call(
        live_refusal_reason, db, user, scopes, envelope,
        fire_account_id=entry.get("fire_account_id"),
        stored_target=entry.get("target_identity"),
        current_target=webhook_target_identity(config.webhooks[0]),
    )
    if reason:
        return None, f"Live mode unavailable: {reason}. Showing the canned demo."
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    # The audit SSOT runs the write, logs a failure for /health's drift counter
    # and returns None; here that None is also a refusal (PD#8, no witness, no
    # live view).
    witness = await safe_audit_write_async(
        lambda: db_call(
            record_webhook_preview_live_render, db,
            actor_user_id=user["id"],
            account_id=parse_int_or_none(data.get("account_id")),
            envelope_flow_id=(
                str(data["flow_id"]) if data.get("flow_id") is not None else None
            ),
        ),
        description="webhook_preview_live_render",
        table="access_log",
        emitter="record_webhook_preview_live_render",
    )
    if witness is None:
        return None, (
            "Live mode unavailable: the access could not be recorded. "
            "Showing the canned demo."
        )
    return envelope, None


@router.post(
    "/admin/integrations/webhook-preview", response_class=HTMLResponse,
)
async def admin_integrations_webhook_preview(request: Request):
    """Render a live preview of the outbound-webhook wire body.

    Task . Consumed by the wizard on
    ``admin/config_tabs/integrations.html`` — HTMX triggers on
    target-type change, sample-event change, and body-template
    keyup-changed. Returns an HTML fragment carrying two ``<pre>``
    blocks (normal + HIPAA-locked shape). Admin-gated.

    The ``{{secret}}`` refusal here mirrors the parse-time refusal in
    ``config._parse_webhooks`` + the wizard-save refusal in
    ``admin_integrations_save`` — three places, one contract (belt +
    suspenders + suspenders' backup so an operator sees the same
    refusal at preview time, save time, and load time).
    """
    user, err = await db_call(_require_admin, request)
    if err:
        return err

    from email_triage.web._webhook_target_types import VALID_TARGET_TYPES
    from email_triage.web._webhook_template import (
        RequiredFieldMissing,
        refuses_secret_binding,
        render_for_target,
    )

    form = await request.form()
    target_type_raw = (form.get("target_type") or "custom").strip()
    target_type = (
        target_type_raw if target_type_raw in VALID_TARGET_TYPES else "custom"
    )
    body_template_raw = form.get("body_template")
    body_template = (
        str(body_template_raw).strip() if body_template_raw is not None else ""
    )
    # SME-panel 2026-07-15 DA PD-N-honesty fold — echo the RESOLVED
    # sample_event key, not the raw form value. A bogus form key would
    # otherwise display "sample event: <bogus>" while rendering
    # triage.completed bytes — record ≠ HEAD-reality (feedback_just_be_honest).
    sample_event_raw = (form.get("sample_event") or "triage.completed").strip()
    sample_event = (
        sample_event_raw if sample_event_raw in _PREVIEW_SAMPLE_ENVELOPES
        else "triage.completed"
    )
    envelope = _PREVIEW_SAMPLE_ENVELOPES[sample_event]

    # Punch 414 (spec DEC-5): ``mode=live`` swaps the canned envelope for the
    # target's last real fire, behind the read-side HIPAA gate. Any refusal
    # falls back to the canned envelope above, with the reason as a banner;
    # the stored envelope never reaches the fragment context on a refusal.
    preview_mode = "canned"
    live_notice: str | None = None
    if (form.get("mode") or "").strip() == "live":
        live_envelope, live_notice = await _resolve_live_envelope(
            request, user, form.get("account_id"),
        )
        if live_envelope is not None:
            envelope = live_envelope
            preview_mode = "live"
            sample_event = str(live_envelope.get("event") or sample_event)

    # SME-panel 2026-07-15 DA PD-5 fold — delegate to the ``{{secret}}``
    # refusal SSOT at ``web/_webhook_template.refuses_secret_binding``.
    # Three sites (parse / wizard-save / wizard-preview) route through
    # ONE regex + one message. A future tightening lands in the SSOT and
    # every site inherits (Prime Directive #5, no mirrored predicates).
    tmpl_effective = body_template
    template_error = refuses_secret_binding(body_template) if body_template else None
    if template_error:
        tmpl_effective = ""

    preview_target = _PreviewTarget(
        target_type=target_type,
        body_template=tmpl_effective or None,
    )

    # Normal (non-HIPAA) render — may raise RequiredFieldMissing when
    # a typed target's required_fields list is not all populated in
    # the sample envelope (the sample carries every field so this only
    # trips if the operator swaps target-type dropdowns to a type not
    # present in _PREVIEW_SAMPLE_ENVELOPES.data — a defensive branch).
    normal_body: str | None
    normal_error: str | None = None
    try:
        _bytes = render_for_target(
            envelope, preview_target, is_hipaa=False, resolved_secret="",
        )
        normal_body = _bytes.decode("utf-8", errors="replace")
    except RequiredFieldMissing as e:
        normal_body = None
        normal_error = str(e)

    # SME-panel 2026-07-15 DA PD-1 fold — HIPAA-preview MUST route through
    # ``render_for_target(is_hipaa=True, _suppress_audit_log=True)``, not
    # the sibling ``_hipaa_locked_bytes`` directly. Rationale: the whole
    # Task  WYSIWYG guarantee is "preview bytes == production emit
    # bytes"; a future addition to the HIPAA branch of
    # ``render_for_target`` (canary field, tighter scrub, added trace)
    # must reach preview transparently. The ``_suppress_audit_log`` opt-
    # in kwarg (leading underscore = "opt in only if you're sure") skips
    # the INFO log so wizard keystrokes don't drown genuine emit-time
    # enforcement signal — the render remains bytes-equal.
    hipaa_bytes = render_for_target(
        envelope, preview_target, is_hipaa=True, resolved_secret="",
        _suppress_audit_log=True,
    )
    hipaa_body = hipaa_bytes.decode("utf-8", errors="replace")

    return await _render(
        request,
        "admin/config_tabs/_webhook_preview_fragment.html",
        {
            "sample_event": sample_event,
            "preview_mode": preview_mode,
            "live_notice": live_notice,
            "target_type": target_type,
            "template_used": tmpl_effective,
            "template_error": template_error,
            "normal_body": normal_body,
            "normal_error": normal_error,
            "hipaa_body": hipaa_body,
            "unreferenced_required": _unreferenced_required_fields(
                tmpl_effective, target_type,
            ),
        },
    )


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
    user, err = await db_call(_require_admin, request)
    if err:
        return err

    config = _get_config(request)
    form = await request.form()

    # ASYNC-DB: this handler's persistence is YAML write +
    # ``secrets.set()`` calls. ``secrets`` is a ``DbSecrets`` wrapper,
    # NOT a ``web/db.py`` helper or a raw ``db.execute`` — it is out of
    # the  (web/db.py + db.execute) migration boundary and is left
    # on the loop deliberately. A follow-up could route DbSecrets
    # through ``db_call`` if its connection-sharing is confirmed.

    def _clean_url(s: str) -> str:
        s = (s or "").strip().rstrip("/")
        return s

    config.push.public_url = _clean_url(form.get("public_url", ""))
    config.push.gmail_topic_name = (form.get("gmail_topic_name", "") or "").strip()
    from email_triage.mail_headers import canonical_email  # N-346 partial 5 R31
    config.push.gmail_subscription_sa_email = canonical_email(
        form.get("gmail_subscription_sa_email", "") or ""
    )
    # Audience defaults to public_url when blank -- explicit empty
    # string is a valid choice (the webhook validator falls back to
    # public_url if audience is empty).
    config.push.gmail_audience = _clean_url(form.get("gmail_audience", ""))

    # ── Google + Office 365 install-level OAuth credentials ──
    # Moved from /config/save to here on 2026-05-10 so every integration
    # setting lives on one admin page. Every credential write routes through
    # the _secret_write SSOT after the 2026-06-08 silent-clobber incident:
    # saving an unrelated setting (the SearXNG URL) on this bundled form
    # blanked the Web client id (an UNCONDITIONAL id write from an emptied
    # field) and let a browser password-manager autofill overwrite the
    # Web/O365 client secrets (the old `if posted:` guard blocks only the
    # EMPTY case, not a non-empty autofilled value). The helpers enforce:
    #   * ids   — blank PRESERVES the stored value (no unconditional write);
    #   * secrets — blank PRESERVES; a Google secret that isn't a real
    #     GOCSPX- secret is REJECTED + surfaced (never silently stored).
    # The companion defense is the template m.secret_input/m.cred_input
    # macros (readonly-until-focus) so a manager can't autofill at load.
    secrets = _get_secrets(request)
    from email_triage.web.routers._secret_write import (
        WRITTEN,
        REJECTED,
        clear_secret,
        looks_like_google_secret,
        set_id_preserve_blank,
        set_secret_if_changed,
    )
    from email_triage.web.oauth_secret_keys import (  # census run13 #9 — OAuth key SSOT
        GOOGLE_OAUTH_WEB_CLIENT_ID, GOOGLE_OAUTH_WEB_CLIENT_SECRET,
        GOOGLE_OAUTH_DESKTOP_CLIENT_ID, GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET,
        O365_OAUTH_TENANT_ID, O365_OAUTH_CLIENT_ID, O365_OAUTH_CLIENT_SECRET,
    )
    rejected_creds: list[str] = []

    # Google — Web (push-enabled) client pair.
    config.google_oauth.web_client_id = set_id_preserve_blank(
        secrets, GOOGLE_OAUTH_WEB_CLIENT_ID,
        form.get("google_oauth_web_client_id"),
        config.google_oauth.web_client_id,
    )
    _web_sec = form.get("google_oauth_web_client_secret")
    _st = set_secret_if_changed(
        secrets, GOOGLE_OAUTH_WEB_CLIENT_SECRET, _web_sec,
        validate=looks_like_google_secret,
    )
    if _st == REJECTED:
        rejected_creds.append("Google Web client secret")
    elif _st == WRITTEN:
        config.google_oauth.web_client_secret = _web_sec

    # Google — Desktop (manual-paste) client pair.
    config.google_oauth.desktop_client_id = set_id_preserve_blank(
        secrets, GOOGLE_OAUTH_DESKTOP_CLIENT_ID,
        form.get("google_oauth_desktop_client_id"),
        config.google_oauth.desktop_client_id,
    )
    _desk_sec = form.get("google_oauth_desktop_client_secret")
    _st = set_secret_if_changed(
        secrets, GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET, _desk_sec,
        validate=looks_like_google_secret,
    )
    if _st == REJECTED:
        rejected_creds.append("Google Desktop client secret")
    elif _st == WRITTEN:
        config.google_oauth.desktop_client_secret = _desk_sec

    # ── Office 365 OAuth install-level credentials ──
    # Single Azure app registration shared across every O365 account on
    # this install. Per-account is_personal_msa flag routes tenant at
    # runtime — "common" if personal, else the install tenant_id below.
    _o365_tenant_posted = form.get("office365_oauth_tenant_id", "").strip()
    if _o365_tenant_posted.lower() == "common":
        # "common" is reserved for the per-account "Personal Microsoft
        # account" checkbox path. At the install level it is the EXPLICIT,
        # declared "clear the tenant" request (vs. a blank submit, which now
        # preserves) — so route it through clear_secret, not a value write.
        config.office365_oauth.tenant_id = ""
        clear_secret(secrets, O365_OAUTH_TENANT_ID)
    else:
        config.office365_oauth.tenant_id = set_id_preserve_blank(
            secrets, O365_OAUTH_TENANT_ID,
            _o365_tenant_posted, config.office365_oauth.tenant_id,
        )
    config.office365_oauth.client_id = set_id_preserve_blank(
        secrets, O365_OAUTH_CLIENT_ID,
        form.get("office365_oauth_client_id"),
        config.office365_oauth.client_id,
    )
    # O365 client secret has no stable prefix to validate against, so it
    # relies on the blank-preserve guard + the readonly-until-focus template
    # layer (which blocks the autofill at page load in the first place).
    _o365_sec = form.get("office365_oauth_client_secret")
    if set_secret_if_changed(
        secrets, O365_OAUTH_CLIENT_SECRET, _o365_sec,
    ) == WRITTEN:
        config.office365_oauth.client_secret = _o365_sec

    # ── Outbound webhook destination ──
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
    webhook_body_template_error: str | None = None
    # Punch 414: the preview's last-event store is keyed by target POSITION, so a
    # change to the target list (URL, scope, order, removal) must forget it.
    from email_triage.web._webhook_live_envelope import webhook_target_identity
    _identities_before = [
        webhook_target_identity(t) for t in (config.webhooks or [])
    ]
    if out_url:
        # Drive C — wizard fields for per-target body templating (task
        #  / N-419). The form now posts ``outbound_webhook_target_type``
        # (dropdown selection, one of ``VALID_TARGET_TYPES``) and
        # ``outbound_webhook_body_template`` (raw operator template, may
        # be empty = use the target-type's registered default). If the
        # form lacks the fields (e.g. pre-wizard client) we preserve the
        # prior WebhookTarget's values so a hand-edited YAML round-trips
        # transparently — closes the SME-panel DB-F2 silent-data-loss
        # regression at every wizard write, no matter which client.
        from email_triage.web._webhook_target_types import VALID_TARGET_TYPES
        _prior = config.webhooks[0] if config.webhooks else None
        _prior_type = getattr(_prior, "target_type", "custom") if _prior else "custom"
        _prior_template = getattr(_prior, "body_template", None) if _prior else None
        _prior_acct_id = getattr(_prior, "account_id", None) if _prior else None

        _form_type = (form.get("outbound_webhook_target_type") or "").strip()
        if _form_type and _form_type in VALID_TARGET_TYPES:
            target_type_value = _form_type
        else:
            target_type_value = _prior_type

        # ``outbound_webhook_body_template``: empty string means "use the
        # target-type's default"; a non-empty value is the operator's
        # override. Reject a template that references ``{{secret}}`` at
        # the wizard boundary too — the parse layer already refuses
        # this at YAML load, but catching it here surfaces the error
        # inline instead of on next restart (SME-panel DA-F1 defense-
        # in-depth).
        _form_template_raw = form.get("outbound_webhook_body_template")
        if _form_template_raw is None:
            body_template_value: str | None = _prior_template
        else:
            _form_template = str(_form_template_raw).strip()
            if not _form_template:
                body_template_value = None
            # SME-panel 2026-07-15 DA-A nit — normalize the whitespace
            # variants of ``{{ secret }}`` so the wizard refusal matches
            # the parse-time refusal (both use the same regex now).
            # HIPAA-SME F2 fold — the parse-side refusal raises
            # ``ConfigError`` at YAML-load time; the wizard-side refusal
            # here sets a local error flag (surfaced through the same
            # flash-error path as any other save-side rejection) so an
            # operator submitting a leaky template gets an inline
            # message rather than an un-scrubbed 500.
            # 2026-07-15 task  SME-panel DA PD-5 fold — the regex +
            # message now live at the ONE SSOT
            # ``web/_webhook_template.refuses_secret_binding``. Three
            # sites (parse / wizard-save / wizard-preview) delegate.
            elif (
                _refusal := __import__(
                    "email_triage.web._webhook_template",
                    fromlist=["refuses_secret_binding"],
                ).refuses_secret_binding(_form_template)
            ) is not None:
                webhook_body_template_error = _refusal
                # Preserve the prior value so a partial save doesn't
                # nuke a previously-valid template on a bad edit.
                body_template_value = _prior_template
            else:
                body_template_value = _form_template

        # DA-F3b Drive-C follow-on (task ): the wizard now surfaces
        # the ``account_id`` field as an advanced text input. Empty =
        # wildcard (matches every account, backward-compat default);
        # a specific id closes the cross-account fanning class for
        # this target. Falls back to ``_prior_acct_id`` when the form
        # key is absent (pre-Drive-C clients) so YAML-edited scopes
        # aren't nuked by an admin save.
        _form_acct_raw = form.get("outbound_webhook_account_id")
        if _form_acct_raw is None:
            account_id_value = _prior_acct_id
        else:
            _form_acct = str(_form_acct_raw).strip()
            account_id_value = _form_acct if _form_acct else None

        # Build / refresh the single canonical target.
        config.webhooks = [
            WebhookTarget(
                url=out_url,
                events=selected_events,
                secret_key=secret_key_name,
                target_type=target_type_value,
                body_template=body_template_value,
                account_id=account_id_value,
            )
        ]
    else:
        # Empty URL clears the destination entirely.
        config.webhooks = []
    if [webhook_target_identity(t) for t in config.webhooks] != _identities_before:
        _live_store = getattr(request.app.state, "last_envelope_per_target", None)
        if _live_store is not None:
            _live_store.clear()
    config.webhooks_allow_external = "webhooks_allow_external" in form
    # Secret is mask-preserve: blank submit keeps the stored value; an
    # autofilled value can't slip in because the field is readonly-until-focus
    # (m.secret_input). Routes through the SSOT like every other secret write.
    set_secret_if_changed(
        secrets, secret_key_name, form.get("outbound_webhook_secret"),
    )

    # ──  Internet Search — optional self-hosted SearXNG host ──
    # Empty = OFF (the Topic editor then offers registry-number lookups
    # only). Persisted in the settings table (off the loop via db_call).
    from email_triage.web.db import set_web_search_searxng_url
    _ws_url = (form.get("web_search_searxng_url", "") or "").strip().rstrip("/")
    await db_call(set_web_search_searxng_url, _get_db(request), _ws_url)

    # ──  — Classification cache (optional Redis) ──
    # URL empty = OFF (default). TTL clamped to the supported window
    # [3600, 7_776_000] = 1 hour to 90 days; anything outside snaps
    # to the nearest bound rather than rejecting the save.
    from email_triage.config import RedisCacheConfig
    from email_triage.cache.classification import (
        build_cache_from_config, clamp_ttl_secs,
        set_install_classification_cache,
    )
    #  — the request-int SSOT (function-local import: avoids a module-top
    # dependency from this sibling router onto the ui._shared package).
    rc_url = (form.get("redis_cache_url", "") or "").strip()
    rc_ttl = clamp_ttl_secs(form.get("redis_cache_ttl_secs"))
    # 2026-05-13 two-level cache knobs. Out-of-range / non-numeric
    # falls back to the default (now via _safe_int, never a 500).
    rc_inner_cap = max(
        1, min(10000, _safe_int(form.get("redis_cache_inner_cap"), 250)),
    )
    rc_strategy = (
        form.get("redis_cache_hint_strategy") or "top_k_with_freq"
    ).strip().lower()
    if rc_strategy not in ("top_k_with_freq", "top_1_dominant"):
        rc_strategy = "top_k_with_freq"
    rc_dom_pct = max(
        50, min(100, _safe_int(form.get("redis_cache_dom_pct"), 70)),
    )
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
        #  tail — same class as admin.py:830/1304/1448 (raw
        # exception __str__ echoing to URL-query flash message). Route
        # through scrub_exc so PHI/secret shapes cannot leak.
        save_error = f"YAML write failed: {scrub_exc(e, purpose='form')}"
        log.error("Integrations YAML write failed", error=fmt_exc(e))

    # SME-panel 2026-07-15 HIPAA F2 fold — surface the wizard-side
    # ``{{secret}}`` refusal through the flash-error path so the
    # operator sees an inline message instead of an un-scrubbed 500.
    # The other settings still save; only the offending body_template
    # was preserved-at-prior. Take precedence over YAML write failures
    # because a ``{{secret}}`` body IS the reason to refuse this save.
    if webhook_body_template_error and not save_error:
        save_error = webhook_body_template_error

    # Surface any REJECTED credential (a posted secret that didn't look valid)
    # so the operator knows it was NOT stored — never silent. The other
    # settings still saved; this is the one credential that needs re-entry.
    if not save_error and rejected_creds:
        save_error = (
            f"{', '.join(rejected_creds)} not saved — the value didn't look "
            "like a valid Google client secret (these start with GOCSPX-). "
            "Re-enter it; other settings were saved."
        )

    log.info(
        "Push config saved",
        actor=user["email"],
        public_url=config.push.public_url,
        topic=config.push.gmail_topic_name,
        rejected_creds=len(rejected_creds),
    )

    qs = "saved=1" if not save_error else err_qs(save_error[:200])
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
    user, err = await db_call(_require_admin, request)
    if err:
        if isinstance(err, RedirectResponse):
            return api_error_response("auth_required", status_code=401, purpose="misc")
        return api_error_response("forbidden", status_code=403, purpose="misc")

    db = _get_db(request)
    config = _get_config(request)
    secrets = _get_secrets(request)

    topic = config.push.gmail_topic_name
    if not topic:
        return api_error_response(
            "topic_unset", status_code=400, purpose="misc",
            extra={"message": "Set push.gmail_topic_name first."},
        )

    from email_triage.web.db import get_email_account, upsert_gmail_watch
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account

    # ASYNC-DB: account read off the loop.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return api_error_response("account_not_found", status_code=404, purpose="misc")
    if acct.get("provider_type") != "gmail_api":
        return api_error_response(
            "not_gmail", status_code=400, purpose="misc",
            extra={"message": "Account is not a Gmail API account."},
        )

    # Resolve email_address. The email_accounts table stores it inside
    # config_json["account"], not as a top-level column. Prefer the
    # live profile (canonical source) and fall back to config so a
    # transient API-down doesn't lose the field. The synthetic poll-
    # mode placeholder rows stamped by the unified-poll-loop already
    # carry the right email, so we also fall back to whatever's there.
    cfg_email = (acct.get("config") or {}).get("account", "")
    profile_email = ""
    from email_triage.web.app import record_provider_outcome
    try:
        provider = _create_provider_from_account(acct, secrets)
        if not isinstance(provider, GmailApiProvider):
            return api_error_response(
                "provider_build_failed", status_code=500, purpose="misc",
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
            except Exception as _swallow_exc:
                log.debug(
                    "provider/probe close failed (best-effort teardown)",
                    error=fmt_exc(_swallow_exc),
                )
    except Exception as e:
        log.error(
            "Manual watch renewal failed",
            account_id=account_id, error=fmt_exc(e),
        )
        # #5 (census 2026-06-10) — a manual force-renew failing on a dead
        # credential routes through the auth_stale funnel (SET iff the error
        # is an auth-revoked signal; a transient API error is needle-filtered).
        # get_profile above fails non-fatally; register_watch is the auth edge.
        await db_call(record_provider_outcome, db, acct, e)
        # Census run23 #1 — mirror the gmail_watches lifecycle SSOT SET
        # half so the row flips to 'errored' immediately on the failed
        # force-renew instead of staying 'active' until the next renewer
        # sweep. Success branch already CLEARs broadly at :1204.
        try:
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=account_id, error_text=fmt_exc(e),
            )
        except Exception as watch_exc:
            log.error(
                "gmail_watches errored-status write failed on force renew",
                account_id=account_id, exc_info=watch_exc,
            )
        return api_error_response(
            "renew_failed", status_code=500, purpose="misc",
            extra={"message": scrub_exc(e, purpose="provider")},
        )

    # register_watch succeeded → the credential is alive → CLEAR any stale
    # auth_stale chip NOW, before the email-resolution branch below. Placing
    # the clear here (not after the upsert) keeps the CLEAR edge as broad as
    # the success: an account whose watch registers but whose email field is
    # unmigrated still must not stay stuck on the chip (DA MUST-FIX #1, #5 —
    # the clear-narrow asymmetry this fix exists to kill). Mirrors push.py's
    # Gmail Start-Push which clears immediately after register_watch.
    await db_call(record_provider_outcome, db, acct, None)

    from datetime import timedelta
    # /run18 : ``data`` is the Gmail register_watch API RESPONSE — a
    # malformed ``expiration`` must not 500 (external-API robustness). Coerce via
    # the _safe_int SSOT, not a bare int().
    exp_ms = _safe_int(data.get("expiration"), 0)
    now = datetime.now(timezone.utc)
    exp_iso = (
        to_utc_iso(datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc))
        if exp_ms else to_utc_iso(now + timedelta(days=7))
    )
    history_id = str(data.get("historyId") or "")

    # Fall back through profile -> config -> existing watch row, in that
    # order. Existing-watch fallback covers the case where get_profile
    # transiently fails AND the account row was saved before the
    # email/account field migration.
    from email_triage.web.db import get_gmail_watch
    # ASYNC-DB: existing-watch read off the loop.
    existing = await db_call(get_gmail_watch, db, account_id)
    existing_email = (existing or {}).get("email_address") or ""
    email_address = profile_email or cfg_email or existing_email
    if not email_address:
        return api_error_response(
            "missing_email_address", status_code=400, purpose="misc",
            extra={"message": "Could not resolve the Gmail address for this "
                              "account. Re-save the account or re-authenticate."},
        )

    # ASYNC-DB: gmail_watches upsert off the loop.
    await db_call(
        upsert_gmail_watch,
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
#  — Classification cache flush
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
    user, err = await db_call(_require_admin, request)
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
        #  — flush_all does a SCAN cursor loop + batched DELETEs
        # on the sync Redis client; dispatched off the event loop so
        # an admin flush doesn't stall every other in-flight request.
        deleted = await cache.aflush_all()
    except Exception as e:
        #  tail — Redis flush failures may echo credential fragments
        # from the driver's error path; scrub before URL-embedding.
        log.error("Classification cache flush failed", error=fmt_exc(e))
        msg = scrub_exc(e, purpose="form")[:120]
        return RedirectResponse(
            f"/admin/integrations?{qs(flush_err=msg)}",
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

    ``embedding:fallback`` is a LEGACY namespace: nothing writes it since
    punch 552 / N-555 removed the fallback chain, and it stays resettable
    only so an operator can clear the count persisted before that.

    Admin-only + CSRF-protected.
    """
    user, err = await db_call(_require_admin, request)
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
        #  tail — same class as :923 (URL-embedded flash message).
        log.error("Lifetime counter reset failed", error=fmt_exc(e))
        msg = scrub_exc(e, purpose="form")[:120]
        return RedirectResponse(
            f"/admin/integrations?{qs(reset_err=msg)}",
            status_code=303,
        )

    log.info(
        "Lifetime counters reset via admin action",
        actor=user["email"],
        namespace=namespace,
        keys_deleted=deleted,
    )
    return RedirectResponse(
        f"/admin/integrations?{qs(reset_ok=namespace)}",
        status_code=303,
    )
