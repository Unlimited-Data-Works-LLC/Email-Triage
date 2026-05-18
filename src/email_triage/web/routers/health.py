"""Unauthenticated liveness/health endpoint.

Exposes ``GET /health`` for container HEALTHCHECK probes and external
monitoring.  Deliberately unauthenticated and minimal — kept cheap
enough to poll every 30 s.

Motivation: using ``/login`` as a liveness signal conflates the auth
surface with the probe surface (NERC CIP-007-R4 — audit-surface
separation).  This endpoint replaces that pattern.

Status semantics:
    - ``ok``        — all subsystems healthy
    - ``degraded``  — at least one subsystem is unhealthy but the app
                      process is still serving (any watcher disconnected
                      > 15 min, DB ping fails, or ``last_triage`` is
                      > 24 h old on an account with an active watcher)

The endpoint NEVER returns 5xx for a degraded state — it always returns
200 with a payload that describes the state.  The HEALTHCHECK probe
can decide whether to trust 200 alone or to also inspect ``status``.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Request

from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import get_current_user as _get_current_user

logger = logging.getLogger("email_triage.web.health")

router = APIRouter()


_STALE_WATCHER_SECONDS = 15 * 60   # 15 minutes
_STALE_TRIAGE_SECONDS = 24 * 60 * 60  # 24 hours


def _db_ok(db) -> bool:
    """Cheap SQLite ping — SELECT 1."""
    try:
        cur = db.execute("SELECT 1")
        row = cur.fetchone()
        return row is not None
    except Exception:
        return False


def _last_triage_iso(db) -> str | None:
    """Return the most recent ``triage_runs.created_at`` value as an ISO
    string in the container's local timezone.

    The DB column stores UTC (written via ``datetime.now(timezone.utc)``).
    We convert to the container's effective local tz via ``.astimezone()``
    — which honors the ``TZ`` env var the container sets at boot (quadlet
    sets ``TZ=America/Detroit``). Result shape is the same ISO-with-offset
    format Python's ``isoformat()`` produces, just with a real offset like
    ``-04:00`` / ``-05:00`` instead of ``+00:00``. Matches operator
    expectation and the TZ-aware log formatter shipped in wave 1 (#3).
    """
    try:
        row = db.execute(
            "SELECT MAX(created_at) AS last_created FROM triage_runs"
        ).fetchone()
        if row is None:
            return None
        # Support both sqlite3.Row and plain tuple rows.
        try:
            val = row["last_created"]
        except (IndexError, KeyError, TypeError):
            val = row[0]
        if not val:
            return None
        # Convert stored UTC string to the container's local tz.
        try:
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone().isoformat()
        except (TypeError, ValueError):
            # Unparseable — fall back to raw string so the endpoint
            # still reports something rather than None.
            return val
    except Exception:
        return None


def _parse_iso(val: str | None) -> datetime | None:
    if not val:
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _watcher_counts(watcher_mgr) -> tuple[int, int, bool]:
    """Return (total, connected, any_stale) — IMAP-IDLE accounts only.

    ``connected`` counts watchers whose state is ``watching``.
    ``any_stale`` is True if any watcher has been disconnected
    (not ``watching``) for more than 15 minutes, judged by its
    ``started_at`` field — UNLESS the same account is enrolled in
    the poll loop, in which case poll is the safety net and a
    dropped IDLE socket is not by itself "degraded".
    """
    if watcher_mgr is None:
        return 0, 0, False
    try:
        statuses = watcher_mgr.all_statuses()
    except Exception:
        return 0, 0, False

    total = len(statuses)
    connected = 0
    any_stale = False
    now = datetime.now(timezone.utc)

    for acct_id, state in statuses.items():
        status = (state or {}).get("status", "")
        if status == "watching":
            connected += 1
            continue
        started_at = _parse_iso((state or {}).get("started_at"))
        if started_at is None:
            continue
        if (now - started_at).total_seconds() <= _STALE_WATCHER_SECONDS:
            continue
        # IDLE has been down > 15 min. Stale only if no poll fallback.
        try:
            if watcher_mgr.is_poll_running(acct_id):
                continue
        except Exception:
            pass
        any_stale = True

    return total, connected, any_stale


def _gmail_push_counts(db, watcher_mgr) -> tuple[int, int, bool]:
    """Return ``(total, healthy, any_stale)`` for Gmail Pub/Sub watches.

    ``healthy`` = row exists AND ``expires_at`` is in the future.

    ``any_stale`` is True only when a watch is expired AND the same
    account is NOT enrolled in the poll loop. Poll covers Gmail too
    (history-id delta on each tick) so an expired Pub/Sub watch with
    poll-fallback is not degraded — push was preferred but the safety
    net is doing its job. Without this check, every install that
    skipped Pub/Sub setup but kept poll enabled would read degraded.
    """
    if db is None:
        return 0, 0, False
    try:
        from email_triage.web.db import list_gmail_watches
        rows = list_gmail_watches(db)
    except Exception:
        return 0, 0, False

    total = len(rows)
    healthy = 0
    any_stale = False
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=_STALE_WATCHER_SECONDS)
    for r in rows:
        exp = _parse_iso(r.get("expires_at"))
        is_healthy = exp is not None and exp > now
        if is_healthy:
            healthy += 1
            continue
        # Expired or invalid. Stale only if no poll fallback.
        try:
            if watcher_mgr is not None and watcher_mgr.is_poll_running(
                r.get("account_id")
            ):
                continue
        except Exception:
            pass
        if exp is None or exp < cutoff:
            any_stale = True
    return total, healthy, any_stale


def _office365_push_counts(db, watcher_mgr) -> dict[str, int]:
    """Return aggregate counts for the O365 Graph subscription table.

    Shape mirrors the operator-facing /health payload and the daily
    digest: ``accounts_with_active_subscriptions`` (subscription_id
    set, status='active', expiration_at in the future),
    ``expiring_in_24h`` (active but expiring within 24h),
    ``errored`` (status='errored' OR expiration_at past).

    Empty dict on read failure — never raises.
    """
    out = {
        "total": 0,
        "accounts_with_active_subscriptions": 0,
        "expiring_in_24h": 0,
        "errored": 0,
    }
    if db is None:
        return out
    try:
        from email_triage.web.db import list_o365_subscriptions
        rows = list_o365_subscriptions(db)
    except Exception:
        return out

    out["total"] = len(rows)
    now = datetime.now(timezone.utc)
    soon = now + timedelta(hours=24)
    for r in rows:
        status = (r.get("status") or "").strip()
        exp = _parse_iso(r.get("expiration_at"))
        if status == "errored":
            out["errored"] += 1
            continue
        if exp is None:
            out["errored"] += 1
            continue
        if exp <= now:
            out["errored"] += 1
            continue
        out["accounts_with_active_subscriptions"] += 1
        if exp <= soon:
            out["expiring_in_24h"] += 1
    return out


def _mailbox_counts(watcher_mgr) -> tuple[int, int]:
    """Return ``(total, watching)`` per-mailbox. Each IMAP mailbox = one
    IDLE socket. A 4-folder account contributes 4 to ``total``."""
    if watcher_mgr is None:
        return 0, 0
    try:
        return watcher_mgr.mailbox_counts()
    except Exception:
        return 0, 0


def _poll_counts(watcher_mgr) -> tuple[int, int]:
    """Return ``(registered, fresh)`` for the unified poll loop. Covers
    every provider type (IMAP, Gmail, O365) — the poll runs regardless
    of push state and is the safety net when push drops."""
    if watcher_mgr is None:
        return 0, 0
    try:
        return watcher_mgr.poll_counts()
    except Exception:
        return 0, 0


def _last_triage_stale(last_triage: datetime | None, connected: int) -> bool:
    """True if we have at least one connected watcher AND the most
    recent triage_runs row is older than 24 h.

    No connected watcher means "nothing is supposed to be firing
    triage runs" — silence is expected, not degraded.
    """
    if connected <= 0:
        return False
    if last_triage is None:
        # Connected watcher exists but there has never been a triage
        # run — could be a fresh install.  Treat as not stale; the
        # first run will tick the clock.
        return False
    age = (datetime.now(timezone.utc) - last_triage).total_seconds()
    return age > _STALE_TRIAGE_SECONDS


def _aggregate_account_states(account_states: list[dict]) -> dict:
    """Fold per-account records (option C: primary mode wins) into
    per-provider buckets that sum to provider total. Returns the shape
    surfaced under ``ingestion`` in /health and consumed by the chip /
    digest aggregators."""
    by_provider: dict[str, dict] = {}
    any_uncovered = False
    any_alert = False
    for s in account_states:
        prov = s.get("provider", "unknown")
        b = by_provider.setdefault(prov, {
            "total": 0, "push": 0, "poll": 0, "uncovered": 0,
            "push_plus_poll": 0,
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
        if s.get("alert"):
            any_alert = True
        if primary == "none":
            any_uncovered = True
    return {
        "providers": by_provider,
        "any_uncovered": any_uncovered,
        "any_alert": any_alert,
    }


def _compute_health_detail_sync(request: Request) -> tuple[dict[str, Any], bool]:
    """Synchronous body of the health snapshot computation.

    #135: the entire health-detail computation is a sequence of blocking
    SQLite reads + watcher-manager rollups (which themselves hit the
    DB). Wrapping the whole thing in a single ``db_call`` keeps the
    event loop free for the duration of one /health probe instead of
    bouncing between the loop and the threadpool for every individual
    SELECT. Net effect: 30s polls don't serialize behind each other.
    """
    app = request.app
    started_at = getattr(app.state, "started_at", None)
    if started_at is None:
        uptime_secs = 0
    else:
        uptime_secs = max(0, int(time.monotonic() - started_at))

    db = getattr(app.state, "db", None)
    db_ok = _db_ok(db) if db is not None else False

    watcher_mgr = getattr(app.state, "watcher_manager", None)

    # Single source of truth — every other counter is a fold over this.
    account_states: list[dict] = []
    if watcher_mgr is not None and db is not None:
        try:
            account_states = watcher_mgr.account_states(db)
        except Exception:
            account_states = []
    ingestion = _aggregate_account_states(account_states)

    # Per-provider conveniences derived from account_states.
    imap_b = ingestion["providers"].get("imap", {})
    gmail_b = ingestion["providers"].get("gmail_api", {})
    o365_b = ingestion["providers"].get("office365", {})

    # Mailbox / poll counts — process-level, not per-account.
    mb_total, mb_watching = _mailbox_counts(watcher_mgr)
    poll_registered, poll_fresh = _poll_counts(watcher_mgr)

    # O365 Graph subscription rollup (#66) — same shape as gmail_push,
    # plus the expiring-in-24h + errored counts the operator surface
    # consumes. Read straight from ``office365_subscriptions``; the
    # account-state fold above already covers per-account active/poll,
    # this is the additional renewer-health view.
    o365_push_block = _office365_push_counts(db, watcher_mgr)

    # IMAP IDLE staleness still tracked — alert if any IMAP account
    # has push_dropped_no_poll. Gmail push expiry covered the same way.
    any_alert = ingestion["any_alert"]

    # Triage-stale check fires only when at least one account is
    # actually ingesting (push primary, poll primary, or just freshly
    # polled). ``any_uncovered`` means no account has any path —
    # silence is expected, not degraded.
    any_ingesting = (
        sum(b.get("push", 0) + b.get("poll", 0)
            for b in ingestion["providers"].values())
    )
    last_triage_iso = _last_triage_iso(db) if db is not None else None
    last_triage_dt = _parse_iso(last_triage_iso)
    triage_stale = _last_triage_stale(last_triage_dt, any_ingesting)

    # PR 5 / C1 — supervisor + watcher rollups.
    supervisor = getattr(app.state, "supervisor", None)
    tasks_block: dict[str, Any] = {}
    if supervisor is not None:
        try:
            tasks_block = supervisor.health_snapshot()
        except Exception:
            tasks_block = {"_error": "snapshot_failed"}

    # Watchers in failing state past 15 min are a hard degradation
    # signal — silent loss of mail ingestion is the worst category
    # of operational failure for this product.
    WATCHER_FAILING_THRESHOLD_SECS = 15 * 60
    watchers_failing: list[dict[str, Any]] = []
    if watcher_mgr is not None:
        try:
            watchers_failing = watcher_mgr.watchers_failing_for(
                WATCHER_FAILING_THRESHOLD_SECS,
            )
        except Exception:
            watchers_failing = []

    audit_failures = int(getattr(app.state, "audit_failures", 0))
    csrf_rejects = int(getattr(app.state, "csrf_rejects", 0))

    # #151 — classification-cache counters (per-process). Empty / safe
    # defaults when the cache module isn't loaded yet (early lifespan
    # tick) so the snapshot stays robust.
    try:
        from email_triage.cache.classification import (
            get_counters as _cache_counters,
            get_install_classification_cache as _get_cls_cache,
        )
        _cc_snap = _cache_counters().snapshot()
        _cc_enabled = bool(
            (_get_cls_cache() is not None)
            and _get_cls_cache().enabled,  # type: ignore[union-attr]
        )
    except Exception:
        _cc_snap = {"hits": 0, "misses": 0, "errors": 0}
        _cc_enabled = False
    # Lifetime (Redis-persisted) counters merged in alongside the
    # process-local snapshot. ``lifetime`` is an empty dict when the
    # persistent backend isn't configured (cache URL absent) —
    # operator-facing UI renders zeros + an explanatory chip in that
    # case.
    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend,
        )
        _pc_be = get_install_counter_backend()
        _cc_lifetime = (
            _pc_be.fetch("classification_cache")
            if _pc_be is not None else {}
        )
    except Exception:
        _cc_lifetime = {}
    classification_cache_block = {
        "enabled": _cc_enabled,
        "hits": _cc_snap.get("hits", 0),
        "misses": _cc_snap.get("misses", 0),
        "errors": _cc_snap.get("errors", 0),
        # Full counter shape (process-local + lifetime).
        "hits_exact": _cc_snap.get("hits_exact", 0),
        "hits_hint_topk": _cc_snap.get("hits_hint_topk", 0),
        "hits_hint_dominant": _cc_snap.get("hits_hint_dominant", 0),
        "hits_hint_skipped": _cc_snap.get("hits_hint_skipped", 0),
        "misses_cold": _cc_snap.get("misses_cold", 0),
        "lifetime": _cc_lifetime,
    }

    # Embedding backend live metrics (#m4-status). Surfaces what's
    # actually loaded + per-call counters so the operator can tell
    # whether the in-process primary is doing the work or the
    # fallback chain has fired. Empty dict when no embedding
    # backend is configured (RAG paths off install-wide).
    embedding_block: dict[str, Any] = {"configured": False}
    _emb_be = getattr(request.app.state, "embedding_backend", None)
    if _emb_be is not None:
        try:
            metrics = (
                _emb_be.metrics() if hasattr(_emb_be, "metrics") else {}
            )
        except Exception:
            metrics = {}
        # 2026-05-13 — Redis-persisted lifetime counters per backend
        # namespace. Empty dicts when no persistent backend wired.
        # Three namespaces: primary (ollama), backup
        # (sentence_transformers), and the fallback fires count.
        try:
            from email_triage.engine.persistent_counters import (
                get_install_counter_backend,
            )
            _pc_be2 = get_install_counter_backend()
            _emb_lifetime = {
                "ollama": (
                    _pc_be2.fetch("embedding:ollama")
                    if _pc_be2 is not None else {}
                ),
                "sentence_transformers": (
                    _pc_be2.fetch("embedding:sentence_transformers")
                    if _pc_be2 is not None else {}
                ),
                "fallback": (
                    _pc_be2.fetch("embedding:fallback")
                    if _pc_be2 is not None else {}
                ),
            }
        except Exception:
            _emb_lifetime = {
                "ollama": {},
                "sentence_transformers": {},
                "fallback": {},
            }
        embedding_block = {
            "configured": True,
            "backend_type": getattr(_emb_be, "backend_type", "?"),
            "model": getattr(
                request.app.state, "embedding_model", "",
            ),
            "metrics": metrics,
            "lifetime": _emb_lifetime,
        }

    # 2026-05-13 — Webhook counter rollup. Process-local counters
    # live on ``app.state.metrics`` (incremented by the Gmail Pub/Sub +
    # Microsoft Graph receivers); lifetime mirror is in Redis under
    # namespace ``webhooks``. Both go in the same block so the
    # ``/admin/stats`` template renders process + lifetime side-by-
    # side with the union of keys.
    try:
        _wh_proc = dict(
            getattr(request.app.state, "metrics", {}) or {},
        )
    except Exception:
        _wh_proc = {}
    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend as _wh_get_pc,
        )
        _wh_pc = _wh_get_pc()
        _wh_life = (
            _wh_pc.fetch("webhooks") if _wh_pc is not None else {}
        )
    except Exception:
        _wh_life = {}
    webhooks_block = {
        "process": _wh_proc,
        "lifetime": _wh_life,
    }

    schema_version_value: int | None = None
    if db is not None:
        try:
            from email_triage.web.migrations import schema_version
            schema_version_value = schema_version(db)
        except Exception:
            schema_version_value = None

    # #125 partial follow-up — surface the same schema-compat verdict
    # the admin /config banner shows, in machine-readable form. Nagios
    # polls /health/detail and fires when ``state`` advances past
    # ``up_to_date`` (warn on ``update_available``, critical on
    # ``incompatible_rollback`` / ``downgrade_not_supported``).
    #
    # Failure-safe: ``gather_version_status`` reads the DB read-only +
    # touches the env var + reads the migrations registry. If anything
    # throws (DB path unreadable, migration registry malformed) the
    # rest of /health/detail must still render — we surface a sentinel
    # ``{"state": "unknown", "error": ...}`` and log the cause.
    #
    # The success-path JSON renames the dataclass's ``status`` field
    # to ``state`` so the failure sentinel + success rows share a key
    # for downstream consumers (Nagios scrape, deploy.sh pre-flight).
    version_status_block: dict[str, Any]
    try:
        from email_triage.version import gather_version_status
        cfg = getattr(app.state, "config", None)
        db_path = None
        if cfg is not None:
            db_path = getattr(
                getattr(cfg, "persistence", None), "db_path", None,
            )
        _vs = gather_version_status(db_path)
        _vs_dict = _vs.to_dict()
        version_status_block = {
            "app_version": _vs_dict.get("app_version"),
            "db_schema_version": _vs_dict.get("db_schema_version"),
            "target_schema_caps": _vs_dict.get("target_schema_caps"),
            "previous_schema_caps": _vs_dict.get("previous_schema_caps"),
            "state": _vs_dict.get("status"),
            "explanation": _vs_dict.get("explanation"),
        }
    except Exception as exc:  # pragma: no cover - failure-safe
        logger.warning(
            "version_status lookup failed for /health/detail: %s",
            exc, exc_info=True,
        )
        version_status_block = {
            "state": "unknown",
            "error": f"{type(exc).__name__}: {exc}",
        }

    # #152 phases 3-4 S4 follow-up — 24h counters for the HIPAA distill
    # pipeline. Sibling to ``version_status`` (and to W2-α's
    # ``baa_status`` if that lands first). Failure-safe: a missing
    # table (pre-v27 schema) returns zeros so the rest of /health/detail
    # still renders.
    style_distill_block: dict[str, Any]
    try:
        from email_triage.web.db import style_distill_event_counts
        if db is not None:
            style_distill_block = style_distill_event_counts(db)
        else:
            style_distill_block = {
                "local_24h": 0, "cloud_24h": 0,
                "failures_24h": 0, "scrubber_rejects_24h": 0,
                "total_24h": 0,
            }
    except Exception as exc:  # pragma: no cover - failure-safe
        logger.warning(
            "style_distill counters failed for /health/detail: %s",
            exc, exc_info=True,
        )
        style_distill_block = {
            "local_24h": 0, "cloud_24h": 0,
            "failures_24h": 0, "scrubber_rejects_24h": 0,
            "total_24h": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }

    # #175 R-B — per-message retry-queue rollup for Nagios polling.
    # Shape:
    #   {"pending": int, "dead_24h": int,
    #    "oldest_pending_age_sec": int|None,
    #    "dead_breakdown_24h": {"<reason>": int, ...}}
    # Failure-safe: when R-A's helpers haven't merged yet, or the
    # table is missing, surface a sentinel
    # ``{"state": "unknown", "error": ...}``. The rest of the
    # /health/detail body must still render so the deploy script's
    # /health probe doesn't go red on the unrelated retry-queue
    # subsystem.
    retry_queue_block: dict[str, Any]
    try:
        retry_queue_block = _compute_retry_queue_block(db)
    except Exception as exc:  # pragma: no cover - failure-safe
        logger.warning(
            "retry_queue rollup failed for /health/detail: %s",
            exc, exc_info=True,
        )
        retry_queue_block = {
            "state": "unknown",
            "error": f"{type(exc).__name__}: {exc}",
        }

    # An errored O365 subscription is degraded only when the account
    # isn't covered by the poll safety net. ``any_alert`` from
    # account_states already handles the per-account verdict
    # (push_dropped_no_poll / no_ingestion); _office365_push_counts
    # is purely the additional renewer-visibility surface so we don't
    # double-degrade here. Kept variable around for readability.
    _ = o365_push_block

    degraded = (
        (not db_ok)
        or any_alert
        or triage_stale
        or bool(tasks_block.get("any_quarantined"))
        or bool(watchers_failing)
    )
    status = "degraded" if degraded else "ok"

    version = getattr(app.state, "version", "unknown")

    # Legacy IMAP-IDLE-account roll-up (kept for Nagios / deploy script
    # compatibility). New consumers should read ``ingestion`` instead.
    legacy_total = imap_b.get("total", 0)
    legacy_connected = imap_b.get("push", 0)

    body: dict[str, Any] = {
        "status": status,
        "uptime_secs": uptime_secs,
        "db": "ok" if db_ok else "error",
        # New canonical shape.
        "ingestion": {
            "imap":      {
                "total":          imap_b.get("total", 0),
                "push":           imap_b.get("push", 0),
                "poll":           imap_b.get("poll", 0),
                "uncovered":      imap_b.get("uncovered", 0),
                "push_plus_poll": imap_b.get("push_plus_poll", 0),
            },
            "gmail_api": {
                "total":          gmail_b.get("total", 0),
                "push":           gmail_b.get("push", 0),
                "poll":           gmail_b.get("poll", 0),
                "uncovered":      gmail_b.get("uncovered", 0),
                "push_plus_poll": gmail_b.get("push_plus_poll", 0),
            },
            "office365": {
                "total":          o365_b.get("total", 0),
                "push":           o365_b.get("push", 0),
                "poll":           o365_b.get("poll", 0),
                "uncovered":      o365_b.get("uncovered", 0),
                "push_plus_poll": o365_b.get("push_plus_poll", 0),
            },
            "any_uncovered": ingestion["any_uncovered"],
            "any_alert":     ingestion["any_alert"],
        },
        # Process-level counters.
        "mailboxes": {"total": mb_total, "connected": mb_watching},
        "poll":      {"registered": poll_registered, "fresh": poll_fresh},
        # Backward-compat keys. Existing consumers (Nagios probe, deploy
        # script grep) read these; will be removed one release after
        # callers migrate to ``ingestion``.
        "watchers": {
            "total":     legacy_total,
            "connected": legacy_connected,
            "mailboxes": {"total": mb_total, "connected": mb_watching},
            "gmail_push": {
                "total":   gmail_b.get("total", 0),
                "healthy": gmail_b.get("push", 0),
            },
            "office365_push": o365_push_block,
            "poll": {"registered": poll_registered, "fresh": poll_fresh},
        },
        "office365_push": o365_push_block,
        "last_triage": last_triage_iso,
        "version": version,
        # PR 5 / C1 — supervisor + watcher + audit + schema rollups.
        "tasks": tasks_block,
        "watchers_failing": watchers_failing,
        "audit_failures": audit_failures,
        "csrf_rejects": csrf_rejects,
        "schema_version": schema_version_value,
        "classification_cache": classification_cache_block,
        "embedding": embedding_block,
        "webhooks": webhooks_block,
        # #125 partial follow-up — schema-compat verdict in
        # machine-readable form so Nagios can poll without scraping
        # /config. Shape mirrors ``VersionStatus.to_dict()`` plus the
        # rename ``status`` -> ``state`` (consistent with the
        # ``{"state": "unknown"}`` sentinel on the failure-safe path).
        "version_status": version_status_block,
        # #169 Wave 2-α I7 — BAA expiry surfacing for Nagios polling.
        # Shape: {"expiring_soon": int, "expired": int,
        # "expired_hipaa_accounts_disabled": int}. ``expiring_soon``
        # rolls the 8-30d + 1-7d buckets together; the three-bucket
        # distinction is exposed in the admin UI instead. The
        # ``_disabled`` counter is the lifetime-of-process tally
        # captured on app.state by the daily-sweep loop.
        "baa_status": _compute_baa_status_block(request),
        # #152 phases 3-4 S4 — 24h counters for the HIPAA describe-and-
        # discard distill pipeline. Sibling field to ``version_status``
        # + ``baa_status``. Shape: {local_24h, cloud_24h, failures_24h,
        # scrubber_rejects_24h, total_24h}.
        "style_distill": style_distill_block,
        # #175 R-B — per-message retry-queue rollup. Nagios polls this
        # block to fire on a pending backlog or 24h-deads spike.
        "retry_queue": retry_queue_block,
    }
    return body, degraded


def _compute_retry_queue_block(db) -> dict[str, Any]:
    """Compute the ``retry_queue`` block for /health/detail.

    Reads the ``watcher_retry_queue`` table directly so this stays
    callable even when R-A's higher-level helpers haven't merged
    yet — the table is what we need, R-A's helpers are just
    sugar. Returns a sentinel ``{"state": "unknown", "error": ...}``
    when the table doesn't exist (pre-migration install).

    Shape:
        {
            "pending": <int>,
            "dead_24h": <int>,
            "oldest_pending_age_sec": <int> or None,
            "dead_breakdown_24h": {
                "max_attempts_exceeded": <int>,
                "auth_revoked": <int>,
                "uidvalidity_changed": <int>,
                "message_gone": <int>,
                "operator_abandoned": <int>,
            },
        }
    """
    if db is None:
        return {
            "state": "unknown",
            "error": "db connection unavailable",
        }

    # First check the table is present. SQLite raises OperationalError
    # on a missing table; converting that to the unknown sentinel keeps
    # /health/detail green during a pre-migration window where the
    # table doesn't exist yet but the schema is otherwise fine.
    try:
        db.execute("SELECT 1 FROM watcher_retry_queue LIMIT 1")
    except Exception as exc:
        return {
            "state": "unknown",
            "error": f"{type(exc).__name__}: {exc}",
        }

    pending = 0
    dead_24h = 0
    oldest_age: int | None = None
    # Pre-populate the canonical reason keys so consumers can rely on
    # the shape even before any row exists with that reason.
    breakdown: dict[str, int] = {
        "max_attempts_exceeded": 0,
        "auth_revoked": 0,
        "uidvalidity_changed": 0,
        "message_gone": 0,
        "operator_abandoned": 0,
    }

    # Pending count + oldest age.
    try:
        row = db.execute(
            "SELECT COUNT(*) AS c, MIN(created_at) AS oldest "
            "FROM watcher_retry_queue WHERE state = 'pending'"
        ).fetchone()
        if row is not None:
            pending = int(row["c"] if hasattr(row, "keys") else row[0])
            oldest_iso = (
                row["oldest"] if hasattr(row, "keys") else row[1]
            )
            if oldest_iso:
                from datetime import datetime, timezone
                try:
                    dt = datetime.fromisoformat(
                        str(oldest_iso).replace("Z", "+00:00")
                    )
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    delta = datetime.now(timezone.utc) - dt
                    oldest_age = int(delta.total_seconds())
                except (TypeError, ValueError):
                    oldest_age = None
    except Exception:
        # Older schema may not have ``state`` column; treat as 0.
        pending = 0

    # Dead-in-24h count + breakdown.
    try:
        from datetime import datetime, timedelta, timezone
        since = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        row = db.execute(
            "SELECT COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND updated_at >= ?",
            (since,),
        ).fetchone()
        if row is not None:
            dead_24h = int(row["c"] if hasattr(row, "keys") else row[0])
        # Breakdown by dead_reason.
        rows = db.execute(
            "SELECT dead_reason, COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND updated_at >= ? "
            "GROUP BY dead_reason",
            (since,),
        ).fetchall()
        for r in rows:
            reason = r["dead_reason"] if hasattr(r, "keys") else r[0]
            count = int(r["c"] if hasattr(r, "keys") else r[1])
            if reason:
                breakdown[reason] = count
    except Exception:
        # Same older-schema path; leave the prefilled zeros.
        pass

    return {
        "pending": pending,
        "dead_24h": dead_24h,
        "oldest_pending_age_sec": oldest_age,
        "dead_breakdown_24h": breakdown,
    }


def _compute_baa_status_block(request: Request) -> dict[str, int]:
    """Return the ``baa_status`` block for /health/detail.

    Failure-safe: any error inside the bucket computation yields the
    silent ``{"expiring_soon": 0, "expired": 0, ...}`` shape so the
    health endpoint never breaks on this enrichment.
    """
    from email_triage.baa_expiry import health_status_block
    try:
        db = request.app.state.db
        auto_disabled_count = int(
            getattr(
                request.app.state, "baa_expiry_disabled_count", 0,
            ) or 0,
        )
        return health_status_block(
            db, auto_disabled_count=auto_disabled_count,
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "baa_status compute failed for /health/detail: %s",
            exc, exc_info=True,
        )
        return {
            "expiring_soon": 0,
            "expired": 0,
            "expired_hipaa_accounts_disabled": 0,
        }


async def _compute_health_detail(request: Request) -> tuple[dict[str, Any], bool]:
    """Async wrapper: run the blocking snapshot off the event loop.

    #135: the underlying computation is pure-blocking (SQLite reads,
    watcher-manager rollups, ``record_access_event`` on /health/detail
    audit). Wrapping at the snapshot boundary — rather than per
    SELECT — minimises threadpool round-trips while still freeing the
    event loop for concurrent /health polls.
    """
    return await db_call(_compute_health_detail_sync, request)


@router.get("/health", include_in_schema=True)
async def health(request: Request) -> Any:
    """Minimal unauthenticated liveness probe.

    #89: split from the operator-facing detail in 2026-04-30. Returns
    just enough for container HEALTHCHECK + external monitors to
    decide ok-vs-degraded:

      {"status": "ok"|"degraded", "uptime_secs": N, "db": "ok"|"error"}

    - 200 on ok; 503 on degraded.
    - No version, no account counts, no task names, no
      audit_failures/csrf_rejects -- those signal operational footprint
      and could help an attacker tune timing.
    - DB shape preserved so the deploy script's `curl /health` parse
      still recognises the up-vs-degraded signal without a JSON
      structural change.

    Operator detail lives at /health/detail (admin-only). Same
    underlying snapshot; this surface just trims it.
    """
    from fastapi.responses import JSONResponse
    body, degraded = await _compute_health_detail(request)
    minimal = {
        "status": body.get("status", "ok"),
        "uptime_secs": body.get("uptime_secs", 0),
        "db": body.get("db", "error"),
    }
    if degraded:
        return JSONResponse(content=minimal, status_code=503)
    return minimal


@router.get("/health/detail", include_in_schema=True)
async def health_detail(request: Request) -> Any:
    """Full operator-facing health snapshot. Admin-only.

    #89: holds the full payload (tasks block, ingestion counts,
    watchers, audit_failures, csrf_rejects, schema_version, version).
    Linked from the dashboard chips + admin/stats; CLI consumers go
    through admin auth like every other admin surface.

    Returns 401/303 redirect for unauthenticated callers, 403 for
    authenticated non-admins. Same 503-on-degraded behaviour as
    /health for status-code consistency.
    """
    from fastapi.responses import JSONResponse, RedirectResponse
    user = _get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return JSONResponse(
            {"error": "admin role required"}, status_code=403,
        )
    body, degraded = await _compute_health_detail(request)
    if degraded:
        return JSONResponse(content=body, status_code=503)
    return body
