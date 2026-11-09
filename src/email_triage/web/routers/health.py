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

from email_triage._errfmt import fmt_exc
import asyncio
import hmac
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Request

from email_triage._errfmt import scrub_class_error_for_persist, scrub_error_for_persist
from email_triage._int_utils import bounded_int  # N-219c R23
from email_triage._isotime import (
    parse_iso, parse_iso_aware, to_utc_iso, now_utc_iso_z,
)  # N-357b R31 + N-316b R32
from email_triage.llm_truncation import llm_truncated_1h  # N-372 obs fold
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import get_current_user as _get_current_user
from email_triage.web.dependencies import is_admin  # N-222 R22 bool SSOT
from email_triage.web.dependencies import is_health_ro  #  machine-role bool
from email_triage.web.dependencies import request_meta  # N-187 R20_12 SSOT
from email_triage.web.error_surface import api_error_response

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.web.health")  # N-196b R21_4

router = APIRouter()


_STALE_WATCHER_SECONDS = 15 * 60   # 15 minutes
_STALE_TRIAGE_SECONDS = 24 * 60 * 60  # 24 hours

#  — "sustained" threshold for the HIPAA style-distill failure
# count. A handful of transient distill backend failures over a 24h
# window is ordinary noise (a backend blip self-heals); ``degraded``
# fires only once the 24h failure count is high enough to mean the
# distill pipeline is genuinely broken. Matches the install-wide
# retry-deads threshold in daily_health.py for consistency.
_STYLE_DISTILL_FAILURE_DEGRADE_THRESHOLD = 5

# ``message_gone`` now means the AMBIGUOUS empty-fetch case ONLY: a 0-byte
# IMAP fetch whose UID SEARCH could NOT confirm the message is gone (still
# present, or unverifiable) — i.e. the systematic-fetch-degradation signal the
# spike fail-safe exists to catch. A CONFIRMED expunge (a provider 404, or a
# 0-byte fetch whose UID SEARCH confirms absent) is the distinct, BENIGN
# ``message_expunged`` reason that never degrades (see the classifier below).
# With that verified split (2026-06-19), ordinary mailbox churn (genuine
# deletions, now ``message_expunged``) no longer lands here — it was tripping
# the old count of 5 on a high-churn account. ``message_gone`` should now spike
# only on a REAL fetch degradation (present-but-empty), so degrade at/above
# this higher 24h count.
_MESSAGE_GONE_DEGRADE_THRESHOLD = 30

# N-372 (2026-07-05): per-reason threshold for ``max_attempts_exceeded``.
# BEFORE: a SINGLE ``max_attempts_exceeded`` dead row flipped /health to 503
# for a full 24h window until ``resolved_at`` slid past the cutoff, even when
# the message that broke was a low-signal FedEx delivery notification tripping
# a transient LLM parse edge (see 2026-07-05 incident). That collapsed the
# operator surface into a single-message-noise → full-CRIT ratio.
# AFTER: aggregate at/above 3 within the last 24h. Rationale:
#   * 1 stuck message per day = the ordinary long-tail residual (transient
#     model burp, a message whose text happens to trip a parser edge). Not
#     systemic.
#   * 2 stuck = still noisy but a low-signal shape.
#   * 3+ stuck in 24h = the systemic-classify-fail curve worth alerting on
#     (backend regression, prompt drift, format-schema misconfig).
# LOWER than ``_MESSAGE_GONE_DEGRADE_THRESHOLD=30`` because ``message_gone`` is
# an AMBIGUOUS churn signal (30 tolerates high-churn accounts), whereas
# ``max_attempts_exceeded`` is a HARD terminal failure post-5-retries and
# already carries strong signal per event. Keeping this tight preserves the
# "fail-safe toward alerting" posture the ``degraded`` OR-chain codifies at
# the site — same design, better SNR.
# the backlog — revisit ~2026-08-05 (N-372 landing 2026-07-05 + 30d):
# threshold=3 is a heuristic chosen at N-372 close to debounce a single
# content-triggered `max_attempts_exceeded` (Ollama upstream #15260
# format-schema bypass, closed via `c53a760e`) from flipping /health for
# 24h. After 30 days of prod signal on the retry-queue's actual
# max_attempts_exceeded arrival rate + distribution, re-evaluate:
# (a) if 30d shows 0-1 hits total, threshold=3 is over-tolerant — tighten
#     back toward 1 (a real dead-row on the post-N-372 stack is a signal
#     worth alerting on, not debouncing);
# (b) if 30d shows a genuine multi-per-week baseline, threshold=3 is
#     right-sized;
# (c) if 30d shows spikes tied to specific accounts / senders, add a
#     per-source dimension instead of a global counter.
# TaskList  tracks the revisit.
_MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD = 3

#  — degrade /health when a present TLS cert is at or within this
# many days of expiry. The ACME auto-renewer rolls well before this,
# so reaching it means the renewer failed — surface it before the
# listener serves a dead cert.
_TLS_CERT_DEGRADE_DAYS = 7

# Container-internal ops access to /health/detail (the admin-session bypass).
# A token shorter than this is treated as UNSET — a blank/weak/default value
# never enables the bypass.
_OPS_TOKEN_MIN_LEN = 16
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _ops_token_authorized(
    *, client_host: str, presented: str, env_token: str,
) -> bool:
    """True only when ALL of the layered conditions hold for the
    /health/detail ops bypass:

      * the request originates from the container's OWN loopback — the
        ``podman exec ... curl https://localhost:8080`` path. The published
        LAN port (0.0.0.0:8080) arrives with the container GATEWAY ip, NOT
        loopback, so a LAN caller can NEVER use the token even if it leaks;
      * a token of at least ``_OPS_TOKEN_MIN_LEN`` chars is configured (a
        blank / weak / unset ``ET_HEALTH_OPS_TOKEN`` disables the bypass —
        the install is then admin-session-only, unchanged);
      * the presented ``X-Ops-Token`` matches, compared in constant time.

    Pure + side-effect-free so the loopback×entropy×match matrix is unit-tested
    directly (the TestClient reports a non-loopback host, which is exactly the
    LAN-denied case)."""
    token = (env_token or "").strip()
    if len(token) < _OPS_TOKEN_MIN_LEN:
        return False
    host = client_host or ""
    if host not in _LOOPBACK_HOSTS and not host.startswith("127."):
        return False
    return hmac.compare_digest((presented or "").strip(), token)


def _read_ops_token() -> str | None:
    """Single reader for the ``ET_HEALTH_OPS_TOKEN`` ops-bypass secret (run18 #6).

    The ONE place the raw ``os.environ`` read for this token lives. The three
    callers route through it: ``/health/detail`` (here), ``/ops/db-backup``
    (``backup.py``), and the ``backup now`` CLI trigger (``cli.py``). Funnelling
    the read keeps the env-var NAME a single literal, so a future rename / alias is
    a one-line change (PD#1/#5 — drift-prevention; ``test_ops_token_read_pin`` bans
    a raw read elsewhere). §164.312(d)+(a)(1) credential-handling hygiene; NOT a
    live defect — the auth DECISION already funnels through ``_ops_token_authorized``.

    Returns the raw env value (``None`` when unset); callers apply their own
    ``or ""`` coalescing exactly as before, so the behaviour is byte-identical to
    the inline reads it replaces. Deliberately logic-free (no ``.strip()`` / length
    floor / loopback gate): ``_ops_token_authorized`` stays the param-pure DECISION
    SSOT and owns all of that — this is only the thin READER half.

    **N-365 R31 (2026-07-05 trust-repair fix-forward per Census run22 §5 +
    the backlog  = TASK ):** the secret-read funnel pin (`test_secret_
    read_funnel_pin.py`) is structurally blind to this env-read (it walks
    `SecretsProvider.get`-shape sites, not `os.environ.get` sites). This
    is a DOCUMENTED DEVIATION, not a pin gap:

    * The env-var is an OPERATOR-CONTROLLED break-glass override for the
      /health detail endpoint (bootstraps before the DbSecrets store is
      readable — the /health endpoint is used for post-container-restart
      readiness probing).
    * Migrating to `DbSecrets` would create a bootstrapping chicken-and-egg
      (readiness probe depends on DB readable, which depends on readiness).
    * The auth DECISION `_ops_token_authorized` provides the fail-CLOSED
      surface (blank / weak / unset disables the bypass); the backlog 
      tracks token-rotation hygiene.

    Sentinel below is a NAMED-DEVIATION marker for future funnel-pin
    tightening (Census run22 §7#4 self-eval: pin walker should surface
    named deviations distinctly from unresolved ones).
    """
    # secret-read: env-ops-token (N-365 named-deviation — bootstrap surface)
    return os.environ.get("ET_HEALTH_OPS_TOKEN")


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
    sets ``TZ=America/New_York``). Result shape is the same ISO-with-offset
    format Python's ``isoformat()`` produces, just with a real offset like
    ``-04:00`` / ``-05:00`` instead of ``+00:00``. Matches operator
    expectation and the TZ-aware log formatter shipped in wave 1.
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
        # N-357b (2026-07-06 baseline shrink): parse_iso_aware SSOT.
        dt = parse_iso_aware(val)
        if dt is None:
            # Unparseable — fall back to raw string so the endpoint
            # still reports something rather than None.
            return val
        return dt.astimezone().isoformat()
    except Exception:
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
        started_at = parse_iso((state or {}).get("started_at"))
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
        exp = parse_iso(r.get("expires_at"))
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
        exp = parse_iso(r.get("expiration_at"))
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
            "watching_off": 0, "push_plus_poll": 0,
        })
        b["total"] += 1
        primary = s.get("primary", "none")
        watching_off = bool(s.get("watching_off"))
        if primary == "push":
            b["push"] += 1
        elif primary == "poll":
            b["poll"] += 1
        elif watching_off:
            # Operator turned push+poll off on purpose — a neutral "watching
            # off" state, NOT uncovered and NOT an alert.
            b["watching_off"] += 1
        else:
            b["uncovered"] += 1
        if s.get("mode") == "push+poll":
            b["push_plus_poll"] += 1
        if s.get("alert"):
            any_alert = True
        if primary == "none" and not watching_off:
            any_uncovered = True
    return {
        "providers": by_provider,
        "any_uncovered": any_uncovered,
        "any_alert": any_alert,
    }


def _compute_health_detail_sync(request: Request) -> tuple[dict[str, Any], bool]:
    """Synchronous body of the health snapshot computation.

    : the entire health-detail computation is a sequence of blocking
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

    # O365 Graph subscription rollup — same shape as gmail_push,
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
    last_triage_dt = parse_iso(last_triage_iso)
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
    # Punch 709: a revoke committed WITHOUT its chained witness (the emergency
    # path) stays an alarm until the chain is repaired and re-verified. A file
    # beside the database, not a counter: it outlives a restart and is seen
    # here when the CLI process set it. Cleared only by clear_emergency_revoke.
    emergency_revoke_pending = False
    if db is not None:
        from email_triage.db.audit import emergency_revoke_pending as _erp
        emergency_revoke_pending = bool(_erp(db))
    csrf_rejects = int(getattr(app.state, "csrf_rejects", 0))

    #  — classification-cache counters (per-process). Empty / safe
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

    # N-93 — topic-match parse-failure + retry-outcome counters. Surfaces how
    # often the §4.4 fail-open valve opens (the qwen3.x format-JSON malformation
    # rate) as a NUMBER, not a log-grep. Process-local snapshot + Redis lifetime,
    # same shape as the cache block; integers only (no PHI).
    try:
        from email_triage.classify.base import get_topic_match_counters
        _tm_snap = get_topic_match_counters().snapshot()
    except Exception:
        _tm_snap = {
            "parse_retried": 0, "retry_recovered": 0,
            "retry_failed_dropped": 0, "salvage_recovered": 0,
        }
    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend as _tm_pc,
        )
        _tm_be = _tm_pc()
        _tm_lifetime = _tm_be.fetch("topic_match") if _tm_be is not None else {}
    except Exception:
        _tm_lifetime = {}
    topic_match_block = {**_tm_snap, "lifetime": _tm_lifetime}

    # Embedding backend live metrics (#m4-status). Surfaces what's
    # actually loaded + per-call counters; a failing embedder shows as
    # errors here (no fallback chain absorbs it, punch 552 / N-555).
    # Empty dict when no embedding backend is configured (RAG paths
    # off install-wide).
    # Punch 562: ONE block shape on every path. /admin/stats reads
    # ``lifetime.<namespace>`` unconditionally and branches on
    # ``metrics.backend_type``, so the unconfigured block and a failed
    # ``metrics()`` read carry them too (StrictUndefined 500'd on both).
    _emb_lifetime_empty = {"ollama": {}, "sentence_transformers": {}}
    embedding_block: dict[str, Any] = {
        "configured": False,
        "backend_type": None,
        "model": "",
        "metrics": {},
        "lifetime": _emb_lifetime_empty,
    }
    _emb_be = getattr(request.app.state, "embedding_backend", None)
    if _emb_be is not None:
        try:
            metrics = (
                _emb_be.metrics() if hasattr(_emb_be, "metrics") else {}
            )
        except Exception:
            metrics = {}
        metrics.setdefault(
            "backend_type", getattr(_emb_be, "backend_type", "?"),
        )
        # 2026-05-13 — Redis-persisted lifetime counters per backend
        # namespace. Empty dicts when no persistent backend wired.
        # One namespace per backend type.
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
            }
        except Exception:
            _emb_lifetime = _emb_lifetime_empty
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

    #  partial follow-up — surface the same schema-compat verdict
    # the admin /config banner shows, in machine-readable form. the monitoring system
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
    # for downstream consumers (the monitoring system scrape, deploy.sh pre-flight).
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
        logger.error(  # N-332 + N-338c: extras carry structured error
            "version_status lookup failed for /health/detail",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
            exc_info=True,
        )
        version_status_block = {
            "state": "unknown",
            "error": scrub_class_error_for_persist(exc),
        }

    #  phases 3-4 S4 follow-up — 24h counters for the HIPAA distill
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
        logger.error(  # N-332 + N-338c: extras carry structured error
            "style_distill counters failed for /health/detail",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
            exc_info=True,
        )
        style_distill_block = {
            "local_24h": 0, "cloud_24h": 0,
            "failures_24h": 0, "scrubber_rejects_24h": 0,
            "total_24h": 0,
            "error": scrub_class_error_for_persist(exc),
        }

    #  R-B — per-message retry-queue rollup for the monitoring system polling.
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
        logger.error(  # N-332 + N-338c: extras carry structured error
            "retry_queue rollup failed for /health/detail",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
            exc_info=True,
        )
        retry_queue_block = {
            "state": "unknown",
            "error": scrub_class_error_for_persist(exc),
        }

    #  — every failure signal /health/detail already computes
    # folds into ``degraded``. Previously the boolean read only five
    # terms (db, any_alert, triage_stale, any_quarantined,
    # watchers_failing) and silently dropped the rest — most starkly
    # ``office365_push.errored``, which had an explicit ``_ =
    # o365_push_block`` discard. A subsystem the operator surface
    # flags red but /health still calls "ok" is exactly the silent-
    # failure class this product cannot afford.
    #
    # Each added term reads a block computed above:
    #   - tasks.any_crashed_recently — a supervised task in the
    #     ``crashed`` state (mid-backoff, not yet quarantined).
    #   - tasks.any_loop_tick_failing — : a supervised_interval_
    #     loop whose ticks have failed N times running while the loop
    #     itself stays nominally ``running``.
    #   - tasks.any_loop_tick_stale — : a supervised_interval_loop
    #     whose last tick is older than a generous multiple of its
    #     interval — the only signal a tick that HANGS forever leaves
    #     (a hung tick never reaches the failure counter at all).
    #   - retry_queue dead-count > 0 — any per-message retry that gave
    #     up in the last 24h. ``state == "unknown"`` is the failure-
    #     safe sentinel (pre-migration / read error) — not degraded.
    #   - audit_failures > 0 — a HIPAA/audit write that did not land.
    #   - version_status.state in the two hard-incompatible states.
    #   - office365_push.errored > 0 — a Graph subscription errored
    #     or expired.
    #   - style_distill.failures_24h sustained past the threshold.
    #   - baa_status.expired > 0 — a BAA past its expiry date.
    #   - tls_cert at/near expiry — : the ACME renewer failed to
    #     roll the cert before the listener would serve a dead one.
    tasks_crashed = bool(tasks_block.get("any_crashed_recently"))
    tasks_tick_failing = bool(tasks_block.get("any_loop_tick_failing"))
    tasks_tick_stale = bool(tasks_block.get("any_loop_tick_stale"))

    # Only GENUINE-FAULT dead retries degrade /health (fire a the monitoring system CRITICAL):
    #   - ``operator_abandoned`` — a deliberate human action; NEVER degrades.
    #   - ``message_expunged`` — a VERIFIED-absent expunge (provider 404, or a
    #     0-byte IMAP fetch whose UID SEARCH confirms gone); benign, NEVER
    #     degrades. Normal mailbox churn (deletions) lands here post-2026-06-19.
    #   - ``message_gone`` — the AMBIGUOUS empty-fetch case: a 0-byte fetch whose
    #     UID could NOT be confirmed gone (still present, or unverifiable). A
    #     SPIKE (>= _MESSAGE_GONE_DEGRADE_THRESHOLD/24h) means systematic fetch
    #     degradation mis-tombstoning real mail → degrade.
    #   - ``max_attempts_exceeded`` (N-372, 2026-07-05) — hard classify /
    #     action failure after N retries. A SINGLE dead row (this incident's
    #     trigger, one FedEx delivery notification tripping a transient LLM
    #     parse edge) previously flipped /health for 24h. Now degrades only at
    #     a SPIKE (>= _MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD/24h) — see the
    #     constant's docblock for the rationale.
    #   - everything else (``auth_revoked``, ``uidvalidity_changed`` (the mail-
    #     loss reason), and any FUTURE unclassified reason) always degrades —
    #     fail-safe toward alerting.
    # Benign rows stay VISIBLE in the body's ``dead_breakdown_24h`` — only the
    # degrade DECISION is narrowed, the event is not hidden. Falls back to the
    # ``dead_24h`` total when the breakdown is absent (older block shape).
    retry_dead = 0
    if retry_queue_block.get("state") != "unknown":
        breakdown = retry_queue_block.get("dead_breakdown_24h")
        # N-219c/38 R23: bounded_int SSOT — parse each count with default=0.
        # A non-numeric value in the breakdown map (extremely unlikely for a
        # Redis-sourced dead-queue count) previously zeroed the WHOLE total;
        # post-migration it zeroes just that entry, which is a strictly-more-
        # granular signal for /health.
        if isinstance(breakdown, dict):
            total = 0
            for reason, raw in breakdown.items():
                n = bounded_int(raw or 0, default=0)
                if reason in ("operator_abandoned", "message_expunged"):
                    continue
                if (
                    reason == "message_gone"
                    and n < _MESSAGE_GONE_DEGRADE_THRESHOLD
                ):
                    continue
                if (
                    reason == "max_attempts_exceeded"
                    and n < _MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD
                ):
                    continue
                total += n
            retry_dead = total
        else:
            retry_dead = bounded_int(
                retry_queue_block.get("dead_24h", 0) or 0, default=0,
            )

    version_state = version_status_block.get("state")
    version_incompatible = version_state in {
        "incompatible_rollback", "downgrade_not_supported",
    }

    o365_errored = bounded_int(  # N-219c R23: SSOT
        o365_push_block.get("errored", 0) or 0, default=0,
    )

    distill_failures = bounded_int(  # N-219c R23: SSOT
        style_distill_block.get("failures_24h", 0) or 0, default=0,
    )
    distill_failing = (
        distill_failures >= _STYLE_DISTILL_FAILURE_DEGRADE_THRESHOLD
    )

    # Computed once here; reused in the body payload below so the BAA
    # bucket query runs a single time per /health probe.
    baa_status_block = _compute_baa_status_block(request)
    baa_expired = bounded_int(  # N-219c R23: SSOT
        baa_status_block.get("expired", 0) or 0, default=0,
    )

    # the backlog  — N-151-tail db-sme fold: /health/detail observability
    # bucket for the MSAL master-key availability. Sibling to `baa_status`:
    # a single, cheap, process-level probe of `_get_master_key()` — the
    # exact accessor `Office365Provider.__init__` uses to set
    # `self._master_key_available`. Restores the compensating control the
    # SOFT gate variant traded away (a boot-time hard raise → boot-time
    # WARN + first-save fail-closed) so operator + the monitoring system can observe the
    # misconfig BEFORE the first re-auth prompt lands in production.
    msal_master_key_status_block = _compute_msal_master_key_status_block(
        request,
    )

    #  — on-disk TLS cert expiry surface. Pure file read (no ACME
    # directory call) so a healthy probe doesn't depend on network.
    # Lets the monitoring system fire on an expiring cert before the listener serves a
    # dead one. ``read_tls_cert_health`` is itself failure-safe; the
    # extra try/except here is belt-and-braces so an import error can't
    # take /health/detail down.
    tls_cert_block: dict[str, Any]
    try:
        from email_triage.web.acme_renewer import read_tls_cert_health
        tls_cert_block = read_tls_cert_health(app)
    except Exception as exc:  # pragma: no cover - failure-safe
        logger.error(  # N-332 + N-338c: extras carry structured error
            "tls_cert read failed for /health/detail",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
            exc_info=True,
        )
        tls_cert_block = {
            "present": False,
            "not_after": None,
            "days_remaining": None,
            "error": scrub_class_error_for_persist(exc),
        }
    # / — a present cert at/near expiry degrades /health: the
    # auto-renewer should have rolled it well before this point.
    cert_degraded = False
    if tls_cert_block.get("present"):
        _cert_days = tls_cert_block.get("days_remaining")
        if (
            isinstance(_cert_days, (int, float))
            and _cert_days <= _TLS_CERT_DEGRADE_DAYS
        ):
            cert_degraded = True

    degraded = (
        (not db_ok)
        or any_alert
        or triage_stale
        or bool(tasks_block.get("any_quarantined"))
        or tasks_crashed
        or tasks_tick_failing
        or tasks_tick_stale
        or bool(watchers_failing)
        or retry_dead > 0
        or audit_failures > 0
        or emergency_revoke_pending
        or version_incompatible
        or o365_errored > 0
        or distill_failing
        or baa_expired > 0
        or cert_degraded
        # the backlog  REDESIGNED v3 Part 1: MSAL master-key SOFT gate
        # ACTIVE + reason=="unavailable" (SOFT path) degrades /health so
        # the monitoring system pages the operator on the N-151 SOFT unavailable signal —
        # restores the compensating control the SOFT variant traded away.
        # STRICT `is False`: only the expected SOFT `unavailable` path fires.
        # `probe_error` / `import_error` surface as `available is None`
        # (UNKNOWN) and do NOT degrade — unknown ≠ WARN (the monitoring system tri-state).
        or msal_master_key_status_block.get("available") is False
    )
    status = "degraded" if degraded else "ok"

    version = getattr(app.state, "version", "unknown")

    # Legacy IMAP-IDLE-account roll-up (kept for the monitoring system / deploy script
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
        # Backward-compat keys. Existing consumers (the monitoring system probe, deploy
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
        "emergency_revoke_pending": emergency_revoke_pending,
        "csrf_rejects": csrf_rejects,
        "schema_version": schema_version_value,
        "classification_cache": classification_cache_block,
        "topic_match": topic_match_block,
        "embedding": embedding_block,
        "webhooks": webhooks_block,
        #  partial follow-up — schema-compat verdict in
        # machine-readable form so the monitoring system can poll without scraping
        # /config. Shape mirrors ``VersionStatus.to_dict()`` plus the
        # rename ``status`` -> ``state`` (consistent with the
        # ``{"state": "unknown"}`` sentinel on the failure-safe path).
        "version_status": version_status_block,
        #  Wave 2-α I7 — BAA expiry surfacing for the monitoring system polling.
        # Shape: {"expiring_soon": int, "expired": int,
        # "expired_hipaa_accounts_disabled": int}. ``expiring_soon``
        # rolls the 8-30d + 1-7d buckets together; the three-bucket
        # distinction is exposed in the admin UI instead. The
        # ``_disabled`` counter is the lifetime-of-process tally
        # captured on app.state by the daily-sweep loop.
        "baa_status": baa_status_block,
        #  phases 3-4 S4 — 24h counters for the HIPAA describe-and-
        # discard distill pipeline. Sibling field to ``version_status``
        # + ``baa_status``. Shape: {local_24h, cloud_24h, failures_24h,
        # scrubber_rejects_24h, total_24h}.
        "style_distill": style_distill_block,
        #  R-B — per-message retry-queue rollup. the monitoring system polls this
        # block to fire on a pending backlog or 24h-deads spike.
        "retry_queue": retry_queue_block,
        #  — on-disk TLS cert expiry. Shape: {present, not_after,
        # days_remaining}. Pure file read; lets a monitor fire before
        # the cert actually expires under the listener.
        "tls_cert": tls_cert_block,
        # the backlog  — N-151-tail db-sme fold: MSAL master-key
        # availability sibling to baa_status. Shape:
        # {"available": bool | None, "reason": str | None}. `available`
        # is None on a probe error (rare — the check is a single
        # secrets-backend read). `reason` is a short slug on the
        # unavailable / probe-failed paths (unset when available == True).
        # Sibling the monitoring system alert on `available in (False, None)` restores
        # the compensating control the N-151 SOFT gate variant traded
        # away — see the backlog  for the pattern-alert build-out.
        "msal_master_key_status": msal_master_key_status_block,
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
            "error": scrub_class_error_for_persist(exc),
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
                # N-357b (2026-07-06 baseline shrink): parse_iso_aware SSOT.
                dt = parse_iso_aware(oldest_iso)
                if dt is None:
                    oldest_age = None
                else:
                    delta = datetime.now(timezone.utc) - dt
                    oldest_age = int(delta.total_seconds())
    except Exception:
        # Older schema may not have ``state`` column; treat as 0.
        pending = 0

    # Dead-in-24h count + breakdown.
    try:
        since = to_utc_iso(
            datetime.now(timezone.utc) - timedelta(hours=24)
        )
        row = db.execute(
            "SELECT COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND resolved_at >= ?",
            (since,),
        ).fetchone()
        if row is not None:
            dead_24h = int(row["c"] if hasattr(row, "keys") else row[0])
        # Breakdown by dead_reason.
        rows = db.execute(
            "SELECT dead_reason, COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND resolved_at >= ? "
            "GROUP BY dead_reason",
            (since,),
        ).fetchall()
        for r in rows:
            reason = r["dead_reason"] if hasattr(r, "keys") else r[0]
            count = int(r["c"] if hasattr(r, "keys") else r[1])
            if reason:
                breakdown[reason] = count
    except Exception as e:
        # Same older-schema path; leave the prefilled zeros.
        logger.warning(
            "Retry-queue dead breakdown unavailable; showing zeros",
            error=fmt_exc(e),
        )

    # N-372 observability fold — surface the cross-backend LLM
    # unclean-finish rolling-window count so a  truncation warning
    # can't go unobserved (the 2-day silent-warning window the N-372
    # incident exposed). Sibling to retry_queue rather than a top-level
    # block per the operator resume directive; the classify layer is
    # upstream of the retry-queue so a spike here PREDICTS retry-queue
    # dead-row arrival, which is why they read together.
    try:
        truncated_1h = int(llm_truncated_1h())
    except Exception:  # never let observability wiring break /health
        truncated_1h = 0

    return {
        "pending": pending,
        "dead_24h": dead_24h,
        "oldest_pending_age_sec": oldest_age,
        "dead_breakdown_24h": breakdown,
        "classify_truncated_1h": truncated_1h,
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
        logger.error(  # N-332 + N-338c: extras carry structured error
            "baa_status compute failed for /health/detail",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
            exc_info=True,
        )
        return {
            "expiring_soon": 0,
            "expired": 0,
            "expired_hipaa_accounts_disabled": 0,
        }


_MSAL_MASTER_KEY_REASON_ENUM: frozenset[str] = frozenset({
    "available",         # probe returned a key
    "unavailable",       # probe raised — expected N-151 SOFT path
    "probe_error",       # probe raised an unexpected class
    "import_error",      # module import failed
})


def _compute_msal_master_key_status_block(
    request: Request,
) -> dict[str, Any]:
    """Return the ``msal_master_key_status`` block for /health/detail.

    the backlog  REDESIGNED v3 Part 1: reduced from a bespoke inline
    probe to a thin SHIM over the Part-0 SSOT accessor
    ``providers._msal_cache_crypto.n151_soft_gate_state()`` — the
    canonical (active, reason) tuple for the N-151 SOFT gate. The
    class-name partition + reason enum + fail-CLOSED posture live at
    Part-0 (single SSOT), so a future consumer (the monitoring system circuit-breaker,
    boot-time WARN) cannot drift from the /health surface's view of
    the gate.

    DB-SME F1 fold (2026-07-10): the shim was previously two probes
    (``n151_soft_gate_active()`` then ``n151_soft_gate_reason()``) — a
    torn-read seam on the transition tick between them. Collapsed onto
    the single-call ``n151_soft_gate_state()`` SSOT so ``active`` and
    ``reason`` are always sourced from ONE underlying probe.

    Shape preserved verbatim from the Part-0-preceding revision (no
    schema break for /health/detail consumers):

      * ``available: bool | None`` — True on success, False on the
        expected N-151 SOFT unavailable path (fail-CLOSED / feeds the
        aggregate degrade OR-term), None on probe_error / import_error
        (unknown ≠ WARN — does NOT degrade the top-line).
      * ``reason: str`` — one of ``_MSAL_MASTER_KEY_REASON_ENUM``.
      * ``error_type: str | None`` — class name on the import_error
        outer path; None on the accessor-covered inner paths (the
        accessor SSOT does NOT expose the class name — Part-0 chose the
        reason-enum partition over the class-name slug so a secrets-
        backend rewrite can't destabilise the surface).
      * ``last_probed_at: str`` — UTC ISO-8601 Z-suffixed timestamp of
        THIS probe (seam retained for the future the backlog 
        pattern-alert `probe_stale` circuit-breaker per DA #3).

    Failure-safe: never raises. On accessor import failure the fail-safe
    posture is `{available: None, reason: "import_error"}`.

    Log-storm discipline (hipaa-sme MUST-FIX #3 + DA #1) PRESERVED: the
    WARN fires ONCE per process boot on the FIRST non-available
    observation, and again ONLY on a state transition (a recovery to
    "available" included). A healthy first observation ("available",
    nothing before it) is silent; ``/health/detail`` still reports it.
    Track LAST reason on ``app.state._msal_master_key_last_reason``.
    """
    # N-316b R32 CI-red fix-forward: use the `_isotime` SSOT
    # (`now_utc_iso_z`) rather than an inline `datetime.now(tz).isoformat().
    # replace(...)` chain — N-357 R31's SSOT-and-drift-prevention rule
    # for aware-now ISO strings + N-335b function-scope shadow-import pin
    # both fire on the inline shape.
    now_iso = now_utc_iso_z()

    def _log_transition_warn(
        request: Request, reason: str, err_type: str | None,
    ) -> None:
        # Once-per-boot + on-transition WARN per hipaa-sme MUST-FIX #3.
        # Track LAST reason on app.state; log when a NON-available reason
        # first appears, or on any flip from a prior different value.
        state = request.app.state
        prev = getattr(state, "_msal_master_key_last_reason", None)
        if prev == reason:
            return
        state._msal_master_key_last_reason = reason
        # The docstring's contract: warn on the FIRST NON-available
        # observation. A healthy first observation after a boot is not a
        # transition; warning on it put a WARNING in every post-reboot daily
        # health (2026-10-10: reason=available prev_reason=None). A later
        # flip to "available" (a recovery) still warns.
        if prev is None and reason == "available":
            return
        logger.warning(
            "msal_master_key_status transition",
            extra={
                "reason": reason,
                "prev_reason": prev,
                "error_type": err_type,
            },
        )

    try:
        from email_triage.providers._msal_cache_crypto import (
            n151_soft_gate_state,
        )
    except Exception as exc:  # pragma: no cover — import-time fail
        _log_transition_warn(request, "import_error", type(exc).__name__)
        return {
            "available": None,
            "reason": "import_error",
            "error_type": type(exc).__name__,
            "last_probed_at": now_iso,
        }

    # DB-SME F1 fold (2026-07-10): single-call SSOT — the prior two-probe
    # pair (`n151_soft_gate_active()` then `n151_soft_gate_reason()`) was a
    # torn-read seam on the transition tick (a healthy→degraded flip landing
    # between the two calls would surface `active=True, reason="available"`).
    # `n151_soft_gate_state()` returns the (active, reason) tuple from ONE
    # underlying probe — both fields agree by construction.
    active, reason = n151_soft_gate_state()

    if not active:
        # On the healthy path, only log a transition if we were previously
        # unavailable — restores the "master key came back" signal for the
        # operator + the monitoring system timeline (a monitor cleared on the healthy poll).
        _log_transition_warn(request, "available", None)
        return {
            "available": True,
            "reason": "available",
            "error_type": None,
            "last_probed_at": now_iso,
        }

    # Gate ACTIVE. Strict-False-only aggregate semantics
    # (v3 Part 1 flip): `available is False` ONLY on the expected N-151
    # SOFT `unavailable` path so it can feed the top-line degrade term.
    # `probe_error` (unexpected class) surfaces as `available=None` —
    # unknown ≠ WARN, and it does NOT flip /health, matching the monitoring system
    # tri-state posture (WARN vs UNKNOWN).
    available: bool | None = False if reason == "unavailable" else None
    _log_transition_warn(request, reason, None)
    return {
        "available": available,
        "reason": reason,
        "error_type": None,
        "last_probed_at": now_iso,
    }


async def _compute_health_detail(request: Request) -> tuple[dict[str, Any], bool]:
    """Async wrapper: run the blocking snapshot off the event loop.

    : the underlying computation is pure-blocking (SQLite reads,
    watcher-manager rollups, ``record_access_event`` on /health/detail
    audit). Wrapping at the snapshot boundary — rather than per
    SELECT — minimises threadpool round-trips while still freeing the
    event loop for concurrent /health polls.
    """
    return await db_call(_compute_health_detail_sync, request)


@router.get("/health", include_in_schema=True)
async def health(request: Request) -> Any:
    """Minimal unauthenticated liveness probe.

    : split from the operator-facing detail in 2026-04-30. Returns
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

    : holds the full payload (tasks block, ingestion counts,
    watchers, audit_failures, csrf_rejects, schema_version, version).
    Linked from the dashboard chips + admin/stats; CLI consumers go
    through admin auth like every other admin surface.

    Returns 401/303 redirect for unauthenticated callers, 403 for
    authenticated non-admins. Same 503-on-degraded behaviour as
    /health for status-code consistency.

    Container-internal ops access: a LOOPBACK-origin request whose
    ``X-Ops-Token`` header matches ``ET_HEALTH_OPS_TOKEN`` (set in the container
    env, NEVER published) gets the detail WITHOUT an admin session — so an
    operator can troubleshoot from inside the container:
        podman exec <ctr> sh -c 'curl -sk -H "X-Ops-Token: $ET_HEALTH_OPS_TOKEN" \
            https://localhost:8080/health/detail'
    Layered (see _ops_token_authorized): loopback-origin AND a >=16-char token
    AND a constant-time match — so the published LAN port can't honor the token
    even if it leaks, and a blank/weak/unset token disables the bypass entirely
    (admin-session-only, unchanged). The body is ops METADATA (no PHI / no
    credentials) — pinned PHI-free by test_health_detail_body_is_phi_free.
    """
    from fastapi.responses import JSONResponse, RedirectResponse

    # N-187 R20_12: authz-boundary host read routes through the request_meta
    # SSOT (consistent empty-string-on-unknown, never None, matches the
    # `""` fallback _ops_token_authorized expects). Imported at module top.
    _meta = request_meta(request)
    _ops_authed = _ops_token_authorized(
        client_host=_meta.host,
        presented=request.headers.get("X-Ops-Token") or "",
        env_token=_read_ops_token() or "",
    )
    if not _ops_authed:
        #  — get_current_user does a sync DB read; route it off the
        # event loop so it cannot collide with a db_call worker on the
        # shared connection.
        user = await db_call(_get_current_user, request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        # N-222 R22: is_admin bool SSOT.
        if not is_admin(user):
            return api_error_response(
                "admin role required", status_code=403, purpose="misc",
            )
    body, degraded = await _compute_health_detail(request)
    if degraded:
        return JSONResponse(content=body, status_code=503)
    return body


# A full git commit sha and nothing else, from the ONE baked-sha module
# (punch 539 rebase, 2026-09-30: hipaa H539-1, db N-539-X1, da DA-C6). See
# health_build's body for why this is a SHAPE assertion rather than a sentinel
# deny-list.
from email_triage._build_sha import FULL_SHA_RE  # noqa: E402


def _served_build_sha(request: Request) -> str:
    """The ONE ``build_sha`` value both build-identity routes serve.

    ``create_app`` stores ``_build_sha.baked_build_sha()`` once, at startup, as
    ``app.state.build_sha``. ``/health/build`` and ``/health/runtime-deps`` both
    answer from that stored value through this function, so the two routes
    cannot disagree about which commit is running (da ``DA-C6``). Re-reading the
    file per request on one route and the stored value on the other would let
    them diverge; one read, one funnel, keeps them equal by construction.

    Shape-gated again here, so a value planted in ``app.state`` by anything
    other than the resolver still cannot reach a scanner unless it is a full
    commit sha: absent beats wrong.
    """
    build_sha = getattr(request.app.state, "build_sha", "") or ""
    return build_sha if FULL_SHA_RE.fullmatch(build_sha) else ""


@router.get("/health/build", include_in_schema=True)
async def health_build(request: Request) -> Any:
    """The deployed build SHA, and NOTHING else. Any authenticated principal.

    WHY A THIRD ROUTE INSTEAD OF REUSING /health/detail
    ===================================================
    cve-arc's container-drift check answers "is this deployment current" by
    comparing the running build's commit to the repo checkout's HEAD (cve-arc
    ``6c841c9``). It needs exactly one datum: the SHA. It does NOT need — and
    must not be handed — the detail body.

    That distinction is load-bearing, not cosmetic. A 2026-06-13 devils-advocate
    review (``30b503ad``) rejected "a token alone on the published port"
    unlocking **/health/detail**, and the follow-up review of a proposed
    LAN-reachable read-only token for that same body returned NO-GO on exactly
    those grounds: it re-creates the rejected artifact head-on. The detail body
    is the sensitive object — `status` alone is a one-bit oracle over sixteen
    OR-terms (audit_failures, cert_degraded, version_incompatible, baa_expired,
    …; see ``_compute_health_detail_sync``), which is precisely the "operational
    footprint"  stripped from the unauthenticated tier.

    A 40-char commit hash is not that object. It is one opaque identifier with
    no counters, no oracle, and no PHI. Narrowing the payload — rather than
    widening who may read the wide payload — is what makes this safe, and it is
    the reusable move: expose the smallest thing that answers the question.

    WHY NO NEW CREDENTIAL
    ====================
    This deliberately introduces NO new token, env var, or header. Bearer
    api-key auth already reaches this router from any origin
    (``get_current_user`` → ``_check_bearer_token`` → ``verify_api_key``), so
    cve-arc holds an ordinary API key like any other client. Consequences worth
    stating: no second secret to provision, rotate or leak; no new env literal
    to thread through the ``_read_ops_token`` SSOT and its AST pin; and no new
    ``hmac.compare_digest`` call site — which matters, because that function
    raises ``TypeError`` on non-ASCII input and is currently reachable only
    behind the loopback gate, so a new origin-agnostic comparator would have
    handed any LAN caller an unauthenticated 500.

    NOT admin-gated, on purpose: requiring ``is_admin`` would force the monitor
    to hold an ADMIN key to read a build number. Least privilege means the
    lowest role that answers the question, so any authenticated, non-disabled
    principal suffices. The ops-token bypass is deliberately NOT honoured here —
    that token is the loopback CLI path and has no business widening a route
    designed for remote callers.

    Returns 200 ``{"build_sha": "<40-hex sha>"}``, or ``""`` whenever the image
    carries no baked commit — an unstamped dev checkout, or a working-tree build
    whose ``COMMIT`` still holds the unsubstituted export-subst placeholder.
    Empty reads as "no answer" to a comparator, which then falls back safely; a
    plausible-but-wrong value can never equal HEAD and would look like permanent
    drift. **Absent beats wrong.**

    THE VALUE IS BUILD-BOUND, NOT RUNTIME-RESOLVED (punch 538 / N-523). It comes
    from ``_build_sha.baked_build_sha()`` — the file the Containerfile baked at
    ``/app/VERSION`` — and NOT from ``_resolve_version()`` / ``app.state.version``.
    That mattered because ``_resolve_version()`` USED TO prefer
    ``EMAIL_TRIAGE_VERSION`` / ``GIT_SHA`` when set, as a documented convenience
    for ``/health`` and ``/health/detail`` where a human reads the value; here a
    scanner ACTS on it, reading the manifests at the reported commit to decide
    whether an advisory is already fixed, so an older image reporting a newer
    commit silenced advisories whose fixes were not running. **That override has
    since been REMOVED from both surfaces** — the operator directed it gutted on
    2026-09-29, so ``/health``'s ``version`` no longer reads the environment
    either, and the two-resolver split is now about SHAPE and reader (a short
    sha or a release tag is a wanted answer on ``/health``; only a full commit
    sha is one here), not about who may be overridden. The same sha is on the
    image as the ``build.sha`` LABEL, which runtime env never could move, so the
    two can be cross-checked.

    This route deliberately has NO degraded/503 branch and never calls
    ``_compute_health_detail`` — that absence is the reason it is not the
    artifact ``30b503ad`` rejected, so it is pinned, not merely intended.

    CONSUMER CONTRACT — **any non-200 means UNKNOWN and MUST NOT be scored as
    drift.** Authentication needs the DB (``verify_api_key``), so a DB outage
    makes this route 500 even though build currency itself has zero DB
    dependency (``app.state.build_sha`` is read once at startup). A monitor must
    therefore distinguish "not current" (a 200 whose sha differs) from "cannot
    tell" (anything else). Scoring a 500 as drift would page for the wrong
    reason and, worse, could trigger a remediation deploy during a database
    incident. A backup or migration holding the write lock can also stall this
    up to ``busy_timeout`` (30s), which a monitor with a shorter HTTP timeout
    sees as a timeout — same rule: UNKNOWN, not drift.

    THIS ROUTE IS THE PRIMARY PATH for steady-state monitoring. The same sha is
    also on the image as the ``build.sha`` LABEL, and both SME reviews initially
    recommended polling that instead — because each costed only the local
    ``last_used_at`` write this route incurs. That recommendation was REVERSED by
    the operator, correctly: ``podman inspect`` needs a host shell and takes locks
    on the SHARED podman runtime, so a scheduled inspect loop serializes against
    every other container on the host and can degrade containers unrelated to
    this one. The local write is a cost paid by this app alone; the inspect loop
    is a cost paid by the whole host. An HTTP GET takes no host-level lock.

    The LABEL stays useful for a ONE-OFF forensic check, or where HTTP is
    unreachable — not as the recurring poll.

    CADENCE: **poll every 10-15 MINUTES. 60s is an absolute ceiling on
    frequency, not a target** — the fastest anything is ever allowed to go, for
    a specific justified reason, never the default. A build sha changes only on
    deploy, so polling a few-times-a-week value at 1-minute resolution buys
    nothing and costs a ``last_used_at`` write per poll on the single-writer DB.
    At 10 minutes drift is caught within one interval, far inside any sane
    remediation window, for ~1/15th the write load of a 60s poll. If a faster
    interval ever seems necessary, the real requirement is event-driven
    notification on deploy — build that instead of tightening this.
    """
    from fastapi.responses import RedirectResponse

    # Same off-loop routing as health_detail: get_current_user does a sync DB
    # read (and a last_used_at write) on the shared connection.
    user = await db_call(_get_current_user, request)
    if user is None:
        # A monitor is an API client, not a browser: answer 401 rather than
        # bouncing it to /login, so a misconfigured token surfaces as an auth
        # failure instead of an HTML redirect the client will misparse.
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return api_error_response("authentication required", status_code=401, purpose="misc")
        return RedirectResponse("/login", status_code=303)

    # READ THE BAKED VALUE, NOT THE RESOLVED ONE (punch 538 / N-523). This used
    # to read `app.state.version`, which is `_resolve_version()` — and that
    # function USED TO return `EMAIL_TRIAGE_VERSION` / `GIT_SHA` VERBATIM when
    # set, ahead of the baked /app/VERSION file. So a runtime env var could name
    # any commit it liked, on any image. A scanner reads the manifests AT the
    # sha this route reports and treats an advisory as fixed if that commit
    # carries the fix, so an older image reporting a newer commit silences
    # advisories whose fixes are not running: the control fails OPEN, on a field
    # whose name says "build". `app.state.build_sha` is `_build_sha.baked_build_sha()`,
    # which reads the file the Containerfile baked and nothing else.
    #
    # The override is now GONE from the other surface too: the operator directed
    # it removed on 2026-09-29, so `_resolve_version()` no longer consults the
    # environment either and /health's `version` is build-bound as well. This
    # route's independence from it therefore no longer rests on that split — it
    # rests on reading a different field, which is the stronger arrangement and
    # the one pinned in tests/test_web/test_health_build_endpoint.py.
    #
    # Then SHAPE-VALIDATE, do not sentinel-filter. The resolver already rejects
    # the placeholders it knows, but enumerating sentinels loses that race by
    # construction — the next new non-sha value is unguarded again. Asserting the
    # SHAPE makes "absent beats wrong" true by construction: anything that is not
    # a full commit sha is not an answer, so we say so with "" and let the
    # consumer fall back. A plausible-but-wrong value can never equal HEAD and
    # would read as permanent drift — a security fix that looks eternally
    # un-deployed on a HIPAA-class service.
    build_sha = _served_build_sha(request)

    # `version` = the RELEASE TAG (pyproject / installed dist metadata), a
    # different question from `build_sha`: "which release line is this" vs
    # "which commit". Both are build identifiers of the same sensitivity class —
    # neither is the detail body, neither is an oracle over anything — so adding
    # it does not touch the narrowness argument. The payload stays a CLOSED,
    # enumerated set of two build identifiers; the pin asserts exactly that set,
    # so this is still a wall rather than an open door.
    try:
        from importlib.metadata import version as _dist_version

        release = _dist_version("email-triage")
    except Exception:
        # Not installed as a distribution (source checkout / odd packaging).
        # Empty, never a placeholder — same "absent beats wrong" rule.
        release = ""

    return {"build_sha": build_sha, "version": release}


# The CLOSED key set of /health/runtime-deps. Declared here, next to the route,
# and asserted by `test_n527_runtime_deps_route_pin`: the safety argument for
# this route is payload narrowness, so a new key must be argued for rather than
# arriving by drift.
_RUNTIME_DEPS_KEYS = frozenset({
    "build_sha",
    "python",
    "runtime_deps_present",
    "distributions",
    "image_manifest_sha256",
    "installed_manifest_sha256",
    "runtime_on_sys_path",
    # Punch 552 / N-555: the drift gate's own bool (``runtime_marker_status``),
    # from the same record as the keys above, so it adds no host fact. The
    # reason text is deliberately NOT here: ``set_mismatch`` detail names
    # packages and versions, the targeting map this route's admin gate withholds.
    "runtime_verified",
    # Punch 734 (design_2026-10-15_os_packages_on_health_runtime_deps_for_cve_arc):
    # the image's Debian packages, keyed by source package, so cve-arc can match
    # OS advisories (OpenSSL is Debian's libcrypto, declared in no lock file).
    # An unreadable status file is os_packages_error, never an empty map.
    "os_release",
    "os_packages",
    "os_packages_unstateable",
    "os_packages_error",
    # Punch 647: libraries vendored INSIDE installed packages (pip/_vendor, the
    # stdlib's ensurepip wheel), which no dist-info scan sees. Carriers are named
    # relative to a root label, never by absolute path.
    "vendored",
    "vendored_error",
    # Punch 848 (design_2026-11-04_bundled_runtime_deps_key_for_cve_arc): what a
    # wheel bundles beyond Python, from its PEP 770 dist-info SBOMs and auditwheel
    # ``.libs`` (cryptography's static OpenSSL was in no other record). A separate
    # key, since cve-arc reads ``vendored`` as PyPI. Carriers are distribution names.
    "bundled",
    "bundled_error",
})


@router.get("/health/runtime-deps", include_in_schema=True)
async def health_runtime_deps(request: Request) -> Any:
    """What is installed on the runtime-deps volume. ADMIN principals only.

    WHY THIS ROUTE EXISTS
    =====================
    The embedding feature pip-installs ~18 distributions into
    ``/app/data/runtime-deps``, which is a HOST BIND MOUNT and therefore survives
    every image rebuild. No manifest in the repository describes it, because the
    install happens AFTER the build — so an external scanner reading this repo at
    the deployed commit cannot see those packages at all. cve-arc measured the
    consequence on 2026-09-29: 18 distributions dated 2026-05-18, 104 OSV records
    (64 unique CVEs, one CRITICAL), invisible to every scanner we run.

    A file in the repo cannot answer this and neither can our own DB row: both
    describe an INTENTION. This route reports the DISK, scanned per request.

    WHY ADMIN, WHERE /health/build IS ANY AUTHENTICATED PRINCIPAL
    ============================================================
    ``health_build``'s narrowness argument turns on the payload being one opaque
    identifier — no counters, no oracle. A LIST OF INSTALLED PACKAGE VERSIONS is
    a different object: it is a targeting map, which is exactly what an attacker
    wants before choosing an exploit. Least privilege means the lowest role that
    answers the question, and for a version inventory that role is admin. Same
    machinery as ``/health/detail`` (``get_current_user`` → ``is_admin``), so no
    new principal kind, role, scope or token is introduced by this change.

    The ops-token bypass is deliberately NOT honoured, for the reason
    ``health_build`` states: that token is the container-loopback CLI path
    (``podman exec … curl https://localhost``) and has no business widening a
    route designed for remote callers.

    THE MONITOR PATH (punch 420, N-535/N-536)
    =========================================
    The gate is ``admin OR health_ro``. The operator chose two independent fences
    for the external scanner's credential (2026-09-29): a ``health_ro`` ROLE that
    reaches only an allowlist of read routes — ``GET /health``,
    ``GET /health/build``, ``GET /health/runtime-deps``, never ``/health/detail`` —
    and a route-SCOPED api key (``api_keys.scope``, a JSON list of exact
    ``METHOD /path`` entries enforced at the Bearer seam, with an enforced
    expiry). Either fence alone bounds the credential, and neither depends on the
    principal owning no data. **No admin key is issued to the scanner.** Both
    fences are enforced at the auth seam (``get_current_user``), so this handler
    only widens its own gate to the role the allowlist (``HEALTH_RO_ALLOWED_ROUTES``)
    already names; it adds no route reach. See the N-529 and N-536 register rows.

    NO DEGRADED BRANCH, NO DETAIL BODY
    ==================================
    This route never calls ``_compute_health_detail`` and has no 503 branch —
    that absence is the reason it is not the artifact the 2026-06-13 review
    rejected, so it is pinned rather than merely intended. Every key below is a
    build or inventory fact. Deliberately ABSENT: filesystem paths, the
    install-state row's ``runtime_deps_path`` / ``current_file`` / error text /
    attempt counts / timestamps, and every ``/health/detail`` field.

    ``build_sha`` comes from the BAKED ``/app/VERSION`` (``_build_sha``), never
    from ``EMAIL_TRIAGE_VERSION``/``GIT_SHA``: a comparator must not be handed a
    value that whoever started the container chose. ``""`` means "no answer" —
    absent beats wrong, and a non-200 means UNKNOWN and must not be scored as
    drift (same consumer contract as ``/health/build``).

    The scan IMPORTS NOTHING from the volume: it reads ``*.dist-info`` directory
    names off disk. Importing a possibly-vulnerable package to find out its
    version would be the exact hazard the caller is asking about.
    ``distributions`` maps a PEP-503 name to EVERY version found, so more than
    one means the tree is ambiguous about what imports — never first-wins.
    """
    from fastapi.responses import RedirectResponse

    # Same off-loop routing as its siblings: get_current_user does a sync DB
    # read (and a last_used_at write) on the shared connection.
    user = await db_call(_get_current_user, request)
    if user is None:
        # A monitor is an API client, not a browser: answer 401 rather than
        # bouncing it to /login, so a misconfigured token surfaces as an auth
        # failure instead of HTML the client will misparse.
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return api_error_response("authentication required", status_code=401, purpose="misc")
        return RedirectResponse("/login", status_code=303)
    # N-222 R22: is_admin bool SSOT (fail-closed on a missing/odd role).
    # : ``admin OR health_ro`` -- the monitor role the seam already confines
    # to HEALTH_RO_ALLOWED_ROUTES.
    if not (is_admin(user) or is_health_ro(user)):
        return api_error_response("admin role required", status_code=403, purpose="misc")

    from email_triage.embedding_bits import (
        runtime_install_record,
        runtime_site_packages_candidates,
    )
    from email_triage.image_inventory import (
        bundled_inventory,
        os_package_inventory,
        vendored_inventory,
    )

    # The one non-mutating snapshot funnel — the same one the admin install card
    # renders from, so the page and this route cannot disagree about whether an
    # install is verified. It never touches sys.path.
    #
    # asyncio.to_thread, NOT db_call: this is filesystem I/O (a directory listing
    # plus two small file reads) and touches no DB. Routing it through db_call
    # would take the process-wide DB write lock for the whole scan and stall
    # every other DB caller — the same reasoning as ``embedding_reverify``'s.
    record = await asyncio.to_thread(runtime_install_record)
    # Punch 734 / 647 / 848: file reads only (dpkg status, manifests, a wheel's
    # zip index, SBOMs, a .libs library's bytes), each of which never raises: a
    # failure is an explicit *_error key.
    os_inv = await asyncio.to_thread(os_package_inventory)
    runtime_roots = runtime_site_packages_candidates()
    vendored = await asyncio.to_thread(vendored_inventory, runtime_roots)
    bundled = await asyncio.to_thread(bundled_inventory, runtime_roots)

    return {
        "build_sha": _served_build_sha(request),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "runtime_deps_present": record["present"],
        "distributions": record["distributions"],
        "image_manifest_sha256": record["image_manifest_sha256"],
        "installed_manifest_sha256": record["installed_manifest_sha256"],
        "runtime_on_sys_path": record["on_sys_path"],
        "runtime_verified": bool(record["verified"]),
        "os_release": os_inv["os_release"],
        "os_packages": os_inv["os_packages"],
        "os_packages_unstateable": os_inv["os_packages_unstateable"],
        "os_packages_error": os_inv["os_packages_error"],
        "vendored": vendored["vendored"],
        "vendored_error": vendored["vendored_error"],
        "bundled": bundled["bundled"],
        "bundled_error": bundled["bundled_error"],
    }
