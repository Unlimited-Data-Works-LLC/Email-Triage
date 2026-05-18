"""Daily health / summary email (#27) + admin-notification channel (CR-2c/2d).

Admin-facing "did the gateway die overnight?" push signal. Renders an
HTML + text email from current app state and ships it over the existing
SMTP helper.

Recipient destination is the canonical
:class:`email_triage.config.AdminEmailConfig` field; the legacy
``HealthEmailConfig.recipients`` is read as a fallback for the
deprecation cycle. The same destination is used by
:func:`send_update_failed_email` (CR-2d) — fired by ``scripts/deploy.sh``
when a post-apply health check fails and snapshot rollback runs — and
will be used by any future admin-targeted email.

PHI stance
----------
No message-level content is ever included — no sender, subject, or
body. Account-level identity (account name, account id) is OK.  When
system HIPAA mode is on, the ``include_hipaa_events`` section is
*dropped entirely* — the operator already knows PHI is flowing and
the summary is redundant.

Attention logic
---------------
Subject gets the ``⚠ Attention`` suffix when:

* Any active watcher's state reports ``status == "error"`` or has been
  ``disconnected`` for more than 15 minutes.
* Any ERROR-level ``log_entries`` row in the last 24h.
* Triage error-rate above ``error_rate_threshold_pct``.

Otherwise the subject line is ``OK``.

All assembly is pure — it takes a DB connection, config, and an
optional ``WatcherManager`` — so tests can feed it synthetic state
without running the full lifespan stack.
"""

from __future__ import annotations

import json as _json
import smtplib
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from email_triage.config import TriageConfig
from email_triage.triage_logging import get_logger, is_hipaa_mode
from email_triage.web.auth import format_from_header

log = get_logger("web.daily_health")


# ---------------------------------------------------------------------------
# Admin-recipient resolution (CR-2c)
# ---------------------------------------------------------------------------

#: Module-level guard so the deprecation log fires once per process,
#: not once per email. Re-set in tests via ``_reset_deprecation_warning``.
_legacy_recipient_warning_logged = False


def _reset_deprecation_warning() -> None:
    """Test hook — clear the once-per-process deprecation guard."""
    global _legacy_recipient_warning_logged
    _legacy_recipient_warning_logged = False


def resolve_admin_recipients(config: TriageConfig) -> list[str]:
    """Return the active admin-notification recipient list.

    CR-2c rename. Canonical destination is
    ``config.admin_email.recipients``; ``config.health_email.recipients``
    is a read-fallback shim during the deprecation cycle. The fallback
    path logs a single ``WARNING`` per process so the operator knows to
    migrate their YAML, then continues to honour the legacy value so
    nothing breaks mid-cycle.
    """
    new = list(getattr(config.admin_email, "recipients", []) or [])
    if new:
        return new
    legacy = list(getattr(config.health_email, "recipients", []) or [])
    if legacy:
        global _legacy_recipient_warning_logged
        if not _legacy_recipient_warning_logged:
            log.warning(
                "health_email.recipients is deprecated — use "
                "admin_email.recipients instead. Old key still honoured "
                "for this release cycle.",
            )
            _legacy_recipient_warning_logged = True
        return legacy
    return []


# ---------------------------------------------------------------------------
# GitHub Releases cache (CR-2c — update-available section)
# ---------------------------------------------------------------------------

#: ``(fetched_at_monotonic, payload_or_none)`` keyed by URL. 1-hour TTL
#: by default; tests reset via ``_reset_release_cache``. The cache lives
#: at module scope because the daily-health email renders once a day in
#: production but tests / "Send now" can fire repeatedly; caching the
#: HTTP fetch avoids hammering GitHub during demos and rate-limit
#: surfaces.
_release_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}
_RELEASE_CACHE_TTL_SECONDS = 3600.0
_RELEASE_FETCH_TIMEOUT_SECONDS = 5.0


def _reset_release_cache() -> None:
    """Test hook — drop the cached Releases response."""
    _release_cache.clear()


def fetch_latest_release(
    url: str,
    *,
    now_monotonic: float | None = None,
) -> dict[str, Any] | None:
    """Return the GitHub Releases ``/latest`` JSON, cached for 1 hour.

    On any fetch failure (network, HTTP error, non-JSON body) returns
    ``None`` — callers render fallback text instead of crashing the
    email. Cache is keyed by URL so a config change picks up
    immediately.

    Pure-ish: the only side effects are the HTTP request and the
    module-level cache; both are dropped via ``_reset_release_cache``
    in tests. The fetch path is monkeypatched at
    ``urllib.request.urlopen`` so tests don't touch the network.
    """
    now = now_monotonic if now_monotonic is not None else time.monotonic()
    cached = _release_cache.get(url)
    if cached is not None:
        fetched_at, payload = cached
        if now - fetched_at < _RELEASE_CACHE_TTL_SECONDS:
            return payload

    payload: dict[str, Any] | None = None
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "email-triage-daily-health",
            },
        )
        with urllib.request.urlopen(
            req, timeout=_RELEASE_FETCH_TIMEOUT_SECONDS,
        ) as resp:
            body = resp.read().decode("utf-8")
        data = _json.loads(body)
        if isinstance(data, dict):
            payload = data
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, OSError) as exc:
        log.warning(
            "GitHub Releases fetch failed",
            url=url, error=str(exc),
        )
        payload = None
    _release_cache[url] = (now, payload)
    return payload


def gather_update_available_section(
    config: TriageConfig,
    *,
    db: sqlite3.Connection | None = None,
    db_path: str | None = None,
) -> dict[str, Any] | None:
    """Build the daily-health "update available" section payload.

    Returns ``None`` when the install is already up to date (no section
    rendered — avoids the noise of a "you're up to date" line every
    morning). Otherwise returns:

        {
            "status": "update_available" | "incompatible_rollback"
                      | "downgrade_not_supported",
            "explanation": "<plain-English line>",
            "current_version": "<app __version__>",
            "latest_version": "<release tag_name>" | None,
            "release_url": "<html_url>" | None,
            "release_notes": "<body>" | None,
            "release_notes_unavailable": bool,
        }

    The latest-version block can be partially populated when the
    GitHub fetch fails — the section still renders the version-status
    half (which is local-only), with a "release notes unavailable"
    fallback line for the GitHub half.

    Schema version source: when ``db`` (live connection) is supplied
    we read ``schema_migrations`` from that connection — this is the
    correct path for the daily-health render, because the email is
    built off the same DB the supervisor is using. ``db_path`` is the
    fallback for the CLI / banner paths that have a path but no open
    connection. If both are missing the function returns ``None``
    rather than guess at a "fresh install" verdict.
    """
    try:
        from email_triage.version import (
            STATUS_UP_TO_DATE, compute_version_status,
            read_previous_schema_caps, read_target_schema_caps,
        )
    except Exception as exc:
        log.warning(
            "gather_update_available_section: version probe failed",
            error=str(exc),
        )
        return None

    # Resolve the live DB schema version. Connection path wins because
    # it sidesteps the "DB at the configured path doesn't exist in the
    # test harness" trap that would otherwise return a phantom
    # schema=0.
    db_schema = 0
    if db is not None:
        try:
            row = db.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            if row and row[0] is not None:
                db_schema = int(row[0])
        except sqlite3.Error:
            db_schema = 0
    elif db_path:
        try:
            from email_triage.version import read_db_schema_version
            db_schema = read_db_schema_version(db_path)
        except Exception:
            db_schema = 0
    else:
        # No way to learn the live schema — skip the section rather
        # than render a misleading verdict.
        return None

    target_caps = read_target_schema_caps()
    if target_caps <= 0 or db_schema <= 0:
        # Either the source migrations registry didn't load (broken
        # checkout) or the DB has no schema_migrations rows (truly
        # fresh, pre-init). Either way: silence is the safer surface.
        return None

    try:
        previous_caps = read_previous_schema_caps()
        vs = compute_version_status(
            db_schema_version=db_schema,
            target_schema_caps=target_caps,
            previous_schema_caps=previous_caps,
        )
    except Exception as exc:
        log.warning(
            "gather_update_available_section: compute_version_status failed",
            error=str(exc),
        )
        return None

    if vs.status == STATUS_UP_TO_DATE:
        return None

    section: dict[str, Any] = {
        "status": vs.status,
        "explanation": vs.explanation,
        "current_version": vs.app_version,
        "latest_version": None,
        "release_url": None,
        "release_notes": None,
        "release_notes_unavailable": True,
    }

    url = (
        getattr(config.admin_email, "release_check_url", "")
        or ""
    ).strip()
    if not url:
        return section
    payload = fetch_latest_release(url)
    if payload is None:
        return section
    section["latest_version"] = payload.get("tag_name") or None
    section["release_url"] = payload.get("html_url") or None
    body = (payload.get("body") or "").strip()
    if body:
        section["release_notes"] = body
        section["release_notes_unavailable"] = False
    return section


# ---------------------------------------------------------------------------
# Retry-queue threshold section (#175 R-B)
# ---------------------------------------------------------------------------

# Per-account threshold: an account with this many or more deads in
# the last 24h fires the per-account banner + email section.
RETRY_DEADS_PER_ACCOUNT_THRESHOLD: int = 3

# Install-wide threshold: total deads across every account in 24h
# that fires the install-wide banner + section.
RETRY_DEADS_INSTALL_WIDE_THRESHOLD: int = 5


def gather_retry_deads_section(
    db: sqlite3.Connection,
) -> dict[str, Any] | None:
    """Build the retry-deads section dict. Returns ``None`` when no
    threshold is crossed (silent — no email section, no banner).

    Shape on threshold-crossing:

        {
            "install_wide": bool,        # ≥5 deads in 24h
            "dead_24h": int,             # total deads in 24h
            "per_account": [             # accounts with ≥3 deads
                {
                    "account_id": int,
                    "account_label": str,
                    "owner": str,
                    "count": int,
                    "breakdown": {"<reason>": int, ...},
                },
                ...
            ],
        }

    Failure-safe: returns ``None`` on any DB error (missing table,
    pre-migration install, schema mismatch). The caller treats
    ``None`` as "nothing to surface" — identical to the clean-day
    code path.
    """
    if db is None:
        return None
    try:
        from datetime import datetime, timedelta, timezone
        since = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        # Install-wide total.
        row = db.execute(
            "SELECT COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND updated_at >= ?",
            (since,),
        ).fetchone()
        if row is None:
            return None
        dead_24h = int(row["c"] if hasattr(row, "keys") else row[0])

        # Per-account aggregate.
        per_account_rows = db.execute(
            "SELECT q.account_id, COUNT(*) AS c, "
            "       COALESCE(ea.name, '') AS account_name, "
            "       COALESCE(u.name, u.email, '') AS owner "
            "FROM watcher_retry_queue q "
            "LEFT JOIN email_accounts ea ON ea.id = q.account_id "
            "LEFT JOIN users u ON u.id = ea.user_id "
            "WHERE q.state = 'dead' AND q.updated_at >= ? "
            "GROUP BY q.account_id "
            "HAVING c >= ?",
            (since, RETRY_DEADS_PER_ACCOUNT_THRESHOLD),
        ).fetchall()

        per_account: list[dict[str, Any]] = []
        for r in per_account_rows:
            acct_id = r["account_id"] if hasattr(r, "keys") else r[0]
            count = int(r["c"] if hasattr(r, "keys") else r[1])
            name = r["account_name"] if hasattr(r, "keys") else r[2]
            owner = r["owner"] if hasattr(r, "keys") else r[3]
            # Breakdown by dead_reason for this account.
            bd_rows = db.execute(
                "SELECT dead_reason, COUNT(*) AS c "
                "FROM watcher_retry_queue "
                "WHERE state = 'dead' AND updated_at >= ? "
                "  AND account_id = ? "
                "GROUP BY dead_reason",
                (since, acct_id),
            ).fetchall()
            breakdown: dict[str, int] = {}
            for br in bd_rows:
                reason = br["dead_reason"] if hasattr(br, "keys") else br[0]
                bcount = int(br["c"] if hasattr(br, "keys") else br[1])
                if reason:
                    breakdown[reason] = bcount
            per_account.append({
                "account_id": acct_id,
                "account_label": name or f"#{acct_id}",
                "owner": owner or "",
                "count": count,
                "breakdown": breakdown,
            })

        install_wide = dead_24h >= RETRY_DEADS_INSTALL_WIDE_THRESHOLD

        # Silent when neither threshold fires.
        if not install_wide and not per_account:
            return None

        return {
            "install_wide": install_wide,
            "dead_24h": dead_24h,
            "per_account": per_account,
        }
    except Exception:
        # DB / table missing or schema mismatch — silent.
        return None


# ---------------------------------------------------------------------------
# State gathering
# ---------------------------------------------------------------------------

def _iso_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def gather_health_state(
    db: sqlite3.Connection,
    config: TriageConfig,
    watcher_manager: Any = None,
    *,
    now: datetime | None = None,
    app: Any = None,
) -> dict[str, Any]:
    """Snapshot everything the digest renders from.

    Split out so ``assemble_daily_health_email`` is a pure function of
    its state dict — easy to test at the seam.

    ``app`` is the FastAPI instance (optional). When supplied, the
    listener-restart-pending check runs and may add an entry to
    ``attention_reasons`` so the daily digest signals the operator
    even on a day when nothing else is wrong. (#81)
    """
    now = now or datetime.now(timezone.utc)
    since_24h = (now - timedelta(hours=24)).isoformat()

    state: dict[str, Any] = {
        "now": now,
        "hipaa_mode": is_hipaa_mode(),
        "attention_reasons": [],
    }

    # --- Ingestion (per-account, all providers) --------------------------
    # Single source of truth — fold the same per-account verdict the
    # /health endpoint and dashboard chip use. Adding a new provider
    # (e.g. O365 Graph) means one branch in WatcherManager._push_state_for
    # and every digest section automatically picks it up.
    account_states_list: list[dict[str, Any]] = []
    if watcher_manager is not None:
        try:
            account_states_list = watcher_manager.account_states(db)
        except Exception:
            account_states_list = []
    state["account_states"] = account_states_list

    # Per-provider aggregate (option C — primary mode wins, sums = total).
    providers: dict[str, dict] = {}
    for s in account_states_list:
        p = s.get("provider", "unknown")
        b = providers.setdefault(p, {
            "total": 0, "push": 0, "poll": 0,
            "uncovered": 0, "push_plus_poll": 0,
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
            _label = s.get("account_name") or f"#{s['account_id']}"
            _owner = f" ({s['owner']})" if s.get("owner") else ""
            state["attention_reasons"].append(
                f"{_label}{_owner}: {s['alert'].replace('_', ' ')}"
            )
    state["providers"] = providers

    # Process-level counters.
    poll_registered = 0
    poll_fresh = 0
    if watcher_manager is not None:
        try:
            poll_registered, poll_fresh = watcher_manager.poll_counts()
        except Exception:
            pass
    state["poll"] = {"registered": poll_registered, "fresh": poll_fresh}
    mb_total = 0
    mb_watching = 0
    if watcher_manager is not None:
        try:
            mb_total, mb_watching = watcher_manager.mailbox_counts()
        except Exception:
            pass
    state["mailboxes"] = {"total": mb_total, "watching": mb_watching}

    # --- Log errors -------------------------------------------------------
    error_rows: list[dict[str, Any]] = []
    error_count_24h = 0
    warning_count_24h = 0
    try:
        error_count_24h = db.execute(
            "SELECT COUNT(*) FROM log_entries WHERE level = 'ERROR' AND ts >= ?",
            (since_24h,),
        ).fetchone()[0]
        warning_count_24h = db.execute(
            "SELECT COUNT(*) FROM log_entries WHERE level = 'WARNING' AND ts >= ?",
            (since_24h,),
        ).fetchone()[0]
        rows = db.execute(
            "SELECT ts, level, logger, message FROM log_entries "
            "WHERE level IN ('ERROR', 'WARNING') AND ts >= ? "
            "ORDER BY id DESC LIMIT 10",
            (since_24h,),
        ).fetchall()
        error_rows = [dict(r) for r in rows]
    except sqlite3.Error:
        pass
    state["error_count_24h"] = error_count_24h
    state["warning_count_24h"] = warning_count_24h
    state["error_rows"] = error_rows
    if error_count_24h > 0:
        state["attention_reasons"].append(
            f"{error_count_24h} ERROR log entries in last 24h"
        )

    # --- Triage activity --------------------------------------------------
    triage_total = 0
    triage_accounts: list[dict[str, Any]] = []
    triage_error_rate = 0.0
    try:
        rows = db.execute(
            "SELECT account_id, account_name, "
            "       SUM(total_messages) AS total, "
            "       COUNT(*) AS runs, "
            "       AVG(elapsed_secs) AS avg_elapsed "
            "FROM triage_runs WHERE created_at >= ? "
            "GROUP BY account_id, account_name "
            "ORDER BY total DESC",
            (since_24h,),
        ).fetchall()
        for r in rows:
            triage_accounts.append({
                "account_id": r["account_id"],
                "account_name": r["account_name"],
                "total": r["total"] or 0,
                "runs": r["runs"] or 0,
                "avg_elapsed": round(r["avg_elapsed"] or 0.0, 2),
            })
            triage_total += r["total"] or 0
        # Error rate = runs with non-empty errors_json / total runs.
        counts = db.execute(
            "SELECT COUNT(*) AS runs, "
            "SUM(CASE WHEN errors_json != '[]' AND errors_json != '' THEN 1 ELSE 0 END) AS err_runs "
            "FROM triage_runs WHERE created_at >= ?",
            (since_24h,),
        ).fetchone()
        if counts and counts["runs"]:
            triage_error_rate = (counts["err_runs"] or 0) * 100.0 / counts["runs"]
    except sqlite3.Error:
        pass
    state["triage_total"] = triage_total
    state["triage_accounts"] = triage_accounts
    state["triage_error_rate"] = round(triage_error_rate, 2)
    if triage_error_rate > max(config.health_email.error_rate_threshold_pct, 0):
        state["attention_reasons"].append(
            f"triage error rate {triage_error_rate:.1f}% exceeds threshold"
        )

    # --- Stale-auth accounts ---------------------------------------------
    # Surface accounts whose OAuth refresh / IMAP password is no longer
    # valid. Set by _maybe_mark_auth_stale on a "Token has been expired
    # or revoked" / "AUTHENTICATIONFAILED" exception. Cleared
    # automatically on the next successful provider call.
    stale_auth_accounts: list[dict[str, Any]] = []
    try:
        rows = db.execute(
            "SELECT s.key, s.value_json, ea.name AS account_name, ea.id AS account_id "
            "FROM settings s "
            "LEFT JOIN email_accounts ea "
            "  ON ea.id = CAST(SUBSTR(s.key, length('auth_stale:') + 1) AS INTEGER) "
            "WHERE s.key LIKE 'auth_stale:%'"
        ).fetchall()
        import json as _json
        for r in rows:
            try:
                payload = _json.loads(r["value_json"]) if r["value_json"] else {}
            except (ValueError, TypeError):
                payload = {}
            if not payload.get("at"):
                continue
            stale_auth_accounts.append({
                "account_id": r["account_id"],
                "account_name": r["account_name"] or "(unknown)",
                "at": payload.get("at"),
                "reason": (payload.get("reason") or "")[:200],
            })
    except sqlite3.Error:
        pass
    state["stale_auth_accounts"] = stale_auth_accounts
    if stale_auth_accounts:
        names = ", ".join(a["account_name"] for a in stale_auth_accounts[:3])
        more = (
            f" (+{len(stale_auth_accounts) - 3} more)"
            if len(stale_auth_accounts) > 3 else ""
        )
        state["attention_reasons"].append(
            f"{len(stale_auth_accounts)} account(s) need re-authentication: {names}{more}"
        )

    # --- HIPAA events -----------------------------------------------------
    hipaa_events_count = 0
    hipaa_recent_actors: list[str] = []
    try:
        hipaa_events_count = db.execute(
            "SELECT COUNT(*) FROM hipaa_access_events WHERE ts >= ?",
            (since_24h,),
        ).fetchone()[0]
        actor_rows = db.execute(
            "SELECT DISTINCT u.email FROM hipaa_access_events ae "
            "LEFT JOIN users u ON u.id = ae.actor_user_id "
            "WHERE ae.ts >= ? AND u.email IS NOT NULL LIMIT 5",
            (since_24h,),
        ).fetchall()
        hipaa_recent_actors = [r[0] for r in actor_rows if r[0]]
    except sqlite3.Error:
        pass
    state["hipaa_events_count"] = hipaa_events_count
    state["hipaa_recent_actors"] = hipaa_recent_actors

    # --- BAA expirations (#169 Wave 2-α — I7) ------------------------------
    # Pull the bucket data here so the renderer can decide whether to
    # surface a section. Returns ``None`` when nothing is in scope so
    # the email isn't bloated by a "BAA: nothing to report" line on a
    # boringly healthy day.
    try:
        from email_triage.baa_expiry import gather_for_daily_email
        state["baa_expirations"] = gather_for_daily_email(db)
    except Exception:
        state["baa_expirations"] = None

    # --- Update available (CR-2c) -----------------------------------------
    # Mirrors the BAA pattern: returns ``None`` on a clean "up to date"
    # day so the email body doesn't grow a redundant "no update" line.
    # The render path keys off this being non-None. Pass ``db`` so the
    # schema-version read uses the live connection rather than the
    # filesystem path (avoids the "configured db_path doesn't exist on
    # this machine" misfire).
    state["update_available"] = None
    if getattr(config.health_email, "include_update_available", True):
        try:
            state["update_available"] = gather_update_available_section(
                config, db=db,
            )
        except Exception:
            # Defensive — a broken version probe never blocks the digest.
            state["update_available"] = None
    # Only escalate to Attention for the dangerous states (rollback
    # incompat, downgrade-not-supported). Plain "update available" is
    # informational and rides in its own section without poking the
    # subject-line flag — operators don't want a daily ⚠ until they
    # apply.
    if state["update_available"]:
        _u_status = state["update_available"].get("status")
        if _u_status in {"incompatible_rollback", "downgrade_not_supported"}:
            state["attention_reasons"].append(
                "Update status: "
                + state["update_available"].get("explanation", _u_status)
            )

    # --- Retry-queue dead-pattern section (#175 R-B) ---------------------
    # Surface accounts piling up abandoned retries, or an install-wide
    # spike. Returns ``None`` on a clean day so the email body doesn't
    # grow a redundant "retry queue: nothing to report" line.
    try:
        state["retry_deads"] = gather_retry_deads_section(db)
    except Exception:
        state["retry_deads"] = None
    if state.get("retry_deads"):
        rd = state["retry_deads"]
        if rd.get("install_wide"):
            state["attention_reasons"].append(
                f"{rd['dead_24h']} messages abandoned in retry queue "
                "in last 24h (install-wide)"
            )
        for acct in rd.get("per_account", []) or []:
            state["attention_reasons"].append(
                f"{acct['account_label']}: {acct['count']} messages "
                "abandoned in retry queue in last 24h"
            )

    # --- API key lifecycle ------------------------------------------------
    api_key_events_count = 0
    api_key_events_recent: list[dict[str, Any]] = []
    try:
        api_key_events_count = db.execute(
            "SELECT COUNT(*) FROM api_key_events WHERE ts >= ?",
            (since_24h,),
        ).fetchone()[0]
        rows = db.execute(
            "SELECT ake.ts, ake.event, ake.name, ake.source, "
            "       au.email AS actor_email, tu.email AS target_email "
            "FROM api_key_events ake "
            "LEFT JOIN users au ON au.id = ake.actor_user_id "
            "LEFT JOIN users tu ON tu.id = ake.target_user_id "
            "WHERE ake.ts >= ? ORDER BY ake.id DESC LIMIT 5",
            (since_24h,),
        ).fetchall()
        api_key_events_recent = [dict(r) for r in rows]
    except sqlite3.Error:
        pass
    state["api_key_events_count"] = api_key_events_count
    state["api_key_events_recent"] = api_key_events_recent

    # --- Queue + storage --------------------------------------------------
    log_row_count = 0
    try:
        log_row_count = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
    except sqlite3.Error:
        pass
    state["log_row_count"] = log_row_count

    # --- Pub/Sub (gated on #1 shipping) -----------------------------------
    # Until #1 lands there's no push_queue metric to surface; render
    # "not configured" so the section exists but isn't misleading.
    state["pubsub_configured"] = bool(config.push.gmail_topic_name)

    # --- O365 Graph subscriptions (#66) ---------------------------------
    # Same shape as gmail_push: total / active / expiring_in_24h /
    # errored. Errored or fully-expired-without-poll-fallback entries
    # bump attention_reasons.
    o365_block = {
        "total": 0,
        "accounts_with_active_subscriptions": 0,
        "expiring_in_24h": 0,
        "errored": 0,
        "rows": [],
    }
    try:
        from email_triage.web.db import (
            list_email_accounts, list_o365_subscriptions,
        )
        rows = list_o365_subscriptions(db)
        o365_block["total"] = len(rows)
        # Per feedback_no_account_id_alone.md — never render
        # `Account #1` alone. Pre-build an id->name map so
        # attention_reasons + row_dicts surface the operator-set
        # name; numeric id rides along as a tiebreaker only.
        _name_by_id: dict[int, str] = {}
        try:
            for a in list_email_accounts(db) or []:
                aid = a.get("id")
                if aid is not None:
                    _name_by_id[int(aid)] = (
                        a.get("name") or a.get("email_address") or ""
                    )
        except Exception:
            pass

        def _label(account_id) -> str:
            try:
                aid_int = int(account_id) if account_id is not None else None
            except (TypeError, ValueError):
                aid_int = None
            name = (
                _name_by_id.get(aid_int)
                if aid_int is not None else ""
            )
            if name and aid_int is not None:
                return f"{name} (id {aid_int})"
            if aid_int is not None:
                return f"id {aid_int}"
            return "(unknown account)"

        soon = now + timedelta(hours=24)
        for r in rows:
            status = (r.get("status") or "").strip()
            exp_raw = r.get("expiration_at") or ""
            try:
                exp = datetime.fromisoformat(
                    str(exp_raw).replace("Z", "+00:00"),
                )
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                exp = None
            row_dict = {
                "account_id": r.get("account_id"),
                "account_label": _label(r.get("account_id")),
                "subscription_id": r.get("subscription_id"),
                "expiration_at": exp_raw,
                "status": status,
                "error_count": r.get("error_count", 0),
                "error_last": r.get("error_last") or "",
            }
            if status == "errored":
                o365_block["errored"] += 1
                row_dict["bucket"] = "errored"
                state["attention_reasons"].append(
                    "Office 365 push subscription errored on "
                    f"{_label(r.get('account_id'))}"
                )
            elif exp is None or exp <= now:
                o365_block["errored"] += 1
                row_dict["bucket"] = "expired"
                state["attention_reasons"].append(
                    "Office 365 push subscription expired on "
                    f"{_label(r.get('account_id'))}"
                )
            else:
                o365_block["accounts_with_active_subscriptions"] += 1
                row_dict["bucket"] = "active"
                if exp <= soon:
                    o365_block["expiring_in_24h"] += 1
            o365_block["rows"].append(row_dict)
    except (sqlite3.Error, Exception):
        # Read failure shouldn't kill the digest.
        pass
    state["office365_push"] = o365_block

    # --- Gateway / container health placeholder ---------------------------
    # Minimal: if we can query the DB we're up. Detailed gateway probing
    # is out of scope for #27.
    state["gateway_ok"] = True

    # --- TLS cert expiry warning (#74) -----------------------------------
    # Manually-managed certs (institutional CA + self-signed) have no
    # auto-renewal hook. Daily-health surfaces a warning at 30 / 14 / 7
    # days before not_after so the operator has lead time. ACME-managed
    # certs renew themselves; this read just reports the active cert's
    # state regardless of how it got there.
    state["cert_expiry_warning"] = None
    try:
        from email_triage.tls_csr import cert_expiry_warning
        from pathlib import Path as _Path
        cd = getattr(getattr(config, "tls", None), "cert_dir", "")
        if cd:
            cert_dir = _Path(cd)
        else:
            cert_dir = _Path(config.persistence.db_path).parent / "certs"
        warn = cert_expiry_warning(cert_dir)
        if warn:
            state["cert_expiry_warning"] = warn
    except Exception:
        # Cert read failures shouldn't fail the health email build.
        pass

    # --- Listener-mode restart pending (#81) ------------------------------
    # When ``app`` is supplied (live process), compare the boot-time
    # listener mode to the saved value. Operator forgot to restart =>
    # the new toggle is silently ignored until the process bounces.
    # The chip on /admin/acme-status surfaces the same condition; this
    # branch hooks daily-health so an operator who set-and-forgot still
    # sees it in tomorrow morning's digest.
    state["listener_restart_pending"] = False
    if app is not None:
        try:
            from email_triage.web.app import is_listener_restart_pending
            if is_listener_restart_pending(app):
                state["listener_restart_pending"] = True
                state["attention_reasons"].append(
                    "Listener mode change pending — restart "
                    "email-triage to take effect"
                )
        except Exception:
            # Defensive: a bad import / state shouldn't kill the digest.
            pass

    return state


def is_interesting(state: dict[str, Any]) -> bool:
    """Return True when the digest should be sent in quiet mode.

    Anything that bumped an Attention reason, or any non-zero error /
    HIPAA / API-key activity, is interesting.  A clean day is dropped.
    """
    if state["attention_reasons"]:
        return True
    if state.get("error_count_24h", 0) > 0:
        return True
    if state.get("warning_count_24h", 0) > 0:
        return True
    if state.get("triage_total", 0) > 0:
        return True
    if state.get("hipaa_events_count", 0) > 0:
        return True
    if state.get("api_key_events_count", 0) > 0:
        return True
    if state.get("stale_auth_accounts"):
        return True
    if state.get("update_available"):
        return True
    if state.get("retry_deads"):
        return True
    return False


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render_html(state: dict[str, Any], config: TriageConfig) -> str:
    parts: list[str] = []
    parts.append(
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
    )
    parts.append(f'<h2>Daily health — {state["now"].strftime("%Y-%m-%d")}</h2>')

    # Attention banner.
    if state["attention_reasons"]:
        parts.append(
            '<div style="padding: 0.75rem 1rem; background: #fff4e5; '
            'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
            '<strong>⚠ Attention</strong><ul>'
        )
        for r in state["attention_reasons"]:
            parts.append(f"<li>{r}</li>")
        # TLS cert expiry warning rides in the same attention block --
        # operator's eye lands on it at the top of the email when
        # something else is also flagged. Plain rendering when nothing
        # else is flagged is below.
        if state.get("cert_expiry_warning"):
            parts.append(f"<li>{state['cert_expiry_warning']}</li>")
        parts.append("</ul></div>")
    elif state.get("cert_expiry_warning"):
        # Cert expiry alone surfaces as its own banner -- we don't
        # want it buried under a green "all green" header.
        parts.append(
            '<div style="padding: 0.75rem 1rem; background: #fff4e5; '
            'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
            f'<strong>⚠ Attention</strong><br>{state["cert_expiry_warning"]}'
            '</div>'
        )
    else:
        parts.append(
            '<div style="padding: 0.5rem 1rem; background: #e8f5e9; '
            'border-left: 3px solid #2e7d32; margin: 0.5rem 0;">'
            '<strong>All green</strong></div>'
        )

    # 1. Status chip row.
    if config.health_email.include_health:
        parts.append("<h3>Status</h3><ul>")
        parts.append(
            f'<li>Gateway: {"OK" if state["gateway_ok"] else "DOWN"}</li>'
        )
        parts.append(
            f'<li>Watchers tracked: {len(state.get("watchers", []))}</li>'
        )
        parts.append(
            f'<li>Errors last 24h: {state.get("error_count_24h", 0)}</li>'
        )
        parts.append("</ul>")

    # 2. Activity digest.
    if config.health_email.include_triage:
        parts.append("<h3>Activity (last 24h)</h3>")
        parts.append(
            f"<p>Messages triaged: <strong>{state['triage_total']}</strong>"
            f" · error rate: {state['triage_error_rate']}%</p>"
        )
        if state["triage_accounts"]:
            parts.append(
                '<table style="width:100%;border-collapse:collapse;">'
                '<tr><th align="left">Account</th>'
                '<th align="right">Msgs</th>'
                '<th align="right">Runs</th>'
                '<th align="right">Avg s</th></tr>'
            )
            for a in state["triage_accounts"]:
                parts.append(
                    f"<tr><td>{a['account_name']}</td>"
                    f"<td align='right'>{a['total']}</td>"
                    f"<td align='right'>{a['runs']}</td>"
                    f"<td align='right'>{a['avg_elapsed']}</td></tr>"
                )
            parts.append("</table>")

    # 3. Error tail.
    if config.health_email.include_errors and state["error_rows"]:
        parts.append("<h3>Error tail</h3><ul>")
        for row in state["error_rows"]:
            parts.append(
                f"<li><code>{row['ts']}</code> "
                f"<strong>{row['level']}</strong> "
                f"{row['logger']} — {row['message']}</li>"
            )
        parts.append("</ul>")

    # 4a. HIPAA audit — DROPPED when system HIPAA mode is on.
    if (
        config.health_email.include_hipaa_events
        and not state["hipaa_mode"]
    ):
        parts.append("<h3>HIPAA access events</h3>")
        parts.append(
            f"<p>Count last 24h: <strong>{state['hipaa_events_count']}</strong></p>"
        )
        if state["hipaa_recent_actors"]:
            parts.append("<p>Recent actors: ")
            parts.append(", ".join(state["hipaa_recent_actors"]))
            parts.append("</p>")

    # 4b. API key lifecycle.
    if config.health_email.include_api_key_events:
        parts.append("<h3>API key events</h3>")
        parts.append(
            f"<p>Count last 24h: <strong>{state['api_key_events_count']}</strong></p>"
        )
        if state["api_key_events_recent"]:
            parts.append("<ul>")
            for e in state["api_key_events_recent"]:
                actor = e.get("actor_email") or "(unknown)"
                parts.append(
                    f"<li><code>{e['ts']}</code> "
                    f"{e['event']} key '{e['name']}' by {actor} "
                    f"via {e['source']}</li>"
                )
            parts.append("</ul>")

    # 4c. BAA expirations (#169 Wave 2-α — I7). Renders ONLY when at
    # least one ai_backends row is in the expiring-soon / expired
    # bucket. On a clean day the section is suppressed entirely so
    # the email doesn't grow a redundant "BAA: nothing to report"
    # line every morning. Bucket data is gathered upstream in
    # ``gather_health_state`` and arrives via ``state["baa_expirations"]``.
    baa = state.get("baa_expirations")
    if baa:
        parts.append("<h3>AI backend vendor agreements</h3>")
        if baa["expired"]:
            parts.append(
                "<p><strong>Expired (HIPAA accounts auto-disabled):"
                "</strong></p><ul>"
            )
            for row in baa["expired"]:
                parts.append(
                    f"<li>{row.name} ({row.type}) — expired "
                    f"{row.baa_expires_at}</li>"
                )
            parts.append("</ul>")
        if baa["expiring_urgent"]:
            parts.append(
                "<p><strong>Expiring within 7 days:</strong></p><ul>"
            )
            for row in baa["expiring_urgent"]:
                parts.append(
                    f"<li>{row.name} ({row.type}) — expires "
                    f"{row.baa_expires_at} "
                    f"({row.days_until_expiry} days)</li>"
                )
            parts.append("</ul>")
        if baa["expiring_soon"]:
            parts.append(
                "<p><strong>Expiring within 30 days:</strong></p><ul>"
            )
            for row in baa["expiring_soon"]:
                parts.append(
                    f"<li>{row.name} ({row.type}) — expires "
                    f"{row.baa_expires_at} "
                    f"({row.days_until_expiry} days)</li>"
                )
            parts.append("</ul>")

    # 4c-bis. Retry queue dead-pattern section (#175 R-B). Renders ONLY
    # when ``state["retry_deads"]`` is non-None (≥3 deads on any one
    # account OR ≥5 deads install-wide in last 24h). Silent on a clean
    # day so the email body doesn't grow a redundant "retry queue:
    # clean" line.
    rd = state.get("retry_deads")
    if rd:
        parts.append("<h3>Retry queue — abandoned messages</h3>")
        if rd.get("install_wide"):
            parts.append(
                f"<p><strong>{rd['dead_24h']}</strong> messages were "
                "abandoned across this install in the last 24 hours.</p>"
            )
        if rd.get("per_account"):
            parts.append("<ul>")
            for acct in rd["per_account"]:
                owner_part = (
                    f" ({acct['owner']})" if acct.get("owner") else ""
                )
                bd_parts: list[str] = []
                for reason, count in (acct.get("breakdown") or {}).items():
                    bd_parts.append(
                        f"{count} {reason.replace('_', ' ')}"
                    )
                bd_text = " — " + ", ".join(bd_parts) if bd_parts else ""
                parts.append(
                    f"<li><strong>{acct['account_label']}</strong>"
                    f"{owner_part}: "
                    f"<strong>{acct['count']}</strong> abandoned in 24h"
                    f"{bd_text}</li>"
                )
            parts.append("</ul>")
        parts.append(
            '<p style="font-size:0.9em;color:#555;">'
            'Review the retry queue in the admin UI to retry-now or '
            'abandon individual rows.'
            '</p>'
        )

    # 4d. Update available (CR-2c). Renders only when state["update_available"]
    # is non-None — gather suppresses the section on an up-to-date install
    # so the email doesn't grow a daily "you're current" line.
    upd = state.get("update_available")
    if upd:
        parts.append("<h3>Email Triage update available</h3>")
        parts.append(
            f'<p><strong>Current version:</strong> {upd["current_version"]}'
        )
        if upd.get("latest_version"):
            parts.append(
                f' &middot; <strong>Latest available:</strong> '
                f'{upd["latest_version"]}'
            )
        parts.append("</p>")
        parts.append(f"<p>{upd['explanation']}</p>")
        if upd.get("release_notes"):
            parts.append("<p><strong>Release notes:</strong></p>")
            # Inline-quote the body. GitHub bodies are markdown; we don't
            # render markdown in the email — surface as a preformatted
            # block so the operator can read what changed without leaving
            # the email.
            _notes = upd["release_notes"]
            if len(_notes) > 4000:
                _notes = _notes[:4000] + "\n…(truncated)"
            # Minimal escaping for the < > characters that show up in
            # release-note PR mentions.
            _escaped = (
                _notes.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            parts.append(
                '<pre style="white-space:pre-wrap;background:#f6f8fa;'
                'padding:0.5rem 0.75rem;border-radius:4px;font-size:0.85em;">'
                f'{_escaped}</pre>'
            )
        elif upd.get("release_notes_unavailable"):
            parts.append(
                "<p><em>Release notes unavailable — check the "
                "release page.</em></p>"
            )
        if upd.get("release_url"):
            parts.append(
                f'<p><a href="{upd["release_url"]}">View release on '
                'GitHub</a></p>'
            )
        latest = upd.get("latest_version") or "<latest>"
        parts.append(
            '<p style="font-size:0.9em;color:#555;">'
            'To apply the update, click the Update Available banner in '
            'your admin UI, or run '
            f'<code>scripts/deploy.sh --from-registry {latest}</code> '
            'on your deploy host.</p>'
        )

    # 5. Queue + storage.
    parts.append("<h3>Queue &amp; storage</h3><ul>")
    parts.append(f"<li>log_entries rows: {state['log_row_count']}</li>")
    if config.health_email.include_pubsub:
        parts.append(
            f'<li>Pub/Sub topic: '
            f'{"configured" if state["pubsub_configured"] else "not configured"}</li>'
        )
        # #66 — O365 Graph subscriptions sibling line. Conditional on
        # the same include_pubsub toggle since both are "external push
        # transport health" surfaces.
        o365 = state.get("office365_push") or {}
        if o365.get("total", 0) > 0:
            parts.append(
                f'<li>Office 365 Graph subscriptions: '
                f'{o365.get("accounts_with_active_subscriptions", 0)}/'
                f'{o365.get("total", 0)} active'
                f', {o365.get("expiring_in_24h", 0)} expiring &lt;24h'
                f', {o365.get("errored", 0)} errored</li>'
            )
        elif state.get("providers", {}).get("office365"):
            parts.append(
                '<li>Office 365 Graph subscriptions: '
                'no accounts have an active subscription</li>'
            )
    parts.append("</ul>")

    # Ingestion (per-provider aggregate + per-account detail).
    _provider_labels = {
        "imap": "IMAP", "gmail_api": "Gmail", "office365": "Office 365",
    }
    if config.health_email.include_watchers and state.get("providers"):
        parts.append("<h3>Ingestion</h3><table style='font-size:0.9em;'>")
        parts.append(
            "<tr><th align='left'>Provider</th>"
            "<th align='right'>Total</th>"
            "<th align='right'>Push</th>"
            "<th align='right'>Poll</th>"
            "<th align='right'>Both</th>"
            "<th align='right'>Uncovered</th></tr>"
        )
        for key, label in _provider_labels.items():
            b = state["providers"].get(key)
            if not b or not b["total"]:
                continue
            unc = b["uncovered"]
            parts.append(
                f"<tr><td>{label}</td>"
                f"<td align='right'>{b['total']}</td>"
                f"<td align='right'>{b['push']}</td>"
                f"<td align='right'>{b['poll']}</td>"
                f"<td align='right'>{b['push_plus_poll']}</td>"
                f"<td align='right'"
                f"{' style=color:#c00' if unc else ''}>{unc}</td></tr>"
            )
        parts.append("</table>")

    if config.health_email.include_watchers and state.get("account_states"):
        parts.append("<h3>Per-account detail</h3><ul>")
        for s in state["account_states"]:
            _label = s.get("account_name") or f"#{s['account_id']}"
            _owner = f" ({s['owner']})" if s.get("owner") else ""
            _prov = _provider_labels.get(s["provider"], s["provider"])
            _mode = s["mode"]
            _alert = s.get("alert")
            if _alert:
                _badge = (
                    f"<strong style='color:#c00'>"
                    f"{_alert.replace('_', ' ').upper()}</strong>"
                )
            elif _mode == "push+poll":
                _badge = "<strong>push + poll</strong>"
            elif _mode == "push":
                _badge = "<strong>push</strong>"
            elif _mode == "poll":
                _badge = "<strong>poll</strong>"
            else:
                _badge = (
                    "<strong style='color:#c00'>NONE</strong>"
                )
            parts.append(
                f"<li>{_label}{_owner} <small>[{_prov}]</small>: {_badge}"
                f" — push: {s['push']['detail']}"
                f"; poll: {'enrolled' if s['poll']['enrolled'] else 'off'}"
                f"{' (fresh)' if s['poll']['fresh'] else ''}</li>"
            )
        parts.append("</ul>")

    if config.health_email.include_watchers and state.get("poll", {}).get("registered"):
        p = state["poll"]
        parts.append(
            f"<p>Poll loop: {p['fresh']}/{p['registered']} accounts ticked "
            f"in the last 2h.</p>"
        )

    if config.health_email.include_watchers and state.get("mailboxes", {}).get("total"):
        m = state["mailboxes"]
        parts.append(
            f"<p>IMAP folders: {m['watching']}/{m['total']} watching.</p>"
        )

    parts.append("</div>")
    return "".join(parts)


def _render_text(state: dict[str, Any], config: TriageConfig) -> str:
    lines: list[str] = []
    lines.append(f"Daily health — {state['now'].strftime('%Y-%m-%d')}")
    lines.append("=" * 40)
    if state["attention_reasons"] or state.get("cert_expiry_warning"):
        lines.append("ATTENTION:")
        for r in state["attention_reasons"]:
            lines.append(f"  - {r}")
        if state.get("cert_expiry_warning"):
            lines.append(f"  - {state['cert_expiry_warning']}")
    else:
        lines.append("All green.")
    lines.append("")

    if config.health_email.include_health:
        lines.append("Status:")
        lines.append(f"  Gateway: {'OK' if state['gateway_ok'] else 'DOWN'}")
        lines.append(f"  Watchers tracked: {len(state.get('watchers', []))}")
        lines.append(f"  Errors last 24h: {state.get('error_count_24h', 0)}")
        lines.append("")

    if config.health_email.include_triage:
        lines.append("Activity (last 24h):")
        lines.append(
            f"  Messages triaged: {state['triage_total']} "
            f"(error rate {state['triage_error_rate']}%)"
        )
        for a in state["triage_accounts"]:
            lines.append(
                f"    {a['account_name']}: msgs={a['total']} "
                f"runs={a['runs']} avg={a['avg_elapsed']}s"
            )
        lines.append("")

    if config.health_email.include_errors and state["error_rows"]:
        lines.append("Error tail:")
        for row in state["error_rows"]:
            lines.append(
                f"  [{row['ts']}] {row['level']} {row['logger']} — {row['message']}"
            )
        lines.append("")

    if (
        config.health_email.include_hipaa_events
        and not state["hipaa_mode"]
    ):
        lines.append("HIPAA access events:")
        lines.append(f"  Count last 24h: {state['hipaa_events_count']}")
        if state["hipaa_recent_actors"]:
            lines.append(f"  Recent actors: {', '.join(state['hipaa_recent_actors'])}")
        lines.append("")

    if config.health_email.include_api_key_events:
        lines.append("API key events:")
        lines.append(f"  Count last 24h: {state['api_key_events_count']}")
        for e in state["api_key_events_recent"]:
            actor = e.get("actor_email") or "(unknown)"
            lines.append(
                f"  [{e['ts']}] {e['event']} key '{e['name']}' "
                f"by {actor} via {e['source']}"
            )
        lines.append("")

    # Retry queue dead-pattern section (#175 R-B). Sibling to the
    # HTML block above; silent on a clean day.
    rd = state.get("retry_deads")
    if rd:
        lines.append("")
        lines.append("Retry queue — abandoned messages")
        lines.append("-" * 32)
        if rd.get("install_wide"):
            lines.append(
                f"{rd['dead_24h']} messages were abandoned across this "
                "install in the last 24 hours."
            )
        for acct in rd.get("per_account", []) or []:
            owner_part = (
                f" ({acct['owner']})" if acct.get("owner") else ""
            )
            bd_parts: list[str] = []
            for reason, count in (acct.get("breakdown") or {}).items():
                bd_parts.append(f"{count} {reason.replace('_', ' ')}")
            bd_text = " — " + ", ".join(bd_parts) if bd_parts else ""
            lines.append(
                f"  {acct['account_label']}{owner_part}: "
                f"{acct['count']} abandoned in 24h{bd_text}"
            )
        lines.append(
            "Review the retry queue in the admin UI to retry-now or "
            "abandon individual rows."
        )
        lines.append("")

    # Update available (CR-2c). Renders only when state["update_available"]
    # is non-None — sibling to the HTML block above.
    upd = state.get("update_available")
    if upd:
        lines.append("")
        lines.append("Email Triage update available")
        lines.append("-" * 30)
        ver_line = f"Current version: {upd['current_version']}"
        if upd.get("latest_version"):
            ver_line += f" | Latest available: {upd['latest_version']}"
        lines.append(ver_line)
        lines.append(upd["explanation"])
        if upd.get("release_notes"):
            lines.append("")
            lines.append("Release notes:")
            _notes = upd["release_notes"]
            if len(_notes) > 4000:
                _notes = _notes[:4000] + "\n…(truncated)"
            lines.append(_notes)
        elif upd.get("release_notes_unavailable"):
            lines.append(
                "Release notes unavailable — check the release page."
            )
        if upd.get("release_url"):
            lines.append(f"Release page: {upd['release_url']}")
        latest = upd.get("latest_version") or "<latest>"
        lines.append(
            "To apply the update, click the Update Available banner in "
            "your admin UI, or run "
            f"`scripts/deploy.sh --from-registry {latest}` "
            "on your deploy host."
        )
        lines.append("")

    lines.append(f"log_entries rows: {state['log_row_count']}")
    if config.health_email.include_pubsub:
        lines.append(
            "Pub/Sub topic: "
            + ("configured" if state["pubsub_configured"] else "not configured")
        )
        # #66 — O365 sibling line in the text-mode digest.
        o365 = state.get("office365_push") or {}
        if o365.get("total", 0) > 0:
            lines.append(
                f"Office 365 Graph subscriptions: "
                f"{o365.get('accounts_with_active_subscriptions', 0)}/"
                f"{o365.get('total', 0)} active, "
                f"{o365.get('expiring_in_24h', 0)} expiring <24h, "
                f"{o365.get('errored', 0)} errored"
            )
        elif state.get("providers", {}).get("office365"):
            lines.append(
                "Office 365 Graph subscriptions: "
                "no accounts have an active subscription"
            )

    _provider_labels = {
        "imap": "IMAP", "gmail_api": "Gmail", "office365": "Office 365",
    }
    if config.health_email.include_watchers and state.get("providers"):
        lines.append("")
        lines.append("Ingestion (per provider):")
        lines.append("  Provider     Total  Push  Poll  Both  Uncovered")
        for key, label in _provider_labels.items():
            b = state["providers"].get(key)
            if not b or not b["total"]:
                continue
            lines.append(
                f"  {label:<11} {b['total']:>5}  {b['push']:>4}  "
                f"{b['poll']:>4}  {b['push_plus_poll']:>4}  "
                f"{b['uncovered']:>9}"
            )

    if config.health_email.include_watchers and state.get("account_states"):
        lines.append("")
        lines.append("Per-account detail:")
        for s in state["account_states"]:
            _label = s.get("account_name") or f"#{s['account_id']}"
            _owner = f" ({s['owner']})" if s.get("owner") else ""
            _prov = _provider_labels.get(s["provider"], s["provider"])
            _alert = s.get("alert")
            _mode_str = (
                _alert.replace("_", " ").upper() if _alert
                else (s["mode"] if s["mode"] != "none" else "NONE")
            )
            poll_str = "off"
            if s["poll"]["enrolled"]:
                poll_str = "fresh" if s["poll"]["fresh"] else "enrolled"
            lines.append(
                f"  {_label}{_owner} [{_prov}]: {_mode_str}"
                f" — push: {s['push']['detail']}; poll: {poll_str}"
            )

    if config.health_email.include_watchers and state.get("poll", {}).get("registered"):
        p = state["poll"]
        lines.append("")
        lines.append(
            f"Poll loop: {p['fresh']}/{p['registered']} accounts "
            f"ticked in the last 2h."
        )
    if config.health_email.include_watchers and state.get("mailboxes", {}).get("total"):
        m = state["mailboxes"]
        lines.append(f"IMAP folders: {m['watching']}/{m['total']} watching.")

    return "\n".join(lines)


def assemble_daily_health_email(
    state: dict[str, Any],
    config: TriageConfig,
) -> EmailMessage:
    """Build the multipart message. Caller supplies To/From at send time."""
    html = _render_html(state, config)
    text = _render_text(state, config)

    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER, build_triage_header,
    )
    msg = EmailMessage()
    date_str = state["now"].strftime("%Y-%m-%d")
    flag = "⚠ Attention" if state["attention_reasons"] else "OK"
    msg["Subject"] = f"[email-triage] Daily health {date_str} — {flag}"
    # Loop-prevention stamp: the daily-health recipients are often
    # operator inboxes, some of which are watched by triage. If a
    # health email is ever re-ingested the pipeline entry check on
    # this header short-circuits before the classifier is called.
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header("health-email")
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------

def send_daily_health_email(
    db: sqlite3.Connection,
    config: TriageConfig,
    secrets: Any,
    watcher_manager: Any = None,
    *,
    force: bool = False,
    app: Any = None,
) -> tuple[bool, str]:
    """Send the digest now. Returns ``(sent, reason)``.

    ``force=True`` bypasses ``quiet_mode`` — used by the "Send now"
    admin button so ops can verify wiring even on a boringly healthy day.
    ``app`` (FastAPI instance) enables the listener-restart-pending
    check (#81) — passed through from the supervisor; tests can omit.
    """
    cfg = config.health_email
    if not cfg.enabled and not force:
        return False, "health email disabled"
    recipients = resolve_admin_recipients(config)
    if not recipients:
        return False, "no recipients configured"
    smtp = config.smtp
    if not smtp.host:
        return False, "SMTP not configured"

    state = gather_health_state(db, config, watcher_manager, app=app)
    if cfg.quiet_mode and not force and not is_interesting(state):
        return False, "quiet_mode: nothing interesting"

    msg = assemble_daily_health_email(state, config)
    msg["From"] = format_from_header(smtp.from_addr, smtp.from_name)
    msg["To"] = ", ".join(recipients)

    password = ""
    if secrets is not None:
        try:
            password = secrets.get("SMTP_PASSWORD") or ""
        except Exception:
            password = ""

    try:
        with smtplib.SMTP(smtp.host, smtp.port) as server:
            if smtp.use_tls:
                server.starttls()
            if smtp.username:
                server.login(smtp.username, password)
            server.send_message(msg)
    except Exception as exc:
        log.error("Daily health email send failed", error=str(exc))
        return False, f"send failed: {exc}"

    log.info(
        "Daily health email sent",
        recipients=len(recipients),
        attention=bool(state["attention_reasons"]),
    )
    return True, "sent"


# ---------------------------------------------------------------------------
# Update-failed email (CR-2d)
# ---------------------------------------------------------------------------

def _assemble_update_failed_email(
    *,
    attempted_tag: str,
    current_tag: str,
    failure_reason: str,
    restored_from_snapshot: str | None,
    now: datetime | None = None,
    repo_url: str = "https://github.com/unlimited-data-works-llc/email-triage",
) -> EmailMessage:
    """Build the multipart message for the update-failed alert.

    Pure (no SMTP, no DB) so tests can pin the body shape without
    standing up the full send codepath. Caller fills From / To.
    """
    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = (
        f"[Email Triage] Update to {attempted_tag} failed — "
        f"rolled back to {current_tag}"
    )

    # Text body
    text_lines = [
        "Email Triage — update failed, install rolled back",
        "=" * 50,
        f"Timestamp: {ts}",
        f"Attempted tag: {attempted_tag}",
        f"Rolled back to: {current_tag}",
        "",
        "Failure reason:",
        f"  {failure_reason}",
        "",
    ]
    if restored_from_snapshot:
        text_lines.append(f"Restored from snapshot: {restored_from_snapshot}")
    else:
        text_lines.append("Restored from snapshot: (none recorded)")
    text_lines.extend([
        "",
        "Current state: running on the previous image.",
        "",
        "Where to look:",
        "  - Admin UI: /logs page for the error tail",
        "  - On the deploy host: `journalctl -u email-triage`",
        f"  - On the deploy host: `scripts/deploy.sh` output for {attempted_tag}",
        "",
        f"If this keeps happening, open an issue at {repo_url}/issues",
        "with the journal tail attached.",
    ])
    text = "\n".join(text_lines)

    # HTML body — minimal styling matching the daily-health email's shape.
    snap_line = (
        f'<li><strong>Restored from snapshot:</strong> '
        f'<code>{restored_from_snapshot}</code></li>'
        if restored_from_snapshot
        else '<li><strong>Restored from snapshot:</strong> (none recorded)</li>'
    )
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        '<h2 style="color:#c00;">Email Triage — update failed, '
        'install rolled back</h2>'
        '<div style="padding: 0.75rem 1rem; background: #fff4e5; '
        'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
        '<ul style="margin:0;padding-left:1.25rem;">'
        f'<li><strong>Timestamp:</strong> {ts}</li>'
        f'<li><strong>Attempted tag:</strong> <code>{attempted_tag}</code></li>'
        f'<li><strong>Rolled back to:</strong> <code>{current_tag}</code></li>'
        f'{snap_line}'
        '</ul></div>'
        '<h3>Failure reason</h3>'
        f'<pre style="white-space:pre-wrap;background:#f6f8fa;padding:0.5rem 0.75rem;'
        f'border-radius:4px;font-size:0.9em;">{failure_reason}</pre>'
        '<p>Current state: running on the previous image.</p>'
        '<h3>Where to look</h3>'
        '<ul>'
        '<li>Admin UI: <code>/logs</code> page for the error tail</li>'
        '<li>On the deploy host: '
        '<code>journalctl -u email-triage</code></li>'
        '<li>On the deploy host: <code>scripts/deploy.sh</code> output '
        f'for <code>{attempted_tag}</code></li>'
        '</ul>'
        f'<p>If this keeps happening, '
        f'<a href="{repo_url}/issues">open an issue</a> with the journal '
        'tail attached.</p>'
        '</div>'
    )

    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER, build_triage_header,
    )
    msg = EmailMessage()
    msg["Subject"] = subject
    # Loop-prevention stamp — same rationale as the daily-health email:
    # admin recipients are often operator inboxes that are themselves
    # watched by triage.
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header("update-failed-email")
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


def send_update_failed_email(
    db: sqlite3.Connection,
    config: TriageConfig,
    secrets: Any,
    *,
    attempted_tag: str,
    current_tag: str,
    failure_reason: str,
    restored_from_snapshot: str | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Fire the update-failed alert. Returns ``(sent, reason)``.

    Wired into ``scripts/deploy.sh``'s post-apply health-check + snapshot
    rollback path (W4-Deploy). Recipients resolve through
    :func:`resolve_admin_recipients` — same destination as the daily
    health digest. ``db`` is currently unused at the body level but kept
    in the signature so future audit-row work (storing the failure event
    in ``log_entries`` or a dedicated table) doesn't churn the caller.

    The caller is responsible for constructing ``failure_reason`` as a
    short plain-English string (e.g. "post-apply /health probe returned
    503 for 60s", "/health/detail JSON parse failed"). This helper does
    not try to interpret the failure — it just relays it.

    Returns ``(False, "<reason>")`` and logs but does not raise when:

    * Admin recipients are unconfigured.
    * SMTP is unconfigured.
    * SMTP send raises.

    Rationale: the rollback path is already in failure-mode; an
    exception escaping this helper would just shoot the messenger.
    """
    recipients = resolve_admin_recipients(config)
    if not recipients:
        log.warning(
            "Update-failed email skipped — no admin recipients configured",
            attempted_tag=attempted_tag,
            current_tag=current_tag,
        )
        return False, "no recipients configured"
    smtp = config.smtp
    if not smtp.host:
        log.warning(
            "Update-failed email skipped — SMTP not configured",
            attempted_tag=attempted_tag,
            current_tag=current_tag,
        )
        return False, "SMTP not configured"

    msg = _assemble_update_failed_email(
        attempted_tag=attempted_tag,
        current_tag=current_tag,
        failure_reason=failure_reason,
        restored_from_snapshot=restored_from_snapshot,
        now=now,
    )
    msg["From"] = format_from_header(smtp.from_addr, smtp.from_name)
    msg["To"] = ", ".join(recipients)

    password = ""
    if secrets is not None:
        try:
            password = secrets.get("SMTP_PASSWORD") or ""
        except Exception:
            password = ""

    try:
        with smtplib.SMTP(smtp.host, smtp.port) as server:
            if smtp.use_tls:
                server.starttls()
            if smtp.username:
                server.login(smtp.username, password)
            server.send_message(msg)
    except Exception as exc:
        log.error(
            "Update-failed email send failed",
            error=str(exc),
            attempted_tag=attempted_tag,
            current_tag=current_tag,
        )
        return False, f"send failed: {exc}"

    # Structured-log audit row. Same pattern the daily-health email uses
    # (search for ``Daily health email sent`` -> ``log_entries`` flow).
    log.info(
        "Update-failed email sent",
        recipients=len(recipients),
        attempted_tag=attempted_tag,
        current_tag=current_tag,
        restored_from_snapshot=restored_from_snapshot or "",
    )
    return True, "sent"
