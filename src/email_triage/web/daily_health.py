"""Daily health / summary email + admin-notification channel (CR-2c/2d).

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
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape as _html_escape  # DA R4 CIDI-drift fold (2026-07-10)
from typing import Any

import httpx

from email_triage._egress import EgressBlocked, Intent, egress_client
from email_triage._int_utils import parse_int_or_none  # N-219c/38 R23
from email_triage._isotime import parse_iso, to_utc_iso
from email_triage.config import TriageConfig
from email_triage.update_check import PUBLIC_REPO_URL
from email_triage.secrets import SecretsDecryptError, read_secret
from email_triage.triage_logging import get_logger, is_hipaa_mode
from email_triage.web.auth import format_from_header
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT
from email_triage._dbapi_errors import DB_ERRORS
from email_triage._errfmt import fmt_exc

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

#: ``(fetched_at_monotonic, payload_or_none, failure_or_none)`` keyed by
#: URL. 1-hour TTL by default; tests reset via ``_reset_release_cache``. The
#: cache lives at module scope because the daily-health email renders once a
#: day in production but tests / "Send now" can fire repeatedly; caching the
#: HTTP fetch avoids hammering GitHub during demos and rate-limit surfaces.
#: ``failure`` is the :func:`update_check.fetch_failure` detail of a failed
#: fetch (punch 584), read back by :func:`last_release_fetch_failure`.
_release_cache: dict[
    str, tuple[float, dict[str, Any] | None, dict[str, Any] | None]
] = {}
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
    in tests. The fetch goes through the egress funnel
    (``egress_client(intent=Intent.PUBLIC_FETCH)``, run17 #5 — was a raw
    ``urllib.request.urlopen``); tests monkeypatch ``egress_client`` so
    they don't touch the network.
    """
    now = now_monotonic if now_monotonic is not None else time.monotonic()
    cached = _release_cache.get(url)
    if cached is not None:
        fetched_at, payload, _failure = cached
        if now - fetched_at < _RELEASE_CACHE_TTL_SECONDS:
            return payload

    from email_triage.update_check import FAILURE_BAD_RESPONSE, fetch_failure

    payload: dict[str, Any] | None = None
    failure: dict[str, Any] | None = None
    try:
        with egress_client(intent=Intent.PUBLIC_FETCH) as c:
            resp = c.get(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "email-triage-daily-health",
                },
                timeout=_RELEASE_FETCH_TIMEOUT_SECONDS,
                # urllib.urlopen followed redirects by default — preserve that
                # (GitHub's API doesn't 302 today, but a future host might); the
                # funnel's SSRF hook re-runs on each hop.
                follow_redirects=True,
            )
        resp.raise_for_status()
        data = _json.loads(resp.text)
        if isinstance(data, dict):
            payload = data
        else:
            failure = fetch_failure(FAILURE_BAD_RESPONSE)
    except (
        httpx.HTTPError, TimeoutError, ValueError, OSError, EgressBlocked,
    ) as exc:
        # httpx.HTTPError covers both transport failures (RequestError:
        # connect/timeout) and a non-2xx raise_for_status (HTTPStatusError),
        # matching the old urllib URLError+HTTPError catch. ValueError = bad JSON.
        # EgressBlocked (punch 584, panel H584-2/DB584-1/DA584-2): the funnel
        # refusing the address (a private/reserved destination, also on a
        # redirect hop) used to escape, so no failure was ever recorded and
        # the stale notice never fired on an install that had not succeeded.
        log.warning(
            "GitHub Releases fetch failed",
            url=url, error=str(exc),
        )
        payload = None
        failure = _classify_release_fetch_error(exc)
    _release_cache[url] = (now, payload, failure)
    return payload


def _classify_release_fetch_error(exc: BaseException) -> dict[str, Any]:
    """Punch 584: how a release fetch failed, so the staleness notice can
    tell "the server answered with an error" (the network works; the address
    is suspect) from "no answer at all" (the network is suspect)."""
    from email_triage.update_check import (
        FAILURE_BAD_RESPONSE, FAILURE_HTTP_STATUS, FAILURE_REFUSED,
        FAILURE_TRANSPORT, fetch_failure,
    )

    if isinstance(exc, EgressBlocked):
        return fetch_failure(FAILURE_REFUSED)
    if isinstance(exc, httpx.HTTPStatusError):
        return fetch_failure(FAILURE_HTTP_STATUS, exc.response.status_code)
    if isinstance(exc, (ValueError, httpx.DecodingError)):
        return fetch_failure(FAILURE_BAD_RESPONSE)
    return fetch_failure(FAILURE_TRANSPORT)


def last_release_fetch_failure(url: str) -> dict[str, Any] | None:
    """The failure detail of the most recent fetch of ``url`` (``None`` when
    it succeeded, was never made, or the cache was reset). Read by the
    update-check sweeper right after a fetch returns ``None``."""
    cached = _release_cache.get(url)
    return cached[2] if cached is not None else None


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
            read_target_schema_caps,
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
            # census run15  — the conn-based, side-effect-free schema-version
            # SSOT (NOT a raw MAX(version) re-inline, and NOT migrations
            # .schema_version, which would _ensure_bookkeeping/CREATE on a
            # read-only banner render). The path-based branch below uses the
            # sibling read_db_schema_version, its own SSOT entry point.
            from email_triage.version import read_schema_version
            db_schema = read_schema_version(db)
        except DB_ERRORS:
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
        # Punch 547: the running app has no :previous image to read; the
        # rollback-safety compare is the deploy's (version-check
        # --previous-schema-caps). A booted container has already migrated
        # the DB to its own target, so no update_available escalation is lost.
        previous_caps = None
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
    # Round 4 (DA): the tag is printed in the email; admit it only through
    # the shared rule (a tag with a line break is dropped, not printed).
    from email_triage.update_check import release_tag
    section["latest_version"] = release_tag(payload)[0]
    # db F-O5-2: https only (the link is rendered as an <a href> below).
    from email_triage.update_check import release_page_url
    section["release_url"] = release_page_url(payload)
    body = (payload.get("body") or "").strip()
    if body:
        section["release_notes"] = body
        section["release_notes_unavailable"] = False
    return section


# ---------------------------------------------------------------------------
# Retry-queue threshold section
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
        since = to_utc_iso(
            datetime.now(timezone.utc) - timedelta(hours=24)
        )

        # Install-wide total.
        row = db.execute(
            "SELECT COUNT(*) AS c FROM watcher_retry_queue "
            "WHERE state = 'dead' AND resolved_at >= ?",
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
            "WHERE q.state = 'dead' AND q.resolved_at >= ? "
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
                "WHERE state = 'dead' AND resolved_at >= ? "
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

def gather_embedding_runtime_section(config: Any) -> dict[str, Any] | None:
    """The punch-569 "embedding runtime update required" section, or ``None``.

    Repeats the admin alert's notice every day until it is fixed (operator
    decision 2026-10-02). Reads ``embedding_bits.update_notice`` — the SAME
    funnel the alert, the banner and the card read (PD-5). A failure to read
    it is a section that says so, never a silent omission: an unreadable
    runtime state is exactly what the admin must hear about.
    """
    from email_triage.embedding_bits import (
        SECURITY_UNKNOWN, UPDATE_ACTION_PATH, update_notice,
    )

    try:
        notice = update_notice()
    except Exception:  # noqa: BLE001
        notice = {
            "kind": "update",
            "headline": "Embedding runtime: the status check failed",
            "consequence": (
                "The app could not read the state of the embedding runtime. "
                "Open the AI Backends page to see it."
            ),
            "security": SECURITY_UNKNOWN,
            "versions": "",
            "advisories": [],
        }
    if notice is None:
        return None
    from email_triage.web.admin_alerts import app_base_url

    base = app_base_url(config)
    return {
        **notice,
        "link": f"{base}{UPDATE_ACTION_PATH}" if base else "",
    }


def gather_embedding_auto_updated_section(
    db: sqlite3.Connection,
) -> dict[str, Any] | None:
    """The "embedding runtime updated automatically" line, or ``None``.

    Reads the automatic updater's durable record through the runner's own
    accessors (PD-5): the SAME ``recent_auto_update`` window and
    ``describe_auto_update`` text the after-the-fact email prints.
    """
    from email_triage.web.embedding_update_runner import (
        describe_auto_update, read_auto_state, recent_auto_update,
    )

    rec = recent_auto_update(read_auto_state(db))
    return describe_auto_update(rec) if rec else None


def _iso_ago(hours: int) -> str:
    return to_utc_iso(datetime.now(timezone.utc) - timedelta(hours=hours))


def gather_n151_soft_gate(
    db: sqlite3.Connection,
    config: TriageConfig,
) -> dict[str, Any]:
    """Snapshot the N-151 MSAL master-key SOFT-gate state for the digest.

    Composes Part-0's ``providers._msal_cache_crypto.n151_soft_gate_active``
    /``n151_soft_gate_reason`` LEVEL predicates with the Part-2
    ``admin_alert:n151_soft_gate`` settings row that records ``since``
    (the ISO stamp the gate first went active).  Returns a bag with
    ``{"active": bool, "reason": str, "since": ISO|None}`` — every field
    populated on every day, so the render path can decide whether to
    show the dedicated ``Credential store`` section (active=True → yes).

    Fail-CLOSED (PD #8): any probe/read exception treats the gate as
    ACTIVE with ``reason == "probe_error"`` and ``since=None`` — the
    render side then still surfaces the section so the operator is not
    silently left with a broken credential store.
    """
    del config  # accessor is process-scoped, no config knob today
    try:
        # DB-SME F1 fold (2026-07-10): route through the atomic
        # ``n151_soft_gate_state()`` SSOT so ``active`` + ``reason`` are
        # captured in one probe.  The prior dual-call
        # (``n151_soft_gate_active()`` + ``n151_soft_gate_reason()``)
        # torn-read on a rotation / backend-flap tick — the two probes
        # crossed the transition and disagreed.  Sibling render sites
        # (admin_alerts, routers/ui/_shared) already use the tuple SSOT.
        from email_triage.providers._msal_cache_crypto import (
            n151_soft_gate_state,
        )
        _active, _reason = n151_soft_gate_state()
        active = bool(_active)
        reason = str(_reason)
    except Exception:
        # Fail-CLOSED: an import/probe failure IS a credential-store
        # problem the operator needs to see.
        return {"active": True, "reason": "probe_error", "since": None}

    since: str | None = None
    try:
        from email_triage.web.db import get_setting
        row = get_setting(db, "admin_alert:n151_soft_gate")
        if isinstance(row, dict):
            _since = row.get("since")
            if isinstance(_since, str) and _since:
                since = _since
    except Exception:
        # Settings row read failure is non-fatal — the section still
        # renders with since=None (Part-2 primitive owns the write).
        since = None

    return {"active": active, "reason": reason, "since": since}


#: ``embedding_runtime_section`` default: compute it here (under the caller's lock).
_COMPUTE_HERE: Any = object()


def gather_health_state(
    db: sqlite3.Connection,
    config: TriageConfig,
    watcher_manager: Any = None,
    *,
    now: datetime | None = None,
    app: Any = None,
    embedding_runtime_section: Any = _COMPUTE_HERE,
) -> dict[str, Any]:
    """Snapshot everything the digest renders from.

    Split out so ``assemble_daily_health_email`` is a pure function of
    its state dict — easy to test at the seam.

    ``app`` is the FastAPI instance (optional). When supplied, the
    listener-restart-pending check runs and may add an entry to
    ``attention_reasons`` so the daily digest signals the operator
    even on a day when nothing else is wrong.
    """
    now = now or datetime.now(timezone.utc)
    # N-203 R22 (2026-07-02): route through A10 stored-ISO SSOT.
    since_24h = to_utc_iso(now - timedelta(hours=24))

    state: dict[str, Any] = {
        "now": now,
        "hipaa_mode": is_hipaa_mode(),
        "attention_reasons": [],
    }

    # --- N-151 MSAL master-key SOFT-gate ------
    # Composed via ``gather_n151_soft_gate`` so tests can drive the seam
    # independently. When active, the digest renders a dedicated
    # ``Credential store`` section FIRST (above the Status chip row) and
    # the subject line flips to ``⚠ Attention`` via ``attention_reasons``.
    state["n151_soft_gate"] = gather_n151_soft_gate(db, config)
    if state["n151_soft_gate"]["active"]:
        state["attention_reasons"].append(
            "MSAL master key unavailable — credential store SOFT-gate "
            f"active since {state['n151_soft_gate']['since']}"
        )

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

    #  — restore-key freshness (productized reminder, not a verbal nag): the
    # automated backups are unrecoverable without the operator's key-only
    # export, so surface when it last happened (None = never on record).
    try:
        from pathlib import Path as _P

        from email_triage import backup as _bk

        _dbp = getattr(getattr(config, "persistence", None), "db_path", "")
        _ddir = _P(_dbp).parent if _dbp else _P("./data")
        _km = _bk.read_key_export_marker(_ddir)
        state["last_key_export"] = _km.get("ts") if _km else None
    except Exception:
        state["last_key_export"] = None

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
        except Exception as e:
            log.error("health: poll counts unavailable; reporting 0", exc_info=e)
    state["poll"] = {"registered": poll_registered, "fresh": poll_fresh}
    mb_total = 0
    mb_watching = 0
    if watcher_manager is not None:
        try:
            mb_total, mb_watching = watcher_manager.mailbox_counts()
        except Exception as e:
            log.error("health: mailbox counts unavailable; reporting 0", exc_info=e)
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
        # ERROR rows first, then the newest WARNINGs. Newest-first alone let
        # ten routine WARNINGs push every ERROR out of the tail, so the
        # 2026-10-10 email said "10 ERROR log entries" and showed none.
        rows = db.execute(
            "SELECT ts, level, logger, message FROM log_entries "
            "WHERE level IN ('ERROR', 'WARNING') AND ts >= ? "
            "ORDER BY CASE level WHEN 'ERROR' THEN 0 ELSE 1 END, id DESC "
            "LIMIT 10",
            (since_24h,),
        ).fetchall()
        error_rows = [dict(r) for r in rows]
    except DB_ERRORS as e:
        log.error("health: log_entries error counts unavailable", exc_info=e)
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
    except DB_ERRORS as e:
        log.error("health: triage error-rate unavailable; reporting 0", exc_info=e)
    state["triage_total"] = triage_total
    state["triage_accounts"] = triage_accounts
    state["triage_error_rate"] = round(triage_error_rate, 2)
    if triage_error_rate > max(config.health_email.error_rate_threshold_pct, 0):
        state["attention_reasons"].append(
            f"triage error rate {triage_error_rate:.1f}% exceeds threshold"
        )

    # --- Stale-auth accounts ---------------------------------------------
    # Surface accounts whose OAuth refresh / IMAP password is no longer
    # valid. The auth_stale flag is maintained by the lifecycle SSOT
    # ``record_provider_outcome`` (web/app.py): SET (needle-filtered via
    # web/_auth_revoked) on an auth-revoked failure, CLEARED on the next
    # successful credentialed provider call — across ALL ingestion surfaces
    # (poll / Gmail+O365 push / IMAP IDLE / watch+subscription renewers /
    # sent-mail capture / the Test action), not just the poll path. Census
    # 2026-06-09 #1.
    stale_auth_accounts: list[dict[str, Any]] = []
    try:
        rows = db.execute(
            "SELECT s.key, s.value_json, ea.name AS account_name, ea.id AS account_id "
            "FROM settings s "
            "LEFT JOIN email_accounts ea "
            "  ON ea.id = CAST(SUBSTR(s.key, length('auth_stale:') + 1) AS INTEGER) "
            "WHERE s.key LIKE 'auth_stale:%'"
        ).fetchall()
        from email_triage.db._helpers import load_json_col
        for r in rows:
            payload = load_json_col(r["value_json"], default={})  # census 
            if not payload.get("at"):
                continue
            stale_auth_accounts.append({
                "account_id": r["account_id"],
                "account_name": r["account_name"] or "(unknown)",
                "at": payload.get("at"),
                "reason": (payload.get("reason") or "")[:200],
            })
    except DB_ERRORS as e:
        log.error("health: stale-auth accounts unavailable", exc_info=e)
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
    # None = the count could not be read. Never report a failed query as 0:
    # "no HIPAA access events" is a claim the digest cannot make then.
    hipaa_events_count: int | None = 0
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
    except DB_ERRORS as e:
        log.error("health: HIPAA access-event counts unavailable", exc_info=e)
        hipaa_events_count = None
        hipaa_recent_actors = []
        state["attention_reasons"].append(
            "HIPAA access-event count unavailable (query failed; see log)"
        )
    state["hipaa_events_count"] = hipaa_events_count
    state["hipaa_recent_actors"] = hipaa_recent_actors

    # --- BAA expirations ------------------------------
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

    # --- Security update (punch 553, operator decision 553-2) ------------
    # Deliberately NOT gated by ``include_update_available``: the admin UI
    # will not let an admin dismiss this notice, so the email cannot
    # suppress it either. Reads the update check's persisted FACTS (no
    # request here); pending-ness is derived against the running version.
    # A read failure leaves the section out and logs (the admin banner is
    # computed independently on every page).
    state["security_update"] = None
    try:
        from email_triage import __version__ as _running_version
        from email_triage.update_check import (
            load_release_facts, security_update_pending,
        )
        _facts = getattr(
            getattr(app, "state", None), "update_check_facts", None,
        )
        if _facts is None:
            _facts = load_release_facts(db)
        state["security_update"] = security_update_pending(
            _facts, _running_version,
        )
    except Exception as exc:
        log.warning(
            "daily health: security-update facts unreadable", error=str(exc),
        )
    if state["security_update"]:
        _sec = state["security_update"]
        state["attention_reasons"].append(
            "Security update required: running "
            f"{_sec['running_version']}, update to "
            f"{_sec.get('target_version') or _sec.get('latest_tag') or 'the newest release'}"
            f" (severity {_sec['severity']})"
        )

    # --- Update check health (db F-O5-1) ----------------------------------
    # A check that keeps failing must not be silent: a security release
    # published meanwhile would go unannounced.
    state["update_check_stale"] = None
    try:
        from email_triage.update_check import (
            load_check_health, update_check_stale,
        )
        _url = getattr(config.admin_email, "release_check_url", "") or ""
        state["update_check_stale"] = update_check_stale(
            load_check_health(db), _url,
            now=(now or datetime.now(timezone.utc)),
        )
    except Exception as exc:
        log.warning("daily health: update-check health unreadable",
                    error=str(exc))
    if state["update_check_stale"]:
        _st = state["update_check_stale"]
        state["attention_reasons"].append(
            f"{_st['title']}: no successful check of "
            f"{_st['host']} since {_st['since'] or 'it was turned on'} "
            f"({_st['cause']}); security updates cannot be announced until "
            "a check succeeds"
        )

    # --- Retry-queue dead-pattern section ---------------------
    # Surface accounts piling up abandoned retries, or an install-wide
    # spike. Returns ``None`` on a clean day so the email body doesn't
    # grow a redundant "retry queue: nothing to report" line.
    try:
        state["retry_deads"] = gather_retry_deads_section(db)
    except Exception:
        state["retry_deads"] = None

    # --- Embedding runtime update required (punch 569 D5) ----------------
    # The admin alert emails this ONCE per transition; this section repeats
    # it daily until it is fixed, and it flips the subject to Attention.
    # Panel B3 db F569-5: the section scans the runtime prefix (filesystem,
    # no DB). The daily tick computes it before taking the DB lock and passes
    # it in; only a caller that did not (the admin "send now") scans here.
    state["embedding_runtime"] = (
        gather_embedding_runtime_section(config)
        if embedding_runtime_section is _COMPUTE_HERE
        else embedding_runtime_section
    )
    # A non-security update that WAITS for the next restart (operator ruling R1) is
    # shown, never silent, but it is not an attention item: the old runtime is
    # serving and the app applies the update itself at the next start.
    if state["embedding_runtime"] and (
        state["embedding_runtime"].get("kind") != "auto_deferred"
        # Panel T DA SHOULD-A1b: a deferral that recurred 3 starts or lasted 7 days is
        # no longer "waiting for the next restart": the operator's no-intervention goal
        # is failing quietly, so it flips the subject to Attention.
        or state["embedding_runtime"].get("escalated")
    ):
        state["attention_reasons"].append(
            state["embedding_runtime"]["headline"]
        )
    # Operator decision 2026-10-25: the app updates the runtime itself. News,
    # not a request, so it does NOT flip the subject to Attention; it is shown
    # while the update is inside the notice window (one daily email).
    try:
        state["embedding_runtime_updated"] = gather_embedding_auto_updated_section(db)
    except Exception:
        state["embedding_runtime_updated"] = None
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
            # Panel AB MUST (C2-display): hashed-derived address first, the
            # unhashed stored copy beside it when they differ.
            "SELECT ake.ts, ake.event, ake.name, ake.source, "
            "       COALESCE(au.email, ake.actor_email) AS actor_email, "
            "       ake.actor_email AS recorded_actor_email, "
            "       tu.email AS target_email "
            "FROM api_key_events ake "
            "LEFT JOIN users au ON au.id = ake.actor_user_id "
            "LEFT JOIN users tu ON tu.id = ake.target_user_id "
            "WHERE ake.ts >= ? ORDER BY ake.id DESC LIMIT 5",
            (since_24h,),
        ).fetchall()
        api_key_events_recent = [dict(r) for r in rows]
    except DB_ERRORS as e:
        log.error("health: API-key event counts unavailable", exc_info=e)
    state["api_key_events_count"] = api_key_events_count
    state["api_key_events_recent"] = api_key_events_recent

    # --- Queue + storage --------------------------------------------------
    log_row_count = 0
    try:
        log_row_count = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
    except DB_ERRORS as e:
        log.error("health: log_entries row count unavailable", exc_info=e)
    state["log_row_count"] = log_row_count

    # --- Pub/Sub (gated on #1 shipping) -----------------------------------
    # Until #1 lands there's no push_queue metric to surface; render
    # "not configured" so the section exists but isn't misleading.
    state["pubsub_configured"] = bool(config.push.gmail_topic_name)

    # --- O365 Graph subscriptions ---------------------------------
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
        # census run17  — account_email SSOT, not the open-coded key.
        from email_triage.db.accounts import account_email
        try:
            for a in list_email_accounts(db) or []:
                aid = a.get("id")
                if aid is not None:
                    _name_by_id[int(aid)] = (
                        a.get("name") or account_email(a) or ""
                    )
        except Exception as e:
            log.warning("health: account name lookup failed; using ids", error=fmt_exc(e))

        def _label(account_id) -> str:
            aid_int = parse_int_or_none(account_id)  # N-219c/38 R23: SSOT
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
            exp = parse_iso(exp_raw)
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
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
    except Exception as e:
        # Read failure shouldn't kill the digest. Exception already covers
        # both drivers' Error (each derives from it); never nest a funnel
        # tuple inside an except tuple -- Python raises TypeError at match
        # time (punch 560 panel, db-sme F1).
        log.error("health: office365 push block unavailable", exc_info=e)
    state["office365_push"] = o365_block

    # --- Gateway / container health placeholder ---------------------------
    # Minimal: if we can query the DB we're up. Detailed gateway probing
    # is out of scope for .
    state["gateway_ok"] = True

    # --- TLS cert expiry warning -----------------------------------
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
    except Exception as e:
        # Cert read failures shouldn't fail the health email build.
        log.error("health: cert expiry check failed", exc_info=e)

    # --- Restore witness markers pending (punch 711, panel AB) -----------
    # Derived from the data dir on every build (no flag to set or clear,
    # PD-18): a marker stays on disk until its restore is recorded, so one
    # that pends (no swap yet, or failing to ingest) is never log-only.
    try:
        from pathlib import Path as _Path
        from email_triage.backup import pending_restore_witness_markers
        _pending = pending_restore_witness_markers(
            _Path(config.persistence.db_path).parent)
        state["restore_witness_pending"] = len(_pending)
        if _pending:
            state["attention_reasons"].append(
                f"{len(_pending)} restore witness marker(s) pending in the data "
                "dir: a restore was extracted but is not yet in the audit chain "
                "(swap not done, or the record failed; see the startup log)"
            )
    except Exception:
        state["restore_witness_pending"] = 0

    # --- Listener-mode restart pending ------------------------------
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
        except Exception as e:
            # Defensive: a bad import / state shouldn't kill the digest.
            log.warning("health: listener-restart check failed", error=fmt_exc(e))

    return state


def _hipaa_count_text(state: dict[str, Any]) -> str:
    """The HIPAA access-event count as shown in both digest bodies.

    ``None`` means the query failed: render "unavailable", never 0.
    """
    n = state["hipaa_events_count"]
    return "unavailable (query failed; see log)" if n is None else str(n)


def is_interesting(state: dict[str, Any]) -> bool:
    """Return True when the digest should be sent in quiet mode.

    Anything that bumped an Attention reason, or any non-zero error /
    HIPAA / API-key activity, is interesting.  A clean day is dropped.
    """
    if state["attention_reasons"]:
        return True
    #  Part 3 — N-151 credential-store SOFT-gate active is a
    # first-class quiet-mode wake-up: the operator MUST see it even
    # when nothing else is off.  (Kept as its own arm so a future
    # refactor of ``attention_reasons`` doesn't accidentally hide it.)
    if state.get("n151_soft_gate", {}).get("active"):
        return True
    if state.get("error_count_24h", 0) > 0:
        return True
    if state.get("warning_count_24h", 0) > 0:
        return True
    if state.get("triage_total", 0) > 0:
        return True
    _hipaa_n = state.get("hipaa_events_count", 0)
    if _hipaa_n is None or _hipaa_n > 0:  # None = unavailable: interesting
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

def _security_update_sentence(sec: dict[str, Any]) -> str:
    """The one plain-English sentence both email bodies use (punch 553)."""
    latest = sec.get("latest_tag") or "the newest release"
    if sec.get("reason") == "marker_absent":
        return (
            f"The newest release ({latest}) does not say whether it fixes a "
            "security problem, so treat it as one and update."
        )
    if sec.get("reason") == "marker_unparseable":
        return (
            f"The newest release ({latest}) carries security information "
            "this install could not read, so treat it as a security update "
            "and update."
        )
    target = sec.get("target_version") or latest
    return (
        f"Update to {target} or later: it fixes a security problem rated "
        f"{sec.get('severity')}."
    )


def _api_key_actor_display(e: dict[str, Any]) -> str:
    """WHO for one api_key_events row (punch 710, panel AB MUST C2-display): the
    address resolved from the hashed ``actor_user_id`` (or, for a CLI row, the
    stored copy), plus the stored copy beside it when the two differ."""
    actor = e.get("actor_email") or "(unknown)"
    recorded = e.get("recorded_actor_email")
    if recorded and recorded != e.get("actor_email"):
        actor += f" (recorded as {recorded})"
    return actor


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

    # 0.5. Credential store (N-151 SOFT-gate) —  REDESIGNED v3 Part 3.
    # Renders as the FIRST content section (above the Status chip row)
    # ONLY when the SOFT-gate is active — the operator's eye lands on
    # it right after the ⚠ Attention banner because a broken MSAL
    # master key means Office 365 accounts silently stop fetching mail.
    # Silent on a healthy day so the digest doesn't grow a permanent
    # "credentials OK" line.
    _n151 = state.get("n151_soft_gate") or {}
    if _n151.get("active"):
        parts.append("<h3>Credential store</h3>")
        parts.append(
            '<div style="padding: 0.5rem 1rem; background: #fff4e5; '
            'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
        )
        # DA R4 CIDI-drift fold (2026-07-10): escape the reason + since
        # before interpolating.  The sibling render site
        # ``_assemble_n151_soft_gate_alert`` in ``web/admin_alerts.py``
        # already ``html.escape``s both fields; mirroring the escape
        # here converges the two render sites (Prime Directive #5).
        _reason_raw = _n151.get("reason", "unavailable")
        parts.append(
            "<p><strong>MSAL master key unavailable.</strong> "
            f"Reason: <code>{_html_escape(str(_reason_raw))}</code>.</p>"
        )
        _since = _n151.get("since")
        if _since:
            parts.append(
                f"<p>SOFT-gate active since <code>{_html_escape(str(_since))}</code>.</p>"
            )
        else:
            parts.append(
                "<p>SOFT-gate active (start time not recorded).</p>"
            )
        parts.append(
            '<p style="font-size:0.9em;color:#555;">'
            'Office 365 accounts cannot decrypt cached refresh tokens '
            'until the master key is restored — new mail will not be '
            'ingested.  Restore the key or re-authenticate the affected '
            'account(s) from Admin → Accounts.'
            '</p>'
        )
        parts.append("</div>")

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
        parts.append(
            "<h3>Error tail</h3><p>Errors first, then warnings, newest first "
            f"within each: showing {len(state['error_rows'])} of "
            f"{state.get('error_count_24h', 0) + state.get('warning_count_24h', 0)} "
            f"entries ({state.get('error_count_24h', 0)} error(s), "
            f"{state.get('warning_count_24h', 0)} warning(s)) in the last 24h.</p><ul>"
        )
        for row in state["error_rows"]:
            parts.append(
                f"<li><code>{_html_escape(str(row['ts']))}</code> "
                f"<strong>{_html_escape(str(row['level']))}</strong> "
                f"{_html_escape(str(row['logger']))} — "
                f"{_html_escape(str(row['message']))}</li>"
            )
        parts.append("</ul>")

    # 4a. HIPAA audit — DROPPED when system HIPAA mode is on.
    if (
        config.health_email.include_hipaa_events
        and not state["hipaa_mode"]
    ):
        parts.append("<h3>HIPAA access events</h3>")
        parts.append(
            f"<p>Count last 24h: <strong>{_hipaa_count_text(state)}</strong></p>"
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
                # The stored address is unhashed DB text: escape it.
                actor = _html_escape(_api_key_actor_display(e))
                parts.append(
                    f"<li><code>{e['ts']}</code> "
                    f"{e['event']} key '{e['name']}' by {actor} "
                    f"via {e['source']}</li>"
                )
            parts.append("</ul>")

    # 4c. BAA expirations. Renders ONLY when at
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

    # 4c-bis. Retry queue dead-pattern section. Renders ONLY
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

    # 4c'. Security update (punch 553). Renders whenever the update check's
    # facts say the running version is missing a security fix; ignores
    # include_update_available (see gather_health_state). Every dynamic
    # value is escaped (R18).
    sec = state.get("security_update")
    if sec:
        _e = _html_escape
        parts.append(
            '<h3 style="color:#b42318;">Security update required</h3>'
        )
        parts.append(
            "<p>This install runs version "
            f"<strong>{_e(str(sec['running_version']))}</strong>. "
            f"{_e(_security_update_sentence(sec))}</p>"
        )
        if sec.get("advisories"):
            parts.append(
                "<p><strong>Advisories:</strong> "
                + ", ".join(_e(str(a)) for a in sec["advisories"])
                + "</p>"
            )
        if sec.get("release_url"):
            parts.append(
                f'<p><a href="{_e(str(sec["release_url"]))}">Read the '
                "release notes</a></p>"
            )
        parts.append(
            "<p><em>This notice repeats every day until the install is "
            "updated.</em></p>"
        )

    # 4c''. Update check failing (db F-O5-1) — escaped (R18).
    st = state.get("update_check_stale")
    if st:
        parts.append(
            '<h3 style="color:#b42318;">'
            f"{_html_escape(str(st['title']))}</h3>"
        )
        parts.append(
            "<p>No successful check of "
            f"<strong>{_html_escape(str(st['host']))}</strong> since "
            f"{_html_escape(str(st['since'] or 'it was turned on'))} "
            f"({_html_escape(str(st['cause']))}). "
            "Until a check succeeds this install cannot be told about "
            f"security updates. {_html_escape(str(st['advice']))}</p>"
        )

    # 4c-ter. Embedding runtime update required (punch 569 D5). Silent when
    # the runtime is current, absent, or not in use.
    er = state.get("embedding_runtime")
    if er:
        import html as _html

        parts.append(f"<h3>{_html.escape(er['headline'])}</h3>")
        parts.append(f"<p>{_html.escape(er['consequence'])}</p>")
        if er.get("advisories"):
            parts.append(
                "<p>Advisories: "
                + ", ".join(
                    f"<code>{_html.escape(str(a))}</code>" for a in er["advisories"]
                )
                + "</p>"
            )
        if er.get("kind") == "update":
            if er.get("link"):
                parts.append(
                    '<p>Click <strong>Update embedding runtime</strong> on '
                    f'<a href="{_html.escape(er["link"])}">the AI Backends page</a>.</p>'
                )
            else:
                parts.append(
                    "<p>Click <strong>Update embedding runtime</strong> on the "
                    "AI Backends tab of the admin settings.</p>"
                )

    # 4c-quater. Embedding runtime updated automatically (operator decision
    # 2026-10-25). After-the-fact news; silent outside the notice window.
    eu = state.get("embedding_runtime_updated")
    if eu:
        import html as _html

        parts.append(f"<h3>{_html.escape(eu['headline'])}</h3>")
        parts.append(
            f"<p>Manifest {_html.escape(eu['versions'])}; security fix: "
            f"{_html.escape(eu['security_label'])}"
            + (f"; {_html.escape(eu['at'])}" if eu["at"] else "")
            + ".</p>"
        )
        if eu["advisories"]:
            parts.append(
                "<p>Advisories: "
                + ", ".join(f"<code>{_html.escape(a)}</code>" for a in eu["advisories"])
                + "</p>"
            )
        if eu["restart_message"]:
            parts.append(f"<p><strong>{_html.escape(eu['restart_message'])}</strong></p>")

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
                f'<p><a href="{_html_escape(str(upd["release_url"]))}">'
                'View release on GitHub</a></p>'
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
        #  — O365 Graph subscriptions sibling line. Conditional on
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

    #  — restore-key freshness: the automated backups can't be restored
    # without the operator's key-only export.
    _lke = state.get("last_key_export")
    if _lke:
        parts.append(
            f"<p>Last key export: <strong>{_lke[:10]}</strong> "
            "<small>(keep your key-only backup current — it's the restore key)"
            "</small></p>"
        )
    else:
        parts.append(
            "<p style='color:#c00'><strong>No restore-key export on record</strong>"
            " — export the key-only backup (Admin → Backup); the automated "
            "backups cannot be restored without it.</p>"
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

    # Credential store (N-151 SOFT-gate) — text twin of the HTML block.
    # Silent on a healthy day; when active it sits ABOVE the Status
    # block so the operator sees it first.
    _n151 = state.get("n151_soft_gate") or {}
    if _n151.get("active"):
        lines.append("Credential store:")
        lines.append(
            f"  MSAL master key unavailable "
            f"(reason: {_n151.get('reason', 'unavailable')})."
        )
        _since = _n151.get("since")
        if _since:
            lines.append(f"  SOFT-gate active since {_since}.")
        else:
            lines.append("  SOFT-gate active (start time not recorded).")
        lines.append(
            "  Office 365 accounts cannot decrypt cached refresh tokens "
            "until the master key is restored."
        )
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
        lines.append(
            "Error tail (errors first, then warnings; showing "
            f"{len(state['error_rows'])} of "
            f"{state.get('error_count_24h', 0) + state.get('warning_count_24h', 0)} "
            f"entries: {state.get('error_count_24h', 0)} error(s), "
            f"{state.get('warning_count_24h', 0)} warning(s) in 24h):"
        )
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
        lines.append(f"  Count last 24h: {_hipaa_count_text(state)}")
        if state["hipaa_recent_actors"]:
            lines.append(f"  Recent actors: {', '.join(state['hipaa_recent_actors'])}")
        lines.append("")

    if config.health_email.include_api_key_events:
        lines.append("API key events:")
        lines.append(f"  Count last 24h: {state['api_key_events_count']}")
        for e in state["api_key_events_recent"]:
            actor = _api_key_actor_display(e)
            lines.append(
                f"  [{e['ts']}] {e['event']} key '{e['name']}' "
                f"by {actor} via {e['source']}"
            )
        lines.append("")

    # Embedding runtime update required (punch 569 D5). Sibling to the
    # HTML block; silent when nothing is needed.
    er = state.get("embedding_runtime")
    if er:
        lines.append("")
        lines.append(er["headline"])
        lines.append("-" * len(er["headline"]))
        lines.append(er["consequence"])
        if er.get("advisories"):
            lines.append("Advisories: " + ", ".join(str(a) for a in er["advisories"]))
        if er.get("kind") == "update":
            lines.append(
                "Click [Update embedding runtime] on "
                + (er["link"] if er.get("link") else
                   "the AI Backends tab of the admin settings")
                + "."
            )

    # Embedding runtime updated automatically (operator decision 2026-10-25).
    eu = state.get("embedding_runtime_updated")
    if eu:
        lines.append("")
        lines.append(eu["headline"])
        lines.append("-" * len(eu["headline"]))
        lines.append(
            f"Manifest {eu['versions']}; security fix: {eu['security_label']}"
            + (f"; {eu['at']}" if eu["at"] else "")
            + "."
        )
        if eu["advisories"]:
            lines.append("Advisories: " + ", ".join(eu["advisories"]))
        if eu["restart_message"]:
            lines.append(eu["restart_message"])

    # Retry queue dead-pattern section. Sibling to the
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

    # Security update (punch 553) — sibling of the HTML block above.
    sec = state.get("security_update")
    if sec:
        lines.append("")
        lines.append("SECURITY UPDATE REQUIRED")
        lines.append("-" * 24)
        lines.append(f"This install runs version {sec['running_version']}.")
        lines.append(_security_update_sentence(sec))
        if sec.get("advisories"):
            lines.append("Advisories: " + ", ".join(
                str(a) for a in sec["advisories"]
            ))
        if sec.get("release_url"):
            lines.append(f"Release notes: {sec['release_url']}")
        lines.append(
            "This notice repeats every day until the install is updated."
        )
        lines.append("")

    # Update check failing (db F-O5-1) — sibling of the HTML block above.
    st = state.get("update_check_stale")
    if st:
        lines.append("")
        _title = str(st["title"]).upper()
        lines.append(_title)
        lines.append("-" * len(_title))
        lines.append(
            f"No successful check of {st['host']} since "
            f"{st['since'] or 'it was turned on'} ({st['cause']})."
        )
        lines.append(
            "Until a check succeeds this install cannot be told about "
            f"security updates. {st['advice']}"
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
        #  — O365 sibling line in the text-mode digest.
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

    #  — restore-key freshness (the automated backups need this key).
    _lke = state.get("last_key_export")
    lines.append("")
    if _lke:
        lines.append(
            f"Last key export: {_lke[:10]} "
            "(keep your key-only backup current -- it's the restore key)."
        )
    else:
        lines.append(
            "WARNING: no restore-key export on record -- export the key-only "
            "backup (Admin -> Backup); the automated backups cannot be restored "
            "without it."
        )

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
    from email_triage.web.smtp_send import stamp_default_message_headers

    msg = EmailMessage()
    date_str = state["now"].strftime("%Y-%m-%d")
    flag = "⚠ Attention" if state["attention_reasons"] else "OK"
    msg["Subject"] = f"[email-triage] Daily health {date_str} — {flag}"
    # N-272b R28 SSOT — RFC-preferred GMT Date + Message-Id at build time.
    # Punch 599: the Message-Id domain is the configured sender's.
    stamp_default_message_headers(
        msg, from_addr=getattr(getattr(config, "smtp", None), "from_addr", ""),
    )
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
    embedding_runtime_section: Any = _COMPUTE_HERE,
) -> tuple[bool, str]:
    """Send the digest now. Returns ``(sent, reason)``.

    ``force=True`` bypasses ``quiet_mode`` — used by the "Send now"
    admin button so ops can verify wiring even on a boringly healthy day.
    ``app`` (FastAPI instance) enables the listener-restart-pending
    check — passed through from the supervisor; tests can omit.
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

    #  — gather_health_state issues many raw reads on the shared
    # sqlite3 connection. send_daily_health_email runs from the
    # daily-health background loop (and the admin "Send now" button);
    # the background path is NOT routed through db_call, so the read
    # batch is taken under the process-wide DB lock to serialise
    # against any request-surface db_call worker. The lock spans the
    # whole snapshot so it is also internally consistent; it is
    # released before the SMTP send so a slow network send never
    # holds the DB lock. (RLock — re-entrant if the admin-button
    # caller is already inside db_call.)
    from email_triage.web.db_writelock import get_write_lock
    with get_write_lock():
        state = gather_health_state(
            db, config, watcher_manager, app=app,
            embedding_runtime_section=embedding_runtime_section,
        )
    if cfg.quiet_mode and not force and not is_interesting(state):
        return False, "quiet_mode: nothing interesting"

    msg = assemble_daily_health_email(state, config)
    msg["From"] = format_from_header(smtp.from_addr, smtp.from_name)
    msg["To"] = ", ".join(recipients)

    password = ""
    if secrets is not None:
        try:
            password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            # A5 — fail closed + diagnose distinctly: unreadable secret
            # store (master-key mismatch) is not "no password set".
            log.error("Daily health email aborted — SMTP password "
                      "unreadable (corrupt secret row or master-key mismatch)")
            return False, "secret store unreadable: SMTP_PASSWORD"

    try:
        from email_triage.web.smtp_send import send_smtp_message
        send_smtp_message(
            msg, smtp_host=smtp.host, smtp_port=smtp.port,
            smtp_user=smtp.username, smtp_password=password, use_tls=smtp.use_tls,
        )
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
    repo_url: str = PUBLIC_REPO_URL,
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
        # Punch 585, panel B5 hipaa B-1: the issue tracker is PUBLIC (no BAA), and
        # journal output can carry PHI-adjacent fields, so the product must never
        # ask for it there.
        f"If this keeps happening, open an issue at {repo_url}/issues",
        "describing the failure and the version. Do not attach logs, journal",
        "output or screenshots: they can contain protected health information.",
        "If maintainers need logs, share them only through a channel your BAA",
        "covers.",
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
        f'<a href="{repo_url}/issues">open an issue</a> describing the failure '
        'and the version. Do not attach logs, journal output or screenshots: '
        'they can contain protected health information. If maintainers need '
        'logs, share them only through a channel your BAA covers.</p>'
        '</div>'
    )

    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER, build_triage_header,
    )
    from email_triage.web.smtp_send import stamp_default_message_headers

    msg = EmailMessage()
    msg["Subject"] = subject
    # N-272b R28 SSOT — RFC-preferred GMT Date + Message-Id at build time.
    stamp_default_message_headers(msg)
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
            password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            # A5 — fail closed + diagnose distinctly (see sibling sender).
            log.error("Update-failed email aborted — SMTP password "
                      "unreadable (corrupt secret row or master-key mismatch)")
            return False, "secret store unreadable: SMTP_PASSWORD"

    try:
        from email_triage.web.smtp_send import send_smtp_message
        send_smtp_message(
            msg, smtp_host=smtp.host, smtp_port=smtp.port,
            smtp_user=smtp.username, smtp_password=password, use_tls=smtp.use_tls,
        )
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
