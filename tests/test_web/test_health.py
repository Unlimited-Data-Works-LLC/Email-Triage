"""Tests for ``GET /health`` (minimal, public) and ``GET /health/detail``
(operator detail, admin-only).

Split into two endpoints in #89 (2026-04-30). Keep these tests in sync
with the Containerfile HEALTHCHECK + scripts/deploy-deployhost.sh post-deploy
probe (both still hit /health).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token


def _admin_cookie_pair():
    """Mint a session cookie matching the conftest test secret +
    admin_user fixture's email/role."""
    return (
        SESSION_COOKIE_NAME,
        create_session_token(
            "test-session-secret-for-signing", "admin@test.com", "admin",
        ),
    )


# ---------------------------------------------------------------------------
# /health -- minimal public probe (#89)
# ---------------------------------------------------------------------------

def test_minimal_health_shape(client, db):
    """/health returns just status + uptime + db. No counters, no
    version, no task names. Status code carries the up-vs-degraded
    signal."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"status", "uptime_secs", "db"}
    assert body["status"] == "ok"
    assert isinstance(body["uptime_secs"], int) and body["uptime_secs"] >= 0
    assert body["db"] == "ok"


def test_minimal_health_unauth_ok(client, db):
    """No session cookie required for the public probe."""
    client.cookies.clear()
    resp = client.get("/health", headers={})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_minimal_health_503_on_db_error(client, db, app):
    """db field flips to error + 503 when the DB connection breaks."""
    db.close()
    resp = client.get("/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["db"] == "error"


# ---------------------------------------------------------------------------
# /health/detail -- admin-only operator surface (#89)
# ---------------------------------------------------------------------------

def test_detail_requires_auth(client, db):
    """Anonymous → 303 redirect to /login."""
    client.cookies.clear()
    resp = client.get("/health/detail", follow_redirects=False)
    assert resp.status_code in (303, 302)
    assert "/login" in resp.headers.get("location", "")


def test_detail_requires_admin(client, db, regular_user, user_cookies):
    """Authenticated non-admin → 403."""
    client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
    resp = client.get("/health/detail")
    assert resp.status_code == 403


def test_detail_returns_full_shape(client, db, admin_user):
    """Admin gets the full operator-facing payload verbatim -- same
    keys the prior single /health surface returned."""
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {
        "status", "uptime_secs", "db",
        "ingestion", "mailboxes", "poll", "watchers",
        "last_triage", "version",
        "tasks", "watchers_failing", "audit_failures",
        "csrf_rejects", "schema_version",
        # #66 — top-level O365 push rollup mirrors the gmail_push line
        # nested under watchers.
        "office365_push",
        # #151 — classification cache counters (enabled, hits, misses,
        # errors). Always present; values reflect the cache singleton
        # (disabled + zeros in the default test config).
        "classification_cache",
        # 2026-05-13 — embedding backend live state + per-call counters.
        # ``configured=false`` + empty metrics when no embedding backend
        # is wired (the test config doesn't set one); admin tab + stats
        # page render an "off" chip in that case.
        "embedding",
        # 2026-05-13 — webhook counters (process + lifetime). Empty
        # dicts in the default test config (no push integrations,
        # no Redis); admin/stats card hides itself in that case.
        "webhooks",
        # 2026-05-15 — schema-compat verdict for Nagios. Same data
        # the admin /config banner uses, in machine-readable shape.
        # Failure-safe: reduces to {"state": "unknown", ...} if the
        # version helper throws.
        "version_status",
        # 2026-05-15 — #169 Wave 2-α I7. BAA expiry surfacing.
        # {"expiring_soon": int, "expired": int,
        #  "expired_hipaa_accounts_disabled": int}. All zeros in
        # the empty-DB test case; populated when ai_backends rows
        # carry close-to-expiry BAAs.
        "baa_status",
        # 2026-05-16 — HIPAA describe-and-discard distill 24h roll-up
        # (#152 phases 3-4 S4). Sibling to version_status. Shape:
        # {local_24h, cloud_24h, failures_24h, scrubber_rejects_24h,
        #  total_24h}.
        "style_distill",
        # 2026-05-17 — #175 R-B. Watcher per-message retry-queue
        # rollup. Shape: {pending, dead_24h, oldest_pending_age_sec,
        # dead_breakdown_24h}. Failure-safe: reduces to
        # {"state": "unknown", "error": ...} when the table is
        # missing (pre-v30 install).
        "retry_queue",
    }
    assert body["status"] == "ok"
    sd = body["style_distill"]
    for k in ("local_24h", "cloud_24h", "failures_24h",
              "scrubber_rejects_24h", "total_24h"):
        assert k in sd, f"style_distill missing key {k!r}"
        assert isinstance(sd[k], int)


# ---------------------------------------------------------------------------
# Degraded-state behaviour (admin /health/detail surface)
# ---------------------------------------------------------------------------


def test_health_degraded_when_watcher_stale(client, db, app, admin_user):
    """A watcher whose ``started_at`` is > 15 min old and whose status
    is NOT ``watching`` should flip overall status to ``degraded``."""
    watcher_mgr = app.state.watcher_manager
    # Account row required: account_states folds over email_accounts.
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (admin_user["id"], "stale-acct", "imap", "{}", 1, now_iso, now_iso),
    )
    acct_id = cur.lastrowid
    db.commit()
    stale_dt = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    watcher_mgr._mb_state[(acct_id, "INBOX")] = {
        "status": "reconnecting",
        "processed": 0,
        "errors": 1,
        "last_message": None,
        "last_error": "connection refused",
        "started_at": stale_dt,
    }
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    assert resp.status_code == 503
    body = resp.json()
    assert body["ingestion"]["imap"]["total"] == 1
    assert body["ingestion"]["imap"]["uncovered"] == 1
    assert body["status"] == "degraded"


def test_health_watcher_connected_counts(client, db, app, admin_user):
    """Watchers in state ``watching`` count as connected; others don't."""
    watcher_mgr = app.state.watcher_manager
    now_iso = datetime.now(timezone.utc).isoformat()
    aids = []
    for name in ("acct-a", "acct-b"):
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (admin_user["id"], name, "imap", "{}", 1, now_iso, now_iso),
        )
        aids.append(cur.lastrowid)
    db.commit()
    watcher_mgr._mb_state[(aids[0], "INBOX")] = {
        "status": "watching",
        "started_at": now_iso,
    }
    watcher_mgr._mb_state[(aids[1], "INBOX")] = {
        "status": "starting",
        "started_at": now_iso,
    }
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    body = resp.json()
    assert body["ingestion"]["imap"]["total"] == 2
    assert body["ingestion"]["imap"]["push"] == 1
    # "starting" within the 15-min window is NOT stale, so status stays ok.
    assert body["status"] == "ok"


def test_health_degraded_when_last_triage_old(client, db, app, admin_user):
    """With a connected watcher and a triage_runs row older than 24 h,
    status must flip to ``degraded`` and ``last_triage`` must be
    surfaced in the response."""
    watcher_mgr = app.state.watcher_manager
    watcher_mgr._mb_state[(1, "INBOX")] = {
        "status": "watching",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    # Insert an email_accounts row so the FK on triage_runs is satisfied.
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (admin_user["id"], "stale-acct", "imap", "{}", 1, now_iso, now_iso),
    )
    acct_id = cur.lastrowid
    stale_created = (datetime.now(timezone.utc) - timedelta(hours=36)).isoformat()
    db.execute(
        "INSERT INTO triage_runs (account_id, account_name, query, "
        "total_messages, results_json, errors_json, elapsed_secs, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (acct_id, "stale-acct", "test", 0, "[]", "[]", 0.0, stale_created),
    )
    db.commit()

    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    # Stale triage means degraded → HTTP 503.
    assert resp.status_code == 503
    body = resp.json()
    # last_triage is serialized in the container's local tz, not UTC,
    # so compare via parsed dt values (both are tz-aware) instead of
    # raw string equality.
    returned = datetime.fromisoformat(body["last_triage"])
    original = datetime.fromisoformat(stale_created)
    assert returned == original
    assert body["status"] == "degraded"


def test_health_last_triage_rendered_in_local_tz(
    client, db, app, admin_user, monkeypatch,
):
    """``last_triage`` is written to DB as UTC but returned over the wire
    converted to the container's local timezone. Set TZ explicitly + assert
    the returned ISO carries the correct offset (not ``+00:00``)."""
    import os
    import time as _time

    # Force a specific tz for this test so the offset is predictable.
    monkeypatch.setenv("TZ", "America/Detroit")
    if hasattr(_time, "tzset"):
        _time.tzset()

    now_iso = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (admin_user["id"], "tz-acct", "imap", "{}", 1, now_iso, now_iso),
    )
    acct_id = cur.lastrowid
    utc_ts = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO triage_runs (account_id, account_name, query, "
        "total_messages, results_json, errors_json, elapsed_secs, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (acct_id, "tz-acct", "test", 0, "[]", "[]", 0.0, utc_ts),
    )
    db.commit()

    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    # This test focuses on TZ rendering, not the degraded vs ok
    # axis. With one IMAP account and no watcher state the
    # uncovered-account alert flips degraded (HTTP 503 since
    # PR 5 / C1) — the body shape is what we care about here.
    assert resp.status_code in (200, 503)
    body = resp.json()
    returned = body["last_triage"]
    assert returned is not None
    # Must parse as tz-aware.
    dt = datetime.fromisoformat(returned)
    assert dt.tzinfo is not None
    # Detroit is UTC-4 (EDT) or UTC-5 (EST). Must NOT be +00:00.
    offset_hrs = dt.utcoffset().total_seconds() / 3600
    assert offset_hrs in (-4, -5), (
        f"Expected Detroit offset -4/-5, got {offset_hrs} from {returned}"
    )
    # Value-equality: parsed returned-dt equals parsed UTC-stored-dt.
    assert dt == datetime.fromisoformat(utc_ts)


# ---------------------------------------------------------------------------
# #120 — disabled accounts excluded from account_states
# ---------------------------------------------------------------------------


def test_disabled_account_does_not_degrade_health(
    client, db, app, admin_user,
):
    """An ``is_active=0`` account is operator-disabled. Its mode is
    "none" by definition (no push, no poll), but that's the EXPECTED
    state -- not a degraded signal. ``account_states`` must skip it
    so ``alert='no_ingestion'`` does not fire and tip ``any_alert``,
    which would degrade /health forever.

    Regression test for the deploy-time 503 caused by a partially-
    configured legacy account (item #120 health-aggregation fix)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    # Active account with a watching mailbox -> not degraded.
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, 'active-acct', 'imap', '{}', 1, ?, ?)",
        (admin_user["id"], now_iso, now_iso),
    )
    active_id = cur.lastrowid
    # Disabled stub -- the kind a half-finished wizard / partial
    # manual config leaves behind.
    db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, 'partial-stub', 'office365', "
        "'{\"client_id\": \"1\"}', 0, ?, ?)",
        (admin_user["id"], now_iso, now_iso),
    )
    db.commit()
    watcher_mgr = app.state.watcher_manager
    watcher_mgr._mb_state[(active_id, "INBOX")] = {
        "status": "watching",
        "processed": 0,
        "errors": 0,
        "last_message": None,
        "last_error": None,
        "started_at": now_iso,
    }

    states = watcher_mgr.account_states(db)
    # Only the active account appears. The disabled stub is skipped
    # at the source of truth.
    assert len(states) == 1
    assert states[0]["account_name"] == "active-acct"
    # No "no_ingestion" alert because the active account IS ingesting,
    # and the disabled stub is excluded from the fold.
    assert states[0]["alert"] is None

    # /health surface inherits the same fold -> ok.
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# #125 partial follow-up — version_status on /health/detail (Nagios surface)
# ---------------------------------------------------------------------------


def test_health_detail_version_status_shape(client, db, admin_user, monkeypatch):
    """The version_status block carries the same fields the admin banner
    consumes. Default test config (in-memory DB, no previous-caps env
    var) reads ``state=update_available`` because the migration
    registry has migrations but the in-memory DB file does not exist
    on disk and ``read_db_schema_version`` returns 0 for that path."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    body = resp.json()
    vs = body["version_status"]
    # Field shape — every key the dataclass exposes, plus our
    # ``status`` -> ``state`` rename for Nagios consistency.
    assert set(vs.keys()) == {
        "app_version",
        "db_schema_version",
        "target_schema_caps",
        "previous_schema_caps",
        "state",
        "explanation",
    }
    assert isinstance(vs["app_version"], str) and vs["app_version"]
    assert isinstance(vs["db_schema_version"], int)
    assert isinstance(vs["target_schema_caps"], int)
    # In-memory DB path doesn't exist on disk -> schema reads as 0.
    assert vs["db_schema_version"] == 0
    # Source registry has at least one migration.
    assert vs["target_schema_caps"] >= 1
    # No env var set -> previous caps stays None.
    assert vs["previous_schema_caps"] is None
    # Default case: target > db, no previous caps -> update_available.
    assert vs["state"] == "update_available"
    assert isinstance(vs["explanation"], str) and vs["explanation"]


def test_health_detail_version_status_state_up_to_date(
    client, db, app, admin_user, monkeypatch,
):
    """When the live DB schema equals the target binary's known cap,
    state reads ``up_to_date``. Forced by stubbing the helper so we
    don't need to mutate the real migrations registry mid-test."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    from email_triage import version as version_mod
    from email_triage.version import VersionStatus, describe_status, STATUS_UP_TO_DATE

    def _fake(_db_path):
        return VersionStatus(
            app_version="1.2.3",
            db_schema_version=25,
            target_schema_caps=25,
            previous_schema_caps=None,
            status=STATUS_UP_TO_DATE,
            explanation=describe_status(STATUS_UP_TO_DATE),
        )

    monkeypatch.setattr(version_mod, "gather_version_status", _fake)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    vs = resp.json()["version_status"]
    assert vs["state"] == "up_to_date"
    assert vs["db_schema_version"] == 25
    assert vs["target_schema_caps"] == 25
    assert vs["previous_schema_caps"] is None


def test_health_detail_version_status_state_update_available(
    client, db, admin_user, monkeypatch,
):
    """Target binary knows about migrations the live DB hasn't run —
    state reads ``update_available``. Forced via stub for determinism."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    from email_triage import version as version_mod
    from email_triage.version import (
        VersionStatus, describe_status, STATUS_UPDATE_AVAILABLE,
    )

    def _fake(_db_path):
        return VersionStatus(
            app_version="1.2.3",
            db_schema_version=20,
            target_schema_caps=25,
            previous_schema_caps=None,
            status=STATUS_UPDATE_AVAILABLE,
            explanation=describe_status(STATUS_UPDATE_AVAILABLE),
        )

    monkeypatch.setattr(version_mod, "gather_version_status", _fake)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    vs = resp.json()["version_status"]
    assert vs["state"] == "update_available"
    assert vs["target_schema_caps"] > vs["db_schema_version"]


def test_health_detail_version_status_state_incompatible_rollback(
    client, db, admin_user, monkeypatch,
):
    """When the ``:previous`` image's schema cap is below the live DB
    schema version (rollback would fail), state reads
    ``incompatible_rollback`` -- the 2026-05-09 deploy-recovery case."""
    from email_triage import version as version_mod
    from email_triage.version import (
        VersionStatus, describe_status, STATUS_INCOMPATIBLE_ROLLBACK,
    )

    def _fake(_db_path):
        return VersionStatus(
            app_version="1.2.3",
            db_schema_version=14,
            target_schema_caps=15,
            previous_schema_caps=13,
            status=STATUS_INCOMPATIBLE_ROLLBACK,
            explanation=describe_status(STATUS_INCOMPATIBLE_ROLLBACK),
        )

    monkeypatch.setattr(version_mod, "gather_version_status", _fake)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    vs = resp.json()["version_status"]
    assert vs["state"] == "incompatible_rollback"
    assert vs["previous_schema_caps"] == 13
    assert vs["db_schema_version"] == 14


def test_health_detail_version_status_state_downgrade_not_supported(
    client, db, admin_user, monkeypatch,
):
    """When the live DB has been written by a newer binary than the one
    running, state reads ``downgrade_not_supported``. The runtime
    would refuse to open the DB; surfacing this in /health/detail
    lets Nagios alarm without a crash loop."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    from email_triage import version as version_mod
    from email_triage.version import (
        VersionStatus, describe_status, STATUS_DOWNGRADE_NOT_SUPPORTED,
    )

    def _fake(_db_path):
        return VersionStatus(
            app_version="1.2.3",
            db_schema_version=30,
            target_schema_caps=25,
            previous_schema_caps=None,
            status=STATUS_DOWNGRADE_NOT_SUPPORTED,
            explanation=describe_status(STATUS_DOWNGRADE_NOT_SUPPORTED),
        )

    monkeypatch.setattr(version_mod, "gather_version_status", _fake)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    vs = resp.json()["version_status"]
    assert vs["state"] == "downgrade_not_supported"
    assert vs["db_schema_version"] > vs["target_schema_caps"]


def test_health_detail_version_status_failure_safe(
    client, db, admin_user, monkeypatch,
):
    """If ``gather_version_status`` raises, the rest of /health/detail
    must still render. The version_status block reduces to
    ``{"state": "unknown", "error": "<ExcType>: <msg>"}`` and the
    response stays 200 (assuming no other degraded signal)."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    from email_triage import version as version_mod

    def _boom(_db_path):
        raise RuntimeError("migrations registry malformed")

    monkeypatch.setattr(version_mod, "gather_version_status", _boom)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    # No other degraded signal in the default test config -> 200.
    assert resp.status_code == 200
    body = resp.json()
    # Rest of the payload still renders.
    assert "ingestion" in body
    assert "schema_version" in body
    assert "tasks" in body
    # version_status reduces to the unknown sentinel.
    vs = body["version_status"]
    assert vs["state"] == "unknown"
    assert "error" in vs
    assert "RuntimeError" in vs["error"]
    assert "migrations registry malformed" in vs["error"]


def test_health_detail_version_status_without_previous_caps_env(
    client, db, admin_user, monkeypatch,
):
    """Absence of EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS must not break the
    endpoint. ``previous_schema_caps`` reads as null and the state
    stays at ``update_available`` (never escalates to
    ``incompatible_rollback`` without the operator-supplied cap)."""
    monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    assert resp.status_code == 200
    vs = resp.json()["version_status"]
    assert vs["previous_schema_caps"] is None
    # Without the previous-caps env var, the helper never escalates.
    assert vs["state"] in ("up_to_date", "update_available")
