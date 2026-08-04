"""Tests for ``GET /health`` (minimal, public) and ``GET /health/detail``
(operator detail, admin-only).

Split into two endpoints in  (2026-04-30). Keep these tests in sync
with the Containerfile HEALTHCHECK + scripts/deploy.sh post-deploy
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
# /health -- minimal public probe
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
# /health/detail -- admin-only operator surface
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
        #  — top-level O365 push rollup mirrors the gmail_push line
        # nested under watchers.
        "office365_push",
        #  — classification cache counters (enabled, hits, misses,
        # errors). Always present; values reflect the cache singleton
        # (disabled + zeros in the default test config).
        "classification_cache",
        # N-93 — topic-match parse-fail/retry-outcome counters (parse_retried /
        # retry_recovered / retry_failed_dropped + lifetime). Surfaces the §4.4
        # fail-open valve's open-rate as a number; integers only (no PHI).
        "topic_match",
        # 2026-05-13 — embedding backend live state + per-call counters.
        # ``configured=false`` + empty metrics when no embedding backend
        # is wired (the test config doesn't set one); admin tab + stats
        # page render an "off" chip in that case.
        "embedding",
        # 2026-05-13 — webhook counters (process + lifetime). Empty
        # dicts in the default test config (no push integrations,
        # no Redis); admin/stats card hides itself in that case.
        "webhooks",
        # 2026-05-15 — schema-compat verdict for the monitoring system. Same data
        # the admin /config banner uses, in machine-readable shape.
        # Failure-safe: reduces to {"state": "unknown", ...} if the
        # version helper throws.
        "version_status",
        # 2026-05-15 —  Wave 2-α I7. BAA expiry surfacing.
        # {"expiring_soon": int, "expired": int,
        #  "expired_hipaa_accounts_disabled": int}. All zeros in
        # the empty-DB test case; populated when ai_backends rows
        # carry close-to-expiry BAAs.
        "baa_status",
        # 2026-05-16 — HIPAA describe-and-discard distill 24h roll-up
        #. Sibling to version_status. Shape:
        # {local_24h, cloud_24h, failures_24h, scrubber_rejects_24h,
        #  total_24h}.
        "style_distill",
        # 2026-05-17 —  R-B. Watcher per-message retry-queue
        # rollup. Shape: {pending, dead_24h, oldest_pending_age_sec,
        # dead_breakdown_24h}. Failure-safe: reduces to
        # {"state": "unknown", "error": ...} when the table is
        # missing (pre-v30 install).
        "retry_queue",
        #  — on-disk TLS cert expiry. Shape: {present, not_after,
        # days_remaining}. ``present=false`` when no cert on disk (the
        # default test config has none). Pure file read; never raises.
        "tls_cert",
        # the backlog  (N-151-tail db-sme fold) — MSAL master-key
        # availability sibling to baa_status. Shape:
        # {"available": bool | None, "reason": str | None}. Restores the
        # boot-time-observable posture the N-151 SOFT gate variant traded
        # away (a boot-time hard raise → boot-time WARN + first-save fail-
        # closed).
        "msal_master_key_status",
    }
    assert body["status"] == "ok"
    # the backlog  — msal_master_key_status shape assertion (SME-panel
    # fold at HEAD c1973b3c: hipaa-sme MUST-FIX #1 fixed-enum reason;
    # DA #2 error_type class-name; DA #3 last_probed_at seam). The test
    # DB has a provisioned master key via the `master_key` autouse fixture
    # (see conftest), so ``available`` must be True + reason "available".
    msal = body["msal_master_key_status"]
    assert set(msal.keys()) == {
        "available", "reason", "error_type", "last_probed_at",
    }
    assert msal["available"] is True, (
        f"msal_master_key_status: expected available=True in the "
        f"test-fixture-provisioned scope; got {msal!r}"
    )
    assert msal["reason"] == "available"
    assert msal["error_type"] is None
    assert isinstance(msal["last_probed_at"], str) and (
        msal["last_probed_at"].endswith("Z")
    ), f"last_probed_at must be UTC-ISO with Z suffix; got {msal!r}"


def test_health_detail_msal_master_key_status_unavailable_path(
    client, monkeypatch, admin_user,
):
    """the backlog  REDESIGNED v3 Part 1 (FLIPPED from prior spec):
    cover the SOFT `unavailable` path end-to-end. Monkeypatch
    `_get_master_key` to raise the expected N-151 SOFT-path class
    (`FileNotFoundError`) and assert:

      1. `available` becomes False (True → False transition on the probe).
      2. `reason` is the fixed enum `"unavailable"` (NOT the raw exception
         text — hipaa-sme MUST-FIX #1 fixed-enum posture).
      3. `error_type` is None on the shim — the accessor SSOT (Part 0)
         does not expose the class name; the reason enum carries the
         partition signal (the monitoring system reads `reason`, not `error_type`).
      4. `/health/detail` now returns 503 + top-line `degraded` — v3 Part 1
         flip: the SOFT `unavailable` path FEEDS the top-line degrade
         OR-term so the monitoring system pages the operator, restoring the compensating
         control the SOFT variant traded away.
    """
    from email_triage.providers import _msal_cache_crypto

    def _raise_unavail():
        raise FileNotFoundError("simulated N-151 SOFT unavailable path")

    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", _raise_unavail,
    )
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    # v3 Part 1: SOFT `unavailable` NOW degrades /health/detail (503).
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["status"] == "degraded", (
        "the backlog  REDESIGNED v3 Part 1 spec: the SOFT "
        "`unavailable` path FEEDS the top-line `degraded` term so the monitoring system "
        "polling /health pages the operator. `probe_error`/`import_error` "
        "(available is None) do NOT degrade — unknown ≠ WARN. "
        f"body={body!r}"
    )
    msal = body["msal_master_key_status"]
    assert msal["available"] is False, msal
    assert msal["reason"] == "unavailable", msal
    # v3 Part 1 shim: accessor SSOT does not expose class name — `reason`
    # is the partition signal, `error_type` is None on the shim's inner
    # paths (import_error outer path still carries the class name).
    assert msal["error_type"] is None, msal
    assert isinstance(msal["last_probed_at"], str)
    sd = body["style_distill"]
    for k in ("local_24h", "cloud_24h", "failures_24h",
              "scrubber_rejects_24h", "total_24h"):
        assert k in sd, f"style_distill missing key {k!r}"
        assert isinstance(sd[k], int)
    tc = body["tls_cert"]
    assert set(("present", "not_after", "days_remaining")) <= set(tc)
    assert isinstance(tc["present"], bool)


def test_health_aggregate_degrades_on_msal_master_key_unavailable(
    client, monkeypatch, db,
):
    """the backlog  REDESIGNED v3 Part 1 PIN — the top-line degrade
    OR-term fires when the N-151 SOFT gate is ACTIVE on the SOFT
    `unavailable` path. Monkeypatches ``_get_master_key`` to raise the
    canonical SOFT-path class (in `_N151_UNAVAIL_TYPES`) so the
    Part-0 accessor reports ``active=True`` + ``reason="unavailable"`` →
    shim returns ``available=False`` → /health returns 503 + status
    ``"degraded"``. the monitoring system polling /health pages the operator; this
    restores the compensating control the SOFT gate variant traded
    away (a boot-time hard raise → boot-time WARN + first-save
    fail-closed) per the redesign's stated intent.
    """
    from email_triage.providers import _msal_cache_crypto

    def _raise_unavail():
        raise FileNotFoundError("v3 Part 1 pin — SOFT unavailable path")

    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", _raise_unavail,
    )
    resp = client.get("/health")
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["status"] == "degraded", body
    # Minimal shape preserved even in the degraded response.
    assert set(body.keys()) == {"status", "uptime_secs", "db"}, body


def test_health_aggregate_does_not_degrade_on_probe_error(
    client, monkeypatch, db,
):
    """the backlog  REDESIGNED v3 Part 1 STRICT semantics pin — a
    `probe_error` outcome (unexpected exception class, e.g. ``ValueError``
    not in the SOFT ``_N151_UNAVAIL_TYPES`` set) leaves ``available=None``
    (UNKNOWN) → top-line does NOT degrade. `unknown ≠ WARN` (the monitoring system
    tri-state posture) — the operator gets `probe_error` visibility on
    /health/detail without a top-line page.
    """
    from email_triage.providers import _msal_cache_crypto

    def _raise_probe_error():
        # A class NOT in `_N151_UNAVAIL_TYPES` — falls to `probe_error`.
        raise ValueError("v3 Part 1 pin — probe_error path")

    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", _raise_probe_error,
    )
    resp = client.get("/health")
    # Strict `is False` OR-term: available=None (probe_error) does NOT
    # flip the top-line.  200 preserved.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok", body


def test_health_minimal_body_no_msal_key_leak_pin(
    client, monkeypatch, db,
):
    """the backlog  REDESIGNED v3 Part 1 LEAK PIN — the minimal /health
    body carries NO ``msal_master_key*`` key on any of the three
    paths (available / unavailable / probe_error).  The MSAL block is
    admin-only via /health/detail; /health only surfaces the top-line
    ``status`` + ``uptime_secs`` + ``db``.
    Guards against a future refactor that copies the block down into the
    minimal shape and leaks the reason enum + last_probed_at to any
    unauthenticated caller.
    """
    from email_triage.providers import _msal_cache_crypto

    # Path 1 — healthy (real fixture master key).
    resp = client.get("/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for k in body.keys():
        assert "msal_master_key" not in k, (
            f"minimal /health body leaked msal_master_key key {k!r} on "
            f"the healthy path; body={body!r}"
        )

    # Path 2 — SOFT unavailable → 503 body; still no leak.
    monkeypatch.setattr(
        _msal_cache_crypto,
        "_get_master_key",
        lambda: (_ for _ in ()).throw(FileNotFoundError("leak-pin unavail")),
    )
    resp = client.get("/health")
    assert resp.status_code == 503, resp.text
    body = resp.json()
    for k in body.keys():
        assert "msal_master_key" not in k, (
            f"minimal /health body leaked msal_master_key key {k!r} on "
            f"the SOFT unavailable path; body={body!r}"
        )
    # Positive shape assertion — minimal contract preserved even on 503.
    assert set(body.keys()) == {"status", "uptime_secs", "db"}, body

    # Path 3 — probe_error (unexpected class) → 200 body; still no leak.
    monkeypatch.setattr(
        _msal_cache_crypto,
        "_get_master_key",
        lambda: (_ for _ in ()).throw(ValueError("leak-pin probe_error")),
    )
    resp = client.get("/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for k in body.keys():
        assert "msal_master_key" not in k, (
            f"minimal /health body leaked msal_master_key key {k!r} on "
            f"the probe_error path; body={body!r}"
        )


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
    monkeypatch.setenv("TZ", "America/New_York")
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
    # New York is UTC-4 (EDT) or UTC-5 (EST). Must NOT be +00:00.
    offset_hrs = dt.utcoffset().total_seconds() / 3600
    assert offset_hrs in (-4, -5), (
        f"Expected New York offset -4/-5, got {offset_hrs} from {returned}"
    )
    # Value-equality: parsed returned-dt equals parsed UTC-stored-dt.
    assert dt == datetime.fromisoformat(utc_ts)


# ---------------------------------------------------------------------------
#  — disabled accounts excluded from account_states
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
    configured legacy account (item  health-aggregation fix)."""
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


def test_watching_off_account_is_neither_alert_nor_uncovered(
    client, db, app, admin_user,
):
    """ follow-up (operator 2026-06-12): an ACTIVE account whose operator
    turned BOTH push and poll OFF on purpose is "watching off" — a neutral
    state, NOT ``alert='no_ingestion'`` and NOT ``uncovered``. Disabling a
    watcher must never degrade /health."""
    from email_triage.web.routers.health import _aggregate_account_states

    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, 'paused-acct', 'imap', "
        "'{\"push_enabled\": false, \"poll_enabled\": false}', 1, ?, ?)",
        (admin_user["id"], now_iso, now_iso),
    )
    db.commit()

    states = app.state.watcher_manager.account_states(db)
    s = next(x for x in states if x["account_name"] == "paused-acct")
    assert s["mode"] == "none"
    assert s["watching_off"] is True
    assert s["alert"] is None                       # NOT an error

    agg = _aggregate_account_states(states)
    assert agg["any_alert"] is False
    assert agg["any_uncovered"] is False
    assert agg["providers"]["imap"]["watching_off"] == 1
    assert agg["providers"]["imap"]["uncovered"] == 0

    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"            # deliberate pause ≠ degraded


def test_push_off_but_poll_enabled_not_running_still_alerts(
    client, db, app, admin_user,
):
    """Inverse guard: push OFF while poll stays ENABLED (default) but isn't
    actually running is NOT a deliberate pause — ingestion was EXPECTED, so it
    MUST still surface as ``no_ingestion``. Only BOTH-off is "watching off"."""
    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, is_active, created_at, updated_at) "
        "VALUES (?, 'push-off-poll-on', 'imap', "
        "'{\"push_enabled\": false, \"poll_enabled\": true}', 1, ?, ?)",
        (admin_user["id"], now_iso, now_iso),
    )
    db.commit()

    states = app.state.watcher_manager.account_states(db)
    s = next(x for x in states if x["account_name"] == "push-off-poll-on")
    assert s["watching_off"] is False
    assert s["alert"] == "no_ingestion"


# ---------------------------------------------------------------------------
#  partial follow-up — version_status on /health/detail (the monitoring system surface)
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
    # ``status`` -> ``state`` rename for the monitoring system consistency.
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
    ``incompatible_rollback`` -- the @skip=tests/* deploy-recovery case."""
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
    lets the monitoring system alarm without a crash loop."""
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
