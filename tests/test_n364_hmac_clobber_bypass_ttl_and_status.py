"""N-364 R31 — HMAC clobber bypass TTL + observability status.

Trust-repair fix-forward per SME panel 2026-07-05 F6 + HIPAA-SME MED
#3 + the backlog N-349b items 4 (show verb + TTL) and 5 (armed_at /
armed_by_actor_id traceability) — TaskList  + .

Closes the "operator arms + forgets" observability gap by (a) stamping
`armed_at` + `expires_at` on the arm row so an audit sweep can see how
old the arm is, (b) treating a past-expiry row as NOT armed on the
is_armed predicate (fail-CLOSED on TTL miss), (c) supplying a read-only
`hmac_clobber_bypass_status` predicate the `secrets show-hmac-clobber-
bypass` CLI verb prints, (d) recording `armed_by_actor_id` on the arm
so §164.308(a)(4)(ii)(C) traceability ties CONSUMPTION back to
ESTABLISHMENT.
"""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone

from email_triage.web.db import (
    HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC,
    HMAC_CLOBBER_BYPASS_KEY,
    arm_hmac_clobber_bypass,
    consume_hmac_clobber_bypass,
    hmac_clobber_bypass_status,
    is_hmac_clobber_bypass_armed,
)


def _fresh_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE settings ("
        "  key        TEXT PRIMARY KEY,"
        "  value_json TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL"
        ")"
    )
    conn.commit()
    return conn


def test_default_ttl_stamped_on_arm():
    """Default arm carries `armed_at` + `expires_at` (default 15 min)."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn)
    status = hmac_clobber_bypass_status(conn)
    assert status["armed"] is True
    assert status["armed_at"] is not None
    assert status["expires_at"] is not None
    # Default TTL is 15 minutes — expires_at MUST be roughly 15 min out.
    expires = datetime.fromisoformat(status["expires_at"].replace("Z", "+00:00"))
    delta = (expires - datetime.now(timezone.utc)).total_seconds()
    assert HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC - 5 <= delta <= HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC + 5


def test_custom_ttl_stamped_on_arm():
    """Passing `ttl_sec` overrides the default."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn, ttl_sec=60)  # 1 minute
    status = hmac_clobber_bypass_status(conn)
    expires = datetime.fromisoformat(status["expires_at"].replace("Z", "+00:00"))
    delta = (expires - datetime.now(timezone.utc)).total_seconds()
    assert 55 <= delta <= 65


def test_zero_ttl_is_no_expiry():
    """Passing `ttl_sec=0` arms without an expiry — explicit break-glass."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn, ttl_sec=0)
    status = hmac_clobber_bypass_status(conn)
    assert status["armed"] is True
    assert status["expires_at"] is None


def test_expired_row_reports_not_armed():
    """A row with `expires_at` in the past reads as NOT armed (fail-
    CLOSED on TTL miss)."""
    conn = _fresh_conn()
    # Bust any cached-value from a prior test — the settings cache is
    # module-level and can carry stale entries across tests.
    from email_triage.web import db as _db
    with _db._settings_cache_lock:
        _db._settings_cache.pop(HMAC_CLOBBER_BYPASS_KEY, None)
    # Route the write through the SSOT (set_setting invalidates the
    # cache), so subsequent `get_setting` reads the fresh row rather
    # than any stale cached entry.
    from email_triage.web.db import set_setting
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    armed_at = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
    set_setting(
        conn,
        HMAC_CLOBBER_BYPASS_KEY,
        {"armed": True, "armed_at": armed_at, "expires_at": past},
    )

    assert is_hmac_clobber_bypass_armed(conn) is False
    status = hmac_clobber_bypass_status(conn)
    assert status["armed"] is False
    assert status["expired"] is True


def test_armed_by_actor_id_captured_when_supplied():
    """Passing `actor_id` on arm stamps it on the row for §164.308(a)(
    4)(ii)(C) traceability."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn, actor_id=42)
    # Fetch the raw row to inspect the payload.
    row = conn.execute(
        "SELECT value_json FROM settings WHERE key = ?",
        (HMAC_CLOBBER_BYPASS_KEY,),
    ).fetchone()
    import json
    payload = json.loads(row["value_json"])
    assert payload["armed_by_actor_id"] == 42
    assert payload["armed"] is True


def test_show_status_when_not_armed():
    conn = _fresh_conn()
    status = hmac_clobber_bypass_status(conn)
    assert status == {"armed": False, "expires_at": None, "armed_at": None, "expired": False}


def test_consume_still_returns_true_on_expired_row():
    """Even after expiry, `consume` removes the row (housekeeping)."""
    conn = _fresh_conn()
    from email_triage.web import db as _db
    with _db._settings_cache_lock:
        _db._settings_cache.pop(HMAC_CLOBBER_BYPASS_KEY, None)
    from email_triage.web.db import set_setting
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    set_setting(
        conn,
        HMAC_CLOBBER_BYPASS_KEY,
        {"armed": True, "armed_at": past, "expires_at": past},
    )

    consumed = consume_hmac_clobber_bypass(conn)
    assert consumed is True
    status = hmac_clobber_bypass_status(conn)
    assert status["armed"] is False
    assert status["armed_at"] is None
