"""Tests for PR 5 / C1 — watcher supervisor + /health rollup.

Covers:
* ``WatcherManager._mark_failing`` / ``_mark_recovered`` lifecycle.
* ``WatcherManager.watchers_failing_for`` time-threshold filter.
* /health surfaces ``tasks`` block from app.state.supervisor.
* /health surfaces ``watchers_failing`` and flips degraded when
  any watcher is past 15 min in failing state.
* /health returns HTTP 503 on degraded.
* /health surfaces ``audit_failures`` + ``schema_version``.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token


# Test fixture seeds session_secret = TEST_SECRET; minted-here cookie
# matches what conftest's admin_cookies fixture would mint, so we can
# attach without needing the fixture in every test signature.
def _admin_cookie_pair():
    return (
        SESSION_COOKIE_NAME,
        create_session_token(
            "test-session-secret-for-signing", "admin@test.com", "admin",
        ),
    )


# ---------------------------------------------------------------------------
# WatcherManager registry behaviour (no Starlette client needed)
# ---------------------------------------------------------------------------

def test_mark_failing_sets_timestamp(app, db):
    mgr = app.state.watcher_manager
    mgr._mark_failing(123, "INBOX", error="connection refused")
    st = mgr._get_mb_state(123, "INBOX")
    assert st["failing_since"] is not None
    assert st["last_error"] == "connection refused"
    assert st["errors"] >= 1


def test_mark_failing_idempotent_does_not_reset_clock(app, db):
    mgr = app.state.watcher_manager
    mgr._mark_failing(124, "INBOX", error="first")
    first_ts = mgr._get_mb_state(124, "INBOX")["failing_since"]
    time.sleep(0.05)
    mgr._mark_failing(124, "INBOX", error="second")
    second_ts = mgr._get_mb_state(124, "INBOX")["failing_since"]
    assert first_ts == second_ts  # original clock preserved
    assert mgr._get_mb_state(124, "INBOX")["last_error"] == "second"
    assert mgr._get_mb_state(124, "INBOX")["errors"] >= 2


def test_mark_recovered_clears_failing_since(app, db):
    mgr = app.state.watcher_manager
    mgr._mark_failing(125, "INBOX", error="boom")
    assert mgr._get_mb_state(125, "INBOX")["failing_since"] is not None
    mgr._mark_recovered(125, "INBOX")
    assert mgr._get_mb_state(125, "INBOX")["failing_since"] is None


def test_watchers_failing_for_threshold(app, db):
    mgr = app.state.watcher_manager
    # Three watchers: one failing for 1s (under threshold), one
    # failing for 2 hours (over threshold), one healthy.
    now = time.time()
    mgr._mb_state[(200, "INBOX")] = {
        **mgr._get_mb_state(200, "INBOX"),
        "failing_since": now - 1,
        "last_error": "transient",
    }
    mgr._mb_state[(201, "INBOX")] = {
        **mgr._get_mb_state(201, "INBOX"),
        "failing_since": now - 7200,  # 2h
        "last_error": "deep",
    }
    # 202 has no failing_since — healthy.
    mgr._get_mb_state(202, "INBOX")
    out = mgr.watchers_failing_for(900)  # 15 min
    aids = {row["account_id"] for row in out}
    assert 201 in aids
    assert 200 not in aids
    assert 202 not in aids
    # Returned dict has the documented shape.
    row_201 = next(r for r in out if r["account_id"] == 201)
    assert row_201["mailbox"] == "INBOX"
    assert row_201["failing_secs"] >= 7200
    assert row_201["last_error"] == "deep"


# ---------------------------------------------------------------------------
# /health rollup
# ---------------------------------------------------------------------------

def test_health_includes_new_blocks(client, db, admin_user):
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    body = resp.json()
    assert "tasks" in body
    assert "watchers_failing" in body
    assert "audit_failures" in body
    assert "schema_version" in body
    # Empty install: tasks is the supervisor snapshot (likely empty
    # in test fixture); watchers_failing is empty; counters at zero.
    assert body["watchers_failing"] == []
    assert body["audit_failures"] == 0
    # schema_version is an int (>=0) when migrations ran.
    assert body["schema_version"] is None or body["schema_version"] >= 0


def test_health_503_when_watcher_failing_long(client, db, app, admin_user):
    """A watcher failing past the 15-min threshold flips /health to 503."""
    mgr = app.state.watcher_manager
    # Plant a long-failing watcher.
    now = time.time()
    mgr._mb_state[(999, "INBOX")] = {
        **mgr._get_mb_state(999, "INBOX"),
        "failing_since": now - 7200,  # 2h
        "last_error": "stuck",
        "status": "reconnecting",
    }
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["watchers_failing"]
    assert any(
        r["account_id"] == 999 for r in body["watchers_failing"]
    )


def test_health_ok_when_watcher_failing_briefly(client, db, app, admin_user):
    """A watcher failing for less than the threshold does NOT flip 503."""
    mgr = app.state.watcher_manager
    now = time.time()
    mgr._mb_state[(998, "INBOX")] = {
        **mgr._get_mb_state(998, "INBOX"),
        "failing_since": now - 5,  # 5s
        "last_error": "transient",
        "status": "reconnecting",
    }
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    body = resp.json()
    # Empty install has any_uncovered → degraded already; the focus
    # of this test is that watchers_failing for THIS account is
    # empty under the threshold even if overall status is degraded
    # for unrelated reasons.
    fails = [
        r for r in body["watchers_failing"] if r["account_id"] == 998
    ]
    assert fails == []


def test_health_503_on_quarantined_task(client, db, app, admin_user):
    """If the supervisor reports any quarantined task, /health flips 503."""
    from email_triage.web.task_supervisor import TaskSupervisor, TaskState
    sup = TaskSupervisor()
    app.state.supervisor = sup
    # Inject a quarantined task state directly. _states is the
    # registry the snapshot reads from.
    sup._states["fake-task"] = TaskState(
        name="fake-task",
        status="quarantined",
        crashes=5,
        last_crash_error_type="ValueError",
        quarantined_reason="5 crashes in 600s",
    )
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    assert resp.status_code == 503
    body = resp.json()
    assert body["tasks"].get("any_quarantined") is True
    assert body["status"] == "degraded"


def test_health_audit_failures_surface(client, db, app, admin_user):
    """Audit-failure counter on app.state surfaces verbatim."""
    app.state.audit_failures = 7
    client.cookies.set(*_admin_cookie_pair())
    resp = client.get("/health/detail")
    body = resp.json()
    assert body["audit_failures"] == 7
