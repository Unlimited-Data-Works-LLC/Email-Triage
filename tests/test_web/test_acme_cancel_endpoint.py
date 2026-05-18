"""Tests for ``POST /admin/acme-status/cancel`` (#103).

The cancel endpoint flips the ``cancel_requested`` flag on the
in-flight ACME job; the worker thread reads the flag at retry-loop
boundaries and transitions to the ``cancelled`` terminal phase.

Coverage:
* admin gate -- non-admin gets 403.
* anonymous gets 303 to /login.
* happy path flips the flag in the DB row + returns ok=True
  with cancelled=True.
* idempotent: cancelling an already-terminal row returns ok=True
  with cancelled=False (no-op).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def reset_acme_state(db):
    """Bind the acme_job_state singleton to the test DB and reset
    between tests."""
    from email_triage.web import acme_job_state
    acme_job_state.set_db_handle(db)
    acme_job_state.reset()
    yield
    acme_job_state.reset()
    acme_job_state.set_db_handle(None)


def test_cancel_requires_login(client):
    resp = client.post(
        "/admin/acme-status/cancel", follow_redirects=False,
    )
    # Anonymous -> 303 to /login (matches _require_admin's first
    # branch).
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


def test_cancel_rejects_non_admin(client, user_cookies):
    resp = client.post(
        "/admin/acme-status/cancel",
        cookies=user_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_cancel_flips_flag_on_in_flight_job(client, db, admin_cookies):
    from email_triage.web import acme_job_state
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition("polling_local", attempt=1)

    resp = client.post(
        "/admin/acme-status/cancel",
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["cancelled"] is True
    assert body["job_id"] == job_id

    row = db.execute(
        "SELECT cancel_requested FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["cancel_requested"] == 1


def test_cancel_on_terminal_job_is_idempotent(client, db, admin_cookies):
    from email_triage.web import acme_job_state
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("publishing", attempt=1)
    acme_job_state.finish_success({"subject_cn": "x.test"})

    resp = client.post(
        "/admin/acme-status/cancel",
        cookies=admin_cookies,
        data={"job_id": job_id},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    # Already terminal -> cancellation is a no-op.
    assert body["cancelled"] is False


def test_cancel_with_no_active_job_returns_ok(client, admin_cookies):
    """No active job, no body field -- endpoint returns ok=True
    with cancelled=False rather than 4xx. Operator clicking the
    button on a stale tab is a benign event, not an error."""
    resp = client.post(
        "/admin/acme-status/cancel",
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["cancelled"] is False
