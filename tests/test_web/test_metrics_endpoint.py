"""Tests for /api/metrics endpoint (PR 10 / E)."""

from __future__ import annotations

import pytest

from email_triage import metrics as metrics_mod


@pytest.fixture(autouse=True)
def _reset_registry():
    metrics_mod.reset_all()
    yield
    metrics_mod.reset_all()


def test_metrics_endpoint_admin_only(
    client, db, app, admin_user, regular_user,
):
    """Admin sees the full text export; non-admin gets 403."""
    from email_triage.web.auth import (
        SESSION_COOKIE_NAME, create_session_token,
    )
    app.state.session_secret = "test-secret"

    admin_token = create_session_token(
        "test-secret", admin_user["email"], "admin",
    )
    client.cookies.set(SESSION_COOKIE_NAME, admin_token)
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
    # Even an empty registry emits the always-present counters once
    # the admin endpoint has run them via app.state.
    assert "# TYPE" in resp.text

    client.cookies.clear()
    user_token = create_session_token(
        "test-secret", regular_user["email"], "user",
    )
    client.cookies.set(SESSION_COOKIE_NAME, user_token)
    resp2 = client.get("/api/metrics")
    assert resp2.status_code == 403


def test_metrics_endpoint_unauth_rejected(client, db):
    """Unauthenticated callers can't read metrics."""
    client.cookies.clear()
    resp = client.get("/api/metrics")
    assert resp.status_code in (401, 403)


def test_metrics_endpoint_includes_runtime_counters(
    client, db, app, admin_user,
):
    """audit_failures + csrf_rejects from app.state get exported."""
    app.state.audit_failures = 3
    app.state.csrf_rejects = 5

    from email_triage.web.auth import (
        SESSION_COOKIE_NAME, create_session_token,
    )
    app.state.session_secret = "test-secret"
    token = create_session_token(
        "test-secret", admin_user["email"], "admin",
    )
    client.cookies.set(SESSION_COOKIE_NAME, token)

    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    assert "et_audit_failures_total" in resp.text
    assert "et_csrf_rejects_total" in resp.text
    # Counters reflect the live state values.
    assert "et_audit_failures_total 3" in resp.text
    assert "et_csrf_rejects_total 5" in resp.text
