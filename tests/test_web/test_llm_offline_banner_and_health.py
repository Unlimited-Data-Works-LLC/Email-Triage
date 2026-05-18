"""Banner + /health adjacent tests for #149.

Covers:
  - dashboard banner renders calm copy when an LLM maintenance
    window is active.
  - dashboard banner renders alert copy when the LLM is unreachable
    outside any window.
  - /health does NOT count an LLM-unreachable failure toward
    ``audit_failures`` and the LLM-unhealthy state does NOT push
    accounts into ``ingestion.any_alert``.
"""

from __future__ import annotations

from email_triage import llm_health
from email_triage.config import LLMMaintenanceWindow


# ---------------------------------------------------------------------------
# Banner rendering
# ---------------------------------------------------------------------------

def test_dashboard_banner_alert_copy_when_unhealthy(client, admin_cookies, app):
    """When the LLM is unhealthy outside a window, the dashboard
    shows the alert banner copy."""
    llm_health._reset_for_test()
    llm_health.set_unhealthy("ollama", ttl_seconds=300, reason="connection refused")
    app.state.config.llm_maintenance_windows = []
    try:
        resp = client.get("/dashboard", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Alert copy + retry-in-N-minutes phrasing.
        assert "Ollama unreachable" in body
        assert "Retrying in about" in body
    finally:
        llm_health._reset_for_test()


def test_dashboard_banner_calm_copy_inside_maintenance_window(
    client, admin_cookies, app, monkeypatch,
):
    """When unhealthy AND inside a configured maintenance window,
    the banner uses the calm 'scheduled maintenance' copy."""
    llm_health._reset_for_test()
    llm_health.set_unhealthy("ollama", ttl_seconds=300, reason="x")
    # Window that matches every minute → guaranteed active for the
    # in-test ``now``.
    app.state.config.llm_maintenance_windows = [
        LLMMaintenanceWindow(
            host="llm-host", cron="* * * * *",
            duration_minutes=30, backend="ollama",
        ),
    ]
    try:
        resp = client.get("/dashboard", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Calm copy markers.
        assert "scheduled maintenance" in body
        assert "Back at" in body
    finally:
        llm_health._reset_for_test()
        app.state.config.llm_maintenance_windows = []


def test_dashboard_no_llm_banner_when_healthy(client, admin_cookies, app):
    """No banner when the LLM is healthy."""
    llm_health._reset_for_test()
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "Ollama unreachable" not in body
    assert "scheduled maintenance" not in body


# ---------------------------------------------------------------------------
# /health regression: LLM-unreachable does NOT push degraded
# ---------------------------------------------------------------------------

def test_health_endpoint_unaffected_by_llm_unhealthy(
    client, admin_cookies, app,
):
    """LLM-unreachable is upstream-infra weather, not a /health
    degradation. ``audit_failures`` and ``ingestion.any_alert``
    must NOT change when the breaker is open."""
    llm_health._reset_for_test()

    # Baseline read.
    base = client.get("/health", cookies=admin_cookies).json()
    base_audit_fail = int(base.get("audit_failures") or 0)
    base_any_alert = bool(base.get("ingestion", {}).get("any_alert") or False)

    # Trip the LLM breaker.
    llm_health.set_unhealthy("ollama", ttl_seconds=300, reason="connection refused")
    try:
        after = client.get("/health", cookies=admin_cookies).json()
        # audit_failures unchanged.
        assert int(after.get("audit_failures") or 0) == base_audit_fail
        # ingestion.any_alert unchanged.
        assert (
            bool(after.get("ingestion", {}).get("any_alert") or False)
            == base_any_alert
        )
    finally:
        llm_health._reset_for_test()
