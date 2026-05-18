"""Tests for the listener-mode restart-pending chip (#81).

The uvicorn listener binds either http or https at process start; it
cannot swap mid-process. When an operator flips ``tls.enabled`` and
hits Save, the YAML + in-memory config update but the live socket
keeps serving the old protocol. The chip on /admin/acme-status warns
about this; the daily-health email picks up the same signal in
``attention_reasons``.

The detection is a frozen-vs-live comparison:

* ``app.state.tls_boot_mode`` -- captured ONCE at lifespan boot,
  never re-read.
* ``app.state.config.tls.enabled`` -- the live, possibly-updated
  saved value.

A divergence => chip on. Process restart re-runs lifespan, which
re-reads tls.enabled, which makes boot_mode match the saved value
again -> chip clears automatically.

Coverage:
* Helper returns False on a fresh boot (no drift).
* Helper returns True when boot_mode disagrees with saved.
* Helper returns False after a "restart" (boot_mode reset to match).
* Chip appears on /admin/acme-status when drift is detected.
* Chip is absent when no drift.
* Chip names both modes (saved vs running) so operator knows which
  way it flipped.
* Daily-health attention_reasons gets a "Listener restart pending"
  entry when drift is detected.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------

def test_helper_returns_false_on_fresh_boot(app, db):
    """tls_boot_mode == saved value (both False by default in test
    config). No drift -> no chip."""
    from email_triage.web.app import is_listener_restart_pending
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = False
    assert is_listener_restart_pending(app) is False


def test_helper_returns_true_when_saved_diverges_from_boot(app, db):
    """Boot bound HTTP, operator flipped to HTTPS + saved -> drift."""
    from email_triage.web.app import is_listener_restart_pending
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    assert is_listener_restart_pending(app) is True


def test_helper_returns_true_when_boot_https_saved_http(app, db):
    """Reverse direction: boot bound HTTPS, operator flipped to
    HTTP + saved. Same chip applies -- listener still on HTTPS."""
    from email_triage.web.app import is_listener_restart_pending
    app.state.tls_boot_mode = True
    app.state.config.tls.enabled = False
    assert is_listener_restart_pending(app) is True


def test_helper_clears_after_simulated_restart(app, db):
    """Restart re-runs lifespan, re-reads tls.enabled. Boot_mode
    realigns with the saved value -> chip disappears."""
    from email_triage.web.app import is_listener_restart_pending
    # Drift state.
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    assert is_listener_restart_pending(app) is True
    # Simulate restart: lifespan re-captures boot_mode from
    # current config.
    app.state.tls_boot_mode = bool(app.state.config.tls.enabled)
    assert is_listener_restart_pending(app) is False


def test_helper_safe_when_state_missing(app):
    """Defensive: helper must not raise if app.state is missing
    pieces (test harness shortcut, etc.). Returns False rather
    than a false-positive chip."""
    from email_triage.web.app import is_listener_restart_pending
    # No db / config installed -- fresh app.
    if hasattr(app.state, "tls_boot_mode"):
        delattr(app.state, "tls_boot_mode")
    assert is_listener_restart_pending(app) is False


# ---------------------------------------------------------------------------
# Page-level tests
# ---------------------------------------------------------------------------

def test_chip_renders_on_acme_status_when_drift(client, app, db, admin_cookies):
    """Operator hit Save with a new tls.enabled. boot_mode != saved
    -> chip appears on the page."""
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Listener mode change pending" in resp.text
    # The chip must name BOTH the saved and running modes so the
    # operator can tell which direction the flip went.
    assert "Saved:" in resp.text
    assert "Currently running:" in resp.text
    # Restart commands documented for both supervisor styles.
    assert "systemctl restart email-triage" in resp.text
    assert "podman restart email-triage" in resp.text


def test_chip_absent_when_boot_matches_saved(client, app, db, admin_cookies):
    """No drift -> no chip. The page still renders normally."""
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = False
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Listener mode change pending" not in resp.text


def test_chip_clears_after_restart_realignment(client, app, db, admin_cookies):
    """Drift -> chip on. Then simulate the restart that realigns
    boot_mode with saved -> chip clears on the next render."""
    # Drift state.
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    resp1 = client.get("/admin/acme-status", cookies=admin_cookies)
    assert "Listener mode change pending" in resp1.text
    # Simulate restart.
    app.state.tls_boot_mode = bool(app.state.config.tls.enabled)
    resp2 = client.get("/admin/acme-status", cookies=admin_cookies)
    assert "Listener mode change pending" not in resp2.text


def test_chip_shows_correct_modes_when_flipping_to_https(
    client, app, db, admin_cookies,
):
    """Boot HTTP, saved HTTPS -> chip says Saved=HTTPS, Running=HTTP."""
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    text = resp.text
    # Order is "Saved: <new>" then "Currently running: <old>".
    saved_idx = text.find("Saved:")
    running_idx = text.find("Currently running:")
    assert saved_idx != -1 and running_idx != -1
    saved_chunk = text[saved_idx:saved_idx + 60]
    running_chunk = text[running_idx:running_idx + 80]
    assert "HTTPS" in saved_chunk
    assert "HTTP" in running_chunk and "HTTPS" not in running_chunk


# ---------------------------------------------------------------------------
# Daily-health integration
# ---------------------------------------------------------------------------

def test_daily_health_attention_reason_when_drift(app, db):
    """gather_health_state(app=app) when drift is present must add
    a 'Listener restart pending' line to attention_reasons. This is
    the no-side-effect signal that flips the daily digest's
    'OK' -> 'Attention' subject prefix."""
    from email_triage.web.daily_health import gather_health_state
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = True
    state = gather_health_state(db, app.state.config, app=app)
    assert state.get("listener_restart_pending") is True
    reasons = state.get("attention_reasons", [])
    assert any("Listener mode change pending" in r for r in reasons)


def test_daily_health_no_attention_when_no_drift(app, db):
    """No drift -> no listener-restart entry in attention_reasons.
    The digest stays clean of false alarms."""
    from email_triage.web.daily_health import gather_health_state
    app.state.tls_boot_mode = False
    app.state.config.tls.enabled = False
    state = gather_health_state(db, app.state.config, app=app)
    assert state.get("listener_restart_pending") is False
    reasons = state.get("attention_reasons", [])
    assert not any("Listener mode change pending" in r for r in reasons)


def test_daily_health_skips_check_when_app_omitted(db):
    """Backward compat: gather_health_state(...) without app kwarg
    must not break. Existing tests + the assemble path both call
    this without app; the listener-restart-pending key is set
    False without consulting any state."""
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state
    cfg = TriageConfig()
    state = gather_health_state(db, cfg)
    assert state.get("listener_restart_pending") is False
