""" Part 4 pin — N-151 SOFT-gate row on the admin Dashboard Health block.

Contract:
* When ``n151_soft_gate_state()`` returns ``(True, reason)``, the admin
  Dashboard renders a prominent single-line warning row at the TOP of the
  Health card with the row-marker text ``"Credential store SOFT-gate
  active"`` and echoes the reason enum.
* When ``n151_soft_gate_state()`` returns ``(False, "available")``, the row
  is completely ABSENT — no empty box, no marker text.
* The gate is admin-only (regular users never see the Health card at all,
  so the row never appears for them regardless of gate state).
* Post-DB-SME-F1 fold: callers use the atomic single-probe SSOT
  ``n151_soft_gate_state()`` — dual-call monkeypatches on the deprecated
  accessors no longer influence the render path.

Mirrors the substring-match idiom from
``tests/test_web/test_dashboard_redesign.py::test_dashboard_admin_sees_health_chips_plus_checklist``
(TestClient GET /dashboard + ``assert "<label>" in resp.text``); no
BeautifulSoup / DOM walk.

Portable text pin — the row copy MUST NOT mention the monitoring system, ops-tokens, or
admin-only-ops paths (feedback_no_admin_path_in_user_copy).
"""
from __future__ import annotations


_ROW_MARKER = "Credential store SOFT-gate active"


def test_dashboard_admin_sees_n151_soft_gate_row_when_active(
    client, db, admin_user, admin_cookies, monkeypatch,
):
    """SOFT-gate ACTIVE → the warning row is rendered with the reason enum."""
    import email_triage.web.routers.ui._shared as _shared

    # Force the accessor result — the ctx builder imports the single SSOT
    # ``n151_soft_gate_state`` inline inside the try/except (DB-SME F1
    # torn-read fold).  Patch on the source module so BOTH import shapes
    # (``from X import Y`` and ``X.Y``) see the override.
    import email_triage.providers._msal_cache_crypto as _crypto
    monkeypatch.setattr(
        _crypto, "n151_soft_gate_state",
        lambda: (True, "unavailable"), raising=True,
    )
    # Belt-and-suspenders: if _shared re-exported the name by-value (it does
    # not today, but a future refactor might), patch there too.
    if hasattr(_shared, "n151_soft_gate_state"):
        monkeypatch.setattr(_shared, "n151_soft_gate_state",
                            _crypto.n151_soft_gate_state, raising=True)

    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    # Row marker present.
    assert _ROW_MARKER in resp.text, (
        "N-151 SOFT-gate active row missing from admin Dashboard Health block."
    )
    # Reason enum echoed inline.
    assert "unavailable" in resp.text
    # Portability: the user-facing row must not leak ops-only vocabulary.
    _low = resp.text.lower()
    assert "the monitoring system" not in _low, "Row copy leaks the monitoring system into user surface."
    assert "ops-token" not in _low
    assert "ops_token" not in _low


def test_dashboard_admin_no_n151_row_when_gate_inactive(
    client, db, admin_user, admin_cookies, monkeypatch,
):
    """SOFT-gate INACTIVE → the row is completely absent (no empty box)."""
    import email_triage.providers._msal_cache_crypto as _crypto

    monkeypatch.setattr(
        _crypto, "n151_soft_gate_state",
        lambda: (False, "available"), raising=True,
    )

    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    # Confirm we're on the admin Dashboard Health block (not a redirected
    # error page) — the Gateway chip is always rendered for admins.
    assert "Gateway" in resp.text
    # Row must not render.
    assert _ROW_MARKER not in resp.text, (
        "N-151 SOFT-gate INACTIVE row must not render (don't cry wolf)."
    )


def test_dashboard_admin_n151_accessor_failure_is_fail_open_ux(
    client, db, admin_user, admin_cookies, monkeypatch,
):
    """A raising accessor must NOT 500 the dashboard (fail-open UX).

    Prime Directive #8 says security controls fail CLOSED — this is a
    non-decisional render degradation (the row simply doesn't appear if
    the probe blows up), which is explicitly the allowed fail-OPEN case
    (project_style_guide rule #8, non-decisional render degradation).
    """
    import email_triage.providers._msal_cache_crypto as _crypto

    def _boom() -> tuple[bool, str]:  # noqa: D401
        raise RuntimeError("simulated crypto-module probe failure")

    monkeypatch.setattr(_crypto, "n151_soft_gate_state", _boom, raising=True)

    resp = client.get("/dashboard", cookies=admin_cookies)
    # No 500 — dashboard still renders.
    assert resp.status_code == 200
    # Row must not appear when the probe crashes (fail-open on the UX).
    assert _ROW_MARKER not in resp.text
