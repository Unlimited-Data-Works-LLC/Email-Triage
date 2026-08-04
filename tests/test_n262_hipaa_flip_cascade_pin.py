"""N-262 R26 structural pin — HIPAA 0→1 cascade SSOT (2026-07-03).

Census R26 discovered MED (HIPAA 0→1 cascade): 5+ derived-state
fields were NOT cascaded on a HIPAA flag flip 0→1 — auto_scan_enabled,
style_alias_mode_enabled, calendar_surrogate_account_id, calendar api
role, style_knobs_hipaa_allow, style_profile. §164.502(a) posture
drift: a HIPAA account rendered enabled RAG/AI/alias toggles until
the next daily sweep or manual re-save.

Operator answered the 6-field decisions 2026-07-03:
  - auto_scan_enabled          → force-OFF + banner (fail-closed)
  - style_alias_mode_enabled   → leave-as-is
  - calendar_surrogate_id      → leave-as-is (resolver gate covers)
  - calendar api role          → force-downgrade + audit event (deferred)
  - style_knobs_hipaa_allow    → leave-as-is (operator opt-in)
  - style_profile              → leave-as-is (read-time scrub)

N-262 landed the `_hipaa_flip_on_cascade` helper implementing the
auto_scan_enabled force-OFF + audit event via `hipaa_boundary_events`
on 0→1 transition. Called INSIDE `set_account_hipaa`'s transaction so
a cascade failure rolls back the flag flip too.

WHAT IT PINS:

1. Anti-vacuity: `_hipaa_flip_on_cascade` imports + is callable.
2. `set_account_hipaa` textually calls `_hipaa_flip_on_cascade` on
   the 0→1 branch (a refactor that drops the call re-opens the
   §164.502(a) posture drift).
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_hipaa_flip_cascade_helper_reachable():
    """Anti-vacuity: `_hipaa_flip_on_cascade` imports + is callable."""
    from email_triage.db.accounts import _hipaa_flip_on_cascade
    assert callable(_hipaa_flip_on_cascade)


def test_set_account_hipaa_calls_cascade_on_flip():
    """`set_account_hipaa` must textually call `_hipaa_flip_on_cascade`
    on the 0→1 direction. A refactor that removes the call re-opens the
    §164.502(a) posture drift."""
    path = SRC_ROOT / "db" / "accounts.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "_hipaa_flip_on_cascade(conn" in source, (
        "N-262 R26 REGRESSION: `set_account_hipaa` no longer calls "
        "`_hipaa_flip_on_cascade`. On a HIPAA 0→1 transition, the "
        "derived-state fields (auto_scan_enabled, etc.) will NOT be "
        "cascaded → §164.502(a) posture drift. Operator's answered "
        "per-field decisions are captured in the helper's docstring."
    )


def test_hipaa_flip_cascade_implements_operator_decisions():
    """N-262b + N-262c: the cascade helper must textually reference
    the two operator-decided cascade actions (auto_scan_enabled +
    calendar_api_role). A refactor that drops either action re-opens
    the specific §164.502(a) posture drift the operator answered."""
    path = SRC_ROOT / "db" / "accounts.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "auto_scan_enabled" in source and "set_auto_scan_enabled_for_account" in source, (
        "N-262 REGRESSION: cascade no longer force-offs "
        "`auto_scan_enabled` — operator's fail-closed HIPAA posture "
        "decision was dropped."
    )
    assert "calendar_api_role" in source, (
        "N-262c REGRESSION: cascade no longer references the calendar "
        "`api` role downgrade — operator's fail-closed §164.502(a) "
        "decision was dropped."
    )


def test_hipaa_flip_warning_banner_present():
    """N-262b: the accounts/_edit.html template must carry the
    0→1 warning banner (a confirm() dialog on the HIPAA checkbox
    onchange when NOT currently HIPAA)."""
    path = SRC_ROOT / "web" / "templates" / "accounts" / "_edit.html"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "Turning HIPAA ON will also force-disable Auto-scan" in source, (
        "N-262b REGRESSION: the HIPAA-flip warning banner is missing "
        "from accounts/_edit.html. Operator's decision was to surface "
        "the auto_scan force-off consequence BEFORE the operator saves."
    )
