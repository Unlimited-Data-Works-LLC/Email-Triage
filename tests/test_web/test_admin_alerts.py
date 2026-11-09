""" Part 2 pins — reusable admin-alert primitive.

Table-driven over ``EVENT_REGISTRY`` so a future consumer registering
its own event automatically inherits the state-machine invariants.

2026-07-10 fold — the primitive was hardened for the
send-then-stamp bug, a reason-change edge, an SMTP-off-the-DB-thread
split, and a fixed-enum HIPAA-leak fix.  Every pin below asserts one
invariant; the whole file exercises the new async
``fire_on_transition`` / ``fire_all`` signatures.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from email_triage.web import admin_alerts
from email_triage.web.admin_alerts import (
    EVENT_REGISTRY,
    AdminAlertEvent,
    N151_SOFT_GATE_EVENT,
    _settings_key,
    fire_all,
    fire_on_transition,
    register_event,
)
from email_triage.web.db import get_setting, set_setting


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

class _StubConfig:
    """Minimal ``config`` shape the primitive touches.

    We only exercise the state-machine paths — the SMTP send is patched
    out at ``_send_admin_alert`` boundary so the tests never care about
    ``smtp`` / ``admin_email`` completeness.
    """


def _reset_state(db, event_key: str) -> None:
    """Drop any persisted admin_alert row for ``event_key``."""
    from email_triage.web.db import delete_setting

    try:
        delete_setting(db, _settings_key(event_key))
    except Exception:
        pass


def _mk_event(
    *,
    key: str,
    active: bool = True,
    cooldown_hours: int = 24,
    reason: str = "test",
) -> AdminAlertEvent:
    """Build a test-only event pinned to a fixed active/inactive probe."""
    ctx = {"reason": reason, "since": None}
    return AdminAlertEvent(
        key=key,
        subject="[test] " + key,
        template_fn=lambda c: ("<p>t</p>", "t"),
        probe_fn=lambda: (active, dict(ctx)),
        cooldown_hours=cooldown_hours,
    )


# ---------------------------------------------------------------------------
# 1) OK -> degraded EDGE fires exactly once (table-driven over registry)
# ---------------------------------------------------------------------------

async def test_admin_alert_fires_once_per_ok_to_degraded_edge(db):
    """PIN: an event flipping OK→degraded fires exactly ONE email.

    Table-driven over ``EVENT_REGISTRY`` — every registered event MUST
    obey the edge-fire discipline (no double-emission on repeat probes
    while the gate stays degraded).

    ``_send_admin_alert`` returns True (successful send) so the
    post-stamp writes ``last_sent_at`` and the second tick's cooldown
    floor is in force.
    """
    assert EVENT_REGISTRY, (
        "Registry must be non-empty (N-151 registers at import)"
    )

    for evt in list(EVENT_REGISTRY.values()):
        _reset_state(db, evt.key)

        with patch.object(
            admin_alerts, "_send_admin_alert", return_value=True,
        ) as send:
            # Force the probe active regardless of the real system.
            with patch.object(
                evt, "probe_fn", lambda: (True, {"reason": "x"}),
            ):
                # First fire: OK -> degraded -> SENT.
                out1 = await fire_on_transition(evt, _StubConfig(), db)
                # Second fire, same active state + reason: SUPPRESSED.
                out2 = await fire_on_transition(evt, _StubConfig(), db)

        assert out1 == "sent", (
            f"event {evt.key!r} did not fire on OK->degraded edge"
        )
        assert out2 == "suppressed", (
            f"event {evt.key!r} re-fired while cooldown was still in force"
        )
        assert send.call_count == 1, (
            f"event {evt.key!r} sent {send.call_count} emails on repeat probe"
        )
        _reset_state(db, evt.key)


# ---------------------------------------------------------------------------
# 2) Settings KV shape — one canonical key layout
# ---------------------------------------------------------------------------

async def test_admin_alert_settings_kv_shape_pin(db):
    """PIN: settings row is stored at ``admin_alert:<key>`` and has the
    ``{last_state, since, last_sent_at, reason}`` shape — this is what
    future events and any migration tooling depend on.

    2026-07-10 fold: ``reason`` is now part of the row (R3 edge detection).
    """
    evt = _mk_event(key="pin_shape", active=True, reason="unavailable")
    register_event(evt)
    _reset_state(db, evt.key)

    with patch.object(admin_alerts, "_send_admin_alert", return_value=True):
        await fire_on_transition(evt, _StubConfig(), db)

    key = _settings_key(evt.key)
    assert key == "admin_alert:pin_shape"

    row = get_setting(db, key)
    assert isinstance(row, dict), "state row must be a JSON object"
    assert set(row.keys()) == {
        "last_state", "since", "last_sent_at", "reason",
    }, f"unexpected keys: {sorted(row.keys())}"
    assert row["last_state"] in {"OK", "degraded"}
    # ISO timestamp roundtrip on the two datetime fields.
    dt = datetime.fromisoformat(row["since"])
    assert dt.tzinfo is not None
    dt2 = datetime.fromisoformat(row["last_sent_at"])
    assert dt2.tzinfo is not None
    # Reason is the probe's fixed enum value, threaded through unchanged.
    assert row["reason"] == "unavailable"

    # Cleanup so the sibling registry pin isn't polluted.
    EVENT_REGISTRY.pop(evt.key, None)
    _reset_state(db, evt.key)


# ---------------------------------------------------------------------------
# 3) Cooldown floor — 24 h suppression
# ---------------------------------------------------------------------------

async def test_admin_alert_cooldown_floor_pin(db):
    """PIN: while active + degraded + reason unchanged, the primitive
    MUST suppress re-sends inside the cooldown window and MUST re-send
    once the window elapses."""
    evt = _mk_event(key="pin_cooldown", active=True, cooldown_hours=24)
    register_event(evt)
    _reset_state(db, evt.key)

    t0 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=True,
    ) as send:
        out_edge = await fire_on_transition(
            evt, _StubConfig(), db, now=t0,
        )
        # 1 hour later — well inside the 24h floor.
        out_within = await fire_on_transition(
            evt, _StubConfig(), db, now=t0 + timedelta(hours=1),
        )
        # 23h 59m — still within.
        out_edge_of_floor = await fire_on_transition(
            evt, _StubConfig(), db,
            now=t0 + timedelta(hours=23, minutes=59),
        )
        # Exactly 24h — floor met, re-send.
        out_after = await fire_on_transition(
            evt, _StubConfig(), db, now=t0 + timedelta(hours=24),
        )

    assert out_edge == "sent"
    assert out_within == "suppressed"
    assert out_edge_of_floor == "suppressed"
    assert out_after == "sent"
    assert send.call_count == 2, (
        f"expected 2 sends (edge + post-cooldown), got {send.call_count}"
    )

    EVENT_REGISTRY.pop(evt.key, None)
    _reset_state(db, evt.key)


# ---------------------------------------------------------------------------
# 4) Silent recovery — degraded -> OK sends NO email
# ---------------------------------------------------------------------------

async def test_admin_alert_silent_recovery_pin(db):
    """PIN: when a degraded gate recovers, we write ``last_state=OK``
    and DO NOT email the operator.  The pain stopping is not itself an
    attention event."""
    # First seed the row as degraded via a real edge-fire.
    evt_active = _mk_event(key="pin_recovery", active=True)
    register_event(evt_active)
    _reset_state(db, evt_active.key)

    t0 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True):
        assert await fire_on_transition(
            evt_active, _StubConfig(), db, now=t0,
        ) == "sent"

    # Now flip the probe inactive on the SAME event key.
    evt_inactive = AdminAlertEvent(
        key="pin_recovery",
        subject=evt_active.subject,
        template_fn=evt_active.template_fn,
        probe_fn=lambda: (False, {}),
        cooldown_hours=24,
    )
    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=True,
    ) as send:
        out = await fire_on_transition(
            evt_inactive, _StubConfig(), db, now=t0 + timedelta(hours=1),
        )
    assert out == "recovered"
    assert send.call_count == 0, "silent recovery must not send an email"

    row = get_setting(db, _settings_key(evt_inactive.key))
    assert row["last_state"] == "OK"

    # And re-firing while OK is a noop.
    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=True,
    ) as send:
        out = await fire_on_transition(
            evt_inactive, _StubConfig(), db, now=t0 + timedelta(hours=2),
        )
    assert out == "noop"
    assert send.call_count == 0

    EVENT_REGISTRY.pop(evt_inactive.key, None)
    _reset_state(db, evt_inactive.key)


# ---------------------------------------------------------------------------
# 5) N-151 event registered at import time
# ---------------------------------------------------------------------------

def test_n151_soft_gate_event_registered_at_import():
    """PIN: the N-151 first consumer registers at module load — a future
    refactor that moves the ``register_event`` call outside module scope
    must be caught."""
    assert "n151_soft_gate" in EVENT_REGISTRY, (
        "N-151 event missing from EVENT_REGISTRY — the "
        "register_event(N151_SOFT_GATE_EVENT) call at module scope was "
        "moved or removed."
    )
    evt = EVENT_REGISTRY["n151_soft_gate"]
    assert evt is N151_SOFT_GATE_EVENT
    assert evt.cooldown_hours == 24
    assert evt.key == "n151_soft_gate"
    # Subject-line contract (customer-facing; changing this is a
    # user-visible behavior change).
    assert "SOFT-gate" in evt.subject
    # Template renders (html, text).
    html, text = evt.template_fn({
        "reason": "unavailable", "since": "2026-07-10T12:00Z",
    })
    assert isinstance(html, str) and isinstance(text, str)
    assert "unavailable" in html
    assert "unavailable" in text


# ---------------------------------------------------------------------------
# 6) fire_all iterates every registered event (async)
# ---------------------------------------------------------------------------

async def test_fire_all_visits_every_registered_event(db):
    """Non-PIN sanity: ``fire_all`` returns one entry per registered
    event.  Guards against a future refactor that filters the sweep.

    2026-07-10 fold: ``fire_all`` is now ``async`` (F3 — SMTP off the
    DB thread) so the caller in digest.py awaits it directly rather
    than re-wrapping in db_call.
    """
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True):
        # Force N-151 probe to a stable answer regardless of the real
        # MSAL key state on the CI runner.
        with patch.object(
            N151_SOFT_GATE_EVENT, "probe_fn",
            lambda: (False, {}),
        ):
            results = await fire_all(_StubConfig(), db)

    for key in EVENT_REGISTRY:
        assert key in results, (
            f"fire_all skipped registered event {key!r}"
        )


# ---------------------------------------------------------------------------
# 7) NEW PIN — stamp last_sent_at ONLY after a successful send (R1)
# ---------------------------------------------------------------------------

async def test_admin_alert_stamp_only_after_successful_send(db):
    """PIN (R1 — send-then-stamp bug): the primitive MUST NOT stamp
    ``last_sent_at`` when :func:`_send_admin_alert` returns False.

    Failure mode without the fix (2026-07-10):
      * ``fire_on_transition`` stamped ``last_sent_at=now`` upfront,
        BEFORE calling ``_send_admin_alert``.
      * Every failure path in ``_send_admin_alert`` (empty recipients,
        no smtp.host, template raise, smtp send raise) returned
        silently.
      * ``last_sent_at`` remained stamped, cooldown floor kicked in,
        the alert never delivered — operator silent for 24h.

    Arm A: send returns False → ``last_sent_at`` is left blank so the
    next tick's cooldown check evaluates True and retries the send.
    Arm B: send returns True → ``last_sent_at`` is stamped so the
    cooldown floor kicks in.
    """
    t0 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

    # --- Arm A: send returns False (empty-recipients / smtp-unconfig / etc.) ---
    evt = _mk_event(
        key="pin_stamp_after_success_failure",
        active=True, cooldown_hours=24,
    )
    register_event(evt)
    _reset_state(db, evt.key)

    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=False,
    ) as send:
        out = await fire_on_transition(evt, _StubConfig(), db, now=t0)
    assert out == "send_failed", (
        "a False return from _send_admin_alert must surface as "
        "'send_failed', not 'sent'"
    )
    assert send.call_count == 1
    row = get_setting(db, _settings_key(evt.key))
    assert isinstance(row, dict)
    assert row["last_state"] == "degraded", (
        "last_state must still flip to degraded upfront so the next "
        "tick's OK->degraded edge detection is stable"
    )
    assert row["since"] is not None
    assert row["last_sent_at"] is None, (
        "last_sent_at must NOT be stamped on a failed send — next "
        "tick's cooldown-ok=True is what makes the retry happen"
    )

    # Confirm the retry: next tick with the same failure returns to
    # ``send_failed`` (not ``suppressed``), because last_sent_at is still None.
    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=False,
    ) as send:
        out2 = await fire_on_transition(
            evt, _StubConfig(), db, now=t0 + timedelta(hours=1),
        )
    assert out2 == "send_failed", (
        "a stuck failing send must keep retrying, not be silenced by "
        "a phantom cooldown"
    )
    assert send.call_count == 1

    EVENT_REGISTRY.pop(evt.key, None)
    _reset_state(db, evt.key)

    # --- Arm B: send returns True → last_sent_at stamped ---
    evt = _mk_event(
        key="pin_stamp_after_success_ok",
        active=True, cooldown_hours=24,
    )
    register_event(evt)
    _reset_state(db, evt.key)

    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=True,
    ) as send:
        out = await fire_on_transition(evt, _StubConfig(), db, now=t0)
    assert out == "sent"
    assert send.call_count == 1
    row = get_setting(db, _settings_key(evt.key))
    assert row["last_state"] == "degraded"
    assert row["since"] is not None
    assert row["last_sent_at"] is not None, (
        "last_sent_at MUST be stamped on a successful send so the "
        "cooldown floor kicks in for the next tick"
    )
    # Timestamp roundtrips as UTC.
    dt = datetime.fromisoformat(row["last_sent_at"])
    assert dt.tzinfo is not None

    EVENT_REGISTRY.pop(evt.key, None)
    _reset_state(db, evt.key)


# ---------------------------------------------------------------------------
# 8) NEW PIN — reason-change edge beats the cooldown floor (R3)
# ---------------------------------------------------------------------------

async def test_admin_alert_reason_change_treated_as_edge(db):
    """PIN (R3 — reason-change is a new edge): while the gate stays
    ``degraded``, a probe returning a NEW ``reason`` must fire a fresh
    send even inside the cooldown window.

    Sequence:
      * t0: probe returns ``(True, reason="unavailable")`` → SENT
        (OK -> degraded edge).
      * t0+2h: probe returns ``(True, reason="probe_error")`` — inside
        the 24 h cooldown floor, BUT the reason has changed, so the
        primitive MUST fire again to notify the operator that a
        distinct failure mode is now active.
    """
    key = "pin_reason_change_edge"
    # Two events sharing the state row but differing in probe output —
    # simpler than mutating a mutable ``ctx`` cell mid-test.
    unavailable_evt = AdminAlertEvent(
        key=key,
        subject="[test] " + key,
        template_fn=lambda c: ("<p>t</p>", "t"),
        probe_fn=lambda: (True, {"reason": "unavailable"}),
        cooldown_hours=24,
    )
    probe_error_evt = AdminAlertEvent(
        key=key,
        subject="[test] " + key,
        template_fn=lambda c: ("<p>t</p>", "t"),
        probe_fn=lambda: (True, {"reason": "probe_error"}),
        cooldown_hours=24,
    )
    register_event(unavailable_evt)
    _reset_state(db, key)

    t0 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
    with patch.object(
        admin_alerts, "_send_admin_alert", return_value=True,
    ) as send:
        # Edge fire on reason=unavailable.
        out1 = await fire_on_transition(
            unavailable_evt, _StubConfig(), db, now=t0,
        )
        # 2h later — still well inside the 24h floor.  Same reason
        # would be SUPPRESSED — confirm that FIRST as a control arm.
        out_control = await fire_on_transition(
            unavailable_evt, _StubConfig(), db,
            now=t0 + timedelta(hours=2),
        )
        # Now the reason FLIPS to probe_error — must fire again.
        out_reason_change = await fire_on_transition(
            probe_error_evt, _StubConfig(), db,
            now=t0 + timedelta(hours=2, minutes=1),
        )

    assert out1 == "sent", "OK -> degraded edge fire missing"
    assert out_control == "suppressed", (
        "control arm: same reason inside cooldown must SUPPRESS "
        "(otherwise the reason-change assertion below proves nothing)"
    )
    assert out_reason_change == "sent", (
        "a distinct probe reason inside the cooldown window MUST fire "
        "a new alert — different failure mode = new operator edge"
    )
    assert send.call_count == 2, (
        f"expected 2 sends (edge + reason-change), got {send.call_count}"
    )

    # Row's ``reason`` now reflects the newer probe.
    row = get_setting(db, _settings_key(key))
    assert row["reason"] == "probe_error"
    # ``since`` still points at the ORIGINAL degradation edge — a
    # reason-change flip must NOT reset ``since`` (that would lie
    # about how long the operator has been in the dark).
    assert row["since"] == t0.isoformat()

    EVENT_REGISTRY.pop(key, None)
    _reset_state(db, key)
