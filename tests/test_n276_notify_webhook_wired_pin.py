"""N-276 R28 structural pin — NotifyAction wired to notification webhook (2026-07-03).

Operator ruling 2026-07-03 (punch ): outbound event webhooks are a
Route/Watch target action. Webhooks are DISABLED on HIPAA accounts
EXCEPT the notification event, which is redacted the same as the SMS
escalation route.

Row 77 flagged `NotifyAction` was log-only vs a live event-webhook
path. The `EventDispatcher` + `Intent.WEBHOOK` egress-funnel + HMAC
signing already exist; N-276 landed the `fire_notification()` helper +
wired NotifyAction to call it + registered the dispatcher on a module-
level accessor so background loops (no request context) can fire it.

WHAT IT PINS (anti-vacuity):

  1. `fire_notification` exists + refuses HIPAA payloads carrying
     forbidden keys (sender/subject/body/etc.).
  2. `NotifyAction.execute` textually calls `fire_notification`.
  3. `web/app.py` lifespan textually calls `register_event_dispatcher`
     on startup + shutdown (None).
"""
from __future__ import annotations

import asyncio

from _pin_harness import SRC_ROOT


def test_fire_notification_refuses_hipaa_payload_leak():
    """N-276 R28: `fire_notification(is_hipaa=True)` refuses payloads
    carrying `sender` / `subject` / `body` / etc. Defense-in-depth
    against a caller forgetting to scrub. Returns False (suppressed)."""
    from email_triage.web.events import fire_notification, register_event_dispatcher

    class _FakeDispatcher:
        def __init__(self):
            self.fired = []
        async def fire(self, event, payload, *, is_hipaa=False, account_id=None):
            # Signature widened for the 2026-07-15 per-target-templating
            # contract: EventDispatcher.fire takes ``is_hipaa`` (HIPAA
            # lock in render_for_target) + ``account_id`` (DA-F3b cross-
            # account fanning fix in _matching_targets). Fake mirrors
            # both so ``fire_notification`` can call it verbatim.
            self.fired.append((event, payload, is_hipaa, account_id))

    fake = _FakeDispatcher()
    register_event_dispatcher(fake)
    try:
        # HIPAA payload with a forbidden key MUST be refused.
        result = asyncio.run(fire_notification(
            {"category": "clinical", "sender": "phi@example.com"},
            is_hipaa=True,
        ))
        assert result is False, (
            "N-276 R28: fire_notification MUST refuse a HIPAA payload "
            "carrying a `sender` key (metadata-only invariant per row 77 "
            "ruling)."
        )
        assert not fake.fired, "dispatcher must not have been called"

        # N-293 R30 (HIPAA-SME fix-forward): the forbidden-key refusal
        # is UNCONDITIONAL — is_hipaa=False + forbidden key STILL refused.
        # This closes the "detection-misfire defeats defense-in-depth"
        # gap the HIPAA-SME post-hoc review flagged.
        fake.fired.clear()
        result = asyncio.run(fire_notification(
            {"category": "clinical", "sender": "phi@example.com"},
            is_hipaa=False,
        ))
        assert result is False, (
            "N-293 R30 REGRESSION: fire_notification MUST refuse ANY "
            "payload carrying a forbidden content-bearing key regardless "
            "of the caller's is_hipaa flag. Detection-misfire on a HIPAA-"
            "tagged account (incident_2026-06-12 shape) previously "
            "silently egressed PHI."
        )
        assert not fake.fired, "dispatcher must not have been called on N-293 refusal"

        # Clean HIPAA payload (metadata-only) succeeds.
        result = asyncio.run(fire_notification(
            {"category": "clinical", "timestamp": "2026-07-03T00:00:00Z",
             "flow_id": "abc"},
            is_hipaa=True,
        ))
        assert result is True, "clean HIPAA payload must dispatch"
        assert len(fake.fired) == 1
        assert fake.fired[0][0] == "notification"
    finally:
        register_event_dispatcher(None)


def test_notify_action_wires_fire_notification():
    """Anti-vacuity: NotifyAction.execute textually calls
    `fire_notification`. A refactor that drops the call re-opens
    the row 77 gap."""
    from email_triage.actions import notify as notify_mod
    import inspect
    src = inspect.getsource(notify_mod.NotifyAction)
    assert "fire_notification" in src, (
        "N-276 R28 REGRESSION: NotifyAction no longer calls "
        "`fire_notification`. Row 77 (outbound event webhook) will "
        "revert to log-only."
    )


def test_app_lifespan_registers_dispatcher():
    """The web app lifespan textually calls `register_event_dispatcher`
    at both startup + shutdown so the module-level accessor stays in
    sync with the request-scoped dispatcher."""
    app_py = SRC_ROOT / "web" / "app.py"
    source = app_py.read_text(encoding="utf-8", errors="replace")
    startup_calls = source.count("register_event_dispatcher(app.state.event_dispatcher)")
    shutdown_calls = source.count("register_event_dispatcher(None)")
    assert startup_calls >= 1, (
        "N-276 R28: app lifespan must call "
        "`register_event_dispatcher(app.state.event_dispatcher)` at "
        "startup — NotifyAction can't fire without it."
    )
    assert shutdown_calls >= 1, (
        "N-276 R28: app lifespan must call `register_event_dispatcher"
        "(None)` at shutdown — otherwise a stale dispatcher stays "
        "registered after aclose()."
    )
