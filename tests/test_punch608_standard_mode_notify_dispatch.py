"""Punch 608 — standard-mode notify was refused on every call, with a §164.312(b) WARNING each time.

`web/events.py::fire_notification` refuses any payload carrying a
content-bearing key (`sender`, `subject`, `body`, …) UNCONDITIONALLY —
N-293 made that deliberate so a caller's HIPAA misfire cannot egress PHI,
and its commit said standard-mode notifications needing sender/subject
"must route through a different helper". That helper was never built.
`NotifyAction` sent every standard-mode payload (which carries sender +
subject by design) to `fire_notification`, so standard mode dispatched
nothing and wrote a `notification_leak_refused` WARNING into the
HMAC-chained `log_entries` on every notification.

Direction of failure before: fail-closed egress, fail-silent function
(no webhook ever fired), audit noise (a false "refused" on every send).

The fix builds that helper, `fire_standard_notification`, and leaves
`fire_notification` exactly as strict as it was. The helper decides HIPAA
itself, at the actuator, through `account_hipaa_effective` (the
account-effective SSOT), so a caller that misjudges HIPAA still cannot
push sender/subject out: anything that is not a verified standard-mode
payload is handed to `fire_notification`, which refuses it and writes the
audit-of-record line. Routine standard-mode sends write nothing.
"""
from __future__ import annotations

import ast
import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

import email_triage.triage_logging as _tl
from email_triage.actions.notify import NotifyAction
from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.web.events import register_event_dispatcher

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    relpath,
)


class _FakeDispatcher:
    def __init__(self):
        self.fired: list[tuple] = []

    async def fire(self, event, payload, *, is_hipaa=False, account_id=None):
        self.fired.append((event, dict(payload), is_hipaa, account_id))


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(_tl, "_hipaa_mode", False)
    fake = _FakeDispatcher()
    register_event_dispatcher(fake)
    lg = logging.getLogger("email_triage.web.events")
    cap = _Capture()
    old_level = lg.level
    lg.addHandler(cap)
    lg.setLevel(logging.DEBUG)
    try:
        yield fake, cap
    finally:
        lg.removeHandler(cap)
        lg.setLevel(old_level)
        register_event_dispatcher(None)


def _refusals(cap: _Capture) -> list[logging.LogRecord]:
    return [
        r for r in cap.records
        if r.levelno >= logging.WARNING and "payload leak refused" in r.getMessage()
    ]


def _message(*, hipaa: bool = False) -> EmailMessage:
    return EmailMessage(
        message_id="m-608",
        provider="imap",
        sender="Alice Example <alice@example.com>",
        recipients=["me@example.com"],
        subject="Quarterly numbers",
        body_text="The numbers are attached.",
        date=datetime(2026, 10, 10, 14, 0, tzinfo=timezone.utc),
        hipaa=hipaa,
    )


def _flow(account) -> FlowState:
    return FlowState(
        flow_id="f-608",
        message_id="m-608",
        provider="imap",
        status=FlowStatus.ACTING,
        state_bag={
            "account_id": account["id"] if account else None,
            "account": account,
        },
    )


async def _notify(account, *, msg_hipaa: bool = False):
    cls = Classification(category="work", confidence=0.9, reason="r", source="llm")
    return await NotifyAction().execute(
        _flow(account), _message(hipaa=msg_hipaa), cls, AsyncMock(),
    )


# --------------------------------------------------------------------------
# Behaviour through the real NotifyAction.execute.
# --------------------------------------------------------------------------

async def test_standard_mode_notification_is_dispatched_with_no_refusal_event(harness):
    """RED before the fix: 0 dispatches and 1 `payload leak refused` WARNING."""
    fake, cap = harness
    await _notify({"id": 7, "hipaa": 0})
    assert len(fake.fired) == 1, "standard-mode notification was not dispatched"
    event, payload, is_hipaa, account_id = fake.fired[0]
    assert event == "notification"
    assert payload["sender"] == "Alice Example <alice@example.com>"
    assert payload["subject"] == "Quarterly numbers"
    assert is_hipaa is False
    assert account_id == "7"
    assert _refusals(cap) == [], "a routine standard-mode send wrote a refusal event"


async def test_install_hipaa_mode_dispatches_metadata_only_with_no_refusal(harness, monkeypatch):
    fake, cap = harness
    monkeypatch.setattr(_tl, "_hipaa_mode", True)
    await _notify({"id": 7, "hipaa": 0})
    assert len(fake.fired) == 1
    _, payload, is_hipaa, _ = fake.fired[0]
    assert is_hipaa is True
    assert "sender" not in payload and "subject" not in payload
    assert _refusals(cap) == []


async def test_per_account_hipaa_with_unstamped_message_dispatches_metadata_only(harness):
    """Install flag off, account flag on, message stamp False. The account
    axis of the SSOT must make the payload metadata-only (before the fix,
    `_build_notification` read the message stamp only)."""
    fake, cap = harness
    await _notify({"id": 9, "hipaa": 1}, msg_hipaa=False)
    assert len(fake.fired) == 1
    _, payload, is_hipaa, _ = fake.fired[0]
    assert is_hipaa is True
    assert "sender" not in payload and "subject" not in payload
    assert _refusals(cap) == []


# --------------------------------------------------------------------------
# The standard door decides HIPAA itself, and refuses for real.
# --------------------------------------------------------------------------

_STANDARD_PAYLOAD = {
    "flow_id": "f-608",
    "account_id": 9,
    "sender": "alice@example.com",
    "subject": "Lab results",
    "category": "work",
    "timestamp": "2026-10-10T14:00:00+00:00",
    "summary": "[work] from alice@example.com: Lab results",
}


async def test_standard_door_refuses_sender_subject_when_the_account_is_hipaa(harness):
    """A caller that wrongly thinks the context is standard (message stamp
    False) still cannot egress sender/subject for a HIPAA account: the door
    asks the SSOT itself, refuses, and writes exactly one refusal event."""
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    ok = await fire_standard_notification(
        dict(_STANDARD_PAYLOAD), account={"id": 9, "hipaa": 1}, message=_message(hipaa=False),
    )
    assert ok is False
    assert fake.fired == []
    assert len(_refusals(cap)) == 1


async def test_standard_door_refuses_when_install_hipaa_mode_is_on(harness, monkeypatch):
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    monkeypatch.setattr(_tl, "_hipaa_mode", True)
    ok = await fire_standard_notification(
        dict(_STANDARD_PAYLOAD), account={"id": 9, "hipaa": 0}, message=_message(),
    )
    assert ok is False and fake.fired == [] and len(_refusals(cap)) == 1


async def test_standard_door_refuses_when_the_account_is_unknown(harness):
    """No account row means the account axis cannot be checked: refuse."""
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    ok = await fire_standard_notification(
        dict(_STANDARD_PAYLOAD), account=None, message=_message(),
    )
    assert ok is False and fake.fired == [] and len(_refusals(cap)) == 1


async def test_standard_door_refuses_when_payload_names_another_account(harness):
    """The HIPAA check must be about the account the webhook routes for."""
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    ok = await fire_standard_notification(
        dict(_STANDARD_PAYLOAD), account={"id": 3, "hipaa": 0}, message=_message(),
    )
    assert ok is False and fake.fired == [] and len(_refusals(cap)) == 1


@pytest.mark.parametrize("extra_key", ["body", "snippet", "attachments", "to", "message_id"])
async def test_standard_door_refuses_content_keys_beyond_sender_subject(harness, extra_key):
    """Standard mode carries sender + subject; message content never."""
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    payload = dict(_STANDARD_PAYLOAD, **{extra_key: "x"})
    ok = await fire_standard_notification(
        payload, account={"id": 9, "hipaa": 0}, message=_message(),
    )
    assert ok is False and fake.fired == [] and len(_refusals(cap)) == 1


async def test_standard_door_dispatches_a_verified_standard_payload(harness):
    from email_triage.web.events import fire_standard_notification
    fake, cap = harness
    ok = await fire_standard_notification(
        dict(_STANDARD_PAYLOAD), account={"id": 9, "hipaa": 0}, message=_message(),
    )
    assert ok is True
    assert len(fake.fired) == 1 and fake.fired[0][2] is False and fake.fired[0][3] == "9"
    assert _refusals(cap) == []


# --------------------------------------------------------------------------
# Structural pin: every `notification` dispatch is HIPAA-decided by the SSOT.
# --------------------------------------------------------------------------

_STRICT_DOOR = "fire_notification"
_SSOT = "account_hipaa_effective"


def _is_notification_fire(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fire"
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "notification"
    )


def _calls(fn: ast.AST, name: str) -> list[ast.Call]:
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            callee = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if callee == name:
                out.append(n)
    return out


def _notification_dispatch_violations(tree: ast.AST) -> list[str]:
    """A `.fire("notification", …)` is allowed only (a) inside the strict
    door `fire_notification`, which refuses every content-bearing key, or
    (b) in a function that calls `account_hipaa_effective` before the fire
    AND hands the HIPAA case to the strict door. Anything else is a third
    door that could dispatch sender/subject on a caller's say-so."""
    violations = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fires = [n for n in ast.walk(fn) if _is_notification_fire(n)]
        if not fires or fn.name == _STRICT_DOOR:
            continue
        ssot = _calls(fn, _SSOT)
        strict = _calls(fn, _STRICT_DOOR)
        for f in fires:
            if not any(s.lineno < f.lineno for s in ssot):
                violations.append(f"{fn.name}:{f.lineno} fires `notification` without {_SSOT} first")
            if not strict:
                violations.append(f"{fn.name}:{f.lineno} never hands the HIPAA case to {_STRICT_DOOR}")
    return violations


def test_every_notification_dispatch_is_hipaa_decided_by_the_ssot():
    offenders, sites = [], 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        sites += sum(1 for n in ast.walk(tree) if _is_notification_fire(n))
        offenders += [f"{relpath(path)}: {v}" for v in _notification_dispatch_violations(tree)]
    assert sites >= 2, "expected the strict and the standard notification doors (pin would be vacuous)"
    assert not offenders, "\n".join(offenders)


def test_notification_dispatch_pin_has_teeth():
    bad = (
        "async def fire_other(payload, *, is_hipaa):\n"
        "    await d.fire('notification', payload, is_hipaa=is_hipaa)\n"
    )
    good = (
        "async def fire_standard(payload, *, account, message):\n"
        "    if account_hipaa_effective(account=account, message=message):\n"
        "        return await fire_notification(payload, is_hipaa=True)\n"
        "    await d.fire('notification', payload, is_hipaa=False)\n"
    )
    assert_pin_has_teeth(_notification_dispatch_violations, bad, good)


def test_standard_door_accepts_every_key_the_standard_payload_carries():
    """`_build_notification`'s keys and the standard door's key set are two
    lists that must agree: a key added to the payload but not the door
    silently drops every standard notification back to the strict door,
    which is the 608 symptom again."""
    from _pin_harness import returned_dict_keys
    from email_triage.web.events import _STANDARD_NOTIFICATION_KEYS
    tree = parse_module(SRC_ROOT / "actions" / "notify.py")
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_build_notification"
    )
    keys = set(returned_dict_keys(fn))
    assert {"sender", "subject"} <= keys, "standard payload shape not found (pin would be vacuous)"
    assert keys <= _STANDARD_NOTIFICATION_KEYS, sorted(keys - _STANDARD_NOTIFICATION_KEYS)


def test_standard_door_only_caller_is_notify_action():
    """`fire_standard_notification` forwards its caller's payload to the
    strict door unchanged; the `account_id` promise behind its entry in
    `_FIRE_NOTIFICATION_KNOWN_CALLERS` holds only while NotifyAction (whose
    payload comes from `_build_notification`) is its sole caller."""
    callers = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        if _calls(tree, "fire_standard_notification"):
            callers.append(relpath(path))
    assert callers == ["actions/notify.py"], callers


def test_notify_action_never_dispatches_directly():
    """NotifyAction reaches webhooks only through the two doors."""
    tree = parse_module(SRC_ROOT / "actions" / "notify.py")
    assert not [n for n in ast.walk(tree) if _is_notification_fire(n)]
    assert _calls(tree, "fire_standard_notification"), "NotifyAction does not use the standard door"
    assert _calls(tree, _STRICT_DOOR), "NotifyAction does not use the strict door"
