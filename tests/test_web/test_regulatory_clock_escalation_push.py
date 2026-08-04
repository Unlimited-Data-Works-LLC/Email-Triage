""" P4c-delivery — the escalation SMTP push (loop-guard header + PHI-free).

hipaa-sme MUST-FIX pin: the escalation email MUST carry the X-Email-Triage
loop-prevention header (send_smtp_message is pure transport + does not add it),
or a push to a watched owner mailbox re-ingests + re-triages.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from email_triage.web.background_sweepers import _send_clock_escalations


def _app():
    smtp = SimpleNamespace(
        host="smtp.example", port=587, username="u", from_addr="bot@example",
        from_name="Triage", use_tls=True,
    )
    config = SimpleNamespace(smtp=smtp, public_url="https://triage.example")
    return SimpleNamespace(state=SimpleNamespace(config=config, secrets=None))


@pytest.mark.asyncio
async def test_escalation_push_stamps_loop_guard_and_is_phi_free(monkeypatch):
    captured = {}

    def _fake_send(msg, **kwargs):
        captured["msg"] = msg

    monkeypatch.setattr(
        "email_triage.web.smtp_send.send_smtp_message", _fake_send,
    )
    notes = [{
        "instance_id": 1, "rung": 1, "to_addr": "pi@site.example",
        "label": "IRB/HRPO unanticipated-problem report", "state": "at_risk",
        "deadline_at": "2026-06-15T00:00:00+00:00",
    }]
    await _send_clock_escalations(_app(), notes)
    msg = captured["msg"]
    assert msg["X-Email-Triage"]                 # loop-prevention stamped
    assert msg["To"] == "pi@site.example"
    body = msg.get_body(preferencelist=("plain",))
    blob = (msg["Subject"] + body.get_content()).lower()
    assert "case_ref" not in blob and "case-" not in blob  # PHI-free
    assert "verify against your sop" in blob     # advisory copy
    # the always-on .ics calendar baseline is attached + PHI-free
    ics_parts = [
        p for p in msg.iter_attachments()
        if p.get_content_type() == "text/calendar"
    ]
    assert len(ics_parts) == 1
    raw = ics_parts[0].get_content()
    ics_str = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
    assert "BEGIN:VEVENT" in ics_str and "BEGIN:VALARM" in ics_str
    assert "case_ref" not in ics_str.lower()


@pytest.mark.asyncio
async def test_escalation_push_skips_when_smtp_unconfigured(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "email_triage.web.smtp_send.send_smtp_message",
        lambda *a, **k: sent.append(1),
    )
    app = _app()
    app.state.config.smtp.host = ""  # not configured
    await _send_clock_escalations(app, [{"to_addr": "x@y", "label": "L",
                                         "state": "at_risk", "deadline_at": None}])
    assert sent == []  # nothing sent


@pytest.mark.asyncio
async def test_escalation_push_skips_out_of_scope_recipient(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "email_triage.web.smtp_send.send_smtp_message",
        lambda *a, **k: sent.append(1),
    )
    await _send_clock_escalations(_app(), [{"to_addr": "", "label": "L",
                                            "state": "at_risk",
                                            "deadline_at": None}])
    assert sent == []  # empty/malformed recipient → BAA gate skips
