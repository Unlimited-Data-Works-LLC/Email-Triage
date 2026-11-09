"""Punch 616 (N-602): the Test Classify paste route consults the BAA gate when
the system HIPAA flag is on.

The paste route was allow-listed in ``tests/test_classify_egress_baa_gate_pin.py``
as "account-UNSCOPED, no HIPAA flag to evaluate". Under the system HIPAA flag
every message is HIPAA, so that reason did not hold: an operator-pasted message
reached a non-BAA external backend in HIPAA mode (fail-OPEN on egress; panel B3
hipaa-sme F1a).

Teeth, driven through the real route with a real external classifier config and
only ``classify`` itself stubbed (to record whether egress was reached):
  * flag ON, external backend, no BAA ack: refused, ``classify`` never called;
  * flag OFF, same backend: ``classify`` reached (the gate is the HIPAA leg only);
  * flag ON, BAA acked for that (backend, host): ``classify`` reached.
"""
from __future__ import annotations

import pytest

from email_triage import triage_logging
from email_triage.engine.models import Classification

_EXTERNAL_URL = "https://api.example-llm.test/v1"
_RAW = (
    "From: sender@example.com\r\n"
    "To: receiver@example.com\r\n"
    "Subject: Lab results for review\r\n"
    "Date: Mon, 14 Apr 2025 10:00:00 +0000\r\n"
    "\r\n"
    "Patient body text."
)


@pytest.fixture
def external_classifier(app, monkeypatch):
    """Point the app config at an external OpenAI-compatible backend and record
    every call that would egress."""
    from email_triage.classify.openai_compat import OpenAICompatClassifier

    cfg = app.state.config.classifier
    monkeypatch.setattr(cfg, "backend", "openai")
    monkeypatch.setattr(cfg, "openai_base_url", _EXTERNAL_URL)
    monkeypatch.setattr(cfg, "openai_model", "test-model")
    calls: list[str] = []

    async def _classify(self, message, categories, list_hints=None):
        calls.append(message.subject)
        return Classification(category="inbox", confidence=0.9, reason="stub",
                              source="llm")

    monkeypatch.setattr(OpenAICompatClassifier, "classify", _classify)
    return calls


def test_system_flag_on_refuses_a_non_baa_backend(client, admin_cookies,
                                                  external_classifier, monkeypatch):
    monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
    resp = client.post("/classify/run", data={"raw_email": _RAW}, cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Classification refused" in resp.text
    assert "no BAA on file" in resp.text
    assert external_classifier == [], "the paste egressed to a non-BAA backend in HIPAA mode"


def test_system_flag_off_reaches_the_backend(client, admin_cookies,
                                             external_classifier, monkeypatch):
    monkeypatch.setattr(triage_logging, "_hipaa_mode", False)
    resp = client.post("/classify/run", data={"raw_email": _RAW}, cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Classification refused" not in resp.text
    assert external_classifier == ["Lab results for review"]


def test_system_flag_on_with_a_baa_ack_reaches_the_backend(client, admin_cookies, admin_user,
                                                           db, external_classifier,
                                                           monkeypatch):
    from email_triage.classify.baa_gate import classifier_baa_status, set_baa_ack
    from email_triage.classify.openai_compat import OpenAICompatClassifier

    status = classifier_baa_status(db, OpenAICompatClassifier(base_url=_EXTERNAL_URL))
    assert status["is_local"] is False, "rig: the backend must be external for this arm"
    set_baa_ack(db, status["backend"], status["host"], admin_user["id"])
    db.commit()
    monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
    resp = client.post("/classify/run", data={"raw_email": _RAW}, cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Classification refused" not in resp.text
    assert external_classifier == ["Lab results for review"]
