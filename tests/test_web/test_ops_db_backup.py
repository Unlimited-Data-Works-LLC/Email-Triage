""" — the loopback ops backup-trigger endpoint.

Auth (loopback + ≥16-char X-Ops-Token, constant-time) is the shared
``_ops_token_authorized`` already unit-tested in the health suite; the
TestClient reports a NON-loopback host, so the real-auth path here is the
LAN-denied 403. The 202/409/503 behaviours are exercised with the auth
monkeypatched True (the same technique the health ops tests use)."""

from __future__ import annotations

import pytest

_AUTH = "email_triage.web.routers.health._ops_token_authorized"


def test_ops_trigger_denied_off_loopback(raw_client):
    # No token + non-loopback TestClient → the real ops gate denies.
    assert raw_client.post("/ops/db-backup").status_code == 403


def test_ops_trigger_503_when_disabled(raw_client, monkeypatch):
    monkeypatch.setattr(_AUTH, lambda **kw: True)
    # backup is disabled by default (config.backup.enabled=False).
    assert raw_client.post("/ops/db-backup").status_code == 503


def test_ops_trigger_202_schedules_run(raw_client, monkeypatch):
    monkeypatch.setattr(_AUTH, lambda **kw: True)
    monkeypatch.setattr(raw_client.app.state.config.backup, "enabled", True)
    monkeypatch.setattr(raw_client.app.state.config.backup, "format", "etbk")

    async def _fake_run(app, fmt, *, trigger="cron"):
        return {"outcome": "success", "format": fmt}

    monkeypatch.setattr(
        "email_triage.web.background_sweepers.run_backup_once", _fake_run
    )
    r = raw_client.post("/ops/db-backup")
    assert r.status_code == 202
    body = r.json()
    assert "request received" in body["detail"]
    assert body["format"] == "etbk"
    assert body["dir"]


def test_ops_trigger_honors_format_query(raw_client, monkeypatch):
    monkeypatch.setattr(_AUTH, lambda **kw: True)
    monkeypatch.setattr(raw_client.app.state.config.backup, "enabled", True)
    monkeypatch.setattr(raw_client.app.state.config.backup, "format", "etbk")

    async def _fake_run(app, fmt, *, trigger="cron"):
        return {"outcome": "success"}

    monkeypatch.setattr(
        "email_triage.web.background_sweepers.run_backup_once", _fake_run
    )
    r = raw_client.post("/ops/db-backup?format=db")
    assert r.status_code == 202
    assert r.json()["format"] == "db"


def test_ops_trigger_409_when_in_flight(raw_client, monkeypatch):
    monkeypatch.setattr(_AUTH, lambda **kw: True)
    monkeypatch.setattr(raw_client.app.state.config.backup, "enabled", True)
    monkeypatch.setattr("email_triage.single_flight.in_flight", lambda key: True)
    assert raw_client.post("/ops/db-backup").status_code == 409
