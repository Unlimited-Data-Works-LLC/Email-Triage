""" — the `email-triage backup now` CLI trigger.

Mocks the egress funnel (``email_triage._egress.egress_client``) so the trigger's
response handling (request received / app-offline / in-flight / no-token) is
exercised without a live server. run17 #5: the trigger now POSTs the loopback ops
endpoint through ``egress_client(intent=Intent.LOCAL_ONLY, verify=False)`` instead
of a raw ``urllib.request.urlopen``, so the mock seam moved from
``urllib.request.urlopen`` to ``egress_client``. cmd_backup imports egress_client
function-locally, so patching the ``email_triage._egress`` source attribute is
what the call picks up. The endpoint auth + scheduling are covered in
tests/test_web/."""

from __future__ import annotations

import argparse
import json

import httpx

from email_triage import cli


def _args(**kw):
    ns = argparse.Namespace(backup_cmd="now", format=None, wait=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class _FakeClient:
    """Stand-in for the ``egress_client`` context manager: ``.post()`` returns a
    prepared ``httpx.Response`` (status mapping path) or raises a prepared
    exception (app-offline / transport-error path)."""

    def __init__(self, *, response=None, exc=None):
        self._response = response
        self._exc = exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, **kw):
        if self._exc is not None:
            raise self._exc
        return self._response


def _patch_egress(monkeypatch, *, response=None, exc=None):
    monkeypatch.setattr(
        "email_triage._egress.egress_client",
        lambda **kw: _FakeClient(response=response, exc=exc),
    )


def _resp(status: int, body: dict) -> httpx.Response:
    """A real httpx.Response (so ``raise_for_status`` behaves exactly as in
    prod) carrying ``body`` as JSON."""
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        request=httpx.Request("POST", "https://localhost:8080/ops/db-backup"),
    )


def test_backup_now_requires_ops_token(monkeypatch, capsys):
    monkeypatch.delenv("ET_HEALTH_OPS_TOKEN", raising=False)
    assert cli.cmd_backup(_args()) == 2
    assert "ET_HEALTH_OPS_TOKEN" in capsys.readouterr().err


def test_backup_now_app_offline_is_fatal(monkeypatch, capsys):
    monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", "x" * 20)
    # httpx.ConnectError is a RequestError — the funnel equivalent of the old
    # urllib URLError "connection refused".
    _patch_egress(monkeypatch, exc=httpx.ConnectError("Connection refused"))
    assert cli.cmd_backup(_args()) == 2
    assert "FATAL: unavailable, app offline" in capsys.readouterr().err


def test_backup_now_request_received(monkeypatch, capsys):
    monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", "x" * 20)
    _patch_egress(monkeypatch, response=_resp(200, {
        "detail": "request received: outputting to /data/backups",
        "dir": "/data/backups",
        "format": "etbk",
    }))
    assert cli.cmd_backup(_args()) == 0
    assert "request received" in capsys.readouterr().out


def test_backup_now_already_in_flight(monkeypatch):
    monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", "x" * 20)
    _patch_egress(
        monkeypatch,
        response=_resp(409, {"detail": "a backup is already in flight"}),
    )
    assert cli.cmd_backup(_args()) == 1


def test_backup_now_disabled_is_fatal(monkeypatch, capsys):
    monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", "x" * 20)
    _patch_egress(
        monkeypatch,
        response=_resp(503, {"detail": "automated backup is disabled"}),
    )
    assert cli.cmd_backup(_args()) == 2
    assert "FATAL: backup disabled" in capsys.readouterr().err
