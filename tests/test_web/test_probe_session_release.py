"""Punch 694, behaviour: a probe that fails after login still releases the provider/IMAP session.

The structural pin is ``tests/test_probe_session_close_pin.py``; these drive the real handlers and
the funnel with fakes that count their closes, on the failing path the old code skipped.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest


class _Provider:
    """Counts its closes; its probe fails or answers as told."""

    def __init__(self, folders=None, fail: Exception | None = None):
        self.folders, self.fail, self.closed = folders or ["INBOX"], fail, 0

    async def list_folders(self):
        if self.fail is not None:
            raise self.fail
        return self.folders

    async def close(self):
        self.closed += 1


def _make_account(db, user_id):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) VALUES (?, ?, 'imap', ?, 0, ?, ?)",
        (user_id, "Probe Acct", json.dumps({"host": "mail.unreachable.invalid",
                                            "username": "t@t.invalid"}), now, now))
    db.commit()
    return cur.lastrowid


@pytest.mark.parametrize("path, module", [
    ("/accounts/{id}/folders", "accounts"),
    ("/accounts/{id}/folders/prefs", "accounts"),
])
@pytest.mark.parametrize("fails", [True, False])
def test_the_folder_routes_close_the_provider_on_a_failed_and_a_good_probe(
        client, admin_cookies, db, admin_user, monkeypatch, path, module, fails):
    acct_id = _make_account(db, admin_user["id"])
    prov = _Provider(fail=RuntimeError("NO [AUTHENTICATIONFAILED] after login") if fails else None)
    import importlib
    mod = importlib.import_module(f"email_triage.web.routers.ui.{module}")
    monkeypatch.setattr(mod, "_create_provider_from_account", lambda acct, secrets: prov)
    resp = client.get(path.format(id=acct_id), cookies=admin_cookies)
    assert resp.status_code == 200
    assert prov.closed == 1, "the session must be released exactly once, failed probe or not"


def test_probe_session_closes_on_a_failed_probe_and_swallows_a_failing_close():
    from email_triage.providers.render_probe import probe_session

    class _BadClose(_Provider):
        async def close(self):
            await super().close()
            raise OSError("socket already gone")

    prov = _BadClose(fail=RuntimeError("probe failed"))

    async def run():
        async with probe_session(prov):
            await prov.list_folders()

    with pytest.raises(RuntimeError, match="probe failed"):  # the probe's error, not the close's
        asyncio.run(run())
    assert prov.closed == 1


def test_probe_session_tolerates_a_sync_close():
    from email_triage.providers.render_probe import probe_session

    class _Sync:
        closed = 0

        def close(self):
            self.closed += 1

    prov = _Sync()

    async def run():
        async with probe_session(prov):
            pass

    asyncio.run(run())
    assert prov.closed == 1


class _Imap:
    _et_cert_verdict = None

    def __init__(self, fail_on: str):
        self.fail_on, self.logouts = fail_on, 0

    def login(self, user, password):
        if self.fail_on == "login":
            raise RuntimeError("LOGIN failed")

    def select(self, mailbox, readonly=True):
        if self.fail_on == "select":
            raise RuntimeError("SELECT failed")
        return "OK", [b"3"]

    def logout(self):
        self.logouts += 1

    def shutdown(self):
        raise AssertionError("shutdown is only the fallback when logout itself fails")


@pytest.mark.parametrize("fail_on", ["login", "select", "none"])
def test_the_imap_connection_probe_logs_out_exactly_once_whatever_fails(monkeypatch, fail_on):
    import email_triage.providers.imap_fetch_transport as transport
    import email_triage.secrets as secrets_mod
    from email_triage.providers.dispatcher import _imap_test_connection

    imap = _Imap(fail_on)
    monkeypatch.setattr(transport, "imap_connect", lambda *a, **kw: imap)
    monkeypatch.setattr(secrets_mod, "read_secret", lambda s, k: "pw")
    acct = {"provider_type": "imap", "id": 1,
            "config": {"host": "mail.invalid", "port": 993, "username": "u"}}
    ok, _ = asyncio.run(_imap_test_connection(acct, object()))
    assert ok is (fail_on == "none")
    assert imap.logouts == 1


def test_a_logout_that_fails_falls_back_to_closing_the_socket():
    from email_triage.providers.dispatcher import _imap_release

    class _Dead:
        shut = 0

        def logout(self):
            raise OSError("connection reset")

        def shutdown(self):
            self.shut += 1

    dead = _Dead()
    _imap_release(dead)
    assert dead.shut == 1
