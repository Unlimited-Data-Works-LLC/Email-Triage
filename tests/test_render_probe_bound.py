"""Behaviour of the ``render_probe`` bound (t20) after panel X.

* NOTE-2 / DA-X1-4: only the probe's OWN bound is reported as "render probe bound" and raised
  as ``RenderProbeTimeout``; a provider's own ``TimeoutError`` passes through unchanged.
* db MUST-1: the label-picker helper ``providers/provider_labels.list_provider_labels_for_account``
  probes through the same bound, so a slow provider cannot hold the label picker, the digest
  editor or the routes page for the provider's whole budget.
* db SHOULD-1 (probe shape of ``panelX/db-sme/probe_latecert.py``): a handshake that outlives a
  short render bound and then fails verification is still logged.

``render_probe`` is imported through ``web/routers/ui/_shared`` (its re-export) and its bound is
patched in the module that defines it.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
import time

import pytest

from email_triage.web.routers.ui._shared import RenderProbeTimeout, render_probe

_HOME = sys.modules[render_probe.__module__]


class _Log:
    def __init__(self) -> None:
        self.infos: list[tuple[str, dict]] = []

    def info(self, msg, **kw):
        self.infos.append((msg, kw))


@pytest.fixture
def probe_log(monkeypatch):
    log = _Log()
    monkeypatch.setattr(_HOME, "_log", log)
    return log


class _Provider:
    _host = "imap.example.invalid"
    _port = 993

    def __init__(self, behaviour):
        self._behaviour = behaviour

    async def list_folders(self):
        return await self._behaviour()


async def test_a_providers_own_timeout_is_not_reported_as_the_bound(probe_log):
    async def own_timeout():
        raise TimeoutError("the provider's own HTTP timeout")

    with pytest.raises(TimeoutError) as info:
        await render_probe(_Provider(own_timeout))
    assert not isinstance(info.value, RenderProbeTimeout)
    assert "own HTTP timeout" in str(info.value)
    assert probe_log.infos == []


async def test_the_probes_own_bound_is_reported(probe_log, monkeypatch):
    monkeypatch.setattr(_HOME, "RENDER_PROBE_TIMEOUT_S", 0.05)

    async def never():
        await asyncio.sleep(3600)

    with pytest.raises(RenderProbeTimeout):
        await render_probe(_Provider(never))
    assert [m for m, _ in probe_log.infos] == ["render probe bound"]
    assert probe_log.infos[0][1]["host"] == "imap.example.invalid"


async def test_an_answer_inside_the_bound_is_returned(probe_log):
    async def answer():
        return ["INBOX"]

    assert await render_probe(_Provider(answer)) == ["INBOX"]
    assert probe_log.infos == []


async def test_the_label_picker_helper_is_bounded(monkeypatch):
    from email_triage.providers import provider_labels

    class _SlowGmail:
        closed = False

        async def list_labels(self):
            await asyncio.sleep(3600)

        async def close(self):
            _SlowGmail.closed = True

    monkeypatch.setattr(_HOME, "RENDER_PROBE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(provider_labels, "list_email_accounts",
                        lambda db, user_id=None: [{"id": 7, "provider_type": "gmail_api"}])
    monkeypatch.setattr(provider_labels, "build_provider", lambda acct, secrets: _SlowGmail())
    provider_labels.invalidate_cache_for_account(7)
    try:
        started = time.monotonic()
        got = await asyncio.wait_for(provider_labels.list_provider_labels_for_account(
            db=None, secrets=None, account_id=7), 5)
        assert got == []
        assert time.monotonic() - started < 2.0
        assert _SlowGmail.closed
    finally:
        provider_labels.invalidate_cache_for_account(7)


async def test_a_render_bound_on_a_slow_handshake_still_logs_the_late_cert_failure(monkeypatch):
    import aioimaplib

    from email_triage import tls
    from email_triage.providers import imap_fetch_transport
    from email_triage.providers.imap import ImapProvider

    events = []
    monkeypatch.setattr(tls, "_logger", lambda: type("R", (), {
        "warning": staticmethod(lambda msg, **kw: events.append(kw.get("action")))})())
    monkeypatch.setattr(tls, "_cert_log_last", {})
    monkeypatch.setattr(tls, "_bound_config", None)

    class _FakeSSL:
        def __init__(self, host, port, ssl_context):
            async def handshake():
                await asyncio.sleep(0.4)
                raise ssl.SSLCertVerificationError(
                    1, "certificate verify failed: self-signed certificate")
            self._client_task = asyncio.ensure_future(handshake())

        async def wait_hello_from_server(self):
            await asyncio.sleep(3600)

    monkeypatch.setattr(aioimaplib, "IMAP4_SSL", _FakeSSL)
    monkeypatch.setattr(imap_fetch_transport, "_aioimaplib_timeout", lambda mod: 5.0)
    monkeypatch.setattr(_HOME, "RENDER_PROBE_TIMEOUT_S", 0.2)
    provider = ImapProvider("imap.example.invalid", 993, "u", "p", use_ssl=True)
    provider._cert_policy = lambda: tls.CertPolicy(check=True, enforce=False)

    with pytest.raises(RenderProbeTimeout):
        await render_probe(provider)
    await asyncio.sleep(0.5)  # the shielded handshake lands and fails verification
    assert events == ["failed_after_handshake_wait"]
    assert provider._client is None
