"""Panel X DA-X1-1 / db SHOULD-2: a connect that fails or is cancelled leaves no client behind.

``ImapProvider._connect`` used to store the new client on ``self._client`` before the greeting
and the login. A render-probe bound (3 s) or a greeting timeout (the watcher's 10 s budget) then
left a client that never logged in: the next call on the SAME provider took the cached-client
short cut and failed (``Abort: command LIST illegal in state NONAUTH``), and nobody closed the
half-open connection. Now the client is cached only once the connect sequence finishes; on any
exception, cancellation included, it is closed and re-raised.

The server is a loopback IMAP stub whose FIRST connection greets late; every later connection
greets at once, so a second call succeeds only if it opens a fresh connection.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

from email_triage.providers.imap import ImapProvider

_LATE = 0.8  # the first connection's greeting delay, longer than every bound below
_BOUND = 0.3


class _Stub:
    """Loopback IMAP stub: CAPABILITY, LOGIN, SELECT, LIST, LOGOUT. ``closed[i]`` is set when connection
    ``i`` sees EOF from the client."""

    def __init__(self) -> None:
        self.closed: list[asyncio.Event] = []
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer) -> None:
        index = len(self.closed)
        closed = asyncio.Event()
        self.closed.append(closed)
        try:
            if index == 0:
                await asyncio.sleep(_LATE)
            writer.write(b"* OK stub ready\r\n")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    return
                tag, cmd = (line.strip().split(b" ", 2) + [b""])[:2]
                cmd = cmd.upper()
                if cmd == b"CAPABILITY":  # aioimaplib asks right after the greeting
                    writer.write(b"* CAPABILITY IMAP4rev1\r\n")
                elif cmd == b"LIST":
                    writer.write(b'* LIST (\\HasNoChildren) "." "INBOX"\r\n')
                elif cmd == b"SELECT":
                    writer.write(b"* 0 EXISTS\r\n* OK [UIDVALIDITY 1] ok\r\n")
                elif cmd == b"LOGOUT":
                    writer.write(b"* BYE\r\n")
                writer.write(tag + b" OK done\r\n")
                await writer.drain()
        except (ConnectionError, OSError):
            return
        finally:
            closed.set()
            writer.close()

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            try:  # 3.12+ waits for open connections too; a leaked one must not hang the test
                await asyncio.wait_for(self.server.wait_closed(), 2)
            except TimeoutError:
                pass


def _provider(port: int) -> ImapProvider:
    return ImapProvider("127.0.0.1", port, "u", "p", use_ssl=False)


async def test_a_render_bound_during_the_greeting_leaves_no_stale_client(monkeypatch):
    """DA's probe shape: the bound hits while the first server greets late; the next call on
    the same provider opens a fresh connection and succeeds, and the abandoned connection is
    closed by the client instead of being left half-open."""
    from email_triage.web.routers.ui._shared import RenderProbeTimeout, render_probe

    monkeypatch.setattr(sys.modules[render_probe.__module__], "RENDER_PROBE_TIMEOUT_S", _BOUND)
    stub = _Stub()
    port = await stub.start()
    provider = _provider(port)
    try:
        with pytest.raises(RenderProbeTimeout):
            await render_probe(provider)
        assert provider._client is None
        await asyncio.wait_for(stub.closed[0].wait(), 2)
        assert await asyncio.wait_for(provider.list_folders(), 5) == ["INBOX"]
    finally:
        await provider.close()
        await stub.stop()


async def test_a_greeting_timeout_leaves_no_stale_client(monkeypatch):
    """The watcher / poller path, same root cause: the greeting outlives the provider's own
    budget (aioimaplib's ``TIMEOUT_SECONDS``, shortened here)."""
    from email_triage.providers import imap_fetch_transport

    monkeypatch.setattr(imap_fetch_transport, "_aioimaplib_timeout", lambda mod: _BOUND)
    stub = _Stub()
    port = await stub.start()
    provider = _provider(port)
    try:
        with pytest.raises(asyncio.TimeoutError):
            await provider.list_folders()
        assert provider._client is None
        await asyncio.wait_for(stub.closed[0].wait(), 2)
        assert await asyncio.wait_for(provider.list_folders(), 5) == ["INBOX"]
    finally:
        await provider.close()
        await stub.stop()


async def test_a_render_bound_during_the_tls_handshake_closes_the_orphaned_connection(monkeypatch):
    """db SHOULD-2 (i): the bound cancels the caller DURING the connect, while the shielded TLS
    handshake still runs, so nobody ever receives the client. Its connection task gets at most
    one more budget (a late certificate failure is still logged, M-DA-7) and is then cancelled,
    which closes the socket. Before, the socket stayed open until asyncio's own 60 s handshake
    timeout. The server reads the ClientHello and never answers it."""
    from email_triage import tls
    from email_triage.providers import imap_fetch_transport
    from email_triage.web.routers.ui._shared import RenderProbeTimeout, render_probe

    monkeypatch.setattr(sys.modules[render_probe.__module__], "RENDER_PROBE_TIMEOUT_S", _BOUND)
    monkeypatch.setattr(imap_fetch_transport, "_aioimaplib_timeout", lambda mod: 0.5)
    closed = asyncio.Event()

    async def silent(reader, writer):
        try:
            while await reader.read(4096):
                pass
        except (ConnectionError, OSError):
            pass
        finally:
            closed.set()
            writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    provider = ImapProvider("127.0.0.1", server.sockets[0].getsockname()[1], "u", "p",
                            use_ssl=True)
    provider._cert_policy = lambda: tls.CertPolicy(check=True, enforce=True)
    try:
        with pytest.raises(RenderProbeTimeout):
            await render_probe(provider)
        assert provider._client is None
        await asyncio.wait_for(closed.wait(), 3)
    finally:
        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), 2)
        except TimeoutError:
            pass


async def test_a_successful_connect_is_cached():
    stub = _Stub()
    stub.closed.append(asyncio.Event())  # connection 0 is taken: every connection greets at once
    port = await stub.start()
    provider = _provider(port)
    try:
        assert await provider.list_folders() == ["INBOX"]
        first = provider._client
        assert first is not None
        assert await provider.list_folders() == ["INBOX"]
        assert provider._client is first
        assert len(stub.closed) == 2  # one real connection, reused
    finally:
        await provider.close()
        await stub.stop()


class _Transport:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def test_discard_closes_a_pending_connection_only_when_it_lands():
    """A connection task still running is NOT cancelled (a late certificate failure must still
    be logged, panel M M-DA-7); its transport is closed once the task lands."""
    from email_triage.providers.imap_fetch_transport import aioimaplib_discard

    task = asyncio.get_running_loop().create_future()
    client = type("C", (), {})()
    client._client_task = task
    client.protocol = type("P", (), {"transport": None})()
    aioimaplib_discard(client)
    assert not task.cancelled()
    transport = _Transport()
    client.protocol.transport = transport
    task.set_result(("transport", "protocol"))
    await asyncio.sleep(0)
    assert transport.closed


async def test_discard_cancels_a_connection_that_outlives_one_more_budget(monkeypatch):
    from email_triage.providers import imap_fetch_transport

    monkeypatch.setattr(imap_fetch_transport, "_aioimaplib_timeout", lambda mod: 0.05)
    task = asyncio.get_running_loop().create_future()  # a handshake that never ends
    client = type("C", (), {})()
    client._client_task = task
    client.protocol = type("P", (), {"transport": None})()
    imap_fetch_transport.aioimaplib_discard(client)
    assert not task.cancelled()
    await asyncio.sleep(0.2)
    assert task.cancelled()


async def test_discard_closes_a_connected_client_at_once():
    from email_triage.providers.imap_fetch_transport import aioimaplib_discard

    task = asyncio.get_running_loop().create_future()
    task.set_result(("transport", "protocol"))
    client = type("C", (), {})()
    client._client_task = task
    transport = _Transport()
    client.protocol = type("P", (), {"transport": transport})()
    aioimaplib_discard(client)
    assert transport.closed
