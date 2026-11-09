"""Teeth for ``tests/_network_guard.py``: a connect or lookup to a non-loopback host is refused
at once, under the test's own node id, on every seam; loopback still works.

The mutation check: ``pytest tests/test_network_guard.py -p no:network-guard`` runs these with
the guard off, and every refusal test goes red (t20 report).
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time

import pytest

import _network_guard

# TEST-NET-1 (RFC 5737): never routed, so an unguarded connect hangs or fails slowly; it never
# raises the guard's own error.
_BLACK_HOLE = ("192.0.2.1", 9)

_LOOPS = [pytest.param(asyncio.SelectorEventLoop, id="selector")]
if sys.platform == "win32":
    _LOOPS.append(pytest.param(asyncio.ProactorEventLoop, id="proactor"))


def _assert_refusal(exc: BaseException, request: pytest.FixtureRequest, where: str) -> None:
    text = str(exc)
    assert request.node.nodeid in text, text
    assert where in text, text


def test_every_seam_holds_the_guard():
    assert _network_guard.installed()


def test_sync_connect_to_a_non_loopback_address_is_refused_at_once(request):
    started = time.monotonic()
    with pytest.raises(_network_guard.OutboundConnectRefused) as info:
        socket.create_connection(_BLACK_HOLE, timeout=5)
    assert time.monotonic() - started < 1.0
    _assert_refusal(info.value, request, "192.0.2.1:9")


def test_connect_ex_to_a_non_loopback_address_is_refused(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(_network_guard.OutboundConnectRefused) as info:
            sock.connect_ex(_BLACK_HOLE)
    _assert_refusal(info.value, request, "192.0.2.1:9")


def test_dns_lookup_of_a_public_name_is_refused_at_once(request):
    started = time.monotonic()
    with pytest.raises(_network_guard.OutboundLookupRefused) as info:
        socket.getaddrinfo("imap.example.invalid", 443)
    assert time.monotonic() - started < 1.0
    assert isinstance(info.value, socket.gaierror)
    _assert_refusal(info.value, request, "imap.example.invalid:443")


@pytest.mark.parametrize("loop_factory", _LOOPS)
def test_asyncio_connect_to_a_non_loopback_address_is_refused_at_once(loop_factory, request):
    loop = loop_factory()
    try:
        started = time.monotonic()
        with pytest.raises(_network_guard.OutboundConnectRefused) as info:
            loop.run_until_complete(asyncio.wait_for(asyncio.open_connection(*_BLACK_HOLE), 5))
        assert time.monotonic() - started < 1.0
    finally:
        loop.close()
    _assert_refusal(info.value, request, "192.0.2.1:9")


def _serve_once(server: socket.socket) -> None:
    conn, _ = server.accept()
    with conn:
        conn.sendall(b"ok")


@pytest.fixture
def loopback_server():
    import threading

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    threads = []

    def serve(n: int = 1) -> int:
        for _ in range(n):
            t = threading.Thread(target=_serve_once, args=(server,), daemon=True)
            t.start()
            threads.append(t)
        return server.getsockname()[1]

    try:
        yield serve
    finally:
        server.close()
        for t in threads:
            t.join(timeout=2)


def test_sync_loopback_connect_still_works(loopback_server):
    port = loopback_server()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        assert sock.recv(2) == b"ok"


def test_localhost_and_ip_literal_lookups_still_work():
    assert socket.getaddrinfo("localhost", 80)
    assert socket.getaddrinfo("127.0.0.1", 80)
    # An IP literal is not a DNS query; the connect seam decides about the address.
    assert socket.getaddrinfo("192.0.2.1", 80)


@pytest.mark.parametrize("loop_factory", _LOOPS)
def test_asyncio_loopback_connect_still_works(loop_factory, loopback_server):
    port = loopback_server()

    async def fetch() -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            return await reader.readexactly(2)
        finally:
            writer.close()

    loop = loop_factory()
    try:
        assert loop.run_until_complete(asyncio.wait_for(fetch(), 5)) == b"ok"
    finally:
        loop.close()


def test_socketpair_still_works():
    a, b = socket.socketpair()
    with a, b:
        a.sendall(b"x")
        assert b.recv(1) == b"x"


@pytest.mark.allow_outbound_network(reason="teeth: the opt-out marker lifts the guard")
def test_the_opt_out_marker_lifts_the_guard():
    _network_guard.check_connect(socket.AF_INET, _BLACK_HOLE, "teeth")
    _network_guard.check_lookup("imap.example.invalid", 443)


def test_the_guard_is_back_after_an_opted_out_test():
    with pytest.raises(_network_guard.OutboundConnectRefused):
        _network_guard.check_connect(socket.AF_INET, _BLACK_HOLE, "teeth")
    with pytest.raises(_network_guard.OutboundLookupRefused):
        _network_guard.check_lookup("imap.example.invalid", 443)


# ---- the other DNS entry points and UDP sendto (panel X) --------------------------------------

def test_gethostbyname_of_a_public_name_is_refused(request):
    with pytest.raises(_network_guard.OutboundLookupRefused) as info:
        socket.gethostbyname("imap.example.invalid")
    _assert_refusal(info.value, request, "imap.example.invalid (socket.gethostbyname)")


def test_gethostbyname_ex_of_a_public_name_is_refused(request):
    with pytest.raises(_network_guard.OutboundLookupRefused) as info:
        socket.gethostbyname_ex("imap.example.invalid")
    _assert_refusal(info.value, request, "imap.example.invalid (socket.gethostbyname_ex)")


def test_gethostbyaddr_of_a_non_loopback_address_is_refused(request):
    """A reverse lookup of an IP literal is still a DNS query (PTR)."""
    with pytest.raises(_network_guard.OutboundLookupRefused) as info:
        socket.gethostbyaddr("192.0.2.1")
    _assert_refusal(info.value, request, "192.0.2.1 (socket.gethostbyaddr)")


def test_getfqdn_of_a_public_name_falls_back_without_a_query():
    """``getfqdn`` swallows the lookup error and returns the name it was given."""
    assert socket.getfqdn("imap.example.invalid") == "imap.example.invalid"


def test_getnameinfo_of_a_non_loopback_address_is_refused(request):
    with pytest.raises(_network_guard.OutboundLookupRefused) as info:
        socket.getnameinfo(("192.0.2.1", 80), 0)
    _assert_refusal(info.value, request, "192.0.2.1 (socket.getnameinfo)")


def test_numeric_getnameinfo_is_not_a_lookup():
    flags = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
    assert socket.getnameinfo(("192.0.2.1", 80), flags) == ("192.0.2.1", "80")


def test_udp_sendto_a_non_loopback_address_is_refused(request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(_network_guard.OutboundConnectRefused) as info:
            sock.sendto(b"x", _BLACK_HOLE)
        with pytest.raises(_network_guard.OutboundConnectRefused):
            sock.sendto(b"x", 0, _BLACK_HOLE)
    _assert_refusal(info.value, request, "192.0.2.1:9 (socket.sendto)")


def test_local_lookups_and_loopback_sendto_still_work():
    assert socket.gethostbyname("localhost")
    assert socket.gethostbyname("127.0.0.1") == "127.0.0.1"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(5)
        tx.sendto(b"x", rx.getsockname())
        assert rx.recv(1) == b"x"


# ---- a raw assignment that removes the guard fails loudly (db NOTE-3) -------------------------

def test_a_raw_seam_assignment_is_caught_and_repaired():
    saved = socket.gethostbyname
    socket.gethostbyname = _network_guard._ORIGINALS["gethostbyname"]  # what a raw assignment does
    try:
        assert not _network_guard.installed()
        with pytest.raises(_network_guard.GuardRemoved) as info:
            _network_guard.reassert_installed("tests/x.py::t")
        assert "socket.gethostbyname" in str(info.value)
        assert "tests/x.py::t" in str(info.value)
        assert _network_guard.installed()
    finally:
        socket.gethostbyname = saved
    assert _network_guard.installed()


def test_the_teardown_check_is_wired(request):
    guard = request.config.pluginmanager.get_plugin(_network_guard.PLUGIN_NAME)
    assert guard is not None
    impls = request.config.pluginmanager.hook.pytest_runtest_teardown.get_hookimpls()
    assert any(impl.plugin is guard for impl in impls)


@pytest.mark.parametrize("host, local", [
    ("127.0.0.1", True), ("127.8.9.10", True), ("::1", True), ("[::1]", True),
    ("::ffff:127.0.0.1", True), ("localhost", True), ("api.localhost", True),
    ("0.0.0.0", True), ("::", True),
    ("192.0.2.1", False), ("198.51.100.7", False), ("x.com", False), ("llm-host", False),
    ("::ffff:192.0.2.1", False), (None, False),
])
def test_what_counts_as_local(host, local):
    assert _network_guard.is_local_host(host) is local
