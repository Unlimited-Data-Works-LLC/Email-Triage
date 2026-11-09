"""Guard: no test reaches a non-loopback host.

Why this exists (t20, 2026-10-26). ``tests/test_web`` rendered the IMAP account edit page
against its fixture host ``x.com``, so each render resolved ``x.com`` in public DNS, opened a
real TCP connection to the internet on port 993, and waited out the 10 s handshake wait
(``tls.tls_connect_async``) and then the 10 s hello wait (``providers/imap.py`` ``_connect``):
seven tests at 20 s each on the main CI run of 56eb55b8. An operator script the tests import
probed an LLM host on the LAN at import time, from every xdist worker, during collection; two
tests reached a public LLM API and an identity provider. A test that depends on the network
is slow, and its result depends on what is reachable from the machine that runs it.

What it refuses, process-wide from ``pytest_configure`` on (collection, session fixtures, the
TestClient portal thread, ``to_thread`` workers, and a task that outlives its test):

* A forward lookup of a name that is not ``localhost`` and not an IP literal raises
  :class:`OutboundLookupRefused` (a ``socket.gaierror``, the class an unknown name raises):
  ``socket.getaddrinfo`` (also what ``loop.getaddrinfo`` calls), ``socket.gethostbyname`` and
  ``socket.gethostbyname_ex``.
* A reverse lookup of an address that is not loopback raises the same error, IP literal or
  not (a PTR query is a DNS query): ``socket.gethostbyaddr`` (what ``socket.getfqdn`` calls;
  ``getfqdn`` swallows the error and returns the name it was given) and
  ``socket.getnameinfo`` unless ``NI_NUMERICHOST`` is set.
* ``socket.socket.connect`` / ``connect_ex`` to a non-loopback address raises
  :class:`OutboundConnectRefused` (a ``ConnectionRefusedError``). This is the sync seam of
  ``socket.create_connection``, ``smtplib``, ``imaplib``, ``http.client`` / ``urllib``, sync
  ``httpx`` and ``ssl.SSLSocket``.
* ``socket.socket.sendto`` to a non-loopback address raises the same error: unconnected UDP
  (a hand-rolled DNS query such as dnspython's ``dns.query.udp``, and the selector loop's
  datagram transport and ``loop.sock_sendto``, which call it).
* ``sock_connect`` on the asyncio selector loop AND the proactor loop. Windows'
  ``ProactorEventLoop`` connects through ``ConnectEx`` and never calls ``socket.connect``, so
  the socket seam alone misses asyncio (and aioimaplib, async httpx, anyio) there.

Allowed: loopback (127.0.0.0/8, ::1, ``localhost``), the unspecified address, ``AF_UNIX`` and
``socket.socketpair``. A refusal is immediate and names the test and the address.

A seam overwritten by a raw assignment (not ``monkeypatch``, which restores it) would switch
the guard off for the rest of the worker without a sound; the teardown check puts the guard
back and fails the test that removed it (:class:`GuardRemoved`).

Opt-out: ``@pytest.mark.allow_outbound_network(reason="...")``; the reason is required
(``tests/test_network_guard_pin.py``). The only holders are the two manual live-integration
tests that skip unless an env var names a live host (``test_cache/test_classification_redis.py``,
``test_topic_recall_harness.py``); no test in a default run needs one.

SCOPE CAVEAT (what a green run does NOT prove): only the Python-level seams above are hooked.
A subprocess does not load this conftest, so a test that runs a child interpreter or a CLI
(``git``, ``curl``) is not covered; nor is a C extension that resolves or opens its own
sockets (it calls the C resolver or ``_socket`` directly); nor a caller that imported a
function from ``_socket`` itself; nor ``socket.sendmsg``; nor the proactor loop's datagram
transport, which sends through ``WSASendTo`` without ``socket.sendto``. The test that the
guard refuses is ``tests/test_network_guard.py``; ``-p no:network-guard`` disables the guard
and turns that test red (the mutation check).
"""

from __future__ import annotations

import asyncio.proactor_events as _proactor_events
import asyncio.selector_events as _selector_events
import ipaddress
import socket

import pytest

PLUGIN_NAME = "network-guard"
MARKER = "allow_outbound_network"


class OutboundConnectRefused(ConnectionRefusedError):
    """A test tried to connect to a non-loopback address."""


class OutboundLookupRefused(socket.gaierror):
    """A test tried to resolve a non-local name, or to reverse-resolve a non-loopback
    address."""


class GuardRemoved(AssertionError):
    """A test left a seam without the guard's wrapper (a raw assignment)."""


class _State:
    """Which test is running, and whether it opted out. Module state, not a contextvar: the
    connect can run on the TestClient portal thread or a ``to_thread`` worker."""

    nodeid = "<collection or session setup>"
    allowed = False


_ORIGINALS: dict[str, object] = {}


def is_local_host(host: object) -> bool:
    """True for ``localhost`` (and ``*.localhost``), a loopback IP literal, or the unspecified
    address. Any other name is not local: deciding would take a DNS query."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    name = host.strip("[]").split("%", 1)[0].lower()
    if name in ("localhost", "") or name.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_unspecified


def _is_ip_literal(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    try:
        ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


def is_local_address(family: int, address: object) -> bool:
    """True when a connect to ``address`` stays on this machine."""
    if family == getattr(socket, "AF_UNIX", None) or isinstance(address, (str, bytes)):
        return True
    return isinstance(address, tuple) and bool(address) and is_local_host(address[0])


def _where(address: object) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        if address[1] is None:
            return str(address[0])
        return f"{address[0]}:{address[1]}"
    return repr(address)


def _refusal(seam: str, address: object) -> str:
    return (f"outbound network refused in tests: {_State.nodeid} -> {_where(address)} "
            f"({seam}). A test must not reach a non-loopback host: stub the client or "
            f"provider, or serve it on 127.0.0.1 (tests/_network_guard.py).")


def check_connect(family: int, address: object, seam: str) -> None:
    """Raise :class:`OutboundConnectRefused` unless the connect stays local or the running
    test opted out."""
    if not _State.allowed and not is_local_address(family, address):
        raise OutboundConnectRefused(_refusal(seam, address))


def _lookup_refused(host: object, port: object, seam: str) -> OutboundLookupRefused:
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    return OutboundLookupRefused(socket.EAI_NONAME, _refusal(seam, (name, port)))


def check_lookup(host: object, port: object, seam: str = "socket.getaddrinfo") -> None:
    """Raise :class:`OutboundLookupRefused` for a name that would need DNS, unless the
    running test opted out."""
    if _State.allowed or host is None or is_local_host(host) or _is_ip_literal(host):
        return
    raise _lookup_refused(host, port, seam)


def check_reverse_lookup(host: object, seam: str) -> None:
    """Raise :class:`OutboundLookupRefused` for a reverse lookup of anything but a loopback
    address or ``localhost``, unless the running test opted out. An IP literal is NOT a pass
    here: resolving it to a name is a PTR query."""
    if _State.allowed or is_local_host(host):
        return
    raise _lookup_refused(host, None, seam)


def _connect(self, address):
    check_connect(self.family, address, "socket.connect")
    return _ORIGINALS["connect"](self, address)


def _connect_ex(self, address):
    check_connect(self.family, address, "socket.connect_ex")
    return _ORIGINALS["connect_ex"](self, address)


def _sendto(self, data, *args):
    if args:  # sendto(data, address) or sendto(data, flags, address)
        check_connect(self.family, args[-1], "socket.sendto")
    return _ORIGINALS["sendto"](self, data, *args)


def _getaddrinfo(host, port, *args, **kwargs):
    check_lookup(host, port)
    return _ORIGINALS["getaddrinfo"](host, port, *args, **kwargs)


def _gethostbyname(hostname):
    check_lookup(hostname, None, "socket.gethostbyname")
    return _ORIGINALS["gethostbyname"](hostname)


def _gethostbyname_ex(hostname):
    check_lookup(hostname, None, "socket.gethostbyname_ex")
    return _ORIGINALS["gethostbyname_ex"](hostname)


def _gethostbyaddr(ip_address):
    check_reverse_lookup(ip_address, "socket.gethostbyaddr")
    return _ORIGINALS["gethostbyaddr"](ip_address)


def _getnameinfo(sockaddr, flags):
    if not flags & socket.NI_NUMERICHOST:
        host = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
        check_reverse_lookup(host, "socket.getnameinfo")
    return _ORIGINALS["getnameinfo"](sockaddr, flags)


async def _selector_sock_connect(self, sock, address):
    check_connect(sock.family, address, "selector loop sock_connect")
    return await _ORIGINALS["selector_sock_connect"](self, sock, address)


async def _proactor_sock_connect(self, sock, address):
    check_connect(sock.family, address, "proactor loop sock_connect")
    return await _ORIGINALS["proactor_sock_connect"](self, sock, address)


#: Every seam the guard holds: (``_ORIGINALS`` key, owner, attribute, wrapper). The one list
#: that installing, :func:`installed` and the teardown check all read.
_SEAMS = (
    ("connect", socket.socket, "connect", _connect),
    ("connect_ex", socket.socket, "connect_ex", _connect_ex),
    ("sendto", socket.socket, "sendto", _sendto),
    ("getaddrinfo", socket, "getaddrinfo", _getaddrinfo),
    ("gethostbyname", socket, "gethostbyname", _gethostbyname),
    ("gethostbyname_ex", socket, "gethostbyname_ex", _gethostbyname_ex),
    ("gethostbyaddr", socket, "gethostbyaddr", _gethostbyaddr),
    ("getnameinfo", socket, "getnameinfo", _getnameinfo),
    ("selector_sock_connect", _selector_events.BaseSelectorEventLoop, "sock_connect",
     _selector_sock_connect),
    ("proactor_sock_connect", _proactor_events.BaseProactorEventLoop, "sock_connect",
     _proactor_sock_connect),
)


def _seam_name(owner: object, attr: str) -> str:
    if isinstance(owner, type):
        return f"{owner.__module__}.{owner.__qualname__}.{attr}"
    return f"{owner.__name__}.{attr}"


def _patch() -> None:
    for _key, owner, attr, wrapper in _SEAMS:
        setattr(owner, attr, wrapper)


def _install() -> None:
    """Patch the seams once per process."""
    if _ORIGINALS:
        return
    _ORIGINALS.update({key: getattr(owner, attr) for key, owner, attr, _w in _SEAMS})
    _patch()


def installed() -> bool:
    """True while every seam holds the guard's wrapper."""
    return all(getattr(owner, attr) is wrapper for _key, owner, attr, wrapper in _SEAMS)


def reassert_installed(nodeid: str | None = None) -> None:
    """Raise :class:`GuardRemoved` if a seam lost the guard's wrapper (db NOTE-3), after
    putting the wrapper back so the tests that follow are guarded again."""
    if not _ORIGINALS:
        return
    removed = [_seam_name(owner, attr) for _key, owner, attr, wrapper in _SEAMS
               if getattr(owner, attr) is not wrapper]
    if not removed:
        return
    _patch()
    raise GuardRemoved(
        f"the network guard was removed from {', '.join(removed)} during "
        f"{nodeid or _State.nodeid} and has been put back. Override a socket seam with "
        f"monkeypatch, which restores it; never a raw assignment (tests/_network_guard.py).")


class _Guard:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item, nextitem):
        _State.nodeid = item.nodeid
        _State.allowed = item.get_closest_marker(MARKER) is not None
        try:
            yield
        finally:
            _State.nodeid = f"<between tests, after {item.nodeid}>"
            _State.allowed = False

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_teardown(self, item, nextitem):
        # After the fixtures' own teardown (monkeypatch has restored what it patched), so a
        # seam still unwrapped was overwritten for good: an ERROR on the test that did it.
        reassert_installed(item.nodeid)


def register(config: pytest.Config) -> None:
    """Idempotent: register the marker, and the guard unless ``-p no:network-guard``
    blocks it (called from ``pytest_configure``)."""
    config.addinivalue_line(
        "markers",
        f"{MARKER}(reason): let this test connect to a non-loopback host or resolve a "
        "non-local name (tests/_network_guard.py). The reason is required.",
    )
    if config.pluginmanager.is_blocked(PLUGIN_NAME):
        return
    if not config.pluginmanager.has_plugin(PLUGIN_NAME):
        config.pluginmanager.register(_Guard(), PLUGIN_NAME)
    _install()
