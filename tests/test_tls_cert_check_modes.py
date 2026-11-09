"""Operator certificate-check modes (2026-10-21): behaviour on real TLS sockets.

Three modes, on IMAP (implicit TLS, sync and async), SMTP (STARTTLS) and HTTPS
egress (httpx and requests), against a loopback server presenting a self-signed
certificate (``email_triage.tls.generate_self_signed_cert``):

* ``cert_check`` off: connects; no verification, no log;
* ``cert_check`` on + ``cert_enforce`` off: the verifying handshake fails, ONE
  ``tls_cert_check_failed`` WARNING is logged (host, port, protocol, error
  class, setting; no PHI, no secret), and the connection goes ahead unverified;
* ``cert_check`` on + ``cert_enforce`` on: the connection is refused with an
  error that names the host.

Plus the verified path (the test CA trusted), the per-account / SMTP override
resolution, and that none of the settings is refused at config load.
"""

from __future__ import annotations

import asyncio
import email.message
import http.server
import socket
import socketserver
import ssl
import threading

import pytest

from email_triage import tls
from email_triage.tls import CertCheckRefused, CertPolicy

HOST = "127.0.0.1"
OFF = CertPolicy(check=False, enforce=False, source="test")
VALIDATE = CertPolicy(check=True, enforce=False, source="test")
ENFORCE = CertPolicy(check=True, enforce=True, source="test")


# ---- fixtures ----------------------------------------------------------------

@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    cert_pem, key_pem = tls.generate_self_signed_cert("localhost")
    (d / "c.pem").write_bytes(cert_pem)
    (d / "k.pem").write_bytes(key_pem)
    return str(d / "c.pem"), str(d / "k.pem")


@pytest.fixture
def server_ctx(cert_files):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert_files)
    return ctx


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(tls, "_bound_config", None)
    monkeypatch.setattr(tls, "_cert_log_last", {})
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
              "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
              "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(k, raising=False)


class _Rec:
    def __init__(self):
        self.events = []

    def warning(self, msg, **kw):
        self.events.append((msg, kw))


@pytest.fixture
def rec(monkeypatch):
    r = _Rec()
    monkeypatch.setattr(tls, "_logger", lambda: r)
    return r


@pytest.fixture
def trust_test_ca(monkeypatch, cert_files):
    """Make the verifying context trust the test certificate (the verified path)."""
    real = tls.client_tls_context

    def _ctx(*, cafile=None, capath=None):
        return real(cafile=cert_files[0])
    monkeypatch.setattr(tls, "client_tls_context", _ctx)


def _serve(handler_factory):
    """A threaded loopback TCP server; returns (port, stop)."""
    srv = socketserver.ThreadingTCPServer((HOST, 0), handler_factory)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    def stop():
        srv.shutdown()
        srv.server_close()
    return srv.server_address[1], stop


def _imap_handler(server_ctx):
    class H(socketserver.StreamRequestHandler):
        def setup(self):
            try:
                self.request = server_ctx.wrap_socket(self.request, server_side=True)
            except (ssl.SSLError, OSError):
                self.request = None
                return
            super().setup()

        def handle(self):
            if self.request is None:
                return
            try:
                self.wfile.write(b"* OK test IMAP ready\r\n")
                for raw in self.rfile:
                    tag, _, cmd = raw.decode().strip().partition(" ")
                    cmd = cmd.upper()
                    if cmd.startswith("CAPABILITY"):
                        self.wfile.write(b"* CAPABILITY IMAP4rev1\r\n")
                    if cmd.startswith("LOGOUT"):
                        self.wfile.write(b"* BYE\r\n" + tag.encode() + b" OK bye\r\n")
                        return
                    self.wfile.write(tag.encode() + b" OK done\r\n")
            except (ssl.SSLError, OSError):
                return

        def finish(self):
            if self.request is not None:
                try:
                    super().finish()
                except (ssl.SSLError, OSError):
                    pass
    return H


def _smtp_handler(server_ctx, received):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            f = sock.makefile("rwb")
            try:
                f.write(b"220 test ESMTP\r\n")
                f.flush()
                tls_on = False
                in_data = False
                while True:
                    raw = f.readline()  # f is rebound after STARTTLS
                    if not raw:
                        return
                    line = raw.decode().strip()
                    if in_data:
                        if line == ".":
                            in_data = False
                            received.append("message")
                            f.write(b"250 queued\r\n")
                        f.flush()
                        continue
                    up = line.upper()
                    if up.startswith("EHLO"):
                        f.write(b"250-test\r\n250 STARTTLS\r\n" if not tls_on else b"250 test\r\n")
                    elif up == "STARTTLS":
                        f.write(b"220 go ahead\r\n")
                        f.flush()
                        try:
                            sock = server_ctx.wrap_socket(sock, server_side=True)
                        except (ssl.SSLError, OSError):
                            return
                        f = sock.makefile("rwb")
                        tls_on = True
                        continue
                    elif up.startswith("DATA"):
                        in_data = True
                        f.write(b"354 go\r\n")
                    elif up.startswith("QUIT"):
                        f.write(b"221 bye\r\n")
                        f.flush()
                        return
                    else:
                        f.write(b"250 ok\r\n")
                    f.flush()
            except (ssl.SSLError, OSError):
                return
    return H


def _https_server(server_ctx):
    class Q(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

        def get_request(self):
            sock, addr = self.socket.accept()
            return server_ctx.wrap_socket(sock, server_side=True), addr

        def handle_error(self, request, client_address):
            pass

    srv = S((HOST, 0), Q)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        srv.shutdown()
        srv.server_close()
    return srv.server_address[1], stop


def _assert_one_event(rec, *, protocol, action, port):
    events = [kw for _m, kw in rec.events if kw.get("event") == "tls_cert_check_failed"]
    assert len(events) == 1, rec.events
    ev = events[0]
    assert ev["host"] == HOST and ev["port"] == port
    assert ev["protocol"] == protocol and ev["action"] == action
    assert ev["error_class"] == "SSLCertVerificationError"
    assert ev["setting"] == "test"
    return ev


# ---- IMAP (sync, the imap_blocking fetch + dispatcher probe path) --------------

@pytest.fixture
def imap_port(server_ctx):
    port, stop = _serve(_imap_handler(server_ctx))
    yield port
    stop()


def test_imap_check_off_connects_unverified_and_logs_nothing(imap_port, rec):
    from email_triage.providers.imap_fetch_transport import imap_connect

    c = imap_connect(HOST, imap_port, cert_policy=OFF)
    assert c._et_cert_verdict == "unchecked"
    c.logout()
    assert rec.events == []


def test_imap_validate_logs_once_then_connects(imap_port, rec):
    from email_triage.providers.imap_fetch_transport import imap_connect

    for _ in range(3):  # three fetches, ONE log event (dedupe)
        c = imap_connect(HOST, imap_port, cert_policy=VALIDATE)
        assert c._et_cert_verdict == "failed"
        c.logout()
    _assert_one_event(rec, protocol="imap", action="connected_unverified", port=imap_port)


def test_imap_enforce_refuses_naming_the_host(imap_port, rec):
    from email_triage.providers.imap_fetch_transport import imap_connect

    with pytest.raises(CertCheckRefused) as ei:
        imap_connect(HOST, imap_port, cert_policy=ENFORCE)
    assert f"{HOST}:{imap_port}" in str(ei.value)
    assert "CERTIFICATE_VERIFY_FAILED" in str(ei.value)
    assert isinstance(ei.value, ssl.SSLCertVerificationError)
    _assert_one_event(rec, protocol="imap", action="refused", port=imap_port)


def test_imap_verified_path(imap_port, rec, trust_test_ca):
    from email_triage.providers.imap_fetch_transport import imap_connect

    c = imap_connect(HOST, imap_port, cert_policy=ENFORCE)
    assert c._et_cert_verdict == "verified"
    c.logout()
    assert rec.events == []


# ---- IMAP (async, aioimaplib: the provider connection and IDLE) ----------------

def _aio(port, policy, *, hello=True):
    from email_triage.providers.imap_fetch_transport import aioimaplib_connect

    async def go():
        c = await aioimaplib_connect(HOST, port, cert_policy=policy)
        if hello:
            await c.wait_hello_from_server()
            await c.logout()
        return c
    return asyncio.run(go())


def test_aioimaplib_off_connects(imap_port, rec):
    _aio(imap_port, OFF)
    assert rec.events == []


def test_aioimaplib_validate_logs_then_connects(imap_port, rec):
    _aio(imap_port, VALIDATE)
    _assert_one_event(rec, protocol="imap", action="connected_unverified", port=imap_port)


def test_aioimaplib_enforce_refuses(imap_port, rec):
    with pytest.raises(CertCheckRefused) as ei:
        _aio(imap_port, ENFORCE)
    assert f"{HOST}:{imap_port}" in str(ei.value)
    _assert_one_event(rec, protocol="imap", action="refused", port=imap_port)


def test_aioimaplib_verified(imap_port, rec, trust_test_ca):
    _aio(imap_port, ENFORCE)
    assert rec.events == []


def test_aioimaplib_unreachable_returns_the_verifying_client(rec):
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens: a connection error, not a certificate error
    c = _aio(port, ENFORCE, hello=False)
    assert c is not None
    assert rec.events == []


def test_slow_handshake_still_logs_a_late_certificate_failure(rec):
    """Panel M M-DA-7: the handshake outlives the wait, then fails verification.
    The client is returned (its own hello reports the failure) and the failure
    is still logged, from a done-callback on the shielded handshake."""
    seen = {}

    async def go():
        fut = asyncio.get_running_loop().create_future()
        client = type("C", (), {})()
        client._client_task = fut
        got = await tls.tls_connect_async(
            lambda ctx: client, host=HOST, port=993, protocol="imap",
            policy=VALIDATE, handshake=lambda c: c._client_task, timeout=0.05,
        )
        seen["same"] = got is client
        seen["before"] = list(rec.events)
        fut.set_exception(ssl.SSLCertVerificationError(
            1, "certificate verify failed: self-signed certificate"))
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(go())
    assert seen["same"] and seen["before"] == []
    _assert_one_event(rec, protocol="imap", action="failed_after_handshake_wait", port=993)


def test_slow_handshake_that_succeeds_logs_nothing(rec):
    async def go():
        fut = asyncio.get_running_loop().create_future()
        client = type("C", (), {})()
        await tls.tls_connect_async(
            lambda ctx: client, host=HOST, port=993, protocol="imap",
            policy=VALIDATE, handshake=lambda c: fut, timeout=0.05,
        )
        fut.set_result(("transport", "protocol"))
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(go())
    assert rec.events == []


def test_a_cancelled_handshake_wait_still_logs_a_late_certificate_failure(rec):
    """Panel X db SHOULD-1: a render-probe bound CANCELS the handshake wait instead of timing
    it out. The handshake (shielded) keeps running and later fails verification; that failure
    is still logged, and the cancellation reaches the caller."""

    async def go():
        fut = asyncio.get_running_loop().create_future()
        client = type("C", (), {})()
        waiter = asyncio.ensure_future(tls.tls_connect_async(
            lambda ctx: client, host=HOST, port=993, protocol="imap",
            policy=VALIDATE, handshake=lambda c: fut, timeout=5.0,
        ))
        await asyncio.sleep(0.01)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not fut.cancelled()
        fut.set_exception(ssl.SSLCertVerificationError(
            1, "certificate verify failed: self-signed certificate"))
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(go())
    _assert_one_event(rec, protocol="imap", action="failed_after_handshake_wait", port=993)


def test_a_cancelled_handshake_wait_discards_the_client(rec):
    """Panel X db SHOULD-2 (i): the cancelled caller never receives the client, so
    ``tls_connect_async`` hands it to the caller's ``discard`` (aioimaplib: close the
    transport once the connection task lands)."""
    discarded = []

    async def go():
        fut = asyncio.get_running_loop().create_future()
        client = type("C", (), {})()
        waiter = asyncio.ensure_future(tls.tls_connect_async(
            lambda ctx: client, host=HOST, port=993, protocol="imap",
            policy=VALIDATE, handshake=lambda c: fut, timeout=5.0,
            discard=discarded.append,
        ))
        await asyncio.sleep(0.01)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        fut.set_result(("transport", "protocol"))
        return client

    client = asyncio.run(go())
    assert discarded == [client]
    assert rec.events == []


def test_aioimaplib_still_has_the_connection_task():
    """The verdict is read from aioimaplib's own connection task; if a release
    renames it, this fails instead of the mode silently losing its verdict."""
    import inspect

    import aioimaplib

    assert "_client_task" in inspect.getsource(aioimaplib.IMAP4.create_client)


# ---- the greeting wait shares the connect's budget (t20) --------------------

class _FakeClient:
    """An aioimaplib client whose connection task and greeting the test drives."""

    def __init__(self, task, hello_after=None):
        self._client_task = task
        self._hello_after = hello_after

    async def wait_hello_from_server(self):
        if self._hello_after is None:
            await asyncio.get_running_loop().create_future()  # never greets
        await asyncio.sleep(self._hello_after)


def test_a_failed_connection_raises_its_own_error_at_once():
    """Before t20 the greeting waited out its whole timeout and reported a
    timeout; the refused connection itself was never seen."""
    from email_triage.providers.imap_fetch_transport import aioimaplib_wait_hello

    async def go():
        loop = asyncio.get_running_loop()
        task = loop.create_future()
        task.set_exception(ConnectionRefusedError("refused"))
        started = loop.time()
        with pytest.raises(ConnectionRefusedError):
            await aioimaplib_wait_hello(_FakeClient(task), started=started, timeout=10.0)
        return loop.time() - started

    assert asyncio.run(go()) < 1.0


def test_the_greeting_gets_only_what_is_left_of_the_budget():
    """An unreachable server cost the handshake wait plus a full greeting wait
    (10 s + 10 s); the greeting now gets the remainder of one budget."""
    from email_triage.providers.imap_fetch_transport import aioimaplib_wait_hello

    async def go():
        loop = asyncio.get_running_loop()
        task = loop.create_future()  # the connect never completes
        spent = 0.4
        started = loop.time() - spent
        with pytest.raises(asyncio.TimeoutError):
            await aioimaplib_wait_hello(_FakeClient(task), started=started, timeout=0.5)
        return loop.time() - (started + spent)

    assert asyncio.run(go()) < 0.4


def test_a_greeting_inside_the_budget_still_succeeds():
    from email_triage.providers.imap_fetch_transport import aioimaplib_wait_hello

    async def go():
        loop = asyncio.get_running_loop()
        task = loop.create_future()
        loop.call_later(0.02, task.set_result, ("transport", "protocol"))
        await aioimaplib_wait_hello(_FakeClient(task, hello_after=0.05),
                                    started=loop.time(), timeout=2.0)

    asyncio.run(go())


def test_a_late_certificate_failure_reaches_the_caller_and_is_logged_once(rec):
    """Panel M M-DA-7 with the shared budget: the handshake outlives the
    handshake wait, then fails verification inside the greeting wait. The caller
    gets the certificate error (not a timeout) and the done-callback logs it once."""
    from email_triage.providers.imap_fetch_transport import aioimaplib_wait_hello

    async def go():
        loop = asyncio.get_running_loop()
        task = loop.create_future()
        client = _FakeClient(task)
        started = loop.time()
        got = await tls.tls_connect_async(
            lambda ctx: client, host=HOST, port=993, protocol="imap",
            policy=VALIDATE, handshake=lambda c: c._client_task, timeout=0.05,
        )
        assert got is client
        loop.call_later(0.05, task.set_exception, ssl.SSLCertVerificationError(
            1, "certificate verify failed: self-signed certificate"))
        with pytest.raises(ssl.SSLCertVerificationError):
            await aioimaplib_wait_hello(client, started=started, timeout=2.0)
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(go())
    _assert_one_event(rec, protocol="imap", action="failed_after_handshake_wait", port=993)


# ---- SMTP STARTTLS ----------------------------------------------------------

@pytest.fixture
def smtp(server_ctx):
    received: list[str] = []
    port, stop = _serve(_smtp_handler(server_ctx, received))
    yield port, received
    stop()


def _send(port, policy):
    from email_triage.web.smtp_send import send_smtp_message

    # EGRESS-OK: delivered to the in-process loopback fake SMTP server on
    # 127.0.0.1 above; nothing leaves the host. Reserved .invalid addresses.
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.invalid"
    msg["To"] = "rcpt@example.invalid"
    msg["Subject"] = "t"
    msg.set_content("x")
    send_smtp_message(msg, smtp_host=HOST, smtp_port=port, use_tls=True,
                      smtp_timeout_secs=10, cert_policy=policy)


def test_smtp_check_off_sends(smtp, rec):
    port, received = smtp
    _send(port, OFF)
    assert received == ["message"]
    assert rec.events == []


def test_smtp_validate_logs_then_sends_on_a_fresh_connection(smtp, rec):
    port, received = smtp
    _send(port, VALIDATE)
    assert received == ["message"]
    _assert_one_event(rec, protocol="smtp-starttls", action="connected_unverified", port=port)


def test_smtp_enforce_refuses_before_any_message(smtp, rec):
    port, received = smtp
    with pytest.raises(CertCheckRefused) as ei:
        _send(port, ENFORCE)
    assert f"{HOST}:{port}" in str(ei.value)
    assert received == []
    _assert_one_event(rec, protocol="smtp-starttls", action="refused", port=port)


def test_smtp_verified_path(smtp, rec, trust_test_ca):
    port, received = smtp
    _send(port, ENFORCE)
    assert received == ["message"]
    assert rec.events == []


def test_smtp_section_override_resolves_over_global(monkeypatch):
    from email_triage.config import OutboundTLSConfig, TriageConfig

    cfg = TriageConfig()
    cfg.outbound_tls = OutboundTLSConfig(cert_check=True, cert_enforce=True)
    cfg.smtp.cert_enforce = False
    monkeypatch.setattr(tls, "_bound_config", cfg)
    assert tls.current_cert_policy() == CertPolicy(True, True, "outbound_tls")
    assert tls.current_cert_policy("smtp") == CertPolicy(True, False, "smtp")


# ---- HTTPS egress -------------------------------------------------------------

@pytest.fixture
def https_port(server_ctx):
    port, stop = _https_server(server_ctx)
    yield port
    stop()


def _bind_mode(monkeypatch, *, check, enforce, **extra):
    from email_triage.config import OutboundTLSConfig, TriageConfig

    cfg = TriageConfig()
    cfg.outbound_tls = OutboundTLSConfig(cert_check=check, cert_enforce=enforce, **extra)
    monkeypatch.setattr(tls, "_bound_config", cfg)


@pytest.mark.parametrize("check,enforce,outcome", [
    (False, False, "ok"), (True, False, "ok-logged"), (True, True, "refused"),
])
def test_httpx_egress_modes(monkeypatch, rec, https_port, check, enforce, outcome):
    import httpx

    from email_triage._egress import Intent, egress_client

    _bind_mode(monkeypatch, check=check, enforce=enforce)
    url = f"https://{HOST}:{https_port}/"
    with egress_client(intent=Intent.LOCAL_ONLY, timeout=10) as c:
        if outcome == "refused":
            with pytest.raises(httpx.ConnectError) as ei:
                c.get(url)
            assert f"{HOST}:{https_port}" in str(ei.value)
        else:
            assert c.get(url).text == "ok"
    events = [kw for _m, kw in rec.events if kw.get("event") == "tls_cert_check_failed"]
    assert len(events) == (0 if outcome == "ok" else 1)
    if events:
        assert events[0]["protocol"] == "https/local_only"
        assert events[0]["setting"] == "outbound_tls"


def test_httpx_async_egress_validate_logs_then_connects(monkeypatch, rec, https_port):
    from email_triage._egress import Intent, egress_async_client

    _bind_mode(monkeypatch, check=True, enforce=False)

    async def go():
        async with egress_async_client(intent=Intent.LOCAL_ONLY, timeout=10) as c:
            return (await c.get(f"https://{HOST}:{https_port}/")).text
    assert asyncio.run(go()) == "ok"
    assert len([1 for _m, kw in rec.events if kw.get("event") == "tls_cert_check_failed"]) == 1


def test_httpx_caller_verify_false_is_kept(monkeypatch, rec, https_port):
    # The CLI's own operator flags (--insecure, the loopback ops trigger) pass
    # verify=False; the mode never overrides a caller's explicit choice.
    from email_triage._egress import Intent, egress_client

    _bind_mode(monkeypatch, check=True, enforce=True)
    insecure = False
    with egress_client(intent=Intent.LOCAL_ONLY, verify=insecure, timeout=10) as c:
        assert c.get(f"https://{HOST}:{https_port}/").text == "ok"
    assert rec.events == []


@pytest.mark.parametrize("check,enforce,outcome", [
    (False, False, "ok"), (True, False, "ok-logged"), (True, True, "refused"),
])
def test_requests_session_modes(monkeypatch, rec, https_port, check, enforce, outcome):
    import requests

    from email_triage._egress import egress_requests_session

    _bind_mode(monkeypatch, check=check, enforce=enforce)
    s = egress_requests_session()
    url = f"https://{HOST}:{https_port}/"
    if outcome == "refused":
        with pytest.raises(requests.exceptions.SSLError) as ei:
            s.get(url, timeout=10)
        assert f"{HOST}:{https_port}" in str(ei.value)
    else:
        assert s.get(url, timeout=10).text == "ok"
    events = [kw for _m, kw in rec.events if kw.get("event") == "tls_cert_check_failed"]
    assert len(events) == (0 if outcome == "ok" else 1)


def test_proxy_resolution_config_over_env(monkeypatch):
    from email_triage._egress import EgressTrust, proxy_for, resolve_egress_trust

    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy:3128")
    monkeypatch.setenv("NO_PROXY", "internal.example")
    assert proxy_for("https://api.example/", resolve_egress_trust()) == "http://env-proxy:3128"
    assert proxy_for("https://internal.example/", resolve_egress_trust()) is None
    _bind_mode(monkeypatch, check=True, enforce=False, proxy_url="http://cfg.invalid:8080")
    assert proxy_for("https://api.example/", resolve_egress_trust()) == "http://cfg.invalid:8080"
    _bind_mode(monkeypatch, check=True, enforce=False, ignore_env=True)
    assert proxy_for("https://api.example/", resolve_egress_trust()) is None
    assert resolve_egress_trust() == EgressTrust(trust_env=False, source="ignore_env")


def test_ca_bundle_env_then_config(monkeypatch, tmp_path):
    from email_triage._egress import resolve_egress_trust

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/env/ca.pem")
    assert resolve_egress_trust().cafile == "/env/ca.pem"
    _bind_mode(monkeypatch, check=True, enforce=False, ca_bundle=str(tmp_path))
    t = resolve_egress_trust()
    assert t.capath == str(tmp_path) and t.cafile is None


def test_unreadable_ca_bundle_falls_back_and_logs(rec):
    ctx = tls.client_tls_context(cafile="/nonexistent/ca.pem")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert [kw["event"] for _m, kw in rec.events] == ["tls_ca_bundle_unreadable"]


# ---- resolution and config load ---------------------------------------------

def test_default_is_validate_and_refuse():
    # Panel M H6 (2026-10-22): the secure default; every mode is still reachable.
    from email_triage.config import OutboundTLSConfig

    assert tls.current_cert_policy() == CertPolicy(True, True, "default")
    assert (OutboundTLSConfig().cert_check, OutboundTLSConfig().cert_enforce) == (True, True)


def test_account_override_tristate():
    assert tls.resolve_cert_policy({}) == CertPolicy(True, True, "default")
    assert tls.resolve_cert_policy({"cert_check": "inherit"}) == CertPolicy(True, True, "default")
    assert tls.resolve_cert_policy({"cert_check": "off"}) == CertPolicy(False, True, "account")
    assert tls.resolve_cert_policy({"cert_enforce": True}) == CertPolicy(True, True, "account")
    assert tls.resolve_cert_policy({"cert_enforce": "off"}) == CertPolicy(True, False, "account")
    assert tls.resolve_cert_policy({"cert_check": "garbage"}) == CertPolicy(True, True, "default")


def test_config_load_never_refuses(tmp_path):
    from email_triage.config import load_config

    p = tmp_path / "c.yaml"
    p.write_text(
        "persistence:\n  encryption_enabled: false\n"
        "outbound_tls:\n  cert_check: maybe\n  cert_enforce: 7\n  ca_bundle: /no/such\n"
        "smtp:\n  cert_check: nonsense\n",
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg.outbound_tls.cert_check is True and cfg.outbound_tls.cert_enforce is True
    assert cfg.smtp.cert_check is None
    assert tls.bound_config() is cfg


@pytest.mark.parametrize("factory", ["HTTPTransport", "AsyncHTTPTransport"])
@pytest.mark.parametrize("leg", ["verified", "caller"])
def test_ignore_env_reaches_the_leg_transports_ca_store(monkeypatch, cert_files, factory, leg):
    """M-DA-6 (panel M): ``outbound_tls.ignore_env`` must stop SSL_CERT_FILE from
    choosing the CA store on every leg. The leg transport's own trust_env used to
    default to True, so httpx read the env bundle even with ignore_env set. With
    env honoured, the env bundle must still choose the store (A3)."""
    import httpx

    from email_triage._egress import Intent, _ModeLegs, resolve_egress_trust

    for var in ("SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", cert_files[0])  # a one-certificate bundle

    def store_size(**extra):
        _bind_mode(monkeypatch, check=True, enforce=False, **extra)
        legs = _ModeLegs(getattr(httpx, factory), intent=Intent.PUBLIC_FETCH,
                         caller_verify=True, transport_kwargs={})
        t = legs.inner(None, leg, resolve_egress_trust())
        return t._pool._ssl_context.cert_store_stats()["x509"]

    assert store_size(ignore_env=True) > 1  # the default store, not the env bundle
    assert store_size() == 1  # env honoured: the env bundle chose the store
