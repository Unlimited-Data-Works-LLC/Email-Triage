"""Punch 776 (a): every verifying egress context judges the presented chain against
``DENIED_SPKI_SHA256`` after the handshake, and refuses (fail closed, no fallback).

77fb1fd9 put the deny list into the BUILD (``scripts/check_distrusted_spki.py`` scans the
image's trust stores). It did nothing at runtime: a server whose chain holds one of the
distrusted Entrust intermediates, reached through a bundle the scan never saw, connected.
``tls.guard_verifying_context`` closes that for every client that gets a verifying context
from ``email_triage.tls`` (IMAP, SMTP, the connection probe), the httpx default-store leg
and the requests adapter in ``_egress.py``.

TEETH. Real loopback TLS: a generated root -> intermediate -> leaf chain served on
127.0.0.1, the root trusted through the client's own bundle. A generated key stands in
for the distrusted one: the test adds its SPKI hash to the live deny dict (monkeypatch),
so the chain, the verification and the refusal are all real.

  * POSITIVE CONTROL on every path: the clean chain connects and answers.
  * the denied key refuses, whichever certificate of the chain carries it;
  * the refusal is not retried unverified (policy: check on, enforce off, where a
    certificate failure WOULD fall back) and is not a ``SSLCertVerificationError``;
  * the same holds for sockets, asyncio (memory BIO), httpx and requests;
  * STRUCTURAL: no verifying context is built in ``src/email_triage`` without
    ``guard_verifying_context``.

CYCLE P FOLD (DA P4 items 1-5). Contexts the guard never saw: a caller's own httpx
``verify=`` (context or CA path), a caller's own IMAP ``ssl_context``, and the context
redis-py builds itself for ``rediss://``. Each is now guarded and refuses a denied chain
here on a real handshake. The context-builder pin above sees only contexts OUR code
builds, so a second census pin walks every TLS CLIENT CONSTRUCTOR in src (``IMAP4_SSL``,
``SMTP_SSL``, ``starttls``, ``from_url``, ``urlopen``, ``build_opener`` ...) and requires
each to be handed a guarded context, so no library builds one of its own. The deny list
itself now ships inside the package (``email_triage/_distrusted_spki.py``): a copy of the
package with no ``scripts/`` beside it still loads it.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from _pin_harness import (
    assert_pin_has_teeth, enclosing_callable, enclosing_fn, parse_source, walk_src,
)
from email_triage import tls

HOST = "127.0.0.1"
DENIED_LABEL = "TEST denied intermediate (tls)"


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _spki_hash(cert) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _issue(subject_cn, subject_key, issuer_cn, issuer_key, *, ca, path_length=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                       critical=False)
    )
    if issuer_cn != subject_cn:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False)
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = (
            builder
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(HOST))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False, crl_sign=False,
                              encipher_only=False, decipher_only=False), critical=True)
        )
    return builder.sign(issuer_key, hashes.SHA256())


class _Pki:
    def __init__(self, tmp_path: Path) -> None:
        root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        self.root = _issue("T root", root_key, "T root", root_key, ca=True)
        self.intermediate = _issue("T mid", mid_key, "T root", root_key, ca=True, path_length=0)
        self.leaf = _issue("T leaf", leaf_key, "T mid", mid_key, ca=False)
        self.root_pem = tmp_path / "root.pem"
        self.root_pem.write_bytes(_pem(self.root))
        self.chain_pem = tmp_path / "chain.pem"
        self.chain_pem.write_bytes(_pem(self.leaf) + _pem(self.intermediate))
        self.key_pem = tmp_path / "leaf.key"
        self.key_pem.write_bytes(leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    def deny(self, monkeypatch, which: str) -> None:
        loader = getattr(tls, "_spki_denylist", None)
        if loader is None:
            return  # the tree before punch 776 has no runtime check: nothing to patch, and
            # the denied-chain tests then fail as "connected instead of refusing"
        tls._denied_label.cache_clear()
        monkeypatch.setitem(
            loader().DENIED_SPKI_SHA256, _spki_hash(getattr(self, which)), DENIED_LABEL)


@pytest.fixture
def pki(tmp_path):
    return _Pki(tmp_path)


def _clear_verdicts() -> None:
    cache = getattr(tls, "_denied_label", None)
    if cache is not None:
        cache.cache_clear()


@pytest.fixture(autouse=True)
def _fresh_verdicts():
    _clear_verdicts()
    yield
    _clear_verdicts()


@pytest.fixture
def server(pki):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki.chain_pem), str(pki.key_pem))
    srv = socket.socket()
    srv.bind((HOST, 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                raw, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            raw.settimeout(5)
            try:
                with ctx.wrap_socket(raw, server_side=True) as conn:
                    conn.recv(65536)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
            except (ssl.SSLError, OSError):
                raw.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
    thread.join(2)


def _trust_only(monkeypatch, pki) -> None:
    """Point every default-store path at the generated root and bind check on / enforce off,
    the mode where an ordinary certificate failure would fall back to unverified."""
    from email_triage.config import OutboundTLSConfig, TriageConfig

    for var in ("SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "HTTPS_PROXY",
                "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", HOST)
    monkeypatch.setenv("SSL_CERT_FILE", str(pki.root_pem))
    cfg = TriageConfig()
    cfg.outbound_tls = OutboundTLSConfig(cert_check=True, cert_enforce=False)
    monkeypatch.setattr(tls, "_bound_config", cfg)


def _socket_get(pki, port):
    ctx = tls.client_tls_context(cafile=str(pki.root_pem))
    with socket.create_connection((HOST, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            return conn.recv(4096)


# ---- sockets ------------------------------------------------------------------

def test_clean_chain_connects_positive_control(pki, server):
    assert _socket_get(pki, server).endswith(b"ok")


@pytest.mark.parametrize("which", ["leaf", "intermediate", "root"])
def test_a_denied_key_anywhere_in_the_verified_chain_refuses(pki, server, monkeypatch, which):
    assert _socket_get(pki, server).endswith(b"ok")  # same server, before the key is denied
    pki.deny(monkeypatch, which)
    with pytest.raises(ssl.SSLError) as info:
        _socket_get(pki, server)
    assert isinstance(info.value, tls.DistrustedChainRefused)
    assert DENIED_LABEL in str(info.value) and HOST in str(info.value)


def test_the_refusal_is_not_a_certificate_verification_error():
    """tls_connect and the requests adapter fall back to unverified, in non-enforce mode,
    only on a certificate-verification failure; a distrusted key must never take that road."""
    exc = tls.DistrustedChainRefused("punch 776: x")
    assert isinstance(exc, ssl.SSLError)
    assert not isinstance(exc, ssl.SSLCertVerificationError)
    assert tls.cert_verify_error(exc) is None


def test_a_context_that_verified_nothing_is_not_judged(pki, server, monkeypatch):
    """cert_check: off is the operator's deliberate mode: nothing was verified, so the guard
    stands down on a CERT_NONE context rather than judging an unverified chain."""
    pki.deny(monkeypatch, "intermediate")
    ctx = tls.guard_verifying_context(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, server), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert conn.recv(4096).endswith(b"ok")


def test_a_missing_deny_list_refuses_not_skips(pki, server, monkeypatch):
    tls._spki_denylist.cache_clear()
    monkeypatch.setattr(tls, "_SPKI_MODULE", "email_triage._no_such_denylist")
    try:
        with pytest.raises(tls.DistrustedChainRefused) as info:
            _socket_get(pki, server)
        assert "was not found" in str(info.value)
    finally:
        tls._spki_denylist.cache_clear()


# ---- asyncio (memory BIO) ------------------------------------------------------

def test_asyncio_clean_connects_and_denied_refuses(pki, server, monkeypatch):
    async def go():
        ctx = tls.client_tls_context(cafile=str(pki.root_pem))
        reader, writer = await asyncio.open_connection(
            HOST, server, ssl=ctx, server_hostname=HOST)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = await reader.read(4096)
        writer.close()
        return data

    assert asyncio.run(go()).endswith(b"ok")
    pki.deny(monkeypatch, "intermediate")
    with pytest.raises(ssl.SSLError) as info:
        asyncio.run(go())
    assert isinstance(info.value, tls.DistrustedChainRefused)


# ---- httpx -----------------------------------------------------------------------

def test_httpx_default_store_leg_clean_connects_and_denied_refuses_without_fallback(
    pki, server, monkeypatch
):
    import httpx

    from email_triage._egress import Intent, egress_client

    _trust_only(monkeypatch, pki)
    url = f"https://{HOST}:{server}/"
    with egress_client(intent=Intent.LOCAL_ONLY, timeout=10) as client:
        assert client.get(url).text == "ok"
        pki.deny(monkeypatch, "intermediate")
        with pytest.raises(httpx.ConnectError) as info:
            client.get(url)
    cause = info.value
    chain = []
    while cause is not None:
        chain.append(cause)
        cause = cause.__cause__ or cause.__context__
    assert any(isinstance(e, tls.DistrustedChainRefused) for e in chain), chain


# ---- requests --------------------------------------------------------------------

def test_requests_adapter_clean_connects_and_denied_refuses_without_fallback(
    pki, server, monkeypatch
):
    import requests

    from email_triage._egress import _cert_mode_adapter

    _trust_only(monkeypatch, pki)
    url = f"https://{HOST}:{server}/"
    session = requests.Session()
    session.mount("https://", _cert_mode_adapter(0))
    assert session.get(url, verify=str(pki.root_pem), timeout=10).text == "ok"
    pki.deny(monkeypatch, "intermediate")
    with pytest.raises(requests.exceptions.SSLError) as info:
        session.get(url, verify=str(pki.root_pem), timeout=10)
    assert DENIED_LABEL in str(info.value)


def test_requests_unverified_request_is_not_given_the_guarded_context(pki, server, monkeypatch):
    """verify=False keeps urllib3's own context, so the guarded one is never flipped to
    CERT_NONE and shared state stays verified."""
    from email_triage._egress import _cert_mode_adapter

    adapter = _cert_mode_adapter(0)
    import requests
    prepared = requests.Request("GET", f"https://{HOST}:{server}/").prepare()
    _, verified = adapter.build_connection_pool_key_attributes(prepared, str(pki.root_pem))
    _, unverified = adapter.build_connection_pool_key_attributes(prepared, False)
    assert isinstance(verified["ssl_context"].sslsocket_class, type)
    assert verified["ssl_context"].sslsocket_class is tls._GuardedSSLSocket
    assert "ssl_context" not in unverified
    _, again = adapter.build_connection_pool_key_attributes(prepared, str(pki.root_pem))
    assert again["ssl_context"] is verified["ssl_context"], "one context per verify value"
    _, other = adapter.build_connection_pool_key_attributes(prepared, True)
    assert other["ssl_context"] is not verified["ssl_context"], "bundles must not share trust"


# ---- structural ------------------------------------------------------------------

_CONTEXT_BUILDERS = {"create_default_context", "create_ssl_context", "create_urllib3_context",
                     "SSLContext"}
# (relpath, enclosing function) -> why it is not a guarded verifying client context
_UNGUARDED_OK = {
    ("tls.py", "build_ssl_context"): "server side (CLIENT_AUTH) for the uvicorn listener",
    ("tls.py", "_unverified_tls_context"): "the deliberate non-verifying cert_check:off leg",
}


def _unguarded_context_builds(tree, relpath: str) -> list[tuple[str, str, int]]:
    import ast

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.attr if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", ""))
        if name not in _CONTEXT_BUILDERS:
            continue
        parent = getattr(node, "_ph_parent", None)
        guarded = (isinstance(parent, ast.Call)
                   and getattr(parent.func, "id", getattr(parent.func, "attr", ""))
                   == "guard_verifying_context")
        if not guarded and (relpath, enclosing_fn(node)) not in _UNGUARDED_OK:
            found.append((relpath, enclosing_fn(node), node.lineno))
    return found


def test_every_verifying_context_in_src_is_guarded():
    found = []
    for _path, relpath, tree in walk_src():
        found.extend(_unguarded_context_builds(tree, relpath))
    assert not found, (
        "a client TLS context built without tls.guard_verifying_context (punch 776 (a)); "
        f"route it through tls.client_tls_context or wrap it: {found}")


def test_the_unguarded_context_pin_has_teeth():
    bad = "import ssl\ndef connect():\n    return ssl.create_default_context()\n"
    good = ("import ssl\nfrom email_triage.tls import guard_verifying_context\n"
            "def connect():\n    return guard_verifying_context(ssl.create_default_context())\n")
    assert_pin_has_teeth(lambda tree: _unguarded_context_builds(tree, "x.py"), bad, good)


def test_client_tls_context_returns_guarded_classes():
    for ctx in (tls.client_tls_context(), tls.client_tls_context(cafile="/no/such/bundle.pem")):
        assert ctx.sslsocket_class is tls._GuardedSSLSocket
        assert ctx.sslobject_class is tls._GuardedSSLObject
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


# ---- cycle P fold: contexts a caller or a library supplies (DA P4 items 1, 2, 4) ---------

def _refused_by_the_list(exc: BaseException) -> bool:
    seen, stack = set(), [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, tls.DistrustedChainRefused) or "punch 776" in str(e):
            return True
        stack.extend([e.__cause__, e.__context__, *[a for a in getattr(e, "args", ())
                                                   if isinstance(a, BaseException)]])
    return False


@pytest.mark.parametrize("shape", ["context", "cafile"])
def test_httpx_caller_verify_is_guarded(pki, server, monkeypatch, shape):
    """DA P4-1: ``egress_client(verify=<the caller's context or CA path>)`` took the
    ``caller`` leg straight to httpx, unguarded; a denied chain completed the handshake."""
    import httpx

    from email_triage._egress import Intent, egress_client

    _trust_only(monkeypatch, pki)
    url = f"https://{HOST}:{server}/"

    def verify():
        if shape == "context":
            return ssl.create_default_context(cafile=str(pki.root_pem))
        return str(pki.root_pem)

    with egress_client(intent=Intent.LOCAL_ONLY, timeout=10, verify=verify()) as client:
        assert client.get(url).text == "ok"  # positive control on the same leg
    pki.deny(monkeypatch, "intermediate")
    with egress_client(intent=Intent.LOCAL_ONLY, timeout=10, verify=verify()) as client:
        with pytest.raises(httpx.ConnectError) as info:
            client.get(url)
    assert _refused_by_the_list(info.value), info.value


def test_guard_caller_tls_shapes(tmp_path):
    ctx = ssl.create_default_context()
    assert tls.guard_caller_tls(ctx) is ctx and ctx.sslsocket_class is tls._GuardedSSLSocket
    assert tls.guard_caller_tls(False) is False and tls.guard_caller_tls(None) is None
    built = tls.guard_caller_tls(str(tmp_path))  # a directory is a CApath
    assert built.sslsocket_class is tls._GuardedSSLSocket and built.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises((OSError, ssl.SSLError)):
        tls.guard_caller_tls(str(tmp_path / "no-such-bundle.pem"))  # never the default store


def test_imap_caller_ssl_context_is_guarded(pki, server, monkeypatch):
    """DA P4-4: ``imap_connect(..., ssl_context=<the caller's>)`` used it as given."""
    from email_triage.providers.imap_fetch_transport import imap_connect

    pki.deny(monkeypatch, "intermediate")
    ctx = ssl.create_default_context(cafile=str(pki.root_pem))
    with pytest.raises(ssl.SSLError) as info:
        imap_connect(HOST, server, ssl_context=ctx)
    assert isinstance(info.value, tls.DistrustedChainRefused), info.value


def test_imap_caller_context_positive_control(monkeypatch):
    import email_triage.providers.imap_fetch_transport as transport

    seen = {}
    monkeypatch.setattr(transport.imaplib, "IMAP4_SSL",
                        lambda host, port, ssl_context=None: seen.setdefault("ctx", ssl_context))
    ctx = ssl.create_default_context()
    assert transport.imap_connect("imap.example.invalid", 993, ssl_context=ctx) is ctx
    assert seen["ctx"].sslsocket_class is tls._GuardedSSLSocket


def test_rediss_uses_the_guarded_connection_and_refuses_a_denied_chain(pki, server, monkeypatch):
    """DA P4-2: for ``rediss://`` redis-py builds its own SSLContext, which the deny list
    never saw. The factory forces the guarded connection class (an override cannot replace
    it); a denied chain is refused before any command, as a redis ConnectionError."""
    redis = pytest.importorskip("redis")
    from email_triage.cache._redis import build_redis_client

    plain = build_redis_client("redis://127.0.0.1:1/0")
    assert plain.connection_pool.connection_class is redis.connection.Connection
    client = build_redis_client(f"rediss://{HOST}:{server}/0", ssl_ca_certs=str(pki.root_pem),
                                connection_class=redis.connection.SSLConnection)
    cls = client.connection_pool.connection_class
    assert issubclass(cls, redis.connection.SSLConnection) and cls is not redis.connection.SSLConnection
    pki.deny(monkeypatch, "intermediate")
    with pytest.raises(redis.exceptions.ConnectionError) as info:
        client.ping()
    assert _refused_by_the_list(info.value), info.value


# ---- cycle P fold: the deny list ships inside the package (DA P4-5, Q6) ---------------------

def test_a_copy_of_the_package_without_scripts_still_loads_the_list(tmp_path):
    """A wheel or portable install has no ``scripts/`` beside the package. Before the fold
    ``_spki_denylist`` looked only there and in ``/app/scripts``, so such an install refused
    every verified connection. The copy below has the package and nothing else."""
    import shutil
    import subprocess
    import sys

    site = tmp_path / "site"
    shutil.copytree(Path(tls.__file__).parent, site / "email_triage",
                    ignore=shutil.ignore_patterns("__pycache__"))
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(site)!r})\n"
        "import email_triage.tls as t\n"
        f"assert t.__file__.startswith({str(site)!r}), t.__file__\n"
        "print(len(t._spki_denylist().DENIED_SPKI_SHA256))\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(probe)], cwd=tmp_path,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert int(proc.stdout.strip().splitlines()[-1]) >= 8


def test_the_build_scan_reads_the_package_list_not_a_copy():
    """ONE list: the build-time scanner re-exports the package module's objects and holds no
    SPKI literal of its own."""
    import re

    from _pin_harness import load_repo_script

    spki = load_repo_script("scripts/check_distrusted_spki.py")
    package = tls._spki_denylist()
    assert spki.DENIED_SPKI_SHA256 == package.DENIED_SPKI_SHA256
    assert spki.spki_sha256.__code__.co_code == package.spki_sha256.__code__.co_code
    source = (Path(tls.__file__).parents[2] / "scripts" / "check_distrusted_spki.py").read_text(
        encoding="utf-8")
    assert not re.search(r"[0-9a-f]{64}", source), "a second copy of an SPKI pin in the script"


def test_the_build_scan_refuses_when_the_list_is_missing(monkeypatch):
    from _pin_harness import load_repo_script

    spki = load_repo_script("scripts/check_distrusted_spki.py")
    monkeypatch.setattr(spki, "_list_candidates", lambda: ["/no/such/_distrusted_spki.py"])
    with pytest.raises(SystemExit) as info:
        spki._load_list_module()
    assert info.value.code == 1


# ---- cycle P fold: census of TLS client constructors (DA P4-3) -------------------------
#
# The context-builder pin above sees a context our code BUILDS. A library handed no context
# builds its own (imaplib/smtplib: an unverified one; urllib, http.client, asyncio, redis-py:
# a verifying one the guard never wraps). This census walks every call of a TLS-capable
# client constructor in src and requires the context it is handed to be guarded:
#   * a call of a guarded builder (``client_tls_context``, ``mode_context``,
#     ``guard_verifying_context``, ``guard_caller_tls``), or
#   * a parameter of the callable handed to ``tls_connect`` / ``tls_connect_async`` (a lambda
#     in the call, or a def named inside its first argument, e.g. ``functools.partial(f, ...)``),
#     which is called only with ``client_tls_context()`` or the deliberate unverified leg.
# ``from_url`` (redis) is allowed only in the factory, whose rediss class is behaviour-tested
# above. Anything else needs a row in _TLS_CLIENT_OK naming the code fix.

# constructor name -> the keyword that hands it a context; TLS_IF_GIVEN: TLS only when given
_TLS_CLIENTS = {
    "IMAP4_SSL": ("ssl_context",), "SMTP_SSL": ("context",), "POP3_SSL": ("context",),
    "FTP_TLS": ("context",), "starttls": ("context", "ssl_context"),
    "HTTPSConnection": ("context",), "HTTPSHandler": ("context",), "urlopen": ("context",),
    "build_opener": (), "from_url": ("connection_class",),
    "open_connection": ("ssl",), "create_connection": ("ssl",), "start_tls": ("sslcontext", "ssl"),
}
_TLS_IF_GIVEN = {"open_connection", "create_connection"}
_GUARDED_BUILDERS = {"client_tls_context", "mode_context", "guard_verifying_context",
                     "guard_caller_tls"}
_TLS_FUNNELS = {"tls_connect", "tls_connect_async"}
# (relpath, enclosing function, constructor) -> reason (and the named code fix)
_TLS_CLIENT_OK = {
    ("cache/_redis.py", "build_redis_client", "from_url"):
        "the redis factory: rediss:// forces the guarded connection class "
        "(test_rediss_uses_the_guarded_connection_and_refuses_a_denied_chain)",
}


def _call_name(call) -> str:
    f = call.func
    return f.attr if hasattr(f, "attr") else getattr(f, "id", "")


def _funnel_callables(tree) -> tuple[set, set[str]]:
    """(lambda nodes, def names) handed to a tls_connect* call as its first argument."""
    import ast

    lambdas, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in _TLS_FUNNELS and node.args:
            for sub in ast.walk(node.args[0]):
                if isinstance(sub, ast.Lambda):
                    lambdas.add(id(sub))
                elif isinstance(sub, ast.Name):
                    names.add(sub.id)
    return lambdas, names


def _guarded_value(value, call, funnel) -> bool:
    import ast

    if isinstance(value, ast.Call) and _call_name(value) in _GUARDED_BUILDERS:
        return True
    if isinstance(value, ast.Name):
        lambdas, names = funnel
        scope = enclosing_callable(call)
        if scope is None:
            return False
        params = {a.arg for a in [*scope.args.posonlyargs, *scope.args.args,
                                  *scope.args.kwonlyargs]}
        handed = (id(scope) in lambdas if isinstance(scope, ast.Lambda)
                  else scope.name in names)
        return value.id in params and handed
    return False


def unguarded_tls_clients(tree, relpath: str) -> list[tuple[str, str, str, int]]:
    import ast

    funnel = _funnel_callables(tree)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        ctor = _call_name(node)
        if ctor not in _TLS_CLIENTS:
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        given = [kw[k] for k in _TLS_CLIENTS[ctor] if k in kw]
        if ctor in _TLS_IF_GIVEN and not given:
            continue  # plain TCP: no TLS without the ssl argument
        if ctor == "build_opener":
            given = [kw2.value for a in node.args if isinstance(a, ast.Call)
                     and _call_name(a) == "HTTPSHandler" for kw2 in a.keywords
                     if kw2.arg == "context"]
        ok = bool(given) and all(_guarded_value(v, node, funnel) for v in given)
        if not ok and (relpath, enclosing_fn(node), ctor) not in _TLS_CLIENT_OK:
            found.append((relpath, enclosing_fn(node), ctor, node.lineno))
    return found


def test_every_tls_client_constructor_in_src_is_handed_a_guarded_context():
    import ast

    found, sites, used_ok = [], 0, set()
    for _path, relpath, tree in walk_src():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in _TLS_CLIENTS:
                sites += 1
                key = (relpath, enclosing_fn(node), _call_name(node))
                if key in _TLS_CLIENT_OK:
                    used_ok.add(key)
        found.extend(unguarded_tls_clients(tree, relpath))
    assert sites >= 4, f"the census found {sites} TLS client site(s): the net is blind"
    assert not found, (
        "a TLS client constructor is handed no guarded context, so the library builds its "
        "own and the punch 776 chain check never runs (cycle P DA P4-3); pass "
        f"tls.client_tls_context() / guard_caller_tls(...) or route through tls_connect: {found}")
    stale = set(_TLS_CLIENT_OK) - used_ok
    assert not stale, f"_TLS_CLIENT_OK rows that match no site: {stale}"


def test_the_tls_client_census_has_teeth():
    detect = lambda tree: unguarded_tls_clients(tree, "x.py")  # noqa: E731
    # the DA P4-4 shape: a caller's context handed straight through
    assert_pin_has_teeth(
        detect,
        "import imaplib\ndef c(h, p, ssl_context=None):\n"
        "    return imaplib.IMAP4_SSL(h, p, ssl_context=ssl_context)\n",
        "import imaplib\nfrom email_triage.tls import guard_caller_tls\n"
        "def c(h, p, ssl_context=None):\n"
        "    return imaplib.IMAP4_SSL(h, p, ssl_context=guard_caller_tls(ssl_context))\n")
    # no context at all: the library builds its own
    assert_pin_has_teeth(detect, "import smtplib\ndef c(h):\n    return smtplib.SMTP_SSL(h)\n")
    assert_pin_has_teeth(detect, "import urllib.request\ndef c(u):\n"
                                 "    return urllib.request.urlopen(u)\n")
    assert_pin_has_teeth(detect, "import asyncio\nasync def c(h):\n"
                                 "    return await asyncio.open_connection(h, 1, ssl=True)\n")
    # a lambda param is fine only when the lambda is handed to tls_connect
    assert_pin_has_teeth(
        detect,
        "import imaplib\ndef c(h, p, run):\n"
        "    return run(lambda ctx: imaplib.IMAP4_SSL(h, p, ssl_context=ctx))\n",
        "import imaplib\nfrom email_triage.tls import tls_connect\ndef c(h, p):\n"
        "    return tls_connect(lambda ctx: imaplib.IMAP4_SSL(h, p, ssl_context=ctx),"
        " host=h, port=p, protocol='imap')\n")
    # a def named inside the funnel argument (functools.partial), and plain TCP
    assert not detect(parse_source(
        "import functools, smtplib\nfrom email_triage.tls import tls_connect\n"
        "def _go(h, ctx):\n    s = smtplib.SMTP(h)\n    s.starttls(context=ctx)\n    return s\n"
        "def c(h):\n    return tls_connect(functools.partial(_go, h), host=h, port=25,"
        " protocol='smtp')\n"
        "async def t(h):\n    return await asyncio.open_connection(h, 1)\n"))
