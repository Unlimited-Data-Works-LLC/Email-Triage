"""Punch 656 (the runtime half, built as punch 776 (a)): the verified-chain SPKI check fails
CLOSED, and no httpx client can reach the network around it.

``tests/test_punch776_runtime_spki_chain_pin.py`` pins the happy edges on real loopback
handshakes (a denied key in the chain refuses, a clean chain connects) and walks every site
that builds a TLS context or constructs a TLS client. Four edges were not pinned:

  1. A chain the check cannot read must REFUSE, never skip (Prime Directive 8). Only
     ``AttributeError`` / ``ValueError`` / ``OSError`` were converted to the typed refusal; a
     getter that returned ``None`` (``TypeError``) or failed inside the TLS library
     (``RuntimeError``) escaped as an untyped error, and the guarded socket closed itself on
     ``DistrustedChainRefused`` only, so the handshaken socket stayed open.
  2. The older-Python path (no public ``get_verified_chain``) and the "no chain at all" path
     were never driven, so a change that turned either into a pass would stay green.
  3. ``_egress._with_mode_transport`` installs the guarded transport unless the caller brings its
     own ``transport=`` / ``mounts=``. No caller in ``src`` does today; nothing kept it so.
  4. ``_ModeLegs.inner`` builds the ``verify`` of every leg of the egress transport; a new leg
     built with a bare ``httpx.create_ssl_context()`` would skip the check on that leg.

TEETH. Arms 1 and 2 run against a fake TLS object (so they hold on any Python) AND, where
``ssl.SSLSocket.get_verified_chain`` exists (Python 3.13+, the image's 3.14), on a real loopback
handshake whose chain getter is broken. The fake carries a locally generated certificate: the
clean one passes, the same one with its key on the (monkeypatched) deny list refuses.
Arms 3 and 4 are AST pins on ``src``, each with a planted bad shape.
"""

from __future__ import annotations

import ast
import socket
import ssl
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from _pin_harness import assert_pin_has_teeth, enclosing_fn, parse_source, walk_src
from email_triage import tls

# Fixtures and helpers of the 776 pin, reused rather than rebuilt (PD-5): a generated
# root -> intermediate -> leaf chain on loopback, and the per-test verdict-cache reset.
from test_punch776_runtime_spki_chain_pin import (  # noqa: F401  (fixtures)
    DENIED_LABEL,
    HOST,
    _fresh_verdicts,
    pki,
    server,
)

_HAS_PUBLIC_CHAIN_API = hasattr(ssl.SSLSocket, "get_verified_chain")


# ---- a fake TLS object ----------------------------------------------------------


def _fake(getter=None, *, sslobj=None, verify_mode=ssl.CERT_REQUIRED):
    """What ``enforce_chain_not_distrusted`` reads: ``context.verify_mode``,
    ``server_hostname``, ``get_verified_chain`` (public, 3.13+) or ``_sslobj`` (older)."""
    obj = SimpleNamespace(
        context=SimpleNamespace(verify_mode=verify_mode), server_hostname="fake.invalid",
    )
    if getter is not None:
        obj.get_verified_chain = getter
    if sslobj is not None:
        obj._sslobj = sslobj
    return obj


def _raiser(exc: BaseException):
    def getter():
        raise exc
    return getter


class _Recorder:
    """Stands in for the TriageLogger: kwargs only, like the real one."""

    def __init__(self) -> None:
        self.events: list[str] = []

    def error(self, message, **kw) -> None:
        self.events.append(kw.get("event", ""))


@pytest.fixture
def log(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(tls, "_logger", lambda: rec)
    return rec


# Every shape of a chain the check cannot use. Each one must refuse with the typed error.
_UNREADABLE = {
    "no_getter_and_no_sslobj": (lambda: _fake(), "could not be read (AttributeError)"),
    "older_python_sslobj_returns_none": (
        lambda: _fake(sslobj=SimpleNamespace(get_verified_chain=lambda: None)),
        "no verified chain was available"),
    "older_python_sslobj_returns_empty": (
        lambda: _fake(sslobj=SimpleNamespace(get_verified_chain=lambda: [])),
        "no verified chain was available"),
    "getter_returns_empty": (lambda: _fake(lambda: []), "no verified chain was available"),
    "getter_returns_none": (lambda: _fake(lambda: None), "could not be read (TypeError)"),
    "getter_raises_value_error": (
        lambda: _fake(_raiser(ValueError("x"))), "could not be read (ValueError)"),
    "getter_raises_os_error": (
        lambda: _fake(_raiser(OSError("x"))), "could not be read (OSError)"),
    "getter_raises_type_error": (
        lambda: _fake(_raiser(TypeError("x"))), "could not be read (TypeError)"),
    "getter_raises_runtime_error": (
        lambda: _fake(_raiser(RuntimeError("x"))), "could not be read (RuntimeError)"),
    "element_is_not_bytes": (lambda: _fake(lambda: ["not der"]), "could not be read (TypeError)"),
    "element_is_not_a_certificate": (
        lambda: _fake(lambda: [b"\x00\x01\x02"]), "a certificate in the server chain could not be read"),
    "element_is_a_truncated_certificate": (
        lambda: _fake(lambda: [b"\x30\x82\xff\xff"]), "a certificate in the server chain could not be read"),
    # The context read sits inside the try (656 NOTE): an object whose ``context`` cannot be read
    # refuses typed, instead of escaping as a raw AttributeError that leaves the socket open.
    "no_context_attribute": (
        lambda: SimpleNamespace(server_hostname="fake.invalid", get_verified_chain=lambda: [b"x"]),
        "could not be read (AttributeError)"),
    "context_is_none": (
        lambda: SimpleNamespace(context=None, server_hostname="fake.invalid"),
        "could not be read (AttributeError)"),
    "context_without_verify_mode": (
        lambda: SimpleNamespace(context=SimpleNamespace(), server_hostname="fake.invalid"),
        "could not be read (AttributeError)"),
}


@pytest.mark.parametrize("name", sorted(_UNREADABLE))
def test_a_chain_the_check_cannot_read_refuses_with_the_typed_error(name, log):
    build, needle = _UNREADABLE[name]
    with pytest.raises(tls.DistrustedChainRefused) as info:
        tls.enforce_chain_not_distrusted(build())
    assert needle in str(info.value), str(info.value)
    assert "fake.invalid" in str(info.value) or "server chain" in str(info.value)
    # the typed refusal is an ssl.SSLError (the stdlib closes the socket on it) and is never
    # taken for a certificate-verification failure, which non-enforce mode retries unverified
    assert isinstance(info.value, ssl.SSLError)
    assert not isinstance(info.value, ssl.SSLCertVerificationError)
    assert log.events and set(log.events) <= {
        "tls_distrusted_chain_unreadable", "tls_distrusted_chain_refused"}, log.events


def test_an_unreadable_chain_is_judged_only_on_a_verifying_context(log):
    """The one deliberate stand-down: ``cert_check: off`` verified nothing, so there is no
    verified chain to judge (an unreadable one included). Pins that the stand-down is
    keyed on the context's mode and nothing else."""
    assert tls.enforce_chain_not_distrusted(_fake(verify_mode=ssl.CERT_NONE)) is None
    assert log.events == []
    with pytest.raises(tls.DistrustedChainRefused):
        tls.enforce_chain_not_distrusted(_fake(verify_mode=ssl.CERT_REQUIRED))
    with pytest.raises(tls.DistrustedChainRefused):
        tls.enforce_chain_not_distrusted(_fake(verify_mode=ssl.CERT_OPTIONAL))


def test_a_clean_generated_chain_passes_and_the_same_chain_with_a_denied_key_refuses(
    pki, monkeypatch, log,
):
    """Positive control for the matrix above: the fake is a usable stand-in. Locally generated
    certificates; the denied key is the generated leaf's, added to the live deny dict."""
    der = [c.public_bytes(serialization.Encoding.DER)
           for c in (pki.leaf, pki.intermediate, pki.root)]
    assert tls.enforce_chain_not_distrusted(_fake(lambda: list(der))) is None
    assert log.events == []
    pki.deny(monkeypatch, "intermediate")
    with pytest.raises(tls.DistrustedChainRefused) as info:
        tls.enforce_chain_not_distrusted(_fake(lambda: list(der)))
    assert DENIED_LABEL in str(info.value) and "fake.invalid" in str(info.value)
    assert log.events == ["tls_distrusted_chain_refused"]


# ---- the same edges on a real loopback handshake ------------------------------------


def _wrap(pki, port, closed: list[bool], monkeypatch):
    real_close = ssl.SSLSocket.close

    def recording_close(self):
        closed.append(True)
        return real_close(self)

    monkeypatch.setattr(tls._GuardedSSLSocket, "close", recording_close)
    ctx = tls.client_tls_context(cafile=str(pki.root_pem))
    raw = socket.create_connection((HOST, port), timeout=5)
    try:
        return ctx.wrap_socket(raw, server_hostname=HOST)
    finally:
        raw.close()


@pytest.mark.skipif(not _HAS_PUBLIC_CHAIN_API, reason="needs SSLSocket.get_verified_chain (3.13+)")
@pytest.mark.parametrize("broken", ["none", "empty", "type_error", "runtime_error"])
def test_a_real_handshake_whose_chain_cannot_be_read_is_refused_and_closed(
    pki, server, monkeypatch, log, broken,
):
    def getter(self):
        if broken == "none":
            return None
        if broken == "empty":
            return []
        raise (TypeError if broken == "type_error" else RuntimeError)("x")

    # positive control on the same server, before the getter is broken
    closed: list[bool] = []
    with _wrap(pki, server, closed, monkeypatch) as conn:
        assert conn.getpeercert()
    assert closed, "the control socket closed on exit"

    monkeypatch.setattr(tls._GuardedSSLSocket, "get_verified_chain", getter)
    closed.clear()
    with pytest.raises(tls.DistrustedChainRefused):
        _wrap(pki, server, closed, monkeypatch)
    assert closed, "a refused handshake must close the socket it completed"


# ---- structural: no httpx client reaches the network around the check ---------------

_EGRESS_CLIENTS = {"egress_client", "egress_async_client"}
_TRANSPORT_KEYWORDS = {"transport", "mounts"}
# (relpath, enclosing function, keyword) -> why a caller may hand an httpx client its own
# transport. EMPTY: a caller's transport is built by the caller, and the egress guard (the
# punch 776 chain check) never sees it. A row needs the code fix that guards that transport.
_TRANSPORT_OVERRIDE_OK: dict[tuple[str, str, str], str] = {}


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def own_transport_handed_to_a_client(tree: ast.AST, relpath: str) -> list[tuple[str, str, str, int]]:
    """Calls that pass ``transport=`` / ``mounts=`` to an egress client factory, to
    ``LazyHttpClient`` (which forwards its kwargs to one), or to an httpx client class."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node) not in _EGRESS_CLIENTS | {"LazyHttpClient", "AsyncClient", "Client"}:
            continue
        for kw in node.keywords:
            if kw.arg in _TRANSPORT_KEYWORDS and (relpath, enclosing_fn(node), kw.arg) not in _TRANSPORT_OVERRIDE_OK:
                found.append((relpath, enclosing_fn(node), kw.arg, node.lineno))
    return found


def test_no_caller_hands_an_egress_httpx_client_its_own_transport():
    found, sites = [], 0
    for _path, relpath, tree in walk_src():
        sites += sum(1 for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and _call_name(n) in _EGRESS_CLIENTS)
        found.extend(own_transport_handed_to_a_client(tree, relpath))
    assert sites >= 3, f"the census found {sites} egress client site(s): the net is blind"
    assert not found, (
        "an httpx client was handed its own transport=/mounts=, so _with_mode_transport leaves "
        "it unguarded and the punch 776 chain check never runs on it; guard the transport and "
        f"add a _TRANSPORT_OVERRIDE_OK row naming the fix: {found}")


def test_the_own_transport_pin_has_teeth():
    detect = lambda tree: own_transport_handed_to_a_client(tree, "x.py")  # noqa: E731
    assert_pin_has_teeth(
        detect,
        "from email_triage._egress import egress_async_client\n"
        "def c(t):\n    return egress_async_client(intent=1, transport=t)\n",
        "from email_triage._egress import egress_async_client\n"
        "def c():\n    return egress_async_client(intent=1, timeout=3)\n")
    assert_pin_has_teeth(
        detect, "def c(t, m):\n    return LazyHttpClient(intent=1, mounts=m)\n")
    # the row list works: the same shape, allow-listed, is not flagged
    _TRANSPORT_OVERRIDE_OK[("x.py", "c", "transport")] = "test row"
    try:
        assert not detect(parse_source(
            "def c(t):\n    return egress_client(intent=1, transport=t)\n"))
    finally:
        del _TRANSPORT_OVERRIDE_OK[("x.py", "c", "transport")]


_GUARDED_VERIFY = {"guard_caller_tls", "guard_verifying_context", "mode_context",
                   "client_tls_context"}


def unguarded_leg_verify(tree: ast.AST) -> list[tuple[str, int]]:
    """In every ``_ModeLegs`` method, an assignment to ``verify`` whose value is not a call of a
    guarded builder. ``_ModeLegs.inner`` builds the verify of each leg of both egress
    transports (verified / unverified / caller), so a leg built from a bare
    ``httpx.create_ssl_context()`` would skip the punch 776 chain check."""
    found = []
    for cls in ast.walk(tree):
        if not (isinstance(cls, ast.ClassDef) and cls.name == "_ModeLegs"):
            continue
        for node in ast.walk(cls):
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "verify" for t in node.targets):
                continue
            value = node.value
            if not (isinstance(value, ast.Call) and _call_name(value) in _GUARDED_VERIFY):
                found.append((enclosing_fn(node), node.lineno))
    return found


def test_every_egress_leg_builds_its_verify_through_a_guarded_builder():
    legs, assigned = 0, 0
    for _path, relpath, tree in walk_src():
        if relpath != "_egress.py":
            continue
        legs = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "_ModeLegs")
        assigned = sum(1 for c in ast.walk(tree)
                       if isinstance(c, ast.ClassDef) and c.name == "_ModeLegs"
                       for n in ast.walk(c) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "verify" for t in n.targets))
        found = unguarded_leg_verify(tree)
        assert not found, (
            "an egress transport leg builds its verify without a guarded builder, so the "
            f"punch 776 chain check never runs on it: {found}")
    assert legs == 1 and assigned >= 3, (
        f"the net is blind: _ModeLegs classes={legs}, verify assignments={assigned}")


def test_the_leg_verify_pin_has_teeth():
    assert_pin_has_teeth(
        unguarded_leg_verify,
        "class _ModeLegs:\n    def inner(self):\n        verify = httpx.create_ssl_context()\n",
        "class _ModeLegs:\n    def inner(self):\n"
        "        verify = guard_verifying_context(httpx.create_ssl_context())\n"
        "        if self.x:\n            verify = guard_caller_tls(self.v)\n")
