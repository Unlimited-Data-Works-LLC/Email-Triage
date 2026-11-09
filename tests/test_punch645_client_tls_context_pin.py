"""Punch 645 — outbound TLS verifies the peer: one client-context SSOT.

``web/smtp_send.send_smtp_message`` called ``server.starttls()`` with no
``context=``. smtplib then builds ``ssl._create_stdlib_context()``: CERT_NONE,
no hostname check, so the SMTP login and the message crossed a TLS session
that authenticated nobody (§164.312(e)(1)). The fix routes it through
``email_triage.tls.client_tls_context()`` (CERT_REQUIRED + hostname check +
the default trust store), the same helper the N-119 IMAP connection probe in
``providers/dispatcher.py`` now uses.

Two halves:

* BEHAVIOURAL — a fake ``smtplib.SMTP`` records what ``starttls`` received;
  ``use_tls=True`` must hand it a verifying context before ``login``, and
  ``use_tls=False`` must never call it.
* STRUCTURAL (count-agnostic, every ``src/email_triage`` file via the shared
  harness) — every ``.starttls(``/``.stls(`` call passes a non-None context;
  every client ``ssl.create_default_context(``/``SSLContext(`` construction
  sits in ``tls.py`` (or on ``_ALLOW`` with a reason); the stdlib's private
  unverified constructors appear nowhere.

Widened by punch 651 (N-119) and punch 657 (panel J DA):

* every ``IMAP4_SSL(``/``SMTP_SSL(``/``POP3_SSL(`` construction passes a
  non-None ``ssl_context=``/``context=`` keyword. With none, imaplib, smtplib
  and poplib build ``ssl._create_stdlib_context()`` (CERT_NONE); that was the
  live IMAP PHI-body fetch (``imap_fetch_transport.imap_connect``);
* the starttls scan also catches the unbound ``smtplib.SMTP.starttls(server)``
  form and a ``getattr(x, "starttls")`` dispatch;
* no file outside ``tls.py`` assigns ``verify_mode`` / ``check_hostname`` /
  ``options`` / ``minimum_version`` / ``maximum_version``, calls
  ``set_ciphers`` / ``load_verify_locations``, or names ``CERT_NONE`` /
  ``CERT_OPTIONAL``; and no file passes a literal ``verify=False`` unless it
  is on ``_VERIFY_FALSE_ALLOW`` with its reason. The stdlib's own unverified
  factories (``ssl._create_unverified_context`` / ``_create_stdlib_context``)
  are already banned in every file, ``tls.py`` included, by
  ``test_no_unverified_stdlib_constructor_anywhere``;
* an ``IMAP4_SSL``/``SMTP_SSL``/``POP3_SSL`` reference that is not called on
  the spot (an alias variable, ``functools.partial``, a ``getattr`` string)
  and a renamed import of one are flagged, because the constructor scan
  cannot follow them.

Operator certificate modes (2026-10-21; the "no opt-out" of punch 645/651
reversed by the operator, design_tls_cert_check_modes_off_validate_enforce): the
pin no longer bans a non-verifying context, it REQUIRES THE MODE HELPER. Every
client context comes from ``email_triage.tls`` (``tls_connect`` /
``tls_connect_async`` / ``mode_context``), which applies ``cert_check`` /
``cert_enforce``: off (unverified, the setup / troubleshooting mode), validate
(verifying handshake; a failure logs one ``tls_cert_check_failed`` WARNING and
the connection goes ahead unverified) or enforce (refused). So:

* no file outside ``tls.py`` names ``client_tls_context`` or
  ``_unverified_tls_context``: the only way to a context is a mode helper;
* every module that builds ``IMAP4_SSL(`` or calls ``.starttls(`` also calls
  ``tls_connect`` or ``tls_connect_async`` (the route, not the output);
* teeth for each mode: the behavioural tests below plus the real-socket suite
  ``tests/test_tls_cert_check_modes.py`` (IMAP sync + async, SMTP STARTTLS,
  httpx and requests egress; off / validate / enforce / verified).

SCOPE CAVEAT: what a green run does NOT prove (panel K db-sme F4):
* a context argument that is a variable holding None at runtime; the scan
  sees only the literal. The behavioural tests are the teeth for the one SSOT
  site (``imap_connect(..., ssl_context=None)``);
* weakening through ``ssl.VerifyMode(0)``, a loop target, or an asyncio
  ``server_hostname=""``;
* a ``starttls`` reached through ``type(s).starttls(s)``, an aliased owner
  (``S = smtplib.SMTP; S.starttls(s)``) or a bound method taken into a
  variable. Constructor indirection is also
  covered one layer down by ``tests/test_egress_funnel_pin.py`` (raw
  imaplib/aioimaplib/smtplib outside the SSOT);
* a third-party client's TLS knobs other than a literal ``verify=False``
  (``egress_client(**kwargs)`` forwards ``verify`` to httpx);
* anything outside ``src/email_triage`` (``scripts/``, e.g. the synthetic,
  non-PHI ``scripts/demo-mailbox-seed.py``);
* ``tls.py`` itself, which is exempt from the weakening scan. The behavioural
  tests (``client_tls_context`` and both IMAP wrappers must hand out
  CERT_REQUIRED + check_hostname) cover it.
"""

from __future__ import annotations

import ast
import asyncio
import ssl
from email.message import EmailMessage

from _tls_assertions import assert_verifying_context as _assert_verifying
from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
)

SSOT_REL = "tls.py"
SMTP_SSOT_REL = "web/smtp_send.py"

# Client-context constructors allowed only in the SSOT.
_CONSTRUCTORS = frozenset({"create_default_context", "SSLContext"})
# The stdlib's unverified/private constructors: forbidden everywhere.
_UNVERIFIED = frozenset({
    "_create_stdlib_context",
    "_create_unverified_context",
    "_create_default_https_context",
})
# The keyword each stdlib STARTTLS spelling takes (smtplib/poplib: context;
# imaplib: ssl_context).
_CONTEXT_KWARGS = frozenset({"context", "ssl_context"})
# Implicit-TLS client classes: with no context they fall back to CERT_NONE.
_SSL_CLASSES = frozenset({"IMAP4_SSL", "SMTP_SSL", "POP3_SSL"})
# Classes whose starttls()/stls() may be called unbound (self first).
_STARTTLS_OWNERS = frozenset({"SMTP", "LMTP", "IMAP4", "POP3"})
_STARTTLS_NAMES = frozenset({"starttls", "stls"})
# Attributes and methods that weaken a built context, and the constants that do it.
_WEAKENING_ATTRS = frozenset({
    "verify_mode", "check_hostname", "options", "minimum_version", "maximum_version",
})
_WEAKENING_CALLS = frozenset({"set_ciphers", "load_verify_locations"})
_WEAK_CONSTANTS = frozenset({"CERT_NONE", "CERT_OPTIONAL"})

# (file relative to src/email_triage, enclosing function) pairs allowed a
# literal ``verify=False``, each with its reason. Keyed by function, not file
# (panel K db-sme FC-3). A new entry is a decision to skip peer verification.
# The mode helpers in tls.py: the only sources of a client context outside it.
_MODE_HELPERS = frozenset({"tls_connect", "tls_connect_async", "mode_context"})
# Names that hand out a context directly; private to tls.py.
_DIRECT_CONTEXT_NAMES = frozenset({"client_tls_context", "_unverified_tls_context"})

_VERIFY_FALSE_ALLOW: dict[tuple[str, str], str] = {
    ("cli.py", "cmd_backup"): "the ops trigger to the fixed loopback "
                              "_OPS_TRIGGER_BASE_URL (egress_client "
                              "Intent.LOCAL_ONLY); a self-signed local cert",
    ("_egress.py", "send"): "the requests certificate-mode adapter: the unverified "
                            "leg for an operator's cert_check off, or the logged "
                            "non-enforce fallback (operator modes 2026-10-21, "
                            "email_triage.tls.CertPolicy)",
}

# Files outside tls.py that may construct a client context, each with a reason.
# Keep it SHORT; a new entry is a decision that a site should not use the SSOT.
_ALLOW: dict[str, str] = {}


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _owner_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _context_missing(call: ast.Call, positional: list[ast.expr]) -> bool:
    ctx = [k.value for k in call.keywords if k.arg in _CONTEXT_KWARGS]
    ctx += positional
    return not ctx or all(_is_none(v) for v in ctx)


def _starttls_without_context(tree: ast.AST) -> list[int]:
    """Lines of a ``.starttls(``/``.stls(`` call with no context, or a None
    one, including the unbound ``smtplib.SMTP.starttls(server)`` form (its first
    positional is the server, not a context), and every
    ``getattr(x, "starttls")`` dispatch, which no scan can follow."""
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        if (_call_name(n) == "getattr" and len(n.args) >= 2
                and isinstance(n.args[1], ast.Constant)
                and n.args[1].value in _STARTTLS_NAMES):
            out.append(n.lineno)
            continue
        if not (isinstance(n.func, ast.Attribute) and n.func.attr in _STARTTLS_NAMES):
            continue
        args = list(n.args)
        if _owner_name(n.func.value) in _STARTTLS_OWNERS:
            args = args[1:]
        # imaplib's ssl_context is the first positional of the bound call.
        if _context_missing(n, args[:1]):
            out.append(n.lineno)
    return out


def _ssl_constructor_without_context(tree: ast.AST) -> list[int]:
    """Lines of an ``IMAP4_SSL(``/``SMTP_SSL(``/``POP3_SSL(`` construction with no
    non-None ``ssl_context=``/``context=`` keyword. The stdlib takes the context
    keyword-only, so a positional one is not looked for."""
    return [n.lineno for n in ast.walk(tree)
            if isinstance(n, ast.Call) and _call_name(n) in _SSL_CLASSES
            and _context_missing(n, [])]


def _context_weakened(tree: ast.AST) -> list[int]:
    """Lines that assign a ``_WEAKENING_ATTRS`` attribute (directly or via
    ``setattr``), call ``set_ciphers`` / ``load_verify_locations``, or name
    ``CERT_NONE`` / ``CERT_OPTIONAL``."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            targets = n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        else:
            targets = []
        if any(isinstance(s, ast.Attribute) and s.attr in _WEAKENING_ATTRS
               for t in targets for s in ast.walk(t)):
            out.append(n.lineno)
        elif (isinstance(n, ast.Call) and _call_name(n) in ("setattr", "__setattr__")
              and isinstance(n.func, (ast.Name, ast.Attribute))
              and any(isinstance(a, ast.Constant) and a.value in _WEAKENING_ATTRS
                      for a in n.args[:2])):
            out.append(n.lineno)
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in _WEAKENING_CALLS):
            out.append(n.lineno)
        elif isinstance(n, (ast.Attribute, ast.Name)) and _owner_name(n) in _WEAK_CONSTANTS:
            out.append(n.lineno)
    return out


def _verify_false(tree: ast.AST) -> list[tuple[int, str]]:
    """``(line, enclosing function)`` of each call passing a literal
    ``verify=False`` (httpx/requests turn peer verification off)."""
    return [(n.lineno, enclosing_fn(n)) for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and any(k.arg == "verify" and isinstance(k.value, ast.Constant)
                    and k.value.value is False for k in n.keywords)]


def _ssl_class_escapes(tree: ast.AST) -> list[int]:
    """Lines where an ``IMAP4_SSL``/``SMTP_SSL``/``POP3_SSL`` reference escapes
    the constructor scan: a load that is not the callee of a call (alias
    variable, ``partial``, an argument), a ``getattr(x, "<class>")``, or a
    renamed import."""
    callees = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, (ast.Attribute, ast.Name)) and isinstance(n.ctx, ast.Load)
                and _owner_name(n) in _SSL_CLASSES and id(n) not in callees):
            out.append(n.lineno)
        elif (isinstance(n, ast.Call) and _call_name(n) == "getattr"
              and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
              and n.args[1].value in _SSL_CLASSES):
            out.append(n.lineno)
        elif isinstance(n, ast.ImportFrom) and any(
                a.name in _SSL_CLASSES and a.asname for a in n.names):
            out.append(n.lineno)
    return out


def _constructions(tree: ast.AST, names: frozenset[str]) -> list[int]:
    """Lines that call one of ``names``, reference one without calling it on
    the spot (an alias variable, or the global
    ``ssl._create_default_https_context = ssl._create_unverified_context``
    idiom, panel K db-sme FC-1), reach one through a ``getattr(x, "<name>")``
    string, or import one under another name."""
    callees = {id(c.func) for c in ast.walk(tree) if isinstance(c, ast.Call)}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _call_name(n) in names:
            out.append(n.lineno)
        elif (isinstance(n, (ast.Attribute, ast.Name)) and _owner_name(n) in names
              and id(n) not in callees):
            out.append(n.lineno)
        elif (isinstance(n, ast.Call) and _call_name(n) == "getattr"
              and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
              and n.args[1].value in names):
            out.append(n.lineno)
        elif isinstance(n, ast.ImportFrom) and any(
                a.name in names and a.asname for a in n.names):
            out.append(n.lineno)
    return out


def _direct_context_refs(tree: ast.AST) -> list[int]:
    """Lines naming ``client_tls_context`` / ``_unverified_tls_context`` (a call,
    a reference, an import or a ``getattr`` string): outside tls.py a context
    must come from a mode helper."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.Name, ast.Attribute)) and _owner_name(n) in _DIRECT_CONTEXT_NAMES:
            out.append(n.lineno)
        elif isinstance(n, ast.ImportFrom) and any(
                a.name in _DIRECT_CONTEXT_NAMES for a in n.names):
            out.append(n.lineno)
        elif (isinstance(n, ast.Call) and _call_name(n) == "getattr" and len(n.args) >= 2
              and isinstance(n.args[1], ast.Constant)
              and n.args[1].value in _DIRECT_CONTEXT_NAMES):
            out.append(n.lineno)
    return out


def _tls_site_without_mode_helper(tree: ast.AST) -> list[int]:
    """Lines of an ``IMAP4_SSL(``/``SMTP_SSL(``/``POP3_SSL(`` construction or a
    ``.starttls(``/``.stls(`` call in a module that never calls a mode helper."""
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    if any(_call_name(c) in _MODE_HELPERS for c in calls):
        return []
    return [c.lineno for c in calls
            if _call_name(c) in _SSL_CLASSES
            or (isinstance(c.func, ast.Attribute) and c.func.attr in _STARTTLS_NAMES)]


def _modules():
    for p in iter_src_files():
        tree = parse_module(p)
        assert tree is not None, f"unparseable: {relpath(p)}"
        yield relpath(p), tree


# ---- behavioural ----------------------------------------------------------

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _default_policy(monkeypatch):
    """The default mode (check on, enforce off), whatever an earlier test bound."""
    from email_triage import tls
    monkeypatch.setattr(tls, "_bound_config", None)

class _FakeSMTP:
    instances: list["_FakeSMTP"] = []

    def __init__(self, host, port, timeout=None):
        self.calls: list[str] = []
        self.context = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, *, context=None):
        self.calls.append("starttls")
        self.context = context

    def login(self, user, password):
        self.calls.append("login")

    def send_message(self, msg):
        self.calls.append("send_message")


def _send(monkeypatch, *, use_tls: bool) -> _FakeSMTP:
    from email_triage.web import smtp_send

    _FakeSMTP.instances = []
    monkeypatch.setattr(smtp_send.smtplib, "SMTP", _FakeSMTP)
    smtp_send.send_smtp_message(
        EmailMessage(), smtp_host="relay.example.invalid", smtp_port=587,
        smtp_user="u", smtp_password="p", use_tls=use_tls,
    )
    assert len(_FakeSMTP.instances) == 1
    return _FakeSMTP.instances[0]


def test_starttls_gets_a_verifying_context_before_login(monkeypatch):
    server = _send(monkeypatch, use_tls=True)
    ctx = server.context
    assert isinstance(ctx, ssl.SSLContext), (
        "starttls() got no context: smtplib falls back to CERT_NONE (punch 645)"
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert server.calls == ["starttls", "login", "send_message"]


def test_use_tls_false_never_calls_starttls(monkeypatch):
    server = _send(monkeypatch, use_tls=False)
    assert "starttls" not in server.calls
    assert server.calls == ["login", "send_message"]


def test_client_tls_context_verifies():
    from email_triage.tls import client_tls_context

    ctx = client_tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert client_tls_context() is not ctx, "a shared mutable context would leak settings"



class _FakeIMAP:
    def __init__(self, host, port, *, ssl_context=None):
        self.ssl_context = ssl_context


def test_imap_connect_hands_imap4_ssl_a_verifying_context(monkeypatch):
    """The stdlib fetch path (``imap_blocking``: single fetch, batch fetch,
    cross-folder search) gets the verifying context when its caller passes none."""
    from email_triage.providers import imap_fetch_transport as t

    monkeypatch.setattr(t.imaplib, "IMAP4_SSL", _FakeIMAP)
    _assert_verifying(t.imap_connect("imap.example.invalid", 993).ssl_context)
    _assert_verifying(
        t.imap_connect("imap.example.invalid", 993, ssl_context=None).ssl_context
    )


def test_imap_connect_plain_builds_no_context(monkeypatch):
    from email_triage.providers import imap_fetch_transport as t

    built = []
    monkeypatch.setattr(t.imaplib, "IMAP4", lambda h, p: built.append((h, p)) or "plain")
    monkeypatch.setattr(t.imaplib, "IMAP4_SSL", _FakeIMAP)
    assert t.imap_connect("h.invalid", 143, use_ssl=False) == "plain"
    assert built == [("h.invalid", 143)]


def test_aioimaplib_connect_hands_imap4_ssl_a_verifying_context(monkeypatch):
    """aioimaplib 2.0.1 already verifies by default; the SSOT passes the context
    explicitly so a library default cannot decide it. The fake has no
    connection task, so the verifying client is returned as built."""
    import sys
    import types

    from email_triage.providers import imap_fetch_transport as t

    fake = types.ModuleType("aioimaplib")

    class _FakeAsync:
        def __init__(self, host=None, port=None, *, ssl_context=None):
            self.ssl_context = ssl_context

    fake.IMAP4_SSL = _FakeAsync
    fake.IMAP4 = lambda host=None, port=None: "plain"
    monkeypatch.setitem(sys.modules, "aioimaplib", fake)
    _assert_verifying(
        asyncio.run(t.aioimaplib_connect("imap.example.invalid", 993)).ssl_context
    )
    assert asyncio.run(t.aioimaplib_connect("h.invalid", 143, use_ssl=False)) == "plain"


def test_each_mode_hands_out_the_right_context(monkeypatch):
    """Teeth per mode at the helper: off -> CERT_NONE with no hostname check;
    validate -> the verifying context first, the unverified one only after a
    certificate failure; enforce -> CertCheckRefused, never an unverified one."""
    from email_triage import tls

    seen = []

    def connect_ok(ctx):
        seen.append(ctx)
        return types_ns()

    def connect_bad(ctx):
        seen.append(ctx)
        if ctx.verify_mode == ssl.CERT_REQUIRED:
            raise ssl.SSLCertVerificationError(1, "certificate verify failed: self-signed")
        return types_ns()

    import types
    types_ns = types.SimpleNamespace
    monkeypatch.setattr(tls, "_logger", lambda: types_ns(warning=lambda *a, **k: None))
    monkeypatch.setattr(tls, "_cert_log_last", {})
    off = tls.CertPolicy(check=False)
    validate = tls.CertPolicy(check=True, enforce=False)
    enforce = tls.CertPolicy(check=True, enforce=True)

    tls.tls_connect(connect_ok, host="h.invalid", port=1, protocol="p", policy=off)
    assert seen[-1].verify_mode == ssl.CERT_NONE and seen[-1].check_hostname is False

    seen.clear()
    r = tls.tls_connect(connect_ok, host="h.invalid", port=1, protocol="p", policy=validate)
    assert len(seen) == 1 and r._et_cert_verdict == "verified"
    _assert_verifying(seen[0])

    seen.clear()
    r = tls.tls_connect(connect_bad, host="h.invalid", port=1, protocol="p", policy=validate)
    assert [c.verify_mode for c in seen] == [ssl.CERT_REQUIRED, ssl.CERT_NONE]
    assert r._et_cert_verdict == "failed"

    seen.clear()
    with pytest.raises(tls.CertCheckRefused, match="h.invalid:1"):
        tls.tls_connect(connect_bad, host="h.invalid", port=1, protocol="p", policy=enforce)
    assert [c.verify_mode for c in seen] == [ssl.CERT_REQUIRED]

    def connect_other(ctx):
        raise ConnectionRefusedError("down")
    with pytest.raises(ConnectionRefusedError):
        tls.tls_connect(connect_other, host="h.invalid", port=1, protocol="p", policy=validate)


# ---- structural -----------------------------------------------------------

def test_every_starttls_passes_a_context():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if (locs := _starttls_without_context(tree))]
    assert not offenders, (
        f"starttls()/stls() without a context: {offenders}. The stdlib default is "
        "CERT_NONE with no hostname check; pass context=client_tls_context() "
        "(email_triage.tls)."
    )


def test_every_ssl_client_construction_passes_a_context():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if (locs := _ssl_constructor_without_context(tree))]
    assert not offenders, (
        f"IMAP4_SSL/SMTP_SSL/POP3_SSL without ssl_context=/context=: {offenders}. "
        "The stdlib default is CERT_NONE with no hostname check; pass "
        "client_tls_context() (email_triage.tls)."
    )


def test_no_context_is_weakened_outside_tls_py():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if rel != SSOT_REL and (locs := _context_weakened(tree))]
    assert not offenders, (
        f"verify_mode/check_hostname assigned or CERT_NONE/CERT_OPTIONAL named "
        f"outside tls.py: {offenders}. That undoes client_tls_context() (punch 657)."
    )


def test_no_ssl_client_class_escapes_the_constructor_scan():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if (locs := _ssl_class_escapes(tree))]
    assert not offenders, (
        f"IMAP4_SSL/SMTP_SSL/POP3_SSL referenced outside a direct call: {offenders}. "
        "Construct it in place so the context check can see the call."
    )


def test_no_verify_false_outside_the_allow_list():
    offenders = [f"{rel}:{line} ({fn})" for rel, tree in _modules()
                 for line, fn in _verify_false(tree)
                 if (rel, fn) not in _VERIFY_FALSE_ALLOW]
    assert not offenders, (
        f"verify=False outside _VERIFY_FALSE_ALLOW: {offenders}. It turns peer "
        "verification off; add a (file, function) entry with a reason only if "
        "that is intended."
    )


def test_verify_false_allow_list_has_no_dead_entries():
    found = {(rel, fn) for rel, tree in _modules() for _line, fn in _verify_false(tree)}
    dead = [k for k in _VERIFY_FALSE_ALLOW if k not in found]
    assert not dead, f"_VERIFY_FALSE_ALLOW entries with nothing to exempt: {dead}"


def test_client_contexts_are_built_only_in_tls_py():
    offenders = []
    for rel, tree in _modules():
        if rel == SSOT_REL or rel in _ALLOW:
            continue
        if locs := _constructions(tree, _CONSTRUCTORS):
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        f"ssl context constructed outside tls.py: {offenders}. Call "
        "email_triage.tls.client_tls_context(), or add an _ALLOW entry with a reason."
    )


def test_no_unverified_stdlib_constructor_anywhere():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if (locs := _constructions(tree, _UNVERIFIED))]
    assert not offenders, f"unverified ssl context constructor in src: {offenders}"


def test_allow_list_has_no_dead_entries():
    rels = {rel: tree for rel, tree in _modules()}
    dead = [k for k in _ALLOW
            if k not in rels or not _constructions(rels[k], _CONSTRUCTORS)]
    assert not dead, f"_ALLOW entries with nothing to exempt: {dead}"


def test_contexts_come_only_from_the_mode_helpers():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if rel != SSOT_REL and (locs := _direct_context_refs(tree))]
    assert not offenders, (
        f"client_tls_context/_unverified_tls_context named outside tls.py: {offenders}. "
        "Get the context from a mode helper (tls_connect / tls_connect_async / "
        "mode_context) so cert_check / cert_enforce apply."
    )


def test_every_tls_site_routes_through_a_mode_helper():
    offenders = [f"{rel}:{locs}" for rel, tree in _modules()
                 if rel != SSOT_REL and (locs := _tls_site_without_mode_helper(tree))]
    assert not offenders, (
        f"IMAP4_SSL/SMTP_SSL/starttls in a module that calls no mode helper: {offenders}."
    )


def test_the_pin_is_not_vacuous():
    """The SSOTs still hold what the pins quantify over, so a deleted call
    cannot read as green."""
    smtp_tree = parse_module(SRC_ROOT / "web" / "smtp_send.py")
    assert smtp_tree is not None
    starttls = [n for n in ast.walk(smtp_tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == "starttls"]
    assert starttls, f"{SMTP_SSOT_REL} no longer calls starttls"
    tls_tree = parse_module(SRC_ROOT / SSOT_REL)
    assert tls_tree is not None
    assert _constructions(tls_tree, _CONSTRUCTORS), "tls.py builds no ssl context"
    imap_tree = parse_module(SRC_ROOT / "providers" / "imap_fetch_transport.py")
    assert imap_tree is not None
    assert len(_constructions(imap_tree, _SSL_CLASSES)) >= 2, (
        "the IMAP SSOT no longer constructs IMAP4_SSL on both its paths"
    )
    for rel in ("providers/imap_fetch_transport.py", "web/smtp_send.py"):
        tree = parse_module(SRC_ROOT / rel)
        assert any(isinstance(n, ast.Call) and _call_name(n) in _MODE_HELPERS
                   for n in ast.walk(tree)), f"{rel} calls no mode helper"


def test_the_pins_have_teeth():
    assert_pin_has_teeth(
        _starttls_without_context,
        "import smtplib\ndef f(s):\n    smtplib.SMTP.starttls(s)\n",
        "import smtplib\ndef f(s, c):\n    smtplib.SMTP.starttls(s, context=c)\n",
    )
    assert_pin_has_teeth(
        _starttls_without_context,
        "def f(s):\n    getattr(s, 'starttls')()\n",
    )
    assert_pin_has_teeth(
        _ssl_constructor_without_context,
        "import imaplib\nc = imaplib.IMAP4_SSL('h', 993)\n",
        "import imaplib\ndef f(x):\n    return imaplib.IMAP4_SSL('h', 993, ssl_context=x)\n",
    )
    assert_pin_has_teeth(
        _ssl_constructor_without_context,
        "import aioimaplib\nc = aioimaplib.IMAP4_SSL(host='h', port=993, ssl_context=None)\n",
    )
    assert_pin_has_teeth(
        _ssl_constructor_without_context,
        "from smtplib import SMTP_SSL\nc = SMTP_SSL('h', 465)\n",
    )
    assert_pin_has_teeth(
        _context_weakened,
        "def f(ctx):\n    ctx.check_hostname = False\n",
        "def f(ctx):\n    return ctx.check_hostname\n",
    )
    assert_pin_has_teeth(
        _context_weakened,
        "import ssl\ndef f(ctx):\n    ctx.verify_mode = ssl.CERT_NONE\n",
    )
    assert_pin_has_teeth(
        _context_weakened,
        "def f(ctx):\n    setattr(ctx, 'verify_mode', 0)\n",
    )
    assert_pin_has_teeth(
        _context_weakened,
        "from ssl import CERT_OPTIONAL\nmode = CERT_OPTIONAL\n",
    )
    for bad in (
        "import ssl\ndef f(ctx):\n    ctx.options |= ssl.OP_NO_TLSv1_3\n",
        "import ssl\ndef f(ctx):\n    ctx.minimum_version = ssl.TLSVersion.SSLv3\n",
        "def f(ctx):\n    ctx.set_ciphers('ALL:@SECLEVEL=0')\n",
        "def f(ctx):\n    ctx.load_verify_locations('/tmp/any.pem')\n",
    ):
        assert_pin_has_teeth(_context_weakened, bad)
    assert_pin_has_teeth(
        _context_weakened,
        "def f(ctx):\n    ctx.__setattr__('verify_mode', 0)\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _UNVERIFIED),
        "from ssl import _create_unverified_context as u\nctx = u()\n",
        "from ssl import create_default_context\nctx = create_default_context()\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _UNVERIFIED),
        "import ssl\nctx = getattr(ssl, '_create_stdlib_context')()\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _CONSTRUCTORS),
        "from ssl import SSLContext as C\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _UNVERIFIED),
        "import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _CONSTRUCTORS),
        "import ssl\nK = ssl.SSLContext\nctx = K(ssl.PROTOCOL_TLS_CLIENT)\n",
    )
    assert_pin_has_teeth(
        _verify_false,
        "import httpx\nc = httpx.Client(verify=False)\n",
        "import httpx\nc = httpx.Client(verify=True)\n",
    )
    assert_pin_has_teeth(
        _ssl_class_escapes,
        "import imaplib\nK = imaplib.IMAP4_SSL\n",
        "import imaplib\ndef f(c):\n    return imaplib.IMAP4_SSL('h', 993, ssl_context=c)\n",
    )
    for bad in (
        "import functools, imaplib\nf = functools.partial(imaplib.IMAP4_SSL, 'h')\n",
        "import imaplib\nK = getattr(imaplib, 'IMAP4_SSL')\n",
        "from smtplib import SMTP_SSL as S\n",
    ):
        assert_pin_has_teeth(_ssl_class_escapes, bad)
    assert_pin_has_teeth(
        _starttls_without_context,
        "def f(s):\n    s.starttls()\n",
        "def f(s, c):\n    s.starttls(context=c)\n",
    )
    assert_pin_has_teeth(
        _starttls_without_context,
        "def f(s):\n    s.starttls(context=None)\n",
        "def f(s, c):\n    s.starttls(c)\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _CONSTRUCTORS),
        "import ssl\nctx = ssl.create_default_context()\n",
        "from email_triage.tls import client_tls_context\nctx = client_tls_context()\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _CONSTRUCTORS),
        "from ssl import SSLContext, PROTOCOL_TLS_CLIENT\nctx = SSLContext(PROTOCOL_TLS_CLIENT)\n",
    )
    assert_pin_has_teeth(
        lambda t: _constructions(t, _UNVERIFIED),
        "import ssl\nctx = ssl._create_unverified_context()\n",
        "import ssl\nctx = ssl.create_default_context()\n",
    )
    assert_pin_has_teeth(
        _direct_context_refs,
        "from email_triage.tls import client_tls_context\nctx = client_tls_context()\n",
        "from email_triage.tls import tls_connect\nc = tls_connect(f, host=h, port=1, protocol='p')\n",
    )
    for bad in (
        "from email_triage import tls\nctx = tls._unverified_tls_context()\n",
        "from email_triage import tls\nmk = tls.client_tls_context\n",
        "from email_triage import tls\nctx = getattr(tls, '_unverified_tls_context')()\n",
    ):
        assert_pin_has_teeth(_direct_context_refs, bad)
    assert_pin_has_teeth(
        _tls_site_without_mode_helper,
        "import imaplib\ndef f(c):\n    return imaplib.IMAP4_SSL('h', 993, ssl_context=c)\n",
        "import imaplib\nfrom email_triage.tls import tls_connect\ndef f():\n"
        "    return tls_connect(lambda c: imaplib.IMAP4_SSL('h', 993, ssl_context=c),"
        " host='h', port=993, protocol='imap')\n",
    )
    assert_pin_has_teeth(
        _tls_site_without_mode_helper,
        "def f(s, c):\n    s.starttls(context=c)\n",
    )
