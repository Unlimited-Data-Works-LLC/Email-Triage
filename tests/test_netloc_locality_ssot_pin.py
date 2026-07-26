"""Destination-locality predicate — SSOT + no-string-prefix-RFC1918 pin
(divergence census 2026-06-09, egress class #2 — locality sub-finding).

The "is this URL a local (non-internet) destination?" decision is the
carve-out behind two egress gates: the webhook external-target gate
(``web/events.is_local_webhook_url``) and the **PHI→LLM BAA gate**
(``classify/base._is_local_host``, a §164.502(e) control). Before this fix
those were byte-identical duplicates using STRING-PREFIX RFC1918 matching
(``host.startswith("10.")``), which **fail-OPENs**: ``10.evil.com`` (a
hostname, not an IP) ``startswith("10.")`` → classified local → PHI could
egress to an external host. Both now delegate to the single hardened SSOT
``_netloc.is_local_destination`` (ipaddress-based private-IP classification).

Three property-tests keep it from re-diverging (never ``len()==N``):
  1. the string-prefix RFC1918 idiom (``"192.168."`` literal) lives nowhere
     in live code outside the SSOT module — a re-inlined copy is the bug;
  2. ``is_local_destination`` is defined exactly once (in ``_netloc.py``);
  3. the two wrappers delegate to it (don't re-implement the decision).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, walk_src  # N-350 R31

# ``SRC_ROOT`` is the package root (``src/email_triage``) — the SAME base this
# pin used for its old ``SRC`` constant, so the relpath form (``web/db.py``)
# and the ``_ALLOWED_IP_ATTR_FILES`` allow-list keys are unchanged.
SSOT = SRC_ROOT / "_netloc.py"

# Distinctive sentinel of the string-prefix RFC1918 idiom. A real URL-locality
# re-implementation uses ``host.startswith("192.168.")``; nothing else has a
# reason to carry this exact literal as code.
_STRINGPREFIX_SENTINEL = "192.168."


def _has_constant(tree: ast.AST, needle: str) -> list[int]:
    """Line numbers of string CONSTANTS equal to needle (NOT comments — a
    comment mentioning the old idiom is fine; a live string literal is not)."""
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and n.value == needle
    ]


def test_no_string_prefix_rfc1918_outside_ssot():
    offenders = []
    for p, rel, tree in walk_src():
        if p == SSOT:
            continue  # the SSOT mentions the old idiom only in its docstring
        locs = _has_constant(tree, _STRINGPREFIX_SENTINEL)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "String-prefix RFC1918 locality idiom re-inlined outside _netloc.py "
        f"(the fail-open the census fixed — a hostname like '192.168.evil.com' "
        f"would be mis-classified local): {offenders}. Call "
        "email_triage._netloc.is_local_destination instead."
    )


def test_is_local_destination_defined_once_in_ssot():
    defs = []
    for p, rel, tree in walk_src():
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef) and n.name == "is_local_destination":
                defs.append(f"{rel}:{n.lineno}")
    assert defs == [f"_netloc.py:{_ssot_def_line()}"], (
        f"is_local_destination must be defined exactly once in _netloc.py; found {defs}"
    )


def _ssot_def_line() -> int:
    tree = parse_module(SSOT); assert tree is not None  # N-350 R31
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == "is_local_destination":
            return n.lineno
    raise AssertionError("is_local_destination vanished from _netloc.py")


def test_wrappers_delegate_to_ssot():
    """The two known destination-locality gates route through the SSOT rather
    than re-implementing the decision."""
    events = (SRC_ROOT / "web" / "events.py").read_text(encoding="utf-8")
    base = (SRC_ROOT / "classify" / "base.py").read_text(encoding="utf-8")
    assert "is_local_destination" in events, "events.is_local_webhook_url no longer delegates to the SSOT"
    assert "is_local_destination" in base, "classify.base._is_local_host no longer delegates to the SSOT"


# ---- teeth -------------------------------------------------------------
def test_pin_has_teeth_string_prefix(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        'def is_local(host):\n    return host.startswith("192.168.")\n',
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _has_constant(tree, _STRINGPREFIX_SENTINEL)


def test_pin_has_teeth_comment_is_not_flagged(tmp_path):
    """A comment mentioning the old idiom must NOT trip the pin (only a live
    string literal does)."""
    ok = tmp_path / "p.py"
    ok.write_text(
        "# was host.startswith('192.168.') — now delegates\n"
        "from email_triage._netloc import is_local_destination\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _has_constant(tree, _STRINGPREFIX_SENTINEL)


# The bind-axis classifier (`transmission_security._is_public_internet_routable`)
# legitimately uses ipaddress attributes for its OWN (opposite-polarity) question.
# It is the ONLY place `ip.is_private` / `ip.is_link_local` may drive a decision.
_ALLOWED_IP_ATTR_FILES = {"web/transmission_security.py"}


def test_no_is_private_locality_attribute_outside_bind_axis():
    """`ip.is_private` INCLUDES link-local (169.254.0.0/16 — the cloud-metadata
    SSRF target). Using it (or `.is_link_local`) for a DESTINATION-locality /
    SSRF decision re-opens the fail-open the SSOT closes — and carries no
    "192.168." literal, so it slips the string-prefix pin (DA MUST-FIX 2026-06-09).
    Forbid the attribute everywhere except the bind-axis classifier; the SSOT
    itself uses the explicit `_LOCAL_NETS` allow-list, NOT `.is_private`."""
    offenders = []
    for p, rel, tree in walk_src():
        if rel in _ALLOWED_IP_ATTR_FILES:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute) and n.attr in ("is_private", "is_link_local"):
                offenders.append(f"{rel}:{n.lineno} (.{n.attr})")
    assert not offenders, (
        "An ipaddress `.is_private`/`.is_link_local` locality decision appeared "
        f"outside the bind-axis: {offenders}. `.is_private` admits link-local "
        "169.254.169.254 (cloud-metadata SSRF). Use _netloc.is_local_destination "
        "(the specific _LOCAL_NETS set) instead."
    )


def test_metadata_ip_is_external_through_every_live_gate():
    """The property that actually matters, asserted AT THE CONSUMER GATES (a
    re-inline replaces the SSOT call path, so SSOT-only behavior tests don't
    protect it). 169.254.169.254 + fe80:: must be EXTERNAL through both gates."""
    from email_triage.web.events import is_local_webhook_url
    from email_triage.classify.base import _is_local_host
    for gate in (is_local_webhook_url, _is_local_host):
        assert gate("http://169.254.169.254/") is False, f"{gate.__name__} SSRF fail-open"
        assert gate("http://[fe80::1]/") is False
        # legit local still works through the gate:
        assert gate("http://127.0.0.1:11434") is True
        assert gate("http://10.0.0.5:11434") is True


def test_pin_has_teeth_is_private_reinline(tmp_path):
    """The teeth for the structural guard: a re-inline via `.is_private` is caught."""
    bad = tmp_path / "m.py"
    bad.write_text(
        "import ipaddress\n"
        "def is_local(host):\n"
        "    return ipaddress.ip_address(host).is_private\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    hits = [n for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr in ("is_private", "is_link_local")]
    assert hits, "the .is_private re-inline must be detectable"


# ---------------------------------------------------------------------------
#  — pin_local_endpoint: the resolver-grounded SSRF gate (resolve every
# A/AAAA, require ALL local, PIN the connect to the validated IP). Unlike
# is_local_destination it does NOT trust `.local` / suffixes by string.
# ---------------------------------------------------------------------------

import socket as _socket  # noqa: E402
from unittest.mock import patch  # noqa: E402
from urllib.parse import urlparse  # noqa: E402


def _fake_getaddrinfo(*ips):
    """A getaddrinfo stand-in returning the given IP strings (hermetic — no
    real DNS). AF inferred from a ':' so IPv6 literals classify correctly."""
    def _f(host, port, *a, **k):
        return [
            (_socket.AF_INET6 if ":" in ip else _socket.AF_INET,
             _socket.SOCK_STREAM, 0, "", (ip, port or 0))
            for ip in ips
        ]
    return _f


def _gaierror(*a, **k):
    raise _socket.gaierror("name resolution failed")


class TestPinLocalEndpoint:
    def test_ip_literal_local_pinned_through(self):
        from email_triage._netloc import pin_local_endpoint
        assert pin_local_endpoint("http://10.0.0.5:11434/api") == "http://10.0.0.5:11434/api"

    def test_ip_literal_metadata_rejected(self):
        from email_triage._netloc import pin_local_endpoint
        assert pin_local_endpoint("http://169.254.169.254/") is None

    def test_ip_literal_public_rejected(self):
        from email_triage._netloc import pin_local_endpoint
        assert pin_local_endpoint("https://8.8.8.8/") is None

    def test_hostname_resolving_local_is_pinned_to_ip(self):
        """A homelab name resolving to a private IP → pinned to that IP, port +
        path preserved (so the connect can't be rebound to another address)."""
        from email_triage._netloc import pin_local_endpoint
        with patch("email_triage._netloc.socket.getaddrinfo",
                   _fake_getaddrinfo("192.168.1.5")):
            out = pin_local_endpoint("http://ollama.home.lan:11434/api/tags")
        assert out == "http://192.168.1.5:11434/api/tags"

    def test_hostname_resolving_public_rejected(self):
        from email_triage._netloc import pin_local_endpoint
        with patch("email_triage._netloc.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")):
            assert pin_local_endpoint("https://example.com/") is None

    def test_mixed_records_fail_closed(self):
        """The rebinding / round-robin defense: ANY non-local resolved address
        rejects the whole endpoint."""
        from email_triage._netloc import pin_local_endpoint
        with patch("email_triage._netloc.socket.getaddrinfo",
                   _fake_getaddrinfo("192.168.1.5", "203.0.113.9")):
            assert pin_local_endpoint("http://rebind.evil/") is None

    def test_dot_local_resolving_metadata_rejected(self):
        """ core: a `.local` name (trusted by STRING in the lenient BAA gate)
        is RESOLVED here — pointing it at the metadata IP is rejected."""
        from email_triage._netloc import pin_local_endpoint
        with patch("email_triage._netloc.socket.getaddrinfo",
                   _fake_getaddrinfo("169.254.169.254")):
            assert pin_local_endpoint("http://metadata.local/") is None

    def test_unresolvable_rejected(self):
        from email_triage._netloc import pin_local_endpoint
        with patch("email_triage._netloc.socket.getaddrinfo", _gaierror):
            assert pin_local_endpoint("http://nope.invalid/") is None

    def test_localhost_pins_to_loopback_hermetic(self):
        """localhost resolves to loopback with no external DNS."""
        from email_triage._netloc import pin_local_endpoint
        out = pin_local_endpoint("http://localhost:11434")
        assert out is not None
        assert urlparse(out).hostname in ("127.0.0.1", "::1")

    def test_ipv6_ula_literal_bracketed(self):
        from email_triage._netloc import pin_local_endpoint
        assert pin_local_endpoint("http://[fd00::1]:8080/api") == "http://[fd00::1]:8080/api"

    def test_malformed_url_rejected(self):
        from email_triage._netloc import pin_local_endpoint
        assert pin_local_endpoint("") is None
        assert pin_local_endpoint("not a url") is None


def test_ssot_behavior_fail_open_closed():
    """The fix itself: a hostname starting '10.'/'192.168.' is NOT local."""
    from email_triage._netloc import is_local_destination
    assert is_local_destination("http://10.evil.com") is False
    assert is_local_destination("http://192-168-1-1.attacker.net") is False
    # legit RFC1918 IP literals + IPv6 ULA stay local:
    assert is_local_destination("http://10.0.0.5:11434") is True
    assert is_local_destination("http://192.168.1.10") is True
    assert is_local_destination("http://[fd00::1]:8080") is True
    assert is_local_destination("https://api.openai.com") is False
    # SSRF: the cloud-metadata link-local IP MUST be external (not "local"),
    # else the probe/webhook SSRF guards fail open. `ipaddress.is_private`
    # would wrongly include it — the SSOT uses the specific _LOCAL_NETS set.
    assert is_local_destination("http://169.254.169.254/") is False
    assert is_local_destination("http://[fe80::1]/") is False
