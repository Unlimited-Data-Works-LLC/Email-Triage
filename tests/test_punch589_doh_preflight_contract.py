"""Punch 589: the ACME CNAME pre-flight queries only resolvers it can reach,
never substitutes a provider the operator did not name, and says which
endpoint it asked.

Before the fix: Quad9 (9.9.9.9) was mapped to ``https://dns.quad9.net/dns-query``,
which answers this HTTP/1.1 JSON request with HTTP 505 (Quad9 retired HTTP/1.1
for DoH on 2025-12-15; measured 505 again 2026-10-10), and any IP missing from
the map was silently sent to ``dns.google`` while the diagnostics named the
configured IP.

The contract tests below drive a REAL ``httpx.Client`` (built by the real
``egress_client`` funnel, so request construction and the egress hook run) with
an ``httpx.MockTransport`` at the transport boundary, answering with replies
captured from the live services on 2026-10-10:

    curl --http1.1 -H 'accept: application/dns-json' \\
      'https://dns.google/resolve?name=www.github.com.&type=CNAME'
    curl --http1.1 -H 'accept: application/dns-json' \\
      'https://cloudflare-dns.com/dns-query?name=www.github.com.&type=CNAME'

Shape references: Google's JSON API doc
(https://developers.google.com/speed/public-dns/docs/doh/json) and Cloudflare's
(https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/),
which states it follows Google's schema. Note the real difference the fixtures
keep: Cloudflare's ``Answer[].name`` has no trailing dot, Google's does.
"""
from __future__ import annotations

import ast
import json
from collections.abc import Callable

import httpx
import pytest

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    iter_src_files,
    iter_string_literals,
    parse_module,
    relpath,
)
from email_triage.config import (
    DEFAULT_PUBLIC_RESOLVERS,
    DOH_JSON_ENDPOINTS,
    TriageConfig,
    validate_config,
)
from email_triage.web.acme_renewer import cname_preflight

# --- genuine replies, verbatim from the live services (2026-10-10) ----------

GOOGLE_CNAME = (
    '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,'
    '"Question":[{"name":"www.github.com.","type":5}],'
    '"Answer":[{"name":"www.github.com.","type":5,"TTL":3586,"data":"github.com."}]}'
)
CLOUDFLARE_CNAME = (
    '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,'
    '"Question":[{"name":"www.github.com","type":5}],'
    '"Answer":[{"name":"www.github.com","type":5,"TTL":3600,"data":"github.com."}]}'
)
GOOGLE_NXDOMAIN = (
    '{"Status":3,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,'
    '"Question":[{"name":"_acme-challenge.nonexistent-zz9-probe.example.","type":5}],'
    '"Authority":[{"name":".","type":6,"TTL":86030,"data":"a.root-servers.net. '
    'nstld.verisign-grs.com. 2026101001 1800 900 604800 86400"}]}'
)
CLOUDFLARE_NXDOMAIN = (
    '{"Status":3,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,'
    '"Question":[{"name":"_acme-challenge.nonexistent-zz9-probe.example","type":5}],'
    '"Authority":[{"name":"","type":6,"TTL":86400,"data":"a.root-servers.net. '
    'nstld.verisign-grs.com. 2026101001 1800 900 604800 86400"}]}'
)

GOOGLE = "https://dns.google/resolve"
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"


def _with_target(reply: str, target: str) -> str:
    """The captured reply with its CNAME target swapped (shape untouched)."""
    data = json.loads(reply)
    data["Answer"][0]["data"] = target
    return json.dumps(data)


@pytest.fixture
def transport(monkeypatch):
    """Route the pre-flight's real egress client through a MockTransport.

    Returns ``(set_handler, requests)``: ``set_handler(fn)`` installs
    ``fn(request) -> httpx.Response``; ``requests`` collects every request the
    real client sent.
    """
    import email_triage._egress as egress

    real = egress.egress_client
    seen: list[httpx.Request] = []
    state: dict[str, Callable[[httpx.Request], httpx.Response]] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return state["fn"](request)

    def _client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real(**kwargs)

    monkeypatch.setattr(egress, "egress_client", _client)
    return (lambda fn: state.__setitem__("fn", fn)), seen


def _endpoint(request: httpx.Request) -> str:
    return f"{request.url.scheme}://{request.url.host}{request.url.path}"


# --- contract: the real reply shapes ----------------------------------------

@pytest.mark.parametrize("resolver,reply", [
    ("8.8.8.8", GOOGLE_CNAME), ("1.1.1.1", CLOUDFLARE_CNAME),
])
def test_real_reply_shape_confirms_a_cname_under_the_zone(transport, resolver, reply):
    set_handler, seen = transport
    set_handler(lambda r: httpx.Response(
        200, text=_with_target(reply, "triage.acme.example.com."),
        headers={"content-type": "application/dns-json"}))
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=[resolver])
    assert ok is True, msgs
    (req,) = seen
    assert _endpoint(req) == DOH_JSON_ENDPOINTS[resolver]
    assert req.url.params["name"] == "_acme-challenge.triage.example.com."
    assert req.url.params["type"] == "CNAME"
    assert req.headers["accept"] == "application/dns-json"


@pytest.mark.parametrize("resolver,reply", [
    ("8.8.8.8", GOOGLE_NXDOMAIN), ("1.1.1.1", CLOUDFLARE_NXDOMAIN),
])
def test_real_nxdomain_reply_fails_and_names_the_endpoint(transport, resolver, reply):
    set_handler, _seen = transport
    set_handler(lambda r: httpx.Response(200, text=reply))
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=[resolver])
    assert ok is False
    assert any("NXDOMAIN" in m and DOH_JSON_ENDPOINTS[resolver] in m
               and resolver in m for m in msgs), msgs


def test_real_reply_with_wrong_target_names_the_endpoint(transport):
    set_handler, _seen = transport
    set_handler(lambda r: httpx.Response(200, text=GOOGLE_CNAME))  # -> github.com.
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"])
    assert ok is False
    assert any("'github.com.'" in m and GOOGLE in m for m in msgs), msgs


# --- no substitution, documented skip ---------------------------------------

def test_prod_resolver_list_passes_when_any_listed_resolver_confirms(transport):
    """Prod: 8.8.8.8, 1.1.1.1, 9.9.9.9. Google confirms, Cloudflare lags,
    Quad9 is skipped by name: the domain passes."""
    assert list(DEFAULT_PUBLIC_RESOLVERS) == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    set_handler, seen = transport

    def _h(r):
        if r.url.host == "dns.google":
            return httpx.Response(200, text=_with_target(GOOGLE_CNAME, "triage.acme.example.com."))
        return httpx.Response(200, text=CLOUDFLARE_NXDOMAIN)

    set_handler(_h)
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    assert ok is True, msgs
    assert {r.url.host for r in seen} == {"dns.google", "cloudflare-dns.com"}
    assert any("resolver 9.9.9.9 skipped" in m for m in msgs)


def test_an_unlisted_resolver_is_skipped_not_sent_to_google(transport):
    set_handler, seen = transport
    set_handler(lambda r: httpx.Response(200, text=CLOUDFLARE_NXDOMAIN))
    _ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=["203.0.113.53", "1.1.1.1"])
    assert [r.url.host for r in seen] == ["cloudflare-dns.com"]
    assert any("resolver 203.0.113.53 skipped" in m for m in msgs)


@pytest.mark.parametrize("resolvers", [["9.9.9.9"], ["9.9.9.9", "149.112.112.112"],
                                       ["203.0.113.53"]])
def test_no_queryable_resolver_skips_the_preflight_without_egress(transport, resolvers):
    """A Quad9-only install used to fail every renewal (505 on every lookup).
    Now the fail-fast convenience check is skipped by name and Let's Encrypt
    judges; nothing is sent to a provider the operator did not name."""
    set_handler, seen = transport
    set_handler(lambda r: pytest.fail(f"unexpected egress to {r.url}"))
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=resolvers)
    assert ok is True
    assert seen == []
    assert any("CNAME pre-flight skipped" in m for m in msgs)
    for ip in resolvers:
        assert any(f"resolver {ip} skipped" in m for m in msgs)


# --- every diagnostic branch names the endpoint actually queried ------------

@pytest.mark.parametrize("make_response,needle", [
    (lambda r: httpx.Response(505, text=""), "DoH HTTP 505"),
    (lambda r: httpx.Response(200, text=json.dumps({"Status": 2})), "rcode=2"),
    (lambda r: httpx.Response(200, text=json.dumps({"Status": 0, "Answer": []})), "no CNAME"),
    (lambda r: httpx.Response(200, text="not json"), "DoH lookup failed"),
])
def test_every_failure_branch_names_endpoint_and_resolver(transport, make_response, needle):
    set_handler, _seen = transport
    set_handler(make_response)
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="acme.example.com",
        public_resolvers=["1.1.1.1"])
    assert ok is False
    hits = [m for m in msgs if needle in m]
    assert hits, msgs
    assert all(CLOUDFLARE in m and "1.1.1.1" in m for m in hits), hits


# --- config validation ------------------------------------------------------

def _acme_cfg(resolvers, *, update_zone="acme.example.com", enabled=True):
    cfg = TriageConfig()
    cfg.tls.acme.enabled = enabled
    cfg.tls.acme.challenge = "dns-01"
    cfg.tls.acme.rfc2136.update_zone = update_zone
    cfg.tls.acme.rfc2136.public_resolvers = list(resolvers)
    return cfg


def _doh_issues(cfg):
    return [i for i in validate_config(cfg) if "DNS-over-HTTPS" in i]


def test_validate_config_names_a_delegation_config_with_no_doh_resolver():
    issues = _doh_issues(_acme_cfg(["9.9.9.9"]))
    assert len(issues) == 1
    assert "9.9.9.9" in issues[0] and "acme.example.com" in issues[0]


@pytest.mark.parametrize("cfg", [
    _acme_cfg(DEFAULT_PUBLIC_RESOLVERS),          # prod: Quad9 alongside Google
    _acme_cfg(["9.9.9.9"], update_zone=""),       # direct mode: no pre-flight
    _acme_cfg(["9.9.9.9"], enabled=False),        # ACME off
])
def test_validate_config_is_quiet_when_the_preflight_can_run_or_never_runs(cfg):
    assert _doh_issues(cfg) == []


def test_admin_form_default_is_the_config_default():
    """The admin ACME form, the YAML parse and the dataclass share one list."""
    from email_triage.config import Rfc2136Config, _parse_resolver_list
    assert Rfc2136Config().public_resolvers == list(DEFAULT_PUBLIC_RESOLVERS)
    assert _parse_resolver_list("", default=list(DEFAULT_PUBLIC_RESOLVERS)) == list(
        DEFAULT_PUBLIC_RESOLVERS)


# --- structural pin ---------------------------------------------------------
#
# INVARIANT (count-agnostic, every src file): (1) a DoH endpoint URL literal
# lives only in config.py (the DOH_JSON_ENDPOINTS SSOT); (2) no ``.get`` on
# DOH_JSON_ENDPOINTS passes a default, so an unlisted IP cannot be mapped to a
# substitute provider again.
#
# SCOPE CAVEAT: (1) matches the three DoH hosts this project has used
# (dns.google, cloudflare-dns.com, dns.quad9.net); a fourth provider's URL is not
# recognised until it is added to _DOH_HOSTS. (2) sees ``DOH_JSON_ENDPOINTS.get``
# by name; a copy bound to another name, or a ``dict(...)`` rebuild, is not
# followed. (1) is the backstop for both: a substitute endpoint needs a URL.

_DOH_HOSTS = ("dns.google", "cloudflare-dns.com", "dns.quad9.net")
_SSOT_FILE = "config.py"


def _doh_violations(tree: ast.AST, rel: str) -> list[str]:
    out: list[str] = []
    if rel != _SSOT_FILE:
        for s in iter_string_literals(tree):
            if any(f"https://{h}" in s for h in _DOH_HOSTS):
                out.append(f"{rel}: DoH endpoint literal {s!r} outside {_SSOT_FILE}")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, (ast.Name, ast.Attribute))
                and (getattr(node.func.value, "id", None)
                     or getattr(node.func.value, "attr", None)) == "DOH_JSON_ENDPOINTS"
                and (len(node.args) > 1 or node.keywords)):
            out.append(f"{rel}:{node.lineno}: DOH_JSON_ENDPOINTS.get with a default")
    return out


def test_doh_endpoints_live_only_in_the_config_ssot_and_never_default():
    violations: list[str] = []
    scanned = 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        scanned += 1
        violations += _doh_violations(tree, relpath(path))
    assert scanned > 100
    assert violations == [], "\n".join(violations)


def test_the_ssot_holds_the_endpoints_and_no_quad9():
    assert (SRC_ROOT / _SSOT_FILE).exists()
    assert set(DOH_JSON_ENDPOINTS.values()) == {GOOGLE, CLOUDFLARE}
    assert "9.9.9.9" not in DOH_JSON_ENDPOINTS
    assert "149.112.112.112" not in DOH_JSON_ENDPOINTS


def test_doh_pin_has_teeth():
    detector = lambda tree: _doh_violations(tree, "web/acme_renewer.py")  # noqa: E731
    assert_pin_has_teeth(
        detector,
        bad_source='E = {"9.9.9.9": "https://dns.quad9.net/dns-query"}\n',
        good_source="from email_triage.config import DOH_JSON_ENDPOINTS\n"
                    "e = DOH_JSON_ENDPOINTS.get(ip)\n",
    )
    assert_pin_has_teeth(
        detector,
        bad_source="e = DOH_JSON_ENDPOINTS.get(ip, FALLBACK)\n",
    )
    assert_pin_has_teeth(
        detector,
        bad_source="e = cfg.DOH_JSON_ENDPOINTS.get(ip, default=FALLBACK)\n",
    )
