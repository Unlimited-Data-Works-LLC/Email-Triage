"""Tests for the DNS-01 CNAME pre-flight (#76).

Mocks dnspython at the function level so the tests don't need a live
DNS resolver. The pre-flight queries CNAME records at
``_acme-challenge.<cert_subject>`` and verifies the target falls
under the configured update zone.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


from email_triage.web.acme_renewer import cname_preflight


# ---------------------------------------------------------------------------
# Fakes for dnspython response objects
# ---------------------------------------------------------------------------

class _FakeRR:
    def __init__(self, target: str):
        # dnspython yields rr.target as a Name; str(.) gives "host.zone."
        # Use a tiny stand-in with a __str__ that matches.
        self.target = _FakeName(target)


class _FakeName:
    def __init__(self, text: str):
        self._text = text.rstrip(".") + "."

    def __str__(self):
        return self._text


class _FakeRRset:
    def __init__(self, target: str, rdtype):
        self.rdtype = rdtype
        self._target = target

    def __iter__(self):
        return iter([_FakeRR(self._target)])


class _FakeResp:
    def __init__(self, *, rcode_val, answer):
        self._rcode = rcode_val
        self.answer = answer

    def rcode(self):
        return self._rcode


@pytest.fixture
def fake_dns():
    """Patch dnspython's query.udp + the rcode/rdatatype enums so the
    pre-flight runs against scripted responses. Returns a dict the test
    can populate with ``{(name, resolver): _FakeResp}``."""
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype

    NOERROR = dns.rcode.NOERROR
    NXDOMAIN = dns.rcode.NXDOMAIN
    CNAME = dns.rdatatype.CNAME

    responses: dict[tuple[str, str], _FakeResp] = {}

    def _fake_udp(query, resolver_ip, port=53, timeout=5):
        # Pull the queried name out of the dns.message.Message.
        name = str(query.question[0].name).rstrip(".") + "."
        key = (name, resolver_ip)
        if key in responses:
            return responses[key]
        # Default: NXDOMAIN.
        return _FakeResp(rcode_val=NXDOMAIN, answer=[])

    with patch("dns.query.udp", side_effect=_fake_udp):
        yield {
            "responses": responses,
            "NOERROR": NOERROR,
            "NXDOMAIN": NXDOMAIN,
            "CNAME": CNAME,
            "rrset": lambda target: _FakeRRset(target, CNAME),
            "noerror_resp": lambda answer: _FakeResp(
                rcode_val=NOERROR, answer=answer,
            ),
            "nxdomain_resp": _FakeResp(rcode_val=NXDOMAIN, answer=[]),
        }


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def test_no_update_zone_skips_check():
    """Direct-publish mode (no CNAME delegation) returns ok=True without
    issuing any DNS queries."""
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone=None,
    )
    assert ok is True
    assert msgs == []


def test_empty_update_zone_skips_check():
    ok, msgs = cname_preflight(
        ["triage.example.com"], update_zone="",
    )
    assert ok is True
    assert msgs == []


def test_cname_pointing_under_update_zone_is_ok(fake_dns):
    """Happy path: CNAME at _acme-challenge.<cert_subject> points to
    a name under the configured update_zone."""
    fake_dns["responses"][
        ("_acme-challenge.triage.example.com.", "8.8.8.8")
    ] = fake_dns["noerror_resp"]([
        fake_dns["rrset"]("triage.acme.example.com"),
    ])
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is True


def test_cname_exact_match_is_ok(fake_dns):
    """CNAME pointing exactly at update_zone (no extra label) is also ok."""
    fake_dns["responses"][
        ("_acme-challenge.triage.example.com.", "8.8.8.8")
    ] = fake_dns["noerror_resp"]([
        fake_dns["rrset"]("acme.example.com"),
    ])
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is True


def test_nxdomain_fails_with_actionable_message(fake_dns):
    """No CNAME on any resolver -> ok=False; message says NXDOMAIN."""
    # Default fake_udp returns NXDOMAIN for unmatched queries -- so we
    # don't need to register a response.
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8", "1.1.1.1"],
    )
    assert ok is False
    assert any("NXDOMAIN" in m for m in msgs)


def test_cname_pointing_elsewhere_fails(fake_dns):
    """CNAME exists but points to the wrong target."""
    fake_dns["responses"][
        ("_acme-challenge.triage.example.com.", "8.8.8.8")
    ] = fake_dns["noerror_resp"]([
        fake_dns["rrset"]("wrong.zone.example.com"),
    ])
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is False
    assert any("wrong.zone.example.com" in m for m in msgs)


def test_one_resolver_seeing_correct_cname_is_enough(fake_dns):
    """If at least one configured resolver sees the right CNAME, ok=True
    even when others lag."""
    # Cloudflare returns NXDOMAIN; Google returns the right CNAME.
    fake_dns["responses"][
        ("_acme-challenge.triage.example.com.", "1.1.1.1")
    ] = fake_dns["nxdomain_resp"]
    fake_dns["responses"][
        ("_acme-challenge.triage.example.com.", "8.8.8.8")
    ] = fake_dns["noerror_resp"]([
        fake_dns["rrset"]("triage.acme.example.com"),
    ])
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["1.1.1.1", "8.8.8.8"],
    )
    assert ok is True


def test_multiple_domains_all_must_pass(fake_dns):
    """ok=True only if every domain has at least one good CNAME."""
    fake_dns["responses"][
        ("_acme-challenge.a.example.com.", "8.8.8.8")
    ] = fake_dns["noerror_resp"]([
        fake_dns["rrset"]("a.acme.example.com"),
    ])
    # b.example.com missing entirely -> NXDOMAIN
    ok, msgs = cname_preflight(
        ["a.example.com", "b.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is False
    assert any("b.example.com" in m for m in msgs)
