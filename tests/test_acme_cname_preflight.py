"""Tests for the DNS-01 CNAME pre-flight.

Mocks httpx at the function level so the tests don't need a live DoH
endpoint. The pre-flight queries CNAME records at
``_acme-challenge.<cert_subject>`` over DoH and verifies the target
falls under the configured update zone.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest


from email_triage.web.acme_renewer import cname_preflight


# ---------------------------------------------------------------------------
# Fake httpx.Client and Response
# ---------------------------------------------------------------------------

# Map operator-configured resolver IP -> DoH endpoint the code contacts.
# Must stay in lock-step with _DOH_ENDPOINTS inside cname_preflight so the
# fixture can key responses by resolver IP the way tests do.
_IP_TO_ENDPOINT = {
    "8.8.8.8": "https://dns.google/resolve",
    "8.8.4.4": "https://dns.google/resolve",
    "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    "1.0.0.1": "https://cloudflare-dns.com/dns-query",
    "9.9.9.9": "https://dns.quad9.net/dns-query",
    "149.112.112.112": "https://dns.quad9.net/dns-query",
}


class _FakeResponse:
    def __init__(self, *, status_code: int = 200, payload: dict[str, Any]):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, responses: dict[tuple[str, str], _FakeResponse]):
        self._responses = responses

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, params=None, headers=None):
        params = params or {}
        name = str(params.get("name", "")).rstrip(".") + "."
        key = (name, url)
        if key in self._responses:
            return self._responses[key]
        # Default: NXDOMAIN JSON payload.
        return _FakeResponse(
            payload={"Status": 3, "Answer": []},
        )


@pytest.fixture
def fake_dns():
    """Patch httpx.Client so the pre-flight runs against scripted DoH
    responses. Returns a dict tests populate with
    ``{(name, doh_endpoint): _FakeResponse}``, plus helpers.
    """
    responses: dict[tuple[str, _FakeResponse], _FakeResponse] = {}

    def _client_factory(*_args, **_kwargs):
        return _FakeClient(responses)

    with patch(
        "httpx.Client",
        side_effect=_client_factory,
    ):
        yield {
            "responses": responses,
            "ip_to_endpoint": _IP_TO_ENDPOINT,
            "noerror_resp": lambda target: _FakeResponse(
                payload={
                    "Status": 0,
                    "Answer": [
                        {
                            "name": "_ignored.",
                            "type": 5,  # CNAME
                            "TTL": 300,
                            "data": target.rstrip(".") + ".",
                        },
                    ],
                },
            ),
            "nxdomain_resp": _FakeResponse(
                payload={"Status": 3, "Answer": []},
            ),
            "servfail_resp": _FakeResponse(
                payload={"Status": 2, "Answer": []},
            ),
            "no_cname_resp": _FakeResponse(
                payload={"Status": 0, "Answer": []},
            ),
        }


def _key(name: str, resolver_ip: str) -> tuple[str, str]:
    """Build a response-map key: (queried CNAME name, DoH endpoint)."""
    return (
        f"_acme-challenge.{name.rstrip('.')}.",
        _IP_TO_ENDPOINT[resolver_ip],
    )


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def test_no_update_zone_skips_check():
    """Direct-publish mode (no CNAME delegation) returns ok=True without
    issuing any DoH queries."""
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
    fake_dns["responses"][_key("triage.example.com", "8.8.8.8")] = (
        fake_dns["noerror_resp"]("triage.acme.example.com")
    )
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is True


def test_cname_exact_match_is_ok(fake_dns):
    """CNAME pointing exactly at update_zone (no extra label) is also ok."""
    fake_dns["responses"][_key("triage.example.com", "8.8.8.8")] = (
        fake_dns["noerror_resp"]("acme.example.com")
    )
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is True


def test_nxdomain_fails_with_actionable_message(fake_dns):
    """No CNAME on any resolver -> ok=False; message says NXDOMAIN."""
    # Default fake returns NXDOMAIN for unmatched queries.
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8", "1.1.1.1"],
    )
    assert ok is False
    assert any("NXDOMAIN" in m for m in msgs)


def test_cname_pointing_elsewhere_fails(fake_dns):
    """CNAME exists but points to the wrong target."""
    fake_dns["responses"][_key("triage.example.com", "8.8.8.8")] = (
        fake_dns["noerror_resp"]("wrong.zone.example.com")
    )
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
    fake_dns["responses"][_key("triage.example.com", "1.1.1.1")] = (
        fake_dns["nxdomain_resp"]
    )
    fake_dns["responses"][_key("triage.example.com", "8.8.8.8")] = (
        fake_dns["noerror_resp"]("triage.acme.example.com")
    )
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["1.1.1.1", "8.8.8.8"],
    )
    assert ok is True


def test_multiple_domains_all_must_pass(fake_dns):
    """ok=True only if every domain has at least one good CNAME."""
    fake_dns["responses"][_key("a.example.com", "8.8.8.8")] = (
        fake_dns["noerror_resp"]("a.acme.example.com")
    )
    # b.example.com missing entirely -> NXDOMAIN
    ok, msgs = cname_preflight(
        ["a.example.com", "b.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is False
    assert any("b.example.com" in m for m in msgs)


def test_doh_endpoint_choice_per_resolver_ip():
    """N-374: preserve operator's resolver-family choice. 8.8.8.8 -> Google,
    1.1.1.1 -> Cloudflare, 9.9.9.9 -> Quad9. Verify by capturing GET urls
    + params + Accept header (N-374b DA F1: DoH JSON API contract shape is
    load-bearing on the response format — RFC 8484 §5 / dns-json requires
    the Accept: application/dns-json header + name/type query params)."""
    seen: list[tuple[str, dict, dict]] = []

    class _CapClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, params=None, headers=None):
            seen.append((url, dict(params or {}), dict(headers or {})))
            return _FakeResponse(payload={"Status": 3, "Answer": []})

    def _client_factory(*_args, **_kwargs):
        return _CapClient()

    with patch(
        "httpx.Client",
        side_effect=_client_factory,
    ):
        cname_preflight(
            ["x.example.com"],
            update_zone="acme.example.com",
            public_resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        )

    urls = [u for u, _, _ in seen]
    assert "https://dns.google/resolve" in urls
    assert "https://cloudflare-dns.com/dns-query" in urls
    assert "https://dns.quad9.net/dns-query" in urls
    # N-374b DA F1 — assert the DoH contract on EVERY GET, not just the
    # endpoint URL. A missing Accept forces dns-wire binary responses
    # (our JSON-decode blows up); missing name/type = 4xx from the
    # resolver.
    for url, params, headers in seen:
        assert params.get("name") == "_acme-challenge.x.example.com."
        assert params.get("type") == "CNAME"
        accept = next(
            (v for k, v in headers.items() if k.lower() == "accept"), None,
        )
        assert accept == "application/dns-json", (
            f"DoH endpoint {url!r} needs Accept: application/dns-json"
        )


def test_doh_http_error_records_message(fake_dns):
    """A non-200 status from the DoH endpoint records a message + no False
    positive (ok stays False since no valid CNAME was returned)."""
    fake_dns["responses"][_key("triage.example.com", "8.8.8.8")] = (
        _FakeResponse(status_code=502, payload={})
    )
    ok, msgs = cname_preflight(
        ["triage.example.com"],
        update_zone="acme.example.com",
        public_resolvers=["8.8.8.8"],
    )
    assert ok is False
    assert any("DoH HTTP 502" in m for m in msgs)
