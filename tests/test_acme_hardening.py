"""Tests for PR 4 ACME hardening (B1-B4).

Covers:
- ``caa_preflight`` — permissive (no CAA), permissive (LE in tag),
  hostile (other CA only), inconclusive (lookup error).
- ``poll_for_value_public`` accepts ``query_fqdn`` and uses it for
  the actual DNS lookup (B3).
- ``diagnose_resolvers`` returns per-resolver state strings (B4).
- ``issue_now_async`` is single-flight-guarded (B1) — second
  concurrent caller raises SingleFlightBusy.
- ``check_and_renew_async`` swallows SingleFlightBusy and reports
  ``deferred`` instead of crashing the renewal_loop tick.

DNS lookups are mocked at the dnspython surface so tests run
offline.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
import types
from unittest.mock import MagicMock, patch

import pytest

from email_triage import single_flight as sf
from email_triage.config import AcmeConfig, Rfc2136Config
from email_triage.single_flight import SingleFlightBusy
from email_triage.web import acme_renewer as acme_mod
from email_triage.web.acme_renewer import (
    AcmeRenewer,
    Rfc2136Publisher,
    caa_preflight,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_caa_response(records: list[tuple[int, str, str]] | None):
    """Build a dnspython-shaped response object with optional CAA RRset."""
    import dns.rcode, dns.rdatatype
    resp = MagicMock()
    resp.rcode.return_value = dns.rcode.NOERROR

    if records is None:
        resp.answer = []
        return resp

    rrset = MagicMock()
    rrset.rdtype = dns.rdatatype.CAA
    rrset.__iter__ = lambda self: iter([
        types.SimpleNamespace(
            flags=flags,
            tag=tag.encode("ascii"),
            value=val.encode("ascii"),
        )
        for flags, tag, val in records
    ])
    resp.answer = [rrset]
    return resp


def _fake_nxdomain_response():
    import dns.rcode
    resp = MagicMock()
    resp.rcode.return_value = dns.rcode.NXDOMAIN
    resp.answer = []
    return resp


# ---------------------------------------------------------------------------
# B2 — caa_preflight
# ---------------------------------------------------------------------------

def test_caa_preflight_no_records_is_permissive():
    """Domain with no CAA in any zone: any CA may issue (RFC 8659)."""
    with patch("dns.query.udp", return_value=_fake_caa_response(None)):
        ok, problems = caa_preflight(["example.com"])
    assert ok is True
    assert problems == []


def test_caa_preflight_letsencrypt_permitted():
    """Zone has CAA with letsencrypt.org as an issuer — ok."""
    def by_zone(q, *args, **kwargs):
        # Match on the question name to decide which response.
        name = str(q.question[0].name).rstrip(".")
        if name == "example.com":
            return _fake_caa_response([(0, "issue", "letsencrypt.org")])
        return _fake_caa_response(None)

    with patch("dns.query.udp", side_effect=by_zone):
        ok, problems = caa_preflight(["api.example.com"])
    assert ok is True


def test_caa_preflight_hostile_records_blocks():
    """CAA exists but only permits a different CA → not ok."""
    def by_zone(q, *args, **kwargs):
        name = str(q.question[0].name).rstrip(".")
        if name == "example.com":
            return _fake_caa_response([(0, "issue", "digicert.com")])
        return _fake_caa_response(None)

    with patch("dns.query.udp", side_effect=by_zone):
        ok, problems = caa_preflight(["api.example.com"])
    assert ok is False
    assert problems
    assert "digicert.com" in problems[0]


def test_caa_preflight_lookup_error_is_inconclusive():
    """Lookup crash = note in problems, but doesn't block (fail-open)."""
    with patch("dns.query.udp", side_effect=OSError("unreachable")):
        ok, problems = caa_preflight(["example.com"])
    assert ok is True  # not hostile — just inconclusive
    assert problems  # but recorded


def test_caa_preflight_walks_to_apex():
    """No CAA at exact label → walks up; finds CAA at parent."""
    seen_zones: list[str] = []

    def by_zone(q, *args, **kwargs):
        name = str(q.question[0].name).rstrip(".")
        seen_zones.append(name)
        if name == "example.com":
            return _fake_caa_response([(0, "issue", "letsencrypt.org")])
        return _fake_caa_response(None)

    with patch("dns.query.udp", side_effect=by_zone):
        caa_preflight(["a.b.api.example.com"])
    # Walk should have queried each label up the chain.
    assert "a.b.api.example.com" in seen_zones
    assert "example.com" in seen_zones


# ---------------------------------------------------------------------------
# B3 — poll_for_value_public honours query_fqdn
# ---------------------------------------------------------------------------

def test_detect_egress_clear_when_root_soa_returned():
    """Real root server returns NOERROR + SOA whose mname contains
    'root-servers.net' -- detector returns 'clear'."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.rcode, dns.rdatatype

    soa_rr = MagicMock()
    soa_rr.mname = "a.root-servers.net."
    soa_rrset = MagicMock()
    soa_rrset.rdtype = dns.rdatatype.SOA
    soa_rrset.__iter__ = lambda self: iter([soa_rr])

    fake_resp = MagicMock()
    fake_resp.rcode.return_value = dns.rcode.NOERROR
    fake_resp.answer = [soa_rrset]

    with patch("dns.query.udp", return_value=fake_resp):
        assert pub._detect_split_horizon_dns() == "clear"


def test_detect_egress_split_horizon_when_nxdomain_at_root():
    """Transparent proxy returns NXDOMAIN for the root probe -- no
    real root server would do that."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.rcode

    fake_resp = MagicMock()
    fake_resp.rcode.return_value = dns.rcode.NXDOMAIN
    fake_resp.answer = []

    with patch("dns.query.udp", return_value=fake_resp):
        assert pub._detect_split_horizon_dns() == "split_horizon"


def test_detect_egress_split_horizon_when_aa_set_on_non_root_zone():
    """Split-horizon DNS for the operator's zone responds AA=True
    at the root probe destination. Real root NEVER sets AA for
    non-root queries, so AA on a non-root probe is the
    split-horizon signature."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.flags, dns.rcode, dns.rdatatype

    # Probe 1 (root SOA) returns clean root SOA.
    soa_rr = MagicMock()
    soa_rr.mname = "a.root-servers.net."
    soa_rrset = MagicMock()
    soa_rrset.rdtype = dns.rdatatype.SOA
    soa_rrset.__iter__ = lambda self: iter([soa_rr])
    root_resp = MagicMock()
    root_resp.rcode.return_value = dns.rcode.NOERROR
    root_resp.answer = [soa_rrset]

    # Probe 2 (parent-zone NS at root) returns AA-flagged response.
    ns_resp = MagicMock()
    ns_resp.rcode.return_value = dns.rcode.NOERROR
    ns_resp.flags = dns.flags.AA
    ns_resp.answer = []

    responses = [root_resp, ns_resp]
    call_count = {"n": 0}

    def fake_udp(q, ip, *a, **kw):
        r = responses[call_count["n"] % len(responses)]
        call_count["n"] += 1
        return r

    with patch("dns.query.udp", side_effect=fake_udp):
        out = pub._detect_split_horizon_dns(
            query_fqdn="_acme-challenge.triage.example.com.",
        )
    assert out == "split_horizon"


def test_detect_egress_clear_when_root_referral_no_aa():
    """Real root referral for non-root zone: NOERROR + AA=False +
    NS records in AUTHORITY. Detector should NOT flag split-horizon."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.rcode, dns.rdatatype

    soa_rr = MagicMock()
    soa_rr.mname = "a.root-servers.net."
    soa_rrset = MagicMock()
    soa_rrset.rdtype = dns.rdatatype.SOA
    soa_rrset.__iter__ = lambda self: iter([soa_rr])
    root_resp = MagicMock()
    root_resp.rcode.return_value = dns.rcode.NOERROR
    root_resp.answer = [soa_rrset]

    referral_resp = MagicMock()
    referral_resp.rcode.return_value = dns.rcode.NOERROR
    referral_resp.flags = 0  # AA NOT set
    referral_resp.answer = []

    responses = [root_resp, referral_resp]
    call_count = {"n": 0}

    def fake_udp(q, ip, *a, **kw):
        r = responses[call_count["n"] % len(responses)]
        call_count["n"] += 1
        return r

    with patch("dns.query.udp", side_effect=fake_udp):
        out = pub._detect_split_horizon_dns(
            query_fqdn="_acme-challenge.triage.example.com.",
        )
    assert out == "clear"


def test_detect_egress_split_horizon_when_wrong_soa_at_root():
    """Proxy returns NOERROR + SOA from local view -- mname doesn't
    contain root-servers.net. Detector flags split-horizon."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.rcode, dns.rdatatype

    soa_rr = MagicMock()
    soa_rr.mname = "ns.local.example."
    soa_rrset = MagicMock()
    soa_rrset.rdtype = dns.rdatatype.SOA
    soa_rrset.__iter__ = lambda self: iter([soa_rr])

    fake_resp = MagicMock()
    fake_resp.rcode.return_value = dns.rcode.NOERROR
    fake_resp.answer = [soa_rrset]

    with patch("dns.query.udp", return_value=fake_resp):
        assert pub._detect_split_horizon_dns() == "split_horizon"


def test_detect_egress_inconclusive_on_total_timeout():
    """Both root probes fail to connect at all -- 'inconclusive'
    (caller treats as clear and runs the normal gate)."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    with patch("dns.query.udp", side_effect=OSError("network unreachable")):
        assert pub._detect_split_horizon_dns() == "inconclusive"


@pytest.mark.asyncio
async def test_poll_authoritative_skips_gate_when_split_horizon(monkeypatch):
    """When detector flags split-horizon, gate skips the auth-NS
    probe, waits public_propagation_split_horizon_wait_secs,
    returns ok with state='split_horizon_wait_then_pass'."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1", tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
        public_propagation_split_horizon_wait_secs=1,  # 1s so test is fast
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    monkeypatch.setattr(
        Rfc2136Publisher, "_detect_split_horizon_dns",
        lambda self, query_fqdn=None: "split_horizon",
    )
    monkeypatch.setattr(
        Rfc2136Publisher, "_resolve_via_authoritative",
        lambda self, *a, **kw: (
            (_ for _ in ()).throw(
                AssertionError("must NOT be called when split-horizon"),
            )
        ),
    )

    ok, info = pub.poll_for_value_authoritative(
        "_acme-challenge.foo.example.com.", "TOKEN",
    )
    assert ok is True
    assert info["state"] == "split_horizon_wait_then_pass"


def test_probe_once_handles_cname_followed_response():
    """Recursor returns CNAME + TXT in the answer section. Probe
    must filter by rdtype before touching .strings -- accessing
    .strings on a CNAME RR raises AttributeError, which the bare
    except would swallow and the probe would lie that nothing was
    visible. Regression for the 2026-04-29 30-min gate-timeout
    bug on CNAME-delegated cert subjects."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1",
        tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    import dns.rcode, dns.rdatatype

    # Build a fake response: answer has both a CNAME rrset (for the
    # cert-subject FQDN) and a TXT rrset (for the CNAME target).
    cname_rrset = MagicMock()
    cname_rrset.rdtype = dns.rdatatype.CNAME
    cname_rr = MagicMock()
    # No .strings attribute -- accessing it raises AttributeError,
    # which is exactly the bug.
    del cname_rr.strings  # ensure attribute lookup raises
    cname_rrset.__iter__ = lambda self: iter([cname_rr])

    txt_rrset = MagicMock()
    txt_rrset.rdtype = dns.rdatatype.TXT
    txt_rr = MagicMock()
    txt_rr.strings = [b"the-token-value"]
    txt_rrset.__iter__ = lambda self: iter([txt_rr])

    fake_resp = MagicMock()
    fake_resp.rcode.return_value = dns.rcode.NOERROR
    fake_resp.answer = [cname_rrset, txt_rrset]

    with patch("dns.query.udp", return_value=fake_resp):
        ok = pub._probe_once(
            "8.8.8.8", 53, "_acme-challenge.foo.example.com.",
            "the-token-value",
        )
    assert ok is True


def test_poll_public_uses_query_fqdn_when_set():
    """When query_fqdn is passed, the probe queries that name (not
    the publish FQDN). The recursor would auto-follow CNAME, so this
    is the path that validates the exact lookup LE performs."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1",
        tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
        public_propagation_timeout_secs=1,
        public_propagation_interval_secs=1,
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    seen_names: list[str] = []

    def fake_probe(self, resolver, port, fqdn, expected):
        seen_names.append(fqdn)
        return True

    with patch.object(Rfc2136Publisher, "_probe_once", fake_probe):
        ok, _ = pub.poll_for_value_public(
            "_acme-challenge.acme.example.com.",  # publish target
            "TOKEN",
            query_fqdn="_acme-challenge.triage.example.com.",  # cert subject
        )
    assert ok is True
    assert seen_names == ["_acme-challenge.triage.example.com."]


def test_poll_public_defaults_to_publish_fqdn():
    """No query_fqdn → behaviour matches pre-B3 (queries publish target)."""
    cfg = Rfc2136Config(
        nameserver="10.0.0.1",
        tsig_key_name="x.",
        public_resolvers=["8.8.8.8"],
        public_propagation_timeout_secs=1,
        public_propagation_interval_secs=1,
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    seen_names: list[str] = []

    def fake_probe(self, resolver, port, fqdn, expected):
        seen_names.append(fqdn)
        return True

    with patch.object(Rfc2136Publisher, "_probe_once", fake_probe):
        pub.poll_for_value_public(
            "_acme-challenge.acme.example.com.", "TOKEN",
        )
    assert seen_names == ["_acme-challenge.acme.example.com."]


# ---------------------------------------------------------------------------
# B4 — diagnose_resolvers
# ---------------------------------------------------------------------------

def test_diagnose_resolvers_classifies_per_resolver():
    cfg = Rfc2136Config(
        nameserver="10.0.0.1",
        tsig_key_name="x.",
        public_resolvers=["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    )
    pub = Rfc2136Publisher(cfg, tsig_secret="seed")

    def by_resolver(q, where, *args, **kwargs):
        if where == "8.8.8.8":
            # NXDOMAIN
            return _fake_nxdomain_response()
        if where == "1.1.1.1":
            # NOERROR + TXT
            import dns.rcode, dns.rdatatype
            resp = MagicMock()
            resp.rcode.return_value = dns.rcode.NOERROR
            rrset = MagicMock()
            rrset.rdtype = dns.rdatatype.TXT
            rrset.__iter__ = lambda self: iter([
                types.SimpleNamespace(strings=[b"the-token-value"]),
            ])
            resp.answer = [rrset]
            return resp
        if where == "9.9.9.9":
            # Connection error
            raise OSError("timeout")
        return _fake_nxdomain_response()

    with patch("dns.query.udp", side_effect=by_resolver):
        out = pub.diagnose_resolvers("_acme-challenge.foo.example.com.")
    assert out["8.8.8.8"] == "nxdomain"
    assert out["1.1.1.1"].startswith("saw_txt:")
    assert "the-token-value" in out["1.1.1.1"]
    assert out["9.9.9.9"].startswith("error:")


# ---------------------------------------------------------------------------
# B1 — single-flight on issue_now_async
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_lock_dict():
    """Each test starts with a clean process-level lock dict."""
    sf._reset_for_tests()
    yield
    sf._reset_for_tests()


def _make_renewer(domains: list[str] | None = None) -> AcmeRenewer:
    cfg = AcmeConfig(
        domains=domains if domains is not None else ["alpha.example.com"],
    )
    secrets = MagicMock()
    secrets.get.return_value = None
    secrets.set.return_value = None
    db = sqlite3.connect(":memory:", check_same_thread=False)
    return AcmeRenewer(
        cfg=cfg, cert_dir="/tmp/test-acme",
        secrets_store=secrets, db=db,
    )


@pytest.mark.asyncio
async def test_issue_now_async_serialises_concurrent_calls(fresh_lock_dict):
    """Two concurrent issue_now_async calls for the same primary
    domain → second raises SingleFlightBusy."""
    renewer = _make_renewer(["alpha.example.com"])
    holder_started = asyncio.Event()
    holder_release = asyncio.Event()

    def slow_issue(*args, **kwargs):
        # Use a sentinel through asyncio to wait inside the to_thread
        # call. We can't await an asyncio.Event from a thread directly,
        # so spin on a flag.
        holder_started.set_threadsafe = None  # avoid lint
        holder_started._loop.call_soon_threadsafe(holder_started.set)
        # Block until the test releases.
        while not holder_release.is_set():
            time.sleep(0.01)
        return {"present": True}

    holder_started._loop = asyncio.get_event_loop()  # type: ignore[attr-defined]

    with patch.object(AcmeRenewer, "issue_now", side_effect=slow_issue):
        first = asyncio.create_task(
            renewer.issue_now_async(directory_url="https://example/dir"),
        )
        await holder_started.wait()
        with pytest.raises(SingleFlightBusy):
            await renewer.issue_now_async(directory_url="https://example/dir")
        holder_release.set()
        result = await first
        assert result == {"present": True}


@pytest.mark.asyncio
async def test_issue_now_async_different_domains_do_not_block(fresh_lock_dict):
    """Two renewers with different primary domains → independent locks."""
    a = _make_renewer(["alpha.example.com"])
    b = _make_renewer(["beta.example.com"])

    def quick_issue(*args, **kwargs):
        return {"domain": "ok"}

    with patch.object(AcmeRenewer, "issue_now", side_effect=quick_issue):
        results = await asyncio.gather(
            a.issue_now_async(directory_url="https://example/dir"),
            b.issue_now_async(directory_url="https://example/dir"),
        )
    assert all(r == {"domain": "ok"} for r in results)


@pytest.mark.asyncio
async def test_check_and_renew_async_swallows_busy(fresh_lock_dict):
    """When the lock is held by an in-flight issue, the periodic
    tick reports 'deferred' instead of raising."""
    renewer = _make_renewer(["alpha.example.com"])
    renewer.cfg.enabled = True

    # Force needs_renewal to return True so check_and_renew_async
    # actually attempts the lock.
    with patch.object(AcmeRenewer, "needs_renewal", return_value=True):
        # Hold the lock manually by acquiring it ourselves.
        lock = await sf._get_or_create_lock(
            f"acme:issue:alpha.example.com",
        )
        await lock.acquire()
        try:
            result = await renewer.check_and_renew_async()
        finally:
            lock.release()

    assert result == {
        "action": "deferred", "reason": "issue_in_progress",
    }


@pytest.mark.asyncio
async def test_check_and_renew_async_skips_when_not_due(fresh_lock_dict):
    renewer = _make_renewer(["alpha.example.com"])
    renewer.cfg.enabled = True

    with patch.object(AcmeRenewer, "needs_renewal", return_value=False), \
         patch.object(
             AcmeRenewer, "cert_metadata",
             return_value={"present": True, "not_after": "2030-01-01"},
         ), \
         patch(
             "email_triage.web.acme_renewer.insert_acme_renewal_log"
         ):
        result = await renewer.check_and_renew_async()

    assert result == {"action": "skipped", "reason": "fresh"}
