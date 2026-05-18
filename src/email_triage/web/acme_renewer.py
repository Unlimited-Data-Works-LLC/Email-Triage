"""ACME (Let's Encrypt) automation: in-process renewal client.

Removes the manual cert-rotation burden that would otherwise grow
with the WebAuthn surface. Renews via the standard ACME protocol —
the same one ``certbot`` speaks — using Duo's ``acme`` Python
package. Default DNS-01 challenge via RFC-2136 against the
operator's BIND on a configurable nameserver.

The CNAME-delegation pattern is supported: the cert subject and
the dynamic-update target can live in different zones. Operator
pre-creates ``_acme-challenge.<cert-subject> CNAME
_acme-challenge.<update-zone>``; the LE validator follows the
CNAME and reads the TXT from the update zone.
``Rfc2136Config.update_zone`` tells the publisher which name to
write to.

Test buttons: the renewer exposes diagnostic operations so the
operator can validate each step of the DNS-01 path independently
from the admin UI without burning ACME-directory rate limits:

* ``test_dns_reachability`` — UDP/TCP probe to nameserver:53.
* ``test_tsig_authentication`` — signed SOA query, verify reply.
* ``test_publish_record`` — write a probe TXT, poll until visible
  via authoritative resolver, delete; per-step timing returned.
* ``test_full_dns01_cycle`` — runs the above end-to-end.
* ``issue_now`` (staging | prod) — full ACME flow against the
  selected directory, gated on caller passing the directory URL
  explicitly so a button click can't accidentally hit prod.

Account key (Ed25519 by default — smaller / faster than RSA-2048
and supported by LE since 2018) is generated on first run and
persisted in the secrets store under ``acme_account_key`` (PEM
encoded private key). Cert + key are written atomically to
``cert_dir/server.crt`` and ``cert_dir/server.key`` so a partial
write can never leave a torn pair on disk.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from email_triage.config import AcmeConfig, Rfc2136Config
from email_triage.single_flight import single_flight
from email_triage.triage_logging import get_logger
from email_triage.web.db_auth_helpers import insert_acme_renewal_log


log = get_logger("web.acme")


# ---------------------------------------------------------------------------
# CAA pre-flight (B2)
# ---------------------------------------------------------------------------

def caa_preflight(
    domains: list[str],
    *,
    public_resolvers: list[str] | None = None,
    issuer: str = "letsencrypt.org",
) -> tuple[bool, list[str]]:
    """Walk up DNS labels for each domain checking CAA records.

    For each label of each domain, query a public resolver for the
    CAA RRset. If any zone in the chain has CAA records and none of
    them grant ``issuer`` an ``issue`` or ``issuewild`` tag, the
    domain is unissuable by ``issuer``. Returns
    ``(ok, problem_messages)`` — ``ok`` is False if any domain hit
    a hostile CAA, ``problem_messages`` describes which.

    A domain with **no** CAA in its label chain (the common case for
    most homelab + small-org deployments) is permissive by RFC 8659:
    any CA may issue. Returns ok=True with an empty problem list.

    Lookup hits one resolver only — querying multiple wouldn't help,
    since the CAA tree is in the public DNS and a single recursor's
    answer is authoritative for issuance purposes. Resolver defaults
    to the first configured public resolver, falling back to 8.8.8.8.
    """
    import dns.message, dns.query, dns.rcode, dns.rdatatype
    resolver_ip = (public_resolvers or ["8.8.8.8"])[0]
    problems: list[str] = []
    for d in domains:
        labels = d.rstrip(".").split(".")
        chain_ok = True  # if any zone in chain blocks, this flips
        for i in range(len(labels)):
            zone = ".".join(labels[i:])
            try:
                q = dns.message.make_query(zone, dns.rdatatype.CAA)
                resp = dns.query.udp(
                    q, resolver_ip, port=53, timeout=5,
                )
                if resp.rcode() != dns.rcode.NOERROR:
                    continue
                caa_records: list[tuple[int, str, str]] = []
                for rrset in resp.answer:
                    if rrset.rdtype != dns.rdatatype.CAA:
                        continue
                    for rr in rrset:
                        # dnspython CAA: flags, tag (bytes), value (bytes)
                        try:
                            tag = rr.tag.decode("ascii", errors="replace")
                            val = rr.value.decode("ascii", errors="replace")
                            caa_records.append((rr.flags, tag, val))
                        except Exception:
                            pass
                if not caa_records:
                    continue  # no CAA at this zone, walk up
                # CAA found — check whether any issue/issuewild tag
                # permits the issuer.
                has_issue_tag = False
                permits_issuer = False
                for flags, tag, val in caa_records:
                    t = tag.lower()
                    if t in ("issue", "issuewild"):
                        has_issue_tag = True
                        # CAA value is the CA's identifier; ignore
                        # parameters after a semicolon for matching.
                        ca = val.split(";")[0].strip().lower()
                        if ca == issuer.lower():
                            permits_issuer = True
                            break
                if has_issue_tag and not permits_issuer:
                    chain_ok = False
                    problems.append(
                        f"{d}: CAA at zone {zone!r} restricts issuance "
                        f"to: {[v for _, t, v in caa_records if t.lower() in ('issue', 'issuewild')]}; "
                        f"missing entry for {issuer}"
                    )
                    break
                # Found a permissive CAA covering this issuer -> ok.
                break
            except Exception as exc:
                # CAA lookup failure is treated as inconclusive (not
                # a fail-closed signal). Note in problems but keep
                # walking; if no zone above blocks, we proceed.
                problems.append(
                    f"{d}: CAA lookup at {zone!r} failed: "
                    f"{type(exc).__name__}"
                )
                continue
        if not chain_ok:
            # already recorded in problems list
            pass
    # ok if every domain's chain was OK (no hostile CAA hit)
    hostile = any(
        ": CAA at zone " in p and "missing entry for" in p
        for p in problems
    )
    return (not hostile), problems


# ---------------------------------------------------------------------------
# CNAME pre-flight (#76)
# ---------------------------------------------------------------------------

def cname_preflight(
    domains: list[str],
    *,
    update_zone: str | None,
    public_resolvers: list[str] | None = None,
    timeout_secs: int = 5,
) -> tuple[bool, list[str]]:
    """Verify the CNAME-delegation chain BEFORE publishing a TXT.

    #76 -- the renewer publishes ``_acme-challenge.<update_zone>``
    when CNAME delegation is configured. LE then queries
    ``_acme-challenge.<cert_subject>`` and follows the CNAME at that
    name to the update zone. If the CNAME isn't configured (or
    points to the wrong target, or hasn't propagated externally),
    LE gets NXDOMAIN -- after the renewer has already burned ~8 min
    publishing + polling.

    This pre-flight queries each public resolver for the CNAME at
    ``_acme-challenge.<cert_subject>`` and verifies the target is
    correct. Fails fast with an actionable error before publishing.

    Returns ``(ok, messages)``:
      - ok=True: every cert subject's CNAME resolves to the
        update-zone target on every public resolver (or no
        update_zone configured -- direct mode, no CNAME expected).
      - ok=False: at least one resolver / domain combo had a
        missing or wrong CNAME; ``messages`` enumerates the gaps.

    No update_zone configured -> ok=True (operator is publishing
    directly; nothing to pre-flight).

    Lookup failures (network, NXDOMAIN, timeout) are recorded in
    ``messages`` but only flip ok=False when no resolver returned a
    correct answer for a given cert subject. One lagging resolver
    out of three is signal but not a hard block.
    """
    if not update_zone:
        return True, []

    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.name as _dnsname

    resolvers = public_resolvers or ["8.8.8.8"]
    expected_target = (
        _dnsname.from_text(update_zone.rstrip(".") + ".")
    )
    messages: list[str] = []
    any_ok_for_each_domain: dict[str, bool] = {}

    for d in domains:
        cert_subject = d.rstrip(".")
        cname_q_name = f"_acme-challenge.{cert_subject}."
        any_ok_for_each_domain[d] = False
        for resolver_ip in resolvers:
            try:
                q = dns.message.make_query(
                    cname_q_name, dns.rdatatype.CNAME,
                )
                resp = dns.query.udp(
                    q, resolver_ip, port=53, timeout=timeout_secs,
                )
                if resp.rcode() == dns.rcode.NXDOMAIN:
                    messages.append(
                        f"{d}: NXDOMAIN at {cname_q_name} via "
                        f"{resolver_ip} -- the CNAME isn't "
                        f"published yet (or not visible externally)."
                    )
                    continue
                if resp.rcode() != dns.rcode.NOERROR:
                    messages.append(
                        f"{d}: rcode={resp.rcode()} at {cname_q_name} "
                        f"via {resolver_ip}"
                    )
                    continue
                # Look for a CNAME RRset in the answer section.
                got_target: str | None = None
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        for rr in rrset:
                            got_target = str(rr.target).rstrip(".") + "."
                            break
                if got_target is None:
                    messages.append(
                        f"{d}: no CNAME at {cname_q_name} via "
                        f"{resolver_ip} (answer was empty)"
                    )
                    continue
                # Compare expected vs got, label-insensitive (DNS
                # names are case-insensitive). Allow the operator to
                # CNAME to a deeper name within the update zone --
                # the right end-state is "name lives somewhere under
                # update_zone", not "exactly equal to update_zone".
                got_name = _dnsname.from_text(got_target)
                if got_name == expected_target or got_name.is_subdomain(
                    expected_target,
                ):
                    any_ok_for_each_domain[d] = True
                    break  # one good resolver = ok for this domain
                messages.append(
                    f"{d}: CNAME at {cname_q_name} points to "
                    f"{got_target!r} via {resolver_ip}; expected "
                    f"target under {update_zone!r}"
                )
            except Exception as exc:
                messages.append(
                    f"{d}: CNAME lookup failed via {resolver_ip}: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue

    overall_ok = all(any_ok_for_each_domain.values())
    return overall_ok, messages


# ---------------------------------------------------------------------------
# Diagnostic test results (rich feedback for the admin UI buttons)
# ---------------------------------------------------------------------------

@dataclass
class TestStepResult:
    """One step in a multi-step test, surfaced in the UI."""
    # pytest's collection heuristic flags Test*-prefixed classes as
    # test cases by default; explicit opt-out keeps these dataclasses
    # in the public API as named (semantic match for "test step")
    # without producing PytestCollectionWarning.
    __test__ = False
    name: str
    ok: bool
    elapsed_ms: int
    detail: str = ""
    error: str = ""


@dataclass
class TestRunResult:
    """Aggregate of one or more diagnostic steps."""
    __test__ = False
    overall_ok: bool
    steps: list[TestStepResult]
    started_at: str
    finished_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_ok": self.overall_ok,
            "steps": [
                {
                    "name": s.name, "ok": s.ok,
                    "elapsed_ms": s.elapsed_ms,
                    "detail": s.detail, "error": s.error,
                }
                for s in self.steps
            ],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed_ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


# ---------------------------------------------------------------------------
# DNS-01 / RFC-2136 publisher
# ---------------------------------------------------------------------------

class Rfc2136Publisher:
    """RFC-2136 dynamic-DNS-update client for the DNS-01 challenge.

    Wraps ``dnspython`` to publish + delete TXT records under the
    operator's TSIG-controlled zone. Zone-aware: knows the publish
    target may differ from the cert subject when CNAME delegation
    is in play (``update_zone`` config).

    All operations are blocking I/O — the renewer wraps calls in
    ``asyncio.to_thread`` for the async path; the admin-UI test
    endpoints can invoke directly when running inside FastAPI's
    threadpool.
    """

    def __init__(self, cfg: Rfc2136Config, tsig_secret: str) -> None:
        if not cfg.nameserver:
            raise ValueError("rfc2136.nameserver is required")
        if not cfg.tsig_key_name:
            raise ValueError("rfc2136.tsig_key_name is required")
        if not tsig_secret:
            raise ValueError("acme_tsig_secret is empty")
        self.cfg = cfg
        self._tsig_secret = tsig_secret

    def _challenge_fqdn(self, cert_subject: str) -> str:
        """Return the FQDN where the TXT record should be written.

        With CNAME delegation (``update_zone`` set), publish target
        is ``_acme-challenge.<update_zone>``. Without delegation,
        publish under the cert subject.
        """
        if self.cfg.update_zone:
            return f"_acme-challenge.{self.cfg.update_zone.rstrip('.')}."
        return f"_acme-challenge.{cert_subject.rstrip('.')}."

    def _publish_zone(self) -> str:
        """The DNS zone to send the UPDATE to (ends with a dot)."""
        zone = self.cfg.update_zone or ""
        if not zone:
            # Fall back to a parent zone — caller should ideally
            # configure update_zone explicitly.
            raise ValueError(
                "rfc2136.update_zone must be set; the publisher "
                "needs to know which zone to send the UPDATE to."
            )
        if not zone.endswith("."):
            zone = zone + "."
        return zone

    def _algo_name(self):
        import dns.tsig
        algo_map = {
            "hmac-sha256": dns.tsig.HMAC_SHA256,
            "hmac-sha384": dns.tsig.HMAC_SHA384,
            "hmac-sha512": dns.tsig.HMAC_SHA512,
            "hmac-sha1": dns.tsig.HMAC_SHA1,
            "hmac-md5": dns.tsig.HMAC_MD5,
        }
        algo = algo_map.get(self.cfg.tsig_algorithm.lower())
        if algo is None:
            raise ValueError(
                f"Unknown TSIG algorithm: {self.cfg.tsig_algorithm!r}"
            )
        return algo

    def _keyring(self):
        import dns.tsigkeyring
        # dnspython expects base64 secret; operator's TSIG file uses
        # this format already.
        return dns.tsigkeyring.from_text({
            self.cfg.tsig_key_name: self._tsig_secret,
        })

    def publish_txt(self, cert_subject: str, value: str, ttl: int = 60) -> str:
        """Publish a TXT record. Returns the FQDN written."""
        import dns.update, dns.query, dns.rdatatype
        fqdn = self._challenge_fqdn(cert_subject)
        zone = self._publish_zone()
        update = dns.update.Update(
            zone,
            keyring=self._keyring(),
            keyalgorithm=self._algo_name(),
        )
        # Strip the trailing zone from fqdn so dnspython composes
        # the absolute name correctly.
        rel = fqdn.rstrip(".")
        z = zone.rstrip(".")
        if rel.endswith("." + z):
            rel = rel[: -(len(z) + 1)]
        elif rel == z:
            rel = "@"
        update.add(rel, ttl, "TXT", f'"{value}"')
        resp = dns.query.tcp(
            update, self.cfg.nameserver, port=self.cfg.nameserver_port,
            timeout=10,
        )
        if resp.rcode() != 0:
            raise RuntimeError(
                f"DNS UPDATE rejected: rcode={dns.rcode.to_text(resp.rcode())}"
            )
        return fqdn

    def delete_txt(self, cert_subject: str) -> None:
        """Delete the TXT record published earlier."""
        import dns.update, dns.query
        zone = self._publish_zone()
        fqdn = self._challenge_fqdn(cert_subject)
        rel = fqdn.rstrip(".")
        z = zone.rstrip(".")
        if rel.endswith("." + z):
            rel = rel[: -(len(z) + 1)]
        elif rel == z:
            rel = "@"
        update = dns.update.Update(
            zone,
            keyring=self._keyring(),
            keyalgorithm=self._algo_name(),
        )
        update.delete(rel, "TXT")
        try:
            dns.query.tcp(
                update, self.cfg.nameserver, port=self.cfg.nameserver_port,
                timeout=10,
            )
        except Exception:
            log.warning(
                "ACME: TXT delete failed (continuing — leftover challenge "
                "record will be ignored by next renewal cycle)",
                fqdn=fqdn,
            )

    def poll_for_value(
        self, fqdn: str, expected: str, *,
        timeout_secs: int = 60, interval_secs: float = 2.0,
        resolver: str | None = None, port: int | None = None,
    ) -> bool:
        """Poll ``fqdn`` for the expected TXT value, or timeout.

        Default resolver is ``self.cfg.nameserver`` — the same
        authority the publish wrote to. Pass ``resolver`` to query
        a different server (used by ``poll_for_value_public`` to
        watch a public recursive resolver during propagation
        windows between authoritative servers).
        """
        import dns.message, dns.query, dns.rdatatype
        target = resolver or self.cfg.nameserver
        target_port = port if port is not None else self.cfg.nameserver_port
        deadline = time.monotonic() + timeout_secs
        q = dns.message.make_query(fqdn, dns.rdatatype.TXT)
        while time.monotonic() < deadline:
            try:
                resp = dns.query.udp(
                    q, target, port=target_port, timeout=5,
                )
                # Filter by rdtype FIRST. When the recursor follows a
                # CNAME (CNAME-delegation pattern), resp.answer
                # contains BOTH the CNAME rrset AND the TXT rrset for
                # the target name. Accessing ``.strings`` on a CNAME
                # RR raises AttributeError -- the prior shape's bare
                # ``except Exception`` swallowed that and returned
                # False, so every probe of a CNAME-followed name
                # failed silently. Operator hit this on 2026-04-29:
                # ``dig +short ... TXT`` returned the value, our gate
                # reported "Visible: none" for the full 30-min budget.
                for rrset in resp.answer:
                    if rrset.rdtype != dns.rdatatype.TXT:
                        continue
                    for r in rrset:
                        text = b"".join(r.strings).decode(
                            "ascii", errors="replace",
                        )
                        if expected in text:
                            return True
            except Exception:
                pass
            time.sleep(interval_secs)
        return False

    def poll_for_value_public(
        self, fqdn: str, expected: str, *,
        timeout_secs: int | None = None,
        interval_secs: float | None = None,
        public_resolvers: list[str] | None = None,
        query_fqdn: str | None = None,
    ) -> tuple[bool, dict[str, bool]]:
        """Wait until ALL configured public recursive resolvers see TXT.

        Calling this AFTER the operator-side authority poll
        guarantees we don't signal the ACME directory before the
        record is visible through the public delegation chain.

        Matches acme.sh behavior: query multiple independent
        resolvers, retry the full set across the timeout window,
        only return ok when every resolver returns the expected
        value. Returns ``(ok, per_resolver_status)`` so the caller
        can log which resolver(s) lagged.

        ``query_fqdn`` overrides the name we query at the recursors.
        Use this in CNAME-delegation setups: ``fqdn`` is where the
        record is *published* (under ``update_zone``), but
        ``query_fqdn = _acme-challenge.<cert_subject>`` is what LE
        actually looks up — the recursor follows the CNAME and
        returns the published TXT. Querying the cert-subject FQDN
        validates the *exact lookup LE will perform*, including
        that the CNAME at the cert subject is publicly visible.
        Defaults to ``fqdn`` when None.

        Resolver list, timeout, and poll interval default to the
        publisher config (operator-overridable in the admin UI).
        """
        resolvers = public_resolvers or list(
            self.cfg.public_resolvers or ["8.8.8.8"]
        )
        if not resolvers:
            resolvers = ["8.8.8.8"]
        timeout = timeout_secs if timeout_secs is not None else (
            self.cfg.public_propagation_timeout_secs or 1800
        )
        interval = interval_secs if interval_secs is not None else (
            self.cfg.public_propagation_interval_secs or 15
        )
        target_fqdn = query_fqdn or fqdn

        seen: dict[str, bool] = {r: False for r in resolvers}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for r in resolvers:
                if seen[r]:
                    continue
                # Single-shot probe per resolver per tick — keeps
                # the per-iteration latency bounded so we re-check
                # already-passing resolvers on the next sweep too
                # (records can disappear from a recursor's cache
                # mid-flight in rare misconfig cases).
                if self._probe_once(r, 53, target_fqdn, expected):
                    seen[r] = True
            if all(seen.values()):
                return True, seen
            time.sleep(interval)
        return all(seen.values()), seen

    def _resolve_authoritative_ns(
        self, name: str, *, seed: str | None = None,
    ) -> str | None:
        """Find an IP of an authoritative NS for the zone containing ``name``.

        Walks up labels asking a seed recursor for NS records until a
        non-empty answer comes back. Uses the first listed NS, resolves
        its A record via the same seed, returns the IP. Used by
        ``poll_for_value_authoritative`` to bypass recursor caches.

        Seed defaults to the first configured public resolver. The seed
        is only used to find the authoritative + resolve the NS hostname
        once -- the actual record query goes direct to the authoritative,
        so seed-side caching doesn't affect the gate decision.
        """
        import dns.message, dns.query, dns.rdatatype, dns.rcode
        seed_ip = seed or (self.cfg.public_resolvers or ["8.8.8.8"])[0]
        labels = name.rstrip(".").split(".")
        for i in range(len(labels)):
            zone = ".".join(labels[i:])
            if not zone:
                continue
            try:
                q = dns.message.make_query(zone, dns.rdatatype.NS)
                resp = dns.query.udp(q, seed_ip, port=53, timeout=5)
            except Exception:
                continue
            ns_targets: list[str] = []
            for rrset in list(resp.answer) + list(resp.authority):
                if rrset.rdtype == dns.rdatatype.NS:
                    for rr in rrset:
                        ns_targets.append(str(rr.target).rstrip("."))
            if not ns_targets:
                continue
            # Resolve the first NS to an IP. Try the additional section
            # first (most servers glue), fall back to a fresh A query.
            for rrset in resp.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    name_str = str(rrset.name).rstrip(".")
                    if name_str in ns_targets:
                        for rr in rrset:
                            return str(rr.address)
            for ns_name in ns_targets:
                try:
                    a_q = dns.message.make_query(ns_name, dns.rdatatype.A)
                    a_resp = dns.query.udp(a_q, seed_ip, port=53, timeout=5)
                    for rrset in a_resp.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            for rr in rrset:
                                return str(rr.address)
                except Exception:
                    continue
        return None

    def _resolve_via_authoritative(
        self, fqdn: str, rdtype, *, max_hops: int = 5,
    ) -> tuple[list[str], str | None]:
        """Resolve ``fqdn`` of type ``rdtype`` by querying authoritative
        servers directly, following CNAMEs by re-finding the target's
        authoritative NS. Returns ``(values, error_or_None)``.

        Bypasses recursor caching entirely. Each CNAME hop re-resolves
        the authoritative NS for the target's zone, so a CNAME from
        zone A pointing to a record in zone B works correctly even
        when those zones live on different nameservers (the supported
        ACME-DNS-01 CNAME-delegation pattern).
        """
        import dns.message, dns.query, dns.rdatatype, dns.rcode
        current = fqdn.rstrip(".") + "."
        for hop in range(max_hops):
            ns_ip = self._resolve_authoritative_ns(current)
            if not ns_ip:
                return [], f"no_authoritative_ns:{current}"
            try:
                q = dns.message.make_query(current, rdtype)
                resp = dns.query.udp(q, ns_ip, port=53, timeout=5)
            except Exception as e:
                return [], f"query_error:{type(e).__name__}"
            if resp.rcode() == dns.rcode.NXDOMAIN:
                return [], f"nxdomain:{current}"
            cname_target: str | None = None
            results: list[str] = []
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for rr in rrset:
                        cname_target = (
                            str(rr.target).rstrip(".") + "."
                        )
                elif rrset.rdtype == rdtype:
                    for rr in rrset:
                        if rdtype == dns.rdatatype.TXT:
                            results.append(
                                b"".join(rr.strings).decode(
                                    "ascii", errors="replace",
                                )
                            )
                        else:
                            results.append(str(rr))
            if results:
                return results, None
            if cname_target and cname_target != current:
                current = cname_target
                continue
            return [], f"no_records:{current}"
        return [], "max_hops_exceeded"

    def _detect_split_horizon_dns(
        self, query_fqdn: str | None = None,
    ) -> str:
        """Detect whether outbound DNS is being rewritten by a
        transparent proxy on the local network.

        Two probes against root servers (198.41.0.4 +
        199.9.14.201, anycast, stable for 25+ years):

        1. **Root SOA**: probe ``. SOA``. Real root returns NOERROR
           + SOA whose ``mname`` contains ``root-servers.net``. A
           proxy that intercepts ALL outbound DNS regardless of
           query content returns NXDOMAIN/REFUSED/wrong SOA --
           caught here.

        2. **Parent-zone NS at root** (only when ``query_fqdn`` is
           given): probe ``<parent_zone> NS`` where parent_zone is
           the last two labels of ``query_fqdn`` (e.g.
           ``example.com.`` for
           ``_acme-challenge.triage.example.com.``). The real root
           NEVER sets the AA (Authoritative Answer) flag for a
           non-root query -- it returns a referral (NS records in
           AUTHORITY section, NS-glue in ADDITIONAL, AA=False).
           A network running split-horizon DNS for the operator's
           zone (intentional privacy posture, e.g. local resolver
           that doesn't leak internal zone queries to upstream)
           responds with AA=True from its local view -- that's
           the signature. The operator's setup is not adversarial;
           the gate just needs to know to skip public-DNS
           verification when the public view isn't visible from
           inside the network.

        Probe (1) catches universal interception. Probe (2) catches
        name-based / split-horizon interception that probe (1)
        misses because the local NS doesn't have a view for the root
        zone but does for the operator's zone.

        Returns one of:

        * ``"clear"``         -- both probes passed (where applicable).
        * ``"split_horizon"`` -- either probe failed the signature.
        * ``"inconclusive"``  -- root probe couldn't reach (timeout).
                                 Caller treats as clear (the gate's
                                 own timeout handles dead networks).

        Pure read; no DNS state mutated.
        """
        import dns.flags, dns.message, dns.query, dns.rdatatype, dns.rcode
        ROOT_IPS = ("198.41.0.4", "199.9.14.201")

        # Probe 1: root SOA.
        root_state = "inconclusive"
        q = dns.message.make_query(".", dns.rdatatype.SOA)
        for ip in ROOT_IPS:
            try:
                resp = dns.query.udp(q, ip, port=53, timeout=5)
            except Exception:
                continue
            if resp.rcode() != dns.rcode.NOERROR:
                return "split_horizon"
            saw_root_soa = False
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    for rr in rrset:
                        if "root-servers.net" in str(rr.mname).lower():
                            saw_root_soa = True
            root_state = "clear" if saw_root_soa else "split_horizon"
            if root_state == "split_horizon":
                return "split_horizon"
            break  # one successful probe is enough

        # Probe 2: parent-zone NS at root, AA-flag check.
        if query_fqdn:
            labels = query_fqdn.rstrip(".").split(".")
            if len(labels) >= 2:
                parent_zone = ".".join(labels[-2:]) + "."
                for ip in ROOT_IPS:
                    try:
                        nsq = dns.message.make_query(
                            parent_zone, dns.rdatatype.NS,
                        )
                        nsresp = dns.query.udp(
                            nsq, ip, port=53, timeout=5,
                        )
                    except Exception:
                        continue
                    if nsresp.flags & dns.flags.AA:
                        # Root NEVER replies AA for a non-root zone.
                        # Local split-horizon resolver DOES.
                        return "split_horizon"
                    break

        return root_state

    def poll_for_value_authoritative(
        self, query_fqdn: str, expected: str, *,
        timeout_secs: int | None = None,
        interval_secs: float | None = None,
    ) -> tuple[bool, dict[str, str]]:
        """Poll the authoritative NS chain for ``query_fqdn`` TXT == ``expected``.

        Cleaner than ``poll_for_value_public`` for the CNAME-delegation
        case: the public-resolver gate suffers from anycast-POP cache
        roulette (one POP holds a stale NXDOMAIN, another has the
        record; the gate fails on the worst-case POP). This function
        queries authoritative servers directly via
        ``_resolve_via_authoritative`` -- no recursor caches in the
        path -- so the gate decision tracks the source-of-truth state.

        LE's own recursor will eventually see the same authoritative
        state; recursor cache lag at LE side is handled by the
        downstream retry loop + grace pause. Returns
        ``(ok, {"state": ..., "values": ...})``.
        """
        import dns.rdatatype as _rdtype
        timeout = timeout_secs if timeout_secs is not None else (
            self.cfg.public_propagation_timeout_secs or 1800
        )
        interval = interval_secs if interval_secs is not None else (
            self.cfg.public_propagation_interval_secs or 15
        )

        # Split-horizon fallback: if the local network's DNS
        # resolver returns the local view for the operator's zones
        # (intentional privacy / no-leak posture, common in
        # homelabs), the gate can't verify the public state from
        # inside that network -- every response carries the local
        # view, not the public-facing authoritative state. Skip
        # the gate, wait for the local-primary -> public-secondary
        # sync (typically a 5-min cron), let LE judge directly.
        # Existing retry-on-ValidationError loop handles LE-side
        # cache lag.
        # Pass query_fqdn so the detector can probe the operator's
        # specific zone for AA-flag-on-non-root-response (catches
        # the name-based split-horizon case that the universal
        # root probe misses).
        egress = self._detect_split_horizon_dns(query_fqdn=query_fqdn)
        if egress == "split_horizon":
            wait = int(getattr(
                self.cfg, "public_propagation_split_horizon_wait_secs", 600,
            ))
            log.warning(
                "ACME: local DNS view shadows public records for this "
                "zone (split-horizon DNS, e.g. operator's privacy "
                "resolver). Skipping public-DNS verification and letting "
                "LE judge directly. Waiting for local-primary -> "
                "public-secondary sync.",
                wait_secs=wait, query_fqdn=query_fqdn,
            )
            time.sleep(wait)
            return True, {
                "state": "split_horizon_wait_then_pass",
                "values": "",
            }

        deadline = time.monotonic() + timeout
        last_err: str = "init"
        last_values: list[str] = []
        while time.monotonic() < deadline:
            values, err = self._resolve_via_authoritative(
                query_fqdn, _rdtype.TXT,
            )
            last_values = values
            last_err = err or "ok"
            for v in values:
                if expected in v:
                    return True, {
                        "state": "ok",
                        "values": ", ".join(values),
                    }
            time.sleep(interval)
        return False, {
            "state": last_err,
            "values": ", ".join(last_values) if last_values else "none",
        }

    def diagnose_resolvers(
        self, fqdn: str, *,
        public_resolvers: list[str] | None = None,
    ) -> dict[str, str]:
        """Probe each public resolver for ``fqdn``; return a per-resolver
        status string suitable for direct log consumption.

        Used after an LE-side ValidationError to triage:
        * "saw_txt:<value>" — resolver sees a TXT (possibly stale).
        * "nxdomain"        — resolver returns NXDOMAIN.
        * "nodata"          — resolver returns NOERROR but no TXT.
        * "error:<type>"    — UDP query failed.

        Pure read; never mutates DNS state.
        """
        import dns.message, dns.query, dns.rcode, dns.rdatatype, dns.resolver
        resolvers = public_resolvers or list(
            self.cfg.public_resolvers or ["8.8.8.8"]
        )
        out: dict[str, str] = {}
        for r in resolvers:
            try:
                q = dns.message.make_query(fqdn, dns.rdatatype.TXT)
                resp = dns.query.udp(q, r, port=53, timeout=5)
                if resp.rcode() == dns.rcode.NXDOMAIN:
                    out[r] = "nxdomain"
                    continue
                values: list[str] = []
                for rrset in resp.answer:
                    for rr in rrset:
                        if rrset.rdtype == dns.rdatatype.TXT:
                            try:
                                values.append(
                                    b"".join(rr.strings).decode(
                                        "ascii", errors="replace",
                                    )
                                )
                            except Exception:
                                pass
                if values:
                    # Truncate sample so log lines stay readable.
                    sample = values[0][:48]
                    out[r] = f"saw_txt:{sample}"
                else:
                    out[r] = "nodata"
            except Exception as e:
                out[r] = f"error:{type(e).__name__}"
        return out

    def _probe_once(
        self, resolver: str, port: int, fqdn: str, expected: str,
    ) -> bool:
        """One UDP TXT query; True iff expected value present.

        Filters answer-section rrsets by rdtype BEFORE accessing
        ``.strings`` -- when the recursor follows a CNAME, the
        answer carries both the CNAME RR and the TXT RR; accessing
        ``.strings`` on the CNAME raises AttributeError, the bare
        ``except`` swallows it, and the function returns False even
        though the TXT was right there. Caused 30-min gate timeouts
        on CNAME-delegated cert subjects (PR-4 / B3 path).
        """
        import dns.message, dns.query, dns.rdatatype
        try:
            q = dns.message.make_query(fqdn, dns.rdatatype.TXT)
            resp = dns.query.udp(q, resolver, port=port, timeout=5)
            for rrset in resp.answer:
                if rrset.rdtype != dns.rdatatype.TXT:
                    continue
                for r in rrset:
                    text = b"".join(r.strings).decode(
                        "ascii", errors="replace",
                    )
                    if expected in text:
                        return True
        except Exception:
            return False
        return False


# ---------------------------------------------------------------------------
# Test-button helpers (called from /admin/acme-status)
# ---------------------------------------------------------------------------

# #77 -- ACME error classification. Maps acme.messages.Error.typ
# (the URN form letsencrypt returns) to a small policy enum:
#   "permanent": skip remaining retries, fail fast
#   "rate_limited": skip + log reset hint
#   "transient": keep retrying with the configured backoff curve
# Anything not in PERMANENT_ERRORS is treated as transient (the right
# default; an unrecognised error class is more likely a transient
# directory hiccup than a permanent block).
_ACME_PERMANENT_ERROR_TYPS: frozenset[str] = frozenset({
    "urn:ietf:params:acme:error:caa",
    "urn:ietf:params:acme:error:accountDoesNotExist",
    "urn:ietf:params:acme:error:unauthorized",
    "urn:ietf:params:acme:error:badCSR",
    "urn:ietf:params:acme:error:rejectedIdentifier",
    "urn:ietf:params:acme:error:malformed",
})
_ACME_RATE_LIMIT_TYPS: frozenset[str] = frozenset({
    "urn:ietf:params:acme:error:rateLimited",
})


def _classify_acme_error(exc: Exception) -> tuple[str, str | None]:
    """Inspect an ACME exception and return (kind, urn_typ_or_none).

    ``kind`` is one of ``"permanent"``, ``"rate_limited"``,
    ``"transient"``. The urn_typ is the raw error type when available
    so the caller can include it in operator-facing messages.

    Walks both ``acme.messages.Error.typ`` (single-error path) and the
    sub-errors list inside ``ValidationError`` (per-authz failures).
    A single permanent sub-error promotes the whole batch to
    permanent: continuing to retry would just re-hit the same
    rejection.
    """
    try:
        from acme import messages as acme_messages  # type: ignore[import]
    except ImportError:
        return ("transient", None)

    def _typ_of(err: Any) -> str | None:
        return getattr(err, "typ", None)

    typs: list[str] = []
    if isinstance(exc, acme_messages.Error):
        t = _typ_of(exc)
        if t:
            typs.append(t)
    # ValidationError carries .failed_authzrs with .body.challenges[].error
    failed = getattr(exc, "failed_authzrs", None) or []
    for authzr in failed:
        body = getattr(authzr, "body", None)
        for ch in getattr(body, "challenges", []) or []:
            err_obj = getattr(ch, "error", None)
            t = _typ_of(err_obj) if err_obj is not None else None
            if t:
                typs.append(t)

    for t in typs:
        if t in _ACME_RATE_LIMIT_TYPS:
            return ("rate_limited", t)
    for t in typs:
        if t in _ACME_PERMANENT_ERROR_TYPS:
            return ("permanent", t)
    return ("transient", typs[0] if typs else None)


def _retry_delay_secs(
    *, attempt: int, backoff: str, configured_secs: int,
) -> int:
    """Compute the sleep before the next retry given the backoff knob.

    ``attempt`` is 1-indexed; the delay is what to sleep AFTER
    finishing attempt N before starting attempt N+1.

    Curves:
      "fixed":       always ``configured_secs``
      "exponential": 15, 30, 60, 120, 300 (capped at configured_secs)
      "fibonacci":   15, 30, 45, 75, 120 (capped at configured_secs)

    The exponential / fibonacci sequences are right for negative-cache
    TTL: first retry fast (caches sometimes just need a poke), later
    retries longer (clear the full neg-cache TTL).
    """
    cap = max(1, int(configured_secs))
    mode = (backoff or "exponential").strip().lower()
    if mode == "fixed":
        return cap
    if mode == "fibonacci":
        # 15 30 45 75 120 195 ...; clamp to cap.
        seq = [15, 30, 45, 75, 120, 195, 315, 510]
    else:  # default exponential
        # 15 30 60 120 300 600 1200 ...; clamp to cap.
        seq = [15, 30, 60, 120, 300, 600, 1200, 2400]
    idx = max(0, min(attempt - 1, len(seq) - 1))
    return min(cap, seq[idx])


def _fmt_exc(e: Exception) -> str:
    """Render an exception in a way that's never empty.

    Some libraries raise bare ``ValueError()`` / ``OSError()`` with no
    args — ``str(e)`` returns ``""`` and the operator sees nothing
    actionable. Fall back to ``repr`` (which always carries the type)
    in that case.
    """
    msg = str(e)
    if msg:
        return f"{type(e).__name__}: {msg}"
    return repr(e)


def test_dns_reachability(cfg: AcmeConfig) -> TestStepResult:
    """Probe the configured nameserver: open UDP+TCP, fire an SOA
    query for the zone, return success on rcode==0 or NOERROR."""
    import dns.message, dns.query, dns.rdatatype
    rfc = cfg.rfc2136
    if not rfc.nameserver:
        return TestStepResult(
            "DNS reachability", False, 0,
            error="rfc2136.nameserver is blank. Paste your authoritative "
                  "DNS server's IP (e.g. dnshost) into the form + Save first.",
        )
    name = rfc.update_zone or (cfg.domains[0] if cfg.domains else "")
    if not name:
        return TestStepResult(
            "DNS reachability", False, 0,
            error="No zone configured to query. Set 'Update zone' or "
                  "at least one entry in 'Domains'.",
        )
    if not name.endswith("."):
        name = name + "."
    t0 = time.monotonic()
    try:
        q = dns.message.make_query(name, dns.rdatatype.SOA)
        resp = dns.query.udp(
            q, rfc.nameserver, port=rfc.nameserver_port, timeout=5,
        )
        rcode = resp.rcode()
        elapsed = _elapsed_ms(t0)
        if rcode == 0:
            return TestStepResult(
                "DNS reachability", True, elapsed,
                detail=f"SOA query OK (rcode=NOERROR) on "
                       f"{rfc.nameserver}:{rfc.nameserver_port} "
                       f"for zone {name}",
            )
        return TestStepResult(
            "DNS reachability", False, elapsed,
            error=f"SOA query returned rcode={rcode} for {name} "
                  f"on {rfc.nameserver}:{rfc.nameserver_port}",
        )
    except Exception as e:
        return TestStepResult(
            "DNS reachability", False, _elapsed_ms(t0),
            error=(
                f"{_fmt_exc(e)} "
                f"(server={rfc.nameserver!r}, "
                f"port={rfc.nameserver_port}, zone={name!r})"
            ),
        )


def test_tsig_authentication(
    cfg: AcmeConfig, tsig_secret: str,
) -> TestStepResult:
    """Send a TSIG-signed UPDATE that adds + removes a probe TXT
    in one transaction. Failure of TSIG-auth surfaces as a BADKEY
    or BADSIG rcode; we report both clearly."""
    import dns.update, dns.query, dns.tsig
    if not tsig_secret:
        return TestStepResult(
            "TSIG authentication", False, 0,
            error="acme_tsig_secret not in secrets store",
        )
    try:
        pub = Rfc2136Publisher(cfg.rfc2136, tsig_secret)
    except Exception as e:
        return TestStepResult(
            "TSIG authentication", False, 0,
            error=f"Publisher config invalid: {_fmt_exc(e)}",
        )
    t0 = time.monotonic()
    try:
        zone = pub._publish_zone()
        # No-op UPDATE: delete the same FQDN the publish path writes
        # to, on the assumption no record exists there yet (caller
        # arranges this — Test 3 cleans up after itself). Targeting
        # a name covered by the operator's update-policy grant means
        # rcode=0 NOERROR proves both TSIG validity AND policy
        # coverage. Using a never-granted probe name (e.g.
        # "__tsig_probe__") would surface rcode=5 REFUSED on a
        # correctly-locked-down zone — wrong signal, since TSIG
        # itself is fine in that case.
        cert_subject = cfg.domains[0] if cfg.domains else ""
        if not cert_subject:
            return TestStepResult(
                "TSIG authentication", False, _elapsed_ms(t0),
                error="No cert domains configured; cannot target a "
                      "policy-covered probe name.",
            )
        challenge_fqdn = pub._challenge_fqdn(cert_subject)
        rel = challenge_fqdn.rstrip(".")
        z = zone.rstrip(".")
        if rel.endswith("." + z):
            rel = rel[: -(len(z) + 1)]
        elif rel == z:
            rel = "@"
        update = dns.update.Update(
            zone,
            keyring=pub._keyring(),
            keyalgorithm=pub._algo_name(),
        )
        update.delete(rel, "TXT")
        resp = dns.query.tcp(
            update, pub.cfg.nameserver, port=pub.cfg.nameserver_port,
            timeout=10,
        )
        rc = resp.rcode()
        elapsed = _elapsed_ms(t0)
        # rcode meaning on a TSIG-signed UPDATE:
        # 0  NOERROR  - TSIG validated AND update-policy permits +
        #               applied (no-op delete on missing record).
        # 5  REFUSED  - TSIG validated BUT update-policy denies the
        #               record name. Tells the operator to widen the
        #               grant or fix the update_zone form field.
        # 9  NOTAUTH  - wrong TSIG key name (raised as PeerBadKey
        #               by dnspython before reaching this point).
        # 16+ TSIG-extended (BADTIME / BADKEY / BADSIG; raised by
        #     dnspython exceptions below).
        if rc == 0:
            return TestStepResult(
                "TSIG authentication", True, elapsed,
                detail=f"TSIG-signed UPDATE accepted by "
                       f"{pub.cfg.nameserver} for {challenge_fqdn} "
                       f"(zone {zone})",
            )
        if rc == 5:
            return TestStepResult(
                "TSIG authentication", False, elapsed,
                error=(
                    f"REFUSED (rcode=5). TSIG itself is OK — the "
                    f"server refused the operation. Most common "
                    f"cause: update-policy on the BIND server "
                    f"doesn't grant key {cfg.rfc2136.tsig_key_name!r} "
                    f"write access to {challenge_fqdn}. "
                    f"Add to the zone: update-policy {{ grant "
                    f"{cfg.rfc2136.tsig_key_name} name "
                    f"{challenge_fqdn} TXT; }};"
                ),
            )
        return TestStepResult(
            "TSIG authentication", False, elapsed,
            error=(
                f"UPDATE rejected: rcode={rc} on {challenge_fqdn} "
                f"(server={pub.cfg.nameserver}, zone={zone})"
            ),
        )
    except dns.tsig.PeerBadKey:
        return TestStepResult(
            "TSIG authentication", False, _elapsed_ms(t0),
            error="Server reports BADKEY: tsig_key_name doesn't match "
                  "any key the server knows about.",
        )
    except dns.tsig.PeerBadSignature:
        return TestStepResult(
            "TSIG authentication", False, _elapsed_ms(t0),
            error="Server reports BADSIG: tsig_secret doesn't match the "
                  "server's key for that name.",
        )
    except Exception as e:
        return TestStepResult(
            "TSIG authentication", False, _elapsed_ms(t0),
            error=(
                f"{_fmt_exc(e)} "
                f"(server={cfg.rfc2136.nameserver!r}, "
                f"key={cfg.rfc2136.tsig_key_name!r}, "
                f"algo={cfg.rfc2136.tsig_algorithm!r})"
            ),
        )


def test_publish_record(
    cfg: AcmeConfig, tsig_secret: str,
) -> TestStepResult:
    """End-to-end: publish a probe TXT, poll until visible, delete.

    Useful when TSIG auth passes but the actual write fails due to
    BIND ``update-policy`` not granting the key permission to write
    the specific record name.
    """
    if not cfg.domains:
        return TestStepResult(
            "Publish & verify TXT", False, 0,
            error="No cert domains configured",
        )
    try:
        pub = Rfc2136Publisher(cfg.rfc2136, tsig_secret)
    except Exception as e:
        return TestStepResult(
            "Publish & verify TXT", False, 0,
            error=f"Publisher config invalid: {_fmt_exc(e)}",
        )
    cert_subject = cfg.domains[0]
    probe_value = f"et-acme-probe-{secrets.token_hex(8)}"
    t0 = time.monotonic()
    try:
        fqdn = pub.publish_txt(cert_subject, probe_value, ttl=30)
    except Exception as e:
        return TestStepResult(
            "Publish & verify TXT", False, _elapsed_ms(t0),
            error=f"Publish failed: {_fmt_exc(e)}",
        )
    visible = pub.poll_for_value(fqdn, probe_value, timeout_secs=30)
    elapsed = _elapsed_ms(t0)
    # Always attempt cleanup, even on visibility failure.
    try:
        pub.delete_txt(cert_subject)
    except Exception:
        pass
    if visible:
        return TestStepResult(
            "Publish & verify TXT", True, elapsed,
            detail=f"Wrote + verified TXT at {fqdn} (probe={probe_value})",
        )
    return TestStepResult(
        "Publish & verify TXT", False, elapsed,
        error=f"TXT was sent but not visible at {fqdn} within 30s. "
              "Check zone update-policy grants the TSIG key write to "
              "this record name.",
    )


def test_full_dns01_cycle(
    cfg: AcmeConfig, tsig_secret: str,
) -> TestRunResult:
    """Run reach -> tsig-auth -> publish-and-verify in sequence."""
    started = _now_iso()
    steps = [
        test_dns_reachability(cfg),
    ]
    if steps[-1].ok:
        steps.append(test_tsig_authentication(cfg, tsig_secret))
        if steps[-1].ok:
            steps.append(test_publish_record(cfg, tsig_secret))
    return TestRunResult(
        overall_ok=all(s.ok for s in steps),
        steps=steps,
        started_at=started,
        finished_at=_now_iso(),
    )


# ---------------------------------------------------------------------------
# ACME client orchestration
# ---------------------------------------------------------------------------

class AcmeRenewer:
    """Async-friendly wrapper that orchestrates the full renewal flow.

    Lifecycle:

    1. ``ensure_account_key`` — generate Ed25519 account key on
       first run; persist encrypted in secrets store.
    2. ``check_and_renew`` — read on-disk cert, parse expiry,
       renew if within threshold; called by the periodic task.
    3. ``issue_now(directory_url)`` — manual trigger for the admin
       UI button; same flow but bypasses the threshold check.
    """

    def __init__(
        self,
        *,
        cfg: AcmeConfig,
        cert_dir: str,
        secrets_store: Any,
        db: sqlite3.Connection,
    ) -> None:
        self.cfg = cfg
        self.cert_dir = Path(cert_dir)
        self.secrets = secrets_store
        self.db = db

    # -- account key --

    def ensure_account_key(self) -> bytes:
        """Return the PEM-encoded RSA-2048 ACME account private key,
        generating + storing on first call.

        #78: previously generated Ed25519 here and then immediately
        regenerated as RSA-2048 in issue_now (jwk-OKP isn't universally
        accepted by ACME directories). Generating RSA up front skips
        the throwaway, halves first-run latency, and removes a comment-
        flagged TODO from the issuance hot path.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        existing = self.secrets.get("acme_account_key")
        if existing:
            return existing.encode("utf-8") if isinstance(existing, str) else existing
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.secrets.set("acme_account_key", pem.decode("utf-8"))
        log.info("ACME: account key generated (RSA-2048) + stored in secrets")
        return pem

    # -- on-disk cert inspection --

    def cert_paths(self) -> tuple[Path, Path]:
        return self.cert_dir / "server.crt", self.cert_dir / "server.key"

    def read_cert_expiry(self) -> datetime | None:
        """Return the on-disk cert's NotAfter, or None if missing /
        unreadable."""
        crt, _ = self.cert_paths()
        if not crt.exists():
            return None
        try:
            from cryptography import x509
            data = crt.read_bytes()
            cert = x509.load_pem_x509_certificate(data)
            na = cert.not_valid_after_utc
            if na.tzinfo is None:
                na = na.replace(tzinfo=timezone.utc)
            return na
        except Exception as e:
            log.warning("ACME: cert parse failed", error=_fmt_exc(e))
            return None

    def cert_metadata(self) -> dict[str, Any]:
        """Read the cert + return ``{ subject_cn, sans, not_before,
        not_after, days_remaining }`` for the admin status page."""
        crt, _ = self.cert_paths()
        if not crt.exists():
            return {"present": False}
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            data = crt.read_bytes()
            cert = x509.load_pem_x509_certificate(data)
            cn = ""
            try:
                attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if attrs:
                    cn = attrs[0].value
            except Exception:
                pass
            sans: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName,
                )
                sans = list(ext.value.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                pass
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
            days_remaining = (na - now).days if na else None
            return {
                "present": True,
                "subject_cn": cn,
                "sans": sans,
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
                "days_remaining": days_remaining,
            }
        except Exception as e:
            return {"present": True, "parse_error": str(e)}

    def needs_renewal(self) -> bool:
        """True iff cert is missing or within renewal_threshold_days
        of expiry."""
        na = self.read_cert_expiry()
        if na is None:
            return True
        return (na - datetime.now(timezone.utc)).days <= self.cfg.renewal_threshold_days

    # -- atomic cert write --

    def _atomic_write_cert(self, fullchain_pem: bytes, key_pem: bytes) -> None:
        """Write fullchain + key under cert_dir without leaving a torn
        pair on disk.

        Both files are written to a sibling tempfile then ``os.replace``-d
        into place. ``os.replace`` is atomic on POSIX and Windows.

        **Order matters: key first, cert second.** The hot-reload watcher
        (`cli.py:_watch_cert`) polls cert mtime and triggers
        ``SSLContext.load_cert_chain`` on change. If we swapped cert
        before key, there's a tiny window where the new cert is paired
        with the old key on disk; the watcher's load_cert_chain would
        SSLError and retry on the next 30s tick. Writing key first
        closes the race -- by the time the cert mtime changes, the
        matching key is already in place.
        """
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        crt, key = self.cert_paths()
        for path, data in ((key, key_pem), (crt, fullchain_pem)):
            tmp = path.with_suffix(path.suffix + ".new")
            tmp.write_bytes(data)
            try:
                if hasattr(os, "chmod"):
                    os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, path)

    # -- ACME order flow --

    def issue_now(self, *, directory_url: str | None = None) -> dict[str, Any]:
        """Run a full ACME order against the configured directory
        (or override). Returns a dict suitable for rendering on
        ``/admin/acme-status``.

        Blocking; caller invokes via ``asyncio.to_thread`` from an
        async context.

        Raises on protocol-level errors (network, account key,
        challenge failure). Caller catches + logs into
        ``acme_renewal_log`` regardless.
        """
        from acme import client as acme_client, messages as acme_messages
        from acme.errors import ConflictError, IssuanceError, ValidationError
        import josepy as jose
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

        directory = directory_url or self.cfg.directory_url
        domains = list(self.cfg.domains)
        if not domains:
            raise RuntimeError("acme.domains is empty")

        # #75 -- live re-attach state. Tells anything watching
        # /admin/acme-status/job that an issue is in flight + which
        # phase it's in. Mark "starting" up front so a page-refresh
        # operator can see the worker exists; transition() updates
        # phase as we move through the order.
        from email_triage.web import acme_job_state
        max_attempts_planned = max(1, int(self.cfg.validation_retries) + 1)
        acme_job_state.start(
            domains=domains,
            directory_url=directory,
            max_attempts=max_attempts_planned,
        )

        # B2 — CAA pre-flight. Catches the silent failure mode where a
        # CAA record forbids letsencrypt.org. Always run as a probe
        # (cheap; one DNS query per label per domain). Hard-fail only
        # when caa_enforce is set; otherwise log + proceed so operators
        # see what would have happened before opting in.
        try:
            caa_ok, caa_problems = caa_preflight(
                domains,
                public_resolvers=self.cfg.rfc2136.public_resolvers,
            )
        except Exception as exc:
            # Pre-flight itself blowing up is a soft failure — never
            # block issuance because of a bug in the probe.
            log.warning(
                "ACME: CAA pre-flight crashed; proceeding without check",
                error=_fmt_exc(exc),
            )
            caa_ok, caa_problems = True, []
        if not caa_ok:
            log.warning(
                "ACME: CAA pre-flight found hostile records",
                problems=caa_problems,
                enforce=self.cfg.caa_enforce,
            )
            if self.cfg.caa_enforce:
                raise RuntimeError(
                    "ACME aborted: CAA records forbid letsencrypt.org "
                    "for one or more configured domains. "
                    f"Problems: {caa_problems}"
                )
        elif caa_problems:
            # Inconclusive lookups, not blocking.
            log.info(
                "ACME: CAA pre-flight had inconclusive lookups",
                notes=caa_problems,
            )

        # #76 -- CNAME pre-flight. When the operator uses the
        # CNAME-delegation pattern (rfc2136.update_zone set to
        # something different from the cert subject), LE will query
        # _acme-challenge.<cert_subject> and follow the CNAME to the
        # update-zone target. If that CNAME isn't published yet (or
        # points wrong, or hasn't propagated externally), the
        # publish/poll cycle is ~8min wasted before LE NXDOMAINs out.
        # Pre-flight catches this in seconds, with an actionable
        # error message. Direct mode (no update_zone) is a no-op
        # since there's no CNAME to verify.
        if (
            getattr(self.cfg.rfc2136, "update_zone", None)
            and self.cfg.rfc2136.update_zone.strip()
        ):
            try:
                cname_ok, cname_problems = cname_preflight(
                    domains,
                    update_zone=self.cfg.rfc2136.update_zone,
                    public_resolvers=self.cfg.rfc2136.public_resolvers,
                )
            except Exception as exc:
                log.warning(
                    "ACME: CNAME pre-flight crashed; proceeding without check",
                    error=_fmt_exc(exc),
                )
                cname_ok, cname_problems = True, []
            if not cname_ok:
                err = (
                    "ACME aborted at CNAME pre-flight: "
                    "the _acme-challenge.<cert_subject> CNAME isn't "
                    "visible at every public resolver, OR doesn't "
                    "point under the configured update_zone. "
                    "Publishing forward will NXDOMAIN at LE after "
                    "wasting the publish/poll/answer cycle. "
                    f"Problems: {cname_problems}"
                )
                acme_job_state.finish_failure(
                    err, kind="cname_preflight",
                )
                raise RuntimeError(err)
            elif cname_problems:
                log.info(
                    "ACME: CNAME pre-flight had inconclusive lookups",
                    notes=cname_problems,
                )

        account_pem = self.ensure_account_key()
        account_key = serialization.load_pem_private_key(
            account_pem, password=None,
        )
        # #78 -- ed25519 throwaway path removed. ensure_account_key()
        # now generates RSA-2048 directly. Older installs that already
        # have an Ed25519 account key from before this change are
        # detected here and regenerated as RSA-2048 (one-time
        # migration; the new key registers as a fresh account on the
        # ACME directory but that's free and harmless).
        if isinstance(account_key, ed25519.Ed25519PrivateKey):
            log.info(
                "ACME: legacy Ed25519 account key detected; "
                "regenerating as RSA-2048 (one-time migration)."
            )
            account_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048,
            )
            account_pem = account_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.secrets.set("acme_account_key", account_pem.decode("utf-8"))

        jose_key = jose.JWKRSA(key=account_key)
        # Directory + ACME client setup.
        import requests
        net = acme_client.ClientNetwork(
            jose_key, user_agent="email-triage-acme/1.0",
        )
        directory_obj = acme_client.ClientV2.get_directory(directory, net)
        client = acme_client.ClientV2(directory_obj, net=net)

        # Register or refresh account. The account key persists in
        # the secrets store across runs, so the second-and-later
        # invocations will hit the directory's "this key is already
        # registered" path. The acme library surfaces that as a
        # ConflictError carrying the existing account's URL — query
        # it back so the client has a registered RegistrationResource
        # to attach to subsequent requests.
        try:
            registration = client.new_account(
                acme_messages.NewRegistration.from_data(
                    email=self.cfg.account_email or None,
                    terms_of_service_agreed=True,
                )
            )
            log.info("ACME: account registered",
                     email=self.cfg.account_email)
        except ConflictError as e:
            registration = client.query_registration(
                acme_messages.RegistrationResource(
                    body=acme_messages.Registration(),
                    uri=e.location,
                )
            )
            log.info("ACME: existing account reattached",
                     account_uri=e.location)
        except acme_messages.Error as e:
            # Defensive: older directories that signal "already
            # registered" via a Problem document rather than 409.
            if "already" in str(e).lower():
                pass
            else:
                raise

        # Build a CSR for the cert (RSA-2048 for the cert key — broadly
        # compatible with browsers; ed25519 cert keys still aren't
        # universally accepted).
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # #78 -- CN field has a 64-char hard limit per RFC 5280. When
        # domains[0] overflows (long subdomains, internal naming
        # conventions), x509.NameAttribute raises ValueError. Fall
        # back to a SAN-only CSR -- modern CAs (LE included) accept
        # CSRs with no CN as long as the SAN list is non-empty, and
        # browsers match on SAN regardless. Most CSR tooling defaults
        # to including CN; explicitly omitting it here is the right
        # call when the constraint binds.
        subject_name = None
        if len(domains[0]) <= 64:
            subject_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
            ])
        else:
            log.warning(
                "ACME: domains[0] exceeds CN 64-char limit; "
                "issuing SAN-only CSR.",
                domain=domains[0], length=len(domains[0]),
            )
            # cryptography requires *some* subject; empty Name is OK.
            subject_name = x509.Name([])
        csr_builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject_name)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
                critical=False,
            )
        )
        csr = csr_builder.sign(cert_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        if self.cfg.challenge != "dns-01":
            raise NotImplementedError(
                f"Only dns-01 implemented; got {self.cfg.challenge!r}. "
                "HTTP-01 stub lives in this module — see #67 followups."
            )

        tsig_secret = self.secrets.get(self.cfg.rfc2136.tsig_secret_ref)
        if not tsig_secret:
            raise RuntimeError(
                f"Secrets store missing key "
                f"{self.cfg.rfc2136.tsig_secret_ref!r}"
            )
        publisher = Rfc2136Publisher(self.cfg.rfc2136, tsig_secret)

        # Validation-retry loop. Each attempt: new_order, publish
        # TXTs, poll local + public resolvers, sleep grace, answer,
        # finalize. On ValidationError (LE-side recursive lookup
        # failed — e.g. negative cache, slow downstream resolver),
        # delete the TXTs, sleep ``validation_retry_delay_secs``,
        # and start a fresh order. Matches acme.sh's "retry on
        # transient DNS failure" behavior.
        max_attempts = max(1, int(self.cfg.validation_retries) + 1)
        last_error: Exception | None = None
        final_order = None
        # #78a -- per-issue correlation id. Stamped on every issuance
        # log line below + on the publisher's per-attempt sweep so a
        # multi-attempt failure in journalctl can be filtered down to
        # one specific issue_now invocation. attempt=N already
        # distinguishes within a run; attempt_id distinguishes across
        # runs / processes / parallel-tab-clicks.
        import secrets as _secrets
        attempt_id = _secrets.token_hex(4)
        log.info(
            "ACME: issue_now starting",
            attempt_id=attempt_id, domains=domains,
            directory=("staging" if "staging" in directory else "prod"),
        )
        for attempt in range(1, max_attempts + 1):
            # #103 -- cancel check at the top of every retry-loop
            # iteration. A click while we were sleeping between
            # attempts (or sitting in propagation poll) takes effect
            # within ~one poll-cycle of the click. Mid-finalizing
            # cancels are intentionally ignored (see check before
            # the finalize call below) -- discarding a successful
            # issuance because the operator clicked while LE was
            # already validating wastes a duplicate-cert rate slot
            # for nothing.
            if acme_job_state.is_cancel_requested():
                err_msg = (
                    "ACME issuance cancelled by operator before "
                    f"attempt {attempt}/{max_attempts}."
                )
                acme_job_state.finish_failure(err_msg, kind="cancelled")
                raise RuntimeError(err_msg)
            # #75 -- live re-attach phase tracking. transition() updates
            # the singleton so the page can poll /admin/acme-status/job
            # and re-attach mid-issue.
            acme_job_state.transition(
                "publishing", attempt=attempt, max_attempts=max_attempts,
            )
            order = client.new_order(csr_pem)
            # #104 -- persist the LE order URL so a process kill
            # mid-finalize can resume from the same order rather
            # than burning a fresh duplicate-cert slot.
            try:
                order_url_val = getattr(order, "uri", None) or getattr(
                    getattr(order, "body", None), "uri", None,
                )
            except Exception:
                order_url_val = None
            if order_url_val:
                acme_job_state.transition(
                    "publishing", order_url=order_url_val,
                )
            published_for: list[str] = []
            try:
                for authz in order.authorizations:
                    domain = authz.body.identifier.value
                    # Pick the dns-01 challenge.
                    challenge = None
                    for c in authz.body.challenges:
                        if c.typ == "dns-01":
                            challenge = c
                            break
                    if challenge is None:
                        raise RuntimeError(
                            f"Directory did not offer dns-01 for {domain}"
                        )
                    response, validation = challenge.response_and_validation(jose_key)
                    # #78a -- stray TXT cleanup at attempt start. If a
                    # prior process crashed mid-flow, an orphaned
                    # _acme-challenge.* TXT can sit in the zone forever
                    # and confuse LE's recursive lookup (multiple TXTs
                    # at the same name, only one of which matches the
                    # current order). Sweep before publishing: a
                    # delete_txt is idempotent and the publish_txt
                    # immediately after restores the right value.
                    try:
                        publisher.delete_txt(domain)
                    except Exception as exc:
                        log.warning(
                            "ACME: pre-publish TXT sweep failed; continuing",
                            domain=domain, attempt=attempt,
                            attempt_id=attempt_id,
                            error=_fmt_exc(exc),
                        )
                    fqdn = publisher.publish_txt(domain, validation, ttl=60)
                    published_for.append(domain)
                    log.info(
                        "ACME: published challenge TXT",
                        domain=domain, fqdn=fqdn, attempt=attempt,
                        attempt_id=attempt_id,
                    )
                    # Two-stage propagation check:
                    # 1. Configured authoritative server — confirms
                    #    dynamic update applied.
                    # 2. Public recursive resolvers — confirms the
                    #    delegation chain LE queries serves the
                    #    record. When an operator's authoritative
                    #    setup separates the update target from the
                    #    public-facing nameservers, propagation can
                    #    lag a single ACME validation window.
                    acme_job_state.transition("polling_local")
                    if not publisher.poll_for_value(
                        fqdn, validation, timeout_secs=120,
                    ):
                        raise RuntimeError(
                            f"Challenge TXT not visible on the "
                            f"configured nameserver "
                            f"({publisher.cfg.nameserver}) within "
                            f"120s of publish — the dynamic update "
                            f"may have been rejected silently."
                        )
                    acme_job_state.visibility(domain, local=True)
                    # B3 — gate by the cert-subject FQDN, not the
                    # update-zone FQDN. LE will query
                    # ``_acme-challenge.<cert_subject>`` and follow the
                    # CNAME (if any) to the update-zone target. The
                    # recursor follows CNAMEs on TXT lookups
                    # automatically, so querying the cert-subject
                    # validates the *exact* path LE takes — including
                    # that the CNAME at the cert subject is publicly
                    # visible. The previous gate queried the
                    # update-zone target, which goes green even when
                    # the CNAME is unpropagated externally.
                    cert_subject_fqdn = (
                        f"_acme-challenge.{domain.rstrip('.')}."
                    )
                    log.info(
                        "ACME: TXT visible on local authority; polling "
                        "authoritative NS chain (bypasses recursor cache)",
                        domain=domain,
                        publish_fqdn=fqdn,
                        query_fqdn=cert_subject_fqdn,
                    )
                    # PR-4 / B3 follow-up: query authoritative servers
                    # directly instead of public recursors. Bypasses
                    # anycast-POP cache roulette where one recursor POP
                    # holds a stale NXDOMAIN while another sees the
                    # record. LE will follow the same authoritative
                    # chain; cache lag on LE's side is handled by the
                    # outer retry loop + pre-validation grace pause.
                    acme_job_state.transition("polling_authoritative")
                    ok, info = publisher.poll_for_value_authoritative(
                        cert_subject_fqdn, validation,
                    )
                    if ok:
                        acme_job_state.visibility(
                            domain, authoritative=True,
                        )
                    if not ok:
                        raise RuntimeError(
                            f"Challenge TXT not visible at the "
                            f"authoritative NS chain within "
                            f"{publisher.cfg.public_propagation_timeout_secs}s "
                            f"when querying {cert_subject_fqdn}. "
                            f"State: {info.get('state')}. "
                            f"Values: {info.get('values') or 'none'}. "
                            f"Verify the CNAME at {cert_subject_fqdn} "
                            f"is published to the registrar's "
                            f"authoritative NS AND that the TXT at "
                            f"{fqdn} reached the public-facing "
                            f"nameserver for that zone."
                        )
                    # Grace pause: even after the public resolvers
                    # we poll see the record, LE's own recursive
                    # path may still be holding a negative cache
                    # entry from an earlier NXDOMAIN. Sleep before
                    # signaling LE so that cache has time to expire.
                    grace = max(0, int(self.cfg.pre_validation_grace_secs))
                    if grace:
                        acme_job_state.transition("grace")
                        log.info(
                            "ACME: pre-validation grace pause",
                            secs=grace, domain=domain,
                        )
                        time.sleep(grace)
                    acme_job_state.transition("answering")
                    client.answer_challenge(challenge, response)
                    log.info(
                        "ACME: challenge answered, awaiting validation",
                        domain=domain, attempt=attempt,
                        attempt_id=attempt_id,
                    )

                acme_job_state.transition("finalizing")
                # Finalize. acme.client uses naive datetimes
                # (implicit UTC) internally — passing a tz-aware
                # datetime raises "can't compare offset-naive and
                # offset-aware datetimes" inside its poll loop.
                deadline = datetime.utcnow() + timedelta(seconds=120)
                final_order = client.poll_and_finalize(
                    order, deadline=deadline,
                )
                fullchain_pem = final_order.fullchain_pem.encode("utf-8")
                # Success — break out of retry loop.
                break
            except ValidationError as e:
                last_error = e
                # #77 -- classify before deciding to retry. CAA / badCSR
                # / accountDoesNotExist / etc are permanent: retrying
                # just burns the validation_retries budget and may
                # rate-limit-trip the directory. rateLimited aborts
                # immediately (retrying makes it worse).
                err_kind, err_typ = _classify_acme_error(e)
                # B4 — diagnostic re-probe. LE returned NXDOMAIN /
                # similar; immediately probe each public resolver for
                # the cert-subject FQDN and log per-resolver state.
                # Helps the operator triage:
                #   all green   -> LE recursor lagging; quick retry.
                #   some red    -> propagation incomplete; longer wait.
                #   all red     -> CNAME / publication gap; abort.
                diagnostics: dict[str, dict[str, str]] = {}
                for d in [a.body.identifier.value for a in order.authorizations]:
                    cert_subject_fqdn = (
                        f"_acme-challenge.{d.rstrip('.')}."
                    )
                    try:
                        diagnostics[d] = publisher.diagnose_resolvers(
                            cert_subject_fqdn,
                        )
                    except Exception as probe_exc:
                        diagnostics[d] = {
                            "_probe_error": _fmt_exc(probe_exc),
                        }
                log.warning(
                    "ACME: validation failed (LE-side DNS lookup)",
                    attempt=attempt, max_attempts=max_attempts,
                    attempt_id=attempt_id,
                    error=_fmt_exc(e),
                    classification=err_kind,
                    error_typ=err_typ,
                    resolver_diagnostics=diagnostics,
                )
                # Permanent / rate-limited errors abort the retry loop.
                # Clean up TXTs in the finally below, then re-raise so
                # the outer try/except marks finish_failure with the
                # right kind.
                if err_kind in ("permanent", "rate_limited"):
                    for d in published_for:
                        try:
                            publisher.delete_txt(d)
                        except Exception:
                            pass
                    err_msg = (
                        f"ACME validation aborted after {attempt} attempts "
                        f"(kind={err_kind}, typ={err_typ or 'unknown'}). "
                        f"Last error: {_fmt_exc(e)}"
                        + (
                            " (retrying makes rate-limit worse; "
                            "wait for the limit window to reset.)"
                            if err_kind == "rate_limited" else ""
                        )
                    )
                    acme_job_state.finish_failure(err_msg, kind=err_kind)
                    raise RuntimeError(err_msg) from e
                # Transient: fall through to finally → cleans up TXTs,
                # then the loop sleeps and starts a fresh order.
            finally:
                for d in published_for:
                    try:
                        publisher.delete_txt(d)
                    except Exception:
                        pass

            # Only reached on retry path (success path 'break'-ed above).
            if attempt < max_attempts:
                # #77 -- backoff curve. Exponential / fibonacci default;
                # operator can pin to "fixed" via config.
                delay = _retry_delay_secs(
                    attempt=attempt,
                    backoff=getattr(
                        self.cfg, "validation_retry_backoff", "exponential",
                    ),
                    configured_secs=self.cfg.validation_retry_delay_secs,
                )
                acme_job_state.transition(
                    "retrying",
                    last_error=_fmt_exc(last_error) if last_error else None,
                )
                log.info(
                    "ACME: sleeping before retry",
                    secs=delay, next_attempt=attempt + 1,
                    attempt_id=attempt_id,
                    backoff=getattr(
                        self.cfg, "validation_retry_backoff", "exponential",
                    ),
                )
                time.sleep(delay)
        else:
            # Loop exhausted without break → all attempts failed.
            err_msg = (
                f"ACME validation failed after {max_attempts} attempts. "
                f"Last error: "
                f"{_fmt_exc(last_error) if last_error else 'unknown'}"
            )
            acme_job_state.finish_failure(err_msg, kind="validation")
            raise RuntimeError(err_msg)

        if final_order is None:
            raise RuntimeError("ACME: no final_order — internal flow bug")

        # Persist atomically.
        cert_key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._atomic_write_cert(fullchain_pem, cert_key_pem)

        meta = self.cert_metadata()
        insert_acme_renewal_log(
            self.db,
            domain=domains[0],
            outcome="renewed",
            not_before=meta.get("not_before"),
            not_after=meta.get("not_after"),
        )
        # PR 10 / E — metrics. Outcome is bounded (renewed | failed |
        # skipped_fresh | deferred) so cardinality stays small.
        try:
            from email_triage import metrics as metrics_mod
            metrics_mod.counter(
                "et_acme_renewals_total",
                "ACME issuance outcomes by directory and result.",
            ).inc(
                directory="staging" if "staging" in directory else "prod",
                outcome="renewed",
            )
        except Exception:
            pass
        log.info("ACME: cert issued + written",
                 domain=domains[0], not_after=meta.get("not_after"),
                 attempt_id=attempt_id)
        # #75 -- terminal-success state for the live re-attach.
        acme_job_state.finish_success(meta)
        return meta

    @single_flight(
        lambda self, **kw: f"acme:issue:{(self.cfg.domains or ['_'])[0]}"
    )
    async def issue_now_async(
        self, *, directory_url: str | None = None,
    ) -> dict[str, Any]:
        """Lock-guarded async wrapper around ``issue_now``.

        Both call sites — admin "Issue Now" route and the periodic
        renewal_loop — funnel through this entry point so a manual
        click during the 24h tick can't race + double-order against
        Let's Encrypt (5 prod certs/week/domain rate limit).

        Second concurrent caller raises ``SingleFlightBusy`` (HTTP
        409); the admin UI surfaces "issuance already in progress",
        the renewal_loop catches and skips the tick.

        #75 -- the live re-attach state singleton (acme_job_state) is
        marked finish_failure on any unhandled exception out of the
        inner sync issue_now. issue_now itself marks finish_success
        on the happy path and finish_failure on the loop-exhausted
        validation-error path; this wrapper catches the rest
        (publish_txt errors, network errors, finalize errors, etc.)
        so the page can re-attach and see the failure state instead
        of a stuck non-terminal phase.
        """
        from email_triage.web import acme_job_state
        try:
            return await asyncio.to_thread(
                self.issue_now, directory_url=directory_url,
            )
        except Exception as exc:
            # Only mark the job state if it's still showing in-flight
            # -- the inner issue_now may have already called
            # finish_failure with a more specific error/kind.
            snap = acme_job_state.current_state()
            if snap.get("in_flight"):
                acme_job_state.finish_failure(
                    f"{type(exc).__name__}: {exc}",
                    kind=type(exc).__name__,
                )
            raise

    async def check_and_renew_async(self) -> dict[str, Any]:
        """Async background-task entrypoint with single-flight on
        the actual issuance call."""
        from email_triage.single_flight import SingleFlightBusy
        if not self.cfg.enabled:
            return {"skipped": "acme.enabled=false"}
        if not self.cfg.domains:
            return {"skipped": "acme.domains empty"}
        if not self.needs_renewal():
            insert_acme_renewal_log(
                self.db, domain=self.cfg.domains[0],
                outcome="skipped_fresh",
                not_after=self.cert_metadata().get("not_after"),
            )
            return {"action": "skipped", "reason": "fresh"}
        try:
            meta = await self.issue_now_async()
            return {"action": "renewed", **meta}
        except SingleFlightBusy:
            log.info(
                "ACME: renewal tick saw issue in progress; deferring",
                domain=self.cfg.domains[0],
            )
            return {"action": "deferred", "reason": "issue_in_progress"}
        except Exception as e:
            insert_acme_renewal_log(
                self.db, domain=self.cfg.domains[0],
                outcome="failed",
                error=_fmt_exc(e),
            )
            log.error(
                "ACME renewal failed; existing cert unchanged",
                exc_info=e,
                domain=self.cfg.domains[0],
            )
            raise

    def check_and_renew(self) -> dict[str, Any]:
        """Background-task entrypoint. Renew if needed; no-op otherwise."""
        if not self.cfg.enabled:
            return {"skipped": "acme.enabled=false"}
        if not self.cfg.domains:
            return {"skipped": "acme.domains empty"}
        if not self.needs_renewal():
            insert_acme_renewal_log(
                self.db, domain=self.cfg.domains[0],
                outcome="skipped_fresh",
                not_after=self.cert_metadata().get("not_after"),
            )
            return {"action": "skipped", "reason": "fresh"}
        try:
            meta = self.issue_now()
            return {"action": "renewed", **meta}
        except Exception as e:
            insert_acme_renewal_log(
                self.db, domain=self.cfg.domains[0],
                outcome="failed",
                error=_fmt_exc(e),
            )
            log.error(
                "ACME renewal failed; existing cert unchanged",
                exc_info=e,
                domain=self.cfg.domains[0],
            )
            raise


async def renewal_loop(renewer: AcmeRenewer, *, stop_event: asyncio.Event) -> None:
    """Long-running background task: tick every
    ``check_interval_hours``, call ``check_and_renew_async``.

    Routes through the single-flight-guarded async path so a
    concurrent manual "Issue Now" click can't race the tick.
    """
    interval = max(1, renewer.cfg.check_interval_hours) * 3600
    log.info("ACME: renewal loop starting",
             interval_hours=renewer.cfg.check_interval_hours)
    while not stop_event.is_set():
        try:
            await renewer.check_and_renew_async()
        except Exception as e:
            log.error("ACME renewal tick raised", exc_info=e)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
        else:
            break
    log.info("ACME: renewal loop stopped")
