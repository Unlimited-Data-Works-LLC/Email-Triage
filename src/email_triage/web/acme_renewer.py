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

from email_triage.secrets import read_secret

import asyncio
import os
import secrets
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email_triage._errfmt import fmt_exc
from email_triage._isotime import assume_utc_if_naive, now_utc_iso  # N-357b R31
from pathlib import Path
from typing import Any

from email_triage.config import AcmeConfig, Rfc2136Config
from email_triage.single_flight import single_flight
from email_triage.triage_logging import get_logger
from email_triage.web.db_auth_helpers import insert_acme_renewal_log
from email_triage._secret_keys import ACME_ACCOUNT_KEY_KEY  # N-231 R22 stored-secret-key SSOT


log = get_logger("web.acme")


# -d/DA-F1 (2026-07-11) — CONFIG-DRIVEN DNS query timeouts. Two
# knobs because DA panel refutation caught that dns.query.udp probes
# (12 sites in this file) run under a SHORTER 5s budget than the
# dns.query.tcp UPDATE/delete-TXT paths (10s). Same-drive fold per
# operator directive "expose ALL".
#   _ACME_DNS_UPDATE_TIMEOUT_SECS — dns.query.tcp UPDATE / delete-TXT
#      (RFC 2136 signed operations); default 10s preserves prior
#      hardcoded value at :498, :527, :1213.
#   _ACME_DNS_PROBE_TIMEOUT_SECS — dns.query.udp probes (CAA lookup,
#      NS resolution, propagation-verify, resolver iteration); default
#      5s preserves prior hardcoded value at :124, :558, :672, :693,
#      :723, :809, :836, :953, :995, :1135.
_ACME_DNS_UPDATE_TIMEOUT_SECS: float = 10.0
_ACME_DNS_PROBE_TIMEOUT_SECS: float = 5.0


def configure_acme_dns_query_timeout(
    timeout_secs: float,
    probe_timeout_secs: float | None = None,
) -> None:
    """-d — set the ACME dns.query.* budgets.

    Called at boot from ``load_config._wire_module_singletons`` with
    ``config.tls.acme.dns_query_timeout_secs`` (UPDATE/tcp path) and
    optionally ``dns_probe_timeout_secs`` (udp probe path). Rejects
    non-positive values. Old single-knob call shape still works and
    only tunes the UPDATE budget; new callers pass both.
    """
    global _ACME_DNS_UPDATE_TIMEOUT_SECS, _ACME_DNS_PROBE_TIMEOUT_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _ACME_DNS_UPDATE_TIMEOUT_SECS = float(timeout_secs)
    if (
        probe_timeout_secs is not None
        and isinstance(probe_timeout_secs, (int, float))
        and probe_timeout_secs > 0
    ):
        _ACME_DNS_PROBE_TIMEOUT_SECS = float(probe_timeout_secs)


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
                    q, resolver_ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS,
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
# CNAME pre-flight
# ---------------------------------------------------------------------------

#: Punch 589: the prefix of the one message ``cname_preflight`` emits when it
#: could query no resolver at all; the renewer logs that case at WARNING (a
#: disabled check), not as an inconclusive lookup.
CNAME_PREFLIGHT_SKIPPED = "CNAME pre-flight skipped"


def cname_preflight(
    domains: list[str],
    *,
    update_zone: str | None,
    public_resolvers: list[str] | None = None,
    timeout_secs: int = 5,
) -> tuple[bool, list[str]]:
    """Verify the CNAME-delegation chain BEFORE publishing a TXT.

     -- the renewer publishes ``_acme-challenge.<update_zone>``
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

    Punch 589: a resolver IP with no entry in
    :data:`email_triage.config.DOH_JSON_ENDPOINTS` is SKIPPED, with a message
    naming it; it is never replaced by another provider. If no configured
    resolver has an endpoint, the pre-flight is skipped with ok=True and a
    message saying so: it is a fail-fast convenience in front of Let's Encrypt,
    which still validates the record, and refusing here is what made a
    Quad9-only install unable to renew at all. Every per-lookup message names
    the endpoint that was actually queried.
    """
    if not update_zone:
        return True, []

    import dns.name as _dnsname

    from email_triage._egress import Intent, egress_client

    # N-374: query over DoH (HTTPS:443) instead of dns.query.udp on port 53.
    # On split-horizon LANs the operator's `public_resolvers` list (e.g.
    # `[8.8.8.8, 1.1.1.1, 9.9.9.9]`) reaches the LAN authoritative NS
    # transparently — every "public" UDP:53 query gets intercepted and
    # answered by the LAN NS, so a pre-flight against the LAN copy of the
    # zone silently reports the wrong view as public. DoH escapes the
    # intercept: HTTPS to `dns.google` / `cloudflare-dns.com` /
    # `dns.quad9.net` reaches the actual public resolver.
    #
    # Preserve the operator's choice of resolver family by mapping each
    # configured IP to its provider's DoH endpoint (the config SSOT). An IP
    # with no endpoint is skipped by name, never sent to a provider the
    # operator did not name (punch 589).
    from email_triage.config import DOH_JSON_ENDPOINTS

    resolvers = [r.strip() for r in (public_resolvers or ["8.8.8.8"]) if r.strip()]
    messages: list[str] = []
    queryable: list[tuple[str, str]] = []
    for resolver_ip in resolvers:
        endpoint = DOH_JSON_ENDPOINTS.get(resolver_ip)
        if endpoint is None:
            messages.append(
                f"resolver {resolver_ip} skipped: it has no DNS-over-HTTPS "
                f"JSON endpoint this pre-flight can query (it is still used "
                f"by the UDP propagation checks)."
            )
            continue
        queryable.append((resolver_ip, endpoint))
    if not queryable:
        messages.append(
            f"{CNAME_PREFLIGHT_SKIPPED}: none of the configured resolvers "
            f"{resolvers} has a DNS-over-HTTPS JSON endpoint (supported: "
            f"{sorted(DOH_JSON_ENDPOINTS)}). Let's Encrypt still validates "
            f"the CNAME."
        )
        return True, messages

    expected_target = (
        _dnsname.from_text(update_zone.rstrip(".") + ".")
    )
    any_ok_for_each_domain: dict[str, bool] = {}

    # Route through the egress funnel — Intent.PUBLIC_FETCH applies the
    # SSRF-guard-only pass-through policy so a compromised _DOH_ENDPOINTS
    # entry can't become a link-local/metadata probe. Non-PHI: ACME
    # pre-flight on public domain names. Fixes the N-374b egress-funnel-
    # pin regression the DoH switch introduced.
    with egress_client(intent=Intent.PUBLIC_FETCH,
                       timeout=float(timeout_secs)) as client:
        for d in domains:
            cert_subject = d.rstrip(".")
            cname_q_name = f"_acme-challenge.{cert_subject}."
            any_ok_for_each_domain[d] = False
            for resolver_ip, endpoint in queryable:
                # Punch 589: every message names the endpoint actually
                # queried, alongside the configured IP it stands for.
                via = f"via {endpoint} (resolver {resolver_ip})"
                try:
                    resp = client.get(
                        endpoint,
                        params={"name": cname_q_name, "type": "CNAME"},
                        headers={"accept": "application/dns-json"},
                    )
                    if resp.status_code != 200:
                        messages.append(
                            f"{d}: DoH HTTP {resp.status_code} for "
                            f"{cname_q_name} {via}"
                        )
                        continue
                    data = resp.json()
                    # RFC 8484 / JSON API: Status field maps to DNS rcode
                    # (0=NOERROR, 3=NXDOMAIN).
                    status = data.get("Status")
                    if status == 3:
                        messages.append(
                            f"{d}: NXDOMAIN at {cname_q_name} {via} "
                            f"-- the CNAME isn't published yet (or not "
                            f"visible externally)."
                        )
                        continue
                    if status != 0:
                        messages.append(
                            f"{d}: rcode={status} at {cname_q_name} {via}"
                        )
                        continue
                    # DoH JSON answer entries: {"name":.., "type":<int>,
                    # "TTL":.., "data":..}. CNAME is dnstype 5.
                    got_target: str | None = None
                    for ans in data.get("Answer", []) or []:
                        if ans.get("type") == 5:
                            got_target = (
                                str(ans.get("data", "")).rstrip(".") + "."
                            )
                            break
                    if got_target is None:
                        messages.append(
                            f"{d}: no CNAME at {cname_q_name} {via} "
                            f"(answer had no CNAME record)"
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
                        f"{got_target!r} {via}; "
                        f"expected target under {update_zone!r}"
                    )
                except Exception as exc:
                    messages.append(
                        f"{d}: DoH lookup failed {via}: "
                        f"{fmt_exc(exc, with_class=True)}"
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
    return now_utc_iso()


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
            timeout=_ACME_DNS_UPDATE_TIMEOUT_SECS,
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
                timeout=_ACME_DNS_UPDATE_TIMEOUT_SECS,
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
                    q, target, port=target_port, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS,
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
                resp = dns.query.udp(q, seed_ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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
                    a_resp = dns.query.udp(a_q, seed_ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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
                resp = dns.query.udp(q, ns_ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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
                resp = dns.query.udp(q, ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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
                            nsq, ip, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS,
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
                resp = dns.query.udp(q, r, port=53, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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
            resp = dns.query.udp(q, resolver, port=port, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS)
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

#  -- ACME error classification. Maps acme.messages.Error.typ
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
            q, rfc.nameserver, port=rfc.nameserver_port, timeout=_ACME_DNS_PROBE_TIMEOUT_SECS,
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
                f"{fmt_exc(e, with_class=True)} "
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
            error=f"Publisher config invalid: {fmt_exc(e, with_class=True)}",
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
            timeout=_ACME_DNS_UPDATE_TIMEOUT_SECS,
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
                f"{fmt_exc(e, with_class=True)} "
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
            error=f"Publisher config invalid: {fmt_exc(e, with_class=True)}",
        )
    cert_subject = cfg.domains[0]
    probe_value = f"et-acme-probe-{secrets.token_hex(8)}"
    t0 = time.monotonic()
    try:
        fqdn = pub.publish_txt(cert_subject, probe_value, ttl=30)
    except Exception as e:
        return TestStepResult(
            "Publish & verify TXT", False, _elapsed_ms(t0),
            error=f"Publish failed: {fmt_exc(e, with_class=True)}",
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

        : previously generated Ed25519 here and then immediately
        regenerated as RSA-2048 in issue_now (jwk-OKP isn't universally
        accepted by ACME directories). Generating RSA up front skips
        the throwaway, halves first-run latency, and removes a comment-
        flagged TODO from the issuance hot path.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        existing = read_secret(self.secrets, ACME_ACCOUNT_KEY_KEY)
        if existing:
            return existing.encode("utf-8") if isinstance(existing, str) else existing
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.secrets.set(ACME_ACCOUNT_KEY_KEY, pem.decode("utf-8"))
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
            # N-357b (2026-07-06 baseline shrink): assume_utc_if_naive SSOT.
            return assume_utc_if_naive(cert.not_valid_after_utc)
        except Exception as e:
            log.warning("ACME: cert parse failed", error=fmt_exc(e, with_class=True))
            return None

    def cert_metadata(self) -> dict[str, Any]:
        """Read the cert + return ``{ subject_cn, sans, not_before,
        not_after, days_remaining }`` for the admin status page.

        Return-shape contract:

        * cert file absent  → ``{"present": False, "valid": False}``
        * cert file present, parsed OK → ``{"present": True,
          "valid": True, ...the metadata fields...}``
        * cert file present, parse FAILED → ``{"present": True,
          "valid": False, "parse_error": "..."}``

        ``valid`` is the flag callers / templates must branch on
        before reading metadata fields. Previously a parse failure
        returned ``{"present": True, "parse_error": ...}`` — a
        success-shaped dict missing every metadata key, so a caller
        that checked only ``present`` then read ``not_after`` /
        ``sans`` hit a ``KeyError`` or a Jinja ``Undefined``.
        """
        crt, _ = self.cert_paths()
        if not crt.exists():
            return {"present": False, "valid": False}
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
                "valid": True,
                "subject_cn": cn,
                "sans": sans,
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
                "days_remaining": days_remaining,
            }
        except Exception as e:
            # Punch 426: the raw parser text is the privileged side's (the log); the dict is
            # the user-facing side (acme_status.html, /health/detail), so it carries the
            # scrubbed string. ``config`` is a SENSITIVE purpose: it renders the generic
            # "config operation failed", never the exception text.
            from email_triage.web._flash import scrub_exc
            log.warning("ACME: cert metadata parse failed", error=fmt_exc(e, with_class=True))
            return {"present": True, "valid": False,
                    "parse_error": scrub_exc(e, purpose="config")}

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
        # census  — route through the _atomicio SSOT (was a hand-rolled
        # temp+replace+chmod copy). Key first, cert second (the hot-reload
        # order — see the docstring); both land 0o600 via the mode param
        # (preserving this site's original perms).
        from email_triage._atomicio import atomic_write_bytes
        for path, data in ((key, key_pem), (crt, fullchain_pem)):
            atomic_write_bytes(path, data, mode=0o600)

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

        #  -- live re-attach state. Tells anything watching
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
        # HTTP-01 branch skips this pre-flight — CAA records constrain
        # the CA choice regardless of challenge mechanism, but the
        # RFC-2136 resolver plumbing lives inside the DNS-01 branch.
        # The HTTP-01 path uses a simpler public-resolver probe (below).
        _preflights_apply = self.cfg.challenge == "dns-01"
        if _preflights_apply:
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
                    error=fmt_exc(exc, with_class=True),
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

            #  -- CNAME pre-flight. When the operator uses the
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
                        error=fmt_exc(exc, with_class=True),
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
                elif any(
                    p.startswith(CNAME_PREFLIGHT_SKIPPED) for p in cname_problems
                ):
                    # Punch 589: no configured resolver has a DoH JSON
                    # endpoint, so the check did not run. Say so at WARNING.
                    log.warning(
                        "ACME: CNAME pre-flight skipped (no DoH-capable resolver)",
                        notes=cname_problems,
                    )
                elif cname_problems:
                    # hipaa-sme MUST-FIX-1 fold — this elif MUST pair with the
                    # `if not cname_ok:` above, not the enclosing
                    # `if (update_zone):`. The earlier `if _preflights_apply:`
                    # wrap accidentally left this at the outer indent, which
                    # both (a) unbinds `cname_problems` on direct-DNS-01 mode
                    # (no update_zone) and (b) silently lost the inconclusive-
                    # lookups info log on the delegation path.
                    log.info(
                        "ACME: CNAME pre-flight had inconclusive lookups",
                        notes=cname_problems,
                    )

        account_pem = self.ensure_account_key()
        account_key = serialization.load_pem_private_key(
            account_pem, password=None,
        )
        #  -- ed25519 throwaway path removed. ensure_account_key()
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
            self.secrets.set(ACME_ACCOUNT_KEY_KEY, account_pem.decode("utf-8"))

        jose_key = jose.JWKRSA(key=account_key)
        from email_triage._egress import configure_requests_session
        # Directory + ACME client setup.
        net = acme_client.ClientNetwork(
            jose_key, user_agent="email-triage-acme/1.0",
        )
        # Operator rulings 2026-10-21 (A3; was punch 547 / panel B1 trust_env
        # off): the ClientNetwork session takes the egress settings, i.e. the
        # environment unless outbound_tls.ignore_env, the configured proxy / CA
        # bundle over it, and the certificate-check mode.
        configure_requests_session(net.session)
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
        #  -- CN field has a 64-char hard limit per RFC 5280. When
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

        # Challenge dispatch. Config load rejects unsupported challenge
        # types when ACME is enabled (config.py:AcmeConfig validation);
        # defense-in-depth for callers that built the renewer directly.
        _SUPPORTED = ("dns-01", "http-01")
        if self.cfg.challenge not in _SUPPORTED:
            raise NotImplementedError(
                f"Only {list(_SUPPORTED)} ACME challenges are implemented; got "
                f"{self.cfg.challenge!r}. Set tls.acme.challenge to a supported "
                f"value, or disable acme and use operator-managed/external TLS."
            )

        publisher: Rfc2136Publisher | None = None
        _http01_publisher: Any = None
        if self.cfg.challenge == "dns-01":
            tsig_secret = read_secret(
                self.secrets, self.cfg.rfc2136.tsig_secret_ref,
            )
            if not tsig_secret:
                raise RuntimeError(
                    f"Secrets store missing key "
                    f"{self.cfg.rfc2136.tsig_secret_ref!r}"
                )
            publisher = Rfc2136Publisher(self.cfg.rfc2136, tsig_secret)
        else:  # http-01
            from email_triage.web.acme_http01 import Http01Publisher
            _http01_publisher = Http01Publisher(self.cfg.http01)
            try:
                _http01_publisher.start()
            except OSError as _bind_exc:
                # DA-SB1 fold — actionable message for the port-bind
                # failure class. Bare OSError bubbles as e.g.
                # `[Errno 98] Address already in use` which is not
                # actionable and leaves acme_job_state singleton
                # inconsistent.
                _err_msg = (
                    f"HTTP-01 standalone listener failed to bind "
                    f"{self.cfg.http01.bind_host}:{self.cfg.http01.bind_port}: "
                    f"{_bind_exc}. Common causes: (a) port already in "
                    f"use — check `ss -tlnp | grep :{self.cfg.http01.bind_port}` "
                    f"on the host; (b) permission denied — low ports "
                    f"require CAP_NET_BIND_SERVICE or root; consider "
                    f"webroot mode (set tls.acme.http01.mode=webroot + "
                    f"tls.acme.http01.webroot_path) to let the operator's "
                    f"existing proxy serve /.well-known/acme-challenge/ "
                    f"on port 80, OR fall back to tls.acme.challenge=dns-01 "
                    f"if RFC-2136 is configured."
                )
                acme_job_state.finish_failure(
                    _err_msg, kind="http01_bind_failure",
                )
                raise RuntimeError(_err_msg) from _bind_exc

        try:
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
                #  -- cancel check at the top of every retry-loop
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
                #  -- live re-attach phase tracking. transition() updates
                # the singleton so the page can poll /admin/acme-status/job
                # and re-attach mid-issue.
                acme_job_state.transition(
                    "publishing", attempt=attempt, max_attempts=max_attempts,
                )
                order = client.new_order(csr_pem)
                #  -- persist the LE order URL so a process kill
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
                # HTTP-01 cleanup needs the token, not the domain — track a
                # sidecar dict so the cleanup helper can dispatch. DNS-01
                # leaves this empty.
                _published_http01_tokens: dict[str, str] = {}

                def _cleanup_published_domain(_dom: str) -> None:
                    """Dispatch cleanup to the active publisher. Idempotent —
                    a missing entry is not an error (protects against a
                    pre-publish sweep on the very first attempt)."""
                    if self.cfg.challenge == "dns-01":
                        try:
                            publisher.delete_txt(_dom)
                        except Exception:
                            pass
                    else:  # http-01
                        _tok = _published_http01_tokens.pop(_dom, None)
                        if _tok:
                            try:
                                _http01_publisher.delete_token(_tok)
                            except Exception:
                                pass

                try:
                    for authz in order.authorizations:
                        domain = authz.body.identifier.value
                        # Pick the challenge matching our configured type.
                        challenge = None
                        for c in authz.body.challenges:
                            if c.typ == self.cfg.challenge:
                                challenge = c
                                break
                        if challenge is None:
                            raise RuntimeError(
                                f"Directory did not offer "
                                f"{self.cfg.challenge!r} for {domain}"
                            )
                        response, validation = challenge.response_and_validation(jose_key)
                        if self.cfg.challenge == "dns-01":
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
                                    error=fmt_exc(exc, with_class=True),
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
                        else:  # http-01
                            # HTTP-01 flow: publish the token → key_auth
                            # pair (in-mem for standalone, file for webroot),
                            # then self-check by fetching our own URL.
                            # The `validation` here is the HTTP-01
                            # keyAuthorization string; the token is on the
                            # challenge object at `.chall.token`.
                            chall_obj = getattr(challenge, "chall", challenge)
                            token = getattr(chall_obj, "token", None)
                            if not token:
                                raise RuntimeError(
                                    f"HTTP-01 challenge for {domain} has no "
                                    f"token attribute — python-acme API drift?"
                                )
                            # Stray-token pre-sweep for retry resilience
                            # (mirrors DNS-01 delete_txt sweep).
                            try:
                                _http01_publisher.delete_token(token)
                            except Exception as e:
                                log.warning(
                                    "ACME: stray HTTP-01 token pre-sweep failed; publishing anyway",
                                    domain=domain,
                                    error=fmt_exc(e),
                                )
                            _http01_publisher.publish_token(token, validation)
                            _published_http01_tokens[domain] = token
                            published_for.append(domain)
                            log.info(
                                "ACME: published HTTP-01 challenge token",
                                domain=domain,
                                mode=self.cfg.http01.mode,
                                attempt=attempt,
                                attempt_id=attempt_id,
                            )
                            acme_job_state.transition("polling_local")
                            if not _http01_publisher.poll_local(
                                token, validation,
                            ):
                                raise RuntimeError(
                                    f"HTTP-01 token not retrievable via the "
                                    f"local self-check within "
                                    f"{self.cfg.http01.self_check_timeout_secs}s. "
                                    f"Mode={self.cfg.http01.mode!r}. "
                                    f"Standalone: verify the listener bound "
                                    f"({self.cfg.http01.bind_host}:"
                                    f"{self.cfg.http01.bind_port}). "
                                    f"Webroot: verify the proxy serves "
                                    f"/.well-known/acme-challenge/ from "
                                    f"{self.cfg.http01.webroot_path!r}."
                                )
                            acme_job_state.visibility(domain, local=True)
                        # Grace pause: even after our local check sees the
                        # challenge, LE's own path may still be holding a
                        # stale negative cache entry. Sleep before signaling
                        # LE so that cache has time to expire. This applies
                        # to both dns-01 and http-01 branches — LE fronts
                        # every validation via its recursive resolvers.
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
                    # offset-aware datetimes" inside its poll loop. So we
                    # need a NAIVE-UTC now: take the aware UTC time and drop
                    # the tzinfo (the non-deprecated path; datetime.utcnow()
                    # is deprecated in 3.12+).
                    deadline = (
                        datetime.now(timezone.utc).replace(tzinfo=None)
                        + timedelta(seconds=120)
                    )
                    final_order = client.poll_and_finalize(
                        order, deadline=deadline,
                    )
                    fullchain_pem = final_order.fullchain_pem.encode("utf-8")
                    # Success — break out of retry loop.
                    break
                except ValidationError as e:
                    last_error = e
                    #  -- classify before deciding to retry. CAA / badCSR
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
                    # B4 diagnostics probe queries DNS resolvers directly — only
                    # meaningful for dns-01. HTTP-01 has no DNS component to probe;
                    # the outer log line still fires (without per-resolver map).
                    if self.cfg.challenge == "dns-01":
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
                                    "_probe_error": fmt_exc(probe_exc, with_class=True),
                                }
                    log.warning(
                        "ACME: validation failed (LE-side DNS lookup)",
                        attempt=attempt, max_attempts=max_attempts,
                        attempt_id=attempt_id,
                        error=fmt_exc(e, with_class=True),
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
                            _cleanup_published_domain(d)
                        err_msg = (
                            f"ACME validation aborted after {attempt} attempts "
                            f"(kind={err_kind}, typ={err_typ or 'unknown'}). "
                            f"Last error: {fmt_exc(e, with_class=True)}"
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
                        _cleanup_published_domain(d)

                # Only reached on retry path (success path 'break'-ed above).
                if attempt < max_attempts:
                    #  -- backoff curve. Exponential / fibonacci default;
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
                        last_error=fmt_exc(last_error, with_class=True) if last_error else None,
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
                    f"{fmt_exc(last_error, with_class=True) if last_error else 'unknown'}"
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
            # PR 10 / E + run17 #9 — metric. Routes through the ONE funnel so the
            # ``renewed`` edge shares the directory/outcome label vocabulary with
            # the failed / skipped_fresh / deferred edges (which were previously
            # uncounted). ``directory`` is the one THIS issuance actually used (the
            # manual Issue-Now path may override cfg).
            self._record_renewal_metric("renewed", directory=directory)
            log.info("ACME: cert issued + written",
                     domain=domains[0], not_after=meta.get("not_after"),
                     attempt_id=attempt_id)
            #  -- terminal-success state for the live re-attach.
            acme_job_state.finish_success(meta)
            return meta
        finally:
            if _http01_publisher is not None:
                try:
                    _http01_publisher.stop()
                except Exception as e:
                    log.warning(
                        "ACME: HTTP-01 publisher stop failed",
                        error=fmt_exc(e),
                    )

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

         -- the live re-attach state singleton (acme_job_state) is
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
                    fmt_exc(exc, with_class=True),
                    kind=type(exc).__name__,
                )
            raise

    def _record_renewal_metric(
        self, outcome: str, *, directory: str | None = None,
    ) -> None:
        """Best-effort: bump ``et_acme_renewals_total{directory, outcome}``.

        run17 #9 (devils-advocate observability gap): the counter was emitted
        ONLY on the ``renewed`` edge, while the renewal LOG
        (``insert_acme_renewal_log``) already recorded all four bounded
        outcomes — so ``/metrics`` showed renewals but was BLIND to ``failed``
        / ``skipped_fresh`` / ``deferred``. Every edge now routes through THIS
        one funnel (PD#5) so the label vocabulary can't drift across sites.

        ``directory`` overrides the configured directory (the manual Issue-Now
        path passes the directory it actually used); default is the configured
        ``directory_url``. Swallowed — a metrics fault must never break a
        renewal tick.
        """
        try:
            from email_triage import metrics as metrics_mod
            d = directory if directory is not None else (
                self.cfg.directory_url or ""
            )
            metrics_mod.counter(
                "et_acme_renewals_total",
                "ACME issuance outcomes by directory and result.",
            ).inc(
                directory="staging" if "staging" in d else "prod",
                outcome=outcome,
            )
        except Exception:
            pass

    #: N-550 (539 fold, round 5): the SCHEDULED renewal's audit event type.
    RENEWAL_EVENT_TYPE = "acme_cert_renewed"

    def _renewal_witness_detail(self, *, outcome: str, error: str = "") -> str:
        """The system-actor row's detail: the NEW certificate's serial and SHA-256
        fingerprint (read back from the file just written) and the acme job id."""
        try:
            from email_triage.web import acme_job_state

            job_id = (acme_job_state.current_state() or {}).get("job_id") or ""
        except Exception as e:  # noqa: BLE001 — a witness never raises
            job_id = f"unreadable:{type(e).__name__}"
        parts = [f"outcome={outcome}", f"job_id={job_id}"]
        if outcome == "success":
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes

                crt, _key = self.cert_paths()
                cert = x509.load_pem_x509_certificate(Path(crt).read_bytes())
                parts.append(f"serial={cert.serial_number:x}")
                parts.append(f"sha256={cert.fingerprint(hashes.SHA256()).hex()}")
            except Exception as e:  # noqa: BLE001 — the row still lands, marked
                parts.append(f"cert_identity_unreadable={type(e).__name__}")
        if error:
            parts.append(f"error={error}")
        return " ".join(parts)

    def _witness_scheduled_renewal(self, *, outcome: str, error: str = "") -> None:
        """Sync-path witness: one ``auth_events`` row, system actor (no user).

        FAIL-SOFT BY DESIGN — the one sanctioned fail-soft witness in the 539
        fold (N-550). Every admin route that changes TLS material REFUSES when its
        intent row cannot be written; this automated rotation does NOT, because
        refusing would turn an audit miss into certificate expiry, an outage of
        the ePHI service (§164.308(a)(7)); there is no human actor whose
        accountability the row exists for; and Let's Encrypt issuance is
        independently recorded in Certificate Transparency logs. A miss is still
        logged and counted for /health by ``safe_audit_write`` (the SSOT's
        counter), never dropped silently. ``acme_jobs`` alone is not the record:
        it is mutable, unchained and carries no certificate identity.
        """
        from email_triage.web._audit import safe_audit_write
        from email_triage.web.db import record_auth_event

        detail = self._renewal_witness_detail(outcome=outcome, error=error)
        safe_audit_write(
            lambda: record_auth_event(
                self.db, event_type=self.RENEWAL_EVENT_TYPE, email="",
                user_id=None, outcome=outcome, detail=detail,
            ),
            description=f"{self.RENEWAL_EVENT_TYPE}:{outcome}",
        )

    async def _witness_scheduled_renewal_async(self, *, outcome: str, error: str = "") -> None:
        """Async-path twin of :meth:`_witness_scheduled_renewal` (same FAIL-SOFT
        policy, same row), through the async SSOT so the write runs on the DB
        writer via ``db_call`` and never raises into the renewal loop."""
        from email_triage.web._audit import safe_audit_write_async
        from email_triage.web.db import record_auth_event
        from email_triage.web.db_threadpool import db_call

        detail = self._renewal_witness_detail(outcome=outcome, error=error)
        await safe_audit_write_async(
            lambda: db_call(
                record_auth_event, self.db, event_type=self.RENEWAL_EVENT_TYPE,
                email="", user_id=None, outcome=outcome, detail=detail,
            ),
            description=f"{self.RENEWAL_EVENT_TYPE}:{outcome}",
        )

    async def check_and_renew_async(self) -> dict[str, Any]:
        """Async background-task entrypoint with single-flight on
        the actual issuance call."""
        from email_triage.single_flight import SingleFlightBusy
        #  — check_and_renew_async is an async background task;
        # route the acme-renewal-log writes (which insert + commit on
        # the shared connection) off the event-loop thread.
        from email_triage.web.db_threadpool import db_call
        if not self.cfg.enabled:
            return {"skipped": "acme.enabled=false"}
        if not self.cfg.domains:
            return {"skipped": "acme.domains empty"}
        if not self.needs_renewal():
            await db_call(
                insert_acme_renewal_log,
                self.db, domain=self.cfg.domains[0],
                outcome="skipped_fresh",
                not_after=self.cert_metadata().get("not_after"),
            )
            self._record_renewal_metric("skipped_fresh")
            return {"action": "skipped", "reason": "fresh"}
        try:
            meta = await self.issue_now_async()
        except SingleFlightBusy:
            log.info(
                "ACME: renewal tick saw issue in progress; deferring",
                domain=self.cfg.domains[0],
            )
            self._record_renewal_metric("deferred")
            return {"action": "deferred", "reason": "issue_in_progress"}
        except Exception as e:
            await db_call(
                insert_acme_renewal_log,
                self.db, domain=self.cfg.domains[0],
                outcome="failed",
                error=fmt_exc(e, with_class=True),
            )
            self._record_renewal_metric("failed")
            await self._witness_scheduled_renewal_async(
                outcome="failure", error=type(e).__name__,
            )
            log.error(
                "ACME renewal failed; existing cert unchanged",
                exc_info=e,
                domain=self.cfg.domains[0],
            )
            raise
        else:
            # N-550: the system-actor witness, AFTER the write, fail-soft; in
            # ``else`` so it can never turn a completed renewal into a "failed" one.
            await self._witness_scheduled_renewal_async(outcome="success")
            return {"action": "renewed", **meta}

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
            self._record_renewal_metric("skipped_fresh")
            return {"action": "skipped", "reason": "fresh"}
        try:
            meta = self.issue_now()
        except Exception as e:
            insert_acme_renewal_log(
                self.db, domain=self.cfg.domains[0],
                outcome="failed",
                error=fmt_exc(e, with_class=True),
            )
            self._record_renewal_metric("failed")
            self._witness_scheduled_renewal(outcome="failure", error=type(e).__name__)
            log.error(
                "ACME renewal failed; existing cert unchanged",
                exc_info=e,
                domain=self.cfg.domains[0],
            )
            raise
        else:
            # N-550: the system-actor witness, AFTER the write, fail-soft.
            self._witness_scheduled_renewal(outcome="success")
            return {"action": "renewed", **meta}


async def renewal_loop(renewer: AcmeRenewer, *, stop_event: asyncio.Event) -> None:
    """Long-running background task: tick every
    ``check_interval_hours``, call ``check_and_renew_async``.

    Routes through the single-flight-guarded async path so a
    concurrent manual "Issue Now" click can't race the tick.

    .. deprecated::
        Superseded by :func:`acme_cert_renewer`, which ports this onto
        ``supervised_interval_loop`` (lease-gated, supervisor-tracked).
        Kept only for the back-compat import surface; the supervised
        block in ``web/app.py`` registers ``acme_cert_renewer``.
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


# ---------------------------------------------------------------------------
# Supervised cert-renewer
# ---------------------------------------------------------------------------
#
# ``renewal_loop`` above had ZERO callers — an ACME cert was issued once
# (manually, via the admin "Issue Now" button) and then silently expired
# ~90 days later because nothing ticked ``check_and_renew``. This block
# ports the renewer onto the supervised-task machinery the rest of the
# background loops use: ``supervised_interval_loop`` for the cadence +
# crash isolation, lease-gating so exactly one instance renews per tick,
# and a resume worker that consumes the ``resume_pending`` ACME job rows
# that ``acme_job_state.resume_on_startup()`` stamps but nothing read.

# Initial start delay — stagger past the o365/gmail renewers' first
# sweeps so a cold boot doesn't fan three renewers out in the same
# second. ACME cadence is hours, so the exact warm-up is cosmetic.
_ACME_RENEWER_WARMUP_SECONDS = 120


def _build_renewer_from_app(app) -> "AcmeRenewer":
    """Construct an :class:`AcmeRenewer` from app state.

    Same wiring the admin routes use (``auth_keys._resolve_renewer``):
    ``config.tls.acme`` + the cert dir + the secrets store + the app
    DB connection. Cert-dir resolution funnels through the shared
    ``tls_csr._resolve_cert_dir`` so the supervised task, the admin
    page, and the manual CSR workflow all agree on the path.
    """
    from email_triage.web.routers.tls_csr import _resolve_cert_dir
    config = app.state.config
    cert_dir = str(_resolve_cert_dir(config))
    return AcmeRenewer(
        cfg=config.tls.acme,
        cert_dir=cert_dir,
        secrets_store=app.state.secrets,
        db=app.state.db,
    )


async def acme_cert_renewer(app) -> None:
    """Supervised ACME cert-renewal loop.

    Ticks every ``config.tls.acme.check_interval_hours`` (default 24h).
    Each tick: resume any in-flight ACME job left ``resume_pending`` by
    a prior process kill, then call ``check_and_renew_async`` which
    no-ops unless the on-disk cert is within ``renewal_threshold_days``
    of expiry.

    No-op when ACME automation is disabled (``acme.enabled=false``) —
    the loop still runs but every tick returns the skip verdict, so an
    operator who flips ``enabled`` on later doesn't need a restart.

    Lease-gated: an ACME order against Let's Encrypt is NOT
    idempotent — every order burns one of the 5-certs/week/domain rate
    slots. The single-flight decorator on ``issue_now_async`` already
    blocks an in-process double-order, but the lease additionally keeps
    a future multi-instance deployment from N instances each ordering.
    """
    from email_triage.web.task_supervisor import supervised_interval_loop

    async def _tick() -> None:
        # N-227c R22 — heartbeat stamp for /admin observability.
        app.state.acme_cert_renewer_status = {"at": now_utc_iso()}
        renewer = _build_renewer_from_app(app)
        # Resume-worker step first: clear any restart-orphaned job so a
        # fresh check_and_renew below isn't blocked behind a stuck
        # 'retrying' row on the recent-jobs surface.
        try:
            await _resume_pending_acme_jobs(app, renewer)
        except Exception as e:
            log.warning(
                "ACME: resume-pending sweep raised (non-fatal)",
                error=fmt_exc(e, with_class=True),
            )
        try:
            await renewer.check_and_renew_async()
        except Exception as e:
            # check_and_renew_async already logged + wrote an
            # acme_renewal_log row; swallow so the loop survives.
            log.error("ACME: renewal tick raised", error=fmt_exc(e, with_class=True))

    interval_secs = max(1, app.state.config.tls.acme.check_interval_hours) * 3600
    await supervised_interval_loop(
        "acme-cert-renewer", float(interval_secs), _tick,
        warmup_secs=_ACME_RENEWER_WARMUP_SECONDS,
        startup_jitter_secs=30.0,
        lease_name="acme-cert-renewer",
        lease_conn=app.state.db,
    )


async def _resume_pending_acme_jobs(app, renewer: "AcmeRenewer") -> int:
    """Consume the ``resume_pending`` ACME job rows.

    ``acme_job_state.resume_on_startup()`` (run once in the app
    lifespan) stamps every non-terminal ``acme_jobs`` row killed
    mid-issuance with a verdict: ``cancelled`` / ``cancelled_no_order``
    / ``cancelled_stale`` are terminal already, but ``resume_pending``
    rows (a live, recent LE order interrupted by the kill) sit in the
    ``retrying`` phase with NOTHING consuming them — until this worker.

    Resume policy: an interrupted order can't be re-driven from the
    Python ``acme`` client without the original in-memory order object
    and challenge responses, which the kill destroyed. Re-finalizing
    blind is not safe. The correct, rate-limit-respectful action is to
    mark the row terminal (``failed`` / kind ``resume_abandoned``) and
    let the very next ``check_and_renew_async`` in this same tick place
    a fresh order — that path is single-flight-guarded and idempotent
    against the on-disk cert state. The interrupted order simply ages
    out on LE's side (a placed-but-unfinalized order is not a cert and
    doesn't consume the issuance rate slot).

    Returns the number of rows resolved.
    """
    from email_triage.web import acme_job_state
    try:
        resumable = acme_job_state.find_resumable()
    except Exception as e:
        log.warning(
            "ACME: find_resumable raised in resume worker",
            error=fmt_exc(e, with_class=True),
        )
        return 0
    resolved = 0
    for row in resumable:
        if row.get("last_error_kind") != "resume_pending":
            # Non-resume_pending non-terminal rows are either freshly
            # in-flight in THIS process (the live job) or were already
            # handled by resume_on_startup. Leave them alone.
            continue
        job_id = row.get("job_id")
        if not job_id:
            continue
        try:
            # ``finish_failure`` mutates the in-RAM ``_STATE`` singleton
            # and write-throughs to whatever job ``_STATE`` currently
            # points at. After a fresh restart ``_STATE`` is idle, so
            # adopt the persisted row first — that binds ``_STATE`` to
            # this job id and the write-through lands on the right row.
            # #239d — adopt_persisted refuses while a *different* job is
            # live (an operator "Issue Now" overlapping this tick); that
            # refusal is benign here, the next tick retries this row.
            if not acme_job_state.adopt_persisted(job_id):
                log.warning(
                    "ACME: resume worker could not adopt job row "
                    "(another issuance live, or row vanished); "
                    "deferring to next tick",
                    job_id=job_id,
                )
                continue
            acme_job_state.finish_failure(
                "ACME issuance interrupted by a process restart; the "
                "partial Let's Encrypt order is abandoned. The next "
                "renewal tick places a fresh order if the cert still "
                "needs one.",
                kind="resume_abandoned",
            )
        except Exception as e:
            log.warning(
                "ACME: resume worker could not close job row",
                job_id=job_id, error=fmt_exc(e, with_class=True),
            )
            continue
        resolved += 1
        log.info(
            "ACME: abandoned a restart-orphaned issuance job; the "
            "renewal tick will reorder if needed",
            job_id=job_id,
            domains=row.get("domains"),
        )
    return resolved


def read_tls_cert_health(app) -> dict[str, Any]:
    """Compute the ``tls_cert`` block for ``/health/detail``.

    Pure on-disk read — no network, no ACME-directory call. Uses the
    existing cert readers (``read_cert_expiry`` / ``cert_metadata``)
    so the health surface and the renewer agree on the cert state.

    Shape::

        {"present": bool,
         "not_after": iso-or-None,
         "days_remaining": int-or-None}

    ``present`` is False when no cert is on disk yet (fresh install,
    ACME not run). Never raises — a parse failure degrades to
    ``{"present": False, "error": "..."}`` so an unreadable cert can't
    take ``/health/detail`` down.
    """
    try:
        renewer = _build_renewer_from_app(app)
        meta = renewer.cert_metadata()
        if not meta.get("present"):
            return {
                "present": False,
                "not_after": None,
                "days_remaining": None,
            }
        if meta.get("parse_error"):
            return {
                "present": True,
                "not_after": None,
                "days_remaining": None,
                "error": meta["parse_error"],
            }
        return {
            "present": True,
            "not_after": meta.get("not_after"),
            "days_remaining": meta.get("days_remaining"),
        }
    except Exception as e:
        # Punch 426: this dict is the /health/detail ``tls_cert`` block, a user-facing
        # surface; the raw text goes to the log, the block carries the scrubbed string.
        from email_triage.web._flash import scrub_exc
        log.warning("ACME: tls_cert health read failed", error=fmt_exc(e, with_class=True))
        return {
            "present": False,
            "not_after": None,
            "days_remaining": None,
            "error": scrub_exc(e, purpose="config"),
        }
