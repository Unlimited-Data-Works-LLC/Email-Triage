"""N-321 R30 unit tests — task  tranche  XFF-consuming SSOT.

DA panel on tranche  flagged §164.312(b) LIVE audit-identity
defect: behind the deploy host's podman NAT every audit row records
`127.0.0.1`. Fix is a separate SSOT (`request_forwarded_for`) that
consumes X-Forwarded-For ONLY when the direct-connect peer is a
KNOWN, TRUSTED reverse proxy per `config.audit.trusted_proxies`.

Operator-approved delivery model 2026-07-03: empty-list default
(preserves current behavior on every install; each operator
populates for their own deploy topology). Docs point at the deploy host's
podman bridge CIDR as an example.
"""
from __future__ import annotations


class _FakeRequest:
    """Minimal stub sufficient for `request_forwarded_for` — matches
    the `request.client.host` / `request.headers.get(...)` /
    `request.scope.get('client')` interface."""

    def __init__(self, peer_host: str, xff: str = ""):
        self.client = type("_C", (), {"host": peer_host})()
        self.headers = {"user-agent": "pytest", "x-forwarded-for": xff}
        self.scope = {"client": (peer_host, 0)}


def _rff(peer, xff, trusted):
    from email_triage.web.dependencies import request_forwarded_for
    return request_forwarded_for(_FakeRequest(peer, xff), trusted)


def test_empty_trusted_list_ignores_xff():
    """Ship-default: empty list = ignore XFF entirely, return raw
    peer identical to `request_meta`."""
    meta = _rff("127.0.0.1", "8.8.8.8", trusted=[])
    assert meta.host == "127.0.0.1"


def test_direct_peer_untrusted_ignores_xff():
    """A peer NOT in trusted CIDRs is a public client — its XFF is
    spoofable (§164.312(b) audit-identity: never trust unverified
    input)."""
    meta = _rff("8.8.8.8", "1.2.3.4", trusted=["127.0.0.1/32"])
    assert meta.host == "8.8.8.8"


def test_trusted_peer_consumes_rightmost_xff():
    """When the direct peer is in a trusted CIDR, walk XFF rightmost-
    first and return the first entry NOT in a trusted CIDR (= true
    client, not an earlier hop)."""
    meta = _rff(
        "127.0.0.1",
        "8.8.8.8, 10.0.0.1, 127.0.0.1",
        trusted=["127.0.0.1/32", "10.0.0.0/8"],
    )
    # 127.0.0.1 (rightmost) trusted, 10.0.0.1 trusted, 8.8.8.8 not.
    assert meta.host == "8.8.8.8"


def test_trusted_peer_with_single_xff_entry():
    meta = _rff("127.0.0.1", "1.2.3.4", trusted=["127.0.0.1/32"])
    assert meta.host == "1.2.3.4"


def test_trusted_peer_empty_xff_returns_peer():
    """A trusted peer with NO XFF header falls back to the direct
    peer (proxy talking to itself, no upstream client)."""
    meta = _rff("127.0.0.1", "", trusted=["127.0.0.1/32"])
    assert meta.host == "127.0.0.1"


def test_all_xff_entries_trusted_returns_leftmost():
    """If EVERY XFF entry is in a trusted CIDR, return the leftmost
    (originator claim per the standard XFF walk)."""
    meta = _rff(
        "127.0.0.1",
        "10.0.0.5, 127.0.0.1",
        trusted=["10.0.0.0/8", "127.0.0.1/32"],
    )
    assert meta.host == "10.0.0.5"


def test_malformed_cidr_in_config_fails_closed():
    """A broken CIDR in config = treat as no-match (raw peer used),
    NOT crash. Fail-CLOSED on config error."""
    meta = _rff("127.0.0.1", "1.2.3.4", trusted=["not-a-cidr"])
    assert meta.host == "127.0.0.1"


def test_malformed_xff_entry_skipped():
    """A non-IP entry inside XFF is skipped — walk continues."""
    meta = _rff(
        "127.0.0.1",
        "8.8.8.8, not-an-ip, 127.0.0.1",
        trusted=["127.0.0.1/32"],
    )
    assert meta.host == "8.8.8.8"


def test_all_malformed_xff_falls_back_to_peer_host():
    """N-337 R30 (trust-repair PHASE2 tranche  DA fix) + TASK 
    residual verify: when EVERY XFF entry is either trusted OR malformed,
    the pre-N-337 code returned `entries[0]` even when entries[0] was a
    non-IP shape — a client-controllable header writing a raw non-IP
    string into audit-actor rows. The fix falls back to `peer_host` on
    that shape. Locks the invariant explicitly (existing tests cover the
    per-entry malformed skip; this case exercises the specific edge
    where the FIRST entry doesn't parse as IP after every rightmost
    entry either was trusted or didn't parse).

    Setup: two entries, first is a non-IP string, second is trusted
    (127.0.0.1). Rightmost walk: 127.0.0.1 is trusted → continue.
    `not-an-ip` doesn't parse → skip. Exit loop with every rightward
    entry non-returnable. Fallback to entries[0] check — non-IP → return
    peer_host (fail-CLOSED against non-IP actor)."""
    meta = _rff(
        "127.0.0.1",
        "not-an-ip, 127.0.0.1",
        trusted=["127.0.0.1/32"],
    )
    assert meta.host == "127.0.0.1", (
        "N-337 fail-CLOSED: with entries[0] non-IP + all rightward "
        "entries trusted-or-malformed, must return peer_host — never "
        "write a raw non-IP string as §164.312(b) audit actor."
    )


def test_all_malformed_and_untrusted_xff_falls_back_to_peer_host():
    """N-337 edge: single non-IP entry, direct peer trusted. Rightmost
    walk exits without finding a non-trusted IP. entries[0] non-IP →
    fallback to peer_host."""
    meta = _rff(
        "127.0.0.1",
        "some-hostname-not-ip",
        trusted=["127.0.0.1/32"],
    )
    assert meta.host == "127.0.0.1", (
        "N-337 fail-CLOSED: single non-IP XFF entry must not be written "
        "as audit actor."
    )


def test_ipv6_loopback_trusted():
    meta = _rff("::1", "2001:db8::1", trusted=["::1/128"])
    assert meta.host == "2001:db8::1"


def test_config_audit_config_exists_with_empty_default():
    """The config dataclass must ship with empty-list default so no
    existing install regresses."""
    from email_triage.config import AuditConfig, TriageConfig
    c = TriageConfig()
    assert isinstance(c.audit, AuditConfig)
    assert c.audit.trusted_proxies == []
