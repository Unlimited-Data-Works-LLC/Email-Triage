"""SSOT for "is this URL a local (non-internet) destination?" — the
destination-locality predicate behind two egress gates.

It backs:
  * the webhook external-target gate (``web/events.is_local_webhook_url`` — A4),
  * the PHI→LLM Business-Associate-Agreement gate (``classify/base._is_local_host``),
    a §164.502(e) egress control: an external LLM endpoint must not receive PHI
    unless a BAA is in place, and a "local" endpoint is the carve-out.

Before 2026-06-09 these were byte-identical duplicates using **string-prefix**
RFC1918 matching (``host.startswith("10.")`` / ``"192.168."`` / a hand-rolled
``172.16``–``172.31`` octet check). That **fails OPEN**: ``urlparse(
"http://10.evil.com").hostname`` is ``"10.evil.com"``, which ``startswith("10.")``
→ classified **local** → PHI could egress to an *external* host the gate believed
was internal. This SSOT hardens the private-IP test to ``ipaddress``-based
classification — a hostname is NOT an IP literal, so it can no longer masquerade
as a private address — and is the single place the logic lives.

NOTE the distinct sibling ``web/transmission_security._is_public_internet_routable``
is intentionally NOT merged here: it answers a different question (is a *bind*
host public-internet-routable, for the boot strict-axis), with the opposite
polarity and a different input shape.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlparse, urlunparse


# The SPECIFIC "trusted private LAN / on-host" ranges — the same intent as the
# old string-prefix check (loopback + RFC1918), made ipaddress-based, plus IPv6
# ULA. DELIBERATELY EXCLUDES link-local 169.254.0.0/16 + fe80::/10 (the cloud-
# metadata IP 169.254.169.254 is a SSRF target — it must stay EXTERNAL so the
# webhook/SSRF/BAA gates fail-closed on it), CGNAT 100.64/10, and 0.0.0.0/8.
# Do NOT replace this with `ipaddress.is_private` — that set INCLUDES link-local,
# which would re-open the SSRF the probe gate guards (test_ai_backends_probe_ssrf).
_LOCAL_NETS = tuple(
    ipaddress.ip_network(c) for c in (
        "127.0.0.0/8",     # IPv4 loopback
        "10.0.0.0/8",      # RFC1918
        "172.16.0.0/12",   # RFC1918
        "192.168.0.0/16",  # RFC1918
        "::1/128",         # IPv6 loopback
        "fc00::/7",        # IPv6 unique-local (ULA)
    )
)


def is_private_or_local_ip(host: str) -> bool:
    """True iff ``host`` is an IP **literal** in the trusted private LAN / on-host
    set (loopback, RFC1918, IPv6 ULA) — see ``_LOCAL_NETS``.

    A non-IP hostname returns False — it is NOT an IP and must never be treated
    as private by a string prefix (the ``10.evil.com`` fail-open this SSOT closes).
    Link-local (incl. the ``169.254.169.254`` cloud-metadata SSRF target), CGNAT,
    and global addresses return False → treated external → fail-closed for the
    webhook / SSRF / PHI-egress gates.
    """
    try:
        ip = ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return any(ip in net for net in _LOCAL_NETS)


# IP ranges that must NEVER be an egress target for an operator-owned / pass-through
# URL (PUBLIC_FETCH / LLM / webhook), even though they are not "local". Polarity-
# opposite companion to ``_LOCAL_NETS``: that set is what we ALLOW as on-LAN; this
# is what we REFUSE outright. Explicit nets ON PURPOSE — NOT ``ipaddress.is_link_local``
# (that attribute is banned outside the bind-axis by test_netloc_locality_ssot_pin,
# because the sibling ``.is_private`` admits link-local and re-opens the metadata SSRF).
_SSRF_BLOCKED_NETS = tuple(
    ipaddress.ip_network(c) for c in (
        "169.254.0.0/16",  # IPv4 link-local — the cloud-metadata target 169.254.169.254
        "fe80::/10",       # IPv6 link-local
        "0.0.0.0/8",       # "this host" / unspecified
        "::/128",          # IPv6 unspecified
        "224.0.0.0/4",     # IPv4 multicast
        "ff00::/8",        # IPv6 multicast
        "240.0.0.0/4",     # IPv4 reserved / future-use
    )
)


def is_ssrf_blocked_ip(host: str) -> bool:
    """True iff ``host`` is an IP **literal** in a range that must never be an
    egress target for an operator-owned / pass-through URL — the cloud-metadata
    link-local block (``169.254.169.254`` & the IPv6 equivalent) plus unspecified /
    multicast / reserved. The polarity-opposite companion to
    :func:`is_private_or_local_ip`: it does NOT block loopback / RFC1918
    (legitimate LAN targets), only the SSRF-dangerous ranges. A non-IP hostname
    returns False (the caller's per-URL gate handles names; this is the IP-literal
    SSRF backstop). IPv4-mapped IPv6 (``::ffff:169.254.169.254``) is normalised so
    a blocked v4 literal can't be smuggled past in v6 form.
    """
    try:
        ip = ipaddress.ip_address(host.strip())
    except (ValueError, AttributeError):
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in _SSRF_BLOCKED_NETS)


def is_local_destination(url: str, *, extra_suffixes: Iterable[str] = ()) -> bool:
    """True iff ``url`` points to a local-only (non-internet) destination.

    Local signals (no config needed): ``localhost`` / ``127.0.0.1`` / ``::1``;
    any IP literal in ``_LOCAL_NETS`` (loopback / RFC1918 / IPv6 ULA — NOT
    link-local); the ``.local`` mDNS suffix. Operator-extensible via
    ``extra_suffixes`` (e.g. an internal homelab domain, sourced from
    ``config.tls.local_url_suffixes``). Everything else is **external**.

    THREAT-MODEL CAVEAT: the ``.local`` mDNS suffix and ``extra_suffixes`` are
    *trusted-resolver* assumptions — a hostname matching them is treated local
    without resolving it, so a split-horizon / mDNS-spoofed name (``metadata.local``)
    could point at an external/metadata IP. That is acceptable for the BAA + webhook
    gates (on-LAN trust), but a stricter SSRF-sensitive caller (the admin AI-backend
    probe) should prefer IP-literal-only locality — use :func:`pin_local_endpoint`,
    which RESOLVES the host, requires every record to be local, and pins the connect
    to the validated IP. IP literals themselves are
    *not* resolver-trusting — link-local/metadata/CGNAT always classify external
    regardless of suffix config.
    """
    if not url:
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith(".local"):
        return True
    for suffix in (extra_suffixes or ()):
        s = (suffix or "").lower().strip()
        if s and host.endswith(s):
            return True
    return is_private_or_local_ip(host)


def _format_host_for_url(ip: str) -> str:
    """Bracket an IPv6 literal for use in a URL netloc; pass IPv4 through."""
    return f"[{ip}]" if ":" in ip else ip


def pin_local_endpoint(url: str) -> str | None:
    """Strict, **resolver-grounded** locality gate for SSRF-sensitive callers
    (the  admin model probe — see the THREAT-MODEL CAVEAT in
    :func:`is_local_destination`, which named this as the follow-up: ).

    Unlike :func:`is_local_destination`, this does NOT trust ``.local`` or
    operator ``extra_suffixes`` by *string*. It:

      1. resolves the URL's host to EVERY A/AAAA record
         (``socket.getaddrinfo``);
      2. requires **all** of them to be loopback / RFC1918 / IPv6-ULA
         (``_LOCAL_NETS`` — link-local 169.254.169.254 cloud-metadata, CGNAT,
         and global addresses are NOT local → **fail closed**);
      3. returns the URL **rewritten to connect to the validated IP literal**,
         so a DNS rebind between this check and the actual socket connect
         (TOCTOU) cannot redirect the request to a different address.

    Returns ``None`` when the host does not resolve, resolves to ANY non-local
    address, or the URL is malformed — the caller must reject on ``None``.

    Pinning substitutes the IP into the netloc for every scheme. For a local
    ``https`` endpoint with a strict hostname-bound certificate this can cause
    TLS verification to fail (the cert names the hostname, not the IP) — that
    is a deliberately fail-safe outcome for a probe whose canonical target is a
    plain-HTTP local Ollama; the operator can enter the model name manually.
    """
    if not url:
        return None
    try:
        parts = urlparse(url)
        host = (parts.hostname or "")
    except Exception:
        return None
    if not host:
        return None

    # An IP literal needs no resolution — classify it directly.
    try:
        ipaddress.ip_address(host.strip())
        ips: list[str] = [host.strip()]
    except ValueError:
        # A hostname → resolve every address it maps to.
        try:
            infos = socket.getaddrinfo(host, parts.port, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError, UnicodeError):
            return None
        ips = []
        for info in infos:
            ip = info[4][0]
            # Drop any IPv6 scope id (``fe80::1%eth0``) before classifying;
            # link-local is rejected anyway, this just keeps parsing clean.
            ip = ip.split("%", 1)[0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            return None

    # FAIL CLOSED: every resolved address must be in the trusted-local set.
    if not all(is_private_or_local_ip(ip) for ip in ips):
        return None

    pinned_ip = ips[0]
    netloc = _format_host_for_url(pinned_ip)
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo = f"{userinfo}:{parts.password}"
        netloc = f"{userinfo}@{netloc}"
    return urlunparse(
        (parts.scheme, netloc, parts.path or "", parts.params,
         parts.query, parts.fragment)
    )
