"""H-04-flag boot-time Transmission Security enforcement (Cycle 7).

Closes EQM-03 GAP g3 (operator-deployment-discipline assumption) per
the H-04-flag finding in ``internal documentation`` §4.1. Per
hipaa-sme-2 regulatory calibration: NOT REQUIRED per literal
§164.312(e)(2)(ii) Addressable doctrine (the EM EQM-03 is regulatorily
complete via deployment contract — mechanism-EXISTS test satisfied),
but OCR-posture-aligned + operator-policy ASAP per
``project_hipaa_asap_policy.md``.

Disposition shape: **Shape A "regulatorily-defensible-but-defense-in-
depth-tier"** per project_hipaa_asap_policy.md §"Disposition shapes
catalog". Does NOT introduce a new EQM-NN substitution; EQM-03
remains the §164.306(d)(3)(ii)(B) Transmission Security EM.

The enforcement is two-axis:

  1. **Attestation axis** (HIPAA-mode default, always-on when
     HIPAA is on): captures the operator-declared perimeter-TLS posture
     in ``config.logging.perimeter_tls_attestation`` as a §164.316(b)(2)
     audit-trail entry. Recognized shapes match the EQM-03 catalog
     (TLSConfig docstring at config.py:303-318): "none" | "nginx" |
     "caddy" | "haproxy" | "traefik" | "wireguard" | "tailscale" |
     "headscale" | "nebula" | "container-ingress". Unknown values
     pass through (operator-extensibility) but the audit-log entry
     captures the raw string so downstream review can flag novel
     postures.

  2. **Strict axis** (HIPAA-mode + ``require_https_app_layer=True``):
     boot-time ``RuntimeError`` when the listener is bound to a
     public-internet-routable address AND ``tls.enabled=False`` AND
     ``perimeter_tls_attestation="none"``. Fail-closed at boot per the
     H-02a G1' precedent (``secrets.enforce_master_key_at_rest_for_hipaa``).

Non-HIPAA mode is a complete no-op regardless of flag values.

§-anchors:
  - §164.312(e)(1) Transmission Security (Standard, Required)
  - §164.312(e)(2)(ii) Encryption (Implementation Spec, Addressable)
  - §164.308(a)(8) Evaluation (Standard, Required) — the
    attestation-axis review provides §164.308(a)(8)-class evidence
    that the technical safeguard is periodically evaluated
  - §164.306(d)(3)(ii)(B) — the equivalent-measure framework EQM-03
    uses; H-04-flag is the defense-in-depth enforcement companion

The mechanism deliberately mirrors the H-02a G1' fail-closed shape
(``secrets.enforce_master_key_at_rest_for_hipaa``) for consistency
+ operator-discoverability: same RuntimeError-with-named-§-anchor +
named-remediation pattern.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from email_triage.triage_logging import get_logger, is_hipaa_mode

log = get_logger("web.transmission_security")


# Known perimeter-TLS posture shapes. Matches the EQM-03 catalog at
# ``config.py`` ``TLSConfig`` docstring (lines ~303-318). Extension by
# the operator works — unknown values pass through; this set just
# distinguishes "operator declared a known shape" from "operator
# declared a custom shape" in the audit-log entry.
_KNOWN_ATTESTATION_SHAPES: frozenset[str] = frozenset({
    "none",
    "nginx",
    "caddy",
    "haproxy",
    "traefik",
    "wireguard",
    "tailscale",
    "headscale",
    "nebula",
    "container-ingress",
})


def _is_public_internet_routable(host: str) -> bool:
    """Classify a bind-host string as public-internet-routable.

    Returns True if a listener bound to ``host`` would accept
    connections from a public-internet client. Used by the strict
    axis to decide whether to fail-closed at boot.

    Classification rules (fail-closed bias):

      - ``""``                   → True. Empty bind host is uvicorn's
        "let the OS pick" — defaults to ``0.0.0.0``; treat as
        public-routable for safety. Operator's CLI default is the
        explicit ``"0.0.0.0"`` shape, but defense-in-depth against
        operators bypassing the CLI.
      - ``"0.0.0.0"`` / ``"::"`` → True. All-interfaces bind. Even on
        a host with no public IP TODAY, the same listener gains
        public reachability if the host is later assigned one
        (cloud VM elastic IP, homelab DMZ reconfiguration). Safer to
        fail-closed.
      - Loopback (``127.0.0.0/8``, ``::1/128``) → False. Strictly
        local; no off-host listener.
      - RFC1918 private IPv4 (``10/8``, ``172.16/12``, ``192.168/16``),
        RFC4193 ULA IPv6 (``fc00::/7``), link-local (``169.254/16``,
        ``fe80::/10``) → False. Operator-controlled-network bind;
        EQM-03's shape (b) / shape (c) cover this.
      - Special-use ranges (CGNAT ``100.64/10``, benchmarking
        ``198.18/15``, TEST-NET) → True (fail-closed). These aren't
        RFC1918 / RFC4193 operator-controlled networks; an operator
        legitimately deploying behind CGNAT can declare the
        attestation explicitly to opt out of strict enforcement.
      - Any other globally-routable IP literal → True.
      - Non-IP hostnames (e.g., ``"localhost"`` literal string in
        operator-supplied YAML, or a DNS name) → DNS-name-aware
        classification: ``"localhost"`` / ``"localhost.localdomain"``
        → False; anything else → True (fail-closed; we can't resolve
        DNS at this enforcement point safely without introducing a
        boot-time network dependency).

    The classification is intentionally narrow + conservative. The
    strict axis fires ONLY when all four conditions hold (HIPAA +
    flag + public-routable + tls.enabled=False + attestation="none");
    any one of the gates being False suppresses the RuntimeError.
    """
    if not host or host == "0.0.0.0" or host == "::":
        return True
    # Try literal IP classification first.
    try:
        ip = ipaddress.ip_address(host.strip())
    except ValueError:
        # Not an IP literal — treat as a hostname.
        h = host.strip().lower()
        if h in ("localhost", "localhost.localdomain"):
            return False
        # Any other hostname: fail-closed. We cannot resolve DNS at
        # boot-enforcement time without introducing a network
        # dependency that fights the goal of the enforcement.
        return True
    if ip.is_loopback:
        return False
    if ip.is_private:
        # Covers RFC1918 IPv4 + RFC4193 IPv6 (Python's ip_address
        # marks these private). Note: RFC6598 carrier-grade NAT
        # (100.64/10) is NOT marked private by Python — it's a
        # "shared address space" that operationally can carry
        # public-internet-bound NAT'd traffic but isn't
        # operator-controlled in the EQM-03 sense. Fall through to
        # the global-unicast bucket below = treat as public-routable
        # for fail-closed bias (operator on CGNAT can declare a
        # perimeter attestation if they actually want this posture).
        return False
    if ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_unspecified:
        # is_unspecified is "0.0.0.0" / "::" — already caught above
        # by the explicit-string check, but defensive.
        return False
    # Anything else (global unicast OR special-use ranges like
    # 100.64/10 CGNAT, 198.18/15 benchmarking) → fail-closed.
    return True


def enforce_transmission_security_for_hipaa(
    cfg: Any,
    bind_host: str,
) -> None:
    """H-04-flag boot-time enforcement of Transmission Security.

    Per H-04-flag verdict (Cycle 7 hipaa-sme-2 + DA cross-route):
    when HIPAA mode is enabled, capture an attestation audit-log
    entry for the declared perimeter-TLS posture (always-on under
    HIPAA mode), AND fail-closed at boot if the operator's
    ``require_https_app_layer`` flag is set BUT the runtime posture
    indicates ePHI would traverse the listener in cleartext on a
    public-internet-routable interface.

    Outside HIPAA mode this helper is a no-op — H-04-flag's threat
    model is HIPAA-scoped per medical-scope drawer §2 principle 1
    (matching H-02a G1' precedent).

    Args:
        cfg: a ``TriageConfig``-shaped object exposing ``.logging``
            (``require_https_app_layer``, ``perimeter_tls_attestation``)
            and ``.tls`` (``enabled``).
        bind_host: the actual host string the listener will bind to —
            sourced from ``email-triage serve --host`` (cli.py) and
            plumbed to the lifespan via ``app.state.bind_host``. Empty
            string is treated as public-routable for fail-closed bias
            (uvicorn's "let the OS pick" defaults to all-interfaces).

    Raises:
        RuntimeError: if HIPAA + flag-set + public-routable +
            ``tls.enabled=False`` + ``perimeter_tls_attestation="none"``.

    Side effects:
        Emits one structured ``log.info`` entry under HIPAA mode
        capturing the attestation posture + the enforcement-axis
        result + the bind-host classification. This is the
        §164.316(b)(2) audit-trail evidence; the SQLiteLogHandler
        chains it into the H-02a HMAC log_entries chain via the
        normal hot-path emit.
    """
    if not is_hipaa_mode():
        return
    # Note: is_hipaa_mode() is the process-global, set by
    # setup_logging() during boot per cfg.logging.hipaa. In
    # production the lifespan call site (web/app.py) runs AFTER
    # setup_logging() so the process-global and cfg.logging.hipaa
    # are consistent. Tests set _hipaa_mode directly via the
    # hipaa_on/hipaa_off fixtures (process-global short-circuit;
    # cfg.logging.hipaa is also set for completeness but the
    # helper reads only the process-global). Boot-order coupling
    # is load-bearing — if a future refactor moves
    # enforce_transmission_security_for_hipaa BEFORE setup_logging
    # the helper will silently no-op on a HIPAA install. Per
    # DA verify-don't-accept R-Surface-3 review 2026-05-24.

    logging_cfg = getattr(cfg, "logging", None)
    tls_cfg = getattr(cfg, "tls", None)
    attestation = str(
        getattr(logging_cfg, "perimeter_tls_attestation", "none") or "none"
    )
    require_flag = bool(
        getattr(logging_cfg, "require_https_app_layer", False)
    )
    tls_enabled = bool(getattr(tls_cfg, "enabled", False))
    public_routable = _is_public_internet_routable(bind_host)
    known_shape = attestation in _KNOWN_ATTESTATION_SHAPES

    # Attestation-axis: always-on under HIPAA mode. Emit one
    # structured audit-trail entry so §164.316(b)(2)(i)/(b)(2)(iii)
    # has the declared posture on the HMAC-chained log_entries
    # record. The chain participates by virtue of the SQLiteLogHandler
    # hot-path — no special emit-path needed here.
    log.info(
        "H-04-flag: HIPAA-mode Transmission Security attestation",
        perimeter_tls_attestation=attestation,
        perimeter_tls_attestation_known_shape=known_shape,
        require_https_app_layer=require_flag,
        tls_enabled=tls_enabled,
        bind_host=bind_host or "(unspecified-defaults-to-public)",
        bind_host_public_routable=public_routable,
    )

    # Strict-axis: fail-closed at boot when all four conditions hold.
    # Any one being False suppresses the enforcement (per design:
    # `tls.enabled=True` satisfies (e)(2)(ii) directly;
    # loopback/RFC1918 bind matches EQM-03 shape (a)/(b)/(c) deployment
    # contract; non-"none" attestation = operator declared a perimeter
    # posture that EQM-03 documents as the EM substitution).
    if not require_flag:
        return
    if tls_enabled:
        return
    if not public_routable:
        return
    if attestation != "none":
        return

    raise RuntimeError(
        "H-04-flag (§164.312(e)(1) Transmission Security Standard + "
        "§164.312(e)(2)(ii) Encryption Addressable + §164.308(a)(8) "
        "Evaluation): HIPAA mode is enabled and "
        "logging.require_https_app_layer=True, but the listener is "
        f"bound to a public-internet-routable address (bind_host="
        f"{bind_host!r}) AND tls.enabled=False AND "
        "logging.perimeter_tls_attestation='none' — ePHI would "
        "traverse the listener in cleartext on a non-operator-"
        "controlled network segment. This defeats EQM-03 (the "
        "§164.306(d)(3)(ii)(B) Transmission Security equivalent "
        "measure documented at config.py TLSConfig docstring), which "
        "assumes an operator-controlled deployment perimeter. "
        "Remediate by ONE of: (1) set tls.enabled=True + configure "
        "an app-layer TLS posture (see TLSConfig docstring §1-4); "
        "(2) bind to loopback / RFC1918 / a known perimeter network "
        "(e.g., --host 127.0.0.1 with an upstream nginx/Caddy/Tailscale "
        "TLS terminator); (3) set logging.perimeter_tls_attestation "
        "to one of 'nginx' | 'caddy' | 'haproxy' | 'traefik' | "
        "'wireguard' | 'tailscale' | 'headscale' | 'nebula' | "
        "'container-ingress' (or a custom string naming the operator's "
        "perimeter TLS shape) to declare an existing EQM-03 deployment "
        "posture. Per hipaa-sme-2 + DA Cycle 7 H-04-flag verdict "
        "2026-05-24."
    )
