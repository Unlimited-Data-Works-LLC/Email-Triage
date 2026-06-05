"""Tests for H-04-flag — boot-time Transmission Security enforcement.

Closes EQM-03 GAP g3 (operator-deployment-discipline assumption) per
the H-04-flag finding in ``internal documentation`` §4.1.

Covers the five dispatch scenarios:
  1. **Attestation** — HIPAA-mode + flag-set + attestation="nginx"
     → boot OK + audit-log entry captures the declared posture
  2. **Strict-fail-public** — HIPAA-mode + flag-set + bind=0.0.0.0 +
     tls.enabled=False + attestation="none" → boot RuntimeError
  3. **Strict-OK-loopback** — HIPAA-mode + flag-set + bind=127.0.0.1
     → boot OK regardless of TLS state
  4. **Non-HIPAA-no-enforcement** — non-HIPAA + flag-set → no-op
     (the flag is HIPAA-scope by design)
  5. **HIPAA-with-tls** — HIPAA-mode + tls.enabled=True → boot OK
     regardless of bind/attestation (app-layer TLS satisfies (e)(2)(ii)
     directly; the EM substitution is moot)

Plus defensive helpers + classifier table.
"""

from __future__ import annotations

import logging

import pytest

import email_triage.triage_logging as _triage_logging
from email_triage.config import LoggingConfig, TLSConfig, TriageConfig
from email_triage.web.transmission_security import (
    _is_public_internet_routable,
    enforce_transmission_security_for_hipaa,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def hipaa_on():
    """Set process-global HIPAA mode ON for the test.

    The autouse fixture ``_restore_hipaa_mode_around_each_test`` in
    ``tests/conftest.py`` snapshots + restores ``_hipaa_mode`` per test,
    so direct assignment here is safe (no leak into the next test).
    """
    _triage_logging._hipaa_mode = True
    yield
    # Restore handled by conftest autouse.


@pytest.fixture
def hipaa_off():
    """Set process-global HIPAA mode OFF for the test."""
    _triage_logging._hipaa_mode = False
    yield


def _cfg(
    *,
    require_https_app_layer: bool = False,
    perimeter_tls_attestation: str = "none",
    tls_enabled: bool = False,
) -> TriageConfig:
    """Build a minimal TriageConfig with the H-04-flag knobs set."""
    cfg = TriageConfig()
    cfg.logging = LoggingConfig(
        hipaa=True,  # The helper checks is_hipaa_mode() not cfg.logging.hipaa
        require_https_app_layer=require_https_app_layer,
        perimeter_tls_attestation=perimeter_tls_attestation,
    )
    cfg.tls = TLSConfig(enabled=tls_enabled)
    return cfg


# ---------------------------------------------------------------------------
# Scenario 1 — Attestation
# ---------------------------------------------------------------------------

class TestAttestation:
    def test_hipaa_mode_attestation_logged(self, hipaa_on, caplog):
        """HIPAA-mode default behavior: always emit one audit-trail
        entry capturing the declared attestation posture. The flag
        being OFF here means the strict-axis enforcement is moot;
        attestation still fires for §164.316 evidence.
        """
        cfg = _cfg(
            require_https_app_layer=False,
            perimeter_tls_attestation="nginx",
        )
        with caplog.at_level(
            logging.INFO,
            logger="email_triage.web.transmission_security",
        ):
            enforce_transmission_security_for_hipaa(
                cfg, bind_host="0.0.0.0",
            )
        # Audit entry present with the declared posture.
        records = [
            r for r in caplog.records
            if r.name == "email_triage.web.transmission_security"
        ]
        assert len(records) == 1
        # The TriageLogger adapter packs kwargs into ``record._extra``.
        extra = getattr(records[0], "_extra", {}) or {}
        assert extra.get("perimeter_tls_attestation") == "nginx"
        assert extra.get("perimeter_tls_attestation_known_shape") is True

    def test_hipaa_mode_with_flag_and_attestation_allows_boot(
        self, hipaa_on,
    ):
        """HIPAA-mode + flag-set + attestation="nginx" + public bind +
        tls.enabled=False — operator declared a perimeter TLS posture
        so the strict axis is suppressed; boot proceeds.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="nginx",
            tls_enabled=False,
        )
        # No RuntimeError = pass.
        enforce_transmission_security_for_hipaa(cfg, bind_host="0.0.0.0")

    def test_custom_attestation_string_passes_through(self, hipaa_on, caplog):
        """Operator may supply a custom attestation string (not in the
        canonical catalog); audit-log entry captures it raw + flags
        it as a non-known shape.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="custom-zerotrust-mesh",
        )
        with caplog.at_level(
            logging.INFO,
            logger="email_triage.web.transmission_security",
        ):
            enforce_transmission_security_for_hipaa(
                cfg, bind_host="0.0.0.0",
            )
        records = [
            r for r in caplog.records
            if r.name == "email_triage.web.transmission_security"
        ]
        assert len(records) == 1
        extra = getattr(records[0], "_extra", {}) or {}
        assert extra.get("perimeter_tls_attestation") == "custom-zerotrust-mesh"
        assert extra.get("perimeter_tls_attestation_known_shape") is False


# ---------------------------------------------------------------------------
# Scenario 2 — Strict fail-closed on public bind
# ---------------------------------------------------------------------------

class TestStrictFailClosed:
    def test_strict_fails_on_public_bind(self, hipaa_on):
        """HIPAA + flag + bind=0.0.0.0 + tls.enabled=False +
        attestation="none" → RuntimeError per H-04-flag verdict.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        with pytest.raises(RuntimeError, match="H-04-flag"):
            enforce_transmission_security_for_hipaa(
                cfg, bind_host="0.0.0.0",
            )

    def test_strict_fails_on_empty_bind_host(self, hipaa_on):
        """Empty bind_host is fail-closed (uvicorn defaults to public)."""
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        with pytest.raises(RuntimeError, match="H-04-flag"):
            enforce_transmission_security_for_hipaa(cfg, bind_host="")

    def test_strict_fails_on_ipv6_all_interfaces(self, hipaa_on):
        """``::`` (IPv6 all-interfaces) is fail-closed."""
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        with pytest.raises(RuntimeError, match="H-04-flag"):
            enforce_transmission_security_for_hipaa(cfg, bind_host="::")

    def test_strict_error_message_names_remediations(self, hipaa_on):
        """The RuntimeError message must name all three remediation
        options so operators can self-remediate without consulting docs.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        with pytest.raises(RuntimeError) as exc_info:
            enforce_transmission_security_for_hipaa(
                cfg, bind_host="0.0.0.0",
            )
        msg = str(exc_info.value)
        assert "tls.enabled=True" in msg
        assert "loopback" in msg
        assert "perimeter_tls_attestation" in msg
        # §-anchor named in the error (operator-discoverability + DA
        # hedge-check on regulatory framing).
        assert "164.312(e)" in msg


# ---------------------------------------------------------------------------
# Scenario 3 — Loopback bind always OK
# ---------------------------------------------------------------------------

class TestLoopbackAllowed:
    @pytest.mark.parametrize("bind_host", [
        "127.0.0.1",
        "::1",
    ])
    def test_loopback_always_ok(self, hipaa_on, bind_host):
        """HIPAA + flag + loopback bind → boot OK regardless of TLS
        state (RFC1918 / loopback covered by EQM-03 shape (a)/(b)/(c)).
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        # No exception.
        enforce_transmission_security_for_hipaa(cfg, bind_host=bind_host)

    @pytest.mark.parametrize("bind_host", [
        "10.0.0.5",
        "172.16.42.1",
        "192.168.1.100",
        "fc00::1",  # RFC4193 ULA
        "169.254.1.1",  # link-local
    ])
    def test_rfc1918_and_link_local_ok(self, hipaa_on, bind_host):
        """Private-network binds (RFC1918, RFC4193, link-local) are
        operator-controlled-network postures per EQM-03 shape (b)/(c).
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        enforce_transmission_security_for_hipaa(cfg, bind_host=bind_host)


# ---------------------------------------------------------------------------
# Scenario 4 — Non-HIPAA is no-op
# ---------------------------------------------------------------------------

class TestNonHipaaNoEnforcement:
    def test_non_hipaa_flag_set_no_op(self, hipaa_off):
        """Non-HIPAA + flag-set + public bind + tls.enabled=False
        → no-op (flag is HIPAA-scope by design; non-HIPAA dev/CI
        installs are not in the threat model).
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=False,
        )
        enforce_transmission_security_for_hipaa(cfg, bind_host="0.0.0.0")

    def test_non_hipaa_no_attestation_log(self, hipaa_off, caplog):
        """Non-HIPAA mode does not emit the attestation audit-log
        entry — the §164.316 trail is HIPAA-mode-scope.
        """
        cfg = _cfg(
            require_https_app_layer=False,
            perimeter_tls_attestation="nginx",
        )
        with caplog.at_level(
            logging.INFO,
            logger="email_triage.web.transmission_security",
        ):
            enforce_transmission_security_for_hipaa(
                cfg, bind_host="0.0.0.0",
            )
        records = [
            r for r in caplog.records
            if r.name == "email_triage.web.transmission_security"
        ]
        assert len(records) == 0


# ---------------------------------------------------------------------------
# Scenario 5 — HIPAA + tls.enabled=True boots regardless
# ---------------------------------------------------------------------------

class TestTlsEnabledSatisfies:
    def test_tls_enabled_allows_public_bind(self, hipaa_on):
        """HIPAA + flag-set + public bind + tls.enabled=True →
        boot OK. App-layer TLS satisfies §164.312(e)(2)(ii) directly;
        the EQM-03 substitution is moot.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=True,
        )
        enforce_transmission_security_for_hipaa(cfg, bind_host="0.0.0.0")

    def test_tls_enabled_allows_empty_bind_host(self, hipaa_on):
        """Even with empty bind_host (fail-closed shape elsewhere),
        tls.enabled=True boots OK.
        """
        cfg = _cfg(
            require_https_app_layer=True,
            perimeter_tls_attestation="none",
            tls_enabled=True,
        )
        enforce_transmission_security_for_hipaa(cfg, bind_host="")


# ---------------------------------------------------------------------------
# Public-routable classifier — defensive coverage
# ---------------------------------------------------------------------------

class TestPublicRoutableClassifier:
    @pytest.mark.parametrize("host,expected", [
        # Fail-closed defaults
        ("", True),
        ("0.0.0.0", True),
        ("::", True),
        # Loopback
        ("127.0.0.1", False),
        ("127.42.0.1", False),
        ("::1", False),
        # RFC1918 IPv4
        ("10.0.0.1", False),
        ("172.16.1.1", False),
        ("172.31.255.254", False),
        ("192.168.0.1", False),
        # RFC4193 ULA IPv6
        ("fc00::1", False),
        ("fd00::abcd", False),
        # Link-local
        ("169.254.1.1", False),
        ("fe80::1", False),
        # CGNAT 100.64/10 — Python's ip_address does NOT mark it
        # private; treat as public-routable (fail-closed bias).
        # Operators on legit CGNAT-only deployments can declare a
        # perimeter attestation to opt out.
        ("100.64.0.1", True),
        # Hostnames
        ("localhost", False),
        ("localhost.localdomain", False),
        ("example.com", True),  # DNS name → fail-closed
        ("triage.internal", True),  # unknown DNS name → fail-closed
        # Public-routable IP literals
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("2001:4860:4860::8888", True),
    ])
    def test_classifier_table(self, host, expected):
        assert _is_public_internet_routable(host) is expected
