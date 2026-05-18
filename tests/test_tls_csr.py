"""Tests for the manual CSR / sign / import workflow (#74)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from email_triage import tls_csr


def _sign_with_test_ca(csr_pem: bytes, *, valid_days: int = 365) -> bytes:
    """Sign a CSR using a synthetic test CA. Mirrors what an
    institutional CA would return: leaf cert built from the CSR's
    public key + subject. Returns leaf-only PEM (no intermediates;
    a real CA's response would also include intermediates -- handled
    by the import path which accepts them as a chain)."""
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        # Carry over the SAN extension so the cert matches the
        # CSR-declared hostnames.
        .add_extension(
            csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            ).value,
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# State detection
# ---------------------------------------------------------------------------

class TestDetectState:
    def test_idle_state_when_dir_empty(self, tmp_path):
        assert tls_csr.detect_state(tmp_path) == tls_csr.STATE_IDLE

    def test_pending_state_when_pending_files_exist(self, tmp_path):
        (tmp_path / tls_csr.PENDING_KEY_FILENAME).write_bytes(b"x")
        (tmp_path / tls_csr.PENDING_CSR_FILENAME).write_bytes(b"x")
        assert tls_csr.detect_state(tmp_path) == tls_csr.STATE_PENDING

    def test_active_state_when_active_files_exist(self, tmp_path):
        (tmp_path / tls_csr.CERT_FILENAME).write_bytes(b"x")
        (tmp_path / tls_csr.KEY_FILENAME).write_bytes(b"x")
        assert tls_csr.detect_state(tmp_path) == tls_csr.STATE_ACTIVE

    def test_pending_takes_precedence_over_active(self, tmp_path):
        """During a rotation the operator may have an old active cert
        AND a fresh pending CSR. The UI should focus on the rotation
        in progress."""
        (tmp_path / tls_csr.CERT_FILENAME).write_bytes(b"x")
        (tmp_path / tls_csr.KEY_FILENAME).write_bytes(b"x")
        (tmp_path / tls_csr.PENDING_KEY_FILENAME).write_bytes(b"x")
        (tmp_path / tls_csr.PENDING_CSR_FILENAME).write_bytes(b"x")
        assert tls_csr.detect_state(tmp_path) == tls_csr.STATE_PENDING


# ---------------------------------------------------------------------------
# Make CSR
# ---------------------------------------------------------------------------

class TestMakeCsr:
    def test_generates_keypair_and_csr(self, tmp_path):
        key_path, csr_path, csr_pem = tls_csr.make_csr(
            tmp_path, hostname="triage.example.com",
        )
        assert key_path.is_file()
        assert csr_path.is_file()
        assert csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
        # Round-trip the CSR -- must parse + carry the requested CN.
        csr = x509.load_pem_x509_csr(csr_pem)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "triage.example.com"

    def test_extra_sans_present_in_csr(self, tmp_path):
        _, _, csr_pem = tls_csr.make_csr(
            tmp_path,
            hostname="primary.example.com",
            extra_sans=["alt.example.com", "10.0.0.5"],
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        sans = list(san_ext.value)
        dns_names = [n.value for n in sans if isinstance(n, x509.DNSName)]
        ip_addrs = [str(n.value) for n in sans if isinstance(n, x509.IPAddress)]
        assert "primary.example.com" in dns_names
        assert "alt.example.com" in dns_names
        assert "10.0.0.5" in ip_addrs

    def test_refuses_to_overwrite_pending_by_default(self, tmp_path):
        tls_csr.make_csr(tmp_path, hostname="a.example.com")
        with pytest.raises(tls_csr.CsrAlreadyPendingError):
            tls_csr.make_csr(tmp_path, hostname="b.example.com")

    def test_overwrite_pending_when_explicit(self, tmp_path):
        tls_csr.make_csr(tmp_path, hostname="a.example.com")
        # Force a new CSR over the old one. Test that the new key + CSR
        # overwrite the old, validated by checking the CN changed.
        _, _, new_csr_pem = tls_csr.make_csr(
            tmp_path, hostname="b.example.com", overwrite_pending=True,
        )
        csr = x509.load_pem_x509_csr(new_csr_pem)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "b.example.com"

    def test_empty_hostname_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            tls_csr.make_csr(tmp_path, hostname="")


# ---------------------------------------------------------------------------
# Cancel / re-download pending
# ---------------------------------------------------------------------------

class TestCancelAndRedownload:
    def test_cancel_clears_files(self, tmp_path):
        tls_csr.make_csr(tmp_path, hostname="x.example.com")
        assert (tmp_path / tls_csr.PENDING_KEY_FILENAME).is_file()
        tls_csr.cancel_pending(tmp_path)
        assert not (tmp_path / tls_csr.PENDING_KEY_FILENAME).is_file()
        assert not (tmp_path / tls_csr.PENDING_CSR_FILENAME).is_file()

    def test_cancel_idempotent(self, tmp_path):
        # Cancel with nothing pending should not raise.
        tls_csr.cancel_pending(tmp_path)
        tls_csr.cancel_pending(tmp_path)

    def test_read_pending_csr_returns_bytes(self, tmp_path):
        _, _, original = tls_csr.make_csr(tmp_path, hostname="x.example.com")
        re_read = tls_csr.read_pending_csr(tmp_path)
        assert re_read == original

    def test_read_pending_csr_raises_when_missing(self, tmp_path):
        with pytest.raises(tls_csr.NoPendingCsrError):
            tls_csr.read_pending_csr(tmp_path)


# ---------------------------------------------------------------------------
# Import signed cert
# ---------------------------------------------------------------------------

class TestImportSignedCert:
    def test_round_trip_make_then_import(self, tmp_path):
        """Operator flow: make CSR -> 'send to CA' (synthetic test CA
        signs it) -> import. After import, server.crt + server.key
        exist; pending files are gone."""
        _, _, csr_pem = tls_csr.make_csr(
            tmp_path, hostname="triage.example.com",
        )
        signed_cert_pem = _sign_with_test_ca(csr_pem)
        crt_path, key_path = tls_csr.import_signed_cert(
            tmp_path, signed_cert_pem,
        )
        assert crt_path.is_file()
        assert key_path.is_file()
        # Pending files were cleaned up.
        assert not (tmp_path / tls_csr.PENDING_KEY_FILENAME).is_file()
        assert not (tmp_path / tls_csr.PENDING_CSR_FILENAME).is_file()
        # Active cert matches what we wrote.
        assert crt_path.read_bytes() == signed_cert_pem

    def test_no_pending_key_raises(self, tmp_path):
        # Try to import without a pending CSR.
        garbage = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"MIIB\n-----END CERTIFICATE-----\n"
        )
        with pytest.raises(tls_csr.NoPendingCsrError):
            tls_csr.import_signed_cert(tmp_path, garbage)

    def test_invalid_pem_raises(self, tmp_path):
        tls_csr.make_csr(tmp_path, hostname="x.example.com")
        with pytest.raises(tls_csr.InvalidPemError):
            tls_csr.import_signed_cert(tmp_path, b"not a real PEM")

    def test_key_mismatch_raises(self, tmp_path):
        """Make a CSR. Sign a DIFFERENT keypair's CSR. Try to import
        that. The mismatch detector rejects."""
        # First operator's pending key+CSR.
        tls_csr.make_csr(tmp_path, hostname="legit.example.com")
        # Generate a SECOND independent CSR + signed cert for a
        # different keypair. Operator tries to paste THIS into
        # the import form for the legit pending CSR. Detector
        # rejects.
        other_dir = tmp_path / "elsewhere"
        other_dir.mkdir()
        _, _, other_csr_pem = tls_csr.make_csr(
            other_dir, hostname="legit.example.com",
        )
        other_signed = _sign_with_test_ca(other_csr_pem)
        with pytest.raises(tls_csr.KeyMismatchError):
            tls_csr.import_signed_cert(tmp_path, other_signed)
        # Pending files NOT cleaned up on rejection -- operator can
        # paste the right cert next try.
        assert (tmp_path / tls_csr.PENDING_KEY_FILENAME).is_file()
        assert (tmp_path / tls_csr.PENDING_CSR_FILENAME).is_file()

    def test_chain_with_intermediates_accepted(self, tmp_path):
        """Real CAs return leaf + intermediates concatenated. Import
        should accept the whole chain and write it verbatim to
        server.crt so curl / browser builds the path."""
        _, _, csr_pem = tls_csr.make_csr(
            tmp_path, hostname="x.example.com",
        )
        leaf = _sign_with_test_ca(csr_pem)
        # Synthesize a fake "intermediate" by signing another cert
        # (semantically nonsense; structurally a valid chain).
        fake_intermediate = _sign_with_test_ca(csr_pem)
        chain_pem = leaf + b"\n" + fake_intermediate
        crt_path, _ = tls_csr.import_signed_cert(tmp_path, chain_pem)
        # The on-disk cert preserves both -- chain length 2.
        md = tls_csr.cert_metadata(crt_path.read_bytes())
        assert md["chain_length"] == 2


# ---------------------------------------------------------------------------
# Self-sign shortcut
# ---------------------------------------------------------------------------

class TestSelfSign:
    def test_writes_active_cert_and_key(self, tmp_path):
        crt, key = tls_csr.self_sign_now(
            tmp_path, hostname="bringup.example.com",
        )
        assert crt.is_file()
        assert key.is_file()
        # State now reads as active.
        assert tls_csr.detect_state(tmp_path) == tls_csr.STATE_ACTIVE


# ---------------------------------------------------------------------------
# Cert metadata + expiry
# ---------------------------------------------------------------------------

class TestCertMetadata:
    def test_metadata_extraction(self, tmp_path):
        _, _, csr_pem = tls_csr.make_csr(
            tmp_path,
            hostname="meta.example.com",
            extra_sans=["alt.example.com"],
        )
        cert_pem = _sign_with_test_ca(csr_pem, valid_days=365)
        md = tls_csr.cert_metadata(cert_pem)
        assert md["subject_cn"] == "meta.example.com"
        assert md["issuer_cn"] == "Test CA"
        # SANs include both hostnames.
        san_dns = [s for s in md["sans"] if s.startswith("DNS:")]
        assert "DNS:meta.example.com" in san_dns
        assert "DNS:alt.example.com" in san_dns
        # ~365d remaining (allow slop for test runtime).
        assert 360 <= md["days_until_expiry"] <= 365

    def test_active_cert_metadata_returns_none_when_missing(self, tmp_path):
        assert tls_csr.active_cert_metadata(tmp_path) is None


class TestExpiryWarning:
    def _install_self_signed(self, tmp_path, valid_days):
        """Install a self-signed cert with a chosen validity window."""
        from email_triage.tls import generate_self_signed_cert, write_cert_files
        cert_pem, key_pem = generate_self_signed_cert(
            hostname="x.example.com",
            valid_days=valid_days,
        )
        write_cert_files(tmp_path, cert_pem, key_pem)

    def test_no_warning_when_far_from_expiry(self, tmp_path):
        self._install_self_signed(tmp_path, valid_days=365)
        assert tls_csr.cert_expiry_warning(tmp_path) is None

    def test_30d_band(self, tmp_path):
        self._install_self_signed(tmp_path, valid_days=25)
        warn = tls_csr.cert_expiry_warning(tmp_path)
        assert warn is not None
        assert "expires in" in warn.lower()

    def test_7d_band_uses_urgent_language(self, tmp_path):
        self._install_self_signed(tmp_path, valid_days=5)
        warn = tls_csr.cert_expiry_warning(tmp_path)
        assert warn is not None
        # 7-day band uses "Renew via" prompt.
        assert "Renew" in warn or "renew" in warn

    def test_warning_when_no_active_cert(self, tmp_path):
        # No cert at all -- no warning to emit.
        assert tls_csr.cert_expiry_warning(tmp_path) is None
