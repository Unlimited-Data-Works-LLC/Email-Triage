"""Tests for self-signed TLS cert generation + cert-dir lookup (#48)."""

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from email_triage.tls import (
    fetch_tailscale_cert,
    generate_self_signed_cert,
    load_existing_cert_paths,
    write_cert_files,
)


class TestSelfSigned:
    def test_generate_returns_pem_bytes(self):
        cert_pem, key_pem = generate_self_signed_cert("example.test")
        assert b"-----BEGIN CERTIFICATE-----" in cert_pem
        assert b"-----BEGIN PRIVATE KEY-----" in key_pem

    def test_cert_has_hostname_san(self):
        cert_pem, _ = generate_self_signed_cert("deployhost.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        names = [d.value for d in san if isinstance(d, x509.DNSName)]
        assert "deployhost.example.com" in names
        assert "localhost" in names

    def test_cert_has_loopback_ip_sans(self):
        cert_pem, _ = generate_self_signed_cert("h.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        ips = [str(ip.value) for ip in san if isinstance(ip, x509.IPAddress)]
        assert "127.0.0.1" in ips
        assert "::1" in ips

    def test_extra_sans_added(self):
        cert_pem, _ = generate_self_signed_cert(
            "h.test", extra_sans=["other.test", "10.0.0.5"],
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        names = [d.value for d in san if isinstance(d, x509.DNSName)]
        ips = [str(ip.value) for ip in san if isinstance(ip, x509.IPAddress)]
        assert "other.test" in names
        assert "10.0.0.5" in ips

    def test_validity_days(self):
        from datetime import datetime, timezone
        cert_pem, _ = generate_self_signed_cert("h.test", valid_days=30)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        # ~30 days plus the 5-min skew slack.
        assert 29 <= delta.days <= 31


class TestWriteAndLoad:
    def test_write_cert_files_creates_both(self, tmp_path: Path):
        cert_pem, key_pem = generate_self_signed_cert("h.test")
        crt, key = write_cert_files(tmp_path / "certs", cert_pem, key_pem)
        assert crt.exists()
        assert key.exists()
        assert crt.read_bytes() == cert_pem
        assert key.read_bytes() == key_pem

    def test_load_existing_returns_pair_when_present(self, tmp_path: Path):
        cert_pem, key_pem = generate_self_signed_cert("h.test")
        write_cert_files(tmp_path / "certs", cert_pem, key_pem)
        crt, key = load_existing_cert_paths(tmp_path / "certs")
        assert crt is not None
        assert key is not None

    def test_load_existing_returns_none_when_absent(self, tmp_path: Path):
        crt, key = load_existing_cert_paths(tmp_path / "no-such-dir")
        assert crt is None
        assert key is None

    def test_load_existing_returns_none_when_partial(self, tmp_path: Path):
        d = tmp_path / "certs"
        d.mkdir()
        (d / "server.crt").write_text("only cert")
        # No key file.
        crt, key = load_existing_cert_paths(d)
        assert crt is None and key is None


class TestFetchTailscale:
    def test_missing_binary_raises(self, tmp_path: Path):
        with pytest.raises(RuntimeError, match="not found"):
            fetch_tailscale_cert(
                "h.example.ts.net", tmp_path,
                tailscale_bin="this-binary-does-not-exist-xyz",
            )

    def test_nonzero_exit_raises(self, tmp_path: Path):
        # Mock subprocess.run to return non-zero.
        from unittest.mock import MagicMock
        mock_result = MagicMock(returncode=1, stderr="permission denied",
                                stdout="")
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="exit 1"):
                fetch_tailscale_cert("h.test", tmp_path)

    def test_success_writes_files(self, tmp_path: Path):
        cert_pem, key_pem = generate_self_signed_cert("h.test")
        cert_dir = tmp_path / "certs"

        from unittest.mock import MagicMock
        def fake_run(cmd, **kwargs):
            # Locate the --cert-file + --key-file args and write them.
            cert_path = Path(cmd[cmd.index("--cert-file") + 1])
            key_path = Path(cmd[cmd.index("--key-file") + 1])
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            crt, key = fetch_tailscale_cert(
                "deployhost.example.ts.net", cert_dir,
            )
        assert crt.exists()
        assert key.exists()
