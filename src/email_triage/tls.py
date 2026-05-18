"""Self-signed TLS cert generation for the internal HTTPS listener.

Produces an RSA-2048 cert + key pair for the FastAPI/uvicorn listener
so the `/` UI runs over HTTPS even on a homelab Tailnet. Defense-in-
depth alongside the WireGuard transport — strict reading of HIPAA
§164.312(e)(1) wants TLS at the app listener regardless of what the
LAN does for transport.

Browser sees a self-signed warning the first time. Operator either
imports the cert as a trusted root (one-click on Tailnet peers) or
clicks through. Upgrade path: replace the cert files with a
real LE / Tailscale-issued cert; uvicorn doesn't care which CA
issued them.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    hostname: str,
    valid_days: int = 365,
    extra_sans: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """Generate a fresh RSA-2048 self-signed cert + key.

    Returns ``(cert_pem, key_pem)`` byte strings the caller writes
    to disk. SAN list defaults to the hostname plus ``localhost`` +
    ``127.0.0.1`` so loopback health checks work without an alias.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "email-triage"),
    ])

    san_entries: list[x509.GeneralName] = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
    ]
    # Add 127.0.0.1 / ::1 as IP SANs so curl --insecure against
    # loopback validates the SAN list rather than tripping on
    # hostname mismatch.
    import ipaddress as _ip
    san_entries.append(x509.IPAddress(_ip.ip_address("127.0.0.1")))
    san_entries.append(x509.IPAddress(_ip.ip_address("::1")))
    for extra in extra_sans or []:
        try:
            san_entries.append(x509.IPAddress(_ip.ip_address(extra)))
        except (ValueError, TypeError):
            san_entries.append(x509.DNSName(extra))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))  # clock skew slack
        .not_valid_after(now + timedelta(days=int(valid_days)))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_cert_files(
    cert_dir: str | Path,
    cert_pem: bytes,
    key_pem: bytes,
) -> tuple[Path, Path]:
    """Write cert + key to ``<cert_dir>/server.crt`` + ``server.key``
    with restrictive perms on the key. Returns the two paths.

    Atomic temp-then-replace per file. Order: key first, cert second --
    the hot-reload watcher (cli.py:_watch_cert) polls cert mtime and
    triggers SSLContext.load_cert_chain on change. Writing key first
    closes the race where a watcher fires with new-cert + old-key.
    """
    cert_dir_path = Path(cert_dir)
    cert_dir_path.mkdir(parents=True, exist_ok=True)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"
    for path, data in ((key, key_pem), (crt, cert_pem)):
        tmp = path.with_suffix(path.suffix + ".new")
        tmp.write_bytes(data)
        # Tighten the key tempfile pre-rename (Unix only — no-op on
        # Windows). Cert file gets default perms, which is correct.
        if path == key:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        os.replace(tmp, path)
    return crt, key


def load_existing_cert_paths(
    cert_dir: str | Path,
) -> tuple[Path | None, Path | None]:
    """Return the cert + key paths if both exist, else ``(None, None)``."""
    cert_dir_path = Path(cert_dir)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"
    if crt.is_file() and key.is_file():
        return crt, key
    return None, None


def fetch_tailscale_cert(
    hostname: str,
    cert_dir: str | Path,
    tailscale_bin: str = "tailscale",
    timeout: int = 60,
) -> tuple[Path, Path]:
    """Fetch a real Let's Encrypt cert for ``hostname`` via the
    Tailscale daemon's HTTPS feature.

    Tailscale issues LE certs for ``<host>.<tailnet>.ts.net`` names
    when HTTPS is enabled in the Tailnet admin console (free for
    personal use). The daemon handles ACME negotiation, DNS-01
    challenge, and renewal cadence; the operator just needs to
    invoke ``tailscale cert <hostname>`` periodically (monthly cron
    is more than enough — LE certs are valid 90 days, Tailscale
    refreshes proactively).

    Shells out to the Tailscale CLI rather than implementing ACME
    in-process — keeps this path zero-dependency and matches the
    standard ops pattern (operator can run the same command by hand
    to verify).

    Returns ``(cert_path, key_path)`` after writing PEMs into
    ``cert_dir/server.crt`` + ``server.key``. Raises RuntimeError on
    any CLI failure with the captured stderr in the message.
    """
    import subprocess
    cert_dir_path = Path(cert_dir)
    cert_dir_path.mkdir(parents=True, exist_ok=True)
    crt = cert_dir_path / "server.crt"
    key = cert_dir_path / "server.key"

    # Tailscale's `cert` subcommand writes two files at the given
    # paths. The CLI requires the hostname argument and refuses
    # alt names that don't resolve via MagicDNS.
    cmd = [
        tailscale_bin, "cert",
        "--cert-file", str(crt),
        "--key-file", str(key),
        hostname,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            f"tailscale binary not found ({e}). Install Tailscale on "
            f"the host and enable HTTPS in the admin console."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"tailscale cert timed out after {timeout}s. The Tailnet "
            f"may not have HTTPS enabled, or the hostname is unknown."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"tailscale cert failed (exit {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:500]}"
        )

    if not crt.is_file() or not key.is_file():
        raise RuntimeError(
            f"tailscale cert reported success but cert files missing "
            f"at {cert_dir_path}"
        )

    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    return crt, key


def cert_mtime(cert_path: Path | str) -> float | None:
    """Return the cert file's mtime, or None if absent.

    Cheap probe used by the hot-reload watcher: poll this on a timer,
    rebuild the SSLContext when the value changes. The ACME renewer's
    atomic-replace write changes the mtime atomically with the new
    bytes appearing on disk, so observing a change is a sufficient
    signal that a fresh cert is ready to load.
    """
    p = Path(cert_path)
    try:
        return p.stat().st_mtime
    except FileNotFoundError:
        return None


def build_ssl_context(cert_path: Path | str, key_path: Path | str):
    """Build an ``ssl.SSLContext`` from the cert + key on disk.

    Used by the hot-reload watcher: the watcher detects an mtime
    change, calls this, swaps it into the running uvicorn server.
    Caller is responsible for the swap mechanism (uvicorn-version-
    dependent).
    """
    import ssl as _ssl
    ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx
