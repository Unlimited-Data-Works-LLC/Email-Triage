"""Make-CSR / sign / import-cert workflow for institutional CAs (#74).

For deployments where the operator gets a 3-year commercial cert from
the org's PKI (Sectigo, DigiCert, internal CA, etc.) instead of using
ACME or self-signed. The flow:

1. Operator clicks "Make CSR" with a hostname + optional SANs.
2. Module generates an RSA-2048 keypair; private key written to
   ``<cert_dir>/server.key.pending``; CSR written to
   ``<cert_dir>/server.csr``. Operator downloads the CSR.
3. Operator submits CSR to their CA, gets back a signed cert.
4. Operator pastes the signed PEM (cert + intermediates).
5. Module validates the imported public key matches the held private
   key, atomically swaps ``server.key.pending`` -> ``server.key`` +
   writes the cert to ``server.crt``. The TLS hot-reload watcher
   picks up the new cert mtime within 30s and reloads SSLContext.

Pure-Python module: no FastAPI, no CLI imports. Both the route
handler and any future CLI subcommand call into the same code.
"""

from __future__ import annotations

import ipaddress as _ip
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger("email_triage.tls_csr")


# ---------------------------------------------------------------------------
# Filenames inside cert_dir
# ---------------------------------------------------------------------------

CERT_FILENAME = "server.crt"
KEY_FILENAME = "server.key"
PENDING_KEY_FILENAME = "server.key.pending"
PENDING_CSR_FILENAME = "server.csr"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TlsCsrError(Exception):
    """Base for the workflow's typed errors."""


class CsrAlreadyPendingError(TlsCsrError):
    """A CSR is already pending; the operator must cancel before
    starting another. Avoids accidentally overwriting an in-flight
    keypair the operator may have already submitted to their CA."""


class NoPendingCsrError(TlsCsrError):
    """Import attempted with no pending key on disk -- nothing to
    pair the cert with. Operator should make a CSR first."""


class KeyMismatchError(TlsCsrError):
    """The imported cert's public key doesn't match the held private
    key. Defense against pasting the wrong cert by mistake."""


class InvalidPemError(TlsCsrError):
    """Submitted PEM didn't parse as a valid X.509 cert chain."""


# ---------------------------------------------------------------------------
# State enum-ish
# ---------------------------------------------------------------------------

# Three operator-visible states the workflow can be in:
STATE_IDLE = "idle"          # No active cert, no pending CSR. Make-CSR / Self-sign available.
STATE_PENDING = "pending"    # Pending key + CSR on disk; awaiting CA-signed cert.
STATE_ACTIVE = "active"      # Active server.crt + server.key in place.


def detect_state(cert_dir: Path) -> str:
    """Inspect cert_dir filesystem to determine which UI to render."""
    cert_dir = Path(cert_dir)
    has_active = (cert_dir / CERT_FILENAME).is_file() and (
        cert_dir / KEY_FILENAME
    ).is_file()
    has_pending = (cert_dir / PENDING_KEY_FILENAME).is_file() and (
        cert_dir / PENDING_CSR_FILENAME
    ).is_file()

    # Pending takes precedence in the UI even when an old active cert
    # exists -- operator is mid-rotation; the pending CSR is what
    # they're working on.
    if has_pending:
        return STATE_PENDING
    if has_active:
        return STATE_ACTIVE
    return STATE_IDLE


# ---------------------------------------------------------------------------
# CSR generation
# ---------------------------------------------------------------------------

def _build_subject(hostname: str, organization: str = "email-triage") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])


def _build_san_entries(hostname: str, extra_sans: list[str] | None) -> list[x509.GeneralName]:
    san_entries: list[x509.GeneralName] = [x509.DNSName(hostname)]
    for extra in extra_sans or []:
        extra = extra.strip()
        if not extra:
            continue
        try:
            san_entries.append(x509.IPAddress(_ip.ip_address(extra)))
        except (ValueError, TypeError):
            san_entries.append(x509.DNSName(extra))
    return san_entries


def make_csr(
    cert_dir: Path,
    hostname: str,
    *,
    extra_sans: list[str] | None = None,
    organization: str = "email-triage",
    overwrite_pending: bool = False,
) -> tuple[Path, Path, bytes]:
    """Generate a fresh RSA-2048 keypair + CSR.

    Returns ``(key_path, csr_path, csr_pem_bytes)``. The CSR bytes are
    returned for the route handler to stream as a download without
    re-reading the file from disk.

    Raises ``CsrAlreadyPendingError`` if a pending key/CSR already
    exists on disk and ``overwrite_pending`` is False -- avoids
    accidentally killing an in-flight CSR the operator may have
    already submitted to their CA.
    """
    if not hostname or not hostname.strip():
        raise ValueError("hostname required")
    cert_dir = Path(cert_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)

    pending_key = cert_dir / PENDING_KEY_FILENAME
    pending_csr = cert_dir / PENDING_CSR_FILENAME

    if pending_key.is_file() or pending_csr.is_file():
        if not overwrite_pending:
            raise CsrAlreadyPendingError(
                "A CSR is already pending. Cancel it first before "
                "starting another, or pass overwrite_pending=True.",
            )
        # Clean up before generating a new one.
        for p in (pending_key, pending_csr):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    # Generate keypair.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Build the CSR.
    san = _build_san_entries(hostname, extra_sans)
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_build_subject(hostname, organization))
        .add_extension(
            x509.SubjectAlternativeName(san),
            critical=False,
        )
    )
    csr = csr_builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Atomic write of the keypair + CSR.
    pending_key.write_bytes(key_pem)
    pending_csr.write_bytes(csr_pem)
    try:
        os.chmod(pending_key, 0o600)
    except OSError:
        pass
    return pending_key, pending_csr, csr_pem


def cancel_pending(cert_dir: Path) -> None:
    """Remove the pending keypair + CSR. Caller's check that the
    operator confirmed."""
    cert_dir = Path(cert_dir)
    for name in (PENDING_KEY_FILENAME, PENDING_CSR_FILENAME):
        try:
            (cert_dir / name).unlink(missing_ok=True)
        except OSError as e:
            logger.warning(
                "Failed to remove pending CSR file: %s (%s)", name, e,
            )


def read_pending_csr(cert_dir: Path) -> bytes:
    """Return the PEM bytes of the pending CSR for re-download."""
    cert_dir = Path(cert_dir)
    p = cert_dir / PENDING_CSR_FILENAME
    if not p.is_file():
        raise NoPendingCsrError(
            "No pending CSR on disk. Make one first.",
        )
    return p.read_bytes()


# ---------------------------------------------------------------------------
# Cert import (the CA-signed PEM)
# ---------------------------------------------------------------------------

def _public_key_fingerprint(pubkey: Any) -> bytes:
    """SHA-256 of the SubjectPublicKeyInfo DER. Used to check that
    the cert's public key matches the held private key's public
    half. Stable across encodings."""
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import hashlib as _h
    return _h.sha256(der).digest()


def _parse_cert_chain(pem_bytes: bytes) -> list[x509.Certificate]:
    """Parse one or more PEM-encoded certs in a single byte string.

    Operator typically pastes their CA's response which is the leaf +
    intermediates concatenated. We accept the whole chain and write it
    verbatim to server.crt so curl / browser builds the path correctly.
    """
    try:
        chain = x509.load_pem_x509_certificates(pem_bytes)
    except (ValueError, TypeError) as e:
        raise InvalidPemError(f"Could not parse PEM cert(s): {e}") from e
    if not chain:
        raise InvalidPemError("PEM input contained no certificates.")
    return chain


def import_signed_cert(
    cert_dir: Path,
    cert_pem: bytes,
) -> tuple[Path, Path]:
    """Validate + atomically swap: pending key -> server.key,
    pasted cert PEM -> server.crt.

    Validates:

    * Pending key exists.
    * Cert PEM parses as one or more X.509 certs.
    * The leaf cert's public key matches the held private key.
    * The cert isn't already expired (warning, not refusal).

    On success: rename ``server.key.pending`` to ``server.key``,
    write the cert PEM (full chain, verbatim) to ``server.crt``,
    delete ``server.csr``. Returns the two paths.

    Raises ``NoPendingCsrError``, ``InvalidPemError``,
    ``KeyMismatchError``.
    """
    cert_dir = Path(cert_dir)
    pending_key = cert_dir / PENDING_KEY_FILENAME
    pending_csr = cert_dir / PENDING_CSR_FILENAME
    active_key = cert_dir / KEY_FILENAME
    active_cert = cert_dir / CERT_FILENAME

    if not pending_key.is_file():
        raise NoPendingCsrError(
            "No pending key on disk. Make a CSR first.",
        )

    # Parse the chain.
    chain = _parse_cert_chain(cert_pem)
    leaf = chain[0]

    # Load the held private key.
    try:
        priv = serialization.load_pem_private_key(
            pending_key.read_bytes(), password=None,
        )
    except (ValueError, TypeError) as e:
        raise InvalidPemError(
            f"Held private key failed to load: {e}",
        ) from e

    # Compare public-key fingerprints.
    if (
        _public_key_fingerprint(leaf.public_key())
        != _public_key_fingerprint(priv.public_key())
    ):
        raise KeyMismatchError(
            "Imported cert's public key does NOT match the held "
            "private key. Did you paste the right cert?",
        )

    # Soft warning on expired cert -- import anyway, operator's call.
    now = datetime.now(timezone.utc)
    try:
        not_after = leaf.not_valid_after_utc  # cryptography 42+
    except AttributeError:
        # Older cryptography; not_valid_after is naive UTC.
        not_after = leaf.not_valid_after.replace(tzinfo=timezone.utc)
    if not_after < now:
        logger.warning(
            "Importing a cert that's already expired: not_after=%s",
            not_after.isoformat(),
        )

    # Atomic swap: promote the pending KEY first, then atomic-write the
    # cert. The hot-reload watcher (cli.py:_watch_cert_thread) polls
    # cert mtime and triggers SSLContext.load_cert_chain on change.
    # Promoting the key first closes the race where the watcher would
    # fire with new-cert + old-key on disk and SSLError out for one
    # 30s tick.
    pending_key.replace(active_key)  # atomic rename on POSIX
    try:
        os.chmod(active_key, 0o600)
    except OSError:
        pass
    # Atomic temp+replace for the cert -- guarantees the watcher
    # never sees a partially-written cert PEM.
    tmp_cert = active_cert.with_suffix(active_cert.suffix + ".new")
    tmp_cert.write_bytes(cert_pem)
    os.replace(tmp_cert, active_cert)
    # Clean up the CSR; it served its purpose.
    try:
        pending_csr.unlink(missing_ok=True)
    except OSError:
        pass

    return active_cert, active_key


# ---------------------------------------------------------------------------
# Cert metadata helpers (used by the UI to render expiry + subject)
# ---------------------------------------------------------------------------

def cert_metadata(cert_pem: bytes) -> dict[str, Any]:
    """Pull operator-facing metadata from a cert PEM. Used by the
    page render to show "currently active: CN=<host>, expires in
    Nd" alongside the manage-cert UI.

    Returns a dict with subject_cn, issuer_cn, not_before, not_after,
    days_until_expiry, sans (list of strings). All values stringified
    for direct template rendering.
    """
    chain = _parse_cert_chain(cert_pem)
    leaf = chain[0]
    out: dict[str, Any] = {}
    try:
        out["subject_cn"] = leaf.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME,
        )[0].value
    except (IndexError, AttributeError):
        out["subject_cn"] = "(unset)"
    try:
        out["issuer_cn"] = leaf.issuer.get_attributes_for_oid(
            NameOID.COMMON_NAME,
        )[0].value
    except (IndexError, AttributeError):
        out["issuer_cn"] = "(unset)"
    try:
        nb = leaf.not_valid_before_utc
        na = leaf.not_valid_after_utc
    except AttributeError:
        nb = leaf.not_valid_before.replace(tzinfo=timezone.utc)
        na = leaf.not_valid_after.replace(tzinfo=timezone.utc)
    out["not_before"] = nb.isoformat()
    out["not_after"] = na.isoformat()
    delta = na - datetime.now(timezone.utc)
    out["days_until_expiry"] = delta.days
    sans: list[str] = []
    try:
        san_ext = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        for entry in san_ext.value:
            if isinstance(entry, x509.DNSName):
                sans.append(f"DNS:{entry.value}")
            elif isinstance(entry, x509.IPAddress):
                sans.append(f"IP:{entry.value}")
    except x509.ExtensionNotFound:
        pass
    out["sans"] = sans
    out["chain_length"] = len(chain)
    return out


def active_cert_metadata(cert_dir: Path) -> dict[str, Any] | None:
    """Convenience: read server.crt + return metadata, or None if
    no active cert."""
    cert_dir = Path(cert_dir)
    p = cert_dir / CERT_FILENAME
    if not p.is_file():
        return None
    try:
        return cert_metadata(p.read_bytes())
    except Exception as e:
        logger.warning("active_cert_metadata: parse failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Self-sign shortcut
# ---------------------------------------------------------------------------

def self_sign_now(
    cert_dir: Path,
    hostname: str,
    *,
    extra_sans: list[str] | None = None,
    valid_days: int = 365,
) -> tuple[Path, Path]:
    """Generate a self-signed cert + key and write directly to the
    active filenames. Skips the CSR + import dance -- intended for
    bring-up before a real CA-signed cert is in flight.

    Wraps ``email_triage.tls.generate_self_signed_cert`` for
    consistency with the existing self-sign code path.
    """
    from email_triage.tls import generate_self_signed_cert, write_cert_files
    cert_pem, key_pem = generate_self_signed_cert(
        hostname=hostname,
        valid_days=valid_days,
        extra_sans=extra_sans,
    )
    return write_cert_files(cert_dir, cert_pem, key_pem)


# ---------------------------------------------------------------------------
# Expiry-warning helper used by daily-health-email
# ---------------------------------------------------------------------------

def cert_expiry_warning(cert_dir: Path) -> str | None:
    """Return a one-line expiry warning string when the active cert is
    near expiry, else None. Thresholds: 7 / 14 / 30 days."""
    md = active_cert_metadata(cert_dir)
    if md is None:
        return None
    days = int(md.get("days_until_expiry") or 0)
    if days <= 7:
        return (
            f"⚠ TLS cert expires in {days} day(s). Renew via "
            f"/admin/tls/csr (institutional CA) or "
            f"/admin/acme-status (ACME)."
        )
    if days <= 14:
        return (
            f"⚠ TLS cert expires in {days} days. Plan renewal."
        )
    if days <= 30:
        return (
            f"TLS cert expires in {days} days. Reminder."
        )
    return None
