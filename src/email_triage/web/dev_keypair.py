"""Dev-keypair login: parse OpenSSH ed25519 public keys, fingerprint
them, and verify ed25519 signatures against challenges.

Admin-managed credential surface (#67). The admin pastes the public
key into ``/admin/dev-keys``; the matching private key never leaves
the operator's machine. Login proceeds via challenge-response —
server emits a 32-byte challenge, operator signs it with the
private key (via the ``email-triage auth dev-login`` CLI), server
verifies the signature against the registered public key.

Hard-bound to a per-key TTL + per-key email allowlist so a leaked
public-key registration on the server has zero secret value (it is,
by definition, public) and the only credential capable of completing
the login is the operator-held private key.

Storage format mirrors OpenSSH's ``id_ed25519.pub``:
``ssh-ed25519 <base64-blob> [comment]``.

The ``<base64-blob>`` decodes to the SSH wire format
``[len][string "ssh-ed25519"][len][raw 32-byte pubkey]`` per
RFC 4253 §6.6 / RFC 8709.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


SSH_ED25519_KEYTYPE = b"ssh-ed25519"


class DevKeyParseError(ValueError):
    """Raised on malformed OpenSSH public-key text."""


@dataclass(frozen=True)
class ParsedDevKey:
    """An OpenSSH ed25519 public key parsed into its parts.

    ``raw_pubkey`` is the 32-byte ed25519 public key suitable for
    direct use with ``cryptography`` primitives.
    ``comment`` is the trailing free-text field (often
    ``user@host``) — informational only, not used in fingerprinting.
    """
    keytype: str
    raw_pubkey: bytes
    blob: bytes  # the full SSH wire blob, used for fingerprinting
    comment: str


def _read_ssh_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Read a length-prefixed SSH string. Returns (value, new_offset)."""
    if offset + 4 > len(buf):
        raise DevKeyParseError("Truncated SSH wire blob (length prefix)")
    (length,) = struct.unpack(">I", buf[offset:offset + 4])
    start = offset + 4
    end = start + length
    if end > len(buf):
        raise DevKeyParseError(
            f"Truncated SSH wire blob (claimed {length} bytes, "
            f"only {len(buf) - start} available)"
        )
    return buf[start:end], end


def parse_ssh_ed25519_pubkey(text: str) -> ParsedDevKey:
    """Parse an OpenSSH ``ssh-ed25519 ... [comment]`` line.

    Raises ``DevKeyParseError`` on:
    - wrong keytype (RSA, ecdsa, etc.) — only ed25519 accepted
    - malformed base64 / wire format
    - keytype prefix in the blob doesn't match the text prefix

    Comment is preserved on the returned dataclass for display in
    the admin UI; it is NOT trusted for any access-control decision.
    """
    if not text or not text.strip():
        raise DevKeyParseError("Empty key text")
    parts = text.strip().split(maxsplit=2)
    if len(parts) < 2:
        raise DevKeyParseError(
            "Public key text must have at least 'keytype base64'"
        )
    keytype = parts[0]
    b64 = parts[1]
    comment = parts[2] if len(parts) >= 3 else ""

    if keytype != "ssh-ed25519":
        raise DevKeyParseError(
            f"Only ssh-ed25519 keys are accepted; got {keytype!r}. "
            "Generate one with: ssh-keygen -t ed25519 -f ~/.ssh/et-dev"
        )

    try:
        blob = base64.b64decode(b64, validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise DevKeyParseError(f"Invalid base64 in key blob: {e}") from e

    # Wire format: string "ssh-ed25519" + string raw_pubkey
    inner_keytype, off = _read_ssh_string(blob, 0)
    if inner_keytype != SSH_ED25519_KEYTYPE:
        raise DevKeyParseError(
            f"Wire-blob keytype {inner_keytype!r} doesn't match "
            f"text prefix {keytype!r}"
        )
    raw_pubkey, off = _read_ssh_string(blob, off)
    if off != len(blob):
        raise DevKeyParseError(
            f"Trailing bytes in wire blob (parsed {off}, total {len(blob)})"
        )
    if len(raw_pubkey) != 32:
        raise DevKeyParseError(
            f"ed25519 public key must be 32 bytes; got {len(raw_pubkey)}"
        )

    return ParsedDevKey(
        keytype=keytype,
        raw_pubkey=raw_pubkey,
        blob=blob,
        comment=comment,
    )


def fingerprint(parsed: ParsedDevKey) -> str:
    """Return ``SHA256:<b64>`` matching ``ssh-keygen -lf`` output.

    Format: ``SHA256:<base64>`` with the trailing ``=`` padding
    stripped (matches OpenSSH's display convention). Used as the
    DB unique key on dev_keys so the same physical key can't be
    registered twice.
    """
    digest = hashlib.sha256(parsed.blob).digest()
    b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"


def verify_signature(
    parsed: ParsedDevKey, message: bytes, signature: bytes,
) -> bool:
    """Verify ``signature`` over ``message`` using the parsed public key.

    ``message`` is the raw bytes signed (typically the challenge
    bytes, NOT base64-encoded — caller is responsible for matching
    its sign-side encoding). ``signature`` is the raw 64-byte
    ed25519 signature.

    Returns True on valid signature, False on any failure
    (invalid sig, wrong key, truncated input). Never raises.
    """
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(parsed.raw_pubkey)
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Defensive: any structural error in the inputs is treated as
        # verify-fail rather than propagated. Login route surfaces a
        # generic "invalid signature" error either way.
        return False


def generate_login_challenge() -> bytes:
    """Mint a fresh 32-byte challenge for a login attempt.

    Cookie-stored, 2-min TTL, single-use (caller deletes on first
    successful verify). 32 bytes of CSPRNG output is the standard
    SSH-CA-style challenge size; ed25519 has no upper bound on
    message length so we don't need to constrain it further.
    """
    import os
    return os.urandom(32)
