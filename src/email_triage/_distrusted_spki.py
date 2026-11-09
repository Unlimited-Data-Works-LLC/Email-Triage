"""The distrusted-key list and the SPKI hasher: the ONE copy (punch 656 / 776, cycle P DA P4-5).

Two readers, one list:

* ``email_triage.tls`` imports this module and judges the VERIFIED chain of every outbound
  handshake against ``DENIED_SPKI_SHA256`` (punch 776 (a), the run-time check);
* ``scripts/check_distrusted_spki.py`` loads this file BY PATH and scans every certificate
  the image bundles at build time (punch 656). It runs under ``python -I -S`` (no
  site-packages), so it cannot import the package; it finds this file in the repo checkout
  or in the image's installed package.

It lives INSIDE the package so a wheel or portable install carries it: before cycle P the
run-time check loaded the build script from ``<repo>/scripts`` or ``/app/scripts``, and an
install with neither directory refused every verified connection. A plain module, not a
data file: setuptools ships every ``.py`` of the package with no package-data declaration
to forget.

KEEP IT STDLIB-ONLY AND SELF-CONTAINED: no import from ``email_triage``, because the build
step executes this file on its own.

THE LIST. ``DENIED_SPKI_SHA256`` is the incident's own ``impacted-intermediates.json``
(emudhra.we-have-a-problem.com): 8 distinct keys across its 16 entries (each key is
certified twice, once under the emSign root and once as a Sectigo cross-sign by AAA
Certificate Services): 6 TLS keys and 2 code-signing keys. The values were checked on
2026-10-30 against the certificate PEM carried in the same file, so the list is the
fingerprint of the key each PEM contains, not the file's word for it. Re-check it on every
base-image or ca-certificates bump, and when the Mozilla bug adds a key.
"""

from __future__ import annotations

import hashlib

# SPKI SHA-256 (lowercase hex) -> "<intermediate name> (<usage>)".
DENIED_SPKI_SHA256: dict[str, str] = {
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": "EM DV TLS CA - G3B (tls)",
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": "EM OV TLS CA - G3B (tls)",
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": "EM EV TLS CA - G3B (tls)",
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": "EM DV TLS CA - G3C (tls)",
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": "EM OV TLS CA - G3C (tls)",
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": "EM EV TLS CA - G3C (tls)",
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": "EM OV CS CA - G3B (code-signing)",
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": "EM OV CS CA - G3C (code-signing)",
}


class DerError(ValueError):
    """The bytes are not a certificate this walker can read."""


def _tlv(buf: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """(tag, content_start, content_end) of the DER element at ``pos``."""
    if pos + 2 > end:
        raise DerError("truncated element header")
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > end:
            raise DerError("unsupported length form")
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    if pos + length > end:
        raise DerError("element runs past its parent")
    return tag, pos, pos + length


def spki_sha256(der: bytes) -> str:
    """SHA-256 (lowercase hex) of the certificate's SubjectPublicKeyInfo DER.

    Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serial,
    signature, issuer, validity, subject, subjectPublicKeyInfo SEQUENCE, ... }, ... }.
    The hash covers the whole SPKI element, header included, which is the value Go,
    Chrome, HPKP and Homebrew's deny-lists use."""
    end = len(der)
    tag, start, stop = _tlv(der, 0, end)
    if tag != 0x30:
        raise DerError("certificate is not a SEQUENCE")
    if stop != end:
        # Only the first certificate is hashed, so bytes after it (a second, denied
        # certificate in a .cer or inside one PEM block) would pass unchecked (DA S2).
        raise DerError(f"{end - stop} byte(s) after the certificate were not checked")
    tag, pos, tbs_end = _tlv(der, start, stop)
    if tag != 0x30:
        raise DerError("tbsCertificate is not a SEQUENCE")
    # optional explicit [0] version, then serial, signature, issuer, validity, subject
    skip = 5
    cursor = pos
    first_tag, _, first_end = _tlv(der, cursor, tbs_end)
    if first_tag == 0xA0:
        cursor = first_end
    for _ in range(skip):
        _, _, element_end = _tlv(der, cursor, tbs_end)
        cursor = element_end
    spki_tag, _, spki_end = _tlv(der, cursor, tbs_end)
    if spki_tag != 0x30:
        raise DerError("subjectPublicKeyInfo is not a SEQUENCE")
    return hashlib.sha256(der[cursor:spki_end]).hexdigest()
