#!/usr/bin/env python3
"""Build-time check: no bundled certificate carries a distrusted public key (punch 656).

WHY. The eMudhra incident (GHSA-6q48-6c7w-9gw2, Mozilla bug 2083709) is a compromise of
KEYS. The image already distrusts the two ROOTS that anchored them (Containerfile, the
N-621 step: emSign ECC Root CA - G3 and AAA Certificate Services, matched by the SHA-256 of
each root's DER). A distrust by root is the wrong granularity for a key compromise: the same
key can be certified again, by another issuer or in a bundle we do not control (a cross-sign
by a root we keep, a certifi release, a vendored bundle in a dependency). Go, Chrome and
Homebrew block these keys by SPKI. Python 3.12 had no hook to read the verified chain of a
live handshake, so a run-time check was out of reach; this is the build-time half: it reads
every certificate the image bundles and refuses the build if any carries a denied key.

WHAT IT CHECKS. For every PEM certificate (and every DER-encoded ``.cer``/``.crt``; a
certificate-named file holding neither is listed in the output, never silently skipped) in a trust-looking file under the roots (default:
the CApath ``/etc/ssl/certs`` and everything under ``/usr/local/lib``, which holds
site-packages and so certifi and every vendored ``cacert.pem``), the SHA-256 of its
SubjectPublicKeyInfo DER (the standard SPKI pin value) against ``DENIED_SPKI_SHA256``.
The match is on the key, not on the certificate: a different subject, issuer, serial or
validity over the same key is refused too.

FAIL CLOSED. It exits 1 when a denied key is found, when a certificate block cannot be
parsed (an unreadable block is not evidence of a clean one), when a root does not exist,
when a directory under a root cannot be listed (``os.walk`` ``onerror``), and when it saw fewer than ``MIN_CERTS`` certificates in total (a scan that found nothing
reads as clean, so a blind scan must fail). It exits 0 only after reading the
certificates and finding none denied. Stdlib only, so the build runs it under
``python -I -S`` with no site-packages and no ``.pth`` file in the way.

THE LIST. ``DENIED_SPKI_SHA256`` and the SPKI hasher live in the package, in
``src/email_triage/_distrusted_spki.py`` (cycle P DA P4-5): the run-time check in
``email_triage.tls`` and this build-time scan read that ONE copy. This script runs under
``python -I -S``, so it cannot import the package: it loads that file BY PATH, from the repo
checkout (``src/email_triage`` beside ``scripts/``) or from the installed package in the
interpreter's site-packages (the image's builder COPY puts it there before the build RUN).
Neither found is exit 1, never an empty list. The names are re-exported here, so
``check_distrusted_spki.DENIED_SPKI_SHA256`` / ``spki_sha256`` / ``DerError`` still read.

Python 3.13 added ``SSLSocket.get_verified_chain()``; the image base is Python 3.14, so a
post-handshake SPKI check over the verified chain is possible there. That is a run-time
control and a separate decision; this script does not make it.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import sys
import sysconfig

_LIST_FILE = os.path.join("email_triage", "_distrusted_spki.py")


def _list_candidates() -> list[str]:
    """Where the package's deny-list module can be: the repo checkout, then the installed
    package of THIS interpreter (``python -I -S`` puts no site-packages on sys.path, but
    ``sysconfig`` still names the directory)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return [os.path.normpath(os.path.join(here, os.pardir, "src", _LIST_FILE)),
            os.path.join(sysconfig.get_path("purelib"), _LIST_FILE)]


def _load_list_module():
    for candidate in _list_candidates():
        if os.path.isfile(candidate):
            spec = importlib.util.spec_from_file_location("_et_distrusted_spki", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    print("punch 656:refusing the build: the distrusted-key list "
          f"({_LIST_FILE}) was not found at {', '.join(_list_candidates())}")
    sys.exit(1)


_LIST = _load_list_module()
DENIED_SPKI_SHA256: dict[str, str] = _LIST.DENIED_SPKI_SHA256
DerError = _LIST.DerError
spki_sha256 = _LIST.spki_sha256

DEFAULT_ROOTS = ("/etc/ssl/certs", "/usr/local/lib")
# Punch 776 (b): the data volume where the lazy embedding installer puts torch, the model
# and any certifi it pulls in. It is NOT a default root: the directory is created after the
# build-time RUN of this script (Containerfile), and a missing root exits 1, so listing it
# in DEFAULT_ROOTS would fail every image build. An optional root is scanned in full when
# it exists (the same script, run in the container) and is named in the output when it
# does not, so the skip is visible and never silent.
OPTIONAL_ROOTS = ("/app/data/runtime-deps",)
MIN_CERTS = 100  # the CApath alone holds ~150; fewer means the scan was blind
MAX_FILE_BYTES = 8 * 1024 * 1024

_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
_CERT_SUFFIXES = (".pem", ".crt", ".cer")
_HASH_LINK_RE = re.compile(r"^[0-9a-f]{8}\.\d+$")  # OpenSSL CApath hash links


def pem_certificates(data: bytes) -> list[bytes]:
    """The DER of every PEM certificate block in ``data``."""
    blobs: list[bytes] = []
    for block in _PEM_RE.findall(data):
        try:
            blobs.append(base64.b64decode(b"".join(block.split()), validate=True))
        except ValueError as exc:
            raise DerError(f"certificate block is not base64: {exc}") from None
    return blobs


def _looks_like_cert_file(name: str) -> bool:
    return name.endswith(_CERT_SUFFIXES) or bool(_HASH_LINK_RE.match(name))


def _looks_like_der_cert(data: bytes) -> bool:
    """A DER certificate: a SEQUENCE (0x30) with a long-form length (0x81..0x83).

    A certificate is always longer than 127 bytes, so its length is long-form; text that
    merely starts with "0" has an ASCII byte, never 0x81, after it."""
    return data[:1] == b"\x30" and data[1:2] in (b"\x81", b"\x82", b"\x83")


def iter_cert_files(root: str, errors: list[str] | None = None):
    """Regular files (symlinks followed to a file) that can hold a certificate.

    ``os.walk`` discards a directory it cannot list unless given ``onerror``; an
    unreadable subdirectory holding a vendored bundle must fail the scan, not shrink
    it silently (hipaa-sme SHOULD-1, fail-OPEN otherwise)."""
    def _walk_error(exc: OSError) -> None:
        if errors is not None:
            errors.append(f"walk {root}: {exc}")

    for dirpath, _dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        for name in sorted(files):
            if _looks_like_cert_file(name):
                path = os.path.join(dirpath, name)
                if os.path.isfile(path):  # a dangling CApath link trusts nothing
                    yield path


class Report:
    def __init__(self) -> None:
        self.certificates = 0
        self.files = 0
        self.denied: list[tuple[str, int, str]] = []  # (path, index in file, key name)
        self.errors: list[str] = []
        self.skipped: list[str] = []  # certificate-named files holding no PEM or DER certificate

    @property
    def ok(self) -> bool:
        return not self.denied and not self.errors


def scan(roots, denied: dict[str, str] | None = None, min_certs: int = MIN_CERTS) -> Report:
    """Scan every certificate file under ``roots``; see the module docstring."""
    denied = DENIED_SPKI_SHA256 if denied is None else denied
    report = Report()
    for root in roots:
        if not os.path.isdir(root):
            report.errors.append(f"root {root!r} is not a directory, so it was not scanned")
            continue
        for path in iter_cert_files(root, report.errors):
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    report.errors.append(f"{path}: larger than {MAX_FILE_BYTES} bytes, not scanned")
                    continue
                with open(path, "rb") as handle:
                    data = handle.read()
                blobs = pem_certificates(data)
            except (OSError, DerError) as exc:
                report.errors.append(f"{path}: {exc}")
                continue
            if not blobs and _looks_like_der_cert(data):
                blobs = [data]  # a DER-encoded .cer/.crt holds exactly one certificate
            if not blobs:
                report.skipped.append(path)  # neither PEM nor DER: counted and printed, not silent
                continue
            report.files += 1
            for index, der in enumerate(blobs):
                try:
                    key = spki_sha256(der)
                except DerError as exc:
                    report.errors.append(f"{path} certificate {index}: {exc}")
                    continue
                report.certificates += 1
                if key in denied:
                    report.denied.append((path, index, denied[key]))
    if report.certificates < min_certs:
        report.errors.append(
            f"saw {report.certificates} certificate(s), fewer than {min_certs}: the scan "
            "was blind, and a blind scan reads as clean"
        )
    return report


def default_roots() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(roots to scan, optional roots that are absent): DEFAULT_ROOTS plus every
    OPTIONAL_ROOTS entry that is a directory."""
    present = tuple(r for r in OPTIONAL_ROOTS if os.path.isdir(r))
    absent = tuple(r for r in OPTIONAL_ROOTS if r not in present)
    return DEFAULT_ROOTS + present, absent


def main(argv: list[str] | None = None) -> int:
    roots = tuple(sys.argv[1:] if argv is None else argv)
    absent: tuple[str, ...] = ()
    if not roots:
        roots, absent = default_roots()
    for path in absent:
        print(f"punch 656:note: optional root {path} does not exist, so it was not scanned")
    report = scan(roots)
    for path, index, name in report.denied:
        print(f"punch 656:{path} certificate {index} carries the distrusted key of {name}")
    for problem in report.errors:
        print(f"punch 656:{problem}")
    for path in report.skipped:
        print(f"punch 656:note: {path} has a certificate name but holds no PEM or DER certificate")
    if not report.ok:
        print(
            "punch 656:refusing the build: a bundled certificate carries a distrusted "
            "eMudhra key, or the bundles could not be read in full"
        )
        return 1
    print(
        f"punch 656:{report.certificates} certificate(s) in {report.files} file(s) under "
        f"{', '.join(roots)}; none carries any of the {len(DENIED_SPKI_SHA256)} distrusted keys"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
