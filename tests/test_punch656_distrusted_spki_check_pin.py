"""Pin for the build-time SPKI deny-list check (punch 656).

The image distrusts the two eMudhra ROOTS by their DER hash (N-621). The compromise is of
six TLS intermediate KEYS (eight with the two code-signing keys), and each key is certified
twice (under the emSign root and as a Sectigo cross-sign by AAA Certificate Services). A
distrust by root does not bound a key. ``scripts/check_distrusted_spki.py`` reads every
certificate the image bundles and refuses the build when one carries a denied key.

What this pin holds:

  1. The SPKI walker equals ``cryptography``'s SPKI DER hash on every incident certificate,
     and the deny list is exactly the set of keys in the incident fixture (the 16 real
     certificates of ``impacted-intermediates.json``): whatever the fixture holds, the list
     covers (count-agnostic).
  2. The match is on the KEY. Both twins of every key are refused, and so are two different
     certificates (other subject, serial and issuer) over one key.
  3. It fails closed: an unparsable block, a non-base64 block, a missing root and a scan that
     saw fewer than ``MIN_CERTS`` certificates all exit 1; a clean scan exits 0.
  4. The walker handles a v1 certificate (no ``[0]`` version) and a long-form length.
  5. The Containerfile COPYs the script and runs it in the runtime stage, after the N-621
     trust-store step and before USER, as a bare RUN (no ``||`` or ``;`` that could swallow
     its exit code).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
import re

import pytest
from _pin_harness import (
    CONTAINERFILE,
    REPO_ROOT,
    dockerfile_instructions,
    dockerfile_stages,
    load_repo_script,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

spki = load_repo_script("scripts/check_distrusted_spki.py")

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "emudhra_impacted_intermediates.pem"


def _der_spki_hash(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def _incident_ders() -> list[bytes]:
    return spki.pem_certificates(FIXTURE.read_bytes())


def _make_cert(key, cn: str, serial: int, issuer_cn: str | None = None) -> bytes:
    """A self-signed (or issuer-named) certificate over ``key``, as PEM."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def keys():
    return ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())


# ── 1. the walker and the list, against the real incident certificates ──────


def test_the_fixture_is_the_incident_list():
    ders = _incident_ders()
    assert len(ders) >= 2
    assert len(ders) == FIXTURE.read_bytes().count(b"-----BEGIN CERTIFICATE-----")


def test_the_walker_equals_cryptography_on_every_incident_certificate():
    for der in _incident_ders():
        assert spki.spki_sha256(der) == _der_spki_hash(x509.load_der_x509_certificate(der))


def test_the_deny_list_is_exactly_the_keys_of_the_incident_fixture():
    fixture_keys = {spki.spki_sha256(der) for der in _incident_ders()}
    assert set(spki.DENIED_SPKI_SHA256) == fixture_keys


def test_every_deny_entry_is_a_lowercase_sha256_with_a_name():
    for key, name in spki.DENIED_SPKI_SHA256.items():
        assert re.fullmatch(r"[0-9a-f]{64}", key), key
        assert name.strip(), key


# ── 2. the match is on the key ──────────────────────────────────────────────


def test_every_incident_certificate_is_refused_whoever_issued_it(tmp_path):
    (tmp_path / "bundle.pem").write_bytes(FIXTURE.read_bytes())
    report = spki.scan([str(tmp_path)], min_certs=1)
    assert not report.ok
    assert len(report.denied) == len(_incident_ders())  # both twins of every key


def test_two_different_certificates_over_one_key_are_both_refused(tmp_path, keys):
    bad_key, other_key = keys
    (tmp_path / "a.pem").write_bytes(_make_cert(bad_key, "First CA", 1))
    (tmp_path / "b.crt").write_bytes(_make_cert(bad_key, "Second CA", 99, issuer_cn="Another Root"))
    (tmp_path / "c.pem").write_bytes(_make_cert(other_key, "Clean CA", 5))
    denied = {_der_spki_hash(x509.load_pem_x509_certificate(
        (tmp_path / "a.pem").read_bytes())): "test key"}
    report = spki.scan([str(tmp_path)], denied=denied, min_certs=1)
    assert sorted(p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for p, _, _ in report.denied) == ["a.pem", "b.crt"]
    assert report.certificates == 3
    assert not report.ok


def test_a_clean_tree_passes(tmp_path, keys):
    (tmp_path / "clean.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5))
    report = spki.scan([str(tmp_path)], min_certs=1)
    assert report.ok and report.certificates == 1 and report.denied == []


def test_a_hash_link_name_and_a_dangling_link_are_handled(tmp_path, keys):
    (tmp_path / "3fa8fcf5.0").write_bytes(_make_cert(keys[0], "Linked CA", 7))
    denied = {_der_spki_hash(x509.load_pem_x509_certificate((tmp_path / "3fa8fcf5.0").read_bytes())): "k"}
    assert len(spki.scan([str(tmp_path)], denied=denied, min_certs=1).denied) == 1


# ── 3. fail closed ──────────────────────────────────────────────────────────


def _block(b64: str) -> bytes:
    return f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n".encode()


@pytest.mark.parametrize(
    "payload",
    [
        _block("AAAA"),  # base64 of three zero bytes: not a certificate
        _block("MAA="),  # a SEQUENCE of length 0: no tbsCertificate
        _block("MIIB"),  # a SEQUENCE whose length runs past the data
        _block("!!!not base64!!!"),
    ],
)
def test_an_unreadable_certificate_block_is_an_error_not_a_pass(tmp_path, keys, payload):
    (tmp_path / "ok.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5))
    (tmp_path / "junk.pem").write_bytes(payload)
    report = spki.scan([str(tmp_path)], min_certs=1)
    assert not report.ok
    assert any("junk.pem" in e for e in report.errors), report.errors


def test_a_missing_root_is_an_error(tmp_path):
    report = spki.scan([str(tmp_path / "absent")], min_certs=0)
    assert not report.ok and report.errors


def test_a_scan_that_saw_too_few_certificates_is_blind_and_fails(tmp_path, keys):
    (tmp_path / "one.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5))
    report = spki.scan([str(tmp_path)])  # the default floor, MIN_CERTS
    assert not report.ok
    assert any("blind" in e for e in report.errors)


def test_main_exits_zero_on_a_full_clean_bundle_and_one_when_a_denied_key_joins(
    tmp_path, keys, capsys
):
    clean = _make_cert(keys[1], "Clean CA", 5)
    (tmp_path / "bundle.pem").write_bytes(clean * spki.MIN_CERTS)
    assert spki.main([str(tmp_path)]) == 0
    assert "none carries any of the" in capsys.readouterr().out
    (tmp_path / "planted.pem").write_bytes(spki._PEM_RE.search(FIXTURE.read_bytes()).group(0))
    assert spki.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "planted.pem" in out and "refusing the build" in out


# ── 3b. punch 776 (b): the runtime-deps volume is an OPTIONAL root ──────────


def test_runtime_deps_is_optional_not_default():
    """The directory does not exist at the Containerfile RUN, and a missing root exits 1:
    listing it in DEFAULT_ROOTS would fail every build. It is an optional root."""
    assert "/app/data/runtime-deps" in spki.OPTIONAL_ROOTS
    assert "/app/data/runtime-deps" not in spki.DEFAULT_ROOTS
    assert not set(spki.OPTIONAL_ROOTS) & set(spki.DEFAULT_ROOTS)


def test_an_absent_optional_root_is_named_and_does_not_fail(tmp_path, keys, capsys, monkeypatch):
    (tmp_path / "bundle.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5) * spki.MIN_CERTS)
    monkeypatch.setattr(spki, "DEFAULT_ROOTS", (str(tmp_path),))
    monkeypatch.setattr(spki, "OPTIONAL_ROOTS", (str(tmp_path / "runtime-deps"),))
    assert spki.main([]) == 0
    out = capsys.readouterr().out
    assert "optional root" in out and "runtime-deps" in out and "was not scanned" in out


def test_a_present_optional_root_is_scanned_and_a_denied_key_in_it_refuses(
    tmp_path, keys, capsys, monkeypatch
):
    base = tmp_path / "base"
    volume = tmp_path / "runtime-deps"
    base.mkdir()
    (volume / "site-packages" / "certifi").mkdir(parents=True)
    (base / "bundle.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5) * spki.MIN_CERTS)
    monkeypatch.setattr(spki, "DEFAULT_ROOTS", (str(base),))
    monkeypatch.setattr(spki, "OPTIONAL_ROOTS", (str(volume),))
    assert spki.main([]) == 0  # present and clean
    capsys.readouterr()
    planted = volume / "site-packages" / "certifi" / "cacert.pem"
    planted.write_bytes(spki._PEM_RE.search(FIXTURE.read_bytes()).group(0))
    assert spki.main([]) == 1  # present with a denied key: refused
    out = capsys.readouterr().out
    assert "cacert.pem" in out and "refusing the build" in out


# ── 4. the DER walker's branches ────────────────────────────────────────────


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + content


def _cert_like(spki_der: bytes, *, version: bool) -> bytes:
    parts = []
    if version:
        parts.append(_der(0xA0, _der(0x02, b"\x02")))
    parts += [
        _der(0x02, b"\x01"),  # serial
        _der(0x30, _der(0x06, b"\x2a\x03")),  # signature algorithm
        _der(0x30, b""),  # issuer
        _der(0x30, b""),  # validity
        _der(0x30, b""),  # subject
        spki_der,
    ]
    return _der(0x30, _der(0x30, b"".join(parts)) + _der(0x30, b"") + _der(0x03, b"\x00"))


@pytest.mark.parametrize("version", [True, False])
@pytest.mark.parametrize("size", [10, 200, 70000])  # short, one-byte long form, two-byte
def test_the_walker_hashes_the_whole_spki_element(version, size):
    element = _der(0x30, b"\x07" * size)
    assert spki.spki_sha256(_cert_like(element, version=version)) == hashlib.sha256(element).hexdigest()


def test_the_scanner_has_teeth_against_a_planted_denied_key(tmp_path):
    """A hand-built certificate whose key is on the list is flagged; the same file
    with a different list is not (the scan is not flagging everything)."""
    element = _der(0x30, b"" * 40)
    pem = _block(base64.b64encode(_cert_like(element, version=True)).decode())
    (tmp_path / "planted.pem").write_bytes(pem)
    listed = {hashlib.sha256(element).hexdigest(): "planted"}
    unlisted = {hashlib.sha256(b"other").hexdigest(): "other"}
    assert len(spki.scan([str(tmp_path)], denied=listed, min_certs=1).denied) == 1
    assert spki.scan([str(tmp_path)], denied=unlisted, min_certs=1).denied == []


# ── 5. the Containerfile runs it, last on the trust store ───────────────────


def _runtime_problems(containerfile: str) -> list[str]:
    stages = dict(dockerfile_stages(containerfile))
    runtime = [text for _line, text in stages["runtime"]]
    problems: list[str] = []
    copies = [i for i, t in enumerate(runtime) if t.upper().startswith("COPY ") and
              "scripts/check_distrusted_spki.py" in t]
    runs = [i for i, t in enumerate(runtime)
            if t.upper().startswith("RUN ") and "check_distrusted_spki" in t]
    trust = [i for i, t in enumerate(runtime)
             if t.upper().startswith("RUN ") and "update-ca-certificates" in t]
    user = next((i for i, t in enumerate(runtime) if t.upper().startswith("USER ")), None)
    if not copies:
        problems.append("the runtime stage does not COPY scripts/check_distrusted_spki.py")
    if len(runs) != 1:
        return problems + [f"expected exactly one runtime RUN of the SPKI check, found {len(runs)}"]
    run = runs[0]
    if not trust or not (trust[0] < run):
        problems.append("the SPKI check must run after the N-621 trust-store step")
    if user is None or not run < user:
        problems.append("the SPKI check must run as root, before USER")
    if copies and not copies[0] < run:
        problems.append("the script must be COPYed before the RUN that executes it")
    body = runtime[run][4:].strip()
    if not re.fullmatch(r"python -I -S /app/scripts/check_distrusted_spki\.py", body):
        problems.append(f"the RUN must be exactly `python -I -S /app/scripts/check_distrusted_spki.py`, "
                        f"with nothing that can swallow its exit code: {body!r}")
    return problems


def test_the_containerfile_runs_the_spki_check_after_the_trust_store_step():
    assert _runtime_problems(CONTAINERFILE.read_text(encoding="utf-8")) == []


def test_the_containerfile_check_has_teeth():
    text = CONTAINERFILE.read_text(encoding="utf-8")
    run = "RUN python -I -S /app/scripts/check_distrusted_spki.py"
    copy = "COPY scripts/check_distrusted_spki.py /app/scripts/check_distrusted_spki.py"
    assert text.count(run) == 1 and text.count(copy) == 1
    assert _runtime_problems(text.replace(run + "\n", "")), "no RUN"
    assert _runtime_problems(text.replace(copy + "\n", "")), "no COPY"
    assert _runtime_problems(text.replace(run, run + " || true")), "exit code swallowed"
    assert _runtime_problems(text.replace(run, run + "; true")), "exit code swallowed"
    assert _runtime_problems(text.replace(run, "RUN python /app/scripts/check_distrusted_spki.py")), "no -I -S"
    # moved before the trust-store step
    moved = text.replace(run + "\n", "")
    anchor = "RUN python -I -S -c \"import base64, glob, hashlib"
    assert moved.count(anchor) == 1
    assert _runtime_problems(moved.replace(anchor, run + "\n" + anchor)), "before the trust-store step"
    # after USER
    after_user = text.replace(run + "\n", "").replace("USER triage", "USER triage\n" + run, 1)
    assert _runtime_problems(after_user), "after USER"


def test_dockerfile_helper_sees_the_instruction():
    assert any("check_distrusted_spki" in t for _l, t in dockerfile_instructions(
        CONTAINERFILE.read_text(encoding="utf-8")))


# ── 5. fail closed on what the walk cannot read or does not parse (class AI fold) ──


def test_an_unreadable_subdirectory_fails_the_scan(tmp_path, keys, monkeypatch):
    """hipaa-sme SHOULD-1: ``os.walk`` swallows a directory it cannot list unless given
    ``onerror``. Without it a vendored bundle in an unreadable subdirectory is skipped,
    the CApath still supplies the floor of certificates, and the scan exits 0."""
    (tmp_path / "ok.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5))
    locked = tmp_path / "locked"
    locked.mkdir()
    real_scandir = os.scandir

    def flaky_scandir(path="."):
        if os.fspath(path) == str(locked):
            raise PermissionError(13, "Permission denied", str(locked))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", flaky_scandir)
    report = spki.scan([str(tmp_path)], min_certs=1)
    assert not report.ok
    assert any("walk" in e and "locked" in e for e in report.errors), report.errors


def _der_of(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def test_a_der_encoded_cer_is_read_and_a_denied_key_in_it_is_refused(tmp_path, keys):
    """hipaa-sme SHOULD-2: a DER ``.cer``/``.crt`` has no PEM block, so it used to be
    skipped silently. It is parsed now: a denied key in it is refused, a clean one counts."""
    bad_der = _der_of(_make_cert(keys[0], "DER Bad CA", 3))
    (tmp_path / "bad.cer").write_bytes(bad_der)
    (tmp_path / "clean.crt").write_bytes(_der_of(_make_cert(keys[1], "DER Clean CA", 4)))
    denied = {_der_spki_hash(x509.load_der_x509_certificate(bad_der)): "der test key"}
    report = spki.scan([str(tmp_path)], denied=denied, min_certs=1)
    assert report.certificates == 2
    assert [name for _, _, name in report.denied] == ["der test key"]
    assert not report.ok and report.skipped == []


def test_a_corrupt_der_certificate_is_an_error_not_a_pass(tmp_path, keys):
    der = _der_of(_make_cert(keys[1], "DER Clean CA", 4))
    (tmp_path / "cut.cer").write_bytes(der[: len(der) // 2])  # a SEQUENCE running past the data
    report = spki.scan([str(tmp_path)], min_certs=0)
    assert not report.ok and any("cut.cer" in e for e in report.errors), report.errors


def test_a_denied_certificate_after_a_clean_one_in_one_blob_is_an_error_not_a_pass(tmp_path, keys):
    """DA S2 on the class AI fold: only the first certificate in a blob is hashed, so a
    denied one appended to a clean one passed. Bytes after the first certificate are an
    error now, in a DER ``.cer`` and inside one PEM block alike."""
    clean = _der_of(_make_cert(keys[1], "DER Clean CA", 6))
    bad = _der_of(_make_cert(keys[0], "DER Bad CA", 7))
    denied = {_der_spki_hash(x509.load_der_x509_certificate(bad)): "der test key"}
    (tmp_path / "two.cer").write_bytes(clean + bad)
    body = base64.encodebytes(clean + bad)
    (tmp_path / "two.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n" + body + b"-----END CERTIFICATE-----\n")
    report = spki.scan([str(tmp_path)], denied=denied, min_certs=0)
    assert not report.ok
    for name in ("two.cer", "two.pem"):
        assert any(name in e and "not checked" in e for e in report.errors), report.errors


def test_a_certificate_named_file_with_no_certificate_is_listed_not_silent(tmp_path, keys, capsys):
    (tmp_path / "bundle.pem").write_bytes(_make_cert(keys[1], "Clean CA", 5) * spki.MIN_CERTS)
    (tmp_path / "notes.crt").write_text("0 not a certificate, just text\n")
    report = spki.scan([str(tmp_path)])
    assert report.ok and [os.path.basename(p) for p in report.skipped] == ["notes.crt"]
    assert spki.main([str(tmp_path)]) == 0
    assert "notes.crt" in capsys.readouterr().out
