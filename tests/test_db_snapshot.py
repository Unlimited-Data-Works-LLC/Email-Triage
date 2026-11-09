"""Automated-backup DB-snapshot primitive (punch ).

``snapshot_db_to_path`` takes a consistent, integrity-VERIFIED snapshot and
only atomically lands it AFTER the full integrity gate passes — the
fail-closed contract an automated, unmonitored backup demands
(devils-advocate FATAL #3: 'success' must mean proven-restorable, not
bytes-written). These exercise ONLY the plaintext path. The encrypted
in-app sweeper variant — the real SQLCipher ``PRAGMA
cipher_integrity_check`` branch — is exercised by the sqlcipher-gated
tests in ``tests/test_backup_encrypted_verify.py`` (a real SQLCipher
build is required; they ``importorskip`` where it is absent, e.g. local
Windows, and run on a the deploy host container / sqlcipher CI). The gate logic is
shared, but "shared logic" is not coverage of the encrypted branch —
this module proves only the plaintext path; the encrypted branch is
proven there.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from email_triage import backup as backup_mod


def _make_plaintext_db(path: Path, rows: int = 5) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t (v) VALUES (?)", [(f"r{i}",) for i in range(rows)]
        )
        conn.commit()
    finally:
        conn.close()


def test_snapshot_lands_and_is_restorable(tmp_path):
    src = tmp_path / "live.db"
    _make_plaintext_db(src, rows=7)
    conn = sqlite3.connect(str(src))
    try:
        out = tmp_path / "backups" / "snap.db"
        result = backup_mod.snapshot_db_to_path(conn, out)
    finally:
        conn.close()

    assert out.exists()
    assert result.path == out
    assert result.integrity == "ok"
    assert result.bytes > 0
    assert result.encrypted is False  # plaintext context (no boot stamp)
    # No .partial left masquerading.
    assert not (out.parent / (out.name + ".partial")).exists()
    # The snapshot is a real, queryable DB carrying the source rows.
    rc = sqlite3.connect(str(out))
    try:
        assert rc.execute("SELECT count(1) FROM t").fetchone()[0] == 7
    finally:
        rc.close()


def test_snapshot_fails_closed_on_corruption(tmp_path, monkeypatch):
    """A snapshot whose bytes are garbage (a truncated / torn backup) MUST
    fail the integrity gate, raise BackupError, and leave NO file (neither
    the target nor the .partial) masquerading as a good backup."""
    src = tmp_path / "live.db"
    _make_plaintext_db(src)
    conn = sqlite3.connect(str(src))

    monkeypatch.setattr(
        backup_mod, "_snapshot_sqlite", lambda _c: b"this is not a database"
    )
    out = tmp_path / "backups" / "snap.db"
    try:
        with pytest.raises(backup_mod.BackupError):
            backup_mod.snapshot_db_to_path(conn, out)
    finally:
        conn.close()

    assert not out.exists()
    assert not (out.parent / (out.name + ".partial")).exists()


def test_snapshot_sha256_matches_written_bytes(tmp_path):
    src = tmp_path / "live.db"
    _make_plaintext_db(src, rows=3)
    conn = sqlite3.connect(str(src))
    try:
        out = tmp_path / "snap.db"
        result = backup_mod.snapshot_db_to_path(conn, out)
    finally:
        conn.close()

    import hashlib
    assert result.sha256 == hashlib.sha256(out.read_bytes()).hexdigest()
    assert result.bytes == out.stat().st_size


# --- retention / marker (phase 2 pure helpers) -----------------------------


def _touch_snapshot(directory: Path, ts: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / backup_mod.snapshot_filename(ts)
    p.write_bytes(b"x")
    return p


def test_list_snapshots_newest_first_ignores_partial_and_marker(tmp_path):
    _touch_snapshot(tmp_path, "20260101T000000Z")
    _touch_snapshot(tmp_path, "20260301T000000Z")
    _touch_snapshot(tmp_path, "20260201T000000Z")
    # Noise that must be ignored.
    (tmp_path / (backup_mod.snapshot_filename("20260401T000000Z") + ".partial")).write_bytes(b"x")
    (tmp_path / backup_mod.BACKUP_MARKER_NAME).write_text("{}")

    names = [p.name for p in backup_mod.list_db_snapshots(tmp_path)]
    assert names == [
        "triage-db-20260301T000000Z.db",
        "triage-db-20260201T000000Z.db",
        "triage-db-20260101T000000Z.db",
    ]


def test_prune_keeps_newest_n_by_embedded_ts(tmp_path):
    for ts in (
        "20260101T000000Z", "20260102T000000Z", "20260103T000000Z",
        "20260104T000000Z", "20260105T000000Z",
    ):
        _touch_snapshot(tmp_path, ts)

    deleted = backup_mod.prune_db_snapshots(tmp_path, keep=2)
    assert {p.name for p in deleted} == {
        "triage-db-20260101T000000Z.db",
        "triage-db-20260102T000000Z.db",
        "triage-db-20260103T000000Z.db",
    }
    survivors = [p.name for p in backup_mod.list_db_snapshots(tmp_path)]
    assert survivors == [
        "triage-db-20260105T000000Z.db",
        "triage-db-20260104T000000Z.db",
    ]


def test_prune_keeps_all_when_fewer_than_n(tmp_path):
    _touch_snapshot(tmp_path, "20260101T000000Z")
    _touch_snapshot(tmp_path, "20260102T000000Z")
    assert backup_mod.prune_db_snapshots(tmp_path, keep=14) == []
    assert len(backup_mod.list_db_snapshots(tmp_path)) == 2


def test_marker_round_trip(tmp_path):
    src = tmp_path / "live.db"
    _make_plaintext_db(src, rows=2)
    conn = sqlite3.connect(str(src))
    try:
        out = tmp_path / "snaps" / backup_mod.snapshot_filename("20260617T031500Z")
        result = backup_mod.snapshot_db_to_path(conn, out)
    finally:
        conn.close()

    backup_mod.write_backup_marker(out.parent, result, ts="20260617T031500Z")
    marker = backup_mod.read_backup_marker(out.parent)
    assert marker is not None
    assert marker["ts"] == "20260617T031500Z"
    assert marker["file"] == out.name
    assert marker["sha256"] == result.sha256
    assert marker["bytes"] == result.bytes
    assert marker["integrity"] == "ok"


def test_read_marker_absent_is_none(tmp_path):
    assert backup_mod.read_backup_marker(tmp_path) is None


# --- retention spec (count / days / weeks) + both formats -------------------


def test_parse_retention_spec():
    assert backup_mod.parse_retention_spec(14) == ("count", 14)
    assert backup_mod.parse_retention_spec("14") == ("count", 14)
    assert backup_mod.parse_retention_spec("14d") == ("age_days", 14)
    assert backup_mod.parse_retention_spec("2w") == ("age_days", 14)
    assert backup_mod.parse_retention_spec("3W") == ("age_days", 21)


def test_snapshot_filename_both_formats():
    assert backup_mod.snapshot_filename("20260617T000000Z", "db").endswith(".db")
    assert backup_mod.snapshot_filename("20260617T000000Z", "etbk").endswith(".etbk")


def test_list_and_prune_cover_both_formats(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    for ts, fmt in [
        ("20260101T000000Z", "db"), ("20260102T000000Z", "etbk"),
        ("20260103T000000Z", "db"),
    ]:
        (tmp_path / backup_mod.snapshot_filename(ts, fmt)).write_bytes(b"x")
    names = [p.name for p in backup_mod.list_db_snapshots(tmp_path)]
    assert names == [
        "triage-db-20260103T000000Z.db",
        "triage-db-20260102T000000Z.etbk",
        "triage-db-20260101T000000Z.db",
    ]
    deleted = backup_mod.prune_backups(tmp_path, 2)  # count
    assert {p.name for p in deleted} == {"triage-db-20260101T000000Z.db"}


def test_prune_backups_age_days(tmp_path):
    from datetime import datetime, timezone
    tmp_path.mkdir(exist_ok=True)
    for ts in ("20260101T000000Z", "20260110T000000Z", "20260115T000000Z"):
        (tmp_path / backup_mod.snapshot_filename(ts, "etbk")).write_bytes(b"x")
    # "Now" = 2026-01-16; keep <= 7 days → only the 01-01 + 01-10 fall outside?
    # cutoff = 01-09; 01-01 (<cutoff) deleted, 01-10 + 01-15 kept.
    now = datetime(2026, 1, 16, tzinfo=timezone.utc)
    deleted = backup_mod.prune_backups(tmp_path, "7d", now=now)
    assert {p.name for p in deleted} == {"triage-db-20260101T000000Z.etbk"}
    survivors = {p.name for p in backup_mod.list_db_snapshots(tmp_path)}
    assert survivors == {
        "triage-db-20260110T000000Z.etbk",
        "triage-db-20260115T000000Z.etbk",
    }


def test_run_status_round_trip(tmp_path):
    backup_mod.write_run_status(
        tmp_path, outcome="failure", ts="20260617T031500Z", fmt="etbk",
        error="OllamaDown",
    )
    st = backup_mod.read_run_status(tmp_path)
    assert st["outcome"] == "failure"
    assert st["error"] == "OllamaDown"
    assert st["format"] == "etbk"
    assert backup_mod.read_run_status(tmp_path / "nope") is None


def test_marker_carries_key_fpr(tmp_path):
    src = tmp_path / "live.db"
    _make_plaintext_db(src, rows=1)
    conn = sqlite3.connect(str(src))
    try:
        out = tmp_path / backup_mod.snapshot_filename("20260617T031500Z", "db")
        result = backup_mod.snapshot_db_to_path(conn, out)
    finally:
        conn.close()
    backup_mod.write_backup_marker(out.parent, result, ts="20260617T031500Z", key_fpr="abc123")
    assert backup_mod.read_backup_marker(out.parent)["key_fpr"] == "abc123"


def test_key_export_marker_round_trip(tmp_path):
    # Absent → None (which is exactly the "no restore key on record" state the
    # health surfaces flag).
    assert backup_mod.read_key_export_marker(tmp_path) is None
    backup_mod.write_key_export_marker(tmp_path, ts="2026-06-17T12:00:00Z")
    km = backup_mod.read_key_export_marker(tmp_path)
    assert km["ts"] == "2026-06-17T12:00:00Z"


# --- public-key (write-only) backup mode -----------------------------------


def _gen_x25519_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def test_pubkey_seal_unseal_roundtrip():
    priv, pub = _gen_x25519_keypair()
    sealed = backup_mod.seal_to_pubkey(b"hello-secret", pub)
    assert backup_mod.unseal_with_privkey(sealed, priv) == b"hello-secret"


def test_pubkey_seal_wrong_private_key_fails():
    _priv1, pub1 = _gen_x25519_keypair()
    priv2, _pub2 = _gen_x25519_keypair()
    sealed = backup_mod.seal_to_pubkey(b"x", pub1)
    with pytest.raises(backup_mod.BundleAuthError):
        backup_mod.unseal_with_privkey(sealed, priv2)


def test_cipher_check_clean_convention():
    """REGRESSION (operator hit it LIVE 2026-06-18 on the encrypted prod DB):
    SQLCipher's PRAGMA cipher_integrity_check returns NO rows when the DB is
    clean (NO 'ok' sentinel — that's the plain integrity_check). The verify gate
    wrongly required a single ('ok',) row, so it rejected EVERY clean encrypted
    snapshot ('cipher_integrity_check is not clean: []'), failing the automated
    backup closed on all encrypted installs. Clean ⇔ empty result."""
    assert backup_mod._cipher_check_clean([]) is True          # clean = no rows
    assert backup_mod._cipher_check_clean(
        [("HMAC verification failed for page 4",)]) is False    # a fault row
    assert backup_mod._cipher_check_clean(
        [("page 240 has an invalid size of 1 bytes",)]) is False
    # cipher_integrity_check NEVER emits an 'ok' row; if any row appears at all
    # it's a fault (do not resurrect the integrity_check 'ok'-row convention).
    assert backup_mod._cipher_check_clean([("ok",)]) is False


def test_validate_public_key_pem_accepts_x25519():
    """The config-time gate accepts a real X25519 public key."""
    _priv, pub = _gen_x25519_keypair()
    backup_mod.validate_public_key_pem(pub)  # must not raise


def test_validate_public_key_pem_rejects_garbage():
    with pytest.raises(backup_mod.BackupError):
        backup_mod.validate_public_key_pem(b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----")


def test_validate_public_key_pem_rejects_wrong_key_type():
    """An RSA / non-X25519 PEM parses but is the WRONG key type → rejected, so
    public-key backup mode can't be armed against an unusable key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(backup_mod.BackupError):
        backup_mod.validate_public_key_pem(ec_pub)


def test_pubkey_sealed_etbk_full_roundtrip(tmp_path):
    import base64
    import os as _os

    priv, pub = _gen_x25519_keypair()
    rand_pp = base64.urlsafe_b64encode(_os.urandom(24)).decode("ascii")
    bundle = _build_plaintext_etbk(tmp_path, rand_pp)
    out = tmp_path / "backups" / backup_mod.snapshot_filename("20260617T000000Z", "etbk")

    result = backup_mod.write_verified_pubkey_etbk(
        bundle, passphrase=rand_pp, public_key_pem=pub, out_path=out, encrypted=False
    )
    assert out.exists() and result.integrity == "ok"
    landed = out.read_bytes()
    assert backup_mod.is_pubkey_sealed(landed)

    # Restore with the OFF-BOX private key: unwrap → unbundle → inner DB present.
    inner, recovered_pp = backup_mod.unwrap_pubkey_sealed_etbk(landed, priv)
    assert recovered_pp == rand_pp
    res = backup_mod.unbundle(inner, passphrase=recovered_pp)
    assert "triage.db" in res.files

    # A different (wrong) private key cannot unwrap the landed backup.
    wrong_priv, _ = _gen_x25519_keypair()
    with pytest.raises(backup_mod.BundleAuthError):
        backup_mod.unwrap_pubkey_sealed_etbk(landed, wrong_priv)


def test_pubkey_unwrap_framing_fails_closed():
    # Crypto-review regression pins: every malformed ETBKP02 framing must fail
    # CLOSED at the unwrap parser (before the private key is even used).
    pk = backup_mod.MAGIC_PUBKEY
    # not a pubkey-sealed bundle
    with pytest.raises(backup_mod.BundleFormatError):
        backup_mod.unwrap_pubkey_sealed_etbk(b"NOTMAGIC" + b"x" * 40, b"dummy")
    # no length header
    with pytest.raises(backup_mod.BundleFormatError):
        backup_mod.unwrap_pubkey_sealed_etbk(pk, b"dummy")
    # length header claims more sealed bytes than present
    with pytest.raises(backup_mod.BundleFormatError):
        backup_mod.unwrap_pubkey_sealed_etbk(
            pk + (100).to_bytes(4, "big") + b"short", b"dummy"
        )
    # sealed present but EMPTY inner
    with pytest.raises(backup_mod.BundleFormatError):
        backup_mod.unwrap_pubkey_sealed_etbk(
            pk + (4).to_bytes(4, "big") + b"abcd", b"dummy"
        )


def test_pubkey_inner_splice_fails_closed_at_unbundle(tmp_path):
    # An attacker who splices a DIFFERENT inner ETBKP01 behind a valid sealed
    # header gets the ORIGINAL passphrase from the unwrap, but the spliced inner
    # was encrypted under a different passphrase → unbundle fails CLOSED (DoS on
    # that one tampered file; no accepted-integrity break). Per the crypto review.
    import base64
    import os as _os

    priv, pub = _gen_x25519_keypair()
    d1 = tmp_path / "one"
    d1.mkdir()
    d2 = tmp_path / "two"
    d2.mkdir()
    pp1 = base64.urlsafe_b64encode(_os.urandom(24)).decode("ascii")
    bundle1 = _build_plaintext_etbk(d1, pp1)
    out = tmp_path / "a.etbk"
    backup_mod.write_verified_pubkey_etbk(
        bundle1, passphrase=pp1, public_key_pem=pub, out_path=out, encrypted=False
    )
    pp2 = base64.urlsafe_b64encode(_os.urandom(24)).decode("ascii")
    bundle2 = _build_plaintext_etbk(d2, pp2)

    landed = out.read_bytes()
    off = backup_mod._MAGIC_LEN
    slen = int.from_bytes(landed[off:off + 4], "big")
    spliced = landed[: off + 4 + slen] + bundle2  # keep header, swap inner

    inner, recovered_pp = backup_mod.unwrap_pubkey_sealed_etbk(spliced, priv)
    assert recovered_pp == pp1
    with pytest.raises((backup_mod.BundleAuthError, backup_mod.BundleFormatError)):
        backup_mod.unbundle(inner, passphrase=recovered_pp)


# --- .etbk path: passphrase derivation + restorability gate ----------------


def test_derive_etbk_passphrase_clears_floor_and_is_deterministic():
    pp1 = backup_mod.derive_etbk_passphrase("master-key-bytes-xyz")
    pp2 = backup_mod.derive_etbk_passphrase("master-key-bytes-xyz")
    assert pp1 == pp2  # deterministic from the key
    assert len(pp1) >= backup_mod._MIN_PASSPHRASE_LEN  # clears build_full_bundle's floor
    # A different key → a different passphrase.
    assert backup_mod.derive_etbk_passphrase("other-key") != pp1
    # The passphrase is NOT the key fingerprint (distinct HKDF info strings).
    assert pp1 != backup_mod.master_key_fingerprint("master-key-bytes-xyz")


def test_master_key_fingerprint_nonsecret_deterministic():
    fpr = backup_mod.master_key_fingerprint("master-key-bytes-xyz")
    assert fpr == backup_mod.master_key_fingerprint("master-key-bytes-xyz")
    assert "master-key-bytes-xyz" not in fpr  # not the key
    assert len(fpr) == 32  # 16 bytes hex
    assert backup_mod.master_key_fingerprint("other-key") != fpr


def _build_plaintext_etbk(tmp_path, passphrase: str) -> bytes:
    """A minimal full bundle (DB + yaml, no certs/key) for a plaintext DB."""
    src = tmp_path / "live.db"
    _make_plaintext_db(src, rows=4)
    cfg = tmp_path / "email-triage.yaml"
    cfg.write_text("# test config\n", encoding="utf-8")

    class _Stub:
        def require(self, name):  # only called when include_master_key=True
            return "unused"

    conn = sqlite3.connect(str(src))
    try:
        return backup_mod.build_full_bundle(
            db_conn=conn,
            config_path=cfg,
            data_dir=tmp_path,
            cert_dir=None,
            secrets_provider=_Stub(),
            master_key_name="x",
            passphrase=passphrase,
            include_master_key=False,
            include_tls_certs=False,
            include_logs=True,
        )
    finally:
        conn.close()


def test_write_verified_etbk_roundtrip(tmp_path):
    pp = backup_mod.derive_etbk_passphrase("k" * 20)
    bundle = _build_plaintext_etbk(tmp_path, pp)
    out = tmp_path / "backups" / "triage-backup-20260617T031500Z.etbk"
    result = backup_mod.write_verified_etbk(
        bundle, passphrase=pp, out_path=out, encrypted=False
    )
    assert out.exists()
    assert result.integrity == "ok"
    assert result.bytes == out.stat().st_size
    assert not (out.parent / (out.name + ".partial")).exists()
    # The landed bundle still round-trips (the inner DB carries the rows).
    res = backup_mod.unbundle(out.read_bytes(), passphrase=pp)
    assert "triage.db" in res.files


def test_write_verified_etbk_fails_closed_on_corrupt_inner_db(tmp_path, monkeypatch):
    pp = backup_mod.derive_etbk_passphrase("k" * 20)
    bundle = _build_plaintext_etbk(tmp_path, pp)
    # Simulate the inner DB failing the strong restorability gate.
    def _boom(_p):
        raise backup_mod.BackupError("inner DB integrity_check failed")
    monkeypatch.setattr(backup_mod, "_verify_snapshot_file", _boom)
    out = tmp_path / "backups" / "bad.etbk"
    with pytest.raises(backup_mod.BackupError):
        backup_mod.write_verified_etbk(bundle, passphrase=pp, out_path=out, encrypted=False)
    assert not out.exists()
    assert not (out.parent / (out.name + ".partial")).exists()
