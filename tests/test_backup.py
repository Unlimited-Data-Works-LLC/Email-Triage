"""Tests for the backup/restore module (#65).

Covers:

* Round-trip for both bundle types (build → unbundle → byte-identical
  files).
* Failure modes: wrong passphrase, tampered ciphertext, tampered
  tarball-with-mismatched-manifest, weak passphrase, magic mismatch.
* Toggle behaviour: ``include_master_key``, ``include_tls_certs``,
  ``include_logs`` each gate exactly the file they advertise.
* DB snapshot consistency under concurrent writes.

The module under test is pure-Python (no FastAPI, no CLI), so these
tests stay fast and self-contained -- no fixtures from the web stack.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from email_triage.backup import (
    BundleAuthError,
    BundleFormatError,
    ManifestHashError,
    MAGIC_FULL,
    MAGIC_KEY_ONLY,
    UnbundleResult,
    WeakPassphraseError,
    build_full_bundle,
    build_key_only_bundle,
    unbundle,
    write_unbundled_to_dir,
    _decrypt,
    _encrypt,
    _tar_members,
    _BundleFile,
    _build_manifest,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeSecrets:
    """Minimal SecretsProvider stand-in for tests. Real provider type
    isn't required by the backup module (it just calls .require).
    """

    def __init__(self, store: dict[str, str] | None = None):
        self._store = dict(store or {})

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value

    def list_keys(self) -> list[str]:
        return list(self._store.keys())

    def require(self, key: str) -> str:
        if key not in self._store:
            raise KeyError(key)
        return self._store[key]


def _seed_test_db(path: Path) -> sqlite3.Connection:
    """Create a small DB resembling email-triage's shape (just enough
    so the snapshot path has data + the log_entries pruning has rows
    to act on)."""
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE settings ("
        "  key TEXT PRIMARY KEY, value_json TEXT NOT NULL, "
        "  updated_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE log_entries ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "  ts TEXT NOT NULL, level TEXT, logger TEXT, "
        "  message TEXT, extra_json TEXT"
        ")"
    )
    # Seed a few rows (current + old) so the prune path has something
    # to delete.
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) VALUES "
        "(?, ?, datetime('now'))",
        ("test_setting", '{"value": 42}'),
    )
    conn.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json) "
        "VALUES (datetime('now'), 'INFO', 'test', 'recent', '{}')"
    )
    conn.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json) "
        "VALUES (datetime('now', '-90 days'), 'INFO', 'test', 'old', '{}')"
    )
    conn.commit()
    return conn


def _seed_test_config(path: Path) -> Path:
    path.write_text("classifier:\n  backend: ollama\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Wire-format / encrypt-decrypt round-trip
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    PASSPHRASE = "this-is-a-strong-passphrase-32"

    def test_round_trip_full(self):
        plaintext = b"hello world" * 100
        blob = _encrypt(plaintext, self.PASSPHRASE, MAGIC_FULL)
        assert blob.startswith(MAGIC_FULL)
        assert _decrypt(blob, self.PASSPHRASE, MAGIC_FULL) == plaintext

    def test_round_trip_key_only(self):
        plaintext = b"raw-fernet-key-bytes-base64-shaped-32"
        blob = _encrypt(plaintext, self.PASSPHRASE, MAGIC_KEY_ONLY)
        assert blob.startswith(MAGIC_KEY_ONLY)
        assert _decrypt(blob, self.PASSPHRASE, MAGIC_KEY_ONLY) == plaintext

    def test_wrong_passphrase_raises_auth(self):
        blob = _encrypt(b"x", self.PASSPHRASE, MAGIC_FULL)
        with pytest.raises(BundleAuthError):
            _decrypt(blob, "different-passphrase-here-32", MAGIC_FULL)

    def test_tampered_ciphertext_raises_auth(self):
        blob = _encrypt(b"x" * 200, self.PASSPHRASE, MAGIC_FULL)
        # Flip a byte well past the magic + salt header -- inside the
        # Fernet ciphertext. Fernet's HMAC catches it.
        flipped = bytearray(blob)
        flipped[60] ^= 0xFF
        with pytest.raises(BundleAuthError):
            _decrypt(bytes(flipped), self.PASSPHRASE, MAGIC_FULL)

    def test_truncated_bundle_raises_format(self):
        with pytest.raises(BundleFormatError):
            _decrypt(b"\x00" * 10, self.PASSPHRASE, MAGIC_FULL)

    def test_unrecognised_magic_raises_format(self):
        # 8-byte non-matching magic + valid-shape rest.
        bogus = b"NOPENOPE" + b"\x00" * 16 + b"x" * 100
        with pytest.raises(BundleFormatError):
            _decrypt(bogus, self.PASSPHRASE, expected_magic=MAGIC_FULL)

    def test_magic_mismatch_raises_format(self):
        # Encrypt as full, try to decrypt as key-only.
        blob = _encrypt(b"x", self.PASSPHRASE, MAGIC_FULL)
        with pytest.raises(BundleFormatError):
            _decrypt(blob, self.PASSPHRASE, expected_magic=MAGIC_KEY_ONLY)

    def test_weak_passphrase_rejected_at_build(self):
        with pytest.raises(WeakPassphraseError):
            _encrypt(b"x", "short", MAGIC_FULL)

    def test_empty_passphrase_rejected(self):
        with pytest.raises(WeakPassphraseError):
            _encrypt(b"x", "", MAGIC_FULL)


# ---------------------------------------------------------------------------
# Full-bundle round-trip
# ---------------------------------------------------------------------------

class TestFullBundle:
    PASSPHRASE = "operator-bundle-passphrase-32"

    def _build(
        self, tmp_path, *, include_master_key=False,
        include_tls_certs=True, include_logs=False,
    ):
        db_path = tmp_path / "triage.db"
        conn = _seed_test_db(db_path)
        config_path = _seed_test_config(tmp_path / "email-triage.yaml")
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        cert_dir = data_dir / "certs"
        cert_dir.mkdir()
        (cert_dir / "server.crt").write_bytes(b"--CERT--")
        (cert_dir / "server.key").write_bytes(b"--KEY--")
        (data_dir / "msal_cache.json").write_bytes(b'{"accounts": []}')

        secrets = _FakeSecrets(
            {"ET_MASTER_KEY": "fernet-key-base64-here-32-bytes-padded"},
        )
        try:
            bundle = build_full_bundle(
                db_conn=conn,
                config_path=config_path,
                data_dir=data_dir,
                cert_dir=cert_dir,
                secrets_provider=secrets,
                master_key_name="ET_MASTER_KEY",
                passphrase=self.PASSPHRASE,
                include_master_key=include_master_key,
                include_tls_certs=include_tls_certs,
                include_logs=include_logs,
                operator_email="op@example.com",
                hostname="testhost",
                schema_version=42,
            )
        finally:
            conn.close()
        return bundle

    def test_round_trip_default_flags(self, tmp_path):
        bundle = self._build(tmp_path)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        assert result.bundle_type == "full"
        assert result.manifest["hostname"] == "testhost"
        assert result.manifest["operator_email"] == "op@example.com"
        assert result.manifest["schema_version"] == 42
        # DB + YAML always present.
        assert "triage.db" in result.files
        assert "email-triage.yaml" in result.files
        # Default flags: certs included, master key not, logs not.
        assert "data/certs/server.crt" in result.files
        assert "data/certs/server.key" in result.files
        assert "data/master_key.bin" not in result.files
        # msal_cache included whenever present (no toggle).
        assert "data/msal_cache.json" in result.files

    def test_include_master_key_adds_file(self, tmp_path):
        bundle = self._build(tmp_path, include_master_key=True)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        assert "data/master_key.bin" in result.files
        assert result.manifest["include"]["master_key"] is True

    def test_no_tls_certs_skips_files(self, tmp_path):
        bundle = self._build(tmp_path, include_tls_certs=False)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        assert "data/certs/server.crt" not in result.files
        assert "data/certs/server.key" not in result.files
        assert result.manifest["include"]["tls_certs"] is False

    def test_no_logs_prunes_old_log_entries(self, tmp_path):
        """include_logs=False prunes log_entries rows older than 30
        days from the snapshot. Open the bundled DB to confirm the
        old row is gone."""
        bundle = self._build(tmp_path, include_logs=False)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        # Write the bundled DB to a file + open it.
        snap_path = tmp_path / "extracted.db"
        snap_path.write_bytes(result.files["triage.db"].data)
        conn = sqlite3.connect(str(snap_path))
        try:
            n_old = conn.execute(
                "SELECT COUNT(*) FROM log_entries "
                "WHERE ts < datetime('now', '-30 days')"
            ).fetchone()[0]
            n_recent = conn.execute(
                "SELECT COUNT(*) FROM log_entries "
                "WHERE ts >= datetime('now', '-30 days')"
            ).fetchone()[0]
        finally:
            conn.close()
        assert n_old == 0
        assert n_recent >= 1

    def test_include_logs_keeps_old_entries(self, tmp_path):
        bundle = self._build(tmp_path, include_logs=True)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        snap_path = tmp_path / "extracted.db"
        snap_path.write_bytes(result.files["triage.db"].data)
        conn = sqlite3.connect(str(snap_path))
        try:
            n_old = conn.execute(
                "SELECT COUNT(*) FROM log_entries "
                "WHERE ts < datetime('now', '-30 days')"
            ).fetchone()[0]
        finally:
            conn.close()
        assert n_old >= 1

    def test_wrong_passphrase_on_unbundle(self, tmp_path):
        bundle = self._build(tmp_path)
        with pytest.raises(BundleAuthError):
            unbundle(bundle, passphrase="totally-different-passphrase-32")

    def test_tampered_tarball_with_manifest_mismatch(self, tmp_path):
        """If someone re-encrypts a tar with a swapped file body but
        leaves the original manifest, the per-file SHA-256 check
        catches it. Synthesize that scenario by hand-rolling the
        tar (manifest from one set of files, tarball with a different
        triage.db blob)."""
        # Build a clean bundle so we have a manifest.
        clean = self._build(tmp_path)
        result = unbundle(clean, passphrase=self.PASSPHRASE)
        # Rebuild the tarball with a corrupted DB but the original
        # manifest.
        corrupt_files = list(result.files.values())
        for entry in corrupt_files:
            if entry.path == "triage.db":
                entry.data = b"corrupt-not-a-real-db" * 100
                break
        # Re-encrypt by hand using the lower-level helpers.
        tar_bytes = _tar_members(corrupt_files, result.manifest)
        rebuilt = _encrypt(tar_bytes, self.PASSPHRASE, MAGIC_FULL)
        with pytest.raises(ManifestHashError):
            unbundle(rebuilt, passphrase=self.PASSPHRASE)

    def test_unbundle_writes_files_to_target(self, tmp_path):
        bundle = self._build(tmp_path, include_master_key=True)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        target = tmp_path / "restore"
        written = write_unbundled_to_dir(result, target)
        assert (target / "triage.db").is_file()
        assert (target / "email-triage.yaml").is_file()
        assert (target / "data/master_key.bin").is_file()
        assert "triage.db" in written


# ---------------------------------------------------------------------------
# Key-only round-trip
# ---------------------------------------------------------------------------

class TestKeyOnlyBundle:
    PASSPHRASE = "key-bundle-different-passphrase-32"

    def test_round_trip_includes_key_bytes(self):
        secrets = _FakeSecrets(
            {"ET_MASTER_KEY": "fernet-key-bytes-encoded-base64-32"},
        )
        bundle = build_key_only_bundle(
            secrets_provider=secrets,
            master_key_name="ET_MASTER_KEY",
            passphrase=self.PASSPHRASE,
            operator_email="op@example.com",
            hostname="testhost",
        )
        assert bundle.startswith(MAGIC_KEY_ONLY)
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        assert result.bundle_type == "key-only"
        assert "master_key.bin" in result.files
        assert (
            result.files["master_key.bin"].data
            == b"fernet-key-bytes-encoded-base64-32"
        )
        assert "master_key_sha256" in result.manifest

    def test_wrong_passphrase_raises_auth(self):
        secrets = _FakeSecrets({"ET_MASTER_KEY": "x" * 32})
        bundle = build_key_only_bundle(
            secrets_provider=secrets,
            master_key_name="ET_MASTER_KEY",
            passphrase=self.PASSPHRASE,
        )
        with pytest.raises(BundleAuthError):
            unbundle(bundle, passphrase="some-other-pass-of-correct-len")

    def test_extract_requires_explicit_master_key_out(self, tmp_path):
        secrets = _FakeSecrets({"ET_MASTER_KEY": "x" * 32})
        bundle = build_key_only_bundle(
            secrets_provider=secrets,
            master_key_name="ET_MASTER_KEY",
            passphrase=self.PASSPHRASE,
        )
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        # Default extraction (no master_key_out) refuses: we don't
        # want the raw key landing on a discoverable path.
        from email_triage.backup import BackupError
        with pytest.raises(BackupError):
            write_unbundled_to_dir(result, tmp_path / "restore")
        # With explicit out path, extraction succeeds.
        out_path = tmp_path / "explicit-key-location"
        written = write_unbundled_to_dir(
            result, tmp_path / "restore", master_key_out=out_path,
        )
        assert out_path.is_file()
        assert written["master_key"] == out_path

    def test_cross_format_mismatch_full_bytes_to_key_path(self, tmp_path):
        """Build a full bundle, then assert sniffing it as key-only
        raises BundleFormatError. unbundle() handles dispatch on its
        own; this is the explicit-mismatch low-level path."""
        secrets = _FakeSecrets({"ET_MASTER_KEY": "x" * 32})
        # Make a full bundle.
        db_path = tmp_path / "x.db"
        conn = _seed_test_db(db_path)
        cfg = _seed_test_config(tmp_path / "x.yaml")
        try:
            full = build_full_bundle(
                db_conn=conn,
                config_path=cfg,
                data_dir=tmp_path,
                cert_dir=None,
                secrets_provider=secrets,
                master_key_name="ET_MASTER_KEY",
                passphrase=TestKeyOnlyBundle.PASSPHRASE,
            )
        finally:
            conn.close()
        # Decrypt-as-key-only: explicit magic mismatch.
        with pytest.raises(BundleFormatError):
            _decrypt(
                full,
                TestKeyOnlyBundle.PASSPHRASE,
                expected_magic=MAGIC_KEY_ONLY,
            )


# ---------------------------------------------------------------------------
# DB snapshot consistency under concurrent writes
# ---------------------------------------------------------------------------

class TestSnapshotConsistency:
    PASSPHRASE = "snapshot-consistency-passphrase-32"

    def test_snapshot_runs_under_concurrent_writes(self, tmp_path):
        """SQLite's online backup API + WAL mode should produce a
        consistent on-disk snapshot even while a writer thread is
        inserting rows. The snapshot's row count must equal SOME
        valid intermediate (not torn / not zero / not DBI corrupt)."""
        db_path = tmp_path / "concurrent.db"
        conn = _seed_test_db(db_path)

        # Spawn a writer thread that inserts settings rows steadily.
        stop = threading.Event()
        # Each writer thread needs its own connection -- sqlite3
        # objects aren't safe to share across threads without
        # check_same_thread=False AND careful serialisation.
        writer_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        writer_conn.execute("PRAGMA journal_mode=WAL")
        write_count = {"n": 0}

        def writer():
            while not stop.is_set():
                try:
                    writer_conn.execute(
                        "INSERT INTO settings (key, value_json, updated_at) "
                        "VALUES (?, ?, datetime('now'))",
                        (f"k{write_count['n']}", '{"v": 1}'),
                    )
                    writer_conn.commit()
                    write_count["n"] += 1
                except sqlite3.OperationalError:
                    # Locked momentarily during the snapshot's
                    # incremental copy; retry on next loop.
                    time.sleep(0.001)

        t = threading.Thread(target=writer, daemon=True)
        t.start()
        time.sleep(0.05)  # let writer get going

        cfg = _seed_test_config(tmp_path / "cc.yaml")
        secrets = _FakeSecrets({"ET_MASTER_KEY": "x" * 32})
        try:
            bundle = build_full_bundle(
                db_conn=conn,
                config_path=cfg,
                data_dir=tmp_path,
                cert_dir=None,
                secrets_provider=secrets,
                master_key_name="ET_MASTER_KEY",
                passphrase=self.PASSPHRASE,
                include_logs=True,
            )
        finally:
            stop.set()
            t.join(timeout=2)
            writer_conn.close()
            conn.close()

        # Decrypt + open the snapshotted DB. Should be valid SQLite,
        # not torn, with SOME non-zero row count <= the writer's
        # final count (snapshot caught a moment in time).
        result = unbundle(bundle, passphrase=self.PASSPHRASE)
        snap_path = tmp_path / "snapshot.db"
        snap_path.write_bytes(result.files["triage.db"].data)
        snap_conn = sqlite3.connect(str(snap_path))
        try:
            n = snap_conn.execute(
                "SELECT COUNT(*) FROM settings"
            ).fetchone()[0]
        finally:
            snap_conn.close()
        # 1 seed row + however many the writer got in before snapshot
        # finished. Must be <= 1 + final write_count.
        assert n >= 1
        assert n <= 1 + write_count["n"]


# ---------------------------------------------------------------------------
# Manifest helpers (unit-level)
# ---------------------------------------------------------------------------

class TestManifest:
    def test_build_manifest_shape(self):
        files = [_BundleFile(path="a.txt", data=b"hello")]
        m = _build_manifest(
            bundle_type="full",
            files=files,
            hostname="h",
            operator_email="e",
            commit_sha="c",
            schema_version=1,
            include={"x": True},
        )
        assert m["bundle_type"] == "full"
        assert m["files"][0]["path"] == "a.txt"
        assert m["files"][0]["size"] == 5
        assert m["files"][0]["sha256"]
        assert m["include"] == {"x": True}

    def test_round_trip_tarball(self):
        files = [
            _BundleFile(path="a.txt", data=b"hello"),
            _BundleFile(path="sub/b.txt", data=b"world", mode=0o600),
        ]
        m = _build_manifest(
            bundle_type="full",
            files=files,
            hostname="h",
            operator_email="",
            commit_sha="",
            schema_version=1,
            include={},
        )
        tar = _tar_members(files, m)
        from email_triage.backup import _untar_to_dict
        manifest, fmap = _untar_to_dict(tar)
        assert manifest == m
        assert fmap["a.txt"].data == b"hello"
        assert fmap["sub/b.txt"].data == b"world"
