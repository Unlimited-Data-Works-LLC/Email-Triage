"""Admin-driven backup export + restore (punch-list #65).

Operator-driven on-demand bundle: admin clicks a button, types a
passphrase, downloads an encrypted tarball. CLI inverse path
unpacks it on the recovery target. No cron, no automated off-host
push -- operator manages cadence + storage.

Two complementary bundle types:

* **Full** (``ETBKP01``) -- DB snapshot + YAML + msal_cache + (optional)
  TLS certs + (optional) master key. One passphrase.
* **Key-only** (``ETBKK01``) -- just the Fernet master key bytes,
  separate passphrase. Operator runs both and stores them apart so
  an attacker holding one bundle still can't decrypt the install.

Wire format (both types):

    [ 8-byte magic | 16-byte PBKDF2 salt | Fernet ciphertext over tar.gz ]

Inside the encrypted tarball: a ``manifest.json`` plus the bundled
files. Manifest carries SHA-256 of each member so an unbundle that
gets garbled bytes (passphrase right, tarball wrong) still surfaces
the integrity break.

This module is pure Python: no FastAPI, no CLI imports. Both the
admin route (``web/routers/backup.py``) and the CLI restore
subcommand call into the same code so the two paths stay in lock-
step.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import secrets as _secrets
import sqlite3
import tarfile
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("email_triage.backup")


# ---------------------------------------------------------------------------
# Wire-format constants
# ---------------------------------------------------------------------------

# Magic prefixes -- each fixed at 8 bytes including the trailing null
# so the CLI can sniff bundle type before attempting decryption.
MAGIC_FULL = b"ETBKP01\x00"
MAGIC_KEY_ONLY = b"ETBKK01\x00"
_MAGIC_LEN = 8

# Random salt per export. Written in the clear because PBKDF2 needs
# it on the decrypt side; secrecy comes from the passphrase.
_SALT_LEN = 16

# NIST 2023 minimum for PBKDF2-HMAC-SHA256. Bumping requires a new
# magic version (ETBKP02 / ETBKK02) so older bundles keep decrypting.
_PBKDF2_ITERS = 600_000

# Minimum passphrase length the build path enforces. Operator hygiene;
# UI copy nudges 16+ random chars but the floor is here as belt.
_MIN_PASSPHRASE_LEN = 12

# Bundle format version baked into manifest. Bump when the manifest
# shape changes; restore code branches on this.
_FORMAT_VERSION = 1

# Log retention applied to the snapshot when ``include_logs=False``.
# Trims a chunk of bundle size on installs that have run a while.
_LOG_RETENTION_DAYS = 30


# ---------------------------------------------------------------------------
# Public exception types
# ---------------------------------------------------------------------------

class BackupError(Exception):
    """Base class for backup/restore errors."""


class BundleFormatError(BackupError):
    """Bundle bytes don't carry a recognised magic prefix, or the
    sniffed type doesn't match what the caller expected."""


class BundleAuthError(BackupError):
    """Decryption failed -- wrong passphrase, tampered ciphertext, or
    truncated bundle. The Fernet layer surfaces these uniformly so we
    can't tell a wrong-passphrase from a tamper without leaking info."""


class ManifestHashError(BackupError):
    """Decryption succeeded but a member's SHA-256 doesn't match the
    manifest's recorded hash. Means the tarball was tampered with at
    a layer above Fernet (someone re-encrypted after edit), OR the
    manifest itself was rewritten. Either way: do not trust."""


class WeakPassphraseError(BackupError, ValueError):
    """Operator-supplied passphrase is too short. Inherits ValueError
    so route handlers can catch with a single except."""


# ---------------------------------------------------------------------------
# Internal helpers -- crypto + manifest
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-shaped key from passphrase + salt via PBKDF2.

    Returns the urlsafe-base64-encoded 32 bytes that ``Fernet`` accepts
    directly. Raises ``WeakPassphraseError`` when passphrase is empty
    or shorter than ``_MIN_PASSPHRASE_LEN`` chars.
    """
    if not passphrase or len(passphrase) < _MIN_PASSPHRASE_LEN:
        raise WeakPassphraseError(
            f"Passphrase must be at least {_MIN_PASSPHRASE_LEN} characters "
            f"(got {len(passphrase) if passphrase else 0}).",
        )
    kdf = PBKDF2HMAC(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERS,
    )
    raw = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _encrypt(plaintext: bytes, passphrase: str, magic: bytes) -> bytes:
    """Wrap ``plaintext`` in the bundle wire format: magic + salt +
    Fernet(plaintext). Salt is freshly random per call."""
    salt = _secrets.token_bytes(_SALT_LEN)
    key = _derive_key(passphrase, salt)
    ciphertext = Fernet(key).encrypt(plaintext)
    return magic + salt + ciphertext


def _decrypt(blob: bytes, passphrase: str, expected_magic: bytes | None) -> bytes:
    """Reverse of ``_encrypt``. When ``expected_magic`` is None, accepts
    either bundle type (caller dispatches on the sniffed magic). When
    not None, raises ``BundleFormatError`` on mismatch.

    Raises ``BundleAuthError`` if Fernet decryption fails (wrong
    passphrase, tampered ciphertext, truncation).
    """
    if len(blob) < _MAGIC_LEN + _SALT_LEN:
        raise BundleFormatError("Bundle too short to be a valid export.")
    magic = blob[:_MAGIC_LEN]
    if magic not in (MAGIC_FULL, MAGIC_KEY_ONLY):
        raise BundleFormatError(
            "Unrecognised magic prefix; not an email-triage backup bundle.",
        )
    if expected_magic is not None and magic != expected_magic:
        raise BundleFormatError(
            f"Bundle type mismatch: got {magic!r}, expected {expected_magic!r}.",
        )
    salt = blob[_MAGIC_LEN:_MAGIC_LEN + _SALT_LEN]
    ciphertext = blob[_MAGIC_LEN + _SALT_LEN:]
    key = _derive_key(passphrase, salt)
    try:
        return Fernet(key).decrypt(ciphertext)
    except InvalidToken as e:
        raise BundleAuthError(
            "Decryption failed -- wrong passphrase or tampered bundle.",
        ) from e


def _sniff_bundle_type(blob: bytes) -> str:
    """Return ``"full"`` or ``"key-only"`` based on the magic prefix,
    or raise ``BundleFormatError``. Read-only -- never decrypts."""
    if len(blob) < _MAGIC_LEN:
        raise BundleFormatError("Bundle too short to read magic prefix.")
    magic = blob[:_MAGIC_LEN]
    if magic == MAGIC_FULL:
        return "full"
    if magic == MAGIC_KEY_ONLY:
        return "key-only"
    raise BundleFormatError(
        "Unrecognised magic prefix; not an email-triage backup bundle.",
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# DB snapshot via SQLite online-backup API
# ---------------------------------------------------------------------------

def _snapshot_sqlite(src_conn: sqlite3.Connection) -> bytes:
    """Take a consistent live snapshot of ``src_conn`` and return its
    bytes. Uses ``sqlite3.Connection.backup()`` -- the right tool for
    a WAL-mode DB under concurrent writes; copies pages incrementally
    and never holds an exclusive lock for more than a tick at a time.

    Caller's connection MUST be the one wrapping the live DB; we open
    a destination at a temp path, drive the backup, then read + unlink.
    """
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="et-backup-snapshot-", suffix=".db")
    os.close(tmp_fd)
    try:
        # The destination connection owns the temp file. Backup is page-
        # by-page; default ``pages=-1`` copies the whole DB in one call.
        dst = sqlite3.connect(tmp_path)
        try:
            src_conn.backup(dst)
        finally:
            dst.close()
        return Path(tmp_path).read_bytes()
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass


def _prune_log_entries_in_snapshot(snapshot_bytes: bytes) -> bytes:
    """Apply log-retention pruning to a DB snapshot. Used when the
    operator opts to exclude logs from the bundle -- shrinks size
    without touching the source DB.

    Opens the snapshot at a temp file, deletes ``log_entries`` rows
    older than ``_LOG_RETENTION_DAYS``, runs ``VACUUM``, returns the
    pruned bytes.
    """
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="et-backup-prune-", suffix=".db",
    )
    os.close(tmp_fd)
    try:
        Path(tmp_path).write_bytes(snapshot_bytes)
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute(
                "DELETE FROM log_entries "
                "WHERE ts < datetime('now', ?)",
                (f"-{_LOG_RETENTION_DAYS} days",),
            )
            conn.commit()
            conn.execute("VACUUM")
            conn.commit()
        finally:
            conn.close()
        return Path(tmp_path).read_bytes()
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------

@dataclass
class _BundleFile:
    """One entry inside the bundle's tarball + manifest."""
    path: str          # Tarball-relative path, e.g. "triage.db"
    data: bytes
    mode: int = 0o644

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.data)


def _build_manifest(
    *,
    bundle_type: str,
    files: list[_BundleFile],
    hostname: str,
    operator_email: str,
    commit_sha: str,
    schema_version: int,
    include: dict[str, bool] | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct the manifest dict that ships inside the tarball as
    ``manifest.json``. Per-file SHA-256 lets the restore path detect
    intra-bundle tampering even when the Fernet wrap remains valid
    (e.g. someone re-encrypted with the same passphrase after edit)."""
    from datetime import datetime, timezone
    m: dict[str, Any] = {
        "format_version": _FORMAT_VERSION,
        "bundle_type": bundle_type,
        "schema_version": int(schema_version),
        "hostname": hostname or "",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "operator_email": operator_email or "",
        "commit_sha": commit_sha or "",
        "files": [
            {
                "path": f.path,
                "size": f.size,
                "sha256": f.sha256,
                "mode": f"0{f.mode:o}",
            }
            for f in files
        ],
    }
    if include is not None:
        m["include"] = include
    if extra:
        m.update(extra)
    return m


def _tar_members(files: list[_BundleFile], manifest: dict[str, Any]) -> bytes:
    """Build a gzipped tarball in memory containing the manifest +
    every file in ``files``. Returns the raw tar.gz bytes ready to
    encrypt."""
    buf = io.BytesIO()
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Manifest first so the unbundle path can read it without
        # iterating the whole tar.
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(manifest_bytes))
        for entry in files:
            info = tarfile.TarInfo(name=entry.path)
            info.size = entry.size
            info.mode = entry.mode
            tf.addfile(info, io.BytesIO(entry.data))
    return buf.getvalue()


def _untar_to_dict(tar_bytes: bytes) -> tuple[dict[str, Any], dict[str, _BundleFile]]:
    """Reverse of ``_tar_members``: returns (manifest_dict, files_map).
    files_map keys on ``path``."""
    buf = io.BytesIO(tar_bytes)
    manifest: dict[str, Any] | None = None
    files: dict[str, _BundleFile] = {}
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            data = f.read()
            if member.name == "manifest.json":
                try:
                    manifest = json.loads(data.decode("utf-8"))
                except Exception as e:
                    raise BundleFormatError(
                        f"manifest.json failed to parse: {e}",
                    ) from e
            else:
                files[member.name] = _BundleFile(
                    path=member.name, data=data, mode=member.mode or 0o644,
                )
    if manifest is None:
        raise BundleFormatError("Bundle has no manifest.json.")
    return manifest, files


def _verify_manifest_hashes(
    manifest: dict[str, Any], files: dict[str, _BundleFile],
) -> None:
    """Cross-check every file in the bundle against the manifest's
    recorded SHA-256. Raises ``ManifestHashError`` on any mismatch
    or missing entry."""
    declared = {entry["path"]: entry for entry in manifest.get("files", [])}
    for path, entry in declared.items():
        if path not in files:
            raise ManifestHashError(
                f"Bundle missing file declared in manifest: {path}",
            )
        actual = files[path].sha256
        expected = entry.get("sha256", "")
        if actual != expected:
            raise ManifestHashError(
                f"SHA-256 mismatch for {path}: expected {expected!r}, "
                f"got {actual!r}.",
            )
    # Extra files not declared in manifest are tolerated -- a future
    # bundle format may add files an older restore doesn't know about.


# ---------------------------------------------------------------------------
# Public API -- build
# ---------------------------------------------------------------------------

def build_full_bundle(
    *,
    db_conn: sqlite3.Connection,
    config_path: Path,
    data_dir: Path,
    cert_dir: Path | None,
    secrets_provider,
    master_key_name: str,
    passphrase: str,
    include_master_key: bool = False,
    include_tls_certs: bool = True,
    include_logs: bool = False,
    operator_email: str = "",
    commit_sha: str = "",
    hostname: str = "",
    schema_version: int = 1,
) -> bytes:
    """Build a full backup bundle and return the encrypted bytes.

    See module docstring for the wire format. ``db_conn`` must be the
    live shared connection (snapshot is taken via the SQLite online-
    backup API; concurrent writes are safe).

    ``include_master_key`` defaults to False; the recommended pattern
    is a separate key-only bundle so the two halves live apart. UI
    enforces the trade-off in copy.

    Raises ``WeakPassphraseError`` for short passphrases,
    ``FileNotFoundError`` for missing input files, ``KeyError`` if the
    master key is missing from the secrets backend when
    ``include_master_key=True``.
    """
    config_path = Path(config_path)
    data_dir = Path(data_dir)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config YAML missing: {config_path}")

    # 1. DB snapshot (always present in a full bundle).
    db_bytes = _snapshot_sqlite(db_conn)
    if not include_logs:
        db_bytes = _prune_log_entries_in_snapshot(db_bytes)

    files: list[_BundleFile] = [
        _BundleFile(path="triage.db", data=db_bytes, mode=0o600),
        _BundleFile(
            path="email-triage.yaml",
            data=config_path.read_bytes(),
            mode=0o644,
        ),
    ]

    # 2. Optional msal_cache.json (Office365 token cache).
    msal_path = data_dir / "msal_cache.json"
    if msal_path.is_file():
        files.append(
            _BundleFile(
                path="data/msal_cache.json",
                data=msal_path.read_bytes(),
                mode=0o600,
            )
        )

    # 3. Optional TLS certs.
    if include_tls_certs and cert_dir is not None:
        crt = Path(cert_dir) / "server.crt"
        key = Path(cert_dir) / "server.key"
        if crt.is_file():
            files.append(
                _BundleFile(
                    path="data/certs/server.crt",
                    data=crt.read_bytes(),
                    mode=0o644,
                )
            )
        if key.is_file():
            files.append(
                _BundleFile(
                    path="data/certs/server.key",
                    data=key.read_bytes(),
                    mode=0o600,
                )
            )

    # 4. Optional master key. UI default OFF; key-only path is the
    # recommended pattern. Bundling encourages "single bundle, single
    # passphrase = full access" trade-off the operator opted into.
    if include_master_key:
        key_str = secrets_provider.require(master_key_name)
        files.append(
            _BundleFile(
                path="data/master_key.bin",
                data=key_str.encode("utf-8"),
                mode=0o600,
            )
        )

    # 5. Manifest + tar + encrypt.
    manifest = _build_manifest(
        bundle_type="full",
        files=files,
        hostname=hostname,
        operator_email=operator_email,
        commit_sha=commit_sha,
        schema_version=schema_version,
        include={
            "master_key": include_master_key,
            "tls_certs": include_tls_certs,
            "logs": include_logs,
        },
    )
    tar_bytes = _tar_members(files, manifest)
    return _encrypt(tar_bytes, passphrase, MAGIC_FULL)


def build_key_only_bundle(
    *,
    secrets_provider,
    master_key_name: str,
    passphrase: str,
    operator_email: str = "",
    hostname: str = "",
) -> bytes:
    """Build a key-only bundle and return the encrypted bytes.

    Tiny payload (~hundred bytes encrypted) -- operator can paste the
    base64 of this into a password-manager note, attach to a vault
    entry, etc. The recovery operator pairs it with a separately-stored
    full bundle to reconstruct the install.

    Manifest carries a SHA-256 of the master key bytes for restore-side
    sanity checking ("does this key match the install whose
    secrets_store rows I just decrypted").
    """
    key_str = secrets_provider.require(master_key_name)
    key_bytes = key_str.encode("utf-8")
    files = [
        _BundleFile(path="master_key.bin", data=key_bytes, mode=0o600),
    ]
    manifest = _build_manifest(
        bundle_type="key-only",
        files=files,
        hostname=hostname,
        operator_email=operator_email,
        commit_sha="",
        schema_version=0,  # not relevant for key-only
        include=None,
        extra={"master_key_sha256": _sha256_bytes(key_bytes)},
    )
    tar_bytes = _tar_members(files, manifest)
    return _encrypt(tar_bytes, passphrase, MAGIC_KEY_ONLY)


# ---------------------------------------------------------------------------
# Public API -- unbundle (decrypt + verify)
# ---------------------------------------------------------------------------

@dataclass
class UnbundleResult:
    """Result of decrypting + parsing a bundle. The ``files`` map
    keys on tarball-relative path; ``manifest`` is the parsed JSON."""
    bundle_type: str
    manifest: dict[str, Any]
    files: dict[str, _BundleFile] = field(default_factory=dict)


def unbundle(bundle: bytes, *, passphrase: str) -> UnbundleResult:
    """Decrypt + parse a bundle. Returns the in-memory
    representation; caller decides where to write files (CLI restore
    extracts to a target dir; tests just inspect the dict).

    Raises ``BundleFormatError`` (bad magic / unparseable manifest),
    ``BundleAuthError`` (wrong passphrase / tampered ciphertext), or
    ``ManifestHashError`` (intra-bundle tampering).
    """
    bundle_type = _sniff_bundle_type(bundle)
    expected_magic = MAGIC_FULL if bundle_type == "full" else MAGIC_KEY_ONLY
    tar_bytes = _decrypt(bundle, passphrase, expected_magic)
    manifest, files = _untar_to_dict(tar_bytes)

    declared_type = manifest.get("bundle_type", "")
    if declared_type != bundle_type:
        # Magic and manifest claim different types. Possible if
        # someone re-magic'd a bundle to misdirect; integrity break.
        raise BundleFormatError(
            f"Bundle type sniff mismatch: magic says {bundle_type!r}, "
            f"manifest says {declared_type!r}.",
        )

    _verify_manifest_hashes(manifest, files)
    return UnbundleResult(
        bundle_type=bundle_type, manifest=manifest, files=files,
    )


# ---------------------------------------------------------------------------
# Helpers exposed for the CLI / route layer
# ---------------------------------------------------------------------------

def write_unbundled_to_dir(
    result: UnbundleResult,
    target_dir: Path,
    *,
    master_key_out: Path | None = None,
) -> dict[str, Path]:
    """Write the bundle's files into ``target_dir`` (creating it if
    needed). Each path becomes ``target_dir / <bundle-relative-path>``,
    EXCEPT the master key in a key-only bundle, which requires
    ``master_key_out`` to be set explicitly -- never default to a
    discoverable path.

    Returns a ``{logical_name: written_path}`` map.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    written: dict[str, Path] = {}
    for path, entry in result.files.items():
        if (
            result.bundle_type == "key-only"
            and path == "master_key.bin"
        ):
            if master_key_out is None:
                raise BackupError(
                    "Key-only bundle requires --master-key-out; refusing "
                    "to extract the raw key to a default path.",
                )
            mko = Path(master_key_out)
            mko.parent.mkdir(parents=True, exist_ok=True)
            mko.write_bytes(entry.data)
            try:
                os.chmod(mko, 0o600)
            except (OSError, NotImplementedError):
                # Windows / non-POSIX FS may reject; not a blocker.
                pass
            written["master_key"] = mko
            continue

        out = target_dir / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(entry.data)
        try:
            os.chmod(out, entry.mode)
        except (OSError, NotImplementedError):
            pass
        written[path] = out
    return written
