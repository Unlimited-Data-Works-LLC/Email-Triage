"""Admin-driven backup export + restore (the backlog ).

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

from email_triage._errfmt import fmt_exc
from email_triage._isotime import now_utc_iso
from email_triage.triage_logging import get_logger  # N-196b R21_4

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
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey as _X25519PrivateKey,
    X25519PublicKey as _X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = get_logger("email_triage.backup")  # N-196b R21_4

# HKDF info for the AUTOMATED .etbk bundle passphrase, derived from the master
# key. DISTINCT from the audit-chain HMAC subkey info
# (b"email_triage/audit/log_chain/hmac/v1", secrets.py) — RFC 5869 §3.1
# domain separation means this is NOT key-reuse vs the audit subkey. The
# automated job has no human to type a passphrase; deriving from the master key
# keeps the snapshot SHARE-compromise-safe (the key never lands on the share)
# with no new stored secret. A master-key rotation orphans prior bundles — the
# marker's key fingerprint makes that detectable rather than a silent failure.
_ETBK_PASSPHRASE_HKDF_INFO = b"email_triage/backup/etbk/passphrase/v1"


# ---------------------------------------------------------------------------
# Wire-format constants
# ---------------------------------------------------------------------------

# Magic prefixes -- each fixed at 8 bytes including the trailing null
# so the CLI can sniff bundle type before attempting decryption.
MAGIC_FULL = b"ETBKP01\x00"
MAGIC_KEY_ONLY = b"ETBKK01\x00"
#  public-key mode (operator-chosen): a full ETBKP01 bundle whose random
# passphrase is SEALED to an X25519 PUBLIC key. The container holds only the
# public key (write-only backups); only the off-box PRIVATE key can restore.
MAGIC_PUBKEY = b"ETBKP02\x00"
_MAGIC_LEN = 8
# Domain-separated from every other HKDF use (audit subkey, etbk passphrase).
_PUBKEY_SEAL_HKDF_INFO = b"email_triage/backup/pubkey-seal/v1"

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


class ArtifactClashError(BackupError):
    """Two on-disk artifacts with the same bundle name hold DIFFERENT bytes
    (punch 432, panel Z SHOULD-Z1-3). The collector cannot know which one is
    this install's file, and bundling either may put another install's token
    under this install's account id, so the bundle is refused (fail closed).
    The message names both paths."""


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


def _sha256_file(path: Path) -> str:
    """Streamed SHA-256 of a file — used for the snapshot marker + the
    host-side readback verify; chunked so a large snapshot doesn't spike
    memory (the whole-file ``read_bytes`` path is the reliability cliff
    db-sme flagged)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
        #
        # N-18 (encryption-at-rest): on an encrypted install ``src_conn`` is a
        # ``sqlcipher3`` connection. A plaintext ``sqlite3.connect`` destination
        # here would (a) write a DECRYPTED copy of the whole PHI DB to /tmp
        # (§164.312(a)(2)(iv) at-rest leak) and (b) fail the unsupported
        # cross-binding ``sqlcipher3 -> sqlite3`` backup. ``open_dedicated_conn``
        # self-selects from the boot-stamped context: encrypted installs get a
        # SQLCipher destination keyed with the SAME storage key as the live DB
        # (PRAGMA key first), so the snapshot temp file — and the bytes bundled —
        # stay encrypted at rest. Restore is byte-verbatim
        # (``write_unbundled_to_dir``), so an encrypted install reopens the
        # encrypted snapshot with its master key: the backup<->restore symmetry
        # holds. Plaintext installs keep the exact stdlib path.
        # the backlog  (Census v3 #8) — SSOT ``open_dedicated_conn``
        # handles both encrypted + plaintext arms with the full
        # init_db arg set (timeout=30.0, check_same_thread=False,
        # cached_statements=0). Pre-fix hand-rolled branch dropped
        # every one of those args on the plaintext side.
        from email_triage.db._engine import open_dedicated_conn
        dst = open_dedicated_conn(tmp_path)
        try:
            src_conn.backup(dst)
        finally:
            dst.close()
        return Path(tmp_path).read_bytes()
    finally:
        # N-18: remove the temp DB *and* its WAL/SHM sidecars. The opener runs
        # in WAL mode, so a ``-wal``/``-shm`` pair is created next to the temp
        # file; unlinking only the main file would leave plaintext PHI pages
        # (plaintext install) or SQLCipher pages (encrypted install) behind.
        for _ext in ("", "-wal", "-shm"):
            try:
                Path(tmp_path + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                # ERROR, path in the TEXT: a kwarg ``path=`` is blanked by
                # the persisted-key allow-list. A mkstemp name, never a
                # mailbox path: not PHI.
                logger.error(
                    f"snapshot temp cleanup failed; plaintext pages may "
                    f"remain on disk at {tmp_path + _ext}",
                    exc_info=_swallow_exc,
                )


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
        # N-18: on an encrypted install ``snapshot_bytes`` are SQLCipher-
        # encrypted (see _snapshot_sqlite). Open with the encrypted opener, or
        # the prune both fails to read the file AND a plaintext re-open would
        # re-leak the PHI. Plaintext installs keep the stdlib path. The pruned
        # file stays encrypted, so the bundled bytes never land plaintext-at-rest.
        from email_triage.db._engine import (
            open_dedicated_conn,
        )
        # the backlog  (Census v3 #8) — SSOT route (same rationale
        # as _snapshot_sqlite site above).
        conn = open_dedicated_conn(tmp_path)
        try:
            # The funnel reads rows by column name (the dbapi-matched Row).
            from email_triage.db._helpers import apply_compatible_row_factory
            apply_compatible_row_factory(conn)
            # Panel P F8: the live prune funnel, which captures the new chain
            # head into ``audit:chain_anchor`` in the same transaction. The raw
            # DELETE this replaces skipped the anchor, so ``audit verify --db``
            # on the backup copy broke at its new head. Age axis only, as
            # before: the count axis is disabled with the largest SQLite LIMIT.
            from email_triage.db.audit import prune_log_entries_by_age_and_count
            prune_log_entries_by_age_and_count(
                conn, retention_days=_LOG_RETENTION_DAYS, max_rows=2**63 - 1,
            )
            conn.execute("VACUUM")
            conn.commit()
        finally:
            conn.close()
        return Path(tmp_path).read_bytes()
    finally:
        # N-18: remove the temp DB *and* its WAL/SHM sidecars (see _snapshot_sqlite).
        for _ext in ("", "-wal", "-shm"):
            try:
                Path(tmp_path + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                # ERROR, path in the TEXT: a kwarg ``path=`` is blanked by
                # the persisted-key allow-list. A mkstemp name, never a
                # mailbox path: not PHI.
                logger.error(
                    f"snapshot temp cleanup failed; plaintext pages may "
                    f"remain on disk at {tmp_path + _ext}",
                    exc_info=_swallow_exc,
                )


# ---------------------------------------------------------------------------
# Standalone DB snapshot — the automated-backup primitive (punch )
# ---------------------------------------------------------------------------

@dataclass
class SnapshotResult:
    """Outcome of :func:`snapshot_db_to_path`. PHI-free — safe to log/audit
    (no DB contents; ``path`` is the install's own backup target)."""
    path: Path
    bytes: int
    sha256: str
    encrypted: bool
    integrity: str  # always "ok" on success (the fn raises otherwise)


def _cipher_check_clean(faults: list) -> bool:
    """True iff SQLCipher's ``PRAGMA cipher_integrity_check`` reports the DB clean.

    SQLCipher returns **NO rows** when the database is externally consistent —
    there is NO ``("ok",)`` sentinel row (that convention belongs to the plain
    ``PRAGMA integrity_check``). Any row(s) are per-page HMAC/size faults. So
    clean ⇔ empty result. (Verified against the Zetetic SQLCipher API docs +
    ``sqlcipher/test/pragma.test``; an earlier check mis-applied the
    ``integrity_check`` "ok"-row convention here, rejecting EVERY clean encrypted
    snapshot — the automated backup's restorability gate then failed closed on
    every encrypted install. Operator hit it 2026-06-18 after the positional-arg
    fix first let the etbk verify run.)"""
    return not faults


def _verify_snapshot_file(path: Path) -> str:
    """Prove a just-written snapshot is RESTORABLE, not merely written.

    Reopens ``path`` through the encryption-aware :func:`open_dedicated_conn`
    (self-selects SQLCipher vs plaintext from the stamped boot context) and
    runs the same gate the migration pre-swap path uses (db/_migrate.py): a
    per-page MAC check on encrypted installs PLUS a FULL ``PRAGMA
    integrity_check`` PLUS a sentinel ``sqlite_master`` read.
    ``cipher_integrity_check`` alone is necessary-not-sufficient — a
    structurally corrupt but MAC-valid snapshot from an interrupted backup
    passes it (devils-advocate FATAL #3). Returns ``"ok"`` or raises
    :class:`BackupError`. Any open/query failure (e.g. a torn/garbage file)
    is normalised to ``BackupError`` so the caller fails closed uniformly.
    Cleans the WAL/SHM sidecars the verify open creates.
    """
    from email_triage.db._engine import (
        dedicated_conn_is_encrypted,
        open_dedicated_encrypted_conn_readish,
    )

    encrypted = dedicated_conn_is_encrypted()
    conn = None
    try:
        # the backlog  (Census v3 #8) — SSOT
        # ``open_dedicated_conn_readish`` handles both arms with the
        # full init_db argument set. RO intent + no WAL pragma
        # requirement preserved (integrity_check needs no WAL).
        from email_triage.db._engine import open_dedicated_conn_readish
        conn = open_dedicated_conn_readish(str(path))
        if encrypted:
            faults = conn.execute("PRAGMA cipher_integrity_check").fetchall()
            if not _cipher_check_clean(faults):
                raise BackupError(
                    f"Snapshot cipher_integrity_check found fault(s): "
                    f"{faults[:3]!r} — snapshot is not trustworthy."
                )
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        if not (len(rows) == 1 and rows[0][0] == "ok"):
            raise BackupError(
                f"Snapshot PRAGMA integrity_check != ok: {rows[:3]!r}"
            )
        # Sentinel read — proves the schema B-tree is actually traversable.
        conn.execute("SELECT count(1) FROM sqlite_master").fetchone()
    except BackupError:
        raise
    except Exception as e:
        raise BackupError(
            f"Snapshot failed integrity verification (did not open as a "
            f"valid database): {e}"
        ) from e
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as _swallow_exc:
                logger.debug(
                    "verify connection close failed",
                    error=fmt_exc(_swallow_exc),
                )
        for _ext in ("-wal", "-shm"):
            try:
                Path(str(path) + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                # ERROR, path in the TEXT (kwarg ``path=`` is blanked by the
                # persisted-key allow-list). The verify temp sits beside the
                # backup destination: an operator-configured dir, not PHI.
                logger.error(
                    f"verify temp sidecar cleanup failed; plaintext pages may "
                    f"remain on disk at {str(path) + _ext}",
                    exc_info=_swallow_exc,
                )
    return "ok"


def snapshot_db_to_path(
    db_conn: sqlite3.Connection, out_path: Path | str,
) -> SnapshotResult:
    """Take a consistent, integrity-VERIFIED snapshot of the live DB and
    atomically place it at ``out_path``. The automated-backup primitive
    (punch ) — distinct from the ``.etbk`` bundle: a RAW encrypted
    ``triage.db`` restorable by file-swap + the separately-held master key.

    FAIL-CLOSED (Prime Directive #8): the snapshot is written to a
    ``.partial`` sibling, integrity-verified, and only then atomically
    renamed into place. ANY integrity failure removes the partial and raises
    :class:`BackupError` — a half / un-verified snapshot is NEVER left
    masquerading as a good backup.

    The snapshot inherits the encrypted-vs-plaintext destination from the
    stamped boot context (the running server stamps it at boot via
    ``web/app.py``'s ``set_dedicated_conn_encryption``; a headless caller
    MUST call ``_cli_stamp_db_encryption`` first) — so on an encrypted
    install the snapshot is SQLCipher ciphertext, never a plaintext leak
    (N-18). Reuses :func:`_snapshot_sqlite` (online-backup API, WAL-safe,
    temp-sidecar cleanup); ``db_conn.backup()`` only READS the source, so
    the live writer is untouched.
    """
    from email_triage.db._engine import dedicated_conn_is_encrypted

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    encrypted = dedicated_conn_is_encrypted()

    snap = _snapshot_sqlite(db_conn)

    # N-210b R23 (2026-07-02): route through _atomicio SSOT with
    # `pre_replace=` verify callback. Prior hand-rolled sequence was correct
    # (chmod BEFORE replace + verify-before-replace) but duplicated the
    # atomic-write logic; a future editor copying the pattern without the
    # chmod-before-swap would regress a §164.312(a)(1) PHI-material control.
    from email_triage._atomicio import atomic_write_bytes
    integrity = None
    def _verify_then_swap(tmp_path: Path) -> None:
        nonlocal integrity
        integrity = _verify_snapshot_file(tmp_path)  # raises on any fault
    tmp = out_path.with_name(out_path.name + ".partial")
    try:
        atomic_write_bytes(out_path, snap, mode=0o600, pre_replace=_verify_then_swap)
    except BaseException:
        # Fail-closed: never leave a partial / WAL / SHM sidecars behind.
        for _ext in ("-wal", "-shm"):
            try:
                Path(str(tmp) + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                logger.warning(
                    "partial snapshot sidecar cleanup failed",
                    error=fmt_exc(_swallow_exc),
                )
        raise

    # sha256/size describe the LANDED artifact (the marker + the host-side
    # readback verify compare against these), computed after the verify open
    # may have touched the file's WAL header.
    return SnapshotResult(
        path=out_path, bytes=out_path.stat().st_size,
        sha256=_sha256_file(out_path),
        encrypted=encrypted, integrity=integrity,
    )


# ---------------------------------------------------------------------------
# Snapshot set: naming, retention, freshness marker (punch  phase 2)
# ---------------------------------------------------------------------------

_SNAPSHOT_PREFIX = "triage-db-"
_SNAPSHOT_SUFFIXES = (".db", ".etbk")  # raw-DB snapshot | full .etbk bundle
# These sit beside the snapshots; they are NOT snapshots, so the prune glob
# skips them by name.
BACKUP_MARKER_NAME = "_LATEST.json"   # last GOOD backup (freshness)
RUN_STATUS_NAME = "_LAST_RUN.json"    # last RUN outcome (success OR failure)


def snapshot_filename(ts: str, fmt: str = "db") -> str:
    """Backup filename for a UTC timestamp (e.g. ``20260617T031500Z``) and
    format (``db`` raw snapshot | ``etbk`` full bundle). Both share the
    ``triage-db-<ts>`` stem so one glob + one ts-ordered retention covers both.

    Retention orders on this EMBEDDED, client-authored timestamp — NEVER on
    filesystem mtime, whose CIFS server-clock skew + coarse granularity can
    misorder two files in the same tick (db-sme). A zero-padded UTC stamp sorts
    lexically == chronologically.
    """
    ext = ".etbk" if fmt == "etbk" else ".db"
    return f"{_SNAPSHOT_PREFIX}{ts}{ext}"


def _snapshot_ts(path: Path) -> str | None:
    """Extract the embedded ``<ts>`` from a ``triage-db-<ts>.<ext>`` name."""
    name = path.name
    if not name.startswith(_SNAPSHOT_PREFIX):
        return None
    core = name[len(_SNAPSHOT_PREFIX):]
    for ext in _SNAPSHOT_SUFFIXES:
        if core.endswith(ext):
            return core[: -len(ext)]
    return None


def list_db_snapshots(directory: Path | str) -> list[Path]:
    """Backup files (both formats) in ``directory``, NEWEST first by embedded
    timestamp. Ignores the markers and any in-flight ``.partial`` write."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    snaps = [
        p
        for p in directory.glob(f"{_SNAPSHOT_PREFIX}*")
        if p.is_file()
        and p.suffix in _SNAPSHOT_SUFFIXES
        and not p.name.endswith(".partial")
    ]
    return sorted(snaps, key=lambda p: p.name, reverse=True)


def parse_retention_spec(spec: str | int) -> tuple[str, int]:
    """Parse the operator's retention spec → ``(mode, n)``:
    plain int / ``"N"`` → ``("count", N)``; ``"Nd"`` → ``("age_days", N)``;
    ``"Nw"`` → ``("age_days", N*7)``. (Operator 2026-06-17: 'd'=days, 'w'=weeks,
    plain INT = a count.)"""
    if isinstance(spec, int):
        return ("count", max(spec, 1))
    s = str(spec).strip().lower()
    if s.endswith("d"):
        return ("age_days", max(int(s[:-1]), 1))
    if s.endswith("w"):
        return ("age_days", max(int(s[:-1]) * 7, 1))
    return ("count", max(int(s), 1))


def prune_backups(
    directory: Path | str, spec: str | int, *, now=None,
) -> list[Path]:
    """Prune per the retention spec (count or age-days), across BOTH formats.
    Returns the deleted paths.

    Prune ONLY AFTER a verified-good new backup lands (never prune-then-write)
    so a run of failed writes can never rotate the set below the kept good ones
    (db-sme/devils-advocate)."""
    from datetime import datetime, timedelta, timezone

    mode, n = parse_retention_spec(spec)
    snaps = list_db_snapshots(directory)  # newest first
    if mode == "count":
        victims = snaps[n:]
    else:  # age_days
        ref = now or datetime.now(timezone.utc)
        cutoff = ref - timedelta(days=n)
        victims = []
        for p in snaps:
            ts = _snapshot_ts(p)
            try:
                dt = (
                    datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(
                        tzinfo=timezone.utc
                    )
                    if ts
                    else None
                )
            except ValueError:
                dt = None
            if dt is not None and dt < cutoff:
                victims.append(p)
    deleted: list[Path] = []
    for p in victims:
        try:
            p.unlink()
            deleted.append(p)
        except OSError as _swallow_exc:
            logger.warning(
                "backup prune could not delete an expired backup",
                path=str(p), error=fmt_exc(_swallow_exc),
            )
    return deleted


def prune_db_snapshots(directory: Path | str, keep: int) -> list[Path]:
    """Back-compat alias — keep newest ``keep`` (count mode)."""
    return prune_backups(directory, int(keep))


def write_backup_marker(
    directory: Path | str, result: "SnapshotResult", *, ts: str,
    key_fpr: str | None = None,
) -> Path:
    """Write the ``_LATEST.json`` freshness marker — written LAST, only after
    a verified-good snapshot has landed. Carries sha256 + byte-count (not just
    a timestamp) so the freshness monitor verifies a GOOD backup exists, not
    merely that *something* was written recently; plus the master-key
    fingerprint so a rotation-orphaned backup is detectable (devils-advocate)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / BACKUP_MARKER_NAME
    payload = {
        "ts": ts,
        "file": result.path.name,
        "sha256": result.sha256,
        "bytes": result.bytes,
        "encrypted": result.encrypted,
        "integrity": result.integrity,
        "key_fpr": key_fpr,
    }
    # N-210b R23: route through _atomicio SSOT (marker carries sha256 +
    # key_fpr — sensitive-adjacent + hygiene).
    from email_triage._atomicio import atomic_write_text
    atomic_write_text(marker, json.dumps(payload, indent=2), mode=0o600)
    return marker


def read_backup_marker(directory: Path | str) -> dict[str, Any] | None:
    """Parse ``_LATEST.json`` (the freshness monitor's source). Returns None if
    absent/unparseable — the monitor treats that as fail-closed (alert)."""
    marker = Path(directory) / BACKUP_MARKER_NAME
    if not marker.is_file():
        return None
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_run_status(
    directory: Path | str, *, outcome: str, ts: str, fmt: str,
    error: str | None = None, file: str | None = None,
    key_fpr: str | None = None,
) -> Path:
    """Per-run status (``_LAST_RUN.json``), written on SUCCESS **and** FAILURE.

    Distinct from the last-GOOD marker: a run that fails AFTER the CLI returned
    "request received" must be detectable, else the stale success-marker makes a
    failed backup look fresh (devils-advocate FATAL-2). The ``--wait`` CLI path
    + the freshness monitor read this for the THIS-run outcome."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / RUN_STATUS_NAME
    payload = {
        "outcome": outcome, "ts": ts, "format": fmt,
        "error": error, "file": file, "key_fpr": key_fpr,
    }
    # N-210b R23: route through _atomicio SSOT (POSIX umask hygiene).
    from email_triage._atomicio import atomic_write_text
    atomic_write_text(p, json.dumps(payload, indent=2), mode=0o600)
    return p


def read_run_status(directory: Path | str) -> dict[str, Any] | None:
    """Parse ``_LAST_RUN.json`` — the last run's outcome (success/failure)."""
    p = Path(directory) / RUN_STATUS_NAME
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


# Restore-key freshness: the automated .etbk / DB snapshots are unrecoverable
# without the operator's separately-held key-only export. Rather than re-nag the
# operator each turn, we PRODUCTIZE the reminder — stamp when they last exported
# the key, surfaced in the health email + dashboard ("Last key export: <date>").
KEY_EXPORT_MARKER_NAME = "_LAST_KEY_EXPORT.json"


def write_key_export_marker(data_dir: Path | str, *, ts: str) -> Path:
    """Record when the operator last exported the key-only bundle (best-effort,
    written from the export route's success path)."""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    p = data_dir / KEY_EXPORT_MARKER_NAME
    # N-210b R23: route through _atomicio SSOT (POSIX umask hygiene).
    from email_triage._atomicio import atomic_write_text
    atomic_write_text(p, json.dumps({"ts": ts}, indent=2), mode=0o600)
    return p


def read_key_export_marker(data_dir: Path | str) -> dict[str, Any] | None:
    """Read the last-key-export marker (the health surfaces' source). None when
    the operator has never exported the key — which is exactly the state worth
    flagging (no restore key on record)."""
    p = Path(data_dir) / KEY_EXPORT_MARKER_NAME
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# .etbk automated path — passphrase derivation + restorability gate
# ---------------------------------------------------------------------------

def derive_etbk_passphrase(master_key: str | bytes) -> str:
    """Derive the AUTOMATED .etbk bundle passphrase from the master key via
    HKDF-SHA256 (distinct info string → domain-separated from the audit
    subkey; RFC 5869 §3.1, NOT key-reuse). Returned as a base64 STR because
    ``build_full_bundle``'s ``_derive_key`` floors at 12 chars and ``.encode``s
    a str — raw HKDF bytes would crash / under-run the floor."""
    ikm = master_key.encode("utf-8") if isinstance(master_key, str) else master_key
    raw = _HKDF(
        algorithm=_hashes.SHA256(), length=32, salt=None,
        info=_ETBK_PASSPHRASE_HKDF_INFO,
    ).derive(ikm)
    pp = base64.urlsafe_b64encode(raw).decode("ascii")
    if len(pp) < _MIN_PASSPHRASE_LEN:  # base64(32B)=43 chars; assert defensively
        raise BackupError("derived .etbk passphrase under the minimum length")
    return pp


def master_key_fingerprint(master_key: str | bytes) -> str:
    """A NON-SECRET, non-reversible fingerprint of the master key for the
    backup marker — lets restore / the freshness check detect a snapshot that
    predates the current key (rotation orphaning) instead of a silent
    'file exists but is undecryptable'. HKDF-derived (distinct info) + 16-byte
    truncation; never the key itself."""
    ikm = master_key.encode("utf-8") if isinstance(master_key, str) else master_key
    raw = _HKDF(
        algorithm=_hashes.SHA256(), length=16, salt=None,
        info=b"email_triage/backup/key-fingerprint/v1",
    ).derive(ikm)
    return raw.hex()


def write_verified_etbk(
    bundle: bytes, *, passphrase: str, out_path: Path | str, encrypted: bool,
) -> SnapshotResult:
    """Verify a freshly-built .etbk bundle is RESTORABLE, then atomically land
    it — the .etbk analogue of ``snapshot_db_to_path``'s gate.

    ``unbundle`` proves only decrypt-ability + manifest-hash integrity, NOT
    that the embedded ``triage.db`` is a traversable, restorable database. So
    this ALSO extracts the inner DB to a temp and runs the SAME strong gate the
    raw-DB path uses (``_verify_snapshot_file``). FAIL-CLOSED: any failure
    removes the partial and raises ``BackupError`` — never a half / unverified
    bundle masquerading as a good backup."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Decrypt + manifest-verify + extract (proves the wrapper is sound).
    result = unbundle(bundle, passphrase=passphrase)
    db_member = result.files.get("triage.db")
    if db_member is None:
        raise BackupError("bundle has no triage.db; cannot verify restorability")

    # 2. Extract the inner DB to a temp + run the strong restorability gate.
    tmp_fd, tmp_db = tempfile.mkstemp(prefix="et-etbk-verify-", suffix=".db")
    os.close(tmp_fd)
    try:
        Path(tmp_db).write_bytes(db_member.data)
        _verify_snapshot_file(Path(tmp_db))  # raises on any integrity fault
    finally:
        for _ext in ("", "-wal", "-shm"):
            try:
                Path(tmp_db + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                # ERROR, path in the TEXT (kwarg ``path=`` is blanked by the
                # persisted-key allow-list). A mkstemp name: not PHI.
                logger.error(
                    f"temp verify DB cleanup failed; plaintext pages may "
                    f"remain on disk at {tmp_db + _ext}",
                    exc_info=_swallow_exc,
                )

    # 3. Atomically land the bundle. N-210b R23: route through _atomicio SSOT
    # (credential-bearing bundle — chmod BEFORE the swap so no world-readable
    # window on POSIX).
    from email_triage._atomicio import atomic_write_bytes
    atomic_write_bytes(out_path, bundle, mode=0o600)

    return SnapshotResult(
        path=out_path, bytes=out_path.stat().st_size,
        sha256=_sha256_file(out_path), encrypted=encrypted, integrity="ok",
    )


# ---------------------------------------------------------------------------
# Public-key (write-only) backup sealing —  operator-chosen mode
# ---------------------------------------------------------------------------

def load_public_key_pem(public_key_pem: bytes) -> _X25519PublicKey:
    """Parse ``public_key_pem`` into an X25519 public key or raise ``BackupError``.

    The ONE seam that turns operator-supplied PEM into a usable key — the seal
    path and the config-time validator both go through it, so the "is this a
    real X25519 public key?" predicate can't drift into two copies (PD#5)."""
    try:
        pub = _serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        raise BackupError(f"backup public_key did not parse as PEM: {e}") from e
    if not isinstance(pub, _X25519PublicKey):
        raise BackupError("backup public_key is not an X25519 public key")
    return pub


def validate_public_key_pem(public_key_pem: bytes) -> None:
    """Config-time fail-closed gate for public-key backup mode.

    Raise ``BackupError`` unless ``public_key_pem`` is a usable X25519 public
    key. Called when the operator SAVES ``backup.encryption: public-key`` so a
    bad / wrong-type / truncated key is rejected at config time — never silently
    accepted only to FAIL every later unattended backup run on seal."""
    load_public_key_pem(public_key_pem)


def resolve_public_key_pem(value: str) -> bytes:
    """Resolve a ``backup.public_key`` config VALUE to PEM bytes — the ONE seam.

    ``value`` is either inline PEM text (contains ``BEGIN``) or a path to a
    ``.pem`` file. Both the config-time save validator AND the run-time consumer
    (``background_sweepers._resolve_backup_pubkey``) go through here, so the
    "inline vs path / does it exist?" predicate can't drift into two subtly
    different copies (PD#5 — the hipaa-sme H304-3 nit). FAIL-CLOSED: an empty
    value or a non-existent path raises ``BackupError`` — public-key mode
    REQUIRES a resolvable key (the caller records the failure)."""
    v = (value or "").strip()
    if not v:
        raise BackupError(
            "backup.encryption=public-key requires backup.public_key "
            "(X25519 public-key PEM text or a path to it)"
        )
    if "BEGIN" in v:
        return v.encode("utf-8")
    p = Path(v)
    if not p.is_file():
        raise BackupError(
            f"backup.public_key path not found: {v} "
            "(expected inline PEM text or a path to a .pem file)"
        )
    return p.read_bytes()


def seal_to_pubkey(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """ECIES-style seal to an X25519 PUBLIC key (write-only backup encryption).

    Ephemeral X25519 → ECDH → HKDF-SHA256 → AES-256-GCM. The container holds
    only the public key, so it can SEAL but never UNSEAL — only the off-box
    private key restores. Layout: ``[ephemeral_pubkey(32) | nonce(12) | ct+tag]``."""
    pub = load_public_key_pem(public_key_pem)
    eph = _X25519PrivateKey.generate()
    shared = eph.exchange(pub)
    key = _HKDF(
        algorithm=_hashes.SHA256(), length=32, salt=None,
        info=_PUBKEY_SEAL_HKDF_INFO,
    ).derive(shared)
    nonce = _secrets.token_bytes(12)
    ct = _AESGCM(key).encrypt(nonce, plaintext, None)
    eph_pub = eph.public_key().public_bytes(
        _serialization.Encoding.Raw, _serialization.PublicFormat.Raw,
    )
    return eph_pub + nonce + ct


def unseal_with_privkey(sealed: bytes, private_key_pem: bytes) -> bytes:
    """Reverse of :func:`seal_to_pubkey` — needs the off-box X25519 PRIVATE key."""
    try:
        priv = _serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as e:
        raise BackupError(f"backup private key did not parse as PEM: {e}") from e
    if not isinstance(priv, _X25519PrivateKey):
        raise BackupError("backup private key is not an X25519 private key")
    if len(sealed) < 32 + 12 + 16:
        raise BackupError("sealed blob too short")
    eph_pub = _X25519PublicKey.from_public_bytes(sealed[:32])
    nonce = sealed[32:44]
    ct = sealed[44:]
    shared = priv.exchange(eph_pub)
    key = _HKDF(
        algorithm=_hashes.SHA256(), length=32, salt=None,
        info=_PUBKEY_SEAL_HKDF_INFO,
    ).derive(shared)
    try:
        return _AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise BundleAuthError(
            "public-key unseal failed — wrong private key or tampered bundle",
        ) from e


def is_pubkey_sealed(blob: bytes) -> bool:
    """True if ``blob`` is a public-key-sealed (ETBKP02) bundle."""
    return blob[:_MAGIC_LEN] == MAGIC_PUBKEY


def write_verified_pubkey_etbk(
    bundle: bytes, *, passphrase: str, public_key_pem: bytes,
    out_path: Path | str, encrypted: bool,
) -> SnapshotResult:
    """Verify the inner .etbk is restorable, SEAL its passphrase to the public
    key, and atomically land the ETBKP02 artifact.

    The container builds + verifies the inner .etbk with a RANDOM passphrase
    (restorability proof intact — the SAME strong gate as the symmetric path,
    run here PRE-seal), then seals that passphrase to the public key and
    discards the plaintext. The landed file is decryptable ONLY by the off-box
    private key, so a container-compromised attacker cannot read it.
    FAIL-CLOSED."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Restorability proof on the inner bundle (we hold the random passphrase).
    result = unbundle(bundle, passphrase=passphrase)
    db_member = result.files.get("triage.db")
    if db_member is None:
        raise BackupError("bundle has no triage.db; cannot verify restorability")
    tmp_fd, tmp_db = tempfile.mkstemp(prefix="et-etbk-pk-verify-", suffix=".db")
    os.close(tmp_fd)
    try:
        Path(tmp_db).write_bytes(db_member.data)
        _verify_snapshot_file(Path(tmp_db))  # raises on any fault
    finally:
        for _ext in ("", "-wal", "-shm"):
            try:
                Path(tmp_db + _ext).unlink(missing_ok=True)
            except Exception as _swallow_exc:
                # ERROR, path in the TEXT (kwarg ``path=`` is blanked by the
                # persisted-key allow-list). A mkstemp name: not PHI.
                logger.error(
                    f"temp verify DB cleanup failed; plaintext pages may "
                    f"remain on disk at {tmp_db + _ext}",
                    exc_info=_swallow_exc,
                )

    # 2. Seal the passphrase + assemble: magic | sealed_len(4) | sealed | inner.
    sealed = seal_to_pubkey(passphrase.encode("utf-8"), public_key_pem)
    blob = MAGIC_PUBKEY + len(sealed).to_bytes(4, "big") + sealed + bundle

    # 3. Atomic land. N-210b R23: route through _atomicio SSOT (pubkey-sealed
    # .etbk.pk carries the passphrase — chmod BEFORE the swap so no world-
    # readable window on POSIX).
    from email_triage._atomicio import atomic_write_bytes
    atomic_write_bytes(out_path, blob, mode=0o600)

    return SnapshotResult(
        path=out_path, bytes=out_path.stat().st_size,
        sha256=_sha256_file(out_path), encrypted=encrypted, integrity="ok",
    )


def unwrap_pubkey_sealed_etbk(
    blob: bytes, private_key_pem: bytes,
) -> tuple[bytes, str]:
    """Reverse the ETBKP02 wrapper with the off-box private key. Returns
    ``(inner_etbk_bytes, passphrase)`` — feed to :func:`unbundle`."""
    if not is_pubkey_sealed(blob):
        raise BundleFormatError("not a public-key-sealed (ETBKP02) bundle")
    off = _MAGIC_LEN
    if len(blob) < off + 4:
        raise BundleFormatError("ETBKP02 bundle truncated (no length header)")
    sealed_len = int.from_bytes(blob[off:off + 4], "big")
    off += 4
    sealed = blob[off:off + sealed_len]
    off += sealed_len
    inner = blob[off:]
    if len(sealed) != sealed_len or not inner:
        raise BundleFormatError("ETBKP02 bundle truncated")
    passphrase = unseal_with_privkey(sealed, private_key_pem).decode("utf-8")
    return inner, passphrase


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
    m: dict[str, Any] = {
        "format_version": _FORMAT_VERSION,
        "bundle_type": bundle_type,
        "schema_version": int(schema_version),
        "hostname": hostname or "",
        "exported_at": now_utc_iso(),
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

    # 2. Optional O365 MSAL token caches (N-177 / R20_2). N-259 R26:
    # route through the artifact-registry glob so a NEW per-account /
    # per-user artifact family lands in backups without editing this
    # collector — matches the registry pattern N-245/N-252 established.
    # HARDCODED literal was silently missing new artifact families
    # per census R26. Glob patterns strip the "./data/" prefix (the
    # registry glob paths are project-relative) so `data_dir.glob(...)`
    # resolves them against the actual data dir.
    from email_triage.providers._ondisk_artifacts import (
        PER_ACCOUNT_ARTIFACT_GLOBS,
        PER_USER_ARTIFACT_GLOBS,
    )
    # Punch 432: search where the WRITER writes, not only where the config
    # says data lives. `providers.factory` builds every cache path
    # CWD-relative (`./data/msal_cache_<id>.json`, the registry glob's own
    # directory), while `data_dir` comes from `persistence.db_path`. They
    # coincide on the deploy host (`/app/data` + `WORKDIR /app`), so nothing was lost
    # there; on an install whose db_path is elsewhere every cache was
    # silently omitted (N-472's class: the wrong DIRECTORY searched). The
    # writer's directory is read FIRST. Panel Z SHOULD-Z1-3: the writer's
    # directory is the backup process's CWD, which is the running provider's
    # only when the collector runs under the server's WORKDIR; a CLI run from
    # another directory may sweep another install's `./data`. So on a
    # same-name clash, identical bytes are one file (bundled once), and
    # DIFFERENT bytes refuse the bundle (`ArtifactClashError`, fail closed):
    # a warning in a backup log is read by no one.
    _by_name: dict = {}
    for glob_pattern in list(PER_ACCOUNT_ARTIFACT_GLOBS) + list(PER_USER_ARTIFACT_GLOBS):
        # Registry globs are `./data/msal_cache_*.json`; strip the
        # `./data/` prefix so `data_dir.glob(...)` resolves against
        # the actual data dir (usually the same path but symlinks +
        # test dirs differ).
        rel_glob = glob_pattern.split("/", 2)[-1] if "/" in glob_pattern else glob_pattern
        writer_dir = Path(glob_pattern).parent
        for p in sorted(writer_dir.glob(Path(glob_pattern).name)) + sorted(data_dir.glob(rel_glob)):
            kept = _by_name.setdefault(p.name, p)
            if (kept is not p and kept.resolve() != p.resolve()
                    and kept.is_file() and p.is_file()
                    and kept.read_bytes() != p.read_bytes()):
                raise ArtifactClashError(
                    f"backup refused: two on-disk artifacts named {p.name!r} "
                    f"hold different bytes: {kept.resolve()} and {p.resolve()}. "
                    "Run the backup from the server's working directory, or "
                    "remove the file that does not belong to this install."
                )
    # Punch 711 (panel AB MUST C2-711): a pending restore-witness marker never
    # travels in a bundle. Restored elsewhere it would record a restore that did
    # not happen there. No registry glob matches one today; this keeps it so.
    _artifact_paths: set = {
        p for p in _by_name.values() if not p.match(RESTORE_WITNESS_GLOB)}
    # N-351 R31 (2026-07-05): removed the N-259b R26 transitional
    # `data_dir.glob("msal_cache*.json")` literal shim — the new
    # registry-membership pin (`test_n177_backup_msal_glob_pin.py::
    # test_backup_iterates_ondisk_artifact_registry`) walks the
    # `PER_ACCOUNT_ARTIFACT_GLOBS` name-reference in `build_full_bundle`
    # + the registry-non-empty check, subsuming the literal check.
    # Sibling `test_backup_uses_glob_not_bare_singleton_LEGACY` also
    # deleted in the same commit.
    for p in sorted(_artifact_paths):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        # Validate the payload is structurally intact before bundling — a
        # truncated cache in the archive is worse than a missing one
        # (restore would leave that account without a usable refresh
        # token). Skip+log on an invalid payload (§164.308(a)(7): don't
        # poison the backup).
        #
        # The ORIGINAL N-177 rationale said "MSAL writes are not
        # atomic-rename on all platforms; a concurrent O365 refresh
        # mid-backup can yield a torn blob." That is FALSE at HEAD and was
        # carried through verbatim until devils-advocate checked it:
        # `providers/office365.py` writes via `_atomicio.atomic_write_bytes`
        # (tmp -> fsync -> chmod -> os.replace), and the tmp name ends
        # `.tmp` so the `msal_cache*.json` glob never sees it. The live
        # threat model is CORRUPT, not torn-by-a-concurrent-refresh: disk
        # damage, an interrupted restore, a truncated off-host staged copy
        # (this project has a filed 2026-07-31 off-host staging incident).
        # The check stays — a control whose job is rejecting malformed
        # input has no frequency clause — but under the rationale that is
        # actually true.
        #
        # N-472 (2026-09-12): the predicate is the WRITER's, not ours.
        # This branch used to hard-code `json.loads`, which N-151's
        # 2026-07-08 plaintext-to-Fernet cutover turned into a reject of
        # every cache the writer produces — so every bundle since then
        # silently omitted every per-account MSAL token cache. Calling
        # the owning module's predicate means the next format migration
        # propagates by construction. Do NOT re-inline a shape check here.
        from email_triage.providers._msal_cache_crypto import (
            is_valid_cache_payload,
        )
        if not is_valid_cache_payload(raw, source=str(p)):
            # torn-write or corrupt; omit from bundle. N-472: this used
            # to `continue` in silence while its own comment promised a
            # log, so a systematically-omitted artifact read exactly like
            # a healthy one.
            logger.warning(
                "backup: omitting on-disk artifact — payload is not a "
                "structurally valid MSAL cache (torn write or corrupt). "
                "Restore will require re-auth for this account.",
                # Direct kwargs — the native TriageLogger shape. NOT for the
                # reason a review of this line first gave: an `extra={...}`
                # dict would ALSO have been scrubbed correctly. Checked at
                # the source (`TriageLogger._merge_extra`): it pops "extra"
                # and `setdefault`s its inner keys to top level, and
                # `TriageLogger.warning` calls it BEFORE `_log`, so both shapes
                # reach `_sanitise` flattened. Recording that here because
                # the claim that they do not was filed, refuted from the
                # function body, and would otherwise get re-derived.
                # Still PD-10 territory: know which logger you hold — this
                # one takes no positional `exc_info`.
                path=str(p),
                payload_bytes=len(raw),
            )
            continue
        # The legacy-PLAINTEXT warning is emitted INSIDE
        # `is_valid_cache_payload`, not here. Reporting it from this side
        # would mean calling `looks_like_legacy_plaintext` at the call
        # site, which is the misuse that function's own docstring forbids.
        # Format knowledge stays in the module that owns the format; this
        # side passes only its own identity (the path), which is the one
        # thing the crypto module cannot derive from bytes.
        #
        # An earlier version of this comment ALSO claimed the call-site
        # shape is "the re-inlined shape check the N-472 pin bans". That
        # was FALSE and devils-advocate proved it by planting the exact
        # shape and running arm B's own offender loop: arm B matches
        # `is_bare_json_loads` and `Attribute.attr == "startswith"`, and
        # `looks_like_legacy_plaintext(raw)` is an `ast.Name` call, so the
        # pin is blind to it. Claiming a protection the pin does not
        # provide is the same defect class N-472 itself is about.
        files.append(
            _BundleFile(
                path=f"data/{p.name}",
                data=raw,
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
        from email_triage.secrets import read_master_key
        key_str = read_master_key(secrets_provider, master_key_name)
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
    from email_triage.secrets import read_master_key
    key_str = read_master_key(secrets_provider, master_key_name)
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
            # N-210 R23 (2026-07-02): route through _atomicio SSOT.
            # Pre-N-210 `mko.write_bytes(...)` + `os.chmod(..., 0o600)`
            # created a world-readable window between the create (default
            # umask) and the chmod — census R23_1 §164.312(a)(1) master-
            # key material integrity/confidentiality hygiene defect.
            # atomic_write_bytes chmods the tmp file BEFORE the rename,
            # so the visible target never has an over-broad mode.
            from email_triage._atomicio import atomic_write_bytes
            atomic_write_bytes(mko, entry.data, mode=0o600)
            written["master_key"] = mko
            continue

        out = target_dir / path
        out.parent.mkdir(parents=True, exist_ok=True)
        # N-210 R23 (2026-07-02): route through _atomicio SSOT so a
        # restricted-mode file (e.g. `master_key.bin` at 0o600 in a FULL
        # bundle) never has a world-readable window between the create
        # and the mode-set. Pre-N-210 `write_bytes` + `os.chmod` had the
        # same defect this fn's key-only branch just closed at :~1428.
        from email_triage._atomicio import atomic_write_bytes
        atomic_write_bytes(out, entry.data, mode=entry.mode)
        written[path] = out
    return written


# ---------------------------------------------------------------------------
# Punch 711 — a restore witness that survives the operator's manual swap-in.
#
# ``email-triage restore`` writes its ``@_cli_audit("restore")`` start/end rows
# into the LIVE database (``config.persistence.db_path``). The swap-in it then
# prints moves that file aside (``mv triage.db triage.db.preexisting``), so the
# chain the operator KEEPS held no record that a restore happened (fail-OPEN on
# the record, §164.308(a)(7)(ii)(B), §164.312(b)). The CLI cannot write into the
# extracted database instead: a bundle that carries its own master key has a
# different chain key. So the CLI leaves a PHI-free marker in the live DATA
# directory (which the swap does not move), and the next server boot records it
# into the restored chain under the post-swap key, then removes it.
#
# Panel AB (MUST C2-711): the boot records a swap only when one HAPPENED. The
# marker carries ``live_chain_head``, the newest ``log_entries.row_hash`` of the
# database the CLI ran against, read AFTER its own ``@_cli_audit`` start row. A
# database that still holds that row is the pre-swap one (a service restart
# before the operator's ``mv``, or an abandoned swap), so the marker stays
# pending; recording it there would put the witness into the file the swap then
# moves aside (711 re-opened). A restored database cannot hold the row: it was
# written after the bundle was made. The identity is the chain head, not the
# file's inode: a ``cp``/``cat >``/``.restore`` swap keeps the inode, and some
# filesystems have no stable inode. The host is NOT a gate: under the quadlet the
# container's hostname is its short ID and changes on every start, which would
# keep every real restore pending; a marker cannot reach another host through a
# backup (``.restore-witness-*`` is excluded from bundles). Punch 720: a marker
# left pending until ``log_entries`` pruned its head row (age or count) would read as
# swapped; the marker also carries ``live_chain_head_ts`` and the boot records
# ``swapped-in`` only when the chain still holds history older than that
# (``_chain_holds_history_before``), else ``swap-unverified``.
# ---------------------------------------------------------------------------

RESTORE_WITNESS_GLOB = ".restore-witness-*.json"

# The marker's only fields: bounded identifiers of the bundle and the actor, no
# PHI, no secret, no file content (a path is recorded as a name only).
# ``live_chain_head`` is a row hash; ``cli_hostname`` is recorded, never gated on.
RESTORE_WITNESS_KEYS: frozenset[str] = frozenset({
    "bundle_name", "bundle_type", "source_hostname", "exported_at",
    "exported_by", "schema_version", "commit_sha", "target_dir",
    "extracted_at", "actor", "live_chain_head", "live_chain_head_ts", "cli_hostname",
})


def write_restore_witness_marker(
    data_dir: Path, payload: dict[str, Any], *, owner_of: Path | None = None,
) -> Path:
    """Write one restore-witness marker into ``data_dir`` (mode 0600, never
    overwrites). Keys outside :data:`RESTORE_WITNESS_KEYS` are dropped.

    Run as root (a host install, or ``podman exec -u root``), the marker is
    chowned to ``owner_of``'s uid/gid (the live DB file), so the service user
    can read and remove it (panel AB SHOULD-C5)."""
    body = {k: payload[k] for k in sorted(RESTORE_WITNESS_KEYS) if payload.get(k) is not None}
    stamp = now_utc_iso().replace(":", "").replace("-", "")
    path = Path(data_dir) / f".restore-witness-{stamp}-{os.getpid()}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        if owner_of is not None and getattr(os, "geteuid", lambda: -1)() == 0:
            st = os.stat(owner_of)
            os.fchown(fh.fileno(), st.st_uid, st.st_gid)
        json.dump(body, fh, sort_keys=True)
    return path


def pending_restore_witness_markers(data_dir: Path) -> list[str]:
    """Names of the restore-witness markers still on disk (pending: not yet
    swapped in, or failing to ingest). Derived from the directory on every
    call, so there is no status flag to set or clear (PD-18)."""
    try:
        return sorted(p.name for p in Path(data_dir).glob(RESTORE_WITNESS_GLOB))
    except OSError:
        return []


def _restore_marker_recorded(conn: sqlite3.Connection, name: str, phases: tuple[str, ...]) -> bool:
    """True when a ``restore`` row in one of ``phases`` naming this marker is
    already in the chain (a commit whose unlink then failed, or an unreadable
    marker seen at an earlier start): never record it twice."""
    # Punch 772: decide on the three FIELDS the witness row carries (``marker``,
    # ``cli_phase``, ``cli_command``), never on a substring of the whole ``extra_json`` (any
    # other row that mentions the name and the phase would count). The SQL ``instr`` only
    # narrows the scan to rows that name the marker; the match is made on the parsed JSON in
    # Python. Not ``json_extract``: N-522's MEDIUM grade rests on src issuing no json1
    # function (``tests/test_n522_no_fts_or_json1_query_pin.py``), and widening it needs a
    # hipaa-sme re-score first. A row whose ``extra_json`` is not a JSON object is skipped.
    for (raw,) in conn.execute(
        "SELECT extra_json FROM log_entries WHERE instr(extra_json, ?) > 0", (name,),
    ):
        try:
            extra = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if (isinstance(extra, dict) and extra.get("marker") == name
                and extra.get("cli_command") == "restore"
                and extra.get("cli_phase") in phases):
            return True
    return False


# Punch 720: slack on the "this chain holds older history" test, so a clock that stepped back
# a little (or two rows stamped out of order across threads) cannot read as older history.
_WITNESS_HISTORY_MARGIN_DAYS = 1.0 / 24.0


def _chain_holds_history_before(conn: sqlite3.Connection, head_ts: Any) -> bool:
    """True when ``log_entries`` still holds a row stamped more than the margin before
    ``head_ts`` (the pre-swap chain's newest row at restore time, from the marker).

    This is the proof that the chain is a DIFFERENT one when the head row is absent. Both
    prune axes (``ts < horizon`` and ``id NOT IN newest max_rows``) delete the OLDEST rows
    first, so a chain that pruned the head holds nothing older than it; a restored chain
    holds the bundle's earlier history. The boot prunes before it ingests
    (``web/app.py``), so this must hold for the database as the ingest sees it. No usable
    ``head_ts`` (an old marker, or one the CLI could not stamp) or an unparseable one
    (``julianday`` is NULL) reads False: unverified, never swapped (PD-8)."""
    if not isinstance(head_ts, str) or not head_ts:
        return False
    return conn.execute(
        "SELECT 1 FROM log_entries WHERE julianday(ts) < julianday(?) - ? LIMIT 1",
        (head_ts, _WITNESS_HISTORY_MARGIN_DAYS),
    ).fetchone() is not None


def ingest_restore_witness_markers(conn: sqlite3.Connection, data_dir: Path) -> int:
    """Record the restore-witness markers in ``data_dir`` whose swap happened
    into the chained ``log_entries`` trail (the ``record_cli_admin_op`` emitter,
    phase ``swapped-in``), committing each before its marker is removed.
    Returns the count recorded.

    Per marker, never blocking the others (panel AB SHOULD-C4):
      * its ``live_chain_head`` is still in this chain: no swap yet; it stays
        pending (no row);
      * already recorded (an unlink failed after the commit): unlink only;
      * unreadable or malformed: ONE ``restore-witness-unreadable`` row naming
        the file (the fact that a restore marker existed is kept), the file kept;
      * a marker with no ``live_chain_head`` (the CLI could not read the live
        chain): recorded with phase ``swap-unverified``, never ``swapped-in``.
    A failed emit propagates with its gap row (the caller logs it); every marker
    not yet recorded stays for the next start."""
    from email_triage.db.audit import record_cli_admin_op

    count = 0
    recorded: list[Path] = []  # witnessed at an earlier start: removed after the loop (punch 726)
    for path in sorted(Path(data_dir).glob(RESTORE_WITNESS_GLOB)):
        if _restore_marker_recorded(conn, path.name, ("swapped-in", "swap-unverified")):
            recorded.append(path)
            continue
        # Decide first (no write inside a catch-all: a failed emit propagates
        # with its gap row, and the caller logs it); then ONE record, ONE commit.
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("marker is not a JSON object")
            unreadable = None
        except (OSError, ValueError) as e:
            payload, unreadable = {}, type(e).__name__
        if unreadable is not None:
            if _restore_marker_recorded(conn, path.name, ("restore-witness-unreadable",)):
                continue
            phase = "restore-witness-unreadable"
            extra = {"cli_command": "restore", "cli_phase": phase,
                     "marker": path.name, "error_class": unreadable}
        else:
            head = payload.get("live_chain_head")
            if head and conn.execute(
                    "SELECT 1 FROM log_entries WHERE row_hash = ? LIMIT 1", (head,),
            ).fetchone() is not None:
                continue
            # Punch 720: an absent head proves a swap only when the chain still holds
            # history older than the head; else the head may have been pruned from THIS
            # chain (age or count), and the row says so instead of claiming the swap.
            if not head:
                phase, why = "swap-unverified", "no-chain-head"
            elif _chain_holds_history_before(conn, payload.get("live_chain_head_ts")):
                phase, why = "swapped-in", None
            else:
                phase, why = "swap-unverified", "head-may-be-pruned"
            extra = {k: payload[k] for k in sorted(RESTORE_WITNESS_KEYS) if k in payload}
            extra.update(cli_command="restore", cli_phase=phase, marker=path.name,
                         swap_verified=(phase == "swapped-in"))
            if why is not None:
                extra["swap_unverified_reason"] = why
        record_cli_admin_op(
            conn, ts=now_utc_iso(), command="restore", phase=phase, extra=extra,
        )
        conn.commit()
        if unreadable is None:
            path.unlink()
            count += 1
    # Punch 726: the unlink of an already-recorded marker follows the loop's witness calls, so
    # the n543 pin (a delete never precedes its witness in a handler) reads this function as
    # witness-first. Safe: the marker's row is already committed, and a failed emit above leaves
    # these for the next start, which finds them recorded again.
    # Class AH fold (hipaa NOTE 6): an unlink that fails here is logged per path with its true
    # reason (the witness IS committed) and never discards the count of new markers recorded.
    for path in recorded:
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.warning(
                "Restore witness recorded, but its marker could not be removed; the next "
                "start retries the removal",
                marker=path.name, error=type(e).__name__,
            )
    return count
