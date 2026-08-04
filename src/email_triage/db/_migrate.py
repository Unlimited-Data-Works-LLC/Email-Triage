"""One-time plaintext <-> SQLCipher migration for an EXISTING install.

New installs never touch this: :func:`email_triage.web.db.init_db_encrypted`
brings a fresh DB up SQLCipher-encrypted from ``init``. This module exists
ONLY to convert an already-running *plaintext* ``triage.db`` to encrypted
(the v0.1.2 cutover) and back (rollback).

Design (per the db-sme + devils-advocate cutover-readiness verdict + the
db-sme/hipaa-sme code review, 2026-05-31):

* **Copy-migration, not in-place ``PRAGMA rekey``.** We open the plaintext
  file and ``sqlcipher_export`` it into a *fresh* encrypted file, then swap.
  This is the only encrypt path validated end-to-end by the bake, and it
  sidesteps the in-place page-rewrite WAL hazard (DP-2).
* **The key is ALWAYS derived here** via
  :func:`email_triage.db._engine.derive_storage_key` — the caller passes the
  master key, never a raw SQLCipher key. A wrong-key permanent brick (DP-1)
  is therefore impossible: the same derivation the app boots with
  (``_make_encrypted_conn``) is the one we encrypt with.
* **WAL is checkpointed (TRUNCATE) before the copy**, then the sidecars are
  removed — folding every committed-but-unmerged page into the main file so
  the export cannot miss data (DP-2). We never blind-delete a populated WAL.
* **The original is backed up** to ``<db>.plaintext.bak`` before the swap,
  and the new file is **verified** before it replaces the live file:
  raw ``sqlite3`` must reject it, keyed ``sqlcipher3`` must open it, the
  table count AND the total row count must match the source, and
  ``PRAGMA integrity_check`` must pass (catches a silently-partial export
  that a table-count-only check would miss — db-sme review SHOULD-FIX #1).

  NOTE the ``<db>.plaintext.bak`` is a PLAINTEXT-PHI copy that persists on
  disk: it is the rollback anchor, but §164.310(d)(2)(i) requires the
  operator to securely dispose it (``shred -u``) once the cutover is
  confirmed healthy — see the runbook disposal step (hipaa-sme review).

This module assumes the service is STOPPED (runbook §3.4). It takes a
best-effort ``BEGIN IMMEDIATE`` write lock and refuses if another writer
holds the DB, but the operator owns the drain.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from email_triage.db._engine import derive_storage_key, format_raw_hex_key


class MigrationError(Exception):
    """Raised when an encrypt/decrypt migration cannot complete safely.

    Always raised BEFORE the live file is replaced — the original is
    preserved (at ``<db>.plaintext.bak`` / left untouched), never silently
    corrupted.
    """


@dataclass(frozen=True)
class MigrationResult:
    """Outcome of an encrypt/decrypt run. Carries NO key material."""

    db_path: str
    backup_path: str
    direction: str  # "encrypt" | "decrypt"
    source_tables: int
    result_tables: int
    source_rows: int
    result_rows: int
    integrity_ok: bool
    raw_sqlite_rejects: bool  # encrypt: must be True; decrypt: must be False


def _suffix_paths(db_path: str) -> tuple[str, str]:
    """WAL / SHM sidecar paths for ``db_path``."""
    return db_path + "-wal", db_path + "-shm"


def _remove_sidecars(db_path: str) -> None:
    for p in _suffix_paths(db_path):
        if os.path.exists(p):
            os.remove(p)


def _attach_arg(path: str) -> str:
    """ATTACH-safe path literal. Forward-slashes so a Windows backslash
    path does not need escaping inside the SQL string (SQLite accepts
    ``/`` on Windows). The cutover itself runs on Linux."""
    return Path(path).as_posix()


def _table_stats(conn: sqlite3.Connection) -> tuple[int, int]:
    """``(table_count, total_row_count)`` across user tables on an OPEN conn.

    Works on either a stdlib ``sqlite3`` conn or a keyed ``sqlcipher3`` conn
    (both DBAPI-2.0). Excludes the ``sqlite_%`` internal tables so the count
    is stable across the export. The row-count is the cross-check a
    table-count-only verify cannot provide (a partial export keeps the
    schema but loses rows).
    """
    names = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    ]
    total = 0
    for n in names:
        total += int(conn.execute(f'SELECT count(1) FROM "{n}"').fetchone()[0])
    return len(names), total


def _integrity_ok(conn: sqlite3.Connection) -> bool:
    """``PRAGMA integrity_check`` returns a single ``("ok",)`` row when clean."""
    rows = conn.execute("PRAGMA integrity_check").fetchall()
    return rows == [("ok",)]


def _is_plaintext_sqlite(db_path: str) -> bool:
    """True if raw stdlib ``sqlite3`` can read ``db_path`` (i.e. it is NOT
    already encrypted). Used to refuse a double-encrypt / double-decrypt."""
    try:
        # -b: short-probe budget from PersistenceConfig.
        from email_triage.db._engine import get_sqlite_probe_timeout_secs
        conn = sqlite3.connect(db_path, timeout=get_sqlite_probe_timeout_secs())
        try:
            conn.execute("SELECT count(1) FROM sqlite_master").fetchone()
            return True
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False


def _checkpoint_plaintext(db_path: str) -> None:
    """Fold a plaintext WAL into the main file, then drop the sidecars.

    Critical (DP-2): we must NOT blind-delete a populated ``-wal`` — it
    holds committed pages not yet merged. ``wal_checkpoint(TRUNCATE)``
    merges them first AND zeroes the WAL; only then is removing the
    sidecars safe. Also doubles as the quiescence probe: a live writer
    holds the RESERVED lock and trips ``BEGIN IMMEDIATE``.
    """
    # -b: standard-opener busy budget from PersistenceConfig.
    from email_triage.db._engine import get_sqlite_busy_wait_secs
    conn = sqlite3.connect(
        db_path, timeout=get_sqlite_busy_wait_secs(), isolation_level=None,
    )
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("COMMIT")
        except sqlite3.OperationalError as e:
            raise MigrationError(
                f"{db_path} is locked by another process — stop the "
                f"service before migrating ({e})."
            ) from e
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    _remove_sidecars(db_path)


def encrypt_plaintext_db(
    db_path: str | Path,
    master_key: str | bytes,
    *,
    purpose: str = "triage",
) -> MigrationResult:
    """Encrypt an existing PLAINTEXT ``triage.db`` to SQLCipher, in place.

    The single safe v0.1.2 cutover primitive. The SQLCipher key is derived
    HERE from ``master_key`` (the operator never supplies a raw key). The
    original is backed up to ``<db>.plaintext.bak`` and the encrypted result
    is verified (raw-rejects + keyed-opens + table/row-count match +
    integrity_check) before it replaces the live file.

    Raises :class:`MigrationError` (leaving the original intact) if the file
    is missing, already encrypted, locked by a running service, ``sqlcipher3``
    is unavailable, or the post-encrypt verification fails.
    """
    # N-432 DA NTH-3 (2026-07-19) + DA-MF-1 fold (batched NTH-panel same-day):
    # Two-layer runtime refusal if a FastAPI app is live on this HOST.
    # Layer 1 (in-process bool) catches a same-process fold; Layer 2
    # (filesystem sentinel `<dbdir>/.app-alive.<pid>`) catches the
    # operator-observable `podman exec ... python -m et migrate` bypass.
    # MUST fire BEFORE the sqlcipher3 import so the refusal surfaces on
    # any platform (the sqlcipher3 wheel is Linux-only).
    from email_triage.db._live_app_gate import assert_no_live_app
    assert_no_live_app("encrypt_plaintext_db", db_path=db_path)

    import sqlcipher3  # lazy: heavy Linux-only binary, mirrors _make_encrypted_conn

    db_path = str(db_path)
    if not os.path.isfile(db_path):
        raise MigrationError(f"No such database file: {db_path}")
    if not _is_plaintext_sqlite(db_path):
        raise MigrationError(
            f"{db_path} is not a readable plaintext SQLite DB — it may "
            f"already be encrypted. Refusing to double-encrypt."
        )

    key_arg = format_raw_hex_key(derive_storage_key(purpose, master_key))

    # 1. Quiesce: checkpoint the WAL into the main file + drop sidecars.
    _checkpoint_plaintext(db_path)
    # -b: standard-opener busy budget from PersistenceConfig.
    from email_triage.db._engine import get_sqlite_busy_wait_secs
    src_conn = sqlite3.connect(db_path, timeout=get_sqlite_busy_wait_secs())
    try:
        source_tables, source_rows = _table_stats(src_conn)
    finally:
        src_conn.close()
    if source_tables < 1:
        raise MigrationError(f"{db_path} has 0 tables — refusing to encrypt.")

    # 2. Back up the plaintext original BEFORE we touch the live path.
    backup_path = db_path + ".plaintext.bak"
    shutil.copy2(db_path, backup_path)

    # 3. sqlcipher_export plaintext -> a FRESH encrypted temp file.
    enc_tmp = db_path + ".enc.tmp"
    if os.path.exists(enc_tmp):
        os.remove(enc_tmp)
    _remove_sidecars(enc_tmp)
    con = sqlcipher3.dbapi2.connect(db_path)  # open plaintext source, no key
    try:
        con.execute(
            f'ATTACH DATABASE "{_attach_arg(enc_tmp)}" AS enc KEY "{key_arg}"'
        )
        con.execute("SELECT sqlcipher_export('enc')")
        con.execute("DETACH DATABASE enc")
    finally:
        con.close()

    # 4. Verify the temp file BEFORE swapping: raw must reject; keyed must
    #    open; table count, row count, and integrity_check must all hold.
    raw_rejects = not _is_plaintext_sqlite(enc_tmp)
    kc = sqlcipher3.dbapi2.connect(enc_tmp)
    try:
        kc.execute(f'PRAGMA key = "{key_arg}"')
        enc_tables, enc_rows = _table_stats(kc)
        integrity_ok = _integrity_ok(kc)
    except Exception as e:  # noqa: BLE001 — any keyed-open failure is fatal
        raise MigrationError(
            f"Encrypted file failed keyed-open verification: {e}"
        ) from e
    finally:
        kc.close()

    if not raw_rejects:
        raise MigrationError(
            "Verification FAILED: raw sqlite3 still opened the encrypted "
            "file — it is not encrypted. Original left intact."
        )
    if enc_tables != source_tables or enc_rows != source_rows:
        raise MigrationError(
            f"Verification FAILED: encrypted file has {enc_tables} tables / "
            f"{enc_rows} rows, source had {source_tables} / {source_rows}. "
            f"Original left intact."
        )
    if not integrity_ok:
        raise MigrationError(
            "Verification FAILED: PRAGMA integrity_check did not return 'ok' "
            "on the encrypted file. Original left intact."
        )

    # 5. Atomic swap — the encrypted file replaces the live path. Original
    #    is preserved at backup_path; clean any sidecars off both files.
    _remove_sidecars(enc_tmp)
    os.replace(enc_tmp, db_path)
    _remove_sidecars(db_path)

    return MigrationResult(
        db_path=db_path,
        backup_path=backup_path,
        direction="encrypt",
        source_tables=source_tables,
        result_tables=enc_tables,
        source_rows=source_rows,
        result_rows=enc_rows,
        integrity_ok=integrity_ok,
        raw_sqlite_rejects=True,
    )


def decrypt_encrypted_db(
    db_path: str | Path,
    master_key: str | bytes,
    *,
    purpose: str = "triage",
) -> MigrationResult:
    """Decrypt a SQLCipher ``triage.db`` back to PLAINTEXT, in place.

    The rollback inverse of :func:`encrypt_plaintext_db` (gate §7
    post-cutover decrypt path), via the same ``sqlcipher_export`` copy +
    swap rather than an in-place ``PRAGMA rekey ""``. Backs the encrypted
    original up to ``<db>.encrypted.bak`` and verifies raw ``sqlite3`` can
    read the result (table/row-count match + integrity_check) before swapping.
    """
    # N-432 DA NTH-3 (2026-07-19) + DA-MF-1 fold: two-layer refusal (in-process
    # bool + filesystem sentinel). See `encrypt_plaintext_db` for full
    # rationale.
    from email_triage.db._live_app_gate import assert_no_live_app
    assert_no_live_app("decrypt_encrypted_db", db_path=db_path)

    import sqlcipher3

    db_path = str(db_path)
    if not os.path.isfile(db_path):
        raise MigrationError(f"No such database file: {db_path}")
    if _is_plaintext_sqlite(db_path):
        raise MigrationError(
            f"{db_path} is already a readable plaintext SQLite DB — "
            f"nothing to decrypt."
        )

    key_arg = format_raw_hex_key(derive_storage_key(purpose, master_key))

    # Count source through a keyed conn + checkpoint the encrypted WAL into
    # the main file before the export.
    kc = sqlcipher3.dbapi2.connect(db_path)
    try:
        kc.execute(f'PRAGMA key = "{key_arg}"')
        try:
            kc.execute("BEGIN IMMEDIATE")
            kc.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            raise MigrationError(
                f"{db_path} is locked by another process — stop the "
                f"service before migrating ({e})."
            ) from e
        kc.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        source_tables, source_rows = _table_stats(kc)
    except MigrationError:
        raise
    except Exception as e:  # noqa: BLE001 — bad key / unreadable
        raise MigrationError(
            f"Could not open the encrypted DB with the derived key: {e}"
        ) from e
    finally:
        kc.close()
    _remove_sidecars(db_path)

    backup_path = db_path + ".encrypted.bak"
    shutil.copy2(db_path, backup_path)

    plain_tmp = db_path + ".plain.tmp"
    if os.path.exists(plain_tmp):
        os.remove(plain_tmp)
    _remove_sidecars(plain_tmp)
    con = sqlcipher3.dbapi2.connect(db_path)  # encrypted source
    try:
        con.execute(f'PRAGMA key = "{key_arg}"')
        con.execute(
            f'ATTACH DATABASE "{_attach_arg(plain_tmp)}" AS plain KEY \'\''
        )  # empty KEY '' = plaintext target
        con.execute("SELECT sqlcipher_export('plain')")
        con.execute("DETACH DATABASE plain")
    finally:
        con.close()

    # Verify: raw sqlite3 must now OPEN the result; table/row counts match;
    # integrity_check passes.
    if not _is_plaintext_sqlite(plain_tmp):
        raise MigrationError(
            "Verification FAILED: decrypted file is still not readable by "
            "raw sqlite3. Original left intact."
        )
    # -b: standard-opener busy budget from PersistenceConfig.
    from email_triage.db._engine import get_sqlite_busy_wait_secs
    vconn = sqlite3.connect(plain_tmp, timeout=get_sqlite_busy_wait_secs())
    try:
        plain_tables, plain_rows = _table_stats(vconn)
        integrity_ok = _integrity_ok(vconn)
    finally:
        vconn.close()
    if plain_tables != source_tables or plain_rows != source_rows:
        raise MigrationError(
            f"Verification FAILED: decrypted file has {plain_tables} tables / "
            f"{plain_rows} rows, source had {source_tables} / {source_rows}. "
            f"Original left intact."
        )
    if not integrity_ok:
        raise MigrationError(
            "Verification FAILED: PRAGMA integrity_check did not return 'ok' "
            "on the decrypted file. Original left intact."
        )

    _remove_sidecars(plain_tmp)
    os.replace(plain_tmp, db_path)
    _remove_sidecars(db_path)

    return MigrationResult(
        db_path=db_path,
        backup_path=backup_path,
        direction="decrypt",
        source_tables=source_tables,
        result_tables=plain_tables,
        source_rows=source_rows,
        result_rows=plain_rows,
        integrity_ok=integrity_ok,
        raw_sqlite_rejects=False,
    )
