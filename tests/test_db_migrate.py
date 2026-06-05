"""Round-trip tests for the one-time plaintext<->SQLCipher migration.

SQLCipher-runtime gated: ``sqlcipher3`` is a Linux-only binary, so this whole
module skips on the Windows dev box (alongside the other encryption-runtime
tests) and runs live in CI / the container.

The guarantee these tests defend (db-sme/DA cutover-readiness, 2026-05-31):
DP-1 — the migration derives the SQLCipher key from the master key the SAME
way the app boots, so the encrypted file the migration produces is exactly
the file the running app can open. There is no operator-supplied raw key to
get wrong.
"""

from __future__ import annotations

import sqlite3

import pytest

sqlcipher3 = pytest.importorskip("sqlcipher3")

from email_triage.db._engine import _make_encrypted_conn, derive_storage_key, format_raw_hex_key
from email_triage.db._migrate import (
    MigrationError,
    decrypt_encrypted_db,
    encrypt_plaintext_db,
)

MASTER_KEY = "test-master-key-0123456789abcdef0123456789abcdef="


def _make_plaintext_db(path) -> dict:
    """Create a small plaintext DB; return the rows we expect to survive."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("CREATE TABLE audit (msg TEXT)")
        rows = [("Alice",), ("Bob",), ("Carol",)]
        conn.executemany("INSERT INTO patients (name) VALUES (?)", rows)
        conn.execute("INSERT INTO audit (msg) VALUES ('chain-root')")
        conn.commit()
    finally:
        conn.close()
    return {"patients": [r[0] for r in rows], "tables": 2}


def _keyed_names(path) -> list[str]:
    """Read patient names back through a keyed sqlcipher3 conn."""
    key_arg = format_raw_hex_key(derive_storage_key("triage", MASTER_KEY))
    conn = sqlcipher3.dbapi2.connect(str(path))
    try:
        conn.execute(f'PRAGMA key = "{key_arg}"')
        return [r[0] for r in conn.execute("SELECT name FROM patients ORDER BY id")]
    finally:
        conn.close()


def _raw_opens(path) -> bool:
    try:
        conn = sqlite3.connect(str(path))
        try:
            conn.execute("SELECT count(1) FROM sqlite_master").fetchone()
            return True
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False


def test_encrypt_then_decrypt_roundtrip(tmp_path):
    db = tmp_path / "triage.db"
    expected = _make_plaintext_db(db)

    enc = encrypt_plaintext_db(db, MASTER_KEY)
    assert enc.direction == "encrypt"
    assert enc.raw_sqlite_rejects is True
    assert enc.source_tables == enc.result_tables == expected["tables"]
    # raw sqlite3 must now REJECT the file; keyed open must read the data.
    assert _raw_opens(db) is False
    assert _keyed_names(db) == expected["patients"]
    # the plaintext original is preserved + still readable.
    assert _raw_opens(tmp_path / "triage.db.plaintext.bak") is True

    dec = decrypt_encrypted_db(db, MASTER_KEY)
    assert dec.direction == "decrypt"
    assert dec.raw_sqlite_rejects is False
    assert dec.source_tables == dec.result_tables == expected["tables"]
    # raw sqlite3 reads the round-tripped data verbatim.
    assert _raw_opens(db) is True
    conn = sqlite3.connect(str(db))
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM patients ORDER BY id")]
    finally:
        conn.close()
    assert names == expected["patients"]


def test_encrypted_file_opens_with_the_app_boot_opener(tmp_path):
    """DP-1 guarantee: the migration's derived key == the app's boot key, so
    the running app's own opener (_make_encrypted_conn) reads the result."""
    db = tmp_path / "triage.db"
    expected = _make_plaintext_db(db)
    encrypt_plaintext_db(db, MASTER_KEY)

    conn = _make_encrypted_conn(str(db), MASTER_KEY, purpose="triage")
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM patients ORDER BY id")]
    finally:
        conn.close()
    assert names == expected["patients"]


def test_wrong_master_key_cannot_open_the_result(tmp_path):
    db = tmp_path / "triage.db"
    _make_plaintext_db(db)
    encrypt_plaintext_db(db, MASTER_KEY)

    wrong_key_arg = format_raw_hex_key(derive_storage_key("triage", "a-different-master-key"))
    conn = sqlcipher3.dbapi2.connect(str(db))
    try:
        conn.execute(f'PRAGMA key = "{wrong_key_arg}"')
        with pytest.raises(Exception):
            conn.execute("SELECT count(1) FROM sqlite_master").fetchone()
    finally:
        conn.close()


def test_refuses_to_double_encrypt(tmp_path):
    db = tmp_path / "triage.db"
    _make_plaintext_db(db)
    encrypt_plaintext_db(db, MASTER_KEY)
    with pytest.raises(MigrationError, match="already be encrypted|double-encrypt"):
        encrypt_plaintext_db(db, MASTER_KEY)


def test_refuses_to_decrypt_plaintext(tmp_path):
    db = tmp_path / "triage.db"
    _make_plaintext_db(db)
    with pytest.raises(MigrationError, match="already.*plaintext|nothing to decrypt"):
        decrypt_encrypted_db(db, MASTER_KEY)


def test_refuses_missing_file(tmp_path):
    with pytest.raises(MigrationError, match="No such database file"):
        encrypt_plaintext_db(tmp_path / "nope.db", MASTER_KEY)


def _keyed_count(path, table) -> int:
    key_arg = format_raw_hex_key(derive_storage_key("triage", MASTER_KEY))
    conn = sqlcipher3.dbapi2.connect(str(path))
    try:
        conn.execute(f'PRAGMA key = "{key_arg}"')
        return int(conn.execute(f'SELECT count(1) FROM "{table}"').fetchone()[0])
    finally:
        conn.close()


def test_populated_wal_rows_survive_encrypt(tmp_path):
    """DP-2: rows committed to an un-checkpointed WAL (the state a stopped
    service leaves on disk) must survive — _checkpoint_plaintext folds the
    WAL into the main file BEFORE the export, so no committed page is lost."""
    import shutil
    from pathlib import Path as _P

    src = tmp_path / "src.db"
    conn = sqlite3.connect(str(src))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")  # do NOT auto-merge into main
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    conn.executemany(
        "INSERT INTO t (v) VALUES (?)", [(str(i),) for i in range(50)]
    )
    conn.commit()  # 50 rows now live in the -wal, NOT the main file

    # Snapshot db + -wal + -shm WHILE the conn is open → a fresh path with a
    # populated, un-merged WAL (closing conn would checkpoint it away).
    db = tmp_path / "triage.db"
    shutil.copy2(str(src), str(db))
    for ext in ("-wal", "-shm"):
        side = _P(str(src) + ext)
        if side.exists():
            shutil.copy2(str(side), str(db) + ext)
    conn.close()
    assert _P(str(db) + "-wal").exists()  # precondition: populated WAL on disk

    r = encrypt_plaintext_db(db, MASTER_KEY)
    assert r.source_rows == 50  # the WAL rows were folded in + counted
    assert r.result_rows == 50
    assert _keyed_count(db, "t") == 50  # all 50 survive in the encrypted file


def test_original_survives_verify_failure(tmp_path, monkeypatch):
    """If the pre-swap verification fails, the live DB is left byte-intact —
    the swap (os.replace) never runs."""
    import email_triage.db._migrate as migmod

    db = tmp_path / "triage.db"
    expected = _make_plaintext_db(db)
    monkeypatch.setattr(migmod, "_integrity_ok", lambda conn: False)

    with pytest.raises(MigrationError, match="integrity_check"):
        encrypt_plaintext_db(db, MASTER_KEY)

    # Original plaintext DB untouched + still readable with its rows.
    assert _raw_opens(db) is True
    conn = sqlite3.connect(str(db))
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM patients ORDER BY id")]
    finally:
        conn.close()
    assert names == expected["patients"]
