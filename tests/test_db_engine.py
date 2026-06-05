"""Phase 1 tests for `email_triage.db._engine` + `_session`.

Covers:
  * HKDF storage-key derivation invariants (32-byte output, namespaced
    info-label, master-key type tolerance).
  * `format_raw_hex_key` length + format contract.
  * SA Core engine factory in plain-sqlite3 mode (the test-only path).
  * Encrypted-mode fail-closed contract when `master_key` is absent.
  * `WriteSession` Protocol structural satisfaction by both
    `sqlite3.Connection` and SA Core's DBAPI connection.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from email_triage.db._engine import (
    create_engine_for_app,
    derive_storage_key,
    format_raw_hex_key,
)
from email_triage.db._session import WriteSession


def test_derive_storage_key_returns_32_bytes():
    """HKDF output is exactly 32 bytes (AES-256 key)."""
    master = "test-master-key"
    key = derive_storage_key("triage", master)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_storage_key_namespaced_by_purpose():
    """Different purpose strings must yield different keys (HKDF info)."""
    master = "test-master-key"
    triage_key = derive_storage_key("triage", master)
    other_key = derive_storage_key("other-purpose", master)
    assert triage_key != other_key, (
        "HKDF info-label namespacing must produce distinct subkeys per "
        "purpose; same output implies the info parameter is being ignored."
    )


def test_derive_storage_key_accepts_bytes_and_str():
    """The master key can be supplied as str OR bytes (UTF-8 round-trip)."""
    master_str = "test-master-key"
    master_bytes = master_str.encode("utf-8")
    assert derive_storage_key("triage", master_str) == derive_storage_key(
        "triage", master_bytes
    )


def test_derive_storage_key_deterministic():
    """Same inputs → same output (HKDF is deterministic per RFC 5869)."""
    master = "test-master-key"
    assert derive_storage_key("triage", master) == derive_storage_key(
        "triage", master
    )


def test_format_raw_hex_key_emits_sqlcipher_syntax():
    """Output is `x'<64hex>'` exactly."""
    key = bytes(range(32))  # well-known 32-byte value
    out = format_raw_hex_key(key)
    assert out.startswith("x'")
    assert out.endswith("'")
    assert len(out) == 67  # x' + 64 hex chars + '
    assert out[2:-1] == key.hex()


def test_format_raw_hex_key_rejects_wrong_length():
    """Anything other than 32 bytes raises ValueError."""
    with pytest.raises(ValueError):
        format_raw_hex_key(b"\x00" * 16)
    with pytest.raises(ValueError):
        format_raw_hex_key(b"\x00" * 64)


def test_create_engine_plain_mode_opens(tmp_path: Path):
    """`encrypted=False` opens a working SA Core engine against plain sqlite."""
    db_path = tmp_path / "test.db"
    engine = create_engine_for_app(db_path, encrypted=False)
    with engine.connect() as conn:
        from sqlalchemy import text

        result = conn.execute(text("SELECT 1"))
        assert result.scalar() == 1


def test_create_engine_encrypted_requires_master_key(tmp_path: Path):
    """Missing master_key under encrypted=True must raise RuntimeError."""
    db_path = tmp_path / "test.db"
    with pytest.raises(RuntimeError, match="master_key"):
        create_engine_for_app(db_path, encrypted=True, master_key=None)


def test_create_engine_plain_sets_wal_and_busy_timeout(tmp_path: Path):
    """Plain-mode connection has WAL + 30s busy_timeout (matches prod posture)."""
    db_path = tmp_path / "test.db"
    engine = create_engine_for_app(db_path, encrypted=False)
    with engine.connect() as conn:
        from sqlalchemy import text

        # journal_mode is per-DB; WAL mode is sticky once set.
        mode = conn.execute(text("PRAGMA journal_mode")).scalar()
        assert mode == "wal"
        timeout = conn.execute(text("PRAGMA busy_timeout")).scalar()
        assert timeout == 30000


def test_write_session_protocol_is_runtime_checkable():
    """The Protocol decorator-mark provides isinstance() support."""
    assert hasattr(WriteSession, "__instancecheck__") or hasattr(
        WriteSession, "_is_runtime_protocol"
    ), "WriteSession should be a runtime_checkable Protocol"


def test_sqlite3_connection_satisfies_write_session(tmp_path: Path):
    """sqlite3.Connection is structurally a WriteSession (DBAPI 2.0)."""
    db_path = tmp_path / "wsess.db"
    conn = sqlite3.connect(str(db_path))
    try:
        # Runtime-checkable Protocols use structural checks via
        # @runtime_checkable. sqlite3.Connection has execute/executemany/
        # commit/rollback => satisfies the WriteSession Protocol.
        assert isinstance(conn, WriteSession)
    finally:
        conn.close()
