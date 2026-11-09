"""T1.1 — the ENCRYPTED branch of ``backup._verify_snapshot_file``, executed for real.

Why this file exists: the encrypted ``.etbk`` / snapshot restorability gate
(``backup.py::_verify_snapshot_file`` encrypted branch + ``_cipher_check_clean``)
had NO executing test. ``test_backup_fail_closed`` forces the PLAINTEXT branch
(``dedicated_conn_is_encrypted()->False``) and ``test_db_snapshot`` tests only the
isolated ``_cipher_check_clean([])`` helper — so the real SQLCipher
``PRAGMA cipher_integrity_check`` path never ran. That untested branch produced
THREE prod backup bugs (``e39c8e2`` keyword-only TypeError, ``fe13c37`` the
``cipher_integrity_check`` "empty == clean" inversion that rejected every clean
encrypted snapshot, ``5c46dce`` the schema-version misread).

These run ONLY where a real SQLCipher build exists: ``importorskip`` skips them
on a host without ``sqlcipher3`` (e.g. the Windows workstation). CI runs them:
``.github/workflows/tests.yml`` installs ``.[dev,encryption]`` (the PyPI
``sqlcipher3==0.6.2`` manylinux wheel; SQLCipher 4.12.0 community in the
2026-10-06 CI log), asserts ``PRAGMA cipher_version`` is 4.x, and runs
``pytest tests/``, then re-runs this file with ``-rA`` and fails on any skip.
(Corrected 2026-10-02, punch 556 / hipaa panel B1: this
docstring used to say no CI job ran the unit suite, which stopped being true
when ``tests.yml`` gained its encryption install.) CI exercises the wheel's
SQLCipher build, not the image's source-built one; run them in the image to cover
that. They build a REAL encrypted SQLCipher DB, run the real
encrypted verify branch CLEAN (the previously-uncovered happy path), then damage
it and assert the gate rejects fail-closed. Mirrors the established sqlcipher test
pattern in ``tests/test_db_migrate.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("sqlcipher3")

from email_triage.backup import BackupError, _verify_snapshot_file
from email_triage.db._engine import (
    _make_encrypted_conn,
    reset_dedicated_conn_encryption,
    set_dedicated_conn_encryption,
)

MASTER_KEY = "t1.1-encrypted-verify-master-key-0123456789abcdef"


@pytest.fixture
def encrypted_context():
    """Stamp the boot context so ``_verify_snapshot_file`` takes the ENCRYPTED
    branch and ``open_dedicated_encrypted_conn_readish`` uses ``MASTER_KEY``.
    Reset on teardown so the encrypted context can't leak into other tests."""
    set_dedicated_conn_encryption(encrypted=True, master_key=MASTER_KEY)
    try:
        yield
    finally:
        reset_dedicated_conn_encryption()


def _make_encrypted_db(path: Path) -> None:
    """A real, traversable encrypted SQLCipher DB at ``path`` — several pages of
    data so a mid-file byte-flip lands in a data page (faults
    ``cipher_integrity_check``) rather than the page-1 salt (open failure)."""
    conn = _make_encrypted_conn(str(path), MASTER_KEY, purpose="triage")
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t (v) VALUES (?)", [("x" * 200,) for _ in range(200)]
        )
        conn.commit()
    finally:
        conn.close()


def test_clean_encrypted_snapshot_verifies_ok(tmp_path, encrypted_context):
    """The previously-UNCOVERED happy path: a clean encrypted snapshot returns
    ``"ok"`` — exercises ``cipher_integrity_check`` (empty == clean, the fe13c37
    fix) + the full ``integrity_check`` + the ``sqlite_master`` sentinel, all on
    the real SQLCipher branch (not the plaintext branch the other tests force)."""
    db = tmp_path / "snap.db"
    _make_encrypted_db(db)
    assert _verify_snapshot_file(db) == "ok"


def test_damaged_encrypted_snapshot_is_rejected(tmp_path, encrypted_context):
    """A byte-flipped encrypted snapshot fails the gate (fail-closed). Proves the
    gate actually REJECTS a corrupt encrypted DB — pre-fe13c37 the inverted
    ``_cipher_check_clean`` mis-read the clean case; this guards the rejection
    edge so a future regression can't silently pass a damaged snapshot."""
    db = tmp_path / "snap.db"
    _make_encrypted_db(db)
    raw = bytearray(db.read_bytes())
    raw[len(raw) - 64] ^= 0xFF  # flip a byte in a late data page, not the salt
    db.write_bytes(raw)
    with pytest.raises(BackupError):
        _verify_snapshot_file(db)


def test_truncated_encrypted_snapshot_is_rejected(tmp_path, encrypted_context):
    """A truncated encrypted file is NORMALISED to ``BackupError`` (the open/query
    failure must fail closed uniformly, not leak a raw sqlcipher exception)."""
    db = tmp_path / "snap.db"
    _make_encrypted_db(db)
    raw = db.read_bytes()
    db.write_bytes(raw[: len(raw) // 2])
    with pytest.raises(BackupError):
        _verify_snapshot_file(db)
