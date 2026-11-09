"""Punch 418: what an existing database does when the master key is read stripped.

Hard constraint from the row: a database keyed with the RAW value (trailing newline) must not
become unopenable in a way an operator cannot read. Both edges are held:

  * a database keyed with the stripped key opens when the secret still carries the newline
    (the new funnel strips it, so both derive the same SQLCipher key);
  * a database keyed WITH the newline refuses with the typed ``EncryptedDbKeyRefused``,
    never a bare ``file is not a database``, and is never retried with the raw value (the
    audit HMAC key and the Fernet key would then disagree with the storage key).

The typed translation is held without SQLCipher (a fake driver, runs everywhere); the two
real-database edges need ``sqlcipher3`` and skip where it is absent (CI / the image run them).
"""

from __future__ import annotations

import sqlite3
import sys
import types
from types import SimpleNamespace

import pytest

from email_triage.db import _engine as _eng
from email_triage.db._engine import _make_encrypted_conn

GENERATED_KEY = "Zm9vYmFyLWdlbmVyYXRlZC10ZXN0LWtleS1ub3QtYS1yZWFsLW9uZQ=="


class _FakeConn:
    def __init__(self, fail_on: str, exc: BaseException):
        self.fail_on, self.exc, self.closed = fail_on, exc, False

    def execute(self, sql, *args):
        if self.fail_on in sql:
            raise self.exc
        return SimpleNamespace(fetchone=lambda: (0,))

    def close(self):
        self.closed = True


def _install_fake_driver(monkeypatch, conn: _FakeConn) -> None:
    dbapi2 = types.ModuleType("sqlcipher3.dbapi2")
    dbapi2.connect = lambda *a, **k: conn
    pkg = types.ModuleType("sqlcipher3")
    pkg.dbapi2 = dbapi2
    monkeypatch.setitem(sys.modules, "sqlcipher3", pkg)
    monkeypatch.setitem(sys.modules, "sqlcipher3.dbapi2", dbapi2)


@pytest.mark.parametrize("read_only,fail_on", [(False, "journal_mode"), (True, "sqlite_master")])
def test_a_wrong_key_is_the_typed_refusal_not_a_bare_driver_error(monkeypatch, read_only, fail_on):
    conn = _FakeConn(fail_on, sqlite3.DatabaseError("file is not a database"))
    _install_fake_driver(monkeypatch, conn)
    with pytest.raises(_eng.EncryptedDbKeyRefused) as info:
        _make_encrypted_conn("/data/triage.db", GENERATED_KEY, read_only=read_only)
    assert conn.closed, "the half-open handle must be closed"
    assert isinstance(info.value.__cause__, sqlite3.DatabaseError)
    text = str(info.value)
    assert "triage.db" in text and "punch 418" in text and "trailing newline" in text
    assert GENERATED_KEY not in text, "the refusal must carry no key material"


def test_the_refusal_names_the_remedy_that_works_today():
    """Cycle P hipaa P4 S1: "restore the original key" cannot work (the funnel strips any
    restored newline). The message names the remedy that does: the last release before
    v0.2.0, which reads the key byte-for-byte, until the punch 831 re-key command ships,
    and the admin-guide section that explains it. No key material, no sha."""
    from pathlib import Path

    text = str(_eng.EncryptedDbKeyRefused("/data/triage.db"))
    assert "restore the original key" not in text
    assert "un-normalised master key" in text
    assert "last release before v0.2.0" in text and "byte-for-byte" in text
    assert "punch 831" in text
    assert _eng.LEGACY_MASTER_KEY_RUNBOOK in text
    runbook = Path(__file__).resolve().parents[1] / _eng.LEGACY_MASTER_KEY_RUNBOOK
    body = runbook.read_text(encoding="utf-8")
    assert "EncryptedDbKeyRefused" in body and "punch 831" in body
    assert "rekey-legacy-master-key" in body


def test_any_other_driver_error_is_not_retyped(monkeypatch):
    conn = _FakeConn("journal_mode", sqlite3.OperationalError("disk I/O error"))
    _install_fake_driver(monkeypatch, conn)
    with pytest.raises(sqlite3.OperationalError):
        _make_encrypted_conn("/data/triage.db", GENERATED_KEY)
    assert conn.closed


def _keyed_db(path, key: str) -> None:
    conn = _make_encrypted_conn(str(path), key)
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.commit()
    conn.close()


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(secrets=SimpleNamespace(
        backend="env", keyfile_path="", external={}, master_key_name="ET_MASTER_KEY",
    ))


def test_a_database_keyed_with_the_stripped_key_opens_when_the_secret_has_a_newline(
    tmp_path, monkeypatch
):
    pytest.importorskip("sqlcipher3")
    from email_triage.secrets import read_bootstrap_master_key

    db = tmp_path / "triage.db"
    _keyed_db(db, GENERATED_KEY)
    monkeypatch.setenv("ET_MASTER_KEY", GENERATED_KEY + "\n")
    conn = _make_encrypted_conn(str(db), read_bootstrap_master_key(_cfg()))
    assert conn.execute("SELECT count(*) FROM t").fetchone()[0] == 0
    conn.close()


def test_a_database_keyed_with_the_raw_newline_refuses_with_the_typed_error(tmp_path, monkeypatch):
    pytest.importorskip("sqlcipher3")
    from email_triage.secrets import read_bootstrap_master_key

    db = tmp_path / "triage.db"
    _keyed_db(db, GENERATED_KEY + "\n")  # the pre-418 write side: raw, newline included
    monkeypatch.setenv("ET_MASTER_KEY", GENERATED_KEY + "\n")
    with pytest.raises(_eng.EncryptedDbKeyRefused):
        _make_encrypted_conn(str(db), read_bootstrap_master_key(_cfg()))
    with pytest.raises(_eng.EncryptedDbKeyRefused):
        _make_encrypted_conn(str(db), read_bootstrap_master_key(_cfg()), read_only=True)
