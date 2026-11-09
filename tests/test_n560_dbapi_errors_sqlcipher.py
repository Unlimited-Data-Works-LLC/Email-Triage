"""N-560 / punch 560 — DB-error handlers fire on a REAL SQLCipher connection.

The structural pin (``test_n560_dbapi_error_funnel_ssot_pin.py``) proves every
matcher routes through ``email_triage._dbapi_errors``. These tests prove the
funnel's purpose on the real driver: an error raised by a ``sqlcipher3``
connection is caught where the stdlib class alone would let it escape.

The sqlcipher3 arms ``importorskip`` (no Windows wheel). CI installs
``sqlcipher3==0.6.2`` through the ``encryption`` extra, so they run there; the
plaintext arm runs everywhere.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys

import pytest

from _pin_harness import tree_src_env


def _encrypted_conn(tmp_path):
    from email_triage.db._engine import _make_encrypted_conn

    return _make_encrypted_conn(str(tmp_path / "n560.db"), "n560-master-key")


def test_sqlcipher_classes_do_not_inherit_from_stdlib():
    """The premise. If a future sqlcipher3 roots its hierarchy at sqlite3's,
    this goes red and the funnel's driver arm becomes redundant (not wrong)."""
    dbapi = pytest.importorskip("sqlcipher3.dbapi2")
    for name in ("Error", "DatabaseError", "OperationalError",
                 "IntegrityError", "ProgrammingError"):
        assert not issubclass(getattr(dbapi, name), getattr(sqlite3, name)), name


def test_missing_table_escapes_stdlib_handler_but_not_the_funnel(tmp_path):
    pytest.importorskip("sqlcipher3")
    from email_triage._dbapi_errors import DB_OPERATIONAL_ERRORS

    conn = _encrypted_conn(tmp_path)
    try:
        with pytest.raises(Exception) as escaped:
            try:
                conn.execute("SELECT 1 FROM no_such_table")
            except sqlite3.OperationalError:  # the pre-560 spelling
                pytest.fail("stdlib class matched a sqlcipher3 error")
        assert type(escaped.value).__module__.startswith("sqlcipher3")

        try:
            conn.execute("SELECT 1 FROM no_such_table")
        except DB_OPERATIONAL_ERRORS:
            pass
    finally:
        conn.close()


def test_read_schema_version_on_encrypted_db_without_bookkeeping(tmp_path):
    """Row 560's reported case: a fresh encrypted DB has no
    ``schema_migrations``. Before the fix this raised
    ``sqlcipher3.dbapi2.OperationalError``; it must report version 0."""
    pytest.importorskip("sqlcipher3")
    from email_triage.version import read_schema_version

    conn = _encrypted_conn(tmp_path)
    try:
        assert read_schema_version(conn) == 0
    finally:
        conn.close()


def test_read_schema_version_on_plaintext_db_without_bookkeeping():
    from email_triage.version import read_schema_version

    conn = sqlite3.connect(":memory:")
    try:
        assert read_schema_version(conn) == 0
    finally:
        conn.close()


def _assert_stale_fk_row_is_written_once_and_chained(conn):
    """One stale-FK access event adds exactly ONE access_log row (the coerced
    re-chain, no double write), and the HMAC chain is intact afterwards: the
    failed INSERT left the tail unchanged inside the caller's transaction
    (punch 560 panel: DA M-a2, db-sme item (a), hipaa-sme H1)."""
    from email_triage.db._helpers import apply_compatible_row_factory
    from email_triage.db.audit import verify_audit_chain
    from email_triage.web.db import list_access_events, record_access_event

    apply_compatible_row_factory(conn)
    before = conn.execute("SELECT COUNT(*) FROM access_log").fetchone()[0]
    rid = record_access_event(
        conn,
        actor_user_id=None,
        method="GET",
        route="/api/v1/accounts/99999/bulk/mail",
        account_id=99999,
        message_id=None,
        status_code=404,
        outcome="not_found",
    )
    assert rid and rid > 0
    after = conn.execute("SELECT COUNT(*) FROM access_log").fetchone()[0]
    assert after == before + 1
    latest = list_access_events(conn, limit=1)[0]
    assert latest["account_id"] is None
    assert "stale_account_id=99999" in (latest["detail"] or "")
    chain = verify_audit_chain(conn, "access_log")
    assert chain["intact"] is True, chain


def test_access_event_fk_coercion_on_encrypted_db(tmp_path):
    """The §164.312(b) path. A request naming a stale account_id violates the
    access_log FK; ``record_access_event`` (through ``record_access_event_txn``)
    must coerce it to NULL and still write the row. Before the fix the
    IntegrityError handler was dead on an encrypted DB, so production's
    never-raise audit funnel swallowed the failure and the access went
    UNLOGGED."""
    pytest.importorskip("sqlcipher3")
    from email_triage.web.db import init_db_encrypted

    conn = init_db_encrypted(str(tmp_path / "n560-full.db"), "n560-master-key")
    try:
        _assert_stale_fk_row_is_written_once_and_chained(conn)
    finally:
        conn.close()


def test_access_event_fk_coercion_on_plaintext_db(tmp_path):
    """The same contract on the stdlib driver, so the row-count and chain
    asserts run on every platform. It cannot catch a stdlib-only matcher (the
    stdlib class matches a stdlib error); that is the encrypted arm's job."""
    from email_triage.web.db import init_db

    conn = init_db(str(tmp_path / "n560-plain.db"))
    try:
        _assert_stale_fk_row_is_written_once_and_chained(conn)
    finally:
        conn.close()


def test_driver_load_failure_degrades_to_stdlib_only():
    """The funnel imports sqlcipher3 eagerly at module load, unlike
    ``db/_engine.py``. A driver whose shared object fails to load can raise
    ``OSError`` rather than ``ImportError``; the funnel must then degrade to
    stdlib-only so a plaintext install still boots (punch 560 panel,
    devils-advocate F4). Run in a subprocess so the broken import cannot
    leak into this process's module cache."""
    code = (
        "import sys\n"
        "class _BrokenDriver:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'sqlcipher3' or name.startswith('sqlcipher3.'):\n"
        "            raise OSError('libsqlcipher.so.0: cannot open shared object file')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _BrokenDriver())\n"
        "import sqlite3\n"
        "import email_triage._dbapi_errors as funnel\n"
        "assert funnel._sqlcipher_dbapi is None\n"
        "assert funnel.DB_ERRORS == (sqlite3.Error,)\n"
        "print('degraded-ok')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=tree_src_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "degraded-ok" in proc.stdout
