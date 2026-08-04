"""Phase 4 tests for the SQLCipher encrypted-boot wiring.

Covers the dev-testable surface of the encrypted-boot contract — the
parts that do NOT require the ``sqlcipher3`` binary (the ``encryption``
extra is Linux/container only and is NOT installed on the Windows dev
box). The real encrypted-open / file-header-is-ciphertext checks are
deferred to the Phase 6 the deploy host-bake; any test here that needs the actual
binary is guarded with ``pytest.importorskip("sqlcipher3")``.

What IS exercised on dev:

  * flag resolution: ``EMAIL_TRIAGE_DB_ENCRYPTION`` env override +
    ``persistence.encryption_enabled`` YAML field, including the
    "unrecognized value defers to YAML" safety;
  * fail-closed contract: encryption requested + sqlcipher3 absent ->
    RuntimeError; encryption requested + master key absent ->
    RuntimeError; HIPAA + encryption requested + both gaps -> RuntimeError;
  * plain path: flag off -> contract returns False (plaintext), no raise,
    even in HIPAA mode (loud advisory, not a hard fail);
  * bootstrap-order sanity: ``read_bootstrap_master_key`` reads the key
    from the bootstrap backend WITHOUT a DB connection (the ordering the
    encrypted path depends on);
  * ``init_db`` plaintext path still works unchanged after the
    ``_bootstrap_schema`` refactor.
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
import types

import pytest

import email_triage.triage_logging as _triage_logging
from email_triage.db import _engine
from email_triage.db._engine import (
    enforce_db_encryption_boot_contract,
    resolve_db_encryption,
    sqlcipher3_available,
)

_ENV_VAR = "EMAIL_TRIAGE_DB_ENCRYPTION"


def _cfg(*, encryption_enabled: bool = False):
    """Minimal config-shaped object — the contract only reads
    ``config.persistence.encryption_enabled``."""
    return types.SimpleNamespace(
        persistence=types.SimpleNamespace(
            encryption_enabled=encryption_enabled
        )
    )


# ---------------------------------------------------------------------------
# Flag resolution
# ---------------------------------------------------------------------------


def test_resolve_defaults_off(monkeypatch):
    monkeypatch.delenv(_ENV_VAR, raising=False)
    assert resolve_db_encryption(_cfg(encryption_enabled=False)) is False


def test_resolve_yaml_field_on(monkeypatch):
    monkeypatch.delenv(_ENV_VAR, raising=False)
    assert resolve_db_encryption(_cfg(encryption_enabled=True)) is True


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on", " On "])
def test_resolve_env_override_true(monkeypatch, val):
    monkeypatch.setenv(_ENV_VAR, val)
    # Env override wins even when YAML says off.
    assert resolve_db_encryption(_cfg(encryption_enabled=False)) is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "OFF"])
def test_resolve_env_override_false(monkeypatch, val):
    monkeypatch.setenv(_ENV_VAR, val)
    # Env override wins even when YAML says on.
    assert resolve_db_encryption(_cfg(encryption_enabled=True)) is False


def test_resolve_env_unrecognized_defers_to_yaml(monkeypatch):
    """A typo'd env value must NOT silently disable encryption — it
    falls through to the YAML field instead of being treated as falsy."""
    monkeypatch.setenv(_ENV_VAR, " trueish-typo ")
    assert resolve_db_encryption(_cfg(encryption_enabled=True)) is True
    assert resolve_db_encryption(_cfg(encryption_enabled=False)) is False


# ---------------------------------------------------------------------------
# Fail-closed contract — encryption requested
# ---------------------------------------------------------------------------


def test_contract_plain_when_flag_off_non_hipaa(monkeypatch, caplog):
    """Flag off + non-HIPAA = plaintext, no raise (the common case) — but a loud
    general PLAINTEXT advisory now fires (operator 2026-06-11: "the default
    should be encrypted anyway; warn on NOT encrypted"). Not fatal."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = False  # autouse fixture restores
    with caplog.at_level("WARNING"):
        result = enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=False), master_key_available=True
        )
    assert result is False
    assert any(
        "opening in PLAINTEXT" in r.message for r in caplog.records
    ), "expected the general plaintext advisory on a non-HIPAA plaintext boot"
    # ...and NOT the HIPAA-specific advisory (this isn't HIPAA mode).
    assert not any(
        "HIPAA mode is ON" in r.message for r in caplog.records
    )


def test_contract_plain_when_flag_off_hipaa_is_advisory_not_fatal(
    monkeypatch, caplog
):
    """HIPAA mode + flag OFF must NOT hard-fail (would break every
    existing plaintext HIPAA install on upgrade) — it logs a loud
    advisory and returns plaintext."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = True
    with caplog.at_level("WARNING"):
        result = enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=False), master_key_available=True
        )
    assert result is False
    assert any(
        "HIPAA mode is ON but persistence.encryption_enabled is" in r.message
        for r in caplog.records
    ), "expected the plaintext-HIPAA advisory warning"


def test_contract_fail_closed_when_sqlcipher_absent(monkeypatch):
    """Encryption requested but sqlcipher3 not importable -> RuntimeError,
    NEVER a silent plaintext fallback. This is the dev-box reality
    (sqlcipher3-binary is not installed here)."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = True
    monkeypatch.setattr(_engine, "sqlcipher3_available", lambda: False)
    with pytest.raises(RuntimeError, match="sqlcipher3"):
        enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=True), master_key_available=True
        )


def test_contract_fail_closed_when_master_key_absent(monkeypatch):
    """Encryption requested + sqlcipher3 present but master key missing
    -> RuntimeError. We stub sqlcipher3_available True so the missing-key
    branch is the one that fires."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = True
    monkeypatch.setattr(_engine, "sqlcipher3_available", lambda: True)
    with pytest.raises(RuntimeError, match="master key"):
        enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=True), master_key_available=False
        )


def test_contract_fail_closed_non_hipaa_when_requested(monkeypatch):
    """Even outside HIPAA mode, an explicit encryption request that can't
    be honored fails closed — coming up plaintext would silently violate
    the operator's stated intent."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = False
    monkeypatch.setattr(_engine, "sqlcipher3_available", lambda: False)
    with pytest.raises(RuntimeError):
        enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=True), master_key_available=True
        )


def test_contract_env_override_drives_fail_closed(monkeypatch):
    """The env override alone (YAML off) is enough to demand encryption,
    so the same fail-closed gate fires when the binary is absent."""
    monkeypatch.setenv(_ENV_VAR, "1")
    _triage_logging._hipaa_mode = True
    monkeypatch.setattr(_engine, "sqlcipher3_available", lambda: False)
    with pytest.raises(RuntimeError, match="sqlcipher3"):
        enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=False), master_key_available=True
        )


def test_contract_succeeds_when_everything_present(monkeypatch):
    """Encryption requested + sqlcipher3 importable + master key present
    -> returns True (open encrypted). No binary actually opened; only the
    decision is exercised."""
    monkeypatch.delenv(_ENV_VAR, raising=False)
    _triage_logging._hipaa_mode = True
    monkeypatch.setattr(_engine, "sqlcipher3_available", lambda: True)
    assert (
        enforce_db_encryption_boot_contract(
            _cfg(encryption_enabled=True), master_key_available=True
        )
        is True
    )


# ---------------------------------------------------------------------------
# sqlcipher3 availability probe
# ---------------------------------------------------------------------------


def test_sqlcipher3_available_is_bool():
    """The probe never raises; returns a plain bool. On the dev box this
    is False (the encryption extra is not installed)."""
    assert isinstance(sqlcipher3_available(), bool)


# ---------------------------------------------------------------------------
# §164.312(b) audit-chain re-emit predicate (hipaa-sme condition 2)
# ---------------------------------------------------------------------------


def test_hipaa_plaintext_advisory_applies_matches_contract(monkeypatch):
    """The lifespan re-emit predicate fires in exactly the case the
    contract logs the advisory: HIPAA mode AND encryption NOT requested.
    Mirrors enforce_db_encryption_boot_contract's no-encryption branch so
    the immediate boot warning and the audit-chain re-emit never drift."""
    from email_triage.db._engine import hipaa_plaintext_advisory_applies

    monkeypatch.delenv(_ENV_VAR, raising=False)

    _triage_logging._hipaa_mode = True
    assert hipaa_plaintext_advisory_applies(_cfg(encryption_enabled=False)) is True
    # encryption requested → no plaintext advisory (it would open encrypted)
    assert hipaa_plaintext_advisory_applies(_cfg(encryption_enabled=True)) is False

    _triage_logging._hipaa_mode = False
    # non-HIPAA plaintext is normal; no advisory.
    assert hipaa_plaintext_advisory_applies(_cfg(encryption_enabled=False)) is False


# ---------------------------------------------------------------------------
# Bootstrap-order sanity
# ---------------------------------------------------------------------------


def test_read_bootstrap_master_key_needs_no_db(monkeypatch):
    """The encrypted-boot ordering relies on the master key being
    readable from the bootstrap backend BEFORE the DB is opened. This
    asserts read_bootstrap_master_key constructs a provider + reads the
    key with NO connection argument."""
    from email_triage import secrets as _secrets

    captured = {}

    class _FakeBootstrap:
        def require(self, name):
            captured["required"] = name
            return "fake-master-key-value"

    def _fake_factory(backend, **kwargs):
        captured["backend"] = backend
        return _FakeBootstrap()

    monkeypatch.setattr(_secrets, "create_secrets_provider", _fake_factory)

    cfg = types.SimpleNamespace(
        secrets=types.SimpleNamespace(
            backend="keyfile",
            keyfile_path="/x/key",
            external={},
            master_key_name="ET_MASTER_KEY",
        )
    )
    key = _secrets.read_bootstrap_master_key(cfg)
    assert key == "fake-master-key-value"
    assert captured["backend"] == "keyfile"
    assert captured["required"] == "ET_MASTER_KEY"


def test_bootstrap_secrets_reuses_passed_master_key(monkeypatch):
    """When the caller passes master_key= (the encrypted path, having
    already read it), bootstrap_secrets_from_config must NOT re-read the
    bootstrap backend — it wraps the connection with the supplied key."""
    from email_triage import secrets as _secrets

    def _explode(*a, **k):  # would be called only on a re-read
        raise AssertionError(
            "create_secrets_provider must not be called when master_key "
            "is supplied"
        )

    monkeypatch.setattr(_secrets, "create_secrets_provider", _explode)

    captured = {}

    class _FakeDbSecrets:
        def __init__(self, conn, master_key):
            captured["conn"] = conn
            captured["master_key"] = master_key

    monkeypatch.setattr(_secrets, "DbSecrets", _FakeDbSecrets)

    sentinel_conn = object()
    cfg = types.SimpleNamespace(
        secrets=types.SimpleNamespace(master_key_name="ET_MASTER_KEY")
    )
    _secrets.bootstrap_secrets_from_config(
        sentinel_conn, cfg, master_key="reused-key"
    )
    assert captured["conn"] is sentinel_conn
    assert captured["master_key"] == "reused-key"


# ---------------------------------------------------------------------------
# Plaintext init_db unchanged after the _bootstrap_schema refactor
# ---------------------------------------------------------------------------


def test_init_db_plaintext_still_works(tmp_path):
    """The Phase 4 refactor factored init_db's body into
    _bootstrap_schema; the plaintext path must remain byte-for-byte
    behaviorally identical for the 554+ existing callers."""
    from email_triage.web.db import init_db

    db_file = tmp_path / "plain.db"
    conn = track(init_db(str(db_file)))
    try:
        # WAL + foreign_keys set by _bootstrap_schema.
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        # Row factory is sqlite3.Row.
        row = conn.execute("SELECT 1 AS one").fetchone()
        assert row["one"] == 1
        # A core table the DDL creates exists.
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "flows" in names
        assert "users" in names
    finally:
        conn.close()


def test_init_db_memory_default_unchanged():
    """init_db() with no args still opens an in-memory DB + bootstraps."""
    from email_triage.web.db import init_db

    conn = track(init_db())
    try:
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "flows" in names
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Real encrypted-open — DEFERRED to Phase 6 the deploy host-bake (needs the binary)
# ---------------------------------------------------------------------------


def test_real_encrypted_open_roundtrip(tmp_path):
    """Container-only: open an encrypted DB, write+read, confirm the
    on-disk file is NOT a plaintext SQLite header. Skipped on dev where
    sqlcipher3-binary is absent; runs in the Phase 6 the deploy host bake."""
    pytest.importorskip("sqlcipher3")
    from email_triage.web.db import init_db_encrypted

    db_file = tmp_path / "enc.db"
    conn = init_db_encrypted(str(db_file), "container-bake-master-key")
    try:
        conn.execute("CREATE TABLE t (x TEXT)")
        conn.execute("INSERT INTO t (x) VALUES (?)", ("phi-secret",))
        conn.commit()
        assert conn.execute("SELECT x FROM t").fetchone()[0] == "phi-secret"
    finally:
        conn.close()

    # On-disk header must NOT be the plaintext "SQLite format 3\0" magic.
    head = db_file.read_bytes()[:16]
    assert head != b"SQLite format 3\x00", (
        "encrypted file leaked a plaintext SQLite header"
    )

    # A stdlib sqlite3 open must reject the encrypted file.
    with pytest.raises(sqlite3.DatabaseError):
        plain = sqlite3.connect(str(db_file))
        plain.execute("SELECT x FROM t").fetchone()


# ---------------------------------------------------------------------------
# N-17 —  dedicated-connection encryption propagation
# ---------------------------------------------------------------------------
#
# The bake-caught coverage gap: the prior encrypted-roundtrip test
# (above) exercises only the MAIN boot conn. The  dedicated-conn
# openers (audit-chain log handler, acme_jobs writer,  write-lock
# conn) open their OWN connections on the same file — and before N-17 did
# a raw plaintext sqlite3.connect with no PRAGMA key. 3059 plaintext tests
# + the roundtrip test passed while the encrypted bake crashed at the
# audit-chain handler open. These tests close that gap.


@pytest.fixture
def _reset_dedicated_conn_ctx():
    """Ensure the process-level dedicated-conn encryption context is clean
    before AND after each test that stamps it (it is process-global)."""
    from email_triage.db._engine import reset_dedicated_conn_encryption

    reset_dedicated_conn_encryption()
    yield
    reset_dedicated_conn_encryption()


def test_dedicated_conn_default_is_plaintext(_reset_dedicated_conn_ctx):
    """With no boot stamp, the dedicated-conn context resolves plaintext —
    every existing (non-encrypted) install is unaffected by N-17."""
    from email_triage.db._engine import dedicated_conn_is_encrypted

    assert dedicated_conn_is_encrypted() is False


def test_set_dedicated_conn_encryption_requires_key():
    """encrypted=True with no master key is a programmer error — the boot
    contract guarantees a key in encrypted mode (§164.312(a)(2)(iv))."""
    from email_triage.db._engine import (
        reset_dedicated_conn_encryption,
        set_dedicated_conn_encryption,
    )

    try:
        with pytest.raises(RuntimeError, match="master_key"):
            set_dedicated_conn_encryption(encrypted=True, master_key=None)
    finally:
        reset_dedicated_conn_encryption()


def test_open_dedicated_conn_plaintext_pragmas(
    tmp_path, _reset_dedicated_conn_ctx
):
    """Plaintext path: open_dedicated_conn sets the same WAL +
    busy_timeout=30000 + foreign_keys PRAGMAs the pre-N-17 openers set
    inline — byte-behaviour parity for every plaintext install."""
    from email_triage.db._engine import open_dedicated_conn

    conn = open_dedicated_conn(str(tmp_path / "p.db"))
    try:
        assert type(conn).__module__ == "sqlite3"
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


def test_open_dedicated_conn_selects_encrypted_when_stamped(
    tmp_path, _reset_dedicated_conn_ctx
):
    """ENCRYPTED PATH (container-only — needs sqlcipher3-binary; runs in
    the Phase 6 the deploy host bake). After the boot stamps encrypted=True, every
    open_dedicated_conn returns a sqlcipher3 connection on the SAME file
    the main encrypted conn created — proving the  dedicated conns
    self-select encryption like the main conn (N-17)."""
    pytest.importorskip("sqlcipher3")
    from email_triage.db._engine import (
        open_dedicated_conn,
        set_dedicated_conn_encryption,
    )
    from email_triage.web.db import init_db_encrypted

    master_key = "container-bake-master-key"
    db_file = tmp_path / "enc.db"

    # Main boot conn creates the encrypted file + schema.
    main = init_db_encrypted(str(db_file), master_key)
    main.close()

    # Stamp the context the way app.lifespan does post-boot-decision.
    set_dedicated_conn_encryption(encrypted=True, master_key=master_key)

    # A dedicated conn now opens encrypted + can read the existing schema.
    conn = open_dedicated_conn(str(db_file), check_same_thread=False)
    try:
        assert type(conn).__module__ == "sqlcipher3.dbapi2", (
            "dedicated conn did not self-select the encrypted driver"
        )
        # Reads the schema written by the main encrypted conn — proves
        # the SQLCipher key was applied (a plaintext open would raise).
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "log_entries" in names
    finally:
        conn.close()


def test_audit_chain_handler_writes_through_encrypted_conn(
    tmp_path, _reset_dedicated_conn_ctx, monkeypatch
):
    """THE bake-gap test (container-only — needs sqlcipher3-binary; runs
    in the Phase 6 the deploy host bake).

    Wires the §164.312(b) audit-chain log handler against an ENCRYPTED DB
    via the real add_sqlite_handler path, emits a log record, flushes, and
    asserts BOTH:
      (1) the handler's dedicated conn is a sqlcipher3 connection
          (``__module__ == "sqlcipher3.dbapi2"``) — i.e. it opened
          encrypted, not raw-plaintext-crash; and
      (2) the row was written AND the hash-chain verifies end-to-end on
          the encrypted file.

    This is the exact path the prior roundtrip test did NOT exercise: it
    only opened the main conn, so the dedicated-conn encryption bypass
    slipped through 3059 plaintext tests and crashed the bake."""
    pytest.importorskip("sqlcipher3")
    import logging

    from email_triage.db._engine import set_dedicated_conn_encryption
    from email_triage.triage_logging import (
        SQLiteLogHandler,
        add_sqlite_handler,
    )
    from email_triage.web.db import init_db_encrypted

    master_key = "container-bake-master-key"
    db_file = tmp_path / "enc.db"

    # Boot: open the main encrypted conn (creates schema incl. log_entries),
    # then stamp the dedicated-conn context exactly as the lifespan does.
    main_conn = init_db_encrypted(str(db_file), master_key)
    set_dedicated_conn_encryption(encrypted=True, master_key=master_key)

    root = logging.getLogger("email_triage")
    pre_handlers = list(root.handlers)
    try:
        # Real production wiring: add_sqlite_handler resolves the file path
        # from main_conn, then opens its OWN dedicated conn via
        # _open_dedicated_log_conn -> open_dedicated_conn (now encrypted).
        add_sqlite_handler(main_conn)

        sqlite_handlers = [
            h for h in root.handlers if isinstance(h, SQLiteLogHandler)
        ]
        assert sqlite_handlers, "add_sqlite_handler attached no handler"
        handler = sqlite_handlers[-1]

        # (1) the handler's conn opened encrypted, not plaintext-crash.
        assert type(handler._conn).__module__ == "sqlcipher3.dbapi2", (
            "audit-chain handler conn is not sqlcipher3 — the  "
            "dedicated-conn encryption bypass (N-17) is still present"
        )

        # (2) emit a real record through the handler + flush to the
        # encrypted file.
        logger = logging.getLogger("email_triage.test_n17")
        logger.setLevel(logging.INFO)
        logger.info("N-17 encrypted audit-chain probe")
        handler.flush()

        # The row landed AND the hash-chain verifies on the encrypted DB.
        from email_triage.db.audit import verify_log_chain

        count = main_conn.execute(
            "SELECT COUNT(*) FROM log_entries"
        ).fetchone()[0]
        assert count >= 1, "no log_entries row written through encrypted conn"

        result = verify_log_chain(main_conn)
        assert result["first_break_id"] is None, (
            f"audit hash-chain broke on the encrypted DB: {result}"
        )
    finally:
        # Detach any handler we added; restore the root handler list.
        for h in list(root.handlers):
            if h not in pre_handlers:
                root.removeHandler(h)
                try:
                    h.close()
                except Exception:
                    pass
        main_conn.close()
