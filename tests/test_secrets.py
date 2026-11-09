"""Tests for the secrets provider abstraction layer."""

import os
import tempfile
from pathlib import Path

import pytest

from email_triage.secrets import (
    ContainerSecrets,
    EnvSecrets,
    SecretNotFound,
    create_secrets_provider,
)


class TestContainerSecrets:
    def test_reads_file(self, tmp_path: Path):
        (tmp_path / "SMTP_PASSWORD").write_text("s3cret\n")
        provider = ContainerSecrets(tmp_path)
        assert provider.get("SMTP_PASSWORD") == "s3cret"

    def test_missing_returns_none(self, tmp_path: Path):
        provider = ContainerSecrets(tmp_path)
        assert provider.get("NONEXISTENT") is None

    def test_list_keys(self, tmp_path: Path):
        (tmp_path / "KEY_A").write_text("a")
        (tmp_path / "KEY_B").write_text("b")
        provider = ContainerSecrets(tmp_path)
        keys = provider.list_keys()
        assert set(keys) == {"KEY_A", "KEY_B"}

    def test_set_raises(self, tmp_path: Path):
        provider = ContainerSecrets(tmp_path)
        with pytest.raises(NotImplementedError):
            provider.set("KEY", "value")

    def test_require_raises_on_missing(self, tmp_path: Path):
        provider = ContainerSecrets(tmp_path)
        with pytest.raises(SecretNotFound):
            provider.require("MISSING")

    def test_require_returns_on_found(self, tmp_path: Path):
        (tmp_path / "API_KEY").write_text("the-key")
        provider = ContainerSecrets(tmp_path)
        assert provider.require("API_KEY") == "the-key"


class TestEnvSecrets:
    def test_reads_env(self, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_XYZ", "hello")
        provider = EnvSecrets()
        assert provider.get("TEST_SECRET_XYZ") == "hello"

    def test_missing_returns_none(self):
        provider = EnvSecrets()
        assert provider.get("DEFINITELY_NOT_SET_12345") is None

    def test_set_raises(self):
        provider = EnvSecrets()
        with pytest.raises(NotImplementedError):
            provider.set("KEY", "value")


class TestFactory:
    def test_container_backend(self):
        provider = create_secrets_provider("container", container_path="/tmp/secrets")
        assert isinstance(provider, ContainerSecrets)

    def test_env_backend(self):
        provider = create_secrets_provider("env")
        assert isinstance(provider, EnvSecrets)

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown secrets backend"):
            create_secrets_provider("vault")


class TestDbSecrets:
    """Tests for the runtime DbSecrets provider."""

    @pytest.fixture
    def db(self):
        from email_triage.web.db import init_db
        from _db_tracking import track
        return track(init_db(":memory:"))

    @pytest.fixture
    def master_key(self):
        from email_triage.secrets import DbSecrets
        return DbSecrets.generate_master_key()

    def test_generate_master_key_unique(self):
        from email_triage.secrets import DbSecrets
        k1 = DbSecrets.generate_master_key()
        k2 = DbSecrets.generate_master_key()
        assert k1 != k2

    def test_set_and_get(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("IMAP_PASSWORD", "hunter2")
        assert store.get("IMAP_PASSWORD") == "hunter2"

    def test_get_missing_returns_none(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        assert store.get("NOTHING") is None

    def test_get_undecryptable_raises_typed_error(self, db, master_key):
        """A stored secret that won't decrypt (here: a master-key
        mismatch) raises the typed SecretsDecryptError, not an opaque
        cryptography InvalidToken escaping into callers."""
        from email_triage.secrets import DbSecrets, SecretsDecryptError
        # Encrypt with one key...
        DbSecrets(db, master_key).set("SMTP_PASSWORD", "hunter2")
        # ...read with a different key — the ciphertext is unreadable.
        store = DbSecrets(db, DbSecrets.generate_master_key())
        with pytest.raises(SecretsDecryptError) as exc:
            store.get("SMTP_PASSWORD")
        assert exc.value.key == "SMTP_PASSWORD"

    def test_set_overwrites(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("KEY", "v1")
        store.set("KEY", "v2")
        assert store.get("KEY") == "v2"

    def test_delete(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("KEY", "value")
        assert store.delete("KEY") is True
        assert store.get("KEY") is None
        assert store.delete("KEY") is False  # Already gone.

    def test_list_keys(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("A", "1")
        store.set("B", "2")
        assert store.list_keys() == ["A", "B"]

    def test_ciphertext_not_plaintext_in_db(self, db, master_key):
        """Values must be encrypted at rest — a DB dump must not expose them."""
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("PASSWORD", "plaintext_secret")
        row = db.execute(
            "SELECT ciphertext FROM secrets_store WHERE key = 'PASSWORD'"
        ).fetchone()
        assert "plaintext_secret" not in row["ciphertext"]

    def test_wrong_master_key_fails_to_decrypt(self, db, master_key):
        """Swapping the master key invalidates all stored secrets."""
        from email_triage.secrets import DbSecrets
        store1 = DbSecrets(db, master_key)
        store1.set("KEY", "value")

        other_key = DbSecrets.generate_master_key()
        store2 = DbSecrets(db, other_key)
        # Different Fernet key must not decrypt store1's ciphertext —
        # get() surfaces the typed SecretsDecryptError, not a
        # raw cryptography InvalidToken.
        from email_triage.secrets import SecretsDecryptError
        with pytest.raises(SecretsDecryptError):
            store2.get("KEY")

    def test_require_raises_when_missing(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        with pytest.raises(SecretNotFound):
            store.require("NOT_THERE")

    def test_bootstrap_from_config(self, db, tmp_path: Path, monkeypatch):
        """bootstrap_secrets_from_config wires env → DbSecrets end-to-end."""
        from email_triage.config import TriageConfig
        from email_triage.secrets import (
            DbSecrets, bootstrap_secrets_from_config,
        )

        # H-07: opt into the dev/CI carve-out so the deprecation warning
        # does not noise up the test log. Test exercises the env code
        # path intentionally; the warning would fire otherwise.
        monkeypatch.setenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", "1")
        master_key = DbSecrets.generate_master_key()
        os.environ["TEST_MASTER_KEY"] = master_key
        try:
            cfg = TriageConfig()
            cfg.secrets.backend = "env"
            cfg.secrets.master_key_name = "TEST_MASTER_KEY"
            store = bootstrap_secrets_from_config(db, cfg)
            assert isinstance(store, DbSecrets)
            store.set("FOO", "bar")
            assert store.get("FOO") == "bar"
        finally:
            del os.environ["TEST_MASTER_KEY"]

    def test_rotate_master_key_roundtrip(self, db, master_key):
        """After rotation, all secrets decrypt with the new key."""
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("A", "alpha")
        store.set("B", "beta")

        new_key = DbSecrets.generate_master_key()
        n = store.rotate_master_key(new_key)
        assert n == 2

        # Old Fernet instance was swapped in-place; same store reads fine.
        assert store.get("A") == "alpha"
        assert store.get("B") == "beta"

        # A fresh store using the NEW key also works.
        store2 = DbSecrets(db, new_key)
        assert store2.get("A") == "alpha"

        # A fresh store using the OLD key no longer decrypts — get()
        # surfaces the typed SecretsDecryptError.
        from email_triage.secrets import SecretsDecryptError
        store_old = DbSecrets(db, master_key)
        with pytest.raises(SecretsDecryptError):
            store_old.get("A")

    def test_rotate_master_key_empty_store(self, db, master_key):
        """Rotating an empty store is a no-op that still succeeds."""
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        n = store.rotate_master_key(DbSecrets.generate_master_key())
        assert n == 0

    def test_rotate_master_key_atomic_on_failure(self, db, master_key):
        """Bad new-key input must not leave the DB in a half-rotated state."""
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        store.set("A", "alpha")
        store.set("B", "beta")

        # An invalid Fernet key triggers Fernet to raise at construction.
        with pytest.raises(Exception):
            store.rotate_master_key("not-a-valid-fernet-key")

        # Original key still works, no rows corrupted.
        assert store.get("A") == "alpha"
        assert store.get("B") == "beta"

    def test_rotate_master_key_begin_immediate_before_select(
        self, db, master_key,
    ):
        """.3 — verify the fix's ordering invariant directly:
        BEGIN IMMEDIATE must run BEFORE the SELECT that reads the
        rows-to-rotate set. The previous order (SELECT first, BEGIN
        second) left a TOCTOU window in which a concurrent ``set()``
        could insert / overwrite a row that the rotation had already
        skipped reading; that row stayed encrypted with the old key,
        and the in-memory ``_fernet = new_fernet`` swap then made it
        unreadable.

        This test installs a hooked ``execute`` on the connection
        that records every SQL statement issued during rotation,
        then asserts BEGIN IMMEDIATE precedes the rotation's SELECT.
        """
        from email_triage.secrets import DbSecrets

        store = DbSecrets(db, master_key)
        store.set("A", "alpha")
        store.set("B", "beta")

        executed: list[str] = []
        db.set_trace_callback(
            lambda sql: executed.append(sql.strip().upper())
        )
        try:
            store.rotate_master_key(DbSecrets.generate_master_key())
        finally:
            db.set_trace_callback(None)

        # Find the indices of the rotation's BEGIN and SELECT.
        begin_idx = next(
            (i for i, s in enumerate(executed) if s.startswith("BEGIN")),
            None,
        )
        select_idx = next(
            (
                i for i, s in enumerate(executed)
                if s.startswith("SELECT KEY, CIPHERTEXT FROM")
            ),
            None,
        )
        assert begin_idx is not None, "no BEGIN issued during rotation"
        assert select_idx is not None, (
            "no rotation SELECT seen — test traced the wrong path"
        )
        assert begin_idx < select_idx, (
            f"BEGIN must precede SELECT (begin={begin_idx}, "
            f"select={select_idx}); SELECT-before-BEGIN reintroduces "
            f"the #145.3 TOCTOU window"
        )
        # And the BEGIN must be IMMEDIATE (RESERVED lock) — a plain
        # BEGIN is DEFERRED, which gives no protection against
        # concurrent writers until the first write inside the txn.
        assert "BEGIN IMMEDIATE" in executed[begin_idx], (
            f"rotation must use BEGIN IMMEDIATE, got: "
            f"{executed[begin_idx]}"
        )

    def test_rotate_master_key_concurrent_writers_atomic(self, tmp_path):
        """Companion to the ordering test: spawn a writer thread that
        commits SET operations through a SEPARATE DbSecrets instance
        on the same DB file. With BEGIN IMMEDIATE acquiring RESERVED
        the writer's commits block until rotation finishes; rows
        that land DURING the rotation's hold encrypt with the old
        key on the writer side, and the rotation pass already
        re-encrypted everything in scope.

        Multi-instance rotation is documented as requiring app
        stoppage (see ``rotate_master_key`` docstring) — this test
        therefore restarts the writer's view AFTER rotation and
        verifies the locking guarantee, not the in-memory-key swap.
        """
        import sqlite3
        import threading
        from email_triage.secrets import DbSecrets
        from email_triage.web.db import init_db
        from _db_tracking import track

        db_path = tmp_path / "rotate-lock.db"
        track(init_db(str(db_path)))

        def _open() -> sqlite3.Connection:
            c = track(sqlite3.connect(
                str(db_path), check_same_thread=False, timeout=10.0,
            ))
            c.row_factory = sqlite3.Row
            return c

        master = DbSecrets.generate_master_key()
        rot_conn = _open()
        rot_store = DbSecrets(rot_conn, master)
        for i in range(20):
            rot_store.set(f"K_{i}", f"v_{i}")

        new_master = DbSecrets.generate_master_key()

        # Writer thread: runs in parallel with rotation, but its
        # writes block on the RESERVED lock until rotation commits.
        writer_errs: list[Exception] = []
        finished = threading.Event()

        def _writer():
            try:
                writer_conn = _open()
                writer_store = DbSecrets(writer_conn, master)
                for i in range(20, 30):
                    # Each call commits; SQLite makes it wait until
                    # the rotation's RESERVED lock releases.
                    writer_store.set(f"K_{i}", f"v_{i}")
                writer_conn.close()
            except Exception as e:
                writer_errs.append(e)
            finally:
                finished.set()

        t = threading.Thread(target=_writer, daemon=True)
        t.start()
        rot_store.rotate_master_key(new_master)
        t.join(timeout=15.0)
        assert finished.is_set(), "writer thread hung past timeout"
        assert not writer_errs, f"writer raised: {writer_errs[:3]}"

        # Anything written BEFORE rotation must read cleanly under
        # the new key — the bug's failure mode was these rows being
        # invisible after rotation when a concurrent set() landed in
        # the SELECT-before-BEGIN gap.
        verify_store = DbSecrets(_open(), new_master)
        for i in range(20):
            assert verify_store.get(f"K_{i}") == f"v_{i}"

        rot_conn.close()

    def test_bootstrap_fails_when_master_key_missing(self, db, monkeypatch):
        """No master key in bootstrap store → SecretNotFound."""
        from email_triage.config import TriageConfig
        from email_triage.secrets import bootstrap_secrets_from_config
        # H-07: opt into the dev/CI carve-out so the deprecation warning
        # does not noise up the test log.
        monkeypatch.setenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", "1")
        cfg = TriageConfig()
        cfg.secrets.backend = "env"
        cfg.secrets.master_key_name = "DEFINITELY_NOT_SET_ANYWHERE_XYZ"
        with pytest.raises(SecretNotFound):
            bootstrap_secrets_from_config(db, cfg)


class TestDbSecretsWriteLock:
    """ — every DbSecrets method that touches the shared
    ``sqlite3.Connection`` must hold the process-wide write lock while
    it does so.

    Why a dedicated test, not the  AST guard
    --------------------------------------------
    The  connection-safety guard cannot verify this. ``secrets.py``
    contains no ``async def`` so it is outside the guard's scanned set;
    and ``DbSecrets`` is invoked as ``secrets.<method>()`` — an
    attribute method call on an instance, a shape the guard does not
    resolve (not a connection-like name, not a sqlite method, not a
    bare-name call). The guard going green is necessary but NOT
    sufficient for the DbSecrets portion of  — this is the
    sufficient proof: it instruments the connection and asserts the
    write lock is held *at the moment of every execute/commit*.

    ``DbSecrets`` is a process-wide singleton called from ~23 async
    handlers; an unlocked touch races a request-surface ``db_call``
    worker on the one shared connection → ``sqlite3.InterfaceError`` /
    corruption in the encrypted credential store.
    """

    @pytest.fixture
    def db(self):
        from email_triage.web.db import init_db
        from _db_tracking import track
        return track(init_db(":memory:"))

    @pytest.fixture
    def master_key(self):
        from email_triage.secrets import DbSecrets
        return DbSecrets.generate_master_key()

    @staticmethod
    def _lock_tracking_store(db, master_key):
        """Return ``(store, lock_states)`` — a ``DbSecrets`` over a
        connection PROXY whose ``execute``/``commit`` record whether
        the process-wide write lock was held by the calling thread at
        that instant.

        A proxy (not attribute-patching) is required: ``execute`` on a
        real ``sqlite3.Connection`` is a read-only C-level attribute.
        The proxy forwards every other attribute untouched.

        ``RLock._is_owned()`` is the reentrant-lock primitive for "does
        the *current* thread hold this lock" — exactly the question
        here, and reentrancy-safe (the real callers nest the lock under
        ``db_call`` / ``@db_write``).
        """
        from email_triage.secrets import DbSecrets
        from email_triage.web.db_writelock import get_write_lock

        lock = get_write_lock()
        lock_states: list[tuple[str, bool]] = []

        class _SpyConn:
            """Forwarding proxy that records lock-held state on each
            connection touch."""

            def __init__(self, real):
                object.__setattr__(self, "_real", real)

            def execute(self, *args, **kwargs):
                lock_states.append(("execute", lock._is_owned()))
                return self._real.execute(*args, **kwargs)

            def commit(self, *args, **kwargs):
                lock_states.append(("commit", lock._is_owned()))
                return self._real.commit(*args, **kwargs)

            def __getattr__(self, name):
                # Everything else (rollback, cursor, row_factory, …)
                # forwards straight through to the real connection.
                return getattr(self._real, name)

        return DbSecrets(_SpyConn(db), master_key), lock_states

    def test_set_holds_write_lock(self, db, master_key):
        store, states = self._lock_tracking_store(db, master_key)
        store.set("IMAP_PASSWORD", "hunter2")
        assert states, "set() did not touch the connection at all"
        unlocked = [op for op, held in states if not held]
        assert not unlocked, (
            f"DbSecrets.set touched the shared connection WITHOUT the "
            f"write lock held: {unlocked}"
        )

    def test_get_holds_write_lock(self, db, master_key):
        # Seed first (set is already verified separately).
        from email_triage.secrets import DbSecrets
        DbSecrets(db, master_key).set("K", "v")
        store, states = self._lock_tracking_store(db, master_key)
        assert store.get("K") == "v"
        assert states, "get() did not touch the connection at all"
        unlocked = [op for op, held in states if not held]
        assert not unlocked, (
            f"DbSecrets.get read the shared connection WITHOUT the "
            f"write lock held: {unlocked}"
        )

    def test_delete_holds_write_lock(self, db, master_key):
        from email_triage.secrets import DbSecrets
        DbSecrets(db, master_key).set("K", "v")
        store, states = self._lock_tracking_store(db, master_key)
        assert store.delete("K") is True
        assert states, "delete() did not touch the connection at all"
        unlocked = [op for op, held in states if not held]
        assert not unlocked, (
            f"DbSecrets.delete touched the shared connection WITHOUT "
            f"the write lock held: {unlocked}"
        )

    def test_list_keys_holds_write_lock(self, db, master_key):
        from email_triage.secrets import DbSecrets
        DbSecrets(db, master_key).set("K", "v")
        store, states = self._lock_tracking_store(db, master_key)
        assert store.list_keys() == ["K"]
        assert states, "list_keys() did not touch the connection at all"
        unlocked = [op for op, held in states if not held]
        assert not unlocked, (
            f"DbSecrets.list_keys read the shared connection WITHOUT "
            f"the write lock held: {unlocked}"
        )

    def test_rotate_master_key_holds_write_lock(self, db, master_key):
        """The whole BEGIN IMMEDIATE … COMMIT transaction — including
        the per-row SELECT/UPDATE loop — must run under the lock."""
        from email_triage.secrets import DbSecrets
        seed = DbSecrets(db, master_key)
        for i in range(5):
            seed.set(f"K_{i}", f"v_{i}")
        store, states = self._lock_tracking_store(db, master_key)
        store.rotate_master_key(DbSecrets.generate_master_key())
        assert states, "rotate_master_key did not touch the connection"
        unlocked = [op for op, held in states if not held]
        assert not unlocked, (
            f"DbSecrets.rotate_master_key touched the shared "
            f"connection WITHOUT the write lock held: {unlocked}"
        )

    def test_lock_is_the_shared_process_wide_lock(self, db, master_key):
        """Sanity: the lock DbSecrets takes is the SAME object
        ``@db_write`` / ``db_call`` take — not a private one. Sharing
        the one RLock is what actually serialises a DbSecrets touch
        against a request-surface ``db_call`` worker.

        Proven the hard way: while ``set`` is mid-DB-touch, a SEPARATE
        thread tries to acquire ``get_write_lock()`` non-blocking — it
        must FAIL, because the shared lock is held.
        """
        import threading
        from email_triage.secrets import DbSecrets
        from email_triage.web.db_writelock import get_write_lock

        lock = get_write_lock()
        held_during_set: list[bool] = []

        class _ProbeConn:
            def __init__(self, real):
                object.__setattr__(self, "_real", real)

            def execute(self, *args, **kwargs):
                acquired_elsewhere: list[bool] = []

                def _try():
                    got = lock.acquire(blocking=False)
                    acquired_elsewhere.append(got)
                    if got:
                        lock.release()

                t = threading.Thread(target=_try)
                t.start()
                t.join()
                held_during_set.append(not acquired_elsewhere[0])
                return self._real.execute(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self._real, name)

        DbSecrets(_ProbeConn(db), master_key).set("K", "v")
        assert held_during_set and all(held_during_set), (
            "the process-wide write lock was NOT held during the "
            "DbSecrets.set DB touch — a concurrent thread could "
            "acquire it, so it is not serialising shared-connection "
            "access"
        )


class TestExternalProviderRegistry:
    """Tests for the Option C extension point."""

    def test_register_and_use(self):
        from email_triage.secrets import (
            SecretsProvider,
            create_secrets_provider,
            register_external_provider,
        )

        class FakeVault(SecretsProvider):
            def __init__(self, url: str = "", token: str = ""):
                self._url = url
                self._token = token
                self._store = {"ET_MASTER_KEY": "fake-key"}
            def get(self, key): return self._store.get(key)
            def set(self, key, value): self._store[key] = value
            def list_keys(self): return list(self._store.keys())

        register_external_provider("fake_vault", FakeVault)
        provider = create_secrets_provider(
            "external:fake_vault",
            external_config={"url": "http://vault.invalid", "token": "abc"},
        )
        assert isinstance(provider, FakeVault)
        assert provider._url == "http://vault.invalid"
        assert provider._token == "abc"

    def test_unregistered_external_raises(self):
        with pytest.raises(ValueError, match="not registered"):
            create_secrets_provider("external:no_such_provider")

    def test_list_registered(self):
        from email_triage.secrets import (
            SecretsProvider,
            list_external_providers,
            register_external_provider,
        )

        class Dummy(SecretsProvider):
            def get(self, key): return None
            def set(self, key, value): pass
            def list_keys(self): return []

        register_external_provider("_dummy_test_provider", Dummy)
        assert "_dummy_test_provider" in list_external_providers()


class TestH07EnvBackendDeprecation:
    """H-07 (Cycle 6, 2026-05-24) — env backend deprecation +
    dev-CI-only carve-out via ``EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY``.

    The selection-time deprecation warning fires from
    :func:`_warn_env_backend_deprecation` called by
    :func:`create_secrets_provider` and :func:`_resolve_auto_backend`.
    Gated by HIPAA mode (G1' RuntimeError handles HIPAA case) and by
    the carve-out env var (dev/CI opt-in).
    """

    @pytest.fixture(autouse=True)
    def _reset_latch(self):
        """Reset the once-per-process latch between tests.

        The H-07 helper has a module-level ``_env_backend_selection_warned``
        that latches True after the first warning. Without resetting,
        a test that runs second would observe a no-op even if its
        conditions would trigger a warning.
        """
        from email_triage.secrets import _reset_env_backend_warn_latch_for_tests
        _reset_env_backend_warn_latch_for_tests()
        yield
        _reset_env_backend_warn_latch_for_tests()

    def test_env_backend_emits_deprecation_warning_at_selection(
        self, monkeypatch, caplog,
    ):
        """Selecting env backend (HIPAA off, carve-out off) emits
        log.warning naming the deprecation + carve-out + sunset."""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider, EnvSecrets

        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        monkeypatch.delenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", raising=False)

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            provider = create_secrets_provider("env")

        assert isinstance(provider, EnvSecrets)
        # The deprecation warning must be in the log capture.
        deprecation_msgs = [
            r for r in caplog.records
            if "H-07" in r.getMessage()
            or "DEPRECATED" in r.getMessage()
        ]
        assert deprecation_msgs, (
            "expected env-backend deprecation warning to fire at "
            "selection time; caplog records: "
            f"{[r.getMessage() for r in caplog.records]}"
        )
        # Punch 547: the warning no longer offers an env var that silences
        # it (the EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY carve-out was removed).
        msg_text = " ".join(r.getMessage() for r in deprecation_msgs)
        assert "EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY" not in msg_text

    def test_retired_carve_out_env_var_no_longer_suppresses(
        self, monkeypatch, caplog,
    ):
        """Punch 547: EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY=1 used to silence the
        H-07 warning — an env var switching off a control's signal. It is
        ignored now (and refused at process start)."""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage import secrets as _secrets
        from email_triage.secrets import create_secrets_provider, EnvSecrets

        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        monkeypatch.setattr(_secrets, "_env_backend_selection_warned", False)
        monkeypatch.setenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", "1")

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            provider = create_secrets_provider("env")

        assert isinstance(provider, EnvSecrets)
        assert any(
            "H-07" in r.getMessage() or "DEPRECATED" in r.getMessage()
            for r in caplog.records
        ), "the retired carve-out var must no longer silence the warning"

    def test_warning_suppressed_in_hipaa_mode(self, monkeypatch, caplog):
        """In HIPAA mode the G1' RuntimeError handles env-backend
        rejection (in enforce_master_key_at_rest_for_hipaa); the H-07
        selection-time warning must be silent so as not to pile up on
        top of an already-fatal boot."""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider, EnvSecrets

        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        monkeypatch.delenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", raising=False)

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            # NB: create_secrets_provider itself does NOT enforce HIPAA-
            # mode rejection — that lives in enforce_master_key_at_rest_
            # for_hipaa(). At the create_ site, we only suppress the
            # additional H-07 deprecation warning to avoid double-warning.
            provider = create_secrets_provider("env")

        assert isinstance(provider, EnvSecrets)
        deprecation_msgs = [
            r for r in caplog.records
            if "H-07" in r.getMessage()
            or "DEPRECATED" in r.getMessage()
        ]
        assert not deprecation_msgs, (
            "HIPAA mode on; H-07 deprecation warning should defer to "
            "G1' RuntimeError handling but got: "
            f"{[r.getMessage() for r in deprecation_msgs]}"
        )

    def test_carve_out_has_no_bypass_under_hipaa_mode(
        self, monkeypatch, caplog
    ):
        """R-5 per db-sme-3 verdict 2026-05-24: HIPAA-on + carve-out-on
        MUST still defer to G1' enforcement. The carve-out env var is a
        non-HIPAA-mode opt-in; under HIPAA mode it has NO bypass effect.

        Structural property: in _warn_env_backend_deprecation, the
        HIPAA-mode gate is checked BEFORE the carve-out gate (per
        secrets.py:776-788). This test pins the property against a
        future refactor that might reorder them — reordering would
        produce a silent-degradation surface where an operator who set
        the carve-out var in dev/CI accidentally suppresses the warning
        in a production deploy where HIPAA mode was also enabled.

        The G1' RuntimeError still fires in
        enforce_master_key_at_rest_for_hipaa; this test verifies that
        the H-07 selection-time warning ALSO stays silent in HIPAA
        mode regardless of the carve-out var, matching the no-double-
        warning rationale of test_env_select_in_hipaa_mode_does_not_
        emit_warning.
        """
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider, EnvSecrets

        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        monkeypatch.setenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", "1")

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            provider = create_secrets_provider("env")

        assert isinstance(provider, EnvSecrets)
        deprecation_msgs = [
            r for r in caplog.records
            if "H-07" in r.getMessage()
            or "DEPRECATED" in r.getMessage()
        ]
        assert not deprecation_msgs, (
            "HIPAA mode on + carve-out env var set; H-07 deprecation "
            "warning must STILL be silent (G1' RuntimeError handles "
            "the rejection). Got: "
            f"{[r.getMessage() for r in deprecation_msgs]}. If this "
            "fails, the carve-out gate may have been reordered ahead "
            "of the HIPAA-mode gate — verify _warn_env_backend_"
            "deprecation at secrets.py."
        )

    def test_warning_once_per_process_latch(self, monkeypatch, caplog):
        """The latch fires the warning at most once per process; a
        second create_secrets_provider call in the same process is a
        no-op for the H-07 warning."""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider

        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        monkeypatch.delenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", raising=False)

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            create_secrets_provider("env")
            first_count = sum(
                1 for r in caplog.records
                if "H-07" in r.getMessage() or "DEPRECATED" in r.getMessage()
            )
            create_secrets_provider("env")
            create_secrets_provider("env")
            second_count = sum(
                1 for r in caplog.records
                if "H-07" in r.getMessage() or "DEPRECATED" in r.getMessage()
            )

        assert first_count == 1, (
            f"expected exactly 1 deprecation warning after first call, "
            f"got {first_count}"
        )
        assert second_count == 1, (
            f"latch failed: deprecation warning fired again after "
            f"second/third create_secrets_provider call, total: "
            f"{second_count}"
        )


    @pytest.mark.parametrize(
        "value", ["", "0", "false", "FALSE", "no", "NO", "off", "garbage", "  "],
    )
    def test_carve_out_var_falsy_values_still_warn(
        self, monkeypatch, caplog, value,
    ):
        """Carve-out env var with falsy/garbage value does NOT suppress —
        the warning still fires. Only documented truthy values opt in."""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider

        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        monkeypatch.setenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", value)

        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            create_secrets_provider("env")

        deprecation_msgs = [
            r for r in caplog.records
            if "H-07" in r.getMessage() or "DEPRECATED" in r.getMessage()
        ]
        assert deprecation_msgs, (
            f"falsy/garbage carve-out value {value!r} should NOT "
            f"suppress; expected warning but got none"
        )

    def test_auto_resolution_to_env_also_emits_deprecation(
        self, monkeypatch, caplog, tmp_path,
    ):
        """The auto-fallback path through _resolve_auto_backend also
        triggers the H-07 deprecation warning. (The auto-fell-back
        warning AND the H-07 deprecation warning fire — they are
        distinct messages.)"""
        import logging
        import email_triage.triage_logging as _tl
        from email_triage.secrets import create_secrets_provider, EnvSecrets

        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        monkeypatch.delenv("EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY", raising=False)

        # tmp_path has no ET_MASTER_KEY file — auto must fall back to env.
        with caplog.at_level(logging.WARNING, logger="email_triage.secrets"):
            provider = create_secrets_provider(
                "auto", container_path=str(tmp_path), master_key_name="ET_MASTER_KEY",
            )

        assert isinstance(provider, EnvSecrets)
        deprecation_msgs = [
            r for r in caplog.records
            if "H-07" in r.getMessage() or "DEPRECATED" in r.getMessage()
        ]
        assert deprecation_msgs, (
            "auto-fell-back-to-env path must also emit H-07 "
            "deprecation warning; caplog: "
            f"{[r.getMessage() for r in caplog.records]}"
        )
