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
        return init_db(":memory:")

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
        # Different Fernet key must not decrypt store1's ciphertext.
        from cryptography.fernet import InvalidToken
        with pytest.raises(InvalidToken):
            store2.get("KEY")

    def test_require_raises_when_missing(self, db, master_key):
        from email_triage.secrets import DbSecrets
        store = DbSecrets(db, master_key)
        with pytest.raises(SecretNotFound):
            store.require("NOT_THERE")

    def test_bootstrap_from_config(self, db, tmp_path: Path):
        """bootstrap_secrets_from_config wires env → DbSecrets end-to-end."""
        from email_triage.config import TriageConfig
        from email_triage.secrets import (
            DbSecrets, bootstrap_secrets_from_config,
        )

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

        # A fresh store using the OLD key no longer decrypts.
        from cryptography.fernet import InvalidToken
        store_old = DbSecrets(db, master_key)
        with pytest.raises(InvalidToken):
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
        """#145.3 — verify the fix's ordering invariant directly:
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

        db_path = tmp_path / "rotate-lock.db"
        init_db(str(db_path))

        def _open() -> sqlite3.Connection:
            c = sqlite3.connect(
                str(db_path), check_same_thread=False, timeout=10.0,
            )
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

    def test_bootstrap_fails_when_master_key_missing(self, db):
        """No master key in bootstrap store → SecretNotFound."""
        from email_triage.config import TriageConfig
        from email_triage.secrets import bootstrap_secrets_from_config
        cfg = TriageConfig()
        cfg.secrets.backend = "env"
        cfg.secrets.master_key_name = "DEFINITELY_NOT_SET_ANYWHERE_XYZ"
        with pytest.raises(SecretNotFound):
            bootstrap_secrets_from_config(db, cfg)


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
            external_config={"url": "http://vault", "token": "abc"},
        )
        assert isinstance(provider, FakeVault)
        assert provider._url == "http://vault"
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
