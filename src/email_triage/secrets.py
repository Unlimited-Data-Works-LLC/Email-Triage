"""Secrets provider abstraction layer.

At runtime the app stores user-managed secrets (per-account passwords,
OAuth tokens, SMTP auth) in an encrypted SQLite column, keyed by a
single *master key*.  The master key itself is fetched from a
"bootstrap" provider — one of the process-level backends below — at
startup.  This pattern (app-managed encrypted store, one env-bound
master key) is the standard approach used by Django, Rails, Sentry,
etc., and gives us: read/write from the web UI, OAuth rotation, and a
portable deployment model.

Bootstrap backends (where the master key lives):

    keyring    - OS credential store (Windows Credential Locker, macOS Keychain)
    keyfile    - Fernet key on disk, read once at startup
    container  - Reads /run/secrets/<key>  (Podman / Docker secrets mount)
    env        - os.environ (legacy escape hatch, logs a warning)
    external:<name> - plugin-registered provider (see register_external_provider)

Runtime secret store:

    DbSecrets  - Fernet-encrypted rows in the ``secrets_store`` SQLite
                 table.  This is what consumer code uses; the above
                 backends only exist to supply its master key.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("email_triage.secrets")

_SERVICE_NAME = "email-triage"


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SecretsProvider(ABC):
    """Uniform interface for retrieving secrets at runtime."""

    @abstractmethod
    def get(self, key: str) -> str | None:
        """Return the secret value, or None if not found."""

    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """Persist a secret value."""

    @abstractmethod
    def list_keys(self) -> list[str]:
        """Return the names of all stored secrets (not values)."""

    def require(self, key: str) -> str:
        """Like get(), but raises if the key is missing."""
        val = self.get(key)
        if val is None:
            raise SecretNotFound(key, backend=self.__class__.__name__)
        return val


class SecretNotFound(Exception):
    def __init__(self, key: str, backend: str = ""):
        self.key = key
        self.backend = backend
        msg = f"Secret '{key}' not found"
        if backend:
            msg += f" (backend: {backend})"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Container backend  (/run/secrets/<key>)
# ---------------------------------------------------------------------------

class ContainerSecrets(SecretsProvider):
    """Reads secrets from files mounted by Podman/Docker."""

    def __init__(self, base_path: str | Path = "/run/secrets"):
        self._base = Path(base_path)

    def get(self, key: str) -> str | None:
        p = self._base / key
        if not p.is_file():
            return None
        return p.read_text().strip()

    def set(self, key: str, value: str) -> None:
        raise NotImplementedError(
            "Container secrets are read-only. "
            "Use 'podman secret create' or 'docker secret create' instead."
        )

    def list_keys(self) -> list[str]:
        if not self._base.is_dir():
            return []
        return [f.name for f in self._base.iterdir() if f.is_file()]


# ---------------------------------------------------------------------------
# Environment variable backend  (legacy / migration)
# ---------------------------------------------------------------------------

class EnvSecrets(SecretsProvider):
    """Reads secrets from environment variables.  Logs a warning on use."""

    _warned = False

    def get(self, key: str) -> str | None:
        val = os.environ.get(key)
        if val is not None and not EnvSecrets._warned:
            logger.warning(
                "Using environment variables for secrets. "
                "Consider migrating to the 'container' or 'keyfile' backend."
            )
            EnvSecrets._warned = True
        return val

    def set(self, key: str, value: str) -> None:
        raise NotImplementedError(
            "Cannot persist secrets via environment variables. "
            "Set them in your shell profile or container config."
        )

    def list_keys(self) -> list[str]:
        # Can't enumerate "which env vars are ours" without a prefix convention.
        return []


# ---------------------------------------------------------------------------
# Keyfile backend  (Fernet-encrypted JSON)
# ---------------------------------------------------------------------------

class KeyfileSecrets(SecretsProvider):
    """Encrypts secrets in a JSON file using Fernet symmetric encryption.

    Requires the ``cryptography`` package (install with ``pip install
    email-triage[keyfile]``).
    """

    def __init__(self, keyfile_path: str | Path, store_path: str | Path | None = None):
        self._keyfile_path = Path(keyfile_path).expanduser()
        self._store_path = (
            Path(store_path).expanduser()
            if store_path
            else self._keyfile_path.parent / "secrets.enc"
        )
        self._fernet: Any = None  # lazy import

    def _get_fernet(self) -> Any:
        if self._fernet is not None:
            return self._fernet
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise ImportError(
                "The 'cryptography' package is required for the keyfile backend. "
                "Install it with: pip install email-triage[keyfile]"
            )
        if not self._keyfile_path.is_file():
            raise FileNotFoundError(
                f"Keyfile not found: {self._keyfile_path}. "
                "Generate one with: python -c "
                "\"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
                f"> {self._keyfile_path}"
            )
        key = self._keyfile_path.read_text().strip().encode()
        self._fernet = Fernet(key)
        return self._fernet

    def _load_store(self) -> dict[str, str]:
        if not self._store_path.is_file():
            return {}
        fernet = self._get_fernet()
        encrypted = self._store_path.read_bytes()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)

    def _save_store(self, data: dict[str, str]) -> None:
        fernet = self._get_fernet()
        plaintext = json.dumps(data).encode()
        encrypted = fernet.encrypt(plaintext)
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_bytes(encrypted)

    def get(self, key: str) -> str | None:
        return self._load_store().get(key)

    def set(self, key: str, value: str) -> None:
        store = self._load_store()
        store[key] = value
        self._save_store(store)

    def list_keys(self) -> list[str]:
        return list(self._load_store().keys())


# ---------------------------------------------------------------------------
# Keyring backend  (OS credential store)
# ---------------------------------------------------------------------------

class KeyringSecrets(SecretsProvider):
    """Uses the OS keyring (Windows Credential Locker, macOS Keychain, etc.).

    Requires the ``keyring`` package (install with ``pip install
    email-triage[keyring]``).
    """

    def __init__(self, service_name: str = _SERVICE_NAME):
        self._service = service_name
        self._kr: Any = None  # lazy import

    def _get_keyring(self) -> Any:
        if self._kr is not None:
            return self._kr
        try:
            import keyring as kr
        except ImportError:
            raise ImportError(
                "The 'keyring' package is required for the keyring backend. "
                "Install it with: pip install email-triage[keyring]"
            )
        self._kr = kr
        return kr

    def get(self, key: str) -> str | None:
        kr = self._get_keyring()
        return kr.get_password(self._service, key)

    def set(self, key: str, value: str) -> None:
        kr = self._get_keyring()
        kr.set_password(self._service, key, value)

    def list_keys(self) -> list[str]:
        # The keyring API doesn't support enumeration.
        # Return empty — users must know their key names.
        return []


# ---------------------------------------------------------------------------
# DbSecrets  (runtime store — encrypted column in SQLite)
# ---------------------------------------------------------------------------

class DbSecrets(SecretsProvider):
    """Fernet-encrypted secrets stored in the ``secrets_store`` DB table.

    This is the runtime-writable store the app uses for all user-managed
    secrets.  The encryption key (``master_key``) is fetched at startup
    from a bootstrap provider — see ``bootstrap_secrets_from_config``.

    The DB column stores ciphertext; plaintext is only ever in memory.
    A lost master key means the encrypted values cannot be recovered —
    same failure mode as any encrypted-at-rest system.
    """

    def __init__(self, conn: Any, master_key: str, table: str = "secrets_store"):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise ImportError(
                "The 'cryptography' package is required for DbSecrets. "
                "Install with: pip install email-triage[keyfile]"
            )
        self._conn = conn
        self._table = table
        if isinstance(master_key, str):
            master_key = master_key.encode()
        self._fernet = Fernet(master_key)

    def get(self, key: str) -> str | None:
        row = self._conn.execute(
            f"SELECT ciphertext FROM {self._table} WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        ciphertext = row["ciphertext"] if hasattr(row, "keys") else row[0]
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def set(self, key: str, value: str) -> None:
        ciphertext = self._fernet.encrypt(value.encode()).decode()
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            f"INSERT INTO {self._table} (key, ciphertext, created_at, updated_at) "
            f"VALUES (?, ?, ?, ?) "
            f"ON CONFLICT(key) DO UPDATE SET ciphertext = excluded.ciphertext, "
            f"updated_at = excluded.updated_at",
            (key, ciphertext, now, now),
        )
        self._conn.commit()

    def delete(self, key: str) -> bool:
        """Remove a secret. Returns True if something was deleted."""
        cur = self._conn.execute(
            f"DELETE FROM {self._table} WHERE key = ?", (key,),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def list_keys(self) -> list[str]:
        rows = self._conn.execute(
            f"SELECT key FROM {self._table} ORDER BY key"
        ).fetchall()
        return [r["key"] if hasattr(r, "keys") else r[0] for r in rows]

    @staticmethod
    def generate_master_key() -> str:
        """Generate a fresh Fernet key. Returns base64 string."""
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()

    def rotate_master_key(self, new_master_key: str) -> int:
        """Re-encrypt every row with a new master key, atomically.

        Reads each ciphertext with the *current* key, encrypts with the
        new key, and UPDATEs the row inside a single transaction.  If
        anything fails, the transaction rolls back and the old master
        key remains valid.

        The caller is responsible for:
          - Stopping the running app before rotation (running app
            processes cache the old Fernet instance in memory)
          - Storing the new key in the bootstrap backend after this
            returns successfully

        Returns the number of rows re-encrypted.
        """
        from cryptography.fernet import Fernet
        if isinstance(new_master_key, str):
            new_master_key = new_master_key.encode()
        new_fernet = Fernet(new_master_key)

        # #145.3 — close the SELECT-before-BEGIN TOCTOU window. If we
        # SELECT first and a concurrent ``set()`` lands a new row (or
        # overwrites an existing row's ciphertext) BEFORE the BEGIN,
        # that row escapes the rotation pass: it stays encrypted with
        # the old key, then ``self._fernet = new_fernet`` below
        # discards the only key that can read it. Future ``.get()``
        # raises InvalidToken.
        #
        # Fix: open a RESERVED-lock transaction with BEGIN IMMEDIATE
        # BEFORE the SELECT. SQLite blocks concurrent writers until
        # we COMMIT/ROLLBACK; the SELECT, the UPDATE loop, and the
        # in-memory key swap all observe the same row set atomically.
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            rows = self._conn.execute(
                f"SELECT key, ciphertext FROM {self._table}"
            ).fetchall()
            for row in rows:
                k = row["key"] if hasattr(row, "keys") else row[0]
                old_ct = row["ciphertext"] if hasattr(row, "keys") else row[1]
                # Decrypt with the *old* key (our _fernet) and re-encrypt
                # with new.  Any failure here aborts the whole rotation.
                plaintext = self._fernet.decrypt(old_ct.encode())
                new_ct = new_fernet.encrypt(plaintext).decode()
                self._conn.execute(
                    f"UPDATE {self._table} SET ciphertext = ?, updated_at = ? "
                    f"WHERE key = ?",
                    (new_ct, now, k),
                )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

        # Swap the in-memory key so subsequent get/set calls use the new
        # one immediately — matches what the app would see after restart.
        self._fernet = new_fernet
        return len(rows)


# ---------------------------------------------------------------------------
# External provider registry  (extension point for Option C backends)
# ---------------------------------------------------------------------------
#
# Third-party or plugin backends (KeePass, Vault, AWS Secrets Manager, etc.)
# register themselves via ``register_external_provider("name", factory)``.
# The factory is called with the ``external`` config dict from YAML.
#
# Enable in config with::
#
#     secrets:
#       backend: "external:keepass"
#       external:
#         database: /mnt/nas/vault.kdbx
#         keyfile: /home/<user>/.kp_keyfile
#
# Providers supply the *master key* (same role as container/keyfile above),
# so they only need ``get()``; ``set()`` and ``list_keys()`` may raise
# NotImplementedError.

_EXTERNAL_PROVIDERS: dict[str, Callable[..., SecretsProvider]] = {}


def register_external_provider(
    name: str,
    factory: Callable[..., SecretsProvider],
) -> None:
    """Register an external secrets backend.

    ``factory`` must accept the ``external`` config dict as **kwargs and
    return a ``SecretsProvider``.  Called at import time by optional
    integration modules (e.g. ``email_triage.secrets_keepass``).
    """
    _EXTERNAL_PROVIDERS[name] = factory


def list_external_providers() -> list[str]:
    """Return the names of currently-registered external providers."""
    return sorted(_EXTERNAL_PROVIDERS.keys())


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_secrets_provider(
    backend: str,
    keyfile_path: str = "~/.config/email-triage/key",
    container_path: str = "/run/secrets",
    external_config: dict[str, Any] | None = None,
) -> SecretsProvider:
    """Create a *bootstrap* secrets provider from a backend name.

    This returns the provider that supplies the master key.  For the
    runtime secret store (user-managed secrets) see ``DbSecrets``.
    """
    if backend == "container":
        return ContainerSecrets(container_path)
    elif backend == "env":
        return EnvSecrets()
    elif backend == "keyfile":
        return KeyfileSecrets(keyfile_path)
    elif backend == "keyring":
        return KeyringSecrets()
    elif backend.startswith("external:"):
        name = backend[len("external:"):]
        if name not in _EXTERNAL_PROVIDERS:
            raise ValueError(
                f"External secrets provider '{name}' is not registered. "
                f"Registered providers: {list_external_providers() or '(none)'}. "
                "Register one at import time via "
                "email_triage.secrets.register_external_provider()."
            )
        return _EXTERNAL_PROVIDERS[name](**(external_config or {}))
    else:
        raise ValueError(
            f"Unknown secrets backend: '{backend}'. "
            "Expected one of: container, env, keyfile, keyring, "
            "external:<name>"
        )


def bootstrap_secrets_from_config(conn: Any, cfg: Any) -> SecretsProvider:
    """Build the runtime ``DbSecrets`` provider from a ``TriageConfig``.

    1. Build the bootstrap provider from ``cfg.secrets.backend``.
    2. Read the master key from it using ``cfg.secrets.master_key_name``.
    3. Wrap the DB connection in ``DbSecrets`` using that key.

    Raises ``SecretNotFound`` if the master key is missing from the
    bootstrap store — this is a hard failure; the app cannot start
    without a master key.
    """
    bootstrap = create_secrets_provider(
        cfg.secrets.backend,
        keyfile_path=cfg.secrets.keyfile_path,
        external_config=cfg.secrets.external,
    )
    master_key = bootstrap.require(cfg.secrets.master_key_name)
    return DbSecrets(conn, master_key)
