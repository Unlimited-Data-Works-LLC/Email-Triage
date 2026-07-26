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
from email_triage._isotime import now_utc_iso
from pathlib import Path
from typing import Any, Callable

#  — DbSecrets shares the one process-wide sqlite3.Connection; every
# touch of it is serialised on the same write lock @db_write / db_call
# use. db_writelock imports only stdlib, so this is cycle-free.
from email_triage.db._helpers import row_get  # N-234 R23 row-factory-agnostic SSOT
from email_triage.web.db_writelock import get_write_lock
from email_triage.triage_logging import get_logger  # N-196b R21_4

logger = get_logger("email_triage.secrets")  # N-196b R21_4

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


class SecretsDecryptError(Exception):
    """A stored secret row exists but cannot be decrypted — a corrupt
    ciphertext or (more likely, since it affects every secret) a
    master-key mismatch. Distinct from SecretNotFound: the row is
    present but unreadable. A typed error so callers can tell
    'unreadable' apart from 'missing' instead of catching an opaque
    cryptography exception."""

    def __init__(self, key: str):
        self.key = key
        super().__init__(
            f"Could not decrypt secret '{key}' — corrupt ciphertext "
            f"or master-key mismatch"
        )


# ---------------------------------------------------------------------------
# Optional-secret read SSOT  (A5, divergence census 2026-06-09)
# ---------------------------------------------------------------------------

def read_secret(secrets: "SecretsProvider | None", key: str) -> str | None:
    """Single sanctioned way to read a *possibly-absent* secret.

    Returns the secret value, or ``None`` when the secrets provider is
    absent (``secrets is None``) or the key is not present.

    It deliberately does **NOT** catch :class:`SecretsDecryptError`. A
    decrypt failure means the row exists but is unreadable — a corrupt
    ciphertext or (far more likely, since it hits *every* secret at once)
    an install-wide master-key mismatch. That is a categorically
    different condition from "the secret was never configured", and the
     typed error exists precisely to keep them apart.

    The divergence this SSOT closes (A5): a dozen call sites each wrapped
    their read in a broad ``except Exception: <falsy>`` that folded the
    *unreadable* case back into the *absent* case — so a master-key
    mismatch silently degraded a security control (e.g. shipped an
    UNSIGNED webhook, or reported a saved account as "needs re-auth")
    with nobody the wiser. Callers MUST let ``SecretsDecryptError``
    propagate, or catch it *explicitly* (``except SecretsDecryptError``)
    and surface a distinct, fail-closed degraded state — never collapse
    it into the absent path with a bare/broad ``except``.

    The ``tests/test_web/test_secret_read_collapse_pin_a5.py`` AST pin
    enforces that no module under ``src/email_triage`` reintroduces the
    broad-except-around-a-secret-read collapse.
    """
    if secrets is None:
        return None
    return secrets.get(key)


def read_secret_required(secrets: "SecretsProvider", key: str) -> str:
    """Single sanctioned way to read a REQUIRED secret (raise if absent).

    The raise-on-missing twin of :func:`read_secret`, for callers where a
    missing secret is a HARD failure — master-key reads, the DR-bundle export
    (``backup.py``), key rotation/migration (``cli.py``). Returns the secret
    value or raises :class:`SecretNotFound` (via the provider's ``require``).
    Like :func:`read_secret` it does NOT swallow :class:`SecretsDecryptError`
    (the  typed-error contract — an unreadable row is categorically
    distinct from an absent one).

    The divergence this SSOT closes (run17 #4 / N-137): the master-key read —
    the highest-privilege secret read, unlocking every ciphertext AND the
    ``log_entries`` HMAC audit-chain key — was done via a raw
    ``provider.require(master_key_name)`` at ``backup.py``/``cli.py`` (the only
    unpinned read surface). Routing every required read through ONE funnel lets
    ``tests/test_secret_read_funnel_pin.py`` ban a raw ``.require()``/``.get()``
    on a secrets/bootstrap receiver outside this module.
    """
    return secrets.require(key)


def get_or_mint_secret(
    secrets: "SecretsProvider",
    key: str,
    mint_fn: Callable[[], str],
    *,
    on_decrypt_error: str = "fail_closed",
    bypass_check: "Callable[[], bool] | None" = None,
    bypass_clear: "Callable[[], None] | None" = None,
    bypass_audit_emit: "Callable[[], None] | None" = None,
) -> str:
    """N-349 R31 (2026-07-04, census DISCOVERED MED; hybrid mode
    added 2026-07-05 per operator decision) — SSOT for the
    read-else-mint pattern.

    The watch-HMAC-key hydration path (``agent_api.py`` +
    ``profile.py``) previously used a hand-rolled shape:

        try:
            existing = secrets.get(key)
        except Exception:  # BROAD — catches SecretsDecryptError too
            existing = None
        if existing is None:
            existing = mint()
            secrets.set(key, existing)

    Same clobber class as the 2026-06-08 OAuth save-clobber (which was
    on the WRITE arm) — mirrored on the READ arm: a
    :class:`SecretsDecryptError` (row present but unreadable) got folded
    into the "absent" branch + a fresh key minted + the unreadable row
    OVERWRITTEN, silently discarding whatever the operator had stored
    under a now-superseded master key.

    Fail-CLOSED policy (this SSOT):

    * ``existing is None`` (secret genuinely absent, e.g. fresh install):
      call ``mint_fn()``, ``.set()``, return the freshly-minted value.
    * :class:`SecretsDecryptError` (row present but unreadable — master-
      key mismatch, corrupt ciphertext): default ``on_decrypt_error=
      "fail_closed"`` propagates the error so the caller can surface a
      distinct degraded state. NEVER folds into the mint path.
    * ``existing is not None``: return the existing value verbatim.

    Callers MUST route watch-HMAC hydration + similar "mint-once, hydrate
    every request" reads through this SSOT. The 3 census-flagged clobber
    sites (agent_api:2510, profile:3543 + :3646) are the migration
    surface tracked under N-349-migrate.

    **Hybrid mode (2026-07-05 operator decision):** callers may pass
    ``bypass_check`` + ``bypass_clear`` callables (typically closures over
    a DB-persisted operator-set flag). When ``bypass_check()`` returns
    True on an unreadable row, the SSOT LOGS the clobber, MINTS + WRITES
    the fresh secret, then calls ``bypass_clear()`` — clear runs LAST so
    a mint or set failure preserves the operator's one-shot flag for the
    next attempt (PD  set/clear symmetry — SME panel 2026-07-05).
    This gives operators an explicit recovery lever without silent
    clobbers. The flag lifecycle is CLI-only per operator directive (no
    env-flag), so a runaway process cannot re-arm the bypass without the
    CLI's audit trail. When ``bypass_check`` is None or returns False,
    the fail-closed policy above holds.

    Race caveat (known follow-up): two concurrent unreadable reads on
    the same key with ``armed=True`` can both observe the flag before
    either mints, resulting in a double-mint where the second write
    clobbers the first. Intra-worker is race-free (sync body); the
    admin-triggered write flow makes multi-worker concurrency for the
    same watch-HMAC key rare in practice. Atomic check-and-consume via
    a `RETURNING`-clause `DELETE` at the settings layer landed under
    N-363 (N-349b item 2) — bypass_check now atomically consumes.

    **N-349b Item 1 (2026-07-07):** callers may pass
    ``bypass_audit_emit`` — a caller-supplied closure over
    ``record_hmac_clobber_bypass_consumed(conn, secret_key=key, ...)``
    that fires an HMAC-chained emitter-owned audit row AFTER the
    fresh mint + ``.set()`` succeed. This closes the §164.312(b) gap
    the 2026-07-05 SME panel surfaced (ARM row visible in the CLI
    audit log, CONSUME event previously only a stdlib warning). The
    call is guarded so an audit-emit failure does NOT block the
    recovery mint — the ``@audit_emitter`` gap-event contract already
    covers audit-visibility on write failure.

    **Pin-design seam (2026-07-11 census verdict, wf_69674c7e-c67):**
    the two live watch-HMAC hydration call sites dispatch this SSOT
    interprocedurally as a first-class function arg through the
    threadpool-hop seam:

        db_call(get_or_mint_secret, secrets, key, mint_fn, ...)

    (see ``web/routers/agent_api.py:2229`` and
    ``web/routers/ui/profile.py:3572`` + the aliased-import twin at
    ``profile.py:3708`` that uses ``_get_or_mint_secret``). A naive
    ``func.id == 'get_or_mint_secret'`` walker sees ZERO direct
    calls. Any future *coverage* pin that tries to enforce
    "watch-HMAC hydration MUST route through this SSOT" needs to
    walk first-arg dispatch through ``db_call`` / ``asyncio.to_thread``
    / ``run_in_executor`` (the same interprocedural-hop discipline
    ``test_async_db_safety.py`` already implements), AND resolve
    ``ImportFrom`` asname bindings so aliased dispatches are visible.
    The existing funnel + collapse pins are NOT weakened by this —
    they still block the raw ``.get`` / ``.require`` / broad-swallow
    shapes underneath — but a coverage pin (as distinct from an
    anti-pattern pin) would need this seam-aware walker.
    """
    try:
        existing = secrets.get(key)
    except SecretsDecryptError:
        if bypass_check is not None and bypass_check():
            # One-shot operator-armed recovery — log, mint, set, THEN
            # clear (PD  set/clear symmetry — a mint or set failure
            # leaves the flag armed so the next attempt can recover;
            # SME panel 2026-07-05 F1 fix).
            # N-242 pin fix (CI-red on 815a3cfe): route via the module-
            # scope TriageLogger `logger` rather than a fresh stdlib
            # `_lg.getLogger(...)` — the latter is the N-242 aliased-
            # import bypass shape.
            logger.warning(
                "N-349 hybrid: unreadable secret + operator-armed bypass flag consumed; minting fresh replacement",
                extra={"secret_key": key},
            )
            minted = mint_fn()
            secrets.set(key, minted)
            if bypass_audit_emit is not None:
                # N-349b Item 1 (2026-07-07): emitter-owned CONSUME
                # audit row inside the HMAC-chained envelope. Guarded
                # — a failed audit-emit MUST NOT block the recovery
                # mint (mint + set already succeeded above; the
                # break-glass semantics preserve). @audit_emitter's
                # `audit_gap_events` row fires on the failure path
                # so the CONSUME event stays visible either way.
                try:
                    bypass_audit_emit()
                except Exception:
                    logger.warning(
                        "N-349b Item 1: bypass-consumed audit emit failed — gap-event should follow",
                        extra={"secret_key": key},
                    )
            if bypass_clear is not None:
                bypass_clear()
            return minted
        if on_decrypt_error == "fail_closed":
            raise
        raise ValueError(
            f"get_or_mint_secret: unexpected "
            f"on_decrypt_error={on_decrypt_error!r} (only 'fail_closed' supported)"
        )
    if existing is not None:
        return existing
    minted = mint_fn()
    secrets.set(key, minted)
    return minted


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
# Environment variable backend  (DEPRECATED — dev / CI carve-out only)
# ---------------------------------------------------------------------------
#
# H-07 (Cycle 6, 2026-05-24): the env backend is DEPRECATED for production
# use and carved out as **dev / CI only**.
#
# Threat-model gaps that drive the deprecation:
#
#   * The Fernet master key sits in the process environment, visible via
#     ``/proc/<pid>/environ``, ``podman inspect``, ``ps eww``, container
#     orchestration logs, etc. Any local-system reader gets the key.
#   * No rotation discipline: the env-var pattern encourages
#     stop-and-restart with a new value, which orphans the previous
#     ciphertext + (post-H-02a) the HMAC audit chain.
#   * No at-rest protection guarantee: the env source (shell rc, systemd
#     unit, container yaml, k8s secret) is operator-discretion, not a
#     project-enforced posture.
#   * **§164.308(a)(4)(ii)(C) Access Establishment and Modification
#     implication**: the env-backend posture is single-master-key-per-
#     process — every process under the same UID reading
#     ``/proc/<pid>/environ`` sees the same master, with no per-actor
#     differentiation. Per hipaa-sme-3 R-2 cross-reference (2026-05-24):
#     the alternative backends (container tmpfs / OS keyring / external:* /
#     keyfile-0600) each support per-actor access-control posture (file
#     permissions, keyring user-scope, HSM/Vault role-based access);
#     env-backend has no equivalent. This is a defense-in-depth gap
#     beyond §164.312(a)(2)(iv) — it's also why the env-backend's "any
#     local-system reader gets the key" framing maps to an access-
#     management failure mode, not just an at-rest-encryption failure.
#
# Acceptable use cases (the carve-out):
#
#   * Local dev (``scripts/dev_preview.py`` and equivalents)
#   * CI runners (test secrets are ephemeral; runner config is throwaway)
#   * Test fixtures that exercise the env-bootstrap code path (the H-02a
#     G1' enforcement test, the bootstrap roundtrip test)
#
# Sunset trajectory (subject to hipaa-sme-2 acceleration):
#
#   * v0.1.x (today): runtime ``log.warning`` at selection-time when env
#     backend is chosen AND HIPAA mode is off AND the carve-out env var
#     ``EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY`` is not set to a truthy value
#     (``1``/``true``/``yes``, case-insensitive). HIPAA mode + env →
#     RuntimeError (G1' enforcement landed in H-02a). The legacy per-
#     instance ``_warned`` (get-time) latch is preserved for back-compat
#     and fires once per process on the first ``.get()`` call.
#   * v0.2.0: warning becomes a RuntimeError in non-HIPAA mode UNLESS
#     the carve-out env var is set. Dev/CI workflows continue
#     unchanged by setting the var; production deploys that quietly used
#     env backend will hard-stop at boot until they migrate.
#   * env-backend removal (timeline pending explicit operator directive
#     — the "v0.3.0 removes" schedule was AI-invented, not authorized;
#     corrected 2026-07-06 per operator directive that v0.3.0 = enterprise
#     scaling scope ONLY, see internal documentation). Final
#     state at removal: ``backend='env'`` raises a ``ValueError`` from
#     ``create_secrets_provider``; carve-out env var removed from the
#     codebase. Current single-install deployment (the deploy host) makes phased
#     ceremony unnecessary — the removal drive can land as one commit;
#     if the project pivots to multi-install (medical-researcher reuse
#     per project_medical_researcher), reinstate a phased schedule.
#
# Companion to H-02a G1' (HIPAA-mode + env → RuntimeError, landed in
# d23f208). H-02a closes the HIPAA-mode case immediately; H-07 carves
# out + sunsets the non-HIPAA-mode case across the v0.2/v0.3 cycle.


class EnvSecrets(SecretsProvider):
    """DEPRECATED. Reads secrets from environment variables.

    See the section docstring above for the H-07 deprecation rationale,
    the dev/CI-only carve-out, the
    ``EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY`` opt-in env var, and the
    deprecation trajectory (removal timeline pending explicit operator directive; the earlier "v0.2.0 / v0.3.0" version-anchor was AI-invented, not authorized — corrected 2026-07-06).

    A get-time once-per-process ``_warned`` latch is preserved for back-
    compat. The selection-time deprecation warning fires from
    :func:`_warn_env_backend_deprecation`, called by
    :func:`create_secrets_provider` and :func:`_resolve_auto_backend`.
    """

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
        # census  — atomic write so a power-loss mid-write can't corrupt the
        # secrets store (ACME keys / OAuth tokens / session secrets); 0o600 so
        # the ciphertext file is owner-only (defense-in-depth on the encryption).
        from email_triage._atomicio import atomic_write_bytes
        atomic_write_bytes(self._store_path, encrypted, mode=0o600)

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
        #  — the shared sqlite3.Connection cannot be used by two
        # threads at once (the driver raises InterfaceError). DbSecrets
        # is a process-wide singleton called from ~23 async handlers;
        # serialise every connection touch on the process-wide write
        # lock — the same RLock @db_write / db_call take — so a secrets
        # read never collides with a request-surface db_call worker.
        # Only the DB read is inside the lock; the Fernet decrypt below
        # is pure CPU and is deliberately left outside it.
        with get_write_lock():
            row = self._conn.execute(
                f"SELECT ciphertext FROM {self._table} WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        ciphertext = row_get(row, "ciphertext", 0)  # N-234 R23 SSOT — sqlcipher3 Row-factory hazard
        from cryptography.fernet import InvalidToken
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as e:
            # The row exists but won't decrypt — corrupt ciphertext or
            # a master-key mismatch. Surface a typed, logged error
            # instead of letting an opaque cryptography exception
            # escape into callers (OTP send, lifespan startup) — .
            logger.error(
                "DbSecrets: could not decrypt secret — corrupt row or master-key mismatch",
                extra={"secret_key": key},
            )
            raise SecretsDecryptError(key) from e

    def set(self, key: str, value: str) -> None:
        # Encrypt before taking the lock — pure CPU, no need to hold the
        # write lock for it. The INSERT/UPSERT + commit run under the
        # process-wide write lock so the shared connection is
        # never touched by two threads at once.
        ciphertext = self._fernet.encrypt(value.encode()).decode()
        now = now_utc_iso()
        with get_write_lock():
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
        # DELETE + commit under the process-wide write lock.
        with get_write_lock():
            cur = self._conn.execute(
                f"DELETE FROM {self._table} WHERE key = ?", (key,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def list_keys(self) -> list[str]:
        # SELECT under the process-wide write lock — a read on
        # the shared connection still collides with a concurrent
        # writer, so every touch is serialised, reads included.
        with get_write_lock():
            rows = self._conn.execute(
                f"SELECT key FROM {self._table} ORDER BY key"
            ).fetchall()
        return [row_get(r, "key", 0) for r in rows]  # N-234 R23 SSOT

    @staticmethod
    def generate_master_key() -> str:
        """Generate a fresh Fernet key. Returns base64 string."""
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()

    # ------------------------------------------------------------------
    # H-02a master-key version registry (Cycle 6, 2026-05-23)
    # ------------------------------------------------------------------
    #
    # The audit log_entries hash chain HMACs each row under a key HKDF-
    # derived from the master key (see
    # ``derive_audit_chain_hmac_key`` below). Rotating the master key
    # changes the derived HMAC subkey, which would orphan every legacy
    # HMAC-signed log_entries row written under the old master.
    #
    # Per hipaa-sme-2 + DA-3 verdicts 2026-05-23 (R1-plumbing-IN), the
    # rotation ceremony PRESERVES old masters in the secrets_store via
    # the key-encrypting-key (KEK) pattern (NIST SP 800-57 §6.2.2): the
    # outgoing master is encrypted under the NEW master's Fernet and
    # stored as ``master_key_history:v{N}`` where N is the version that
    # was active BEFORE the rotation. The next NEW row written to
    # log_entries stamps ``master_key_version = N + 1`` (the new
    # current version) so the verifier can pick the right HMAC subkey
    # for each chain-aware row.
    #
    # Version derivation is deliberately schema-light: the master-key-
    # version state lives in the secrets_store as ``master_key_history:v*``
    # rows. ``current_master_version()`` returns ``max(N for v{N} rows) + 1``
    # (or 0 if no history rows exist — initial deployment). No separate
    # settings-table row + no separate version column on
    # ``secrets_store``; the history rows themselves ARE the registry.

    _MASTER_KEY_HISTORY_PREFIX = "master_key_history:v"

    def _list_master_key_history_versions(self) -> list[int]:
        """Return sorted list of historical master-key version numbers.

        Reads ``master_key_history:v{N}`` rows from ``secrets_store`` and
        returns ``[N1, N2, ...]`` sorted ascending. Empty list on fresh
        installs (no rotations yet).

        Used by :meth:`current_master_version` and by audit-chain
        startup (lifespan loads all historical keys into the version
        map for verifier dispatch).
        """
        with get_write_lock():
            rows = self._conn.execute(
                f"SELECT key FROM {self._table} "
                f"WHERE key LIKE ? ORDER BY key",
                (self._MASTER_KEY_HISTORY_PREFIX + "%",),
            ).fetchall()
        versions = []
        for r in rows:
            k = row_get(r, "key", 0)  # N-234 R23 SSOT
            try:
                n = int(k[len(self._MASTER_KEY_HISTORY_PREFIX):])
                versions.append(n)
            except (ValueError, IndexError):
                # Malformed history key — skip silently; not load-bearing
                # for verification (only versions referenced by actual
                # log_entries rows matter).
                continue
        return sorted(versions)

    def current_master_version(self) -> int:
        """Return the version number of the *current* master key.

        Initial deployment (no rotations) → 0.
        After N rotations → N.
        """
        versions = self._list_master_key_history_versions()
        return (max(versions) + 1) if versions else 0

    def get_historical_master_key(self, version: int) -> bytes | None:
        """Return the decrypted historical master key for ``version``, or None.

        ``version`` of 0 means "the initial master key" (no rotations have
        occurred for it). If 0 is requested AND no rotations have ever
        happened, returns ``self._fernet``'s key — but the live master
        key is not directly exposed by Fernet, so this helper instead
        returns None in that case; callers (audit-chain startup) should
        treat the live master separately (it's already in
        ``self._fernet``; HKDF-derive the chain key directly from it).

        For rotated installs: the v{0}..v{N-1} rows in secrets_store
        contain prior-master ciphertexts encrypted under the
        *current* master (per KEK pattern in rotate_master_key). Decrypt
        with self._fernet and return the bytes.

        Returns the decoded historical master key as bytes, or None if
        no history row exists for that version.
        """
        if version >= self.current_master_version():
            # Caller wants the live master — they should not need this
            # function; the live key sits in ``self._fernet`` already.
            # Return None to surface the API misuse (lifespan caller
            # filters out the current version before calling).
            return None
        key_name = f"{self._MASTER_KEY_HISTORY_PREFIX}{version}"
        ciphertext = self.get(key_name)  # decrypts under current master
        if ciphertext is None:
            return None
        return ciphertext.encode()

    def rotate_master_key(self, new_master_key: str) -> int:
        """Re-encrypt every row with a new master key, atomically.

        Reads each ciphertext with the *current* key, encrypts with the
        new key, and UPDATEs the row inside a single transaction.  If
        anything fails, the transaction rolls back and the old master
        key remains valid.

        **H-02a (Cycle 6, 2026-05-23)**: also preserves the outgoing
        master key as a ``master_key_history:v{N}`` row encrypted under
        the NEW master (key-encrypting-key pattern per NIST SP 800-57
        §6.2.2). This is REQUIRED for §164.312(c)(1) integrity of the
        ``log_entries`` HMAC chain across the rotation boundary:
        without preserved old masters, every legacy HMAC-signed audit
        row becomes unverifiable at the next rotation, breaking
        §164.316(b)(2)(i) 6-year retention. The new HMAC key is HKDF-
        derived from the new master at startup (see
        :func:`derive_audit_chain_hmac_key` + audit-chain lifespan
        wiring in web/app.py).

        The caller is responsible for:
          - Stopping the running app before rotation (running app
            processes cache the old Fernet instance in memory)
          - Storing the new key in the bootstrap backend after this
            returns successfully

        Returns the number of rows re-encrypted (excluding the new
        history row added in this call — that row is internal
        bookkeeping, not a user secret).
        """
        from cryptography.fernet import Fernet
        if isinstance(new_master_key, str):
            new_master_key = new_master_key.encode()
        new_fernet = Fernet(new_master_key)

        # Determine the version number we are rotating FROM. The new
        # ``master_key_history:v{N}`` row uses this N — the version that
        # was current before the rotation.
        rotating_from_version = self.current_master_version()

        # Wrap the outgoing master key under the NEW key's Fernet
        # BEFORE entering the transaction. KEK pattern: the historical
        # master sits at-rest encrypted under the current master, the
        # same protection-tier as every other secrets_store row.
        old_master_bytes = self._fernet_master_key_bytes()
        wrapped_old_master = new_fernet.encrypt(old_master_bytes).decode()
        history_key = (
            f"{self._MASTER_KEY_HISTORY_PREFIX}{rotating_from_version}"
        )

        # .3 — close the SELECT-before-BEGIN TOCTOU window. If we
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
        now = now_utc_iso()
        #  — the whole BEGIN IMMEDIATE … COMMIT/ROLLBACK transaction
        # runs under the process-wide write lock so the shared
        # connection is never touched by another thread mid-rotation.
        # The lock spans the ROLLBACK in the except branch too — that
        # ROLLBACK is itself a connection touch. The Fernet
        # decrypt/encrypt inside the loop necessarily runs under the
        # lock here: it is interleaved with the per-row UPDATEs of one
        # atomic transaction and cannot be hoisted out.
        with get_write_lock():
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                rows = self._conn.execute(
                    f"SELECT key, ciphertext FROM {self._table}"
                ).fetchall()
                for row in rows:
                    # N-234 R23: route through row_get SSOT — sqlcipher3
                    # Row-factory hazard on secret decrypt.
                    k = row_get(row, "key", 0)
                    old_ct = row_get(row, "ciphertext", 1)
                    # Decrypt with the *old* key (our _fernet) and
                    # re-encrypt with new. Any failure here aborts the
                    # whole rotation.
                    plaintext = self._fernet.decrypt(old_ct.encode())
                    new_ct = new_fernet.encrypt(plaintext).decode()
                    self._conn.execute(
                        f"UPDATE {self._table} SET ciphertext = ?, "
                        f"updated_at = ? WHERE key = ?",
                        (new_ct, now, k),
                    )
                # H-02a: insert the wrapped outgoing master as a history
                # row. UPSERT shape protects against re-running rotation
                # against a partially-rotated DB (idempotent on the
                # version slot — though such a re-run is itself a bug,
                # the row already encrypted under the new key would
                # still decrypt cleanly).
                self._conn.execute(
                    f"INSERT INTO {self._table} "
                    f"(key, ciphertext, created_at, updated_at) "
                    f"VALUES (?, ?, ?, ?) "
                    f"ON CONFLICT(key) DO UPDATE SET "
                    f"ciphertext = excluded.ciphertext, "
                    f"updated_at = excluded.updated_at",
                    (history_key, wrapped_old_master, now, now),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

        # Swap the in-memory key so subsequent get/set calls use the new
        # one immediately — matches what the app would see after restart.
        self._fernet = new_fernet
        return len(rows)

    def _fernet_master_key_bytes(self) -> bytes:
        """Return the bytes of the current Fernet master key.

        Used by :meth:`rotate_master_key` to wrap the outgoing master
        under the new master (KEK pattern). Fernet does not expose its
        key directly via a public attribute; this helper reads the
        underlying signing+encryption key bytes from the
        :class:`cryptography.fernet.Fernet` instance.

        Implementation: a Fernet key is the urlsafe-base64 encoding of
        16 bytes signing key + 16 bytes encryption key. The Fernet
        instance keeps these on private attributes ``_signing_key``
        and ``_encryption_key``. We reconstruct the original key
        bytes by base64-encoding their concatenation.

        This helper is internal — callers outside ``rotate_master_key``
        should not need it.
        """
        import base64
        return base64.urlsafe_b64encode(
            self._fernet._signing_key + self._fernet._encryption_key
        )


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

# ---------------------------------------------------------------------------
# H-07 env-backend deprecation surface (Cycle 6, 2026-05-24)
# ---------------------------------------------------------------------------
#
# Per the EnvSecrets section docstring above. The selection-time
# deprecation warning fires from this helper at every factory call site
# that resolves to the env backend, gated by:
#
#   - HIPAA mode: silent (the G1' RuntimeError in
#     :func:`enforce_master_key_at_rest_for_hipaa` fires earlier in
#     lifespan / CLI bootstrap; a second warning here would be noise on
#     top of an already-fatal boot)
#   - Carve-out env var ``EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY`` set to a
#     truthy value (``1`` / ``true`` / ``yes``, case-insensitive): silent.
#     This is the documented dev/CI opt-in.
#
# A module-level once-per-process latch prevents repeated emission when
# the factory is called from multiple lifespan / CLI paths within one
# process (web app + CLI subcommand sharing the same interpreter).
# The latch + log.warning are not thread-safe by construction — at
# worst, two threads racing through the gate both emit the warning,
# which is the operator-detection-friendly degradation (two warnings
# vs zero). Per db-sme-2 cross-route Q1: no behavior change beyond the
# log.warning side-effect; no shared mutable state touched outside the
# latch flag itself.

_ENV_BACKEND_CARVE_OUT_VAR = "EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY"
_env_backend_selection_warned = False


def _env_backend_carve_out_active() -> bool:
    """Return True when the operator has opted into the dev/CI carve-out.

    Truthy values: ``1``, ``true``, ``yes`` (case-insensitive). Anything
    else — including unset, empty string, ``0``, ``false``, ``no``,
    ``off``, garbage — is treated as the carve-out NOT being active,
    which means the deprecation warning fires.
    """
    from email_triage._envbool import parse_bool
    return parse_bool(os.environ.get(_ENV_BACKEND_CARVE_OUT_VAR))


def _warn_env_backend_deprecation() -> None:
    """Emit the H-07 selection-time deprecation warning for env backend.

    No-op if:
      - already warned once in this process (once-per-process latch), OR
      - HIPAA mode is enabled (G1' RuntimeError handles HIPAA case), OR
      - the carve-out env var is set to a truthy value (dev/CI opt-in).

    Called from :func:`create_secrets_provider` and
    :func:`_resolve_auto_backend` at every site that lands on the env
    backend.
    """
    global _env_backend_selection_warned
    if _env_backend_selection_warned:
        return
    # Late-bind the HIPAA-mode check to avoid an import cycle: this
    # module is imported very early during config parsing, before
    # triage_logging is necessarily settled. The late import inside the
    # function matches the pattern in
    # :func:`enforce_master_key_at_rest_for_hipaa`.
    try:
        from email_triage.triage_logging import is_hipaa_mode
        if is_hipaa_mode():
            # G1' enforce_master_key_at_rest_for_hipaa() will RuntimeError
            # later in lifespan / CLI bootstrap; don't pile a warning on
            # top of an already-fatal boot.
            return
    except Exception:
        # If the HIPAA-mode probe fails for any reason (cycle, import
        # error during test fixture setup), default to emitting the
        # warning — operator-detectable surfacing is the safer default.
        pass
    if _env_backend_carve_out_active():
        return
    logger.warning(
        "secrets.backend='env' is DEPRECATED (H-07). The Fernet master "
        "key is visible via /proc/<pid>/environ and `podman inspect`. "
        "Migrate to 'container' (podman/docker secret), 'keyfile' "
        "(mode 0600 on disk), 'keyring' (OS credential store), or "
        "'external:<name>' (Vault / KeePass / AWS Secrets Manager / "
        "etc.). For dev / CI use cases, set %s=1 to suppress this "
        "warning. Deprecation: warning becomes RuntimeError (unless "
        "the carve-out env var is set), then env backend is removed "
        "— removal timeline pending explicit operator directive.",
        _ENV_BACKEND_CARVE_OUT_VAR,
    )
    _env_backend_selection_warned = True


def _reset_env_backend_warn_latch_for_tests() -> None:
    """Test-only: reset the once-per-process latch.

    Exposed for unit tests that need to exercise multiple selection
    paths in one pytest process. NOT public API; not for use outside
    ``tests/``.
    """
    global _env_backend_selection_warned
    _env_backend_selection_warned = False


def _resolve_auto_backend(container_path: str, master_key_name: str) -> str:
    """Resolve the deployment-aware ``auto`` backend.

    Prefers ``container`` when the master key is present as a container
    secret (``<container_path>/<master_key_name>``) — that keeps the
    Fernet master key out of the process environment. Falls back to
    ``env`` otherwise, with a loud WARNING: the env backend exposes the
    key via ``/proc/<pid>/environ`` and ``podman inspect``.
    """
    import os

    # N-242b R24: TriageLogger SSOT — HMAC-chain audit sink.
    log = get_logger("secrets")
    candidate = os.path.join(container_path, master_key_name)
    if os.path.isfile(candidate):
        log.info(
            "secrets backend 'auto' resolved to 'container'",
            extra={"error_msg": str(candidate)},
        )
        return "container"
    log.warning(
        "secrets backend 'auto' resolved to 'env' — Fernet master key "
        "will be read from process environment (visible via "
        "/proc/<pid>/environ + `podman inspect`). For hardened deploy, "
        "provide the key as a podman/docker secret with the configured "
        "master_key_name, or set secrets.backend explicitly to 'keyfile'.",
        extra={"error_msg": str(candidate), "name": master_key_name},
    )
    # H-07 (Cycle 6): distinct from the auto-fell-back warning above —
    # this one is the env-backend deprecation warning gated by HIPAA
    # mode + carve-out env var. The auto-fell-back warning explains
    # WHY we landed on env; the deprecation warning says env is going
    # away.
    _warn_env_backend_deprecation()
    return "env"


def create_secrets_provider(
    backend: str,
    keyfile_path: str = "~/.config/email-triage/key",
    container_path: str = "/run/secrets",
    external_config: dict[str, Any] | None = None,
    master_key_name: str = "ET_MASTER_KEY",
) -> SecretsProvider:
    """Create a *bootstrap* secrets provider from a backend name.

    This returns the provider that supplies the master key.  For the
    runtime secret store (user-managed secrets) see ``DbSecrets``.

    ``backend="auto"`` is deployment-aware — it resolves to
    ``container`` when the master key is present as a container secret
    (``<container_path>/<master_key_name>``), else to ``env`` with a
    loud WARNING. ``master_key_name`` is only consulted for that
    ``auto`` resolution.
    """
    if backend == "auto":
        backend = _resolve_auto_backend(container_path, master_key_name)
    if backend == "container":
        return ContainerSecrets(container_path)
    elif backend == "env":
        # H-07 (Cycle 6): emit selection-time deprecation warning unless
        # HIPAA mode (G1' RuntimeError fires) or carve-out env var set.
        # The _resolve_auto_backend path above already emitted via its
        # own call to this helper; the latch makes the second call a
        # no-op so the warning only fires once per process.
        _warn_env_backend_deprecation()
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
            "Expected one of: auto, container, env, keyfile, keyring, "
            "external:<name>"
        )


def read_bootstrap_master_key(cfg: Any) -> str:
    """Read the Fernet master key from the bootstrap backend — NO DB needed.

    Steps 1-2 of :func:`bootstrap_secrets_from_config`, factored out for
    the v0.1.2 single-file encryption encrypted-boot ordering: the
    SQLCipher storage key is HKDF-derived from this master key, so the
    key MUST be read BEFORE the (encrypted) DB connection is opened —
    whereas :func:`bootstrap_secrets_from_config` needs the open
    connection to construct ``DbSecrets``.

    The master key lives in the *bootstrap backend* (env / keyfile /
    container secret / keyring / external), NOT in the DB itself, so this
    read has no chicken-and-egg dependency on the database. The
    encrypted ``secrets_store`` *table* (which DbSecrets reads later) is a
    separate surface that only becomes readable AFTER the encrypted
    connection is open.

    Raises ``SecretNotFound`` if the master key is missing — a hard
    failure; the app cannot start (encrypted OR plaintext) without it.
    """
    bootstrap = create_secrets_provider(
        cfg.secrets.backend,
        keyfile_path=cfg.secrets.keyfile_path,
        external_config=cfg.secrets.external,
        master_key_name=cfg.secrets.master_key_name,
    )
    return read_secret_required(bootstrap, cfg.secrets.master_key_name)


def bootstrap_secrets_from_config(
    conn: Any, cfg: Any, *, master_key: str | None = None
) -> SecretsProvider:
    """Build the runtime ``DbSecrets`` provider from a ``TriageConfig``.

    1. Build the bootstrap provider from ``cfg.secrets.backend``.
    2. Read the master key from it using ``cfg.secrets.master_key_name``.
    3. Wrap the DB connection in ``DbSecrets`` using that key.

    Raises ``SecretNotFound`` if the master key is missing from the
    bootstrap store — this is a hard failure; the app cannot start
    without a master key.

    ``master_key`` (optional,  Phase 4): when the caller has ALREADY
    read the master key via :func:`read_bootstrap_master_key` (the
    encrypted-boot path reads it before opening the DB), pass it here to
    skip a redundant second bootstrap-backend read. When ``None`` (the
    plaintext path + every existing caller), steps 1-2 run as before.
    """
    if master_key is None:
        master_key = read_bootstrap_master_key(cfg)
    return DbSecrets(conn, master_key)


# ---------------------------------------------------------------------------
# H-02a audit-chain HMAC key derivation (Cycle 6, 2026-05-23)
# ---------------------------------------------------------------------------

# The ``log_entries`` hash chain HMACs each row under a key derived from the
# master key via HKDF-SHA256 per RFC 5869. The derived subkey narrows the
# blast radius of any single-purpose key compromise:
#
#   - An attacker who reads the HMAC chain subkey can forge audit rows but
#     cannot decrypt secrets_store ciphertexts (those use the master Fernet
#     key directly, not the derived HMAC subkey).
#   - An attacker who reads the master key has both surfaces, but that
#     attacker has already won — they can decrypt every secret and forge
#     the audit chain regardless of how the chain key is derived.
#
# Why HKDF and not raw master key:
#
#   1. NIST SP 800-108 / RFC 5869 standard construction for per-purpose
#      subkey derivation.
#   2. ``cryptography`` library already a dep (see DbSecrets Fernet import).
#   3. Versioned ``info`` string reserves space for future cryptographic
#      upgrades (e.g., HKDF-SHA512 or post-quantum) without ambiguity about
#      which row was hashed under which derivation.
#
# The ``info`` field is the per-purpose label per RFC 5869 §3.2; using a
# project-namespaced + purpose-qualified + version-tagged string makes the
# derivation deterministic AND distinct from any other HKDF call site
# (current or future) under the same master.
#
# Per medical-scope drawer §2.6: this docstring + the ``info`` constant
# together name the regulatory framework (§164.312(c)(1) Required-spec
# integrity), the standard (RFC 5869), and the version suffix (v1) so a
# future auditor can trace the derivation without cross-referencing.

_AUDIT_CHAIN_HMAC_HKDF_INFO_V1 = b"email_triage/audit/log_chain/hmac/v1"


def derive_audit_chain_hmac_key(master_key: str | bytes) -> bytes:
    """Derive the audit-chain HMAC-SHA256 subkey via HKDF-SHA256.

    Implements RFC 5869 HKDF-Extract-and-Expand with:
        algorithm = SHA256
        length    = 32 bytes (HMAC-SHA256 block size)
        salt      = None (HKDF treats absent salt as a zero-block; the
                    master key itself provides the entropy)
        info      = ``_AUDIT_CHAIN_HMAC_HKDF_INFO_V1`` (versioned per-
                    purpose label)

    Closes H-02a §164.312(c)(1) Required-spec integrity gap by giving
    ``compute_log_row_hash`` a secret it can HMAC under — defeating the
    insider-with-DB-write threat model the prior SHA-256-secretless
    chain admitted (per hipaa-sme-2 Cycle-5 second-pass verdict).

    Args:
        master_key: the Fernet master key (str or bytes). Either form
            is accepted; bytes is encoded internally.

    Returns:
        32 raw bytes suitable for use as an HMAC-SHA256 key. NOT the
        Fernet representation; this is the OUTPUT of HKDF, not a key
        for any other cryptographic primitive.

    References:
        - RFC 5869 (HKDF) §3.1, retrieved 2026-05-23 from
          https://www.rfc-editor.org/rfc/rfc5869
        - NIST SP 800-108 Rev. 1 (Key Derivation Using PRFs), §6.3
          (HKDF as an instantiation), retrieved 2026-05-23 from
          https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf
        - NIST SP 800-66 Rev. 2 §4.4 (HIPAA Security Rule integrity-
          control implementations), retrieved 2026-05-23 from
          https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if isinstance(master_key, str):
        master_key_bytes = master_key.encode("utf-8")
    else:
        master_key_bytes = master_key

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_AUDIT_CHAIN_HMAC_HKDF_INFO_V1,
    )
    return hkdf.derive(master_key_bytes)


def enforce_master_key_at_rest_for_hipaa(cfg: Any) -> None:
    """G1' boot-time enforcement of master-key at-rest protection.

    Per H-02a + G1' verdict (hipaa-sme-2 + DA-3 2026-05-23): when HIPAA
    mode is enabled, the HKDF-derived audit-chain HMAC subkey is
    structurally meaningful ONLY if the master key itself meets
    §164.312(a)(2)(iv) at-rest protection. This helper enforces that
    requirement at boot time — fail-closed if the deploy is misconfigured.

    Rules:

    - HIPAA mode + ``secrets.backend == 'env'`` → RuntimeError. The env
      backend exposes the Fernet master key via ``/proc/<pid>/environ``
      and ``podman inspect``, which renders the HMAC subkey forgeable
      by the same insider-with-DB-write attacker H-02a is designed to
      stop.
    - HIPAA mode + ``secrets.backend == 'keyfile'`` + non-0600 file
      permissions → RuntimeError. Group/world-readable keyfile = same
      attacker class.
    - All other backends (``container``, ``keyring``, ``external:*``)
      are accepted: each delegates at-rest protection to a system with
      a credible security model (container runtime / OS keyring /
      purpose-built secrets backend).

    Outside HIPAA mode this helper is a no-op — the env backend is
    still operational for dev/CI surfaces. Per medical-scope drawer
    §2 principle 1: H-02a's threat model is HIPAA-scoped, not
    universal.

    The companion finding H-07 (deprecate env-backend entirely) tracks
    the broader carve-out cleanup as Cycle 6 must-land separately (or
    operator-routed defer with concrete reason) per the consolidated
    GO 2026-05-23.

    Args:
        cfg: a ``TriageConfig``-shaped object whose ``.secrets``
            attribute exposes ``.backend`` and ``.keyfile_path``.

    Raises:
        RuntimeError: if HIPAA mode is on AND the master-key backend
            is one of the forbidden shapes above.
    """
    # Late-bind the HIPAA-mode check to avoid a cycle: triage_logging
    # already imports from secrets indirectly via web.db's shim chain.
    from email_triage.triage_logging import is_hipaa_mode
    if not is_hipaa_mode():
        return
    backend = getattr(cfg.secrets, "backend", None)
    if backend == "env":
        raise RuntimeError(
            "H-02a (§164.312(c)(1) + §164.312(a)(2)(iv)): HIPAA mode is "
            "enabled but secrets.backend='env'. The env backend exposes "
            "the Fernet master key via /proc/<pid>/environ and `podman "
            "inspect`, which renders the HKDF-derived audit-chain HMAC "
            "subkey structurally meaningless against the insider-with-"
            "DB-write threat model H-02a closes. Use "
            "secrets.backend='container' / 'keyring' / 'external:<name>' "
            "/ 'keyfile' (mode 0600) instead. Per hipaa-sme-2 + DA-3 G1' "
            "boot-enforcement verdict 2026-05-23."
        )
    if backend == "keyfile":
        kpath = getattr(cfg.secrets, "keyfile_path", None)
        if kpath:
            expanded = os.path.expanduser(str(kpath))
            try:
                mode = os.stat(expanded).st_mode
            except FileNotFoundError:
                # The bootstrap path would already have raised
                # SecretNotFound if the keyfile was actually missing;
                # reaching here means the path resolves differently
                # between bootstrap and this stat (rare; misconfig).
                raise RuntimeError(
                    f"H-02a: keyfile {expanded} not stat-able during "
                    f"boot-enforcement check. Per G1' verdict, HIPAA "
                    f"mode requires the keyfile to exist at mode 0600."
                )
            if mode & 0o077:
                raise RuntimeError(
                    f"H-02a (§164.312(c)(1) + §164.312(a)(2)(iv)): "
                    f"HIPAA mode is enabled and secrets.backend="
                    f"'keyfile' but {expanded} has mode "
                    f"{oct(mode & 0o777)} (group/world bits set). "
                    f"Fernet master key must be 0600 (owner-only). "
                    f"Run: chmod 600 {expanded}. Per hipaa-sme-2 + "
                    f"DA-3 G1' boot-enforcement verdict 2026-05-23."
                )


def wire_audit_chain_hmac_keys(
    provider: SecretsProvider,
    cfg: Any,
) -> None:
    """Derive + register HMAC subkeys for every known master-key version.

    Called once at app startup (web/app.py lifespan + every CLI bootstrap
    that opens a DbSecrets provider) AFTER the provider is populated and
    AFTER :func:`enforce_master_key_at_rest_for_hipaa` has gated the
    deploy. Registers the resulting version → key map with
    :func:`email_triage.db.audit.set_hmac_keys` so subsequent
    ``compute_log_row_hash`` / ``verify_log_chain`` calls find the keys
    they need.

    Per H-02a R1-plumbing-IN verdict (hipaa-sme-2 + DA-3 2026-05-23):
    legacy HMAC chain rows must remain verifiable across master-key
    rotations per §164.316(b)(2)(i) 6-year retention. The
    ``DbSecrets.rotate_master_key`` ceremony preserves outgoing master
    keys under ``secrets_store:master_key_history:v{N}`` via the KEK
    pattern; this helper loads each preserved version, decrypts it
    (chain-of-trust via the current master), HKDF-derives a chain
    subkey from each, and registers them all.

    For non-DbSecrets providers (e.g., a future read-only external
    backend), only the current master is reachable (no history surface).
    Such deploys register HMAC key version 0 only; rotation requires
    custom plumbing per that backend's contract.

    Args:
        provider: the runtime secrets provider returned by
            :func:`bootstrap_secrets_from_config`.
        cfg: a ``TriageConfig``-shaped object whose ``.secrets``
            attribute exposes ``.master_key_name``.

    Side effects:
        Populates the module-level HMAC registry in
        ``email_triage.db.audit`` via ``set_hmac_keys``.
    """
    # Late-bind to avoid an import cycle (db.audit doesn't import
    # secrets at module load; the import here lives inside a function).
    from email_triage.db.audit import set_hmac_keys

    if isinstance(provider, DbSecrets):
        current_version = provider.current_master_version()
        current_master_bytes = provider._fernet_master_key_bytes()
        hmac_keys: dict[int, bytes] = {
            current_version: derive_audit_chain_hmac_key(current_master_bytes),
        }
        for v in provider._list_master_key_history_versions():
            if v >= current_version:
                continue
            historical = provider.get_historical_master_key(v)
            if historical is None:
                # Operator-visible: a history row is missing or
                # undecryptable. The verifier will raise a chain
                # break on any row referencing this version. Log at
                # WARNING so this surfaces in the operator's /logs
                # viewer immediately.
                logger.warning(
                    "H-02a: master_key_history version missing or "
                    "undecryptable; legacy chain rows under that "
                    "version will fail verification with "
                    "operator-detectable error. Restore the row "
                    "before continuing if any log_entries reference "
                    "this version.",
                    extra={"n": v},
                )
                continue
            hmac_keys[v] = derive_audit_chain_hmac_key(historical)
        set_hmac_keys(hmac_keys, current_version=current_version)
        return

    # Non-DbSecrets provider — only the current master is exposed.
    current_master_str = provider.get(cfg.secrets.master_key_name) or ""
    if current_master_str:
        set_hmac_keys(
            {0: derive_audit_chain_hmac_key(current_master_str)},
            current_version=0,
        )
