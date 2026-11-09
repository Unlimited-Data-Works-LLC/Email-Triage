"""SQLAlchemy Core engine factory for v0.1.2 single-file encryption.

This module is the engine/connection-pool seam between the application
helpers and the underlying SQLite + SQLCipher backend. It exposes a
``create_engine_for_app(db_path, *, encrypted=...)`` factory that:

  * derives the single SQLCipher storage key from the existing
    ``DbSecrets`` master via HKDF-SHA256 (RFC 5869), reusing the
    EQM-05 audit-chain HMAC-key derivation precedent so no new
    §164.308(a)(4)(ii)(C) Access Management key-management surface
    is introduced;
  * uses SA Core's ``create_engine("sqlite://", creator=...)`` pattern
    so the encrypted DBAPI driver is :mod:`sqlcipher3` (sync; coleifer
    fork; the only actively-maintained Python SQLCipher binding) —
    NOT the deprecated ``sqlite+pysqlcipher://`` URL dialect (which
    points at the abandoned ``pysqlcipher3`` driver) and NOT the
    incompatible ``sqlite+aiosqlite://`` URL (``aiosqlite`` wraps
    stdlib ``sqlite3``, not ``sqlcipher3``; per builder-2 + DA-2
    SHOWSTOPPER verdict 2026-05-28);
  * runs every post-connect PRAGMA (``key`` BEFORE any other SQL, then
    journal_mode=WAL, busy_timeout=30000, foreign_keys=ON,
    cached_statements=0 per CPython #118172 mitigation from Phase 0
    ) under a single ``creator`` callable so the engine is fully
    populated by the time the writer thread accepts work.

Why SA Core (not ORM)
---------------------
Per ``internal documentation`` §0 + §2: hand-tuned SQL
with qmark ``?`` placeholders is retained at every callsite. SA Core
exists here ONLY to (a) give Alembic a stable ``Engine`` to introspect
for migrations, (b) provide the ``creator=`` pattern that wires
``sqlcipher3`` cleanly, and (c) be the v0.2.0  forward-compat seam
where the URL swaps from ``sqlite://`` to ``postgresql+asyncpg://``.
No declarative models. No identity map. No sessions.

§-anchors (§164.316(b)(1) policies-and-procedures inline coverage per
EQM-08 row):
    §164.312(a)(2)(iv) Encryption — single-file SQLCipher AES-256-CBC
        + HMAC-SHA512 page integrity via the ``sqlcipher3-binary``
        coleifer fork; ``PRAGMA key`` raw-hex form bypasses PBKDF2
        because HKDF already produces a uniform 256-bit key.
    §164.308(a)(4)(ii)(C) Access Management — key derivation is a
        thin HKDF wrapper around the master key already enforced
        per ``secrets.enforce_master_key_at_rest_for_hipaa``.
"""

from __future__ import annotations

import logging

from email_triage.triage_logging import get_logger  # N-196b R21_4
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote

logger = get_logger("email_triage.db._engine")  # N-196b R21_4

# Punch 547 (operator directive 2026-09-29): the encryption mode has ONE store,
# the ``persistence.encryption_enabled`` config field. The former
# ``EMAIL_TRIAGE_DB_ENCRYPTION`` env override is gone. Config is loaded BEFORE the
# DB is opened, so the field can always decide; an env var that can turn
# encryption off is a bypass anyone with quadlet write access can type. A
# leftover setting is REFUSED at start (``_env_registry.RETIRED``).

# -b (2026-07-11) — CONFIG-DRIVEN sqlite3 lock-wait budgets, per
# feedback_dynamic_over_hardcoding. Pre-fix, ~10 sites hardcoded
# ``timeout=30.0`` / ``busy_timeout=30000`` / ``timeout=5.0`` as float
# literals. These module-level constants are the single source of
# truth; every opener + PRAGMA site reads them. Boot-time wiring
# (``cli._boot_from_config``) calls :func:`configure_sqlite_timeouts`
# with the resolved ``PersistenceConfig`` values so a YAML tune reaches
# ALL sites in one hop.
#
# Defaults preserve the prior hardcoded behavior byte-identically:
#   30.0 s standard-opener busy wait
#   30000 ms PRAGMA busy_timeout (derived: 30.0 * 1000)
#    5.0 s short-probe budget (plaintext detection, migration probes)
_SQLITE_BUSY_WAIT_SECS: float = 30.0
_SQLITE_PROBE_TIMEOUT_SECS: float = 5.0


def configure_sqlite_timeouts(
    busy_wait_secs: float = 30.0,
    probe_timeout_secs: float = 5.0,
) -> None:
    """-b — set the process-wide sqlite3 lock-wait budgets.

    Called ONCE at boot from ``cli._boot_from_config`` with the
    resolved ``persistence.sqlite_busy_wait_secs`` +
    ``sqlite_probe_timeout_secs`` values. Every subsequent opener +
    PRAGMA site in this module + ``db/_migrate.py`` + ``web/db.py``
    reads the module-level constants below, so a config change
    propagates uniformly.

    Type-guarded defensively: rejects non-positive values (would
    disable the busy loop) by falling back to the sane default;
    integer inputs are coerced to float for the connect kwarg.

    DB-SME F1 (2026-07-11): also refuses sub-1.0s busy_wait_secs and
    sub-0.5s probe_timeout_secs — sub-1s standard-opener starves WAL
    writers under contention (EBUSY storm at RESERVED-lock acquire);
    sub-0.5s probe is too short even for a bootstrap plaintext check.
    """
    global _SQLITE_BUSY_WAIT_SECS, _SQLITE_PROBE_TIMEOUT_SECS
    if isinstance(busy_wait_secs, (int, float)) and busy_wait_secs >= 1.0:
        _SQLITE_BUSY_WAIT_SECS = float(busy_wait_secs)
    elif isinstance(busy_wait_secs, (int, float)) and busy_wait_secs > 0:
        logger.warning(
            "configure_sqlite_timeouts: busy_wait_secs=%r < 1.0s "
            "refused (would EBUSY-storm under WAL contention); "
            "keeping default %.1f",
            busy_wait_secs, _SQLITE_BUSY_WAIT_SECS,
        )
    if isinstance(probe_timeout_secs, (int, float)) and probe_timeout_secs >= 0.5:
        _SQLITE_PROBE_TIMEOUT_SECS = float(probe_timeout_secs)
    elif isinstance(probe_timeout_secs, (int, float)) and probe_timeout_secs > 0:
        logger.warning(
            "configure_sqlite_timeouts: probe_timeout_secs=%r < 0.5s "
            "refused (too short for a bootstrap plaintext probe); "
            "keeping default %.1f",
            probe_timeout_secs, _SQLITE_PROBE_TIMEOUT_SECS,
        )


def get_sqlite_busy_wait_secs() -> float:
    """Accessor for the current standard-opener lock-wait budget (seconds)."""
    return _SQLITE_BUSY_WAIT_SECS


def get_sqlite_busy_pragma_ms() -> int:
    """Accessor for the ``PRAGMA busy_timeout`` value (milliseconds),
    derived from the standard-opener budget so tuning stays coherent
    between the DBAPI busy loop and the SQL-layer busy loop.
    """
    return int(_SQLITE_BUSY_WAIT_SECS * 1000)


def get_sqlite_probe_timeout_secs() -> float:
    """Accessor for the short-probe budget (seconds) used by boot-time
    plaintext detection and migration integrity probes.
    """
    return _SQLITE_PROBE_TIMEOUT_SECS


# N-432 walresetbug P1 (2026-07-19) — SQLite walresetbug (fixed upstream
# in SQLite 3.51.3, 2026-03-13) races WAL-checkpoint against concurrent
# writers and can corrupt the WAL header. Under an HMAC-chained audit
# table that is §164.312(b)/(c)(1) integrity loss. Baked-in v0.2.0
# versions are 3.45.3 (SQLCipher `sqlcipher3-binary==0.5.4.post2`) +
# 3.46.1 (stdlib libsqlite3 via ``python:3.12-slim``), BOTH < 3.51.3.
# P0 disables auto-checkpoint and serializes checkpoints through the
# writer-lock — this floor sensor is the second layer, so when the
# base image gets a fresh libsqlite3 (or SQLCipher publishes a 3.51.3+
# fork) the operator sees the transition in the boot banner rather
# than learning about it from a CVE tracker. Non-fail-closed: the
# app still starts; the warn goes to the health surface + logs.
SQLITE_WALRESETBUG_FIX_VERSION: tuple[int, int, int] = (3, 51, 3)


def assert_sqlite_walresetbug_floor() -> dict[str, Any]:
    """Emit a WARNING when the running SQLite / SQLCipher is below the
    walresetbug fix floor (3.51.3). Returns a dict recording the current
    versions + `exposed` bool for /health surfacing.

    Called ONCE at lifespan startup after the DB is opened. Non-fatal:
    the P0 (``PRAGMA wal_autocheckpoint = 0`` + serialized checkpoint
    funnel) is the actual mitigation — this sensor exists so a base-
    image bump or a SQLCipher-fork bump becomes visible immediately
    instead of via an out-of-band CVE tracker.
    """
    floor = SQLITE_WALRESETBUG_FIX_VERSION
    stdlib_v = tuple(sqlite3.sqlite_version_info)
    stdlib_exposed = stdlib_v < floor

    # devils-advocate MF-2 (2026-07-19): narrow the except so a
    # HIPAA-mode install where sqlcipher3 IS present but the version
    # probe fails (mispackaged wheel, missing sqlite_version_info attr)
    # does NOT silently mark sqlcipher_available=False. That would MUTE
    # the sensor for the exact install-class it exists to protect.
    sqlcipher_v: tuple[int, ...] | None = None
    sqlcipher_available = False
    sqlcipher_probe_error: str | None = None
    try:
        import sqlcipher3  # lazy: heavy binary
        sqlcipher_available = True
    except ImportError:
        # Plaintext install path — sqlcipher3 legitimately absent. Log at
        # DEBUG so  silent-swallow ratchet is not tripped and an
        # operator investigating why the sensor reports sqlcipher_
        # available=False can grep for the exact reason.
        logger.debug(
            "assert_sqlite_walresetbug_floor: sqlcipher3 not importable "
            "(plaintext install path); walresetbug sensor covers stdlib "
            "arm only."
        )
    if sqlcipher_available:
        try:
            sqlcipher_v = tuple(sqlcipher3.sqlite_version_info)
        except Exception as _probe_exc:  # pragma: no cover — mispackaged wheel
            # Route through fmt_exc SSOT (census run13 #8 + F4) — the hand-
            # rolled twin-idiom would trip test_exc_render_twin_ssot_pin.
            from email_triage._errfmt import fmt_exc
            sqlcipher_probe_error = fmt_exc(_probe_exc, with_class=True)
            logger.warning(
                "SQLCipher present but version-probe FAILED — walresetbug "
                "exposure UNDETERMINED for the encrypted arm. "
                "Investigate sqlcipher3 wheel: %s",
                sqlcipher_probe_error,
            )
    sqlcipher_exposed = (
        sqlcipher_available
        and sqlcipher_v is not None
        and sqlcipher_v < floor
    )

    exposed = stdlib_exposed or sqlcipher_exposed
    status = {
        "at": None,  # caller fills with now_utc_iso()
        "floor": ".".join(str(x) for x in floor),
        "stdlib_version": ".".join(str(x) for x in stdlib_v),
        "sqlcipher_available": sqlcipher_available,
        "sqlcipher_version": (
            ".".join(str(x) for x in sqlcipher_v)
            if sqlcipher_v is not None else None
        ),
        # devils-advocate MF-2: surface UNDETERMINED state for the
        # encrypted arm so /health + register can distinguish "plaintext
        # install" from "sqlcipher present but version-probe failed".
        "sqlcipher_probe_error": sqlcipher_probe_error,
        "stdlib_exposed": stdlib_exposed,
        "sqlcipher_exposed": sqlcipher_exposed,
        "exposed": exposed,
        "mitigations_active": (
            "PRAGMA wal_autocheckpoint=0 + serialized "
            "checkpoint_wal_truncate under @db_write"
        ),
    }

    # hipaa-sme MF-3 (2026-07-19): structured payload so an operator scanning
    # logs on future deploys sees exposed=True + mitigation=P0-writelock-
    # funnel-active together — WARN reads as "known, mitigated, non-
    # actionable on this deployment" not as "unpatched CVE surface".
    _extra = {
        "sqlite3_version": status["stdlib_version"],
        "sqlcipher3_version": status["sqlcipher_version"],
        "sqlcipher_available": status["sqlcipher_available"],
        "floor": status["floor"],
        "exposed": status["exposed"],
        "stdlib_exposed": status["stdlib_exposed"],
        "sqlcipher_exposed": status["sqlcipher_exposed"],
        "mitigation": (
            "P0-writelock-funnel-active"
            if exposed else "P0-defense-in-depth"
        ),
        "mitigations_active": status["mitigations_active"],
    }
    # N-432 Path-3 (2026-07-20) log-clarity fold (DA MF-DA-2): post-Path-3 the
    # sqlcipher arm CLEARS (source-built against SQLCipher v4.20.0 / SQLite
    # 3.54.1) while the stdlib arm remains PRE-3.51.3 (python:3.14-slim base
    # ships Debian's default libsqlite3-0). Render the mixed-arm state so
    # operators reading logs post-Path-3 don't misread `sqlcipher=3.54.1 <
    # fix floor 3.51.3` (WHICH ISN'T TRUE — sqlcipher is ABOVE the floor).
    # Downgrade to INFO when ONLY the stdlib arm is exposed (the PHI-bearing
    # arm is clean + defense-in-depth active per internal documentation
    # §4.34); reserve WARNING for the sqlcipher arm being exposed (still a
    # PHI-integrity red flag).
    if status["sqlcipher_exposed"]:
        logger.warning(
            "SQLite walresetbug exposure on PRIMARY (encrypted PHI) arm — "
            "sqlcipher=%s < fix floor %s (CVE-class WAL header corruption "
            "under concurrent checkpoint race). Mitigations ACTIVE: %s. "
            "Rebuild sqlcipher3 against SQLCipher >= 4.14.0 (Path-3 recipe) "
            "to clear the primary-arm exposure.",
            status["sqlcipher_version"],
            status["floor"],
            status["mitigations_active"],
            extra={"_extra": _extra},
        )
    elif status["stdlib_exposed"]:
        logger.info(
            "SQLite walresetbug floor: SECONDARY (stdlib) arm=%s < %s "
            "(defense-in-depth active); PRIMARY (encrypted PHI, sqlcipher) "
            "arm=%s >= %s (Path-3 walresetbug fix applied). Per "
            "docs/hipaa-findings-register.md §4.34 the stdlib arm is a "
            "non-PHI secondary path with N-432 app-level defenses accepted "
            "as §164.306(d)(3)(ii)(B) equivalent measure.",
            status["stdlib_version"],
            status["floor"],
            status["sqlcipher_version"],
            status["floor"],
            extra={"_extra": _extra},
        )
    else:
        logger.info(
            "SQLite walresetbug floor OK — stdlib=%s sqlcipher=%s "
            ">= %s. Auto-checkpoint pin + serialized checkpoint funnel "
            "still in effect as defense-in-depth.",
            status["stdlib_version"],
            status["sqlcipher_version"],
            status["floor"],
            extra={"_extra": _extra},
        )
    return status

# Single source of truth for the HIPAA-mode-plaintext advisory text so the
# boot-time emit (console/file, immediate) and the §164.312(b) audit-chain
# re-emit (after add_sqlite_handler attaches) are byte-identical.
HIPAA_PLAINTEXT_ADVISORY = (
    "HIPAA mode is ON but persistence.encryption_enabled is OFF. The DB "
    "will open in PLAINTEXT. §164.312(a)(2)(iv) expects encryption-at-rest; "
    "if you rely on disk-level encryption (LUKS/dm-crypt) as the equivalent "
    "measure, record that as an EQM rationale. To enable SQLCipher "
    "single-file encryption set persistence.encryption_enabled=true "
    "(requires the 'encryption' extra + a master key)."
)

# General (non-HIPAA) plaintext-at-rest advisory. email-triage's POSTURE is
# encrypted-at-rest by DEFAULT — the ``init`` scaffold + the example configs set
# persistence.encryption_enabled=true, so a plaintext install is a deliberate or
# legacy exception worth flagging on EVERY boot (operator 2026-06-11: "the
# default should be encrypted anyway; warn on NOT encrypted"). Loud but NOT
# fatal — an existing plaintext install keeps working; this is a nudge to
# convert. (The HIPAA-mode variant above carries the §-anchor + the audit-chain
# re-emit; this plain one is a console/file boot warning only.)
PLAINTEXT_ADVISORY = (
    "DB encryption is OFF — the database is opening in PLAINTEXT at rest. "
    "email-triage defaults to SQLCipher AES-256 encryption-at-rest; enable it "
    "with persistence.encryption_enabled=true + a master key, then convert "
    "the existing file in place with "
    "'email-triage db encrypt'."
)

# Versioned per-purpose HKDF info label. Future schema-evolution that
# changes the derivation contract bumps the ``v1`` suffix — keeping the
# audit-trail per ``feedback_hipaa_sme_standards_2026-05-23.md`` §2.7
# durable-disposition discipline.
_DB_STORAGE_KEY_HKDF_INFO_TMPL = b"email_triage/db/storage_key/%s/v1"


def derive_storage_key(purpose: str, master_key: str | bytes) -> bytes:
    """Derive the single SQLCipher storage key via HKDF-SHA256.

    Mirrors :func:`email_triage.secrets.derive_audit_chain_hmac_key`
    (same algorithm, same length, same salt convention) but with a
    namespaced ``info`` label so the storage-key derivation cannot
    collide with the audit-chain HMAC derivation. Under single-file encryption,
    ``purpose`` is fixed to ``"triage"``; under v0.2.0  pg_tde
    retrofit, ``purpose`` may be per-tablespace.

    Args:
        purpose: per-key namespace tag. ``"triage"`` for the single
            v0.1.2 file; reserved for v0.2.0 expansion.
        master_key: Fernet master key (str or bytes) — same value
            ``DbSecrets`` returns from :meth:`master_key_str`.

    Returns:
        32 raw bytes suitable as the SQLCipher AES-256 key. Pass
        through :func:`format_raw_hex_key` before handing to
        ``PRAGMA key``.

    References:
        - RFC 5869 (HKDF) §3.1.
        - NIST SP 800-66 Rev. 2 §4.4 (HIPAA integrity controls).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if isinstance(master_key, str):
        master_key_bytes = master_key.encode("utf-8")
    else:
        master_key_bytes = master_key

    info_label = _DB_STORAGE_KEY_HKDF_INFO_TMPL % purpose.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info_label,
    )
    return hkdf.derive(master_key_bytes)


def format_raw_hex_key(key: bytes) -> str:
    """Render a 32-byte key as SQLCipher's raw-hex ``PRAGMA key`` form.

    SQLCipher's ``PRAGMA key`` accepts either a passphrase (which it
    runs through PBKDF2-SHA512, 256 000 rounds by default) or a raw
    256-bit key in the ``"x'<64-hex>'"`` syntax that uses the bytes
    directly as the AES-256 key. We use the raw-hex form because the
    HKDF output is already cryptographically uniform — running PBKDF2
    on top adds ~250-500 ms boot cost per connection with zero entropy
    gain. The HKDF derivation IS the §164.308(a)(4)(ii)(C) key-
    derivation control; PBKDF2 would be a redundant second derivation
    surface, not an additional control.

    Raises:
        ValueError: if ``key`` is not exactly 32 bytes (SQLCipher
            rejects any other length under the raw-hex form).
    """
    if len(key) != 32:
        raise ValueError(
            f"SQLCipher raw-hex key must be exactly 32 bytes; got {len(key)}"
        )
    return f"x'{key.hex()}'"


# ---------------------------------------------------------------------------
# N-17 — process-level encrypted-conn context for  dedicated connections
# ---------------------------------------------------------------------------
#
# The  dedicated-connection pattern (audit-chain log handler, acme_jobs
# writer,  write-lock conn) and the CLI / banner read paths open their
# OWN connections on the same DB file as the main boot conn. Before N-17
# those openers did a raw ``sqlite3.connect(db_path)`` with no PRAGMA key —
# on an encrypted install they could not open the file at all (hard crash at
# the first PRAGMA for the audit-chain + acme conns; silent commit-scope /
# isolation loss for the  lock conn via its except-fallback).
#
# Root cause: the SQLCipher key (and the encrypted-vs-plaintext decision)
# lived ONLY inside the boot lifespan + ``_make_encrypted_conn``; the
# dedicated openers had neither the key nor the decision.
#
# Fix: the boot lifespan owns the encryption decision + master key already
# (it calls ``enforce_db_encryption_boot_contract`` + ``read_bootstrap_
# master_key`` before ``init_db_encrypted``). It stamps that resolved
# context HERE, ONCE, via :func:`set_dedicated_conn_encryption`. Every
# dedicated-conn opener then routes through :func:`open_dedicated_conn`,
# which self-selects encrypted-vs-plaintext exactly like the main conn —
# no per-call-site threading of the key through app.py, and the openers
# stay decoupled from config.
#
# Threading the key through a process-level holder (vs. every app.py call
# site) matches how the boot already owns key ordering: the key is read
# once, before any dedicated conn exists, and is process-global by nature
# (one DB file, one key, one process).
#
# §-anchor: §164.312(b) Audit controls — the audit-chain log handler conn
# MUST open against the encrypted file or the tamper-evident log cannot be
# written; a swallowed failure here would silently disable the audit trail
# (the wrong fail-mode), so :func:`open_dedicated_conn` does NOT try/except
# the encrypted open.

_DEDICATED_CONN_ENCRYPTED: bool = False
_DEDICATED_CONN_MASTER_KEY: str | bytes | None = None
_DEDICATED_CONN_PURPOSE: str = "triage"


def set_dedicated_conn_encryption(
    *,
    encrypted: bool,
    master_key: str | bytes | None,
    purpose: str = "triage",
) -> None:
    """Stamp the process-level context the  dedicated-conn openers use.

    Called ONCE by the boot lifespan (and by the CLI entrypoints) AFTER the
    encrypted-vs-plaintext decision is resolved
    (:func:`enforce_db_encryption_boot_contract`) and the master key is
    read (:func:`email_triage.secrets.read_bootstrap_master_key`).

    When ``encrypted`` is True, ``master_key`` MUST be non-None — every
    subsequent :func:`open_dedicated_conn` will HKDF-derive the SQLCipher
    storage key from it. Passing ``encrypted=True`` with no key is a
    programmer error (the boot contract guarantees a key in that mode).
    """
    global _DEDICATED_CONN_ENCRYPTED
    global _DEDICATED_CONN_MASTER_KEY
    global _DEDICATED_CONN_PURPOSE
    if encrypted and master_key is None:
        raise RuntimeError(
            "set_dedicated_conn_encryption(encrypted=True) requires a "
            "master_key — the SQLCipher storage key for #211 dedicated "
            "connections is HKDF-derived from it. The boot contract "
            "guarantees a key in encrypted mode (§164.312(a)(2)(iv))."
        )
    _DEDICATED_CONN_ENCRYPTED = bool(encrypted)
    _DEDICATED_CONN_MASTER_KEY = master_key
    _DEDICATED_CONN_PURPOSE = purpose


def reset_dedicated_conn_encryption() -> None:
    """Clear the dedicated-conn context. Test-fixture teardown only.

    Tests open per-test plaintext DBs; the encrypted context must not leak
    across tests. Production sets the context once at boot and never resets.
    """
    global _DEDICATED_CONN_ENCRYPTED
    global _DEDICATED_CONN_MASTER_KEY
    global _DEDICATED_CONN_PURPOSE
    _DEDICATED_CONN_ENCRYPTED = False
    _DEDICATED_CONN_MASTER_KEY = None
    _DEDICATED_CONN_PURPOSE = "triage"


def dedicated_conn_is_encrypted() -> bool:
    """True iff dedicated-conn openers should open the encrypted SQLCipher
    path this process. Pure read of the stamped boot context."""
    return _DEDICATED_CONN_ENCRYPTED


def open_dedicated_encrypted_conn_readish(db_path: str) -> sqlite3.Connection:
    """Open a READ-ONLY SQLCipher conn (encrypted arm of
    :func:`open_dedicated_conn_readish`). Uses the boot-stamped master key +
    purpose. Caller must guard with :func:`dedicated_conn_is_encrypted` first.

    Punch 556 / N-559: this used to open a READ-WRITE handle and run the
    standard WAL pragmas, on a docstring claim that sqlcipher3 has no
    ``mode=ro`` equivalent. That claim was false: sqlcipher3's ``connect``
    takes ``uri=`` and passes ``SQLITE_OPEN_URI`` to ``sqlite3_open_v2``, so
    ``file:...?mode=ro`` opens SQLite's read-only handle under SQLCipher
    exactly as under stdlib sqlite3 (measured on the shipped image, whose
    sqlcipher3 reports SQLite 3.53.3, the SQLCipher v4.17.0 build per
    pyproject.toml: INSERT raises "attempt to write a readonly database"). It now routes through :func:`_make_encrypted_conn` with
    ``read_only=True`` — the ONE place the key is derived and applied — so
    the name keeps its callers while the handle can no longer write. The
    name is kept (not renamed to ``readonly``) so the  SSOT pins and the
    three callers stay byte-stable; the behaviour is now read-only, not
    "read-ish"."""
    if _DEDICATED_CONN_MASTER_KEY is None:
        raise RuntimeError(
            "open_dedicated_encrypted_conn_readish: no master key stamped — "
            "call set_dedicated_conn_encryption(encrypted=True, ...) first."
        )
    return _make_encrypted_conn(
        db_path,
        _DEDICATED_CONN_MASTER_KEY,
        purpose=_DEDICATED_CONN_PURPOSE,
        read_only=True,
    )


def open_dedicated_conn(
    db_path: str,
    *,
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    """Open a -style dedicated connection that SELF-SELECTS encryption.

    The single encrypted-aware replacement for the raw
    ``sqlite3.connect(db_path)`` calls that the dedicated-conn openers
    (audit-chain log handler, acme_jobs writer,  write-lock conn) +
    the standalone-CLI FlowStore / embedding-bits paths used before N-17.

    When the process boot (or the CLI entrypoint) stamped
    :func:`set_dedicated_conn_encryption` with ``encrypted=True``, this
    opens a ``sqlcipher3`` connection via :func:`_make_encrypted_conn`
    (PRAGMA key first, then WAL/busy/FK) — byte-identical PRAGMA sequence
    to the main boot conn. Otherwise it opens the plaintext stdlib
    ``sqlite3`` path with the same PRAGMAs the pre-N-17 openers set (WAL,
    busy_timeout=30000, foreign_keys=ON, cached_statements=0).

    This opener is for READ-WRITE dedicated conns. The two read-ONLY-intent
    callers (CLI ``audit verify`` / ``audit reconcile --read-only`` and the
    version banner) keep their own ``file:...?mode=ro`` open on the
    plaintext path (a read-only handle rejects ``PRAGMA journal_mode``, so
    it must not route here) and use :func:`open_dedicated_encrypted_conn_
    readish` on the encrypted path.

    The returned conn's ``row_factory`` is NOT set here — callers apply
    :func:`email_triage.db._helpers.apply_compatible_row_factory` (N-16),
    which already selects the right Row class for whichever dbapi this
    returns. Keeping row_factory at the call site preserves each opener's
    existing post-open sequence (e.g. ``set_cached_db_path``).

    Does NOT try/except the encrypted open — a swallowed failure would
    silently disable the §164.312(b) audit chain (the wrong fail-mode).
    A genuinely broken encrypted open MUST surface as a boot crash, the
    same fail-closed posture as the main conn.

    Args:
        db_path: filesystem path to the single DB file.
        check_same_thread: passed to the plaintext ``sqlite3.connect`` (the
            dedicated conns are held across threadpool workers, so the
            openers pass ``False``); the encrypted path always uses
            ``check_same_thread=False`` (see :func:`_make_encrypted_conn`).
    """
    if _DEDICATED_CONN_ENCRYPTED:
        return _make_encrypted_conn(
            db_path,
            _DEDICATED_CONN_MASTER_KEY,  # type: ignore[arg-type]
            purpose=_DEDICATED_CONN_PURPOSE,
        )
    conn = sqlite3.connect(
        db_path,
        timeout=_SQLITE_BUSY_WAIT_SECS,
        check_same_thread=check_same_thread,
        cached_statements=0,
    )
    _apply_standard_pragmas(conn)
    return conn


def open_dedicated_conn_readish(db_path: str) -> sqlite3.Connection:
    """the backlog  (Census v3 #8) — SSOT RO opener that respects the
    boot-stamped encryption context. Sibling of
    :func:`open_dedicated_conn` (RW) and
    :func:`open_dedicated_encrypted_conn_readish` (encrypted arm).

    * Under encryption: delegates to
      :func:`open_dedicated_encrypted_conn_readish` — a SQLCipher
      ``mode=ro`` handle (punch 556 / N-559; before that fix it was a RW
      handle and only the caller's SELECT-only habit kept it read-only).
    * Under plaintext: opens the read-only ``file:...?mode=ro`` URI
      with the FULL init_db argument set: ``uri=True``,
      ``check_same_thread=False``, ``timeout=30.0``,
      ``cached_statements=0``. Does NOT run
      :func:`_apply_standard_pragmas` — a read-only handle rejects
      ``PRAGMA journal_mode = WAL`` (that's the whole reason for
      the ``mode=ro`` bypass at the boot-context RO seams; see
      ``version.py:read_db_schema_version`` docstring for the
      historical N-17 rationale).

    Motivating drift: pre-fix, 7 sites hand-rolled the encrypted/
    plaintext branch and each drifted independently on the argument
    set — ``timeout=30.0`` missing at version.py + cli.py:2425/2573/
    2578; ``check_same_thread=False`` missing at backup.py:278/324/
    406; ``cached_statements=0`` missing at all 7. Converging on
    ONE opener + one pin closes the class (§164.312(a)(2)(iv)
    encryption at rest + reliability under WAL busy contention).
    """
    if _DEDICATED_CONN_ENCRYPTED:
        return open_dedicated_encrypted_conn_readish(db_path)
    return sqlite3.connect(
        f"file:{quote(db_path, safe='/')}?mode=ro",
        uri=True,
        check_same_thread=False,
        timeout=_SQLITE_BUSY_WAIT_SECS,
        cached_statements=0,
    )


def _apply_standard_pragmas(conn: sqlite3.Connection) -> None:
    """N-214 R23 (2026-07-02): the ONE SSOT for the standard-opener PRAGMA
    sequence (journal_mode=WAL, busy_timeout=30000, foreign_keys=ON). Two
    pre-N-214 spellings existed (`journal_mode=WAL` vs `journal_mode = WAL`)
    across 2 openers — a tuning change would have needed 2 replays or one
    opener would silently mistune. Route both openers through here.

    ORDER-CRITICAL note for the encrypted path: `PRAGMA key = ...` MUST fire
    BEFORE this helper; the SQLCipher opener does that inline, then calls
    into here for the standard set.
    """
    conn.execute("PRAGMA journal_mode = WAL")
    # -b: PRAGMA busy_timeout derived from _SQLITE_BUSY_WAIT_SECS
    # so a config tune reaches BOTH the DBAPI busy loop
    # (sqlite3.connect timeout=) AND the SQL-layer busy loop coherently.
    conn.execute(f"PRAGMA busy_timeout = {int(_SQLITE_BUSY_WAIT_SECS * 1000)}")
    conn.execute("PRAGMA foreign_keys = ON")
    # N-432 walresetbug P0 (2026-07-19) — disable SQLite's built-in
    # WAL auto-checkpoint. The auto-checkpoint fires opportunistically
    # from ANY reader crossing the 1000-page threshold and runs inside
    # SQLite's C-level checkpoint routine, OUTSIDE the process-wide
    # writer-lock (``_write_lock`` / ``@db_write``). The walresetbug
    # (fixed upstream in SQLite 3.51.3, 2026-03-13) races the checkpoint
    # against a concurrent write and can corrupt the WAL header — on the
    # HMAC-chained ``log_entries`` audit table that is §164.312(b)/(c)(1)
    # integrity loss. Baked-in versions in v0.2.0 are 3.45.3 (SQLCipher
    # `sqlcipher3-binary==0.5.4.post2`) + 3.46.1 (stdlib libsqlite3 via
    # ``python:3.12-slim``), BOTH < 3.51.3. Setting autocheckpoint=0
    # ensures every checkpoint fires only from the SERIALIZED periodic
    # task ``checkpoint_wal_truncate`` (web/db.py, @db_write) so no two
    # writer/checkpoint operations touch the WAL at the same time.
    conn.execute("PRAGMA wal_autocheckpoint = 0")


# The admin-guide section the refusal below points to (pinned to exist).
LEGACY_MASTER_KEY_RUNBOOK = "docs/legacy-master-key-refusal-runbook.md"


class EncryptedDbKeyRefused(RuntimeError):
    """The SQLCipher storage key derived from the master key does not open this
    database (punch 418). Typed so a caller never sees a bare ``file is not a
    database`` from sqlcipher3.

    The usual cause since punch 418: the database was created while ``ET_MASTER_KEY``
    carried a trailing newline (the env backend returned it verbatim), so it was
    keyed with that newline; the master key is now read with trailing CR/LF
    stripped (``secrets.read_master_key``), which derives a different key. There is
    NO silent fallback to the raw value: every derivative of the master key (audit
    HMAC chain, DbSecrets Fernet key) would then disagree with the storage key.
    The other cause is simply the wrong key. The message carries no key material.

    The remedy it names is the one that works today (cycle P hipaa P4 S1: "restore
    the original key" could not, because the funnel strips any restored newline):
    stay on the last release before v0.2.0, which reads the key byte-for-byte,
    until the legacy re-key command ships (punch 831). The refusal fires on the
    first page read, before any migration, so that release still opens the file.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        super().__init__(
            f"the storage key derived from the master key does not open "
            f"{str(db_path).replace(chr(92), '/').rsplit('/', 1)[-1]!r}: the master key is wrong, or the "
            "database was keyed with the un-normalised master key (the secret carried a "
            "trailing newline, which is now stripped; punch 418). Not retried with the raw "
            "value. If the key is right, keep running the last release before v0.2.0, which "
            "reads the key byte-for-byte, until the legacy re-key command ships (tracked as "
            f"punch 831); see {LEGACY_MASTER_KEY_RUNBOOK}."
        )


def _is_wrong_storage_key(exc: BaseException) -> bool:
    """True when ``exc`` is the driver's wrong-key signal: a DatabaseError from
    either SQLite driver whose text is ``file is not a database``."""
    from email_triage._dbapi_errors import DB_DATABASE_ERRORS

    return isinstance(exc, DB_DATABASE_ERRORS) and "not a database" in str(exc).lower()


def _make_encrypted_conn(
    db_path: str,
    master_key: str | bytes,
    *,
    purpose: str = "triage",
    read_only: bool = False,
) -> sqlite3.Connection:
    """Open a single SQLCipher-encrypted connection.

    Order matters: ``PRAGMA key`` MUST be the FIRST SQL the connection
    sees (per SQLCipher documentation at zetetic.net/sqlcipher/sqlcipher-api/),
    BEFORE any read or query. Subsequent PRAGMAs (journal_mode,
    busy_timeout, foreign_keys, cached_statements) configure the
    connection for v0.1.2's workload pattern; ``cached_statements=0``
    is the Phase 0  mitigation for CPython issue #118172 (multi-
    thread cursor-cache silent corruption on Python 3.12+).

    ``read_only=True`` (punch 556 / N-559) opens ``file:<path>?mode=ro`` with
    ``uri=True`` — SQLite's read-only handle, which refuses every write with
    "attempt to write a readonly database" and never creates the file (a
    typo'd path raises instead of leaving an empty encrypted DB). It skips
    :func:`_apply_standard_pragmas`: ``journal_mode`` would be a write, and
    the checkpoint/foreign-key settings are meaningless on a reader. It sets
    ``PRAGMA query_only`` as a second layer (that pragma alone is NOT
    read-only — sqlite.org: a checkpoint or COMMIT still runs — so
    ``mode=ro`` is the control) and then reads ``sqlite_master``: under
    SQLCipher a wrong key only surfaces at the first page read, so this read
    makes a bad key fail HERE, at open, instead of at the caller's first
    query. ``immutable=1`` is deliberately NOT used: it skips locking and
    change detection, and sqlite.org warns of incorrect results or
    SQLITE_CORRUPT when the file changes — the live DB always does.

    A WAL database opened ``mode=ro`` still needs its ``-shm``/``-wal``
    files to exist or the directory to be writable so SQLite can create
    them (sqlite.org/wal.html §5); the reader takes WAL read locks through
    ``-shm`` and so sees rows a concurrent writer has committed.

    Sidecars left behind (punch 556, db-sme F-R3-5): on a quiescent WAL
    database (no other connection open, so no ``-shm``/``-wal``) a reader
    creates both and leaves them on close, an empty ``-wal`` and a ``-shm``.
    A read-write connection, as the last one, checkpoints and deletes them;
    a read-only one cannot. They are left on purpose. Deleting a ``-wal``
    or ``-shm`` is only safe when no other connection can have the file
    open, which a CLI or banner caller cannot know, and the next connection
    simply reuses them (pinned by the N-559 runtime test R8). Run any reader
    as the database's own user, so the sidecars it creates are owned by
    that user.

    The path is percent-encoded (``quote(..., safe='/')``) before
    ``?mode=ro`` is appended: in a URI a raw ``?`` or ``#`` ends the path
    and a raw ``%`` starts an escape, so an unquoted path with one of them
    opens a different file (punch 556, DA O8-F2).
    """
    import sqlcipher3  # lazy: heavy binary; not needed at import time

    key = derive_storage_key(purpose, master_key)
    pragma_key_arg = format_raw_hex_key(key)

    if read_only:
        conn = sqlcipher3.dbapi2.connect(
            f"file:{quote(db_path, safe='/')}?mode=ro",
            uri=True,
            check_same_thread=False,
            cached_statements=0,
            timeout=_SQLITE_BUSY_WAIT_SECS,
        )
    else:
        conn = sqlcipher3.dbapi2.connect(
            db_path,
            check_same_thread=False,
            cached_statements=0,
            timeout=_SQLITE_BUSY_WAIT_SECS,
        )
    # ORDER-CRITICAL: PRAGMA key must be the first SQL the conn sees.
    conn.execute(f"PRAGMA key = \"{pragma_key_arg}\"")
    try:
        if not read_only:
            _apply_standard_pragmas(conn)
            return conn
        conn.execute("PRAGMA query_only = ON")
        conn.execute(
            f"PRAGMA busy_timeout = {int(_SQLITE_BUSY_WAIT_SECS * 1000)}"
        )
        # Key check: the first page read. A wrong key raises here.
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except BaseException as exc:
        # Close the half-open handle; a wrong key becomes the typed refusal
        # (punch 418), every other error is re-raised unchanged.
        conn.close()
        if _is_wrong_storage_key(exc):
            raise EncryptedDbKeyRefused(db_path) from exc
        raise
    return conn


def create_engine_for_app(
    db_path: str | Path,
    *,
    encrypted: bool = True,
    master_key: str | bytes | None = None,
) -> Any:
    """Build a SQLAlchemy Core ``Engine`` for the email-triage single file.

    ``encrypted=True`` (the production default) wires the SQLCipher
    ``creator=`` callable; ``master_key`` is required in that mode.
    ``encrypted=False`` opens a plain ``sqlite3`` connection — for
    tests, fixtures, and migrations against an unencrypted scratch
    DB. Per :mod:`internal documentation` §4 Phase 4,
    HIPAA-mode boot raises ``RuntimeError`` if ``encrypted=False`` is
    reached.

    Returns a SQLAlchemy Core ``Engine``. Uses ``NullPool`` — the
    ``WriterBackend`` Protocol owns its own long-lived connection
    via the writer thread; SA's pool would compete with it.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    db_path_str = str(db_path)

    if encrypted:
        if master_key is None:
            raise RuntimeError(
                "create_engine_for_app(encrypted=True) requires master_key. "
                "HIPAA-mode boot must NEVER fall back to a plaintext engine "
                "(EQM-08 fail-closed contract)."
            )

        def _creator() -> sqlite3.Connection:
            return _make_encrypted_conn(db_path_str, master_key)

        # Embed the real path in the URL even though ``creator`` owns the
        # actual connection: SA leaves ``engine.url.database`` populated so
        # Alembic env.py + the baseline migration can discover the path via
        # ``bind.engine.url.database``. The creator still overrides HOW the
        # connection is opened (sqlcipher3 + PRAGMA key).
        engine = create_engine(
            f"sqlite:///{db_path_str}",
            creator=_creator,
            poolclass=NullPool,
            future=True,
        )
        logger.info(
            "v0.1.2 SA Core engine created (encrypted via sqlcipher3)",
            extra={"_extra": {"db_path": db_path_str}},
        )
        return engine

    # Plain stdlib sqlite3 path — TESTS / FIXTURES / DEV ONLY.
    def _plain_creator() -> sqlite3.Connection:
        conn = sqlite3.connect(
            db_path_str,
            check_same_thread=False,
            cached_statements=0,
            timeout=_SQLITE_BUSY_WAIT_SECS,
        )
        _apply_standard_pragmas(conn)  # N-214 R23: SSOT
        return conn

    engine = create_engine(
        f"sqlite:///{db_path_str}",
        creator=_plain_creator,
        poolclass=NullPool,
        future=True,
    )
    logger.info(
        "v0.1.2 SA Core engine created (plain sqlite3 — non-HIPAA path)",
        extra={"_extra": {"db_path": db_path_str}},
    )
    return engine


# ---------------------------------------------------------------------------
# Phase 4 — encrypted-boot resolution + fail-closed contract
# ---------------------------------------------------------------------------
#
# These helpers are the single decision point for "does this boot open an
# encrypted DB or a plaintext one, and is that choice safe?" They are
# deliberately separated from the FastAPI lifespan so the contract is
# unit-testable WITHOUT standing up the whole app (and without the
# ``sqlcipher3`` binary, which is the ``encryption`` extra — Linux/
# container only, NOT installed on the Windows dev box).
#
# §-anchors (inline §164.316(b)(1) per EQM-08):
#     §164.312(a)(2)(iv) Encryption — the fail-closed gate guarantees an
#         encryption-required deploy can NEVER come up serving PHI from a
#         plaintext file because a dependency or key was missing.
#     §164.306(d)(3)(i) Required-spec implementation — once the operator
#         declares HIPAA mode + encryption, the addressable→required
#         escalation is enforced in code, not left to deploy discipline.


def sqlcipher3_available() -> bool:
    """True iff the ``sqlcipher3`` binding can be imported in this process.

    Probes WITHOUT opening any connection. ``sqlcipher3-binary`` is the
    ``encryption`` extra (Linux/container only); on a dev box without it
    this returns ``False``, which is exactly what the fail-closed gate
    needs to distinguish "encryption requested but impossible" from
    "encryption working."
    """
    try:
        import sqlcipher3  # noqa: F401
    except Exception:  # ImportError, or a partial/native-load failure
        return False
    return True


def resolve_db_encryption(config: Any) -> bool:
    """Resolve whether THIS boot wants the DB opened encrypted.

    Resolution: the ``config.persistence.encryption_enabled`` field, and
    nothing else — no environment override (punch 547).

    This is the *intent* layer only — it does NOT enforce the fail-closed
    contract (that's :func:`enforce_db_encryption_boot_contract`, which
    also factors in HIPAA mode + ``sqlcipher3`` availability + master-key
    presence). A non-HIPAA install can legitimately resolve ``True`` here
    and the contract will still require the binary + key to be present.
    """
    persistence = getattr(config, "persistence", None)
    return bool(getattr(persistence, "encryption_enabled", False))


# N-432 walresetbug Path-3 (2026-07-20) — cipher_version boot assertion (hipaa-sme MF-4).
# §164.312(a)(2)(iv) fail-closed: post-Path-3 the container source-builds sqlcipher3
# against SQLCipher v4.20.0 (SQLite 3.54.1). A base-image bump or a Containerfile edit
# that silently regresses the vendored SQLCipher would be caught by
# ``assert_cipher_version_floor`` below — a pre-4.14 binding FAILS the boot instead
# of serving under a walresetbug-buggy binary. Fail-CLOSED per PD#14.
SQLCIPHER_MIN_MAJOR_MINOR: tuple[int, int] = (4, 14)  # walresetbug fix landed at 4.14.0 (SQLite 3.51.3, 2026-03-17)
SQLCIPHER_EXPECTED_MAJOR_MINOR: tuple[int, int] = (4, 20)  # source-built.pins declares v4.20.0 (punch 731)

#: Written by the Containerfile as the OUTPUT of ``source_built.py verify`` on
#: the runtime image (punch 547). It exists iff this image proved its Path-3
#: source-built declaration. It sits outside every mounted volume (/app/data,
#: /app/config) and is absent from any repo checkout, so neither a dev/CI run nor
#: an environment variable can claim or disclaim Path-3 status.
PATH3_VERIFIED_MARKER: Path = Path("/app/.path3-verified")


def assert_cipher_version_floor() -> dict[str, Any]:
    """Boot-time fail-CLOSED guard on SQLCipher cipher_version (§164.312(a)(2)(iv)).

    Opens an in-memory SQLCipher connection, reads ``PRAGMA cipher_version``,
    and asserts the running binary is on the walresetbug-clean line
    (SQLCipher >= 4.14.0, SQLite >= 3.51.3). RAISES ``RuntimeError`` if the
    assertion fails — the app refuses to serve under a walresetbug-buggy
    encrypted binary.

    The Containerfile build-time smoke catches this earlier (unified builder-
    stage assert + runtime-stage smoke); ``assert_cipher_version_floor`` is
    the RUNTIME backstop for any base-image swap, container-image drift, or
    manually-swapped sqlcipher3 install that would bypass the build-time gate.

    Called from ``web/app.py`` lifespan alongside
    :func:`assert_sqlite_walresetbug_floor` (the /health-facing SENSOR — that
    one is non-fatal by design). Skipped cleanly when ``sqlcipher3`` isn't
    importable (the plaintext boot path;
    :func:`enforce_db_encryption_boot_contract` owns that decision).

    Returns a dict for /health surfacing when the assertion passes.

    Panel origin: hipaa-sme MF-4 in workflow ``wqpqvcbj6`` (2026-07-20).
    """
    # N-432 Path-3 + punch 547: enforce the floor only in an image that PROVED
    # it is the Path-3 build — the baked marker below. Local dev + CI run a
    # pip-installed sqlcipher3-binary with an older vendored SQLCipher and are
    # not the Path-3 baseline, so this fail-CLOSED guard must not halt them;
    # they carry no marker. The gate used to be the EMAIL_TRIAGE_PATH3_BASELINE
    # env var, and ``-e EMAIL_TRIAGE_PATH3_BASELINE=0`` on the container skipped
    # the guard: an env var disarming a fail-closed control (operator directive
    # 2026-09-29). A file baked by the build cannot be typed.
    if not PATH3_VERIFIED_MARKER.is_file():
        return {"applicable": False, "reason": f"not a Path-3-verified image ({PATH3_VERIFIED_MARKER} absent)"}

    try:
        import sqlcipher3.dbapi2 as sqlcipher_dbapi
    except ImportError:
        # Plaintext boot path — enforce_db_encryption_boot_contract owns the
        # decision on whether missing sqlcipher3 is a fail-closed condition
        # (HIPAA + encryption requested) or not. This function just no-ops
        # cleanly so the plaintext arm isn't blocked by an encryption-only
        # assertion.
        return {"applicable": False, "reason": "sqlcipher3 not importable"}

    conn = sqlcipher_dbapi.connect(":memory:")
    try:
        row = conn.execute("PRAGMA cipher_version").fetchone()
    finally:
        conn.close()

    if not row or not row[0]:
        raise RuntimeError(
            "SQLCipher cipher_version probe returned empty — the sqlcipher3 "
            "binding loaded but its crypto path is broken. Per "
            "§164.312(a)(2)(iv) fail-closed contract, the app will NOT serve "
            "under a broken encryption binding."
        )

    version_str = str(row[0]).split()[0]  # strip trailing ' community' etc.
    # Isdigit-guard rather than try/int-except so this doesn't inflate the
    # N-219 R23 ratchet (`try: int(X) except (ValueError, TypeError)` cap).
    # The two version-part strings must both be pure digit runs; anything
    # else fails-closed (SQLCipher cipher_version has always been dotted-int).
    parts_str = version_str.split(".")
    if len(parts_str) < 2 or not (parts_str[0].isdigit() and parts_str[1].isdigit()):
        raise RuntimeError(
            f"SQLCipher cipher_version={row[0]!r} could not be parsed as "
            f"major.minor. Per §164.312(a)(2)(iv) fail-closed contract, the "
            f"app will NOT serve under an unrecognized encryption binding."
        )
    major_minor = (int(parts_str[0]), int(parts_str[1]))

    if major_minor < SQLCIPHER_MIN_MAJOR_MINOR:
        raise RuntimeError(
            f"SQLCipher cipher_version={row[0]!r} < walresetbug-fix floor "
            f"{'.'.join(str(x) for x in SQLCIPHER_MIN_MAJOR_MINOR)}.0. The "
            f"Path-3 Containerfile source-builds sqlcipher3 against SQLCipher "
            f"v4.20.0 (SQLite 3.54.1); a pre-4.14 binding here means the "
            f"image was built WITHOUT the Path-3 recipe. Per "
            f"§164.312(a)(2)(iv) fail-closed contract, the app will NOT "
            f"serve under a walresetbug-buggy encryption binding."
        )

    return {
        "applicable": True,
        "cipher_version": row[0],
        "major_minor": ".".join(str(x) for x in major_minor),
        "min_floor": ".".join(str(x) for x in SQLCIPHER_MIN_MAJOR_MINOR) + ".0",
        "expected_line": ".".join(str(x) for x in SQLCIPHER_EXPECTED_MAJOR_MINOR) + ".x",
        "at_expected_line": major_minor == SQLCIPHER_EXPECTED_MAJOR_MINOR,
    }


#: The first 16 bytes of every plaintext SQLite 3 database file.
_SQLITE_PLAINTEXT_HEADER = b"SQLite format 3\x00"


def _db_header(db_path: Any) -> bytes | None:
    """The first 16 bytes of the database file: THE header reader for both
    wrong-mode guards (punches 547 and 614, PD-5). ``b""`` for no path, an
    in-memory database, or a file that does not exist. ``None`` for a file
    that exists but cannot be read (permissions, an SELinux label, a different
    container user): its content is unknown, which is not the same as empty
    (panel B3 db-sme fold check FC-1)."""
    raw = str(db_path or "")
    if raw in ("", ":memory:"):
        return b""
    try:
        with open(raw, "rb") as fh:
            return fh.read(16)
    except FileNotFoundError:
        return b""
    except OSError:
        return None


def db_file_looks_encrypted(db_path: Any) -> bool:
    """True when ``db_path`` is an existing file of at least 16 bytes whose
    header is NOT the plaintext SQLite magic — a SQLCipher file (its page 1 is
    ciphertext). Missing / empty / unreadable -> False (nothing to protect, or
    the open itself will fail)."""
    head = _db_header(db_path)
    return head is not None and len(head) == 16 and head != _SQLITE_PLAINTEXT_HEADER


def _db_content_kind(db_path: Any) -> str:
    """What is on disk at ``db_path``, decided before any connection exists.

    ``"plaintext"`` / ``"encrypted"``: the main file has a full 16-byte header,
    and it is (or is not) the plaintext SQLite magic. ``"new"``: no data to
    protect (no path, an in-memory database, or a main file shorter than one
    header with no ``-wal`` or an empty one). ``"orphan_wal"``: a main file
    shorter than one header beside a NON-EMPTY ``-wal``. ``"undecidable"``: the
    main file is short and the ``-wal`` cannot be inspected.

    Panel B3 db-sme F1, measured with stdlib sqlite 3.50.4: SQLite writes page 1
    to the MAIN file during ``PRAGMA journal_mode=WAL``, before any WAL frame
    exists, so its own crash path never leaves a short main file beside a WAL
    that holds data; and opening a zero-page database DELETES its ``-wal``
    (``pagerOpenWalIfPresent``) before any page is decoded, in either cipher
    mode. So an orphan WAL is external damage (a truncated main file, a partial
    restore), and ANY open loses it, whatever its page 1 holds. The earlier
    claim that a crashed fresh encrypted database "still opens" from its WAL was
    REFUTED for SQLite's pager (PARTIAL for sqlcipher3, which shares the pager
    code but was not measured), so the WAL's page 1 is no longer parsed."""
    head = _db_header(db_path)
    if head is None:
        return "undecidable"
    if len(head) == 16:
        return "plaintext" if head == _SQLITE_PLAINTEXT_HEADER else "encrypted"
    raw = str(db_path or "")
    if raw in ("", ":memory:"):
        return "new"
    try:
        return "orphan_wal" if Path(raw + "-wal").stat().st_size > 0 else "new"
    except FileNotFoundError:
        return "new"
    except OSError:
        return "undecidable"


def db_file_looks_plaintext(db_path: Any) -> bool:
    """True when ``db_path``'s header is the plaintext SQLite magic (punch 614).
    A short main file is never "plaintext": it is new, or an orphan WAL that
    :func:`refuse_orphan_wal` refuses in both modes."""
    return _db_content_kind(db_path) == "plaintext"


def refuse_orphan_wal(config: Any) -> None:
    """Fail CLOSED, in BOTH encryption modes, when the database's main file is
    shorter than one header but its ``-wal`` holds data (panel B3 db-sme F1).

    Any open, encrypted or plaintext, deletes that ``-wal`` (SQLite discards the
    WAL of a zero-page database) and then builds an empty database that boots
    "healthy": silent data loss (integrity, §164.312(c)(1)). SQLite's own crash
    path never produces this state (see :func:`_db_content_kind`), so no
    healthy install reaches the refusal. Called by
    :func:`enforce_db_encryption_boot_contract` BEFORE its mode branch, and by
    the ``email-triage preflight`` deploy check, on the one header reader.
    """
    db_path = getattr(getattr(config, "persistence", None), "db_path", None)
    kind = _db_content_kind(db_path)
    if kind == "orphan_wal":
        raise RuntimeError(
            "The configured database file is shorter than one SQLite header, but "
            "its -wal file holds data. Opening it, encrypted or not, would delete "
            "that -wal and start an empty database (SQLite discards the WAL of a "
            "database with no pages), so the app will not open it (orphan WAL, "
            "panel B3 db-sme F1). Restore the database from a backup. Remove the "
            "leftover -wal only if the database is meant to be new."
        )
    if kind == "undecidable":
        raise RuntimeError(
            "The app cannot read the configured database file, or its -wal file, "
            "so it cannot tell whether an open would discard data, and it will not "
            "open it (panel B3 db-sme F1 / FC-1). Check the file and directory "
            "permissions, the SELinux label, and the user the service runs as. Do "
            "NOT restore or delete anything: the database may be healthy."
        )


def refuse_plaintext_open_of_encrypted_file(config: Any) -> None:
    """Fail CLOSED when the config resolves encryption OFF but the database
    file on disk is encrypted (punch 547).

    With the env override gone, an install whose encryption was switched on
    ONLY by ``EMAIL_TRIAGE_DB_ENCRYPTION=true`` while its YAML still says
    ``false`` would otherwise try to open ciphertext as plaintext. Refuse with
    the fix instead. Called by :func:`enforce_db_encryption_boot_contract` and
    by the ``email-triage preflight`` deploy check.
    """
    if resolve_db_encryption(config):
        return
    db_path = getattr(getattr(config, "persistence", None), "db_path", None)
    if db_file_looks_encrypted(db_path):
        raise RuntimeError(
            "The config resolves DB encryption OFF (persistence.encryption_enabled "
            "is false) but the configured database file is encrypted. Set "
            "persistence.encryption_enabled: true in the config file. The app "
            "will not open an encrypted database as plaintext (punch 547; the "
            "EMAIL_TRIAGE_DB_ENCRYPTION env override no longer exists)."
        )


def refuse_encrypted_open_of_plaintext_file(config: Any) -> None:
    """Fail CLOSED when the config resolves encryption ON but the database file
    on disk is plaintext (punch 614; panel B2, db-sme B4c).

    Since ``903b96183`` (2026-08-18) a config that omits
    ``persistence.encryption_enabled`` resolves to encrypted. An EXISTING
    plaintext install with such a config would otherwise be opened with
    ``PRAGMA key`` and then ``PRAGMA journal_mode = WAL``, leaving the refusal
    to SQLCipher's behaviour on a wrong-mode open, which can touch the WAL
    index or replay a hot journal before page 1 fails to decrypt. Refuse on the
    header instead, before any connection exists: the mirror of
    :func:`refuse_plaintext_open_of_encrypted_file` (punch 547), on the same
    header reader. A refusal, never a migration
    (``decision_encrypted_default_refuses_never_auto_migrates``).
    """
    if not resolve_db_encryption(config):
        return
    db_path = getattr(getattr(config, "persistence", None), "db_path", None)
    # A short main file (orphan WAL / undecidable) is refused in both modes by
    # refuse_orphan_wal, which both callers run first (panel B3 db-sme F1).
    if _db_content_kind(db_path) == "plaintext":
        raise RuntimeError(
            "The config resolves DB encryption ON (persistence.encryption_enabled "
            "is true, or it is omitted and encryption is the default) but the "
            "configured database file is a plaintext SQLite database. The app will "
            "not open a plaintext database in encrypted mode (punch 614). Either "
            "set persistence.encryption_enabled: false in the config file to keep "
            "running this database in plaintext, or stop the service and convert it "
            "with 'email-triage db encrypt'."
        )


def enforce_db_encryption_boot_contract(
    config: Any,
    *,
    master_key_available: bool,
) -> bool:
    """Decide the effective boot DB mode + enforce the fail-closed contract.

    Returns ``True`` when the app MUST open the encrypted (SQLCipher)
    connection, ``False`` when it opens the plaintext ``sqlite3`` path.

    The fail-closed rules (per ``internal documentation``
    §4.3) — evaluated only when encryption was requested
    (:func:`resolve_db_encryption` is ``True``) OR HIPAA mode is on:

      * **HIPAA mode + encryption requested** is the encryption-REQUIRED
        posture. If ``sqlcipher3`` is not importable → ``RuntimeError``.
        If the master key is unavailable → ``RuntimeError``. NEVER a
        silent plaintext fallback (§164.312(a)(2)(iv)).
      * **HIPAA mode WITHOUT encryption requested** is NOT auto-escalated
        here — operator may run HIPAA mode with disk-level encryption
        (LUKS) instead of SQLCipher, a documented EQM-03-style equivalent
        measure. We log a loud advisory but do not force-enable, because
        forcing it would break every existing plaintext HIPAA install on
        upgrade. Escalating HIPAA→required-SQLCipher is a separate,
        operator-ratified migration (Phase 6 cutover), not an upgrade
        surprise.
      * **Non-HIPAA + encryption requested**: still fail-closed on a
        missing binary or key — the operator explicitly asked for
        encryption; coming up plaintext would silently violate that
        request. (Same RuntimeError, framed as a misconfiguration.)
      * **Non-HIPAA + encryption NOT requested**: plaintext path,
        unchanged. The overwhelmingly common existing-install case.

    Args:
        config: a ``TriageConfig``-shaped object exposing
            ``.persistence.encryption_enabled``.
        master_key_available: whether the boot sequence successfully read
            a master key from the bootstrap secrets backend. Passed in
            (not read here) because the caller owns the secrets-bootstrap
            ordering; this keeps the contract a pure function of its
            inputs and trivially testable.

    Raises:
        RuntimeError: when encryption is required (or explicitly
            requested) but ``sqlcipher3`` is unavailable or no master key
            could be read.
    """
    from email_triage.triage_logging import is_hipaa_mode

    requested = resolve_db_encryption(config)
    hipaa = is_hipaa_mode()

    # Both modes, before the branch: an orphan WAL is lost by ANY open (panel B3
    # db-sme F1), so neither the plaintext nor the encrypted arm may proceed.
    refuse_orphan_wal(config)

    if not requested:
        refuse_plaintext_open_of_encrypted_file(config)
        if hipaa:
            # Loud advisory, NOT a hard fail — see the HIPAA-without-
            # encryption branch in the docstring above. This early emit
            # gives the operator an IMMEDIATE boot signal (console/file).
            # It is RE-EMITTED through the §164.312(b) audit chain by the
            # lifespan AFTER add_sqlite_handler attaches (the chain handler
            # is not yet wired at boot-contract time) — see
            # :func:`hipaa_plaintext_advisory_applies` + its lifespan
            # caller. hipaa-sme condition 2: "operator was warned they're
            # running plaintext in HIPAA mode" must be a tamper-evident
            # audit event, not stderr-only.
            logger.warning(HIPAA_PLAINTEXT_ADVISORY)
        else:
            # Encrypted-at-rest is the default posture; a plaintext boot in ANY
            # mode is flagged loudly (operator 2026-06-11 "warn on NOT
            # encrypted"). Not fatal — existing plaintext installs keep working.
            logger.warning(PLAINTEXT_ADVISORY)
        return False

    # Encryption requested from here down — fail-closed on any gap.
    refuse_encrypted_open_of_plaintext_file(config)
    if not sqlcipher3_available():
        raise RuntimeError(
            "DB encryption requested "
            f"({'HIPAA mode + ' if hipaa else ''}"
            "persistence.encryption_enabled) but the 'sqlcipher3' binding could "
            "not be imported. Install the 'encryption' extra "
            "(sqlcipher3-binary) — Linux/container only. Per EQM-08 "
            "fail-closed contract, the app will NOT fall back to a "
            "plaintext database (§164.312(a)(2)(iv))."
        )
    if not master_key_available:
        raise RuntimeError(
            "DB encryption requested but no master key is available from "
            "the secrets backend. The SQLCipher storage key is HKDF-"
            "derived from the master key; without it the encrypted file "
            "cannot be opened. Provision the master key "
            "('email-triage secrets init-master-key') before enabling "
            "encryption. Per EQM-08 fail-closed contract, the app will "
            "NOT fall back to a plaintext database "
            "(§164.312(a)(2)(iv))."
        )
    return True


def hipaa_plaintext_advisory_applies(config: Any) -> bool:
    """True iff this boot is HIPAA-mode AND opening the DB in plaintext.

    The lifespan calls this AFTER ``add_sqlite_handler`` attaches the
    §164.312(b) audit-chain log handler, then re-emits
    :data:`HIPAA_PLAINTEXT_ADVISORY` through the app logger so the
    "operator ran plaintext under HIPAA mode" advisory is a tamper-
    evident ``log_entries`` row, not stderr-only (hipaa-sme condition 2).
    Mirrors the no-encryption branch of
    :func:`enforce_db_encryption_boot_contract` exactly so the two never
    drift.
    """
    from email_triage.triage_logging import is_hipaa_mode

    return is_hipaa_mode() and not resolve_db_encryption(config)
