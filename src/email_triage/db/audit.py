"""Audit cluster — log_entries hash chain, HIPAA boundary/access events,
auth events, user-status events, API-key lifecycle events, access-log
middleware sink, discover-run records.

Extracted from ``email_triage.web.db`` per the backlog #277a (2026-05-23) to
unblock the H-02a HMAC migration (Task #1) without dragging it through the
8819-LOC god-module. No semantic changes; pure verbatim relocation.

``web/db.py`` retains a re-export shim so all existing
``from email_triage.web.db import <name>`` callers (554 refs across 76
files at extraction time) keep working unchanged.

Cycle hazard preserved: ``SQLiteLogHandler.emit()`` in ``triage_logging.py``
does a deliberate LATE import of ``compute_log_row_hash`` +
``get_last_log_row_hash`` (the handler can be set up before web/db init
on some startup paths). This module MUST NOT import ``triage_logging``
at module load; the re-export shim in ``web/db.py`` keeps the existing
``from email_triage.web.db import compute_log_row_hash`` import-string
working, preserving the late-import contract.

Cross-module deps (non-cycle):
- ``@db_write`` from ``email_triage.web.db_writelock`` (NOT from web/db) —
  imported at module top because db_writelock has no upward deps.
- ``get_setting`` + ``invalidate_setting_cache`` from ``email_triage.web.db``
  (used by ``_capture_chain_anchor`` + ``verify_log_chain`` for the
  post-prune chain-anchor) — late-bound INSIDE the function bodies to
  match the pattern of existing inline ``import json`` calls and to
  keep this module load-order-independent. The dep is unidirectional
  (db.audit → web.db) so no cycle risk; the late-bind is defensive.

Helper duplication: ``_rows`` + ``_row`` are duplicated from
``web/db.py:529-547`` (10 LOC). A shared ``db/_helpers.py`` belongs to
a future #277b/c sub-task when ≥2 modules legitimately need them.
"""

from __future__ import annotations

from email_triage.db.columns import AUTH_EVENTS_COLUMNS, USER_STATUS_EVENTS_COLUMNS
from email_triage._isotime import now_utc_iso

from email_triage.db._helpers import (
    dump_json_col, load_json_col, refuse_undeclared_nesting,
)

import sqlite3
import threading
from typing import Any

from email_triage.web.db_writelock import db_write
from email_triage._dbapi_errors import DB_INTEGRITY_ERRORS, DB_OPERATIONAL_ERRORS


# ---------------------------------------------------------------------------
# H-02a HMAC key registry (Cycle 6, 2026-05-23)
# ---------------------------------------------------------------------------
#
# The audit-chain HMAC-SHA256 subkey is HKDF-derived from the
# DbSecrets master key at app startup (see secrets.py
# derive_audit_chain_hmac_key + web/app.py lifespan wiring + cli.py
# bootstrap). The derived subkey is stashed in the process-wide
# ``_HMAC_KEYS`` dict, version-keyed so verify_log_chain can dispatch
# per-row across master-key rotations (per R1-plumbing-IN verdict
# 2026-05-23T23:02Z: rotation preserves old masters under
# secrets_store:master_key_history:v{N} via KEK pattern; startup loads
# each into the version map so legacy HMAC chain rows remain
# verifiable for §164.316(b)(2)(i) 6-year retention).
#
# Threading: every read+write goes through ``_hmac_keys_lock``. The
# write path is exactly two callers (set_hmac_keys at lifespan startup
# AND _set_hmac_key_for_test in test fixtures); reads are on the
# log-emit hot path (SQLiteLogHandler.emit) and the verifier path
# (verify_log_chain). The dict is replaced wholesale on writes; reads
# return the live dict's keys/values without copying.
#
# D1 fail-closed (per medical-scope §164.312(c)(1) Required-spec):
# when compute_log_row_hash is invoked with hash_alg='hmac-sha256-v1'
# AND the corresponding master_key_version is not in _HMAC_KEYS, it
# raises RuntimeError. This is the override of D2 fail-open per
# hipaa-sme-2 + DA-3 verdicts: any silent SHA-256 fallback would
# admit the insider-with-DB-write threat model H-02a closes. Test
# fixtures use the explicit _set_hmac_key_for_test() escape hatch
# rather than letting compute_log_row_hash auto-degrade.

_HMAC_KEYS: dict[int, bytes] = {}
_HMAC_CURRENT_VERSION: int | None = None
_hmac_keys_lock = threading.Lock()


def set_hmac_keys(
    keys_by_version: dict[int, bytes],
    current_version: int,
) -> None:
    """Install the HMAC-key registry — called once at app startup.

    The lifespan / CLI bootstrap derives one HMAC subkey per known
    master-key version (current + every preserved historical version
    in ``secrets_store:master_key_history:v*``), then calls this
    helper to populate the module-level registry.

    Args:
        keys_by_version: dict mapping integer master_key_version to
            the corresponding 32-byte HMAC-SHA256 subkey. MUST include
            ``current_version``; SHOULD include every historical
            version that any log_entries row references.
        current_version: the version stamped on NEW rows. Always the
            highest-numbered version in the dict.

    Raises:
        ValueError: if ``current_version`` is not in ``keys_by_version``.
    """
    if current_version not in keys_by_version:
        raise ValueError(
            f"current_version={current_version} not present in "
            f"keys_by_version dict (versions={sorted(keys_by_version.keys())})"
        )
    global _HMAC_CURRENT_VERSION
    with _hmac_keys_lock:
        _HMAC_KEYS.clear()
        _HMAC_KEYS.update(keys_by_version)
        _HMAC_CURRENT_VERSION = current_version


def _set_hmac_key_for_test(
    key: bytes,
    version: int = 0,
    *,
    keep_existing: bool = False,
) -> None:
    """Test-only HMAC key installer — D1-fail-closed escape hatch.

    Test fixtures call this explicitly to provision an HMAC key in
    the registry rather than letting :func:`compute_log_row_hash` fail
    closed with RuntimeError. NOT a fallback in the primitive itself;
    explicit per hipaa-sme-2 + DA-3 D1 verdict 2026-05-23.

    Args:
        key: 32-byte HMAC-SHA256 subkey. In tests, generate via
            :func:`email_triage.secrets.derive_audit_chain_hmac_key`
            against a test master key, or hard-code a constant.
        version: master-key version slot to install at. Default 0 (the
            initial master-key version on a fresh install with no
            rotations).
        keep_existing: if True, MERGE into the existing registry; if
            False (default), REPLACE the registry entirely. Tests that
            simulate rotation install v0+v1 with keep_existing=True
            on the second call.
    """
    global _HMAC_CURRENT_VERSION
    with _hmac_keys_lock:
        if not keep_existing:
            _HMAC_KEYS.clear()
        _HMAC_KEYS[version] = key
        # Test helper picks the current-version as the highest installed
        # so tests don't need a separate set_hmac_keys() call.
        _HMAC_CURRENT_VERSION = max(_HMAC_KEYS.keys())


def _clear_hmac_keys_for_test() -> None:
    """Test-only registry reset. Restores the D1-fail-closed posture."""
    global _HMAC_CURRENT_VERSION
    with _hmac_keys_lock:
        _HMAC_KEYS.clear()
        _HMAC_CURRENT_VERSION = None


def _get_hmac_key(version: int) -> bytes | None:
    """Return the HMAC subkey for ``version``, or None if absent.

    None return = D1-fail-closed path is engaged: caller
    (:func:`compute_log_row_hash`) MUST raise RuntimeError per
    §164.312(c)(1) Required-spec verdict. Caller is responsible for
    the error message; this helper is mechanism-only.
    """
    with _hmac_keys_lock:
        return _HMAC_KEYS.get(version)


def _get_current_hmac_version() -> int | None:
    """Return the current (highest-installed) HMAC key version.

    Returns None if no HMAC keys are provisioned (fresh process,
    test-fixture absent, lifespan didn't wire it). Callers
    (:func:`insert_log_entry`, :func:`compute_log_row_hash` when
    called without explicit version) treat None as the D1-fail-closed
    trigger — they will fail when trying to write HMAC rows.
    """
    with _hmac_keys_lock:
        return _HMAC_CURRENT_VERSION


# ---------------------------------------------------------------------------
# DDL — audit-cluster tables (each block is idempotent via IF NOT EXISTS).
# Order in this file matches their previous ``_ALL_DDL`` order in web/db.py
# so the FK-dependency invariants (e.g. hipaa_access_events → email_accounts,
# users) hold when web/db.py's ``init_db`` calls them after the
# email_accounts / users DDL.
# ---------------------------------------------------------------------------

_USER_STATUS_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS user_status_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    target_user_id INTEGER NOT NULL,
    actor_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_user_status_events_target ON user_status_events(target_user_id);
CREATE INDEX IF NOT EXISTS idx_user_status_events_ts ON user_status_events(ts);
"""

_HIPAA_BOUNDARY_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS hipaa_boundary_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    scope     TEXT NOT NULL,
    direction TEXT NOT NULL,
    actor_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_hipaa_boundary_ts    ON hipaa_boundary_events(ts);
CREATE INDEX IF NOT EXISTS idx_hipaa_boundary_scope ON hipaa_boundary_events(scope);
"""


# PR 9 / D4 — append-only audit trail for credential use. The
# pre-PR-9 shape was: dev_keys.last_used_at + dev_keys.last_used_ip
# overwrite the row on every successful auth; same for hardware_keys.
# Operators auditing "when did key X authenticate, from where, for
# whom" historically had ONLY the most-recent value -- prior uses
# were silently lost. This table records each use as a row so the
# full history is preserved.
#
# event_type:
#   "login_otp"          -- standard email-OTP login.
#   "login_dev_keypair"  -- admin-managed Ed25519 keypair login.
#   "login_webauthn"     -- per-user FIDO2 passkey.
#
# key_id is NULL for OTP (no key); for the other two, it points to
# dev_keys.id or hardware_keys.id respectively. outcome is
# "success" / "denied:<reason>" so failed attempts (wrong sig, key
# revoked, hardware-key-wins block) leave a trace too.
_AUTH_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS auth_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    email       TEXT    NOT NULL,
    key_id      INTEGER,
    ip          TEXT,
    user_agent  TEXT,
    outcome     TEXT    NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts      ON auth_events(ts);
CREATE INDEX IF NOT EXISTS idx_auth_events_user    ON auth_events(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_event   ON auth_events(event_type);
CREATE INDEX IF NOT EXISTS idx_auth_events_outcome ON auth_events(outcome);
"""

_LOG_ENTRIES_DDL = """\
CREATE TABLE IF NOT EXISTS log_entries (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT NOT NULL,
    level              TEXT NOT NULL,
    logger             TEXT NOT NULL DEFAULT '',
    message            TEXT NOT NULL DEFAULT '',
    extra_json         TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL,
    prev_hash          TEXT NOT NULL DEFAULT '',
    row_hash           TEXT NOT NULL DEFAULT '',
    hash_alg           TEXT NOT NULL DEFAULT 'sha256',
    master_key_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_log_entries_ts ON log_entries(ts);
CREATE INDEX IF NOT EXISTS idx_log_entries_level ON log_entries(level);
"""

# H-02a (Cycle 6, 2026-05-23) — new columns:
#
# - ``hash_alg`` (TEXT, default 'sha256'): the hash algorithm used to compute
#   this row's ``row_hash``. Legacy rows written before the H-02a migration
#   land as 'sha256' (default applied by ALTER TABLE in
#   ``web.db._apply_migrations``). New rows written under HMAC stamp
#   'hmac-sha256-v1'. Future cryptographic upgrades bump the version suffix
#   (e.g., 'hmac-sha256-v2' or 'hmac-sha3-v1') without rewriting old rows.
#
# - ``master_key_version`` (INTEGER, default 0): the version of the master key
#   that was active when this row was written. The HMAC key is HKDF-derived
#   from the master key; ``DbSecrets.rotate_master_key`` preserves old masters
#   in the ``secrets_store`` under ``master_key_history:v{N}`` keys (key-
#   encrypting-key pattern per NIST SP 800-57 §6.2.2) so the verifier can
#   compute the correct historical HMAC for every chain-aware row. New
#   installs without a prior rotation see ``master_key_version=0`` for all
#   rows (the initial master key).
#
# Both columns are NOT NULL with sensible defaults so the idempotent
# ``ALTER TABLE log_entries ADD COLUMN`` migrations in
# ``web.db._apply_migrations`` apply cleanly on upgrade installs without
# back-fill. The verifier's per-row dispatch in :func:`verify_log_chain`
# handles every (hash_alg, master_key_version) combination including the
# legacy ('sha256', 0) pair for pre-H-02a rows.

_HIPAA_ACCESS_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS hipaa_access_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    account_id    INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    operation     TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    detail        TEXT
);
CREATE INDEX IF NOT EXISTS idx_hipaa_access_ts      ON hipaa_access_events(ts);
CREATE INDEX IF NOT EXISTS idx_hipaa_access_account ON hipaa_access_events(account_id);
"""

_API_KEY_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS api_key_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    event          TEXT NOT NULL,
    key_id         INTEGER NOT NULL,
    actor_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    name           TEXT NOT NULL DEFAULT '',
    expires_at     TEXT,
    source         TEXT NOT NULL,
    -- Punch 710 (v54): WHO granted or revoked: the actor's address, or the CLI
    -- kernel principal (``cli:<user>``). Stored, NOT in the row hash (the
    -- canonical field tuple is frozen per table).
    actor_email    TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_key_events_ts ON api_key_events(ts);
CREATE INDEX IF NOT EXISTS idx_api_key_events_target ON api_key_events(target_user_id);
"""

#  — generic access-audit log (HIPAA §164.312(b)). Sibling of
# hipaa_access_events but covers every authenticated PHI-surface
# request, not only triage-pipeline writes. The middleware in
# web/app.py records here on every request whose path matches a
# PHI-touch prefix (/classify, /triage/run, /accounts/<id>/{messages,
# digest, folders, discover, bulk}, /api/v1, /runs/<id>).
#
# No PHI is persisted: route + method + status + actor are stamped;
# the request body is never logged. account_id and message_id are
# extracted from the URL path when present so the auditor can answer
# "who looked at this account / message, and when?" without scraping
# the path themselves.
# NOTE: this is the ORIGINAL-install shape only. Later web/db.py migrations add
# columns NOT shown here — request_id, and auth_source / auth_key_id
# (present but NOT written by record_access_event, hence excluded from the chain
# canonical tuple). The live schema is the migrated one; do not read this inline
# DDL as the authoritative column set.
_ACCESS_LOG_DDL = """\
CREATE TABLE IF NOT EXISTS access_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    actor_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    method         TEXT NOT NULL,
    route          TEXT NOT NULL,
    account_id     INTEGER REFERENCES email_accounts(id) ON DELETE SET NULL,
    message_id     TEXT,
    status_code    INTEGER NOT NULL,
    outcome        TEXT NOT NULL,
    detail         TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_log_ts        ON access_log(ts);
CREATE INDEX IF NOT EXISTS idx_access_log_actor     ON access_log(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_access_log_account   ON access_log(account_id);
"""

# Lifted from web/db.py _apply_migrations (formerly inline at lines
# 603-617) per #277a Decision C — DDL cohesion with the audit cluster.
# Still re-applied (idempotent IF NOT EXISTS) by _apply_migrations on
# upgrade installs that pre-date the audit-package extraction.
#
# Discover audit: who ran a Discover Categories scan against which account,
# when, and how broadly. Discover exposes sender + subject of every scanned
# message and is mail-read-level privilege and needs an audit row regardless
# of the HIPAA flag. Metadata only (no sender / subject / raw_description /
# raw_category) because the scan output is proposals-in-review, not actions
# taken.
_DISCOVER_RUNS_DDL = """\
CREATE TABLE IF NOT EXISTS discover_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id     INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    account_name   TEXT NOT NULL DEFAULT '',
    actor_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    scanned_count  INTEGER NOT NULL DEFAULT 0,
    errors_count   INTEGER NOT NULL DEFAULT 0,
    folders        TEXT NOT NULL DEFAULT '[]',
    elapsed_secs   REAL NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discover_runs_acct ON discover_runs(account_id);
CREATE INDEX IF NOT EXISTS idx_discover_runs_created ON discover_runs(created_at);
"""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AUDIT_CHAIN_ANCHOR_KEY = "audit:chain_anchor"

#  / N-15 — the canonical-field SSOT for the audit-event HMAC chains.
#
# Maps each chained audit-event table to the ORDERED tuple of column names whose
# values feed ``_canonical_audit_row`` (and therefore ``row_hash``). The keys of
# this dict ARE the set of chained audit tables — ``get_last_audit_row_hash`` /
# ``_chain_insert`` validate the table name against it (allow-list; the table
# name is interpolated into SQL, so this is also the injection guard).
#
# OPTION A (SME/DA design review wf_7af575de-5d8, unanimous): the field tuple
# holds only the IMMUTABLE creation fields. ``hipaa_access_events`` is the ONLY
# table with an in-place UPDATE (``update_hipaa_access_event`` finalises
# outcome+detail), so it EXCLUDES ``outcome`` + ``detail`` — that makes the
# finalise UPDATE chain-transparent (it touches no hashed column, so row_hash is
# unchanged and the chain needs no O(n) re-link). The inverse pin
# (test_audit_chain_pin.py) asserts this exclusion so a future dev cannot
# silently add a hashed mutable field. The other 7 tables are append-only
# (verified: no UPDATE statements at HEAD), so every immutable content column is
# hashed, with ONE exception: ``api_key_events.actor_email`` (punch 710, v54) is
# stored but NOT hashed. Hashing it would NOT re-hash existing rows: the verifier
# dispatches per row on ``hash_alg`` (``CHAIN_HASH_ALG_CURRENT``, ), so a new
# keyed alg label with a widened tuple covers new rows only. It is deferred
# because a chain-format change during the v0.2.0 bug-fix freeze carries verifier
# risk; v0.2.x hashes it under a new label (panel AB MUST-C4). Until then readers
# display the address resolved from the HASHED ``actor_user_id`` first.
#
# FIELD ORDER IS A FROZEN CONTRACT: reordering re-hashes the chain. These chains
# have no pre-#26 history (every existing row is a prechain row_hash=''), so the
# order is fixed from the first chained write forward.
_AUDIT_CHAIN_CANONICAL_FIELDS: dict[str, tuple[str, ...]] = {
    # who (actor_user_id) / whose-account (account_id) / what (operation) / when
    # (ts) — the access FACT. outcome+detail EXCLUDED (mutable; Option A).
    "hipaa_access_events": ("ts", "actor_user_id", "account_id", "operation"),
    "hipaa_boundary_events": ("ts", "scope", "direction", "actor_id", "reason"),
    "auth_events": (
        "ts", "event_type", "user_id", "email", "key_id", "ip",
        "user_agent", "outcome", "detail",
    ),
    "user_status_events": (
        "ts", "target_user_id", "actor_user_id", "event", "reason",
    ),
    "api_key_events": (
        "ts", "event", "key_id", "actor_user_id", "target_user_id",
        "name", "expires_at", "source",
    ),
    # access_log is append-only (no UPDATE) so all WRITTEN columns are hashed.
    # auth_source/auth_key_id columns exist but record_access_event never
    # populates them (always NULL) — excluded because they are not in the
    # writer's data dict; request_id IS written and is hashed.
    "access_log": (
        "ts", "actor_user_id", "method", "route", "account_id",
        "message_id", "status_code", "outcome", "detail", "request_id",
    ),
    "discover_runs": (
        "account_id", "account_name", "actor_user_id", "scanned_count",
        "errors_count", "folders", "elapsed_secs", "created_at",
    ),
    # §164.502(e) cloud-PHI-egress accounting trail. was_cloud = the egress
    # signal; recipient_hash = a correlatable per-contact digest (already
    # hashed, no PHI plaintext) — both immutable, both hashed for full
    # tamper-evidence on the disclosure record.
    "style_distill_events": (
        "ts", "account_id", "actor_user_id", "backend_id", "backend_type",
        "was_cloud", "outcome", "latency_ms", "layer1_drops",
        "layer2_matches", "layer3_entities", "scrubber_degraded",
        "error_class", "kind", "recipient_hash",
    ),
    #  — regulatory clock transitions. APPEND-ONLY (every transition is a new
    # row; no in-place UPDATE — a correction is a new determination_corrected
    # event), so EVERY written column is immutable and hashed; no Option-A
    # mutable-field exclusion. (`id` autoincrement + the 4 chain cols are not
    # data.) Chain columns added in migration v47 — the dedicated chained table
    # SUPERSEDES the design's "chain into the pruned log_entries" projection
    # model (pruning would breach §164.316(b)(2)(i) retention; see _v47).
    "regulatory_clock_event": (
        "instance_id", "event_kind", "actor_user_id", "from_state", "to_state",
        "escalation_rung", "delivered_to_ref", "detail", "created_at",
    ),
}


# ---------------------------------------------------------------------------
# Row-shape helpers — duplicated from web/db.py:529-547 per #277a Decision B.
# A shared db/_helpers.py belongs to a future #277b/c sub-task when ≥2
# modules legitimately need them.
# ---------------------------------------------------------------------------

# N-235 R23 — collapsed onto db/_helpers.py (was 3 byte-identical SSOTs).
from email_triage.db._helpers import _row, _rows  # noqa: E402,F401 — re-export


# ---------------------------------------------------------------------------
# Log entries — CRUD + pruning
# ---------------------------------------------------------------------------

def insert_log_entry(
    conn: sqlite3.Connection,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra: dict | None = None,
) -> None:
    """Insert a log entry into the database — chain-aware.

     — ``@db_write`` holds the process-wide write lock for the
    ``get_last_log_row_hash`` read + the INSERT so a foreign writer
    cannot slot between the chain-tail read and the INSERT and break
    the HIPAA log hash-chain. (Commit timing is still caller-owned —
    see the note below — so the commit itself is not under this lock;
    the chain-critical read+INSERT pair is.)

    .. warning::

        This helper exists for tests and for non-stdlib-logging surfaces
        (structured-event sinks, fixture seeding). The stdlib
        ``logging`` path goes through :class:`SQLiteLogHandler` and
        MUST stay there — that handler caches the last row hash on the
        instance, eliminating a SELECT per emit on the hot path.

        Helper writers MUST keep this chain-aware. Inserting empty
        ``prev_hash`` / ``row_hash`` strings here re-introduces the
        legacy "pre-chain row" gap that
        :func:`verify_log_chain` skips silently — leaving entire
        windows of activity outside the integrity envelope. HIPAA
        §164.312(c)(1) integrity rests on every row being chained.

    Computes ``prev_hash`` + ``row_hash`` via :func:`compute_log_row_hash`
    against the current chain tail (:func:`get_last_log_row_hash`).
    Caller still owns commit timing — pass an autocommit connection or
    commit explicitly.

    H-02a (Cycle 6, 2026-05-23): new rows stamp a keyed ``hash_alg``
    (``CHAIN_HASH_ALG_CURRENT``, ``hmac-sha256-v2`` since N-507 option A)
    and ``master_key_version`` = current registry version. Raises RuntimeError if no HMAC key is
    provisioned (D1 fail-closed; see :func:`compute_log_row_hash`).
    """
    import json
    now = now_utc_iso()
    # census run17 #1 — route this writer through the persisted-log redaction
    # SSOT BEFORE the hash preimage is built (hash == store). phi_allowlist=False
    # = SECRET-STRIP ONLY: this writer's sole production caller (the CLI
    # admin-op audit, cli.py) already curates its payload via _SAFE_ARG_KEYS, so
    # the full PHI ALLOWLIST would destroy the §164.312(b) audit-row CONTENT
    # (admin action name / flags / error_class → redacted) without removing any
    # leak (devils-advocate diff-review, 2026-06-27). The full PHI allowlist
    # guards the UNCURATED raw-getLogger sink (SQLiteLogHandler.emit). Lazy
    # import avoids an import cycle (triage_logging late-imports web.db).
    from email_triage import triage_logging as _tlog
    extra_json = json.dumps(
        _tlog.redact_persisted_extra(
            extra or {}, hipaa=_tlog._hipaa_mode, phi_allowlist=False
        )
    )
    # Punch 606: the message rides the same secret-value funnel the extras
    # just did (inside redact_persisted_extra), before the hash preimage.
    message = _tlog.scrub_persisted_log_text(message)
    prev_hash = get_last_log_row_hash(conn)
    # H-02a: stamp the current HMAC version on the row + compute under
    # the current HMAC subkey. _get_current_hmac_version() returns None
    # if the registry is unprovisioned; compute_log_row_hash will
    # RuntimeError in that case (D1 fail-closed). insert_log_entry has
    # no special-case path for missing keys — it's the same primitive
    # contract as the hot-path SQLiteLogHandler.emit().
    current_version = _get_current_hmac_version()
    hash_alg = CHAIN_HASH_ALG_CURRENT
    row_hash = compute_log_row_hash(
        prev_hash, ts, level, logger, message, extra_json,
        hash_alg=hash_alg,
        master_key_version=current_version,
    )
    conn.execute(
        "INSERT INTO log_entries "
        "(ts, level, logger, message, extra_json, created_at, "
        " prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ts, level, logger, message, extra_json, now,
            prev_hash, row_hash, hash_alg, current_version or 0,
        ),
    )
    # Don't commit every entry — caller should batch or use autocommit.


def recent_cert_check_failures(
    conn: sqlite3.Connection, *, logger: str, message: str, since_iso: str,
    limit: int = 5,
) -> list[dict]:
    """Panel M M-DA-10 (warning only): the recent ``tls_cert_check_failed``
    rows whose connection went ahead unverified (``action`` =
    ``connected_unverified``), newest first, deduplicated by (host, port,
    protocol), as ``{host, port, protocol, ts}``. Read-only, for the admin
    banner. The caller passes the event's logger and message
    (``email_triage.tls`` ``CERT_FAIL_LOGGER`` / ``CERT_FAIL_MESSAGE``)."""
    rows = conn.execute(
        "SELECT ts, extra_json FROM log_entries "
        # ORDER BY ts (not id) lets idx_log_entries_ts serve the range; ORDER BY
        # id walked the whole audit table backwards on every admin render when
        # no row matched (panel M, M-DA-12: SCAN log_entries, ~476k rows in prod).
        "WHERE logger = ? AND message = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
        (logger, message, since_iso, max(1, limit) * 20),
    ).fetchall()
    out: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        extra = load_json_col(row[1], default={})
        if not isinstance(extra, dict) or extra.get("action") != "connected_unverified":
            continue
        key = (extra.get("host"), extra.get("port"), extra.get("protocol"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"host": str(extra.get("host") or ""), "port": extra.get("port"),
                    "protocol": str(extra.get("protocol") or ""), "ts": str(row[0])})
        if len(out) >= limit:
            break
    return out


def list_log_entries(
    conn: sqlite3.Connection,
    limit: int = 200,
    level: str | None = None,
    offset: int = 0,
    query: str | None = None,
) -> list[dict]:
    """Return recent log entries, newest first.

    ``query`` is a case-insensitive substring filter that matches
    against message + logger + extra_json. Useful for correlating on
    flow_id, account_name, uid, or any text the caller threaded into
    log extras.
    """
    import json
    clauses: list[str] = []
    params: list = []
    if level:
        clauses.append("level = ?")
        params.append(level.upper())
    if query:
        # Match anywhere in message / logger / extras. LIKE with lower()
        # for case-insensitive; % wildcards wrap the query term.
        q_like = f"%{query.lower()}%"
        clauses.append(
            "(LOWER(message) LIKE ? OR LOWER(logger) LIKE ? "
            "OR LOWER(extra_json) LIKE ?)"
        )
        params.extend([q_like, q_like, q_like])
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    sql = (
        f"SELECT * FROM log_entries {where}"
        f"ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        extra = load_json_col(d.pop("extra_json", "{}"), default={})
        # Render-time legacy unpack: rows emitted before the
        # ec06f21 fix landed with shape {"_extra": "<stringified
        # dict>"} (the SQLite handler's old emit() walked
        # vars(record) and stored record._extra as a
        # str()-coerced single key instead of hoisting the inner
        # keys to top-level). Detect that shape + parse the
        # stringified dict via ast.literal_eval (it's a Python
        # repr, not JSON — single-quoted strings) so the /logs
        # pill renderer + Details column can see the actual
        # error / account / uid / flow_id fields. Backfilling the
        # rows would invalidate the audit hash chain; the
        # render-time unpack leaves storage intact.
        if (
            isinstance(extra, dict)
            and len(extra) == 1
            and "_extra" in extra
            and isinstance(extra["_extra"], str)
        ):
            import ast as _ast
            try:
                inner = _ast.literal_eval(extra["_extra"])
                if isinstance(inner, dict):
                    extra = {str(k): v for k, v in inner.items()}
            except (ValueError, SyntaxError):
                # Malformed; leave the original shape so the
                # operator can still see something even if pills
                # don't render.
                pass
        d["extra"] = extra
        result.append(d)
    return result


def _capture_chain_anchor(conn: sqlite3.Connection) -> None:
    """Stamp the post-prune chain head into the settings table.

    Called inside the same transaction as a prune so anchor + DELETE are
    atomic. After the oldest rows are gone, the new chain-aware head row
    no longer has its predecessor in the table — its ``prev_hash`` would
    otherwise look like a chain break to :func:`verify_log_chain`. The
    anchor seeds the verifier with the head's recorded ``prev_hash`` so
    the chain validates from that boundary forward.

    Stored shape (settings table, key ``audit:chain_anchor``)::

        {"head_id": int, "head_prev_hash": str, "anchored_at": iso}

    No-op when the table is empty post-prune (nothing to anchor).
    """
    # Late-bind the settings-table helpers from web/db. The dep is
    # unidirectional (db.audit -> web.db) so no cycle; the late-bind
    # keeps this module load-order-independent and matches the existing
    # pattern of inline ``import json`` etc. in helpers throughout
    # web/db.py.
    from email_triage.web.db import invalidate_setting_cache, set_setting_txn
    # H-02a (Cycle 6): anchor extended to include the head row's
    # hash_alg + master_key_version so verify_log_chain's anchor-seed
    # path knows which primitive + key version to apply when re-walking
    # post-prune. Pre-H-02a rows default to ('sha256', 0) via the
    # ALTER TABLE migration, so anchors written before the H-02a deploy
    # but read after stay correct: their head row's hash_alg field
    # resolves to 'sha256' (legacy default).
    head = conn.execute(
        "SELECT id, prev_hash, hash_alg, master_key_version FROM log_entries "
        "WHERE row_hash != '' "
        "ORDER BY id ASC LIMIT 1"
    ).fetchone()
    if head is None:
        return
    anchor = {
        "head_id": int(head["id"]),
        "head_prev_hash": head["prev_hash"] or "",
        "head_hash_alg": head["hash_alg"] or "sha256",
        "head_master_key_version": int(head["master_key_version"] or 0),
        "anchored_at": now_utc_iso(),
    }
    # The txn-aware settings SSOT (allow-list step 2, B3): NOT set_setting(),
    # which auto-commits, because the anchor write must share the prune
    # transaction. set_setting_txn upserts without committing and invalidates
    # the in-process settings cache itself.
    set_setting_txn(conn, _AUDIT_CHAIN_ANCHOR_KEY, anchor)
    # A second post-write invalidation. NOTE: this is NOT the exit edge that
    # set_setting_txn's PRECONDITION asks for: it runs BEFORE the prune's
    # conn.commit(), so a reader between here and that commit can still
    # refill the cache with the pre-prune anchor for up to the cache TTL.
    # Pre-existing behaviour (the old inline UPSERT invalidated at this same
    # point); s2 panel B-S1.
    invalidate_setting_cache(_AUDIT_CHAIN_ANCHOR_KEY)


# ---------------------------------------------------------------------------
#  Deliverable 3 — @audit_emitter decorator (declaration only).
# Full helper + redaction-map machinery lives at the end of this module
# (search for "Deliverable 3 — audit-emitter gap-event sentinel"). The
# decorator itself is hoisted here so it's defined BEFORE the 7
# audit-emitter functions that consume it (`record_user_status_event`
# etc.). Forward references would otherwise NameError at import time.
# ---------------------------------------------------------------------------

def audit_emitter(fn):  # type: ignore[no-untyped-def]
    """Mark a ``@db_write`` helper as an audit-row emitter.

    See full docstring at the end-of-module helper block. Composition
    order is ``@db_write`` OUTER, ``@audit_emitter`` INNER::

        @db_write
        @audit_emitter
        def record_user_status_event(conn, ...):
            ...
    """
    fn._is_audit_emitter = True
    return fn


@db_write
def prune_log_entries(conn: sqlite3.Connection, keep: int = 5000) -> int:
    """Delete old log entries, keeping the most recent *keep* rows.

    Legacy count-only helper. Kept for back-compat with any external
    callers — prefer :func:`prune_log_entries_by_age_and_count`, which
    the web app wires up at startup + every 30 min.

    Captures the new head row's ``prev_hash`` into ``audit:chain_anchor``
    inside the same transaction as the DELETE so the verifier doesn't
    flag the post-prune boundary as a chain break.
    """
    cursor = conn.execute(
        "DELETE FROM log_entries WHERE id NOT IN "
        "(SELECT id FROM log_entries ORDER BY id DESC LIMIT ?)",
        (keep,),
    )
    if cursor.rowcount > 0:
        _capture_chain_anchor(conn)
    conn.commit()
    return cursor.rowcount


@db_write
def prune_log_entries_by_age_and_count(
    conn: sqlite3.Connection,
    *,
    retention_days: int = 30,
    max_rows: int = 50000,
) -> int:
    """Delete rows older than ``retention_days`` OR beyond ``max_rows``.

    Combined rotation policy (item #26c): an age axis bounds long-tail
    retention, a count axis bounds explosive-growth edge cases (debug
    bursts, log-level churn). Whichever axis trims more wins — they are
    applied with an OR in a single DELETE for atomicity.

    Captures the new head row's ``prev_hash`` into ``audit:chain_anchor``
    inside the same transaction as the DELETE so the verifier doesn't
    flag the post-prune boundary as a chain break ( — HIPAA
    §164.312(c)(1) integrity).

    Returns the number of rows deleted. Idempotent — a second call on
    an already-bounded table is a no-op.
    """
    cursor = conn.execute(
        "DELETE FROM log_entries WHERE "
        "ts < datetime('now', ?) "
        "OR id NOT IN (SELECT id FROM log_entries ORDER BY id DESC LIMIT ?)",
        (f"-{int(retention_days)} days", int(max_rows)),
    )
    if cursor.rowcount > 0:
        _capture_chain_anchor(conn)
    conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# N-349b Item 1 — HMAC clobber bypass consumption audit emitter (2026-07-07)
# ---------------------------------------------------------------------------
# The 2026-07-05 N-349 hybrid SME panel surfaced a §164.312(b) gap: the ARM
# event for `secrets allow-hmac-clobber-once` emits a `@_cli_audit("secrets")`
# row (visible in the HMAC-chained `log_entries` envelope), but the CONSUME
# event — the watch-HMAC hydration path in `get_or_mint_secret` observing
# `bypass_check()==True` on an unreadable row and MINTING a fresh secret —
# previously fired only a stdlib `logger.warning` from `secrets.py`. That
# warning routes through `SQLiteLogHandler.emit` in production (also chained
# per  + H-02a) but the correlation between the ARM CLI row and the
# CONSUME `SQLiteLogHandler` row was implicit (both go into `log_entries` via
# different paths). An investigator sweeping the security-key lifecycle
# needs an EXPLICIT emitter-owned CONSUME event tagged as a bypass consumption
# so an arm-without-consume (or consume-without-arm) fires an obvious diff.
#
# This helper is the emitter-shaped counterpart: `@db_write` OUTER +
# `@audit_emitter` INNER, routing through the `insert_log_entry` chain-
# aware primitive. A write failure fires a matching `audit_gap_events` row
# via `db_writelock._wrap` per the redaction-map entry below.
#
# HIPAA §164.312(b) audit-controls + §164.308(a)(4)(ii)(C) access-establish/
# modification (the ARM→CONSUME lifecycle ties operator authorization to
# the actual break-glass event). Register row N-3xx filed same-commit.


@db_write
@audit_emitter  # N-349b Item 1 R31 (2026-07-07) — gap-event on write failure
def record_hmac_clobber_bypass_consumed(
    conn: sqlite3.Connection,
    *,
    secret_key: str,
    actor_user_id: int | None = None,
    watch_id: str | None = None,
) -> None:
    """N-349b Item 1 R31 (2026-07-07) — HMAC-chained audit row at
    operator-armed HMAC-clobber-bypass consumption.

    Called from ``get_or_mint_secret`` (via a caller-supplied
    ``bypass_audit_emit`` closure) after ``bypass_check()`` returned
    True AND the fresh mint + ``.set()`` succeeded — that is, after the
    break-glass lever fully fired. The row participates in the same
    ``log_entries`` HMAC chain as the CLI ARM row + the same-file
    `logger.warning` sibling, giving an investigator ONE tamper-evident
    envelope covering the whole ARM→CONSUME lifecycle.

    Args are keyword-only + bounded:

    * ``secret_key`` — the settings key (e.g. ``watch_hmac:<uuid>``);
      operator-chosen namespaced string, no PHI.
    * ``actor_user_id`` — the request-context user id iff callers plumb
      it (currently ``None`` at all 3 sites; plumbing is a follow-up).
    * ``watch_id`` — the watch UUID whose HMAC the mint replaced.

    All 3 are IN-class in ``_AUDIT_EMITTER_REDACTION_MAP`` (Safe-Harbor —
    typed IDs / operator-namespaced strings) so a gap-event row would
    carry them verbatim.
    """
    now = now_utc_iso()
    # Route through the chain-aware primitive so the row lands in the
    # SAME `log_entries` envelope the CLI arm-audit row + the
    # SQLiteLogHandler warning sibling occupy — one chain, one seek
    # per verifier sweep.
    insert_log_entry(
        conn,
        now,
        "WARNING",
        "email_triage.secrets.n349_hybrid",
        "HMAC clobber bypass CONSUMED — fresh secret minted after operator-armed one-shot",
        extra={
            "event": "hmac_clobber_bypass_consumed",
            "secret_key": secret_key,
            "actor_user_id": actor_user_id,
            "watch_id": watch_id,
        },
    )
    conn.commit()


# ---------------------------------------------------------------------------
# N-157 — CLI admin-op chain-write emitter (2026-07-09)
# ---------------------------------------------------------------------------
# The H-03-auto CLI audit auto-emit path at ``cli.py::_emit_cli_audit_event``
# previously wrote directly through ``insert_log_entry`` — a raw chain-
# primitive call that bypasses the ``@audit_emitter`` gap-event sentinel
# (audit_gap_events, per  Deliverable 3). If the ``@db_write`` wrapper
# rolled back on a SQLITE_MISUSE / cursor-corruption inside the CLI-op
# emit path, the failure had no tamper-evident record — §164.312(b) Audit
# Controls gap.
#
# ``record_cli_admin_op`` is the emitter-shaped SSOT: ``@db_write`` OUTER +
# ``@audit_emitter`` INNER, routing through ``insert_log_entry`` so the
# row lands in the SAME ``log_entries`` HMAC-chained envelope every
# other emitter uses.  Redaction-map entry below marks the 3 typed IN
# fields (Safe-Harbor bounded strings) with ``extra`` split OUT (it is
# a nested pre-redacted dict — the caller has already applied the
# ``_SAFE_ARG_KEYS`` allow-list at ``cli.py:197-227``, so the raw hash
# below captures the payload without re-storing it in the gap row).
#
# The CLI actuator at ``_emit_cli_audit_event`` is responsible for the
# fail-loud policy (operator-directed 2026-07-08 AskUserQuestion:
# "Fail-loud with recovery flag"): default = raise on emit failure
# BEFORE the wrapped handler runs (phase='start'); `--allow-unaudited`
# preserves the H-03-auto fail-soft posture the operator relies on
# mid-incident.  ``record_cli_admin_op`` itself just records the row —
# the gate-decision lives at the actuator per PD #9 (gate at the
# ACTUATOR, not the writer).


@db_write
@audit_emitter  # N-157 (2026-07-09) — gap-event on write failure
def record_cli_admin_op(
    conn: sqlite3.Connection,
    *,
    ts: str,
    command: str,
    phase: str,
    extra: dict,
    allow_unaudited: bool = False,
) -> None:
    """N-157 (§164.312(b)) — chain-write for CLI admin-op start/end.

    Routes through ``insert_log_entry`` so the row lands in the
    ``log_entries`` HMAC-chained envelope alongside every other
    audit-emitter surface. A write failure fires an
    ``audit_gap_events`` row via ``db_writelock._wrap`` per the
    redaction-map entry.

    Keyword-only arguments are pre-redacted by the caller at
    ``cli.py::_emit_cli_audit_event`` (the ``_SAFE_ARG_KEYS`` allow-list
    strips any argparse Namespace field not on the audit-safe list).
    ``command`` + ``phase`` are bounded operator-namespaced strings
    (Safe-Harbor IN); ``ts`` is an ISO timestamp (IN); ``extra`` is a
    nested dict of already-redacted fields — kept OUT to keep the
    redacted payload compact (raw hash still binds it so an investigator
    can cross-match against the ``log_entries`` row a successful write
    would have produced).

    ``allow_unaudited`` is the fail-loud gate bypass flag (Safe-Harbor
    typed bool — 1 bit, no PHI vector) — DA fold N-157 Fix #2 promoted
    it to a dedicated top-level IN field on the gap-row so an
    investigator can determine the fail-loud policy state at the moment
    of the failed emit without cross-matching against external CLI-
    invocation logs (shell history / journalctl / system audit).
    HIPAA-sme calibration 2026-07-09: §164.502(b) NET-REDUCTION of the
    investigation surface (bypass bit stays inside the HMAC-chained
    envelope, not spread across external logs) + §164.312(b) audit-
    integrity strengthened.  Redundant on the SUCCESS path (``extra``
    carries the same field via ``_SAFE_ARG_KEYS``) — LOAD-BEARING on the
    FAILURE path (the gap-row is where the bypass signal now lands).
    """
    insert_log_entry(
        conn,
        ts,
        "INFO",
        "email_triage.cli.audit",
        f"cli admin op: {command} ({phase})",
        extra=extra,
    )


# ---------------------------------------------------------------------------
# User-status events (disabled/enabled audit + session-epoch bump)
# ---------------------------------------------------------------------------

@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_user_status_event(
    conn: sqlite3.Connection,
    target_user_id: int,
    actor_user_id: int | None,
    event: str,
    reason: str = "",
) -> int:
    """Record a user-status change (disabled/enabled).  Returns the new row id."""
    now = now_utc_iso()
    #  — chained audit write (SSOT). Own-commit emitter.
    row_id = _chain_insert(conn, "user_status_events", {
        "ts": now,
        "target_user_id": target_user_id,
        "actor_user_id": actor_user_id,
        "event": event,
        "reason": reason or "",
    })
    conn.commit()
    return row_id


@db_write
@audit_emitter  # A2 (census 2026-06-09) — gap-event on write failure (§164.312(b))
def set_user_disabled(
    conn: sqlite3.Connection,
    target_user_id: int,
    disabled: bool,
    actor_user_id: int | None = None,
    reason: str = "",
    *,
    emergency_reason: str | None = None,
    cli_principal: str | None = None,
    source: str = "unknown",
) -> bool:
    """Flip a user's ``disabled`` flag and record the audit row atomically.

    Returns True if the flag actually changed, False if it was already
    in the requested state (no-op, no event recorded).

    Punch 709: ``emergency_reason`` (a code from ``EMERGENCY_REVOKE_REASONS``,
    for the stop-the-account direction only) is the explicit emergency flag.
    Without it nothing changes: a failed witness rolls the flip back and raises.
    With it, a failure of the WITNESS phase alone (the ``users`` update has
    already succeeded) commits the flip without the witness and calls
    :func:`record_emergency_revoke`; a healthy chain takes the normal path and
    writes no gap row. Only an enabled admin, or the host CLI (no user id,
    ``source="cli"``), may pass the flag (:func:`check_emergency_actor`, the
    flag branch's first statement). Like every refusal raised in this
    ``@audit_emitter``, that one leaves exactly one row: the ``db_write``
    sentinel's PHI-free ``set_user_disabled`` gap row (lead ruling 2026-11-03).
    The gap row's actor is built by the funnel from ``actor_user_id`` (the id
    the gate checked) and, for the host CLI only, ``cli_principal``; no caller
    supplies a label that could name someone else (cycle P hipaa S2).
    """
    if emergency_reason is not None:
        check_emergency_actor(conn, actor_user_id, source)
        check_emergency_reason(emergency_reason)
        if not disabled:
            raise EmergencyRevokeRefused("the emergency path only stops an account")
    row = conn.execute(
        "SELECT disabled FROM users WHERE id = ?", (target_user_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"User {target_user_id} not found")
    current = bool(row["disabled"])
    if current == bool(disabled):
        return False

    now = now_utc_iso()
    event = "disabled" if disabled else "enabled"

    witness_failure: Exception | None = None
    try:
        # Pass 1 is the normal witnessed flip. Pass 2 exists only after a
        # witness failure under the emergency flag: it redoes the flip alone.
        for phase in ("witnessed", "emergency"):
            conn.execute("BEGIN")
            if disabled:
                #  — bump session_epoch so the disabled user's
                # outstanding session tokens die immediately AND stay dead
                # if the account is later re-enabled (a re-enable must not
                # resurrect pre-disable sessions).
                conn.execute(
                    "UPDATE users SET disabled = 1, disabled_at = ?, "
                    "disabled_by_user_id = ?, "
                    "session_epoch = session_epoch + 1 WHERE id = ?",
                    (now, actor_user_id, target_user_id),
                )
            else:
                conn.execute(
                    "UPDATE users SET disabled = 0, disabled_at = NULL, "
                    "disabled_by_user_id = NULL WHERE id = ?",
                    (target_user_id,),
                )
            if phase == "emergency":
                break
            #  — chained audit write (SSOT), txn-aware: NO commit here; the
            # explicit COMMIT below makes the users flip + the audit row atomic.
            try:
                _chain_insert(conn, "user_status_events", {
                    "ts": now,
                    "target_user_id": target_user_id,
                    "actor_user_id": actor_user_id,
                    "event": event,
                    "reason": reason or "",
                })
                break
            except Exception as witness_exc:
                if emergency_reason is None:
                    raise
                # Punch 709: undo the half-open transaction and go round again
                # for the flip alone; record_emergency_revoke raises the alarm.
                # SQLite rolls back by itself on SQLITE_FULL / IOERR / NOMEM, and
                # a ROLLBACK then raises "no transaction is active", which would
                # lose the emergency disable on exactly a damaged-storage chain.
                witness_failure = witness_exc
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    if witness_failure is not None:
        record_emergency_revoke(
            conn, kind="user", target_id=target_user_id,
            actor_user_id=actor_user_id, cli_principal=cli_principal,
            reason=emergency_reason, witness_exc=witness_failure,
        )
    return True


@db_write
def bump_session_epoch(conn: sqlite3.Connection, user_id: int) -> int:
    """Invalidate every outstanding session for ``user_id``.

    Increments ``users.session_epoch``; the user-loader
    (``dependencies.get_current_user``) rejects any session cookie
    stamped with an older epoch. Powers the "sign out all sessions"
    control; :func:`set_user_disabled` folds the same bump into its
    own transaction. Returns the new epoch.
    """
    conn.execute(
        "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    row = conn.execute(
        "SELECT session_epoch FROM users WHERE id = ?", (user_id,),
    ).fetchone()
    return int(row["session_epoch"]) if row is not None else 0


def list_user_status_events(
    conn: sqlite3.Connection,
    target_user_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    """List user-status events newest-first, optionally filtered by target."""
    if target_user_id is not None:
        rows = conn.execute(
            f"SELECT {USER_STATUS_EVENTS_COLUMNS} FROM user_status_events WHERE target_user_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (target_user_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {USER_STATUS_EVENTS_COLUMNS} FROM user_status_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# Auth events (PR 9 / D4 — credential-use audit trail)
# ---------------------------------------------------------------------------

def record_auth_event_txn(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    email: str,
    user_id: int | None = None,
    key_id: int | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    outcome: str = "success",
    detail: str | None = None,
) -> int:
    """TXN-AWARE chained auth_events emit — ``_chain_insert``, does NOT commit.

    N-520 — the ``*_txn`` sibling of :func:`record_auth_event`, following the
    in-tree :func:`record_hipaa_boundary_txn` / ``emit_clock_event_txn``
    convention. Use INSIDE the caller's open transaction when the row must be
    atomic with the state change it witnesses: the caller does its write(s)
    through their own ``*_txn`` siblings + this emit, then ONE commit (rollback
    on any error), so the state change and its tamper-evident audit row land or
    roll back TOGETHER. The caller owns commit/rollback; :func:`record_auth_event`
    is the own-commit standalone wrapper.

    THE ONE chain-writer for ``auth_events`` (PD#3/PD#5) — the own-commit
    wrapper delegates here, so the row shape has a single author.

    **UNDECORATED, and deliberately so** (``543-design.md`` M-2/M-3, both
    measured at the object):

    * **No ``@db_write``.** ``web/db_writelock.py:136-190`` rolls back
      unconditionally on any exception — ``conn.rollback()`` when
      ``conn.in_transaction``, then a defensive ``execute("ROLLBACK")``
      regardless. A decorated ``*_txn`` raising inside a caller-owned
      transaction would therefore roll back the *caller's* transaction,
      including work the caller did before calling it, and the caller's own
      ``except: conn.rollback()`` would become a no-op it cannot distinguish
      from success. The transaction boundary must stay the funnel's to own.
    * **No ``@audit_emitter``.** That decorator's whole body sets
      ``fn._is_audit_emitter = True`` (``:716-728``); the attribute is CONSUMED
      by ``db_write``'s wrapper (``web/db_writelock.py:224``) to write the
      ``audit_gap_events`` row. On a function with no ``@db_write`` outside it
      the marker is never read — a no-op that reads as coverage, which is worse
      than absent. The gap row must also be written OUTSIDE the funnel's
      transaction, or the funnel's own rollback would erase the only record
      that the pair failed.

    Returns the new row id.
    """
    return _chain_insert(conn, "auth_events", {
        "ts": now_utc_iso(),
        "event_type": event_type,
        "user_id": user_id,
        "email": email,
        "key_id": key_id,
        "ip": ip,
        "user_agent": user_agent,
        "outcome": outcome,
        "detail": detail,
    })


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_auth_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    email: str,
    user_id: int | None = None,
    key_id: int | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    outcome: str = "success",
    detail: str | None = None,
) -> int:
    """Append an auth_events row. Returns the new row id.

    PR 9 / D4. Captures every credential-use attempt (success or
    failure) for HIPAA-flavoured audit. Does NOT replace the
    last_used_at columns on dev_keys / hardware_keys (those drive
    the admin UI's "last used N min ago" display) -- this table
    is the historical source of truth.

    The function does not swallow exceptions; the caller decides
    whether an audit-write failure should poison the auth flow.
    Standard pattern: log at WARNING and proceed (auth succeeded;
    audit drift is a degraded condition, not a denial).

    OWN-COMMIT emitter — it commits, so it must NOT be used where the row has to
    be atomic with a coupled state write. That is N-520: a self-committing state
    write lands, then a fail-closed chain loses the witness for a change that is
    already durable. For that case use :func:`record_auth_event_txn` inside the
    caller's transaction (the shape :func:`record_system_hipaa_flip` uses).
    """
    #  — chained audit write (SSOT), via the txn-aware sibling so the row
    # shape has ONE author (PD#5). Own-commit wrapper: same shape as
    # ``record_hipaa_boundary`` over ``record_hipaa_boundary_txn``.
    row_id = record_auth_event_txn(
        conn,
        event_type=event_type,
        email=email,
        user_id=user_id,
        key_id=key_id,
        ip=ip,
        user_agent=user_agent,
        outcome=outcome,
        detail=detail,
    )
    conn.commit()
    return row_id


@db_write
@audit_emitter  # N-520 step 2 — gap-event when a paired witness fails
def record_witnessed_state_change(
    conn: sqlite3.Connection,
    *,
    operation: str,
    state_txn: Any,
    witness_txn: Any,
) -> Any:
    """Run ONE state change and the audit row that witnesses it in ONE transaction.

    N-520 (commit-before-witness). The caller hands two callables:

    * ``state_txn(conn) -> result``: the state write, through NON-committing
      ``*_txn`` siblings only. It must not commit.
    * ``witness_txn(conn, result)``: the witness, through a chain-writing
      ``*_txn`` emitter only (``record_auth_event_txn``,
      ``record_hipaa_access_event_txn``, ``record_access_event_txn``). It may
      return without writing when ``result`` says no state changed.

    Both land under ONE ``conn.commit()``. A raise in either rolls BOTH back and
    propagates (Directive 8, fail closed); ``@db_write`` holds the process write
    lock for the whole unit and writes the ``audit_gap_events`` row, so a lost
    witness takes its state change with it and leaves a durable record that the
    pair failed. Same shape as :func:`record_system_hipaa_flip` (N-466) and
    :func:`record_runtime_settings_change` (N-540).

    A ``state_txn`` that commits on its own would put the commit-before-witness
    defect back inside this funnel. The unit runs as ``BEGIN`` then
    ``SAVEPOINT`` then ``state_txn`` then ``RELEASE``: a commit anywhere inside
    ``state_txn`` (even one followed by more writes) destroys the savepoint, so
    the ``RELEASE`` fails and the funnel raises BEFORE the witness. The explicit
    ``BEGIN`` is load-bearing: without it the savepoint would be the outermost
    transaction and its ``RELEASE`` would COMMIT the state before the witness
    (db-sme s2 probe_savepoint2). The runtime refusal fires only after the
    stray commit is durable, so the STRUCTURAL guard is the N-520 pin's
    ``state_txn`` arm (``test_no_state_txn_reaches_a_self_committing_helper``),
    which resolves every call inside each caller's ``state_txn`` argument (a
    lambda body or the def it names) against the self-committing closure.

    Refused before any write: an autocommit connection, and a connection that
    is already inside a transaction (the funnel would otherwise commit or roll
    back another writer's half-done work as part of this unit).

    The settings cache is cleared UNCONDITIONALLY in ``finally`` on EVERY exit
    edge (commit, rollback, refusal), so the rule lives here and no caller can
    forget it: ``set_setting_txn`` requires the rollback-edge invalidation,
    without which a reader that cached the uncommitted (or pre-revoke) value
    serves it for the settings-cache TTL (s2 panel db N1-M1 / hipaa M-N4, DA
    final verdict; same rule as :func:`record_system_hipaa_flip`). The funnel
    does not know which keys ``state_txn`` touched, so it clears the whole
    cache (a 60 s TTL refill; every successful OTP, webauthn and passkey login runs through here, so the clear is per-login, a safe-direction cost: punch row filed for a keyed clear). Returns
    ``state_txn``'s result.
    """
    try:
        if conn.isolation_level is None:
            raise RuntimeError(
                f"{operation}: a witnessed state change requires a "
                "transaction-capable (non-autocommit) connection so the state "
                "write + its chained audit row are atomic; got isolation_level=None"
            )
        if conn.in_transaction:
            raise RuntimeError(
                f"{operation}: the connection already holds an open "
                "transaction; a witnessed state change must start clean so it "
                "never commits or rolls back another writer's pending work"
            )
        try:
            conn.execute("BEGIN")
            conn.execute("SAVEPOINT witnessed_state_change")
            result = state_txn(conn)
            try:
                conn.execute("RELEASE SAVEPOINT witnessed_state_change")
            except DB_OPERATIONAL_ERRORS as exc:
                # Both drivers (punch 560): sqlcipher3's OperationalError is
                # not a sqlite3 subclass, and prod runs sqlcipher.
                raise RuntimeError(
                    f"{operation}: state_txn committed its own write; the "
                    "witness would land after a durable state change (N-520). "
                    "Use the writer's *_txn sibling."
                ) from exc
            witness_txn(conn, result)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return result
    finally:
        # Guarded: a raise from HERE would replace the error already
        # propagating (and @audit_emitter's gap row would record the wrong
        # reason). Same shape as record_system_hipaa_flip's exit edge.
        try:
            from email_triage.web.db import invalidate_setting_cache
            invalidate_setting_cache()
        except Exception:
            from email_triage.triage_logging import get_logger
            get_logger("db.audit").error(
                "settings-cache invalidation failed on a witnessed-state-change "
                "exit edge; a cached setting may serve a superseded value "
                "until its TTL",
                operation=operation,
                exc_info=True,
            )


def record_user_offboard(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    account_ids: list[int],
    actor_user_id: int,
    reason: str,
) -> None:
    """Offboard a user: deactivate each account, then set the user's disabled flag.

    N-520 step 2 — the ONE offboard path for the admin API and the admin UI
    (both ``_offboard_user`` closures were identical copies). Each step is its
    own atomic witnessed unit, so no committed step lacks its row:

    * per account, ``set_account_active_txn(False)`` and an
      ``auth_events(event_type='account_deactivated')`` row in ONE transaction
      (:func:`record_witnessed_state_change`); a no-op deactivation writes no
      row;
    * then :func:`set_user_disabled`, which already writes the flip and its
      ``user_status_events`` row atomically.

    The actor's address is read from ``users`` by id before any write and a
    missing actor refuses (same rule as the delegate funnels). A failure on
    account N leaves accounts 1..N-1 deactivated WITH their rows and the user
    still enabled; the caller sees the raise and the admin can retry.
    """
    from email_triage.db.accounts import (
        invalidate_account_label_cache, set_account_active_txn,
    )
    actor_email = _actor_email_for(conn, actor_user_id, what="offboard actor")
    for acct_id in account_ids:
        def _witness(c, changed, _aid=int(acct_id), _email=actor_email,
                     _actor=actor_user_id, _uid=int(user_id)):
            if changed:
                record_auth_event_txn(
                    c, event_type="account_deactivated", email=_email,
                    user_id=_actor, outcome="success",
                    detail=f"account_id={_aid} offboard_user_id={_uid}",
                )
        if record_witnessed_state_change(
            conn, operation="account_deactivated",
            state_txn=lambda c, _aid=int(acct_id): set_account_active_txn(
                c, _aid, False,
            ),
            witness_txn=_witness,
        ):
            invalidate_account_label_cache(int(acct_id))
    set_user_disabled(
        conn, user_id, True, actor_user_id=actor_user_id, reason=reason,
    )


@db_write
@audit_emitter  # punch  — gap-event when the atomic grant's witness fails
def record_hardware_key_registration(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    transports: list[str] | None,
    aaguid: bytes | None,
    nickname: str,
    email: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> int:
    """GRANT a hardware key and witness it ATOMICALLY. Returns the new key id.

    Punch . Enrolment is an access-granting event (§164.312(b);
    §164.308(a)(4)); revocation already rode the chain (N-121) but enrolment
    only logged. The ``hardware_keys`` row and its
    ``auth_events(event_type='hardware_key_registered', outcome='success')``
    row go through their ``*_txn`` siblings inside ONE transaction, so a failed
    emit (``_chain_insert`` is fail-closed on an HMAC-key gap, Directive 12)
    rolls the key back too: no credential is ever granted without its witness
    (N-520 shape, same as :func:`record_system_hipaa_flip`). Fail CLOSED (PD#8):
    the enrolment is refused rather than landing unwitnessed.

    The REFUSED-enrolment row is not written here — it has no state change to
    be atomic with; the route writes it through :func:`record_auth_event`.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a hardware-key grant requires a transaction-capable "
            "(non-autocommit) connection so the hardware_keys insert + its "
            "chained auth_events witness are atomic; got isolation_level=None "
            "(autocommit)"
        )
    # Local import: keep db.audit free of a module-level db.users dependency
    # (same idiom as the flip funnel's local web.db import).
    from email_triage.db.users import add_hardware_key_txn
    try:
        new_id = add_hardware_key_txn(
            conn, user_id=user_id, credential_id=credential_id,
            public_key=public_key, sign_count=sign_count,
            transports=transports, aaguid=aaguid, nickname=nickname,
        )
        record_auth_event_txn(
            conn, event_type="hardware_key_registered",
            email=email, user_id=user_id, key_id=new_id,
            ip=ip, user_agent=user_agent, outcome="success",
        )
        conn.commit()
    except Exception:
        # ``conn.rollback()``: a no-op when no transaction is active, so a
        # failure before any DML cannot mask the original exception.
        conn.rollback()
        raise
    return new_id


class GrantRefused(str):
    """A grant the funnel refused AND witnessed (its denied row is written).
    Returned, never raised, so ``@audit_emitter`` records no audit gap for a
    refused business write (panel P F4). The value is the denied row's outcome."""

    @property
    def outcome(self) -> str:
        return str(self)

    def __bool__(self) -> bool:
        # Panel P G3: a refusal is never truthy, so an ``if new_id:`` caller
        # cannot read it as a granted id. Callers still test with isinstance
        # (pinned in tests/test_web/test_punch627_grant_refusal_edges.py).
        return False


DEV_KEY_DUPLICATE = GrantRefused("denied:duplicate_fingerprint")


@db_write
@audit_emitter  # punch 627 — gap-event when the atomic grant's witness fails
def record_dev_key_registration(
    conn: sqlite3.Connection,
    *,
    name: str,
    public_key: str,
    fingerprint: str,
    email_allowlist: list[str],
    created_by_user_id: int | None,
    expires_at: str,
    email: str,
    ip: str | None = None,
) -> "int | GrantRefused":
    """GRANT a dev key and witness it ATOMICALLY. Returns the new key id, or
    :data:`DEV_KEY_DUPLICATE` (a witnessed refusal).

    Punch 627 (register N-611). A dev-key registration is an access-granting
    event (§164.312(b); §164.308(a)(4)); its revoke already rode the chain
    (N-121) but the grant only logged. Same shape as
    :func:`record_hardware_key_registration`: the ``dev_keys`` row and its
    ``auth_events(event_type='dev_key_registered', outcome='success')`` row go
    through their ``*_txn`` siblings inside ONE transaction, so a failed emit
    rolls the key back too (fail CLOSED, PD#8). ``email``/``created_by_user_id``
    on the row are the granting admin, as on ``dev_key_revoked``.

    A duplicate fingerprint (the ``dev_keys.fingerprint`` UNIQUE, a racing
    grant of the same key past the route's pre-check) is a refused BUSINESS
    write, not a lost audit row (panel P F4): it rolls back, writes the
    ``outcome='denied:duplicate_fingerprint'`` row, and RETURNS
    :data:`DEV_KEY_DUPLICATE` instead of raising, so ``@audit_emitter`` writes no
    ``audit_gap_events`` row for it. A gap row means the witness failed: a raise
    here (the success witness, the denied witness, any other error) still gets
    one.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a dev-key grant requires a transaction-capable (non-autocommit) "
            "connection so the dev_keys insert + its chained auth_events "
            "witness are atomic; got isolation_level=None (autocommit)"
        )
    # Local import: keep db.audit free of a module-level db.users dependency
    # (same idiom as record_hardware_key_registration).
    from email_triage.db.users import add_dev_key_txn
    try:
        try:
            new_id = add_dev_key_txn(
                conn, name=name, public_key=public_key, fingerprint=fingerprint,
                email_allowlist=email_allowlist,
                created_by_user_id=created_by_user_id, expires_at=expires_at,
            )
        except DB_INTEGRITY_ERRORS as e:
            if "dev_keys.fingerprint" not in str(e):
                raise
            conn.rollback()
            record_auth_event_txn(
                conn, event_type="dev_key_registered",
                email=email, user_id=created_by_user_id,
                ip=ip, outcome=DEV_KEY_DUPLICATE.outcome, detail="admin grant",
            )
            conn.commit()
            return DEV_KEY_DUPLICATE
        record_auth_event_txn(
            conn, event_type="dev_key_registered",
            email=email, user_id=created_by_user_id, key_id=new_id,
            ip=ip, outcome="success", detail="admin grant",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return new_id


USER_DUPLICATE = GrantRefused("denied:duplicate_email")


@db_write
@audit_emitter  # punch 668 -- gap-event when the atomic user grant's witness fails
def record_user_creation(
    conn: sqlite3.Connection,
    *,
    email: str,
    name: str,
    role: str,
    notify_email: str | None = None,
    actor_user_id: int | None,
    actor_email: str,
    ip: str | None = None,
    source: str = "unknown",
) -> "int | GrantRefused":
    """CREATE a user and witness it ATOMICALLY. Returns the new user id, or
    :data:`USER_DUPLICATE` (a witnessed refusal).

    Punch 668 (register N-611 class). Creating a user is the root access grant
    (§164.312(b); §164.308(a)(4)): the ``users`` row and its
    ``auth_events(event_type='user_created', outcome='success')`` row go through
    ONE transaction (``record_auth_event_txn``, the N-520 shape), so a failed
    witness rolls the user back too (fail CLOSED, PD#8). The one writer for the
    API route, the UI route and the CLI, so there is no second INSERT to drift.

    Column mapping (punch 668; one convention for all three grant events):
    ``email`` is the ACTOR (the requesting admin; the resolved CLI principal for
    the CLI), ``user_id`` is the SUBJECT, the NEW user's id (indexed, so a
    per-user trail shows the grant), and ``detail`` carries only the bounded
    ``role`` / ``source`` and the typed ``actor_user_id``. The new user's address
    and name are never in the event. (``dev_key_registered`` puts the admin in
    ``user_id`` because its subject is a key, not a user.)

    A duplicate address (the ``users.email`` UNIQUE, the one duplicate
    detector: no caller pre-checks) is a refused BUSINESS write, not a lost
    audit row (as dev keys, panel P F4): it rolls back, writes the
    ``denied:duplicate_email`` row, and RETURNS
    :data:`USER_DUPLICATE`, so ``@audit_emitter`` writes no ``audit_gap_events``
    row for it. A raise here (the witness, any other error) still gets one.

    A blank or non-str ``actor_email`` is refused BEFORE the INSERT
    (``ValueError``, which also leaves a gap row): the witness's ``email`` is the
    ACTOR, and an unattributed root grant must never look like a complete record.
    """
    if not isinstance(actor_email, str) or not actor_email.strip():
        raise ValueError(
            "record_user_creation requires a non-blank actor_email: the grant "
            "witness records WHO created the user"
        )
    if conn.isolation_level is None:
        raise RuntimeError(
            "a user grant requires a transaction-capable (non-autocommit) "
            "connection so the users insert + its chained auth_events "
            "witness are atomic; got isolation_level=None (autocommit)"
        )
    detail = f"role={role} source={source} actor_user_id={actor_user_id}"
    try:
        try:
            cursor = conn.execute(
                "INSERT INTO users (email, name, role, notify_email, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (email, name, role, notify_email, now_utc_iso()),
            )
        except DB_INTEGRITY_ERRORS as e:
            if "users.email" not in str(e):
                raise
            conn.rollback()
            record_auth_event_txn(
                conn, event_type="user_created", email=actor_email,
                ip=ip, outcome=USER_DUPLICATE.outcome, detail=detail,
            )
            conn.commit()
            return USER_DUPLICATE
        new_id = cursor.lastrowid
        record_auth_event_txn(
            conn, event_type="user_created", email=actor_email, user_id=new_id,
            ip=ip, outcome="success", detail=detail,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return new_id


@db_write
@audit_emitter  # punch 674 -- gap-event when an atomic role / email change's witness fails
def record_user_update(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    name: str | None = None,
    role: str | None = None,
    email: str | None = None,
    notify_email: str | None = None,
    actor_user_id: int | None,
    actor_email: str,
    ip: str | None = None,
    source: str = "unknown",
    _in_caller_txn: bool = False,
) -> bool:
    """UPDATE an existing user's admin-editable fields; a ROLE or login-EMAIL
    change commits with its chained witness ATOMICALLY. Returns ``False`` when
    no such user.

    Punch 674. Raising (or lowering) a user's role is access modification
    (§164.308(a)(4)(ii)(C), §164.312(b)). The ``UPDATE users SET role`` and its
    ``auth_events(event_type='user_role_changed', outcome='success')`` row go
    through ONE transaction (``record_auth_event_txn``), so a failed witness
    rolls the whole update back (fail CLOSED, PD#8). The one writer for the API
    PATCH, the UI form and the ``user re-normalize-emails`` CLI sweep. ``None``
    leaves a field unchanged; ``notify_email=""`` clears it.

    The login EMAIL is a credential (hipaa-sme ruling, panel Z MUST-Z1-1): OTP
    codes are sent to ``users.email``, so changing it re-binds the login factor,
    the email-OTP equivalent of a password change (§164.308(a)(5)(ii)(D),
    §164.312(d)). Its ``UPDATE`` writes ``user_email_changed`` in the same
    transaction, the same way as the role.

    Each witness is written only when the stored value CHANGES (an unchanged
    value is no grant: the ``set_user_disabled`` no-op rule). Column mapping (the
    668 convention): ``email`` is the ACTOR, ``user_id`` is the SUBJECT, and
    ``detail`` carries the old/new value, ``source`` and the typed
    ``actor_user_id``. For the email arm the old and new ADDRESSES are stored in
    plain text (``repr``-quoted): a hash cannot answer where the factor was
    re-pointed (DA NOTE-Z1-5). They are workforce identifiers, not PHI, in the
    encrypted, HMAC-chained store; the gap-row redaction map below still keeps
    them out of ``audit_gap_events``.

    The current role and email are read INSIDE the write transaction
    (``BEGIN IMMEDIATE``, the ``db/accounts.py`` read-modify-write pattern), so
    a second process (the CLI sweep) cannot make ``old_*`` stale (db NOTE-Z1-4).

    A caller that already holds a transaction (punch 696, the ``db/accounts.py``
    N-342 rule) owns it on every edge: this funnel issues no BEGIN, COMMIT or
    ROLLBACK of its own, so the update and its witness commit with the caller's
    writes. The caller then holds the write lock that NOTE-Z1-4 relies on. On a
    raise, ``@db_write`` rolls the caller's whole transaction back before it
    writes the gap row, so a nested failure loses the caller's earlier writes
    too; it never commits them. The caller DECLARES that nesting with
    ``_in_caller_txn=True`` (punch 708): an open transaction nobody declared is
    a leak, and this funnel refuses it before any write instead of leaving the
    update and its witness uncommitted in it.

    ``session_epoch``: bumped whenever a role or email is SUBMITTED (N-238 /
    N-250, the behaviour both callers had), and in the same statement as any
    role/email write (the N-238 pin).

    A blank actor, a non-autocommit connection or a role outside ``UserRole``
    is refused BEFORE any write (``ValueError`` / ``RuntimeError``, which also
    leave a gap row).
    """
    from email_triage.engine.models import UserRole  # local: keep db.audit light

    if not isinstance(actor_email, str) or not actor_email.strip():
        raise ValueError(
            "record_user_update requires a non-blank actor_email: the role "
            "witness records WHO changed it"
        )
    if conn.isolation_level is None:
        raise RuntimeError(
            "a user update requires a transaction-capable (non-autocommit) "
            "connection so a role change + its chained auth_events witness are "
            "atomic; got isolation_level=None (autocommit)"
        )
    if role is not None and role not in {r.value for r in UserRole}:
        raise ValueError(f"invalid role: {role!r}")
    # db NOTE-Z1-4: take the write lock BEFORE reading the old values; a caller
    # that already holds a transaction owns the lock (db/accounts.py N-342).
    nested = bool(getattr(conn, "in_transaction", False))
    refuse_undeclared_nesting(nested, _in_caller_txn, what="record_user_update")
    if not nested:
        conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT role, email FROM users WHERE id = ?", (user_id,),
        ).fetchone()
        if row is None:
            if not nested:
                conn.rollback()  # end the read transaction
            return False
        bumped = False
        if role is not None and role != row["role"]:
            conn.execute(
                "UPDATE users SET role = ?, session_epoch = session_epoch + 1 "
                "WHERE id = ?",
                (role, user_id),
            )
            record_auth_event_txn(
                conn, event_type="user_role_changed", email=actor_email,
                user_id=user_id, ip=ip, outcome="success",
                detail=(f"old_role={row['role']} new_role={role} "
                        f"source={source} actor_user_id={actor_user_id}"),
            )
            bumped = True
        if email is not None and email != row["email"]:
            conn.execute(
                "UPDATE users SET email = ?, session_epoch = session_epoch + 1 "
                "WHERE id = ?",
                (email, user_id),
            )
            record_auth_event_txn(
                conn, event_type="user_email_changed", email=actor_email,
                user_id=user_id, ip=ip, outcome="success",
                detail=(f"old_email={row['email']!r} new_email={email!r} "
                        f"source={source} actor_user_id={actor_user_id}"),
            )
            bumped = True
        if name is not None:
            conn.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
        if notify_email is not None:
            conn.execute(
                "UPDATE users SET notify_email = ? WHERE id = ?",
                (notify_email or None, user_id),
            )
        if (role is not None or email is not None) and not bumped:
            conn.execute(
                "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?",
                (user_id,),
            )
        # Punch 696: a caller-held transaction is the caller's to commit or roll
        # back (the N-342 rule), on every edge: the update and its witness then
        # commit with the caller's other writes, or not at all.
        if not nested:
            conn.commit()
    except Exception:
        if not nested:
            conn.rollback()
        raise
    return True


DELEGATE_ACCOUNT_MISSING = GrantRefused("denied:account_not_found")
DELEGATE_IS_OWNER = GrantRefused("denied:owner_is_delegate")


def _actor_email_for(conn: sqlite3.Connection, actor_user_id: int | None, *, what: str) -> str:
    """The acting user's address, read from ``users`` by id (punch 673).

    The witness's ``email`` column is the ACTOR (the 668 convention). Taking it
    from the row the id names, not from a caller string, leaves one source for
    the attribution. An id that names no user, or none at all, refuses BEFORE
    any write (``ValueError``): an unattributed access grant or revocation must
    never look like a complete record."""
    row = None
    if actor_user_id is not None:
        row = conn.execute(
            "SELECT email FROM users WHERE id = ?", (actor_user_id,),
        ).fetchone()
    email = (row["email"] if row is not None else None) or ""
    if not email.strip():
        raise ValueError(
            f"an account-delegate {what} requires an existing acting user "
            f"(got {what}={actor_user_id!r}): the witness records WHO acted"
        )
    return email


@db_write
@audit_emitter  # punch 673 -- gap-event when the atomic delegate grant's witness fails
def record_account_delegate_grant(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    user_id: int,
    granted_by: int | None,
    ip: str | None = None,
) -> "bool | GrantRefused":
    """GRANT a user delegate access to an account and witness it ATOMICALLY.

    Punch 673. A delegation lets ``user_id`` act on another user's mailbox (routes,
    watcher, digests, run-triage), so it is an access grant (§164.308(a)(4),
    §164.312(b)). The ``account_delegates`` row and its
    ``auth_events(event_type='account_delegate_granted', outcome='success')`` row
    commit in ONE transaction (``record_auth_event_txn``, the N-520 shape): a
    failed witness rolls the grant back (fail CLOSED, PD#8).

    Column mapping (the 668 convention): ``email`` is the ACTOR (read from
    ``users`` by ``granted_by``), ``user_id`` is the SUBJECT (the delegate), and
    ``detail`` carries only the typed ``account_id`` and ``actor_user_id``.

    Returns ``True`` for a new grant and ``False`` when the row already exists
    (no state change, so no row: the ``set_user_disabled`` no-op rule). A grant
    the funnel refuses (no such account, or the owner named as their own
    delegate) is a refused BUSINESS write: it writes its ``denied:<slug>`` row
    and RETURNS the :class:`GrantRefused`, so ``@audit_emitter`` records no audit
    gap for it. A missing actor raises before any write.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "an account-delegate grant requires a transaction-capable "
            "(non-autocommit) connection so the account_delegates insert + its "
            "chained auth_events witness are atomic; got isolation_level=None"
        )
    actor_email = _actor_email_for(conn, granted_by, what="granted_by")
    detail = f"account_id={int(account_id)} actor_user_id={int(granted_by)}"
    try:
        owner = conn.execute(
            "SELECT user_id FROM email_accounts WHERE id = ?", (account_id,),
        ).fetchone()
        refused = (
            DELEGATE_ACCOUNT_MISSING if owner is None
            else DELEGATE_IS_OWNER if owner["user_id"] == user_id
            else None
        )
        if refused is not None:
            record_auth_event_txn(
                conn, event_type="account_delegate_granted", email=actor_email,
                user_id=user_id, ip=ip, outcome=refused.outcome, detail=detail,
            )
            conn.commit()
            return refused
        cur = conn.execute(
            "INSERT OR IGNORE INTO account_delegates "
            "(account_id, user_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
            (account_id, user_id, granted_by, now_utc_iso()),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False
        record_auth_event_txn(
            conn, event_type="account_delegate_granted", email=actor_email,
            user_id=user_id, ip=ip, outcome="success", detail=detail,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


@db_write
@audit_emitter  # punch 673 -- gap-event when the atomic delegate revoke's witness fails
def record_account_delegate_revoke(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    user_id: int,
    revoked_by: int | None,
    ip: str | None = None,
) -> bool:
    """REVOKE a user's delegate access and witness it ATOMICALLY.

    Punch 673, the termination edge of :func:`record_account_delegate_grant`
    (§164.308(a)(4)(ii)(C) access modification, §164.312(b)): the DELETE and its
    ``auth_events(event_type='account_delegate_revoked')`` row commit together,
    and a failed witness rolls the revocation back and raises. Same column
    mapping as the grant. Returns ``True`` when a row was removed and ``False``
    when there was none (no state change, no row). A missing actor raises before
    any write.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "an account-delegate revoke requires a transaction-capable "
            "(non-autocommit) connection so the account_delegates delete + its "
            "chained auth_events witness are atomic; got isolation_level=None"
        )
    actor_email = _actor_email_for(conn, revoked_by, what="revoked_by")
    detail = f"account_id={int(account_id)} actor_user_id={int(revoked_by)}"
    try:
        cur = conn.execute(
            "DELETE FROM account_delegates WHERE account_id = ? AND user_id = ?",
            (account_id, user_id),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False
        record_auth_event_txn(
            conn, event_type="account_delegate_revoked", email=actor_email,
            user_id=user_id, ip=ip, outcome="success", detail=detail,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def list_auth_events(
    conn: sqlite3.Connection,
    *,
    limit: int = 100,
    user_id: int | None = None,
    event_type: str | None = None,
) -> list[dict]:
    """Return recent auth_events rows newest-first."""
    where: list[str] = []
    params: list = []
    if user_id is not None:
        where.append("user_id = ?")
        params.append(user_id)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    sql = f"SELECT {AUTH_EVENTS_COLUMNS} FROM auth_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# HIPAA boundary event helpers
# ---------------------------------------------------------------------------

def record_hipaa_boundary_txn(
    conn: sqlite3.Connection,
    scope: str,
    direction: str,
    actor_id: int | None = None,
    reason: str = "",
    *,
    ts: str | None = None,
) -> int:
    """TXN-AWARE chained boundary emit — ``_chain_insert``, does NOT commit.

    N-466 — the `*_txn` sibling of :func:`record_hipaa_boundary`, following the
    in-tree ``emit_clock_event_txn`` convention. Use INSIDE the caller's open
    transaction when the event must be atomic with the state mutation it
    witnesses: the caller does its write(s) + this emit, then ONE commit
    (rollback on any error), so the posture flip and its tamper-evident audit
    row land or roll back TOGETHER. The caller owns commit/rollback;
    ``record_hipaa_boundary`` is the own-commit standalone wrapper.

    THE ONE chain-writer for ``hipaa_boundary_events`` (PD#3/PD#5): the
    own-commit wrapper, the system-flip funnel
    (:func:`record_system_hipaa_flip`) and the per-account flip
    (``db/accounts.set_account_hipaa``) all route through here, so there is a
    single place the row shape is authored. ``direction`` is ``"on"`` /
    ``"off"`` for a flip, or ``"cascade"`` for the N-262 R26 derived-state
    force-off trail. Returns the new row id.

    ``ts`` is keyword-only and defaults to now. Pass it when SEVERAL rows of one
    transaction must share a timestamp: ``set_account_hipaa`` writes an
    ``"on"`` row plus a ``"cascade"`` row and both must carry the SAME ``ts``,
    because ``latest_hipaa_boundary`` (``ORDER BY ts DESC LIMIT 1``) and
    ``latest_hipaa_boundaries_for_accounts`` (``ts = MAX(ts)``, "duplicate-tick
    collisions keep the first") would otherwise report the account's latest
    boundary direction as ``"cascade"`` rather than the flip itself. Keyword-only
    so :func:`record_hipaa_boundary`'s positional signature — and with it the
    ``_bind_args_to_emitter_signature`` key list — is unchanged.
    """
    return _chain_insert(conn, "hipaa_boundary_events", {
        "ts": ts or now_utc_iso(),
        "scope": scope,
        "direction": direction,
        "actor_id": actor_id,
        "reason": reason,
    })


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_hipaa_boundary(
    conn: sqlite3.Connection,
    scope: str,
    direction: str,
    actor_id: int | None = None,
    reason: str = "",
) -> int:
    """Record a HIPAA mode-change event. Returns the new row id.

    ``scope`` is either the literal string ``"system"`` for the global
    flag, or ``"account:{id}"`` for a per-account flip.  ``direction``
    is ``"on"`` or ``"off"``.  The row is how the log viewer renders
    "before this point PHI may be present / after this point it is
    scrubbed" dividers.

    OWN-COMMIT emitter — it commits, so it must NOT be used where the row has
    to be atomic with a coupled state write (that was N-466: the settings row
    committed at its own call, then a fail-closed chain lost the witness). For
    that case use :func:`record_hipaa_boundary_txn` inside the caller's
    transaction, or the :func:`record_system_hipaa_flip` funnel.
    """
    #  — chained audit write (SSOT), via the txn-aware sibling so the row
    # shape has ONE author (PD#5). Own-commit wrapper: same shape as
    # ``record_clock_event`` over ``emit_clock_event_txn``.
    row_id = record_hipaa_boundary_txn(conn, scope, direction, actor_id, reason)
    conn.commit()
    return row_id


@db_write
@audit_emitter  # N-466 — gap-event when the atomic flip's boundary emit fails
def record_system_hipaa_flip(
    conn: sqlite3.Connection,
    *,
    settings_key: str,
    new_runtime: dict,
    direction: str | None,
    actor_id: int | None = None,
    reason: str = "",
) -> int | None:
    """Persist a ``runtime_settings`` change and (on a flip) its system
    HIPAA boundary event ATOMICALLY. Returns the boundary row id, or None
    when ``direction`` is None (no flip — settings-only save).

    N-466. The defect this closes: ``admin_security_save`` wrote the settings
    row through the own-commit ``set_setting`` and only THEN emitted the
    boundary event through the own-commit ``record_hipaa_boundary``. Because
    ``_chain_insert`` is fail-closed BY DESIGN on an HMAC-key gap
    (Directive 12), a rotation window (version set, key absent) made the
    safeguard-disabling settings row durable with ZERO durable witness —
    ``/admin/security/save`` is in no ``_PHI_ROUTE_PREFIXES``, so
    ``hipaa_boundary_events`` is the SOLE witness for this route.
    §164.308(a)(1)(ii)(B)+(D), §164.312(b).

    Fix shape — NOT a reorder (a reorder just moves which half is orphaned):
    both writes go through their ``*_txn`` siblings inside ONE transaction, so
    a failed emit rolls the settings row back too. The caller applies the
    in-process flag only AFTER this returns, so a rollback leaves the DB row,
    the live ``triage_logging._hipaa_mode`` flag and the settings cache all
    agreeing on the PRE-save posture — fail CLOSED (PD#8).

    PRECONDITION, non-negotiable: ``invalidate_setting_cache`` runs in the
    ``finally``, i.e. on EVERY exit edge — commit AND rollback. Without the
    rollback edge a racing reader on the shared connection that sees the
    uncommitted row (SQLite serialized mode guards individual calls, NOT
    transactions) caches it for the 60s TTL, so ``_get_runtime_settings`` is
    served a ``hipaa: False`` value for a row that does not exist and never
    reaches the N-464 row-absent branch. Measured 2026-09-12; the reader is
    the ingestion hot path via ``_is_dry_run`` (background_sweepers /
    poll_ingestion / ingestion_push / triage_classify), so it is a running
    poller overlapping an admin save, not an admin-vs-admin collision.

    WHAT THIS ``finally:`` DOES AND DOES NOT BUY — corrected 2026-09-25 after
    db-sme F1 / hipaa-sme 422-F3, because the earlier wording here ("without
    the rollback edge the conversion REOPENS N-464") read as though WITH the
    edge it were closed. It closes the post-rollback read. It does NOT close a
    reader whose SELECT-to-populate gap STRADDLES the invalidation, because
    ``get_setting`` populates outside the lock it read the cache under, and an
    invalidation is a ``pop`` that cannot stop a populate already in flight.
    That residual is N-513, closed separately by the ``_settings_cache_epoch``
    generation counter in ``web/db.py`` — this ``finally:`` alone NARROWS the
    window, it does not close it.

    Atomicity requires a deferred (non-autocommit) connection — on an
    autocommit handle each statement commits immediately and there is no
    rollback path. Fail CLOSED rather than silently lose atomicity (same
    guard, same reasoning as ``db/regulatory_clock._clock_txn``).
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a system HIPAA flip requires a transaction-capable "
            "(non-autocommit) connection so the runtime_settings write + its "
            "chained boundary event are atomic; got isolation_level=None "
            "(autocommit)"
        )
    # Local imports: web.db imports this module at module scope, so a
    # module-level import here would be a cycle (same idiom as
    # db/accounts.set_account_hipaa importing _chain_insert locally).
    from email_triage.web.db import invalidate_setting_cache, set_setting_txn
    row_id: int | None = None
    try:
        set_setting_txn(conn, settings_key, new_runtime)
        if direction is not None:
            row_id = record_hipaa_boundary_txn(
                conn, "system", direction, actor_id=actor_id, reason=reason,
            )
        conn.commit()
    except Exception:
        # ``conn.rollback()`` and not ``execute("ROLLBACK")``: a no-op when no
        # transaction is active, so a failure BEFORE any DML cannot mask the
        # original exception with "cannot rollback - no transaction is active".
        conn.rollback()
        raise
    finally:
        # EVERY exit edge — see the PRECONDITION above. ``set_setting_txn``
        # already invalidated on the write; this is the edge that matters,
        # because on rollback there is no commit and an after-COMMIT
        # invalidation would never run.
        #
        # db-sme F2: guarded because a raise from HERE would REPLACE the
        # audit-emit failure that is propagating, and ``@audit_emitter``'s
        # gap-event row would then record the wrong reason for the gap. The
        # rollback has already happened, so swallowing costs the diagnosis of
        # a cache-invalidation failure, not the control.
        try:
            invalidate_setting_cache(settings_key)
        except Exception:
            # ``get_logger`` locally, matching this module's idiom (audit.py
            # has no module-level logger). ONE positional + kwargs only —
            # PD#10: a positional 2nd arg binds to ``exc_info``.
            from email_triage.triage_logging import get_logger
            get_logger("db.audit").error(
                "settings-cache invalidation failed on the HIPAA-flip exit "
                "edge; the cache may serve a superseded value until its TTL",
                exc_info=True,
            )
    return row_id


def runtime_settings_changed_keys(prev: dict | None, new: dict) -> list[str]:
    """Sorted NAMES of the keys whose value differs between ``prev`` and ``new``.

    N-540. A key present on one side only counts as changed. ``prev is None``
    (no stored row yet) makes every key of ``new`` changed, so a first save is
    witnessed rather than skipped. Names only, never values: a value could
    carry operator free text (hipaa-sme, N-540 ruling).
    """
    if prev is None:
        return sorted(new)
    return sorted(
        k for k in set(prev) | set(new)
        if k not in prev or k not in new or prev[k] != new[k]
    )


@db_write
@audit_emitter  # N-540 — gap-event when the runtime-settings witness fails
def record_runtime_settings_change(
    conn: sqlite3.Connection,
    *,
    settings_key: str,
    new_runtime: dict,
    actor_user_id: int | None,
    actor_email: str,
) -> int | None:
    """Persist a ``runtime_settings`` blob and its ``runtime_settings_changed``
    auth event ATOMICALLY. Returns the auth-event row id, or None when the
    blob did not change (the write still runs; nothing new to witness).

    N-540 (punch 545). ``config_save`` own-committed this blob, which carries
    ``dry_run``, ``log_level`` and the bulk-triage knobs, through
    ``set_setting`` with no audit row on any path; the only row in that
    handler (``classifier_config_changed``) witnesses a different operation
    and stays its own event. The witness is UNCONDITIONAL on a changed blob,
    with no posture-bearing-key allow-list (hipaa-sme: an allow-list fails
    silently as the blob widens), and ``detail`` carries the changed key NAMES
    only, never values.

    Same shape as :func:`record_system_hipaa_flip`: the settings row and the
    chained row go through their ``*_txn`` siblings inside ONE transaction,
    so a fail-closed chain (Directive 12) rolls the settings row back too and
    the caller's in-process apply, which runs only after this returns, never
    runs ahead of a durable row. Autocommit is refused, and
    ``invalidate_setting_cache`` runs on every exit edge, for the reasons set
    out on that function.

    The previous blob is read from a cold cache entry under the process-wide
    write lock (``@db_write`` here, ``get_write_lock()`` in ``config_save``),
    so the diff is against the row this write replaces, not a cached copy. The
    LOCK is the guarantee, not the transaction: under legacy transaction
    control the implicit BEGIN comes at the first DML, after the read. A writer
    of this key outside the process lock could change a key between the read
    and the write without it being named in ``changed_keys``; none exists today
    (fail-OPEN on witness detail only; the blob write is still witnessed).
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a runtime-settings save requires a transaction-capable "
            "(non-autocommit) connection so the runtime_settings write + its "
            "chained auth event are atomic; got isolation_level=None "
            "(autocommit)"
        )
    import json as _json
    # Local imports: web.db imports this module at module scope (same idiom as
    # record_system_hipaa_flip).
    from email_triage.web.db import (
        get_setting, invalidate_setting_cache, set_setting_txn,
    )
    row_id: int | None = None
    try:
        invalidate_setting_cache(settings_key)
        changed = runtime_settings_changed_keys(
            get_setting(conn, settings_key), new_runtime,
        )
        set_setting_txn(conn, settings_key, new_runtime)
        if changed:
            row_id = record_auth_event_txn(
                conn,
                event_type="runtime_settings_changed",
                email=actor_email,
                user_id=actor_user_id,
                outcome="success",
                detail=_json.dumps(
                    {"settings_key": settings_key, "changed_keys": changed},
                    sort_keys=True,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        # Guarded for the same reason as record_system_hipaa_flip (db-sme F2):
        # a raise here would replace the propagating emit failure.
        try:
            invalidate_setting_cache(settings_key)
        except Exception:
            from email_triage.triage_logging import get_logger
            get_logger("db.audit").error(
                "settings-cache invalidation failed on the runtime-settings "
                "exit edge; the cache may serve a superseded value until its "
                "TTL",
                exc_info=True,
            )
    return row_id


def _watch_group_audit_key(group_id: str) -> str:
    """The group key as it may enter ``access_log``. A ``gid:<uuid>`` key is
    kept. A legacy key is ``legacy:<creator>:<watch name>`` (or
    ``legacy:none:<watch_id>``); the name is an operator free-text label that
    can carry a patient name, and every ``access_log`` column is chain-hashed
    and retained, so only ``legacy:<creator id>`` is recorded (hipaa-sme panel
    B2 F2; PD#5: one place for all three watch routes)."""
    if group_id.startswith("legacy:"):
        return "legacy:" + group_id.split(":", 2)[1]
    return group_id


def _audit_watch_save_non_owner(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int,
    group_id: str,
    target_account_ids: list[int],
    unbound_account_ids: list[int],
    route: str,
    outcome: str = "watch_save",
) -> None:
    """One ``access_log`` row per NON-OWNER HIPAA account a watch-group write
    touched — does NOT commit (N-539, PD#14).

    The ONE implementation of the loop both watch-save routes used to own
    (only ``save_new`` had it). The gate is actor≠owner (``is_account_owner``)
    AND ``account_hipaa_effective(account=acct)`` — with no message in scope
    that is the system flag OR the account flag, the same fold the route's
    ``is_account_hipaa`` computed (N-266 names it the SSOT). An account whose row
    the save DELETED (an unbind on edit) is witnessed too, with
    ``"unbound": true`` in ``detail``; ``save_new`` has no unbound accounts,
    so its rows keep their exact pre-N-539 shape. ``outcome`` is
    ``"watch_save"`` for both save routes and ``"watch_delete"`` for
    :func:`record_watch_group_delete`.
    """
    import json as _json
    from email_triage.db.accounts import get_email_account
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.account_scope import is_account_owner

    audit_group_id = _watch_group_audit_key(group_id)
    touched = [(a, False) for a in target_account_ids]
    touched += [(a, True) for a in unbound_account_ids]
    for acct_id, unbound in touched:
        acct = get_email_account(conn, acct_id)
        if acct is None:
            continue
        if (is_account_owner(acct, actor_user_id)
                or not account_hipaa_effective(account=acct)):
            continue
        detail: dict = {"group_id": audit_group_id}
        if unbound:
            detail["unbound"] = True
        record_access_event_txn(
            conn,
            actor_user_id=actor_user_id,
            method="POST",
            route=route,
            account_id=acct_id,
            message_id=None,
            status_code=200,
            outcome=outcome,
            detail=_json.dumps(detail, separators=(",", ":")),
        )


@db_write
@audit_emitter  # N-539 — gap-event when a watch-save access witness fails
def record_watch_group_save(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int,
    group_id: str | None,
    name: str,
    enabled: bool,
    filter_: Any,
    actions: Any,
    target_account_ids: list[int],
    route: str,
) -> tuple[str, list[str], list[str]]:
    """Save a watch group and its non-owner access-event rows ATOMICALLY.
    Returns ``(group_id_final, created_watch_ids, deleted_watch_ids)``.

    N-539 (punch 544) and the N-520 family-10 member. ``save_new`` committed
    the watch rows and THEN emitted its ``access_log`` rows (late witness);
    ``save_existing`` emitted none (no witness). Both routes now call this:
    the watch rows go through ``save_watch_group_txn`` and the rows through
    :func:`_audit_watch_save_non_owner` inside ONE transaction, so a
    fail-closed chain (Directive 12) rolls the watch save back with it.
    Autocommit is refused for the reason set out on
    :func:`record_system_hipaa_flip`.

    Caller-side invariant (``save_watch_group_txn``): ``target_account_ids``
    must already be intersected with the actor's manageable set and stripped
    of non-owner HIPAA accounts; this funnel witnesses what it is given and
    does not re-check access (PD#9 is the route's, ``_profile_watches_collect_
    target_ids``). If a caller skips that, audit still fails closed (the row is
    written) while access fails open (the bind goes through).
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a watch-group save requires a transaction-capable "
            "(non-autocommit) connection so the watch rows + their chained "
            "access events are atomic; got isolation_level=None (autocommit)"
        )
    # Local import: web.email_watches is a web-layer module (same idiom as
    # record_system_hipaa_flip importing web.db).
    from email_triage.web.email_watches import save_watch_group_txn
    try:
        group_id_final, created, deleted, unbound = save_watch_group_txn(
            conn,
            user_id=actor_user_id,
            group_id=group_id,
            name=name,
            enabled=enabled,
            filter_=filter_,
            actions=actions,
            target_account_ids=target_account_ids,
        )
        _audit_watch_save_non_owner(
            conn,
            actor_user_id=actor_user_id,
            group_id=group_id_final,
            target_account_ids=target_account_ids,
            unbound_account_ids=unbound,
            route=route,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return group_id_final, created, deleted


@db_write
@audit_emitter  # N-539 — gap-event when a watch-delete access witness fails
def record_watch_group_delete(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int,
    group: dict,
    route: str,
) -> int:
    """Delete every row of a watch group and witness each non-owner HIPAA
    account it covered ATOMICALLY. Returns the number of rows deleted.

    N-539's third watch-group write path: ``profile_watches_delete`` removed
    the rows through the own-commit ``delete_watch`` with no access-event row,
    the same no-witness shape as the edit path. Same funnel shape as
    :func:`record_watch_group_save`.

    ``group`` is the caller's ALREADY-RESOLVED, actor-scoped group: the result
    of ``get_watch_group(conn, group_id, actor_user_id)`` in the caller's own
    hop, which answers 404 on ``None`` (allow-list step 2, B4; s2 panel
    conditions (a)-(c)). This funnel deletes only ``group["watch_ids"]`` and
    must NOT resolve the group again: a second lookup here would make the
    caller's gate a result-ignored, decorative reference. The f5 pin
    (``test_f5_watch_writer_scope_pin.py``) holds both halves.
    """
    if conn.isolation_level is None:
        raise RuntimeError(
            "a watch-group delete requires a transaction-capable "
            "(non-autocommit) connection so the row deletes + their chained "
            "access events are atomic; got isolation_level=None (autocommit)"
        )
    from email_triage.web.email_watches import delete_watch_txn, get_watch
    try:
        count = 0
        unbound: list[int] = []
        for wid in group["watch_ids"]:
            w = get_watch(conn, wid)
            if delete_watch_txn(conn, wid):
                count += 1
                if w is not None and w.account_id is not None:
                    unbound.append(int(w.account_id))
        _audit_watch_save_non_owner(
            conn,
            actor_user_id=actor_user_id,
            group_id=group["group_id"],
            target_account_ids=[],
            unbound_account_ids=unbound,
            route=route,
            outcome="watch_delete",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return count


_WEBHOOK_PREVIEW_ROUTE = "/admin/integrations/webhook-preview"


@db_write
@audit_emitter  # punch 414 — gap-event when the live-render witness fails
def record_webhook_preview_live_render(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int,
    account_id: int | None,
    envelope_flow_id: str | None,
) -> int:
    """Witness one live-mode render of the outbound-webhook wizard preview.

    Punch 414, §164.312(b): "My last real event" shows an admin the last
    envelope a target fired, so each render is a PHI-adjacent read. One chained
    ``access_log`` row per render, ``outcome="webhook_preview_live_render"``
    (the event class rides ``outcome`` as ``"watch_delete"`` does), through
    :func:`record_access_event_txn` so the row shape keeps one author. No new
    table. ``account_id`` is the envelope's account when it carries one, else
    ``None`` (a wildcard target). The canned mode never calls this: only the
    live path is PHI-adjacent. ``envelope_flow_id`` is an opaque id, ``None``
    when the event has no ``flow_id`` (``triage.completed`` carries a run id).

    The caller treats a raise as a refusal and falls back to the canned render
    (PD#8: no witness, no live view). OWN-COMMIT, with no coupled state write.
    """
    import json as _json

    row_id = record_access_event_txn(
        conn,
        actor_user_id=actor_user_id,
        method="POST",
        route=_WEBHOOK_PREVIEW_ROUTE,
        account_id=account_id,
        message_id=None,
        status_code=200,
        outcome="webhook_preview_live_render",
        detail=_json.dumps(
            {"mode": "live", "flow_id": envelope_flow_id},
            separators=(",", ":"),
        ),
    )
    conn.commit()
    return row_id


def list_hipaa_boundary_events(
    conn: sqlite3.Connection,
    since: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    """List boundary events newest-first, optionally filtered by timestamp.

    ``offset`` pages the mode-toggle trail."""
    if since:
        rows = conn.execute(
            "SELECT be.*, u.email AS actor_email "
            "FROM hipaa_boundary_events be "
            "LEFT JOIN users u ON u.id = be.actor_id "
            "WHERE be.ts >= ? ORDER BY be.ts DESC LIMIT ? OFFSET ?",
            (since, limit, int(offset)),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT be.*, u.email AS actor_email "
            "FROM hipaa_boundary_events be "
            "LEFT JOIN users u ON u.id = be.actor_id "
            "ORDER BY be.ts DESC LIMIT ? OFFSET ?",
            (limit, int(offset)),
        ).fetchall()
    return _rows(rows)


def latest_hipaa_boundary(
    conn: sqlite3.Connection,
    scope: str,
) -> dict | None:
    """Return the most recent boundary event for the given scope, or None."""
    row = conn.execute(
        "SELECT be.*, u.email AS actor_email "
        "FROM hipaa_boundary_events be "
        "LEFT JOIN users u ON u.id = be.actor_id "
        "WHERE be.scope = ? ORDER BY be.ts DESC LIMIT 1",
        (scope,),
    ).fetchone()
    return _row(row)


def latest_hipaa_boundaries_for_accounts(
    conn: sqlite3.Connection,
) -> dict[str, dict]:
    """Return the most recent ``account:<id>`` boundary event for every account.

    .3 — single GROUP-BY query that replaces the per-account
    :func:`latest_hipaa_boundary` round-trip in the compliance page loop.
    Returns a dict keyed by ``scope`` (e.g. ``"account:42"``) mapping to
    the same dict shape as :func:`latest_hipaa_boundary`. The ``actor_email``
    join is preserved.

    Implementation: rank rows per scope by ts DESC, take rank=1. Uses the
    correlated-subquery flavour because SQLite's ROW_NUMBER() requires
    3.25+ and we already index ``(scope, ts)`` via the schema.
    """
    rows = conn.execute(
        "SELECT be.*, u.email AS actor_email "
        "FROM hipaa_boundary_events be "
        "LEFT JOIN users u ON u.id = be.actor_id "
        "WHERE be.scope LIKE 'account:%' "
        "  AND be.ts = ("
        "      SELECT MAX(ts) FROM hipaa_boundary_events be2 "
        "      WHERE be2.scope = be.scope"
        "  ) "
        "ORDER BY be.scope"
    ).fetchall()
    # If two rows share scope+ts (unlikely; ts is microsecond-resolution
    # ISO-8601), we keep the first — duplicate-tick collisions don't
    # affect the "most recent" rendering and are vanishingly rare.
    out: dict[str, dict] = {}
    for r in rows:
        d = dict(r)
        scope = d.get("scope")
        if scope and scope not in out:
            out[scope] = d
    return out


# ---------------------------------------------------------------------------
# HIPAA access event helpers (§164.312(b) access-audit trail)
# ---------------------------------------------------------------------------

def phi_access_audit_required(
    *,
    account_hipaa: bool,
    actor_user_id: int | None,
    owner_id: int | None,
) -> bool:
    """PD#14 gate SSOT — does this access need a §164.312(b) access-event row?

    True iff the account is HIPAA-flagged AND the actor is NOT the owner.

    - **System actor (`actor_user_id is None`) STILL requires the row** — a
      null principal is not the owner (``None != owner_id``), so it is a
      non-owner PHI access. Do NOT add an ``actor_user_id is not None`` guard:
      that was the N-72 bug — it silently dropped system-initiated PHI reads
      (scheduled bulk-triage / back-scan on a HIPAA mailbox) from the audit
      trail. This is the single source of truth for that decision so the
      bookend helper (``audit_phi_access``) and the start/finalise bracket
      sites (triage_runner / triage_runner_bulk / topic_backscan) cannot drift
      apart in their gate logic.
    - **Owner self-access** (``actor_user_id == owner_id``) is the §164.502(a)
      self-disclosure carve-out and is exempt.
    - **Non-HIPAA account**: never required.
    """
    if not account_hipaa:
        return False
    return actor_user_id != owner_id


def record_hipaa_access_event_txn(
    conn: sqlite3.Connection,
    actor_user_id: int | None,
    account_id: int,
    operation: str,
    outcome: str = "ok",
    detail: str | None = None,
) -> int:
    """TXN-AWARE chained hipaa_access_events emit — does NOT commit.

    N-520 — the ``*_txn`` sibling of :func:`record_hipaa_access_event`. Use
    INSIDE the caller's open transaction so a PHI-access row and the state change
    it witnesses land or roll back together. UNDECORATED for the M-2/M-3 reasons
    set out in full on :func:`record_auth_event_txn` (a ``@db_write`` here would
    roll back the CALLER's transaction; an ``@audit_emitter`` here is a marker
    nothing reads). The caller owns commit/rollback.

    THE ONE chain-writer for ``hipaa_access_events`` (PD#3/PD#5). ``outcome`` and
    ``detail`` are STORED but EXCLUDED from the canonical hash (Option A) because
    :func:`update_hipaa_access_event` finalises them in place; the chain hashes
    only the immutable access FACT (ts/actor/account/operation), so the finalise
    UPDATE is chain-transparent. Returns the new row id.
    """
    return _chain_insert(conn, "hipaa_access_events", {
        "ts": now_utc_iso(),
        "actor_user_id": actor_user_id,
        "account_id": account_id,
        "operation": operation,
        "outcome": outcome,
        "detail": detail,
    })


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_hipaa_access_event(
    conn: sqlite3.Connection,
    actor_user_id: int | None,
    account_id: int,
    operation: str,
    outcome: str = "ok",
    detail: str | None = None,
) -> int:
    """Record a user-initiated OR system-initiated access to a HIPAA-flagged account.

    ``actor_user_id`` is the authenticated user id for user-initiated
    operations (e.g. ``"discover"`` / ``"manual_triage"``). For
    system-initiated operations (background sender failures, scheduled
    digest archive-failure visibility per H-06 §164.308(a)(7), etc.)
    pass ``None`` — the column allows NULL and the actor convention
    becomes "system" at read-time. Annotation widened to ``int | None``
    per hipaa-sme-3 R-2 verify-don't-accept review 2026-05-24 (signature
    previously claimed non-Optional while builder code + schema both
    permitted NULL).

    ``operation`` is one of ``"discover"`` / ``"manual_triage"`` /
    ``"digest_archive_failed"`` (per H-06). ``outcome`` is ``"ok"`` or
    ``"error"``. ``detail`` is a short free-text field — never PHI
    (used for error classes, count of messages touched, etc.).

    OWN-COMMIT emitter — it commits, so it must NOT be used where the row has to
    be atomic with a coupled state write (that is N-520). For that case use
    :func:`record_hipaa_access_event_txn` inside the caller's transaction.

    Note this is the POINT-witness entry point. The START/UPDATE bracket
    (``outcome="in_progress"`` here, finalised by
    :func:`update_hipaa_access_event`) is already witness-first and needs no
    ``*_txn`` treatment — do not convert those call sites.
    """
    #  — the headline PHI-access boundary log, HMAC-chained via the txn-aware
    # sibling so the row shape has ONE author (PD#5). Own-commit wrapper.
    row_id = record_hipaa_access_event_txn(
        conn, actor_user_id, account_id, operation, outcome, detail
    )
    conn.commit()
    return row_id


@db_write
@audit_emitter  # §164.312(b) finalise-gap — gap-event on UPDATE failure
def update_hipaa_access_event(
    conn: sqlite3.Connection,
    event_id: int,
    outcome: str,
    detail: str | None = None,
) -> None:
    """Finalise outcome/detail on an event recorded at op-START.

    ``record_hipaa_access_event`` (an ``@audit_emitter``) emits the row at
    op-start with ``outcome="in_progress"``; this UPDATE finalises the SAME
    row to its terminal outcome. All 6 finalise call sites wrap this in a
    best-effort ``try/except`` that only ``log.warning(...)``s — so a FAILED
    finalise-UPDATE (e.g. lock contention) would silently leave the row
    frozen at ``in_progress``, the audit record affirmatively LYING about the
    operation outcome with nothing recording the loss.

    Decorating with ``@audit_emitter`` closes that §164.312(b) gap: the
    ``@db_write`` wrapper's except clause writes a chained ``audit_gap_events``
    row keyed by this helper's name when the UPDATE raises, THEN re-raises (the
    call sites swallow the re-raise to a warning → the operation still
    completes; the finalise is best-effort, but the loss is now VISIBLE +
    §164.312(c)(1) tamper-evident). The START-side emitter gap-covered the row
    CREATION, not this finalise — this completes the bracket.

    Gap-row triage note (DA hedge-check on N-58): a gap row for this helper
    ALSO fires when the write is SHED at the writer-queue boundary
    (``WriterQueueFull`` /  DEFECT-B) — in that case the UPDATE never ran
    and the row is simply still at ``in_progress``; the gap signals
    backpressure, NOT audit corruption. An operator/runbook reading a
    ``helper_name=update_hipaa_access_event`` gap row must treat it as
    possibly-backpressure, not definitely-integrity-loss.

     / N-15 CHAIN-TRANSPARENCY CONTRACT (Option A — BINDING, hipaa-sme).
    ``hipaa_access_events`` rows are HMAC-chained (``_chain_insert``), but the
    canonical hash covers ONLY the immutable creation fields
    (``_AUDIT_CHAIN_CANONICAL_FIELDS["hipaa_access_events"]`` = ts, actor_user_id,
    account_id, operation). ``outcome`` + ``detail`` are deliberately EXCLUDED so
    THIS in-place UPDATE is chain-transparent — it touches no hashed column, so
    ``row_hash`` stays valid and the chain needs no O(n) re-link. **If you ever
    add a column to this UPDATE, that column MUST stay OUT of the canonical field
    tuple** — adding a hashed mutable field would make this UPDATE silently break
    the chain. The tuple-exclusion is enforced by
    ``tests/test_audit_chain_pin.py::test_hipaa_access_events_excludes_mutable_fields``.
    The §164.306(d)(3)(ii)(B) bounded-coverage decision (outcome/detail not
    tamper-evident on a SUCCESSFUL overwrite; a FAILED finalise already gap-rows)
    is recorded in the §164.316 register (N-15).
    """
    conn.execute(
        "UPDATE hipaa_access_events SET outcome = ?, detail = ? WHERE id = ?",
        (outcome, detail, event_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Regulatory clock transition events — chained audit-event emitters.
#
# `regulatory_clock_event` is a DEDICATED HMAC-chained audit table (chain
# columns added in migration v47). These two helpers are its ONLY legitimate
# writers — the inverse-INSERT pin (tests/test_audit_chain_pin.py, registry-
# keyed) catches any raw INSERT that bypasses `_chain_insert`. Every transition
# is a NEW chained row (append-only; a correction is a new
# `determination_corrected` event with actor + reason, never an in-place edit —
# 21 CFR Part 11 audit-trail semantics). This SUPERSEDES the design's "chain
# into log_entries, project here" model (log_entries is pruned → would breach
# §164.316(b)(2)(i) retention; see migration `_v47`).
# ---------------------------------------------------------------------------

# The 9 legal transition kinds (mirrors the regulatory_clock_event CHECK in
# migration v46). The human-disposition subset MUST name the acting human —
# record_clock_ack enforces it (propose-then-confirm; the LLM never auto-files).
_CLOCK_EVENT_KINDS = frozenset({
    "detected", "determined", "awareness_set", "escalated", "acked",
    "submitted", "dismissed", "breached", "determination_corrected",
})
# Kinds a HUMAN must own (record_clock_ack requires a non-null actor for these).
# PHASE-2 ROUTING NOTE: the design's high-confidence "auto-arm" band (D2 / design
# §168) may have the SYSTEM emit a `determined` event with NO human actor. That
# path MUST call record_clock_event(event_kind="determined", actor_user_id=None
# or a config actor), NOT record_clock_ack — record_clock_ack deliberately
# REJECTS a null actor, so routing a system auto-determination through it is a
# bug. Human-confirmed determinations go through record_clock_ack; system
# auto-determinations go through record_clock_event.
_CLOCK_HUMAN_DISPOSITION_KINDS = frozenset({
    "determined", "awareness_set", "acked", "submitted", "dismissed",
    "determination_corrected",
})


def _clock_event_chain_row(
    *, instance_id, event_kind, actor_user_id, from_state, to_state,
    escalation_rung, delivered_to_ref, detail,
) -> dict:
    """Validate + build the ``regulatory_clock_event`` chain-insert data dict.

    Shared by the standalone own-commit ``record_clock_event`` and the
    txn-aware ``emit_clock_event_txn`` so the event-kind validation + the
    canonical column set live in ONE place (PD#5 — no mirrored copies)."""
    if event_kind not in _CLOCK_EVENT_KINDS:
        raise ValueError(
            f"clock event: unknown event_kind {event_kind!r} "
            f"(legal kinds: {sorted(_CLOCK_EVENT_KINDS)})"
        )
    return {
        "instance_id": instance_id,
        "event_kind": event_kind,
        "actor_user_id": actor_user_id,
        "from_state": from_state,
        "to_state": to_state,
        "escalation_rung": escalation_rung,
        "delivered_to_ref": delivered_to_ref,
        "detail": detail,
        "created_at": now_utc_iso(),
    }


def require_human_clock_actor(event_kind: str, actor_user_id: int | None) -> None:
    """Fail-closed guard for a HUMAN-disposition clock transition: it MUST name
    the acting human (propose-then-confirm — the LLM never auto-files/auto-
    closes), and the kind must be a disposition kind. Raises ``ValueError`` on a
    null actor or a system-only kind. Shared by ``record_clock_ack`` and the
    Phase-2 lifecycle helpers (db/regulatory_clock.py)."""
    if actor_user_id is None:
        raise ValueError(
            f"clock disposition {event_kind!r} requires a non-null "
            f"actor_user_id (use the system path for automatic transitions)"
        )
    if event_kind not in _CLOCK_HUMAN_DISPOSITION_KINDS:
        raise ValueError(
            f"{event_kind!r} is not a human-disposition kind "
            f"({sorted(_CLOCK_HUMAN_DISPOSITION_KINDS)})"
        )


def emit_clock_event_txn(
    conn: sqlite3.Connection,
    *,
    instance_id: int,
    event_kind: str,
    actor_user_id: int | None = None,
    from_state: str | None = None,
    to_state: str | None = None,
    escalation_rung: int | None = None,
    delivered_to_ref: str | None = None,
    detail: str | None = None,
) -> int:
    """TXN-AWARE chained clock-event emit — validates + ``_chain_insert``, does
    NOT commit. Use INSIDE the caller's open transaction when the event must be
    atomic with a state mutation on ``regulatory_clock_instance``: the caller
    does its UPDATE(s) + this emit, then ONE ``conn.commit()`` (rollback on any
    error), so the state flip + the chained audit row land or roll back together
    (same atomic-state-flip-plus-audit-row guarantee as
    ``db/accounts.set_account_hipaa``). The caller owns commit/rollback;
    ``record_clock_event`` is the own-commit standalone wrapper. Returns the new
    row id."""
    return _chain_insert(conn, "regulatory_clock_event", _clock_event_chain_row(
        instance_id=instance_id, event_kind=event_kind,
        actor_user_id=actor_user_id, from_state=from_state, to_state=to_state,
        escalation_rung=escalation_rung, delivered_to_ref=delivered_to_ref,
        detail=detail,
    ))


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_clock_event(
    conn: sqlite3.Connection,
    *,
    instance_id: int,
    event_kind: str,
    actor_user_id: int | None = None,
    from_state: str | None = None,
    to_state: str | None = None,
    escalation_rung: int | None = None,
    delivered_to_ref: str | None = None,
    detail: str | None = None,
) -> int:
    """Record a regulatory-clock transition as a chained audit-event row.

    THE single STANDALONE writer for ``regulatory_clock_event`` — routes through
    ``_chain_insert`` so every transition is HMAC-chained + tamper-evident
    (§164.312(c)(1)), retained (dedicated table, never pruned), and fail-closed
    (``_chain_insert`` RuntimeErrors if no HMAC key is provisioned — never an
    unsigned audit row, Directive 12). Own-commit emitter; use this when there is
    no coupled state mutation (e.g. the sweep's ``escalated``/``breached``). For
    a transition that must be atomic with a ``regulatory_clock_instance`` UPDATE,
    use ``emit_clock_event_txn`` inside the caller's ``BEGIN…COMMIT``.

    ``actor_user_id`` is the human for a disposition event, or ``None`` for a
    system/sweep transition (``detected``/``escalated``/``breached``). ``detail``
    is short free-text that MAY carry PHI → redacted-at-write in the gap-event
    payload (the ``_AUDIT_EMITTER_REDACTION_MAP`` "out" set); the stored value is
    encrypted at rest with the rest of the SQLCipher DB. Returns the new row id.
    """
    row_id = emit_clock_event_txn(
        conn, instance_id=instance_id, event_kind=event_kind,
        actor_user_id=actor_user_id, from_state=from_state, to_state=to_state,
        escalation_rung=escalation_rung, delivered_to_ref=delivered_to_ref,
        detail=detail,
    )
    conn.commit()
    return row_id


def record_clock_ack(
    conn: sqlite3.Connection,
    *,
    instance_id: int,
    event_kind: str,
    actor_user_id: int,
    from_state: str | None = None,
    to_state: str | None = None,
    detail: str | None = None,
) -> int:
    """Record a standalone HUMAN-disposition clock transition (acked / … ).

    Thin fail-closed specialization of :func:`record_clock_event`: enforces
    ``require_human_clock_actor`` (non-null actor + a disposition kind), then
    delegates the chained write to ``record_clock_event`` (ONE chain-writer, ONE
    redaction-map entry — the gap fires under ``record_clock_event``). Returns
    the new row id."""
    require_human_clock_actor(event_kind, actor_user_id)
    return record_clock_event(
        conn,
        instance_id=instance_id,
        event_kind=event_kind,
        actor_user_id=actor_user_id,
        from_state=from_state,
        to_state=to_state,
        detail=detail,
    )


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_discover_run(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    account_name: str,
    actor_user_id: int | None,
    scanned_count: int,
    errors_count: int,
    folders: list[str],
    elapsed_secs: float,
) -> int:
    """Record a completed Discover Categories scan for audit.

    Unlike ``hipaa_access_events`` (which is HIPAA-only), every discover
    run lands a row here — Discover exposes sender + subject of every
    scanned message and is mail-read-level privilege. Answering "who
    scanned which mailbox + scope" is the audit question.

    Metadata only: no sender, subject, raw_description or raw_category.
    Discover content is proposals in review, not actions taken.
    """
    import json as _json
    now = now_utc_iso()
    #  — chained audit write (SSOT). Own-commit emitter.
    row_id = _chain_insert(conn, "discover_runs", {
        "account_id": account_id,
        "account_name": account_name or "",
        "actor_user_id": actor_user_id,
        "scanned_count": int(scanned_count),
        "errors_count": int(errors_count),
        "folders": _json.dumps(list(folders or [])),
        "elapsed_secs": float(elapsed_secs),
        "created_at": now,
    })
    conn.commit()
    return row_id


def list_discover_runs(
    conn: sqlite3.Connection,
    account_id: int | None = None,
    actor_user_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """List discover runs newest-first with optional filters.

    ``offset`` pages through the trail — the
    compliance page's "load older" pager passes it so the full audit
    record is accessible, not just the newest ``limit``."""
    where: list[str] = []
    params: list = []
    if account_id is not None:
        where.append("dr.account_id = ?")
        params.append(account_id)
    if actor_user_id is not None:
        where.append("dr.actor_user_id = ?")
        params.append(actor_user_id)
    sql = (
        "SELECT dr.*, u.email AS actor_email "
        "FROM discover_runs dr "
        "LEFT JOIN users u ON u.id = dr.actor_user_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY dr.created_at DESC LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(int(offset))
    rows = conn.execute(sql, params).fetchall()
    return _rows(rows)


def list_hipaa_access_events(
    conn: sqlite3.Connection,
    account_id: int | None = None,
    actor_user_id: int | None = None,
    since: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    """List access events newest-first with optional filters.

    ``offset`` pages the §164.312(b) PHI-access trail (
    reachability)."""
    where: list[str] = []
    params: list = []
    if account_id is not None:
        where.append("ae.account_id = ?")
        params.append(account_id)
    if actor_user_id is not None:
        where.append("ae.actor_user_id = ?")
        params.append(actor_user_id)
    if since:
        where.append("ae.ts >= ?")
        params.append(since)
    sql = (
        "SELECT ae.*, u.email AS actor_email, ea.name AS account_name "
        "FROM hipaa_access_events ae "
        "LEFT JOIN users u ON u.id = ae.actor_user_id "
        "LEFT JOIN email_accounts ea ON ea.id = ae.account_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ae.ts DESC LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(int(offset))
    rows = conn.execute(sql, params).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# API key lifecycle event helpers (audit trail for create/delete)
# ---------------------------------------------------------------------------

# Panel AB MUST-C1 (ab-da R3-1): the typed actor a REVOKE records when its caller
# passed none. A grant with no actor is refused instead.
API_KEY_UNATTRIBUTED_PREFIX = "unattributed:"


class ApiKeyEventUnattributed(ValueError):
    """An api-key GRANT whose witness would name no actor (punch 710, PD-8)."""


def record_api_key_event_txn(
    conn: sqlite3.Connection,
    *,
    event: str,
    key_id: int,
    actor_user_id: int | None,
    target_user_id: int | None,
    name: str,
    expires_at: str | None,
    source: str,
    actor_email: str | None = None,
) -> int:
    """TXN-AWARE chained api_key_events emit — does NOT commit.

    N-520 — the ``*_txn`` sibling of :func:`record_api_key_event`. Use INSIDE the
    caller's open transaction so the key create/revoke and its audit row land or
    roll back together. UNDECORATED for the M-2/M-3 reasons set out in full on
    :func:`record_auth_event_txn`. The caller owns commit/rollback.

    THE ONE chain-writer for ``api_key_events`` (PD#3/PD#5). ``key_id`` is
    intentionally NOT a foreign key — revoked ``api_keys`` rows are deleted, but
    the audit row must survive. Returns the new row id.

    Punch 710: ``actor_email`` records WHO acted: the session user's address, or
    the CLI kernel principal (``cli._cli_actor``), whose ``actor_user_id`` is
    NULL by design. It is stored in the row but NOT hashed. Hashing it would not
    re-hash existing rows (the verifier dispatches per row on ``hash_alg``, so a
    new keyed alg label covers new rows only); it waits for v0.2.x because a
    chain-format change during the bug-fix freeze carries verifier risk (panel
    AB MUST-C4). Every src caller passes it (``tests/test_710_api_key_actor_pin.py``).

    A row with NO actor (``actor_user_id`` None and no ``actor_email``) is never
    written as such (panel AB MUST-C1, ab-da R3-1):
      * a GRANT is refused: :class:`ApiKeyEventUnattributed` is raised before any
        write, so ``store_api_key`` rolls the grant back and writes its gap row;
      * a REVOKE is never refused (that would leave the key live): the row
        records the typed sentinel ``unattributed:<source>`` and an ``auth_events``
        alarm row is written in the SAME transaction.
    """
    if actor_user_id is None and not actor_email:
        if event != "api_key_revoked":
            raise ApiKeyEventUnattributed(
                f"{event}: an api_key_events row needs an actor "
                "(actor_user_id or actor_email); refusing an unattributed grant")
        actor_email = API_KEY_UNATTRIBUTED_PREFIX + str(source)
        record_auth_event_txn(
            conn,
            event_type="api_key_revoke_unattributed",
            email=actor_email,
            outcome="alarm",
            detail=(f"api key #{int(key_id)} revoked with no actor; its "
                    f"api_key_events row records {actor_email}"),
        )
    return _chain_insert(conn, "api_key_events", {
        "ts": now_utc_iso(),
        "event": event,
        "key_id": key_id,
        "actor_user_id": actor_user_id,
        "target_user_id": target_user_id,
        "name": name,
        "expires_at": expires_at,
        "source": source,
        "actor_email": actor_email,
    })


@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_api_key_event(
    conn: sqlite3.Connection,
    *,
    event: str,
    key_id: int,
    actor_user_id: int | None,
    target_user_id: int | None,
    name: str,
    expires_at: str | None,
    source: str,
    actor_email: str | None = None,
) -> int:
    """Insert an api_key_events row. Returns the new row id.

    ``event`` is ``"api_key_created"`` or ``"api_key_revoked"``. ``source``
    is one of ``"ui"``, ``"api"``, ``"cli"``. ``key_id`` is intentionally
    NOT a foreign key — revoked api_keys rows are deleted, but we want
    the audit row to survive.

    OWN-COMMIT emitter — it commits, so it must NOT be used where the row has to
    be atomic with a coupled state write (that was N-520: ``web/auth.py``'s
    ``store_api_key`` / ``delete_api_key`` committed the key row, then emitted
    here; punch 627 / 689 moved both onto the txn sibling). For that case use
    :func:`record_api_key_event_txn` inside the caller's transaction.
    """
    #  — chained audit write (SSOT), via the txn-aware sibling so the row
    # shape has ONE author (PD#5). Own-commit wrapper.
    row_id = record_api_key_event_txn(
        conn,
        event=event,
        key_id=key_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        name=name,
        expires_at=expires_at,
        source=source,
        actor_email=actor_email,
    )
    conn.commit()
    return row_id


def list_api_key_events(
    conn: sqlite3.Connection,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Return recent api_key_events newest-first, joined with user emails.

    Both actor and target user emails are looked up so the compliance UI
    can render readable rows even after either user is deleted (the FK
    is ON DELETE SET NULL so the row survives the user record).
    ``offset`` pages the key-lifecycle trail."""
    rows = conn.execute(
        # Punch 710: explicit columns, not ``ake.*``: the table now has its own
        # ``actor_email``, and a duplicate name resolves by the row factory
        # (``sqlite3.Row`` returns the FIRST), which would hide the joined
        # email on every pre-v54 row.
        # Panel AB MUST (C2-display): the address resolved from the HASHED
        # ``actor_user_id`` wins; the unhashed stored copy fills in only for a
        # CLI row (``actor_user_id`` NULL) and is shown beside it when they
        # differ (``recorded_actor_email``). ``au.email`` is the CURRENT address.
        "SELECT ake.id, ake.ts, ake.event, ake.key_id, ake.actor_user_id, "
        "       ake.target_user_id, ake.name, ake.expires_at, ake.source, "
        "       ake.prev_hash, ake.row_hash, ake.hash_alg, ake.master_key_version, "
        "       COALESCE(au.email, ake.actor_email) AS actor_email, "
        "       ake.actor_email AS recorded_actor_email, "
        "       tu.email AS target_email "
        "FROM api_key_events ake "
        "LEFT JOIN users au ON au.id = ake.actor_user_id "
        "LEFT JOIN users tu ON tu.id = ake.target_user_id "
        "ORDER BY ake.id DESC LIMIT ? OFFSET ?",
        (limit, int(offset)),
    ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# Access log)
# ---------------------------------------------------------------------------

@db_write
@audit_emitter  #  D3 — gap-event on write failure
def record_access_event(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int | None,
    method: str,
    route: str,
    account_id: int | None,
    message_id: str | None,
    status_code: int,
    outcome: str,
    detail: str | None = None,
    request_id: str | None = None,
) -> int:
    """Insert an access_log row. Returns the new row id.

    Called by the access-audit middleware on every authenticated
    request that hits a PHI-touch route prefix. No PHI is persisted —
    only the route shape, method, status, and any account/message
    identifiers extracted from the URL path. ``request_id`` (when
    provided) correlates the row with the structured-log lines
    emitted during the same request scope.

    **Failure policy.** This function does NOT swallow exceptions.
    The caller (``AccessAuditMiddleware.dispatch``) is responsible
    for the failure-handling shape (re-raise in dev mode, log + count
    in prod, never silent). A previous version silently returned 0
    on error, which made ``access_log`` un-trustable as the HIPAA
    audit source of truth. If you need an "audit must not crash the
    request" boundary, put it at the caller, not here.

    OWN-COMMIT emitter — it commits, so it must NOT be used where the row has to
    be atomic with a coupled state write (that is N-520: the watch-group save and
    the digest send-stamp both commit their state, then emit here). For that case
    use :func:`record_access_event_txn` inside the caller's transaction. The
    middleware path, which has no coupled state write of its own, correctly stays
    on this own-commit entry point.
    """
    #  — chained audit write (SSOT), via the txn-aware sibling so the row shape
    # AND the FK-coercion re-chain have ONE author (PD#5). Own-commit wrapper.
    row_id = record_access_event_txn(
        conn,
        actor_user_id=actor_user_id,
        method=method,
        route=route,
        account_id=account_id,
        message_id=message_id,
        status_code=status_code,
        outcome=outcome,
        detail=detail,
        request_id=request_id,
    )
    conn.commit()
    return row_id


def record_access_event_txn(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int | None,
    method: str,
    route: str,
    account_id: int | None,
    message_id: str | None,
    status_code: int,
    outcome: str,
    detail: str | None = None,
    request_id: str | None = None,
) -> int:
    """TXN-AWARE chained access_log emit — does NOT commit.

    N-520 — the ``*_txn`` sibling of :func:`record_access_event`. Use INSIDE the
    caller's open transaction so a §164.312(b) access row and the state change it
    witnesses land or roll back together. UNDECORATED for the M-2/M-3 reasons set
    out in full on :func:`record_auth_event_txn`. The caller owns
    commit/rollback.

    THE ONE chain-writer for ``access_log`` (PD#3/PD#5), including the
    FK-coercion re-chain below — the own-commit wrapper delegates here.

    **The ``IntegrityError`` re-chain is PRESERVED, and it is still sound inside a
    caller-owned transaction.** A constraint violation fails the INSERT
    *statement* without ending the transaction, so nothing of this emit is
    durable and the chain tail is unchanged — the retry reads the same tail and
    chains the FK-coerced row cleanly, exactly as it does in the own-commit form.
    Note the caller's earlier DML in the same transaction is untouched by that
    statement failure, which is the intended shape: the point of the re-chain is
    that the audit row still records what was TRIED.

    **One narrowing of the caught set, deliberate and worth knowing.** In the
    own-commit form the ``conn.commit()`` sat INSIDE the ``try``, so an
    ``IntegrityError`` raised by a deferred constraint AT COMMIT time also
    triggered the re-chain — which would have inserted a SECOND row for a first
    row that had already been written. Here the commit is the wrapper's and is
    outside this ``try``, so only an INSERT-time violation re-chains. That is
    strictly the safer half; a commit-time failure now propagates to the caller
    (fail-closed, PD#8) instead of silently double-writing.

    Returns the new row id.
    """
    now = now_utc_iso()
    # access_log is append-only, so every written column is hashed. PERF NOTE:
    # _chain_insert does one PK-indexed `get_last_audit_row_hash` SELECT per call;
    # on this hot per-request path a cached tail (mirroring
    # SQLiteLogHandler._last_row_hash: prime once, advance in-mem, reset-to-cold
    # on write error) would avoid it. Deferred as a scoped perf follow-up (a
    # module-level cache would break the multi-DB test isolation the suite relies
    # on; the correct home is a per-connection/per-middleware cache) — raised to
    # db-sme in the  implementation review.
    try:
        return _chain_insert(conn, "access_log", {
            "ts": now,
            "actor_user_id": actor_user_id,
            "method": method,
            "route": route,
            "account_id": account_id,
            "message_id": message_id,
            "status_code": int(status_code),
            "outcome": outcome,
            "detail": detail,
            "request_id": request_id,
        })
    except DB_INTEGRITY_ERRORS as e:
        # FK violation -- typically because the URL referenced an
        # account_id (or actor_user_id) that no longer exists in
        # the parent table. Don't fail the audit write; coerce the
        # offending FK to NULL and stash the original in `detail`.
        # The audit row still records what was tried, which is the
        # whole point under HIPAA §164.312(b).
        msg = str(e).lower()
        stale_bits: list[str] = []
        coerced_account = account_id
        coerced_actor = actor_user_id
        if "foreign key" in msg:
            # We don't get column-level info from sqlite3's
            # IntegrityError, so just NULL both FK columns and note
            # the original values. Routes typically only carry one
            # of these, so the noise is bounded.
            if account_id is not None:
                stale_bits.append(f"stale_account_id={account_id}")
                coerced_account = None
            if actor_user_id is not None:
                stale_bits.append(f"stale_actor_user_id={actor_user_id}")
                coerced_actor = None
        merged_detail = detail or ""
        if stale_bits:
            tail = " ".join(stale_bits)
            merged_detail = f"{merged_detail} | {tail}".strip(" |") if merged_detail else tail
        # The first _chain_insert raised on the INSERT (constraint), so nothing of
        # this emit is durable and the chain tail is unchanged; this retry reads
        # the same tail and chains the FK-coerced row cleanly. Chain integrity
        # preserved. NO commit here — the caller owns commit timing (N-520).
        return _chain_insert(conn, "access_log", {
            "ts": now,
            "actor_user_id": coerced_actor,
            "method": method,
            "route": route,
            "account_id": coerced_account,
            "message_id": message_id,
            "status_code": int(status_code),
            "outcome": outcome,
            "detail": merged_detail,
            "request_id": request_id,
        })


def list_access_events(
    conn: sqlite3.Connection,
    limit: int = 100,
    actor_user_id: int | None = None,
    account_id: int | None = None,
    offset: int = 0,
) -> list[dict]:
    """Return recent access_log rows newest-first, joined with actor email.

    ``offset`` pages the §164.312(b) PHI-route trail."""
    where = []
    params: list = []
    if actor_user_id is not None:
        where.append("al.actor_user_id = ?")
        params.append(actor_user_id)
    if account_id is not None:
        where.append("al.account_id = ?")
        params.append(account_id)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    params.append(int(offset))
    rows = conn.execute(
        "SELECT al.*, "
        "       u.email AS actor_email, "
        "       ea.name AS account_name "
        "FROM access_log al "
        "LEFT JOIN users u ON u.id = al.actor_user_id "
        "LEFT JOIN email_accounts ea ON ea.id = al.account_id "
        f"{where_sql} "
        "ORDER BY al.id DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# Audit-table totals
#
# The compliance page renders each audit table with a hard LIMIT (100 /
# 50). Once a table exceeds its cap the oldest rows silently vanish and
# the operator reads a subset as the whole trail — a compliance-
# visibility gap (silent-truncation audit, row ). These COUNT(*)
# helpers give the true denominator so the page can say
# "showing 100 of 4,213 — older entries not shown". Each mirrors its
# ``list_*`` sibling's base table; the compliance page calls them
# unfiltered (matching its unfiltered list_* calls), so they take no
# predicate — add filter params here AND to the list sibling together
# if a filtered count is ever needed (keep the two in lockstep).
# ---------------------------------------------------------------------------

def count_hipaa_access_events(conn: sqlite3.Connection) -> int:
    """Total rows in ``hipaa_access_events`` (the PHI access trail)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM hipaa_access_events"
    ).fetchone()
    return int(row[0] if row is not None else 0)


def count_api_key_events(conn: sqlite3.Connection) -> int:
    """Total rows in ``api_key_events`` (key create/revoke trail)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM api_key_events"
    ).fetchone()
    return int(row[0] if row is not None else 0)


def count_discover_runs(conn: sqlite3.Connection) -> int:
    """Total rows in ``discover_runs`` (folder-discovery audit)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM discover_runs"
    ).fetchone()
    return int(row[0] if row is not None else 0)


def count_access_events(conn: sqlite3.Connection) -> int:
    """Total rows in ``access_log`` (PHI-route access trail)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM access_log"
    ).fetchone()
    return int(row[0] if row is not None else 0)


def count_hipaa_boundary_events(conn: sqlite3.Connection) -> int:
    """Total rows in ``hipaa_boundary_events`` (mode-toggle trail)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM hipaa_boundary_events"
    ).fetchone()
    return int(row[0] if row is not None else 0)


# ---------------------------------------------------------------------------
# Log entries hash chain
# ---------------------------------------------------------------------------

def _canonical_log_row(
    prev_hash: str,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra_json: str,
) -> bytes:
    """The canonical bytestring used as input to every chain-hash flavor.

    Form: ``prev_hash | ts | level | logger | message | extra_json``
    joined with the literal pipe. Pipes inside any field do NOT need
    escaping because the hash purpose is detection, not parsing back:
    two rows that hash to the same value implies every field is equal
    AND the predecessor is the same.

    Shared by :func:`_compute_log_row_hash_sha256` (legacy verifier
    path) and :func:`compute_log_row_hash` (HMAC dispatch). Keeping
    the canonical form in one place ensures the migration boundary is
    purely about the keyed-vs-unkeyed primitive, not about field
    order or separator semantics.
    """
    canonical = f"{prev_hash}|{ts}|{level}|{logger}|{message}|{extra_json}"
    return canonical.encode("utf-8")


def _compute_log_row_hash_sha256(
    prev_hash: str,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra_json: str,
) -> str:
    """Legacy SHA-256 hash — used ONLY by :func:`verify_log_chain` to
    re-verify rows stamped with ``hash_alg='sha256'`` (pre-H-02a).

    NOT for writing new rows. New rows go through the HMAC path of
    :func:`compute_log_row_hash`; legacy rows remain verifiable
    forever per §164.316(b)(2)(i) 6-year retention until the v0.2.0
    sunset removes this branch (operator must explicitly opt in via
    ``config.audit.permit_legacy_sha256_chain = true`` to retain it
    past a future release; removal of the flag + this branch entirely is deferred pending explicit operator directive — the earlier "v0.3.0 removes" version-anchor was AI-invented, not authorized; corrected 2026-07-06).

    See :func:`_canonical_log_row` for the canonical-form contract.
    """
    import hashlib
    return hashlib.sha256(
        _canonical_log_row(prev_hash, ts, level, logger, message, extra_json)
    ).hexdigest()


# Punch  / N-507 option A (operator 2026-10-12, conditional on hipaa-sme).
# The ONE alg every chain writer stamps on a new row. ``hmac-sha256-v2`` binds
# the row's own ``hash_alg`` and ``master_key_version`` into the keyed
# preimage, so neither label can be rewritten on a v2 row without the key.
# Prospective only: v1 and sha256 rows keep verifying under their stored form
# and nothing is re-hashed, so the byte-identity freeze is untouched.
CHAIN_HASH_ALG_CURRENT = "hmac-sha256-v2"
# Every keyed alg, oldest first. Shared by the log_entries walk and its SQL
# so the keyed-row classification has one source.
KEYED_CHAIN_HASH_ALGS: tuple[str, ...] = ("hmac-sha256-v1", "hmac-sha256-v2")
# The keyed alg a chain has DOWNGRADED from once a current row exists: no
# current writer stamps it, so a v1 row after the first v2 row of the same
# chain is a downgrade signal. A sha256 row after it is already a keyless
# signal where no writer produces one (N-507; D for log_entries).
_SUPERSEDED_KEYED_ALG = "hmac-sha256-v1"


def _apply_chain_hmac(
    canonical: bytes,
    *,
    hash_alg: str = CHAIN_HASH_ALG_CURRENT,
    master_key_version: int | None = None,
    _what: str = "compute_audit_row_hash",
) -> str:
    """Apply the keyed-hash dispatch to an ALREADY-canonicalized row.

     / N-15 — the SSOT for the ``(hash_alg, master_key_version)`` dispatch
    shared by every audit chain (PD#5/#6). It operates STRICTLY above the
    canonicalization line: each chain owns its own canonical BYTE form
    (``_canonical_log_row`` = pipe-join / NO NFC; ``_canonical_gap_row`` and
    ``_canonical_audit_row`` = newline-join / NFC) and those forms are FROZEN —
    NOT unified here — because unifying them would silently re-hash 6-year-
    retained history and break the fail-closed verifier (the 2026-05-31 incident
    shape; guarded by ``tests/test_audit_chain_byte_identity_freeze.py``). This
    helper only chooses the keyed primitive + key version.

    ``_what`` names the caller in the fail-closed error message so the pre-#26
    message contract (``compute_log_row_hash`` / ``compute_gap_row_hash``)
    survives the dedup.

    Raises:
        RuntimeError: D1 fail-closed per §164.312(c)(1) Required-spec — HMAC was
            requested but no key is provisioned for the version. Real-deployment
            startup wires the registry via :func:`set_hmac_keys` (secrets
            bootstrap); tests via :func:`_set_hmac_key_for_test`.
        ValueError: unknown ``hash_alg``.
    """
    if hash_alg == "sha256":
        import hashlib
        return hashlib.sha256(canonical).hexdigest()
    if hash_alg in KEYED_CHAIN_HASH_ALGS:
        version = (
            master_key_version
            if master_key_version is not None
            else _get_current_hmac_version()
        )
        if version is None:
            raise RuntimeError(
                f"H-02a (§164.312(c)(1) Required-spec): {_what} requested "
                f"HMAC-SHA256 but no HMAC key has been provisioned. "
                f"Real-deployment startup must call db.audit.set_hmac_keys() "
                f"after deriving subkeys via "
                f"secrets.derive_audit_chain_hmac_key(); test fixtures must "
                f"call db.audit._set_hmac_key_for_test(). Fail-closed per "
                f"hipaa-sme-2 + DA-3 verdicts 2026-05-23."
            )
        key = _get_hmac_key(version)
        if key is None:
            raise RuntimeError(
                f"H-02a (§164.312(c)(1) Required-spec): {_what} requested "
                f"HMAC-SHA256 under master_key_version={version} but that "
                f"version has no key in the HMAC registry. Either the "
                f"master_key_history row was deleted from secrets_store, OR the "
                f"lifespan failed to load all historical versions. Operator "
                f"must restore the missing history row before any further "
                f"chained audit writes succeed. Fail-closed per hipaa-sme-2 + "
                f"DA-3 verdicts 2026-05-23."
            )
        import hmac
        import hashlib
        if hash_alg == "hmac-sha256-v1":
            return hmac.new(key, canonical, hashlib.sha256).hexdigest()
        # v2 (N-507 option A): the alg and the RESOLVED key version are
        # prefixed to the frozen canonical bytes, newline-separated, so the
        # stored labels are inside the keyed hash. The version bound is the
        # one the key was looked up under; writers store that same value.
        bound = f"{hash_alg}\n{version}\n".encode("utf-8")
        return hmac.new(key, bound + canonical, hashlib.sha256).hexdigest()
    raise ValueError(
        f"{_what}: unknown hash_alg={hash_alg!r}. "
        f"Expected one of: 'sha256' (legacy), 'hmac-sha256-v1' (H-02a), "
        f"'hmac-sha256-v2' (N-507)."
    )


def compute_log_row_hash(
    prev_hash: str,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra_json: str,
    *,
    hash_alg: str = CHAIN_HASH_ALG_CURRENT,
    master_key_version: int | None = None,
) -> str:
    """Compute the chain hash for a new log_entries row.

    H-02a (Cycle 6, 2026-05-23): closes the §164.312(c)(1) Required-
    spec integrity gap by replacing secretless SHA-256 with HMAC-
    SHA256 keyed by a HKDF-derived subkey of the DbSecrets master key.

    Args:
        prev_hash, ts, level, logger, message, extra_json: the canonical
            row fields. See :func:`_canonical_log_row` for the form.
        hash_alg: which keyed primitive to apply. Default
            ``CHAIN_HASH_ALG_CURRENT`` (``'hmac-sha256-v2'``, N-507 option
            A; ``'hmac-sha256-v1'`` rows still verify). Legacy rows are
            NEVER re-written under HMAC; the
            verifier dispatches on the row's stored ``hash_alg`` and
            uses :func:`_compute_log_row_hash_sha256` for legacy rows.
            Callers that explicitly need the legacy primitive (verifier
            path) should call that helper directly.
        master_key_version: which master-key version's HMAC subkey to
            use. ``None`` (default) → use the current registry version
            from :func:`_get_current_hmac_version`. Verifier paths
            pass the explicit version from the row.

    Returns:
        Hex-encoded hash string (always 64 chars for SHA-256-based
        algorithms).

    Raises:
        RuntimeError: D1 fail-closed per hipaa-sme-2 + DA-3 verdicts
            2026-05-23 — if a keyed ``hash_alg`` is requested
            but no HMAC key is provisioned for the requested
            ``master_key_version``. Test fixtures MUST call
            :func:`_set_hmac_key_for_test` to install a key BEFORE
            inserting any rows (the test-only escape hatch is explicit
            rather than implicit). Real-deployment startup
            (``web/app.py`` lifespan + ``cli.py`` bootstrap) wires the
            registry via :func:`set_hmac_keys`; if THAT path fails,
            RuntimeError surfaces the misconfigured deploy rather
            than silently degrading compliance.
        ValueError: if ``hash_alg`` is not one of the recognized values
            (``'sha256'``, ``'hmac-sha256-v1'``, ``'hmac-sha256-v2'``).
    """
    #  — dispatch extracted to the shared _apply_chain_hmac SSOT. The
    # canonical BYTE form (_canonical_log_row: pipe-join, NO NFC) is FROZEN and
    # passed in; only the keyed-hash dispatch is shared. Byte-identity guarded
    # by tests/test_audit_chain_byte_identity_freeze.py.
    return _apply_chain_hmac(
        _canonical_log_row(prev_hash, ts, level, logger, message, extra_json),
        hash_alg=hash_alg,
        master_key_version=master_key_version,
        _what="compute_log_row_hash",
    )


def get_last_log_row_hash(conn: sqlite3.Connection) -> str:
    """Return the row_hash of the newest log_entries row, or empty
    string if the table has no chain-aware rows yet."""
    row = conn.execute(
        "SELECT row_hash FROM log_entries "
        "WHERE row_hash != '' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (row["row_hash"] if row else "") or ""


# ---------------------------------------------------------------------------
#  / N-15 — generalized audit-EVENT chain (hipaa_access_events + 7 siblings).
# Reuses the EQM-05 HMAC key + the shared _apply_chain_hmac dispatch; the
# canonical byte form is the modern newline+NFC shape (NOT the log_entries
# pipe form). See _AUDIT_CHAIN_CANONICAL_FIELDS for the per-table field SSOT.
# ---------------------------------------------------------------------------

def _canonical_audit_row(prev_hash: str, fields: tuple) -> bytes:
    """Canonical byte form for a chained audit-EVENT row.

    Form: ``prev_hash`` then each field, NFC-normalised, newline-joined, utf-8 —
    the same shape as :func:`_canonical_gap_row` (the modern audit form). A
    ``None`` value becomes ``""`` (explicit, so a numeric ``0`` is preserved and
    not folded to empty as ``f or ""`` would). Field order is fixed by the
    table's entry in :data:`_AUDIT_CHAIN_CANONICAL_FIELDS` and is a FROZEN
    contract — reordering re-hashes the chain.

    Intentionally distinct from :func:`_canonical_log_row` (pipe-join, NO NFC);
    the two forms are NOT unified (see :func:`_apply_chain_hmac`).
    """
    import unicodedata as _ud
    parts = [prev_hash, *fields]
    return "\n".join(
        _ud.normalize("NFC", "" if f is None else str(f)) for f in parts
    ).encode("utf-8")


def compute_audit_row_hash(
    prev_hash: str,
    fields: tuple,
    *,
    hash_alg: str = CHAIN_HASH_ALG_CURRENT,
    master_key_version: int | None = None,
) -> str:
    """Compute the chain hash for a new chained audit-event row.

    Reuses the EQM-05 HMAC key + the shared :func:`_apply_chain_hmac` dispatch
    (same key as ``log_entries`` / ``audit_gap_events``; no new key surface).
    """
    return _apply_chain_hmac(
        _canonical_audit_row(prev_hash, fields),
        hash_alg=hash_alg,
        master_key_version=master_key_version,
        _what="compute_audit_row_hash",
    )


def get_last_audit_row_hash(conn: sqlite3.Connection, table: str) -> str:
    """Return the newest chain-aware ``row_hash`` for an audit-event table.

    Generalises :func:`get_last_log_row_hash` / :func:`get_last_gap_row_hash`
    over the chained audit tables. ``table`` MUST be a key of
    :data:`_AUDIT_CHAIN_CANONICAL_FIELDS` — that allow-list is also the
    SQL-injection guard for the interpolated table name. Skips prechain rows
    (``row_hash = ''``, i.e. every pre-v43 row) so the migration boundary is not
    a false break (mirrors the ``WHERE row_hash != ''`` filter of the two live
    chains).
    """
    if table not in _AUDIT_CHAIN_CANONICAL_FIELDS:
        raise ValueError(
            f"get_last_audit_row_hash: {table!r} is not a chained audit table"
        )
    row = conn.execute(
        f"SELECT row_hash FROM {table} "
        f"WHERE row_hash != '' "
        f"ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (row["row_hash"] if row else "") or ""


def _chain_insert(
    conn: sqlite3.Connection,
    table: str,
    data: dict[str, Any],
) -> int:
    """INSERT a chained audit-event row — the SSOT for every chained audit write.

     / N-15. ``data`` maps DATA column name -> value (NOT the chain columns).
    The helper (1) reads the chain tail (:func:`get_last_audit_row_hash`),
    (2) computes ``row_hash`` over the table's canonical field tuple
    (:data:`_AUDIT_CHAIN_CANONICAL_FIELDS` — a ``KeyError`` here means a writer
    omitted a canonical field, surfaced loudly rather than silently unhashed),
    (3) INSERTs ``data`` + the 4 chain columns.

    FAIL-CLOSED (PD#8/): always requests ``CHAIN_HASH_ALG_CURRENT``
    (``hmac-sha256-v2``); if no HMAC key is provisioned, :func:`_apply_chain_hmac` raises RuntimeError BEFORE any row
    is written. An audit-event write is a PRIMARY control — never the secretless
    SHA-256 fallback that only the gap-event RECOVERY path (inside an exception
    handler) is permitted.

    TRANSACTION-AWARE (db-sme hard constraint): does NOT commit. The caller owns
    commit timing, so this composes with the in-txn writers ``set_user_disabled``
    (audit.py) and ``set_account_hipaa`` (db/accounts.py), each of which INSERTs
    its audit row inside an explicit ``BEGIN...COMMIT`` atomic with a state
    mutation — a self-committing helper would break that atomicity. Returns the
    new row id (``cur.lastrowid``).
    """
    if table not in _AUDIT_CHAIN_CANONICAL_FIELDS:
        raise ValueError(
            f"_chain_insert: {table!r} is not a chained audit table"
        )
    field_names = _AUDIT_CHAIN_CANONICAL_FIELDS[table]
    canonical_values = tuple(data[name] for name in field_names)
    prev_hash = get_last_audit_row_hash(conn, table)
    version = _get_current_hmac_version()
    hash_alg = CHAIN_HASH_ALG_CURRENT
    row_hash = compute_audit_row_hash(
        prev_hash, canonical_values,
        hash_alg=hash_alg, master_key_version=version,
    )
    cols = [
        *data.keys(), "prev_hash", "row_hash", "hash_alg", "master_key_version",
    ]
    vals = [*data.values(), prev_hash, row_hash, hash_alg, version]
    placeholders = ", ".join(["?"] * len(cols))
    cur = conn.execute(
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
        vals,
    )
    return cur.lastrowid


_DELETION = (
    "a predecessor was deleted (which needs only write access to the table, "
    "not the key)"
)


def _with_row_note(r, row_note, authenticated: bool, text: str) -> str:
    """Append the chain's own row note, when it has one, to a break reason."""
    return text if row_note is None else f"{text}; {row_note(r, authenticated)}"


def _prev_hash_placement(r, hash_index) -> str | None:
    """Where a break row's stored ``prev_hash`` points, as an OBSERVATION.

    Punch  fold 3 (db-529 ADDENDUM 7). ``hash_index`` is
    ``{row_hash: lowest id}`` over EVERY chained row of the table, built before
    the walk, so "names no row in this table" is a claim about the whole table
    and not merely about the rows already walked — a re-ordered row's named
    predecessor can sit at a HIGHER id.

    Narrows, never exculpates: a holder of the key can manufacture any of these
    placements, and on a keyless row anyone with write access can. Returns
    ``None`` for an empty stored ``prev_hash``: that is the chain's genesis
    value, not a hash that names a row.

    A MATCH rules out one thing only — the removal of THIS row's own linkage
    target (hipaa-529-2 Amendment 2). It does NOT rule out deletion as a cause
    of the break: delete row 6 while raced row 7 points at row 5 and both hold
    at once. The text says so; it never reads "deletion is excluded".
    """
    stored = (r["prev_hash"] or "")
    if stored == "":
        return None
    named = hash_index.get(stored) if hash_index else None
    if named is None:
        return (
            "its stored prev_hash names no row in this table: consistent with "
            "a deleted predecessor or a forged row"
        )
    if named < r["id"]:
        return (
            f"its stored prev_hash names row id={named}, still in the table, "
            "which is not its predecessor: this row's own linkage target was not "
            "removed, but a deletion elsewhere in the chain is not excluded; "
            "consistent with a concurrent write between reading the chain tail "
            "and inserting, or with a key holder re-ordering or mimicking one, "
            "who could also have manufactured this match"
        )
    return (
        f"its stored prev_hash names row id={named}, which is not an earlier "
        "row: the table's rows are not in chain order"
    )


def _chain_mismatch_reason(
    r, canonical_values, hash_alg, row_hasher, row_note, *, hash_index=None,
) -> str:
    """Say what a ``row_hash`` mismatch shows, never what caused it.

    Punch . The old single reason called every mismatch tampering. The
    rule (hipaa-529, db-529, da-529 fold-checks), extended at fold 3: a reason
    may NAME only causes that have a producer on THIS table and whose
    precondition this row satisfies, and may EXCLUDE a cause only when the
    benign-cause set for that table is complete. Otherwise the cause is
    "neither confirmed nor excluded".

    - ``row_note`` is passed only by a chain whose own writer can write an
      unlinked row (``verify_gap_chain``). Without it the text says no writer
      on this table produces one BY FAILING: ``_chain_insert`` fails closed.
    - Deleting a predecessor needs only write access to the table. Only a
      forged or re-ordered row that still verifies needs the key.
    - On an HMAC row a second recompute against the stored ``prev_hash``
      separates "content altered" (never an unlinked-row cause, since such a
      row is self-consistent by construction) from "linkage wrong".
    - On a keyless ``sha256`` row nothing is authenticated, so the text says
      the recompute proves nothing; ``row_note`` still reports what the row
      shows, as unauthenticated.
    - Every "a legitimate writer cannot produce this" claim rests on writes
      being SERIALISED, and the lock is process-wide only
      (:mod:`email_triage.web.db_writelock`, ``_write_lock`` at ``web/db_writelock.py:65-69``: a module-level ``threading.RLock``, "One lock for the whole process"). Both writers read the chain tail
      and then INSERT with no ``BEGIN IMMEDIATE`` around the pair, so a second
      process can leave a self-consistent row whose non-empty ``prev_hash`` was
      already stale. The text states that premise and names the concurrent
      write as NOT excluded. Reachability differs by table and the text says
      which: a second process demonstrably writes ``audit_gap_events`` (a
      failed ``@audit_emitter`` call under ``record_cli_admin_op`` from the
      CLI), while for the registry chains cross-process reachability is
      UNPROVEN — not disproven: ``cli.py`` contains zero calls to any of those
      nine emitters, and the app is launched single-worker (no ``workers=`` on
      the ``uvicorn.run`` call and no ``--workers`` / ``WEB_CONCURRENCY`` in the
      tree, measured 2026-09-25). Both SME seats agree the gap chain is where
      the pair is DEMONSTRATED and the registry half is not, so the text reads
      architecturally open, NOT demonstrated. Two uvicorn WORKERS would be two
      processes running every web-route emitter, so this premise is a
      deployment-shape assumption, not a code property.
    - Invariant for the gap chain: NOTHING about the stored ``prev_hash``
      excludes a failed chain-tail read. Marker absence never excludes it (rows
      written before the marker shipped carry none), and neither does a
      non-empty ``prev_hash`` (the race above). Only a keyed row carrying the
      marker evidences it.
    - ``hash_index`` feeds :func:`_prev_hash_placement`, an observation that
      narrows the cause set and never clears the row.
    """
    if hash_alg == "sha256":
        placement = _prev_hash_placement(r, hash_index)
        return _with_row_note(
            r, row_note, False,
            "row_hash mismatch on a keyless (sha256) row: a predecessor was "
            "deleted, the row was altered, or it was forged or re-ordered; a "
            "recompute against its stored prev_hash proves nothing, because "
            "anyone with write access can produce a keyless row"
            + (f". Unauthenticated observation: {placement}" if placement else ""),
        )
    try:
        self_consistent = row_hasher(
            r["prev_hash"] or "", canonical_values, hash_alg,
            r["master_key_version"],
        ) == (r["row_hash"] or "")
    except Exception as second_exc:  # db-529 NEW-2: say so, accuse nothing
        return (
            "row_hash does not match its predecessor, and a second recompute "
            "against its stored prev_hash could not be completed "
            f"({type(second_exc).__name__}); the mismatch is unexplained"
        )
    if not self_consistent:
        return (
            "row content does not match its hash under either its predecessor "
            "or its stored prev_hash: the row was altered in place, or forged "
            "or re-ordered"
        )
    head = (
        "stored prev_hash does not match its predecessor; the row is "
        f"self-consistent under HMAC key version {r['master_key_version']}"
    )
    placement = _prev_hash_placement(r, hash_index)
    where = f"; {placement}" if placement else ""
    if row_note is None:
        return (
            f"{head}. No writer on this table produces an unlinked row by "
            "failing (_chain_insert fails closed), and with writes serialised "
            "by the process-wide write lock a legitimate writer does not "
            f"produce one either, so {_DELETION}, or the row was forged or "
            "re-ordered by someone holding the key. That premise is IN-PROCESS "
            "only: the lock does not span processes and reading the tail and "
            "INSERTing are not one atomic step, so a concurrent write from a "
            "second process is not excluded — but no second-process writer has "
            "been demonstrated for this table, so that exposure is "
            f"architecturally open, NOT demonstrated{where}"
        )
    if (r["prev_hash"] or "") != "":
        return _with_row_note(
            r, row_note, True,
            f"{head}: {_DELETION}, the row was forged or re-ordered by someone "
            "holding the key, or a concurrent write left it linked to a chain "
            f"tail that was already stale{where}",
        )
    return _with_row_note(
        r, row_note, True,
        f"{head} and its stored prev_hash is empty, so it was written as if it "
        "were the first row: consistent with a chain-tail read that failed at "
        "write time, OR with a row forged or re-ordered by someone holding the "
        "key, OR with rows added before it",
    )


def _verify_chain_rows(
    table: str, rows, field_names, row_hasher, *, prechain_is_break: bool = False,
    row_note=None,
) -> dict:
    """Walk one chain's rows id-ascending and report the first break.

    The shared walk behind :func:`verify_audit_chain` and
    :func:`verify_gap_chain` (PD#5: one walk, two canonical forms). Each caller
    passes its own ``row_hasher(expected_prev, values, hash_alg, key_version)``
    so a chain is always re-hashed with the SAME canonical byte form its writer
    used; the forms are frozen and deliberately not unified (see
    :func:`_apply_chain_hmac`).

    ``keyless_count`` counts rows hashed with secretless SHA-256. They verify,
    but anyone with write access could have produced them, so callers must
    show the count, not just ``intact``. ``downgrade_count`` counts
    ``hmac-sha256-v1`` rows after the chain's first ``hmac-sha256-v2`` row
    (``current_alg_from_id``): every writer stamps v2, so none has a current
    producer (N-507 option A). Like ``keyless_count`` it is a signal, not a
    break. ``prechain_is_break`` is for a table
    born with its chain columns and one writer: there a row with no hash
    cannot be pre-chain, so it is reported as the break it is.

    ``break_count`` counts every row that does not verify, not only the first
    (da-529 M5): the table is never pruned, so one standing break would
    otherwise hide every later one behind the same red; only the FIRST break is
    described. ``row_note(row, authenticated)`` is passed only for a chain
    whose writer can write an unlinked row, and adds what the row shows about
    that cause; see :func:`_chain_mismatch_reason`.

    Fold 3 (db-529 ADDENDUM 7): a ``{row_hash: lowest id}`` index over EVERY
    chained row is built BEFORE the walk and handed to
    :func:`_prev_hash_placement`, so a break reason can say whether the row's
    stored ``prev_hash`` still names a row of this table. Built over all rows,
    not the rows walked so far, because a re-ordered row's named predecessor
    can sit at a higher id.
    """
    # Materialised: this function now iterates ``rows`` twice, and a one-shot
    # cursor would leave the index EMPTY, silently dropping the discriminator
    # rather than failing (pattern_a_bare_return_is_a_silent_pass).
    rows = list(rows)
    # Duplicate row_hash values (identical content and predecessor) keep the
    # LOWEST id: the placement text is an observation, so it names the earliest
    # row that could carry that hash rather than choosing between them.
    hash_index: dict[str, int] = {}
    for _r in rows:
        _rh = (_r["row_hash"] or "")
        if _rh:
            hash_index.setdefault(_rh, _r["id"])
    expected_prev = ""
    chain_length = prechain_count = rows_checked = keyless_count = 0
    break_count = 0
    # N-507 option A: a v1 row after this chain's first current-alg row.
    downgrade_count = 0
    current_alg_from_id: int | None = None
    valid_through_id: int | None = None
    first_break_id: int | None = None
    first_break_reason: str | None = None

    for r in rows:
        row_hash = (r["row_hash"] or "")
        if row_hash == "":
            prechain_count += 1
            # Panel P G1b (R11): ``_chain_insert`` always hashes and fails
            # closed, so a blank row ABOVE this table's first hashed row has
            # no producer: it is a row not authenticated by the key, injected
            # or blanked. Below the first hashed row it is pre-v43 history.
            if prechain_is_break or chain_length > 0:
                break_count += 1
                if first_break_id is None:
                    first_break_id = r["id"]
                    first_break_reason = (
                        "row without a chain hash in a table born chained — "
                        "written outside the chain writer"
                        if prechain_is_break else
                        "row without a chain hash above the table's first "
                        "hashed row — no writer produces one (N-609)"
                    )
            continue
        chain_length += 1
        rows_checked += 1
        canonical_values = tuple(r[name] for name in field_names)
        hash_alg = r["hash_alg"] or "hmac-sha256-v1"
        if hash_alg == "sha256":
            keyless_count += 1
        elif hash_alg == CHAIN_HASH_ALG_CURRENT:
            if current_alg_from_id is None:
                current_alg_from_id = r["id"]
        elif hash_alg == _SUPERSEDED_KEYED_ALG and current_alg_from_id is not None:
            downgrade_count += 1
        if hash_alg == CHAIN_HASH_ALG_CURRENT and r["master_key_version"] is None:
            # Panel E db F-1: every writer stores the version a v2 row was
            # keyed under, and _apply_chain_hmac resolves None to the CURRENT
            # version, so a NULLed label would verify until the next rotation.
            # Checked here, not in _apply_chain_hmac, whose callers may pass
            # None on purpose.
            break_count += 1
            if first_break_id is None:
                first_break_id = r["id"]
                first_break_reason = "v2 row has no key version"
            expected_prev = row_hash
            continue
        recompute_error: str | None = None
        try:
            recomputed = row_hasher(
                expected_prev, canonical_values, hash_alg, r["master_key_version"],
            )
        except Exception as e:  # missing key version, unknown alg, …
            from email_triage._errfmt import fmt_exc
            recomputed = None
            recompute_error = f"hash recompute failed: {fmt_exc(e, with_class=True)}"
        if recomputed is not None and recomputed == row_hash:
            valid_through_id = r["id"]
        else:
            break_count += 1
            if first_break_id is None:
                first_break_id = r["id"]
                if recompute_error is None:
                    first_break_reason = _chain_mismatch_reason(
                        r, canonical_values, hash_alg, row_hasher, row_note,
                        hash_index=hash_index,
                    )
                elif row_note is None:
                    first_break_reason = recompute_error
                else:
                    # The key is gone, so nothing in the row is authenticated.
                    first_break_reason = f"{recompute_error}; {row_note(r, False)}"
        # Advance the running chain value to THIS row's stored hash so a single
        # break does not cascade-flag every following row.
        expected_prev = row_hash

    return {
        "table": table,
        "chain_length": chain_length,
        "rows_checked": rows_checked,
        "valid_through_id": valid_through_id,
        "first_break_id": first_break_id,
        "first_break_reason": first_break_reason,
        "break_count": break_count,
        "prechain_count": prechain_count,
        "keyless_count": keyless_count,
        "downgrade_count": downgrade_count,
        "current_alg_from_id": current_alg_from_id,
        "intact": first_break_id is None,
    }


def _not_verified(table: str, reason: str) -> dict:
    """A table-level NOT-intact result for a chain whose rows could not be walked.

    ``intact`` is False with ``first_break_id`` None, deliberately: there is no
    row to point at. Read ``intact``; do not derive it from first_break_id.
    Shared by :func:`verify_audit_chain` and :func:`verify_gap_chain` (punch
     F4: the registry verifier used to raise instead), so both report a
    table they cannot read the same way.
    """
    return {
        "table": table, "chain_length": 0, "rows_checked": 0,
        "valid_through_id": None, "first_break_id": None,
        "first_break_reason": reason, "break_count": 0, "prechain_count": 0,
        "keyless_count": 0, "downgrade_count": 0, "current_alg_from_id": None,
        "missing_id_count": None, "intact": False,
    }


def _missing_id_count(conn: sqlite3.Connection, table: str, rows) -> int | None:
    """Punch  (N-510): how many ids this table issued and no longer holds.

    Every chained table declares ``id INTEGER PRIMARY KEY AUTOINCREMENT``, so
    ``sqlite_sequence.seq`` is the highest id ever issued and no id is reused.
    ``max(seq, MAX(id)) - COUNT(*)`` is the number of issued ids now absent.
    The hash walk cannot see that: a raced row plus deletion of the rows it
    skipped verifies intact (N-510), but the deleted ids stay missing.

    A SIGNAL shown beside ``keyless_count``, not a gate (punch  panel,
    2026-09-25). Measured: four rollback shapes (ROLLBACK, a failed NOT NULL or
    UNIQUE statement inside a committed transaction, ROLLBACK TO a savepoint)
    consume no id; ``INSERT OR IGNORE`` when it ignores and ``INSERT OR
    REPLACE`` when it replaces DO advance ``seq`` and leave a gap that looks
    exactly like a deletion. Neither is used on a chained table, and
    ``test_no_insert_or_ignore_or_replace_on_a_chained_table`` keeps it so.
    Why it stays a signal anyway: whoever can delete rows can also rewrite
    ``sqlite_sequence`` (delete the newest rows and lower ``seq`` and the gap is
    gone), and a restore, a VACUUM or a migration that rebuilds a table and
    re-assigns ids are not measured, so a gate could refuse a deploy on benign
    state. What it does catch is careless or accidental loss, and a deletion by
    someone who does not also rewrite the sequence.

    None, never 0, when it cannot be measured: no ``sqlite_sequence`` table, or
    an EMPTY table with no sequence row (nothing ever inserted). A 0 there would
    read as "no ids missing" about a table nobody counted.

    With rows present and no sequence row, the count falls back to
    ``MAX(id) - COUNT(*)``: a LOWER BOUND that still shows interior gaps but not
    trailing deletions (db-529-2, fold-check of 27ca9f6b). The sequence row is
    ordinary data: the actor who deleted rows can ``DELETE FROM sqlite_sequence``
    too, and returning None then would let that one statement silence the
    signal. On an AUTOINCREMENT table (every chained table, pinned by
    ``test_every_chained_table_declares_autoincrement``) SQLite writes the
    sequence row on the first insert, so rows without one mean it was removed.
    """
    try:
        seq = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
        ).fetchone()
    except DB_OPERATIONAL_ERRORS:
        return None
    ids = {r["id"] for r in rows}
    if seq is None:
        if not ids:
            return None
        return max(0, max(ids) - len(ids))
    return max(0, max([seq[0], *ids]) - len(ids))


def verify_audit_chain(conn: sqlite3.Connection, table: str) -> dict:
    """Verify one chained audit-event table's HMAC chain. Read-only, idempotent.

     / N-15 — generalises :func:`verify_log_chain` over the audit-event
    tables. Walks rows id-ascending; for each chain-aware row (``row_hash !=
    ''``) recomputes the row hash from the RUNNING expected-prev (the previous
    chain row's ``row_hash``) + the table's canonical field tuple
    (:data:`_AUDIT_CHAIN_CANONICAL_FIELDS`) and compares to the stored
    ``row_hash``. Recomputing against the running expected-prev (NOT the stored
    ``prev_hash``) means ONE comparison catches all three tamper shapes: a
    mutated hashed field, a deleted predecessor, and a forged/re-ordered row.

    Per-row dispatch on ``(hash_alg, master_key_version)``: a row whose key
    version is no longer provisioned surfaces as a break ("hash recompute
    failed"), operator-detectable, not silent (mirrors verify_log_chain).

    Prechain rows (``row_hash = ''`` — every pre-v43 row) are counted + skipped,
    never flagged: tamper-evidence is prospective from the v43 deploy, a bounded
    limitation recorded in the §164.316 register.

    A missing or unreadable table is reported NOT intact (punch  F4), not
    raised, so a caller walking every chain still reports the others. The
    reason names no cause: a table removed after the last start and a backup
    snapshot that predates the table both produce it.

    Returns: table, chain_length, rows_checked, valid_through_id, first_break_id,
    first_break_reason, break_count, prechain_count, keyless_count, intact (bool).
    """
    if table not in _AUDIT_CHAIN_CANONICAL_FIELDS:
        raise ValueError(
            f"verify_audit_chain: {table!r} is not a chained audit table"
        )
    field_names = _AUDIT_CHAIN_CANONICAL_FIELDS[table]
    select_cols = [
        "id", "prev_hash", "row_hash", "hash_alg", "master_key_version",
        *field_names,
    ]
    present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if present is None:
        return _not_verified(table, "table missing — the chain cannot be verified")
    try:
        rows = conn.execute(
            f"SELECT {', '.join(select_cols)} FROM {table} ORDER BY id ASC"
        ).fetchall()
    except DB_OPERATIONAL_ERRORS as e:
        from email_triage._errfmt import fmt_exc
        return _not_verified(
            table, f"chain could not be read: {fmt_exc(e, with_class=True)}"
        )

    def _hasher(prev, values, hash_alg, key_version):
        return compute_audit_row_hash(
            prev, values, hash_alg=hash_alg, master_key_version=key_version,
        )

    result = _verify_chain_rows(table, rows, field_names, _hasher)
    result["missing_id_count"] = _missing_id_count(conn, table, rows)
    return result


# N-468 (punch ). The audit_gap_events content columns, in the order
# _canonical_gap_row hashes them. Every written column is hashed: nothing
# UPDATEs or DELETEs a gap row (grep over src/, 2026-09-24). Kept OUT of
# _AUDIT_CHAIN_CANONICAL_FIELDS on purpose: that registry is the set of tables
# written through _chain_insert (and pinned as such); the gap table is a chain
# PRIMITIVE with its own writer, like log_entries.
GAP_CHAIN_TABLE = "audit_gap_events"
_GAP_CHAIN_FIELDS: tuple[str, ...] = (
    "ts", "helper_name", "original_args_redacted", "original_args_hash",
    "exc_type", "exc_msg",
)

# Punch  (N-507): the chained tables where a keyless (``sha256``) row has a
# legitimate producer. Only the gap writer degrades to one, when the chain key
# is unavailable (N-467). Every table written through ``_chain_insert`` is
# hashed with the current keyed alg unconditionally, so a keyless row there has no
# current producer and ``audit verify --all-chains`` (the deploy bake) FAILS
# on it. /compliance stays warn-only: a monitoring surface and a deploy gate
# carry different obligations.
KEYLESS_PERMITTED_TABLES: frozenset[str] = frozenset({GAP_CHAIN_TABLE})


def verify_gap_chain(conn: sqlite3.Connection) -> dict:
    """Verify the ``audit_gap_events`` HMAC chain. Read-only, idempotent.

    N-468 (punch ): the chain was built on every gap write and never
    checked by anything. Same walk and result shape as
    :func:`verify_audit_chain`, re-hashing each row with the gap writer's own
    canonical form (:func:`compute_gap_row_hash`), so writer and verifier
    cannot drift apart. Rows are dispatched on their own ``hash_alg``: an
    ``hmac-sha256-v1`` row needs its key version provisioned; a ``sha256`` row
    (the N-467 degraded form) verifies with no key, and is therefore
    tamper-EVIDENT only against accidental change, not against someone who can
    write the table; the result's ``keyless_count`` says how many there are. No
    anchor or watermark is needed: the table is never pruned.

    Fails CLOSED. A missing table is reported NOT intact: ``init_db`` runs every
    pending migration before the app serves, and migration v38 creates this
    table, so a serving connection is at schema >= v38 and a missing table was
    removed. A restart does NOT recreate it (v38 does not re-run on a migrated
    DB); recovery is a restore or a migration-level repair. A table that cannot
    be read is reported NOT intact too.
    A row with no chain hash is a break, not pre-chain: the table was born with
    its chain columns and has one writer.
    """
    select_cols = [
        "id", "prev_hash", "row_hash", "hash_alg", "master_key_version",
        *_GAP_CHAIN_FIELDS,
    ]
    present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (GAP_CHAIN_TABLE,),
    ).fetchone()
    if present is None:
        return _not_verified(
            GAP_CHAIN_TABLE,
            "table missing — migration v38 created it before the app served, so it "
            "was removed; a restart will NOT recreate it (restore or repair)"
        )
    try:
        rows = conn.execute(
            f"SELECT {', '.join(select_cols)} FROM {GAP_CHAIN_TABLE} ORDER BY id ASC"
        ).fetchall()
    except DB_OPERATIONAL_ERRORS as e:
        from email_triage._errfmt import fmt_exc
        return _not_verified(
            GAP_CHAIN_TABLE, f"chain could not be read: {fmt_exc(e, with_class=True)}"
        )

    def _hasher(prev, values, hash_alg, key_version):
        return compute_gap_row_hash(
            prev, *values, hash_alg=hash_alg, master_key_version=key_version,
        )

    result = _verify_chain_rows(
        GAP_CHAIN_TABLE, rows, _GAP_CHAIN_FIELDS, _hasher, prechain_is_break=True,
        row_note=_gap_break_note,
    )
    result["missing_id_count"] = _missing_id_count(conn, GAP_CHAIN_TABLE, rows)
    return result


def _gap_break_note(r, authenticated: bool) -> str:
    """What a broken gap row shows about a failed chain-tail read (punch ).

    Reports observations and excludes NOTHING (fold 3, hipaa-529-2 amendment,
    which withdrew the fold-2 exclusion). The cause is "neither confirmed nor
    excluded" in every state except a keyed row carrying the writer's marker,
    where it is evidenced. ``authenticated`` is True only when the row verified
    under its key against its stored ``prev_hash``; otherwise (keyless row, key
    no longer provisioned) BOTH bytes this note reads — the marker and the
    stored ``prev_hash`` — are reported as unauthenticated.
    """
    cls = _gap_marker_class(r["exc_msg"])
    marker = f"'{GAP_TAIL_UNREADABLE_MARKER}{cls}]'" if cls else None
    if (r["prev_hash"] or "") != "":
        if authenticated:
            text = (
                "its stored prev_hash is not empty, inside its keyed hash, and "
                "the gap writer stores a non-empty prev_hash only when its read "
                "of the chain tail returned a value"
            )
        else:
            text = (
                "its stored prev_hash is not empty, but that byte is not "
                "authenticated here (a keyless row, or a key that is no longer "
                "provisioned), so anyone with write access could have written it"
            )
        if marker:
            text += (
                f"; its exc_msg nevertheless begins with the writer's {marker} "
                "marker, which the writer sets only when that read FAILED, so "
                "the two bytes disagree about the same write and no enumerated "
                "gap-writer path produces the pair"
            )
        return text + (
            ". Neither byte excludes the cause: reading the chain tail and "
            "INSERTing are not one atomic step, the write lock is process-wide "
            "only, and a second process does write this table (a failed audit "
            "emit from the CLI), so a concurrent write leaves a non-empty "
            "prev_hash that was already stale; the benign-cause set for this "
            "table is not closed — a failed chain-tail read at write time is "
            "neither confirmed nor excluded"
        )
    if marker and authenticated:
        return (
            f"the row carries the gap writer's {marker} marker inside its keyed "
            "hash, which the writer sets only when its chain-tail read failed: "
            "that cause is evidenced (a holder of the key could still have "
            "written it)"
        )
    if marker:
        return (
            f"its exc_msg begins with the gap writer's {marker} marker, but those "
            "bytes are not authenticated here (a keyless row, or a key that is no "
            "longer provisioned), so anyone with write access could have written "
            "them: a failed chain-tail read at write time is neither confirmed "
            "nor excluded"
        )
    return (
        "the row carries no tail-read marker, and rows written before the marker "
        "shipped never carry one: a failed chain-tail read at write time is "
        "neither confirmed nor excluded"
    )


def verify_all_audit_chains(conn: sqlite3.Connection) -> dict[str, dict]:
    """Verify every chained audit table except ``log_entries``. Returns
    ``{table: result}``.

     — count-agnostic over :data:`_AUDIT_CHAIN_CANONICAL_FIELDS`, so a future
    chained event table is verified with no edit here; plus ``audit_gap_events``
    via :func:`verify_gap_chain` (N-468). Feeds the /compliance surface.
    ``log_entries`` keeps its own verifier, :func:`verify_log_chain`, because it
    alone is PRUNED: its anchor re-roots the chain after a prune, and its
    watermark caches progress. Neither applies to any table verified here.
    """
    results = {
        table: verify_audit_chain(conn, table)
        for table in _AUDIT_CHAIN_CANONICAL_FIELDS
    }
    results[GAP_CHAIN_TABLE] = verify_gap_chain(conn)
    # Punch 709 (cycle P hipaa Q3): a revoke committed under the emergency flag has
    # no chained witness, so its table still verifies intact. "Intact" is true of the
    # chain; completeness is a separate fact, reported beside it and never folded
    # into ``intact``.
    try:
        known = known_emergency_revoke_gaps(conn)
    except Exception as exc:
        known = {}
        for table in _EMERGENCY_WITNESS_TABLE.values():
            if table in results:
                results[table]["known_emergency_gaps_error"] = type(exc).__name__
    for table, count in known.items():
        if table in results:
            results[table]["known_emergency_gap_count"] = count
    return results


def verify_log_chain(
    conn: sqlite3.Connection,
    limit: int | None = None,
    since: str | None = None,
    *,
    app_state: Any = None,
) -> dict:
    """Walk log_entries newest-to-oldest (or oldest-to-newest with
    limit on each end) and verify every chain-aware row's row_hash
    matches recomputation against the stored prev_hash + row fields.

    Args:
        conn: open SQLite connection.
        limit: optional cap on number of rows verified.
        since: optional ISO-8601 timestamp. The full chain is still
            walked end-to-end (hash verification is sequential by
            construction), but breaks at rows with ``ts < since`` are
            tolerated and not surfaced. Use to verify a window of
            recent activity without flagging known pre-cutoff history.
        app_state: optional ``starlette.datastructures.State`` (or any
            attribute-bearing object) used as a watermark cache. When
            provided, a previous clean verify result is cached as
            ``app_state.audit_chain_verified =
            {"valid_through_id": int, "expected_prev": str}`` and
            subsequent calls walk only rows above the watermark — the
            verified prefix is taken on trust. A break or any seek
            argument (``limit``, ``since``) bypasses the cache and
            re-walks from the beginning. NOT thread-safe across procs;
            single-process FastAPI app.state is the intended scope.

    Punch 625 (N-609) fixed rule, no config floor (operator 2026-10-22):
    a ``sha256`` row above the derived first-keyed boundary is the N-507
    substitution signature (``post_boundary_keyless_count``, ``audit verify``
    FAILs). Every other ``sha256`` row is UNVERIFIABLE
    (``unverifiable_keyless_count``, ``audit verify`` exits 3): a pre-H-02a
    legacy row and a substitution cannot be told apart until a keyed legacy
    seal vouches for the prefix (punch 669). Zero ``sha256`` rows PASS.

    Returns:
        chain_length:    rows with non-empty row_hash
        rows_checked:    rows actually verified this pass
        valid_through_id: id of the highest-id row with intact chain
        first_break_id:   id of the lowest-id chain-aware row whose
                          stored row_hash differs from recomputed
                          (None if no break found)
        first_break_ts:   ts string of the broken row (None if no break)
        first_break_expected: full expected hash at break (None if no
                              break)
        first_break_found: full stored hash at break (None if no break)
        first_break_reason:  short human-readable description
        prechain_count:  rows whose row_hash is empty (legacy /
                         pre-migration); these are skipped, not
                         flagged
        legacy_chain_length:  rows with ``hash_alg='sha256'`` (legacy
                              pre-H-02a chain); subset of ``chain_length``
        hmac_chain_length:    rows with a keyed ``hash_alg`` (v1 or v2)
                              (H-02a chain); subset of ``chain_length``
        hash_alg_boundary_id: smallest id where ``hash_alg !=`` legacy
                              ('sha256') — the migration boundary;
                              None if entire chain is still SHA-256
        post_boundary_keyless_count: ``sha256`` rows with an id ABOVE
                              ``hash_alg_boundary_id``. Both log writers
                              stamp a keyed alg unconditionally, so
                              no current writer produces one: each is the
                              N-507 substitution signature (a sha256 row's
                              label is not authenticated, so it verifies).
                              Counted, not a break (punch ); ``audit
                              verify`` FAILS on it (N-507 option D).
        unverifiable_keyless_count: every other ``sha256`` row (below the
                              derived boundary, or no keyed row to derive
                              one). Each is a legacy row or a substitution;
                              ``audit verify`` exits 3 on any (punch 625).
        downgrade_count:      ``hmac-sha256-v1`` rows with an id ABOVE
                              ``current_alg_from_id``, the first
                              ``hmac-sha256-v2`` row. Both writers stamp v2,
                              so none is produced (N-507 option A). Counted,
                              not a break; ``audit verify`` FAILS on it.

    On a walk seeded from the watermark cache, the four alg counts above
    describe the WHOLE chain, like ``chain_length``: the trusted prefix is
    counted by SQL (punch ; /compliance passes ``app_state``, so every
    load after the first used to report a false zero).

    Idempotent + read-only.

    H-02a (Cycle 6, 2026-05-23): per-row dispatch on
    ``(hash_alg, master_key_version)``. Legacy SHA-256 rows verify via
    :func:`_compute_log_row_hash_sha256`; new HMAC-SHA256 rows verify
    via :func:`compute_log_row_hash` with the explicit
    ``master_key_version`` from the row. A row whose
    ``master_key_version`` has no entry in the HMAC registry (e.g.,
    operator deleted ``master_key_history:v{N}`` from secrets_store)
    surfaces as a chain break with reason "missing HMAC key for
    master_key_version=N" — operator-detectable, not silent.
    """
    # Late-bind get_setting from web/db (settings-table helper; the dep
    # is unidirectional db.audit -> web.db so no cycle).
    from email_triage.web.db import get_setting

    # ---- Watermark cache lookup (fast-path) -----------------------
    # Only the no-arg verify (full clean walk) caches and only the
    # no-arg verify reads the cache. ``limit``/``since`` callers want
    # an explicit window — never use the cache for them.
    cache_active = (
        app_state is not None
        and limit is None
        and since is None
    )
    cached: dict | None = None
    if cache_active:
        cached = getattr(app_state, "audit_chain_verified", None)

    # ---- Anchor seed (post-prune chain start) ---------------------
    # When the oldest chain-aware rows have been pruned, the new head's
    # ``prev_hash`` is no longer "" — it points at a row that no longer
    # exists in the table. Seed ``expected_prev`` from the anchor that
    # the pruner stamped so the boundary doesn't look like a break.
    anchor = None
    try:
        anchor = get_setting(conn, _AUDIT_CHAIN_ANCHOR_KEY)
    except Exception:
        anchor = None

    # ---- Build the row iterator ----------------------------------
    # H-02a: SELECT widened to include hash_alg + master_key_version.
    # On pre-H-02a DBs the ALTER TABLE migration filled defaults
    # ('sha256', 0) for every row; the legacy verifier path handles
    # those correctly via _compute_log_row_hash_sha256.
    if (
        cached is not None
        and isinstance(cached, dict)
        and "valid_through_id" in cached
        and "expected_prev" in cached
        and cached["valid_through_id"] is not None
    ):
        # Skip rows already verified clean.
        rows = conn.execute(
            "SELECT id, ts, level, logger, message, extra_json, "
            "       prev_hash, row_hash, hash_alg, master_key_version, created_at "
            "FROM log_entries WHERE id > ? ORDER BY id ASC",
            (int(cached["valid_through_id"]),),
        ).fetchall()
        # Resume the walk; pre-watermark chain is on trust.
        expected_prev = cached["expected_prev"] or ""
        # rows-already-verified contribute to chain_length on prior passes
        # but for THIS call rows_checked is just what we walk now.
        seeded_from_cache = True
    else:
        rows = conn.execute(
            "SELECT id, ts, level, logger, message, extra_json, "
            "       prev_hash, row_hash, hash_alg, master_key_version, created_at "
            "FROM log_entries ORDER BY id ASC"
        ).fetchall()
        # If an anchor exists, seed from the head row's recorded
        # prev_hash. The anchor's head_id may already be gone (next
        # prune cycle); the anchor still holds the prev_hash it had
        # when stamped, which is what we need.
        if anchor and isinstance(anchor, dict):
            expected_prev = anchor.get("head_prev_hash", "") or ""
        else:
            expected_prev = ""
        seeded_from_cache = False

    chain_length = 0
    prechain_count = 0
    rows_checked = 0
    legacy_chain_length = 0
    hmac_chain_length = 0
    post_boundary_keyless_count = 0
    hash_alg_boundary_id: int | None = None
    # Punch 625 (N-609): a sha256 row the derived boundary cannot place.
    unverifiable_keyless_count = 0
    # N-507 option A: the first current-alg (v2) row, and v1 rows after it.
    downgrade_count = 0
    current_alg_from_id: int | None = None
    _keyed_in = ", ".join("?" * len(KEYED_CHAIN_HASH_ALGS))
    if seeded_from_cache:
        # Punch : the boundary may sit in the trusted prefix. Seed it
        # first so a keyless row walked above the watermark is classified
        # against the real boundary, not against "none seen yet". The same
        # holds for the first v2 row and a v1 row walked above it.
        _wm = int(cached["valid_through_id"])  # type: ignore[index]
        hash_alg_boundary_id = conn.execute(
            "SELECT MIN(id) FROM log_entries WHERE row_hash != '' "
            f"AND hash_alg IN ({_keyed_in}) AND id <= ?",
            (*KEYED_CHAIN_HASH_ALGS, _wm),
        ).fetchone()[0]
        current_alg_from_id = conn.execute(
            "SELECT MIN(id) FROM log_entries WHERE row_hash != '' "
            "AND hash_alg = ? AND id <= ?",
            (CHAIN_HASH_ALG_CURRENT, _wm),
        ).fetchone()[0]
    last_valid_id: int | None = (
        int(cached["valid_through_id"]) if seeded_from_cache else None
    )
    first_break_id: int | None = None
    first_break_ts: str | None = None
    first_break_expected: str | None = None
    first_break_found: str | None = None
    first_break_reason: str | None = None
    # Punch 625 rule (a): ``id`` is outside the row hash (_canonical_log_row),
    # so a renumber below 1 could slip under any boundary; no writer issues
    # one. Checked by SQL over the whole table, because a cached walk reads
    # only ids above its watermark.
    below_one = conn.execute(
        "SELECT id, ts, row_hash FROM log_entries WHERE id < 1 ORDER BY id LIMIT 1"
    ).fetchone()
    if below_one is not None:
        first_break_id = below_one["id"]
        first_break_ts = below_one["ts"]
        first_break_found = below_one["row_hash"]
        first_break_reason = (
            f"log_entries row at id={below_one['id']}: no writer issues an id "
            f"below 1, and the id is outside the row hash (N-609)"
        )
    # Panel P G1 (N-609): a blank-row_hash row skips the link check, so it
    # must have a legitimate writer. The only one is the gap sentinel
    # (triage_logging.is_gap_sentinel_row, the writer's own shape). Any other
    # blank row above the first hashed row is a break; one below it is
    # pre-chain history or a fabrication, which cannot be told apart
    # (UNVERIFIABLE). The first hashed id is read over the whole table so
    # both count sites classify against the same boundary.
    first_hashed_id = conn.execute(
        "SELECT MIN(id) FROM log_entries WHERE row_hash != ''"
    ).fetchone()[0]
    gap_sentinel_count = 0
    unverifiable_blank_count = 0

    def _blank_row(r, first_hashed_id) -> bool:
        """Classify one blank-hash row. True when it is a break.

        ``first_hashed_id`` is passed, and the predicate imported here, so
        every name this closure reads is bound in its own scope or declared
        ``nonlocal`` (the N-338c resolver does not chain enclosing locals).
        The import stays function-local: triage_logging must not be a
        module-level import of db.audit."""
        from email_triage.triage_logging import is_gap_sentinel_row
        nonlocal gap_sentinel_count, unverifiable_blank_count
        nonlocal first_break_id, first_break_ts, first_break_expected
        nonlocal first_break_found, first_break_reason
        if first_hashed_id is None:
            # G1b: with no hashed row left, even sentinel-only is wholesale
            # destruction until shown otherwise: UNVERIFIABLE, never PASS.
            unverifiable_blank_count += 1
            return False
        if is_gap_sentinel_row(r):
            # Counted and shown, never silent. The walk does NOT reseed here:
            # expected_prev carries across, so a sentinel planted where a
            # keyed row was deleted still breaks at the next row's link.
            gap_sentinel_count += 1
            return False
        if r["id"] < first_hashed_id:
            unverifiable_blank_count += 1
            return False
        if first_break_id is None or r["id"] < first_break_id:
            first_break_id = r["id"]
            first_break_ts = r["ts"]
            first_break_expected = None
            first_break_found = r["row_hash"]
            first_break_reason = (
                f"blank row_hash at id={r['id']} above the first hashed row "
                f"(id={first_hashed_id}), and not the gap sentinel's shape: no "
                f"writer produces one (N-609)"
            )
        return True

    for r in rows:
        if not r["row_hash"]:
            prechain_count += 1
            if _blank_row(r, first_hashed_id):
                break
            continue
        chain_length += 1
        rows_checked += 1
        row_hash_alg = r["hash_alg"] or "sha256"
        row_mkv = int(r["master_key_version"] or 0)
        if row_hash_alg == "sha256":
            legacy_chain_length += 1
            if hash_alg_boundary_id is not None:
                post_boundary_keyless_count += 1
            else:
                unverifiable_keyless_count += 1
        elif row_hash_alg in KEYED_CHAIN_HASH_ALGS:
            hmac_chain_length += 1
            if hash_alg_boundary_id is None:
                hash_alg_boundary_id = r["id"]
            if row_hash_alg == CHAIN_HASH_ALG_CURRENT:
                if current_alg_from_id is None:
                    current_alg_from_id = r["id"]
            elif current_alg_from_id is not None:
                downgrade_count += 1
        # Verify prev_hash links cleanly to predecessor row's hash.
        if r["prev_hash"] != expected_prev:
            # Tolerate breaks before the --since cutoff: hash
            # verification is sequential, so we can't skip the row,
            # but we can suppress reporting it. Resync expected_prev
            # to the stored prev_hash so subsequent rows compare
            # against actual chain state, and continue walking.
            if since is not None and r["ts"] < since:
                expected_prev = r["row_hash"]
                last_valid_id = r["id"]
                continue
            if first_break_id is None:
                first_break_id = r["id"]
                first_break_ts = r["ts"]
                first_break_expected = expected_prev
                first_break_found = r["prev_hash"]
                first_break_reason = (
                    f"prev_hash mismatch at id={r['id']}: "
                    f"expected {expected_prev[:12]}..., "
                    f"stored {r['prev_hash'][:12]}..."
                )
            break
        # H-02a: per-row dispatch on hash_alg. Legacy rows use the
        # SHA-256 helper directly (zero-key); HMAC rows go through
        # compute_log_row_hash with explicit master_key_version so the
        # right historical subkey is selected. Either path bubbles up
        # RuntimeError if a HMAC row references a key version that has
        # been deleted from the secrets_store history.
        try:
            if row_hash_alg == "sha256":
                recomputed = _compute_log_row_hash_sha256(
                    r["prev_hash"], r["ts"], r["level"], r["logger"],
                    r["message"], r["extra_json"],
                )
            else:
                recomputed = compute_log_row_hash(
                    r["prev_hash"], r["ts"], r["level"], r["logger"],
                    r["message"], r["extra_json"],
                    hash_alg=row_hash_alg,
                    master_key_version=row_mkv,
                )
        except (RuntimeError, ValueError) as e:
            # Surface as chain break, not exception, so the verifier
            # remains a read-only diagnostic. Operator gets the precise
            # error in first_break_reason.
            if since is not None and r["ts"] < since:
                expected_prev = r["row_hash"]
                last_valid_id = r["id"]
                continue
            if first_break_id is None:
                first_break_id = r["id"]
                first_break_ts = r["ts"]
                first_break_expected = None
                first_break_found = r["row_hash"]
                first_break_reason = (
                    f"recompute failed at id={r['id']} "
                    f"(hash_alg={row_hash_alg}, "
                    f"master_key_version={row_mkv}): {e}"
                )
            break
        if recomputed != r["row_hash"]:
            if since is not None and r["ts"] < since:
                expected_prev = r["row_hash"]
                last_valid_id = r["id"]
                continue
            if first_break_id is None:
                first_break_id = r["id"]
                first_break_ts = r["ts"]
                first_break_expected = recomputed
                first_break_found = r["row_hash"]
                first_break_reason = (
                    f"row_hash mismatch at id={r['id']} "
                    f"(hash_alg={row_hash_alg}, "
                    f"master_key_version={row_mkv}): "
                    f"recomputed {recomputed[:12]}..., "
                    f"stored {r['row_hash'][:12]}..."
                )
            break
        last_valid_id = r["id"]
        expected_prev = r["row_hash"]
        if limit is not None and rows_checked >= limit:
            break

    # When seeded from the watermark cache the per-pass walk only saw
    # rows above the watermark. Restore the cumulative ``chain_length``
    # by adding the trusted prefix size so consumers (compliance page,
    # daily health email) don't see a sudden drop after the first cache
    # hit. Punch : the legacy/hmac/post-boundary counts are restored
    # the same way (the boundary was seeded from the prefix before the
    # walk). Before  they described only this walk, so /compliance
    # showed 0 keyless rows on every load after the first. The alg
    # predicate mirrors the loop's ``r["hash_alg"] or "sha256"``.
    if seeded_from_cache:
        watermark = int(cached["valid_through_id"])  # type: ignore[index]
        prefix = conn.execute(
            "SELECT COUNT(*) AS c, "
            "  COALESCE(SUM(COALESCE(NULLIF(hash_alg, ''), 'sha256') = 'sha256'), 0) AS legacy, "
            f"  COALESCE(SUM(hash_alg IN ({_keyed_in})), 0) AS hmac, "
            "  COALESCE(SUM(COALESCE(NULLIF(hash_alg, ''), 'sha256') = 'sha256' "
            "               AND ? IS NOT NULL AND id > ?), 0) AS post_boundary, "
            "  COALESCE(SUM(COALESCE(NULLIF(hash_alg, ''), 'sha256') = 'sha256' "
            "               AND NOT (? IS NOT NULL AND id > ?)), 0) AS unverifiable, "
            "  COALESCE(SUM(hash_alg = ? AND ? IS NOT NULL AND id > ?), 0) AS downgrade "
            "FROM log_entries WHERE row_hash != '' AND id <= ?",
            (*KEYED_CHAIN_HASH_ALGS,
             hash_alg_boundary_id, hash_alg_boundary_id,
             hash_alg_boundary_id, hash_alg_boundary_id,
             _SUPERSEDED_KEYED_ALG, current_alg_from_id, current_alg_from_id,
             watermark),
        ).fetchone()
        if prefix:
            chain_length += int(prefix["c"])
            legacy_chain_length += int(prefix["legacy"])
            hmac_chain_length += int(prefix["hmac"])
            post_boundary_keyless_count += int(prefix["post_boundary"])
            unverifiable_keyless_count += int(prefix["unverifiable"])
            downgrade_count += int(prefix["downgrade"])
        # Panel P G1: the trusted prefix's blank rows, classified by the same
        # predicate. A blank row written into the prefix after it was cached
        # (into an id gap) would otherwise never be seen.
        for b in conn.execute(
            "SELECT id, ts, level, logger, message, extra_json, prev_hash, row_hash, "
            "hash_alg, master_key_version, created_at "
            "FROM log_entries WHERE (row_hash IS NULL OR row_hash = '') "
            "AND id <= ? ORDER BY id ASC",
            (watermark,),
        ).fetchall():
            prechain_count += 1
            _blank_row(b, first_hashed_id)

    # Cache the watermark + chain tail when this was a clean full verify.
    if (
        cache_active
        and first_break_id is None
        and last_valid_id is not None
    ):
        try:
            app_state.audit_chain_verified = {
                "valid_through_id": int(last_valid_id),
                "expected_prev": expected_prev or "",
            }
        except Exception as _swallow_exc:
            # ``app_state`` may be a frozen mapping or otherwise
            # unwritable; cache miss is acceptable.
            from email_triage._errfmt import fmt_exc
            from email_triage.triage_logging import get_logger as _gl
            _gl("db.audit").debug(
                "audit chain verified-cache write failed (cache miss accepted)",
                error=fmt_exc(_swallow_exc),
            )
    elif cache_active and first_break_id is not None:
        # Break detected — invalidate the cache so the next call
        # re-walks from the beginning.
        try:
            app_state.audit_chain_verified = None
        except Exception as _swallow_exc:
            from email_triage._errfmt import fmt_exc
            from email_triage.triage_logging import get_logger as _gl
            _gl("db.audit").debug(
                "audit chain verified-cache clear failed",
                error=fmt_exc(_swallow_exc),
            )

    # Panel P G2: the ONE verdict every consumer reads (the CLI, /compliance,
    # audit reconcile), so none hand-rolls PASS/FAIL/UNVERIFIABLE (PD-5).
    if (first_break_id is not None or post_boundary_keyless_count
            or downgrade_count):
        verdict = "fail"
    elif unverifiable_keyless_count or unverifiable_blank_count:
        verdict = "unverifiable"
    else:
        verdict = "pass"

    return {
        "verdict": verdict,
        "chain_length": chain_length,
        "rows_checked": rows_checked,
        "valid_through_id": last_valid_id,
        "first_break_id": first_break_id,
        "first_break_ts": first_break_ts,
        "first_break_expected": first_break_expected,
        "first_break_found": first_break_found,
        "first_break_reason": first_break_reason,
        "prechain_count": prechain_count,
        # H-02a additions
        "legacy_chain_length": legacy_chain_length,
        "hmac_chain_length": hmac_chain_length,
        "hash_alg_boundary_id": hash_alg_boundary_id,
        # Punch  / N-507: keyless rows after the first keyed row.
        "post_boundary_keyless_count": post_boundary_keyless_count,
        # Punch 625 (N-609): sha256 rows no keyed boundary follows (exit 3).
        "unverifiable_keyless_count": unverifiable_keyless_count,
        # Panel P G1: blank-hash rows. Gap sentinels are counted and shown,
        # never silent; a non-sentinel blank row below the first hashed row is
        # UNVERIFIABLE (one above it is the break above).
        "gap_sentinel_count": gap_sentinel_count,
        "unverifiable_blank_count": unverifiable_blank_count,
        "first_hashed_id": first_hashed_id,
        # N-507 option A: v1 rows after the first v2 row (downgrade signal).
        "downgrade_count": downgrade_count,
        "current_alg_from_id": current_alg_from_id,
    }


# ---------------------------------------------------------------------------
#  Deliverable 3 — audit-emitter gap-event sentinel
# ---------------------------------------------------------------------------
#
# Background
# ----------
# When a `@db_write` audit-emitter helper raises mid-write (the live
# the test container  cascade reproduces exactly this: SQLITE_MISUSE /
# cursor-corruption inside `acquire_db_lock` leaks into other
# `@db_write` calls), the audit row never lands and the operator has
# NO visible trace of the dropped event. §164.312(b) Audit Controls
# requires the lost emit be visible somewhere; §164.312(c)(1)
# Integrity Controls requires the visibility-row itself be tamper-
# evident.
#
# This is the parallel of the SQLiteLogHandler `#239e` drop-sentinel:
# when the primary write fails, write a smaller "we tried, here's
# what we tried" row to a separate table that is harder to corrupt
# (because it's hash-chained and goes through the same RLock-
# serialised `@db_write` envelope).
#
# Mechanism
# ---------
# The `@audit_emitter` decorator marks a helper as an audit-row
# emitter. It is INNER to `@db_write`; the wrapper checks
# ``getattr(fn, "_is_audit_emitter", False)`` in its except clause
# and, after the existing rollback discipline, writes an
# ``audit_gap_events`` row recording the failed emit. The gap-event
# write itself is HMAC-chained per `compute_log_row_hash` /
# `get_last_gap_row_hash` (REUSING the same chain key as
# `log_entries` per EQM-05 — no new key, no new key-rotation
# surface).
#
# Per-emitter redaction map keeps PHI out of the gap-table per
# §164.502(a) Minimum Necessary + §164.514(b)(2)(i) Safe-Harbor:
# typed numeric IDs + bounded-enum strings are stored verbatim;
# free-text + addressing identifiers (email, IP, user-agent, detail)
# are SHA-256 hashed only. The hipaa-sme verdict 2026-05-25
# documents the per-emitter IN/OUT split.
#
# H-12 register row anchored: §164.312(b) + §164.312(c)(1) +
# §164.502(a) + §164.514(b)(2)(i).

import hashlib as _hashlib  # local-style import per audit.py convention

# Schema: the ``audit_gap_events`` table is defined ONLY by migration v38
# (``web/migrations.py``). Punch  removed an uncalled ``_*_DDL`` copy that
# sat here: nothing ran it, so a schema fix made in it would not have taken
# effect. It was deliberately NOT wired into ``web/db.py``'s ``_ALL_DDL``: that
# would make every boot recreate a dropped table, and N-468's gap verifier
# reports a missing table as NOT intact precisely because a restart does not
# recreate it (the repair shape for a dropped table is punch 's open
# decision). Pin: ``tests/test_punch528_ddl_constant_has_caller_pin.py``.


# Per-emitter redaction map. For each emitter, the field-name lists
# split arguments into:
#   - "in":   stored verbatim in ``original_args_redacted`` (typed
#             numeric IDs, bounded-enum strings — Safe-Harbor-class)
#   - "out":  excluded entirely from the redacted payload (free-text,
#             addressing identifiers — PHI-class). Their values still
#             contribute to ``original_args_hash`` so a future
#             investigator can match the gap row against a hash-
#             matched payload from elsewhere (log_entries, request
#             trace) without storing the PHI itself.
#
# hipaa-sme verdict 2026-05-25 — §164.502(a) Minimum Necessary +
# §164.514(b)(2)(i) Safe-Harbor.
_AUDIT_EMITTER_REDACTION_MAP: dict[str, dict[str, set[str]]] = {
    "record_user_status_event": {
        "in":  {"target_user_id", "actor_user_id", "event"},
        "out": {"reason"},
    },
    "record_auth_event": {
        "in":  {"event_type", "user_id", "key_id", "outcome"},
        "out": {"email", "ip", "user_agent", "detail"},
    },
    # Punch  — the atomic hardware-key GRANT funnel. ``user_id`` is a typed
    # id and ``sign_count`` a counter => IN. The credential material
    # (``credential_id`` / ``public_key`` / ``aaguid``), the authenticator
    # ``transports`` list, the operator-typed free-text ``nickname`` and the
    # addressing fields (``email`` / ``ip`` / ``user_agent``) => OUT/hash-only,
    # mirroring record_auth_event's split. Keyword-only after ``conn``.
    "record_hardware_key_registration": {
        "in":  {"user_id", "sign_count"},
        "out": {"credential_id", "public_key", "transports", "aaguid",
                "nickname", "email", "ip", "user_agent"},
    },
    # Punch 627 — the atomic dev-key GRANT funnel. ``created_by_user_id`` is a
    # typed id => IN. The key material (``public_key`` / ``fingerprint``), the
    # operator-typed ``name``, the allowlisted addresses, ``expires_at`` and the
    # addressing fields (``email`` / ``ip``) => OUT/hash-only, mirroring
    # record_hardware_key_registration's split. Keyword-only after ``conn``.
    "record_dev_key_registration": {
        "in":  {"created_by_user_id"},
        "out": {"name", "public_key", "fingerprint", "email_allowlist",
                "expires_at", "email", "ip"},
    },
    # Punch 668 -- the atomic user-create GRANT funnel. ``role`` and ``source``
    # are bounded enums and ``actor_user_id`` a typed id => IN. The new user's
    # ``email`` / ``name`` / ``notify_email`` and the actor's ``actor_email`` /
    # ``ip`` are addressing identifiers or operator free text => OUT/hash-only,
    # mirroring record_dev_key_registration's split. Keyword-only after ``conn``.
    "record_user_creation": {
        "in":  {"role", "actor_user_id", "source"},
        "out": {"email", "name", "notify_email", "actor_email", "ip"},
    },
    # Punch 674 -- the user-update funnel. ``user_id`` / ``actor_user_id`` are
    # typed ids and ``role`` / ``source`` bounded enums => IN; the addresses
    # (``email`` / ``notify_email`` / ``actor_email``), the free-text ``name``
    # and ``ip`` => OUT/hash-only (record_user_creation's split). Panel Z
    # MUST-Z1-1: this entry also covers the ``user_email_changed`` witness (it
    # is written inside this funnel, the UI and CLI writers both route here),
    # so a failed email change's gap row keeps the new address out.
    "record_user_update": {
        "in":  {"user_id", "role", "actor_user_id", "source", "_in_caller_txn"},
        "out": {"name", "email", "notify_email", "actor_email", "ip"},
    },
    # Punch 673 -- the atomic account-delegate grant / revoke funnels. Every
    # argument but ``ip`` is a typed id => IN; ``ip`` is an addressing
    # identifier => OUT/hash-only. Keyword-only after ``conn``.
    "record_account_delegate_grant": {
        "in":  {"account_id", "user_id", "granted_by"},
        "out": {"ip"},
    },
    # N-520 step 2 — the generic witnessed-state funnel. ``operation`` is a
    # bounded code-literal slug => IN. The two callables are code, not data;
    # they can close over request values, so they are hash-only => OUT.
    "record_witnessed_state_change": {
        "in":  {"operation"},
        "out": {"state_txn", "witness_txn"},
    },
    "record_account_delegate_revoke": {
        "in":  {"account_id", "user_id", "revoked_by"},
        "out": {"ip"},
    },
    "record_hipaa_boundary": {
        "in":  {"scope", "direction", "actor_id"},
        "out": {"reason"},
    },
    # N-466 — the atomic system-flip funnel. ``settings_key`` is an
    # operator-namespaced constant and ``direction``/``actor_id`` are a
    # bounded enum + typed id (Safe-Harbour class) => IN. ``new_runtime`` is
    # the whole settings blob (operator-authored free-text log_level etc., and
    # a shape that may widen) and ``reason`` is free text => OUT/hash-only.
    # Keyword-only after ``conn``, so no positional-bind branch is needed in
    # ``_bind_args_to_emitter_signature``.
    "record_system_hipaa_flip": {
        "in":  {"settings_key", "direction", "actor_id"},
        "out": {"new_runtime", "reason"},
    },
    # N-540 — the runtime-settings funnel. Same split as the flip funnel:
    # ``settings_key`` is a constant and ``actor_user_id`` a typed id => IN;
    # ``new_runtime`` is the whole blob and ``actor_email`` an addressing
    # identifier => OUT/hash-only. Keyword-only after ``conn``.
    "record_runtime_settings_change": {
        "in":  {"settings_key", "actor_user_id"},
        "out": {"new_runtime", "actor_email"},
    },
    # N-539 — the watch-group save funnel. ``actor_user_id``,
    # ``target_account_ids`` (typed ids) and ``enabled`` (bool) => IN.
    # ``name``, ``filter_`` (sender addresses, subject terms) and ``actions``
    # are operator free text; ``group_id`` and ``route`` can carry a legacy
    # ``legacy:<creator>:<name>`` key => OUT/hash-only. Keyword-only after
    # ``conn``.
    "record_watch_group_save": {
        "in":  {"actor_user_id", "target_account_ids", "enabled"},
        "out": {"group_id", "name", "filter_", "actions", "route"},
    },
    # N-539 — the watch-group delete funnel; same split as the save funnel.
    # ``group`` (allow-list step 2, B4) is the caller's resolved group dict:
    # its ``group_id`` can be a legacy ``legacy:<creator>:<name>`` key and its
    # ``representative`` carries operator free text => OUT/hash-only.
    "record_watch_group_delete": {
        "in":  {"actor_user_id"},
        "out": {"group", "route"},
    },
    # Punch 414 -- the wizard preview's live-render witness. ``actor_user_id``
    # and ``account_id`` are typed ids and ``envelope_flow_id`` an opaque
    # non-PHI flow id (spec DEC-3) => IN. The route is a constant, not a
    # parameter. Keyword-only after ``conn``.
    "record_webhook_preview_live_render": {
        "in":  {"actor_user_id", "account_id", "envelope_flow_id"},
        "out": set(),
    },
    "record_hipaa_access_event": {
        "in":  {"actor_user_id", "account_id", "operation", "outcome"},
        "out": {"detail"},
    },
    # §164.312(b) finalise-gap (hipaa-sme + db-sme). update_hipaa_access_event
    # finalises a record_hipaa_access_event-emitted row. ``detail`` is the SAME
    # free-text-may-contain-PHI field as on the creation event → OUT/hash-only
    # (mirror the split exactly). ``event_id`` (typed numeric id) + ``outcome``
    # (bounded-enum) are Safe-Harbor-class → IN.
    "update_hipaa_access_event": {
        "in":  {"event_id", "outcome"},
        "out": {"detail"},
    },
    "record_discover_run": {
        "in":  {"account_id", "actor_user_id", "scanned_count",
                "errors_count", "elapsed_secs"},
        # account_name + folders names are operator-readable strings
        # that may include PHI-adjacent labels (folder names from
        # user mailboxes).
        "out": {"account_name", "folders"},
    },
    "record_api_key_event": {
        "in":  {"event", "key_id", "actor_user_id", "target_user_id",
                "source"},
        # API-key name is operator-chosen and may include identifying
        # text — hash-only. Punch 710: ``actor_email`` is an addressing
        # identifier — hash-only.
        "out": {"name", "expires_at", "actor_email"},
    },
    "record_access_event": {
        "in":  {"actor_user_id", "method", "route", "account_id",
                "status_code", "outcome"},
        # message_id + detail + request_id are PHI-adjacent — hash-only.
        "out": {"message_id", "detail", "request_id"},
    },
    # A2 (census 2026-06-09; hipaa-sme re-ruling) — two emitters completed.
    # set_user_disabled writes user_status_events (PIN-2 audit table); its
    # redaction split mirrors record_user_status_event (same table). Note
    # ``disabled`` (the bool arg) is the IN field, NOT ``event`` (a derived
    # local that never binds).
    "set_user_disabled": {
        "in":  {"target_user_id", "actor_user_id", "disabled"},
        "out": {"reason"},
    },
    # record_style_distill_event writes style_distill_events — "one audit row
    # per distillation, sibling to hipaa_access_events" (§164.502(e) cloud
    # PHI-egress accounting). ``was_cloud`` is the egress signal and MUST be
    # readable in the gap row. recipient_hash is a correlatable per-contact
    # identifier → hash-only (Minimum Necessary).
    "record_style_distill_event": {
        "in":  {"account_id", "actor_user_id", "backend_id", "backend_type",
                "was_cloud", "outcome", "kind", "scrubber_degraded",
                "error_class", "latency_ms", "layer1_drops",
                "layer2_matches", "layer3_entities"},
        "out": {"recipient_hash"},
    },
    #  — regulatory clock transition emitter. instance_id/event_kind/actor/
    # state/rung are typed ids + bounded enums; delivered_to_ref is a non-PHI
    # contact id → all IN (readable in the gap row). `detail` is short free-text
    # that MAY carry PHI → OUT (hash-only). record_clock_ack delegates to
    # record_clock_event, so a gap fires under THIS name for both.
    "record_clock_event": {
        "in":  {"instance_id", "event_kind", "actor_user_id", "from_state",
                "to_state", "escalation_rung", "delivered_to_ref"},
        "out": {"detail"},
    },
    # N-349b Item 1 R31 (2026-07-07) — HMAC clobber bypass consumption
    # emitter. All 3 fields are Safe-Harbor-class: `secret_key` is an
    # operator-namespaced settings key ("watch_hmac:<uuid>"),
    # `actor_user_id` is a typed row id, `watch_id` is a UUID. No PHI
    # egress path even in the gap row. No OUT-fields.
    "record_hmac_clobber_bypass_consumed": {
        "in":  {"secret_key", "actor_user_id", "watch_id"},
        "out": set(),
    },
    # N-157 (2026-07-09) — CLI admin-op chain-write emitter. `ts` is an
    # ISO timestamp, `command` is an operator-namespaced dotted CLI verb
    # ("user.create", "secrets.rotate-master-key"), `phase` is a bounded
    # enum ("start", "end"). All three are Safe-Harbor-class → IN.
    # `allow_unaudited` is the fail-loud gate bypass flag — a bounded
    # bool (1 bit, Safe-Harbor by construction, no PHI vector) promoted
    # to a dedicated top-level IN field per DA fold Fix #2 +
    # hipaa-sme §164.502(b) calibration 2026-07-09 (NET-REDUCTION of
    # the investigation surface — bypass bit stays inside the HMAC-
    # chained envelope, not spread across external CLI-invocation logs).
    # `extra` is a NESTED pre-redacted dict — the caller at
    # `cli.py::_emit_cli_audit_event` has already applied the
    # `_SAFE_ARG_KEYS` allow-list (bounded-string / typed-int / bool /
    # path-as-string). Kept OUT for a conservative gap-row posture — the
    # raw hash still binds it so an investigator can cross-match against
    # the log_entries row a successful write would have produced. The
    # SAFE_ARG_KEYS allow-list is the SSOT for what may appear inside
    # `extra` — a new key added there without a redaction-map review is
    # the CIDI-drift class Prime Directive #5 catches.
    "record_cli_admin_op": {
        "in":  {"ts", "command", "phase", "allow_unaudited"},
        "out": {"extra"},
    },
}


def _bind_args_to_emitter_signature(
    helper_name: str,
    args: tuple,
    kwargs: dict,
) -> dict:
    """Map positional + keyword args of an audit-emitter call to a
    name→value dict, using the documented signatures.

    Doing this without ``inspect.signature`` because the wrapper has
    already gone through ``@db_write``'s ``functools.wraps`` — we
    have the helper name, not a clean reference to the original
    signature object. The mapping below mirrors the source-of-truth
    signatures in this module (lines 681/804/873/982/1035/1145/1203).

    Returns an empty dict for an unknown helper name (defensive: the
    redaction map below will then redact everything as "unknown",
    which is the safe-fail mode).
    """
    # First positional arg is always ``conn`` — skip it.
    pos = list(args[1:])
    out: dict = dict(kwargs)
    # Helpers whose extras after ``conn`` are positional:
    if helper_name == "record_user_status_event":
        keys = ["target_user_id", "actor_user_id", "event", "reason"]
        for i, v in enumerate(pos):
            if i < len(keys):
                out[keys[i]] = v
    elif helper_name == "record_hipaa_boundary":
        keys = ["scope", "direction", "actor_id", "reason"]
        for i, v in enumerate(pos):
            if i < len(keys):
                out[keys[i]] = v
    elif helper_name == "record_hipaa_access_event":
        keys = ["actor_user_id", "account_id", "operation", "outcome",
                "detail"]
        for i, v in enumerate(pos):
            if i < len(keys):
                out[keys[i]] = v
    elif helper_name == "set_user_disabled":
        # A2 (census 2026-06-09) — positional after ``conn``:
        # (target_user_id, disabled, actor_user_id, reason), then the punch-709
        # keyword-only three (callers pass those by keyword; they stay OUT of the
        # redaction map, so a gap row carries them as hash-only).
        keys = ["target_user_id", "disabled", "actor_user_id", "reason",
                "emergency_reason", "cli_principal", "source"]
        for i, v in enumerate(pos):
            if i < len(keys):
                out[keys[i]] = v
    elif helper_name == "update_hipaa_access_event":
        # §164.312(b) finalise-gap — positional after ``conn``:
        # (event_id, outcome, detail). The 6 finalise call sites all pass
        # positionally via ``db_call(update_hipaa_access_event, conn,
        # audit_event_id, outcome, detail)``.
        keys = ["event_id", "outcome", "detail"]
        for i, v in enumerate(pos):
            if i < len(keys):
                out[keys[i]] = v
    # record_auth_event / record_discover_run / record_api_key_event /
    # record_access_event / record_style_distill_event are all keyword-only
    # after ``conn`` (the ``*,`` in their signature) — pos[] is empty, only
    # kwargs apply.
    return out


def _redact_args(helper_name: str, args: tuple, kwargs: dict) -> str:
    """Build the JSON-encoded redacted-args payload for a gap-event
    row.

    Returns a compact JSON object containing only the IN-class fields
    per the per-emitter redaction map. Unknown helpers (defensive
    safety net for a future emitter that's marked @audit_emitter
    without a map entry) return ``"{}"`` — no payload, no PHI risk.
    """
    import json as _json
    bound = _bind_args_to_emitter_signature(helper_name, args, kwargs)
    spec = _AUDIT_EMITTER_REDACTION_MAP.get(helper_name)
    if spec is None:
        # Unknown emitter — return empty payload (safe-fail). The
        # hash-only line below STILL captures the args, so an
        # investigator can match by hash even when the redaction
        # map hasn't been authored yet.
        return _json.dumps({})
    redacted: dict = {}
    for field in spec.get("in", set()):
        if field in bound:
            v = bound[field]
            # Coerce numeric / str / bool / None straight through;
            # other types stringify (defensive — bounded-enum should
            # be str or int).
            if isinstance(v, (int, float, str, bool)) or v is None:
                redacted[field] = v
            else:
                redacted[field] = str(v)
    return _json.dumps(redacted, sort_keys=True)


def _hash_args(args: tuple, kwargs: dict) -> str:
    """SHA-256 hex of the canonicalised arg payload (all values,
    including PHI). Lets an investigator MATCH a gap row to a
    separately-stored PHI payload (e.g. a log_entries line) without
    storing the payload here.

    Canonical form: positional values stringified in order, then
    kwargs JSON-encoded with sorted keys. Both inputs and the
    separator are stable so two runs of the same emit produce the
    same hash.
    """
    import json as _json
    # Skip args[0] (conn) — sqlite3.Connection objects don't
    # canonicalise across processes / runs.
    pos_part = "|".join(repr(a) for a in args[1:])
    kw_part = _json.dumps(kwargs, sort_keys=True, default=repr)
    canonical = f"{pos_part}||{kw_part}".encode("utf-8")
    return _hashlib.sha256(canonical).hexdigest()


# Punch . The gap writer prefixes a row's exc_msg with this marker, then the
# exception class name and "] ", when it could not read the chain tail and so
# wrote the row against an empty prev_hash. Read it only through
# gap_row_tail_unreadable_class (prefix match, keyed rows only).
GAP_TAIL_UNREADABLE_MARKER = "[chain-tail-unreadable:"


def _read_gap_chain_tail(conn: sqlite3.Connection) -> str:
    """Return the row_hash of the newest chained audit_gap_events row, or ""
    for an empty table. Raises whatever the read raises: the gap writer needs
    to know the read failed (punch , da-529 M3)."""
    row = conn.execute(
        "SELECT row_hash FROM audit_gap_events "
        "WHERE row_hash != '' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (row["row_hash"] if row else "") or ""


def get_last_gap_row_hash(conn: sqlite3.Connection) -> str:
    """Return the row_hash of the newest audit_gap_events row, or
    empty string if the table has no chain-aware rows yet.

    Mirrors :func:`get_last_log_row_hash` — same WHERE clause
    skipping prechain-sentinel rows (which we don't currently emit
    but reserve for future use), same DESC LIMIT 1.

    An ``OperationalError`` (for example a missing table) also returns "".
    The gap writer does not call this: it calls :func:`_read_gap_chain_tail`
    so that a failed read marks the row instead of passing for an empty table.
    """
    try:
        return _read_gap_chain_tail(conn)
    except DB_OPERATIONAL_ERRORS:
        return ""


def _escape_gap_exc_text(text: str) -> str:
    """Escape exception text that could be read as the writer's marker.

    Text that starts with a backslash or with :data:`GAP_TAIL_UNREADABLE_MARKER`
    gets one leading backslash; nothing is removed (hipaa-529: exc_msg is the
    audit record, so escape, never strip). Only the writer can then put the
    marker at position 0.
    """
    if text.startswith("\\") or text.startswith(GAP_TAIL_UNREADABLE_MARKER):
        return "\\" + text
    return text


def gap_row_tail_unreadable_class(exc_msg: str | None, hash_alg: str | None) -> str | None:
    """Return the exception class named by a gap row's tail-unreadable
    marker, or None.

    Prefix match only, never substring. Only an HMAC-keyed row counts: on a
    keyless ``sha256`` row anyone with write access could have written the
    marker, so it is not evidence there. Rows written before the marker
    shipped never carry it, so None says nothing about them.
    """
    if not (hash_alg or "").startswith("hmac-"):
        return None
    return _gap_marker_class(exc_msg)


def _gap_marker_class(exc_msg: str | None) -> str | None:
    """The class named by a leading tail-read marker, or None. Prefix only.
    Says nothing about whether the bytes are authentic; callers decide that."""
    text = exc_msg or ""
    if not text.startswith(GAP_TAIL_UNREADABLE_MARKER):
        return None
    end = text.find("] ", len(GAP_TAIL_UNREADABLE_MARKER))
    cls = text[len(GAP_TAIL_UNREADABLE_MARKER):end] if end > 0 else ""
    return cls if cls.isidentifier() else None


def _canonical_gap_row(
    prev_hash: str,
    ts: str,
    helper_name: str,
    original_args_redacted: str,
    original_args_hash: str,
    exc_type: str,
    exc_msg: str,
) -> bytes:
    """Canonical byte form of an ``audit_gap_events`` row for HMAC.

    Mirrors :func:`_canonical_log_row`'s shape (newline-joined, NFC-
    normalised strings → utf-8). Field order is fixed. Adding a field
    changes the hash of EVERY existing row, even when appended at the end
    and even when empty: the join adds one more separator. A new field
    therefore needs a new ``hash_alg`` id whose rows use the longer form,
    with old rows kept on theirs (db-529 F3; guarded by
    ``tests/test_audit_chain_byte_identity_freeze.py``). Changing the VALUE
    written into an existing field, as the punch  marker in
    ``exc_msg`` does, moves no old row.
    """
    import unicodedata as _ud
    fields = [
        prev_hash,
        ts,
        helper_name,
        original_args_redacted,
        original_args_hash,
        exc_type,
        exc_msg,
    ]
    return "\n".join(
        _ud.normalize("NFC", str(f or "")) for f in fields
    ).encode("utf-8")


def compute_gap_row_hash(
    prev_hash: str,
    ts: str,
    helper_name: str,
    original_args_redacted: str,
    original_args_hash: str,
    exc_type: str,
    exc_msg: str,
    *,
    hash_alg: str = CHAIN_HASH_ALG_CURRENT,
    master_key_version: int | None = None,
) -> str:
    """Compute the chain hash for a new ``audit_gap_events`` row.

    EQM-05 reuse: same keyed primitive (``CHAIN_HASH_ALG_CURRENT``) + same chain key
    as :func:`compute_log_row_hash`. The gap-events chain is a
    SECOND chain (separate ``prev_hash`` lineage) keyed identically,
    so a KEYED gap row cannot be forged without that key. A degraded row
    (``hash_alg='sha256'``, NULL key version; N-467) is keyless: anyone who
    can write the table can forge one. :func:`verify_gap_chain` counts such rows
    as ``keyless_count`` and /compliance shows them. (``verify_log_chain``
    reports its own sha256 rows as ``legacy_chain_length``, and the ones after
    its first keyed row as ``post_boundary_keyless_count``; /compliance shows
    both since punch .)
    """
    #  — dispatch extracted to the shared _apply_chain_hmac SSOT. The
    # canonical BYTE form (_canonical_gap_row: newline-join, WITH NFC) is FROZEN
    # and passed in. Byte-identity guarded by the freeze test.
    return _apply_chain_hmac(
        _canonical_gap_row(
            prev_hash, ts, helper_name,
            original_args_redacted, original_args_hash, exc_type, exc_msg,
        ),
        hash_alg=hash_alg,
        master_key_version=master_key_version,
        _what="compute_gap_row_hash",
    )


def _write_audit_gap_event(
    conn: sqlite3.Connection,
    *,
    helper_name: str,
    args: tuple,
    kwargs: dict,
    exc: BaseException,
) -> None:
    """Append a gap-event row recording a failed audit-emitter call.

    Best-effort: any exception in this function is caught by the
    caller (``db_writelock.db_write.wrapper``) and swallowed so the
    ORIGINAL exception still propagates. The point is to leave a
    trace, not to chain a second failure.

    Idempotence: not guaranteed — a gap-event for the SAME failed
    emit could fire twice if the wrapper itself were retried. The
    table has no unique constraint; two near-identical rows in the
    chain are acceptable (gap-events are append-only audit trail,
    not state).

    HMAC chain: reads the previous row_hash via
    :func:`_read_gap_chain_tail`, computes the new row_hash and INSERTs both in
    one ``conn.execute``.

    Stated limit — the write-path race (punch  fold 3, db-529 ADDENDUM 7).
    The tail READ and the INSERT are NOT one atomic step, and the write lock
    (:mod:`email_triage.web.db_writelock`, ``_write_lock`` at ``web/db_writelock.py:65-69``: a module-level ``threading.RLock``, "One lock for the whole process") is process-wide only, so two
    processes can read the same chain tail and both insert against it; the
    later row is self-consistent with a stale, non-empty ``prev_hash`` and the
    verifier reports a break on it. A second process writing this table is
    demonstrated, not hypothetical: a failed ``@audit_emitter`` call under
    ``record_cli_admin_op`` lands here in the CLI process.
    Stated limit — the INSERT itself can still cost the row TODAY
    (db-529-2 addendum 9). The re-scoped N-467 claim covers the enumerated
    PRE-INSERT steps; the ``conn.execute(INSERT)`` is not one of them. Under
    write contention it can raise ``SQLITE_BUSY`` once ``PRAGMA busy_timeout``
    expires, and nothing here catches that: the gap row is lost, exactly as with
    a dropped table. The window is CONFIG-DERIVED, not a fixed 30 s —
    ``_SQLITE_BUSY_WAIT_SECS`` (:mod:`email_triage.db._engine`) defaults to 30.0
    but is reassigned from config, so an install that shortens the busy wait for
    latency shortens the time before a contended recovery-path write starts
    discarding audit rows. Measured floor: values below 1.0 s are REFUSED and
    the default is kept, so the operator-reachable minimum is 1.0 s.

    DO NOT close the race with ``BEGIN IMMEDIATE`` or a cross-process lock on
    THIS path. This writer runs on the recovery path, so a ``SQLITE_BUSY``
    propagating out of the one function whose job is to leave a row behind
    loses the row and reintroduces N-467 — and it WIDENS exactly the loss route
    above, by taking the write lock earlier and holding it longer, on the same
    operator-shortened timeout. That is worse than the misleading break reason
    it would fix. The cost is carried on the VERIFIER side instead:
    :func:`_prev_hash_placement` reports where a break row's stored
    ``prev_hash`` points, so a raced row is distinguishable from a deleted
    predecessor, and the reason names the concurrent write as a cause.

    The row must survive the failure it records (N-467, punch  and
    ). The steps enumerated here degrade to a stated value instead of
    costing the row: the timestamp to "" (distinguishable in the row; a clock
    that just raised is not called again), the redacted arguments to
    ``{"redaction_failed": "<class>"}``, the argument hash to "", the
    exception text to ``<exception text unavailable: <class>>``, the HMAC to
    keyless ``sha256`` with a NULL key version, and an unreadable chain tail
    to an empty ``prev_hash``. The exception text is also coerced to
    encodable UTF-8 (a lone surrogate becomes a backslash escape), because
    the hash and the INSERT bind would otherwise raise on it. One ERROR after
    the commit names each degradation by class, never by message text.
    enumeration_complete=false: this is the list of steps examined, not a
    proof that nothing else before the INSERT can raise.

    ``exc_msg`` format (hipaa-529 Condition A): the redacted exception text,
    coerced to encodable UTF-8,
    with one leading backslash added when it starts with a backslash or with
    :data:`GAP_TAIL_UNREADABLE_MARKER`, then cut to 500 characters. When the
    chain tail could not be read, the writer prefixes
    ``[chain-tail-unreadable:<class>] `` and cuts to 500 again, so the marker
    always survives. Read the marker with
    :func:`gap_row_tail_unreadable_class` only.

    What this does NOT cover: a dropped ``audit_gap_events`` table. The INSERT
    itself raises there and no row is kept (punch  stays open for it).
    """
    helper = helper_name or "<unknown>"
    exc_type = type(exc).__name__
    degraded_steps: list[str] = []
    try:
        now = now_utc_iso()
    except Exception as step_exc:
        degraded_steps.append(f"timestamp:{type(step_exc).__name__}")
        now = ""
    try:
        redacted = _redact_args(helper, args, kwargs)
    except Exception as step_exc:
        degraded_steps.append(f"redact_args:{type(step_exc).__name__}")
        redacted = dump_json_col({"redaction_failed": type(step_exc).__name__})
    try:
        arg_hash = _hash_args(args, kwargs)
    except Exception as step_exc:
        degraded_steps.append(f"args_hash:{type(step_exc).__name__}")
        arg_hash = ""
    # N-42: exc_msg INSERTs into the HMAC-chained audit_gap_events table —
    # scrub PHI shapes before they enter the un-expungeable chain.
    try:
        from email_triage._errfmt import redact_exc
        exc_text = _escape_gap_exc_text(
            redact_exc(str(exc)).encode("utf-8", "backslashreplace").decode("utf-8")
        ) if exc else ""
    except Exception as step_exc:
        degraded_steps.append(f"exc_text:{type(step_exc).__name__}")
        exc_text = f"<exception text unavailable: {type(step_exc).__name__}>"
    exc_msg = exc_text[:500]
    # Punch : reading the chain tail is on the recovery path too, so it
    # must not cost the row either. Any failure, OperationalError included
    # (da-529 M3), writes the row against an empty prev_hash and marks it.
    # Unless the table is empty the verifier then reports a break at this row;
    # on an empty table "" is the right genesis value and only the marker shows.
    prev_unreadable: str | None = None
    try:
        prev_hash = _read_gap_chain_tail(conn)
    except Exception as prev_exc:
        prev_unreadable = type(prev_exc).__name__
        prev_hash = ""
    if prev_unreadable is not None:
        exc_msg = (f"{GAP_TAIL_UNREADABLE_MARKER}{prev_unreadable}] " + exc_msg)[:500]
    # N-467 (punch ). This row is the control of last resort for every
    # @audit_emitter helper, and the commonest reason an emitter fails is the
    # HMAC key being unavailable (no version provisioned, or a rotation window
    # where the current version has no key yet). The HMAC attempt is therefore
    # wrapped, and ANY failure degrades to the secretless SHA-256 form with a
    # NULL key version. That fallback is permitted here and nowhere else: this
    # is the gap-event RECOVERY path, inside the emitter's exception handler
    # (see _chain_insert, which fails closed). A try/except rather than a
    # pre-check of the key: a pre-check resolves the key once and
    # _apply_chain_hmac resolves it again, so a rotation landing between the
    # two would still lose the row. The row's own hash_alg='sha256' + NULL
    # version tells a later auditor; the ERROR log tells the operator now.
    version = _get_current_hmac_version()
    degraded_by: str | None = None
    try:
        hash_alg = CHAIN_HASH_ALG_CURRENT
        row_hash = compute_gap_row_hash(
            prev_hash, now, helper, redacted, arg_hash, exc_type, exc_msg,
            hash_alg=hash_alg, master_key_version=version,
        )
    except Exception as hmac_exc:
        degraded_by = type(hmac_exc).__name__
        hash_alg, version = "sha256", None
        row_hash = compute_gap_row_hash(
            prev_hash, now, helper, redacted, arg_hash, exc_type, exc_msg,
            hash_alg=hash_alg, master_key_version=None,
        )
    conn.execute(
        "INSERT INTO audit_gap_events "
        "(ts, helper_name, original_args_redacted, original_args_hash, "
        " exc_type, exc_msg, prev_hash, row_hash, hash_alg, "
        " master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (now, helper, redacted, arg_hash, exc_type, exc_msg,
         prev_hash, row_hash, hash_alg, version),
    )
    conn.commit()
    # Logged only once the row is committed: a failure here must not cost the
    # row, which would be the N-467 outcome by another route. ONE call carries
    # every degradation, so no notice can suppress another (da-529 M7).
    notices: list[str] = []
    if degraded_by is not None:
        notices.append(
            f"audit gap-event DEGRADED to secretless sha256 (N-467): HMAC "
            f"unavailable ({degraded_by}) while recording a failed "
            f"{helper} emit; the gap row is written but is not keyed"
        )
    if prev_unreadable is not None:
        notices.append(
            f"audit gap-event chain tail unreadable ({prev_unreadable}) while "
            f"recording a failed {helper} emit; the gap row is written with an "
            f"empty prev_hash and its exc_msg starts with "
            f"'{GAP_TAIL_UNREADABLE_MARKER}{prev_unreadable}]'; unless it is the "
            f"first row in the table the chain verifier reports a break at it "
            f"(punch #529)"
        )
    if degraded_steps:
        notices.append(
            f"audit gap-event row build degraded ({', '.join(degraded_steps)}) "
            f"while recording a failed {helper} emit; the gap row is written "
            f"with placeholder values for those fields (punch #529)"
        )
    if notices:
        from email_triage.triage_logging import get_logger
        get_logger("db.audit").error(" | ".join(notices))


# Punch 582. The audit-write losses no exception carries to the @db_write
# sentinel (a fire-and-forget write cancelled before it launched, an inner
# write cancelled mid-flight, writes still in flight at shutdown, a writer
# queue abandoned, a done-callback that threw, a sync write interrupted by a
# BaseException, an Exception swallowed by the best-effort SSOT that never
# reached the sentinel) used to leave a trace only in the pruned log_entries. They
# now land in the same chained table as the raise class, through the same
# writer. The row is PHI-free by construction: the args are empty and the
# exception text is an enum, a table identifier and a count; the caller's
# description (which can carry a route path) never reaches it.
AUDIT_WRITE_LOSS_CLASSES: frozenset[str] = frozenset({
    "cancelled_before_launch",
    "inner_cancelled",
    "shutdown_undrained",
    "writer_queue_abandoned",
    "done_callback_swallow",
    "interrupted_sync",
    "failed_unrecorded",
})

# Panel B7 (hipaa F2, db DB-3): loss classes whose row says a write MAY have
# been lost, not that it was. Their ``exc_msg`` carries the fixed suffix
# `` certainty=presumptive`` so a reviewer reads them as such. ONE set: a
# class db-sme later rules presumptive is a one-line addition here.
#   * ``done_callback_swallow``: the callback threw; the write may have landed.
#   * ``inner_cancelled``: ``SqliteWriterThread._run`` runs a queued item with
#     no ``fut.cancelled()`` check, so a write whose awaiting future was
#     cancelled may still commit (db-sme B7 addendum).
#   * ``interrupted_sync``: the interrupt can land after the write committed
#     (a narrow window, but not provably closed).
# L1, L5, L6 and L11 are certain: the write was never submitted, refused,
# never run, or failed.
#   * ``shutdown_undrained``: ``count`` is an UPPER BOUND taken at the drain
#     deadline. A write it counts may still land during the writer's join
#     window, and the same write may be counted again by an L5 ``WriterStopped``
#     shed row or by ``writer_queue_abandoned``. Reconcile these rows against
#     ``access_log``; never add them up.
PRESUMPTIVE_LOSS_CLASSES: frozenset[str] = frozenset({
    "shutdown_undrained",
    "done_callback_swallow",
    "inner_cancelled",
    "interrupted_sync",
})

import re as _re  # local-style import per audit.py convention

_LOSS_IDENT_RE = _re.compile(r"[a-z][a-z0-9_]{0,63}")


class AuditWriteLost(Exception):
    """The exception value a punch-582 gap row records: ``<loss_class>
    table=<table> count=<n>``, plus `` certainty=presumptive`` for a class in
    :data:`PRESUMPTIVE_LOSS_CLASSES`; nothing else."""


def record_audit_write_loss(
    conn: sqlite3.Connection,
    *,
    loss_class: str,
    table: str = "unknown",
    count: int = 1,
    helper_name: str = "audit_write_loss",
    lost_at: str | None = None,
) -> None:
    """Append ONE ``audit_gap_events`` row for ``count`` lost audit writes of
    one loss class, through :func:`_write_audit_gap_event` (the raise-class
    and shed-class writer; no second chain, no raw INSERT). The caller holds
    the write lock. ``loss_class`` must be one of
    :data:`AUDIT_WRITE_LOSS_CLASSES`; ``table`` and ``helper_name`` must be
    lower-case identifiers, so no free text reaches the chain. Raises on a bad
    argument or a failed write; the web layer's recorder turns that into the
    gap-on-gap signal (``web/_audit.record_audit_loss``).

    ``lost_at`` (DA fold-check, panel B7) is when the loss happened, for a
    row recorded later than that (the L6 sentinel replayed at boot). It
    must parse as an ISO timestamp and is re-formatted by the ``_isotime``
    SSOT, so no free text reaches the chain."""
    if loss_class not in AUDIT_WRITE_LOSS_CLASSES:
        raise ValueError(f"unknown audit-write loss class: {loss_class!r}")
    for name, value in (("table", table), ("helper_name", helper_name)):
        if not isinstance(value, str) or not _LOSS_IDENT_RE.fullmatch(value):
            raise ValueError(f"audit-write loss {name} must be an identifier")
    n = int(count)
    if n < 1:
        raise ValueError("audit-write loss count must be at least 1")
    when = ""
    if lost_at is not None:
        from email_triage._isotime import parse_iso_aware, to_utc_iso
        dt = parse_iso_aware(lost_at)
        if dt is None:
            raise ValueError("audit-write loss lost_at must be an ISO timestamp")
        when = f" lost_at={to_utc_iso(dt)}"
    _write_audit_gap_event(
        conn,
        helper_name=helper_name,
        args=(),
        kwargs={},
        exc=AuditWriteLost(
            f"{loss_class} table={table} count={n}{when}"
            + (" certainty=presumptive"
               if loss_class in PRESUMPTIVE_LOSS_CLASSES else "")
        ),
    )


_AUDIT_GAP_RECORDED_ATTR = "_et_audit_gap_recorded"


def mark_audit_gap_recorded(exc: BaseException) -> None:
    """Tag ``exc`` once its gap row is committed (the ``@db_write`` sentinel,
    the  shed path), so the best-effort SSOT that later swallows it does
    not record the same loss again (punch 582). Best effort: an exception
    type that refuses attributes is simply not tagged."""
    try:
        setattr(exc, _AUDIT_GAP_RECORDED_ATTR, True)
    except Exception:
        # Untagged, the best-effort SSOT one layer out records a second
        # (failed_unrecorded) row for this loss: noisy, never silent.
        from email_triage.triage_logging import get_logger
        get_logger("db.audit").warning(
            f"audit gap row written but {type(exc).__name__} cannot be "
            f"tagged; a second loss row may follow for the same failure"
        )


def audit_gap_recorded(exc: BaseException) -> bool:
    """True when :func:`mark_audit_gap_recorded` tagged ``exc``."""
    return bool(getattr(exc, _AUDIT_GAP_RECORDED_ATTR, False))


# Punch 709 (operator decision 2026-11-02 8:13 PM): the EMERGENCY revoke.
# ``delete_api_key`` and ``set_user_disabled`` share one transaction with their
# chained witness and fail CLOSED, so with the HMAC chain broken (no key
# provisioned, an unreadable tail, a dropped table) a compromised key could not
# be stopped in the app. Both take an ``emergency_reason`` and, ONLY when the
# witness phase failed, commit the revoke WITHOUT the witness and call
# :func:`record_emergency_revoke`, the ONE funnel: one PHI-free
# ``audit_gap_events`` row naming the chain that lost its witness, a CRITICAL log
# line, and a durable marker the ``/health`` surface reads. The chained record of
# that one event is knowingly given up (§164.308(a)(6)(ii) incident response over
# §164.312(b) for one row); a healthy chain never reaches this path.
#
# Only an enabled admin or the host CLI may pass the flag
# (:func:`check_emergency_actor`, checked before any write: PD-9), and only cli.py
# passes it (tests/test_709_emergency_revoke_pin.py). The gap rows' actor is built
# INSIDE each edge from the id the gate checked (:func:`emergency_actor`), never
# taken as a caller-supplied label (cycle P hipaa S2).
#
# The marker is set and cleared ONLY by :func:`record_emergency_revoke` and
# :func:`clear_emergency_revoke` (PD-18: one funnel per edge), and each edge
# leaves its own chained ``audit_gap_events`` row (``emergency_revoke`` /
# ``emergency_revoke_cleared``; the clear unlinks only after its row). It is a file next
# to the database, not a counter, so it survives a restart and is seen by the
# web process when the CLI process set it.
EMERGENCY_REVOKE_REASONS: frozenset[str] = frozenset({
    "credential_compromised",
    "suspected_intrusion",
    "insider_misuse",
    "other_incident",
})
EMERGENCY_REVOKE_KINDS: frozenset[str] = frozenset({"api_key", "user"})
EMERGENCY_REVOKE_MARKER = ".audit-emergency-revoke"
# The gap row's table name for what lost its witness, per kind.
_EMERGENCY_WITNESS_TABLE = {"api_key": "api_key_events", "user": "user_status_events"}
_EMERGENCY_PRINCIPAL_RE = _re.compile(r"[a-z][a-z0-9_.-]{0,31}")


class AuditEmergencyRevoke(Exception):
    """The exception value an emergency-revoke gap row records:
    ``emergency_revoke kind=<kind> table=<witness table> target_id=<n>
    actor=<user:n|cli[:principal]> reason=<code> witness_failure=<class>``;
    every field is an integer, a controlled-vocabulary code or a class name, so
    no free text and no PHI reaches the chain."""


class EmergencyRevokeRefused(ValueError):
    """The emergency path was asked for with a reason outside
    :data:`EMERGENCY_REVOKE_REASONS`, a kind outside
    :data:`EMERGENCY_REVOKE_KINDS`, or for a re-enable. Raised BEFORE any write."""


def check_emergency_reason(reason: object) -> str:
    """Return ``reason`` when it is in the controlled vocabulary; raise
    :class:`EmergencyRevokeRefused` otherwise. Called before any write."""
    if not isinstance(reason, str) or reason not in EMERGENCY_REVOKE_REASONS:
        raise EmergencyRevokeRefused(
            f"emergency revoke needs a reason code, one of "
            f"{sorted(EMERGENCY_REVOKE_REASONS)}"
        )
    return reason


def emergency_actor(actor_user_id: int | None, cli_principal: str | None = None) -> str:
    """The gap row's actor field: ``user:<id>``, or ``cli[:principal]`` for the
    host CLI (the principal is kept only when it is a plain identifier)."""
    if actor_user_id is not None:
        return f"user:{int(actor_user_id)}"
    name = (cli_principal or "").lower()
    if _EMERGENCY_PRINCIPAL_RE.fullmatch(name):
        return f"cli:{name}"
    return "cli"


def check_emergency_actor(
    conn: sqlite3.Connection, actor_user_id: int | None, source: str,
) -> None:
    """Who may take the emergency path (punch 709, PD-9), decided where the
    revoke happens and never from a caller-supplied label: an ENABLED user whose
    role is admin (the ``is_admin`` SSOT), or the host CLI (``source == "cli"``
    with no user id; every web route passes its session user). Raises
    :class:`EmergencyRevokeRefused` otherwise. Called BEFORE any write, so a
    refused caller leaves no revoke, no marker and no ``emergency_revoke`` row."""
    if actor_user_id is None:
        if source == "cli":
            return
        raise EmergencyRevokeRefused(
            "the emergency path needs an enabled admin or the host CLI")
    from email_triage.web.dependencies import is_admin  # N-222 role SSOT
    row = conn.execute(
        "SELECT role, disabled FROM users WHERE id = ?", (int(actor_user_id),),
    ).fetchone()
    if row is None or bool(row[1]) or not is_admin({"role": row[0]}):
        raise EmergencyRevokeRefused(
            "the emergency path needs an enabled admin or the host CLI")


def _emergency_marker_path(conn: sqlite3.Connection):
    """The marker path next to the main database file, or None for a database
    with no file (``:memory:``)."""
    from pathlib import Path
    for _seq, name, file in conn.execute("PRAGMA database_list"):
        if name == "main" and file:
            return Path(file).parent / EMERGENCY_REVOKE_MARKER
    return None


def emergency_revoke_pending(conn: sqlite3.Connection) -> bool:
    """True while an emergency revoke has not been reconciled (the ``/health``
    flag). Read-only. A database with no file, or an unreadable path, reads
    False: unknown is not an alarm, and ``/health`` already degrades on a
    broken database."""
    try:
        path = _emergency_marker_path(conn)
        return path is not None and path.exists()
    except Exception:
        return False


def record_emergency_revoke(
    conn: sqlite3.Connection,
    *,
    kind: str,
    target_id: int,
    actor_user_id: int | None,
    cli_principal: str | None = None,
    reason: str,
    witness_exc: BaseException,
) -> dict:
    """The ONE emergency-revoke funnel (punch 709). Called after the revoke is
    committed WITHOUT its chained witness. Sets the marker, writes one
    ``audit_gap_events`` row through :func:`_write_audit_gap_event` (which
    degrades to keyless sha256 when the HMAC key is the broken part, the
    existing recovery path), then logs CRITICAL. Never raises: the revoke is
    already durable, and every step that fails is named in the CRITICAL line
    and in the returned ``{"marker_set", "gap_written"}``. The caller holds the
    write lock. The row's actor is built HERE from ``actor_user_id`` (the id
    the actuator's :func:`check_emergency_actor` passed) and, only when there
    is no user id, ``cli_principal``, so it cannot contradict who was checked."""
    check_emergency_reason(reason)
    if kind not in EMERGENCY_REVOKE_KINDS:
        raise EmergencyRevokeRefused(f"unknown emergency revoke kind: {kind!r}")
    actor = emergency_actor(actor_user_id, cli_principal)
    target = int(target_id)
    table = _EMERGENCY_WITNESS_TABLE[kind]
    cause = type(witness_exc).__name__
    message = (
        f"emergency_revoke kind={kind} table={table} target_id={target} "
        f"actor={actor} reason={reason} witness_failure={cause}"
    )
    marker_set = gap_written = False
    try:
        from email_triage._atomicio import atomic_write_text
        from email_triage._isotime import now_utc_iso as _now
        path = _emergency_marker_path(conn)
        if path is not None:
            atomic_write_text(path, f"emergency_revoke kind={kind} at={_now()}\n")
            marker_set = True
    except Exception:
        marker_set = False
    try:
        _write_audit_gap_event(
            conn, helper_name="emergency_revoke", args=(), kwargs={},
            exc=AuditEmergencyRevoke(message),
        )
        gap_written = True
    except Exception:
        gap_written = False
    try:
        from email_triage.triage_logging import get_logger
        get_logger("db.audit").critical(
            f"EMERGENCY REVOKE with the audit chain broken: {message}; the "
            f"revoke is committed WITHOUT its chained witness (punch 709); "
            f"health_marker_set={marker_set} gap_row_written={gap_written}; "
            f"repair the chain, then run `audit clear-emergency-flag`"
        )
    except Exception as log_exc:
        # The logger itself failed: the process stderr is the last channel.
        import sys as _sys
        _sys.stderr.write(
            f"EMERGENCY REVOKE (punch 709): {message}; "
            f"health_marker_set={marker_set} gap_row_written={gap_written}; "
            f"the CRITICAL log line failed: {type(log_exc).__name__}\n"
        )
    return {"marker_set": marker_set, "gap_written": gap_written}


class AuditEmergencyRevokeCleared(Exception):
    """The exception value the clear edge's gap row records:
    ``emergency_revoke_cleared actor=<user:n|cli[:principal]>``; the row's own
    ``ts`` is when. A plain id only: no free text and no PHI."""


def clear_emergency_revoke(
    conn: sqlite3.Connection,
    *,
    actor_user_id: int | None,
    source: str,
    cli_principal: str | None = None,
) -> dict:
    """The ONE clear edge for the emergency marker (PD-18). Removes it only when
    the repair is PROVEN: every chained table verifies intact, the
    ``log_entries`` chain verdict is ``pass``, and an HMAC key is provisioned
    (so a new witness can be written). Before the marker goes, the clear is
    recorded as ONE chained ``emergency_revoke_cleared`` row in
    ``audit_gap_events`` (the table that holds the set edge's row) through the
    chain's writer :func:`_write_audit_gap_event`, naming the actor (who; the
    row's ``ts`` is when). If that row cannot be written the marker STAYS (fail
    closed: no unrecorded clear) and a blocker says so. The same actor gate as
    the revoke (:func:`check_emergency_actor`: an enabled admin or the host CLI)
    is the FIRST statement, before any read or write (PD-9, cycle P DA P709g
    S1); the actor is then built here from the checked id. Returns
    ``{"cleared": bool, "blockers": [...]}``; ``blockers`` holds table names and
    fixed phrases only."""
    check_emergency_actor(conn, actor_user_id, source)
    actor = emergency_actor(actor_user_id, cli_principal)
    path = _emergency_marker_path(conn)
    if path is None or not path.exists():
        return {"cleared": False, "blockers": ["no emergency marker"]}
    blockers = [
        t for t, r in verify_all_audit_chains(conn).items() if not r.get("intact")
    ]
    if verify_log_chain(conn).get("verdict") != "pass":
        blockers.append("log_entries")
    if _get_current_hmac_version() is None:
        blockers.append("no HMAC key provisioned")
    if blockers:
        return {"cleared": False, "blockers": blockers}
    try:
        _write_audit_gap_event(
            conn, helper_name="emergency_revoke_cleared", args=(), kwargs={},
            exc=AuditEmergencyRevokeCleared(f"emergency_revoke_cleared actor={actor}"),
        )
    except Exception:
        conn.rollback()
        return {"cleared": False,
                "blockers": ["the emergency_revoke_cleared row could not be written"]}
    try:
        path.unlink()
    except OSError:
        return {"cleared": False,
                "blockers": ["the emergency marker could not be removed"]}
    return {"cleared": True, "blockers": []}


def known_emergency_revoke_gaps(conn: sqlite3.Connection) -> dict[str, int]:
    """``{witness table: count}`` of ``emergency_revoke`` gap rows naming that
    table (cycle P hipaa Q3). Each is a revoke committed WITHOUT its chained
    witness: a KNOWN gap in that table's record, which a chain verify cannot
    see because nothing was broken. Read-only; reported beside ``intact`` by
    :func:`verify_all_audit_chains` and ``audit verify``, never inside it. The
    table is the row's ``table=`` field, matched as a whole field."""
    return {
        table: int(conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = 'emergency_revoke' "
            "AND instr(exc_msg || ' ', ' table=' || ? || ' ') > 0",
            (table,),
        ).fetchone()[0])
        for table in sorted(set(_EMERGENCY_WITNESS_TABLE.values()))
    }


class AuditLossDeferred(RuntimeError):
    """The loss sink refused to write because the calling thread already
    held the write lock with its own transaction open on the shared
    connection (punch 582, panel B7 DB-1). Writing the gap row would commit
    that caller's unfinished transaction. The web recorder reports the
    refusal as gap-on-gap (L10): an ERROR naming the class plus a ``/health``
    bump."""


def _record_audit_write_loss_locked(
    conn: sqlite3.Connection, default_lock_timeout: float,
    loss_class: str, table: str, count: int, helper_name: str | None,
    lock_timeout: float | None = None, lost_at: str | None = None,
) -> None:
    """The body of the sink :func:`make_audit_loss_sink` returns: take the
    process-wide write lock within ``lock_timeout`` seconds, then record.

    It never commits a transaction it did not open (panel B7 DB-1). If this
    thread already held the lock and a transaction is open, the transaction
    is the caller's: raise :class:`AuditLossDeferred` without touching
    ``conn``. If the lock was free and a transaction is still open, it is
    residue a failed write left behind: roll it back, log an ERROR, then
    record. ``lock_timeout`` overrides the sink's default bound for one call
    (the L6 shutdown path uses 1 s)."""
    from email_triage.web.db_writelock import get_write_lock
    if lock_timeout is None:
        lock_timeout = default_lock_timeout
    lock = get_write_lock()
    # CPython's RLock exposes ``_is_owned``. Without it, assume the caller
    # owns the lock: never touch a connection that may hold its transaction.
    is_owned = getattr(lock, "_is_owned", None)
    owned = bool(is_owned()) if callable(is_owned) else True
    if not lock.acquire(timeout=lock_timeout):
        raise TimeoutError(
            f"write lock not acquired within {lock_timeout}s"
        )
    try:
        if conn.in_transaction:
            if owned:
                raise AuditLossDeferred(
                    "audit-loss sink refused: the caller's transaction is "
                    "open on the shared connection"
                )
            conn.rollback()
            from email_triage.triage_logging import get_logger
            get_logger("db.audit").error(
                f"audit-loss sink discarded orphaned uncommitted writes "
                f"before recording loss_class={loss_class} table={table}"
            )
        record_audit_write_loss(
            conn, loss_class=loss_class, table=table, count=count,
            helper_name=helper_name or "audit_write_loss", lost_at=lost_at,
        )
    finally:
        lock.release()


# Punch 636: how long the loss sink waits for the write lock; a term of the
# shutdown envelope (tests/test_636_shutdown_envelope_pin.py), since the
# shutdown drain and sweep record through it.
AUDIT_LOSS_SINK_LOCK_TIMEOUT_SECS: float = 5.0


def make_audit_loss_sink(
    conn: sqlite3.Connection, *,
    lock_timeout: float = AUDIT_LOSS_SINK_LOCK_TIMEOUT_SECS,
):
    """The sink the web layer registers (``web/_audit.register_audit_loss_sink``)
    at lifespan start: a SYNC callable ``(loss_class, table, count,
    helper_name)`` that takes the process-wide write lock within
    ``lock_timeout`` seconds and records the loss on ``conn``. Sync on
    purpose: it is called from done-callbacks and from shutdown, where a
    scheduled write might never run. A lock it cannot take in time raises
    ``TimeoutError``, which the recorder reports as gap-on-gap. A partial,
    not a closure, so every name the body reads is bound in its own scope
    (N-338c)."""
    import functools as _functools  # local-style import per audit.py convention
    return _functools.partial(_record_audit_write_loss_locked, conn, lock_timeout)


# Note: ``audit_emitter`` is defined earlier in this module (hoisted
# above the 7 emitter functions that consume it). Full docstring +
# usage examples are at that definition.
