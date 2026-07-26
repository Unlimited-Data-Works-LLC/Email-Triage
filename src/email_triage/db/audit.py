"""Audit cluster — log_entries hash chain, HIPAA boundary/access events,
auth events, user-status events, API-key lifecycle events, access-log
middleware sink, discover-run records.

Extracted from ``email_triage.web.db`` per the backlog #277a (2026-05-23) to
unblock the H-02a HMAC migration (Task #1) without dragging it through the
8819-LOC god-module. No semantic changes; pure verbatim relocation.

``web/db.py`` retains a re-export shim so all existing
``from email_triage.web.db import <name>`` callers (554 refs across 76
files at extraction time) keep working unchanged.

Cycle hazard preserved: ``triage_logging.py:419`` does a deliberate LATE
import of ``compute_log_row_hash`` + ``get_last_log_row_hash`` inside
``SQLiteLogHandler.emit()`` (the handler can be set up before web/db init
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

from email_triage._isotime import now_utc_iso

from email_triage.db._helpers import dump_json_col, load_json_col

import sqlite3
import threading
from typing import Any

from email_triage.web.db_writelock import db_write


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
    source         TEXT NOT NULL
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
# hashed.
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

    H-02a (Cycle 6, 2026-05-23): new rows stamp
    ``hash_alg='hmac-sha256-v1'`` and ``master_key_version`` =
    current registry version. Raises RuntimeError if no HMAC key is
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
    prev_hash = get_last_log_row_hash(conn)
    # H-02a: stamp the current HMAC version on the row + compute under
    # the current HMAC subkey. _get_current_hmac_version() returns None
    # if the registry is unprovisioned; compute_log_row_hash will
    # RuntimeError in that case (D1 fail-closed). insert_log_entry has
    # no special-case path for missing keys — it's the same primitive
    # contract as the hot-path SQLiteLogHandler.emit().
    current_version = _get_current_hmac_version()
    hash_alg = "hmac-sha256-v1"
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
    from email_triage.web.db import invalidate_setting_cache
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
    # Inline UPSERT — avoid set_setting() because that helper auto-commits
    # and we need the anchor write to share the prune transaction.
    import json as _json
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET "
        "value_json = excluded.value_json, "
        "updated_at = excluded.updated_at",
        (_AUDIT_CHAIN_ANCHOR_KEY, dump_json_col(anchor), anchor["anchored_at"]),
    )
    # Keep the in-process settings cache coherent with this
    # transactional write. The cache otherwise serves a stale value
    # for up to TTL seconds after a prune sweep.
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
) -> bool:
    """Flip a user's ``disabled`` flag and record the audit row atomically.

    Returns True if the flag actually changed, False if it was already
    in the requested state (no-op, no event recorded).
    """
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
    try:
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
        #  — chained audit write (SSOT), txn-aware: NO commit here; the
        # explicit COMMIT below makes the users flip + the audit row atomic.
        _chain_insert(conn, "user_status_events", {
            "ts": now,
            "target_user_id": target_user_id,
            "actor_user_id": actor_user_id,
            "event": event,
            "reason": reason or "",
        })
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
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
            "SELECT * FROM user_status_events WHERE target_user_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (target_user_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM user_status_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# Auth events (PR 9 / D4 — credential-use audit trail)
# ---------------------------------------------------------------------------

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
    """
    now = now_utc_iso()
    #  — chained audit write (SSOT). Own-commit emitter.
    row_id = _chain_insert(conn, "auth_events", {
        "ts": now,
        "event_type": event_type,
        "user_id": user_id,
        "email": email,
        "key_id": key_id,
        "ip": ip,
        "user_agent": user_agent,
        "outcome": outcome,
        "detail": detail,
    })
    conn.commit()
    return row_id


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
    sql = "SELECT * FROM auth_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# HIPAA boundary event helpers
# ---------------------------------------------------------------------------

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
    """
    now = now_utc_iso()
    #  — chained audit write (SSOT). Own-commit emitter. The SECOND writer of
    # this table (db/accounts.py set_account_hipaa, in-txn) routes through the
    # same SSOT — both are pinned by the table-keyed inverse pin.
    row_id = _chain_insert(conn, "hipaa_boundary_events", {
        "ts": now,
        "scope": scope,
        "direction": direction,
        "actor_id": actor_id,
        "reason": reason,
    })
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
    """
    now = now_utc_iso()
    #  — the headline PHI-access boundary log, now HMAC-chained (SSOT). outcome
    # + detail are STORED but EXCLUDED from the canonical hash (Option A) because
    # update_hipaa_access_event finalises them in place; the chain hashes only the
    # immutable access FACT (ts/actor/account/operation), so the finalise UPDATE
    # is chain-transparent. Own-commit emitter.
    row_id = _chain_insert(conn, "hipaa_access_events", {
        "ts": now,
        "actor_user_id": actor_user_id,
        "account_id": account_id,
        "operation": operation,
        "outcome": outcome,
        "detail": detail,
    })
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
) -> int:
    """Insert an api_key_events row. Returns the new row id.

    ``event`` is ``"api_key_created"`` or ``"api_key_revoked"``. ``source``
    is one of ``"ui"``, ``"api"``, ``"cli"``. ``key_id`` is intentionally
    NOT a foreign key — revoked api_keys rows are deleted, but we want
    the audit row to survive.
    """
    now = now_utc_iso()
    #  — chained audit write (SSOT). Own-commit emitter.
    row_id = _chain_insert(conn, "api_key_events", {
        "ts": now,
        "event": event,
        "key_id": key_id,
        "actor_user_id": actor_user_id,
        "target_user_id": target_user_id,
        "name": name,
        "expires_at": expires_at,
        "source": source,
    })
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
        "SELECT ake.*, "
        "       au.email AS actor_email, "
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
    """
    now = now_utc_iso()
    #  — chained audit write via the SSOT. access_log is append-only, so every
    # written column is hashed. PERF NOTE: _chain_insert does one PK-indexed
    # `get_last_audit_row_hash` SELECT per call; on this hot per-request path a
    # cached tail (mirroring SQLiteLogHandler._last_row_hash: prime once, advance
    # in-mem, reset-to-cold on write error) would avoid it. Deferred as a scoped
    # perf follow-up (a module-level cache would break the multi-DB test
    # isolation the suite relies on; the correct home is a per-connection/
    # per-middleware cache) — raised to db-sme in the  implementation review.
    try:
        row_id = _chain_insert(conn, "access_log", {
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
        conn.commit()
        return row_id
    except sqlite3.IntegrityError as e:
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
        # The first _chain_insert raised on the INSERT (constraint), so nothing
        # committed and the chain tail is unchanged; this retry reads the same
        # tail and chains the FK-coerced row cleanly. Chain integrity preserved.
        row_id = _chain_insert(conn, "access_log", {
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
        conn.commit()
        return row_id


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


def _apply_chain_hmac(
    canonical: bytes,
    *,
    hash_alg: str = "hmac-sha256-v1",
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
    if hash_alg == "hmac-sha256-v1":
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
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()
    raise ValueError(
        f"{_what}: unknown hash_alg={hash_alg!r}. "
        f"Expected one of: 'sha256' (legacy), 'hmac-sha256-v1' (H-02a)."
    )


def compute_log_row_hash(
    prev_hash: str,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra_json: str,
    *,
    hash_alg: str = "hmac-sha256-v1",
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
            ``'hmac-sha256-v1'`` — the H-02a-mandated algorithm for new
            rows. Legacy rows are NEVER re-written under HMAC; the
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
            2026-05-23 — if ``hash_alg='hmac-sha256-v1'`` is requested
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
            (``'sha256'``, ``'hmac-sha256-v1'``).
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
    hash_alg: str = "hmac-sha256-v1",
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

    FAIL-CLOSED (PD#8/): always requests ``hmac-sha256-v1``; if no HMAC key
    is provisioned, :func:`_apply_chain_hmac` raises RuntimeError BEFORE any row
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
    hash_alg = "hmac-sha256-v1"
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

    Returns: table, chain_length, rows_checked, valid_through_id, first_break_id,
    first_break_reason, prechain_count, intact (bool).
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
    rows = conn.execute(
        f"SELECT {', '.join(select_cols)} FROM {table} ORDER BY id ASC"
    ).fetchall()

    expected_prev = ""
    chain_length = prechain_count = rows_checked = 0
    valid_through_id: int | None = None
    first_break_id: int | None = None
    first_break_reason: str | None = None

    for r in rows:
        row_hash = (r["row_hash"] or "")
        if row_hash == "":
            prechain_count += 1
            continue
        chain_length += 1
        rows_checked += 1
        canonical_values = tuple(r[name] for name in field_names)
        hash_alg = r["hash_alg"] or "hmac-sha256-v1"
        try:
            recomputed = compute_audit_row_hash(
                expected_prev, canonical_values,
                hash_alg=hash_alg,
                master_key_version=r["master_key_version"],
            )
        except Exception as e:  # missing key version, unknown alg, …
            recomputed = None
            if first_break_id is None:
                from email_triage._errfmt import fmt_exc
                first_break_id = r["id"]
                first_break_reason = (
                    f"hash recompute failed: {fmt_exc(e, with_class=True)}"
                )
        if recomputed is not None and recomputed == row_hash:
            valid_through_id = r["id"]
        elif first_break_id is None:
            first_break_id = r["id"]
            first_break_reason = (
                "row_hash mismatch — row tampered, a predecessor was deleted, "
                "or a row was forged/re-ordered"
            )
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
        "prechain_count": prechain_count,
        "intact": first_break_id is None,
    }


def verify_all_audit_chains(conn: sqlite3.Connection) -> dict[str, dict]:
    """Verify every chained audit-event table. Returns ``{table: result}``.

     — count-agnostic: iterates :data:`_AUDIT_CHAIN_CANONICAL_FIELDS`, so a
    future chained table is verified automatically with no edit here. Convenience
    for the /compliance surface + operator audits. ``log_entries`` and
    ``audit_gap_events`` keep their own verifiers (:func:`verify_log_chain`,
    distinct anchor/watermark semantics).
    """
    return {
        table: verify_audit_chain(conn, table)
        for table in _AUDIT_CHAIN_CANONICAL_FIELDS
    }


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
        hmac_chain_length:    rows with ``hash_alg='hmac-sha256-v1'``
                              (H-02a chain); subset of ``chain_length``
        hash_alg_boundary_id: smallest id where ``hash_alg !=`` legacy
                              ('sha256') — the migration boundary;
                              None if entire chain is still SHA-256

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
            "       prev_hash, row_hash, hash_alg, master_key_version "
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
            "       prev_hash, row_hash, hash_alg, master_key_version "
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
    hash_alg_boundary_id: int | None = None
    last_valid_id: int | None = (
        int(cached["valid_through_id"]) if seeded_from_cache else None
    )
    first_break_id: int | None = None
    first_break_ts: str | None = None
    first_break_expected: str | None = None
    first_break_found: str | None = None
    first_break_reason: str | None = None
    for r in rows:
        if not r["row_hash"]:
            prechain_count += 1
            continue
        chain_length += 1
        rows_checked += 1
        row_hash_alg = r["hash_alg"] or "sha256"
        row_mkv = int(r["master_key_version"] or 0)
        if row_hash_alg == "sha256":
            legacy_chain_length += 1
        elif row_hash_alg == "hmac-sha256-v1":
            hmac_chain_length += 1
            if hash_alg_boundary_id is None:
                hash_alg_boundary_id = r["id"]
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
    # hit. H-02a: legacy/hmac counts + boundary_id are NOT restored
    # from cache (they describe THIS walk's view; consumers that need
    # totals across the cache should re-compute by walking from id=0).
    if seeded_from_cache:
        prefix_len = conn.execute(
            "SELECT COUNT(*) AS c FROM log_entries "
            "WHERE row_hash != '' AND id <= ?",
            (int(cached["valid_through_id"]),),  # type: ignore[index]
        ).fetchone()
        chain_length += int(prefix_len["c"]) if prefix_len else 0

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
        except Exception:
            # ``app_state`` may be a frozen mapping or otherwise
            # unwritable; cache miss is acceptable.
            pass
    elif cache_active and first_break_id is not None:
        # Break detected — invalidate the cache so the next call
        # re-walks from the beginning.
        try:
            app_state.audit_chain_verified = None
        except Exception:
            pass

    return {
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

_AUDIT_GAP_EVENT_DDL = """\
CREATE TABLE IF NOT EXISTS audit_gap_events (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                    TEXT NOT NULL,
    helper_name           TEXT NOT NULL,
    original_args_redacted TEXT NOT NULL,
    original_args_hash    TEXT NOT NULL,
    exc_type              TEXT NOT NULL,
    exc_msg               TEXT NOT NULL,
    prev_hash             TEXT NOT NULL DEFAULT '',
    row_hash              TEXT NOT NULL DEFAULT '',
    hash_alg              TEXT,
    master_key_version    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_gap_events_ts ON audit_gap_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_gap_events_helper ON audit_gap_events(helper_name);
"""


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
    "record_hipaa_boundary": {
        "in":  {"scope", "direction", "actor_id"},
        "out": {"reason"},
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
        # text — hash-only.
        "out": {"name", "expires_at"},
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
        # (target_user_id, disabled, actor_user_id, reason).
        keys = ["target_user_id", "disabled", "actor_user_id", "reason"]
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


def get_last_gap_row_hash(conn: sqlite3.Connection) -> str:
    """Return the row_hash of the newest audit_gap_events row, or
    empty string if the table has no chain-aware rows yet.

    Mirrors :func:`get_last_log_row_hash` — same WHERE clause
    skipping prechain-sentinel rows (which we don't currently emit
    but reserve for future use), same DESC LIMIT 1.
    """
    try:
        row = conn.execute(
            "SELECT row_hash FROM audit_gap_events "
            "WHERE row_hash != '' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        # Table doesn't exist yet (pre-migration-v38 process boot).
        # The gap-write helper handles this by skipping the chain
        # write — better than crashing the wrapper's exception path.
        return ""
    return (row["row_hash"] if row else "") or ""


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
    normalised strings → utf-8). Field order is fixed; any future
    schema addition MUST extend at the END to preserve hashes of
    rows under the old field set.
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
    hash_alg: str = "hmac-sha256-v1",
    master_key_version: int | None = None,
) -> str:
    """Compute the chain hash for a new ``audit_gap_events`` row.

    EQM-05 reuse: same ``hmac-sha256-v1`` primitive + same chain key
    as :func:`compute_log_row_hash`. The gap-events chain is a
    SECOND chain (separate ``prev_hash`` lineage) keyed identically,
    so an attacker cannot forge a gap row without holding the same
    HMAC key that protects the log_entries chain.
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
    :func:`get_last_gap_row_hash` and computes the new row_hash
    inside the same `conn.execute(INSERT)` transaction so the chain
    advances atomically.
    """
    now = now_utc_iso()
    helper = helper_name or "<unknown>"
    redacted = _redact_args(helper, args, kwargs)
    arg_hash = _hash_args(args, kwargs)
    exc_type = type(exc).__name__
    # N-42: exc_msg INSERTs into the HMAC-chained audit_gap_events table —
    # scrub PHI shapes before they enter the un-expungeable chain.
    from email_triage._errfmt import redact_exc
    exc_msg = redact_exc(str(exc))[:500] if exc else ""
    prev_hash = get_last_gap_row_hash(conn)
    version = _get_current_hmac_version()
    hash_alg = "hmac-sha256-v1" if version is not None else "sha256"
    row_hash = compute_gap_row_hash(
        prev_hash, now, helper, redacted, arg_hash, exc_type, exc_msg,
        hash_alg=hash_alg, master_key_version=version,
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


# Note: ``audit_emitter`` is defined earlier in this module (hoisted
# above the 7 emitter functions that consume it). Full docstring +
# usage examples are at that definition.
