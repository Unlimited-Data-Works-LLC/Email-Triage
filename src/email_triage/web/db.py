"""Shared SQLite schema for the email triage system.

Manages all tables: flows (via FlowStore), users, classification lists,
list rules, OTP codes, and API keys.  Provides a single ``init_db`` entry
point that idempotently creates every table and index.
"""

from __future__ import annotations

from email_triage._isotime import now_utc_iso, to_utc_iso, to_utc_iso_z

import sqlite3
import threading
from pathlib import Path
from typing import Any

from email_triage.web.db_writelock import db_write
from email_triage.db._helpers import apply_compatible_row_factory, row_get, dump_json_col, load_json_col
# census #6 — secret-scrub SSOT (leaf module, stdlib-only → no import cycle).
# At top so a module-import-time caller can't NameError on the alias.
from email_triage._secret_scrub import (
    SECRET_TOKEN_KEYS as _WATCHER_RETRY_TOKEN_KEYS,
    scrub_secrets_from_text as _scrub_secrets,
)
# census run13 #2 — the BOTH-legs (PHI + secret) persisted-error funnel. The
# actuators below scrub at the write boundary (PD#9 — gate at the actuator), so
# every caller is covered regardless of how it built the error string.
from email_triage._errfmt import scrub_error_for_persist as _scrub_err_persist

from email_triage.db._helpers import row_get  # N-234c R23 SSOT
# Audit cluster — DDL constants live in db/audit.py. Imported
# here for _ALL_DDL ordering; the functions over these tables are
# re-exported via the back-compat shim at the bottom of this module.
from email_triage.db.audit import (
    _ACCESS_LOG_DDL,
    _API_KEY_EVENTS_DDL,
    _AUTH_EVENTS_DDL,
    _DISCOVER_RUNS_DDL,
    _HIPAA_ACCESS_EVENTS_DDL,
    _HIPAA_BOUNDARY_EVENTS_DDL,
    _LOG_ENTRIES_DDL,
    _USER_STATUS_EVENTS_DDL,
)

# ---------------------------------------------------------------------------
# DDL statements  (each block is idempotent via IF NOT EXISTS)
# ---------------------------------------------------------------------------

# Flows table is owned by engine/store.py but we declare it here too so that
# ``init_db`` can bootstrap a complete schema from scratch.
_FLOWS_DDL = """\
CREATE TABLE IF NOT EXISTS flows (
    flow_id           TEXT PRIMARY KEY,
    message_id        TEXT NOT NULL,
    provider          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'created',
    revision          INTEGER NOT NULL DEFAULT 0,
    classification_json TEXT,
    actions_completed_json TEXT NOT NULL DEFAULT '[]',
    actions_pending_json   TEXT NOT NULL DEFAULT '[]',
    state_bag_json    TEXT NOT NULL DEFAULT '{}',
    error             TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE(provider, message_id)
);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
CREATE INDEX IF NOT EXISTS idx_flows_provider_message ON flows(provider, message_id);
"""

_USERS_DDL = """\
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'user',
    notify_email TEXT,
    created_at   TEXT NOT NULL,
    last_login   TEXT,
    disabled             INTEGER NOT NULL DEFAULT 0,
    disabled_at          TEXT,
    disabled_by_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""

_CLASSIFICATION_LISTS_DDL = """\
CREATE TABLE IF NOT EXISTS classification_lists (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    category   TEXT NOT NULL,
    owner_id   INTEGER REFERENCES users(id),
    is_global  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lists_owner ON classification_lists(owner_id);
CREATE INDEX IF NOT EXISTS idx_lists_global ON classification_lists(is_global);
"""

_LIST_RULES_DDL = """\
CREATE TABLE IF NOT EXISTS list_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id    INTEGER NOT NULL REFERENCES classification_lists(id) ON DELETE CASCADE,
    rule_type  TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    skip_ai    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_list ON list_rules(list_id);
"""

_OTP_CODES_DDL = """\
CREATE TABLE IF NOT EXISTS otp_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_codes(email);
"""

_API_KEYS_DDL = """\
CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT NOT NULL,
    name         TEXT NOT NULL,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    expires_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash);
"""

_CATEGORIES_DDL = """\
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    slug        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(user_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_categories_slug ON categories(slug);
-- NOTE: idx_categories_user_id and idx_categories_system_slug_uniq are
-- created AFTER ensure_categories_user_id_migration runs, because on
-- legacy installs the user_id column does not exist yet and DDL here
-- would fail. See ensure_categories_user_id_migration and
-- ensure_categories_indexes below.
"""

_SETTINGS_DDL = """\
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_EMAIL_ACCOUNTS_DDL = """\
CREATE TABLE IF NOT EXISTS email_accounts (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                       TEXT NOT NULL,
    provider_type              TEXT NOT NULL,
    config_json                TEXT NOT NULL DEFAULT '{}',
    is_active                  INTEGER NOT NULL DEFAULT 1,
    hipaa                      INTEGER NOT NULL DEFAULT 0,
    created_under_system_hipaa INTEGER NOT NULL DEFAULT 0,
    aliases_json               TEXT NOT NULL DEFAULT '[]',
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_accounts_user ON email_accounts(user_id);
"""

_ACCOUNT_ROUTES_DDL = """\
CREATE TABLE IF NOT EXISTS account_routes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    category    TEXT NOT NULL,
    actions_json TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(account_id, category)
);
CREATE INDEX IF NOT EXISTS idx_account_routes_acct ON account_routes(account_id);
"""

_ACCOUNT_FOLDER_PREFS_DDL = """\
CREATE TABLE IF NOT EXISTS account_folder_prefs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    folder_path TEXT NOT NULL,
    included    INTEGER NOT NULL DEFAULT 1,
    UNIQUE(account_id, folder_path)
);
CREATE INDEX IF NOT EXISTS idx_account_folder_prefs_acct ON account_folder_prefs(account_id);
"""

_TRIAGE_RUNS_DDL = """\
CREATE TABLE IF NOT EXISTS triage_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    account_name  TEXT NOT NULL DEFAULT '',
    query         TEXT NOT NULL DEFAULT '',
    total_messages INTEGER NOT NULL DEFAULT 0,
    results_json  TEXT NOT NULL DEFAULT '[]',
    errors_json   TEXT NOT NULL DEFAULT '[]',
    elapsed_secs  REAL NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_runs_acct ON triage_runs(account_id);
CREATE INDEX IF NOT EXISTS idx_triage_runs_created ON triage_runs(created_at);
"""

_USER_ESCALATION_PREFS_DDL = """\
CREATE TABLE IF NOT EXISTS user_escalation_prefs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category           TEXT NOT NULL,
    cooldown_minutes   INTEGER NOT NULL DEFAULT 15,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE(user_id, category)
);
CREATE INDEX IF NOT EXISTS idx_user_escalation_user ON user_escalation_prefs(user_id);
"""

_SECRETS_STORE_DDL = """\
CREATE TABLE IF NOT EXISTS secrets_store (
    key        TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_GMAIL_WATCHES_DDL = """\
CREATE TABLE IF NOT EXISTS gmail_watches (
    account_id    INTEGER PRIMARY KEY REFERENCES email_accounts(id) ON DELETE CASCADE,
    email_address TEXT NOT NULL,
    topic_name    TEXT NOT NULL,
    history_id    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    -- N-256 R25: lifecycle triple (sibling to office365_subscriptions).
    status        TEXT NOT NULL DEFAULT 'active',
    error_count   INTEGER NOT NULL DEFAULT 0,
    error_last    TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gmail_watches_email ON gmail_watches(email_address);
CREATE INDEX IF NOT EXISTS idx_gmail_watches_expires ON gmail_watches(expires_at);
"""

#  — per-account delegation. Lets the account owner (or an admin)
# grant a non-admin user the right to manage a specific account
# (routes, watcher, folder prefs, digest schedules, run-triage).
# Restricted out of delegate scope: HIPAA flag flip + account
# deletion (owner / admin only — those are blast-radius operations
# that should stay with the responsible party).
#
# Audit: delegate add / remove emit INFO log lines via the standard
# logger; the ASGI access-audit middleware covers the broader
# "who hit which route" trail.
_ACCOUNT_DELEGATES_DDL = """\
CREATE TABLE IF NOT EXISTS account_delegates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    granted_at   TEXT NOT NULL,
    UNIQUE(account_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_account_delegates_user
    ON account_delegates(user_id);
CREATE INDEX IF NOT EXISTS idx_account_delegates_account
    ON account_delegates(account_id);
"""

# Loop-prevention dedup table. When a message is moved/labeled into
# a folder that's also being watched, the destination-folder watcher
# would re-fire on the new IMAP UID. We dedup by RFC-5322 Message-Id
# (cross-folder stable, cross-provider stable) hashed with the
# account_id so the raw id never sits in the DB. SHA-256 keeps the
# row small + collision-resistant; HIPAA: Message-Id is not on the
# §164.514 18-identifier list, but hashing is belt-and-suspenders so
# a DB leak doesn't disclose mailbox metadata anyway.
#
# Trimmed by the existing log-prune background loop; default
# retention 90 days (a real cascade re-fires within seconds, so the
# window is comfortably wide for any reasonable storage cost).
_TRIAGED_MESSAGES_DDL = """\
CREATE TABLE IF NOT EXISTS triaged_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    msg_id_hash   TEXT NOT NULL,
    ts            TEXT NOT NULL,
    UNIQUE(account_id, msg_id_hash)
);
CREATE INDEX IF NOT EXISTS idx_triaged_messages_ts ON triaged_messages(ts);
"""

#  — admin-managed dev-keypair table. Per-key TTL + per-email
# allowlist + audit fields. Public key stored in OpenSSH
# "ssh-ed25519 AAAA... user@host" format; fingerprint is
# SHA256:<b64> matching `ssh-keygen -lf` output. Login uses
# challenge-response over the registered ed25519 keypair.
_DEV_KEYS_DDL = """\
CREATE TABLE IF NOT EXISTS dev_keys (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT NOT NULL,
    public_key           TEXT NOT NULL,
    fingerprint          TEXT NOT NULL UNIQUE,
    email_allowlist_json TEXT NOT NULL DEFAULT '[]',
    created_by_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at           TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    last_used_at         TEXT,
    last_used_email      TEXT,
    last_used_ip         TEXT,
    revoked_at           TEXT,
    revoked_by_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_dev_keys_fingerprint ON dev_keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_dev_keys_active     ON dev_keys(revoked_at, expires_at);
"""

#  — WebAuthn / FIDO2 hardware-key registrations. credential_id is
# the WebAuthn cred id (16-1023 bytes per spec); public_key is the
# COSE-encoded public key the browser produced at registration.
# sign_count is a monotonic counter the authenticator increments per
# use — server rejects assertions where the submitted count is <=
# stored, catching cloned-authenticator attacks.
_HARDWARE_KEYS_DDL = """\
CREATE TABLE IF NOT EXISTS hardware_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,
    public_key      BLOB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT,
    aaguid          BLOB,
    nickname        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    revoked_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_hw_keys_user_active ON hardware_keys(user_id, revoked_at);
"""

#  — short-lived ceremony challenges for WebAuthn register +
# authenticate flows. 5-minute TTL, prune-on-read. Cookie-carried
# challenges leak under MITM; in-memory dies on restart and breaks
# multi-worker. DB matches the existing `otp_codes` pattern.
_WEBAUTHN_CHALLENGES_DDL = """\
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT,
    kind        TEXT NOT NULL,
    challenge   BLOB NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_email ON webauthn_challenges(email);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user  ON webauthn_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_exp   ON webauthn_challenges(expires_at);
"""

#  — ACME renewal log. One row per renewal attempt (success or
# failure); /admin/acme-status reads from here.
_ACME_RENEWAL_LOG_DDL = """\
CREATE TABLE IF NOT EXISTS acme_renewal_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    domain      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    not_before  TEXT,
    not_after   TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_acme_renewal_log_ts ON acme_renewal_log(ts);
"""

# H-05 (Cycle 7, 2026-05-24) — printable single-use recovery codes for
# MFA fallback. Operator-driven at enrollment time via `user enroll-mfa`
# CLI; user prints + stores physically. Codes are SHA-256 hashed at
# rest (same pattern as `otp_codes`); never logged or echoed plaintext.
# Default count per code-set: 10 (matches AWS / GitHub's lower bound).
# One-time consumption: `used_at` is stamped on first valid presentation,
# subsequent attempts return invalid + emit `record_auth_event`
# outcome="denied:recovery_code_already_used".
_RECOVERY_CODES_DDL = """\
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    used_at     TEXT,
    UNIQUE(user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_used ON recovery_codes(user_id, used_at);
"""

# H-05 (Cycle 7, 2026-05-24) — operator-key recovery tokens (last-
# resort MFA recovery). Generated by `user reset-mfa <target_user>`
# CLI; operator hands the printed token to the target user via an
# out-of-band channel; target user consumes once at /auth/mfa/recovery.
# Single-use + short TTL (24h default per design Q3) so a leaked
# token has a bounded blast radius. Token is SHA-256 hashed at rest;
# the plaintext is printed to CLI stdout ONCE and never persisted.
_OPERATOR_RECOVERY_KEYS_DDL = """\
CREATE TABLE IF NOT EXISTS operator_recovery_keys (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    target_user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operator_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    token_hash         TEXT NOT NULL UNIQUE,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    used_at            TEXT
);
CREATE INDEX IF NOT EXISTS idx_operator_recovery_target ON operator_recovery_keys(target_user_id);
CREATE INDEX IF NOT EXISTS idx_operator_recovery_expires ON operator_recovery_keys(expires_at);
"""

_ALL_DDL = [
    _FLOWS_DDL,
    _USERS_DDL,
    _USER_STATUS_EVENTS_DDL,
    _CLASSIFICATION_LISTS_DDL,
    _LIST_RULES_DDL,
    _OTP_CODES_DDL,
    _API_KEYS_DDL,
    _CATEGORIES_DDL,
    _SETTINGS_DDL,
    _EMAIL_ACCOUNTS_DDL,
    _ACCOUNT_ROUTES_DDL,
    _ACCOUNT_FOLDER_PREFS_DDL,
    _TRIAGE_RUNS_DDL,
    _LOG_ENTRIES_DDL,
    _USER_ESCALATION_PREFS_DDL,
    _SECRETS_STORE_DDL,
    _HIPAA_BOUNDARY_EVENTS_DDL,
    _AUTH_EVENTS_DDL,
    _HIPAA_ACCESS_EVENTS_DDL,
    _GMAIL_WATCHES_DDL,
    _API_KEY_EVENTS_DDL,
    _ACCESS_LOG_DDL,
    _TRIAGED_MESSAGES_DDL,
    _ACCOUNT_DELEGATES_DDL,
    _DEV_KEYS_DDL,
    _HARDWARE_KEYS_DDL,
    _WEBAUTHN_CHALLENGES_DDL,
    _ACME_RENEWAL_LOG_DDL,
    _RECOVERY_CODES_DDL,
    _OPERATOR_RECOVERY_KEYS_DDL,
]


# N-235 R23 — collapsed onto db/_helpers.py (was 3 byte-identical SSOTs).
from email_triage.db._helpers import _row, _rows  # noqa: E402,F401 — re-export


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Return True if `table.column` exists — used for idempotent ALTER TABLEs."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


@db_write
def checkpoint_wal_truncate(conn: sqlite3.Connection) -> dict[str, int]:
    """N-432 walresetbug P0 (2026-07-19) — serialized WAL-checkpoint SSOT.

    Runs ``PRAGMA wal_checkpoint(TRUNCATE)`` under the ``@db_write`` writer
    lock so no writer or other checkpoint can concurrently touch the WAL.
    The paired ``PRAGMA wal_autocheckpoint = 0`` in
    ``db/_engine.py::_apply_standard_pragmas`` prevents SQLite's built-in
    reader-driven auto-checkpoint from firing outside this lock — the
    walresetbug (SQLite < 3.51.3) races the checkpoint against a
    concurrent write and can corrupt the WAL header, which on the
    HMAC-chained ``log_entries`` audit table is §164.312(b)/(c)(1)
    integrity loss.

    Returns the raw ``PRAGMA wal_checkpoint`` result row as a dict:
    ``{"busy": <0/1>, "log": <wal-frames>, "checkpointed": <frames>}``.

    Wired from ``web/app.py::_wal_checkpoint_loop`` via
    ``supervised_interval_loop`` at a periodic cadence + ``db_call``
    (so the checkpoint runs on the writer thread, not the event loop).
    """
    row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    conn.commit()
    if row is None:
        return {"busy": -1, "log": -1, "checkpointed": -1}
    return {
        "busy": int(row[0]),
        "log": int(row[1]),
        "checkpointed": int(row[2]),
    }


@db_write
def _apply_migrations(conn: sqlite3.Connection) -> None:
    """Apply idempotent column additions for schema upgrades.

    SQLite's ``CREATE TABLE IF NOT EXISTS`` covers new tables, but it
    does NOT back-fill new columns on an existing table.  We use
    ``ALTER TABLE ADD COLUMN`` here guarded by a ``PRAGMA table_info``
    check so the migration is safe to run against any prior version.

    Note on versioning: there is no ``_CURRENT_SCHEMA_VERSION`` integer
    and no ``schema_version`` table. Every migration below is idempotent
    (``IF NOT EXISTS`` for new tables, ``_column_exists()`` guards for
    new columns) so startup on any prior DB converges to the current
    shape regardless of history. The previous version-integer scheme
    was write-only metadata — no code branched on it — and caused
    repeated merge conflicts when parallel branches each claimed the
    next integer. If a non-idempotent migration is ever needed, a
    sentinel row (or ``user_version`` PRAGMA) can be introduced at
    that time.
    """
    #  — log_entries hash-chain columns. Existing rows get empty
    # strings; the verifier treats them as pre-chain (skipped) and
    # validates from the first row written by a hash-aware emit.
    if not _column_exists(conn, "log_entries", "prev_hash"):
        conn.execute(
            "ALTER TABLE log_entries ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
        )
    if not _column_exists(conn, "log_entries", "row_hash"):
        conn.execute(
            "ALTER TABLE log_entries ADD COLUMN row_hash TEXT NOT NULL DEFAULT ''"
        )

    # H-02a (Cycle 6, 2026-05-23) — HMAC-SHA256 migration columns. See
    # internal documentation H-02a + db/audit.py _LOG_ENTRIES_DDL
    # rationale block. NOT-NULL defaults make this a safe idempotent upgrade:
    # legacy rows keep ('sha256', 0) and remain verifiable forever per
    # §164.316(b)(2)(i) 6-year retention; new rows post-deploy stamp
    # ('hmac-sha256-v1', <current master version>) and verify under HMAC.
    if not _column_exists(conn, "log_entries", "hash_alg"):
        conn.execute(
            "ALTER TABLE log_entries ADD COLUMN "
            "hash_alg TEXT NOT NULL DEFAULT 'sha256'"
        )
    if not _column_exists(conn, "log_entries", "master_key_version"):
        conn.execute(
            "ALTER TABLE log_entries ADD COLUMN "
            "master_key_version INTEGER NOT NULL DEFAULT 0"
        )

    # v10-era: per-account HIPAA flag + creation-under-system-HIPAA marker.
    if not _column_exists(conn, "email_accounts", "hipaa"):
        conn.execute(
            "ALTER TABLE email_accounts ADD COLUMN hipaa INTEGER NOT NULL DEFAULT 0"
        )
    if not _column_exists(conn, "email_accounts", "created_under_system_hipaa"):
        conn.execute(
            "ALTER TABLE email_accounts ADD COLUMN "
            "created_under_system_hipaa INTEGER NOT NULL DEFAULT 0"
        )

    # v13: universal discover-run audit trail. Parallel to hipaa_access_events
    # but covers every account — Discover Categories is mail-read-level
    # privilege and needs an audit row regardless of the HIPAA flag. Metadata
    # only (no sender / subject / raw_description / raw_category) because the
    # scan output is proposals-in-review, not actions taken.
    #
    # #277a (2026-05-23): the inline DDL was lifted to db.audit._DISCOVER_RUNS_DDL
    # for cluster cohesion. Still re-applied here (idempotent IF NOT EXISTS) so
    # upgrade installs that pre-date #277a continue to bootstrap the table
    # without needing a separate migration step.
    conn.executescript(_DISCOVER_RUNS_DDL)

    # v14: who clicked "Run triage" for audit. NULL = system-initiated
    # (push consumer, watcher, scheduled digest). UI manual triage path
    # stamps the logged-in user's id here.
    if not _column_exists(conn, "triage_runs", "actor_user_id"):
        conn.execute(
            "ALTER TABLE triage_runs ADD COLUMN actor_user_id INTEGER "
            "REFERENCES users(id) ON DELETE SET NULL"
        )

    # v15: disable-user toggle (fail-closed kill-switch). New users
    # default to 0 (not disabled) so existing installs are unaffected.
    if not _column_exists(conn, "users", "disabled"):
        conn.execute(
            "ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0"
        )
        conn.execute("ALTER TABLE users ADD COLUMN disabled_at TEXT")
        conn.execute(
            "ALTER TABLE users ADD COLUMN disabled_by_user_id INTEGER "
            "REFERENCES users(id) ON DELETE SET NULL"
        )

    # : WebAuthn per-user handle. Server-assigned 16-64 byte stable
    # identifier; populated lazily on first hardware-key registration.
    if not _column_exists(conn, "users", "webauthn_user_handle"):
        conn.execute(
            "ALTER TABLE users ADD COLUMN webauthn_user_handle BLOB"
        )

    # : access_log gains auth_source + auth_key_id so every audit
    # row is traceable to the auth path that minted the session.
    if not _column_exists(conn, "access_log", "auth_source"):
        conn.execute("ALTER TABLE access_log ADD COLUMN auth_source TEXT")
    if not _column_exists(conn, "access_log", "auth_key_id"):
        conn.execute("ALTER TABLE access_log ADD COLUMN auth_key_id INTEGER")

    # PR-1 (A2): request_id correlates an audit row with the
    # structured-log lines emitted during the same request. Same
    # ID is mirrored back to the client as X-Request-ID and lives
    # in the ContextVar `triage_logging.request_id_var`.
    if not _column_exists(conn, "access_log", "request_id"):
        conn.execute("ALTER TABLE access_log ADD COLUMN request_id TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_log_request_id "
            "ON access_log(request_id)"
        )

    #  — per-user session epoch for stateless-token revocation.
    # create_session_token stamps the user's current epoch into the
    # signed cookie; get_current_user rejects a token whose epoch no
    # longer matches. Bumping the epoch (set_user_disabled, the
    # "sign out all sessions" control) instantly invalidates every
    # outstanding session for that user. Existing users default to 0;
    # a token minted before this column existed carries no epoch field
    # and decodes as epoch 0 — it stays valid until its TTL, matching
    # the pre-#205 behaviour.
    if not _column_exists(conn, "users", "session_epoch"):
        conn.execute(
            "ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL "
            "DEFAULT 0"
        )

    conn.commit()


@db_write
def migrate_oauth_creds_to_install_level(conn: sqlite3.Connection) -> tuple[str, str] | None:
    """One-shot: lift per-account Gmail client_id/secret up to install level.

    Scans ``email_accounts.config_json`` for any non-empty client_id +
    client_secret pair. If found, returns the FIRST pair encountered
    (caller writes it to ``config.google_oauth.web_*``) and scrubs those
    keys from every account's config_json. Idempotent: subsequent calls
    find nothing and return None.

    The "first pair wins" policy assumes a single Google Cloud project
    per install (the common case). Installs with multiple projects will
    need to retype in /config — flagged via return value + caller log.
    """
    import json
    rows = conn.execute(
        "SELECT id, config_json FROM email_accounts WHERE provider_type = 'gmail_api'"
    ).fetchall()

    found: tuple[str, str] | None = None
    any_scrubbed = False
    for row in rows:
        try:
            cfg = load_json_col(row["config_json"], default={})
        except (json.JSONDecodeError, TypeError):
            continue
        cid = cfg.get("client_id", "")
        csec = cfg.get("client_secret", "")
        if found is None and cid and csec:
            found = (cid, csec)
        if "client_id" in cfg or "client_secret" in cfg:
            cfg.pop("client_id", None)
            cfg.pop("client_secret", None)
            conn.execute(
                "UPDATE email_accounts SET config_json = ? WHERE id = ?",
                (dump_json_col(cfg), row["id"]),
            )
            any_scrubbed = True
    if any_scrubbed:
        conn.commit()
    return found


@db_write
def migrate_o365_creds_to_install_level(
    conn: sqlite3.Connection,
    secrets,
) -> tuple[str, str, str] | None:
    """One-shot: lift per-account O365 client/tenant/secret up to install level.

    Mirrors ``migrate_oauth_creds_to_install_level`` for Gmail with two
    differences:

    1. ``tenant_id`` is a third lifted field (Gmail has no tenant
       concept). The first non-``"common"`` / non-empty / non-
       ``"organizations"`` literal wins; falls back to whatever
       appears.
    2. ``client_secret`` lived in the secrets store, not in
       ``config_json``. We pull the first non-empty
       ``ACCOUNT_{id}_O365_SECRET`` row.

    Per-account ``tenant_id == "common"`` is the legacy spelling of
    "this is a personal Microsoft account." Migration preserves the
    operator's choice by setting ``is_personal_msa = True`` on every
    such account before scrubbing the old keys.

    Returns ``(tenant_id, client_id, client_secret)`` or ``None`` if
    no per-account O365 creds existed. ``""`` for any field the
    operator never populated.
    """
    import json
    rows = conn.execute(
        "SELECT id, config_json FROM email_accounts WHERE provider_type = 'office365'"
    ).fetchall()

    chosen_tenant: str = ""
    chosen_cid: str = ""
    chosen_csec: str = ""
    any_scrubbed = False

    # First pass: pick the install-level values (tenant + client_id).
    for row in rows:
        try:
            cfg = load_json_col(row["config_json"], default={})
        except (json.JSONDecodeError, TypeError):
            continue
        tid = cfg.get("tenant_id", "")
        cid = cfg.get("client_id", "")
        # Prefer a proper org tenant GUID over "common"/"organizations".
        if not chosen_tenant and tid and tid not in ("common", "organizations"):
            chosen_tenant = tid
        if not chosen_cid and cid:
            chosen_cid = cid
    # Fallback: if nothing better turned up, accept whatever existed.
    if not chosen_tenant:
        for row in rows:
            try:
                cfg = load_json_col(row["config_json"], default={})
            except (json.JSONDecodeError, TypeError):
                continue
            tid = cfg.get("tenant_id", "")
            if tid:
                chosen_tenant = tid
                break

    # Secret comes from the secrets store, not config_json.
    if secrets is not None:
        from email_triage.secrets import SecretsDecryptError, read_secret
        # census run15 #7 — derive the key via the table-driven SSOT, never a
        # hardcoded f-string copy (a 3rd fork of the O365 key name would desync
        # from the store/read side on any future key-name change).
        from email_triage.providers.traits import secret_key_for_account
        for row in rows:
            sk = secret_key_for_account(row["id"], "office365")
            try:
                v = read_secret(secrets, sk) or ""
            except SecretsDecryptError:
                # A5 — unreadable secret (corrupt row / master-key mismatch)
                # is not "no secret": surface it instead of silently
                # hydrating O365 as if unconfigured.
                from email_triage.triage_logging import get_logger
                get_logger("web.db").error(
                    "O365 client-secret unreadable during config hydration "
                    "(corrupt row or master-key mismatch)",
                    account_id=row["id"],
                )
                v = ""
            if v:
                chosen_csec = v
                break

    # Second pass: scrub stale keys + set is_personal_msa where
    # tenant_id == "common".
    for row in rows:
        try:
            cfg = load_json_col(row["config_json"], default={})
        except (json.JSONDecodeError, TypeError):
            continue
        legacy_tenant = cfg.get("tenant_id", "")
        had_legacy_keys = (
            "client_id" in cfg
            or "tenant_id" in cfg
            or "client_secret" in cfg
        )
        if not had_legacy_keys:
            continue
        if legacy_tenant == "common":
            cfg["is_personal_msa"] = True
        cfg.pop("client_id", None)
        cfg.pop("tenant_id", None)
        cfg.pop("client_secret", None)
        conn.execute(
            "UPDATE email_accounts SET config_json = ? WHERE id = ?",
            (dump_json_col(cfg), row["id"]),
        )
        any_scrubbed = True

    if any_scrubbed:
        conn.commit()

    if not (chosen_tenant or chosen_cid or chosen_csec):
        return None
    return (chosen_tenant, chosen_cid, chosen_csec)


@db_write
def scrub_queue_summary_from_routes(conn: sqlite3.Connection) -> int:
    """Strip the deprecated `queue_summary` action from saved routes.

    Called from init_db on every startup. The queue_summary action was
    removed in favour of the digest pipeline. Existing route configs
    that reference it would otherwise raise "unknown action" at triage
    time. Idempotent — runs cheaply when nothing matches.

    Returns the number of route rows that were updated.
    """
    import json

    rows = conn.execute(
        "SELECT id, actions_json FROM account_routes "
        "WHERE actions_json LIKE '%queue_summary%'"
    ).fetchall()
    updated = 0
    for row in rows:
        try:
            actions = load_json_col(row["actions_json"], default=[])
        except Exception:
            continue
        kept = [a for a in actions if (a or {}).get("action") != "queue_summary"]
        if len(kept) == len(actions):
            continue
        # v0.1.2 dialect-portability fix: Python-side ISO timestamp instead
        # of SQLite-specific strftime('%Y-%m-%dT%H:%M:%fZ', 'now'). Same wire
        # format; portable to Postgres for v0.2.0  retrofit.

        _now_iso = now_utc_iso()
        conn.execute(
            "UPDATE account_routes SET actions_json = ?, "
            "updated_at = ? WHERE id = ?",
            (dump_json_col(kept), _now_iso, row["id"]),
        )
        updated += 1
    if updated:
        conn.commit()
    return updated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _bootstrap_schema(
    conn: sqlite3.Connection, db_path: str
) -> sqlite3.Connection:
    """Configure an already-opened connection + ensure the full schema.

    Factored out of :func:`init_db` so BOTH the plaintext
    path (``init_db``) and the SQLCipher path (``init_db_encrypted``)
    share one identical bootstrap body — same PRAGMAs, same DDL, same
    migrations, same idempotent scrubs. The ONLY difference between the
    two entry points is HOW the connection was opened (stdlib ``sqlite3``
    vs ``sqlcipher3`` with ``PRAGMA key`` already applied); everything
    downstream of the open is the same, so it lives here.

    The caller is responsible for having already run the encryption
    ``PRAGMA key`` (if any) — by the time the connection reaches this
    function it must be a fully-usable, decrypted handle.
    """
    # : cache the resolved path so single_flight._open_lock_conn
    # does not need to issue a concurrent PRAGMA database_list to
    # discover it. Routed via :func:`set_cached_db_path` because
    # sqlite3.Connection in CPython 3.13 silently rejects
    # ``setattr(conn, ...)`` (the class has no ``__dict__``).
    from email_triage.single_flight import set_cached_db_path
    set_cached_db_path(conn, db_path)
    # N-16: resolve the Row factory from the conn's own dbapi module —
    # stdlib sqlite3.Row type-rejects a sqlcipher3 cursor, so a bare
    # ``conn.row_factory = sqlite3.Row`` crashes the encrypted boot.
    apply_compatible_row_factory(conn)
    # N-214 R23 (2026-07-02): route through _engine's SSOT. The old
    # per-opener 3-line spelling drifted across 4 sites; the SSOT ensures
    # tuning changes (e.g. wal_autocheckpoint, synchronous=NORMAL) touch
    # one place. Wait up to 30s for a held write lock is now the
    # SSOT's busy_timeout=30000 setting.
    from email_triage.db._engine import _apply_standard_pragmas
    _apply_standard_pragmas(conn)

    for ddl in _ALL_DDL:
        conn.executescript(ddl)

    # Apply idempotent ALTER-TABLE migrations for upgraded DBs.
    _apply_migrations(conn)

    # Per-user categories migration + index creation. Must run
    # from init_db so tests that use init_db directly (without going
    # through app.lifespan) get the new schema + partial unique index.
    ensure_categories_user_id_migration(conn)

    # Scrub the deprecated queue_summary action from saved route
    # configs. Idempotent.
    scrub_queue_summary_from_routes(conn)

    # PR 2 / A4: numbered schema-migration framework runs LAST so it
    # sees a fully-bootstrapped legacy schema. Future migrations land
    # in ``web/migrations.py`` MIGRATIONS list; the legacy helpers
    # above stay where they are until individually absorbed.
    from email_triage.web.migrations import run_migrations
    run_migrations(conn)

    #  — seed the regulatory-clock policy catalog (base rows; idempotent
    # re-assert) once the v46 tables exist. Mirrors seed_categories; the
    # re-assert preserves the operator's enabled toggle + per-account override
    # rows. Late import keeps web/db <- db/regulatory_clock acyclic.
    from email_triage.db.regulatory_clock import seed_regulatory_clock_catalog
    seed_regulatory_clock_catalog(conn)

    return conn


def init_db(db_path: str | Path = ":memory:") -> sqlite3.Connection:
    """Open (or create) the PLAINTEXT database and ensure all tables exist.

    Returns a connection with WAL mode and foreign keys enabled.
    Uses ``check_same_thread=False`` because FastAPI serves requests
    in a threadpool while the connection is created at startup.
    This is safe because the system is single-writer by design.

    This is the default, unchanged path for every existing install and
    every test/fixture. The SQLCipher-encrypted equivalent is
    :func:`init_db_encrypted`, routed at boot only when
    ``persistence.encryption_enabled`` resolves ON.
    """
    # Drop the in-process settings cache — a fresh DB
    # invalidates any cached read by definition. Production calls
    # init_db once at startup; tests call it per fixture and need
    # the cache cleared so cross-test reuse doesn't leak entries.
    invalidate_setting_cache()

    #  Cycle 10 Phase 0:
    # - ``cached_statements=0`` mitigates CPython issue #118172
    #   (3.12/3.13 multi-thread cursor-cache silent corruption).
    #   On a shared connection with check_same_thread=False, the
    #   driver-side prepared-statement cache can return wrong-row
    #   results or hit SystemError under concurrent reads. Setting
    #   cached_statements=0 disables that cache; ~5-10% per-call
    #   regression on cached paths, but eliminates the corruption
    #   class entirely. See https://github.com/python/cpython/issues/118172
    # - ``timeout=30.0`` is belt-and-suspenders — the PRAGMA
    #   busy_timeout=30000 set inside _bootstrap_schema already configures
    #   the same underlying sqlite3_busy_timeout() primitive; setting
    #   both ensures the value is in effect during init even before
    #   the PRAGMA runs.
    # -b: standard-opener busy budget from PersistenceConfig
    # (SSOT lives in db._engine; both DBAPI kwarg + PRAGMA busy_timeout
    # derive from _SQLITE_BUSY_WAIT_SECS so a tune stays coherent).
    from email_triage.db._engine import get_sqlite_busy_wait_secs
    conn = sqlite3.connect(
        str(db_path),
        timeout=get_sqlite_busy_wait_secs(),
        check_same_thread=False,
        cached_statements=0,
    )
    return _bootstrap_schema(conn, str(db_path))


def init_db_encrypted(
    db_path: str | Path,
    master_key: str | bytes,
    *,
    purpose: str = "triage",
) -> sqlite3.Connection:
    """Open (or create) the SQLCipher-ENCRYPTED database + ensure schema.

    The encrypted analogue of :func:`init_db`. Opens the
    single-file SQLCipher connection via
    :func:`email_triage.db._engine._make_encrypted_conn` — which applies
    ``PRAGMA key`` (HKDF-derived raw-hex key) as the FIRST SQL the
    connection sees, BEFORE any read — then runs the identical
    :func:`_bootstrap_schema` body as the plaintext path.

    The returned object is a ``sqlcipher3`` connection, which is a
    DBAPI-2.0 / stdlib-``sqlite3``-compatible handle: every existing
    helper, the ``WriteSession`` Protocol, and ``set_cached_db_path``
    work against it unchanged. The ONE incompatibility is the row
    factory: stdlib ``sqlite3.Row`` is a C type that type-rejects a
    foreign (sqlcipher3) cursor, so ``conn.row_factory = sqlite3.Row``
    raises ``TypeError`` on this handle (N-16). ``_bootstrap_schema``
    therefore uses :func:`apply_compatible_row_factory`, which selects
    ``sqlcipher3.dbapi2.Row`` for this connection and ``sqlite3.Row``
    for the plaintext one.

    This function assumes the caller has ALREADY verified
    (:func:`email_triage.db._engine.enforce_db_encryption_boot_contract`)
    that ``sqlcipher3`` is importable and ``master_key`` is real. It
    raises if ``sqlcipher3`` cannot be imported (defensive — the contract
    should have caught it first), and NEVER falls back to plaintext.

    Args:
        db_path: filesystem path to the single encrypted DB file.
        master_key: the Fernet master key from the secrets backend; the
            SQLCipher storage key is HKDF-derived from it.
        purpose: HKDF namespace tag — ``"triage"`` under single-file encryption;
            reserved for v0.2.0  per-tablespace expansion.
    """
    # Late import: ``_engine`` pulls in SQLAlchemy lazily; keeping the
    # import inside the function avoids loading SA on the plaintext path
    # and matches the lazy-import convention used elsewhere in this file.
    from email_triage.db._engine import _make_encrypted_conn

    # Drop the in-process settings cache — same rationale as
    # init_db; a freshly-opened DB invalidates any cached read.
    invalidate_setting_cache()

    conn = _make_encrypted_conn(str(db_path), master_key, purpose=purpose)
    return _bootstrap_schema(conn, str(db_path))


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------

@db_write
def ensure_categories_indexes(conn: sqlite3.Connection) -> None:
    """Create the user_id + partial system-slug unique indexes.

    Called after the user_id column is known to exist (either because
    the migration just added it, or because the fresh DDL created the
    table with it). Idempotent.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_categories_user_id "
        "ON categories(user_id)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_categories_system_slug_uniq "
        "ON categories(slug) WHERE user_id IS NULL"
    )
    conn.commit()


@db_write
def ensure_categories_user_id_migration(conn: sqlite3.Connection) -> bool:
    """Migrate legacy ``categories`` table to include ``user_id`` column
    and a composite ``UNIQUE(user_id, slug)`` constraint.

    Pre-migration shape: ``slug TEXT NOT NULL UNIQUE`` (no user_id).
    Post-migration: per-user personal categories become possible, with
    existing rows carrying ``user_id = NULL`` = system-wide (the
    current semantics).

    SQLite doesn't support dropping/altering table-level UNIQUE
    constraints cleanly, so recreate the table, copy rows, swap names.
    Idempotent: if the column already exists, no-op.
    """
    cols = conn.execute("PRAGMA table_info(categories)").fetchall()
    # N-16: row_get duck-types on keys() so a sqlcipher3 Row takes the
    # keyed branch too — isinstance(c, sqlite3.Row) would mis-steer it.
    col_names = {row_get(c, "name", 1) for c in cols}
    if "user_id" in col_names:
        # Legacy upgrade path where user_id already exists: still make
        # sure the user_id + system-slug indexes are present.
        ensure_categories_indexes(conn)
        return False

    conn.execute("BEGIN")
    try:
        conn.execute("""
            CREATE TABLE categories_new (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
                slug        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                sort_order  INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                UNIQUE(user_id, slug)
            )
        """)
        conn.execute("""
            INSERT INTO categories_new
                (id, user_id, slug, description, sort_order, created_at, updated_at)
            SELECT id, NULL, slug, description, sort_order, created_at, updated_at
              FROM categories
        """)
        conn.execute("DROP TABLE categories")
        conn.execute("ALTER TABLE categories_new RENAME TO categories")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_categories_slug ON categories(slug)")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    ensure_categories_indexes(conn)
    return True


@db_write
def seed_categories(conn: sqlite3.Connection, categories: dict[str, str]) -> int:
    """Seed categories from config if the table is empty.

    Called at startup so YAML categories bootstrap the database on first run.
    Returns the number of categories seeded (0 if table already had data).
    """
    row = conn.execute("SELECT COUNT(*) AS cnt FROM categories").fetchone()
    if row["cnt"] > 0:
        return 0

    now = now_utc_iso()
    for i, (slug, desc) in enumerate(categories.items()):
        conn.execute(
            "INSERT INTO categories (slug, description, sort_order, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (slug, desc, i, now, now),
        )
    conn.commit()
    return len(categories)


# Categories the system inserts on startup if the table already has
# data but is missing them. New phases extend this dict; existing
# installs pick the additions up on next restart.
_UPGRADE_CATEGORIES: dict[str, str] = {
    "meeting-request": (
        "An email asking to schedule a meeting (no .ics attached, "
        "just prose). Distinct from `meetings`, which covers existing "
        "invites and agendas."
    ),
    "self-event": (
        "A note-to-self that the operator emailed to their own "
        "address describing a personal event (a reminder, a coffee, "
        "a dentist appointment, a school pickup). The body usually "
        "carries a date or time. Triggers the self-sent event "
        "extraction path that writes the event to the operator's "
        "self-schedule calendar."
    ),
}


@db_write
def ensure_upgrade_categories(conn: sqlite3.Connection) -> int:
    """Insert any ``_UPGRADE_CATEGORIES`` rows that are missing.

    No-op when every slug is already present. Returns the number of
    rows actually inserted. Called from the web app's startup lifespan
    after ``seed_categories`` so existing installs gain new system
    categories without losing user-added ones.
    """
    rows = conn.execute("SELECT slug FROM categories").fetchall()
    existing = {r["slug"] for r in rows}
    if not (set(_UPGRADE_CATEGORIES) - existing):
        return 0

    # Sort_order: append after the highest existing.
    max_row = conn.execute(
        "SELECT COALESCE(MAX(sort_order), 0) AS m FROM categories"
    ).fetchone()
    next_sort = int(max_row["m"]) + 1 if max_row else 0

    now = now_utc_iso()
    inserted = 0
    for slug, desc in _UPGRADE_CATEGORIES.items():
        if slug in existing:
            continue
        conn.execute(
            "INSERT INTO categories (slug, description, sort_order, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (slug, desc, next_sort, now, now),
        )
        next_sort += 1
        inserted += 1
    conn.commit()
    return inserted


# Cap personal categories per user to bound prompt size in the
# classifier. System cats are operator-curated (admin-only); personal
# cats are user-curated (can grow faster) so the cap is narrower.
MAX_PERSONAL_CATEGORIES_PER_USER = 20


def list_categories(
    conn: sqlite3.Connection,
    user_id: int | None = None,
    scope: str = "all",
) -> list[dict]:
    """Return categories, ordered by sort_order.

    ``scope``:
    * ``"system"`` — only system cats (``user_id IS NULL``).
    * ``"personal"`` — only ``user_id == <user_id>`` (requires user_id).
    * ``"all"`` (default) — system cats when ``user_id`` is None; else
      system ∪ personal for that user.
    """
    if scope == "system":
        rows = conn.execute(
            "SELECT id, user_id, slug, description, sort_order FROM categories "
            "WHERE user_id IS NULL ORDER BY sort_order, id"
        ).fetchall()
    elif scope == "personal":
        if user_id is None:
            return []
        rows = conn.execute(
            "SELECT id, user_id, slug, description, sort_order FROM categories "
            "WHERE user_id = ? ORDER BY sort_order, id",
            (user_id,),
        ).fetchall()
    else:  # all
        if user_id is None:
            rows = conn.execute(
                "SELECT id, user_id, slug, description, sort_order FROM categories "
                "WHERE user_id IS NULL ORDER BY sort_order, id"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, user_id, slug, description, sort_order FROM categories "
                "WHERE user_id IS NULL OR user_id = ? ORDER BY sort_order, id",
                (user_id,),
            ).fetchall()
    return _rows(rows)


def get_categories_dict(
    conn: sqlite3.Connection,
    user_id: int | None = None,
) -> dict[str, str]:
    """Return categories as {slug: description} for the classifier.

    Personal cats override system cats on slug collision (the user's
    description wins). When ``user_id`` is None, returns system cats
    only — preserves legacy behaviour for admin / shared paths.
    """
    if user_id is None:
        rows = conn.execute(
            "SELECT slug, description FROM categories "
            "WHERE user_id IS NULL ORDER BY sort_order, id"
        ).fetchall()
        return {r["slug"]: r["description"] for r in rows}

    #  — one query instead of two. System rows (user_id IS NULL)
    # sort before personal rows via `user_id IS NOT NULL` (0 then 1),
    # so the dict build applies personal descriptions last and the
    # user's wording wins on a slug collision — same override + order
    # as the prior system-then-user two-SELECT.
    rows = conn.execute(
        "SELECT slug, description FROM categories "
        "WHERE user_id IS NULL OR user_id = ? "
        "ORDER BY (user_id IS NOT NULL), sort_order, id",
        (user_id,),
    ).fetchall()
    result: dict[str, str] = {}
    for r in rows:
        result[r["slug"]] = r["description"]
    return result


def count_personal_categories(conn: sqlite3.Connection, user_id: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM categories WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return int(row["c"] if row else 0)


def get_category(conn: sqlite3.Connection, category_id: int) -> dict | None:
    """Get a single category by ID."""
    row = conn.execute(
        "SELECT id, user_id, slug, description, sort_order FROM categories WHERE id = ?",
        (category_id,),
    ).fetchone()
    return _row(row)


@db_write
def create_category(
    conn: sqlite3.Connection,
    slug: str,
    description: str,
    user_id: int | None = None,
) -> int:
    """Create a new category. Returns the ID.

    ``user_id`` None = system-wide (admin-only path). Non-None = personal
    category for that user; subject to MAX_PERSONAL_CATEGORIES_PER_USER.
    Raises ValueError when the personal cap would be exceeded.
    """
    if user_id is not None:
        if count_personal_categories(conn, user_id) >= MAX_PERSONAL_CATEGORIES_PER_USER:
            raise ValueError(
                f"Personal category limit reached "
                f"({MAX_PERSONAL_CATEGORIES_PER_USER} per user). "
                f"Delete an unused category first."
            )
    now = now_utc_iso()
    max_order = conn.execute(
        "SELECT COALESCE(MAX(sort_order), -1) AS m FROM categories"
    ).fetchone()["m"]
    cursor = conn.execute(
        "INSERT INTO categories (user_id, slug, description, sort_order, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, slug, description, max_order + 1, now, now),
    )
    conn.commit()
    return cursor.lastrowid


@db_write
def update_category(conn: sqlite3.Connection, category_id: int, slug: str, description: str) -> bool:
    """Update a category. Returns True if updated."""
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE categories SET slug = ?, description = ?, updated_at = ? WHERE id = ?",
        (slug, description, now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


@db_write
def delete_category(conn: sqlite3.Connection, category_id: int) -> bool:
    """Delete a category. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    return cursor.rowcount > 0


@db_write
def promote_category_to_system(conn: sqlite3.Connection, category_id: int) -> bool:
    """Promote a personal category (user_id != NULL) to system (user_id = NULL).

    Fails if the slug already exists at system scope (to avoid collisions).
    Admin-only path; caller enforces authorisation.
    """
    row = conn.execute(
        "SELECT slug, user_id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None or row["user_id"] is None:
        return False
    # Reject if system cat with this slug already exists.
    existing = conn.execute(
        "SELECT 1 FROM categories WHERE user_id IS NULL AND slug = ?",
        (row["slug"],),
    ).fetchone()
    if existing is not None:
        raise ValueError(
            f"System category with slug '{row['slug']}' already exists; "
            f"cannot promote."
        )
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE categories SET user_id = NULL, updated_at = ? WHERE id = ?",
        (now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


@db_write
def demote_category_to_user(
    conn: sqlite3.Connection, category_id: int, target_user_id: int,
) -> bool:
    """Demote a system category (user_id = NULL) to personal scope for
    ``target_user_id``.

    Fails (returns False) if the cat doesn't exist or is already personal.
    Raises ValueError on:
      - target user already at MAX_PERSONAL_CATEGORIES_PER_USER cap
      - target user already has a personal cat with the same slug
      - target user_id doesn't exist

    Admin-only path; caller enforces authorisation.

    Note this changes visibility for everyone except the target user --
    the cat disappears from their classifier prompt. UI surface should
    confirm before invoking.
    """
    row = conn.execute(
        "SELECT slug, user_id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None or row["user_id"] is not None:
        return False
    # Verify target user exists.
    target = conn.execute(
        "SELECT id FROM users WHERE id = ?", (target_user_id,)
    ).fetchone()
    if target is None:
        raise ValueError(f"Target user_id {target_user_id} does not exist.")
    # Reject if target user already at the personal cap.
    if count_personal_categories(conn, target_user_id) >= MAX_PERSONAL_CATEGORIES_PER_USER:
        raise ValueError(
            f"Target user already at the personal category cap "
            f"({MAX_PERSONAL_CATEGORIES_PER_USER}); cannot demote."
        )
    # Reject if target user already has a personal cat with the same slug.
    existing = conn.execute(
        "SELECT 1 FROM categories WHERE user_id = ? AND slug = ?",
        (target_user_id, row["slug"]),
    ).fetchone()
    if existing is not None:
        raise ValueError(
            f"Target user already has a personal category with slug "
            f"'{row['slug']}'; cannot demote."
        )
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE categories SET user_id = ?, updated_at = ? WHERE id = ?",
        (target_user_id, now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Settings helpers (key-value store)
#
# Architecture:
#
# * **Single-writer.** Only ``set_setting`` and ``delete_setting`` mutate
#   the ``settings`` table (with one in-tree exception: the audit chain
#   anchor in ``triage_logging.py`` UPSERTs inside a transaction; that
#   site invalidates the cache explicitly via :func:`invalidate_setting_cache`).
# * **Process-local TTL cache** in front of ``get_setting`` to absorb
#   the hot read pattern (digest scheduler tick, poll loop, watcher
#   restore) without forcing every read through SQLite's GIL-serialised
#   handle. The cache is in-memory only; it does NOT survive a process
#   restart, and is NOT shared between processes / workers — DB is the
#   source of truth, the cache is a per-process accelerator.
# * **Corrupt-row defensive**: ``get_setting`` wraps
#   ``json.loads`` in try/except. A row with mangled JSON (operator
#   manual SQL edit, partial write, encoding issue) used to bubble a
#   ``JSONDecodeError`` up through every caller — digest scheduler
#   tick, poll loop, watcher state read all aborted. Now we log a
#   structured WARNING with the **key only** (the value is suspect /
#   potentially sensitive) and return ``None``, matching "row not
#   found" semantics. The poisoned row stays in place until an
#   operator fixes or deletes it.
# ---------------------------------------------------------------------------

# In-process TTL cache for ``get_setting``. Keyed by setting key →
# ``(value, expires_at_monotonic)``. Single source of truth on TTL —
# tests can monkey-patch :data:`_SETTINGS_CACHE_TTL_SECONDS` to a
# small value (or to 0 to disable the cache).
_SETTINGS_CACHE_TTL_SECONDS: float = 60.0
_settings_cache: dict[str, tuple[Any, float]] = {}
# ``get_setting`` runs on the threadpool workers (every ``db_call``),
# so concurrent reads/writes hit ``_settings_cache`` from multiple
# threads. dict ops are individually atomic under CPython's GIL, but a
# read-modify (``get`` then ``pop`` on expiry) is not — two threads can
# race the pop and one hits a KeyError-shaped surprise, or a clear()
# can interleave a mid-iteration mutation. Guard every mutation.
_settings_cache_lock = threading.Lock()


def invalidate_setting_cache(key: str | None = None) -> None:
    """Drop a cached setting entry (or the entire cache when ``key`` is None).

    Called by :func:`set_setting` / :func:`delete_setting` automatically.
    Exposed so the audit-chain anchor in ``triage_logging`` (which
    UPSERTs the settings row inside its own transaction) and any future
    in-tree direct writer can keep the cache coherent.
    """
    with _settings_cache_lock:
        if key is None:
            _settings_cache.clear()
        else:
            _settings_cache.pop(key, None)


def get_setting(conn: sqlite3.Connection, key: str) -> dict | None:
    """Get a setting by key. Returns the parsed JSON value or None.

    Caches the parsed result for :data:`_SETTINGS_CACHE_TTL_SECONDS`
    seconds in-process. Corrupt JSON rows return ``None`` after a
    structured WARNING is emitted (key only — the value is suspect).
    """
    import json
    import time as _time

    # Cache hit.
    with _settings_cache_lock:
        cached = _settings_cache.get(key)
        if cached is not None:
            value, expires_at = cached
            if _time.monotonic() < expires_at:
                return value
            # Expired — drop it and fall through to re-read.
            _settings_cache.pop(key, None)

    row = conn.execute(
        "SELECT value_json FROM settings WHERE key = ?", (key,),
    ).fetchone()
    if row is None:
        # Negative cache: avoid re-querying for missing keys inside the
        # TTL window. The cache invalidates on set_setting, so a later
        # write becomes visible.
        if _SETTINGS_CACHE_TTL_SECONDS > 0:
            with _settings_cache_lock:
                _settings_cache[key] = (None, _time.monotonic() + _SETTINGS_CACHE_TTL_SECONDS)
        return None

    try:
        # NOT routed through load_json_col — this site has custom corrupt-
        # handling the leaf helper can't replicate: the except logs the
        # offending KEY (forensics) AND skips the cache so a fix-via-set takes
        # effect. value_json is also any-shape.
        value = json.loads(row["value_json"])  # json-col-ok (census )
    except json.JSONDecodeError as exc:
        # .1 — defensive on corrupt JSON. Log key only (value is
        # suspect / potentially sensitive). Treat as missing so callers
        # don't crash. Skip the cache so a fix-via-set takes effect.
        from email_triage.triage_logging import get_logger
        get_logger("web.db.settings").warning(
            "settings_row_corrupt_json",
            key=key,
            error=str(exc),
        )
        return None

    if _SETTINGS_CACHE_TTL_SECONDS > 0:
        with _settings_cache_lock:
            _settings_cache[key] = (value, _time.monotonic() + _SETTINGS_CACHE_TTL_SECONDS)
    return value


@db_write
def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    """Set a setting (upsert) and invalidate the in-process cache."""
    import json
    now = now_utc_iso()
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (key, dump_json_col(value), now),
    )
    conn.commit()
    invalidate_setting_cache(key)


@db_write
def delete_setting(conn: sqlite3.Connection, key: str) -> bool:
    """Delete a setting. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    conn.commit()
    invalidate_setting_cache(key)
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# N-349 hybrid — operator-armed one-shot HMAC clobber bypass (CLI-only)
# ---------------------------------------------------------------------------
#
# The `get_or_mint_secret` SSOT in `secrets.py` is fail-CLOSED by default:
# an unreadable secret row (master-key mismatch) raises SecretsDecryptError
# instead of silently minting a replacement. That prevents the clobber
# class the 2026-06-08 OAuth save-clobber post-mortem closed on the WRITE
# arm, mirrored to the READ arm.
#
# Some recovery scenarios need the OPPOSITE — a receiver holding an old
# master key whose consumer HAS the current key must be able to mint a
# fresh HMAC secret so the receiver + system re-sync. Operator arms the
# one-shot bypass via the CLI (`secrets allow-hmac-clobber-once`); the
# NEXT unreadable-read triggered by an actual watch-HMAC hydration path
# consumes the flag + mints a replacement + clears the flag. Env-flag
# is DELIBERATELY NOT supported (per operator directive 2026-07-05) so a
# runaway process cannot re-arm the bypass without the CLI's audit trail.

HMAC_CLOBBER_BYPASS_KEY = "secrets:hmac_clobber_bypass_once"

# N-364 R31 (2026-07-05 trust-repair fix-forward per SME panel F6 +
# HIPAA-SME MED #3 + the backlog N-349b item 4 = TASK ): default TTL
# on the operator-armed bypass. If the operator arms the flag + then
# forgets (or the intended admin re-save never happens), the first
# LEGITIMATE unreadable read months later silently consumes it. TTL
# forces the arm to expire — operator re-arms if they still need to
# recover. 15 minutes is chosen to bound the window to a single admin-
# session length; operator can extend via the CLI verb's `--ttl-min`
# flag (see cli.py::cmd_secrets).
HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC = 15 * 60


def is_hmac_clobber_bypass_armed(conn: sqlite3.Connection) -> bool:
    """True iff the operator has armed a one-shot HMAC clobber bypass
    (via the `secrets allow-hmac-clobber-once` CLI verb) AND the arm
    has not yet expired per its TTL. Consumed by the next
    SecretsDecryptError-triggered watch-HMAC hydration or by an
    explicit `consume_hmac_clobber_bypass` call.

    N-364 R31 (2026-07-05): TTL-aware. A row with `expires_at` in the
    past reports as NOT armed (even though the row is still in the
    settings table). Cleanup of the expired row happens on the next
    consume — this predicate is a read-only status check.
    """
    row = get_setting(conn, HMAC_CLOBBER_BYPASS_KEY)
    if not row:
        return False
    if not row.get("armed"):
        return False
    exp = row.get("expires_at")
    if exp:
        from datetime import datetime, timezone
        from email_triage._isotime import parse_iso_aware
        expires_at = parse_iso_aware(exp)
        if expires_at is None:
            # Malformed expires_at — treat as expired (fail-CLOSED).
            return False
        if datetime.now(timezone.utc) >= expires_at:
            return False
    return True


def hmac_clobber_bypass_status(conn: sqlite3.Connection) -> dict[str, Any]:
    """N-364 R31 (2026-07-05) — read-only status for the operator's
    `secrets show-hmac-clobber-bypass` CLI verb. Never mutates state.

    Returns a dict with keys: ``armed`` (bool), ``expires_at`` (ISO
    string or None), ``armed_at`` (ISO string or None), ``expired``
    (bool — True iff the row is present but past its expiry;
    `armed=False` in that case).
    """
    row = get_setting(conn, HMAC_CLOBBER_BYPASS_KEY)
    if not row:
        return {"armed": False, "expires_at": None, "armed_at": None, "expired": False}
    exp = row.get("expires_at")
    armed_at = row.get("armed_at")
    expired = False
    if exp:
        from datetime import datetime, timezone
        from email_triage._isotime import parse_iso_aware
        expires_at = parse_iso_aware(exp)
        if expires_at is None:
            expired = True
        else:
            expired = datetime.now(timezone.utc) >= expires_at
    return {
        "armed": bool(row.get("armed")) and not expired,
        "expires_at": exp,
        "armed_at": armed_at,
        "expired": expired,
    }


def arm_hmac_clobber_bypass(
    conn: sqlite3.Connection,
    *,
    ttl_sec: int | None = None,
    actor_id: int | None = None,
) -> None:
    """CLI-only — arm the one-shot HMAC clobber bypass. See module
    docstring for the recovery contract.

    N-364 R31 (2026-07-05): now stamps `armed_at` + `expires_at` in the
    settings row per SME panel F6 + HIPAA-SME MED #3. Default TTL is
    :data:`HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC` (15 min). Pass
    ``ttl_sec`` to override; pass 0 to arm without expiry (operator
    explicit break-glass — accept until manually cleared).

    N-364 R31 also captures ``actor_id`` (§164.308(a)(4)(ii)(C) — ties
    the ESTABLISHMENT event to the CONSUMPTION log line). CLI callers
    supply it from the authenticated CLI actor; None is acceptable for
    scripted/bootstrap runs but sacrifices actor traceability.

    Delegates to :func:`set_setting` (which carries the `@db_write`
    decorator + cache-invalidation).
    """
    from datetime import datetime, timedelta, timezone
    if ttl_sec is None:
        ttl_sec = HMAC_CLOBBER_BYPASS_DEFAULT_TTL_SEC
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "armed": True,
        "armed_at": to_utc_iso_z(now),
    }
    if actor_id is not None:
        payload["armed_by_actor_id"] = int(actor_id)
    if ttl_sec and ttl_sec > 0:
        payload["expires_at"] = to_utc_iso_z(
            now + timedelta(seconds=int(ttl_sec)),
        )
    set_setting(conn, HMAC_CLOBBER_BYPASS_KEY, payload)


def clear_hmac_clobber_bypass(conn: sqlite3.Connection) -> None:
    """Consume + clear the one-shot HMAC clobber bypass. Called by the
    SSOT after a bypass-authorised mint completes. Delegates to
    :func:`delete_setting` (which carries the `@db_write` decorator).

    Retained for API parity + downstream tooling that arms/clears
    separately. Prefer :func:`consume_hmac_clobber_bypass` inside the
    SSOT hot path — it's atomic against concurrent unreadable-reads.
    """
    delete_setting(conn, HMAC_CLOBBER_BYPASS_KEY)


def consume_hmac_clobber_bypass(conn: sqlite3.Connection) -> bool:
    """N-363 R31 (2026-07-05 trust-repair fix-forward per SME panel
    2026-07-05 DA F1 residual + the backlog N-349b item 2 = TASK ) —
    atomic check-and-consume of the one-shot HMAC clobber bypass.

    Returns ``True`` iff a bypass row was armed AND was consumed by this
    call; ``False`` if no bypass was armed. Under two concurrent
    unreadable-reads with `armed=True`, EXACTLY ONE call returns True
    (the other observes the row already gone). Race-safe by SQL
    atomicity of the `DELETE` (SQLite serialises WRITEs on the settings
    table via `@db_write`).

    Replaces the non-atomic `is_hmac_clobber_bypass_armed(...) → …
    → clear_hmac_clobber_bypass(...)` sequence that N-349 hybrid
    (`b739ea11`) used. The old two-step shape allowed a double-mint
    race (both workers observed armed=True, both minted). This SSOT
    collapses the check + clear into ONE atomic operation. Delegates
    to :func:`delete_setting` (which carries the `@db_write` decorator
    + cache-invalidation) — the delete-existed boolean IS the
    consumed-a-row signal.

    NOTE: any settings row under `HMAC_CLOBBER_BYPASS_KEY` is treated
    as "armed" — the arm helper writes `{"armed": true}` and never
    writes `{"armed": false}`. Absent row = not armed. Row-present-
    with-armed=false would be an inconsistent state and this consume
    still returns True on the delete (safest: an inconsistent row
    surfaces + gets removed on the next consume).
    """
    return delete_setting(conn, HMAC_CLOBBER_BYPASS_KEY)


# ---------------------------------------------------------------------------
#  Internet Search — SearXNG free-text backend (opt-in, admin-configured)
# ---------------------------------------------------------------------------

#: Settings-table key for the optional self-hosted SearXNG host that powers
#: the Topic editor's free-text Internet Search (the non-HIPAA path; HIPAA
#: Topics are registry-only regardless). Stored as ``{"searxng_url": "..."}``.
WEB_SEARCH_SETTING_KEY = "web_search"


def get_web_search_searxng_url(conn: sqlite3.Connection) -> str | None:
    """Return the operator-configured SearXNG base URL, or None.

    None means free-text Internet Search is **not configured** — the editor
    shows a self-explaining disabled state and falls back to registry-only
    (study-number) lookups. This single host is the ONLY destination the
    web-search egress ever calls (design §3d allow-list); it is set by an
    admin via /admin/integrations, so a misconfig can't repoint it without
    admin access.
    """
    cfg = get_setting(conn, WEB_SEARCH_SETTING_KEY)
    if not isinstance(cfg, dict):
        return None
    url = cfg.get("searxng_url")
    if isinstance(url, str) and url.strip():
        return url.strip()
    return None


def set_web_search_searxng_url(conn: sqlite3.Connection, url: str | None) -> None:
    """Set (or, on empty/None, clear) the SearXNG base URL.

    Delegates to the (write-decorated) ``set_setting`` / ``delete_setting``
    so it inherits the single-writer path + cache invalidation.
    """
    cleaned = (url or "").strip()
    if cleaned:
        set_setting(conn, WEB_SEARCH_SETTING_KEY, {"searxng_url": cleaned})
    else:
        delete_setting(conn, WEB_SEARCH_SETTING_KEY)


# ---------------------------------------------------------------------------
# Bool-setting convenience helpers
#
# Many call sites store ``{"enabled": bool}`` under a settings key. Going
# through ``set_setting`` / ``get_setting`` directly works, but the
# ``{"enabled": ...}`` wrapper repeats at every site (6+ in-tree as of
# Bundle D) and the read side has to reach into ``raw.get("enabled")``
# defensively. These helpers centralise the shape so future fields
# (e.g. ``disabled_by``, ``disabled_at``) can land in one place.
#
# Forward-compat: the dict shape is preserved; only the ``enabled`` key
# is read/written here. Other fields (set by other code paths) are left
# untouched on read; ``set_bool_setting`` overwrites the entire blob, so
# callers that need to preserve sibling keys must do their own
# read-modify-write.
#
# Legacy compat: rows written under bare-bool or bare-int shape (one
# pre-#145.7 path stored ``True``/``1`` directly) are still readable —
# the truthiness of the unwrapped value is honoured.
# ---------------------------------------------------------------------------

def get_bool_setting(
    conn: sqlite3.Connection, key: str, default: bool = False,
) -> bool:
    """Read a ``{"enabled": bool}``-shaped settings row.

    Returns ``default`` when the row is missing. Honours legacy bare-bool
    / bare-int values for backwards compatibility with rows written
    before this helper landed.
    """
    raw = get_setting(conn, key)
    if raw is None:
        return bool(default)
    if isinstance(raw, dict):
        if "enabled" in raw:
            return bool(raw.get("enabled"))
        # Dict without ``enabled`` key — treat as missing (default).
        return bool(default)
    # Legacy bare-bool / bare-int / bare-string.
    return bool(raw)


def set_bool_setting(
    conn: sqlite3.Connection, key: str, value: bool,
) -> None:
    """Persist a ``{"enabled": bool}``-shaped settings row."""
    set_setting(conn, key, {"enabled": bool(value)})


# ---------------------------------------------------------------------------
# Per-mailbox high-water mark helpers
#
# IMAP UIDs are LOCAL to a mailbox — UID 500 in INBOX is unrelated to UID
# 500 in Spam. When we watch multiple folders per account we must track
# one HWM per (account, mailbox). Storage key:
#   watch_hwm:<account_id>:mailbox:<mailbox_name>
# The legacy per-account key ``watch_hwm:<account_id>`` is still honored
# as the INBOX HWM on first read (almost every existing install watches
# only INBOX), and then rewritten in the new shape so subsequent reads
# are direct hits.
# ---------------------------------------------------------------------------

def _hwm_key_for(account_id: int, mailbox: str) -> str:
    # .3 — registry-backed, but keep the helper for backwards-compat
    # so existing call sites don't churn.
    from email_triage.web.settings_keys import watch_hwm_mailbox
    return watch_hwm_mailbox(account_id, mailbox)


def _legacy_hwm_key_for(account_id: int) -> str:
    from email_triage.web.settings_keys import watch_hwm
    return watch_hwm(account_id)


def get_mailbox_hwm(
    conn: sqlite3.Connection, account_id: int, mailbox: str,
) -> dict | None:
    """Return the per-mailbox HWM dict, migrating a legacy per-account
    key on first read when ``mailbox`` is ``INBOX``.

    The migration path: if there is no new-shaped key yet AND a legacy
    per-account key exists AND the caller is asking about INBOX, copy
    the legacy value into the new key and return it. The legacy key is
    left intact — callers like ``watch/reset-hwm`` / ``watch/set-hwm-current``
    already write the new key directly, so the legacy key becomes inert
    once the migration has fired once.
    """
    new = get_setting(conn, _hwm_key_for(account_id, mailbox))
    if new is not None:
        return new
    if mailbox == "INBOX":
        legacy = get_setting(conn, _legacy_hwm_key_for(account_id))
        if legacy is not None:
            # Seed the new-shaped key so subsequent reads don't have to
            # rediscover the legacy one.
            set_setting(conn, _hwm_key_for(account_id, mailbox), legacy)
            return legacy
    return None


def make_hwm_value(uid: int, uidvalidity: int | None) -> dict:
    """The SINGLE constructor for a persisted high-water-mark value.

    Every HWM write — unified poll, IDLE watcher, operator "Set HWM to
    current" — builds its value here, so the ``{uid, uidvalidity,
    updated_at}`` shape (and crucially the ``uidvalidity`` epoch the
    reset guard ``app._resolve_hwm_with_uidvalidity`` needs) can't drift
    or be omitted by a hand-rolled dict literal. ``uidvalidity`` is
    ``None`` for providers that don't expose it (Gmail/O365).

    Divergence census 2026-06-09  / N-50: the operator "Set HWM" path
    had hand-rolled a literal missing ``uidvalidity`` → silent mail loss
    after a UIDVALIDITY epoch change. Routing all writers through this
    builder (pinned: no raw HWM-dict literal outside it) is the
    count-agnostic prevention.
    """
    return {
        "uid": int(uid),
        "uidvalidity": uidvalidity,
        "updated_at": now_utc_iso(),
    }


def set_mailbox_hwm(
    conn: sqlite3.Connection, account_id: int, mailbox: str, value: dict,
) -> None:
    set_setting(conn, _hwm_key_for(account_id, mailbox), value)


def delete_mailbox_hwm(
    conn: sqlite3.Connection, account_id: int, mailbox: str,
) -> bool:
    return delete_setting(conn, _hwm_key_for(account_id, mailbox))


# ---------------------------------------------------------------------------
# Email account helpers
# ---------------------------------------------------------------------------











# ---------------------------------------------------------------------------
# Unified push + poll config — bounds and back-compat
# ---------------------------------------------------------------------------
#
# Every account carries three independent knobs:
#   * push_enabled — start the real-time mechanism (IMAP IDLE / Gmail
#     Pub/Sub / Graph subscription) for this provider
#   * poll_enabled — run a background poller on the configured cadence
#     regardless of push state; acts as a safety net when push is on and
#     as primary ingestion when push is off
#   * poll_interval_minutes — cadence in minutes (default 60, range
#     10–240, step 10)
#
# These live in ``account.config_json``. For previously-saved accounts
# that predate this model we synthesize sensible defaults on read so
# nothing has to be migrated at the DB layer — the three keys appear
# once an account is saved again.















# ---------------------------------------------------------------------------
# Per-account delegation
# ---------------------------------------------------------------------------



































# ---------------------------------------------------------------------------
# Account route helpers (per-account category→action mappings)
# ---------------------------------------------------------------------------









# ---------------------------------------------------------------------------
# Account Folder Preferences
# ---------------------------------------------------------------------------







# ---------------------------------------------------------------------------
# Triage run tracking
# ---------------------------------------------------------------------------

@db_write
def record_triage_run(
    conn: sqlite3.Connection,
    account_id: int,
    account_name: str,
    query: str,
    total_messages: int,
    results: list[dict],
    errors: list[str],
    elapsed_secs: float,
    actor_user_id: int | None = None,
) -> int:
    """Record a completed triage run. Returns the run ID.

    ``actor_user_id`` stamps who initiated the run for audit on the
    ``/runs`` view. System-initiated runs (push, watch, scheduled)
    leave it ``None`` — the UI renders those as ``system``.
    """
    import json
    now = now_utc_iso()
    cursor = conn.execute(
        "INSERT INTO triage_runs "
        "(account_id, account_name, query, total_messages, results_json, "
        "errors_json, elapsed_secs, created_at, actor_user_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (account_id, account_name, query, total_messages,
         dump_json_col(results), dump_json_col(errors), elapsed_secs, now,
         actor_user_id),
    )
    conn.commit()
    return cursor.lastrowid


def list_triage_runs(
    conn: sqlite3.Connection,
    limit: int = 20,
    account_id: int | None = None,
) -> list[dict]:
    """Return recent triage runs, newest first.

    Each row carries ``actor_email`` and ``actor_name`` resolved from
    ``actor_user_id`` when present — NULL for system-initiated runs.
    """
    import json
    base = (
        "SELECT tr.*, u.email AS actor_email, u.name AS actor_name "
        "FROM triage_runs tr LEFT JOIN users u ON tr.actor_user_id = u.id "
    )
    if account_id is not None:
        rows = conn.execute(
            base + "WHERE tr.account_id = ? ORDER BY tr.id DESC LIMIT ?",
            (account_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            base + "ORDER BY tr.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["results"] = load_json_col(d.pop("results_json", "[]"), default=[])
        d["errors"] = load_json_col(d.pop("errors_json", "[]"), default=[])
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# triage_jobs — background whole-mailbox triage runs
# ---------------------------------------------------------------------------
#
# Distinct from ``triage_runs`` (one row per completed inline run, holds
# the results JSON for the UI). ``triage_jobs`` is the BACKGROUND-job
# control table — one row per long-running sweep, status tracks
# queued/running/cancelled/done/failed. The runner task drains queued
# rows, processes messages under rate-limit + concurrency knobs, and
# updates progress counters every batch. Per-message results still
# write into the existing ``triage_runs`` table (one row per message
# under the same actor) so the UI can show "live feed" without
# denormalising into the job row.

import secrets as _secrets_mod  # local alias; module-level ``secrets`` is the SecretsProvider import elsewhere


def _new_job_id() -> str:
    """Generate a job_id of the form ``tjob_<12-hex>``."""
    # N-244b R25: SSOT — `_ids.new_short_id`. Byte-identical wire shape.
    from email_triage._ids import new_short_id
    return new_short_id("tjob")


@db_write
def create_triage_job(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: int | None,
    query: str,
    rate_msg_per_min: int,
    concurrency: int,
    kind: str = "triage",
) -> str:
    """Insert a queued triage_job row. Returns the job_id.

    ``kind`` (v21+) discriminates the workload:

      * ``"triage"`` (default) — legacy whole-mailbox classify-then-
        act sweep. The bulk runner walks the provider search results
        + classifies + dispatches actions per-message.
      * ``"style_mine"`` — M-3 style-mine variant. The bulk runner
        pulls up to ``rate_msg_per_min`` sent messages, runs M-3
        distill once, persists the resulting profile, and finishes.
        ``query`` for style-mine jobs encodes the sent-folder name +
        the resolved limit; the runner re-parses it at job start.

    Pre-v21 callers omit ``kind`` and get the legacy default. New
    callers (style-mine handoff path) pass ``kind='style_mine'``
    explicitly.
    """
    job_id = _new_job_id()
    now = now_utc_iso()
    conn.execute(
        "INSERT INTO triage_jobs "
        "(job_id, account_id, actor_user_id, query, status, "
        " rate_msg_per_min, concurrency, kind, created_at) "
        "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)",
        (job_id, account_id, actor_user_id, query,
         rate_msg_per_min, concurrency, kind, now),
    )
    conn.commit()
    return job_id


def get_triage_job(
    conn: sqlite3.Connection, job_id: str,
) -> dict | None:
    """Return one job row by id, or None."""
    row = conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (job_id,),
    ).fetchone()
    return _row(row)


def _triage_jobs_where(
    account_id: int | None,
    status: str | None,
    account_ids,
) -> tuple[str | None, list]:
    """Build the shared WHERE clause for the triage_jobs list + count.

    Returns ``(where_sql_or_None, params)``. ``where_sql`` is the
    ``"WHERE …"`` fragment (no LIMIT), or ``None`` to signal "the
    requested account_ids scope is EMPTY → the caller manages no
    accounts → return zero rows" so list/count short-circuit identically.

     — ``account_ids`` (a set/iterable of ids) pushes the per-user
    visibility scope INTO the query so a ``LIMIT`` applies AFTER the
    scope, not before it. The old call fetched the global newest-N then
    client-filtered to the user's accounts, so a user whose newest jobs
    were outnumbered by other users' jobs saw NONE of their own (silent-
    truncation audit, row ). One funnel for the predicate keeps the
    list query and the COUNT(*) denominator from drifting apart.
    """
    clauses: list[str] = []
    params: list = []
    if account_id is not None:
        clauses.append("account_id = ?")
        params.append(account_id)
    if account_ids is not None:
        ids = sorted({int(a) for a in account_ids})
        if not ids:
            # Empty scope: the user manages nothing. Signal short-circuit.
            return None, []
        placeholders = ",".join("?" * len(ids))
        clauses.append(f"account_id IN ({placeholders})")
        params.extend(ids)
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def list_triage_jobs(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    account_ids=None,
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Recent jobs, newest-first. Filter by account_id, a set of
    ``account_ids`` (per-user visibility scope), and/or status.

    When ``account_ids`` is an EMPTY set the result is ``[]`` (the user
    manages no accounts) — the cap never gets a chance to hide a user's
    own jobs behind other users' newer ones.

    ``offset`` pages the user's jobs so the full
    history past the page cap is reachable from the Bulk-runs page."""
    where, params = _triage_jobs_where(account_id, status, account_ids)
    if where is None:
        return []
    params.append(limit)
    params.append(int(offset))
    rows = conn.execute(
        f"SELECT * FROM triage_jobs {where} "
        f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return _rows(rows)


def count_triage_jobs(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    account_ids=None,
    status: str | None = None,
) -> int:
    """Total triage_jobs matching the SAME filters as
    :func:`list_triage_jobs` (minus the LIMIT) — the honest denominator
    for a "newest N of M" notice. Shares ``_triage_jobs_where`` so the
    count can't diverge from the list."""
    where, params = _triage_jobs_where(account_id, status, account_ids)
    if where is None:
        return 0
    row = conn.execute(
        f"SELECT COUNT(*) FROM triage_jobs {where}",
        params,
    ).fetchone()
    return int(row[0]) if row is not None else 0


def count_active_triage_jobs_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Number of queued/running jobs on this account.

    Used by the run handler to refuse a second submit while an
    earlier job is still draining (one bulk job per account at a
    time, per  design)."""
    row = conn.execute(
        "SELECT COUNT(*) AS cnt FROM triage_jobs "
        "WHERE account_id = ? AND status IN ('queued', 'running')",
        (account_id,),
    ).fetchone()
    return int(row["cnt"]) if row else 0


@db_write
def claim_next_queued_triage_job(
    conn: sqlite3.Connection,
) -> dict | None:
    """Atomically pick the oldest queued job, flip to running, return.

    Returns None when no queued job exists. The runner task calls
    this in a loop with a short sleep between empty results."""
    now = now_utc_iso()
    # SQLite single-writer guarantee makes this safe without an
    # explicit lock — the UPDATE returns 0 rows if another caller
    # claimed it first; we re-poll on the next loop iteration.
    cursor = conn.execute(
        "UPDATE triage_jobs "
        "SET status = 'running', started_at = ?, last_progress_at = ? "
        "WHERE job_id = ("
        "  SELECT job_id FROM triage_jobs "
        "  WHERE status = 'queued' "
        "  ORDER BY created_at ASC LIMIT 1"
        ") "
        "RETURNING *",
        (now, now),
    )
    row = cursor.fetchone()
    conn.commit()
    return _row(row)


@db_write
def bump_triage_job_counters(
    conn: sqlite3.Connection,
    job_id: str,
    *,
    seen: int = 0,
    processed: int = 0,
    skipped: int = 0,
    errors: int = 0,
    cache_skipped: int = 0,
) -> None:
    """Increment per-message counters + refresh ``last_progress_at``.

    Called by the runner after each message lands so the UI's
    progress poll sees fresh numbers. All args are deltas to
    add (default 0) — caller passes whichever bucket the message
    landed in. ``cache_skipped`` counts messages resolved
    from the back-scan study_match_cache (LLM skipped), surfaced on the
    job row so the progress UI can show resume-effectiveness."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE triage_jobs SET "
        "  total_seen = total_seen + ?, "
        "  total_processed = total_processed + ?, "
        "  total_skipped = total_skipped + ?, "
        "  total_errors = total_errors + ?, "
        "  total_cache_skipped = total_cache_skipped + ?, "
        "  last_progress_at = ? "
        "WHERE job_id = ?",
        (seen, processed, skipped, errors, cache_skipped, now, job_id),
    )
    conn.commit()


@db_write
def set_triage_job_ceiling_hit(conn: sqlite3.Connection, job_id: str) -> None:
    """ — flag a back-scan whose window enumeration hit
    ``BACKSCAN_SEARCH_CEILING`` (older mail past it was NOT scanned this run), so
    the progress status fragment can surface a user-facing "narrow the window /
    re-run" banner. Idempotent (sets the flag to 1). Called via ``db_call`` from
    the back-scan fetcher; commits internally like the counter bumps."""
    conn.execute(
        "UPDATE triage_jobs SET ceiling_hit = 1 WHERE job_id = ?", (job_id,)
    )
    conn.commit()


@db_write
def finish_triage_job(
    conn: sqlite3.Connection,
    job_id: str,
    *,
    status: str,
    error_text: str | None = None,
) -> None:
    """Move a running job to a terminal status (done/cancelled/failed).

    Refuses to set non-terminal statuses — the runner uses
    ``set_triage_job_status`` for cancellation requests that arrive
    mid-run (it just flips the column; the runner notices on the
    next batch boundary and exits via this function)."""
    if status not in ("done", "cancelled", "failed"):
        raise ValueError(f"Not a terminal status: {status!r}")
    now = now_utc_iso()
    conn.execute(
        "UPDATE triage_jobs SET status = ?, ended_at = ?, "
        "  error_text = ? "
        "WHERE job_id = ?",
        # census run13 #2 — scrub BOTH legs (PHI address/mailbox-path via
        # redact_exc + token secrets) at this actuator, so every
        # finish_triage_job caller is covered. Defence-in-depth: covers a
        # future caller who var-launders a raw f"{type(e).__name__}: {e}"
        # render into `error_text` without routing through the persist SSOT
        # `email_triage._errfmt.scrub_class_error_for_persist` (N-375).
        (status, now, _scrub_err_persist(error_text), job_id),
    )
    conn.commit()


@db_write
def request_triage_job_cancel(
    conn: sqlite3.Connection, job_id: str,
) -> bool:
    """UI cancel button. Flips queued/running -> cancelled.

    Runner observes the new status at its next batch boundary and
    exits via ``finish_triage_job(status='cancelled')`` (which is
    idempotent — second call is a no-op write of the same status).
    Returns True if the row was actually updated, False if the job
    was already terminal."""
    cursor = conn.execute(
        "UPDATE triage_jobs SET status = 'cancelled' "
        "WHERE job_id = ? AND status IN ('queued', 'running')",
        (job_id,),
    )
    conn.commit()
    return cursor.rowcount > 0


@db_write
def update_triage_job_cursor(
    conn: sqlite3.Connection,
    job_id: str,
    cursor: str | None,
) -> None:
    """Persist the resume cursor returned by provider.search_iter.

    Called by the bulk runner after each successfully-processed
    batch. The cursor is provider-specific (IMAP UID, Gmail
    pageToken, O365 nextLink URL) and opaque to the runner —
    only the provider's search_iter knows how to interpret it
    on resume. None overwrites the column with NULL (used at
    job start to clear stale state).

    Also bumps last_progress_at — same staleness signal the UI
    polls."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE triage_jobs SET cursor = ?, last_progress_at = ? "
        "WHERE job_id = ?",
        (cursor, now, job_id),
    )
    conn.commit()


def is_message_processed_in_job(
    conn: sqlite3.Connection, job_id: str, message_id: str,
) -> bool:
    """True if (job_id, message_id) is already recorded.

    Single-row PK lookup against triage_job_messages — used by
    the bulk runner to skip messages a prior crashed-and-resumed
    pass already handled. Composite PRIMARY KEY (job_id,
    message_id) makes this O(log n)."""
    row = conn.execute(
        "SELECT 1 FROM triage_job_messages "
        "WHERE job_id = ? AND message_id = ? LIMIT 1",
        (job_id, message_id),
    ).fetchone()
    return row is not None


@db_write
def record_processed_message(
    conn: sqlite3.Connection,
    job_id: str,
    message_id: str,
    status: str,
) -> None:
    """Stamp (job_id, message_id) with its terminal status.

    INSERT OR IGNORE — second call for the same (job_id,
    message_id) is a no-op. Status is one of:
      'p' processed (classified + acted)
      's' skipped (e.g. loop-prevention X-Email-Triage header)
      'e' error  (per-message exception)
    """
    now = now_utc_iso()
    conn.execute(
        "INSERT OR IGNORE INTO triage_job_messages "
        "(job_id, message_id, status, processed_at) "
        "VALUES (?, ?, ?, ?)",
        (job_id, message_id, status, now),
    )
    conn.commit()


def count_processed_messages_in_job(
    conn: sqlite3.Connection, job_id: str,
) -> dict:
    """Aggregate processed-message counts for a job.

    Used on resume to rebuild triage_jobs counters when a row
    is requeued: requeue zeros total_processed/skipped/errors,
    so the resumed run pre-bumps from this aggregate before
    walking new pages. Without that the UI would show a fresh
    start despite the dedup table guarding the work."""
    rows = conn.execute(
        "SELECT status, COUNT(*) AS cnt "
        "FROM triage_job_messages WHERE job_id = ? GROUP BY status",
        (job_id,),
    ).fetchall()
    out = {"p": 0, "s": 0, "e": 0}
    for r in rows:
        out[r["status"]] = int(r["cnt"])
    return out


@db_write
def requeue_orphaned_triage_jobs(
    conn: sqlite3.Connection,
) -> int:
    """App-startup recovery — flip ``running`` rows with no
    ``ended_at`` back to ``queued``.

    Process restart kills the runner task mid-drain. Affected rows
    are stuck in ``running`` forever. Resetting them to ``queued``
    lets the new runner pick them up; the ``flow_states`` dedupe
    via ``get_or_create_flow`` skips already-processed messages on
    the resume.

    Returns count of rows reset."""
    # N-240 R24: zero the counters at requeue time. The docstring at
    # `_load_processed_counts` (:2244) declared "requeue zeros
    # total_processed/skipped/errors so the resumed run pre-bumps from
    # the aggregate before walking new pages" — but this UPDATE only
    # touched status/timestamps, so counters LIVED across the requeue.
    # On resume the runner pre-bumped from the aggregate → old + new =
    # DOUBLE-COUNT. The docstring invariant demanded the reset here;
    # census R24 caught it (contradiction between the invariant and
    # this UPDATE).
    #
    # N-427 (census run22 D2): PD#18 sibling — `ceiling_hit` (migration
    # v44, INTEGER NOT NULL DEFAULT 0) is SET when window enumeration
    # returns len(pairs) >= BACKSCAN_SEARCH_CEILING (topic_backscan.py:
    # 351-352) but had no CLEAR path. On requeue, the cache-warmed resume
    # falls below the ceiling and no idempotent re-SET fires → the amber
    # "narrow the window / re-run" banner (templates/profile/
    # _topic_backscan_status.html:35) stays stuck on the completed row.
    # Textbook PD#18 violation. Cleared here alongside the counters.
    cursor = conn.execute(
        "UPDATE triage_jobs SET status = 'queued', "
        "  started_at = NULL, last_progress_at = NULL, "
        "  total_processed = 0, total_skipped = 0, total_errors = 0, "
        "  total_cache_skipped = 0, total_seen = 0, "
        "  ceiling_hit = 0 "
        "WHERE status = 'running' AND ended_at IS NULL"
    )
    conn.commit()
    return cursor.rowcount


@db_write
def prune_triage_runs(
    conn: sqlite3.Connection,
    retention_days: int = 90,
) -> int:
    """Delete ``triage_runs`` rows older than ``retention_days``.

    ``triage_runs`` records one row per completed inline triage run and
    grew unbounded — nothing trimmed it. This mirrors
    :func:`prune_triaged_messages`: an age-based DELETE on the indexed
    ``created_at`` column, idempotent, run on the same cadence as the
    log-entries prune loop. Returns the number of rows removed.
    """
    from datetime import datetime, timedelta, timezone
    cutoff = to_utc_iso(datetime.now(timezone.utc)
              - timedelta(days=int(retention_days)))
    try:
        cur = conn.execute(
            "DELETE FROM triage_runs WHERE created_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount or 0
    except Exception:
        # Best-effort prune — a swallowed exception here is invisible to
        # the ``@db_write`` decorator's rollback path. If the DELETE
        # opened an implicit transaction and ``commit()`` failed, roll
        # it back so the next explicit-``BEGIN`` helper does not raise
        # "cannot start a transaction within a transaction".
        try:
            if conn.in_transaction:
                conn.rollback()
        except Exception:
            pass
        return 0


# ---------------------------------------------------------------------------
# User escalation preferences
# ---------------------------------------------------------------------------

def get_user_escalation_categories(conn: sqlite3.Connection, user_id: int) -> set[str]:
    """Return the set of category slugs a user has escalation enabled for."""
    rows = conn.execute(
        "SELECT category FROM user_escalation_prefs WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return {r["category"] for r in rows}


@db_write
def set_user_escalation_categories(
    conn: sqlite3.Connection,
    user_id: int,
    categories: list[str],
) -> None:
    """Replace all escalation categories for a user.

    Live schema (post-migration) has ``updated_at`` as NOT NULL with no
    default; INSERT must supply both timestamps. The CREATE TABLE in
    this file lags the migration -- we set both regardless.
    """
    now = now_utc_iso()
    conn.execute("DELETE FROM user_escalation_prefs WHERE user_id = ?", (user_id,))
    for cat in categories:
        conn.execute(
            "INSERT INTO user_escalation_prefs "
            "(user_id, category, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, cat, now, now),
        )
    conn.commit()


def should_escalate(
    conn: sqlite3.Connection,
    user_id: int,
    category: str,
) -> str | None:
    """Check if a user wants escalation for this category.

    Returns the user's ``notify_email`` if escalation is configured for
    this category and a notify address is set, or ``None`` otherwise.
    """
    row = conn.execute(
        "SELECT u.notify_email "
        "FROM user_escalation_prefs ep "
        "JOIN users u ON u.id = ep.user_id "
        "WHERE ep.user_id = ? AND ep.category = ?",
        (user_id, category),
    ).fetchone()
    if row is None:
        return None
    if not row["notify_email"]:
        return None
    return row["notify_email"]


# ---------------------------------------------------------------------------
# User disable / enable (fail-closed kill switch)
# ---------------------------------------------------------------------------

def is_user_disabled(conn: sqlite3.Connection, user_id: int) -> bool:
    """Return True if the user is currently disabled.

    Source-of-truth read. No caching — callers in auth paths invoke
    this on every request so a newly-flipped disable takes effect
    immediately.

    For per-account loops that need the same answer for every owner,
    prefer :func:`disabled_user_ids` (one query, set-membership lookup)
    over calling this function in a tight loop.
    """
    row = conn.execute(
        "SELECT disabled FROM users WHERE id = ?", (user_id,),
    ).fetchone()
    if row is None:
        # Missing user is treated as disabled (fail-closed).
        return True
    return bool(row["disabled"])


def disabled_user_ids(conn: sqlite3.Connection) -> set[int]:
    """Return the set of currently-disabled user ids.

    .4 — single query, replaces ``is_user_disabled(db, owner_id)``
    inside per-account loops in app.py (watcher restore, digest sender,
    unified poll). Callers build this set once per loop iteration and
    do O(1) ``owner_id in disabled`` membership checks.

    Note: a user_id that does not exist in ``users`` is NOT in this
    set. Callers wanting fail-closed treatment for missing users
    should compare against the full known-user set, or fall back to
    :func:`is_user_disabled` for that one row.
    """
    rows = conn.execute(
        "SELECT id FROM users WHERE disabled = 1"
    ).fetchall()
    return {int(r["id"]) for r in rows}


# ---------------------------------------------------------------------------
# Loop-prevention dedup (cross-folder, cross-provider)
# ---------------------------------------------------------------------------

def _hash_msg_id(account_id: int, rfc_message_id: str) -> str:
    """SHA-256 of ``account_id || rfc_message_id`` — used as the dedup
    key so the raw RFC-5322 Message-Id never sits in the DB."""
    import hashlib
    return hashlib.sha256(
        f"{int(account_id)}:{rfc_message_id}".encode("utf-8")
    ).hexdigest()


@db_write
def mark_triaged(
    conn: sqlite3.Connection,
    account_id: int,
    rfc_message_id: str,
) -> None:
    """Record that a message has been triaged. Idempotent (UNIQUE
    constraint short-circuits double-inserts)."""
    if not rfc_message_id:
        return
    now = now_utc_iso()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO triaged_messages "
            "(account_id, msg_id_hash, ts) VALUES (?, ?, ?)",
            (account_id, _hash_msg_id(account_id, rfc_message_id), now),
        )
        conn.commit()
    except Exception:
        # Loop-prevention is best-effort; a DB error here must not
        # break the triage pipeline. But the swallowed exception means
        # the ``@db_write`` decorator's rollback path never sees it —
        # if the INSERT opened an implicit transaction and the
        # ``commit()`` failed, ``conn.in_transaction`` stays True and
        # the next explicit-``BEGIN`` helper raises "cannot start a
        # transaction within a transaction". Roll back here so
        # the next lock holder starts clean.
        try:
            if conn.in_transaction:
                conn.rollback()
        except Exception:
            pass


def is_triaged(
    conn: sqlite3.Connection,
    account_id: int,
    rfc_message_id: str,
) -> bool:
    """True if a message with this (account, rfc_message_id) has
    already been triaged. Used as a pre-classifier loop guard."""
    if not rfc_message_id:
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM triaged_messages "
            "WHERE account_id = ? AND msg_id_hash = ?",
            (account_id, _hash_msg_id(account_id, rfc_message_id)),
        ).fetchone()
    except Exception:
        return False
    return row is not None


@db_write
def prune_triaged_messages(
    conn: sqlite3.Connection,
    retention_days: int = 90,
) -> int:
    """Delete dedup rows older than ``retention_days``. Returns the
    number of rows removed. Idempotent; runs on the same cadence as
    the log-entries prune loop."""
    from datetime import datetime, timedelta, timezone
    cutoff = to_utc_iso(datetime.now(timezone.utc)
              - timedelta(days=int(retention_days)))
    try:
        cur = conn.execute(
            "DELETE FROM triaged_messages WHERE ts < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount or 0
    except Exception:
        # Best-effort prune — see prune_triage_runs. Roll back any
        # transaction the failed commit left open so the next
        # explicit-``BEGIN`` helper starts clean.
        try:
            if conn.in_transaction:
                conn.rollback()
        except Exception:
            pass
        return 0


# ---------------------------------------------------------------------------
# Gmail Pub/Sub watch state
# ---------------------------------------------------------------------------

@db_write
def upsert_gmail_watch(
    conn: sqlite3.Connection,
    account_id: int,
    email_address: str,
    topic_name: str,
    history_id: str,
    expires_at: str,
) -> None:
    """Insert or update the Gmail-watch row for ``account_id``.

    ``email_address`` is normalized to ``strip().lower()`` on write so
    case + whitespace mismatches between operator-typed config and
    Pub/Sub-delivered values don't cause the webhook lookup to miss
    (every operational mail provider treats local-part as
    case-insensitive — see RFC 5321 + Gmail-API contract).
    """
    # N-346c OPEN — v0.2.0 scope, awaiting a proper drive. Corrected
    # 2026-07-06 from a false "v0.3.0 SCOPE-PARK" attribution per
    # operator directive — v0.3.0 is enterprise-scaling scope only
    # (see internal documentation), NOT a catch-all for
    # AI-parked semantics work. Default action + operator override
    # handle filed in WAITING-ON-OP.md. Current v0.2.0 posture: no
    # behavior change (current hash shape stays).
    # The `gmail_watches.email_address` column persists this normalized
    # value + the sibling `needle` read path at :2618 must produce the
    # same shape for lookup. Migrating to `canonical_email(email_address)`
    # would break existing-row lookups by adding IDNA + local-part
    # quoting-strip semantics that current persisted rows don't carry.
    # Safe migration requires a backfill or dual-shape lookup.
    normalized_email = (email_address or "").strip().lower()
    now = now_utc_iso()
    # N-347 R31 (2026-07-04, Census DISCOVERED HIGH): reset lifecycle
    # triple (status/error_count/error_last) inline on the ON CONFLICT
    # branch — mirrors the O365 sibling upsert. Pre-N-347, 4 of 5
    # `upsert_gmail_watch` callers omitted a follow-up
    # `record_gmail_watch_outcome(None)` clear, so a re-registered
    # watch inherited the stale `errored` chip — the OAuth-recovery
    # path (the code path a user hits SPECIFICALLY to recover from
    # the errored state) left the chip stuck. Clearing the triple in
    # the UPSERT SSOT itself prevents any caller from skipping the
    # clear. Fresh INSERT branch already gets DEFAULT 'active' + 0 +
    # NULL via the v50 column definitions; no INSERT column list
    # change required.
    conn.execute(
        "INSERT INTO gmail_watches "
        "(account_id, email_address, topic_name, history_id, expires_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  email_address = excluded.email_address, "
        "  topic_name    = excluded.topic_name, "
        "  history_id    = excluded.history_id, "
        "  expires_at    = excluded.expires_at, "
        "  updated_at    = excluded.updated_at, "
        "  status        = 'active', "
        "  error_count   = 0, "
        "  error_last    = NULL",
        (account_id, normalized_email, topic_name, history_id, expires_at, now, now),
    )
    conn.commit()


@db_write
def update_gmail_watch_history(
    conn: sqlite3.Connection, account_id: int, history_id: str,
) -> None:
    """Advance the stored history cursor; leaves ``expires_at`` alone."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE gmail_watches SET history_id = ?, updated_at = ? WHERE account_id = ?",
        (history_id, now, account_id),
    )
    conn.commit()


def get_gmail_watch(conn: sqlite3.Connection, account_id: int) -> dict | None:
    row = conn.execute(
        "SELECT * FROM gmail_watches WHERE account_id = ?", (account_id,),
    ).fetchone()
    return _row(row)


def get_gmail_watch_by_email(conn: sqlite3.Connection, email_address: str) -> dict | None:
    """Look up a Gmail watch row by email, case-insensitively.

    Pub/Sub delivers the address in lowercase per the Gmail API
    contract; the operator may have typed it in mixed case at
    account-creation time. Match LOWER(stored) against
    LOWER(supplied) so the webhook always finds the row.

    N-346c (2026-07-08) dual-lookup shim: try BOTH normalization shapes —
    ``strip().lower()`` (the currently-persisted shape) and
    ``canonical_email()`` (adds IDNA A-label encoding for the domain).
    For an ASCII-domain install both shapes collide + one probe hits.
    For an IDN-domain install (München / xn--mnchen-3ya) the canonical
    probe closes the A-label/U-label envelope collision class without
    a persisted-row backfill window. Both probes stay case-insensitive
    at the SQL level via ``LOWER(email_address)``.
    """
    if not email_address:
        return None
    # First shape: the current persisted-write shape (strip().lower()).
    legacy = email_address.strip().lower()
    from email_triage.mail_headers import canonical_email
    canonical = canonical_email(email_address)
    # SQL keeps `LOWER(email_address) = ?` for legacy row compat —
    # `test_webhooks.py::test_email_address_case_insensitive` locks in
    # the contract that pre-normalization mixed-case rows (that pre-date
    # the upsert-time normalization) MUST still be findable case-
    # insensitively; this is a documented #post-#92 production
    # regression the test guards. The functional index migration OR
    # backfill-and-drop-LOWER refactor is a follow-up not gated on
    # N-346c; on the single-digit-cardinality reference install the
    # table scan is nil-cost. Dedup on `(canonical, legacy)` handles
    # the ASCII-collision case where both shapes are the same string.
    seen: set[str] = set()
    for needle in (canonical, legacy):
        if not needle or needle in seen:
            continue
        seen.add(needle)
        row = conn.execute(
            "SELECT * FROM gmail_watches WHERE LOWER(email_address) = ?",
            (needle,),
        ).fetchone()
        if row is not None:
            return _row(row)
    return None


@db_write
def delete_gmail_watch(conn: sqlite3.Connection, account_id: int) -> None:
    conn.execute("DELETE FROM gmail_watches WHERE account_id = ?", (account_id,))
    conn.commit()


def list_gmail_watches_expiring(
    conn: sqlite3.Connection, before_iso: str,
) -> list[dict]:
    """Watches with ``expires_at <= before_iso`` that are real Pub/Sub
    subscriptions (``topic_name != ''``), oldest first.

    Synthetic poll-mode rows created by B3 carry ``topic_name=''`` and
    an epoch sentinel ``expires_at`` — they must not be returned here
    or the renewer sweep would log a spurious warning every tick.
    Real push rows with an empty topic_name still indicate genuine
    config drift and should surface elsewhere.
    """
    rows = conn.execute(
        "SELECT * FROM gmail_watches "
        "WHERE expires_at <= ? AND topic_name != '' "
        "ORDER BY expires_at ASC",
        (before_iso,),
    ).fetchall()
    return _rows(rows)


def list_gmail_watches(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM gmail_watches ORDER BY email_address ASC"
    ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# Office 365 / Microsoft Graph webhook subscriptions
#
# One row per account holding the active Graph subscription state.
# Sister table to ``gmail_watches`` for the parallel push pipeline.
# Created by migration v6 (``create_office365_subscriptions``).
# ---------------------------------------------------------------------------

@db_write
def upsert_o365_subscription(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    subscription_id: str,
    expiration_at: str,
) -> None:
    """Insert or replace the O365 subscription row for ``account_id``.

    Resets ``status='active'`` + ``error_count=0`` + ``error_last=NULL``
    on every successful create/renew so the row tracks the most-recent
    healthy state. ``last_renewed_at`` is bumped to now; the renewer
    uses it as an audit cursor.
    """
    now = now_utc_iso()
    conn.execute(
        "INSERT INTO office365_subscriptions "
        "(account_id, subscription_id, expiration_at, last_renewed_at, "
        " last_notification_at, status, error_count, error_last, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, NULL, 'active', 0, NULL, ?, ?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  subscription_id = excluded.subscription_id, "
        "  expiration_at   = excluded.expiration_at, "
        "  last_renewed_at = excluded.last_renewed_at, "
        "  status          = 'active', "
        "  error_count     = 0, "
        "  error_last      = NULL, "
        "  updated_at      = excluded.updated_at",
        (account_id, subscription_id, expiration_at, now, now, now),
    )
    conn.commit()


def get_o365_subscription(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    row = conn.execute(
        "SELECT * FROM office365_subscriptions WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    return _row(row)


def get_o365_subscription_by_subscription_id(
    conn: sqlite3.Connection, subscription_id: str,
) -> dict | None:
    """Demux a Graph webhook delivery to the owning account row."""
    if not subscription_id:
        return None
    row = conn.execute(
        "SELECT * FROM office365_subscriptions WHERE subscription_id = ?",
        (subscription_id,),
    ).fetchone()
    return _row(row)


@db_write
def delete_o365_subscription(
    conn: sqlite3.Connection, account_id: int,
) -> None:
    conn.execute(
        "DELETE FROM office365_subscriptions WHERE account_id = ?",
        (account_id,),
    )
    conn.commit()


def list_o365_subscriptions(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM office365_subscriptions ORDER BY account_id ASC"
    ).fetchall()
    return _rows(rows)


def list_o365_subscriptions_expiring(
    conn: sqlite3.Connection, before_iso: str,
) -> list[dict]:
    """Subscriptions with ``expiration_at <= before_iso``, oldest first.

    Used by the renewer sweep to find rows about to expire.
    """
    rows = conn.execute(
        "SELECT * FROM office365_subscriptions "
        "WHERE expiration_at <= ? "
        "ORDER BY expiration_at ASC",
        (before_iso,),
    ).fetchall()
    return _rows(rows)


@db_write
def record_push_delivery(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    provider: str,
) -> None:
    """Bump today's per-account push-delivery counter.

    Called from the Gmail Pub/Sub + O365 Graph webhook handlers
    immediately after a successful ``queue.put_nowait``. The
    in-memory ``app.state.metrics`` counter remains for live-debug
    introspection; this writes a persisted row so /admin/stats
    can render a rolling-window rollup.

    ``provider`` is a free-text discriminator matching the values
    the webhook handlers use:
      * ``'gmail'``     — Gmail Pub/Sub push (POST /webhooks/gmail)
      * ``'office365'`` — Microsoft Graph webhook (POST /webhooks/office365)

    Day key = UTC date in ISO ``YYYY-MM-DD`` shape so a count
    accumulated across a day boundary lands in the right slot
    regardless of the operator's local timezone.

    Never raises. Counter writes are best-effort; a counter
    failure must NOT block the push delivery (Pub/Sub / Graph
    would retry on a 5xx, and a webhook handler that fails
    *after* it queued the work creates spurious duplicate
    deliveries). Caller wraps in try/except for the same reason.

    UPSERT collides on the composite primary key
    ``(account_id, provider, day)`` so a busy push day collapses
    to one row that increments in place — no row-per-delivery
    growth.
    """
    if account_id is None or not provider:
        return
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn.execute(
        "INSERT INTO push_deliveries (account_id, provider, day, count) "
        "VALUES (?, ?, ?, 1) "
        "ON CONFLICT (account_id, provider, day) "
        "DO UPDATE SET count = count + 1",
        (int(account_id), provider, today),
    )
    conn.commit()


def get_push_deliveries_window(
    conn: sqlite3.Connection,
    *,
    days: int = 14,
) -> list[dict]:
    """Return per-(account, provider, day) push-delivery counts.

    Rolling window. ``days=14`` returns the last 14 UTC days
    inclusive of today. Empty list if the table is empty or the
    window has no rows — the caller renders "no deliveries yet"
    rather than treating an empty result as an error.

    Rows shape (one per non-zero slot):
      ``{"account_id": int, "account_name": str, "provider": str,
         "day": "YYYY-MM-DD", "count": int}``

    ``account_name`` is joined from ``email_accounts`` so the
    operator-facing surface can render "Truma <#5>" rather than
    a bare numeric ID per the ``feedback_no_account_id_alone``
    rule. NULL name (account deleted while history retained)
    falls back to empty string; consumer renders ``Account
    #<id>`` for that case.

    Sort key: ``day DESC, account_name ASC, provider ASC`` so
    the most-recent day surfaces first + per-day rows group by
    account.
    """
    if days < 1:
        days = 1
    from datetime import datetime, timedelta, timezone
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=days - 1)
    ).strftime("%Y-%m-%d")
    cur = conn.execute(
        "SELECT pd.account_id, "
        "       COALESCE(ea.name, '') AS account_name, "
        "       pd.provider, pd.day, pd.count "
        "FROM push_deliveries pd "
        "LEFT JOIN email_accounts ea ON ea.id = pd.account_id "
        "WHERE pd.day >= ? "
        "ORDER BY pd.day DESC, account_name ASC, pd.provider ASC",
        (cutoff,),
    )
    return [
        {
            "account_id": row[0],
            "account_name": row[1] or "",
            "provider": row[2],
            "day": row[3],
            "count": row[4],
        }
        for row in cur.fetchall()
    ]


@db_write
def prune_push_deliveries(
    conn: sqlite3.Connection,
    *,
    keep_days: int = 90,
) -> int:
    """Drop rows older than ``keep_days`` from ``push_deliveries``.

    Called from the daily-health tick (sibling to the log-entries
    prune). Returns the number of rows deleted so the caller can
    log the trim. 90-day default mirrors the existing log-retention
    posture; operator can shorten via a future setting if the table
    bloats on a high-volume install.

    Never raises: callers (cron-ish) should not crash if the table
    is missing on a pre-v24 DB read.
    """
    if keep_days < 1:
        keep_days = 1
    from datetime import datetime, timedelta, timezone
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=keep_days)
    ).strftime("%Y-%m-%d")
    try:
        cur = conn.execute(
            "DELETE FROM push_deliveries WHERE day < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount or 0
    except Exception:
        # Best-effort prune — see prune_triage_runs. Roll back any
        # transaction the failed commit left open so the next
        # explicit-``BEGIN`` helper starts clean.
        try:
            if conn.in_transaction:
                conn.rollback()
        except Exception:
            pass
        return 0


@db_write
def record_o365_notification(
    conn: sqlite3.Connection, subscription_id: str,
) -> None:
    """Stamp ``last_notification_at`` on a webhook delivery.

    No-op when the subscription_id isn't in our table — the webhook
    receiver will have already 200'd to stop Graph retries; this just
    forwards the heartbeat.
    """
    now = now_utc_iso()
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET last_notification_at = ?, updated_at = ? "
        "WHERE subscription_id = ?",
        (now, now, subscription_id),
    )
    conn.commit()


@db_write
def update_o365_subscription_delta_link(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    delta_link: str,
) -> None:
    """Persist Graph's ``@odata.deltaLink`` cursor on the row.

    Called by the push consumer after every successful delta walk —
    same role as ``update_gmail_watch_history`` for the Gmail path.
    A NULL cursor means "no walk has completed yet"; the consumer
    treats that as a signal to start the delta feed from scratch.
    """
    now = now_utc_iso()
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET delta_link = ?, updated_at = ? "
        "WHERE account_id = ?",
        (delta_link, now, account_id),
    )
    conn.commit()


@db_write
def record_o365_subscription_renewal(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    subscription_id: str,
    new_expiration_at: str,
) -> None:
    """Record a successful subscription renewal.

    Like ``upsert_o365_subscription`` but doesn't reset
    ``last_notification_at`` — preserves the heartbeat across renews.
    Resets error bookkeeping (``status='active'``, ``error_count=0``)
    so a row that was flapping but recovered shows clean.
    """
    now = now_utc_iso()
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET subscription_id = ?, "
        "    expiration_at   = ?, "
        "    last_renewed_at = ?, "
        "    status          = 'active', "
        "    error_count     = 0, "
        "    error_last      = NULL, "
        "    updated_at      = ? "
        "WHERE account_id = ?",
        (subscription_id, new_expiration_at, now, now, account_id),
    )
    conn.commit()


@db_write
def record_o365_subscription_error(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    error_text: str,
) -> None:
    """Record a renewer / create failure on the row.

    Bumps ``error_count``, stamps ``error_last`` (truncated to 500
    chars), flips ``status`` to ``'errored'``. Surfaced by /health
    + the daily digest so transient Graph errors don't go silent.
    """
    now = now_utc_iso()
    # census #6 — scrub token-shaped secrets (Graph error responses can
    # carry an access_token / client_secret) before persisting + truncate.
    truncated = _scrub_secrets(error_text) or ""
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET error_count = error_count + 1, "
        "    error_last = ?, "
        "    status = 'errored', "
        "    updated_at = ? "
        "WHERE account_id = ?",
        (truncated, now, account_id),
    )
    conn.commit()


@db_write
def record_o365_subscription_outcome(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    error_text: str | None,
) -> None:
    """N-69 — single funnel for the ``office365_subscriptions.status`` lifecycle.

    The status flag is a *lifecycle* flag (PD#18): SET to ``'errored'`` on any
    failure, CLEARED to ``'active'`` on any live success.  Before N-69 it was
    SET via ``record_o365_subscription_error`` (error-bumping path) but CLEARED
    only via ``record_o365_subscription_renewal`` — NOT on notification receipt
    or delta-walk success, so a healthy subscription that had previously errored
    stayed stuck as ``'errored'`` on /health until the next renewal window.

    Route ALL writers of ``office365_subscriptions.status`` through this funnel:

    * ``error_text is None``   → success path; clear to ``'active'`` + reset
      ``error_count``/``error_last`` (idempotent: a row already active is a
      no-op on status/error_count thanks to the WHERE guard).
    * ``error_text is not None`` → failure path; delegates to
      ``record_o365_subscription_error`` for the bump-and-scrub logic already
      there (DRY, single secret-scrub SSOT).

    The existing ``record_o365_subscription_renewal`` writes additional fields
    (``subscription_id``, ``expiration_at``, ``last_renewed_at``) and should
    CONTINUE to be called for a full renewal; it must also call this funnel
    (or be replaced by it) so the status stays in sync.
    ``upsert_o365_subscription`` resets status on CREATE — that path is
    already correct (creates as 'active') and is exempt because it rewrites
    the whole row.

    The pin ``tests/test_n69_o365_subscription_lifecycle_pin.py`` enforces
    count-agnostic coverage: every writer of ``office365_subscriptions.status``
    outside this funnel is a violation.
    """
    now = now_utc_iso()
    if error_text is None:
        # Success path — clear to active, reset error bookkeeping.
        # Idempotent: if the row is already active and error_count=0 this
        # is a cheap UPDATE that changes nothing.
        conn.execute(
            "UPDATE office365_subscriptions "
            "SET status = 'active', "
            "    error_count = 0, "
            "    error_last = NULL, "
            "    updated_at = ? "
            "WHERE account_id = ?",
            (now, account_id),
        )
    else:
        # N-352 R31 (2026-07-04 Census DISCOVERED MED): the failure
        # branch previously duplicated `record_o365_subscription_error`'s
        # UPDATE inline — the SSOT funnel unrolled inside itself, a
        # drift-twin INSIDE the pin's own funnel. Two scrub-fn variants
        # + two `status='errored'` UPDATE strings evolved side-by-side.
        # Restore the docstring-promised delegation so bump-and-scrub
        # semantics stay in ONE place.
        record_o365_subscription_error(
            conn, account_id=account_id, error_text=error_text,
        )
        return
    conn.commit()


@db_write
def record_gmail_watch_outcome(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    error_text: str | None,
) -> None:
    """N-256 R25 — SINGLE funnel for the ``gmail_watches.status``
    lifecycle. Sibling to :func:`record_o365_subscription_outcome`.

    The status flag is a *lifecycle* flag (PD#18): SET to ``'errored'``
    on any watch renewal / notification failure, CLEARED to ``'active'``
    on any live success. Route ALL writers of ``gmail_watches.status``
    through this funnel:

    * ``error_text is None``   → success path; clear to ``'active'`` +
      reset ``error_count``/``error_last`` (idempotent).
    * ``error_text is not None`` → failure path; bump ``error_count``
      + set ``error_last`` (scrubbed) + status → ``'errored'``.

    The pin ``tests/test_n256_gmail_watch_lifecycle_pin.py`` enforces
    count-agnostic coverage: every writer of ``gmail_watches.status``
    outside this funnel is a violation.

    No-op on ``UPDATE`` when the row doesn't exist yet — a fresh
    account with no gmail_watches row simply does nothing (matches
    O365 sibling behaviour). Callers do NOT need to guard on
    row-existence.
    """
    now = now_utc_iso()
    if error_text is None:
        conn.execute(
            "UPDATE gmail_watches "
            "SET status = 'active', "
            "    error_count = 0, "
            "    error_last = NULL, "
            "    updated_at = ? "
            "WHERE account_id = ?",
            (now, account_id),
        )
    else:
        truncated = _scrub_err_persist(error_text) or ""
        conn.execute(
            "UPDATE gmail_watches "
            "SET error_count = error_count + 1, "
            "    error_last = ?, "
            "    status = 'errored', "
            "    updated_at = ? "
            "WHERE account_id = ?",
            (truncated, now, account_id),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# User meeting preferences (settings-backed; no schema migration)
# ---------------------------------------------------------------------------

def get_meeting_prefs(conn: sqlite3.Connection, user_id: int | None) -> dict:
    """Return the user's meeting preferences dict, or empty if none set.

    The intercept action and the outbound-webhook API hand the dict to
    ``MeetingPreferences.from_dict`` which fills defaults.
    """
    if not user_id:
        return {}
    from email_triage.web import settings_keys as S
    return get_setting(conn, S.meeting_prefs(user_id)) or {}


def set_meeting_prefs(
    conn: sqlite3.Connection, user_id: int, prefs: dict,
) -> None:
    """Persist the user's meeting preferences. Caller validates."""
    from email_triage.web import settings_keys as S
    set_setting(conn, S.meeting_prefs(user_id), prefs)


def is_calendar_enabled(conn: sqlite3.Connection, account_id: int) -> bool:
    """Return True if the per-account calendar flag is set.

    The flag is stored as ``{"enabled": bool}`` in the settings table;
    reading the raw row directly is not safe (an empty dict from a
    prior disable would be truthy). All call sites should use this
    helper.
    """
    from email_triage.web import settings_keys as S
    return get_bool_setting(conn, S.calendar_enabled(account_id), default=False)


# ---------------------------------------------------------------------------
# Per-account derived style profile (M-3)
#
# Stored under ``style_profile:<account_id>`` in the settings k-v table.
# The full M-3 spec (in docs/major-features/style-learning.md) calls for a
# dedicated ``style_profiles`` table with Fernet-encrypted body once the
# feature ships end-to-end. For the distillation foundation we piggyback
# on the existing settings store — the profile is structured metadata
# (~1-2KB), not message bodies, so plaintext-at-rest is acceptable for
# the first iteration and a future migration into a dedicated table can
# read this same key.
# ---------------------------------------------------------------------------









# ---------------------------------------------------------------------------
# Alias-aware learning (punch list )
#
# When an operator has multiple addresses on one account (primary +
# aliases) they can opt into a per-alias descriptor partition. The
# alias-mode toggle is a column on ``email_accounts``; the descriptors
# live in ``account_style_per_alias``. Single-descriptor accounts and
# accounts with alias-mode OFF behave exactly as pre-v23.
#
# The ``from_address`` storage value is the normalised bare address
# (see :func:`normalise_from_address`). Display-name, ``+suffix`` tags,
# angle brackets, and case are stripped before storage so two captures
# of ``"Display Name" <Sam+work@Example.Tld>`` and ``sam@example.tld``
# read as the same alias bucket.
# ---------------------------------------------------------------------------















# ---------------------------------------------------------------------------
# Per-user style knobs (M-1 + M-2)
#
# Five columns on ``users`` (added by migration v11) capture the user's
# explicit writing-style preferences. M-1 is the free-text guide; M-2 is
# the structured radio + text knobs. These are USER-STATED and complement
# M-3's SYSTEM-INFERRED derived profile.
# ---------------------------------------------------------------------------

# Allowlists used by both the form-save validator and any direct caller.
STYLE_TONE_CHOICES = ("formal", "neutral", "casual", "terse")
STYLE_LENGTH_CHOICES = ("brief", "medium", "full")
STYLE_GREETING_CHOICES = ("none", "first-name", "formal-name", "custom")











# ---------------------------------------------------------------------------
# Style-learning admin cadence + mine-limit defaults
#
# Two install-wide knobs admin sets on /config Style learning section:
#
#   * ``style_learning:capture_interval_hours`` — how often the
#     :func:`_sent_mail_capture_loop` ticks. Already read by
#     ``_resolve_capture_interval_hours`` in web/app.py; the setters
#     below give /config a write path. Range 1–72 hours, default 6.
#
#   * ``style_learning:mine_limit_default`` — the default number of
#     messages the inline preview / mine-now path scans on a single
#     button press. Per-account override on /profile/style-data wins
#     when present (``config_json["mine_limit_override"]``). Range
#     1–500, default 50. Operator picks higher values when they want
#     a richer distill corpus but accepts that > 50 routes through
#     the bulk worker (HTMX timeout protection).
#
# Both stored in the ``settings`` table — operator-tunable without
# restart and without needing to touch the YAML config (style learning
# was DB-resident from day one; the YAML config covers the install's
# durable-infra surface like SMTP host + classifier backend).
# ---------------------------------------------------------------------------



# Threshold above which the inline mine-now / preview path is too slow
# for an HTMX request and the operator gets handed off to the bulk
# worker. 50 is the historical inline cap; values > 50 trigger the
# style_mine bulk-job kind. Operator sees a "watching the bulk runs
# page" message + a link to that page when the resolved limit crosses
# this line. Tunable here so an install with faster LLM hardware can
# raise it without code changes (constants only; not operator-exposed
# on /config yet).
STYLE_LEARNING_INLINE_LIMIT_CEILING = 50












# ---------------------------------------------------------------------------
# Per-account "auto-scan on schedule" toggle
#
# Lives in ``email_accounts.config_json["auto_scan_enabled"]`` as a
# bool. Default: ON for non-HIPAA, OFF for HIPAA-flagged accounts —
# HIPAA defaults to opt-in everywhere (the helper reads HIPAA off the
# account dict so the value is right even when the explicit key is
# absent on an un-touched account).
#
# When OFF, the :func:`_sent_mail_capture_loop` skips this account.
# Only the operator-driven "Mine the Sent Items Now" button still
# fires. HIPAA-without-opt-in is independent of this knob — those
# accounts are gated by ``is_style_knobs_hipaa_allow`` and refuse
# even the on-demand path until the operator opts in.
# ---------------------------------------------------------------------------


def is_auto_scan_enabled_for_account(account: dict | None) -> bool:
    """Resolve the per-account auto-scan toggle with HIPAA-aware default.

    Non-HIPAA accounts default ON; HIPAA-flagged accounts default
    OFF. The explicit key on ``config_json["auto_scan_enabled"]``
    overrides the default in either direction.

    N-81: the HIPAA default uses is_account_hipaa (folds the system flag)
    so a system-HIPAA install with acct["hipaa"]=0 still defaults OFF."""
    if account is None or not isinstance(account, dict):
        return False
    cfg = account.get("config")
    if isinstance(cfg, dict):
        raw = cfg.get("auto_scan_enabled")
        if raw is not None:
            return bool(raw)
    from email_triage.triage_logging import is_account_hipaa
    return not is_account_hipaa(account)


def set_auto_scan_enabled_for_account(
    conn: sqlite3.Connection, account_id: int, enabled: bool,
) -> None:
    """Persist the per-account auto-scan toggle.

    Stored explicitly (vs falling through to the HIPAA-aware default)
    so the operator's choice is durable across a HIPAA flag flip.
    """
    update_account_config_keys(
        conn, account_id, auto_scan_enabled=bool(enabled),
    )




# ---------------------------------------------------------------------------
# Per-account RAG-over-sent-mail toggle (M-4 scaffold)
#
# A boolean stored under ``rag_sent_index_enabled:<account_id>``. Default
# is OFF; the operator opts in per account via the Integrations tab.
# HIPAA-flagged accounts render the toggle disabled and the helper at
# ``actions/sent_mail_index.py`` short-circuits regardless of this
# value -- the toggle is the operator UX surface, the HIPAA gate is
# the privacy guarantee.
# ---------------------------------------------------------------------------







# ---------------------------------------------------------------------------
# Per-account M-1+M-2 HIPAA-allow opt-in
#
# A boolean stored under ``style_knobs_hipaa_allow:<account_id>``. Default
# is OFF; the operator opts in per HIPAA-flagged account via the
# account-edit Integrations tab. The flag is meaningful ONLY when the
# account is HIPAA-flagged; non-HIPAA accounts ignore it (their
# M-1+M-2 path is already unrestricted).
#
# Rationale: M-1 (free-text style guide) and M-2 (tone / length /
# greeting / signature radios) take operator-typed strings as input.
# Per §164.502(a) self-disclosure carve-out, operator's own knobs are
# first-party — not PHI by construction. M-3 / M-4 / M-7 read the
# operator's sent mail and stay hard-off regardless of this flag.
#
# See ``docs/hipaa-audit.md`` for the per-layer audit and
# ``internal documentation`` for the sign-off log entry.
# ---------------------------------------------------------------------------







# ---------------------------------------------------------------------------
# HIPAA-safe M-3 describe-and-discard descriptor
#
# Storage lives in the dedicated ``hipaa_style_descriptors`` table (v25)
# rather than under a settings row — see the migration docstring for the
# rationale. Helpers below are the only public read/write surface.
#
# Install-wide gate: ``style_learning:hipaa_distill_enabled`` (default
# OFF). Operator flips it on /config after the LLM-backend posture
# sign-off. Per-account gate still applies: even with the install-wide
# flag on, the distill action checks both ``is_account_hipaa(acct)`` and
# ``is_style_knobs_hipaa_allow(conn, account_id)`` before touching mail.
# ---------------------------------------------------------------------------


#: Re-distill cadence: rebuild the HIPAA descriptor at most this often.
#: Operator-tunable later via /config; this is the constant default. One
#: week = same target as the backlog phase-3 spec ("weekly cadence:
#: descriptor is rebuilt weekly so stale descriptor doesn't accumulate
#: PHI risk over time").
HIPAA_STYLE_DESCRIPTOR_REBUILD_INTERVAL_HOURS = 168  # 7 days












# ---------------------------------------------------------------------------
# style_distill_events — audit-row split for the HIPAA distill pipeline
#. Sibling to ``hipaa_access_events`` but the shape
# is wrong for the existing table; see ``_v27_create_style_distill_audit
# _and_queue`` for the rationale.
# ---------------------------------------------------------------------------







# ---------------------------------------------------------------------------
# style_distill_queue — exponential-backoff retry queue for the HIPAA
# distill pipeline. One row per account; the worker
# polls for the oldest ready row.
# ---------------------------------------------------------------------------

#: Backoff schedule in seconds; index = attempt number, value = wait
#: until next attempt. Per operator directive: NO fallback-to-local on
#: cloud failure. Retry the same backend with exponential backoff and
#: surface for operator review after attempt 8.
#:
#: Derived from :data:`email_triage.retry_backoff.STYLE_DISTILL_SCHEDULE`
#: so the schedule lives in one place across both queues.
#: The seconds-tuple is preserved here for backward compatibility with
#: tests + call sites that pin the exact integer values.
from email_triage.retry_backoff import (
    STYLE_DISTILL_SCHEDULE as _STYLE_DISTILL_SCHEDULE,
    compute_next_attempt_at as _compute_next_attempt_at,
)
STYLE_DISTILL_BACKOFF_SECONDS: tuple[int, ...] = tuple(
    int(td.total_seconds()) for td in _STYLE_DISTILL_SCHEDULE
)

#: Maximum number of attempts before the row stops being scheduled
#: for retry. The row stays in the queue (with next_retry_at NULL) so
#: operator review can find it.
STYLE_DISTILL_MAX_ATTEMPTS = len(STYLE_DISTILL_BACKOFF_SECONDS)


















# ---------------------------------------------------------------------------
# Per-contact HIPAA style descriptors
#
# Same describe-and-discard pipeline shape as M-3, but keyed on a salted
# hash of the recipient address rather than the plaintext address. The
# descriptor JSON shape is identical to the account-level descriptor —
# the scrubber is shared. Storage in dedicated ``per_contact_style_hipaa``
# table (v28); see the migration docstring for the schema + the choice
# of a separate table vs adding ``recipient_hash`` to the account-level
# descriptors table.
# ---------------------------------------------------------------------------

#: Freshness window for per-contact descriptors. After this, draft-time
#: look-up still finds the row (so the GC sweep won't have removed it
#: yet) but treats the descriptor as stale → falls back to the account-
#: level descriptor only. Operator-tunable later if needed.
HIPAA_PER_CONTACT_FRESHNESS_DAYS = 30


#: Minimum sent-message count to a single recipient before a per-contact
#: distill fires. Caller responsibility — the trigger logic lives in
#: whichever surface watches the sent-mail stream. The constant is here
#: so call sites stay in sync.
HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES = 20














# ---------------------------------------------------------------------------
# style_distill_queue_contacts — per-contact retry queue (v28)
#
# Sibling to ``style_distill_queue`` (v27) but keyed on
# ``(account_id, recipient_hash)``. The two queues are processed by the
# same worker but the helpers are distinct so the v27 helpers (one row
# per account) don't grow conditional args.
# ---------------------------------------------------------------------------















# ---------------------------------------------------------------------------
# hipaa_send_counters — HIPAA outbound-message counters for the M-3 + M-7
# trigger watchers.
#
# Counter rows are keyed on (account_id, recipient_hash). The empty string
# in recipient_hash is the ACCOUNT-AGGREGATE row that drives the M-3
# watcher; non-empty hashes drive the per-contact M-7 watcher.
#
# Privacy invariant: no plaintext recipient ever lands here. Callers pass
# the already-hashed value (the watcher hashes once at the boundary via
# :func:`email_triage.style_learning.hash_recipient_for_install`).
# ---------------------------------------------------------------------------

#: Sentinel value for the account-aggregate counter row.
#: ``recipient_hash=''`` accumulates ALL outbound messages for the account
#: (regardless of recipient) and drives the M-3 (account-level) trigger.
HIPAA_SEND_COUNTER_AGGREGATE_HASH = ""


def _validate_recipient_hash_or_aggregate(recipient_hash: str) -> str:
    """Validate ``recipient_hash`` is either the aggregate sentinel ``''``
    or a 64-char lowercase hex SHA-256 digest. Returns the normalised
    value (lowercased). Raises :class:`ValueError` on bad input.

    The defensive ``@`` check mirrors the same belt-and-braces gate in
    :func:`record_style_distill_event` (v27/v28) — easy to accidentally
    pass a plaintext address.
    """
    h = "" if recipient_hash is None else str(recipient_hash).lower()
    if h == HIPAA_SEND_COUNTER_AGGREGATE_HASH:
        return h
    if "@" in h:
        raise ValueError(
            "recipient_hash carries '@' — caller passed plaintext"
        )
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError(
            "recipient_hash must be a 64-char SHA-256 hex digest "
            "or the aggregate sentinel ''"
        )
    return h


def _bump_hipaa_send_counters(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Bump the HIPAA send-counter rows for ``(account_id, recipient_hash)``
    WITHOUT committing.

    Shared core of :func:`record_hipaa_sent_message` and
    :func:`record_hipaa_sent_message_if_new`. Issuing the bumps without a
    ``commit()`` lets the caller fold them into a wider transaction — the
    ``if_new`` wrapper needs the dedup INSERT and these counter bumps to
    commit as ONE unit, so the commit point belongs to the caller.
    """
    h = _validate_recipient_hash_or_aggregate(recipient_hash)
    if h == HIPAA_SEND_COUNTER_AGGREGATE_HASH:
        # The caller asked us to bump ONLY the aggregate — unusual
        # (production callers always bump both via the higher-level
        # wrapper) but allow it for test ergonomics. Skip the
        # double-write.
        targets = (h,)
    else:
        targets = (h, HIPAA_SEND_COUNTER_AGGREGATE_HASH)
    now = now_utc_iso()
    for target_h in targets:
        existing = conn.execute(
            "SELECT count FROM hipaa_send_counters "
            "WHERE account_id = ? AND recipient_hash = ?",
            (int(account_id), target_h),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO hipaa_send_counters "
                "(account_id, recipient_hash, count, "
                " first_seen_at, last_seen_at) "
                "VALUES (?, ?, 1, ?, ?)",
                (int(account_id), target_h, now, now),
            )
        else:
            conn.execute(
                "UPDATE hipaa_send_counters SET "
                "  count = count + 1, "
                "  last_seen_at = ? "
                "WHERE account_id = ? AND recipient_hash = ?",
                (now, int(account_id), target_h),
            )


@db_write
def record_hipaa_sent_message(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Increment the HIPAA send counter for ``(account_id, recipient_hash)``.

    Bumps two rows in a single call:

      1. The per-recipient row keyed on the non-empty hash.
      2. The account-aggregate row keyed on the empty-string sentinel.

    Both rows' ``count`` columns increment by 1 + ``last_seen_at`` is
    refreshed to ``now``. ``first_seen_at`` is set on the row's first
    increment after a reset and left untouched on subsequent bumps.

    Idempotency: this helper is NOT idempotent across calls — it's
    designed to be called exactly once per logical outbound message.
    The upstream caller (a future HIPAA-aware sent-stream observer)
    is responsible for dedup against re-delivered IMAP UIDs / Graph
    delta messages. We treat each invocation as a real send.

    Privacy: the helper rejects ``recipient_hash`` containing ``@`` or
    of the wrong length — defensive guard against a caller that
    accidentally passes plaintext. The aggregate-row sentinel is the
    only exception (empty string).
    """
    _bump_hipaa_send_counters(
        conn, account_id=account_id, recipient_hash=recipient_hash,
    )
    conn.commit()


@db_write
def record_hipaa_sent_message_if_new(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    msgid_hash: str,
    recipient_hashes: list[str] | tuple[str, ...],
) -> bool:
    """Dedup-aware wrapper around :func:`record_hipaa_sent_message`.

    Idempotently records ONE outbound message's contribution to the
    M-3 + M-7 threshold counters. Designed to be called from the
    HIPAA Sent-folder scanner where the same Sent-folder snapshot
    may be re-walked across cron ticks; this helper ensures each
    unique RFC Message-ID counts exactly once across the install's
    lifetime.

    Steps
    -----
    1. Validate ``msgid_hash`` (must be 64-char hex; defensive guard
       against accidental plaintext-Message-ID at the call site).
    2. Try to INSERT a row into ``hipaa_sent_dedup`` with
       ``(account_id, msgid_hash, now)``. If the primary key already
       exists, return ``False`` (already counted on a prior scan).
    3. For each recipient hash, bump the per-recipient row and the
       account aggregate.
    4. Commit the dedup INSERT and every counter bump as ONE
       transaction, then return ``True``.

    Atomicity
    ----------------
    The dedup INSERT and the counter bumps share a single ``commit()``.
    A crash between recording the message as "seen" and incrementing
    the M-3/M-7 counters used to leave the dedup row claiming the
    message was counted while the counters had never moved — silently
    under-counting the install forever. Folding both into one
    transaction makes the record atomic: either the message is deduped
    AND counted, or neither happened. The ``@db_write`` decorator holds
    the process-wide write lock for the whole call, so no foreign
    writer can flush this half-built transaction.

    Privacy posture
    ---------------
    The dedup table stores only ``(account_id, salted-msgid-hash,
    recorded_at)`` — no plaintext Message-IDs, no recipient
    addresses, no subject/body bytes. The hash uses the same salt
    as the per-contact M-7 path (one rotation invalidates both
    surfaces consistently — see
    :func:`email_triage.style_learning.per_contact_hipaa.hash_message_id_for_install`).

    Returns
    -------
    ``True`` when this call recorded a NEW message (counters bumped);
    ``False`` when the message was already in the dedup table (no-op
    on counters).
    """

    if not msgid_hash or not isinstance(msgid_hash, str):
        raise ValueError("msgid_hash must be a non-empty string")
    h = msgid_hash.strip().lower()
    if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
        raise ValueError(
            f"msgid_hash must be 64-char lowercase hex "
            f"(got len={len(h)!r})"
        )

    now = now_utc_iso()
    cur = conn.execute(
        "INSERT OR IGNORE INTO hipaa_sent_dedup "
        "  (account_id, msgid_hash, recorded_at) "
        "VALUES (?, ?, ?)",
        (int(account_id), h, now),
    )
    if cur.rowcount == 0:
        # Already in dedup; counters were bumped on the prior scan.
        # No-op on the counters — but the INSERT OR IGNORE still opened
        # an implicit sqlite3 transaction even though it inserted zero
        # rows. Returning without a commit/rollback leaves
        # ``conn.in_transaction`` True, so the NEXT helper that issues
        # an explicit ``BEGIN`` / ``BEGIN IMMEDIATE`` raises
        # ``OperationalError: cannot start a transaction within a
        # transaction``. Roll the (empty) transaction back so the
        # next lock holder starts clean.
        conn.rollback()
        return False

    # New message — bump per-recipient + aggregate, then commit the
    # dedup INSERT and every counter bump together. A single commit
    # makes "deduped" and "counted" atomic: a crash before this
    # point rolls back both; a crash after it has persisted both.
    for rh in recipient_hashes or ():
        _bump_hipaa_send_counters(
            conn, account_id=account_id, recipient_hash=rh,
        )
    conn.commit()
    return True


@db_write
def prune_hipaa_sent_dedup(
    conn: sqlite3.Connection,
    *,
    older_than_days: int = 90,
) -> int:
    """Drop dedup rows older than ``older_than_days``. Returns row count.

    Bounds table growth on long-running installs. 90 days is a sensible
    default: the cron loop scans the Sent folder every 6h with a
    50-message window, so the table holds at most ~360 rows per active
    HIPAA account per day; pruning at 90 days caps each account around
    32k rows worst case. In practice the cron's ``limit=50`` ceiling
    means an active HIPAA account contributes ~5-15 unique messages
    per scan tick, so steady-state is much smaller.

    Called from the cron sweep alongside the HIPAA counter scan; safe
    to invoke from CLI / tests as well.
    """
    from datetime import datetime, timedelta, timezone
    cutoff = to_utc_iso(
        datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
    )
    cur = conn.execute(
        "DELETE FROM hipaa_sent_dedup WHERE recorded_at < ?",
        (cutoff,),
    )
    conn.commit()
    return int(cur.rowcount)


def get_hipaa_send_counter(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str = HIPAA_SEND_COUNTER_AGGREGATE_HASH,
) -> dict | None:
    """Return ``{count, first_seen_at, last_seen_at}`` for the row, or None.

    The empty-string default reads the account-aggregate row (M-3
    counter). Pass a hash for per-contact (M-7) reads.
    """
    h = _validate_recipient_hash_or_aggregate(recipient_hash)
    row = conn.execute(
        "SELECT count, first_seen_at, last_seen_at "
        "FROM hipaa_send_counters "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    ).fetchone()
    if row is None:
        return None
    return {
        "count": int(row_get(row, "count", 0)),
        "first_seen_at": (
            row_get(row, "first_seen_at", 1)
        ),
        "last_seen_at": (
            row_get(row, "last_seen_at", 2)
        ),
    }


@db_write
def reset_hipaa_send_counter(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str = HIPAA_SEND_COUNTER_AGGREGATE_HASH,
    commit: bool = True,
) -> None:
    """Reset a counter row to 0 + clear its timestamps.

    Called by the trigger watcher AFTER a successful enqueue so the
    next N=20 detection starts from zero. Idempotent — second call
    on a zeroed row is a no-op SQL-wise but still safe.
    """
    h = _validate_recipient_hash_or_aggregate(recipient_hash)
    conn.execute(
        "UPDATE hipaa_send_counters SET "
        "  count = 0, first_seen_at = NULL, last_seen_at = NULL "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    )
    if commit:
        conn.commit()


def list_hipaa_per_contact_counters(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    min_count: int = 0,
) -> list[dict]:
    """List per-contact counter rows for an account, optionally filtered.

    Excludes the account-aggregate sentinel row by construction (the
    M-7 watcher iterates this list to find per-recipient triggers).
    """
    rows = conn.execute(
        "SELECT recipient_hash, count, first_seen_at, last_seen_at "
        "FROM hipaa_send_counters "
        "WHERE account_id = ? AND recipient_hash != '' "
        "  AND count >= ? "
        "ORDER BY count DESC",
        (int(account_id), int(min_count)),
    ).fetchall()
    return [
        {
            "recipient_hash": (
                row_get(r, "recipient_hash", 0)
            ),
            "count": int(row_get(r, "count", 1)),
            "first_seen_at": (
                row_get(r, "first_seen_at", 2)
            ),
            "last_seen_at": (
                row_get(r, "last_seen_at", 3)
            ),
        }
        for r in rows
    ]




# ---------------------------------------------------------------------------
# Anti-AI style guide (install-wide + per-user override)
#
# The anti-AI style guide is a free-text list of AI mannerisms the
# draft-reply LLM should AVOID (e.g. "Never open with 'Certainly!'; never
# use 'I hope this email finds you well'; avoid em-dashes for narrative
# pause"). Two surfaces:
#
#   * Install-wide guide → settings table, key
#     :data:`email_triage.web.settings_keys.ANTI_AI_STYLE_GUIDE_GLOBAL`.
#     Operator-typed on /config (admin only). Stored as a JSON-encoded
#     string (single value, no dict wrapper).
#   * Per-user override → ``users`` table columns
#     ``anti_ai_style_guide_user`` (TEXT) and
#     ``anti_ai_style_guide_disable_global`` (INTEGER bool).
#
# At draft-reply prompt-build time the two combine: by default the user
# notes + global notes are both fed into the prompt; if the user ticked
# "Disable install-wide guide", ONLY the user notes are used. The
# HIPAA gate piggybacks on the existing M-1+M-2 opt-in
# (``style_knobs_hipaa_allow:<id>``) — the anti-AI block is also
# operator-typed text (no PHI inputs by construction) and inherits the
# §164.502(a) self-disclosure carve-out.
#
# Length cap: 4000 chars per textarea (UI-side) so a 1MB POST can't
# stuff the DB. Caller is responsible for trimming; helpers store
# whatever they receive.
# ---------------------------------------------------------------------------

#: Hard upper bound on stored anti-AI guide text (per surface). UI textareas
#: render with this as ``maxlength``; the save handlers truncate defensively.
ANTI_AI_STYLE_GUIDE_MAX_LEN = 4000










# ---------------------------------------------------------------------------
# Style-data summary helpers (M-8)
#
# Read-only counts and metadata for the /profile/style-data page. We
# defensively probe for the ``sent_mail_index`` table because M-4
# ships in a parallel branch — the helpers degrade to zero counts when
# the table is absent (fresh install on this branch / pre-M-4 data
# directory) so the page renders the empty state instead of crashing.
# ---------------------------------------------------------------------------











# ---------------------------------------------------------------------------
# Per-contact style-layering toggle (M-7)
#
# Refines M-4: when replying to a recurring contact, narrow the retrieval
# pool to "replies I've sent to THIS person" before falling back to the
# global pool. Default ON when M-4 is on (operator opted into RAG once;
# matching by recipient is the privacy-neutral default refinement).
# Stored under ``account.config.style_learning_per_contact_enabled``
# rather than its own settings key so a future "Delete this account's
# style data" sweep deletes config + retrieval rows together.
#
# Opt-out shape: missing key = on (existing accounts that opted into
# M-4 keep working without touching this flag).
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------

def get_dashboard_dismissed_steps(
    conn: sqlite3.Connection, user_id: int,
) -> list[str]:
    """Return dashboard checklist step ids the user has dismissed.

    Stored as ``{"steps": [...]}`` under ``user:{id}:dashboard_dismissed_steps``.
    An older raw-list format is tolerated.
    """
    raw = get_setting(conn, f"user:{int(user_id)}:dashboard_dismissed_steps")
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, dict):
        steps = raw.get("steps")
        if isinstance(steps, list):
            return [str(x) for x in steps]
    return []


def set_dashboard_dismissed_steps(
    conn: sqlite3.Connection, user_id: int, steps: list[str],
) -> None:
    """Persist the user's dismissed dashboard steps (idempotent)."""
    # Deduplicate while preserving order.
    seen: set[str] = set()
    cleaned: list[str] = []
    for s in steps:
        s = str(s)
        if s and s not in seen:
            seen.add(s)
            cleaned.append(s)
    set_setting(
        conn,
        f"user:{int(user_id)}:dashboard_dismissed_steps",
        {"steps": cleaned},
    )


def get_dashboard_getting_started(
    conn: sqlite3.Connection, user: dict,
) -> dict:
    """Resolve the getting-started checklist state for ``user``.

    Returns a dict with the keys the dashboard template renders:

    * ``steps``: ordered list of ``{id, title, done, dismissed, href,
      button, optional}`` entries.
    * ``all_done``: True when every non-optional step is either done
      or dismissed.
    * ``account_count``: convenience int the template uses to decide
      the "Enable Calendar" deep-link target.
    * ``first_account_id``: id of the user's first account, or None.
    """
    user_id = int(user["id"])
    accounts = list_email_accounts(conn, user_id=user_id)
    account_count = len(accounts)
    first_account_id = accounts[0]["id"] if accounts else None

    # Meeting prefs: "non-default" means the user visited the profile
    # page at least once. Empty dict = never saved; anything else counts.
    from email_triage.web import settings_keys as _S
    raw_prefs = get_setting(conn, _S.meeting_prefs(user_id))
    prefs_set = bool(raw_prefs)

    # API keys: any row scoped to this user (treat as at-least-one
    # generated, including revoked — dismissal handles the "I'm done
    # with this nudge" case).
    try:
        from email_triage.web.auth import list_api_keys
        keys = list_api_keys(conn, user_id=user_id)
    except Exception:
        keys = []
    has_key = bool(keys)

    # Any calendar-enabled account belonging to the user.
    calendar_on = any(
        is_calendar_enabled(conn, a["id"]) for a in accounts
    )

    dismissed = set(get_dashboard_dismissed_steps(conn, user_id))

    steps = [
        {
            "id": "add_account",
            "title": "Add your first email account",
            "done": account_count >= 1,
            "dismissed": "add_account" in dismissed,
            "href": "/accounts",
            "button": "Add account",
            "optional": False,
        },
        {
            "id": "set_prefs",
            "title": "Set working hours and preferences",
            "done": prefs_set,
            "dismissed": "set_prefs" in dismissed,
            "href": "/profile",
            "button": "Open profile",
            "optional": False,
        },
        {
            "id": "enable_calendar",
            "title": "Enable Calendar (optional)",
            "done": calendar_on,
            "dismissed": "enable_calendar" in dismissed,
            "href": (
                f"/accounts/{first_account_id}/edit"
                if first_account_id else "/accounts"
            ),
            "button": "Enable calendar",
            "optional": True,
        },
        {
            "id": "generate_token",
            "title": "Generate an access token for your AI assistant (optional)",
            "done": has_key,
            "dismissed": "generate_token" in dismissed,
            "href": "/accounts/api-keys",
            "button": "Manage tokens",
            "optional": True,
        },
    ]

    all_done = all(
        s["done"] or s["dismissed"]
        for s in steps
        if not s["optional"]
    )

    return {
        "steps": steps,
        "all_done": all_done,
        "account_count": account_count,
        "first_account_id": first_account_id,
    }


def get_recent_triage_runs_for_user(
    conn: sqlite3.Connection, user_id: int, limit: int = 5,
) -> list[dict]:
    """Return recent triage runs for accounts owned by ``user_id``.

    Dashboard shows "my" recent activity only — a user scoped to their
    own accounts; admins who want a global view click through to /runs
    or /admin/stats.
    """
    import json
    rows = conn.execute(
        "SELECT tr.*, u.email AS actor_email, u.name AS actor_name "
        "FROM triage_runs tr "
        "LEFT JOIN users u ON tr.actor_user_id = u.id "
        "JOIN email_accounts ea ON ea.id = tr.account_id "
        "WHERE ea.user_id = ? "
        "ORDER BY tr.id DESC LIMIT ?",
        (int(user_id), int(limit)),
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        d["results"] = load_json_col(d.pop("results_json", "[]"), default=[])
        d["errors"] = load_json_col(d.pop("errors_json", "[]"), default=[])
        out.append(d)
    return out


def count_triage_messages_in_window(
    conn: sqlite3.Connection, *, since_iso: str,
) -> int:
    """Sum of messages across triage_runs since ``since_iso``."""
    row = conn.execute(
        "SELECT COALESCE(SUM(total_messages), 0) AS cnt "
        "FROM triage_runs WHERE created_at >= ?",
        (since_iso,),
    ).fetchone()
    return int(row["cnt"]) if row else 0


def triage_performance_per_message(
    conn: sqlite3.Connection, *, since_iso: str,
) -> dict:
    """Return per-message seconds stats across the given window.

    Normalises per run's ``elapsed_secs / total_messages`` so a single
    big-batch run doesn't skew the average. Runs with zero messages are
    skipped (they happen for empty queries).
    """
    rows = conn.execute(
        "SELECT elapsed_secs, total_messages FROM triage_runs "
        "WHERE created_at >= ? AND total_messages > 0",
        (since_iso,),
    ).fetchall()
    per_msg: list[float] = []
    for r in rows:
        elapsed = r["elapsed_secs"] or 0.0
        total = r["total_messages"] or 0
        if total > 0:
            per_msg.append(float(elapsed) / float(total))
    if not per_msg:
        return {"avg": 0.0, "min": 0.0, "max": 0.0, "samples": 0}
    return {
        "avg": sum(per_msg) / len(per_msg),
        "min": min(per_msg),
        "max": max(per_msg),
        "samples": len(per_msg),
    }


def triage_category_counts(
    conn: sqlite3.Connection, *, since_iso: str,
) -> dict[str, int]:
    """Per-category message counts across triage_runs in the window."""
    import json
    rows = conn.execute(
        "SELECT results_json FROM triage_runs WHERE created_at >= ?",
        (since_iso,),
    ).fetchall()
    counts: dict[str, int] = {}
    for r in rows:
        for entry in load_json_col(r["results_json"], default=[]):
            cat = entry.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def triage_account_breakdown(
    conn: sqlite3.Connection, *, since_iso: str,
) -> list[dict]:
    """Per-account totals + avg elapsed across the window."""
    rows = conn.execute(
        "SELECT account_id, account_name, "
        "       SUM(total_messages) AS total, "
        "       COUNT(*) AS runs, "
        "       AVG(elapsed_secs) AS avg_elapsed "
        "FROM triage_runs WHERE created_at >= ? "
        "GROUP BY account_id, account_name "
        "ORDER BY total DESC",
        (since_iso,),
    ).fetchall()
    return [
        {
            "account_id": r["account_id"],
            "account_name": r["account_name"],
            "total": r["total"] or 0,
            "runs": r["runs"] or 0,
            "avg_elapsed": round(r["avg_elapsed"] or 0.0, 2),
        }
        for r in rows
    ]


def triage_error_rate(
    conn: sqlite3.Connection, *, since_iso: str,
) -> dict:
    """Error-rate trend for the admin stats page.

    Error = run with a non-empty ``errors_json``.
    """
    row = conn.execute(
        "SELECT COUNT(*) AS runs, "
        "SUM(CASE WHEN errors_json != '[]' AND errors_json != '' THEN 1 ELSE 0 END) AS err_runs "
        "FROM triage_runs WHERE created_at >= ?",
        (since_iso,),
    ).fetchone()
    runs = (row["runs"] or 0) if row else 0
    err_runs = (row["err_runs"] or 0) if row else 0
    pct = (err_runs * 100.0 / runs) if runs else 0.0
    return {"runs": runs, "err_runs": err_runs, "pct": round(pct, 2)}


# ---------------------------------------------------------------------------
# Multi-label per message
# ---------------------------------------------------------------------------
#
# Labels are install-wide tags decorating messages independently of
# LLM category. See migration v18 for schema rationale. The helpers
# below mirror the categories shape — list/create/delete on the
# catalog, plus per-message apply/remove/list on the junction.


def list_labels(conn: sqlite3.Connection) -> list[dict]:
    """Return the install-wide label catalog, ordered by slug."""
    rows = conn.execute(
        "SELECT slug, name, color, created_by_user_id, "
        "       created_at, updated_at "
        "FROM labels ORDER BY slug"
    ).fetchall()
    return _rows(rows)


def get_label(conn: sqlite3.Connection, slug: str) -> dict | None:
    """Return one label row by slug, or None."""
    row = conn.execute(
        "SELECT slug, name, color, created_by_user_id, "
        "       created_at, updated_at "
        "FROM labels WHERE slug = ?",
        (slug,),
    ).fetchone()
    return _row(row)


@db_write
def create_label(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    color: str = "#6c757d",
    created_by_user_id: int | None = None,
) -> str:
    """Insert a label. Returns the slug. Raises sqlite3.IntegrityError
    on duplicate slug — the catalog is install-wide and slugs are PK.

    ``color`` accepts any string (rendered into a ``style="background:..."``
    chip) — the manage UI constrains it to a hex picker but we don't
    re-validate here. Empty / blank strings fall back to the default
    grey so a botched form post still renders a visible chip.
    """
    now = now_utc_iso()
    color = (color or "").strip() or "#6c757d"
    conn.execute(
        "INSERT INTO labels (slug, name, color, created_by_user_id, "
        "                    created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (slug, name, color, created_by_user_id, now, now),
    )
    conn.commit()
    return slug


@db_write
def update_label(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    color: str,
) -> bool:
    """Update name + color on an existing label. Returns True if
    a row was updated."""
    now = now_utc_iso()
    color = (color or "").strip() or "#6c757d"
    cursor = conn.execute(
        "UPDATE labels SET name = ?, color = ?, updated_at = ? "
        "WHERE slug = ?",
        (name, color, now, slug),
    )
    conn.commit()
    return cursor.rowcount > 0


@db_write
def delete_label(conn: sqlite3.Connection, slug: str) -> bool:
    """Delete a label + every message_labels row referencing it.

    The junction table's FK on label_slug does NOT carry ON DELETE
    CASCADE. We could add it, but the per-FK cascade direction has
    historically been hand-rolled in the data helpers (every other
    table follows the same shape); doing it here keeps the helpers
    consistent.
    """
    conn.execute(
        "DELETE FROM message_labels WHERE label_slug = ?", (slug,),
    )
    cursor = conn.execute(
        "DELETE FROM labels WHERE slug = ?", (slug,),
    )
    conn.commit()
    return cursor.rowcount > 0


@db_write
def apply_labels_to_message(
    conn: sqlite3.Connection,
    message_id: str,
    account_id: int,
    label_slugs: list[str],
    applied_by_actor: int | None = None,
) -> int:
    """Attach one or more labels to a message. Returns rows inserted.

    INSERT OR IGNORE — re-applying an existing (message_id, slug)
    pair is a no-op, not an error. Skips any slug not present in
    the labels catalog (silent — the caller is responsible for
    validation; this is the defensive line for rule-driven applies
    where a label might have been deleted between rule creation +
    rule firing).
    """
    if not label_slugs:
        return 0
    now = now_utc_iso()
    valid_slugs = {
        r["slug"] for r in conn.execute(
            "SELECT slug FROM labels"
        ).fetchall()
    }
    inserted = 0
    for slug in label_slugs:
        if slug not in valid_slugs:
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO message_labels "
            "(message_id, account_id, label_slug, applied_by_actor, applied_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (message_id, account_id, slug, applied_by_actor, now),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def get_rule_provider_labels(
    conn: sqlite3.Connection, rule_id: int,
) -> list[dict]:
    """Read + parse ``list_rules.provider_labels`` JSON for one rule.

    Returns a list of ``{"account_id": int, "label_slug": str}``
    dicts. NULL / empty / parse-error all collapse to ``[]`` so a
    corrupt JSON value doesn't crash the page render.

    Sibling of the install-internal ``adds_labels`` reader on the
    rules-page snapshot. Kept here so non-template consumers
    (apply phase, tests) can pull the same shape without re-parsing.
    """
    row = conn.execute(
        "SELECT provider_labels FROM list_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    if row is None:
        return []
    # census  SSOT — empty/corrupt/non-list provider_labels → [].
    parsed = load_json_col(row_get(row, "provider_labels", 0), default=[])
    out: list[dict] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        aid = entry.get("account_id")
        slug = entry.get("label_slug")
        if not isinstance(aid, int) or not isinstance(slug, str):
            continue
        if not slug:
            continue
        out.append({"account_id": aid, "label_slug": slug})
    return out


@db_write
def set_rule_provider_labels(
    conn: sqlite3.Connection,
    rule_id: int,
    entries: list[dict],
) -> None:
    """Write ``list_rules.provider_labels`` JSON for one rule.

    Each ``entries`` element must be a dict with:
      * ``account_id`` — int (validated)
      * ``label_slug`` — non-empty str (validated)

    Malformed entries are silently dropped (defensive — the form
    parser is the authoritative validator; this is the second-line
    guard). An empty result writes NULL so the column round-trips
    cleanly to ``[]`` via :func:`get_rule_provider_labels`.

    Companion of the install-internal ``adds_labels`` writer baked
    into :func:`_add_rule_snapshot` / :func:`_save_rule_snapshot`
    (the rules-page handlers); kept as a standalone DB helper so
    non-handler callers (tests, future apply-phase fast path) can
    persist the same shape without going through the form layer.

    AUTH CONTRACT (N-60 / PD#9, DA MF-2): this writer does NO list-ownership
    check — it takes a bare ``rule_id``. Any router/handler that wires it up
    MUST first gate on ``email_triage.web._list_authz.is_list_writable_by(
    list_row, user_id=…, role=…)`` (gate at the ACTUATOR) or it re-opens the
    N-60 horizontal-privilege hole in a shape the structural pin can't see.
    The tripwire ``test_list_rule_authz_pin``::
    ``test_dormant_rule_mutator_has_no_router_caller`` fails the moment a
    router references this symbol.
    """
    import json as _json
    cleaned: list[dict] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        aid = entry.get("account_id")
        slug = entry.get("label_slug")
        if not isinstance(aid, int):
            continue
        if not isinstance(slug, str) or not slug:
            continue
        cleaned.append({"account_id": aid, "label_slug": slug})
    payload = dump_json_col(cleaned) if cleaned else None  # N-199 R21_7 SSOT (provider_labels — non-_json-suffix JSON col)
    conn.execute(
        "UPDATE list_rules SET provider_labels = ? WHERE id = ?",
        (payload, rule_id),
    )
    conn.commit()


@db_write
def remove_label_from_message(
    conn: sqlite3.Connection,
    message_id: str,
    label_slug: str,
) -> bool:
    """Remove a single label from a message. Returns True if a row
    was deleted."""
    cursor = conn.execute(
        "DELETE FROM message_labels WHERE message_id = ? AND label_slug = ?",
        (message_id, label_slug),
    )
    conn.commit()
    return cursor.rowcount > 0


def list_labels_on_message(
    conn: sqlite3.Connection,
    message_id: str,
) -> list[dict]:
    """Return enriched label rows for one message (joined to catalog
    for name + color). Ordered by slug.

    Returns an empty list when the message has no labels — never
    raises for "unknown message". Labels are forward-only; absence
    is the normal pre-tag state.
    """
    rows = conn.execute(
        "SELECT ml.label_slug AS slug, l.name, l.color, "
        "       ml.applied_at, ml.applied_by_actor "
        "FROM message_labels ml "
        "JOIN labels l ON l.slug = ml.label_slug "
        "WHERE ml.message_id = ? "
        "ORDER BY ml.label_slug",
        (message_id,),
    ).fetchall()
    return _rows(rows)


def list_messages_with_label(
    conn: sqlite3.Connection,
    label_slug: str,
    account_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    """Return (message_id, account_id, applied_at) rows tagged with
    ``label_slug``. When ``account_id`` is supplied, restrict to that
    account. Ordered by applied_at DESC (most recent first).

    Used by the /triage "has label X" filter — the existing triage
    surface fetches messages from the provider; this helper supplies
    the set of message_ids to intersect with the provider's search
    result.
    """
    if account_id is not None:
        rows = conn.execute(
            "SELECT message_id, account_id, applied_at FROM message_labels "
            "WHERE label_slug = ? AND account_id = ? "
            "ORDER BY applied_at DESC LIMIT ?",
            (label_slug, account_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT message_id, account_id, applied_at FROM message_labels "
            "WHERE label_slug = ? "
            "ORDER BY applied_at DESC LIMIT ?",
            (label_slug, limit),
        ).fetchall()
    return _rows(rows)


# ---------------------------------------------------------------------------
# AI backends catalog (migration v26 —  Wave 2-α I3 + I6)
# ---------------------------------------------------------------------------
#
# Single source of truth helpers for the admin-curated ``ai_backends``
# table and the per-account ``style_learning_backend_id`` FK column.
# Both surfaces (admin CRUD + per-account selector) consume these so
# the SQL lives in one place and the routers stay declarative.
#
# API-key handling: ``create_ai_backend`` + ``update_ai_backend``
# never touch ``DbSecrets`` themselves — the router is the only place
# that knows about the plaintext key (via the form input). Helpers
# accept the ``api_key_secret_ref`` *name* the router minted after
# storing the secret. That keeps the secrets-store dependency out of
# this module and matches the pattern already in ``loader.py``
# (which resolves the ref → plaintext exactly once per ``load_backend``
# call).
# ---------------------------------------------------------------------------

def decode_backup_models_value(raw) -> "list[str]":
    """ — parse a raw ``backup_models_json`` column VALUE into an ordered
    ``list[str]``. The ONE decode used by the admin form, the  classify
    resolver, AND the  ai_backends loader — never re-hand-rolled (PD#5).
    Tolerant (census  SSOT): missing / empty / corrupt / non-list → ``[]``."""
    return [
        str(m) for m in load_json_col(raw, default=[]) if str(m).strip()
    ]


def _decode_backup_models(row: dict) -> dict:
    """ — parse the ``backup_models_json`` column into a ``backup_models``
    ``list[str]`` on a row dict (the admin form + classify resolver consume it).
    """
    row["backup_models"] = decode_backup_models_value(row.get("backup_models_json"))
    return row


def _encode_backup_models(backup_models: "list[str] | None") -> "str | None":
    """ — JSON-encode an ordered backup-model list for storage.
    Empty / None → NULL (column stays absent of an empty array)."""
    import json
    cleaned = [str(m).strip() for m in (backup_models or []) if str(m).strip()]
    return dump_json_col(cleaned) if cleaned else None


def list_ai_backends(
    conn: sqlite3.Connection,
    *,
    enabled_only: bool = False,
    baa_certified_only: bool = False,
) -> list[dict]:
    """Return every row in ``ai_backends`` ordered by name.

    Filters are AND-combined and BOTH default to OFF so the admin
    list view sees disabled + non-BAA rows in addition to the active
    ones. Per-account selector callers pass ``enabled_only=True`` so
    disabled rows don't appear in the dropdown.
    """
    where: list[str] = []
    if enabled_only:
        where.append("enabled = 1")
    if baa_certified_only:
        where.append("baa_certified = 1")
    sql = (
        "SELECT id, name, type, endpoint, api_key_secret_ref, model, "
        "       backup_models_json, "
        "       baa_certified, baa_expires_at, enabled, "
        "       created_by, created_at "
        "FROM ai_backends"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY name"
    rows = conn.execute(sql).fetchall()
    return [_decode_backup_models(r) for r in _rows(rows)]


def get_ai_backend(
    conn: sqlite3.Connection, backend_id: int,
) -> dict | None:
    """Return a single ``ai_backends`` row by id, or None."""
    row = conn.execute(
        "SELECT id, name, type, endpoint, api_key_secret_ref, model, "
        "       backup_models_json, "
        "       baa_certified, baa_expires_at, enabled, "
        "       created_by, created_at "
        "FROM ai_backends WHERE id = ?",
        (int(backend_id),),
    ).fetchone()
    d = _row(row)
    return _decode_backup_models(d) if d else None


@db_write
def create_ai_backend(
    conn: sqlite3.Connection,
    *,
    name: str,
    type_: str,
    endpoint: str,
    api_key_secret_ref: str | None,
    model: str | None,
    baa_certified: bool,
    baa_expires_at: str | None,
    enabled: bool,
    created_by: int | None,
    backup_models: "list[str] | None" = None,
) -> int:
    """Insert a new row and return its id.

    Raises ``sqlite3.IntegrityError`` when:
      * ``name`` already in use (UNIQUE)
      * ``type_`` is not in the CHECK enum
      * ``baa_certified=1`` but ``baa_expires_at`` is empty (CHECK)
    The router catches these + re-renders the form with the message.

    ``backup_models`` is an ordered list of model names stored as
    a JSON array in ``backup_models_json``.
    """
    cur = conn.execute(
        "INSERT INTO ai_backends "
        "(name, type, endpoint, api_key_secret_ref, model, "
        " backup_models_json, "
        " baa_certified, baa_expires_at, enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            name,
            type_,
            endpoint,
            api_key_secret_ref,
            model,
            _encode_backup_models(backup_models),
            int(bool(baa_certified)),
            baa_expires_at,
            int(bool(enabled)),
            created_by,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


@db_write
def update_ai_backend(
    conn: sqlite3.Connection,
    backend_id: int,
    *,
    name: str,
    type_: str,
    endpoint: str,
    api_key_secret_ref: str | None,
    model: str | None,
    baa_certified: bool,
    baa_expires_at: str | None,
    enabled: bool,
    backup_models: "list[str] | None" = None,
) -> bool:
    """Update an existing ``ai_backends`` row. Returns True on hit.

    ``api_key_secret_ref`` semantics:
      * Pass the existing ref to PRESERVE the stored key (no-op).
      * Pass ``None`` to CLEAR the ref (e.g. operator switched a
        keyed backend to Ollama). The DbSecrets row referenced by
        the old ref stays in the secrets table — the router clears
        it explicitly via ``DbSecrets.delete()`` to keep the secrets
        store tidy.
      * Pass a fresh ref to REPLACE (router minted a new secret name
        + stored the new plaintext under it).
    """
    cur = conn.execute(
        "UPDATE ai_backends SET "
        "  name = ?, type = ?, endpoint = ?, "
        "  api_key_secret_ref = ?, model = ?, "
        "  backup_models_json = ?, "
        "  baa_certified = ?, baa_expires_at = ?, "
        "  enabled = ? "
        "WHERE id = ?",
        (
            name,
            type_,
            endpoint,
            api_key_secret_ref,
            model,
            _encode_backup_models(backup_models),
            int(bool(baa_certified)),
            baa_expires_at,
            int(bool(enabled)),
            int(backend_id),
        ),
    )
    conn.commit()
    return cur.rowcount > 0


@db_write
def delete_ai_backend(conn: sqlite3.Connection, backend_id: int) -> bool:
    """Delete a backend row. FK on ``email_accounts`` is ``ON DELETE
    SET NULL`` so any account selecting this backend falls back to the
    install default cleanly. Returns True on hit.
    """
    cur = conn.execute(
        "DELETE FROM ai_backends WHERE id = ?", (int(backend_id),),
    )
    conn.commit()
    return cur.rowcount > 0


def count_accounts_using_ai_backend(
    conn: sqlite3.Connection, backend_id: int,
) -> int:
    """How many ``email_accounts`` currently FK to this backend.

    Used by the delete-confirmation surface so the operator sees
    "deleting this will revert 3 accounts to the install default"
    before they confirm.
    """
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM email_accounts "
        "WHERE style_learning_backend_id = ?",
        (int(backend_id),),
    ).fetchone()
    return int(row_get(row, "n", 0))


@db_write
def set_account_style_learning_backend(
    conn: sqlite3.Connection,
    account_id: int,
    backend_id: int | None,
) -> bool:
    """Update one account's ``style_learning_backend_id`` FK.

    Pass ``backend_id=None`` to clear (revert to install default).
    Returns True on hit. Idempotent — setting to the same value is a
    no-op write that still returns True.
    """
    now = now_utc_iso()
    cur = conn.execute(
        "UPDATE email_accounts SET "
        "  style_learning_backend_id = ?, updated_at = ? "
        "WHERE id = ?",
        (
            int(backend_id) if backend_id is not None else None,
            now,
            int(account_id),
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def get_account_style_learning_backend(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    """Return the ``ai_backends`` row currently selected by this account.

    Returns ``None`` when the FK is NULL (install default) or when the
    target row has been deleted (FK auto-cleared by ON DELETE SET NULL).
    """
    row = conn.execute(
        "SELECT ab.id, ab.name, ab.type, ab.endpoint, "
        "       ab.api_key_secret_ref, ab.model, "
        "       ab.baa_certified, ab.baa_expires_at, ab.enabled "
        "FROM email_accounts ea "
        "JOIN ai_backends ab "
        "  ON ab.id = ea.style_learning_backend_id "
        "WHERE ea.id = ?",
        (int(account_id),),
    ).fetchone()
    return _row(row)


# ---------------------------------------------------------------------------
# watcher_retry_queue — the single consolidated retry queue
# ---------------------------------------------------------------------------
#
# Every per-message ingestion failure — IMAP IDLE watcher, unified poll,
# Gmail push, O365 push — parks here. The retry-subsystem rebuild
# collapsed the two legacy queues onto this one table; the
# ``failure_kind`` column (v35) is the only per-row distinction:
# ``'llm_unreachable'`` rows are skipped by the drainer while the LLM
# breaker is open, NULL rows (ordinary fetch/process failures) drain
# every tick.
#
# Schema lives in migration v30 (+ failure_kind in v35). Addressing is
# provider-specific (mailbox+uid+uidvalidity for IMAP, gmail_msg_id for
# Gmail, o365_msg_id for O365). The state machine is pending → done /
# dead.
#
# Privacy
# -------
# ``last_error_msg`` is BOTH PHI-scrubbed (``redact_exc`` — address /
# mailbox-path) AND token-scrubbed before INSERT, via
# ``_scrub_watcher_retry_error_msg`` -> ``_errfmt.scrub_error_for_persist``
# (census run13 #2; was secret-leg-only — the ``_WATCHER_RETRY_TOKEN_KEYS``
# set covers ONLY the token leg). HIPAA accounts may have provider error
# responses that incidentally carry PHI; we scrub at the persistence boundary
# regardless of the account's HIPAA flag.

#: Maximum length of ``last_error_msg`` before truncation. 500 chars
#: is enough to identify the error shape but small enough that a
#: provider-side stacktrace can't bloat the row.
_WATCHER_RETRY_LAST_ERROR_MAX = 500

#: ``_WATCHER_RETRY_TOKEN_KEYS`` / ``_scrub_secrets`` are imported at the top of
#: this module from the ``_secret_scrub`` SSOT (census #6).

#: Valid ``dead_reason`` values. The sweeper sets exactly one of
#: these when transitioning a row to state='dead'.
WATCHER_RETRY_DEAD_REASONS: frozenset[str] = frozenset({
    "max_attempts_exceeded",
    "uidvalidity_changed",
    "message_gone",
    # Verified-absent expunge: a provider 404, OR a 0-byte IMAP fetch whose
    # UID SEARCH confirms the message is genuinely gone. Distinct from
    # message_gone — it is the BENIGN, confirmed-gone outcome and never trips
    # the message_gone spike fail-safe (see routers/health.py). The ambiguous
    # "fetched empty but the UID may still be present" case stays message_gone.
    "message_expunged",
    "auth_revoked",
    "operator_abandoned",
})


def _scrub_watcher_retry_error_msg(msg: str | None) -> str | None:
    """PHI-scrub + token-scrub + truncate a persisted error message.

    Delegates to ``_errfmt.scrub_error_for_persist`` (census run13 #2) — BOTH
    legs: redact_exc (PHI address/mailbox-path, N-42) + the token scrub. Was
    secret-leg-only (`_scrub_secrets`), so a live IMAP/Graph fetch exception
    carrying a recipient address / mailbox path persisted cleartext into the
    admin-rendered ``watcher_retry_queue.last_error_msg``. Keeps the 500-char
    cap shared with every other persisted-error-text writer.
    """
    return _scrub_err_persist(msg, max_len=_WATCHER_RETRY_LAST_ERROR_MAX)


@db_write
def enqueue_retry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    provider_type: str,
    mailbox: str | None = None,
    uid: int | None = None,
    uidvalidity: int | None = None,
    gmail_msg_id: str | None = None,
    o365_msg_id: str | None = None,
    error_class: str,
    error_msg: str | None = None,
    failure_kind: str | None = None,
) -> int:
    """Insert (or bump) a row in ``watcher_retry_queue``.

    Addressing semantics
    --------------------
    Exactly one provider-specific addressing tuple must be populated:

    * ``provider_type='imap'`` → ``mailbox`` and ``uid`` required;
      ``uidvalidity`` is required *non-null* only on servers that expose
      it. A server whose ``SELECT`` carries no ``UIDVALIDITY`` line
      legitimately yields ``uidvalidity=None`` (RFC 3501 §2.3.1.1 makes
      the response code OPTIONAL); #239c — rather than rejecting that
      row (which raised ``ValueError``, was swallowed, and froze the
       IMAP-poll high-water mark forever, re-walking + re-failing
      the same message every tick), ``None`` is stored as the sentinel
      ``0``. The drainer already treats ``uidvalidity=0`` as a sentinel:
      a live mailbox never reports 0, so a server that *does* expose
      UIDVALIDITY will mismatch and the row marks dead, while a server
      that exposes none reads ``None`` live and the mismatch check is
      skipped so recovery proceeds.
    * ``provider_type='gmail'`` → ``gmail_msg_id`` required.
    * ``provider_type='office365'`` → ``o365_msg_id`` required.

    ``failure_kind``
    ----------------
    Optional classifier for the failure. ``'llm_unreachable'`` marks a
    row the drainer must skip while the LLM circuit breaker is open
    (re-running classify against a dead backend just burns latency);
    NULL means an ordinary per-message fetch/process failure, drained on
    every tick. On the bump branch the value is refreshed only when a
    non-None argument is given, so re-enqueuing without a kind keeps the
    original classification.

    The UNIQUE partial indexes (see migration v30) on each addressing
    tuple guarantee that re-enqueuing the same logical message hits
    the UPDATE branch rather than creating a duplicate row.

    On duplicate (existing pending row): increments ``attempt_count``,
    refreshes ``last_error_*``, recomputes ``next_attempt_at`` via
    :func:`email_triage.retry_backoff.compute_next_attempt_at`. If the
    schedule is exhausted, the row stays pending with the LAST entry's
    backoff applied — the sweeper transitions it to ``dead`` on the
    next due fire (the spec keeps this state transition in the sweeper,
    not the enqueue path).

    On duplicate row in ``state='done'`` or ``state='dead'``: a fresh
    pending row would require dropping the old row first (the partial
    UNIQUE index allows only one pending). We resurrect the row in
    place: set ``state='pending'``, ``attempt_count=0``, clear
    ``resolved_at`` + ``dead_reason``, set fresh ``next_attempt_at``.

    Returns
    -------
    int
        The row id (``watcher_retry_queue.id``).
    """
    from datetime import datetime, timezone
    from email_triage.retry_backoff import (
        WATCHER_RETRY_SCHEDULE, compute_next_attempt_at,
    )

    # Validate provider_type addressing.
    pt = (provider_type or "").lower().strip()
    if pt == "imap":
        if mailbox is None or uid is None:
            raise ValueError(
                "enqueue_retry: provider_type='imap' requires mailbox, uid"
            )
        # #239c — a server with no UIDVALIDITY response code yields
        # None here legitimately. Store the sentinel 0 instead of
        # raising: rejecting froze the IMAP-poll HWM forever (the
        # ValueError was swallowed → uid_safe=False →  HWM cap →
        # endless re-walk of the same message). 0 is safe — a live
        # mailbox never reports UIDVALIDITY 0.
        if uidvalidity is None:
            uidvalidity = 0
    elif pt == "gmail":
        if not gmail_msg_id:
            raise ValueError(
                "enqueue_retry: provider_type='gmail' requires gmail_msg_id"
            )
    elif pt == "office365":
        if not o365_msg_id:
            raise ValueError(
                "enqueue_retry: provider_type='office365' requires o365_msg_id"
            )
    else:
        raise ValueError(
            f"enqueue_retry: unsupported provider_type {provider_type!r}"
        )

    scrubbed_msg = _scrub_watcher_retry_error_msg(error_msg)
    now_iso = now_utc_iso()

    # Look up the existing row (if any) by the provider-specific
    # addressing tuple. We split the SELECT per provider_type so each
    # query hits its own UNIQUE partial index.
    existing_row: sqlite3.Row | None = None
    if pt == "imap":
        existing_row = conn.execute(
            "SELECT id, attempt_count, state FROM watcher_retry_queue "
            "WHERE provider_type='imap' AND account_id=? "
            "  AND mailbox=? AND uid=? AND uidvalidity=?",
            (int(account_id), mailbox, int(uid), int(uidvalidity)),
        ).fetchone()
    elif pt == "gmail":
        existing_row = conn.execute(
            "SELECT id, attempt_count, state FROM watcher_retry_queue "
            "WHERE provider_type='gmail' AND account_id=? "
            "  AND gmail_msg_id=?",
            (int(account_id), str(gmail_msg_id)),
        ).fetchone()
    elif pt == "office365":
        existing_row = conn.execute(
            "SELECT id, attempt_count, state FROM watcher_retry_queue "
            "WHERE provider_type='office365' AND account_id=? "
            "  AND o365_msg_id=?",
            (int(account_id), str(o365_msg_id)),
        ).fetchone()

    if existing_row is not None:
        existing_id = int(existing_row["id"])
        existing_state = str(existing_row["state"])
        if existing_state == "pending":
            new_count = int(existing_row["attempt_count"]) + 1
            next_dt = compute_next_attempt_at(
                new_count, WATCHER_RETRY_SCHEDULE,
            )
            # If schedule exhausted, leave next_attempt_at at the last
            # scheduled point (now + final delta) so the sweeper picks
            # it up + transitions to dead. We never write NULL into a
            # NOT NULL column.
            if next_dt is None:
                next_dt = datetime.now(timezone.utc) + (
                    WATCHER_RETRY_SCHEDULE[-1]
                )
            # failure_kind: refresh only when a non-None value was
            # passed (a bare re-enqueue keeps the original kind via
            # COALESCE(?, failure_kind)).
            conn.execute(
                "UPDATE watcher_retry_queue SET "
                "  attempt_count=?, next_attempt_at=?, "
                "  last_error_class=?, last_error_msg=?, last_error_at=?, "
                "  failure_kind=COALESCE(?, failure_kind) "
                "WHERE id=?",
                (
                    new_count, to_utc_iso(next_dt),
                    str(error_class), scrubbed_msg, now_iso,
                    failure_kind,
                    existing_id,
                ),
            )
            conn.commit()
            return existing_id
        # done / dead → resurrect.
        next_dt = compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)
        # compute_next_attempt_at(0, schedule) is always non-None
        # because len(WATCHER_RETRY_SCHEDULE) > 0.
        assert next_dt is not None
        conn.execute(
            "UPDATE watcher_retry_queue SET "
            "  state='pending', attempt_count=0, "
            "  next_attempt_at=?, last_error_class=?, last_error_msg=?, "
            "  last_error_at=?, resolved_at=NULL, dead_reason=NULL, "
            "  failure_kind=COALESCE(?, failure_kind) "
            "WHERE id=?",
            (
                to_utc_iso(next_dt),
                str(error_class), scrubbed_msg, now_iso,
                failure_kind,
                existing_id,
            ),
        )
        conn.commit()
        return existing_id

    # No existing row — fresh INSERT.
    next_dt = compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)
    assert next_dt is not None
    cur = conn.execute(
        "INSERT INTO watcher_retry_queue ("
        "  account_id, provider_type, "
        "  mailbox, uid, uidvalidity, "
        "  gmail_msg_id, o365_msg_id, "
        "  state, attempt_count, failure_kind, "
        "  next_attempt_at, "
        "  last_error_class, last_error_msg, last_error_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?, ?)",
        (
            int(account_id), pt,
            mailbox, (int(uid) if uid is not None else None),
            (int(uidvalidity) if uidvalidity is not None else None),
            gmail_msg_id, o365_msg_id,
            failure_kind,
            to_utc_iso(next_dt),
            str(error_class), scrubbed_msg, now_iso,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_due_retries(
    conn: sqlite3.Connection, *, limit: int = 10,
) -> list[sqlite3.Row]:
    """Return up to ``limit`` rows whose ``next_attempt_at <= now()`` AND
    ``state='pending'``.

    Ordering is ``next_attempt_at ASC`` — the longest-overdue rows go
    first. The partial index ``idx_watcher_retry_due`` covers this
    query exactly.

    Note on the timestamp comparison
    --------------------------------
    Rows are written with Python's ``datetime.isoformat()`` which
    produces ``'2026-05-17T12:34:56.789012+00:00'`` (T separator,
    microseconds, +00:00 suffix). SQLite's ``datetime('now')`` returns
    ``'2026-05-17 12:34:56'`` (space separator, no microseconds, no
    tz). Lexical string comparison of those formats is BROKEN because
    'T' > ' '. We compare against the current UTC time formatted as
    a Python-ISO string built in the application — keeping the
    comparison apples-to-apples.
    """
    now_iso = now_utc_iso()
    rows = conn.execute(
        "SELECT * FROM watcher_retry_queue "
        "WHERE state='pending' AND next_attempt_at <= ? "
        "ORDER BY next_attempt_at ASC LIMIT ?",
        (now_iso, int(limit)),
    ).fetchall()
    return list(rows)


@db_write
def mark_retry_done(conn: sqlite3.Connection, retry_id: int) -> None:
    """Transition a row to ``state='done'``.

    Idempotent: re-marking a done / dead row is a no-op (the UPDATE
    has a ``WHERE state='pending'`` guard).
    """
    now_iso = now_utc_iso()
    conn.execute(
        "UPDATE watcher_retry_queue "
        "SET state='done', resolved_at=? "
        "WHERE id=? AND state='pending'",
        (now_iso, int(retry_id)),
    )
    conn.commit()


@db_write
def mark_retry_dead(
    conn: sqlite3.Connection, retry_id: int, *, reason: str,
) -> None:
    """Transition a row to ``state='dead'`` with the given ``reason``.

    ``reason`` must be one of :data:`WATCHER_RETRY_DEAD_REASONS`. The
    column itself has no CHECK constraint (we want to surface bad
    reasons in logs, not lose the row), but we validate at the writer.
    """
    if reason not in WATCHER_RETRY_DEAD_REASONS:
        raise ValueError(
            f"mark_retry_dead: invalid reason {reason!r}; "
            f"expected one of {sorted(WATCHER_RETRY_DEAD_REASONS)}"
        )
    now_iso = now_utc_iso()
    conn.execute(
        "UPDATE watcher_retry_queue "
        "SET state='dead', dead_reason=?, resolved_at=? "
        "WHERE id=? AND state='pending'",
        (str(reason), now_iso, int(retry_id)),
    )
    conn.commit()


@db_write
def resurrect_auth_revoked_retries(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Flip all ``watcher_retry_queue`` rows for ``account_id`` with
    ``state='dead' AND dead_reason='auth_revoked'`` back to ``state='pending'``.

    Symmetric CLEAR half of ``mark_retry_dead(reason='auth_revoked')`` at
    ``watcher_retry.py:175`` (N-386 — watcher_retry_queue lifecycle asymmetry,
    MED). Before this landing, ``auth_revoked`` was SET-broad / CLEAR-narrow
    (PD#18): the only path back to pending was ``enqueue_retry``'s dead-branch
    resurrection, which requires the SAME (account_id, addressing-tuple) to
    fire ANOTHER watcher exception with a resurrectable path — rare after a
    provider outage recovers. A mid-outage frozen row stayed dead forever
    while the account itself was healthy again.

    Sibling of ``_clear_auth_stale``: both fire on every provider-success path
    via the ``record_provider_outcome`` funnel (``app.py:1610``). The other 5
    ``WATCHER_RETRY_DEAD_REASONS`` values (``max_attempts_exceeded``,
    ``uidvalidity_changed``, ``message_gone``, ``message_expunged``,
    ``operator_abandoned``) are terminal by design — see the
    ``_TERMINAL_BY_DESIGN`` set in
    ``tests/test_watcher_retry_dead_reason_symmetry_pin.py``.

    Idempotent + cheap: the ``WHERE account_id=? AND state='dead'`` narrow is
    covered by ``idx_watcher_retry_account`` (migration v30). The residual
    ``dead_reason`` filter runs over the (typically empty) small set of dead
    rows for the account. SQLite skips the WAL page write when no rows match.

    Returns the number of rows flipped (>0 → caller may log; 0 → common case).
    """
    # Mirror ``enqueue_retry`` — the schedule + backoff computer are imported
    # locally to avoid a module-import cycle with retry_backoff.
    from email_triage.retry_backoff import (
        WATCHER_RETRY_SCHEDULE, compute_next_attempt_at,
    )
    next_dt = compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)
    assert next_dt is not None
    cur = conn.execute(
        "UPDATE watcher_retry_queue "
        "SET state='pending', dead_reason=NULL, resolved_at=NULL, "
        "    attempt_count=0, next_attempt_at=? "
        "WHERE account_id=? AND state='dead' AND dead_reason='auth_revoked'",
        (to_utc_iso(next_dt), int(account_id)),
    )
    conn.commit()
    return cur.rowcount or 0


def get_retry(
    conn: sqlite3.Connection, retry_id: int,
) -> sqlite3.Row | None:
    """Return the row by id, or None."""
    return conn.execute(
        "SELECT * FROM watcher_retry_queue WHERE id=?",
        (int(retry_id),),
    ).fetchone()


def _retries_for_admin_where(
    account_id: int | None, state: str | None,
) -> tuple[str, list[Any]]:
    """Shared WHERE builder for the admin retry-queue list + count.

    Returns ``(where_sql, params)`` (where_sql is ``""`` for no filter).
     — list and count MUST share this funnel so the "showing N of M"
    denominator can't drift from the list it annotates (Prime Directive
    #5: two mirrored predicate copies WILL drift). Add a filter axis here
    and BOTH list_retries_for_admin and count_retries_for_admin pick it
    up in lockstep."""
    clauses: list[str] = []
    params: list[Any] = []
    if account_id is not None:
        clauses.append("account_id = ?")
        params.append(int(account_id))
    if state is not None:
        clauses.append("state = ?")
        params.append(str(state))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def list_retries_for_admin(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    state: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """List rows for the admin UI (consumed by R-B).

    Filters:
      * ``account_id`` — limit to one account (None = all accounts).
      * ``state`` — filter by state (None = all states).

    ``offset`` pages the queue so the full backlog
    past the page cap is accessible, not just counted.

    Ordering: most-recent first, by COALESCE(last_error_at, created_at).
    """
    where, params = _retries_for_admin_where(account_id, state)
    params.append(int(limit))
    params.append(int(offset))
    rows = conn.execute(
        f"SELECT * FROM watcher_retry_queue {where} "
        "ORDER BY COALESCE(last_error_at, created_at) DESC "
        "LIMIT ? OFFSET ?",
        tuple(params),
    ).fetchall()
    return list(rows)


def count_retries_for_admin(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    state: str | None = None,
) -> int:
    """Total retry-queue rows matching the SAME filters as
    :func:`list_retries_for_admin` (minus the LIMIT) — the honest
    denominator for the admin page's "showing first N of M" notice. Shares ``_retries_for_admin_where`` with the list so the
    count can't drift from the list it annotates."""
    where, params = _retries_for_admin_where(account_id, state)
    row = conn.execute(
        f"SELECT COUNT(*) FROM watcher_retry_queue {where}",
        tuple(params),
    ).fetchone()
    return int(row[0]) if row is not None else 0


def count_recent_deads(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    since_hours: int = 24,
) -> int:
    """Count dead rows whose ``resolved_at`` is within ``since_hours``.

    Drives R-B's pattern-detection threshold (e.g. "more than 20 dead
    in the past 24h → flag in daily-health email"). Returns 0 when no
    matches.
    """
    from datetime import datetime, timezone, timedelta
    cutoff_iso = to_utc_iso(
        datetime.now(timezone.utc) - timedelta(hours=int(since_hours))
    )
    clauses = ["state = 'dead'", "resolved_at >= ?"]
    params: list[Any] = [cutoff_iso]
    if account_id is not None:
        clauses.append("account_id = ?")
        params.append(int(account_id))
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM watcher_retry_queue "
        "WHERE " + " AND ".join(clauses),
        tuple(params),
    ).fetchone()
    if row is None:
        return 0
    return int(row_get(row, "c", 0))


def count_pending_retries(
    conn: sqlite3.Connection,
    *,
    failure_kind: str | None = None,
) -> int:
    """Count rows in ``state='pending'``, optionally by ``failure_kind``.

    With ``failure_kind='llm_unreachable'`` this is the "messages queued
    while the LLM backend is down" depth surfaced on the /config + page
    banners — the consolidated replacement for the retired
    ``triage_retry_queue.queue_depth``.
    """
    clauses = ["state='pending'"]
    params: list[Any] = []
    if failure_kind is not None:
        clauses.append("failure_kind = ?")
        params.append(str(failure_kind))
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM watcher_retry_queue "
        "WHERE " + " AND ".join(clauses),
        tuple(params),
    ).fetchone()
    if row is None:
        return 0
    return int(row_get(row, "c", 0))


# ---------------------------------------------------------------------------
# #277a back-compat shim — audit cluster moved to email_triage.db.audit
# (2026-05-23). Explicit re-exports (NOT ``import *``) so every existing
# ``from email_triage.web.db import <name>`` import string keeps working
# unchanged for the 554 known call sites across 76 files at extraction
# time. The ``triage_logging.py`` deliberate-late-import pattern depends on
# this shim preserving the import string verbatim.
#
# When adding more #277b/c/d cluster extractions, mirror this block at the
# bottom of web/db.py rather than scattering shim imports through the file.
# ---------------------------------------------------------------------------

from email_triage.db.audit import (  # noqa: E402, F401
    _AUDIT_CHAIN_ANCHOR_KEY,
    _capture_chain_anchor,
    _get_current_hmac_version,
    _set_hmac_key_for_test,
    bump_session_epoch,
    compute_log_row_hash,
    count_access_events,
    count_api_key_events,
    count_discover_runs,
    count_hipaa_access_events,
    count_hipaa_boundary_events,
    get_last_log_row_hash,
    insert_log_entry,
    latest_hipaa_boundaries_for_accounts,
    latest_hipaa_boundary,
    list_access_events,
    list_api_key_events,
    list_auth_events,
    list_discover_runs,
    list_hipaa_access_events,
    list_hipaa_boundary_events,
    list_log_entries,
    list_user_status_events,
    prune_log_entries,
    prune_log_entries_by_age_and_count,
    record_access_event,
    record_api_key_event,
    record_auth_event,
    record_discover_run,
    record_hipaa_access_event,
    record_hipaa_boundary,
    record_user_status_event,
    set_hmac_keys,
    set_user_disabled,
    update_hipaa_access_event,
    verify_audit_chain,
    verify_all_audit_chains,
    verify_log_chain,
)


# ---------------------------------------------------------------------------
# #277b back-compat shim — account cluster moved to email_triage.db.accounts
# (2026-05-29). Explicit re-exports (NOT ``import *``) so every existing
# ``from email_triage.web.db import <name>`` import string keeps working
# unchanged for the public-name surface (336-name baseline; zero names lost).
# Widely late-imported by web/dependencies.py (can_manage_account,
# get_email_account), web/app.py (list_email_accounts), actions/*, etc. —
# this shim preserves every one of those import strings verbatim.
#
# Mirrors the #277a audit.py shim block above. When #277c lands db/style.py,
# add a sibling block here rather than scattering shim imports.
# ---------------------------------------------------------------------------

from email_triage.db.accounts import (  # noqa: E402, F401
    INGESTION_POLL_MIN,
    INGESTION_POLL_MAX,
    INGESTION_POLL_STEP,
    INGESTION_POLL_DEFAULT,
    AliasValidationError,
    _looks_like_email,
    normalize_aliases,
    normalise_from_address,
    account_email,
    account_aliases,
    account_addresses,
    clamp_poll_interval_minutes,
    _account_mailboxes,
    _apply_account_config_back_compat,
    apply_ingestion_back_compat,
    list_email_accounts,
    get_email_account,
    create_email_account,
    account_is_active,
    set_account_active,
    set_account_hipaa,
    update_email_account,
    update_email_account_config,
    update_account_config_keys,
    update_email_account_aliases,
    delete_email_account,
    add_account_delegate,
    remove_account_delegate,
    list_account_delegates,
    is_account_delegate,
    can_manage_account,
    can_administer_account,
    list_account_routes,
    get_account_route,
    upsert_account_route,
    delete_account_route,
    effective_routes_by_cat,
    get_mailbox_route_overrides,
    set_mailbox_route_overrides,
    get_folder_prefs,
    save_folder_prefs,
    get_visible_folders,
    is_alias_mode_enabled_for_account,
    set_alias_mode_enabled_for_account,
)

# ---------------------------------------------------------------------------
# #277c back-compat shim — style cluster moved to email_triage.db.style
# (2026-05-29). Explicit re-exports (NOT ``import *``) so every existing
# ``from email_triage.web.db import <name>`` import string keeps working
# unchanged. _has_table/_has_column were promoted to db/_helpers (db-sme
# SUB-1); re-exported here so profile.py's web.db import keeps resolving.
# Mirrors the #277a audit.py + #277b accounts.py shim blocks above.
# ---------------------------------------------------------------------------

from email_triage.db._helpers import (  # noqa: E402, F401
    _has_column,
    _has_table,
)

from email_triage.db.style import (  # noqa: E402, F401
    _style_profile_key,
    get_style_profile,
    set_style_profile,
    delete_style_profile,
    get_account_style_per_alias,
    set_account_style_per_alias,
    list_account_style_per_alias,
    delete_account_style_per_alias,
    get_user_style_knobs,
    set_user_style_knobs,
    is_style_learning_master_enabled,
    set_style_learning_master_enabled,
    get_style_learning_capture_interval_hours,
    set_style_learning_capture_interval_hours,
    get_style_learning_mine_limit_default,
    set_style_learning_mine_limit_default,
    resolve_account_mine_limit,
    is_style_learning_account_enabled,
    _rag_sent_index_key,
    is_rag_sent_index_enabled,
    set_rag_sent_index_enabled,
    _style_knobs_hipaa_allow_key,
    is_style_knobs_hipaa_allow,
    set_style_knobs_hipaa_allow,
    is_hipaa_style_distill_enabled,
    set_hipaa_style_distill_enabled,
    get_hipaa_style_descriptor,
    set_hipaa_style_descriptor,
    delete_hipaa_style_descriptor,
    record_style_distill_event,
    style_distill_event_counts,
    list_style_distill_events,
    _style_distill_compute_next_retry,
    enqueue_style_distill_retry,
    pause_style_distill_account,
    unpause_style_distill_account,
    unpause_baa_paused_style_distill_accounts,
    unpause_scrubber_fail_style_distill_accounts,
    clear_style_distill_queue_entry,
    get_style_distill_queue_entry,
    list_paused_style_distill_accounts,
    claim_next_style_distill_queue_entry,
    get_per_contact_style_hipaa,
    set_per_contact_style_hipaa,
    delete_per_contact_style_hipaa,
    delete_all_per_contact_style_hipaa,
    list_per_contact_style_hipaa_for_account,
    gc_per_contact_style_hipaa,
    enqueue_style_distill_contact_retry,
    pause_style_distill_contact,
    unpause_style_distill_contact,
    unpause_baa_paused_style_distill_contacts,
    unpause_scrubber_fail_style_distill_contacts,
    clear_style_distill_contact_queue_entry,
    get_style_distill_contact_queue_entry,
    list_paused_style_distill_contacts,
    claim_next_style_distill_contact_queue_entry,
    last_successful_style_distill_at,
    get_global_anti_ai_style_guide,
    set_global_anti_ai_style_guide,
    get_user_anti_ai_style_guide,
    set_user_anti_ai_style_guide,
    get_sent_mail_index_summary,
    get_captured_pair_count,
    delete_sent_mail_index_for_account,
    is_style_learning_per_contact_enabled,
    STYLE_KNOB_DEFAULTS,
    STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS,
    STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS,
    STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS,
    STYLE_LEARNING_MINE_LIMIT_MIN,
    STYLE_LEARNING_MINE_LIMIT_MAX,
    STYLE_LEARNING_MINE_LIMIT_DEFAULT,
    STYLE_LEARNING_HIPAA_DISTILL_ENABLED,
    HIPAA_PER_CONTACT_GC_DAYS,
)
