"""Shared SQLite schema for the email triage system.

Manages all tables: flows (via FlowStore), users, classification lists,
list rules, OTP codes, and API keys.  Provides a single ``init_db`` entry
point that idempotently creates every table and index.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

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
#   "login_webauthn"     -- per-user FIDO2 hardware key.
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

_LOG_ENTRIES_DDL = """\
CREATE TABLE IF NOT EXISTS log_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    level      TEXT NOT NULL,
    logger     TEXT NOT NULL DEFAULT '',
    message    TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    prev_hash  TEXT NOT NULL DEFAULT '',
    row_hash   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_log_entries_ts ON log_entries(ts);
CREATE INDEX IF NOT EXISTS idx_log_entries_level ON log_entries(level);
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

_GMAIL_WATCHES_DDL = """\
CREATE TABLE IF NOT EXISTS gmail_watches (
    account_id    INTEGER PRIMARY KEY REFERENCES email_accounts(id) ON DELETE CASCADE,
    email_address TEXT NOT NULL,
    topic_name    TEXT NOT NULL,
    history_id    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gmail_watches_email ON gmail_watches(email_address);
CREATE INDEX IF NOT EXISTS idx_gmail_watches_expires ON gmail_watches(expires_at);
"""

# #50 — per-account delegation. Lets the account owner (or an admin)
# grant a non-admin user the right to manage a specific account
# (routes, watcher, folder prefs, digest schedules, run-triage).
# Restricted out of delegate scope: HIPAA flag flip + account
# deletion (owner / admin only — those are blast-radius operations
# that should stay with the responsible party).
#
# Audit: delegate add / remove emit INFO log lines via the standard
# logger; the ASGI access-audit middleware (#41) covers the broader
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

# #41 — generic access-audit log (HIPAA §164.312(b)). Sibling of
# hipaa_access_events but covers every authenticated PHI-surface
# request, not only triage-pipeline writes. The middleware in
# web/app.py records here on every request whose path matches a
# PHI-touch prefix (/classify, /triage/run, /accounts/<id>/{messages,
# digest, folders, discover, bulk}, /api/openclaw, /runs/<id>).
#
# No PHI is persisted: route + method + status + actor are stamped;
# the request body is never logged. account_id and message_id are
# extracted from the URL path when present so the auditor can answer
# "who looked at this account / message, and when?" without scraping
# the path themselves.
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

# #67 — admin-managed dev-keypair table. Per-key TTL + per-email
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

# #67 — WebAuthn / FIDO2 hardware-key registrations. credential_id is
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

# #67 — short-lived ceremony challenges for WebAuthn register +
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

# #67 — ACME renewal log. One row per renewal attempt (success or
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
]


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Return True if `table.column` exists — used for idempotent ALTER TABLEs."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


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
    # #42 — log_entries hash-chain columns. Existing rows get empty
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
    conn.execute("""
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
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discover_runs_acct ON discover_runs(account_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discover_runs_created ON discover_runs(created_at);")

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

    # #67: WebAuthn per-user handle. Server-assigned 16-64 byte stable
    # identifier; populated lazily on first hardware-key registration.
    if not _column_exists(conn, "users", "webauthn_user_handle"):
        conn.execute(
            "ALTER TABLE users ADD COLUMN webauthn_user_handle BLOB"
        )

    # #67: access_log gains auth_source + auth_key_id so every audit
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

    conn.commit()


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
            cfg = json.loads(row["config_json"] or "{}")
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
                (json.dumps(cfg), row["id"]),
            )
            any_scrubbed = True
    if any_scrubbed:
        conn.commit()
    return found


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
            cfg = json.loads(row["config_json"] or "{}")
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
                cfg = json.loads(row["config_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            tid = cfg.get("tenant_id", "")
            if tid:
                chosen_tenant = tid
                break

    # Secret comes from the secrets store, not config_json.
    if secrets is not None:
        for row in rows:
            sk = f"ACCOUNT_{row['id']}_O365_SECRET"
            try:
                v = secrets.get(sk) or ""
            except Exception:
                v = ""
            if v:
                chosen_csec = v
                break

    # Second pass: scrub stale keys + set is_personal_msa where
    # tenant_id == "common".
    for row in rows:
        try:
            cfg = json.loads(row["config_json"] or "{}")
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
            (json.dumps(cfg), row["id"]),
        )
        any_scrubbed = True

    if any_scrubbed:
        conn.commit()

    if not (chosen_tenant or chosen_cid or chosen_csec):
        return None
    return (chosen_tenant, chosen_cid, chosen_csec)


def scrub_queue_summary_from_routes(conn: sqlite3.Connection) -> int:
    """Strip the deprecated `queue_summary` action from saved routes.

    Called from init_db on every startup. The queue_summary action was
    removed in favour of the digest pipeline. Existing route configs
    that reference it would otherwise raise "unknown action" at triage
    time. Idempotent — runs cheaply when nothing matches.

    Returns the number of route rows that were updated.
    """
    rows = conn.execute(
        "SELECT id, actions_json FROM account_routes "
        "WHERE actions_json LIKE '%queue_summary%'"
    ).fetchall()
    updated = 0
    for row in rows:
        try:
            actions = json.loads(row["actions_json"]) or []
        except Exception:
            continue
        kept = [a for a in actions if (a or {}).get("action") != "queue_summary"]
        if len(kept) == len(actions):
            continue
        conn.execute(
            "UPDATE account_routes SET actions_json = ?, "
            "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (json.dumps(kept), row["id"]),
        )
        updated += 1
    if updated:
        conn.commit()
    return updated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path: str | Path = ":memory:") -> sqlite3.Connection:
    """Open (or create) the database and ensure all tables exist.

    Returns a connection with WAL mode and foreign keys enabled.
    Uses ``check_same_thread=False`` because FastAPI serves requests
    in a threadpool while the connection is created at startup.
    This is safe because the system is single-writer by design.
    """
    # Drop the in-process settings cache (#140.2) — a fresh DB
    # invalidates any cached read by definition. Production calls
    # init_db once at startup; tests call it per fixture and need
    # the cache cleared so cross-test reuse doesn't leak entries.
    invalidate_setting_cache()

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    for ddl in _ALL_DDL:
        conn.executescript(ddl)

    # Apply idempotent ALTER-TABLE migrations for upgraded DBs.
    _apply_migrations(conn)

    # Per-user categories migration + index creation (#62). Must run
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

    return conn


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------

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
    col_names = {c["name"] if isinstance(c, sqlite3.Row) else c[1] for c in cols}
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


def seed_categories(conn: sqlite3.Connection, categories: dict[str, str]) -> int:
    """Seed categories from config if the table is empty.

    Called at startup so YAML categories bootstrap the database on first run.
    Returns the number of categories seeded (0 if table already had data).
    """
    row = conn.execute("SELECT COUNT(*) AS cnt FROM categories").fetchone()
    if row["cnt"] > 0:
        return 0

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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


def ensure_upgrade_categories(conn: sqlite3.Connection) -> int:
    """Insert any ``_UPGRADE_CATEGORIES`` rows that are missing.

    No-op when every slug is already present. Returns the number of
    rows actually inserted. Called from the web app's startup lifespan
    after ``seed_categories`` so existing installs gain new system
    categories without losing user-added ones.
    """
    from datetime import datetime, timezone
    rows = conn.execute("SELECT slug FROM categories").fetchall()
    existing = {r["slug"] for r in rows}
    if not (set(_UPGRADE_CATEGORIES) - existing):
        return 0

    # Sort_order: append after the highest existing.
    max_row = conn.execute(
        "SELECT COALESCE(MAX(sort_order), 0) AS m FROM categories"
    ).fetchone()
    next_sort = int(max_row["m"]) + 1 if max_row else 0

    now = datetime.now(timezone.utc).isoformat()
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
    return [dict(r) for r in rows]


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

    result: dict[str, str] = {}
    sys_rows = conn.execute(
        "SELECT slug, description FROM categories "
        "WHERE user_id IS NULL ORDER BY sort_order, id"
    ).fetchall()
    for r in sys_rows:
        result[r["slug"]] = r["description"]
    user_rows = conn.execute(
        "SELECT slug, description FROM categories "
        "WHERE user_id = ? ORDER BY sort_order, id",
        (user_id,),
    ).fetchall()
    for r in user_rows:
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
    return dict(row) if row else None


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
    from datetime import datetime, timezone
    if user_id is not None:
        if count_personal_categories(conn, user_id) >= MAX_PERSONAL_CATEGORIES_PER_USER:
            raise ValueError(
                f"Personal category limit reached "
                f"({MAX_PERSONAL_CATEGORIES_PER_USER} per user). "
                f"Delete an unused category first."
            )
    now = datetime.now(timezone.utc).isoformat()
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


def update_category(conn: sqlite3.Connection, category_id: int, slug: str, description: str) -> bool:
    """Update a category. Returns True if updated."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE categories SET slug = ?, description = ?, updated_at = ? WHERE id = ?",
        (slug, description, now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def delete_category(conn: sqlite3.Connection, category_id: int) -> bool:
    """Delete a category. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    return cursor.rowcount > 0


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE categories SET user_id = NULL, updated_at = ? WHERE id = ?",
        (now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE categories SET user_id = ?, updated_at = ? WHERE id = ?",
        (target_user_id, now, category_id),
    )
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Settings helpers (key-value store)
#
# Architecture (#140.1 + #140.2):
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
# * **Corrupt-row defensive** (#140.1): ``get_setting`` wraps
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


def invalidate_setting_cache(key: str | None = None) -> None:
    """Drop a cached setting entry (or the entire cache when ``key`` is None).

    Called by :func:`set_setting` / :func:`delete_setting` automatically.
    Exposed so the audit-chain anchor in ``triage_logging`` (which
    UPSERTs the settings row inside its own transaction) and any future
    in-tree direct writer can keep the cache coherent.
    """
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
    cached = _settings_cache.get(key)
    if cached is not None:
        value, expires_at = cached
        if _time.monotonic() < expires_at:
            return value
        # Expired — fall through to re-read.
        _settings_cache.pop(key, None)

    row = conn.execute(
        "SELECT value_json FROM settings WHERE key = ?", (key,),
    ).fetchone()
    if row is None:
        # Negative cache: avoid re-querying for missing keys inside the
        # TTL window. The cache invalidates on set_setting, so a later
        # write becomes visible.
        if _SETTINGS_CACHE_TTL_SECONDS > 0:
            _settings_cache[key] = (None, _time.monotonic() + _SETTINGS_CACHE_TTL_SECONDS)
        return None

    try:
        value = json.loads(row["value_json"])
    except json.JSONDecodeError as exc:
        # #140.1 — defensive on corrupt JSON. Log key only (value is
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
        _settings_cache[key] = (value, _time.monotonic() + _SETTINGS_CACHE_TTL_SECONDS)
    return value


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    """Set a setting (upsert) and invalidate the in-process cache."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (key, json.dumps(value), now),
    )
    conn.commit()
    invalidate_setting_cache(key)


def delete_setting(conn: sqlite3.Connection, key: str) -> bool:
    """Delete a setting. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    conn.commit()
    invalidate_setting_cache(key)
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Bool-setting convenience helpers (#145.7)
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
    # #140.3 — registry-backed, but keep the helper for backwards-compat
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

def get_mailbox_route_overrides(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str,
) -> list[dict]:
    """#51 — per-(account, mailbox) route overrides.

    Stored under the settings key ``mailbox_routes:<account_id>:<mailbox>``
    as a JSON list of ``{category, actions: [...]}`` rows. Returns an
    empty list when no overrides exist for that mailbox (caller should
    then fall back to the account-wide ``account_routes`` table).
    """
    raw = get_setting(conn, f"mailbox_routes:{account_id}:{mailbox}")
    if not isinstance(raw, list):
        return []
    return [r for r in raw if isinstance(r, dict)]


def set_mailbox_route_overrides(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str,
    routes: list[dict],
) -> None:
    """Persist per-(account, mailbox) route overrides. Pass an empty
    list to clear all overrides for that mailbox."""
    key = f"mailbox_routes:{account_id}:{mailbox}"
    if not routes:
        # Empty -> drop the row so the account-wide fallback kicks in
        # cleanly without a stub override. delete_setting() invalidates
        # the in-process cache (#140.2).
        delete_setting(conn, key)
        return
    set_setting(conn, key, routes)


def effective_routes_by_cat(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str | None = None,
) -> dict[str, list[dict]]:
    """Return ``{category: actions}`` for the given mailbox.

    Per-mailbox overrides (if any) layer on top of the account-wide
    ``account_routes`` table. Per-category granularity: a mailbox can
    override one category and inherit the rest. Pass ``mailbox=None``
    (or a mailbox with no overrides) to get the legacy account-wide
    map unchanged.
    """
    base = {
        r["category"]: r["actions"]
        for r in list_account_routes(conn, account_id)
    }
    if not mailbox:
        return base
    overrides = get_mailbox_route_overrides(conn, account_id, mailbox)
    for r in overrides:
        cat = r.get("category")
        if not cat:
            continue
        actions = r.get("actions") or []
        if isinstance(actions, list):
            base[cat] = actions
    return base


def _account_mailboxes(cfg: dict) -> list[str]:
    """Return the effective list of mailboxes for an IMAP account config.

    Applies the legacy-compat shim then validates: must be a non-empty
    list of non-empty strings. Falls back to ``["INBOX"]`` for any shape
    that would otherwise leave us with nothing to watch.
    """
    if not isinstance(cfg, dict):
        return ["INBOX"]
    mbs = cfg.get("mailboxes")
    if isinstance(mbs, list):
        valid = [m for m in mbs if isinstance(m, str) and m.strip()]
        if valid:
            return valid
    legacy = cfg.get("mailbox")
    if isinstance(legacy, str) and legacy.strip():
        return [legacy]
    return ["INBOX"]


def _apply_account_config_back_compat(cfg: dict) -> dict:
    """Read-side shim: fill in ``mailboxes`` for legacy single-mailbox configs.

    Older configs stored one folder as ``mailbox`` (str). The current
    canonical shape is ``mailboxes`` (list[str]). We leave the legacy
    ``mailbox`` key alone when present so any lingering readers of the
    old key keep working; we only ADD ``mailboxes`` alongside it.

    Idempotent — safe to call on already-migrated configs.
    """
    if not isinstance(cfg, dict):
        return cfg
    if "mailboxes" not in cfg and "mailbox" in cfg:
        legacy = cfg.get("mailbox")
        if isinstance(legacy, str) and legacy:
            cfg["mailboxes"] = [legacy]
        else:
            cfg["mailboxes"] = ["INBOX"]
    return cfg


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

INGESTION_POLL_MIN = 10
INGESTION_POLL_MAX = 240
INGESTION_POLL_STEP = 10
INGESTION_POLL_DEFAULT = 60


def clamp_poll_interval_minutes(value: int) -> int:
    """Clamp a poll interval to [POLL_MIN, POLL_MAX] and snap to step 10.

    Shared by the save handler, the back-compat shim, and any test that
    needs to normalise an interval — keeps the "what's a valid cadence"
    answer in one place.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return INGESTION_POLL_DEFAULT
    v = max(INGESTION_POLL_MIN, min(INGESTION_POLL_MAX, v))
    # Snap to nearest step.
    v = INGESTION_POLL_MIN + round(
        (v - INGESTION_POLL_MIN) / INGESTION_POLL_STEP
    ) * INGESTION_POLL_STEP
    return max(INGESTION_POLL_MIN, min(INGESTION_POLL_MAX, v))


def apply_ingestion_back_compat(
    conn: sqlite3.Connection,
    account_id: int,
    provider_type: str,
    cfg: dict,
    default_minutes: int = INGESTION_POLL_DEFAULT,
) -> dict:
    """Materialise ``push_enabled`` / ``poll_enabled`` / ``poll_interval_minutes``
    onto ``cfg`` if any are missing.

    Back-compat rules:
      * ``push_enabled``: mirror legacy ``watch:{id}`` setting for IMAP
        accounts (True when setting is enabled, False when missing or
        disabled). For Gmail, True when an active gmail_watches row
        exists (non-empty topic + unexpired). For other providers,
        default to True (push_enabled is "start the provider's push
        mechanism" — the WatcherManager decides whether to act).
      * ``poll_enabled``: ALWAYS True for legacy accounts — dormant
        accounts start getting 60-min polls. Operators can opt out via
        the edit form.
      * ``poll_interval_minutes``: carry forward the B3-era
        ``poll_interval_override`` if set; otherwise use
        ``default_minutes``. Always clamped + step-snapped.

    Mutates and returns ``cfg``. Safe to call on already-migrated configs
    (keys already present are left alone).

    #134.2 — fast-path: when ``push_enabled``, ``poll_enabled``, AND
    ``poll_interval_minutes`` are already present in ``cfg``, skip the
    legacy ``settings``/``gmail_watches`` lookups entirely. Migrated rows
    (the common case for new accounts created post-B3) take this path and
    avoid 1-2 DB round-trips per account on every ``list_email_accounts``
    fold.
    """
    if not isinstance(cfg, dict):
        return cfg

    # Fast path: already migrated, nothing to back-fill. Per-account
    # ``list_email_accounts`` calls inside loops (digest scheduler,
    # poll loop) used to issue a settings + gmail_watches SELECT for
    # every row even when the cfg was already complete; this short-circuit
    # eliminates that noise.
    if (
        "push_enabled" in cfg
        and "poll_enabled" in cfg
        and "poll_interval_minutes" in cfg
    ):
        # Defensive: still clamp the interval in case of out-of-band edit.
        cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
            cfg["poll_interval_minutes"],
        )
        return cfg

    import json as _json

    # poll_interval_minutes
    if "poll_interval_minutes" not in cfg:
        raw = cfg.get("poll_interval_override")
        if isinstance(raw, int):
            cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(raw)
        else:
            cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
                default_minutes,
            )
    else:
        # Normalise in case someone hand-edited config_json out of band.
        cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
            cfg.get("poll_interval_minutes", default_minutes),
        )

    # poll_enabled — default True for every provider (legacy or fresh).
    if "poll_enabled" not in cfg:
        cfg["poll_enabled"] = True

    # push_enabled — provider-specific inference.
    # #138 phase 2 — table-driven dispatch via ProviderDispatcher.
    # Each ptype's ``infer_push_enabled`` reads its own state row
    # (settings ``watch:<id>`` for IMAP, ``gmail_watches`` for Gmail,
    # default-only for O365 until Graph wiring lands).
    if "push_enabled" not in cfg:
        from email_triage.providers.dispatcher import get_dispatch
        disp = get_dispatch(provider_type)
        if disp is None:
            cfg["push_enabled"] = True
        else:
            cfg["push_enabled"] = disp.infer_push_enabled(
                conn, account_id, default=True,
            )

    return cfg


def account_email(acct: dict | None) -> str:
    """Resolve the operator-facing email address for an account.

    Different provider types store the address under different keys:

    - **Gmail (native)** stores it as ``config["account"]``
      (the Google account selected via OAuth).
    - **Office 365 (Graph)** stores it as ``config["account"]``
      (the AAD identity from MSAL).
    - **IMAP** prefers ``config["email_address"]`` (operator-set
      on the account edit page, shipped 2026-05-13 after operator
      hit the alias-mode bug where IMAP LOGIN usernames like
      ``you`` collide with actual addresses like
      ``you@example.com`` — Dovecot allows bare usernames +
      a server-side default domain, so the LOGIN value isn't the
      email). Falls back to ``config["username"]`` for older
      accounts where the operator hasn't filled in the new field
      yet — many IMAP installs do use the full address as the
      LOGIN, so the legacy fallback stays correct for them.

    Returns the first non-empty hit in priority order, or "" when
    neither is set (account not yet saved). Single source of truth
    for every read site; the alternative (each caller open-coding
    the fallback) shipped silent gaps — see the "Send digest now
    (test)" bug 2026-05-05 where the digest-test handler only read
    ``config["account"]`` and rejected every IMAP account as
    "no email address".
    """
    if not acct:
        return ""
    cfg = acct.get("config") or {}
    addr = (cfg.get("account") or "").strip()
    if addr:
        return addr
    email_addr = (cfg.get("email_address") or "").strip()
    if email_addr:
        return email_addr
    return (cfg.get("username") or "").strip()


def account_aliases(acct: dict | None) -> list[dict]:
    """Return the list of additional addresses configured for an account.

    Each entry is ``{"address": "...", "label": "..."}``. Stored as
    ``email_accounts.aliases_json`` (JSON list, default ``[]``) and
    surfaced on the read path by ``list_email_accounts`` /
    ``get_email_account``. The primary address (``account_email``)
    is NOT in this list — it's tracked separately in the provider
    config. Use ``account_addresses`` when you want the union.

    Returns an empty list on a missing or malformed value rather
    than raising; the storage column is parsed once on read so
    callers can treat the result as authoritative.
    """
    if not acct:
        return []
    raw = acct.get("aliases") or []
    if isinstance(raw, list):
        out: list[dict] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            addr = str(entry.get("address") or "").strip().lower()
            if not addr:
                continue
            label = str(entry.get("label") or "").strip()
            out.append({"address": addr, "label": label})
        return out
    return []


def account_addresses(acct: dict | None) -> set[str]:
    """Return the full set of addresses that route to this account.

    Union of the resolved primary address (``account_email``) and any
    additional addresses configured under ``aliases_json`` (#106's
    schema-backed storage) PLUS legacy ``config["aliases"]`` strings
    (#107's pre-merge format — tolerated for back-compat with any
    operator who set them via the older path). All values normalized
    to lowercase + stripped so callers can compare with a normalized
    incoming ``to_addr`` directly.

    The primary is implicit-included; alias UI / save paths reject
    storing the primary as an alias to keep the union de-duplicated
    by construction. An account with no primary yet (fresh row, never
    saved) yields just the alias addresses (or the empty set if none).

    Used by:
      - HIPAA recipient-mismatch guard (#106 + web/app.py)
      - Recipient-digest collector (alias mail flows under parent acct)
      - Triage-runner self-match (#107 self-sent event)
    """
    if not acct:
        return set()
    out: set[str] = set()
    primary = account_email(acct).strip().lower()
    if primary:
        out.add(primary)
    # #106 canonical path — JSON-array column.
    for entry in account_aliases(acct):
        addr = entry.get("address", "")
        if addr:
            out.add(addr)
    # Legacy / pre-merge fallback: config["aliases"] as list[str] or
    # comma-separated string. Kept so any account configured via the
    # #107 ad-hoc path during the parallel-build window still routes
    # correctly. Future cleanup can drop this once the operator
    # confirms zero rows use the legacy shape.
    cfg = acct.get("config") or {}
    raw = cfg.get("aliases")
    if isinstance(raw, list):
        candidates = [str(x or "") for x in raw]
    elif isinstance(raw, str):
        candidates = []
        for chunk in raw.replace("\n", ",").replace(";", ",").split(","):
            candidates.append(chunk)
    else:
        candidates = []
    for c in candidates:
        addr = c.strip().lower()
        if addr and "@" in addr:
            out.add(addr)
    return out


def list_email_accounts(
    conn: sqlite3.Connection,
    user_id: int | None = None,
    include_delegated: bool = True,
) -> list[dict]:
    """List email accounts. If user_id is None, returns all (admin view).

    With ``user_id`` set:
    * Returns accounts where this user is the owner.
    * Plus accounts where this user is a delegate (#50) — unless
      ``include_delegated=False`` (legacy callers that genuinely
      want owner-only).

    Each row includes ``is_delegate`` (False for owner-of, True
    when surfaced via the delegates JOIN) so the UI can chip
    appropriately.
    """
    import json
    if user_id is not None:
        # Owner rows.
        owner_rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "WHERE ea.user_id = ? ORDER BY ea.id",
            (user_id,),
        ).fetchall()
        rows = list(owner_rows)
        if include_delegated:
            delegate_rows = conn.execute(
                "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
                "       1 AS is_delegate "
                "FROM email_accounts ea "
                "JOIN users u ON ea.user_id = u.id "
                "JOIN account_delegates ad ON ad.account_id = ea.id "
                "WHERE ad.user_id = ? AND ea.user_id != ? "
                "ORDER BY ea.id",
                (user_id, user_id),
            ).fetchall()
            rows.extend(delegate_rows)
    else:
        rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "ORDER BY u.email, ea.id",
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        cfg = _apply_account_config_back_compat(
            json.loads(d.pop("config_json", "{}")),
        )
        cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
        d["config"] = cfg
        # Parse the alias list once on read. Stored as a JSON array of
        # ``{"address","label"}`` dicts; malformed values fall back to
        # an empty list so a corrupt row doesn't blow up the whole
        # /accounts page render. Pre-aliases-column rows (legacy DBs
        # before v10) surface as missing keys in the dict_factory
        # output — also coerce to empty list.
        raw_aliases = d.pop("aliases_json", "[]") or "[]"
        try:
            parsed_aliases = json.loads(raw_aliases)
        except (TypeError, ValueError):
            parsed_aliases = []
        if not isinstance(parsed_aliases, list):
            parsed_aliases = []
        d["aliases"] = parsed_aliases
        # Synthesize the resolved email address up-front so callers
        # don't have to know the per-provider field-name dance. See
        # ``account_email`` for the resolution rules.
        d["email_address"] = account_email(d)
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# Per-account delegation (#50)
# ---------------------------------------------------------------------------

def add_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
    granted_by: int | None,
) -> bool:
    """Grant a user delegate access to an account. Idempotent: returns
    True on first add, False if the row already exists. Raises ValueError
    if user_id == account_owner (owner is not a delegate of their own
    account)."""
    from datetime import datetime, timezone
    owner = conn.execute(
        "SELECT user_id FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    if owner is None:
        raise ValueError(f"Account {account_id} not found")
    if owner["user_id"] == user_id:
        raise ValueError(
            "Owner cannot be added as a delegate of their own account"
        )
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT OR IGNORE INTO account_delegates "
        "(account_id, user_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
        (account_id, user_id, granted_by, now),
    )
    conn.commit()
    return cur.rowcount > 0


def remove_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
) -> bool:
    """Revoke delegate access. Returns True if a row was removed."""
    cur = conn.execute(
        "DELETE FROM account_delegates "
        "WHERE account_id = ? AND user_id = ?",
        (account_id, user_id),
    )
    conn.commit()
    return cur.rowcount > 0


def list_account_delegates(
    conn: sqlite3.Connection,
    account_id: int,
) -> list[dict]:
    """Return delegates for ``account_id`` as ``[{user_id, email, name,
    granted_by, granted_by_email, granted_at}, ...]`` ordered by grant
    time."""
    rows = conn.execute(
        "SELECT ad.user_id, u.email, u.name, "
        "       ad.granted_by, "
        "       gu.email AS granted_by_email, "
        "       ad.granted_at "
        "FROM account_delegates ad "
        "JOIN users u ON u.id = ad.user_id "
        "LEFT JOIN users gu ON gu.id = ad.granted_by "
        "WHERE ad.account_id = ? "
        "ORDER BY ad.granted_at",
        (account_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def is_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
) -> bool:
    """True if ``user_id`` has delegate access to ``account_id``."""
    row = conn.execute(
        "SELECT 1 FROM account_delegates "
        "WHERE account_id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()
    return row is not None


def can_manage_account(
    conn: sqlite3.Connection,
    user: dict | None,
    acct: dict | None,
) -> bool:
    """Authz gate for per-account operations. True when:

    * ``user`` has admin role, OR
    * ``user`` is the account owner, OR
    * ``user`` has a delegate row for this account.

    Sensitive operations (HIPAA flag flip, account deletion) bypass
    this and check admin/owner directly — delegates intentionally
    cannot escalate or destroy the account.
    """
    if not user or not acct:
        return False
    if user.get("role") == "admin":
        return True
    if acct.get("user_id") == user.get("id"):
        return True
    return is_account_delegate(conn, acct["id"], user["id"])


def get_email_account(conn: sqlite3.Connection, account_id: int) -> dict | None:
    """Get a single email account by ID."""
    import json
    row = conn.execute(
        "SELECT ea.*, u.email AS owner_email, u.name AS owner_name "
        "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
        "WHERE ea.id = ?",
        (account_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    cfg = _apply_account_config_back_compat(
        json.loads(d.pop("config_json", "{}")),
    )
    cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
    d["config"] = cfg
    raw_aliases = d.pop("aliases_json", "[]") or "[]"
    try:
        parsed_aliases = json.loads(raw_aliases)
    except (TypeError, ValueError):
        parsed_aliases = []
    if not isinstance(parsed_aliases, list):
        parsed_aliases = []
    d["aliases"] = parsed_aliases
    d["email_address"] = account_email(d)
    return d


def create_email_account(
    conn: sqlite3.Connection,
    user_id: int,
    name: str,
    provider_type: str,
    config: dict,
    hipaa: bool | None = None,
    is_active: bool = True,
) -> int:
    """Create an email account. Returns the new ID.

    If ``hipaa`` is None (the default), the per-account flag is inferred
    from the current system HIPAA state — if system HIPAA is ON the
    account is auto-flagged and ``created_under_system_hipaa`` is set
    so the flag cannot be unset until system HIPAA is later turned off
    ("sticky inheritance").  An explicit ``hipaa`` value from the
    caller overrides the inference.

    ``is_active`` defaults to True for full-form callers (manual-add
    POST /accounts where every credential lands in one submit). The
    new-account wizard's step-1 handler passes ``is_active=False`` so
    the half-configured stub (empty ``config``) does not get polled
    by background watchers / pollers / triage workers until the wizard
    finishes (item #120). Step-5 submit flips to True via
    ``set_account_active``. Background pollers already gate on
    ``is_active`` (six call sites in app.py + ui.py), so flipping the
    flag suppresses the "missing credentials" error spam that triggered
    Nagios alerts on the homelab monitoring path.
    """
    import json
    from datetime import datetime, timezone
    from email_triage.triage_logging import is_hipaa_mode
    now = datetime.now(timezone.utc).isoformat()
    system_hipaa = is_hipaa_mode()
    if hipaa is None:
        hipaa = system_hipaa
    created_under = 1 if system_hipaa else 0
    cursor = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        " created_under_system_hipaa, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, provider_type, json.dumps(config),
         int(bool(hipaa)), created_under, int(bool(is_active)),
         now, now),
    )
    conn.commit()
    return cursor.lastrowid


def set_account_active(
    conn: sqlite3.Connection,
    account_id: int,
    active: bool,
) -> bool:
    """Flip ``is_active`` without touching name / provider_type / config.

    Used by the wizard's step-5 finish handler to enable an account
    that was created in the disabled state at step 1 (item #120).
    Also useful for an admin "pause this account" surface that we
    might add later.

    Returns True when a row was updated.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET is_active = ?, updated_at = ? "
        "WHERE id = ?",
        (int(bool(active)), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def set_account_hipaa(
    conn: sqlite3.Connection,
    account_id: int,
    hipaa: bool,
    actor_id: int | None = None,
    reason: str = "",
) -> dict:
    """Flip an account's HIPAA flag and record the boundary event.

    Enforces the lock rule: if the account was created while system
    HIPAA was on AND system HIPAA is still on, the flag cannot be
    turned off.  Raises ``PermissionError`` in that case.  The flip
    and the boundary-event write happen in a single transaction.

    Returns the refreshed account dict.
    """
    from email_triage.triage_logging import is_hipaa_mode, is_account_hipaa_locked
    acct = get_email_account(conn, account_id)
    if acct is None:
        raise ValueError(f"Account {account_id} not found")

    # No-op: flag already in the requested state.
    current = bool(acct.get("hipaa", False))
    if current == bool(hipaa):
        return acct

    # Lock enforcement.
    if not hipaa and is_account_hipaa_locked(acct):
        raise PermissionError(
            "Cannot unset HIPAA flag while system HIPAA mode is active "
            "for an account that was created under system HIPAA."
        )

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    direction = "on" if hipaa else "off"
    scope = f"account:{account_id}"
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE email_accounts SET hipaa = ?, updated_at = ? WHERE id = ?",
            (int(bool(hipaa)), now, account_id),
        )
        conn.execute(
            "INSERT INTO hipaa_boundary_events "
            "(ts, scope, direction, actor_id, reason) VALUES (?, ?, ?, ?, ?)",
            (now, scope, direction, actor_id, reason),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return get_email_account(conn, account_id)


def update_email_account(
    conn: sqlite3.Connection,
    account_id: int,
    name: str,
    provider_type: str,
    config: dict,
    is_active: bool = True,
) -> bool:
    """Update an email account. Returns True if updated."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET name = ?, provider_type = ?, config_json = ?, "
        "is_active = ?, updated_at = ? WHERE id = ?",
        (name, provider_type, json.dumps(config), int(is_active), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def update_email_account_config(
    conn: sqlite3.Connection, account_id: int, config: dict,
) -> bool:
    """Patch the config_json for an account without touching the other
    columns. Used by the history-poll loop to clear a
    ``poll_interval_override`` on push↔poll transitions."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET config_json = ?, updated_at = ? WHERE id = ?",
        (json.dumps(config), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def update_account_config_keys(
    conn: sqlite3.Connection,
    account_id: int,
    /,
    **patches: Any,
) -> bool:
    """Read-modify-write a subset of an account's ``config_json`` keys
    atomically.

    Replaces the 7-site idiom::

        config = dict(acct.get("config") or {})
        config[k] = v
        update_email_account_config(db, aid, config)

    The read-modify-write happens inside a single ``BEGIN IMMEDIATE``
    transaction so a concurrent writer cannot clobber an unrelated
    key between the read and the write — the pre-fix idiom hit this
    on the calendar-surrogate save vs the digest-schedule save when
    both arrive in the same second. Other config keys not named in
    ``patches`` are preserved verbatim.

    Patches with value ``None`` mean "delete the key" (the operator
    is clearing a setting). Patches with any other value overwrite.

    Emits a single structured INFO log per call listing the keys
    that changed (audit signal — operators reviewing config drift
    can see which knob moved without enabling row-level audit). The
    log line does NOT include values, since some config knobs (e.g.
    ``imap.host``) may pin to operator-identifying infrastructure;
    the keys-only shape is the conservative-safe surface.

    Returns
    -------
    bool
        True when the row was found and updated; False when
        ``account_id`` does not exist.
    """
    import json
    from datetime import datetime, timezone

    # BEGIN IMMEDIATE acquires the write lock up front so a concurrent
    # reader-then-writer can't slot in between our SELECT and UPDATE.
    # SQLite's default deferred mode would hit "database is locked"
    # under contention but only after the SELECT — too late. We fold
    # the read + write into one transaction explicitly.
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return False
        try:
            current = json.loads(row[0] or "{}")
        except (TypeError, ValueError):
            current = {}
        if not isinstance(current, dict):
            current = {}

        merged = dict(current)
        changed_keys: list[str] = []
        for key, value in patches.items():
            if value is None:
                if key in merged:
                    merged.pop(key, None)
                    changed_keys.append(key)
            else:
                if merged.get(key) != value:
                    merged[key] = value
                    changed_keys.append(key)

        if not changed_keys:
            conn.execute("ROLLBACK")
            return True  # No-op write — row exists, nothing to change.

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE email_accounts "
            "SET config_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(merged), now, account_id),
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise

    # Structured-log emission AFTER the commit so a log failure
    # cannot orphan a successful write. owner + account_name surface
    # per ``feedback_no_account_id_alone.md`` — the numeric account_id
    # is a tiebreaker only; logs use the human-readable owner +
    # account_name as the primary key.
    try:
        meta = conn.execute(
            "SELECT ea.name AS account_name, "
            "       u.email AS owner, u.name AS owner_name "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "WHERE ea.id = ?",
            (account_id,),
        ).fetchone()
        import logging
        logger = logging.getLogger("email_triage.web.db")
        log_extra: dict[str, Any] = {"account_id": account_id}
        if meta is not None:
            d = dict(meta)
            if d.get("owner_name"):
                log_extra["owner"] = d["owner_name"]
            elif d.get("owner"):
                log_extra["owner"] = d["owner"]
            if d.get("account_name"):
                log_extra["account_name"] = d["account_name"]
        log_extra["changed_keys"] = sorted(changed_keys)
        logger.info(
            "Account config keys updated",
            extra={"_extra": log_extra},
        )
    except Exception:
        # Log emission must never sink the call — the write already
        # landed. Best-effort only.
        pass
    return True


class AliasValidationError(ValueError):
    """Raised when a proposed alias list violates the storage contract.

    Constructor takes a single human-readable reason that's safe to
    surface to the operator (the UI just renders this string verbatim
    above the alias form).
    """


def _looks_like_email(addr: str) -> bool:
    """Lightweight RFC-shaped check used by the alias validator.

    Intentionally conservative: requires an ``@`` plus at least one
    dot in the host part. Doesn't try to validate the local part —
    real RFC 5322 grammar is too permissive to be useful as a UI
    gate, and we already let the SMTP / IMAP layer reject impossible
    addresses at the actual-use point.
    """
    s = (addr or "").strip()
    if "@" not in s:
        return False
    host = s.split("@")[-1]
    return "." in host and len(host) > 2


def normalize_aliases(
    raw: list[dict],
    *,
    primary: str = "",
) -> list[dict]:
    """Validate + normalize an alias list before write.

    Rules:
    * Each entry must be a dict with at least an ``address`` key.
    * Address must be RFC-shaped (``_looks_like_email``).
    * Address is lowercased + stripped.
    * Label is stripped (empty allowed).
    * The primary address (when supplied) cannot also be an alias.
    * Duplicate addresses across entries are rejected.

    Raises :class:`AliasValidationError` on first violation with a
    plain-language reason. Returns the cleaned list on success.
    """
    norm_primary = (primary or "").strip().lower()
    seen: set[str] = set()
    out: list[dict] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            raise AliasValidationError(
                "Each additional address must be a name/value entry."
            )
        addr = str(entry.get("address") or "").strip().lower()
        label = str(entry.get("label") or "").strip()
        if not addr:
            raise AliasValidationError(
                "Address can't be blank — type the email address you want to add."
            )
        if not _looks_like_email(addr):
            raise AliasValidationError(
                f"'{addr}' doesn't look like a valid email address. "
                f"It needs an @ and a dot in the part after the @."
            )
        if norm_primary and addr == norm_primary:
            raise AliasValidationError(
                "That's already this account's main address — "
                "no need to add it again."
            )
        if addr in seen:
            raise AliasValidationError(
                f"'{addr}' is listed twice. Each address can only appear once."
            )
        seen.add(addr)
        out.append({"address": addr, "label": label})
    return out


def update_email_account_aliases(
    conn: sqlite3.Connection,
    account_id: int,
    aliases: list[dict],
) -> bool:
    """Replace the stored alias list for an account.

    ``aliases`` should already be validated via :func:`normalize_aliases`
    — this writer is dumb (json.dumps + UPDATE). Returns True if a row
    was updated.
    """
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET aliases_json = ?, updated_at = ? "
        "WHERE id = ?",
        (json.dumps(aliases), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def delete_email_account(conn: sqlite3.Connection, account_id: int) -> bool:
    """Delete an email account. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM email_accounts WHERE id = ?", (account_id,))
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Account route helpers (per-account category→action mappings)
# ---------------------------------------------------------------------------

def list_account_routes(conn: sqlite3.Connection, account_id: int) -> list[dict]:
    """Return all route mappings for an account."""
    import json
    rows = conn.execute(
        "SELECT id, account_id, category, actions_json, created_at, updated_at "
        "FROM account_routes WHERE account_id = ? ORDER BY category",
        (account_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["actions"] = json.loads(d.pop("actions_json", "[]"))
        result.append(d)
    return result


def get_account_route(conn: sqlite3.Connection, account_id: int, category: str) -> dict | None:
    """Get a single route mapping for an account + category."""
    import json
    row = conn.execute(
        "SELECT id, account_id, category, actions_json FROM account_routes "
        "WHERE account_id = ? AND category = ?",
        (account_id, category),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["actions"] = json.loads(d.pop("actions_json", "[]"))
    return d


def upsert_account_route(
    conn: sqlite3.Connection,
    account_id: int,
    category: str,
    actions: list[dict],
) -> int:
    """Create or update a route mapping. Returns the row ID."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    actions_json = json.dumps(actions)

    existing = conn.execute(
        "SELECT id FROM account_routes WHERE account_id = ? AND category = ?",
        (account_id, category),
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE account_routes SET actions_json = ?, updated_at = ? WHERE id = ?",
            (actions_json, now, existing["id"]),
        )
        conn.commit()
        return existing["id"]
    else:
        cursor = conn.execute(
            "INSERT INTO account_routes (account_id, category, actions_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (account_id, category, actions_json, now, now),
        )
        conn.commit()
        return cursor.lastrowid


def delete_account_route(conn: sqlite3.Connection, route_id: int) -> bool:
    """Delete a route mapping. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM account_routes WHERE id = ?", (route_id,))
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Account Folder Preferences
# ---------------------------------------------------------------------------

def get_folder_prefs(conn: sqlite3.Connection, account_id: int) -> dict[str, bool]:
    """Return folder preferences as {folder_path: included}.

    Folders not in the table are considered included (default behaviour).
    Only explicitly excluded folders are stored with included=0.
    """
    rows = conn.execute(
        "SELECT folder_path, included FROM account_folder_prefs WHERE account_id = ?",
        (account_id,),
    ).fetchall()
    return {row["folder_path"]: bool(row["included"]) for row in rows}


def save_folder_prefs(
    conn: sqlite3.Connection,
    account_id: int,
    prefs: dict[str, bool],
) -> None:
    """Save folder include/exclude preferences.

    *prefs* is ``{folder_path: included}``.  Existing prefs for the
    account are replaced entirely (delete + re-insert).
    """
    conn.execute(
        "DELETE FROM account_folder_prefs WHERE account_id = ?",
        (account_id,),
    )
    for folder_path, included in prefs.items():
        conn.execute(
            "INSERT INTO account_folder_prefs (account_id, folder_path, included) "
            "VALUES (?, ?, ?)",
            (account_id, folder_path, int(included)),
        )
    conn.commit()


def get_visible_folders(
    conn: sqlite3.Connection,
    account_id: int,
    all_folders: list[str],
    separator: str = ".",
) -> list[str]:
    """Filter a list of server folders by the account's preferences.

    A folder is excluded if:
    - It is explicitly excluded (included=0), OR
    - Any of its ancestor folders are explicitly excluded.

    Folders with no preference entry are included by default.
    """
    prefs = get_folder_prefs(conn, account_id)
    # Build set of excluded paths.
    excluded = {path for path, inc in prefs.items() if not inc}

    visible = []
    for folder in all_folders:
        # Check if this folder or any ancestor is excluded.
        is_excluded = False
        for ex_path in excluded:
            if folder == ex_path or folder.startswith(ex_path + separator):
                is_excluded = True
                break
        if not is_excluded:
            visible.append(folder)
    return visible


# ---------------------------------------------------------------------------
# Triage run tracking
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO triage_runs "
        "(account_id, account_name, query, total_messages, results_json, "
        "errors_json, elapsed_secs, created_at, actor_user_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (account_id, account_name, query, total_messages,
         json.dumps(results), json.dumps(errors), elapsed_secs, now,
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
        d["results"] = json.loads(d.pop("results_json", "[]"))
        d["errors"] = json.loads(d.pop("errors_json", "[]"))
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# triage_jobs — background whole-mailbox triage runs (#101)
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
    return "tjob_" + _secrets_mod.token_hex(6)


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
    from datetime import datetime, timezone
    job_id = _new_job_id()
    now = datetime.now(timezone.utc).isoformat()
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
    return dict(row) if row else None


def list_triage_jobs(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    status: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Recent jobs, newest-first. Filter by account_id and/or status."""
    clauses: list[str] = []
    params: list = []
    if account_id is not None:
        clauses.append("account_id = ?")
        params.append(account_id)
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM triage_jobs {where} "
        f"ORDER BY created_at DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def count_active_triage_jobs_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Number of queued/running jobs on this account.

    Used by the run handler to refuse a second submit while an
    earlier job is still draining (one bulk job per account at a
    time, per #101 design)."""
    row = conn.execute(
        "SELECT COUNT(*) AS cnt FROM triage_jobs "
        "WHERE account_id = ? AND status IN ('queued', 'running')",
        (account_id,),
    ).fetchone()
    return int(row["cnt"]) if row else 0


def claim_next_queued_triage_job(
    conn: sqlite3.Connection,
) -> dict | None:
    """Atomically pick the oldest queued job, flip to running, return.

    Returns None when no queued job exists. The runner task calls
    this in a loop with a short sleep between empty results."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    return dict(row) if row else None


def bump_triage_job_counters(
    conn: sqlite3.Connection,
    job_id: str,
    *,
    seen: int = 0,
    processed: int = 0,
    skipped: int = 0,
    errors: int = 0,
) -> None:
    """Increment per-message counters + refresh ``last_progress_at``.

    Called by the runner after each message lands so the UI's
    progress poll sees fresh numbers. All four args are deltas to
    add (default 0) — caller passes whichever bucket the message
    landed in."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE triage_jobs SET "
        "  total_seen = total_seen + ?, "
        "  total_processed = total_processed + ?, "
        "  total_skipped = total_skipped + ?, "
        "  total_errors = total_errors + ?, "
        "  last_progress_at = ? "
        "WHERE job_id = ?",
        (seen, processed, skipped, errors, now, job_id),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE triage_jobs SET status = ?, ended_at = ?, "
        "  error_text = ? "
        "WHERE job_id = ?",
        (status, now, error_text, job_id),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    cursor = conn.execute(
        "UPDATE triage_jobs SET status = 'queued', "
        "  started_at = NULL, last_progress_at = NULL "
        "WHERE status = 'running' AND ended_at IS NULL"
    )
    conn.commit()
    return cursor.rowcount


def get_triage_stats(conn: sqlite3.Connection) -> dict:
    """Get aggregate triage stats for the dashboard."""
    stats = {}

    # Total runs.
    row = conn.execute("SELECT COUNT(*) AS cnt FROM triage_runs").fetchone()
    stats["total_runs"] = row["cnt"] if row else 0

    # Total messages processed.
    row = conn.execute("SELECT COALESCE(SUM(total_messages), 0) AS cnt FROM triage_runs").fetchone()
    stats["total_messages"] = row["cnt"] if row else 0

    # Recent runs (last 10).
    stats["recent_runs"] = list_triage_runs(conn, limit=10)

    # Category breakdown from all results.
    import json
    rows = conn.execute("SELECT results_json FROM triage_runs").fetchall()
    cat_counts: dict[str, int] = {}
    for r in rows:
        for entry in json.loads(r["results_json"] or "[]"):
            cat = entry.get("category", "unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    stats["category_counts"] = dict(sorted(cat_counts.items(), key=lambda x: -x[1]))

    return stats


# ---------------------------------------------------------------------------
# Log entries (for admin log viewer)
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
    """
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    extra_json = json.dumps(extra or {})
    prev_hash = get_last_log_row_hash(conn)
    row_hash = compute_log_row_hash(
        prev_hash, ts, level, logger, message, extra_json,
    )
    conn.execute(
        "INSERT INTO log_entries "
        "(ts, level, logger, message, extra_json, created_at, "
        " prev_hash, row_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, level, logger, message, extra_json, now, prev_hash, row_hash),
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
        extra = json.loads(d.pop("extra_json", "{}"))
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
        # rows would invalidate the audit hash chain (#131); the
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


_AUDIT_CHAIN_ANCHOR_KEY = "audit:chain_anchor"


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
    from datetime import datetime, timezone
    head = conn.execute(
        "SELECT id, prev_hash FROM log_entries "
        "WHERE row_hash != '' "
        "ORDER BY id ASC LIMIT 1"
    ).fetchone()
    if head is None:
        return
    anchor = {
        "head_id": int(head["id"]),
        "head_prev_hash": head["prev_hash"] or "",
        "anchored_at": datetime.now(timezone.utc).isoformat(),
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
        (_AUDIT_CHAIN_ANCHOR_KEY, _json.dumps(anchor), anchor["anchored_at"]),
    )
    # Keep the in-process settings cache (#140.2) coherent with this
    # transactional write. The cache otherwise serves a stale value
    # for up to TTL seconds after a prune sweep.
    invalidate_setting_cache(_AUDIT_CHAIN_ANCHOR_KEY)


def prune_log_entries(conn: sqlite3.Connection, keep: int = 5000) -> int:
    """Delete old log entries, keeping the most recent *keep* rows.

    Legacy count-only helper. Kept for back-compat with any external
    callers — prefer :func:`prune_log_entries_by_age_and_count`, which
    the web app wires up at startup + every 30 min.

    Captures the new head row's ``prev_hash`` into ``audit:chain_anchor``
    inside the same transaction as the DELETE so the verifier doesn't
    flag the post-prune boundary as a chain break (#131).
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
    flag the post-prune boundary as a chain break (#131 — HIPAA
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
# User escalation preferences
# ---------------------------------------------------------------------------

def get_user_escalation_categories(conn: sqlite3.Connection, user_id: int) -> set[str]:
    """Return the set of category slugs a user has escalation enabled for."""
    rows = conn.execute(
        "SELECT category FROM user_escalation_prefs WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return {r["category"] for r in rows}


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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

    #134.4 — single query, replaces ``is_user_disabled(db, owner_id)``
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


def record_user_status_event(
    conn: sqlite3.Connection,
    target_user_id: int,
    actor_user_id: int | None,
    event: str,
    reason: str = "",
) -> int:
    """Record a user-status change (disabled/enabled).  Returns the new row id."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO user_status_events "
        "(ts, target_user_id, actor_user_id, event, reason) "
        "VALUES (?, ?, ?, ?, ?)",
        (now, target_user_id, actor_user_id, event, reason or ""),
    )
    conn.commit()
    return cur.lastrowid


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
    from datetime import datetime, timezone
    row = conn.execute(
        "SELECT disabled FROM users WHERE id = ?", (target_user_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"User {target_user_id} not found")
    current = bool(row["disabled"])
    if current == bool(disabled):
        return False

    now = datetime.now(timezone.utc).isoformat()
    event = "disabled" if disabled else "enabled"
    try:
        conn.execute("BEGIN")
        if disabled:
            conn.execute(
                "UPDATE users SET disabled = 1, disabled_at = ?, "
                "disabled_by_user_id = ? WHERE id = ?",
                (now, actor_user_id, target_user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET disabled = 0, disabled_at = NULL, "
                "disabled_by_user_id = NULL WHERE id = ?",
                (target_user_id,),
            )
        conn.execute(
            "INSERT INTO user_status_events "
            "(ts, target_user_id, actor_user_id, event, reason) "
            "VALUES (?, ?, ?, ?, ?)",
            (now, target_user_id, actor_user_id, event, reason or ""),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True


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
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# HIPAA boundary event helpers
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO auth_events "
        "(ts, event_type, user_id, email, key_id, ip, user_agent, "
        " outcome, detail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (now, event_type, user_id, email, key_id, ip, user_agent,
         outcome, detail),
    )
    conn.commit()
    return cur.lastrowid


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
    return [dict(r) for r in rows]


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO hipaa_boundary_events "
        "(ts, scope, direction, actor_id, reason) VALUES (?, ?, ?, ?, ?)",
        (now, scope, direction, actor_id, reason),
    )
    conn.commit()
    return cur.lastrowid


def list_hipaa_boundary_events(
    conn: sqlite3.Connection,
    since: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """List boundary events newest-first, optionally filtered by timestamp."""
    if since:
        rows = conn.execute(
            "SELECT be.*, u.email AS actor_email "
            "FROM hipaa_boundary_events be "
            "LEFT JOIN users u ON u.id = be.actor_id "
            "WHERE be.ts >= ? ORDER BY be.ts DESC LIMIT ?",
            (since, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT be.*, u.email AS actor_email "
            "FROM hipaa_boundary_events be "
            "LEFT JOIN users u ON u.id = be.actor_id "
            "ORDER BY be.ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


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
    return dict(row) if row else None


def latest_hipaa_boundaries_for_accounts(
    conn: sqlite3.Connection,
) -> dict[str, dict]:
    """Return the most recent ``account:<id>`` boundary event for every account.

    #134.3 — single GROUP-BY query that replaces the per-account
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

def record_hipaa_access_event(
    conn: sqlite3.Connection,
    actor_user_id: int,
    account_id: int,
    operation: str,
    outcome: str = "ok",
    detail: str | None = None,
) -> int:
    """Record a user-initiated access to a HIPAA-flagged account.

    ``operation`` is one of ``"discover"`` / ``"manual_triage"``.
    ``outcome`` is ``"ok"`` or ``"error"``. ``detail`` is a short
    free-text field — never PHI (used for error classes, count of
    messages touched, etc.).
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO hipaa_access_events "
        "(ts, actor_user_id, account_id, operation, outcome, detail) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (now, actor_user_id, account_id, operation, outcome, detail),
    )
    conn.commit()
    return cur.lastrowid


def update_hipaa_access_event(
    conn: sqlite3.Connection,
    event_id: int,
    outcome: str,
    detail: str | None = None,
) -> None:
    """Update outcome/detail on an event recorded at the start of an operation."""
    conn.execute(
        "UPDATE hipaa_access_events SET outcome = ?, detail = ? WHERE id = ?",
        (outcome, detail, event_id),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO discover_runs "
        "(account_id, account_name, actor_user_id, scanned_count, "
        " errors_count, folders, elapsed_secs, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id,
            account_name or "",
            actor_user_id,
            int(scanned_count),
            int(errors_count),
            _json.dumps(list(folders or [])),
            float(elapsed_secs),
            now,
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_discover_runs(
    conn: sqlite3.Connection,
    account_id: int | None = None,
    actor_user_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """List discover runs newest-first with optional filters."""
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
    sql += " ORDER BY dr.created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def list_hipaa_access_events(
    conn: sqlite3.Connection,
    account_id: int | None = None,
    actor_user_id: int | None = None,
    since: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """List access events newest-first with optional filters."""
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
    sql += " ORDER BY ae.ts DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# API key lifecycle event helpers (audit trail for create/delete)
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO api_key_events "
        "(ts, event, key_id, actor_user_id, target_user_id, name, expires_at, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now, event, key_id, actor_user_id, target_user_id, name, expires_at, source),
    )
    conn.commit()
    return cur.lastrowid


def list_api_key_events(
    conn: sqlite3.Connection,
    limit: int = 100,
) -> list[dict]:
    """Return recent api_key_events newest-first, joined with user emails.

    Both actor and target user emails are looked up so the compliance UI
    can render readable rows even after either user is deleted (the FK
    is ON DELETE SET NULL so the row survives the user record).
    """
    rows = conn.execute(
        "SELECT ake.*, "
        "       au.email AS actor_email, "
        "       tu.email AS target_email "
        "FROM api_key_events ake "
        "LEFT JOIN users au ON au.id = ake.actor_user_id "
        "LEFT JOIN users tu ON tu.id = ake.target_user_id "
        "ORDER BY ake.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Access log (#41 — HIPAA §164.312(b))
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    try:
        cur = conn.execute(
            "INSERT INTO access_log "
            "(ts, actor_user_id, method, route, account_id, message_id, "
            " status_code, outcome, detail, request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, actor_user_id, method, route, account_id, message_id,
             int(status_code), outcome, detail, request_id),
        )
        conn.commit()
        return cur.lastrowid
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
        cur = conn.execute(
            "INSERT INTO access_log "
            "(ts, actor_user_id, method, route, account_id, message_id, "
            " status_code, outcome, detail, request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, coerced_actor, method, route, coerced_account,
             message_id, int(status_code), outcome, merged_detail,
             request_id),
        )
        conn.commit()
        return cur.lastrowid


def list_access_events(
    conn: sqlite3.Connection,
    limit: int = 100,
    actor_user_id: int | None = None,
    account_id: int | None = None,
) -> list[dict]:
    """Return recent access_log rows newest-first, joined with actor email."""
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
    rows = conn.execute(
        "SELECT al.*, "
        "       u.email AS actor_email, "
        "       ea.name AS account_name "
        "FROM access_log al "
        "LEFT JOIN users u ON u.id = al.actor_user_id "
        "LEFT JOIN email_accounts ea ON ea.id = al.account_id "
        f"{where_sql} "
        "ORDER BY al.id DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Log entries hash chain (#42 — tamper-evidence on log_entries)
# ---------------------------------------------------------------------------

def compute_log_row_hash(
    prev_hash: str,
    ts: str,
    level: str,
    logger: str,
    message: str,
    extra_json: str,
) -> str:
    """SHA-256 of the canonical row representation, chained off
    ``prev_hash``.

    Canonical form is ``prev_hash | ts | level | logger | message |
    extra_json`` joined with the literal pipe — pipes inside any
    field do NOT need escaping because the hash purpose is detection,
    not parsing back. Two rows that hash to the same value implies
    every field is equal AND the predecessor is the same; a tampered
    row breaks the next row's input → next row's recomputed hash
    diverges from stored.
    """
    import hashlib
    canonical = f"{prev_hash}|{ts}|{level}|{logger}|{message}|{extra_json}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_last_log_row_hash(conn: sqlite3.Connection) -> str:
    """Return the row_hash of the newest log_entries row, or empty
    string if the table has no chain-aware rows yet."""
    row = conn.execute(
        "SELECT row_hash FROM log_entries "
        "WHERE row_hash != '' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (row["row_hash"] if row else "") or ""


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

    Idempotent + read-only.
    """
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
            "       prev_hash, row_hash "
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
            "       prev_hash, row_hash "
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
        # Verify row_hash matches recomputation from canonical fields.
        recomputed = compute_log_row_hash(
            r["prev_hash"], r["ts"], r["level"], r["logger"],
            r["message"], r["extra_json"],
        )
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
                    f"row_hash mismatch at id={r['id']}: "
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
    # hit.
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
    }


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


def mark_triaged(
    conn: sqlite3.Connection,
    account_id: int,
    rfc_message_id: str,
) -> None:
    """Record that a message has been triaged. Idempotent (UNIQUE
    constraint short-circuits double-inserts)."""
    if not rfc_message_id:
        return
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO triaged_messages "
            "(account_id, msg_id_hash, ts) VALUES (?, ?, ?)",
            (account_id, _hash_msg_id(account_id, rfc_message_id), now),
        )
        conn.commit()
    except Exception:
        # Loop-prevention is best-effort; a DB error here must not
        # break the triage pipeline.
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


def prune_triaged_messages(
    conn: sqlite3.Connection,
    retention_days: int = 90,
) -> int:
    """Delete dedup rows older than ``retention_days``. Returns the
    number of rows removed. Idempotent; runs on the same cadence as
    the log-entries prune loop."""
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=int(retention_days))).isoformat()
    try:
        cur = conn.execute(
            "DELETE FROM triaged_messages WHERE ts < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount or 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Gmail Pub/Sub watch state
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    normalized_email = (email_address or "").strip().lower()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO gmail_watches "
        "(account_id, email_address, topic_name, history_id, expires_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  email_address = excluded.email_address, "
        "  topic_name    = excluded.topic_name, "
        "  history_id    = excluded.history_id, "
        "  expires_at    = excluded.expires_at, "
        "  updated_at    = excluded.updated_at",
        (account_id, normalized_email, topic_name, history_id, expires_at, now, now),
    )
    conn.commit()


def update_gmail_watch_history(
    conn: sqlite3.Connection, account_id: int, history_id: str,
) -> None:
    """Advance the stored history cursor; leaves ``expires_at`` alone."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE gmail_watches SET history_id = ?, updated_at = ? WHERE account_id = ?",
        (history_id, now, account_id),
    )
    conn.commit()


def get_gmail_watch(conn: sqlite3.Connection, account_id: int) -> dict | None:
    row = conn.execute(
        "SELECT * FROM gmail_watches WHERE account_id = ?", (account_id,),
    ).fetchone()
    return dict(row) if row else None


def get_gmail_watch_by_email(conn: sqlite3.Connection, email_address: str) -> dict | None:
    """Look up a Gmail watch row by email, case-insensitively.

    Pub/Sub delivers the address in lowercase per the Gmail API
    contract; the operator may have typed it in mixed case at
    account-creation time. Match LOWER(stored) against
    LOWER(supplied) so the webhook always finds the row.
    """
    needle = (email_address or "").strip().lower()
    if not needle:
        return None
    row = conn.execute(
        "SELECT * FROM gmail_watches WHERE LOWER(email_address) = ?",
        (needle,),
    ).fetchone()
    return dict(row) if row else None


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
    return [dict(r) for r in rows]


def list_gmail_watches(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM gmail_watches ORDER BY email_address ASC"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Office 365 / Microsoft Graph webhook subscriptions  (#53)
#
# One row per account holding the active Graph subscription state.
# Sister table to ``gmail_watches`` for the parallel push pipeline.
# Created by migration v6 (``create_office365_subscriptions``).
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    return dict(row) if row else None


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
    return dict(row) if row else None


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
    return [dict(r) for r in rows]


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
    return [dict(r) for r in rows]


def record_push_delivery(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    provider: str,
) -> None:
    """Bump today's per-account push-delivery counter (#166).

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
        return 0


def record_o365_notification(
    conn: sqlite3.Connection, subscription_id: str,
) -> None:
    """Stamp ``last_notification_at`` on a webhook delivery.

    No-op when the subscription_id isn't in our table — the webhook
    receiver will have already 200'd to stop Graph retries; this just
    forwards the heartbeat.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET last_notification_at = ?, updated_at = ? "
        "WHERE subscription_id = ?",
        (now, now, subscription_id),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE office365_subscriptions "
        "SET delta_link = ?, updated_at = ? "
        "WHERE account_id = ?",
        (delta_link, now, account_id),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    truncated = (error_text or "")[:500]
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


# ---------------------------------------------------------------------------
# User meeting preferences (settings-backed; no schema migration)
# ---------------------------------------------------------------------------

def get_meeting_prefs(conn: sqlite3.Connection, user_id: int | None) -> dict:
    """Return the user's meeting preferences dict, or empty if none set.

    The intercept action and the OpenClaw API hand the dict to
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

def _style_profile_key(account_id: int) -> str:
    from email_triage.web.settings_keys import style_profile
    return style_profile(account_id)


def get_style_profile(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    """Return the persisted style-profile dict for ``account_id``.

    Returns ``None`` when no profile has been built yet. Callers
    typically pass the result to
    :meth:`email_triage.actions.style_profile.StyleProfile.from_dict`
    to rehydrate a typed object — that method tolerates missing keys
    so a hand-edit or older schema does not crash startup.
    """
    raw = get_setting(conn, _style_profile_key(account_id))
    if raw is None or not isinstance(raw, dict):
        return None
    return raw


def set_style_profile(
    conn: sqlite3.Connection, account_id: int, profile: dict,
) -> None:
    """Persist a style profile dict for ``account_id`` (upsert)."""
    if not isinstance(profile, dict):
        raise ValueError("style profile must be a dict")
    set_setting(conn, _style_profile_key(account_id), profile)


def delete_style_profile(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Drop the persisted style profile for ``account_id``.

    Returns True when a row was deleted. Used by the M-8 "Forget my
    style profile" UI when it lands.
    """
    return delete_setting(conn, _style_profile_key(account_id))


# ---------------------------------------------------------------------------
# Alias-aware learning (punch list #162)
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

def normalise_from_address(value: str | None) -> str:
    """Reduce a free-form ``From:`` header value to a comparable bare address.

    Drops the display-name prefix, surrounding angle brackets, the
    ``+suffix`` tag (Gmail-style "subaddress"), and casing. Empty /
    invalid inputs collapse to ``""`` so callers can treat the result
    as ``str`` unconditionally.

    Examples
    --------
    >>> normalise_from_address('"Display Name" <Sam+work@Example.Tld>')
    'sam@example.tld'
    >>> normalise_from_address('alice@example.com')
    'alice@example.com'
    >>> normalise_from_address(None)
    ''
    """
    if not value:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    # If a ``<addr>`` block is present, prefer its content over the
    # display-name part. We deliberately don't try to be RFC 5322
    # complete — the inputs are ``From:`` header values pulled from
    # an ``EmailMessage`` that the providers have already normalised
    # one level (display name + bare address coexisting is the
    # mainstream shape).
    if "<" in s and ">" in s:
        lt = s.rfind("<")
        gt = s.find(">", lt)
        if lt != -1 and gt != -1 and gt > lt:
            s = s[lt + 1: gt].strip()
    # Drop any surrounding quotes / whitespace.
    s = s.strip().strip('"').strip("'").strip()
    if not s:
        return ""
    # Lowercase + split off the ``+suffix`` tag if present. The tag
    # is part of the same delivery destination on Gmail-style "plus
    # addressing" -- two captures of ``alice+work@x`` and ``alice@x``
    # belong in the same bucket.
    s = s.lower()
    if "@" not in s:
        return s
    local, _, domain = s.partition("@")
    if "+" in local:
        local = local.split("+", 1)[0]
    if not local or not domain:
        return ""
    return f"{local}@{domain}"


def is_alias_mode_enabled_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Return True when alias-aware learning is on for ``account_id``.

    Default False so existing accounts retain single-descriptor
    behaviour until the operator explicitly opts in on
    ``/profile/style-data``. Pre-v23 DBs (no column) read as False.
    """
    try:
        row = conn.execute(
            "SELECT style_alias_mode_enabled FROM email_accounts "
            "WHERE id = ?",
            (int(account_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    if row is None:
        return False
    val = row["style_alias_mode_enabled"] if hasattr(row, "keys") else row[0]
    return bool(val)


def set_alias_mode_enabled_for_account(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Flip the alias-aware-learning toggle for ``account_id``."""
    conn.execute(
        "UPDATE email_accounts SET style_alias_mode_enabled = ? "
        "WHERE id = ?",
        (1 if enabled else 0, int(account_id)),
    )
    conn.commit()


def get_account_style_per_alias(
    conn: sqlite3.Connection, account_id: int, from_address: str,
) -> dict | None:
    """Return the per-alias descriptor dict, or None if absent.

    ``from_address`` is normalised before lookup so the caller may
    pass the raw header value. The empty string is a valid key (the
    "no alias bucket / default" row) but the picker that consumes
    this helper always falls back to the account-wide descriptor
    when the per-alias row is missing.
    """
    addr = normalise_from_address(from_address)
    try:
        row = conn.execute(
            "SELECT descriptor_json FROM account_style_per_alias "
            "WHERE account_id = ? AND from_address = ?",
            (int(account_id), addr),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v23 install -- treat as "no row".
        return None
    if row is None:
        return None
    import json as _json
    raw = row["descriptor_json"] if hasattr(row, "keys") else row[0]
    try:
        parsed = _json.loads(raw or "{}")
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def set_account_style_per_alias(
    conn: sqlite3.Connection,
    account_id: int,
    from_address: str,
    descriptor: dict,
    *,
    sample_count: int | None = None,
) -> None:
    """Upsert a per-alias descriptor.

    ``from_address`` is normalised before write; the same address in
    any case / display-name shape lands in the same row. The
    ``sample_count`` argument lets the caller record the contributing
    sample count without inspecting the dict (useful when the dict
    came from a third-party shape that didn't include the field).
    """
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    addr = normalise_from_address(from_address)
    import json as _json
    from datetime import datetime, timezone
    sc = sample_count if sample_count is not None else int(
        descriptor.get("sample_count") or 0,
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO account_style_per_alias "
        "(account_id, from_address, descriptor_json, sample_count, updated_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id, from_address) DO UPDATE SET "
        "  descriptor_json = excluded.descriptor_json, "
        "  sample_count    = excluded.sample_count, "
        "  updated_at      = excluded.updated_at",
        (int(account_id), addr, _json.dumps(descriptor), int(sc), now),
    )
    conn.commit()


def list_account_style_per_alias(
    conn: sqlite3.Connection, account_id: int,
) -> list[dict]:
    """Return all per-alias descriptor rows for ``account_id``.

    Each entry is ``{"from_address": str, "descriptor": dict,
    "sample_count": int, "updated_at": str}``. Ordered by
    ``from_address`` (lexicographic) so the operator-facing picker
    has a stable layout. Returns ``[]`` on pre-v23 installs.
    """
    try:
        rows = conn.execute(
            "SELECT from_address, descriptor_json, sample_count, updated_at "
            "FROM account_style_per_alias "
            "WHERE account_id = ? "
            "ORDER BY from_address",
            (int(account_id),),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    import json as _json
    out: list[dict] = []
    for r in rows:
        raw = r["descriptor_json"] if hasattr(r, "keys") else r[1]
        try:
            desc = _json.loads(raw or "{}")
        except (TypeError, ValueError):
            desc = {}
        if not isinstance(desc, dict):
            desc = {}
        out.append({
            "from_address": (
                r["from_address"] if hasattr(r, "keys") else r[0]
            ),
            "descriptor": desc,
            "sample_count": int(
                (r["sample_count"] if hasattr(r, "keys") else r[2]) or 0,
            ),
            "updated_at": (
                r["updated_at"] if hasattr(r, "keys") else r[3]
            ) or "",
        })
    return out


def delete_account_style_per_alias(
    conn: sqlite3.Connection,
    account_id: int,
    from_address: str | None = None,
) -> int:
    """Delete per-alias descriptor rows.

    When ``from_address`` is None, every per-alias row for the account
    is dropped. When given, only the matching row is dropped (the
    address is normalised first so case / suffix variants resolve to
    the same row).

    Returns the number of rows deleted.
    """
    if from_address is None:
        cur = conn.execute(
            "DELETE FROM account_style_per_alias WHERE account_id = ?",
            (int(account_id),),
        )
    else:
        addr = normalise_from_address(from_address)
        cur = conn.execute(
            "DELETE FROM account_style_per_alias "
            "WHERE account_id = ? AND from_address = ?",
            (int(account_id), addr),
        )
    conn.commit()
    return cur.rowcount or 0


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

STYLE_KNOB_DEFAULTS = {
    "style_guide": "",
    "style_tone": "neutral",
    "style_length": "medium",
    "style_signature": "",
    "style_greeting": "first-name",
    "style_greeting_custom": "",
}


def get_user_style_knobs(
    conn: sqlite3.Connection, user_id: int | None,
) -> dict:
    """Return the user's style-knob dict, defaulted on missing keys.

    Returns the canonical default dict (matching ``STYLE_KNOB_DEFAULTS``)
    when ``user_id`` is None or the row is absent. Older DBs that
    haven't yet run migration v11 don't have the columns; the
    KeyError-on-row-access falls back to defaults so this is safe to
    call before the migration runs.
    """
    if not user_id:
        return dict(STYLE_KNOB_DEFAULTS)
    try:
        row = conn.execute(
            "SELECT style_guide, style_tone, style_length, "
            "       style_signature, style_greeting, style_greeting_custom "
            "FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v11 DB (columns don't exist yet).
        return dict(STYLE_KNOB_DEFAULTS)
    if row is None:
        return dict(STYLE_KNOB_DEFAULTS)
    out = dict(STYLE_KNOB_DEFAULTS)
    for k in STYLE_KNOB_DEFAULTS:
        v = row[k] if hasattr(row, "keys") else None
        if v is None:
            continue
        out[k] = str(v)
    return out


def set_user_style_knobs(
    conn: sqlite3.Connection, user_id: int, knobs: dict,
) -> None:
    """Persist the user's style knobs (full upsert across all columns).

    Caller must validate values against the allowlists; this helper
    only enforces type coercion (everything stored as TEXT). Missing
    keys fall back to ``STYLE_KNOB_DEFAULTS`` so the DB stays in a
    valid post-v11 state.
    """
    merged = dict(STYLE_KNOB_DEFAULTS)
    for k in STYLE_KNOB_DEFAULTS:
        if k in knobs and knobs[k] is not None:
            merged[k] = str(knobs[k])
    conn.execute(
        "UPDATE users SET "
        "  style_guide = ?, style_tone = ?, style_length = ?, "
        "  style_signature = ?, style_greeting = ?, "
        "  style_greeting_custom = ? "
        "WHERE id = ?",
        (
            merged["style_guide"],
            merged["style_tone"],
            merged["style_length"],
            merged["style_signature"],
            merged["style_greeting"],
            merged["style_greeting_custom"],
            int(user_id),
        ),
    )
    conn.commit()


def is_style_learning_master_enabled(conn: sqlite3.Connection) -> bool:
    """Return the install-wide style-learning master toggle.

    Stored under settings key ``style_learning:master`` as
    ``{"enabled": bool}``. Default ON when the row is missing — this
    is the privacy-neutral default for user-stated knobs (no
    cross-user inference involved). The Cross-cutting toggle at
    /config flips this off when the operator wants to suppress all
    style influence on draft replies.
    """
    return get_bool_setting(conn, "style_learning:master", default=True)


def set_style_learning_master_enabled(
    conn: sqlite3.Connection, enabled: bool,
) -> None:
    """Flip the install-wide style-learning master toggle."""
    set_bool_setting(conn, "style_learning:master", enabled)


# ---------------------------------------------------------------------------
# Style-learning admin cadence + mine-limit defaults (#161 follow-up)
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

STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS = 1
STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS = 72
STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS = 6

STYLE_LEARNING_MINE_LIMIT_MIN = 1
STYLE_LEARNING_MINE_LIMIT_MAX = 500
STYLE_LEARNING_MINE_LIMIT_DEFAULT = 50

# Threshold above which the inline mine-now / preview path is too slow
# for an HTMX request and the operator gets handed off to the bulk
# worker. 50 is the historical inline cap; values > 50 trigger the
# style_mine bulk-job kind. Operator sees a "watching the bulk runs
# page" message + a link to that page when the resolved limit crosses
# this line. Tunable here so an install with faster LLM hardware can
# raise it without code changes (constants only; not operator-exposed
# on /config yet).
STYLE_LEARNING_INLINE_LIMIT_CEILING = 50


def get_style_learning_capture_interval_hours(
    conn: sqlite3.Connection,
) -> int:
    """Read the install-wide capture-loop cadence (hours).

    Returns the operator-set value, or
    :data:`STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS` when no
    explicit value is stored. Out-of-range / non-numeric values
    clamp into the documented range so the loop's sleep helper
    never sees a value it can't honour."""
    raw = get_setting(conn, "style_learning:capture_interval_hours")
    hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if isinstance(raw, dict):
        try:
            hours = int(
                raw.get("hours")
                or STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
            )
        except (TypeError, ValueError):
            hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    elif isinstance(raw, (int, float)):
        try:
            hours = int(raw)
        except (TypeError, ValueError):
            hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if hours < STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS:
        hours = STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS
    elif hours > STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS:
        hours = STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS
    return hours


def set_style_learning_capture_interval_hours(
    conn: sqlite3.Connection, hours: int,
) -> None:
    """Persist the install-wide capture-loop cadence (hours).

    Clamps to the documented range; the YAML loader / loop reader
    re-clamps defensively in case the row is hand-edited."""
    try:
        h = int(hours)
    except (TypeError, ValueError):
        h = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if h < STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS:
        h = STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS
    elif h > STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS:
        h = STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS
    set_setting(conn, "style_learning:capture_interval_hours", {"hours": h})


def get_style_learning_mine_limit_default(
    conn: sqlite3.Connection,
) -> int:
    """Read the install-wide default for the mine-now / preview limit.

    Out-of-range / non-numeric values clamp into the documented range;
    missing row falls back to
    :data:`STYLE_LEARNING_MINE_LIMIT_DEFAULT` (50)."""
    raw = get_setting(conn, "style_learning:mine_limit_default")
    val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if isinstance(raw, dict):
        try:
            val = int(
                raw.get("limit") or STYLE_LEARNING_MINE_LIMIT_DEFAULT
            )
        except (TypeError, ValueError):
            val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    elif isinstance(raw, (int, float)):
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if val < STYLE_LEARNING_MINE_LIMIT_MIN:
        val = STYLE_LEARNING_MINE_LIMIT_MIN
    elif val > STYLE_LEARNING_MINE_LIMIT_MAX:
        val = STYLE_LEARNING_MINE_LIMIT_MAX
    return val


def set_style_learning_mine_limit_default(
    conn: sqlite3.Connection, limit: int,
) -> None:
    """Persist the install-wide default mine-now / preview limit.

    Clamps to the documented range so a typo doesn't wedge the inline
    path with a giant scan."""
    try:
        v = int(limit)
    except (TypeError, ValueError):
        v = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if v < STYLE_LEARNING_MINE_LIMIT_MIN:
        v = STYLE_LEARNING_MINE_LIMIT_MIN
    elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
        v = STYLE_LEARNING_MINE_LIMIT_MAX
    set_setting(conn, "style_learning:mine_limit_default", {"limit": v})


def resolve_account_mine_limit(
    conn: sqlite3.Connection, account: dict | None,
) -> int:
    """Resolve the effective mine-now / preview limit for one account.

    Per-account override (``config_json.mine_limit_override``) wins
    when present and positive; falls through to the install-wide
    default. Empty / unset / non-positive override → install default.
    """
    if account is not None and isinstance(account, dict):
        cfg = account.get("config") or {}
        if isinstance(cfg, dict):
            raw = cfg.get("mine_limit_override")
            if raw is not None and raw != "":
                try:
                    v = int(raw)
                    if v > 0:
                        if v < STYLE_LEARNING_MINE_LIMIT_MIN:
                            v = STYLE_LEARNING_MINE_LIMIT_MIN
                        elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
                            v = STYLE_LEARNING_MINE_LIMIT_MAX
                        return v
                except (TypeError, ValueError):
                    pass
    return get_style_learning_mine_limit_default(conn)


# ---------------------------------------------------------------------------
# Per-account "auto-scan on schedule" toggle (#161 item 2)
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
    overrides the default in either direction."""
    if account is None or not isinstance(account, dict):
        return False
    cfg = account.get("config")
    if isinstance(cfg, dict):
        raw = cfg.get("auto_scan_enabled")
        if raw is not None:
            return bool(raw)
    return not bool(account.get("hipaa"))


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


def is_style_learning_account_enabled(account: dict | None) -> bool:
    """Return the per-account style-learning toggle from config.

    Pulled from ``account.config["style_learning_enabled"]``. Default
    is True (on) — opt-out shape so existing accounts keep working
    when columns are first added. Sites that mutate this go through
    the standard account-edit save path which writes config_json.
    """
    if account is None:
        return False
    cfg = account.get("config") if isinstance(account, dict) else None
    if not isinstance(cfg, dict):
        return True
    val = cfg.get("style_learning_enabled")
    if val is None:
        return True
    return bool(val)


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

def _rag_sent_index_key(account_id: int) -> str:
    from email_triage.web.settings_keys import rag_sent_index_enabled
    return rag_sent_index_enabled(account_id)


def is_rag_sent_index_enabled(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    account: dict | None = None,
) -> bool:
    """Return True when the per-account RAG-over-sent-mail toggle is on.

    Default-on / default-off is HIPAA-aware (#157, 2026-05-11). When
    the operator has not explicitly toggled the setting, the per-render
    default depends on the account's HIPAA flag:

      * HIPAA-flagged account → default OFF. Owner must opt IN
        explicitly. Under §164.502(a) the owner gets the choice but
        the install does not auto-mine PHI mail.
      * Non-HIPAA account → default ON. The "AI learns from your
        past replies" experience is the project's mainline; new
        accounts should benefit without a manual toggle.

    Existing accounts with an explicitly-saved value keep that value;
    the HIPAA-aware split applies only when no row exists in the
    settings table. The HIPAA hard gates layered on the M-4 path
    itself (e.g. ``SentMailIndex._hipaa_short_circuit``) are unchanged
    — they still refuse a HIPAA-flagged account even if this helper
    returned True; the toggle is the operator UX surface, the hard
    gate is the privacy guarantee.

    Parameters
    ----------
    conn:
        Active SQLite connection.
    account_id:
        Account whose setting we're reading.
    account:
        Optional account dict (with ``hipaa`` field) for the
        HIPAA-aware default. Callers that already have the dict in
        hand (e.g. the background loop) should pass it to avoid a
        round-trip; callers that don't fall through to the legacy
        default-off behaviour (the conservative posture). When
        ``account is None`` we do NOT load the account row ourselves
        — the caller's path may not have the account_id privilege
        check we'd need, and the conservative default cannot leak data.
    """
    raw = get_setting(conn, _rag_sent_index_key(account_id))
    if raw is None:
        # No explicit value saved — apply the HIPAA-aware default.
        if account is not None:
            from email_triage.triage_logging import is_account_hipaa
            if is_account_hipaa(account):
                return False
            return True
        # Caller didn't supply the account — use the conservative
        # default to keep the existing posture for any pre-#157 path
        # that doesn't yet know about the split.
        return False
    if isinstance(raw, dict):
        if "enabled" in raw:
            return bool(raw.get("enabled"))
        return False
    return bool(raw)


def set_rag_sent_index_enabled(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Persist the per-account RAG toggle (upsert)."""
    set_bool_setting(conn, _rag_sent_index_key(account_id), enabled)


# ---------------------------------------------------------------------------
# Per-account M-1+M-2 HIPAA-allow opt-in (#152 Phase 2)
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
# See ``docs/m-series-hipaa-audit.md`` for the per-layer audit and
# ``docs/privacy-audit-runbook.md`` for the sign-off log entry.
# ---------------------------------------------------------------------------

def _style_knobs_hipaa_allow_key(account_id: int) -> str:
    from email_triage.web.settings_keys import style_knobs_hipaa_allow
    return style_knobs_hipaa_allow(account_id)


def is_style_knobs_hipaa_allow(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Return True when the operator has opted in to M-1+M-2 for this
    HIPAA-flagged account. Default False."""
    return get_bool_setting(
        conn, _style_knobs_hipaa_allow_key(account_id), default=False,
    )


def set_style_knobs_hipaa_allow(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Persist the per-account M-1+M-2 HIPAA-allow opt-in (upsert)."""
    set_bool_setting(
        conn, _style_knobs_hipaa_allow_key(account_id), enabled,
    )


# ---------------------------------------------------------------------------
# HIPAA-safe M-3 describe-and-discard descriptor (#152 phase 3)
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

#: Install-wide settings-table key for the phase-3 HIPAA distill flag.
#: Default OFF. Lives on /config under the privacy section.
STYLE_LEARNING_HIPAA_DISTILL_ENABLED = "style_learning:hipaa_distill_enabled"

#: Re-distill cadence: rebuild the HIPAA descriptor at most this often.
#: Operator-tunable later via /config; this is the constant default. One
#: week = same target as the punch-list phase-3 spec ("weekly cadence:
#: descriptor is rebuilt weekly so stale descriptor doesn't accumulate
#: PHI risk over time").
HIPAA_STYLE_DESCRIPTOR_REBUILD_INTERVAL_HOURS = 168  # 7 days


def is_hipaa_style_distill_enabled(conn: sqlite3.Connection) -> bool:
    """Install-wide gate on the phase-3 distill pipeline.

    Default OFF. The pipeline scaffold lives in
    :mod:`email_triage.actions.hipaa_style_distill` but is not wired into
    any production caller until the operator both (a) flips this flag and
    (b) signs off on the LLM-backend posture (Ollama-local-only per the
    current default).
    """
    return get_bool_setting(
        conn, STYLE_LEARNING_HIPAA_DISTILL_ENABLED, default=False,
    )


def set_hipaa_style_distill_enabled(
    conn: sqlite3.Connection, enabled: bool,
) -> None:
    """Flip the install-wide HIPAA-distill enabled flag."""
    set_bool_setting(
        conn, STYLE_LEARNING_HIPAA_DISTILL_ENABLED, enabled,
    )


def get_hipaa_style_descriptor(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    """Return the persisted HIPAA descriptor row, or None.

    Shape::

        {
            "descriptor": <dict>,        # parsed descriptor_json
            "version": <int>,            # descriptor_version
            "rebuilt_at": <iso8601 str>,
            "message_count": <int>,
            "scrubber_outcome": <str>,
        }

    Returns ``None`` when no row exists (descriptor never built).
    Tolerant of corrupt JSON: a parse failure also returns ``None`` so
    the caller falls back to "no descriptor available; either re-distill
    or render empty".
    """
    import json as _json
    row = conn.execute(
        "SELECT descriptor_json, descriptor_version, rebuilt_at, "
        "       message_count, scrubber_outcome "
        "FROM hipaa_style_descriptors WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if row is None:
        return None
    try:
        descriptor = _json.loads(
            row["descriptor_json"] if hasattr(row, "keys") else row[0]
        )
    except (ValueError, TypeError):
        return None
    if not isinstance(descriptor, dict):
        return None
    return {
        "descriptor": descriptor,
        "version": int(
            row["descriptor_version"] if hasattr(row, "keys") else row[1]
        ),
        "rebuilt_at": (
            row["rebuilt_at"] if hasattr(row, "keys") else row[2]
        ),
        "message_count": int(
            row["message_count"] if hasattr(row, "keys") else row[3]
        ),
        "scrubber_outcome": (
            row["scrubber_outcome"] if hasattr(row, "keys") else row[4]
        ),
    }


def set_hipaa_style_descriptor(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    descriptor: dict,
    version: int,
    message_count: int,
    scrubber_outcome: str = "clean",
) -> None:
    """Persist a scrubbed HIPAA descriptor (upsert).

    Callers should only invoke this AFTER the scrubber pass returns
    clean. A 'dropped' outcome is an error path — the action should
    delete any existing row rather than writing a fresh one with
    ``scrubber_outcome='dropped'`` so a future read can't see a
    partial / poisoned descriptor.
    """
    import json as _json
    from datetime import datetime, timezone
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO hipaa_style_descriptors "
        "(account_id, descriptor_json, descriptor_version, rebuilt_at, "
        " message_count, scrubber_outcome) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  descriptor_json    = excluded.descriptor_json, "
        "  descriptor_version = excluded.descriptor_version, "
        "  rebuilt_at         = excluded.rebuilt_at, "
        "  message_count      = excluded.message_count, "
        "  scrubber_outcome   = excluded.scrubber_outcome",
        (
            int(account_id),
            _json.dumps(descriptor),
            int(version),
            now,
            int(message_count),
            str(scrubber_outcome or "clean"),
        ),
    )
    conn.commit()


def delete_hipaa_style_descriptor(
    conn: sqlite3.Connection, account_id: int,
) -> None:
    """Remove the HIPAA descriptor row for ``account_id`` (idempotent).

    Called by the distill action when the scrubber drops the descriptor
    (a clean descriptor never landed; remove any stale one too).
    """
    conn.execute(
        "DELETE FROM hipaa_style_descriptors WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# style_distill_events — audit-row split for the HIPAA distill pipeline
# (#152 phases 3-4 S4). Sibling to ``hipaa_access_events`` but the shape
# is wrong for the existing table; see ``_v27_create_style_distill_audit
# _and_queue`` for the rationale.
# ---------------------------------------------------------------------------

def record_style_distill_event(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: int | None,
    backend_id: int | None,
    backend_type: str,
    was_cloud: bool,
    outcome: str,
    latency_ms: int = 0,
    layer1_drops: int = 0,
    layer2_matches: int = 0,
    layer3_entities: int = 0,
    scrubber_degraded: bool = False,
    error_class: str | None = None,
    kind: str = "account_m3",
    recipient_hash: str | None = None,
) -> int:
    """Insert one ``style_distill_events`` row + return the id.

    The PHI-safety contract: callers pass COUNTS only, never the
    matched text or raw error message. ``error_class`` is the type-
    name of the exception (``"HTTPError"`` / ``"TimeoutError"``) —
    never ``str(exc)`` since some providers embed the request body in
    the message string.

    ``kind`` discriminates the audit row's pipeline (``'account_m3'``
    for the v27 M-3 path; ``'per_contact'`` for the v28 M-7 HIPAA path).
    ``recipient_hash`` is the 64-hex SHA-256 digest of the recipient
    address for ``kind='per_contact'`` rows — NEVER the plaintext
    address. NULL for ``kind='account_m3'`` rows.
    """
    from datetime import datetime, timezone
    # Defensive: reject anything that looks like a plaintext email.
    # The hash is exactly 64 hex chars, lower-cased; plaintext would
    # carry an ``@`` or be the wrong length.
    if recipient_hash is not None:
        h = str(recipient_hash).lower()
        if "@" in h:
            raise ValueError(
                "recipient_hash carries '@' — caller passed plaintext"
            )
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(
                "recipient_hash must be a 64-char SHA-256 hex digest"
            )
        recipient_hash = h
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO style_distill_events "
        "(ts, account_id, actor_user_id, backend_id, backend_type, "
        " was_cloud, outcome, latency_ms, layer1_drops, layer2_matches, "
        " layer3_entities, scrubber_degraded, error_class, kind, "
        " recipient_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            int(account_id),
            actor_user_id if actor_user_id is None else int(actor_user_id),
            backend_id if backend_id is None else int(backend_id),
            str(backend_type or ""),
            1 if was_cloud else 0,
            str(outcome),
            int(latency_ms or 0),
            int(layer1_drops or 0),
            int(layer2_matches or 0),
            int(layer3_entities) if layer3_entities is not None else 0,
            1 if scrubber_degraded else 0,
            (str(error_class) if error_class else None),
            str(kind or "account_m3"),
            recipient_hash,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def style_distill_event_counts(
    conn: sqlite3.Connection,
    *,
    since_iso: str | None = None,
) -> dict:
    """Return per-bucket counters for the /health/detail summary.

    Shape::

        {
            "local_24h":            <int>,  # was_cloud=0 successes
            "cloud_24h":            <int>,  # was_cloud=1 successes
            "failures_24h":         <int>,  # outcome=backend_fail
            "scrubber_rejects_24h": <int>,  # outcome=scrubber_fail
            "total_24h":            <int>,  # any outcome in the window
        }

    ``since_iso`` defaults to ``now - 24h`` (UTC). Caller may pass an
    explicit cutoff to inspect a different window.
    """
    from datetime import datetime, timezone, timedelta
    if since_iso is None:
        since_iso = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
    out = {
        "local_24h": 0,
        "cloud_24h": 0,
        "failures_24h": 0,
        "scrubber_rejects_24h": 0,
        "total_24h": 0,
    }
    rows = conn.execute(
        "SELECT outcome, was_cloud, COUNT(*) AS cnt "
        "FROM style_distill_events "
        "WHERE ts >= ? "
        "GROUP BY outcome, was_cloud",
        (since_iso,),
    ).fetchall()
    for row in rows:
        outcome = row["outcome"] if hasattr(row, "keys") else row[0]
        was_cloud = int(row["was_cloud"] if hasattr(row, "keys") else row[1])
        cnt = int(row["cnt"] if hasattr(row, "keys") else row[2])
        out["total_24h"] += cnt
        if outcome == "success":
            if was_cloud:
                out["cloud_24h"] += cnt
            else:
                out["local_24h"] += cnt
        elif outcome == "backend_fail":
            out["failures_24h"] += cnt
        elif outcome == "scrubber_fail":
            out["scrubber_rejects_24h"] += cnt
    return out


def list_style_distill_events(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """List events newest-first with optional per-account filter."""
    where = ""
    params: list = []
    if account_id is not None:
        where = "WHERE account_id = ?"
        params.append(int(account_id))
    params.append(int(limit))
    rows = conn.execute(
        f"SELECT * FROM style_distill_events {where} "
        f"ORDER BY ts DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# style_distill_queue — exponential-backoff retry queue for the HIPAA
# distill pipeline (#152 phases 3-4 S3). One row per account; the worker
# polls for the oldest ready row.
# ---------------------------------------------------------------------------

#: Backoff schedule in seconds; index = attempt number, value = wait
#: until next attempt. Per operator directive: NO fallback-to-local on
#: cloud failure. Retry the same backend with exponential backoff and
#: surface for operator review after attempt 8.
#:
#: Derived from :data:`email_triage.retry_backoff.STYLE_DISTILL_SCHEDULE`
#: (#175 R-A) so the schedule lives in one place across both queues.
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


def _style_distill_compute_next_retry(
    attempt_count: int, *, now: "datetime | None" = None,
) -> "str | None":
    """Compute the ISO timestamp for the next retry, or None when
    ``attempt_count`` exceeds the schedule (final attempt landed).

    Note on indexing
    ----------------
    The style-distill queue uses 1-based attempt numbering ("attempt 1
    just landed; compute wait for attempt 2"); the shared
    :func:`email_triage.retry_backoff.compute_next_attempt_at` uses
    0-based ("0 failures so far; compute wait for the first retry").
    We bridge the off-by-one here: ``attempt_count=1`` → index 0 in
    the shared helper. This preserves the public contract that
    :data:`STYLE_DISTILL_BACKOFF_SECONDS[0]` is the wait after attempt
    1, used by the pinned tests in ``test_style_distill_queue.py``.
    """
    if attempt_count <= 0:
        attempt_count = 1
    next_dt = _compute_next_attempt_at(
        attempt_count - 1,  # 1-based → 0-based bridge
        _STYLE_DISTILL_SCHEDULE,
        now=now,
    )
    if next_dt is None:
        return None
    return next_dt.isoformat()


def enqueue_style_distill_retry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    last_error: str | None,
) -> dict:
    """Schedule a HIPAA-distill retry after a ``backend_fail``.

    Upsert by ``account_id``: increments ``attempt_count`` on an existing
    row, inserts a fresh row at attempt 1 when none exists. ``last_error``
    is the short class-name of the failure (NEVER raw error text). Returns
    the row shape post-update.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT attempt_count, paused FROM style_distill_queue "
        "WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if existing is None:
        attempt = 1
    else:
        if int(existing["paused"]):
            # Paused rows don't auto-retry; operator must unpause.
            return {
                "account_id": int(account_id),
                "attempt_count": int(existing["attempt_count"]),
                "next_retry_at": None,
                "last_error": last_error,
                "paused": True,
            }
        attempt = int(existing["attempt_count"]) + 1
    next_retry = _style_distill_compute_next_retry(attempt)
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (
                int(account_id), attempt, next_retry,
                last_error, now, now,
            ),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue SET "
            "  attempt_count = ?, "
            "  next_retry_at = ?, "
            "  last_error = ?, "
            "  last_attempt_at = ? "
            "WHERE account_id = ?",
            (attempt, next_retry, last_error, now, int(account_id)),
        )
    conn.commit()
    return {
        "account_id": int(account_id),
        "attempt_count": attempt,
        "next_retry_at": next_retry,
        "last_error": last_error,
        "paused": False,
    }


def pause_style_distill_account(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    last_error: str,
) -> None:
    """Mark a queue row paused after ``scrubber_fail``.

    Retrying a leaky LLM does not help; the account stays out of the
    auto-retry loop until operator intervention. Admin UI surfaces
    paused accounts in a banner.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT account_id FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, 1, NULL, ?, ?, 1, ?)",
            (int(account_id), last_error, now, now),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue SET "
            "  paused = 1, next_retry_at = NULL, "
            "  last_error = ?, last_attempt_at = ? "
            "WHERE account_id = ?",
            (last_error, now, int(account_id)),
        )
    conn.commit()


def unpause_style_distill_account(
    conn: sqlite3.Connection, *, account_id: int,
) -> None:
    """Operator action: clear the paused flag + reset attempt_count.

    Used when an operator has investigated a scrubber-paused account
    + wants it back in the retry loop (e.g. swapped backends).
    """
    conn.execute(
        "UPDATE style_distill_queue SET "
        "  paused = 0, attempt_count = 0, next_retry_at = NULL, "
        "  last_error = NULL "
        "WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()


def clear_style_distill_queue_entry(
    conn: sqlite3.Connection, *, account_id: int,
) -> None:
    """Remove a queue row after a successful distill.

    Idempotent — second call on the same account is a no-op.
    """
    conn.execute(
        "DELETE FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()


def get_style_distill_queue_entry(
    conn: sqlite3.Connection, *, account_id: int,
) -> dict | None:
    """Return the queue row for an account, or None."""
    row = conn.execute(
        "SELECT * FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    return dict(row) if row else None


def list_paused_style_distill_accounts(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return all paused queue rows, joined with account name.

    Used by the admin banner that warns "the following accounts have
    paused style learning (scrubber rejected the descriptor)".
    """
    rows = conn.execute(
        "SELECT q.*, ea.name AS account_name "
        "FROM style_distill_queue q "
        "LEFT JOIN email_accounts ea ON ea.id = q.account_id "
        "WHERE q.paused = 1 "
        "ORDER BY q.last_attempt_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def claim_next_style_distill_queue_entry(
    conn: sqlite3.Connection,
) -> dict | None:
    """Pick the oldest queue row whose ``next_retry_at`` is in the past.

    Returns None when no row is ready. The worker calls this on a
    short polling loop; SQLite's single-writer guarantee makes the
    poll-and-update sequence safe.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT * FROM style_distill_queue "
        "WHERE paused = 0 AND next_retry_at IS NOT NULL "
        "  AND next_retry_at <= ? "
        "ORDER BY next_retry_at ASC LIMIT 1",
        (now,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Per-contact HIPAA style descriptors (#152 phase 4 / M-7 — Wave 3)
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

#: Per-contact GC cut-off. Rows older than this with no re-distill
#: trigger get deleted by the daily sweep. Matches the punch spec
#: ("operator may have stopped emailing that contact").
HIPAA_PER_CONTACT_GC_DAYS = 90

#: Minimum sent-message count to a single recipient before a per-contact
#: distill fires. Caller responsibility — the trigger logic lives in
#: whichever surface watches the sent-mail stream. The constant is here
#: so call sites stay in sync.
HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES = 20


def get_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> dict | None:
    """Return the per-contact descriptor row, or None.

    Shape::

        {
            "descriptor": <dict>,        # parsed descriptor_json
            "version": <int>,
            "message_count": <int>,
            "last_distilled_at": <iso8601 str>,
            "last_updated": <iso8601 str>,
            "scrubber_outcome": <str>,
        }

    Tolerant of corrupt JSON (returns None) so a hand-edit / legacy
    shape doesn't crash the draft-time look-up.
    """
    import json as _json
    if not recipient_hash:
        return None
    row = conn.execute(
        "SELECT descriptor_json, descriptor_version, message_count, "
        "       last_distilled_at, last_updated, scrubber_outcome "
        "FROM per_contact_style_hipaa "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash)),
    ).fetchone()
    if row is None:
        return None
    try:
        descriptor = _json.loads(
            row["descriptor_json"] if hasattr(row, "keys") else row[0]
        )
    except (ValueError, TypeError):
        return None
    if not isinstance(descriptor, dict):
        return None
    return {
        "descriptor": descriptor,
        "version": int(
            row["descriptor_version"] if hasattr(row, "keys") else row[1]
        ),
        "message_count": int(
            row["message_count"] if hasattr(row, "keys") else row[2]
        ),
        "last_distilled_at": (
            row["last_distilled_at"] if hasattr(row, "keys") else row[3]
        ),
        "last_updated": (
            row["last_updated"] if hasattr(row, "keys") else row[4]
        ),
        "scrubber_outcome": (
            row["scrubber_outcome"] if hasattr(row, "keys") else row[5]
        ),
    }


def set_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    descriptor: dict,
    version: int,
    message_count: int,
    scrubber_outcome: str = "clean",
) -> None:
    """Persist (UPSERT) a scrubbed per-contact descriptor.

    Callers MUST hash the recipient via
    :func:`email_triage.style_learning.hash_recipient_for_install`
    before calling — this helper does NOT accept a plaintext address.
    The ``recipient_hash`` parameter is enforced to look like a 64-hex
    SHA-256 digest; anything else raises ``ValueError`` to catch the
    "accidentally passed the plaintext address" mistake.
    """
    import json as _json
    from datetime import datetime, timezone
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    if not isinstance(recipient_hash, str):
        raise ValueError("recipient_hash must be a string")
    h = recipient_hash.lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError(
            "recipient_hash must be a 64-char lowercase SHA-256 hex digest"
        )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO per_contact_style_hipaa "
        "(account_id, recipient_hash, descriptor_json, "
        " descriptor_version, message_count, "
        " last_distilled_at, last_updated, scrubber_outcome) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id, recipient_hash) DO UPDATE SET "
        "  descriptor_json    = excluded.descriptor_json, "
        "  descriptor_version = excluded.descriptor_version, "
        "  message_count      = excluded.message_count, "
        "  last_distilled_at  = excluded.last_distilled_at, "
        "  last_updated       = excluded.last_updated, "
        "  scrubber_outcome   = excluded.scrubber_outcome",
        (
            int(account_id),
            h,
            _json.dumps(descriptor),
            int(version),
            int(message_count),
            now,
            now,
            str(scrubber_outcome or "clean"),
        ),
    )
    conn.commit()


def delete_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Remove a single per-contact descriptor row (idempotent)."""
    conn.execute(
        "DELETE FROM per_contact_style_hipaa "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()


def delete_all_per_contact_style_hipaa(
    conn: sqlite3.Connection, *, account_id: int,
) -> int:
    """Clear every per-contact descriptor for an account.

    Used by the operator "Clear style data" surface (when one exists)
    and during account deletion paths that want belt-and-braces over
    the ON DELETE CASCADE. Returns the rowcount.
    """
    cur = conn.execute(
        "DELETE FROM per_contact_style_hipaa WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()
    return cur.rowcount


def list_per_contact_style_hipaa_for_account(
    conn: sqlite3.Connection, *, account_id: int,
) -> list[dict]:
    """Return per-contact rows (hashes + metadata, NOT the descriptor JSON).

    Used by the operator admin surface listing "we have style data for
    N recurring contacts on this account". The descriptor JSON is
    intentionally omitted — caller asks for one specific hash to read
    the full descriptor.
    """
    rows = conn.execute(
        "SELECT recipient_hash, descriptor_version, message_count, "
        "       last_distilled_at, last_updated, scrubber_outcome "
        "FROM per_contact_style_hipaa WHERE account_id = ? "
        "ORDER BY last_distilled_at DESC",
        (int(account_id),),
    ).fetchall()
    return [dict(r) for r in rows]


def gc_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    gc_days: int | None = None,
    now: "datetime | None" = None,
) -> int:
    """Delete per-contact descriptors older than ``gc_days`` since
    last distill. Returns the count of removed rows.

    Daily sweep — sibling to :func:`baa_expiry_daily_sweep`. The
    cut-off defaults to :data:`HIPAA_PER_CONTACT_GC_DAYS` (90 days);
    callers may override for tests. Idempotent — a re-run on a clean
    DB returns 0.

    Per the punch spec: "operator may have stopped emailing that
    contact". A row with no re-distill in 90 days means no new mail
    has crossed the trigger threshold; the overlay is stale + the
    hash storage is no longer earning its keep.
    """
    from datetime import datetime, timezone, timedelta
    days = HIPAA_PER_CONTACT_GC_DAYS if gc_days is None else int(gc_days)
    base = now or datetime.now(timezone.utc)
    cutoff = (base - timedelta(days=days)).isoformat()
    cur = conn.execute(
        "DELETE FROM per_contact_style_hipaa "
        "WHERE last_distilled_at < ?",
        (cutoff,),
    )
    conn.commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# style_distill_queue_contacts — per-contact retry queue (v28)
#
# Sibling to ``style_distill_queue`` (v27) but keyed on
# ``(account_id, recipient_hash)``. The two queues are processed by the
# same worker but the helpers are distinct so the v27 helpers (one row
# per account) don't grow conditional args.
# ---------------------------------------------------------------------------

def enqueue_style_distill_contact_retry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    last_error: str | None,
) -> dict:
    """Schedule a per-contact distill retry after a ``backend_fail``.

    Same exponential-backoff schedule as the account-level queue
    (:data:`STYLE_DISTILL_BACKOFF_SECONDS`). Upsert by ``(account_id,
    recipient_hash)``.
    """
    from datetime import datetime, timezone
    if not recipient_hash:
        raise ValueError("recipient_hash required")
    h = str(recipient_hash).lower()
    if len(h) != 64:
        raise ValueError(
            "recipient_hash must be a 64-char SHA-256 hex digest"
        )
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT attempt_count, paused FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    ).fetchone()
    if existing is None:
        attempt = 1
    else:
        if int(existing["paused"]):
            return {
                "account_id": int(account_id),
                "recipient_hash": h,
                "attempt_count": int(existing["attempt_count"]),
                "next_retry_at": None,
                "last_error": last_error,
                "paused": True,
            }
        attempt = int(existing["attempt_count"]) + 1
    next_retry = _style_distill_compute_next_retry(attempt)
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue_contacts "
            "(account_id, recipient_hash, attempt_count, next_retry_at, "
            " last_error, last_attempt_at, paused, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (
                int(account_id), h, attempt, next_retry,
                last_error, now, now,
            ),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue_contacts SET "
            "  attempt_count = ?, "
            "  next_retry_at = ?, "
            "  last_error = ?, "
            "  last_attempt_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (attempt, next_retry, last_error, now, int(account_id), h),
        )
    conn.commit()
    return {
        "account_id": int(account_id),
        "recipient_hash": h,
        "attempt_count": attempt,
        "next_retry_at": next_retry,
        "last_error": last_error,
        "paused": False,
    }


def pause_style_distill_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    last_error: str,
) -> None:
    """Pause a per-contact queue row after ``scrubber_fail``.

    The account-level row stays active; only THIS contact pauses.
    Operator clears via :func:`unpause_style_distill_contact`.
    """
    from datetime import datetime, timezone
    h = str(recipient_hash).lower()
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT 1 FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue_contacts "
            "(account_id, recipient_hash, attempt_count, next_retry_at, "
            " last_error, last_attempt_at, paused, created_at) "
            "VALUES (?, ?, 1, NULL, ?, ?, 1, ?)",
            (int(account_id), h, last_error, now, now),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue_contacts SET "
            "  paused = 1, next_retry_at = NULL, "
            "  last_error = ?, last_attempt_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (last_error, now, int(account_id), h),
        )
    conn.commit()


def unpause_style_distill_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Operator action: clear paused flag for a specific contact row."""
    conn.execute(
        "UPDATE style_distill_queue_contacts SET "
        "  paused = 0, attempt_count = 0, next_retry_at = NULL, "
        "  last_error = NULL "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()


def clear_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Remove a per-contact queue row after a successful distill.

    Idempotent — second call on the same key is a no-op.
    """
    conn.execute(
        "DELETE FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()


def get_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> dict | None:
    """Return the per-contact queue row for ``(account, contact)``, or None."""
    row = conn.execute(
        "SELECT * FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    ).fetchone()
    return dict(row) if row else None


def list_paused_style_distill_contacts(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return all paused per-contact queue rows joined with account name.

    Sibling to :func:`list_paused_style_distill_accounts`. Plaintext
    recipient is NEVER joined in — the row stores only the hash.
    """
    rows = conn.execute(
        "SELECT q.*, ea.name AS account_name "
        "FROM style_distill_queue_contacts q "
        "LEFT JOIN email_accounts ea ON ea.id = q.account_id "
        "WHERE q.paused = 1 "
        "ORDER BY q.last_attempt_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def claim_next_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
) -> dict | None:
    """Pick the oldest per-contact queue row whose ``next_retry_at`` is past.

    Sibling to :func:`claim_next_style_distill_queue_entry`. Worker
    polls both queues on each tick.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT * FROM style_distill_queue_contacts "
        "WHERE paused = 0 AND next_retry_at IS NOT NULL "
        "  AND next_retry_at <= ? "
        "ORDER BY next_retry_at ASC LIMIT 1",
        (now,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# hipaa_send_counters — HIPAA outbound-message counters for the M-3 + M-7
# trigger watchers (#171-B / v29).
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
    from datetime import datetime, timezone
    h = _validate_recipient_hash_or_aggregate(recipient_hash)
    if h == HIPAA_SEND_COUNTER_AGGREGATE_HASH:
        # The caller asked us to bump ONLY the aggregate — unusual
        # (production callers always bump both via the higher-level
        # wrapper) but allow it for test ergonomics. Skip the
        # double-write.
        targets = (h,)
    else:
        targets = (h, HIPAA_SEND_COUNTER_AGGREGATE_HASH)
    now = datetime.now(timezone.utc).isoformat()
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
    conn.commit()


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
        "count": int(row["count"] if hasattr(row, "keys") else row[0]),
        "first_seen_at": (
            row["first_seen_at"] if hasattr(row, "keys") else row[1]
        ),
        "last_seen_at": (
            row["last_seen_at"] if hasattr(row, "keys") else row[2]
        ),
    }


def reset_hipaa_send_counter(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str = HIPAA_SEND_COUNTER_AGGREGATE_HASH,
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
                r["recipient_hash"] if hasattr(r, "keys") else r[0]
            ),
            "count": int(r["count"] if hasattr(r, "keys") else r[1]),
            "first_seen_at": (
                r["first_seen_at"] if hasattr(r, "keys") else r[2]
            ),
            "last_seen_at": (
                r["last_seen_at"] if hasattr(r, "keys") else r[3]
            ),
        }
        for r in rows
    ]


def last_successful_style_distill_at(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    kind: str = "account_m3",
    recipient_hash: str | None = None,
) -> str | None:
    """Return the ISO timestamp of the most-recent successful distill, or None.

    Reads ``style_distill_events``. ``outcome='success'`` AND
    (when applicable) the matching ``recipient_hash`` filter:

      * ``kind='account_m3'``:  recipient_hash IS NULL filter.
      * ``kind='per_contact'``: recipient_hash = <hash> filter.

    Returns None when no qualifying row exists (first-time trigger
    fires on this).
    """
    where_parts = [
        "account_id = ?",
        "kind = ?",
        "outcome = 'success'",
    ]
    params: list = [int(account_id), str(kind)]
    if kind == "per_contact":
        if recipient_hash is None:
            raise ValueError(
                "recipient_hash required for kind='per_contact'"
            )
        h = _validate_recipient_hash_or_aggregate(recipient_hash)
        if h == HIPAA_SEND_COUNTER_AGGREGATE_HASH:
            raise ValueError(
                "recipient_hash sentinel '' not valid for "
                "kind='per_contact' lookup"
            )
        where_parts.append("recipient_hash = ?")
        params.append(h)
    else:
        where_parts.append("recipient_hash IS NULL")
    sql = (
        "SELECT ts FROM style_distill_events "
        "WHERE " + " AND ".join(where_parts) + " "
        "ORDER BY ts DESC LIMIT 1"
    )
    row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    return row["ts"] if hasattr(row, "keys") else row[0]


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


def get_global_anti_ai_style_guide(conn: sqlite3.Connection) -> str:
    """Return the install-wide anti-AI style guide string.

    Returns the empty string when the row is missing or the stored
    value isn't a plain string (defensive: a hand-edit / legacy dict
    shape will not crash the prompt build).
    """
    from email_triage.web.settings_keys import ANTI_AI_STYLE_GUIDE_GLOBAL
    raw = get_setting(conn, ANTI_AI_STYLE_GUIDE_GLOBAL)
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    # Defensive: settings table can hold any JSON shape. A dict written
    # by an older code path collapses to empty rather than leaking
    # ``{"value": "..."}``-style ugliness into the LLM prompt.
    return ""


def set_global_anti_ai_style_guide(
    conn: sqlite3.Connection, text: str,
) -> None:
    """Persist the install-wide anti-AI style guide (upsert).

    Stores a plain JSON string (no dict wrapper). Empty / whitespace-only
    input is normalised to the empty string so a "clear the field"
    operator action takes effect immediately.
    """
    from email_triage.web.settings_keys import ANTI_AI_STYLE_GUIDE_GLOBAL
    cleaned = (text or "").strip()
    set_setting(conn, ANTI_AI_STYLE_GUIDE_GLOBAL, cleaned)


def get_user_anti_ai_style_guide(
    conn: sqlite3.Connection, user_id: int | None,
) -> tuple[str, bool]:
    """Return ``(user_text, disable_global)`` for the user.

    Returns ``("", False)`` when ``user_id`` is missing or the columns
    haven't been added yet (pre-v20 DB). The disable flag is forced to
    False on a None user so an anonymous prompt-build path doesn't
    accidentally suppress the install-wide guide.
    """
    if not user_id:
        return ("", False)
    try:
        row = conn.execute(
            "SELECT anti_ai_style_guide_user, "
            "       anti_ai_style_guide_disable_global "
            "FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v20 DB — columns don't exist yet.
        return ("", False)
    if row is None:
        return ("", False)
    text = ""
    disable = False
    try:
        text = str(row["anti_ai_style_guide_user"] or "")
        disable = bool(row["anti_ai_style_guide_disable_global"])
    except (KeyError, IndexError, TypeError):
        # Defensive: row factory may not return mapping-style rows in
        # some test fixtures; fall back to the empty defaults.
        return ("", False)
    return (text, disable)


def set_user_anti_ai_style_guide(
    conn: sqlite3.Connection, user_id: int, *,
    text: str, disable_global: bool,
) -> None:
    """Persist the per-user anti-AI guide + disable-global flag."""
    cleaned = (text or "").strip()
    conn.execute(
        "UPDATE users SET "
        "  anti_ai_style_guide_user = ?, "
        "  anti_ai_style_guide_disable_global = ? "
        "WHERE id = ?",
        (cleaned, 1 if disable_global else 0, int(user_id)),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Style-data summary helpers (M-8)
#
# Read-only counts and metadata for the /profile/style-data page. We
# defensively probe for the ``sent_mail_index`` table because M-4
# ships in a parallel branch — the helpers degrade to zero counts when
# the table is absent (fresh install on this branch / pre-M-4 data
# directory) so the page renders the empty state instead of crashing.
# ---------------------------------------------------------------------------

def _has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    """True when ``table_name`` exists in the SQLite schema."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _has_column(
    conn: sqlite3.Connection, table_name: str, column_name: str,
) -> bool:
    """True when ``column_name`` exists on ``table_name``."""
    if not _has_table(conn, table_name):
        return False
    rows = conn.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()
    for r in rows:
        # PRAGMA returns (cid, name, type, notnull, dflt_value, pk)
        name = r[1] if not hasattr(r, "keys") else r["name"]
        if name == column_name:
            return True
    return False


def get_sent_mail_index_summary(
    conn: sqlite3.Connection, account_id: int,
) -> dict:
    """Summarise the sent-mail-index rows for ``account_id``.

    Returns a dict shaped for the /profile/style-data page:

    * ``count``: total indexed rows (0 if table absent or no rows).
    * ``oldest``: ISO timestamp of the oldest sent_at, or None.
    * ``newest``: ISO timestamp of the newest sent_at, or None.
    * ``embedding_model``: most-recently-used embedding model name,
      or empty string.
    * ``sample_subjects``: up to 3 subjects (caller redacts under
      HIPAA; this helper does NOT redact — gating is at the route).
    * ``available``: True when the M-4 table exists. False is the
      "feature not installed yet" signal the template uses to hide
      the section entirely.
    """
    out: dict = {
        "count": 0,
        "oldest": None,
        "newest": None,
        "embedding_model": "",
        "sample_subjects": [],
        "available": False,
    }
    if not _has_table(conn, "sent_mail_index"):
        return out
    out["available"] = True

    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(sent_at) AS oldest, "
        "       MAX(sent_at) AS newest "
        "FROM sent_mail_index WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    if row is not None:
        out["count"] = int(
            row["n"] if hasattr(row, "keys") else row[0],
        )
        out["oldest"] = (
            row["oldest"] if hasattr(row, "keys") else row[1]
        )
        out["newest"] = (
            row["newest"] if hasattr(row, "keys") else row[2]
        )

    if out["count"] == 0:
        return out

    # Most-recent embedding model name (an account could have rows from
    # multiple models if the operator swapped backends; we surface the
    # newest). One row is plenty.
    model_row = conn.execute(
        "SELECT embedding_model FROM sent_mail_index "
        "WHERE account_id = ? "
        "ORDER BY indexed_at DESC LIMIT 1",
        (account_id,),
    ).fetchone()
    if model_row is not None:
        out["embedding_model"] = (
            (model_row["embedding_model"]
             if hasattr(model_row, "keys")
             else model_row[0]) or ""
        )

    sample_rows = conn.execute(
        "SELECT subject FROM sent_mail_index "
        "WHERE account_id = ? "
        "ORDER BY sent_at DESC LIMIT 3",
        (account_id,),
    ).fetchall()
    out["sample_subjects"] = [
        (r["subject"] if hasattr(r, "keys") else r[0]) or "(no subject)"
        for r in sample_rows
    ]
    return out


def get_captured_pair_count(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Count rows where ``is_captured_pair = 1`` for ``account_id``.

    M-6 (the capture loop) ships this column in a parallel branch.
    Until that lands, the column is absent and this helper returns 0.
    Defence-in-depth: even when the column exists, missing-row counts
    return 0 instead of raising.
    """
    if not _has_column(conn, "sent_mail_index", "is_captured_pair"):
        return 0
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM sent_mail_index "
            "WHERE account_id = ? AND is_captured_pair = 1",
            (account_id,),
        ).fetchone()
    except sqlite3.Error:
        return 0
    if row is None:
        return 0
    return int(row["n"] if hasattr(row, "keys") else row[0])


def delete_sent_mail_index_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Drop every sent_mail_index row for ``account_id``.

    Mirrors :meth:`SentMailIndex.delete_account_index` but stays
    DB-only so the /profile/style-data delete path doesn't need to
    instantiate the M-4 helper (which requires an embedding backend).
    Returns the number of rows deleted (0 when the table is absent).
    """
    if not _has_table(conn, "sent_mail_index"):
        return 0
    cur = conn.execute(
        "DELETE FROM sent_mail_index WHERE account_id = ?",
        (account_id,),
    )
    conn.commit()
    try:
        return int(cur.rowcount or 0)
    except Exception:
        return 0


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

def is_style_learning_per_contact_enabled(account: dict | None) -> bool:
    """Return the per-account "match by recipient" sub-toggle.

    Read from ``account.config["style_learning_per_contact_enabled"]``.
    Default is True (on) -- the privacy-neutral refinement of an
    already-opted-in M-4 surface. The HIPAA gate at
    :class:`SentMailIndex` short-circuits regardless of this value;
    this flag is the operator UX surface only.
    """
    if account is None:
        return False
    cfg = account.get("config") if isinstance(account, dict) else None
    if not isinstance(cfg, dict):
        return True
    val = cfg.get("style_learning_per_contact_enabled")
    if val is None:
        return True
    return bool(val)


# ---------------------------------------------------------------------------
# Dashboard helpers (#12)
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
        d["results"] = json.loads(d.pop("results_json", "[]"))
        d["errors"] = json.loads(d.pop("errors_json", "[]"))
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
        for entry in json.loads(r["results_json"] or "[]"):
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
# Multi-label per message (#129)
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
    return [dict(r) for r in rows]


def get_label(conn: sqlite3.Connection, slug: str) -> dict | None:
    """Return one label row by slug, or None."""
    row = conn.execute(
        "SELECT slug, name, color, created_by_user_id, "
        "       created_at, updated_at "
        "FROM labels WHERE slug = ?",
        (slug,),
    ).fetchone()
    return dict(row) if row else None


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    color = (color or "").strip() or "#6c757d"
    conn.execute(
        "INSERT INTO labels (slug, name, color, created_by_user_id, "
        "                    created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (slug, name, color, created_by_user_id, now, now),
    )
    conn.commit()
    return slug


def update_label(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    color: str,
) -> bool:
    """Update name + color on an existing label. Returns True if
    a row was updated."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    color = (color or "").strip() or "#6c757d"
    cursor = conn.execute(
        "UPDATE labels SET name = ?, color = ?, updated_at = ? "
        "WHERE slug = ?",
        (name, color, now, slug),
    )
    conn.commit()
    return cursor.rowcount > 0


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    rules-page snapshot (#129). Kept here so non-template consumers
    (apply phase, tests) can pull the same shape without re-parsing.
    """
    import json as _json
    row = conn.execute(
        "SELECT provider_labels FROM list_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    if row is None:
        return []
    raw = row["provider_labels"] if hasattr(row, "keys") else row[0]
    if not raw:
        return []
    try:
        parsed = _json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
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
    payload = _json.dumps(cleaned) if cleaned else None
    conn.execute(
        "UPDATE list_rules SET provider_labels = ? WHERE id = ?",
        (payload, rule_id),
    )
    conn.commit()


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
    return [dict(r) for r in rows]


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
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# AI backends catalog (migration v26 — #169 Wave 2-α I3 + I6)
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
        "       baa_certified, baa_expires_at, enabled, "
        "       created_by, created_at "
        "FROM ai_backends"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY name"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_ai_backend(
    conn: sqlite3.Connection, backend_id: int,
) -> dict | None:
    """Return a single ``ai_backends`` row by id, or None."""
    row = conn.execute(
        "SELECT id, name, type, endpoint, api_key_secret_ref, model, "
        "       baa_certified, baa_expires_at, enabled, "
        "       created_by, created_at "
        "FROM ai_backends WHERE id = ?",
        (int(backend_id),),
    ).fetchone()
    return dict(row) if row is not None else None


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
) -> int:
    """Insert a new row and return its id.

    Raises ``sqlite3.IntegrityError`` when:
      * ``name`` already in use (UNIQUE)
      * ``type_`` is not in the CHECK enum
      * ``baa_certified=1`` but ``baa_expires_at`` is empty (CHECK)
    The router catches these + re-renders the form with the message.
    """
    cur = conn.execute(
        "INSERT INTO ai_backends "
        "(name, type, endpoint, api_key_secret_ref, model, "
        " baa_certified, baa_expires_at, enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            name,
            type_,
            endpoint,
            api_key_secret_ref,
            model,
            int(bool(baa_certified)),
            baa_expires_at,
            int(bool(enabled)),
            created_by,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


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
        "  baa_certified = ?, baa_expires_at = ?, "
        "  enabled = ? "
        "WHERE id = ?",
        (
            name,
            type_,
            endpoint,
            api_key_secret_ref,
            model,
            int(bool(baa_certified)),
            baa_expires_at,
            int(bool(enabled)),
            int(backend_id),
        ),
    )
    conn.commit()
    return cur.rowcount > 0


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
    return int(row["n"] if hasattr(row, "keys") else row[0])


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
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------
# watcher_retry_queue — per-message retry queue (#175 R-A, v30)
# ---------------------------------------------------------------------------
#
# Per-message exception handler for the watcher / push consumer / poll
# loop. Where ``triage_retry_queue`` (v16) parks messages whose CLASSIFY
# step failed because the LLM backend was offline, this queue parks
# messages whose per-message FETCH / PROCESS step raised an exception
# (IMAP fetch timeout, transient provider 5xx, network blip, etc.).
#
# Schema lives in migration v30. Addressing is provider-specific
# (mailbox+uid+uidvalidity for IMAP, gmail_msg_id for Gmail,
# o365_msg_id for O365). The state machine is pending → done / dead.
#
# Privacy
# -------
# ``last_error_msg`` is PHI-scrubbed before INSERT (see
# :data:`_WATCHER_RETRY_TOKEN_KEYS`). HIPAA accounts may have provider
# error responses that incidentally carry PHI; we scrub at the
# persistence boundary regardless of the account's HIPAA flag.

#: Maximum length of ``last_error_msg`` before truncation. 500 chars
#: is enough to identify the error shape but small enough that a
#: provider-side stacktrace can't bloat the row.
_WATCHER_RETRY_LAST_ERROR_MAX = 500

#: Token-shaped keys to strip from any embedded dict in the error
#: message. Mirrors :data:`email_triage.triage_logging.TriageLogger._TOKEN_KEYS`
#: but kept inline so this module is self-contained (web/db.py is
#: imported from many places + adding a triage_logging dependency
#: at module-import time risks an import cycle).
_WATCHER_RETRY_TOKEN_KEYS: frozenset[str] = frozenset({
    "authorization", "access_token", "refresh_token", "id_token",
    "code", "auth_code", "client_secret", "bearer_token",
    "api_key", "password", "smtp_password", "imap_password",
    "session_token",
})

#: Valid ``dead_reason`` values. The sweeper sets exactly one of
#: these when transitioning a row to state='dead'.
WATCHER_RETRY_DEAD_REASONS: frozenset[str] = frozenset({
    "max_attempts_exceeded",
    "uidvalidity_changed",
    "message_gone",
    "auth_revoked",
    "operator_abandoned",
})


def _scrub_watcher_retry_error_msg(msg: str | None) -> str | None:
    """Return a PHI-scrubbed + truncated copy of ``msg``.

    The scrub is a best-effort token-shape strip: any substring of
    the form ``<key>: "value"``, ``<key>='value'``, ``"<key>": value``,
    etc. is replaced with the key + ``[REDACTED]``. This catches the
    common shapes (dict-repr, urlencoded form, kwargs-style) from
    provider clients (e.g.
    ``OAuthError: {'access_token': '...'}`` or
    ``... refresh_token='abc' ...``) without trying to parse arbitrary
    exception text — which is a losing game.

    After scrubbing, the result is truncated to
    :data:`_WATCHER_RETRY_LAST_ERROR_MAX` characters.
    """
    if msg is None:
        return None
    import re
    out = str(msg)
    for key in _WATCHER_RETRY_TOKEN_KEYS:
        # Two shapes we catch:
        #   "key": "value"         (dict-repr / JSON)
        #   key='value' / key=...  (kwargs / urlencoded)
        # Both produce the same redacted output.
        ek = re.escape(key)
        # Shape 1: quoted key + colon + quoted value.
        out = re.sub(
            r"(['\"]" + ek + r"['\"]\s*:\s*['\"])"
            r"[^'\"]*"
            r"(['\"])",
            r"\1[REDACTED]\2",
            out,
            flags=re.IGNORECASE,
        )
        # Shape 2: bare key followed by = and quoted value.
        out = re.sub(
            r"(\b" + ek + r"\s*=\s*['\"])"
            r"[^'\"]*"
            r"(['\"])",
            r"\1[REDACTED]\2",
            out,
            flags=re.IGNORECASE,
        )
        # Shape 3: bare key followed by = and bare value (no quotes).
        # Bound the value at whitespace / common delimiters so we
        # don't gobble the rest of the message.
        out = re.sub(
            r"(\b" + ek + r"\s*=\s*)"
            r"[^\s,;&)}\]]+",
            r"\1[REDACTED]",
            out,
            flags=re.IGNORECASE,
        )
    if len(out) > _WATCHER_RETRY_LAST_ERROR_MAX:
        out = out[: _WATCHER_RETRY_LAST_ERROR_MAX - 3] + "..."
    return out


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
) -> int:
    """Insert (or bump) a row in ``watcher_retry_queue``.

    Addressing semantics
    --------------------
    Exactly one provider-specific addressing tuple must be populated:

    * ``provider_type='imap'`` → ``mailbox``, ``uid``, ``uidvalidity``
      all required.
    * ``provider_type='gmail'`` → ``gmail_msg_id`` required.
    * ``provider_type='office365'`` → ``o365_msg_id`` required.

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
        The row id (``triage_retry_queue.id``).
    """
    from datetime import datetime, timezone
    from email_triage.retry_backoff import (
        WATCHER_RETRY_SCHEDULE, compute_next_attempt_at,
    )

    # Validate provider_type addressing.
    pt = (provider_type or "").lower().strip()
    if pt == "imap":
        if mailbox is None or uid is None or uidvalidity is None:
            raise ValueError(
                "enqueue_retry: provider_type='imap' requires mailbox, "
                "uid, uidvalidity"
            )
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
    now_iso = datetime.now(timezone.utc).isoformat()

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
            conn.execute(
                "UPDATE watcher_retry_queue SET "
                "  attempt_count=?, next_attempt_at=?, "
                "  last_error_class=?, last_error_msg=?, last_error_at=? "
                "WHERE id=?",
                (
                    new_count, next_dt.isoformat(),
                    str(error_class), scrubbed_msg, now_iso,
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
            "  last_error_at=?, resolved_at=NULL, dead_reason=NULL "
            "WHERE id=?",
            (
                next_dt.isoformat(),
                str(error_class), scrubbed_msg, now_iso,
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
        "  state, attempt_count, "
        "  next_attempt_at, "
        "  last_error_class, last_error_msg, last_error_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)",
        (
            int(account_id), pt,
            mailbox, (int(uid) if uid is not None else None),
            (int(uidvalidity) if uidvalidity is not None else None),
            gmail_msg_id, o365_msg_id,
            next_dt.isoformat(),
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
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT * FROM watcher_retry_queue "
        "WHERE state='pending' AND next_attempt_at <= ? "
        "ORDER BY next_attempt_at ASC LIMIT ?",
        (now_iso, int(limit)),
    ).fetchall()
    return list(rows)


def mark_retry_done(conn: sqlite3.Connection, retry_id: int) -> None:
    """Transition a row to ``state='done'``.

    Idempotent: re-marking a done / dead row is a no-op (the UPDATE
    has a ``WHERE state='pending'`` guard).
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE watcher_retry_queue "
        "SET state='done', resolved_at=? "
        "WHERE id=? AND state='pending'",
        (now_iso, int(retry_id)),
    )
    conn.commit()


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
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE watcher_retry_queue "
        "SET state='dead', dead_reason=?, resolved_at=? "
        "WHERE id=? AND state='pending'",
        (str(reason), now_iso, int(retry_id)),
    )
    conn.commit()


def get_retry(
    conn: sqlite3.Connection, retry_id: int,
) -> sqlite3.Row | None:
    """Return the row by id, or None."""
    return conn.execute(
        "SELECT * FROM watcher_retry_queue WHERE id=?",
        (int(retry_id),),
    ).fetchone()


def list_retries_for_admin(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    state: str | None = None,
    limit: int = 200,
) -> list[sqlite3.Row]:
    """List rows for the admin UI (consumed by R-B).

    Filters:
      * ``account_id`` — limit to one account (None = all accounts).
      * ``state`` — filter by state (None = all states).

    Ordering: most-recent first, by COALESCE(last_error_at, created_at).
    """
    clauses: list[str] = []
    params: list[Any] = []
    if account_id is not None:
        clauses.append("account_id = ?")
        params.append(int(account_id))
    if state is not None:
        clauses.append("state = ?")
        params.append(str(state))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    rows = conn.execute(
        f"SELECT * FROM watcher_retry_queue {where} "
        "ORDER BY COALESCE(last_error_at, created_at) DESC "
        "LIMIT ?",
        tuple(params),
    ).fetchall()
    return list(rows)


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
    cutoff_iso = (
        datetime.now(timezone.utc) - timedelta(hours=int(since_hours))
    ).isoformat()
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
    return int(row["c"] if hasattr(row, "keys") else row[0])
