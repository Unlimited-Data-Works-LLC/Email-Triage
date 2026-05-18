"""Numbered schema-migration framework.

The legacy approach (idempotent ``CREATE TABLE IF NOT EXISTS`` +
ad-hoc ``_column_exists()``-guarded ``ALTER TABLE`` helpers in
``init_db``) works for forward-only column additions but offers
nothing else: no version tracking, no rollback, no observability
into "what migrations has this install run." When a migration
half-applies (network blip mid-DDL, OOM during a data backfill),
there's no marker on disk that says "v17 is in progress" — the next
boot retries the whole thing and may hit constraint errors on rows
that the previous attempt already inserted.

This module ships a numbered registry plus a bookkeeping table.
Each migration is a function in ``MIGRATIONS`` keyed by an integer
version. ``run_migrations(conn)`` runs every migration whose version
is greater than what ``schema_migrations`` reports as currently
applied, each wrapped in ``BEGIN IMMEDIATE … COMMIT`` so a partial
failure rolls back to the prior version.

**Coexistence with legacy helpers.** The existing ``_apply_migrations``
+ ``ensure_*_migration`` helpers in ``db.py`` are the pre-framework
shape. They stay in place — re-implementing them all in one PR is
risky. The framework is additive: the legacy helpers run first (as
they always did), then ``run_migrations`` runs any registered
migrations on top. Future schema changes go through the framework
exclusively. Future PRs can absorb individual legacy helpers as
numbered migrations without breaking installs that have already
executed them via the legacy path (each migration body checks
``IF NOT EXISTS`` / column presence so re-running is a no-op).

**Idempotency requirement for migration bodies.** The framework
records "v17 applied" only after the body returns. A body that
half-applies (writes some rows, then raises) must leave the DB in
a state where re-running the body completes without error. In
practice: prefer ``CREATE TABLE IF NOT EXISTS`` over ``CREATE
TABLE``, prefer ``INSERT ... ON CONFLICT`` over plain ``INSERT``,
and check column presence before ``ALTER TABLE ADD COLUMN``.

**Checksum guard.** Each migration's body is hashed; the recorded
checksum must match the current code on subsequent runs. If a
shipped migration is later edited, the runner refuses to start —
catches the worst-case "I edited migration 12 in place after it
already ran on prod" mistake.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable


_log = logging.getLogger("email_triage.web.migrations")


# ---------------------------------------------------------------------------
# Bookkeeping table
# ---------------------------------------------------------------------------

_SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    applied_at TEXT    NOT NULL,
    checksum   TEXT    NOT NULL
)
"""


def _ensure_bookkeeping(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA_MIGRATIONS_DDL)
    conn.commit()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Migration:
    """One numbered migration. ``body(conn)`` does the work."""
    version: int
    name: str
    body: Callable[[sqlite3.Connection], None]

    def checksum(self) -> str:
        # Hash the source of body() so a future edit-after-ship
        # mistake surfaces. inspect.getsource may include indentation
        # whitespace — that's fine; hashing the literal string keeps
        # the comparison strict.
        src = inspect.getsource(self.body)
        return hashlib.sha256(src.encode("utf-8")).hexdigest()


# Module-level list of registered migrations. Append-only; numbers
# are stable identifiers and must never be re-used or re-ordered.
MIGRATIONS: list[Migration] = []


def register(version: int, name: str):
    """Decorator that registers a migration body.

    Usage::

        @register(1, "create_foo_table")
        def _v1(conn):
            conn.execute("CREATE TABLE IF NOT EXISTS foo (id INTEGER PRIMARY KEY)")

    Numbers must be unique and strictly ascending. The first time a
    duplicate or out-of-order registration is detected, the decorator
    raises at import time so the bug shows up at process start, not
    at first migration run.
    """

    def deco(func: Callable[[sqlite3.Connection], None]):
        if any(m.version == version for m in MIGRATIONS):
            raise RuntimeError(
                f"duplicate migration version {version!r} "
                f"({name!r}); numbers must be unique"
            )
        if MIGRATIONS and version <= MIGRATIONS[-1].version:
            raise RuntimeError(
                f"migration version {version!r} ({name!r}) does not "
                f"strictly increase past previous version "
                f"{MIGRATIONS[-1].version!r} ({MIGRATIONS[-1].name!r})"
            )
        MIGRATIONS.append(Migration(version=version, name=name, body=func))
        return func

    return deco


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class MigrationError(RuntimeError):
    """Raised when migration runner detects a fatal condition.

    Specifically: checksum mismatch (someone edited a shipped
    migration), version regression (DB at version > max-known), or
    a body raise that survives the rollback.
    """


def applied_versions(conn: sqlite3.Connection) -> dict[int, dict]:
    """Return ``{version: {name, applied_at, checksum}}``."""
    _ensure_bookkeeping(conn)
    rows = conn.execute(
        "SELECT version, name, applied_at, checksum FROM schema_migrations"
    ).fetchall()
    out: dict[int, dict] = {}
    for r in rows:
        # Row may be a sqlite3.Row or a tuple depending on row_factory.
        if hasattr(r, "keys"):
            out[r["version"]] = {
                "name": r["name"],
                "applied_at": r["applied_at"],
                "checksum": r["checksum"],
            }
        else:
            out[r[0]] = {"name": r[1], "applied_at": r[2], "checksum": r[3]}
    return out


def schema_version(conn: sqlite3.Connection) -> int:
    """Return the highest applied version, or 0 if none."""
    applied = applied_versions(conn)
    return max(applied.keys(), default=0)


def pending_migrations(conn: sqlite3.Connection) -> list[Migration]:
    """Return migrations registered but not yet applied, ordered."""
    applied = applied_versions(conn)
    return [m for m in MIGRATIONS if m.version not in applied]


def run_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply every registered migration whose version > current.

    Returns the list of versions applied during this call (empty if
    already up to date). Raises ``MigrationError`` on:

    * checksum mismatch for an already-applied version (someone
      edited a shipped migration body);
    * DB version > max registered (rollback to older code without
      a corresponding down-migration — refuse to run rather than
      pretend the schema is fine);
    * any exception inside a migration body (transaction rolls back,
      bookkeeping row is NOT written, error re-raises).
    """
    _ensure_bookkeeping(conn)
    applied = applied_versions(conn)

    # Guard 1: checksum verification on every already-applied row.
    for m in MIGRATIONS:
        if m.version in applied:
            current = m.checksum()
            recorded = applied[m.version]["checksum"]
            if current != recorded:
                raise MigrationError(
                    f"migration {m.version} ({m.name!r}) was edited "
                    f"after it was applied to this database. Recorded "
                    f"checksum {recorded[:16]}..., current "
                    f"{current[:16]}.... Refusing to run further "
                    f"migrations until this is reconciled."
                )

    # Guard 2: DB at a version newer than this code knows about.
    max_registered = max((m.version for m in MIGRATIONS), default=0)
    max_applied = max(applied.keys(), default=0)
    if max_applied > max_registered:
        raise MigrationError(
            f"database at schema version {max_applied} but this code "
            f"only knows up to {max_registered}. Roll back is not "
            f"supported automatically; reconcile manually before "
            f"starting this version."
        )

    # Apply pending migrations in order, each in its own transaction.
    applied_now: list[int] = []
    for m in pending_migrations(conn):
        _log.info(
            "applying migration",
            extra={"_extra": {"version": m.version, "name": m.name}},
        )
        try:
            conn.execute("BEGIN IMMEDIATE")
            m.body(conn)
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            conn.execute(
                "INSERT INTO schema_migrations "
                "(version, name, applied_at, checksum) "
                "VALUES (?, ?, ?, ?)",
                (m.version, m.name, now, m.checksum()),
            )
            conn.commit()
            applied_now.append(m.version)
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            _log.error(
                "migration failed; rolled back",
                extra={"_extra": {
                    "version": m.version,
                    "name": m.name,
                    "error_type": type(exc).__name__,
                }},
            )
            raise MigrationError(
                f"migration {m.version} ({m.name!r}) failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    return applied_now


# ---------------------------------------------------------------------------
# Registered migrations
# ---------------------------------------------------------------------------
#
# Future migrations append here. Numbers are stable forever; do not
# renumber, do not delete (write a v_n that reverses v_(n-k) instead).
#
# Existing legacy helpers in db.py (``ensure_categories_user_id_migration``,
# ``ensure_upgrade_categories``, ``migrate_oauth_creds_to_install_level``,
# the ``_apply_migrations`` ALTER TABLE block) are the pre-framework
# shape. They run from init_db on every boot (idempotent), and the
# framework runs after them. Future PRs can absorb individual legacy
# helpers as numbered migrations here; the v_n body should detect
# "already done by legacy path" via the same ``IF NOT EXISTS`` /
# column-presence checks the legacy code uses, so installs that ran
# the legacy path see a no-op when v_n applies.


@register(1, "framework_bootstrap")
def _v1_framework_bootstrap(conn: sqlite3.Connection) -> None:
    """First numbered migration: marks "framework is live on this DB".

    No schema change — the bookkeeping table itself is created by
    ``_ensure_bookkeeping``. This row exists so a fresh install has a
    visible v1 in ``schema_migrations`` and the operator can see at a
    glance that the framework ran.
    """
    # Intentionally empty body. The point is the bookkeeping row.
    pass


@register(2, "create_triage_jobs")
def _v2_create_triage_jobs(conn: sqlite3.Connection) -> None:
    """Background-triage job table for whole-mailbox runs.

    Synchronous /triage/run handles small batches (<=100 messages)
    inline. Larger sweeps need a background-job model: the HTTP
    request returns immediately with a job_id, a runner task drains
    the work over minutes-to-hours under operator-tunable rate +
    concurrency limits, and the UI polls a progress endpoint via
    HTMX for live status.

    Schema:
      job_id         TEXT PK   — ``tjob_<12-hex>`` UUID-style handle
      account_id     INTEGER   — FK to email_accounts.id
      actor_user_id  INTEGER   — who initiated (HIPAA audit trail)
      query          TEXT      — provider-native query string
      status         TEXT      — queued/running/cancelled/done/failed
      total_seen     INTEGER   — message IDs returned by provider
      total_processed INTEGER  — fetch+classify+act done count
      total_skipped  INTEGER   — loop-prevention header / dedup
      total_errors   INTEGER   — per-message exceptions
      rate_msg_per_min INTEGER — rate-limit setting at job creation
      concurrency    INTEGER   — semaphore size at job creation
      started_at     TEXT      — ISO 8601 (set when status=running)
      last_progress_at TEXT    — ISO 8601 (UI staleness check)
      ended_at       TEXT      — ISO 8601 (terminal status only)
      error_text     TEXT      — populated on status=failed
      created_at     TEXT      — ISO 8601 (always set on insert)

    Indexes:
      idx_triage_jobs_account_status — UI lists "running on this
        account?" + "recent jobs on this account"
      idx_triage_jobs_status — runner polls for queued jobs to drain
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS triage_jobs (
            job_id            TEXT PRIMARY KEY,
            account_id        INTEGER NOT NULL,
            actor_user_id     INTEGER,
            query             TEXT    NOT NULL,
            status            TEXT    NOT NULL DEFAULT 'queued',
            total_seen        INTEGER NOT NULL DEFAULT 0,
            total_processed   INTEGER NOT NULL DEFAULT 0,
            total_skipped     INTEGER NOT NULL DEFAULT 0,
            total_errors      INTEGER NOT NULL DEFAULT 0,
            rate_msg_per_min  INTEGER NOT NULL DEFAULT 30,
            concurrency       INTEGER NOT NULL DEFAULT 1,
            started_at        TEXT,
            last_progress_at  TEXT,
            ended_at          TEXT,
            error_text        TEXT,
            created_at        TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_triage_jobs_account_status
        ON triage_jobs(account_id, status)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_triage_jobs_status
        ON triage_jobs(status)
    """)


@register(3, "create_triage_job_messages")
def _v3_create_triage_job_messages(conn: sqlite3.Connection) -> None:
    """Per-job dedup record for whole-mailbox triage runs.

    Bulk runs need a record of "this job already handled this
    message" so resume-after-restart doesn't re-classify + re-act
    on already-processed mail (which double-fires non-idempotent
    actions like notify + draft_reply). The composite PK on
    (job_id, message_id) makes the existence check a primary-key
    lookup; INSERT OR IGNORE makes the write idempotent on a
    second-attempt pass that lost its in-memory state.

    Status column lets the runner distinguish processed (classified
    + acted) from skipped (loop-prevention header) from error
    (per-message exception). Aggregate counters on triage_jobs
    stay the source of truth for the UI; this table is the
    forensic + dedup record.

    Indexed on (job_id) for the bulk delete-on-cancel path; the
    PK already supports the per-message lookup.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS triage_job_messages (
            job_id        TEXT NOT NULL,
            message_id    TEXT NOT NULL,
            status        TEXT NOT NULL,
            processed_at  TEXT NOT NULL,
            PRIMARY KEY (job_id, message_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_triage_job_messages_job
        ON triage_job_messages(job_id)
    """)


@register(4, "add_triage_jobs_cursor")
def _v4_add_triage_jobs_cursor(conn: sqlite3.Connection) -> None:
    """High-water-mark resume cursor on triage_jobs.

    Step 8 made resume safe (already-processed messages get
    skipped via the dedup table). It did NOT make resume
    efficient — the runner re-walks the entire provider result
    set on resume, fetching every page just so the dedup gate
    can short-circuit each msg_id. For a 10k-mailbox sweep that
    crashed at 9000, resume re-issues the SEARCH + walks 9000
    UIDs through the dedup gate before reaching new work.

    The cursor column lets each provider stash an opaque resume
    handle. Format is provider-specific:

      IMAP:    string-encoded max UID processed (ascending walk)
      Gmail:   nextPageToken from messages.list
      O365:    fully-qualified @odata.nextLink URL with $skiptoken

    The runner reads the cursor on job entry, threads it into
    provider.search_iter(resume_cursor=...), and writes the
    new cursor back via update_triage_job_cursor after each
    batch. Crash mid-batch -> next start resumes from the
    last persisted cursor; dedup table catches any messages
    re-emitted by the provider between cursor-saves.

    Idempotent column add — skipped on installs where the
    column already exists (re-running the migration on a
    schema-edited DB shouldn't error)."""
    cur = conn.execute("PRAGMA table_info(triage_jobs)")
    existing = {row[1] for row in cur.fetchall()}
    if "cursor" not in existing:
        conn.execute("ALTER TABLE triage_jobs ADD COLUMN cursor TEXT")


@register(5, "digest_format_default_preview_off")
def _v5_flip_digest_preview_off(conn: sqlite3.Connection) -> None:
    """One-time flip: include_body_preview -> False on every stored
    custom-digest config.

    Operator feedback 2026-05-07: the per-row preview adds noise on
    content-aggregator newsletters where the subject already carries
    the headline. Default flipped to False on the dataclass; this
    migration brings every existing stored config in line so the
    default is consistent across new + old digests on the same
    install. Toggle stays available — operators who actually want
    the per-row context can re-enable per digest.

    Storage shape: digest_configs are stored as a JSON list under
    ``settings.value_json`` keyed by ``digest_configs:<account_id>``
    (one row per account). Each list entry is a dict; the preview
    flag lives at ``entry.format.include_body_preview``. Migration
    walks every settings row matching the prefix, parses the JSON,
    flips True -> False on each entry's format dict, and writes
    back the modified JSON.

    Idempotent — re-running finds nothing to flip (all entries
    already False) and is a no-op. Empty / malformed rows are left
    alone so a corrupt entry doesn't abort the migration.
    """
    import json
    from datetime import datetime, timezone

    cur = conn.execute(
        "SELECT key, value_json FROM settings "
        "WHERE key LIKE 'digest_configs:%'"
    )
    rows = cur.fetchall()
    now_iso = datetime.now(timezone.utc).isoformat()
    for r in rows:
        # row may be sqlite3.Row or tuple depending on row_factory
        key = r["key"] if hasattr(r, "keys") else r[0]
        raw = r["value_json"] if hasattr(r, "keys") else r[1]
        try:
            data = json.loads(raw) if raw else None
        except (TypeError, ValueError):
            continue
        if not isinstance(data, list):
            continue
        changed = False
        for entry in data:
            if not isinstance(entry, dict):
                continue
            fmt = entry.get("format")
            if not isinstance(fmt, dict):
                continue
            if fmt.get("include_body_preview") is True:
                fmt["include_body_preview"] = False
                changed = True
        if changed:
            conn.execute(
                "UPDATE settings SET value_json = ?, updated_at = ? "
                "WHERE key = ?",
                (json.dumps(data), now_iso, key),
            )


@register(6, "backfill_account_tz_default")
def _v6_backfill_account_tz_default(conn: sqlite3.Connection) -> None:
    """Default per-account timezone for calendar render enrichment.

    Punch-list #109 adds pre-rendered local-tz strings to the
    calendar API response so LLM-agent consumers don't have to
    do timezone arithmetic. The local strings are computed against
    a per-account ``tz`` field stored under ``email_accounts.config_json``.

    This migration backfills the default (``America/Detroit``) for
    every existing account row whose config_json does NOT already
    have a ``tz`` key. Future accounts get the default at create-
    time via the account form (the dropdown defaults to
    ``America/Detroit`` when no value is supplied).

    Why ``America/Detroit`` and not UTC: the install was originally
    seeded for a single Eastern US household. Defaulting to UTC
    would cause the API to render UTC times to humans, which is
    explicitly disallowed in the handover spec. Operators in
    other zones change the value via the account-edit form.

    Idempotent: a row whose config already declares ``tz`` (any
    value, including the empty string) is left untouched.
    """
    import json

    rows = conn.execute(
        "SELECT id, config_json FROM email_accounts"
    ).fetchall()
    for row in rows:
        rid = row["id"] if hasattr(row, "keys") else row[0]
        raw = row["config_json"] if hasattr(row, "keys") else row[1]
        try:
            cfg = json.loads(raw or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(cfg, dict):
            continue
        if "tz" in cfg:
            continue
        cfg["tz"] = "America/Detroit"
        conn.execute(
            "UPDATE email_accounts SET config_json = ? WHERE id = ?",
            (json.dumps(cfg), rid),
        )


@register(7, "create_acme_jobs")
def _v7_create_acme_jobs(conn: sqlite3.Connection) -> None:
    """ACME issuance job table -- restart-recovery for the renewer.

    Punch-list #104. The previous shape lived in process memory only
    (``acme_job_state._STATE`` singleton); a process kill mid-issuance
    abandoned both the operator-visible state AND the in-flight LE
    order context. If LE finalised the order before the kill, the
    cert was dropped on the floor and the operator's only recourse
    was to re-trigger -- which could collide with the LE prod
    duplicate-cert rate limit (5 per exact-cert-FQDNs per week).

    Schema mirrors triage_jobs (#101) so the operator-surfacing
    code can stay symmetric across both job types:

      job_id            TEXT PK   ``acme_<12-hex>`` UUID-style handle
      actor_user_id     INTEGER   who clicked Issue Now (audit trail)
      domains_json      TEXT      JSON list of FQDNs in the SAN list
      directory_url     TEXT      staging vs prod LE
      order_url         TEXT      LE-returned order URL once placed
      phase             TEXT      mirrors the PHASES tuple
      attempt           INTEGER   retry counter
      max_attempts      INTEGER   from config
      visibility_json   TEXT      per-domain DNS visibility map
      last_error        TEXT      nullable
      last_error_kind   TEXT      nullable; 'cancelled' for #103
      cancel_requested  INTEGER   BOOL flag (#103)
      started_at        TEXT      ISO 8601 (set when phase=starting)
      last_progress_at  TEXT      ISO 8601 (UI staleness signal)
      ended_at          TEXT      ISO 8601 (terminal phase only)
      created_at        TEXT      always set on insert

    Indexes:
      idx_acme_jobs_phase -- worker scans for in-flight rows on
        startup; UI lists recent + active jobs by phase.

    Idempotent: re-running on a DB that already has the table is a
    no-op (CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS).
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_jobs (
            job_id            TEXT PRIMARY KEY,
            actor_user_id     INTEGER,
            domains_json      TEXT NOT NULL,
            directory_url     TEXT NOT NULL,
            order_url         TEXT,
            phase             TEXT NOT NULL DEFAULT 'starting',
            attempt           INTEGER NOT NULL DEFAULT 0,
            max_attempts      INTEGER NOT NULL DEFAULT 1,
            visibility_json   TEXT NOT NULL DEFAULT '{}',
            last_error        TEXT,
            last_error_kind   TEXT,
            cancel_requested  INTEGER NOT NULL DEFAULT 0,
            started_at        TEXT,
            last_progress_at  TEXT,
            ended_at          TEXT,
            created_at        TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_acme_jobs_phase
        ON acme_jobs(phase)
    """)


@register(8, "create_office365_subscriptions")
def _v8_create_office365_subscriptions(conn: sqlite3.Connection) -> None:
    """Per-account Microsoft Graph webhook subscription state.

    Mirrors the role of ``gmail_watches`` for the O365 provider — one
    row per account holding the active subscription_id, its expiry,
    last-renewal/last-notification timestamps, and a small
    error-bookkeeping pair so the renewer can surface trouble in
    /health + the daily digest without flooding logs.

    Schema (single PK on account_id; one active subscription per
    account by Graph contract for ``me/mailFolders('Inbox')/messages``):

      account_id            INTEGER PK   FK -> email_accounts(id)
      subscription_id       TEXT NOT NULL — Graph-assigned UUID
      expiration_at         TEXT NOT NULL — ISO 8601 UTC, real expiry
      last_renewed_at       TEXT NOT NULL — ISO 8601 UTC, audit cursor
      last_notification_at  TEXT          — ISO 8601 UTC, last webhook hit
      status                TEXT NOT NULL — 'active' | 'errored' | 'expired'
      error_count            INTEGER NOT NULL DEFAULT 0
      error_last             TEXT — last error message (truncated)
      created_at             TEXT NOT NULL
      updated_at             TEXT NOT NULL

    Indexes:
      idx_office365_subscriptions_subid — webhook lookup by subscription_id
      idx_office365_subscriptions_expiry — renewer sweep by expiration
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS office365_subscriptions (
            account_id            INTEGER PRIMARY KEY
                                    REFERENCES email_accounts(id)
                                    ON DELETE CASCADE,
            subscription_id       TEXT    NOT NULL,
            expiration_at         TEXT    NOT NULL,
            last_renewed_at       TEXT    NOT NULL,
            last_notification_at  TEXT,
            status                TEXT    NOT NULL DEFAULT 'active',
            error_count           INTEGER NOT NULL DEFAULT 0,
            error_last            TEXT,
            created_at            TEXT    NOT NULL,
            updated_at            TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
            idx_office365_subscriptions_subid
            ON office365_subscriptions(subscription_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_office365_subscriptions_expiry
            ON office365_subscriptions(expiration_at)
    """)


@register(9, "create_email_watches")
def _v9_create_email_watches(conn: sqlite3.Connection) -> None:
    """Email watches — operator-defined match-and-fire on classified mail.

    Punch-list #100. Each row is one watch: a filter, an action set
    (escalate / webhook / both), and a scope (single account or all
    accounts when ``account_id IS NULL``). The webhook signing secret
    is held in the secrets store under ``watch_<id>_hmac`` — never on
    this row.

    Schema:
      watch_id      TEXT PK   ``watch_<12-hex>``
      name          TEXT      operator-supplied label
      enabled       INTEGER   1/0; disabled watches don't fire but stay
                              in the list so the operator can flip them
                              back on without re-typing the filter
      account_id    INTEGER   FK -> email_accounts(id) when scoped to one
                              account; NULL means "all non-HIPAA accounts"
                              (the matcher excludes HIPAA accounts from
                              the all-scope sweep)
      filter_json   TEXT      JSON dict — see WatchFilter dataclass
      actions_json  TEXT      JSON dict — see WatchActions dataclass
      created_at    TEXT      ISO 8601 UTC
      updated_at    TEXT      ISO 8601 UTC

    Indexes:
      idx_email_watches_account — list-by-account is the hot path
                                   (UI, matcher); index lets the all-
                                   accounts NULL-row scan stay cheap

    Idempotent — re-running on a DB that already has the table is a
    no-op (CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS).
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_watches (
            watch_id     TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            enabled      INTEGER NOT NULL DEFAULT 1,
            account_id   INTEGER
                         REFERENCES email_accounts(id)
                         ON DELETE CASCADE,
            filter_json  TEXT NOT NULL DEFAULT '{}',
            actions_json TEXT NOT NULL DEFAULT '{}',
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_email_watches_account
            ON email_watches(account_id)
    """)


@register(10, "add_email_account_aliases")
def _v10_add_email_account_aliases(conn: sqlite3.Connection) -> None:
    """Per-account additional-address list (#106).

    One physical mailbox can be reachable at several addresses (the
    same inbox receives mail at ``user@example.com`` AND at
    ``alias1@example.com`` because the second address forwards to
    the first; or because the mailbox has been delegated additional
    Office 365 / Google Workspace addresses). Today the recipient
    routing + the digest recipient-mismatch guard key off the single
    primary address — alias-addressed mail either misses its account
    entirely or gets blocked by the guard when delivery to the alias
    target tries to round-trip the digest.

    This migration adds ``email_accounts.aliases_json``: a JSON array
    of ``{"address": "...", "label": "..."}`` dicts. Default is the
    empty list ``[]``. The primary address (``account_email``) is
    NOT stored here — it's still derived from the provider config —
    and the writer rejects attempts to add it as an alias so the
    union (primary ∪ aliases) stays de-duplicated by construction.

    Per-alias separate route sets / send-from-alias / per-alias
    digest streams are explicitly OUT of scope. A sibling
    ``account_aliases`` table with a ``route_set_id`` column is
    the natural follow-up; this migration only adds the JSON-array
    column the simpler shape needs.

    Idempotent column add — skipped on installs where the column
    already exists, so re-running the migration on a schema-edited
    DB is a no-op rather than an error.
    """
    cur = conn.execute("PRAGMA table_info(email_accounts)")
    existing = {row[1] for row in cur.fetchall()}
    if "aliases_json" not in existing:
        conn.execute(
            "ALTER TABLE email_accounts "
            "ADD COLUMN aliases_json TEXT NOT NULL DEFAULT '[]'"
        )


@register(11, "add_user_style_knobs")
def _v11_add_user_style_knobs(conn: sqlite3.Connection) -> None:
    """Per-user writing-style knobs for the M-1 + M-2 prompt knobs.

    Five new columns on ``users`` capture explicit user-stated
    preferences that get prepended to the draft-reply prompt:

      style_guide            TEXT '' — free-text paragraph describing
                                       the user's writing voice (M-1)
      style_tone             TEXT 'neutral' — radio-group: formal /
                                       neutral / casual / terse (M-2)
      style_length           TEXT 'medium' — radio-group: brief /
                                       medium / full (M-2)
      style_signature        TEXT '' — sign-off line (e.g. "— Operator A")
      style_greeting         TEXT 'first-name' — radio-group: none /
                                       first-name / formal-name / custom
      style_greeting_custom  TEXT '' — populated only when greeting='custom'

    The defaults match the "no preference" state — when every column
    is at its default and ``style_guide`` is empty,
    :func:`format_style_knobs_for_prompt` returns the empty string so
    the LLM prompt is unchanged. This means rolling forward to v11 on
    an existing install is a behaviour-neutral schema extension.

    Idempotent: each ALTER guards on ``PRAGMA table_info`` so re-runs
    skip already-present columns. Sibling to the ``users.notify_email``
    column add — same shape, same pattern.

    Adjacent to M-3's per-account derived profile (settings k-v key
    ``style_profile:<account_id>``). M-1 + M-2 are user-stated, M-3
    is system-inferred — ordering at prompt-build time is knobs first,
    derived profile second (see actions/draft_reply.py).
    """
    cur = conn.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cur.fetchall()}
    additions = [
        ("style_guide",           "TEXT NOT NULL DEFAULT ''"),
        ("style_tone",            "TEXT NOT NULL DEFAULT 'neutral'"),
        ("style_length",          "TEXT NOT NULL DEFAULT 'medium'"),
        ("style_signature",       "TEXT NOT NULL DEFAULT ''"),
        ("style_greeting",        "TEXT NOT NULL DEFAULT 'first-name'"),
        ("style_greeting_custom", "TEXT NOT NULL DEFAULT ''"),
    ]
    for col, decl in additions:
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")


@register(12, "create_sent_mail_index")
def _v12_create_sent_mail_index(conn: sqlite3.Connection) -> None:
    """Per-account vector index of sent mail (M-4 scaffold).

    M-4 (retrieval-augmented few-shot examples) indexes the user's
    sent mail so :class:`DraftReplyAction` can pull the most-similar
    past replies as few-shot examples at draft time. This migration
    creates the storage table; the helper that populates + queries it
    lives in ``actions/sent_mail_index.py`` and the eventual wiring
    into ``draft_reply`` is M-5's job (this migration ships only the
    scaffold).

    Schema notes:
      account_id        FK -> email_accounts(id) ON DELETE CASCADE so
                        deleting an account drops its index.
      message_id        provider-native id (Gmail message id, IMAP
                        UID-as-string, Graph internal id). Unique per
                        provider but NOT cross-folder portable; see
                        rfc_message_id below.
      rfc_message_id    RFC 5322 Message-ID header. Stable across
                        folders (the same message in Sent + Inbox via
                        IMAP shares this id but has different UIDs
                        per mailbox). UNIQUE with account_id so we
                        dedup re-indexing of the same logical message.
      sent_at           ISO 8601 UTC -- the message's Date: header.
      to_addresses      JSON list of recipient strings; stored as TEXT
                        with default '[]' so old rows + a partial
                        write are still parseable.
      subject           plaintext subject. Redacted ("[REDACTED]") at
                        index time when the source account is HIPAA-
                        flagged -- but the helper short-circuits at
                        index_message() entry, so HIPAA accounts
                        produce zero rows in normal operation. The
                        defensive redaction here covers a future
                        operator who flips a non-HIPAA account to
                        HIPAA after rows are already present.
      body_excerpt      first 1000 chars of the stripped body. Same
                        redaction story as subject.
      embedding_vec     packed float32 array via ``struct.pack``. We
                        do NOT store JSON: 4 bytes/dim vs ~12-15 chars
                        decimal-as-text per dim is a 3-4x size win.
      embedding_model   model name + version string ("nomic-embed-
                        text:latest"). When the operator switches
                        embedding models, every row's vector is from
                        the OLD model and similarity comparisons
                        across models are nonsense -- the retrieval
                        helper compares this column to the configured
                        model and treats mismatched rows as stale
                        (rebuild guard).
      indexed_at        ISO 8601 UTC. Operator surface for "when did
                        this account last index" + the M-8 forget
                        sweep can purge by age.

    Indexes:
      idx_sent_mail_account   per-account scans (the dominant access
                              pattern: every retrieval is scoped to
                              one account).
      idx_sent_mail_indexed   age-based sweeps (M-8 + the rebuild
                              guard scans rows older than the model
                              flip).

    sqlite-vec virtual-table integration is OPT-IN at runtime: the
    migration creates only the canonical TABLE so installs without
    the extension still apply v12 cleanly. The helper in
    ``actions/sent_mail_index.py`` builds the vec0 virtual table
    on first use when ``app.state.sqlite_vec_available`` is True;
    when False, retrieval falls back to in-memory cosine over the
    rows in this table.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sent_mail_index (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL
                            REFERENCES email_accounts(id) ON DELETE CASCADE,
            message_id      TEXT    NOT NULL,
            rfc_message_id  TEXT,
            sent_at         TEXT    NOT NULL,
            to_addresses    TEXT    NOT NULL DEFAULT '[]',
            subject         TEXT,
            body_excerpt    TEXT,
            embedding_vec   BLOB,
            embedding_model TEXT    NOT NULL,
            indexed_at      TEXT    NOT NULL,
            UNIQUE(account_id, rfc_message_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sent_mail_account
            ON sent_mail_index(account_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sent_mail_indexed
            ON sent_mail_index(indexed_at)
    """)


@register(13, "add_o365_subscriptions_delta_link")
def _v13_add_o365_subscriptions_delta_link(conn: sqlite3.Connection) -> None:
    """Persist the Microsoft Graph ``@odata.deltaLink`` cursor per
    subscription so the push consumer can advance through the delta
    feed across deliveries.

    Graph's ``/me/mailFolders('Inbox')/messages/delta`` endpoint
    returns a deltaLink in the final page of every walk. Storing it
    here lets the next webhook delivery pass it back to Graph and
    receive only the messages that changed since the last walk —
    same role as Gmail's history_id.

    The column is nullable: a freshly-created subscription has no
    delta cursor until the first delta walk completes, and the push
    consumer treats NULL as "do an initial walk with no cursor".

    Idempotent column-add — skipped on installs where the column
    already exists.

    NOTE: Originally authored against an older baseline as v9; renumbered
    to v13 at integration time so the version is monotone after main
    landed v9-v12 from parallel-build agents.
    """
    cur = conn.execute("PRAGMA table_info(office365_subscriptions)")
    existing = {row[1] for row in cur.fetchall()}
    if "delta_link" not in existing:
        conn.execute(
            "ALTER TABLE office365_subscriptions ADD COLUMN delta_link TEXT"
        )


@register(14, "add_sent_mail_index_captured_pair")
def _v14_add_sent_mail_index_captured_pair(conn: sqlite3.Connection) -> None:
    """Captured-pair flag on ``sent_mail_index`` (M-6 edit-feedback loop).

    M-6 (continuous-learning loop) scans the user's Sent folder for
    messages carrying the ``X-Email-Triage: draft-reply`` header. When
    such a message is found, the original AI-drafted body (carried in
    a sibling ``X-Email-Triage-Draft-Body`` header as base64 plaintext)
    is compared against the body the user actually sent. The SENT
    version becomes a "gold standard" example -- the user reviewed,
    edited, and sent it. We re-index that row in ``sent_mail_index``
    and flag it as captured so the M-4 retrieval ranker can weight
    captured pairs higher than general sent mail.

    Single-table design: rather than a sibling ``captured_pairs``
    table, M-6 reuses ``sent_mail_index``. One storage shape, one
    retrieval path, one ranking knob. The captured-pair signal is
    the boolean column added here; ``retrieve_similar`` boosts the
    cosine score for rows where ``is_captured_pair = 1``.

    Idempotent column add -- skipped on installs where the column
    already exists. Default ``0`` matches the existing-row meaning
    "general sent mail, not a captured edit-feedback pair".
    """
    cur = conn.execute("PRAGMA table_info(sent_mail_index)")
    existing = {row[1] for row in cur.fetchall()}
    if "is_captured_pair" not in existing:
        conn.execute(
            "ALTER TABLE sent_mail_index "
            "ADD COLUMN is_captured_pair INTEGER NOT NULL DEFAULT 0"
        )


@register(15, "add_sent_mail_index_embedding_norm")
def _v15_add_sent_mail_index_embedding_norm(conn: sqlite3.Connection) -> None:
    """Precomputed L2 norm column on ``sent_mail_index`` (#136 RAG perf).

    The M-4 retrieval hot path used to walk every indexed row and
    recompute the candidate vector's L2 norm in pure Python on every
    call -- ~10k rows x 768 dims of multiplications + sqrts per draft
    reply, all on the event loop. The fix is to store the norm at
    write time and let retrieval read it instead.

    Schema change: add ``embedding_norm REAL NOT NULL DEFAULT 0.0``.
    The default lets the ``ALTER TABLE`` add the column without
    rewriting existing rows; the backfill below then walks each
    existing row, unpacks the float32 vector, computes the L2 norm,
    and writes it back.

    The backfill uses the stdlib (``struct.unpack`` + ``math.sqrt``)
    rather than numpy so this migration body stays dependency-light --
    migrations should not import the project's hot-path libraries.
    The retrieval helper in ``actions/sent_mail_index.py`` is the
    correct place for numpy.

    Idempotent:
      * Column add is guarded by a ``PRAGMA table_info`` check.
      * Backfill skips rows where ``embedding_norm > 0`` so a second
        run is a no-op even when the previous run hit every row.
      * Rows with empty / NULL / corrupt vec blobs are left at the
        column default (0.0). The retrieval helper already treats
        norm == 0 as "skip this row" (cosine is 0/0 = undefined).
    """
    import math
    import struct

    cur = conn.execute("PRAGMA table_info(sent_mail_index)")
    existing = {row[1] for row in cur.fetchall()}
    if "embedding_norm" not in existing:
        conn.execute(
            "ALTER TABLE sent_mail_index "
            "ADD COLUMN embedding_norm REAL NOT NULL DEFAULT 0.0"
        )

    # Backfill. Only rows whose norm is still the default 0.0 are
    # touched, so re-running is cheap (one SELECT scan, zero writes).
    rows = conn.execute(
        "SELECT id, embedding_vec FROM sent_mail_index "
        "WHERE embedding_norm <= 0.0"
    ).fetchall()
    for row in rows:
        rid = row["id"] if hasattr(row, "keys") else row[0]
        blob = row["embedding_vec"] if hasattr(row, "keys") else row[1]
        if not blob:
            continue
        n, rem = divmod(len(blob), 4)
        if rem or n == 0:
            # Corrupt blob -- leave norm at 0.0 so retrieval skips it
            # (defensive: same shape the runtime _unpack_vec already
            # returns []) rather than aborting the whole migration.
            continue
        try:
            vec = struct.unpack(f"<{n}f", blob)
        except struct.error:
            continue
        norm = math.sqrt(sum(x * x for x in vec))
        if norm <= 0.0:
            continue
        conn.execute(
            "UPDATE sent_mail_index SET embedding_norm = ? WHERE id = ?",
            (norm, rid),
        )


@register(16, "create_triage_retry_queue")
def _v16_create_triage_retry_queue(conn: sqlite3.Connection) -> None:
    """Durable retry queue for triage attempts that the LLM rejected
    (#149 Bundle A — LLM offline handling).

    When the classify path fires :class:`LLMBackendUnreachableError`
    (Ollama down, network blip, etc.), the watcher / push consumer /
    poll loop need somewhere to park the message so it can be
    retried after the backend recovers without re-fetching it from
    the provider. This table is that parking lot.

    Schema:
      id              INTEGER PK AUTOINCREMENT
      message_id      TEXT NOT NULL          provider-native id
      account_id      INTEGER NOT NULL       FK -> email_accounts.id
                                              (logical; not enforced
                                              so a deleted account
                                              doesn't fail the worker)
      mailbox         TEXT                    IMAP folder for IMAP rows
      uid             TEXT                    UID for IMAP rows
                                              (mailbox + uid is the
                                              IMAP fetch key; the
                                              push paths set
                                              message_id only)
      attempt_count   INTEGER NOT NULL DEFAULT 0
      next_attempt_at TEXT NOT NULL          ISO 8601 UTC; index for
                                              the worker's "ready"
                                              scan
      last_error      TEXT                    capped at 1000 chars
                                              by the writer
      last_error_type TEXT                    exception class name
      created_at      TEXT NOT NULL          ISO 8601 UTC
      updated_at      TEXT NOT NULL          ISO 8601 UTC

    Index on ``(next_attempt_at, account_id)`` powers the worker
    loop: ``WHERE next_attempt_at <= ? ORDER BY next_attempt_at``
    is the dominant query, account-scoped fan-out is a secondary
    use case.

    Idempotent: ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX
    IF NOT EXISTS``. Re-running on a DB that already has the table
    is a no-op.

    Logical uniqueness on ``(account_id, message_id)`` is enforced
    in the writer (``triage_retry_queue.enqueue``) rather than at
    the DDL level — two concurrent watchers attempting to enqueue
    the same message both succeed; one row results because the
    second SELECT sees the first row and UPDATEs instead of
    INSERTing. SQLite's lack of ON CONFLICT semantics with mixed
    UPDATE-or-INSERT logic makes the uniqueness constraint brittle;
    application-layer enforcement is the cleaner shape here.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS triage_retry_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id      TEXT NOT NULL,
            account_id      INTEGER NOT NULL,
            mailbox         TEXT,
            uid             TEXT,
            attempt_count   INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL,
            last_error      TEXT,
            last_error_type TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_triage_retry_queue_ready
        ON triage_retry_queue(next_attempt_at, account_id)
    """)


@register(17, "watches_per_account_fanout")
def _v17_watches_per_account_fanout(conn: sqlite3.Connection) -> None:
    """Punch-list #154 + #155 — move watches off the implicit
    "all accounts" NULL row onto an explicit multi-account fan-out.

    Pre-v17 the ``email_watches`` table allowed ``account_id IS NULL``
    to mean "fire on every non-HIPAA account on this install". The
    new editor lives on ``/profile/watches`` and asks the operator to
    tick the accounts they want a watch to fire on; the save handler
    inserts one row per ticked account, all sharing a ``watch_group_id``
    so the editor can re-group them as one row for display + edit.

    Schema delta:
      * ``watch_group_id`` TEXT — uuid-hex; rows with the same group
        id are treated as one logical watch by the editor. NULL on
        existing rows is fine — the editor falls back to
        ``(created_by_user_id, name)`` grouping for legacy rows
        that pre-date the column.
      * ``created_by_user_id`` INTEGER — FK to users(id); the
        operator who created (or, for backfilled rows, will
        "own") this watch. NULL on truly orphan rows (no install-
        wide creator we can attribute to).

    Backfill (the heart of this migration):
      For every existing ``account_id IS NULL`` row, fan out to one
      row per non-HIPAA email_accounts row on the install. Each
      fan-out row gets a fresh ``watch_id`` but shares the same
      ``watch_group_id`` (a single uuid hex) AND copies every
      other column (name, enabled, filter_json, actions_json,
      timestamps) from the source row. The original NULL row is
      DELETEd after the fan-out completes.

      Creator attribution: pre-v17 the table didn't track who made
      the watch, so backfilled fan-out rows get
      ``created_by_user_id = email_accounts.user_id`` (the account
      owner) — that matches the post-v17 invariant that a watch is
      "owned" by the user whose account it fires on, AND it means
      the new ``/profile/watches`` page will surface backfilled
      watches to the right operator (no orphan watches floating in
      an admin-only inbox).

      HIPAA-flagged accounts are SKIPPED. The pre-v17 NULL-row
      semantics already excluded HIPAA accounts from the all-scope
      sweep (see ``email_watches.list_watches`` + watch_runner.py),
      so this preserves behaviour exactly — a NULL-row watch did
      not fire on a HIPAA mailbox, and the post-v17 fan-out does
      not produce a row for one either.

    Idempotency: ALTER TABLE ADD COLUMN runs once (re-running the
    body would raise on the second ALTER); the framework re-applies
    a registered migration only if its version isn't recorded in
    ``schema_migrations``, so v17 fires once per DB. The backfill
    is bounded by "rows where account_id IS NULL" which evaporates
    to zero after the first pass.

    Hash-chain (log-chain) impact: this migration writes ONLY to
    ``email_watches`` (no access_log / auth_events / hipaa_access_events
    rows). ``verify_log_chain`` continues to pass — it inspects
    audit tables, not feature tables.
    """
    import json
    import uuid as _uuid

    # 1) Add new columns. SQLite's ALTER TABLE ADD COLUMN is fine
    # because the column is nullable; existing rows get NULL by
    # default.
    cols = {
        r[1] for r in conn.execute(
            "PRAGMA table_info(email_watches)"
        ).fetchall()
    }
    if "watch_group_id" not in cols:
        conn.execute(
            "ALTER TABLE email_watches "
            "ADD COLUMN watch_group_id TEXT"
        )
    if "created_by_user_id" not in cols:
        conn.execute(
            "ALTER TABLE email_watches "
            "ADD COLUMN created_by_user_id INTEGER "
            "REFERENCES users(id) ON DELETE SET NULL"
        )

    # 2) Backfill. Pull every NULL-account row first, then iterate.
    null_rows = conn.execute(
        "SELECT watch_id, name, enabled, filter_json, actions_json, "
        "       created_at, updated_at "
        "FROM email_watches WHERE account_id IS NULL"
    ).fetchall()

    # Eligible accounts: non-HIPAA only. The legacy NULL-row scope
    # excluded HIPAA-flagged accounts; preserve that exactly.
    acct_rows = conn.execute(
        "SELECT id, user_id "
        "FROM email_accounts "
        "WHERE COALESCE(hipaa, 0) = 0"
    ).fetchall()
    eligible = [(r[0], r[1]) for r in acct_rows] if acct_rows else []

    for nr in null_rows:
        # sqlite3.Row supports indexing; tuple does too — handle both.
        if hasattr(nr, "keys"):
            wid = nr["watch_id"]
            name = nr["name"]
            enabled = nr["enabled"]
            filter_json = nr["filter_json"]
            actions_json = nr["actions_json"]
            created_at = nr["created_at"]
            updated_at = nr["updated_at"]
        else:
            (wid, name, enabled, filter_json,
             actions_json, created_at, updated_at) = nr

        group_id = _uuid.uuid4().hex

        for acct_id, owner_user_id in eligible:
            new_wid = f"watch_{_uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO email_watches "
                "(watch_id, name, enabled, account_id, "
                " filter_json, actions_json, created_at, updated_at, "
                " watch_group_id, created_by_user_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    new_wid, name, enabled, acct_id,
                    filter_json, actions_json,
                    created_at, updated_at,
                    group_id, owner_user_id,
                ),
            )

        # Delete the original NULL row after fan-out succeeds. If
        # eligible was empty (install with zero non-HIPAA accounts),
        # we still drop the NULL row — its scope was never anything
        # other than "no accounts", and keeping it around would
        # confuse the post-v17 invariant "no NULL-account rows".
        conn.execute(
            "DELETE FROM email_watches WHERE watch_id = ?", (wid,),
        )

    # 3) Index on the grouping column so the editor's "fetch every
    # row in this group" query stays cheap as the table grows.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_email_watches_group "
        "ON email_watches(watch_group_id)"
    )


@register(18, "create_labels")
def _v18_create_labels(conn: sqlite3.Connection) -> None:
    """Multi-LABEL per message (#129) — operator-curated tags that
    decorate messages independently of LLM classification.

    Gmail-style labels. Today every message gets exactly ONE category
    from the LLM. Labels add a parallel surface: operator can attach
    any number of slugs (``vendor-action-required``, ``tax-related``)
    via the /labels UI, the bulk-tag action on triage results, or a
    matching ``list_rules.adds_labels`` row. LLM classification path
    is unchanged.

    Schema:
      labels(slug PK, name, color hex, created_by_user_id, created_at,
             updated_at)
        — install-wide catalog (no per-account scope in v1).

      message_labels(message_id, account_id, label_slug, applied_by_actor,
                     applied_at)
        — junction table; composite PK on (message_id, label_slug).
        Index on (account_id, label_slug) powers the "/triage filter:
        has-label-X" reads.

      list_rules.adds_labels TEXT — JSON array of slugs. When a
        list-rule matches, the labels in this column are attached to
        the message in addition to whatever the LLM (or skip_ai) does
        with the category. Additive, never overrides category.

    Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT
    EXISTS + a column-presence guard on ALTER TABLE. Re-running on
    a DB that already has the tables is a no-op.

    Backfill: none. Existing messages have no labels (forward-only).
    HIPAA: label slugs are non-PHI by definition; storage non-
    sensitive. The actor != owner audit rule applies to viewing
    labels on PHI accounts (per feedback_hipaa_actor_owner_gate),
    not to the label catalog itself.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS labels (
            slug                TEXT NOT NULL PRIMARY KEY,
            name                TEXT NOT NULL,
            color               TEXT NOT NULL DEFAULT '#6c757d',
            created_by_user_id  INTEGER REFERENCES users(id),
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS message_labels (
            message_id        TEXT NOT NULL,
            account_id        INTEGER NOT NULL REFERENCES email_accounts(id),
            label_slug        TEXT NOT NULL REFERENCES labels(slug),
            applied_by_actor  INTEGER REFERENCES users(id),
            applied_at        TEXT NOT NULL,
            PRIMARY KEY (message_id, label_slug)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_message_labels_account_label
        ON message_labels(account_id, label_slug)
    """)
    # Column-presence guard for list_rules.adds_labels. PRAGMA
    # table_info returns one row per column; presence check avoids
    # the ALTER TABLE error on a re-run.
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(list_rules)").fetchall()
    }
    if "adds_labels" not in cols:
        conn.execute(
            "ALTER TABLE list_rules ADD COLUMN adds_labels TEXT"
        )


@register(19, "add_user_anti_ai_style_guide")
def _v19_add_user_anti_ai_style_guide(conn: sqlite3.Connection) -> None:
    """Per-user anti-AI style guide + disable-global flag.

    The anti-AI style guide is a free-text list of AI mannerisms the
    operator wants the draft-reply LLM to AVOID (e.g. "Never open with
    'Certainly!'; never use 'I hope this email finds you well'; avoid
    em-dashes for narrative pause"). Two surfaces:

      * Install-wide guide lives in the ``settings`` table under key
        ``anti_ai_style_guide_global`` (no schema change here).
      * Per-user override lives on ``users`` — two columns added by
        this migration:

          anti_ai_style_guide_user            TEXT '' — free-text
                                              override scoped to this
                                              user.
          anti_ai_style_guide_disable_global  INTEGER 0 — when 1 the
                                              install-wide guide is
                                              skipped for this user
                                              (per-user notes are
                                              substituted, not stacked).

    Both default to "no preference" (empty / 0) so existing rows + a
    behaviour-neutral roll-forward stay identical to pre-v19 behaviour
    until the operator explicitly fills in text on /config (admin) or
    /profile?tab=writing (per-user).

    HIPAA gate: same shape as the M-1+M-2 knobs (operator-typed text,
    no PHI inputs by construction). The anti-AI block routes through
    :func:`build_style_prompt_prefix`, which already enforces
    ``hipaa and not m1m2_hipaa_allow → empty prefix``; the anti-AI
    section inherits that gate for free.

    Idempotent: PRAGMA table_info guards each ALTER so re-runs skip
    already-present columns.
    """
    cur = conn.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cur.fetchall()}
    additions = [
        ("anti_ai_style_guide_user",           "TEXT NOT NULL DEFAULT ''"),
        ("anti_ai_style_guide_disable_global", "INTEGER NOT NULL DEFAULT 0"),
    ]
    for col, decl in additions:
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")


@register(20, "sent_folder_override_string_to_list")
def _v20_sent_folder_override_string_to_list(conn: sqlite3.Connection) -> None:
    """Reshape ``email_accounts.config_json["sent_folder_override"]``
    from a single string to a list of strings.

    The picker on ``/profile/style-data`` now lets the operator tick
    one or more sent-like folders (Sent + Sent Items + Drafts-That-
    Were-Sent + etc.) so the M-3 / M-4 / M-6 capture paths can fan
    learning across every folder that carries the user's reply voice.
    The persisted shape becomes ``list[str]``; the legacy scalar
    string (one folder) wraps to ``[value]``; missing key stays
    missing (resolves to "discover at mine time"); already-a-list
    rows are left alone (idempotency on re-run).

    Empty / whitespace-only legacy strings collapse to ``[]`` so the
    column reads cleanly across the install — readers treat empty
    list and missing key the same way (fall through to
    ``find_sent_folder`` discovery).

    Idempotent: re-running on a DB that was already migrated finds
    every row already in list shape and writes nothing.
    """
    import json

    rows = conn.execute(
        "SELECT id, config_json FROM email_accounts"
    ).fetchall()
    for row in rows:
        rid = row["id"] if hasattr(row, "keys") else row[0]
        raw = row["config_json"] if hasattr(row, "keys") else row[1]
        try:
            cfg = json.loads(raw or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(cfg, dict):
            continue
        if "sent_folder_override" not in cfg:
            continue
        cur = cfg["sent_folder_override"]
        if isinstance(cur, list):
            # Already migrated (re-run, or new install that wrote a
            # list directly via the post-v19 save handler). No-op.
            continue
        if isinstance(cur, str):
            stripped = cur.strip()
            cfg["sent_folder_override"] = [stripped] if stripped else []
        else:
            # Defensive: any other shape (None, int, dict) collapses
            # to the empty list — the post-v19 reader treats this as
            # "no override, discover at mine time".
            cfg["sent_folder_override"] = []
        conn.execute(
            "UPDATE email_accounts SET config_json = ? WHERE id = ?",
            (json.dumps(cfg), rid),
        )


@register(21, "add_triage_jobs_kind")
def _v21_add_triage_jobs_kind(conn: sqlite3.Connection) -> None:
    """Add a ``kind`` discriminator column to ``triage_jobs``.

    Background-job rows now serve two distinct workloads:

      * ``kind='triage'`` — the original whole-mailbox triage sweep
        (classify-then-act over a provider search). This is the
        legacy default; pre-v21 rows + new rows that don't set the
        column read as 'triage' so the existing runner stays the
        path of least surprise.
      * ``kind='style_mine'`` — the M-3 style-mine variant. Operator
        clicked "Mine the Sent Items Now" on /profile/style-data with
        a per-account or install-wide limit > 50; the inline path
        would block the HTMX request past the browser timeout, so
        the same M-3 distill code runs in the bulk-job worker. The
        worker writes the result via :func:`set_style_profile` and
        finishes the row; no per-message ``triage_runs`` rows are
        produced (a single style-mine job collapses to one logical
        output).

    The bulk runner branches on this column at job-start: 'triage'
    falls through to the legacy classify-then-act path,
    'style_mine' enters the M-3 distill path. Mis-set / unknown
    kinds fall back to 'triage' so a future kind added without a
    branch doesn't deadletter — operator sees a no-op completion
    with the standard counters at zero.

    Idempotent: PRAGMA table_info guards the ALTER so re-runs skip
    the column when it already exists.
    """
    cur = conn.execute("PRAGMA table_info(triage_jobs)")
    existing = {row[1] for row in cur.fetchall()}
    if "kind" not in existing:
        conn.execute(
            "ALTER TABLE triage_jobs "
            "ADD COLUMN kind TEXT NOT NULL DEFAULT 'triage'"
        )


@register(22, "add_list_rules_provider_labels")
def _v22_add_list_rules_provider_labels(conn: sqlite3.Connection) -> None:
    """Provider-native label picker on rule editor (#163).

    Today every list rule can carry ``adds_labels`` — a JSON array of
    install-internal label slugs from the v18 ``labels`` catalog. That
    catalog is independent of the provider-native labels operators
    already maintain in Gmail / IMAP folders / Outlook categories.

    This migration adds a PARALLEL column ``provider_labels``:
      * shape — JSON array of ``{"account_id": int, "label_slug": str}``
        objects (NULL / empty = no provider labels apply for this rule)
      * semantics — when a rule matches a message, the apply phase
        scans entries whose ``account_id`` equals the message's
        account and calls ``provider.apply_label`` for each
        ``label_slug``. Per-account scoping because provider-native
        labels are per-mailbox; "apply Gmail label X to an IMAP
        message" has no meaning.
      * compatibility — the existing install-internal ``adds_labels``
        column stays as-is; both columns can be populated on the same
        rule (operator wants both an internal tag + a provider label).

    HIPAA gate: the picker route + helper both refuse to enumerate
    labels for HIPAA-flagged accounts (per the actor != owner rule).
    The apply phase doesn't need a separate gate because HIPAA
    accounts short-circuit the entire triage pipeline upstream.

    Idempotent: PRAGMA table_info guards the ALTER so re-running on
    a DB that already carries the column is a no-op.
    """
    cols = {
        row[1] for row in conn.execute(
            "PRAGMA table_info(list_rules)"
        ).fetchall()
    }
    if "provider_labels" not in cols:
        conn.execute(
            "ALTER TABLE list_rules ADD COLUMN provider_labels TEXT"
        )


@register(23, "add_account_style_per_alias")
def _v23_add_account_style_per_alias(conn: sqlite3.Connection) -> None:
    """Per-alias writing-style descriptors (punch list #162).

    Today the system stores ONE M-3 writing-style descriptor per
    account (under settings key ``style_profile:<id>``). Operators
    who send from multiple addresses on the same account (primary +
    aliases) want a separate descriptor per ``From:`` address so the
    formal-work voice doesn't bleed into the casual-personal voice
    when AI drafts replies.

    Two schema artefacts land here:

      * ``account_style_per_alias`` -- child table keyed by
        ``(account_id, from_address)``. The ``from_address`` column
        holds a normalised bare address (lowercase, no display name,
        no ``+suffix`` tag, no angle brackets). The empty string is a
        reserved value used for the legacy "single descriptor / no
        alias mode" row when used as a default bucket key.

      * ``email_accounts.style_alias_mode_enabled`` -- INTEGER bool,
        default 0. When 1 the M-3 mine + draft-stitch paths partition
        by ``From:`` address; when 0 (default) behaviour stays
        identical to pre-v23.

    Single-descriptor accounts are unchanged. The settings-table row
    under ``style_profile:<id>`` remains the canonical place for the
    account-wide descriptor. The child table is read-on-demand only
    when alias-mode is on for the account.

    Idempotent: ``IF NOT EXISTS`` on the table; PRAGMA table_info
    guard on the ALTER.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS account_style_per_alias ("
        "  account_id      INTEGER NOT NULL,"
        "  from_address    TEXT    NOT NULL,"
        "  descriptor_json TEXT    NOT NULL,"
        "  sample_count    INTEGER NOT NULL DEFAULT 0,"
        "  updated_at      TEXT    NOT NULL,"
        "  PRIMARY KEY (account_id, from_address),"
        "  FOREIGN KEY (account_id) REFERENCES email_accounts(id)"
        "    ON DELETE CASCADE"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_account_style_per_alias_acct "
        "ON account_style_per_alias (account_id)"
    )
    cur = conn.execute("PRAGMA table_info(email_accounts)")
    existing = {row[1] for row in cur.fetchall()}
    if "style_alias_mode_enabled" not in existing:
        conn.execute(
            "ALTER TABLE email_accounts "
            "ADD COLUMN style_alias_mode_enabled INTEGER NOT NULL DEFAULT 0"
        )


@register(24, "create_push_deliveries")
def _v24_create_push_deliveries(conn: sqlite3.Connection) -> None:
    """Per-day push-delivery counter table (#166).

    Today the Gmail Pub/Sub webhook + the Office365 Graph webhook
    bump an in-memory ``app.state.metrics`` counter on every
    incoming push. The counter survives only until the next
    container restart, so the operator-facing /admin/stats page
    rendered "Per-day delivery counts are a future enhancement"
    instead of any real number.

    This migration lands the persistence layer behind that surface.
    One row per (account, provider, day) holds the count. The
    webhook handlers UPSERT on every successful queue.put_nowait;
    /admin/stats reads a rolling window (default 14 days); a daily-
    health cron prune drops rows older than 90 days so the table
    doesn't grow unbounded.

    Shared shape across providers so the same UI surface renders
    Gmail + O365 (+ future IMAP-IDLE) counts without per-provider
    schema duplication. ``provider`` is a free-text discriminator
    matching the values the webhook handlers use
    (``'gmail'`` / ``'office365'``).

    Columns
    -------
      * ``account_id``  — FK to email_accounts.id (ON DELETE CASCADE
                          so removing an account drops its history)
      * ``provider``    — TEXT, one of 'gmail' / 'office365' / etc.
      * ``day``         — TEXT, UTC date in ISO 'YYYY-MM-DD' shape
      * ``count``       — INTEGER, total deliveries for this slot

    PRIMARY KEY ``(account_id, provider, day)`` so the UPSERT path
    can collide-and-increment in one statement. Index on ``day``
    powers the rolling-window read without scanning every row.

    Idempotent: ``IF NOT EXISTS`` on the table; same on the index.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS push_deliveries ("
        "  account_id INTEGER NOT NULL,"
        "  provider   TEXT    NOT NULL,"
        "  day        TEXT    NOT NULL,"
        "  count      INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (account_id, provider, day),"
        "  FOREIGN KEY (account_id) REFERENCES email_accounts(id)"
        "    ON DELETE CASCADE"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_push_deliveries_day "
        "ON push_deliveries (day)"
    )


@register(25, "add_hipaa_style_descriptor")
def _v25_add_hipaa_style_descriptor(conn: sqlite3.Connection) -> None:
    """HIPAA-safe describe-and-discard descriptor storage (#152 phase 3).

    Phase 3 of the M-3 HIPAA lift wants a structured, post-scrubbed
    writing-style descriptor for HIPAA-flagged accounts that have the
    operator-set ``style_knobs_hipaa_allow:<id>`` opt-in. The descriptor
    is built by reading sent-mail bodies in-memory only, feeding them
    to the distillation LLM under a strict structured-output schema,
    scrubbing the response against a PHI regex+allowlist, and persisting
    ONLY the scrubbed structured JSON — never raw bodies, never free-form
    prose, never anything that survived the scrubber.

    Storage shape — sibling table, NOT a settings row
    -------------------------------------------------
    A dedicated ``hipaa_style_descriptors`` table keyed on
    ``account_id`` rather than columns on ``email_accounts`` or a
    settings row under ``style_profile:<id>``. Three reasons:

      1. **Schema versioning** — the descriptor JSON shape will evolve
         (phase 4 adds per-recipient hashed-key descriptors). A dedicated
         ``descriptor_version`` column lets the loader detect a stale
         JSON shape and force a re-distill rather than rendering a
         partial / wrong profile.
      2. **Audit clarity** — auditors asking "what PHI-derived data
         does this install hold?" can point at one table, not grep
         settings rows. The table doubles as the regen-cadence ledger
         (``rebuilt_at``).
      3. **Clean phase-4 extension** — phase 4 (M-7 per-contact) wants
         ``(account_id, recipient_hash)`` rows of the same descriptor
         shape. A future migration can add ``recipient_hash`` as a
         column with a default of ``''`` (the account-wide row), no
         schema split.

    Columns
    -------
      * ``account_id``           — FK to email_accounts.id (ON DELETE CASCADE)
      * ``descriptor_json``      — TEXT, the scrubbed structured descriptor
      * ``descriptor_version``   — INT, bumped on JSON schema changes
      * ``rebuilt_at``           — TEXT (UTC ISO8601), last successful distill
      * ``message_count``        — INT, source sent-mail messages contributing
      * ``scrubber_outcome``     — TEXT ('clean' / 'dropped'); informational
                                   (a 'dropped' row should never persist —
                                   the action drops the entire descriptor —
                                   but the column exists for forensics
                                   if a future bug ever lets one through)

    Idempotent: ``IF NOT EXISTS`` on the table.

    NOT WIRED INTO PRODUCTION CALLERS
    ---------------------------------
    The phase 3 distill pipeline (``actions.hipaa_style_distill``) lives
    behind an install-wide flag (``style_learning:hipaa_distill_enabled``,
    default OFF) and is not called from any existing M-3 site yet. This
    migration lands the schema so operator opt-in is a single flag flip
    + a re-deploy, not a code change.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hipaa_style_descriptors ("
        "  account_id         INTEGER PRIMARY KEY,"
        "  descriptor_json    TEXT    NOT NULL,"
        "  descriptor_version INTEGER NOT NULL DEFAULT 1,"
        "  rebuilt_at         TEXT    NOT NULL,"
        "  message_count      INTEGER NOT NULL DEFAULT 0,"
        "  scrubber_outcome   TEXT    NOT NULL DEFAULT 'clean',"
        "  FOREIGN KEY (account_id) REFERENCES email_accounts(id)"
        "    ON DELETE CASCADE"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hipaa_style_descriptors_rebuilt "
        "ON hipaa_style_descriptors (rebuilt_at)"
    )


@register(26, "create_ai_backends")
def _v26_create_ai_backends(conn: sqlite3.Connection) -> None:
    """Admin-curated AI backend registry + per-account selector FK (#169 Wave 1 I1).

    Pre-#169 the install picks ONE classifier backend from YAML config
    (``config.classifier.backend``: ``ollama`` / ``openai`` / ``gemini``).
    BAA acknowledgments live in settings rows keyed
    ``baa_ack:<backend>:<host>`` (see ``baa_gate.py``) — one ack per
    (backend, host) tuple, no expiration tracking, no operator-visible
    catalog of which backends are available, no per-account override.

    Operator decision 2026-05-15: lift backend selection out of the
    YAML and into the DB as an admin-curated catalog with explicit
    BAA-certification + expiration tracking, and let HIPAA-flagged
    accounts pick a different (BAA-certified) backend than non-HIPAA
    accounts on the same install. Style-learning specifically wants
    this — phase 3-4 of the M-3 lift (per ``_v25``) needs a cloud-BAA
    path when the local Ollama is too small for the distill prompt.

    Schema — ``ai_backends`` table
    ------------------------------
      * ``id``                 — INTEGER PK AUTOINCREMENT, the FK target.
      * ``name``               — TEXT UNIQUE; human-readable label
                                 ("OpenAI Enterprise", "Azure OpenAI
                                 GPT-4o", "Local Ollama"). Shown in the
                                 per-account dropdown.
      * ``type``               — TEXT with a CHECK constraint pinned
                                 to the four known shapes:
                                   ``ollama``        — local-first / homelab Ollama
                                   ``openai``        — api.openai.com (or proxy)
                                   ``azure_openai``  — Azure-hosted GPT
                                   ``gemini``        — Google generativelanguage.googleapis.com
                                 Anthropic intentionally absent — per
                                 ``feedback_no_anthropic``. GitHub
                                 Copilot evaluated 2026-05-15 and
                                 discarded — ToS scope-restricts
                                 Copilot Chat to coding tasks.
      * ``endpoint``           — TEXT base URL or equivalent. Ollama:
                                 ``http://localhost:11434``. OpenAI:
                                 ``https://api.openai.com/v1``. Azure:
                                 ``https://<resource>.openai.azure.com/``.
                                 Gemini: ``https://generativelanguage
                                 .googleapis.com/v1beta``.
      * ``api_key_secret_ref`` — TEXT, name of the row in
                                 ``secrets_store`` (Fernet-encrypted).
                                 NULL for Ollama (no key needed). The
                                 loader fetches the plaintext via
                                 :class:`DbSecrets` and never returns
                                 it to callers outside the adapter
                                 instance.
      * ``model``              — TEXT, model identifier (e.g.
                                 ``gpt-4o-mini``, ``gemini-2.0-flash``,
                                 ``llama3.1:8b``). NULL allowed when
                                 the backend has a sensible default.
      * ``baa_certified``      — INTEGER 0/1. 1 means the operator has
                                 a Business Associate Agreement in
                                 force with the vendor for this entry.
                                 The ``baa_gate`` consumer (Wave 2)
                                 reads this column instead of the
                                 settings-row pattern. Defaults to 0
                                 — operator must explicitly check the
                                 BAA box.
      * ``baa_expires_at``     — TEXT, ISO date string (YYYY-MM-DD).
                                 NULL when ``baa_certified=0``; mandatory
                                 when ``baa_certified=1`` (enforced
                                 by CHECK constraint). Wave 2 surfaces
                                 expiring + expired BAAs in the admin
                                 UI.
      * ``enabled``            — INTEGER 0/1. 0 hides the row from
                                 per-account dropdowns. Operator can
                                 disable a backend (e.g. budget cut,
                                 vendor outage) without deleting it.
                                 Defaults to 1.
      * ``created_by``         — INTEGER FK users.id, the admin who
                                 added the row. ON DELETE SET NULL
                                 so deleting an admin doesn't cascade
                                 into the backend catalog.
      * ``created_at``         — TEXT (UTC ISO8601). DEFAULT
                                 datetime('now') so callers can omit
                                 it on INSERT.

    CHECK constraint: when ``baa_certified=1``, ``baa_expires_at IS
    NOT NULL``. Operator can't claim a BAA without committing to an
    expiration date.

    INDEX ``idx_ai_backends_selector`` on
    ``(baa_certified, baa_expires_at, enabled)`` powers the per-
    account dropdown filter — "show me enabled backends, BAA-certified
    first, ordered by soonest-to-expire". Single composite index
    covers both the HIPAA-required (``baa_certified=1 AND enabled=1``)
    and non-HIPAA (``enabled=1``) selector reads.

    Schema — ``email_accounts.style_learning_backend_id`` column
    ------------------------------------------------------------
    Nullable FK pointing at ``ai_backends.id``. NULL means "use the
    install default" (Ollama with the YAML-configured URL+model).
    ON DELETE SET NULL so deleting a backend doesn't cascade into
    accounts (the account falls back to install default + Wave 2
    raises a warning banner).

    Classifier backend FK NOT added in this migration. Per the #169
    punch entry, the per-account classifier override is deferred —
    today's classifier is install-wide, reshaping it is a separate
    bundle. Only the style-learning selector lands here so phase 3-4
    of #152 can unblock.

    Idempotent
    ----------
    ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX IF NOT EXISTS`` +
    column-presence guard via ``PRAGMA table_info`` on the ALTER. Re-
    running on a DB that already has the table + column is a no-op.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ai_backends ("
        "  id                 INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  name               TEXT    NOT NULL UNIQUE,"
        "  type               TEXT    NOT NULL"
        "      CHECK (type IN ('ollama', 'openai', 'azure_openai',"
        "                      'gemini')),"
        "  endpoint           TEXT    NOT NULL,"
        "  api_key_secret_ref TEXT,"
        "  model              TEXT,"
        "  baa_certified      INTEGER NOT NULL DEFAULT 0"
        "      CHECK (baa_certified IN (0, 1)),"
        "  baa_expires_at     TEXT,"
        "  enabled            INTEGER NOT NULL DEFAULT 1"
        "      CHECK (enabled IN (0, 1)),"
        "  created_by         INTEGER REFERENCES users(id)"
        "      ON DELETE SET NULL,"
        "  created_at         TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  CHECK (baa_certified = 0 OR baa_expires_at IS NOT NULL)"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_backends_selector "
        "ON ai_backends (baa_certified, baa_expires_at, enabled)"
    )
    # Column-presence guard on the FK addition so a re-run is a no-op.
    cols = {
        row[1] for row in conn.execute(
            "PRAGMA table_info(email_accounts)"
        ).fetchall()
    }
    if "style_learning_backend_id" not in cols:
        conn.execute(
            "ALTER TABLE email_accounts "
            "ADD COLUMN style_learning_backend_id INTEGER "
            "REFERENCES ai_backends(id) ON DELETE SET NULL"
        )


@register(27, "create_style_distill_audit_and_queue")
def _v27_create_style_distill_audit_and_queue(conn: sqlite3.Connection) -> None:
    """Style-distill audit-row split + retry queue (#152 phases 3-4 S3+S4).

    Two new tables for the HIPAA describe-and-discard pipeline:

      * ``style_distill_events`` — one audit row per distillation
        attempt, regardless of outcome. Sibling to ``hipaa_access_events``
        but the shape is wrong for the existing table (no backend_id,
        no scrubber metadata, no was_cloud bit). The split lets
        operators answer "how often did cloud distillation fire on
        HIPAA accounts in the last 24h" without joining
        ``hipaa_access_events`` rows against ``email_accounts`` against
        ``ai_backends`` to recover the backend type.
      * ``style_distill_queue`` — one row per pending HIPAA distill
        attempt with retry-backoff state. Considered extending
        ``triage_jobs`` with ``kind='style_distill_hipaa'`` (the
        ``kind`` discriminator from v21 supports it) but the existing
        columns are wrong for the retry-with-backoff semantics:
        ``triage_jobs`` is one row per mailbox sweep with a cursor and
        per-message dedup; the style-distill queue is one row per
        account with an exponential-backoff schedule. Different
        primary key, different lifecycle. The clean split is the
        right call; the discriminator approach was rejected.

    ``style_distill_events`` schema
    -------------------------------
      * ``id``               — INTEGER PK AUTOINCREMENT
      * ``ts``               — TEXT (UTC ISO8601). Default datetime('now').
      * ``account_id``       — FK email_accounts.id ON DELETE CASCADE.
                               Required (the audit row exists only in
                               the context of a specific account).
      * ``actor_user_id``    — INTEGER FK users.id ON DELETE SET NULL.
                               Who triggered the distill (may be NULL
                               for the scheduled-retry path where no
                               human actor exists).
      * ``backend_id``       — INTEGER FK ai_backends.id ON DELETE SET
                               NULL. The backend the operator picked
                               for this account at distill time. NULL
                               when ``backend_type='ollama'`` and the
                               account is on the install default
                               (matches ``style_learning_backend_id IS
                               NULL`` on the account row).
      * ``backend_type``     — TEXT, the adapter's ``backend_type``
                               (``ollama`` / ``openai`` / ``azure_openai``
                               / ``gemini``). Captured at audit time
                               so the row is self-describing even after
                               the ``ai_backends`` row is deleted.
      * ``was_cloud``        — INTEGER 0/1. Set from
                               ``not adapter.is_local`` at distill time.
                               Belt-and-braces — ``backend_type='ollama'``
                               implies local, the cloud variants imply
                               cloud, but capturing the boolean directly
                               avoids re-deriving it from the type in
                               every reporting query.
      * ``outcome``          — TEXT, one of:
                                 ``"success"``         — clean descriptor persisted
                                 ``"scrubbed_partial"`` — common_phrases dropped,
                                                          rest persisted
                                 ``"scrubber_fail"``   — structural PHI leak,
                                                          descriptor discarded
                                 ``"backend_fail"``    — LLM call / network / timeout
                                 ``"no_messages"``     — corpus empty
                                 ``"cadence_skip"``    — descriptor still fresh
                                 ``"disabled"``        — install-wide flag off
                                 ``"not_opted_in"``    — per-account opt-in off
                                 ``"not_hipaa"``       — account not HIPAA-flagged
      * ``latency_ms``       — INTEGER, end-to-end distill latency. 0
                               when the path short-circuited before the
                               LLM call.
      * ``layer1_drops``     — INTEGER, count of fields the schema-
                               coercion layer dropped/snapped to default
                               (the LLM returned a value outside the
                               closed enum).
      * ``layer2_matches``   — INTEGER, count of HIPAA-18 regex matches
                               across all descriptor fields.
      * ``layer3_entities``  — INTEGER, count of NER entities flagged.
                               -1 when layer 3 was skipped (NER lib
                               not available; the ``scrubber_degraded``
                               flag captures the qualitative reason).
      * ``scrubber_degraded`` — INTEGER 0/1. 1 when layer 3 was not
                                available + the scrubber proceeded
                                with only layers 1+2.
      * ``error_class``       — TEXT, type-name of the exception that
                                caused ``outcome='backend_fail'``. NULL
                                otherwise. NEVER the exception message
                                (which could contain PHI from a leaked
                                provider error).

    Indexes
    -------
      * ``idx_style_distill_events_ts`` on (ts) — for /health/detail
        24-hour roll-up queries.
      * ``idx_style_distill_events_account`` on (account_id, ts) — for
        per-account history surfaces.

    ``style_distill_queue`` schema
    ------------------------------
      * ``account_id``       — INTEGER PK (one queue row per account;
                               re-enqueueing simply updates the existing
                               row). FK email_accounts.id ON DELETE
                               CASCADE.
      * ``attempt_count``    — INTEGER, monotonic since the last
                               success (reset to 0 on success).
      * ``next_retry_at``    — TEXT (UTC ISO8601), when the worker
                               should next attempt the distill. NULL
                               when there's no pending work (the row
                               is a leftover record of a final-attempt
                               failure that's kept for operator review).
      * ``last_error``       — TEXT, short class-name of the last
                               failure ("backend_fail:HTTPError",
                               "scrubber_fail"). Surfaced in the
                               admin banner. NEVER raw error text.
      * ``last_attempt_at``  — TEXT (UTC ISO8601). NULL until the
                               first attempt.
      * ``paused``           — INTEGER 0/1. Set to 1 when a
                               ``scrubber_fail`` lands — retrying a
                               leaky LLM does not help, the account is
                               paused until operator intervention. The
                               admin UI surfaces a list of paused
                               accounts in a banner.
      * ``created_at``       — TEXT (UTC ISO8601). DEFAULT datetime('now').

    Index
    -----
      * ``idx_style_distill_queue_ready`` on
        (next_retry_at, paused) — for the worker's "pick the oldest
        ready row" poll.

    Idempotent
    ----------
    ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX IF NOT EXISTS`` on
    both tables. Re-runs are a no-op.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS style_distill_events ("
        "  id                INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ts                TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  account_id        INTEGER NOT NULL"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  actor_user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,"
        "  backend_id        INTEGER REFERENCES ai_backends(id) ON DELETE SET NULL,"
        "  backend_type      TEXT    NOT NULL DEFAULT '',"
        "  was_cloud         INTEGER NOT NULL DEFAULT 0"
        "      CHECK (was_cloud IN (0, 1)),"
        "  outcome           TEXT    NOT NULL,"
        "  latency_ms        INTEGER NOT NULL DEFAULT 0,"
        "  layer1_drops      INTEGER NOT NULL DEFAULT 0,"
        "  layer2_matches    INTEGER NOT NULL DEFAULT 0,"
        "  layer3_entities   INTEGER NOT NULL DEFAULT 0,"
        "  scrubber_degraded INTEGER NOT NULL DEFAULT 0"
        "      CHECK (scrubber_degraded IN (0, 1)),"
        "  error_class       TEXT"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_style_distill_events_ts "
        "ON style_distill_events (ts)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_style_distill_events_account "
        "ON style_distill_events (account_id, ts)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS style_distill_queue ("
        "  account_id      INTEGER PRIMARY KEY"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  attempt_count   INTEGER NOT NULL DEFAULT 0,"
        "  next_retry_at   TEXT,"
        "  last_error      TEXT,"
        "  last_attempt_at TEXT,"
        "  paused          INTEGER NOT NULL DEFAULT 0"
        "      CHECK (paused IN (0, 1)),"
        "  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_style_distill_queue_ready "
        "ON style_distill_queue (next_retry_at, paused)"
    )


@register(28, "create_per_contact_style_hipaa")
def _v28_create_per_contact_style_hipaa(conn: sqlite3.Connection) -> None:
    """HIPAA-safe per-contact style descriptor (#152 phase 4 / M-7 — Wave 3).

    Wave 3 of the M-7 lift: a per-recipient style overlay for HIPAA-
    flagged accounts that have opted in to style learning. The non-HIPAA
    M-7 path (``actions.draft_reply._extract_addr`` + the per-contact
    filter on ``SentMailIndex``) stays untouched — it operates on
    plaintext recipient addresses fed through RAG retrieval, which is
    fine when the corpus doesn't carry PHI.

    The HIPAA path needs a parallel pipeline: same describe-and-discard
    distillation as M-3 (account-level), but keyed on a SALTED HASH of
    the recipient address rather than the plaintext address itself. The
    hash preserves the look-up (draft-time we hash the To: address +
    look it up) without persisting the operator's recipient identity
    in a form that a DB-level attacker could enumerate.

    Why a dedicated table instead of extending ``hipaa_style_descriptors``
    -------------------------------------------------------------------
    The v25 migration docstring anticipated this as a column addition
    (``recipient_hash`` defaulting to ``''`` for the account-wide row).
    We picked a separate table for three reasons:

      1. **Distinct lifecycle.** Account-level descriptors are mandatory
         (every HIPAA-style-enabled account has exactly one). Per-contact
         rows are opt-in overlays: they appear when the operator sends
         to a recurring correspondent, get GC'd after 90 days of no
         use, and can grow to many rows per account (one per recurring
         contact). Mixing the two in one table means every account-
         level read has to filter on ``recipient_hash IS NULL`` or
         ``= ''``, and every per-contact query has to filter the
         opposite — a foot-gun.
      2. **Index profile differs.** The account-level table has a
         unique index on ``account_id`` (1 row per account).
         The per-contact table needs a composite unique on
         ``(account_id, recipient_hash)`` plus a per-account scan-by-
         freshness index for the GC sweep.
      3. **Audit clarity.** "How many per-contact rows does account X
         hold?" should be one SELECT COUNT(*) — not a JOIN with a
         filter.

    The descriptor JSON shape is IDENTICAL to the account-level shape
    (closed-vocabulary schema; see
    :mod:`email_triage.style_learning.phi_scrubber`). The scrubber is
    reused verbatim — there is no separate per-contact scrubber.

    Columns
    -------
      * ``id``                — INTEGER PK AUTOINCREMENT
      * ``account_id``        — FK email_accounts.id ON DELETE CASCADE.
      * ``recipient_hash``    — TEXT, SHA-256 hex of the lowercased
                                recipient address salted with the
                                install style-salt (see
                                :func:`email_triage.style_learning.\
hash_recipient_for_install`). Length 64 hex chars.
      * ``descriptor_json``   — TEXT, the scrubbed structured descriptor
                                (same shape as account-level).
      * ``descriptor_version`` — INT, bumped on JSON schema changes.
      * ``message_count``     — INT, source sent-mail messages contributing.
      * ``last_distilled_at`` — TEXT (UTC ISO8601), the last successful
                                distill timestamp. Drives the GC sweep +
                                the freshness gate at draft-time.
      * ``last_updated``      — TEXT (UTC ISO8601), DEFAULT datetime('now').
                                Bumped on every UPSERT including the
                                no-change "row touched" cases.
      * ``scrubber_outcome``  — TEXT ('clean' / 'scrubbed_partial');
                                informational.

    Indexes
    -------
      * Unique on ``(account_id, recipient_hash)`` — drives draft-time
        look-up + UPSERT semantics.
      * ``(account_id, last_distilled_at)`` — drives the GC sweep
        ("which rows are >90 days old") + the per-account "list my
        contacts" admin surface.

    Per-contact retry queue + audit-row split
    -----------------------------------------
    The new table ``style_distill_queue_contacts`` mirrors the v27
    ``style_distill_queue`` shape but keyed on ``(account_id,
    recipient_hash)`` instead of ``account_id`` alone. Distill
    failures for per-contact runs land here; the worker treats it
    as a sibling queue.

    Reasons NOT to overload v27's queue with a nullable recipient
    column:

      * The v27 PK is ``account_id``. Adding ``recipient_hash`` as a
        new PK column means table-rebuild in SQLite (cannot ALTER
        PRIMARY KEY directly).
      * The existing helpers (``enqueue_style_distill_retry``,
        ``pause_style_distill_account``, ``clear_style_distill_queue_entry``,
        ``claim_next_style_distill_queue_entry``) all assume one row
        per account; a per-contact extension would require touching
        every helper signature.
      * The two queues have different "what does paused mean"
        semantics: pausing an account-level row means "we won't
        rebuild the account's writing style"; pausing a per-contact
        row means "we won't refine the overlay for THIS contact"
        (account-level still works). Different surface, different
        admin banner, different unpause path.

    The ``style_distill_events`` table grows two new columns:

      * ``kind``           — TEXT, ``'account_m3'`` (default; covers
                             every existing v27 row) or ``'per_contact'``
                             (new in W3).
      * ``recipient_hash`` — TEXT, NULL for ``kind='account_m3'``;
                             populated for ``kind='per_contact'``.

    NEVER the plaintext recipient — the same privacy invariant as the
    descriptor table.

    Idempotent
    ----------
    ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX IF NOT EXISTS``
    on the two new tables. The ``ALTER TABLE ADD COLUMN`` on
    ``style_distill_events`` is wrapped in a column-presence check via
    PRAGMA so re-runs are no-ops.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS per_contact_style_hipaa ("
        "  id                 INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  account_id         INTEGER NOT NULL"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  recipient_hash     TEXT    NOT NULL,"
        "  descriptor_json    TEXT    NOT NULL,"
        "  descriptor_version INTEGER NOT NULL DEFAULT 1,"
        "  message_count      INTEGER NOT NULL DEFAULT 0,"
        "  last_distilled_at  TEXT    NOT NULL,"
        "  last_updated       TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  scrubber_outcome   TEXT    NOT NULL DEFAULT 'clean'"
        ")"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_per_contact_style_hipaa_account_recipient "
        "ON per_contact_style_hipaa (account_id, recipient_hash)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_per_contact_style_hipaa_account_distilled "
        "ON per_contact_style_hipaa (account_id, last_distilled_at)"
    )

    conn.execute(
        "CREATE TABLE IF NOT EXISTS style_distill_queue_contacts ("
        "  account_id      INTEGER NOT NULL"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  recipient_hash  TEXT    NOT NULL,"
        "  attempt_count   INTEGER NOT NULL DEFAULT 0,"
        "  next_retry_at   TEXT,"
        "  last_error      TEXT,"
        "  last_attempt_at TEXT,"
        "  paused          INTEGER NOT NULL DEFAULT 0"
        "      CHECK (paused IN (0, 1)),"
        "  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  PRIMARY KEY (account_id, recipient_hash)"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_style_distill_queue_contacts_ready "
        "ON style_distill_queue_contacts (next_retry_at, paused)"
    )

    # Extend style_distill_events with kind + recipient_hash columns.
    # ALTER TABLE ADD COLUMN is idempotent only via column-presence check.
    existing_cols = {
        row[1] for row in conn.execute(
            "PRAGMA table_info(style_distill_events)"
        ).fetchall()
    }
    if "kind" not in existing_cols:
        conn.execute(
            "ALTER TABLE style_distill_events "
            "ADD COLUMN kind TEXT NOT NULL DEFAULT 'account_m3'"
        )
    if "recipient_hash" not in existing_cols:
        conn.execute(
            "ALTER TABLE style_distill_events "
            "ADD COLUMN recipient_hash TEXT"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_style_distill_events_kind "
        "ON style_distill_events (kind, ts)"
    )


@register(29, "create_hipaa_send_counters")
def _v29_create_hipaa_send_counters(conn: sqlite3.Connection) -> None:
    """HIPAA outbound-message counter table (#171-B trigger watcher).

    Drives the threshold gate on the M-3 + M-7 trigger watchers. A
    HIPAA-flagged account cannot reuse :class:`SentMailIndex` (the
    M-4 store hard-gates HIPAA at every public method by design), so
    there is no existing per-recipient sent-mail counter we can read.
    This table fills that gap.

    Shape
    -----
      * ``account_id``       — FK email_accounts.id ON DELETE CASCADE.
      * ``recipient_hash``   — TEXT, 64-hex SHA-256 digest of the
                               recipient address (via
                               :func:`email_triage.style_learning.\
hash_recipient_for_install`). NEVER the plaintext.
                               Special value ``''`` (empty string) is
                               the ACCOUNT-AGGREGATE row that drives
                               the M-3 trigger — total outbound
                               messages since the last successful
                               account-level distill. Every increment
                               bumps both the recipient row + the
                               aggregate row.
      * ``count``            — INTEGER, monotonic since last reset.
                               Reset to 0 by the trigger watcher
                               when it successfully enqueues a
                               distill for this row.
      * ``first_seen_at``    — TEXT (UTC ISO8601). Earliest contributor
                               to the current window. NULL when count=0.
      * ``last_seen_at``     — TEXT (UTC ISO8601). Most-recent contributor.

    Primary key: ``(account_id, recipient_hash)``. The recipient-hash
    column carries the empty string for the account-aggregate row so
    one table holds both views; queries for the M-3 watcher filter
    ``WHERE recipient_hash = ''`` and queries for the M-7 watcher filter
    ``WHERE recipient_hash != ''``.

    Why a counter table instead of scanning ``sent_mail_index``
    ----------------------------------------------------------
    ``sent_mail_index`` short-circuits HIPAA accounts at every public
    method (``SentMailIndex.__init__`` + ``index_message``); the
    feature is hard-off on HIPAA by design (#152 W2-β). The HIPAA
    pipeline therefore has zero rows there. A dedicated counter table
    avoids re-deriving HIPAA-safe accounting from a table that is
    intentionally empty on HIPAA accounts. The counter rows hold ONLY
    counts + timestamps + the salted-hash key — no PHI by construction.

    Why an account-aggregate row inside the same table
    --------------------------------------------------
    The alternative is a second table ``hipaa_account_send_counters``
    keyed on account_id alone. Single-table-with-sentinel-key is the
    cheaper schema: one CREATE, one INDEX, one CASCADE rule. The
    trade-off is the discriminator filter on every read — small cost.

    Privacy invariant
    -----------------
    No plaintext recipient address EVER lands in this table. Callers
    pass the already-hashed value (the watcher hashes at the boundary
    via :func:`hash_recipient_for_install`). The ``record_hipaa_\
sent_message`` helper rejects values containing ``@`` defensively —
    same belt-and-braces as
    :func:`record_style_distill_event` in v27/v28.

    Idempotent
    ----------
    ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX IF NOT EXISTS``;
    re-runs are no-ops.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hipaa_send_counters ("
        "  account_id     INTEGER NOT NULL"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  recipient_hash TEXT    NOT NULL,"
        "  count          INTEGER NOT NULL DEFAULT 0,"
        "  first_seen_at  TEXT,"
        "  last_seen_at   TEXT,"
        "  PRIMARY KEY (account_id, recipient_hash)"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hipaa_send_counters_account "
        "ON hipaa_send_counters (account_id)"
    )


@register(30, "create_watcher_retry_queue")
def _v30_create_watcher_retry_queue(conn: sqlite3.Connection) -> None:
    """Watcher per-message retry queue (#175 R-A).

    Sibling to the v16 ``triage_retry_queue`` (LLM-backend-unreachable
    retries) but with a different shape + purpose. Where v16 parks
    messages whose CLASSIFY step failed because the LLM backend is
    offline, this table parks messages whose per-message FETCH /
    PROCESS step raised an exception in the watcher (IMAP IDLE / IMAP
    poll / Gmail push / O365 push). The two queues coexist because the
    failure modes + retry semantics + privacy gates are different —
    merging them would conflate "LLM came back up, retry classify" with
    "transient IMAP timeout, retry fetch".

    Why a separate table from ``triage_retry_queue``
    ------------------------------------------------
    The spec for #175 named the new table ``triage_retry_queue``; the
    name was already taken by v16. Renaming v16 would force a destructive
    schema migration on a table that is in production use (sweeper +
    UI banner depend on it). Two tables, two sweepers — both small,
    both purpose-specific — beats fighting that collision.

    Schema
    ------
    ``id``               INTEGER PK AUTOINCREMENT
    ``account_id``       INTEGER NOT NULL FK email_accounts(id) CASCADE
    ``provider_type``    TEXT NOT NULL CHECK in {'imap','gmail','office365'}
    ``mailbox``          TEXT             IMAP folder name (IMAP rows only)
    ``uid``              INTEGER          IMAP UID (IMAP rows only)
    ``uidvalidity``      INTEGER          IMAP UIDVALIDITY at enqueue
                                          time — guards against UID
                                          renumbering during the retry
                                          window (IMAP rows only)
    ``gmail_msg_id``     TEXT             Gmail-native id (Gmail only)
    ``o365_msg_id``      TEXT             O365-native id (O365 only)
    ``state``            TEXT NOT NULL DEFAULT 'pending'
                         CHECK in {'pending','done','dead'}
    ``attempt_count``    INTEGER NOT NULL DEFAULT 0
    ``first_seen_at``    TEXT NOT NULL DEFAULT now()
    ``next_attempt_at``  TEXT NOT NULL    ISO 8601 UTC; index for the
                                          sweeper's "due" scan
    ``last_error_class`` TEXT             exception class name
    ``last_error_msg``   TEXT             PHI-scrubbed + truncated to
                                          500 chars before insert
    ``last_error_at``    TEXT
    ``resolved_at``      TEXT             set on transition to done / dead
    ``dead_reason``      TEXT             one of:
                                          max_attempts_exceeded /
                                          uidvalidity_changed /
                                          message_gone /
                                          auth_revoked /
                                          operator_abandoned
    ``created_at``       TEXT NOT NULL DEFAULT now()

    Indexes
    -------
    * ``idx_watcher_retry_due`` — partial on ``next_attempt_at`` for
      ``state='pending'``. Powers the sweeper's hot query.
    * ``idx_watcher_retry_account`` — ``(account_id, state)`` for
      admin-UI filters.
    * ``idx_watcher_retry_imap_addr`` — UNIQUE partial on
      ``(account_id, mailbox, uid, uidvalidity)`` for
      ``provider_type='imap'``. Drives INSERT OR IGNORE upsert.
    * ``idx_watcher_retry_gmail_addr`` — UNIQUE partial on
      ``(account_id, gmail_msg_id)`` for ``provider_type='gmail'``.
    * ``idx_watcher_retry_o365_addr`` — UNIQUE partial on
      ``(account_id, o365_msg_id)`` for ``provider_type='office365'``.

    The UNIQUE-partial indexes mean re-enqueuing the same logical
    message is safe — INSERT OR IGNORE on the addressing tuple bumps
    ``attempt_count`` via the application-layer UPDATE branch in
    :func:`email_triage.web.db.enqueue_retry` rather than creating a
    duplicate row.

    Idempotent — ``CREATE TABLE IF NOT EXISTS`` + ``CREATE INDEX IF NOT
    EXISTS`` throughout. Re-running on a DB that already has the table
    is a no-op.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS watcher_retry_queue ("
        "  id               INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  account_id       INTEGER NOT NULL"
        "      REFERENCES email_accounts(id) ON DELETE CASCADE,"
        "  provider_type    TEXT    NOT NULL"
        "      CHECK (provider_type IN ('imap','gmail','office365')),"
        "  mailbox          TEXT,"
        "  uid              INTEGER,"
        "  uidvalidity      INTEGER,"
        "  gmail_msg_id     TEXT,"
        "  o365_msg_id      TEXT,"
        "  state            TEXT    NOT NULL DEFAULT 'pending'"
        "      CHECK (state IN ('pending','done','dead')),"
        "  attempt_count    INTEGER NOT NULL DEFAULT 0,"
        "  first_seen_at    TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  next_attempt_at  TEXT    NOT NULL,"
        "  last_error_class TEXT,"
        "  last_error_msg   TEXT,"
        "  last_error_at    TEXT,"
        "  resolved_at      TEXT,"
        "  dead_reason      TEXT,"
        "  created_at       TEXT    NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_watcher_retry_due "
        "ON watcher_retry_queue (next_attempt_at) "
        "WHERE state='pending'"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_watcher_retry_account "
        "ON watcher_retry_queue (account_id, state)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_watcher_retry_imap_addr "
        "ON watcher_retry_queue (account_id, mailbox, uid, uidvalidity) "
        "WHERE provider_type='imap'"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_watcher_retry_gmail_addr "
        "ON watcher_retry_queue (account_id, gmail_msg_id) "
        "WHERE provider_type='gmail'"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_watcher_retry_o365_addr "
        "ON watcher_retry_queue (account_id, o365_msg_id) "
        "WHERE provider_type='office365'"
    )


@register(31, "create_embedding_bits_install_state")
def _v31_create_embedding_bits_install_state(conn: sqlite3.Connection) -> None:
    """Singleton install-state row for the slim-image lazy embedding stack
    (#180).

    The v0.1.1+ container ships at ~250 MB (vs the v0.1.0 ~2 GiB) by
    lifting torch + sentence-transformers + the all-MiniLM-L6-v2 model
    weights out of the image and downloading them on first use. This
    table tracks the install state of those runtime-only bits so the
    AI Backends admin page can render a status card with progress +
    error surface, the FastAPI startup hook can check "are we ready?"
    before the embedding backend's first call, and the operator can
    retry a partial install without losing state across container
    restarts.

    Why a singleton vs a queue table
    --------------------------------
    The install is install-wide (not per-account), runs at most once
    per container lifetime (idempotent on rerun — verifies hashes and
    skips already-staged files), and has no parallel sibling rows. A
    one-row state table is the right shape; a queue would force fake
    addressing semantics on a non-queue workload. Retry-with-backoff
    semantics live in the worker logic (loop with exponential delay +
    hash-fail re-attempt), not in row state.

    Triage_jobs reuse for the reindex side
    --------------------------------------
    The complementary feature — when the operator switches embedding
    models and existing sent-mail-index vectors need re-computing —
    DOES reuse the existing ``triage_jobs`` table with
    ``kind='embedding_reindex'`` (the discriminator from v21). The
    reindex is genuinely per-account work (sent_mail_index rows are
    scoped per email_accounts.id) and fits the existing job shape
    cleanly. Operator's instruction 2026-05-17 was explicit:
    triage_jobs + kind discriminator for reindex; new lightweight
    state row for install.

    Schema
    ------
      * ``id``                 — INTEGER PK CHECK (id = 1). Belt-and-
                                 braces enforcement that this is a
                                 singleton; INSERT must use id=1 or
                                 the constraint trips.
      * ``status``             — TEXT NOT NULL, one of:
                                   ``"not_installed"`` — fresh
                                                          container,
                                                          nothing
                                                          downloaded
                                   ``"downloading"``   — fetching files
                                                          from upstream
                                   ``"verifying"``     — computing
                                                          SHA-256 over
                                                          downloaded /
                                                          sideloaded
                                                          bits
                                   ``"installing"``    — running pip
                                                          install
                                                          against the
                                                          fetched wheels
                                   ``"installed"``     — runtime deps
                                                          present +
                                                          verified;
                                                          embed backend
                                                          can load
                                   ``"failed"``        — last attempt
                                                          ended in
                                                          error; UI
                                                          surfaces
                                                          [Retry] +
                                                          last_error_*
      * ``install_method``     — TEXT NULLABLE. ``"auto"`` (downloaded
                                 from PyPI + HuggingFace) or
                                 ``"sideload"`` (operator pre-staged
                                 the bits into a known directory).
                                 NULL until the first attempt picks a
                                 method.
      * ``manifest_sha256``    — TEXT NULLABLE. SHA-256 over the
                                 manifest JSON used for this install.
                                 Lets a future version bump detect "the
                                 install on disk is from an older
                                 manifest, re-run".
      * ``runtime_deps_path``  — TEXT NULLABLE. Filesystem location
                                 the installer wrote to (default:
                                 ``/app/data/runtime-deps/site-packages``).
                                 NULL until install completes.
      * ``progress_files_done`` / ``progress_files_total`` — INTEGER
                                 NOT NULL DEFAULT 0. UI progress bar
                                 surface during ``downloading`` /
                                 ``verifying``.
      * ``progress_bytes_done`` / ``progress_bytes_total`` — INTEGER
                                 NOT NULL DEFAULT 0. Byte-level
                                 progress for the larger files
                                 (torch CPU wheel is ~200 MB).
      * ``current_file``       — TEXT NULLABLE. Name of the file
                                 currently being downloaded /
                                 verified, surfaced under the
                                 progress bar.
      * ``attempt_count``      — INTEGER NOT NULL DEFAULT 0. Monotonic
                                 since last success (reset to 0 on
                                 ``status='installed'``). Bumps on each
                                 attempt; surfaces "3 attempts failed"
                                 in the admin banner.
      * ``last_attempt_at``    — TEXT NULLABLE (UTC ISO8601). NULL
                                 until the first attempt.
      * ``installed_at``       — TEXT NULLABLE (UTC ISO8601). Set when
                                 ``status='installed'``. Persists
                                 across re-attempts (lets the UI show
                                 "installed 3 days ago, last verify 1
                                 hour ago" semantics).
      * ``last_error_class``   — TEXT NULLABLE. Short class-name of
                                 the last failure (``"HashMismatch"``,
                                 ``"HTTPError"``, ``"PipInstallError"``).
                                 NULL on clean install paths.
      * ``last_error_msg``     — TEXT NULLABLE. Scrubbed + truncated
                                 to 500 chars before insert. NEVER
                                 raw stderr — could leak a transient
                                 username / token in a pip error path.
      * ``last_error_at``      — TEXT NULLABLE (UTC ISO8601).
      * ``created_at``         — TEXT NOT NULL DEFAULT now(). Row
                                 lifetime marker.

    The migration also seeds the singleton row with status =
    ``not_installed`` on first run so the UI never has to handle the
    "table exists but row missing" case.

    Idempotent — ``CREATE TABLE IF NOT EXISTS`` + ``INSERT OR IGNORE``
    on the singleton. Re-running on a DB that already has the row is
    a no-op.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS embedding_bits_install_state ("
        "  id                    INTEGER PRIMARY KEY CHECK (id = 1),"
        "  status                TEXT    NOT NULL DEFAULT 'not_installed'"
        "      CHECK (status IN ('not_installed','downloading',"
        "                        'verifying','installing','installed',"
        "                        'failed')),"
        "  install_method        TEXT"
        "      CHECK (install_method IN ('auto','sideload') OR install_method IS NULL),"
        "  manifest_sha256       TEXT,"
        "  runtime_deps_path     TEXT,"
        "  progress_files_done   INTEGER NOT NULL DEFAULT 0,"
        "  progress_files_total  INTEGER NOT NULL DEFAULT 0,"
        "  progress_bytes_done   INTEGER NOT NULL DEFAULT 0,"
        "  progress_bytes_total  INTEGER NOT NULL DEFAULT 0,"
        "  current_file          TEXT,"
        "  attempt_count         INTEGER NOT NULL DEFAULT 0,"
        "  last_attempt_at       TEXT,"
        "  installed_at          TEXT,"
        "  last_error_class      TEXT,"
        "  last_error_msg        TEXT,"
        "  last_error_at         TEXT,"
        "  created_at            TEXT    NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "INSERT OR IGNORE INTO embedding_bits_install_state (id) "
        "VALUES (1)"
    )


@register(32, "add_sent_mail_index_embedding_dimension")
def _v32_add_sent_mail_index_embedding_dimension(
    conn: sqlite3.Connection,
) -> None:
    """Add ``embedding_dimension`` column to ``sent_mail_index`` (#180 C).

    The lazy-install embedding-bits feature lets the operator switch
    backends/models after the install is running. When the dimension
    changes (e.g. all-MiniLM-L6-v2 = 384 -> nomic-embed-text = 768),
    the existing vectors become incomparable to new ones (different
    spaces; cosine over mismatched dims is nonsense).

    Today the system stores ``embedding_model`` per row + treats a
    model mismatch as "stale, ignore", but it lacks an explicit
    dimension column. Adding it lets:

      * The reindex job (#180 C) detect dimension changes cheaply
        without re-loading the backend at scan time.
      * The retrieval helper short-circuit on dim mismatch even
        when the operator renamed the model but kept the same
        dim (e.g. fine-tuned variant of MiniLM still at 384) —
        avoiding a stale-by-name-but-compatible-by-dim false negative.

    Idempotent column-add — skipped on installs where the column
    already exists. New rows backfill via the next index_message
    call (the dimension is derived from the embedding vector's
    actual length, stored alongside the packed bytes); rows from
    pre-v32 have NULL dimension which the reindex job treats as
    "unknown, re-embed".
    """
    cur = conn.execute("PRAGMA table_info(sent_mail_index)")
    existing = {row[1] for row in cur.fetchall()}
    if "embedding_dimension" not in existing:
        conn.execute(
            "ALTER TABLE sent_mail_index "
            "ADD COLUMN embedding_dimension INTEGER"
        )
