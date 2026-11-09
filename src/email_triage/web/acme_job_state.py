"""Job-state tracker for the ACME issuance worker.

Originally this was a process-memory singleton: enough for
the live re-attach UI but lost on every process restart. the backlog
 lifts the state to a persistent ``acme_jobs`` row so a kill
mid-issuance doesn't drop the LE order context on the floor.

The public surface (``start`` / ``transition`` / ``visibility`` /
``finish_success`` / ``finish_failure`` / ``current_state``) is
unchanged. When a DB handle is bound via ``set_db_handle(conn)``,
every mutation also writes through to the bound row; reads return
the DB row when present, otherwise fall back to the in-RAM cache.

The single-flight invariant is preserved: only one ACME issuance
runs at a time per install (``single_flight`` decorator on
``issue_now_async``), so a single "current job" record is the
right shape. The DB just outlives the process.

Additions for  / :
  - ``cancel_requested`` flag exposed via ``is_cancel_requested()``;
    the worker checks at retry-loop boundaries and transitions to
    ``cancelled`` cleanly.
  - ``request_cancel()`` flips the flag (UI Cancel button hits it
    via the new admin endpoint).
  - ``cancelled`` phase added to ``PHASES`` and treated as terminal.
  - ``find_resumable()`` returns rows where ``phase`` is non-terminal
    so the supervised worker can resume them on startup.

Storage: a single ``acme_jobs`` row per issuance. The row carrying
the live job is the most-recent ``created_at`` row; older rows are
the recent-history surface ( calls for the last-10 list on
``/admin/tls`` similar to Recent Bulk Runs).
"""

from __future__ import annotations

from email_triage.db.columns import ACME_JOBS_COLUMNS
from email_triage.db._helpers import dump_json_col, load_json_col

import json
import secrets as _secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any

from email_triage._isotime import now_utc_iso, parse_iso
from email_triage.db._helpers import apply_compatible_row_factory
from email_triage._dbapi_errors import DB_ERRORS, DB_OPERATIONAL_ERRORS
from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger

log = get_logger("web.acme")


# Phase enum (string-typed to keep JSON serialization trivial).
# 'cancelled' added in  -- separates operator-cancelled from
# automatic-failed for the UI status pill + future filtering on
# the recent-jobs surface.
PHASES: tuple[str, ...] = (
    "idle",
    "starting",
    "publishing",
    "polling_local",
    "polling_authoritative",
    "grace",
    "answering",
    "finalizing",
    "retrying",
    "done",
    "failed",
    "cancelled",
)

# Terminal phases; UI polling stops on these.
TERMINAL_PHASES: frozenset[str] = frozenset({
    "idle", "done", "failed", "cancelled",
})


# ---------------------------------------------------------------------------
# DB binding
# ---------------------------------------------------------------------------

# Module-level DB handle. ``set_db_handle(conn)`` is called once
# during app startup (after init_db); the AcmeRenewer + admin
# routes inherit the binding. Tests that exercise the in-RAM
# fallback simply skip the bind call.
_db_lock = threading.Lock()
_db: sqlite3.Connection | None = None
# True when ``_db`` is a dedicated connection this module opened
# itself (file-backed install) — so detach can close it. False when
# ``_db`` is the shared app connection (in-memory / test path), which
# this module must NOT close.
_db_owned: bool = False


def _resolve_main_db_path(conn: sqlite3.Connection) -> str | None:
    """Return the file path backing ``conn``'s ``main`` database.

    None for an in-memory database — a second ``connect(":memory:")``
    opens an unrelated empty DB, so the dedicated-connection path
    must fall back to the shared connection in that case.
    """
    try:
        for row in conn.execute("PRAGMA database_list").fetchall():
            if row[1] == "main":
                return row[2] or None
    except DB_ERRORS:
        return None
    return None


def _open_dedicated_conn(db_path: str) -> sqlite3.Connection:
    """Open a dedicated connection for ``acme_jobs`` writes, mirroring
    the PRAGMAs ``init_db`` sets on the main connection.

     — ``acme_job_state`` must not write the shared app
    connection: a foreign ROLLBACK from a concurrent threadpool write
    helper could discard a half-built ``acme_jobs`` write. Its own
    connection isolates its commit scope.
    """
    # N-17: route through the encrypted-aware shared opener so the
    # acme_jobs writer opens against an ENCRYPTED file on an encrypted
    # install (raw sqlite3.connect would hard-crash at the first PRAGMA).
    # The opener self-selects encrypted-vs-plaintext + applies the same
    # WAL/busy/FK PRAGMAs this site set inline.
    from email_triage.db._engine import open_dedicated_conn

    conn = open_dedicated_conn(db_path, check_same_thread=False)
    from email_triage.single_flight import set_cached_db_path

    set_cached_db_path(conn, db_path)
    # N-16: factory from the conn's own dbapi module (sqlite3.Row vs
    # sqlcipher3.dbapi2.Row) — open_dedicated_conn may return either.
    apply_compatible_row_factory(conn)
    return conn


def set_db_handle(conn: sqlite3.Connection | None) -> None:
    """Bind the SQLite connection used for ``acme_jobs`` persistence.

    Pass ``None`` to detach (used by tests that exercise the
    RAM-only fallback path).

     — when ``conn`` is file-backed this module opens its OWN
    dedicated connection on the same DB file (isolated commit scope,
    so a foreign ROLLBACK on the shared connection can't discard an
    ``acme_jobs`` write). For an in-memory database it keeps the
    shared connection — a second ``:memory:`` connect would open an
    unrelated empty DB.
    """
    global _db, _db_owned
    with _db_lock:
        # Close a previously-opened dedicated connection before
        # rebinding so a re-bind / detach doesn't leak a handle.
        if _db_owned and _db is not None:
            try:
                _db.close()
            except DB_ERRORS:
                pass
        if conn is None:
            _db = None
            _db_owned = False
            return
        db_path = _resolve_main_db_path(conn)
        if db_path:
            _db = _open_dedicated_conn(db_path)
            _db_owned = True
        else:
            # In-memory database — cannot be reopened; share it.
            _db = conn
            _db_owned = False


def _get_db() -> sqlite3.Connection | None:
    with _db_lock:
        return _db


# ---------------------------------------------------------------------------
# In-RAM cache (fallback + cross-thread coalescing)
# ---------------------------------------------------------------------------

class _JobState:
    """Mutable singleton; protected by a single lock.

    Even with DB persistence the in-RAM mirror is useful: the
    worker thread updates phase 10+ times per attempt; an in-RAM
    write coalesces with a DB UPSERT so the snapshot reads on the
    UI poll path don't have to round-trip SQLite for each request.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reset_unlocked()

    def _reset_unlocked(self) -> None:
        self.job_id: str | None = None
        self.phase: str = "idle"
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.attempt: int = 0
        self.max_attempts: int = 0
        self.domains: list[str] = []
        self.directory_url: str | None = None
        self.order_url: str | None = None
        self.last_error: str | None = None
        self.last_error_kind: str | None = None
        self.result: dict[str, Any] | None = None
        # Per-domain visibility map: domain -> {local, authoritative,
        # public_count}.
        self.visibility: dict[str, dict[str, Any]] = {}
        self.cancel_requested: bool = False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            elapsed = (
                (now - self.started_at) if self.started_at else 0.0
            )
            return {
                "job_id": self.job_id,
                "phase": self.phase,
                "in_flight": self.phase not in TERMINAL_PHASES,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "elapsed_secs": elapsed,
                "attempt": self.attempt,
                "max_attempts": self.max_attempts,
                "domains": list(self.domains),
                "directory_url": self.directory_url,
                "order_url": self.order_url,
                "last_error": self.last_error,
                "last_error_kind": self.last_error_kind,
                "result": self.result,
                "visibility": {k: dict(v) for k, v in self.visibility.items()},
                "cancel_requested": self.cancel_requested,
            }

    def start(
        self,
        domains: list[str],
        directory_url: str,
        max_attempts: int,
        actor_user_id: int | None = None,
    ) -> str:
        with self._lock:
            self._reset_unlocked()
            # N-244 R24: SSOT — `_ids.new_short_id`. Byte-identical shape.
            from email_triage._ids import new_short_id
            self.job_id = new_short_id("acme")
            self.phase = "starting"
            self.started_at = time.time()
            self.attempt = 0
            self.max_attempts = max_attempts
            self.domains = list(domains)
            self.directory_url = directory_url
            for d in domains:
                self.visibility[d] = {
                    "local": False,
                    "authoritative": False,
                    "public_count": 0,
                }
            return self.job_id

    def transition(self, phase: str, **fields: Any) -> None:
        if phase not in PHASES:
            raise ValueError(f"unknown phase: {phase!r}")
        with self._lock:
            self.phase = phase
            for k, v in fields.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def visibility_set(self, domain: str, **flags: Any) -> None:
        with self._lock:
            entry = self.visibility.setdefault(
                domain,
                {"local": False, "authoritative": False, "public_count": 0},
            )
            entry.update(flags)

    def finish_success(self, result: dict[str, Any]) -> None:
        with self._lock:
            self.phase = "done"
            self.finished_at = time.time()
            self.result = dict(result)
            self.last_error = None
            self.last_error_kind = None

    def finish_failure(
        self, error: str, *, kind: str | None = None,
    ) -> None:
        with self._lock:
            # 'cancelled' kind routes to the cancelled terminal
            # phase so the UI can distinguish operator-aborted from
            # automatic-failed.
            self.phase = "cancelled" if kind == "cancelled" else "failed"
            self.finished_at = time.time()
            #  tail — ACME job errors are displayed in the ACME
            # status UI (`last_error` is read by the operator-facing
            # status endpoint). Route through scrub_exc so provider
            # errors (DNS challenge failures, TSIG key issues) cannot
            # echo secret fragments to the operator UI. Log sinks
            # upstream preserve full traceback for privileged debug.
            from email_triage.web._flash import scrub_exc
            if isinstance(error, BaseException):
                self.last_error = scrub_exc(error, purpose="form")
            else:
                self.last_error = scrub_exc(str(error), purpose="form")
            self.last_error_kind = kind

    def reset(self) -> None:
        """Clear back to idle. Used by tests; also useful if an
        operator needs to clear a stuck terminal state from the UI.
        """
        with self._lock:
            self._reset_unlocked()

    def request_cancel(self) -> None:
        with self._lock:
            self.cancel_requested = True

    def is_cancel_requested(self) -> bool:
        with self._lock:
            return self.cancel_requested


# Module-level singleton. The product invariant (single concurrent
# issuance) makes a global the right shape.
_STATE = _JobState()


# ---------------------------------------------------------------------------
# DB write-through helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return now_utc_iso()


def _row_to_snapshot(row: sqlite3.Row | dict | None) -> dict[str, Any] | None:
    """Convert an ``acme_jobs`` row to the same dict shape that
    ``_JobState.snapshot()`` returns. None on missing input."""
    if row is None:
        return None
    if hasattr(row, "keys"):
        d = dict(row)
    else:
        # tuple form (unlikely with row_factory=Row but tolerate it)
        d = dict(row)
    domains = []
    try:
        domains = load_json_col(d.get("domains_json"), default=[])
    except (TypeError, ValueError):
        domains = []
    visibility = {}
    try:
        visibility = load_json_col(d.get("visibility_json"), default={})
    except (TypeError, ValueError):
        visibility = {}
    started_at = d.get("started_at")
    _started_dt = parse_iso(started_at)
    started_epoch = (
        _started_dt.timestamp() if _started_dt is not None else None
    )
    ended_at = d.get("ended_at")
    _ended_dt = parse_iso(ended_at)
    finished_epoch = (
        _ended_dt.timestamp() if _ended_dt is not None else None
    )
    elapsed = 0.0
    if started_epoch:
        ref = finished_epoch or time.time()
        elapsed = max(0.0, ref - started_epoch)
    phase = d.get("phase") or "idle"
    return {
        "job_id": d.get("job_id"),
        "phase": phase,
        "in_flight": phase not in TERMINAL_PHASES,
        "started_at": started_epoch,
        "finished_at": finished_epoch,
        "elapsed_secs": elapsed,
        "attempt": int(d.get("attempt") or 0),
        "max_attempts": int(d.get("max_attempts") or 0),
        "domains": domains,
        "directory_url": d.get("directory_url"),
        "order_url": d.get("order_url"),
        "last_error": d.get("last_error"),
        "last_error_kind": d.get("last_error_kind"),
        "result": None,  # rebuild on terminal phase from cert metadata
        "visibility": visibility,
        "cancel_requested": bool(d.get("cancel_requested") or 0),
        "created_at": d.get("created_at"),
        "ended_at": d.get("ended_at"),
        "last_progress_at": d.get("last_progress_at"),
        "actor_user_id": d.get("actor_user_id"),
    }


def _db_insert_row(state_snapshot: dict[str, Any], actor_user_id: int | None) -> None:
    conn = _get_db()
    if conn is None:
        return
    now = _now_iso()
    started_iso = (
        datetime.fromtimestamp(state_snapshot["started_at"], tz=timezone.utc)
        .isoformat() if state_snapshot.get("started_at") else None
    )
    # SW-1 (2026-05-31): serialize this acme dedicated-conn write with the main
    # writer under the  process-wide write lock (INCIDENT-1 cross-conn
    # WAL-contention class). No logging inside the locked region -> no handler.lock
    # inversion;  is the outermost lock everywhere -> no deadlock.
    from email_triage.web.db_writelock import get_write_lock
    try:
        with get_write_lock():
            conn.execute(
                """
                INSERT INTO acme_jobs (
                    job_id, actor_user_id, domains_json, directory_url,
                    phase, attempt, max_attempts, visibility_json,
                    cancel_requested, started_at, last_progress_at,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state_snapshot["job_id"],
                    actor_user_id,
                    dump_json_col(state_snapshot["domains"]),
                    state_snapshot["directory_url"],
                    state_snapshot["phase"],
                    state_snapshot["attempt"],
                    state_snapshot["max_attempts"],
                    dump_json_col(state_snapshot["visibility"]),
                    1 if state_snapshot["cancel_requested"] else 0,
                    started_iso,
                    now,
                    now,
                ),
            )
            conn.commit()
    except DB_OPERATIONAL_ERRORS as e:
        # Table missing (no migration ran) — fall back to RAM-only
        # state so older test setups keep working; log the miss.
        log.warning(
            "acme job row not persisted; keeping RAM-only state",
            job_id=state_snapshot.get("job_id"),
            error=fmt_exc(e),
        )


def _db_update_row(job_id: str | None, fields: dict[str, Any]) -> None:
    """Apply a partial UPDATE to the ``acme_jobs`` row identified
    by ``job_id``. Silently no-ops if the binding or the row is
    missing (RAM-only fallback)."""
    conn = _get_db()
    if conn is None or not job_id:
        return
    if not fields:
        return
    # census #6/#8 — scrub the persisted last_error at the single write
    # boundary (covers phase/finish_failure/cancel). The ACME path carries
    # TSIG HMAC keys + ACME/EAB creds (secret leg) AND a mail/DNS exception can
    # echo a recipient address or mailbox path (PHI leg); last_error renders in
    # the admin UI, so a raw exception leaks either. Route through the persist
    # SSOT (BOTH legs) — census run13 #8 closed the PHI leg that the
    # secret-only scrub left open here.
    if fields.get("last_error"):
        from email_triage._errfmt import scrub_error_for_persist
        fields = {**fields, "last_error": scrub_error_for_persist(fields["last_error"])}
    cols = ", ".join(f"{k} = ?" for k in fields.keys())
    vals = list(fields.values()) + [job_id]
    # SW-1: serialize with the main writer under  (see _db_insert_row).
    from email_triage.web.db_writelock import get_write_lock
    try:
        with get_write_lock():
            conn.execute(
                f"UPDATE acme_jobs SET {cols} WHERE job_id = ?",
                vals,
            )
            conn.commit()
    except DB_OPERATIONAL_ERRORS as e:
        log.warning(
            "acme job update not persisted; keeping RAM-only state",
            job_id=job_id,
            error=fmt_exc(e),
        )


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def current_state() -> dict[str, Any]:
    """Snapshot for JSON serialization.

    Source of truth: the in-RAM cache (kept current by every mutation
    in this process). The DB row is the persistence layer for restart
    survival; ``find_resumable`` reads it on app startup. Mid-process
    UI polls hit the cache to avoid SQLite round-trips.
    """
    return _STATE.snapshot()


def get_persisted_row(job_id: str) -> dict[str, Any] | None:
    """Look up an ``acme_jobs`` row by id. Returns the snapshot dict
    or None if not bound / not found."""
    conn = _get_db()
    if conn is None:
        return None
    try:
        row = conn.execute(
            f"SELECT {ACME_JOBS_COLUMNS} FROM acme_jobs WHERE job_id = ?", (job_id,),
        ).fetchone()
    except DB_OPERATIONAL_ERRORS:
        return None
    return _row_to_snapshot(row)


def list_recent(limit: int = 10) -> list[dict[str, Any]]:
    """Recent ACME jobs, newest first. Empty if not bound."""
    conn = _get_db()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            f"SELECT {ACME_JOBS_COLUMNS} FROM acme_jobs "
            "ORDER BY created_at DESC LIMIT ?", (int(limit),),
        ).fetchall()
    except DB_OPERATIONAL_ERRORS:
        return []
    return [_row_to_snapshot(r) for r in rows]


def find_resumable() -> list[dict[str, Any]]:
    """Return rows whose phase is non-terminal -- candidates for
    resume on app startup. Empty if the DB binding is absent or
    the table doesn't exist yet."""
    conn = _get_db()
    if conn is None:
        return []
    placeholders = ", ".join("?" for _ in TERMINAL_PHASES)
    try:
        rows = conn.execute(
            f"SELECT {ACME_JOBS_COLUMNS} FROM acme_jobs "
            f"WHERE phase NOT IN ({placeholders}) "
            f"ORDER BY created_at ASC",
            tuple(TERMINAL_PHASES),
        ).fetchall()
    except DB_OPERATIONAL_ERRORS:
        return []
    return [_row_to_snapshot(r) for r in rows]


def start(
    domains: list[str],
    directory_url: str,
    max_attempts: int,
    *,
    actor_user_id: int | None = None,
) -> str:
    """Mark a new job as starting. Returns the new job_id.

    Resets prior terminal state on the in-RAM mirror. Inserts a new
    ``acme_jobs`` row when the DB is bound.
    """
    job_id = _STATE.start(
        domains, directory_url, max_attempts, actor_user_id,
    )
    snap = _STATE.snapshot()
    _db_insert_row(snap, actor_user_id=actor_user_id)
    return job_id


def transition(phase: str, **fields: Any) -> None:
    """Move to a new phase + optionally update tracked fields."""
    _STATE.transition(phase, **fields)
    snap = _STATE.snapshot()
    update: dict[str, Any] = {
        "phase": snap["phase"],
        "attempt": snap["attempt"],
        "max_attempts": snap["max_attempts"],
        "last_progress_at": _now_iso(),
    }
    # Surface the recoverable fields the resume logic needs.
    if "order_url" in fields or snap.get("order_url"):
        update["order_url"] = snap.get("order_url")
    if "last_error" in fields:
        update["last_error"] = snap.get("last_error")
    _db_update_row(snap["job_id"], update)


def visibility(domain: str, **flags: Any) -> None:
    """Stamp per-domain DNS visibility flags."""
    _STATE.visibility_set(domain, **flags)
    snap = _STATE.snapshot()
    _db_update_row(snap["job_id"], {
        "visibility_json": dump_json_col(snap["visibility"]),
        "last_progress_at": _now_iso(),
    })


def finish_success(result: dict[str, Any]) -> None:
    """Mark terminal-success. ``result`` is the cert metadata dict."""
    _STATE.finish_success(result)
    snap = _STATE.snapshot()
    _db_update_row(snap["job_id"], {
        "phase": "done",
        "ended_at": _now_iso(),
        "last_progress_at": _now_iso(),
        "last_error": None,
        "last_error_kind": None,
    })


def finish_failure(error: str, *, kind: str | None = None) -> None:
    """Mark terminal-failure. ``kind`` is an optional short
    classification (e.g. 'CAA', 'rate_limited', 'validation',
    'cancelled')."""
    _STATE.finish_failure(error, kind=kind)
    snap = _STATE.snapshot()
    _db_update_row(snap["job_id"], {
        "phase": snap["phase"],
        "ended_at": _now_iso(),
        "last_progress_at": _now_iso(),
        "last_error": str(error),
        "last_error_kind": kind,
    })


def reset() -> None:
    """Clear back to idle (in-RAM only -- DB rows are history)."""
    _STATE.reset()


def request_cancel(job_id: str | None = None) -> bool:
    """Flip the ``cancel_requested`` flag. The worker reads it at
    each retry-loop boundary and transitions to ``cancelled``.

    When ``job_id`` is given and matches a persisted row, the flag
    is also flipped on the row (so a worker that boot-resumes a
    cancelled job picks up the intent). Idempotent: cancelling an
    already-cancelled or terminal job is a no-op (returns False);
    cancelling a live job returns True.
    """
    snap = _STATE.snapshot()
    target_id = job_id or snap.get("job_id")
    # Idempotency: if the row exists and is already in a terminal
    # phase, no-op.
    if target_id:
        row = get_persisted_row(target_id)
        if row and row["phase"] in TERMINAL_PHASES:
            return False
    # Flip in-RAM only when this process owns the live job
    # (otherwise the in-RAM cache may be unrelated -- a cross-
    # process cancel writes the DB row only).
    if snap.get("job_id") == target_id:
        if snap.get("phase") in TERMINAL_PHASES:
            return False
        _STATE.request_cancel()
    _db_update_row(target_id, {
        "cancel_requested": 1,
        "last_progress_at": _now_iso(),
    })
    return True


def is_cancel_requested(job_id: str | None = None) -> bool:
    """Has cancel been requested on the in-flight (or named) job?

    Reads from the in-RAM mirror first (fast path). Falls back to
    the DB row if a job_id is given that isn't this process's
    current job (e.g. a resume worker checking its own row)."""
    snap = _STATE.snapshot()
    target_id = job_id or snap.get("job_id")
    if snap.get("job_id") == target_id and target_id is not None:
        return _STATE.is_cancel_requested()
    if target_id:
        row = get_persisted_row(target_id)
        if row:
            return bool(row.get("cancel_requested"))
    return False


def adopt_persisted(job_id: str) -> bool:
    """Load the named persisted row into the in-RAM mirror so this
    process can resume it. Returns True if adopted.

    Used by the supervised worker on app startup -- it picks a
    resumable row, calls adopt, and proceeds with the existing
    transition() / finish_*() helpers as if it had originated the
    job in this process.

    #239d -- refuses to rebind ``_STATE`` when a *different* job is
    currently live (non-terminal phase) in this process. The resume
    worker runs on every renewer tick, NOT under the ``single_flight``
    lock that guards ``issue_now_async``; an operator clicking "Issue
    Now" the instant the resume sweep fires would otherwise have its
    live job's ``_STATE`` reset out from under it, corrupting both
    rows. Adopting the same job id is still allowed (idempotent
    re-adopt); an idle ``_STATE`` is always adoptable.
    """
    row = get_persisted_row(job_id)
    if row is None:
        return False
    with _STATE._lock:
        if (
            _STATE.phase not in TERMINAL_PHASES
            and _STATE.job_id is not None
            and _STATE.job_id != job_id
        ):
            return False
        _STATE._reset_unlocked()
        _STATE.job_id = row["job_id"]
        _STATE.phase = row["phase"]
        _STATE.started_at = row["started_at"]
        _STATE.finished_at = row["finished_at"]
        _STATE.attempt = row["attempt"]
        _STATE.max_attempts = row["max_attempts"]
        _STATE.domains = list(row["domains"])
        _STATE.directory_url = row["directory_url"]
        _STATE.order_url = row.get("order_url")
        _STATE.last_error = row["last_error"]
        _STATE.last_error_kind = row["last_error_kind"]
        _STATE.visibility = dict(row["visibility"])
        _STATE.cancel_requested = bool(row["cancel_requested"])
    return True


def resume_on_startup(*, max_age_secs: int = 7 * 24 * 3600) -> list[dict[str, Any]]:
    """Scan ``acme_jobs`` for non-terminal rows and resolve each.

    Resume policy:
      1. ``order_url`` NULL              -> mark cancelled (the worker
         hadn't reached LE yet; safe-cheap to retry from the top via
         the next renewal tick rather than auto-resume here).
      2. ``order_url`` set, recent       -> leave as-is + log; the
         resume worker (future  piece) polls LE.
      3. ``order_url`` set, stale (older
         than ``max_age_secs``)          -> mark cancelled; LE order
         likely aged out; operator decides whether to retry.

    Returns the list of resolved row snapshots (decided action +
    reason in ``last_error_kind``).

    Implementation note: the spec calls for "poll LE for finalization"
    on case 2; that's a non-trivial async piece + needs the renewer
    instance + account key. For this bundle we mark the row with the
    resume verdict ("resume_pending" or "stale_cancelled") and let
    the supervised worker (sibling piece on the backlog) pick it
    up. Tests cover the verdict-stamp behaviour directly.
    """
    resolved: list[dict[str, Any]] = []
    rows = find_resumable()
    now = time.time()
    for row in rows:
        verdict: str
        if row.get("cancel_requested"):
            # Cancel-requested before the kill: honour it.
            _db_update_row(row["job_id"], {
                "phase": "cancelled",
                "ended_at": _now_iso(),
                "last_progress_at": _now_iso(),
                "last_error": "operator cancelled before restart",
                "last_error_kind": "cancelled",
            })
            verdict = "cancelled"
        elif not row.get("order_url"):
            # Pre-LE-order kill: nothing to resume; mark cancelled.
            _db_update_row(row["job_id"], {
                "phase": "cancelled",
                "ended_at": _now_iso(),
                "last_progress_at": _now_iso(),
                "last_error": (
                    "process restart before LE order placed; "
                    "no rate-limit consequence to retry"
                ),
                "last_error_kind": "restart_no_order",
            })
            verdict = "cancelled_no_order"
        else:
            started = row.get("started_at") or 0
            age = max(0, now - started)
            if age > max_age_secs:
                _db_update_row(row["job_id"], {
                    "phase": "cancelled",
                    "ended_at": _now_iso(),
                    "last_progress_at": _now_iso(),
                    "last_error": (
                        f"LE order older than {max_age_secs}s "
                        f"on resume; likely aged out"
                    ),
                    "last_error_kind": "stale_order",
                })
                verdict = "cancelled_stale"
            else:
                # Live order, recent enough -- defer to the resume
                # worker. Stamp the row so the surface shows it.
                _db_update_row(row["job_id"], {
                    "phase": "retrying",
                    "last_progress_at": _now_iso(),
                    "last_error": (
                        "process restart mid-issuance; "
                        "resume pending"
                    ),
                    "last_error_kind": "resume_pending",
                })
                verdict = "resume_pending"
        snap = get_persisted_row(row["job_id"])
        if snap is not None:
            snap["_verdict"] = verdict
            resolved.append(snap)
    return resolved
