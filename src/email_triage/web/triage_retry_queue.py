"""Durable retry queue for triage attempts that the LLM rejected
(#149 Bundle A).

When the classify step fails because the LLM backend is offline
(``LLMBackendUnreachableError`` from ``email_triage.llm_health``),
losing the message is the wrong move — the operator should be
able to bring the LLM back up and have queued mail get classified
without re-fetching it from the provider. This module is the
durable backbone: rows live in ``triage_retry_queue`` (migration
v16); a background worker drains them on an exponential backoff.

Schema (v16, see ``web/migrations.py``)::

    CREATE TABLE triage_retry_queue (
      id              INTEGER PK AUTOINCREMENT,
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
    );
    CREATE INDEX idx_triage_retry_queue_ready
      ON triage_retry_queue(next_attempt_at, account_id);

Backoff: 1m, 2m, 4m, 8m, 15m, 30m, 60m, 120m. ±10% jitter on each
to avoid thundering-herd retries when a 100-message backlog all
becomes ready at the same minute.

Idempotency: ``(account_id, message_id)`` is logically unique —
:func:`enqueue` UPDATEs the existing row instead of INSERTing
a duplicate. Two parallel watchers hitting the same message both
end up with one row, attempt_count bumped twice (ok — that means
"we tried twice and both failed", which is true).
"""

from __future__ import annotations

import logging
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any


_log = logging.getLogger("email_triage.web.triage_retry_queue")


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Default exponential backoff schedule (minutes). Index into this
# list by attempt_count. Past the end → terminal failure.
DEFAULT_BACKOFF_MINUTES: tuple[int, ...] = (1, 2, 4, 8, 15, 30, 60, 120)

DEFAULT_MAX_ATTEMPTS: int = len(DEFAULT_BACKOFF_MINUTES)

DEFAULT_JITTER_FRACTION: float = 0.10  # ±10%


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_next_attempt_at(
    attempt_count: int,
    *,
    schedule: tuple[int, ...] = DEFAULT_BACKOFF_MINUTES,
    jitter_fraction: float = DEFAULT_JITTER_FRACTION,
    rng: random.Random | None = None,
) -> tuple[str, int]:
    """Return ``(iso_timestamp, applied_minutes_int)`` for the next
    retry of a row whose pre-bump ``attempt_count`` was N.

    ``applied_minutes_int`` is the post-jitter minute count, useful
    for log lines + tests. Jitter is symmetric: ±jitter_fraction of
    the base schedule entry.
    """
    if not schedule:
        # Defensive: empty schedule means "retry immediately".
        return (_utc_now_iso(), 0)
    idx = min(max(0, attempt_count), len(schedule) - 1)
    base = schedule[idx]
    r = rng or random
    jitter = base * jitter_fraction * (2 * r.random() - 1)  # [-frac, +frac]
    minutes = max(0.0, base + jitter)
    next_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return (next_at.isoformat(), int(round(minutes)))


def _row_to_dict(row: Any) -> dict[str, Any]:
    if hasattr(row, "keys"):
        return {k: row[k] for k in row.keys()}
    # Tuple shape — preserve stable ordering matching the SELECT below.
    cols = (
        "id", "message_id", "account_id", "mailbox", "uid",
        "attempt_count", "next_attempt_at", "last_error",
        "last_error_type", "created_at", "updated_at",
    )
    return {c: row[i] for i, c in enumerate(cols)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enqueue(
    conn: sqlite3.Connection,
    *,
    message_id: str,
    account_id: int,
    mailbox: str | None,
    uid: str | None,
    error: Exception,
    schedule: tuple[int, ...] = DEFAULT_BACKOFF_MINUTES,
    jitter_fraction: float = DEFAULT_JITTER_FRACTION,
    rng: random.Random | None = None,
) -> dict[str, Any]:
    """Insert a retry row, OR bump attempt_count on an existing row.

    Returns the row dict after the write. Caller logs via the
    returned ``attempt_count`` so a watcher's "queued for retry"
    line shows "attempt 3 of 8" without an extra DB round-trip.

    The ``error`` argument is captured as ``last_error`` (string)
    and ``last_error_type`` (class name). Stack traces are not
    captured — the row is operator-facing, not a debugger surface.
    """
    now_iso = _utc_now_iso()
    err_text = str(error)[:1000]  # cap so a giant traceback can't bloat the row
    err_type = type(error).__name__

    cur = conn.execute(
        "SELECT id, attempt_count FROM triage_retry_queue "
        "WHERE account_id = ? AND message_id = ? LIMIT 1",
        (int(account_id), str(message_id)),
    )
    existing = cur.fetchone()

    if existing is not None:
        existing_id = existing["id"] if hasattr(existing, "keys") else existing[0]
        existing_attempts = existing["attempt_count"] if hasattr(existing, "keys") else existing[1]
        new_attempts = int(existing_attempts) + 1
        next_at, _minutes = _compute_next_attempt_at(
            new_attempts, schedule=schedule,
            jitter_fraction=jitter_fraction, rng=rng,
        )
        conn.execute(
            "UPDATE triage_retry_queue SET "
            "attempt_count = ?, next_attempt_at = ?, "
            "last_error = ?, last_error_type = ?, updated_at = ? "
            "WHERE id = ?",
            (new_attempts, next_at, err_text, err_type, now_iso, existing_id),
        )
        conn.commit()
        return {
            "id": int(existing_id),
            "message_id": str(message_id),
            "account_id": int(account_id),
            "mailbox": mailbox,
            "uid": uid,
            "attempt_count": new_attempts,
            "next_attempt_at": next_at,
            "last_error": err_text,
            "last_error_type": err_type,
            "created_at": now_iso,  # not authoritative — caller should not rely on this for existing rows
            "updated_at": now_iso,
        }

    # First enqueue — attempt_count starts at 0 (the failure that
    # triggered this enqueue is the "0th try"; the worker's next
    # attempt is the 1st, so we backoff using index 0 = 1 minute).
    next_at, _minutes = _compute_next_attempt_at(
        0, schedule=schedule, jitter_fraction=jitter_fraction, rng=rng,
    )
    cur = conn.execute(
        "INSERT INTO triage_retry_queue ("
        "  message_id, account_id, mailbox, uid, attempt_count, "
        "  next_attempt_at, last_error, last_error_type, "
        "  created_at, updated_at"
        ") VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
        (
            str(message_id), int(account_id),
            mailbox, uid,
            next_at, err_text, err_type,
            now_iso, now_iso,
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    return {
        "id": int(new_id) if new_id else 0,
        "message_id": str(message_id),
        "account_id": int(account_id),
        "mailbox": mailbox,
        "uid": uid,
        "attempt_count": 0,
        "next_attempt_at": next_at,
        "last_error": err_text,
        "last_error_type": err_type,
        "created_at": now_iso,
        "updated_at": now_iso,
    }


def dequeue_ready(
    conn: sqlite3.Connection,
    *,
    limit: int = 10,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    now_iso: str | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``limit`` rows whose ``next_attempt_at <= now`` AND
    whose ``attempt_count < max_attempts``.

    Rows whose ``attempt_count >= max_attempts`` are NOT returned —
    they should be drained via :func:`mark_terminal_failure` by an
    operator-facing sweep. The worker calls this then fans out one
    re-fetch per row.
    """
    when = now_iso or _utc_now_iso()
    cur = conn.execute(
        "SELECT id, message_id, account_id, mailbox, uid, "
        "       attempt_count, next_attempt_at, last_error, "
        "       last_error_type, created_at, updated_at "
        "FROM triage_retry_queue "
        "WHERE next_attempt_at <= ? "
        "  AND attempt_count < ? "
        "ORDER BY next_attempt_at ASC "
        "LIMIT ?",
        (when, int(max_attempts), int(limit)),
    )
    return [_row_to_dict(r) for r in cur.fetchall()]


def mark_succeeded(conn: sqlite3.Connection, queue_id: int) -> None:
    """Delete the row — retry succeeded."""
    conn.execute(
        "DELETE FROM triage_retry_queue WHERE id = ?",
        (int(queue_id),),
    )
    conn.commit()


def mark_terminal_failure(
    conn: sqlite3.Connection,
    queue_id: int,
    *,
    reason: str = "max_attempts_exhausted",
) -> None:
    """Delete the row + emit a loud ERROR log.

    Per the punch-list spec we delete rather than carrying a
    terminal-failure status column: a row sitting around with
    nowhere to go just creates noise + storage overhead. The ERROR
    log line is the durable artefact; the operator can find it via
    ``/logs`` later.
    """
    cur = conn.execute(
        "SELECT message_id, account_id, mailbox, uid, "
        "       attempt_count, last_error, last_error_type "
        "FROM triage_retry_queue WHERE id = ? LIMIT 1",
        (int(queue_id),),
    )
    row = cur.fetchone()
    if row is None:
        return  # Already gone — idempotent.
    rd = _row_to_dict(row)
    conn.execute(
        "DELETE FROM triage_retry_queue WHERE id = ?",
        (int(queue_id),),
    )
    conn.commit()
    _log.error(
        "Triage retry queue: terminal failure",
        extra={"_extra": {
            "queue_id": int(queue_id),
            "message_id": rd.get("message_id"),
            "account_id": rd.get("account_id"),
            "mailbox": rd.get("mailbox"),
            "attempt_count": rd.get("attempt_count"),
            "last_error_type": rd.get("last_error_type"),
            "reason": reason,
        }},
    )


def queue_depth(conn: sqlite3.Connection) -> int:
    """Return total rows in ``triage_retry_queue``. Used by the UI
    banner ("M messages queued for retry")."""
    cur = conn.execute("SELECT COUNT(*) FROM triage_retry_queue")
    row = cur.fetchone()
    if row is None:
        return 0
    return int(row[0] if not hasattr(row, "keys") else row[0])


__all__ = [
    "DEFAULT_BACKOFF_MINUTES",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_JITTER_FRACTION",
    "enqueue",
    "dequeue_ready",
    "mark_succeeded",
    "mark_terminal_failure",
    "queue_depth",
    "_compute_next_attempt_at",
]
