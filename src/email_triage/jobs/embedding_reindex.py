"""Re-embed an account's ``sent_mail_index`` rows (#180 C).

When the operator switches embedding backends or models, the
existing per-row vectors are computed against the OLD backend —
similarity comparisons across backends are nonsense (different
embedding spaces; cosine over mismatched dims is undefined). The
retrieval helper already treats mismatched ``embedding_model`` rows
as stale, but until they're re-embedded they're effectively wasted
disk + an empty retrieval result.

This module drains ``triage_jobs`` rows with ``kind='embedding_reindex'``:

  * One job per account (scoped via ``account_id``).
  * Iterates ``sent_mail_index`` rows for that account in batches of
    100; pulls the stored body_excerpt + subject; computes a fresh
    vector via the currently-configured embedding backend; writes
    back the new vector + ``embedding_norm`` + ``embedding_model``
    + ``embedding_dimension``.
  * Bumps ``triage_jobs.total_processed`` after each batch for the
    UI polling surface.
  * Idempotent + resumable: rows whose ``embedding_model`` already
    matches the target backend's model are skipped, so a worker
    that crashed mid-job restarts cleanly without re-doing work.

Belt-and-braces gate
--------------------
Refuses to run if :func:`is_runtime_ready` returns False — the embed
backend can't load without the bits installed, and a job that fails
on every row burns CPU + audit storage without making progress. The
admin enqueue path also checks the same gate, but defence in depth.

HIPAA
-----
The job inherits the HIPAA short-circuit from :class:`SentMailIndex`
— a HIPAA-flagged account has no rows to re-embed (index_message
short-circuits at write time). Re-embed is a no-op on those
accounts; we log + finish-done immediately rather than walking an
empty row set.

Dispatch wiring
---------------
``triage_runner_bulk.bulk_triage_loop`` branches on ``kind`` and
imports :func:`run_embedding_reindex_job` lazily so the bulk runner
doesn't pull the embedding-stack lookup on every dispatcher tick.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import sqlite3
import struct
from datetime import datetime, timezone
from typing import Any

from email_triage.embedding_bits import is_runtime_ready
from email_triage.web.db import (
    bump_triage_job_counters,
    create_triage_job,
    finish_triage_job,
    get_email_account,
    get_triage_job,
)

log = logging.getLogger("email_triage.jobs.embedding_reindex")

BATCH_SIZE = 100
# Yield to the event loop between batches so a long-running reindex
# doesn't starve other tasks (the embed backend's asyncio.to_thread
# already yields per-embed, but the row-loop is otherwise CPU-bound
# under the GIL).
INTER_BATCH_SLEEP_SECS = 0.0


# ---------------------------------------------------------------------------
# Vector packing (mirrors actions/sent_mail_index.py to keep the
# on-disk format stable; importing the private helpers from there
# would be a circular-import risk via the action layer)
# ---------------------------------------------------------------------------

def _pack_vec(vec: list[float]) -> bytes:
    """Pack a float vector to bytes (float32 little-endian)."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enqueue_embedding_reindex(
    conn: sqlite3.Connection,
    account_id: int,
    actor_user_id: int | None,
) -> str:
    """Insert a queued ``embedding_reindex`` triage_jobs row.

    Returns the job_id. The query column carries a JSON descriptor of
    the target backend at enqueue time so a worker that restarts on
    a later container generation still knows which backend to reembed
    against (otherwise a config swap between enqueue + run would
    silently re-embed against the new-NEW backend).

    Audit + admin gating live in the route handler — this function
    is a pure queue-write helper. Callers MUST confirm the actor is
    admin before calling.
    """
    payload = {
        "account_id": int(account_id),
        # Target-backend hint is informational — the worker re-reads
        # app.state.embedding_backend at run time so a hot-reload
        # path (future) would still use the live config.
        "enqueued_at": _now_iso(),
    }
    return create_triage_job(
        conn,
        account_id=int(account_id),
        actor_user_id=actor_user_id,
        query=json.dumps(payload),
        # Reindex is CPU-bound on the embed backend; tune defaults
        # conservatively. The bulk-runner-supervised rate limit /
        # concurrency aren't really meaningful for reindex (one
        # job at a time per account; embedding backend has its own
        # serialisation) but the columns are non-null so we pass
        # something sensible.
        rate_msg_per_min=600,
        concurrency=1,
        kind="embedding_reindex",
    )


def needs_reindex(
    *,
    current_backend: dict[str, Any],
    target_backend: dict[str, Any],
) -> bool:
    """True if the configured backend differs from what rows were
    embedded against.

    Three triggers:
      1. ``backend_type`` changed (sentence_transformers <-> ollama)
      2. ``model`` name changed
      3. ``dimension`` changed (catches fine-tuned siblings sharing
         a model name but different output dims — should be rare but
         the dimension field is the truth here)

    Each arg is a dict with ``backend_type`` + ``model`` +
    ``dimension`` keys. None / "" values miss safely (don't trip a
    reindex on absence; only on a positive mismatch).
    """
    cb = current_backend or {}
    tb = target_backend or {}
    if cb.get("backend_type") and tb.get("backend_type"):
        if cb["backend_type"] != tb["backend_type"]:
            return True
    if cb.get("model") and tb.get("model"):
        if cb["model"] != tb["model"]:
            return True
    if cb.get("dimension") and tb.get("dimension"):
        try:
            if int(cb["dimension"]) != int(tb["dimension"]):
                return True
        except (TypeError, ValueError):
            return True
    return False


async def run_embedding_reindex_job(
    app: Any,
    conn: sqlite3.Connection,
    job_row: dict[str, Any],
) -> None:
    """Drain one ``embedding_reindex`` job to completion.

    Signature matches :func:`run_style_mine_job` and
    :func:`run_triage_all` so the bulk-runner dispatcher can call it
    uniformly: ``await handler(app, conn, job)``.
    """
    job_id = job_row["job_id"]
    account_id = int(job_row["account_id"])

    # 1. Belt-and-braces: refuse to run if the embedding stack
    #    isn't installed yet. The admin button also gates this but
    #    a future code path that enqueues from elsewhere shouldn't
    #    be able to spin a doomed job.
    if not is_runtime_ready():
        finish_triage_job(
            conn, job_id, status="failed",
            error_text=(
                "Embedding runtime is not installed yet — install via "
                "the AI Backends config card before enqueueing reindex."
            ),
        )
        return

    # 2. Resolve the live embedding backend. None means the operator
    #    hasn't configured one — there's nothing to reindex against.
    embedding_backend = getattr(app.state, "embedding_backend", None)
    if embedding_backend is None:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text=(
                "No embedding backend configured — reindex needs a "
                "live primary backend to compute new vectors."
            ),
        )
        return
    target_model = getattr(app.state, "embedding_model", "") or ""
    target_backend_type = getattr(
        embedding_backend, "backend_type", "",
    )

    # 3. HIPAA short-circuit. A HIPAA-flagged account has zero rows
    #    in sent_mail_index by construction (index_message exits at
    #    entry), so the reindex is structurally a no-op. We finish
    #    'done' rather than 'failed' — the operator's intent was
    #    served, just trivially.
    acct = get_email_account(conn, account_id)
    if acct is None:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="account not found",
        )
        return
    if acct.get("hipaa") or acct.get("created_under_system_hipaa"):
        log.info(
            "embedding_reindex: HIPAA account; trivially done",
            extra={"_extra": {"account_id": account_id}},
        )
        finish_triage_job(conn, job_id, status="done")
        return

    # 4. Count total rows up-front for progress display. The worker
    #    bumps total_processed on each row; UI poll computes the
    #    "X of Y" by reading total_processed + the column we capture
    #    here. We persist the total via update_triage_job_cursor (the
    #    cursor column is currently NULL on reindex jobs so we get
    #    free reuse). The dedup table (triage_job_messages) is NOT
    #    used — message-id idempotence isn't the right shape for
    #    "skip rows already at target model".
    total_row = conn.execute(
        "SELECT COUNT(*) AS n FROM sent_mail_index WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    total = int(total_row["n"] if total_row else 0)

    if total == 0:
        log.info(
            "embedding_reindex: account has no sent_mail_index rows",
            extra={"_extra": {"account_id": account_id}},
        )
        finish_triage_job(conn, job_id, status="done")
        return

    # Persist the total via the cursor field so the UI can show
    # "X of Y" without an extra COUNT(*) on every poll.
    conn.execute(
        "UPDATE triage_jobs SET cursor = ? WHERE job_id = ?",
        (str(total), job_id),
    )
    conn.commit()

    # 5. Walk rows in batches. Using id as the cursor (autoincrement,
    #    monotonic) gives a stable resume order regardless of
    #    embedding_model edits during the run.
    last_id = 0
    processed = 0
    errors = 0
    skipped = 0

    while True:
        # Cancel check — operator cancels via the bulk-runs cancel
        # endpoint; the job status flips to 'cancelled' and we exit
        # at the next batch boundary.
        latest = get_triage_job(conn, job_id)
        if latest and latest.get("status") == "cancelled":
            log.info(
                "embedding_reindex: cancellation observed",
                extra={"_extra": {
                    "job_id": job_id, "account_id": account_id,
                }},
            )
            # finish_triage_job is idempotent under the request_triage_
            # job_cancel set; bulk runner's wrapper will tag the row.
            return

        batch = conn.execute(
            "SELECT id, message_id, subject, body_excerpt, "
            "       embedding_model, embedding_dimension "
            "FROM sent_mail_index "
            "WHERE account_id = ? AND id > ? "
            "ORDER BY id ASC LIMIT ?",
            (account_id, last_id, BATCH_SIZE),
        ).fetchall()
        if not batch:
            break

        for row in batch:
            row_id = int(row["id"])
            last_id = row_id

            # Skip rows already at the target model (idempotent
            # resume on a restarted worker).
            if (
                row["embedding_model"]
                and row["embedding_model"] == target_model
            ):
                skipped += 1
                continue

            text_for_embedding = (
                (row["subject"] or "") + "\n\n" + (row["body_excerpt"] or "")
            ).strip()
            if not text_for_embedding:
                # Empty source — can't re-embed. Mark as skipped + move on.
                skipped += 1
                continue

            try:
                vec = await embedding_backend.embed_text(text_for_embedding)
            except Exception as exc:  # noqa: BLE001
                # Transient errors (Ollama unreachable mid-job, model
                # warmup hiccup) — log + count + continue. The job
                # finishes 'done' with an error count; operator can
                # re-enqueue if errors are high. We don't retry per-row
                # here: the retry_backoff schedules are tuned for
                # message-level retry (#175), not embedding probes that
                # are typically deterministic-fail when wrong.
                errors += 1
                log.warning(
                    "embedding_reindex: embed_text failed",
                    extra={"_extra": {
                        "account_id": account_id,
                        "row_id": row_id,
                        "error_type": type(exc).__name__,
                    }},
                )
                continue

            if not vec:
                skipped += 1
                continue

            norm = math.sqrt(sum(x * x for x in vec))
            packed = _pack_vec([float(x) for x in vec])
            dimension = len(vec)
            now = _now_iso()
            try:
                conn.execute(
                    "UPDATE sent_mail_index SET "
                    "  embedding_vec = ?, "
                    "  embedding_norm = ?, "
                    "  embedding_model = ?, "
                    "  embedding_dimension = ?, "
                    "  indexed_at = ? "
                    "WHERE id = ?",
                    (
                        packed, float(norm), target_model,
                        dimension, now, row_id,
                    ),
                )
            except sqlite3.Error as exc:
                errors += 1
                log.warning(
                    "embedding_reindex: row write failed",
                    extra={"_extra": {
                        "account_id": account_id, "row_id": row_id,
                        "error_type": type(exc).__name__,
                    }},
                )
                continue

            processed += 1

        # Commit the batch + bump the UI counter.
        conn.commit()
        bump_triage_job_counters(
            conn, job_id,
            seen=len(batch),
            processed=sum(1 for r in batch if int(r["id"]) <= last_id),
            skipped=0,
            errors=0,
        )
        # Direct counter set rather than continuous deltas — bump_*
        # adds, so to avoid drift on resume we just absorb the batch
        # cleanly. The cancellation poll already happened above.
        if INTER_BATCH_SLEEP_SECS > 0:
            await asyncio.sleep(INTER_BATCH_SLEEP_SECS)

    log.info(
        "embedding_reindex: finished",
        extra={"_extra": {
            "account_id": account_id,
            "total": total,
            "processed": processed,
            "skipped": skipped,
            "errors": errors,
            "target_model": target_model,
            "target_backend": target_backend_type,
        }},
    )
    finish_triage_job(
        conn, job_id,
        status="done" if errors == 0 else "done",
        error_text=(
            f"{errors} row(s) failed to re-embed; "
            f"{processed} succeeded, {skipped} skipped"
        ) if errors else None,
    )


__all__ = [
    "run_embedding_reindex_job",
    "enqueue_embedding_reindex",
    "needs_reindex",
]
