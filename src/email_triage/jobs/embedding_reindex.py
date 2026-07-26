"""Re-embed an account's ``sent_mail_index`` rows.

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
from typing import Any

from email_triage.db._helpers import dump_json_col, load_json_col  # N-205 R22: dump_json_col added for json-col SSOT
from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23
from email_triage.triage_logging import get_logger  # N-196b R21_4
from email_triage.embedding_bits import is_runtime_ready
from email_triage.web.db import (
    bump_triage_job_counters,
    create_triage_job,
    finish_triage_job,
    get_email_account,
    get_triage_job,
)

log = get_logger("email_triage.jobs.embedding_reindex")  # N-196b R21_4

BATCH_SIZE = 100
# Yield to the event loop AND to the single-writer lock between batches.
# Beyond not starving the event loop (the embed backend's asyncio.to_thread
# already yields per-embed), the >0 sleep is a WRITE-LOCK FAIRNESS yield: a
# multi-account reindex is a sustained heavy-write workload, and on the
# SQLCipher-encrypted DB each batched UPDATE+commit carries ~2× the per-page
# encrypt+fsync cost of plaintext (and ~2× again for 768-dim e5 vectors vs
# 384-dim MiniLM). The 2026-05-31 SQLCipher lock-storm (WAL contention that
# forced audit-handler flush_interval=1) is a known live failure mode on this
# box; a small inter-batch yield lets concurrent live-triage audit writers
# acquire the write lock between heavy reindex lock-holds. ( design §
# "write-lock availability"; §164.308(a)(7) Contingency.) Was 0.0.
INTER_BATCH_SLEEP_SECS = 0.05

#  reliability gate: a reindex of PHI-derived vectors that errors on a
# LARGE fraction of attempted rows must NOT finish 'done' — that would let a
# half-embedded corpus pass as success with no operator alarm (the read path
# silently returns degraded recall). Above this error fraction (errors /
# (processed+errors)) the job finishes 'failed' so the operator re-enqueues.
# The pre-existing all-errored-none-succeeded case is the degenerate 1.0.
HIGH_ERROR_FAIL_FRACTION = 0.5


# ---------------------------------------------------------------------------
# Vector packing (mirrors actions/sent_mail_index.py to keep the
# on-disk format stable; importing the private helpers from there
# would be a circular-import risk via the action layer)
# ---------------------------------------------------------------------------

def _pack_vec(vec: list[float]) -> bytes:
    """Pack a float vector to bytes (float32 little-endian)."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enqueue_embedding_reindex(
    conn: sqlite3.Connection,
    account_id: int,
    actor_user_id: int | None,
    *,
    target: dict | None = None,
) -> str:
    """Insert a queued ``embedding_reindex`` triage_jobs row.

    Returns the job_id.

     (N-91a fix, 2026-06-13): ``target`` pins the intended embedding target
    — ``{"backend_type": ..., "model": ...}`` — into the job payload. This lets
    a later model change SUPERSEDE an in-flight job whose pinned target is now
    stale (see :func:`supersede_or_enqueue_reindex`), instead of the old dedupe
    which merely *skipped* an account with an in-flight job and so left it
    stranded at the start-time stamp when the model changed mid-run. Prefer
    :func:`supersede_or_enqueue_reindex` over calling this directly so the
    supersede/dedupe decision is made in one place.

    The worker still embeds against the LIVE ``app.state.embedding_model`` at
    run time; the pin is used for the supersede DECISION, and the worker's
    per-batch cancel-check stops a superseded job at the next batch boundary.

    Audit + admin gating live in the route handler — this is a pure queue-write
    helper. Callers MUST confirm the actor is admin before calling.
    """
    payload: dict = {
        "account_id": int(account_id),
        "enqueued_at": _now_iso(),
    }
    if target:
        payload["target"] = {
            "backend_type": str(target.get("backend_type") or ""),
            "model": str(target.get("model") or ""),
        }
    return create_triage_job(
        conn,
        account_id=int(account_id),
        actor_user_id=actor_user_id,
        query=dump_json_col(payload),  # N-205 R22: route through json-col SSOT
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


def _job_pinned_target(job_row: dict) -> dict:
    """Extract the pinned ``{backend_type, model}`` from a reindex job's
    payload (the ``query`` JSON column). Returns ``{}`` for a legacy/unpinned
    job or an unparseable payload — an unknown target is treated as STALE by
    the supersede logic (we can't prove it's current)."""
    # load_json_col SSOT (census #16b): the ``query`` JSON column degrades to
    # {} on a legacy/unpinned/corrupt/wrong-shape payload (an unknown target is
    # treated as STALE), replacing the prior json.loads + ValueError/TypeError
    # guard — the dict accessors below are isinstance-guarded and never raise.
    payload = load_json_col(
        job_row.get("query"), default={}, label="triage_jobs.query",
    )
    t = payload.get("target")
    if isinstance(t, dict):
        return {
            "backend_type": str(t.get("backend_type") or ""),
            "model": str(t.get("model") or ""),
        }
    return {}


def supersede_or_enqueue_reindex(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: int | None,
    target: dict,
) -> str:
    """SSOT for enqueueing a reindex. Enqueue a job for ``account_id``
    pinned to ``target``, handling an in-flight job per its PHASE:

      * no in-flight job                  -> enqueue            (``"enqueued"``)
      * in-flight QUEUED job              -> skip               (``"skipped"``)
        — it hasn't read the live model yet, so it self-corrects to the latest
        target when it starts (this is the old D-A3 idempotency, preserved)
      * in-flight RUNNING job already at
        the new target                    -> skip               (``"skipped"``)
      * in-flight RUNNING job at a
        DIFFERENT / unknown (legacy)
        target                            -> cancel it + enqueue a fresh pinned
                                             job                 (``"superseded"``)

    The RUNNING-supersede is the N-91a fix. The worker reads
    ``app.state.embedding_model`` ONCE at job start, so a job that is already
    RUNNING when the model changes would otherwise finish against — and leave
    the account stranded at — the OLD stamp, with nothing to re-trigger it.
    Cancelling it makes the worker's per-batch cancel-check stop it at the next
    batch boundary; the fresh job re-embeds against the new target. A QUEUED job
    needs no supersede (it reads the live model when it starts). Both the
    model-change fan-out (admin) and the manual single-account reindex route
    through here, so the decision lives in ONE place.
    """
    from email_triage.web.db import request_triage_job_cancel
    existing = conn.execute(
        "SELECT job_id, query, status FROM triage_jobs "
        "WHERE account_id = ? AND kind = 'embedding_reindex' "
        "AND status IN ('queued', 'running') "
        "ORDER BY created_at DESC LIMIT 1",
        (int(account_id),),
    ).fetchone()
    if existing is not None:
        if existing["status"] == "queued":
            # Not started yet -> it self-corrects to the live model on start.
            return "skipped"
        # RUNNING: it read the live model at start; it may be stranded now.
        pinned = _job_pinned_target(dict(existing))
        # SAME only when the running job has a KNOWN model that matches the new
        # target; a legacy/unpinned running job (no model) is treated as stale.
        same_target = bool(pinned.get("model")) and not needs_reindex(
            current_backend=pinned, target_backend=target,
        )
        if same_target:
            return "skipped"
        request_triage_job_cancel(conn, existing["job_id"])
        enqueue_embedding_reindex(conn, account_id, actor_user_id, target=target)
        return "superseded"
    enqueue_embedding_reindex(conn, account_id, actor_user_id, target=target)
    return "enqueued"


#: Job statuses that mean "no longer making progress".
_TERMINAL_STATUSES = frozenset({"done", "failed", "cancelled"})


def aggregate_reindex_progress(
    conn: sqlite3.Connection,
    *,
    account_ids,
) -> dict:
    """Roll up the embedding-reindex WAVE across accounts.

    A model change enqueues one ``embedding_reindex`` job per active account;
    the per-job page shows each in isolation, but there was no single "X of Y
    accounts reindexed / NN% of all messages" view. This computes it, scoped to
    ``account_ids`` (the caller's manageable set — never cross-user).

    "The wave" = the current burst: if any reindex job in scope is non-terminal,
    the wave is every reindex job created at-or-after the OLDEST still-active
    job's ``created_at`` (so the already-finished siblings from the same enqueue
    burst count toward "done", but a previous, fully-finished wave does not). If
    NOTHING is active, returns ``{"active": False, ...}`` so the UI fragment can
    render empty and stop polling.

    Per-account dedupe keeps the NEWEST job (a re-enqueue supersedes). Returns a
    plain dict (JSON/template-friendly): ``active``, ``accounts``, ``done``,
    ``processed``, ``total``, ``pct`` (0-100 int), ``status_counts``, and
    ``rows`` (one ``{account_id, status, processed, total, pct}`` per account,
    sorted by account_id).
    """
    empty = {
        "active": False, "accounts": 0, "done": 0, "processed": 0,
        "total": 0, "pct": 0, "status_counts": {}, "rows": [],
    }
    ids = [int(a) for a in (account_ids or [])]
    if not ids:
        return empty
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT account_id, status, total_processed, cursor, created_at "
        f"FROM triage_jobs WHERE kind = 'embedding_reindex' "
        f"AND account_id IN ({placeholders}) "
        f"ORDER BY created_at DESC LIMIT 500",
        ids,
    ).fetchall()
    jobs = [dict(r) for r in rows]
    active = [j for j in jobs if (j.get("status") or "") not in _TERMINAL_STATUSES]
    if not active:
        return empty

    # ISO-8601 created_at sorts lexicographically == chronologically.
    floor = min((j.get("created_at") or "") for j in active)
    wave = [j for j in jobs if (j.get("created_at") or "") >= floor]

    # Dedupe to the newest job per account (wave is created_at DESC).
    by_account: dict[int, dict] = {}
    for j in wave:
        aid = int(j["account_id"])
        if aid not in by_account:
            by_account[aid] = j

    out_rows: list[dict] = []
    sum_p = sum_t = 0
    status_counts: dict[str, int] = {}
    for aid, j in by_account.items():
        processed = int(j.get("total_processed") or 0)
        total = bounded_int(j.get("cursor") or 0, default=0)  # N-219c/4 R23: SSOT
        status = j.get("status") or "queued"
        if total > 0:
            pct = int(round(processed / total * 100))
        else:
            # No rows to embed → a terminal job is 100% by definition.
            pct = 100 if status in _TERMINAL_STATUSES else 0
        status_counts[status] = status_counts.get(status, 0) + 1
        sum_p += processed
        sum_t += total
        out_rows.append({
            "account_id": aid, "status": status,
            "processed": processed, "total": total, "pct": pct,
        })

    overall = int(round(sum_p / sum_t * 100)) if sum_t > 0 else 0
    return {
        "active": True,
        "accounts": len(out_rows),
        "done": status_counts.get("done", 0),
        "processed": sum_p,
        "total": sum_t,
        "pct": overall,
        "status_counts": status_counts,
        "rows": sorted(out_rows, key=lambda r: r["account_id"]),
    }


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
        # N-219c/15 R23: parse both; either non-numeric OR they differ → True
        # (mirrors pre-migration: parse-fail branch also returned True).
        _cd = parse_int_or_none(cb["dimension"])
        _td = parse_int_or_none(tb["dimension"])
        if _cd is None or _td is None or _cd != _td:
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

    #  — run_embedding_reindex_job is awaited from the bulk
    # dispatcher loop on the event-loop thread. Every shared-connection
    # touch below (the @db_write finish/bump helpers, get_email_account,
    # the raw COUNT / cursor / batch-SELECT / per-row UPDATE statements)
    # hops to the threadpool via db_call.
    from email_triage.web.db_threadpool import db_call

    # 1. Belt-and-braces: refuse to run if the embedding stack
    #    isn't installed yet. The admin button also gates this but
    #    a future code path that enqueues from elsewhere shouldn't
    #    be able to spin a doomed job.
    if not is_runtime_ready():
        await db_call(
            finish_triage_job,
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
        await db_call(
            finish_triage_job,
            conn, job_id, status="failed",
            error_text=(
                "No embedding backend configured — reindex needs a "
                "live primary backend to compute new vectors."
            ),
        )
        return
    target_model = getattr(app.state, "embedding_model", "") or ""
    #  — the value stamped into / compared against embedding_model.
    # Encodes the E5 prefix scheme so a model/scheme change invalidates
    # old rows; no-op for non-E5 models. MUST match sent_mail_index's
    # stamp + the retrieve filter.
    from email_triage.engine.embedding_backend import (
        e5_prefix, embedding_stamp,
    )
    target_stamp = embedding_stamp(target_model)
    target_backend_type = getattr(
        embedding_backend, "backend_type", "",
    )

    # 3. HIPAA short-circuit. A HIPAA-flagged account has zero rows
    #    in sent_mail_index by construction (index_message exits at
    #    entry), so the reindex is structurally a no-op. We finish
    #    'done' rather than 'failed' — the operator's intent was
    #    served, just trivially.
    #
    #    N-81: route through is_account_hipaa (folds the system flag).
    #    The previous fork added ``acct.get("created_under_system_hipaa")``
    #    as an extra condition — that column is a lock-guard indicator
    #    (is_account_hipaa_locked), NOT a HIPAA-active indicator.
    #    An account de-HIPAA'd after creation (system flag off,
    #    acct["hipaa"]=0) CAN have sent_mail_index rows and should be
    #    re-indexed; the old OR-branch over-skipped it.
    from email_triage.triage_logging import is_account_hipaa as _iah_reindex
    acct = await db_call(get_email_account, conn, account_id)
    if acct is None:
        await db_call(
            finish_triage_job,
            conn, job_id, status="failed",
            error_text="account not found",
        )
        return
    if _iah_reindex(acct):
        log.info(
            "embedding_reindex: HIPAA account; trivially done",
            extra={"_extra": {"account_id": account_id}},
        )
        await db_call(finish_triage_job, conn, job_id, status="done")
        return

    # 4. Count total rows up-front for progress display. The worker
    #    bumps total_processed on each row; UI poll computes the
    #    "X of Y" by reading total_processed + the column we capture
    #    here. We persist the total via update_triage_job_cursor (the
    #    cursor column is currently NULL on reindex jobs so we get
    #    free reuse). The dedup table (triage_job_messages) is NOT
    #    used — message-id idempotence isn't the right shape for
    #    "skip rows already at target model".
    def _count_total() -> int:
        total_row = conn.execute(
            "SELECT COUNT(*) AS n FROM sent_mail_index WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        return int(total_row["n"] if total_row else 0)

    total = await db_call(_count_total)

    if total == 0:
        log.info(
            "embedding_reindex: account has no sent_mail_index rows",
            extra={"_extra": {"account_id": account_id}},
        )
        await db_call(finish_triage_job, conn, job_id, status="done")
        return

    # Persist the total via the cursor field so the UI can show
    # "X of Y" without an extra COUNT(*) on every poll.
    def _persist_total_cursor() -> None:
        conn.execute(
            "UPDATE triage_jobs SET cursor = ? WHERE job_id = ?",
            (str(total), job_id),
        )
        conn.commit()

    await db_call(_persist_total_cursor)

    # 5. Walk rows in batches. Using id as the cursor (autoincrement,
    #    monotonic) gives a stable resume order regardless of
    #    embedding_model edits during the run.
    last_id = 0
    processed = 0
    errors = 0
    skipped = 0

    while True:
        # Cancel check + batch fetch in one threadpool hop. Operator
        # cancels via the bulk-runs cancel endpoint; the job status
        # flips to 'cancelled' and we exit at the next batch boundary.
        def _cancel_check_and_fetch(_last_id: int):
            latest = get_triage_job(conn, job_id)
            cancelled = bool(latest and latest.get("status") == "cancelled")
            if cancelled:
                return True, []
            rows = conn.execute(
                "SELECT id, message_id, subject, body_excerpt, "
                "       embedding_model, embedding_dimension "
                "FROM sent_mail_index "
                "WHERE account_id = ? AND id > ? "
                "ORDER BY id ASC LIMIT ?",
                (account_id, _last_id, BATCH_SIZE),
            ).fetchall()
            return False, rows

        cancelled, batch = await db_call(_cancel_check_and_fetch, last_id)
        if cancelled:
            log.info(
                "embedding_reindex: cancellation observed",
                extra={"_extra": {
                    "job_id": job_id, "account_id": account_id,
                }},
            )
            # finish_triage_job is idempotent under the request_triage_
            # job_cancel set; bulk runner's wrapper will tag the row.
            return
        if not batch:
            break

        # Snapshot the cumulative counters so the per-batch bump below
        # uses this batch's genuine delta. The old code bumped
        # processed by len(batch) and skipped/errors by a literal 0 —
        # so the job's UI counters always showed every row processed.
        _batch_start_processed = processed
        _batch_start_skipped = skipped
        _batch_start_errors = errors

        #  — the embed call is awaited per-row; the SQLite UPDATE
        # is NOT. Collect the per-row updates here and apply them in a
        # single db_call hop at the batch boundary so no row write
        # runs on the event-loop thread.
        pending_updates: list[tuple] = []

        for row in batch:
            row_id = int(row["id"])
            last_id = row_id

            # Skip rows already at the target model (idempotent
            # resume on a restarted worker).
            if (
                row["embedding_model"]
                and row["embedding_model"] == target_stamp
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
                #  — "passage: " prefix for E5 (symmetric with the
                # "query: " prefix at retrieve); no-op for non-E5.
                vec = await embedding_backend.embed_text(
                    e5_prefix(target_model, "passage") + text_for_embedding
                )
            except Exception as exc:  # noqa: BLE001
                # Transient errors (Ollama unreachable mid-job, model
                # warmup hiccup) — log + count + continue. The job
                # finishes 'done' with an error count; operator can
                # re-enqueue if errors are high. We don't retry per-row
                # here: the retry_backoff schedules are tuned for
                # message-level retry, not embedding probes that
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
            pending_updates.append(
                (packed, float(norm), target_stamp, dimension, now, row_id),
            )

        # Apply the batch's row updates + commit in one threadpool hop.
        # Per-row write failures are counted but don't abort the batch
        # — matches the pre-#241 per-row try/except behaviour.
        def _apply_batch_updates(updates: list[tuple]) -> int:
            ok = 0
            for params in updates:
                try:
                    conn.execute(
                        "UPDATE sent_mail_index SET "
                        "  embedding_vec = ?, "
                        "  embedding_norm = ?, "
                        "  embedding_model = ?, "
                        "  embedding_dimension = ?, "
                        "  indexed_at = ? "
                        "WHERE id = ?",
                        params,
                    )
                    ok += 1
                except sqlite3.Error as exc:
                    log.warning(
                        "embedding_reindex: row write failed",
                        extra={"_extra": {
                            "account_id": account_id,
                            "row_id": params[5],
                            "error_type": type(exc).__name__,
                        }},
                    )
            conn.commit()
            return ok

        batch_ok = await db_call(_apply_batch_updates, pending_updates)
        processed += batch_ok
        errors += len(pending_updates) - batch_ok

        # Bump the UI counter.
        await db_call(
            bump_triage_job_counters,
            conn, job_id,
            seen=len(batch),
            processed=processed - _batch_start_processed,
            skipped=skipped - _batch_start_skipped,
            errors=errors - _batch_start_errors,
        )
        # bump_* ADDS — so each batch contributes only its own delta
        # (cumulative-now minus cumulative-at-batch-start). Over the
        # run the job counters sum to the true processed / skipped /
        # errors totals. The cancellation poll already happened above.
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
    #  reliability: fail the job if every row errored (the pre-existing
    #  rule) OR if a HIGH fraction of *attempted* rows errored
    # (HIGH_ERROR_FAIL_FRACTION) — silent partial-embedding of PHI-derived
    # vectors reported as 'done' would leave the corpus half-searchable with
    # no operator alarm. ``skipped`` rows (already-at-target / empty source)
    # are NOT failures, so the fraction is over processed+errors only.
    _attempted = processed + errors
    _high_error = bool(
        _attempted and (errors / _attempted) >= HIGH_ERROR_FAIL_FRACTION
    )
    await db_call(
        finish_triage_job,
        conn, job_id,
        status="failed" if ((errors and not processed) or _high_error) else "done",
        error_text=(
            f"{errors} row(s) failed to re-embed; "
            f"{processed} succeeded, {skipped} skipped"
            + (
                f" — error rate {errors / _attempted:.0%} ≥ "
                f"{HIGH_ERROR_FAIL_FRACTION:.0%} threshold; re-enqueue."
                if _high_error else ""
            )
        ) if errors else None,
    )


__all__ = [
    "run_embedding_reindex_job",
    "enqueue_embedding_reindex",
    "needs_reindex",
]
