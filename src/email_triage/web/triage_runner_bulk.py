"""Background runner for whole-mailbox triage jobs.

Distinct from ``triage_runner.py`` (which handles synchronous inline
runs of <=100 messages via the /triage/run HTTP path). This module
hosts the long-running task that drains the ``triage_jobs`` queue —
one job at a time, under operator-tunable rate-limit + concurrency
knobs, with cancel-checks at every batch boundary.

Design (full design lives in the backlog ):

* Single supervised task per app process. ``app.py`` registers it
  via ``TaskSupervisor.supervise()`` so a crash gets a bounded
  restart + circuit breaker, same as the digest scheduler etc.
* On startup the task first calls
  :func:`requeue_orphaned_triage_jobs` to flip any ``running`` rows
  with no ``ended_at`` back to ``queued`` — recovery from a process
  kill mid-drain. ``flow_states`` dedupe (via
  ``get_or_create_flow``) ensures already-processed messages skip on
  resume.
* Then the poll loop: every ``POLL_INTERVAL_SECS``, atomically claim
  the oldest queued row via ``claim_next_queued_triage_job`` and
  call :func:`run_triage_all`. The poll cadence is the only "idle
  cost" — stays at 5 s because the table is tiny and most
  installs see one job a week.
* Shutdown is handled by ``TaskSupervisor.stop_all()``; the in-
  flight ``run_triage_all`` may be cancelled mid-batch. Cancelled
  jobs get caught by the next startup's requeue pass — they restart
  from scratch but flow_states dedupe makes that idempotent.

Per-message processing (rate-limit, concurrency, classify+act) is
intentionally written here rather than reused from
``triage_runner.run_triage`` — that function returns a single
TriageRunResult after collecting every result in memory, which is
the wrong shape for a long-running sweep that needs to write
progress + per-message audit rows incrementally + check cancel
between batches. Shared building blocks (provider creation,
classifier creation, hint collection) DO call into
``triage_runner.py`` helpers via ``email_triage.web.routers.ui``
so the configuration + setup paths stay in one place.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time

from email_triage.web.db import (
    bump_triage_job_counters,
    claim_next_queued_triage_job,
    count_processed_messages_in_job,
    finish_triage_job,
    get_triage_job,
    is_message_processed_in_job,
    record_processed_message,
    requeue_orphaned_triage_jobs,
    update_triage_job_cursor,
)
from email_triage.web.db_threadpool import db_call
from email_triage._errfmt import fmt_exc, scrub_class_error_for_persist, scrub_error_for_persist  # N-42: scrub exc text into error_text
from email_triage._int_utils import bounded_int  # N-219c/6 R23


from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.triage_runner_bulk")  # N-196b R21_4

# Poll cadence between queue checks. Short enough that a freshly
# submitted job starts within a few seconds; long enough that an
# idle install isn't burning a row read every second. Tunable via
# the env var below for tests that want faster feedback.
POLL_INTERVAL_SECS = 5.0

# Default page size for provider.search_iter. Each batch is a
# bounded unit of "fetch a chunk of UIDs + classify them + bump
# counters + check cancel". 200 keeps memory low + responsiveness
# high (cancel observed within at most one batch's wall time).
BATCH_SIZE = 200


class TokenBucket:
    """Async-safe token bucket for outbound classify-rate limiting.

    Operator sets ``rate_per_min`` (refill rate) on the admin Config
    page. Bucket refills continuously; ``acquire()`` consumes one
    token and sleeps until one is available. ``burst`` lets a fresh
    bucket front-load a few tokens so the first N messages of a job
    don't single-step at the configured cadence.
    """

    def __init__(self, rate_per_min: int, burst: int = 5) -> None:
        # Floor at 1/min so a misconfigured 0 doesn't deadlock.
        rate = max(1, int(rate_per_min)) / 60.0
        self._rate = rate           # tokens per second
        self._burst = max(1, int(burst))
        self._tokens = float(self._burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        # Loop structure: take the lock, refill + check, release the
        # lock before sleeping. Sleeping while holding the lock would
        # serialise every concurrent acquire() into single-file at
        # 1-token cadence regardless of the configured rate.
        while True:
            async with self._lock:
                now = time.monotonic()
                # Refill since last check, cap at burst.
                self._tokens = min(
                    self._burst,
                    self._tokens + (now - self._last) * self._rate,
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Sleep just long enough for one token to drip. Compute
                # under the lock so the rate doesn't shift between
                # threads, then sleep outside.
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


async def _process_one_message(
    *,
    ctx,
    msg_id: str,
    conn,
    acct,
    actor_user_id: int | None,
    job_id: str,
    bucket: "TokenBucket",
    sem: "asyncio.Semaphore",
):
    """Classify + act on one message under the bulk runner's primitives.

     — the classify + act body is the shared
    :func:`email_triage.web.triage_one.triage_single_message`. This
    wrapper keeps the bulk-runner-specific concerns: the per-job dedup
    gate, the rate-limit token + concurrency semaphore, and the
    immediate per-message ``triage_runs`` row write (vs the inline
    path's batched end-of-run write).

    Before  this path registered only Move/Label/AddLabel/Notify/
    DraftReply and never fired / rule-labels or  watches —
    that drift is now fixed: ``ctx`` carries the full action set + the
    rule-label maps, so a bulk sweep applies labels + fires watches
    exactly like the inline path.

    Returns a one-letter status:
      'p' processed | 's' skipped | 'e' error | 'd' dedup (already done)
    """
    from email_triage.web.db import record_triage_run
    from email_triage.web.triage_one import triage_single_message

    # Dedup gate. A prior crashed-and-resumed pass may
    # have already classified + acted on this message.
    # ASYNC-DB: dedup read off the event loop. The bulk runner
    # is a supervised task that shares the app event loop, so a
    # blocking SELECT here stalls every concurrent HTTP request too.
    if await db_call(is_message_processed_in_job, conn, job_id, msg_id):
        return "d"

    def _record_outcome(conn, entry, status, errors):
        # ASYNC-DB: per-message triage_runs row + dedup row,
        # batched into ONE off-loop hop instead of two separate
        # threadpool round-trips per message.
        try:
            record_triage_run(
                conn, acct["id"], acct.get("name", ""),
                query=f"bulk:{job_id}",
                total_messages=1,
                results=[entry],
                errors=errors,
                elapsed_secs=0.0,
                actor_user_id=actor_user_id,
            )
        except Exception:
            pass
        try:
            record_processed_message(conn, job_id, msg_id, status)
        except Exception:
            # Dedup write itself failed — likely DB locked. Don't mask
            # the real per-message outcome.
            pass

    # Rate-limit + concurrency caps gate the actual provider /
    # classifier work. Token first (system-wide cadence), then a
    # semaphore slot (parallel cap).
    await bucket.acquire()
    async with sem:
        try:
            message = await ctx.provider.fetch_message(msg_id)
        except Exception as e:
            # #1 (census run16 / db-sme + DA MUST-FIX) — a per-message fetch 401
            # here is a DEAD TOKEN: re-raise so it propagates through
            # run_triage_all's gather (return_exceptions=False) to the outer SET
            # edge (record_provider_outcome @1144) instead of being recorded as a
            # per-message "error" + returned cleanly, which lets run_triage_all's
            # post-search CLEAR mask the revoked credential. The search leg lives
            # in the CALLER (run_triage_all's search_iter) — a cross-FUNCTION
            # asymmetry the census's 5-site (within-one-function) list missed.
            from email_triage.web._auth_revoked import is_auth_revoked_exc
            if is_auth_revoked_exc(e):
                raise
            _log.warning(
                "bulk per-message fetch error",
                extra={"job_id": job_id, "msg_id": msg_id, "err": repr(e)},
            )
            err_entry = {
                "message_id": msg_id,
                "status": "error",
                "error": scrub_class_error_for_persist(e),
            }
            await db_call(
                _record_outcome, conn, err_entry, "e",
                [scrub_class_error_for_persist(e)],
            )
            return "e"

        try:
            res = await triage_single_message(ctx, message, msg_id)
            entry = res.entry
            status = res.status
        except Exception as e:
            # The shared helper re-raises LLMBackendUnreachableError so
            # the watcher / poll / push paths can route it to their
            # retry queues. The bulk runner has no per-message retry
            # queue — and a raised exception would abort the whole
            # ``asyncio.gather`` batch — so catch it here, mirroring
            # the pre-#199 bulk path's broad per-message ``except``.
            _log.warning(
                "bulk per-message triage error",
                extra={"job_id": job_id, "msg_id": msg_id, "err": repr(e)},
            )
            entry = {
                "message_id": msg_id,
                "status": "error",
                "error": scrub_class_error_for_persist(e),
            }
            status = "e"

        # Persist the per-message triage_runs row + dedup row
        # immediately (the bulk runner writes incrementally rather
        # than batching). ASYNC-DB: both writes batched into one
        # off-loop hop.
        await db_call(
            _record_outcome, conn, entry, status,
            [entry.get("error", "")] if status == "e" else [],
        )
        return status




async def run_style_mine_job(
    app,
    conn: sqlite3.Connection,
    job: dict,
) -> None:
    """ item 5 — Execute one ``kind='style_mine'`` job end-to-end.

    Sibling of :func:`run_triage_all` for the style-mine variant. The
    inline ``_mine_or_preview`` path on /profile/style-data hands off
    to this worker when the resolved limit exceeds
    :data:`STYLE_LEARNING_INLINE_LIMIT_CEILING`.

    Steps:
      1. Parse the limit from ``job.query`` (encoded as
         ``style_mine:limit=N``); fall back to the
         install-wide default on a parse failure.
      2. Re-run the same provider build + sent-folder resolution +
         M-3 distill the inline path used.
      3. On success: write the profile via :func:`set_style_profile`
         and finalise the job with ``status='done'``.
      4. On any failure: record an audit row + ``status='failed'``
         with the exception summary.

    Counter shape: the job's per-message axis is "messages mined into
    the descriptor(s)". We bump ``total_seen`` with the number of
    messages actually fetched and ``total_processed`` with the
    same count on success — so the bulk-runs UI shows N/N at
    completion, not 1/N (the pre-2026-05-18 shape, which the operator
    read as "half-broken" since the Progress column renders as
    ``total_processed / total_seen``). The dedup table
    (``triage_job_messages``) is not used — a style_mine collapses
    many messages to one logical output, so per-message dedup rows
    would inflate state for no reader benefit.
    """
    from email_triage.web.db import (
        get_email_account, is_user_disabled, set_style_profile,
        record_hipaa_access_event, update_hipaa_access_event,
        is_style_knobs_hipaa_allow,
        get_style_learning_mine_limit_default,
        STYLE_LEARNING_MINE_LIMIT_MAX,
        is_alias_mode_enabled_for_account,
        account_addresses as _account_addresses,
        set_account_style_per_alias,
    )
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.providers.sent_folder import (
        find_sent_folder, normalize_sent_folder_override,
    )
    from email_triage.providers.traits import default_search_query
    from email_triage.engine.models import MailFilter
    from email_triage.actions.style_profile import (
        extract_style_profile, extract_style_profiles_per_alias,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
    )
    from email_triage.web._audit import safe_audit_write_async

    job_id = job["job_id"]
    account_id = job["account_id"]
    actor_user_id = job.get("actor_user_id")
    raw_query = job.get("query", "") or ""

    # Parse limit out of the query column. Format set at queue time
    # is ``style_mine:limit=N``; any other shape falls back to the
    # install-wide default. Clamp defensively.
    #  — run_style_mine_job is awaited from the bulk dispatcher
    # loop on the event-loop thread; route the setting read off-loop.
    limit = await db_call(get_style_learning_mine_limit_default, conn)
    if raw_query.startswith("style_mine:limit="):
        limit = bounded_int(  # N-219c/6 R23: SSOT
            raw_query.split("=", 1)[1], default=limit,
        )
    if limit < 1:
        limit = 1
    elif limit > STYLE_LEARNING_MINE_LIMIT_MAX:
        limit = STYLE_LEARNING_MINE_LIMIT_MAX

    secrets = app.state.secrets
    config = getattr(app.state, "config", None)

    def _validate_style_job(conn, account_id, job_id):
        # ASYNC-DB: account read + owner-disabled read + HIPAA-gate
        # read + (on failure) finish_triage_job write, batched into one
        # off-loop hop. The bulk runner shares the app event loop, so
        # blocking SELECTs here stall every concurrent HTTP request.
        acct_ = get_email_account(conn, account_id)
        if acct_ is None:
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="account not found",
            )
            return None, None, False
        owner_id_ = acct_.get("user_id")
        if owner_id_ is not None and is_user_disabled(conn, owner_id_):
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="account owner disabled",
            )
            return None, None, False
        # HIPAA gate (defence in depth — the inline handler already
        # checked, but a queued job survives an operator re-flag while
        # waiting in the queue). HIPAA-flagged + no opt-in fails the
        # job before any provider fetch.
        account_hipaa_ = is_account_hipaa(acct_)
        if account_hipaa_ and not is_style_knobs_hipaa_allow(
            conn, account_id,
        ):
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="hipaa_gate: opt-in required",
            )
            return None, None, False
        return acct_, owner_id_, account_hipaa_

    acct, owner_id, account_hipaa = await db_call(
        _validate_style_job, conn, account_id, job_id,
    )
    if acct is None:
        return

    # Provider + classifier build. Same shape as run_triage_all.
    if config is None:
        # ASYNC-DB: terminal-state write off the loop.
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text="classifier not configured",
        )
        return
    try:
        provider = _create_provider_from_account(acct, secrets)
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        # ASYNC-DB: terminal-state write off the loop.
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text=f"setup: {fmt_exc(e, with_class=True)}",
        )
        return

    # HIPAA audit bookend (actor != owner only) — mirrors the inline
    # path's audit_phi_access (web/routers/ui/_shared.py SSOT). The
    # inline path writes one row; this path bookends two (in_progress
    # at start, final outcome at end) because the work is long-running
    # and an auditor wants both timestamps.
    audit_event_id: int | None = None
    # N-79: PD#14 predicate SSOT — a system-initiated (actor=None) bulk
    # style-mine of a HIPAA mailbox is a non-owner PHI read and MUST audit
    # (drops the old `actor_user_id is not None` clause, the N-72 sibling bug).
    from email_triage.db.audit import phi_access_audit_required
    if phi_access_audit_required(
        account_hipaa=account_hipaa,
        actor_user_id=actor_user_id,
        owner_id=owner_id,
    ):
        # ASYNC-DB: HIPAA audit-row write off the loop.
        # Census run17 #3 — route the swallowed emit through the
        # best-effort audit SSOT so a write failure surfaces to /health's
        # audit-failure drift counter instead of being log-only.
        audit_event_id = await safe_audit_write_async(
            lambda: db_call(
                record_hipaa_access_event,
                conn, actor_user_id, account_id, "style_mine_bulk",
                outcome="in_progress",
            ),
            description=f"phi_access style_mine_bulk in_progress account_id={account_id}",
            table="hipaa_access_events",
            emitter="record_hipaa_access_event",
        )

    # N-114 — HIPAA + BAA egress gate (§164.308(b)(1), shared SSOT). The style-
    # mine ships sent-mail BODIES to `classifier` (extract_style_profile /
    # _per_alias below); the opt-in (is_style_knobs_hipaa_allow, gated upstream)
    # governs the M-1/M-2 typed knobs ONLY, never the M-3 body-mine egress (the
    # leak: the opt-in wrongly lifted it). For a HIPAA account on an external
    # non-BAA'd classifier that raw PHI must NOT egress. Refuse the whole mine
    # BEFORE either the per-alias or single-profile path; no-op for local /
    # BAA-acked (baa_block_status → None). (Belt-and-suspenders with the
    # extract_style_profile in-fn gate.)
    if account_hipaa:
        from email_triage.classify.baa_gate import baa_block_status
        _sm_blk = await db_call(baa_block_status, conn, classifier, True)
        if _sm_blk is not None:
            if audit_event_id is not None:
                # Allow-list step 2 (B1): finalise through the SSOT.
                await safe_audit_write_async(
                    lambda: db_call(
                        update_hipaa_access_event, conn, audit_event_id,
                        "blocked",
                        f"baa_gate: backend={_sm_blk['backend']} host={_sm_blk['host']}",
                    ),
                    description=(
                        f"style_mine_finalise job={job_id} "
                        f"audit_event_id={audit_event_id} outcome=blocked"
                    ),
                    table="hipaa_access_events",
                    emitter="update_hipaa_access_event",
                )
            await db_call(
                finish_triage_job, conn, job_id, status="failed",
                error_text=(
                    "style_mine: HIPAA account blocked from non-BAA classifier "
                    f"({_sm_blk['backend']} @ {_sm_blk['host'] or '?'}). "
                    "Acknowledge a BAA on /config or switch to a local Ollama."
                ),
            )
            return

    # N-82 (Defect B) — auth_stale lifecycle funnel for the style-mine
    # credentialed search. Late import to avoid the app.py circular import.
    from email_triage.web.app import record_provider_outcome
    from email_triage.web._auth_revoked import is_auth_revoked_exc

    failed_with: str | None = None
    try:
        # Sent-folder resolution — multi-folder fan-out. Override list
        # takes priority over auto-discovery. Iterate every configured
        # folder, merge UIDs as (folder, uid) pairs so each fetch hits
        # the right mailbox (UIDs are mailbox-scoped per RFC 3501
        # § 2.3.1.1). Same pattern as sent_mail_index.py.
        cfg = acct.get("config") or {}
        overrides = normalize_sent_folder_override(
            cfg.get("sent_folder_override")
        )
        if overrides:
            sent_folders = list(overrides)
        else:
            try:
                sent_folders = [await find_sent_folder(provider)]
            except Exception as e:
                _log.warning(
                    "style_mine: sent folder discovery failed",
                    extra={"job_id": job_id, "err": repr(e)},
                )
                sent_folders = ["Sent"]
        sent_folder = (
            sent_folders[0] if len(sent_folders) == 1
            else ", ".join(sent_folders)
        )

        query = default_search_query(
            acct.get("provider_type", "")
        ) or "in:sent"

        # Divide the limit across folders so a single one doesn't
        # monopolize the corpus.
        per_folder_limit = max(
            1, -(-limit // max(1, len(sent_folders))),
        )
        merged_pairs: list[tuple[str, str]] = []
        seen_keys: set[tuple[str, str]] = set()
        for folder in sent_folders:
            try:
                part = await provider.search(
                    query, per_folder_limit,
                    filter=MailFilter(folder=folder),
                )
            except Exception as e:
                # N-82 — auth-revoked: re-raise to the outer except so the
                # chip is SET. Transient errors are swallowed (continue).
                if is_auth_revoked_exc(e):
                    raise
                _log.warning(
                    "style_mine: per-folder search failed; continuing",
                    extra={
                        "job_id": job_id, "folder": folder,
                        "err": repr(e),
                    },
                )
                continue
            for mid in part or ():
                key = (folder, mid)
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_pairs.append(key)
        # N-82 — all per-folder searches completed without auth error; the
        # credential is alive. CLEAR any prior stale chip. Outside the loop
        # so one db_call covers the whole sweep.
        # NOTE (vs run_triage_all's `if not cancelled and not failed_with`):
        # this CLEAR needs no failed_with guard because it is reached ONLY when
        # the search loop fell through cleanly — an auth-revoked error re-raises
        # (above) to the outer except → SET edge, and `failed_with` is not yet
        # assigned on this path (the no_messages/finalise assignments are
        # downstream). Keep this CLEAR before any failure assignment so a future
        # refactor can't let a failed run reach it (PD#18 set-broad/clear-narrow).
        try:
            await db_call(record_provider_outcome, conn, acct, None)
        except Exception:
            pass

        # ASYNC-DB: counter write off the loop.
        await db_call(
            bump_triage_job_counters, conn, job_id,
            seen=len(merged_pairs),
        )

        messages = []
        for folder, mid in merged_pairs:
            try:
                msg = await provider.fetch_message(mid, folder=folder)
                messages.append(msg)
            except Exception as e:
                # #1 (census run16) — auth-revoked on the FETCH leg must
                # propagate like the SEARCH leg already does (N-82), so it
                # reaches the outer record_provider_outcome SET edge instead of
                # being swallowed and letting the post-search CLEAR mask a
                # revoked credential. Transient errors still continue.
                if is_auth_revoked_exc(e):
                    raise
                _log.warning(
                    "style_mine: fetch failed; continuing",
                    extra={
                        "job_id": job_id, "msg_id": mid, "err": repr(e),
                    },
                )

        if not messages:
            failed_with = "no_messages: nothing in the sent folder"
        else:
            # M-6 captured-pair set for the corpus weighting.
            def _read_captured_ids(conn, account_id):
                # ASYNC-DB: sent_mail_index captured-pair read
                # off the loop.
                ids_: set[str] = set()
                try:
                    rows_ = conn.execute(
                        "SELECT message_id FROM sent_mail_index "
                        "WHERE account_id = ? AND is_captured_pair = 1",
                        (account_id,),
                    ).fetchall()
                    for r in rows_:
                        mid_ = (
                            r["message_id"] if hasattr(r, "keys") else r[0]
                        )
                        if mid_:
                            ids_.add(str(mid_))
                except Exception:
                    return set()
                return ids_

            captured_ids: set[str] = await db_call(
                _read_captured_ids, conn, account_id,
            )

            # 2026-05-13 — alias-mode parity with the inline path.
            # Before this fix, the bulk runner always called
            # ``extract_style_profile`` (single-profile) + wrote only
            # the account-wide ``settings["style_profile:<id>"]`` row.
            # Operators with alias-mode ON + a limit > inline ceiling
            # (default 50, operator's was 100) had their mine routed
            # through here and got zero per-alias rows — visible as
            # "Last built: never" on every alias row in the picker
            # table even after a successful mine.
            #
            # Mirror the inline path: when alias_mode is on, partition
            # by parsed-From, write one row per non-empty bucket to
            # ``account_style_per_alias``, then refresh the account-
            # wide descriptor from the largest bucket so the legacy
            # ``style_profile:<id>`` row stays accurate as the
            # fallback.
            # ASYNC-DB: alias-mode flag read off the loop.
            alias_mode_on = await db_call(
                is_alias_mode_enabled_for_account, conn, account_id,
            )
            if alias_mode_on:
                known_addresses = _account_addresses(acct)
                alias_descriptors, _unknown = (
                    await extract_style_profiles_per_alias(
                        messages, classifier,
                        known_addresses=known_addresses,
                        captured_message_ids=captured_ids,
                        account_hipaa=account_hipaa, conn=conn,  # N-114 BAA gate
                    )
                )

                def _persist_alias_profiles(conn):
                    # ASYNC-DB: per-alias persist loop + account-
                    # wide refresh + counter bump, batched into one
                    # off-loop hop.
                    persisted_ = 0
                    for addr, prof in alias_descriptors.items():
                        try:
                            set_account_style_per_alias(
                                conn, account_id, addr,
                                prof.to_dict(),
                                sample_count=prof.sample_count,
                            )
                            persisted_ += 1
                        except Exception as e:
                            _log.warning(
                                "style_mine: per-alias persist failed; "
                                "continuing",
                                extra={
                                    "job_id": job_id,
                                    "account_id": account_id,
                                    "addr": addr,
                                    "err": repr(e),
                                },
                            )
                    # Refresh the account-wide row from the largest
                    # bucket so the fallback (when alias-mode flips
                    # OFF later) carries the dominant style. Mirrors
                    # the inline path's set_style_profile call inside
                    # the alias branch.
                    if alias_descriptors:
                        best = max(
                            alias_descriptors.values(),
                            key=lambda p: p.sample_count,
                        )
                        try:
                            set_style_profile(
                                conn, account_id, best.to_dict(),
                            )
                        except Exception as style_exc:
                            _log.warning(
                                "bulk triage: account-wide style profile refresh failed",
                                account_id=account_id,
                                error=fmt_exc(style_exc),
                            )
                    # 2026-05-18 — bump by the actual message count,
                    # not 1. Pre-fix this incremented total_processed
                    # by 1 (the agent's "one logical output = one
                    # descriptor" semantic), but the Recent bulk runs
                    # UI renders ``total_processed / total_seen`` as a
                    # progress bar — "1 / 100" reads as "1 of 100
                    # messages done" / "half-broken" to any operator
                    # (or customer) even though all 100 messages WERE
                    # actually mined. Bumping by ``len(messages)``
                    # gets the bar to 100%.
                    bump_triage_job_counters(
                        conn, job_id, processed=len(messages),
                    )
                    return persisted_

                persisted = await db_call(_persist_alias_profiles, conn)
                _log.info(
                    "style_mine: per-alias profiles saved",
                    extra={
                        "job_id": job_id,
                        "account_id": account_id,
                        "aliases": persisted,
                        "samples": sum(
                            p.sample_count
                            for p in alias_descriptors.values()
                        ),
                    },
                )
            else:
                profile = await extract_style_profile(
                    messages, classifier,
                    captured_message_ids=captured_ids,
                    account_hipaa=account_hipaa, conn=conn,  # N-114 BAA egress gate
                )

                def _persist_profile(conn):
                    # ASYNC-DB: account-wide profile write +
                    # counter bump, batched into one off-loop hop.
                    set_style_profile(conn, account_id, profile.to_dict())
                    # See alias branch above for the rationale on
                    # bumping by ``len(messages)`` instead of 1.
                    bump_triage_job_counters(
                        conn, job_id, processed=len(messages),
                    )

                await db_call(_persist_profile, conn)
                _log.info(
                    "style_mine: profile saved",
                    extra={
                        "job_id": job_id,
                        "account_id": account_id,
                        "samples": profile.sample_count,
                    },
                )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        failed_with = fmt_exc(e, with_class=True)
        _log.exception(
            "style_mine: run failed",
            extra={"job_id": job_id},
        )
        # N-82 — auth-revoked failure (re-raised from per-folder search or
        # any other credentialed op) → SET the re-auth chip, needle-filtered.
        try:
            await db_call(record_provider_outcome, conn, acct, e)
        except Exception:
            pass
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        if hasattr(classifier, "close"):
            try:
                await classifier.close()
            except Exception:
                pass

    def _finalise_style_job(conn):
        # ASYNC-DB: terminal-state resolution read + (conditional)
        # finish write, batched into one off-loop hop.
        latest = get_triage_job(conn, job_id)
        if latest and latest["status"] == "running":
            if failed_with:
                finish_triage_job(
                    conn, job_id, status="failed",
                    error_text=failed_with,
                )
            else:
                finish_triage_job(conn, job_id, status="done")

    await db_call(_finalise_style_job, conn)

    # Close HIPAA audit row.
    if audit_event_id is not None:
        outcome = "error" if failed_with else "success"
        # ASYNC-DB: HIPAA audit-row update off the loop, through the
        # SSOT (allow-list step 2, B1).
        await safe_audit_write_async(
            lambda: db_call(
                update_hipaa_access_event,
                conn, audit_event_id, outcome,
                f"style_mine job {job_id}",
            ),
            description=(
                f"style_mine_finalise job={job_id} "
                f"audit_event_id={audit_event_id} outcome={outcome}"
            ),
            table="hipaa_access_events",
            emitter="update_hipaa_access_event",
        )


async def run_triage_all(
    app,
    conn: sqlite3.Connection,
    job: dict,
) -> None:
    """Execute one bulk triage job end-to-end.

    Walks ``provider.search_iter(job.query)`` in batches; for each
    message in a batch, acquires a token from the rate-limit bucket
    + a semaphore slot, then classifies + acts. After each batch,
    re-reads the job row to honour an in-flight cancel + bumps the
    progress counters.

    Cancel handling — three observation points:

    1. Between batches (cheapest): re-read the job row; if status
       has flipped to ``cancelled``, break out of the batch loop
       immediately. The cancelled status was already written by
       the UI handler, so do NOT call ``finish_triage_job`` here —
       that would clobber ``ended_at`` with a later wall-clock
       value than the cancel write set.
    2. asyncio.CancelledError (process shutdown): re-raise to the
       supervisor; the row stays ``running`` and the next process
       start will requeue it.
    3. Any other exception: catch + finish the job as ``failed``
       with the exception type + message in ``error_text``.
    """
    # is_account_hipaa lives in triage_logging (canonical home next to
    # the redaction helpers); access_audit re-exports happen elsewhere
    # but not for this symbol. Pinned import path so the bulk runner
    # doesn't ImportError when the function is finally called.
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import (
        get_email_account, list_account_routes, list_categories,
        is_user_disabled, record_hipaa_access_event,
        update_hipaa_access_event,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _load_all_list_hints, _is_dry_run,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.web._audit import safe_audit_write_async

    job_id = job["job_id"]
    account_id = job["account_id"]
    actor_user_id = job.get("actor_user_id")
    query = job.get("query", "") or ""
    rate_msg_per_min = int(job.get("rate_msg_per_min") or 30)
    concurrency = max(1, int(job.get("concurrency") or 1))

    secrets = app.state.secrets

    def _validate_bulk_job(conn, account_id, job_id):
        # ASYNC-DB: account read + owner-disabled read + category
        # read + route read + (on failure) finish_triage_job write,
        # batched into one off-loop hop. The bulk runner shares the app
        # event loop, so blocking SELECTs here stall every concurrent
        # HTTP request.
        acct_ = get_email_account(conn, account_id)
        if acct_ is None:
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="account not found",
            )
            return None, None, None, None
        owner_id_ = acct_.get("user_id")
        if owner_id_ is not None and is_user_disabled(conn, owner_id_):
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="account owner disabled",
            )
            return None, None, None, None
        categories_ = _get_categories_from_db(conn, user_id=owner_id_)
        if not categories_:
            finish_triage_job(
                conn, job_id, status="failed",
                error_text="no categories configured",
            )
            return None, None, None, None
        routes_ = list_account_routes(conn, account_id)
        return acct_, owner_id_, categories_, routes_

    acct, owner_id, categories, account_routes = await db_call(
        _validate_bulk_job, conn, account_id, job_id,
    )
    if acct is None:
        return

    routes_by_cat = {r["category"]: r["actions"] for r in account_routes}
    account_hipaa = is_account_hipaa(acct)

    # Build provider + classifier once per job. Provider is closed
    # in the finally block below so a long sweep doesn't leak the
    # underlying connection on failure.
    try:
        provider = _create_provider_from_account(acct, secrets)
        classifier = _build_classifier_from_config(app.state.config)
    except Exception as e:
        # ASYNC-DB: terminal-state write off the loop.
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text=f"setup: {fmt_exc(e, with_class=True)}",
        )
        return

    # HIPAA audit bookend — one row per JOB, only when a NON-OWNER
    # actor initiated. Owner sweeping their own mailbox is
    # first-party access; admin / delegate sweeping someone else's
    # is third-party PHI access + gets the §164.312(b) row.
    audit_event_id: int | None = None
    # N-79: PD#14 predicate SSOT — a system-initiated (actor=None) whole-mailbox
    # triage of a HIPAA account is a non-owner PHI read and MUST audit (drops
    # the old `actor_user_id is not None` clause, the N-72 sibling bug). The
    # comment above already states intent: "gets the §164.312(b) row".
    from email_triage.db.audit import phi_access_audit_required
    if phi_access_audit_required(
        account_hipaa=account_hipaa,
        actor_user_id=actor_user_id,
        owner_id=owner_id,
    ):
        # ASYNC-DB: HIPAA audit-row write off the loop.
        # Census run17 #3 — route the swallowed emit through the
        # best-effort audit SSOT so a write failure surfaces to /health's
        # audit-failure drift counter instead of being log-only.
        audit_event_id = await safe_audit_write_async(
            lambda: db_call(
                record_hipaa_access_event,
                conn, actor_user_id, account_id, "bulk_triage",
                outcome="in_progress",
            ),
            description=f"phi_access bulk_triage in_progress account_id={account_id}",
            table="hipaa_access_events",
            emitter="record_hipaa_access_event",
        )

    #  — terminal-state flags initialised BEFORE the outer try so
    # the audit-row close in its ``finally`` can read them even when a
    # failure fires in the job-setup window (registry / runtime-burst
    # read / preload / context build). Previously that window sat
    # *outside* every try block: an exception there skipped the audit
    # close at the end of the function entirely, leaving the
    # ``in_progress`` HIPAA row open forever.
    cancelled = False
    failed_with: str | None = None

    #  — outer try whose ``finally`` ALWAYS closes the
    # ``in_progress`` audit row, no matter where in the job a failure
    # occurs. It opens immediately after the ``in_progress`` write so
    # there is no longer an unguarded window between the row being
    # opened and the row being closed.
    try:
        #  — uniform action set across every ingestion path. Calendar
        # actions (invite / suggest-meeting) are registered but stay inert
        # for bulk: the bulk runner does not wire a calendar provider, so
        # the meeting-intercept inject is a no-op (calendar_wired=False)
        # and any explicitly-routed calendar action would skip. This is
        # behaviour-preserving — the pre-#199 bulk path had no calendar
        # support — while keeping a single registry shape.
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )

        # .2 — burst is operator-tunable via the /config page. Read
        # the saved runtime setting at job-RUN time (not job-CREATE time)
        # so an operator's mid-queue tuning takes effect on the next job
        # without restarting. Default 1 preserves legacy "single-step at
        # the configured cadence" behaviour for installs that never set
        # the knob. Falls back to the legacy heuristic only if the saved
        # value is missing OR explicitly zero (a 0 from a stale save
        # would otherwise short-circuit to 1 here, masking operator
        # intent).
        operator_burst: int | None = None
        try:
            from email_triage.web.db import get_setting as _get_setting
            # ASYNC-DB: runtime-settings read off the loop.
            runtime_saved = await db_call(
                _get_setting, conn, "runtime_settings",
            ) or {}
            if "bulk_triage_burst" in runtime_saved:
                operator_burst = int(runtime_saved["bulk_triage_burst"])
        except Exception:
            # Don't let a settings lookup hiccup take down the runner;
            # fall through to the heuristic.
            operator_burst = None
        burst = (
            max(1, operator_burst)
            if operator_burst is not None and operator_burst > 0
            else max(1, rate_msg_per_min // 6)
        )
        bucket = TokenBucket(rate_msg_per_min, burst=burst)
        sem = asyncio.Semaphore(concurrency)

        # .1 — load classification lists + rules once per JOB. A bulk
        # sweep can process tens of thousands of messages; the prior
        # per-message refetch was the dominant DB-noise source on long
        # runs.
        #
        # ASYNC-DB: the once-per-job preload — list hints, the
        # resume counter read + pre-bump, the rule-label maps, the
        # dry-run flag — is one clean sequence of reads (plus one
        # conditional write), batched into a single off-loop hop.
        def _preload_job(conn, job_id):
            try:
                lh_lists, lh_rules = _load_all_list_hints(conn)
            except Exception:
                # Don't let a missing-table / mid-migration race kill
                # the run; fall back to per-message lookup for safety.
                _log.exception("preload _load_all_list_hints failed")
                lh_lists = None
                lh_rules = None
            # Resume support: if the row was requeued
            # after a crash, the previous pass may have already
            # processed N messages — those rows live in
            # triage_job_messages and is_message_processed_in_job will
            # short-circuit them inside _process_one_message. Pre-bump
            # the aggregate counters from the dedup table so the UI
            # doesn't show "0 / 10000 processed" at restart while the
            # dedup gate keeps clearing already-done work. The seen
            # counter still grows from the search_iter walk;
            # processed/skipped/errors come from the dedup record.
            pre_ = count_processed_messages_in_job(conn, job_id)
            if pre_["p"] or pre_["s"] or pre_["e"]:
                bump_triage_job_counters(
                    conn, job_id,
                    processed=pre_["p"], skipped=pre_["s"],
                    errors=pre_["e"],
                )
            return (
                lh_lists, lh_rules,
                _build_rule_labels_map(conn),
                _build_rule_provider_labels_map(conn),
                _is_dry_run(conn),
            )

        (
            list_hints_lists, list_hints_rules_by_list,
            rule_labels_map, rule_provider_labels_map, dry_run_flag,
        ) = await db_call(_preload_job, conn, job_id)

        # High-water-mark cursor. On a fresh run the row
        # has cursor=NULL; on resume after a crash, the persisted
        # cursor lets the provider's search_iter restart from the last
        # successful batch boundary. Provider-specific format (IMAP
        # max-UID-int, Gmail pageToken, O365 nextLink URL); the runner
        # just opaque-passes it through.
        resume_cursor = job.get("cursor")

        # Query-stage self-skip. Same rewrite as triage_runner —
        # exclude install-self-from at the SEARCH stage so a long bulk
        # sweep doesn't burn FETCH calls on every digest the install
        # ever delivered to its own watched mailbox.
        from email_triage.mail_headers import build_self_skip_query
        _self_from_addr = getattr(
            getattr(app.state.config, "smtp", None), "from_addr", "",
        )
        effective_query = build_self_skip_query(
            query, _self_from_addr, provider_type=acct["provider_type"],
        )

        #  — build the shared per-message context ONCE per job. The
        # bulk path does NOT use the durable rfc-id / $EmailTriaged
        # dedup gates (its per-job triage_job_messages table is the
        # dedup mechanism) so durable_dedup / mark_triaged_on_success
        # stay False. It now DOES fire / rule-labels + 
        # watches via this ctx — the pre-#199 bulk path skipped them.
        ctx = TriageContext(
            db=conn, config=app.state.config, secrets=secrets, acct=acct,
            classifier=classifier, provider=provider, registry=registry,
            categories=categories,
            routes_by_cat=routes_by_cat,
            list_hints_lists=list_hints_lists,
            list_hints_rules_by_list=list_hints_rules_by_list,
            rule_labels_map=rule_labels_map,
            rule_provider_labels_map=rule_provider_labels_map,
            self_from_addr=_self_from_addr,
            dry_run=dry_run_flag,
            account_hipaa=account_hipaa,
            actor_user_id=actor_user_id,
            durable_dedup=False,
            mark_triaged_on_success=False,
            set_keyword_on_success=False,
            fire_watches=True,
        )

        # N-82 (Defect B) — auth_stale lifecycle funnel for the bulk-triage
        # credentialed search. Mirrors the topic_backscan.py wiring: SET the
        # chip on an auth-revoked search failure (needle-filtered; transient
        # errors do not set it), CLEAR it on a clean run. Late import to
        # avoid the app.py circular import (same pattern as background_sweepers
        # and topic_backscan).
        from email_triage.web.app import record_provider_outcome

        try:
            async for batch, batch_cursor in provider.search_iter(
                effective_query,
                batch_size=BATCH_SIZE,
                resume_cursor=resume_cursor,
            ):
                # Cancel check at batch boundary BEFORE any work.
                # ASYNC-DB: cancel-check read off the loop.
                latest = await db_call(get_triage_job, conn, job_id)
                if latest is None or latest["status"] == "cancelled":
                    cancelled = True
                    break

                # ASYNC-DB: per-batch seen-counter write off loop.
                await db_call(
                    bump_triage_job_counters, conn, job_id,
                    seen=len(batch),
                )

                # Schedule per-message tasks; the semaphore inside
                # _process_one_message caps actual parallelism. Letting
                # asyncio queue every task in the batch is fine — they
                # contend on the semaphore and the rate-limit bucket
                # serialises further.
                tasks = [
                    asyncio.create_task(_process_one_message(
                        ctx=ctx, msg_id=msg_id, conn=conn, acct=acct,
                        actor_user_id=actor_user_id, job_id=job_id,
                        bucket=bucket, sem=sem,
                    ))
                    for msg_id in batch
                ]
                statuses = await asyncio.gather(
                    *tasks, return_exceptions=False,
                )

                processed = sum(1 for s in statuses if s == "p")
                skipped = sum(1 for s in statuses if s == "s")
                errors = sum(1 for s in statuses if s == "e")

                def _persist_batch_progress(
                    conn, processed, skipped, errors, batch_cursor,
                ):
                    # ASYNC-DB: per-batch counter bump +
                    # resume-cursor persist, one off-loop hop.
                    bump_triage_job_counters(
                        conn, job_id,
                        processed=processed, skipped=skipped,
                        errors=errors,
                    )
                    # Persist the resume cursor AFTER the batch's
                    # per-message work completes. Crash-during-batch
                    # leaves the cursor at the previous batch's value;
                    # resume re-walks the current batch's UIDs but the
                    # dedup table short-circuits the
                    # already-processed entries so the only repeated
                    # work is the provider page fetch + the dedup-table
                    # lookups.
                    if batch_cursor is not None:
                        try:
                            update_triage_job_cursor(
                                conn, job_id, batch_cursor,
                            )
                        except Exception:
                            _log.exception(
                                "cursor persist failed; continuing",
                                extra={"job_id": job_id},
                            )

                await db_call(
                    _persist_batch_progress, conn,
                    processed, skipped, errors, batch_cursor,
                )
            # N-82 — search_iter completed without exception (may have been
            # cancelled by the inner break above, but the credential proved
            # alive for at least the first page). CLEAR any prior stale chip.
            # Outside the for-loop so one db_call covers the whole sweep.
            if not cancelled and not failed_with:
                try:
                    await db_call(record_provider_outcome, conn, acct, None)
                except Exception:
                    pass
        except asyncio.CancelledError:
            # Process shutdown. Don't write a terminal row — leave it
            # 'running' so the next start's requeue picks it up.
            # Re-raise so the supervisor sees the cancellation cleanly.
            raise
        except Exception as e:
            failed_with = fmt_exc(e, with_class=True)
            _log.exception("bulk run failed", extra={"job_id": job_id})
            # N-82 — auth-revoked search failure → SET the re-auth chip
            # (needle-filtered: transient errors do not set it). Mirrors
            # topic_backscan.py's wiring on the same credential.
            try:
                await db_call(record_provider_outcome, conn, acct, e)
            except Exception:
                pass
        finally:
            try:
                await provider.close()
            except Exception:
                pass
            #  — drain the classifier's long-lived httpx pool.
            if "classifier" in locals() and hasattr(classifier, "close"):
                try:
                    await classifier.close()
                except Exception:
                    pass

        # Resolve terminal state. Cancelled writes are owned by the UI
        # path; only finalise here if the row is still 'running'.
        # ``_completion`` carries the clean-done signal + the authoritative
        # job-row counts out to the event loop so the run18 census #7 bulk
        # terminal emit can fire (a threadpool db_call cannot ``await`` the
        # async webhook). Set ONLY when THIS run writes 'done' — so a
        # cancelled/failed sweep, or an already-terminal row on resume,
        # emits nothing.
        _completion: dict = {"done": False}

        def _finalise_bulk_job(conn):
            # ASYNC-DB: terminal-state resolution read +
            # (conditional) finish write, one off-loop hop.
            latest = get_triage_job(conn, job_id)
            if latest and latest["status"] == "running":
                if cancelled:
                    finish_triage_job(conn, job_id, status="cancelled")
                elif failed_with:
                    finish_triage_job(
                        conn, job_id, status="failed",
                        error_text=failed_with,
                    )
                else:
                    finish_triage_job(conn, job_id, status="done")
                    _completion["done"] = True
                    _completion["total_seen"] = latest["total_seen"] or 0
                    _completion["total_processed"] = (
                        latest["total_processed"] or 0
                    )
                    _completion["total_errors"] = latest["total_errors"] or 0

        await db_call(_finalise_bulk_job, conn)

        # run18 census #7 — emit triage.completed for a bulk sweep that
        # finished cleanly. The per-message triage_runs rows are already
        # written by _record_outcome, so record=False: this only fires the
        # outbound webhook, with the run-level tallies read off the
        # job row (no 10k-element results list). HIPAA accounts are
        # hard-skipped inside fire_triage_completed. Best-effort: a webhook
        # failure must never fail the job.
        if _completion["done"]:
            dispatcher = getattr(app.state, "event_dispatcher", None)
            if dispatcher is not None:
                from email_triage.web.events import complete_triage_run
                try:
                    await complete_triage_run(
                        dispatcher, conn, app.state.config, acct,
                        run_id=f"bulk_{job_id}",
                        query=f"bulk:{job_id}",
                        trigger="bulk",
                        total_messages=_completion["total_seen"],
                        results_count=_completion["total_processed"],
                        errors_count=_completion["total_errors"],
                        elapsed_secs=0.0,
                        record=False,
                    )
                except Exception as e:
                    _log.warning(
                        "bulk triage.completed dispatch failed",
                        extra={"job_id": job_id, "err": repr(e)},
                    )
    except asyncio.CancelledError:
        #  — a cancel anywhere in the job-setup window (before the
        # inner try took over) still reaches here. Mark cancelled so
        # the audit row in the finally closes as "cancelled", then
        # re-raise so the supervisor sees the cancellation cleanly.
        cancelled = True
        raise
    except Exception as e:
        #  — a failure in the job-setup window (registry build,
        # runtime-burst read, preload, context build) or in
        # _finalise_bulk_job lands here. It previously escaped every
        # try block, skipping the audit-row close entirely. Record it
        # so the finally closes the row as "error", then re-raise to
        # preserve the prior propagate-to-caller behaviour.
        if failed_with is None:
            failed_with = fmt_exc(e, with_class=True)
        raise
    finally:
        #  — ALWAYS close the HIPAA audit row. This finally covers
        # the whole span from immediately after the in_progress write,
        # so no exception path can leave the row stuck "in_progress".
        if audit_event_id is not None:
            outcome = (
                "cancelled" if cancelled
                else ("error" if failed_with else "success")
            )
            # ASYNC-DB: HIPAA audit-row update off the loop, through
            # the SSOT (allow-list step 2, B1).
            await safe_audit_write_async(
                lambda: db_call(
                    update_hipaa_access_event,
                    conn, audit_event_id, outcome,
                    f"bulk job {job_id}",
                ),
                description=(
                    f"bulk_triage_finalise job={job_id} "
                    f"audit_event_id={audit_event_id} outcome={outcome}"
                ),
                table="hipaa_access_events",
                emitter="update_hipaa_access_event",
            )


async def bulk_triage_runner(app) -> None:
    """Long-running task: drain queued triage_jobs one at a time.

    Spawned by app.py via TaskSupervisor.supervise() so a crash
    triggers bounded restart + circuit breaker rather than killing
    the whole process. Each loop iteration:

      1. Atomically claim the oldest queued job (None if empty).
      2. If claimed, run it via :func:`run_triage_all`.
      3. If empty, sleep ``POLL_INTERVAL_SECS`` and repeat.

    Crashes during a job leave the row in ``running`` with no
    ``ended_at`` — picked up by the next process start's requeue
    pass.
    """
    conn = app.state.db
    # Startup recovery — runs once before the loop. Any rows left
    # in ``running`` from a previous process flip back to ``queued``.
    try:
        # ASYNC-DB: startup-recovery write off the loop.
        n = await db_call(requeue_orphaned_triage_jobs, conn)
        if n:
            _log.info(
                "Requeued orphaned bulk-triage jobs after restart",
                extra={"count": n},
            )
    except Exception:
        # Don't let a startup-recovery hiccup take down the runner;
        # log and proceed. The orphans stay 'running' until next
        # restart.
        _log.exception("requeue_orphaned_triage_jobs failed")

    while True:
        try:
            # ASYNC-DB: atomic job-claim write off the loop.
            job = await db_call(claim_next_queued_triage_job, conn)
        except Exception:
            _log.exception("claim_next_queued_triage_job raised; sleeping")
            await asyncio.sleep(POLL_INTERVAL_SECS)
            continue

        if job is None:
            await asyncio.sleep(POLL_INTERVAL_SECS)
            continue

        # Run the claimed job. Catch-all so one bad job doesn't
        # take down the loop. The runner body is responsible for
        # writing a terminal status; the except clause below is
        # the safety net for "body raised before reaching
        # finish_triage_job".
        #
        #  item 5 — branch on ``kind`` (v21 column). Default to
        # legacy 'triage' on missing/unknown so a future kind that
        # arrives without a handler doesn't deadletter — it would
        # run through the triage classifier path and emit an
        # operator-visible failure that's easier to diagnose than a
        # silent queue stall.
        kind = (job.get("kind") or "triage")
        try:
            if kind == "style_mine":
                await run_style_mine_job(app, conn, job)
            elif kind == "embedding_reindex":
                #  C — re-embed an account's sent_mail_index rows
                # after a backend swap. Lazy-imported so the
                # embedding-bits package isn't pulled on every
                # dispatcher tick (most installs are not actively
                # reindexing).
                from email_triage.jobs.embedding_reindex import (
                    run_embedding_reindex_job,
                )
                await run_embedding_reindex_job(app, conn, job)
            elif kind == "topic_backscan":
                #  — back-scan HISTORICAL mail for one (topic, account)
                # over a 30/60/90-day window. Lazy-imported so the topic
                # matcher / classify stack isn't pulled on every dispatcher
                # tick (most installs aren't actively back-scanning).
                from email_triage.jobs.topic_backscan import (
                    run_topic_backscan_job,
                )
                await run_topic_backscan_job(app, conn, job)
            else:
                await run_triage_all(app, conn, job)
        except asyncio.CancelledError:
            # App shutdown. The job stays in 'running'; next start
            # requeues it. Surface the cancel so the supervisor
            # tears down cleanly.
            _log.info(
                "Bulk triage cancelled by shutdown",
                extra={"job_id": job["job_id"]},
            )
            raise
        except Exception as e:
            # Fail LOUD on a code defect (incident_2026-06-11): a programming
            # defect (ImportError/AttributeError/NameError/TypeError) fails
            # every time for every input — it logs CRITICAL with a CODE-DEFECT
            # banner + flips /health degraded, NOT a quiet "failed job" that
            # looks like a transient auth/network blip. Operational failures log
            # as before. ``failure_text`` stamps the CODE-DEFECT error_text.
            from email_triage.job_drain_safety import (
                failure_text, note_drain_failure,
            )
            note_drain_failure(_log, job_id=job["job_id"], kind=kind, exc=e)
            try:
                def _safety_net_finish(conn, job_id, err_text):
                    # ASYNC-DB: re-read + conditional finish write,
                    # batched into one off-loop hop. Re-read so we don't
                    # clobber a state another path already moved to
                    # terminal (e.g. cancel arriving right before the
                    # exception).
                    latest = get_triage_job(conn, job_id)
                    if latest and latest["status"] == "running":
                        finish_triage_job(
                            conn, job_id, status="failed",
                            error_text=err_text,
                        )

                await db_call(
                    _safety_net_finish, conn, job["job_id"],
                    failure_text(e),
                )
            except Exception:
                _log.exception(
                    "finish_triage_job(failed) write also raised; "
                    "row will be picked up by next-restart requeue",
                )
