"""Background runner for whole-mailbox triage jobs (#101).

Distinct from ``triage_runner.py`` (which handles synchronous inline
runs of <=100 messages via the /triage/run HTTP path). This module
hosts the long-running task that drains the ``triage_jobs`` queue —
one job at a time, under operator-tunable rate-limit + concurrency
knobs, with cancel-checks at every batch boundary.

Design (full design lives in punch-list #101):

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


_log = logging.getLogger("email_triage.web.triage_runner_bulk")

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
    msg_id: str,
    provider,
    classifier,
    categories,
    routes_by_cat,
    registry,
    conn,
    acct,
    account_hipaa: bool,
    actor_user_id: int | None,
    job_id: str,
    bucket: TokenBucket,
    sem: asyncio.Semaphore,
    self_from_addr: str = "",
    list_hints_lists=None,
    list_hints_rules_by_list=None,
):
    """Classify one message + fire its routed actions.

    Mirrors the inner-loop body of ``triage_runner.run_triage`` but
    runs under the bulk runner's rate-limit + concurrency primitives
    and writes a per-message ``triage_runs`` row immediately rather
    than batching them into a single end-of-run write.

    Returns a one-letter status used by the caller to bump the
    right counter:
      'p' — processed (classified + acted)
      's' — skipped   (e.g. our own X-Email-Triage header)
      'e' — error
    """
    from email_triage.web.db import record_triage_run
    from email_triage.web.routers.ui import (
        _collect_list_hints_for_message, _is_dry_run,
    )
    from email_triage.mail_headers import get_triage_header, is_self_origin

    # Dedup gate (#101 step 8). A prior crashed-and-resumed pass
    # may have already classified + acted on this message; the
    # triage_job_messages table records every (job_id, msg_id)
    # the runner finished. Hit -> return 'd' (dedup) without
    # bumping any counter — the counters were bumped on the
    # original pass, and run_triage_all pre-bumps them from
    # count_processed_messages_in_job at job start so resume
    # shows the right totals. Skipping here also avoids burning
    # a rate-limit token on work that's already done.
    if is_message_processed_in_job(conn, job_id, msg_id):
        return "d"

    # Rate-limit + concurrency caps gate the actual provider /
    # classifier work. Token first (system-wide cadence), then a
    # semaphore slot (parallel cap).
    await bucket.acquire()
    async with sem:
        try:
            message = await provider.fetch_message(msg_id)
            message.hipaa = account_hipaa
            et_header = get_triage_header(getattr(message, "headers", {}) or {})
            if et_header:
                # Loop prevention — our own outbound digests / drafts
                # carry this header; classifying them would re-trigger
                # actions on synthetic mail.
                record_triage_run(
                    conn, acct["id"], acct.get("name", ""),
                    query=f"bulk:{job_id}",
                    total_messages=1,
                    results=[{
                        "message_id": msg_id,
                        "status": "skipped",
                        "skip_reason": "x_email_triage_header",
                        "reason": "self_origin",
                        "x_email_triage": et_header,
                    }],
                    errors=[],
                    elapsed_secs=0.0,
                    actor_user_id=actor_user_id,
                )
                record_processed_message(conn, job_id, msg_id, "s")
                return "s"
            # Defense in depth (#117): downstream MTA may have stripped
            # the X-Email-Triage header. Match on sender == install's
            # smtp.from_addr as a secondary self-origin skip.
            if is_self_origin(
                getattr(message, "sender", "") or "", self_from_addr,
            ):
                record_triage_run(
                    conn, acct["id"], acct.get("name", ""),
                    query=f"bulk:{job_id}",
                    total_messages=1,
                    results=[{
                        "message_id": msg_id,
                        "status": "skipped",
                        "skip_reason": "self_from_match",
                        "reason": "self_origin",
                    }],
                    errors=[],
                    elapsed_secs=0.0,
                    actor_user_id=actor_user_id,
                )
                record_processed_message(conn, job_id, msg_id, "s")
                return "s"

            hints = _collect_list_hints_for_message(
                conn, message,
                lists=list_hints_lists,
                rules_by_list=list_hints_rules_by_list,
            )
            classification = await classifier.classify(
                message, categories, hints or None,
            )

            # Resolve actions for the classification's category. Bulk
            # uses the same per-account routes table as inline.
            entry = {
                "message_id": msg_id,
                "category": classification.category,
                "confidence": classification.confidence,
                "source": classification.source,
            }
            if not account_hipaa:
                entry["sender"] = getattr(message, "sender", None)
                entry["subject"] = getattr(message, "subject", None)
            try:
                if message.date:
                    entry["date"] = message.date.isoformat()
            except Exception:
                pass

            # Fire actions resolved by the route table. Mirrors the
            # inline path's behaviour: dry-run skips action.execute
            # while still recording the resolved category.
            #
            # ``routes_by_cat[cat]`` is the route row's ``actions``
            # list — each entry a ``{"action": <name>, "config": <dict>}``
            # dict (same shape ``list_account_routes`` returns). Iterating
            # the list yields these dicts; the inline path at
            # ``triage_runner.py:621`` pulls ``action_def.get("action", "")``
            # off each dict to look up the registered action. Before this
            # fix, the bulk loop iterated the dicts directly into
            # ``registry.get(...)`` which always returned None — every
            # action silently no-opped in bulk mode (operator-invisible
            # because no test asserted on ``actions_fired`` in bulk).
            dry_run = _is_dry_run(conn)
            actions_fired: list[str] = []
            for action_def in routes_by_cat.get(classification.category, []):
                action_name = (
                    action_def.get("action", "")
                    if isinstance(action_def, dict) else str(action_def)
                )
                if not action_name:
                    continue
                action = registry.get(action_name)
                if action is None:
                    continue
                if dry_run:
                    actions_fired.append(f"dry-run:{action_name}")
                    continue
                try:
                    await action.execute(
                        # Bulk doesn't materialise FlowState rows for
                        # every message — actions that need state_bag
                        # context (calendar_provider, meeting_prefs)
                        # operate on a stand-in dict. The inline
                        # path's calendar invite + suggest-meeting
                        # actions use this; bulk callers would skip
                        # those routes by configuration.
                        _StateBag(acct=acct),
                        message, classification, provider,
                    )
                    actions_fired.append(action_name)
                except Exception as ae:
                    actions_fired.append(f"err:{action_name}:{ae}")
            entry["actions"] = actions_fired

            record_triage_run(
                conn, acct["id"], acct.get("name", ""),
                query=f"bulk:{job_id}",
                total_messages=1,
                results=[entry],
                errors=[],
                elapsed_secs=0.0,
                actor_user_id=actor_user_id,
            )
            record_processed_message(conn, job_id, msg_id, "p")
            return "p"
        except Exception as e:
            _log.warning(
                "bulk per-message error",
                extra={"job_id": job_id, "msg_id": msg_id, "err": repr(e)},
            )
            try:
                record_triage_run(
                    conn, acct["id"], acct.get("name", ""),
                    query=f"bulk:{job_id}",
                    total_messages=1,
                    results=[{
                        "message_id": msg_id,
                        "status": "error",
                        "error": f"{type(e).__name__}: {e}",
                    }],
                    errors=[f"{type(e).__name__}: {e}"],
                    elapsed_secs=0.0,
                    actor_user_id=actor_user_id,
                )
            except Exception:
                pass
            try:
                record_processed_message(conn, job_id, msg_id, "e")
            except Exception:
                # Dedup write itself failed — likely DB locked.
                # Don't mask the real per-message error.
                pass
            return "e"


class _StateBag:
    """Placeholder flow-shaped object for action.execute signatures.

    The Action base class signature expects something with attributes
    the inline path's :class:`FlowState` provides. Bulk doesn't
    materialise full flows; this stand-in carries the minimum set
    actions actually read (account dict for HIPAA flag etc.). Routes
    that touch calendar / meeting state (AcceptInviteAction,
    SuggestMeetingTimesAction) need the inline path's flow shape and
    operators should not wire them into bulk routes.
    """
    def __init__(self, *, acct: dict):
        self.acct = acct
        self.state_bag: dict = {}
        # Common flow attrs that some actions read on existence checks.
        self.flow_id = ""
        self.message_id = ""
        self.actions_pending: list[str] = []
        self.actions_completed: list[str] = []
        self.revision = 0


async def run_style_mine_job(
    app,
    conn: sqlite3.Connection,
    job: dict,
) -> None:
    """#161 item 5 — Execute one ``kind='style_mine'`` job end-to-end.

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

    job_id = job["job_id"]
    account_id = job["account_id"]
    actor_user_id = job.get("actor_user_id")
    raw_query = job.get("query", "") or ""

    # Parse limit out of the query column. Format set at queue time
    # is ``style_mine:limit=N``; any other shape falls back to the
    # install-wide default. Clamp defensively.
    limit = get_style_learning_mine_limit_default(conn)
    if raw_query.startswith("style_mine:limit="):
        try:
            limit = int(raw_query.split("=", 1)[1])
        except (TypeError, ValueError):
            pass
    if limit < 1:
        limit = 1
    elif limit > STYLE_LEARNING_MINE_LIMIT_MAX:
        limit = STYLE_LEARNING_MINE_LIMIT_MAX

    secrets = app.state.secrets
    config = getattr(app.state, "config", None)

    acct = get_email_account(conn, account_id)
    if acct is None:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="account not found",
        )
        return

    owner_id = acct.get("user_id")
    if owner_id is not None and is_user_disabled(conn, owner_id):
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="account owner disabled",
        )
        return

    # HIPAA gate (defence in depth — the inline handler already
    # checked, but a queued job survives an operator re-flag while
    # waiting in the queue). HIPAA-flagged + no opt-in fails the
    # job before any provider fetch.
    account_hipaa = is_account_hipaa(acct)
    if account_hipaa and not is_style_knobs_hipaa_allow(conn, account_id):
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="hipaa_gate: opt-in required",
        )
        return

    # Provider + classifier build. Same shape as run_triage_all.
    if config is None:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="classifier not configured",
        )
        return
    try:
        provider = _create_provider_from_account(acct, secrets)
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text=f"setup: {type(e).__name__}: {e}",
        )
        return

    # HIPAA audit bookend (actor != owner only) — mirrors the inline
    # path's _record_style_data_hipaa_access. The inline path writes
    # one row; this path bookends two (in_progress at start, final
    # outcome at end) because the work is long-running and an
    # auditor wants both timestamps.
    audit_event_id: int | None = None
    if (
        actor_user_id is not None
        and account_hipaa
        and actor_user_id != owner_id
    ):
        try:
            audit_event_id = record_hipaa_access_event(
                conn, actor_user_id, account_id, "style_mine_bulk",
                outcome="in_progress",
            )
        except Exception:
            _log.exception(
                "HIPAA audit row write failed (style_mine in_progress)"
            )

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

        bump_triage_job_counters(conn, job_id, seen=len(merged_pairs))

        messages = []
        for folder, mid in merged_pairs:
            try:
                msg = await provider.fetch_message(mid, folder=folder)
                messages.append(msg)
            except Exception as e:
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
            captured_ids: set[str] = set()
            try:
                rows = conn.execute(
                    "SELECT message_id FROM sent_mail_index "
                    "WHERE account_id = ? AND is_captured_pair = 1",
                    (account_id,),
                ).fetchall()
                for r in rows:
                    mid = (
                        r["message_id"] if hasattr(r, "keys") else r[0]
                    )
                    if mid:
                        captured_ids.add(str(mid))
            except Exception:
                captured_ids = set()

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
            alias_mode_on = is_alias_mode_enabled_for_account(
                conn, account_id,
            )
            if alias_mode_on:
                known_addresses = _account_addresses(acct)
                alias_descriptors, _unknown = (
                    await extract_style_profiles_per_alias(
                        messages, classifier,
                        known_addresses=known_addresses,
                        captured_message_ids=captured_ids,
                    )
                )
                persisted = 0
                for addr, prof in alias_descriptors.items():
                    try:
                        set_account_style_per_alias(
                            conn, account_id, addr,
                            prof.to_dict(),
                            sample_count=prof.sample_count,
                        )
                        persisted += 1
                    except Exception as e:
                        _log.warning(
                            "style_mine: per-alias persist failed; continuing",
                            extra={
                                "job_id": job_id,
                                "account_id": account_id,
                                "addr": addr,
                                "err": repr(e),
                            },
                        )
                # Refresh the account-wide row from the largest bucket
                # so the fallback (when alias-mode flips OFF later)
                # carries the dominant style. Mirrors the inline path's
                # set_style_profile call inside the alias branch.
                if alias_descriptors:
                    best = max(
                        alias_descriptors.values(),
                        key=lambda p: p.sample_count,
                    )
                    try:
                        set_style_profile(conn, account_id, best.to_dict())
                    except Exception:
                        pass
                # 2026-05-18 — bump by the actual message count, not 1.
                # Pre-fix this incremented total_processed by 1 (the
                # agent's "one logical output = one descriptor"
                # semantic), but the Recent bulk runs UI renders
                # ``total_processed / total_seen`` as a progress bar
                # — "1 / 100" reads as "1 of 100 messages done" /
                # "half-broken" to any operator (or any customer)
                # even though all 100 messages WERE actually mined.
                # Bumping by ``len(messages)`` gets the bar to 100%
                # and matches the natural reading.
                bump_triage_job_counters(
                    conn, job_id, processed=len(messages),
                )
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
                )
                set_style_profile(conn, account_id, profile.to_dict())
                # See alias branch above for the rationale on bumping
                # by ``len(messages)`` instead of 1.
                bump_triage_job_counters(
                    conn, job_id, processed=len(messages),
                )
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
        failed_with = f"{type(e).__name__}: {e}"
        _log.exception(
            "style_mine: run failed",
            extra={"job_id": job_id},
        )
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

    # Resolve terminal state.
    latest = get_triage_job(conn, job_id)
    if latest and latest["status"] == "running":
        if failed_with:
            finish_triage_job(
                conn, job_id, status="failed",
                error_text=failed_with,
            )
        else:
            finish_triage_job(conn, job_id, status="done")

    # Close HIPAA audit row.
    if audit_event_id is not None:
        outcome = "error" if failed_with else "success"
        try:
            update_hipaa_access_event(
                conn, audit_event_id, outcome,
                f"style_mine job {job_id}",
            )
        except Exception:
            _log.exception(
                "HIPAA audit row update failed (style_mine final)"
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
        _get_categories_from_db, _load_all_list_hints,
    )
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.add_label import AddLabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.registry import ActionRegistry

    job_id = job["job_id"]
    account_id = job["account_id"]
    actor_user_id = job.get("actor_user_id")
    query = job.get("query", "") or ""
    rate_msg_per_min = int(job.get("rate_msg_per_min") or 30)
    concurrency = max(1, int(job.get("concurrency") or 1))

    secrets = app.state.secrets

    acct = get_email_account(conn, account_id)
    if acct is None:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="account not found",
        )
        return

    owner_id = acct.get("user_id")
    if owner_id is not None and is_user_disabled(conn, owner_id):
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="account owner disabled",
        )
        return

    categories = _get_categories_from_db(conn, user_id=owner_id)
    if not categories:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text="no categories configured",
        )
        return

    account_routes = list_account_routes(conn, account_id)
    routes_by_cat = {r["category"]: r["actions"] for r in account_routes}
    account_hipaa = is_account_hipaa(acct)

    # Build provider + classifier once per job. Provider is closed
    # in the finally block below so a long sweep doesn't leak the
    # underlying connection on failure.
    try:
        provider = _create_provider_from_account(acct, secrets)
        classifier = _build_classifier_from_config(app.state.config)
    except Exception as e:
        finish_triage_job(
            conn, job_id, status="failed",
            error_text=f"setup: {type(e).__name__}: {e}",
        )
        return

    # HIPAA audit bookend — one row per JOB, only when a NON-OWNER
    # actor initiated. Owner sweeping their own mailbox is
    # first-party access; admin / delegate sweeping someone else's
    # is third-party PHI access + gets the §164.312(b) row.
    audit_event_id: int | None = None
    if (
        actor_user_id is not None
        and account_hipaa
        and actor_user_id != owner_id
    ):
        try:
            audit_event_id = record_hipaa_access_event(
                conn, actor_user_id, account_id, "bulk_triage",
                outcome="in_progress",
            )
        except Exception:
            _log.exception("HIPAA audit row write failed (in_progress)")

    registry = ActionRegistry()
    registry.register(MoveAction())
    registry.register(LabelAction())
    registry.register(AddLabelAction())
    registry.register(NotifyAction())
    registry.register(DraftReplyAction())

    # #145.2 — burst is operator-tunable via the /config page. Read
    # the saved runtime setting at job-RUN time (not job-CREATE time)
    # so an operator's mid-queue tuning takes effect on the next job
    # without restarting. Default 1 preserves legacy "single-step at
    # the configured cadence" behaviour for installs that never set
    # the knob. Falls back to the legacy heuristic only if the saved
    # value is missing OR explicitly zero (a 0 from a stale save would
    # otherwise short-circuit to 1 here, masking operator intent).
    operator_burst: int | None = None
    try:
        from email_triage.web.db import get_setting as _get_setting
        runtime_saved = _get_setting(conn, "runtime_settings") or {}
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

    # #134.1 — load classification lists + rules once per JOB. A bulk
    # sweep can process tens of thousands of messages; the prior
    # per-message refetch was the dominant DB-noise source on long runs.
    try:
        list_hints_lists, list_hints_rules_by_list = _load_all_list_hints(conn)
    except Exception:
        # Don't let a missing-table / mid-migration race kill the run;
        # fall back to per-message lookup for safety.
        _log.exception("preload _load_all_list_hints failed")
        list_hints_lists = None
        list_hints_rules_by_list = None

    cancelled = False
    failed_with: str | None = None

    # Resume support (#101 step 8): if the row was requeued after a
    # crash, the previous pass may have already processed N
    # messages — those rows live in triage_job_messages and
    # is_message_processed_in_job will short-circuit them inside
    # _process_one_message. Pre-bump the aggregate counters from
    # the dedup table so the UI doesn't show "0 / 10000 processed"
    # at restart while the dedup gate keeps clearing already-done
    # work. The seen counter still grows from the search_iter
    # walk; processed/skipped/errors come from the dedup record.
    pre = count_processed_messages_in_job(conn, job_id)
    if pre["p"] or pre["s"] or pre["e"]:
        bump_triage_job_counters(
            conn, job_id,
            processed=pre["p"], skipped=pre["s"], errors=pre["e"],
        )

    # High-water-mark cursor (#101 step 9). On a fresh run the row
    # has cursor=NULL; on resume after a crash, the persisted
    # cursor lets the provider's search_iter restart from the last
    # successful batch boundary. Provider-specific format (IMAP
    # max-UID-int, Gmail pageToken, O365 nextLink URL); the runner
    # just opaque-passes it through.
    resume_cursor = job.get("cursor")

    # Query-stage self-skip (#117). Same rewrite as triage_runner —
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

    try:
        async for batch, batch_cursor in provider.search_iter(
            effective_query,
            batch_size=BATCH_SIZE,
            resume_cursor=resume_cursor,
        ):
            # Cancel check at batch boundary BEFORE any work.
            latest = get_triage_job(conn, job_id)
            if latest is None or latest["status"] == "cancelled":
                cancelled = True
                break

            bump_triage_job_counters(conn, job_id, seen=len(batch))

            # Schedule per-message tasks; the semaphore inside
            # _process_one_message caps actual parallelism. Letting
            # asyncio queue every task in the batch is fine — they
            # contend on the semaphore and the rate-limit bucket
            # serialises further.
            tasks = [
                asyncio.create_task(_process_one_message(
                    msg_id=msg_id, provider=provider, classifier=classifier,
                    categories=categories, routes_by_cat=routes_by_cat,
                    registry=registry, conn=conn, acct=acct,
                    account_hipaa=account_hipaa,
                    actor_user_id=actor_user_id, job_id=job_id,
                    bucket=bucket, sem=sem,
                    self_from_addr=_self_from_addr,
                    list_hints_lists=list_hints_lists,
                    list_hints_rules_by_list=list_hints_rules_by_list,
                ))
                for msg_id in batch
            ]
            statuses = await asyncio.gather(*tasks, return_exceptions=False)

            processed = sum(1 for s in statuses if s == "p")
            skipped = sum(1 for s in statuses if s == "s")
            errors = sum(1 for s in statuses if s == "e")
            bump_triage_job_counters(
                conn, job_id,
                processed=processed, skipped=skipped, errors=errors,
            )

            # Persist the resume cursor AFTER the batch's per-message
            # work completes. Crash-during-batch leaves the cursor
            # at the previous batch's value; resume re-walks the
            # current batch's UIDs but the dedup table (#101 step 8)
            # short-circuits the already-processed entries so the
            # only repeated work is the provider page fetch + the
            # dedup-table lookups.
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
    except asyncio.CancelledError:
        # Process shutdown. Don't write a terminal row — leave it
        # 'running' so the next start's requeue picks it up. Re-raise
        # so the supervisor sees the cancellation cleanly.
        raise
    except Exception as e:
        failed_with = f"{type(e).__name__}: {e}"
        _log.exception("bulk run failed", extra={"job_id": job_id})
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        # #139 — drain the classifier's long-lived httpx pool.
        if "classifier" in locals() and hasattr(classifier, "close"):
            try:
                await classifier.close()
            except Exception:
                pass

    # Resolve terminal state. Cancelled writes are owned by the UI
    # path; only finalise here if the row is still 'running'.
    latest = get_triage_job(conn, job_id)
    if latest and latest["status"] == "running":
        if cancelled:
            finish_triage_job(conn, job_id, status="cancelled")
        elif failed_with:
            finish_triage_job(
                conn, job_id, status="failed", error_text=failed_with,
            )
        else:
            finish_triage_job(conn, job_id, status="done")

    # Close the HIPAA audit row.
    if audit_event_id is not None:
        outcome = (
            "cancelled" if cancelled
            else ("error" if failed_with else "success")
        )
        try:
            update_hipaa_access_event(
                conn, audit_event_id, outcome,
                f"bulk job {job_id}",
            )
        except Exception:
            _log.exception("HIPAA audit row update failed")


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
        n = requeue_orphaned_triage_jobs(conn)
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
            job = claim_next_queued_triage_job(conn)
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
        # #161 item 5 — branch on ``kind`` (v21 column). Default to
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
                # #180 C — re-embed an account's sent_mail_index rows
                # after a backend swap. Lazy-imported so the
                # embedding-bits package isn't pulled on every
                # dispatcher tick (most installs are not actively
                # reindexing).
                from email_triage.jobs.embedding_reindex import (
                    run_embedding_reindex_job,
                )
                await run_embedding_reindex_job(app, conn, job)
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
            _log.exception(
                "Bulk triage job raised — marking failed",
                extra={"job_id": job["job_id"]},
            )
            try:
                # Re-read so we don't clobber a state another path
                # already moved to terminal (e.g. cancel arriving
                # right before the exception).
                latest = get_triage_job(conn, job["job_id"])
                if latest and latest["status"] == "running":
                    finish_triage_job(
                        conn, job["job_id"], status="failed",
                        error_text=f"{type(e).__name__}: {e}",
                    )
            except Exception:
                _log.exception(
                    "finish_triage_job(failed) write also raised; "
                    "row will be picked up by next-restart requeue",
                )
