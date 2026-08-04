""" Topic back-scan job — match HISTORICAL mail against ONE Topic.

The steady-state Topic match is baked into the primary classify pass (design
``internal documentation`` §1) — there is NO separate
scan on the live path. The **only** ``triage_jobs`` work this feature adds is
the explicit, user-triggered **back-scan / "Preview matches"** over *historical*
mail: messages that were classified (or arrived) before the Topic existed, or
before its current ``topic_version``. This module drains those jobs.

What one back-scan job does (``kind='topic_backscan'``)
------------------------------------------------------
For a ``(topic, account)`` over a 30 / 60 / 90-day window:

  1. Iterate the account's recent messages in the window (the fetch is
     **thin + injectable** — production wires the provider; tests pass synthetic
     messages, so no live Ollama / IMAP is needed to exercise the logic).
  2. Run :func:`email_triage.actions.topic_matcher.match_topics_for_message`
     (the band/K orchestration over the classify pass) — fail-open, so a flaky
     classifier degrades the back-scan, never crashes it.
  3. For each **matched** verdict, ``insert_topic_hit(source='backscan',
     reason_terms=verdict.reason_terms, confidence=verdict.confidence)`` and
     cache the verdict in ``study_match_cache`` (so a re-preview at the same
     ``topic_version`` skips already-scanned mail).

Write-path discipline (design §4.4 — the v0.1.2 INCIDENT-1 lesson)
-----------------------------------------------------------------
Every write rides the **existing single-writer** thread via ``db_call`` — NO new
SQLCipher connection (a 4th re-opens the encrypted lock-storm). Writes are
committed in **small bounded batches** (``WRITE_BATCH_SIZE``), NOT a 100-row
lock-hold like ``embedding_reindex._apply_batch_updates`` — SQLCipher's per-page
crypto widens every write-lock window, so a long lock-hold under encryption
re-creates the contention that fix reduced. The bulk runner drains this job with
inter-batch yields so a long back-scan doesn't starve other tasks.

Enqueue idempotency
-----------------------------------------
:func:`enqueue_topic_backscan` reuses the  embedding-reindex guard pattern
verbatim — ``SELECT 1 FROM triage_jobs WHERE kind='topic_backscan' AND status
IN ('queued','running') LIMIT 1`` ⇒ skip — so rapid re-presses (or a
``topic_version`` bump that re-triggers) never fan out duplicate jobs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from email_triage.actions.topic_configs import get_topic, insert_topic_hit
from email_triage.actions.topic_matcher import match_topics_for_message
from email_triage.db._helpers import dump_json_col, load_json_col
from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23
from email_triage.web.db import (
    create_triage_job,
    finish_triage_job,
    get_email_account,
    get_triage_job,
)

from email_triage.triage_logging import get_logger  # N-196b R21_4
log = get_logger("email_triage.jobs.topic_backscan")  # N-196b R21_4

#: Allowed back-scan windows, in days (design §8 R3 — 30 / 60 / 90 + All,
#: on-demand). ``0`` = "All mail" (no lower time bound — scan the whole
#: mailbox), added 2026-06-08 per operator ask for a [30/60/90/All] control.
ALLOWED_WINDOW_DAYS = (0, 30, 60, 90)
DEFAULT_WINDOW_DAYS = 30

#: The floor date used for the "All mail" (window_days == 0) scan — a
#: timezone-aware epoch so ``after_dt`` has no practical lower bound without
#: special-casing the provider fetch (which already takes an ``after``).
_ALL_MAIL_AFTER = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: How many messages a single provider/search batch pulls before we run the
#: matcher over them + flush. Kept modest so the per-batch write flush stays a
#: SMALL bounded lock-hold (design §4.4 / v0.1.2 INCIDENT-1), not a 100-row
#: encrypted-write storm.
FETCH_BATCH_SIZE = 25

#: Ceiling on how many messages ONE back-scan enumerates over its window
#: (operator 2026-06-12 "raise the cap + paginate"). The prior inline 10_000 —
#: applied most-recent-first — SILENTLY dropped older mail past it on a busy
#: window, and on Gmail/Graph the single-page ``search`` was capped even lower
#: (Google's hard 500), so a Gmail back-scan saw only the first 500. Now the
#: providers are PAGINATED (``search_iter`` follows the pageToken/nextLink) so
#: the WHOLE window is enumerated up to this ceiling; the ceiling is a safety
#: bound (the back-scan LLM-classifies EVERY enumerated message — there is no
#: pre-LLM ``study_match_cache`` skip PER RUN (but 's skip lets a re-run
#: RESUME the dropped tail across runs) — so it must stay finite) and hitting
#: it is SURFACED (WARNING log + job counter), never silent. 50k covers any
#: realistic personal-mailbox window; a larger corpus narrows the window or
#: re-runs. See ``_default_provider_fetcher_batches``.
BACKSCAN_SEARCH_CEILING = 50_000

#: Max DB writes (hit + cache rows) we hold before committing. Deliberately
#: small — under SQLCipher a long write-lock hold widens the contention window.
WRITE_BATCH_SIZE = 10

#: Yield to the event loop between fetch batches so a long back-scan doesn't
#: starve concurrent HTTP / other jobs on the shared loop.
INTER_BATCH_SLEEP_SECS = 0.0


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


# ---------------------------------------------------------------------------
# Verdict field access — duck-typed so the real classify-layer TopicVerdict
# and a test mock's verdict objects are both accepted.
# ---------------------------------------------------------------------------

def _v_topic_id(v: Any) -> Any:
    return v.get("topic_id") if isinstance(v, dict) else getattr(v, "topic_id", None)


def _v_confidence(v: Any) -> float:
    raw = v.get("confidence") if isinstance(v, dict) else getattr(v, "confidence", 0.0)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _v_reason_terms(v: Any) -> list[str]:
    raw = (
        v.get("reason_terms") if isinstance(v, dict)
        else getattr(v, "reason_terms", None)
    )
    if not raw:
        return []
    return [str(t) for t in raw]


# ---------------------------------------------------------------------------
# Message identity / header access (provider-normalised EmailMessage OR a
# duck-typed synthetic message in tests).
# ---------------------------------------------------------------------------

def _msg_rfc_message_id(msg: Any) -> str:
    """The durable RFC 5322 Message-ID — the cross-folder hit identity.

    A6 (census 2026-06-09): delegates to the message-level SSOT
    ``mail_headers.get_message_rfc_id`` so the header-casing authority is
    shared (was a local 3-casing loop). Same resolution order — header in
    any casing, then ``rfc822_message_id``, then ``message_id`` — for both
    object and dict messages. Empty string when none is present.
    """
    from email_triage.mail_headers import get_message_rfc_id
    return get_message_rfc_id(msg)


def _msg_folder(msg: Any) -> str:
    val = getattr(msg, "folder", None) if not isinstance(msg, dict) else msg.get("folder")
    return str(val) if val else ""


def _msg_provider_uid(msg: Any) -> str | None:
    val = (
        getattr(msg, "provider_uid", None) if not isinstance(msg, dict)
        else msg.get("provider_uid")
    )
    return str(val) if val else None


def _msg_uidvalidity(msg: Any) -> int:
    val = (
        getattr(msg, "uidvalidity", None) if not isinstance(msg, dict)
        else msg.get("uidvalidity")
    )
    return parse_int_or_none(val) or 0  # N-219c/15 R23: SSOT


def _msg_body_keywords(msg: Any) -> list[str]:
    """Cheap body keywords the pre-filter ranks on.

    The matcher reads no body itself — the caller (or the message) supplies the
    already-extracted keywords. We accept a ``body_keywords`` attr if present,
    else fall back to an empty list (the pre-filter's always-on band means a
    keyword-free message is still seen by the LLM, design §4.1)."""
    val = (
        getattr(msg, "body_keywords", None) if not isinstance(msg, dict)
        else msg.get("body_keywords")
    )
    if not val:
        return []
    return [str(k) for k in val]


# ---------------------------------------------------------------------------
# The injectable fetch interface.
#
# A ``MessageFetcher`` is an async callable that yields the historical messages
# for ``(account, window)`` in batches. Production builds one over the live
# provider; a test passes a fetcher that yields synthetic messages, so the whole
# job runs with NO live Ollama and NO live IMAP.
# ---------------------------------------------------------------------------

#: ``async (account_id, after_dt) -> AsyncIterator[list[message]]`` — yields
#: message batches (each ≤ FETCH_BATCH_SIZE) for the window.
MessageFetcher = Callable[[int, datetime], Any]


async def _default_provider_fetcher_batches(
    app: Any,
    conn: sqlite3.Connection,
    account_id: int,
    after_dt: datetime,
    headers_only: bool = False,
    stamp_folder: bool = False,
    job_id: str | None = None,
):
    """Production fetcher: pull the account's window mail via its provider.

    ``headers_only`` (operator 2026-06-12): when True, fetch only headers
    (IMAP ``BODY.PEEK[HEADER]``) — the cheap path for the keyword Preview pass,
    which scans the WHOLE window and only needs headers/keywords. Defaults
    False so the back-scan (which feeds the LLM) keeps full bodies.

    ``stamp_folder`` (operator 2026-06-12): when True, stamp each yielded
    message's source ``.folder``. The parsed ``EmailMessage`` does NOT otherwise
    carry which mailbox it came from, yet its ``message_id`` IS the IMAP UID and
    UIDs are mailbox-scoped (RFC 3501 §2.3.1.1) — so a later re-fetch (the topic
    Preview's "Test Details" full-body pull) needs the folder to re-address the
    UID. Defaults False so the back-scan's persisted ``topic_hits`` identity
    (which keys on the durable RFC Message-ID, NOT the folder/UID) is byte-for-
    byte unchanged; only the ephemeral Preview path opts in.

    Mirrors the style-mine / triage fetch idiom in ``triage_runner_bulk`` —
    build the provider from the account + secrets, search the window, fetch each
    message. Kept OUT of the core drain loop (which takes a fetcher) so the
    drain is testable without a live provider. Yields message batches.
    """
    from email_triage.engine.models import MailFilter
    from email_triage.web.db_threadpool import db_call
    # ``_create_provider_from_account`` is exported by web.routers.ui (the same
    # module triage_runner_bulk imports it from — see its local import). The
    # prior ``from web.triage_runner_bulk import _create_provider_from_account``
    # was a BUG: that name is only a *function-local* import inside
    # triage_runner_bulk, never a module-level attribute — so this import raised
    # ImportError the instant a real back-scan first iterated the fetcher,
    # failing EVERY non-test back-scan with zero messages scanned / zero hits.
    # Importing from the module that actually exports it fixes that. Kept as a
    # local (in-function) import so the web→jobs cycle resolves at call time.
    from email_triage.web.routers.ui import (  # local — avoid cycle
        _create_provider_from_account,
    )

    secrets = app.state.secrets
    acct = await db_call(get_email_account, conn, account_id)
    if acct is None:
        return
    provider = _create_provider_from_account(acct, secrets)
    # auth_stale lifecycle SSOT funnel (census 2026-06-09 #1). Although the
    # backscan is operator-initiated, it hits the SAME credential the
    # continuous monitors watch — wiring it surfaces a dead token via the
    # re-auth chip immediately, instead of deferring to the next poll cycle /
    # watch-renewal sweep (which could be hours away for a push-only account).
    from email_triage.web.app import record_provider_outcome
    from email_triage.web._auth_revoked import is_auth_revoked_exc
    try:
        #  all-folders (operator 2026-06-11): the topic back-scan scans the
        # WHOLE mailbox, not just the configured/watched folder. A topic's mail
        # is routinely filed into Archive / project folders, so an INBOX-only
        # scan misses most of it — and the "All mail" (window_days == 0) control
        # PROMISES whole-mailbox coverage (the §66 comment) but the old
        # single-folder search only delivered INBOX. Providers that expose
        # ``search_all_folders`` (IMAP) return ``(folder, uid)`` pairs we fetch
        # per-folder — UIDs are mailbox-scoped (RFC 3501 §2.3.1.1), so the
        # folder MUST ride along to SELECT the right mailbox before FETCH.
        # Providers whose plain ``search`` already spans the whole mailbox —
        # Gmail (labels are global) and Graph (``/me/messages`` is mailbox-wide)
        # — have no ``search_all_folders`` and take the single-search path. The
        # capability is duck-typed (hasattr), NOT provider-type-branched, so a
        # new provider opts in just by exposing the method.
        search_all = getattr(provider, "search_all_folders", None)
        try:
            if callable(search_all):
                # IMAP: ONE cross-folder SEARCH returns every in-window UID
                # (the server isn't paged; the ceiling is a client-side bound).
                # exclude_special_use: skip Trash/Junk/Drafts + Gmail's \All
                # virtual folder so a whole-mailbox scan never resurrects
                # user-deleted or quarantined PHI into a digest, and never
                # double-counts the \All mirror (hipaa-sme/DA 2026-06-11).
                pairs = await search_all(
                    "", BACKSCAN_SEARCH_CEILING, filter=MailFilter(after=after_dt),
                    exclude_special_use=True,
                )
            else:
                # Gmail/Graph: the single-page ``search`` is provider-capped
                # (Google's hard 500 / Graph's 1000) — it SILENTLY saw only the
                # first page. Paginate ``search_iter`` (pageToken / @odata.nextLink)
                # with the SAME window filter so the WHOLE window is enumerated up
                # to the ceiling (operator 2026-06-12 "raise the cap + paginate").
                pairs = []
                search_iter = getattr(provider, "search_iter", None)
                if callable(search_iter):
                    async for _ids, _cursor in search_iter(
                        "", filter=MailFilter(after=after_dt),
                    ):
                        # folder=None → fetch against the provider default
                        # (Gmail/Graph are mailbox-wide; the folder arg is moot).
                        pairs.extend((None, mid) for mid in (_ids or ()))
                        if len(pairs) >= BACKSCAN_SEARCH_CEILING:
                            break
                else:
                    # Provider without a paged variant — single-page fallback.
                    mids = await provider.search(
                        "", BACKSCAN_SEARCH_CEILING, filter=MailFilter(after=after_dt),
                    )
                    pairs = [(None, mid) for mid in (mids or ())]
        except Exception as _search_exc:
            # Auth-revoked search failure → flag the account (needle-filtered;
            # transient errors ignored), then re-raise so the job still records
            # as failed at the drain level.
            try:
                await db_call(record_provider_outcome, conn, acct, _search_exc)
            except Exception:
                pass
            raise
        # search succeeded → the credential is alive; clear any prior chip.
        await db_call(record_provider_outcome, conn, acct, None)

        # No silent caps (operator 2026-06-12): if the window enumeration hit the
        # ceiling, older mail past it is NOT scanned this run — say so loudly
        # (the back-scan LLM-classifies every enumerated message, so the ceiling
        # is a real bound, not a paging artifact). The ceiling is high enough that
        # a normal personal-mailbox window never trips it; when it does, the
        # operator narrows the window or re-runs.
        if len(pairs) >= BACKSCAN_SEARCH_CEILING:
            pairs = pairs[:BACKSCAN_SEARCH_CEILING]
            log.warning(
                "topic_backscan: window enumeration hit the message ceiling — "
                "older mail in this window was NOT scanned this run; narrow the "
                "window or re-run",
                extra={"_extra": {
                    "account_id": account_id,
                    "ceiling": BACKSCAN_SEARCH_CEILING,
                }},
            )
            #  — surface the ceiling hit on the job row so the progress UI
            # can banner it (the user-facing surface; the WARNING above is the
            # system-level one). Enumeration finishes before any batch is
            # yielded, so the flag lands early and the live status poll sees it.
            if job_id:
                from email_triage.web.db import set_triage_job_ceiling_hit
                await db_call(set_triage_job_ceiling_hit, conn, job_id)

        async def _fetch_one(mid: str, fldr: str | None) -> Any | None:
            """Single-message fetch with the right mailbox; one bad fetch
            (deleted between SEARCH and FETCH, encoding) skips, never fails
            the job."""
            try:
                if fldr is not None:
                    return await provider.fetch_message(
                        mid, folder=fldr, headers_only=headers_only,
                    )
                return await provider.fetch_message(
                    mid, headers_only=headers_only,
                )
            except Exception as fexc:  # noqa: BLE001 — one bad fetch ≠ job fail
                # #1 (census run16) — auth-revoked is a DEAD TOKEN, not "one bad
                # fetch". The search-leg CLEAR (record_provider_outcome None)
                # already fired, so SET the chip here and propagate — otherwise
                # the chip is left CLEARED on a revoked credential (masks
                # re-auth). Transient errors still skip (return None).
                if is_auth_revoked_exc(fexc):
                    await db_call(record_provider_outcome, conn, acct, fexc)
                    raise
                log.warning(
                    "topic_backscan: fetch failed; skipping",
                    extra={"_extra": {
                        "account_id": account_id, "folder": fldr,
                        "error_type": type(fexc).__name__,
                    }},
                )
                return None

        # Group (folder, uid) by folder so each mailbox is fetched on ONE
        # connection via fetch_messages_batch — one TLS+LOGIN per
        # FOLDER-CHUNK instead of per message. The all-folders widening over a
        # large mailbox (the mail host is ~80k UIDs) is exactly the workload where the
        # per-message login cost would dominate (db-sme 2026-06-11). Chunked at
        # FETCH_BATCH_SIZE so a huge folder never loads thousands of messages
        # into memory at once, and each yielded batch stays a SMALL bounded
        # downstream write-hold. Providers without fetch_messages_batch
        # (Gmail/Graph) take the per-message path.
        by_folder: dict[Any, list[str]] = {}
        for folder, mid in pairs or ():
            by_folder.setdefault(folder, []).append(mid)
        batch_fetch = getattr(provider, "fetch_messages_batch", None)

        for folder, uids in by_folder.items():
            for i in range(0, len(uids), FETCH_BATCH_SIZE):
                chunk = uids[i:i + FETCH_BATCH_SIZE]
                out: list[Any] = []
                if folder is not None and callable(batch_fetch):
                    try:
                        out = list(await batch_fetch(
                            chunk, folder=folder, headers_only=headers_only,
                        ))
                    except Exception as exc:  # noqa: BLE001 — per-message fallback
                        # #1 (census run16) — a batch auth-revoked is a dead
                        # token: SET the chip + propagate (the per-message
                        # fallback would only re-hit the same revoked credential
                        # and _fetch_one would re-raise anyway). Transient batch
                        # failures still fall back to per-message.
                        if is_auth_revoked_exc(exc):
                            await db_call(record_provider_outcome, conn, acct, exc)
                            raise
                        log.warning(
                            "topic_backscan: folder batch-fetch failed; "
                            "per-message fallback",
                            extra={"_extra": {
                                "account_id": account_id, "folder": folder,
                                "error_type": type(exc).__name__,
                            }},
                        )
                        out = []
                        for mid in chunk:
                            m = await _fetch_one(mid, folder)
                            if m is not None:
                                out.append(m)
                else:
                    for mid in chunk:
                        m = await _fetch_one(mid, folder)
                        if m is not None:
                            out.append(m)
                # fetch_messages_batch returns empty-shell messages for UIDs it
                # couldn't fetch; the drain skips them (no RFC Message-ID → no
                # hit row), so no extra filtering is needed here.
                if stamp_folder and folder is not None:
                    # Pin the source mailbox onto each message so a downstream
                    # re-fetch can re-address the (mailbox-scoped) UID. Best-
                    # effort: never fail the scan on a stamp. None folder =
                    # whole-mailbox provider (Gmail/Graph) that ignores it.
                    for _m in out:
                        try:
                            _m.folder = folder
                        except Exception:  # noqa: BLE001 — stamp is non-fatal
                            pass
                if out:
                    yield out
    finally:
        close = getattr(provider, "close", None)
        if close is not None:
            try:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:  # noqa: BLE001 — best-effort close
                pass


# ---------------------------------------------------------------------------
# Enqueue — with the  idempotency guard VERBATIM.
# ---------------------------------------------------------------------------

def enqueue_topic_backscan(
    conn: sqlite3.Connection,
    *,
    topic_id: int,
    account_id: int,
    actor_user_id: int | None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> str | None:
    """Insert a queued ``topic_backscan`` job, or skip if one is in flight.

    **#37 idempotency guard, VERBATIM** (mirrors the embedding-reindex enqueue
    dedup in ``web/routers/ui/admin.py``): if a non-terminal ``topic_backscan``
    job already exists, do NOT queue a second one — return ``None``. Rapid
    re-presses of "Preview matches" (or a ``topic_version`` bump that retriggers)
    collapse to the single in-flight run.

    The guard here is scoped to ``kind='topic_backscan'`` install-wide (matching
    the design doc's exact clause: ``WHERE kind='topic_backscan' AND status IN
    ('queued','running') LIMIT 1``) so a single back-scan worker drains them one
    at a time against the shared GPU/Ollama (design §4.4: back-scan runs
    concurrency=1, never during peak ingest).

    The job's ``query`` column carries a JSON descriptor (topic_id +
    window_days) the worker re-reads at run time. Returns the new ``job_id``, or
    ``None`` when the dedup skipped it.
    """
    if conn.execute(
        "SELECT 1 FROM triage_jobs WHERE kind='topic_backscan' "
        "AND status IN ('queued','running') LIMIT 1",
    ).fetchone():
        return None

    if window_days not in ALLOWED_WINDOW_DAYS:
        window_days = DEFAULT_WINDOW_DAYS
    payload = {
        "topic_id": int(topic_id),
        "window_days": int(window_days),
        "enqueued_at": _now_iso(),
    }
    return create_triage_job(
        conn,
        account_id=int(account_id),
        actor_user_id=actor_user_id,
        query=dump_json_col(payload),  # N-205 R22: route through json-col SSOT (was raw json.dumps → forked the ASCII-bloat pin's coverage)
        rate_msg_per_min=600,
        concurrency=1,
        kind="topic_backscan",
    )


# ---------------------------------------------------------------------------
# The drain.
# ---------------------------------------------------------------------------

async def run_topic_backscan_job(
    app: Any,
    conn: sqlite3.Connection,
    job_row: dict[str, Any],
    *,
    fetcher_batches: Any | None = None,
) -> None:
    """Drain one ``topic_backscan`` job to completion.

    Signature matches the other bulk-runner handlers
    (``await handler(app, conn, job)``) so the dispatcher can call it uniformly.
    ``fetcher_batches`` is the **injectable** message source — an async generator
    yielding message batches; production defaults to
    :func:`_default_provider_fetcher_batches`, tests pass a synthetic generator
    so the drain runs with no live provider / no live Ollama.
    """
    from email_triage.web.db_threadpool import db_call

    job_id = job_row["job_id"]
    account_id = int(job_row["account_id"])
    # N-72 — extract actor from the job row so the HIPAA bookend can apply
    # the actor≠owner gate correctly (PD#14).
    actor_user_id: int | None = job_row.get("actor_user_id")
    if actor_user_id is not None:
        actor_user_id = parse_int_or_none(actor_user_id)  # N-219c/4 R23: SSOT

    # Parse the back-scan descriptor (topic_id + window) out of the query column.
    topic_id, window_days = _parse_job_descriptor(job_row)
    if topic_id is None:
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text="topic_backscan: missing/invalid topic_id in job query",
        )
        return

    # Resolve the Topic + account up front. A deleted Topic / missing account is
    # a trivial done (intent served, nothing to scan).
    topic = await db_call(get_topic, conn, topic_id)
    if topic is None:
        log.info(
            "topic_backscan: topic gone; trivially done",
            extra={"_extra": {"topic_id": topic_id}},
        )
        await db_call(finish_triage_job, conn, job_id, status="done")
        return
    topic_version = int(getattr(topic, "topic_version", 1) or 1)

    acct = await db_call(get_email_account, conn, account_id)
    if acct is None:
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text="topic_backscan: account not found",
        )
        return

    # N-72 / PD#14 — HIPAA audit bookend. Mirror triage_runner_bulk's pattern
    # (lines ~793-811): one row per job, written only when a NON-OWNER actor
    # initiated a scan on a HIPAA account. Owner scanning their own mailbox is
    # first-party access and is exempt (feedback_hipaa_actor_owner_gate).
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import record_hipaa_access_event, update_hipaa_access_event
    from email_triage.web._audit import safe_audit_write_async
    from email_triage.db.audit import phi_access_audit_required
    account_hipaa = is_account_hipaa(acct)
    owner_id = acct.get("user_id")
    # N-72 audit state — initialised before the outer try so the finally can
    # always close the row (mirrors the  triage_runner_bulk pattern).
    audit_event_id: int | None = None
    # PD#14 gate via the predicate SSOT (N-79) — actor≠owner (owner self-access
    # exempt), NOT actor≠null: a SYSTEM-initiated (actor_user_id=None) back-scan
    # reading a HIPAA mailbox's PHI is still a non-owner access and must be
    # audited. This site already had the correct gate (the N-72 fix); routing it
    # through the shared predicate keeps it from re-drifting from its siblings.
    if phi_access_audit_required(
        account_hipaa=account_hipaa,
        actor_user_id=actor_user_id,
        owner_id=owner_id,
    ):
        # Best-effort audit write routed through the SSOT (run17 #3): a failed
        # §164.312(b) row write surfaces on /health's audit-failure drift
        # counter instead of being swallowed here. The wrapper returns the new
        # row id (or None on failure), so audit_event_id keeps flowing to the
        # finally bookend / update_hipaa_access_event calls below.
        audit_event_id = await safe_audit_write_async(
            lambda: db_call(
                record_hipaa_access_event,
                conn, actor_user_id, account_id, "topic_backscan",
                outcome="in_progress",
            ),
            description=f"topic_backscan hipaa_access in_progress account={account_id}",
        )

    # Build the classifier once (the matcher rides its classify_with_topics).
    classifier = _build_classifier(app)
    if classifier is None:
        if audit_event_id is not None:
            try:
                # hipaa-sme must-fix — NO message was read on this branch, so
                # the §164.312(b) row must say "skipped" (intent-to-scan not
                # actuated), NOT "error" (which is reserved for the
                # post-iteration path where PHI WAS read before a failure) —
                # else the access trail misdescribes a never-actuated scan as a
                # failed access.
                await db_call(
                    update_hipaa_access_event, conn, audit_event_id, "skipped",
                    "topic_backscan: no classifier configured; 0 messages read",
                )
            except Exception:
                pass
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text="topic_backscan: no classifier configured",
        )
        return

    # N-113 — HIPAA + BAA egress gate (shared SSOT with triage_runner + the Topic
    # preview; ). The back-scan re-classifies EVERY scanned message through
    # ``classifier`` (match_topics_for_message below). If the account is HIPAA-
    # flagged AND the configured classifier is external with no BAA ack on file,
    # that PHI must NOT flow to the non-BAA subprocessor (§164.308(b)(1)). The
    # §164.312(b) audit bookend above RECORDS the access; THIS gate PREVENTS the
    # un-BAA'd egress — placed before any message body is read. (The egress
    # funnel's LLM_PHI intent is pass-through by design; the per-message PHI
    # decision lives here at the baa_gate SSOT, not at the shared egress client.)
    from email_triage.classify.baa_gate import baa_block_status
    baa_block = await db_call(baa_block_status, conn, classifier, account_hipaa)
    if baa_block is not None:
        if audit_event_id is not None:
            try:
                await db_call(
                    update_hipaa_access_event, conn, audit_event_id, "blocked",
                    f"baa_gate: backend={baa_block['backend']} host={baa_block['host']}",
                )
            except Exception:
                log.exception(
                    "topic_backscan: HIPAA audit row update failed (blocked)",
                    extra={"_extra": {"job_id": job_id}},
                )
        await db_call(
            finish_triage_job, conn, job_id, status="failed",
            error_text=(
                "topic_backscan: HIPAA-flagged account blocked from non-BAA "
                f"classifier ({baa_block['backend']} @ {baa_block['host'] or '?'}). "
                "Acknowledge a BAA on /config or switch to a local Ollama."
            ),
        )
        return

    # window_days == 0 means "All mail" — scan from the epoch (no lower
    # bound) rather than ``now - 0 days`` (which would scan nothing).
    if int(window_days) == 0:
        after_dt = _ALL_MAIL_AFTER
    else:
        after_dt = datetime.now(timezone.utc) - timedelta(days=int(window_days))

    if fetcher_batches is None:
        fetcher_batches = _default_provider_fetcher_batches(
            app, conn, account_id, after_dt, job_id=job_id,
        )

    # The matcher only needs THIS Topic's config (one-Topic back-scan) — but it
    # takes the active-Topic LIST so the band logic is identical to the live
    # path. A one-element list runs the single-call band (≤ K).
    active_topics = [topic]

    #  categories-threading — match_topics_for_message re-classifies each
    # message, and its taxonomy gate drops EVERY verdict (fail-open) when the
    # parsed category is not in ``categories``. The production classifier
    # carries no ``.categories`` attribute, so the matcher's classifier
    # fallback resolves to ``{}`` and silently yields zero hits. Fetch the
    # Topic owner's taxonomy once and pass it explicitly so the back-scan
    # actually produces matches.
    from email_triage.web.db import bump_triage_job_counters, get_categories_dict
    owner_uid = int(getattr(topic, "user_id", 0) or 0) or None
    categories = await db_call(get_categories_dict, conn, user_id=owner_uid)
    #  — fingerprint the cache-verdict inputs NOT already in the (topic_id,
    # topic_version, account_id, rfc_id) key: the owner's CATEGORY taxonomy (an
    # input to the matcher's fail-open gate) + the configured classifier model.
    # A category delete/rename or a model-config swap changes this fingerprint,
    # so the cache READ below misses the now-stale rows and they re-scan —
    # closing the  SCOPED CONTRACT gap. prefer_loaded runtime model drift is
    # intentionally NOT captured (infra weather; acceptable cache reuse).
    _model_id = str(getattr(classifier, "_model", "") or "")
    match_fp = _match_fingerprint(categories, _model_id)

    #  v3 reinforcement (operator 2026-06-12 "curation + reinforcement loop"):
    # load this Topic's learned SENDER signals once. A thumbs-DOWN sender is
    # auto-DROPPED from the digest — skipped BEFORE the LLM (also saves the
    # classify call). A thumbs-UP sender is left to match normally (it's already
    # kept when it matches; we don't fabricate a hit for a non-match).
    from email_triage.actions.topic_configs import normalize_feedback_sender
    from email_triage.cache.topic_feedback import load_topic_sender_signals
    from email_triage.mail_headers import get_triage_header
    _fb_topic_id = int(getattr(topic, "id", 0) or 0)
    # Cache-aware read: the OPTIONAL Redis mirror if configured, else the DB.
    sender_signals = await load_topic_sender_signals(conn, _fb_topic_id)

    seen = 0
    processed = 0
    matched_hits = 0
    errors = 0
    cache_skipped = 0  #  — messages resolved from study_match_cache (no LLM)
    #  — incremental resume. Load every message already scanned at THIS
    # topic_version ONCE; the per-message loop SKIPS it before the (expensive)
    # LLM classify (re-emitting its cached hit so a re-preview stays complete).
    # This is what makes a re-run classify only NEW mail — and what makes the
    # finite BACKSCAN_SEARCH_CEILING safely raise-able: a re-run RESUMES into the
    # dropped older tail instead of re-walking the head. A topic_version bump
    # invalidates by construction (the cache key includes topic_version).
    #
    # CACHE-VALIDITY CONTRACT (db-sme  review +  close): the cache row is
    # keyed (topic_id, topic_version, account_id, rfc_id) AND tagged with a
    # match_fingerprint over the owner's CATEGORY taxonomy + the configured
    # classifier model. So the cache now captures the MESSAGE (immutable), the
    # TOPIC config (topic_version bumps on any topic edit), the CATEGORY taxonomy
    # + model (via the fingerprint — ), and the live SENDER-feedback signals
    # (re-applied each run BEFORE the skip below — NOT cached, so the ordering
    # guard below is what protects a newly-thumbs-down sender). A category
    # delete/rename or a model swap now CHANGES the fingerprint → the read below
    # misses those rows → they re-scan, so the formerly-documented stale-
    # matched=1 re-emission can no longer happen. (Pre-#60 rows carry an empty
    # fingerprint → a non-empty current fingerprint never matches → re-scanned
    # exactly once.)
    cached_verdicts = await db_call(
        _load_scan_cache, conn, topic_id, topic_version, account_id, match_fp,
    )
    # N-72 — terminal-state flags for the audit-row finally.
    _failed_with: str | None = None
    # Pending writes flushed in small bounded batches (NOT a 100-row hold).
    pending: list[tuple[str, dict[str, Any]]] = []

    async def _flush() -> None:
        nonlocal pending, errors
        if not pending:
            return
        batch = pending
        pending = []
        written = await db_call(
            _apply_write_batch, conn, topic_id, topic_version, account_id, batch,
            match_fp,
        )
        # _apply_write_batch returns count of rows it failed to write.
        errors += written

    # N-72 — outer try/finally mirrors triage_runner_bulk's  pattern:
    # the audit-row close runs even if the drain raises, so the in_progress
    # row is NEVER left open.
    try:
        try:
            async for batch in fetcher_batches:
                # Cancellation check at each batch boundary.
                latest = await db_call(get_triage_job, conn, job_id)
                if latest and latest.get("status") == "cancelled":
                    log.info(
                        "topic_backscan: cancellation observed",
                        extra={"_extra": {"job_id": job_id}},
                    )
                    await _flush()
                    return

                _seen_before = seen
                _processed_before = processed
                _cache_skipped_before = cache_skipped
                for msg in batch or ():
                    seen += 1
                    rfc_id = _msg_rfc_message_id(msg)
                    if not rfc_id:
                        # No durable identity — can't key a hit/cache row.
                        continue

                    # Never surface email-triage's OWN generated content
                    # (drafts, digests it sent) in a Topic digest — it's flagged
                    # with the X-Email-Triage loop-prevention header, the same
                    # self-origin guard the live runner uses (operator 2026-06-12).
                    if get_triage_header(getattr(msg, "headers", None) or {}):
                        continue

                    #  v3 reinforcement: a thumbs-DOWN sender is auto-dropped
                    # from this Topic — skip it before the classify call.
                    if sender_signals:
                        _sender_key = normalize_feedback_sender(
                            getattr(msg, "sender", "") or "",
                        )
                        if _sender_key and sender_signals.get(_sender_key) == -1:
                            continue

                    #  — incremental-resume skip. Already scanned at this
                    # topic_version? Skip the (expensive) LLM classify entirely.
                    # Re-emit the cached hit so a re-preview stays complete even
                    # if topic_hits was cleared (insert_topic_hit is an
                    # idempotent UPSERT); a matched=0 cached row just skips.
                    _cached = cached_verdicts.get(rfc_id)
                    if _cached is not None:
                        cache_skipped += 1
                        if _cached["matched"]:
                            pending.append((
                                "hit",
                                {
                                    "msg": _hit_identity(msg, rfc_id),
                                    "reason_terms": _cached["reason_terms"],
                                    "confidence": _cached["confidence"],
                                },
                            ))
                            matched_hits += 1
                            if len(pending) >= WRITE_BATCH_SIZE:
                                await _flush()
                        continue

                    verdicts = await match_topics_for_message(
                        msg, active_topics, classifier,
                        body_keywords=_msg_body_keywords(msg),
                        categories=categories,
                    )
                    processed += 1

                    # match_topics_for_message returns only MATCHED verdicts. We
                    # still write a (matched=0) cache row for a scanned-but-no-match
                    # message so a re-preview skips it; and a hit + (matched=1)
                    # cache row for a positive.
                    matched_this = {
                        _v_topic_id(v) for v in verdicts
                        if _v_topic_id(v) is not None
                    }
                    this_matched = topic_id in matched_this or (
                        # tolerate a verdict whose topic_id didn't echo back
                        bool(verdicts) and len(active_topics) == 1
                    )

                    if this_matched:
                        verdict = _pick_verdict(verdicts, topic_id)
                        reason_terms = _v_reason_terms(verdict)
                        confidence = _v_confidence(verdict)
                        pending.append((
                            "hit",
                            {
                                "msg": _hit_identity(msg, rfc_id),
                                "reason_terms": reason_terms,
                                "confidence": confidence,
                            },
                        ))
                        pending.append((
                            "cache",
                            {
                                "rfc_id": rfc_id,
                                "matched": 1,
                                "confidence": confidence,
                                "reason_terms": reason_terms,
                            },
                        ))
                        matched_hits += 1
                    else:
                        pending.append((
                            "cache",
                            {
                                "rfc_id": rfc_id, "matched": 0,
                                "confidence": 0.0, "reason_terms": [],
                            },
                        ))

                    if len(pending) >= WRITE_BATCH_SIZE:
                        await _flush()

                await _flush()
                # Advance the job row each batch so the UI poll sees LIVENESS:
                # advancing total_seen + a fresh last_progress_at heartbeat (per
                # feedback_long_running_check_in — alive == output advancing, not
                # just status='running'). Without this the row is a frozen
                # 0-of-0 for the whole scan. Per-batch (not per-message) keeps
                # the single-writer write-amp negligible (FETCH_BATCH_SIZE msgs
                # per bump); rides the existing db_call writer (no new conn).
                _d_seen = seen - _seen_before
                _d_processed = processed - _processed_before
                _d_cache = cache_skipped - _cache_skipped_before
                if _d_seen or _d_processed or _d_cache:
                    await db_call(
                        bump_triage_job_counters, conn, job_id,
                        seen=_d_seen, processed=_d_processed,
                        cache_skipped=_d_cache,
                    )
                if INTER_BATCH_SLEEP_SECS > 0:
                    await asyncio.sleep(INTER_BATCH_SLEEP_SECS)
        except asyncio.CancelledError:
            await _flush()
            raise
        except Exception as exc:  # noqa: BLE001 — surface as a failed job, not a crash
            await _flush()
            # Fail LOUD on a code defect (incident_2026-06-11): an
            # ImportError/AttributeError/NameError/TypeError fails every time —
            # log CRITICAL + flip /health degraded, not a quiet "failed job"
            # that reads like a transient auth/network blip (the exact masking
            # that hid the dead-feature ImportError). Operational errors log as
            # before. failure_text stamps a CODE-DEFECT: prefix on the row.
            from email_triage.job_drain_safety import (
                failure_text, note_drain_failure,
            )
            note_drain_failure(log, job_id=job_id, kind="topic_backscan", exc=exc)
            _failed_with = failure_text(exc)
            await db_call(
                finish_triage_job, conn, job_id, status="failed",
                error_text=_failed_with,
            )
            return
    finally:
        # N-72 — close the HIPAA audit row regardless of exit path.
        if audit_event_id is not None:
            outcome = "error" if _failed_with else "success"
            try:
                await db_call(
                    update_hipaa_access_event, conn, audit_event_id, outcome,
                    f"topic_backscan job {job_id}",
                )
            except Exception:
                log.exception(
                    "topic_backscan: HIPAA audit row update failed",
                    extra={"_extra": {"job_id": job_id}},
                )

    await _flush()
    log.info(
        "topic_backscan: finished",
        extra={"_extra": {
            "job_id": job_id, "topic_id": topic_id, "account_id": account_id,
            "window_days": window_days, "seen": seen, "processed": processed,
            "matched": matched_hits, "errors": errors,
            #  — how many messages were resolved from the resume cache (LLM
            # skipped). On a first scan this is 0; on a re-run it is ~everything
            # already scanned, so processed ≈ only the NEW mail.
            "cache_skipped": cache_skipped,
        }},
    )
    await db_call(finish_triage_job, conn, job_id, status="done")


# ---------------------------------------------------------------------------
#  — incremental-resume cache read. Load every message already scanned at a
# given topic_version so the drain can SKIP it before the (expensive) LLM
# classify. Keyed identically to the write (topic_id, topic_version, account_id)
# so a topic_version bump invalidates by construction (different key → empty
# load → full re-scan).
# ---------------------------------------------------------------------------

def _match_fingerprint(categories: "dict[str, str] | None", model_id: str) -> str:
    """A short, stable fingerprint of the cache-verdict inputs NOT already in the
    ``(topic_id, topic_version, account_id, rfc822_message_id)`` key: the
    owner's CATEGORY taxonomy (slug->description, an input to
    ``match_topics_for_message``'s fail-open gate) and the configured classifier
    ``model``. A category delete/rename or a model-config swap changes this, so
    ``_load_scan_cache``'s equality filter misses the stale rows and the drain
    re-scans them — closing the  SCOPED CONTRACT gap. 16 hex chars (64 bits)
    is ample for a cache tag. prefer_loaded runtime model drift is intentionally
    out of scope (a verdict from a slightly different resident model is
    acceptable cache reuse; only a DELIBERATE config change invalidates)."""
    payload = {
        "categories": sorted(
            (str(k), str(v)) for k, v in (categories or {}).items()
        ),
        "model": str(model_id or ""),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _load_scan_cache(
    conn: sqlite3.Connection,
    topic_id: int,
    topic_version: int,
    account_id: int,
    match_fingerprint: str,
) -> dict[str, dict[str, Any]]:
    """Return ``{rfc822_message_id: {matched, confidence, reason_terms}}`` for
    every cached message at this (topic_id, topic_version, account_id) whose
    ``match_fingerprint`` ALSO matches.
    A stale-fingerprint row (category/model changed since it was cached) is NOT
    returned, so the drain re-scans it instead of re-emitting a stale verdict.
    The lookup rides the UNIQUE-key autoindex prefix (topic_id, topic_version,
    account_id), with ``match_fingerprint`` a residual equality on that already-
    narrowed per-account rowset, so the read is cheap even at the ceiling."""
    rows = conn.execute(
        "SELECT rfc822_message_id, matched, confidence, reason_terms_json "
        "FROM study_match_cache "
        "WHERE topic_id = ? AND topic_version = ? AND account_id = ? "
        "AND match_fingerprint = ?",
        (int(topic_id), int(topic_version), int(account_id),
         str(match_fingerprint)),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        out[r["rfc822_message_id"]] = {
            "matched": int(r["matched"]),
            "confidence": float(r["confidence"]),
            # load_json_col SSOT (census ) — a corrupt column degrades to []
            # rather than 500ing the whole back-scan.
            "reason_terms": load_json_col(r["reason_terms_json"], default=[]),
        }
    return out


# ---------------------------------------------------------------------------
# Write batch — runs on the single-writer thread (via db_call). SMALL bounded
# batch (WRITE_BATCH_SIZE), NOT a 100-row encrypted lock-hold.
# ---------------------------------------------------------------------------

def _apply_write_batch(
    conn: sqlite3.Connection,
    topic_id: int,
    topic_version: int,
    account_id: int,
    batch: list[tuple[str, dict[str, Any]]],
    match_fingerprint: str,
) -> int:
    """Apply one bounded batch of hit + cache writes; return the failure count.

    Each hit goes through :func:`insert_topic_hit` (the UPSERT with the
    ``first_seen_at = MIN`` pin) with ``source='backscan'``. Each cache row is an
    UPSERT on ``study_match_cache``'s ``(topic_id, topic_version, account_id,
    rfc822_message_id)`` unique key so a re-scan at the same version is a no-op
    refresh, not a duplicate. The whole batch commits once (a single small
    write-lock window).

    Note: ``insert_topic_hit`` is ``@db_write`` (commits internally); calling it
    here — already on the writer thread via ``db_call`` — is the documented
    single-writer reentrancy path (the RLock is reentrant). We do the
    ``study_match_cache`` UPSERTs inline (no per-row helper) and commit once at
    the end to keep the cache writes in one bounded window.
    """
    failures = 0
    now = _now_iso()
    for kind, item in batch:
        try:
            if kind == "hit":
                ident = item["msg"]
                insert_topic_hit(
                    conn,
                    topic_id=topic_id,
                    account_id=account_id,
                    rfc822_message_id=ident["rfc_id"],
                    folder=ident["folder"],
                    provider_uid=ident["provider_uid"],
                    uidvalidity=ident["uidvalidity"],
                    reason_terms=item["reason_terms"],
                    confidence=item["confidence"],
                    source="backscan",
                    seen_at=now,
                )
            else:  # cache
                conn.execute(
                    "INSERT INTO study_match_cache ("
                    "  topic_id, topic_version, account_id, rfc822_message_id, "
                    "  matched, confidence, reason_terms_json, scanned_at, "
                    "  match_fingerprint"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(topic_id, topic_version, account_id, "
                    "            rfc822_message_id) DO UPDATE SET "
                    "  matched           = excluded.matched, "
                    "  confidence        = excluded.confidence, "
                    "  reason_terms_json = excluded.reason_terms_json, "
                    "  scanned_at        = excluded.scanned_at, "
                    "  match_fingerprint = excluded.match_fingerprint",
                    (
                        int(topic_id), int(topic_version), int(account_id),
                        item["rfc_id"], int(item["matched"]),
                        float(item["confidence"]),
                        dump_json_col(list(item["reason_terms"] or [])),
                        now, str(match_fingerprint),
                    ),
                )
        except sqlite3.Error as exc:
            failures += 1
            log.warning(
                "topic_backscan: row write failed",
                extra={"_extra": {
                    "kind": kind, "error_type": type(exc).__name__,
                }},
            )
    conn.commit()
    return failures


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------

def _hit_identity(msg: Any, rfc_id: str) -> dict[str, Any]:
    return {
        "rfc_id": rfc_id,
        "folder": _msg_folder(msg),
        "provider_uid": _msg_provider_uid(msg),
        "uidvalidity": _msg_uidvalidity(msg),
    }


def _pick_verdict(verdicts: Iterable[Any], topic_id: int) -> Any:
    """Pick the verdict whose ``topic_id`` matches; fall back to the first.

    A one-Topic back-scan's classifier may or may not echo the ``topic_id`` back
    (a mock might omit it); when no verdict carries the id we take the first
    matched verdict, since the matcher already filtered to matches for this
    Topic's classify call."""
    first = None
    for v in verdicts or ():
        if first is None:
            first = v
        if _v_topic_id(v) == topic_id:
            return v
    return first


def _parse_job_descriptor(job_row: dict[str, Any]) -> tuple[int | None, int]:
    """Pull ``(topic_id, window_days)`` out of the job's JSON query column."""
    raw = job_row.get("query") or ""
    # census  SSOT — corrupt/empty job query column degrades to {}
    # (→ topic_id None, default window — same as the old non-dict guard).
    data = load_json_col(raw, default={})
    tid = data.get("topic_id")
    topic_id: int | None = parse_int_or_none(tid)  # N-219c/45 R23: SSOT
    window = data.get("window_days", DEFAULT_WINDOW_DAYS)
    window_days = bounded_int(window, default=DEFAULT_WINDOW_DAYS)  # N-219c/19 R23: SSOT
    if window_days not in ALLOWED_WINDOW_DAYS:
        window_days = DEFAULT_WINDOW_DAYS
    return topic_id, window_days


def _build_classifier(app: Any) -> Any:
    """Resolve the classifier for the back-scan (same one the live pass uses).

    Prefer a classifier already on ``app.state``; else build one from config via
    the bulk-runner helper. Returns ``None`` when neither is available (the job
    then finishes failed with a clear message)."""
    clf = getattr(getattr(app, "state", None), "classifier", None)
    if clf is not None:
        return clf
    config = getattr(getattr(app, "state", None), "config", None)
    if config is None:
        return None
    try:
        # web.routers.ui is the real export site (triage_runner_bulk only
        # imports this name function-locally — never a module-level attr; see
        # test_infunction_import_resolution_pin). The old triage_runner_bulk
        # import raised ImportError → caught below → classifier silently None.
        from email_triage.web.routers.ui import (
            _build_classifier_from_config,
        )
        return _build_classifier_from_config(config)
    except Exception:  # noqa: BLE001
        return None


__all__ = [
    "ALLOWED_WINDOW_DAYS",
    "DEFAULT_WINDOW_DAYS",
    "enqueue_topic_backscan",
    "run_topic_backscan_job",
]
