"""#277d background-sweepers cluster — carved out of web/app.py (2026-05-30).

The periodic background maintenance loops + their per-account workers,
extracted from :mod:`email_triage.web.app` as the FINAL #277d cluster
(mirroring watcher.py / digest.py / ingestion_push.py / poll_ingestion.py).

Members (all lease-gated via ``supervised_interval_loop`` where they loop):

  * ``_baa_expiry_sweeper``           — hourly BAA-expiry auto-disable sweep
  * ``_per_contact_style_gc_sweeper`` — daily per-contact HIPAA style GC
  * ``_style_distill_trigger_sweeper``— 15-min M-3/M-7 distill triggers
  * ``_watcher_retry_sweeper`` + ``_recover_one_retry_row``
                                       — the consolidated retry-queue drainer
  * ``_hipaa_boundary_drift_detector``— 10-min HIPAA-flag audit reconciliation (PR9/D3)
  * ``_sent_mail_capture_loop`` + ``_run_sent_mail_capture_sweep``
        + ``_resolve_capture_interval_hours`` + ``_seconds_until_next_capture_tick``
        + ``_run_hipaa_counter_for_account``
                                       — the M-6 sent-mail edit-feedback capture loop
                                         and its HIPAA threshold-counter sibling

``email_triage.web.app`` re-exports every public name below via a bottom
re-export shim so existing ``from email_triage.web.app import
_watcher_retry_sweeper`` (test suite + lifespan task registration) keeps
resolving unchanged.

Free-name analysis (closing the dependency graph): every external name
these bodies reference is either a stdlib / third-party import replicated
at this module's top, ``log`` / ``fmt_exc`` (replicated), an intra-cluster
name (moved together), or a function-local import already inside the body.
The cluster needs ONE sanctioned ``email_triage.web.app`` late-import —
``record_provider_outcome`` (the auth_stale lifecycle funnel, function-local
in ``_recover_one_retry_row``; census run15 #4), exactly as poll_ingestion.py
function-locally late-imports the same funnel. Everything else stays out of
app.py (originally ZERO; the funnel is the single sanctioned exception).

The module logger keeps the ``"web.app"`` namespace (NOT
``"web.background_sweepers"``) to preserve the ``_PHI_KEYS`` scrubber
binding (§164.312(a)(2)(iv)) and log-line continuity, exactly mirroring
``poll_ingestion.py``.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from email_triage._isotime import now_utc_iso
from typing import Any

from fastapi import FastAPI

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc, scrub_error_for_persist
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT

log = get_logger("web.app")


async def _baa_expiry_sweeper(app: FastAPI) -> None:
    """Run the BAA-expiry sweep once per hour.

    The sweep is fully synchronous + idempotent (see
    :mod:`email_triage.baa_expiry`). Re-running on a day where no row
    is in scope is a single SELECT + bucket math; running on a day
    with an expired backend re-clears already-cleared FKs (no-op).
    The HOURLY cadence is enough to keep ``app.state.baa_expiry_status``
    fresh for the health endpoint without hammering SQLite — the
    underlying state changes at most once per day (a date crossing).

    Stamps two pieces of state:

    * ``app.state.baa_expiry_status``  — latest summary dict, used by
      the admin pages + the daily-health email to surface the
      buckets without re-running the sweep on every render.
    * ``app.state.baa_expiry_disabled_count`` — cumulative count of
      auto-disabled accounts since process boot. /health/detail
      surfaces this so a the monitoring system poll can see "how many BAA-driven
      downgrades have fired today" without scraping the audit log.
    """
    from email_triage.baa_expiry import baa_expiry_daily_sweep
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    # Initialise the cumulative counter on app.state so the health
    # endpoint reads a defined value even before the first tick.
    if not hasattr(app.state, "baa_expiry_disabled_count"):
        app.state.baa_expiry_disabled_count = 0
    if not hasattr(app.state, "baa_expiry_status"):
        app.state.baa_expiry_status = None

    async def _tick() -> None:
        #  — baa_expiry_daily_sweep issues raw reads on the shared
        # connection. db_call dispatches it off the loop UNDER the
        # process-wide DB lock, so it cannot race a request-surface
        # db_call worker on the same sqlite3.Connection.
        summary = await db_call(baa_expiry_daily_sweep, app.state.db)
        app.state.baa_expiry_status = summary
        app.state.baa_expiry_disabled_count = (
            int(app.state.baa_expiry_disabled_count or 0)
            + len(summary.get("auto_disabled") or [])
        )
        if summary.get("auto_disabled"):
            log.warning(
                "BAA expiry sweep auto-disabled HIPAA accounts",
                count=len(summary["auto_disabled"]),
                expired=summary.get("expired", 0),
            )

    #  — lease-gated: the auto-disable sweep must run on exactly
    # one instance per tick in a multi-instance deployment. Idempotent
    # + a transparent no-op single-instance.
    await supervised_interval_loop(
        "baa-expiry-daily-sweep", 3600, _tick,
        warmup_secs=5,
        startup_jitter_secs=30.0,
        lease_name="baa-expiry-daily-sweep",
        lease_conn=app.state.db,
    )


async def _per_contact_style_gc_sweeper(app: FastAPI) -> None:
    """Daily GC sweep for per-contact HIPAA style descriptors.

    Per-contact rows older than
    :data:`HIPAA_PER_CONTACT_GC_DAYS` (90 days) since last distill get
    deleted — operator likely stopped emailing that contact + the
    hash storage no longer earns its keep. Cascade-safe with the
    account ON DELETE.

    Cadence: daily (24h). The DELETE is cheap (single statement on
    a tiny indexed range) so running it daily rather than hourly
    keeps log volume low while staying well inside the freshness
    semantics. Idempotent — re-runs on a clean state return 0.

    Stamps ``app.state.per_contact_style_gc_status`` with the latest
    summary for /health/detail.
    """
    from email_triage.style_learning.per_contact_hipaa import (
        per_contact_gc_daily_sweep,
    )
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    if not hasattr(app.state, "per_contact_style_gc_status"):
        app.state.per_contact_style_gc_status = None

    async def _tick() -> None:
        #  — route the GC sweep through db_call so its DB access
        # runs off the loop under the process-wide DB lock.
        summary = await db_call(per_contact_gc_daily_sweep, app.state.db)
        app.state.per_contact_style_gc_status = summary
        if summary.get("removed"):
            log.info(
                "Per-contact style GC removed stale rows",
                count=summary["removed"],
                gc_days=summary["gc_days"],
            )

    #  — lease-gated global GC sweep; one instance per tick.
    await supervised_interval_loop(
        "per-contact-style-gc-daily-sweep", 86400, _tick,
        warmup_secs=8,
        startup_jitter_secs=30.0,
        lease_name="per-contact-style-gc-daily-sweep",
        lease_conn=app.state.db,
    )


async def _style_distill_trigger_sweeper(app: FastAPI) -> None:
    """Periodic trigger watcher for M-3 + M-7 HIPAA-safe style distills.

    Drives the trigger plane that sits between the user's sent mail
    + the existing queue worker. Conditions evaluated each tick (see
    :mod:`email_triage.style_learning.trigger_watcher`):

      * M-3 (account-level): first-time after opt-in, threshold
        (≥20 new sent messages since last success), stale (>7 days).
      * M-7 (per-contact): threshold (≥20 per recipient), stale
        (>30 days for inactive contacts with an overlay).

    Cadence: 15 minutes. The first-time trigger spec asks for an
    initial distill "within 5 minutes" of opt-in; the supervisor
    fires the first tick on startup-warmup ~12s in + every 15 min
    thereafter, so the worst-case latency on a freshly-flipped opt-in
    is ~15 min. Tightening this to 5 min would mean wasted work on
    a fleet of long-running installs; 15 min is the right trade-off
    + matches the homelab cron rules for ``/projects`` mining.

    Stamps ``app.state.style_trigger_sweep_status`` with the latest
    summary for /health/detail.
    """
    from email_triage.style_learning.trigger_watcher import (
        run_trigger_sweep,
    )
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    if not hasattr(app.state, "style_trigger_sweep_status"):
        app.state.style_trigger_sweep_status = None

    async def _tick() -> None:
        #  — route the trigger sweep through db_call so its DB
        # access runs off the loop under the process-wide DB lock.
        summary = await db_call(run_trigger_sweep, app.state.db)
        # Convert dataclass to dict for health-endpoint serialisation.
        # The dataclass is internal; the dict is the external surface.
        app.state.style_trigger_sweep_status = {
            "ts": summary.ts,
            "m3_evaluated": summary.m3_evaluated,
            "m3_enqueued": summary.m3_enqueued,
            "m7_evaluated": summary.m7_evaluated,
            "m7_enqueued": summary.m7_enqueued,
            "m3_reasons": dict(summary.m3_reasons or {}),
            "m7_reasons": dict(summary.m7_reasons or {}),
        }
        if summary.m3_enqueued or summary.m7_enqueued:
            log.info(
                "Style-distill trigger sweep enqueued work",
                m3_enqueued=summary.m3_enqueued,
                m7_enqueued=summary.m7_enqueued,
            )

    #  — lease-gated: the trigger sweep enqueues distill work; one
    # instance per tick avoids two instances double-enqueueing.
    await supervised_interval_loop(
        "style-distill-trigger-sweeper", 900, _tick,
        warmup_secs=12,
        startup_jitter_secs=30.0,
        lease_name="style-distill-trigger-sweeper",
        lease_conn=app.state.db,
    )


# ---------------------------------------------------------------------------
# Consolidated retry-queue drainer
# ---------------------------------------------------------------------------

#: Drainer tick cadence. Matches the shortest backoff bucket in
#: :data:`email_triage.retry_backoff.WATCHER_RETRY_SCHEDULE` so a
#: 30s-bucket retry fires on the next tick (worst-case 60s late, mean
#: 45s late).
_WATCHER_RETRY_TICK_SECONDS = 30

#: Per-tick fanout cap. Higher = faster drain on a large backlog; lower
#: = less impact on the LLM / provider when many messages were stuck
#: on the same outage.
_WATCHER_RETRY_PER_TICK_LIMIT = 10


async def _recover_one_retry_row(app: FastAPI, row: Any) -> str:
    """Recover one ``watcher_retry_queue`` row: re-fetch + full re-triage.

    Returns one of:

      * ``"done"``    — the message was re-fetched and re-triaged to a
        terminal (processed / skipped) status. Caller marks the row done.
      * ``"dead:<reason>"`` — the row can never succeed (account gone,
        UIDVALIDITY changed, message gone). Caller marks it dead with
        ``<reason>``.
      * ``"retry"``   — a transient failure; caller bumps attempt_count
        and re-enqueues so the backoff schedule pushes the next try out.
      * ``"retry:llm_unreachable"`` —  — the re-triage failed
        because the LLM backend is down (``classify`` raised
        ``LLMBackendUnreachableError``, which ``triage_single_message``
        re-raises unchanged). Caller bumps attempt_count AND re-enqueues
        with ``failure_kind='llm_unreachable'`` so the drainer's
        LLM-breaker gate skips the row while the backend stays down —
        otherwise a row whose ORIGINAL failure was an ordinary
        fetch/process error (``failure_kind`` NULL) would keep burning a
        full re-fetch+classify per tick against a dead backend, because
        a bare ``"retry"`` re-enqueue does not upgrade the kind.
      * ``"skip"``    — the install is in dry-run mode; the row
        is left untouched (still ``pending``) for a later real drain.
        Caller does NOT bump attempt_count and does NOT mark the row.

    The recovery runs the FULL triage path via
    :func:`email_triage.web.triage_one.triage_single_message` — classify
    + route + ACT. Re-acting is safe because every action is idempotent
    (the durable ``action_idempotency`` table, /): an action that
    already created a draft / event on the original attempt short-circuits
    on the re-run.
    """
    from email_triage.web.db import (
        get_email_account, effective_routes_by_cat,
        _account_mailboxes,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _is_dry_run,
        _create_calendar_provider_from_account,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.web.routers.ui._shared import _load_all_list_hints
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.calendars import is_calendar_effectively_enabled
    from email_triage.web.db import get_meeting_prefs
    #  — the re-triage re-raises this unchanged when the LLM backend
    # is down; the verdict it drives carries the failure_kind upgrade.
    from email_triage.llm_health import LLMBackendUnreachableError
    #  — every DB helper this recovery path touches the SHARED
    # connection with MUST go through ``db_call`` so the process-wide DB
    # lock serialises it against ``db_call`` workers and ``@db_write``
    # helpers. A bare ``asyncio.to_thread(<db helper>)`` or a sync DB
    # call on the event-loop thread bypasses the lock → ``InterfaceError:
    # bad parameter or other API misuse`` when it overlaps a db_call
    # worker on the same ``sqlite3.Connection``.
    from email_triage.web.db_threadpool import db_call
    # census run15 #4 — auth_stale lifecycle SSOT funnel. The retry drainer
    # re-fetches with the account's stored credential, so it is a credentialed
    # provider surface like the poll / push / sent-scan paths: it must CLEAR the
    # re-auth chip on a successful re-fetch and SET it on an auth-revoked one
    # (PD#18 both-edges-one-funnel) — previously it did neither, so a row that
    # drained during an outage left the chip stuck, and a dead token on the
    # drainer path looked healthy.
    from email_triage.web.app import record_provider_outcome

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    account_id = int(row["account_id"])
    provider_type = str(row["provider_type"])
    mailbox = row["mailbox"]
    uid = row["uid"]
    uidvalidity = row["uidvalidity"]
    gmail_msg_id = row["gmail_msg_id"]
    o365_msg_id = row["o365_msg_id"]

    # -- Resolve the account ------------------------------------------------
    #  — db_call (not bare to_thread) so the read is lock-serialised.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        # Account deleted while the row sat in the queue — unrecoverable.
        return "dead:operator_abandoned"

    # -- Dry-run guard ---------------------------------------------
    # A retry row was enqueued because a REAL action failed (dry-run was
    # OFF when it was created — dry-run never enqueues, the action loop
    # just logs and returns status="p"). If dry-run is now ON, running
    # the recovery would only log the would-be actions, return "p", and
    # the drainer would mark the row ``done`` — silently discarding a
    # genuine failure. Skip instead: leave the row ``pending`` so the
    # next drain after dry-run is turned back off recovers it for real.
    if await db_call(_is_dry_run, db):
        return "skip"

    # -- Build the provider -------------------------------------------------
    # IMAP rows pin the connection to the row's mailbox so the UID
    # addresses correctly (UIDs are mailbox-scoped, RFC 3501 §2.3.1.1).
    if provider_type == "imap":
        provider = _create_provider_from_account(
            acct, secrets, mailbox_override=mailbox,
        )
    else:
        provider = _create_provider_from_account(acct, secrets)

    _cal_provider = None
    try:
        # -- IMAP: guard UIDVALIDITY ---------------------------------------
        # A backfilled v16 row carries uidvalidity=0 (sentinel — the
        # original epoch is unknown); the live mailbox value will never
        # be 0, so a backfilled row marks dead here, which is the
        # correct conservative outcome.
        if provider_type == "imap":
            live_uidvalidity = None
            if hasattr(provider, "get_uidvalidity"):
                try:
                    live_uidvalidity = await provider.get_uidvalidity()
                except Exception as _uv_exc:
                    # Can't read UIDVALIDITY → transient. Route through the
                    # lifecycle funnel: it SETS the auth_stale chip iff _uv_exc
                    # is an auth-revoked needle (no-op otherwise), so an IMAP
                    # dead-credential surfaces here too.
                    await db_call(record_provider_outcome, db, acct, _uv_exc)
                    return "retry"
            if (
                uidvalidity is not None
                and live_uidvalidity is not None
                and int(uidvalidity) != int(live_uidvalidity)
            ):
                return "dead:uidvalidity_changed"

        # -- Re-fetch the message ------------------------------------------
        if provider_type == "imap":
            fetch_id = str(uid)
        elif provider_type == "gmail":
            fetch_id = str(gmail_msg_id)
        else:  # office365
            fetch_id = str(o365_msg_id)

        try:
            message = await provider.fetch_message(fetch_id)
        except Exception as fe:
            # 404-shaped provider errors → the message is gone (deleted
            # / archived between enqueue and recovery). Anything else is
            # transient.
            status = getattr(fe, "status", None)
            if status == 404:
                # Provider DEFINITIVELY reports the message gone (HTTP 404) — a
                # benign expunge, NOT the ambiguous empty-fetch case. The
                # provider authenticated and responded, so auth is healthy:
                # CLEAR any prior re-auth chip (PD#18 clear edge). Distinct
                # reason so it never trips the message_gone spike fail-safe.
                await db_call(record_provider_outcome, db, acct, None)
                return "dead:message_expunged"
            # Transient OR auth-revoked re-fetch failure. Route through the
            # lifecycle funnel — it SETS the auth_stale chip iff fe is an
            # auth-revoked needle (no-op for an ordinary transient), so the
            # retry drainer is not the one provider surface that can't surface a
            # dead token (PD#18 set edge).
            await db_call(record_provider_outcome, db, acct, fe)
            return "retry"

        # The provider authenticated and returned a message — auth is healthy.
        # CLEAR any prior auth_stale re-auth chip through the lifecycle SSOT
        # funnel (PD#18 clear edge), so a row that drained DURING an outage does
        # not leave the chip stuck once the token recovers. Covers the IMAP
        # empty-fetch (message-gone) branch below too — the FETCH still proved
        # auth. Mirrors ingestion_push.py:300 / the sent-scan twins.
        await db_call(record_provider_outcome, db, acct, None)

        # IMAP has no 404 — a missing UID yields an empty EmailMessage
        # (the stdlib backend returns data=[None]; see imap_blocking).
        # Detect it: no headers, no sender, no body → the UID is gone.
        if provider_type == "imap":
            _has_headers = bool(getattr(message, "headers", None))
            _has_sender = bool(getattr(message, "sender", ""))
            _has_body = bool(
                getattr(message, "body_text", "")
                or getattr(message, "body_html", "")
            )
            if not _has_headers and not _has_sender and not _has_body:
                # 0-byte / completely-empty fetch. Per RFC 3501 a UID FETCH
                # returns no data when the UID is gone — but a transient or
                # SYSTEMATIC fetch degradation can also yield empty for a UID
                # that is STILL present (mis-tombstoning real mail). VERIFY
                # before classifying: a confirmed-absent UID is a benign
                # ``message_expunged`` (never degrades /health); a still-present
                # OR unverifiable UID stays ``message_gone`` so the spike
                # fail-safe keeps watching the real fetch-degradation case.
                present = None
                if hasattr(provider, "uid_exists"):
                    try:
                        present = await provider.uid_exists(fetch_id)
                    except Exception:
                        present = None
                # §-anchor (hipaa-sme 2026-06-19): a VERIFIED-absent expunge is
                # an AUTHORIZED provider-side state change (the provider is the
                # mail system-of-record) — NOT a §164.312(c) integrity event nor
                # a §164.308(a)(7) availability loss for this triage layer. The
                # mail-LOSS hazard (present-but-empty / unverifiable fetch) stays
                # message_gone and still degrades, per the §164.308(a)(1)(ii)(B)
                # Risk-Management detective control. (db-sme cross-routed the
                # removed-alert; hipaa-sme verdict: acceptable, no register row.)
                if present is False:
                    return "dead:message_expunged"
                return "dead:message_gone"

        # -- Build the full TriageContext + re-triage ----------------------
        classifier = _build_classifier_from_config(config)
        #  — db_call (not bare to_thread) so these reads are
        # lock-serialised against db_call workers / @db_write helpers.
        categories = await db_call(
            _get_categories_from_db, db, acct.get("user_id"),
        )
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )
        mb_for_routes = (
            mailbox or (_account_mailboxes(acct.get("config") or {}) or [None])[0]
        )
        routes_by_cat = await db_call(
            effective_routes_by_cat, db, account_id, mailbox=mb_for_routes,
        )
        _lh_lists, _lh_rules = await db_call(_load_all_list_hints, db)
        _acct_hipaa = account_hipaa_effective(account=acct)
        _self_from_addr = getattr(
            getattr(config, "smtp", None), "from_addr", "",
        )

        # Calendar provider — only when calendar is effectively enabled,
        # so a recovered meeting-request gets the same intercept the
        # live ingestion paths give it.
        #
        #  — these helpers all READ the shared connection
        # (``is_calendar_effectively_enabled`` →
        # ``resolve_surrogate_account``/``is_calendar_enabled``;
        # ``_create_calendar_provider_from_account`` with ``db=`` →
        # ``resolve_surrogate_account``; ``get_meeting_prefs``). Calling
        # them inline runs them on the EVENT-LOOP thread, unlocked. Route
        # each through ``db_call`` so the read is lock-serialised.
        _mp = None
        try:
            if await db_call(is_calendar_effectively_enabled, db, acct):
                _cal_provider = await db_call(
                    _create_calendar_provider_from_account,
                    acct, secrets, db=db,
                )
            _mp = await db_call(get_meeting_prefs, db, acct.get("user_id"))
        except Exception:
            _mp = None

        #  — these reads also build the TriageContext; run them off
        # the loop under the DB lock rather than inline.
        _rule_labels_map = await db_call(_build_rule_labels_map, db)
        _rule_provider_labels_map = await db_call(
            _build_rule_provider_labels_map, db,
        )
        _dry_run = await db_call(_is_dry_run, db)

        ctx = TriageContext(
            db=db, config=config, secrets=secrets, acct=acct,
            classifier=classifier, provider=provider,
            registry=registry, categories=categories,
            routes_by_cat=routes_by_cat or {},
            list_hints_lists=_lh_lists,
            list_hints_rules_by_list=_lh_rules,
            rule_labels_map=_rule_labels_map,
            rule_provider_labels_map=_rule_provider_labels_map,
            calendar_provider=_cal_provider,
            meeting_prefs=_mp,
            self_from_addr=_self_from_addr,
            dry_run=_dry_run,
            account_hipaa=_acct_hipaa,
            actor_user_id=None,
            durable_dedup=True,
            mark_triaged_on_success=True,
            set_keyword_on_success=(provider_type == "imap"),
            #  — fire watches on retry recovery (reverts ).
            #  set this False on the premise "watches already
            # fired on the original ingestion attempt." That premise
            # is FALSE for the dominant retry case: when the LLM
            # backend is down, ``classify`` raises
            # ``LLMBackendUnreachableError`` BEFORE the  watch-fire
            # stage, so watches NEVER fired originally — and the 
            # LLM-down retry worker exists precisely for that case.
            # Suppressing the fire here meant a  escalation watch
            # (pager / SMS) on mail that arrived during an LLM outage
            # silently never fired. Re-firing is now safe:  (as
            # hardened by ) made ``fire_watches_for_message``
            # idempotent per ``(account_id, rfc_message_id, watch_id)``
            # via the durable ``watch_fire_idempotency`` table
            # (created v36, re-keyed on the RFC Message-ID by v37) —
            # a claim-before-fire that a second drainer pass (or a
            # restart mid-drain) treats as a no-op, so the pager/SMS
            # escalation cannot be duplicated.
            fire_watches=True,
        )
        try:
            res = await triage_single_message(ctx, message, fetch_id)
        except LLMBackendUnreachableError:
            #  — the re-triage hit a dead LLM backend. ``classify``
            # raises ``LLMBackendUnreachableError`` BEFORE the route+act
            # stage and ``triage_single_message`` re-raises it unchanged
            # rather than collapsing it into ``status='e'``.
            # Surface a distinct verdict so the sweeper re-enqueues with
            # ``failure_kind='llm_unreachable'``: a row whose ORIGINAL
            # failure was an ordinary fetch/process error carries a NULL
            # ``failure_kind``, and a bare ``"retry"`` re-enqueue keeps
            # NULL (COALESCE) — leaving the LLM-breaker gate unable to
            # skip it, so it re-fetches + re-classifies every tick
            # against the dead backend. The distinct verdict upgrades
            # the kind so the gate engages.
            return "retry:llm_unreachable"
        if res.status in ("p", "s"):
            return "done"
        # status == "e" — the re-triage itself errored (classify failed,
        # an action FAILED, etc.). Transient — bump + re-enqueue.
        return "retry"
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        if _cal_provider is not None:
            try:
                await _cal_provider.close()
            except Exception:
                pass


async def _watcher_retry_sweeper(app: FastAPI) -> None:
    """Drain ``watcher_retry_queue`` — the single consolidated retry queue.

    The retry/recovery subsystem rebuild collapsed the two
    legacy queues (``triage_retry_queue`` v16 + ``watcher_retry_queue``
    v30) onto this one table + this one drainer. Every per-message
    ingestion failure — IMAP IDLE watcher, unified poll, Gmail push,
    O365 push — lands here, and this loop is the ONLY thing that
    re-fetches + re-triages them.

    Per tick:

      1. **Cap sweep** — rows whose ``attempt_count`` has reached
         ``len(WATCHER_RETRY_SCHEDULE)`` transition to
         ``dead(max_attempts_exceeded)``.
      2. **LLM-breaker gate** — when the LLM circuit breaker is open,
         ``failure_kind='llm_unreachable'`` rows are skipped this tick
         (re-running classify against a dead backend just burns
         latency). Ordinary fetch/process failures are NOT gated — they
         drain regardless of LLM health.
      3. **Drain** — up to :data:`_WATCHER_RETRY_PER_TICK_LIMIT` due
         rows. For each, :func:`_recover_one_retry_row` resolves the
         account, builds the provider, (IMAP) checks live UIDVALIDITY,
         re-fetches, and runs the FULL triage path (classify + route +
         ACT). On a terminal verdict → ``mark_retry_done`` /
         ``mark_retry_dead``; on a transient failure → re-enqueue so the
         backoff schedule pushes the next attempt out.

    Lease-gated: exactly one instance drains per tick.
    """
    from email_triage.retry_backoff import (
        WATCHER_RETRY_SCHEDULE, max_attempts as _max_attempts,
    )
    from email_triage.web.db import (
        list_due_retries, mark_retry_dead, mark_retry_done, enqueue_retry,
        WATCHER_RETRY_DEAD_REASONS,
    )
    from email_triage.llm_health import (
        LLMBackendUnreachableError, is_healthy,
    )
    from email_triage.web.task_supervisor import supervised_interval_loop
    #  — drain every DB helper through db_call so reads + writes are
    # serialised on the process-wide DB lock against db_call workers.
    # The write helpers (mark_retry_*/enqueue_retry) are @db_write so a
    # bare to_thread was already lock-safe; routing them through db_call
    # too keeps the whole drainer uniformly greppable and covers the
    # un-decorated READ (list_due_retries) which a bare to_thread leaves
    # unlocked.
    from email_triage.web.db_threadpool import db_call

    max_attempts = _max_attempts(WATCHER_RETRY_SCHEDULE)

    if not hasattr(app.state, "watcher_retry_sweep_status"):
        app.state.watcher_retry_sweep_status = None

    def _llm_breaker_open() -> bool:
        """True when the configured classifier backend is unhealthy."""
        try:
            backend = getattr(
                getattr(app.state.config, "classifier", None),
                "backend", "ollama",
            )
            return not is_healthy(backend)
        except Exception:
            # Unknown health → assume healthy so llm_unreachable rows
            # still get a chance to drain rather than stalling forever.
            return False

    async def _tick() -> None:
        db = app.state.db

        # 1 — cap sweep. list_due_retries only returns pending rows; a
        # row at/over the attempt cap is transitioned to dead here so
        # it stops being re-drained.
        due_rows = await db_call(
            list_due_retries, db, limit=_WATCHER_RETRY_PER_TICK_LIMIT,
        )
        breaker_open = _llm_breaker_open()
        transitioned_dead = 0
        recovered = 0
        re_enqueued = 0
        skipped_llm = 0
        skipped_dry_run = 0

        for row in due_rows:
            row_id = int(row["id"])
            attempt_count = int(row["attempt_count"])
            failure_kind = (
                row["failure_kind"] if "failure_kind" in row.keys() else None
            )

            # 1 — cap sweep.
            if attempt_count >= max_attempts:
                try:
                    await db_call(
                        mark_retry_dead, db, row_id,
                        reason="max_attempts_exceeded",
                    )
                    transitioned_dead += 1
                except Exception as exc:
                    log.warning(
                        "Retry drainer: dead-transition failed",
                        row_id=row_id, error=fmt_exc(exc),
                    )
                continue

            # 2 — LLM-breaker gate. Skip llm_unreachable rows while the
            # classifier backend is down; ordinary failures drain anyway.
            if failure_kind == "llm_unreachable" and breaker_open:
                skipped_llm += 1
                continue

            # 3 — recover.
            try:
                verdict = await _recover_one_retry_row(app, row)
            except asyncio.CancelledError:
                raise
            except LLMBackendUnreachableError as exc:
                #  — defence in depth. _recover_one_retry_row already
                # catches this around the triage call and returns
                # ``"retry:llm_unreachable"``; should the error escape by
                # any other path, classify it here too so the row is
                # still re-enqueued with the failure_kind upgrade rather
                # than collapsed to a generic ``"retry"``.
                verdict = "retry:llm_unreachable"
                log.warning(
                    "Retry drainer: recovery hit LLM-down; re-enqueueing "
                    "as llm_unreachable",
                    row_id=row_id, error=fmt_exc(exc),
                )
            except Exception as exc:
                # An unexpected error inside recovery is transient —
                # bump + re-enqueue.
                verdict = "retry"
                log.warning(
                    "Retry drainer: recovery raised; re-enqueueing",
                    row_id=row_id, error=fmt_exc(exc),
                )

            if verdict == "done":
                try:
                    await db_call(mark_retry_done, db, row_id)
                    recovered += 1
                except Exception as exc:
                    log.warning(
                        "Retry drainer: mark_retry_done failed",
                        row_id=row_id, error=fmt_exc(exc),
                    )
            elif verdict == "skip":
                # #239b — install is in dry-run; the row is left
                # untouched (still pending, attempt_count unchanged) for
                # a real drain once dry-run is turned back off.
                skipped_dry_run += 1
                continue
            elif verdict.startswith("dead:"):
                reason = verdict.split(":", 1)[1]
                if reason not in WATCHER_RETRY_DEAD_REASONS:
                    reason = "operator_abandoned"
                try:
                    await db_call(mark_retry_dead, db, row_id, reason=reason)
                    transitioned_dead += 1
                except Exception as exc:
                    log.warning(
                        "Retry drainer: dead-transition failed",
                        row_id=row_id, error=fmt_exc(exc),
                    )
            else:
                # "retry" / "retry:llm_unreachable" — bump attempt_count
                # via the enqueue_retry upsert.
                #
                #  — when recovery failed because the LLM backend is
                # down, stamp ``failure_kind='llm_unreachable'`` so the
                # next tick's LLM-breaker gate skips the row. A plain
                # ``"retry"`` re-enqueue passes ``failure_kind=None``,
                # and ``enqueue_retry`` COALESCEs that — keeping the
                # row's EXISTING kind. That is correct for an ordinary
                # transient failure (a row originally stamped
                # llm_unreachable stays so), but it cannot UPGRADE a row
                # whose original failure carried a NULL kind. The
                # llm_unreachable verdict passes the kind explicitly so
                # the upgrade lands.
                _retry_failure_kind = (
                    "llm_unreachable"
                    if verdict == "retry:llm_unreachable"
                    else None
                )
                try:
                    await db_call(
                        enqueue_retry,
                        db,
                        account_id=int(row["account_id"]),
                        provider_type=str(row["provider_type"]),
                        mailbox=row["mailbox"],
                        uid=row["uid"],
                        uidvalidity=row["uidvalidity"],
                        gmail_msg_id=row["gmail_msg_id"],
                        o365_msg_id=row["o365_msg_id"],
                        error_class=str(
                            row["last_error_class"] or "RetryFailed"
                        ),
                        error_msg=row["last_error_msg"],
                        failure_kind=_retry_failure_kind,
                    )
                    re_enqueued += 1
                except Exception as exc:
                    log.warning(
                        "Retry drainer: re-enqueue failed",
                        row_id=row_id, error=fmt_exc(exc),
                    )

        app.state.watcher_retry_sweep_status = {
            "ts": now_utc_iso(),
            "due_seen": len(due_rows),
            "recovered": recovered,
            "transitioned_dead": transitioned_dead,
            "re_enqueued": re_enqueued,
            "skipped_llm_breaker": skipped_llm,
            "skipped_dry_run": skipped_dry_run,
        }

    #  — lease-gated: a single drainer per tick keeps two instances
    # from re-running the same retry-queue rows.
    await supervised_interval_loop(
        "watcher-retry-sweeper", _WATCHER_RETRY_TICK_SECONDS, _tick,
        warmup_secs=7,
        startup_jitter_secs=30.0,
        lease_name="watcher-retry-sweeper",
        lease_conn=app.state.db,
    )


async def _hipaa_boundary_drift_detector(app: FastAPI) -> None:
    """Periodically reconcile is_hipaa_mode() with the last
    ``hipaa_boundary_events`` row.

    PR 9 / D3. Catches the gap where a direct DB edit of the system
    HIPAA flag bypasses the audit row that ``/config/save`` would
    have written. Every 10 minutes, checks the current effective
    flag against the last recorded direction; on mismatch, appends a
    new boundary event with ``actor_id=None`` and ``reason="auto-
    detected"`` so the audit trail is never missing a transition.

    Idempotent: if the recorded direction already matches, no row is
    appended.
    """
    from email_triage.triage_logging import is_hipaa_mode
    from email_triage.web.db import (
        latest_hipaa_boundary, record_hipaa_boundary,
    )
    from email_triage.web.task_supervisor import supervised_interval_loop
    #  — route the DB read + write through db_call so they run off
    # the event loop under the process-wide DB lock (a direct sync call
    # here would stall the loop waiting on the RLock when a db_call
    # worker holds it).
    from email_triage.web.db_threadpool import db_call

    async def _tick() -> None:
        db = app.state.db
        # N-227c R22 — heartbeat stamp for /admin observability.
        app.state.hipaa_boundary_drift_detector_status = {
            "at": now_utc_iso(),
        }
        current_on = bool(is_hipaa_mode())
        current_direction = "on" if current_on else "off"
        latest = await db_call(latest_hipaa_boundary, db, "system")
        recorded_direction = latest.get("direction") if latest else "off"
        if recorded_direction != current_direction:
            await db_call(
                record_hipaa_boundary,
                db,
                scope="system",
                direction=current_direction,
                actor_id=None,
                reason="auto-detected drift",
            )
            log.warning(
                "HIPAA system flag drifted from audit trail; "
                "appended auto-detected boundary",
                expected=recorded_direction,
                found=current_direction,
            )

    #  — lease-gated: a drift-detected boundary row must be written
    # once, not once-per-instance. Converting to supervised_interval_loop
    # also fixes the pre-#204 cancel inconsistency (the old bare
    # ``await asyncio.sleep`` was not CancelledError-guarded).
    await supervised_interval_loop(
        "hipaa-boundary-drift-detector", 10 * 60, _tick,
        warmup_secs=15,
        startup_jitter_secs=30.0,
        lease_name="hipaa-boundary-drift-detector",
        lease_conn=app.state.db,
    )


async def _regulatory_clock_escalator(app: FastAPI) -> None:
    """ Phase 4 — recompute regulatory-clock state from the anchor + derived
    deadline each tick (running→at_risk→breached) and chain breaches.

    Idempotent + self-healing: state is DERIVED, so a missed sweep sees an
    already-breached clock next tick (never double-arms). Lease-gated ( —
    one instance writes), 15-min cadence, warmup+jitter — mirrors
    ``_hipaa_boundary_drift_detector``. The per-tick work is bounded
    (``_SWEEP_PER_TICK_CAP``) and dispatched OFF the event loop via ``db_call``
    so the single-writer chain isn't stampeded by a correlated SUSAR blast. The
    escalation rung DELIVERY (notifications) is Phase 4c; this engine marks the
    derived state + chains the legal ``breached`` transitions."""
    from email_triage.db.regulatory_clock import sweep_regulatory_clocks
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    async def _tick() -> None:
        res = await db_call(sweep_regulatory_clocks, app.state.db)
        # N-227c R22 — stamp includes the outcome summary (this sweeper's
        # single-shot res dict IS the summary).
        app.state.regulatory_clock_escalator_status = {
            "at": now_utc_iso(),
            "scanned": res.get("scanned", 0),
            "breached": res.get("breached", 0),
            "at_risk": res.get("at_risk", 0),
            "escalated": res.get("escalated", 0),
        }
        if res.get("breached") or res.get("at_risk") or res.get("escalated"):
            log.info(
                "regulatory-clock sweep applied transitions",
                breached=res.get("breached"), at_risk=res.get("at_risk"),
                escalated=res.get("escalated"), scanned=res.get("scanned"),
            )
        # Best-effort PHI-free escalation push (the chained audit record already
        # landed in the sweep). The in-app Compliance page is the always-on
        # delivery; this SMTP push is an additional channel, skipped silently if
        # SMTP isn't configured.
        notifications = res.get("notifications") or []
        if notifications:
            await _send_clock_escalations(app, notifications)
            #  P4f — the second calendar channel: also write the deadline to
            # the owner's connected calendar (gmail/o365) as a live event.
            # Best-effort + self-only; skipped for IMAP/calendar-disabled (the
            # .ics attachment above covers those clocks).
            await _write_clock_events_to_calendars(app, notifications)

    await supervised_interval_loop(
        "regulatory-clock-escalator", 15 * 60, _tick,
        warmup_secs=15,
        startup_jitter_secs=30.0,
        lease_name="regulatory-clock-escalator",
        lease_conn=app.state.db,
    )


# ---------------------------------------------------------------------------
#  — automated encrypted DB-snapshot backup (in-app sweeper)
# ---------------------------------------------------------------------------

_DB_BACKUP_INTERVAL_DEFAULT = 24 * 60 * 60  # daily
_DB_BACKUP_KEEP_DEFAULT = 14


def _db_backup_config(config) -> dict | None:
    """Resolve the automated-backup config from the config file's ``backup:``
    section (``config.backup`` / ``BackupConfig``), or None when DISABLED.

    Config-file driven, NOT env vars (feedback_no_env_vars_for_paths). Fail-
    closed: OFF unless ``backup.enabled``. ``cadence`` ∈ {``manual`` (default —
    CLI/cron triggers it, NO in-app timer), ``daily``, ``weekly``}; ``format``
    ∈ {``etbk`` (default full bundle), ``db`` (raw snapshot)}; ``retention`` is
    the operator spec (``14`` count | ``14d`` days | ``2w`` weeks). The operator
    flips ``enabled`` on only AFTER the key-only export.
    """
    bk = getattr(config, "backup", None)
    if bk is None or not getattr(bk, "enabled", False):
        return None
    cadence = (getattr(bk, "cadence", "manual") or "manual").lower()
    interval = {"daily": 24 * 60 * 60, "weekly": 7 * 24 * 60 * 60}.get(cadence)
    fmt = (getattr(bk, "format", "etbk") or "etbk").lower()
    if fmt not in ("etbk", "db"):
        fmt = "etbk"
    return {
        "dir": getattr(bk, "dir", "") or None,
        "cadence": cadence,
        "interval": interval,  # None for manual (no timer)
        "format": fmt,
        "retention": getattr(bk, "retention", "")
        or str(_DB_BACKUP_KEEP_DEFAULT),
        "encryption": (getattr(bk, "encryption", "master-key") or "master-key").lower(),
        "public_key": getattr(bk, "public_key", "") or "",
    }


def _backup_out_dir(app: FastAPI, cfg: dict) -> str:
    """Backup output dir: the config's ``backup.dir`` override, else
    ``<data_dir>/backups`` (a container-local volume; the host-side job
    relocates to the SMB share — the share is never in the container)."""
    from pathlib import Path

    d = cfg.get("dir")
    if d:
        return d
    db_path = getattr(getattr(app.state.config, "persistence", None), "db_path", "")
    base = Path(db_path).parent if db_path else Path("./data")
    return str(base / "backups")


def _resolve_backup_pubkey(cfg: dict) -> bytes:
    """Resolve the X25519 backup public key (PEM bytes) for public-key mode.

    Delegates to the ONE shared resolver ``backup.resolve_public_key_pem`` so the
    inline-vs-path / exists predicate is single-sourced with the config-time save
    validator (PD#5 — no two mirrored copies to drift; hipaa-sme H304-3).
    FAIL-CLOSED: raises if missing/unresolvable — public-key mode REQUIRES it (the
    failure is recorded as a backup FAILURE by ``run_backup_once``'s try/except)."""
    from email_triage import backup as _bk

    return _bk.resolve_public_key_pem(cfg.get("public_key") or "")


async def _record_backup_audit(db, *, outcome: str, detail: dict) -> None:
    """PHI-free audit row for one automated backup run.

    IN-PROCESS via ``db_call`` — the HMAC-chain-safe, single-writer mechanism
    the SME panel required (NEVER a cross-process raw INSERT, which would fork
    the chain). Best-effort: a failed audit write is logged, never raised — it
    must not poison the backup outcome (mirrors the manual-export route)."""
    import json

    from email_triage.web._audit import safe_audit_write_async
    from email_triage.web.db import record_auth_event
    from email_triage.web.db_threadpool import db_call

    # Best-effort, never-raise audit write routed through the SSOT
    # (census run17 #3) — a failed audit row must not poison the backup
    # outcome, and the failure is logged uniformly for /health's
    # audit-failure drift counter (no longer swallowed silently).
    await safe_audit_write_async(
        lambda: db_call(
            record_auth_event,
            db,
            event_type="db_snapshot_backup",
            email="system:auto-backup",
            outcome=outcome,
            detail=json.dumps(detail, separators=(",", ":")),
        ),
        description=f"db_snapshot_backup outcome={outcome}",
    )


from email_triage.single_flight import single_flight  # noqa: E402


@single_flight("db_backup")
async def run_backup_once(app: FastAPI, fmt: str, *, trigger: str = "cron") -> dict:
    """Produce ONE backup IN-PROCESS — the single core shared by the cadence
    sweeper AND the CLI/ops trigger.

    IN-PROCESS by design: the boot-stamped encryption context makes the
    snapshot/bundle SQLCipher ciphertext (no plaintext leak), the audit row is a
    safe single-writer in-process write (no cross-process HMAC-chain fork), and
    there is no stdout DB channel. ``@single_flight`` makes a concurrent caller
    fail fast with ``SingleFlightBusy`` (a clear 'already in flight', not a
    silent no-op).

    FAIL-CLOSED: a failed run records a per-run FAILURE status + a failure audit
    row + re-raises — it NEVER writes the success marker, so a stale marker can't
    make a failed run look fresh (devils-advocate FATAL-2). The success path
    writes the marker LAST then prunes (never prune-then-write)."""
    from pathlib import Path

    from email_triage import backup as backup_mod
    from email_triage.db._engine import dedicated_conn_is_encrypted
    from email_triage.secrets import read_bootstrap_master_key
    from email_triage.version import read_db_schema_version
    from email_triage.web.db_threadpool import db_call

    config = app.state.config
    cfg = _db_backup_config(config) or {}
    db = app.state.db
    out_dir = Path(_backup_out_dir(app, cfg))
    retention = cfg.get("retention", "14")
    fmt = "etbk" if fmt == "etbk" else "db"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    out_path = out_dir / backup_mod.snapshot_filename(ts, fmt)

    # Read the master key INSIDE the try: a SecretNotFound / decrypt failure here
    # is a backup FAILURE that MUST record the per-run FAILURE status + audit, not
    # die before them — else the stale success marker makes a failed backup look
    # fresh (the silent-failure class this feature exists to close; DA FATAL).
    # key_fpr stays None until the key resolves, so the failure path can still
    # write the status.
    key_fpr: str | None = None
    try:
        master_key = read_bootstrap_master_key(config)
        key_fpr = backup_mod.master_key_fingerprint(master_key)
        # FAIL-CLOSED at the ACTUATOR (PD#9 — gate the run path, not just the
        # config writer; devils-advocate FATAL-1). The off-box X25519 seal is
        # applied ONLY by the etbk bundle path; the raw ``db`` snapshot has no
        # seal layer, so a ``public-key`` + ``db`` combo would write a snapshot
        # readable with the ON-BOX master key — silently voiding the exact
        # exposure public-key mode exists to prevent. A YAML/CLI-edited config
        # could arm this even though the save-form rejects it, so refuse HERE
        # (records a backup FAILURE) rather than emit a weak "public-key" backup.
        if (cfg.get("encryption", "master-key") == "public-key"
                and fmt != "etbk"):
            raise backup_mod.BackupError(
                "backup.encryption=public-key requires the etbk bundle format "
                "(format=etbk) — the raw db snapshot has no off-box seal layer "
                "and would be readable with the on-box master key."
            )
        if fmt == "etbk":
            from email_triage.web.routers.backup import (
                _make_bootstrap_provider,
                _resolve_cert_dir,
                _resolve_config_path,
                _resolve_data_dir,
            )

            # Passphrase source depends on the encryption mode: public-key =
            # a RANDOM passphrase (sealed to the off-box public key after the
            # verify); master-key = HKDF-derived (restore needs only the key).
            enc_mode = cfg.get("encryption", "master-key")
            if enc_mode == "public-key":
                import base64
                import os as _os

                pubkey_pem = _resolve_backup_pubkey(cfg)
                pp = base64.urlsafe_b64encode(_os.urandom(24)).decode("ascii")
            else:
                pubkey_pem = None
                pp = backup_mod.derive_etbk_passphrase(master_key)

            # Real DB schema version for the manifest. `app.state.schema_version`
            # is NEVER populated (so the old getattr default 1 was written into
            # EVERY manifest, regardless of the real schema). Read the live value
            # the way daily_health does — encryption-aware (49 on prod, not 1).
            schema_v = await asyncio.to_thread(
                read_db_schema_version, config.persistence.db_path,
            )
            bundle = await db_call(
                backup_mod.build_full_bundle,
                # build_full_bundle takes db_conn KEYWORD-ONLY (`def …(*, db_conn,
                # …)`); passing `db` positionally was a TypeError that crashed
                # EVERY automated .etbk backup (the manual export route already
                # uses db_conn=db). Operator hit it running `backup now`.
                db_conn=db,
                config_path=_resolve_config_path(config),
                data_dir=_resolve_data_dir(config),
                cert_dir=_resolve_cert_dir(config),
                secrets_provider=_make_bootstrap_provider(config),
                master_key_name=config.secrets.master_key_name,
                passphrase=pp,
                include_master_key=False,
                include_tls_certs=True,
                include_logs=False,
                commit_sha=str(getattr(app.state, "version", ""))[:12],
                schema_version=schema_v,
            )
            enc = dedicated_conn_is_encrypted()
            # archive+compress (above) → verify → seal: write_verified_*etbk
            # runs the strong restorability gate BEFORE the (public-key) seal.
            if pubkey_pem is not None:
                result = await asyncio.to_thread(
                    backup_mod.write_verified_pubkey_etbk,
                    bundle, passphrase=pp, public_key_pem=pubkey_pem,
                    out_path=out_path, encrypted=enc,
                )
            else:
                result = await asyncio.to_thread(
                    backup_mod.write_verified_etbk,
                    bundle, passphrase=pp, out_path=out_path, encrypted=enc,
                )
        else:
            result = await db_call(backup_mod.snapshot_db_to_path, db, out_path)
    except Exception as e:  # noqa: BLE001 — record + re-raise
        backup_mod.write_run_status(
            out_dir, outcome="failure", ts=ts, fmt=fmt,
            error=type(e).__name__, key_fpr=key_fpr,
        )
        await _record_backup_audit(
            db, outcome="failure",
            detail={"format": fmt, "trigger": trigger, "error": type(e).__name__},
        )
        log.error(
            "automated DB backup FAILED",
            format=fmt, trigger=trigger, error=fmt_exc(e),
        )
        raise

    # Success: marker LAST, then per-run status, then prune.
    backup_mod.write_backup_marker(out_dir, result, ts=ts, key_fpr=key_fpr)
    backup_mod.write_run_status(
        out_dir, outcome="success", ts=ts, fmt=fmt,
        file=result.path.name, key_fpr=key_fpr,
    )
    deleted = backup_mod.prune_backups(out_dir, retention)
    await _record_backup_audit(
        db, outcome="success",
        detail={
            "format": fmt, "trigger": trigger, "file": result.path.name,
            "bytes": result.bytes, "sha256": result.sha256,
            "pruned": len(deleted),
        },
    )
    log.info(
        "automated DB backup landed",
        format=fmt, trigger=trigger, file=result.path.name,
        bytes=result.bytes, pruned=len(deleted),
    )
    return {
        "outcome": "success", "format": fmt, "file": result.path.name,
        "bytes": result.bytes, "dir": str(out_dir),
    }


async def _db_backup_sweeper(app: FastAPI) -> None:
    """ — automated backup CADENCE leg (daily/weekly). The work is
    ``run_backup_once`` (shared with the CLI/ops trigger). DISABLED unless
    ``backup.enabled`` AND cadence ∈ {daily, weekly} (``manual`` = the CLI
    drives it, no timer). Lease-gated, warmup + jitter — mirrors
    ``_regulatory_clock_escalator``."""
    from email_triage.single_flight import SingleFlightBusy
    from email_triage.web.task_supervisor import supervised_interval_loop

    cfg = _db_backup_config(app.state.config)
    if cfg is None:
        log.info(
            "automated DB backup disabled (config backup.enabled false); "
            "sweeper inert"
        )
        return
    if cfg["interval"] is None:
        log.info(
            "automated DB backup cadence=manual; timer inert "
            "(CLI/cron triggers it)"
        )
        return

    async def _tick() -> None:
        # N-227c R22 — heartbeat stamp for /admin observability.
        app.state.db_backup_sweeper_status = {
            "at": now_utc_iso(),
            "format": cfg.get("format"),
        }
        try:
            await run_backup_once(app, cfg["format"], trigger="cron")
        except SingleFlightBusy:
            log.info("db-backup tick skipped — a backup is already in flight")

    await supervised_interval_loop(
        "db-backup-sweeper", float(cfg["interval"]), _tick,
        warmup_secs=20,
        startup_jitter_secs=30.0,
        lease_name="db-backup-sweeper",
        lease_conn=app.state.db,
    )


def _clock_escalation_recipient_in_scope(to_addr: str) -> bool:
    """ P4c BAA gate. v1 delivers ONLY to the account OWNER (resolved from
    the account's user — in-scope by construction for their own clock), so a
    non-empty address passes. When higher-rung delegate/compliance recipients
    are added (a §164.308(a)(4) disclosure to a third party), THIS gate must be
    extended to refuse an UNVERIFIED contact (fail-closed → degrade to
    owner-only), never silently email an unscoped address."""
    return bool(to_addr and "@" in to_addr)


async def _send_clock_escalations(app: FastAPI, notifications: list) -> None:
    """Best-effort PHI-free escalation push. Owner recipient; label +
    days-left only (no PHI). Skipped silently if SMTP isn't configured; a send
    failure is logged, never raised (the audit record + in-app surface stand)."""
    from email_triage.db.regulatory_clock import build_escalation_notification
    from email_triage.engine.ics import build_clock_ics
    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER, build_triage_header,
    )
    from email_triage.secrets import SecretsDecryptError, read_secret
    from email_triage.web.smtp_send import (
        format_from_header,
        send_smtp_message,
        stamp_default_message_headers,
    )
    from email.message import EmailMessage

    config = app.state.config
    secrets = getattr(app.state, "secrets", None)
    smtp = config.smtp
    if not getattr(smtp, "host", ""):
        return  # SMTP not configured → the in-app Compliance page is delivery
    password = ""
    if secrets is not None:
        try:
            password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            log.error(
                "regulatory-clock escalation push aborted — SMTP password "
                "unreadable (corrupt secret row or master-key mismatch)"
            )
            return
    base = (getattr(config, "public_url", "") or "").rstrip("/")
    deep_link = f"{base}/compliance" if base else "the Compliance page in email-triage"
    for n in notifications:
        to_addr = n.get("to_addr") or ""
        if not _clock_escalation_recipient_in_scope(to_addr):
            log.warning("regulatory-clock escalation: recipient out of scope; skipped")
            continue
        note = build_escalation_notification(
            label=n.get("label") or "regulatory deadline",
            deadline_at=n.get("deadline_at"), state=n.get("state") or "at_risk",
            deep_link=deep_link,
        )
        msg = EmailMessage()
        msg["Subject"] = note["subject"]
        msg["From"] = format_from_header(smtp.from_addr, smtp.from_name)
        msg["To"] = to_addr
        # N-272b R28 SSOT — RFC-preferred GMT Date + Message-Id at build time
        # (send_smtp_message is pure transport + does not add them).
        stamp_default_message_headers(msg)
        # hipaa-sme MUST-FIX: stamp the loop-prevention header (send_smtp_message
        # is pure transport + does NOT add it, unlike send_simple_smtp_email).
        # Without it, an escalation to a WATCHED owner mailbox re-ingests +
        # re-triages (mail_headers drops X-Email-Triage-stamped mail).
        msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header("escalation")
        msg.set_content(note["body"])
        # Always-on .ics calendar baseline: attach a PHI-free VEVENT+
        # VALARM so the deadline lands in the recipient's calendar (portable, no
        # OAuth). Same scrub-at-write posture as the body — label + days only.
        ics = build_clock_ics(
            uid=f"regclock-{n.get('instance_id')}@email-triage",
            label=n.get("label") or "regulatory deadline",
            deadline_at=n.get("deadline_at"), deep_link=deep_link,
        )
        if ics:
            msg.add_attachment(
                ics, maintype="text", subtype="calendar",
                filename="regulatory-deadline.ics",
            )
        try:
            await asyncio.to_thread(
                send_smtp_message, msg, smtp_host=smtp.host, smtp_port=smtp.port,
                smtp_user=smtp.username, smtp_password=password,
                use_tls=smtp.use_tls,
            )
        except Exception as exc:
            log.warning(
                "regulatory-clock escalation send failed", error=str(exc)
            )


def _resolve_clock_calendar_provider(db, secrets, account_id: int):
    """Off-loop: load the account, gate on calendar-enabled + the self-only
    surrogate refusal (HIPAA), and return a CalendarProvider or None. Mirrors
    ``openclaw._open_calendar``'s resolution but returns None instead of raising
    — a missing / disabled / IMAP calendar just means the .ics-in-email is the
    channel for that clock. ``db=db`` makes the factory resolve (and HIPAA-refuse)
    the surrogate itself, so a HIPAA clock account writes ONLY to its own
    calendar (self-only)."""
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.web.db import get_email_account, is_calendar_enabled
    from email_triage.web.routers.ui import _create_calendar_provider_from_account
    acct = get_email_account(db, account_id)
    if not acct:
        return None
    surrogate = resolve_surrogate_account(db, acct)
    flag_acct_id = (surrogate or acct)["id"]
    if not is_calendar_enabled(db, flag_acct_id):
        return None
    return _create_calendar_provider_from_account(acct, secrets, db=db)


async def _write_clock_events_to_calendars(app: FastAPI, notifications: list) -> None:
    """ P4f — direct calendar-write: land each escalating clock's deadline as a
    LIVE all-day event on the owner's connected calendar (gmail_api / office365),
    in ADDITION to the always-on .ics-in-email — a second, richer channel that the
    calendar app keeps + alarms natively.

    Self-only: the provider factory's surrogate resolution REFUSES any HIPAA
    account, so a HIPAA clock writes ONLY to its own calendar (or skips entirely
    when the account is IMAP / calendar-disabled — the .ics is then the channel).
    PHI-FREE scrub-at-write: SUMMARY = the clock LABEL only; NO description /
    case_ref / raw_deadline_phrase, and NO VALARM (the .ics already carries the
    alarm — never double-alarm). Once per clock (``calendar_written_at`` stamp, so
    a clock that escalates twice lands ONE event). Fail-OPEN: the .ics already
    delivered, so any calendar-API hiccup logs + skips, never breaks the sweep."""

    from email_triage._isotime import parse_iso
    from email_triage.db.regulatory_clock import mark_clock_calendar_written
    from email_triage.engine.models import CalendarEvent
    from email_triage.providers.calendar_base import CalendarScopeError
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    secrets = getattr(app.state, "secrets", None)
    for n in notifications:
        if n.get("calendar_written"):
            continue  # one event per clock — already written on an earlier rung
        account_id = n.get("account_id")
        deadline_at = n.get("deadline_at")
        instance_id = n.get("instance_id")
        if not account_id or not deadline_at:
            continue
        dl = parse_iso(deadline_at)
        if dl is None:
            continue
        try:
            provider = await db_call(
                _resolve_clock_calendar_provider, db, secrets, account_id,
            )
        except Exception as exc:
            log.warning(
                "regulatory-clock calendar provider resolve failed",
                error=str(exc),
            )
            continue
        if provider is None:
            continue  # IMAP / calendar-disabled / HIPAA-surrogate-refused → .ics is the channel
        # A TIMED marker AT the deadline instant. deadline_at is a real instant
        # (anchor + N days), so a timed event is precise AND serializes correctly
        # on both providers — it sidesteps the O365 all-day serialization bug
        # (tz-anchored all-day smears the day for a non-UTC viewer; tracked
        # separately on the punch list). The always-on .ics carries the all-day
        # form. 30-min block, transparency=free so it never blanks the PI's day.
        event = CalendarEvent(
            event_id="",
            summary=f"Regulatory deadline: {n.get('label') or 'regulatory deadline'}",
            start=dl,
            end=dl + timedelta(minutes=30),
            all_day=False,
            ical_uid=f"regclock-{instance_id}@email-triage",
            transparency="transparent",  # a free marker, not a busy block
        )
        try:
            await provider.create_event(event)
            await db_call(mark_clock_calendar_written, db, instance_id)
            log.info(
                "regulatory-clock calendar event written",
                instance_id=instance_id,
            )
        except (CalendarScopeError, NotImplementedError) as exc:
            log.info(
                "regulatory-clock calendar-write skipped (no calendar scope)",
                error=str(exc),
            )
        except Exception as exc:
            log.warning(
                "regulatory-clock calendar-write failed", error=str(exc),
            )
        finally:
            try:
                await provider.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
#  V3 — Topic retention soft-expire + tombstone horizon-purge sweep.
#
# Design §2 + §9 C-V3.1 (soft-tombstone-then-horizon-purge). Two jobs, one
# daily tick:
#
#   1. **Soft-expire** live ``topic_hits`` older than their owning Topic's
#      ``retention_days`` (relative to ``first_seen_at``) — set ``expired_at``
#      so the feedback/audit view survives the expiry (rows are NOT deleted
#      here). Idempotent: the WHERE guard skips already-expired/removed rows.
#
#   2. **Horizon hard-purge** Topics soft-tombstoned (``deleted_at`` set) for
#      longer than :data:`_TOPIC_PURGE_TOMBSTONE_HORIZON_DAYS`. The parent row
#      AND its child rows (``topic_hits`` / ``study_match_cache`` /
#      ``study_digest_state``) are hard-deleted. The hit-store is a
#      reconstructable derived cache (re-create the Topic → back-scan
#      repopulates from the mailbox), so this is space reclamation + stale
#      ``topic_version`` GC, NOT a data-loss path (design §9 V3 note).
#
# **C-V3.2 (HARD gate):** the §164.312(b) audit chain (``hipaa_access_events``
# / ``log_entries`` / the SQLiteLogHandler HMAC chain) MUST survive a Topic
# purge. The schema carries NO foreign key from any audit/register table to
# ``topics`` / ``topic_hits``, so a child-then-parent DELETE here can never
# cascade into the audit trail. This sweep deletes ONLY topic tables; it
# never touches ``log_entries`` or any audit/register table — verified by the
# explicit table list below.
#
# **Bounded small batches (encrypted-write-path lesson, v0.1.2 INCIDENT-1):**
# every statement is ``LIMIT``-capped so a backlog of expired hits or a large
# tombstoned Topic drains over several daily ticks rather than issuing one
# unbounded DELETE that would hold the single SQLCipher writer for a long
# transaction and re-trigger the encrypted lock-storm.
# ---------------------------------------------------------------------------

#: Days a Topic stays soft-tombstoned before the horizon purge hard-deletes
#: it + its children. Longer than a typical ``retention_days`` so an
#: accidental delete is recoverable for a while (re-create + back-scan).
_TOPIC_PURGE_TOMBSTONE_HORIZON_DAYS = 30

#: Per-statement row cap. Keeps each DELETE/UPDATE small under the single
#: SQLCipher writer (bounded-batch lesson). A backlog drains across ticks.
_TOPIC_PURGE_BATCH_LIMIT = 200

#: Tables whose rows the horizon-purge may hard-delete. EXPLICIT allow-list —
#: the three  child tables + the parent. NO audit/register/log table is on
#: this list (C-V3.2): the purge physically cannot reach the §164.312(b)
#: chain because it never names those tables.
_TOPIC_CHILD_TABLES = ("topic_hits", "study_match_cache", "study_digest_state")


def _topic_retention_purge_once(
    conn: sqlite3.Connection,
    *,
    now: datetime | None = None,
    horizon_days: int = _TOPIC_PURGE_TOMBSTONE_HORIZON_DAYS,
    batch_limit: int = _TOPIC_PURGE_BATCH_LIMIT,
) -> dict[str, int]:
    """Run ONE bounded retention soft-expire + tombstone horizon-purge pass.

    Synchronous + ``@db_write`` so it routes through the single-writer thread
    (no new SQLCipher connection — design §4.4 / v0.1.2 INCIDENT-1). Pure
    helper: tests pass ``now`` for determinism.

    Returns counters ``{"hits_expired", "topics_purged", "child_rows_purged"}``
    for /health/detail observability. Idempotent across ticks (a clean state
    returns all-zero); bounded by ``batch_limit`` so a large backlog drains
    over several ticks rather than one long-held writer transaction.

    Never touches the audit/log_entries/register chain (C-V3.2): it issues
    DELETE/UPDATE against ONLY the  topic tables named in
    :data:`_TOPIC_CHILD_TABLES` + ``topics``.
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from email_triage._isotime import to_utc_iso  # N-203 R22: A10 SSOT

    now = now or _dt.now(_tz.utc)
    # N-203 R22 (2026-07-02): route through A10 stored-ISO SSOT — widened
    # pin now catches `now = now or _dt.now(...)` BoolOp shape.
    now_iso = to_utc_iso(now)
    horizon_iso = to_utc_iso(now - _td(days=int(horizon_days)))

    counters = {"hits_expired": 0, "topics_purged": 0, "child_rows_purged": 0}

    # --- 1. Soft-expire hits past their Topic's retention_days ------------
    # Age is relative to first_seen_at vs the owning Topic's retention_days
    # (0 = keep forever — skip those). Only live rows (not removed, not
    # already expired) are eligible; the UPDATE sets expired_at so the
    # feedback/audit view of an expired hit survives (NOT a delete).
    # Bounded by batch_limit via a subselect of eligible ids.
    expire_ids = [
        int(r[0]) for r in conn.execute(
            "SELECT th.id FROM topic_hits th "
            "JOIN topics t ON t.id = th.topic_id "
            "WHERE th.removed_at IS NULL AND th.expired_at IS NULL "
            "  AND t.retention_days > 0 "
            "  AND th.first_seen_at < "
            "      datetime(?, '-' || t.retention_days || ' days') "
            "LIMIT ?",
            (now_iso, int(batch_limit)),
        ).fetchall()
    ]
    if expire_ids:
        placeholders = ",".join("?" for _ in expire_ids)
        cur = conn.execute(
            f"UPDATE topic_hits SET expired_at = ? "
            f"WHERE id IN ({placeholders}) AND expired_at IS NULL",
            (now_iso, *expire_ids),
        )
        counters["hits_expired"] = cur.rowcount or 0

    # --- 2. Horizon hard-purge soft-tombstoned Topics ---------------------
    # Pick a bounded set of Topics tombstoned past the horizon, delete their
    # child rows (bounded per child table), then the parent rows. Child-
    # then-parent ordering keeps each statement small + makes the no-audit-
    # cascade explicit (we never rely on ON DELETE CASCADE reaching an audit
    # table — there is no such FK, C-V3.2).
    purge_topic_ids = [
        int(r[0]) for r in conn.execute(
            "SELECT id FROM topics "
            "WHERE deleted_at IS NOT NULL AND deleted_at < ? "
            "ORDER BY deleted_at LIMIT ?",
            (horizon_iso, int(batch_limit)),
        ).fetchall()
    ]
    if purge_topic_ids:
        tph = ",".join("?" for _ in purge_topic_ids)
        # Child rows first (bounded per table). These tables ONLY ever hold
        # topic-derived rows — no audit/register data lives here.
        for child in _TOPIC_CHILD_TABLES:
            cur = conn.execute(
                f"DELETE FROM {child} WHERE topic_id IN ({tph})",
                tuple(purge_topic_ids),
            )
            counters["child_rows_purged"] += cur.rowcount or 0
        # Parent rows last.
        cur = conn.execute(
            f"DELETE FROM topics WHERE id IN ({tph})",
            tuple(purge_topic_ids),
        )
        counters["topics_purged"] = cur.rowcount or 0

    conn.commit()
    return counters


# Decorate at import time without forcing a top-level db_writelock import
# cycle: bind @db_write lazily on first registration. The undecorated
# function above stays unit-testable with a bare connection.
def _topic_retention_purge_db_write():
    from email_triage.web.db_writelock import db_write
    return db_write(_topic_retention_purge_once)


async def _topic_retention_purge_sweeper(app: FastAPI) -> None:
    """Daily  V3 sweep: soft-expire stale hits + horizon-purge tombstones.

    Lease-gated: the purge mutates shared state, so exactly one
    instance runs per tick in a multi-instance deployment; a transparent
    no-op single-instance. Cadence: daily — the underlying state (a Topic's
    retention window, a tombstone's age) changes at most once per day, and
    the bounded batches mean a large backlog still drains a chunk every tick
    until it clears.

    Routes the (``@db_write``) purge helper through ``db_call`` so it runs
    off the event loop under the process-wide DB lock — never on a new
    SQLCipher connection (§4.4). Stamps ``app.state.topic_retention_purge_status``
    for /health/detail. Per-tick errors are logged + swallowed so a transient
    DB hiccup never tears down the supervised loop.
    """
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    if not hasattr(app.state, "topic_retention_purge_status"):
        app.state.topic_retention_purge_status = None

    purge_helper = _topic_retention_purge_db_write()

    async def _tick() -> None:
        try:
            summary = await db_call(purge_helper, app.state.db)
        except Exception as exc:
            log.warning(
                "Topic retention/purge sweep failed",
                error=fmt_exc(exc),
            )
            return
        app.state.topic_retention_purge_status = {
            "ts": now_utc_iso(),
            **summary,
        }
        if summary.get("topics_purged") or summary.get("hits_expired"):
            log.info(
                "Topic retention/purge sweep",
                hits_expired=summary.get("hits_expired", 0),
                topics_purged=summary.get("topics_purged", 0),
                child_rows_purged=summary.get("child_rows_purged", 0),
            )

    #  — lease-gated: the purge hard-deletes rows; run it on exactly one
    # instance per tick. Idempotent + a no-op single-instance.
    await supervised_interval_loop(
        "topic-retention-purge-sweeper", 86400, _tick,
        warmup_secs=20,
        startup_jitter_secs=30.0,
        lease_name="topic-retention-purge-sweeper",
        lease_conn=app.state.db,
    )


async def _sent_mail_capture_loop(app: FastAPI) -> None:
    """Background task that scans Sent folders for AI-drafted-then-edited
    pairs (M-6 edit-feedback capture loop).

    Cron-anchored: ticks every ``style_learning.capture_interval_hours``
    hours (default 6), aligned to wall-clock multiples of that interval
    plus 0-300s of random jitter so a 50-install fleet doesn't slam
    Sent folders at the same instant.

    Per-account gates (each independently checked):
      * Account is active (``is_active=True``)
      * Account opted into M-4 RAG via the ``rag_sent_index_enabled``
        per-account toggle (M-6 piggybacks on M-4's opt-in -- captured
        pairs flow into the same store M-4 retrieves from)
      * Account is NOT HIPAA-flagged (defence in depth: the
        :class:`SentMailCaptureLoop` re-checks this at every public
        method)
      * The install-wide style-learning master toggle is on
      * An embedding backend is wired on ``app.state`` (no backend ⇒
        no captures; the underlying :class:`SentMailIndex` would
        refuse the construction anyway)

    Audit row: each scan attempt writes an ``auth_events`` row with
    ``event_type="sent_mail_capture"`` + ``outcome="success"`` /
    ``"failure"`` plus a ``count=N`` detail. This is operational
    metadata (was the capture loop healthy?), NOT PHI access -- it
    runs only on non-HIPAA accounts by gate, and the row carries no
    message content.
    """
    from email_triage.web.task_supervisor import supervised_interval_loop

    #  — ported onto supervised_interval_loop. The per-tick body is
    # _run_sent_mail_capture_sweep; the cron-anchored cadence is passed
    # as a callable interval (re-evaluated each cycle), so each sleep
    # still lands on the next wall-clock interval boundary + jitter.
    #
    # -style lease-gate: the M-6 sweep walks Sent folders and writes
    # captured pairs into the shared sent_mail_index; it is idempotent
    # (re-walking a snapshot re-captures the same pairs), but exactly one
    # instance per tick is the right multi-instance posture. A
    # transparent no-op on a single-instance install. The lease TTL
    # defaults to 3600s for a callable interval (see
    # supervised_interval_loop) — fine here: a crashed holder's lease
    # auto-expires well within the 6h cron cadence.
    await supervised_interval_loop(
        "sent-mail-capture-loop",
        lambda: _seconds_until_next_capture_tick(app),
        lambda: _run_sent_mail_capture_sweep(app),
        warmup_secs=60,
        startup_jitter_secs=30.0,
        lease_name="sent-mail-capture-loop",
        lease_conn=app.state.db,
    )


_SENT_MAIL_CAPTURE_DEFAULT_HOURS = 6
_SENT_MAIL_CAPTURE_JITTER_SECONDS = 300  # 0..5 minutes


def _resolve_capture_interval_hours(app: FastAPI) -> int:
    """Read the configured capture interval (hours).

    Thin shim around
    :func:`email_triage.web.db.get_style_learning_capture_interval_hours`
    so the loop + the /config save handler + the
    /profile/style-data banner all share one source of truth +
    one clamp policy. Local exception swallow keeps the loop's
    sleep helper resilient if the DB hop hiccups (returns the
    default in that case).
    """
    try:
        from email_triage.web.db import (
            get_style_learning_capture_interval_hours,
        )
        return get_style_learning_capture_interval_hours(app.state.db)
    except Exception:
        return _SENT_MAIL_CAPTURE_DEFAULT_HOURS


def _seconds_until_next_capture_tick(
    app: FastAPI, *, now: datetime | None = None,
) -> float:
    """Seconds until the next wall-clock capture-interval boundary +
    random jitter.

    Boundaries are at multiples of the interval hours from UTC midnight
    (e.g. interval=6h ⇒ 00:00, 06:00, 12:00, 18:00 UTC). Pure helper so
    tests can pass ``now`` for determinism.
    """
    import random
    interval_hours = _resolve_capture_interval_hours(app)
    if now is None:
        now = datetime.now(timezone.utc)
    interval_secs = interval_hours * 3600
    seconds_since_midnight = (
        now - now.replace(hour=0, minute=0, second=0, microsecond=0)
    ).total_seconds()
    next_boundary_offset = (
        (int(seconds_since_midnight) // interval_secs + 1) * interval_secs
    )
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    next_tick = midnight + timedelta(seconds=next_boundary_offset)
    seconds = (next_tick - now).total_seconds()
    seconds += random.uniform(0, _SENT_MAIL_CAPTURE_JITTER_SECONDS)
    return max(seconds, 1.0)


async def _run_sent_mail_capture_sweep(app: FastAPI) -> dict[str, int]:
    """Run one M-6 sweep across every opted-in non-HIPAA account.

    Pure async function so tests can drive it directly without
    waiting on the cron loop. Returns counters for observability:
    ``{"considered", "captured_total", "skipped_hipaa", "skipped_disabled",
    "skipped_no_backend", "errors"}``.
    """
    from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
    from email_triage.actions.sent_mail_index import (
        NonLocalBackendError, SentMailIndex,
    )
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import (
        is_rag_sent_index_enabled,
        is_style_learning_master_enabled,
        list_email_accounts,
        record_auth_event,
    )
    #  — ``async def`` sweep: route every sync DB helper through
    # ``db_call`` so it runs off the event loop under the process-wide
    # DB lock instead of colliding with db_call workers on the shared
    # ``sqlite3.Connection``.
    from email_triage.web.db_threadpool import db_call
    # census run17 #3 — best-effort audit-emit SSOT (never-raise + WARN
    # so a swallowed audit failure stays visible to /health's drift
    # counter); the async sibling wraps the ``await db_call`` seam.
    from email_triage.web._audit import safe_audit_write_async

    db = app.state.db
    secrets = app.state.secrets

    counters = {
        "considered": 0,
        "captured_total": 0,
        "skipped_hipaa": 0,
        "skipped_disabled": 0,
        "skipped_no_backend": 0,
        "skipped_auto_scan_off": 0,
        "errors": 0,
        #  — HIPAA threshold-counter producer wired into the same
        # sweep. HIPAA accounts no longer ``skipped_hipaa`` outright;
        # they dispatch to :class:`HipaaSentCounterLoop` which counts
        # WITHOUT reading bodies. ``skipped_hipaa`` is preserved for
        # back-compat with anything reading these counters but is no
        # longer incremented in the normal path (only on the per-
        # account auto-scan-off / style-learning-off escape hatches).
        "hipaa_counter_recorded": 0,
    }

    # Master toggle: install-wide off ⇒ no work.
    try:
        if not await db_call(is_style_learning_master_enabled, db):
            return counters
    except Exception:
        return counters

    # Embedding backend wired? Without it the SentMailIndex
    # construction would refuse anyway.
    backend = getattr(app.state, "embedding_backend", None)
    if backend is None:
        counters["skipped_no_backend"] = 1
        return counters
    embedding_model = getattr(app.state, "embedding_model", "") or ""
    sqlite_vec_available = bool(
        getattr(app.state, "sqlite_vec_available", False)
    )

    #  item 2 — per-account "auto-scan on schedule" toggle. When
    # OFF the loop SKIPS this account; only the operator-driven
    # "Mine the Sent Items Now" button on /profile/style-data fires
    # for that mailbox. HIPAA-flagged accounts default OFF
    # (opt-in-everywhere posture); non-HIPAA default ON.
    from email_triage.web.db import is_auto_scan_enabled_for_account

    accounts = await db_call(list_email_accounts, db)
    for acct in accounts:
        counters["considered"] += 1
        if not acct.get("is_active", True):
            counters["skipped_disabled"] += 1
            continue
        if is_account_hipaa(acct):
            #  — HIPAA accounts dispatch to the threshold-counter
            # loop (no body access; counts only). The loop checks its
            # own gates (per-account auto-scan, style_learning master
            # + per-account opt-in) so we can hand it any HIPAA-
            # flagged active account here and let it short-circuit
            # when not opted in.
            try:
                if not is_auto_scan_enabled_for_account(acct):
                    counters["skipped_auto_scan_off"] += 1
                    log.info(
                        "Sent mail capture: HIPAA auto-scan off for "
                        "account",
                        account_id=acct.get("id"),
                        reason="auto_scan_enabled=false",
                    )
                    continue
                hipaa_new = await _run_hipaa_counter_for_account(
                    db, secrets, acct,
                )
                counters["hipaa_counter_recorded"] += int(hipaa_new or 0)
            except Exception as hipaa_err:
                counters["errors"] += 1
                err_text = scrub_error_for_persist(hipaa_err)  # run13 #2
                log.warning(
                    "HIPAA sent counter: sweep failed for account",
                    account_id=acct.get("id"),
                    error=err_text,
                )
            continue
        if not is_auto_scan_enabled_for_account(acct):
            counters["skipped_auto_scan_off"] += 1
            log.info(
                "Sent mail capture: auto-scan off for account",
                account_id=acct.get("id"),
                reason="auto_scan_enabled=false",
            )
            continue
        try:
            if not await db_call(
                is_rag_sent_index_enabled, db, acct["id"], account=acct,
            ):
                continue
        except Exception:
            continue

        # census run17  — resolve via the account_email SSOT (not the
        # open-coded materialized key) so a non-loader-built dict still
        # resolves; local renamed off the SSOT name to avoid shadowing it.
        from email_triage.db.accounts import account_email
        acct_email = account_email(acct)
        try:
            from email_triage.web.routers.ui import (
                _create_provider_from_account,
            )
            provider = _create_provider_from_account(acct, secrets)
        except Exception as e:
            counters["errors"] += 1
            log.warning(
                "Sent mail capture: provider build failed",
                account_id=acct.get("id"),
                error=fmt_exc(e),
            )
            #  — @db_write helper; route through db_call so it
            # runs off the event loop under the DB lock. census run17 #3 —
            # via safe_audit_write_async so a failed audit emit is logged
            # (visible to /health's drift counter), not silently swallowed.
            await safe_audit_write_async(
                lambda: db_call(
                    record_auth_event,
                    db,
                    event_type="sent_mail_capture",
                    email=acct_email,
                    outcome="failure",
                    detail=f"provider_build: {scrub_error_for_persist(e)[:200]}",
                ),
                description="sent_mail_capture provider_build outcome=failure",
            )
            continue

        # 2026-05-11 — per-account sent-folder override (set via
        # /profile/style-data). Now a list[str] (one or more folders
        # the operator wants the AI to fan learning across) — empty
        # list falls through to the provider's default Sent path
        # (Gmail in:sent, O365 sentitems, IMAP whatever folder the
        # watcher SELECTed). Legacy scalar string shape is tolerated
        # via ``normalize_sent_folder_override`` even on installs that
        # haven't run migration v19 yet.
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        _acct_cfg = acct.get("config") or {}
        _sent_overrides = normalize_sent_folder_override(
            _acct_cfg.get("sent_folder_override"),
        )

        try:
            try:
                index = SentMailIndex(
                    db, acct["id"],
                    embedding_backend=backend,
                    embedding_model=embedding_model,
                    provider=provider,
                    sqlite_vec_available=sqlite_vec_available,
                    sent_folders=_sent_overrides,
                )
            except NonLocalBackendError:
                # Operator switched to a non-local embedding backend
                # mid-flight. Defence in depth: silently skip; M-4 is
                # local-only by design.
                counters["skipped_no_backend"] += 1
                continue

            loop = SentMailCaptureLoop(
                db, acct["id"],
                provider=provider,
                sent_mail_index=index,
                sent_folders=_sent_overrides,
            )
            # auth_stale lifecycle SSOT funnel (census 2026-06-09 #1) — late
            # import to avoid the web/app.py import cycle.
            from email_triage.web.app import record_provider_outcome
            try:
                captured = await loop.scan_recent(limit=50)
            except Exception as scan_err:
                counters["errors"] += 1
                err_text = scrub_error_for_persist(scan_err)  # run13 #2 — audit detail (both legs)
                log.warning(
                    "Sent mail capture: scan failed",
                    account_id=acct.get("id"),
                    error=err_text,
                )
                #  — @db_write helper; route through db_call.
                # census run17 #3 — via safe_audit_write_async (never-raise
                # + WARN on failure, no longer a silent swallow).
                await safe_audit_write_async(
                    lambda: db_call(
                        record_auth_event,
                        db,
                        event_type="sent_mail_capture",
                        email=acct_email,
                        outcome="failure",
                        detail=err_text[:400],
                    ),
                    description="sent_mail_capture scan outcome=failure",
                )
                # Auth-revoked sent-scan failure → surface the re-auth chip
                # (needle-filtered, so a transient error is ignored). The
                # sent-mail-capture path previously set nothing. Census #1.
                try:
                    await db_call(record_provider_outcome, db, acct, scan_err)
                except Exception:
                    pass
                continue

            counters["captured_total"] += int(captured or 0)
            # Sent-folder scan succeeded → the credential is alive; clear any
            # prior auth_stale chip (idempotent-cheap; outside the scan
            # try/except so its own db_call can't be mis-recorded as a scan
            # failure; wrapped to match the failure sites). Census 2026-06-09 #1.
            try:
                await db_call(record_provider_outcome, db, acct, None)
            except Exception:
                pass
            #  — @db_write helper; route through db_call.
            # census run17 #3 — via safe_audit_write_async (never-raise +
            # WARN on failure, no longer a silent swallow).
            await safe_audit_write_async(
                lambda: db_call(
                    record_auth_event,
                    db,
                    event_type="sent_mail_capture",
                    email=acct_email,
                    outcome="success",
                    detail=f"count={int(captured or 0)}",
                ),
                description="sent_mail_capture scan outcome=success",
            )
            log.info(
                "Sent mail capture sweep complete for account",
                account_id=acct.get("id"),
                captured=int(captured or 0),
            )
        finally:
            try:
                await provider.close()
            except Exception:
                pass

    return counters


async def _run_hipaa_counter_for_account(
    db: sqlite3.Connection,
    secrets: Any,
    acct: dict,
) -> int:
    """Run one tick of :class:`HipaaSentCounterLoop` for a HIPAA account.

    Sister to the non-HIPAA branch in :func:`_run_sent_mail_capture_sweep`
    but with the body-aware steps stripped out — no embedding backend
    needed, no :class:`SentMailIndex`, no RAG opt-in check. The loop's
    own gates (per-account style-learning + master) decide whether to
    do work; this helper just supplies the plumbing (provider build,
    sent-folder override, audit row).

    Returns the number of NEW outbound messages recorded into the
    counters this tick.

    Errors are captured + logged + recorded as ``auth_events``
    ``event_type="hipaa_sent_counter"`` with ``outcome="failure"`` so
    the operator can see them on /admin/audit. Successes also write
    an event row with ``count=N`` so the daily-health email can
    surface counter-loop health alongside the existing capture-loop
    health.
    """
    from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
    from email_triage.providers.sent_folder import (
        normalize_sent_folder_override,
    )
    from email_triage.web.db import record_auth_event
    #  — ``async def`` helper: route the @db_write record_auth_event
    # through db_call so the audit write runs off the event loop under
    # the process-wide DB lock.
    from email_triage.web.db_threadpool import db_call
    # census run17 #3 — best-effort audit-emit SSOT (never-raise + WARN
    # so a swallowed audit failure stays visible to /health's drift
    # counter); the async sibling wraps the ``await db_call`` seam.
    from email_triage.web._audit import safe_audit_write_async
    # N-67 — auth_stale lifecycle SSOT funnel (mirrors the non-HIPAA
    # _run_sent_mail_capture_sweep twin): wire both the scan failure edge
    # (auth-revoked token → SET the chip) and the success edge (clear it),
    # so a dead OAuth token on a HIPAA mailbox surfaces as auth_stale
    # instead of staying invisible. Late import to avoid the web/app.py
    # import cycle (same pattern as the non-HIPAA twin at line ~1321).
    from email_triage.web.app import record_provider_outcome

    # census run17  — resolve via the account_email SSOT (see twin above).
    from email_triage.db.accounts import account_email
    acct_email = account_email(acct)
    try:
        from email_triage.web.routers.ui import _create_provider_from_account
        provider = _create_provider_from_account(acct, secrets)
    except Exception as e:
        log.warning(
            "HIPAA sent counter: provider build failed",
            account_id=acct.get("id"),
            error=fmt_exc(e),
        )
        await safe_audit_write_async(
            lambda: db_call(
                record_auth_event,
                db,
                event_type="hipaa_sent_counter",
                email=acct_email,
                outcome="failure",
                detail=f"provider_build: {scrub_error_for_persist(e)[:200]}",
            ),
            description="hipaa_sent_counter provider_build outcome=failure",
        )
        return 0

    _acct_cfg = acct.get("config") or {}
    _sent_overrides = normalize_sent_folder_override(
        _acct_cfg.get("sent_folder_override"),
    )

    try:
        loop = HipaaSentCounterLoop(
            db, acct["id"],
            provider=provider,
            secrets=secrets,
            sent_folders=_sent_overrides,
        )
        try:
            new_count = await loop.scan_recent(limit=50)
        except Exception as scan_err:
            err_text = scrub_error_for_persist(scan_err)  # run13 #2
            log.warning(
                "HIPAA sent counter: scan failed",
                account_id=acct.get("id"),
                error=err_text,
            )
            await safe_audit_write_async(
                lambda: db_call(
                    record_auth_event,
                    db,
                    event_type="hipaa_sent_counter",
                    email=acct_email,
                    outcome="failure",
                    detail=err_text[:400],
                ),
                description="hipaa_sent_counter scan outcome=failure",
            )
            # N-67 — auth-revoked scan failure → surface the re-auth chip.
            # Needle-filtered (transient errors are ignored), matching the
            # non-HIPAA twin. Wrapped to not swallow the scan_err above.
            try:
                await db_call(record_provider_outcome, db, acct, scan_err)
            except Exception:
                pass
            return 0

        # N-67 — scan succeeded → the credential is alive; clear any prior
        # auth_stale chip (idempotent; same pattern as the non-HIPAA twin).
        # Outside the scan try/except so its own db_call can't be
        # mis-recorded as a scan failure.
        try:
            await db_call(record_provider_outcome, db, acct, None)
        except Exception:
            pass
        await safe_audit_write_async(
            lambda: db_call(
                record_auth_event,
                db,
                event_type="hipaa_sent_counter",
                email=acct_email,
                outcome="success",
                detail=f"recorded={int(new_count)}",
            ),
            description="hipaa_sent_counter scan outcome=success",
        )
        return int(new_count or 0)
    finally:
        try:
            await provider.close()
        except Exception:
            pass
