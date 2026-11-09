"""Push / webhook ingestion — extracted from web/app.py.

Drop-in refactor. NO semantic change. The push-ingestion cluster (the
Gmail Pub/Sub push consumer + ``_process_push_item``, the Office 365 Graph
push processor ``_process_office365_push_item``, and the Gmail watch
renewer + its sweep) moves here from ``web/app.py`` as the 3rd web/app.py
carve (after ``web/watcher.py`` + ``web/digest.py``). ``web/app.py`` keeps a
bottom re-export shim so ``from email_triage.web.app import
_process_push_item`` (test suite) + the lifespan task registration
(``_gmail_push_consumer`` / ``_gmail_watch_renewer``) resolve unchanged.

Dependency cut: the only staying-app.py dependency is ``_acct_log_extras``
(a shared log-extras formatter, 40+ consumers repo-wide) — LATE-IMPORTED
from ``email_triage.web.app`` inside the 3 functions that use it
(cycle-break: app.py re-exports the names defined here). Everything else is
a top-level stdlib/sibling import (below) or a local import already inside
the moved bodies (db helpers, provider construction, triage registry) —
self-contained. ``_TRANSIENT_FETCH`` is a function-local in
``_process_push_item``, not a module constant; it moves with the body.

The module logger keeps the ``"web.app"`` record name so existing push log
records are byte-identical post-move.

HIPAA: these consumers fetch + classify + act on live push-delivered mail
(PHI-touching), but this is pure relocation — the per-account HIPAA gate,
audit emits, and triage path are byte-identical to the web/app.py original.
§-location-agnostic; no PHI-handling semantics changed.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from fastapi import FastAPI

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import bounded_int  # N-219c/23 R23
from email_triage._isotime import to_utc_iso

#: Logger record name preserved as "web.app" for byte-identical push logs.
log = get_logger("web.app")


async def _gmail_push_consumer(app: FastAPI) -> None:
    """Drain ``app.state.push_queue`` and reconcile Gmail deltas.

    Each queue item is ``{"email", "history_id", "account_id"}``.  For
    each item we look up the stored history cursor, call
    ``list_history`` on the provider, fetch + classify + route every
    new message, and advance the cursor.

    One handler failure never kills the consumer — exceptions on a
    single item are logged and processing continues.
    """
    # Defer start so the app finishes wiring up.
    await asyncio.sleep(2)
    log.info("Gmail push consumer started")

    while True:
        try:
            item = await app.state.push_queue.get()
        except asyncio.CancelledError:
            log.info("Gmail push consumer cancelled")
            return

        try:
            # Demux by provider — Gmail items lack the "provider" key
            # (legacy shape), O365 items carry provider="office365".
            provider_kind = (
                item.get("provider") if isinstance(item, dict) else None
            )
            if provider_kind == "office365":
                await _process_office365_push_item(app, item)
            else:
                await _process_push_item(app, item)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.error(
                "Push consumer: item processing failed",
                error=fmt_exc(e),
                item=item,
            )
            # N-213b R23 (2026-07-02): route failure through the
            # WatchStatusRecorder SSOT so `/watch/status` reflects the
            # non-IMAP ingestion sibling's error state. Fail-open — a
            # None manager (test seams / boot) becomes a no-op.
            try:
                from email_triage.web._watch_status_recorder import (
                    record_message_result,
                )
                _account_id = int(item.get("account_id", 0)) if isinstance(item, dict) else 0
                _mailbox = str(item.get("mailbox", "INBOX")) if isinstance(item, dict) else "INBOX"
                _source = "o365-push" if provider_kind == "office365" else "gmail-push"
                _manager = getattr(app.state, "watcher_manager", None)
                if _account_id > 0:
                    record_message_result(
                        _manager, _account_id, _mailbox, _source,
                        success=False, error=e,
                    )
            except Exception:  # noqa: BLE001
                pass  # telemetry write must not shadow the original error
        else:
            # N-213c R23 (2026-07-02): success path — no exception raised
            # from either provider's _process_*_push_item. Record success
            # telemetry so /watch/status reflects the non-IMAP ingestion
            # sibling's healthy state (previously reported processed=0
            # regardless of throughput). Skips inside _process_push_item
            # (owner-disabled, watch-none, stale historyId) still count as
            # "success" here — they exercised the handler without erroring.
            try:
                from email_triage.web._watch_status_recorder import (
                    record_message_result,
                )
                _account_id = int(item.get("account_id", 0)) if isinstance(item, dict) else 0
                _mailbox = str(item.get("mailbox", "INBOX")) if isinstance(item, dict) else "INBOX"
                _source = "o365-push" if provider_kind == "office365" else "gmail-push"
                _manager = getattr(app.state, "watcher_manager", None)
                if _account_id > 0:
                    record_message_result(
                        _manager, _account_id, _mailbox, _source, success=True,
                    )
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                app.state.push_queue.task_done()
            except ValueError:
                pass  # Queue.task_done can raise if over-called.

async def _process_push_item(app: FastAPI, item: dict) -> None:
    """Reconcile one Pub/Sub delivery into triage actions."""
    # Late import: _acct_log_extras is a shared log-extras
    # helper (40+ consumers) that STAYS in web/app.py; importing at
    # module top would cycle (app.py re-exports the names defined
    # here). Mirrors the watcher/#277c late-import precedent.
    from email_triage.web.app import _acct_log_extras, record_provider_outcome
    from email_triage.web.db import (
        get_email_account, get_gmail_watch, update_gmail_watch_history,
        list_account_routes, record_triage_run,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _is_dry_run, _load_all_list_hints,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.providers.gmail_api import (
        GmailApiError, GmailApiProvider, GmailHistoryExpiredError,
    )
    import httpx
    from email_triage.triage_logging import account_hipaa_effective

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    account_id = item["account_id"]
    incoming_history_id = str(item["history_id"])

    #  — _process_push_item is the Gmail push consumer; it runs on
    # the event-loop thread (awaited from the push-drainer task), so
    # every shared-connection touch hops to the threadpool via db_call.
    from email_triage.web.db_threadpool import db_call

    watch = await db_call(get_gmail_watch, db, account_id)
    if watch is None:
        log.warning("Push consumer: no watch row", account_id=account_id)
        return

    # Idempotency: Pub/Sub can deliver the same historyId more than
    # once, and the webhook may enqueue multiple items during a burst.
    # Compare as ints — Gmail historyIds are monotonic integers.
    stored_hid_int = bounded_int(watch["history_id"], default=0)  # N-219c/23 R23: SSOT
    incoming_hid_int = bounded_int(incoming_history_id, default=0)  # N-219c/23 R23: SSOT
    if incoming_hid_int and incoming_hid_int <= stored_hid_int:
        log.debug(
            "Push consumer: stale historyId, skipping",
            account_id=account_id,
            stored=watch["history_id"],
            incoming=incoming_history_id,
        )
        return

    from email_triage.web.db import is_user_disabled as _iud

    # Account lookup + owner-disabled gate in one threadpool hop.
    def _push_acct_and_gate():
        a = get_email_account(db, account_id)
        if a is None:
            return None, False
        oid = a.get("user_id")
        return a, (oid is not None and _iud(db, oid))

    acct, _owner_disabled = await db_call(_push_acct_and_gate)
    if acct is None:
        log.error("Push consumer: account vanished", account_id=account_id)
        return

    # Fail-closed: skip push processing for accounts whose owner is
    # disabled. Do NOT advance the history cursor (N-62 DA HIGH-1): the
    # Gmail historyId is a WHOLE-MAILBOX watermark, so advancing it to
    # ``incoming_history_id`` on a SKIP would push the un-fetched mail of
    # THIS notification below the cursor — permanently lost (never
    # re-walked) when the owner is re-enabled. Leaving the cursor put means
    # re-enable re-walks every delta since the last REAL processed point;
    # the ``triaged_messages`` dedup no-ops anything already done, and a
    # long disable that ages out the history hits the existing
    # GmailHistoryExpiredError re-seed path. Re-walk is SAFE; advance LOSES.
    owner_id = acct.get("user_id")
    if _owner_disabled:
        log.warning(
            "Push consumer: skipping (owner disabled)",
            account_id=account_id, owner_id=owner_id,
        )
        return

    # Fail-closed is_active gate (Loop-5 census, N-62). A deactivated
    # account must not be classified/acted on. Do NOT advance the history
    # cursor (DA HIGH-1) — same whole-mailbox-watermark reasoning as the
    # owner-disabled branch above: advancing on a skip loses the mail that
    # arrived during the inactive window. Re-activation re-walks from the
    # last real processed point (dedup-safe); O365's consumer below makes
    # the same do-not-advance choice. Default True so a row missing the
    # column isn't silently paused.
    if not acct.get("is_active", True):
        log.warning(
            "Push consumer: skipping (account inactive)",
            account_id=account_id, owner_id=owner_id,
        )
        return

    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, GmailApiProvider):
        log.error(
            "Push consumer: account is not gmail_api",
            **_acct_log_extras(acct),
            provider_type=acct.get("provider_type"),
        )
        #  — close the just-built provider before the early return.
        # This return is BEFORE the try/finally that owns provider.close,
        # so without this the provider's HTTP session leaks.
        try:
            await provider.close()
        except Exception:
            pass
        return

    t0 = time.time()
    try:
        start_hid = watch["history_id"]
        try:
            delta = await provider.list_history(start_history_id=start_hid)
        except GmailHistoryExpiredError:
            # Bounded backfill: walk the last 7 days (Gmail's history
            # retention window — anything older than this is what made
            # the cursor expire in the first place) up to 200 messages.
            # Idempotency keys on each action (PR 6) prevent duplicate
            # draft_reply / move / etc. for messages we've already
            # processed under a fresher cursor.
            #
            # BACKFILL_CAP is a deliberate cap: a runaway backfill on a
            # high-volume mailbox would otherwise re-classify thousands
            # of messages and burn LLM quota. The operator can re-run a
            # full classify-from-scratch via a whole-mailbox triage if
            # they actually want everything.
            from email_triage.web._backfill_chip import (
                BACKFILL_CAP, mark_backfill_capped,
            )
            log.warning(
                "Push consumer: history_id expired, recovering via "
                "bounded backfill",
                **_acct_log_extras(acct), stale_history_id=start_hid,
            )
            #  — fetch BACKFILL_CAP+1 as a saturation PROBE.
            # ``search(limit=N)`` returns AT MOST N, so a gap of exactly
            # CAP returns CAP and lost nothing; only > CAP proves the gap
            # overflowed. Process at most CAP (the cost bound); the extra
            # probe id is covered by the chip + the operator's full
            # backfill, so dropping it here is not a new silent loss.
            probe_ids = await provider.search(
                "newer_than:7d", limit=BACKFILL_CAP + 1,
            )
            saturated = len(probe_ids) > BACKFILL_CAP
            recent_ids = probe_ids[:BACKFILL_CAP]
            delta = {
                "history": [
                    {"messagesAdded": [
                        {"message": {"id": mid}} for mid in recent_ids
                    ]}
                ] if recent_ids else [],
                "historyId": incoming_history_id,
            }
            # If the bounded walk SATURATED the cap, more mail than we
            # enumerated may sit in the gap; the cursor is about to be
            # reseeded to "now", so that excess is never re-walked. Emit a
            # DISTINCT warning + raise an operator-visible chip so the gap
            # isn't silent. A non-saturated recovery clears nothing (punch
            # 854): the 7-day walk cannot reach mail an EARLIER gap skipped,
            # so a stored chip stays until the operator's dismiss.
            if saturated:
                log.warning(
                    "Push consumer: history-expired backfill CAPPED — "
                    "older mail in the gap may be un-triaged "
                    "(history_backfill_capped)",
                    **_acct_log_extras(acct),
                    stale_history_id=start_hid,
                    recovered_count=len(recent_ids),
                    cap=BACKFILL_CAP, window="newer_than:7d",
                )
                await db_call(
                    mark_backfill_capped, db, account_id,
                    kind="gmail_history", window="last 7 days",
                    recovered=BACKFILL_CAP,
                    source_mailbox="INBOX",  # N-211c R23: Gmail push = INBOX-scope
                )
            log.info(
                "Push consumer: history-expired recovery complete",
                **_acct_log_extras(acct),
                stale_history_id=start_hid,
                recovered_count=len(recent_ids),
            )

        # The Gmail history fetch succeeded → the OAuth credential is alive;
        # clear any prior auth_stale chip here (before we branch on delta
        # contents) so BOTH the empty-delta early return below and the full
        # path clear it. The push path previously never cleared, so an account
        # the poll path had flagged stayed stuck on the re-auth chip once it
        # recovered via push (divergence census 2026-06-09, finding #1).
        await db_call(record_provider_outcome, db, acct, None)

        # Collect new message ids from the delta. Dedupe — the same
        # message can appear under both messageAdded and labelAdded
        # entries if the label filter is permissive.
        seen_ids: set[str] = set()
        message_ids: list[str] = []
        for entry in delta.get("history", []):
            for added in entry.get("messagesAdded", []) or []:
                mid = (added.get("message") or {}).get("id")
                if mid and mid not in seen_ids:
                    seen_ids.add(mid)
                    message_ids.append(mid)

        if not message_ids:
            log.info(
                "Push consumer: empty delta",
                **_acct_log_extras(acct),
                history_id=delta.get("historyId"),
            )
            await db_call(
                update_gmail_watch_history, db, account_id,
                str(delta.get("historyId") or incoming_history_id),
            )
            # N-256b R27: push consumer received + acknowledged a
            # notification → the Gmail watch is live. Clear any prior
            # errored state via the SSOT lifecycle funnel.
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=account_id, error_text=None,
            )
            return

        classifier = _build_classifier_from_config(config)
        # Gmail push delivers without a per-mailbox concept; passing
        # mailbox=None yields the account-wide route map.  per-
        # mailbox overrides fire only on the IMAP watcher path where
        # the mailbox is known.
        from email_triage.web.db import effective_routes_by_cat

        #  — categories + routes + list-hint loads are sequential
        # shared-connection reads; fold them into one threadpool hop.
        def _push_setup_reads():
            return (
                _get_categories_from_db(db, user_id=acct.get("user_id")),
                effective_routes_by_cat(db, account_id, mailbox=None),
                _load_all_list_hints(db),
            )

        categories, routes_by_cat, (_lh_lists, _lh_rules) = await db_call(
            _push_setup_reads,
        )

        #  — uniform full action set across every ingestion path.
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )

        # Calendar provider + meeting prefs (shared across the delta).
        # 2026-05-13 — surrogate-aware gate so IMAP-with-surrogate
        # accounts (Gmail surrogate routing through this Gmail push
        # consumer) correctly produce a calendar provider.
        from email_triage.web.db import (
            get_meeting_prefs as _gmp,
        )
        from email_triage.web.calendars import (
            is_calendar_effectively_enabled as _ice_eff,
        )
        from email_triage.web.routers.ui import (
            _create_calendar_provider_from_account as _ccp,
        )
        _cal_provider = None
        try:
            #  — _ice_eff / _gmp read the shared connection and
            # _ccp opens a calendar provider that reads it too; fold
            # all three into one sync closure dispatched via a single
            # db_call hop so the push consumer never blocks the loop
            # on SQLite.
            def _calendar_ctx():
                cal_provider = None
                if _ice_eff(db, acct):
                    # Pass db so IMAP-with-surrogate accounts (
                    # phase 1A++) get the surrogate's provider.
                    cal_provider = _ccp(acct, secrets, db=db)
                return cal_provider, _gmp(db, acct.get("user_id"))

            _cal_provider, _mp = await db_call(_calendar_ctx)
        except Exception:
            _mp = None
        # IMAP accounts store the address as config["username"]; use the
        # account_email SSOT (census run17 ) so loop-prevention resolves
        # for IMAP too without open-coding the materialized key.
        #  — alias-aware self-address set so action-side recipient
        # matching can take the union of primary + configured aliases.
        from email_triage.web.db import account_addresses as _aa, account_email
        _self_email = account_email(acct)
        _self_email_addresses = _aa(acct)

        results: list[dict] = []
        errors: list[dict] = []
        skipped_vanished = 0
        from email_triage.mail_headers import (
            get_triage_header as _gth, get_rfc_message_id as _grfc,
            is_self_origin as _is_self_origin,
        )
        from email_triage.web.db import is_triaged, mark_triaged
        from email_triage.web.triage_inflight import claim as _inflight_claim
        # Resolve install-wide self-from once per delta; cheap dict
        # lookup, but no point doing it per-message. ( secondary
        # check.)
        _self_from_addr = getattr(
            getattr(app.state.config, "smtp", None), "from_addr", "",
        )

        # Per-message fetch with classification of two error families:
        #   1. Race — Gmail API 404 means the message was deleted /
        #      archived / expunged by the user between the push
        #      notification firing and us calling messages.get. Benign;
        #      log INFO + skip.
        #   2. Transient network — httpx ReadTimeout / ConnectError /
        #      RemoteProtocolError / PoolTimeout / ReadError. Single
        #      retry with backoff before falling through to the
        #      generic per-message error path.
        # This single retry buys one more shot before the message
        # falls through to the per-message error path. From there
        # a durable retry-queue row is enqueued, and the
        # history cursor only advances when that enqueue succeeds
        # (see ``retry_enqueue_failed`` below) — so an exhausted
        # transient failure is NOT lost: it is either retried from the
        # queue or re-walked when the held cursor replays the delta.
        _TRANSIENT_FETCH = (
            httpx.ReadTimeout, httpx.ConnectError,
            httpx.RemoteProtocolError, httpx.PoolTimeout,
            httpx.ReadError,
        )

        async def _fetch_with_retry(_mid: str):
            """Return (message_or_None, vanished_bool).

            vanished=True signals 404-race; caller skips silently.
            On non-404 GmailApiError or final-attempt transient
            failure, the underlying exception propagates so the
            outer except records it as a per-message error.
            """
            for _attempt in range(2):
                try:
                    return (await provider.fetch_message(_mid), False)
                except GmailApiError as _e:
                    if getattr(_e, "status", None) == 404:
                        log.info(
                            "Push consumer: message vanished before "
                            "fetch (skipped — likely deleted or "
                            "archived between push and consume)",
                            **_acct_log_extras(acct),
                            message_id=_mid,
                        )
                        return (None, True)
                    raise
                except _TRANSIENT_FETCH as _e:
                    if _attempt >= 1:
                        raise
                    log.warning(
                        "Push consumer: transient fetch error, "
                        "retrying once",
                        **_acct_log_extras(acct),
                        message_id=_mid,
                        error=fmt_exc(_e),
                    )
                    await asyncio.sleep(2.0)
            # Unreachable (loop either returns or re-raises) but
            # satisfies the type checker.
            return (None, False)

        #  - the Gmail push consumer now runs the SAME per-message
        # body as every other ingestion path. durable_dedup /
        # mark_triaged_on_success stay True (the push path relied on the
        # rfc-id dedup gate before ). set_keyword_on_success is
        # False - Gmail has no IMAP keyword sentinel. It now ALSO fires
        # / rule-labels +  watches - the pre-#199 push path
        # skipped them.
        #  — both rule-label maps read the shared connection; build
        # them in one off-loop db_call hop before the TriageContext
        # ctor so the push consumer never runs SQLite on the loop.
        # R1 HIGH-1 — fold _is_dry_run into the same hop so the ctor's
        # dry_run= argument no longer hits SQLite on the event loop.
        def _rule_label_maps():
            return (
                _build_rule_labels_map(db),
                _build_rule_provider_labels_map(db),
                _is_dry_run(db),
            )

        (
            _rule_labels_map,
            _rule_provider_labels_map,
            _dry_run,
        ) = await db_call(_rule_label_maps)
        _push_ctx = TriageContext(
            db=db, config=config, secrets=secrets, acct=acct,
            classifier=classifier, provider=provider, registry=registry,
            categories=categories,
            routes_by_cat=routes_by_cat,
            list_hints_lists=_lh_lists,
            list_hints_rules_by_list=_lh_rules,
            rule_labels_map=_rule_labels_map,
            rule_provider_labels_map=_rule_provider_labels_map,
            calendar_provider=_cal_provider,
            meeting_prefs=_mp,
            self_email=_self_email,
            self_email_addresses=set(_self_email_addresses),
            account_addrs=list(_self_email_addresses),
            self_from_addr=_self_from_addr,
            dry_run=_dry_run,
            account_hipaa=account_hipaa_effective(account=acct),
            actor_user_id=None,
            durable_dedup=True,
            mark_triaged_on_success=True,
            set_keyword_on_success=False,
            fire_watches=True,
        )
        #  — when a per-message failure cannot be durably enqueued
        # for retry, the history cursor must NOT advance past this
        # delta: Gmail Pub/Sub does not redeliver an advanced cursor,
        # so an un-enqueued failure would lose the message forever.
        # The next webhook re-walks the same range; the dedup table
        # catches the messages we already processed.
        retry_enqueue_failed = False
        for mid in message_ids:
            # In-flight dedup gate. The IMAP watcher and this
            # push consumer can race on the same UID/message-id when
            # a Gmail history delta arrives while an aioimaplib watch
            # cycle is mid-fetch.
            with _inflight_claim(app.state, account_id, mid) as _won:
                if not _won:
                    log.info(
                        "Skipping concurrent triage cycle (in_flight)",
                        message_id=mid, account_id=account_id,
                        skip_reason="in_flight",
                    )
                    continue
                try:
                    message, _vanished = await _fetch_with_retry(mid)
                    if _vanished:
                        skipped_vanished += 1
                        continue
                    _res = await triage_single_message(
                        _push_ctx, message, mid,
                    )
                    if _res.status == "e":
                        # Route the error through the existing per-message
                        # except so the retry-queue enqueue fires unchanged.
                        raise RuntimeError(
                            _res.entry.get("error", "triage error")
                        )
                    #  — Gmail push site watch-fire delivery retry.
                    if _res.unretried_watch_failures > 0:
                        try:
                            from email_triage.web.watcher_retry import (
                                enqueue_watch_delivery_retry as _wdr,
                            )
                            await db_call(
                                _wdr,
                                app.state.db,
                                account_id=int(account_id),
                                provider_type=acct.get(
                                    "provider_type", "gmail_api",
                                ),
                                failed_count=_res.unretried_watch_failures,
                                total_count=len(
                                    _res.entry.get("watches_fired") or []
                                ),
                                gmail_msg_id=str(mid),
                            )
                        except Exception as exc:
                            # #8: a failed enqueue means the
                            # undelivered watch is NOT queued for re-fire — surface
                            # it (fail VISIBLE, PD#8) rather than silently swallow.
                            log.warning(
                                "watch-delivery retry enqueue FAILED (gmail push) "
                                "— the undelivered watch is NOT queued for re-fire",
                                gmail_msg_id=str(mid),
                                error=fmt_exc(exc),
                            )
                    results.append(_res.entry)
                except Exception as e:
                    errors.append({"message_id": mid, "error": fmt_exc(e)})
                    log.error(
                        "Push consumer: per-message error",
                        **_acct_log_extras(acct), message_id=mid,
                        error=fmt_exc(e),
                    )
                    #  — an LLM-unreachable failure must stamp
                    # ``failure_kind='llm_unreachable'`` so the retry
                    # drainer's LLM-breaker gate can skip the doomed
                    # classify round-trip while the breaker is open.
                    # triage_single_message re-raises
                    # LLMBackendUnreachableError unchanged, so the bare
                    # ``except`` here receives the real exception type.
                    from email_triage.llm_health import (
                        LLMBackendUnreachableError,
                    )
                    _is_llm_down = isinstance(e, LLMBackendUnreachableError)
                    # Durable per-message retry queue. Gmail push site:
                    # pass the gmail message id as the addressing tuple.
                    # Auth-revoked -> enqueue + immediately dead.
                    _enqueued = False
                    try:
                        from email_triage.web.watcher_retry import (
                            enqueue_watcher_retry as _wr_enqueue_g,
                        )
                        #  — enqueue_watcher_retry writes a retry row on
                        # the shared connection; dispatch off the push
                        # consumer's loop thread via db_call.
                        _rid = await db_call(
                            _wr_enqueue_g,
                            app.state.db,
                            account_id=int(account_id),
                            provider_type=acct.get(
                                "provider_type", "gmail_api",
                            ),
                            gmail_msg_id=str(mid),
                            error=e,
                            failure_kind=(
                                "llm_unreachable" if _is_llm_down else None
                            ),
                        )
                        _enqueued = _rid is not None
                    except Exception:
                        _enqueued = False
                    if not _enqueued:
                        #  — hold the cursor back so this delta is
                        # re-walked on the next webhook.
                        retry_enqueue_failed = True
                        log.warning(
                            "Push consumer: retry enqueue failed — "
                            "history cursor will not advance this delta",
                            **_acct_log_extras(acct), message_id=mid,
                        )

        elapsed = time.time() - t0
        from email_triage._ids import new_run_id
        run_id = new_run_id("push", account_id)
        #  tail — route through the `complete_triage_run` SSOT so this
        # Gmail-push terminal RECORDS the run row AND EMITS the
        # `et_triage_runs_total{trigger,outcome}` counter AND fires the
        # outbound webhook in one call. Pre-fix, `record_triage_run` +
        # `fire_triage_completed` were called separately and the counter
        # never fired for gmail-push — Prometheus IS-activity-review
        # (§164.308(a)(1)(ii)(D)) silently under-reported.
        dispatcher = getattr(app.state, "event_dispatcher", None)
        from email_triage.web.events import complete_triage_run
        try:
            await complete_triage_run(
                dispatcher, db, config, acct,
                run_id=run_id,
                query="gmail_push",
                trigger="push",
                total_messages=len(message_ids),
                results=results,
                errors=errors,
                elapsed_secs=elapsed,
            )
        except Exception as _e:
            log.warning(
                "push: complete_triage_run outer (webhook/emit) failed",
                error=str(_e),
            )

        # Advance cursor to the latest historyId from the delta —
        # UNLESS a per-message failure could not be durably enqueued
        # for retry. Holding the cursor lets the next webhook
        # re-walk the same range; the dedup table no-ops messages we
        # already processed.
        final_hid = str(delta.get("historyId") or incoming_history_id)
        if retry_enqueue_failed:
            log.warning(
                "Push consumer: NOT advancing history cursor — a retry "
                "enqueue failed this delta; next webhook will re-walk",
                **_acct_log_extras(acct),
                held_history_id=final_hid,
            )
        else:
            await db_call(update_gmail_watch_history, db, account_id, final_hid)
            # N-256b R27: main push-consumer success path — messages
            # processed + cursor advanced → clear any prior errored
            # watch state via the SSOT.
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=account_id, error_text=None,
            )

        log.info(
            "Push consumer: processed delta",
            **_acct_log_extras(acct),
            messages=len(message_ids),
            errors=len(errors),
            vanished=skipped_vanished,
            history_id=final_hid,
            cursor_advanced=not retry_enqueue_failed,
            elapsed=f"{elapsed:.1f}s",
        )
    except Exception as _push_exc:
        # An auth-revoked failure on the push path must surface the re-auth
        # chip — the push consumer previously set nothing, so a dead OAuth
        # token looked healthy ("Watching") instead of "Re-authenticate
        # required". Record (needle-filtered, so a transient/5xx error is
        # ignored) then re-raise so the caller's retry/error handling is
        # unchanged. Census 2026-06-09 #1.
        try:
            await db_call(record_provider_outcome, db, acct, _push_exc)
        except Exception:
            pass
        # Census run23 #1 — mirror the SET half of the lifecycle SSOT the
        # sibling renewer failure branches at :1494 already wire. Pre-fix
        # the auth_stale chip flipped but `gmail_watches.status` stayed
        # 'active' on /health for hours until the next renewer sweep.
        try:
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=account_id, error_text=fmt_exc(_push_exc),
            )
        except Exception:
            pass
        raise
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        # Close the calendar provider if we opened one for invite/suggest
        # actions. Defined inside the success branch above; may not exist
        # if we returned early on the empty-delta path.
        _cp = locals().get("_cal_provider")
        if _cp is not None:
            try:
                await _cp.close()
            except Exception:
                pass

async def _process_office365_push_item(app: FastAPI, item: dict) -> None:
    """Reconcile one Microsoft Graph subscription notification.

    Item shape::

        {"provider":"office365", "account_id":int,
         "subscription_id":str, "resource":str, "change_type":str,
         "message_id":str}

    Strategy: walk the Graph delta feed for the account's Inbox using
    the stored ``@odata.deltaLink`` cursor (same role as Gmail's
    ``history_id``), fetch each new message, classify, and run the
    action chain. Bundle F-followup F-3 brought this to parity with
    the Gmail push consumer — the previous scaffold deferred the
    actual fetch+classify to a poll-kick.

    Why delta-walk instead of the per-message ``message_id`` from
    the webhook payload? Graph's notification batches can carry
    multiple resources; relying on the delta cursor means duplicate
    deliveries (Graph retries on any non-2xx) are absorbed by the
    cursor, and a missed delivery is recovered on the next walk —
    same idempotency guarantee Gmail's history_id provides.
    """
    # Late import: _acct_log_extras is a shared log-extras
    # helper (40+ consumers) that STAYS in web/app.py; importing at
    # module top would cycle (app.py re-exports the names defined
    # here). Mirrors the watcher/#277c late-import precedent.
    from email_triage.web.app import _acct_log_extras, record_provider_outcome
    from email_triage.web.db import (
        get_email_account, get_o365_subscription,
        record_o365_subscription_outcome,
        record_triage_run, update_o365_subscription_delta_link,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _is_dry_run, _load_all_list_hints,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.providers.office365 import (
        Office365Provider, GraphDeltaResyncRequiredError, GraphError,
    )
    from email_triage.triage_logging import account_hipaa_effective

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    account_id = item.get("account_id")
    if not account_id:
        return

    #  — _process_office365_push_item is the O365 push consumer; it
    # runs on the event-loop thread (awaited from the push-drainer
    # task). Every shared-connection touch hops to the threadpool via
    # db_call.
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.db import is_user_disabled as _iud

    # Account lookup + owner-disabled gate + subscription row read in
    # one threadpool hop.
    def _o365_push_preamble():
        a = get_email_account(db, account_id)
        if a is None:
            return None, False, None
        oid = a.get("user_id")
        disabled = oid is not None and _iud(db, oid)
        if disabled:
            return a, True, None
        return a, False, get_o365_subscription(db, account_id)

    acct, _owner_disabled, sub_row = await db_call(_o365_push_preamble)
    if acct is None:
        log.warning(
            "Office365 push consumer: account missing",
            account_id=account_id,
        )
        return

    # Fail-closed: skip push processing for accounts whose owner is
    # disabled. Don't advance the cursor either — re-enable should
    # see the backlog.
    owner_id = acct.get("user_id")
    if _owner_disabled:
        log.warning(
            "Office365 push consumer: skipping (owner disabled)",
            account_id=account_id, owner_id=owner_id,
        )
        return

    # Fail-closed is_active gate (Loop-5 census). Mirror the owner-
    # disabled branch EXACTLY: just return, do NOT advance the delta
    # cursor. O365's delta feed is re-walked fresh on each webhook (the
    # cursor is NOT advanced on skip — see the owner-disabled comment
    # above and the module docstring), and the dedup table catches any
    # message already processed under a fresher cursor — so leaving the
    # cursor put means re-activation re-discovers the backlog cleanly.
    # This is the deliberate ASYMMETRY with the Gmail consumer above
    # (Gmail advances; O365 does not) — each mirrors ITS OWN provider's
    # owner-disabled handling. Default True so a missing column doesn't
    # silently pause the account.
    if not acct.get("is_active", True):
        log.warning(
            "Office365 push consumer: skipping (account inactive)",
            account_id=account_id, owner_id=owner_id,
        )
        return

    stored_delta_link = (
        (sub_row or {}).get("delta_link") if sub_row else None
    )

    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, Office365Provider):
        log.error(
            "Office365 push consumer: account is not office365",
            **_acct_log_extras(acct),
            provider_type=acct.get("provider_type"),
        )
        #  — close the just-built provider before the early return.
        # This return is BEFORE the try/finally that owns provider.close,
        # so without this the provider's HTTP session leaks.
        try:
            await provider.close()
        except Exception:
            pass
        return

    t0 = time.time()
    _cal_provider = None
    try:
        # Walk the delta feed. Resync (410 / "resyncRequired") falls
        # back to a bounded backfill — same shape as Gmail's
        # GmailHistoryExpiredError path. The bound (200 most recent)
        # caps LLM cost on a stale cursor; the dedup table catches
        # any messages already processed under a fresher cursor.
        next_delta_link: str = ""
        resync_walk_complete = False
        try:
            message_ids, next_delta_link = await provider.poll_delta(
                stored_delta_link or None,
            )
        except GraphDeltaResyncRequiredError:
            from email_triage.web._backfill_chip import (
                BACKFILL_CAP, mark_backfill_capped, probe_resync_walk,
            )
            log.warning(
                "Office365 push consumer: delta cursor expired, "
                "recovering via bounded backfill",
                **_acct_log_extras(acct),
            )
            #  — CAP+1 probe, following nextLink (punch 854): only
            # >CAP is real saturation. Process at most CAP; the probe id
            # is covered by the chip + the operator's full backfill.
            message_ids, saturated = await probe_resync_walk(provider)
            # Saturated cap ⇒ mail beyond the bound is never enumerated
            # and the cursor reseeds past it. Distinct warning + operator
            # chip. A non-saturated "ALL" walk enumerated the whole mailbox,
            # so it covers any earlier gap; the chip is cleared after the walked
            # messages are processed, below (punch 854).
            if saturated:
                log.warning(
                    "Office365 push consumer: resync backfill CAPPED — "
                    "older mail in the gap may be un-triaged "
                    "(resync_backfill_capped)",
                    **_acct_log_extras(acct),
                    recovered_count=len(message_ids), cap=BACKFILL_CAP,
                )
                await db_call(
                    mark_backfill_capped, db, account_id,
                    kind="o365_resync", window="most recent",
                    recovered=BACKFILL_CAP,
                    source_mailbox="INBOX",  # N-211c R23: O365 push = INBOX-scope
                )
            else:
                resync_walk_complete = True
            # After the backfill, kick a fresh delta walk to seed the
            # cursor for the next webhook delivery. We don't need its
            # ids (the search above already gave us recent ones), only
            # the new deltaLink.
            try:
                _, next_delta_link = await provider.poll_delta(None)
            except Exception as e:
                log.warning(
                    "Office365 push consumer: post-resync delta seed "
                    "failed (non-fatal)",
                    **_acct_log_extras(acct), error=fmt_exc(e),
                )
                next_delta_link = ""

        # The Graph delta walk succeeded → the OAuth credential is alive;
        # clear any prior auth_stale chip before branching on delta contents
        # (covers the empty-delta early return below and the full path). The
        # O365 push path previously never cleared. Census 2026-06-09 #1.
        await db_call(record_provider_outcome, db, acct, None)
        # N-69 — delta walk succeeded → clear the subscription status to
        # 'active'. Before this, a subscription that had previously errored
        # (e.g. during renewal) stayed 'errored' on /health even after the
        # first successful push delivery, because no success path cleared it.
        try:
            await db_call(
                record_o365_subscription_outcome,
                db,
                account_id=account_id,
                error_text=None,
            )
        except Exception:
            pass

        if not message_ids:
            log.info(
                "Office365 push consumer: empty delta",
                **_acct_log_extras(acct),
            )
            if next_delta_link:
                await db_call(
                    update_o365_subscription_delta_link,
                    db, account_id=account_id,
                    delta_link=next_delta_link,
                )
            return

        classifier = _build_classifier_from_config(config)
        # O365 push delivers without a per-mailbox concept; passing
        # mailbox=None yields the account-wide route map.
        from email_triage.web.db import effective_routes_by_cat

        #  — categories + routes loads fold into one threadpool hop.
        def _o365_setup_reads():
            return (
                _get_categories_from_db(db, user_id=acct.get("user_id")),
                effective_routes_by_cat(db, account_id, mailbox=None),
            )

        categories, routes_by_cat = await db_call(_o365_setup_reads)

        #  /  — uniform full action set across every ingestion
        # path. Before  this consumer hand-built a bare 8-action
        # registry (no AddLabel / SelfSentEvent); now it shares the
        # standard registry with every other path.
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )

        # Calendar provider + meeting prefs (shared across the delta).
        # 2026-05-13 — surrogate-aware gate; see commit "fix(calendar):
        # surrogate-aware enable check at every dispatch site".
        from email_triage.web.db import (
            get_meeting_prefs as _gmp,
        )
        from email_triage.web.calendars import (
            is_calendar_effectively_enabled as _ice_eff,
        )
        from email_triage.web.routers.ui import (
            _create_calendar_provider_from_account as _ccp,
        )
        _cal_provider = None
        try:
            #  — _ice_eff / _gmp read the shared connection and
            # _ccp opens a calendar provider that reads it too; fold
            # all three into one off-loop db_call hop. The closure
            # always returns a provider value (None when calendar is
            # disabled) — the old inline form left _cal_provider
            # undefined on the disabled branch, a latent NameError at
            # the TriageContext ctor below.
            def _calendar_ctx():
                cal_provider = None
                if _ice_eff(db, acct):
                    cal_provider = _ccp(acct, secrets, db=db)
                return cal_provider, _gmp(db, acct.get("user_id"))

            _cal_provider, _mp = await db_call(_calendar_ctx)
        except Exception:
            _mp = None
        # census run17  — account_email SSOT, not the open-coded key.
        #  — alias-aware self-address set so action-side recipient
        # matching takes the union of primary + configured aliases.
        from email_triage.web.db import account_addresses as _aa, account_email
        _self_email = account_email(acct)
        _self_email_addresses = _aa(acct)
        #  secondary self-skip — install-wide self-from address.
        _self_from_addr = getattr(
            getattr(app.state.config, "smtp", None), "from_addr", "",
        )

        results: list[dict] = []
        errors: list[dict] = []
        from email_triage.web.triage_inflight import claim as _inflight_claim
        #  — the O365 Graph-push consumer now runs the SAME
        # per-message body as every other ingestion path
        # (triage_single_message / ). Before  it ran a
        # hand-rolled classify→act loop that silently DROPPED
        # / rule-labels,  watches,  durable
        # idempotency and  stop-on-failure — the exact feature
        # drift  was created to kill. durable_dedup /
        # mark_triaged_on_success stay True (the push path relied on
        # the rfc-id dedup gate before ); set_keyword_on_success
        # is False — Graph has no IMAP keyword sentinel.
        #  — both rule-label maps read the shared connection; build
        # them in one off-loop db_call hop before the TriageContext
        # ctor so the push consumer never runs SQLite on the loop.
        # R1 HIGH-1 — fold _load_all_list_hints + _is_dry_run into the
        # SAME hop so the list-rule preload (/ — early-returns
        # on None list_hints_rules_by_list, so it MUST land here) and
        # the ctor's dry_run= argument no longer hit SQLite on the
        # event loop. Replaces the previous raw `_load_all_list_hints`
        # call directly before this hop + the raw `_is_dry_run` in the
        # ctor.
        def _rule_label_maps():
            return (
                _build_rule_labels_map(db),
                _build_rule_provider_labels_map(db),
                _load_all_list_hints(db),
                _is_dry_run(db),
            )

        (
            _rule_labels_map,
            _rule_provider_labels_map,
            _lh_pair,
            _dry_run,
        ) = await db_call(_rule_label_maps)
        _lh_lists, _lh_rules = _lh_pair
        _push_ctx = TriageContext(
            db=db, config=config, secrets=secrets, acct=acct,
            classifier=classifier, provider=provider, registry=registry,
            categories=categories,
            routes_by_cat=routes_by_cat,
            list_hints_lists=_lh_lists,
            list_hints_rules_by_list=_lh_rules,
            rule_labels_map=_rule_labels_map,
            rule_provider_labels_map=_rule_provider_labels_map,
            calendar_provider=_cal_provider,
            meeting_prefs=_mp,
            self_email=_self_email,
            self_email_addresses=set(_self_email_addresses),
            account_addrs=list(_self_email_addresses),
            self_from_addr=_self_from_addr,
            dry_run=_dry_run,
            account_hipaa=account_hipaa_effective(account=acct),
            actor_user_id=None,
            durable_dedup=True,
            mark_triaged_on_success=True,
            set_keyword_on_success=False,
            fire_watches=True,
        )
        #  — when a per-message failure cannot be durably enqueued
        # for retry, the delta_link cursor must NOT advance: an
        # un-enqueued failure would never be re-walked. Holding the
        # cursor lets the next webhook re-walk; the dedup table no-ops
        # the messages already processed.
        retry_enqueue_failed = False
        for mid in message_ids:
            # In-flight dedup gate — the push consumer and the
            # unified poll loop can race on the same Graph message id.
            with _inflight_claim(app.state, account_id, mid) as _won:
                if not _won:
                    log.info(
                        "Skipping concurrent triage cycle (in_flight)",
                        message_id=mid, account_id=account_id,
                        skip_reason="in_flight",
                    )
                    continue
                try:
                    # 404 means the message was deleted between the delta
                    # walk + the per-message fetch — common when an
                    # operator clears their Inbox while the webhook is
                    # in flight. Mirror Gmail's vanished-message handling:
                    # log + skip, don't fail the whole delta.
                    try:
                        message = await provider.fetch_message(mid)
                    except GraphError as ge:
                        if ge.status == 404:
                            log.info(
                                "Office365 push: message vanished before "
                                "fetch (404)",
                                **_acct_log_extras(acct),
                                message_id=mid,
                            )
                            continue
                        raise
                    _res = await triage_single_message(
                        _push_ctx, message, mid,
                    )
                    if _res.status == "e":
                        # Route the error through the per-message except so
                        # the retry-queue enqueue fires unchanged.
                        raise RuntimeError(
                            _res.entry.get("error", "triage error")
                        )
                    #  — O365 push site watch-fire delivery retry.
                    if _res.unretried_watch_failures > 0:
                        try:
                            from email_triage.web.watcher_retry import (
                                enqueue_watch_delivery_retry as _wdr,
                            )
                            await db_call(
                                _wdr,
                                app.state.db,
                                account_id=int(account_id),
                                provider_type=acct.get(
                                    "provider_type", "office365",
                                ),
                                failed_count=_res.unretried_watch_failures,
                                total_count=len(
                                    _res.entry.get("watches_fired") or []
                                ),
                                o365_msg_id=str(mid),
                            )
                        except Exception as exc:
                            # #8: a failed enqueue means the
                            # undelivered watch is NOT queued for re-fire — surface
                            # it (fail VISIBLE, PD#8) rather than silently swallow.
                            log.warning(
                                "watch-delivery retry enqueue FAILED (o365 push) "
                                "— the undelivered watch is NOT queued for re-fire",
                                o365_msg_id=str(mid),
                                error=fmt_exc(exc),
                            )
                    results.append(_res.entry)
                except Exception as e:
                    errors.append({"message_id": mid, "error": fmt_exc(e)})
                    log.error(
                        "Office365 push consumer: per-message error",
                        **_acct_log_extras(acct),
                        message_id=mid, error=fmt_exc(e),
                    )
                    #  — stamp ``failure_kind='llm_unreachable'`` on an
                    # LLM-unreachable failure so the retry drainer's
                    # LLM-breaker gate engages. triage_single_message
                    # re-raises LLMBackendUnreachableError unchanged.
                    from email_triage.llm_health import (
                        LLMBackendUnreachableError,
                    )
                    _is_llm_down = isinstance(e, LLMBackendUnreachableError)
                    # Durable per-message retry queue. O365 push site:
                    # pass the Graph resource id as the addressing tuple.
                    # Auth-revoked → enqueue + dead.
                    _enqueued_o = False
                    try:
                        from email_triage.web.watcher_retry import (
                            enqueue_watcher_retry as _wr_enqueue_o,
                        )
                        #  — enqueue_watcher_retry writes a retry row on
                        # the shared connection; dispatch off the O365 push
                        # consumer's loop thread via db_call.
                        _rid_o = await db_call(
                            _wr_enqueue_o,
                            app.state.db,
                            account_id=int(account_id),
                            provider_type=acct.get(
                                "provider_type", "office365",
                            ),
                            o365_msg_id=str(mid),
                            error=e,
                            failure_kind=(
                                "llm_unreachable" if _is_llm_down else None
                            ),
                        )
                        _enqueued_o = _rid_o is not None
                    except Exception:
                        _enqueued_o = False
                    if not _enqueued_o:
                        #  — hold the delta_link back so the next
                        # webhook re-walks this delta.
                        retry_enqueue_failed = True
                        log.warning(
                            "Office365 push consumer: retry enqueue failed — "
                            "delta_link cursor will not advance this delta",
                            **_acct_log_extras(acct), message_id=mid,
                        )

        elapsed = time.time() - t0
        from email_triage._ids import new_run_id
        run_id = new_run_id("o365_push", account_id)
        #  tail — route through the `complete_triage_run` SSOT so
        # this O365-push terminal RECORDS the run row AND EMITS the
        # `et_triage_runs_total{trigger,outcome}` counter AND fires the
        # outbound webhook in one call. Pre-fix, `record_triage_run` +
        # `fire_triage_completed` were called separately and the counter
        # never fired for o365-push — Prometheus IS-activity-review
        # (§164.308(a)(1)(ii)(D)) silently under-reported. Same-shape
        # as the Gmail push path so external integrations don't have
        # to special-case provider.
        dispatcher = getattr(app.state, "event_dispatcher", None)
        from email_triage.web.events import complete_triage_run
        try:
            await complete_triage_run(
                dispatcher, db, config, acct,
                run_id=run_id,
                query="office365_push",
                trigger="push",
                total_messages=len(message_ids),
                results=results,
                errors=errors,
                elapsed_secs=elapsed,
            )
        except Exception as _e:
            log.warning(
                "o365 push: complete_triage_run outer "
                "(webhook/emit) failed",
                error=str(_e),
            )

        # Advance cursor only after the whole delta processed —
        # mid-delta crash means the next webhook re-walks the same
        # range, the dedup table catches messages we already acted on.
        #  — also hold the cursor when a per-message failure could
        # not be durably enqueued for retry: advancing past it would
        # lose the message (the next webhook would never re-walk it).
        if next_delta_link and not retry_enqueue_failed:
            await db_call(
                update_o365_subscription_delta_link,
                db, account_id=account_id,
                delta_link=next_delta_link,
            )
        elif retry_enqueue_failed:
            log.warning(
                "Office365 push consumer: NOT advancing delta_link — a "
                "retry enqueue failed this delta; next webhook re-walks",
                **_acct_log_extras(acct),
            )

        # Punch 854: a non-saturated resync walk covers the gap only once its
        # messages were processed and every failure was durably queued.
        walk_covered = resync_walk_complete and not retry_enqueue_failed
        if walk_covered:
            from email_triage.web._backfill_chip import clear_backfill_capped
            await db_call(clear_backfill_capped, db, account_id,
                          source_mailbox="INBOX",  # N-211c R23
                          walk_kind="o365_resync")

        log.info(
            "Office365 push consumer: processed delta",
            **_acct_log_extras(acct),
            messages=len(message_ids),
            errors=len(errors),
            cursor_advanced=not retry_enqueue_failed,
            elapsed=f"{elapsed:.1f}s",
        )
    except Exception as _push_exc:
        # Auth-revoked failure on the O365 push path → surface the re-auth
        # chip (previously set nothing here). Needle-filtered; re-raise to
        # preserve the caller's handling. Census 2026-06-09 #1.
        try:
            await db_call(record_provider_outcome, db, acct, _push_exc)
        except Exception:
            pass
        # Census run23 #1 — mirror the O365 lifecycle SSOT SET half so the
        # `office365_subscriptions.status` flag flips to 'errored' on a
        # push-consumer failure. Pre-fix the auth_stale chip flipped while
        # the row stayed 'active' on /health until the next renewer sweep.
        try:
            from email_triage.web.db import record_o365_subscription_outcome
            await db_call(
                record_o365_subscription_outcome, db,
                account_id=account_id, error_text=fmt_exc(_push_exc),
            )
        except Exception:
            pass
        raise
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

async def _gmail_watch_renewer(app: FastAPI) -> None:
    """Periodically re-register Gmail watches approaching expiry.

    Gmail watches expire after ~7 days.  We renew anything expiring in
    the next 48 hours.  Re-registering is idempotent — Gmail treats it
    as extending the existing watch and returns a fresh expiration.
    """
    from email_triage.web.task_supervisor import supervised_interval_loop

    #  — lease-gated: re-registering a Gmail watch is idempotent,
    # but exactly one instance per tick is the right multi-instance
    # posture — no point N instances all renewing the same watches.
    await supervised_interval_loop(
        "gmail-watch-renewer", 30 * 60,
        lambda: _run_watch_renewal_sweep(app, window_hours=48),
        warmup_secs=30,
        startup_jitter_secs=30.0,
        lease_name="gmail-watch-renewer",
        lease_conn=app.state.db,
    )

async def _run_watch_renewal_sweep(app: FastAPI, *, window_hours: int = 48) -> None:
    """Renew any Gmail watches expiring within ``window_hours`` hours.

    Factored out for direct testability — tests can invoke this
    function without driving the sleep loop of ``_gmail_watch_renewer``.
    """
    # Late import: _acct_log_extras is a shared log-extras
    # helper (40+ consumers) that STAYS in web/app.py; importing at
    # module top would cycle (app.py re-exports the names defined
    # here). Mirrors the watcher/#277c late-import precedent.
    from email_triage.web.app import _acct_log_extras, record_provider_outcome
    from datetime import timedelta
    from email_triage.web.db import (
        list_gmail_watches_expiring, upsert_gmail_watch, get_email_account,
    )
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account
    #  — ``async def`` sweep: route every sync DB helper through
    # ``db_call`` so it runs off the event loop under the process-wide
    # DB lock instead of racing db_call workers on the shared connection.
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    now = datetime.now(timezone.utc)
    horizon = to_utc_iso(now + timedelta(hours=window_hours))
    expiring = await db_call(list_gmail_watches_expiring, db, horizon)

    if not expiring:
        return

    topic = config.push.gmail_topic_name
    if not topic:
        log.warning(
            "Watch renewer: watches expiring but gmail_topic_name unset",
            count=len(expiring),
        )
        return

    for watch in expiring:
        acct_id = watch["account_id"]
        acct = await db_call(get_email_account, db, acct_id)
        if acct is None:
            continue
        # Fail-closed is_active gate (Loop-5 census). A deactivated
        # account's Gmail watch must NOT be re-registered — re-arming the
        # push registration is exactly what would resurrect live PHI
        # ingestion for a paused account. The watch row is left intact (it
        # expires naturally on its own ~7-day clock; we just stop
        # *extending* it), so re-activation + a watcher start re-registers
        # it. Default True so a missing column never silently pauses.
        if not acct.get("is_active", True):
            log.debug(
                "Watch renewer: skipping (account inactive)",
                account_id=acct_id,
            )
            continue
        try:
            provider = _create_provider_from_account(acct, secrets)
            if not isinstance(provider, GmailApiProvider):
                continue
            # Re-fetch profile email alongside the watch register so a
            # stale / empty stored email_address gets corrected on
            # every renew. Earlier renewer just preserved the existing
            # row's email_address — once empty, always empty, and the
            # webhook lookup at /webhooks/gmail would silently miss
            # every Pub/Sub delivery for that account.
            profile_email = ""
            try:
                profile = await provider.get_profile()
                profile_email = str(profile.get("emailAddress", "")).strip()
            except Exception as e:
                log.warning(
                    "Auto-renew: profile fetch failed (non-fatal)",
                    **_acct_log_extras(acct), error=fmt_exc(e),
                )
            try:
                data = await provider.register_watch(topic)
            finally:
                try:
                    await provider.close()
                except Exception:
                    pass
            # register_watch succeeded → the OAuth credential is alive; clear
            # any prior auth_stale chip BEFORE the email-resolution branch so
            # the empty-email `continue` below also clears it. The renewer
            # previously never cleared. Census 2026-06-09 #1.
            await db_call(record_provider_outcome, db, acct, None)
            from email_triage.web.routers.ui._shared import _safe_int
            # /run18 : ``data`` is the Gmail register_watch API RESPONSE — a
            # malformed ``expiration`` must not 500 (external-API robustness). Coerce
            # via the _safe_int SSOT, not a bare int().
            exp_ms = _safe_int(data.get("expiration"), 0)
            exp_iso = to_utc_iso(datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc)) \
                if exp_ms else to_utc_iso(now + timedelta(days=7))
            # Prefer fresh profile email; fall back through stored
            # value, then config "account" key. If everything is empty
            # we'd persist "" again — log loudly so the operator can
            # re-auth instead of leaving a silently-broken row.
            cfg_email = (acct.get("config") or {}).get("account", "")
            new_email = (
                profile_email or watch.get("email_address") or cfg_email or ""
            ).strip()
            if not new_email:
                log.warning(
                    "Auto-renew: empty email_address — refusing to overwrite "
                    "watch row with blank value; re-auth the account",
                    **_acct_log_extras(acct),
                )
                continue
            await db_call(
                upsert_gmail_watch,
                db,
                account_id=acct_id,
                email_address=new_email,
                topic_name=topic,
                history_id=str(data.get("historyId") or watch["history_id"]),
                expires_at=exp_iso,
            )
            # N-256b R27: wire the gmail_watches lifecycle SSOT (N-256).
            # A successful renew clears status → 'active' + resets
            # error counters; /health reflects the live watch state.
            from email_triage.web.db import record_gmail_watch_outcome
            await db_call(
                record_gmail_watch_outcome, db,
                account_id=acct_id, error_text=None,
            )
            log.info(
                "Gmail watch renewed",
                **_acct_log_extras(acct), new_expires_at=exp_iso,
                email_refreshed=bool(profile_email),
            )
        except Exception as e:
            log.error(
                "Gmail watch renewal failed",
                **_acct_log_extras(acct), error=fmt_exc(e),
            )
            # Auth-revoked renewal failure → surface the re-auth chip (the
            # renewer previously set nothing, so a dead token on a push-only
            # account stayed invisible). Needle-filtered. Census 2026-06-09 #1.
            try:
                await db_call(record_provider_outcome, db, acct, e)
            except Exception:
                pass
            # N-256b R27: wire the gmail_watches lifecycle SSOT (N-256).
            # A failed renew bumps error_count + sets status='errored';
            # /health now surfaces this without waiting for a next tick.
            try:
                from email_triage.web.db import record_gmail_watch_outcome
                await db_call(
                    record_gmail_watch_outcome, db,
                    account_id=acct_id, error_text=fmt_exc(e),
                )
            except Exception:
                pass
