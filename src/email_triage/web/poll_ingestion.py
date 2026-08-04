"""#277d — poll-ingestion cluster carved from web/app.py (2026-05-29).

The unified push+poll ingestion loop's POLL arm: the per-provider
single-shot polls (Office 365 / Gmail / IMAP), the cadence helpers, and
the supervised loop + per-tick dispatcher. Extracted VERBATIM from
``web/app.py`` (god-module decomposition); ``web/app.py`` re-exports
every public name from its bottom shim so existing imports
(``from email_triage.web.app import _poll_once_imap`` etc. — the provider
dispatch table, the lifespan task registration, the test suite) keep
resolving unchanged.

The 4 shared ingestion helpers (``_acct_log_extras``,
``_resolve_hwm_with_uidvalidity``, ``_maybe_mark_auth_stale``,
``_clear_auth_stale``) STAY in ``web/app.py`` and are late-imported
inside the bodies that use them (cycle-break) — mirrors the
``web/watcher.py`` / ``web/ingestion_push.py`` carve precedent.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from fastapi import FastAPI

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._int_utils import parse_int_or_none  # N-219c/46 R23
from email_triage._isotime import parse_iso, parse_iso_aware, to_utc_iso  # N-316 R30 (same-hunk satellite completeness fix on N-305) + N-357 R31 (parse_iso_aware SSOT)

# #277d / PIN A — bind the SAME logger name as web/app.py and the sibling
# carves (watcher.py / ingestion_push.py / digest.py all use "web.app").
# Keeps emitted log-record logger-names byte-identical (log filters /
# the monitoring system greps keyed on logger="web.app" keep matching) AND routes through
# get_logger so the _PHI_KEYS scrubber stays engaged (§164.312(a)(2)(iv)).
log = get_logger("web.app")


async def _poll_once_office365(app: FastAPI, acct: dict) -> None:
    """Single-shot Office 365 poll: walk the Graph Inbox delta feed and
    triage every changed message.

    Before this, the dispatcher's ``_o365_poll_once`` was a ``return
    None`` stub — an O365 account added via the UI received ZERO triage,
    yet ``_run_unified_poll_tick`` recorded a poll tick regardless so
    the dashboard showed it healthily polling.

    Mirrors :func:`_process_office365_push_item` — the working Graph
    push consumer — but reads/writes the delta cursor from the
    ``office365_poll_cursor:<id>`` settings key instead of the
    ``office365_subscriptions`` row (a poll-only account has no
    subscription row). The two paths share ``provider.poll_delta`` and
    the standard ``triage_single_message`` per-message body, so a
    poll-ingested O365 message gets the exact same classify + route +
    act treatment as a push-ingested one.

    Cursor discipline matches the push path: the cursor only advances
    after the whole delta is processed AND every per-message failure
    was durably enqueued for retry — a held cursor means the next tick
    re-walks, and the dedup table no-ops anything already acted on.
    """
    # #277d late import (cycle-break): these shared ingestion helpers
    # STAY in web/app.py (used across watcher + poll + push); a module-top
    # import would cycle (app.py re-exports the names defined here).
    from email_triage.web.app import _acct_log_extras
    from email_triage.web.db import (
        get_email_account, get_setting, set_setting, record_triage_run,
        effective_routes_by_cat, account_addresses as _aa, account_email,
    )
    from email_triage.web.settings_keys import (
        office365_poll_cursor as _o365_poll_cursor_key,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _is_dry_run, _load_all_list_hints,
        _create_calendar_provider_from_account as _ccp,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.providers.office365 import (
        Office365Provider, GraphDeltaResyncRequiredError, GraphError,
    )
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.triage_inflight import claim as _inflight_claim
    # -residual — this ``async def`` poll runs on the event loop;
    # a sync DB helper called inline races ``db_call`` workers on the
    # shared ``sqlite3.Connection``. Route every shared-connection DB
    # read/write through ``db_call`` so it runs off the loop under the
    # process-wide lock.
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets
    account_id = acct["id"]

    cursor_key = _o365_poll_cursor_key(account_id)
    cursor_state = await db_call(get_setting, db, cursor_key) or {}
    stored_delta_link = cursor_state.get("delta_link") or None

    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, Office365Provider):
        log.error(
            "Office365 poll: account is not office365",
            **_acct_log_extras(acct),
            provider_type=acct.get("provider_type"),
        )
        try:
            await provider.close()
        except Exception:
            pass
        return

    t0 = time.time()
    _cal_provider = None
    try:
        # Walk the delta feed. Resync (410 / "resyncRequired") falls
        # back to a bounded backfill — same shape as the push consumer.
        next_delta_link: str = ""
        try:
            message_ids, next_delta_link = await provider.poll_delta(
                stored_delta_link,
            )
        except GraphDeltaResyncRequiredError:
            from email_triage.web._backfill_chip import (
                BACKFILL_CAP, mark_backfill_capped, clear_backfill_capped,
            )
            log.warning(
                "Office365 poll: delta cursor expired, recovering via "
                "bounded backfill",
                **_acct_log_extras(acct),
            )
            #  — CAP+1 probe (search returns ≤N; only >CAP is real
            # saturation). Process at most CAP; the probe id is covered
            # by the chip + the operator's full backfill.
            _probe_ids = await provider.search("ALL", limit=BACKFILL_CAP + 1)
            saturated = len(_probe_ids) > BACKFILL_CAP
            message_ids = _probe_ids[:BACKFILL_CAP]
            # Saturated cap ⇒ older mail in the gap is never enumerated
            # and the cursor reseeds past it. Distinct warning + operator
            # chip; clear it on a non-saturated recovery.
            if saturated:
                log.warning(
                    "Office365 poll: resync backfill CAPPED — older mail "
                    "in the gap may be un-triaged "
                    "(resync_backfill_capped)",
                    **_acct_log_extras(acct),
                    recovered_count=len(message_ids), cap=BACKFILL_CAP,
                )
                await db_call(
                    mark_backfill_capped, db, account_id,
                    kind="o365_resync", window="most recent",
                    recovered=BACKFILL_CAP,
                    source_mailbox="INBOX",  # N-211c R23: O365 delta-poll = INBOX-scope
                )
            else:
                await db_call(clear_backfill_capped, db, account_id,
                              source_mailbox="INBOX")  # N-211c R23
            try:
                _, next_delta_link = await provider.poll_delta(None)
            except Exception as e:
                log.warning(
                    "Office365 poll: post-resync delta seed failed "
                    "(non-fatal)",
                    **_acct_log_extras(acct), error=fmt_exc(e),
                )
                next_delta_link = ""

        # First-ever poll bootstrap: a fresh poll-only account has no
        # stored cursor. The delta walk above returns the full current
        # Inbox — triaging it would dump the whole backlog on first
        # tick. Mirror the IMAP/Gmail poll bootstrap: seed the cursor,
        # triage nothing this tick, pick up only NEW mail from here on.
        if stored_delta_link is None:
            if next_delta_link:
                await db_call(
                    set_setting, db, cursor_key,
                    {"delta_link": next_delta_link},
                )
            log.info(
                "Office365 poll: first tick — cursor seeded, backlog "
                "skipped",
                **_acct_log_extras(acct),
                backlog_size=len(message_ids),
            )
            return

        if not message_ids:
            if next_delta_link:
                await db_call(
                    set_setting, db, cursor_key,
                    {"delta_link": next_delta_link},
                )
            log.debug(
                "Office365 poll: empty delta",
                **_acct_log_extras(acct),
            )
            return

        classifier = _build_classifier_from_config(config)
        categories = await db_call(
            _get_categories_from_db, db, user_id=acct.get("user_id"),
        )
        routes_by_cat = await db_call(
            effective_routes_by_cat, db, account_id, mailbox=None,
        )
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )

        # Calendar provider + meeting prefs — surrogate-aware gate,
        # same as the push consumer.
        from email_triage.web.db import get_meeting_prefs as _gmp
        from email_triage.web.calendars import (
            is_calendar_effectively_enabled as _ice_eff,
        )
        try:
            if await db_call(_ice_eff, db, acct):
                _cal_provider = await db_call(_ccp, acct, secrets, db=db)
            _mp = await db_call(_gmp, db, acct.get("user_id"))
        except Exception:
            _mp = None
        # census run17  — account_email SSOT, not the open-coded key.
        _self_email = account_email(acct)
        # ``account_addresses`` only parses the in-memory acct dict —
        # no DB — so it stays a plain call.
        _self_email_addresses = _aa(acct)
        _self_from_addr = getattr(
            getattr(app.state.config, "smtp", None), "from_addr", "",
        )
        _lh_lists, _lh_rules = await db_call(_load_all_list_hints, db)
        # -residual — hoist the constructor-inline DB reads out so
        # they route through db_call.
        _rule_labels_map = await db_call(_build_rule_labels_map, db)
        _rule_provider_labels_map = await db_call(
            _build_rule_provider_labels_map, db,
        )
        _dry_run = await db_call(_is_dry_run, db)

        _poll_ctx = TriageContext(
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

        results: list[dict] = []
        errors: list[dict] = []
        #  — hold the cursor when a per-message failure can't be
        # durably enqueued; the next tick re-walks it.
        retry_enqueue_failed = False
        for mid in message_ids:
            # In-flight dedup gate — the poll loop and the push
            # consumer can race on the same Graph message id.
            with _inflight_claim(app.state, account_id, mid) as _won:
                if not _won:
                    log.info(
                        "Skipping concurrent triage cycle (in_flight)",
                        message_id=mid, account_id=account_id,
                        skip_reason="in_flight",
                    )
                    continue
                try:
                    try:
                        message = await provider.fetch_message(mid)
                    except GraphError as ge:
                        if ge.status == 404:
                            log.info(
                                "Office365 poll: message vanished before "
                                "fetch (404)",
                                **_acct_log_extras(acct), message_id=mid,
                            )
                            continue
                        raise
                    _res = await triage_single_message(_poll_ctx, message, mid)
                    if _res.status == "e":
                        raise RuntimeError(
                            _res.entry.get("error", "triage error")
                        )
                    #  — O365 poll site watch-fire delivery retry.
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
                                "watch-delivery retry enqueue FAILED (o365 poll) "
                                "— the undelivered watch is NOT queued for re-fire",
                                o365_msg_id=str(mid),
                                error=fmt_exc(exc),
                            )
                    results.append(_res.entry)
                except Exception as e:
                    errors.append({"message_id": mid, "error": fmt_exc(e)})
                    log.error(
                        "Office365 poll: per-message error",
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
                    _enqueued_o = False
                    try:
                        from email_triage.web.watcher_retry import (
                            enqueue_watcher_retry as _wr_enqueue_o,
                        )
                        # -residual — enqueue_watcher_retry wraps the
                        # @db_write enqueue_retry; route it off the loop.
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
                        retry_enqueue_failed = True
                        log.warning(
                            "Office365 poll: retry enqueue failed — poll "
                            "cursor will not advance this delta",
                            **_acct_log_extras(acct), message_id=mid,
                        )

        elapsed = time.time() - t0
        #  tail (DA F6 fold, 2026-07-11 batched-panel) — route through
        # the `complete_triage_run` SSOT so this O365-poll terminal
        # RECORDS the run row AND EMITS the `et_triage_runs_total{
        # trigger,outcome}` counter AND fires the outbound webhook in one
        # call. Pre-fix, `record_triage_run` + `fire_triage_completed`
        # were called separately here (sibling IMAP-poll at :1187 was
        # already converted per run18 census #7); the O365-poll silence
        # meant `trigger="poll"` counter under-reported for O365-poll
        # installs — analog of the pre-fix IMAP-watch / Gmail / O365
        # push silences the same drive closed. `trigger="poll"`
        # distinguishes poll-driven from push-driven completions
        # (`_poll_state_key` observability + integration compatibility).
        dispatcher = getattr(app.state, "event_dispatcher", None)
        from email_triage.web.events import complete_triage_run
        from email_triage._ids import new_run_id
        try:
            await complete_triage_run(
                dispatcher, db, config, acct,
                run_id=new_run_id("o365_poll", account_id),
                query="office365_poll",
                trigger="poll",
                total_messages=len(message_ids),
                results=results,
                errors=errors,
                elapsed_secs=elapsed,
            )
        except Exception as _e:
            log.warning(
                "o365 poll: complete_triage_run outer (webhook/emit) failed",
                error=str(_e),
            )

        # Advance the cursor only after the whole delta processed and
        # every failure was durably enqueued.
        if next_delta_link and not retry_enqueue_failed:
            await db_call(
                set_setting, db, cursor_key,
                {"delta_link": next_delta_link},
            )
        elif retry_enqueue_failed:
            log.warning(
                "Office365 poll: NOT advancing poll cursor — a retry "
                "enqueue failed this delta; next tick re-walks",
                **_acct_log_extras(acct),
            )

        log.info(
            "Office365 poll: processed delta",
            **_acct_log_extras(acct),
            messages=len(message_ids),
            errors=len(errors),
            cursor_advanced=not retry_enqueue_failed,
            elapsed=f"{elapsed:.1f}s",
        )
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

# ---------------------------------------------------------------------------
# Unified push + poll ingestion loop — POLL arm
# ---------------------------------------------------------------------------

_POLL_TICK_SECONDS = 60

_POLL_LOOP_START_DELAY_SECONDS = 45

def _poll_state_key(account_id: int) -> str:
    from email_triage.web.settings_keys import poll_state
    return poll_state(account_id)

def _effective_poll_interval_min(acct: dict, ingestion=None) -> int:
    """Return the per-account poll cadence in minutes.

    Reads ``poll_interval_minutes`` from the account config (the DB
    back-compat shim sets this for every account). Falls back to the
    install-level default, then to 60 if that's somehow unreachable.
    """
    cfg = acct.get("config") or {}
    raw = cfg.get("poll_interval_minutes")
    if isinstance(raw, int) and raw > 0:
        from email_triage.web.db import clamp_poll_interval_minutes
        return clamp_poll_interval_minutes(raw)
    if ingestion is not None:
        return int(getattr(ingestion, "default_poll_interval_minutes", 60))
    return 60

async def _unified_poll_loop(app: FastAPI) -> None:
    """Background loop: every tick, evaluate every account and dispatch
    its provider-specific poll if the cadence has elapsed.

    The loop itself is cheap (one settings read + one datetime compare
    per account per tick). The per-provider polls are also cheap when
    nothing changed.
    """
    from email_triage.web.task_supervisor import supervised_interval_loop

    #  — ported onto supervised_interval_loop. The per-tick body is
    # _run_unified_poll_tick; the helper supplies the warm-up delay, the
    # while-True scaffolding and the cancel-safe interval sleep.
    #
    # -style lease-gate: a poll sweep re-fetches mail and triages it;
    # each provider dispatch is idempotent (Gmail's consumer skips a
    # non-advancing historyId, IMAP polls by UID HWM), but exactly one
    # instance per tick is the right multi-instance posture — no point N
    # instances all polling the same mailboxes. A transparent no-op on a
    # single-instance install.
    await supervised_interval_loop(
        "unified-poll-loop", _POLL_TICK_SECONDS,
        lambda: _run_unified_poll_tick(app),
        warmup_secs=_POLL_LOOP_START_DELAY_SECONDS,
        startup_jitter_secs=30.0,
        lease_name="unified-poll-loop",
        lease_conn=app.state.db,
    )

# Back-compat alias: tests and external callers may still reference the
# old B3 name. Both point to the same coroutine.
_gmail_history_poller = _unified_poll_loop

async def _run_unified_poll_tick(app: FastAPI) -> None:
    """Evaluate every account; fire a provider-specific poll for any
    whose configured interval has elapsed since last poll.

    Extracted from the sleep loop for direct testability.
    """
    # #277d late import (cycle-break): these shared ingestion helpers
    # STAY in web/app.py (used across watcher + poll + push); a module-top
    # import would cycle (app.py re-exports the names defined here).
    from email_triage.web.app import _acct_log_extras, record_provider_outcome
    from email_triage.web.db import (
        list_email_accounts, disabled_user_ids, get_setting, set_setting,
    )
    #  — this is an ``async def`` tick: a sync DB helper called
    # directly here runs on the EVENT-LOOP thread, unlocked, and collides
    # with ``db_call`` workers on the shared ``sqlite3.Connection``.
    # Route every DB read/write through ``db_call`` so it runs off the
    # loop under the process-wide DB lock.
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    config = app.state.config
    ingestion = config.ingestion
    now = datetime.now(timezone.utc)

    watcher_mgr = getattr(app.state, "watcher_manager", None)

    # .4 — pre-fetch disabled set once per poll tick.
    accounts_for_poll = await db_call(list_email_accounts, db)
    _disabled_owners = await db_call(disabled_user_ids, db)

    for acct in accounts_for_poll:
        # Fail-closed: skip accounts whose owner is disabled.
        owner_id = acct.get("user_id")
        if owner_id is not None and owner_id in _disabled_owners:
            continue
        if not acct.get("is_active", True):
            continue
        cfg = acct.get("config") or {}
        if not cfg.get("poll_enabled", True):
            continue

        account_id = acct["id"]
        interval_min = _effective_poll_interval_min(acct, ingestion)

        # Has enough time elapsed?
        state = await db_call(get_setting, db, _poll_state_key(account_id)) or {}
        last_poll_iso = state.get("last_poll_at")
        # N-357 R31 (2026-07-05 SSOT collapse of the N-305 assume-UTC-
        # on-naive shim — sibling site to `web/auth.py` at ~L169 + ~L595).
        # Was 5 lines of inline parse + None-guard + tzinfo-assume; now
        # one `parse_iso_aware` call with the None-preservation contract
        # documented in `_isotime.parse_iso_aware`. Elapsed math on the
        # aware `now` stays valid on legacy naive `last_poll_at` rows.
        last_poll = parse_iso_aware(last_poll_iso) if last_poll_iso else None
        if last_poll is not None:
            elapsed_s = (now - last_poll).total_seconds()
            if elapsed_s < interval_min * 60:
                continue

        # Fire dispatch per provider type. Wrap each account in its own
        # try/except so one account's failure can't abort the sweep.
        #  phase 2 — table-driven dispatch via ProviderDispatcher.
        ptype = acct.get("provider_type")
        from email_triage.providers.dispatcher import get_dispatch
        disp = get_dispatch(ptype)
        try:
            if disp is None:
                log.warning(
                    "Unified poll: unknown provider type, skipping",
                    **_acct_log_extras(acct), provider_type=ptype,
                )
            elif not disp.poll_implemented:
                #  — a provider whose poll is still a stub must NOT
                # be silently ticked as healthy. (All shipped providers
                # implement poll today; this guards a future addition.)
                log.warning(
                    "Unified poll: provider poll not implemented, "
                    "skipping",
                    **_acct_log_extras(acct), provider_type=ptype,
                )
            else:
                await disp.poll_once(app, acct)
            # Successful dispatch — the credential is alive; clear any prior
            # stale-auth flag via the lifecycle SSOT funnel (census 2026-06-09
            # #1; idempotent-cheap, no write when already clear).
            #  — writes the settings table; route through db_call so the
            # delete is lock-serialised.
            await db_call(record_provider_outcome, db, acct, None)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning(
                "Unified poll: dispatch failed",
                **_acct_log_extras(acct), provider=ptype, error=fmt_exc(e),
            )
            # Detect OAuth/IMAP auth-revoked death and persist a stale-auth
            # flag (needle-filtered inside the funnel) so the UI surfaces a
            # re-auth chip and the daily health email calls it out.
            #  — writes the settings table; route through db_call.
            await db_call(record_provider_outcome, db, acct, e)
            # Census run23 #1 (borderline site — verifier flagged
            # SME-scope): the poll-mode gmail_watches / office365_subscriptions
            # rows are cursor placeholders (topic_name='') rather than live
            # push watches, but the same lifecycle status flag is the store,
            # so mirror the SET half. Both funnels no-op on a missing row
            # (SSOT docstring line 3337-3340 / O365 sibling), so
            # unconditional dispatch is safe for accounts that never had a
            # push watch or subscription registered.
            try:
                from email_triage.web.db import (
                    record_gmail_watch_outcome,
                    record_o365_subscription_outcome,
                )
                if ptype == "gmail_api":
                    await db_call(
                        record_gmail_watch_outcome, db,
                        account_id=account_id, error_text=fmt_exc(e),
                    )
                elif ptype == "office365":
                    await db_call(
                        record_o365_subscription_outcome, db,
                        account_id=account_id, error_text=fmt_exc(e),
                    )
            except Exception:
                pass

        # Record the tick regardless of dispatch outcome — a failing
        # provider shouldn't cause every tick to retry it within the
        # interval window (that would amplify a bad cred or network
        # blip into a retry storm).
        state["last_poll_at"] = to_utc_iso(now)
        #  — set_setting writes the shared connection; lock-serialise.
        await db_call(set_setting, db, _poll_state_key(account_id), state)
        if watcher_mgr is not None:
            try:
                watcher_mgr._mark_poll_tick(account_id, to_utc_iso(now))
            except Exception:
                pass

# Back-compat alias for tests and any external caller that imported the
# old name.
_run_history_poll_tick = _run_unified_poll_tick

async def _poll_once_gmail(app: FastAPI, acct: dict) -> None:
    """Single-shot Gmail poll: enqueue onto push_queue with the LIVE
    historyId so the consumer's idempotency check cleanly drops no-op
    ticks and fires a delta fetch when new mail has arrived.

    Mirrors the pre-refactor B3 behaviour; the historical mode-transition
    cadence distinction is gone, but the get_profile-then-enqueue shape
    (plus poll-mode cursor bootstrap on first ever tick) is preserved.
    """
    # #277d late import (cycle-break): these shared ingestion helpers
    # STAY in web/app.py (used across watcher + poll + push); a module-top
    # import would cycle (app.py re-exports the names defined here).
    from email_triage.web.app import _acct_log_extras
    from email_triage.web.db import (
        get_gmail_watch, upsert_gmail_watch,
    )
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account
    # -residual — this ``async def`` poll runs on the event loop;
    # a sync DB helper called inline races ``db_call`` workers on the
    # shared ``sqlite3.Connection``. Route every DB read/write through
    # ``db_call`` so it runs off the loop under the process-wide lock.
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    account_id = acct["id"]
    watch = await db_call(get_gmail_watch, db, account_id)

    provider = _create_provider_from_account(acct, app.state.secrets)
    if not isinstance(provider, GmailApiProvider):
        try:
            await provider.close()
        except Exception:
            pass
        return
    try:
        profile = await provider.get_profile()
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    live_history_id = str(profile.get("historyId", ""))
    profile_email = str(profile.get("emailAddress", ""))
    cfg_email = (acct.get("config") or {}).get("account", "")

    if watch is None:
        # First-ever poll — seed the cursor via a synthetic watch row
        # (empty topic = poll-mode). Do NOT enqueue on the bootstrap
        # tick — there's no baseline to compute a delta against.
        if live_history_id:
            await db_call(
                upsert_gmail_watch,
                db,
                account_id=account_id,
                email_address=profile_email or cfg_email,
                topic_name="",
                history_id=live_history_id,
                expires_at="1970-01-01T00:00:00+00:00",
            )
        return

    history_id = live_history_id or str(watch.get("history_id") or "")
    email = watch.get("email_address") or profile_email or cfg_email
    if not history_id:
        return

    try:
        app.state.push_queue.put_nowait({
            "email": email,
            "history_id": history_id,
            "account_id": account_id,
        })
    except asyncio.QueueFull:
        log.warning(
            "Unified poll: push_queue full, skipping tick",
            **_acct_log_extras(acct),
        )

async def _poll_once_imap(app: FastAPI, acct: dict) -> None:
    """Single-shot IMAP poll across every configured mailbox.

    For each mailbox: SELECT, SEARCH UID hwm+1:*, fetch + triage any new
    UIDs, advance the HWM. Empty search = fast no-op (the cheap safety-
    net case). Fresh accounts (hwm=0) are seeded from the current latest
    UID so we don't dump the whole backlog — matches the IDLE watcher's
    behaviour.
    """
    # #277d late import (cycle-break): these shared ingestion helpers
    # STAY in web/app.py (used across watcher + poll + push); a module-top
    # import would cycle (app.py re-exports the names defined here).
    from email_triage.web.app import _acct_log_extras, _resolve_hwm_with_uidvalidity
    from email_triage.web.db import (
        _account_mailboxes, get_mailbox_hwm, set_mailbox_hwm, make_hwm_value,
        list_account_routes,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _is_dry_run,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )
    from email_triage.triage_logging import account_hipaa_effective
    # -residual — this ``async def`` poll runs on the event loop;
    # a sync DB helper called inline races ``db_call`` workers on the
    # shared ``sqlite3.Connection``. Route every shared-connection DB
    # read/write through ``db_call`` so it runs off the loop under the
    # process-wide lock. (``_account_mailboxes`` parses the in-memory
    # acct dict — no DB — so it stays a plain call.)
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets
    account_id = acct["id"]
    cfg = acct.get("config") or {}
    mailboxes = _account_mailboxes(cfg)

    classifier = None
    categories = None
    routes_by_cat = None
    registry = None

    from email_triage.providers.base import ProviderTransientError

    for mb in mailboxes:
        provider = None
        try:
            provider = _create_provider_from_account(
                acct, secrets, mailbox_override=mb,
            )
            hwm_data = await db_call(get_mailbox_hwm, db, account_id, mb) or {}
            _had_stored_uid = bool(int(hwm_data.get("uid", 0)))
            since_uid, _live_uidvalidity = await _resolve_hwm_with_uidvalidity(
                provider, account_id, mb, hwm_data,
            )
            if _had_stored_uid and since_uid == 0:
                # UIDVALIDITY changed — re-seed to the current latest UID
                # rather than polling from 0 (which would re-triage the
                # whole mailbox backlog). New mail is picked up on the
                # next poll cycle.
                try:
                    _latest = await provider.get_latest_uid()
                except Exception:
                    _latest = 0
                await db_call(set_mailbox_hwm, db, account_id, mb,
                              make_hwm_value(_latest, _live_uidvalidity))
                # run18  — a UIDVALIDITY reseed advances the cursor past
                # every message below the new latest UID WITHOUT enumerating
                # them, so any mail that arrived in the gap is never triaged —
                # the same un-triage hazard the cursor-expiry (Gmail history /
                # O365 delta-resync) recovery path chips. The reseed branch
                # previously stayed SILENT while the cursor-expiry path raised
                # the operator chip, so a renumbered mailbox lost its backfill
                # notice. Emit the same chip here (operator action is identical:
                # run a whole-mailbox triage, then dismiss). ``recovered=0`` —
                # the reseed enumerates nothing (vs the bounded backfill that
                # walks up to BACKFILL_CAP).
                from email_triage.web._backfill_chip import mark_backfill_capped
                await db_call(
                    mark_backfill_capped, db, account_id,
                    kind="imap_uidvalidity",
                    window="mailbox renumbered — UIDVALIDITY change; reseeded to latest",
                    recovered=0,
                    source_mailbox=mb,  # N-211 R23: mailbox-scope
                )
                continue

            wm = getattr(app.state, "watcher_manager", None)
            try:
                new_messages = await provider.poll_once(mb, since_uid)
            except ProviderTransientError as e:
                # PR 7 / C3 — broken provider, NOT a quiet mailbox.
                # Bump the watcher state so /health surfaces it after
                # 15 min of consecutive failure (matches the C1 plumbing
                # used by IDLE watchers). Do NOT update HWM, do NOT
                # record a triage_run with zero messages. Via the
                # lifecycle funnel (census #7) so set/clear stay symmetric.
                if wm is not None:
                    wm.record_mailbox_outcome(
                        account_id, mb, sticky_error=e,
                    )
                log.warning(
                    "Unified poll: provider transient error",
                    **_acct_log_extras(acct), mailbox=mb,
                    error=fmt_exc(e),
                )
                continue
            # poll_once succeeded → the mailbox connection + credential are
            # alive. Clear any prior failing_since via the SAME lifecycle
            # funnel (census #7): the poll path previously SET on a transient
            # error but never CLEARED on success, so a recovered poll-only
            # mailbox stayed "failing" on /health (past the 15-min threshold)
            # until a process restart. Both edges are now symmetric.
            if wm is not None:
                wm.record_mailbox_outcome(
                    account_id, mb, sticky_error=None,
                )

            # N-198 R21_6 (2026-07-02): backfill-chip lifecycle symmetry —
            # SET on UIDVALIDITY reseed at :790, CLEAR here on any
            # subsequent successful poll (chip meant "we hit BACKFILL_CAP
            # or reseeded"; a poll landing means we're processing normally
            # again). Mirror the failing_since set-broad/clear-narrow fix
            # (census #7) — both edges of a status flag route through the
            # SAME lifecycle funnel. Idempotent: clear when unset is a
            # no-op DELETE.
            try:
                from email_triage.web._backfill_chip import clear_backfill_capped
                # N-211 R23: mailbox-scope; sibling mailbox's chip preserved.
                await db_call(clear_backfill_capped, db, account_id,
                              source_mailbox=mb)
            except Exception:  # pragma: no cover — non-decisional telemetry
                pass

            if not new_messages:
                # Cheap no-op case — no new mail. Seed HWM on first poll
                # of a fresh mailbox so subsequent polls don't dump the
                # backlog.
                if since_uid == 0:
                    try:
                        latest = await provider.get_latest_uid()
                        if latest > 0:
                            await db_call(
                                set_mailbox_hwm, db, account_id, mb,
                                make_hwm_value(latest, _live_uidvalidity),
                            )
                    except Exception:
                        pass
                continue

            # Lazy-build the classifier + action registry only once per
            # account (shared across all its mailboxes with new mail).
            #  — the registry is now the uniform full action set.
            if classifier is None:
                classifier = _build_classifier_from_config(config)
                categories = await db_call(
                    _get_categories_from_db, db,
                    user_id=acct.get("user_id"),
                )
                registry = build_default_registry(
                    include_add_label=True, include_self_event=True,
                )

            #  — per-mailbox route overrides resolve EACH iteration
            # (cheap dict build) since two mailboxes on the same
            # account can carry different overrides.
            #
            # .9 — semantics note for operators chasing "I changed a
            # route, why did the next message still apply the old action?"
            # ``routes_by_cat`` is captured ONCE per (account, mailbox) at
            # the start of this poll cycle — NOT re-read per message.
            # Concretely: every message in ``new_messages`` below sees the
            # same routing table, even if the operator edits routes mid-
            # cycle via /routes. Edits take effect on the NEXT poll start,
            # not mid-cycle. This is deliberate: re-reading per message
            # would double the DB load on a bursty fetch (10s of new UIDs)
            # and admit a confusing race where a long fetch sees two
            # different rule sets in one batch. The /routes UI does NOT
            # currently surface "applies on next poll" — operators are
            # expected to know polls fire on a per-account interval.
            from email_triage.web.db import effective_routes_by_cat
            routes_by_cat = await db_call(
                effective_routes_by_cat, db, account_id, mailbox=mb,
            )
            # / — list-rule buckets for triage_single_message's
            # rule-label appliers, loaded once per (account, mailbox)
            # cycle alongside routes_by_cat.
            from email_triage.web.routers.ui import _load_all_list_hints
            _lh_lists, _lh_rules = await db_call(_load_all_list_hints, db)
    
            results: list[dict] = []
            errors: list[dict] = []
            #  — HWM discipline. The poll path must NOT advance the
            # mailbox high-water mark past a UID that errored AND failed
            # to enqueue a retry row: doing so leaves the message below
            # the HWM forever, never re-walked, never retried. We track
            # the contiguous run of UIDs (ascending) that ended
            # processed / skipped OR were durably enqueued for retry,
            # and only advance the HWM to the end of that run. A UID
            # that errored-and-failed-to-enqueue caps the run — the
            # next poll re-SEARCHes from there.
            #
            # new_messages arrives UID-ascending from provider.poll_once
            # (SEARCH UID hwm+1:* is monotonic). We walk it in order;
            # ``hwm_safe_uid`` advances only while every UID so far is
            # safe, and freezes the moment one is not.
            hwm_safe_uid = since_uid
            hwm_run_open = True  # cleared when a non-safe UID is hit
            from email_triage.web.triage_inflight import (
                mark_inflight as _mark_inflight,
                release_inflight as _release_inflight,
            )
            _self_from_addr = getattr(
                getattr(app.state.config, "smtp", None), "from_addr", "",
            )
            _acct_hipaa = account_hipaa_effective(account=acct)

            #  - per-mailbox calendar context. The pre-#199 poll
            # path registered no calendar actions, so the meeting
            # intercept was inert. The uniform registry now includes
            # them; wire the calendar provider once per mailbox so a
            # poll-ingested meeting request gets the same intercept
            # treatment as the IDLE / push paths.
            _cal_provider = None
            _mp = None
            try:
                from email_triage.web.db import (
                    get_meeting_prefs as _gmp_p,
                )
                from email_triage.web.calendars import (
                    is_calendar_effectively_enabled as _ice_p_eff,
                )
                from email_triage.web.routers.ui import (
                    _create_calendar_provider_from_account as _ccp_p,
                )
                if await db_call(_ice_p_eff, db, acct):
                    _cal_provider = await db_call(
                        _ccp_p, acct, secrets, db=db,
                    )
                _mp = await db_call(_gmp_p, db, acct.get("user_id"))
            except Exception:
                _mp = None

            #  - the unified poll path now runs the SAME per-message
            # body as every other ingestion path. durable_dedup /
            # mark_triaged_on_success / set_keyword_on_success stay True
            # (the poll path relied on the $EmailTriaged + rfc-id gates
            # before ). It now ALSO fires / rule-labels +
            #  watches - the pre-#199 poll path skipped them.
            # -residual — the three rule-map/dry-run reads were
            # inline DB calls inside the constructor; hoisted + routed
            # through db_call so they run off the loop under the lock.
            _rule_labels_map = await db_call(_build_rule_labels_map, db)
            _rule_provider_labels_map = await db_call(
                _build_rule_provider_labels_map, db,
            )
            _dry_run = await db_call(_is_dry_run, db)
            _ctx = TriageContext(
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
                set_keyword_on_success=True,
                fire_watches=True,
            )
            try:
                for message in new_messages:
                    uid = str(message.message_id)
                    uid_int: int | None = parse_int_or_none(uid)  # N-219c/46 R23: SSOT
                    # In-flight dedup gate. A concurrent cycle
                    # owns this UID; it is neither this poll's success
                    # nor failure. The next safe UID will carry the HWM
                    # past it, or the next poll re-walks it — either way
                    # the message is not lost.
                    if not _mark_inflight(app.state, account_id, uid):
                        log.info(
                            "Skipping concurrent triage cycle (in_flight)",
                            message_id=uid, account_id=account_id,
                            mailbox=mb, skip_reason="in_flight",
                        )
                        continue
                    #  — per-UID safety verdict. Set True only when
                    # the message ended processed / skipped OR a retry
                    # row was durably enqueued for it. A bare error with
                    # no retry row leaves it False → the HWM run caps
                    # here.
                    uid_safe = False
                    try:
                        _res = await triage_single_message(
                            _ctx, message, uid,
                        )
                        if _res.status == "e":
                            # Route the error through the existing
                            # per-message except so the retry-queue
                            # enqueue fires unchanged.
                            raise RuntimeError(
                                _res.entry.get("error", "triage error")
                            )
                        if _res.status == "s":
                            # Skipped ($EmailTriaged / rfc-id / self-
                            # origin) - the pre-#199 poll path did not
                            # record a result row for skips; preserve.
                            uid_safe = True
                            continue
                        #  — IMAP poll-once site watch-fire
                        # delivery retry.
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
                                        "provider_type", "imap",
                                    ),
                                    failed_count=(
                                        _res.unretried_watch_failures
                                    ),
                                    total_count=len(
                                        _res.entry.get("watches_fired")
                                        or []
                                    ),
                                    mailbox=mb,
                                    uid=str(uid),
                                    uidvalidity=_live_uidvalidity,
                                )
                            except Exception as exc:
                                # #8: a failed enqueue means
                                # the undelivered watch is NOT queued for
                                # re-fire — surface it (fail VISIBLE, PD#8)
                                # rather than silently swallow.
                                log.warning(
                                    "watch-delivery retry enqueue FAILED "
                                    "(imap poll) — the undelivered watch is "
                                    "NOT queued for re-fire",
                                    mailbox=mb,
                                    uid=str(uid),
                                    error=fmt_exc(exc),
                                )
                        results.append(_res.entry)
                        uid_safe = True
                        # N-213d R23 (2026-07-02): success telemetry to the
                        # watch-status recorder SSOT — /watch/status previously
                        # reported processed=0 for every poll-consumer account
                        # (only IMAP-IDLE watcher wrote counters). Fail-open.
                        try:
                            from email_triage.web._watch_status_recorder import (
                                record_message_result,
                            )
                            _src = (acct.get("provider_type") or "imap") + "-poll"
                            _mgr = getattr(app.state, "watcher_manager", None)
                            record_message_result(
                                _mgr, account_id, mb, _src,
                                success=True, message_id=uid,
                            )
                        except Exception:  # noqa: BLE001
                            pass
                    except Exception as e:
                        errors.append(
                            {"message_id": uid, "error": fmt_exc(e)}
                        )
                        # N-213d R23: error telemetry — same SSOT, opposite
                        # branch. Fail-open on any telemetry-side error so
                        # the original error path is unchanged.
                        try:
                            from email_triage.web._watch_status_recorder import (
                                record_message_result,
                            )
                            _src = (acct.get("provider_type") or "imap") + "-poll"
                            _mgr = getattr(app.state, "watcher_manager", None)
                            record_message_result(
                                _mgr, account_id, mb, _src,
                                success=False, error=e,
                            )
                        except Exception:  # noqa: BLE001
                            pass
                        log.error(
                            "Unified poll: per-message error",
                            **_acct_log_extras(acct), mailbox=mb,
                            message_id=uid, error=fmt_exc(e),
                        )
                        #  — stamp ``failure_kind='llm_unreachable'``
                        # on an LLM-unreachable failure so the retry
                        # drainer's LLM-breaker gate engages.
                        # triage_single_message re-raises
                        # LLMBackendUnreachableError unchanged.
                        from email_triage.llm_health import (
                            LLMBackendUnreachableError,
                        )
                        _is_llm_down = isinstance(
                            e, LLMBackendUnreachableError,
                        )
                        # Durable per-message retry row. uidvalidity
                        # surfaced by the  HWM guard.  — the
                        # UID is "safe" to pass under the HWM ONLY when
                        # this enqueue succeeds: a durable retry row
                        # means the drainer will re-walk it. An enqueue
                        # FAILURE holds the HWM back so the next poll
                        # re-SEARCHes the message.
                        try:
                            from email_triage.web.watcher_retry import (
                                enqueue_watcher_retry as _wr_enqueue_p,
                            )
                            # -residual — enqueue_watcher_retry wraps
                            # the @db_write enqueue_retry; route it off
                            # the loop through db_call.
                            _rid = await db_call(
                                _wr_enqueue_p,
                                app.state.db,
                                account_id=int(account_id),
                                provider_type=acct.get(
                                    "provider_type", "imap",
                                ),
                                mailbox=mb,
                                uid=str(uid),
                                uidvalidity=_live_uidvalidity,
                                error=e,
                                failure_kind=(
                                    "llm_unreachable"
                                    if _is_llm_down else None
                                ),
                            )
                            uid_safe = _rid is not None
                        except Exception:
                            uid_safe = False
                    finally:
                        # Release the in-flight slot. Idempotent.
                        _release_inflight(app.state, account_id, uid)
                        #  — extend the contiguous safe run. The
                        # run stays open only while every UID so far
                        # (ascending) has been safe; the first unsafe
                        # UID freezes it.
                        if hwm_run_open and uid_int is not None:
                            if uid_safe:
                                if uid_int > hwm_safe_uid:
                                    hwm_safe_uid = uid_int
                            else:
                                hwm_run_open = False
            finally:
                if _cal_provider is not None:
                    try:
                        await _cal_provider.close()
                    except Exception:
                        pass
            if hwm_safe_uid > since_uid:
                await db_call(set_mailbox_hwm, db, account_id, mb,
                              make_hwm_value(hwm_safe_uid, _live_uidvalidity))

            if results or errors:
                # run18 census #7 — record the run AND emit triage.completed
                # through the complete_triage_run SSOT. The pre-fix code here
                # called record_triage_run but never fired the outbound webhook,
                # while the same-file O365 poll sibling (_poll_once_office365)
                # did — a silent divergence for IMAP-poll-only installs. Emitting
                # right where the record happens (per-mailbox) mirrors that
                # sibling's record->emit adjacency. The whole call is best-effort
                # (try/except: pass) so neither the history row nor the webhook
                # can break the poll loop.
                dispatcher = getattr(app.state, "event_dispatcher", None)
                try:
                    from email_triage.web.events import complete_triage_run
                    from email_triage._ids import new_run_id
                    await complete_triage_run(
                        dispatcher, db, config, acct,
                        run_id=new_run_id("imap_poll", account_id, mb),
                        query="poll",
                        trigger="poll",
                        total_messages=len(new_messages),
                        results=results,
                        errors=errors,
                        elapsed_secs=0.0,
                    )
                except Exception:
                    pass

                log.info(
                    "Unified poll: IMAP processed new mail",
                    **_acct_log_extras(acct),
                    mailbox=mb, messages=len(new_messages),
                    errors=len(errors), new_hwm=hwm_safe_uid,
                )

        finally:
            if provider is not None:
                try:
                    await provider.close()
                except Exception:
                    pass
