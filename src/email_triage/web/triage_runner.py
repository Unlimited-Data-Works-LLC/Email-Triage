"""Reusable triage-pipeline runner for one account.

Extracted out of the ``/triage/run`` HTML route in ``ui.py`` so the
same pipeline can be invoked from the UI, the outbound-webhook API, scheduled
jobs, and (eventually) anything else that wants to fire a one-shot
classify-and-route on an account.

The runner owns the provider lifecycle, HIPAA audit bookends, action
dispatch, and ``triage_runs`` row recording. Callers get a structured
dict back and decide how to render it.
"""

from __future__ import annotations

import functools
import sqlite3
import time
from typing import Any

from email_triage.config import TriageConfig
from email_triage.secrets import SecretsProvider
from email_triage.triage_logging import get_logger, is_account_hipaa
from email_triage._errfmt import fmt_exc, scrub_class_error_for_persist, scrub_error_for_persist

log = get_logger("web.triage_runner")


class TriageRunResult(dict):
    """Typed-ish wrapper so callers can rely on the keys.

    Keys: run_id, account_id, account_name, query, results,
    errors, elapsed_secs, total_messages.
    """


# N-385 (batched SME panel fold 2026-07-10) — the bounded ``outcome`` vocabulary
# for ``et_triage_runs_total``. Every ``TriageRunResult(error=<literal>)``
# construction site in this module MUST use a slug in this set (enforced by
# ``tests/test_triage_run_outcome_ssot_pin.py``). An unknown value at runtime
# coerces to ``"error_other"`` in the decorator wrapper — the fail-safe path
# for a future error slug that lands before the frozenset is updated. Prevents
# an unbounded label-cardinality bomb on the Prometheus SSOT (Prime Directive
# 5: an unbounded value flowing into a bounded surface is CIDI drift). Mirrors
# ``emit_llm_outcome``'s ``transport_error`` fail-safe coercion.
_TRIAGE_OUTCOMES: frozenset[str] = frozenset({
    "success",
    "error",             # top-level catch (fn raised, or shape-error at return)
    "error_other",       # runtime coerce sentinel — an unknown error slug
    "user_disabled",     # owner_disabled fail-closed at preamble
    "no_categories",     # empty categories at preamble
    "provider_error",    # provider construction / auth failure
    "classifier_error",  # classifier build failure
    "baa_required",      # HIPAA account routed to a non-local backend
})


def _emit_triage_run_outcome_metric(fn):
    """Decorator — bump ``et_triage_runs_total{trigger, outcome}`` on every
    :func:`run_triage` terminal (N-385, divergence census wf_69674c7e-c67
    2026-07-10, HIGH).

    Before this wrapper, the core triage-runner hot path emitted ZERO counters
    of any kind — a ``grep metrics|counter|Counter|inc\\(`` returned 0 hits
    across the file, so every message triaged was invisible to every counter
    registry (and specifically to the operator-facing Prometheus ``/metrics``
    surface, which was the divergence census's canonical). Wrapping here so a
    new terminal exit (a future ``return TriageRunResult(...)`` for a fresh
    error class) cannot silently escape the count — the decorator anchors the
    emit at the ONE function-return seam.

    ``outcome`` reads from the ``TriageRunResult.error`` field: an empty /
    absent ``error`` = ``"success"``; a literal error slug matching
    :data:`_TRIAGE_OUTCOMES` passes through; ANY OTHER value coerces to
    ``"error_other"`` (fail-safe: never let an unbounded string flow onto a
    Prometheus label). A non-dict / ``.get``-less return classifies as
    ``"error"`` (a shape-defect is a bug, not a healthy run — fail-CLOSED per
    ``feedback_just_be_honest``). ``trigger`` mirrors the kwarg the caller
    passed (``"manual"`` / ``"api"`` / ``"watch"`` / ``"push"`` /
    ``"scheduled"``). Fail-open on the metrics side: a registry hiccup MUST
    NOT take down a triage run.
    """
    @functools.wraps(fn)
    async def _wrapped(*args, **kwargs):
        trigger = kwargs.get("trigger", "manual")
        outcome = "error"
        try:
            result = await fn(*args, **kwargs)
            try:
                outcome = result.get("error") or "success"
            except Exception:
                outcome = "error"
            # Bound the label vocabulary — an unrecognized slug becomes
            # ``error_other`` on its way to the Prometheus counter (mirrors
            # ``emit_llm_outcome``'s ``transport_error`` fail-safe coercion).
            if outcome not in _TRIAGE_OUTCOMES:
                outcome = "error_other"
            return result
        finally:
            #  (Census v3 re-run) — delegate to the shared SSOT so a
            # future emit-shape change lands once, not twice.
            from email_triage.web._triage_metrics import (
                emit_triage_run_outcome_metric,
            )
            emit_triage_run_outcome_metric(trigger=trigger, outcome=outcome)

    return _wrapped


@_emit_triage_run_outcome_metric
async def run_triage(
    db: sqlite3.Connection,
    config: TriageConfig,
    secrets: SecretsProvider,
    acct: dict,
    *,
    query: str,
    limit: int,
    actor_user_id: int | None = None,
    trigger: str = "manual",
    force_reclassify: bool = False,
) -> TriageRunResult:
    """Run a single triage cycle on ``acct``.

    Parameters
    ----------
    actor_user_id:
        The user who initiated the run. Used for the HIPAA access-audit
        row. Pass ``None`` for system-initiated runs (push consumer,
        watcher, scheduled). HIPAA access events are only recorded when
        ``actor_user_id`` is set — system runs use ``triage_runs.run_id``
        as their trail.
    trigger:
        Free-text label persisted alongside the run. Conventions:
        ``manual``, ``api``, ``watch``, ``push``, ``scheduled``.
    force_reclassify:
        Bypass the optional Redis classification cache and force
        the LLM call on every message. Result is still written back to
        the cache so the next un-forced run hits. Used by the "Force
        re-classify" debug checkbox on /triage/run. Defaults to False.
    """
    from email_triage.web.db import (
        is_user_disabled,
        list_account_routes, record_triage_run, record_hipaa_access_event,
        update_hipaa_access_event,
    )
    from email_triage.web.db_threadpool import db_call
    from email_triage.web._audit import safe_audit_write_async
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db,
        _load_all_list_hints, _is_dry_run,
    )
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
        _build_rule_labels_map, _build_rule_provider_labels_map,
    )

    account_id = acct["id"]
    owner_id = acct.get("user_id")

    #  — run_triage is awaited directly from the /triage/classify
    # route handler (and other ingestion paths), so its body runs on
    # the event-loop thread. Every shared-connection touch must hop to
    # the threadpool via db_call. The owner-disabled gate, the route
    # load, and the category load are sequential reads — fold them into
    # one hop.
    def _run_triage_preamble_reads():
        disabled = (
            owner_id is not None and is_user_disabled(db, owner_id)
        )
        account_routes = list_account_routes(db, account_id)
        categories = _get_categories_from_db(
            db, user_id=acct.get("user_id"),
        )
        return disabled, account_routes, categories

    owner_disabled, account_routes, categories = await db_call(
        _run_triage_preamble_reads,
    )

    # Fail-closed: if the account owner is disabled, refuse to run.
    # Covers every call site (UI, outbound-webhook API, scheduled, push, watch).
    if owner_disabled:
        log.warning(
            "Triage refused: owner disabled",
            account_id=account_id, owner_id=owner_id, trigger=trigger,
        )
        return TriageRunResult(
            run_id="",
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=0,
            results=[],
            errors=["User disabled"],
            elapsed_secs=0.0,
            error="user_disabled",
        )

    routes_by_cat = {r["category"]: r["actions"] for r in account_routes}

    # Per-user personal cats: classifier sees system cats unioned
    # with the account owner's personal cats (user override wins on
    # slug collision).
    if not categories:
        return TriageRunResult(
            run_id="",
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=0,
            results=[],
            errors=["No categories configured. Add categories first."],
            elapsed_secs=0.0,
            error="no_categories",
        )

    # HIPAA access-audit bookend — only when a NON-OWNER user
    # initiated the run. Owner triaging their own mailbox is
    # first-party access (data subject = authorized party for their
    # own data; §164.502(a) self-disclosure). Admin / delegate
    # triaging someone else's mailbox is third-party PHI access +
    # gets the §164.312(b) audit row.
    audit_event_id: int | None = None
    owner_id_for_audit = acct.get("user_id")
    # N-79: gate through the PD#14 predicate SSOT — a system-initiated
    # (actor_user_id=None) triage of a HIPAA mailbox is a non-owner PHI read
    # and MUST audit. The old `actor_user_id is not None` clause silently
    # dropped that case (the N-72 bug, un-root-cause-scoped to this sibling).
    from email_triage.db.audit import phi_access_audit_required
    if phi_access_audit_required(
        account_hipaa=is_account_hipaa(acct),
        actor_user_id=actor_user_id,
        owner_id=owner_id_for_audit,
    ):
        audit_event_id = await safe_audit_write_async(
            lambda: db_call(
                record_hipaa_access_event,
                db, actor_user_id, account_id, "manual_triage",
                outcome="in_progress",
            ),
            description=f"manual_triage account={account_id} actor={actor_user_id} outcome=in_progress",
            table="hipaa_access_events",
            emitter="record_hipaa_access_event",
        )

    # Provider + classifier — fail fast and finalise the audit row.
    provider = None
    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception as e:
        if audit_event_id is not None:
            # Allow-list step 2 (B1): the finalise routes through the SSOT so a
            # failure is WARNING-logged, /health-counted and gap-ledgered.
            _err_class = type(e).__name__
            await safe_audit_write_async(
                lambda: db_call(
                    update_hipaa_access_event,
                    db, audit_event_id, "error",
                    f"provider: {_err_class}",
                ),
                description=(
                    f"manual_triage_finalise account={account_id} "
                    f"audit_event_id={audit_event_id} outcome=error"
                ),
                table="hipaa_access_events",
                emitter="update_hipaa_access_event",
            )
        return TriageRunResult(
            run_id="",
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=0,
            results=[],
            errors=[scrub_error_for_persist(f"Provider error: {e}")],
            elapsed_secs=0.0,
            error="provider_error",
        )

    try:
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        try:
            await provider.close()
        except Exception:
            pass
        return TriageRunResult(
            run_id="",
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=0,
            results=[],
            errors=[scrub_error_for_persist(f"Classifier error: {e}")],
            elapsed_secs=0.0,
            error="classifier_error",
        )

    # HIPAA + BAA gate — when the account is HIPAA-flagged AND
    # the configured classifier is external AND no BAA acknowledgment
    # is on file for the (backend, vendor_host) tuple, refuse to
    # proceed. PHI must not flow to a non-BAA subprocessor (HIPAA
    # §164.308(b)(1)). Operator can ack the BAA on /config.
    if is_account_hipaa(acct):
        from email_triage.classify.baa_gate import (
            classifier_baa_status, is_safe_for_hipaa,
        )
        #  — both baa-gate helpers touch the shared connection.
        baa_safe = await db_call(is_safe_for_hipaa, db, classifier)
        if not baa_safe:
            try:
                await provider.close()
            except Exception:
                pass
            status = await db_call(classifier_baa_status, db, classifier)
            if audit_event_id is not None:
                await safe_audit_write_async(
                    lambda: db_call(
                        update_hipaa_access_event,
                        db, audit_event_id, "blocked",
                        f"baa_gate: backend={status['backend']} host={status['host']}",
                    ),
                    description=(
                        f"manual_triage_finalise account={account_id} "
                        f"audit_event_id={audit_event_id} outcome=blocked"
                    ),
                    table="hipaa_access_events",
                    emitter="update_hipaa_access_event",
                )
            return TriageRunResult(
                run_id="",
                account_id=account_id,
                account_name=acct.get("name", ""),
                query=query,
                total_messages=0,
                results=[],
                errors=[
                    "HIPAA-flagged account blocked from non-BAA classifier "
                    f"({status['backend']} @ {status['host'] or '?'}). "
                    "Acknowledge a BAA on /config or switch backend to a "
                    "local Ollama."
                ],
                elapsed_secs=0.0,
                error="baa_required",
            )

    # .1 — load classification lists + rules ONCE per run.
    # Previously each message triggered a 1+N rules fetch via
    # ``_collect_list_hints_for_message(db, msg)``; for a 100-message
    # bulk run that was 600+ queries on the inline path. Now: 2
    # queries up front, then pure in-memory matching per message.
    #  /  — load rule-driven label maps once per run. Built +
    # indexed by rule id so the per-message apply path is O(1). The map
    # builders live in triage_one.py so every ingestion path
    # shares the exact same parse + schema-fallback logic.
    #  — all four loads are sequential DB reads; fold into one hop.
    def _run_triage_rule_loads():
        lh_lists, lh_rules = _load_all_list_hints(db)
        return (
            lh_lists, lh_rules,
            _build_rule_labels_map(db),
            _build_rule_provider_labels_map(db),
        )

    (
        list_hints_lists, list_hints_rules_by_list,
        _rule_labels_map, _rule_provider_labels_map,
    ) = await db_call(_run_triage_rule_loads)

    results: list[dict] = []
    errors: list[str] = []
    t0 = time.time()
    account_hipaa = is_account_hipaa(acct)

    # Query-stage self-skip. Push the X-Email-Triage check up
    # to the provider's SEARCH so the install's own outbound digests
    # / draft replies never enter the result set in the first place.
    # Saves a per-self-message FETCH on every triage run; the secondary
    # X-Email-Triage check below catches anything the SEARCH filter
    # missed (e.g. account-level outbound from a different from-address).
    from email_triage.mail_headers import build_self_skip_query
    self_from_addr = getattr(
        getattr(config, "smtp", None), "from_addr", "",
    )
    effective_query = build_self_skip_query(
        query, self_from_addr, provider_type=acct["provider_type"],
    )
    try:
        message_ids = await provider.search(effective_query, limit)
    except Exception as e:
        errors.append(scrub_error_for_persist(f"search: {e}"))
        message_ids = []

    # Calendar provider + meeting prefs are stashed on each flow's
    # state_bag so the invite + suggest_meeting_times actions can
    # reach them without threading new args through the Action ABC.
    calendar_provider = None
    meeting_prefs_raw = None
    # ``self_email`` is the account's primary outbound identity —
    # used by invite-reply attendee matching, draft "from" header
    # selection, etc. Stays a single value (the primary). The
    # full alias-aware set is exposed alongside as
    # ``self_email_addresses`` so consumers that need recipient
    # matching (e.g. "is this message addressed to me?" checks
    # for  alias routing) can take the union without the
    # ABC plumbing knowing about aliases.
    from email_triage.web.db import account_addresses, account_email
    self_email = account_email(acct)
    self_email_addresses = account_addresses(acct)
    #  self-sent event triage state. Populated below when calendar
    # is enabled; defaults to "off" so action chain skips the self-event
    # path on accounts without calendar wiring.
    self_schedule_calendar_id: str | None = None
    calendar_surrogate_active = False
    account_addrs: list[str] = list(self_email_addresses)
    try:
        from email_triage.web.db import (
            account_addresses,
            get_setting, get_meeting_prefs,
        )
        from email_triage.web.calendars import (
            get_self_schedule_calendar_id, resolve_surrogate_account,
            is_calendar_effectively_enabled,
        )
        from email_triage.web.routers.ui import _create_calendar_provider_from_account

        #  — the calendar-context wiring is a cluster of
        # shared-connection reads (is_calendar_effectively_enabled,
        # get_meeting_prefs, resolve_surrogate_account, plus the
        # surrogate-resolving provider build). Fold the whole cluster
        # into one threadpool hop.
        def _run_triage_calendar_wiring():
            # 2026-05-13 — surrogate-aware gate. An IMAP-with-surrogate
            # account carries calendar_enabled=False on its own row
            # but gets routed through a Gmail / O365 surrogate that
            # owns the flag. is_calendar_effectively_enabled
            # consolidates both.
            cal_provider = None
            if is_calendar_effectively_enabled(db, acct):
                # db kwarg unlocks the IMAP-with-surrogate path
                #.
                cal_provider = _create_calendar_provider_from_account(
                    acct, secrets, db=db,
                )
            prefs_raw = get_meeting_prefs(db, acct.get("user_id"))
            # Self-sent event triage needs the account's
            # self_schedule destination + the account's address set so
            # the action can match From == To. Surrogate flag is
            # checked so a delegate's calendar never receives a
            # self-sent event from a routed-through account.
            sched_cal_id = get_self_schedule_calendar_id(acct)
            surrogate_active = (
                resolve_surrogate_account(db, acct) is not None
            )
            addrs = account_addresses(acct)
            return (
                cal_provider, prefs_raw, sched_cal_id,
                surrogate_active, addrs,
            )

        (
            calendar_provider, meeting_prefs_raw,
            self_schedule_calendar_id, calendar_surrogate_active,
            account_addrs,
        ) = await db_call(_run_triage_calendar_wiring)
    except Exception as e:
        log.warning("Failed to wire calendar context", error=fmt_exc(e))

    #  — _is_dry_run reads the dry-run setting from the shared
    # connection; resolve it off the loop before building the context.
    dry_run = await db_call(_is_dry_run, db)

    if message_ids:
        #  — the per-message body is the shared triage_single_message
        # helper. run_triage is the reference path: it uses the FULL
        # action set + fires / rule-labels +  watches, and
        # does NOT use the durable rfc-id / $EmailTriaged dedup gates
        # (the query-stage self-skip + the X-Email-Triage header check
        # are its loop guards). Those gate flags stay False here so 
        # is behaviour-preserving for this path.
        registry = build_default_registry(
            include_add_label=True, include_self_event=True,
        )
        ctx = TriageContext(
            db=db, config=config, secrets=secrets, acct=acct,
            classifier=classifier, provider=provider, registry=registry,
            categories=categories,
            routes_by_cat=routes_by_cat,
            list_hints_lists=list_hints_lists,
            list_hints_rules_by_list=list_hints_rules_by_list,
            rule_labels_map=_rule_labels_map,
            rule_provider_labels_map=_rule_provider_labels_map,
            calendar_provider=calendar_provider,
            meeting_prefs=meeting_prefs_raw,
            self_email=self_email,
            self_email_addresses=set(self_email_addresses),
            account_addrs=account_addrs,
            self_schedule_calendar_id=self_schedule_calendar_id,
            calendar_surrogate_active=calendar_surrogate_active,
            self_from_addr=self_from_addr,
            dry_run=dry_run,
            account_hipaa=account_hipaa,
            actor_user_id=actor_user_id,
            durable_dedup=False,
            mark_triaged_on_success=False,
            set_keyword_on_success=False,
            fire_watches=True,
        )

        for msg_id in message_ids:
            try:
                message = await provider.fetch_message(msg_id)
                #  — force_reclassify is a run_triage-only debug
                # knob; stamp it before handing the message off (the
                # shared helper stamps account_id but not this flag).
                if force_reclassify:
                    if getattr(message, "raw_metadata", None) is None:
                        try:
                            message.raw_metadata = {}
                        except Exception:
                            pass
                    if isinstance(getattr(message, "raw_metadata", None), dict):
                        message.raw_metadata["force_reclassify"] = True
            except Exception as e:
                #  tail — the results-entry ``entry["error"]`` lands
                # in the batch return (agent API caller, triage-completed
                # webhook / UI) AND in ``triage_runs.results_json``. Punch
                # 603: the persisted-error SSOT, same as the triage branch
                # below and the bulk sibling. ``scrub_exc`` (the flash
                # funnel used here before) has no ``key=value`` token leg
                # and kept ``access_token=...`` verbatim.
                entry: dict[str, Any] = {"message_id": msg_id}
                entry["status"] = "error"
                entry["error"] = scrub_class_error_for_persist(e)
                log.error(
                    "Triage error for message",
                    message_id=msg_id, error=fmt_exc(e),
                )
                results.append(entry)
                continue
            try:
                res = await triage_single_message(ctx, message, msg_id)
                results.append(res.entry)
            except Exception as e:
                # The shared helper re-raises LLMBackendUnreachableError
                # (so the watcher / poll / push paths can route it to
                # their retry queues). run_triage has no retry queue —
                # record it as a per-message error, matching the
                # pre-#199 inline path's broad per-message ``except``.
                # 2026-07-09 post-drive-full-census discovered class: raw
                # `str(e)` leaked PHI-adjacent exception text. Punch 603:
                # `fmt_exc` (PHI leg only, no cap) was still the weaker
                # variant; the entry is returned AND persisted, so it takes
                # the persisted-error SSOT (PHI + secret legs + 500 cap),
                # as `triage_runner_bulk` already did.
                entry = {"message_id": msg_id, "status": "error",
                         "error": scrub_class_error_for_persist(e)}
                log.error(
                    "Triage error for message",
                    message_id=msg_id, error=fmt_exc(e),
                )
                results.append(entry)

    elapsed = time.time() - t0

    try:
        await provider.close()
    except Exception:
        pass
    if calendar_provider is not None:
        try:
            await calendar_provider.close()
        except Exception:
            pass
    #  — drain the classifier's long-lived httpx pool. Classifier
    # backends that don't expose ``close()`` (legacy or test stubs)
    # are silently skipped via hasattr.
    if hasattr(classifier, "close"):
        try:
            await classifier.close()
        except Exception:
            pass

    if audit_event_id is not None:
        outcome = "error" if errors else "ok"
        detail = f"messages={len(results)}"
        if errors:
            detail += f"; errors={len(errors)}"
        await safe_audit_write_async(
            lambda: db_call(
                update_hipaa_access_event,
                db, audit_event_id, outcome, detail,
            ),
            description=(
                f"manual_triage_finalise account={account_id} "
                f"audit_event_id={audit_event_id} outcome={outcome}"
            ),
            table="hipaa_access_events",
            emitter="update_hipaa_access_event",
        )

    from email_triage._ids import new_run_id
    run_id = new_run_id(trigger, account_id)
    try:
        await db_call(
            record_triage_run,
            db,
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=len(results),
            results=results,
            errors=errors,
            elapsed_secs=elapsed,
            actor_user_id=actor_user_id,
        )
    except Exception as e:
        log.warning("Failed to record triage run", error=fmt_exc(e))

    return TriageRunResult(
        run_id=run_id,
        account_id=account_id,
        account_name=acct.get("name", ""),
        query=query,
        total_messages=len(results),
        results=results,
        errors=errors,
        elapsed_secs=elapsed,
        trigger=trigger,
    )
