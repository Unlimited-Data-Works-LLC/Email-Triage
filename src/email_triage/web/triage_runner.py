"""Reusable triage-pipeline runner for one account.

Extracted out of the ``/triage/run`` HTML route in ``ui.py`` so the
same pipeline can be invoked from the UI, the OpenClaw API, scheduled
jobs, and (eventually) anything else that wants to fire a one-shot
classify-and-route on an account.

The runner owns the provider lifecycle, HIPAA audit bookends, action
dispatch, and ``triage_runs`` row recording. Callers get a structured
dict back and decide how to render it.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from email_triage.config import TriageConfig
from email_triage.secrets import SecretsProvider
from email_triage.triage_logging import get_logger, is_account_hipaa
from email_triage._errfmt import fmt_exc

log = get_logger("web.triage_runner")


class TriageRunResult(dict):
    """Typed-ish wrapper so callers can rely on the keys.

    Keys: run_id, account_id, account_name, query, results,
    errors, elapsed_secs, total_messages.
    """


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
        Bypass the optional Redis classification cache (#151) and force
        the LLM call on every message. Result is still written back to
        the cache so the next un-forced run hits. Used by the "Force
        re-classify" debug checkbox on /triage/run. Defaults to False.
    """
    from email_triage.web.db import (
        is_user_disabled,
        list_account_routes, record_triage_run, record_hipaa_access_event,
        update_hipaa_access_event,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _collect_list_hints_for_message,
        _load_all_list_hints, _is_dry_run,
    )
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.add_label import AddLabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.invite import (
        AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
    )
    from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
    from email_triage.actions.self_sent_event import SelfSentEventAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.engine.models import FlowState, FlowStatus

    account_id = acct["id"]

    # Fail-closed: if the account owner is disabled, refuse to run.
    # Covers every call site (UI, OpenClaw API, scheduled, push, watch).
    owner_id = acct.get("user_id")
    if owner_id is not None and is_user_disabled(db, owner_id):
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

    account_routes = list_account_routes(db, account_id)
    routes_by_cat = {r["category"]: r["actions"] for r in account_routes}

    # Per-user personal cats (#62): classifier sees system cats unioned
    # with the account owner's personal cats (user override wins on
    # slug collision).
    categories = _get_categories_from_db(db, user_id=acct.get("user_id"))
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
    if (
        actor_user_id is not None
        and is_account_hipaa(acct)
        and actor_user_id != owner_id_for_audit
    ):
        try:
            audit_event_id = record_hipaa_access_event(
                db, actor_user_id, account_id, "manual_triage",
                outcome="in_progress",
            )
        except Exception as e:
            log.warning("Failed to record HIPAA access event", error=fmt_exc(e))

    # Provider + classifier — fail fast and finalise the audit row.
    provider = None
    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception as e:
        if audit_event_id is not None:
            try:
                update_hipaa_access_event(
                    db, audit_event_id, "error",
                    f"provider: {type(e).__name__}",
                )
            except Exception:
                pass
        return TriageRunResult(
            run_id="",
            account_id=account_id,
            account_name=acct.get("name", ""),
            query=query,
            total_messages=0,
            results=[],
            errors=[f"Provider error: {e}"],
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
            errors=[f"Classifier error: {e}"],
            elapsed_secs=0.0,
            error="classifier_error",
        )

    # HIPAA + BAA gate (#59) — when the account is HIPAA-flagged AND
    # the configured classifier is external AND no BAA acknowledgment
    # is on file for the (backend, vendor_host) tuple, refuse to
    # proceed. PHI must not flow to a non-BAA subprocessor (HIPAA
    # §164.308(b)(1)). Operator can ack the BAA on /config.
    if is_account_hipaa(acct):
        from email_triage.classify.baa_gate import (
            classifier_baa_status, is_safe_for_hipaa,
        )
        if not is_safe_for_hipaa(db, classifier):
            try:
                await provider.close()
            except Exception:
                pass
            status = classifier_baa_status(db, classifier)
            if audit_event_id is not None:
                try:
                    update_hipaa_access_event(
                        db, audit_event_id, "blocked",
                        f"baa_gate: backend={status['backend']} host={status['host']}",
                    )
                except Exception:
                    pass
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

    # #134.1 — load classification lists + rules ONCE per run.
    # Previously each message triggered a 1+N rules fetch via
    # ``_collect_list_hints_for_message(db, msg)``; for a 100-message
    # bulk run that was 600+ queries on the inline path. Now: 2
    # queries up front, then pure in-memory matching per message.
    list_hints_lists, list_hints_rules_by_list = _load_all_list_hints(db)

    # #129 — load rule-driven labels in one extra read. Mapping is
    # rule_id -> [label_slug, ...] parsed from list_rules.adds_labels
    # (JSON array, NULL = no labels). Built once + indexed by rule id
    # so the per-message match path can attach labels in O(1).
    import json as _json_labels
    _rule_labels_map: dict[int, list[str]] = {}
    try:
        for r in db.execute(
            "SELECT id, adds_labels FROM list_rules WHERE adds_labels IS NOT NULL"
        ).fetchall():
            try:
                parsed = _json_labels.loads(r["adds_labels"] or "[]")
            except Exception:
                parsed = []
            if isinstance(parsed, list) and parsed:
                _rule_labels_map[int(r["id"])] = [str(s) for s in parsed]
    except Exception:
        # Pre-v18 schema (column missing). Leave map empty.
        _rule_labels_map = {}

    # #163 — load rule-driven provider-native label assignments in
    # one extra read. Mapping is rule_id -> [{"account_id", "label_slug"}, ...]
    # parsed from list_rules.provider_labels (JSON array, NULL = none).
    # Same indexed-once-per-run shape the install-internal labels map
    # uses; the per-message apply scan filters entries by the message's
    # account_id so provider.apply_label only fires on the right
    # mailbox.
    _rule_provider_labels_map: dict[int, list[dict]] = {}
    try:
        for r in db.execute(
            "SELECT id, provider_labels FROM list_rules "
            "WHERE provider_labels IS NOT NULL"
        ).fetchall():
            try:
                parsed = _json_labels.loads(r["provider_labels"] or "[]")
            except Exception:
                parsed = []
            cleaned: list[dict] = []
            if isinstance(parsed, list):
                for entry in parsed:
                    if not isinstance(entry, dict):
                        continue
                    aid = entry.get("account_id")
                    slug = entry.get("label_slug")
                    if not isinstance(aid, int) or not isinstance(slug, str):
                        continue
                    if not slug:
                        continue
                    cleaned.append(
                        {"account_id": aid, "label_slug": slug}
                    )
            if cleaned:
                _rule_provider_labels_map[int(r["id"])] = cleaned
    except Exception:
        # Pre-v22 schema (column missing). Leave map empty.
        _rule_provider_labels_map = {}

    results: list[dict] = []
    errors: list[str] = []
    t0 = time.time()
    account_hipaa = is_account_hipaa(acct)

    # Query-stage self-skip (#117). Push the X-Email-Triage check up
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
        errors.append(f"search: {e}")
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
    # for #106 alias routing) can take the union without the
    # ABC plumbing knowing about aliases.
    from email_triage.web.db import account_addresses, account_email
    self_email = account_email(acct)
    self_email_addresses = account_addresses(acct)
    # #107 self-sent event triage state. Populated below when calendar
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
        # 2026-05-13 — surrogate-aware gate. An IMAP-with-surrogate
        # account carries calendar_enabled=False on its own row but
        # gets routed through a Gmail / O365 surrogate that owns the
        # flag. is_calendar_effectively_enabled consolidates both.
        if is_calendar_effectively_enabled(db, acct):
            # db kwarg unlocks the IMAP-with-surrogate path
            # (#105 phase 1A++).
            calendar_provider = _create_calendar_provider_from_account(
                acct, secrets, db=db,
            )
        meeting_prefs_raw = get_meeting_prefs(db, acct.get("user_id"))
        # Self-sent event triage (#107) needs the account's
        # self_schedule destination + the account's address set so
        # the action can match From == To. Surrogate flag is
        # checked so a delegate's calendar never receives a
        # self-sent event from a routed-through account.
        self_schedule_calendar_id = get_self_schedule_calendar_id(acct)
        if resolve_surrogate_account(db, acct) is not None:
            calendar_surrogate_active = True
        account_addrs = account_addresses(acct)
    except Exception as e:
        log.warning("Failed to wire calendar context", error=fmt_exc(e))

    if message_ids:
        registry = ActionRegistry()
        registry.register(MoveAction())
        registry.register(LabelAction())
        registry.register(AddLabelAction())
        registry.register(NotifyAction())
        registry.register(DraftReplyAction())
        registry.register(AcceptInviteAction())
        registry.register(DeclineInviteAction())
        registry.register(TentativeInviteAction())
        registry.register(SuggestMeetingTimesAction())
        registry.register(SelfSentEventAction())

        dry_run = _is_dry_run(db)

        from email_triage.mail_headers import (
            get_triage_header, is_self_origin,
        )
        # Resolve install-wide self-from once per run (#117). Cheap dict
        # lookup but no point doing it per-message inside the loop.
        self_from_addr = getattr(
            getattr(config, "smtp", None), "from_addr", "",
        )

        for msg_id in message_ids:
            entry: dict[str, Any] = {"message_id": msg_id}
            try:
                message = await provider.fetch_message(msg_id)
                message.hipaa = account_hipaa
                # #151 — stamp account_id + force_reclassify so the
                # classification cache lookup is per-account-isolated
                # and obeys the debug bypass. raw_metadata may be a
                # fresh dict from the provider, so update in place.
                if message.raw_metadata is None:
                    message.raw_metadata = {}
                message.raw_metadata["account_id"] = int(account_id)
                if force_reclassify:
                    message.raw_metadata["force_reclassify"] = True
                if not account_hipaa:
                    entry["sender"] = message.sender
                    entry["subject"] = message.subject

                # Loop-prevention: skip mail that email-triage itself
                # generated. Digests + draft replies + OTP + health
                # email all carry the X-Email-Triage header; without
                # this short-circuit a digest delivered to a watched
                # inbox would be re-classified + potentially re-routed,
                # cascading back into more outbound mail.
                et_header = get_triage_header(message.headers)
                if et_header:
                    log.info(
                        "Skipping re-triage of email-triage-generated message",
                        message_id=msg_id,
                        x_email_triage=et_header,
                    )
                    entry["status"] = "skipped"
                    entry["skip_reason"] = "x_email_triage_header"
                    entry["reason"] = "self_origin"
                    entry["x_email_triage"] = et_header
                    results.append(entry)
                    continue
                # Defense in depth (#117): downstream MTA may have
                # stripped X-Email-Triage. Match on sender == install's
                # smtp.from_addr as a secondary skip.
                if is_self_origin(message.sender or "", self_from_addr):
                    log.info(
                        "Skipping self-origin message (header missing)",
                        message_id=msg_id,
                    )
                    entry["status"] = "skipped"
                    entry["skip_reason"] = "self_from_match"
                    entry["reason"] = "self_origin"
                    results.append(entry)
                    continue

                hints = _collect_list_hints_for_message(
                    db, message,
                    lists=list_hints_lists,
                    rules_by_list=list_hints_rules_by_list,
                )
                classification = await classifier.classify(
                    message, categories, hints or None,
                )

                # #129 — rule-driven labels. For every rule that
                # matches this message, union its ``adds_labels``
                # set + attach via apply_labels_to_message. Additive
                # only: labels never override the LLM category. The
                # match check mirrors classify.hints._rule_matches so
                # we stay consistent with what fed the classifier.
                if _rule_labels_map:
                    from email_triage.classify.hints import _rule_matches
                    matched_label_slugs: set[str] = set()
                    for _bucket in list_hints_rules_by_list.values():
                        for _rule in _bucket:
                            slugs = _rule_labels_map.get(_rule.id)
                            if not slugs:
                                continue
                            if _rule_matches(_rule, message):
                                matched_label_slugs.update(slugs)
                    if matched_label_slugs:
                        try:
                            from email_triage.web.db import (
                                apply_labels_to_message,
                            )
                            apply_labels_to_message(
                                db, msg_id, account_id,
                                sorted(matched_label_slugs),
                                applied_by_actor=actor_user_id,
                            )
                            entry["labels_applied"] = sorted(
                                matched_label_slugs,
                            )
                        except Exception as _lbl_exc:
                            log.warning(
                                "rule-driven label apply failed",
                                message_id=msg_id,
                                error=fmt_exc(_lbl_exc),
                            )

                # #163 — provider-native label apply. Each rule may
                # carry a list of provider_labels entries
                # ({"account_id", "label_slug"}); for each entry whose
                # account_id matches THIS message's account, call
                # provider.apply_label. Mirrors the structure of the
                # install-internal label apply above. Per-account
                # filter is the linchpin: a rule shared across
                # accounts only fires on the matching mailbox.
                if _rule_provider_labels_map:
                    from email_triage.classify.hints import _rule_matches
                    matched_provider_labels: set[str] = set()
                    for _bucket in list_hints_rules_by_list.values():
                        for _rule in _bucket:
                            entries_pl = _rule_provider_labels_map.get(
                                _rule.id,
                            )
                            if not entries_pl:
                                continue
                            if not _rule_matches(_rule, message):
                                continue
                            for pl_entry in entries_pl:
                                if int(pl_entry.get("account_id", -1)) == account_id:
                                    label_slug = pl_entry.get(
                                        "label_slug", "",
                                    )
                                    if label_slug:
                                        matched_provider_labels.add(
                                            label_slug,
                                        )
                    for slug_pl in sorted(matched_provider_labels):
                        try:
                            await provider.apply_label(msg_id, slug_pl)
                        except NotImplementedError:
                            log.debug(
                                "provider.apply_label unsupported",
                                provider=getattr(
                                    provider, "name", "?",
                                ),
                            )
                        except Exception as _pl_exc:
                            log.warning(
                                "provider label apply failed",
                                message_id=msg_id,
                                label=slug_pl,
                                error=fmt_exc(_pl_exc),
                            )
                    if matched_provider_labels:
                        entry["provider_labels_applied"] = sorted(
                            matched_provider_labels,
                        )
                entry["category"] = classification.category
                entry["confidence"] = classification.confidence
                # ``source`` is a system label ({"llm","list_rule",
                # "list_hint"}) — never PHI. Persisted both modes
                # so the recipient-digest renderer can map to a
                # fixed phrase under HIPAA mode (Option B
                # redaction) while still showing the verbatim
                # reason in standard mode.
                entry["source"] = classification.source
                # ``date`` is the message's own Date header — a
                # provider-supplied timestamp, not user content.
                # Persisted both modes so the digest's datetime
                # column reflects the original mail's send time
                # rather than the triage run's wall clock.
                try:
                    entry["date"] = (
                        message.date.isoformat() if message.date else ""
                    )
                except Exception:
                    entry["date"] = ""
                # HIPAA: classifier reason is free-form natural language
                # that can echo subject/body PHI ("patient's appointment",
                # test results, etc.). Redact before persisting to
                # triage_runs.results_json. The in-flight log path is
                # already scrubbed by TriageLogger._PHI_KEYS.
                entry["reason"] = (
                    "[redacted]" if account_hipaa else classification.reason
                )

                # Email watches (#100) — match-and-fire BEFORE the
                # per-route action loop. A watch's escalate / webhook
                # is independent of the categorise→route action chain,
                # but it still happens after classification so the
                # match has the category available. Errors in the
                # watch path NEVER block the route-and-act stage —
                # ``fire_watches_for_message`` swallows per-watch
                # failures + always returns a list.
                try:
                    from email_triage.web.watch_runner import (
                        fire_watches_for_message,
                    )
                    watch_results = await fire_watches_for_message(
                        db=db, config=config, secrets=secrets,
                        account=acct,
                        sender=getattr(message, "sender", "") or "",
                        subject=getattr(message, "subject", "") or "",
                        body_text=getattr(message, "body_text", "") or "",
                        category=classification.category,
                        message_id=msg_id,
                        actor_user_id=actor_user_id,
                    )
                    if watch_results:
                        # Persist a compact summary on the per-message
                        # entry so the operator can see what fired in
                        # the run results. No PII — only watch ids,
                        # action mix, and redaction posture.
                        entry["watches_fired"] = [
                            {
                                "watch_id": r["watch_id"],
                                "watch_name": r["watch_name"],
                                "escalate_ok": bool(
                                    (r.get("escalate") or {}).get("ok")
                                ),
                                "webhook_ok": bool(
                                    (r.get("webhook") or {}).get("ok")
                                ),
                                "redaction": r["redaction"],
                            }
                            for r in watch_results
                        ]
                except Exception as _watch_exc:
                    log.warning(
                        "watch fire raised in runner",
                        message_id=msg_id, error=fmt_exc(_watch_exc),
                    )

                actions_taken = []
                _runner_action_defs = routes_by_cat.get(classification.category, [])
                # 2026-05-13 — meeting-request intercept auto-inject.
                # See actions/suggest_meeting_times.py:inject_meeting_intercept.
                # ``calendar_provider`` is the per-account provider built
                # earlier in this function; bool-truthy means calendar
                # was successfully wired for the account.
                try:
                    from email_triage.actions.suggest_meeting_times import (
                        inject_meeting_intercept as _inject_r,
                    )
                    _runner_action_defs = _inject_r(
                        _runner_action_defs, classification.category,
                        calendar_wired=calendar_provider is not None,
                        has_meeting_prefs=bool(meeting_prefs_raw),
                    )
                except Exception:
                    pass
                for action_def in _runner_action_defs:
                    action_name = action_def.get("action", "")
                    action_config = action_def.get("config", {})
                    action = registry.get(action_name)
                    if action is None:
                        continue
                    if dry_run:
                        log.info(
                            "DRY RUN: would execute action",
                            action=action_name,
                            category=classification.category,
                            message_id=msg_id,
                        )
                        actions_taken.append({
                            "name": action_name, "result": "dry_run",
                            "data": None, "error": None,
                        })
                        continue
                    flow = FlowState(
                        flow_id=FlowState.new_id(),
                        message_id=msg_id,
                        provider=acct["provider_type"],
                        status=FlowStatus.ACTING,
                        state_bag={
                            "calendar_provider": calendar_provider,
                            "meeting_prefs": meeting_prefs_raw,
                            "self_email": self_email,
                            # #106 — full set of addresses that route
                            # into this account (primary + aliases).
                            # Actions matching "is this addressed to
                            # me?" should consult this union rather
                            # than ``self_email`` alone.
                            "self_email_addresses": self_email_addresses,
                            "account_id": account_id,
                            "account_name": acct.get("name", ""),
                            "owner": acct.get("owner_name") or acct.get("owner_email", ""),
                            # #73 — SMTP for escalation send.
                            "smtp_config": config.smtp,
                            "secrets": secrets,
                            # #107 — self-sent event triage path.
                            "account": acct,
                            "account_hipaa": account_hipaa,
                            "account_addresses": account_addrs,
                            "self_schedule_calendar_id": self_schedule_calendar_id,
                            "calendar_surrogate_active": calendar_surrogate_active,
                            "db": db,
                            # #129 tail — add-label action needs the
                            # actor for the message_labels.applied_by
                            # column on internal-label writes. Mirrors
                            # how the rule-driven label path above
                            # threads ``actor_user_id`` into
                            # ``apply_labels_to_message``.
                            "actor_user_id": actor_user_id,
                        },
                    )
                    output = await action.execute(
                        flow, message, classification, provider, action_config,
                    )
                    actions_taken.append({
                        "name": action_name,
                        "result": output.result.value,
                        "data": output.data,
                        "error": output.error,
                    })

                entry["actions"] = actions_taken
                entry["status"] = "ok"

            except Exception as e:
                entry["status"] = "error"
                entry["error"] = str(e)
                log.error("Triage error for message", message_id=msg_id, error=fmt_exc(e))

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
    # #139 — drain the classifier's long-lived httpx pool. Classifier
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
        try:
            update_hipaa_access_event(db, audit_event_id, outcome, detail)
        except Exception as e:
            log.warning("Failed to finalize HIPAA access event", error=fmt_exc(e))

    run_id = f"{trigger}_{account_id}_{int(time.time())}"
    try:
        record_triage_run(
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
