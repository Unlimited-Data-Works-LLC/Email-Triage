"""Single shared per-message triage body.

Before this module the "classify one message, then act on it" body
was copy-pasted across FIVE ingestion paths — ``run_triage`` (the UI /
API one-shot), ``_process_one_message`` (the bulk sweeper),
``_watch_account`` (the IMAP IDLE watcher), ``_poll_once_imap`` (the
unified poller) and ``_process_push_item`` (the Gmail push consumer).
The five copies had DRIFTED: rule-driven labels, provider-native
labels and email watches only fired on the ``run_triage``
copy; the watcher / poll / push / bulk copies silently skipped them.

:func:`triage_single_message` is the single invariant body. Every
ingestion path now calls it, so a feature added here lands on every
path at once — the drift is structurally impossible to reintroduce.

What stays in the CALLER (per-path, injected as parameters):

* the message FETCH (each path fetches differently — retry wrappers,
  pre-fetch dedup, batch delivery);
* the in-flight gate lifecycle (``mark_inflight`` / ``release_inflight``
  in the caller's ``try/finally``);
* the high-water-mark advance;
* bulk-job dedup + counters;
* the ``record_triage_run`` cadence (per-message vs end-of-run batch);
* the HIPAA access-audit bookend.

What the helper OWNS (the invariant body):

* self-origin skip — ``X-Email-Triage`` header + ``is_self_origin``;
* the ``$EmailTriaged`` keyword + ``is_triaged`` rfc-id dedup
  (flag-gated — see ``durable_dedup`` / ``keyword_dedup`` below so the
  inline + bulk paths, which do NOT use these gates, keep their
  current behaviour);
* list-hint collection;
* ``classifier.classify``;
* the  rule-driven internal labels apply;
* the  rule-driven provider-native labels apply;
* meeting-request intercept injection;
* the action-execution loop — including  stop-on-failure: a
  ``FAILED`` action breaks the chain so following actions do NOT run;
* ``fire_watches_for_message``;
* assembly of the HIPAA-redacted per-message result ``entry`` dict;
* ``mark_triaged`` post-success rfc-id stamp.
"""

from __future__ import annotations

from email_triage.db._helpers import load_json_col

import json as _json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import REDACTED_PLACEHOLDER, get_logger

log = get_logger("web.triage_one")


@dataclass
class TriageContext:
    """Per-run / per-cycle context shared across every message.

    Built ONCE by the caller (per triage run, per watcher connect, per
    poll cycle, per push delta, per bulk job) and handed unchanged to
    :func:`triage_single_message` for each message. Holds everything
    that does not vary message-to-message.
    """

    # -- Persistence + config -------------------------------------------
    db: sqlite3.Connection
    config: Any
    secrets: Any
    acct: dict

    # -- Pipeline collaborators -----------------------------------------
    classifier: Any
    provider: Any
    registry: Any
    #: Category map / list the classifier sees — whatever
    #: ``_get_categories_from_db`` returns for the account owner.
    categories: Any
    #: ``{category: [ {"action", "config"}, ... ]}`` route map. May be
    #: re-resolved per message by the caller (watcher) — in that case the
    #: caller passes a fresh map via the ``routes_by_cat`` override on
    #: :func:`triage_single_message`.
    routes_by_cat: dict[str, list]

    # -- Classification list hints ---------------------
    list_hints_lists: Any = None
    list_hints_rules_by_list: Any = None

    # -- Rule-driven label maps ---------------------------
    #: ``{rule_id: [label_slug, ...]}`` — install-internal labels.
    rule_labels_map: dict[int, list[str]] = field(default_factory=dict)
    #: ``{rule_id: [{"account_id", "label_slug"}, ...]}`` — provider labels.
    rule_provider_labels_map: dict[int, list[dict]] = field(
        default_factory=dict,
    )

    # -- Calendar context -----------------------------------------------
    calendar_provider: Any = None
    meeting_prefs: Any = None
    self_email: str = ""
    self_email_addresses: set[str] = field(default_factory=set)
    account_addrs: list[str] = field(default_factory=list)
    self_schedule_calendar_id: str | None = None
    calendar_surrogate_active: bool = False

    # -- Behaviour flags ------------------------------------------------
    #: Free-text self-from address for the  secondary self-skip.
    self_from_addr: str = ""
    #: When True, the action loop logs instead of executing.
    dry_run: bool = False
    #: HIPAA redaction posture for the result ``entry`` dict.
    account_hipaa: bool = False
    #: User who initiated the run; ``None`` for system runs. Threaded
    #: into the  label apply + the watch fire + the add-label action.
    actor_user_id: int | None = None
    #: When True, the ``$EmailTriaged`` keyword + ``is_triaged`` rfc-id
    #: gate run inside the helper. The watcher / poll / push paths set
    #: this True (they relied on the gate before ). The inline +
    #: bulk paths leave it False — they never used the gate and  is
    #: a behaviour-preserving refactor for the gates, not a new feature.
    durable_dedup: bool = False
    #: When True, the post-success ``mark_triaged`` rfc-id stamp runs.
    #: Paired with ``durable_dedup`` on the watcher / poll / push paths.
    mark_triaged_on_success: bool = False
    #: When True, an IMAP ``$EmailTriaged`` keyword is set post-success
    #: (only meaningful for IMAP providers).
    set_keyword_on_success: bool = False
    #: When True, fire email watches after classification.
    fire_watches: bool = True
    #: When True (default), the  live Topic-match stage runs after
    #: classify: the just-classified message is matched against the
    #: account's active Topics on ``ctx.classifier`` (so a HIPAA account's
    #: match inherits its local-only classify gate — design §1a) and each
    #: positive becomes a ``topic_hits`` row. Fail-OPEN (§4.4) and skipped
    #: on ``dry_run`` (a preview must not write hits). Default True so the
    #: feature lands on every ingestion path at once (the  invariant).
    match_topics: bool = True


@dataclass
class TriageMessageResult:
    """Outcome of one :func:`triage_single_message` call."""

    #: The HIPAA-redacted per-message result dict (the ``entry``).
    entry: dict[str, Any]
    #: One-letter status mirroring the bulk runner's vocabulary:
    #: ``'p'`` processed, ``'s'`` skipped, ``'e'`` error.
    status: str
    #:  — count of email-watch fires whose escalate / webhook
    #: delivery did NOT succeed on this message. A live-path caller
    #: that sees a non-zero value should enqueue a row in
    #: ``watcher_retry_queue`` so the drainer re-fires the message;
    #: the  ``watch_fire_idempotency`` table ensures only the
    #: not-yet-delivered watches are re-attempted on re-fire. Counted
    #: by the same :func:`email_triage.web.watch_runner._delivered`
    #: predicate the recording-gate uses, so the retry-enqueue check
    #: is bit-identical to the "do not record this fire" check. A
    #: config-skip (no SMTP relay / no notify address) is NOT counted
    #: — re-firing would skip identically. The drainer's own call to
    #: ``triage_single_message`` must NOT enqueue from this value
    #: (it would loop); the drainer is the only caller that ignores
    #: this field.
    unretried_watch_failures: int = 0


def _build_rule_labels_map(db: sqlite3.Connection) -> dict[int, list[str]]:
    """ — ``{rule_id: [label_slug, ...]}`` from ``list_rules.adds_labels``.

    Built once per run. Pre-v18 schema (column missing) yields ``{}``.
    """
    out: dict[int, list[str]] = {}
    try:
        rows = db.execute(
            "SELECT id, adds_labels FROM list_rules "
            "WHERE adds_labels IS NOT NULL"
        ).fetchall()
    except Exception:
        return {}
    for r in rows:
        try:
            parsed = load_json_col(r["adds_labels"], default=[])
        except Exception:
            parsed = []
        if isinstance(parsed, list) and parsed:
            out[int(r["id"])] = [str(s) for s in parsed]
    return out


def _build_rule_provider_labels_map(
    db: sqlite3.Connection,
) -> dict[int, list[dict]]:
    """ — ``{rule_id: [{"account_id", "label_slug"}, ...]}``.

    Parsed from ``list_rules.provider_labels``. Built once per run.
    Pre-v22 schema (column missing) yields ``{}``.

    A1 (census 2026-06-09) — **build-time account-scope gate** (the actuator
    layer). Each entry's ``account_id`` is dropped unless the RULE'S OWNER can
    manage it (owner/delegate/admin). The storage-time gate in
    ``categories.py`` blocks NEW cross-account targets at write; this filter is
    the defense-in-depth at the apply boundary — it additionally neutralizes
    any pre-existing poisoned row OR a future non-handler writer, so the apply
    path (``_apply_rule_provider_labels``) never sees an unauthorized target.
    §164.312(a)(1) at the actuator. (2026-06-09 backfill of the live store was
    CLEAN — zero poison — so this is durable hardening, not active remediation.)
    """
    from email_triage.db.accounts import can_manage_account, get_email_account
    out: dict[int, list[dict]] = {}
    try:
        rows = db.execute(
            "SELECT lr.id, lr.provider_labels, cl.owner_id "
            "FROM list_rules lr "
            "JOIN classification_lists cl ON lr.list_id = cl.id "
            "WHERE lr.provider_labels IS NOT NULL"
        ).fetchall()
    except Exception:
        return {}

    _owner: dict[int, dict | None] = {}
    _manageable: dict[tuple, bool] = {}

    def _owner_can_manage(owner_id, account_id) -> bool:
        key = (owner_id, account_id)
        if key not in _manageable:
            if owner_id not in _owner:
                orow = db.execute(
                    "SELECT id, role FROM users WHERE id = ?", (owner_id,),
                ).fetchone()
                _owner[owner_id] = dict(orow) if orow else None
            owner = _owner[owner_id]
            acct = get_email_account(db, account_id)
            _manageable[key] = bool(
                owner is not None and acct is not None
                and can_manage_account(db, owner, acct)
            )
        return _manageable[key]

    for r in rows:
        try:
            parsed = load_json_col(r["provider_labels"], default=[])
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
                # A1 actuator gate — drop targets the rule-owner can't manage.
                if not _owner_can_manage(r["owner_id"], aid):
                    log.warning(
                        "provider-label apply gate: dropped unmanageable "
                        "target (rule owner cannot manage account)",
                        rule_id=int(r["id"]), account_id=aid,
                    )
                    continue
                cleaned.append({"account_id": aid, "label_slug": slug})
        if cleaned:
            out[int(r["id"])] = cleaned
    return out


def build_default_registry(*, include_add_label: bool, include_self_event: bool):
    """Build the standard :class:`ActionRegistry` for a triage path.

     made the action set uniform across every ingestion path. Before
    the refactor the watcher / poll / push / bulk paths each registered
    a DIFFERENT subset (the bulk + poll paths had no calendar actions at
    all; the watcher + push paths had no ``AddLabel`` / ``SelfSentEvent``).
    There is no correctness reason for the divergence — an action that is
    not in any route never fires — so all five paths now register the
    full set via this one helper.

    ``include_add_label`` / ``include_self_event`` are kept as knobs only
    so a caller could opt out; every in-tree caller passes ``True``.
    """
    from email_triage.actions.registry import ActionRegistry
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.add_label import AddLabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.invite import (
        AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
    )
    from email_triage.actions.suggest_meeting_times import (
        SuggestMeetingTimesAction,
    )
    from email_triage.actions.self_sent_event import SelfSentEventAction
    from email_triage.actions.mute import MuteAction
    from email_triage.actions.regulatory_clock import RegulatoryClockAction

    registry = ActionRegistry()
    registry.register(MoveAction())
    registry.register(LabelAction())
    if include_add_label:
        registry.register(AddLabelAction())
    registry.register(NotifyAction())
    registry.register(DraftReplyAction())
    registry.register(AcceptInviteAction())
    registry.register(DeclineInviteAction())
    registry.register(TentativeInviteAction())
    registry.register(SuggestMeetingTimesAction())
    # Punch 596: `escalate` (EscalateAction, SMTP to an email-to-SMS gateway)
    # is deliberately NOT registered here. It needs a recipient in
    # config["notify_email"] or state_bag["notify_email"]; no web route writer
    # sets either, and the web state_bag carries neither, so on this path it
    # could only ever return SKIPPED. b778e0a60 registered it and offered it in
    # the routes editor without rendering it. Wiring it needs a gated recipient
    # writer and N-567's owner-only-on-HIPAA gate first. cli.py's serve-path
    # registry keeps it (YAML routes can set notify_email). Watch-fired
    # escalation is a separate path (web/email_watches.py, N-567).
    # 2026-07-17 — MuteAction: post-classification marker (see actions/mute.py
    # docstring). Belongs in EVERY live ingestion registry so a route
    # ticking "mute" is honored via watcher / poll / push / bulk. Missing here
    # would ship the "offered-but-unregistered" dead-in-prod shape
    # (incident_2026-06-11) that test_available_actions_in_live_registry pins.
    registry.register(MuteAction())
    #  — the "clock" route action MUST live here (the registry EVERY live
    # ingestion path uses), not only in cli.py's serve-path registry: an action
    # offered in the routes UI but absent here is DEAD in prod (the operator
    # configures it; nothing runs it). The completeness pin
    # test_available_actions_in_live_registry enforces this.
    registry.register(RegulatoryClockAction())
    if include_self_event:
        registry.register(SelfSentEventAction())
    return registry


async def _match_topics_live(
    ctx: "TriageContext",
    message: Any,
    msg_id: str,
    rfc_id: str,
    *,
    db_call: Any,
) -> None:
    """ — match one just-classified message against the account's active
    Topics and persist each positive as a ``topic_hits`` row (``source='live'``).

    The steady-state Topic match (design §1) rides the SAME ``ctx.classifier``
    the message was just classified on, so a HIPAA account's match runs on its
    local-only backend automatically (§1a — the read/match gate is inherited
    per-account, never a Topic-wide override). Mirrors the back-scan's
    match→persist (``jobs/topic_backscan``) for the single live message:

    1. Read the account's active Topics (``list_active_topics_for_account``)
       off the loop via ``db_call``. No Topics ⇒ nothing to match — and NO LLM
       call (the matcher is never invoked), so a mailbox with no Topics pays
       only one small table read per message.
    2. Run the band/K matcher, threading the REAL ``categories``
       (``ctx.categories``) so the topic-match seam's taxonomy gate does not
       fail every verdict open — the  categories-threading bug (see the
       matcher docstring).
    3. UPSERT a hit per matched verdict via ``insert_topic_hit`` on the
       single-writer thread. The ``first_seen_at = MIN`` pin makes a later
       back-scan of the same message idempotent (no double-count).

    Fail-OPEN throughout (§4.4): a flaky GPU / classifier degrades the Topic
    digest, it NEVER blocks core triage. The caller guards ``ctx.match_topics``
    + ``not ctx.dry_run`` + a present ``rfc_id`` and swallows any raise; this
    body additionally isolates each per-hit write so one bad row never sinks
    the rest.
    """
    from email_triage.actions.topic_configs import (
        insert_topic_hit, list_active_topics_for_account,
        normalize_feedback_sender,
    )
    from email_triage.cache.topic_feedback import load_topic_sender_signals
    from email_triage.actions.topic_matcher import match_topics_for_message
    from email_triage.jobs.topic_backscan import (
        _msg_body_keywords, _msg_folder, _msg_provider_uid, _msg_uidvalidity,
        _v_confidence, _v_reason_terms, _v_topic_id,
    )

    db = ctx.db
    account_id = int(ctx.acct["id"])

    topics = await db_call(list_active_topics_for_account, db, account_id)
    if not topics:
        return

    # Never persist a Topic hit for email-triage's OWN generated content
    # (X-Email-Triage). The main triage flow already skips self-origin upstream
    # (the loop-prevention guard), but defense-in-depth here keeps a Topic digest
    # free of self-generated mail for any caller (operator 2026-06-12).
    from email_triage.mail_headers import get_triage_header
    if get_triage_header(getattr(message, "headers", None) or {}):
        return

    verdicts = await match_topics_for_message(
        message, topics, ctx.classifier,
        body_keywords=_msg_body_keywords(message),
        categories=ctx.categories,
    )
    if not verdicts:
        return

    folder = _msg_folder(message)
    provider_uid = _msg_provider_uid(message)
    uidvalidity = _msg_uidvalidity(message)

    # Resolve each verdict's topic_id to one of THIS account's active Topics
    # before writing — never persist a hit for a Topic that isn't watching
    # this account (defensive against a classifier echoing an unexpected id).
    active_ids = [int(getattr(t, "id", 0) or 0) for t in topics]
    active_id_set = set(active_ids)
    #  v3 reinforcement (operator 2026-06-12): a thumbs-DOWN sender is muted
    # for that Topic — never persist a live hit for it. Signals are per-Topic;
    # cache the lookup so a multi-verdict message queries each Topic at most once.
    _fb_sender_key = normalize_feedback_sender(getattr(message, "sender", "") or "")
    _fb_sig_cache: dict[int, dict] = {}
    for v in verdicts:
        tid = _v_topic_id(v)
        if tid is None and len(active_ids) == 1:
            # A one-Topic account whose verdict didn't echo the id back —
            # attribute it to the single watching Topic (mirrors the
            # back-scan's ``_pick_verdict`` tolerance).
            tid = active_ids[0]
        if tid is None or int(tid) not in active_id_set:
            continue
        if _fb_sender_key:
            sigs = _fb_sig_cache.get(int(tid))
            if sigs is None:
                # Cache-aware: OPTIONAL Redis mirror if configured, else the DB.
                sigs = await load_topic_sender_signals(db, int(tid))
                _fb_sig_cache[int(tid)] = sigs
            if sigs.get(_fb_sender_key) == -1:
                continue  # muted sender — skip the live hit
        try:
            await db_call(
                insert_topic_hit, db,
                topic_id=int(tid), account_id=account_id,
                rfc822_message_id=rfc_id, folder=folder,
                provider_uid=provider_uid, uidvalidity=uidvalidity,
                reason_terms=_v_reason_terms(v),
                confidence=_v_confidence(v),
                source="live",
            )
        except Exception as exc:  # noqa: BLE001 — one bad row ≠ block triage
            log.warning(
                "topic hit write failed",
                message_id=msg_id, topic_id=tid, error=fmt_exc(exc),
            )


async def triage_single_message(
    ctx: TriageContext,
    message: Any,
    msg_id: str,
    *,
    routes_by_cat: dict[str, list] | None = None,
) -> TriageMessageResult:
    """Classify + act on one already-fetched message.

    This is the single invariant per-message body shared by all five
    ingestion paths. The caller is responsible for fetching
    ``message`` and for everything listed in the module docstring;
    everything else lives here.

    Parameters
    ----------
    ctx:
        Per-run context — see :class:`TriageContext`.
    message:
        The already-fetched :class:`EmailMessage`. ``message.hipaa`` is
        stamped by this function from ``ctx.account_hipaa``.
    msg_id:
        The provider message id / UID, used for logging + the result
        ``entry``.
    routes_by_cat:
        Optional per-message route-map override. The IMAP IDLE watcher
        re-resolves routes per message (it is a long-lived coroutine
        with no cycle boundary); it passes a fresh map here. Every other
        caller omits this and ``ctx.routes_by_cat`` is used.

    Returns
    -------
    TriageMessageResult
        ``.entry`` is the HIPAA-redacted result dict; ``.status`` is one
        of ``'p'`` / ``'s'`` / ``'e'``.
    """
    import asyncio

    from email_triage.engine.models import (
        ActionResult, FlowState, FlowStatus,
    )
    from email_triage.mail_headers import get_triage_header, is_self_origin
    from email_triage.web.routers.ui import _collect_list_hints_for_message
    # #239a — every sync DB helper in this body touches the SHARED
    # connection. Called inline on whatever event loop the caller runs,
    # the SQLite work + the @db_write lock-acquire block that loop
    # thread. Route each through ``db_call`` so it runs off the loop
    # under the process-wide DB lock — consistent with the rest of the
    # ingestion paths post-#236.
    from email_triage.web.db_threadpool import db_call

    db = ctx.db
    acct = ctx.acct
    account_id = acct["id"]
    account_hipaa = ctx.account_hipaa
    routes = routes_by_cat if routes_by_cat is not None else ctx.routes_by_cat

    entry: dict[str, Any] = {"message_id": msg_id}

    try:
        message.hipaa = account_hipaa
        #  — stamp account_id + force_reclassify so the
        # classification cache lookup is per-account-isolated.
        if getattr(message, "raw_metadata", None) is None:
            try:
                message.raw_metadata = {}
            except Exception:
                pass
        if isinstance(getattr(message, "raw_metadata", None), dict):
            message.raw_metadata["account_id"] = int(account_id)

        if not account_hipaa:
            entry["sender"] = message.sender
            entry["subject"] = message.subject

        # -- Self-origin skip -------------------------------------------
        # Loop-prevention: skip mail email-triage itself generated.
        # Digests / draft replies / OTP / health email all carry the
        # X-Email-Triage header; re-triaging them cascades into more
        # outbound mail.
        et_header = get_triage_header(getattr(message, "headers", {}) or {})
        if et_header:
            log.info(
                "Skipping re-triage of email-triage-generated message",
                message_id=msg_id, x_email_triage=et_header,
                skip_reason="self_origin",
            )
            entry["status"] = "skipped"
            entry["skip_reason"] = "x_email_triage_header"
            entry["reason"] = "self_origin"
            entry["x_email_triage"] = et_header
            return TriageMessageResult(entry=entry, status="s")
        # Defense in depth: downstream MTA may have stripped the
        # header. Match on sender == install's smtp.from_addr.
        if is_self_origin(getattr(message, "sender", "") or "", ctx.self_from_addr):
            log.info(
                "Skipping self-origin message (header missing)",
                message_id=msg_id, skip_reason="self_origin",
            )
            entry["status"] = "skipped"
            entry["skip_reason"] = "self_from_match"
            entry["reason"] = "self_origin"
            return TriageMessageResult(entry=entry, status="s")

        # -- RFC 5322 Message-ID ----------------------------------------
        # Resolved once, unconditionally. The durable dedup gate below
        # uses it (flag-gated), and the  watch-fire stage uses it as
        # the idempotency key ( Bug 2 — the provider ``msg_id`` for
        # IMAP is a mailbox-scoped UID that collides across folders /
        # UIDVALIDITY epochs; the RFC Message-ID is mail-global).
        from email_triage.mail_headers import get_rfc_message_id
        _rfc_id = get_rfc_message_id(getattr(message, "headers", {}) or {})

        # -- Durable dedup gates (flag-gated) ---------------------------
        # The watcher / poll / push paths relied on these before .
        # The inline + bulk paths never used them — ctx.durable_dedup
        # stays False there so  is behaviour-preserving for them.
        if ctx.durable_dedup:
            # IMAP $EmailTriaged keyword sentinel — survives COPY into
            # watched destination folders.
            if "$EmailTriaged" in (getattr(message, "labels", None) or []):
                log.info(
                    "Skipping already-triaged message (keyword sentinel)",
                    message_id=msg_id,
                )
                entry["status"] = "skipped"
                entry["skip_reason"] = "keyword_sentinel"
                entry["reason"] = "already_triaged"
                return TriageMessageResult(entry=entry, status="s")
            # Cross-folder dedup: same RFC Message-Id seen before (any
            # folder, this account) → skip.
            if _rfc_id:
                from email_triage.web.db import is_triaged
                if await db_call(is_triaged, db, account_id, _rfc_id):
                    log.info(
                        "Skipping already-triaged message (rfc_id dedup)",
                        message_id=msg_id,
                    )
                    entry["status"] = "skipped"
                    entry["skip_reason"] = "rfc_id_dedup"
                    entry["reason"] = "already_triaged"
                    return TriageMessageResult(entry=entry, status="s")

        # -- Classify ---------------------------------------------------
        #  — list-hint matching is pure in-memory when ctx is
        # preloaded (lists + rules_by_list both supplied), but routed
        # off-loop via db_call to remove the fragile contract dependency
        # on every TriageContext caller setting those fields. The
        # TriageContext dataclass accepts None as a default, so a future
        # ingestion path that misses the preload would silently regress
        # to an on-loop DB read on the per-message hot path
        # (_collect_list_hints_for_message falls back to
        # _load_all_list_hints(db) when either kwarg is None).
        # Dispatching unconditionally costs one threadpool hop per
        # message (~10-50μs) and makes the helper correct-by-construction
        # regardless of caller.
        hints = await db_call(
            _collect_list_hints_for_message,
            db, message,
            lists=ctx.list_hints_lists,
            rules_by_list=ctx.list_hints_rules_by_list,
        )
        # N-113 — HIPAA + BAA egress CHOKEPOINT (§164.308(b)(1), PD#5). EVERY
        # ingestion + runner path funnels through this one function to classify;
        # only run_triage gated at ctx-build, so poll/push/watcher/sweeper/bulk
        # reached ctx.classifier.classify (and the downstream Topic match at
        # _match_topics_live) with a HIPAA account's PHI UN-gated. Gate the SHARED
        # consumer ONCE so all paths fail closed on an external, non-BAA'd
        # classifier for a HIPAA message — covering the primary classify here AND
        # the Topic match below. No-op for the common local / BAA-acked classifier
        # (baa_block_status returns None). The shared decision SSOT, same as the
        # back-scan job + the Topic preview.
        if account_hipaa:
            from email_triage.classify.baa_gate import baa_block_status
            _baa_block = await db_call(baa_block_status, db, ctx.classifier, True)
            if _baa_block is not None:
                log.warning(
                    "triage_single_message: classify BLOCKED for HIPAA account "
                    f"{account_id} — classifier {_baa_block.get('backend')} @ "
                    f"{_baa_block.get('host') or '?'} is not BAA-acked; skipped "
                    "(no PHI egress, N-113).",
                    message_id=msg_id,
                )
                entry["status"] = "skipped"
                entry["skip_reason"] = "baa_required"
                entry["reason"] = "hipaa_baa_required"
                return TriageMessageResult(entry=entry, status="s")
        classification = await ctx.classifier.classify(
            message, ctx.categories, hints or None,
        )

        # --  regulatory-clock detection (flag-OFF default) ----------
        # Stage-A recall gate → Stage-B local-Ollama confirm → a CANDIDATE
        # clock for human propose-then-confirm. Gated on the detection flag AND
        # ``not ctx.dry_run`` (it writes a candidate = a side effect, N-61).
        # Fully FAIL-SOFT: the orchestrator swallows all errors → None, and the
        # whole block is also try/except'd, so a detector miss NEVER blocks core
        # triage (§4.4). The orchestrator is async-on-the-loop (LLM I/O) and
        # returns a SPEC; the @db_write candidate insert runs OFF the loop via
        # db_call so it can't block the event loop on the writer lock.
        if not ctx.dry_run and getattr(
            getattr(ctx.config, "regulatory_clock", None),
            "detection_enabled", False,
        ):
            try:
                from email_triage.classify.safety_detect import (
                    create_clock_candidate_from_detection,
                    detect_regulatory_clock,
                )
                _match = await detect_regulatory_clock(
                    message, ctx.classifier,
                    account_id=account_id, detection_enabled=True,
                )
                if _match is not None:
                    # The def-resolve + keyed-hash salt + candidate INSERT all
                    # run OFF the event loop (F1) under the  writer RLock.
                    await db_call(
                        create_clock_candidate_from_detection,
                        ctx.db, ctx.secrets, _match,
                    )
            except Exception:
                # Belt-and-suspenders: the orchestrator is already fail-soft.
                # But a swallow with NO signal loses more than a state row:
                # `create_clock_candidate` writes the instance row and emits
                # the chained `detected` event ATOMICALLY (regulatory_clock.py
                # :951 -> record_clock_event, @db_write @audit_emitter), and
                # this `except` sits ABOVE the emitter — so a whole-call
                # failure means the `audit_gap_events` backstop never runs
                # (there was no emit to fall back from). Log, then stay
                # fail-soft (the triage run must not die for a candidate row).
                #
                # The wording is deliberately CONDITIONAL: this `try:` also
                # covers the import and the detect call above, so an
                # ImportError or a writer-not-started RuntimeError arrives
                # here with no detection and no lost deadline. Asserting "after
                # a confirmed detection" would make this ERROR row itself false
                # — the defect the rest of this commit removes — and would pin
                # daily_health to Attention for 24h on a false premise.
                #
                # message_id/account_id make the loss RECOVERABLE (§164.308(a)
                # (1)(ii)(D) review, not just §164.312(b) record): without them
                # the row proves a deadline was lost but not WHICH one. Both
                # are in `_PERSIST_SAFE_KEYS`, so they survive HIPAA-mode
                # redaction into extra_json and do NOT reach the daily-health
                # email, which selects the `message` column only.
                #
                # PD#10 / N-332: TriageLogger.warning is (msg, *args, **extra)
                # with NO exc_info parameter — only .error()/.critical()/.log()
                # thread it — so exc_info there is silently kept as a log FIELD,
                # not a traceback. `.exception()` is the documented
                # error(msg, exc_info=True) parity helper. ERROR, not WARNING:
                # daily_health counts warning_count_24h but appends no attention
                # reason for it, so WARNING would re-create the silent-PASS
                # shape one level quieter.
                log.exception(
                    "regulatory-clock: candidate path raised; if a detection "
                    "was confirmed, its deadline has NOT been recorded",
                    message_id=msg_id,
                    account_id=account_id,
                )

        # --  rule-driven internal labels ---------------------------
        # #239a — the helper's body is cheap pure-Python rule matching
        # plus one @db_write (``apply_labels_to_message``). Dispatch the
        # whole helper through ``db_call`` so the write — and its
        # lock-acquire — runs off the event loop. The helper only
        # mutates ``entry`` (forwarded by reference) and the awaited
        # dispatch fully serialises that mutation before we read on.
        # N-61 (Loop-5 census) — a dry_run/preview MUST apply no side effects:
        # no internal/provider labels, no watch escalations/webhooks, no IMAP
        # keyword, no dedup stamp. Gate every side-effecting stage on ``not
        # ctx.dry_run`` (the action loop L735 + topic-match L683 already are).
        if not ctx.dry_run:
            await db_call(
                _apply_rule_internal_labels,
                ctx, message, msg_id, entry, classification,
            )

            # --  rule-driven provider-native labels ----------------
            await _apply_rule_provider_labels(
                ctx, message, msg_id, entry, classification,
            )

        entry["category"] = classification.category
        entry["confidence"] = classification.confidence
        entry["source"] = classification.source
        try:
            entry["date"] = (
                message.date.isoformat()
                if getattr(message, "date", None) else ""
            )
        except Exception:
            entry["date"] = ""
        # HIPAA: classifier reason is free-form natural language that can
        # echo subject/body PHI. Redact before persisting.
        entry["reason"] = (
            REDACTED_PLACEHOLDER if account_hipaa else classification.reason  # N-217c R23
        )

        # -- Email watches ---------------------------------------
        # Match-and-fire BEFORE the per-route action loop. Errors NEVER
        # block the route-and-act stage.
        unretried_watch_failures = 0
        # N-61 — watch-fire sends REAL escalations (SMTP/SMS) + webhook POSTs;
        # a preview must never trigger them. ``not ctx.dry_run`` gate.
        if ctx.fire_watches and not ctx.dry_run:
            try:
                from email_triage.web.watch_runner import (
                    _delivered as _watch_delivered,
                    fire_watches_for_message,
                )
                watch_results = await fire_watches_for_message(
                    db=db, config=ctx.config, secrets=ctx.secrets,
                    account=acct,
                    sender=getattr(message, "sender", "") or "",
                    subject=getattr(message, "subject", "") or "",
                    body_text=getattr(message, "body_text", "") or "",
                    category=classification.category,
                    message_id=msg_id,
                    #  Bug 2 — idempotency keyed on the RFC 5322
                    # Message-ID, not the mailbox-scoped provider id.
                    idempotency_key=_rfc_id,
                    actor_user_id=ctx.actor_user_id,
                )
                if watch_results:
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
                    #  — count non-delivered fires using the SAME
                    # predicate `fire_watches_for_message` uses to gate
                    # the `_record_watch_fired` write (the recording
                    # gate). DRY guarantees the live-path retry-enqueue
                    # check fires iff the recording gate skipped — i.e.
                    # iff the next drainer pass would re-attempt.
                    # `_delivered` excludes config-skips (no SMTP relay
                    # / no notify_email) — those are not delivery
                    # failures, a re-fire would skip identically.
                    unretried_watch_failures = sum(
                        1 for r in watch_results
                        if not _watch_delivered(r)
                    )
                    if unretried_watch_failures:
                        log.warning(
                            "watch fire(s) did not deliver — caller "
                            "should enqueue retry",
                            message_id=msg_id,
                            failed_count=unretried_watch_failures,
                            total=len(watch_results),
                        )
            except Exception as _watch_exc:
                log.warning(
                    "watch fire raised in triage_single_message",
                    message_id=msg_id, error=fmt_exc(_watch_exc),
                )

        # --  Topic match (live path; design §1) ---------------------
        # Match the just-classified message against the account's active
        # Topics on the SAME classifier (HIPAA → local, gate inherited §1a)
        # and record each positive as a topic_hits row — the steady-state
        # match that feeds the Topic digest. Fail-OPEN: a degraded match
        # NEVER blocks core triage. Skipped on dry-run (a preview must not
        # write hits), when the caller opts out (ctx.match_topics), or when
        # the message has no durable RFC Message-ID to key a hit on.
        if ctx.match_topics and not ctx.dry_run and _rfc_id:
            try:
                await _match_topics_live(
                    ctx, message, msg_id, _rfc_id, db_call=db_call,
                )
            except Exception as _topic_exc:  # noqa: BLE001 — never block triage
                log.warning(
                    "topic match raised in triage_single_message",
                    message_id=msg_id, error=fmt_exc(_topic_exc),
                )

        # -- Action loop -------------------------
        actions_taken: list[dict] = []
        action_defs = list(routes.get(classification.category, []))
        # Meeting-request intercept auto-inject.
        try:
            from email_triage.actions.suggest_meeting_times import (
                inject_meeting_intercept,
            )
            action_defs = inject_meeting_intercept(
                action_defs, classification.category,
                calendar_wired=ctx.calendar_provider is not None,
                has_meeting_prefs=bool(ctx.meeting_prefs),
            )
        except Exception:
            # Best-effort intercept; never block the route path.
            pass

        action_failed = False  #  — surface a FAILED action to the caller
        for action_def in action_defs:
            if isinstance(action_def, dict):
                action_name = action_def.get("action", "")
                action_config = action_def.get("config", {})
            else:
                action_name = str(action_def)
                action_config = {}
            if not action_name:
                continue
            action = ctx.registry.get(action_name)
            if action is None:
                #  — an action wired to a category but absent from
                # the registry was silently dropped. A typo'd action
                # name in a category's route config would then just
                # quietly do nothing. Log it so the misconfiguration
                # is visible.
                log.warning(
                    "skipping unregistered action",
                    action=action_name,
                    category=classification.category,
                    message_id=msg_id,
                )
                continue
            if ctx.dry_run:
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
                    "calendar_provider": ctx.calendar_provider,
                    "meeting_prefs": ctx.meeting_prefs,
                    "self_email": ctx.self_email,
                    "self_email_addresses": ctx.self_email_addresses,
                    "account_id": account_id,
                    "account_name": acct.get("name", ""),
                    "owner": acct.get("owner_name") or acct.get(
                        "owner_email", "",
                    ),
                    "smtp_config": getattr(ctx.config, "smtp", None),
                    "secrets": ctx.secrets,
                    "account": acct,
                    "account_hipaa": account_hipaa,
                    "account_addresses": ctx.account_addrs,
                    "self_schedule_calendar_id": ctx.self_schedule_calendar_id,
                    "calendar_surrogate_active": ctx.calendar_surrogate_active,
                    "db": db,
                    "actor_user_id": ctx.actor_user_id,
                    "config": ctx.config,
                },
            )
            output = await action.execute(
                flow, message, classification, ctx.provider, action_config,
            )
            actions_taken.append({
                "name": action_name,
                "result": output.result.value,
                "data": output.data,
                "error": output.error,
            })
            #  — stop-on-failure. A FAILED action breaks the chain;
            # subsequent actions do NOT run. Mirrors FlowEngine.
            # route_and_act. Without this, e.g. [label, move, draft_reply]
            # where ``move`` fails still drafts a reply.
            if output.result == ActionResult.FAILED:
                log.warning(
                    "Action failed — halting action chain (#198)",
                    message_id=msg_id, action=action_name,
                    error=output.error,
                )
                action_failed = True
                break

        entry["actions"] = actions_taken

        #  — a FAILED action means the message was NOT fully
        # processed. Returning ``status='p'`` here would dedup-stamp
        # it, advance the cursor, and lose it forever. Return
        # ``status='e'`` instead so the caller enqueues a retry; the
        # durable action_idempotency store makes the
        # already-succeeded earlier actions in the chain safe to
        # re-run on the retry. The dedup stamp + keyword sentinel
        # below are deliberately SKIPPED on the failure path.
        if action_failed:
            entry["status"] = "error"
            entry["error"] = (
                "action chain halted on a failed action"
            )
            return TriageMessageResult(
                entry=entry, status="e",
                unretried_watch_failures=unretried_watch_failures,
            )

        entry["status"] = "ok"

        # -- Post-success dedup stamp -----------------------------------
        # N-61 — dry_run is "poll-but-don't-ACT": classify + record the run +
        # advance the cursor + record PROCESSING, but take no actions. So the
        # install-internal ``mark_triaged`` rfc_id dedup STAYS (the caller
        # advances the durable cursor on status="p" in dry_run too — db-sme
        # trace; keeping the stamp coherent with that avoids the DA MF-1
        # dedup/cursor inconsistency, and the DB dedup covers replay). The IMAP
        # ``$EmailTriaged`` keyword below, by contrast, is a LIVE-MAILBOX
        # mutation (an ACTION) → suppressed in dry_run.
        if ctx.mark_triaged_on_success and _rfc_id:
            try:
                from email_triage.web.db import mark_triaged
                # #239a — @db_write helper; dispatch off-loop.
                await db_call(mark_triaged, db, account_id, _rfc_id)
            except Exception:
                pass
        if (ctx.set_keyword_on_success and not ctx.dry_run
                and acct.get("provider_type") == "imap"):
            try:
                await ctx.provider.set_keywords(msg_id, ["$EmailTriaged"])
            except Exception:
                # Best-effort. Not every IMAP server allows custom
                # keywords; rfc_id dedup is the primary guard.
                pass

        return TriageMessageResult(
            entry=entry, status="p",
            unretried_watch_failures=unretried_watch_failures,
        )

    except asyncio.CancelledError:
        # Cooperative shutdown — never swallow.
        raise
    except Exception as e:
        #  — LLM-unreachable failures are upstream-infra weather,
        # not a per-message bug. The watcher / poll / push callers have
        # bespoke retry-queue + maintenance-window handling keyed on
        # this exception type, so it must propagate rather than be
        # collapsed into a generic ``status='e'`` entry. The caller's
        # ``except`` block owns it.
        from email_triage.llm_health import LLMBackendUnreachableError
        if isinstance(e, LLMBackendUnreachableError):
            raise
        #  tail — see the sibling site at triage_runner.py:513 for
        # the class rationale (results-entry ``entry["error"]`` shown to
        # user via triage-completed webhook / UI must be scrub_exc'd).
        from email_triage.web._flash import scrub_exc
        entry["status"] = "error"
        entry["error"] = scrub_exc(e, purpose="triage")
        log.error(
            "Triage error for message",
            message_id=msg_id, error=fmt_exc(e),
        )
        return TriageMessageResult(entry=entry, status="e")


def _apply_rule_internal_labels(
    ctx: TriageContext, message: Any, msg_id: str,
    entry: dict, classification: Any,
) -> None:
    """ — attach rule-driven install-internal labels.

    For every rule that matches this message, union its ``adds_labels``
    set + attach via ``apply_labels_to_message``. Additive only — labels
    never override the LLM category.
    """
    if not ctx.rule_labels_map or not ctx.list_hints_rules_by_list:
        return
    from email_triage.classify.hints import _rule_matches

    matched_label_slugs: set[str] = set()
    for _bucket in ctx.list_hints_rules_by_list.values():
        for _rule in _bucket:
            slugs = ctx.rule_labels_map.get(_rule.id)
            if not slugs:
                continue
            if _rule_matches(_rule, message):
                matched_label_slugs.update(slugs)
    if not matched_label_slugs:
        return
    try:
        from email_triage.web.db import apply_labels_to_message
        apply_labels_to_message(
            ctx.db, msg_id, ctx.acct["id"],
            sorted(matched_label_slugs),
            applied_by_actor=ctx.actor_user_id,
        )
        entry["labels_applied"] = sorted(matched_label_slugs)
    except Exception as _lbl_exc:
        log.warning(
            "rule-driven label apply failed",
            message_id=msg_id, error=fmt_exc(_lbl_exc),
        )


async def _apply_rule_provider_labels(
    ctx: TriageContext, message: Any, msg_id: str,
    entry: dict, classification: Any,
) -> None:
    """ — apply rule-driven provider-native labels.

    Each rule may carry ``provider_labels`` entries
    (``{"account_id", "label_slug"}``); for each entry whose account_id
    matches THIS message's account, call ``provider.apply_label``. The
    per-account filter is the linchpin: a rule shared across accounts
    only fires on the matching mailbox.
    """
    if not ctx.rule_provider_labels_map or not ctx.list_hints_rules_by_list:
        return
    from email_triage.classify.hints import _rule_matches

    account_id = ctx.acct["id"]
    matched_provider_labels: set[str] = set()
    for _bucket in ctx.list_hints_rules_by_list.values():
        for _rule in _bucket:
            entries_pl = ctx.rule_provider_labels_map.get(_rule.id)
            if not entries_pl:
                continue
            if not _rule_matches(_rule, message):
                continue
            for pl_entry in entries_pl:
                if int(pl_entry.get("account_id", -1)) == account_id:
                    label_slug = pl_entry.get("label_slug", "")
                    if label_slug:
                        matched_provider_labels.add(label_slug)
    if not matched_provider_labels:
        return
    # §164.502(e) egress gate via the SSOT — in HIPAA mode the provider
    # write is skipped so a PHI-adjacent label string never leaves the
    # perimeter. The gate input goes through the one resolver (message
    # stamp + system flag + per-account flag, most-restrictive) so it
    # can't drift vs LabelAction / AddLabelAction.
    from email_triage.actions.provider_labels import (
        push_provider_labels,
        resolve_label_hipaa,
    )

    hipaa = resolve_label_hipaa(message=message, account=ctx.acct)
    applied, skipped, errors = await push_provider_labels(
        ctx.provider, msg_id, sorted(matched_provider_labels), hipaa=hipaa,
    )
    if applied:
        entry["provider_labels_applied"] = applied
    if skipped and hipaa:
        entry["provider_labels_skipped_hipaa"] = skipped
        # PHI-free log: message_id (opaque uid) + label slugs only — no
        # sender/subject fields here (do not add any; this site does not
        # route through build_action_log_extras' HIPAA redaction).
        log.info(
            "rule provider labels skipped (HIPAA mode)",
            message_id=msg_id, labels=skipped,
        )
    elif skipped:
        log.debug(
            "provider.apply_label unsupported",
            provider=getattr(ctx.provider, "name", "?"),
            labels=skipped,
        )
    for _lbl, _detail, _exc in errors:
        log.warning(
            "provider label apply failed",
            message_id=msg_id, label=_lbl, error=_detail,
        )
