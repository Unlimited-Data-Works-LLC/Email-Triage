"""Trigger watchers for the HIPAA M-3 + M-7 distill queues (#171-B).

The W2-β + W3 work shipped the DATA plane: the distill modules
(:mod:`distill_hipaa`, :mod:`per_contact_hipaa`), the audit/queue
tables, and the worker contract (existing queue worker drains the
``style_distill_queue`` + ``style_distill_queue_contacts`` rows).

What was missing — and what this module ships — is the
**trigger plane**: the logic that decides "this account / this
(account, recipient) pair has crossed a condition that warrants a
fresh distill" and enqueues a row.

Conditions
==========

M-3 (account-level)
-------------------

  1. **First-time trigger.** No prior successful
     :data:`style_distill_events` row at all for this account
     (``kind='account_m3' AND outcome='success'``). Fires once after
     the operator flips M-1 (per-account opt-in) on.
  2. **N=20 new sent messages.** Since the last successful distill,
     the account has accumulated ≥20 outbound messages (tracked via
     the v29 :func:`hipaa_send_counters` aggregate row).
  3. **Stale trigger.** Last successful distill is older than
     :data:`STYLE_DISTILL_STALE_TRIGGER_DAYS` (7 days). Refresh
     descriptor so it doesn't drift.

M-7 (per-contact)
-----------------

  1. **N=20 per-recipient.** The
     ``hipaa_send_counters`` row for ``(account_id, recipient_hash)``
     has reached :data:`HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES`
     (20). Same threshold constant the spec calls out.
  2. **Stale trigger.** Last successful per-contact distill is older
     than :data:`HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS` (30 days).
     Refresh the overlay.

Idempotency
===========

Both watchers skip enqueueing when:

  * The queue (``style_distill_queue`` for M-3,
    ``style_distill_queue_contacts`` for M-7) already holds a row
    for the key. The existing row's exponential-backoff schedule
    drives the worker; double-enqueueing would reset progress.
  * The account is paused (``paused=1``). Operator intervention
    required to unpause.

The threshold-reset action — :func:`reset_hipaa_send_counter` — fires
AFTER the enqueue lands. The next N=20 detection therefore starts
from zero on a fresh window, preventing immediate re-trigger after
the queue row is processed + cleared.

Privacy invariants
==================

  * No plaintext recipient address EVER reaches this module's public
    surface. The watcher reads pre-hashed counter rows + audit rows
    that store only the hash. The hash function is centralised in
    :func:`email_triage.style_learning.hash_recipient_for_install`
    (re-used at the upstream call site that increments the counter).
  * The HIPAA gate runs once per account at the top of each watcher
    cycle. Non-HIPAA accounts + opted-out accounts get no work
    queued — defence-in-depth atop the distill function's own gate.

Watcher entrypoint
==================

Production caller is the background task
``_style_distill_trigger_sweeper`` in :mod:`email_triage.web.app`,
which ticks every 15 minutes (see the lifespan section). Each tick:

  1. Calls :func:`enqueue_m3_triggers(conn)`.
  2. Calls :func:`enqueue_m7_triggers(conn)`.
  3. Stamps ``app.state.style_trigger_sweep_status`` for /health/detail.

For local debugging + ad-hoc operator runs, the same entrypoints can
be invoked directly from a Python REPL with an open DB connection.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from email_triage.triage_logging import is_account_hipaa
from email_triage.web.db import (
    HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES,
    HIPAA_SEND_COUNTER_AGGREGATE_HASH,
    enqueue_style_distill_contact_retry,
    enqueue_style_distill_retry,
    get_hipaa_send_counter,
    get_style_distill_contact_queue_entry,
    get_style_distill_queue_entry,
    is_hipaa_style_distill_enabled,
    is_style_knobs_hipaa_allow,
    last_successful_style_distill_at,
    list_hipaa_per_contact_counters,
    reset_hipaa_send_counter,
)

log = logging.getLogger("email_triage.style_learning.trigger_watcher")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Threshold (in new outbound messages) past which an account-level
#: M-3 distill is triggered. Mirrors the per-contact constant for
#: consistency; the spec calls out N=20 for both surfaces.
HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES = 20

#: Stale-refresh window for account-level M-3 distills. After this
#: many days since the last success, the watcher enqueues a refresh
#: regardless of message count. Matches the project's weekly cadence.
STYLE_DISTILL_STALE_TRIGGER_DAYS = 7

#: Stale-refresh window for per-contact M-7 distills. Longer than the
#: account-level window because per-contact descriptors are an overlay
#: + the volume per contact is lower. 30 days aligns with the freshness
#: gate at draft-time (``HIPAA_PER_CONTACT_FRESHNESS_DAYS=30``); after
#: this point the overlay is no longer applied at draft anyway, so
#: refreshing it any later would just keep stale data alive.
HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS = 30


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

@dataclass
class TriggerDecision:
    """One trigger evaluation outcome. Used by both M-3 + M-7 paths.

    For M-3 rows, ``recipient_hash`` is None.
    For M-7 rows, ``recipient_hash`` is the 64-hex SHA-256 digest.
    """

    account_id: int
    recipient_hash: str | None
    should_enqueue: bool
    reason: str
    counter: int = 0
    last_success_at: str | None = None


@dataclass
class TriggerSweepSummary:
    """Aggregate result of one watcher tick. Stamped on
    ``app.state.style_trigger_sweep_status`` for /health/detail.
    """

    ts: str
    m3_evaluated: int = 0
    m3_enqueued: int = 0
    m7_evaluated: int = 0
    m7_enqueued: int = 0
    m3_reasons: dict[str, int] = None  # type: ignore[assignment]
    m7_reasons: dict[str, int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.m3_reasons is None:
            self.m3_reasons = {}
        if self.m7_reasons is None:
            self.m7_reasons = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    """Indirect for tests."""
    return datetime.now(timezone.utc)


def _parse_iso(ts: str | None) -> datetime | None:
    """Tolerant ISO8601 parse. Returns None on any error so a corrupt
    timestamp on a single row doesn't blow up the whole sweep."""
    if not ts:
        return None
    try:
        out = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if out.tzinfo is None:
        out = out.replace(tzinfo=timezone.utc)
    return out


def _eligible_hipaa_accounts(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return account rows that may have a distill enqueued.

    Gates applied (in order, cheapest first):

      1. Install-wide HIPAA distill flag on
         (:func:`is_hipaa_style_distill_enabled`).
      2. Account row exists + is HIPAA-flagged.
      3. Per-account M-1+M-2 opt-in is on
         (:func:`is_style_knobs_hipaa_allow`).

    Returns ``[]`` short-circuit when the install-wide flag is off.

    The list excludes soft-deleted accounts. We DON'T filter on
    BAA-expiry here — the distill function's own gate handles that
    (and surfaces the right outcome via the audit row). Filtering
    here would silently skip accounts that just need a BAA renewal
    notice + obscure the operator's surface.
    """
    if not is_hipaa_style_distill_enabled(conn):
        return []
    rows = conn.execute(
        "SELECT id, hipaa, user_id, name "
        "FROM email_accounts "
        "WHERE COALESCE(is_active, 1) = 1 "
        "  AND COALESCE(hipaa, 0) = 1"
    ).fetchall()
    out: list[dict] = []
    for row in rows:
        acct = {
            "id": int(row["id"]),
            "hipaa": int(row["hipaa"] or 0),
            "user_id": row["user_id"],
            "name": row["name"] if hasattr(row, "keys") else None,
        }
        # is_account_hipaa also handles the install-wide HIPAA mode;
        # the SQL filter is the row's own flag, this is the canonical
        # gate that callers downstream use.
        if not is_account_hipaa(acct):
            continue
        if not is_style_knobs_hipaa_allow(conn, acct["id"]):
            continue
        out.append(acct)
    return out


def _is_already_queued_account(
    conn: sqlite3.Connection, account_id: int,
) -> tuple[bool, bool]:
    """Return ``(has_row, is_paused)`` for the account-level queue.

    ``has_row=True`` covers any state — pending retry, final-attempt
    leftover (next_retry_at=NULL), or paused. The watcher skips
    enqueueing on any non-None row so the existing exponential-
    backoff state isn't reset.

    Paused rows have ``has_row=True`` AND ``is_paused=True`` so the
    caller can distinguish "operator paused" from "auto-retry in
    flight" in the sweep summary.
    """
    row = get_style_distill_queue_entry(conn, account_id=account_id)
    if row is None:
        return (False, False)
    return (True, bool(row.get("paused")))


def _is_already_queued_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> tuple[bool, bool]:
    """Sibling of :func:`_is_already_queued_account` for the per-contact queue."""
    row = get_style_distill_contact_queue_entry(
        conn, account_id=account_id, recipient_hash=recipient_hash,
    )
    if row is None:
        return (False, False)
    return (True, bool(row.get("paused")))


# ---------------------------------------------------------------------------
# M-3 (account-level) trigger evaluation
# ---------------------------------------------------------------------------

def evaluate_m3_trigger_for_account(
    conn: sqlite3.Connection, account_id: int,
    *, now: datetime | None = None,
) -> TriggerDecision:
    """Decide whether ``account_id`` warrants an M-3 distill enqueue.

    Pure-DB function: no provider calls, no LLM calls, no clock side
    effects. ``now`` is injectable for tests.

    Decision order
    --------------

      1. Already queued (any state) → skip with ``reason='already_queued'``.
      2. No prior successful distill → enqueue with ``reason='first_time'``.
      3. Last success older than 7 days → enqueue with ``reason='stale'``.
      4. Counter ≥ 20 → enqueue with ``reason='threshold_reached'``.
      5. None of the above → skip with ``reason='no_trigger'``.

    Note: gates (HIPAA, opted-in, install flag) are NOT re-checked here
    — the caller filters via :func:`_eligible_hipaa_accounts`. This
    function trusts its input.
    """
    now = now or _now()

    has_row, _is_paused = _is_already_queued_account(conn, account_id)
    if has_row:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=None,
            should_enqueue=False,
            reason="already_queued",
        )

    last_success = last_successful_style_distill_at(
        conn, account_id=account_id, kind="account_m3",
    )

    if last_success is None:
        # First-time trigger — operator just enabled M-1 (or no
        # success has ever landed). Schedule the first distill.
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=None,
            should_enqueue=True,
            reason="first_time",
            last_success_at=None,
        )

    parsed_last = _parse_iso(last_success)
    if parsed_last is not None:
        age = now - parsed_last
        if age >= timedelta(days=STYLE_DISTILL_STALE_TRIGGER_DAYS):
            return TriggerDecision(
                account_id=account_id,
                recipient_hash=None,
                should_enqueue=True,
                reason="stale",
                last_success_at=last_success,
            )

    counter_row = get_hipaa_send_counter(
        conn, account_id=account_id,
        recipient_hash=HIPAA_SEND_COUNTER_AGGREGATE_HASH,
    )
    counter = int(counter_row["count"]) if counter_row else 0
    if counter >= HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=None,
            should_enqueue=True,
            reason="threshold_reached",
            counter=counter,
            last_success_at=last_success,
        )

    return TriggerDecision(
        account_id=account_id,
        recipient_hash=None,
        should_enqueue=False,
        reason="no_trigger",
        counter=counter,
        last_success_at=last_success,
    )


def enqueue_m3_triggers(
    conn: sqlite3.Connection,
    *, now: datetime | None = None,
) -> tuple[list[TriggerDecision], dict[str, int]]:
    """Evaluate + enqueue M-3 triggers across all eligible accounts.

    Returns a tuple of:

      * the list of :class:`TriggerDecision` objects (one per
        evaluated account), and
      * a reason histogram dict (e.g.
        ``{'first_time': 2, 'threshold_reached': 1, 'stale': 0,
        'already_queued': 4, 'no_trigger': 7}``) for logging /
        /health/detail.

    Side effects on enqueue:

      * Row inserted into ``style_distill_queue`` via
        :func:`enqueue_style_distill_retry` with
        ``last_error=f'trigger:{reason}'`` so the audit trail can
        distinguish operator-fired distills from auto-trigger ones
        even if no audit row exists yet.
      * Account-aggregate counter row reset via
        :func:`reset_hipaa_send_counter`. The next N=20 detection
        starts from zero.
    """
    accounts = _eligible_hipaa_accounts(conn)
    decisions: list[TriggerDecision] = []
    reasons: dict[str, int] = {}
    for acct in accounts:
        decision = evaluate_m3_trigger_for_account(
            conn, acct["id"], now=now,
        )
        decisions.append(decision)
        reasons[decision.reason] = reasons.get(decision.reason, 0) + 1
        if not decision.should_enqueue:
            continue
        try:
            enqueue_style_distill_retry(
                conn,
                account_id=decision.account_id,
                last_error=f"trigger:{decision.reason}",
            )
            # Reset the aggregate counter. The first-success path on
            # the worker will not re-clear it (success clears the
            # queue row only); leaving the counter ticking would
            # immediately re-trigger.
            reset_hipaa_send_counter(
                conn,
                account_id=decision.account_id,
                recipient_hash=HIPAA_SEND_COUNTER_AGGREGATE_HASH,
            )
            log.info(
                "m3 trigger enqueued",
                extra={"_extra": {
                    "account_id": decision.account_id,
                    "reason": decision.reason,
                    "counter": decision.counter,
                }},
            )
        except Exception:
            # The watcher MUST NOT raise — a single account's enqueue
            # failure shouldn't poison the whole sweep. Other accounts
            # still get a chance.
            log.exception(
                "m3 trigger enqueue failed",
                extra={"_extra": {
                    "account_id": decision.account_id,
                }},
            )
    return decisions, reasons


# ---------------------------------------------------------------------------
# M-7 (per-contact) trigger evaluation
# ---------------------------------------------------------------------------

def evaluate_m7_trigger_for_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    counter_row: dict | None = None,
    now: datetime | None = None,
) -> TriggerDecision:
    """Decide whether ``(account_id, recipient_hash)`` warrants an M-7 enqueue.

    Pure-DB function. ``counter_row`` may be passed in to avoid a
    second SELECT when the caller has already read the counter
    (e.g. from :func:`list_hipaa_per_contact_counters`).

    Decision order
    --------------

      1. Already queued (any state) → skip ``reason='already_queued'``.
      2. Counter < threshold AND no prior success → skip
         ``reason='below_threshold'``. (First-time M-7 fires on count;
         per-contact descriptors are an overlay, not mandatory like
         the M-3 account-level row.)
      3. Counter ≥ threshold + no prior success → enqueue
         ``reason='first_time'``.
      4. Counter ≥ threshold + prior success exists → enqueue
         ``reason='threshold_reached'``.
      5. Counter < threshold + last success older than 30d → enqueue
         ``reason='stale'``.
      6. None of the above → skip ``reason='no_trigger'``.

    Note: the M-7 first-time path REQUIRES the counter threshold; we
    don't fire an empty M-7 distill on a contact we've never sent to
    in volume.
    """
    now = now or _now()

    has_row, _is_paused = _is_already_queued_contact(
        conn, account_id=account_id, recipient_hash=recipient_hash,
    )
    if has_row:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=recipient_hash,
            should_enqueue=False,
            reason="already_queued",
        )

    if counter_row is None:
        counter_row = get_hipaa_send_counter(
            conn, account_id=account_id,
            recipient_hash=recipient_hash,
        )
    counter = int(counter_row["count"]) if counter_row else 0

    last_success = last_successful_style_distill_at(
        conn, account_id=account_id, kind="per_contact",
        recipient_hash=recipient_hash,
    )
    parsed_last = _parse_iso(last_success)

    threshold_reached = counter >= HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES

    if threshold_reached and last_success is None:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=recipient_hash,
            should_enqueue=True,
            reason="first_time",
            counter=counter,
        )
    if threshold_reached:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=recipient_hash,
            should_enqueue=True,
            reason="threshold_reached",
            counter=counter,
            last_success_at=last_success,
        )
    if parsed_last is not None:
        age = now - parsed_last
        if age >= timedelta(days=HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS):
            return TriggerDecision(
                account_id=account_id,
                recipient_hash=recipient_hash,
                should_enqueue=True,
                reason="stale",
                counter=counter,
                last_success_at=last_success,
            )

    if last_success is None:
        return TriggerDecision(
            account_id=account_id,
            recipient_hash=recipient_hash,
            should_enqueue=False,
            reason="below_threshold",
            counter=counter,
        )
    return TriggerDecision(
        account_id=account_id,
        recipient_hash=recipient_hash,
        should_enqueue=False,
        reason="no_trigger",
        counter=counter,
        last_success_at=last_success,
    )


def evaluate_m7_triggers_for_account(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    now: datetime | None = None,
) -> list[TriggerDecision]:
    """Iterate every per-contact counter row + every stale prior
    success for ``account_id``; return one decision per (account,
    recipient_hash) pair examined.

    The function unions two row sets:

      * Counter rows (drives the threshold path).
      * Per-contact descriptor rows with no current counter (drives
        the stale-refresh path on a contact the operator stopped
        sending to but whose overlay still exists).

    The union is the right shape: a contact may have a stale
    descriptor + no recent sends, OR fresh sends + no descriptor.
    Either independently can warrant an enqueue.
    """
    now = now or _now()
    # Collect counter rows.
    counter_rows = list_hipaa_per_contact_counters(
        conn, account_id=account_id, min_count=1,
    )
    counter_hashes = {r["recipient_hash"] for r in counter_rows}

    # Collect descriptor rows (for stale-refresh of inactive contacts).
    descriptor_hashes: set[str] = set()
    rows = conn.execute(
        "SELECT recipient_hash FROM per_contact_style_hipaa "
        "WHERE account_id = ?",
        (int(account_id),),
    ).fetchall()
    for r in rows:
        h = r["recipient_hash"] if hasattr(r, "keys") else r[0]
        if h:
            descriptor_hashes.add(h)

    all_hashes = counter_hashes | descriptor_hashes
    counter_by_hash = {r["recipient_hash"]: r for r in counter_rows}

    decisions: list[TriggerDecision] = []
    for h in sorted(all_hashes):
        decision = evaluate_m7_trigger_for_contact(
            conn,
            account_id=account_id,
            recipient_hash=h,
            counter_row=counter_by_hash.get(h),
            now=now,
        )
        decisions.append(decision)
    return decisions


def enqueue_m7_triggers(
    conn: sqlite3.Connection,
    *, now: datetime | None = None,
) -> tuple[list[TriggerDecision], dict[str, int]]:
    """Evaluate + enqueue M-7 triggers across all eligible accounts.

    Iterates eligible accounts; for each, walks the union of (counter
    rows ∪ descriptor rows) and evaluates per-contact. Enqueues every
    decision where ``should_enqueue=True``.

    Returns ``(decisions, reasons)`` mirroring
    :func:`enqueue_m3_triggers`.
    """
    accounts = _eligible_hipaa_accounts(conn)
    all_decisions: list[TriggerDecision] = []
    reasons: dict[str, int] = {}
    for acct in accounts:
        decisions = evaluate_m7_triggers_for_account(
            conn, account_id=acct["id"], now=now,
        )
        for decision in decisions:
            all_decisions.append(decision)
            reasons[decision.reason] = reasons.get(decision.reason, 0) + 1
            if not decision.should_enqueue:
                continue
            assert decision.recipient_hash is not None
            try:
                enqueue_style_distill_contact_retry(
                    conn,
                    account_id=decision.account_id,
                    recipient_hash=decision.recipient_hash,
                    last_error=f"trigger:{decision.reason}",
                )
                reset_hipaa_send_counter(
                    conn,
                    account_id=decision.account_id,
                    recipient_hash=decision.recipient_hash,
                )
                # Log only the hash — privacy invariant.
                log.info(
                    "m7 trigger enqueued",
                    extra={"_extra": {
                        "account_id": decision.account_id,
                        "recipient_hash_prefix":
                            decision.recipient_hash[:8],
                        "reason": decision.reason,
                        "counter": decision.counter,
                    }},
                )
            except Exception:
                log.exception(
                    "m7 trigger enqueue failed",
                    extra={"_extra": {
                        "account_id": decision.account_id,
                        "recipient_hash_prefix":
                            decision.recipient_hash[:8],
                    }},
                )
    return all_decisions, reasons


# ---------------------------------------------------------------------------
# Full-sweep entry point
# ---------------------------------------------------------------------------

def run_trigger_sweep(
    conn: sqlite3.Connection,
    *, now: datetime | None = None,
) -> TriggerSweepSummary:
    """One full sweep: M-3 then M-7. Returns a :class:`TriggerSweepSummary`.

    This is the entry point the background task in ``web/app.py`` calls
    once per tick. Idempotent across ticks: a second invocation with
    no new sent messages in between is a no-op (every decision lands
    on ``already_queued`` or ``no_trigger``).
    """
    now = now or _now()
    m3_decisions, m3_reasons = enqueue_m3_triggers(conn, now=now)
    m7_decisions, m7_reasons = enqueue_m7_triggers(conn, now=now)

    m3_enqueued = sum(1 for d in m3_decisions if d.should_enqueue)
    m7_enqueued = sum(1 for d in m7_decisions if d.should_enqueue)
    return TriggerSweepSummary(
        ts=now.isoformat(),
        m3_evaluated=len(m3_decisions),
        m3_enqueued=m3_enqueued,
        m7_evaluated=len(m7_decisions),
        m7_enqueued=m7_enqueued,
        m3_reasons=m3_reasons,
        m7_reasons=m7_reasons,
    )


__all__ = [
    "HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES",
    "STYLE_DISTILL_STALE_TRIGGER_DAYS",
    "HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS",
    "TriggerDecision",
    "TriggerSweepSummary",
    "evaluate_m3_trigger_for_account",
    "evaluate_m7_trigger_for_contact",
    "evaluate_m7_triggers_for_account",
    "enqueue_m3_triggers",
    "enqueue_m7_triggers",
    "run_trigger_sweep",
]
