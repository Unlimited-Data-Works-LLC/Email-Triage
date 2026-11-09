"""Cron-anchored renewer for Microsoft Graph webhook subscriptions.

Graph subscriptions for mail resources expire after ~3 days (4230
minutes is the documented max). Without a renewer the push pipeline
goes silent the moment that window closes — Graph stops delivering
notifications, the dashboard chip stays "active" until the
``last_notification_at`` heartbeat ages out, and the operator notices
only when triage stops happening for a particular account.

Sister loop to ``_gmail_watch_renewer`` in ``app.py``. Two key shape
differences worth calling out:

* **Cron-anchored, not poll-anchored.** Sleeps to a wall-clock minute
  boundary every hour at HH:00 with ``random.uniform(0, 60)`` jitter
  so a 50-account install doesn't fire 50 simultaneous Graph PATCH
  requests. (The Gmail renewer uses a flat 30-min interval — fine for
  a few-account homelab but coarse for operators running larger
  installs.)
* **Configurable renewal window.** ``office365_subscription_renewal_window_hours``
  on ``PushConfig`` (default 24) controls how far ahead of expiration
  the loop refreshes. Operators on shaky Graph connections shrink this
  to give themselves more retry chances; operators with reliable links
  can leave the default. Subscriptions die hard once expired — Graph
  drops the row server-side and the only path back is
  ``create_subscription`` from scratch.
* **Bounded concurrency.** ``asyncio.Semaphore(_RENEW_CONCURRENCY)``
  caps the parallel PATCH count so the renewer can't itself become a
  burst against Graph's rate limits. Default is 4 — enough to keep a
  large install fresh in the 60-minute tick window while staying
  comfortably under any reasonable Graph quota.

Audit: each renewal attempt writes an ``auth_events`` row with
``event_type="o365_subscription_renewed"`` and ``outcome=success`` or
``"failure"`` plus the truncated error reason. This is operational
metadata (a token-refresh-shaped event), NOT PHI access — sub renewal
doesn't read a single message header. HIPAA gate is intentionally
absent here; the row goes in regardless of the account's hipaa flag.
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone
from typing import Any

from email_triage._errfmt import scrub_error_for_persist
from email_triage._isotime import now_utc_iso, to_utc_iso
from email_triage.triage_logging import get_logger
from email_triage.web._audit import safe_audit_write_async

log = get_logger("web.o365_renewer")


# Concurrency cap: a 50-account install on the same renewal window
# would otherwise PATCH all 50 subscriptions at once. Four parallel
# calls is enough to keep a big install fresh in the hourly tick
# while staying well under any sensible Graph rate limit.
_RENEW_CONCURRENCY = 4

# Tick cadence: every hour, anchored to HH:00 + jitter. The wall-clock
# anchor matters more than the interval — a poll-anchored loop drifts
# across restarts and a 50-install fleet would synchronise on the same
# 60-minute drift, slamming Graph at the same second.
_TICK_INTERVAL_SECONDS = 60 * 60  # 1 hour
_MAX_JITTER_SECONDS = 60          # 0-60s after HH:00 boundary

# Initial start delay: stagger past the gmail renewer's 30s bias so
# we don't clobber its first sweep when the process boots.
_START_DELAY_SECONDS = 90


async def _o365_subscription_renewer_loop(app) -> None:
    """Tick every 60 minutes; renew any O365 subscription expiring
    within the configured window.

    Cron-anchored: the loop sleeps to the next HH:00 + jitter rather
    than ``asyncio.sleep(3600)`` after the previous tick finished.
    That keeps the sweep on a stable cadence regardless of how long
    the previous tick took (a slow tick due to many subscriptions
    doesn't push the next tick into HH:30 territory).
    """
    from email_triage.web.task_supervisor import supervised_interval_loop

    async def _tick() -> None:
        cfg = app.state.config
        window_hours = int(getattr(
            cfg.push,
            "office365_subscription_renewal_window_hours",
            24,
        ))
        await _run_o365_renewal_sweep(app, window_hours=window_hours)
        # N-227c R22 — heartbeat stamp for /admin observability.
        app.state.o365_subscription_renewer_loop_status = {
            "at": now_utc_iso(),
            "window_hours": window_hours,
        }

    # Cron-anchored cadence — sleep to the next HH:00 + jitter boundary,
    # recomputed each tick so wall-clock skew snaps back to schedule —
    # via supervised_interval_loop's callable-interval form.  —
    # lease-gated: renewing a Graph subscription is idempotent, one
    # instance per tick.
    await supervised_interval_loop(
        "o365-subscription-renewer", _seconds_until_next_tick, _tick,
        warmup_secs=_START_DELAY_SECONDS,
        startup_jitter_secs=30.0,
        lease_name="o365-subscription-renewer",
        lease_conn=app.state.db,
    )


def _seconds_until_next_tick(*, now: datetime | None = None) -> float:
    """Return seconds until the next HH:00 boundary plus 0-60s jitter.

    Pure helper for testability — pass ``now`` in tests to make the
    return value deterministic. The randomness only kicks in when
    ``now`` is the default (production wall clock).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    # Round up to the next hour boundary.
    next_hour = (now + timedelta(hours=1)).replace(
        minute=0, second=0, microsecond=0,
    )
    # If we somehow got called exactly on the boundary, push to the
    # following hour rather than scheduling a zero-second sleep.
    if next_hour <= now:
        next_hour = next_hour + timedelta(hours=1)
    seconds = (next_hour - now).total_seconds()
    seconds += random.uniform(0, _MAX_JITTER_SECONDS)
    return max(seconds, 1.0)


async def _run_o365_renewal_sweep(
    app, *, window_hours: int = 24,
) -> dict[str, int]:
    """Renew every O365 subscription expiring within ``window_hours``.

    Pure async function so tests can drive it directly without
    waiting on the cron loop. Returns counters
    ``{"considered", "renewed", "failed"}`` for observability — the
    loop discards them, but tests assert on them.

    Per-row failures don't kill the sweep: each renewal is wrapped
    in try/except, success records a fresh ``expiration_at`` +
    audit row, failure flips ``status='errored'`` + audit row +
    log line. The next tick re-tries automatically.
    """
    from email_triage.web.db import (
        get_email_account,
        list_o365_subscriptions_expiring,
        record_auth_event,
        record_o365_subscription_error,
        record_o365_subscription_outcome,
        record_o365_subscription_renewal,
    )
    from email_triage.providers.office365 import Office365Provider
    from email_triage.web.routers.ui import _create_provider_from_account
    #  — this sweep fans out ``_renew_one`` coroutines concurrently
    # via ``asyncio.gather``; each one MUST route its DB work through
    # ``db_call`` so the process-wide DB lock serialises it against
    # other db_call workers / @db_write helpers on the shared
    # ``sqlite3.Connection``. A bare sync DB call on the event-loop
    # thread bypasses the lock.
    from email_triage.web.db_threadpool import db_call

    db = app.state.db
    secrets = app.state.secrets

    now = datetime.now(timezone.utc)
    horizon = to_utc_iso(now + timedelta(hours=window_hours))
    expiring = await db_call(list_o365_subscriptions_expiring, db, horizon)

    counters = {
        "considered": len(expiring), "renewed": 0, "failed": 0,
        "skipped_inactive": 0,
    }
    if not expiring:
        return counters

    semaphore = asyncio.Semaphore(_RENEW_CONCURRENCY)

    async def _renew_one(row: dict[str, Any]) -> None:
        """Renew one subscription. Wrapped + isolated so per-row
        failures don't propagate."""
        account_id = row["account_id"]
        subscription_id = row["subscription_id"]
        async with semaphore:
            acct = await db_call(get_email_account, db, account_id)
            if acct is None:
                # Orphaned subscription row — account was deleted but
                # the subscription survived. Log and skip; the
                # FK ON DELETE CASCADE should prevent this in practice.
                log.warning(
                    "O365 renewer: orphaned subscription row "
                    "(account vanished)",
                    account_id=account_id,
                    subscription_id=subscription_id,
                )
                return

            # Fail-closed is_active gate (Loop-5 census). A deactivated
            # account's Graph subscription must NOT be renewed — extending
            # it re-arms live PHI ingestion for a paused account. The
            # subscription row is left intact; it dies on its own ~3-day
            # Graph clock (Graph drops it server-side), and re-activation +
            # a watcher start re-creates it. Default True so a missing
            # column never silently pauses the account.
            if not acct.get("is_active", True):
                log.debug(
                    "O365 renewer: skipping (account inactive)",
                    account_id=account_id,
                    subscription_id=subscription_id,
                )
                counters["skipped_inactive"] += 1
                return

            # census run17  — account_email SSOT, not the open-coded key;
            # local renamed off the SSOT name to avoid shadowing it.
            from email_triage.db.accounts import account_email
            acct_email = account_email(acct)
            # auth_stale lifecycle SSOT funnel (census 2026-06-09 #1) — late
            # import to avoid the web/app.py import cycle.
            from email_triage.web.app import record_provider_outcome
            try:
                provider = _create_provider_from_account(acct, secrets)
                if not isinstance(provider, Office365Provider):
                    log.error(
                        "O365 renewer: account is not office365",
                        account_id=account_id,
                        provider_type=acct.get("provider_type"),
                    )
                    return
                try:
                    data = await provider.renew_subscription(
                        subscription_id,
                    )
                finally:
                    try:
                        await provider.close()
                    except Exception:
                        pass

                new_exp = (
                    (data or {}).get("expirationDateTime")
                    or row["expiration_at"]
                )
                # Graph hands back the same subscription_id on a
                # PATCH renew (rotation-via-id is not in the contract).
                new_sub_id = (
                    (data or {}).get("id") or subscription_id
                )
            except Exception as e:
                err_text = scrub_error_for_persist(e)  # census run13 #2 — audit detail rides the HMAC chain (both legs)
                # N-69 — route the failure through the status lifecycle funnel
                # (record_o365_subscription_outcome) which now owns the error
                # bookkeeping, replacing the direct record_o365_subscription_error
                # call. The funnel's failure path is equivalent (scrub + bump +
                # set errored), keeping record_o365_subscription_error in db.py
                # as the inner implementation but routing through the funnel so
                # the lifecycle pin has one canonical entry point.
                #
                # N-520 step 2 (s2 panel hipaa, row 3 failure edge): the
                # errored status / error_count bump and its outcome=failure
                # witness commit in ONE transaction through the same funnel
                # as the success edge. A failed witness rolls the bump back
                # (operational retry state only; no access opens) and the
                # @audit_emitter gap row records it.
                from email_triage.db.audit import (
                    record_auth_event_txn, record_witnessed_state_change,
                )
                from email_triage.web.db import (
                    record_o365_subscription_outcome_txn,
                )
                await safe_audit_write_async(
                    lambda: db_call(
                        record_witnessed_state_change,
                        db,
                        operation="o365_subscription_renewed",
                        state_txn=lambda c: record_o365_subscription_outcome_txn(
                            c, account_id=account_id, error_text=err_text,
                        ),
                        witness_txn=lambda c, _r: record_auth_event_txn(
                            c,
                            event_type="o365_subscription_renewed",
                            email=acct_email,
                            outcome="failure",
                            detail=err_text[:400],
                        ),
                    ),
                    description=(
                        "o365_subscription_renewed "
                        f"account_id={account_id} outcome=failure"
                    ),
                )
                counters["failed"] += 1
                log.warning(
                    "O365 subscription renewal failed",
                    account_id=account_id,
                    subscription_id=subscription_id,
                    error=err_text,
                )
                # The auth_stale chip write for this edge runs after both
                # branches (below), so it follows every witness in source order.
                renew_err: Exception | None = e
            else:
                renew_err = None
                # N-520 step 2 (543-design M-4): the renewal row and its
                # witness commit in ONE transaction in ONE db_call hop,
                # through the safe_audit_write SSOT (a failed witness rolls
                # the renewal back, the @audit_emitter gap row records it, and
                # the per-row isolation of this sweep is kept). The funnel
                # returns True only when both landed; anything else counts
                # as a failed renewal, and the next sweep retries it.
                from email_triage.db.audit import (
                    record_auth_event_txn, record_witnessed_state_change,
                )
                from email_triage.web.db import (
                    record_o365_subscription_renewal_txn,
                )

                def _renewal_state(c):
                    record_o365_subscription_renewal_txn(
                        c,
                        account_id=account_id,
                        subscription_id=new_sub_id,
                        new_expiration_at=new_exp,
                    )
                    return True

                recorded = await safe_audit_write_async(
                    lambda: db_call(
                        record_witnessed_state_change,
                        db,
                        operation="o365_subscription_renewed",
                        state_txn=_renewal_state,
                        witness_txn=lambda c, _r: record_auth_event_txn(
                            c,
                            event_type="o365_subscription_renewed",
                            email=acct_email,
                            outcome="success",
                            detail=f"sub={new_sub_id} exp={new_exp}",
                        ),
                    ),
                    description=(
                        "o365_subscription_renewed "
                        f"account_id={account_id} outcome=success"
                    ),
                )
                if recorded is not True:
                    counters["failed"] += 1
                    log.warning(
                        "O365 subscription renewed at Graph but the local "
                        "row + witness did not commit; next sweep retries",
                        account_id=account_id,
                        subscription_id=subscription_id,
                    )
                    return
                counters["renewed"] += 1
                log.info(
                    "O365 subscription renewed",
                    account_id=account_id,
                    new_expires_at=new_exp,
                )
            # Census 2026-06-09 #1, both edges, AFTER both witnessed units:
            # * success → the OAuth credential is alive; clear any prior
            #   auth_stale chip (the renewer previously never cleared);
            # * failure → an auth-revoked renewal surfaces the re-auth chip
            #   (needle-filtered; the renewer previously set nothing, so a
            #   dead token on a push-only O365 account stayed invisible).
            # N-520 step 2: outside the renewal try, so a chip-write failure
            # is never recorded as a FAILED renewal.
            try:
                await db_call(record_provider_outcome, db, acct, renew_err)
            except Exception as chip_err:
                log.warning(
                    "O365 renewer: auth_stale chip write failed after a "
                    "witnessed renewal outcome",
                    account_id=account_id,
                    error=scrub_error_for_persist(chip_err),
                )

    await asyncio.gather(
        *[_renew_one(row) for row in expiring],
        return_exceptions=False,
    )
    return counters
