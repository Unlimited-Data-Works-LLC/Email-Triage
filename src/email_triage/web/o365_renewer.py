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

from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger

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
    await asyncio.sleep(_START_DELAY_SECONDS)
    log.info("Office 365 subscription renewer started")

    while True:
        try:
            cfg = app.state.config
            window_hours = int(
                getattr(
                    cfg.push,
                    "office365_subscription_renewal_window_hours",
                    24,
                )
            )
            await _run_o365_renewal_sweep(app, window_hours=window_hours)
        except asyncio.CancelledError:
            log.info("Office 365 subscription renewer cancelled")
            return
        except Exception as e:
            log.error(
                "Office 365 subscription renewer sweep failed",
                error=fmt_exc(e),
            )

        # Sleep to the next HH:00 + jitter boundary. Recompute every
        # tick so wall-clock skew (NTP correction, suspend/resume)
        # snaps us back to the schedule.
        try:
            await asyncio.sleep(_seconds_until_next_tick())
        except asyncio.CancelledError:
            log.info("Office 365 subscription renewer cancelled")
            return


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
        record_o365_subscription_renewal,
    )
    from email_triage.providers.office365 import Office365Provider
    from email_triage.web.routers.ui import _create_provider_from_account

    db = app.state.db
    secrets = app.state.secrets

    now = datetime.now(timezone.utc)
    horizon = (now + timedelta(hours=window_hours)).isoformat()
    expiring = list_o365_subscriptions_expiring(db, horizon)

    counters = {"considered": len(expiring), "renewed": 0, "failed": 0}
    if not expiring:
        return counters

    semaphore = asyncio.Semaphore(_RENEW_CONCURRENCY)

    async def _renew_one(row: dict[str, Any]) -> None:
        """Renew one subscription. Wrapped + isolated so per-row
        failures don't propagate."""
        account_id = row["account_id"]
        subscription_id = row["subscription_id"]
        async with semaphore:
            acct = get_email_account(db, account_id)
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

            account_email = acct.get("email_address") or ""
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
                record_o365_subscription_renewal(
                    db,
                    account_id=account_id,
                    subscription_id=new_sub_id,
                    new_expiration_at=new_exp,
                )
                try:
                    record_auth_event(
                        db,
                        event_type="o365_subscription_renewed",
                        email=account_email,
                        outcome="success",
                        detail=f"sub={new_sub_id} exp={new_exp}",
                    )
                except Exception as audit_err:
                    log.warning(
                        "O365 renewer: audit row insert failed "
                        "(non-fatal)",
                        account_id=account_id,
                        error=fmt_exc(audit_err),
                    )
                counters["renewed"] += 1
                log.info(
                    "O365 subscription renewed",
                    account_id=account_id,
                    new_expires_at=new_exp,
                )
            except Exception as e:
                err_text = fmt_exc(e)
                try:
                    record_o365_subscription_error(
                        db,
                        account_id=account_id,
                        error_text=err_text,
                    )
                except Exception:
                    pass
                try:
                    record_auth_event(
                        db,
                        event_type="o365_subscription_renewed",
                        email=account_email,
                        outcome="failure",
                        detail=err_text[:400],
                    )
                except Exception:
                    pass
                counters["failed"] += 1
                log.warning(
                    "O365 subscription renewal failed",
                    account_id=account_id,
                    subscription_id=subscription_id,
                    error=err_text,
                )

    await asyncio.gather(
        *[_renew_one(row) for row in expiring],
        return_exceptions=False,
    )
    return counters
