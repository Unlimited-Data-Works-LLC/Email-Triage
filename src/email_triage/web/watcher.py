"""IMAP watcher orchestration — extracted from web/app.py.

Drop-in refactor. NO semantic change. The push-watcher cluster
(:class:`WatcherManager` + the per-account :func:`_watch_account` IDLE
loop) moves here from ``web/app.py`` as the 4th  god-module
extraction (after the ``db/`` cluster #277a-c). ``web/app.py`` keeps a
bottom re-export shim so ``from email_triage.web.app import
WatcherManager`` (used by the test suite + the lifespan + the
``get_watcher_manager`` dependency) keeps resolving unchanged.

Partition: this is the IMAP IDLE *push*-watch surface. The shared
ingestion helpers it leans on STAY in ``web/app.py`` because they are
used by the (still-resident) poll + push clusters too:
  * ``_acct_log_extras`` — log-extras formatter, 40+ consumers repo-wide.
  * ``_resolve_hwm_with_uidvalidity`` — IMAP high-water-mark resolver,
    shared with ``_poll_once_imap``.
  * ``_poll_state_key`` — settings-key builder, shared with the poller.
They are LATE-IMPORTED from ``email_triage.web.app`` inside the two
methods that use them (cycle-break: app.py re-exports WatcherManager
defined here). Everything else the cluster needs is either a top-level
stdlib/sibling import (below) or a local import already inside the
moved bodies (provider construction, classifier build, triage registry,
db helpers) — self-contained, no app.py dependency.

The module logger keeps the ``"web.app"`` record name so existing
log-stream filters + dashboards see byte-identical watcher log records.

HIPAA: ``_watch_account`` fetches → classifies → runs actions on live
mail (PHI-touching), but this is pure relocation — the per-account
HIPAA gate (``is_account_hipaa`` / disabled-owner checks), the audit
emits, and the triage path are byte-identical to the web/app.py
original. §-location-agnostic; no PHI-handling semantics changed.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI

from email_triage.triage_logging import REDACTED, get_logger
from email_triage.web import settings_keys as _settings_keys
from email_triage._errfmt import fmt_exc
from email_triage.web.task_supervisor import next_backoff_delay  # N-228 R22 SSOT
from email_triage._isotime import now_utc_iso, parse_iso, parse_iso_aware  # N-357 R31 (SSOT collapse of 2 sites)
from email_triage._hm_render import render_hm_for_audience  #  SSOT
from email_triage.web._watch_status_recorder import record_message_result  # N-213b R27

#: Logger record name preserved as "web.app" (not "web.watcher") so the
#: watcher's existing log-stream identity is byte-identical post-move.
log = get_logger("web.app")


# -e (2026-07-11) — CONFIG-DRIVEN per-watcher shutdown grace budget.
# Pre-fix: hardcoded ``timeout=3.0`` at 2 asyncio.wait_for sites (:933, :971).
# Compute-bound async cancellation wait — a bounded ceiling so one stuck
# watcher can't hold up the rest at shutdown/account-stop. Module-level
# SSOT with a boot-wired setter reading
# ``config.ingestion.watcher_shutdown_grace_secs``.
_WATCHER_SHUTDOWN_GRACE_SECS: float = 3.0


def configure_watcher_shutdown_grace(timeout_secs: float) -> None:
    """-e — set the per-watcher shutdown grace timeout.

    Called at boot from ``load_config._wire_module_singletons``.
    Rejects non-positive values.
    """
    global _WATCHER_SHUTDOWN_GRACE_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _WATCHER_SHUTDOWN_GRACE_SECS = float(timeout_secs)


class WatcherManager:
    """Manages per-account ingestion lifecycle — push + poll.

    Every account has two independent knobs:

      * ``push_enabled`` — start the provider's real-time mechanism.
        For IMAP that means one IDLE coroutine per watched mailbox
        (N concurrent connections per account). For Gmail it means the
        Pub/Sub webhook registration. For Office 365, Graph subscriptions
        (not yet wired).
      * ``poll_enabled`` — register the account for the unified poll
        loop, which ticks every ``poll_interval_minutes``. The poll is a
        cheap no-op when nothing changed (IMAP ``SEARCH UID hwm:*``
        returns empty; Gmail's live ``historyId`` equals stored so the
        consumer's idempotency check drops the item).

    The manager exposes account-level API; callers don't see the
    per-mailbox composite keys.
    """

    def __init__(self, app: FastAPI):
        self.app = app
        # Composite key: (account_id, mailbox) → Task.
        self._tasks: dict[tuple[int, str], asyncio.Task] = {}
        # Per-(account, mailbox) raw state from the watcher coroutine.
        self._mb_state: dict[tuple[int, str], dict[str, Any]] = {}
        # Accounts currently enrolled in the unified poll loop. The loop
        # reads this set every tick; changes take effect on the next
        # tick. We also record ``last_poll_at`` for chip rendering.
        self._poll_registered: dict[int, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Aggregate (per-account) view — what the UI sees.
    # ------------------------------------------------------------------

    def _account_mailboxes_with_state(self, account_id: int) -> list[str]:
        return [mb for (aid, mb) in self._mb_state if aid == account_id]

    def _aggregate_status(self, account_id: int) -> dict[str, Any]:
        """Roll up per-mailbox state for an account.

        * ``status``: the most "active" mailbox status wins
          (watching > starting > reconnecting > error > unsupported >
          stopped). If any mailbox is watching, the account reads as
          watching; if every mailbox errored out, the account is
          ``error``.
        * ``processed`` / ``errors``: summed across mailboxes.
        * ``last_message`` / ``last_error``: whichever per-mailbox state
          was most recent by timestamp.
        """
        mbs = self._account_mailboxes_with_state(account_id)
        if not mbs:
            return {
                "status": "stopped",
                "processed": 0,
                "errors": 0,
                "last_message": None,
                "last_error": None,
                "started_at": None,
                "mailboxes": [],
            }

        priority = [
            "watching", "starting", "reconnecting", "error",
            "unsupported", "stopped",
        ]
        processed = 0
        errors = 0
        last_message = None
        last_error = None
        started_at = None
        statuses: list[str] = []
        per_mb: list[dict[str, Any]] = []

        for mb in mbs:
            s = self._mb_state.get((account_id, mb), {})
            statuses.append(s.get("status", "stopped"))
            processed += int(s.get("processed", 0) or 0)
            errors += int(s.get("errors", 0) or 0)
            lm = s.get("last_message")
            if lm and (not last_message or
                       lm.get("at", "") > (last_message.get("at", ""))):
                last_message = lm
            le = s.get("last_error")
            if le:
                last_error = le
            sa = s.get("started_at")
            if sa and (not started_at or sa < started_at):
                started_at = sa
            per_mb.append({"mailbox": mb, "status": s.get("status", "stopped")})

        agg_status = "stopped"
        for candidate in priority:
            if candidate in statuses:
                agg_status = candidate
                break

        return {
            "status": agg_status,
            "processed": processed,
            "errors": errors,
            "last_message": last_message,
            "last_error": last_error,
            "started_at": started_at,
            "mailboxes": per_mb,
        }

    def status(self, account_id: int) -> dict[str, Any]:
        """Return the aggregate watcher state for an account."""
        return self._aggregate_status(account_id)

    def all_statuses(self) -> dict[int, dict[str, Any]]:
        """Return aggregate state per account for any account that has
        ever had a watcher started."""
        account_ids = {aid for (aid, _) in self._mb_state}
        return {aid: self._aggregate_status(aid) for aid in account_ids}

    def is_running(self, account_id: int) -> bool:
        """True when push OR poll is active for this account.

        This is the chip answer: push-watching counts, poll-enrolled
        counts. A dormant account (both off) reads False.
        """
        return self.is_push_running(account_id) or self.is_poll_running(account_id)

    def is_push_running(self, account_id: int) -> bool:
        """True when ANY push task for this account is still running."""
        for (aid, _mb), task in self._tasks.items():
            if aid == account_id and task is not None and not task.done():
                return True
        return False

    def is_poll_running(self, account_id: int) -> bool:
        """True when this account is enrolled in the unified poll loop."""
        return account_id in self._poll_registered

    def poll_last_tick(self, account_id: int) -> str | None:
        """ISO timestamp of the most recent poll tick for this account,
        or ``None`` if no poll has fired since startup."""
        entry = self._poll_registered.get(account_id)
        if not entry:
            return None
        return entry.get("last_poll_at")

    def _mark_poll_tick(self, account_id: int, iso_ts: str) -> None:
        """Invoked by the unified poll loop to record a tick (even a
        no-op tick) so the UI chip can show "last polled Nm ago"."""
        if account_id in self._poll_registered:
            self._poll_registered[account_id]["last_poll_at"] = iso_ts

    # ------------------------------------------------------------------
    # Public counters — used by /health, dashboard chip, daily digest.
    # IMAP IDLE only. Gmail Pub/Sub state lives in ``gmail_watches`` and
    # is queried separately; Office 365 Graph subscriptions are not yet
    # wired (see the backlog item).
    # ------------------------------------------------------------------

    def mailbox_counts(self) -> tuple[int, int]:
        """Return ``(total_mailboxes, watching_mailboxes)`` across all
        IMAP accounts. Each mailbox = one IDLE socket."""
        total = len(self._mb_state)
        watching = sum(
            1 for s in self._mb_state.values()
            if (s or {}).get("status") == "watching"
        )
        return total, watching

    def poll_counts(self) -> tuple[int, int]:
        """Return ``(registered, fresh)`` for the unified poll loop.

        ``fresh`` = ticked within the last 2 hours (covers a 60-min
        default cadence + grace). Accounts that have never ticked
        (just-restarted process) count as not-fresh; the next tick
        catches them up.
        """
        registered = len(self._poll_registered)
        fresh = 0
        cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
        for entry in self._poll_registered.values():
            last = entry.get("last_poll_at")
            if not last:
                continue
            # N-357 R31 (2026-07-05 SSOT collapse). Sibling to lines ~429 +
            # ~520 in this file.
            dt = parse_iso_aware(last)
            if dt is None:
                continue
            if dt >= cutoff:
                fresh += 1
        return registered, fresh

    # ------------------------------------------------------------------
    # Single source of truth for "is this account ingesting?"
    #
    # ``account_states`` returns one record per account, joining the
    # three disjoint inputs (IMAP IDLE _mb_state, gmail_watches DB rows,
    # poll _poll_registered) into a unified per-account verdict. Every
    # operator-facing surface (/health, dashboard chip, daily digest)
    # folds over this list rather than rebuilding the join — keeps the
    # surfaces consistent and shrinks each new-provider rollout (e.g.
    #  O365 Graph) to one branch in this method.
    # ------------------------------------------------------------------

    def account_states(self, db) -> list[dict[str, Any]]:
        """Per-account ingestion verdict.

        Each record::

            {
              "account_id": int, "account_name": str, "owner": str,
              "smtp_config": SmtpConfig, "secrets": SecretsProvider,
              "provider": "imap" | "gmail_api" | "office365",
              "push": {"configured": bool, "active": bool, "detail": str},
              "poll": {"enrolled": bool, "last_tick": iso|None, "fresh": bool},
              "mode":    "push" | "poll" | "push+poll" | "none",
              "primary": "push" | "poll" | "none",
              "alert":   None | "no_ingestion" | "push_dropped_no_poll",
            }

        ``mode`` reports every active path (option B detail).
        ``primary`` collapses the ambiguity for chip/aggregate display
        — push wins when both are active (push is real-time; poll is
        the safety net). Aggregate by ``primary`` to get sums that
        equal totals.
        """
        from email_triage.web.db import (
            list_email_accounts, list_gmail_watches,
            list_o365_subscriptions,
        )
        try:
            accts = list_email_accounts(db)
        except Exception:
            return []
        try:
            gmail_watch_by_id = {
                r["account_id"]: r for r in list_gmail_watches(db)
            }
        except Exception:
            gmail_watch_by_id = {}
        try:
            o365_sub_by_id = {
                r["account_id"]: r for r in list_o365_subscriptions(db)
            }
        except Exception:
            o365_sub_by_id = {}

        now = datetime.now(timezone.utc)
        out: list[dict[str, Any]] = []
        for a in accts:
            # : skip operator-disabled accounts. is_active=0 is the
            # explicit "this account is not running" signal -- pollers /
            # watchers / triage workers already gate on it (six call
            # sites in app.py + ui.py). Including a disabled row here
            # would emit alert="no_ingestion" (no push, no poll, mode
            # ="none"), which then bubbles up through any_alert and
            # degrades /health forever. The new-account wizard creates
            # rows with is_active=False until the operator clicks
            # through to step 5; without this filter every fresh
            # install would self-degrade between step 1 and step 5.
            # Same reason for legacy partial accounts the operator
            # disabled by hand on the edit page.
            if not a.get("is_active", True):
                continue
            push = self._push_state_for(
                a, gmail_watch_by_id, now,
                o365_sub_by_id=o365_sub_by_id,
            )
            poll = self._poll_state_for(a["id"], now)

            modes: list[str] = []
            if push["active"]:
                modes.append("push")
            if poll["enrolled"]:
                modes.append("poll")
            if not modes:
                mode = "none"
            elif len(modes) == 2:
                mode = "push+poll"
            else:
                mode = modes[0]

            if push["active"]:
                primary = "push"
            elif poll["enrolled"]:
                primary = "poll"
            else:
                primary = "none"

            #  follow-up (operator 2026-06-12): distinguish an operator who
            # INTENTIONALLY turned a watcher off from a broken one. Ingestion is
            # "intended" when push is enabled (push.configured = push_enabled) OR
            # poll is enabled (config poll_enabled, default True). When mode==none
            # AND neither path is intended, the operator deliberately stopped
            # watching this (still-active) account — that is "watching off", NOT
            # an error. Only alert when ingestion was EXPECTED but isn't running.
            cfg = a.get("config") or {}
            poll_intended = bool(cfg.get("poll_enabled", True))
            ingestion_intended = bool(push.get("configured")) or poll_intended
            watching_off = (
                mode == "none"
                and not push.get("transient")
                and not ingestion_intended
            )

            alert: str | None = None
            if mode == "none" and not push.get("transient"):
                if ingestion_intended:
                    # Push and/or poll is ENABLED but no path is live — a real
                    # ingestion failure the operator must fix.
                    alert = "no_ingestion"
                # else: watching_off — a deliberate pause, no alert.
            elif (push["configured"] and not push["active"]
                  and not poll["enrolled"] and not push.get("transient")):
                alert = "push_dropped_no_poll"

            out.append({
                "account_id": a["id"],
                "account_name": a.get("name", ""),
                "owner": (
                    a.get("owner_name") or a.get("owner_email", "")
                ),
                "provider": a.get("provider_type", ""),
                "push": push,
                "poll": poll,
                "mode": mode,
                "primary": primary,
                "alert": alert,
                # True ⇒ active account, but the operator turned BOTH push and
                # poll off on purpose: a neutral "watching off" state, never an
                # alert and never counted as "uncovered".
                "watching_off": watching_off,
            })
        return out

    def _push_state_for(
        self, acct: dict, gmail_watch_by_id: dict, now: datetime,
        *, o365_sub_by_id: dict | None = None,
    ) -> dict[str, Any]:
        """Provider-specific push state. New providers add a branch.

        ``transient`` flags the brief grace period where push isn't
        active yet but just started / just expired and the caller
        shouldn't escalate to an alert. 15-minute window matches the
        legacy ``_STALE_WATCHER_SECONDS`` rule.
        """
        aid = acct["id"]
        provider = acct.get("provider_type", "")
        cfg = acct.get("config") or {}
        grace = timedelta(minutes=15)

        if provider == "imap":
            configured = bool(cfg.get("push_enabled", True))
            mbs = [
                (mb, st) for (a_id, mb), st in self._mb_state.items()
                if a_id == aid
            ]
            total_mb = len(mbs)
            watching_mb = sum(
                1 for _mb, st in mbs
                if (st or {}).get("status") == "watching"
            )
            active = total_mb > 0 and watching_mb > 0
            # Transient: any IDLE coroutine started within the grace
            # window. Starting / reconnecting in their first 15 min is
            # expected, not an alert.
            transient = False
            for _mb, st in mbs:
                started_at = (st or {}).get("started_at")
                if not started_at:
                    continue
                # N-357 R31 (2026-07-05 SSOT collapse). See docstring at
                # `_isotime.parse_iso_aware` — one call replaces the 5-line
                # inline parse + None-skip + tzinfo-assume shim.
                sd = parse_iso_aware(started_at)
                if sd is None:
                    continue
                if (now - sd) <= grace:
                    transient = True
                    break
            if not configured:
                detail = "IDLE not configured"
            elif total_mb == 0:
                detail = "IDLE configured, not started"
            else:
                detail = f"{watching_mb}/{total_mb} folders watching"
            return {
                "configured": configured, "active": active,
                "detail": detail, "transient": transient,
            }

        if provider == "gmail_api":
            wr = gmail_watch_by_id.get(aid)
            configured = wr is not None
            active = False
            transient = False
            detail = "Pub/Sub not configured"
            if wr:
                exp_raw = wr.get("expires_at")
                exp_dt = parse_iso(exp_raw)
                if exp_dt is not None and exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt and exp_dt > now:
                    active = True
                    detail = f"Pub/Sub healthy, expires {exp_raw}"
                elif exp_dt:
                    age_secs = (now - exp_dt).total_seconds()
                    if age_secs <= grace.total_seconds():
                        transient = True  # renew job will catch it
                    age_h = int(age_secs // 3600)
                    detail = f"Pub/Sub expired {age_h}h ago"
                else:
                    detail = "Pub/Sub row invalid"
            return {
                "configured": configured, "active": active,
                "detail": detail, "transient": transient,
            }

        if provider == "office365":
            # Graph subscriptions, mirroring the Gmail Pub/Sub branch
            #. One row per account in ``office365_subscriptions``;
            # active iff status='active' AND expiration_at in the future.
            wr = (o365_sub_by_id or {}).get(aid) if o365_sub_by_id else None
            configured = wr is not None
            active = False
            transient = False
            detail = "Graph push not configured"
            if wr:
                exp_raw = wr.get("expiration_at")
                exp_dt = parse_iso(exp_raw)
                if exp_dt is not None and exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                status = (wr.get("status") or "").strip()
                if status == "errored":
                    detail = (
                        f"Graph subscription errored "
                        f"({wr.get('error_count', 0)}x); "
                        f"{(wr.get('error_last') or '')[:80]}"
                    )
                elif exp_dt and exp_dt > now:
                    active = True
                    detail = f"Graph push healthy, expires {exp_raw}"
                elif exp_dt:
                    age_secs = (now - exp_dt).total_seconds()
                    if age_secs <= grace.total_seconds():
                        transient = True  # renewer will catch it
                    age_h = int(age_secs // 3600)
                    detail = f"Graph subscription expired {age_h}h ago"
                else:
                    detail = "Graph subscription row invalid"
            return {
                "configured": configured, "active": active,
                "detail": detail, "transient": transient,
            }

        return {
            "configured": False, "active": False,
            "detail": f"unknown provider: {provider}",
            "transient": False,
        }

    def _poll_state_for(self, account_id: int, now: datetime) -> dict[str, Any]:
        entry = self._poll_registered.get(account_id)
        if entry is None:
            return {"enrolled": False, "last_tick": None, "fresh": False}
        last = entry.get("last_poll_at")
        # N-357 R31 (2026-07-05 SSOT collapse). See docstring at
        # `_isotime.parse_iso_aware` — one call replaces the 5-line
        # inline parse + None-skip + tzinfo-assume shim (sibling to
        # this fn's `sd = parse_iso_aware(started_at)` migration above).
        dt = parse_iso_aware(last)
        fresh = False
        if dt is not None:
            fresh = dt >= (now - timedelta(hours=2))
        return {"enrolled": True, "last_tick": last, "fresh": fresh}

    # ------------------------------------------------------------------
    # Internal per-(account, mailbox) helpers used by the watcher coroutine.
    # ------------------------------------------------------------------

    def _get_mb_state(self, account_id: int, mailbox: str) -> dict[str, Any]:
        return self._mb_state.setdefault((account_id, mailbox), {
            "status": "stopped",
            "processed": 0,
            "errors": 0,
            "last_message": None,
            "last_error": None,
            "started_at": None,
            # PR 5 / C1 — wall-clock timestamp of when the watcher
            # most-recently transitioned into a failing state. Set by
            # _mark_failing(), cleared by _mark_recovered(). /health
            # uses this to decide when to flip to 503 (failing past
            # the 15-min threshold).
            "failing_since": None,
            "last_attempt": None,
        })

    def _mark_failing(
        self, account_id: int, mailbox: str,
        *, error: str | None = None,
    ) -> None:
        """Stamp the watcher's failing_since timestamp.

        Idempotent: if the watcher is already failing, the original
        timestamp is preserved (don't reset the clock just because
        another retry tick fired). Cleared by ``_mark_recovered``.
        """
        import time as _time
        st = self._get_mb_state(account_id, mailbox)
        if st.get("failing_since") is None:
            st["failing_since"] = _time.time()
        st["last_attempt"] = _time.time()
        if error:
            st["last_error"] = error
        st["errors"] = int(st.get("errors", 0)) + 1

    def _mark_recovered(self, account_id: int, mailbox: str) -> None:
        """Clear the failing_since, last_error, and last_attempt fields
        on a successful tick.

        PD#18 / N-49 set-broad/clear-narrow fix: ``last_error`` is SET
        on every transient failure tick (via ``_mark_failing``) but was
        NEVER cleared on recovery, so a recovered watcher rendered a
        stale error string in the admin watch-status UI even after the
        mailbox was healthy again. ``last_attempt`` has the same shape
        (latent). Both are now cleared here — the single success-clear
        site — through the same funnel that already owns
        ``failing_since``. The "unsupported" terminal error (written
        outside the funnel with ``status="unsupported"``) is sticky by
        design and is NOT routed through this clear path.
        """
        st = self._get_mb_state(account_id, mailbox)
        st["failing_since"] = None
        st["last_error"] = None
        st["last_attempt"] = None
        # N-246 R24: PD#18 monotone-tally fix. `errors` was SET on every
        # failing tick (:565) but never CLEARed on recovery, so the
        # `/watch/status` tally at :133 accumulated forever — same
        # set-broad/clear-narrow shape N-49 fixed for `last_error`.
        st["errors"] = 0

    def record_mailbox_outcome(
        self,
        account_id: int,
        mailbox: str,
        *,
        sticky_error: BaseException | None,
    ) -> None:
        """The single funnel for the per-mailbox ``failing_since`` flag.

         v0.2.0 kwarg refactor: ``sticky_error`` is KEYWORD-ONLY so
        every call reads self-documenting — the intent (SET failing vs
        CLEAR to healthy) is visible AT the call site rather than
        depending on the reader knowing "positional 3rd arg is the
        exception". DA-115 F1 rec (2026-07-11 batched panel).

        ``failing_since`` is a *lifecycle* flag (SET on a failing tick,
        CLEAR on a successful one) and before this it was wired
        un-symmetrically: the unified-poll path SET it on a transient
        provider error but its SUCCESS path never CLEARED it, so a
        poll-only mailbox that recovered stayed "failing" on /health past
        the 15-min threshold until a process restart (divergence census
        2026-06-09 #7 — the same set-broad/clear-narrow shape as the
        auth_stale flag fixed in N-44 via ``record_provider_outcome``).

        Route BOTH edges of EVERY continuous per-mailbox surface (poll,
        IDLE reconnect) through here so set and clear can't drift again.
        ``_mark_failing`` / ``_mark_recovered`` are private to this funnel
        (pinned: ``tests/test_watcher_failing_lifecycle_pin.py``).

        * ``sticky_error is None``  -> the tick succeeded -> clear.
        * ``sticky_error is not None`` -> the tick failed -> stamp
          ``failing_since`` (idempotent: an already-failing watcher
          keeps its original timestamp so /health measures the true
          outage duration).
        """
        if sticky_error is None:
            self._mark_recovered(account_id, mailbox)
        else:
            self._mark_failing(
                account_id, mailbox, error=fmt_exc(sticky_error),
            )

    def watchers_failing_for(self, threshold_secs: float) -> list[dict[str, Any]]:
        """Return per-mailbox watchers that have been failing past
        ``threshold_secs``. Used by /health to apply the C1 rollup.
        """
        import time as _time
        now = _time.time()
        out: list[dict[str, Any]] = []
        for (aid, mb), st in self._mb_state.items():
            since = st.get("failing_since")
            if since is None:
                continue
            elapsed = now - float(since)
            if elapsed >= threshold_secs:
                out.append({
                    "account_id": aid,
                    "mailbox": mb,
                    "failing_secs": int(elapsed),
                    "last_error": st.get("last_error"),
                    "errors": int(st.get("errors", 0)),
                })
        return out

    # ------------------------------------------------------------------
    # Start / stop.
    # ------------------------------------------------------------------

    async def start(self, account_id: int) -> str:
        """Start push and/or poll for the account per its config flags.

        Reads ``push_enabled`` and ``poll_enabled`` from the account's
        config (back-compat shim in ``apply_ingestion_back_compat``
        materialises these from legacy state for accounts that predate
        the unified model). Both can be true — push and poll run in
        parallel, push for low-latency delivery and poll as a safety
        net. If both are false, returns "Ingestion disabled" without
        touching anything.

        Fail-closed: if the owning user is disabled, neither is started.
        """
        # Late import: these shared ingestion helpers STAY in
        # web/app.py (used across watcher + poll + push); importing at
        # module top would cycle (app.py re-exports the names defined
        # here). Mirrors the #277c late-import precedent.
        from email_triage.web.app import _poll_state_key
        from email_triage.web.db import (
            _account_mailboxes, get_email_account, is_user_disabled,
            set_bool_setting,
        )
        from email_triage.web.db_threadpool import db_call
        db = self.app.state.db
        #  — WatcherManager.start is awaited from route handlers on
        # the event-loop thread; route every shared-connection touch
        # through db_call. Account lookup + the owner-disabled gate are
        # sequential reads — fold them into one hop.
        def _start_preamble_reads():
            acct = get_email_account(db, account_id)
            if acct is None:
                return None, False
            owner_id = acct.get("user_id")
            disabled = (
                owner_id is not None and is_user_disabled(db, owner_id)
            )
            return acct, disabled

        acct, owner_disabled = await db_call(_start_preamble_reads)
        if acct is None:
            return "Account not found"
        owner_id = acct.get("user_id")
        if owner_disabled:
            log.warning(
                "Watcher start refused: owner disabled",
                account_id=account_id, owner_id=owner_id,
            )
            return "Owner disabled"

        # Fail-closed is_active gate (Loop-5 census). A deactivated
        # account must not (re)start ingestion — restore_from_settings
        # already skips inactive rows, but start() is ALSO the actuator
        # for the per-account funnel + the watcher-bounce + manual
        # start routes, so the gate belongs at THIS actuator too (PD#9:
        # gate at the actuator, not just the writer). Default True so a
        # row missing the column never silently pauses everyone (the
        # column is INTEGER NOT NULL DEFAULT 1, so this is belt-and-
        # braces).
        if not acct.get("is_active", True):
            log.info(
                "Watcher start refused: account inactive",
                account_id=account_id,
            )
            return "Account inactive"

        cfg = acct.get("config") or {}
        push_wanted = bool(cfg.get("push_enabled", True))
        poll_wanted = bool(cfg.get("poll_enabled", True))

        if not push_wanted and not poll_wanted:
            return "Ingestion disabled"

        msgs: list[str] = []

        # ── Poll arm: register with the unified loop. Cheap no-op
        # when already registered. ──────────────────────────────
        if poll_wanted:
            already = account_id in self._poll_registered
            # Hydrate ``last_poll_at`` from DB-persisted state on
            # first registration so the dashboard chip reports
            # accurately across process restarts. Without this the
            # chip showed N-of-M "fresh" for up to one full poll
            # cadence after restart, even though every account had a
            # recent DB-persisted tick. The unified poll tick
            # already updates DB + in-memory together; this just
            # backfills the in-memory side at startup time.
            initial_last_poll: str | None = None
            if not already:
                try:
                    from email_triage.web.db import get_setting
                    persisted = (
                        await db_call(
                            get_setting, self.app.state.db,
                            _poll_state_key(account_id),
                        )
                        or {}
                    )
                    initial_last_poll = persisted.get("last_poll_at") or None
                except Exception:
                    initial_last_poll = None
            self._poll_registered[account_id] = self._poll_registered.get(
                account_id,
                {"last_poll_at": initial_last_poll, "registered_at":
                    now_utc_iso()},
            )
            if not already:
                msgs.append(
                    f"Poll enabled ({int(cfg.get('poll_interval_minutes', 60))} min)"
                )

        # ── Push arm: depends on provider type. ─────────────────
        if push_wanted:
            ptype = acct.get("provider_type")
            #  phase 2 — table-driven dispatch via ProviderDispatcher.
            # IMAP delegates to ``self._start_imap_push`` (touches manager-
            # private state); Gmail records intent in ``settings.watch``
            # via the dispatcher's gmail start_push (which uses
            # ``set_bool_setting`` per .7); O365 records "not yet
            # implemented". Resolved cherry-pick: G2's dispatcher path
            # subsumes D2's inline ``set_bool_setting`` rewrite at this
            # site — the helper still lives in the gmail dispatch body.
            from email_triage.providers.dispatcher import get_dispatch
            disp = get_dispatch(ptype)
            if disp is None:
                msgs.append(f"Push: unknown provider '{ptype}'")
            else:
                msg = await disp.start_push(self, account_id, acct)
                if ptype == "office365":
                    log.debug(
                        "Office 365 push not yet implemented; poll-only",
                        account_id=account_id,
                    )
                msgs.append(msg)
        else:
            # Explicitly record "push off" so restore_from_settings
            # doesn't resurrect a previously-enabled IDLE watcher.
            await db_call(
                set_bool_setting, db, _settings_keys.watch(account_id), False,
            )

        return " · ".join(msgs) if msgs else "No ingestion started"

    async def _start_imap_push(self, account_id: int, acct: dict) -> str:
        """Launch IMAP IDLE watchers for every configured mailbox.

        Broken out of ``start()`` so the new unified entrypoint stays
        legible. Fail-closed checks already happened in the caller.
        """
        from email_triage.web.db import _account_mailboxes, set_bool_setting
        from email_triage.web.db_threadpool import db_call
        from email_triage.providers.base import PushCapable
        from email_triage.web.routers.ui import _create_provider_from_account

        secrets = self.app.state.secrets
        try:
            provider = _create_provider_from_account(acct, secrets)
        except Exception as e:
            return f"Push: provider error: {e}"

        if not isinstance(provider, PushCapable):
            try:
                await provider.close()
            except Exception:
                pass
            return (
                f"Push: provider '{acct['provider_type']}' does not support IDLE"
            )

        try:
            await provider.close()
        except Exception:
            pass

        #  — _start_imap_push is an async def; route the settings
        # write off the event-loop thread.
        await db_call(
            set_bool_setting, self.app.state.db,
            _settings_keys.watch(account_id), True,
        )

        mailboxes = _account_mailboxes(acct.get("config") or {})
        now = now_utc_iso()

        supervisor = getattr(self.app.state, "supervisor", None)

        started: list[str] = []
        for mb in mailboxes:
            key = (account_id, mb)
            existing = self._tasks.get(key)
            if existing is not None and not existing.done():
                continue
            self._mb_state[key] = {
                "status": "starting",
                "processed": 0,
                "errors": 0,
                "last_message": None,
                "last_error": None,
                "started_at": now,
            }
            # Run the watcher under the TaskSupervisor so an unexpected
            # exit (a bug escaping _watch_account's reconnect loop)
            # is logged, restarted with backoff, and visible on /health
            # — instead of the task silently disappearing. The
            # supervisor handles task.cancel() cleanly, so the
            # WatcherManager's own stop()/stop_all() still work
            # unchanged. Fall back to a bare task pre-supervisor (e.g.
            # tests that build a WatcherManager without one).
            sup_name = f"watcher:{account_id}:{mb}"
            if supervisor is not None and not supervisor.is_running(sup_name):
                task = supervisor.supervise(
                    sup_name,
                    (lambda m=mb: _watch_account(
                        self, account_id, mailbox=m,
                    )),
                    restart_on_failure=True,
                )
            else:
                task = asyncio.create_task(
                    _watch_account(self, account_id, mailbox=mb),
                    name=f"watcher-{account_id}-{mb}",
                )
            self._tasks[key] = task
            started.append(mb)

        if not started:
            return "Push: already watching"
        if len(started) == 1:
            return "Push: watching started"
        return f"Push: watching started on {len(started)} mailboxes"

    async def stop(self, account_id: int, *, persist: bool = True) -> str:
        """Stop both push and poll for the account.

        ``persist=True`` (default) clears the ``watch:<id>`` setting so a
        restart leaves the push arm off. ``persist=False`` tears down
        running tasks but leaves settings intact — used when a user is
        disabled (the preference should return automatically on re-enable)
        or when bouncing the watcher mid-config-change.
        """
        from email_triage.web.db import set_bool_setting
        from email_triage.web.db_threadpool import db_call
        db = self.app.state.db
        if persist:
            #  — stop is an async def; route the settings write
            # off the event-loop thread.
            await db_call(
                set_bool_setting, db, _settings_keys.watch(account_id), False,
            )

        # Poll arm: remove from the unified loop's registry. Cheap.
        self._poll_registered.pop(account_id, None)

        # Push arm: cancel every mailbox task for this account.
        cancelled: list[tuple[tuple[int, str], asyncio.Task]] = []
        for key in list(self._tasks):
            aid, _mb = key
            if aid != account_id:
                continue
            task = self._tasks.pop(key, None)
            if task is not None and not task.done():
                task.cancel()
                cancelled.append((key, task))

        # Parallel-await so stopping N mailboxes doesn't take N * (per-
        # task shutdown grace). Bound each wait so a single stuck watcher
        # can't hold up the rest — same 3 s cap stop_all uses.
        if cancelled:
            await asyncio.gather(
                *(asyncio.wait_for(t, timeout=_WATCHER_SHUTDOWN_GRACE_SECS) for _, t in cancelled),
                return_exceptions=True,
            )

        # Drop state entries for this account entirely. Previously these
        # were kept and just marked status="stopped", but the bubbles
        # those produced lingered on the Accounts page after the
        # operator unchecked a mailbox from the watch list (bounce =
        # stop + start; start re-populates only currently-configured
        # mailboxes; the unchecked one's old "stopped" entry was never
        # purged so it kept rendering). Clean tear-down here means
        # bubbles only render for mailboxes the watcher actually
        # tracks right now.
        for (aid, _mb) in list(self._mb_state.keys()):
            if aid == account_id:
                self._mb_state.pop((aid, _mb), None)
        return "Watching stopped"

    async def stop_all(self) -> None:
        """Stop all watcher tasks (called on shutdown).

        Cancels every task in parallel and waits up to 3 s per task
        for the cancellation to propagate (the per-task ``finally``
        runs ``provider.close()`` which can itself touch the network).
        A single hung watcher cannot block the rest. Total worst-case
        shutdown is ~3 s regardless of watcher count — the gather
        fans out across every ``(account_id, mailbox)`` task we own.
        """
        cancelled: list[tuple[tuple[int, str], asyncio.Task]] = []
        for key in list(self._tasks):
            task = self._tasks.pop(key, None)
            if task is None or task.done():
                continue
            task.cancel()
            cancelled.append((key, task))

        if cancelled:
            results = await asyncio.gather(
                *(asyncio.wait_for(t, timeout=_WATCHER_SHUTDOWN_GRACE_SECS) for _, t in cancelled),
                return_exceptions=True,
            )
            for (key, _), result in zip(cancelled, results):
                account_id, mailbox = key
                if isinstance(result, asyncio.TimeoutError):
                    log.warning(
                        "Watcher didn't shut down within 3s; abandoning",
                        account_id=account_id, mailbox=mailbox,
                    )
                elif isinstance(result, asyncio.CancelledError):
                    pass  # expected
                elif isinstance(result, Exception):
                    log.warning(
                        "Watcher shutdown raised",
                        account_id=account_id, mailbox=mailbox,
                        error=str(result),
                    )

        self._mb_state.clear()
        self._poll_registered.clear()

    async def restore_from_settings(self) -> None:
        """Restart push + poll for every active, enabled account.

        The back-compat shim in ``apply_ingestion_back_compat`` has
        already synthesized ``push_enabled`` / ``poll_enabled`` on every
        account read from the DB, so we just call ``start()`` and let it
        honour those flags. Legacy accounts that previously had
        ``watch:{id}`` enabled come back as push+poll; previously-dormant
        accounts come back as poll-only (default — no silent total
        dormancy).

        Skips accounts owned by disabled users — fail-closed at startup.
        """
        from email_triage.web.db import (
            disabled_user_ids, list_email_accounts,
        )
        db = self.app.state.db
        # async-db-ok — restore_from_settings is invoked once
        # from the lifespan startup hook (app.py lifespan), before the
        # server accepts requests. No event-loop contention; the two
        # reads run single-threaded.
        accounts = list_email_accounts(db)  # async-db-ok: lifespan startup
        # .4 — pre-fetch disabled set once; the prior per-account
        # is_user_disabled(db, owner_id) lookup is a 1-query-per-row
        # pattern on a hot path that runs at startup for every account.
        disabled_owners = disabled_user_ids(db)  # async-db-ok: lifespan startup
        restored = 0
        for acct in accounts:
            if not acct.get("is_active", True):
                continue
            owner_id = acct.get("user_id")
            if owner_id is not None and owner_id in disabled_owners:
                log.info(
                    "Skipping watcher restore: owner disabled",
                    account=acct["name"], owner_id=owner_id,
                )
                continue
            cfg = acct.get("config") or {}
            if not cfg.get("push_enabled") and not cfg.get("poll_enabled"):
                # Operator explicitly opted out — no-op.
                continue
            msg = await self.start(acct["id"])
            if msg and msg != "Ingestion disabled":
                restored += 1
                log.info(
                    "Restored watcher", account=acct["name"], detail=msg,
                )
        if restored:
            log.info("Watchers restored from settings", count=restored)

    async def stop_for_user(self, user_id: int) -> list[int]:
        """Stop every watcher whose account is owned by ``user_id``.

        Called when a user is disabled mid-flight. Returns the list of
        account_ids whose watcher was stopped. The persisted
        ``watch:<account_id>`` setting is left intact so re-enabling
        the user restores the prior push/poll posture.
        """
        from email_triage.web.db import list_email_accounts
        from email_triage.web.db_threadpool import db_call
        db = self.app.state.db
        stopped: list[int] = []
        #  — stop_for_user is awaited from the disable-user route
        # handler on the event-loop thread; route the read off-loop.
        _user_accounts = await db_call(
            list_email_accounts, db, user_id=user_id,
        )
        for acct in _user_accounts:
            acct_id = acct["id"]
            if self.is_running(acct_id):
                # N-76b R31 (census r26 close-out): route through the
                # ``apply_account_active_state`` SSOT so the auth_stale
                # chip clear (record_provider_outcome(db, acct, None))
                # + the N-76 log-line + the auth_stale lifecycle set/
                # clear symmetry fire uniformly on both the user-
                # disable teardown AND the per-account-deactivate
                # teardown. The sibling docstring explicitly names
                # this funnel as the mirror of stop_for_user
                # (watcher.py:1192-1194); adopting the SSOT closes
                # the "every account of a disabled user renders
                # 'Re-authenticate required' forever" defect.
                await self.apply_account_active_state(
                    acct_id, active=False,
                )
                stopped.append(acct_id)
        if stopped:
            log.info(
                "Stopped watchers for disabled user",
                user_id=user_id, account_ids=stopped,
            )
        return stopped

    async def apply_account_deleted(
        self, account_id: int, actor_user_id: int | None = None,
    ) -> dict:
        """Lifecycle funnel for permanent account deletion.

        Mirrors :meth:`apply_account_active_state` for the DELETED case.
        Every account-DELETE actuator MUST call this funnel BEFORE (or
        atomically around) deleting the ``email_accounts`` row or the
        owning user row — otherwise:

          * a live IMAP IDLE task / poll registration keeps running for
            the ghost account (leaked IMAP connection + CPU);
          * provider credentials (OAuth tokens, IMAP passwords) remain
            in ``secrets_store`` indefinitely, violating
            §164.310(d)(2)(i) media disposal.

        What this does:

        1. ``self.stop(account_id, persist=True)`` — cancels every live
           IMAP IDLE task and removes the account from the unified poll
           loop.  ``persist=True`` clears the ``watch:{id}`` setting on
           purpose: a Removed account is a FULL offboard (credentials are
           purged below), so a later re-enable via Edit's is_active toggle
           is a re-SETUP (re-enter creds + reconfigure the watch), not a
           resume — there is no paused state worth preserving. (N-108:
           since the operator's "never delete an account" ruling, the
           account ROW soft-survives the Remove; only its live state +
           credentials are torn down here.)

        2. ``purge_account_local_state(conn, account_id, secrets)`` via
           ``db_call`` — sweeps ``settings`` rows + ``secrets_store``
           credentials via the L1 SSOT.

        Returns a dict with ``{"settings_deleted": int, "secrets_deleted":
        int, "account_id": int}`` (from ``purge_account_local_state``)
        plus a ``"watcher_stopped"`` bool.

        The caller is responsible for deleting the ``email_accounts`` row
        itself (or relying on the FK CASCADE on user-delete).
        """
        from email_triage.db.accounts import purge_account_local_state
        from email_triage.db.audit import record_hipaa_access_event
        from email_triage.web.db_threadpool import db_call

        db = self.app.state.db
        secrets = getattr(self.app.state, "secrets", None)

        # Tear down live watcher + poll registration (persist=True so the
        # watch:{id} preference is cleared — the account is gone for good).
        # BEST-EFFORT: a stop() failure must NEVER skip the credential purge
        # below — the purge is the §164.310(d)(2)(i) must-happen action, and
        # the N-62 fail-closed is_active gate already prevents PHI USE for a
        # vanished account, so a lingering task is a leak (degraded), not a
        # disclosure. A stop() exception is logged + swallowed; the purge runs.
        watcher_stopped = self.is_running(account_id)
        try:
            await self.stop(account_id, persist=True)
        except Exception as exc:  # noqa: BLE001 — best-effort teardown
            watcher_stopped = False
            log.warning(
                "apply_account_deleted: watcher stop failed (best-effort); "
                "continuing to the credential purge",
                account_id=account_id,
                error=fmt_exc(exc),
            )

        # Purge settings + secrets + PHI tables via the SSOT. This is the
        # must-happen §164.310(d)(2)(i) action; if it raises it PROPAGATES so
        # the caller can fail CLOSED (refuse the row delete rather than orphan
        # creds). Emit ONE §164.312(b) / §164.308(a)(4)(ii)(C) access-
        # termination audit row here (the SSOT seam) on BOTH outcomes (census
        # N-64 hipaa-sme must-fix) — never PHI in the detail, only counts.
        from email_triage.web._audit import safe_audit_write_async

        async def _audit(outcome: str, detail: str) -> None:
            # census run17 #3 — route the §164.312(b)/§164.308(a)(4)(ii)(C)
            # access-termination emit through the async SSOT sibling so the
            # db_call-seam failure is logged via the ONE audit-failure funnel
            # /health watches (was a hand-rolled try/except WARNING). First real
            # caller of safe_audit_write_async (audit must not mask the op).
            await safe_audit_write_async(
                lambda: db_call(
                    record_hipaa_access_event, db,
                    actor_user_id, account_id, "account_purged", outcome, detail,
                ),
                description=(
                    f"account_purged account_id={account_id} outcome={outcome}"
                ),
            )

        try:
            purge_result = await db_call(
                purge_account_local_state, db, account_id, secrets,
            )
        except Exception as exc:
            await _audit(
                "error",
                f"watcher_stopped={watcher_stopped}; purge failed: "
                f"{fmt_exc(exc)[:160]}",
            )
            raise

        await _audit(
            "ok",
            f"settings={purge_result.get('settings_deleted', 0)} "
            f"secrets={purge_result.get('secrets_deleted', 0)} "
            f"phi_rows={purge_result.get('phi_rows_deleted', 0)} "
            f"msal_cache={purge_result.get('msal_cache_deleted', 0)} "
            f"watcher_stopped={watcher_stopped}",
        )

        log.info(
            "apply_account_deleted: lifecycle teardown complete",
            account_id=account_id,
            watcher_stopped=watcher_stopped,
            settings_deleted=purge_result.get("settings_deleted", 0),
            secrets_deleted=purge_result.get("secrets_deleted", 0),
            phi_rows_deleted=purge_result.get("phi_rows_deleted", 0),
            msal_cache_deleted=purge_result.get("msal_cache_deleted", 0),
        )
        return {**purge_result, "watcher_stopped": watcher_stopped}

    async def apply_account_active_state(
        self, account_id: int, active: bool,
    ) -> str:
        """Lifecycle funnel for an account's ``is_active`` transition.

        Deactivating an account (``active=False``) must tear down LIVE
        ingestion the same way disabling its owner does — otherwise a
        paused HIPAA account keeps reading + classifying + acting on PHI
        until the next process restart (the Loop-5 census defect:
        §164.502(a)(1) / §164.312(a)). Re-activating restarts it the way
        the owner-enable / restore path does.

        This MIRRORS ``stop_for_user`` (the owner-disable teardown): a
        **local-state suppression** — cancel the running push/poll tasks
        with ``persist=False`` (leave the ``watch:<id>`` preference
        intact so re-activation restores the prior posture) and rely on
        the fail-closed ``is_active`` gates now planted at every push /
        IDLE / renewer ACTUATOR to keep the gmail_watch / o365
        subscription rows dormant. We deliberately do NOT delete /
        unregister the Gmail watch or Graph subscription here — that is
        exactly what owner-disable does NOT do either, and an API
        unregister (Graph DELETE / Gmail stop) is a network call that can
        fail and would diverge from the owner-disable contract. The
        renewer gates (which skip an inactive account) are what stop the
        still-present push registrations from being re-armed; cancelling
        the IDLE task here is what stops the live IMAP fetch→classify→act.

        ``active=True`` re-runs ``start()`` (honours the account's
        push/poll flags), the same entrypoint ``restore_from_settings``
        uses — so re-activation restores push+poll per the stored config.

        Returns a short human-readable status string (for the log line /
        caller). Idempotent: deactivating an already-stopped account is a
        cheap no-op (``stop`` tolerates no running tasks); activating an
        already-running account is a cheap no-op (``start`` re-registers
        idempotently).

        Documented residual (hipaa-sme N-62): because we do NOT API-unregister,
        the provider keeps SENDING notifications for ~3-7 days post-deactivation
        (until the gmail_watch / Graph subscription expires unrenewed). Each
        such notification hits the consumer's fail-closed ``is_active`` gate and
        is SKIPPED — the ping is a contentless metadata change-event (no PHI
        body) and we make NO authenticated fetch, so the covered entity performs
        NO §164.501 "use" of PHI. A receive-but-discard posture is an acceptable
        §164.502(a)(1) no-use state, not an open gap (the local actuator gates
        are the fail-closed control). A best-effort API-unregister to shorten the
        window is a possible future defense-in-depth, but must stay best-effort
        and must NEVER become the control compliance rests on.
        """
        if not active:
            # Mirror stop_for_user: persist=False so the push preference
            # returns automatically on re-activation. stop() cancels every
            # IDLE task for the account AND removes it from the unified
            # poll registry — the two live local ingestion surfaces.
            await self.stop(account_id, persist=False)
            # N-76 — clear the auth_stale chip on deactivation. A paused
            # account showing "Re-authenticate required" permanently is
            # misleading: the account is PAUSED, not in need of re-auth. The
            # chip should reflect the credential's last-known liveness, not
            # a stale failure from before pausing. Route through the SSOT
            # funnel (record_provider_outcome(db, acct, None)) so the
            # set/clear paths stay symmetric (feedback_auth_stale_lifecycle).
            # Best-effort: a DB read failure here must never block the
            # deactivation itself.
            try:
                from email_triage.web.db import get_email_account
                from email_triage.web.db_threadpool import db_call
                db = self.app.state.db
                acct = await db_call(get_email_account, db, account_id)
                if acct is not None:
                    from email_triage.web.app import record_provider_outcome
                    await db_call(record_provider_outcome, db, acct, None)
            except Exception:
                log.warning(
                    "apply_account_active_state: auth_stale clear failed "
                    "(best-effort; deactivation proceeds)",
                    account_id=account_id,
                )
            log.info(
                "Account deactivated — ingestion torn down "
                "(push/poll tasks cancelled; registrations left dormant "
                "behind the is_active actuator gates)",
                account_id=account_id,
            )
            return "Ingestion stopped (account inactive)"
        # active=True — restart per the account's push/poll flags, the
        # same path restore_from_settings uses. start() itself fail-closes
        # on owner-disabled + (now) inactive, so a race that re-flips the
        # row back to inactive before this runs is caught there too.
        msg = await self.start(account_id)
        log.info(
            "Account reactivated — ingestion restored",
            account_id=account_id, detail=msg,
        )
        return msg


def _watch_status_phi(message: Any, *, account_hipaa: bool) -> tuple[str, str]:
    """(sender, subject) for the watcher's ``last_message`` status dict.

    N-77 sibling fix. The ``last_message`` dict is rendered in the admin
    watch-status partial (``accounts/_watch_status.html``), so when the
    account is effective-HIPAA the sender + subject are PHI and must NOT be
    surfaced. Redact at the SOURCE (the dict is consumed by multiple readers
    — the partial accesses these keys directly), not in the template. Returns
    the ``REDACTED`` sentinel (a string, so ``subject[:60]`` / ``|length`` in
    the template stay valid) when ``account_hipaa``; the raw values otherwise.

    ``account_hipaa`` is the already-resolved per-account verdict
    (``account_hipaa_effective(account=acct)`` computed once on the per-message
    path), not a fresh global read — so this stays correct on a non-HIPAA
    install with a per-account-HIPAA mailbox.
    """
    if account_hipaa:
        return REDACTED, REDACTED
    return message.sender, (message.subject or "")


def _watch_log_phi(
    message: Any, reason: Any, *, account_hipaa: bool
) -> dict[str, Any]:
    """PHI fields for the watcher's "triaged message" log line.

    N-77. The log line is a §164.312(b) activity record; for an
    effective-HIPAA account it must carry NO PHI, so sender/subject/reason are
    OMITTED entirely (not even a sentinel). For a non-HIPAA account they are
    included (subject capped, reason only when it is not itself already
    redacted). ``account_hipaa`` is the resolved per-account verdict.
    """
    if account_hipaa:
        return {}
    fields: dict[str, Any] = {
        "sender": message.sender,
        "subject": (message.subject or "")[:80],
    }
    if reason and reason != REDACTED:
        fields["reason"] = reason[:500]
    return fields


async def _watch_account(
    manager: WatcherManager,
    account_id: int,
    *,
    mailbox: str = "INBOX",
) -> None:
    """Long-lived coroutine: IMAP IDLE watch + triage for one
    ``(account, mailbox)`` pair.

    On each new message UID yielded by the provider's ``watch()`` async
    generator, fetches the message, classifies it, and runs actions from
    the account's route configuration.  Reconnects with exponential
    backoff on errors.

    Persists a high-water mark (last processed UID) per ``(account,
    mailbox)`` so that restarts don't reprocess old messages. IMAP UIDs
    are monotonically increasing integers **within a mailbox** — UID 500
    in INBOX and UID 500 in Spam are unrelated, so the HWM MUST be
    mailbox-scoped to be correct across multi-folder watches.
    """
    # Late import: these shared ingestion helpers STAY in
    # web/app.py (used across watcher + poll + push); importing at
    # module top would cycle (app.py re-exports the names defined
    # here). Mirrors the #277c late-import precedent.
    from email_triage.web.app import (
        _acct_log_extras, _resolve_hwm_with_uidvalidity, record_provider_outcome,
    )
    app = manager.app
    backoff = 5  # seconds, doubles on consecutive failures, max 300
    max_backoff = 300

    while True:
        provider = None
        acct: dict | None = None
        try:
            db = app.state.db
            config = app.state.config
            secrets = app.state.secrets

            from email_triage.web.db import (
                get_email_account, list_account_routes, record_triage_run,
                get_mailbox_hwm, set_mailbox_hwm, make_hwm_value,
                account_is_active as _account_is_active,
            )
            from email_triage.web.routers.ui import (
                _create_provider_from_account, _build_classifier_from_config,
                _get_categories_from_db,
            )
            from email_triage.web.triage_one import build_default_registry

            #  — _watch_account is the IMAP IDLE watcher coroutine;
            # it runs as a long-lived task ON the event-loop thread, so
            # every shared-connection touch must hop to the threadpool
            # via db_call.
            from email_triage.web.db_threadpool import db_call

            acct = await db_call(get_email_account, db, account_id)
            if acct is None:
                log.error("Watcher: account not found",
                          account_id=account_id, mailbox=mailbox)
                st = manager._get_mb_state(account_id, mailbox)
                st["status"] = "error"
                # the backlog  (Census v3 #4) — PD#18 SET-must-CLEAR:
                # every ``_watch_account`` terminal exit routes the
                # lifecycle through ``record_mailbox_outcome`` so
                # ``/health watchers_failing_for()`` sees the terminal
                # transition. Sibling exits (NotImplementedError terminal +
                # generic-Exception terminal further down) already do
                # this — this exit did
                # not, so ``/health`` treated the mailbox as an active
                # watcher after the coroutine had exited for good.
                # hipaa-sme F1 fold: pass exc=None so ``failing_since``
                # CLEARS (matches N-70 :2085 pattern for terminal
                # exits). Passing a RuntimeError HERE would SET
                # failing_since via the exc-is-not-None branch — the
                # exact bug this fix claims to close (permanently-
                # exited watcher reporting as failing).
                manager.record_mailbox_outcome(
                    account_id, mailbox, sticky_error=None,
                )
                #  (Census v3 re-run) write-order fix: the recovery
                # funnel (_mark_recovered) clears ``last_error`` to None
                # via the PD#18 set-broad/clear-narrow fix. This exit is
                # a permanent terminal (account gone) — the diagnostic
                # story must survive as the sticky reason for the
                # /watch/status UI. Order matters: set it AFTER
                # record_mailbox_outcome zeroed it. Same shape as the
                # NotImplementedError sibling at :2100.
                st["last_error"] = "Account not found"
                return

            provider = _create_provider_from_account(
                acct, secrets, mailbox_override=mailbox,
            )
            classifier = _build_classifier_from_config(config)
            categories = await db_call(
                _get_categories_from_db, db, user_id=acct.get("user_id"),
            )

            #  / 2026-05-13 — per-mailbox route overrides resolve
            # inside the watch() loop below, NOT once at watcher
            # startup: the IDLE watcher is a long-running coroutine
            # whose loop never restarts on its own, so a routing-table
            # cached for the watcher's lifetime would go stale the
            # moment an operator saved a new route.  replaced the
            # original strict per-message resolve with a short-TTL
            # cache (``_setup_cache`` below) — a routing edit still
            # lands within ``_SETUP_CACHE_TTL`` so the operator-facing
            # symptom (save a route → next message ignores it) cannot
            # recur, while a message burst no longer pays ~6 DB
            # round-trips per message.
            #
            # The POLL path at the bottom of this module caches per
            # cycle because polls naturally restart on their interval;
            # the IDLE watcher's short TTL is the cycle-less analogue.

            #  — uniform full action set across every ingestion path.
            registry = build_default_registry(
                include_add_label=True, include_self_event=True,
            )

            #  — short-TTL cache for the per-message setup state.
            # The IDLE watcher rebuilt ~10 DB round-trips of routing /
            # rule-label / list-hint / runtime-setting state for EVERY
            # message (see the per-message block in the watch() loop
            # below). On a burst that is pure overhead. The earlier
            # comment is right that the IDLE watcher has no cycle
            # boundary and so cannot cache for the container lifetime —
            # but a *short* TTL keeps the "rules change live" contract
            # intact (an operator edit lands within the TTL window,
            # same staleness a poll cycle would carry) while collapsing
            # a message burst onto one DB read of each. The cache holds
            # ONLY config-shaped state; the calendar provider + meeting
            # prefs stay per-message (tied to provider lifecycle).
            _setup_cache: dict[str, Any] = {}
            _setup_cache_expires: float = 0.0
            _SETUP_CACHE_TTL = 30.0  # seconds

            # Load high-water mark — last successfully processed UID for
            # THIS mailbox. UIDs are per-mailbox, so INBOX and Spam each
            # carry their own mark; the db helper migrates any legacy
            # per-account key to INBOX on first read.
            _hwm_data = await db_call(
                get_mailbox_hwm, db, account_id, mailbox,
            )
            # Did a prior cursor EXIST for this (account, mailbox)? Derived
            # from the STORED row BEFORE _resolve_hwm_with_uidvalidity collapses
            # it to 0 on a UIDVALIDITY change. This is the loss-signal that
            # tells the reseed branch below apart: a stored cursor that now
            # resolves to 0 means a renumber (real mail loss → chip), whereas
            # no stored cursor means a first-watch (no loss → no chip). Same
            # derivation as the poll path (poll_ingestion._poll_once_imap).
            _had_stored_uid = bool(int((_hwm_data or {}).get("uid", 0)))
            hwm_uid, _live_uidvalidity = await _resolve_hwm_with_uidvalidity(
                provider, account_id, mailbox, _hwm_data,
            )

            # N-201 R22 (2026-07-02): per-tick guard against the SET-then-
            # CLEAR straight-line wipe. If the reseed branch fires
            # `mark_backfill_capped` this tick (UIDVALIDITY renumber), the
            # subsequent post-IDLE-connect `clear_backfill_capped` at line
            # ~1520 would wipe the just-set chip on the same tick. Census
            # run22 R22_2 (HIGH — the ONLY §164.502(a)(1) un-triaged-PHI-
            # in-the-gap signal). Track set-this-tick and gate CLEAR.
            _backfill_chip_set_this_tick = False
            if hwm_uid:
                log.info("Watcher resuming from high-water mark",
                         account=acct["name"], mailbox=mailbox, hwm_uid=hwm_uid)
            else:
                # First watch for this (account, mailbox) — or the
                # mailbox's UIDVALIDITY just changed — seed the HWM to
                # the current latest UID so we only triage NEW mail from
                # this point forward, not the entire backlog.
                if hasattr(provider, "get_latest_uid"):
                    latest = await provider.get_latest_uid()
                    if latest > 0:
                        hwm_uid = latest
                        await db_call(set_mailbox_hwm, db, account_id, mailbox,
                                      make_hwm_value(hwm_uid, _live_uidvalidity))
                        if _had_stored_uid:
                            # A cursor WAS stored but resolved to 0 → this
                            # mailbox's UIDVALIDITY changed (a renumber), not a
                            # first watch. The reseed advances the HWM past every
                            # message below the new latest UID WITHOUT enumerating
                            # them, so any mail that arrived in the gap is never
                            # triaged — the same un-triage hazard the poll path
                            # (poll_ingestion._poll_once_imap) chips. The IDLE
                            # watcher previously stayed SILENT on a renumber while
                            # the poll sibling raised the operator chip (N-171,
                            # the run18  / N-170 root-cause sibling on the
                            # watcher path). Emit the SAME chip via the SAME
                            # funnel so operator action is identical (run a
                            # whole-mailbox triage, then dismiss); recovered=0 —
                            # the reseed enumerates nothing. Gated on
                            # _had_stored_uid so a genuine first-watch seed (no
                            # prior cursor → no loss) does NOT false-chip.
                            from email_triage.web._backfill_chip import (
                                mark_backfill_capped,
                            )
                            await db_call(
                                mark_backfill_capped, db, account_id,
                                kind="imap_uidvalidity",
                                window="mailbox renumbered — UIDVALIDITY change; reseeded to latest",
                                recovered=0,
                                source_mailbox=mailbox,  # N-211 R23: mailbox-scope
                            )
                            _backfill_chip_set_this_tick = True  # N-201
                        log.info(
                            "Watcher seeded high-water mark to current latest",
                            account=acct["name"], mailbox=mailbox,
                            hwm_uid=hwm_uid,
                        )

            manager._get_mb_state(account_id, mailbox)["status"] = "watching"
            # PR 5 / C1 — flip out of failing on a successful connect
            # so /health stops counting this mailbox against the
            # 15-min "failing too long" threshold. Via the lifecycle
            # funnel (census #7) so set/clear stay symmetric.
            manager.record_mailbox_outcome(
                account_id, mailbox, sticky_error=None,
            )
            log.info("Watcher connected", account=acct["name"], mailbox=mailbox)
            # IMAP connect + IDLE established → the credential is alive; clear
            # any prior auth_stale chip. The IMAP IDLE watcher previously never
            # cleared, so an account flagged by the poll path stayed stuck once
            # the watcher reconnected. Census 2026-06-09 #1.
            await db_call(record_provider_outcome, db, acct, None)
            # N-198 R21_6 → N-201 R22 (2026-07-02): backfill-chip lifecycle
            # symmetry — SET on UIDVALIDITY renumber at :~1483, CLEAR here
            # on successful IDLE connect ONLY when SET did NOT fire this
            # tick. The `_backfill_chip_set_this_tick` gate closes the
            # same-tick wipe hazard census run22 R22_2 discovered — the
            # UIDVALIDITY-renumber chip is the only §164.502(a)(1)
            # un-triaged-PHI-in-the-gap operator signal, and unconditional
            # CLEAR wiped it before the operator could see it.
            if not _backfill_chip_set_this_tick:
                try:
                    from email_triage.web._backfill_chip import clear_backfill_capped
                    # N-211 R23: mailbox-scope so a sibling mailbox's chip is
                    # NOT wiped by THIS mailbox's success reconnect. Uses
                    # kwarg (not positional) — clear() accepts source_mailbox
                    # keyword-only.
                    await db_call(clear_backfill_capped, db, account_id,
                                  source_mailbox=mailbox)
                except Exception:  # pragma: no cover — non-decisional telemetry
                    pass
            backoff = 5  # reset on successful connection

            #  — hand the resolved high-water mark to watch() so its
            # post-IDLE scan is a UID-range search (SEARCH UID hwm+1:*)
            # seeded at the resume point, not a SEARCH UNSEEN that would
            # miss a new-but-already-\Seen message. The uid_int <=
            # hwm_uid guard below stays as the durable per-message dedup.
            async for uid in provider.watch(since_uid=hwm_uid):
                # Skip UIDs at or below the high-water mark — already
                # triaged in a previous session.
                uid_int = int(uid)
                if uid_int <= hwm_uid:
                    continue
                # In-flight dedup gate. A push-mode delivery and
                # this watcher cycle can race on the same UID; the
                # second cycle would otherwise pay for a full fetch +
                # classify before tripping the persistent
                # triaged_messages table on the first cycle's
                # post-success write. Volatile (per-process) — the
                # ``claim()`` context manager marks at entry and ALWAYS
                # releases at with-exit (exception-safe SSOT, ).
                from email_triage.web.triage_inflight import claim as _inflight_claim
                # Fail-closed is_active re-check (Loop-5 census), run BEFORE
                # claiming the in-flight slot. The funnel
                # (apply_account_active_state) cancels this task on deactivation,
                # so in the common path we never reach here after a deactivate.
                # Defense-in-depth: the IDLE loop is long-lived and the
                # supervisor may restart it, so a fresh per-message read of
                # is_active stops a paused account's fetch→classify→act WITHOUT
                # waiting for a process restart. ``acct`` is fetched once per
                # connection (top of this loop) so it can't reflect a mid-watch
                # deactivation on its own — hence the fresh read. Cheap
                # single-column read.
                #
                # census run13 #3 — ORDER MATTERS: this db_call can RAISE.
                # Running it BEFORE the claim means a DB error here can't leak
                # the in-flight slot. (run18  — routing through ``claim()``
                # now makes that leak structurally impossible regardless: the CM
                # releases on ANY exit, so even a raise inside the with-block
                # frees the slot. The pre-claim placement is kept as belt-and-
                # suspenders + to skip the claim entirely on a deactivated
                # account.) After the claim there is no await before the try.
                _still_active = await db_call(
                    _account_is_active, db, account_id,
                )
                if not _still_active:
                    log.info(
                        "Watcher stopping: account deactivated mid-watch",
                        account_id=account_id, mailbox=mailbox,
                    )
                    # the backlog  (Census v3 #4) — PD#18 CLEAR
                    # side. Account deactivated by the operator is a
                    # clean shutdown, not a failure; pass exc=None so
                    # the ``failing_since`` marker clears (matches
                    # sibling clean-connect + unsupported terminal calls).
                    manager.record_mailbox_outcome(
                        account_id, mailbox, sticky_error=None,
                    )
                    return
                with _inflight_claim(app.state, account_id, uid) as _won:
                    if not _won:
                        log.info(
                            "Skipping concurrent triage cycle (in_flight)",
                            message_id=uid, account=acct["name"], mailbox=mailbox,
                            skip_reason="in_flight",
                        )
                        continue
                    t0 = time.time()
                    try:
                        message = await provider.fetch_message(uid)

                        #  - per-message calendar context. Built per
                        # message (lazily) so a provider close on the
                        # watcher's main provider doesn't drag down the
                        # calendar client. 2026-05-13 - surrogate-aware
                        # gate so IMAP-with-surrogate accounts get the
                        # calendar provider here.
                        _cal_provider = None
                        _mp = None
                        try:
                            from email_triage.web.db import (
                                get_meeting_prefs as _gmp,
                            )
                            from email_triage.web.calendars import (
                                is_calendar_effectively_enabled as _ice_eff,
                            )
                            from email_triage.web.routers.ui import (
                                _create_calendar_provider_from_account as _ccp,
                            )
                            from email_triage.web.db_threadpool import db_call

                            #  — this runs on the watcher loop thread.
                            # _ice_eff / _gmp read the shared connection and
                            # _ccp opens a calendar provider that also reads
                            # it; fold all three into one sync closure
                            # dispatched through a single db_call hop so the
                            # event loop is never blocked on SQLite here.
                            def _calendar_ctx():
                                cal_provider = None
                                if _ice_eff(db, acct):
                                    cal_provider = _ccp(acct, secrets, db=db)
                                return cal_provider, _gmp(db, acct.get("user_id"))

                            _cal_provider, _mp = await db_call(_calendar_ctx)
                        except Exception:
                            _mp = None

                        from email_triage.web.triage_one import (
                            TriageContext, triage_single_message,
                            _build_rule_labels_map,
                            _build_rule_provider_labels_map,
                        )
                        from email_triage.web.db import (
                            account_addresses as _aa_inline,
                            account_email as _ae_inline,
                        )
                        from email_triage.triage_logging import (
                            account_hipaa_effective,
                        )

                        #  — rebuild the cacheable setup state only when
                        # the short TTL has lapsed. On a message burst this
                        # collapses ~6 DB round-trips per message (routing
                        # table, runtime settings, list hints, both
                        # rule-label maps) onto one read per TTL window.
                        # 2026-05-13 note still holds: the IDLE watcher has
                        # no cycle boundary, so this MUST stay short-lived —
                        # a routing edit must land within ``_SETUP_CACHE_TTL``
                        # (operator-observable parity with a poll cycle).
                        _now_mono = time.monotonic()
                        if not _setup_cache or _now_mono >= _setup_cache_expires:
                            from email_triage.web.db import (
                                effective_routes_by_cat, get_setting,
                            )
                            from email_triage.web.routers.ui import (
                                _load_all_list_hints,
                            )

                            #  — the per-TTL setup-cache rebuild is a
                            # cluster of shared-connection reads; fold the
                            # whole rebuild into one threadpool hop.
                            def _rebuild_setup_cache():
                                _rt = get_setting(db, "runtime_settings")
                                _lh_lists, _lh_rules = _load_all_list_hints(db)
                                return {
                                    "routes_by_cat": effective_routes_by_cat(
                                        db, account_id, mailbox=mailbox,
                                    ),
                                    "dry_run": (_rt or {}).get("dry_run", False),
                                    "lh_lists": _lh_lists,
                                    "lh_rules": _lh_rules,
                                    "rule_labels_map": _build_rule_labels_map(db),
                                    "rule_provider_labels_map": (
                                        _build_rule_provider_labels_map(db)
                                    ),
                                }

                            _setup_cache = await db_call(_rebuild_setup_cache)
                            _setup_cache_expires = (
                                _now_mono + _SETUP_CACHE_TTL
                            )

                        _acct_hipaa = account_hipaa_effective(account=acct)

                        #  - the IMAP IDLE watcher now runs the SAME
                        # per-message body as every other ingestion path.
                        # durable_dedup / mark_triaged_on_success /
                        # set_keyword_on_success stay True (the watcher
                        # relied on the $EmailTriaged + rfc-id gates before
                        # ). It now ALSO fires / rule-labels +
                        #  watches - the pre-#199 watcher skipped them.
                        _ctx = TriageContext(
                            db=db, config=config, secrets=secrets,
                            acct=acct, classifier=classifier,
                            provider=provider, registry=registry,
                            categories=categories,
                            routes_by_cat=_setup_cache["routes_by_cat"],
                            list_hints_lists=_setup_cache["lh_lists"],
                            list_hints_rules_by_list=_setup_cache["lh_rules"],
                            rule_labels_map=_setup_cache["rule_labels_map"],
                            rule_provider_labels_map=(
                                _setup_cache["rule_provider_labels_map"]
                            ),
                            calendar_provider=_cal_provider,
                            meeting_prefs=_mp,
                            self_email=_ae_inline(acct),
                            self_email_addresses=set(_aa_inline(acct)),
                            account_addrs=list(_aa_inline(acct)),
                            self_from_addr=getattr(
                                getattr(app.state.config, "smtp", None),
                                "from_addr", "",
                            ),
                            dry_run=_setup_cache["dry_run"],
                            account_hipaa=_acct_hipaa,
                            actor_user_id=None,
                            durable_dedup=True,
                            mark_triaged_on_success=True,
                            set_keyword_on_success=True,
                            fire_watches=True,
                        )
                        try:
                            _res = await triage_single_message(
                                _ctx, message, uid,
                            )
                        finally:
                            if _cal_provider is not None:
                                try:
                                    await _cal_provider.close()
                                except Exception:
                                    pass
                        _entry = _res.entry

                        # A skip from the shared helper ($EmailTriaged /
                        # rfc-id dedup, self-origin) - the pre-#199 watcher
                        # ``continue``d here without recording a run or
                        # advancing the HWM. Preserve that: skips do not
                        # advance the HWM (the dedup gate re-catches the UID
                        # cheaply next time) and do not write a triage_run.
                        if _res.status == "s":
                            continue

                        #  — live-path watch-fire delivery retry. If any watch
                        # escalate/webhook returned ok=False (genuine delivery
                        # failure, not a config skip), enqueue a retry row so the
                        # drainer re-fires.  idempotency ensures already-
                        # delivered watches are skipped on the re-fire.
                        #
                        # #9: this runs BEFORE the status=="e"
                        # re-raise below. A message that BOTH errored a routed action
                        # AND left a watch undelivered used to skip this block (the
                        # re-raise pre-empted it), so the generic per-message handler
                        # enqueued a NULL-kind row that the admin reads as a generic
                        # "fetch/process error" instead of a delivery failure. Running
                        # the delivery-retry enqueue first stamps the correct
                        # ``watch_delivery_failure`` kind for the undelivered watch.
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
                                        _entry.get("watches_fired") or []
                                    ),
                                    mailbox=mailbox,
                                    uid=str(uid),
                                    uidvalidity=_live_uidvalidity,
                                )
                            except Exception as exc:
                                # #8: a failed enqueue means the
                                # undelivered watch is NOT queued for re-fire — that
                                # is a lost escalation, surface it (fail VISIBLE, PD#8)
                                # rather than silently swallow. The pre-enqueue warning
                                # in triage_single_message announces the NEED to
                                # enqueue; it does NOT cover the enqueue itself raising.
                                log.warning(
                                    "watch-delivery retry enqueue FAILED — the "
                                    "undelivered watch fire is NOT queued for re-fire",
                                    account_id=int(account_id),
                                    mailbox=mailbox,
                                    uid=str(uid),
                                    error=fmt_exc(exc),
                                )

                        if _res.status == "e":
                            # Re-raise into the watcher's existing per-message except
                            # so the retry-queue + maintenance-window handling fires
                            # unchanged. (The  delivery-retry above already ran,
                            # so a watch-undelivered status=="e" row is correctly
                            # labelled before this generic error path takes over.)
                            raise RuntimeError(
                                _entry.get("error", "triage error")
                            )

                        actions_taken = _entry.get("actions", [])
                        classification_category = _entry.get("category", "")
                        classification_confidence = _entry.get(
                            "confidence", 0.0,
                        )

                        elapsed = time.time() - t0
                        # N-213b R27: route per-message state updates
                        # through the `record_message_result` SSOT. The
                        # SSOT owns the increment (processed+=1) + the
                        # PD#18 per-message success clear-edge
                        # (last_error=None + errors=0) + the rich
                        # last_message dict shape (with sender/subject
                        # PHI-scrub via account_hipaa). Passing raw
                        # sender/subject; SSOT does the REDACTED
                        # substitution when account_hipaa=True. Migration
                        # collapses N-213 deferred + N-192 exc_render_twin
                        # + last_message shape drift into one call.
                        record_message_result(
                            manager, account_id, mailbox, "imap-idle",
                            success=True,
                            message_id=str(uid),
                            sender=getattr(message, "sender", None),
                            subject=getattr(message, "subject", None),
                            category=classification_category,
                            confidence=classification_confidence,
                            account_hipaa=_acct_hipaa,
                        )

                        # Log with sender/subject in standard mode, omit in
                        # HIPAA.
                        log_kwargs: dict[str, Any] = {
                            "account": acct["name"],
                            "uid": uid,
                            "category": classification_category,
                            "confidence": classification_confidence,
                            "elapsed": f"{elapsed:.1f}s",
                        }
                        # PHI fields (sender/subject/reason) are OMITTED for an
                        # effective-HIPAA account — §164.312(b): the log record
                        # carries no PHI. Same authoritative per-account verdict
                        # (_acct_hipaa) as the status dict above, so the two
                        # sibling sinks redact consistently and the gate cannot
                        # fail open on a per-account-HIPAA-on-non-HIPAA-install.
                        log_kwargs.update(
                            _watch_log_phi(
                                message, _entry.get("reason"),
                                account_hipaa=_acct_hipaa,
                            )
                        )
                        log.info("Watcher triaged message", **log_kwargs)

                        #  tail — route through the `complete_triage_run`
                        # SSOT so this IMAP-watch terminal RECORDS the run row
                        # AND EMITS the `et_triage_runs_total{trigger,outcome}`
                        # counter AND fires the outbound webhook, in one call.
                        # Pre-fix, `record_triage_run` + `fire_triage_completed`
                        # were called separately here (both fail-soft) and the
                        # counter never fired for watch-triggered triages —
                        # Prometheus IS-activity-review silently under-reported.
                        # `complete_triage_run` internally: fail-soft records
                        # (§164.308(a)(1)(ii)(D)), emits counter unconditionally,
                        # gates the webhook on dispatcher-None internally, so we
                        # pass `dispatcher` verbatim (may be None).
                        dispatcher = getattr(
                            app.state, "event_dispatcher", None,
                        )
                        from email_triage.web.events import (
                            complete_triage_run,
                        )
                        from email_triage._ids import new_run_id
                        try:
                            await complete_triage_run(
                                dispatcher, db, config, acct,
                                run_id=new_run_id("watch", account_id),
                                query="IDLE",
                                trigger="watch",
                                total_messages=1,
                                results=[_entry],
                                errors=[],
                                elapsed_secs=elapsed,
                            )
                        except Exception as _e:
                            log.warning(
                                "watch: complete_triage_run outer "
                                "(webhook/emit) failed",
                                error=str(_e),
                            )

                        # Advance the high-water mark so this UID is not
                        # reprocessed after a restart. Per-mailbox key.
                        if uid_int > hwm_uid:
                            hwm_uid = uid_int
                            await db_call(set_mailbox_hwm, db, account_id, mailbox,
                                          make_hwm_value(hwm_uid, _live_uidvalidity))
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        # Every per-message failure — LLM-unreachable or
                        # ordinary fetch/process error — routes onto the
                        # single consolidated retry queue. The
                        # ``failure_kind`` field is the only distinction:
                        # ``'llm_unreachable'`` rows are skipped by the
                        # drainer while the LLM breaker is open. Auth-
                        # revoked errors enqueue + immediately dead so the
                        # admin sees the artefact but no retries fire.
                        from email_triage.llm_health import (
                            LLMBackendUnreachableError,
                        )
                        _is_llm_down = isinstance(e, LLMBackendUnreachableError)
                        # Census run23 #1 (revised per DA MF-1): route the
                        # per-message failure through the
                        # record_message_result SSOT for the two REAL failure
                        # edges — ordinary triage error AND unscheduled LLM
                        # outage — but SKIP it inside a scheduled LLM
                        # maintenance window (LLM-down is expected /
                        # documented downtime; bumping errors + setting
                        # last_error would red-chip /watch/status for a
                        # documented, operator-configured window and would
                        # invert the whole point of Bundle C's window-aware
                        # log copy). Prior N-213b R27 wiring only fired on
                        # the non-LLM-down else-branch; this preserves that
                        # intent and additionally covers the unscheduled
                        # LLM-outage case that was pre-fix invisible to
                        # /watch/status + /health + the dashboard chip.
                        _record_ssot = True
                        if _is_llm_down:
                            # Maintenance-window-aware log copy (Bundle C).
                            from email_triage.llm_maintenance import (
                                MaintenanceWindow, active_window_for,
                            )
                            windows = list(getattr(
                                app.state.config, "llm_maintenance_windows", []
                            ) or [])
                            rt_windows = [
                                MaintenanceWindow(
                                    host=w.host, cron=w.cron,
                                    duration_minutes=w.duration_minutes,
                                    backend=w.backend,
                                ) for w in windows
                            ]
                            active = active_window_for(e.backend, rt_windows)
                            if active is not None:
                                # Scheduled maintenance window — the LLM
                                # being unreachable is EXPECTED. Suppress
                                # the SSOT SET so /watch/status stays green
                                # during documented downtime; the retry
                                # drainer picks these up when the window
                                # ends and the success edge above fires
                                # symmetrically.
                                _record_ssot = False
                                log.info(
                                    "Watcher: LLM in scheduled maintenance "
                                    "window — message queued for post-window "
                                    "retry",
                                    backend=e.backend,
                                    maintenance_host=active.window.host,
                                    ends_at=render_hm_for_audience(active.ends_at),
                                    account=acct["name"], mailbox=mailbox,
                                    uid=uid,
                                )
                            else:
                                # Unscheduled LLM outage — SSOT records the
                                # failure (pre-fix this was silent — the
                                # UNDER-report class census run23 #1
                                # discovered).
                                log.info(
                                    "Watcher: LLM backend unhealthy — "
                                    "message queued for retry",
                                    account=acct["name"], mailbox=mailbox,
                                    uid=uid, backend=e.backend,
                                    host=e.host, port=e.port,
                                )
                        else:
                            log.error(
                                "Watcher: message triage error",
                                account=acct["name"],
                                mailbox=mailbox,
                                uid=uid,
                                error=fmt_exc(e),
                            )
                        # Durable per-message retry row. The error log above
                        # stays (operator journalctl monitoring depends on
                        # it); this adds a row the drainer picks up on
                        # backoff.
                        try:
                            from email_triage.web.watcher_retry import (
                                enqueue_watcher_retry as _wr_enqueue,
                            )
                            from email_triage.web.db_threadpool import db_call
                            #  — enqueue_watcher_retry writes a retry row
                            # on the shared connection; dispatch it off the
                            # watcher loop thread through db_call.
                            await db_call(
                                _wr_enqueue,
                                app.state.db,
                                account_id=int(account_id),
                                provider_type=acct.get(
                                    "provider_type", "imap",
                                ),
                                mailbox=mailbox,
                                uid=str(uid),
                                uidvalidity=_live_uidvalidity,
                                error=e,
                                failure_kind=(
                                    "llm_unreachable" if _is_llm_down else None
                                ),
                            )
                        except Exception:
                            pass

        except asyncio.CancelledError as _cancel_exc:
            log.info(
                "Watcher cancelled",
                **(_acct_log_extras(acct) if acct else {"account_id": account_id}),
                mailbox=mailbox,
            )
            # the backlog  (Census v3 #4) — PD#18 CLEAR side. Task
            # cancel is a clean shutdown from the ``WatcherManager.
            # stop()``/``stop_all()`` path; pass exc=None so
            # ``failing_since`` clears (matches sibling clean-
            # connect + unsupported terminal calls). DA F3 caveat:
            # ``failing_since`` clears assume ``CancelledError`` is
            # ONLY raised by the operator-driven WatcherManager.stop()
            # / stop_all() paths. If a future task-group orchestration
            # propagates cancel from a sibling failure, revisit — that
            # would justify preserving ``failing_since`` on the peer's
            # behalf. Passing the CancelledError
            # itself would mark the watcher as failing when the
            # operator explicitly asked to stop it.
            manager.record_mailbox_outcome(
                account_id, mailbox, sticky_error=None,
            )
            break
        except NotImplementedError as e:
            # Permanent failure — the provider has no IDLE-style
            # generator (e.g. Gmail push, Graph webhooks). Retrying
            # will never succeed. Mark the watcher unsupported, log
            # once at ERROR, and exit the loop cleanly.
            state = manager._get_mb_state(account_id, mailbox)
            state["status"] = "unsupported"
            log.error(
                "Watcher: provider does not support IDLE generator — "
                "stopping retries",
                account_id=account_id,
                mailbox=mailbox,
                error=fmt_exc(e),
            )
            # N-70 — terminal exit: clear failing_since so /health does not
            # keep reporting this mailbox as "failing for N minutes" after
            # the watcher has exited permanently. The unsupported state is
            # surfaced via state["status"]; the health rollup no longer needs
            # the failing_since timestamp to describe the situation. Via the
            # lifecycle funnel (census #7) so set/clear stay symmetric.
            manager.record_mailbox_outcome(
                account_id, mailbox, sticky_error=None,
            )
            # Set the STICKY unsupported reason AFTER the funnel clear. The
            # recovery funnel (_mark_recovered) now also clears last_error
            # (this batch's PD#18 fix) — but this terminal is permanent-
            # unsupported, NOT a recovery, so the reason must survive as the
            # sticky last_error for the watch-status UI. Order matters: set it
            # after record_mailbox_outcome zeroed it.
            state["last_error"] = (
                "Real-time watch is not supported on this provider. "
                "Use Pub/Sub push or the server-side poller."
            )
            # Clear the watch:enabled setting so restore_from_settings
            # doesn't resurrect the same hopeless task on next startup.
            try:
                from email_triage.web.db import set_bool_setting
                from email_triage.web.db_threadpool import db_call
                await db_call(
                    set_bool_setting, app.state.db,
                    _settings_keys.watch(account_id), False,
                )
            except Exception:
                pass
            break
        except Exception as e:
            # PR 5 / C1 — record the failure with a wall-clock
            # timestamp so /health can apply the 15-min threshold
            # (and so the operator can see "this watcher has been
            # red for 22 minutes" via the admin UI). Via the lifecycle
            # funnel (census #7) so set/clear stay symmetric.
            manager.record_mailbox_outcome(
                account_id, mailbox, sticky_error=e,
            )
            state = manager._get_mb_state(account_id, mailbox)
            state["status"] = "reconnecting"
            log.warning(
                "Watcher connection lost, reconnecting",
                **(_acct_log_extras(acct) if acct else {"account_id": account_id}),
                mailbox=mailbox,
                error=fmt_exc(e),
                backoff=backoff,
            )
            # Auth-revoked connection failure (changed IMAP password / revoked
            # OAuth) → surface the re-auth chip instead of an endless
            # "reconnecting" with no cue. Needle-filtered (transient drops are
            # ignored); guard acct (may be None if the account lookup itself
            # failed). Census 2026-06-09 #1.
            if acct is not None:
                try:
                    await db_call(record_provider_outcome, db, acct, e)
                except Exception:
                    pass
            await asyncio.sleep(backoff)
            backoff = next_backoff_delay(backoff, factor=2.0, max_delay=max_backoff)  # N-228 R22 SSOT
        finally:
            if provider is not None:
                try:
                    await provider.close()
                except Exception:
                    pass
