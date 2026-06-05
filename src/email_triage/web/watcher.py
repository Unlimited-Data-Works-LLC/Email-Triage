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

from email_triage.triage_logging import get_logger
from email_triage.web import settings_keys as _settings_keys
from email_triage._errfmt import fmt_exc
from email_triage._isotime import parse_iso

#: Logger record name preserved as "web.app" (not "web.watcher") so the
#: watcher's existing log-stream identity is byte-identical post-move.
log = get_logger("web.app")


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
            dt = parse_iso(last)
            if dt is None:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
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

            alert: str | None = None
            if mode == "none" and not push.get("transient"):
                alert = "no_ingestion"
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
                sd = parse_iso(started_at)
                if sd is None:
                    continue
                if sd.tzinfo is None:
                    sd = sd.replace(tzinfo=timezone.utc)
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
        dt = parse_iso(last)
        fresh = False
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
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
        """Clear the failing_since timestamp on a successful tick."""
        st = self._get_mb_state(account_id, mailbox)
        st["failing_since"] = None

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
                    datetime.now(timezone.utc).isoformat()},
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
        now = datetime.now(timezone.utc).isoformat()

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
                *(asyncio.wait_for(t, timeout=3.0) for _, t in cancelled),
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
                *(asyncio.wait_for(t, timeout=3.0) for _, t in cancelled),
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
                await self.stop(acct_id, persist=False)
                stopped.append(acct_id)
        if stopped:
            log.info(
                "Stopped watchers for disabled user",
                user_id=user_id, account_ids=stopped,
            )
        return stopped

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
    from email_triage.web.app import _acct_log_extras, _resolve_hwm_with_uidvalidity
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
                get_mailbox_hwm, set_mailbox_hwm,
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
            hwm_uid, _live_uidvalidity = await _resolve_hwm_with_uidvalidity(
                provider, account_id, mailbox, _hwm_data,
            )

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
                        await db_call(set_mailbox_hwm, db, account_id, mailbox, {
                            "uid": hwm_uid,
                            "uidvalidity": _live_uidvalidity,
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        })
                        log.info(
                            "Watcher seeded high-water mark to current latest",
                            account=acct["name"], mailbox=mailbox,
                            hwm_uid=hwm_uid,
                        )

            manager._get_mb_state(account_id, mailbox)["status"] = "watching"
            # PR 5 / C1 — flip out of failing on a successful connect
            # so /health stops counting this mailbox against the
            # 15-min "failing too long" threshold.
            manager._mark_recovered(account_id, mailbox)
            log.info("Watcher connected", account=acct["name"], mailbox=mailbox)
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
                # post-success write. Volatile (per-process) — claim
                # at fetch start, release in the per-message finally.
                from email_triage.web.triage_inflight import (
                    mark_inflight as _mark_inflight,
                    release_inflight as _release_inflight,
                )
                if not _mark_inflight(app.state, account_id, uid):
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
                        is_account_hipaa, is_hipaa_mode,
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

                    _acct_hipaa = is_hipaa_mode() or is_account_hipaa(acct)

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
                    if _res.status == "e":
                        # Re-raise into the watcher's existing
                        # per-message except so the retry-queue +
                        # maintenance-window handling fires unchanged.
                        raise RuntimeError(
                            _entry.get("error", "triage error")
                        )

                    #  — live-path watch-fire delivery retry. If
                    # any watch escalate/webhook returned ok=False
                    # (genuine delivery failure, not a config skip),
                    # enqueue a retry row so the drainer re-fires.
                    #  idempotency ensures already-delivered
                    # watches are skipped on the re-fire.
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
                        except Exception:
                            # Best-effort; the warning already logged
                            # in triage_single_message surfaces the gap.
                            pass

                    actions_taken = _entry.get("actions", [])
                    classification_category = _entry.get("category", "")
                    classification_confidence = _entry.get(
                        "confidence", 0.0,
                    )

                    elapsed = time.time() - t0
                    state = manager._get_mb_state(account_id, mailbox)
                    state["processed"] = state.get("processed", 0) + 1
                    state["last_message"] = {
                        "sender": message.sender,
                        "subject": message.subject,
                        "category": classification_category,
                        "confidence": classification_confidence,
                        "at": datetime.now(timezone.utc).isoformat(),
                        "mailbox": mailbox,
                    }

                    # Log with sender/subject in standard mode, omit in
                    # HIPAA.
                    log_kwargs: dict[str, Any] = {
                        "account": acct["name"],
                        "uid": uid,
                        "category": classification_category,
                        "confidence": classification_confidence,
                        "elapsed": f"{elapsed:.1f}s",
                    }
                    if not is_hipaa_mode():
                        log_kwargs["sender"] = message.sender
                        log_kwargs["subject"] = (message.subject or "")[:80]
                        _reason = _entry.get("reason")
                        if _reason and _reason != "[redacted]":
                            log_kwargs["reason"] = _reason[:500]
                    log.info("Watcher triaged message", **log_kwargs)

                    # Record as a triage run (1-message batch). The
                    # shared helper already built the HIPAA-redacted
                    # entry.
                    try:
                        await db_call(
                            record_triage_run,
                            db,
                            account_id=account_id,
                            account_name=acct.get("name", ""),
                            query="IDLE",
                            total_messages=1,
                            results=[_entry],
                            errors=[],
                            elapsed_secs=elapsed,
                        )
                    except Exception:
                        pass

                    # Outbound webhook (HIPAA + quiet-hours gated).
                    dispatcher = getattr(
                        app.state, "event_dispatcher", None,
                    )
                    if dispatcher is not None:
                        from email_triage.web.events import (
                            fire_triage_completed,
                        )
                        try:
                            await fire_triage_completed(
                                dispatcher, db, config, acct,
                                {
                                    "run_id": (
                                        f"watch_{account_id}_"
                                        f"{int(time.time())}"
                                    ),
                                    "query": "IDLE",
                                    "total_messages": 1,
                                    "results": [{}],
                                    "errors": [],
                                    "elapsed_secs": elapsed,
                                },
                                trigger="watch",
                            )
                        except Exception as _e:
                            log.warning(
                                "watch: triage.completed dispatch failed",
                                error=str(_e),
                            )

                    # Advance the high-water mark so this UID is not
                    # reprocessed after a restart. Per-mailbox key.
                    if uid_int > hwm_uid:
                        hwm_uid = uid_int
                        await db_call(set_mailbox_hwm, db, account_id, mailbox, {
                            "uid": hwm_uid,
                            "uidvalidity": _live_uidvalidity,
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        })
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
                            log.info(
                                "Watcher: LLM in scheduled maintenance "
                                "window — message queued for post-window "
                                "retry",
                                backend=e.backend,
                                maintenance_host=active.window.host,
                                ends_at=active.ends_at.strftime("%H:%M UTC"),
                                account=acct["name"], mailbox=mailbox,
                                uid=uid,
                            )
                        else:
                            log.info(
                                "Watcher: LLM backend unhealthy — "
                                "message queued for retry",
                                account=acct["name"], mailbox=mailbox,
                                uid=uid, backend=e.backend,
                                host=e.host, port=e.port,
                            )
                    else:
                        state = manager._get_mb_state(account_id, mailbox)
                        state["errors"] = state.get("errors", 0) + 1
                        state["last_error"] = fmt_exc(e)
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
                finally:
                    # Release the in-flight slot so a re-delivery (Gmail
                    # push retry, IMAP IDLE re-emit) for the same UID
                    # can proceed once this cycle is fully done.
                    _release_inflight(app.state, account_id, uid)

        except asyncio.CancelledError:
            log.info(
                "Watcher cancelled",
                **(_acct_log_extras(acct) if acct else {"account_id": account_id}),
                mailbox=mailbox,
            )
            break
        except NotImplementedError as e:
            # Permanent failure — the provider has no IDLE-style
            # generator (e.g. Gmail push, Graph webhooks). Retrying
            # will never succeed. Mark the watcher unsupported, log
            # once at ERROR, and exit the loop cleanly.
            state = manager._get_mb_state(account_id, mailbox)
            state["status"] = "unsupported"
            state["last_error"] = (
                "Real-time watch is not supported on this provider. "
                "Use Pub/Sub push or the server-side poller."
            )
            log.error(
                "Watcher: provider does not support IDLE generator — "
                "stopping retries",
                account_id=account_id,
                mailbox=mailbox,
                error=fmt_exc(e),
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
            # red for 22 minutes" via the admin UI).
            manager._mark_failing(account_id, mailbox, error=fmt_exc(e))
            state = manager._get_mb_state(account_id, mailbox)
            state["status"] = "reconnecting"
            log.warning(
                "Watcher connection lost, reconnecting",
                **(_acct_log_extras(acct) if acct else {"account_id": account_id}),
                mailbox=mailbox,
                error=fmt_exc(e),
                backoff=backoff,
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        finally:
            if provider is not None:
                try:
                    await provider.close()
                except Exception:
                    pass
