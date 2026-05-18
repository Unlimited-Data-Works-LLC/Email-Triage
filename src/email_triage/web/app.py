"""FastAPI application for the email triage web interface.

Server-rendered UI with HTMX for dynamic interactions, Pico CSS for
classless styling.  No JavaScript build step.

Auth: passwordless email OTP (6-digit code, 10-minute expiry).
Roles: admin, power_user, user.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from email_triage.config import TriageConfig, load_config
from email_triage.secrets import SecretsProvider, create_secrets_provider
from email_triage.triage_logging import get_logger, setup_logging
from email_triage.web.db import init_db, seed_categories
from email_triage.web import settings_keys as _settings_keys
from email_triage._errfmt import fmt_exc

log = get_logger("web.app")

_WEB_DIR = Path(__file__).parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"


def _resolve_version() -> str:
    """Resolve a short build identifier for the ``/health`` endpoint.

    Preference order:
        1. ``EMAIL_TRIAGE_VERSION`` env var (runtime override — ad-hoc
           testing, manual deploys, CI injection)
        2. ``GIT_SHA`` env var (common CI convention)
        3. ``/app/VERSION`` file baked in at container build time by
           the Containerfile (``COPY COMMIT /app/VERSION``). The deploy
           script writes ``git rev-parse HEAD`` into the ``COMMIT`` file
           in the build context before ``podman build``.
        4. ``.git/HEAD`` walked to a commit sha (first 7 chars) — dev
           checkout fallback.
        5. ``"unknown"``

    Resolved once at startup; the health endpoint reads the cached
    value from ``app.state.version`` and never shells out.
    """
    for key in ("EMAIL_TRIAGE_VERSION", "GIT_SHA"):
        val = os.environ.get(key, "").strip()
        if val:
            return val[:40]  # defensive cap — short sha is 7, full is 40

    # Baked-in build identifier — container image path.
    try:
        with open("/app/VERSION", encoding="utf-8") as f:
            v = f.read().strip()
    except OSError:
        v = ""
    # Treat the placeholder "dev" / "unknown" sentinels as "no baked value"
    # so local dev checkouts still fall through to the .git/HEAD walk.
    if v and v not in {"dev", "unknown"}:
        return v[:40]

    # Walk from this file up to find a .git directory or file.
    # Bounded by filesystem root to avoid infinite loops.
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        candidate = parent / ".git"
        if not candidate.exists():
            continue
        try:
            if candidate.is_file():
                # Worktree layout — ``.git`` is a file: "gitdir: <path>".
                first_line = candidate.read_text(encoding="utf-8").splitlines()[0]
                if first_line.startswith("gitdir:"):
                    gitdir = Path(first_line.split(":", 1)[1].strip())
                    if not gitdir.is_absolute():
                        gitdir = (parent / gitdir).resolve()
                else:
                    break
            else:
                gitdir = candidate

            head_file = gitdir / "HEAD"
            if not head_file.is_file():
                break
            head = head_file.read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref = head.split(" ", 1)[1].strip()
                # Check packed refs first, then loose.
                loose = gitdir / ref
                if loose.is_file():
                    sha = loose.read_text(encoding="utf-8").strip()
                    if sha:
                        return sha[:7]
                # Try commondir (worktree shares objects + packed-refs).
                commondir_file = gitdir / "commondir"
                if commondir_file.is_file():
                    common = Path(commondir_file.read_text(encoding="utf-8").strip())
                    if not common.is_absolute():
                        common = (gitdir / common).resolve()
                    packed = common / "packed-refs"
                    loose_shared = common / ref
                    if loose_shared.is_file():
                        sha = loose_shared.read_text(encoding="utf-8").strip()
                        if sha:
                            return sha[:7]
                    if packed.is_file():
                        for line in packed.read_text(encoding="utf-8").splitlines():
                            if line.startswith("#") or line.startswith("^"):
                                continue
                            parts = line.split()
                            if len(parts) == 2 and parts[1] == ref:
                                return parts[0][:7]
                # Fall through to unknown.
                break
            else:
                # Detached HEAD — the file contains the sha directly.
                if head:
                    return head[:7]
        except Exception:
            break
        break

    return "unknown"


def _acct_log_extras(acct: dict) -> dict:
    """Return owner + account identifiers for structured logs.

    Always emits ``account_name``, ``owner_name`` (or ``owner_email`` as
    fallback), and ``account_id``. Operators identify accounts by
    name/owner; the id is a tiebreaker when names collide. Never log
    account_id alone — admins can't look it up.

    Splat into any log call where ``acct`` (from
    ``get_email_account`` / ``list_email_accounts``) is in scope.

    HIPAA: ``acct["name"]`` and owner identifiers are workforce-member
    identifiers (the operator of the mailbox), not patient data. Safe
    to log on any account. Message-level PHI (sender, subject, body)
    is handled separately by the logger's ``_PHI_KEYS`` scrubber.
    """
    out = {
        "account_name": acct.get("name", ""),
        "account_id": acct["id"],
    }
    owner_name = acct.get("owner_name") or ""
    owner_email = acct.get("owner_email") or ""
    if owner_name:
        out["owner"] = owner_name
    elif owner_email:
        out["owner"] = owner_email
    return out


# ---------------------------------------------------------------------------
# Watcher Manager — manages per-account IMAP IDLE background tasks
# ---------------------------------------------------------------------------

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
    # wired (see PUNCH-LIST item).
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
            try:
                dt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt >= cutoff:
                    fresh += 1
            except Exception:
                continue
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
    # #53 O365 Graph) to one branch in this method.
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
            # #120: skip operator-disabled accounts. is_active=0 is the
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
                try:
                    sd = datetime.fromisoformat(
                        str(started_at).replace("Z", "+00:00")
                    )
                    if sd.tzinfo is None:
                        sd = sd.replace(tzinfo=timezone.utc)
                    if (now - sd) <= grace:
                        transient = True
                        break
                except Exception:
                    continue
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
                exp_dt: datetime | None = None
                if exp_raw:
                    try:
                        exp_dt = datetime.fromisoformat(
                            str(exp_raw).replace("Z", "+00:00")
                        )
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        exp_dt = None
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
            # (#53). One row per account in ``office365_subscriptions``;
            # active iff status='active' AND expiration_at in the future.
            wr = (o365_sub_by_id or {}).get(aid) if o365_sub_by_id else None
            configured = wr is not None
            active = False
            transient = False
            detail = "Graph push not configured"
            if wr:
                exp_raw = wr.get("expiration_at")
                exp_dt: datetime | None = None
                if exp_raw:
                    try:
                        exp_dt = datetime.fromisoformat(
                            str(exp_raw).replace("Z", "+00:00")
                        )
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        exp_dt = None
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
        fresh = False
        if last:
            try:
                dt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                fresh = dt >= (now - timedelta(hours=2))
            except Exception:
                fresh = False
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
        from email_triage.web.db import (
            _account_mailboxes, get_email_account, is_user_disabled,
            set_bool_setting,
        )
        db = self.app.state.db
        acct = get_email_account(db, account_id)
        if acct is None:
            return "Account not found"
        owner_id = acct.get("user_id")
        if owner_id is not None and is_user_disabled(db, owner_id):
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
                        get_setting(self.app.state.db, _poll_state_key(account_id))
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
            # #138 phase 2 — table-driven dispatch via ProviderDispatcher.
            # IMAP delegates to ``self._start_imap_push`` (touches manager-
            # private state); Gmail records intent in ``settings.watch``
            # via the dispatcher's gmail start_push (which uses
            # ``set_bool_setting`` per #145.7); O365 records "not yet
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
            set_bool_setting(db, _settings_keys.watch(account_id), False)

        return " · ".join(msgs) if msgs else "No ingestion started"

    async def _start_imap_push(self, account_id: int, acct: dict) -> str:
        """Launch IMAP IDLE watchers for every configured mailbox.

        Broken out of ``start()`` so the new unified entrypoint stays
        legible. Fail-closed checks already happened in the caller.
        """
        from email_triage.web.db import _account_mailboxes, set_bool_setting
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

        set_bool_setting(self.app.state.db, _settings_keys.watch(account_id), True)

        mailboxes = _account_mailboxes(acct.get("config") or {})
        now = datetime.now(timezone.utc).isoformat()

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
        db = self.app.state.db
        if persist:
            set_bool_setting(db, _settings_keys.watch(account_id), False)

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
        accounts = list_email_accounts(db)
        # #134.4 — pre-fetch disabled set once; the prior per-account
        # is_user_disabled(db, owner_id) lookup is a 1-query-per-row
        # pattern on a hot path that runs at startup for every account.
        disabled_owners = disabled_user_ids(db)
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
        db = self.app.state.db
        stopped: list[int] = []
        for acct in list_email_accounts(db, user_id=user_id):
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
                _get_categories_from_db, _collect_list_hints_for_message,
            )
            from email_triage.actions.move import MoveAction
            from email_triage.actions.label import LabelAction
            from email_triage.actions.notify import NotifyAction
            from email_triage.actions.draft_reply import DraftReplyAction
            from email_triage.actions.invite import (
                AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
            )
            from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
            from email_triage.actions.registry import ActionRegistry
            from email_triage.engine.models import FlowState, FlowStatus

            acct = get_email_account(db, account_id)
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
            categories = _get_categories_from_db(db, user_id=acct.get("user_id"))

            # #51 / 2026-05-13 — per-mailbox route overrides resolve
            # PER-MESSAGE (inside the watch() loop below), NOT once at
            # watcher startup. The IDLE watcher is a long-running
            # coroutine; its loop never restarts on its own, so a
            # routing-table cache built here would stay stale for the
            # entire container lifetime. Operator-side symptom (caught
            # 2026-05-13 by a meeting-request that didn't draft a
            # reply): save a new route via /routes/save → next
            # incoming message still uses the OLD table → no
            # actions fire. Mitigation is one tiny SELECT per new
            # message, dwarfed by the fetch + classify cost.
            #
            # The POLL path at the bottom of this module is
            # deliberately the OPPOSITE — caches per cycle — because
            # polls naturally restart on their interval; the comment
            # there documents the trade-off. IDLE has no cycle, so
            # it can't ride that pattern.
            from email_triage.web.db import effective_routes_by_cat

            registry = ActionRegistry()
            registry.register(MoveAction())
            registry.register(LabelAction())
            registry.register(NotifyAction())
            registry.register(DraftReplyAction())
            registry.register(AcceptInviteAction())
            registry.register(DeclineInviteAction())
            registry.register(TentativeInviteAction())
            registry.register(SuggestMeetingTimesAction())

            # Load high-water mark — last successfully processed UID for
            # THIS mailbox. UIDs are per-mailbox, so INBOX and Spam each
            # carry their own mark; the db helper migrates any legacy
            # per-account key to INBOX on first read.
            _hwm_data = get_mailbox_hwm(db, account_id, mailbox)
            hwm_uid = int((_hwm_data or {}).get("uid", 0))

            if hwm_uid:
                log.info("Watcher resuming from high-water mark",
                         account=acct["name"], mailbox=mailbox, hwm_uid=hwm_uid)
            else:
                # First watch for this (account, mailbox) — seed the
                # HWM to the current latest UID so we only triage NEW
                # mail from this point forward, not the entire backlog.
                if hasattr(provider, "get_latest_uid"):
                    latest = await provider.get_latest_uid()
                    if latest > 0:
                        hwm_uid = latest
                        set_mailbox_hwm(db, account_id, mailbox, {
                            "uid": hwm_uid,
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

            async for uid in provider.watch():
                # Skip UIDs at or below the high-water mark — already
                # triaged in a previous session.
                uid_int = int(uid)
                if uid_int <= hwm_uid:
                    continue
                # In-flight dedup gate (#114). A push-mode delivery and
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
                    # Tag with the resolved HIPAA state for this account
                    # so downstream actions and logs scrub correctly.
                    from email_triage.triage_logging import is_account_hipaa
                    message.hipaa = is_account_hipaa(acct)
                    # Loop-prevention: if this mail carries our own
                    # X-Email-Triage stamp, skip it before paying for
                    # the classifier call. Digest delivered into a
                    # watched inbox is the canonical cascade risk.
                    from email_triage.mail_headers import (
                        get_triage_header, get_rfc_message_id,
                        is_self_origin,
                    )
                    _et_header = get_triage_header(message.headers)
                    if _et_header:
                        log.info(
                            "Skipping re-triage of email-triage-generated message",
                            message_id=uid,
                            account=acct["name"],
                            x_email_triage=_et_header,
                            skip_reason="self_origin",
                        )
                        continue
                    # Defense in depth (#117): downstream MTA / forwarder
                    # may have stripped the X-Email-Triage header. If
                    # the sender matches the install's outbound
                    # smtp.from_addr, skip anyway.
                    _self_from = getattr(
                        getattr(app.state.config, "smtp", None),
                        "from_addr", "",
                    )
                    if is_self_origin(message.sender or "", _self_from):
                        log.info(
                            "Skipping self-origin message (header missing)",
                            message_id=uid,
                            account=acct["name"],
                            skip_reason="self_origin",
                        )
                        continue
                    # IMAP $EmailTriaged keyword sentinel — survives
                    # COPY into watched destination folders.
                    if "$EmailTriaged" in (message.labels or []):
                        log.info(
                            "Skipping already-triaged message (keyword sentinel)",
                            message_id=uid, account=acct["name"], mailbox=mailbox,
                        )
                        continue
                    # Cross-folder dedup: same RFC Message-Id seen
                    # before (any folder, this account) → skip. Stops
                    # the cascade where a moved message reaches a
                    # watched destination folder with a fresh UID.
                    _rfc_id = get_rfc_message_id(message.headers)
                    if _rfc_id:
                        from email_triage.web.db import is_triaged
                        if is_triaged(db, account_id, _rfc_id):
                            log.info(
                                "Skipping already-triaged message (rfc_id dedup)",
                                message_id=uid, account=acct["name"],
                                mailbox=mailbox,
                            )
                            continue
                    hints = _collect_list_hints_for_message(db, message)
                    classification = await classifier.classify(
                        message, categories, hints or None,
                    )

                    # Execute actions (respecting dry-run mode).
                    from email_triage.web.db import get_setting
                    _rt = get_setting(db, "runtime_settings")
                    _dry_run = (_rt or {}).get("dry_run", False)

                    # 2026-05-13 — re-resolve the routing table for
                    # EVERY message. See the comment at the watcher
                    # setup site (above ActionRegistry construction)
                    # for the operator-symptom rationale. One small
                    # SELECT per new mail arrival; safe because new
                    # mail arrivals are naturally rate-limited by
                    # actual human + automated mail volume.
                    routes_by_cat = effective_routes_by_cat(
                        db, account_id, mailbox=mailbox,
                    )

                    actions_taken = []
                    action_defs = routes_by_cat.get(classification.category, [])
                    # 2026-05-13 — meeting-request intercept auto-inject.
                    # The UI presents suggest_meeting_times as automatic
                    # ("Meeting-Request Intercept") and the action's own
                    # docstring uses "intercept" — but the action was
                    # previously only reachable via explicit route config,
                    # AND the route picker didn't even surface it. Inject
                    # at the routing boundary so every consumer (IDLE
                    # watcher, push consumers, poll loop, manual triage)
                    # gets the same auto-fire behaviour from one source.
                    try:
                        from email_triage.web.db import (
                            get_meeting_prefs as _gmp2,
                        )
                        from email_triage.web.calendars import (
                            is_calendar_effectively_enabled as _ice2_eff,
                        )
                        from email_triage.actions.suggest_meeting_times import (
                            inject_meeting_intercept as _inject,
                        )
                        _cal_on = bool(_ice2_eff(db, acct))
                        _prefs2 = _gmp2(db, acct.get("user_id"))
                        action_defs = _inject(
                            action_defs, classification.category,
                            calendar_wired=_cal_on,
                            has_meeting_prefs=bool(_prefs2),
                        )
                    except Exception:
                        # Best-effort intercept; never block the route
                        # path on intercept-machinery failure.
                        pass
                    for action_def in action_defs:
                        action_name = action_def.get("action", "")
                        action_config = action_def.get("config", {})
                        action = registry.get(action_name)
                        if action is None:
                            continue

                        if _dry_run:
                            log.info(
                                "DRY RUN: would execute action",
                                action=action_name,
                                category=classification.category,
                                uid=uid,
                                account=acct["name"],
                            )
                            actions_taken.append({
                                "name": action_name,
                                "result": "dry_run",
                                "data": None,
                                "error": None,
                            })
                            continue

                        # Calendar context: lazily built per-flow so a
                        # provider close on the watcher's main provider
                        # doesn't drag down the calendar client. The
                        # invite + suggest_meeting_times actions read
                        # these from state_bag.
                        _cal_provider = None
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
                            # 2026-05-13 — surrogate-aware gate so
                            # IMAP-with-surrogate accounts get the
                            # calendar provider built here (otherwise
                            # the in-loop suggest_meeting_times +
                            # invite actions all SKIP with
                            # calendar_not_enabled).
                            if _ice_eff(db, acct):
                                # Pass db so IMAP-with-surrogate
                                # accounts (#105 phase 1A++) get
                                # the surrogate's provider here.
                                _cal_provider = _ccp(acct, secrets, db=db)
                            _mp = _gmp(db, acct.get("user_id"))
                        except Exception:
                            _mp = None

                        from email_triage.web.db import (
                            account_addresses as _aa_inline,
                            account_email as _ae_inline,
                        )
                        flow = FlowState(
                            flow_id=FlowState.new_id(),
                            message_id=uid,
                            provider=acct["provider_type"],
                            status=FlowStatus.ACTING,
                            state_bag={
                                "calendar_provider": _cal_provider,
                                "meeting_prefs": _mp,
                                "self_email": _ae_inline(acct),
                                # #106 — see triage_runner.run_triage
                                # for the alias-aware self-set rationale.
                                "self_email_addresses": _aa_inline(acct),
                                "account_id": account_id,
                                "account_name": acct.get("name", ""),
                                "owner": acct.get("owner_name") or acct.get("owner_email", ""),
                                # #73 — SMTP for escalation send.
                                "smtp_config": app.state.config.smtp,
                                "secrets": app.state.secrets,
                            },
                        )
                        try:
                            output = await action.execute(
                                flow, message, classification, provider, action_config,
                            )
                        finally:
                            if _cal_provider is not None:
                                try:
                                    await _cal_provider.close()
                                except Exception:
                                    pass
                        actions_taken.append({
                            "name": action_name,
                            "result": output.result.value,
                            "data": output.data,
                            "error": output.error,
                        })

                    # Loop-prevention post-triage: stamp the dedup
                    # table with this message's RFC Message-Id, and
                    # set the IMAP $EmailTriaged keyword sentinel
                    # so the message carries the marker even if it
                    # gets COPY'd into another watched folder.
                    if _rfc_id:
                        from email_triage.web.db import mark_triaged
                        mark_triaged(db, account_id, _rfc_id)
                    if acct["provider_type"] == "imap":
                        try:
                            await provider.set_keywords(uid, ["$EmailTriaged"])
                        except Exception:
                            # Best-effort. Not every IMAP server allows
                            # custom keywords; rfc_id dedup is the
                            # primary guard, the keyword is a bonus.
                            pass

                    elapsed = time.time() - t0
                    state = manager._get_mb_state(account_id, mailbox)
                    state["processed"] = state.get("processed", 0) + 1
                    state["last_message"] = {
                        "sender": message.sender,
                        "subject": message.subject,
                        "category": classification.category,
                        "confidence": classification.confidence,
                        "at": datetime.now(timezone.utc).isoformat(),
                        "mailbox": mailbox,
                    }

                    # Log with sender/subject in standard mode, omit in HIPAA.
                    from email_triage.triage_logging import is_hipaa_mode
                    log_kwargs: dict[str, Any] = {
                        "account": acct["name"],
                        "uid": uid,
                        "category": classification.category,
                        "confidence": classification.confidence,
                        "elapsed": f"{elapsed:.1f}s",
                    }
                    if not is_hipaa_mode():
                        log_kwargs["sender"] = message.sender
                        log_kwargs["subject"] = message.subject[:80]
                        if classification.reason:
                            # 500 chars fits a full classifier reason without
                            # truncating the LLM's thought mid-sentence. Full
                            # text still stored in triage_runs.results_json.
                            log_kwargs["reason"] = classification.reason[:500]
                    log.info("Watcher triaged message", **log_kwargs)

                    # Record as a triage run (1-message batch).
                    # HIPAA redaction matches triage_runner.run_triage:
                    # sender + subject + reason are scrubbed when the
                    # account is HIPAA-flagged. source + date are
                    # system labels / provider-supplied timestamps,
                    # safe in both modes — emit always so the
                    # recipient-digest renderer can map source to
                    # the Option B fixed phrase + render the
                    # message's actual Date header.
                    from email_triage.triage_logging import (
                        is_account_hipaa, is_hipaa_mode,
                    )
                    _acct_hipaa = is_hipaa_mode() or is_account_hipaa(acct)
                    _entry = {
                        "message_id": uid,
                        "category": classification.category,
                        "confidence": classification.confidence,
                        "source": classification.source,
                        "actions": actions_taken,
                        "status": "ok",
                    }
                    if not _acct_hipaa:
                        _entry["sender"] = message.sender
                        _entry["subject"] = message.subject
                    _entry["reason"] = (
                        "[redacted]" if _acct_hipaa
                        else classification.reason
                    )
                    try:
                        _entry["date"] = (
                            message.date.isoformat()
                            if getattr(message, "date", None) else ""
                        )
                    except Exception:
                        _entry["date"] = ""
                    try:
                        record_triage_run(
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
                    dispatcher = getattr(app.state, "event_dispatcher", None)
                    if dispatcher is not None:
                        from email_triage.web.events import fire_triage_completed
                        try:
                            await fire_triage_completed(
                                dispatcher, db, config, acct,
                                {
                                    "run_id": f"watch_{account_id}_{int(time.time())}",
                                    "query": "IDLE",
                                    "total_messages": 1,
                                    "results": [{}],
                                    "errors": [],
                                    "elapsed_secs": elapsed,
                                },
                                trigger="watch",
                            )
                        except Exception as _e:
                            log.warning("watch: triage.completed dispatch failed", error=str(_e))

                    # Advance the high-water mark so this UID is not
                    # reprocessed after a restart. Per-mailbox key —
                    # the HWM belongs to the folder the UID came from.
                    if uid_int > hwm_uid:
                        hwm_uid = uid_int
                        set_mailbox_hwm(db, account_id, mailbox, {
                            "uid": hwm_uid,
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        })

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # #149 — LLM-unreachable failures are upstream-infra
                    # weather, not a per-message bug. Enqueue on the
                    # durable retry queue (Bundle A) and log calmly.
                    # Maintenance windows (Bundle C) override the log
                    # severity to INFO + adjust the copy.
                    from email_triage.llm_health import (
                        LLMBackendUnreachableError,
                    )
                    if isinstance(e, LLMBackendUnreachableError):
                        from email_triage.web.triage_retry_queue import (
                            enqueue as _q_enqueue,
                        )
                        from email_triage.llm_maintenance import (
                            active_window_for,
                        )
                        windows = list(getattr(
                            app.state.config, "llm_maintenance_windows", []
                        ) or [])
                        # Convert config dataclasses -> runtime
                        # MaintenanceWindow shape (same fields).
                        from email_triage.llm_maintenance import (
                            MaintenanceWindow,
                        )
                        rt_windows = [
                            MaintenanceWindow(
                                host=w.host, cron=w.cron,
                                duration_minutes=w.duration_minutes,
                                backend=w.backend,
                            ) for w in windows
                        ]
                        active = active_window_for(e.backend, rt_windows)
                        try:
                            row = _q_enqueue(
                                db, message_id=str(uid),
                                account_id=int(account_id),
                                mailbox=mailbox, uid=str(uid),
                                error=e,
                            )
                        except Exception as q_exc:
                            log.error(
                                "Watcher: failed to enqueue retry",
                                account=acct["name"], mailbox=mailbox,
                                uid=uid, error=fmt_exc(q_exc),
                            )
                            row = {"attempt_count": 0}
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
                                attempt=row.get("attempt_count"),
                            )
                        else:
                            log.info(
                                "Watcher: LLM backend unhealthy — "
                                "message queued for retry",
                                account=acct["name"], mailbox=mailbox,
                                uid=uid, backend=e.backend,
                                host=e.host, port=e.port,
                                attempt=row.get("attempt_count"),
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
                        # #175 R-B — durable per-message retry queue.
                        # The error log above stays (operator's
                        # journalctl monitoring depends on it); this
                        # adds a row to the retry queue so the sweeper
                        # picks it up on backoff. Auth-revoked errors
                        # enqueue + immediately dead so the admin sees
                        # the artefact but no retries fire (the only
                        # cure is re-auth, not waiting).
                        try:
                            from email_triage.web.watcher_retry import (
                                enqueue_watcher_retry as _wr_enqueue,
                            )
                            _wr_enqueue(
                                app.state.db,
                                account_id=int(account_id),
                                provider_type=acct.get(
                                    "provider_type", "imap",
                                ),
                                mailbox=mailbox,
                                uid=str(uid),
                                error=e,
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
                set_bool_setting(app.state.db, _settings_keys.watch(account_id), False)
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


def create_app(config: TriageConfig | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Accepts an optional config for testing.  When *None*, config is
    loaded from the standard search paths at startup.
    """
    if config is None:
        config = load_config()
    setup_logging(config.logging)

    db_path = Path(config.persistence.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        conn = init_db(db_path)
        # Per-user personal categories migration (#62) -- runs before
        # seeding so seed_categories writes into the new schema.
        from email_triage.web.db import ensure_categories_user_id_migration
        if ensure_categories_user_id_migration(conn):
            log.info("Migrated categories table to per-user schema")
        # Seed categories from YAML on first run.
        seeded = seed_categories(conn, config.classifier.categories)
        if seeded:
            log.info("Seeded categories from config", count=seeded)
        # Top up newer phases' system categories on existing installs.
        from email_triage.web.db import ensure_upgrade_categories
        added = ensure_upgrade_categories(conn)
        if added:
            log.info("Inserted upgrade categories", count=added)

        # One-time backfill — restore newsletter render_as on
        # legacy-migrated digest configs. The 2026-05-05
        # digest_configs migration silently mapped legacy
        # `digest_schedules:<id>` rows into custom DigestConfigs
        # with render_as="grouped_list", losing the LLM-extracted
        # article-card rendering the original scheduler produced.
        # Restored as a render_as option (commits this batch);
        # this backfill flips category-newsletter configs to use
        # the restored format. Idempotent — only flips configs
        # currently on grouped_list / plain_list (preserves any
        # operator-set explicit choice).
        try:
            from email_triage.actions.digest_configs import (
                _backfill_newsletter_render_as,
            )
            flipped = _backfill_newsletter_render_as(conn)
            if flipped:
                log.info(
                    "Backfilled newsletter render_as on legacy configs",
                    count=flipped,
                )
        except Exception as e:
            log.warning(
                "Newsletter render_as backfill failed",
                error=fmt_exc(e),
            )

        # Build the runtime secrets provider: bootstrap backend supplies
        # the master key, DbSecrets holds everything else.
        from email_triage.secrets import (
            bootstrap_secrets_from_config, SecretNotFound,
        )
        try:
            secrets = bootstrap_secrets_from_config(conn, config)
        except SecretNotFound as e:
            log.error(
                "Master key not found in bootstrap store. "
                "Generate one and add it via: "
                "'email-triage secrets init-master-key'",
                missing_key=e.key, backend=e.backend,
            )
            raise
        except ImportError as e:
            log.error("Cryptography package required for DbSecrets", error=fmt_exc(e))
            raise

        app.state.db = conn
        app.state.config = config
        app.state.secrets = secrets
        app.state.started_at = time.monotonic()
        app.state.version = _resolve_version()

        # #81 -- capture the listener mode the uvicorn socket actually
        # bound at boot. Operator-facing surfaces compare this to the
        # current saved value to flag "you flipped the toggle but the
        # running listener is still on the old protocol." The boot
        # value is FROZEN here -- never re-read from config later, or
        # the chip would mask drift the moment the operator hits Save.
        app.state.tls_boot_mode = bool(getattr(config.tls, "enabled", False))

        # #104 -- bind the ACME job-state module to this process's
        # SQLite connection so the singleton write-throughs land on
        # disk. ``acme_jobs`` survives process restarts; the supervised
        # worker scans non-terminal rows on boot and decides
        # resume / cancel per the resume-policy table.
        try:
            from email_triage.web import acme_job_state
            acme_job_state.set_db_handle(conn)
            try:
                resolved = acme_job_state.resume_on_startup()
                if resolved:
                    log.info(
                        "ACME: resolved %d in-flight job(s) on startup",
                        len(resolved),
                    )
            except Exception as e:
                log.warning(
                    "ACME: resume_on_startup raised; continuing",
                    error=fmt_exc(e),
                )
        except Exception as e:
            log.warning(
                "ACME: set_db_handle binding failed; using RAM-only state",
                error=fmt_exc(e),
            )

        # Persistent session_secret. Pre-PR-9.5 the secret was a
        # module-level random in dependencies.py, regenerated on every
        # process start -- which meant every container restart kicked
        # everyone out (existing cookies' signatures stopped
        # validating). Now: read from the secrets store, generate +
        # store on first run only. Sessions survive deploys + restarts
        # bounded only by their TTL.
        existing_session_secret = secrets.get("session_secret")
        if not existing_session_secret:
            import secrets as _stdlib_secrets
            existing_session_secret = _stdlib_secrets.token_hex(32)
            secrets.set("session_secret", existing_session_secret)
            log.info("session_secret minted + stored in secrets store")
        app.state.session_secret = existing_session_secret

        # PR 8 / D1 follow-up: CSRF enforcement gate.
        # Two surfaces, env var wins:
        #   1. tls.csrf_enforce in YAML (operator-edited via UI).
        #   2. EMAIL_TRIAGE_CSRF_ENFORCE env var (truthy = enforce).
        # The env var wins so an operator who's debugging "CSRF is
        # rejecting my form" can flip it off without touching YAML +
        # waiting for a save round-trip.
        _env_csrf = (
            os.environ.get("EMAIL_TRIAGE_CSRF_ENFORCE", "")
            .strip().lower()
        )
        if _env_csrf in ("1", "true", "yes", "on"):
            app.state.csrf_enforce = True
        elif _env_csrf in ("0", "false", "no", "off"):
            app.state.csrf_enforce = False
        else:
            app.state.csrf_enforce = bool(
                getattr(config.tls, "csrf_enforce", False)
            )

        # #82 item 4 — operator-defined CSRF exempt path prefixes.
        # Stored on app.state so a /admin/security save can refresh
        # without a restart. The middleware reads this on every
        # request.
        app.state.csrf_extra_exempt_prefixes = list(
            getattr(config.tls, "csrf_exempt_prefixes", []) or [],
        )

        # M-4 scaffold: probe the sqlite-vec extension at startup so
        # the rest of the codebase can gate vector-search code paths
        # on a single boolean. Missing extension = M-4 retrieval
        # falls back to an in-memory cosine over the rows in
        # ``sent_mail_index`` (degrades gracefully -- the install
        # still works, retrieval is just slower for accounts with a
        # very large sent-mail backlog).
        #
        # The probe runs on the live ``conn``; sqlite3's
        # ``enable_load_extension`` is opt-in (compile-time flag on
        # the python-sqlite3 module). On Windows + on most distros'
        # default Python the flag is OFF, in which case the probe
        # exits via the AttributeError branch and leaves
        # ``sqlite_vec_available`` False. That is the expected,
        # supported behaviour for an install that hasn't installed
        # the extension.
        app.state.sqlite_vec_available = False
        try:
            import sqlite_vec  # type: ignore
            try:
                conn.enable_load_extension(True)
                sqlite_vec.load(conn)
                conn.enable_load_extension(False)
                app.state.sqlite_vec_available = True
                log.info("sqlite-vec extension loaded (M-4 retrieval enabled)")
            except (AttributeError, Exception) as e:
                # AttributeError: this Python's sqlite3 was built
                # without ``--enable-loadable-sqlite-extensions``.
                # OperationalError: extension binary present but the
                # SQLite library refused to load it. Either way the
                # feature degrades to the in-memory fallback path.
                log.info(
                    "sqlite-vec not loaded; M-4 retrieval will use "
                    "in-memory fallback",
                    error=type(e).__name__,
                )
        except ImportError:
            # Package not installed at all. M-4 is opt-in; this is
            # not an install-broken condition.
            log.info(
                "sqlite-vec package not installed; M-4 retrieval "
                "falls back to in-memory cosine",
            )

        # M-5: build the embedding backend that the draft-reply
        # prompt builder feeds to ``SentMailIndex.retrieve_similar``.
        # ``build_embedding_backend`` returns None when the operator
        # hasn't configured ``embedding:`` in YAML; the draft-reply
        # path treats absence as "RAG retrieval skipped" (one-time
        # INFO log) without blocking M-1+M-2 / M-3 layers.
        #
        # Non-allowlist backends raise ValueError at construction
        # (anthropic / openai / etc.). We let the error propagate
        # so a misconfigured YAML surfaces at boot rather than the
        # first draft-reply call.
        app.state.embedding_backend = None
        app.state.embedding_model = ""
        try:
            from email_triage.engine.embedding_backend import (
                build_embedding_backend,
            )
            backend = build_embedding_backend(config)
            if backend is not None:
                app.state.embedding_backend = backend
                app.state.embedding_model = (
                    getattr(config.embedding, "model_name", "") or ""
                )
                log.info(
                    "Embedding backend configured (M-5 RAG enabled)",
                    backend_type=getattr(backend, "backend_type", ""),
                    model=app.state.embedding_model,
                )
            else:
                log.info(
                    "No embedding backend configured; "
                    "M-5 RAG retrieval will be skipped at draft time",
                )
        except ValueError as e:
            # Non-local backend in YAML. Re-raise so the operator
            # sees it at boot, not at the first draft-reply call.
            log.error(
                "Embedding backend rejected by allowlist", error=str(e),
            )
            raise

        # Hydrate the soft-launch reject counter from log_entries so
        # the /health surface reflects cumulative state, not just
        # since-last-restart. (#83.6) Process-local counter is still
        # the live source of truth -- this just primes it.
        #
        # Operator can baseline-reset the counter without touching the
        # historical log_entries by setting the ``csrf_count_since``
        # setting to an ISO timestamp; hydration only counts entries
        # newer than that. Useful for "I addressed the historical
        # rejections, give me a clean slate to monitor on" without
        # losing the audit trail.
        try:
            from email_triage.web.db import get_setting
            baseline = (get_setting(conn, "csrf_count_since") or "").strip()
            if baseline:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM log_entries "
                    "WHERE logger = 'email_triage.web.csrf' "
                    "AND message LIKE 'CSRF token%' "
                    "AND created_at > ?",
                    (baseline,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM log_entries "
                    "WHERE logger = 'email_triage.web.csrf' "
                    "AND message LIKE 'CSRF token%'",
                ).fetchone()
            app.state.csrf_rejects = int(row["n"]) if row else 0
        except Exception:
            app.state.csrf_rejects = 0

        # One-shot migration: lift any per-account Gmail OAuth creds
        # up to the install-level secrets store. Pre-B1 installs kept
        # client_id/client_secret per-account; B1 centralises them.
        from email_triage.web.db import (
            migrate_oauth_creds_to_install_level,
            migrate_o365_creds_to_install_level,
        )
        found = migrate_oauth_creds_to_install_level(conn)
        if found is not None:
            cid, csec = found
            # Only seed the Web-app slot if it's currently empty; respect
            # any value the admin has already entered via /config.
            if not secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID"):
                secrets.set("GOOGLE_OAUTH_WEB_CLIENT_ID", cid)
                secrets.set("GOOGLE_OAUTH_WEB_CLIENT_SECRET", csec)
                log.warning(
                    "Migrated per-account Gmail OAuth creds to install-level "
                    "(Web-app slot). Verify at /config — retype in the "
                    "Desktop slot if that's the flow you intended.",
                )

        # Parallel migration for Office 365: lifts per-account
        # client_id/tenant_id from config_json + first non-empty
        # ACCOUNT_*_O365_SECRET from the secrets store to install-level.
        o365_found = migrate_o365_creds_to_install_level(conn, secrets)
        if o365_found is not None:
            tid, cid, csec = o365_found
            if tid and not secrets.get("O365_OAUTH_TENANT_ID"):
                secrets.set("O365_OAUTH_TENANT_ID", tid)
            if cid and not secrets.get("O365_OAUTH_CLIENT_ID"):
                secrets.set("O365_OAUTH_CLIENT_ID", cid)
            if csec and not secrets.get("O365_OAUTH_CLIENT_SECRET"):
                secrets.set("O365_OAUTH_CLIENT_SECRET", csec)
            log.warning(
                "Migrated per-account Office 365 OAuth creds to install-level. "
                "Verify at /config — if accounts had different Azure tenants, "
                "only one was kept and the others will need their probe to be "
                "rerun after editing the install tenant.",
            )

        # Hydrate config.google_oauth from the secrets store so the
        # rest of the app can read it as plain attributes. Empty
        # strings when unset — callers must check before use.
        config.google_oauth.web_client_id = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_ID") or ""
        config.google_oauth.web_client_secret = secrets.get("GOOGLE_OAUTH_WEB_CLIENT_SECRET") or ""
        config.google_oauth.desktop_client_id = secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_ID") or ""
        config.google_oauth.desktop_client_secret = secrets.get("GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET") or ""

        # Sibling hydration for the install-level Office 365 OAuth creds.
        config.office365_oauth.tenant_id = secrets.get("O365_OAUTH_TENANT_ID") or ""
        config.office365_oauth.client_id = secrets.get("O365_OAUTH_CLIENT_ID") or ""
        config.office365_oauth.client_secret = secrets.get("O365_OAUTH_CLIENT_SECRET") or ""

        # Register the install-level OAuth creds with the provider
        # factory (module-level singleton — read by every provider
        # construction site without parameter threading).
        from email_triage.web.routers.ui import (
            set_install_google_oauth, set_install_ingestion_config,
            set_install_office365_oauth,
        )
        set_install_google_oauth(config.google_oauth)
        set_install_office365_oauth(config.office365_oauth)
        set_install_ingestion_config(config.ingestion)

        # #151 — install-level optional classification cache. Empty URL
        # returns None (no behaviour change). Lazy connect: nothing
        # actually talks to Redis until the first lookup.
        try:
            from email_triage.cache.classification import (
                build_cache_from_config, set_install_classification_cache,
            )
            set_install_classification_cache(
                build_cache_from_config(getattr(config, "redis_cache", None)),
            )
        except Exception as _cache_init_err:
            # Best-effort — don't block startup on a cache build hiccup.
            from email_triage._errfmt import fmt_exc as _fmt
            log.warning(
                "Classification cache init failed; cache disabled",
                error=_fmt(_cache_init_err),
            )

        # 2026-05-13 — persistent counter backend. Mirrors cache /
        # embedding / webhook counter increments to Redis so the
        # lifetime totals survive container restarts. Reuses the
        # same Redis URL the cache uses — no second URL field for
        # the operator to manage. Empty cache URL = persistence
        # disabled (process-local counters keep working unchanged).
        try:
            from email_triage.engine.persistent_counters import (
                build_counter_backend_from_config,
                set_install_counter_backend,
            )
            set_install_counter_backend(
                build_counter_backend_from_config(
                    getattr(config, "redis_cache", None),
                ),
            )
        except Exception as _pc_err:
            from email_triage._errfmt import fmt_exc as _fmt
            log.warning(
                "Persistent counter backend init failed; counters stay process-local",
                error=_fmt(_pc_err),
            )

        # Enable SQLite logging so admin log viewer works.
        from email_triage.triage_logging import add_sqlite_handler
        add_sqlite_handler(conn)

        # One-shot log_entries prune on boot — bounds the table after
        # every restart so a crash-loop or long offline stretch can't
        # leave a decade of rows hanging around.
        from email_triage.web.db import prune_log_entries_by_age_and_count
        try:
            _pruned = prune_log_entries_by_age_and_count(
                conn,
                retention_days=config.logging.retention_days,
                max_rows=config.logging.max_rows,
            )
            if _pruned:
                log.info(
                    "Pruned log_entries on startup",
                    deleted=_pruned,
                    retention_days=config.logging.retention_days,
                    max_rows=config.logging.max_rows,
                )
        except Exception as e:
            log.error("Startup log_entries prune failed", error=fmt_exc(e))

        # Restore runtime settings (dry-run, log level, HIPAA) from DB.
        from email_triage.web.db import get_setting
        _rt_settings = get_setting(conn, "runtime_settings")
        if _rt_settings:
            import logging as stdlib_logging
            from email_triage import triage_logging
            level_name = _rt_settings.get("log_level", "INFO").upper()
            root_logger = stdlib_logging.getLogger("email_triage")
            root_logger.setLevel(getattr(stdlib_logging, level_name, stdlib_logging.INFO))
            triage_logging._hipaa_mode = _rt_settings.get("hipaa", False)
            log.info(
                "Runtime settings restored from DB",
                dry_run=_rt_settings.get("dry_run", False),
                log_level=level_name,
                hipaa=_rt_settings.get("hipaa", False),
            )

        # Startup mode breadcrumbs — one line each, in increasing severity.
        # Intentionally terse; the full picture is in /config and /compliance.
        from email_triage.triage_logging import is_hipaa_mode
        _system_hipaa = is_hipaa_mode()
        if _system_hipaa:
            log.info("Starting in HIPAA mode (system-wide)")

        # For DEBUG logs, set Python log level via standard config
        # (LOG_LEVEL env var, /admin runtime settings, or
        # logging.dictConfig) — there is no longer a YAML toggle.

        # Record a boundary event if the system HIPAA state has changed
        # since the last recorded system-scope boundary.  This keeps the
        # log viewer's "before/after" dividers accurate across restarts
        # and captures the effective state at each startup.
        from email_triage.web.db import (
            latest_hipaa_boundary, record_hipaa_boundary,
        )
        _last = latest_hipaa_boundary(conn, "system")
        _last_direction = _last["direction"] if _last else "off"
        _current_direction = "on" if _system_hipaa else "off"
        if _last_direction != _current_direction:
            record_hipaa_boundary(
                conn, "system", _current_direction,
                actor_id=None, reason="startup",
            )

        log.info("Web UI started", db_path=str(db_path))

        # Instantiate the Gmail push queue + consumer support state
        # before spawning supervised tasks (factories close over
        # app.state.push_queue, so it must exist first).
        app.state.push_queue = asyncio.Queue(maxsize=256)
        app.state.metrics = getattr(app.state, "metrics", {})

        # Outbound event dispatcher — used by the triage.completed
        # emitter from manual, watcher, push and OpenClaw API call sites.
        from email_triage.web.events import EventDispatcher
        app.state.event_dispatcher = EventDispatcher(
            targets=getattr(config, "webhooks", []) or [],
            secrets_provider=secrets,
            allow_external=getattr(config, "webhooks_allow_external", False),
            local_url_suffixes=list(
                getattr(config.tls, "local_url_suffixes", []) or [],
            ),
        )

        # Background-task supervisor (PR 2 / A3). Replaces the
        # bare-asyncio.create_task pattern with crash detection +
        # bounded restart + circuit breaker. Each task runs inside a
        # fresh request_id context so its log lines correlate.
        from email_triage.web.task_supervisor import TaskSupervisor
        supervisor = TaskSupervisor()
        app.state.supervisor = supervisor
        supervisor.supervise(
            "digest-scheduler", lambda: _digest_scheduler(app),
        )
        supervisor.supervise(
            "gmail-push-consumer", lambda: _gmail_push_consumer(app),
        )
        supervisor.supervise(
            "gmail-watch-renewer", lambda: _gmail_watch_renewer(app),
        )
        # O365 / Microsoft Graph subscription renewer (#53 follow-up F-2).
        # Cron-anchored hourly sweep; refreshes any subscription whose
        # expiration_at falls within the configured window
        # (push.office365_subscription_renewal_window_hours, default 24h).
        # Subscriptions expire after ~3 days otherwise — without this loop
        # the push pipeline silently dies one window after enable.
        from email_triage.web.o365_renewer import (
            _o365_subscription_renewer_loop,
        )
        supervisor.supervise(
            "o365-subscription-renewer",
            lambda: _o365_subscription_renewer_loop(app),
        )
        # Unified push + poll ingestion loop: one tick every 60 s
        # evaluates every account across every provider; dispatches a
        # provider-specific one-shot poll for any account whose
        # ``poll_interval_minutes`` has elapsed. Acts as safety net when
        # push is on and primary ingestion when push is off.
        supervisor.supervise(
            "unified-poll-loop", lambda: _unified_poll_loop(app),
        )
        supervisor.supervise(
            "log-entries-pruner", lambda: _log_entries_prune_loop(app),
        )
        # PR 9 / D3 — HIPAA boundary drift detector.
        supervisor.supervise(
            "hipaa-boundary-drift-detector",
            lambda: _hipaa_boundary_drift_detector(app),
        )
        # Daily health email sender (#27). Same cadence pattern as the
        # digest scheduler: ticks once a minute and fires when wall-clock
        # crosses ``config.health_email.send_at``.
        supervisor.supervise(
            "daily-health-email-sender",
            lambda: _daily_health_email_sender(app),
        )
        # Per-recipient per-account daily digest. Owner opt-in via the
        # account-edit form; ticks once a minute and fires when the
        # configured ``HH:10`` bucket matches.
        supervisor.supervise(
            "recipient-digest-sender",
            lambda: _recipient_digest_sender(app),
        )
        # Background whole-mailbox triage queue drainer (#101). Runs
        # one job at a time under operator-tunable rate-limit +
        # concurrency knobs. The first thing this task does on
        # startup is requeue any 'running' rows orphaned by a
        # process restart.
        from email_triage.web.triage_runner_bulk import bulk_triage_runner
        supervisor.supervise(
            "bulk-triage-runner",
            lambda: bulk_triage_runner(app),
        )
        # M-6 edit-feedback capture loop. Cron-anchored every
        # ``style_learning.capture_interval_hours`` hours (default 6).
        # Scans Sent folders on opted-in non-HIPAA accounts for
        # AI-drafted-then-edited messages and writes captured pairs
        # into ``sent_mail_index`` for higher-weighted M-4 retrieval
        # + M-3 distillation.
        supervisor.supervise(
            "sent-mail-capture-loop",
            lambda: _sent_mail_capture_loop(app),
        )
        # #149 Bundle A — durable retry queue worker. Drains
        # ``triage_retry_queue`` rows whose backoff has elapsed.
        # Each tick re-fetches + reclassifies one batch of queued
        # messages; on success the row is deleted, on failure the
        # row's attempt counter is bumped and the next attempt is
        # pushed out per the exponential schedule. Hops over its
        # tick when the LLM circuit breaker (Bundle B) is open.
        supervisor.supervise(
            "triage-retry-worker",
            lambda: _triage_retry_worker(app),
        )

        # #169 Wave 2-α I7 — daily BAA expiry sweep + auto-disable
        # for HIPAA accounts. Tick once per hour; the sweep itself
        # is idempotent so running it more often than needed is
        # safe + cheap.
        supervisor.supervise(
            "baa-expiry-daily-sweep",
            lambda: _baa_expiry_sweeper(app),
        )

        # #152 Wave 3 — daily GC sweep for per-contact HIPAA style
        # descriptors. Drops rows older than 90 days since last
        # distill (operator likely stopped emailing that contact).
        # Tick once per day; idempotent.
        supervisor.supervise(
            "per-contact-style-gc-daily-sweep",
            lambda: _per_contact_style_gc_sweeper(app),
        )

        # #171-B — M-3 + M-7 trigger watcher. Ticks every 15 minutes;
        # evaluates first-time + threshold + stale triggers on every
        # eligible HIPAA-opted-in account + per-contact pair, enqueues
        # rows on ``style_distill_queue`` / ``style_distill_queue_contacts``
        # for the existing worker to drain. Idempotent across ticks
        # (already-queued rows skip; no new sends → no work).
        supervisor.supervise(
            "style-distill-trigger-sweeper",
            lambda: _style_distill_trigger_sweeper(app),
        )

        # #175 R-A — watcher per-message retry queue sweeper. Ticks
        # every 30s (or immediately on a pubsub wake when Redis is
        # available); drains schedule-exhausted rows + stamps a
        # summary on ``app.state.watcher_retry_sweep_status`` for
        # /health/detail. R-B extends this sweeper with the per-row
        # re-fetch + re-classify path; until that lands the sweeper
        # only enforces the terminal-state transition.
        supervisor.supervise(
            "watcher-retry-sweeper",
            lambda: _watcher_retry_sweeper(app),
        )

        # Start the watcher manager and restore previously-enabled watchers.
        watcher_mgr = WatcherManager(app)
        app.state.watcher_manager = watcher_mgr
        await watcher_mgr.restore_from_settings()

        yield

        # Shutdown: stop watchers first, then supervised tasks.
        await watcher_mgr.stop_all()
        await supervisor.stop_all()

        # Drain long-lived httpx clients introduced by #139. Each
        # close() is best-effort + idempotent — surface any error in
        # the log but never block shutdown on a stuck pool.
        try:
            await app.state.event_dispatcher.aclose()
        except Exception as e:
            log.warning("event_dispatcher aclose failed",
                        error=fmt_exc(e))
        try:
            from email_triage.web import watch_runner as _wr
            await _wr.aclose_module()
        except Exception as e:
            log.warning("watch_runner aclose failed", error=fmt_exc(e))
        try:
            cert_cache = getattr(app.state, "_gmail_cert_cache", None)
            if cert_cache is not None:
                await cert_cache.aclose()
        except Exception as e:
            log.warning("gmail_cert_cache aclose failed",
                        error=fmt_exc(e))
        try:
            backend = getattr(app.state, "embedding_backend", None)
            if backend is not None and hasattr(backend, "close"):
                await backend.close()
        except Exception as e:
            log.warning("embedding_backend close failed",
                        error=fmt_exc(e))
        try:
            classifier = getattr(app.state, "classifier", None)
            if classifier is not None and hasattr(classifier, "close"):
                await classifier.close()
        except Exception as e:
            log.warning("classifier close failed", error=fmt_exc(e))

        conn.close()
        log.info("Web UI stopped")

    app = FastAPI(
        title="Email Triage",
        lifespan=lifespan,
    )

    # Access-audit middleware (#41 — HIPAA §164.312(b)). Records every
    # authenticated request hitting a PHI-touch route prefix. Mounted
    # before any routes so it sees the response status from downstream
    # handlers.
    from email_triage.web.access_audit import (
        AccessAuditMiddleware,
        RequestIdMiddleware,
    )
    from email_triage.web.csrf import CsrfMiddleware
    app.add_middleware(AccessAuditMiddleware)
    # CSRF middleware (PR 8 / D1). Enforce-by-default as of #82
    # (2026-05-10). Violations return HTTP 403. Operator can opt out
    # via ``tls: { csrf_enforce: false }`` in YAML or the
    # ``EMAIL_TRIAGE_CSRF_ENFORCE=0`` env var (env wins). When
    # disabled, violations still log + bump ``app.state.csrf_rejects``
    # so the operator can size + verify before re-enabling.
    app.add_middleware(CsrfMiddleware)
    # Request-ID middleware MUST be the outermost (added LAST in
    # FastAPI's onion model = executed FIRST on inbound). Otherwise
    # the audit middleware wouldn't see request.state.request_id and
    # the access_log row would land without a correlation ID.
    app.add_middleware(RequestIdMiddleware)

    # Static files
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Templates
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    # Server-side CSRF input renderer — closes the JS-shim race where
    # cached /api/csrf-token fetch hadn't returned before a plain
    # HTML form submitted. See web/csrf.py:csrf_input docstring.
    from email_triage.web.csrf import csrf_input as _csrf_input
    templates.env.globals["csrf_input"] = _csrf_input
    app.state.templates = templates

    # Register routers
    from email_triage.web.routers.ui import router as ui_router
    from email_triage.web.routers.api import router as api_router
    from email_triage.web.routers.webhooks import router as webhook_router
    from email_triage.web.routers.openclaw import router as openclaw_router
    from email_triage.web.routers.health import router as health_router
    # #67 — auth-surface upgrade routes (dev-keypair admin + login,
    # WebAuthn registration + login, ACME diagnostic test buttons).
    from email_triage.web.routers.auth_keys import router as auth_keys_router
    # External-integrations admin (Gmail Pub/Sub config + watch state).
    from email_triage.web.routers.integrations import (
        router as integrations_router,
    )
    # Backup export (admin-driven; pure-py module + CLI restore inverse).
    from email_triage.web.routers.backup import router as backup_router
    # Manual TLS CSR / sign / import workflow for institutional CAs.
    from email_triage.web.routers.tls_csr import router as tls_csr_router
    # End-user how-to runbook (#128). Anonymous access — non-PHI.
    from email_triage.web.routers.help import router as help_router

    # Health probe is UNAUTHENTICATED by design — container HEALTHCHECK
    # and external monitors must be able to hit it without creds.  It
    # is mounted at the top level (no auth dependency on this router).
    app.include_router(health_router)
    app.include_router(ui_router)
    app.include_router(auth_keys_router)
    app.include_router(integrations_router)
    app.include_router(backup_router)
    app.include_router(tls_csr_router)
    app.include_router(help_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(openclaw_router)
    app.include_router(webhook_router)

    return app


def _digest_scheduler_last_run_key(
    acct_id: int, idx: int, day_str: str,
) -> str:
    """Settings key for the per-(account, schedule, day) ``ran``
    flag. Stored under one key per account-schedule-day so a single
    day's flag clears on the natural day rollover (no settings table
    sweep needed; old keys are harmless dead weight). Module-level so
    the test suite can construct the same key without re-implementing
    the format.
    """
    return f"digest_scheduler:last_run:{acct_id}:{idx}:{day_str}"


async def _digest_scheduler_tick(
    app: FastAPI, now: datetime,
) -> list[tuple[int, int, str]]:
    """Run one scheduler tick. Returns the list of
    ``(account_id, schedule_idx, category)`` tuples that fired.

    Extracted from :func:`_digest_scheduler` so the per-tick logic is
    unit-testable without spinning up the infinite loop. Side effects:
    writes the per-(acct,idx,day) ``ran`` flag BEFORE invoking the
    digest body (single-source-of-truth dedup) and dispatches each
    fired schedule to :func:`_run_scheduled_digest`. Caller (the
    loop in ``_digest_scheduler``) is responsible for the 60 s
    cadence and exception logging.
    """
    current_time = now.strftime("%H:%M")
    today_key = now.strftime("%Y-%m-%d")

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    from email_triage.web.db import (
        get_setting, disabled_user_ids, list_email_accounts,
        get_email_account, list_account_routes, set_setting,
    )

    fired: list[tuple[int, int, str]] = []

    accounts = list_email_accounts(db)
    # #134.4 — single set-membership lookup per tick beats one
    # disabled-flag SELECT per account.
    disabled_owners = disabled_user_ids(db)
    for acct in accounts:
        # Skip disabled accounts.
        if not acct.get("is_active", True):
            continue
        # Skip accounts owned by disabled users (fail-closed).
        owner_id = acct.get("user_id")
        if owner_id is not None and owner_id in disabled_owners:
            continue
        acct_id = acct["id"]

        # Load schedules (new multi-schedule format).
        schedules = get_setting(
            db, _settings_keys.digest_schedules(acct_id),
        )

        # Backward compat: fall back to legacy single-schedule.
        if schedules is None:
            old_cfg = (
                get_setting(db, _settings_keys.digest(acct_id)) or {}
            )
            if old_cfg.get("schedule_enabled"):
                schedules = [{
                    "time_utc": old_cfg.get("schedule_time", "07:00"),
                    "category": old_cfg.get("category", "newsletters"),
                    "enabled": True,
                }]
            else:
                schedules = []

        for idx, sched in enumerate(schedules):
            if not sched.get("enabled", True):
                continue

            sched_time = sched.get("time_utc", "07:00")

            # #72 — cadence gate. Default 'daily' (legacy
            # behavior). 'weekly' fires only when today's
            # weekday (Mon=0..Sun=6) is in the schedule's
            # ``days_of_week`` list. Time-of-day match still
            # required either way; daily dedup key keeps the
            # one-fire-per-day invariant.
            cadence = sched.get("cadence", "daily")
            if cadence == "weekly":
                wanted = sched.get("days_of_week") or []
                if now.weekday() not in wanted:
                    continue

            # #141 elapsed-window match. Parse "HH:MM" and
            # fire when current_time has caught up OR passed
            # the schedule. ``str`` comparison works because
            # zero-padded "HH:MM" is lexicographically ordered
            # the same way as the clock; no extra parsing.
            elapsed = current_time >= sched_time
            if not elapsed:
                continue

            # #141 persistent dedup. Read once, write the
            # flag BEFORE running so a crash / cancel mid-run
            # doesn't double-fire on the next tick. (We accept
            # the trade: a crash in the digest body skips the
            # day. Better than two sends to the same recipient
            # for the same window.)
            run_key = _digest_scheduler_last_run_key(
                acct_id, idx, today_key,
            )
            if get_setting(db, run_key) is not None:
                continue
            set_setting(db, run_key, {"ran_at": now.isoformat()})
            category = sched.get("category", "newsletters")
            fired.append((acct_id, idx, category))
            log.info(
                "Running scheduled digest",
                account=acct["name"],
                time=sched_time,
                category=category,
            )
            # Build a digest_cfg dict for _run_scheduled_digest.
            # Start from the account-wide digest setting, then
            # overlay every per-schedule field so new #63
            # parameters (source_folder, search_filter, limit,
            # html_template, recipient_mode, recipient_custom,
            # delete_originals, format_prompt) take effect when
            # the operator set them.
            digest_cfg = get_setting(db, _settings_keys.digest(acct_id)) or {}
            digest_cfg["category"] = category
            for _key in (
                "format_prompt", "source_folder", "search_filter",
                "html_template", "recipient_mode",
                "recipient_custom", "limit", "delete_originals",
            ):
                if _key in sched and sched[_key] not in (None, ""):
                    digest_cfg[_key] = sched[_key]
            try:
                await _run_scheduled_digest(
                    db, config, secrets, acct, digest_cfg,
                )
            except Exception as e:
                log.error(
                    "Scheduled digest failed",
                    account=acct["name"],
                    category=category,
                    error=fmt_exc(e),
                )

    return fired


async def _digest_scheduler(app: FastAPI) -> None:
    """Background task that runs scheduled digest generation.

    Checks every 60 seconds whether any account has digest schedules
    due. Supports multiple schedules per account (different categories
    at different times).

    #141 — Two correctness bugs the persistent + elapsed-window pair
    fixes:

    1. **Restart-amnesia (was: in-memory ``set``).** The previous
       implementation tracked "already fired today" in a process-local
       set. A restart between the schedule minute and end-of-day made
       the dedup forget — the digest could either re-fire (restart at
       the schedule minute) or, paired with the precise-match below,
       skip silently.
    2. **Precise-match miss (was: ``current_time == sched_time``).**
       The loop slept 60 s and demanded an HH:MM equality. Any tick
       that took longer than the wake-budget (cold LLM call, disk
       hiccup, GC pause) woke up at HH:MM+1 and skipped that day's
       digest with no log line.

    Replacement: per-``(account, schedule_idx, date)`` flag in the
    settings table and an "elapsed AND not-yet-run-today" match.
    Converts the precise tick to at-least-once-per-day. Survives
    process restarts because the flag is on disk.

    Per-tick logic lives in :func:`_digest_scheduler_tick` so the
    decision logic is unit-testable without spinning up the loop.
    """
    # Wait a few seconds for the app to finish starting up.
    await asyncio.sleep(5)
    log.info("Digest scheduler started")

    while True:
        try:
            now = datetime.now(timezone.utc)
            await _digest_scheduler_tick(app, now)
            # #141 — yesterday's per-day flags become harmless dead
            # weight once the date rolls over. We don't sweep them
            # on every tick; the settings table is small and the
            # daily backup-export already round-trips it. If long-
            # term creep ever bites, a one-shot DELETE on
            # ``settings WHERE key LIKE 'digest_scheduler:last_run:%'
            # AND key NOT LIKE '...:<today>'`` drains the lot.
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("Digest scheduler error", error=fmt_exc(e))

        await asyncio.sleep(60)


async def _run_scheduled_digest(
    db: sqlite3.Connection,
    config: TriageConfig,
    secrets: SecretsProvider,
    acct: dict,
    digest_cfg: dict,
) -> None:
    """Execute a scheduled digest for one account."""
    from email_triage.web.routers.ui import (
        _create_provider_from_account,
        _build_classifier_from_config,
    )
    from email_triage.web.db import list_account_routes
    from email_triage.actions.digest import generate_digest
    from datetime import date

    category = digest_cfg.get("category", "newsletters")
    delete_originals = digest_cfg.get("delete_originals", False)

    # Source folder: explicit override on the schedule wins; fall back
    # to the route-inferred move folder for this category.
    source_folder = (digest_cfg.get("source_folder") or "").strip()
    if not source_folder:
        routes = list_account_routes(db, acct["id"])
        for r in routes:
            if r["category"] == category:
                for a in r.get("actions", []):
                    if a.get("action") == "move":
                        fm = a.get("config", {}).get("folder_map", {})
                        source_folder = fm.get(category, "")
                        break

    # Search limit: per-schedule override wins over hard-coded 50.
    _limit = digest_cfg.get("limit", 50)
    try:
        search_limit = int(_limit)
    except (TypeError, ValueError):
        search_limit = 50

    provider = _create_provider_from_account(acct, secrets)

    try:
        if source_folder and hasattr(provider, "select_folder"):
            await provider.select_folder(source_folder)

        # Scheduled digest uses the same preset convention as the
        # manual UI. Per-schedule `search_filter` setting (future) will
        # let operators pick; for now default matches the UI default.
        from datetime import timedelta
        _preset = digest_cfg.get("search_filter", "today") if isinstance(digest_cfg, dict) else "today"
        _today = date.today().strftime("%d-%b-%Y")
        if _preset == "unread_week":
            _week_ago = (date.today() - timedelta(days=7)).strftime("%d-%b-%Y")
            query = f"UNSEEN SINCE {_week_ago}"
        elif _preset == "unread_today":
            query = f"UNSEEN SINCE {_today}"
        else:
            query = f"SINCE {_today}"
        # Gmail API provider needs a `label:<folder>` clause so the
        # account-native translator routes the search correctly.
        if acct.get("provider_type") == "gmail_api" and source_folder:
            _label = source_folder.strip("/")
            if _label and f"label:{_label}" not in query:
                query = f"label:{_label} {query}"
        log.info("Scheduled digest search", account=acct.get("name", ""),
                 query=query, preset=_preset, source_folder=source_folder)
        uids = await provider.search(query, limit=search_limit)
        log.info("Scheduled digest search result",
                 account=acct.get("name", ""),
                 query=query, uid_count=len(uids))

        if not uids:
            log.info("Scheduled digest: no messages", account=acct["name"])
            return

        from email_triage.triage_logging import is_account_hipaa
        _hipaa = is_account_hipaa(acct)
        messages = []
        for uid in uids:
            try:
                msg = await provider.fetch_message(uid)
                msg.hipaa = _hipaa
                messages.append(msg)
            except Exception:
                pass

        if not messages:
            return

        classifier = _build_classifier_from_config(config)
        digest_html, article_count, source_count = await generate_digest(
            provider, classifier, messages, delete_originals=delete_originals,
            signature_template=config.summary_email.signature,
            category=category,
            account=acct.get("name", ""),
            html_template=digest_cfg.get("html_template", "") if isinstance(digest_cfg, dict) else "",
        )

        if article_count > 0:
            from email_triage.mail_headers import (
                X_EMAIL_TRIAGE_HEADER, build_triage_header,
            )
            from email_triage.actions.digest import _category_title
            from datetime import datetime as _dt
            _now = _dt.now().astimezone()
            subject = (
                f"Your Daily {_category_title(category)} Digest \u2014 "
                f"{_now.strftime('%A, %B %d, %Y')}"
            )
            from email_triage.web.routers.ui import (
                _account_mailbox_address, _resolve_digest_recipient,
            )
            # Scheduled digests don't have an interactive user — the
            # account owner is the natural "user.email" for the
            # user_email mode and for Reply-To. Look it up once from
            # the DB; an operator who deleted the owner falls back to
            # the account-mailbox address.
            _owner_email = ""
            try:
                _oid = acct.get("user_id")
                if _oid:
                    _row = db.execute(
                        "SELECT email FROM users WHERE id = ?", (_oid,),
                    ).fetchone()
                    if _row is not None:
                        _owner_email = _row["email"] or ""
            except Exception:
                pass

            _rmode = digest_cfg.get("recipient_mode", "back_to_account") if isinstance(digest_cfg, dict) else "back_to_account"
            _rcustom = digest_cfg.get("recipient_custom", "") if isinstance(digest_cfg, dict) else ""
            destination, eff_mode, _warn = _resolve_digest_recipient(
                acct, _owner_email, _rmode, _rcustom, hipaa=_hipaa,
            )
            if _warn:
                log.warning(
                    "Scheduled digest recipient down-shifted",
                    account=acct.get("name", ""),
                    requested_mode=_rmode,
                    effective_mode=eff_mode,
                    reason=_warn,
                )

            _digest_headers = {
                X_EMAIL_TRIAGE_HEADER: build_triage_header(
                    "digest",
                    category=category,
                    account=acct.get("name", ""),
                    hipaa=_hipaa,
                ),
            }
            _smtp = getattr(config, "smtp", None)
            _from_addr = getattr(_smtp, "from_addr", "") if _smtp else ""
            _from_name = getattr(_smtp, "from_name", "") if _smtp else ""
            _reply_to = _owner_email or None

            _mechanism = "none"
            _delivered = False
            try:
                if eff_mode == "back_to_account":
                    if hasattr(provider, "deliver_to_inbox"):
                        await provider.deliver_to_inbox(
                            to=[destination],
                            subject=subject,
                            body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        _mechanism = "deliver_to_inbox"
                    else:
                        await provider.create_draft(
                            to=[destination],
                            subject=subject,
                            body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        _mechanism = "create_draft"
                    _delivered = True
                else:
                    if _from_addr and _smtp and getattr(_smtp, "host", ""):
                        from email_triage.web.auth import smtp_send_digest
                        _pw = secrets.get("SMTP_PASSWORD") or ""
                        smtp_send_digest(
                            smtp_host=_smtp.host,
                            smtp_port=_smtp.port,
                            smtp_user=_smtp.username,
                            smtp_password=_pw,
                            from_addr=_from_addr,
                            from_name=_from_name,
                            to_addr=destination,
                            reply_to=_reply_to or "",
                            subject=subject,
                            html_body=digest_html,
                            use_tls=_smtp.use_tls,
                            extra_headers=_digest_headers,
                        )
                        _mechanism = "smtp"
                        _delivered = True
                    else:
                        await provider.create_draft(
                            to=[destination],
                            subject=subject,
                            body=digest_html,
                            extra_headers=_digest_headers,
                            from_addr=_from_addr or None,
                            from_name=_from_name or None,
                            reply_to=_reply_to,
                        )
                        _mechanism = "create_draft"
                        _delivered = True
            except NotImplementedError:
                try:
                    await provider.create_draft(
                        to=[destination],
                        subject=subject,
                        body=digest_html,
                        extra_headers=_digest_headers,
                        from_addr=_from_addr or None,
                        from_name=_from_name or None,
                        reply_to=_reply_to,
                    )
                    _mechanism = "create_draft"
                    _delivered = True
                except Exception as e:
                    log.warning(
                        "Digest delivery failed",
                        account=acct["name"], error=fmt_exc(e),
                    )
            except Exception as e:
                log.warning(
                    "Digest delivery failed",
                    account=acct["name"], error=fmt_exc(e),
                )

            if _delivered:
                log.info(
                    "Scheduled digest delivered",
                    account=acct["name"],
                    category=category,
                    recipient_mode=eff_mode,
                    recipient=destination,
                    destination_folder=("Inbox" if _mechanism == "deliver_to_inbox"
                                        else "Drafts" if _mechanism == "create_draft"
                                        else "SMTP"),
                    mechanism=_mechanism,
                    subject=subject,
                    article_count=article_count,
                    source_count=source_count,
                    provider=getattr(provider, "name", ""),
                )

    finally:
        await provider.close()


def get_db(request: Request) -> sqlite3.Connection:
    """Retrieve the shared database connection from app state."""
    return request.app.state.db


def get_request_accounts(
    request: Request,
    *,
    user_id: int | None = None,
    include_delegated: bool = True,
) -> list[dict]:
    """Memoised per-request ``list_email_accounts`` (#145.6).

    Several handlers + their helpers each called ``list_email_accounts``
    independently inside a single request render — 2-3 calls per page on
    /accounts, /logs, /stats, etc. This helper caches the lookup on
    ``request.state`` so the second + subsequent calls within the same
    request reuse the result.

    The cache key is ``(user_id, include_delegated)`` because admin views
    pass ``user_id=None`` while user-scoped views pass an id; both shapes
    can co-exist in the same render (admin viewing their own row alongside
    the all-accounts list, etc.).
    """
    from email_triage.web.db import list_email_accounts
    cache: dict = getattr(request.state, "_accounts_cache", None)
    if cache is None:
        cache = {}
        try:
            request.state._accounts_cache = cache
        except Exception:
            # ``request.state`` is normally settable; if a test stub
            # rejects it, fall through to the no-cache path.
            return list_email_accounts(
                request.app.state.db,
                user_id=user_id,
                include_delegated=include_delegated,
            )
    key = (user_id, include_delegated)
    if key not in cache:
        cache[key] = list_email_accounts(
            request.app.state.db,
            user_id=user_id,
            include_delegated=include_delegated,
        )
    return cache[key]


def get_templates(request: Request) -> Jinja2Templates:
    """Retrieve the Jinja2 templates from app state."""
    return request.app.state.templates


def get_config(request: Request) -> TriageConfig:
    """Retrieve the triage config from app state."""
    return request.app.state.config


def get_secrets(request: Request) -> SecretsProvider:
    """Retrieve the secrets provider from app state."""
    return request.app.state.secrets


def get_watcher_manager(request: Request) -> WatcherManager:
    """Retrieve the watcher manager from app state."""
    return request.app.state.watcher_manager


# ---------------------------------------------------------------------------
# Listener-mode restart detection (#81)
# ---------------------------------------------------------------------------

def is_listener_restart_pending(app: FastAPI) -> bool:
    """Return True when the saved ``tls.enabled`` differs from the value
    the uvicorn listener bound at process boot.

    Set on first lifespan tick from ``config.tls.enabled``; never
    re-read after that. Comparing the FROZEN boot value to the LIVE
    config catches "operator flipped the toggle, hit Save, but the
    in-process socket is still serving the old protocol." The flag
    auto-clears on the next process restart, so no manual reset is
    needed -- ``systemctl restart email-triage`` makes the chip go
    away on its own.

    The comparison is intentionally a strict bool() vs bool() so a
    None / unset config field reads as False on both sides (i.e.
    "still off" rather than "drift detected").
    """
    boot_mode = getattr(app.state, "tls_boot_mode", None)
    if boot_mode is None:
        # State not initialised (test harness skipped lifespan, etc.).
        # Be conservative: no chip rather than a false positive.
        return False
    cfg = getattr(app.state, "config", None)
    if cfg is None:
        return False
    saved_mode = bool(getattr(cfg.tls, "enabled", False))
    return bool(boot_mode) != saved_mode


# ---------------------------------------------------------------------------
# Gmail push consumer + watch renewal
# ---------------------------------------------------------------------------

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
        except Exception as e:
            log.error(
                "Push consumer: item processing failed",
                error=fmt_exc(e),
                item=item,
            )
        finally:
            try:
                app.state.push_queue.task_done()
            except ValueError:
                pass  # Queue.task_done can raise if over-called.


async def _process_push_item(app: FastAPI, item: dict) -> None:
    """Reconcile one Pub/Sub delivery into triage actions."""
    from email_triage.web.db import (
        get_email_account, get_gmail_watch, update_gmail_watch_history,
        list_account_routes, record_triage_run,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _collect_list_hints_for_message,
    )
    from email_triage.providers.gmail_api import (
        GmailApiError, GmailApiProvider, GmailHistoryExpiredError,
    )
    import httpx
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.engine.models import FlowState, FlowStatus
    from email_triage.triage_logging import is_account_hipaa

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    account_id = item["account_id"]
    incoming_history_id = str(item["history_id"])

    watch = get_gmail_watch(db, account_id)
    if watch is None:
        log.warning("Push consumer: no watch row", account_id=account_id)
        return

    # Idempotency: Pub/Sub can deliver the same historyId more than
    # once, and the webhook may enqueue multiple items during a burst.
    # Compare as ints — Gmail historyIds are monotonic integers.
    try:
        stored_hid_int = int(watch["history_id"])
        incoming_hid_int = int(incoming_history_id)
    except (TypeError, ValueError):
        stored_hid_int = 0
        incoming_hid_int = 0
    if incoming_hid_int and incoming_hid_int <= stored_hid_int:
        log.debug(
            "Push consumer: stale historyId, skipping",
            account_id=account_id,
            stored=watch["history_id"],
            incoming=incoming_history_id,
        )
        return

    acct = get_email_account(db, account_id)
    if acct is None:
        log.error("Push consumer: account vanished", account_id=account_id)
        return

    # Fail-closed: skip push processing for accounts whose owner is
    # disabled. We still advance the history cursor to avoid re-processing
    # the same backlog when the user is re-enabled.
    from email_triage.web.db import is_user_disabled as _iud
    owner_id = acct.get("user_id")
    if owner_id is not None and _iud(db, owner_id):
        log.warning(
            "Push consumer: skipping (owner disabled)",
            account_id=account_id, owner_id=owner_id,
        )
        try:
            update_gmail_watch_history(db, account_id, incoming_history_id)
        except Exception:
            pass
        return

    provider = _create_provider_from_account(acct, secrets)
    if not isinstance(provider, GmailApiProvider):
        log.error(
            "Push consumer: account is not gmail_api",
            **_acct_log_extras(acct),
            provider_type=acct.get("provider_type"),
        )
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
            # 200 is a deliberate cap: a runaway backfill on a high-
            # volume mailbox would otherwise re-classify thousands of
            # messages and burn LLM quota. The operator can re-run a
            # full classify-from-scratch via the dedicated /classify
            # admin tool if they actually want everything.
            log.warning(
                "Push consumer: history_id expired, recovering via "
                "bounded backfill",
                **_acct_log_extras(acct), stale_history_id=start_hid,
            )
            recent_ids = await provider.search("newer_than:7d", limit=200)
            delta = {
                "history": [
                    {"messagesAdded": [
                        {"message": {"id": mid}} for mid in recent_ids
                    ]}
                ] if recent_ids else [],
                "historyId": incoming_history_id,
            }
            log.info(
                "Push consumer: history-expired recovery complete",
                **_acct_log_extras(acct),
                stale_history_id=start_hid,
                recovered_count=len(recent_ids),
            )

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
            update_gmail_watch_history(db, account_id, str(delta.get("historyId") or incoming_history_id))
            return

        classifier = _build_classifier_from_config(config)
        categories = _get_categories_from_db(db, user_id=acct.get("user_id"))
        # Gmail push delivers without a per-mailbox concept; passing
        # mailbox=None yields the account-wide route map. #51 per-
        # mailbox overrides fire only on the IMAP watcher path where
        # the mailbox is known.
        from email_triage.web.db import effective_routes_by_cat
        routes_by_cat = effective_routes_by_cat(db, account_id, mailbox=None)

        from email_triage.actions.invite import (
            AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
        )
        from email_triage.actions.suggest_meeting_times import SuggestMeetingTimesAction
        registry = ActionRegistry()
        registry.register(MoveAction())
        registry.register(LabelAction())
        registry.register(NotifyAction())
        registry.register(DraftReplyAction())
        registry.register(AcceptInviteAction())
        registry.register(DeclineInviteAction())
        registry.register(TentativeInviteAction())
        registry.register(SuggestMeetingTimesAction())

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
            if _ice_eff(db, acct):
                # Pass db so IMAP-with-surrogate accounts (#105
                # phase 1A++) get the surrogate's provider.
                _cal_provider = _ccp(acct, secrets, db=db)
            _mp = _gmp(db, acct.get("user_id"))
        except Exception:
            _mp = None
        # IMAP accounts store the address as config["username"];
        # use the resolved field synthesized in db.get_email_account
        # so loop-prevention works for IMAP too.
        _self_email = acct.get("email_address", "")
        # #106 — alias-aware self-address set so action-side recipient
        # matching can take the union of primary + configured aliases.
        from email_triage.web.db import account_addresses as _aa
        _self_email_addresses = _aa(acct)

        results: list[dict] = []
        errors: list[dict] = []
        skipped_vanished = 0
        from email_triage.mail_headers import (
            get_triage_header as _gth, get_rfc_message_id as _grfc,
            is_self_origin as _is_self_origin,
        )
        from email_triage.web.db import is_triaged, mark_triaged
        from email_triage.web.triage_inflight import (
            mark_inflight as _mark_inflight,
            release_inflight as _release_inflight,
        )
        # Resolve install-wide self-from once per delta; cheap dict
        # lookup, but no point doing it per-message. (#117 secondary
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
        # The history_id advances unconditionally after the loop
        # (line further below — `update_gmail_watch_history`), so a
        # transient failure that exhausts retries means the message is
        # lost — Pub/Sub does NOT redeliver advanced cursors. The retry
        # buys one more shot at it before that happens.
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

        for mid in message_ids:
            # In-flight dedup gate (#114). The IMAP watcher and this
            # push consumer can race on the same UID/message-id when
            # a Gmail history delta arrives while an aioimaplib watch
            # cycle is mid-fetch. The second cycle would otherwise
            # land with a stub-shaped message (the first cycle's
            # mid-flight FETCH partially populated the second pass'
            # cache).
            if not _mark_inflight(app.state, account_id, mid):
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
                message.hipaa = is_account_hipaa(acct)
                _et_header = _gth(message.headers)
                if _et_header:
                    log.info(
                        "Skipping re-triage of email-triage-generated message",
                        message_id=mid,
                        x_email_triage=_et_header,
                        skip_reason="self_origin",
                    )
                    results.append({
                        "message_id": mid,
                        "status": "skipped",
                        "skip_reason": "self_origin",
                        "x_email_triage": _et_header,
                    })
                    continue
                # Defense in depth (#117): self-origin sender check.
                if _is_self_origin(message.sender or "", _self_from_addr):
                    log.info(
                        "Skipping self-origin message (header missing)",
                        message_id=mid, account_id=account_id,
                        skip_reason="self_origin",
                    )
                    results.append({
                        "message_id": mid,
                        "status": "skipped",
                        "skip_reason": "self_origin",
                    })
                    continue
                # Cross-folder dedup. Gmail history-poll surfaces
                # messages by ID; same message reaching us twice
                # (label add then move) produces duplicate ids in
                # the delta. RFC Message-Id catches that.
                _rfc_id = _grfc(message.headers)
                if _rfc_id and is_triaged(db, account_id, _rfc_id):
                    log.info(
                        "Skipping already-triaged message (rfc_id dedup)",
                        message_id=mid,
                    )
                    continue
                hints = _collect_list_hints_for_message(db, message)
                classification = await classifier.classify(
                    message, categories, hints or None,
                )
                actions_taken: list[dict] = []
                _gp_action_defs = routes_by_cat.get(classification.category, [])
                # 2026-05-13 — meeting-request intercept auto-inject.
                # See actions/suggest_meeting_times.py:inject_meeting_intercept.
                try:
                    from email_triage.web.db import (
                        get_meeting_prefs as _gmp_g,
                    )
                    from email_triage.web.calendars import (
                        is_calendar_effectively_enabled as _ice_g_eff,
                    )
                    from email_triage.actions.suggest_meeting_times import (
                        inject_meeting_intercept as _inject_g,
                    )
                    _gp_action_defs = _inject_g(
                        _gp_action_defs, classification.category,
                        calendar_wired=bool(_ice_g_eff(db, acct)),
                        has_meeting_prefs=bool(_gmp_g(db, acct.get("user_id"))),
                    )
                except Exception:
                    pass
                for action_def in _gp_action_defs:
                    action_name = action_def.get("action", "")
                    action_config = action_def.get("config", {})
                    action = registry.get(action_name)
                    if action is None:
                        continue
                    flow = FlowState(
                        flow_id=FlowState.new_id(),
                        message_id=mid,
                        provider=acct["provider_type"],
                        status=FlowStatus.ACTING,
                        state_bag={
                            "calendar_provider": _cal_provider,
                            "meeting_prefs": _mp,
                            "self_email": _self_email,
                            # #106 — alias-aware self-set, matches the
                            # parallel addition in triage_runner.run_triage.
                            "self_email_addresses": _self_email_addresses,
                            "account_id": account_id,
                            "account_name": acct.get("name", ""),
                            "owner": acct.get("owner_name") or acct.get("owner_email", ""),
                            # #73 — SMTP for escalation send.
                            "smtp_config": app.state.config.smtp,
                            "secrets": app.state.secrets,
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
                # Loop-prevention: stamp RFC id post-triage. Gmail
                # has no IMAP keyword; the dedup table is the only
                # cross-delta guard.
                if _rfc_id:
                    mark_triaged(db, account_id, _rfc_id)
                # HIPAA redaction parity with triage_runner.run_triage.
                from email_triage.triage_logging import (
                    is_account_hipaa, is_hipaa_mode,
                )
                _acct_hipaa = is_hipaa_mode() or is_account_hipaa(acct)
                _entry = {
                    "message_id": mid,
                    "category": classification.category,
                    "confidence": classification.confidence,
                    "source": classification.source,
                    "actions": actions_taken,
                    "status": "ok",
                }
                if not _acct_hipaa:
                    _entry["sender"] = message.sender
                    _entry["subject"] = message.subject
                _entry["reason"] = (
                    "[redacted]" if _acct_hipaa
                    else classification.reason
                )
                try:
                    _entry["date"] = (
                        message.date.isoformat()
                        if getattr(message, "date", None) else ""
                    )
                except Exception:
                    _entry["date"] = ""
                results.append(_entry)
            except Exception as e:
                errors.append({"message_id": mid, "error": fmt_exc(e)})
                log.error(
                    "Push consumer: per-message error",
                    **_acct_log_extras(acct), message_id=mid, error=fmt_exc(e),
                )
                # #175 R-B — durable per-message retry queue.
                # Gmail push site: pass the gmail message id (the
                # Pub/Sub payload's resource id) as the addressing
                # tuple. Auth-revoked → enqueue + immediately dead.
                try:
                    from email_triage.web.watcher_retry import (
                        enqueue_watcher_retry as _wr_enqueue_g,
                    )
                    _wr_enqueue_g(
                        app.state.db,
                        account_id=int(account_id),
                        provider_type=acct.get(
                            "provider_type", "gmail_api",
                        ),
                        gmail_msg_id=str(mid),
                        error=e,
                    )
                except Exception:
                    pass
            finally:
                # Release the in-flight slot (#114). Idempotent —
                # safe even when the gate above short-circuited the
                # cycle without actually claiming.
                _release_inflight(app.state, account_id, mid)

        elapsed = time.time() - t0
        run_id = f"push_{account_id}_{int(time.time())}"
        try:
            record_triage_run(
                db,
                account_id=account_id,
                account_name=acct.get("name", ""),
                query="gmail_push",
                total_messages=len(message_ids),
                results=results,
                errors=errors,
                elapsed_secs=elapsed,
            )
        except Exception:
            pass

        # Outbound webhook (HIPAA + quiet-hours gated).
        dispatcher = getattr(app.state, "event_dispatcher", None)
        if dispatcher is not None:
            from email_triage.web.events import fire_triage_completed
            try:
                await fire_triage_completed(
                    dispatcher, db, config, acct,
                    {
                        "run_id": run_id,
                        "query": "gmail_push",
                        "total_messages": len(message_ids),
                        "results": results,
                        "errors": errors,
                        "elapsed_secs": elapsed,
                    },
                    trigger="push",
                )
            except Exception as _e:
                log.warning("push: triage.completed dispatch failed", error=str(_e))

        # Advance cursor to the latest historyId from the delta.
        final_hid = str(delta.get("historyId") or incoming_history_id)
        update_gmail_watch_history(db, account_id, final_hid)

        log.info(
            "Push consumer: processed delta",
            **_acct_log_extras(acct),
            messages=len(message_ids),
            errors=len(errors),
            vanished=skipped_vanished,
            history_id=final_hid,
            elapsed=f"{elapsed:.1f}s",
        )
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


async def _baa_expiry_sweeper(app: FastAPI) -> None:
    """Run the BAA-expiry sweep once per hour (#169 Wave 2-α — I7).

    The sweep is fully synchronous + idempotent (see
    :mod:`email_triage.baa_expiry`). Re-running on a day where no row
    is in scope is a single SELECT + bucket math; running on a day
    with an expired backend re-clears already-cleared FKs (no-op).
    The HOURLY cadence is enough to keep ``app.state.baa_expiry_status``
    fresh for the health endpoint without hammering SQLite — the
    underlying state changes at most once per day (a date crossing).

    Stamps two pieces of state:

    * ``app.state.baa_expiry_status``  — latest summary dict, used by
      the admin pages + the daily-health email to surface the
      buckets without re-running the sweep on every render.
    * ``app.state.baa_expiry_disabled_count`` — cumulative count of
      auto-disabled accounts since process boot. /health/detail
      surfaces this so a Nagios poll can see "how many BAA-driven
      downgrades have fired today" without scraping the audit log.
    """
    await asyncio.sleep(5)
    log.info("BAA expiry sweeper started")

    # Initialise the cumulative counter on app.state so the health
    # endpoint reads a defined value even before the first tick.
    if not hasattr(app.state, "baa_expiry_disabled_count"):
        app.state.baa_expiry_disabled_count = 0
    if not hasattr(app.state, "baa_expiry_status"):
        app.state.baa_expiry_status = None

    from email_triage.baa_expiry import baa_expiry_daily_sweep

    while True:
        try:
            summary = await asyncio.to_thread(
                lambda: baa_expiry_daily_sweep(app.state.db),
            )
            app.state.baa_expiry_status = summary
            app.state.baa_expiry_disabled_count = (
                int(app.state.baa_expiry_disabled_count or 0)
                + len(summary.get("auto_disabled") or [])
            )
            if summary.get("auto_disabled"):
                log.warning(
                    "BAA expiry sweep auto-disabled HIPAA accounts",
                    count=len(summary["auto_disabled"]),
                    expired=summary.get("expired", 0),
                )
        except asyncio.CancelledError:
            log.info("BAA expiry sweeper cancelled")
            return
        except Exception as e:
            log.error("BAA expiry sweeper error", error=fmt_exc(e))

        try:
            # Sleep one hour between sweeps — see docstring.
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            log.info("BAA expiry sweeper cancelled")
            return


async def _per_contact_style_gc_sweeper(app: FastAPI) -> None:
    """Daily GC sweep for per-contact HIPAA style descriptors (#152 W3).

    Per-contact rows older than
    :data:`HIPAA_PER_CONTACT_GC_DAYS` (90 days) since last distill get
    deleted — operator likely stopped emailing that contact + the
    hash storage no longer earns its keep. Cascade-safe with the
    account ON DELETE.

    Cadence: daily (24h). The DELETE is cheap (single statement on
    a tiny indexed range) so running it daily rather than hourly
    keeps log volume low while staying well inside the freshness
    semantics. Idempotent — re-runs on a clean state return 0.

    Stamps ``app.state.per_contact_style_gc_status`` with the latest
    summary for /health/detail.
    """
    await asyncio.sleep(8)
    log.info("Per-contact style GC sweeper started")

    if not hasattr(app.state, "per_contact_style_gc_status"):
        app.state.per_contact_style_gc_status = None

    from email_triage.style_learning.per_contact_hipaa import (
        per_contact_gc_daily_sweep,
    )

    while True:
        try:
            summary = await asyncio.to_thread(
                lambda: per_contact_gc_daily_sweep(app.state.db),
            )
            app.state.per_contact_style_gc_status = summary
            if summary.get("removed"):
                log.info(
                    "Per-contact style GC removed stale rows",
                    count=summary["removed"],
                    gc_days=summary["gc_days"],
                )
        except asyncio.CancelledError:
            log.info("Per-contact style GC sweeper cancelled")
            return
        except Exception as e:
            log.error(
                "Per-contact style GC sweeper error",
                error=fmt_exc(e),
            )

        try:
            # Sleep 24 hours between sweeps.
            await asyncio.sleep(86400)
        except asyncio.CancelledError:
            log.info("Per-contact style GC sweeper cancelled")
            return


async def _style_distill_trigger_sweeper(app: FastAPI) -> None:
    """Periodic trigger watcher for M-3 + M-7 HIPAA-safe style distills (#171-B).

    Drives the trigger plane that sits between the user's sent mail
    + the existing queue worker. Conditions evaluated each tick (see
    :mod:`email_triage.style_learning.trigger_watcher`):

      * M-3 (account-level): first-time after opt-in, threshold
        (≥20 new sent messages since last success), stale (>7 days).
      * M-7 (per-contact): threshold (≥20 per recipient), stale
        (>30 days for inactive contacts with an overlay).

    Cadence: 15 minutes. The first-time trigger spec asks for an
    initial distill "within 5 minutes" of opt-in; the supervisor
    fires the first tick on startup-warmup ~12s in + every 15 min
    thereafter, so the worst-case latency on a freshly-flipped opt-in
    is ~15 min. Tightening this to 5 min would mean wasted work on
    a fleet of long-running installs; 15 min is the right trade-off
    + matches the homelab cron rules for ``/projects`` mining.

    Stamps ``app.state.style_trigger_sweep_status`` with the latest
    summary for /health/detail.
    """
    await asyncio.sleep(12)
    log.info("Style-distill trigger sweeper started")

    if not hasattr(app.state, "style_trigger_sweep_status"):
        app.state.style_trigger_sweep_status = None

    from email_triage.style_learning.trigger_watcher import (
        run_trigger_sweep,
    )

    while True:
        try:
            summary = await asyncio.to_thread(
                lambda: run_trigger_sweep(app.state.db),
            )
            # Convert dataclass to dict for health-endpoint
            # serialisation. The dataclass is internal; the dict is
            # the external surface.
            app.state.style_trigger_sweep_status = {
                "ts": summary.ts,
                "m3_evaluated": summary.m3_evaluated,
                "m3_enqueued": summary.m3_enqueued,
                "m7_evaluated": summary.m7_evaluated,
                "m7_enqueued": summary.m7_enqueued,
                "m3_reasons": dict(summary.m3_reasons or {}),
                "m7_reasons": dict(summary.m7_reasons or {}),
            }
            if summary.m3_enqueued or summary.m7_enqueued:
                log.info(
                    "Style-distill trigger sweep enqueued work",
                    m3_enqueued=summary.m3_enqueued,
                    m7_enqueued=summary.m7_enqueued,
                )
        except asyncio.CancelledError:
            log.info("Style-distill trigger sweeper cancelled")
            return
        except Exception as e:
            log.error(
                "Style-distill trigger sweeper error",
                error=fmt_exc(e),
            )

        try:
            # Sleep 15 minutes between sweeps.
            await asyncio.sleep(900)
        except asyncio.CancelledError:
            log.info("Style-distill trigger sweeper cancelled")
            return


# ---------------------------------------------------------------------------
# Watcher per-message retry queue sweeper (#175 R-A)
# ---------------------------------------------------------------------------

#: Sweeper tick cadence. Matches the shortest backoff bucket in
#: :data:`email_triage.retry_backoff.WATCHER_RETRY_SCHEDULE` so a
#: 30s-bucket retry fires on the next tick (worst-case 60s late, mean
#: 45s late). When Redis is available the pubsub wake path bypasses
#: the poll wait entirely.
_WATCHER_RETRY_TICK_SECONDS = 30

#: Per-tick fanout cap. Higher = faster drain on a large backlog; lower
#: = less impact on the LLM / provider when many messages were stuck
#: on the same outage. 10 is the same shape #149's ``_triage_retry_worker``
#: uses + has proven safe in prod since 2026-05.
_WATCHER_RETRY_PER_TICK_LIMIT = 10

#: Redis pubsub channel for immediate-fire on new enqueue. Sweeper
#: subscribes; the enqueue path (R-B's surface) PUBLISHes. Channel
#: namespace ``et:retry:*`` is reserved for #175.
_WATCHER_RETRY_WAKE_CHANNEL = "et:retry:wake"

#: Redis counter namespace for terminal-state transitions. Keys:
#: ``enqueued`` / ``succeeded`` / ``dead_max_attempts`` /
#: ``dead_uidvalidity`` / ``dead_gone`` / ``dead_auth`` / ``attempts_total``.
_WATCHER_RETRY_COUNTER_NS = "retry_queue"


async def _watcher_retry_sweeper(app: FastAPI) -> None:
    """Sweep ``watcher_retry_queue``; fire retries that are due (#175 R-A).

    Sibling to :func:`_baa_expiry_sweeper`,
    :func:`_style_distill_trigger_sweeper`,
    :func:`_per_contact_style_gc_sweeper`. Same supervised-task pattern.

    Tick cadence
    ------------
    * **Plain poll**: every 30s (:data:`_WATCHER_RETRY_TICK_SECONDS`).
      Matches the shortest backoff bucket.
    * **Pubsub wake** (optional): when ``app.state.redis`` is set, the
      sweeper subscribes to ``et:retry:wake`` and runs an immediate
      sweep on every message. The poll path stays alive as a backstop
      — Redis is best-effort by design.

    Re-ingestion is delegated to R-B's enqueue sites + admin UI for the
    actual triage call (R-A is foundation-only). The sweeper here only
    transitions state machine entries:

    * **pending → done** on operator manual resolution (R-B surface).
    * **pending → dead(max_attempts_exceeded)** when the schedule is
      exhausted.

    R-B's worktree extends this sweeper with the per-row re-fetch +
    re-classify path. Until that lands, the sweeper drains the
    schedule-exhausted rows (so they don't sit at ``state='pending'``
    forever) + logs the rest at DEBUG. Nothing here re-fires triage.

    Counter accounting
    ------------------
    When ``app.state.redis`` is set, every terminal transition bumps a
    counter in the ``et:counters:retry_queue`` HASH (see
    :mod:`email_triage.engine.persistent_counters` for the persistence
    pattern). Counters are best-effort — Redis being down NEVER fails
    the SQLite state transition.
    """
    await asyncio.sleep(7)  # let supervisor finish boot burst
    log.info("Watcher retry sweeper started")

    if not hasattr(app.state, "watcher_retry_sweep_status"):
        app.state.watcher_retry_sweep_status = None

    from email_triage.retry_backoff import (
        WATCHER_RETRY_SCHEDULE, max_attempts as _max_attempts,
    )
    from email_triage.web.db import (
        list_due_retries, mark_retry_dead,
    )

    # Subscribe to the pubsub wake channel when Redis is available.
    # The subscriber runs in the background so the poll loop here
    # doesn't block on recv(); each message just sets an event that
    # the poll loop checks at the top of its while-true.
    wake_event = asyncio.Event()

    async def _wake_listener() -> None:
        redis_client = getattr(app.state, "redis", None)
        if redis_client is None:
            return
        try:
            pubsub = redis_client.pubsub()
            await asyncio.to_thread(
                pubsub.subscribe, _WATCHER_RETRY_WAKE_CHANNEL,
            )
        except Exception as exc:
            log.debug(
                "Watcher retry pubsub subscribe failed; "
                "falling back to poll-only path",
                error=fmt_exc(exc),
            )
            return
        try:
            while True:
                msg = await asyncio.to_thread(
                    pubsub.get_message,
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
                if msg is not None:
                    wake_event.set()
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            return
        except Exception as exc:
            # Redis flapped mid-listen. Log + return; sweeper falls
            # back to plain polling.
            log.debug(
                "Watcher retry pubsub listener exited; "
                "falling back to poll-only path",
                error=fmt_exc(exc),
            )

    listener_task: asyncio.Task | None = None
    redis_client = getattr(app.state, "redis", None)
    if redis_client is not None:
        try:
            listener_task = asyncio.create_task(_wake_listener())
        except Exception as exc:
            log.debug(
                "Watcher retry pubsub listener spawn failed",
                error=fmt_exc(exc),
            )
            listener_task = None

    max_attempts = _max_attempts(WATCHER_RETRY_SCHEDULE)

    def _bump_counter(field: str, by: int = 1) -> None:
        """Best-effort Redis counter bump. Silent on Redis failure."""
        client = getattr(app.state, "redis", None)
        if client is None:
            return
        try:
            client.hincrby(
                f"et:counters:{_WATCHER_RETRY_COUNTER_NS}", field, by,
            )
        except Exception as exc:
            log.debug(
                "Watcher retry counter bump failed",
                field=field, error=fmt_exc(exc),
            )

    while True:
        try:
            db = app.state.db
            rows = await asyncio.to_thread(
                lambda: list_due_retries(db, limit=_WATCHER_RETRY_PER_TICK_LIMIT),
            )
            transitioned_dead = 0
            for row in rows:
                row_id = int(row["id"])
                attempt_count = int(row["attempt_count"])
                # Schedule exhausted → mark dead immediately. R-B's
                # consumer fan-out runs BEFORE this gate when wired
                # in; until then, exhausted rows here keep the queue
                # bounded.
                if attempt_count >= max_attempts:
                    try:
                        await asyncio.to_thread(
                            lambda rid=row_id: mark_retry_dead(
                                db, rid, reason="max_attempts_exceeded",
                            ),
                        )
                        transitioned_dead += 1
                        _bump_counter("dead_max_attempts")
                    except Exception as exc:
                        log.warning(
                            "Watcher retry sweeper: dead-transition failed",
                            row_id=row_id, error=fmt_exc(exc),
                        )

            # Stamp summary on app.state for /health/detail (R-B will
            # surface this).
            app.state.watcher_retry_sweep_status = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "due_seen": len(rows),
                "transitioned_dead": transitioned_dead,
            }
        except asyncio.CancelledError:
            log.info("Watcher retry sweeper cancelled")
            if listener_task is not None:
                listener_task.cancel()
            return
        except Exception as e:
            log.error(
                "Watcher retry sweeper error",
                error=fmt_exc(e),
            )

        # Sleep until either (a) the poll interval elapses or (b) a
        # pubsub wake fires. asyncio.wait_for with a short timeout is
        # the cleanest cancellation-safe pattern here.
        try:
            wake_event.clear()
            try:
                await asyncio.wait_for(
                    wake_event.wait(),
                    timeout=_WATCHER_RETRY_TICK_SECONDS,
                )
            except asyncio.TimeoutError:
                pass  # plain poll path — sweep again
        except asyncio.CancelledError:
            log.info("Watcher retry sweeper cancelled")
            if listener_task is not None:
                listener_task.cancel()
            return


async def _daily_health_email_sender(app: FastAPI) -> None:
    """Tick every 60 s; fire the daily health email when clock crosses send_at.

    Local-time based (``datetime.now().astimezone()``) so the send time
    honours whatever TZ the container was configured with (#3).  Uses
    a ``last_sent_date`` guard on ``app.state`` to avoid re-firing within
    the same calendar day even if the process restarts or the clock
    oscillates across the HH:MM boundary.
    """
    await asyncio.sleep(10)
    log.info("Daily health email sender started")

    from email_triage.web.daily_health import (
        resolve_admin_recipients,
        send_daily_health_email,
    )

    last_sent_date: str | None = None

    while True:
        try:
            cfg = app.state.config
            hc = cfg.health_email
            # CR-2c — recipient list now comes from the canonical
            # ``admin_email.recipients`` with a fallback to the legacy
            # ``health_email.recipients`` field. The resolver logs a
            # deprecation warning the first time the fallback is used.
            if hc.enabled and resolve_admin_recipients(cfg):
                now_local = datetime.now().astimezone()
                today_key = now_local.strftime("%Y-%m-%d")
                current_hm = now_local.strftime("%H:%M")
                if current_hm == hc.send_at and last_sent_date != today_key:
                    last_sent_date = today_key
                    # Pass ``app`` so the listener-restart-pending
                    # check (#81) runs and can promote a stale
                    # toggle to attention_reasons.
                    sent, reason = await asyncio.to_thread(
                        lambda: send_daily_health_email(
                            app.state.db,
                            app.state.config,
                            app.state.secrets,
                            getattr(app.state, "watcher_manager", None),
                            app=app,
                        ),
                    )
                    log.info(
                        "Daily health email tick fired",
                        sent=sent, reason=reason, at=current_hm,
                    )
        except asyncio.CancelledError:
            log.info("Daily health email sender cancelled")
            return
        except Exception as e:
            log.error("Daily health email sender error", error=fmt_exc(e))

        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            log.info("Daily health email sender cancelled")
            return


def _filter_digest_candidates(
    *,
    db, acct: dict, dcfg, now_utc, last_sent: str | None,
) -> list[dict]:
    """Cheap dry-run: resolve window + gather rows + apply custom
    filter. Returns the rows that WOULD feed into the renderer.

    No provider fetch. No LLM. Same logic as ``_fire_one_digest``
    steps 1-3, hoisted into a sibling so the "Show matches" UI
    button can preview the filter shape without paying the
    provider-fetch + LLM-extraction costs of a full render.

    Caller (Show-matches route) renders the returned rows as a
    candidate table; the count doubles as an ETA gauge for the
    full Preview / Send-test paths (newsletter formats run ~30-90s
    of LLM extraction per source).
    """
    from email_triage.actions.digest_configs import PRESET_ID
    from email_triage.actions.digest_filter import (
        resolve_window, row_matches_filter,
    )
    from email_triage.actions.recipient_digest import (
        gather_digest_rows,
    )

    is_preset = dcfg.id == PRESET_ID
    if is_preset:
        since_iso = (now_utc - timedelta(hours=24)).isoformat()
    else:
        since_iso, _until_iso = resolve_window(
            dcfg.window, now=now_utc, last_sent_iso=last_sent,
        )
    rows = gather_digest_rows(
        db, account_id=acct["id"], since_iso=since_iso,
    )
    if not is_preset:
        rows = [r for r in rows if row_matches_filter(r, dcfg.filter)]
        if dcfg.format.max_rows and len(rows) > dcfg.format.max_rows:
            rows = rows[: dcfg.format.max_rows]
    return rows


async def _render_digest_payload(
    *,
    db, secrets, acct: dict, dcfg, hipaa: bool,
    now_utc, last_sent: str | None, config=None,
) -> tuple[str, str, str, list[dict]]:
    """Render the digest's email payload without sending it.

    Returns ``(subject, html_body, plain_body, rows)``. Empty
    ``rows`` means the window had no matching rows; the three
    string fields are empty strings in that case. ``rows`` is the
    actual list (not just the count) so the caller can pass it
    to ``send_recipient_digest`` — the preset path's legacy
    default subject uses ``len(rows)`` when subject_override is
    None, so we need the list to keep that contract intact.

    Provider fetch + LLM extraction fire for newsletter formats
    here — the cost moment. Caller chooses what to do with the
    result: SMTP-send (``_fire_one_digest``) or stuff into an
    iframe for the Preview UI (no SMTP).

    Raises if the newsletter render path is selected but
    ``config`` wasn't passed (newsletter classifier needs it).
    """
    from email_triage.actions.digest_configs import PRESET_ID
    from email_triage.actions.digest_render import render_digest
    from email_triage.actions.recipient_digest import (
        build_custom_digest_subject,
        render_html as render_preset_html,
        render_plain as render_preset_plain,
    )

    rows = _filter_digest_candidates(
        db=db, acct=acct, dcfg=dcfg,
        now_utc=now_utc, last_sent=last_sent,
    )
    if not rows:
        return ("", "", "", [])

    is_preset = dcfg.id == PRESET_ID
    account_email = (acct.get("email_address") or "").strip()

    # Render dispatch — preset (legacy table), newsletter (async
    # provider re-fetch + LLM extraction), or the sync custom
    # dispatcher (table / grouped_list / plain_list).
    if is_preset:
        html_body = render_preset_html(
            rows=rows,
            account_name=acct.get("name", ""),
            account_email=account_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
        )
        plain_body = render_preset_plain(
            rows=rows,
            account_name=acct.get("name", ""),
            account_email=account_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
        )
    elif dcfg.format.render_as in ("newsletter", "newsletter_classic"):
        from email_triage.actions.digest_render import (
            render_newsletter_async,
        )
        from email_triage.web.routers.ui import (
            _create_provider_from_account,
            _build_classifier_from_config,
        )
        if config is None:
            raise RuntimeError(
                "Newsletter digest path requires the runtime config; "
                "caller of _render_digest_payload must pass "
                "config=app.state.config"
            )
        try:
            provider = _create_provider_from_account(acct, secrets)
            classifier = _build_classifier_from_config(config)
        except Exception as e:
            log.error(
                "Newsletter digest setup failed",
                account_id=acct["id"], digest_id=dcfg.id,
                error=fmt_exc(e),
            )
            raise
        # Re-fetch each row's source message so the article
        # extractor has body_html. Drop fetch failures silently;
        # they reduce the digest by one source rather than aborting.
        # HIPAA: stamp ``msg.hipaa`` on every fetched message so
        # ``actions.digest.extract_articles`` fires its fail-closed
        # gate (skip LLM extraction off-host when the message is
        # PHI-flagged + classifier is non-local). Without this stamp
        # the gate is dead — ``getattr(message, "hipaa", False)``
        # returns False and PHI bodies travel to the LLM endpoint.
        # Sibling paths (line ~2138 scheduled-digest, line ~2592
        # /digests/generate, line ~4004 watcher) already set this;
        # the per-digest send path was missing it (audit punch-list
        # #110, 2026-05-08).
        msg_ids = [r.get("message_id") for r in rows if r.get("message_id")]
        messages = []
        for mid in msg_ids:
            try:
                _msg = await provider.fetch_message(mid)
                _msg.hipaa = hipaa
                messages.append(_msg)
            except Exception as fe:
                log.warning(
                    "Newsletter source fetch failed",
                    account_id=acct["id"], digest_id=dcfg.id,
                    message_id=mid, error=fmt_exc(fe),
                )
        # Signature template is operator-configured under
        # config.summary_email.signature; threaded through to the
        # newsletter render so the rendered footer matches what
        # the legacy /digests/generate manual button produced
        # before the multi-digest refactor moved the path.
        # digest_name surfaces dcfg.name in the rendered body so
        # the recipient knows WHICH of several digests sent the
        # email (matches the cadence-aware subject line).
        _signature = ""
        try:
            _signature = (
                config.summary_email.signature or ""
            )
        except AttributeError:
            pass
        try:
            html_body = await render_newsletter_async(
                cfg=dcfg, provider=provider, classifier=classifier,
                messages=messages,
                account_name=acct.get("name", ""),
                account_email=account_email,
                hipaa=hipaa,
                date_str=now_utc.strftime("%A, %B %d, %Y"),
                signature=_signature,
                digest_name=getattr(dcfg, "name", "") or "",
                html_template=getattr(
                    dcfg.format, "html_template", "",
                ) or "",
            )
        finally:
            try:
                await provider.close()
            except Exception:
                pass
        import re as _re
        plain_body = _re.sub(r"<[^>]+>", "", html_body)
        plain_body = _re.sub(r"\n{3,}", "\n\n", plain_body)
    else:
        html_body = render_digest(
            cfg=dcfg, rows=rows,
            account_name=acct.get("name", ""),
            account_email=account_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
        )
        import re as _re
        plain_body = _re.sub(r"<[^>]+>", "", html_body)
        plain_body = _re.sub(r"\n{3,}", "\n\n", plain_body)

    # Subject: preset uses the legacy default in send_recipient_digest
    # (signalled via empty string here; SMTP-bound caller passes None
    # to send_recipient_digest's subject_override which falls through
    # to its own legacy default). Custom digests get the cadence-aware
    # name-driven subject we ship as build_custom_digest_subject.
    if is_preset:
        subject = ""
    else:
        subject = build_custom_digest_subject(dcfg, now_utc.astimezone())

    return (subject, html_body, plain_body, rows)


async def _fire_one_digest(
    *,
    db, secrets, smtp,
    acct: dict, dcfg, hipaa: bool,
    now_utc, last_sent: str | None, to_addr: str,
    config=None,
    is_test_send: bool = False,
) -> int:
    """Run one digest (preset or custom) end-to-end.

    Resolves window → gathers rows → filters in-process for
    custom → renders → sends → stamps state + audit row.

    Returns the number of rows actually sent. ``0`` means the
    digest didn't send — either the recipient mismatch guard
    refused, the row gather failed, OR the window had no
    matching rows. The caller can branch on ``rv == 0`` to tell
    the operator "nothing to send" instead of falsely reporting
    "✓ Sent" — which was the original bug behind the test-send
    UX silently lying when the window was empty.

    Raises on programmer errors (newsletter path missing config,
    SMTP send failure, etc.). Scheduler caller wraps in try/except
    so one bad digest doesn't abort the loop; test-send route's
    try/except surfaces the failure to the operator.

    ``is_test_send=True`` skips the ``digest_mark_sent`` state
    write so a manual test-send doesn't shift the next scheduled
    fire's window or trip the idempotence guard. The real
    scheduled send still has to happen at its scheduled time.
    """
    from email_triage.actions.digest_configs import (
        PRESET_ID, mark_sent as digest_mark_sent,
    )
    from email_triage.actions.recipient_digest import (
        send_recipient_digest,
    )

    # HIPAA recipient hardening: defense-in-depth assertion that the
    # send target is one of the addresses that route into this
    # account's own mailbox. The design contract (recipient_digest.py
    # module doc) is "delivery locked to the account; never to
    # notify_email or any other surface" — but the digest config is
    # now a JSON blob with a filter / format / advanced field that
    # operators can edit. If a future schema change introduces a
    # ``to_addr`` override, OR if a caller passes a wrong ``to_addr``
    # arg, the HIPAA path must refuse rather than leak. Standard-mode
    # accounts get the same check too (logged at error too) — single
    # code path, mistake is a mistake regardless of HIPAA flag.
    #
    # #106 multi-address: an account may legitimately receive mail at
    # several addresses (primary plus configured aliases — same inbox,
    # different SMTP destinations). The match expands to the union
    # ``{primary} ∪ aliases`` so a digest delivered to ``alias1@example.com``
    # for an account whose primary is ``user@example.com`` still
    # round-trips into the same physical mailbox. The data-subject
    # boundary is unchanged: aliases route to the SAME mailbox; the
    # mismatch case the guard exists to catch (delivery to a third
    # party's address) is still rejected.
    from email_triage.web.db import account_addresses
    valid_targets = {a for a in account_addresses(acct) if a}
    norm_to = (to_addr or "").strip().lower()
    if not valid_targets or norm_to not in valid_targets:
        log.error(
            "Digest send refused: recipient mismatch",
            account_id=acct["id"], digest_id=dcfg.id,
            hipaa=hipaa, to=to_addr,
            valid_count=len(valid_targets),
        )
        # Test-send caller wants to surface this — the scheduled
        # caller logs + carries on. Raise either way; scheduler
        # already wraps in try/except.
        raise RuntimeError(
            "Digest recipient mismatch — to_addr does not match "
            "any address (primary or alias) that routes into "
            "this account."
        )

    # Render via the shared payload helper. Preview / Show-matches
    # routes call the same helper without coming through here, so
    # the render shape is bit-identical across all three paths.
    subject, html_body, plain_body, rows = await _render_digest_payload(
        db=db, secrets=secrets, acct=acct, dcfg=dcfg,
        hipaa=hipaa, now_utc=now_utc, last_sent=last_sent,
        config=config,
    )

    if not rows:
        # Empty-window skip. For scheduled fires, stamp last_sent
        # so the next tick in the same minute bucket doesn't
        # re-evaluate (same idempotence rule as a real send). For
        # a test-send, skip the stamp — operator is debugging
        # filter shape; mutating real state would shift the next
        # scheduled fire's window. Return 0 so the caller can
        # render an honest "no matching messages" message instead
        # of false "✓ Sent" — the original bug behind the
        # silent-success UX.
        if not is_test_send:
            digest_mark_sent(db, acct["id"], dcfg.id, now_utc, 0)
        return 0

    is_preset = dcfg.id == PRESET_ID
    # Preset uses the legacy default in send_recipient_digest;
    # _render_digest_payload signals this with subject == "".
    subject_override = subject or None
    smtp_password = secrets.get("SMTP_PASSWORD") or ""
    await asyncio.to_thread(
        send_recipient_digest,
        smtp_host=smtp.host,
        smtp_port=smtp.port,
        smtp_user=smtp.username,
        smtp_password=smtp_password,
        from_addr=smtp.from_addr,
        from_name=smtp.from_name,
        to_addr=to_addr,
        account_name=acct.get("name", ""),
        rows=rows,
        hipaa=hipaa,
        use_tls=smtp.use_tls,
        fallback_dt_iso=now_utc.isoformat(),
        html_body_override=html_body,
        plain_body_override=plain_body,
        subject_override=subject_override,
    )
    # State + audit only stamp on real sends, not test-sends.
    # Test-send is for previewing what'll go out; mutating
    # last_sent / writing an audit row would (a) shift the next
    # scheduled fire's window if window kind is "since_last_sent"
    # and (b) pollute the audit trail with operator-debug rows.
    #
    # Wrap the post-send writes in try/except so a state-write
    # failure (e.g. transient DB lock) doesn't make a successful
    # send look like a failure. The send itself isn't wrapped —
    # SMTP failures must propagate so the operator sees them.
    if not is_test_send:
        try:
            digest_mark_sent(
                db, acct["id"], dcfg.id, now_utc, len(rows),
            )
        except Exception as e:
            log.warning(
                "Digest sender: mark_sent failed",
                account_id=acct["id"], digest_id=dcfg.id,
                error=fmt_exc(e),
            )
        try:
            from email_triage.web.db import record_access_event
            record_access_event(
                db,
                actor_user_id=None,
                method="POST",
                route="/internal/recipient-digest",
                account_id=acct["id"],
                message_id=None,
                status_code=200,
                outcome="recipient_digest_sent",
                detail=(
                    f"digest_id={dcfg.id} kind={dcfg.kind} "
                    f"row_count={len(rows)} hipaa={hipaa} "
                    f"to={to_addr} "
                    f"filter_advanced={'yes' if dcfg.filter.advanced else 'no'}"
                ),
            )
        except Exception as e:
            log.warning(
                "Digest sender: audit row write failed",
                account_id=acct["id"], digest_id=dcfg.id,
                error=fmt_exc(e),
            )
    log.info(
        "Digest sent",
        account_id=acct["id"], digest_id=dcfg.id,
        kind=dcfg.kind, rows=len(rows), hipaa=hipaa,
        test_send=is_test_send,
    )
    return len(rows)


async def _recipient_digest_sender(app: FastAPI) -> None:
    """Tick every 60s; fire each account's enabled digest configs
    when the clock crosses their scheduled time.

    Phase 4 of the multi-digest refactor. Reads
    ``settings.digest_configs:<account_id>`` (created on first
    read by ``digest_configs.list_digest_configs`` from legacy
    ``recipient_digest_enabled`` + ``digest_schedules:<id>``
    storage). Each config carries its own schedule, filter,
    window, and render selector.

    Two render paths:

    - ``preset_daily_activity`` → legacy
      ``recipient_digest.render_html`` table. Wire output is
      byte-for-byte identical to the pre-Phase-4 sender so the
      preset survives the cutover unchanged.
    - ``custom`` → ``actions.digest_render.render_digest``
      dispatcher (grouped_list / plain_list / table).

    Idempotence is per-digest now: the state key is
    ``digest_state:<acct_id>:<digest_id>`` so two digests on the
    same account at different times can co-exist. The preset's
    state mirrors into the legacy
    ``recipient_digest_state:<acct_id>`` row so a rollback past
    Phase 4 doesn't double-send.
    """
    await asyncio.sleep(15)
    log.info("Recipient digest sender started")

    from email_triage.actions.digest_configs import (
        get_last_sent as digest_get_last_sent,
        list_digest_configs,
    )
    from email_triage.actions.digest_filter import digest_should_fire
    from email_triage.web.db import list_email_accounts

    while True:
        try:
            cfg = app.state.config
            db = app.state.db
            secrets = app.state.secrets
            smtp = cfg.smtp
            now_local = datetime.now().astimezone()
            now_utc = datetime.now(timezone.utc)

            for acct in list_email_accounts(db):
                if not acct.get("is_active", True):
                    continue
                acct_id = acct["id"]
                to_addr = (acct.get("email_address") or "").strip()
                if not to_addr:
                    # Account hasn't been saved with credentials
                    # yet — skip silently per pre-Phase-4 behaviour.
                    continue

                from email_triage.triage_logging import is_hipaa_mode
                hipaa = (
                    is_hipaa_mode()
                    or bool(acct.get("hipaa", False))
                )

                try:
                    digest_cfgs = list_digest_configs(db, acct_id)
                except Exception as e:
                    log.warning(
                        "Digest sender: list_digest_configs failed",
                        account_id=acct_id, error=fmt_exc(e),
                    )
                    continue

                for dcfg in digest_cfgs:
                    last_sent = digest_get_last_sent(
                        db, acct_id, dcfg.id,
                    )
                    if not digest_should_fire(
                        dcfg,
                        last_sent_iso=last_sent,
                        now_local=now_local,
                    ):
                        continue
                    if not smtp.host:
                        log.warning(
                            "Digest sender: SMTP not configured; "
                            "skipping",
                            account_id=acct_id,
                            digest_id=dcfg.id,
                        )
                        continue

                    try:
                        await _fire_one_digest(
                            db=db, secrets=secrets, smtp=smtp,
                            acct=acct, dcfg=dcfg, hipaa=hipaa,
                            now_utc=now_utc, last_sent=last_sent,
                            to_addr=to_addr,
                            config=app.state.config,
                        )
                    except Exception as e:
                        # Per-digest isolation: scheduler must keep
                        # going even when one digest fails. Log +
                        # continue to the next digest on this
                        # account, then to the next account.
                        log.error(
                            "Digest fire failed",
                            account_id=acct_id, digest_id=dcfg.id,
                            error=fmt_exc(e),
                        )

        except asyncio.CancelledError:
            log.info("Recipient digest sender cancelled")
            return
        except Exception as e:
            log.error(
                "Recipient digest sender error", error=fmt_exc(e),
            )

        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            log.info("Recipient digest sender cancelled")
            return


def _maybe_mark_auth_stale(db, acct: dict, err: Exception) -> None:
    """Detect OAuth refresh-token death and persist a per-account flag.

    Triggered by any provider exception whose message matches the
    Google "Token has been expired or revoked" / "invalid_grant"
    signatures or the IMAP / Graph "AUTHENTICATIONFAILED" /
    "InvalidAuthenticationToken" patterns. Cleared from the same
    setting key on the next successful provider call (see the success
    paths in the watcher loops).
    """
    try:
        msg = str(err) or ""
    except Exception:
        return
    needles = (
        "Token has been expired or revoked",
        "invalid_grant",
        "AUTHENTICATIONFAILED",
        "InvalidAuthenticationToken",
        "Invalid Credentials",
    )
    if not any(n in msg for n in needles):
        return
    try:
        from email_triage.web.db import set_setting
        from datetime import datetime, timezone
        set_setting(db, _settings_keys.auth_stale(acct["id"]), {
            "at": datetime.now(timezone.utc).isoformat(),
            "reason": msg[:300],
        })
        log.warning(
            "Account auth flagged stale — re-authentication required",
            **_acct_log_extras(acct), reason=msg[:200],
        )
    except Exception:
        pass


def _clear_auth_stale(db, account_id: int) -> None:
    """Clear the stale-auth flag on a successful provider call."""
    try:
        # Use the public helper so the in-process settings cache
        # (#140.2) is invalidated alongside the DB delete.
        from email_triage.web.db import delete_setting
        delete_setting(db, _settings_keys.auth_stale(account_id))
    except Exception:
        pass


async def _hipaa_boundary_drift_detector(app: FastAPI) -> None:
    """Periodically reconcile is_hipaa_mode() with the last
    ``hipaa_boundary_events`` row.

    PR 9 / D3. Catches the gap where a direct DB edit of the system
    HIPAA flag bypasses the audit row that ``/config/save`` would
    have written. Every 10 minutes, checks the current effective
    flag against the last recorded direction; on mismatch, appends a
    new boundary event with ``actor_id=None`` and ``reason="auto-
    detected"`` so the audit trail is never missing a transition.

    Idempotent: if the recorded direction already matches, no row is
    appended.
    """
    from email_triage.triage_logging import is_hipaa_mode
    from email_triage.web.db import (
        latest_hipaa_boundary, record_hipaa_boundary,
    )

    SWEEP_INTERVAL_SECONDS = 10 * 60
    await asyncio.sleep(15)
    log.info("HIPAA boundary drift detector started")

    while True:
        try:
            db = app.state.db
            current_on = bool(is_hipaa_mode())
            current_direction = "on" if current_on else "off"
            latest = latest_hipaa_boundary(db, "system")
            recorded_direction = (
                latest.get("direction") if latest else "off"
            )
            if recorded_direction != current_direction:
                record_hipaa_boundary(
                    db,
                    scope="system",
                    direction=current_direction,
                    actor_id=None,
                    reason="auto-detected drift",
                )
                log.warning(
                    "HIPAA system flag drifted from audit trail; "
                    "appended auto-detected boundary",
                    expected=recorded_direction,
                    found=current_direction,
                )
        except Exception as e:
            log.error(
                "HIPAA boundary drift detector raised",
                exc_info=e,
            )
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


async def _log_entries_prune_loop(app: FastAPI) -> None:
    """Periodically trim ``log_entries`` by age + row count.

    Cadence mirrors the watch renewer (every 30 min) — frequent enough
    that a log storm can't grow the table unchecked, but cheap: one
    DELETE against an indexed primary key.
    """
    await asyncio.sleep(30)
    log.info("log_entries pruner started")

    SWEEP_INTERVAL_SECONDS = 30 * 60  # every 30 minutes

    while True:
        try:
            db = app.state.db
            cfg = app.state.config
            from email_triage.web.db import prune_log_entries_by_age_and_count
            deleted = prune_log_entries_by_age_and_count(
                db,
                retention_days=cfg.logging.retention_days,
                max_rows=cfg.logging.max_rows,
            )
            if deleted:
                log.info(
                    "Pruned log_entries",
                    deleted=deleted,
                    retention_days=cfg.logging.retention_days,
                    max_rows=cfg.logging.max_rows,
                )
            # Loop-prevention dedup table: trim rows older than 90d.
            # 90d is far past any plausible cascade window (real
            # cascades re-fire within seconds) but bounded so the
            # table can't grow unbounded across years.
            from email_triage.web.db import prune_triaged_messages
            try:
                tr_deleted = prune_triaged_messages(db, retention_days=90)
                if tr_deleted:
                    log.info("Pruned triaged_messages dedup rows",
                             deleted=tr_deleted, retention_days=90)
            except Exception as e2:
                log.warning("triaged_messages prune failed", error=str(e2))
            # #166 — push-delivery counter table: trim rows older
            # than 90d. Mirrors the log-retention posture. /admin/stats
            # only renders a rolling 14-day window so 90d is generous
            # for ad-hoc operator inspection across the most-recent
            # quarter; tighter retention is a future setting.
            from email_triage.web.db import prune_push_deliveries
            try:
                pd_deleted = prune_push_deliveries(db, keep_days=90)
                if pd_deleted:
                    log.info("Pruned push_deliveries counter rows",
                             deleted=pd_deleted, keep_days=90)
            except Exception as e3:
                log.warning("push_deliveries prune failed", error=str(e3))
        except asyncio.CancelledError:
            log.info("log_entries pruner cancelled")
            return
        except Exception as e:
            log.error("log_entries prune sweep failed", error=fmt_exc(e))

        try:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            log.info("log_entries pruner cancelled")
            return


async def _triage_retry_worker(app: FastAPI) -> None:
    """Drain ``triage_retry_queue`` rows whose ``next_attempt_at`` has
    elapsed (#149 Bundle A).

    Tick cadence: every 30 s. Each tick:

    1. If the LLM backend is still flagged unhealthy (Bundle B), skip
       this tick — fetching + re-running classify when the breaker is
       open just burns connection-attempt latency.
    2. Otherwise pull up to 10 ready rows. For each row: re-fetch the
       message via the original provider, re-run the triage path. On
       success → :func:`mark_succeeded`. On failure → bump the attempt
       counter via :func:`enqueue` (which extends the backoff). When
       attempt_count reaches the cap → :func:`mark_terminal_failure`
       drops the row + emits an ERROR.

    Worker is intentionally simple. No concurrency: 10 rows / 30 s
    is plenty for a backlog of ~1k messages over a 50-min outage. If
    the install needs higher throughput, raise the per-tick limit.

    The worker re-uses :func:`run_triage` so the full triage
    pipeline (classify + route + act) fires. That's the contract: a
    queued row resumes where it left off, not just at the classify
    step.
    """
    await asyncio.sleep(30)  # let the supervisor finish boot burst
    log.info("Triage retry worker started")

    TICK_INTERVAL_SECONDS = 30
    PER_TICK_LIMIT = 10

    from email_triage.web.triage_retry_queue import (
        DEFAULT_MAX_ATTEMPTS, dequeue_ready, enqueue as _q_enqueue,
        mark_succeeded, mark_terminal_failure,
    )
    from email_triage.llm_health import is_healthy

    while True:
        try:
            db = app.state.db

            # First pass — drain any rows that have already burned
            # through the attempt cap. mark_terminal_failure deletes
            # them with an ERROR log; without this sweep they'd sit
            # forever tripping nothing because dequeue_ready filters
            # them out by the same WHERE clause.
            try:
                cap_rows = db.execute(
                    "SELECT id FROM triage_retry_queue "
                    "WHERE attempt_count >= ?",
                    (int(DEFAULT_MAX_ATTEMPTS),),
                ).fetchall()
                for cr in cap_rows:
                    cr_id = cr["id"] if hasattr(cr, "keys") else cr[0]
                    mark_terminal_failure(
                        db, int(cr_id),
                        reason="max_attempts_exhausted",
                    )
            except Exception as exc:
                log.warning(
                    "Triage retry worker: terminal-failure sweep raised",
                    error=fmt_exc(exc),
                )

            # Bundle B short-circuit: LLM still down → skip this tick.
            if not is_healthy("ollama"):
                # Calm signal — the per-failure log already fired
                # when the breaker tripped. Debug-level keeps the
                # log-volume sane during a long outage.
                log.debug(
                    "Triage retry worker: LLM backend still unhealthy, "
                    "skipping tick"
                )
            else:
                rows = dequeue_ready(db, limit=PER_TICK_LIMIT)
                for row in rows:
                    # Resume one row. The DB-bound row carries
                    # account_id + message_id (+ mailbox, uid for
                    # IMAP). Re-fetch via the same provider that
                    # originally surfaced the message.
                    queue_id = int(row.get("id") or 0)
                    account_id = int(row.get("account_id") or 0)
                    message_id = str(row.get("message_id") or "")
                    if not queue_id or not account_id or not message_id:
                        # Defensive: a malformed row would otherwise
                        # block the queue forever. Drop with WARNING.
                        log.warning(
                            "Triage retry worker: dropping malformed row",
                            queue_id=queue_id, row=row,
                        )
                        try:
                            mark_succeeded(db, queue_id)
                        except Exception:
                            pass
                        continue

                    try:
                        # Re-run the full triage path for this single
                        # message via the existing triage_runner.
                        # ``run_triage`` accepts an explicit
                        # message_id list when given a custom query;
                        # we use the in-house resume helper.
                        await _retry_one_message(app, row)
                        mark_succeeded(db, queue_id)
                        log.info(
                            "Triage retry worker: message reclassified",
                            account_id=account_id,
                            message_id=message_id,
                        )
                    except Exception as exc:
                        # Re-bump and let the backoff schedule push
                        # the next attempt out. enqueue() UPDATEs the
                        # existing row when (account_id, message_id)
                        # already exists.
                        try:
                            updated = _q_enqueue(
                                db,
                                message_id=message_id,
                                account_id=account_id,
                                mailbox=row.get("mailbox"),
                                uid=row.get("uid"),
                                error=exc,
                            )
                            log.info(
                                "Triage retry worker: retry failed, "
                                "scheduled next attempt",
                                queue_id=queue_id,
                                account_id=account_id,
                                attempt=updated.get("attempt_count"),
                                next_at=updated.get("next_attempt_at"),
                                error=fmt_exc(exc),
                            )
                        except Exception as enq_exc:
                            log.error(
                                "Triage retry worker: re-enqueue failed",
                                queue_id=queue_id, error=fmt_exc(enq_exc),
                            )
        except asyncio.CancelledError:
            log.info("Triage retry worker cancelled")
            return
        except Exception as e:
            log.error(
                "Triage retry worker tick raised",
                error=fmt_exc(e),
            )

        try:
            await asyncio.sleep(TICK_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            log.info("Triage retry worker cancelled")
            return


async def _retry_one_message(app: FastAPI, row: dict) -> None:
    """Re-run triage on one queued message.

    Lightweight wrapper around the existing watcher / push-consumer
    triage path — fetch the message via the account's provider,
    classify, run actions. We piggyback on the manual triage
    subset: provider + classifier + routes; keep the surface
    minimal to avoid duplicating the full watcher state machine.

    Raises on any failure; caller (``_triage_retry_worker``) is
    responsible for re-enqueueing on exception.
    """
    from email_triage.web.db import get_email_account
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db,
    )

    db = app.state.db
    secrets = app.state.secrets
    config = app.state.config

    account_id = int(row["account_id"])
    message_id = str(row["message_id"])

    acct = get_email_account(db, account_id)
    if acct is None:
        # Account deleted while the row sat in the queue. Treat as
        # success (drop the row) — there's no recoverable work left.
        log.info(
            "Triage retry worker: account deleted, dropping queue row",
            account_id=account_id,
            message_id=message_id,
        )
        return

    provider = _create_provider_from_account(acct, secrets)
    try:
        message = await provider.fetch_message(message_id)
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    classifier = _build_classifier_from_config(config)
    categories = _get_categories_from_db(db, user_id=acct.get("user_id"))
    classification = await classifier.classify(message, categories, None)

    log.info(
        "Triage retry: reclassified",
        account_id=account_id,
        account_name=acct.get("name"),
        owner=acct.get("owner_name") or acct.get("owner_email"),
        message_id=message_id,
        category=classification.category,
        confidence=classification.confidence,
    )


async def _sent_mail_capture_loop(app: FastAPI) -> None:
    """Background task that scans Sent folders for AI-drafted-then-edited
    pairs (M-6 edit-feedback capture loop).

    Cron-anchored: ticks every ``style_learning.capture_interval_hours``
    hours (default 6), aligned to wall-clock multiples of that interval
    plus 0-300s of random jitter so a 50-install fleet doesn't slam
    Sent folders at the same instant.

    Per-account gates (each independently checked):
      * Account is active (``is_active=True``)
      * Account opted into M-4 RAG via the ``rag_sent_index_enabled``
        per-account toggle (M-6 piggybacks on M-4's opt-in -- captured
        pairs flow into the same store M-4 retrieves from)
      * Account is NOT HIPAA-flagged (defence in depth: the
        :class:`SentMailCaptureLoop` re-checks this at every public
        method)
      * The install-wide style-learning master toggle is on
      * An embedding backend is wired on ``app.state`` (no backend ⇒
        no captures; the underlying :class:`SentMailIndex` would
        refuse the construction anyway)

    Audit row: each scan attempt writes an ``auth_events`` row with
    ``event_type="sent_mail_capture"`` + ``outcome="success"`` /
    ``"failure"`` plus a ``count=N`` detail. This is operational
    metadata (was the capture loop healthy?), NOT PHI access -- it
    runs only on non-HIPAA accounts by gate, and the row carries no
    message content.
    """
    await asyncio.sleep(60)  # let other tasks settle past the boot burst
    log.info("Sent mail capture loop started")

    while True:
        try:
            await _run_sent_mail_capture_sweep(app)
        except asyncio.CancelledError:
            log.info("Sent mail capture loop cancelled")
            return
        except Exception as e:
            log.error(
                "Sent mail capture sweep failed",
                error=fmt_exc(e),
            )

        # Sleep until the next interval boundary + jitter.
        try:
            await asyncio.sleep(
                _seconds_until_next_capture_tick(app),
            )
        except asyncio.CancelledError:
            log.info("Sent mail capture loop cancelled")
            return


_SENT_MAIL_CAPTURE_DEFAULT_HOURS = 6
_SENT_MAIL_CAPTURE_JITTER_SECONDS = 300  # 0..5 minutes


def _resolve_capture_interval_hours(app: FastAPI) -> int:
    """Read the configured capture interval (hours).

    Thin shim around
    :func:`email_triage.web.db.get_style_learning_capture_interval_hours`
    so the loop + the /config save handler + the
    /profile/style-data banner all share one source of truth +
    one clamp policy. Local exception swallow keeps the loop's
    sleep helper resilient if the DB hop hiccups (returns the
    default in that case).
    """
    try:
        from email_triage.web.db import (
            get_style_learning_capture_interval_hours,
        )
        return get_style_learning_capture_interval_hours(app.state.db)
    except Exception:
        return _SENT_MAIL_CAPTURE_DEFAULT_HOURS


def _seconds_until_next_capture_tick(
    app: FastAPI, *, now: datetime | None = None,
) -> float:
    """Seconds until the next wall-clock capture-interval boundary +
    random jitter.

    Boundaries are at multiples of the interval hours from UTC midnight
    (e.g. interval=6h ⇒ 00:00, 06:00, 12:00, 18:00 UTC). Pure helper so
    tests can pass ``now`` for determinism.
    """
    import random
    interval_hours = _resolve_capture_interval_hours(app)
    if now is None:
        now = datetime.now(timezone.utc)
    interval_secs = interval_hours * 3600
    seconds_since_midnight = (
        now - now.replace(hour=0, minute=0, second=0, microsecond=0)
    ).total_seconds()
    next_boundary_offset = (
        (int(seconds_since_midnight) // interval_secs + 1) * interval_secs
    )
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    next_tick = midnight + timedelta(seconds=next_boundary_offset)
    seconds = (next_tick - now).total_seconds()
    seconds += random.uniform(0, _SENT_MAIL_CAPTURE_JITTER_SECONDS)
    return max(seconds, 1.0)


async def _run_sent_mail_capture_sweep(app: FastAPI) -> dict[str, int]:
    """Run one M-6 sweep across every opted-in non-HIPAA account.

    Pure async function so tests can drive it directly without
    waiting on the cron loop. Returns counters for observability:
    ``{"considered", "captured_total", "skipped_hipaa", "skipped_disabled",
    "skipped_no_backend", "errors"}``.
    """
    from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
    from email_triage.actions.sent_mail_index import (
        NonLocalBackendError, SentMailIndex,
    )
    from email_triage.triage_logging import is_account_hipaa
    from email_triage.web.db import (
        is_rag_sent_index_enabled,
        is_style_learning_master_enabled,
        list_email_accounts,
        record_auth_event,
    )

    db = app.state.db
    secrets = app.state.secrets

    counters = {
        "considered": 0,
        "captured_total": 0,
        "skipped_hipaa": 0,
        "skipped_disabled": 0,
        "skipped_no_backend": 0,
        "skipped_auto_scan_off": 0,
        "errors": 0,
    }

    # Master toggle: install-wide off ⇒ no work.
    try:
        if not is_style_learning_master_enabled(db):
            return counters
    except Exception:
        return counters

    # Embedding backend wired? Without it the SentMailIndex
    # construction would refuse anyway.
    backend = getattr(app.state, "embedding_backend", None)
    if backend is None:
        counters["skipped_no_backend"] = 1
        return counters
    embedding_model = getattr(app.state, "embedding_model", "") or ""
    sqlite_vec_available = bool(
        getattr(app.state, "sqlite_vec_available", False)
    )

    # #161 item 2 — per-account "auto-scan on schedule" toggle. When
    # OFF the loop SKIPS this account; only the operator-driven
    # "Mine the Sent Items Now" button on /profile/style-data fires
    # for that mailbox. HIPAA-flagged accounts default OFF
    # (opt-in-everywhere posture); non-HIPAA default ON.
    from email_triage.web.db import is_auto_scan_enabled_for_account

    accounts = list_email_accounts(db)
    for acct in accounts:
        counters["considered"] += 1
        if not acct.get("is_active", True):
            counters["skipped_disabled"] += 1
            continue
        if is_account_hipaa(acct):
            counters["skipped_hipaa"] += 1
            continue
        if not is_auto_scan_enabled_for_account(acct):
            counters["skipped_auto_scan_off"] += 1
            log.info(
                "Sent mail capture: auto-scan off for account",
                account_id=acct.get("id"),
                reason="auto_scan_enabled=false",
            )
            continue
        try:
            if not is_rag_sent_index_enabled(db, acct["id"], account=acct):
                continue
        except Exception:
            continue

        account_email = acct.get("email_address") or ""
        try:
            from email_triage.web.routers.ui import (
                _create_provider_from_account,
            )
            provider = _create_provider_from_account(acct, secrets)
        except Exception as e:
            counters["errors"] += 1
            log.warning(
                "Sent mail capture: provider build failed",
                account_id=acct.get("id"),
                error=fmt_exc(e),
            )
            try:
                record_auth_event(
                    db,
                    event_type="sent_mail_capture",
                    email=account_email,
                    outcome="failure",
                    detail=f"provider_build: {fmt_exc(e)[:200]}",
                )
            except Exception:
                pass
            continue

        # 2026-05-11 — per-account sent-folder override (set via
        # /profile/style-data). Now a list[str] (one or more folders
        # the operator wants the AI to fan learning across) — empty
        # list falls through to the provider's default Sent path
        # (Gmail in:sent, O365 sentitems, IMAP whatever folder the
        # watcher SELECTed). Legacy scalar string shape is tolerated
        # via ``normalize_sent_folder_override`` even on installs that
        # haven't run migration v19 yet.
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        _acct_cfg = acct.get("config") or {}
        _sent_overrides = normalize_sent_folder_override(
            _acct_cfg.get("sent_folder_override"),
        )

        try:
            try:
                index = SentMailIndex(
                    db, acct["id"],
                    embedding_backend=backend,
                    embedding_model=embedding_model,
                    provider=provider,
                    sqlite_vec_available=sqlite_vec_available,
                    sent_folders=_sent_overrides,
                )
            except NonLocalBackendError:
                # Operator switched to a non-local embedding backend
                # mid-flight. Defence in depth: silently skip; M-4 is
                # local-only by design.
                counters["skipped_no_backend"] += 1
                continue

            loop = SentMailCaptureLoop(
                db, acct["id"],
                provider=provider,
                sent_mail_index=index,
                sent_folders=_sent_overrides,
            )
            try:
                captured = await loop.scan_recent(limit=50)
            except Exception as scan_err:
                counters["errors"] += 1
                err_text = fmt_exc(scan_err)
                log.warning(
                    "Sent mail capture: scan failed",
                    account_id=acct.get("id"),
                    error=err_text,
                )
                try:
                    record_auth_event(
                        db,
                        event_type="sent_mail_capture",
                        email=account_email,
                        outcome="failure",
                        detail=err_text[:400],
                    )
                except Exception:
                    pass
                continue

            counters["captured_total"] += int(captured or 0)
            try:
                record_auth_event(
                    db,
                    event_type="sent_mail_capture",
                    email=account_email,
                    outcome="success",
                    detail=f"count={int(captured or 0)}",
                )
            except Exception:
                pass
            log.info(
                "Sent mail capture sweep complete for account",
                account_id=acct.get("id"),
                captured=int(captured or 0),
            )
        finally:
            try:
                await provider.close()
            except Exception:
                pass

    return counters


async def _process_office365_push_item(app: FastAPI, item: dict) -> None:
    """Reconcile one Microsoft Graph subscription notification (#53).

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
    from email_triage.web.db import (
        get_email_account, get_o365_subscription, list_account_routes,
        record_triage_run, update_o365_subscription_delta_link,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _collect_list_hints_for_message,
    )
    from email_triage.providers.office365 import (
        Office365Provider, GraphDeltaResyncRequiredError, GraphError,
    )
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.engine.models import FlowState, FlowStatus
    from email_triage.triage_logging import is_account_hipaa

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    account_id = item.get("account_id")
    if not account_id:
        return

    acct = get_email_account(db, account_id)
    if acct is None:
        log.warning(
            "Office365 push consumer: account missing",
            account_id=account_id,
        )
        return

    # Fail-closed: skip push processing for accounts whose owner is
    # disabled. Don't advance the cursor either — re-enable should
    # see the backlog.
    from email_triage.web.db import is_user_disabled as _iud
    owner_id = acct.get("user_id")
    if owner_id is not None and _iud(db, owner_id):
        log.warning(
            "Office365 push consumer: skipping (owner disabled)",
            account_id=account_id, owner_id=owner_id,
        )
        return

    sub_row = get_o365_subscription(db, account_id)
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
        try:
            message_ids, next_delta_link = await provider.poll_delta(
                stored_delta_link or None,
            )
        except GraphDeltaResyncRequiredError:
            log.warning(
                "Office365 push consumer: delta cursor expired, "
                "recovering via bounded backfill",
                **_acct_log_extras(acct),
            )
            message_ids = await provider.search("ALL", limit=200)
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

        if not message_ids:
            log.info(
                "Office365 push consumer: empty delta",
                **_acct_log_extras(acct),
            )
            if next_delta_link:
                update_o365_subscription_delta_link(
                    db, account_id=account_id,
                    delta_link=next_delta_link,
                )
            return

        classifier = _build_classifier_from_config(config)
        categories = _get_categories_from_db(
            db, user_id=acct.get("user_id"),
        )
        # O365 push delivers without a per-mailbox concept; passing
        # mailbox=None yields the account-wide route map.
        from email_triage.web.db import effective_routes_by_cat
        routes_by_cat = effective_routes_by_cat(
            db, account_id, mailbox=None,
        )

        from email_triage.actions.invite import (
            AcceptInviteAction, DeclineInviteAction, TentativeInviteAction,
        )
        from email_triage.actions.suggest_meeting_times import (
            SuggestMeetingTimesAction,
        )
        registry = ActionRegistry()
        registry.register(MoveAction())
        registry.register(LabelAction())
        registry.register(NotifyAction())
        registry.register(DraftReplyAction())
        registry.register(AcceptInviteAction())
        registry.register(DeclineInviteAction())
        registry.register(TentativeInviteAction())
        registry.register(SuggestMeetingTimesAction())

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
        try:
            if _ice_eff(db, acct):
                _cal_provider = _ccp(acct, secrets, db=db)
            _mp = _gmp(db, acct.get("user_id"))
        except Exception:
            _mp = None
        _self_email = acct.get("email_address", "")

        results: list[dict] = []
        errors: list[dict] = []
        from email_triage.mail_headers import (
            get_triage_header as _gth, get_rfc_message_id as _grfc,
        )
        from email_triage.web.db import is_triaged, mark_triaged
        for mid in message_ids:
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
                message.hipaa = is_account_hipaa(acct)
                _et_header = _gth(message.headers)
                if _et_header:
                    log.info(
                        "Skipping re-triage of email-triage-generated "
                        "message",
                        message_id=mid,
                        x_email_triage=_et_header,
                    )
                    results.append({
                        "message_id": mid,
                        "status": "skipped",
                        "reason": "x-email-triage header present",
                    })
                    continue
                _rfc_id = _grfc(message.headers)
                if _rfc_id and is_triaged(db, account_id, _rfc_id):
                    log.info(
                        "Skipping already-triaged message "
                        "(rfc_id dedup)",
                        message_id=mid,
                    )
                    continue
                hints = _collect_list_hints_for_message(db, message)
                classification = await classifier.classify(
                    message, categories, hints or None,
                )
                actions_taken: list[dict] = []
                _o365_action_defs = routes_by_cat.get(
                    classification.category, [],
                )
                # 2026-05-13 — meeting-request intercept auto-inject.
                # See actions/suggest_meeting_times.py:inject_meeting_intercept.
                try:
                    from email_triage.web.db import (
                        get_meeting_prefs as _gmp_o,
                    )
                    from email_triage.web.calendars import (
                        is_calendar_effectively_enabled as _ice_o_eff,
                    )
                    from email_triage.actions.suggest_meeting_times import (
                        inject_meeting_intercept as _inject_o,
                    )
                    _o365_action_defs = _inject_o(
                        _o365_action_defs, classification.category,
                        calendar_wired=bool(_ice_o_eff(db, acct)),
                        has_meeting_prefs=bool(_gmp_o(db, acct.get("user_id"))),
                    )
                except Exception:
                    pass
                for action_def in _o365_action_defs:
                    action_name = action_def.get("action", "")
                    action_config = action_def.get("config", {})
                    action = registry.get(action_name)
                    if action is None:
                        continue
                    flow = FlowState(
                        flow_id=FlowState.new_id(),
                        message_id=mid,
                        provider=acct["provider_type"],
                        status=FlowStatus.ACTING,
                        state_bag={
                            "calendar_provider": _cal_provider,
                            "meeting_prefs": _mp,
                            "self_email": _self_email,
                            "account_id": account_id,
                            "account_name": acct.get("name", ""),
                            "owner": (
                                acct.get("owner_name")
                                or acct.get("owner_email", "")
                            ),
                            "smtp_config": app.state.config.smtp,
                            "secrets": app.state.secrets,
                        },
                    )
                    output = await action.execute(
                        flow, message, classification, provider,
                        action_config,
                    )
                    actions_taken.append({
                        "name": action_name,
                        "result": output.result.value,
                        "data": output.data,
                        "error": output.error,
                    })
                if _rfc_id:
                    mark_triaged(db, account_id, _rfc_id)
                # HIPAA redaction parity with Gmail push consumer.
                from email_triage.triage_logging import (
                    is_account_hipaa as _iah, is_hipaa_mode,
                )
                _acct_hipaa = is_hipaa_mode() or _iah(acct)
                _entry = {
                    "message_id": mid,
                    "category": classification.category,
                    "confidence": classification.confidence,
                    "source": classification.source,
                    "actions": actions_taken,
                    "status": "ok",
                }
                if not _acct_hipaa:
                    _entry["sender"] = message.sender
                    _entry["subject"] = message.subject
                _entry["reason"] = (
                    "[redacted]" if _acct_hipaa
                    else classification.reason
                )
                try:
                    _entry["date"] = (
                        message.date.isoformat()
                        if getattr(message, "date", None) else ""
                    )
                except Exception:
                    _entry["date"] = ""
                results.append(_entry)
            except Exception as e:
                errors.append({"message_id": mid, "error": fmt_exc(e)})
                log.error(
                    "Office365 push consumer: per-message error",
                    **_acct_log_extras(acct),
                    message_id=mid, error=fmt_exc(e),
                )
                # #175 R-B — durable per-message retry queue.
                # O365 push site: pass the Graph resource id as the
                # addressing tuple. Auth-revoked → enqueue + dead.
                try:
                    from email_triage.web.watcher_retry import (
                        enqueue_watcher_retry as _wr_enqueue_o,
                    )
                    _wr_enqueue_o(
                        app.state.db,
                        account_id=int(account_id),
                        provider_type=acct.get(
                            "provider_type", "office365",
                        ),
                        o365_msg_id=str(mid),
                        error=e,
                    )
                except Exception:
                    pass

        elapsed = time.time() - t0
        run_id = f"o365_push_{account_id}_{int(time.time())}"
        try:
            record_triage_run(
                db,
                account_id=account_id,
                account_name=acct.get("name", ""),
                query="office365_push",
                total_messages=len(message_ids),
                results=results,
                errors=errors,
                elapsed_secs=elapsed,
            )
        except Exception:
            pass

        # Outbound webhook (HIPAA + quiet-hours gated). Same shape
        # as the Gmail push path so external integrations don't have
        # to special-case provider.
        dispatcher = getattr(app.state, "event_dispatcher", None)
        if dispatcher is not None:
            from email_triage.web.events import fire_triage_completed
            try:
                await fire_triage_completed(
                    dispatcher, db, config, acct,
                    {
                        "run_id": run_id,
                        "query": "office365_push",
                        "total_messages": len(message_ids),
                        "results": results,
                        "errors": errors,
                        "elapsed_secs": elapsed,
                    },
                    trigger="push",
                )
            except Exception as _e:
                log.warning(
                    "o365 push: triage.completed dispatch failed",
                    error=str(_e),
                )

        # Advance cursor only after the whole delta processed —
        # mid-delta crash means the next webhook re-walks the same
        # range, the dedup table catches messages we already acted on.
        if next_delta_link:
            update_o365_subscription_delta_link(
                db, account_id=account_id,
                delta_link=next_delta_link,
            )

        log.info(
            "Office365 push consumer: processed delta",
            **_acct_log_extras(acct),
            messages=len(message_ids),
            errors=len(errors),
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


async def _gmail_watch_renewer(app: FastAPI) -> None:
    """Periodically re-register Gmail watches approaching expiry.

    Gmail watches expire after ~7 days.  We renew anything expiring in
    the next 48 hours.  Re-registering is idempotent — Gmail treats it
    as extending the existing watch and returns a fresh expiration.
    """
    await asyncio.sleep(30)
    log.info("Gmail watch renewer started")

    RENEW_WINDOW_HOURS = 48
    SWEEP_INTERVAL_SECONDS = 30 * 60  # every 30 minutes

    while True:
        try:
            await _run_watch_renewal_sweep(app, window_hours=RENEW_WINDOW_HOURS)
        except asyncio.CancelledError:
            log.info("Gmail watch renewer cancelled")
            return
        except Exception as e:
            log.error("Watch renewer sweep failed", error=fmt_exc(e))

        try:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            log.info("Gmail watch renewer cancelled")
            return


async def _run_watch_renewal_sweep(app: FastAPI, *, window_hours: int = 48) -> None:
    """Renew any Gmail watches expiring within ``window_hours`` hours.

    Factored out for direct testability — tests can invoke this
    function without driving the sleep loop of ``_gmail_watch_renewer``.
    """
    from datetime import timedelta
    from email_triage.web.db import (
        list_gmail_watches_expiring, upsert_gmail_watch, get_email_account,
    )
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account

    db = app.state.db
    config = app.state.config
    secrets = app.state.secrets

    now = datetime.now(timezone.utc)
    horizon = (now + timedelta(hours=window_hours)).isoformat()
    expiring = list_gmail_watches_expiring(db, horizon)

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
        acct = get_email_account(db, acct_id)
        if acct is None:
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
            exp_ms = int(data.get("expiration", 0))
            exp_iso = datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc).isoformat() \
                if exp_ms else (now + timedelta(days=7)).isoformat()
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
            upsert_gmail_watch(
                db,
                account_id=acct_id,
                email_address=new_email,
                topic_name=topic,
                history_id=str(data.get("historyId") or watch["history_id"]),
                expires_at=exp_iso,
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


# ---------------------------------------------------------------------------
# Unified push + poll ingestion loop
# ---------------------------------------------------------------------------
#
# Every account has two independent knobs (push_enabled + poll_enabled).
# This loop drives the poll arm. It ticks every _POLL_TICK_SECONDS, and
# for each account with ``poll_enabled=True`` checks whether its
# ``poll_interval_minutes`` has elapsed since its last poll — if so,
# dispatches to a provider-specific one-shot polling routine.
#
# Per-account dispatch:
#   * Gmail:  reuse the existing B3 safety-poll path — ``get_profile()``
#             then enqueue onto ``push_queue`` with the LIVE historyId.
#             The consumer's idempotency check (incoming <= stored →
#             skip) makes the no-op case cheap and silent.
#   * IMAP:   open a connection, ``SEARCH UID hwm+1:*``, fetch and
#             triage any new messages, advance the HWM. Empty search
#             result returns immediately — no fetch.
#   * O365:   placeholder (Graph subscriptions not yet wired).
#
# Errors on one account never kill the sweep — each dispatch is wrapped
# in try/except. The per-account last-poll timestamp is stored in the
# settings table keyed ``poll:last:{account_id}`` AND surfaced on the
# WatcherManager so the UI chip can show "last polled Nm ago".

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
    await asyncio.sleep(_POLL_LOOP_START_DELAY_SECONDS)
    log.info("Unified poll loop started")
    while True:
        try:
            await _run_unified_poll_tick(app)
        except asyncio.CancelledError:
            log.info("Unified poll loop cancelled")
            return
        except Exception as e:
            log.error("Unified poll loop tick failed", error=fmt_exc(e))
        try:
            await asyncio.sleep(_POLL_TICK_SECONDS)
        except asyncio.CancelledError:
            log.info("Unified poll loop cancelled")
            return


# Back-compat alias: tests and external callers may still reference the
# old B3 name. Both point to the same coroutine.
_gmail_history_poller = _unified_poll_loop


async def _run_unified_poll_tick(app: FastAPI) -> None:
    """Evaluate every account; fire a provider-specific poll for any
    whose configured interval has elapsed since last poll.

    Extracted from the sleep loop for direct testability.
    """
    from email_triage.web.db import (
        list_email_accounts, disabled_user_ids, get_setting, set_setting,
    )

    db = app.state.db
    config = app.state.config
    ingestion = config.ingestion
    now = datetime.now(timezone.utc)

    watcher_mgr = getattr(app.state, "watcher_manager", None)

    # #134.4 — pre-fetch disabled set once per poll tick.
    accounts_for_poll = list_email_accounts(db)
    _disabled_owners = disabled_user_ids(db)

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
        state = get_setting(db, _poll_state_key(account_id)) or {}
        last_poll_iso = state.get("last_poll_at")
        last_poll = None
        if last_poll_iso:
            try:
                last_poll = datetime.fromisoformat(last_poll_iso)
            except (TypeError, ValueError):
                last_poll = None
        if last_poll is not None:
            elapsed_s = (now - last_poll).total_seconds()
            if elapsed_s < interval_min * 60:
                continue

        # Fire dispatch per provider type. Wrap each account in its own
        # try/except so one account's failure can't abort the sweep.
        # #138 phase 2 — table-driven dispatch via ProviderDispatcher.
        ptype = acct.get("provider_type")
        from email_triage.providers.dispatcher import get_dispatch
        disp = get_dispatch(ptype)
        try:
            if disp is None:
                log.warning(
                    "Unified poll: unknown provider type, skipping",
                    **_acct_log_extras(acct), provider_type=ptype,
                )
            else:
                await disp.poll_once(app, acct)
                if ptype == "office365":
                    log.debug(
                        "O365 poll not yet implemented",
                        **_acct_log_extras(acct),
                    )
            # Successful dispatch — clear any prior stale-auth flag.
            _clear_auth_stale(db, account_id)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning(
                "Unified poll: dispatch failed",
                **_acct_log_extras(acct), provider=ptype, error=fmt_exc(e),
            )
            # Detect Gmail OAuth refresh-token death and persist a
            # stale-auth flag so the UI can surface a re-auth chip
            # and the daily health email can call it out.
            _maybe_mark_auth_stale(db, acct, e)

        # Record the tick regardless of dispatch outcome — a failing
        # provider shouldn't cause every tick to retry it within the
        # interval window (that would amplify a bad cred or network
        # blip into a retry storm).
        state["last_poll_at"] = now.isoformat()
        set_setting(db, _poll_state_key(account_id), state)
        if watcher_mgr is not None:
            try:
                watcher_mgr._mark_poll_tick(account_id, now.isoformat())
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
    from email_triage.web.db import (
        get_gmail_watch, upsert_gmail_watch,
    )
    from email_triage.providers.gmail_api import GmailApiProvider
    from email_triage.web.routers.ui import _create_provider_from_account

    db = app.state.db
    account_id = acct["id"]
    watch = get_gmail_watch(db, account_id)

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
            upsert_gmail_watch(
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
    from email_triage.web.db import (
        _account_mailboxes, get_mailbox_hwm, set_mailbox_hwm,
        list_account_routes, record_triage_run,
    )
    from email_triage.web.routers.ui import (
        _create_provider_from_account, _build_classifier_from_config,
        _get_categories_from_db, _collect_list_hints_for_message,
    )
    from email_triage.actions.move import MoveAction
    from email_triage.actions.label import LabelAction
    from email_triage.actions.notify import NotifyAction
    from email_triage.actions.draft_reply import DraftReplyAction
    from email_triage.actions.registry import ActionRegistry
    from email_triage.engine.models import FlowState, FlowStatus
    from email_triage.triage_logging import is_account_hipaa

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
            hwm_data = get_mailbox_hwm(db, account_id, mb) or {}
            since_uid = int(hwm_data.get("uid", 0))

            try:
                new_messages = await provider.poll_once(mb, since_uid)
            except ProviderTransientError as e:
                # PR 7 / C3 — broken provider, NOT a quiet mailbox.
                # Bump the watcher state so /health surfaces it after
                # 15 min of consecutive failure (matches the C1 plumbing
                # used by IDLE watchers). Do NOT update HWM, do NOT
                # record a triage_run with zero messages.
                wm = getattr(app.state, "watcher_manager", None)
                if wm is not None:
                    wm._mark_failing(account_id, mb, error=fmt_exc(e))
                log.warning(
                    "Unified poll: provider transient error",
                    **_acct_log_extras(acct), mailbox=mb,
                    error=fmt_exc(e),
                )
                continue

            if not new_messages:
                # Cheap no-op case — no new mail. Seed HWM on first poll
                # of a fresh mailbox so subsequent polls don't dump the
                # backlog.
                if since_uid == 0:
                    try:
                        latest = await provider.get_latest_uid()
                        if latest > 0:
                            set_mailbox_hwm(db, account_id, mb, {
                                "uid": int(latest),
                                "updated_at": datetime.now(timezone.utc).isoformat(),
                            })
                    except Exception:
                        pass
                continue

            # Lazy-build the classifier + action registry only once per
            # account (shared across all its mailboxes with new mail).
            if classifier is None:
                classifier = _build_classifier_from_config(config)
                categories = _get_categories_from_db(db, user_id=acct.get("user_id"))
                registry = ActionRegistry()
                registry.register(MoveAction())
                registry.register(LabelAction())
                registry.register(NotifyAction())
                registry.register(DraftReplyAction())

            # #51 — per-mailbox route overrides resolve EACH iteration
            # (cheap dict build) since two mailboxes on the same
            # account can carry different overrides.
            #
            # #145.9 — semantics note for operators chasing "I changed a
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
            routes_by_cat = effective_routes_by_cat(db, account_id, mailbox=mb)
    
            results: list[dict] = []
            errors: list[dict] = []
            max_uid = since_uid
            from email_triage.mail_headers import (
                get_triage_header as _gth, get_rfc_message_id as _grfc,
                is_self_origin as _is_self_origin,
            )
            from email_triage.web.db import is_triaged, mark_triaged
            from email_triage.web.triage_inflight import (
                mark_inflight as _mark_inflight,
                release_inflight as _release_inflight,
            )
            _self_from_addr = getattr(
                getattr(app.state.config, "smtp", None), "from_addr", "",
            )
            for message in new_messages:
                uid = str(message.message_id)
                # In-flight dedup gate (#114).
                if not _mark_inflight(app.state, account_id, uid):
                    log.info(
                        "Skipping concurrent triage cycle (in_flight)",
                        message_id=uid, account_id=account_id, mailbox=mb,
                        skip_reason="in_flight",
                    )
                    continue
                try:
                    try:
                        uid_int = int(uid)
                        if uid_int > max_uid:
                            max_uid = uid_int
                    except (TypeError, ValueError):
                        pass
                    message.hipaa = is_account_hipaa(acct)
                    _et_header = _gth(message.headers)
                    if _et_header:
                        log.info(
                            "Skipping re-triage of email-triage-generated message",
                            message_id=uid,
                            x_email_triage=_et_header,
                            skip_reason="self_origin",
                        )
                        continue
                    # Defense in depth (#117): self-origin sender check.
                    if _is_self_origin(
                        message.sender or "", _self_from_addr,
                    ):
                        log.info(
                            "Skipping self-origin message (header missing)",
                            message_id=uid, mailbox=mb,
                            skip_reason="self_origin",
                        )
                        continue
                    if "$EmailTriaged" in (message.labels or []):
                        log.info(
                            "Skipping already-triaged message (keyword sentinel)",
                            message_id=uid, mailbox=mb,
                        )
                        continue
                    _rfc_id = _grfc(message.headers)
                    if _rfc_id and is_triaged(db, account_id, _rfc_id):
                        log.info(
                            "Skipping already-triaged message (rfc_id dedup)",
                            message_id=uid, mailbox=mb,
                        )
                        continue
                    hints = _collect_list_hints_for_message(db, message)
                    classification = await classifier.classify(
                        message, categories, hints or None,
                    )
                    actions_taken: list[dict] = []
                    _poll_action_defs = (routes_by_cat or {}).get(
                        classification.category, [],
                    )
                    # 2026-05-13 — meeting-request intercept auto-inject.
                    # See actions/suggest_meeting_times.py:inject_meeting_intercept.
                    try:
                        from email_triage.web.db import (
                            get_meeting_prefs as _gmp_p,
                        )
                        from email_triage.web.calendars import (
                            is_calendar_effectively_enabled as _ice_p_eff,
                        )
                        from email_triage.actions.suggest_meeting_times import (
                            inject_meeting_intercept as _inject_p,
                        )
                        _poll_action_defs = _inject_p(
                            _poll_action_defs, classification.category,
                            calendar_wired=bool(_ice_p_eff(db, acct)),
                            has_meeting_prefs=bool(_gmp_p(db, acct.get("user_id"))),
                        )
                    except Exception:
                        pass
                    for action_def in _poll_action_defs:
                        action_name = action_def.get("action", "")
                        action_config = action_def.get("config", {})
                        action = registry.get(action_name)
                        if action is None:
                            continue
                        flow = FlowState(
                            flow_id=FlowState.new_id(),
                            message_id=uid,
                            provider=acct["provider_type"],
                            status=FlowStatus.ACTING,
                            state_bag={
                                "account_id": account_id,
                                "account_name": acct.get("name", ""),
                                "owner": acct.get("owner_name") or acct.get("owner_email", ""),
                                # #73 — SMTP for escalation send.
                                "smtp_config": app.state.config.smtp,
                                "secrets": app.state.secrets,
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
                    if _rfc_id:
                        mark_triaged(db, account_id, _rfc_id)
                    if acct["provider_type"] == "imap":
                        try:
                            await provider.set_keywords(uid, ["$EmailTriaged"])
                        except Exception:
                            pass
                    # HIPAA redaction parity with triage_runner.run_triage.
                    from email_triage.triage_logging import (
                        is_account_hipaa, is_hipaa_mode,
                    )
                    _acct_hipaa = (
                        is_hipaa_mode() or is_account_hipaa(acct)
                    )
                    _entry = {
                        "message_id": uid,
                        "category": classification.category,
                        "confidence": classification.confidence,
                        "source": classification.source,
                        "actions": actions_taken,
                        "status": "ok",
                    }
                    if not _acct_hipaa:
                        _entry["sender"] = message.sender
                        _entry["subject"] = message.subject
                    _entry["reason"] = (
                        "[redacted]" if _acct_hipaa
                        else classification.reason
                    )
                    try:
                        _entry["date"] = (
                            message.date.isoformat()
                            if getattr(message, "date", None) else ""
                        )
                    except Exception:
                        _entry["date"] = ""
                    results.append(_entry)
                except Exception as e:
                    errors.append({"message_id": uid, "error": fmt_exc(e)})
                    log.error(
                        "Unified poll: per-message error",
                        **_acct_log_extras(acct), mailbox=mb,
                        message_id=uid, error=fmt_exc(e),
                    )
                    # #175 R-B — durable per-message retry queue.
                    # Unified poll site: IMAP-shape addressing (mb +
                    # uid). uidvalidity isn't surfaced at this scope;
                    # R-A's helper accepts it as None and the sweeper
                    # re-validates from the live mailbox on retry.
                    try:
                        from email_triage.web.watcher_retry import (
                            enqueue_watcher_retry as _wr_enqueue_p,
                        )
                        _wr_enqueue_p(
                            app.state.db,
                            account_id=int(account_id),
                            provider_type=acct.get(
                                "provider_type", "imap",
                            ),
                            mailbox=mb,
                            uid=str(uid),
                            error=e,
                        )
                    except Exception:
                        pass
                finally:
                    # Release the in-flight slot (#114). Idempotent.
                    _release_inflight(app.state, account_id, uid)

            if max_uid > since_uid:
                set_mailbox_hwm(db, account_id, mb, {
                    "uid": max_uid,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })

            if results or errors:
                try:
                    record_triage_run(
                        db,
                        account_id=account_id,
                        account_name=acct.get("name", ""),
                        query="poll",
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
                    errors=len(errors), new_hwm=max_uid,
                )

        finally:
            if provider is not None:
                try:
                    await provider.close()
                except Exception:
                    pass
