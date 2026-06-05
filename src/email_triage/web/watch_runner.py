"""Watch fire pipeline — match classified mail, run escalate + webhook.

the backlog . Sits between the classifier output and the
route-and-act stage in the triage runner. For every classified
message we fetch the watch list scoped to the account, run the
matcher, and fire the configured actions on each hit.

This module is the single authority on:
    * Which watches apply to a given account (all-scope + per-account
      union, with the HIPAA exclusion on all-scope).
    * What payload shape leaves the box (HIPAA redaction; body always
      omitted regardless of mode).
    * The audit row written to ``access_log`` per fire.

Both UI test buttons and the production triage path go through
:func:`fire_watches_for_message` — keeps the no-PII contract +
audit gate uniform.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from typing import Any

import httpx

from email_triage._errfmt import fmt_exc
from email_triage._http_client import LazyHttpClient
from email_triage.triage_logging import is_account_hipaa, is_hipaa_mode
from email_triage.web.email_watches import (
    EmailWatch,
    hmac_secret_key,
    list_watches,
    matches,
    shape_webhook_payload,
    write_audit_row,
)
from email_triage.web.events import sign_payload

log = logging.getLogger("email_triage.web.watch_runner")


# ---------------------------------------------------------------------------
# Long-lived webhook client
# ---------------------------------------------------------------------------
#
# Watch fires are 1-N matched watches per classified message; each
# previously opened + closed a fresh httpx client (TLS handshake every
# time). A module-level ``LazyHttpClient`` collapses that into a single
# pool. The default 10 s timeout matches the legacy per-call value;
# callers that want a different budget pass it through ``_post_webhook
# (..., timeout=...)`` and the per-request override flows to httpx.
#
# Drained from the FastAPI lifespan shutdown via :func:`aclose_module`.

_WEBHOOK_CLIENT = LazyHttpClient(timeout=10.0)


async def aclose_module() -> None:
    """Drain the module-level webhook client.

    Called from the FastAPI lifespan shutdown so the connection pool
    closes cleanly. Idempotent — safe to call when no fire ever ran.
    """
    await _WEBHOOK_CLIENT.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_notify_email(
    db: sqlite3.Connection, user_id: int | None,
) -> str:
    """Look up ``users.notify_email`` for the account owner.

    Used as the post-#156 fallback when neither the watch nor the
    account carries a notify address. Returns empty string on any
    error or when the user has no profile notify address set.

    Concurrency: this raw read runs inside the triage pipeline,
    which is driven from background loops (IMAP watcher, unified poll,
    push consumers). The shared ``sqlite3`` connection cannot be used
    by two threads at once, so the read is taken under the process-wide
    DB lock to serialise against any request-surface ``db_call`` worker.
    """
    if not user_id:
        return ""
    from email_triage.web.db_writelock import get_write_lock
    try:
        with get_write_lock():
            row = db.execute(
                "SELECT notify_email FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
    except Exception:
        return ""
    if row is None:
        return ""
    try:
        val = row["notify_email"]
    except (IndexError, KeyError):
        val = row[0] if len(row) else None
    return (val or "").strip()


# ---------------------------------------------------------------------------
# Resolver — which watches apply to (account, message)?
# ---------------------------------------------------------------------------


def resolve_watches_for_account(
    db: sqlite3.Connection,
    account: dict,
) -> list[EmailWatch]:
    """Return enabled watches that apply to this account.

    Per-account watches: always included.

    All-accounts watches (account_id NULL): included unless the account
    carries the HIPAA flag. The all-scope sweep is for non-PHI surfaces
    only — operators who need a watch on a HIPAA mailbox set a per-
    account watch with their own opt-in.

    Concurrency: ``list_watches`` issues a raw read on the
    shared ``sqlite3`` connection. This resolver runs inside the triage
    pipeline driven from background loops, so the read is taken under
    the process-wide DB lock to serialise against any request-surface
    ``db_call`` worker thread.
    """
    from email_triage.web.db_writelock import get_write_lock
    with get_write_lock():
        rows = list_watches(
            db,
            account_id=account["id"],
            include_all_accounts=not is_account_hipaa(account),
        )
    return [w for w in rows if w.enabled]


# ---------------------------------------------------------------------------
# Action plumbing
# ---------------------------------------------------------------------------


async def _send_escalate(
    *,
    config,
    secrets,
    notify_email: str,
    sender: str,
    subject: str,
    category: str,
    hipaa: bool,
) -> dict[str, Any]:
    """Fire an escalate-style alert. Mirrors actions/escalate.py shape.

    Standard mode: ``URGENT [<category>]: New email from <sender> —
    "<subject>"`` as the SMTP subject.

    HIPAA mode: ``URGENT [<category>]: New email from <first-name>``.

    Returns a small result dict (``{"ok": bool, "to": str, "mode": str,
    "error": str?}``).
    """
    smtp = config.smtp
    if not smtp.host:
        return {"ok": False, "to": notify_email, "mode": "skipped",
                "error": "smtp_not_configured"}
    if not notify_email:
        return {"ok": False, "to": "", "mode": "skipped",
                "error": "no_notify_email"}

    # Build the alert line. We deliberately re-use the same shape as
    # actions/escalate.py rather than importing its helpers — those
    # helpers operate on EmailMessage objects and the watch path
    # already has clean strings.
    cat = (category or "").strip()
    prefix = f"URGENT [{cat}]" if cat else "URGENT"
    if hipaa:
        # First-name extraction: drop honorifics, take the first
        # meaningful word of the display segment.
        s = (sender or "").strip()
        if "<" in s:
            s = s.split("<")[0].strip().strip('"')
        parts = s.split()
        prefixes = {"dr.", "mr.", "mrs.", "ms.", "prof."}
        first = ""
        for p in parts:
            if p.lower() not in prefixes:
                first = p
                break
        if not first and parts:
            first = parts[0]
        alert = f"{prefix}: New email from {first}"
        mode = "hipaa"
    else:
        # Surface the full sender + subject — SMS gateways concat
        # subject + body so the alert reads as one line.
        alert = (
            f"{prefix}: New email from {sender or 'unknown'} — "
            f"\"{subject or ''}\""
        )
        mode = "standard"

    smtp_password = ""
    if secrets is not None:
        try:
            smtp_password = secrets.get("SMTP_PASSWORD") or ""
        except Exception:
            smtp_password = ""

    try:
        from email_triage.web.smtp_send import send_simple_smtp_email
        # smtplib is blocking — run it off the event loop so a watch
        # escalation send doesn't stall the loop it shares.
        await asyncio.to_thread(
            send_simple_smtp_email,
            smtp_host=smtp.host,
            smtp_port=smtp.port,
            smtp_user=smtp.username,
            smtp_password=smtp_password,
            from_addr=smtp.from_addr,
            to_addr=notify_email,
            subject=alert,
            body="Open your inbox to review.",
            use_tls=smtp.use_tls,
            from_name=smtp.from_name,
            triage_source="watch_escalate",
        )
        return {"ok": True, "to": notify_email, "mode": mode}
    except Exception as e:
        log.warning(
            "watch escalate send failed",
            extra={"to": notify_email, "error": fmt_exc(e)},
        )
        return {"ok": False, "to": notify_email, "mode": mode,
                "error": fmt_exc(e)}


async def _post_webhook(
    *,
    url: str,
    secret: str,
    payload: dict[str, Any],
    timeout: float = 10.0,
) -> dict[str, Any]:
    """POST ``payload`` to ``url`` with HMAC-SHA256 signature header.

    Always returns a result dict; never raises (best-effort, mirrors
    EventDispatcher._deliver).
    """
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Event-Type": "watch.fired",
    }
    if secret:
        headers["X-Signature-256"] = f"sha256={sign_payload(body, secret)}"

    try:
        client = await _WEBHOOK_CLIENT.get()
        # Per-request ``timeout=`` override flows to httpx and lets
        # callers tighten / loosen the budget without standing up a
        # second client. Default 10 s matches the legacy value.
        resp = await client.post(
            url, content=body, headers=headers, timeout=timeout,
        )
        return {
            "url": url,
            "status": resp.status_code,
            "ok": 200 <= resp.status_code < 300,
        }
    except Exception as e:
        log.warning(
            "watch webhook failed",
            extra={"url": url, "error": fmt_exc(e)},
        )
        return {"url": url, "status": 0, "ok": False, "error": fmt_exc(e)}


# ---------------------------------------------------------------------------
# Top-level fire
# ---------------------------------------------------------------------------


async def fire_one_watch(
    *,
    db: sqlite3.Connection,
    config,
    secrets,
    watch: EmailWatch,
    account: dict,
    sender: str,
    subject: str,
    body_text: str = "",
    category: str = "",
    message_id: str = "",
    actor_user_id: int | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Run actions for one matched watch. Writes the audit row.

    Returns a structured result dict with ``escalate`` + ``webhook``
    sub-results so the test-fire UI surface can echo what happened.
    """
    hipaa = is_account_hipaa(account) or is_hipaa_mode()

    escalate_result: dict[str, Any] | None = None
    webhook_result: dict[str, Any] | None = None

    if watch.actions.escalate.enabled:
        # Resolution order:
        #   1. Per-watch override (legacy field, kept for back-compat
        #      with rows saved before the "Send to" box was removed).
        #   2. Per-account notify_email in the account config blob
        #      (older surface — still respected on existing installs).
        #   3. User profile notify_email (users.notify_email) — the
        #      canonical address post-#156. The watch editor no longer
        #      asks for a per-watch destination; everything routes to
        #      the operator's stored profile address.
        # If all three are empty the action no-ops with a logged
        # "no_notify_email" result — visible in the audit row.
        from email_triage.web.db_threadpool import db_call
        #  — _user_notify_email reads the users table on the shared
        # connection; this fires from background watcher/push loops, so
        # dispatch it off the loop thread via db_call. The short-circuit
        # is preserved: the profile lookup runs only when neither the
        # per-watch nor the per-account address resolved.
        notify = (
            (watch.actions.escalate.notify_email or "").strip()
            or (account.get("config") or {}).get("notify_email", "")
        )
        if not notify:
            notify = (
                await db_call(
                    _user_notify_email, db, account.get("user_id"),
                )
                or ""
            )
        if not notify:
            log.info(
                "watch escalate: no notify address resolved",
                extra={
                    "watch_id": watch.watch_id,
                    "account_id": account.get("id"),
                    "user_id": account.get("user_id"),
                },
            )
        escalate_result = await _send_escalate(
            config=config,
            secrets=secrets,
            notify_email=notify,
            sender=sender,
            subject=subject,
            category=category,
            hipaa=hipaa,
        )

    if watch.actions.webhook.enabled and (watch.actions.webhook.url or "").strip():
        # Resolve secret from store; fall back to empty (the receiver
        # can still verify nothing — but the operator should set a
        # secret. We don't refuse to fire; the audit row records the
        # posture).
        secret = ""
        if secrets is not None:
            try:
                secret = secrets.get(hmac_secret_key(watch.watch_id)) or ""
            except Exception:
                secret = ""
        payload = shape_webhook_payload(
            watch,
            sender=sender,
            subject=subject,
            body_text=body_text,
            category=category,
            account_id=account["id"],
            account_name=account.get("name", ""),
            message_id=message_id,
            hipaa=hipaa,
        )
        webhook_result = await _post_webhook(
            url=watch.actions.webhook.url.strip(),
            secret=secret,
            payload=payload,
        )

    redaction = "hipaa_redacted" if hipaa else "standard"
    try:
        #  — write_audit_row writes the shared connection; dispatch
        # off the watcher/push loop thread via db_call.
        from email_triage.web.db_threadpool import db_call
        await db_call(
            write_audit_row,
            db,
            watch=watch,
            account_id=account["id"],
            actor_user_id=actor_user_id,
            message_id=message_id,
            escalate_fired=bool(escalate_result and escalate_result.get("ok")),
            webhook_fired=bool(webhook_result and webhook_result.get("ok")),
            redaction=redaction,
            request_id=request_id,
        )
    except Exception as e:
        log.warning("watch audit row failed", extra={"error": fmt_exc(e)})

    return {
        "watch_id": watch.watch_id,
        "watch_name": watch.name,
        "escalate": escalate_result,
        "webhook": webhook_result,
        "redaction": redaction,
    }


# ---------------------------------------------------------------------------
# Watch-fire idempotency
# ---------------------------------------------------------------------------
#
#  restored ``fire_watches=True`` in the retry drainer
# (``_recover_one_retry_row`` in ``app.py``).  had suppressed it on
# the false premise that watches always fired on the original ingestion
# attempt — false for the dominant LLM-down retry case, where
# ``classify`` raises before the watch-fire stage, so the  retry
# worker is the FIRST time watches fire for that message. Restoring the
# fire fixes a silent-dropped-escalation bug, but without a guard a
# second drainer pass (or a container restart mid-drain) would re-send a
# pager/SMS escalation. The durable ``watch_fire_idempotency`` table
# (created by migration v36, re-keyed on the RFC Message-ID by v37)
# records each watch that has *successfully fired* for a message, so a
# re-run skips it.
#
#  hardened the original  design, which had three bugs:
#
#   * Bug 1 — the record was written UNCONDITIONALLY after the fire, so
#     a watch whose escalation SMTP send FAILED (``_send_escalate``
#     returns ``{ok: False}`` without raising) was still recorded as
#     fired → every retry skipped it and the pager/SMS was permanently
#     dropped. Fix: ``_record_watch_fired`` runs ONLY after a delivered
#     fire — the table is a record of *success*, never of an attempt
#     (``_delivered`` is the gate). A failed fire leaves no row, so it
#     is naturally retryable; nothing has to be "un-recorded".
#   * Bug 2 — the key used the provider message id, which for IMAP is
#     the mailbox-scoped UID (collides across folders / UIDVALIDITY
#     epochs). Fix: key on the RFC 5322 Message-ID — see the v37
#     migration docstring. ``fire_watches_for_message`` accepts an
#     explicit ``idempotency_key`` and the sole production caller
#     (``triage_single_message``) passes the RFC Message-ID.
#   * Bug 3 — check (``_watch_already_fired``) and record
#     (``_record_watch_fired``) straddle the ``await fire_one_watch``
#     with the SMTP / webhook I/O in between; two concurrent runs could
#     both pass the check and both fire (duplicate pager/SMS). Fix: the
#     whole check → fire → record sequence for one
#     ``(account, idempotency_key, watch)`` runs under a per-key
#     ``asyncio.Lock`` (``_watch_fire_lock``). The second runner waits,
#     then re-checks after the first completes and sees the success
#     record — so it skips. Because the durable table records only
#     *successful* fires, if the first runner's fire FAILED it wrote no
#     row, and the second runner correctly re-fires instead of wrongly
#     skipping a never-delivered escalation.
#
# Why an in-process lock and not a durable claim row: a durable
# "claim" makes the absence of a row ambiguous (never-fired vs
# fired-then-failed-and-released) and a release-on-failure can drop a
# live-path escalation (the claim winner fails, the loser already
# skipped — zero fires, and the live path has no retry pass). Keeping
# the table a pure record-of-success removes that ambiguity entirely;
# the only remaining concern is two *concurrent* fires, which are
# always within ONE process (the app is a single container / single
# event loop — the retry drainer and the live ingestion paths share
# it), so a process-local ``asyncio.Lock`` keyed on the message
# identity fully serialises them. Cross-restart idempotency is carried
# by the durable success record, not the lock (a restart kills both
# racers anyway). The separate live-path "a failed fire is never
# retried" gap is tracked as its own the backlog item — out of scope
# here.
#
# The table read/write is dispatched through ``db_call`` so the SQLite
# work runs off the event loop under the process-wide DB lock — the
# watch path runs inside the triage pipeline driven from background
# loops (IMAP watcher, unified poll, push consumers), which share one
# ``sqlite3`` connection with the request-surface ``db_call`` workers
#.


# Per-(account, idempotency_key, watch) async locks serialising the
# check → fire → record sequence. Keyed by the same tuple
# the durable table is keyed on.
#
# Lifecycle is REFCOUNTED, not inferred from lock state. ``_watch_fire
# _refcount`` tracks, per key, how many coroutines currently hold-or-
# want the lock: every ``_get_watch_fire_lock`` increments it, every
# ``_release_watch_fire_lock`` decrements it, and the entry is pruned
# only when the count returns to 0. Both dicts are mutated exclusively
# on the single-threaded event loop, so the count is exact.
#
# Why not infer idleness from ``asyncio.Lock`` state: ``Lock.release()``
# empties ``_waiters`` and wakes the next waiter *synchronously*, but
# that waiter does not actually hold the lock until its task is next
# scheduled. In that window ``locked()`` is False AND ``_waiters`` is
# empty even though a coroutine still needs the lock — a prune in that
# window would drop the entry, and a later coroutine for the same key
# would mint a SECOND lock object, splitting the key across two locks
# and defeating the serialisation (→ a duplicate pager). The refcount
# has no such window: a waiting coroutine has already incremented the
# count before it ever awaits ``acquire()``, so the count is non-zero
# for the entire hold-or-want span. (, hardening from db-sme's
# Option-4 re-review.)
_watch_fire_locks: dict[tuple[Any, str, Any], asyncio.Lock] = {}
_watch_fire_refcount: dict[tuple[Any, str, Any], int] = {}


def _get_watch_fire_lock(
    account_id: Any, idempotency_key: str, watch_id: Any,
) -> asyncio.Lock:
    """Return the shared :class:`asyncio.Lock` for one watch-fire key.

    All coroutines firing the same ``(account, idempotency_key,
    watch)`` get the *same* lock object, so the check → fire → record
    sequence is serialised within the process. Created on first use.

    Increments the key's refcount — the caller MUST pair every call
    with exactly one :func:`_release_watch_fire_lock` (use a
    ``try/finally``). The increment happens here, BEFORE the caller
    awaits ``acquire()``, so a coroutine that is merely *waiting* for
    the lock already counts — closing the prune-race window.
    """
    key = (account_id, idempotency_key, watch_id)
    lock = _watch_fire_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _watch_fire_locks[key] = lock
    _watch_fire_refcount[key] = _watch_fire_refcount.get(key, 0) + 1
    return lock


def _release_watch_fire_lock(
    account_id: Any, idempotency_key: str, watch_id: Any,
) -> None:
    """Drop the key's refcount; prune the lock entry when it hits 0.

    Pairs 1:1 with :func:`_get_watch_fire_lock` (call it in a
    ``finally``). When the refcount returns to 0 — no coroutine holds
    or is waiting on the key — the lock + refcount entries are removed
    so the registry stays bounded to the working set of in-flight /
    contended fires. The count is mutated only on the event loop, so
    "0" is exact: there is no scheduler window in which a coroutine
    still needs the lock yet the count reads 0.
    """
    key = (account_id, idempotency_key, watch_id)
    n = _watch_fire_refcount.get(key, 0) - 1
    if n <= 0:
        _watch_fire_refcount.pop(key, None)
        _watch_fire_locks.pop(key, None)
    else:
        _watch_fire_refcount[key] = n


def _watch_already_fired(
    db: sqlite3.Connection,
    account_id: Any,
    idempotency_key: str,
    watch_id: Any,
) -> bool:
    """True if this watch has already *successfully fired* for this message.

    Reads the durable ``watch_fire_idempotency`` table, which holds a
    row only for a watch that fired and DELIVERED (see
    :func:`_record_watch_fired`). On any error — table missing, DB
    error, or no usable key (empty ``idempotency_key``) — returns False
    (fail-open: let the watch fire). A watch escalation NOT firing is
    the worse outcome, so the guard never suppresses on uncertainty.

    Dispatched through ``db_call`` by the caller — this body is the
    sync DB work.
    """
    if account_id is None or not idempotency_key or watch_id is None:
        return False
    from email_triage.web.db_writelock import get_write_lock
    try:
        with get_write_lock():
            row = db.execute(
                "SELECT 1 FROM watch_fire_idempotency "
                "WHERE account_id=? AND rfc_message_id=? AND watch_id=?",
                (int(account_id), str(idempotency_key), str(watch_id)),
            ).fetchone()
    except Exception as e:
        log.warning(
            "watch-fire idempotency lookup failed; firing",
            extra={"watch_id": watch_id, "error": fmt_exc(e)},
        )
        return False
    return row is not None


def _record_watch_fired(
    db: sqlite3.Connection,
    account_id: Any,
    idempotency_key: str,
    watch_id: Any,
) -> None:
    """Record that this watch has successfully fired for this message.

    ``INSERT OR IGNORE`` into the durable ``watch_fire_idempotency``
    table. Called by :func:`fire_watches_for_message` ONLY after a
    fire that :func:`_delivered` confirms delivered — the table is a
    record of *success*, so a failed fire leaves no row and stays
    retryable.

    A write failure is logged and swallowed: the fire already
    happened, so failing to record only risks a future duplicate,
    never a dropped escalation. Dispatched through ``db_call`` by the
    caller — this body is the sync DB work.
    """
    if account_id is None or not idempotency_key or watch_id is None:
        return
    from datetime import datetime, timezone

    from email_triage.web.db_writelock import get_write_lock
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_write_lock():
            db.execute(
                "INSERT OR IGNORE INTO watch_fire_idempotency "
                "(account_id, rfc_message_id, watch_id, fired_at) "
                "VALUES (?, ?, ?, ?)",
                (int(account_id), str(idempotency_key),
                 str(watch_id), now),
            )
            db.commit()
    except Exception as e:
        log.warning(
            "watch-fire idempotency record failed",
            extra={"watch_id": watch_id, "error": fmt_exc(e)},
        )


def _delivered(result: dict[str, Any]) -> bool:
    """True if a ``fire_one_watch`` result counts as a delivered fire.

    A fire is "delivered" — and so worth recording in the durable
    idempotency table — when every action that was *attempted*
    succeeded. The distinction that matters for  Bug 1:

      * escalate ``ok=True``           → delivered.
      * escalate ``ok=False`` with
        ``mode="skipped"``             → a config no-op (no SMTP relay
        or no notify address). NOT a delivery failure — retrying will
        not fix missing config, so this still counts as delivered and
        is recorded (a re-fire would skip identically).
      * escalate ``ok=False`` with
        ``mode`` in {standard,hipaa}   → a genuine SMTP send failure →
        NOT delivered → not recorded, so a retry re-fires.
      * webhook ``ok=False``           → a genuine POST failure → NOT
        delivered → not recorded.

    A watch with neither action enabled has nothing to deliver; that
    is treated as delivered (a retry would change nothing).
    """
    escalate = result.get("escalate")
    webhook = result.get("webhook")

    # Escalate: a genuine send failure is ok=False AND not a config
    # skip. A skipped escalate (no SMTP / no notify_email) is not a
    # delivery failure — re-firing would skip identically.
    if escalate is not None:
        if not escalate.get("ok") and escalate.get("mode") != "skipped":
            return False

    # Webhook: any non-2xx / transport error is a delivery failure.
    if webhook is not None:
        if not webhook.get("ok"):
            return False

    return True


async def fire_watches_for_message(
    *,
    db: sqlite3.Connection,
    config,
    secrets,
    account: dict,
    sender: str,
    subject: str,
    body_text: str = "",
    category: str = "",
    message_id: str = "",
    idempotency_key: str = "",
    actor_user_id: int | None = None,
    request_id: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve + match + fire every applicable watch.

    Called by the triage runner after classification, before the
    action loop. Errors in one watch never block the others —
    each fire is independent, both for the action calls and the
    audit row.

     /  — each watch fire is idempotent per ``(account_id,
    idempotency_key, watch_id)`` via the durable
    ``watch_fire_idempotency`` table. The retry drainer
    (``_recover_one_retry_row``) re-runs this function with
    ``fire_watches=True``; without the guard a second drainer pass
    would re-send a pager/SMS escalation.

    The guard has two parts:

      * The durable table records a watch only after it has
        *successfully fired* (``_record_watch_fired``, gated by
        ``_delivered``). A re-run that sees the record skips the watch
        (reported with ``"skipped_idempotent": True`` so the test-fire
        UI surface still sees a result row). A fire that failed to
        deliver leaves no row and so stays retryable.
      * The check → fire → record sequence for one watch runs under a
        per-``(account, idempotency_key, watch)`` ``asyncio.Lock`` so
        two concurrent runs (a drainer pass overlapping live
        ingestion, or two folders' copies of the same RFC message)
        cannot both pass the check and both fire. The second runner
        waits, re-checks, sees the success record, skips.

    Parameters
    ----------
    idempotency_key:
        The stable identity used for the idempotency record — the RFC
        5322 Message-ID of the mail ( Bug 2; the provider
        ``message_id`` for IMAP is a mailbox-scoped UID that collides
        across folders / UIDVALIDITY epochs). When empty this falls
        back to ``message_id`` — no worse than the pre-#250 keying for
        the pathological no-Message-ID-header message.
    message_id:
        The provider message id — still threaded through to the audit
        row + webhook payload (those want the provider's own id), and
        used as the idempotency-key fallback.
    """
    from email_triage.web.db_threadpool import db_call

    account_id = account.get("id")
    #  Bug 2 — the idempotency key is the RFC 5322 Message-ID when
    # the caller supplies it; the provider message_id is the fallback.
    idem_key = (idempotency_key or "").strip() or message_id
    # /#239a — resolve_watches_for_account does sync SQLite on the
    # shared connection; dispatch it off the event loop.
    watches = await db_call(resolve_watches_for_account, db, account)
    out: list[dict[str, Any]] = []
    for w in watches:
        try:
            if not matches(w, sender=sender, subject=subject,
                           body_text=body_text):
                continue
        except Exception as e:
            log.warning(
                "watch match raised; skipping",
                extra={"watch_id": w.watch_id, "error": fmt_exc(e)},
            )
            continue
        #  Bug 3 — serialise check → fire → record for this watch
        # under a per-key async lock so a concurrent run (drainer vs
        # live, or two folders' copies of one RFC message) cannot both
        # fire. The second runner waits here, then re-checks below and
        # sees the success record written by the first.
        lock = _get_watch_fire_lock(account_id, idem_key, w.watch_id)
        try:
            async with lock:
                # Re-check inside the lock: a concurrent run that
                # already fired+recorded this watch makes this a skip.
                already = await db_call(
                    _watch_already_fired,
                    db, account_id, idem_key, w.watch_id,
                )
                if already:
                    log.info(
                        "watch already fired for message; skipping re-fire",
                        extra={
                            "watch_id": w.watch_id,
                            "account_id": account_id,
                            "message_id": message_id,
                        },
                    )
                    out.append({
                        "watch_id": w.watch_id,
                        "watch_name": w.name,
                        "escalate": None,
                        "webhook": None,
                        "redaction": None,
                        "skipped_idempotent": True,
                    })
                    continue
                try:
                    res = await fire_one_watch(
                        db=db, config=config, secrets=secrets,
                        watch=w, account=account,
                        sender=sender, subject=subject,
                        body_text=body_text,
                        category=category, message_id=message_id,
                        actor_user_id=actor_user_id,
                        request_id=request_id,
                    )
                except Exception as e:
                    # The fire raised before completing — nothing is
                    # recorded, so the next drainer pass retries it.
                    log.warning(
                        "watch fire raised",
                        extra={
                            "watch_id": w.watch_id,
                            "error": fmt_exc(e),
                        },
                    )
                    continue
                out.append(res)
                #  Bug 1 — record ONLY a delivered fire. A fire
                # whose escalation SMTP send or webhook POST genuinely
                # failed is left unrecorded so a retry re-fires it; a
                # pager/SMS that never delivered is not falsely marked
                # done. A config-skip (no SMTP relay / no notify
                # address) DOES count as delivered — see ``_delivered``.
                if _delivered(res):
                    await db_call(
                        _record_watch_fired,
                        db, account_id, idem_key, w.watch_id,
                    )
                else:
                    log.info(
                        "watch fire did not deliver; not recorded",
                        extra={
                            "watch_id": w.watch_id,
                            "account_id": account_id,
                            "message_id": message_id,
                        },
                    )
        finally:
            # Drop this coroutine's refcount on the per-key lock;
            # pairs 1:1 with the _get_watch_fire_lock above. The lock
            # entry is pruned when the count hits 0 so the registry
            # stays bounded to the in-flight working set.
            _release_watch_fire_lock(account_id, idem_key, w.watch_id)
    return out
