"""Watch fire pipeline — match classified mail, run escalate + webhook.

Punch-list #100. Sits between the classifier output and the
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
# Long-lived webhook client (#139)
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
    """
    if not user_id:
        return ""
    try:
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
    """
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
        send_simple_smtp_email(
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
        # Resolution order (#156):
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
        notify = (
            (watch.actions.escalate.notify_email or "").strip()
            or (account.get("config") or {}).get("notify_email", "")
            or _user_notify_email(db, account.get("user_id"))
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
        write_audit_row(
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
    actor_user_id: int | None = None,
    request_id: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve + match + fire every applicable watch.

    Called by the triage runner after classification, before the
    action loop. Errors in one watch never block the others —
    each fire is independent, both for the action calls and the
    audit row.
    """
    watches = resolve_watches_for_account(db, account)
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
        try:
            res = await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=account,
                sender=sender, subject=subject, body_text=body_text,
                category=category, message_id=message_id,
                actor_user_id=actor_user_id, request_id=request_id,
            )
            out.append(res)
        except Exception as e:
            log.warning(
                "watch fire raised",
                extra={"watch_id": w.watch_id, "error": fmt_exc(e)},
            )
    return out
