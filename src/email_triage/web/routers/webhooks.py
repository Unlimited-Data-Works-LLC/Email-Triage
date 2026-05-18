"""Webhook receivers for push notifications.

Handles incoming push notifications from:
- Gmail Pub/Sub (signed-JWT-authenticated push subscription)
- Microsoft Graph (subscription change notifications)

The Gmail endpoint verifies Google's signed JWT before accepting the
payload; the Graph endpoint still uses validation-token echo only —
`clientState` verification lands in a follow-up phase.
"""

from __future__ import annotations

import base64
import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage.web.gmail_push_auth import (
    GmailPushVerificationError,
    _CertCache,
    verify_pubsub_jwt,
)

log = get_logger("web.webhooks")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _get_cert_cache(request: Request) -> _CertCache:
    cache = getattr(request.app.state, "_gmail_cert_cache", None)
    if cache is None:
        cache = _CertCache()
        request.app.state._gmail_cert_cache = cache
    return cache


@router.post("/gmail")
async def gmail_push(request: Request):
    """Receive Gmail push notifications via Google Cloud Pub/Sub.

    Flow:
        1. Verify the Authorization: Bearer <JWT> header (RS256, Google
           public certs, expected audience + issuer + SA email).
        2. Base64-decode the Pub/Sub envelope to {emailAddress, historyId}.
        3. Enqueue onto ``app.state.push_queue`` for the background
           consumer to reconcile via list_history.
    """
    config = getattr(request.app.state, "config", None)
    push_cfg = getattr(config, "push", None) if config else None

    if push_cfg is None:
        log.warning("Gmail push: no PushConfig on app state")
        return JSONResponse({"status": "error", "reason": "not_configured"}, status_code=503)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        _inc_counter(request, "gmail_push.auth_missing")
        return JSONResponse({"status": "error", "reason": "missing_token"}, status_code=401)

    token = auth_header[7:].strip()
    audience = push_cfg.gmail_audience or push_cfg.public_url

    try:
        await verify_pubsub_jwt(
            token,
            audience=audience,
            sa_email=push_cfg.gmail_subscription_sa_email,
            cert_cache=_get_cert_cache(request),
        )
    except GmailPushVerificationError as e:
        _inc_counter(request, "gmail_push.auth_failed")
        log.warning("Gmail push: JWT verification failed", reason=e.reason)
        return JSONResponse({"status": "error", "reason": "unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "reason": "bad_json"}, status_code=400)

    message = body.get("message", {}) if isinstance(body, dict) else {}
    raw_data = message.get("data", "")
    if not raw_data:
        return JSONResponse({"status": "ignored", "reason": "no_data"})

    try:
        decoded = base64.b64decode(raw_data).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as e:
        log.warning("Gmail push: failed to decode data", error=fmt_exc(e))
        return JSONResponse({"status": "ignored", "reason": "decode_error"})

    email_address = payload.get("emailAddress", "")
    history_id = payload.get("historyId")
    if not email_address or history_id is None:
        return JSONResponse({"status": "ignored", "reason": "incomplete_payload"})

    # Demux: is any account actually watching this mailbox?
    db = getattr(request.app.state, "db", None)
    if db is None:
        return JSONResponse({"status": "error", "reason": "no_db"}, status_code=503)

    from email_triage.web.db import get_gmail_watch_by_email
    watch = get_gmail_watch_by_email(db, email_address)
    if watch is None:
        # In-flight delivery after stop_watch, or an email we never watched.
        # Return 200 so Pub/Sub stops retrying.
        log.warning("Gmail push: no active watch for address", email=email_address)
        return JSONResponse({"status": "dropped", "reason": "no_watch"})

    queue = getattr(request.app.state, "push_queue", None)
    if queue is None:
        return JSONResponse({"status": "error", "reason": "no_queue"}, status_code=503)

    try:
        queue.put_nowait({
            "email": email_address,
            "history_id": str(history_id),
            "account_id": watch["account_id"],
        })
    except Exception:
        # Queue full — 503 so Pub/Sub retries.
        _inc_counter(request, "gmail_push.queue_full")
        return JSONResponse({"status": "error", "reason": "queue_full"}, status_code=503)

    # #166 — persist a per-day per-account delivery row for the
    # /admin/stats rollup. Best-effort: any failure here MUST NOT
    # 5xx the webhook (Pub/Sub would retry, double-counting and
    # double-queueing). The in-memory counter at _inc_counter
    # remains for live debug; this writes the persisted shape.
    try:
        from email_triage.web.db import record_push_delivery
        record_push_delivery(
            db, account_id=watch["account_id"], provider="gmail",
        )
    except Exception:
        log.warning(
            "Gmail push: failed to record delivery counter",
            account_id=watch["account_id"],
        )

    log.info(
        "Gmail push queued",
        email=email_address,
        history_id=history_id,
        account_id=watch["account_id"],
    )
    return JSONResponse({"status": "queued"})


def _inc_counter(request: Request, key: str) -> None:
    """Bump a process-local webhook counter on ``app.state.metrics``.

    Also mirrors to Redis via the install-level persistent counter
    backend when configured (namespace ``webhooks``). Best-effort;
    Redis hiccups are silent. Process-local stays authoritative.
    """
    try:
        from email_triage.engine.persistent_counters import (
            get_install_counter_backend,
        )
        be = get_install_counter_backend()
        if be is not None:
            be.incr("webhooks", key)
    except Exception:  # noqa: BLE001
        pass
    _inc_counter_local(request, key)


def _inc_counter_local(request: Request, key: str) -> None:
    metrics = getattr(request.app.state, "metrics", None)
    if metrics is None:
        metrics = {}
        request.app.state.metrics = metrics
    metrics[key] = metrics.get(key, 0) + 1


# ---------------------------------------------------------------------------
# Microsoft Graph webhook receiver  (#53)
# ---------------------------------------------------------------------------

async def _office365_webhook(request: Request):
    """Receive Microsoft Graph subscription change notifications.

    Two modes:

    * **Validation handshake** — Graph POSTs ``?validationToken=<x>``
      when a subscription is created. We must echo the token in the
      body within 10 seconds. No body expected.
    * **Change notifications** — Graph POSTs ``{"value": [...]}`` with
      one or more notification records. Each carries ``subscriptionId``
      + ``clientState`` + ``resource`` + ``changeType`` + a small
      ``resourceData`` blob (id, @odata.type, @odata.id, @odata.etag).

    Security:

    * ``clientState`` per-subscription secret is the only authentication
      Graph offers. We compare it against the stored value on the
      ``office365_subscriptions`` row; mismatches are dropped + counted.
      Compared with ``hmac.compare_digest`` to keep the check
      constant-time.
    * Endpoint is local-network gated by default — operator opts in to
      public-facing exposure via ``tls.local_url_suffixes`` (per the
      no-external-data-flow rule). The webhook itself doesn't enforce
      that here; the surrounding deploy / reverse-proxy layer does.
      We do still demux every notification through the DB so a
      mis-targeted delivery from a different tenant can't queue work
      against an unrelated account.
    """
    # ----- Validation handshake -----------------------------------------
    validation_token = request.query_params.get("validationToken")
    if validation_token:
        from fastapi.responses import PlainTextResponse
        log.info("Office365 webhook validation handshake")
        return PlainTextResponse(validation_token)

    # ----- Change notification ------------------------------------------
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"status": "error", "reason": "bad_json"}, status_code=400,
        )

    notifications = body.get("value", []) if isinstance(body, dict) else []
    if not notifications:
        return JSONResponse({"status": "ok", "queued": 0})

    db = getattr(request.app.state, "db", None)
    push_queue = getattr(request.app.state, "push_queue", None)

    queued = 0
    dropped_unknown = 0
    dropped_clientstate = 0

    # Lazy import to avoid touching DB helpers when only the validation
    # path runs.
    if db is not None:
        from email_triage.web.db import (
            get_o365_subscription_by_subscription_id,
            record_o365_notification,
        )
    else:
        get_o365_subscription_by_subscription_id = None  # type: ignore[assignment]
        record_o365_notification = None  # type: ignore[assignment]

    import hmac

    for notification in notifications:
        if not isinstance(notification, dict):
            continue
        sub_id = (notification.get("subscriptionId") or "").strip()
        client_state = notification.get("clientState") or ""
        resource = notification.get("resource", "")
        change_type = notification.get("changeType", "")
        resource_data = notification.get("resourceData") or {}
        message_id = ""
        if isinstance(resource_data, dict):
            message_id = (resource_data.get("id") or "").strip()

        if not sub_id:
            dropped_unknown += 1
            continue

        watch = None
        if db is not None and get_o365_subscription_by_subscription_id is not None:
            try:
                watch = get_o365_subscription_by_subscription_id(db, sub_id)
            except Exception:
                watch = None

        if watch is None:
            # Unknown subscription_id — could be in-flight after delete,
            # could be cross-tenant misdirection. Drop silently with a
            # 200 so Graph stops retrying; bump a counter for diagnosis.
            dropped_unknown += 1
            log.warning(
                "Office365 push: unknown subscription_id",
                subscription_id=sub_id,
            )
            continue

        # clientState verification — constant-time compare.
        # #132 — when no clientState secret is stored for this
        # account (neither per-account nor install-wide), the prior
        # implementation skipped the compare entirely. That meant any
        # actor who learned the subscriptionId (Microsoft Graph leaks
        # subscriptionIds in API responses to anyone with the right
        # tenant token, AND old code paths logged them) could POST
        # to /webhooks/office365 and queue triage work for that
        # account. Fail closed: missing secret == 401 + audit.
        expected_state = _expected_client_state(request, watch)
        if not expected_state:
            account_id_for_log = watch.get("account_id")
            log.info(
                "office365_clientstate missing for account "
                f"{account_id_for_log} — webhook delivery rejected; "
                "operator must re-register the subscription so a "
                "freshly-generated clientState lands on both sides.",
                account_id=account_id_for_log,
                subscription_id=sub_id,
            )
            try:
                from email_triage.web.db import record_auth_event
                if db is not None:
                    record_auth_event(
                        db,
                        event_type="o365_webhook_auth",
                        email="",
                        outcome="failure",
                        detail=(
                            f"clientstate_unset account_id="
                            f"{account_id_for_log} subscription_id="
                            f"{sub_id}"
                        ),
                    )
            except Exception:
                pass
            _inc_counter(request, "office365_push.client_state_unset")
            return JSONResponse(
                {
                    "status": "error",
                    "reason": "clientstate_unset",
                },
                status_code=401,
            )
        if not hmac.compare_digest(
            str(client_state), str(expected_state),
        ):
            dropped_clientstate += 1
            log.warning(
                "Office365 push: clientState mismatch",
                account_id=watch.get("account_id"),
                subscription_id=sub_id,
                had_client_state=bool(client_state),
            )
            try:
                from email_triage.web.db import record_auth_event
                if db is not None:
                    record_auth_event(
                        db,
                        event_type="o365_webhook_auth",
                        email="",
                        outcome="failure",
                        detail=(
                            f"clientstate_mismatch account_id="
                            f"{watch.get('account_id')} subscription_id="
                            f"{sub_id} had_client_state="
                            f"{bool(client_state)}"
                        ),
                    )
            except Exception:
                pass
            _inc_counter(request, "office365_push.client_state_mismatch")
            return JSONResponse(
                {
                    "status": "error",
                    "reason": "clientstate_mismatch",
                },
                status_code=401,
            )

        # Stamp last_notification_at heartbeat.
        if record_o365_notification is not None:
            try:
                record_o365_notification(db, sub_id)
            except Exception:
                pass

        if push_queue is not None:
            try:
                push_queue.put_nowait({
                    "provider": "office365",
                    "account_id": watch.get("account_id"),
                    "subscription_id": sub_id,
                    "resource": resource,
                    "change_type": change_type,
                    "message_id": message_id,
                })
                queued += 1
                # #166 — persist a per-day per-account delivery row
                # for the /admin/stats rollup. Best-effort: any
                # failure here MUST NOT 5xx the webhook (Graph
                # would retry, double-counting + double-queueing).
                try:
                    from email_triage.web.db import record_push_delivery
                    record_push_delivery(
                        db,
                        account_id=watch.get("account_id"),
                        provider="office365",
                    )
                except Exception:
                    log.warning(
                        "Office365 push: failed to record delivery counter",
                        account_id=watch.get("account_id"),
                    )
            except Exception:
                _inc_counter(request, "office365_push.queue_full")
                # Queue full — return 503 so Graph retries.
                return JSONResponse(
                    {"status": "error", "reason": "queue_full"},
                    status_code=503,
                )

    if dropped_unknown:
        _inc_counter(request, "office365_push.unknown_subscription")
    # ``dropped_clientstate`` no longer increments per-notification —
    # auth failures short-circuit the whole request to 401. The local
    # counter stays in the response body at zero so existing
    # integration tests / dashboards that read the JSON shape don't
    # have to change in lockstep with this fix.

    log.info(
        "Office365 push processed",
        queued=queued,
        dropped_unknown=dropped_unknown,
        dropped_clientstate=dropped_clientstate,
    )
    return JSONResponse({
        "status": "ok",
        "queued": queued,
        "dropped_unknown": dropped_unknown,
        "dropped_clientstate": dropped_clientstate,
    })


def _expected_client_state(request: Request, watch: dict) -> str:
    """Return the expected ``clientState`` for this subscription row.

    Strategy: secrets store keyed by
    ``office365_clientstate:<account_id>``. Falls back to the install-
    wide ``office365_clientstate`` secret if a per-account value isn't
    set, and finally to empty string. Empty-string return is treated
    by the receiver as "needs re-registration" — the receiver MUST
    fail-closed (HTTP 401) rather than skipping the compare. See
    #132 for the security gap that caused this contract change:
    pre-fix subscriptions registered with ``client_state=""`` on the
    Graph side stay deliverable until the operator clicks Stop +
    Start in /admin/integrations to re-register with a freshly-
    generated secret.
    """
    account_id = watch.get("account_id") if watch else None
    secrets = getattr(request.app.state, "secrets", None)
    if secrets is None or account_id is None:
        return ""
    try:
        from email_triage.web.settings_keys import office365_clientstate
        per_acct = secrets.get(office365_clientstate(account_id))
        if per_acct:
            return str(per_acct)
        install = secrets.get("office365_clientstate")
        if install:
            return str(install)
    except Exception:
        pass
    return ""


@router.post("/office365")
async def office365_push(request: Request):
    """Canonical O365/Graph webhook receiver path (#53)."""
    return await _office365_webhook(request)


@router.post("/graph")
async def graph_push(request: Request):
    """Back-compat alias for ``/webhooks/office365``.

    Older subscriptions registered before #53 used ``/webhooks/graph``
    as the notificationUrl; keep the alias around so they don't go
    silent during the transition window.
    """
    return await _office365_webhook(request)
