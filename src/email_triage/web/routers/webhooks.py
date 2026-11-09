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
from email_triage.web._audit import safe_audit_write_async
from email_triage.web.db_threadpool import db_call
from email_triage.web.gmail_push_auth import (
    GmailPushTransientFetchError,
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
    except GmailPushTransientFetchError as e:
        # N-288 R30: brief DNS/network failure during JWKS fetch.
        # Return 503 so Pub/Sub retries (its default behavior on 5xx)
        # + suppresses the stack trace that a bare exception would
        # produce. Log a WARN not an ERROR — this is expected during
        # a transient outage.
        _inc_counter(request, "gmail_push.jwks_transient")
        log.warning("Gmail push: JWKS cert fetch transient failure",
                    reason=e.reason)
        return JSONResponse(
            {"status": "retry", "reason": "jwks_fetch_transient"},
            status_code=503,
        )

    # N-233 R22 — route through the SSOT so the 400-on-malformed shape
    # matches the auth entry points. FastAPI turns HTTPException(400)
    # into `{"detail":"invalid_json"}` — Google Pub/Sub only checks the
    # status_code, not the body.
    from email_triage.web.routers._json import parse_json_body
    from fastapi import HTTPException as _HTTPException
    try:
        body = await parse_json_body(request)
    except _HTTPException as e:
        return JSONResponse({"status": "error", "reason": "bad_json"}, status_code=e.status_code)

    message = body.get("message", {}) if isinstance(body, dict) else {}
    raw_data = message.get("data", "")
    if not raw_data:
        return JSONResponse({"status": "ignored", "reason": "no_data"})

    try:
        #  tail — external URL-safe base64 from Gmail push (RFC 4648
        # §5, padding-stripped). Route through the SSOT so a length-not-
        # multiple-of-4 input decodes correctly instead of raising and
        # dropping the push.
        from email_triage._base64url import b64decode_permissive
        decoded = b64decode_permissive(raw_data).decode("utf-8")
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
    # ASYNC-DB: watch demux read off the event loop — this is the
    # live Gmail push-ingestion path.
    watch = await db_call(get_gmail_watch_by_email, db, email_address)
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

    #  — persist a per-day per-account delivery row for the
    # /admin/stats rollup. Best-effort: any failure here MUST NOT
    # 5xx the webhook (Pub/Sub would retry, double-counting and
    # double-queueing). The in-memory counter at _inc_counter
    # remains for live debug; this writes the persisted shape.
    try:
        from email_triage.web.db import record_push_delivery
        # ASYNC-DB: delivery-counter write off the event loop.
        await db_call(
            record_push_delivery,
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

    N-385 (2026-07-10 wf_69674c7e-c67, HIGH): the Prometheus text ``/metrics``
    surface is the canonical operator-facing counter registry (see the
    ``email_triage.metrics`` module docstring). This funnel is the ONE
    convergence seam every webhook counter caller already routes through,
    so mirroring here through :func:`~email_triage.metrics.emit_webhook_event`
    lifts every callsite onto the SSOT without a per-site edit.
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
    # N-385 — Prometheus SSOT mirror. Fail-open (the funnel already swallows).
    try:
        from email_triage.metrics import emit_webhook_event
        emit_webhook_event(key)
    except Exception:  # noqa: BLE001
        pass


def _inc_counter_local(request: Request, key: str) -> None:
    metrics = getattr(request.app.state, "metrics", None)
    if metrics is None:
        metrics = {}
        request.app.state.metrics = metrics
    metrics[key] = metrics.get(key, 0) + 1


# ---------------------------------------------------------------------------
# Microsoft Graph webhook receiver
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
    # N-233 R22 — same SSOT routing as gmail_push (see comment above).
    from email_triage.web.routers._json import parse_json_body
    from fastapi import HTTPException as _HTTPException
    try:
        body = await parse_json_body(request)
    except _HTTPException as e:
        return JSONResponse(
            {"status": "error", "reason": "bad_json"}, status_code=e.status_code,
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
                # ASYNC-DB: subscription demux read off the loop.
                watch = await db_call(
                    get_o365_subscription_by_subscription_id, db, sub_id,
                )
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
        #  — when no clientState secret is stored for this
        # account (neither per-account nor install-wide), the prior
        # implementation skipped the compare entirely. That meant any
        # actor who learned the subscriptionId (Microsoft Graph leaks
        # subscriptionIds in API responses to anyone with the right
        # tenant token, AND old code paths logged them) could POST
        # to /webhooks/office365 and queue triage work for that
        # account. Fail closed: missing secret == 401 + audit.
        expected_state, cs_undecryptable = _expected_client_state(request, watch)
        if not expected_state:
            account_id_for_log = watch.get("account_id")
            # A5 / F-1 — distinguish "operator never registered a secret"
            # (unset) from "a stored secret won't decrypt" (master-key
            # mismatch). Both fail closed (401), but the durable audit row
            # must record the TRUE cause (§164.312(b) audit accuracy).
            cause = "undecryptable" if cs_undecryptable else "unset"
            if cs_undecryptable:
                log.error(
                    "office365_clientstate unreadable for account "
                    f"{account_id_for_log} — stored secret won't decrypt "
                    "(corrupt row / master-key mismatch); webhook rejected. "
                    "Check the secrets master key.",
                    account_id=account_id_for_log,
                    subscription_id=sub_id,
                )
            else:
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
                    # ASYNC-DB: auth-event write off the loop.
                    await safe_audit_write_async(
                        lambda: db_call(
                            record_auth_event,
                            db,
                            event_type="o365_webhook_auth",
                            email="",
                            outcome="failure",
                            detail=(
                                f"clientstate_{cause} account_id="
                                f"{account_id_for_log} subscription_id="
                                f"{sub_id}"
                            ),
                        ),
                        description=(
                            f"o365_webhook_auth clientstate_{cause} "
                            f"account_id={account_id_for_log}"
                        ),
                    )
            except Exception as _swallow_exc:
                log.error(
                    "o365 webhook: auth-failure audit write failed",
                    exc_info=_swallow_exc,
                )
            _inc_counter(
                request,
                "office365_push.client_state_"
                + ("undecryptable" if cs_undecryptable else "unset"),
            )
            return JSONResponse(
                {
                    "status": "error",
                    "reason": f"clientstate_{cause}",
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
                    # ASYNC-DB: auth-event write off the loop.
                    await safe_audit_write_async(
                        lambda: db_call(
                            record_auth_event,
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
                        ),
                        description=(
                            f"o365_webhook_auth clientstate_mismatch "
                            f"account_id={watch.get('account_id')}"
                        ),
                    )
            except Exception as _swallow_exc:
                log.error(
                    "o365 webhook: client_state mismatch audit write failed",
                    exc_info=_swallow_exc,
                )
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
                # ASYNC-DB: heartbeat write off the loop.
                await db_call(record_o365_notification, db, sub_id)
            except Exception as hb_exc:
                log.warning(
                    "O365 notification heartbeat write failed",
                    sub_id=sub_id, error=fmt_exc(hb_exc),
                )

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
                #  — persist a per-day per-account delivery row
                # for the /admin/stats rollup. Best-effort: any
                # failure here MUST NOT 5xx the webhook (Graph
                # would retry, double-counting + double-queueing).
                try:
                    from email_triage.web.db import record_push_delivery
                    # ASYNC-DB: delivery-counter write off the loop.
                    await db_call(
                        record_push_delivery,
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


def _expected_client_state(request: Request, watch: dict) -> tuple[str, bool]:
    """Return ``(expected_clientState, undecryptable)`` for this row.

    Strategy: secrets store keyed by
    ``office365_clientstate:<account_id>``. Falls back to the install-
    wide ``office365_clientstate`` secret if a per-account value isn't
    set, and finally to empty string. Empty-string return is treated
    by the receiver as "needs re-registration" — the receiver MUST
    fail-closed (HTTP 401) rather than skipping the compare. See
     for the security gap that caused this contract change:
    pre-fix subscriptions registered with ``client_state=""`` on the
    Graph side stay deliverable until the operator clicks Stop +
    Start in /admin/integrations to re-register with a freshly-
    generated secret.

    ``undecryptable`` is True when a stored clientState secret EXISTS
    but won't decrypt (corrupt row / master-key mismatch) — distinct
    from genuinely-unset (``("", False)``). The receiver fails closed
    either way, but threads the true cause into the §164.312(b) audit
    row so a key mismatch isn't recorded as "operator forgot to
    register" (A5 / SME finding F-1).
    """
    account_id = watch.get("account_id") if watch else None
    secrets = getattr(request.app.state, "secrets", None)
    if secrets is None or account_id is None:
        return "", False
    from email_triage.web.settings_keys import office365_clientstate
    from email_triage.secrets import SecretsDecryptError, read_secret
    try:
        per_acct = read_secret(secrets, office365_clientstate(account_id))
        if per_acct:
            return str(per_acct), False
        install = read_secret(secrets, "office365_clientstate")
        if install:
            return str(install), False
    except SecretsDecryptError:
        # A5 — returning "" still fails closed (caller rejects the push
        # with 401, per ); but report the TRUE cause so a master-key
        # mismatch isn't mistaken for an unset clientState.
        log.error(
            "office365 clientState unreadable — corrupt secret row or "
            "master-key mismatch; webhook will be rejected as if unset",
            account_id=account_id,
        )
        return "", True
    return "", False


@router.post("/office365")
async def office365_push(request: Request):
    """Canonical O365/Graph webhook receiver path."""
    return await _office365_webhook(request)


@router.post("/graph")
async def graph_push(request: Request):
    """Back-compat alias for ``/webhooks/office365``.

    Older subscriptions registered before  used ``/webhooks/graph``
    as the notificationUrl; keep the alias around so they don't go
    silent during the transition window.
    """
    return await _office365_webhook(request)
