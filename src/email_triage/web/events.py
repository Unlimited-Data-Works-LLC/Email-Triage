"""Outbound event webhooks with HMAC-SHA256 signing.

Fires HTTP POST requests to configured webhook URLs when key events
occur in the triage pipeline (flow classified, finished, failed, etc.).

Each webhook payload is signed with HMAC-SHA256 using a shared secret
so the receiver (e.g. OpenClaw) can verify authenticity.

Usage::

    dispatcher = EventDispatcher(config.webhooks, secrets_provider)
    await dispatcher.fire("flow.classified", {"flow_id": "...", "category": "..."})

The :func:`fire_triage_completed` helper is the central emit point for
the ``triage.completed`` event — used by the manual UI handler, the
IMAP watcher, the Gmail push consumer, and the OpenClaw API. It bakes
in the HIPAA hard-skip, per-account quiet hours, per-account pause,
and global kill switch so individual call sites stay one-liners.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from email_triage._errfmt import fmt_exc
from email_triage._http_client import LazyHttpClient
from email_triage.config import TriageConfig, WebhookTarget
from email_triage.triage_logging import is_account_hipaa

logger = logging.getLogger("email_triage.web.events")


def sign_payload(payload: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a webhook payload."""
    return hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(payload: bytes, secret: str, signature: str) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(expected, signature)


class EventDispatcher:
    """Dispatches events to configured webhook targets.

    Parameters
    ----------
    targets:
        List of ``WebhookTarget`` from config (url, events, secret_key).
    secrets_provider:
        Secrets provider to resolve secret keys to actual values.
        If None, the ``secret_key`` field on targets is used directly
        as the signing secret (useful for testing).
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        targets: list[WebhookTarget] | None = None,
        secrets_provider: Any = None,
        timeout: float = 10.0,
        allow_external: bool = False,
        local_url_suffixes: list[str] | None = None,
    ):
        self._targets = targets or []
        self._secrets = secrets_provider
        self._timeout = timeout
        # #60 — external webhook URLs are deny-by-default. The
        # operator must explicitly set webhooks_allow_external: true
        # in YAML (mapped through to here) to ship events off-host.
        # All targets are still HMAC-signed + carry only metadata
        # (event name, flow_id, counts, trigger label) — no message
        # content — but this guard prevents accidental egress when
        # an operator copies a config from a less-restrictive install.
        self._allow_external = allow_external
        # Operator-supplied "treat-as-local" hostname suffixes (e.g.
        # an internal homelab domain). Source tree carries no
        # operator-specific suffix; this list is the seam.
        self._extra_local_suffixes = list(local_url_suffixes or [])
        # Long-lived httpx client (#139). Webhook fan-out previously
        # opened + closed a fresh client per ``fire()`` call, eating
        # a TLS handshake for every triage-completed event. The
        # dispatcher is a per-process singleton (one on
        # ``app.state.event_dispatcher``); the client lives for the
        # life of the dispatcher and is drained on shutdown via
        # :meth:`aclose`.
        self._http = LazyHttpClient(timeout=self._timeout)

    def _resolve_secret(self, target: WebhookTarget) -> str:
        """Resolve the signing secret for a target."""
        if not target.secret_key:
            return ""
        if self._secrets is not None:
            try:
                val = self._secrets.get(target.secret_key)
                return val or ""
            except Exception:
                return ""
        # Fall back to using secret_key directly (testing).
        return target.secret_key

    def _is_local_url(self, url: str) -> bool:
        """True if the URL points to a local-only destination.

        Always-on signals (no config needed):
          * localhost / 127.0.0.1 / ::1
          * RFC1918 private IPv4 (10/8, 172.16/12, 192.168/16)
          * .local mDNS suffix

        Operator-extensible: any suffix in
        ``config.tls.local_url_suffixes`` (e.g. ``.home.lan``,
        ``.internal.example``) is also treated as local. The source
        tree carries no operator-specific suffix; the operator wires
        their internal hostname pattern via YAML.
        """
        if not url:
            return False
        from urllib.parse import urlparse
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        if host.endswith(".local"):
            return True
        for suffix in (self._extra_local_suffixes or ()):
            s = suffix.lower().strip()
            if s and host.endswith(s):
                return True
        if host.startswith("10.") or host.startswith("192.168."):
            return True
        if host.startswith("172."):
            try:
                second = int(host.split(".")[1])
                if 16 <= second <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        return False

    def _matching_targets(self, event: str) -> list[WebhookTarget]:
        """Return targets subscribed to the given event.

        External-URL targets are filtered out unless ``allow_external``
        was set at construction time. Filtered-out targets are logged
        once on first dispatch attempt; subsequent dispatches are
        silent (we don't spam the log every event).
        """
        matched = []
        for t in self._targets:
            if not t.events or event in t.events:
                if not self._allow_external and not self._is_local_url(t.url):
                    logger.warning(
                        "Webhook target dropped — external URL "
                        "(set webhooks_allow_external: true in YAML to permit) "
                        "url=%s event=%s",
                        t.url, event,
                    )
                    continue
                matched.append(t)
        return matched

    async def fire(self, event: str, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Fire an event to all matching webhook targets.

        Returns a list of result dicts with delivery status for each target.
        Delivery failures are logged but never raise — webhook delivery
        is best-effort and must not block the triage pipeline.
        """
        targets = self._matching_targets(event)
        if not targets:
            return []

        payload = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        results = []
        client = await self._http.get()
        for target in targets:
            result = await self._deliver(client, target, event, payload_bytes)
            results.append(result)

        return results

    async def aclose(self) -> None:
        """Drain the long-lived webhook client. Safe to call on
        shutdown even if no events have been dispatched."""
        await self._http.aclose()

    async def _deliver(
        self,
        client: httpx.AsyncClient,
        target: WebhookTarget,
        event: str,
        payload: bytes,
    ) -> dict[str, Any]:
        """Deliver a payload to a single target."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Event-Type": event,
        }

        secret = self._resolve_secret(target)
        if secret:
            signature = sign_payload(payload, secret)
            headers["X-Signature-256"] = f"sha256={signature}"

        try:
            resp = await client.post(target.url, content=payload, headers=headers)
            logger.info(
                "Webhook delivered",
                extra={
                    "url": target.url,
                    "event": event,
                    "status": resp.status_code,
                },
            )
            return {
                "url": target.url,
                "status": resp.status_code,
                "success": 200 <= resp.status_code < 300,
            }
        except Exception as e:
            logger.warning(
                "Webhook delivery failed",
                extra={"url": target.url, "event": event, "error": fmt_exc(e)},
            )
            return {
                "url": target.url,
                "status": 0,
                "success": False,
                "error": fmt_exc(e),
            }


# ---------------------------------------------------------------------------
# triage.completed central emitter
# ---------------------------------------------------------------------------

def _parse_hhmm(s: str) -> tuple[int, int] | None:
    try:
        h, m = s.split(":")
        return int(h), int(m)
    except Exception:
        return None


def is_in_quiet_hours(now_utc: datetime, start: str, end: str) -> bool:
    """Return True if ``now_utc`` falls inside ``[start, end)`` in UTC.

    ``start`` and ``end`` are ``HH:MM`` strings. Cross-midnight ranges
    (e.g. ``22:00`` -> ``08:00``) are supported by splitting at midnight.
    A range where start == end is treated as "always quiet" (the
    operator probably wants to hard-pause; the explicit ``paused`` flag
    is the cleaner way to do that, but we don't crash on it).
    """
    s = _parse_hhmm(start)
    e = _parse_hhmm(end)
    if s is None or e is None:
        return False
    cur_min = now_utc.hour * 60 + now_utc.minute
    s_min = s[0] * 60 + s[1]
    e_min = e[0] * 60 + e[1]
    if s_min == e_min:
        return True
    if s_min < e_min:
        return s_min <= cur_min < e_min
    # Cross midnight: quiet from start..24:00 OR 00:00..end.
    return cur_min >= s_min or cur_min < e_min


def get_openclaw_quiet_settings(db: sqlite3.Connection, account_id: int) -> dict:
    """Return the per-account OpenClaw webhook gate settings.

    Shape: ``{"enabled": bool, "paused": bool, "start_utc": "HH:MM", "end_utc": "HH:MM"}``.
    Missing rows return defaults (``enabled=True``, ``paused=False``).
    """
    from email_triage.web.db import get_setting
    from email_triage.web.settings_keys import openclaw_quiet
    raw = get_setting(db, openclaw_quiet(account_id)) or {}
    return {
        "enabled": bool(raw.get("enabled", True)),
        "paused": bool(raw.get("paused", False)),
        "start_utc": raw.get("start_utc", ""),
        "end_utc": raw.get("end_utc", ""),
    }


async def fire_triage_completed(
    dispatcher: EventDispatcher | None,
    db: sqlite3.Connection,
    config: TriageConfig,
    acct: dict,
    run: dict,
    *,
    trigger: str = "manual",
) -> bool:
    """Emit ``triage.completed`` for one account/run, gated by safety checks.

    Returns True if an attempt was made (one or more targets received
    the payload), False if the emit was suppressed. Suppression reasons,
    in order: dispatcher missing, global kill, account HIPAA, account
    paused, account in quiet hours.

    The payload is intentionally lean — counts and metadata only, no
    sender/subject/body. OpenClaw fetches detail via the API when it
    needs it.
    """
    if dispatcher is None:
        return False

    # Global kill switch.
    if not getattr(config.push, "openclaw_webhook_enabled", True):
        return False

    # HIPAA hard-skip — PHI never leaves the process.
    if is_account_hipaa(acct):
        return False

    # Per-account pause + quiet hours.
    settings = get_openclaw_quiet_settings(db, acct["id"])
    if not settings["enabled"] or settings["paused"]:
        return False
    if settings["start_utc"] and settings["end_utc"]:
        if is_in_quiet_hours(datetime.now(timezone.utc),
                             settings["start_utc"], settings["end_utc"]):
            return False

    payload = {
        "run_id": run.get("run_id", ""),
        "account_id": acct["id"],
        "account_name": acct.get("name", ""),
        "query": run.get("query", ""),
        "total_messages": run.get("total_messages", 0),
        "results_count": len(run.get("results") or []),
        "errors_count": len(run.get("errors") or []),
        "elapsed_secs": round(float(run.get("elapsed_secs") or 0.0), 3),
        "trigger": trigger,
    }

    try:
        await dispatcher.fire("triage.completed", payload)
    except Exception as e:
        logger.warning("triage.completed dispatch failed", extra={"error": fmt_exc(e)})
        return False
    return True
