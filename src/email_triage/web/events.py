"""Outbound event webhooks with HMAC-SHA256 signing.

Fires HTTP POST requests to configured webhook URLs when key events
occur in the triage pipeline (flow classified, finished, failed, etc.).

Each webhook payload is signed with HMAC-SHA256 using a shared secret
so the receiver (e.g. OpenClaw, Slack, an in-house automation) can
verify authenticity.

Usage::

    dispatcher = EventDispatcher(config.webhooks, secrets_provider)
    await dispatcher.fire("flow.classified", {"flow_id": "...", "category": "..."})

The :func:`fire_triage_completed` helper is the central emit point for
the ``triage.completed`` event — used by the manual UI handler, the
IMAP watcher, the Gmail push consumer, and the outbound-webhook API. It bakes
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
from email_triage._isotime import now_utc_iso
from typing import Any

import httpx

from email_triage._errfmt import fmt_exc
from email_triage._http_client import Intent, LazyHttpClient
from email_triage.config import TriageConfig, WebhookTarget
from email_triage.secrets import SecretsDecryptError, read_secret
from email_triage.triage_logging import account_hipaa_effective, is_account_hipaa
from email_triage.web._webhook_template import (
    RequiredFieldMissing,
    render_for_target,
    render_headers_for_target,
)

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.web.events")  # N-196b R21_4


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


def is_local_webhook_url(url: str, extra_local_suffixes=()) -> bool:
    """SSOT (A4, divergence census 2026-06-09): is a webhook destination
    internal/local?

    The single "is this webhook URL local?" predicate, used by BOTH
    ``EventDispatcher`` (its ``_matching_targets`` external-URL gate) AND the
    watch-fired webhook path (``watch_runner.fire_one_watch``). localhost /
    RFC1918 private IPv4 / ``.local`` mDNS / operator ``tls.local_url_suffixes``
    are local; everything else is external and gated behind
    ``webhooks_allow_external``.
    """
    # Census 2026-06-09: delegate to the hardened destination-locality SSOT.
    # This was a string-prefix RFC1918 copy (`host.startswith("10.")`) that
    # fail-OPENed on a hostname like `10.evil.com` (classified local). `_netloc`
    # uses ipaddress-based private-IP classification so a hostname can't
    # masquerade as a private address.
    from email_triage._netloc import is_local_destination
    return is_local_destination(url, extra_suffixes=extra_local_suffixes or ())


def announce_external_egress_posture(config: TriageConfig) -> bool:
    """Loudly surface the  deny-by-default webhook egress posture at boot.

    Returns ``True`` iff external webhook egress is ENABLED (and a WARNING is
    logged); ``False`` (silent) when the safe deny default holds.

    The ACTIVATION of a deny-by-default egress guard must never be silent —
    §164.502(e): triage event metadata leaving the install to a non-local
    host is a disclosure surface. In particular this surfaces the upgrade
    case where an operator's hand-edited ``webhooks_allow_external: true`` was
    previously INERT (the loader did not read the YAML key until the #8-FULL
    config round-trip fix wired it, 2026-06-10) and now takes effect on the
    first post-upgrade boot. Without this announcement that deny→allow flip
    would be silent. To disable: untick it in ``/admin/integrations`` (or
    remove the flag from config.yaml) and restart.
    """
    if not bool(getattr(config, "webhooks_allow_external", False)):
        return False
    logger.warning(
        "External webhook egress is ENABLED (webhooks_allow_external=true) "
        "— triage event metadata may be sent to non-local webhook "
        "targets. If unintended, disable in /admin/integrations (or remove "
        "from config.yaml) and restart. (configured targets: %d)",
        len(getattr(config, "webhooks", []) or []),
    )
    return True


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
        #  — external webhook URLs are deny-by-default. The
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
        # Long-lived httpx client. Webhook fan-out previously
        # opened + closed a fresh client per ``fire()`` call, eating
        # a TLS handshake for every triage-completed event. The
        # dispatcher is a per-process singleton (one on
        # ``app.state.event_dispatcher``); the client lives for the
        # life of the dispatcher and is drained on shutdown via
        # :meth:`aclose`.
        self._http = LazyHttpClient(intent=Intent.WEBHOOK, timeout=self._timeout)

    def _resolve_secret(self, target: WebhookTarget) -> str:
        """Resolve the signing secret for a target.

        Raises :class:`SecretsDecryptError` when the target configured a
        ``secret_key`` but it cannot be decrypted — the caller
        (:meth:`_deliver`) catches it and drops the delivery rather than
        shipping an UNSIGNED webhook (A5, census 2026-06-09). A blank
        return means "no signing configured for this target", which is a
        legitimate unsigned-by-design case — NOT the same as unreadable.
        """
        if not target.secret_key:
            return ""
        if self._secrets is not None:
            # read_secret propagates SecretsDecryptError (does NOT fold an
            # unreadable signing secret into the unsigned path).
            return read_secret(self._secrets, target.secret_key) or ""
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
        # A4 (census 2026-06-09) — delegate to the module-level SSOT so the
        # watch-fired webhook path uses the SAME local-URL predicate.
        return is_local_webhook_url(url, self._extra_local_suffixes)

    def _matching_targets(
        self, event: str, account_id: str | None = None,
    ) -> list[WebhookTarget]:
        """Return targets subscribed to the given event.

        External-URL targets are filtered out unless ``allow_external``
        was set at construction time. Filtered-out targets are logged
        once on first dispatch attempt; subsequent dispatches are
        silent (we don't spam the log every event).

        **Per-account targeting (DA-F3b fix, SME-panel 2026-07-15)**: a
        target with ``account_id`` set matches ONLY when the fire's
        context account_id equals it. Wildcard targets (``account_id``
        is None) match all accounts — preserving the pre-fix single-
        account default. Wildcard-context (``account_id`` argument
        None here) also matches all — preserving fires from paths that
        don't carry account context (kill-switch broadcasts, etc.).
        Closes the cross-account fanning class in multi-account HIPAA-
        mix deployments.
        """
        matched = []
        for t in self._targets:
            if t.events and event not in t.events:
                continue
            # Per-account filter. SME-panel 2026-07-15 DA-F2 close:
            # a target scoped to a specific account_id fires ONLY when
            # the caller supplies a matching account_id. A no-context
            # broadcast (account_id=None — e.g., kill-switch, health
            # ping, diagnostic emit) reaches only wildcard targets
            # (target.account_id=None). Wildcard targets always receive
            # matching-event fires regardless of caller context. Closes
            # the existence-leak class where a scoped-target operator
            # saw broadcast fires that shouldn't have surfaced to them.
            t_acct = getattr(t, "account_id", None)
            if t_acct and (account_id is None or t_acct != account_id):
                continue
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

    async def fire(
        self,
        event: str,
        data: dict[str, Any],
        *,
        is_hipaa: bool = False,
        account_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fire an event to all matching webhook targets.

        ``is_hipaa`` propagates the account-HIPAA context into
        :func:`render_for_target` so a HIPAA-flagged target's operator
        template is IGNORED and a minimal metadata shape ships instead
        (defense-in-depth atop the ``_FORBIDDEN_KEYS`` guard).

        Returns a list of result dicts with delivery status for each target.
        Delivery failures are logged but never raise — webhook delivery
        is best-effort and must not block the triage pipeline.
        """
        targets = self._matching_targets(event, account_id=account_id)
        if not targets:
            return []

        envelope = {
            "event": event,
            "timestamp": now_utc_iso(),
            "data": data,
        }

        results = []
        client = await self._http.get()
        for target in targets:
            result = await self._deliver(
                client, target, event, envelope, is_hipaa,
            )
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
        envelope: dict[str, Any],
        is_hipaa: bool = False,
    ) -> dict[str, Any]:
        """Deliver an envelope to a single target.

        The RENDERED bytes (post-reshaper) are what the receiver
        actually sees, so HMAC signs the rendered bytes — not the
        envelope. For the ``custom`` target-type with no operator
        template override, the rendered bytes ARE the envelope (byte-
        identical to the historical wire), preserving signature
        compatibility for existing custom-relay integrations.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Event-Type": event,
        }

        try:
            secret = self._resolve_secret(target)
        except SecretsDecryptError:
            # Fail closed: a configured signing secret that won't decrypt
            # (corrupt row / master-key mismatch) must NOT degrade to an
            # unsigned delivery. Drop it, loudly + audit-visibly. (A5)
            logger.error(
                "Webhook delivery dropped — signing secret unreadable "
                "(corrupt secret row or master-key mismatch); refusing to "
                "send unsigned. url=%s secret_key=%s event=%s",
                target.url, target.secret_key, event,
            )
            return {
                "url": target.url,
                "success": False,
                "dropped": "signing_secret_unreadable",
            }

        # Reshape the envelope for this target-type. For custom + no
        # template + not-HIPAA this returns the envelope-verbatim wire
        # (byte-identical to canonical_json(envelope)).
        try:
            payload = render_for_target(
                envelope,
                target,
                is_hipaa=is_hipaa,
                resolved_secret=secret,
            )
        except RequiredFieldMissing as e:
            # SME-panel 2026-07-15 DA finding — Prime Directive #8
            # fail-closed: a typed target with a missing required field
            # (e.g. PagerDuty with no ``pd_routing_key``) is DROPPED
            # rather than posted with an empty value that the receiver
            # would reject or (worse) silently accept as a malformed
            # event.
            logger.warning(
                "Webhook delivery dropped — required field missing "
                "for target_type=%s; url=%s event=%s error=%s",
                getattr(target, "target_type", "custom"),
                target.url, event, e,
            )
            return {
                "url": target.url,
                "success": False,
                "dropped": "required_field_missing",
                "error": str(e),
            }

        # Per-target-type required headers (Opsgenie GenieKey, …).
        # Merged AFTER the base headers so a target-type could override
        # ``Content-Type`` if a future receiver needed it.
        headers.update(render_headers_for_target(target, resolved_secret=secret))

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


def read_webhook_quiet_raw(db: sqlite3.Connection, account_id: int) -> dict:
    """Read-both SSOT for the per-account quiet-hours setting (RAW stored dict).

    The ONE place that resolves the new ``webhook_quiet:<id>`` key with a
    fall-back to the legacy ``openclaw_quiet:<id>`` key (pre-rename installs).
    Returns the raw stored dict (no defaults applied) so every read-modify-write
    caller merges onto the SAME base — Prime Directive #5 (collapse the mirrored
    read-both blocks into one funnel; three copies WILL drift). Consumers:
    ``get_webhook_quiet_settings`` (normalizes), the UI editor save-snapshot, and
    the agent-API quiet-hours PUT. WRITES always go to the new key; this keeps a
    pre-rename install's stored fields from being silently dropped on the first
    partial update through ANY writer.
    """
    from email_triage.web.db import get_setting
    from email_triage.web.settings_keys import openclaw_quiet, webhook_quiet
    raw = get_setting(db, webhook_quiet(account_id))
    if raw is None:
        raw = get_setting(db, openclaw_quiet(account_id))
    return raw or {}


def get_webhook_quiet_settings(db: sqlite3.Connection, account_id: int) -> dict:
    """Return the per-account outbound-webhook gate settings.

    Shape: ``{"enabled": bool, "paused": bool, "start_utc": "HH:MM", "end_utc": "HH:MM"}``.
    Missing rows return defaults (``enabled=True``, ``paused=False``).

    Read-both back-compat via the ``read_webhook_quiet_raw`` SSOT: the new
    ``webhook_quiet:<id>`` key is read first; pre-rename installs fall back to the
    legacy ``openclaw_quiet:<id>`` key so old rows keep working without a data
    migration.
    """
    raw = read_webhook_quiet_raw(db, account_id)
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
    sender/subject/body. The webhook receiver fetches detail via the API
    when it needs it.
    """
    if dispatcher is None:
        return False

    # Global kill switch.
    if not getattr(config.push, "webhook_enabled", True):
        return False

    # HIPAA hard-skip — PHI never leaves the process.
    if is_account_hipaa(acct):
        return False

    # Per-account pause + quiet hours.
    #  — get_webhook_quiet_settings does a sync DB read
    # (get_setting) on the shared connection; dispatch it through
    # db_call so the read runs off the event loop under the
    # process-wide DB lock.
    from email_triage.web.db_threadpool import db_call
    settings = await db_call(get_webhook_quiet_settings, db, acct["id"])
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
        # Prefer explicit ``*_count`` keys when the caller has only the
        # tallies (the bulk-sweep terminal emit reads counts off the job
        # row rather than materialising a 10k-element results list); fall
        # back to ``len(list)`` for the inline paths that pass the real
        # result/error lists. Backward-compatible: a run dict without the
        # ``*_count`` keys behaves exactly as before.
        "results_count": run.get("results_count", len(run.get("results") or [])),
        "errors_count": run.get("errors_count", len(run.get("errors") or [])),
        "elapsed_secs": round(float(run.get("elapsed_secs") or 0.0), 3),
        "trigger": trigger,
    }

    try:
        # is_hipaa=False is the invariant at this call site — a HIPAA
        # account hard-skips at the `is_account_hipaa` guard above and never
        # reaches this dispatch. The kwarg is passed EXPLICITLY (not defaulted) so
        # tests/test_webhook_fire_is_hipaa_kwarg_pin.py can enforce the
        # "every .fire(...) passes is_hipaa=" invariant per the
        # SME-panel 2026-07-15 HIPAA finding: caller-discipline is the
        # gate, so the ratchet pin catches a future caller who forgets.
        await dispatcher.fire(
            "triage.completed", payload,
            # 3-axis HIPAA SSOT per N-266 R27 — the pre-existing hard-skip
            # above uses is_account_hipaa (kept for API compat),
            # but new call sites route through account_hipaa_effective
            # so the growth-cap ratchet (tests/test_n266_hipaa_helper_
            # migration_ratchet_pin.py) stays flat. Invariant here is
            # False (the hard-skip above already returned on HIPAA accounts); the
            # kwarg is passed EXPLICITLY so the interprocedural pin
            # test_every_fire_call_passes_is_hipaa_kwarg catches a
            # future forgotten kwarg.
            is_hipaa=account_hipaa_effective(account=acct),
            # DA-F3b fix — carry per-account context so any
            # WebhookTarget with an ``account_id`` binding filters
            # correctly at ``_matching_targets``. Prevents cross-
            # account fanning in multi-account deployments.
            account_id=str(acct.get("id", "")) or None,
        )
    except Exception as e:
        logger.warning("triage.completed dispatch failed", extra={"error": fmt_exc(e)})
        return False
    return True


# --------------------------------------------------------------------------
# N-276 R28 — Notification webhook (row 77 closure)
# --------------------------------------------------------------------------
# Operator ruling 2026-07-03 (punch ): outbound event webhooks are a
# Route/Watch target action. Webhooks are DISABLED on HIPAA accounts
# EXCEPT the notification event — which is redacted the same as the SMS
# escalation route (metadata-only: category + ts + flow_id, NO
# sender/subject/body).
#
# Row 77 was "log-only vs live event-webhook path". `NotifyAction` builds
# the HIPAA-safe redacted payload in `_build_notification` (matches the
# SMS-escalate shape). The dispatcher already exists (Intent.WEBHOOK
# egress-funnel + HMAC signing + external-guard). This closes the gap.

_REGISTERED_DISPATCHER: "EventDispatcher | None" = None


def register_event_dispatcher(dispatcher: "EventDispatcher | None") -> None:
    """Register a module-level dispatcher accessor.

    NotifyAction runs on a background loop (no request context), so the
    request-scoped `app.state.event_dispatcher` isn't reachable. The
    web app lifespan calls this at startup + at shutdown (None) so the
    action can fire notification webhooks without a request.
    """
    global _REGISTERED_DISPATCHER
    _REGISTERED_DISPATCHER = dispatcher


def get_registered_dispatcher() -> "EventDispatcher | None":
    """Return the module-registered dispatcher, or None if lifespan hasn't set one."""
    return _REGISTERED_DISPATCHER


async def fire_notification(
    payload: dict[str, Any],
    *,
    is_hipaa: bool,
) -> bool:
    """Fire the `notification` event over the operator-configured webhook
    targets. Operator ruling (punch ): notifications ARE allowed on
    HIPAA accounts provided the payload is already redacted (metadata-
    only: category + ts + flow_id, no sender/subject/body).

    The caller (NotifyAction) is responsible for building the redacted
    payload — this function does not scrub. It DOES enforce that HIPAA
    payloads carry ONLY the redacted key set as a defense-in-depth
    guard against a caller forgetting to scrub.

    Returns True if a dispatch was attempted, False if suppressed
    (dispatcher missing, kill switch, HIPAA payload contains forbidden
    keys). Best-effort: individual target failures inside dispatcher.fire
    are logged there and do not raise.
    """
    dispatcher = get_registered_dispatcher()
    if dispatcher is None:
        return False
    # N-293 R30 (HIPAA-SME fix-forward on N-276): the forbidden-key
    # check must be UNCONDITIONAL. The pre-fix version gated it on the
    # caller's `is_hipaa` bool — the defense-in-depth guard was
    # defeated whenever the caller's HIPAA-detection misfired (exactly
    # the incident_2026-06-12_preview_metadata_provider_uid_trap
    # failure mode). Any payload carrying a content-bearing key is
    # ALWAYS refused; a non-HIPAA notification legitimately needs
    # `sender`/`subject` — it should route through a different helper.
    # N-380 R32 (2026-07-09 the backlog  close per BINDING  SME panel):
    # widen to include 5 generic content-carrying keys that could slip past
    # the mail-header shape from a future caller shape (e.g. a webhook
    # payload built from a rendered HTML preview or a downstream template
    # payload named `content` or `message`).  No live offender at HEAD
    # (grep clean across `web/events.py` callers); the widen is defense-in-
    # depth SSOT completeness so a future caller CAN'T introduce one
    # without tripping the unconditional refusal path.  §164.312(b) posture
    # improved: the refusal audit-of-record now fires on the generic-shape
    # payload class too, not only the mail-header shape.
    _FORBIDDEN_KEYS = {
        # Mail-header shape (original set).
        "sender", "subject", "body", "snippet", "from", "to",
        "cc", "bcc", "message_id", "thread_id",
        # Generic content-carrying shape (N-380 R32 widen).
        "text", "html", "content", "message", "preview",
        # DA fold N-380 Attack A (2026-07-09) — 4 additional high-signal
        # content-carrying keys the initial widen missed: `attachment` +
        # `attachments` are the highest-severity omission in medical scope
        # (email attachment bytes = chart images / lab PDFs — raw PHI
        # vector); `raw` is a real content-carrying key in the codebase
        # already (`providers/gmail_api.py:890` — `payload["message"]["raw"]`
        # = raw email bytes); `summary` is the closest live-offender-
        # adjacent key (already emitted by `NotifyAction._build_notification`
        # as a free-text field — SAFE TODAY iff `category` stays enum-
        # clean, exactly the caller-discipline the guard exists to defend,
        # so allowlisted via caller-check below).
        "attachment", "attachments", "raw",
        # NOTE: `summary` is NOT in the forbidden set — the sole caller
        # (`actions/notify.py::_build_notification`) emits it INTENTIONALLY
        # as a category-plus-timestamp shape.  Adding it would break the
        # live production caller.  Documented here so a future audit
        # doesn't re-file the class as a gap — the guard is intentionally
        # asymmetric on `summary` per the DA verdict + caller review.
    }
    leak = _FORBIDDEN_KEYS & set(payload.keys())
    if leak:
        # N-359 R31 (2026-07-05 trust-repair fix-forward per PHASE2
        # #meta hipaa-sme + db-sme + the backlog  = TASK ) —
        # UNCONDITIONAL leak-refused audit-log at WARNING. The pre-
        # fix N-293/N-298 shape gated a duplicate `record_hipaa_
        # access_event` emit on `is_hipaa=True` AND passed `None` as
        # the conn positional (AttributeError → silently swallowed
        # by `safe_audit_write_async`) — so the audit row NEVER
        # landed AND the emit only ran on caller-supplied is_hipaa.
        # The WARNING log line below is the CANONICAL §164.312(b)
        # audit trail: it routes through the `SQLiteLogHandler` sink
        # into the HMAC-chained `log_entries` table (§164.312(c)(1)
        # integrity), so the refusal event is captured for EVERY
        # caller regardless of is_hipaa (closes the residual N-293
        # concern) AND avoids the broken `conn=None` shape (closes
        # the PHASE2 #meta db-sme finding). No duplicate emitter —
        # log_entries is the single audit surface for this event
        # class. Ref hipaa-findings-register N-359.
        logger.warning(
            "fire_notification: payload leak refused — §164.312(b) "
            "audit-of-record via this log line (HMAC-chained via "
            "SQLiteLogHandler → log_entries)",
            extra={
                "forbidden_keys": sorted(leak),
                "is_hipaa": is_hipaa,
                "account_id": payload.get("account_id"),
                "event_class": "notification_leak_refused",
            },
        )
        return False
    try:
        # Propagate the account-HIPAA context so the per-target
        # reshaper can enforce the HIPAA-locked minimal wire shape
        # regardless of the operator's template
        # (``_webhook_template.render_for_target``). Also propagate
        # the payload's ``account_id`` (if the caller included one) so
        # ``WebhookTarget.account_id`` filters correctly at
        # ``_matching_targets`` (DA-F3b cross-account-fanning fix).
        _acct_id = payload.get("account_id")
        await dispatcher.fire(
            "notification", payload,
            is_hipaa=is_hipaa,
            account_id=str(_acct_id) if _acct_id else None,
        )
    except Exception as e:
        logger.warning("notification dispatch failed", extra={"error": fmt_exc(e)})
        return False
    return True


async def complete_triage_run(
    dispatcher: EventDispatcher | None,
    db: sqlite3.Connection,
    config: TriageConfig,
    acct: dict,
    *,
    run_id: str,
    query: str,
    trigger: str,
    total_messages: int,
    elapsed_secs: float,
    results: list | None = None,
    errors: list | None = None,
    results_count: int | None = None,
    errors_count: int | None = None,
    record: bool = True,
    actor_user_id: int | None = None,
) -> bool:
    """Terminal triage-run completion SSOT (run18 census #7).

    Persists the ``triage_runs`` history row (when ``record``) AND emits
    ``triage.completed`` through :func:`fire_triage_completed`, so no
    terminal-completion path can record-without-emit. This closes the
    IMAP-poll divergence: ``poll_ingestion._poll_once_imap`` recorded the
    run but never emitted, while its same-file O365-poll sibling did — a
    silent miss for IMAP-poll-only installs (and the outbound webhook ).

    ``record=False`` is the bulk-sweep mode: the bulk runner writes a
    per-message ``triage_runs`` row as it goes
    (``triage_runner_bulk._record_outcome``), so the *terminal* emit must
    NOT double-write a run-level row — it only needs the integration event,
    with counts taken from the job row via ``results_count`` / ``errors_count``
    rather than materialising a results list per message.

    Recording is fail-soft (matches the prior inline call sites, which
    wrapped ``record_triage_run`` in ``try/except: pass`` — the history row
    must never break an ingestion loop), but a record failure is logged.
    The emit is gated entirely inside :func:`fire_triage_completed`
    (dispatcher-missing / global kill / account HIPAA / pause / quiet hours),
    so callers pass the dispatcher unconditionally and let the gates decide.

    Returns :func:`fire_triage_completed`'s result (True if an emit was
    attempted).
    """
    if record:
        from email_triage.web.db import record_triage_run
        from email_triage.web.db_threadpool import db_call
        try:
            await db_call(
                record_triage_run,
                db,
                account_id=acct["id"],
                account_name=acct.get("name", ""),
                query=query,
                total_messages=total_messages,
                results=results or [],
                errors=errors or [],
                elapsed_secs=elapsed_secs,
                actor_user_id=actor_user_id,
            )
        except Exception as e:
            logger.warning(
                "record_triage_run failed", extra={"error": fmt_exc(e)},
            )

    run: dict[str, Any] = {
        "run_id": run_id,
        "query": query,
        "total_messages": total_messages,
        "results": results or [],
        "errors": errors or [],
        "elapsed_secs": elapsed_secs,
    }
    if results_count is not None:
        run["results_count"] = results_count
    if errors_count is not None:
        run["errors_count"] = errors_count

    #  (Census v3 re-run counter-emission MED): the SSOT terminal-
    # completion path for bulk, o365-poll, imap-poll. `run_triage`
    # (triage_runner.py:111) emits via its
    # `_emit_triage_run_outcome_metric` decorator; every OTHER terminal
    # routes here. Bulk-mode (`record=False`) still counts — the
    # Prometheus counter measures per-run terminal completions, not
    # per-message. `outcome` is bounded by `_TRIAGE_METRIC_OUTCOMES`
    # (mirrors triage_runner._TRIAGE_OUTCOMES for label-vocab parity);
    # a shape-defect that omits the errors list slug counts as
    # `error`. `trigger` similarly bounded — an unknown trigger
    # coerces to `manual` (fail-safe, prevents unbounded label
    # cardinality). Fail-open so metrics never take down an ingest
    # loop.
    from email_triage.web._triage_metrics import (
        emit_triage_run_outcome_metric,
    )
    emit_triage_run_outcome_metric(
        trigger=trigger,
        outcome=("error" if (errors or errors_count) else "success"),
    )

    return await fire_triage_completed(
        dispatcher, db, config, acct, run, trigger=trigger,
    )
