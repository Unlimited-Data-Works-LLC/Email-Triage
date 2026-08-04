""" — reusable admin-alert primitive (Part 2).

A tiny state-machine + registry that lets any subsystem publish
"attention-needed" telemetry to the operator's inbox without hand-rolling
a settings row, cooldown floor, or a bespoke SMTP send path.

State machine
-------------
For each registered event ``evt`` we persist one settings row:

    settings[f"admin_alert:{evt.key}"] = {
        "last_state":    "OK" | "degraded",
        "since":         ISO-8601 UTC (transition-in),
        "last_sent_at":  ISO-8601 UTC | None,
        "reason":        str | None,  # R3 — reason-change edge detection
    }

On every :func:`fire_on_transition` call we probe the event and cross:

* ``active and last_state == "OK"``       → **sent**        (edge fire)
* ``active and last_state == "degraded"`` → **suppressed** or **sent**
  depending on (a) the ``cooldown_hours`` floor since ``last_sent_at``
  AND (b) whether the current probe's reason differs from the row's
  stored reason — a reason change is a new edge (R3) that beats the
  cooldown floor and re-notifies the operator that a distinct failure
  mode is now active.
* ``not active and last_state == "degraded"`` → **recovered** (silent —
  operator does not need a second email to be told the pain stopped)
* ``not active and last_state == "OK"``   → **noop**

The send is orchestrated OFF the DB thread (F3): the state read +
edge write happen inside :func:`db_call`; :func:`_send_admin_alert`
runs in a thread via :func:`loop.run_in_executor`; the post-stamp of
``last_sent_at`` runs inside :func:`db_call` only when the send
returned ``True`` (R1) — a failed send leaves ``last_sent_at``
unchanged so the next tick's cooldown-ok evaluates true and retries.

The primitive intentionally does NOT emit an audit-chain row — these are
OPERATIONAL notifications about the running system's health.  They carry
no PHI, no per-mailbox scope, and no user action.  A ``log.info`` line is
sufficient forensic evidence.

Related invariants — see ``project_style_guide`` drawer:

* Recipient path funnels through :func:`resolve_admin_recipients` so a
  future YAML rename (like the CR-2c ``admin_email.recipients`` move)
  changes ONE call site (§Prime Directive 5 — collapse mirrored lists).
* Every SMTP message carries the ``X-Email-Triage`` loop-prevention
  header (a triage-watched admin mailbox otherwise self-referentially
  triages its own alert on delivery).
* Settings writes route through :func:`set_setting` so the in-process
  settings cache invalidates for the sibling reader.

The N-151 soft-gate (Part 1's first consumer) registers at module load;
future events (backup drift, watcher supervisor stall, disk-pressure)
register the same shape.
"""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from email_triage._isotime import parse_iso_aware
from email_triage.triage_logging import get_logger

log = get_logger("web.admin_alerts")


# ---------------------------------------------------------------------------
# Event registry
# ---------------------------------------------------------------------------

#: Settings-key prefix — one row per event.  The literal is baked into
#: :func:`_settings_key` (SSOT) so future renames touch one call site.
_SETTINGS_KEY_PREFIX = "admin_alert:"


def _settings_key(event_key: str) -> str:
    """Return the ``settings`` row key for an event.

    Kept as an SSOT helper so the pin ``test_admin_alert_settings_kv_shape_pin``
    asserts the literal shape in one place.
    """
    return f"{_SETTINGS_KEY_PREFIX}{event_key}"


@dataclass
class AdminAlertEvent:
    """A registered admin-alert event.

    Attributes
    ----------
    key
        Short, dot/underscore-safe identifier used as the settings-row
        suffix and the ``X-Email-Triage`` sub-tag.  MUST be stable across
        releases — a rename orphans the historical settings row and the
        state machine re-fires from ``last_state="OK"``.
    subject
        Email ``Subject:`` header.  Kept off the caller so the
        register-once + subject-once discipline stays enforceable.
    template_fn
        ``ctx -> (html, text)`` renderer.  ``ctx`` is whatever
        :attr:`probe_fn` returned merged with the state-machine's own
        ``since`` / ``last_sent_at`` timestamps (which come from the
        settings row, not the probe).
    cooldown_hours
        Minimum interval between re-sends while the gate is stuck
        ``degraded``.  A value < 1 collapses to "always suppress" —
        callers should pass ``0`` if they never want a repeat notice.
    probe_fn
        Pure predicate ``() -> (active, ctx)``.  MUST NOT raise — a
        raising probe would swallow the transition; wrap fallible
        probes to return ``(True, {"error": "..."})``.
    """

    key: str
    subject: str
    template_fn: Callable[[dict], tuple[str, str]]
    probe_fn: Callable[[], tuple[bool, dict]]
    cooldown_hours: int = 24


#: Process-wide registry.  Module-level like the mail-header table + the
#: audit-emitter registry — one canonical view for every consumer.
EVENT_REGISTRY: dict[str, AdminAlertEvent] = {}


def register_event(evt: AdminAlertEvent) -> None:
    """Register an event.  Idempotent under repeat imports (last-wins).

    A duplicate key overwrites — this is deliberate so a fixture / test
    can shadow the module-level registration without a teardown dance.
    """
    EVENT_REGISTRY[evt.key] = evt


def _iter_registry() -> list[AdminAlertEvent]:
    """Return a stable-order snapshot of the registry.

    Copying the values list means a probe that registers a new event
    mid-sweep does not surprise the outer loop; sorting by key keeps
    the tick's log line + the pin's traversal deterministic.
    """
    return sorted(EVENT_REGISTRY.values(), key=lambda e: e.key)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

_STATE_OK = "OK"
_STATE_DEGRADED = "degraded"


def _now_utc(now: datetime | None) -> datetime:
    """Coerce ``now`` to a timezone-aware UTC :class:`datetime`.

    Callers may pass ``None`` (production tick) or a fixed clock (tests);
    a naive ``datetime`` is treated as UTC — the same shape the settings
    row's ISO string round-trips.
    """
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_iso(value: Any) -> datetime | None:
    """Best-effort parse of an ISO-8601 timestamp; ``None`` on garbage.

    A corrupt / missing ``last_sent_at`` should not brick the state
    machine — treat it as "we have never sent" and fall through to the
    edge-fire branch.  Sibling forgiving-JSON pattern lives in
    :func:`get_setting`.
    """
    # N-263 R27 SSOT — `datetime.fromisoformat` bare-raises on the
    # trailing-``Z`` shape Python <3.11 does not accept and can leak
    # non-UTC-aware datetimes back to the state machine. `parse_iso_aware`
    # handles None / empty / unparseable / naive-→-UTC in one seam.
    dt = parse_iso_aware(value)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc)


def _load_state(db: sqlite3.Connection, evt: AdminAlertEvent) -> dict:
    """Read the persisted state row, returning a defaulted dict.

    An absent / non-dict row initialises to ``last_state=OK`` — the
    steady starting point.  This is where the state machine begins the
    first time an event is ever fired.

    Includes the ``reason`` field (added under R3): the row's
    last-known probe reason, used to detect a REASON-CHANGE edge while
    the gate remains ``degraded`` — a new distinct failure mode must
    beat the cooldown floor and re-notify the operator (see
    :func:`_decide_action_and_stamp_pre`).  Absent / legacy rows
    default ``reason=None``; ``None`` compares unequal to any real
    reason string, so the first tick that observes a concrete reason
    against a legacy row is treated as a change-edge (fires once, then
    stabilises).
    """
    from email_triage.web.db import get_setting

    raw = get_setting(db, _settings_key(evt.key))
    if not isinstance(raw, dict):
        return {
            "last_state": _STATE_OK,
            "since": None,
            "last_sent_at": None,
            "reason": None,
        }
    return {
        "last_state": raw.get("last_state") or _STATE_OK,
        "since": raw.get("since"),
        "last_sent_at": raw.get("last_sent_at"),
        "reason": raw.get("reason"),
    }


def _store_state(
    db: sqlite3.Connection, evt: AdminAlertEvent, state: dict,
) -> None:
    """Persist the state row via the settings SSOT."""
    from email_triage.web.db import set_setting

    set_setting(db, _settings_key(evt.key), state)


#: Internal action label passed from the pre-stamp helper into the async
#: orchestrator.  Not user-visible — the async :func:`fire_on_transition`
#: converts it to the outward-facing ``"sent"`` / ``"send_failed"`` labels
#: depending on the SMTP outcome.
_ACTION_SEND_PENDING = "_send_pending"


def _decide_action_and_stamp_pre(
    evt: AdminAlertEvent,
    config: Any,
    db: sqlite3.Connection,
    now_utc: datetime,
) -> tuple[str, dict | None]:
    """Sync worker: probe, load state, decide, apply the pre-stamp.

    Runs INSIDE :func:`db_call` so the state-row read + write are
    serialised under the process-wide DB lock — the SMTP send
    happens OUTSIDE this call, off the DB thread (F3).

    Returns ``(action, ctx_for_send | None)``:

    * ``("noop", None)``          — nothing to do (OK stayed OK; probe raised).
    * ``("recovered", None)``     — degraded → OK; state flipped, no send.
    * ``("suppressed", None)``    — degraded + cooldown floor + reason unchanged.
    * ``(_ACTION_SEND_PENDING, ctx)`` — the orchestrator must attempt a send.

    Pre-stamp discipline (R1):

    * ``last_state="degraded"`` + ``since=<edge_iso>`` are written UPFRONT
      so the next tick's edge-detection sees us in ``degraded`` even if
      the send fails / crashes.
    * ``last_sent_at`` is NOT stamped here — the post-stamp writes it
      only after :func:`_send_admin_alert` returns ``True``.  A false
      return leaves ``last_sent_at`` unchanged so the next tick's
      cooldown-ok evaluates true and retries.
    * ``reason`` is stored in the row so the R3 reason-change-edge
      check (below) has a comparison point on the next tick.
    """
    now_iso = now_utc.isoformat()

    try:
        active, ctx = evt.probe_fn()
    except Exception as exc:  # pragma: no cover — defensive
        # A raising probe is a defect in the caller — surface loud and
        # bail without stamping state, so the next tick retries.
        log.error(
            "admin_alert_probe_raised",
            event_key=evt.key,
            error=str(exc),
        )
        return ("noop", None)
    ctx = dict(ctx or {})
    current_reason = ctx.get("reason")

    state = _load_state(db, evt)
    last_state = state["last_state"]
    last_sent_at = _parse_iso(state.get("last_sent_at"))
    last_reason = state.get("reason")

    # --- Recovery arms (active=False) -----------------------------------
    if not active:
        if last_state == _STATE_DEGRADED:
            _store_state(db, evt, {
                "last_state": _STATE_OK,
                "since": now_iso,
                "last_sent_at": state.get("last_sent_at"),
                "reason": None,
            })
            log.info(
                "admin_alert_recovered_silent",
                event_key=evt.key,
                previously_since=state.get("since"),
            )
            return ("recovered", None)
        return ("noop", None)

    # --- Degraded arms (active=True) ------------------------------------
    if last_state == _STATE_OK:
        # OK -> degraded edge: stamp last_state + since upfront (R1);
        # last_sent_at deferred to the post-stamp so a failed send
        # doesn't trip the cooldown floor into muting the next tick.
        new_state = {
            "last_state": _STATE_DEGRADED,
            "since": now_iso,
            "last_sent_at": None,
            "reason": current_reason,
        }
        _store_state(db, evt, new_state)
        ctx.setdefault("since", now_iso)
        ctx.setdefault("last_sent_at", None)
        log.info(
            "admin_alert_edge_pending",
            event_key=evt.key,
            since=now_iso,
        )
        return (_ACTION_SEND_PENDING, ctx)

    # Still degraded — respect the cooldown floor, UNLESS the probe's
    # reason changed since the row was last stamped.  R3: a distinct
    # failure mode (e.g. was "unavailable", now "probe_error") is a NEW
    # edge from the operator's point of view; the cooldown was meant to
    # prevent noisy re-sends of the SAME condition, not to swallow the
    # transition into a different condition.
    if last_sent_at is None:
        # No timestamp on record (fresh row, corrupt, or a prior send
        # that failed and left this None): treat as "cooldown satisfied"
        # and re-send.  The alternative (suppress forever) is worse —
        # a stuck degraded state that never re-notifies is a silent lie.
        cooldown_ok = True
    else:
        cooldown_ok = (
            now_utc - last_sent_at
            >= timedelta(hours=max(0, evt.cooldown_hours))
        )

    reason_changed = (current_reason != last_reason)

    if not cooldown_ok and not reason_changed:
        log.info(
            "admin_alert_suppressed_cooldown",
            event_key=evt.key,
            since=state.get("since"),
            last_sent_at=state.get("last_sent_at"),
            cooldown_hours=evt.cooldown_hours,
            reason=current_reason,
        )
        return ("suppressed", None)

    # Fire: cooldown expired OR reason changed.
    # ``since`` is preserved — it points at the ORIGINAL degradation
    # edge; restoring it on every re-send / reason-flip would lie about
    # how long the operator has been in the dark.  ``reason`` flips to
    # the new value so the next tick compares against the current one.
    # ``last_sent_at`` is preserved here (post-stamp writes on success);
    # a failed send therefore leaves the previous timestamp in place.
    new_state = {
        "last_state": _STATE_DEGRADED,
        "since": state.get("since") or now_iso,
        "last_sent_at": state.get("last_sent_at"),
        "reason": current_reason,
    }
    _store_state(db, evt, new_state)
    ctx.setdefault("since", new_state["since"])
    ctx.setdefault("last_sent_at", state.get("last_sent_at"))
    log.info(
        (
            "admin_alert_reason_change_pending"
            if reason_changed and not cooldown_ok
            else "admin_alert_resend_pending"
        ),
        event_key=evt.key,
        since=new_state["since"],
        reason=current_reason,
        prior_reason=last_reason,
        cooldown_hours=evt.cooldown_hours,
    )
    return (_ACTION_SEND_PENDING, ctx)


def _stamp_last_sent_at_success(
    evt: AdminAlertEvent,
    db: sqlite3.Connection,
    now_utc: datetime,
) -> None:
    """Post-send: write ``last_sent_at=now`` only after a successful send.

    Runs INSIDE :func:`db_call`.  Re-reads the state row so a
    concurrent recovery (degraded → OK) that raced between the
    pre-stamp and the send is preserved — we only overwrite
    ``last_sent_at``, not the whole row.  A missing/torn row falls
    back to a fresh degraded snapshot so the next tick's edge
    detection is stable.
    """
    from email_triage.web.db import get_setting

    now_iso = now_utc.isoformat()
    raw = get_setting(db, _settings_key(evt.key))
    if not isinstance(raw, dict):
        # Race / wipe: reconstruct a minimal degraded row.  Since is
        # unknown → use now; without it the next tick's ``since`` field
        # would be None which the render path treats as "just now".
        state = {
            "last_state": _STATE_DEGRADED,
            "since": now_iso,
            "last_sent_at": now_iso,
            "reason": None,
        }
    else:
        state = dict(raw)
        state["last_sent_at"] = now_iso
    _store_state(db, evt, state)


async def fire_on_transition(
    evt: AdminAlertEvent,
    config: Any,
    db: sqlite3.Connection,
    *,
    now: datetime | None = None,
) -> str:
    """Run the state machine for one event.

    Returns one of ``"sent"``, ``"send_failed"``, ``"suppressed"``,
    ``"recovered"``, ``"noop"``.  The label doubles as the tick's
    telemetry (see :func:`fire_all`'s dict result) — do not repurpose
    the strings without updating the corresponding pin.

    Async orchestration (F3):

    1. **Decide + pre-stamp** — :func:`_decide_action_and_stamp_pre`
       runs inside :func:`db_call` so the state read + edge-write are
       serialised under the process-wide DB lock.
    2. **SMTP send** — :func:`_send_admin_alert` runs in a thread via
       :func:`loop.run_in_executor` so the socket / TLS / DNS work
       happens OFF the DB thread (the writer thread otherwise stalls
       for the ~seconds an SMTP round-trip takes).
    3. **Post-stamp on success** — :func:`_stamp_last_sent_at_success`
       runs inside :func:`db_call` and writes ``last_sent_at=now``
       ONLY when the send returned ``True`` (R1).  A false / raised
       send leaves ``last_sent_at`` unchanged → next tick's
       cooldown-ok evaluates true → retry.
    """
    from email_triage.web.db_threadpool import db_call

    now_utc = _now_utc(now)
    action, ctx = await db_call(
        _decide_action_and_stamp_pre, evt, config, db, now_utc,
    )
    if action != _ACTION_SEND_PENDING:
        return action

    # Send OFF the DB thread — the module-level ``_send_admin_alert``
    # lookup happens at call time so an active ``patch.object`` in a
    # test still intercepts the executor's callable.
    loop = asyncio.get_running_loop()
    try:
        sent_ok = await loop.run_in_executor(
            None, _send_admin_alert, config, evt, ctx,
        )
    except Exception as exc:  # pragma: no cover — defensive
        # A raise from the sender is treated identically to a
        # returned-False: state has been pre-stamped so the next tick
        # still sees the degradation, and last_sent_at is left blank
        # so the next tick will retry the send.
        log.error(
            "admin_alert_send_raised",
            event_key=evt.key,
            error=str(exc),
        )
        return "send_failed"

    if not sent_ok:
        log.warning(
            "admin_alert_send_failed_retry_next_tick",
            event_key=evt.key,
        )
        return "send_failed"

    await db_call(_stamp_last_sent_at_success, evt, db, now_utc)
    log.info("admin_alert_sent", event_key=evt.key)
    return "sent"


async def fire_all(
    config: Any, db: sqlite3.Connection,
) -> dict[str, str]:
    """Run every registered event, returning ``{key: outcome}``.

    Wired into the digest tick.  A single event's failure MUST NOT
    block the others — each is wrapped in a try/except that records
    ``"noop"`` and moves on.  ``fire_on_transition`` is now async (F3),
    so the sweep awaits each event serially — the state machine is
    per-event and the SMTP work already runs off the DB thread; adding
    parallel gather here would only muddy the log ordering.
    """
    results: dict[str, str] = {}
    for evt in _iter_registry():
        try:
            results[evt.key] = await fire_on_transition(evt, config, db)
        except Exception as exc:  # pragma: no cover — defensive
            log.error(
                "admin_alert_fire_all_event_raised",
                event_key=evt.key,
                error=str(exc),
            )
            results[evt.key] = "noop"
    return results


# ---------------------------------------------------------------------------
# SMTP sender — shared by every event
# ---------------------------------------------------------------------------

def _send_admin_alert(
    config: Any, evt: AdminAlertEvent, ctx: dict,
) -> bool:
    """Assemble + send one admin-alert email.

    Returns ``True`` when :func:`send_smtp_message` returned without
    raising (the SMTP hop accepted the message); ``False`` on every
    early-return / failure path.  The async orchestrator
    (:func:`fire_on_transition`) uses this boolean to gate the
    post-stamp of ``last_sent_at`` — a false return leaves the
    timestamp unchanged so the next tick retries (R1).

    Fail-CLOSED-BUT-QUIET on the send itself: unconfigured recipient
    list or SMTP host is logged at WARNING and returns False; an SMTP
    raise is logged at ERROR and returns False.  The state machine
    already stamped ``last_state=degraded`` upstream — an escape here
    would just shoot the messenger.
    """
    from email.message import EmailMessage

    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER, build_triage_header,
    )
    from email_triage.secrets import read_secret, SecretsDecryptError
    from email_triage._secret_keys import SMTP_PASSWORD_KEY
    from email_triage.web.daily_health import resolve_admin_recipients
    from email_triage.web.smtp_send import (
        format_from_header, send_smtp_message, stamp_default_message_headers,
    )

    recipients = resolve_admin_recipients(config)
    if not recipients:
        log.warning(
            "admin_alert_skipped_no_recipients", event_key=evt.key,
        )
        return False
    smtp = getattr(config, "smtp", None)
    if smtp is None or not getattr(smtp, "host", None):
        log.warning(
            "admin_alert_skipped_smtp_unconfigured", event_key=evt.key,
        )
        return False

    try:
        html, text = evt.template_fn(ctx)
    except Exception as exc:
        log.error(
            "admin_alert_template_raised",
            event_key=evt.key,
            error=str(exc),
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = evt.subject
    stamp_default_message_headers(msg)
    # Loop-prevention stamp — an admin recipient's inbox is likely
    # watched by triage itself; the header keeps the alert out of the
    # triage pipeline on delivery.
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header(
        f"admin-alert-{evt.key}",
    )
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    msg["From"] = format_from_header(smtp.from_addr, smtp.from_name)
    msg["To"] = ", ".join(recipients)

    password = ""
    secrets = getattr(config, "_admin_alert_secrets", None)
    # The primitive is called from the daily-health tick, which already
    # holds ``app.state.secrets``.  For unit tests + the callsite in
    # digest.py we accept a ``secrets`` object riding on ``config`` or
    # skip password read entirely — the sender treats an empty password
    # the same as an unauthenticated SMTP hop (dev/test).
    if secrets is not None:
        try:
            password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
        except SecretsDecryptError:
            log.error(
                "admin_alert_smtp_password_unreadable",
                event_key=evt.key,
            )
            return False

    try:
        send_smtp_message(
            msg,
            smtp_host=smtp.host,
            smtp_port=smtp.port,
            smtp_user=smtp.username,
            smtp_password=password,
            use_tls=smtp.use_tls,
        )
    except Exception as exc:
        log.error(
            "admin_alert_send_failed",
            event_key=evt.key,
            error=str(exc),
        )
        return False

    log.info(
        "admin_alert_delivered",
        event_key=evt.key,
        recipients=len(recipients),
    )
    return True


# ---------------------------------------------------------------------------
# N-151 first consumer — MSAL soft-gate active
# ---------------------------------------------------------------------------
#
# When the MSAL master key becomes unavailable (missing keyring, corrupt
# secret row, master-key mismatch) the O365 provider silently degrades
# to "no cached token" and re-prompts on every hop.  The N-151 soft-gate
# probe surfaces that state; this alert surfaces it to the operator so
# they can act on it before users hit a re-auth loop.

def _assemble_n151_soft_gate_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text) for the N-151 soft-gate alert.

    Mirrors the update-failed email's minimal-styling body — same
    palette (amber for a warning, no red — the system is degraded, not
    down) and the same ``max-width: 680px`` container.  Contains NO
    PHI: the reason is a fixed enum string, ``since`` is a timestamp.
    """
    import html as _html

    reason = str(ctx.get("reason") or "unknown")
    since = str(ctx.get("since") or "just now")
    what_now_url = (
        "https://github.com/unlimited-data-works-llc/email-triage/blob/main/"
        "internal documentation"
    )

    text_lines = [
        "Email Triage — credential store SOFT-gate active",
        "=" * 50,
        f"Since: {since}",
        f"Reason: {reason}",
        "",
        "What this means:",
        "  The MSAL cache-encryption master key is currently unavailable.",
        "  Office 365 accounts will re-prompt for sign-in on every hop",
        "  until the key is restored. Existing background triage keeps",
        "  running against non-O365 providers.",
        "",
        "What to do:",
        "  1. Check the /health endpoint for the msal_master_key_status.",
        "  2. See the recovery guide:",
        f"     {what_now_url}",
        "",
        "This is a repeat-suppressed alert — you will not be re-emailed",
        "for at least 24 hours while the gate stays active.",
    ]
    text = "\n".join(text_lines)

    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        '<h2 style="color:#b45309;">Email Triage — credential store '
        'SOFT-gate active</h2>'
        '<div style="padding: 0.75rem 1rem; background: #fff8e1; '
        'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
        '<ul style="margin:0;padding-left:1.25rem;">'
        f'<li><strong>Since:</strong> {_html.escape(since)}</li>'
        f'<li><strong>Reason:</strong> <code>{_html.escape(reason)}</code></li>'
        '</ul></div>'
        '<h3>What this means</h3>'
        '<p>The MSAL cache-encryption master key is currently unavailable. '
        'Office 365 accounts will re-prompt for sign-in on every hop until '
        'the key is restored. Existing background triage keeps running '
        'against non-O365 providers.</p>'
        '<h3>What to do</h3>'
        '<ol>'
        '<li>Check the <code>/health</code> endpoint for '
        '<code>msal_master_key_status</code>.</li>'
        f'<li>See the '
        f'<a href="{_html.escape(what_now_url)}">recovery guide</a>.</li>'
        '</ol>'
        '<p style="color:#555;font-size:0.9em;">'
        'This is a repeat-suppressed alert — you will not be re-emailed '
        'for at least 24 hours while the gate stays active.'
        '</p>'
        '</div>'
    )
    return html, text


def _n151_probe() -> tuple[bool, dict]:
    """Probe wrapper — bounces exceptions into a fail-CLOSED tuple.

    F1 fold (2026-07-10): routed through the SSOT
    :func:`n151_soft_gate_state` — a single atomic probe returning
    ``(active, reason)``.  The prior dual-call
    (``n151_soft_gate_active()`` + ``n151_soft_gate_reason()``) was
    tearable on a transition tick (probe A saw the master key, probe
    B ran after a keyring flap and disagreed).  The SSOT accessor
    caches the probe result for the duration of one call.

    HIPAA-FOLD-1 (2026-07-10): a raise from the probe is bounced into
    the FIXED ``"probe_error"`` enum — NOT the exception string.  The
    exception's ``__str__`` can carry keyring / master-key metadata
    that leaks into the outbound SMTP body (a §164.514(b) minimum-
    necessary violation) since the admin-alert template renders the
    ``reason`` field verbatim.  Fixed enum only.
    """
    try:
        from email_triage.providers._msal_cache_crypto import (
            n151_soft_gate_state,
        )
        active, reason = n151_soft_gate_state()
        return (active, {"reason": reason, "since": None})
    except Exception:  # pragma: no cover — defensive
        return (True, {"reason": "probe_error", "since": None})


N151_SOFT_GATE_EVENT = AdminAlertEvent(
    key="n151_soft_gate",
    subject="[email-triage] Attention — credential store SOFT-gate active",
    template_fn=_assemble_n151_soft_gate_alert,
    cooldown_hours=24,
    probe_fn=_n151_probe,
)

register_event(N151_SOFT_GATE_EVENT)
