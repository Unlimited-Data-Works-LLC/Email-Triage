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
        ``degraded``.  ``0`` RE-SENDS ON EVERY TICK (the floor is
        ``elapsed >= 0``); the earlier docstring said a value below 1
        meant "always suppress", which the code never did (punch 569).
        For an event that must email once per transition, use
        ``repeat_while_degraded=False`` instead.
    repeat_while_degraded
        ``True`` (the default): re-send every ``cooldown_hours`` while
        the condition holds.  ``False`` (punch 569): send on the edge and
        on a REASON change only; a send that failed (``last_sent_at``
        still ``None``) is retried regardless, so the one email is not
        lost to a transient SMTP failure.
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
    #: Optional DB-reading probe ``(db) -> (active, ctx)`` (same
    #: MUST-NOT-raise contract), run inside the same ``db_call`` as the state
    #: read. It is used only while ``probe_fn`` is :func:`probe_reads_db`, so
    #: ``probe_fn`` stays the one seam that forces a probe (the table-driven
    #: edge pin patches it on every registered event).
    probe_db_fn: Callable[[sqlite3.Connection], tuple[bool, dict]] | None = None
    repeat_while_degraded: bool = True
    #: Punch 569: ``probe_fn`` reads the FILESYSTEM, not the DB, so the
    #: orchestrator runs it in a worker thread BEFORE the ``db_call`` hop and
    #: the state machine consumes that result. A filesystem scan never holds
    #: the process-wide DB lock (the N-543 rule), and this sweep ticks every
    #: 60 s. Same MUST-NOT-raise contract; a raise is the same ``noop``.
    probe_off_lock: bool = False


#: An off-lock probe returns this to skip a tick: no state change, no email.
PROBE_SKIP: tuple[bool, dict] = (False, {"reason": "__skip__"})


def probe_reads_db() -> tuple[bool, dict]:
    """Sentinel ``probe_fn`` for an event whose real probe is ``probe_db_fn``."""
    raise RuntimeError("probe_reads_db is a sentinel; the state machine calls probe_db_fn")


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
    probed: tuple[bool, dict] | None = None,
) -> tuple[str, dict | None]:
    """Sync worker: probe, load state, decide, apply the pre-stamp.

    ``probed`` is the result of an off-lock probe (``probe_off_lock``),
    already run by :func:`fire_on_transition`; when given, no probe runs here.

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
        if probed is not None:
            active, ctx = probed
        elif evt.probe_fn is probe_reads_db and evt.probe_db_fn is not None:
            active, ctx = evt.probe_db_fn(db)
        else:
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
    elif not evt.repeat_while_degraded:
        # Punch 569: a once-per-transition event never re-sends the SAME
        # condition; the reason-change edge below still fires.
        cooldown_ok = False
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
    probed: tuple[bool, dict] | None = None
    if evt.probe_off_lock:
        # Punch 569: a filesystem probe runs OFF the DB lock (N-543).
        try:
            probed = await asyncio.to_thread(evt.probe_fn)
        except Exception as exc:  # pragma: no cover — defensive
            log.error(
                "admin_alert_probe_raised",
                event_key=evt.key,
                error=str(exc),
            )
            return "noop"
        if probed is PROBE_SKIP:
            return "noop"
    action, ctx = await db_call(
        _decide_action_and_stamp_pre, evt, config, db, now_utc, probed,
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

    # Punch 569: the app's own origin, so a template can link to the page
    # that fixes the condition. ``push.public_url`` is the one configured
    # origin; empty when unset, and a template must then say where to go
    # in words instead of printing a broken link.
    ctx = dict(ctx)
    ctx.setdefault("app_url", app_base_url(config))
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
    stamp_default_message_headers(msg, from_addr=smtp.from_addr)
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


def app_base_url(config: Any) -> str:
    """``push.public_url`` without a trailing slash, or "".

    The app's own origin for links in admin emails. Shared by the admin
    alerts, the daily health embedding section and the regulatory-clock
    escalation push (which read a non-existent ``config.public_url`` before
    punch 569, so its link never printed)."""
    push = getattr(config, "push", None)
    return str(getattr(push, "public_url", "") or "").rstrip("/")


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
    from email_triage.update_check import PUBLIC_REPO_URL

    # Punch 585: this linked internal documentation in the PRIVATE
    # repository, a file that never existed. The recovery steps now live in the
    # shipped install.md (scripts/publish-docs-allowlist.txt), in the subsection
    # this alert is named after (panel B5 hipaa B-2).
    what_now_url = (
        f"{PUBLIC_REPO_URL}/blob/main/docs/install.md"
        "#if-the-credential-store-soft-gate-alert-fires"
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
        "  1. Check msal_master_key_status on /health/detail (admin sign-in).",
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
        '<li>Check <code>/health/detail</code> (admin sign-in) for '
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


# ---------------------------------------------------------------------------
# N-564 — account-bound watches the fire gate refuses
# ---------------------------------------------------------------------------


def _watch_unattributed_probe(db: sqlite3.Connection) -> tuple[bool, dict]:
    """Active while any enabled account-bound watch is refused by the fire
    gate (no creator, a creator who lost access, a disabled creator, or on a
    HIPAA-effective mailbox a creator who is not its owner). Counts
    only: no watch names, no account ids (fail-CLOSED on error, fixed enum)."""
    try:
        from email_triage.web.email_watches import count_not_firing_watches
        n, unattributed = count_not_firing_watches(db)
        return (n > 0, {"count": n, "unattributed": unattributed,
                        "reason": "watches_not_firing"})
    except Exception:  # pragma: no cover — defensive
        return (True, {"count": None, "unattributed": None,
                       "reason": "probe_error"})


def _assemble_watch_unattributed_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text). Counts + the owner's next step; no PHI."""
    import html as _html

    n = ctx.get("count")
    k = ctx.get("unattributed")
    count = "an unknown number of" if n is None else str(n)
    lines = [
        "Email Triage — mail watches are not firing",
        "=" * 50,
        f"{count} enabled watch(es) do not fire, because the person recorded "
        "as creating them may not run a watch on that mailbox (or no one is "
        "recorded).",
    ]
    if k:
        lines += [
            "",
            f"{k} of them have no recorded creator. Watches created through "
            "the API before this release were stored that way. To reactivate "
            "one, the owner of the mailbox opens their Watches page, checks "
            "the alert address and webhook URL, and saves the watch.",
        ]
    if n is None or k is None or n > k:
        lines += [
            "",
            "The others were created by someone whose access to the mailbox "
            "was removed or whose account is disabled, or, on a mailbox marked "
            "for protected health information, by someone other than its "
            "owner: there only the owner's watches run. The owner deletes the "
            "watch or creates it again.",
        ]
    text = "\n".join(lines)
    body = _html.escape(text).replace("\n", "<br>")
    html = (
        '<div style="max-width:680px;font-family:sans-serif;">'
        f"{body}</div>"
    )
    return html, text


# ---------------------------------------------------------------------------
# Punch 569 D5 — embedding runtime update required
# ---------------------------------------------------------------------------
#
# The operator (2026-10-02): admins rarely log in, and must not learn that the
# embedding runtime needs updating from a failed embedding. So the moment a new
# image's manifest leaves the installed runtime stale (still serving) or refused
# (a security change), the admin gets ONE email with a link to the one-click
# action; the daily health email repeats it until it is fixed. Once per
# transition: ``repeat_while_degraded=False``, and the probe's ``reason`` is the
# notice's stable ``alert_reason``, so stale_ok -> security-refused (a second
# image) is a second email and a re-read of the same state is not.

def _embedding_runtime_probe() -> tuple[bool, dict]:
    """Probe wrapper over ``embedding_bits.update_notice`` (the notice SSOT).

    Fail-CLOSED like N-151: a raise reads as active with the FIXED
    ``probe_error`` reason, never the exception text (which can carry volume
    paths into an email).
    """
    try:
        from email_triage.embedding_bits import update_in_progress, update_notice

        if update_in_progress():
            # Panel B3 DA F569-4: mid-swap the prefix is two renames apart, so a
            # scan can read a mixed tree and email a false alarm. Skip this tick.
            return PROBE_SKIP
        notice = update_notice()
    except Exception:  # pragma: no cover — defensive
        return (True, {"reason": "probe_error", "notice": None})
    if notice is None:
        return (False, {"reason": None})
    if notice.get("auto") or notice.get("integrity_wait"):
        # Operator decision 2026-10-25: the app updates the runtime itself, so
        # this "click the button" email would be wrong (and a duplicate of the
        # after-the-fact notice minutes later). A failed automatic attempt has
        # its own event (EMBEDDING_RUNTIME_AUTO_FAILED_EVENT), an INTEGRITY
        # refusal (which the app never heals) its own URGENT one
        # (EMBEDDING_RUNTIME_INTEGRITY_EVENT); a restart request (kind
        # "restart") still comes through here.
        return (False, {"reason": None})
    return (True, {"reason": notice["alert_reason"], "notice": notice})


def _embedding_integrity_probe() -> tuple[bool, dict]:
    """Probe for an INTEGRITY refusal while the auto-updater is on: the installed
    runtime no longer matches the record made when it was verified (or the image's
    manifest cannot be read), embedding is off, and the app will NOT replace it by
    itself (hipaa-sme R3, possible tamper evidence under §164.312(c)(1)). Fail
    CLOSED like its siblings: a raise reads as active with a FIXED reason."""
    try:
        from email_triage.embedding_bits import update_in_progress, update_notice

        if update_in_progress():
            return PROBE_SKIP
        notice = update_notice()
    except Exception:  # pragma: no cover — defensive
        return (True, {"reason": "probe_error", "notice": None})
    if notice is None or not notice.get("integrity_wait"):
        return (False, {"reason": None})
    return (True, {"reason": notice["alert_reason"], "notice": notice})


def _assemble_embedding_integrity_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text) for an integrity refusal. No PHI: a fixed token, the
    notice's own fixed sentences, no path. For ``manifest_unreadable`` the image,
    not the volume, is at fault, and the text says so."""
    import html as _html

    from email_triage.embedding_bits import UPDATE_ACTION_PATH

    notice = ctx.get("notice") or {
        "headline": "Embedding runtime: the integrity status check failed",
        "consequence": (
            "The app could not read the state of the embedding runtime. "
            "Open the AI Backends page to see it."
        ),
        "integrity_token": "",
    }
    token = str(notice.get("integrity_token") or "")
    reason = str(notice.get("integrity_reason") or "")
    image_at_fault = token == "manifest_unreadable"
    base = str(ctx.get("app_url") or "")
    where = f"{base}{UPDATE_ACTION_PATH}" if base else ""
    where_text = where or (
        "the AI Backends tab of the email-triage admin settings (Config > AI Backends)"
    )
    if image_at_fault:
        steps = [
            "What to do:",
            "  Redeploy a good image. The fault is in the image, not in the data",
            "  volume, and the app cannot update the runtime from it.",
        ]
    else:
        steps = [
            "What to do:",
            "  1. Read what changed (above), and on the AI Backends page the runtime",
            "     card names the same packages. The audit log records this detection",
            "     (event embedding_runtime_update, outcome denied:integrity).",
            "  2. When you are satisfied, click [Update embedding runtime] here:",
            f"     {where_text}",
            "  The replaced files are kept on the data volume for inspection.",
        ]
    lines = [
        f"Email Triage — {notice['headline']}",
        "=" * 50,
        notice["consequence"],
        *(["", f"What changed: {reason}"] if reason else []),
        "",
        *steps,
        "",
        "The app does not replace this runtime by itself. You get this email again",
        "every 6 hours until it is fixed.",
    ]
    text = "\n".join(lines)
    action_html = (
        "<p>Redeploy a good image. The fault is in the image, not in the data "
        "volume, and the app cannot update the runtime from it.</p>"
        if image_at_fault else
        "<ol><li>Read what changed (above); on the AI Backends page the runtime card "
        "names the same packages. The audit log records this detection (event "
        "<code>embedding_runtime_update</code>, outcome <code>denied:integrity</code>)."
        "</li>"
        "<li>When you are satisfied, click <strong>Update embedding runtime</strong>"
        + (f': <a href="{_html.escape(where)}">{_html.escape(where)}</a>' if where
           else f" on {_html.escape(where_text)}")
        + ".</li></ol><p>The replaced files are kept on the data volume for inspection.</p>"
    )
    changed_html = (
        f'<p style="margin:0.5rem 0 0 0;"><strong>What changed:</strong> '
        f"<code>{_html.escape(reason)}</code></p>" if reason else ""
    )
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        f'<h2 style="color:#b91c1c;">{_html.escape(notice["headline"])}</h2>'
        '<div style="padding: 0.75rem 1rem; background: #fef2f2; '
        'border-left: 3px solid #b91c1c; margin: 0.5rem 0;">'
        f'<p style="margin:0;">{_html.escape(notice["consequence"])}</p>'
        + changed_html
        + "</div>"
        "<h3>What to do</h3>"
        + action_html
        + '<p style="color:#555;font-size:0.9em;">The app does not replace this '
        "runtime by itself. You get this email again every 6 hours until it is "
        "fixed.</p></div>"
    )
    return html, text


def _embedding_auto_failed_probe() -> tuple[bool, dict]:
    """Probe for a FAILED automatic update that leaves embedding off or a
    security fix undone. Fail-CLOSED like :func:`_embedding_runtime_probe`.

    A failure while the old runtime still serves and the change is not a
    security fix is NOT an email (it is a daily-health line and a retry): the
    operator's rule is that the old set keeps serving then.
    """
    try:
        from email_triage.embedding_bits import (
            SECURITY_NONE, update_in_progress, update_notice,
        )

        if update_in_progress():
            return PROBE_SKIP
        notice = update_notice()
    except Exception:  # pragma: no cover — defensive
        return (True, {"reason": "probe_error", "notice": None})
    if notice is None or notice.get("kind") != "auto_failed":
        return (False, {"reason": None})
    if notice.get("serving") and notice.get("security") == SECURITY_NONE:
        return (False, {"reason": None})
    return (True, {"reason": notice["alert_reason"], "notice": notice})


def _embedding_auto_updated_probe(db: sqlite3.Connection) -> tuple[bool, dict]:
    """Probe for the after-the-fact "it was updated" notice: active while the
    last automatic update is inside the notice window. The reason carries the
    update's timestamp, so each update is one email and a re-read is not."""
    try:
        from email_triage.web.embedding_update_runner import (
            read_auto_state, recent_auto_update,
        )

        rec = recent_auto_update(read_auto_state(db))
    except Exception:  # pragma: no cover — defensive
        return (False, {"reason": None})
    if rec is None:
        return (False, {"reason": None})
    return (True, {"reason": f"updated:{rec.get('at')}", "updated": rec})


def _assemble_embedding_auto_failed_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text) for a failed automatic update. No PHI: set versions,
    a security yes/no/unknown, advisory ids, an error CLASS name, fixed
    sentences."""
    import html as _html

    from email_triage.embedding_bits import SECURITY_FIX, SECURITY_UNKNOWN

    notice = ctx.get("notice") or {
        "headline": "Embedding runtime: the automatic update status check failed",
        "consequence": (
            "The app could not read the state of the embedding runtime. "
            "Open the AI Backends page to see it."
        ),
        "security": SECURITY_UNKNOWN,
        "versions": "",
        "advisories": [],
        "failures": 0,
        "error_class": "",
    }
    base = str(ctx.get("app_url") or "")
    where = f"{base}/config?tab=ai_backends" if base else ""
    where_text = where or (
        "the AI Backends tab of the email-triage admin settings (Config > AI Backends)"
    )
    security_note = (
        "This release fixes a security problem in the embedding runtime."
        if notice.get("security") == SECURITY_FIX else ""
    )
    advisories = [str(a) for a in notice.get("advisories") or []]
    lines = [
        f"Email Triage — {notice['headline']}",
        "=" * 50,
        notice["consequence"],
    ]
    if security_note:
        lines.append(security_note)
    if notice.get("versions"):
        lines.append(f"Manifest:  {notice['versions']}")
    if advisories:
        lines.append(f"Advisories: {', '.join(advisories)}")
    lines += [
        "",
        "What the app is doing: it retries by itself, with longer waits between",
        "attempts (15 minutes, doubling, up to 6 hours). Nothing needs clicking.",
        "If it keeps failing, the error class above names the step; the",
        "application log has the detail.",
        f"  {where_text}",
        "",
        "You get this email again every 6 hours until the runtime is current.",
    ]
    text = "\n".join(lines)
    facts = []
    if notice.get("versions"):
        facts.append(f"<li><strong>Manifest:</strong> {_html.escape(notice['versions'])}</li>")
    if advisories:
        facts.append(
            "<li><strong>Advisories:</strong> "
            + ", ".join(f"<code>{_html.escape(a)}</code>" for a in advisories)
            + "</li>"
        )
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        f'<h2 style="color:#b91c1c;">{_html.escape(notice["headline"])}</h2>'
        '<div style="padding: 0.75rem 1rem; background: #fef2f2; '
        'border-left: 3px solid #b91c1c; margin: 0.5rem 0;">'
        f'<p style="margin:0;">{_html.escape(notice["consequence"])}</p>'
        + (f'<p style="margin:0.5rem 0 0 0;">{_html.escape(security_note)}</p>' if security_note else "")
        + (f'<ul style="margin:0.5rem 0 0 0;padding-left:1.25rem;">{"".join(facts)}</ul>' if facts else "")
        + '</div>'
        '<h3>What the app is doing</h3>'
        '<p>It retries by itself, with longer waits between attempts (15 minutes, '
        'doubling, up to 6 hours). Nothing needs clicking. If it keeps failing, '
        'the application log has the detail.</p>'
        + (f'<p><a href="{_html.escape(where)}">{_html.escape(where)}</a></p>' if where else "")
        + '<p style="color:#555;font-size:0.9em;">You get this email again every '
        '6 hours until the runtime is current.</p>'
        '</div>'
    )
    return html, text


def _assemble_embedding_auto_updated_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text) for the after-the-fact notice. Read-only news: what
    changed and when, never a request."""
    import html as _html

    from email_triage.web.embedding_update_runner import describe_auto_update

    d = describe_auto_update(ctx.get("updated") or {})
    lines = [
        f"Email Triage — {d['headline']}",
        "=" * 50,
        "The app replaced the embedding runtime by itself. Every file was",
        "hash-checked against this release's manifest before it went live, and",
        "the previous runtime was kept until the new one verified.",
        "",
        f"Manifest:  {d['versions']}",
        f"Security:  {d['security_label']}",
    ]
    if d["advisories"]:
        lines.append(f"Advisories: {', '.join(d['advisories'])}")
    if d["reason"]:
        lines.append(f"Trigger:   {d['reason']}")
    if d["at"]:
        lines.append(f"When:      {d['at']}")
    if d["restart_message"]:
        lines += ["", "What to do:", f"  {d['restart_message']}"]
    else:
        lines += ["", "Nothing to do."]
    text = "\n".join(lines)
    facts = [
        f"<li><strong>Manifest:</strong> {_html.escape(d['versions'])}</li>",
        f"<li><strong>Security:</strong> {_html.escape(d['security_label'])}</li>",
    ]
    if d["advisories"]:
        facts.append(
            "<li><strong>Advisories:</strong> "
            + ", ".join(f"<code>{_html.escape(a)}</code>" for a in d["advisories"])
            + "</li>"
        )
    if d["reason"]:
        facts.append(f"<li><strong>Trigger:</strong> <code>{_html.escape(d['reason'])}</code></li>")
    if d["at"]:
        facts.append(f"<li><strong>When:</strong> {_html.escape(d['at'])}</li>")
    tail = (
        f"<p><strong>{_html.escape(d['restart_message'])}</strong></p>"
        if d["restart_message"] else "<p>Nothing to do.</p>"
    )
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        f'<h2>{_html.escape(d["headline"])}</h2>'
        "<p>The app replaced the embedding runtime by itself. Every file was "
        "hash-checked against this release's manifest before it went live, and "
        "the previous runtime was kept until the new one verified.</p>"
        f'<ul style="padding-left:1.25rem;">{"".join(facts)}</ul>'
        + tail
        + '</div>'
    )
    return html, text


def _assemble_embedding_runtime_alert(ctx: dict) -> tuple[str, str]:
    """Render (html, text) for the embedding-runtime alert. No PHI: set
    versions, a security yes/no/unknown, advisory ids from the image's own
    manifest, and fixed sentences."""
    import html as _html

    from email_triage.embedding_bits import (
        RESTART_MESSAGE, SECURITY_FIX, SECURITY_NONE, SECURITY_UNKNOWN,
        UPDATE_ACTION_PATH,
    )

    notice = ctx.get("notice") or {
        "kind": "update",
        "headline": "Embedding runtime: the status check failed",
        "consequence": (
            "The app could not read the state of the embedding runtime. "
            "Open the AI Backends page to see it."
        ),
        "security": SECURITY_UNKNOWN,
        "versions": "",
        "advisories": [],
    }
    base = str(ctx.get("app_url") or "")
    if base:
        where = f"{base}{UPDATE_ACTION_PATH}"
        where_text = where
    else:
        where = ""
        where_text = (
            "the AI Backends tab of the email-triage admin settings "
            "(Config > AI Backends)"
        )
    is_restart = notice.get("kind") == "restart"
    security = str(notice.get("security") or "")
    security_label = {
        SECURITY_FIX: "yes — this release fixes a security problem",
        # Panel B3 hipaa F2b: what is known is the release-time flag, not
        # the absence of a security problem.
        SECURITY_NONE: "no (not marked as a security fix at release)",
        SECURITY_UNKNOWN: "unknown — treated as a security fix",
    }.get(security, "")
    advisories = [str(a) for a in notice.get("advisories") or []]
    lines = [
        f"Email Triage — {notice['headline']}",
        "=" * 50,
    ]
    if notice.get("versions"):
        lines.append(f"Manifest:  {notice['versions']}")
    if security_label:
        lines.append(f"Security:  {security_label}")
    if advisories:
        lines.append(f"Advisories: {', '.join(advisories)}")
    lines += ["", notice["consequence"], ""]
    if is_restart:
        lines += ["What to do:", f"  {RESTART_MESSAGE[0].upper()}{RESTART_MESSAGE[1:]}."]
    else:
        lines += [
            "What to do:",
            "  Open the page below and click [Update embedding runtime].",
            "  The new runtime is installed beside the old one, every file is",
            "  hash-checked, and the old one is kept until the new one verifies.",
            f"  {where_text}",
        ]
    lines += [
        "",
        "You get this email once for this state. The daily health email",
        "repeats it until it is fixed.",
    ]
    text = "\n".join(lines)

    facts = []
    if notice.get("versions"):
        facts.append(f"<li><strong>Manifest:</strong> {_html.escape(notice['versions'])}</li>")
    if security_label:
        facts.append(f"<li><strong>Security:</strong> {_html.escape(security_label)}</li>")
    if advisories:
        facts.append(
            "<li><strong>Advisories:</strong> "
            + ", ".join(f"<code>{_html.escape(a)}</code>" for a in advisories)
            + "</li>"
        )
    if is_restart:
        action_html = (
            f"<p><strong>{_html.escape(RESTART_MESSAGE[0].upper() + RESTART_MESSAGE[1:])}.</strong></p>"
        )
    elif where:
        action_html = (
            '<p>Open the page and click <strong>Update embedding runtime</strong>: '
            f'<a href="{_html.escape(where)}">{_html.escape(where)}</a></p>'
            "<p>The new runtime is installed beside the old one, every file is "
            "hash-checked, and the old one is kept until the new one verifies.</p>"
        )
    else:
        action_html = (
            f"<p>Open {_html.escape(where_text)} and click "
            "<strong>Update embedding runtime</strong>.</p>"
        )
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        f'<h2 style="color:#b45309;">{_html.escape(notice["headline"])}</h2>'
        '<div style="padding: 0.75rem 1rem; background: #fff8e1; '
        'border-left: 3px solid #d17b00; margin: 0.5rem 0;">'
        f'<p style="margin:0;">{_html.escape(notice["consequence"])}</p>'
        + (f'<ul style="margin:0.5rem 0 0 0;padding-left:1.25rem;">{"".join(facts)}</ul>' if facts else "")
        + '</div>'
        '<h3>What to do</h3>'
        + action_html
        + '<p style="color:#555;font-size:0.9em;">You get this email once for '
        'this state. The daily health email repeats it until it is fixed.</p>'
        '</div>'
    )
    return html, text


WATCH_UNATTRIBUTED_EVENT = AdminAlertEvent(
    key="watch_unattributed",
    subject="[email-triage] Attention — mail watches not firing",
    template_fn=_assemble_watch_unattributed_alert,
    cooldown_hours=24,
    probe_fn=probe_reads_db,
    probe_db_fn=_watch_unattributed_probe,
)

register_event(WATCH_UNATTRIBUTED_EVENT)


EMBEDDING_RUNTIME_UPDATE_EVENT = AdminAlertEvent(
    key="embedding_runtime_update",
    subject="[email-triage] Attention — embedding runtime update required",
    template_fn=_assemble_embedding_runtime_alert,
    cooldown_hours=24,
    probe_fn=_embedding_runtime_probe,
    repeat_while_degraded=False,
    probe_off_lock=True,
)

register_event(EMBEDDING_RUNTIME_UPDATE_EVENT)


# Operator decision 2026-10-25: the runtime updates itself. A FAILED automatic
# update that leaves embedding off, or a security fix undone, is urgent and
# repeats every 6 hours until fixed (the automatic retry runs on its own
# backoff); a successful one is ONE after-the-fact email.
EMBEDDING_RUNTIME_AUTO_FAILED_EVENT = AdminAlertEvent(
    key="embedding_runtime_auto_update_failed",
    subject="[email-triage] URGENT — embedding runtime automatic update failed",
    template_fn=_assemble_embedding_auto_failed_alert,
    cooldown_hours=6,
    probe_fn=_embedding_auto_failed_probe,
    repeat_while_degraded=True,
    probe_off_lock=True,
)

register_event(EMBEDDING_RUNTIME_AUTO_FAILED_EVENT)


EMBEDDING_RUNTIME_AUTO_UPDATED_EVENT = AdminAlertEvent(
    key="embedding_runtime_auto_updated",
    subject="[email-triage] Embedding runtime updated automatically",
    template_fn=_assemble_embedding_auto_updated_alert,
    cooldown_hours=24,
    probe_fn=probe_reads_db,
    probe_db_fn=_embedding_auto_updated_probe,
    repeat_while_degraded=False,
)

register_event(EMBEDDING_RUNTIME_AUTO_UPDATED_EVENT)


# hipaa-sme R3 (2026-10-25): an INTEGRITY refusal (the volume no longer matches the
# record made when the runtime was verified, or the image's manifest is unreadable)
# is never healed by the app. Embedding is off until an admin acts, so it is URGENT
# and repeats every 6 hours, like a failed automatic update.
EMBEDDING_RUNTIME_INTEGRITY_EVENT = AdminAlertEvent(
    key="embedding_runtime_integrity_refused",
    subject="[email-triage] URGENT — embedding runtime refused: its files changed after install",
    template_fn=_assemble_embedding_integrity_alert,
    cooldown_hours=6,
    probe_fn=_embedding_integrity_probe,
    repeat_while_degraded=True,
    probe_off_lock=True,
)

register_event(EMBEDDING_RUNTIME_INTEGRITY_EVENT)


# Panel T DA SHOULD-A1b (2026-10-25): a NON-security update that keeps being deferred (the
# runtime was already loaded at 3 starts running, or 7 days have passed) is the operator's
# "no intervention" goal failing quietly. The daily health flips to Attention, and this event
# names it by email once a day until a start applies the update.
def _embedding_deferred_probe() -> tuple[bool, dict]:
    try:
        from email_triage.embedding_bits import update_in_progress, update_notice

        if update_in_progress():
            return PROBE_SKIP
        notice = update_notice()
    except Exception:  # pragma: no cover — defensive
        return (True, {"reason": "probe_error", "notice": None})
    if notice is None or notice.get("kind") != "auto_deferred" or not notice.get("escalated"):
        return (False, {"reason": None})
    return (True, {"reason": notice["alert_reason"], "notice": notice})


def _assemble_embedding_deferred_alert(ctx: dict) -> tuple[str, str]:
    import html as _html

    notice = ctx.get("notice") or {
        "headline": "Embedding runtime update keeps being deferred",
        "consequence": "Restart the container so the update is applied before anything loads the runtime.",
        "advisories": [],
    }
    lines = [
        f"Email Triage — {notice['headline']}",
        "=" * 50,
        notice["consequence"],
        "",
        "Nothing is broken: the installed runtime is still verified and serving. The",
        "update is not a security fix, so the app never swaps it under a loaded runtime",
        "(that would pause embedding until a restart).",
        "",
        "You get this email once a day until a start applies the update.",
    ]
    html = (
        '<div style="font-family: -apple-system, Segoe UI, sans-serif; '
        'max-width: 680px; margin: 0 auto;">'
        f'<h2 style="color:#b45309;">{_html.escape(notice["headline"])}</h2>'
        f'<p>{_html.escape(notice["consequence"])}</p>'
        "<p>Nothing is broken: the installed runtime is still verified and serving. "
        "The update is not a security fix, so the app never swaps it under a loaded "
        "runtime (that would pause embedding until a restart).</p>"
        '<p style="color:#555;font-size:0.9em;">You get this email once a day until a '
        "start applies the update.</p></div>"
    )
    return html, "\n".join(lines)


EMBEDDING_RUNTIME_DEFERRED_EVENT = AdminAlertEvent(
    key="embedding_runtime_update_deferred",
    subject="[email-triage] Attention — embedding runtime update keeps being deferred",
    template_fn=_assemble_embedding_deferred_alert,
    cooldown_hours=24,
    probe_fn=_embedding_deferred_probe,
    repeat_while_degraded=True,
    probe_off_lock=True,
)

register_event(EMBEDDING_RUNTIME_DEFERRED_EVENT)
