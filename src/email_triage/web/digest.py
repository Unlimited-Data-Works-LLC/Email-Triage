"""Digest + daily-health-email senders — extracted from web/app.py.

Drop-in refactor. NO semantic change. The recipient-digest + daily-health
email cluster moves here from ``web/app.py`` as the 2nd web/app.py carve
(after ``web/watcher.py``). ``web/app.py`` keeps a bottom re-export shim so
``from email_triage.web.app import _fire_one_digest`` (the test suite) +
the lifespan task registration (``_daily_health_email_sender`` /
``_recipient_digest_sender``) keep resolving unchanged.

Self-contained cut: the cluster has NO staying app.py-function dependency
(unlike the watcher) — its only app.py references were the module logger
(re-created below) and the digest-only ``_DAILY_HEALTH_STATE_KEY`` settings
key (co-moved here). So there are no cycle-break late-imports; everything
else the senders need is a top-level stdlib/sibling import (below) or a
local import already inside the moved bodies (db helpers, mailer, render
context) — no app.py import at all, no import cycle.

The module logger keeps the ``"web.app"`` record name so existing digest
log records are byte-identical post-move.

HIPAA: the digest senders render + email PHI-bearing message summaries, but
this is pure relocation — the recipient-scoping, redaction, and quiet-hours
/ HIPAA gating are byte-identical to the web/app.py original.
§-location-agnostic; no PHI-handling semantics changed.
"""

from __future__ import annotations

from email_triage.secrets import read_secret

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc
from email_triage._secret_keys import SMTP_PASSWORD_KEY  # N-231 R22 stored-secret-key SSOT

#: Logger record name preserved as "web.app" for byte-identical digest logs.
log = get_logger("web.app")


_DAILY_HEALTH_STATE_KEY = "daily_health_email_state"

async def _daily_health_email_sender(app: FastAPI) -> None:
    """Tick every 60 s; fire the daily health email when clock crosses send_at.

    Local-time based (``datetime.now().astimezone()``) so the send time
    honours whatever TZ the container was configured with.  Uses
    a DB-backed ``last_sent_date`` marker (the ``daily_health_email_state``
    ``settings`` row) to avoid re-firing within the same calendar day
    even if the process restarts, the clock oscillates across the HH:MM
    boundary, or the supervisor lease moves to another instance — the
    same shape the recipient-digest sender uses for its idempotence.
    """
    from email_triage.web.admin_alerts import fire_all as _fire_admin_alerts
    from email_triage.web.daily_health import (
        resolve_admin_recipients,
        send_daily_health_email,
    )
    from email_triage.web.db import get_setting, set_setting
    from email_triage.web.db_threadpool import db_call
    from email_triage.web.task_supervisor import supervised_interval_loop

    async def _tick() -> None:
        cfg = app.state.config
        hc = cfg.health_email
        now_local = datetime.now().astimezone()
        current_hm = now_local.strftime("%H:%M")
        # CR-2c — recipient list comes from the canonical
        # ``admin_email.recipients`` with a fallback to the legacy
        # ``health_email.recipients`` field.
        if hc.enabled and resolve_admin_recipients(cfg):
            today_key = now_local.strftime("%Y-%m-%d")
            if current_hm != hc.send_at:
                # F4 hoist (2026-07-10): fall through to the
                # admin-alert sweep even on off-schedule ticks so the
                # N-151 SOFT-gate + siblings advance every 60 s
                # regardless of whether hc.send_at was crossed on
                # THIS tick.  The admin-alert primitive carries its
                # own per-event cooldown; no double-send risk.
                pass
            else:
                # DB-backed guard: read the persisted last-sent date.
                state = await db_call(
                    get_setting, app.state.db, _DAILY_HEALTH_STATE_KEY,
                ) or {}
                if (state or {}).get("last_sent_date") != today_key:
                    # Stamp BEFORE the send so a crash / lease handoff
                    # between the stamp and the send does not re-fire —
                    # at-most-once is the safer failure mode for a
                    # health-status notification.
                    await db_call(
                        set_setting, app.state.db, _DAILY_HEALTH_STATE_KEY,
                        {"last_sent_date": today_key},
                    )
                    # Pass ``app`` so the listener-restart-pending check
                    # runs and can promote a stale toggle to
                    # attention_reasons.
                    #  — send_daily_health_email does extensive
                    # synchronous reads on the SHARED app.state.db
                    # connection.  A bare asyncio.to_thread runs it
                    # unlocked → collides with db_call workers on the
                    # same sqlite3.Connection.  Route it through
                    # db_call so the process-wide DB lock serialises it.
                    # Panel B3 db F569-5: the punch-569 section scans the
                    # runtime prefix; compute it OFF the DB lock (N-543).
                    from email_triage.web.daily_health import (
                        gather_embedding_runtime_section,
                    )
                    _er = await asyncio.to_thread(
                        gather_embedding_runtime_section, app.state.config,
                    )
                    sent, reason = await db_call(
                        send_daily_health_email,
                        app.state.db,
                        app.state.config,
                        app.state.secrets,
                        getattr(app.state, "watcher_manager", None),
                        app=app,
                        embedding_runtime_section=_er,
                    )
                    log.info(
                        "Daily health email tick fired",
                        sent=sent, reason=reason, at=current_hm,
                    )
                    # N-227b R22 — stamp app.state.<name>_status so
                    # /admin can observe the sweeper's outcome.  Was
                    # previously blind.
                    app.state.daily_health_email_sender_status = {
                        "sent": bool(sent),
                        "reason": str(reason) if reason else "",
                        "at": now_local.isoformat(),
                        "date_key": today_key,
                    }

        #  Part 2 — Fire the registered admin-alert events on
        # every tick, not only after a health-email send.  F4 hoist
        # (2026-07-10): moved OUT of the ``if hc.enabled and
        # resolve_admin_recipients(cfg)`` block so a mis-configured or
        # disabled health-email sender does NOT silently mute the
        # operator alerts (the very failure mode the alerts exist to
        # surface).  Each event carries its own per-key ``cooldown_hours``
        # floor + reason-change edge detection, so ticking every 60 s
        # is safe — the state machine collapses repeat probes.
        #
        # F3 caller-side: ``fire_all`` is now ``async``; the SMTP send
        # happens off the DB thread inside the primitive, and the DB
        # reads/writes are routed through db_call internally.  Await
        # directly — do NOT re-wrap in ``db_call`` (that would put the
        # SMTP work back onto the DB thread and stall the writer).
        try:
            alert_results = await _fire_admin_alerts(
                app.state.config,
                app.state.db,
            )
            log.info(
                "Admin-alert sweep fired",
                results=alert_results,
                at=current_hm,
            )
        except Exception as exc:
            # Fail-CLOSED-BUT-QUIET: an alert failure MUST NOT bubble
            # out of the tick or the supervisor restarts a loop whose
            # primary job (daily-health) already succeeded.
            log.error(
                "Admin-alert sweep raised",
                error=fmt_exc(exc),
            )

    #  — lease-gated so one instance owns the daily send.
    await supervised_interval_loop(
        "daily-health-email-sender", 60, _tick,
        warmup_secs=10,
        startup_jitter_secs=30.0,
        lease_name="daily-health-email-sender",
        lease_conn=app.state.db,
    )

def _filter_digest_candidates(
    *,
    db, acct: dict, dcfg, now_utc, last_sent: str | None,
    apply_cap: bool = True,
) -> tuple[list[dict], int]:
    """Cheap dry-run: resolve window + gather rows + apply custom
    filter. Returns ``(rows, total_matched)``.

    ``rows`` is what WOULD feed into the renderer — post-filter AND
    (when ``apply_cap``) post-``max_rows`` cap. ``total_matched`` is
    the count post-filter but BEFORE the cap, so every caller can
    surface "showing N of M" when the row limit dropped some. Before
     the cap silently sliced ``rows[:max_rows]`` and the dropped
    messages vanished from BOTH the candidate preview and the digest
    the user actually received, with no "and N more" — operator-facing
    data loss (silent-truncation audit, row ).

    ``apply_cap=False`` returns the FULL filtered list (no max_rows
    slice) — the Show-matches dry-run uses it to PAGE through every
    match, so the operator can see the whole match
    set, not just the first ``max_rows`` that would actually send.

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
    # total_matched is the post-filter count BEFORE the cap — the
    # honest denominator for "showing N of M". The preset path does
    # not cap (the ``if not is_preset`` below), so its denominator
    # equals len(rows) and omitted is always 0.
    total_matched = len(rows)
    if not is_preset and apply_cap:
        if dcfg.format.max_rows and len(rows) > dcfg.format.max_rows:
            rows = rows[: dcfg.format.max_rows]
    return rows, total_matched


def _digest_omission_notice_html(
    *, shown: int, total: int, max_rows: int,
) -> str:
    """One small HTML block telling the recipient the digest was
    capped at ``max_rows`` and ``total - shown`` messages were left
    out. Returned for injection before ``</body>`` by
    :func:`_render_digest_payload`. Empty string when nothing was
    dropped (caller already guards, but keep it total)."""
    omitted = max(0, total - shown)
    if omitted <= 0:
        return ""
    import html as _html
    return (
        "<div style=\"margin:14px 0;padding:10px 12px;"
        "border-left:3px solid #b58900;background:#fff8e1;"
        "font-size:13px;color:#5c4400;border-radius:3px;\">"
        f"Showing the {shown} most recent of "
        f"<strong>{total}</strong> matching messages. "
        f"{omitted} older message{'s were' if omitted != 1 else ' was'} "
        f"omitted by this digest's row limit "
        f"(max_rows&nbsp;=&nbsp;{_html.escape(str(max_rows))}). "
        "Raise the limit in the digest settings to include more."
        "</div>"
    )


def _inject_before_body_close(html_body: str, block: str) -> str:
    """Insert ``block`` just before the last ``</body>`` in
    ``html_body`` (case-insensitive). If there is no body close tag
    (a fragment), append. One funnel so every render format — preset,
    newsletter, custom table/grouped/plain — gets the notice the same
    way without threading it through each renderer's signature."""
    if not block:
        return html_body
    import re as _re
    m = None
    for m in _re.finditer(r"</body\s*>", html_body, _re.IGNORECASE):
        pass  # keep the LAST match
    if m is None:
        return html_body + block
    i = m.start()
    return html_body[:i] + block + html_body[i:]


def _build_compliance_clocks_section_html(clocks: list[dict]) -> str:
    """ — the per-recipient "Regulatory deadlines" digest section (HTML).

    Input is :func:`list_compliance_clocks_for_account` output, already
    HIPAA-MINIMAL (label + state + days_left + account_name; NO ``case_ref`` /
    ``raw_deadline_phrase``). One advisory ``<section>``; empty string when
    there are no clocks (caller skips injection). Wording funnels through
    ``clock_deadline_phrase`` so it matches the escalation email exactly (PD#5).
    ``html.escape`` the label defensively even though it is seed-data policy
    text."""
    if not clocks:
        return ""
    import html as _html

    from email_triage.db.regulatory_clock import clock_deadline_phrase
    items = []
    for c in clocks:
        label = _html.escape(str(c.get("label") or "Regulatory deadline"))
        when = _html.escape(clock_deadline_phrase(c.get("days_left")))
        days_left = c.get("days_left")
        overdue = isinstance(days_left, int) and days_left < 0
        color = "#b00020" if overdue else "#334155"
        items.append(
            f"<div style=\"margin:4px 0;color:{color};\">"
            f"<strong>{label}</strong> &middot; {when}</div>"
        )
    return (
        "<section style=\"margin:1.5em 0;padding:0.35em 0.9em;"
        "border-left:4px solid #2563eb;background:#f1f5f9;border-radius:4px;\">"
        "<h3 style=\"font-size:1.15em;margin:0.4em 0;color:#1e293b;\">"
        "Regulatory deadlines</h3>"
        + "".join(items)
        + "<div style=\"margin-top:6px;font-size:12px;color:#888;\">"
        "Reminders based on your configured policy — verify against your SOP. "
        "Advisory, not an official record.</div>"
        "</section>"
    )


def _build_compliance_clocks_section_plain(clocks: list[dict]) -> str:
    """Plain-text twin of :func:`_build_compliance_clocks_section_html`."""
    if not clocks:
        return ""
    from email_triage.db.regulatory_clock import clock_deadline_phrase
    lines = ["Regulatory deadlines"]
    for c in clocks:
        label = str(c.get("label") or "Regulatory deadline")
        lines.append(f"  - {label}: {clock_deadline_phrase(c.get('days_left'))}")
    lines.append(
        "  (Reminders based on your configured policy — verify against your "
        "SOP. Advisory, not an official record.)"
    )
    return "\n".join(lines)


async def _render_digest_payload(
    *,
    db, secrets, acct: dict, dcfg, hipaa: bool,
    now_utc, last_sent: str | None, config=None,
    redact_pii: bool = False,
) -> tuple[str, str, str, list[dict], int]:
    """Render the digest's email payload without sending it.

    ``redact_pii`` (N-174) is the display-minimum-necessary gate for the
    sender + subject cells, threaded down to the PRESET renderer
    (``recipient_digest.render_html`` / ``render_plain``). Default
    ``False`` = the DELIVERED behavior (``_fire_one_digest`` omits it →
    verbatim to the account's own authorized mailbox, byte-unchanged).
    The PREVIEW handler (``digest_preview``) passes
    ``redact_pii=effective_hipaa`` because that surface is reachable by a
    managing non-owner — the sibling of N-162 / N-172. N-175 COMPLETED
    the net: ALL THREE dispatch branches now honor ``redact_pii`` — the
    preset (``recipient_digest.render_html`` / ``render_plain``, N-174),
    the custom dispatcher (``render_digest`` → table / grouped_list /
    plain_list), AND the newsletter (``render_newsletter_async`` →
    ``generate_digest`` → ``build_digest_html``). Every preview-reachable
    render path that emits matched-message sender/subject PHI redacts it
    when ``redact_pii`` is True; the DELIVERED send (``_fire_one_digest``)
    omits the flag → every branch stays byte-unchanged to the account's
    own authorized mailbox.

    Returns ``(subject, html_body, plain_body, rows, total_matched)``.
    Empty ``rows`` means the window had no matching rows; the three
    string fields are empty strings and ``total_matched`` is 0 in that
    case. ``rows`` is the actual list (not just the count) so the
    caller can pass it to ``send_recipient_digest`` — the preset path's
    legacy default subject uses ``len(rows)`` when subject_override is
    None, so we need the list to keep that contract intact.

    ``total_matched`` is the post-filter count BEFORE the ``max_rows``
    cap. When it exceeds ``len(rows)`` an omission notice is injected
    into ``html_body`` / ``plain_body`` so the recipient sees that the
    digest was capped (silent-truncation audit ); the caller may
    also surface the count in its own header.

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

    #  — _filter_digest_candidates does a synchronous DB read
    # (gather_digest_rows) on the shared connection; this is an
    # ``async def`` so route it through db_call to run off the loop
    # under the process-wide DB lock.
    from email_triage.web.db_threadpool import db_call as _db_call
    rows, total_matched = await _db_call(
        _filter_digest_candidates,
        db=db, acct=acct, dcfg=dcfg,
        now_utc=now_utc, last_sent=last_sent,
    )
    if not rows:
        return ("", "", "", [], 0)

    is_preset = dcfg.id == PRESET_ID
    # census run17  — resolve via the account_email SSOT, not the open-coded
    # materialized key; local renamed off the SSOT name to avoid shadowing it.
    from email_triage.db.accounts import account_email
    acct_email = account_email(acct)

    # Render dispatch — preset (legacy table), newsletter (async
    # provider re-fetch + LLM extraction), or the sync custom
    # dispatcher (table / grouped_list / plain_list).
    if is_preset:
        html_body = render_preset_html(
            rows=rows,
            account_name=acct.get("name", ""),
            account_email=acct_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
            redact_pii=redact_pii,
        )
        plain_body = render_preset_plain(
            rows=rows,
            account_name=acct.get("name", ""),
            account_email=acct_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
            redact_pii=redact_pii,
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
        # the per-digest send path was missing it (audit the backlog
        # , 2026-05-08).
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
            log.debug("digest: summary_email signature not configured; footer left empty")
        try:
            html_body = await render_newsletter_async(
                cfg=dcfg, provider=provider, classifier=classifier,
                messages=messages,
                account_name=acct.get("name", ""),
                account_email=acct_email,
                hipaa=hipaa,
                # N-269 R28: route through the LOCAL date-header SSOT
                # (LIVE tz-off-by-one drift fix — census R28 flagged this
                # as UTC-derived while its 2 sibling sites are local).
                date_str=__import__(
                    "email_triage._isotime", fromlist=["now_local_date_header"]
                ).now_local_date_header(),
                signature=_signature,
                digest_name=getattr(dcfg, "name", "") or "",
                html_template=getattr(
                    dcfg.format, "html_template", "",
                ) or "",
                redact_pii=redact_pii,
            )
        finally:
            try:
                await provider.close()
            except Exception as close_exc:
                log.warning("digest: provider close failed", error=fmt_exc(close_exc))
        #  — HTML→text via the engine.html_text SSOT (drops script/style
        # content + keeps block structure; was an ad-hoc tag-strip).
        from email_triage.engine.html_text import html_to_text
        plain_body = html_to_text(html_body)
    else:
        html_body = render_digest(
            cfg=dcfg, rows=rows,
            account_name=acct.get("name", ""),
            account_email=acct_email,
            hipaa=hipaa,
            fallback_dt_iso=now_utc.isoformat(),
            redact_pii=redact_pii,
        )
        #  — HTML→text via the engine.html_text SSOT (drops script/style
        # content + keeps block structure; was an ad-hoc tag-strip).
        from email_triage.engine.html_text import html_to_text
        plain_body = html_to_text(html_body)

    # Subject: preset uses the legacy default in send_recipient_digest
    # (signalled via empty string here; SMTP-bound caller passes None
    # to send_recipient_digest's subject_override which falls through
    # to its own legacy default). Custom digests get the cadence-aware
    # name-driven subject we ship as build_custom_digest_subject.
    if is_preset:
        subject = ""
    else:
        subject = build_custom_digest_subject(dcfg, now_utc.astimezone())

    #  — if the max_rows cap dropped messages, tell the recipient
    # in the body they actually receive. One injection point here
    # covers every render format (preset / newsletter / custom).
    omitted = max(0, total_matched - len(rows))
    if omitted:
        notice_html = _digest_omission_notice_html(
            shown=len(rows), total=total_matched,
            max_rows=int(getattr(dcfg.format, "max_rows", 0) or 0),
        )
        html_body = _inject_before_body_close(html_body, notice_html)
        plain_body = (
            plain_body.rstrip()
            + f"\n\n— Showing the {len(rows)} most recent of "
            f"{total_matched} matching messages; {omitted} omitted "
            f"by this digest's row limit. Raise the limit to include "
            f"more.\n"
        )

    #  — per-recipient "Regulatory deadlines" section. The recipient's OWN
    # account's compliance clocks (label + days only). ACCOUNT-scoped (not the
    # user-wide list) so a digest for one account never surfaces another owned
    # account's deadlines. No NEW HIPAA access-event is needed here — NOT via an
    # "owner self-access" actor check (this send is SYSTEM-initiated,
    # actor_user_id=None) but because the digest envelope is recipient-LOCKED to
    # the data-subject account's OWN mailbox (the fail-closed to_addr ==
    # acct.email_address guard in _fire_one_digest) AND the whole hipaa=True send
    # already emits its §164.312(b) access-event row. The section adds no new
    # recipient and no PHI beyond the digest envelope. (A maintainer reusing this
    # reader on an ACTOR-bearing surface — a logged-in user viewing clocks — MUST
    # add the actor≠owner access-event there.)
    # One injection point → every render format gets it. Off-loop via db_call.
    # Fail-OPEN by design: surfacing the clocks is a NON-DECISIONAL render
    # enhancement, so a clock-read hiccup (DB error, pre-#34 schema) must NEVER
    # break the actual digest send — PD#8's one permitted fail-open. Log + skip.
    try:
        from email_triage.db.regulatory_clock import (
            list_compliance_clocks_for_account,
        )
        clocks = await _db_call(
            list_compliance_clocks_for_account,
            db, account_id=acct["id"],
            account_name=acct.get("name"), now_iso=now_utc.isoformat(),
        )
        if clocks:
            html_body = _inject_before_body_close(
                html_body, _build_compliance_clocks_section_html(clocks),
            )
            plain_body = (
                plain_body.rstrip()
                + "\n\n" + _build_compliance_clocks_section_plain(clocks) + "\n"
            )
    except Exception as e:
        log.warning(
            "Digest sender: regulatory-clock section skipped", error=str(e),
        )

    return (subject, html_body, plain_body, rows, total_matched)

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
    #  — ``async def`` helper: route the post-send DB writes through
    # db_call so they run off the event loop under the process-wide DB
    # lock instead of stalling the loop on the RLock.
    from email_triage.web.db_threadpool import db_call
    from email_triage.web._audit import safe_audit_write_async

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
    #  multi-address: an account may legitimately receive mail at
    # several addresses (primary plus configured aliases — same inbox,
    # different SMTP destinations). The match expands to the union
    # ``{primary} ∪ aliases`` so a digest delivered to ``alias1@example.com``
    # for an account whose primary is ``user@example.com`` still
    # round-trips into the same physical mailbox. The data-subject
    # boundary is unchanged: aliases route to the SAME mailbox; the
    # mismatch case the guard exists to catch (delivery to a third
    # party's address) is still rejected.
    from email_triage.web.db import account_addresses
    # N-253 R25: route through the canonical-email SSOT so a display-
    # name-wrapped `Alice <a@x>` and the bare `a@x` compare identically
    # against the allow-list — §164.312(a)(1) unauthorized-recipient
    # enforcement.
    from email_triage.mail_headers import canonical_email
    valid_targets = {canonical_email(a) for a in account_addresses(acct) if a}
    norm_to = canonical_email(to_addr)
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
    (
        subject, html_body, plain_body, rows, _total_matched,
    ) = await _render_digest_payload(
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
            #  — digest_mark_sent writes the shared connection;
            # route the empty-window stamp off the loop via db_call.
            from email_triage.web.db_threadpool import db_call
            await db_call(
                digest_mark_sent, db, acct["id"], dcfg.id, now_utc, 0,
            )
        return 0

    is_preset = dcfg.id == PRESET_ID
    # Preset uses the legacy default in send_recipient_digest;
    # _render_digest_payload signals this with subject == "".
    subject_override = subject or None
    smtp_password = read_secret(secrets, SMTP_PASSWORD_KEY) or ""
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
            await db_call(
                digest_mark_sent,
                db, acct["id"], dcfg.id, now_utc, len(rows),
            )
        except Exception as e:
            log.warning(
                "Digest sender: mark_sent failed",
                account_id=acct["id"], digest_id=dcfg.id,
                error=fmt_exc(e),
            )
        # N-73 / §164.312(b) — HIPAA recipient-digest send must write a
        # hipaa_access_events row (not just access_log) when the account
        # is HIPAA-flagged. Mirrors the N-33-B pattern from
        # web/topic_digest_sender.py. The actor is None (system-initiated).
        # Audit failure must NEVER fail the send: the emit is routed through
        # the safe_audit_write_async SSOT (log-on-failure, visible to /health's
        # audit-failure drift counter), not a hand-rolled swallowing try/except
        # that hid the failure from the drift counter (census run17 #3).
        if hipaa:
            from email_triage.web.db import record_hipaa_access_event
            await safe_audit_write_async(
                lambda: db_call(
                    record_hipaa_access_event,
                    db,
                    None,                           # system-initiated send
                    int(acct["id"]),
                    "recipient_digest_sent",
                    "ok",
                    (
                        f"digest_id={dcfg.id} kind={dcfg.kind} "
                        f"row_count={len(rows)}"
                        # to_addr deliberately excluded — db/audit contract:
                        # account_id is the column; never email in detail.
                    ),
                ),
                description=f"recipient_digest_sent hipaa_access account_id={acct['id']} digest_id={dcfg.id}",
                table="hipaa_access_events",
                emitter="record_hipaa_access_event",
            )
        # Route the access-log emit through the safe_audit_write_async SSOT
        # (census run17 #3) so a write failure is logged uniformly and stays
        # visible to /health's audit-failure drift counter.
        from email_triage.web.db import record_access_event
        await safe_audit_write_async(
            lambda: db_call(
                record_access_event,
                db,
                actor_user_id=None,
                method="POST",
                route="/internal/recipient-digest",
                account_id=acct["id"],
                message_id=None,
                status_code=200,
                outcome="recipient_digest_sent",
                detail=(
                    # N-136 (§164.514(b) minimum-necessary): the recipient email
                    # (to_addr) is deliberately EXCLUDED from access_log.detail —
                    # account_id is already the column, and the sibling
                    # hipaa_access emit above honors the same "never email in
                    # detail" db/audit contract.
                    f"digest_id={dcfg.id} kind={dcfg.kind} "
                    f"row_count={len(rows)} hipaa={hipaa} "
                    f"filter_advanced={'yes' if dcfg.filter.advanced else 'no'}"
                ),
            ),
            description=f"recipient_digest_sent route=/internal/recipient-digest account_id={acct['id']} digest_id={dcfg.id}",
            table="access_log",
            emitter="record_access_event",
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
    from email_triage.actions.digest_configs import (
        get_last_sent as digest_get_last_sent,
        list_digest_configs,
    )
    from email_triage.actions.digest_filter import digest_should_fire
    from email_triage.web.db import list_email_accounts
    from email_triage.web.task_supervisor import supervised_interval_loop
    #  — ``async def`` tick: route the sync DB reads through db_call
    # so they run off the event loop under the process-wide DB lock.
    from email_triage.web.db_threadpool import db_call

    async def _tick() -> None:
        cfg = app.state.config
        db = app.state.db
        secrets = app.state.secrets
        smtp = cfg.smtp
        now_local = datetime.now().astimezone()
        now_utc = datetime.now(timezone.utc)
        # N-227b R22 — heartbeat stamp so /admin can observe the sweeper
        # ran. Per-digest outcome is logged separately; the app.state
        # snapshot answers "did the sweeper run at all recently?".
        app.state.recipient_digest_sender_status = {"at": now_local.isoformat()}

        for acct in await db_call(list_email_accounts, db):
            if not acct.get("is_active", True):
                continue
            acct_id = acct["id"]
            # census run17  — account_email SSOT, not the open-coded key.
            from email_triage.db.accounts import account_email
            to_addr = account_email(acct)
            if not to_addr:
                # Account hasn't been saved with credentials yet —
                # skip silently per pre-Phase-4 behaviour.
                continue

            from email_triage.triage_logging import account_hipaa_effective
            hipaa = account_hipaa_effective(account=acct)

            try:
                digest_cfgs = await db_call(list_digest_configs, db, acct_id)
            except Exception as e:
                log.warning(
                    "Digest sender: list_digest_configs failed",
                    account_id=acct_id, error=fmt_exc(e),
                )
                continue

            for dcfg in digest_cfgs:
                last_sent = await db_call(
                    digest_get_last_sent, db, acct_id, dcfg.id,
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

    #  — lease-gated so one instance fires the digests; per-digest
    # idempotence is DB-backed (the digest_state key) so it stays
    # correct even if leadership moves between instances.
    await supervised_interval_loop(
        "recipient-digest-sender", 60, _tick,
        warmup_secs=15,
        startup_jitter_secs=30.0,
        lease_name="recipient-digest-sender",
        lease_conn=app.state.db,
    )
