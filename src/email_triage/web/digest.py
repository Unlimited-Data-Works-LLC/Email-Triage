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

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI

from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

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
        # CR-2c — recipient list comes from the canonical
        # ``admin_email.recipients`` with a fallback to the legacy
        # ``health_email.recipients`` field.
        if hc.enabled and resolve_admin_recipients(cfg):
            now_local = datetime.now().astimezone()
            today_key = now_local.strftime("%Y-%m-%d")
            current_hm = now_local.strftime("%H:%M")
            if current_hm != hc.send_at:
                return
            # DB-backed guard: read the persisted last-sent date.
            state = await db_call(
                get_setting, app.state.db, _DAILY_HEALTH_STATE_KEY,
            ) or {}
            if (state or {}).get("last_sent_date") == today_key:
                return
            # Stamp BEFORE the send so a crash / lease handoff between
            # the stamp and the send does not re-fire — at-most-once is
            # the safer failure mode for a health-status notification.
            await db_call(
                set_setting, app.state.db, _DAILY_HEALTH_STATE_KEY,
                {"last_sent_date": today_key},
            )
            # Pass ``app`` so the listener-restart-pending check
            # runs and can promote a stale toggle to
            # attention_reasons.
            #  — send_daily_health_email does extensive synchronous
            # reads on the SHARED app.state.db connection. A bare
            # asyncio.to_thread runs it unlocked → collides with
            # db_call workers on the same sqlite3.Connection. Route it
            # through db_call so the process-wide DB lock serialises it.
            sent, reason = await db_call(
                send_daily_health_email,
                app.state.db,
                app.state.config,
                app.state.secrets,
                getattr(app.state, "watcher_manager", None),
                app=app,
            )
            log.info(
                "Daily health email tick fired",
                sent=sent, reason=reason, at=current_hm,
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

    #  — _filter_digest_candidates does a synchronous DB read
    # (gather_digest_rows) on the shared connection; this is an
    # ``async def`` so route it through db_call to run off the loop
    # under the process-wide DB lock.
    from email_triage.web.db_threadpool import db_call as _db_call
    rows = await _db_call(
        _filter_digest_candidates,
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
    #  — ``async def`` helper: route the post-send DB writes through
    # db_call so they run off the event loop under the process-wide DB
    # lock instead of stalling the loop on the RLock.
    from email_triage.web.db_threadpool import db_call

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
        try:
            from email_triage.web.db import record_access_event
            await db_call(
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

        for acct in await db_call(list_email_accounts, db):
            if not acct.get("is_active", True):
                continue
            acct_id = acct["id"]
            to_addr = (acct.get("email_address") or "").strip()
            if not to_addr:
                # Account hasn't been saved with credentials yet —
                # skip silently per pre-Phase-4 behaviour.
                continue

            from email_triage.triage_logging import is_hipaa_mode
            hipaa = (
                is_hipaa_mode()
                or bool(acct.get("hipaa", False))
            )

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
