"""Routes for the triage_classify concern.

Split out of the legacy `web/routers/ui.py`. Helpers
live in `_shared`; this file holds only the @router-decorated
handlers + handler-local helpers for this URL surface.
No behavior changes from pre-split — every handler body is
byte-for-byte identical.
"""
from __future__ import annotations

import asyncio
import email as email_mod
import email.policy
import email.utils
import json as json_mod
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.web._flash import scrub_exc  # N-179 R21_2 sub-3 SSOT
from email_triage.web.error_html import error_article

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.web.db import can_manage_account
from email_triage.web import settings_keys as _S
from email_triage.web.app import get_config, get_db, get_secrets, get_templates
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_otp,
    get_user_by_email,
    send_otp_email,
    store_otp,
    update_last_login,
    verify_otp,
)
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import (
    is_admin as _is_admin,  # N-222h R22 SSOT alias (local `is_admin` shadows callable)
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    RequireUserFragment,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import REDACTED_PLACEHOLDER, get_logger
from email_triage._errfmt import fmt_exc, scrub_class_error_for_persist, scrub_error_for_persist

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.triage_classify")

router = APIRouter()

# / — Bulk-runs index page size. Module-level so tests can
# monkeypatch it small to exercise the pager without seeding 50+ jobs.
_JOBS_CAP = 50


from . import _shared
# Snapshot every helper from _shared into this module's globals so
# handler bare-name references resolve. globals().update is used
# instead of `from _shared import *` because * skips underscore-
# prefixed names (which is most helpers).
globals().update({
    _n: _v for _n, _v in vars(_shared).items()
    if not _n.startswith('__')
})


def __getattr__(name):
    """Legacy install-singleton names + PEP-562 fallback to ``_shared``.

    Two roles folded into one module-level ``__getattr__`` (census
    wf_56d1585d 2026-07-09 D3 — SSOT self-shadowing fix; Python only
    honours the LAST ``__getattr__`` per module, so previously the
    install-singleton compat glue was dead code from an unnoticed second
    override):

    1. Route reads of legacy install-singleton names
       (``_install_google_oauth`` / ``_install_ingestion_config``) through
       the factory module. Code that did
       ``from email_triage.web.routers.ui import _install_ingestion_config``
       (test fixtures, future plugins) keeps working.
    2. Late-bound lookup on ``_shared`` — catches names added to
       ``_shared`` after this module's ``globals().update`` populated, plus
       names the package-level monkeypatch mirror writes onto ``_shared``
       after import.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


@router.get("/classify", response_class=HTMLResponse)
async def classify_page(request: Request, user: RequireUser):
    """Test-classify page — open to any authenticated user.

    Useful to investigate why a specific message classified the way
    it did, regardless of admin role. Categories shown to the user
    are scoped to system + their personal categories (already the
    case in classify_run); no admin-only data leaks via the test
    surface.
    """
    templates = get_templates(request)
    return await _render(templates, request, "classify.html", {"user": user})


@router.post("/classify/run", response_class=HTMLResponse)
async def classify_run(
    request: Request, user: RequireUserFragment,
):
    """Parse a raw email and classify it via the configured LLM.

     sub-E: open to any authenticated user. The categories pulled
    from the DB are user-scoped (system + the user's personal),
    not admin-global; no privilege escalation via this endpoint.
    """
    templates = get_templates(request)
    db = get_db(request)
    config = get_config(request)

    # Read the pasted raw email via parse_form so a large message (HTML +
    # inline base64 images) isn't rejected by Starlette 1.3.1's 1 MiB per-field
    # default (CVE-2026-54283 enforcement). See web/form_limits.
    from email_triage.web.form_limits import parse_form
    raw_email = str((await parse_form(request)).get("raw_email") or "")
    if not raw_email.strip():
        # Preserve the old required-field contract (was Form(...) → 422) now
        # that we parse the form manually — render a friendly HTML article
        # instead of FastAPI's raw JSON 422.
        return HTMLResponse(
            error_article(ValueError("Paste a raw email to classify."),
                          heading="No input"),
            status_code=422,
        )

    # Parse the raw email.
    try:
        parsed = _parse_raw_email(raw_email)
    except Exception as exc:
        return HTMLResponse(
            error_article(exc, heading='Parse error')
        )

    # Get categories from DB (user-scoped: system + current user's personal).
    categories = await db_call(
        _get_categories_from_db, db, user_id=user["id"],
    )
    if not categories:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
            '<p>No categories configured. Add categories first.</p></article>'
        )

    # Collect list hints (from all lists in DB).
    list_hints = _collect_list_hints_for_message(db, parsed)

    # -followup — Test Classify must mirror the production
    # engine/flow.py:classify() short-circuit on skip_ai=True hints,
    # otherwise operator's "test what would happen" preview lies. A
    # rule with Skip AI ON forces the category WITHOUT calling the
    # LLM in production; the same must happen here. Operator caught
    # this 2026-05-12 when a `sender_domain CTOx.com` rule went to
    # Promotions in production — the rule was advisory (skip_ai=No)
    # so the LLM legitimately overrode it, but Test Classify didn't
    # expose the advisory-vs-force distinction at all.
    from email_triage.classify.hints import find_skip_ai_hint
    skip_hint = find_skip_ai_hint(list_hints or [])
    if skip_hint is not None:
        classification = Classification(
            category=skip_hint.category,
            confidence=1.0,
            reason=(
                f"Matched rule (Force category): "
                f"{skip_hint.rule_type.value} = \"{skip_hint.pattern}\""
            ),
            source="list_rule",
        )
        return await _render(templates, request, "classify/_result.html", {
            "classification": classification,
            "parsed": parsed,
            "timing": 0.0,
            "model": "(skipped — list rule forced category)",
            "list_hints": list_hints,
            "skip_hint": skip_hint,
        })

    # Build the classifier.
    backend = config.classifier.backend

    t0 = time.time()
    _local_suffixes = list(
        getattr(config.tls, "local_url_suffixes", []) or [],
    )
    try:
        if backend == "ollama":
            from email_triage.classify.ollama import OllamaClassifier
            classifier = OllamaClassifier(
                model=config.classifier.model,
                base_url=config.classifier.ollama_url,
                prefer_loaded=config.classifier.prefer_loaded,
                local_url_suffixes=_local_suffixes,
                prefer_loaded_skip_embeddings=(
                    config.classifier.prefer_loaded_skip_embeddings
                ),
                embedding_name_markers=(
                    config.classifier.embedding_name_markers
                ),
                backup_models=config.classifier.backup_models,
                num_ctx=config.classifier.num_ctx,
                ollama_think=config.classifier.ollama_think,
                ollama_no_think_marker=(
                    config.classifier.ollama_no_think_marker
                ),
                ollama_keep_alive=config.classifier.ollama_keep_alive,
            )
        elif backend == "openai":
            from email_triage.classify.openai_compat import (
                OpenAICompatClassifier,
            )
            classifier = OpenAICompatClassifier(
                base_url=config.classifier.openai_base_url,
                model=config.classifier.openai_model,
                local_url_suffixes=_local_suffixes,
            )
        elif backend == "gemini":
            from email_triage.classify.gemini import GeminiClassifier
            classifier = GeminiClassifier(
                model=config.classifier.gemini_model,
            )
        else:
            import html as _html
            # N-83: backend is a config-stored string; escape before HTML interpolation.
            return HTMLResponse(
                f'<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
                f'<p>Unknown classifier backend: {_html.escape(str(backend))}</p></article>'
            )

        try:
            # Punch 616 (panel B3 hipaa-sme F1a): the pasted text belongs to no
            # account, but with the system HIPAA flag on every message is HIPAA,
            # so the BAA gate decides before it can egress (§164.308(b)(1)).
            # Refuse, never degrade; the finally below still drains the pool.
            from email_triage.classify.baa_gate import baa_block_status
            from email_triage.triage_logging import account_hipaa_effective
            if account_hipaa_effective(message=parsed):
                _baa_block = await db_call(baa_block_status, db, classifier, True)
                if _baa_block is not None:
                    import html as _html
                    _target = (f"{_baa_block.get('backend') or backend} @ "
                               f"{_baa_block.get('host') or '?'}")
                    _log.warning(
                        "Test Classify refused: HIPAA mode is on and classifier "
                        f"{_target} has no BAA on file; nothing was sent (punch 616).",
                    )
                    return HTMLResponse(
                        '<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
                        '<p>Classification refused: HIPAA mode is on and the configured '
                        f'classifier ({_html.escape(_target)}) has no BAA on file. '
                        'Nothing was sent.</p></article>'
                    )
            classification = await classifier.classify(parsed, categories, list_hints or None)
        finally:
            #  — drain the long-lived httpx pool the classifier
            # opened for /api/chat. The per-request handler discards
            # the classifier on return; without close() the pool sits
            # open until GC.
            if hasattr(classifier, "close"):
                try:
                    await classifier.close()
                except Exception:
                    pass
        elapsed = time.time() - t0
    except Exception as exc:
        elapsed = time.time() - t0
        return HTMLResponse(
            error_article(exc, heading=f'Classification error ({elapsed:.1f}s)')
        )

    model_label = config.classifier.model if backend == "ollama" else backend
    return await _render(templates, request, "classify/_result.html", {
        "classification": classification,
        "parsed": parsed,
        "timing": elapsed,
        "model": model_label,
        # -followup — pass advisory hints through so the result
        # page can surface "rule matched but AI overrode" cases.
        # Operator caught this discrepancy on a CTOx rule that the
        # AI legitimately overrode (rule was advisory, not Force).
        "list_hints": list_hints,
        "skip_hint": None,  # the skip_ai short-circuit returned earlier
    })


@router.get("/triage", response_class=HTMLResponse)
async def triage_page(request: Request, user: RequireUser):
    """Run Triage page — select account, limit, and run.

    When the current user can see accounts owned by more than one
    person (admin-of-the-install OR delegate of someone else's
    account), surface an "Owner" filter dropdown that defaults to
    the current user. Accounts list filters to the selected owner.
    """
    db = get_db(request)
    templates = get_templates(request)

    snap = await db_call(
        _triage_page_snapshot, db, user,
        request.query_params.get("owner_filter"),
    )

    #  — surface whether the optional classification cache is
    # configured so the template can hide / show the force-reclassify
    # debug toggle. Defensive default (False) on any import error so
    # an install without the optional ``redis`` extra renders cleanly.
    classification_cache_enabled = False
    try:
        from email_triage.cache.classification import (
            get_install_classification_cache,
        )
        _cc = get_install_classification_cache()
        classification_cache_enabled = bool(_cc is not None and _cc.enabled)
    except Exception:
        classification_cache_enabled = False

    return await _render(templates, request, "triage/run.html", {
        "user": user,
        "classification_cache_enabled": classification_cache_enabled,
        **snap,
    })


@router.post("/triage/run", response_class=HTMLResponse)
async def triage_run(request: Request, user: RequireUserFragment):
    """Execute a triage cycle on the selected account.

    Thin wrapper over :func:`email_triage.web.triage_runner.run_triage` —
    parses the form, enforces ownership, calls the runner, then fires
    the ``triage.completed`` event and renders the results template.
    """
    db = get_db(request)
    secrets = get_secrets(request)
    config = get_config(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")

    form = await request.form()
    account_id = _safe_int(form.get("account_id"), 0)
    # Mode: "inline" (default; bounded sync run) or "all" (background
    # whole-mailbox sweep, ). The form field is the radio button
    # added on triage/run.html in step 6.
    mode = (form.get("mode") or "inline").strip()
    limit = _safe_int(form.get("limit"), 5)

    #  — preset dropdown + Other/freeform. Preset maps to IMAP SEARCH
    # syntax; the Gmail provider's translator converts at search time.
    preset = (form.get("search_preset") or "").strip()
    freeform = form.get("query", "").strip()
    query = _triage_preset_to_query(preset, freeform)

    #  — "Has label" filter. When set, intersect the provider's
    # search results with the set of message_ids tagged with this
    # slug on this account. The intersection lives in
    # triage_runner.run_triage's caller flow — we read the labeled
    # ids here, then pass via a label_filter_ids set.
    has_label = (form.get("has_label") or "").strip().lower()

    #  — force re-classify checkbox. Bypasses the optional Redis
    # classification cache for this run (every message hits the LLM).
    # Result still gets written back so the next non-force run hits.
    # Default unchecked — operator opts in to spend tokens.
    force_reclassify = bool(form.get("force_reclassify"))

    if limit < 1 or limit > 100:
        limit = 5

    from email_triage.web.db import get_email_account

    # / — DB-before-network: fetch + can-manage in one hop.
    def _triage_run_gate() -> tuple[dict | None, bool]:
        acct_ = get_email_account(db, account_id)
        if acct_ is None:
            return None, False
        return acct_, can_manage_account(db, user, acct_)

    acct, _can_manage = await db_call(_triage_run_gate)
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )
    if not _can_manage:
        return HTMLResponse("Forbidden", status_code=403)

    # ── Bulk-mode branch ──
    # "All matches (background)" — create a triage_jobs row + 303 to
    # the progress page. The supervised bulk runner picks it up
    # within POLL_INTERVAL_SECS. Refuses a second concurrent submit
    # on the same account (one bulk job per account at a time).
    if mode == "all":
        from email_triage.web.db import (
            create_triage_job, count_active_triage_jobs_for_account,
        )

        def _bulk_job_db_work() -> str | None:
            """/ — active-job check + runtime read + job create
            in one threadpool hop. Returns the new job id, or ``None``
            when a bulk run is already active on this account.
            """
            if count_active_triage_jobs_for_account(db, account_id) > 0:
                return None
            runtime = _get_runtime_settings(db)
            rate = int(runtime.get(
                "bulk_triage_rate_msg_per_min",
                _RUNTIME_DEFAULTS["bulk_triage_rate_msg_per_min"],
            ))
            conc = int(runtime.get(
                "bulk_triage_concurrency",
                _RUNTIME_DEFAULTS["bulk_triage_concurrency"],
            ))
            return create_triage_job(
                db, account_id=account_id, actor_user_id=user["id"],
                query=query, rate_msg_per_min=rate, concurrency=conc,
            )

        job_id = await db_call(_bulk_job_db_work)
        if job_id is None:
            return HTMLResponse(
                '<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
                '<p><strong>A bulk run is already active on this account.</strong> Wait for it to finish or cancel it from its progress page.</p></article>'
            )
        # The submit form is HTMX-driven (it swaps inline results
        # into #triage-results for inline mode). For bulk mode we
        # need a full-page navigation to the progress page, NOT an
        # in-place swap. HTMX recognizes the HX-Redirect response
        # header and triggers window.location — same effect as a
        # plain 303 for non-HTMX clients (we still set status 200
        # so HTMX honours the header rather than chasing redirect).
        is_htmx = _shared.is_htmx(request)
        target = f"/triage/jobs/{job_id}"
        if is_htmx:
            return HTMLResponse(
                "", status_code=200, headers={"HX-Redirect": target},
            )
        return RedirectResponse(target, status_code=303)

    if not acct.get("is_active", True):
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
            '<p><strong>Account disabled.</strong> This account is not enabled. '
            'Enable it in <a href="/accounts">account settings</a> to run triage.</p></article>'
        )

    from email_triage.web.triage_runner import run_triage
    from email_triage.web.events import fire_triage_completed

    run = await run_triage(
        db, config, secrets, acct,
        query=query, limit=limit,
        actor_user_id=user["id"], trigger="manual",
        force_reclassify=force_reclassify,
    )

    #  — "Has label" filter. Apply post-runner: keep only result
    # rows whose message_id is tagged with the chosen slug on this
    # account. v1 trade-off: the runner classifies + acts on every
    # match first, then we filter the view; integrating this into
    # provider.search would need a per-provider message-id-in-set
    # primitive (Gmail/Outlook/IMAP have none). Forward-only label
    # set; in practice operators tag a few dozen messages, so the
    # filtered view is small relative to the input.
    if has_label:
        from email_triage.web.db import list_messages_with_label
        labeled = await db_call(
            list_messages_with_label, db, has_label, account_id, 10000,
        )
        labeled_ids = {r["message_id"] for r in labeled}
        if labeled_ids:
            run["results"] = [
                r for r in run["results"]
                if r.get("message_id") in labeled_ids
            ]
        else:
            run["results"] = []

    if run.get("error") == "no_categories":
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>No categories configured. Add categories first.</p></article>'
        )
    if run.get("error") == "provider_error":
        msg = (run["errors"] or ["Provider error"])[0]
        # N-83: msg is a provider/classifier error string (attacker-reachable via
        # a crafted server banner or LLM-echo); route through error_article so
        # the dynamic value is html.escape()'d before reaching the response.
        return HTMLResponse(error_article(msg, heading="Provider error"))
    if run.get("error") == "classifier_error":
        msg = (run["errors"] or ["Classifier error"])[0]
        # N-83: same class — classifier error string may echo provider content.
        return HTMLResponse(error_article(msg, heading="Classifier error"))

    # Best-effort outbound webhook emit. Never blocks the response.
    dispatcher = getattr(request.app.state, "event_dispatcher", None)
    if dispatcher is not None:
        try:
            await fire_triage_completed(dispatcher, db, config, acct, run, trigger="manual")
        except Exception as e:
            _log.warning("triage.completed dispatch failed", error=fmt_exc(e))

    #  — labels catalog drives the bulk-tag toolbar on the
    # results table. Pass even when empty so the template's
    # `{% if all_labels %}` gate stays consistent across renders.
    from email_triage.web.db import list_labels
    all_labels = await db_call(list_labels, db)

    return await _render(templates, request, "triage/_results.html", {
        "results": run["results"],
        "errors": run["errors"],
        "total": run["total_messages"],
        "elapsed": run["elapsed_secs"],
        "acct": acct,
        "query": query,
        "dry_run": _is_dry_run(db),
        "all_labels": all_labels,
    })


# ---------------------------------------------------------------------------
# Triage preview — read-only smoke test of a query before running for real
# ---------------------------------------------------------------------------

@router.post("/triage/preview", response_class=HTMLResponse)
async def triage_preview(request: Request, user: RequireUserFragment):
    """Return up to 20 message headers matching the supplied query.

    Read-only — no classifier call, no actions executed, no
    triage_runs / triage_jobs / flow_states writes. Operator uses
    this to verify a freeform query catches the messages they
    expect before launching an inline run or a background sweep.

    HIPAA: when the actor is NOT the account owner AND the account
    is HIPAA-flagged, write a hipaa_access_event row
    (event_type=triage_preview). Render shape stays full —
    sender/subject are operationally necessary to make the preview
    useful, and the §164.312(b) audit row tracks the access. Same
    parity rule as triage_runner.run_triage / run_triage_all
    (tightened in this batch to gate on actor != owner).

    Rate-limited to 1 request per account per 10 s — preview is
    cheap (1 search + 20 headers-only fetches) but a button-spam
    chain would still hammer the provider's API.
    """
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    form = await request.form()
    account_id = _safe_int(form.get("account_id"), 0)
    preset = (form.get("search_preset") or "").strip()
    freeform = form.get("query", "").strip()
    query = _triage_preset_to_query(preset, freeform)

    from email_triage.web.db import get_email_account

    #  phase 3 — DB-before-network: provider preview hits IMAP/Gmail.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )

    import time as _time
    from email_triage.triage_logging import is_account_hipaa

    def _preview_gate_db_work() -> tuple[str, dict]:
        """/ — can-manage check + rate-limit read/write +
        HIPAA audit, all in one threadpool hop. Returns
        ``(kind, payload)``:
          - ("forbidden", {})        → 403
          - ("cooldown", {wait})     → amber cool-down chip
          - ("ok", {})               → handler proceeds to provider
        """
        if not can_manage_account(db, user, acct):
            return "forbidden", {}

        # Cheap rate-limit: 1 preview / account / 10 s. Stored in a
        # ratelimit:* setting key with a wall-clock timestamp +
        # bucketed window. Overkill to plumb a per-account redis-like
        # primitive for this; the get_setting / set_setting pair works.
        from email_triage.web.db import get_setting, set_setting
        rl_key = f"ratelimit:triage_preview:{account_id}"
        last = get_setting(db, rl_key) or 0.0
        now = _time.time()
        if now - float(last) < 10.0:
            wait = int(10 - (now - float(last)))
            return "cooldown", {"wait": wait}
        set_setting(db, rl_key, now)

        # HIPAA audit row — actor != owner on HIPAA account (PD#14 SSOT).
        # Owner self-access exempt; gate lives in audit_phi_access.
        audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="triage_preview",
            outcome="success",
        )
        return "ok", {}

    kind, payload = await db_call(_preview_gate_db_work)
    if kind == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    if kind == "cooldown":
        wait = payload["wait"]
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
            f'<p>Preview cooling down — wait ~{wait}s and try again.</p></article>'
        )

    # Provider lookup + fetch.
    try:
        provider = await db_call(
            _create_provider_from_account, acct, secrets,
        )
    except Exception as e:
        return HTMLResponse(
            error_article(
                scrub_class_error_for_persist(e),
                heading='Provider error',
            )
        )

    PREVIEW_LIMIT = 20
    rows: list[dict] = []
    err: str | None = None
    try:
        ids = await provider.search(query or "ALL", limit=PREVIEW_LIMIT)
        for msg_id in ids[:PREVIEW_LIMIT]:
            try:
                msg = await provider.fetch_message(
                    msg_id, headers_only=True,
                )
                row = {
                    "id": msg_id,
                    "sender": getattr(msg, "sender", "") or "",
                    "subject": getattr(msg, "subject", "") or "",
                    "date_iso": "",
                }
                try:
                    if msg.date:
                        row["date_iso"] = msg.date.isoformat()
                except Exception as date_exc:
                    _log.warning(
                        "Preview row date not ISO-formatted; date left blank",
                        message_id=msg_id, error=fmt_exc(date_exc),
                    )
                rows.append(row)
            except Exception as fe:
                rows.append({
                    "id": msg_id, "sender": "(fetch error)",
                    "subject": str(fe), "date_iso": "",
                })
    except Exception as e:
        err = scrub_class_error_for_persist(e)
    finally:
        try:
            await provider.close()
        except Exception as _swallow_exc:
            _log.debug(
                "provider/probe close failed (best-effort teardown)",
                error=fmt_exc(_swallow_exc),
            )

    return await _render(templates, request, "triage/_preview.html", {
        "rows": rows,
        "total": len(rows),
        "limit": PREVIEW_LIMIT,
        "error": err,
        "query": query,
        "acct": acct,
    })


# ---------------------------------------------------------------------------
# Bulk triage jobs — /triage/jobs index + /triage/jobs/<job_id> per-job
# ---------------------------------------------------------------------------

@router.get(
    "/triage/jobs", response_class=HTMLResponse,
)
async def triage_jobs_index(request: Request, user: RequireUser):
    """Index of bulk runs across every account the user can manage.

    Filed because the per-job page (``/triage/jobs/<id>``) was the
    only surface — there was no listing. The mine-limit-override
    tooltip on ``/profile/style-data`` referenced "the Bulk runs
    page" with no place to point. This handler is that page.

    Shows queued / running first (live work), then recent done /
    failed / cancelled (history). Cap at 50 across both, newest
    first.
    """
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        list_email_accounts, list_triage_jobs, count_triage_jobs,
    )
    from email_triage.web._pagination import page_window, clamp_offset

    JOBS_CAP = _JOBS_CAP
    raw_offset = request.query_params.get("offset")

    def _jobs_index_reads(db, user_id):
        # Pull all accounts the user owns / delegates so we can
        # narrow jobs to "their" surface — admin-viewing-everyone is
        # a separate concern.
        accts = list_email_accounts(db, user_id=user_id)
        acct_ids = {int(a["id"]) for a in accts}
        accts_by_id = {int(a["id"]): a for a in accts}
        #  — push the account scope INTO the query so the cap applies
        # AFTER the per-user filter (a user's own jobs were vanishing
        # behind other users' newer ones).  reachability — page via
        # ?offset= so the full history past the cap is reachable. Active
        # jobs are the newest, so they always sit on page 1.
        total = count_triage_jobs(db, account_ids=acct_ids)
        off = clamp_offset(raw_offset, JOBS_CAP, total)
        jobs = list_triage_jobs(
            db, account_ids=acct_ids, limit=JOBS_CAP, offset=off,
        )
        win = page_window(
            total=total, offset=off, limit=JOBS_CAP, shown=len(jobs),
        )
        return jobs, accts_by_id, win

    jobs, accts_by_id, jobs_win = await db_call(
        _jobs_index_reads, db, user.get("id"),
    )

    # Split for the template: active (queued + running) at top,
    # everything else underneath. Within each bucket, newest first
    # (already sorted by created_at DESC from the DB).
    active = [j for j in jobs if j.get("status") in ("queued", "running")]
    done = [j for j in jobs if j.get("status") not in ("queued", "running")]

    return await _render(templates, request, "triage/jobs_index.html", {
        "user": user,
        "active_jobs": active,
        "done_jobs": done,
        "jobs_win": jobs_win,
        "accts_by_id": accts_by_id,
    })


# NOTE: this STATIC path must be registered BEFORE ``/triage/jobs/{job_id}``
# below, or Starlette matches "reindex-progress" as a job_id.
@router.get(
    "/triage/jobs/reindex-progress", response_class=HTMLResponse,
)
async def triage_reindex_aggregate_fragment(request: Request, user: RequireUser):
    """HTMX fragment — rolled-up cross-account embedding-reindex progress.

    Renders the wave (one bar + per-account rows) ONLY while a reindex is active
    in the user's account scope; returns empty otherwise so the self-poll on the
    fragment stops. Scoped to the user's manageable accounts — same surface the
    jobs index uses; no cross-user leak.
    """
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import list_email_accounts
    from email_triage.jobs.embedding_reindex import aggregate_reindex_progress

    def _reads(db, user_id):
        accts = list_email_accounts(db, user_id=user_id)
        acct_ids = {int(a["id"]) for a in accts}
        accts_by_id = {int(a["id"]): a for a in accts}
        agg = aggregate_reindex_progress(db, account_ids=acct_ids)
        return agg, accts_by_id

    agg, accts_by_id = await db_call(_reads, db, user.get("id"))
    return await _render(
        templates, request, "triage/_reindex_aggregate.html",
        {"user": user, "agg": agg, "accts_by_id": accts_by_id},
    )


@router.get(
    "/triage/jobs/{job_id}", response_class=HTMLResponse,
)
async def triage_job_page(
    request: Request, job_id: str, user: RequireUser,
):
    """Full-page progress view for a bulk-triage job."""
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, list_triage_runs,
    )

    # / — every read in this handler hops via threadpool;
    # the page is polled every 2s so this matters at scale. The
    # can-manage check folds into the same hop.
    def _triage_job_page_reads(db, job_id):
        job = get_triage_job(db, job_id)
        if job is None:
            return None, None, [], False
        acct = get_email_account(db, job["account_id"])
        if acct is None:
            return job, None, [], False
        can_manage = can_manage_account(db, user, acct)
        feed = list_triage_runs(db, account_id=job["account_id"], limit=20)
        return job, acct, feed, can_manage

    job, acct, feed, _can_manage = await db_call(
        _triage_job_page_reads, db, job_id,
    )
    if job is None:
        return HTMLResponse("Job not found", status_code=404)

    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not _can_manage:
        return HTMLResponse("Forbidden", status_code=403)

    # Recent per-message rows for the live feed. Filter to runs
    # initiated by this job's actor on this account, started after
    # the job started_at — close enough; the runner stamps the
    # query column with "bulk:<job_id>" so we could filter exactly,
    # but limiting to recent rows keeps the read cheap.
    feed = [r for r in feed if r.get("query") == f"bulk:{job_id}"]

    return await _render(templates, request, "triage/job_progress.html", {
        "user": user,
        "acct": acct,
        "job": job,
        "feed": feed,
        "eta_secs": _job_eta_secs(job),
    })


@router.get(
    "/triage/jobs/{job_id}/progress",
    response_class=HTMLResponse,
)
async def triage_job_progress_fragment(
    request: Request, job_id: str, user: RequireUserFragment,
):
    """HTMX-poll fragment — the live progress block.

    Returned every 2s by the page's hx-trigger. Renders just the
    progress bar + counters + recent feed; the surrounding
    page chrome stays put."""
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, list_triage_runs,
    )

    # / — same hot-poll fragment as triage_job_page; bundle
    # the three reads + the can-manage check into a single hop.
    def _triage_job_progress_reads(db, job_id):
        job = get_triage_job(db, job_id)
        if job is None:
            return None, None, [], False
        acct = get_email_account(db, job["account_id"])
        can_manage = (
            acct is not None and can_manage_account(db, user, acct)
        )
        feed = list_triage_runs(db, account_id=job["account_id"], limit=20)
        return job, acct, feed, can_manage

    job, acct, feed, _can_manage = await db_call(
        _triage_job_progress_reads, db, job_id,
    )
    if job is None:
        return HTMLResponse("Job not found", status_code=404)

    if not _can_manage:
        return HTMLResponse("Forbidden", status_code=403)

    feed = [r for r in feed if r.get("query") == f"bulk:{job_id}"]

    return await _render(
        templates, request, "triage/_job_progress_fragment.html",
        {
            "job": job,
            "feed": feed,
            "eta_secs": _job_eta_secs(job),
        },
    )


@router.post(
    "/triage/jobs/{job_id}/cancel", response_class=HTMLResponse,
)
async def triage_job_cancel(
    request: Request, job_id: str, user: RequireUser,
):
    """Operator-driven cancel button.

    Flips the row's status to 'cancelled'. The supervised runner
    notices at the next batch boundary and exits cleanly. Returns
    a 303 back to the progress page so the operator sees the
    cancelled state on the next render."""

    db = get_db(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, request_triage_job_cancel,
    )

    # / — job fetch + account fetch + can-manage check +
    # the cancel write, ALL in one threadpool call.
    def _triage_job_cancel_apply() -> str:
        """Returns ``not_found`` / ``forbidden`` / ``ok``; on ``ok``
        the cancel has already been written.
        """
        job = get_triage_job(db, job_id)
        if job is None:
            return "not_found"
        acct = get_email_account(db, job["account_id"])
        if acct is None or not can_manage_account(db, user, acct):
            return "forbidden"
        request_triage_job_cancel(db, job_id)
        return "ok"

    status = await db_call(_triage_job_cancel_apply)
    if status == "not_found":
        return HTMLResponse("Job not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    return RedirectResponse(
        f"/triage/jobs/{job_id}", status_code=303,
    )


# ---------------------------------------------------------------------------
# Discover Categories
# ---------------------------------------------------------------------------

@router.get("/triage/discover", response_class=HTMLResponse)
async def discover_page(request: Request, user: RequireUser):
    """Discover Categories page -- scan a mailbox and suggest categories."""
    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(
        _discover_page_snapshot, db, user,
        request.query_params.get("owner_filter"),
    )

    return await _render(templates, request, "triage/discover.html", {
        "user": user,
        **snap,
    })


@router.get("/triage/discover/folders", response_class=HTMLResponse)
async def discover_folders(request: Request, user: RequireUserFragment):
    """HTMX endpoint to load folder list for an account."""
    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")

    account_id = _safe_int(request.query_params.get("account_id"), 0)

    from email_triage.web.db import get_email_account

    # / — DB-before-network: fetch + can-manage in one hop.
    def _discover_folders_gate() -> tuple[dict | None, bool]:
        acct_ = get_email_account(db, account_id)
        if acct_ is None:
            return None, False
        return acct_, can_manage_account(db, user, acct_)

    acct, _can_manage = await db_call(_discover_folders_gate)
    if acct is None:
        return await _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "error": "Account not found.",
        })
    if not _can_manage:
        return await _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "error": "Access denied.",
        })

    try:
        provider = await db_call(
            _create_provider_from_account, acct, secrets,
        )
        async with probe_session(provider):
            folders = await render_probe(provider, account_id=account_id)
    except Exception as e:
        return await _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "visible": set(),
            "error": f"Could not load folders: {scrub_exc(e, purpose='provider')}",  # N-179 R21_2
        })

    # Default checkboxes to the visible (included) folders from the routes
    # page prefs.  Folders with no pref entry are included by default.
    #  phase 3 — read happens after the network round-trip; threadpool
    # hop here lets a concurrent discover request progress while we wait.
    from email_triage.web.db import get_visible_folders
    visible = set(await db_call(get_visible_folders, db, account_id, folders))

    return await _render(templates, request, "triage/_discover_folders.html", {
        "folders": folders, "visible": visible, "error": None,
    })


def _redact_folders_if_hipaa(
    msg: str, folders: list[str], *, account_hipaa: bool,
) -> str:
    """HIPAA-redact every (relative) mailbox-folder name from an already-
    scrubbed, operator-facing error string (run18 #3 — §164.502(b) minimum-
    necessary / §164.514(d)(1)).

    THE one folder-redaction idiom (PD#5/#1) — shared by the per-folder funnel
    :func:`_scrub_folder_scan_error` AND the ``discover_run`` OUTER ``except``,
    so the two cannot drift. The scrub SSOT
    (:func:`email_triage._errfmt.scrub_error_for_persist` → ``redact_exc``)
    strips address- and PATH-shaped PHI, but a *relative* IMAP mailbox name
    ("INBOX.Smith-Labs") is NOT path-shaped, so it provably escapes the scrubber
    (the N-42 documented residual). On a HIPAA account we therefore redact each
    folder string wherever it survives in the (already-scrubbed) message —
    mirroring the sender/subject HIPAA redaction already in ``discover_run``.
    Non-HIPAA accounts keep readable folder names (fail-closed only for HIPAA);
    the address/path/secret scrub already ran UNCONDITIONALLY upstream.

    Each ``f`` truthiness guard avoids the empty-string ``replace`` trap
    (``"".replace("", x)`` would splice ``[redacted]`` between every char)."""
    if account_hipaa:
        for f in folders:
            if f:
                msg = msg.replace(f, REDACTED_PLACEHOLDER)  # N-217c R23
    return msg


def _scrub_folder_scan_error(
    prefix: str, folder: str, exc: BaseException, *, account_hipaa: bool,
) -> str:
    """Build a scrubbed, operator-facing folder-scan error for the discover
    ``errors`` list (run18 #3 — §164.502(b) minimum-necessary / §164.514(d)(1)).

    ONE funnel for BOTH discover folder-scan error sites (peek + select) so the
    two cannot drift (PD#5). The exception text routes through the scrub SSOT
    (:func:`email_triage._errfmt.scrub_error_for_persist`) — identical to the
    sibling ``triage_preview`` — which strips PHI-shaped substrings (email
    addresses, filesystem/mailbox PATHS) AND token-shaped secrets; the relative
    MAILBOX FOLDER NAME (a patient-named "INBOX.Smith-Labs") then routes through
    the shared :func:`_redact_folders_if_hipaa` HIPAA leg (the N-42 residual the
    scrub SSOT can't catch — both the explicit interpolation AND any echo inside
    the exception text). Non-HIPAA accounts keep the readable folder name
    (fail-closed only for HIPAA, per the sibling)."""
    msg = scrub_error_for_persist(f"{prefix} {folder}: {exc}") or ""
    return _redact_folders_if_hipaa(msg, [folder], account_hipaa=account_hipaa)


@router.post("/triage/discover/run", response_class=HTMLResponse)
async def discover_run(request: Request, user: RequireUserFragment):
    """Execute a category discovery scan on the selected account."""
    db = get_db(request)
    secrets = get_secrets(request)
    config = get_config(request)
    templates = get_templates(request)
    is_admin = _is_admin(user)  # N-222h R22 (was: user["role"] == "admin")

    form = await request.form()
    account_id = _safe_int(form.get("account_id"), 0)
    limit = _safe_int(form.get("limit"), 25)
    query = form.get("query", "ALL").strip()
    scan_scope = form.get("scan_scope", "inbox").strip()
    selected_folders = form.getlist("folders")  # For "selected" scope.

    if limit < 1 or limit > 100:
        limit = 25

    from email_triage.web.db import get_email_account
    from email_triage.triage_logging import is_account_hipaa

    #  phase 3 — DB-before-network: discover scan hits IMAP/Gmail.
    def _discover_gate_db_work() -> tuple[dict | None, bool, int | None]:
        """/ — fetch + can-manage check + (HIPAA) in-progress
        audit row, all in one threadpool hop. Returns
        ``(acct, can_manage, audit_event_id)``.
        """
        acct_ = get_email_account(db, account_id)
        if acct_ is None:
            return None, False, None
        if not can_manage_account(db, user, acct_):
            return acct_, False, None
        # HIPAA access-audit event (§164.312(b)). N-80: owner-self is EXEMPT
        # (§164.502(a) self-disclosure carve-out) — gate through the PD#14
        # predicate SSOT so discover matches the consolidated bookend
        # (audit_phi_access) + the other start→finalise bracket sites
        # (run_triage / topic_backscan / triage_runner_bulk). Before this,
        # discover audited on is_account_hipaa ALONE → an owner discovering
        # their OWN HIPAA mailbox over-audited (fail-safe, but divergent).
        audit_id: int | None = None
        from email_triage.db.audit import phi_access_audit_required
        if phi_access_audit_required(
            account_hipaa=is_account_hipaa(acct_),
            actor_user_id=user["id"],
            owner_id=acct_.get("user_id"),
        ):
            from email_triage.web.db import record_hipaa_access_event
            from email_triage.web._audit import safe_audit_write
            audit_id = safe_audit_write(
                lambda: record_hipaa_access_event(
                    db, user["id"], account_id, "discover",
                    outcome="in_progress",
                ),
                description=(
                    f"discover hipaa_access in_progress "
                    f"account_id={account_id} user_id={user['id']}"
                ),
                table="hipaa_access_events",
                emitter="record_hipaa_access_event",
            )
        return acct_, True, audit_id

    acct, _can_manage, _audit_event_id = await db_call(
        _discover_gate_db_work,
    )
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )
    if not _can_manage:
        return HTMLResponse("Forbidden", status_code=403)

    if not acct.get("is_active", True):
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
            '<p><strong>Account disabled.</strong> Enable it in '
            '<a href="/accounts">account settings</a> first.</p></article>'
        )

    # Helper: record the universal discover-run audit row. Called from
    # every exit path that represents a run attempt (success, partial-
    # failure, provider/classifier setup failure). Wrapped in try/except
    # so an audit insert failure never breaks the user-visible response.
    # / — async so the SQLite write runs off the event loop.
    async def _record_discover_audit(
        *, scanned: int, err_count: int, elapsed: float,
        folders: list[str] | None = None,
    ) -> None:
        def _work() -> None:
            from email_triage.web.db import record_discover_run
            from email_triage.web._audit import safe_audit_write
            # run18 #2 — route the best-effort discover-run audit through the
            # SSOT (never-raise + uniform audit_write_failed WARNING for
            # /health drift), not a hand-rolled swallowing try/except.
            safe_audit_write(
                lambda: record_discover_run(
                    db,
                    account_id=account_id,
                    account_name=acct.get("name", ""),
                    actor_user_id=user["id"],
                    scanned_count=scanned,
                    errors_count=err_count,
                    folders=folders or [],
                    elapsed_secs=elapsed,
                ),
                description=(
                    f"discover_run account={account_id} "
                    f"scanned={scanned} errors={err_count}"
                ),
            )

        await db_call(_work)

    async def _update_discover_hipaa_audit(outcome: str, detail: str) -> None:
        """/ — patch the HIPAA in-progress row off the loop."""
        if _audit_event_id is None:
            return

        def _work() -> None:
            from email_triage.web.db import update_hipaa_access_event
            update_hipaa_access_event(db, _audit_event_id, outcome, detail)

        await db_call(_work)

    # Create provider and classifier.
    try:
        provider = await db_call(
            _create_provider_from_account, acct, secrets,
        )
    except Exception as e:
        await _update_discover_hipaa_audit(
            "error", f"provider: {type(e).__name__}",
        )
        await _record_discover_audit(scanned=0, err_count=1, elapsed=0.0)
        return HTMLResponse(
            error_article(e, heading='Provider error')
        )

    try:
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        await _update_discover_hipaa_audit(
            "error", f"classifier: {type(e).__name__}",
        )
        await _record_discover_audit(scanned=0, err_count=1, elapsed=0.0)
        return HTMLResponse(
            error_article(e, heading='Classifier error')
        )

    # N-113 — HIPAA + BAA egress gate (§164.308(b)(1), shared SSOT). discover
    # scans the account's mail and completes it on `classifier` (the
    # classifier.complete() calls below); for a HIPAA account on an external
    # non-BAA'd classifier that PHI must NOT egress. Refuse BEFORE any complete()
    # — fail closed (audit "blocked" + a clear UI error). No-op for the common
    # local / BAA-acked classifier (baa_block_status → None). (audit alone is NOT
    # a gate — the N-113 lesson.)
    if isinstance(acct, dict) and is_account_hipaa(acct):
        from email_triage.ai_backends.base import BackendBAARequiredError
        from email_triage.classify.baa_gate import baa_block_status
        _baa_blk = await db_call(baa_block_status, db, classifier, True)
        if _baa_blk is not None:
            await _update_discover_hipaa_audit(
                "blocked",
                f"baa_gate: backend={_baa_blk['backend']} host={_baa_blk['host']}",
            )
            await _record_discover_audit(scanned=0, err_count=0, elapsed=0.0)
            return HTMLResponse(error_article(
                BackendBAARequiredError(
                    "HIPAA account: the configured classifier "
                    f"({_baa_blk['backend']} @ {_baa_blk['host'] or '?'}) is not "
                    "BAA-acked — discover skipped (no PHI egress). Acknowledge a "
                    "BAA on /config or switch to a local Ollama."
                ),
                heading='BAA required',
            ))

    # Get existing categories for comparison (account-scoped when an
    # account is bound to this discovery run, else user-scoped).
    _disc_user_id = acct.get("user_id") if isinstance(acct, dict) else user["id"]
    existing_categories = await db_call(
        _get_categories_from_db, db, user_id=_disc_user_id,
    )

    from email_triage.classify.discover import (
        build_consolidation_prompt,
        build_discover_prompt,
    )

    raw_results = []
    errors = []
    t0 = time.time()
    # run18 #3 (§164.502(b)) — resolve the HIPAA flag ONCE up front so every
    # folder-scan error built into `errors` below can redact a patient-named
    # mailbox folder out of the operator-facing page (the scrub SSOT can't
    # catch a *relative* mailbox name — the N-42 residual). is_account_hipaa
    # is already imported in this function scope (above).
    _account_hipaa = is_account_hipaa(acct)

    # Punch 694: the folder probe sits INSIDE the try whose finally owns the provider's close,
    # so a probe that dies outside ``Exception`` still releases the session.
    try:
        # Determine which folders to scan.
        folders_to_scan: list[str] = ["INBOX"]  # Default.
        if scan_scope == "all":
            try:
                # Punch 693: a scan the user started gets the provider's own 10 s budget, not
                # the 3 s page-render bound (a slow server showed the INBOX-only fallback as
                # an error on a scan the user asked for).
                all_folders = await render_probe(
                    provider, account_id=account_id,
                    timeout_s=USER_SCAN_PROBE_TIMEOUT_S,
                )
                folders_to_scan = all_folders if all_folders else ["INBOX"]
            except Exception as e:
                _log.warning("Could not list folders, falling back to INBOX", error=fmt_exc(e))
                errors.append(scrub_error_for_persist(
                    f"Could not list folders ({e}), scanning INBOX only."
                ))
        elif scan_scope == "selected" and selected_folders:
            folders_to_scan = selected_folders

        multi_folder = len(folders_to_scan) > 1
        can_peek = hasattr(provider, "peek_recent_uids") and hasattr(provider, "select_folder")

        # ── Build the list of (folder, uid) to classify ──
        # For multi-folder scans with IMAP: peek dates from each folder
        # (lightweight UID + INTERNALDATE fetch), pool them, pick the
        # newest `limit` messages globally.  This naturally weights toward
        # active folders instead of wasting slots on dead ones.
        targets: list[tuple[str, str]] = []  # (folder, uid)

        if multi_folder and can_peek:
            # Peek phase — cheap: only fetches UIDs + dates, no bodies.
            from email.utils import parsedate_to_datetime
            import re as _re

            candidates: list[tuple[str, str, datetime]] = []  # (folder, uid, dt)
            peek_per_folder = max(limit, 50)  # Generous peek to get enough candidates.

            for folder in folders_to_scan:
                try:
                    await provider.select_folder(folder)
                    pairs = await provider.peek_recent_uids(query, peek_per_folder)
                    for uid, date_str in pairs:
                        # Parse INTERNALDATE format: "16-Apr-2026 14:30:00 -0400"
                        try:
                            dt = parsedate_to_datetime(date_str)
                        except Exception:
                            try:
                                dt = datetime.strptime(
                                    date_str.strip(),
                                    "%d-%b-%Y %H:%M:%S %z",
                                )
                            except Exception:
                                dt = datetime.min.replace(tzinfo=timezone.utc)
                        candidates.append((folder, uid, dt))
                except Exception as e:
                    _log.warning("Discover peek failed", folder=folder, error=fmt_exc(e))
                    errors.append(_scrub_folder_scan_error(
                        "Could not peek", folder, e,
                        account_hipaa=_account_hipaa,
                    ))
                    continue

            # Sort by date descending, pick the newest `limit`.
            candidates.sort(key=lambda c: c[2], reverse=True)
            targets = [(folder, uid) for folder, uid, _ in candidates[:limit]]

            _log.info(
                "Discover peek complete",
                folders=len(folders_to_scan),
                candidates=len(candidates),
                selected=len(targets),
            )
        else:
            # Single folder (or provider without peek support): simple search.
            if can_peek and folders_to_scan[0] != "INBOX":
                await provider.select_folder(folders_to_scan[0])
            # Query-stage self-skip: exclude install's own outbound
            # from the discover scan too. Discover doesn't action; it
            # builds a category-discovery prompt — but it still spends
            # an LLM call per scanned message, so dropping self-mail at
            # SEARCH saves real money on large mailboxes.
            from email_triage.mail_headers import build_self_skip_query
            cfg = get_config(request)
            _self_from_addr = getattr(
                getattr(cfg, "smtp", None), "from_addr", "",
            )
            _eff_query = build_self_skip_query(
                query, _self_from_addr, provider_type=acct["provider_type"],
            )
            message_ids = await provider.search(_eff_query, limit)
            folder_name = folders_to_scan[0] if folders_to_scan else "INBOX"
            targets = [(folder_name, uid) for uid in message_ids]

        if not targets:
            await provider.close()
            # Universal audit row: record even when no messages matched.
            await _record_discover_audit(
                scanned=0,
                err_count=len(errors),
                elapsed=time.time() - t0,
                folders=folders_to_scan,
            )
            return await _render(templates, request, "triage/_discover_results.html", {
                "consolidated": [],
                "raw_results": [],
                "errors": errors,
                "total": 0,
                "elapsed": time.time() - t0,
                "acct": acct,
                "query": query,
                "new_count": 0,
                "existing_count": 0,
                "folders_scanned": folders_to_scan,
            })

        # ── Phase 1: Classify each selected message ──
        # Group targets by folder to minimise SELECT commands.
        from collections import defaultdict
        by_folder: dict[str, list[str]] = defaultdict(list)
        for folder, uid in targets:
            by_folder[folder].append(uid)

        current_folder = None
        for folder, uids in by_folder.items():
            if can_peek and folder != current_folder:
                try:
                    await provider.select_folder(folder)
                    current_folder = folder
                except Exception as e:
                    _log.warning("Discover: could not select folder", folder=folder, error=fmt_exc(e))
                    errors.append(_scrub_folder_scan_error(
                        "Error selecting", folder, e,
                        account_hipaa=_account_hipaa,
                    ))
                    continue

            for msg_id in uids:
                try:
                    message = await provider.fetch_message(msg_id)
                    message.hipaa = _account_hipaa
                    # Self-skip: even with the SEARCH-stage filter
                    # multi-folder peek paths skip the rewrite, so a
                    # secondary fetch-stage check is cheap insurance.
                    from email_triage.mail_headers import (
                        get_triage_header as _gth_d,
                        is_self_origin as _iso_d,
                    )
                    if _gth_d(message.headers):
                        continue
                    _cfg_d = get_config(request)
                    _from_d = getattr(
                        getattr(_cfg_d, "smtp", None), "from_addr", "",
                    )
                    if _iso_d(message.sender or "", _from_d):
                        continue
                    prompt = build_discover_prompt(message)
                    raw_text = await classifier.complete(prompt)
                    parsed = _parse_llm_json_or_array(raw_text)

                    # HIPAA: scrub sender/subject AND raw_description
                    # from the raw-scan panel. The LLM still sees the
                    # message for categorisation (local model, PHI stays
                    # on-device), but the persisted audit row shows
                    # redacted placeholders. raw_description is the
                    # classifier's free-form output — same PHI risk as
                    # the triage classifier's `reason` field.
                    raw_results.append({
                        "sender": REDACTED_PLACEHOLDER if _account_hipaa else message.sender,
                        "subject": REDACTED_PLACEHOLDER if _account_hipaa else message.subject,
                        "raw_category": parsed.get("category", "unknown"),
                        "raw_description": (
                            REDACTED_PLACEHOLDER if _account_hipaa
                            else parsed.get("description", "")
                        ),
                        "folder": folder,
                    })
                except Exception as e:
                    _log.warning(
                        "Discover: failed to process message",
                        message_id=msg_id, folder=folder, error=fmt_exc(e),
                    )
                    continue

    except Exception as e:
        # run18 #3 (DA, §164.502(b)) — the single-folder ``select_folder`` (:~1293)
        # and the unguarded ``provider.search`` (:~1307) bubble HERE carrying the
        # relative mailbox name, which the scrub SSOT can't catch (the N-42
        # residual). Redact EVERY scanned folder on a HIPAA account so a patient-
        # named folder can't reach the operator page — the SAME §164.502(b)
        # control the peek/select funnel sites already apply, closing the CLASS
        # (PD#1) rather than the two redacted sites + one un-redacted (PD#5).
        msg = scrub_error_for_persist(e) or ""
        errors.append(
            _redact_folders_if_hipaa(
                msg, folders_to_scan, account_hipaa=_account_hipaa,
            )
        )
        _log.error("Discover scan error", error=fmt_exc(e))
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        #  — drain the classifier's long-lived httpx pool. The
        # discover-scan endpoint's classifier is built once at
        # function entry and reused across N messages; close on exit.
        if "classifier" in locals() and hasattr(classifier, "close"):
            try:
                await classifier.close()
            except Exception:
                pass
        if _audit_event_id is not None:
            outcome = "error" if errors else "ok"
            detail = f"scanned={len(raw_results)}"
            if errors:
                detail += f"; errors={len(errors)}"

            def _finalize_hipaa_audit() -> None:
                """/ — finalize the HIPAA row off the loop."""
                from email_triage.web.db import update_hipaa_access_event
                from email_triage.web._audit import safe_audit_write
                # Allow-list step 2 (B1): the finalise routes through the SSOT.
                safe_audit_write(
                    lambda: update_hipaa_access_event(
                        db, _audit_event_id, outcome, detail,
                    ),
                    description=(
                        f"classify_preview_finalise "
                        f"audit_event_id={_audit_event_id} outcome={outcome}"
                    ),
                    table="hipaa_access_events",
                    emitter="update_hipaa_access_event",
                )

            await db_call(_finalize_hipaa_audit)

    # Phase 2: Aggregate raw suggestions.
    aggregated: dict[str, dict] = {}
    for r in raw_results:
        key = r["raw_category"].lower().strip()
        if key not in aggregated:
            aggregated[key] = {
                "category": key,
                "description": r["raw_description"],
                "count": 0,
                "examples": [],
            }
        aggregated[key]["count"] += 1
        if len(aggregated[key]["examples"]) < 5:
            aggregated[key]["examples"].append(r["subject"][:60])

    agg_list = sorted(aggregated.values(), key=lambda x: x["count"], reverse=True)

    # Phase 3: Consolidation via LLM.
    consolidated = []
    if agg_list and not errors:
        try:
            consolidation_prompt = build_consolidation_prompt(
                agg_list, existing_categories,
            )
            consolidation_text = await classifier.complete(consolidation_prompt)
            parsed_consolidated = _parse_llm_json_or_array(consolidation_text)

            if isinstance(parsed_consolidated, list):
                consolidated = parsed_consolidated
            elif isinstance(parsed_consolidated, dict):
                # LLM wrapped it in an object -- try to find the array inside.
                for v in parsed_consolidated.values():
                    if isinstance(v, list):
                        consolidated = v
                        break
                if not consolidated:
                    consolidated = [parsed_consolidated]
        except Exception as e:
            errors.append(scrub_error_for_persist(f"Consolidation failed: {e}"))
            _log.error("Discover consolidation error", error=fmt_exc(e))

    # Ensure consolidated entries have expected keys.
    # is_new is determined server-side by checking the DB — the LLM's
    # self-reported is_new flag is unreliable (it hallucinates matches
    # against categories that don't exist).
    existing_slugs = {s.lower() for s in existing_categories}
    clean_consolidated = []
    for cat in consolidated:
        slug = cat.get("slug", "unknown")
        clean_consolidated.append({
            "slug": slug,
            "description": cat.get("description", ""),
            "count": cat.get("count", 0),
            "is_new": slug.lower() not in existing_slugs,
            "merged_from": cat.get("merged_from", []),
        })

    new_count = sum(1 for c in clean_consolidated if c["is_new"])
    existing_count = len(clean_consolidated) - new_count

    elapsed = time.time() - t0

    # Collect unique folders that actually had results.
    folders_with_results = sorted({r["folder"] for r in raw_results})

    # Universal discover-run audit row — runs for every account (HIPAA and
    # non-HIPAA alike). Independent of the HIPAA access event above; HIPAA
    # accounts intentionally land in both trails.
    await _record_discover_audit(
        scanned=len(raw_results),
        err_count=len(errors),
        elapsed=elapsed,
        folders=folders_to_scan,
    )

    return await _render(templates, request, "triage/_discover_results.html", {
        "consolidated": clean_consolidated,
        "raw_results": raw_results,
        "errors": errors,
        "total": len(raw_results),
        "elapsed": elapsed,
        "acct": acct,
        "query": query,
        "new_count": new_count,
        "existing_count": existing_count,
        "folders_scanned": folders_to_scan,
        "folders_with_results": folders_with_results,
    })


