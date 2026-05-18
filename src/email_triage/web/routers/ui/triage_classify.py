"""Routes for the triage_classify concern.

Split out of the legacy `web/routers/ui.py` (#144). Helpers
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

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

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
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

_log = get_logger("web.ui.triage_classify")

router = APIRouter()


def __getattr__(name):
    """Route reads of legacy install-singleton names through the factory.

    The factory module (#138.1) now owns ``_install_google_oauth`` and
    ``_install_ingestion_config``. Code that did
    ``from email_triage.web.routers.ui import _install_ingestion_config``
    (e.g. test fixtures, future plugins) keeps working — PEP 562 lets
    us proxy module-level reads to the factory's current values.
    """
    if name == "_install_google_oauth":
        from email_triage.providers import factory as _f
        return _f._install_google_oauth
    if name == "_install_ingestion_config":
        from email_triage.providers import factory as _f
        return _f._install_ingestion_config
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")



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
    """PEP 562 fallback — late-bound lookup on _shared.

    Catches names added to `_shared` after this module's globals
    were populated, plus names that the package-level monkeypatch
    mirror writes onto `_shared` AFTER import.
    """
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f'module {__name__!r} has no attribute {name!r}'
    )


@router.get("/classify", response_class=HTMLResponse)
async def classify_page(request: Request):
    """Test-classify page — open to any authenticated user (#95 sub-E).

    Useful to investigate why a specific message classified the way
    it did, regardless of admin role. Categories shown to the user
    are scoped to system + their personal categories (already the
    case in classify_run); no admin-only data leaks via the test
    surface.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    templates = get_templates(request)
    return _render(templates, request, "classify.html", {"user": user})


@router.post("/classify/run", response_class=HTMLResponse)
async def classify_run(request: Request, raw_email: str = Form(...)):
    """Parse a raw email and classify it via the configured LLM.

    #95 sub-E: open to any authenticated user. The categories pulled
    from the DB are user-scoped (system + the user's personal),
    not admin-global; no privilege escalation via this endpoint.
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    templates = get_templates(request)
    db = get_db(request)
    config = get_config(request)

    # Parse the raw email.
    try:
        parsed = _parse_raw_email(raw_email)
    except Exception as exc:
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
            f'<p><strong>Parse error:</strong> {exc}</p></article>'
        )

    # Get categories from DB (user-scoped: system + current user's personal).
    categories = _get_categories_from_db(db, user_id=user["id"])
    if not categories:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
            '<p>No categories configured. Add categories first.</p></article>'
        )

    # Collect list hints (from all lists in DB).
    list_hints = _collect_list_hints_for_message(db, parsed)

    # #163-followup — Test Classify must mirror the production
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
        from email_triage.engine.models import Classification
        classification = Classification(
            category=skip_hint.category,
            confidence=1.0,
            reason=(
                f"Matched rule (Force category): "
                f"{skip_hint.rule_type.value} = \"{skip_hint.pattern}\""
            ),
            source="list_rule",
        )
        return _render(templates, request, "classify/_result.html", {
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
            )
        elif backend == "openai":
            from email_triage.classify.openai_compat import OpenAIClassifier
            classifier = OpenAIClassifier(
                model=config.classifier.openai_model,
                base_url=config.classifier.openai_base_url,
                local_url_suffixes=_local_suffixes,
            )
        elif backend == "gemini":
            from email_triage.classify.gemini import GeminiClassifier
            classifier = GeminiClassifier(
                model=config.classifier.gemini_model,
            )
        else:
            return HTMLResponse(
                f'<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
                f'<p>Unknown classifier backend: {backend}</p></article>'
            )

        try:
            classification = await classifier.classify(parsed, categories, list_hints or None)
        finally:
            # #139 — drain the long-lived httpx pool the classifier
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
            f'<article style="border-left:3px solid var(--pico-color-red-500);padding:0.5rem 1rem;">'
            f'<p><strong>Classification error ({elapsed:.1f}s):</strong> {exc}</p></article>'
        )

    model_label = config.classifier.model if backend == "ollama" else backend
    return _render(templates, request, "classify/_result.html", {
        "classification": classification,
        "parsed": parsed,
        "timing": elapsed,
        "model": model_label,
        # #163-followup — pass advisory hints through so the result
        # page can surface "rule matched but AI overrode" cases.
        # Operator caught this discrepancy on a CTOx rule that the
        # AI legitimately overrode (rule was advisory, not Force).
        "list_hints": list_hints,
        "skip_hint": None,  # the skip_ai short-circuit returned earlier
    })


@router.get("/triage", response_class=HTMLResponse)
async def triage_page(request: Request):
    """Run Triage page — select account, limit, and run.

    When the current user can see accounts owned by more than one
    person (admin-of-the-install OR delegate of someone else's
    account), surface an "Owner" filter dropdown that defaults to
    the current user. Accounts list filters to the selected owner.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)

    snap = await db_call(
        _triage_page_snapshot, db, user,
        request.query_params.get("owner_filter"),
    )

    # #151 — surface whether the optional classification cache is
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

    return _render(templates, request, "triage/run.html", {
        "user": user,
        "classification_cache_enabled": classification_cache_enabled,
        **snap,
    })


@router.post("/triage/run", response_class=HTMLResponse)
async def triage_run(request: Request):
    """Execute a triage cycle on the selected account.

    Thin wrapper over :func:`email_triage.web.triage_runner.run_triage` —
    parses the form, enforces ownership, calls the runner, then fires
    the ``triage.completed`` event and renders the results template.
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    secrets = get_secrets(request)
    config = get_config(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    form = await request.form()
    account_id = int(form.get("account_id", 0))
    # Mode: "inline" (default; bounded sync run) or "all" (background
    # whole-mailbox sweep, #101). The form field is the radio button
    # added on triage/run.html in step 6.
    mode = (form.get("mode") or "inline").strip()
    limit = int(form.get("limit", 5))

    # #61 — preset dropdown + Other/freeform. Preset maps to IMAP SEARCH
    # syntax; the Gmail provider's translator converts at search time.
    preset = (form.get("search_preset") or "").strip()
    freeform = form.get("query", "").strip()
    query = _triage_preset_to_query(preset, freeform)

    # #129 — "Has label" filter. When set, intersect the provider's
    # search results with the set of message_ids tagged with this
    # slug on this account. The intersection lives in
    # triage_runner.run_triage's caller flow — we read the labeled
    # ids here, then pass via a label_filter_ids set.
    has_label = (form.get("has_label") or "").strip().lower()

    # #151 — force re-classify checkbox. Bypasses the optional Redis
    # classification cache for this run (every message hits the LLM).
    # Result still gets written back so the next non-force run hits.
    # Default unchecked — operator opts in to spend tokens.
    force_reclassify = bool(form.get("force_reclassify"))

    if limit < 1 or limit > 100:
        limit = 5

    from email_triage.web.db import get_email_account

    # #135 phase 3 — DB-before-network: triage runs hit the provider next.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )
    if not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    # ── Bulk-mode branch (#101) ──
    # "All matches (background)" — create a triage_jobs row + 303 to
    # the progress page. The supervised bulk runner picks it up
    # within POLL_INTERVAL_SECS. Refuses a second concurrent submit
    # on the same account (one bulk job per account at a time).
    if mode == "all":
        from email_triage.web.db import (
            create_triage_job, count_active_triage_jobs_for_account,
        )
        if count_active_triage_jobs_for_account(db, account_id) > 0:
            return HTMLResponse(
                '<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
                '<p><strong>A bulk run is already active on this account.</strong> Wait for it to finish or cancel it from its progress page.</p></article>'
            )
        runtime = _get_runtime_settings(db)
        rate = int(runtime.get(
            "bulk_triage_rate_msg_per_min",
            _RUNTIME_DEFAULTS["bulk_triage_rate_msg_per_min"],
        ))
        conc = int(runtime.get(
            "bulk_triage_concurrency",
            _RUNTIME_DEFAULTS["bulk_triage_concurrency"],
        ))
        job_id = create_triage_job(
            db, account_id=account_id, actor_user_id=user["id"],
            query=query, rate_msg_per_min=rate, concurrency=conc,
        )
        # The submit form is HTMX-driven (it swaps inline results
        # into #triage-results for inline mode). For bulk mode we
        # need a full-page navigation to the progress page, NOT an
        # in-place swap. HTMX recognizes the HX-Redirect response
        # header and triggers window.location — same effect as a
        # plain 303 for non-HTMX clients (we still set status 200
        # so HTMX honours the header rather than chasing redirect).
        is_htmx = request.headers.get("HX-Request") == "true"
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

    # #129 — "Has label" filter. Apply post-runner: keep only result
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
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            f'<p>{msg}</p></article>'
        )
    if run.get("error") == "classifier_error":
        msg = (run["errors"] or ["Classifier error"])[0]
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            f'<p>{msg}</p></article>'
        )

    # Best-effort outbound webhook emit. Never blocks the response.
    dispatcher = getattr(request.app.state, "event_dispatcher", None)
    if dispatcher is not None:
        try:
            await fire_triage_completed(dispatcher, db, config, acct, run, trigger="manual")
        except Exception as e:
            _log.warning("triage.completed dispatch failed", error=fmt_exc(e))

    # #129 — labels catalog drives the bulk-tag toolbar on the
    # results table. Pass even when empty so the template's
    # `{% if all_labels %}` gate stays consistent across renders.
    from email_triage.web.db import list_labels
    all_labels = await db_call(list_labels, db)

    return _render(templates, request, "triage/_results.html", {
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
async def triage_preview(request: Request):
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
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    form = await request.form()
    account_id = int(form.get("account_id", 0))
    preset = (form.get("search_preset") or "").strip()
    freeform = form.get("query", "").strip()
    query = _triage_preset_to_query(preset, freeform)

    from email_triage.web.db import get_email_account

    # #135 phase 3 — DB-before-network: provider preview hits IMAP/Gmail.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )
    if not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    # Cheap rate-limit: 1 preview / account / 10 s. Stored in a
    # ratelimit:* setting key with a wall-clock timestamp + bucketed
    # window. Overkill to plumb a per-account redis-like primitive
    # for this; the existing get_setting / set_setting pattern works.
    import time as _time
    from email_triage.web.db import get_setting, set_setting
    rl_key = f"ratelimit:triage_preview:{account_id}"
    last = get_setting(db, rl_key) or 0.0
    now = _time.time()
    if now - float(last) < 10.0:
        wait = int(10 - (now - float(last)))
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
            f'<p>Preview cooling down — wait ~{wait}s and try again.</p></article>'
        )
    set_setting(db, rl_key, now)

    # HIPAA audit row — actor != owner on HIPAA account.
    from email_triage.triage_logging import is_account_hipaa
    if (
        is_account_hipaa(acct)
        and user.get("id") != acct.get("user_id")
    ):
        try:
            from email_triage.web.db import record_hipaa_access_event
            record_hipaa_access_event(
                db, user["id"], account_id, "triage_preview",
                outcome="success",
            )
        except Exception as e:
            _log.warning(
                "HIPAA preview audit row write failed",
                error=fmt_exc(e),
            )

    # Provider lookup + fetch.
    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception as e:
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            f'<p>Provider error: {type(e).__name__}: {e}</p></article>'
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
                except Exception:
                    pass
                rows.append(row)
            except Exception as fe:
                rows.append({
                    "id": msg_id, "sender": "(fetch error)",
                    "subject": str(fe), "date_iso": "",
                })
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        try:
            await provider.close()
        except Exception:
            pass

    return _render(templates, request, "triage/_preview.html", {
        "rows": rows,
        "total": len(rows),
        "limit": PREVIEW_LIMIT,
        "error": err,
        "query": query,
        "acct": acct,
    })


# ---------------------------------------------------------------------------
# Bulk triage jobs (#101) — /triage/jobs index + /triage/jobs/<job_id> per-job
# ---------------------------------------------------------------------------

@router.get(
    "/triage/jobs", response_class=HTMLResponse,
)
async def triage_jobs_index(request: Request):
    """Index of bulk runs across every account the user can manage.

    Filed because the per-job page (``/triage/jobs/<id>``) was the
    only surface — there was no listing. The mine-limit-override
    tooltip on ``/profile/style-data`` referenced "the Bulk runs
    page" with no place to point. This handler is that page.

    Shows queued / running first (live work), then recent done /
    failed / cancelled (history). Cap at 50 across both, newest
    first.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        list_email_accounts, list_triage_jobs,
    )

    def _jobs_index_reads(db, user_id):
        # Pull all accounts the user owns / delegates so we can
        # narrow jobs to "their" surface — admin-viewing-everyone is
        # a separate concern.
        accts = list_email_accounts(db, user_id=user_id)
        acct_ids = {int(a["id"]) for a in accts}
        accts_by_id = {int(a["id"]): a for a in accts}
        # No per-user filter on triage_jobs today; we filter
        # client-side via the account_id set above. 50 is the cap;
        # paging not implemented (no operator pressure yet).
        jobs = list_triage_jobs(db, limit=50)
        jobs = [j for j in jobs if int(j["account_id"]) in acct_ids]
        return jobs, accts_by_id

    jobs, accts_by_id = await db_call(
        _jobs_index_reads, db, user.get("id"),
    )

    # Split for the template: active (queued + running) at top,
    # everything else underneath. Within each bucket, newest first
    # (already sorted by created_at DESC from the DB).
    active = [j for j in jobs if j.get("status") in ("queued", "running")]
    done = [j for j in jobs if j.get("status") not in ("queued", "running")]

    return _render(templates, request, "triage/jobs_index.html", {
        "user": user,
        "active_jobs": active,
        "done_jobs": done,
        "accts_by_id": accts_by_id,
    })


@router.get(
    "/triage/jobs/{job_id}", response_class=HTMLResponse,
)
async def triage_job_page(request: Request, job_id: str):
    """Full-page progress view for a bulk-triage job."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, list_triage_runs,
    )

    # #135 phase 3 — every read in this handler hops via threadpool;
    # the page is polled every 2s so this matters at scale.
    def _triage_job_page_reads(db, job_id):
        job = get_triage_job(db, job_id)
        if job is None:
            return None, None, []
        acct = get_email_account(db, job["account_id"])
        feed = list_triage_runs(db, account_id=job["account_id"], limit=20)
        return job, acct, feed

    job, acct, feed = await db_call(_triage_job_page_reads, db, job_id)
    if job is None:
        return HTMLResponse("Job not found", status_code=404)

    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    # Recent per-message rows for the live feed. Filter to runs
    # initiated by this job's actor on this account, started after
    # the job started_at — close enough; the runner stamps the
    # query column with "bulk:<job_id>" so we could filter exactly,
    # but limiting to recent rows keeps the read cheap.
    feed = [r for r in feed if r.get("query") == f"bulk:{job_id}"]

    return _render(templates, request, "triage/job_progress.html", {
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
    request: Request, job_id: str,
):
    """HTMX-poll fragment — the live progress block.

    Returned every 2s by the page's hx-trigger. Renders just the
    progress bar + counters + recent feed; the surrounding
    page chrome stays put."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, list_triage_runs,
    )

    # #135 phase 3 — same hot-poll fragment as triage_job_page; bundle
    # the three reads into a single threadpool hop.
    def _triage_job_progress_reads(db, job_id):
        job = get_triage_job(db, job_id)
        if job is None:
            return None, None, []
        acct = get_email_account(db, job["account_id"])
        feed = list_triage_runs(db, account_id=job["account_id"], limit=20)
        return job, acct, feed

    job, acct, feed = await db_call(_triage_job_progress_reads, db, job_id)
    if job is None:
        return HTMLResponse("Job not found", status_code=404)

    if acct is None or not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    feed = [r for r in feed if r.get("query") == f"bulk:{job_id}"]

    return _render(
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
async def triage_job_cancel(request: Request, job_id: str):
    """Operator-driven cancel button.

    Flips the row's status to 'cancelled'. The supervised runner
    notices at the next batch boundary and exits cleanly. Returns
    a 303 back to the progress page so the operator sees the
    cancelled state on the next render."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)

    from email_triage.web.db import (
        get_email_account, get_triage_job, request_triage_job_cancel,
    )

    # #135 phase 3 — fold the three sync hops into one threadpool call.
    def _triage_job_cancel_apply(db, job_id, user_id, is_admin):
        job = get_triage_job(db, job_id)
        if job is None:
            return None, None, "not_found"
        acct = get_email_account(db, job["account_id"])
        if acct is None:
            return job, None, "forbidden"
        # Mirror can_manage_account's logic without re-importing in the
        # nested helper: owner-or-admin OR explicit delegate. Defer the
        # delegate check to the outer caller via the acct return.
        return job, acct, "ok"

    is_admin = user["role"] == "admin"
    job, acct, status = await db_call(
        _triage_job_cancel_apply, db, job_id, user["id"], is_admin,
    )
    if status == "not_found":
        return HTMLResponse("Job not found", status_code=404)
    if acct is None or not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    await db_call(request_triage_job_cancel, db, job_id)
    return RedirectResponse(
        f"/triage/jobs/{job_id}", status_code=303,
    )


# ---------------------------------------------------------------------------
# Discover Categories
# ---------------------------------------------------------------------------

@router.get("/triage/discover", response_class=HTMLResponse)
async def discover_page(request: Request):
    """Discover Categories page -- scan a mailbox and suggest categories."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(
        _discover_page_snapshot, db, user,
        request.query_params.get("owner_filter"),
    )

    return _render(templates, request, "triage/discover.html", {
        "user": user,
        **snap,
    })


@router.get("/triage/discover/folders", response_class=HTMLResponse)
async def discover_folders(request: Request):
    """HTMX endpoint to load folder list for an account."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    account_id = int(request.query_params.get("account_id", 0))

    from email_triage.web.db import get_email_account
    # #135 phase 3 — DB-before-network: provider.list_folders() below.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "error": "Account not found.",
        })
    if not can_manage_account(db, user, acct):
        return _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "error": "Access denied.",
        })

    try:
        provider = _create_provider_from_account(acct, secrets)
        folders = await provider.list_folders()
        await provider.close()
    except Exception as e:
        return _render(templates, request, "triage/_discover_folders.html", {
            "folders": [], "visible": set(), "error": f"Could not load folders: {e}",
        })

    # Default checkboxes to the visible (included) folders from the routes
    # page prefs.  Folders with no pref entry are included by default.
    # #135 phase 3 — read happens after the network round-trip; threadpool
    # hop here lets a concurrent discover request progress while we wait.
    from email_triage.web.db import get_visible_folders
    visible = set(await db_call(get_visible_folders, db, account_id, folders))

    return _render(templates, request, "triage/_discover_folders.html", {
        "folders": folders, "visible": visible, "error": None,
    })


@router.post("/triage/discover/run", response_class=HTMLResponse)
async def discover_run(request: Request):
    """Execute a category discovery scan on the selected account."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    secrets = get_secrets(request)
    config = get_config(request)
    templates = get_templates(request)
    is_admin = user["role"] == "admin"

    form = await request.form()
    account_id = int(form.get("account_id", 0))
    limit = int(form.get("limit", 25))
    query = form.get("query", "ALL").strip()
    scan_scope = form.get("scan_scope", "inbox").strip()
    selected_folders = form.getlist("folders")  # For "selected" scope.

    if limit < 1 or limit > 100:
        limit = 25

    from email_triage.web.db import get_email_account

    # #135 phase 3 — DB-before-network: discover scan hits IMAP/Gmail.
    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            '<p>Account not found.</p></article>'
        )
    if not can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    if not acct.get("is_active", True):
        return HTMLResponse(
            '<article style="border-left:3px solid var(--pico-color-amber-500);padding:0.5rem 1rem;">'
            '<p><strong>Account disabled.</strong> Enable it in '
            '<a href="/accounts">account settings</a> first.</p></article>'
        )

    # HIPAA access-audit event (§164.312(b)).
    from email_triage.triage_logging import is_account_hipaa
    _audit_event_id: int | None = None
    if is_account_hipaa(acct):
        from email_triage.web.db import record_hipaa_access_event
        try:
            _audit_event_id = record_hipaa_access_event(
                db, user["id"], account_id, "discover", outcome="in_progress",
            )
        except Exception as e:
            _log.warning("Failed to record HIPAA access event", error=fmt_exc(e))

    # Helper: record the universal discover-run audit row. Called from
    # every exit path that represents a run attempt (success, partial-
    # failure, provider/classifier setup failure). Wrapped in try/except
    # so an audit insert failure never breaks the user-visible response.
    def _record_discover_audit(
        *, scanned: int, err_count: int, elapsed: float,
        folders: list[str] | None = None,
    ) -> None:
        try:
            from email_triage.web.db import record_discover_run
            record_discover_run(
                db,
                account_id=account_id,
                account_name=acct.get("name", ""),
                actor_user_id=user["id"],
                scanned_count=scanned,
                errors_count=err_count,
                folders=folders or [],
                elapsed_secs=elapsed,
            )
        except Exception as audit_err:
            _log.warning(
                "Failed to record discover_run audit", error=str(audit_err),
            )

    # Create provider and classifier.
    try:
        provider = _create_provider_from_account(acct, secrets)
    except Exception as e:
        if _audit_event_id is not None:
            from email_triage.web.db import update_hipaa_access_event
            update_hipaa_access_event(db, _audit_event_id, "error", f"provider: {type(e).__name__}")
        _record_discover_audit(scanned=0, err_count=1, elapsed=0.0)
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            f'<p>Provider error: {e}</p></article>'
        )

    try:
        classifier = _build_classifier_from_config(config)
    except Exception as e:
        if _audit_event_id is not None:
            from email_triage.web.db import update_hipaa_access_event
            update_hipaa_access_event(db, _audit_event_id, "error", f"classifier: {type(e).__name__}")
        _record_discover_audit(scanned=0, err_count=1, elapsed=0.0)
        return HTMLResponse(
            f'<article style="border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;">'
            f'<p>Classifier error: {e}</p></article>'
        )

    # Get existing categories for comparison (account-scoped when an
    # account is bound to this discovery run, else user-scoped).
    _disc_user_id = acct.get("user_id") if isinstance(acct, dict) else user["id"]
    existing_categories = _get_categories_from_db(db, user_id=_disc_user_id)

    from email_triage.classify.discover import (
        build_consolidation_prompt,
        build_discover_prompt,
    )

    raw_results = []
    errors = []
    t0 = time.time()

    # Determine which folders to scan.
    folders_to_scan: list[str] = ["INBOX"]  # Default.
    if scan_scope == "all":
        try:
            all_folders = await provider.list_folders()
            folders_to_scan = all_folders if all_folders else ["INBOX"]
        except Exception as e:
            _log.warning("Could not list folders, falling back to INBOX", error=fmt_exc(e))
            errors.append(f"Could not list folders ({e}), scanning INBOX only.")
    elif scan_scope == "selected" and selected_folders:
        folders_to_scan = selected_folders

    multi_folder = len(folders_to_scan) > 1
    can_peek = hasattr(provider, "peek_recent_uids") and hasattr(provider, "select_folder")

    try:
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
                    errors.append(f"Could not peek {folder}: {e}")
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
            # Query-stage self-skip (#117): exclude install's own outbound
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
            _record_discover_audit(
                scanned=0,
                err_count=len(errors),
                elapsed=time.time() - t0,
                folders=folders_to_scan,
            )
            return _render(templates, request, "triage/_discover_results.html", {
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

        from email_triage.triage_logging import is_account_hipaa
        _account_hipaa = is_account_hipaa(acct)
        current_folder = None
        for folder, uids in by_folder.items():
            if can_peek and folder != current_folder:
                try:
                    await provider.select_folder(folder)
                    current_folder = folder
                except Exception as e:
                    _log.warning("Discover: could not select folder", folder=folder, error=fmt_exc(e))
                    errors.append(f"Error selecting {folder}: {e}")
                    continue

            for msg_id in uids:
                try:
                    message = await provider.fetch_message(msg_id)
                    message.hipaa = _account_hipaa
                    # Self-skip (#117): even with the SEARCH-stage filter
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
                        "sender": "[redacted]" if _account_hipaa else message.sender,
                        "subject": "[redacted]" if _account_hipaa else message.subject,
                        "raw_category": parsed.get("category", "unknown"),
                        "raw_description": (
                            "[redacted]" if _account_hipaa
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
        errors.append(str(e))
        _log.error("Discover scan error", error=fmt_exc(e))
    finally:
        try:
            await provider.close()
        except Exception:
            pass
        # #139 — drain the classifier's long-lived httpx pool. The
        # discover-scan endpoint's classifier is built once at
        # function entry and reused across N messages; close on exit.
        if "classifier" in locals() and hasattr(classifier, "close"):
            try:
                await classifier.close()
            except Exception:
                pass
        if _audit_event_id is not None:
            from email_triage.web.db import update_hipaa_access_event
            outcome = "error" if errors else "ok"
            detail = f"scanned={len(raw_results)}"
            if errors:
                detail += f"; errors={len(errors)}"
            try:
                update_hipaa_access_event(db, _audit_event_id, outcome, detail)
            except Exception as e:
                _log.warning("Failed to finalize HIPAA access event", error=fmt_exc(e))

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
            errors.append(f"Consolidation failed: {e}")
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
    _record_discover_audit(
        scanned=len(raw_results),
        err_count=len(errors),
        elapsed=elapsed,
        folders=folders_to_scan,
    )

    return _render(templates, request, "triage/_discover_results.html", {
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


