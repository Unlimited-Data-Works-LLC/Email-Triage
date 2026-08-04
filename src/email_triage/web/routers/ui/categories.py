"""Routes for the categories concern.

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

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage._envbool import parse_bool
from email_triage.engine.models import WEB_ALLOWED_RULE_TYPES
from email_triage.web._flash import scrub_exc  # N-179 R21_2 sub-3 SSOT
from email_triage.web.error_html import error_chip

from email_triage.engine.models import Classification, EmailMessage, UserRole
from email_triage.providers.provider_labels import (
    list_provider_labels_for_account,
)
from email_triage.web.db import can_manage_account, get_email_account
from email_triage.web import settings_keys as _S
from email_triage.web._list_authz import may_manage_global_lists
from email_triage.web._audit import safe_audit_write
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
from email_triage.web.dependencies import (  # N-337: audit-XFF SSOT
    audit_forwarded_for,
    request_meta,
    OwnedAccount,
    OwnedAccountOrLogin,
    OwnedGmailApiAccount,
    RequireUser,
    RequireUserFragment,
    admin_gate_response,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc, scrub_error_for_persist
from email_triage._int_utils import parse_int_or_none  # N-219c/8 R23

# async-db: handlers route SQLite through db_call
_log = get_logger("web.ui.categories")

router = APIRouter()


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


def _parse_provider_labels_form(raw_values: list[str]) -> list[dict]:
    """ — parse the ``provider_labels`` form field into the DB
    shape.

    Each form value is ``<account_id>:<label_slug>`` (the picker
    checkbox encoding). Malformed entries (no ``:``, non-int prefix)
    are silently dropped — defensive line for half-submitted forms
    or tampered DOM values.

    Returns a list of ``{"account_id": int, "label_slug": str}``
    dicts ready for ``_save_rule_snapshot`` / ``_create_list_snapshot``
    / ``_add_rule_snapshot``.
    """
    out: list[dict] = []
    for raw in raw_values or []:
        if not isinstance(raw, str) or ":" not in raw:
            continue
        aid_str, slug = raw.split(":", 1)
        slug = slug.strip()
        if not slug:
            continue
        aid = parse_int_or_none(aid_str)  # N-219c/8 R23: SSOT
        if aid is None:
            continue
        out.append({"account_id": aid, "label_slug": slug})
    return out


def _gate_provider_labels(conn, user: dict, parsed: list[dict]) -> list[dict]:
    """A1 (2026-06-09 divergence census, CRITICAL) — fail-closed account-scope
    gate for client-supplied provider-label targets.

    The ``provider_labels`` form value is ``<account_id>:<label_slug>`` — the
    ``account_id`` prefix is fully attacker-controllable (a tampered DOM value
    or a hand-crafted POST). Without this gate, a user could submit ANOTHER
    user's ``account_id`` and have the saved rule write a provider-label-apply
    into a mailbox they do not manage; the background rule-runner later applies
    it with no actor gate — a cross-account §164.312(a)(1) WRITE.

    Drops every entry whose account the actor cannot manage (owner / delegate /
    admin, via :func:`can_manage_account`), fail-closed, logging the drop count
    (PHI-free). Mirrors the N-28 read-side gate on the search-details path; this
    is the write-side sibling.
    """
    if not parsed:
        return parsed
    gated: list[dict] = []
    dropped = 0
    for pl in parsed:
        acct = get_email_account(conn, pl["account_id"])
        if acct is not None and can_manage_account(conn, user, acct):
            gated.append(pl)
        else:
            dropped += 1
    if dropped:
        _log.warning(
            "provider_label account-scope: dropped unmanageable target(s)",
            extra={"_extra": {"user_id": user.get("id"), "dropped": dropped}},
        )
    return gated


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, user: RequireUser):
    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_build_rules_page_snapshot, db, user)

    return await _render(templates, request, "rules/lists.html", {
        "user": user,
        "personal_lists": snap["personal_lists"],
        "global_lists": snap["global_lists"],
        "categories": snap["categories"],
        "all_labels": snap.get("all_labels", []),
        "rule_types": list(WEB_ALLOWED_RULE_TYPES),
    })


@router.get("/rules/global", response_class=HTMLResponse)
async def global_rules_page(request: Request, user: RequireUser):
    if not may_manage_global_lists(user["role"]):
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_build_rules_page_snapshot, db, user)

    return await _render(templates, request, "rules/global.html", {
        "user": user,
        "global_lists": snap["global_lists"],
        "categories": snap["categories"],
        "all_labels": snap.get("all_labels", []),
        "rule_types": list(WEB_ALLOWED_RULE_TYPES),
    })


@router.post("/rules/create", response_class=HTMLResponse)
async def create_list(
    request: Request,
    user: RequireUserFragment,
    name: str = Form(...),
    category: str = Form(...),
    is_global: str = Form("0"),
    rule_type: str = Form(""),
    pattern: str = Form(""),
    skip_ai: str = Form("0"),
):
    global_flag = parse_bool(is_global)
    if global_flag and not may_manage_global_lists(user["role"]):
        return HTMLResponse("Forbidden", status_code=403)

    db = get_db(request)

    #  — "Also adds labels" multi-select on the rule form. Form
    # field is repeated (one entry per checkbox), so read via getlist
    # on the form-data dict rather than the per-arg Form binding.
    form = await request.form()
    adds_labels = [
        slug.strip().lower()
        for slug in form.getlist("adds_labels")
        if slug and slug.strip()
    ]
    #  — "Also apply provider labels" multi-select. Each value is
    # ``<account_id>:<label_slug>``; parse + drop malformed entries.
    provider_labels = _parse_provider_labels_form(
        form.getlist("provider_labels"),
    )
    # A1 (census 2026-06-09) — fail-closed account-scope gate: drop any
    # client-supplied provider-label target the actor can't manage.
    provider_labels = await db_call(
        _gate_provider_labels, db, user, provider_labels,
    )

    await db_call(
        _create_list_snapshot, db, name, category, user["id"],
        global_flag, rule_type, pattern, skip_ai, adds_labels,
        provider_labels,
    )

    if global_flag:
        return RedirectResponse("/rules/global", status_code=303)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{list_id}/delete", response_class=HTMLResponse)
async def delete_list(
    request: Request, list_id: int, user: RequireUserFragment,
):
    db = get_db(request)
    status, is_global = await db_call(
        _delete_list_snapshot, db, list_id, user["id"], user["role"],
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    if is_global:
        return RedirectResponse("/rules/global", status_code=303)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{list_id}/add-rule", response_class=HTMLResponse)
async def add_rule(
    request: Request,
    list_id: int,
    user: RequireUserFragment,
    rule_type: str = Form(...),
    pattern: str = Form(...),
    skip_ai: str = Form("0"),
):
    db = get_db(request)

    #  — "Also adds labels" on the per-list add-rule form.
    form = await request.form()
    adds_labels = [
        slug.strip().lower()
        for slug in form.getlist("adds_labels")
        if slug and slug.strip()
    ]
    #  — "Also apply provider labels" multi-select.
    provider_labels = _parse_provider_labels_form(
        form.getlist("provider_labels"),
    )
    # A1 (census 2026-06-09) — fail-closed account-scope gate: drop any
    # client-supplied provider-label target the actor can't manage.
    provider_labels = await db_call(
        _gate_provider_labels, db, user, provider_labels,
    )

    status, is_global = await db_call(
        _add_rule_snapshot, db, list_id, rule_type, pattern, skip_ai,
        user["id"], user["role"], adds_labels, provider_labels,
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    #  — empty / whitespace-only pattern rejected at the snapshot
    # layer. Surface as 400 so the operator sees an actionable error
    # rather than a silently-dropped or match-everything rule.
    if status == "invalid_pattern":
        return HTMLResponse(
            "Pattern must not be empty", status_code=400,
        )

    if is_global:
        return RedirectResponse("/rules/global", status_code=303)
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{list_id}/rules/{rule_id}/delete", response_class=HTMLResponse)
async def delete_rule(
    request: Request, list_id: int, rule_id: int,
    user: RequireUserFragment,
):
    db = get_db(request)
    status, is_global = await db_call(
        _delete_rule_snapshot, db, list_id, rule_id, user["id"], user["role"],
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    if is_global:
        return RedirectResponse("/rules/global", status_code=303)
    return RedirectResponse("/rules", status_code=303)


# ---------------------------------------------------------------------------
# Per-row rule edit affordance. Three endpoints feed the
# inline-edit pattern from categories: GET .../edit renders the
# edit-mode partial; GET .../row renders the view-mode partial
# (used by Cancel to revert without persisting); POST .../save
# updates the rule and returns the freshly-rendered view-mode row.
# ---------------------------------------------------------------------------


@router.get(
    "/rules/{list_id}/rules/{rule_id}/edit",
    response_class=HTMLResponse,
)
async def edit_rule_form(
    request: Request, list_id: int, rule_id: int,
    user: RequireUserFragment,
):
    """Inline edit form for one rule (HTMX swap target = the row tr).

    Sibling-pattern of /categories/{cat_id}/edit. Read-only auth
    check: owner of the list OR admin/power_user (matches the
    update-paths' role gate).

     — also builds ``provider_label_groups``: one entry per
    managed account (the account list is requester-scoped to the
    accounts this user owns/manages — that access boundary, NOT the
    HIPAA flag, is the control; the is_account_hipaa pre-filter was
    removed 2026-06-06 per the §160.103 use-vs-disclosure SME ruling),
    each carrying the labels / folders /
    categories that already exist on the provider. The template
    renders the picker so the operator can pick from labels they
    ALREADY HAVE rather than re-defining everything in the install-
    internal catalog.
    """
    db = get_db(request)
    templates = get_templates(request)
    # Pull the rule + the list catalog of labels (same shape the
    # full /rules page render uses for the create form).
    from email_triage.web.db import list_labels, list_email_accounts
    status, rule, lst = await db_call(
        _get_rule_snapshot, db, list_id, rule_id, user["id"], user["role"],
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    all_labels = await db_call(list_labels, db)

    #  — provider-native labels per account. The account list is
    # already requester-scoped: list_email_accounts(user_id=requester)
    # returns ONLY accounts this user owns or is a delegate of, so every
    # account here is one the requester is authorized to MANAGE. That
    # access boundary IS the control — surfacing an account's own labels
    # to its authorized manager is an intra-entity §160.103 "use" (the
    # strings never leave the install), NOT a third-party disclosure, so
    # the HIPAA flag is the wrong axis to gate on (SME ruling 2026-06-06:
    # owner self-access is §164.502(b)(2)-exempt + §164.524-favored;
    # delegate/admin access is §164.514(d) role-based use). The prior
    # is_account_hipaa pre-filter was removed as over-reach.
    # N-109: this feeds the provider-label picker (a human picks from labels
    # that exist on their managed accounts). A deactivated (creds-purged)
    # account's provider label fetch would fail, so active_only hides it.
    accounts = await db_call(
        list_email_accounts, db, user_id=user.get("id"), active_only=True,
    )
    secrets = request.app.state.secrets
    #  — the per-account provider-label lookups are independent
    # provider round-trips (Gmail/O365 list_labels, IMAP list_folders);
    # run them concurrently. list_provider_labels_for_account is
    # fail-soft — returns [] and never raises — so a plain gather can't
    # be tripped by one bad provider.
    _label_lists = await asyncio.gather(*(
        list_provider_labels_for_account(
            db=db, secrets=secrets, account_id=int(a["id"]),
        )
        for a in accounts
    ))
    provider_label_groups = [
        {
            "account_id": int(a["id"]),
            "account_name": a.get("name", "") or "",
            "provider_type": a.get("provider_type", "") or "",
            "labels": labels,
        }
        for a, labels in zip(accounts, _label_lists)
    ]
    return await _render(templates, request, "rules/_rule_edit.html", {
        "user": user,
        "lst": lst,
        "rule": rule,
        "rule_types": list(WEB_ALLOWED_RULE_TYPES),
        "all_labels": all_labels,
        "provider_label_groups": provider_label_groups,
    })


@router.get(
    "/rules/{list_id}/rules/{rule_id}/row",
    response_class=HTMLResponse,
)
async def rule_row(
    request: Request, list_id: int, rule_id: int,
    user: RequireUserFragment,
):
    """Return the view-mode row partial (Cancel target from edit mode)."""
    db = get_db(request)
    templates = get_templates(request)
    status, rule, lst = await db_call(
        _get_rule_snapshot, db, list_id, rule_id, user["id"], user["role"],
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    return await _render(templates, request, "rules/_rule_row.html", {
        "user": user,
        "lst": lst,
        "rule": rule,
    })


@router.post(
    "/rules/{list_id}/rules/{rule_id}/save",
    response_class=HTMLResponse,
)
async def save_rule(
    request: Request,
    list_id: int,
    rule_id: int,
    user: RequireUserFragment,
    rule_type: str = Form(...),
    pattern: str = Form(...),
    skip_ai: str = Form("0"),
):
    """Update an existing rule. Returns the view-mode row partial on
    success so the HTMX swap restores read-only mode. Plain-form
    POSTs (no HTMX) fall through to a 303 back to /rules — the form
    in `_rule_edit.html` carries both `action=` and `hx-post=` so it
    degrades gracefully if HTMX is off."""
    db = get_db(request)
    templates = get_templates(request)

    # Mirrors create / add-rule — adds_labels is repeated form data.
    form = await request.form()
    adds_labels = [
        slug.strip().lower()
        for slug in form.getlist("adds_labels")
        if slug and slug.strip()
    ]
    #  — "Also apply provider labels" multi-select.
    provider_labels = _parse_provider_labels_form(
        form.getlist("provider_labels"),
    )
    # A1 (census 2026-06-09) — fail-closed account-scope gate: drop any
    # client-supplied provider-label target the actor can't manage.
    provider_labels = await db_call(
        _gate_provider_labels, db, user, provider_labels,
    )

    status, rule, lst = await db_call(
        _save_rule_snapshot, db, list_id, rule_id, rule_type, pattern,
        skip_ai, user["id"], user["role"], adds_labels, provider_labels,
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)
    #  — empty / whitespace-only pattern rejected at the snapshot
    # layer; same surface as the add-rule path.
    if status == "invalid_pattern":
        return HTMLResponse(
            "Pattern must not be empty", status_code=400,
        )

    # HTMX request → return the row partial. Plain form POST →
    # 303 back to the page (let the browser refresh).
    if _shared.is_htmx(request):
        return await _render(templates, request, "rules/_rule_row.html", {
            "user": user,
            "lst": lst,
            "rule": rule,
        })
    if lst.get("is_global"):
        return RedirectResponse("/rules/global", status_code=303)
    return RedirectResponse("/rules", status_code=303)


# ---------------------------------------------------------------------------
# Categories (admin only)
# ---------------------------------------------------------------------------

@router.get("/categories", response_class=HTMLResponse)
async def categories_page(request: Request):
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    scope = (request.query_params.get("scope") or "all").strip()
    snap = await db_call(_build_categories_page_snapshot, db, scope)

    return await _render(templates, request, "categories/manage.html", {
        "user": user,
        **snap,
    })


@router.post("/categories/create", response_class=HTMLResponse)
async def categories_create(request: Request, slug: str = Form(...), description: str = Form(...)):
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    slug = slug.strip().lower()
    description = description.strip()

    success, cats = await db_call(
        _categories_create_snapshot, db, slug, description,
    )
    if not success:
        return await _render(templates, request, "categories/manage.html", {
            "user": user, "categories": cats,
            "error": f"Category '{slug}' already exists.",
        })

    return await _render(templates, request, "categories/manage.html", {
        "user": user, "categories": cats,
        "success": f"Category '{slug}' created.",
    })


@router.get("/categories/{cat_id}/edit", response_class=HTMLResponse)
async def categories_edit_form(request: Request, cat_id: int):
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    from email_triage.web.db import get_category
    db = get_db(request)
    templates = get_templates(request)

    cat = await db_call(get_category, db, cat_id)
    if cat is None:
        return HTMLResponse("Not found", status_code=404)

    return await _render(templates, request, "categories/_edit.html", {"cat": cat})


@router.get("/categories/{cat_id}/row", response_class=HTMLResponse)
async def categories_row(request: Request, cat_id: int):
    """Return a single row fragment (for cancel from edit mode)."""
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    from email_triage.web.db import get_category
    db = get_db(request)
    templates = get_templates(request)

    cat = await db_call(get_category, db, cat_id)
    if cat is None:
        return HTMLResponse("Not found", status_code=404)

    return await _render(templates, request, "categories/_row.html", {"cat": cat})


@router.put("/categories/{cat_id}", response_class=HTMLResponse)
async def categories_update(request: Request, cat_id: int, slug: str = Form(...), description: str = Form(...)):
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    slug = slug.strip().lower()
    description = description.strip()

    cat = await db_call(
        _categories_update_snapshot, db, cat_id, slug, description,
    )

    return await _render(templates, request, "categories/_row.html", {"cat": cat})


@router.delete("/categories/{cat_id}", response_class=HTMLResponse)
async def categories_delete(request: Request, cat_id: int):
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    from email_triage.web.db import delete_category
    db = get_db(request)

    await db_call(delete_category, db, cat_id)
    # Return empty string to remove the row from the DOM.
    return HTMLResponse("")


# --- Personal categories (any authenticated user; owned by request user) ---

@router.get("/rules/personal-categories", response_class=HTMLResponse)
async def personal_categories_page(request: Request, user: RequireUser):
    """Standalone page for personal categories, sitting under the
    Rules cluster (alongside Categories + Discover Categories). The
    embedded form posts to the existing
    ``/profile/personal-categories/create`` + DELETE handlers — only
    the discovery surface moved, not the data path."""
    from email_triage.web.db import (
        list_categories, MAX_PERSONAL_CATEGORIES_PER_USER,
    )
    db = get_db(request)
    templates = get_templates(request)

    personal_categories = await db_call(
        list_categories, db, user_id=user["id"], scope="personal",
    )
    return await _render(templates, request, "categories/personal.html", {
        "user": user,
        "personal_categories": personal_categories,
        "personal_cap": MAX_PERSONAL_CATEGORIES_PER_USER,
    })


@router.post("/profile/personal-categories/create", response_class=HTMLResponse)
async def personal_category_create(
    request: Request,
    user: RequireUser,
    slug: str = Form(...),
    description: str = Form(...),
):
    from email_triage.web.db import MAX_PERSONAL_CATEGORIES_PER_USER
    db = get_db(request)
    templates = get_templates(request)

    slug = slug.strip().lower()
    description = description.strip()

    error, personal_categories = await db_call(
        _personal_category_create_snapshot, db, slug, description, user["id"],
    )
    return await _render(templates, request,
                   "profile/_personal_categories.html", {
        "personal_categories": personal_categories,
        "personal_cap": MAX_PERSONAL_CATEGORIES_PER_USER,
        "error": error,
    })


@router.delete(
    "/profile/personal-categories/{cat_id}",
    response_class=HTMLResponse,
)
async def personal_category_delete(
    request: Request, cat_id: int, user: RequireUser,
):
    from email_triage.web.db import MAX_PERSONAL_CATEGORIES_PER_USER
    db = get_db(request)
    templates = get_templates(request)

    status, personal_categories = await db_call(
        _personal_category_delete_snapshot, db, cat_id, user["id"],
    )
    if status == "forbidden":
        return HTMLResponse("Forbidden", status_code=403)

    return await _render(templates, request,
                   "profile/_personal_categories.html", {
        "personal_categories": personal_categories,
        "personal_cap": MAX_PERSONAL_CATEGORIES_PER_USER,
    })


@router.post("/categories/{cat_id}/promote", response_class=HTMLResponse)
async def categories_promote(request: Request, cat_id: int):
    """Promote a personal category to system scope. Admin-only."""
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    from email_triage.web.db import (
        promote_category_to_system, get_category, record_auth_event,
    )
    db = get_db(request)
    templates = get_templates(request)

    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    def _promote_db_work() -> tuple[str, dict]:
        """/ — pre-read + promote + audit + post-read in ONE
        threadpool hop. Returns ``(kind, payload)``:
          - ("value_error", {cat, error})    → render _row.html w/ error
          - ("not_found", {})                → 404
          - ("ok", {cat, owners_by_id})      → render _row.html
        """
        # Capture the pre-state for the audit detail (slug + originating
        # owner) -- after the UPDATE the user_id column is NULL, so we'd
        # lose the "from" leg if we read it post-mutation.
        pre = get_category(db, cat_id)
        pre_owner = pre.get("user_id") if pre else None
        pre_slug = pre.get("slug") if pre else "?"

        try:
            ok = promote_category_to_system(db, cat_id)
        except ValueError as e:
            safe_audit_write(
                lambda: record_auth_event(
                    db, event_type="category_promote",
                    email=user.get("email", ""),
                    user_id=user["id"], ip=client_host,
                    user_agent=user_agent,
                    outcome="failure",
                    detail=scrub_error_for_persist(
                        f"cat_id={cat_id} slug={pre_slug} reason={e}"),  # run13 #2 — chained audit detail
                ),
                description=f"category_promote user_id={user['id']} cat_id={cat_id} outcome=failure",
            )
            cat = get_category(db, cat_id) or {
                "id": cat_id, "slug": "?", "description": str(e),
            }
            return "value_error", {"cat": cat, "error": scrub_exc(e, purpose="misc")}  # N-179 R21_2

        if not ok:
            safe_audit_write(
                lambda: record_auth_event(
                    db, event_type="category_promote",
                    email=user.get("email", ""),
                    user_id=user["id"], ip=client_host,
                    user_agent=user_agent,
                    outcome="failure",
                    detail=(
                        f"cat_id={cat_id} "
                        "reason=not_found_or_already_system"
                    ),
                ),
                description=f"category_promote user_id={user['id']} cat_id={cat_id} outcome=failure",
            )
            return "not_found", {}

        safe_audit_write(
            lambda: record_auth_event(
                db, event_type="category_promote",
                email=user.get("email", ""),
                user_id=user["id"], ip=client_host, user_agent=user_agent,
                outcome="success",
                detail=(
                    f"cat_id={cat_id} slug={pre_slug} "
                    f"from_user_id={pre_owner}"
                ),
            ),
            description=f"category_promote user_id={user['id']} cat_id={cat_id} outcome=success",
        )

        cat = get_category(db, cat_id)
        user_rows = db.execute(
            "SELECT id, email, name FROM users"
        ).fetchall()
        owners_by_id = {u["id"]: dict(u) for u in user_rows}
        return "ok", {"cat": cat, "owners_by_id": owners_by_id}

    kind, payload = await db_call(_promote_db_work)
    if kind == "not_found":
        return HTMLResponse("Not found or already system", status_code=404)
    if kind == "value_error":
        return await _render(templates, request, "categories/_row.html", {
            "cat": payload["cat"],
            "owners_by_id": {},
            "error": payload["error"],
        })
    return await _render(templates, request, "categories/_row.html", {
        "cat": payload["cat"],
        "owners_by_id": payload["owners_by_id"],
    })


@router.get("/categories/{cat_id}/demote-form", response_class=HTMLResponse)
async def categories_demote_form(request: Request, cat_id: int):
    """Inline form for selecting which user to demote a system category
    to. Returns a row partial with a user-picker dropdown. Admin-only.
    HTMX swap target is the cat-row tr."""
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    db = get_db(request)
    templates = get_templates(request)

    status, cat, users = await db_call(
        _categories_demote_form_snapshot, db, cat_id,
    )
    if status == "not_found":
        return HTMLResponse("Not found", status_code=404)
    if status == "not_system":
        return HTMLResponse("Not a system category", status_code=400)

    return await _render(templates, request, "categories/_row_demote_form.html", {
        "cat": cat,
        "users": users,
    })


@router.post("/categories/{cat_id}/demote", response_class=HTMLResponse)
async def categories_demote(
    request: Request, cat_id: int,
    target_user_id: int = Form(...),
):
    """Demote a system category to personal scope for one user. Admin-only."""
    user, err = await db_call(_require_admin_user, request)
    if err:
        return err

    from email_triage.web.db import (
        demote_category_to_user, get_category, record_auth_event,
    )
    db = get_db(request)
    templates = get_templates(request)

    client_host = audit_forwarded_for(request).host or None  # N-337: XFF-aware SSOT (§164.312(b))
    user_agent = request.headers.get("user-agent")

    def _demote_db_work() -> tuple[str, dict]:
        """/ — pre-read + demote + audit + post-read in ONE
        threadpool hop. Returns ``(kind, payload)`` — see the
        ``categories_promote`` twin for the kind vocabulary.
        """
        pre = get_category(db, cat_id)
        pre_slug = pre.get("slug") if pre else "?"

        try:
            ok = demote_category_to_user(db, cat_id, target_user_id)
        except ValueError as e:
            safe_audit_write(
                lambda: record_auth_event(
                    db, event_type="category_demote",
                    email=user.get("email", ""),
                    user_id=user["id"], ip=client_host,
                    user_agent=user_agent,
                    outcome="failure",
                    detail=scrub_error_for_persist(
                        f"cat_id={cat_id} slug={pre_slug} "
                        f"to_user_id={target_user_id} reason={e}"
                    ),  # run13 #2 — chained audit detail
                ),
                description=f"category_demote user_id={user['id']} cat_id={cat_id} to_user_id={target_user_id} outcome=failure",
            )
            cat = get_category(db, cat_id) or {
                "id": cat_id, "slug": "?", "description": str(e),
            }
            return "value_error", {"cat": cat, "error": scrub_exc(e, purpose="misc")}  # N-179 R21_2

        if not ok:
            safe_audit_write(
                lambda: record_auth_event(
                    db, event_type="category_demote",
                    email=user.get("email", ""),
                    user_id=user["id"], ip=client_host,
                    user_agent=user_agent,
                    outcome="failure",
                    detail=(
                        f"cat_id={cat_id} to_user_id={target_user_id} "
                        "reason=not_found_or_already_personal"
                    ),
                ),
                description=f"category_demote user_id={user['id']} cat_id={cat_id} to_user_id={target_user_id} outcome=failure",
            )
            return "not_found", {}

        safe_audit_write(
            lambda: record_auth_event(
                db, event_type="category_demote",
                email=user.get("email", ""),
                user_id=user["id"], ip=client_host, user_agent=user_agent,
                outcome="success",
                detail=(
                    f"cat_id={cat_id} slug={pre_slug} "
                    f"to_user_id={target_user_id}"
                ),
            ),
            description=f"category_demote user_id={user['id']} cat_id={cat_id} to_user_id={target_user_id} outcome=success",
        )

        cat = get_category(db, cat_id)
        user_rows = db.execute(
            "SELECT id, email, name FROM users"
        ).fetchall()
        owners_by_id = {u["id"]: dict(u) for u in user_rows}
        return "ok", {"cat": cat, "owners_by_id": owners_by_id}

    kind, payload = await db_call(_demote_db_work)
    if kind == "not_found":
        return HTMLResponse(
            "Not found or already personal", status_code=404,
        )
    if kind == "value_error":
        return await _render(templates, request, "categories/_row.html", {
            "cat": payload["cat"],
            "owners_by_id": {},
            "error": payload["error"],
        })
    return await _render(templates, request, "categories/_row.html", {
        "cat": payload["cat"],
        "owners_by_id": payload["owners_by_id"],
    })


# ---------------------------------------------------------------------------
# Email accounts (all users; admin sees all)
# ---------------------------------------------------------------------------

@router.post("/categories/add-discovered", response_class=HTMLResponse)
async def add_discovered_category(request: Request, user: RequireUserFragment):
    """HTMX endpoint to add a single discovered category (admin only)."""
    _admin_err = admin_gate_response(user)
    if _admin_err is not None:
        return _admin_err

    db = get_db(request)
    form = await request.form()
    slug = form.get("slug", "").strip()
    description = form.get("description", "").strip()

    if not slug:
        return HTMLResponse(
            '<span style="color:var(--pico-del-color);">Missing slug</span>'
        )

    try:
        from email_triage.web.db import create_category
        await db_call(create_category, db, slug, description)
        return HTMLResponse(
            '<span style="color:var(--pico-ins-color);">Added &#10003;</span>'
        )
    except Exception as e:
        _log.error("Failed to add discovered category", slug=slug, error=fmt_exc(e))
        return HTMLResponse(
            error_chip(e, prefix='Error: ')
        )


