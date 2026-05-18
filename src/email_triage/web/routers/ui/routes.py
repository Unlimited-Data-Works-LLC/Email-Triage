"""Routes for the routes concern.

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

_log = get_logger("web.ui.routes")

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


@router.get("/accounts/{account_id}/routes", response_class=HTMLResponse)
async def accounts_routes_page(
    request: Request, account_id: int, owned: OwnedAccountOrLogin,
):
    """Show the route configuration page for an account.

    Migrated to ``OwnedAccountOrLogin`` (#137 phase 2) — full-page
    navigation target keeps the redirect-to-/login UX for anonymous
    users (the dep returns a RedirectResponse rather than raising
    401). Non-owner / not-found still raise 403 / 404 — same UX
    the inline preamble had.
    """
    if isinstance(owned, RedirectResponse):
        return owned
    user, acct, db, secrets = owned
    templates = get_templates(request)

    ctx = await _build_routes_context(request, db, secrets, user, acct)

    # Persist this account as the operator's last-edited routes
    # account so the top-level /routes page lands here next time.
    await db_call(_set_last_routes_account_id, db, user["id"], account_id)

    return _render(templates, request, "accounts/routes.html", ctx)


@router.get("/routes", response_class=HTMLResponse)
async def routes_top_level_page(request: Request):
    """Top-level /routes page with account-picker dropdown.

    GET /routes (no params) — render full page with the account
    list, defaulting to the user's most-recently-edited account
    (persisted) or the first manageable account.

    GET /routes?account_id=N — render full page with that account
    selected. Forbidden when the user can't manage the account.

    HTMX (HX-Request header) — return JUST the body partial so the
    dropdown's hx-target="#routes-table-region" can swap it in.
    """
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    secrets = get_secrets(request)
    templates = get_templates(request)

    raw_aid = request.query_params.get("account_id")

    def _routes_top_resolve(db, user, raw_aid):
        """#135 phase 2 — manageable list + account resolution +
        permission check in a single threadpool hop."""
        from email_triage.web.db import (
            get_email_account, list_email_accounts,
        )
        if user["role"] == "admin":
            all_accounts = list_email_accounts(db)
        else:
            all_accounts = list_email_accounts(db, user_id=user["id"])
        manageable = [
            {"id": a["id"], "name": a["name"]} for a in all_accounts
        ]
        if not manageable:
            return {"manageable": [], "acct": None, "forbidden": False}

        target_id: int | None = None
        if raw_aid:
            try:
                target_id = int(raw_aid)
            except (TypeError, ValueError):
                target_id = None
        if target_id is None:
            target_id = _get_last_routes_account_id(db, user["id"])
        if target_id is None:
            target_id = manageable[0]["id"]

        acct = get_email_account(db, target_id)
        if acct is None:
            target_id = manageable[0]["id"]
            acct = get_email_account(db, target_id)
            if acct is None:
                return {"manageable": [], "acct": None, "forbidden": False}

        if not can_manage_account(db, user, acct):
            return {"manageable": manageable, "acct": None, "forbidden": True}

        return {
            "manageable": manageable, "acct": acct, "forbidden": False,
            "target_id": target_id,
        }

    resolved = await db_call(_routes_top_resolve, db, user, raw_aid)
    if resolved["forbidden"]:
        return HTMLResponse("Forbidden", status_code=403)
    if resolved["acct"] is None:
        return _render(templates, request, "routes_top.html", {
            "user": user,
            "manageable_accounts": resolved["manageable"],
            "acct": None,
        })

    acct = resolved["acct"]
    target_id = resolved["target_id"]

    ctx = await _build_routes_context(request, db, secrets, user, acct)
    ctx["manageable_accounts"] = resolved["manageable"]

    # Persist as last-edited.
    await db_call(_set_last_routes_account_id, db, user["id"], target_id)

    # HTMX swap: return only the body partial.
    if request.headers.get("HX-Request") == "true":
        return _render(
            templates, request,
            "accounts/_routes_body.html", ctx,
        )

    return _render(templates, request, "routes_top.html", ctx)


@router.post("/accounts/{account_id}/routes/save", response_class=HTMLResponse)
async def accounts_routes_save(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Save a single category → actions mapping for an account."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    is_admin = user["role"] == "admin"

    from email_triage.web.db import upsert_account_route

    form = await request.form()
    category = form.get("category", "").strip()
    if not category:
        return HTMLResponse("Category required", status_code=400)

    # Parse selected actions and their configs.
    actions = []
    action_names = form.getlist("actions")
    for action_name in action_names:
        action_config: dict[str, Any] = {}
        if action_name == "move":
            folder = form.get("move_folder", "")
            if folder:
                action_config["folder_map"] = {category: folder}
        elif action_name == "label":
            prefix = form.get("label_prefix", "")
            if prefix:
                action_config["label_prefix"] = prefix
            # #163 follow-up — operator picked one or more provider-
            # native labels via the multi-select. Persist them on the
            # action's config; LabelAction.execute reads ``labels``
            # and applies each. Empty list (operator unticked them
            # all) means fall back to the legacy classification-
            # category-as-label shape, same as pre-#163.
            label_targets = [
                s for s in form.getlist("label_targets") if s
            ]
            if label_targets:
                action_config["labels"] = label_targets
        elif action_name == "add-label":
            # #129 tail — internal-label slugs are repeated form
            # fields (one per checked chip in the picker); provider-
            # native names come from a free-text comma-separated
            # input. Same shape the list-rule editor uses for
            # ``adds_labels`` so the action's config dict matches the
            # rule-driven label apply path's persisted state.
            internal_slugs = [
                s.strip().lower()
                for s in form.getlist("add_label_internal")
                if s and s.strip()
            ]
            raw_provider = (form.get("add_label_provider") or "").strip()
            provider_names = [
                n.strip()
                for n in raw_provider.split(",")
                if n and n.strip()
            ]
            if internal_slugs:
                action_config["labels"] = internal_slugs
            if provider_names:
                action_config["provider_labels"] = provider_names
        actions.append({"action": action_name, "config": action_config})

    upsert_account_route(db, account_id, category, actions)

    # Probe provider for label/folder targets the route will use.
    # If any are missing, surface "will auto-create on first matching
    # email" so the operator sees the deferred work explicitly. Best-
    # effort: any probe failure (auth, network) just shows "Saved"
    # without the addendum — the auto-create logic still runs at
    # apply-time so the route works either way.
    will_create: list[str] = []
    try:
        secrets = get_secrets(request)
        targets: list[str] = []
        for a in actions:
            cfg = a.get("config") or {}
            if a["action"] == "label":
                pfx = cfg.get("label_prefix", "")
                targets.append(f"{pfx}/{category}" if pfx else category)
            elif a["action"] == "move":
                fmap = cfg.get("folder_map") or {}
                f = fmap.get(category)
                if f:
                    targets.append(f)
        if targets:
            provider = _create_provider_from_account(acct, secrets)
            try:
                will_create = await _probe_missing_labels(provider, targets)
            finally:
                try:
                    await provider.close()
                except Exception:
                    pass
    except Exception as e:
        _log.debug(
            "Route-save label probe failed; skipping pre-flight notice",
            error=fmt_exc(e), account_id=account_id, category=category,
        )
        will_create = []

    # Saved-chip text: "Saved 14:02" with optional auto-create hint.
    # The chip is short by design; the JS in _routes_body.html fades
    # it out after 3 seconds. Operator's wall clock (server-side
    # rendered for simplicity — request and save round-trip are
    # under a second so server-vs-browser clock skew is invisible).
    from datetime import datetime as _dt
    saved_at = _dt.now().strftime("%H:%M")
    msg_parts = [f"Saved {saved_at}"]
    if will_create:
        joined = ", ".join(f"<code>{n}</code>" for n in will_create)
        msg_parts.append(
            f'Will auto-create {joined} on first matching email.'
        )

    return HTMLResponse(
        '<small style="color:var(--pico-ins-color);">'
        + " &middot; ".join(msg_parts)
        + '</small>'
    )


@router.post("/accounts/{account_id}/routes/save-all", response_class=HTMLResponse)
async def accounts_routes_save_all(
    request: Request, account_id: int, owned: OwnedAccount,
):
    """Save every category mapping in one transaction (Pause-mode).

    Form payload: ``row_count`` plus per-row keys:
      * ``row_<i>_category``    — category slug
      * ``row_<i>_actions``     — repeated; selected action names
      * ``row_<i>_move_folder`` — folder for the move action (may be empty)

    Validation: every category slug must be one of the known
    categories for this account's owner. Unknown slugs abort the
    whole batch (no partial saves). Returns a success chip on OK,
    a red error chip listing the bad rows otherwise.
    """
    # #137 — preamble collapsed to ``OwnedAccount``. The ``owned``
    # parameter is bound on the handler signature below.
    user, acct, db, _ = owned

    from email_triage.web.db import upsert_account_route

    form = await request.form()
    try:
        row_count = int(form.get("row_count", "0"))
    except (TypeError, ValueError):
        row_count = 0

    valid_cats = set(
        _get_categories_from_db(db, user_id=acct.get("user_id")).keys()
    )

    # Pre-validate every row before writing anything. Atomic semantics
    # — operator gets per-row errors back without partial state on disk.
    parsed: list[tuple[str, list[dict]]] = []
    errors: list[str] = []
    for i in range(row_count):
        cat = (form.get(f"row_{i}_category") or "").strip()
        if not cat:
            errors.append(f"Row {i}: category missing.")
            continue
        if cat not in valid_cats:
            errors.append(f"Row {i}: unknown category {cat!r}.")
            continue
        action_names = form.getlist(f"row_{i}_actions")
        move_folder = (form.get(f"row_{i}_move_folder") or "").strip()
        # #163 follow-up — per-row provider-label multi-select for
        # the existing ``label`` action. JS in _routes_body.html
        # serialises the multi-select per row when building the
        # save-all payload.
        label_targets = [
            s for s in form.getlist(f"row_{i}_label_targets") if s
        ]
        # #129 tail — per-row add-label config (separate action).
        # Internal slugs use the indexed repeating-field convention
        # (``row_{i}_add_label_internal``); provider-native names
        # are a single comma-separated text field per row. Matches
        # the per-action POST shape above.
        row_internal_slugs = [
            s.strip().lower()
            for s in form.getlist(f"row_{i}_add_label_internal")
            if s and s.strip()
        ]
        raw_provider = (form.get(f"row_{i}_add_label_provider") or "").strip()
        row_provider_names = [
            n.strip()
            for n in raw_provider.split(",")
            if n and n.strip()
        ]
        actions: list[dict[str, Any]] = []
        for a in action_names:
            cfg: dict[str, Any] = {}
            if a == "move" and move_folder:
                cfg["folder_map"] = {cat: move_folder}
            elif a == "label" and label_targets:
                cfg["labels"] = label_targets
            elif a == "add-label":
                if row_internal_slugs:
                    cfg["labels"] = row_internal_slugs
                if row_provider_names:
                    cfg["provider_labels"] = row_provider_names
            actions.append({"action": a, "config": cfg})
        parsed.append((cat, actions))

    if errors:
        chips = "<br>".join(errors)
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f"Validation failed — nothing saved.<br>{chips}</small>",
            status_code=400,
        )

    # All rows valid — persist. Atomicity is enforced via the
    # pre-validation block above (no row writes if any row failed
    # validation). ``upsert_account_route`` commits per call, so a
    # SAVEPOINT wrapper would be released on the first commit anyway;
    # the validation gate is the practical atomicity boundary.
    try:
        for cat, actions in parsed:
            upsert_account_route(db, account_id, cat, actions)
    except Exception as e:
        return HTMLResponse(
            f'<small style="color:var(--pico-del-color);">'
            f"Save failed: {e}</small>",
            status_code=500,
        )

    return HTMLResponse(
        f'<small style="color:var(--pico-ins-color);">'
        f"Saved {len(parsed)} route{'s' if len(parsed) != 1 else ''}.</small>"
    )


@router.delete("/accounts/{account_id}/routes/{route_id}", response_class=HTMLResponse)
async def accounts_routes_delete(
    request: Request, account_id: int, route_id: int,
    owned: OwnedAccount,
):
    """Delete a route mapping."""
    # #137 — preamble collapsed to ``OwnedAccount``.
    user, acct, db, _ = owned
    is_admin = user["role"] == "admin"

    from email_triage.web.db import delete_account_route

    delete_account_route(db, route_id)
    return HTMLResponse("")


# ---------------------------------------------------------------------------
# Folder Preferences (subscribe/unsubscribe folders per account)
# ---------------------------------------------------------------------------

