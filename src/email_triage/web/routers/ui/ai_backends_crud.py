"""Admin CRUD routes for the ``ai_backends`` catalog (#169 Wave 2-α — I3).

Lives on ``/config/ai-backends/*`` — sibling of the existing
``/config?tab=ai_backends`` embedding-backend admin (different concern:
that tab configures the install's embedding chain; this surface
manages the DB-row catalog of LLM backends per migration v26).

Routes
------
GET  /config/ai-backends                  — list view, table + Add button
GET  /config/ai-backends/new              — add-backend form
POST /config/ai-backends                  — create
GET  /config/ai-backends/{id}/edit        — edit form
POST /config/ai-backends/{id}             — update (incl. enable / disable)
POST /config/ai-backends/{id}/delete      — delete

Every handler requires admin role. Mutating handlers are CSRF-protected
via the standard middleware (cookie + form-field double-submit).

API-key handling
----------------
**Plaintext API keys NEVER round-trip through templates.** Save flow:

  1. Form posts plaintext key in ``api_key_plain``.
  2. Handler mints a stable secret name
     (``ai_backend_key:{backend_id}`` post-insert, or
     ``ai_backend_key:new:{timestamp}`` pre-insert) and stores the
     plaintext via :meth:`DbSecrets.set`.
  3. Handler stores ONLY the secret name on the row
     (``api_key_secret_ref`` column).

Display flow:

  * Show "Key is set" / "No key" + a "Replace key" toggle. The form
    NEVER pre-fills the key input.
  * On edit-without-replace, the handler preserves the existing
    ``api_key_secret_ref`` verbatim.

Audit
-----
Every create / update / delete writes an ``auth_events`` row via
:func:`record_auth_event` with one of these event types:
``ai_backend_create`` / ``ai_backend_update`` / ``ai_backend_delete``.
Detail carries ``backend_id`` + ``name`` + ``type`` + an enable/disable
or BAA-flip note when applicable.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage._errfmt import fmt_exc
from email_triage.ai_backends.registry import BACKEND_TYPES
from email_triage.web.app import (
    get_config, get_db, get_secrets, get_templates,
)
from email_triage.web.db import (
    count_accounts_using_ai_backend,
    create_ai_backend,
    delete_ai_backend,
    get_ai_backend,
    list_ai_backends,
    record_auth_event,
    update_ai_backend,
)
from email_triage.web.dependencies import get_current_user

_log = logging.getLogger("email_triage.web.ui.ai_backends_crud")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_admin(request: Request) -> tuple[dict | None, Any]:
    """Standard admin gate: returns (user, error_response). When user
    is None the caller should ``return err`` directly.
    """
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _render(request: Request, name: str, ctx: dict) -> HTMLResponse:
    """Delegate to ``_shared._render`` so the auto-injected template
    globals (``baa_banner``, ``hipaa_mode``, OAuth handles) land here
    too. Local wrapper kept for handler-side ergonomics — handlers
    pass (request, name, ctx) not (templates, request, name, ctx).
    """
    from email_triage.web.routers.ui._shared import _render as _render_shared
    return _render_shared(get_templates(request), request, name, ctx)


def _allowed_types() -> list[str]:
    """Type-name dropdown options, sorted for stable UI ordering."""
    return sorted(BACKEND_TYPES.keys())


def _secret_ref_for(backend_id: int) -> str:
    return f"ai_backend_key:{backend_id}"


def _audit(
    db: sqlite3.Connection,
    user: dict,
    *,
    event_type: str,
    detail: str,
    outcome: str = "success",
) -> None:
    """Wrap record_auth_event with the per-handler log + best-effort
    semantic. Audit failures are logged but never poison the user
    flow (mirrors the standing pattern in admin.py).
    """
    try:
        record_auth_event(
            db,
            event_type=event_type,
            email=user.get("email", ""),
            user_id=user.get("id"),
            outcome=outcome,
            detail=detail,
        )
    except Exception as exc:
        _log.warning(
            "ai_backend audit row failed",
            extra={"_extra": {
                "event": event_type,
                "outcome": outcome,
                "error": fmt_exc(exc),
            }},
        )


def _parse_form_row(form: Any) -> dict[str, Any]:
    """Extract + normalise the row fields from a posted form.

    Pure — used by create + update so the validation rules live in
    one place. Returns the dict ready to feed into create_ai_backend
    / update_ai_backend (minus ``api_key_secret_ref`` which the
    handler resolves separately).
    """
    name = (form.get("name") or "").strip()
    type_ = (form.get("type") or "").strip().lower()
    endpoint = (form.get("endpoint") or "").strip()
    model = (form.get("model") or "").strip() or None
    baa_certified = (form.get("baa_certified") in ("1", "on", "true"))
    baa_expires_at = (form.get("baa_expires_at") or "").strip() or None
    enabled = (form.get("enabled") in ("1", "on", "true"))
    return {
        "name": name,
        "type_": type_,
        "endpoint": endpoint,
        "model": model,
        "baa_certified": baa_certified,
        "baa_expires_at": baa_expires_at,
        "enabled": enabled,
    }


def _validate_row(row: dict[str, Any]) -> str | None:
    """Return an error message or ``None`` when the row is valid.

    Mirrors the CHECK constraints in v26 + extra UX-side rules
    (name required, endpoint required, type in registry).
    """
    if not row["name"]:
        return "Name is required."
    if row["type_"] not in BACKEND_TYPES:
        return (
            f"Type {row['type_']!r} is not supported. Pick one of: "
            f"{', '.join(_allowed_types())}."
        )
    if not row["endpoint"]:
        return "Endpoint URL is required."
    if row["baa_certified"] and not row["baa_expires_at"]:
        return (
            "When BAA-certified is checked, BAA expiration date is "
            "required."
        )
    return None


# ---------------------------------------------------------------------------
# List view + Add button
# ---------------------------------------------------------------------------

@router.get("/config/ai-backends", response_class=HTMLResponse)
async def ai_backends_index(request: Request):
    """List every ``ai_backends`` row + Add-backend button. Admin only."""
    user, err = _require_admin(request)
    if err:
        return err
    db = get_db(request)
    rows = list_ai_backends(db)
    # Enrich with the in-use account count + a friendly BAA-bucket
    # label so the table doesn't need to do the math inline.
    from email_triage.baa_expiry import classify_bucket
    items: list[dict] = []
    for r in rows:
        bucket, days = classify_bucket(
            baa_certified=bool(r.get("baa_certified")),
            baa_expires_at=r.get("baa_expires_at"),
        )
        items.append({
            **r,
            "in_use_count": count_accounts_using_ai_backend(db, r["id"]),
            "bucket": bucket,
            "days_until_expiry": days,
        })
    # ``baa_banner`` is auto-injected by ``_shared._render`` for admin
    # users (see #171-D). Removed from per-handler ctx so the banner
    # has a single source of truth.
    return _render(request, "admin/ai_backends/_index.html", {
        "user": user,
        "items": items,
        "save_msg": request.query_params.get("save_msg", ""),
        "save_error": request.query_params.get("save_error", ""),
    })


# ---------------------------------------------------------------------------
# Add form (GET)
# ---------------------------------------------------------------------------

@router.get("/config/ai-backends/new", response_class=HTMLResponse)
async def ai_backends_new_form(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    return _render(request, "admin/ai_backends/_form.html", {
        "user": user,
        "mode": "create",
        "row": {
            "name": "",
            "type": "ollama",
            "endpoint": "",
            "api_key_secret_ref": None,
            "model": "",
            "baa_certified": 0,
            "baa_expires_at": "",
            "enabled": 1,
        },
        "allowed_types": _allowed_types(),
        "form_error": None,
    })


# ---------------------------------------------------------------------------
# Create (POST)
# ---------------------------------------------------------------------------

@router.post("/config/ai-backends", response_class=HTMLResponse)
async def ai_backends_create(request: Request):
    user, err = _require_admin(request)
    if err:
        return err
    db = get_db(request)
    secrets = get_secrets(request)
    form = await request.form()
    row = _parse_form_row(form)
    err_msg = _validate_row(row)
    if err_msg:
        return _render(request, "admin/ai_backends/_form.html", {
            "user": user,
            "mode": "create",
            "row": {
                "name": row["name"],
                "type": row["type_"],
                "endpoint": row["endpoint"],
                "api_key_secret_ref": None,
                "model": row["model"] or "",
                "baa_certified": int(row["baa_certified"]),
                "baa_expires_at": row["baa_expires_at"] or "",
                "enabled": int(row["enabled"]),
            },
            "allowed_types": _allowed_types(),
            "form_error": err_msg,
        })

    # Insert FIRST with a NULL key ref so we know the new id. Then,
    # if a plaintext key was supplied, store it under a stable
    # backend-id-keyed secret name and UPDATE the row's ref column.
    # This sidesteps the chicken-and-egg of "we want the id as part
    # of the secret name, but we don't have the id until after
    # INSERT" without storing the plaintext under a throwaway name.
    try:
        new_id = create_ai_backend(
            db,
            name=row["name"],
            type_=row["type_"],
            endpoint=row["endpoint"],
            api_key_secret_ref=None,
            model=row["model"],
            baa_certified=row["baa_certified"],
            baa_expires_at=row["baa_expires_at"],
            enabled=row["enabled"],
            created_by=user.get("id"),
        )
    except sqlite3.IntegrityError as exc:
        return _render(request, "admin/ai_backends/_form.html", {
            "user": user,
            "mode": "create",
            "row": {
                "name": row["name"],
                "type": row["type_"],
                "endpoint": row["endpoint"],
                "api_key_secret_ref": None,
                "model": row["model"] or "",
                "baa_certified": int(row["baa_certified"]),
                "baa_expires_at": row["baa_expires_at"] or "",
                "enabled": int(row["enabled"]),
            },
            "allowed_types": _allowed_types(),
            "form_error": (
                "Could not save. The name may already be in use, "
                "or the values failed a schema check: "
                f"{exc}"
            ),
        })

    # Plaintext key handling (the only place it sees the wire).
    api_key_plain = (form.get("api_key_plain") or "").strip()
    secret_ref: str | None = None
    if api_key_plain and secrets is not None:
        secret_ref = _secret_ref_for(new_id)
        try:
            secrets.set(secret_ref, api_key_plain)
            update_ai_backend(
                db, new_id,
                name=row["name"],
                type_=row["type_"],
                endpoint=row["endpoint"],
                api_key_secret_ref=secret_ref,
                model=row["model"],
                baa_certified=row["baa_certified"],
                baa_expires_at=row["baa_expires_at"],
                enabled=row["enabled"],
            )
        except Exception as exc:
            _log.error(
                "API-key persistence failed; row created without key",
                extra={"_extra": {
                    "backend_id": new_id,
                    "error": fmt_exc(exc),
                }},
            )

    _audit(
        db, user,
        event_type="ai_backend_create",
        detail=(
            f"id={new_id} name={row['name']!r} "
            f"type={row['type_']!r} baa_certified={row['baa_certified']} "
            f"enabled={row['enabled']}"
        ),
    )
    return RedirectResponse(
        f"/config/ai-backends?save_msg=Backend+{row['name']}+added.",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Edit form (GET)
# ---------------------------------------------------------------------------

@router.get(
    # `{backend_id:int}` (Starlette int converter) is the defense-in-
    # depth fix for the 2026-05-18 routing bug: a sibling router at
    # ``/config/ai-backends/embedding-install`` previously got eaten
    # by this route's plain `{backend_id}` pattern and 422'd on the
    # int validation. With the converter, FastAPI's router rejects
    # non-int paths at MATCH time and falls through cleanly to the
    # next route. Same fix applied to the POST update + POST delete
    # routes below.
    "/config/ai-backends/{backend_id:int}/edit",
    response_class=HTMLResponse,
)
async def ai_backends_edit_form(request: Request, backend_id: int):
    user, err = _require_admin(request)
    if err:
        return err
    db = get_db(request)
    backend = get_ai_backend(db, backend_id)
    if backend is None:
        return HTMLResponse("Not found", status_code=404)
    return _render(request, "admin/ai_backends/_form.html", {
        "user": user,
        "mode": "edit",
        "row": backend,
        "allowed_types": _allowed_types(),
        "form_error": None,
        "in_use_count": count_accounts_using_ai_backend(db, backend_id),
    })


# ---------------------------------------------------------------------------
# Update (POST)
# ---------------------------------------------------------------------------

@router.post(
    # See the comment on the GET .../{backend_id:int}/edit route above
    # for why `{backend_id:int}` matters. Same converter applied here.
    "/config/ai-backends/{backend_id:int}",
    response_class=HTMLResponse,
)
async def ai_backends_update(request: Request, backend_id: int):
    user, err = _require_admin(request)
    if err:
        return err
    db = get_db(request)
    secrets = get_secrets(request)
    existing = get_ai_backend(db, backend_id)
    if existing is None:
        return HTMLResponse("Not found", status_code=404)
    form = await request.form()
    row = _parse_form_row(form)
    err_msg = _validate_row(row)
    if err_msg:
        return _render(request, "admin/ai_backends/_form.html", {
            "user": user,
            "mode": "edit",
            "row": {
                **existing,
                "name": row["name"],
                "type": row["type_"],
                "endpoint": row["endpoint"],
                "model": row["model"] or "",
                "baa_certified": int(row["baa_certified"]),
                "baa_expires_at": row["baa_expires_at"] or "",
                "enabled": int(row["enabled"]),
            },
            "allowed_types": _allowed_types(),
            "form_error": err_msg,
        })

    # API-key handling — three operator intents on update:
    #   (a) leave unchanged: form doesn't carry replace_key + no plain
    #       text → preserve existing ref verbatim
    #   (b) replace: ``replace_key`` checkbox + ``api_key_plain`` filled
    #       → mint / reuse the backend-id-keyed secret name + store new
    #   (c) clear: ``clear_key`` checkbox → drop the ref + delete the
    #       secrets-store row
    api_key_plain = (form.get("api_key_plain") or "").strip()
    do_replace = (form.get("replace_key") in ("1", "on", "true"))
    do_clear = (form.get("clear_key") in ("1", "on", "true"))
    secret_ref: str | None = existing.get("api_key_secret_ref")
    if do_clear:
        old_ref = secret_ref
        secret_ref = None
        if old_ref and secrets is not None and hasattr(secrets, "delete"):
            try:
                secrets.delete(old_ref)
            except Exception as exc:
                _log.warning(
                    "API-key secrets-store delete failed",
                    extra={"_extra": {
                        "backend_id": backend_id,
                        "ref": old_ref,
                        "error": fmt_exc(exc),
                    }},
                )
    elif do_replace and api_key_plain and secrets is not None:
        secret_ref = _secret_ref_for(backend_id)
        try:
            secrets.set(secret_ref, api_key_plain)
        except Exception as exc:
            _log.error(
                "API-key persistence failed during update",
                extra={"_extra": {
                    "backend_id": backend_id,
                    "error": fmt_exc(exc),
                }},
            )

    try:
        update_ai_backend(
            db, backend_id,
            name=row["name"],
            type_=row["type_"],
            endpoint=row["endpoint"],
            api_key_secret_ref=secret_ref,
            model=row["model"],
            baa_certified=row["baa_certified"],
            baa_expires_at=row["baa_expires_at"],
            enabled=row["enabled"],
        )
    except sqlite3.IntegrityError as exc:
        return _render(request, "admin/ai_backends/_form.html", {
            "user": user,
            "mode": "edit",
            "row": {
                **existing,
                "name": row["name"],
                "type": row["type_"],
                "endpoint": row["endpoint"],
                "model": row["model"] or "",
                "baa_certified": int(row["baa_certified"]),
                "baa_expires_at": row["baa_expires_at"] or "",
                "enabled": int(row["enabled"]),
            },
            "allowed_types": _allowed_types(),
            "form_error": (
                "Could not save. The name may already be in use, "
                "or the values failed a schema check: "
                f"{exc}"
            ),
        })

    # Build a compact diff string for the audit row so the operator
    # can read "what changed" off a single line.
    parts: list[str] = [f"id={backend_id}", f"name={row['name']!r}"]
    if existing.get("enabled") != int(row["enabled"]):
        parts.append(
            f"enabled:{int(existing.get('enabled') or 0)}->{int(row['enabled'])}"
        )
    if existing.get("baa_certified") != int(row["baa_certified"]):
        parts.append(
            f"baa:{int(existing.get('baa_certified') or 0)}->{int(row['baa_certified'])}"
        )
    if do_clear:
        parts.append("api_key=cleared")
    elif do_replace and api_key_plain:
        parts.append("api_key=replaced")
    _audit(
        db, user,
        event_type="ai_backend_update",
        detail=", ".join(parts),
    )
    return RedirectResponse(
        f"/config/ai-backends?save_msg=Backend+{row['name']}+updated.",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Delete (POST)
# ---------------------------------------------------------------------------

@router.post(
    # See the comment on the GET .../{backend_id:int}/edit route above
    # for why `{backend_id:int}` matters. Same converter applied here.
    "/config/ai-backends/{backend_id:int}/delete",
    response_class=HTMLResponse,
)
async def ai_backends_delete(request: Request, backend_id: int):
    user, err = _require_admin(request)
    if err:
        return err
    db = get_db(request)
    secrets = get_secrets(request)
    backend = get_ai_backend(db, backend_id)
    if backend is None:
        return HTMLResponse("Not found", status_code=404)

    # FK on email_accounts is ON DELETE SET NULL — affected accounts
    # fall back to the install default automatically. Capture the
    # count for the audit row + the redirect banner.
    in_use_count = count_accounts_using_ai_backend(db, backend_id)
    name = backend["name"]
    secret_ref = backend.get("api_key_secret_ref")

    delete_ai_backend(db, backend_id)

    # Best-effort secrets-store cleanup. We don't want orphaned
    # encrypted blobs accumulating.
    if secret_ref and secrets is not None and hasattr(secrets, "delete"):
        try:
            secrets.delete(secret_ref)
        except Exception as exc:
            _log.warning(
                "API-key secrets-store delete failed on row delete",
                extra={"_extra": {
                    "backend_id": backend_id,
                    "ref": secret_ref,
                    "error": fmt_exc(exc),
                }},
            )

    _audit(
        db, user,
        event_type="ai_backend_delete",
        detail=(
            f"id={backend_id} name={name!r} "
            f"affected_accounts={in_use_count}"
        ),
    )
    msg = (
        f"Backend+{name}+deleted."
        f"+{in_use_count}+accounts+reverted+to+install+default."
        if in_use_count else f"Backend+{name}+deleted."
    )
    return RedirectResponse(
        f"/config/ai-backends?save_msg={msg}",
        status_code=303,
    )
