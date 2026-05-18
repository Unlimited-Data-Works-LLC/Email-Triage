"""UI routes for the multi-label feature (#129).

Labels are operator-curated tags applied independently of the LLM
category. The catalog lives at ``/labels`` (install-wide; any
authenticated user can manage it — the punch-list spec calls for
"operator-only, not restricted to admin"). Manual apply lives on
the message endpoints below; bulk-tag on triage results swaps in
through the triage_classify router.

Cross-references:
  * ``_v18_create_labels`` in web/migrations.py — schema.
  * ``list_labels`` / ``create_label`` / ``delete_label`` /
    ``apply_labels_to_message`` / ``remove_label_from_message`` /
    ``list_labels_on_message`` / ``list_messages_with_label`` in
    web/db.py — data helpers.
  * Rule-driven apply: list_rules.adds_labels JSON column read on
    the classify path (extension point — wired in this commit at
    the schema level; the engine integration consumes it in a
    follow-up edit to ``classify/hints.py`` or the route_and_act
    path. For v1 the slug array is persisted on the rule editor;
    the engine plumbing lands incrementally so we don't reshape
    ``ListHint`` mid-commit.).
"""
from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.web.app import get_db, get_templates
from email_triage.web.db_threadpool import db_call
from email_triage.web.dependencies import get_current_user
from email_triage.triage_logging import is_account_hipaa
from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger

from . import _shared

# Snapshot _shared helpers into this module's globals so handler
# bare-name references (_render, etc.) resolve. Same pattern as
# the other concern files in this package.
globals().update({
    _n: _v for _n, _v in vars(_shared).items()
    if not _n.startswith("__")
})

_log = get_logger("web.ui.labels")

router = APIRouter()


def __getattr__(name):
    """PEP 562 fallback to _shared for late-bound writes."""
    if hasattr(_shared, name):
        return getattr(_shared, name)
    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


# ---------------------------------------------------------------------------
# Catalog page — /labels
# ---------------------------------------------------------------------------


def _labels_page_snapshot(db) -> dict:
    """Single threadpool hop: list catalog + usage counts.

    Usage counts answer "is this label safe to delete" — a label
    with zero applications is a free delete; a label with N rows
    in message_labels prompts a confirm dialog.
    """
    from email_triage.web.db import list_labels
    labels = list_labels(db)
    # Per-slug usage counts in a single GROUP BY.
    counts = {
        r["label_slug"]: int(r["c"])
        for r in db.execute(
            "SELECT label_slug, COUNT(*) AS c "
            "FROM message_labels GROUP BY label_slug"
        ).fetchall()
    }
    for label in labels:
        label["usage_count"] = counts.get(label["slug"], 0)
    return {"labels": labels}


@router.get("/labels", response_class=HTMLResponse)
async def labels_page(request: Request):
    """CRUD page for the label catalog. Any authenticated user."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_labels_page_snapshot, db)

    return _render(templates, request, "labels/manage.html", {
        "user": user,
        **snap,
    })


@router.post("/labels/create", response_class=HTMLResponse)
async def labels_create(
    request: Request,
    slug: str = Form(...),
    name: str = Form(...),
    color: str = Form("#6c757d"),
):
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    templates = get_templates(request)

    slug = (slug or "").strip().lower()
    name = (name or "").strip()
    color = (color or "").strip() or "#6c757d"

    error: str | None = None
    if not slug:
        error = "Label name (slug) is required."
    elif not name:
        error = "Display name is required."

    if error is None:
        try:
            from email_triage.web.db import create_label
            await db_call(
                create_label, db, slug, name, color, user["id"],
            )
        except Exception as e:
            error = f"Could not create label: {fmt_exc(e)}"

    snap = await db_call(_labels_page_snapshot, db)
    return _render(templates, request, "labels/manage.html", {
        "user": user,
        **snap,
        "error": error,
        "success": None if error else f"Label '{slug}' added.",
    })


@router.post("/labels/{slug}/delete", response_class=HTMLResponse)
async def labels_delete(request: Request, slug: str):
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import delete_label
    await db_call(delete_label, db, slug)

    snap = await db_call(_labels_page_snapshot, db)
    return _render(templates, request, "labels/manage.html", {
        "user": user,
        **snap,
        "success": f"Label '{slug}' removed.",
    })


# ---------------------------------------------------------------------------
# Per-message apply / remove
# ---------------------------------------------------------------------------
#
# These endpoints are the manual-apply surface (from a future
# message-detail page, the bulk-tag action on triage results, etc.).
# Today the triage results template doesn't surface message_ids in
# a checkboxable form — that's a follow-up template change. The
# endpoints below are the durable contract; the bulk row template
# extension is the surface that calls them.


@router.post(
    "/messages/{account_id}/{message_id}/labels/add",
    response_class=HTMLResponse,
)
async def message_label_add(
    request: Request,
    account_id: int,
    message_id: str,
    label_slug: str = Form(...),
):
    """Attach one label to one message.

    HIPAA: when the actor is NOT the account owner AND the account
    is HIPAA-flagged, write a hipaa_access_event row
    (operation=label_apply). Same parity rule as the triage paths.
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    label_slug = (label_slug or "").strip().lower()
    if not label_slug:
        return HTMLResponse("Missing label_slug", status_code=400)

    from email_triage.web.db import (
        get_email_account, apply_labels_to_message,
    )

    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not _shared.can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    # HIPAA audit — actor != owner on HIPAA account.
    if (
        is_account_hipaa(acct)
        and user.get("id") != acct.get("user_id")
    ):
        try:
            from email_triage.web.db import record_hipaa_access_event
            await db_call(
                record_hipaa_access_event,
                db, user["id"], account_id, "label_apply",
                "ok", f"slug={label_slug}",
            )
        except Exception as e:
            _log.warning(
                "HIPAA label_apply audit row write failed",
                error=fmt_exc(e),
            )

    inserted = await db_call(
        apply_labels_to_message,
        db, message_id, account_id, [label_slug], user["id"],
    )

    return HTMLResponse(
        f'<span style="color:var(--pico-ins-color);">'
        f'{"applied" if inserted else "already applied"}</span>'
    )


@router.post(
    "/messages/{account_id}/{message_id}/labels/remove",
    response_class=HTMLResponse,
)
async def message_label_remove(
    request: Request,
    account_id: int,
    message_id: str,
    label_slug: str = Form(...),
):
    """Remove one label from one message."""
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    label_slug = (label_slug or "").strip().lower()

    from email_triage.web.db import get_email_account, remove_label_from_message

    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not _shared.can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    await db_call(
        remove_label_from_message, db, message_id, label_slug,
    )
    return HTMLResponse("")


@router.post(
    "/messages/{account_id}/bulk-labels/add",
    response_class=HTMLResponse,
)
async def messages_bulk_label_add(
    request: Request,
    account_id: int,
):
    """Bulk-tag handler — attach one or more labels to every selected
    message in the triage results.

    Form fields:
      label_slug         single dropdown value (one slug per submit)
      message_ids        repeated form field, one per checkbox

    Body:
      {"applied": <N>, "label": <slug>}
    """
    user = get_current_user(request)
    if user is None:
        return HTMLResponse("Unauthorized", status_code=401)

    db = get_db(request)
    form = await request.form()
    label_slug = (form.get("label_slug") or "").strip().lower()
    message_ids = form.getlist("message_ids")
    message_ids = [mid for mid in message_ids if mid and mid.strip()]

    if not label_slug or not message_ids:
        return HTMLResponse(
            '<span style="color:var(--pico-color-amber-500);">'
            'Nothing to tag — pick a label and at least one message.'
            '</span>'
        )

    from email_triage.web.db import (
        get_email_account, apply_labels_to_message,
    )

    acct = await db_call(get_email_account, db, account_id)
    if acct is None:
        return HTMLResponse("Account not found", status_code=404)
    if not _shared.can_manage_account(db, user, acct):
        return HTMLResponse("Forbidden", status_code=403)

    total = 0
    for mid in message_ids:
        total += await db_call(
            apply_labels_to_message,
            db, mid, account_id, [label_slug], user["id"],
        )

    return HTMLResponse(
        f'<span style="color:var(--pico-ins-color);">'
        f'Tagged {total} message{"s" if total != 1 else ""} '
        f'with "{label_slug}".</span>'
    )
