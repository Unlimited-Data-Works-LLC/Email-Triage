"""UI routes for the multi-label feature.

Labels are operator-curated tags applied independently of the LLM
category. The catalog lives at ``/labels`` (install-wide; any
authenticated user can manage it — the backlog spec calls for
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
from email_triage.web.dependencies import RequireUser, RequireUserFragment
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

# async-db: handlers route SQLite through db_call
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
async def labels_page(request: Request, user: RequireUser):
    """CRUD page for the label catalog. Any authenticated user."""
    db = get_db(request)
    templates = get_templates(request)
    snap = await db_call(_labels_page_snapshot, db)

    return await _render(templates, request, "labels/manage.html", {
        "user": user,
        **snap,
    })


@router.post("/labels/create", response_class=HTMLResponse)
async def labels_create(
    request: Request,
    user: RequireUserFragment,
    slug: str = Form(...),
    name: str = Form(...),
    color: str = Form("#6c757d"),
):
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
    return await _render(templates, request, "labels/manage.html", {
        "user": user,
        **snap,
        "error": error,
        "success": None if error else f"Label '{slug}' added.",
    })


@router.post("/labels/{slug}/delete", response_class=HTMLResponse)
async def labels_delete(
    request: Request, slug: str, user: RequireUserFragment,
):
    db = get_db(request)
    templates = get_templates(request)

    from email_triage.web.db import delete_label
    await db_call(delete_label, db, slug)

    snap = await db_call(_labels_page_snapshot, db)
    return await _render(templates, request, "labels/manage.html", {
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
    user: RequireUserFragment,
    label_slug: str = Form(...),
):
    """Attach one label to one message.

    HIPAA: when the actor is NOT the account owner AND the account
    is HIPAA-flagged, write a hipaa_access_event row
    (operation=label_apply). Same parity rule as the triage paths.
    """
    db = get_db(request)
    label_slug = (label_slug or "").strip().lower()
    if not label_slug:
        return HTMLResponse("Missing label_slug", status_code=400)

    from email_triage.web.db import (
        get_email_account, apply_labels_to_message,
    )

    def _label_add_db_work() -> tuple[int, str, bool]:
        """/ — fetch + auth check + (HIPAA audit) + apply in
        one threadpool hop. Returns ``(status, body, inserted)``;
        status 200 means the apply ran, ``inserted`` is then valid.
        """
        acct = get_email_account(db, account_id)
        if acct is None:
            return 404, "Account not found", False
        if not _shared.can_manage_account(db, user, acct):
            return 403, "Forbidden", False

        # HIPAA audit — actor != owner on HIPAA account (PD#14 SSOT).
        _shared.audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="label_apply",
            outcome="ok",
            detail=f"slug={label_slug}",
        )

        inserted = apply_labels_to_message(
            db, message_id, account_id, [label_slug], user["id"],
        )
        return 200, "", bool(inserted)

    status, body, inserted = await db_call(_label_add_db_work)
    if status != 200:
        return HTMLResponse(body, status_code=status)

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
    user: RequireUserFragment,
    label_slug: str = Form(...),
):
    """Remove one label from one message.

    HIPAA: when the actor is NOT the account owner AND the account
    is HIPAA-flagged, write a hipaa_access_event row
    (operation=label_remove). Same actor!=owner parity rule as the
    sibling ``message_label_add`` path — owner self-access is exempt.
    """
    db = get_db(request)
    label_slug = (label_slug or "").strip().lower()

    from email_triage.web.db import get_email_account, remove_label_from_message

    def _label_remove_db_work() -> tuple[int, str]:
        """/ — fetch + auth check + (HIPAA audit) + remove in
        one threadpool hop. Returns ``(status, body)``; 200 means the
        remove ran.
        """
        acct = get_email_account(db, account_id)
        if acct is None:
            return 404, "Account not found"
        if not _shared.can_manage_account(db, user, acct):
            return 403, "Forbidden"

        # HIPAA audit — actor != owner on HIPAA account (PD#14 SSOT).
        # Owner self-access is exempt; the gate lives in audit_phi_access.
        _shared.audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="label_remove",
            outcome="ok",
            detail=f"slug={label_slug}",
        )

        remove_label_from_message(db, message_id, label_slug)
        return 200, ""

    status, body = await db_call(_label_remove_db_work)
    if status != 200:
        return HTMLResponse(body, status_code=status)
    return HTMLResponse("")


@router.post(
    "/messages/{account_id}/bulk-labels/add",
    response_class=HTMLResponse,
)
async def messages_bulk_label_add(
    request: Request,
    account_id: int,
    user: RequireUserFragment,
):
    """Bulk-tag handler — attach one or more labels to every selected
    message in the triage results.

    Form fields:
      label_slug         single dropdown value (one slug per submit)
      message_ids        repeated form field, one per checkbox

    Body:
      {"applied": <N>, "label": <slug>}
    """
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

    def _bulk_label_db_work() -> tuple[int, str, int]:
        """/ — fetch + auth check + (HIPAA audit) + bulk apply
        in ONE threadpool hop. The per-message apply loop runs inside
        the single hop so a 50-message bulk tag is one thread crossing,
        not 50. Returns ``(status, body, total)``.
        """
        acct = get_email_account(db, account_id)
        if acct is None:
            return 404, "Account not found", 0
        if not _shared.can_manage_account(db, user, acct):
            return 403, "Forbidden", 0

        # HIPAA audit — actor != owner on HIPAA account.
        # One row per bulk operation (a bulk-tag is one operator action);
        # bulk_n records how many messages it touched. Owner self-access
        # is exempt; the gate lives in audit_phi_access.
        _shared.audit_phi_access(
            db,
            actor_user_id=user["id"],
            account=acct,
            operation="label_apply",
            outcome="ok",
            detail=f"slug={label_slug} bulk_n={len(message_ids)}",
        )

        total_ = 0
        for mid in message_ids:
            total_ += apply_labels_to_message(
                db, mid, account_id, [label_slug], user["id"],
            )
        return 200, "", total_

    status, body, total = await db_call(_bulk_label_db_work)
    if status != 200:
        return HTMLResponse(body, status_code=status)

    # N-68 — label_slug is form-derived (form.get("label_slug")); escape it
    # before it lands in the HTML body (reflected-XSS class).
    import html as _html_mod
    return HTMLResponse(
        f'<span style="color:var(--pico-ins-color);">'
        f'Tagged {total} message{"s" if total != 1 else ""} '
        f'with "{_html_mod.escape(label_slug)}".</span>'
    )
