"""Admin retry-queue page.

Per-message retry rows that R-A's sweeper drains live in the
``watcher_retry_queue`` table. This router gives the admin three
operations against that table:

  GET  /admin/retry-queue          — list view + filter dropdown.
  POST /admin/retry-queue/{id}/retry-now  — bump next_attempt_at to
        NOW so the next sweeper tick picks the row up.
  POST /admin/retry-queue/{id}/abandon    — mark_retry_dead with
        ``reason='operator_abandoned'``.

Every action writes an ``access_log`` row via
:func:`record_access_event` so the audit trail stays intact under
HIPAA §164.312(b).

HIPAA filter: the ``mailbox`` column is suppressed for rows whose
account is HIPAA-flagged (the table cell renders "(redacted)"
instead). The ``last_error_msg`` text is already PHI-scrubbed at
persist time by R-A, so this view doesn't re-redact it — it just
displays whatever R-A's enqueue path stored.

Failure-safe: when R-A's helpers don't import (parallel-build
race, this commit cherry-picked before R-A's), the GET renders an
empty list with an explanatory note. The POSTs return a 503 with
the same note. The audit row still fires for the attempt.
"""
from __future__ import annotations

from email_triage._isotime import now_utc_iso

from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage.web.app import get_db, get_templates
from email_triage.web.db_threadpool import db_call
from email_triage.web._audit import safe_audit_write
from email_triage._errfmt import fmt_exc


# async-db: handlers route SQLite through db_call

router = APIRouter()


# Set of state slugs the filter dropdown accepts. The default
# render combines pending+dead because those are the rows that
# need operator attention; ``done`` rows are kept as a separate
# tab for forensic browsing of what already succeeded on retry.
_STATE_FILTERS: tuple[str, ...] = (
    "pending_and_dead",
    "pending",
    "dead",
    "done",
    "all",
)


# Census 2026-06-09 #3: UI admin gate → the dependencies SSOT.
from email_triage.web.dependencies import require_admin_ui as _require_admin


def _audit(
    db: Any,
    *,
    user: dict,
    route: str,
    method: str,
    status_code: int,
    outcome: str,
    detail: str | None = None,
) -> None:
    """Write an access_log row. Never raises — audit failure must
    not break the operator's workflow on this page. Routed through the
    best-effort audit-write SSOT so the miss is visible to /health's
    audit-failure drift counter (census run17 #3)."""
    def _emit():
        from email_triage.web.db import record_access_event
        return record_access_event(
            db,
            actor_user_id=user.get("id"),
            method=method,
            route=route,
            account_id=None,
            message_id=None,
            status_code=int(status_code),
            outcome=outcome,
            detail=detail,
        )
    safe_audit_write(
        _emit, description=f"access_log {method} {route} outcome={outcome}",
    )


#  — admin retry-queue page caps. Combined pending+dead caps each
# half at 200; a single-state filter caps at 400. Past the cap the
# oldest rows silently vanish and the queue looks complete — surface
# "showing first N of M" so a backlog larger than the cap is visible.
_CAP_COMBINED = 200
_CAP_SINGLE = 400


def _load_rows(
    db: Any, *, state_filter: str, offset: int = 0,
):
    """Pull rows from R-A's helper, augment with HIPAA mailbox
    suppression. Returns ``(rows, error_note, page_win, cap_segments)``:

    * ``error_note`` — a plain-English string when R-A's helper is
      missing/raised, else None.
    * ``page_win`` — a ``PageWindow`` for the SINGLE-state views
      (pending / dead / all), which page via ``?offset=`` so the full
      backlog past the cap is REACHABLE. None for the combined
      ``pending_and_dead`` summary.
    * ``cap_segments`` — for the combined view only, a per-half
      ``{label, shown, total, cap, view_all_state}`` so the operator can
      jump to the paginated single-state view to reach the full backlog.
    """
    from email_triage.web._pagination import page_window, clamp_offset
    try:
        from email_triage.web.db import (
            list_retries_for_admin, count_retries_for_admin,
        )
    except ImportError:
        return [], (
            "Retry queue not yet available on this install. The "
            "sweeper foundation lands on the next deploy; once it's "
            "live, queued retries will show up here."
        ), None, []

    cap_segments: list[dict[str, Any]] = []
    page_win = None
    state_param: str | None
    if state_filter == "pending_and_dead":
        # R-A's helper takes a single state slug. Two calls + merge.
        # The combined view is a summary (first cap of each); the full
        # backlog is reached by clicking through to a single-state view,
        # which paginates. So no offset here — just the per-half segments
        # carrying a ``view_all_state`` for the "view all N →" link.
        try:
            pending = list_retries_for_admin(
                db, state="pending", limit=_CAP_COMBINED,
            )
            dead = list_retries_for_admin(
                db, state="dead", limit=_CAP_COMBINED,
            )
            rows = list(pending) + list(dead)
            for label, shown_rows, st in (
                ("pending", pending, "pending"),
                ("dead", dead, "dead"),
            ):
                total = count_retries_for_admin(db, state=st)
                if total > len(shown_rows):
                    cap_segments.append({
                        "label": label, "shown": len(shown_rows),
                        "total": total, "cap": _CAP_COMBINED,
                        "view_all_state": st,
                    })
        except Exception as exc:
            return [], (
                f"Could not read the retry queue ({fmt_exc(exc)}). "
                "Try refreshing or check /health/detail."
            ), None, []
    else:
        state_param = state_filter if state_filter != "all" else None
        try:
            total = count_retries_for_admin(db, state=state_param)
            off = clamp_offset(offset, _CAP_SINGLE, total)
            rows = list(list_retries_for_admin(
                db, state=state_param, limit=_CAP_SINGLE, offset=off,
            ))
            page_win = page_window(
                total=total, offset=off, limit=_CAP_SINGLE, shown=len(rows),
            )
        except Exception as exc:
            return [], (
                f"Could not read the retry queue ({fmt_exc(exc)}). "
                "Try refreshing or check /health/detail."
            ), None, []

    # Augment each row with an ``account_label`` and HIPAA flag.
    # The DB query that backs ``list_retries_for_admin`` may or may
    # not already include ``account_name``+``hipaa`` — defensively
    # look them up if missing.
    augmented: list[dict[str, Any]] = []
    acct_cache: dict[int, dict[str, Any]] = {}
    for r in rows:
        row = dict(r) if hasattr(r, "keys") else r
        acct_id = row.get("account_id")
        if acct_id and acct_id not in acct_cache:
            try:
                arow = db.execute(
                    "SELECT ea.id, ea.name, ea.hipaa, "
                    "       COALESCE(u.name, u.email, '') AS owner "
                    "FROM email_accounts ea "
                    "LEFT JOIN users u ON u.id = ea.user_id "
                    "WHERE ea.id = ? LIMIT 1",
                    (int(acct_id),),
                ).fetchone()
                if arow is not None:
                    acct_cache[acct_id] = dict(arow)
            except Exception:
                acct_cache[acct_id] = {}
        acct = acct_cache.get(acct_id, {}) if acct_id else {}
        # N-81: route through is_account_hipaa (folds system flag so
        # a system-HIPAA install with acct["hipaa"]=0 still redacts).
        from email_triage.triage_logging import is_account_hipaa as _iah_rq
        is_hipaa = _iah_rq(acct) if acct else False
        row["account_label"] = (
            acct.get("name") or f"#{acct_id}" if acct_id else "(unknown)"
        )
        row["account_owner"] = acct.get("owner") or ""
        # HIPAA mailbox suppression. Other addressing tuples
        # (gmail_msg_id / o365_msg_id) are opaque ids, not PHI;
        # they stay visible. mailbox is a folder name like
        # "INBOX/Patients-2026" which can leak grouping intent.
        if is_hipaa and row.get("mailbox"):
            row["mailbox_display"] = "(redacted)"
        else:
            row["mailbox_display"] = row.get("mailbox") or ""
        # Plain-English "last error" cleanup — strip module
        # qualname prefix ("httpx.ReadTimeout" → "ReadTimeout").
        err_class = row.get("error_class") or row.get("last_error_class") or ""
        if "." in err_class:
            err_class = err_class.rsplit(".", 1)[-1]
        row["error_class_short"] = err_class
        augmented.append(row)

    return augmented, None, page_win, cap_segments


@router.get("/admin/retry-queue", response_class=HTMLResponse)
async def retry_queue_index(request: Request):
    """List the retry queue. Default filter shows pending+dead."""
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    db = get_db(request)
    templates = get_templates(request)

    state_filter = (
        request.query_params.get("state") or "pending_and_dead"
    ).strip().lower()
    if state_filter not in _STATE_FILTERS:
        state_filter = "pending_and_dead"
    #  — single-state views page via ?offset=; clamped in _load_rows.
    raw_offset = request.query_params.get("offset")

    def _index_db_work():
        """/ — list load + audit write in one threadpool hop."""
        rows_, error_note_, page_win_, cap_segments_ = _load_rows(
            db, state_filter=state_filter, offset=raw_offset,
        )
        # Audit the read (HIPAA — admin viewing a list that names
        # accounts is a §164.312(b) auditable event).
        _audit(
            db, user=user, route="/admin/retry-queue", method="GET",
            status_code=200,
            outcome="ok" if error_note_ is None else "degraded",
            detail=f"state={state_filter} rows={len(rows_)}",
        )
        return rows_, error_note_, page_win_, cap_segments_

    rows, error_note, page_win, cap_segments = await db_call(_index_db_work)

    # Defer to _shared._render for the BAA-banner injection +
    # hipaa_mode ctx + retry_queue_banner ctx (used by base.html
    # for the install-wide threshold-crossed banner). Importing
    # _shared at module load would create a circular dep with the
    # __init__.py's globals().update; defer to call time.
    from email_triage.web.routers.ui import _shared
    return await _shared._render(
        templates, request, "admin/retry_queue/_index.html",
        {
            "user": user,
            "rows": rows,
            "state_filter": state_filter,
            "state_filters": _STATE_FILTERS,
            "error_note": error_note,
            "cap_segments": cap_segments,
            "page_win": page_win,
        },
    )


@router.post("/admin/retry-queue/{retry_id}/retry-now")
async def retry_queue_retry_now(
    request: Request, retry_id: int,
):
    """Bump ``next_attempt_at`` to NOW so the sweeper picks the row
    up on the next tick. R-A doesn't expose a dedicated "bump"
    helper, so we touch the column directly inside this handler.
    """
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    db = get_db(request)

    def _retry_now_db_work() -> tuple[int, str]:
        """/ — lookup + UPDATE + audit in one threadpool hop.
        Returns ``(status_code, body)``; status 303 means redirect.
        """
        # Look up the row first so the audit detail can carry useful
        # context. ``get_retry`` is R-A's helper — fall back to a
        # direct SELECT if it isn't on the import path.
        row: dict[str, Any] | None = None
        helpers_present = True
        try:
            from email_triage.web.db import get_retry  # noqa: F401
        except ImportError:
            helpers_present = False
        if helpers_present:
            try:
                r = get_retry(db, int(retry_id))
                row = dict(r) if r is not None else None
            except Exception:
                row = None

        if row is None and helpers_present:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/retry-now",
                method="POST", status_code=404, outcome="not_found",
                detail=f"retry_id={retry_id}",
            )
            return 404, "Not Found"

        if not helpers_present:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/retry-now",
                method="POST", status_code=503, outcome="degraded",
                detail="retry queue helpers not present (R-A not merged)",
            )
            return 503, "Retry queue is not yet active on this install."

        # Direct UPDATE on the column. This bypasses R-A's "compute next
        # attempt" backoff math intentionally — the operator-driven
        # retry-now bypasses the schedule by design.
        now_iso = now_utc_iso()
        try:
            db.execute(
                "UPDATE watcher_retry_queue SET next_attempt_at = ? "
                "WHERE id = ?",
                (now_iso, int(retry_id)),
            )
            db.commit()
        except Exception as exc:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/retry-now",
                method="POST", status_code=500, outcome="error",
                detail=fmt_exc(exc),
            )
            return 500, "Internal error"

        _audit(
            db, user=user,
            route=f"/admin/retry-queue/{retry_id}/retry-now",
            method="POST", status_code=303, outcome="ok",
            detail=f"retry_id={retry_id} account_id={row.get('account_id')}",
        )
        return 303, ""

    status_code, body = await db_call(_retry_now_db_work)
    if status_code == 303:
        return RedirectResponse("/admin/retry-queue", status_code=303)
    return HTMLResponse(body, status_code=status_code)


@router.post("/admin/retry-queue/{retry_id}/abandon")
async def retry_queue_abandon(
    request: Request, retry_id: int,
):
    """Mark the row dead with ``reason='operator_abandoned'``.
    The sweeper will not pick it up again."""
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    db = get_db(request)

    def _abandon_db_work() -> tuple[int, str]:
        """/ — lookup + mark_retry_dead + audit in one
        threadpool hop. Returns ``(status_code, body)``; 303 = redirect.
        """
        try:
            from email_triage.web.db import (
                mark_retry_dead, get_retry,
            )
        except ImportError:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/abandon",
                method="POST", status_code=503, outcome="degraded",
                detail="retry queue helpers not present (R-A not merged)",
            )
            return 503, "Retry queue is not yet active on this install."

        row = None
        try:
            r = get_retry(db, int(retry_id))
            row = dict(r) if r is not None else None
        except Exception:
            row = None

        if row is None:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/abandon",
                method="POST", status_code=404, outcome="not_found",
                detail=f"retry_id={retry_id}",
            )
            return 404, "Not Found"

        try:
            mark_retry_dead(db, int(retry_id), reason="operator_abandoned")
        except Exception as exc:
            _audit(
                db, user=user,
                route=f"/admin/retry-queue/{retry_id}/abandon",
                method="POST", status_code=500, outcome="error",
                detail=fmt_exc(exc),
            )
            return 500, "Internal error"

        _audit(
            db, user=user,
            route=f"/admin/retry-queue/{retry_id}/abandon",
            method="POST", status_code=303, outcome="ok",
            detail=f"retry_id={retry_id} account_id={row.get('account_id')}",
        )
        return 303, ""

    status_code, body = await db_call(_abandon_db_work)
    if status_code == 303:
        return RedirectResponse("/admin/retry-queue", status_code=303)
    return HTMLResponse(body, status_code=status_code)
