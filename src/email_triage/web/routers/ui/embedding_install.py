"""Admin routes for the lazy embedding-stack install (#180).

Lives at ``/config/ai-backends/embedding-*`` — siblings of the
existing ``/config/ai-backends/save`` POST. Each handler is admin-
only (HIPAA / install-wide install ops are not delegate-grantable)
and writes an ``auth_events`` audit row at the action boundary.

Routes
------
POST /config/ai-backends/embedding-install
     Spawn the auto-download installer. Returns 303 to /config?tab=ai_backends.

POST /config/ai-backends/embedding-sideload
     Spawn the sideload installer. Requires source_dir form field.
     Returns 303 to /config?tab=ai_backends.

POST /config/ai-backends/embedding-install-cancel
     Flip the process-local cancel flag. Worker exits at the next
     file boundary. Returns 303.

POST /config/ai-backends/embedding-reverify
     Re-hash on-disk files against the manifest (no download).
     Returns 303.

POST /config/ai-backends/embedding-reindex/{account_id}
     Enqueue a triage_jobs row with kind='embedding_reindex' for one
     account. Returns 303.

GET  /config/ai-backends/embedding-install-status
     Return the install card partial for HTMX self-polling. NO
     full-page response — partial only.

Async install spawning
----------------------
The actual install is long-running (5-10 minutes). The route fires
off an asyncio task that runs in the background and updates the
install_state row + invokes the progress_callback (which writes
back to the same row). The route returns 303 immediately so the
browser redirects + re-renders the AI Backends tab with the now-
active install card; the card's HTMX poll picks up state changes
from there.

We deliberately do NOT use the bulk-runner triage_jobs path for the
install itself — install is install-wide (singleton), not per-
account, and the triage_jobs runner's progress shape doesn't fit a
files-and-bytes pipeline. The install_state singleton row is the
right home; the worker is a fire-and-forget asyncio task.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage._errfmt import fmt_exc
from email_triage.embedding_bits import (
    DEFAULT_MANIFEST_PATH,
    get_install_status,
    get_runtime_deps_path,
    install_auto,
    install_sideload,
    is_runtime_ready,
    request_cancel,
    reverify,
)
from email_triage.web.app import get_db, get_templates
from email_triage.web.db import record_auth_event
from email_triage.web.dependencies import get_current_user

_log = logging.getLogger("email_triage.web.ui.embedding_install")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_admin(request: Request) -> tuple[dict | None, Any]:
    """Standard admin gate. Mirrors the pattern in ai_backends_crud.

    Returns (user, error_response). When user is None the caller
    should ``return err`` directly.
    """
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _audit(
    db: sqlite3.Connection,
    user: dict,
    *,
    event_type: str,
    detail: str,
    outcome: str = "success",
) -> None:
    """Best-effort audit log. Mirrors ai_backends_crud._audit."""
    try:
        record_auth_event(
            db,
            event_type=event_type,
            email=user.get("email", "") or "",
            user_id=user.get("id"),
            outcome=outcome,
            detail=detail,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "embedding-install audit row failed",
            extra={"_extra": {
                "event": event_type, "outcome": outcome,
                "error": fmt_exc(exc),
            }},
        )


def _redirect_to_tab() -> RedirectResponse:
    return RedirectResponse(
        "/config?tab=ai_backends", status_code=303,
    )


def _is_htmx(request: Request) -> bool:
    """Did this request come from HTMX (vs a plain browser POST)?

    Used by every mutating route to decide between (a) returning the
    install-card partial in-place (HTMX case), or (b) emitting a 303
    redirect to the full /config page (back-compat for direct form
    posts / scripted tools / curl).

    Header set by htmx.org's request layer. Case-insensitive lookup
    via FastAPI's headers Mapping.
    """
    return request.headers.get("HX-Request", "").lower() == "true"


def _render_install_card(request: Request) -> HTMLResponse:
    """Return the install-card partial against the current DB state.

    Routes call this on the HTMX branch instead of ``_redirect_to_tab``
    so the user's click result swaps the card in-place. The polling
    attributes the template attaches when the state is in-flight
    keep the card live until a terminal state lands.
    """
    db = get_db(request)
    templates = get_templates(request)
    install_state = get_install_status(db)
    manifest_sha = install_state.get("manifest_sha256") or ""
    return templates.TemplateResponse(
        request,
        "admin/config_tabs/_embedding_install_card.html",
        {
            "request": request,
            "install_state": install_state,
            "install_manifest_sha_short": (
                manifest_sha[:12] if manifest_sha else ""
            ),
            "install_runtime_ready": is_runtime_ready(),
        },
    )


def _post_response(request: Request) -> HTMLResponse | RedirectResponse:
    """Branch on HTMX vs plain POST.

    HTMX: return the install-card partial (current DB state).
    Plain: 303 to /config?tab=ai_backends (back-compat).
    """
    if _is_htmx(request):
        return _render_install_card(request)
    return _redirect_to_tab()


def _manifest_path() -> Path:
    """Resolve the manifest path — env override > foundation default."""
    import os
    raw = os.environ.get("EMBEDDING_BITS_MANIFEST", "").strip()
    if raw:
        return Path(raw)
    return Path(DEFAULT_MANIFEST_PATH)


def _progress_writer(
    db_path: str,
) -> Any:
    """Build a progress_callback that opens a short-lived connection
    each call.

    The installer runs in a background asyncio.Task; it can't share
    the request-scoped sqlite3.Connection (different thread, different
    transaction). We open a connection per callback invocation —
    cheap (SQLite open-file is microseconds) and avoids the
    connection-affinity headache.

    Right now the installer ALSO writes to the install_state row via
    its own conn argument (handed in at install_auto call time), so
    this callback is supplementary — used for any UI-only fields not
    already covered by the installer's internal _update_state calls.
    Kept here as the extension point if the row schema grows.
    """
    def _cb(payload: dict) -> None:
        # Currently a no-op pass-through — the installer writes
        # directly to install_state, so this callback only logs the
        # progress at debug level for operator-visible journals.
        _log.debug(
            "embedding-install progress",
            extra={"_extra": {"payload": payload}},
        )
    return _cb


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/config/ai-backends/embedding-install", response_class=HTMLResponse)
async def embedding_install(request: Request):
    """Kick off the auto-download install. Admin-only."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)

    # Refuse to spawn if an install is already in flight. The
    # install_state row's status is the truth; we read it under the
    # request connection so the UI sees consistent state.
    state = get_install_status(db)
    if state["status"] in ("downloading", "verifying", "installing"):
        _audit(
            db, user,
            event_type="embedding_install_start",
            detail="rejected — install already in flight",
            outcome="failure",
        )
        return _post_response(request)

    _audit(
        db, user,
        event_type="embedding_install_start",
        detail="method=auto",
    )

    target_dir = get_runtime_deps_path()
    manifest_path = _manifest_path()

    # 2026-05-18 — flip status to "downloading" synchronously BEFORE
    # spawning the worker. Otherwise the HTMX response (or the 303-
    # followed page render) wins the race and shows the prior state
    # (installed / failed / not_installed), forcing the operator to
    # manually reload to see progress. With the synchronous flip, the
    # immediate card render carries status="downloading" + the polling
    # attributes the template attaches in that branch keep the card
    # live until the terminal state lands.
    from email_triage.embedding_bits import _update_state
    _update_state(
        db,
        status="downloading",
        install_method="auto",
        current_file=None,
        progress_files_done=0,
        progress_bytes_done=0,
        bump_attempt=True,
        set_last_attempt_now=True,
        clear_error=True,
    )
    db.commit()

    # Fire-and-forget: install runs in the background, writes its own
    # state, returns. We use the app-state DB connection for the
    # worker so it has a stable handle for the duration (the request
    # connection goes away when this handler returns).
    app_db = request.app.state.db

    async def _run() -> None:
        try:
            await install_auto(
                conn=app_db,
                manifest_path=manifest_path,
                target_dir=target_dir,
                progress_callback=_progress_writer(""),
            )
        except Exception:  # noqa: BLE001
            _log.exception("embedding install_auto task raised")

    asyncio.create_task(_run())
    return _post_response(request)


@router.post("/config/ai-backends/embedding-sideload", response_class=HTMLResponse)
async def embedding_sideload(request: Request):
    """Kick off the sideload install. Admin-only."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)

    form = await request.form()
    source_dir_raw = (form.get("source_dir") or "").strip()
    if not source_dir_raw:
        source_dir_raw = "/app/data/runtime-deps/sideload"
    source_dir = Path(source_dir_raw)

    if not source_dir.exists() or not source_dir.is_dir():
        _audit(
            db, user,
            event_type="embedding_install_start",
            detail=f"method=sideload; source_dir not found: {source_dir_raw}",
            outcome="failure",
        )
        # Write the user-visible error to the install_state row so the
        # admin tab surfaces it on the next render.
        from email_triage.embedding_bits import _update_state, _scrub_error
        _update_state(
            db,
            status="failed",
            install_method="sideload",
            last_error_class="FileNotFoundError",
            last_error_msg=f"Source dir does not exist: {source_dir_raw}",
            bump_attempt=True,
            set_last_attempt_now=True,
        )
        db.commit()
        return _post_response(request)

    state = get_install_status(db)
    if state["status"] in ("downloading", "verifying", "installing"):
        _audit(
            db, user,
            event_type="embedding_install_start",
            detail="rejected — install already in flight",
            outcome="failure",
        )
        return _post_response(request)

    _audit(
        db, user,
        event_type="embedding_install_start",
        detail=f"method=sideload; source_dir={source_dir_raw}",
    )

    # Same synchronous status flip as the auto path — the HTMX swap
    # needs to see "downloading" immediately, not whatever the prior
    # state was.
    from email_triage.embedding_bits import _update_state
    _update_state(
        db,
        status="downloading",
        install_method="sideload",
        current_file=None,
        progress_files_done=0,
        progress_bytes_done=0,
        bump_attempt=True,
        set_last_attempt_now=True,
        clear_error=True,
    )
    db.commit()

    target_dir = get_runtime_deps_path()
    manifest_path = _manifest_path()
    app_db = request.app.state.db

    async def _run() -> None:
        try:
            await install_sideload(
                conn=app_db,
                manifest_path=manifest_path,
                source_dir=source_dir,
                target_dir=target_dir,
                progress_callback=_progress_writer(""),
            )
        except Exception:  # noqa: BLE001
            _log.exception("embedding install_sideload task raised")

    asyncio.create_task(_run())
    return _post_response(request)


@router.post(
    "/config/ai-backends/embedding-install-cancel",
    response_class=HTMLResponse,
)
async def embedding_install_cancel(request: Request):
    """Flip the cancel flag. Admin-only."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)

    request_cancel()
    _audit(
        db, user,
        event_type="embedding_install_cancelled",
        detail="operator requested cancel",
    )
    return _post_response(request)


@router.post(
    "/config/ai-backends/embedding-reverify",
    response_class=HTMLResponse,
)
async def embedding_reverify(request: Request):
    """Re-hash staged files against the manifest. No re-download."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)

    _audit(
        db, user,
        event_type="embedding_install_reverify",
        detail="operator triggered re-verify",
    )

    target_dir = get_runtime_deps_path()
    manifest_path = _manifest_path()

    # Reverify is fast (just rehash; no download) — run inline so the
    # admin UI surfaces the result immediately. await-via-to_thread
    # so it doesn't block the event loop while hashing.
    try:
        result = await asyncio.to_thread(
            reverify,
            conn=db,
            manifest_path=manifest_path,
            target_dir=target_dir,
        )
        if result.status == "failed":
            _audit(
                db, user,
                event_type="embedding_install_reverify",
                detail=f"reverify failed: {result.error_class}",
                outcome="failure",
            )
    except Exception:  # noqa: BLE001
        _log.exception("embedding reverify raised")

    return _post_response(request)


@router.post(
    "/config/ai-backends/embedding-reindex/{account_id}",
    response_class=HTMLResponse,
)
async def embedding_reindex(request: Request, account_id: int):
    """Enqueue a reindex job for one account. Admin-only."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)

    if not is_runtime_ready():
        _audit(
            db, user,
            event_type="embedding_reindex_enqueue",
            detail=f"account_id={account_id} rejected — runtime not ready",
            outcome="failure",
        )
        return RedirectResponse(
            "/config?tab=ai_backends&save_error="
            "Embedding+runtime+is+not+installed+yet",
            status_code=303,
        )

    from email_triage.jobs.embedding_reindex import (
        enqueue_embedding_reindex,
    )
    job_id = enqueue_embedding_reindex(
        db, account_id=account_id, actor_user_id=user.get("id"),
    )
    _audit(
        db, user,
        event_type="embedding_reindex_enqueue",
        detail=f"account_id={account_id} job_id={job_id}",
    )
    return RedirectResponse(
        f"/triage/run?account_id={account_id}", status_code=303,
    )


@router.get(
    "/config/ai-backends/embedding-install-status",
    response_class=HTMLResponse,
)
async def embedding_install_status(request: Request):
    """HTMX poll endpoint — returns the install card partial only.

    NOT a full page render — the parent template's hx-swap=outerHTML
    replaces just this card. Same admin gate as the mutating routes
    (a non-admin GET would expose install-state surface that's
    sensitive in the failure-message column)."""
    user, err = _require_admin(request)
    if err is not None:
        return err
    db = get_db(request)
    templates = get_templates(request)

    install_state = get_install_status(db)
    manifest_sha = install_state.get("manifest_sha256") or ""

    return templates.TemplateResponse(
        request,
        "admin/config_tabs/_embedding_install_card.html",
        {
            "request": request,
            "install_state": install_state,
            "install_manifest_sha_short": manifest_sha[:12] if manifest_sha else "",
            "install_runtime_ready": is_runtime_ready(),
        },
    )
