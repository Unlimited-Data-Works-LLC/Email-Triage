"""Admin routes for the lazy embedding-stack install.

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

POST /config/ai-backends/embedding-remove
     Delete the runtime prefix and reset the install-state row in one
     step, through the ``embedding_bits.remove_install`` funnel the CLI
     also uses. Returns 303.

POST /config/ai-backends/embedding-update
     Punch 569: replace the installed runtime atomically — stage the image's
     set beside the live one, verify it, swap, re-verify, roll back on any
     failure. The ONE action behind the [Update embedding runtime] banner
     button. Returns 303 (HTMX: the card partial).

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

from . import _shared

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from email_triage._errfmt import scrub_error_for_persist

from email_triage.embedding_bits import (
    RESTART_MESSAGE,
    RemoveInFlight,
    RemoveTargetRefused,
    auto_update_enabled,
    auto_update_failure,
    get_install_status,
    get_runtime_deps_path,
    install_auto,
    install_sideload,
    is_runtime_ready,
    remove_install,
    request_cancel,
    resolve_manifest_path,
    reverify,
    runtime_importable_probe,
    runtime_install_record,
    runtime_site_packages_candidates,
    update_in_progress,
)
from email_triage.web._audit import safe_audit_write
from email_triage.web.app import get_db, get_templates
from email_triage.web.error_html import error_article
from email_triage.web.db import record_auth_event
from email_triage.web.db_threadpool import db_call
from email_triage.web.embedding_update_runner import (
    UpdateActor,
    schedule_tombstone_purge,
    start_runtime_update,
)

# async-db: handlers route SQLite through db_call
from email_triage.triage_logging import get_logger  # N-196b R21_4

_log = get_logger("email_triage.web.ui.embedding_install")  # N-196b R21_4
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Census 2026-06-09 #3: UI admin gate → the dependencies SSOT.
from email_triage.web.dependencies import require_admin_ui as _require_admin


def _update_pause_note() -> str:
    """The notice SSOT's "embedding pauses until restart" sentence, or ""."""
    from email_triage.embedding_bits import UPDATE_PAUSE_NOTE, _runtime_loaded_here

    return UPDATE_PAUSE_NOTE if _runtime_loaded_here() else ""


def _audit(
    db: sqlite3.Connection,
    user: dict,
    *,
    event_type: str,
    detail: str,
    outcome: str = "success",
) -> None:
    """Best-effort audit log. Mirrors ai_backends_crud._audit.

    Routes record_auth_event through the best-effort audit SSOT (census
    run17 #3). Audit failures are logged uniformly via ``safe_audit_write``
    (so /health's audit-failure drift check sees the miss) and never poison
    the user flow.
    """
    safe_audit_write(
        lambda: record_auth_event(
            db,
            event_type=event_type,
            email=user.get("email", "") or "",
            user_id=user.get("id"),
            outcome=outcome,
            detail=detail,
        ),
        description=f"embedding_install_audit event={event_type} outcome={outcome}",
    )


#: What a REFUSED removal shows the admin. Static text only: an exception string
#: reaching a template context is the N-179 leak class.
_REFUSED_NO_WITNESS = (
    "Nothing was removed: the audit record of this removal could not be "
    "written, and the runtime is never removed without one. Try again; if it "
    "keeps failing, the application log names the cause."
)
_REFUSED_IN_FLIGHT = (
    "Nothing was removed: an install is in progress. Cancel it, wait for it to "
    "stop, then remove."
)
_REFUSED_PROTECTED_TARGET = (
    "Nothing was removed: the runtime location could not be identified as the "
    "installed runtime, or it holds the database or the data volume, so it "
    "cannot be deleted from here."
)


def _redirect_to_tab() -> RedirectResponse:
    return RedirectResponse(
        "/config?tab=ai_backends", status_code=303,
    )


def build_install_card_context(
    install_state: dict, *, action_error: str = "",
) -> dict[str, Any]:
    """The install card's context — THE one builder, for every render site.

    Four sites render this partial (the AI-backends tab in ``admin.py``, the
    HTMX poll endpoint, and the post-action swaps) and each used to assemble the
    context itself, with ``is_runtime_ready()`` in it. Two consequences, both
    real defects (N-525 / punch 540):

    * ``is_runtime_ready()`` MUTATES ``sys.path`` — it called
      ``add_runtime_to_sys_path()``, which inserted the volume's site-packages
      at index 0 of the SERVING process for the rest of its life. So merely
      OPENING the AI-backends tab positioned volume code ahead of the image and
      the stdlib, whether or not the embedding feature was configured. A display
      surface must not do that. This builder uses
      :func:`runtime_importable_probe`, which searches the same directories via
      ``PathFinder`` and touches nothing.
    * The card said "Files verified against the pinned manifest baked into this
      image" in the installed state unconditionally. Nothing had verified
      anything of the kind: it was true of the STAGED WHEELS at install time and
      said nothing about the installed package set, which is precisely the claim
      an operator reads it as. The wording now follows
      :func:`runtime_marker_status` through ``install_verified``.

    Caller-supplied ``install_state`` because only the caller holds the DB
    connection; everything else here is a filesystem read. ``action_error`` is
    the STATIC message a refused action shows at the top of the card (never
    exception text); every other render passes nothing and gets "".
    """
    manifest_sha = install_state.get("manifest_sha256") or ""
    record = runtime_install_record()
    return {
        "install_state": install_state,
        "install_manifest_sha_short": (
            manifest_sha[:12] if manifest_sha else ""
        ),
        # Non-mutating: never positions volume code on the serving process's
        # import path (N-525).
        "install_runtime_ready": runtime_importable_probe(),
        "install_verified": record["verified"],
        "install_verify_reason": record["reason"],
        "install_runtime_present": record["present"],
        "install_image_manifest_sha_short": (
            record["image_manifest_sha256"][:12]
        ),
        "install_action_error": action_error,
        # Punch 569: the card names the state (stale_ok serves until updated)
        # and, after an update under loaded packages, the restart.
        "install_runtime_state": record["state"],
        "install_runtime_serving": record["serving"],
        "install_restart_pending": record["restart_pending"],
        "install_restart_message": RESTART_MESSAGE,
        # Panel B3 DA F569-2: said before the click (the notice SSOT's text).
        "install_update_pause_note": _update_pause_note(),
        # Operator decision 2026-10-25: with auto-update on, the card says the
        # app updates the runtime itself and shows no request-to-click.
        "install_auto_update": auto_update_enabled(),
        "install_auto_failure": auto_update_failure(),
        # hipaa-sme R3: an INTEGRITY refusal is never healed by the app, so the
        # card keeps the button (a human decides) and says why.
        "install_integrity_wait": bool(
            auto_update_enabled() and record["integrity_refusal"]
        ),
        # Punch 732: where pip --prefix puts the packages, derived from the
        # running interpreter (lib/python<maj>.<min>/site-packages), never a
        # literal version that goes stale on the next base-image bump.
        "install_site_packages": str(runtime_site_packages_candidates()[0]),
    }


async def _render_install_card(
    request: Request, *, action_error: str = "",
) -> HTMLResponse:
    """Return the install-card partial against the current DB state.

    Routes call this on the HTMX branch instead of ``_redirect_to_tab``
    so the user's click result swaps the card in-place. The polling
    attributes the template attaches when the state is in-flight
    keep the card live until a terminal state lands.

    / — ``get_install_status`` runs off the event loop.
    """
    db = get_db(request)
    templates = get_templates(request)
    install_state = await db_call(get_install_status, db)
    ctx: dict[str, Any] = {"request": request}
    ctx.update(build_install_card_context(install_state, action_error=action_error))
    return templates.TemplateResponse(
        request,
        "admin/config_tabs/_embedding_install_card.html",
        ctx,
    )


async def _post_response(
    request: Request, *, action_error: str = "", heading: str = "Removal refused",
) -> HTMLResponse | RedirectResponse:
    """Branch on HTMX vs plain POST.

    HTMX: return the install-card partial (current DB state), carrying
    ``action_error`` when the action was refused — a 200, because HTMX 1.x does
    not swap a 4xx/5xx body and the admin would see nothing happen.
    Plain: 303 to /config?tab=ai_backends (back-compat); a REFUSED plain POST
    gets a 503 error page instead, since that page renders no flash.
    """
    if _shared.is_htmx(request):
        return await _render_install_card(request, action_error=action_error)
    if action_error:
        return HTMLResponse(
            error_article(action_error, heading=heading),
            status_code=503,
        )
    return _redirect_to_tab()


def _manifest_path() -> Path:
    """Resolve the manifest path — thin alias over the domain-module SSOT.

    N-524 hoisted the resolver into ``embedding_bits.resolve_manifest_path``
    because the drift gate needs it there too, and three copies of "which
    manifest is this image's" is three chances for the gate to compare against a
    different file than the installer used. Kept as a local name so the existing
    call sites read unchanged.
    """
    return resolve_manifest_path()


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
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    def _install_db_work() -> bool:
        """/ — in-flight check + audit + status flip in one
        threadpool hop. Returns ``True`` when an install is already
        in flight (handler should bail without spawning a worker).
        """
        # Refuse to spawn if an install is already in flight. The
        # install_state row's status is the truth; we read it under the
        # request connection so the UI sees consistent state.
        state = get_install_status(db)
        if (
            state["status"] in ("downloading", "verifying", "installing")
            or update_in_progress()
        ):
            _audit(
                db, user,
                event_type="embedding_install_start",
                detail="rejected — install already in flight",
                outcome="failure",
            )
            return True

        _audit(
            db, user,
            event_type="embedding_install_start",
            detail="method=auto",
        )

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
        return False

    already_in_flight = await db_call(_install_db_work)
    if already_in_flight:
        return await _post_response(request)

    target_dir = get_runtime_deps_path()
    manifest_path = _manifest_path()

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

    #  — track the fire-and-forget task on app.state so it has a
    # strong reference until completion (asyncio only weak-refs tasks,
    # so a bare create_task can be gc-collected mid-run) and tests can
    # drain at teardown. Same canonical pattern as
    # ``access_audit.py:239-258``. ``set.discard`` is idempotent so the
    # done-callback is safe if the task completes between add and
    # discard.
    task = asyncio.create_task(_run())
    pending = getattr(request.app.state, "_fire_and_forget_pending", None)
    if pending is None:
        pending = set()
        request.app.state._fire_and_forget_pending = pending
    pending.add(task)
    task.add_done_callback(pending.discard)
    return await _post_response(request)


@router.post("/config/ai-backends/embedding-sideload", response_class=HTMLResponse)
async def embedding_sideload(request: Request):
    """Kick off the sideload install. Admin-only."""
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    form = await request.form()
    source_dir_raw = (form.get("source_dir") or "").strip()
    if not source_dir_raw:
        source_dir_raw = "/app/data/runtime-deps/sideload"
    source_dir = Path(source_dir_raw)

    if not source_dir.exists() or not source_dir.is_dir():
        def _sideload_notfound_db_work() -> None:
            """/ — failure-path audit + state write in one hop."""
            _audit(
                db, user,
                event_type="embedding_install_start",
                detail=(
                    f"method=sideload; source_dir not found: {source_dir_raw}"
                ),
                outcome="failure",
            )
            # Write the user-visible error to the install_state row so
            # the admin tab surfaces it on the next render.
            from email_triage.embedding_bits import _update_state
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

        await db_call(_sideload_notfound_db_work)
        return await _post_response(request)

    def _sideload_db_work() -> bool:
        """/ — in-flight check + audit + status flip in one
        threadpool hop. Returns ``True`` when an install is already
        in flight (handler should bail without spawning a worker).
        """
        state = get_install_status(db)
        if (
            state["status"] in ("downloading", "verifying", "installing")
            or update_in_progress()
        ):
            _audit(
                db, user,
                event_type="embedding_install_start",
                detail="rejected — install already in flight",
                outcome="failure",
            )
            return True

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
        return False

    already_in_flight = await db_call(_sideload_db_work)
    if already_in_flight:
        return await _post_response(request)

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

    #  — track on app.state (same canonical pattern as the auto-
    # install path above + ``access_audit.py:239``).
    task = asyncio.create_task(_run())
    pending = getattr(request.app.state, "_fire_and_forget_pending", None)
    if pending is None:
        pending = set()
        request.app.state._fire_and_forget_pending = pending
    pending.add(task)
    task.add_done_callback(pending.discard)
    return await _post_response(request)


@router.post(
    "/config/ai-backends/embedding-install-cancel",
    response_class=HTMLResponse,
)
async def embedding_install_cancel(request: Request):
    """Flip the cancel flag. Admin-only."""
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    request_cancel()
    await db_call(
        _audit, db, user,
        event_type="embedding_install_cancelled",
        detail="operator requested cancel",
    )
    return await _post_response(request)


@router.post(
    "/config/ai-backends/embedding-reverify",
    response_class=HTMLResponse,
)
async def embedding_reverify(request: Request):
    """Re-hash staged files against the manifest. No re-download."""
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    await db_call(
        _audit, db, user,
        event_type="embedding_install_reverify",
        detail="operator triggered re-verify",
    )

    target_dir = get_runtime_deps_path()
    manifest_path = _manifest_path()

    # Reverify is fast (just rehash; no download) — run inline so the
    # admin UI surfaces the result immediately. await-via-to_thread
    # so it doesn't block the event loop while hashing.
    #
    #  — reverify is intentionally NOT routed through db_call: it
    # spends the bulk of its time hashing files (CPU), and holding the
    # process-wide DB lock for that whole span would stall every other
    # DB caller. Its only DB touch is the inner ``_update_state``, which
    # is ``@db_write``-decorated and so acquires the lock for just the
    # UPDATE+commit.
    try:
        result = await asyncio.to_thread(
            reverify,
            conn=db,
            manifest_path=manifest_path,
            target_dir=target_dir,
        )
        if result.status == "failed":
            await db_call(
                _audit, db, user,
                event_type="embedding_install_reverify",
                detail=f"reverify failed: {result.error_class}",
                outcome="failure",
            )
    except Exception:  # noqa: BLE001
        _log.exception("embedding reverify raised")

    return await _post_response(request)


@router.post(
    "/config/ai-backends/embedding-update",
    response_class=HTMLResponse,
)
async def embedding_update(request: Request):
    """Replace the installed runtime with this image's set, atomically. Admin-only.

    Punch 569 D3: the ONE action behind the [Update embedding runtime] banner
    button and the card. The work is :func:`embedding_bits.update_runtime`
    (stage beside the live prefix, verify every hash, swap by rename,
    re-verify, roll back on failure); the old set keeps serving until the swap.

    Admin gate and CSRF like its siblings (the app-wide ``Csrf`` middleware
    enforces the token the form carries). Everything around that work (the
    witness-first INTENT row, the in-flight guard, the OUTCOME row, the release
    of the claimed row, the tombstone purge) lives in ONE place,
    :func:`email_triage.web.embedding_update_runner.start_runtime_update`, which
    the app's own automatic updater also calls (operator decision 2026-10-25):
    two callers, one funnel (PD-5, ``tests/test_autoupd_single_funnel_pin.py``).

    An optional ``source_dir`` form field sideloads (air-gapped installs); the
    banner button posts without it, which downloads.
    """
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    form = await request.form()
    source_dir_raw = (form.get("source_dir") or "").strip()
    source_dir = Path(source_dir_raw) if source_dir_raw else None
    refused = await start_runtime_update(
        request.app,
        actor=UpdateActor.from_user(user),
        source_dir=source_dir,
        manifest_path=_manifest_path(),
    )
    if refused:
        return await _post_response(
            request, action_error=refused, heading="Update refused",
        )
    return await _post_response(request)


@router.post(
    "/config/ai-backends/embedding-reindex/{account_id}",
    response_class=HTMLResponse,
)
async def embedding_reindex(request: Request, account_id: int):
    """Enqueue a reindex job for one account. Admin-only."""
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    if not is_runtime_ready():
        await db_call(
            _audit, db, user,
            event_type="embedding_reindex_enqueue",
            detail=f"account_id={account_id} rejected — runtime not ready",
            outcome="failure",
        )
        return RedirectResponse(
            "/config?tab=ai_backends&save_error="
            "Embedding+runtime+is+not+installed+yet",
            status_code=303,
        )

    #  — pin the LIVE target so a later model change can supersede this
    # manual reindex if it's still in-flight + stale. Read app.state on the
    # loop thread (cheap attribute access) before the threadpool hop.
    _app_state = request.app.state
    _eb = getattr(_app_state, "embedding_backend", None)
    live_target = {
        "backend_type": getattr(_eb, "backend_type", "") if _eb is not None else "",
        "model": getattr(_app_state, "embedding_model", "") or "",
    }

    def _reindex_db_work() -> str:
        """/ — enqueue (supersede-aware, ) + audit in one hop."""
        from email_triage.jobs.embedding_reindex import (
            supersede_or_enqueue_reindex,
        )
        outcome = supersede_or_enqueue_reindex(
            db, account_id=account_id, actor_user_id=user.get("id"),
            target=live_target,
        )
        _audit(
            db, user,
            event_type="embedding_reindex_enqueue",
            detail=f"account_id={account_id} outcome={outcome}",
        )
        return outcome

    await db_call(_reindex_db_work)
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
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)
    templates = get_templates(request)

    install_state = await db_call(get_install_status, db)
    ctx: dict[str, Any] = {"request": request}
    ctx.update(build_install_card_context(install_state))

    return templates.TemplateResponse(
        request,
        "admin/config_tabs/_embedding_install_card.html",
        ctx,
    )


@router.post(
    "/config/ai-backends/embedding-remove",
    response_class=HTMLResponse,
)
async def embedding_remove(request: Request):
    """Remove the runtime install — delete the prefix, reset the row. Admin-only.

    The admin half of the ONE removal funnel (N-526 / punch 541); the CLI
    ``embedding-bits remove`` is the other. Both call
    ``embedding_bits.remove_install``, which does the delete and the row reset in
    one step, so neither can do half of it.

    Admin gate and CSRF like its siblings (the template emits ``csrf_input``;
    the app-wide ``Csrf`` middleware enforces it). The audit shape is the CLI's
    witness-first one (N-543, punch 539 fold-check): an INTENT row through
    ``record_auth_event`` is written and committed BEFORE the delete, and the
    removal is REFUSED, with a visible message on the card, if that write
    fails; then a best-effort OUTCOME row. Both go through the audit-emitter
    SSOT, never a raw INSERT, which would fork the HMAC chain (PD-3). Before the
    fold-check this route wrote its only row AFTER the delete and the
    self-committing row reset, best-effort.

    Removing is NOT destructive of PHI or configuration: it deletes downloaded
    third-party packages and model weights that a re-install reproduces from the
    pinned manifest. It does not touch the embedding config, so a re-install is
    the inverse operation.
    """
    user, err = await db_call(_require_admin, request)
    if err is not None:
        return err
    db = get_db(request)

    def _remove_db_work() -> dict:
        # N-543: the INTENT row first. ``record_auth_event`` commits it itself, so
        # it is durable before anything irreversible happens. This is the CLI
        # half's N-157 shape (``cli.py`` ``_emit_cli_audit_event``: the
        # ``safe_audit_write`` result is None -> refuse): the failure is logged
        # and counted for /health's audit-failure drift check, and the removal
        # does NOT go ahead. The ``True`` sentinel keeps a falsy row id from
        # reading as a failure.
        witnessed = safe_audit_write(
            lambda: (record_auth_event(
                db,
                event_type="embedding_install_remove",
                email=user.get("email", "") or "",
                user_id=user.get("id"),
                outcome="attempt",
                detail="remove requested",
            ), True)[1],
            description="embedding_install_audit event=embedding_install_remove outcome=attempt",
        )
        if witnessed is None:
            return {"refused": _REFUSED_NO_WITNESS}
        try:
            summary = remove_install(conn=db)
        except RemoveInFlight as exc:
            _audit(
                db, user,
                event_type="embedding_install_remove",
                detail=f"rejected — {scrub_error_for_persist(exc)}",
                outcome="failure",
            )
            return {"refused": _REFUSED_IN_FLIGHT}
        except RemoveTargetRefused as exc:
            _audit(
                db, user,
                event_type="embedding_install_remove",
                detail=f"rejected — {scrub_error_for_persist(exc)}",
                outcome="failure",
            )
            return {"refused": _REFUSED_PROTECTED_TARGET}
        except Exception as exc:
            # The intent row is already durable; record how it ended, best
            # effort, then let the error surface (the CLI's phase='end' shape).
            _audit(
                db, user,
                event_type="embedding_install_remove",
                detail=f"error — {scrub_error_for_persist(exc)}",
                outcome="failure",
            )
            raise
        # The OUTCOME row. Best-effort is correct here and only here: the intent
        # row already names who removed what, so a lost outcome row leaves an
        # attempt with no result (detectable), not an unrecorded deletion.
        _audit(
            db, user,
            event_type="embedding_install_remove",
            detail=(
                f"removed={summary['removed']} "
                f"residual_tree={summary['residual_tree']} "
                f"tombstone={summary['tombstone'] or 'none'} "
                f"sys_path_entries={len(summary['sys_path_entries'])} "
                f"restart_required={summary['restart_required']}"
            ),
            # A partial delete is not a success: the row is reset either way, but
            # packages remain on the volume, so the audit trail must not record
            # this as a clean removal.
            outcome="success" if not summary["residual_tree"] else "failure",
        )
        db.commit()
        return summary

    # Serialised on the process-wide DB lock like every other install action: the
    # rmtree and the row reset must not interleave with an installer worker.
    summary = await db_call(_remove_db_work)
    refused = summary.get("refused") or ""
    if refused:
        _log.warning(
            "embedding remove refused",
            extra={"_extra": {"reason": refused}},
        )
    else:
        # The writer work is done; the bytes go now, off the writer (N-543).
        schedule_tombstone_purge(request.app)
    return await _post_response(request, action_error=refused)
