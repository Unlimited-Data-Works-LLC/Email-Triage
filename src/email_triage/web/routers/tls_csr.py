"""Make-CSR / sign / import-cert admin surface (#74).

Routes:

* GET  ``/admin/tls/csr``               render state-aware page
* POST ``/admin/tls/csr/make``          generate keypair + CSR (downloads CSR)
* POST ``/admin/tls/csr/download``      re-download the pending CSR
* POST ``/admin/tls/csr/cancel``        clear pending key + CSR
* POST ``/admin/tls/csr/import``        validate + atomically swap in CA-signed cert
* POST ``/admin/tls/csr/self-sign``     generate self-signed cert immediately

All admin-only. Audit row via ``record_auth_event`` on every write
path so the operator-facing trail captures who did what when. Hot-
reload watcher (cli.py:_watch_cert_thread) picks up swaps within
30s without a service restart.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from email_triage import tls_csr
from email_triage.web.dependencies import get_current_user

log = logging.getLogger("email_triage.web.routers.tls_csr")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


def _get_config(request: Request):
    return request.app.state.config


def _get_templates(request: Request):
    return request.app.state.templates


def _render(request: Request, name: str, ctx: dict[str, Any] | None = None):
    from email_triage.web.routers.ui import _render as _render_ui
    return _render_ui(_get_templates(request), request, name, ctx or {})


def _require_admin(request: Request):
    user = get_current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return None, HTMLResponse("Forbidden", status_code=403)
    return user, None


def _resolve_cert_dir(config) -> Path:
    """Same convention as the rest of the codebase: explicit
    ``tls.cert_dir`` if set, else ``<data_dir>/certs``."""
    cd = getattr(getattr(config, "tls", None), "cert_dir", "")
    if cd:
        return Path(cd)
    db_path = getattr(getattr(config, "persistence", None), "db_path", "")
    if db_path:
        return Path(db_path).parent / "certs"
    return Path("./data/certs")


def _audit(
    db: sqlite3.Connection,
    *,
    event_type: str,
    email: str,
    outcome: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        from email_triage.web.db import record_auth_event
        detail = json.dumps(metadata or {}, separators=(",", ":"))
        record_auth_event(
            db,
            event_type=event_type,
            email=email,
            outcome=outcome,
            detail=detail,
        )
    except Exception as e:
        log.warning("TLS-CSR audit write failed: %s", e)


def _qstr(s: str) -> str:
    """Cheap query-string escape. We only ever pass short
    operator-facing strings; full urllib.parse.quote_plus would be
    fine but adds a micro-import for no real win."""
    return s.replace("&", "%26").replace(" ", "+").replace("=", "%3D")


# ---------------------------------------------------------------------------
# Page render
# ---------------------------------------------------------------------------

@router.get("/admin/tls/csr", response_class=HTMLResponse)
async def admin_tls_csr_page(request: Request):
    """Render the state-aware page. Three states:

    * ``idle``    -- no active cert, no pending CSR. Show Make-CSR
                     form + Self-sign button.
    * ``pending`` -- pending key + CSR on disk. Show CSR re-download
                     + paste-cert form + Cancel button.
    * ``active``  -- active server.crt + server.key. Show metadata
                     (subject, issuer, expiry days) + "Make new CSR"
                     to start a rotation.
    """
    user, err = _require_admin(request)
    if err:
        return err

    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)
    state = tls_csr.detect_state(cert_dir)
    active_md = tls_csr.active_cert_metadata(cert_dir) if state == tls_csr.STATE_ACTIVE else None

    return _render(request, "admin/tls_csr.html", {
        "user": user,
        "state": state,
        "cert_dir": str(cert_dir),
        "active_cert": active_md,
        "saved": request.query_params.get("saved") == "1",
        "error": request.query_params.get("err") or "",
    })


# ---------------------------------------------------------------------------
# Make CSR
# ---------------------------------------------------------------------------

@router.post("/admin/tls/csr/make", response_class=Response)
async def admin_tls_csr_make(
    request: Request,
    hostname: str = Form(...),
    extra_sans: str = Form(""),
    organization: str = Form("email-triage"),
):
    """Generate keypair + CSR. Returns the CSR as a download
    (operator's CA wants the PEM). Pending key stays on disk under
    server.key.pending until import or cancel."""
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)

    sans_list = [s.strip() for s in extra_sans.split(",") if s.strip()]
    try:
        _key, _csr_path, csr_pem = tls_csr.make_csr(
            cert_dir,
            hostname=hostname.strip(),
            extra_sans=sans_list,
            organization=organization.strip() or "email-triage",
        )
    except tls_csr.CsrAlreadyPendingError as e:
        _audit(
            db,
            event_type="tls_csr_make",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "already_pending"},
        )
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )
    except ValueError as e:
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )
    except Exception as e:
        log.error("CSR generation failed: %s", e, exc_info=e)
        _audit(
            db,
            event_type="tls_csr_make",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"error": type(e).__name__},
        )
        return RedirectResponse(
            "/admin/tls/csr?err=CSR+generation+failed%3B+see+logs",
            status_code=303,
        )

    _audit(
        db,
        event_type="tls_csr_make",
        email=user.get("email", ""),
        outcome="success",
        metadata={
            "hostname": hostname.strip(),
            "extra_sans": sans_list,
            "csr_bytes": len(csr_pem),
        },
    )

    safe_host = "".join(
        c if c.isalnum() or c in (".-_") else "_"
        for c in hostname.strip()
    ) or "host"
    fname = f"{safe_host}.csr"
    return Response(
        content=csr_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Re-download pending CSR
# ---------------------------------------------------------------------------

@router.post("/admin/tls/csr/download", response_class=Response)
async def admin_tls_csr_download(request: Request):
    """Re-download the pending CSR. Useful if the operator lost the
    initial download or needs to send the same CSR to a second CA."""
    user, err = _require_admin(request)
    if err:
        return err

    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)
    try:
        csr_pem = tls_csr.read_pending_csr(cert_dir)
    except tls_csr.NoPendingCsrError as e:
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )

    return Response(
        content=csr_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="server.csr"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Cancel pending
# ---------------------------------------------------------------------------

@router.post("/admin/tls/csr/cancel", response_class=HTMLResponse)
async def admin_tls_csr_cancel(request: Request):
    """Discard the pending key + CSR. Operator's call -- if they've
    already submitted to a CA, the CSR they have is now orphaned
    (the held private key is gone, so the eventual signed cert can't
    be paired with it). Show a confirmation step in the UI."""
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)
    tls_csr.cancel_pending(cert_dir)
    _audit(
        db,
        event_type="tls_csr_cancel",
        email=user.get("email", ""),
        outcome="success",
        metadata={},
    )
    return RedirectResponse(
        "/admin/tls/csr?saved=1",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Import signed cert
# ---------------------------------------------------------------------------

@router.post("/admin/tls/csr/import", response_class=HTMLResponse)
async def admin_tls_csr_import(
    request: Request,
    cert_pem: str = Form(""),
    cert_file: UploadFile | None = None,  # type: ignore[assignment]
):
    """Validate + import the CA-signed cert. Accepts either pasted
    PEM (form field) or an uploaded ``.pem`` file. The pasted path
    is the common case for ops who get the cert as text.

    On success: pending key promotes to server.key, cert PEM lands at
    server.crt, server.csr is removed, hot-reload watcher picks it up
    within 30s.
    """
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)

    # Resolve cert bytes from either form field or upload.
    raw: bytes
    if cert_file is not None and getattr(cert_file, "filename", ""):
        try:
            raw = await cert_file.read()
        except Exception as e:
            return RedirectResponse(
                f"/admin/tls/csr?err={_qstr(f'Upload read failed: {e}')}",
                status_code=303,
            )
    else:
        raw = (cert_pem or "").strip().encode("utf-8")

    if not raw:
        return RedirectResponse(
            "/admin/tls/csr?err=No+PEM+provided",
            status_code=303,
        )

    try:
        crt_path, key_path = tls_csr.import_signed_cert(cert_dir, raw)
    except tls_csr.NoPendingCsrError as e:
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )
    except tls_csr.InvalidPemError as e:
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )
    except tls_csr.KeyMismatchError as e:
        _audit(
            db,
            event_type="tls_csr_import",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "key_mismatch"},
        )
        return RedirectResponse(
            f"/admin/tls/csr?err={_qstr(str(e))}",
            status_code=303,
        )
    except Exception as e:
        log.error("Cert import failed: %s", e, exc_info=e)
        _audit(
            db,
            event_type="tls_csr_import",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"error": type(e).__name__},
        )
        return RedirectResponse(
            "/admin/tls/csr?err=Import+failed%3B+see+logs",
            status_code=303,
        )

    _audit(
        db,
        event_type="tls_csr_import",
        email=user.get("email", ""),
        outcome="success",
        metadata={
            "cert_bytes": len(raw),
            "cert_path": str(crt_path),
            "key_path": str(key_path),
        },
    )

    return RedirectResponse(
        "/admin/tls/csr?saved=1",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Self-sign shortcut
# ---------------------------------------------------------------------------

@router.post("/admin/tls/csr/self-sign", response_class=HTMLResponse)
async def admin_tls_csr_self_sign(
    request: Request,
    hostname: str = Form(...),
    extra_sans: str = Form(""),
    valid_days: str = Form("365"),
):
    """Generate a self-signed cert + key and drop directly into
    cert_dir. Skips CSR + CA import.

    Use case: bring up a working TLS listener for browser pinning /
    WebAuthn testing before issuing a real institutional cert. The
    operator accepts the browser warning while the CA-signed cert is
    in flight; later, generates a CSR + imports the real cert which
    overwrites the self-signed.
    """
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)
    cert_dir = _resolve_cert_dir(config)

    sans_list = [s.strip() for s in extra_sans.split(",") if s.strip()]
    try:
        days = int(valid_days)
    except (TypeError, ValueError):
        days = 365
    if days < 1:
        days = 365

    try:
        crt_path, key_path = tls_csr.self_sign_now(
            cert_dir,
            hostname=hostname.strip(),
            extra_sans=sans_list,
            valid_days=days,
        )
    except Exception as e:
        log.error("Self-sign failed: %s", e, exc_info=e)
        _audit(
            db,
            event_type="tls_csr_self_sign",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"error": type(e).__name__},
        )
        return RedirectResponse(
            "/admin/tls/csr?err=Self-sign+failed%3B+see+logs",
            status_code=303,
        )

    _audit(
        db,
        event_type="tls_csr_self_sign",
        email=user.get("email", ""),
        outcome="success",
        metadata={
            "hostname": hostname.strip(),
            "extra_sans": sans_list,
            "valid_days": days,
        },
    )

    return RedirectResponse(
        "/admin/tls/csr?saved=1",
        status_code=303,
    )
