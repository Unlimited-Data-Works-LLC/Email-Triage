"""Admin-driven backup export (punch-list #65).

Two POST routes that produce encrypted bundle downloads + a GET that
renders the form. Both routes:

* Are admin-only.
* Validate passphrase length + match.
* Call into the pure ``email_triage.backup`` module so the CLI restore
  side stays in lockstep.
* Write an audit row via ``record_auth_event`` so the operator-facing
  trail captures who exported what when.

Restore is CLI-only (``email-triage restore <bundle>``); attempting
to drop a bundle into a running install is foot-shooty (open WAL,
in-flight writes). The recommended pattern is documented in the
operator runbook.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from email_triage import backup as backup_mod
from email_triage._errfmt import fmt_exc
from email_triage.web.dependencies import get_current_user

log = logging.getLogger("email_triage.web.routers.backup")
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


def _resolve_config_path(config) -> Path:
    """Find the YAML the running install was loaded from. Mirrors
    ``_write_config_yaml`` in ui.py + ``load_config``'s search
    order. Returns the first match; falls back to the canonical
    container path if nothing's found (so bundles still build on
    fresh installs that haven't saved a YAML).
    """
    candidates = [
        Path("./email-triage.yaml"),
        Path("./config/email-triage.yaml"),
        Path.home() / ".config" / "email-triage" / "config.yaml",
    ]
    for p in candidates:
        if p.exists():
            return p
    # Fallback: write a temp YAML so build_full_bundle has something
    # to bundle. Pure-Python module requires the path to exist.
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="et-config-fallback-", suffix=".yaml")
    import os as _os
    _os.close(fd)
    Path(tmp).write_text(
        "# Fallback YAML (no config file found at export time).\n",
        encoding="utf-8",
    )
    return Path(tmp)


def _resolve_data_dir(config) -> Path:
    """Best-effort data-dir resolution. ``persistence.db_path`` is the
    canonical anchor; data files (msal_cache, certs) sit alongside."""
    db_path = getattr(getattr(config, "persistence", None), "db_path", "")
    if db_path:
        return Path(db_path).parent
    # Fallback to the conventional ./data
    return Path("./data")


def _resolve_cert_dir(config) -> Path | None:
    cd = getattr(getattr(config, "tls", None), "cert_dir", "")
    if cd:
        return Path(cd)
    # Convention: <data_dir>/certs
    dd = _resolve_data_dir(config)
    candidate = dd / "certs"
    return candidate if candidate.is_dir() else None


def _make_bootstrap_provider(config):
    """Construct a fresh bootstrap secrets provider from config.
    The runtime ``app.state.secrets`` is a ``DbSecrets`` wrapper
    that doesn't expose the master key directly; bootstrap is the
    layer that knows how to read it.
    """
    from email_triage.secrets import create_secrets_provider
    return create_secrets_provider(
        backend=config.secrets.backend,
        keyfile_path=config.secrets.keyfile_path,
        external_config=config.secrets.external,
    )


def _audit_event(
    db: sqlite3.Connection,
    *,
    event_type: str,
    email: str,
    outcome: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Write an entry to ``auth_events`` for the export. Metadata
    JSON-encoded into the ``detail`` column. Failure to record is
    logged but never fails the download -- audit gap is less bad
    than denying a working backup.
    """
    try:
        import json
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
        log.warning(
            "Backup audit write failed",
            extra={"_extra": {
                "event_type": event_type,
                "outcome": outcome,
                "error": fmt_exc(e),
            }},
        )


def _filename(config, kind: str, ext: str) -> str:
    """Build the download filename from hostname + kind + ISO date.
    No internal-infra leakage; hostname is the install's own."""
    import socket
    host = ""
    try:
        host = (socket.gethostname() or "").split(".")[0]
    except Exception:
        host = ""
    if not host:
        host = "host"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"email-triage-{kind}-{host}-{ts}.{ext}"


# ---------------------------------------------------------------------------
# Page render
# ---------------------------------------------------------------------------

@router.get("/admin/backup", response_class=HTMLResponse)
async def admin_backup_legacy(request: Request):
    """Legacy URL — Backup is now a tab on /config.

    303-redirect preserves bookmarks + log links. Forwards any
    error query so the user-visible flash survives the bounce.
    Auth gate runs FIRST so anonymous users still bounce to /login
    and non-admin users still get 403 — preserves the pre-refactor
    contract that ``follow_redirects=False`` tests pin against.
    """
    user, err = _require_admin(request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=backup{tail}", status_code=303,
    )


def build_backup_context(request: Request) -> dict:
    """Build the context dict the Backup tab body needs.

    Trivial today (just an error flash forwarded from the export
    handlers' redirect targets) but kept as a named helper to match
    the per-tab build_*_context shape the /config dispatch table
    expects.
    """
    return {
        "saved": False,
        "error": request.query_params.get("err") or "",
    }


# ---------------------------------------------------------------------------
# Full-bundle export
# ---------------------------------------------------------------------------

@router.post("/admin/backup/export-full", response_class=Response)
async def admin_backup_export_full(
    request: Request,
    passphrase: str = Form(...),
    passphrase_confirm: str = Form(...),
    include_master_key: str = Form(""),
    include_tls_certs: str = Form(""),
    include_logs: str = Form(""),
):
    """Build + stream a full backup bundle. Form fields are
    URL-encoded; checkboxes carry "1" when checked, "" when not."""
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)

    # Validation. Mismatch + length are both 303-redirect-with-err
    # so the form re-renders on the same page.
    if passphrase != passphrase_confirm:
        return RedirectResponse(
            "/admin/backup?err=Passphrases+did+not+match",
            status_code=303,
        )

    inc_key = include_master_key in ("1", "on", "true")
    inc_certs = include_tls_certs in ("1", "on", "true")
    inc_logs = include_logs in ("1", "on", "true")

    try:
        bundle = backup_mod.build_full_bundle(
            db_conn=db,
            config_path=_resolve_config_path(config),
            data_dir=_resolve_data_dir(config),
            cert_dir=_resolve_cert_dir(config),
            secrets_provider=_make_bootstrap_provider(config),
            master_key_name=config.secrets.master_key_name,
            passphrase=passphrase,
            include_master_key=inc_key,
            include_tls_certs=inc_certs,
            include_logs=inc_logs,
            operator_email=user.get("email", ""),
            commit_sha=getattr(request.app.state, "version", "")[:12],
            hostname=_filename(config, "x", "x").split("-")[2],
            schema_version=int(
                getattr(request.app.state, "schema_version", 1) or 1,
            ),
        )
    except backup_mod.WeakPassphraseError as e:
        _audit_event(
            db,
            event_type="backup_export_full",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "weak_passphrase"},
        )
        return RedirectResponse(
            f"/admin/backup?err={fmt_exc(e).replace(' ', '+')}",
            status_code=303,
        )
    except Exception as e:
        log.error(
            "Full bundle build failed",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )
        _audit_event(
            db,
            event_type="backup_export_full",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"error": type(e).__name__},
        )
        return RedirectResponse(
            "/admin/backup?err=Build+failed%3B+see+logs",
            status_code=303,
        )

    _audit_event(
        db,
        event_type="backup_export_full",
        email=user.get("email", ""),
        outcome="success",
        metadata={
            "bytes": len(bundle),
            "include_master_key": inc_key,
            "include_tls_certs": inc_certs,
            "include_logs": inc_logs,
        },
    )

    # CR-2b hook: a successful encrypted backup supersedes the
    # internal pre-upgrade rollback safety net. Delete older
    # ``triage.db.preupgrade-*`` files; keep the most recent in
    # case the operator runs export-then-undo. Never blocks the
    # download.
    try:
        from email_triage.backup_snapshot_cleanup import (
            cleanup_after_successful_backup,
        )
        cleanup_after_successful_backup(_resolve_data_dir(config))
    except Exception as e:
        log.warning(
            "preupgrade snapshot cleanup failed (non-fatal)",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )

    fname = _filename(config, "export", "etbk")
    return Response(
        content=bundle,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Key-only export
# ---------------------------------------------------------------------------

@router.post("/admin/backup/export-key", response_class=Response)
async def admin_backup_export_key(
    request: Request,
    passphrase: str = Form(...),
    passphrase_confirm: str = Form(...),
):
    """Build + stream a key-only bundle. Tiny payload (~hundred bytes
    encrypted). Operator stores this separately from the full bundle
    so an attacker who gets one bundle can't decrypt the install."""
    user, err = _require_admin(request)
    if err:
        return err

    db = _get_db(request)
    config = _get_config(request)

    if passphrase != passphrase_confirm:
        return RedirectResponse(
            "/admin/backup?err=Passphrases+did+not+match",
            status_code=303,
        )

    try:
        bundle = backup_mod.build_key_only_bundle(
            secrets_provider=_make_bootstrap_provider(config),
            master_key_name=config.secrets.master_key_name,
            passphrase=passphrase,
            operator_email=user.get("email", ""),
            hostname=_filename(config, "x", "x").split("-")[2],
        )
    except backup_mod.WeakPassphraseError as e:
        _audit_event(
            db,
            event_type="backup_export_key",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "weak_passphrase"},
        )
        return RedirectResponse(
            f"/admin/backup?err={fmt_exc(e).replace(' ', '+')}",
            status_code=303,
        )
    except Exception as e:
        log.error(
            "Key-only bundle build failed",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )
        _audit_event(
            db,
            event_type="backup_export_key",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"error": type(e).__name__},
        )
        return RedirectResponse(
            "/admin/backup?err=Build+failed%3B+see+logs",
            status_code=303,
        )

    _audit_event(
        db,
        event_type="backup_export_key",
        email=user.get("email", ""),
        outcome="success",
        metadata={"bytes": len(bundle)},
    )

    fname = _filename(config, "key", "etbkkey")
    return Response(
        content=bundle,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Cache-Control": "no-store",
        },
    )
