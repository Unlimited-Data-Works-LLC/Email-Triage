"""Admin-driven backup export (the backlog ).

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
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)

from email_triage import backup as backup_mod
from email_triage._envbool import parse_bool
from email_triage._errfmt import fmt_exc
from email_triage.web._audit import safe_audit_write_async
from email_triage.web.db_threadpool import db_call
from email_triage.web._flash import flash_redirect  # N-179 R20_1 sub-1
from email_triage.web.routers._redirect import err_qs, read_flash

from email_triage.triage_logging import get_logger  # N-196b R21_4
log = get_logger("email_triage.web.routers.backup")  # N-196b R21_4
router = APIRouter()

# Strong refs to fire-and-queue backup tasks so the event loop's weak ref can't
# let one be GC'd mid-run. Discarded on done.
_BACKUP_BG_TASKS: set = set()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db(request: Request) -> sqlite3.Connection:
    return request.app.state.db


def _get_config(request: Request):
    return request.app.state.config


def _get_templates(request: Request):
    return request.app.state.templates


async def _render(request: Request, name: str, ctx: dict[str, Any] | None = None):
    """ / Option B — async wrapper delegating to the shared async
    ``_render``; callers ``await`` it."""
    from email_triage.web.routers.ui import _render as _render_ui
    return await _render_ui(_get_templates(request), request, name, ctx or {})


# Census 2026-06-09 #3: byte-identical UI admin gate → the dependencies SSOT.
from email_triage.web.dependencies import request_meta  # N-187 R20_12 authz SSOT
from email_triage.web.dependencies import require_admin_ui as _require_admin


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
        master_key_name=config.secrets.master_key_name,
    )


async def _audit_event(
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

    ASYNC-DB: the write runs off the event loop. Every caller is
    an ``async def`` handler, so this stays awaitable.
    """
    try:
        import json
        from email_triage.web.db import record_auth_event
        detail = json.dumps(metadata or {}, separators=(",", ":"))
        await safe_audit_write_async(
            lambda: db_call(
                record_auth_event,
                db,
                event_type=event_type,
                email=email,
                outcome=outcome,
                detail=detail,
            ),
            description=f"backup_audit event_type={event_type} outcome={outcome}",
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
    user, err = await db_call(_require_admin, request)
    if err:
        return err
    qs = request.url.query
    tail = ("&" + qs) if qs else ""
    return RedirectResponse(
        f"/config?tab=backup{tail}", status_code=303,
    )


def build_backup_context(request: Request) -> dict:
    """Build the context dict the Backup tab body needs.

    Carries the export error flash AND (since ) the current
    ``config.backup`` values so the Automated-backup config form
    pre-fills the operator's saved settings instead of blank
    defaults. ``public_key`` is an X25519 PUBLIC key (write-only
    seal target), safe to render. ``backup_dir_effective`` shows the
    resolved on-disk output dir (``backup.dir`` override, else
    ``<data_dir>/backups``) so the operator sees exactly where bundles
    land — the dir the host-side SMB relocation reads.
    """
    config = _get_config(request)
    bk = getattr(config, "backup", None)
    # Effective output dir (mirrors background_sweepers._backup_out_dir
    # without importing it — that module lazily imports THIS router).
    eff_dir = getattr(bk, "dir", "") or ""
    if not eff_dir:
        db_path = getattr(
            getattr(config, "persistence", None), "db_path", "",
        )
        base = Path(db_path).parent if db_path else Path("./data")
        eff_dir = str(base / "backups")
    return {
        "saved": bool(request.query_params.get("saved")),
        "error": read_flash(request)[1] or "",
        "backup_save_msg": request.query_params.get("save_msg") or "",
        "backup_save_error": request.query_params.get("save_error") or "",
        "backup_enabled": bool(getattr(bk, "enabled", False)),
        "backup_cadence": getattr(bk, "cadence", "manual") or "manual",
        "backup_format": getattr(bk, "format", "etbk") or "etbk",
        "backup_retention": str(getattr(bk, "retention", "14") or "14"),
        "backup_encryption": getattr(bk, "encryption", "master-key")
        or "master-key",
        "backup_public_key": getattr(bk, "public_key", "") or "",
        "backup_dir": getattr(bk, "dir", "") or "",
        "backup_dir_effective": eff_dir,
    }


# ---------------------------------------------------------------------------
# Automated-backup config save
# ---------------------------------------------------------------------------

_CADENCE_CHOICES = ("manual", "daily", "weekly")
_FORMAT_CHOICES = ("etbk", "db")
_ENCRYPTION_CHOICES = ("master-key", "public-key")


@router.post("/admin/backup/config-save", response_class=HTMLResponse)
async def admin_backup_config_save(
    request: Request,
    enabled: str = Form(""),
    cadence: str = Form("manual"),
    format: str = Form("etbk"),
    retention: str = Form("14"),
    encryption: str = Form("master-key"),
    public_key: str = Form(""),
    dir: str = Form(""),
):
    """Persist the ``backup:`` config section from the Admin → Backup form.

    The CONFIG path.
    Mutates ``config.backup.*`` and persists via the shared ``_write_config_yaml``
    SSOT (which now round-trips the ``backup:`` block) TRANSACTIONALLY — if the
    YAML write fails the in-memory mutation is rolled back, so the live sweeper
    (which reads ``config.backup`` each tick) and the on-disk config can never
    split-brain. On success the in-memory mutation is what the next sweep/trigger
    uses; no restart required.

    FAIL-CLOSED validation (reject → re-render with an error, never persist a
    half-armed config):
      * ``encryption=public-key`` REQUIRES a parseable X25519 ``public_key`` —
        a bad/empty/wrong-type key is rejected HERE so every later unattended
        backup can't silently FAIL on seal.
      * ``retention`` must parse (``N`` count | ``Nd`` days | ``Nw`` weeks).
      * ``cadence`` / ``format`` / ``encryption`` must be known enums.
    """
    from email_triage.web.dependencies import require_admin_ui
    user, err = await db_call(require_admin_ui, request)
    if err:
        return err

    config = _get_config(request)

    enabled_b = parse_bool(enabled)
    cadence_v = (cadence or "manual").strip().lower()
    format_v = (format or "etbk").strip().lower()
    encryption_v = (encryption or "master-key").strip().lower()
    retention_v = (retention or "14").strip()
    public_key_v = (public_key or "").strip()
    dir_v = (dir or "").strip()

    def _reject(msg: str):
        from urllib.parse import quote
        return RedirectResponse(
            f"/config?tab=backup&save_error={quote(msg)}",
            status_code=303,
        )

    if cadence_v not in _CADENCE_CHOICES:
        return _reject(f"Unknown cadence '{cadence_v}'.")
    if format_v not in _FORMAT_CHOICES:
        return _reject(f"Unknown format '{format_v}'.")
    if encryption_v not in _ENCRYPTION_CHOICES:
        return _reject(f"Unknown encryption mode '{encryption_v}'.")

    # Retention must parse — reject a typo rather than persist a spec the
    # pruner will choke on at run time.
    try:
        backup_mod.parse_retention_spec(retention_v)
    except Exception:
        return _reject(
            f"Retention '{retention_v}' is not valid "
            "(use N, Nd for days, or Nw for weeks).",
        )

    # FAIL-CLOSED (devils-advocate FATAL-1): public-key mode + the raw ``db``
    # snapshot is a silent fail-OPEN — the off-box seal is applied ONLY by the
    # etbk bundle path, so a db snapshot under "public-key" would be readable
    # with the on-box master key, voiding the very guarantee the mode promises.
    # Refuse the combo at config time (mirrored at the run actuator in
    # run_backup_once so a hand-edited YAML can't arm it either).
    if encryption_v == "public-key" and format_v != "etbk":
        return _reject(
            "Public-key mode requires the full bundle (.etbk) format — the "
            "raw database snapshot has no off-box seal layer.",
        )

    # Public-key mode is unrecoverable-on-bad-key: resolve + validate the PEM
    # HERE (via the SAME shared seam the run-time consumer uses), fail-closed,
    # so the operator can't arm public-key backups against a key that every
    # unattended run would then FAIL to seal to.
    if encryption_v == "public-key":
        if not public_key_v:
            return _reject(
                "Public-key mode requires an X25519 public key "
                "(paste the PEM, or a path to it).",
            )
        try:
            pem_bytes = backup_mod.resolve_public_key_pem(public_key_v)
            backup_mod.validate_public_key_pem(pem_bytes)
        except backup_mod.BackupError as e:
            return _reject(f"Public key rejected: {fmt_exc(e)}")
        except Exception as e:  # noqa: BLE001
            return _reject(f"Public key could not be read: {fmt_exc(e)}")

    # All validated — persist TRANSACTIONALLY (devils-advocate FATAL-2). The
    # live cadence sweeper reads ``app.state.config.backup`` each tick, so a
    # mutate-then-failed-write would split-brain: the operator sees an error,
    # assumes nothing changed, yet the running sweeper already flipped. Snapshot
    # the prior values, mutate, attempt the write, and ROLL BACK on failure so
    # in-memory and on-disk always agree (both old on failure, both new on
    # success).
    bk = config.backup
    _prior = (bk.enabled, bk.cadence, bk.format, bk.retention,
              bk.encryption, bk.public_key, bk.dir)
    bk.enabled = enabled_b
    bk.cadence = cadence_v
    bk.format = format_v
    bk.retention = retention_v
    bk.encryption = encryption_v
    bk.public_key = public_key_v
    bk.dir = dir_v

    from email_triage.web.routers.ui._shared import _write_config_yaml
    try:
        _write_config_yaml(config)
    except Exception as e:
        (bk.enabled, bk.cadence, bk.format, bk.retention,
         bk.encryption, bk.public_key, bk.dir) = _prior  # roll back — no split-brain
        log.error(
            "backup config YAML write failed",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )
        return _reject(f"YAML write failed: {fmt_exc(e)}")

    await _audit_event(
        _get_db(request),
        event_type="backup_config_save",
        email=user.get("email", ""),
        outcome="success",
        metadata={
            "enabled": enabled_b,
            "cadence": cadence_v,
            "format": format_v,
            "encryption": encryption_v,
            "retention": retention_v,
            "has_public_key": bool(public_key_v),
        },
    )

    return RedirectResponse(
        "/config?tab=backup&save_msg=Automated+backup+settings+saved",
        status_code=303,
    )


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
    user, err = await db_call(_require_admin, request)
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

    inc_key = parse_bool(include_master_key)
    inc_certs = parse_bool(include_tls_certs)
    inc_logs = parse_bool(include_logs)

    try:
        # ASYNC-DB: the bundle build calls
        # ``sqlite3.Connection.backup()`` on the shared connection —
        # a blocking, page-by-page snapshot. Dispatching the whole
        # build through ``db_call`` runs it off the event loop AND
        # under the / lock, so a concurrent request can't
        # collide on the shared connection mid-snapshot.
        # Real DB schema version for the manifest. `app.state.schema_version` is
        # never populated, so the old getattr default wrote schema 1 into every
        # bundle regardless of the real value. Read it the way daily_health does
        # (encryption-aware). Same fix applied to the automated run_backup_once.
        from email_triage.version import read_db_schema_version
        schema_v = await db_call(
            read_db_schema_version, config.persistence.db_path,
        )
        bundle = await db_call(
            backup_mod.build_full_bundle,
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
            schema_version=schema_v,
        )
    except backup_mod.WeakPassphraseError as e:
        await _audit_event(
            db,
            event_type="backup_export_full",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "weak_passphrase"},
        )
        return flash_redirect("/admin/backup", err=e, purpose="form")
    except Exception as e:
        log.error(
            "Full bundle build failed",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )
        await _audit_event(
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

    await _audit_event(
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
    user, err = await db_call(_require_admin, request)
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
        await _audit_event(
            db,
            event_type="backup_export_key",
            email=user.get("email", ""),
            outcome="failure",
            metadata={"reason": "weak_passphrase"},
        )
        return flash_redirect("/admin/backup", err=e, purpose="form")
    except Exception as e:
        log.error(
            "Key-only bundle build failed",
            extra={"_extra": {"error": fmt_exc(e), "type": type(e).__name__}},
        )
        await _audit_event(
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

    await _audit_event(
        db,
        event_type="backup_export_key",
        email=user.get("email", ""),
        outcome="success",
        metadata={"bytes": len(bundle)},
    )

    #  — stamp the restore-key freshness so the health email + dashboard can
    # show "Last key export: <date>" (the automated backups are unrecoverable
    # without this key). Best-effort; never fail the download.
    try:
        from email_triage import backup as _bk
        from email_triage._isotime import now_utc_iso
        _bk.write_key_export_marker(_resolve_data_dir(config), ts=now_utc_iso())
    except Exception as e:  # noqa: BLE001
        log.warning(
            "key-export marker write failed (non-fatal)",
            extra={"_extra": {"error": fmt_exc(e)}},
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


# ---------------------------------------------------------------------------
# Loopback ops trigger — the CLI / host-cron entry point
# ---------------------------------------------------------------------------

@router.post("/ops/db-backup")
async def ops_db_backup_trigger(request: Request):
    """On-demand backup trigger. Auth mirrors /health/detail: loopback
    origin AND a ≥16-char ``X-Ops-Token`` (the existing ``ET_HEALTH_OPS_TOKEN``),
    constant-time — the published LAN port arrives as the container gateway IP,
    so a leaked token can't be used off-loopback. The CLI runs INSIDE the
    container (host cron does ``podman exec … email-triage backup now``) so
    localhost is loopback.

    Fire-and-queue: schedules ``run_backup_once`` in-process (single-flight) and
    returns 202 "request received: outputting to <dir>" immediately; the
    per-run ``_LAST_RUN.json`` carries the eventual success/failure (the CLI
    ``--wait`` path polls it). A 2nd trigger while one runs → 409. Disabled →
    503. App-down is the CLI's problem (connection refused → its own FATAL)."""
    from email_triage.web.routers.health import (
        _ops_token_authorized,
        _read_ops_token,
    )

    # N-187 R20_12: authz-boundary — route through request_meta SSOT.
    _meta = request_meta(request)
    if not _ops_token_authorized(
        client_host=_meta.host,
        presented=request.headers.get("X-Ops-Token") or "",
        env_token=_read_ops_token() or "",
    ):
        return Response(status_code=403, content="forbidden")

    # Lazy imports (background_sweepers lazily imports THIS router's resolvers —
    # importing at module load would risk a cycle).
    from email_triage import single_flight as _sf
    from email_triage.web.background_sweepers import (
        _backup_out_dir,
        _db_backup_config,
        run_backup_once,
    )

    cfg = _db_backup_config(request.app.state.config)
    if cfg is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "automated backup is disabled (set backup.enabled in the config)"},
        )

    fmt = cfg["format"]
    qfmt = request.query_params.get("format")
    if qfmt in ("etbk", "db"):
        fmt = qfmt

    if _sf.in_flight("db_backup"):
        return JSONResponse(
            status_code=409, content={"detail": "a backup is already in flight"},
        )

    out_dir = _backup_out_dir(request.app, cfg)

    import asyncio

    async def _runner() -> None:
        from email_triage.single_flight import SingleFlightBusy

        try:
            await run_backup_once(request.app, fmt, trigger="cli")
        except SingleFlightBusy:
            log.info("ops db-backup trigger: already in flight; skipped")
        except Exception as e:  # noqa: BLE001 — recorded in _LAST_RUN.json
            log.error(
                "ops db-backup run failed",
                extra={"_extra": {"error": fmt_exc(e)}},
            )

    # Retain a strong reference: the event loop keeps only a WEAK ref to a bare
    # create_task, so a fire-and-queue task with no external ref can be GC'd
    # mid-flight — silently dropping the backup after the 202 returned (a 2nd
    # silent-drop path; devils-advocate). Hold it + discard on done.
    _t = asyncio.create_task(_runner())
    _BACKUP_BG_TASKS.add(_t)
    _t.add_done_callback(_BACKUP_BG_TASKS.discard)

    return JSONResponse(
        status_code=202,
        content={
            "detail": f"request received: outputting to {out_dir}",
            "format": fmt,
            "dir": out_dir,
        },
    )
