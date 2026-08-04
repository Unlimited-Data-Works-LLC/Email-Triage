"""Tests for ``EMAIL_TRIAGE_AUDIT_STRICT`` audit-write failure policy.

The strict-audit env var is the only surviving piece of the retired
dev-mode system (removed 2026-05-16). It flips the access-audit
middleware from production's fire-and-forget mode (exceptions are
caught, logged, counted on ``app.state.audit_failures``) to strict
mode where exceptions re-raise so the bug surfaces immediately on
the request response.

These tests pin:
  - With ``EMAIL_TRIAGE_AUDIT_STRICT`` set, audit-write exceptions
    re-raise from the middleware (operator debug aid).
  - Without it, audit-write exceptions are caught + counted on
    ``app.state.audit_failures`` (production safety).
  - The env-var name itself, to prevent an accidental rename or
    revert to the old ``EMAIL_TRIAGE_DEV_MODE`` regressing the
    operator's deploy-time invocation.
"""

from __future__ import annotations

import asyncio
import sqlite3

import pytest
# Full-tree `-n auto` hardening: these file-DB / audit-global suites flake when
# co-resident on a worker (SQLite file-lock contention + load-amplified async-audit
# timing). Each passes in isolation. Pin them to one xdist worker so they run
# serially, not concurrently — the project-sanctioned facet-2 fix (testinfra drawer).
pytestmark = pytest.mark.xdist_group("file_db_audit_serial")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from email_triage.web.access_audit import (
    AccessAuditMiddleware,
    RequestIdMiddleware,
)


def _build_app(*, db: sqlite3.Connection | None = None) -> Starlette:
    async def phi(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/classify/test", phi)])
    # Same ordering as web/app.py: audit added first (inner), request-id
    # second (outer / runs first).
    app.add_middleware(AccessAuditMiddleware)
    app.add_middleware(RequestIdMiddleware)
    if db is not None:
        app.state.db = db
    return app


@pytest.fixture
def db():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.executescript(
        """
        CREATE TABLE access_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT NOT NULL,
            actor_user_id INTEGER,
            method        TEXT NOT NULL,
            route         TEXT NOT NULL,
            account_id    INTEGER,
            message_id    TEXT,
            status_code   INTEGER NOT NULL,
            outcome       TEXT NOT NULL,
            detail        TEXT,
            request_id    TEXT
        );
        """
    )
    c.commit()
    yield c
    c.close()


async def _classify_and_drain_audit(app) -> int:
    """GET /classify/test via an in-process ASGI client and drain the
    fire-and-forget audit-write task ON THE SAME event loop, then return
    ``app.state.audit_failures``.

    Replaces the old ``asyncio.new_event_loop()`` + ``gather`` drain, which
    created a SECOND loop and tried to ``gather`` tasks bound to the sync
    ``TestClient``'s portal loop — a cross-loop await that does NOT drive them.
    Under load (CI) the fire-and-forget ``_audit_write`` had not run when the
    counter was read, so it read 0 (the load-amplified flake this file's header
    acknowledges). With ``httpx.ASGITransport`` the request, the
    ``asyncio.create_task``'d ``_audit_write``, and the drain ``gather`` all
    share the pytest-asyncio loop (``asyncio_mode = "auto"``), so the drain
    deterministically completes the write before the counter is read.
    """
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test",
    ) as client:
        r = await client.get("/classify/test")
        assert r.status_code == 200
    pending = list(getattr(app.state, "_audit_pending", None) or [])
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    return int(getattr(app.state, "audit_failures", 0))


def test_strict_mode_reraises_on_audit_write_failure(monkeypatch, db):
    """With ``EMAIL_TRIAGE_AUDIT_STRICT`` set, an audit-write
    exception must surface on the request response so the operator
    sees the failure immediately (rather than discovering it via
    drift on ``/health``)."""
    from email_triage.web import access_audit

    monkeypatch.setenv("EMAIL_TRIAGE_AUDIT_STRICT", "1")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(access_audit, "_record_access_event", boom)

    app = _build_app(db=db)
    client = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(RuntimeError, match="simulated DB outage"):
        client.get("/classify/test")


async def test_production_mode_catches_and_counts_audit_write_failure(
    monkeypatch, db,
):
    """Without ``EMAIL_TRIAGE_AUDIT_STRICT``, the audit-write
    exception is logged + counted on ``app.state.audit_failures``.
    The request itself still returns 200 — we never poison a user's
    response over an audit-store glitch."""
    from email_triage.web import access_audit

    # Ensure unset; tests run in arbitrary order so we explicitly
    # delete rather than rely on the absence.
    monkeypatch.delenv("EMAIL_TRIAGE_AUDIT_STRICT", raising=False)
    # Belt-and-braces: also clear the retired env-var name so a stale
    # CI environment can't accidentally pass this test for the wrong
    # reason.
    monkeypatch.delenv("EMAIL_TRIAGE_DEV_MODE", raising=False)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(access_audit, "_record_access_event", boom)

    app = _build_app(db=db)
    # Production (non-strict) mode: the request returns 200 (never re-raises)
    # and the fire-and-forget audit-write failure is counted. Same-loop drain.
    assert await _classify_and_drain_audit(app) == 1


async def test_strict_env_var_name_is_audit_strict(monkeypatch, db):
    """Pin the exact env-var name. A rename or revert to the retired
    ``EMAIL_TRIAGE_DEV_MODE`` would silently regress the operator's
    deploy-time invocation; this test asserts that only the new
    name flips strict mode on."""
    from email_triage.web import access_audit

    monkeypatch.delenv("EMAIL_TRIAGE_AUDIT_STRICT", raising=False)
    # Set the retired name — it must NOT re-enable strict behaviour.
    monkeypatch.setenv("EMAIL_TRIAGE_DEV_MODE", "1")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(access_audit, "_record_access_event", boom)

    app = _build_app(db=db)
    # The retired EMAIL_TRIAGE_DEV_MODE must NOT enable strict mode: the request
    # returns 200 (strict would re-raise) and the failure is counted. Same-loop
    # drain (the old new-loop gather raced under CI load — load-amplified flake).
    assert await _classify_and_drain_audit(app) == 1
