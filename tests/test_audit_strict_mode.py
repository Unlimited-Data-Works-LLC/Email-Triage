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


def test_production_mode_catches_and_counts_audit_write_failure(
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
    client = TestClient(app)
    r = client.get("/classify/test")
    assert r.status_code == 200

    # Drain pending audit-write tasks before reading the counter.
    pending = getattr(app.state, "_audit_pending", None)
    if pending:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        finally:
            loop.close()

    assert getattr(app.state, "audit_failures", 0) == 1


def test_strict_env_var_name_is_audit_strict(monkeypatch, db):
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
    client = TestClient(app)
    # Production-mode behaviour: 200 response, counter incremented.
    r = client.get("/classify/test")
    assert r.status_code == 200

    pending = getattr(app.state, "_audit_pending", None)
    if pending:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        finally:
            loop.close()

    assert getattr(app.state, "audit_failures", 0) == 1
