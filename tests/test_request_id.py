"""Tests for request-ID propagation across middleware + logger.

Covers:
- ``RequestIdMiddleware`` mints / honours / mirrors the ID.
- Untrusted inbound ``X-Request-ID`` headers are ignored.
- ``triage_logging.request_id_var`` flows into log ``_extra``.
- ``new_request_context`` works for non-HTTP-originated tasks.
- Audit-fail-fast: ``record_access_event`` failure increments
  ``app.state.audit_failures`` (not silently swallowed).
"""

from __future__ import annotations

import logging
import sqlite3

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from email_triage import triage_logging
from email_triage.triage_logging import (
    get_request_id,
    new_request_context,
    request_id_var,
    TriageLogger,
)
from email_triage.web.access_audit import (
    AccessAuditMiddleware,
    RequestIdMiddleware,
)


# ---------------------------------------------------------------------------
# Fixtures: a minimal Starlette app with both middlewares installed.
# ---------------------------------------------------------------------------

def _build_app(*, db: sqlite3.Connection | None = None) -> Starlette:
    async def hello(request):
        # Echo back the resolved request_id so the test can assert it.
        return PlainTextResponse(getattr(request.state, "request_id", ""))

    async def phi(request):
        # PHI-touch path — middleware should write an access_log row.
        return PlainTextResponse("ok")

    app = Starlette(routes=[
        Route("/hello", hello),
        Route("/classify/test", phi),
    ])
    # Same registration order as web/app.py — audit added first
    # (= inner), request-id added second (= outer / runs first).
    app.add_middleware(AccessAuditMiddleware)
    app.add_middleware(RequestIdMiddleware)

    if db is not None:
        app.state.db = db
    return app


@pytest.fixture
def db():
    # check_same_thread=False because TestClient runs handlers in
    # a different thread than the fixture's setup; this matches
    # the production app.state.db which is shared across the
    # ASGI request thread pool.
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.executescript("""
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
    """)
    c.commit()
    yield c
    c.close()


# ---------------------------------------------------------------------------
# Middleware behaviour
# ---------------------------------------------------------------------------

def test_middleware_mints_id_when_inbound_header_absent():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/hello")
    assert r.status_code == 200
    minted = r.text
    assert minted
    assert len(minted) == 12  # uuid4().hex[:12]
    # Mirrored as response header.
    assert r.headers["X-Request-ID"] == minted


def test_middleware_ignores_untrusted_inbound_header():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/hello", headers={"X-Request-ID": "spoofed-by-attacker"})
    assert r.status_code == 200
    # Trust flag absent → header ignored, fresh ID minted.
    assert r.text != "spoofed-by-attacker"
    assert r.headers["X-Request-ID"] != "spoofed-by-attacker"


def test_middleware_honours_trusted_proxy_header():
    """When request.state.from_trusted_proxy is True, inbound
    X-Request-ID is honoured (sanitised + length-capped)."""
    async def trust_marker(request, call_next):
        request.state.from_trusted_proxy = True
        return await call_next(request)

    from starlette.middleware.base import BaseHTTPMiddleware

    class TrustingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.from_trusted_proxy = True
            return await call_next(request)

    async def hello(request):
        return PlainTextResponse(getattr(request.state, "request_id", ""))

    app = Starlette(routes=[Route("/hello", hello)])
    app.add_middleware(RequestIdMiddleware)  # inner
    app.add_middleware(TrustingMiddleware)   # outer — sets the flag first
    client = TestClient(app)
    r = client.get("/hello", headers={"X-Request-ID": "upstream-abc-123"})
    assert r.text == "upstream-abc-123"
    assert r.headers["X-Request-ID"] == "upstream-abc-123"


def test_middleware_sanitises_trusted_inbound_header():
    """Header content is hex+alnum+[-_], length-capped at 64."""
    from starlette.middleware.base import BaseHTTPMiddleware

    class TrustingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.from_trusted_proxy = True
            return await call_next(request)

    async def hello(request):
        return PlainTextResponse(getattr(request.state, "request_id", ""))

    app = Starlette(routes=[Route("/hello", hello)])
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(TrustingMiddleware)
    client = TestClient(app)
    # Embedded space + slash should be stripped; result still non-empty.
    r = client.get(
        "/hello",
        headers={"X-Request-ID": "abc 123/../../etc/passwd"},
    )
    # Spaces and slashes filtered out.
    assert " " not in r.text
    assert "/" not in r.text
    assert r.text  # something survived


def test_middleware_response_header_for_error_status():
    """Even when the route returns a non-2xx, the response carries
    X-Request-ID so client-side telemetry can correlate."""
    async def boom(request):
        return PlainTextResponse("nope", status_code=500)

    app = Starlette(routes=[Route("/boom", boom)])
    app.add_middleware(RequestIdMiddleware)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/boom")
    assert r.status_code == 500
    assert r.headers.get("X-Request-ID")


# ---------------------------------------------------------------------------
# ContextVar propagation into TriageLogger
# ---------------------------------------------------------------------------

def test_triage_logger_injects_request_id(caplog):
    log = TriageLogger(logging.getLogger("email_triage.test"))
    with new_request_context("test-job") as rid:
        with caplog.at_level(logging.INFO, logger="email_triage.test"):
            log.info("hello", flow_id="f1")
        records = [r for r in caplog.records if r.name == "email_triage.test"]
        assert records
        extra = records[-1]._extra  # type: ignore[attr-defined]
        assert extra["request_id"] == rid
        assert extra["flow_id"] == "f1"


def test_triage_logger_no_request_id_when_outside_context(caplog):
    log = TriageLogger(logging.getLogger("email_triage.test_outside"))
    # Make sure the ContextVar is at its default empty string.
    request_id_var.set("")
    with caplog.at_level(logging.INFO, logger="email_triage.test_outside"):
        log.info("hello")
    records = [r for r in caplog.records if r.name == "email_triage.test_outside"]
    assert records
    extra = records[-1]._extra  # type: ignore[attr-defined]
    assert "request_id" not in extra


def test_triage_logger_request_id_survives_hipaa_strip(caplog):
    """request_id is opaque, not PHI, so HIPAA mode must not strip it."""
    log = TriageLogger(logging.getLogger("email_triage.test_hipaa"))
    triage_logging._hipaa_mode = True
    try:
        with new_request_context() as rid:
            with caplog.at_level(logging.INFO, logger="email_triage.test_hipaa"):
                log.info(
                    "x",
                    sender="should-be-stripped@example.com",
                    flow_id="f9",
                )
        records = [
            r for r in caplog.records if r.name == "email_triage.test_hipaa"
        ]
        extra = records[-1]._extra  # type: ignore[attr-defined]
        assert extra["request_id"] == rid
        assert extra["flow_id"] == "f9"
        assert "sender" not in extra  # PHI scrubbed
    finally:
        triage_logging._hipaa_mode = False


def test_new_request_context_resets_to_outer_value():
    request_id_var.set("outer")
    with new_request_context() as inner:
        assert get_request_id() == inner
        assert inner != "outer"
    assert get_request_id() == "outer"


# ---------------------------------------------------------------------------
# Audit fail-fast (no silent swallow)
# ---------------------------------------------------------------------------

def test_audit_failure_increments_counter(monkeypatch, db):
    """If record_access_event raises, dispatch logs + bumps the
    counter on app.state. Response is still returned (we don't poison
    the user's request) but the failure is auditable.

    #135.2: post-E-refactor the audit write is fire-and-forget on a
    task tracked by ``app.state._audit_pending``. Patch the
    module-cached reference (access_audit imported the helper at
    module load) and drain the pending set before asserting."""
    import asyncio
    from email_triage.web import access_audit

    def boom(*args, **kwargs):
        raise RuntimeError("simulated DB outage")

    # Patch the cached reference in access_audit (E imported it
    # `as _record_access_event` at module load — patching
    # web.db.record_access_event misses).
    monkeypatch.setattr(access_audit, "_record_access_event", boom)

    app = _build_app(db=db)
    client = TestClient(app)
    r = client.get("/classify/test")
    assert r.status_code == 200  # request still served

    # Drain pending audit-write tasks before reading the counter.
    pending = getattr(app.state, "_audit_pending", None)
    if pending:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        finally:
            loop.close()

    assert getattr(app.state, "audit_failures", 0) == 1


def test_audit_failure_strict_mode_reraises(monkeypatch, db):
    """In strict-audit mode, audit failure re-raises so the bug is
    visible.

    #135.2 post-E: dispatch awaits ``_audit_write`` synchronously when
    EMAIL_TRIAGE_AUDIT_STRICT is set so the exception surfaces on the
    request response (production path is fire-and-forget). Test
    patches the module-cached reference (E imported the helper at
    module load)."""
    from email_triage.web import access_audit

    monkeypatch.setenv("EMAIL_TRIAGE_AUDIT_STRICT", "1")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(access_audit, "_record_access_event", boom)

    app = _build_app(db=db)
    client = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(RuntimeError, match="simulated DB outage"):
        client.get("/classify/test")


def test_access_log_row_carries_request_id(db):
    """A real audit row written under a request scope must have
    the same request_id we minted on the way in."""
    app = _build_app(db=db)
    client = TestClient(app)
    r = client.get("/classify/test")
    assert r.status_code == 200
    minted = r.headers["X-Request-ID"]
    rows = db.execute(
        "SELECT request_id FROM access_log ORDER BY id DESC LIMIT 1"
    ).fetchall()
    assert rows
    assert rows[0][0] == minted


# ---------------------------------------------------------------------------
# Middleware ordering invariant (regression guard)
# ---------------------------------------------------------------------------

def test_middleware_ordering_request_id_outermost():
    """If RequestIdMiddleware is registered BEFORE AccessAuditMiddleware,
    the audit row would land without a request_id. This test asserts
    the order matches what app.py uses, so a future refactor doesn't
    silently regress."""
    from email_triage.web import app as app_module

    # Read the source so we don't have to boot the full lifespan.
    import inspect
    src = inspect.getsource(app_module.create_app)
    assert "AccessAuditMiddleware" in src
    assert "RequestIdMiddleware" in src
    audit_pos = src.index("app.add_middleware(AccessAuditMiddleware)")
    req_pos = src.index("app.add_middleware(RequestIdMiddleware)")
    assert audit_pos < req_pos, (
        "AccessAuditMiddleware must be added BEFORE RequestIdMiddleware "
        "so RequestId becomes the outermost (executed first on inbound)."
    )
