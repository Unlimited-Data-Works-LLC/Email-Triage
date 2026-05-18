"""Tests for #41 — access-audit log + middleware."""

from email_triage.web.access_audit import (
    _extract_account_id,
    _extract_message_id,
    _is_phi_path,
    _outcome_from_status,
)
from email_triage.web.db import (
    list_access_events,
    record_access_event,
)


class TestPhiPathClassifier:
    def test_classify_route_is_phi(self):
        assert _is_phi_path("/classify")
        assert _is_phi_path("/classify/preview")

    def test_triage_run_is_phi(self):
        assert _is_phi_path("/triage/run")

    def test_account_messages_is_phi(self):
        assert _is_phi_path("/accounts/3/messages")
        assert _is_phi_path("/accounts/3/messages/abc123/body")

    def test_account_digest_is_phi(self):
        assert _is_phi_path("/accounts/7/digest/generate")
        assert _is_phi_path("/accounts/7/digest/run/0")

    def test_openclaw_account_is_phi(self):
        assert _is_phi_path("/api/openclaw/accounts/1/messages/abc/body")

    def test_runs_detail_is_phi(self):
        assert _is_phi_path("/runs/abc-123")

    def test_login_is_not_phi(self):
        assert not _is_phi_path("/login")
        assert not _is_phi_path("/")

    def test_static_is_not_phi(self):
        assert not _is_phi_path("/static/style.css")

    def test_health_is_not_phi(self):
        assert not _is_phi_path("/health")

    def test_logs_is_not_phi(self):
        assert not _is_phi_path("/logs")

    def test_config_is_not_phi(self):
        assert not _is_phi_path("/config")

    def test_accounts_list_is_not_phi(self):
        # Bare /accounts is the management list, not mail content.
        assert not _is_phi_path("/accounts")


class TestPathExtractors:
    def test_account_id_from_account_path(self):
        assert _extract_account_id("/accounts/42/messages") == 42
        assert _extract_account_id("/accounts/7/digest/generate") == 7

    def test_account_id_from_openclaw_path(self):
        assert _extract_account_id("/api/openclaw/accounts/3/messages/abc/body") == 3

    def test_account_id_from_unrelated_path_is_none(self):
        assert _extract_account_id("/login") is None
        assert _extract_account_id("/classify") is None

    def test_message_id_extracted(self):
        assert _extract_message_id(
            "/api/openclaw/accounts/3/messages/abc-123/body"
        ) == "abc-123"

    def test_message_id_capped(self):
        long_id = "a" * 500
        assert len(_extract_message_id(f"/messages/{long_id}/x")) == 200

    def test_message_id_absent(self):
        assert _extract_message_id("/login") is None


class TestOutcomeMapping:
    def test_ok(self):
        assert _outcome_from_status(200) == "ok"
        assert _outcome_from_status(204) == "ok"
        assert _outcome_from_status(303) == "ok"

    def test_denied(self):
        assert _outcome_from_status(401) == "denied"
        assert _outcome_from_status(403) == "denied"

    def test_not_found(self):
        assert _outcome_from_status(404) == "not_found"

    def test_error(self):
        assert _outcome_from_status(500) == "error"
        assert _outcome_from_status(422) == "error"


class TestAccessLogPersistence:
    def test_record_and_list(self, db, regular_user):
        record_access_event(
            db,
            actor_user_id=regular_user["id"],
            method="POST",
            route="/triage/run",
            account_id=None,
            message_id=None,
            status_code=200,
            outcome="ok",
        )
        rows = list_access_events(db, limit=10)
        assert len(rows) == 1
        assert rows[0]["route"] == "/triage/run"
        assert rows[0]["actor_user_id"] == regular_user["id"]
        assert rows[0]["actor_email"] == regular_user["email"]

    def test_list_filtered_by_actor(self, db, regular_user, admin_user):
        record_access_event(
            db, actor_user_id=admin_user["id"], method="GET",
            route="/runs/abc", account_id=None, message_id=None,
            status_code=200, outcome="ok",
        )
        record_access_event(
            db, actor_user_id=regular_user["id"], method="GET",
            route="/runs/xyz", account_id=None, message_id=None,
            status_code=200, outcome="ok",
        )
        rows = list_access_events(db, actor_user_id=regular_user["id"])
        assert len(rows) == 1
        assert rows[0]["route"] == "/runs/xyz"

    def test_list_filtered_by_account(self, db, admin_user):
        from email_triage.web.db import create_email_account
        a1 = create_email_account(
            db, admin_user["id"], "A1", "imap", {"host": "x"},
        )
        a2 = create_email_account(
            db, admin_user["id"], "A2", "imap", {"host": "y"},
        )
        record_access_event(
            db, actor_user_id=admin_user["id"], method="POST",
            route=f"/accounts/{a1}/digest/generate",
            account_id=a1, message_id=None,
            status_code=200, outcome="ok",
        )
        record_access_event(
            db, actor_user_id=admin_user["id"], method="POST",
            route=f"/accounts/{a2}/digest/generate",
            account_id=a2, message_id=None,
            status_code=200, outcome="ok",
        )
        rows = list_access_events(db, account_id=a1)
        assert len(rows) == 1
        assert rows[0]["account_id"] == a1

    def test_stale_account_id_coerces_to_null(self, db, regular_user):
        """If the URL referenced an account_id that doesn't exist
        (caller has a stale ID, account was deleted, etc.), the
        FK-violation IntegrityError must NOT fail the audit write.
        Coerce account_id to NULL and stash the original in the
        detail column so the audit row still records what was tried."""
        # Account 99999 definitely doesn't exist.
        rid = record_access_event(
            db,
            actor_user_id=regular_user["id"],
            method="GET",
            route="/api/openclaw/accounts/99999/bulk/mail",
            account_id=99999,
            message_id=None,
            status_code=404,
            outcome="not_found",
        )
        assert rid > 0
        rows = list_access_events(db, limit=10)
        # Most recent row carries the route + NULL account_id +
        # stale-id note in detail.
        latest = rows[0]
        assert latest["route"] == "/api/openclaw/accounts/99999/bulk/mail"
        assert latest["account_id"] is None
        assert "stale_account_id=99999" in (latest["detail"] or "")

    def test_stale_actor_user_id_coerces_to_null(self, db):
        """Same fallback applies if actor_user_id references a
        deleted user. Less likely (sessions outlive deletes) but
        same defensive pattern."""
        rid = record_access_event(
            db,
            actor_user_id=999999,
            method="GET",
            route="/runs/abc",
            account_id=None,
            message_id=None,
            status_code=200,
            outcome="ok",
        )
        assert rid > 0
        rows = list_access_events(db, limit=1)
        latest = rows[0]
        assert latest["actor_user_id"] is None
        assert "stale_actor_user_id=999999" in (latest["detail"] or "")


class TestMiddlewareIntegration:
    def test_middleware_logs_authenticated_phi_request(
        self, client, user_cookies, db, regular_user,
    ):
        """Hitting a PHI-touch route writes an access_log row."""
        before = len(list_access_events(db, limit=1000))
        # Trigger a request to /classify (renders form, no actual work).
        resp = client.get("/classify", cookies=user_cookies)
        # Whether the response is 200 or a redirect, the audit row should land.
        assert resp.status_code in (200, 303, 401, 403)
        after = len(list_access_events(db, limit=1000))
        # The audit table grew by exactly 1.
        assert after == before + 1
        latest = list_access_events(db, limit=1)[0]
        assert latest["route"] == "/classify"
        assert latest["method"] == "GET"

    def test_middleware_skips_non_phi_routes(
        self, client, user_cookies, db,
    ):
        """Hitting /health or /static does NOT write an access_log row."""
        before = len(list_access_events(db, limit=1000))
        client.get("/health")
        client.get("/static/style.css")
        after = len(list_access_events(db, limit=1000))
        assert after == before


class TestFireAndForgetAuditWrite:
    """#135.2 — audit write is fire-and-forget (off the request path)
    but MUST still complete. These tests pin the contract:

    1. The write lands on app.state DB after the response settles.
    2. The middleware does NOT block the response on the write
       (we don't measure wall-clock here — the contract is that the
       create_task path is taken; the fact that the threadpool work
       happens off the loop is verified by the conversion itself).
    3. A pending-tasks set is tracked on app.state so a future
       graceful shutdown can drain outstanding writes.
    """

    def test_pending_tasks_set_tracks_writes(
        self, client, user_cookies, db, regular_user, app,
    ):
        """The middleware tracks audit-write tasks on
        ``app.state._audit_pending`` so they can be awaited at
        shutdown. After all writes complete the set drains."""
        client.get("/classify", cookies=user_cookies)
        # By the time TestClient returns, the pending set exists
        # (created lazily on first PHI-path request) and has either
        # been populated and drained, or holds at most the in-flight
        # task. Either way the attribute is present.
        pending = getattr(app.state, "_audit_pending", None)
        assert pending is not None
        # All tasks should have completed by now (TestClient drains).
        assert all(t.done() for t in pending)

    def test_record_helper_is_module_cached(self):
        """#135.2: ``record_access_event`` is imported once at module
        load, not lazily on every request. The previous lazy import
        was a per-request lookup tax."""
        from email_triage.web import access_audit
        from email_triage.web.db import record_access_event
        # Module-level reference exists and points at the same callable.
        assert access_audit._record_access_event is record_access_event

    def test_middleware_uses_request_state_user_when_present(
        self, client, db, regular_user, user_cookies,
    ):
        """#135.2: when the auth dependency on the route already
        resolved a user onto ``request.state.user``, the middleware
        reuses it instead of re-running the full auth lookup. We
        can't read ``request.state`` from outside the request scope,
        so we verify the contract by hitting a PHI route and
        confirming the actor_user_id ends up correct."""
        # This is the same path test_middleware_logs_authenticated_phi_request
        # exercises; the assertion here is just on the resolved actor.
        client.get("/classify", cookies=user_cookies)
        latest = list_access_events(db, limit=1)[0]
        assert latest["actor_user_id"] == regular_user["id"]


class TestHealthHandlerAsyncConversion:
    """#135.1 — verify /health + /health/detail conversion didn't break
    the response shape. The existing 11 health tests in test_health.py
    cover the response-shape contract end-to-end; these add a direct
    cross-check that ``_compute_health_detail`` is now async and runs
    its blocking work via ``db_call`` (i.e. the conversion is wired up,
    not just the handler signature).

    A wall-clock concurrency test was considered but rejected:
    in-memory SQLite + TestClient threading is racy in ways unrelated
    to the conversion (TestClient itself is not designed for multiple
    concurrent threads against a shared in-memory DB). The wired-up
    check below is deterministic and tests the actual contract.
    """

    def test_compute_health_detail_is_coroutine(self):
        """The function is async — direct call returns a coroutine."""
        import inspect
        from email_triage.web.routers.health import _compute_health_detail
        assert inspect.iscoroutinefunction(_compute_health_detail)

    def test_compute_health_detail_uses_db_call(self):
        """The async wrapper delegates to ``db_call`` (not a direct
        sync call). Verified by inspection of the source — sufficient
        to pin the contract that the blocking work happens off the
        event loop."""
        import inspect
        from email_triage.web.routers import health
        src = inspect.getsource(health._compute_health_detail)
        # Must reference db_call to wrap the sync body.
        assert "db_call" in src
        # Must call the sync body helper, not duplicate it.
        assert "_compute_health_detail_sync" in src

    def test_health_endpoint_still_returns_minimal_shape(self, client, db):
        """End-to-end smoke after the conversion: /health still returns
        {status, uptime_secs, db} only. Mirrors test_minimal_health_shape
        in test_health.py — kept here as a guard that the conversion
        didn't accidentally widen the public shape."""
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert set(body.keys()) == {"status", "uptime_secs", "db"}
        assert body["status"] == "ok"
