"""Tests for  — access-audit log + middleware."""

import time

from _portal_loop import _one_portal_loop
from email_triage.web._audit import get_last_audit_exc
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


def _drain_audit_writes(
    app,
    db=None,
    expected_delta: int = 1,
    before: int | None = None,
    timeout: float = 10.0,
) -> None:
    """Block until every fire-and-forget audit-write task has finished
    AND (when ``db`` is passed) the ``access_log`` row-count has grown
    by ``expected_delta`` above ``before``.

    .2 made the access-audit write fire-and-forget: the middleware
    ``asyncio.create_task``s it and tracks the task on
    ``app.state._audit_pending``. By the time ``TestClient.get()``
    returns the response has been sent, but the write task may still be
    pending on the TestClient portal's event loop.

    HISTORY — Prior implementation polled ONLY ``app.state._audit_pending``
    (task-set drain) as a proxy for "row-landed". Under CI load, the
    middleware's ``asyncio.create_task`` had not YET registered the task
    on the pending set by the time the test thread began polling, so the
    set was seen as {} → drain returned immediately → the row hadn't
    landed → the ``after == before + 1`` assertion failed. Task-set
    membership is the WRONG liveness signal; the actual assertion is
    row-count. Same class as `feedback_fix_flaky_tests_dont_dismiss`
    (2026-07-09 fix-forward on the CI-red at `4326340a` — 3rd recurrence).

    NEW SHAPE — When callers pass ``db`` + ``before``, this helper polls
    BOTH the task-set (belt) AND the DB row-count (braces). Returns only
    when both agree the write has landed. Legacy callers passing just
    ``app`` still get the old task-set-only drain (backwards-compatible).

    2026-07-10 root-cause fix (feedback_fix_flaky_tests_dont_dismiss rule
    5, escalating-timeout anti-pattern) — the 15→30→45s timeout escalation
    was a band-aid on a SILENT-SWALLOW race: a swallowed
    ``sqlite3.OperationalError`` / ``ProgrammingError`` inside
    ``safe_audit_write_async`` transitioned the task to ``done=True`` with
    NO row landing, so the task-set arm passed and the row-count arm
    burned the full timeout waiting for a row that would never come. Both
    swallow seams (``_audit.safe_audit_write_async`` and
    ``access_audit.dispatch``'s outer ``except``) now stash the exception
    on ``_audit._LAST_AUDIT_EXC``; this helper snapshots that before the
    poll loop and fails FAST with the real exception class named if a
    swallow lands during the drain — turning the black-box hang into a
    first-poll fail-loud. Timeout restored to 10s (comfortable ceiling on
    CI xdist scheduling jitter; no longer papering over silent failures).
    """
    exc_before = get_last_audit_exc()
    deadline = time.monotonic() + timeout
    # the backlog  (DA  F3 root-cause fix): auto-create a
    # ``threading.Event`` on app.state so ``attach_audit_done_callback``
    # can wake this helper on task completion instead of the 20ms
    # polling interval eating GIL under xdist_load. If the fixture
    # didn't provide one, create it here — the middleware picks it up
    # via ``getattr(..., None)`` at next task boot.
    import threading as _threading
    signal = getattr(app.state, "_audit_pending_signal", None)
    if signal is None:
        signal = _threading.Event()
        app.state._audit_pending_signal = signal
    import asyncio as _asyncio
    from email_triage.web._audit import _AsyncCancelledMarker
    while time.monotonic() < deadline:
        exc_now = get_last_audit_exc()
        if exc_now is not None and exc_now is not exc_before:
            exc, description, _stamped = exc_now
            # the backlog  — db-sme F2 (2026-07-11): enumerate
            # the skip classes EXPLICITLY (not "task-teardown-
            # shaped"). Only cancels from the access_audit_middleware
            # description path are skipped — a future non-cancel
            # BaseException-derived audit-write bug won't be silently
            # swallowed. sqlite3.OperationalError / IntegrityError /
            # DBError etc. still trigger the fail-loud path.
            # Two stash paths can race for a cancelled fire-and-forget
            # audit task: (a) inside ``safe_audit_write_async``'s
            # ``except BaseException`` with the caller-passed
            # description (``"access_log GET route=..."``); (b) inside
            # ``attach_audit_done_callback`` with the create_task-site
            # description (``"access_audit_middleware"``). Accept both
            # by description prefix — the CLASS check is the primary
            # gate; description prefix is defense-in-depth against a
            # future audit-write bug misclassifying as cancel.
            _is_task_cancel = (
                isinstance(exc, (_asyncio.CancelledError, _AsyncCancelledMarker))
                and (
                    description == "access_audit_middleware"
                    or description.startswith("access_log ")
                )
            )
            if not _is_task_cancel:
                raise AssertionError(
                    "audit-write raised (swallowed by safe_audit_write* — "
                    f"see feedback_fix_flaky_tests_dont_dismiss rule 5): "
                    f"{description} -> {type(exc).__name__}: {exc}"
                )
            # Update exc_before so we don't re-flag the same cancel.
            exc_before = exc_now
        pending = getattr(app.state, "_audit_pending", None)
        # First arm: task-set drained. Snapshot before iterating —
        # ``task.add_done_callback(pending.discard)`` mutates the set
        # from the portal thread on task completion, racing the main-
        # thread iteration here (RuntimeError-under-load flake class).
        task_set_drained = (
            pending is not None and all(t.done() for t in list(pending))
        )
        # Second arm: row-count matches expected delta. This is the
        # REAL liveness signal — the row we're about to assert on has
        # actually landed in the DB. When db+before are provided,
        # row-count is authoritative ON ITS OWN — task_set_drained is
        # a proxy that becomes STALE on cancel: under CI xdist the
        # portal loop can cancel the fire-and-forget task before its
        # ``asyncio.to_thread``-scheduled INSERT lands, at which point
        # ``pending.discard(task)`` fires immediately (task-set drained)
        # while the executor thread keeps completing the INSERT.
        # AND-gating on task_set-drain would prematurely satisfy the
        # first arm and lose the second-arm wait budget on a signal
        # that already passed. Trust the strong signal alone.
        if db is not None and before is not None:
            if row_count_matches := (
                len(list_access_events(db, limit=1000))
                >= before + expected_delta
            ):
                return
        elif task_set_drained:
            # Legacy path: row-count unavailable, task-set best signal.
            return
        # the backlog : event-driven wait replaces raw sleep. The
        # done-callback attached by ``attach_audit_done_callback`` fires
        # ``signal.set()`` from the portal loop the moment any
        # fire-and-forget audit task completes; the ``.wait(0.02)``
        # returns instantly and the next poll pass re-checks all
        # conditions. If no task completes within 20ms the wait times
        # out and we fall through — same wall-clock cadence as pre-fix,
        # but under xdist_load the wake-latency drops from ~20ms fixed
        # to microseconds. ``.clear()`` before the wait so we only
        # respond to fresh completions, not the previous set.
        signal.clear()
        signal.wait(timeout=0.02)
    raise AssertionError(
        "audit-write did not drain within "
        f"{timeout}s — app.state._audit_pending still has in-flight tasks "
        "OR access_log row-count did not reach expected delta"
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

    def test_digest_candidates_is_phi(self):
        # N-172 — the digest "Show matches" dry-run lists matched
        # sender/subject = PHI. Plural ``digests`` + the ``/<digest_id>/``
        # segment was NOT covered by the singular ``digest/...``
        # alternatives, so no §164.312(b) access_log row fired (any actor).
        assert _is_phi_path("/accounts/3/digests/5/candidates")

    def test_digest_preview_is_phi(self):
        # N-173 — preview renders the digest body via the SAME
        # ``_render_digest_payload`` send-render path; the iframe srcdoc
        # embeds matched sender/subject/body = PHI. Same plural-``digests``
        # blind spot as candidates → no §164.312(b) row fired pre-N-173.
        assert _is_phi_path("/accounts/3/digests/5/preview")

    def test_digest_test_send_is_phi(self):
        # N-173 — test-send runs the full ``_fire_one_digest`` path
        # (gather→filter→render→SMTP); reads + discloses matched mail
        # content. PHI-bearing → must emit the §164.312(b) access_log row.
        assert _is_phi_path("/accounts/3/digests/5/test-send")

    def test_digest_config_subroutes_are_not_phi(self):
        # Scoped extension (N-172 + N-173): the candidates/preview/test-send
        # extension must NOT over-match the sibling digests/* subroutes —
        # they are config CRUD (new / new/edit / {id}/edit / save / delete)
        # or a query-syntax check (validate-query returns only a MATCH
        # COUNT, no sender/subject/body), not mail-content reads, so they
        # stay out of the audit table to avoid noise.
        assert not _is_phi_path("/accounts/3/digests/new")
        assert not _is_phi_path("/accounts/3/digests/new/edit")
        assert not _is_phi_path("/accounts/3/digests/5/edit")
        assert not _is_phi_path("/accounts/3/digests/5/save")
        assert not _is_phi_path("/accounts/3/digests/5/delete")
        assert not _is_phi_path("/accounts/3/digests/5/validate-query")

    def test_webhook_account_is_phi(self):
        assert _is_phi_path("/api/v1/accounts/1/messages/abc/body")

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

    def test_account_id_from_webhook_path(self):
        assert _extract_account_id("/api/v1/accounts/3/messages/abc/body") == 3

    def test_account_id_from_digest_candidates_path(self):
        # N-172 — the audit row must carry the account_id for the
        # candidates dry-run, not just classify it as PHI.
        assert _extract_account_id("/accounts/3/digests/5/candidates") == 3

    def test_account_id_from_digest_preview_and_test_send(self):
        # N-173 — the audit row must carry the account_id for the
        # preview + test-send PHI routes too, not just classify them.
        assert _extract_account_id("/accounts/3/digests/5/preview") == 3
        assert _extract_account_id("/accounts/7/digests/2/test-send") == 7

    def test_account_id_from_unrelated_path_is_none(self):
        assert _extract_account_id("/login") is None
        assert _extract_account_id("/classify") is None

    def test_message_id_extracted(self):
        assert _extract_message_id(
            "/api/v1/accounts/3/messages/abc-123/body"
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
            db, admin_user["id"], "A1", "imap", {"host": "x.invalid"},
        )
        a2 = create_email_account(
            db, admin_user["id"], "A2", "imap", {"host": "y.invalid"},
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
            route="/api/v1/accounts/99999/bulk/mail",
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
        assert latest["route"] == "/api/v1/accounts/99999/bulk/mail"
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
        self, client, app, user_cookies, db, regular_user,
    ):
        """Hitting a PHI-touch route writes an access_log row."""
        before = len(list_access_events(db, limit=1000))
        with _one_portal_loop(client):
            # Trigger a request to /classify (renders form, no actual work).
            resp = client.get("/classify", cookies=user_cookies)
            # Whether the response is 200 or a redirect, the audit row should land.
            assert resp.status_code in (200, 303, 401, 403)
            #  + `4326340a` CI-red fix-forward — the audit write is
            # fire-and-forget; drain BOTH the pending task set (belt) AND
            # the DB row-count (braces). Task-set-membership alone is the
            # wrong liveness signal — under CI load the ``create_task`` may
            # not have registered yet when polling begins.
            _drain_audit_writes(app, db=db, expected_delta=1, before=before)
        after = len(list_access_events(db, limit=1000))
        # The audit table grew by exactly 1.
        assert after == before + 1
        latest = list_access_events(db, limit=1)[0]
        assert latest["route"] == "/classify"
        assert latest["method"] == "GET"

    def test_middleware_skips_non_phi_routes(
        self, client, app, user_cookies, db,
    ):
        """Hitting /health or /static does NOT write an access_log row."""
        before = len(list_access_events(db, limit=1000))
        # F577-4: an after==before check with no wait passes even if /health
        # WERE audited (the write had not landed yet). Send a PHI request
        # last and drain on the held loop: once its row lands, any earlier
        # /health or /static row would have landed too.
        with _one_portal_loop(client):
            client.get("/health")
            client.get("/static/style.css")
            client.get("/classify", cookies=user_cookies)
            _drain_audit_writes(app, db=db, expected_delta=1, before=before)
        after = len(list_access_events(db, limit=1000))
        assert after == before + 1
        assert list_access_events(db, limit=1)[0]["route"] == "/classify"


class TestFireAndForgetAuditWrite:
    """.2 — audit write is fire-and-forget (off the request path)
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
        before = len(list_access_events(db, limit=1000))

        # Record every task the middleware adds. A snapshot of the set
        # taken after the request raced the task's own done-callback: a
        # write that finished first had already discarded itself, so the
        # snapshot was empty (main CI on b0dcc994, 2026-10-09; the same
        # sha was green on its branch). The middleware reuses an existing
        # set, so pre-installing this one sees the add whatever the timing.
        class _RecordingSet(set):
            def __init__(self):
                super().__init__()
                self.added = []

            def add(self, item):
                self.added.append(item)
                super().add(item)

        recorder = _RecordingSet()
        app.state._audit_pending = recorder
        with _one_portal_loop(client):
            client.get("/classify", cookies=user_cookies)
            # The middleware tracked the write on the same set object.
            assert getattr(app.state, "_audit_pending", None) is recorder
            tasks = list(recorder.added)
            _drain_audit_writes(app, db=db, expected_delta=1, before=before)
            # The row has landed; the task finishes one loop hop later. On
            # the held loop nothing cancels it, so done() means completed
            # (punch 577: on a per-request loop a cancelled task also reads
            # done) — hence the explicit not-cancelled check.
            deadline = time.monotonic() + 10.0
            while not all(t.done() for t in tasks) and time.monotonic() < deadline:
                time.sleep(0.02)
            assert tasks
            assert all(t.done() and not t.cancelled() for t in tasks)
        assert len(list_access_events(db, limit=1000)) == before + 1

    def test_record_helper_is_module_cached(self):
        """.2: ``record_access_event`` is imported once at module
        load, not lazily on every request. The previous lazy import
        was a per-request lookup tax."""
        from email_triage.web import access_audit
        from email_triage.web.db import record_access_event
        # Module-level reference exists and points at the same callable.
        assert access_audit._record_access_event is record_access_event

    def test_middleware_uses_request_state_user_when_present(
        self, client, app, db, regular_user, user_cookies,
    ):
        """.2: when the auth dependency on the route already
        resolved a user onto ``request.state.user``, the middleware
        reuses it instead of re-running the full auth lookup. We
        can't read ``request.state`` from outside the request scope,
        so we verify the contract by hitting a PHI route and
        confirming the actor_user_id ends up correct."""
        # This is the same path test_middleware_logs_authenticated_phi_request
        # exercises; the assertion here is just on the resolved actor.
        #  tail (2026-07-09 CI-red on de050c40 exposed the missed
        # legacy call-site): drain by DB row-count, not task-set
        # membership — task-set drain is the WRONG liveness signal
        # under CI load per the drainer's HISTORY docstring.
        before = len(list_access_events(db, limit=100))
        with _one_portal_loop(client):
            client.get("/classify", cookies=user_cookies)
            _drain_audit_writes(app, db=db, expected_delta=1, before=before)
        latest = list_access_events(db, limit=1)[0]
        assert latest["actor_user_id"] == regular_user["id"]


class TestHealthHandlerAsyncConversion:
    """.1 — verify /health + /health/detail conversion didn't break
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


class TestDigestRouteAuditNetCompleteness:
    """N-173 — count-agnostic structural pin over the §164.312(b)
    access-audit net for the ``digests/*`` route family (PD#4: prove the
    enumeration net complete, don't trust ``len(X)==N``).

    The source of truth for "what digests routes EXIST" is the live
    FastAPI router, not a hand-counted list. Every actual
    ``/accounts/{account_id}/digests/...`` route MUST be classified here
    as PHI-bearing (reads/discloses matched mail content → needs the
    access_log row) or config-only (CRUD / query-syntax check → stays
    out to avoid noise + over-match). ``_is_phi_path`` must then agree
    with that classification for every member.

    Teeth:
      * Add a NEW digests route to the router without classifying it
        here → ``test_router_digests_routes_all_classified`` RED (forces
        a human to decide PHI vs config for the new surface).
      * Mark a route PHI-bearing here but forget to widen the regex →
        ``test_is_phi_path_matches_classification`` RED (True != False).
      * Let the regex over-match a config route (e.g. validate-query) →
        same test RED (False != True).
    """

    # template path -> True (PHI-bearing, needs §164.312(b) row) / False
    # (config-only). Evidence is in the enumeration signature on N-173.
    EXPECTED = {
        "/accounts/{account_id}/digests/new": False,
        "/accounts/{account_id}/digests/new/edit": False,
        "/accounts/{account_id}/digests/{digest_id}/edit": False,
        "/accounts/{account_id}/digests/{digest_id}/save": False,
        "/accounts/{account_id}/digests/{digest_id}/delete": False,
        "/accounts/{account_id}/digests/{digest_id}/test-send": True,
        "/accounts/{account_id}/digests/{digest_id}/candidates": True,
        "/accounts/{account_id}/digests/{digest_id}/preview": True,
        "/accounts/{account_id}/digests/{digest_id}/validate-query": False,
    }

    @staticmethod
    def _router_digest_templates() -> set[str]:
        """Every ``/accounts/.../digests/...`` path template the live
        accounts router actually serves (the structural source of
        truth)."""
        from email_triage.web.routers.ui.accounts import router
        out: set[str] = set()
        for route in router.routes:
            path = getattr(route, "path", "")
            if "/digests" in path:
                out.add(path)
        return out

    @staticmethod
    def _concrete(template: str) -> str:
        return template.replace(
            "{account_id}", "3"
        ).replace("{digest_id}", "5")

    def test_router_digests_routes_all_classified(self):
        """Net-completeness: the router's actual digests routes EXACTLY
        equal the classified set — no unclassified new route, no stale
        key that no longer maps to a real route."""
        actual = self._router_digest_templates()
        expected = set(self.EXPECTED)
        missing = actual - expected  # a new route nobody classified
        stale = expected - actual    # a key that no route serves
        assert not missing, (
            "unclassified digests route(s) — classify PHI vs config in "
            f"EXPECTED + widen the regex if PHI-bearing: {sorted(missing)}"
        )
        assert not stale, (
            f"EXPECTED has digests route(s) the router no longer serves: "
            f"{sorted(stale)}"
        )

    def test_is_phi_path_matches_classification(self):
        """``_is_phi_path`` agrees with the PHI/config classification for
        every enumerated digests route (the complete net + the
        over-match guard, both edges)."""
        for template, is_phi in self.EXPECTED.items():
            path = self._concrete(template)
            assert _is_phi_path(path) is is_phi, (
                f"{path}: _is_phi_path={_is_phi_path(path)} expected={is_phi}"
            )

    def test_phi_digest_routes_extract_account_id(self):
        """Every PHI-bearing digests route yields its account_id for the
        audit row (classification alone is insufficient — the row must
        carry who/what)."""
        for template, is_phi in self.EXPECTED.items():
            if not is_phi:
                continue
            path = self._concrete(template)
            assert _extract_account_id(path) == 3, (
                f"{path}: account_id not extracted for the audit row"
            )

    def test_planted_phi_digest_route_would_fail_net(self):
        """Teeth demonstrator: a hypothetical new PHI-bearing digests
        route NOT in the regex is classified False — proving the net
        pin would catch the regression (the assertion that would fire in
        ``test_is_phi_path_matches_classification`` if such a route were
        added to EXPECTED as PHI without widening the regex)."""
        planted = "/accounts/3/digests/5/export-matches"
        # Not in the regex → currently False; if someone added it to
        # EXPECTED=True without touching the regex, the classification
        # test above would go RED. This documents the teeth without
        # mutating module state.
        assert _is_phi_path(planted) is False
