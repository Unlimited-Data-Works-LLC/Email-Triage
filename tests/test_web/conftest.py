"""Shared fixtures for web tests."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import State

from email_triage.config import TriageConfig
from email_triage.web.app import create_app
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    store_otp,
)
from email_triage.web.db import init_db, seed_categories

TEST_SECRET = "test-session-secret-for-signing"


@pytest.fixture(scope="session")
def _session_app():
    """The session-scoped FastAPI app — built once.

    ``create_app`` builds ~4000 FastAPI routes, the dominant per-file
    cost of the web test suite. Build them once and share the app for
    the whole session; ``_reset_app_state`` restores per-test
    ``app.state`` isolation around it.

    Also snapshots the ``app.state`` that ``create_app`` itself
    populates (notably ``app.state.templates``, set in the synchronous
    body of ``create_app`` — not in the lifespan, which the default
    ``client`` fixture never enters). ``_reset_app_state`` restores
    from this snapshot so create-time state survives the per-test
    wipe; only the keys individual tests stamp are discarded.
    """
    config = TriageConfig()
    config.persistence.db_path = ":memory:"
    application = create_app(config)
    base_state = dict(application.state._state)
    return application, base_state


@pytest.fixture
def app(_session_app):
    """The shared FastAPI app, with ``app.state`` reset for this test.

    Thin accessor over ``_session_app`` — the autouse
    ``_reset_app_state`` has already restored a clean ``app.state``
    before this fixture is reached.
    """
    application, _ = _session_app
    return application


@pytest.fixture(autouse=True)
def _reset_app_state(_session_app):
    """Give every test a fresh ``app.state``.

    The app is session-scoped, so without this the ``app.state``
    mutations one test makes would leak into the next. Replace the
    whole ``State`` — restored from the post-``create_app`` snapshot
    rather than emptied — so a future test that stamps a new attribute
    is discarded automatically, while the state ``create_app`` set up
    (``templates``, etc.) is preserved. Verified safe to swap the
    whole object: nothing in ``app.py`` captures the ``State`` by
    reference; every access is ``app.state.<attr>`` dereferenced fresh.

    Autouse, so it fires even for a test that takes bare ``app`` with
    no ``db``. The ``db`` fixture *also* takes this as an explicit
    parameter — that pins the reset→db ordering edge (see ``db``).
    Being reached via both paths is intentional: pytest deduplicates
    a fixture reached more than once, so it still runs exactly once
    per test.
    """
    application, base_state = _session_app
    #  — SETUP-side audit-write drain (belt to ``_drain_audit_writes_after_
    # test``'s teardown braces). A prior test's fire-and-forget audit task can
    # register on ``_audit_pending`` slightly AFTER its response returned, so
    # that test's TEARDOWN drain may have polled an empty set and passed before
    # the task appeared. The undrained task then runs into THIS test and bumps
    # the session-shared ``audit_failures`` counter / races the about-to-be-
    # swapped db conn — the run-to-run full-tree flake (; e.g.
    # test_audit_failure_increments_counter intermittently seeing 2, not 1).
    # Draining here BEFORE the state swap guarantees any lagging task finishes
    # (bumping the about-to-be-discarded OLD state) so THIS test starts clean,
    # regardless of the prior test's exit timing. Bounded poll; absent set =
    # nothing to drain.
    import time as _time
    _pending = getattr(application.state, "_audit_pending", None)
    if _pending:
        _deadline = _time.monotonic() + 5.0
        # Snapshot before iterating: task.add_done_callback(pending.discard)
        # mutates the set from the portal thread on task completion, which
        # concurrently races the main-thread iteration in ``all(...)`` —
        # under full-sweep timing this raised ``RuntimeError: Set changed
        # size during iteration`` in the fixture (TaskList #4).
        while _time.monotonic() < _deadline and not all(t.done() for t in list(_pending)):
            _time.sleep(0.02)
    # 2026-07-10 drain-race root-cause fix: reset the swallow stash so a
    # prior test's swallowed audit-write exception does not false-trip the
    # next test's fail-fast drain check. See _audit._LAST_AUDIT_EXC.
    from email_triage.web._audit import clear_last_audit_exc
    clear_last_audit_exc()
    application.state = State(dict(base_state))
    return None


@pytest.fixture(autouse=True)
def _drain_audit_writes_after_test(_session_app):
    """Drain fire-and-forget audit-write tasks at the end of every test.

    The access-audit middleware makes the PHI-path audit write
    fire-and-forget: it ``asyncio.create_task``s the write and tracks
    the task on ``app.state._audit_pending``. ``TestClient`` returns as
    soon as the *response* is sent — the write task can still be
    pending on the TestClient portal's loop.

    Left undrained, that lagging task crosses the test boundary: the
    next test's ``db`` fixture swaps ``app.state.db`` for a fresh
    in-memory connection while the previous test's audit ``db_call``
    worker is still mid-write, and the two race on the shared
    connection / write lock — a non-deterministic 500 on the next
    request (the test_labels.py cross-class flake). Draining here, at
    teardown, closes the class of flake for *every* web test rather
    than per-file.

    Bounded poll: a genuinely stuck write raises rather than hanging
    the suite. The ``_audit_pending`` set is created lazily on the
    first PHI-path request — absent set means nothing to drain.
    """
    import time as _time

    yield
    application, _ = _session_app
    deadline = _time.monotonic() + 5.0
    while _time.monotonic() < deadline:
        pending = getattr(application.state, "_audit_pending", None)
        # Snapshot before iterating — see the SETUP-side drain above
        # for the RuntimeError-under-load race (TaskList #4).
        if pending is None or all(t.done() for t in list(pending)):
            return
        _time.sleep(0.02)
    raise AssertionError(
        "audit-write tasks did not drain within 5s — "
        "app.state._audit_pending still has in-flight tasks at "
        "test teardown"
    )


@pytest.fixture(autouse=True)
def _cancel_pending_tasks_after_test(_session_app):
    """Drain non-audit fire-and-forget asyncio tasks at the end of every test.

    Sibling of ``_drain_audit_writes_after_test``. The audit drain
    only covers the PHI-path audit-write task class; this drain covers
    the rest:

      * ``app.state._fire_and_forget_pending`` — the registry the
        ``embedding_install`` handlers add into (and any future bare
        ``create_task`` site that mirrors the canonical pattern).
      * ``app.state.watcher_manager._tasks`` — the per-mailbox
        watcher tasks. ``WatcherManager(app)`` is re-instantiated
        per-test in the ``db`` fixture; without explicit cancel, the
        previous instance's tasks survive on the dying TestClient
        portal loop until gc, accumulating across the suite (the 
        IOCP-wedge hypothesis).
      * ``app.state.supervisor`` — ``stop_all()`` cancels every
        supervised task with the supervisor's own 3s per-task timeout.

    All three drains are best-effort + bounded; a stuck task raises
    AssertionError instead of hanging the suite. Mirrors the
    ``_drain_audit_writes_after_test`` shape exactly so the failure
    mode is consistent.
    """
    import asyncio as _asyncio
    import time as _time

    yield
    application, _ = _session_app

    # Cancel watcher_manager._tasks (per-test instance dict; the test
    # may have left running mailbox-watcher coroutines behind).
    wm = getattr(application.state, "watcher_manager", None)
    # Tests legitimately swap in a fake watcher_manager that mirrors the
    # PUBLIC interface (all_statuses/account_states/...) but not the
    # private ``_tasks`` dict. This drain is best-effort, so a manager
    # with no real tasks simply has nothing to cancel — read defensively.
    wm_tasks = getattr(wm, "_tasks", {}) or {}
    if wm is not None:
        for task in list(wm_tasks.values()):
            if not task.done():
                task.cancel()

    # Cancel fire-and-forget tasks (embedding_install + future sites).
    pending = getattr(application.state, "_fire_and_forget_pending", None)
    if pending is not None:
        for task in list(pending):
            if not task.done():
                task.cancel()

    # Drain — bounded poll matching _drain_audit_writes_after_test
    # shape. 5s deadline; if a task refuses to cancel in that window
    # the test surfaces it rather than the suite hanging.
    deadline = _time.monotonic() + 5.0
    while _time.monotonic() < deadline:
        # Snapshot both collections before iterating — cancel-done
        # callbacks discard entries concurrently from the portal
        # thread (TaskList #4 race class).
        wm_done = all(t.done() for t in list(wm_tasks.values()))
        pending_done = pending is None or all(t.done() for t in list(pending))
        if wm_done and pending_done:
            break
        _time.sleep(0.02)
    else:
        raise AssertionError(
            "fire-and-forget tasks did not drain within 5s — "
            "watcher_manager._tasks or app.state._fire_and_forget_pending "
            "still has in-flight tasks at test teardown"
        )

    # supervisor.stop_all() is an async cancel-and-wait; run it on a
    # short-lived loop. Best-effort — any failure is logged via the
    # supervisor's own handling, never propagated to the test.
    sup = getattr(application.state, "supervisor", None)
    if sup is not None:
        try:
            _asyncio.run(sup.stop_all())
        except Exception:
            pass


class _InMemorySecrets:
    """Test-only secrets provider that stores values in a dict."""
    def __init__(self):
        self._store: dict[str, str] = {}
    def get(self, key: str) -> str | None:
        return self._store.get(key)
    def set(self, key: str, value: str) -> None:
        self._store[key] = value
    def delete(self, key: str) -> bool:
        if key in self._store:
            del self._store[key]
            return True
        return False
    def list_keys(self) -> list[str]:
        return list(self._store.keys())


@pytest.fixture
def db(app, _reset_app_state):
    """Set up the database and attach it to the app.

    Depends on ``_reset_app_state`` explicitly — not for its return
    value (it returns None) but to force the ordering reset→db. The
    ``app`` fixture is session-scoped; if the autouse reset ran
    *after* ``db`` it would wipe the ``app.state.db`` this fixture
    just installed. The dependency edge makes the order deterministic
    rather than relying on pytest's autouse-vs-explicit heuristic.

    Teardown closes the connection. Any fire-and-forget task that
    *captured* this connection (the access-audit middleware does, for
    a PHI-path request) and lags past the test boundary will, at most,
    see a clean ``sqlite3.ProgrammingError`` on its next operation —
    surfaced inside the lagging task's own try/except (the audit-write
    catches ``Exception`` and bumps ``audit_failures``). Without the
    close, a lagging task continues writing to a connection that is
    semantically dead but still open, and the test that next observes
    a residual race surfaces it as a non-deterministic 500 in an
    unrelated test (the original ``test_labels`` / ``test_discover``
    cross-class flake — ). The audit-pending drain
    (``_drain_audit_writes_after_test``) addresses the *audit* variant
    of fire-and-forget; closing the connection here closes the
    leak-channel class for every fire-and-forget shape, not just
    audit.
    """
    import time

    from email_triage.web.app import WatcherManager
    from email_triage.web.task_supervisor import TaskSupervisor

    config = TriageConfig()
    conn = init_db(":memory:")
    seed_categories(conn, config.classifier.categories)
    app.state.db = conn
    app.state.config = config
    app.state.session_secret = TEST_SECRET
    app.state.secrets = _InMemorySecrets()
    app.state.watcher_manager = WatcherManager(app)
    #  — wire the TaskSupervisor so the watcher-start path takes
    # the supervisor branch at ``web/app.py:878`` instead of falling
    # through to the bare-task fallback at ``:887``. Production sets
    # ``app.state.supervisor`` (NOT ``task_supervisor``) at the
    # lifespan in ``app.py:2240``; the watcher reads it via
    # ``getattr(self.app.state, "supervisor", None)`` at ``app.py:853``.
    # The attribute name match is load-bearing — db-sme's scope-add on
    # the investigation verdict caught this naming bug pre-implement.
    app.state.supervisor = TaskSupervisor()
    app.state.started_at = time.monotonic()
    app.state.version = "testsha1"
    #  — install-wide CSRF default is now True (enforce). The shared `client`
    # fixture is now the token-injecting `_CsrfClient`, which auto-mints a valid
    # X-CSRF-Token on guarded requests, so the test posture MATCHES the live prod
    # posture (enforce=True) and a route that stops requiring a token is caught.
    # (CSRF-enforcement migration step 2 — flipped from the legacy soft-launch
    # default.) The hand-rolled negative tests in test_csrf.py mint their own
    # tokens / set their own headers and are not disturbed (the injector is
    # idempotent). A test that needs the OLD soft posture sets
    # ``app.state.csrf_enforce = False`` itself.
    app.state.csrf_enforce = True
    try:
        yield conn
    finally:
        # Teardown order: pytest finalizes in REVERSE setup order, so
        # this ``db`` finalizer runs BEFORE the audit-pending drain.
        # That ordering is what we want. Closing the connection first
        # forces any lagging fire-and-forget worker (e.g. an audit-
        # write threadpool worker mid-INSERT on this very ``conn``) to
        # surface a clean ``sqlite3.ProgrammingError`` on its next
        # operation — caught inside ``_audit_write``'s own try/except,
        # the task transitions to ``done()`` with an exception, and
        # the subsequent ``_drain_audit_writes_after_test`` poll
        # immediately sees ``all(t.done())`` and returns. Without
        # this close, the lagging worker keeps using a live handle to
        # a connection the test is conceptually finished with; any
        # *non-audit* fire-and-forget shape (``embedding_install``'s
        # background task, future code paths) that the drain does not
        # cover would then leave a live writer on stale state into
        # the next test's window.
        try:
            conn.close()
        except Exception:
            # A connection that's already been closed (or never fully
            # opened) is harmless — the goal here is "no live handle
            # crosses the test boundary"; do not let cleanup itself
            # become a new failure source.
            pass


@pytest.fixture
def strict_undefined_templates(app):
    """Render templates under Jinja ``StrictUndefined`` for this test.

    Production uses Jinja's default lenient ``Undefined`` so a template
    that reads a missing attribute renders an empty string and never
    500s the user. The cost: a template↔handler CONTRACT-DRIFT bug (a
    template reading a key the handler never provides) produces silent
    blank/wrong output that NO test catches unless it asserts on the
    rendered content. That blind spot shipped three such bugs in the 
    Topic editor (the blank account multiselect; the digest options that
    neither saved nor displayed).

    Opt into this fixture in a render test to make those bugs LOUD: under
    ``StrictUndefined`` a missing-attr read raises ``UndefinedError`` →
    the route returns 500, so ``assert resp.status_code == 200`` fails at
    test time. Save/restore the shared env's undefined handler (the
    session app's Jinja ``Environment`` is one object across tests).

    Reusable for any page — extend coverage to more routes over time.
    """
    from jinja2 import StrictUndefined
    env = app.state.templates.env
    prior = env.undefined
    env.undefined = StrictUndefined
    try:
        yield
    finally:
        env.undefined = prior


@pytest.fixture
def client(app, db):
    """TestClient with database initialized.

    Now the token-injecting ``_CsrfClient`` (CSRF-enforcement migration step 2):
    it auto-mints a valid X-CSRF-Token on guarded POST/PUT/PATCH/DELETE so the
    functional POST suite runs under enforce=True (matching prod) without each
    test hand-minting a token. Idempotent — a test that supplies its own token
    (header / data= / json= csrf_token) is untouched."""
    return _CsrfClient(app, raise_server_exceptions=False)


@pytest.fixture
def raw_client(app, db):
    """A PLAIN TestClient with NO CSRF auto-injection — for the CSRF negative
    SSOT (test_csrf.py), which mints / withholds tokens itself to assert the
    enforce + reject behaviour. The shared ``client`` injects a valid token,
    which would mask a no-token negative assertion (the exact thing those tests
    exist to prove)."""
    return TestClient(app, raise_server_exceptions=False)


class _CsrfClient(TestClient):
    """A TestClient that auto-mints + injects a VALID CSRF token (the
    ``X-CSRF-Token`` header) on guarded POST/PUT/PATCH/DELETE requests, so a
    functional POST test can run under ``csrf_enforce=True`` WITHOUT hand-minting
    a token per call.

    Step 1 of the CSRF-test-enforcement migration — this is OPT-IN via the
    ``csrf_client`` fixture; the shared ``client`` fixture and the soft-launch
    default (conftest ``app.state.csrf_enforce = False``) are UNCHANGED.

    The token is minted from THIS request's session cookie + the live
    ``app.state.session_secret`` (the SAME secret the middleware verifies with),
    so it composes with any user/admin session automatically. Idempotent: if the
    caller already passed an ``X-CSRF-Token`` header OR a ``csrf_token`` form
    field, inject NOTHING — so the hand-rolled negative tests in test_csrf.py are
    never disturbed. No session cookie => inject nothing (preserves the
    middleware's anonymous short-circuit, csrf.py:295)."""

    _GUARDED = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        self._csrf_app = app

    def request(self, method, url, **kwargs):
        if str(method).upper() in self._GUARDED:
            headers = dict(kwargs.get("headers") or {})
            data = kwargs.get("data")
            json_body = kwargs.get("json")
            has_header = any(k.lower() == "x-csrf-token" for k in headers)
            # Token already supplied as a form field (data=) OR a JSON field
            # (json=) — inject nothing, so a hand-rolled negative test that posts
            # a deliberately-bad token (header check runs first, so an injected
            # header would mask it) is never disturbed.
            has_field = (
                (isinstance(data, dict) and "csrf_token" in data)
                or (isinstance(json_body, dict) and "csrf_token" in json_body)
            )
            if not has_header and not has_field:
                from email_triage.web.auth import SESSION_COOKIE_NAME
                call_cookies = kwargs.get("cookies") or {}
                session_token = (
                    (call_cookies.get(SESSION_COOKIE_NAME)
                     if isinstance(call_cookies, dict) else None)
                    or self.cookies.get(SESSION_COOKIE_NAME)
                )
                if session_token:
                    from email_triage.web.csrf import (
                        CSRF_HEADER_NAME, mint_csrf_token,
                    )
                    secret = getattr(
                        self._csrf_app.state, "session_secret", "") or ""
                    if secret:
                        headers[CSRF_HEADER_NAME] = mint_csrf_token(
                            secret, session_token)
                        kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


@pytest.fixture
def csrf_client(app, db):
    """OPT-IN client that runs with CSRF **enforced** + auto-injects a valid
    token on guarded requests. Use this for new / migrated POST tests so a route
    that stops requiring a token is actually caught (the shared ``client`` stays
    soft-launch until the migration flips the default last)."""
    app.state.csrf_enforce = True
    return _CsrfClient(app, raise_server_exceptions=False)


def pytest_sessionfinish(session, exitstatus):
    """Print the CSRF reject tally at the end of the run — the by-route shapes
    that POSTed without a valid token under soft-launch (the routes still on the
    plain ``client``; they shrink as files adopt ``csrf_client``). Best-effort.

    IMPORTANT — this is MIGRATION PROGRESS, **not a CSRF-coverage report**: a
    route already on ``csrf_client`` (token injected) never appears, and a route
    with NO csrf test at all is INVISIBLE. An empty tally means "no soft-launch
    token-less POSTs were seen this run", NOT "every route is csrf-protected" —
    the negative coverage SSOT is ``test_csrf.py`` (and the step-2 route-table
    pin). Under ``pytest-xdist`` the tally is PER-WORKER, so this prints once per
    worker, not a unified suite-wide view."""
    try:
        from email_triage.web.csrf import csrf_reject_report
        report = csrf_reject_report()
    except Exception:
        return
    if not report:
        return
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    lines = [f"  {n:>4}  {route}" for route, n in
             sorted(report.items(), key=lambda kv: (-kv[1], kv[0]))]
    msg = ("Routes POSTed token-less under soft-launch (route shape -> count) — "
           "migrate these onto csrf_client. This is MIGRATION PROGRESS, NOT a "
           "csrf-coverage report (a route with no csrf test is invisible; "
           "per-worker under xdist):\n" + "\n".join(lines))
    if tr is not None:
        tr.write_sep("=", "CSRF migration: token-less POSTs seen (not coverage)")
        tr.write_line(msg)


@pytest.fixture
def admin_user(db):
    """Create an admin user and return their details."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("admin@test.com", "Test Admin", "admin", now),
    )
    db.commit()
    return {"id": cursor.lastrowid, "email": "admin@test.com", "name": "Test Admin", "role": "admin"}


@pytest.fixture
def regular_user(db):
    """Create a regular user and return their details."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("user@test.com", "Test User", "user", now),
    )
    db.commit()
    return {"id": cursor.lastrowid, "email": "user@test.com", "name": "Test User", "role": "user"}


@pytest.fixture
def admin_cookies(admin_user):
    """Session cookies for the admin user.

    H-05 (Cycle 7): the test session stamps ``mfa_verified_at`` so
    the hard-cutover middleware (``require_auth`` extension at
    ``dependencies.py``) accepts the session even when a test flips
    HIPAA mode on mid-flight. Tests that exercise the OTP-rejection-
    in-HIPAA-mode gate use the helper at ``web.mfa`` directly rather
    than this fixture (see ``tests/test_web/test_mfa.py``).
    """
    import time
    token = create_session_token(
        TEST_SECRET, admin_user["email"], admin_user["role"],
        mfa_verified_at=int(time.time()),
    )
    return {SESSION_COOKIE_NAME: token}


@pytest.fixture
def user_cookies(regular_user):
    """Session cookies for a regular user.

    H-05 (Cycle 7): see ``admin_cookies`` docstring for the
    ``mfa_verified_at`` stamp rationale.
    """
    import time
    token = create_session_token(
        TEST_SECRET, regular_user["email"], regular_user["role"],
        mfa_verified_at=int(time.time()),
    )
    return {SESSION_COOKIE_NAME: token}


@pytest.fixture
def power_user(db):
    """Create a power_user and return their details (N-60 rule-authz tests).

    A power_user is scoped to own-personal + GLOBAL lists; the rule gates must
    NOT let them touch another user's personal list (Loop-5 census)."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("power@test.com", "Test Power", "power_user", now),
    )
    db.commit()
    return {"id": cursor.lastrowid, "email": "power@test.com",
            "name": "Test Power", "role": "power_user"}


@pytest.fixture
def power_user_cookies(power_user):
    """Session cookies for a power_user."""
    import time
    token = create_session_token(
        TEST_SECRET, power_user["email"], power_user["role"],
        mfa_verified_at=int(time.time()),
    )
    return {SESSION_COOKIE_NAME: token}
