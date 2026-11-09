"""Playwright end-to-end harness — fixtures that boot a REAL server.

The unit/web suites drive the app in-process via Starlette's
``TestClient`` (no socket). A real browser can't talk to that, so this
harness boots the SAME ``create_app`` over a real uvicorn socket and
points Playwright at it.

Design — why this looks the way it does
=======================================

* **``lifespan="off"``.** uvicorn normally runs the ASGI lifespan, which
  bootstraps the secrets provider (needs a master key) and starts the
  mailbox watchers / supervised loops (real IMAP/Graph egress). We do
  NOT want either in an e2e test. So we skip the lifespan and stamp
  ``app.state`` by hand — the exact same minimal, inert state the
  ``db`` fixture in ``tests/test_web/conftest.py`` installs for the
  TestClient suite. Same app, same wiring, just served on a socket.

* **uvicorn in a daemon thread.** The canonical pytest-playwright
  pattern (Playwright docs + the FastAPI testing community): build a
  ``uvicorn.Server`` and run it in a background thread, poll ``/health``
  for readiness, set ``server.should_exit`` at teardown. Session-scoped
  because ``create_app`` builds ~4000 routes — far too expensive to
  rebuild per test.

* **Known session secret + minted cookie.** Production sources
  ``session_secret`` from the secrets store in the lifespan; with the
  lifespan off we set a known one, so we can mint a matching
  ``create_session_token`` cookie and inject it into the browser
  context — every spec starts authenticated, no login-UI flow.

* **In-memory DB, shared connection.** The server runs in THIS process,
  so an ``:memory:`` SQLite connection stamped on ``app.state.db`` is
  visible to request handlers (FastAPI's threadpool, ``check_same_thread
  =False`` — single-writer by design, identical to the unit suite).
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

import pytest

# These imports are only reachable when the e2e extra is installed. The
# default test run never collects this directory (``addopts =
# --ignore=tests/e2e`` in pyproject), so a dev without Playwright never
# hits them.
from email_triage.config import TriageConfig
from email_triage.web.app import create_app
from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
from email_triage.web.db import (
    create_email_account,
    init_db,
    seed_categories,
)

# A fixed signing secret + a deterministic test user. The cookie minted
# from these authenticates against the booted server because we stamp
# the SAME secret on ``app.state.session_secret`` below.
E2E_SESSION_SECRET = "e2e-session-secret-for-playwright"
E2E_USER_EMAIL = "e2e-admin@test.local"
E2E_USER_ROLE = "admin"


class _InMemorySecrets:
    """Mirror of the unit suite's test secrets provider.

    The app reads ``app.state.secrets`` for things like the audit-chain
    key plumbing; a dict-backed provider keeps every value local and
    deterministic. (Kept in lock-step with
    ``tests/test_web/conftest.py:_InMemorySecrets``.)
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value

    def list_keys(self) -> list[str]:
        return list(self._store.keys())


def _free_port() -> int:
    """Bind ``:0`` and return the OS-assigned free port (atomic, race-free)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _seed(conn) -> dict:
    """Seed the minimal data the profile specs need.

    One admin user + two accounts they manage (so the "Mailboxes to
    scan" multiselect has real options to render) — one ordinary, one
    HIPAA-flagged (to exercise the 🔒 badge + the HIPAA→registry-only
    note). Both inert: ``push_enabled``/``poll_enabled`` False, so even
    if a watcher path were reached it would skip (it isn't — lifespan is
    off). Topics are created by the specs themselves via the real save
    endpoint, so none is pre-seeded.
    """
    cfg = TriageConfig()
    seed_categories(conn, cfg.classifier.categories)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (E2E_USER_EMAIL, "E2E Admin", E2E_USER_ROLE, now),
    )
    conn.commit()
    user_id = conn.execute(
        "SELECT id FROM users WHERE email=?", (E2E_USER_EMAIL,)
    ).fetchone()["id"]

    inert = {"push_enabled": False, "poll_enabled": False}
    research_id = create_email_account(
        conn, user_id=user_id, name="Research Inbox",
        provider_type="imap", config={**inert, "account": "research@test.local"},
        hipaa=False,
    )
    clinic_id = create_email_account(
        conn, user_id=user_id, name="Clinic Inbox",
        provider_type="imap", config={**inert, "account": "clinic@test.local"},
        hipaa=True,
    )
    return {
        "user_id": user_id,
        "research_account_id": research_id,
        "clinic_account_id": clinic_id,
    }


@pytest.fixture(scope="session")
def e2e_server():
    """Boot ``create_app`` on a real socket (lifespan off, inert, seeded).

    Yields a dict with ``base_url`` + the seeded ids. Session-scoped:
    one boot for the whole e2e run.
    """
    import uvicorn

    # uvicorn opens its own event loop in this thread. On Windows the
    # default Proactor loop is fine for the HTTP server; no policy
    # override is needed for a pure-HTTP app (no asyncio subprocesses).
    config = TriageConfig()
    config.persistence.db_path = ":memory:"

    app = create_app(config)

    # Stamp the SAME inert app.state the TestClient ``db`` fixture builds
    # (tests/test_web/conftest.py). ``create_app`` already set
    # ``app.state.templates`` in its synchronous body.
    from email_triage.web.app import WatcherManager
    from email_triage.web.task_supervisor import TaskSupervisor

    conn = init_db(":memory:")
    seeded = _seed(conn)
    app.state.db = conn
    app.state.config = config
    app.state.session_secret = E2E_SESSION_SECRET
    app.state.secrets = _InMemorySecrets()
    app.state.watcher_manager = WatcherManager(app)
    app.state.supervisor = TaskSupervisor()
    app.state.started_at = time.monotonic()
    app.state.version = "e2e-test"
    # CSRF enforcement migration step 2 — ENFORCE, matching prod (and the unit
    # tier). The real rendered forms carry their ``csrf_input`` hidden field, and
    # the browser submits it, so the middleware's form-field path validates it
    # against the session. A form missing ``csrf_input`` will 403 here (correct —
    # that's a real prod bug the browser tier should catch).
    app.state.csrf_enforce = True

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    uv_config = uvicorn.Config(
        app, host="127.0.0.1", port=port, lifespan="off", log_level="error",
    )
    server = uvicorn.Server(uv_config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Readiness: poll /health until the ASGI app is SERVING. We accept
    # 200 (ok) AND 503 (degraded) as "ready" — a 503 here means the app
    # is fully mounted and routing but the health snapshot is degraded
    # (our seeded accounts are inert, so they read as "uncovered
    # mailboxes" => degraded). That's a valid running state for e2e and
    # does not affect page rendering. Only a connection error / timeout
    # means "not up yet"; keep polling on those.
    deadline = time.monotonic() + 20.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        if server.should_exit:  # pragma: no cover - defensive
            break
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as r:
                if r.status == 200:
                    break
        except urllib.error.HTTPError as http_exc:
            # The server answered with an HTTP status (e.g. 503 degraded)
            # => it is up and routing. Ready.
            if http_exc.code == 503:
                break
            last_err = http_exc
        except Exception as exc:  # noqa: BLE001 - connection not up yet
            last_err = exc
        time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError(
            f"e2e server did not become ready at {base_url}/health "
            f"within 20s (last error: {last_err!r})"
        )

    try:
        # ``conn`` is exposed so specs can seed dynamic server-side state
        # (e.g. a reindex job) into the SAME in-memory DB the server reads.
        # ``app`` is exposed so walk specs (e.g. tests/e2e/walk/
        # test_ops_db_backup_trigger.py) can reach app.state.config to flip
        # per-test config without re-importing create_app.
        yield {"base_url": base_url, "port": port, "conn": conn, "app": app, **seeded}
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def base_url(e2e_server) -> str:
    """pytest-playwright reads ``base_url`` to resolve ``page.goto('/...')``."""
    return e2e_server["base_url"]


@pytest.fixture
def e2e_cookie(e2e_server) -> dict:
    """A Playwright cookie dict authenticating as the seeded admin.

    Minted from the SAME secret stamped on the server, so the auth
    middleware validates it. ``mfa_verified_at`` is set so the HIPAA
    hard-cutover middleware accepts the session (mirrors ``admin_cookies``
    in the unit suite).
    """
    token = create_session_token(
        E2E_SESSION_SECRET, E2E_USER_EMAIL, E2E_USER_ROLE,
        mfa_verified_at=int(time.time()),
    )
    return {
        "name": SESSION_COOKIE_NAME,
        "value": token,
        "url": e2e_server["base_url"],
    }


@pytest.fixture
def authed_page(page, e2e_cookie):
    """A Playwright ``page`` whose context already carries the session cookie.

    Add the cookie BEFORE the spec navigates, so the first ``goto`` is
    authenticated. Specs take ``authed_page`` instead of ``page``.
    """
    page.context.add_cookies([e2e_cookie])
    return page


@pytest.fixture(autouse=True)
def _hermetic_jobs(e2e_server):
    """Every e2e spec starts with NO in-flight ``topic_backscan``.

    The server is session-scoped (one ``:memory:`` DB for the whole run) and
    boots ``lifespan="off"``, so the bulk runner never drains: a
    ``topic_backscan`` a prior spec left QUEUED lingers in ``triage_jobs`` and
    trips the install-wide single-flight guard in a LATER spec. That
    later spec's Re-Triage then enqueues nothing (``queued: 0``); because the
    lingering job belongs to a DIFFERENT topic, the handler's recovery lookup
    can't adopt it, so the live-status fragment (``#topic-retriage-status``)
    never renders and the spec fails — but ONLY in-suite, never standalone (a
    fresh DB), the classic order-dependent flake. Concretely the 
    ceiling-banner spec seeds a ``topic_backscan`` and never clears it, which
    is exactly what broke the  retriage spec once its (separate) spinner-id
    fix let part (2) run.

    Cancelling any in-flight backscan before each spec makes the jobs surface
    per-test hermetic. We UPDATE (not DELETE) so the rows survive — a spec that
    GETs a specific job by id (e.g. the ceiling-banner progress fragment) is
    unaffected — and 'cancelled' is terminal, so the single-flight guard
    (``status IN ('queued','running')``) no longer counts it.
    """
    conn = e2e_server["conn"]
    conn.execute(
        "UPDATE triage_jobs SET status='cancelled' "
        "WHERE kind='topic_backscan' AND status IN ('queued', 'running')"
    )
    conn.commit()
    yield
