"""Shared fixtures for web tests."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from email_triage.config import TriageConfig
from email_triage.web.app import create_app
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    store_otp,
)
from email_triage.web.db import init_db, seed_categories

TEST_SECRET = "test-session-secret-for-signing"


@pytest.fixture
def app():
    """Create a FastAPI app with in-memory database."""
    config = TriageConfig()
    config.persistence.db_path = ":memory:"
    application = create_app(config)
    # Override lifespan manually for testing.
    return application


class _InMemorySecrets:
    """Test-only secrets provider that stores values in a dict."""
    def __init__(self):
        self._store: dict[str, str] = {}
    def get(self, key: str) -> str | None:
        return self._store.get(key)
    def set(self, key: str, value: str) -> None:
        self._store[key] = value
    def list_keys(self) -> list[str]:
        return list(self._store.keys())


@pytest.fixture
def db(app):
    """Set up the database and attach it to the app."""
    import time

    from email_triage.web.app import WatcherManager

    config = TriageConfig()
    conn = init_db(":memory:")
    seed_categories(conn, config.classifier.categories)
    app.state.db = conn
    app.state.config = config
    app.state.session_secret = TEST_SECRET
    app.state.secrets = _InMemorySecrets()
    app.state.watcher_manager = WatcherManager(app)
    app.state.started_at = time.monotonic()
    app.state.version = "testsha1"
    # #82 — install-wide CSRF default is now True (enforce). The vast
    # majority of legacy web tests POST without minting a token and
    # rely on the request reaching the handler. Hold the test fixture
    # at the legacy soft-launch posture so existing coverage stays
    # green; individual CSRF tests opt into enforce by setting
    # ``app.state.csrf_enforce = True`` themselves.
    app.state.csrf_enforce = False
    return conn


@pytest.fixture
def client(app, db):
    """TestClient with database initialized."""
    return TestClient(app, raise_server_exceptions=False)


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
    """Session cookies for the admin user."""
    token = create_session_token(TEST_SECRET, admin_user["email"], admin_user["role"])
    return {SESSION_COOKIE_NAME: token}


@pytest.fixture
def user_cookies(regular_user):
    """Session cookies for a regular user."""
    token = create_session_token(TEST_SECRET, regular_user["email"], regular_user["role"])
    return {SESSION_COOKIE_NAME: token}
