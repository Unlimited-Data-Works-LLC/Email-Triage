"""Tests for FastAPI dependency injection helpers."""

from unittest.mock import MagicMock, patch

import pytest

from email_triage.web.dependencies import (
    get_current_user,
    get_session_secret,
    require_auth,
    require_role,
)
from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
)


def _make_request(cookies=None, app_state=None, url_path="/dashboard", headers=None):
    """Build a mock Request with cookies, headers, and app state."""
    request = MagicMock()
    request.cookies = cookies or {}
    request.headers = headers or {}
    request.url.path = url_path

    state = MagicMock()
    if app_state:
        for k, v in app_state.items():
            setattr(state, k, v)
    else:
        state.session_secret = None
    request.app.state = state
    return request


class TestGetSessionSecret:
    def test_from_app_state(self):
        request = _make_request(app_state={"session_secret": "from-app"})
        assert get_session_secret(request) == "from-app"

    def test_generates_fallback(self):
        request = _make_request(app_state={"session_secret": None})
        secret = get_session_secret(request)
        assert isinstance(secret, str)
        assert len(secret) == 64  # hex of 32 bytes


class TestGetCurrentUser:
    def test_no_cookie(self):
        request = _make_request()
        assert get_current_user(request) is None

    def test_invalid_cookie(self):
        request = _make_request(
            cookies={SESSION_COOKIE_NAME: "garbage"},
            app_state={"session_secret": "test-secret"},
        )
        assert get_current_user(request) is None

    def test_valid_cookie_but_no_user_in_db(self):
        secret = "test-secret"
        token = create_session_token(secret, "ghost@example.com", "user")
        from email_triage.web.db import init_db
        db = init_db(":memory:")

        request = _make_request(
            cookies={SESSION_COOKIE_NAME: token},
            app_state={"session_secret": secret, "db": db},
        )
        request.app.state.db = db
        assert get_current_user(request) is None

    def test_valid_session(self):
        from datetime import datetime, timezone
        from email_triage.web.db import init_db

        secret = "test-secret"
        db = init_db(":memory:")
        db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            ("alice@example.com", "Alice", "admin", datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        token = create_session_token(secret, "alice@example.com", "admin")
        request = _make_request(
            cookies={SESSION_COOKIE_NAME: token},
            app_state={"session_secret": secret, "db": db},
        )
        request.app.state.db = db

        user = get_current_user(request)
        assert user is not None
        assert user["email"] == "alice@example.com"


class TestRequireAuth:
    def test_unauthenticated_api(self):
        request = _make_request(url_path="/api/status", app_state={"session_secret": "s"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_auth(request)
        assert exc_info.value.status_code == 401

    def test_unauthenticated_ui(self):
        request = _make_request(url_path="/dashboard", app_state={"session_secret": "s"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_auth(request)
        assert exc_info.value.status_code == 303


class TestRequireRole:
    def test_correct_role(self):
        from datetime import datetime, timezone
        from email_triage.web.db import init_db

        secret = "test-secret"
        db = init_db(":memory:")
        db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin@test.com", "Admin", "admin", datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        token = create_session_token(secret, "admin@test.com", "admin")
        request = _make_request(
            cookies={SESSION_COOKIE_NAME: token},
            app_state={"session_secret": secret, "db": db},
        )
        request.app.state.db = db

        dep = require_role("admin")
        user = dep(request)
        assert user["role"] == "admin"

    def test_wrong_role(self):
        from datetime import datetime, timezone
        from email_triage.web.db import init_db
        from fastapi import HTTPException

        secret = "test-secret"
        db = init_db(":memory:")
        db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            ("user@test.com", "User", "user", datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        token = create_session_token(secret, "user@test.com", "user")
        request = _make_request(
            cookies={SESSION_COOKIE_NAME: token},
            app_state={"session_secret": secret, "db": db},
        )
        request.app.state.db = db

        dep = require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            dep(request)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# #137 — OwnedAccount dep tests.
# ---------------------------------------------------------------------------


class TestRequireOwnedAccount:
    """Direct invocation tests for ``_require_owned_account``.

    The dep is exercised end-to-end by every migrated handler test
    in test_account_wizard.py / test_accounts.py / etc. — those check
    the 200 happy path. These tests pin the 401 / 404 / 403 error
    shape so future behavior changes don't silently regress the gate.
    """

    def _setup(self, *, with_user=True, with_account=True,
               account_owner_id=1, user_id=1, role="user",
               delegate_user_id=None):
        from datetime import datetime, timezone
        from email_triage.web.db import (
            create_email_account,
            init_db,
            seed_categories,
        )
        from email_triage.config import TriageConfig

        config = TriageConfig()
        db = init_db(":memory:")
        seed_categories(db, config.classifier.categories)

        # Owner exists at id=1 always (so account FK is satisfied).
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("owner@test.com", "Owner", "user", now),
        )
        actor_user = None
        if with_user:
            if user_id == 1:
                actor_user = {
                    "id": 1, "email": "owner@test.com",
                    "name": "Owner", "role": role,
                }
            else:
                cur = db.execute(
                    "INSERT INTO users (email, name, role, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (f"actor{user_id}@test.com", "Actor", role, now),
                )
                actor_user = {
                    "id": cur.lastrowid, "email": f"actor{user_id}@test.com",
                    "name": "Actor", "role": role,
                }
        db.commit()

        account_id = 0
        if with_account:
            account_id = create_email_account(
                db, account_owner_id, "TestAcct",
                provider_type="imap", config={}, is_active=True,
            )
            if delegate_user_id is not None:
                from email_triage.web.db import add_account_delegate
                add_account_delegate(
                    db, account_id, delegate_user_id,
                    granted_by=account_owner_id,
                )

        # Build a minimal request-shaped object that the dep can read.
        class _AppState:
            pass
        state = _AppState()
        state.db = db
        state.secrets = MagicMock()
        request = MagicMock()
        request.app.state = state
        request.url.path = f"/accounts/{account_id}/edit"
        request.headers = {}
        request.cookies = {}
        return db, request, actor_user, account_id

    def test_anonymous_raises_401(self):
        from email_triage.web.dependencies import _require_owned_account
        from fastapi import HTTPException

        db, request, _, account_id = self._setup(with_user=False)
        # Patch get_current_user to return None (no auth).
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=None,
        ):
            with pytest.raises(HTTPException) as exc:
                _require_owned_account(request, account_id)
        assert exc.value.status_code == 401

    def test_unknown_account_raises_404(self):
        from email_triage.web.dependencies import _require_owned_account
        from fastapi import HTTPException

        db, request, user, _ = self._setup(with_account=False)
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=user,
        ):
            with pytest.raises(HTTPException) as exc:
                _require_owned_account(request, 9999)
        assert exc.value.status_code == 404

    def test_non_owner_non_admin_raises_403(self):
        """User exists, account exists, but user is neither owner,
        delegate, nor admin → 403."""
        from email_triage.web.dependencies import _require_owned_account
        from fastapi import HTTPException

        db, request, actor_user, account_id = self._setup(
            user_id=2, account_owner_id=1, role="user",
        )
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=actor_user,
        ):
            with pytest.raises(HTTPException) as exc:
                _require_owned_account(request, account_id)
        assert exc.value.status_code == 403

    def test_owner_unpacks_correctly(self):
        """Owner gets back (user, acct, db, secrets) tuple."""
        from email_triage.web.dependencies import _require_owned_account

        db, request, owner, account_id = self._setup()
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=owner,
        ):
            user, acct, db_out, secrets_out = _require_owned_account(
                request, account_id,
            )
        assert user["id"] == owner["id"]
        assert acct["id"] == account_id
        assert acct["name"] == "TestAcct"
        assert db_out is db
        assert secrets_out is request.app.state.secrets

    def test_admin_passes(self):
        from email_triage.web.dependencies import _require_owned_account

        db, request, admin, account_id = self._setup(
            user_id=2, account_owner_id=1, role="admin",
        )
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=admin,
        ):
            user, acct, _, _ = _require_owned_account(
                request, account_id,
            )
        assert user["role"] == "admin"
        assert acct["id"] == account_id

    def test_delegate_passes(self):
        from email_triage.web.dependencies import _require_owned_account

        db, request, delegate, account_id = self._setup(
            user_id=2, account_owner_id=1, role="user",
            delegate_user_id=2,
        )
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=delegate,
        ):
            user, acct, _, _ = _require_owned_account(
                request, account_id,
            )
        assert user["id"] == delegate["id"]
        assert acct["id"] == account_id


class TestOwnedAccountForProvider:
    """Provider-gated factory variant — used to be ``_verify_account_owner``
    in routers/ui.py for the gmail_api-only paths."""

    def test_wrong_provider_raises_400(self):
        from email_triage.web.dependencies import OwnedAccountForProvider
        from fastapi import HTTPException
        from datetime import datetime, timezone
        from email_triage.web.db import (
            create_email_account, init_db, seed_categories,
        )
        from email_triage.config import TriageConfig

        config = TriageConfig()
        db = init_db(":memory:")
        seed_categories(db, config.classifier.categories)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("o@x.com", "Own", "user", now),
        )
        db.commit()
        owner = {"id": 1, "email": "o@x.com", "role": "user", "name": "Own"}
        # Create an IMAP account, but the dep wants gmail_api.
        aid = create_email_account(
            db, 1, "Acct", provider_type="imap", config={}, is_active=True,
        )

        class _State:
            pass
        st = _State()
        st.db = db
        st.secrets = MagicMock()
        request = MagicMock()
        request.app.state = st
        request.url.path = f"/accounts/{aid}/gmail-api/auth/start"
        request.headers = {}
        request.cookies = {}

        dep = OwnedAccountForProvider("gmail_api")
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=owner,
        ):
            with pytest.raises(HTTPException) as exc:
                dep(request, aid)
        assert exc.value.status_code == 400
        assert "gmail_api" in exc.value.detail


# ---------------------------------------------------------------------------
# #137 phase 2 — OwnedAccountOrLogin tests.
# ---------------------------------------------------------------------------


class TestRequireOwnedAccountOrLogin:
    """Direct tests for ``_require_owned_account_or_login``.

    Same lookup + owner/admin/delegate gate as the base dep, but
    anon → RedirectResponse (303 to /login) instead of raising
    HTTPException 401. Non-owner / not-found still raise 403 / 404.
    """

    def _setup(self, *, with_user=True, with_account=True,
               account_owner_id=1, user_id=1, role="user"):
        from datetime import datetime, timezone
        from email_triage.web.db import (
            create_email_account,
            init_db,
            seed_categories,
        )
        from email_triage.config import TriageConfig

        config = TriageConfig()
        db = init_db(":memory:")
        seed_categories(db, config.classifier.categories)

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("owner@test.com", "Owner", "user", now),
        )
        actor_user = None
        if with_user:
            if user_id == 1:
                actor_user = {
                    "id": 1, "email": "owner@test.com",
                    "name": "Owner", "role": role,
                }
            else:
                cur = db.execute(
                    "INSERT INTO users (email, name, role, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (f"actor{user_id}@test.com", "Actor", role, now),
                )
                actor_user = {
                    "id": cur.lastrowid, "email": f"actor{user_id}@test.com",
                    "name": "Actor", "role": role,
                }
        db.commit()

        account_id = 0
        if with_account:
            account_id = create_email_account(
                db, account_owner_id, "TestAcct",
                provider_type="imap", config={}, is_active=True,
            )

        class _AppState:
            pass
        state = _AppState()
        state.db = db
        state.secrets = MagicMock()
        request = MagicMock()
        request.app.state = state
        request.url.path = f"/accounts/{account_id}/edit"
        request.headers = {}
        request.cookies = {}
        return db, request, actor_user, account_id

    def test_anonymous_returns_redirect_to_login(self):
        """Anon user gets a RedirectResponse(303 → /login), NOT an
        HTTPException. This is the core difference from
        ``_require_owned_account``."""
        from email_triage.web.dependencies import (
            _require_owned_account_or_login,
        )
        from fastapi.responses import RedirectResponse

        db, request, _, account_id = self._setup(with_user=False)
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=None,
        ):
            result = _require_owned_account_or_login(request, account_id)
        assert isinstance(result, RedirectResponse)
        assert result.status_code == 303
        # FastAPI stores the Location in headers.
        assert result.headers["location"] == "/login"

    def test_unknown_account_raises_404(self):
        """Authenticated user, missing account → 404 (matches
        ``_require_owned_account``)."""
        from email_triage.web.dependencies import (
            _require_owned_account_or_login,
        )
        from fastapi import HTTPException

        db, request, user, _ = self._setup(with_account=False)
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=user,
        ):
            with pytest.raises(HTTPException) as exc:
                _require_owned_account_or_login(request, 9999)
        assert exc.value.status_code == 404

    def test_non_owner_non_admin_raises_403(self):
        """Authenticated, account exists, but user lacks rights → 403."""
        from email_triage.web.dependencies import (
            _require_owned_account_or_login,
        )
        from fastapi import HTTPException

        db, request, actor_user, account_id = self._setup(
            user_id=2, account_owner_id=1, role="user",
        )
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=actor_user,
        ):
            with pytest.raises(HTTPException) as exc:
                _require_owned_account_or_login(request, account_id)
        assert exc.value.status_code == 403

    def test_owner_unpacks_correctly(self):
        """Owner gets back (user, acct, db, secrets) tuple — same
        shape as the base dep, ready for ``user, acct, db, secrets =
        ctx`` in handlers."""
        from email_triage.web.dependencies import (
            _require_owned_account_or_login,
        )
        from fastapi.responses import RedirectResponse

        db, request, owner, account_id = self._setup()
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=owner,
        ):
            result = _require_owned_account_or_login(request, account_id)
        # Sanity check: NOT a RedirectResponse on the happy path.
        assert not isinstance(result, RedirectResponse)
        user, acct, db_out, secrets_out = result
        assert user["id"] == owner["id"]
        assert acct["id"] == account_id
        assert acct["name"] == "TestAcct"
        assert db_out is db
        assert secrets_out is request.app.state.secrets

    def test_admin_passes(self):
        """Admin role bypasses owner check (same as base dep)."""
        from email_triage.web.dependencies import (
            _require_owned_account_or_login,
        )
        from fastapi.responses import RedirectResponse

        db, request, admin, account_id = self._setup(
            user_id=2, account_owner_id=1, role="admin",
        )
        with patch(
            "email_triage.web.dependencies.get_current_user",
            return_value=admin,
        ):
            result = _require_owned_account_or_login(request, account_id)
        assert not isinstance(result, RedirectResponse)
        user, acct, _, _ = result
        assert user["role"] == "admin"
        assert acct["id"] == account_id
