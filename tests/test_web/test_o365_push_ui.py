"""Tests for the per-account Office 365 push Start/Stop UI (F-1).

Bundle F-followup #1. Covers the per-account subscription start/stop
endpoints exposed on the account-edit Integrations panel and the
chip rendering on the same panel.

What's exercised:

* ``POST /accounts/{id}/o365-push/start`` round-trip — happy path
  creates a Graph subscription (mocked) + persists the
  ``office365_subscriptions`` row + writes an ``o365_push_start``
  audit row, and returns 303 to ``/accounts/{id}/edit?tab=integrations``.
* Auth gating — anonymous redirects to /login, non-owner / non-admin /
  non-delegate gets 403, wrong provider type gets 400.
* ``POST /accounts/{id}/o365-push/stop`` — drops the local row even
  if the Graph DELETE call fails (idempotency contract); writes an
  ``o365_push_stop`` audit row.
* Public-URL gate — Start fails fast (no Graph call) when the install
  hasn't configured ``push.public_url``; redirect carries an error
  query string and an audit row is written with outcome=failure.
* Edit-page render — Start button visible only on O365 accounts; the
  same button is hidden on Gmail / IMAP accounts.

The Graph create_subscription / delete_subscription calls are
patched at the provider level so the suite never touches the real
Microsoft Graph API.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.db import (
    delete_o365_subscription,
    get_o365_subscription,
    list_auth_events,
    upsert_o365_subscription,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _seed_o365_account(db, *, user_id: int, name: str = "acct1") -> int:
    """Insert a minimal email_accounts row tagged provider_type='office365'.

    Returns the new account id. ``config_json`` carries placeholder
    Microsoft Graph fields the provider factory expects.
    """
    now = datetime.now(timezone.utc).isoformat()
    cfg = {
        "client_id": "test-client-id",
        "tenant_id": "common",
        "account": "user@example.com",
    }
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "office365", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


def _seed_gmail_account(db, *, user_id: int, name: str = "g-acct") -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "gmail_api",
            '{"account": "user@example.com"}', now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def with_public_url(app):
    """Configure the install with a public URL so Start can build a
    notificationUrl. Tests that exercise the empty-public-url path
    skip this fixture."""
    app.state.config.push.public_url = "https://host.example.ts.net"
    return app


@pytest.fixture
def force_msal_present():
    """Patch ``HAS_MSAL=True`` on the office365 provider module so the
    constructor doesn't bail in CI. The provider's MSAL-only paths
    (``_acquire_token``) are mocked at the call sites that need them
    via ``patch.object`` on ``create_subscription`` /
    ``delete_subscription`` directly. Mirrors the helper used by
    tests/test_web/test_office365_push.py."""
    from email_triage.providers import office365 as o365_mod

    original = getattr(o365_mod, "HAS_MSAL", False)
    o365_mod.HAS_MSAL = True
    try:
        yield
    finally:
        o365_mod.HAS_MSAL = original


# ---------------------------------------------------------------------------
# Start handler
# ---------------------------------------------------------------------------


class TestO365PushStart:
    def test_anonymous_redirects_to_login(self, client, db, admin_user):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/start",
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        assert "/login" in resp.headers.get("location", "")

    def test_non_manager_returns_403(
        self, client, db, regular_user, admin_user, user_cookies, with_public_url,
    ):
        # Admin owns the account; regular_user has no delegate row.
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/start",
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_wrong_provider_type_returns_400(
        self, client, db, admin_user, admin_cookies, with_public_url,
    ):
        # Gmail account; Start should refuse.
        acct_id = _seed_gmail_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/start",
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_account_not_found_returns_404(
        self, client, admin_cookies, with_public_url,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/accounts/99999/o365-push/start",
            follow_redirects=False,
        )
        assert resp.status_code == 404

    def test_public_url_unset_redirects_with_error(
        self, client, db, admin_user, admin_cookies,
    ):
        """No public_url means we can't build a notificationUrl. Start
        must fast-fail with a redirect carrying an error query param
        instead of attempting a Graph call that would fail anyway —
        and an audit row should record the failure for visibility."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/start",
            follow_redirects=False,
        )
        assert resp.status_code == 303
        loc = resp.headers["location"]
        assert f"/accounts/{acct_id}/edit?tab=integrations" in loc
        assert "o365_err=public_url_unset" in loc
        # No DB row created — no Graph call happened.
        assert get_o365_subscription(db, acct_id) is None
        # Audit row written with outcome=failure.
        events = list_auth_events(db, event_type="o365_push_start")
        assert any(
            e.get("outcome") == "failure"
            and e.get("detail") == "public_url_unset"
            for e in events
        )

    def test_happy_path_creates_subscription_and_audit(
        self,
        client,
        db,
        admin_user,
        admin_cookies,
        with_public_url,
        force_msal_present,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        future_iso = "2099-01-02T03:04:05.0000000Z"
        graph_response = {
            "id": "sub-test-1",
            "expirationDateTime": future_iso,
            "resource": "me/mailFolders('Inbox')/messages",
            "changeType": "created",
        }

        # Patch the provider's create_subscription so no real HTTP call
        # is made. Also patch close so the cleanup in finally is a no-op.
        with patch(
            "email_triage.providers.office365.Office365Provider.create_subscription",
            new_callable=AsyncMock,
        ) as mock_create, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_create.return_value = graph_response
            resp = client.post(
                f"/accounts/{acct_id}/o365-push/start",
                follow_redirects=False,
            )
        assert resp.status_code == 303, resp.text
        assert (
            resp.headers["location"]
            == f"/accounts/{acct_id}/edit?tab=integrations"
        )
        # Provider was called with the canonical webhook path.
        mock_create.assert_awaited_once()
        kwargs = mock_create.await_args.kwargs
        assert kwargs["webhook_url"].endswith("/webhooks/office365")
        # DB row persisted.
        row = get_o365_subscription(db, acct_id)
        assert row is not None
        assert row["subscription_id"] == "sub-test-1"
        assert row["status"] == "active"
        # Audit row with outcome=success.
        events = list_auth_events(db, event_type="o365_push_start")
        assert any(e.get("outcome") == "success" for e in events)

    def test_graph_failure_records_audit_failure(
        self, client, db, admin_user, admin_cookies, with_public_url,
        force_msal_present,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.providers.office365.Office365Provider.create_subscription",
            new_callable=AsyncMock,
        ) as mock_create, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_create.side_effect = RuntimeError("Graph 503")
            resp = client.post(
                f"/accounts/{acct_id}/o365-push/start",
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert "o365_err=create_failed" in resp.headers["location"]
        assert get_o365_subscription(db, acct_id) is None
        events = list_auth_events(db, event_type="o365_push_start")
        assert any(e.get("outcome") == "failure" for e in events)


# ---------------------------------------------------------------------------
# Stop handler
# ---------------------------------------------------------------------------


class TestO365PushStop:
    def test_anonymous_redirects_to_login(self, client, db, admin_user):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/stop",
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        assert "/login" in resp.headers.get("location", "")

    def test_non_manager_returns_403(
        self, client, db, regular_user, admin_user, user_cookies,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/stop",
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_wrong_provider_type_returns_400(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_gmail_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365-push/stop",
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_stop_drops_row_and_writes_audit(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-stop-1",
            expiration_at=future,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.providers.office365.Office365Provider.delete_subscription",
            new_callable=AsyncMock,
        ) as mock_delete, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            resp = client.post(
                f"/accounts/{acct_id}/o365-push/stop",
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert (
            resp.headers["location"]
            == f"/accounts/{acct_id}/edit?tab=integrations"
        )
        mock_delete.assert_awaited_once_with("sub-stop-1")
        # Local row dropped.
        assert get_o365_subscription(db, acct_id) is None
        # Audit row with outcome=success.
        events = list_auth_events(db, event_type="o365_push_stop")
        assert any(e.get("outcome") == "success" for e in events)

    def test_stop_drops_row_even_if_graph_delete_fails(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        """Idempotency contract: a Graph 4xx/5xx during DELETE must not
        leave the local row in place. Operator can always retry Start
        cleanly afterwards."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-stop-fail",
            expiration_at=future,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.providers.office365.Office365Provider.delete_subscription",
            new_callable=AsyncMock,
        ) as mock_delete, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_delete.side_effect = RuntimeError("Graph 410 Gone")
            resp = client.post(
                f"/accounts/{acct_id}/o365-push/stop",
                follow_redirects=False,
            )
        assert resp.status_code == 303
        assert get_o365_subscription(db, acct_id) is None

    def test_stop_with_no_existing_row_is_idempotent(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        """Stop on an account that never had a subscription should still
        return 303 and write a stop audit row — no error, no Graph call."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.providers.office365.Office365Provider.delete_subscription",
            new_callable=AsyncMock,
        ) as mock_delete:
            resp = client.post(
                f"/accounts/{acct_id}/o365-push/stop",
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # No Graph call when there's nothing to delete.
        mock_delete.assert_not_awaited()


# ---------------------------------------------------------------------------
# Edit-page render — chip visibility per provider
# ---------------------------------------------------------------------------


class TestO365PushChipRender:
    def test_o365_account_shows_start_button(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=integrations",
        )
        assert resp.status_code == 200
        body = resp.text
        # Section header is the user-facing label.
        assert "Office 365 push" in body
        # The Start Push form posts to the canonical path.
        assert f"/accounts/{acct_id}/o365-push/start" in body
        # OFF state with no subscription row.
        assert "Push: OFF" in body

    def test_o365_account_with_subscription_shows_stop(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-active",
            expiration_at=future,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=integrations",
        )
        assert resp.status_code == 200
        body = resp.text
        assert "Push: ON" in body
        assert f"/accounts/{acct_id}/o365-push/stop" in body
        # Subscription id surfaced (truncated).
        assert "sub-active" in body

    def test_gmail_account_does_not_show_o365_section(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_gmail_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=integrations",
        )
        assert resp.status_code == 200
        body = resp.text
        # Gmail-side chip section header still renders.
        assert "Gmail Pub/Sub push" in body
        # O365 section header should NOT render on a Gmail account.
        assert "Office 365 push" not in body
        assert f"/accounts/{acct_id}/o365-push/start" not in body
