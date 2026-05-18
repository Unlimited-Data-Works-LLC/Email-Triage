"""Tests for the /admin/integrations Gmail Pub/Sub admin surface.

Covers the page render, the save handler's YAML round-trip, the
manual renew-watch endpoint's auth gating, and the bounded-backfill
recovery path on history-id expiry. These tests don't talk to Gmail
or GCP -- the watch-renewal path is exercised against a real DB row
with the provider build mocked, and the history-recovery path patches
``provider.list_history`` + ``provider.search`` directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
from email_triage.web.db import upsert_gmail_watch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_gmail_account(db, *, email: str, user_id: int):
    """Insert a minimal email_accounts row tagged provider_type='gmail_api'.

    The schema column is ``name`` (operator label), not
    ``account_name``; ``email_address`` lives on the watch row, not
    on email_accounts. Set the essentials and return the new id.
    """
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            user_id, f"acct-{email}", "gmail_api",
            "{}", now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Page render + auth gating
# ---------------------------------------------------------------------------

class TestAdminIntegrationsPage:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get("/admin/integrations", follow_redirects=False)
        # 303 redirect to /login (set by the admin gate).
        assert resp.status_code in (303, 302)
        assert "/login" in resp.headers.get("location", "")

    def test_regular_user_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/integrations")
        assert resp.status_code == 403

    def test_admin_renders(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        # Re-enable server exceptions for clearer failures here.
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        body = resp.text
        # Form fields are present.
        assert 'name="public_url"' in body
        assert 'name="gmail_topic_name"' in body
        assert 'name="gmail_subscription_sa_email"' in body
        assert 'name="gmail_audience"' in body

    def test_admin_sees_existing_watches(
        self, client, admin_cookies, db, admin_user,
    ):
        acct_id = _add_gmail_account(
            db, email="watched@gmail.com", user_id=admin_user["id"],
        )
        upsert_gmail_watch(
            db,
            account_id=acct_id,
            email_address="watched@gmail.com",
            topic_name="projects/x/topics/y",
            history_id="42",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        assert "watched@gmail.com" in resp.text
        assert "projects/x/topics/y" in resp.text
        # Status bucket should be "healthy" (far-future expires_at).
        assert "healthy" in resp.text

    def test_blank_email_address_falls_back_to_account_config(
        self, client, admin_cookies, db, admin_user,
    ):
        """Stale gmail_watches rows from before the write-time fallback
        landed have empty ``email_address``. The Account column would
        render blank. Read-time fallback now fills from
        ``account.config_json["account"]`` so the column is informative
        even before the operator clicks Renew."""
        # Create a Gmail account with config.account set, then insert a
        # gmail_watches row with email_address=''.
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                admin_user["id"], "stale-gmail", "gmail_api",
                '{"account": "stale@gmail.com"}', now, now,
            ),
        )
        db.commit()
        acct_id = cur.lastrowid
        upsert_gmail_watch(
            db,
            account_id=acct_id,
            email_address="",  # legacy: empty
            topic_name="projects/x/topics/y",
            history_id="0",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        # Fallback should surface the address from config.account.
        assert "stale@gmail.com" in resp.text


# ---------------------------------------------------------------------------
# Save handler — round-trip through _write_config_yaml
# ---------------------------------------------------------------------------

class TestAdminIntegrationsSave:
    def _form(
        self,
        *,
        public_url: str = "https://deployhost.example.ts.net",
        topic: str = "projects/proj-a/topics/gmail-push",
        sa_email: str = "pusher@proj-a.iam.gserviceaccount.com",
        audience: str = "https://deployhost.example.ts.net",
    ):
        return {
            "public_url": public_url,
            "gmail_topic_name": topic,
            "gmail_subscription_sa_email": sa_email,
            "gmail_audience": audience,
        }

    def test_save_normalizes_trailing_slash(
        self, client, admin_cookies, app,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.ui._write_config_yaml",
        ) as mock_write:
            resp = client.post(
                "/admin/integrations/save",
                data=self._form(public_url="https://deployhost.example.ts.net/"),
                follow_redirects=False,
            )
        assert resp.status_code == 303
        # Trailing slash stripped from public_url; in-memory config
        # mutated to the cleaned value.
        assert app.state.config.push.public_url == "https://deployhost.example.ts.net"
        # _write_config_yaml called with the same config object so the
        # YAML emit picks up the cleaned values.
        mock_write.assert_called_once()

    def test_save_lowercases_sa_email(self, client, admin_cookies, app):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            client.post(
                "/admin/integrations/save",
                data=self._form(
                    sa_email="Pusher@Proj-A.IAM.GserviceAccount.COM",
                ),
                follow_redirects=False,
            )
        assert app.state.config.push.gmail_subscription_sa_email == (
            "pusher@proj-a.iam.gserviceaccount.com"
        )

    def test_save_persists_topic(self, client, admin_cookies, app):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            client.post(
                "/admin/integrations/save",
                data=self._form(topic="projects/proj-b/topics/other"),
                follow_redirects=False,
            )
        assert app.state.config.push.gmail_topic_name == (
            "projects/proj-b/topics/other"
        )

    def test_save_yaml_failure_surfaces_in_redirect(
        self, client, admin_cookies,
    ):
        """If _write_config_yaml raises, the redirect carries an err
        query param (operator-visible) instead of crashing the request."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.ui._write_config_yaml",
            side_effect=FileNotFoundError("no yaml found"),
        ):
            resp = client.post(
                "/admin/integrations/save",
                data=self._form(),
                follow_redirects=False,
            )
        assert resp.status_code == 303
        loc = resp.headers["location"]
        assert "err=" in loc

    def test_regular_user_save_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/integrations/save",
            data={
                "public_url": "x", "gmail_topic_name": "t",
                "gmail_subscription_sa_email": "x@y", "gmail_audience": "x",
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Renew-now endpoint
# ---------------------------------------------------------------------------

class TestRenewWatchEndpoint:
    def test_topic_unset_returns_400(
        self, client, admin_cookies, db, admin_user, app,
    ):
        # Default config has empty topic.
        app.state.config.push.gmail_topic_name = ""
        acct_id = _add_gmail_account(
            db, email="x@gmail.com", user_id=admin_user["id"],
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/admin/integrations/{acct_id}/renew-watch",
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "topic_unset"

    def test_unknown_account_returns_404(
        self, client, admin_cookies, app,
    ):
        app.state.config.push.gmail_topic_name = "projects/p/topics/t"
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post("/admin/integrations/99999/renew-watch")
        assert resp.status_code == 404
        assert resp.json()["error"] == "account_not_found"

    def test_non_gmail_account_rejected(
        self, client, admin_cookies, db, admin_user, app,
    ):
        app.state.config.push.gmail_topic_name = "projects/p/topics/t"
        # Insert a non-gmail account.
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                admin_user["id"], "imap-acct", "imap",
                "{}", now, now,
            ),
        )
        db.commit()
        acct_id = cur.lastrowid
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/admin/integrations/{acct_id}/renew-watch",
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "not_gmail"

    def test_anonymous_returns_401(self, client):
        resp = client.post("/admin/integrations/1/renew-watch")
        # Admin gate: redirect-resp converts to 401 here per the JSON
        # branch at the top of the handler.
        assert resp.status_code == 401

    def test_regular_user_returns_403(
        self, client, user_cookies, db, regular_user,
    ):
        acct_id = _add_gmail_account(
            db, email="x@gmail.com", user_id=regular_user["id"],
        )
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/admin/integrations/{acct_id}/renew-watch",
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# D4 — history-id expiry recovery (bounded backfill)
# ---------------------------------------------------------------------------

class TestHistoryExpiryRecovery:
    """When ``provider.list_history`` raises GmailHistoryExpiredError
    (cursor older than Gmail's ~7-day retention window), the consumer
    falls back to a bounded backfill over the last 7 days, capped at
    200 messages. This locks in the recovery path so a future regression
    in _process_push_item doesn't silently drop a week of messages.
    """

    @pytest.mark.asyncio
    async def test_recovery_calls_search_with_7d_200(
        self, app, db, admin_user,
    ):
        """The bounded-backfill query is `newer_than:7d` with limit=200.
        Stricter caps would shrink the recovery window without warning;
        looser caps would invite runaway LLM-quota burn on a high-
        volume mailbox."""
        from email_triage.web.app import _process_push_item
        from email_triage.providers.gmail_api import (
            GmailApiProvider, GmailHistoryExpiredError,
        )

        # Pre-existing watch row pointing at a stale history_id.
        acct_id = _add_gmail_account(
            db, email="recover@gmail.com", user_id=admin_user["id"],
        )
        upsert_gmail_watch(
            db,
            account_id=acct_id,
            email_address="recover@gmail.com",
            topic_name="projects/p/topics/t",
            history_id="100",
            expires_at="2099-01-01T00:00:00+00:00",
        )

        # Fake provider: list_history raises expired; search returns
        # a small list. Capture the search args so we can assert on
        # the recovery contract.
        captured: dict = {}

        class _FakeProvider(GmailApiProvider):  # type: ignore[misc]
            def __init__(self, *a, **kw):
                # Skip the real GmailApiProvider __init__; we only need
                # the methods exercised by _process_push_item.
                pass

            async def list_history(self, *, start_history_id):
                # Real shape carries (status, body, url); body usually
                # the parsed JSON dict from Gmail.
                raise GmailHistoryExpiredError(
                    404,
                    {"error": {"message": "historyId is too old"}},
                    "https://gmail.googleapis.com/gmail/v1/users/me/history",
                )

            async def search(self, query, *, limit=None):
                captured["query"] = query
                captured["limit"] = limit
                return []  # zero recovered messages — exits cleanly

            async def close(self):
                return None

        item = {
            "email": "recover@gmail.com",
            "history_id": "999",  # incoming new id
            "account_id": acct_id,
        }

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=_FakeProvider(),
        ):
            await _process_push_item(app, item)

        assert captured.get("query") == "newer_than:7d"
        assert captured.get("limit") == 200
