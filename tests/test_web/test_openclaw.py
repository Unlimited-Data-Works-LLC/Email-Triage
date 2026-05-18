"""Tests for the /api/openclaw/* bearer-token API."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_account(db, user_id, *, hipaa=False, name="Acct", ptype="imap"):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, ptype,
         json.dumps({"host": "mail.test.com", "username": "x@y.com"}),
         1 if hipaa else 0, now, now),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def api_key(db, admin_user):
    """Create an API key for admin_user, return raw value + cookies dict."""
    from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), name="test", user_id=admin_user["id"])
    return raw


@pytest.fixture
def bearer(api_key):
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture
def fake_provider():
    """A MagicMock provider exposing the EmailProvider interface."""
    p = MagicMock()
    p.search = AsyncMock(return_value=["m1", "m2"])
    p.fetch_message = AsyncMock(return_value=MagicMock(
        message_id="m1", thread_id="t1", sender="a@b.com",
        recipients=["x@y.com"], subject="Hi", body_text="Hello",
        date=datetime.now(timezone.utc), labels=["INBOX"], headers={},
    ))
    p.apply_label = AsyncMock(return_value=None)
    p.move_message = AsyncMock(return_value=None)
    p.archive = AsyncMock(return_value=None)
    p.create_draft = AsyncMock(return_value="draft-1")
    p.close = AsyncMock(return_value=None)
    return p


@pytest.fixture
def patch_provider(fake_provider):
    """Stub _create_provider_from_account to return our fake."""
    with patch(
        "email_triage.web.routers.openclaw._create_provider_from_account",
        create=True,
    ):
        # The router imports it lazily inside endpoints; patch the source.
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            yield fake_provider


# ---------------------------------------------------------------------------
# Auth + HIPAA gate
# ---------------------------------------------------------------------------

class TestAuth:
    def test_missing_bearer_is_401(self, client):
        resp = client.get("/api/openclaw/accounts")
        assert resp.status_code == 401

    def test_unknown_bearer_is_401(self, client):
        resp = client.get(
            "/api/openclaw/accounts",
            headers={"Authorization": "Bearer et_does_not_exist"},
        )
        assert resp.status_code == 401

    def test_valid_bearer_lists_accounts(self, client, db, admin_user, bearer):
        _make_account(db, admin_user["id"], name="Work")
        resp = client.get("/api/openclaw/accounts", headers=bearer)
        assert resp.status_code == 200
        data = resp.json()
        assert "accounts" in data
        assert any(a["name"] == "Work" for a in data["accounts"])


class TestHipaaGate:
    def test_hipaa_account_excluded_from_list(self, client, db, admin_user, bearer):
        _make_account(db, admin_user["id"], hipaa=True, name="PHI Inbox")
        _make_account(db, admin_user["id"], hipaa=False, name="Work")
        resp = client.get("/api/openclaw/accounts", headers=bearer)
        assert resp.status_code == 200
        names = [a["name"] for a in resp.json()["accounts"]]
        assert "Work" in names
        assert "PHI Inbox" not in names

    def test_hipaa_account_direct_fetch_403(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/messages?q=is:unread",
            headers=bearer,
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["detail"]["error"] == "hipaa_blocked"

    def test_hipaa_account_triage_403(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/triage",
            json={"query": "is:unread", "limit": 1},
            headers=bearer,
        )
        assert resp.status_code == 403


class TestOwnership:
    def test_other_users_account_is_403(
        self, client, db, regular_user, admin_user,
    ):
        from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
        # Token belongs to regular_user.
        raw = generate_api_key()
        store_api_key(db, hash_api_key(raw), name="t", user_id=regular_user["id"])
        bearer = {"Authorization": f"Bearer {raw}"}

        aid = _make_account(db, admin_user["id"], name="AdminBox")
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/messages?q=ALL",
            headers=bearer,
        )
        assert resp.status_code == 403

    def test_admin_token_does_not_bypass_other_user_account(
        self, client, db, admin_user, regular_user, bearer,
    ):
        """OpenClaw is strict-per-user even for admins. Admin's
        bearer token can fetch admin's accounts but NOT regular
        user's accounts. Cross-user visibility belongs in the web
        UI, not in agent-driven API access. (Punch-list 2026-04-30)"""
        # ``bearer`` fixture is admin's token. Account belongs to
        # regular_user.
        other_aid = _make_account(
            db, regular_user["id"], name="OtherUserBox",
        )
        resp = client.get(
            f"/api/openclaw/accounts/{other_aid}/messages?q=ALL",
            headers=bearer,
        )
        assert resp.status_code == 403

    def test_admin_token_lists_only_own_accounts(
        self, client, db, admin_user, regular_user, bearer,
    ):
        """List endpoint excludes accounts the admin doesn't own /
        delegate. Cross-user view stays in the web UI."""
        _make_account(db, admin_user["id"], name="AdminBox")
        _make_account(db, regular_user["id"], name="OtherBox")
        resp = client.get(
            "/api/openclaw/accounts", headers=bearer,
        )
        assert resp.status_code == 200
        names = [a["name"] for a in resp.json()["accounts"]]
        assert "AdminBox" in names
        assert "OtherBox" not in names


# ---------------------------------------------------------------------------
# Provider-backed endpoints
# ---------------------------------------------------------------------------

class TestProviderEndpoints:
    def test_list_messages(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/messages?q=is:unread&limit=20",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["message_ids"] == ["m1", "m2"]
        assert body["query"] == "is:unread"

    def test_fetch_message(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/messages/m1", headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["message_id"] == "m1"
        assert body["sender"] == "a@b.com"

    def test_apply_label(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/messages/m1/label",
            json={"label": "Priority"},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["label"] == "Priority"
        patch_provider.apply_label.assert_awaited_once_with("m1", "Priority")

    def test_move_message(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/messages/m1/move",
            json={"folder": "Archive"},
            headers=bearer,
        )
        assert resp.status_code == 200
        patch_provider.move_message.assert_awaited_once_with("m1", "Archive")

    def test_archive(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/messages/m1/archive",
            headers=bearer,
        )
        assert resp.status_code == 200
        patch_provider.archive.assert_awaited_once_with("m1")

    def test_create_draft(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/messages/m1/draft",
            json={"to": ["bob@x.com"], "subject": "Re", "body": "hi"},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["draft_id"] == "draft-1"


# ---------------------------------------------------------------------------
# Triage endpoint + outbound webhook
# ---------------------------------------------------------------------------

class TestTriageEndpoint:
    def test_triage_runs_returns_results(
        self, client, db, admin_user, bearer, patch_provider,
    ):
        aid = _make_account(db, admin_user["id"])
        # Seed a category so the runner doesn't bail early.
        from email_triage.web.db import seed_categories
        seed_categories(db, [{"slug": "general", "description": "anything"}])

        # Stub classifier so the test doesn't hit Ollama.
        # The runner imports it from ui.py at call time, so patch there.
        with patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
        ) as mk_cls:
            mock_cls = MagicMock()
            from email_triage.engine.models import Classification
            mock_cls.classify = AsyncMock(return_value=Classification(
                category="general", confidence=0.9, reason="t",
            ))
            mk_cls.return_value = mock_cls

            resp = client.post(
                f"/api/openclaw/accounts/{aid}/triage",
                json={"query": "ALL", "limit": 2},
                headers=bearer,
            )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["account_id"] == aid
        assert data["total_messages"] == 2
        assert data["trigger"] == "api"
        assert data["run_id"].startswith("api_")


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_429_when_over_quota(self, client, db, admin_user):
        # Override the bucket to size 2.
        from email_triage.web.ratelimit import TokenBucket
        client.app.state.openclaw_rate_limit = TokenBucket(rate_per_min=2)

        from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
        raw = generate_api_key()
        store_api_key(db, hash_api_key(raw), name="t", user_id=admin_user["id"])
        bearer = {"Authorization": f"Bearer {raw}"}

        # Two requests succeed.
        assert client.get("/api/openclaw/accounts", headers=bearer).status_code == 200
        assert client.get("/api/openclaw/accounts", headers=bearer).status_code == 200
        # Third gets rate-limited.
        resp = client.get("/api/openclaw/accounts", headers=bearer)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# Quiet-hours endpoint
# ---------------------------------------------------------------------------

class TestQuietHoursEndpoint:
    def test_set_quiet_hours_persists(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.put(
            f"/api/openclaw/accounts/{aid}/quiet-hours",
            json={"enabled": True, "start_utc": "22:00", "end_utc": "08:00"},
            headers=bearer,
        )
        assert resp.status_code == 200
        from email_triage.web.events import get_openclaw_quiet_settings
        s = get_openclaw_quiet_settings(db, aid)
        assert s["start_utc"] == "22:00"
        assert s["end_utc"] == "08:00"

    def test_set_quiet_hours_pause_only(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.put(
            f"/api/openclaw/accounts/{aid}/quiet-hours",
            json={"paused": True},
            headers=bearer,
        )
        assert resp.status_code == 200
        from email_triage.web.events import get_openclaw_quiet_settings
        assert get_openclaw_quiet_settings(db, aid)["paused"] is True


# ---------------------------------------------------------------------------
# /api/openclaw/health (admin-token gated, install-wide health)
# ---------------------------------------------------------------------------

class TestOpenclawHealth:
    def test_admin_token_returns_full_payload(
        self, client, db, admin_user, bearer,
    ):
        """Admin bearer token gets the same body /health/detail serves."""
        resp = client.get("/api/openclaw/health", headers=bearer)
        assert resp.status_code == 200
        body = resp.json()
        # Same shape /health/detail returns -- carries the operator
        # signal fields, not just the minimal probe.
        assert set(body.keys()) >= {
            "status", "uptime_secs", "db",
            "ingestion", "mailboxes", "poll", "watchers",
            "last_triage", "version",
            "tasks", "watchers_failing",
            "audit_failures", "csrf_rejects", "schema_version",
        }

    def test_missing_bearer_is_401(self, client):
        resp = client.get("/api/openclaw/health")
        assert resp.status_code == 401

    def test_non_admin_token_is_403(self, client, db, regular_user):
        """Token from a non-admin user gets 403 (install-wide health
        is admin-only). Different gate than the per-user account
        scope on other /api/openclaw/* endpoints."""
        from email_triage.web.auth import (
            generate_api_key, hash_api_key, store_api_key,
        )
        raw = generate_api_key()
        store_api_key(
            db, hash_api_key(raw), name="user-token",
            user_id=regular_user["id"],
        )
        resp = client.get(
            "/api/openclaw/health",
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert resp.status_code == 403
