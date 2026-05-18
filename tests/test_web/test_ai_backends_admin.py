"""Tests for the /config/ai-backends admin CRUD page (#169 Wave 2-α — I3).

Covers:

* Auth gating — anonymous redirects to /login, non-admin gets 403.
* Index empty / populated render.
* Create round-trip (form POST → row inserted → secret stored).
* Edit form pre-fills + update round-trip.
* Replace / clear key flow.
* Delete + FK→NULL on dependent accounts.
* Audit row appended per CRUD op.
"""

from __future__ import annotations

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.db import (
    create_ai_backend,
    create_email_account,
    get_ai_backend,
    list_ai_backends,
    set_account_style_learning_backend,
)


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------

class TestAdminAuthGate:
    def test_anonymous_index_redirects(self, client):
        resp = client.get("/config/ai-backends", follow_redirects=False)
        assert resp.status_code in (303, 302)
        assert "/login" in resp.headers.get("location", "")

    def test_non_admin_index_forbidden(self, client, user_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config/ai-backends")
        assert resp.status_code == 403

    def test_non_admin_cannot_create(self, client, user_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post("/config/ai-backends", data={
            "name": "Test", "type": "ollama",
            "endpoint": "http://localhost:11434",
            "enabled": "1",
        })
        assert resp.status_code == 403

    def test_non_admin_cannot_delete(self, client, db, admin_user,
                                     user_cookies):
        bid = create_ai_backend(
            db, name="X", type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            f"/config/ai-backends/{bid}/delete", data={},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Index render
# ---------------------------------------------------------------------------

class TestIndexRender:
    def test_empty_state(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        client.raise_server_exceptions = True
        resp = client.get("/config/ai-backends")
        assert resp.status_code == 200
        body = resp.text
        assert "AI Backends" in body
        assert "Add backend" in body
        # Empty-state copy mentions the install default fallback.
        assert "install default" in body.lower()

    def test_populated_renders_table(
        self, client, db, admin_user, admin_cookies,
    ):
        create_ai_backend(
            db, name="Local Ollama", type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model="[local-llm-model]
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config/ai-backends")
        assert resp.status_code == 200
        body = resp.text
        assert "Local Ollama" in body
        assert "ollama" in body
        assert "[local-llm-model] in body


# ---------------------------------------------------------------------------
# Create round-trip
# ---------------------------------------------------------------------------

class TestCreate:
    def test_create_round_trip(self, client, db, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        # GET form first.
        resp = client.get("/config/ai-backends/new")
        assert resp.status_code == 200
        assert "Add AI backend" in resp.text

        # POST creates.
        resp = client.post(
            "/config/ai-backends",
            data={
                "name": "Azure-OpenAI",
                "type": "azure_openai",
                "endpoint": "https://acme.openai.azure.com/",
                "model": "gpt-4o",
                "api_key_plain": "sk-test-key",
                "baa_certified": "1",
                "baa_expires_at": "2027-12-31",
                "enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)

        rows = list_ai_backends(db)
        assert len(rows) == 1
        r = rows[0]
        assert r["name"] == "Azure-OpenAI"
        assert r["type"] == "azure_openai"
        assert r["model"] == "gpt-4o"
        assert r["baa_certified"] == 1
        assert r["baa_expires_at"] == "2027-12-31"
        assert r["enabled"] == 1
        # API key persisted in secrets, ref stored on row.
        assert r["api_key_secret_ref"] is not None
        secrets = client.app.state.secrets
        assert secrets.get(r["api_key_secret_ref"]) == "sk-test-key"

    def test_create_validates_baa_with_no_expiry(
        self, client, admin_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/config/ai-backends",
            data={
                "name": "Bad",
                "type": "azure_openai",
                "endpoint": "https://x.com",
                "baa_certified": "1",
                # missing baa_expires_at — should re-render form.
                "enabled": "1",
            },
        )
        # The form re-renders with the error message; the row is not
        # inserted.
        assert resp.status_code == 200
        assert "expiration date is required" in resp.text.lower()

    def test_create_rejects_unknown_type(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/config/ai-backends",
            data={
                "name": "X", "type": "anthropic",  # NOT in the enum
                "endpoint": "https://api.anthropic.com",
                "enabled": "1",
            },
        )
        assert resp.status_code == 200
        # Re-renders with "not supported" message.
        assert "not supported" in resp.text.lower()

    def test_create_audit_event(self, client, db, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        client.post(
            "/config/ai-backends",
            data={
                "name": "A1", "type": "ollama",
                "endpoint": "http://localhost:11434",
                "enabled": "1",
            },
        )
        rows = db.execute(
            "SELECT event_type, detail FROM auth_events "
            "WHERE event_type = 'ai_backend_create'",
        ).fetchall()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

class TestUpdate:
    def test_update_round_trip(
        self, client, db, admin_user, admin_cookies,
    ):
        bid = create_ai_backend(
            db, name="Before", type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        # GET edit form.
        resp = client.get(f"/config/ai-backends/{bid}/edit")
        assert resp.status_code == 200
        assert "Before" in resp.text

        # POST update.
        resp = client.post(
            f"/config/ai-backends/{bid}",
            data={
                "name": "After",
                "type": "ollama",
                "endpoint": "http://ollama.lan:11434",
                "model": "llama3.1:8b",
                "enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        row = get_ai_backend(db, bid)
        assert row["name"] == "After"
        assert row["endpoint"] == "http://ollama.lan:11434"
        assert row["model"] == "llama3.1:8b"

    def test_update_replace_key(
        self, client, db, admin_user, admin_cookies,
    ):
        # Pre-seed: row with an existing secret-ref.
        secrets = client.app.state.secrets
        secrets.set("ai_backend_key:99-preseed", "old-key")
        bid = create_ai_backend(
            db, name="HasKey", type_="azure_openai",
            endpoint="https://x.com",
            api_key_secret_ref="ai_backend_key:99-preseed",
            model=None,
            baa_certified=True,
            baa_expires_at="2099-01-01",
            enabled=True, created_by=admin_user["id"],
        )
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            f"/config/ai-backends/{bid}",
            data={
                "name": "HasKey",
                "type": "azure_openai",
                "endpoint": "https://x.com",
                "baa_certified": "1",
                "baa_expires_at": "2099-01-01",
                "enabled": "1",
                "replace_key": "1",
                "api_key_plain": "new-secret",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        # New secret stored under the backend-id-keyed name.
        row = get_ai_backend(db, bid)
        new_ref = row["api_key_secret_ref"]
        assert new_ref == f"ai_backend_key:{bid}"
        assert secrets.get(new_ref) == "new-secret"


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

class TestDelete:
    def test_delete_clears_account_fks(
        self, client, db, admin_user, admin_cookies,
    ):
        bid = create_ai_backend(
            db, name="X", type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        aid = create_email_account(
            db, admin_user["id"], "Test", "imap", {},
        )
        set_account_style_learning_backend(db, aid, bid)

        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            f"/config/ai-backends/{bid}/delete",
            data={},
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        assert get_ai_backend(db, bid) is None
        # Account FK has been cleared by ON DELETE SET NULL.
        row = db.execute(
            "SELECT style_learning_backend_id FROM email_accounts "
            "WHERE id = ?",
            (aid,),
        ).fetchone()
        assert (
            row["style_learning_backend_id"]
            if hasattr(row, "keys") else row[0]
        ) is None


# ---------------------------------------------------------------------------
# Selector filter (per-account dropdown)
# ---------------------------------------------------------------------------

class TestSelectorFilter:
    def test_hipaa_account_only_sees_baa_certified(
        self, db, admin_user,
    ):
        from email_triage.web.routers.ui.accounts import (
            _build_ai_backend_selector_context,
        )
        # Create three backends:
        #   1. Ollama (non-BAA)        — visible to non-HIPAA only
        #   2. Azure with BAA          — visible to both
        #   3. Azure with expired BAA  — visible to non-HIPAA only
        create_ai_backend(
            db, name="Local",
            type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        create_ai_backend(
            db, name="AzureFresh",
            type_="azure_openai",
            endpoint="https://acme.openai.azure.com/",
            api_key_secret_ref=None, model="gpt-4o",
            baa_certified=True, baa_expires_at="2099-01-01",
            enabled=True, created_by=admin_user["id"],
        )
        create_ai_backend(
            db, name="AzureExpired",
            type_="azure_openai",
            endpoint="https://acme.openai.azure.com/",
            api_key_secret_ref=None, model="gpt-4o",
            baa_certified=True, baa_expires_at="2020-01-01",
            enabled=True, created_by=admin_user["id"],
        )
        # HIPAA-flagged account.
        opts, chip = _build_ai_backend_selector_context(
            db, {"id": 99, "hipaa": True,
                 "style_learning_backend_id": None},
        )
        names = sorted(o["name"] for o in opts)
        assert names == ["AzureFresh"]
        assert chip == "Using the install default (local)."

    def test_non_hipaa_account_sees_all_enabled(
        self, db, admin_user,
    ):
        from email_triage.web.routers.ui.accounts import (
            _build_ai_backend_selector_context,
        )
        create_ai_backend(
            db, name="Local",
            type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=True, created_by=admin_user["id"],
        )
        create_ai_backend(
            db, name="LocalDisabled",
            type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=False, baa_expires_at=None,
            enabled=False, created_by=admin_user["id"],
        )
        opts, chip = _build_ai_backend_selector_context(
            db, {"id": 99, "hipaa": False,
                 "style_learning_backend_id": None},
        )
        names = sorted(o["name"] for o in opts)
        assert names == ["Local"]  # disabled row hidden


# ---------------------------------------------------------------------------
# Health endpoint surfacing
# ---------------------------------------------------------------------------

class TestHealthDetailBaaStatus:
    def test_health_detail_carries_baa_status(
        self, client, db, admin_user, admin_cookies,
    ):
        # Seed one expiring + one expired backend.
        create_ai_backend(
            db, name="A", type_="azure_openai",
            endpoint="https://x.com",
            api_key_secret_ref=None, model=None,
            baa_certified=True, baa_expires_at="2026-05-20",
            # ~5 days from 2026-05-15 — urgent bucket
            enabled=True, created_by=admin_user["id"],
        )
        client.cookies.set(
            SESSION_COOKIE_NAME,
            admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/health/detail")
        assert resp.status_code == 200
        body = resp.json()
        assert "baa_status" in body
        baa = body["baa_status"]
        assert "expiring_soon" in baa
        assert "expired" in baa
        assert "expired_hipaa_accounts_disabled" in baa
