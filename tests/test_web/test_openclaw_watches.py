"""Tests for /api/openclaw/accounts/{id}/watches CRUD + admin /admin/watches."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_account(db, user_id, *, hipaa=False, name="acct1", ptype="imap"):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, name, ptype,
            json.dumps({"host": "mail.example.com",
                        "username": "u@example.com"}),
            1 if hipaa else 0, now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def api_key(db, admin_user):
    from email_triage.web.auth import (
        generate_api_key, hash_api_key, store_api_key,
    )
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), name="test", user_id=admin_user["id"],
    )
    return raw


@pytest.fixture
def bearer(api_key):
    return {"Authorization": f"Bearer {api_key}"}


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_list_for_fresh_account(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{acct_id}/watches",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json() == {"account_id": acct_id, "watches": []}

    def test_unauth_is_401(self, client, db, admin_user):
        acct_id = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{acct_id}/watches",
        )
        assert resp.status_code == 401


class TestCreate:
    def test_create_mints_id(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "Boss VIP",
            "filter": {"from_addr": "boss@"},
            "actions": {
                "escalate": {
                    "enabled": True, "notify_email": "ops@example.com",
                },
            },
        }
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        )
        assert resp.status_code == 200
        out = resp.json()
        assert out["watch_id"].startswith("watch_")
        assert out["account_id"] == acct_id
        assert out["actions"]["escalate"]["enabled"] is True

    def test_validation_error_returns_400(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            # No name, no filters → validation fails.
            "actions": {"escalate": {"enabled": True}},
        }
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        )
        assert resp.status_code == 400

    def test_hmac_secret_minted_in_secrets_store(
        self, client, db, admin_user, bearer, app,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "with secret",
            "filter": {"keyword": "ping"},
            "actions": {
                "webhook": {
                    "enabled": True,
                    "url": "http://192.168.1.10:9000/h",
                },
            },
        }
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        )
        assert resp.status_code == 200
        out = resp.json()
        from email_triage.web.email_watches import hmac_secret_key
        secret = app.state.secrets.get(hmac_secret_key(out["watch_id"]))
        assert secret  # minted server-side


class TestUpdate:
    def test_patch_overlays_fields(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "Boss",
            "filter": {"from_addr": "boss@"},
            "actions": {"escalate": {"enabled": True}},
        }
        created = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        ).json()
        wid = created["watch_id"]
        resp = client.patch(
            f"/api/openclaw/accounts/{acct_id}/watches/{wid}",
            json={"enabled": False}, headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        # Filter + actions preserved through partial overlay.
        assert resp.json()["filter"]["from_addr"] == "boss@"


class TestDelete:
    def test_delete_removes_watch(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "x",
            "filter": {"from_addr": "boss@"},
            "actions": {"escalate": {"enabled": True}},
        }
        created = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        ).json()
        wid = created["watch_id"]
        resp = client.delete(
            f"/api/openclaw/accounts/{acct_id}/watches/{wid}",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_unknown_returns_404(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        resp = client.delete(
            f"/api/openclaw/accounts/{acct_id}/watches/watch_nope",
            headers=bearer,
        )
        assert resp.status_code == 404


class TestTestFire:
    def test_test_fire_returns_result_dict(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "x",
            "filter": {"from_addr": "boss@"},
            "actions": {
                "escalate": {
                    "enabled": True, "notify_email": "ops@example.com",
                },
            },
        }
        created = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches",
            json=body, headers=bearer,
        ).json()
        wid = created["watch_id"]
        # No SMTP host is set on the test config, so escalate skips
        # (returns ok=False with smtp_not_configured) but the endpoint
        # itself returns 200 + the result dict.
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/watches/{wid}/test-fire",
            json={}, headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["result"]["watch_id"] == wid
        assert body["result"]["escalate"]["ok"] is False


class TestHIPAA:
    def test_openclaw_refuses_hipaa_account(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.get(
            f"/api/openclaw/accounts/{acct_id}/watches",
            headers=bearer,
        )
        # The OpenClaw scope-gate refuses HIPAA accounts at 403 — same
        # contract as every other endpoint on the surface.
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# /admin/watches
# ---------------------------------------------------------------------------


class TestAdminWatchesPage:
    def test_admin_can_view(
        self, client, db, admin_user, admin_cookies,
    ):
        # Seed two watches across two accounts.
        acct1 = _make_account(db, admin_user["id"], name="acct1")
        from email_triage.web import email_watches as W
        W.upsert_watch(db, W.EmailWatch(
            name="watch-one",
            account_id=acct1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(enabled=True, notify_email="x@y"),
            ),
        ))
        W.upsert_watch(db, W.EmailWatch(
            name="every-acct",
            account_id=None,
            filter=W.WatchFilter(keyword="invoice"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True, url="http://192.168.1.10:9000/h",
                ),
            ),
        ))
        resp = client.get("/admin/watches", cookies=admin_cookies)
        assert resp.status_code == 200
        text = resp.text
        assert "watch-one" in text
        assert "every-acct" in text
        # Cross-account scope label appears for the all-scope watch.
        assert "All accounts" in text

    def test_non_admin_gets_403(
        self, client, db, regular_user, user_cookies,
    ):
        resp = client.get("/admin/watches", cookies=user_cookies)
        assert resp.status_code == 403
