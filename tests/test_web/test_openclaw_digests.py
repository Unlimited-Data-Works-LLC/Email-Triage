"""Tests for the /api/openclaw/accounts/{id}/digests CRUD surface."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest


def _make_account(db, user_id, *, ptype="imap"):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, "Acct", ptype,
            json.dumps({"host": "mail.test", "username": "u@test"}),
            0, now, now,
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
# GET list
# ---------------------------------------------------------------------------


class TestList:
    def test_list_returns_preset_for_fresh_account(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{acct_id}/digests",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["account_id"] == acct_id
        assert len(body["digests"]) >= 1
        first = body["digests"][0]
        assert first["kind"] == "preset_daily_activity"

    def test_unauth_is_401(self, client, db, admin_user):
        acct_id = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{acct_id}/digests",
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST create
# ---------------------------------------------------------------------------


class TestCreate:
    def test_create_mints_id_and_persists(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            "name": "AI News",
            "enabled": True,
            "schedule": {"cadence": "daily", "time_local": "06:30"},
            "filter": {"categories": ["newsletter"]},
        }
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/digests",
            json=body, headers=bearer,
        )
        assert resp.status_code == 200
        out = resp.json()
        assert out["id"]
        assert out["name"] == "AI News"
        assert out["kind"] == "custom"

    def test_validation_error_returns_400(
        self, client, db, admin_user, bearer,
    ):
        acct_id = _make_account(db, admin_user["id"])
        body = {
            # Missing name → validate() fails for custom kind.
            "schedule": {"cadence": "daily", "time_local": "08:10"},
        }
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/digests",
            json=body, headers=bearer,
        )
        assert resp.status_code == 400
        # FastAPI wraps detail under "detail" — payload depends on
        # raise shape; both legitimate here.
        assert "name" in resp.text


# ---------------------------------------------------------------------------
# PATCH update
# ---------------------------------------------------------------------------


class TestPatch:
    def test_patch_partial_overlay_keeps_other_fields(
        self, client, db, admin_user, bearer,
    ):
        from email_triage.actions.digest_configs import (
            DigestConfig, upsert_digest_config,
        )
        acct_id = _make_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(
                kind="custom", name="orig", enabled=True,
            ),
        )
        resp = client.patch(
            f"/api/openclaw/accounts/{acct_id}/digests/{seeded.id}",
            json={"enabled": False}, headers=bearer,
        )
        assert resp.status_code == 200
        out = resp.json()
        assert out["enabled"] is False
        assert out["name"] == "orig"  # untouched

    def test_patch_preset_only_accepts_constrained_keys(
        self, client, db, admin_user, bearer,
    ):
        from email_triage.actions.digest_configs import (
            PRESET_ID, get_digest_config, list_digest_configs,
        )
        acct_id = _make_account(db, admin_user["id"])
        list_digest_configs(db, acct_id)  # triggers preset creation
        # Try to demote preset to a custom-named thing.
        resp = client.patch(
            f"/api/openclaw/accounts/{acct_id}/digests/{PRESET_ID}",
            json={
                "name": "should not stick",
                "kind": "custom",
                "enabled": False,
                "schedule": {"time_local": "09:30"},
            },
            headers=bearer,
        )
        assert resp.status_code == 200
        preset = get_digest_config(db, acct_id, PRESET_ID)
        # Constrained keys land — name and kind don't.
        assert preset.enabled is False
        assert preset.schedule.time_local == "09:30"
        assert preset.name == "Daily Activity"
        assert preset.kind == "preset_daily_activity"


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_custom(self, client, db, admin_user, bearer):
        from email_triage.actions.digest_configs import (
            DigestConfig, get_digest_config, upsert_digest_config,
        )
        acct_id = _make_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="bye"),
        )
        resp = client.delete(
            f"/api/openclaw/accounts/{acct_id}/digests/{seeded.id}",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert get_digest_config(db, acct_id, seeded.id) is None

    def test_delete_preset_400(self, client, db, admin_user, bearer):
        from email_triage.actions.digest_configs import (
            PRESET_ID, list_digest_configs,
        )
        acct_id = _make_account(db, admin_user["id"])
        list_digest_configs(db, acct_id)
        resp = client.delete(
            f"/api/openclaw/accounts/{acct_id}/digests/{PRESET_ID}",
            headers=bearer,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# validate-query
# ---------------------------------------------------------------------------


class TestValidateQuery:
    def test_empty_query_returns_ok_zero(
        self, client, db, admin_user, bearer,
    ):
        from email_triage.actions.digest_configs import (
            DigestConfig, upsert_digest_config,
        )
        acct_id = _make_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="x"),
        )
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/digests/{seeded.id}/"
            "validate-query",
            json={"advanced": ""}, headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["match_count"] == 0


# ---------------------------------------------------------------------------
# test-send
# ---------------------------------------------------------------------------


class TestTestSend:
    def test_test_send_blocks_when_smtp_not_configured(
        self, client, db, admin_user, bearer,
    ):
        """Default test app has no SMTP; 503 with detail."""
        from email_triage.actions.digest_configs import (
            DigestConfig, upsert_digest_config,
        )
        acct_id = _make_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="x"),
        )
        resp = client.post(
            f"/api/openclaw/accounts/{acct_id}/digests/{seeded.id}/"
            "test-send",
            headers=bearer,
        )
        assert resp.status_code == 503
        assert "SMTP" in resp.text
