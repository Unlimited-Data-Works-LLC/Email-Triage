"""Tests for API key management — generation, auth, CRUD, CLI."""

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.auth import (
    API_KEY_PREFIX,
    delete_api_key,
    generate_api_key,
    hash_api_key,
    list_api_keys,
    store_api_key,
    verify_api_key,
)


class TestApiKeyGeneration:
    def test_key_has_prefix(self):
        key = generate_api_key()
        assert key.startswith(API_KEY_PREFIX)

    def test_keys_are_unique(self):
        keys = {generate_api_key() for _ in range(20)}
        assert len(keys) == 20

    def test_key_length(self):
        key = generate_api_key()
        # Prefix + 32 bytes urlsafe base64 ≈ 43 chars.
        assert len(key) > 30

    def test_hash_is_deterministic(self):
        key = generate_api_key()
        assert hash_api_key(key) == hash_api_key(key)

    def test_hash_differs_for_different_keys(self):
        a = generate_api_key()
        b = generate_api_key()
        assert hash_api_key(a) != hash_api_key(b)


class TestApiKeyStorage:
    def test_store_and_verify(self, db, admin_user):
        raw_key = generate_api_key()
        key_hash = hash_api_key(raw_key)
        key_id = store_api_key(db, key_hash, "test-key", admin_user["id"])

        assert key_id > 0
        user = verify_api_key(db, raw_key)
        assert user is not None
        assert user["email"] == "admin@test.com"
        assert user["role"] == "admin"
        assert user["auth_method"] == "api_key"
        assert user["key_name"] == "test-key"

    def test_verify_wrong_key(self, db, admin_user):
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "key", admin_user["id"])

        user = verify_api_key(db, "et_wrong-key-totally-invalid")
        assert user is None

    def test_verify_expired_key(self, db, admin_user):
        raw_key = generate_api_key()
        expired = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        store_api_key(db, hash_api_key(raw_key), "expired", admin_user["id"], expires_at=expired)

        user = verify_api_key(db, raw_key)
        assert user is None

    def test_verify_updates_last_used(self, db, admin_user):
        raw_key = generate_api_key()
        key_id = store_api_key(db, hash_api_key(raw_key), "key", admin_user["id"])

        # Initially last_used_at is NULL.
        row = db.execute("SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        assert row["last_used_at"] is None

        verify_api_key(db, raw_key)
        row = db.execute("SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        assert row["last_used_at"] is not None

    def test_list_keys_all(self, db, admin_user, regular_user):
        store_api_key(db, hash_api_key("k1"), "admin-key", admin_user["id"])
        store_api_key(db, hash_api_key("k2"), "user-key", regular_user["id"])

        all_keys = list_api_keys(db)
        assert len(all_keys) == 2

    def test_list_keys_by_user(self, db, admin_user, regular_user):
        store_api_key(db, hash_api_key("k1"), "admin-key", admin_user["id"])
        store_api_key(db, hash_api_key("k2"), "user-key", regular_user["id"])

        admin_keys = list_api_keys(db, user_id=admin_user["id"])
        assert len(admin_keys) == 1
        assert admin_keys[0]["name"] == "admin-key"

    def test_delete_key(self, db, admin_user):
        raw_key = generate_api_key()
        key_id = store_api_key(db, hash_api_key(raw_key), "to-delete", admin_user["id"])

        assert delete_api_key(db, key_id) is True
        assert verify_api_key(db, raw_key) is None

    def test_delete_nonexistent(self, db):
        assert delete_api_key(db, 999) is False


class TestBearerAuth:
    """Test Bearer token authentication on API endpoints."""

    def test_api_with_bearer_token(self, client, db, admin_user):
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "test-bearer", admin_user["id"])

        resp = client.get(
            "/api/status",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["email"] == "admin@test.com"

    def test_api_with_invalid_bearer(self, client, db, admin_user):
        resp = client.get(
            "/api/status",
            headers={"Authorization": "Bearer invalid-key"},
        )
        assert resp.status_code == 401

    def test_api_with_empty_bearer(self, client, db, admin_user):
        resp = client.get(
            "/api/status",
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401

    def test_api_with_no_auth(self, client, db):
        resp = client.get("/api/status")
        assert resp.status_code == 401

    def test_bearer_takes_precedence_over_cookie(self, client, db, admin_user, admin_cookies):
        """Bearer token should work even if cookie is also present."""
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "bearer-key", admin_user["id"])

        resp = client.get(
            "/api/status",
            headers={"Authorization": f"Bearer {raw_key}"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

    def test_bearer_respects_roles(self, client, db, regular_user):
        """API key inherits user's role — regular user can't access admin endpoints."""
        raw_key = generate_api_key()
        store_api_key(db, hash_api_key(raw_key), "user-key", regular_user["id"])

        resp = client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert resp.status_code == 403


class TestApiKeyEndpoints:
    """Test API key CRUD via REST endpoints."""

    def test_create_key(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            "/api/keys",
            json={"name": "my-key"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "key" in data
        assert data["key"].startswith(API_KEY_PREFIX)
        assert data["name"] == "my-key"
        assert data["user_id"] == admin_user["id"]

    def test_create_key_for_another_user(self, client, db, admin_user, regular_user, admin_cookies):
        resp = client.post(
            "/api/keys",
            json={"name": "user-key", "user_email": regular_user["email"]},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["user_id"] == regular_user["id"]

    def test_non_admin_cannot_create_for_others(self, client, db, admin_user, regular_user, user_cookies):
        resp = client.post(
            "/api/keys",
            json={"name": "key", "user_email": admin_user["email"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_list_keys_admin_sees_all(self, client, db, admin_user, regular_user, admin_cookies):
        store_api_key(db, hash_api_key("k1"), "admin-key", admin_user["id"])
        store_api_key(db, hash_api_key("k2"), "user-key", regular_user["id"])

        resp = client.get("/api/keys", cookies=admin_cookies)
        assert resp.status_code == 200
        assert len(resp.json()["keys"]) == 2

    def test_list_keys_user_sees_own(self, client, db, admin_user, regular_user, user_cookies):
        store_api_key(db, hash_api_key("k1"), "admin-key", admin_user["id"])
        store_api_key(db, hash_api_key("k2"), "user-key", regular_user["id"])

        resp = client.get("/api/keys", cookies=user_cookies)
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert len(keys) == 1
        assert keys[0]["name"] == "user-key"

    def test_delete_key(self, client, db, admin_user, admin_cookies):
        key_id = store_api_key(db, hash_api_key("k1"), "to-delete", admin_user["id"])

        resp = client.delete(f"/api/keys/{key_id}", cookies=admin_cookies)
        assert resp.status_code == 204

    def test_delete_key_not_found(self, client, db, admin_user, admin_cookies):
        resp = client.delete("/api/keys/999", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_user_cannot_delete_others_key(self, client, db, admin_user, regular_user, user_cookies):
        key_id = store_api_key(db, hash_api_key("k1"), "admin-key", admin_user["id"])

        resp = client.delete(f"/api/keys/{key_id}", cookies=user_cookies)
        assert resp.status_code == 403

    def test_create_key_nonexistent_user(self, client, db, admin_user, admin_cookies):
        resp = client.post(
            "/api/keys",
            json={"name": "key", "user_email": "ghost@test.com"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 404


class TestApiKeyLifecycleAudit:
    """Audit-trail regressions: every mint/revoke MUST log + persist a
    row to ``api_key_events``. The raw token must NEVER appear in
    either surface."""

    def test_store_api_key_logs_creation_event(self, db, admin_user, caplog):
        import logging
        raw_key = generate_api_key()
        with caplog.at_level(logging.INFO, logger="email_triage.web.auth"):
            store_api_key(
                db, hash_api_key(raw_key), "audited", admin_user["id"],
                actor_user_id=admin_user["id"],
                actor_email=admin_user["email"],
                source="ui",
            )

        creates = [
            r for r in caplog.records
            if r.getMessage() == "api_key_created"
            and getattr(r, "_extra", {}).get("event") == "api_key_created"
        ]
        assert len(creates) == 1
        extra = creates[0]._extra
        assert extra["actor_email"] == admin_user["email"]
        assert extra["actor_user_id"] == admin_user["id"]
        assert extra["target_user_id"] == admin_user["id"]
        assert extra["target_email"] == admin_user["email"]
        assert extra["name"] == "audited"
        assert extra["source"] == "ui"

    def test_store_api_key_records_to_audit_table(self, db, admin_user):
        raw_key = generate_api_key()
        key_id = store_api_key(
            db, hash_api_key(raw_key), "persisted", admin_user["id"],
            actor_user_id=admin_user["id"],
            actor_email=admin_user["email"],
            source="api",
        )
        rows = db.execute(
            "SELECT * FROM api_key_events WHERE key_id = ?", (key_id,),
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["event"] == "api_key_created"
        assert row["actor_user_id"] == admin_user["id"]
        assert row["target_user_id"] == admin_user["id"]
        assert row["name"] == "persisted"
        assert row["source"] == "api"

    def test_delete_api_key_records_revocation_event(
        self, db, admin_user, caplog,
    ):
        import logging
        raw_key = generate_api_key()
        key_id = store_api_key(
            db, hash_api_key(raw_key), "doomed", admin_user["id"],
            actor_user_id=admin_user["id"],
            actor_email=admin_user["email"],
            source="ui",
        )

        with caplog.at_level(logging.INFO, logger="email_triage.web.auth"):
            assert delete_api_key(
                db, key_id,
                actor_user_id=admin_user["id"],
                actor_email=admin_user["email"],
                source="cli",
            ) is True

        revokes = [
            r for r in caplog.records
            if r.getMessage() == "api_key_revoked"
            and getattr(r, "_extra", {}).get("event") == "api_key_revoked"
        ]
        assert len(revokes) == 1
        assert revokes[0]._extra["source"] == "cli"
        assert revokes[0]._extra["key_id"] == key_id

        rows = db.execute(
            "SELECT * FROM api_key_events WHERE key_id = ? AND event = ?",
            (key_id, "api_key_revoked"),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["source"] == "cli"
        assert rows[0]["target_user_id"] == admin_user["id"]
        assert rows[0]["name"] == "doomed"

    def test_audit_table_survives_key_deletion(self, db, admin_user):
        """Once revoked, the api_keys row is gone but both the
        creation and revocation rows in api_key_events remain."""
        raw_key = generate_api_key()
        key_id = store_api_key(
            db, hash_api_key(raw_key), "ghost", admin_user["id"],
            actor_user_id=admin_user["id"],
            actor_email=admin_user["email"],
            source="ui",
        )
        delete_api_key(
            db, key_id,
            actor_user_id=admin_user["id"],
            actor_email=admin_user["email"],
            source="ui",
        )

        # The api_keys row is gone.
        assert db.execute(
            "SELECT 1 FROM api_keys WHERE id = ?", (key_id,),
        ).fetchone() is None

        # But both audit rows survive.
        rows = db.execute(
            "SELECT event FROM api_key_events WHERE key_id = ? ORDER BY id",
            (key_id,),
        ).fetchall()
        events = [r["event"] for r in rows]
        assert events == ["api_key_created", "api_key_revoked"]

    def test_api_key_event_never_logs_raw_token(
        self, db, admin_user, caplog,
    ):
        """The structured log entry MUST NOT include the raw token or
        its hash anywhere — only ``key_id`` is the correlation handle."""
        import logging
        raw_key = generate_api_key()
        key_hash = hash_api_key(raw_key)

        with caplog.at_level(logging.INFO, logger="email_triage.web.auth"):
            key_id = store_api_key(
                db, key_hash, "no-leak", admin_user["id"],
                actor_user_id=admin_user["id"],
                actor_email=admin_user["email"],
                source="ui",
            )
            delete_api_key(
                db, key_id,
                actor_user_id=admin_user["id"],
                actor_email=admin_user["email"],
                source="ui",
            )

        for rec in caplog.records:
            # Inspect the message AND every value in the structured
            # extras dict the TriageLogger attaches to ``_extra``.
            haystack_parts = [rec.getMessage()]
            extra = getattr(rec, "_extra", {}) or {}
            for v in extra.values():
                haystack_parts.append(str(v))
            haystack = "\n".join(haystack_parts)
            assert raw_key not in haystack, (
                f"raw token leaked into log record: {rec!r}"
            )
            assert key_hash not in haystack, (
                f"key hash leaked into log record: {rec!r}"
            )

        # Same check for the persisted audit rows.
        rows = db.execute(
            "SELECT * FROM api_key_events WHERE key_id = ?", (key_id,),
        ).fetchall()
        assert rows
        for row in rows:
            for v in dict(row).values():
                if isinstance(v, str):
                    assert raw_key not in v
                    assert key_hash not in v

    def test_audit_insert_failure_does_not_block_creation(
        self, db, admin_user, monkeypatch,
    ):
        """If the audit-table insert raises, the key MUST still be
        minted and verifiable. We swallow the audit error so admins
        never lose access because of a bug in the audit path."""
        from email_triage.web import db as db_mod

        def boom(*args, **kwargs):
            raise RuntimeError("audit storage exploded")

        monkeypatch.setattr(db_mod, "record_api_key_event", boom)

        raw_key = generate_api_key()
        key_id = store_api_key(
            db, hash_api_key(raw_key), "resilient", admin_user["id"],
            actor_user_id=admin_user["id"],
            actor_email=admin_user["email"],
            source="ui",
        )
        # Key really exists and verifies.
        assert key_id > 0
        user = verify_api_key(db, raw_key)
        assert user is not None
        assert user["email"] == admin_user["email"]

        # Audit row was NOT written (because the insert raised) but
        # the mint succeeded — that's the whole point.
        rows = db.execute(
            "SELECT * FROM api_key_events WHERE key_id = ?", (key_id,),
        ).fetchall()
        assert rows == []


class TestCLIApiKeyParser:
    """Test CLI apikey subcommand parsing."""

    def test_apikey_create_args(self):
        from email_triage.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["apikey", "create", "--name", "test", "--user", "admin@test.com"])
        assert args.command == "apikey"
        assert args.apikey_cmd == "create"
        assert args.name == "test"
        assert args.user == "admin@test.com"

    def test_apikey_list_args(self):
        from email_triage.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["apikey", "list"])
        assert args.apikey_cmd == "list"

    def test_apikey_delete_args(self):
        from email_triage.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["apikey", "delete", "42"])
        assert args.apikey_cmd == "delete"
        assert args.key_id == 42
