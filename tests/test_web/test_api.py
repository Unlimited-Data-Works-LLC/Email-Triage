"""Tests for JSON REST API endpoints."""

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME


class TestAPIStatus:
    def test_unauthenticated(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 401

    def test_authenticated(self, client, admin_cookies):
        resp = client.get("/api/status", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "user" in data
        assert data["user"]["email"] == "admin@test.com"
        assert "flows" in data
        assert "categories" in data


class TestAPIUsers:
    def test_list_users(self, client, admin_cookies, admin_user):
        resp = client.get("/api/users", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["users"]) == 1
        assert data["users"][0]["email"] == "admin@test.com"

    def test_list_users_forbidden(self, client, user_cookies):
        resp = client.get("/api/users", cookies=user_cookies)
        assert resp.status_code == 403

    def test_create_user(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/api/users",
            json={"email": "new@test.com", "name": "New User", "role": "user"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@test.com"
        assert data["id"] is not None

    def test_create_duplicate(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/api/users",
            json={"email": "admin@test.com", "name": "Dup", "role": "user"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 409

    def test_create_invalid_role(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/api/users",
            json={"email": "x@x.com", "name": "X", "role": "superadmin"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 422

    def test_get_user(self, client, db, admin_cookies, admin_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (admin_user["email"],)
        ).fetchone()
        resp = client.get(f"/api/users/{row['id']}", cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.json()["email"] == "admin@test.com"

    def test_get_nonexistent_user(self, client, admin_cookies, admin_user):
        resp = client.get("/api/users/999", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_update_user(self, client, db, admin_cookies, regular_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (regular_user["email"],)
        ).fetchone()
        resp = client.patch(
            f"/api/users/{row['id']}",
            json={"name": "Renamed", "role": "power_user"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed"
        assert resp.json()["role"] == "power_user"

    def test_update_invalid_role(self, client, db, admin_cookies, regular_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (regular_user["email"],)
        ).fetchone()
        resp = client.patch(
            f"/api/users/{row['id']}",
            json={"role": "root"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 422

    def test_delete_user(self, client, db, admin_cookies, regular_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (regular_user["email"],)
        ).fetchone()
        resp = client.delete(f"/api/users/{row['id']}", cookies=admin_cookies)
        assert resp.status_code == 204

    def test_delete_self_forbidden(self, client, db, admin_cookies, admin_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (admin_user["email"],)
        ).fetchone()
        resp = client.delete(f"/api/users/{row['id']}", cookies=admin_cookies)
        assert resp.status_code == 400

    def test_delete_nonexistent(self, client, admin_cookies, admin_user):
        resp = client.delete("/api/users/999", cookies=admin_cookies)
        assert resp.status_code == 404


class TestAPICategories:
    def test_list_categories(self, client, admin_cookies):
        resp = client.get("/api/categories", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "to-respond" in data["categories"]

    def test_create_category(self, client, admin_cookies):
        resp = client.post("/api/categories", json={
            "slug": "urgent", "description": "Time-sensitive emails",
        }, cookies=admin_cookies)
        assert resp.status_code == 201
        data = resp.json()
        assert data["slug"] == "urgent"
        assert data["description"] == "Time-sensitive emails"

        # Verify it shows up in the list.
        resp2 = client.get("/api/categories", cookies=admin_cookies)
        assert "urgent" in resp2.json()["categories"]

    def test_create_duplicate_category(self, client, admin_cookies):
        resp = client.post("/api/categories", json={
            "slug": "to-respond", "description": "Already exists",
        }, cookies=admin_cookies)
        assert resp.status_code == 409

    def test_update_category(self, client, admin_cookies, db):
        from email_triage.web.db import list_categories
        cats = list_categories(db)
        first = cats[0]

        resp = client.put(f"/api/categories/{first['id']}", json={
            "description": "Updated description",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.json()["description"] == "Updated description"

    def test_delete_category(self, client, admin_cookies, db):
        from email_triage.web.db import create_category
        cat_id = create_category(db, "temp-cat", "Temporary")

        resp = client.delete(f"/api/categories/{cat_id}", cookies=admin_cookies)
        assert resp.status_code == 204

        # Verify it's gone.
        resp2 = client.get("/api/categories", cookies=admin_cookies)
        assert "temp-cat" not in resp2.json()["categories"]

    def test_delete_nonexistent_category(self, client, admin_cookies):
        resp = client.delete("/api/categories/99999", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_create_category_non_admin(self, client, user_cookies):
        resp = client.post("/api/categories", json={
            "slug": "test", "description": "Test",
        }, cookies=user_cookies)
        assert resp.status_code == 403

    def test_unauthenticated(self, client):
        resp = client.get("/api/categories")
        assert resp.status_code == 401
