"""Tests for HTMX HTML endpoints."""

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME, store_otp


class TestLoginFlow:
    def test_login_page(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "Sign In" in resp.text

    def test_login_redirects_if_logged_in(self, client, admin_cookies):
        resp = client.get("/login", cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"

    def test_login_email_unknown_user(self, client):
        resp = client.post("/login/email", data={"email": "nobody@test.com"})
        assert resp.status_code == 200
        assert "No account found" in resp.text

    def test_login_email_valid_user(self, client, admin_user):
        resp = client.post("/login/email", data={"email": admin_user["email"]})
        assert resp.status_code == 200
        assert "6-digit code" in resp.text

    def test_login_verify_wrong_code(self, client, db, admin_user):
        store_otp(db, admin_user["email"], "123456")
        resp = client.post(
            "/login/verify",
            data={"email": admin_user["email"], "code": "000000"},
        )
        assert resp.status_code == 200
        assert "Invalid or expired" in resp.text

    def test_login_verify_correct_code(self, client, db, admin_user):
        code = "123456"
        store_otp(db, admin_user["email"], code)
        resp = client.post(
            "/login/verify",
            data={"email": admin_user["email"], "code": code},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"
        assert SESSION_COOKIE_NAME in resp.cookies

    def test_logout(self, client, admin_cookies):
        resp = client.get("/logout", cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


class TestLoginVerifyStrict:
    """Login verification accepts ONLY OTP codes against the
    ``otp_codes`` table. Any other path that previously short-
    circuited verification is gone; these tests guard against
    accidental reintroduction."""

    def test_arbitrary_six_digit_code_rejected(
        self, client, db, admin_user,
    ):
        """An OTP-shaped code that wasn't actually issued must fail
        verification with the same response any wrong code would."""
        resp = client.post(
            "/login/verify",
            data={"email": admin_user["email"], "code": "000000"},
        )
        assert resp.status_code == 200
        assert "Invalid or expired" in resp.text

    def test_no_dev_mode_banner_renders(self, client, admin_cookies):
        """Anti-regression: the retired DEV MODE banner must never
        appear in a logged-in render. The whole dev-mode system was
        removed 2026-05-16; this guard catches an accidental
        re-introduction of the red-banner string in base.html."""
        resp = client.get("/dashboard", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "DEV MODE" not in resp.text


class TestHipaaIndicators:
    """Login badge, nav lock glyph, compliance page visibility + access."""

    def _reset_system(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_login_hides_hipaa_indicator_by_default(self, client):
        self._reset_system()
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "HIPAA mode" not in resp.text
        assert "Compliance mode" not in resp.text

    def test_login_shows_hipaa_badge_and_lock_when_system_on(self, client):
        self._reset_system()
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            resp = client.get("/login")
            assert resp.status_code == 200
            assert "HIPAA mode" in resp.text
            assert "Compliance mode" in resp.text
        finally:
            self._reset_system()

    def test_nav_shows_lock_when_hipaa_on(self, client, admin_cookies):
        self._reset_system()
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            resp = client.get("/dashboard", cookies=admin_cookies)
            assert resp.status_code == 200
            # The title attribute is our signature for the brand lock glyph.
            assert 'title="HIPAA mode is active"' in resp.text
        finally:
            self._reset_system()

    def test_nav_no_lock_when_hipaa_off(self, client, admin_cookies):
        self._reset_system()
        resp = client.get("/dashboard", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'title="HIPAA mode is active"' not in resp.text


class TestCompliancePage:
    """Admin spot-check compliance page."""

    def _reset_system(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_compliance_requires_auth(self, client):
        resp = client.get("/compliance", follow_redirects=False)
        # Unauthed → redirect to login
        assert resp.status_code in (303, 302)

    def test_compliance_forbidden_for_non_admin(self, client, user_cookies):
        resp = client.get("/compliance", cookies=user_cookies)
        assert resp.status_code == 403

    def test_compliance_loads_for_admin(self, client, admin_cookies, db, admin_user):
        self._reset_system()
        from email_triage.web.db import create_email_account
        create_email_account(db, admin_user["id"], "Visible", "imap", {})
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Compliance" in resp.text
        assert "Visible" in resp.text
        assert "System HIPAA" in resp.text

    def test_compliance_shows_effective_on_when_system_on(
        self, client, admin_cookies, db, admin_user,
    ):
        self._reset_system()
        from email_triage.web.db import create_email_account
        create_email_account(db, admin_user["id"], "Whatever", "imap", {})
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            resp = client.get("/compliance", cookies=admin_cookies)
            assert resp.status_code == 200
            assert "System HIPAA: ON" in resp.text
        finally:
            self._reset_system()


class TestDashboard:
    def test_unauthenticated_redirects(self, client):
        resp = client.get("/dashboard", follow_redirects=False)
        assert resp.status_code == 303

    def test_authenticated_shows_dashboard(self, client, admin_cookies):
        resp = client.get("/dashboard", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Dashboard" in resp.text
        assert "Test Admin" in resp.text

    def test_root_redirects_to_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303

    def test_root_redirects_to_dashboard_if_logged_in(self, client, admin_cookies):
        resp = client.get("/", cookies=admin_cookies, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"


class TestUserManagement:
    def test_admin_can_view_users(self, client, admin_cookies):
        resp = client.get("/users", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "User Management" in resp.text

    def test_non_admin_forbidden(self, client, user_cookies):
        resp = client.get("/users", cookies=user_cookies)
        assert resp.status_code == 403

    def test_unauthenticated_redirects(self, client):
        resp = client.get("/users", follow_redirects=False)
        assert resp.status_code == 303

    def test_create_user(self, client, admin_cookies):
        resp = client.post(
            "/users/create",
            data={
                "email": "new@test.com",
                "name": "New User",
                "role": "power_user",
                "notify_email": "",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_create_duplicate_user(self, client, db, admin_cookies, admin_user):
        resp = client.post(
            "/users/create",
            data={
                "email": admin_user["email"],
                "name": "Dup",
                "role": "user",
                "notify_email": "",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 409

    def test_update_user(self, client, db, admin_cookies, regular_user):
        # Get the user ID.
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (regular_user["email"],)
        ).fetchone()
        user_id = row["id"]

        resp = client.post(
            f"/users/{user_id}/update",
            data={"name": "Updated Name", "role": "power_user", "notify_email": ""},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        updated = db.execute(
            "SELECT name, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        assert updated["name"] == "Updated Name"
        assert updated["role"] == "power_user"

    def test_delete_user(self, client, db, admin_cookies, regular_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (regular_user["email"],)
        ).fetchone()
        user_id = row["id"]

        resp = client.post(
            f"/users/{user_id}/delete",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        deleted = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        assert deleted is None

    def test_cannot_delete_self(self, client, db, admin_cookies, admin_user):
        row = db.execute(
            "SELECT id FROM users WHERE email = ?", (admin_user["email"],)
        ).fetchone()
        admin_id = row["id"]

        resp = client.post(
            f"/users/{admin_id}/delete",
            cookies=admin_cookies,
        )
        assert resp.status_code == 400

    def test_non_admin_cannot_create(self, client, user_cookies):
        resp = client.post(
            "/users/create",
            data={"email": "x@x.com", "name": "X", "role": "user", "notify_email": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 403


class TestCategoriesUI:
    def test_categories_page_shows_seeded(self, client, admin_cookies):
        resp = client.get("/categories", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "to-respond" in resp.text

    def test_create_category(self, client, admin_cookies, db):
        resp = client.post("/categories/create", data={
            "slug": "travel", "description": "Travel-related emails",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert "travel" in resp.text
        assert "Category &#39;travel&#39; created." in resp.text or "travel" in resp.text

    def test_edit_form(self, client, admin_cookies, db):
        from email_triage.web.db import list_categories
        cats = list_categories(db)
        first = cats[0]

        resp = client.get(f"/categories/{first['id']}/edit", cookies=admin_cookies)
        assert resp.status_code == 200
        assert first["slug"] in resp.text
        assert 'name="slug"' in resp.text  # It's an edit form

    def test_update_category(self, client, admin_cookies, db):
        from email_triage.web.db import list_categories
        cats = list_categories(db)
        first = cats[0]

        resp = client.put(f"/categories/{first['id']}", data={
            "slug": first["slug"],
            "description": "Brand new description",
        }, cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Brand new description" in resp.text

    def test_delete_category(self, client, admin_cookies, db):
        from email_triage.web.db import create_category
        cat_id = create_category(db, "deleteme", "To be deleted")

        resp = client.delete(f"/categories/{cat_id}", cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.text == ""  # Row removed from DOM

    def test_cancel_edit(self, client, admin_cookies, db):
        from email_triage.web.db import list_categories
        cats = list_categories(db)
        first = cats[0]

        resp = client.get(f"/categories/{first['id']}/row", cookies=admin_cookies)
        assert resp.status_code == 200
        assert first["slug"] in resp.text

    def test_non_admin_blocked(self, client, user_cookies):
        resp = client.get("/categories", cookies=user_cookies)
        assert resp.status_code == 403

    def test_unauthenticated_redirect(self, client):
        resp = client.get("/categories", follow_redirects=False)
        assert resp.status_code == 303


class TestClassifyUI:
    def test_classify_page_loads(self, client, admin_cookies):
        resp = client.get("/classify", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Test Classification" in resp.text
        assert "raw_email" in resp.text

    def test_classify_page_open_to_regular_users(self, client, user_cookies):
        """#95 sub-E — Test Classify is no longer admin-only.
        Useful to any authenticated user investigating a
        misclassification. Categories pulled from DB are still
        user-scoped (system + the user's personal), so no
        admin-only data leaks via this surface."""
        resp = client.get("/classify", cookies=user_cookies)
        assert resp.status_code == 200
        assert "raw_email" in resp.text

    def test_classify_page_unauthenticated(self, client):
        resp = client.get("/classify", follow_redirects=False)
        assert resp.status_code == 303

    def test_classify_run_empty_rejected(self, client, admin_cookies):
        resp = client.post("/classify/run", data={"raw_email": ""}, cookies=admin_cookies)
        # FastAPI rejects empty required form field with 422.
        assert resp.status_code == 422

    def test_classify_run_parses_raw_email(self, client, admin_cookies):
        """Test that the raw email parsing logic correctly extracts fields."""
        raw = (
            "From: sender@example.com\r\n"
            "To: receiver@example.com\r\n"
            "Subject: Test Subject Line\r\n"
            "Date: Mon, 14 Apr 2025 10:00:00 +0000\r\n"
            "\r\n"
            "This is the email body."
        )
        # This will fail at the LLM call (no Ollama running in tests),
        # but the error message will confirm the email was parsed.
        resp = client.post("/classify/run", data={"raw_email": raw}, cookies=admin_cookies)
        assert resp.status_code == 200
        # The response will be an error about the classifier connection,
        # not a parse error.
        assert "Parse error" not in resp.text
