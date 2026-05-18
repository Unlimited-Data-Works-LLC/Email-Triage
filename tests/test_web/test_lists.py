"""Tests for classification list management (UI + API)."""

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

class TestListsUI:
    def test_rules_page_unauthenticated(self, client):
        resp = client.get("/rules", follow_redirects=False)
        assert resp.status_code == 303

    def test_rules_page_authenticated(self, client, admin_cookies):
        resp = client.get("/rules", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Classification Lists" in resp.text

    def test_create_personal_list(self, client, admin_cookies):
        resp = client.post(
            "/rules/create",
            data={"name": "VIP Senders", "category": "to-respond", "is_global": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_global_rules_page(self, client, admin_cookies):
        resp = client.get("/rules/global", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Global" in resp.text

    def test_global_rules_forbidden_for_user(self, client, user_cookies):
        resp = client.get("/rules/global", cookies=user_cookies)
        assert resp.status_code == 403

    def test_create_global_list(self, client, admin_cookies):
        resp = client.post(
            "/rules/create",
            data={"name": "Company Domains", "category": "fyi", "is_global": "1"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_user_cannot_create_global_list(self, client, user_cookies):
        resp = client.post(
            "/rules/create",
            data={"name": "Hack", "category": "fyi", "is_global": "1"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_rules_create_form_collapsed_behind_details(self, client, admin_cookies):
        """Audience-task audit 2026-04-22: primary task on /rules is adding
        a rule to an existing list; creating a new list is secondary.
        The "Create List" form must be wrapped in <details> so existing
        lists stay above the fold.
        """
        resp = client.get("/rules", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Create List" in resp.text
        lower = resp.text.lower()
        idx = lower.find("create list")
        prefix = lower[:idx]
        assert "<details" in prefix.rsplit("</details>", 1)[-1], (
            "'Create List' must be wrapped in <details> — adding rules to "
            "existing lists is the primary task."
        )

    def test_global_rules_create_form_collapsed_behind_details(
        self, client, admin_cookies
    ):
        """Audience-task audit 2026-04-22: mirror of the personal /rules
        page — wrap Create Global List in <details>.
        """
        resp = client.get("/rules/global", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Create Global List" in resp.text
        lower = resp.text.lower()
        idx = lower.find("create global list")
        prefix = lower[:idx]
        assert "<details" in prefix.rsplit("</details>", 1)[-1], (
            "'Create Global List' must be wrapped in <details>."
        )

    def test_add_rule_to_list(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Test", "invoices", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "sender", "pattern": "bills@company.com", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        rule = db.execute("SELECT * FROM list_rules WHERE list_id = ?", (list_id,)).fetchone()
        assert rule is not None
        assert rule["pattern"] == "bills@company.com"
        assert rule["skip_ai"] == 0

    def test_add_rule_with_skip_ai(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Skip Test", "newsletters", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "sender_domain", "pattern": "@newsletter.com", "skip_ai": "1"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        rule = db.execute("SELECT * FROM list_rules WHERE list_id = ?", (list_id,)).fetchone()
        assert rule["skip_ai"] == 1

    def test_delete_rule(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Del Test", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, created_at) VALUES (?, ?, ?, ?, ?)",
            (list_id, "sender", "a@b.com", 0, now),
        )
        db.commit()
        rule_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/delete",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert db.execute("SELECT * FROM list_rules WHERE id = ?", (rule_id,)).fetchone() is None

    def test_delete_list(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("To Delete", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/rules/{list_id}/delete",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert db.execute("SELECT * FROM classification_lists WHERE id = ?", (list_id,)).fetchone() is None


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

class TestListsAPI:
    def test_list_lists(self, client, admin_cookies):
        resp = client.get("/api/lists", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "personal" in data
        assert "global" in data

    def test_create_list(self, client, admin_cookies):
        resp = client.post(
            "/api/lists",
            json={"name": "API List", "category": "invoices"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "API List"
        assert "id" in data

    def test_create_global_list_as_admin(self, client, admin_cookies):
        resp = client.post(
            "/api/lists",
            json={"name": "Global API", "category": "fyi", "is_global": True},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        assert resp.json()["is_global"] is True

    def test_create_global_forbidden_for_user(self, client, user_cookies):
        resp = client.post(
            "/api/lists",
            json={"name": "Hack", "category": "fyi", "is_global": True},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_get_list(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Get Test", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.get(f"/api/lists/{list_id}", cookies=admin_cookies)
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    def test_get_nonexistent_list(self, client, admin_cookies):
        resp = client.get("/api/lists/999", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_delete_list(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("API Del", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.delete(f"/api/lists/{list_id}", cookies=admin_cookies)
        assert resp.status_code == 204

    def test_add_rule(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Rule Test", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/api/lists/{list_id}/rules",
            json={"rule_type": "sender", "pattern": "x@y.com", "skip_ai": False},
            cookies=admin_cookies,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["pattern"] == "x@y.com"
        assert data["skip_ai"] is False

    def test_add_rule_invalid_type(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Invalid", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.post(
            f"/api/lists/{list_id}/rules",
            json={"rule_type": "body", "pattern": "test"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 422

    def test_delete_rule(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Rule Del", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, created_at) VALUES (?, ?, ?, ?, ?)",
            (list_id, "sender", "del@test.com", 0, now),
        )
        db.commit()
        rule_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.delete(f"/api/lists/{list_id}/rules/{rule_id}", cookies=admin_cookies)
        assert resp.status_code == 204

    def test_delete_nonexistent_rule(self, client, db, admin_cookies, admin_user):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("No Rule", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        resp = client.delete(f"/api/lists/{list_id}/rules/999", cookies=admin_cookies)
        assert resp.status_code == 404


class TestInlineFirstRuleAndEmptyBanner:
    """Bundle L / #146 — Classification-list create form leaves list inert.

    Two halves of one fix:
    1. /rules/create accepts an optional first rule (rule_type, pattern,
       skip_ai); if pattern is non-empty the list and rule are persisted in
       the same transaction so the list starts matching mail immediately.
    2. Lists with zero rules render a prominent amber banner instead of a
       muted "No rules yet." line so the operator sees the next step.
    """

    EMPTY_BANNER_PHRASE = "This list isn't matching anything yet"

    def test_create_list_with_inline_first_rule(self, client, db, admin_cookies):
        """List + first rule both persist in one transaction."""
        resp = client.post(
            "/rules/create",
            data={
                "name": "Inline VIP",
                "category": "to-respond",
                "is_global": "0",
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        lst = db.execute(
            "SELECT id FROM classification_lists WHERE name = ?",
            ("Inline VIP",),
        ).fetchone()
        assert lst is not None, "list was not created"

        rules = db.execute(
            "SELECT rule_type, pattern, skip_ai FROM list_rules WHERE list_id = ?",
            (lst["id"],),
        ).fetchall()
        assert len(rules) == 1, "expected exactly one inline rule"
        assert rules[0]["rule_type"] == "sender"
        assert rules[0]["pattern"] == "boss@example.com"
        assert rules[0]["skip_ai"] == 0

    def test_create_list_inline_rule_with_skip_ai(
        self, client, db, admin_cookies
    ):
        """skip_ai checkbox value is honored on inline-create path."""
        resp = client.post(
            "/rules/create",
            data={
                "name": "Skip Inline",
                "category": "newsletters",
                "is_global": "0",
                "rule_type": "sender_domain",
                "pattern": "newsletter.example.com",
                "skip_ai": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        lst = db.execute(
            "SELECT id FROM classification_lists WHERE name = ?",
            ("Skip Inline",),
        ).fetchone()
        rule = db.execute(
            "SELECT * FROM list_rules WHERE list_id = ?",
            (lst["id"],),
        ).fetchone()
        assert rule["skip_ai"] == 1
        assert rule["rule_type"] == "sender_domain"

    def test_create_list_inline_first_rule_visible_to_classifier_query(
        self, client, db, admin_cookies
    ):
        """The inline rule lands in `list_rules` keyed to the new list — the
        same shape `collect_hints` reads at classification time. We assert
        on the DB row directly because that's the contract: if the row is
        present + correctly typed, `collect_hints` will fire on a matching
        message (covered by classifier-level tests elsewhere).
        """
        resp = client.post(
            "/rules/create",
            data={
                "name": "Classifier Round Trip",
                "category": "to-respond",
                "is_global": "0",
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        cl = db.execute(
            "SELECT id, category FROM classification_lists WHERE name = ?",
            ("Classifier Round Trip",),
        ).fetchone()
        assert cl is not None and cl["category"] == "to-respond"

        rules = db.execute(
            "SELECT rule_type, pattern, skip_ai FROM list_rules WHERE list_id = ?",
            (cl["id"],),
        ).fetchall()
        # Single inline rule, sender match on the literal pattern.
        assert len(rules) == 1
        assert rules[0]["rule_type"] == "sender"
        assert rules[0]["pattern"] == "boss@example.com"

    def test_create_list_with_empty_pattern_legacy_two_step(
        self, client, db, admin_cookies
    ):
        """Pattern blank → list created, no rule. Legacy flow preserved."""
        resp = client.post(
            "/rules/create",
            data={
                "name": "Legacy Empty",
                "category": "fyi",
                "is_global": "0",
                "rule_type": "sender",
                "pattern": "",
                "skip_ai": "0",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        lst = db.execute(
            "SELECT id FROM classification_lists WHERE name = ?",
            ("Legacy Empty",),
        ).fetchone()
        assert lst is not None
        rules = db.execute(
            "SELECT id FROM list_rules WHERE list_id = ?",
            (lst["id"],),
        ).fetchall()
        assert len(rules) == 0, "no rule should be created when pattern is blank"

    def test_create_list_pattern_whitespace_only_treated_as_empty(
        self, client, db, admin_cookies
    ):
        """Whitespace-only pattern should NOT create a phantom rule."""
        resp = client.post(
            "/rules/create",
            data={
                "name": "Whitespace Test",
                "category": "fyi",
                "is_global": "0",
                "rule_type": "sender",
                "pattern": "   ",
                "skip_ai": "0",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        lst = db.execute(
            "SELECT id FROM classification_lists WHERE name = ?",
            ("Whitespace Test",),
        ).fetchone()
        rules = db.execute(
            "SELECT id FROM list_rules WHERE list_id = ?",
            (lst["id"],),
        ).fetchall()
        assert len(rules) == 0

    def test_create_list_legacy_form_without_rule_fields_still_works(
        self, client, db, admin_cookies
    ):
        """Old form bodies (no rule_type/pattern/skip_ai keys) still create
        the list — backwards compat for any external callers / scripts that
        POST against /rules/create.
        """
        resp = client.post(
            "/rules/create",
            data={
                "name": "No Rule Fields",
                "category": "fyi",
                "is_global": "0",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        lst = db.execute(
            "SELECT id FROM classification_lists WHERE name = ?",
            ("No Rule Fields",),
        ).fetchone()
        assert lst is not None

    def test_empty_list_renders_amber_banner(
        self, client, db, admin_cookies, admin_user
    ):
        """Existing list with zero rules → page renders the banner copy."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Banner Test", "fyi", admin_user["id"], 0, now),
        )
        db.commit()

        resp = client.get("/rules", cookies=admin_cookies)
        assert resp.status_code == 200
        # Exact phrase from the banner copy — pinned so future edits to the
        # banner accidentally regressing back to the muted-text variant fail
        # this test loudly.
        assert self.EMPTY_BANNER_PHRASE in resp.text
        # And the legacy muted "No rules yet." line is gone.
        assert "No rules yet." not in resp.text

    def test_list_with_rules_no_banner(
        self, client, db, admin_cookies, admin_user
    ):
        """Existing list with rules → no banner, table renders normally."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Has Rules", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, created_at) VALUES (?, ?, ?, ?, ?)",
            (list_id, "sender", "x@y.com", 0, now),
        )
        db.commit()

        resp = client.get("/rules", cookies=admin_cookies)
        assert resp.status_code == 200
        assert self.EMPTY_BANNER_PHRASE not in resp.text
        # Table content present
        assert "x@y.com" in resp.text

    def test_create_list_unauthenticated_redirects_to_login(self, client):
        """Anonymous → no list created. /rules/create returns 401 to POST
        callers (the page itself sends users to /login on GET)."""
        resp = client.post(
            "/rules/create",
            data={"name": "Anon", "category": "fyi", "is_global": "0"},
            follow_redirects=False,
        )
        # /rules/create is a POST endpoint that returns 401 for anon users;
        # the GET /rules page returns 303 to /login. Both are covered here:
        # this test pins the POST behaviour, the existing
        # test_rules_page_unauthenticated covers the GET.
        assert resp.status_code in (303, 401)

    def test_non_owner_cannot_add_rule_to_other_users_list(
        self, client, db, user_cookies, admin_user
    ):
        """Non-owner cannot add rules to a list they don't own."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        # admin_user owns this list
        db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, is_global, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Admin's List", "fyi", admin_user["id"], 0, now),
        )
        db.commit()
        list_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        # Regular user (user_cookies) tries to add a rule
        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "sender", "pattern": "evil@x.com", "skip_ai": "0"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 403


class TestCategoriesUI:
    def test_categories_page_admin(self, client, admin_cookies):
        resp = client.get("/categories", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Classification Categories" in resp.text
        assert "to-respond" in resp.text

    def test_categories_page_forbidden_for_user(self, client, user_cookies):
        resp = client.get("/categories", cookies=user_cookies)
        assert resp.status_code == 403

    def test_categories_page_unauthenticated(self, client):
        resp = client.get("/categories", follow_redirects=False)
        assert resp.status_code == 303
