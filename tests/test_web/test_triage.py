"""Tests for the Run Triage web interface and account routes."""

import json
from datetime import datetime, timezone

import pytest


class TestTriagePage:
    """Tests for the Run Triage page (GET /triage)."""

    def test_triage_page_requires_auth(self, client):
        resp = client.get("/triage", follow_redirects=False)
        assert resp.status_code == 303

    def test_triage_page_loads(self, client, admin_cookies, admin_user):
        resp = client.get("/triage", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Run Triage" in resp.text

    def test_triage_page_shows_no_accounts_message(self, client, admin_cookies, admin_user):
        resp = client.get("/triage", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "No email accounts configured" in resp.text

    def test_triage_page_shows_accounts(self, client, db, admin_cookies, admin_user):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Test IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()

        resp = client.get("/triage", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Test IMAP" in resp.text
        assert "Run Triage" in resp.text

    def test_triage_page_regular_user_sees_own_accounts(
        self, client, db, user_cookies, regular_user, admin_user
    ):
        now = datetime.now(timezone.utc).isoformat()
        # Admin's account.
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Admin IMAP", "imap", json.dumps({}), now, now),
        )
        # User's account.
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (regular_user["id"], "User IMAP", "imap", json.dumps({}), now, now),
        )
        db.commit()

        resp = client.get("/triage", cookies=user_cookies)
        assert resp.status_code == 200
        assert "User IMAP" in resp.text
        assert "Admin IMAP" not in resp.text


class TestAccountRoutes:
    """Tests for account route configuration (GET/POST /accounts/{id}/routes)."""

    def _create_account(self, db, user_id, name="Test IMAP"):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, name, "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        return cursor.lastrowid

    def test_routes_page_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/routes", follow_redirects=False)
        assert resp.status_code == 303

    def test_routes_page_loads(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/routes", cookies=admin_cookies)
        assert resp.status_code == 200
        # Page heading matches the account-edit pattern
        # ("Editing: <name>") + the routing tab strip below.
        assert "Editing:" in resp.text
        assert "Routes" in resp.text  # H3 + tab label
        assert "Test IMAP" in resp.text

    def test_routes_page_shows_categories(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/routes", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "to-respond" in resp.text
        assert "invoices" in resp.text

    def test_routes_page_forbidden_for_other_user(
        self, client, db, user_cookies, regular_user, admin_user
    ):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/routes", cookies=user_cookies)
        assert resp.status_code == 403

    def test_save_route(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/routes/save",
            data={"category": "invoices", "actions": ["move", "label"], "move_folder": "INBOX.Invoices"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "saved" in resp.text.lower()

        # Verify it was stored.
        row = db.execute(
            "SELECT actions_json FROM account_routes WHERE account_id = ? AND category = ?",
            (acct_id, "invoices"),
        ).fetchone()
        assert row is not None
        actions = json.loads(row["actions_json"])
        assert len(actions) == 2
        assert actions[0]["action"] == "move"
        assert actions[0]["config"]["folder_map"]["invoices"] == "INBOX.Invoices"
        assert actions[1]["action"] == "label"

    def test_save_route_upserts(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])

        # Save initially.
        client.post(
            f"/accounts/{acct_id}/routes/save",
            data={"category": "invoices", "actions": ["move"], "move_folder": "INBOX.Old"},
            cookies=admin_cookies,
        )

        # Update.
        client.post(
            f"/accounts/{acct_id}/routes/save",
            data={"category": "invoices", "actions": ["label"]},
            cookies=admin_cookies,
        )

        # Should have one route, not two.
        rows = db.execute(
            "SELECT * FROM account_routes WHERE account_id = ? AND category = ?",
            (acct_id, "invoices"),
        ).fetchall()
        assert len(rows) == 1
        actions = json.loads(rows[0]["actions_json"])
        assert len(actions) == 1
        assert actions[0]["action"] == "label"

    def test_save_route_forbidden(self, client, db, user_cookies, regular_user, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/routes/save",
            data={"category": "invoices", "actions": ["move"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_delete_route(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])

        # Create a route.
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO account_routes (account_id, category, actions_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (acct_id, "invoices", json.dumps([{"action": "move"}]), now, now),
        )
        db.commit()
        route_id = cursor.lastrowid

        resp = client.delete(
            f"/accounts/{acct_id}/routes/{route_id}",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        # Verify deleted.
        row = db.execute(
            "SELECT * FROM account_routes WHERE id = ?", (route_id,)
        ).fetchone()
        assert row is None

    def test_routes_page_not_found(self, client, admin_cookies, admin_user):
        resp = client.get("/accounts/99999/routes", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_routes_page_create_folder_form_collapsed_behind_details(
        self, client, db, admin_cookies, admin_user, monkeypatch
    ):
        """Audience-task audit 2026-04-22: Create New Folder is a secondary
        action on /accounts/{id}/routes — the primary task is editing the
        category → action mapping. The create-folder form must be wrapped
        in <details> so the category table stays above the fold.

        The form only renders when the provider returns a folder list, so
        we stub the provider to return a minimal folder set.
        """
        acct_id = self._create_account(db, admin_user["id"])

        # Stub provider so list_folders() returns a non-empty list and the
        # create-folder block renders.
        class _FakeProvider:
            async def list_folders(self):
                return ["INBOX", "INBOX.Triage"]

            async def close(self):
                return None

        from email_triage.web.routers import ui as ui_mod
        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account",
            lambda acct, secrets, google_oauth=None: _FakeProvider(),
        )

        resp = client.get(f"/accounts/{acct_id}/routes", cookies=admin_cookies)
        assert resp.status_code == 200
        # The form exists…
        assert "Create New Folder" in resp.text
        # …and is wrapped in a <details> block. Everything before the label
        # must contain an unclosed <details tag (i.e. the label sits inside
        # a <details> that hasn't closed yet).
        lower = resp.text.lower()
        idx = lower.find("create new folder")
        prefix = lower[:idx]
        assert "<details" in prefix.rsplit("</details>", 1)[-1], (
            "'Create New Folder' must be wrapped in <details> — primary task "
            "(category → action mapping) should stay above the fold."
        )


class TestFolderRoutes:
    """Tests for folder listing and creation."""

    def _create_account(self, db, user_id):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, "Test IMAP", "imap",
             json.dumps({"host": "mail.test.com", "username": "test@test.com"}),
             now, now),
        )
        db.commit()
        return cursor.lastrowid

    def test_folders_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/folders")
        assert resp.status_code == 401

    def test_folders_forbidden_for_other_user(
        self, client, db, user_cookies, regular_user, admin_user
    ):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/folders", cookies=user_cookies)
        assert resp.status_code == 403

    def test_folders_not_found(self, client, admin_cookies, admin_user):
        resp = client.get("/accounts/99999/folders", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_create_folder_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/folders/create",
            data={"folder": "INBOX.Test"},
        )
        assert resp.status_code == 401

    def test_create_folder_not_found(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/accounts/99999/folders/create",
            data={"folder": "INBOX.Test"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 404


class TestFolderPrefsRoutes:
    """Tests for folder preference endpoints."""

    def _create_account(self, db, user_id):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, "Test IMAP", "imap",
             json.dumps({"host": "mail.test.com", "username": "test@test.com"}),
             now, now),
        )
        db.commit()
        return cursor.lastrowid

    def test_prefs_page_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/folders/prefs", follow_redirects=False)
        assert resp.status_code == 303

    def test_prefs_page_forbidden(self, client, db, user_cookies, regular_user, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/folders/prefs", cookies=user_cookies)
        assert resp.status_code == 403

    def test_prefs_page_not_found(self, client, admin_cookies, admin_user):
        resp = client.get("/accounts/99999/folders/prefs", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_prefs_page_loads(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/folders/prefs", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Folder Preferences" in resp.text

    def test_save_prefs(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/folders/prefs",
            data={
                "all_folders": ["INBOX", "INBOX.Archive", "INBOX.Triage"],
                "included": ["INBOX", "INBOX.Triage"],
                # INBOX.Archive is NOT included.
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        # Should redirect back to routes page with flash message.
        assert resp.status_code == 303
        assert f"/accounts/{acct_id}/routes" in resp.headers.get("location", "")
        assert "folder_msg=" in resp.headers.get("location", "")

        # Verify DB state.
        from email_triage.web.db import get_folder_prefs
        prefs = get_folder_prefs(db, acct_id)
        assert prefs["INBOX"] is True
        assert prefs["INBOX.Triage"] is True
        assert prefs["INBOX.Archive"] is False

    def test_save_prefs_forbidden(self, client, db, user_cookies, regular_user, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/folders/prefs",
            data={"all_folders": "INBOX", "included": "INBOX"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403


class TestDigestRoutes:
    """Tests for newsletter digest endpoints."""

    def _create_account(self, db, user_id):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, "Test IMAP", "imap",
             json.dumps({"host": "mail.test.com", "username": "test@test.com"}),
             now, now),
        )
        db.commit()
        return cursor.lastrowid

    def test_save_config_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{acct_id}/digest/save-config",
                           data={"category": "newsletters", "schedule_time": "07:00"})
        assert resp.status_code == 401

    def test_save_config_forbidden(self, client, db, user_cookies, regular_user, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{acct_id}/digest/save-config",
                           data={"category": "newsletters"},
                           cookies=user_cookies)
        assert resp.status_code == 403

    def test_save_config_success(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/digest/save-config",
            data={
                "format_prompt": "custom format",
                "delete_originals": "1",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "saved" in resp.text.lower()

        # Verify stored in settings.
        from email_triage.web.db import get_setting
        config = get_setting(db, f"digest:{acct_id}")
        assert config is not None
        assert config["format_prompt"] == "custom format"
        assert config["delete_originals"] is True

    def test_add_schedule(self, client, db, admin_cookies, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/digest/schedule/add",
            data={
                "schedule_time": "07:00",
                "category": "newsletters",
                "tz_offset": "300",  # EST: UTC-5
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200

        # Verify stored — 07:00 EST + 300 min offset = 12:00 UTC.
        from email_triage.web.db import get_setting
        schedules = get_setting(db, f"digest_schedules:{acct_id}")
        assert schedules is not None
        assert len(schedules) == 1
        assert schedules[0]["time_utc"] == "12:00"
        assert schedules[0]["category"] == "newsletters"
        assert schedules[0]["enabled"] is True

    def test_toggle_schedule(self, client, db, admin_cookies, admin_user):
        from email_triage.web.db import set_setting
        acct_id = self._create_account(db, admin_user["id"])
        set_setting(db, f"digest_schedules:{acct_id}", [
            {"time_utc": "12:00", "category": "newsletters", "enabled": True},
        ])
        resp = client.post(
            f"/accounts/{acct_id}/digest/toggle/0",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        from email_triage.web.db import get_setting
        schedules = get_setting(db, f"digest_schedules:{acct_id}")
        assert schedules[0]["enabled"] is False

    def test_delete_schedule(self, client, db, admin_cookies, admin_user):
        from email_triage.web.db import set_setting
        acct_id = self._create_account(db, admin_user["id"])
        set_setting(db, f"digest_schedules:{acct_id}", [
            {"time_utc": "12:00", "category": "newsletters", "enabled": True},
            {"time_utc": "18:00", "category": "notifications", "enabled": True},
        ])
        resp = client.delete(
            f"/accounts/{acct_id}/digest/schedule/0",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        from email_triage.web.db import get_setting
        schedules = get_setting(db, f"digest_schedules:{acct_id}")
        assert len(schedules) == 1
        assert schedules[0]["category"] == "notifications"

    def test_add_schedule_duplicate_ignored(self, client, db, admin_cookies, admin_user):
        from email_triage.web.db import set_setting
        acct_id = self._create_account(db, admin_user["id"])
        set_setting(db, f"digest_schedules:{acct_id}", [
            {"time_utc": "12:00", "category": "newsletters", "enabled": True},
        ])
        # Try to add the same schedule again (same UTC time + category).
        resp = client.post(
            f"/accounts/{acct_id}/digest/schedule/add",
            data={
                "schedule_time": "07:00",
                "category": "newsletters",
                "tz_offset": "300",  # 07:00 EST = 12:00 UTC — duplicate
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        from email_triage.web.db import get_setting
        schedules = get_setting(db, f"digest_schedules:{acct_id}")
        assert len(schedules) == 1  # No duplicate added

    def test_legacy_schedule_migration(self, client, db, admin_cookies, admin_user):
        """Old single-schedule format is migrated to multi-schedule on load."""
        from email_triage.web.db import set_setting, get_setting
        acct_id = self._create_account(db, admin_user["id"])
        # Seed the legacy format.
        set_setting(db, f"digest:{acct_id}", {
            "schedule_enabled": True,
            "schedule_time": "08:30",
            "category": "newsletters",
            "format_prompt": "old prompt",
        })
        # Hit the toggle endpoint — this triggers _load_digest_schedules
        # which should migrate the legacy format.
        resp = client.post(
            f"/accounts/{acct_id}/digest/toggle/0",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        schedules = get_setting(db, f"digest_schedules:{acct_id}")
        assert schedules is not None
        assert len(schedules) == 1
        assert schedules[0]["time_utc"] == "08:30"
        # Toggle should have paused it.
        assert schedules[0]["enabled"] is False

    def test_save_config_not_found(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/99999/digest/save-config",
                           data={"category": "newsletters"},
                           cookies=admin_cookies)
        assert resp.status_code == 404

    def test_generate_requires_auth(self, client, db, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{acct_id}/digest/generate",
                           data={"category": "newsletters"})
        assert resp.status_code == 401

    def test_generate_forbidden(self, client, db, user_cookies, regular_user, admin_user):
        acct_id = self._create_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{acct_id}/digest/generate",
                           data={"category": "newsletters"},
                           cookies=user_cookies)
        assert resp.status_code == 403

    def test_generate_not_found(self, client, admin_cookies, admin_user):
        resp = client.post("/accounts/99999/digest/generate",
                           data={"category": "newsletters"},
                           cookies=admin_cookies)
        assert resp.status_code == 404


class TestFolderPrefsDB:
    """Tests for folder preference DB helpers."""

    def test_get_prefs_empty(self, db, admin_user):
        from email_triage.web.db import create_email_account, get_folder_prefs
        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        prefs = get_folder_prefs(db, acct_id)
        assert prefs == {}

    def test_save_and_get_prefs(self, db, admin_user):
        from email_triage.web.db import (
            create_email_account, save_folder_prefs, get_folder_prefs,
        )
        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        save_folder_prefs(db, acct_id, {
            "INBOX": True,
            "INBOX.Archive": False,
            "INBOX.Triage": True,
        })
        prefs = get_folder_prefs(db, acct_id)
        assert prefs == {
            "INBOX": True,
            "INBOX.Archive": False,
            "INBOX.Triage": True,
        }

    def test_save_prefs_replaces(self, db, admin_user):
        from email_triage.web.db import (
            create_email_account, save_folder_prefs, get_folder_prefs,
        )
        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        save_folder_prefs(db, acct_id, {"INBOX": True, "Archive": False})
        save_folder_prefs(db, acct_id, {"INBOX": False})
        prefs = get_folder_prefs(db, acct_id)
        assert prefs == {"INBOX": False}
        # Archive pref should be gone (full replace).
        assert "Archive" not in prefs

    def test_get_visible_folders(self, db, admin_user):
        from email_triage.web.db import (
            create_email_account, save_folder_prefs, get_visible_folders,
        )
        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        all_folders = [
            "INBOX", "INBOX.Archive", "INBOX.Archive.2024",
            "INBOX.Triage", "INBOX.Triage.Invoices",
        ]
        # Exclude Archive (should also hide Archive.2024).
        save_folder_prefs(db, acct_id, {
            "INBOX": True,
            "INBOX.Archive": False,
            "INBOX.Triage": True,
        })
        visible = get_visible_folders(db, acct_id, all_folders)
        assert "INBOX" in visible
        assert "INBOX.Triage" in visible
        assert "INBOX.Triage.Invoices" in visible
        assert "INBOX.Archive" not in visible
        assert "INBOX.Archive.2024" not in visible

    def test_get_visible_folders_no_prefs(self, db, admin_user):
        """With no prefs saved, all folders are visible."""
        from email_triage.web.db import create_email_account, get_visible_folders
        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        all_folders = ["INBOX", "INBOX.Archive", "INBOX.Triage"]
        visible = get_visible_folders(db, acct_id, all_folders)
        assert visible == all_folders


class TestBuildFolderTree:
    """Tests for the folder tree builder."""

    def test_flat_folders(self):
        from email_triage.web.routers.ui import _build_folder_tree
        tree = _build_folder_tree(["INBOX", "Sent", "Trash"])
        assert len(tree) == 3
        assert tree[0]["name"] == "INBOX"
        assert tree[0]["path"] == "INBOX"
        assert tree[0]["children"] == []

    def test_nested_folders(self):
        from email_triage.web.routers.ui import _build_folder_tree
        folders = [
            "INBOX", "INBOX.Triage", "INBOX.Triage.Invoices",
            "INBOX.Archive", "Sent",
        ]
        tree = _build_folder_tree(folders)
        # Root should have INBOX and Sent.
        names = [n["name"] for n in tree]
        assert "INBOX" in names
        assert "Sent" in names

        inbox = [n for n in tree if n["name"] == "INBOX"][0]
        child_names = [c["name"] for c in inbox["children"]]
        assert "Archive" in child_names
        assert "Triage" in child_names

        triage = [c for c in inbox["children"] if c["name"] == "Triage"][0]
        assert len(triage["children"]) == 1
        assert triage["children"][0]["name"] == "Invoices"
        assert triage["children"][0]["path"] == "INBOX.Triage.Invoices"

    def test_empty_folders(self):
        from email_triage.web.routers.ui import _build_folder_tree
        tree = _build_folder_tree([])
        assert tree == []


class TestAccountRoutesDB:
    """Tests for account_routes DB helpers."""

    def test_upsert_and_list(self, db, admin_user):
        from email_triage.web.db import (
            create_email_account,
            upsert_account_route,
            list_account_routes,
            get_account_route,
        )

        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})

        # Upsert a route.
        route_id = upsert_account_route(
            db, acct_id, "invoices",
            [{"action": "move", "config": {"folder_map": {"invoices": "INBOX.Invoices"}}}],
        )
        assert route_id > 0

        # List routes.
        routes = list_account_routes(db, acct_id)
        assert len(routes) == 1
        assert routes[0]["category"] == "invoices"
        assert routes[0]["actions"][0]["action"] == "move"

        # Get single route.
        route = get_account_route(db, acct_id, "invoices")
        assert route is not None
        assert route["category"] == "invoices"

        # Upsert again (update).
        route_id2 = upsert_account_route(
            db, acct_id, "invoices",
            [{"action": "label"}],
        )
        assert route_id2 == route_id  # Same row.
        route = get_account_route(db, acct_id, "invoices")
        assert len(route["actions"]) == 1
        assert route["actions"][0]["action"] == "label"

    def test_delete_route(self, db, admin_user):
        from email_triage.web.db import (
            create_email_account,
            upsert_account_route,
            delete_account_route,
            list_account_routes,
        )

        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        route_id = upsert_account_route(db, acct_id, "invoices", [])

        assert delete_account_route(db, route_id)
        assert len(list_account_routes(db, acct_id)) == 0

    def test_get_nonexistent_route(self, db, admin_user):
        from email_triage.web.db import create_email_account, get_account_route

        acct_id = create_email_account(db, admin_user["id"], "Test", "imap", {})
        route = get_account_route(db, acct_id, "nonexistent")
        assert route is None


# ---------------------------------------------------------------------------
# Category Discovery
# ---------------------------------------------------------------------------


class TestDiscoverPage:
    """Tests for the Discover Categories page (GET /triage/discover)."""

    def test_requires_auth(self, client):
        resp = client.get("/triage/discover", follow_redirects=False)
        assert resp.status_code == 303

    def test_page_loads(self, client, admin_cookies, admin_user):
        resp = client.get("/triage/discover", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Discover Categories" in resp.text

    def test_shows_no_accounts_message(self, client, admin_cookies, admin_user):
        resp = client.get("/triage/discover", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "No email accounts configured" in resp.text

    def test_shows_accounts(self, client, db, admin_cookies, admin_user):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "My IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()

        resp = client.get("/triage/discover", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "My IMAP" in resp.text
        assert "Discover Categories" in resp.text

    def test_regular_user_sees_own_accounts(
        self, client, db, user_cookies, regular_user, admin_user,
    ):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Admin IMAP", "imap", json.dumps({}), now, now),
        )
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (regular_user["id"], "User IMAP", "imap", json.dumps({}), now, now),
        )
        db.commit()

        resp = client.get("/triage/discover", cookies=user_cookies)
        assert resp.status_code == 200
        assert "User IMAP" in resp.text
        assert "Admin IMAP" not in resp.text


class TestDiscoverRun:
    """Tests for the discover run endpoint (POST /triage/discover/run)."""

    def test_requires_auth(self, client):
        resp = client.post("/triage/discover/run", data={"account_id": "1", "limit": "10", "query": "ALL"})
        assert resp.status_code == 401

    def test_account_not_found(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/triage/discover/run",
            data={"account_id": "99999", "limit": "10", "query": "ALL"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Account not found" in resp.text

    def test_forbidden_for_other_user(
        self, client, db, user_cookies, regular_user, admin_user,
    ):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Admin IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid

        resp = client.post(
            "/triage/discover/run",
            data={"account_id": str(acct_id), "limit": "10", "query": "ALL"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_disabled_account(self, client, db, admin_cookies, admin_user):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            (admin_user["id"], "Disabled IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid

        resp = client.post(
            "/triage/discover/run",
            data={"account_id": str(acct_id), "limit": "10", "query": "ALL"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Account disabled" in resp.text


class TestAddDiscoveredCategory:
    """Tests for the add-discovered endpoint (POST /categories/add-discovered)."""

    def test_requires_auth(self, client):
        resp = client.post(
            "/categories/add-discovered",
            data={"slug": "test-cat", "description": "A test category"},
        )
        assert resp.status_code == 401

    def test_requires_admin(self, client, user_cookies, regular_user):
        resp = client.post(
            "/categories/add-discovered",
            data={"slug": "test-cat", "description": "A test category"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_adds_category(self, client, db, admin_cookies, admin_user):
        resp = client.post(
            "/categories/add-discovered",
            data={"slug": "new-discovery", "description": "Discovered by scan"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Added" in resp.text or "✓" in resp.text or "&#10003;" in resp.text

        # Verify stored in DB.
        row = db.execute(
            "SELECT slug, description FROM categories WHERE slug = ?",
            ("new-discovery",),
        ).fetchone()
        assert row is not None
        assert row["slug"] == "new-discovery"
        assert row["description"] == "Discovered by scan"

    def test_missing_slug(self, client, admin_cookies, admin_user):
        resp = client.post(
            "/categories/add-discovered",
            data={"slug": "", "description": "No slug provided"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Missing slug" in resp.text

    def test_duplicate_slug_error(self, client, db, admin_cookies, admin_user):
        # Add it once.
        client.post(
            "/categories/add-discovered",
            data={"slug": "duplicate-test", "description": "First"},
            cookies=admin_cookies,
        )
        # Add it again — should fail.
        resp = client.post(
            "/categories/add-discovered",
            data={"slug": "duplicate-test", "description": "Second"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Error" in resp.text


class TestParseLlmJsonOrArray:
    """Unit tests for _parse_llm_json_or_array helper."""

    def _parse(self, text):
        from email_triage.web.routers.ui import _parse_llm_json_or_array
        return _parse_llm_json_or_array(text)

    def test_parse_json_object(self):
        result = self._parse('{"category": "billing", "description": "Bills and invoices"}')
        assert result["category"] == "billing"

    def test_parse_json_array(self):
        result = self._parse('[{"slug": "billing"}, {"slug": "newsletters"}]')
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["slug"] == "billing"

    def test_parse_with_think_tags(self):
        text = '<think>Let me analyze this...</think>{"category": "billing", "description": "test"}'
        result = self._parse(text)
        assert result["category"] == "billing"

    def test_parse_with_markdown_fences(self):
        text = '```json\n[{"slug": "newsletters"}]\n```'
        result = self._parse(text)
        assert isinstance(result, list)
        assert result[0]["slug"] == "newsletters"

    def test_parse_with_preamble_text(self):
        text = 'Here is the result:\n{"category": "spam", "description": "Spam emails"}'
        result = self._parse(text)
        assert result["category"] == "spam"

    def test_parse_array_before_object(self):
        # If [ appears before {, parse as array.
        text = '[{"slug": "a"}, {"slug": "b"}]'
        result = self._parse(text)
        assert isinstance(result, list)

    def test_parse_no_json_raises(self):
        with pytest.raises(ValueError, match="No JSON found"):
            self._parse("This is just plain text with no JSON.")


class TestDiscoverFolders:
    """Tests for the discover folders HTMX endpoint (GET /triage/discover/folders)."""

    def test_requires_auth(self, client):
        resp = client.get("/triage/discover/folders?account_id=1")
        assert resp.status_code == 401

    def test_account_not_found(self, client, admin_cookies, admin_user):
        resp = client.get(
            "/triage/discover/folders?account_id=99999",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Account not found" in resp.text

    def test_forbidden_for_other_user(
        self, client, db, user_cookies, regular_user, admin_user,
    ):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Admin IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid

        resp = client.get(
            f"/triage/discover/folders?account_id={acct_id}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Access denied" in resp.text

    def test_discover_form_has_folder_options(self, client, db, admin_cookies, admin_user):
        """Discover page should have scan scope radio buttons."""
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (admin_user["id"], "Test IMAP", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()

        resp = client.get("/triage/discover", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "scan_scope" in resp.text
        assert "INBOX only" in resp.text
        assert "All folders" in resp.text
        assert "Selected folders" in resp.text

    def test_discover_run_accepts_scan_scope(self, client, db, admin_cookies, admin_user):
        """Discover run should accept scan_scope parameter without error."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            (admin_user["id"], "Disabled", "imap", json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid

        # Should get "disabled" error, not a crash from the scan_scope param.
        resp = client.post(
            "/triage/discover/run",
            data={
                "account_id": str(acct_id),
                "limit": "10",
                "query": "ALL",
                "scan_scope": "all",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Account disabled" in resp.text


# ---------------------------------------------------------------------------
# triage_runs.actor_user_id (audit item #15a)
# ---------------------------------------------------------------------------


class TestTriageRunsActorUserId:
    """``triage_runs.actor_user_id`` captures who initiated the run.

    NULL for system-initiated runs (push consumer, watcher, scheduled),
    populated for UI manual runs. The dashboard "Started by" column
    renders the name / email, falling back to ``system`` for NULL.
    """

    def _make_account(self, db, user_id):
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, is_active, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (user_id, "Test IMAP", "imap",
             json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        return cursor.lastrowid

    def test_triage_runs_has_actor_user_id_column(self, db):
        """Migration must add the column for upgraded DBs."""
        rows = db.execute("PRAGMA table_info(triage_runs)").fetchall()
        cols = {r["name"] for r in rows}
        assert "actor_user_id" in cols

    def test_triage_runs_records_actor_user_id_for_manual_run(
        self, db, admin_user,
    ):
        """Passing ``actor_user_id`` persists it. Mirrors what the UI
        manual-triage path does (``actor_user_id=user['id']``)."""
        from email_triage.web.db import record_triage_run, list_triage_runs

        acct_id = self._make_account(db, admin_user["id"])
        run_id = record_triage_run(
            db,
            account_id=acct_id,
            account_name="Test IMAP",
            query="UNSEEN",
            total_messages=0,
            results=[],
            errors=[],
            elapsed_secs=0.1,
            actor_user_id=admin_user["id"],
        )
        assert run_id > 0

        row = db.execute(
            "SELECT actor_user_id FROM triage_runs WHERE id = ?", (run_id,),
        ).fetchone()
        assert row["actor_user_id"] == admin_user["id"]

        runs = list_triage_runs(db, limit=5)
        assert runs[0]["actor_user_id"] == admin_user["id"]
        assert runs[0]["actor_email"] == admin_user["email"]
        assert runs[0]["actor_name"] == admin_user["name"]

    def test_triage_runs_actor_null_for_system_trigger(self, db, admin_user):
        """System-initiated runs (push, watch, scheduled) call
        ``record_triage_run`` without ``actor_user_id`` - must store NULL
        and render as ``system`` on the dashboard."""
        from email_triage.web.db import record_triage_run, list_triage_runs

        acct_id = self._make_account(db, admin_user["id"])
        run_id = record_triage_run(
            db,
            account_id=acct_id,
            account_name="Test IMAP",
            query="gmail_push",
            total_messages=0,
            results=[],
            errors=[],
            elapsed_secs=0.1,
        )
        row = db.execute(
            "SELECT actor_user_id FROM triage_runs WHERE id = ?", (run_id,),
        ).fetchone()
        assert row["actor_user_id"] is None

        runs = list_triage_runs(db, limit=5)
        assert runs[0]["actor_user_id"] is None
        assert runs[0]["actor_email"] is None
        assert runs[0]["actor_name"] is None

    def test_list_triage_runs_exposes_actor_name_and_system(
        self, client, db, admin_cookies, admin_user,
    ):
        """#11 / #15a: ``list_triage_runs`` must surface the actor name
        for manual runs and leave it NULL for system-initiated rows so
        downstream views (dashboard recent activity, /logs, future
        /runs page) can label each row without a second query.

        Before the #12 dashboard redesign this assertion lived on the
        dashboard HTML; the data contract is the same, it just lives
        on dedicated pages now, so we assert against the helper.
        """
        from email_triage.web.db import list_triage_runs, record_triage_run

        acct_id = self._make_account(db, admin_user["id"])
        record_triage_run(
            db, account_id=acct_id, account_name="Test IMAP",
            query="UNSEEN", total_messages=0, results=[], errors=[],
            elapsed_secs=0.1, actor_user_id=admin_user["id"],
        )
        record_triage_run(
            db, account_id=acct_id, account_name="Test IMAP",
            query="gmail_push", total_messages=0, results=[], errors=[],
            elapsed_secs=0.1,
        )

        runs = list_triage_runs(db, limit=5)
        # Newest first: system row, then manual row.
        assert runs[0]["actor_user_id"] is None
        assert runs[0]["actor_name"] is None
        assert runs[1]["actor_user_id"] == admin_user["id"]
        assert runs[1]["actor_name"] == admin_user["name"]


class TestRunTriageActorThrough:
    """``run_triage`` must thread its ``actor_user_id`` param through
    to ``record_triage_run`` - the UI route passes ``user['id']`` on
    manual runs, and that value needs to land on the row."""

    async def test_run_triage_threads_actor_user_id(self, app, db, admin_user):
        import json as _json
        from unittest.mock import AsyncMock, MagicMock, patch

        from email_triage.engine.models import Classification
        from email_triage.web.triage_runner import run_triage

        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, is_active, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "Test IMAP", "imap",
             _json.dumps({"host": "mail.test.com", "username": "u@t.com"}),
             now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid
        acct_row = db.execute(
            "SELECT * FROM email_accounts WHERE id = ?", (acct_id,),
        ).fetchone()
        acct = dict(acct_row)
        acct["config"] = _json.loads(acct_row["config_json"])

        fake_provider = MagicMock()
        fake_provider.search = AsyncMock(return_value=[])
        fake_provider.close = AsyncMock()
        fake_classifier = MagicMock()
        fake_classifier.classify = AsyncMock(return_value=Classification(
            category="action-required", confidence=0.9, reason="x",
        ))

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await run_triage(
                db, app.state.config, app.state.secrets, acct,
                query="ALL", limit=5,
                actor_user_id=admin_user["id"], trigger="manual",
            )

        row = db.execute(
            "SELECT actor_user_id FROM triage_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["actor_user_id"] == admin_user["id"]

    async def test_run_triage_system_trigger_stores_null_actor(
        self, app, db, admin_user,
    ):
        """Background paths (watch/push/scheduled) call ``run_triage``
        without ``actor_user_id``. The row must store NULL so the
        dashboard labels it ``system``."""
        import json as _json
        from unittest.mock import AsyncMock, MagicMock, patch

        from email_triage.engine.models import Classification
        from email_triage.web.triage_runner import run_triage

        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, is_active, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "Test IMAP", "imap",
             _json.dumps({"host": "mail.test.com", "username": "u@t.com"}),
             now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid
        acct_row = db.execute(
            "SELECT * FROM email_accounts WHERE id = ?", (acct_id,),
        ).fetchone()
        acct = dict(acct_row)
        acct["config"] = _json.loads(acct_row["config_json"])

        fake_provider = MagicMock()
        fake_provider.search = AsyncMock(return_value=[])
        fake_provider.close = AsyncMock()
        fake_classifier = MagicMock()
        fake_classifier.classify = AsyncMock(return_value=Classification(
            category="action-required", confidence=0.9, reason="x",
        ))

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await run_triage(
                db, app.state.config, app.state.secrets, acct,
                query="ALL", limit=5,
                actor_user_id=None, trigger="push",
            )

        row = db.execute(
            "SELECT actor_user_id FROM triage_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["actor_user_id"] is None
