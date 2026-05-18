"""Tests for per-user personal categories (#62 + #87)."""

import pytest

from email_triage.web.db import (
    MAX_PERSONAL_CATEGORIES_PER_USER,
    count_personal_categories,
    create_category,
    delete_category,
    demote_category_to_user,
    get_categories_dict,
    list_categories,
    promote_category_to_system,
)


class TestPersonalCategorySchema:
    def test_system_cat_default(self, db):
        cat_id = create_category(db, "system-only", "A system cat")
        cats = list_categories(db, scope="system")
        assert any(c["id"] == cat_id and c["user_id"] is None for c in cats)

    def test_personal_cat_scoped_to_user(self, db, regular_user):
        cat_id = create_category(
            db, "my-woodworking", "Woodworking sites",
            user_id=regular_user["id"],
        )
        personal = list_categories(
            db, user_id=regular_user["id"], scope="personal",
        )
        assert any(c["id"] == cat_id for c in personal)

    def test_same_slug_two_users(self, db, admin_user, regular_user):
        """Two users may each have a personal cat with the same slug."""
        a = create_category(db, "receipts", "Admin receipts",
                            user_id=admin_user["id"])
        b = create_category(db, "receipts", "User receipts",
                            user_id=regular_user["id"])
        assert a != b

    def test_system_slug_collision_rejected(self, db):
        """Two rows with the same slug at system scope must fail."""
        create_category(db, "shared-slug", "first")
        with pytest.raises(Exception):
            create_category(db, "shared-slug", "dup")

    def test_personal_cap(self, db, regular_user):
        """Hitting the personal cap raises ValueError."""
        for i in range(MAX_PERSONAL_CATEGORIES_PER_USER):
            create_category(
                db, f"cat-{i}", f"Cat {i}", user_id=regular_user["id"],
            )
        assert count_personal_categories(db, regular_user["id"]) == \
            MAX_PERSONAL_CATEGORIES_PER_USER
        with pytest.raises(ValueError, match="Personal category limit"):
            create_category(
                db, "over-limit", "over", user_id=regular_user["id"],
            )


class TestClassifierMerge:
    def test_merge_system_plus_personal(self, db, admin_user, regular_user):
        """get_categories_dict(user_id) returns system ∪ this user's
        personal, but excludes other users' personal cats."""
        create_category(db, "admin-only", "Admin only",
                        user_id=admin_user["id"])
        create_category(db, "user-only", "User only",
                        user_id=regular_user["id"])

        # Regular user sees system + their own.
        merged = get_categories_dict(db, user_id=regular_user["id"])
        assert "user-only" in merged
        assert "admin-only" not in merged

        # Admin sees system + their own.
        merged_admin = get_categories_dict(db, user_id=admin_user["id"])
        assert "admin-only" in merged_admin
        assert "user-only" not in merged_admin

    def test_personal_overrides_system_on_slug(self, db, regular_user):
        """Personal cat with same slug as system wins in merged dict."""
        sys_id = create_category(db, "shared", "System description")
        create_category(
            db, "shared", "User personal description",
            user_id=regular_user["id"],
        )
        merged = get_categories_dict(db, user_id=regular_user["id"])
        assert merged["shared"] == "User personal description"
        # System-scope-only query still returns the system description.
        sys_only = get_categories_dict(db, user_id=None)
        assert sys_only["shared"] == "System description"

    def test_system_only_when_no_user_id(self, db, regular_user):
        create_category(db, "personal-cat", "x", user_id=regular_user["id"])
        sys_only = get_categories_dict(db, user_id=None)
        assert "personal-cat" not in sys_only


class TestPromote:
    def test_promote_personal_to_system(self, db, regular_user):
        cat_id = create_category(
            db, "candidate", "Useful", user_id=regular_user["id"],
        )
        assert promote_category_to_system(db, cat_id) is True
        sys_cats = list_categories(db, scope="system")
        row = next(c for c in sys_cats if c["id"] == cat_id)
        assert row["user_id"] is None

    def test_promote_system_is_noop(self, db):
        cat_id = create_category(db, "already-system", "x")
        assert promote_category_to_system(db, cat_id) is False

    def test_promote_collision_rejected(self, db, regular_user):
        create_category(db, "dup-slug", "System")
        cat_id = create_category(
            db, "dup-slug", "Personal", user_id=regular_user["id"],
        )
        with pytest.raises(ValueError, match="already exists"):
            promote_category_to_system(db, cat_id)


class TestProfileUI:
    def test_personal_categories_page_shows_section(
        self, client, user_cookies, db, regular_user,
    ):
        """Personal Categories moved from a /profile sub-tab to its
        own page under the Rules cluster (2026-05-05 nav reorg).
        Same form + HTMX endpoints; only the surface changed.
        """
        create_category(
            db, "my-hobby", "Hobby stuff", user_id=regular_user["id"],
        )
        resp = client.get("/rules/personal-categories", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Personal Categories" in resp.text
        assert "my-hobby" in resp.text

    def test_profile_create_personal_category(
        self, client, user_cookies, db, regular_user,
    ):
        resp = client.post(
            "/profile/personal-categories/create",
            data={"slug": "new-personal",
                  "description": "From form"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "new-personal" in resp.text
        # Confirm it was stored under this user.
        personal = list_categories(
            db, user_id=regular_user["id"], scope="personal",
        )
        assert any(c["slug"] == "new-personal" for c in personal)

    def test_profile_delete_only_own_cat(
        self, client, user_cookies, db, admin_user,
    ):
        """User cannot delete another user's personal cat via the personal
        endpoint -- 403."""
        other_id = create_category(
            db, "admins-own", "x", user_id=admin_user["id"],
        )
        resp = client.delete(
            f"/profile/personal-categories/{other_id}",
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_my_rules_dropdown_shows_personal_categories(
        self, client, user_cookies, db, regular_user,
    ):
        """Regression for the 2026-05-17 bug: the "Suggested Category"
        dropdown on /rules (and /rules/global) was sourced from
        ``_get_categories_from_db(db)`` without a ``user_id`` arg,
        which collapses to system-only (``user_id IS NULL``) and
        silently hides every personal category the user created via
        the Categories page. Operator caught it: they could see their
        personal category on the Categories tab but it wasn't in the
        Rules form's dropdown. Fix passes ``user_id=user["id"]`` to
        the snapshot helper. This test exists to catch any future
        site that unscopes the call by accident.
        """
        create_category(
            db, "vendor-followup", "Vendor follow-up reminders",
            user_id=regular_user["id"],
        )
        resp = client.get("/rules", cookies=user_cookies)
        assert resp.status_code == 200
        # The dropdown emits `<option value="<slug>"...>...` entries.
        # Belt-and-braces: assert both the slug and the description
        # title text are present, so a future refactor that swaps the
        # template idiom for the dropdown still trips this regression.
        assert "vendor-followup" in resp.text, (
            "Personal category slug missing from /rules dropdown "
            "(see _build_rules_page_snapshot — user_id must be passed)"
        )
        assert "Vendor follow-up reminders" in resp.text


class TestDemote:
    """#87 second half: move a system category to personal scope for one user."""

    def test_demote_system_to_user(self, db, regular_user):
        cat_id = create_category(db, "infrequent", "Niche category")
        assert demote_category_to_user(db, cat_id, regular_user["id"]) is True
        personal = list_categories(
            db, user_id=regular_user["id"], scope="personal",
        )
        assert any(c["id"] == cat_id for c in personal)
        # System scope should no longer see it.
        sys_only = list_categories(db, scope="system")
        assert not any(c["id"] == cat_id for c in sys_only)

    def test_demote_personal_is_noop(self, db, regular_user):
        """Demoting a cat that is already personal returns False."""
        cat_id = create_category(
            db, "personal", "x", user_id=regular_user["id"],
        )
        assert demote_category_to_user(db, cat_id, regular_user["id"]) is False

    def test_demote_collision_rejected(self, db, regular_user):
        """Target user already has a personal cat with the same slug ->
        ValueError."""
        create_category(
            db, "newsletter", "Personal", user_id=regular_user["id"],
        )
        sys_id = create_category(db, "newsletter", "System")
        with pytest.raises(ValueError, match="already has a personal"):
            demote_category_to_user(db, sys_id, regular_user["id"])

    def test_demote_cap_exceeded(self, db, regular_user):
        """Target user already at the personal cap -> ValueError."""
        for i in range(MAX_PERSONAL_CATEGORIES_PER_USER):
            create_category(
                db, f"p-{i}", f"P {i}", user_id=regular_user["id"],
            )
        sys_id = create_category(db, "would-overflow", "system")
        with pytest.raises(ValueError, match="personal category cap"):
            demote_category_to_user(db, sys_id, regular_user["id"])

    def test_demote_unknown_user_rejected(self, db):
        sys_id = create_category(db, "any", "x")
        with pytest.raises(ValueError, match="does not exist"):
            demote_category_to_user(db, sys_id, 99999)


class TestPromoteDemoteAudit:
    """#87 audit-trail requirement: scope flips write to auth_events."""

    def test_promote_writes_audit_event(
        self, client, admin_cookies, db, regular_user,
    ):
        cat_id = create_category(
            db, "to-promote", "x", user_id=regular_user["id"],
        )
        resp = client.post(
            f"/categories/{cat_id}/promote", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT event_type, outcome, detail FROM auth_events "
            "WHERE event_type = 'category_promote'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
        assert f"cat_id={cat_id}" in rows[0]["detail"]
        assert "slug=to-promote" in rows[0]["detail"]
        assert f"from_user_id={regular_user['id']}" in rows[0]["detail"]

    def test_demote_writes_audit_event(
        self, client, admin_cookies, db, regular_user,
    ):
        cat_id = create_category(db, "to-demote", "system")
        resp = client.post(
            f"/categories/{cat_id}/demote",
            data={"target_user_id": regular_user["id"]},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT event_type, outcome, detail FROM auth_events "
            "WHERE event_type = 'category_demote'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
        assert f"cat_id={cat_id}" in rows[0]["detail"]
        assert "slug=to-demote" in rows[0]["detail"]
        assert f"to_user_id={regular_user['id']}" in rows[0]["detail"]

    def test_demote_collision_writes_failure_audit(
        self, client, admin_cookies, db, regular_user,
    ):
        create_category(
            db, "dupe", "Personal", user_id=regular_user["id"],
        )
        sys_id = create_category(db, "dupe", "System")
        resp = client.post(
            f"/categories/{sys_id}/demote",
            data={"target_user_id": regular_user["id"]},
            cookies=admin_cookies,
        )
        # Returns the row partial with error inline (200, not a 4xx)
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT outcome, detail FROM auth_events "
            "WHERE event_type = 'category_demote'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "failure"
        assert "already has a personal" in rows[0]["detail"]


class TestDemoteRouteAuth:
    """#87 admin-only gate on the demote routes."""

    def test_demote_form_requires_admin(
        self, client, user_cookies, db,
    ):
        cat_id = create_category(db, "any", "x")
        resp = client.get(
            f"/categories/{cat_id}/demote-form", cookies=user_cookies,
        )
        # _require_admin_user returns 403 for non-admin
        assert resp.status_code == 403

    def test_demote_post_requires_admin(
        self, client, user_cookies, db, admin_user,
    ):
        cat_id = create_category(db, "any", "x")
        resp = client.post(
            f"/categories/{cat_id}/demote",
            data={"target_user_id": admin_user["id"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_demote_form_rejects_personal_cat(
        self, client, admin_cookies, db, regular_user,
    ):
        cat_id = create_category(
            db, "already-personal", "x", user_id=regular_user["id"],
        )
        resp = client.get(
            f"/categories/{cat_id}/demote-form", cookies=admin_cookies,
        )
        assert resp.status_code == 400
