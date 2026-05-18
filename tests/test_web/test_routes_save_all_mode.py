"""Tests for the manual Save-All mode on the routes table (#116).

Covers:
  * POST /accounts/{id}/routes/save-all writes every row in one
    transaction — atomic on validation failure.
  * Unknown category aborts the whole batch (no partial saves).
  * Empty actions list clears the route's actions.
  * Move folder + label actions persist correctly.
"""

from email_triage.web.db import (
    create_email_account, list_account_routes, upsert_account_route,
)


def _create_account(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "user@example.com"},
    )


class TestRoutesSaveAll:
    def test_save_all_writes_every_row(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        # Three categories from the default seed. Use a dict where
        # repeated values get a list — httpx form-encodes that the
        # multi-value way browsers do.
        data = {
            "row_count": "3",
            "row_0_category": "newsletters",
            "row_0_actions": "label",
            "row_0_move_folder": "",
            "row_1_category": "to-respond",
            "row_1_actions": ["notify", "draft_reply"],
            "row_1_move_folder": "",
            "row_2_category": "notifications",
            "row_2_actions": "move",
            "row_2_move_folder": "Junk",
        }
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data=data, cookies=user_cookies,
        )
        assert resp.status_code == 200, resp.text
        assert "Saved" in resp.text
        routes = list_account_routes(db, a1)
        cats = {r["category"]: r for r in routes}
        # Newsletters → label only.
        assert [a["action"] for a in cats["newsletters"]["actions"]] == ["label"]
        # to-respond → notify + draft_reply.
        names = sorted(a["action"] for a in cats["to-respond"]["actions"])
        assert names == ["draft_reply", "notify"]
        # notifications → move with folder_map.
        notif_actions = cats["notifications"]["actions"]
        move = next(a for a in notif_actions if a["action"] == "move")
        assert move["config"]["folder_map"]["notifications"] == "Junk"

    def test_unknown_category_rejects_whole_batch(
        self, client, db, regular_user, user_cookies,
    ):
        """Validation error on ANY row aborts the whole batch — no
        partial state lands on disk."""
        a1 = _create_account(db, regular_user["id"])
        # Pre-seed one route so we can detect "unchanged on rollback".
        upsert_account_route(
            db, a1, "newsletters",
            [{"action": "label", "config": {}}],
        )
        data = {
            "row_count": "2",
            "row_0_category": "newsletters",
            "row_0_actions": "notify",
            "row_0_move_folder": "",
            # Bogus second row.
            "row_1_category": "this-is-not-a-real-category",
            "row_1_actions": "label",
            "row_1_move_folder": "",
        }
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data=data, cookies=user_cookies,
        )
        assert resp.status_code == 400
        # Error chip mentions the bad row.
        assert "this-is-not-a-real-category" in resp.text
        # Pre-seeded route was NOT overwritten.
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        action_names = [a["action"] for a in nl["actions"]]
        assert action_names == ["label"]

    def test_anonymous_unauthorized(self, client, db, regular_user):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data={"row_count": "0"},
        )
        assert resp.status_code == 401

    def test_not_owned_returns_403(
        self, client, db, admin_user, regular_user, user_cookies,
    ):
        a_admin = _create_account(db, admin_user["id"], name="other_acct")
        resp = client.post(
            f"/accounts/{a_admin}/routes/save-all",
            data={"row_count": "0"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_empty_actions_clears_route(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        upsert_account_route(
            db, a1, "newsletters",
            [{"action": "label", "config": {}}],
        )
        data = {
            "row_count": "1",
            "row_0_category": "newsletters",
            # No row_0_actions key → empty list on the server.
            "row_0_move_folder": "",
        }
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data=data, cookies=user_cookies,
        )
        assert resp.status_code == 200
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        # upsert with [] persists empty actions list.
        assert nl["actions"] == []
