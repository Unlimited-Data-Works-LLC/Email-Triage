"""Verify every POST handler hit from the routes-table page returns
a 200 (HTMX-swappable) or 4xx error chip — never a 303 redirect.

A 303 from an HTMX endpoint causes a full-page reload (HTMX follows
redirects by default), which is the exact UX bug #116 fixes.

The folder-prefs save IS allowed to 303 — it's a plain POST from a
non-HTMX page (folder_prefs.html). This test scopes to the routes
page handlers only.
"""

from email_triage.web.db import create_email_account


def _create_account(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "user@example.com"},
    )


class TestNo303Redirects:
    def test_routes_save_returns_200(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={"category": "newsletters", "actions": ["label"]},
            cookies=user_cookies, follow_redirects=False,
        )
        assert resp.status_code == 200, (
            f"routes/save must return 200 (HTMX chip), got {resp.status_code}"
        )
        assert "location" not in [k.lower() for k in resp.headers.keys()]

    def test_routes_save_all_returns_200(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data={"row_count": "0"},
            cookies=user_cookies, follow_redirects=False,
        )
        assert resp.status_code == 200, (
            f"routes/save-all must return 200, got {resp.status_code}"
        )

    def test_folder_create_returns_200(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/folders/create",
            data={"folder": "TestFolder", "parent": ""},
            cookies=user_cookies, follow_redirects=False,
        )
        # Response is 200 even on provider error — error message is
        # rendered as a chip, not a redirect.
        assert resp.status_code == 200
        # No redirect header.
        assert "location" not in [k.lower() for k in resp.headers.keys()]

    def test_route_delete_returns_200(
        self, client, db, regular_user, user_cookies,
    ):
        from email_triage.web.db import upsert_account_route
        a1 = _create_account(db, regular_user["id"])
        upsert_account_route(
            db, a1, "newsletters",
            [{"action": "label", "config": {}}],
        )
        # Find the route_id.
        from email_triage.web.db import list_account_routes
        routes = list_account_routes(db, a1)
        rid = routes[0]["id"]
        resp = client.delete(
            f"/accounts/{a1}/routes/{rid}",
            cookies=user_cookies, follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_routes_top_htmx_returns_200(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.get(
            f"/routes?account_id={a1}",
            cookies=user_cookies,
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "location" not in [k.lower() for k in resp.headers.keys()]
