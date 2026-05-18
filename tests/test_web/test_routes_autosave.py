"""Tests for routes-table auto-save behaviour (#116).

Covers:
  * Per-row POST hits /routes/save with category + actions and
    server returns the chip ('Saved HH:MM ...').
  * Move-folder selection persists in route config.
  * Pending indicator markup present (the row carries the
    ``route-row`` class so client JS can flip it pending).
  * The body partial does NOT have per-row Save buttons (the spec
    drops them in favour of the change-debounce auto-save).
"""

from email_triage.web.db import (
    create_email_account, list_account_routes, upsert_account_route,
)


def _create_account(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "user@example.com"},
    )


class TestRoutesAutoSave:
    def test_route_save_returns_saved_chip(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={"category": "newsletters", "actions": ["label"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Chip text starts with "Saved" + a timestamp.
        assert "Saved" in resp.text
        # Persisted to DB.
        routes = list_account_routes(db, a1)
        assert any(r["category"] == "newsletters" for r in routes)

    def test_route_save_with_move_folder(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "newsletters",
                "actions": ["move"],
                "move_folder": "Newsletters",
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Saved" in resp.text
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        actions = nl["actions"]
        move_act = next(a for a in actions if a["action"] == "move")
        assert move_act["config"]["folder_map"]["newsletters"] == "Newsletters"

    def test_no_per_row_save_buttons_in_partial(self):
        """The auto-save UX removes the per-row Save button. The body
        partial must not render an inline ``<button type="submit">Save</button>``
        inside any route-row form — the trigger is the row-level
        ``hx-trigger="change ... delay:500ms"`` instead."""
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        text = path.read_text(encoding="utf-8")
        # Per-row form fields end before the </form> — assert no
        # 'Save' submit button text inside the per-row form region.
        # Look for the per-row form open + count "Save" submit buttons
        # WITHIN the row scope. Easy proxy: the original line 151 string
        # ``<button type="submit" class="outline" ... >Save</button>``
        # must be gone. We check for the legacy structure explicitly.
        assert ">Save</button>" not in text, (
            "Per-row Save button must be removed in favour of "
            "auto-save change-debounce trigger."
        )

    def test_pending_indicator_class_in_partial(self):
        """The body partial must carry the ``route-row`` class on
        each row so the client JS can toggle ``route-pending`` while
        the debounce window runs. Updated 2026-05-12 — the row root
        moved from <tr class="route-row"> (table layout) to <article
        class="route-row route-card"> (card layout). The class name
        survives both layouts so the JS keeps working unchanged."""
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        text = path.read_text(encoding="utf-8")
        # Class list may be compound (`route-row route-card`);
        # match the bare class token instead of the entire attr.
        assert "route-row" in text
        assert "route-pending" in text  # CSS rule + JS toggle target
        assert "fade-out" in text       # chip-fade CSS class

    def test_change_debounce_trigger_present(self):
        """Each row form must carry the change-debounced HTMX
        trigger. Updated 2026-05-12 — closest-anchor moved from
        <tr> to <article> when the row root changed; the debounce
        delay is unchanged."""
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        text = path.read_text(encoding="utf-8")
        assert "delay:500ms" in text
        # Body partial uses `change from:closest article` (was
        # `closest tr` before the card-layout refresh).
        assert "change from:closest article" in text

    def test_overwrite_existing_route(
        self, client, db, regular_user, user_cookies,
    ):
        """Successive saves to the same category overwrite — the
        change debounce can fire multiple times as the operator
        toggles checkboxes; final state must be the latest save."""
        a1 = _create_account(db, regular_user["id"])
        # First save: label
        client.post(
            f"/accounts/{a1}/routes/save",
            data={"category": "newsletters", "actions": ["label"]},
            cookies=user_cookies,
        )
        # Second save: notify (replace)
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={"category": "newsletters", "actions": ["notify"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        action_names = [a["action"] for a in nl["actions"]]
        assert action_names == ["notify"]
