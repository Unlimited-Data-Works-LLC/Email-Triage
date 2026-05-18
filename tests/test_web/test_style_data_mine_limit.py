"""#161 item 4 — per-account "Messages to mine" override + install default.

Covers:

  * GET /profile/style-data renders the input with placeholder = install
    default; with override value pre-filled when set.
  * POST /profile/style-data/mine-limit-override persists / clears the
    override.
  * ``resolve_account_mine_limit`` returns the right value across the
    {override-set, no-override, out-of-range-override} grid.
"""

from __future__ import annotations

from email_triage.web.db import (
    create_email_account,
    get_email_account,
    resolve_account_mine_limit,
    set_style_learning_mine_limit_default,
    update_account_config_keys,
    STYLE_LEARNING_MINE_LIMIT_DEFAULT,
    STYLE_LEARNING_MINE_LIMIT_MAX,
)


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


class TestRender:
    def test_page_shows_placeholder_with_install_default(
        self, client, user_cookies, db, regular_user,
    ):
        _make_acct(db, regular_user["id"], "Personal")
        set_style_learning_mine_limit_default(db, 75)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert 'name="mine_limit_override"' in resp.text
        # Placeholder = install default.
        assert 'placeholder="75"' in resp.text

    def test_override_value_prefilled_when_set(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(db, a, mine_limit_override=100)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert 'value="100"' in resp.text


class TestSave:
    def test_save_persists_override(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        resp = client.post(
            f"/profile/style-data/mine-limit-override?account_id={a}",
            data={"mine_limit_override": "100"},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        assert acct["config"].get("mine_limit_override") == 100

    def test_empty_clears_override(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(db, a, mine_limit_override=100)
        resp = client.post(
            f"/profile/style-data/mine-limit-override?account_id={a}",
            data={"mine_limit_override": ""},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        # update_account_config_keys' None contract drops the key.
        assert "mine_limit_override" not in (acct.get("config") or {})

    def test_save_clamps_above_max(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        resp = client.post(
            f"/profile/style-data/mine-limit-override?account_id={a}",
            data={"mine_limit_override": "9999"},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        assert (
            acct["config"]["mine_limit_override"]
            == STYLE_LEARNING_MINE_LIMIT_MAX
        )


class TestResolver:
    def test_no_override_returns_install_default(self, db, regular_user):
        a = _make_acct(db, regular_user["id"], "Personal")
        set_style_learning_mine_limit_default(db, 75)
        acct = get_email_account(db, a)
        assert resolve_account_mine_limit(db, acct) == 75

    def test_override_wins(self, db, regular_user):
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(db, a, mine_limit_override=42)
        acct = get_email_account(db, a)
        assert resolve_account_mine_limit(db, acct) == 42

    def test_no_override_no_default_returns_baseline(self, db, regular_user):
        a = _make_acct(db, regular_user["id"], "Personal")
        acct = get_email_account(db, a)
        assert (
            resolve_account_mine_limit(db, acct)
            == STYLE_LEARNING_MINE_LIMIT_DEFAULT
        )

    def test_invalid_override_falls_through_to_default(
        self, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(
            db, a, mine_limit_override="not-a-number",
        )
        set_style_learning_mine_limit_default(db, 50)
        acct = get_email_account(db, a)
        assert resolve_account_mine_limit(db, acct) == 50
