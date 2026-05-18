"""Tests for #51 — per-mailbox route overrides."""

from email_triage.web.db import (
    create_email_account,
    effective_routes_by_cat,
    get_mailbox_route_overrides,
    set_mailbox_route_overrides,
    upsert_account_route,
)


def _make_account(db, regular_user):
    return create_email_account(
        db, regular_user["id"], "ACCT", "imap", {"host": "x.example.com"},
    )


def _set_account_routes(db, account_id, routes):
    for cat, actions in routes.items():
        upsert_account_route(db, account_id, cat, actions)


def test_no_overrides_returns_account_wide(db, regular_user):
    acct = _make_account(db, regular_user)
    _set_account_routes(db, acct, {
        "newsletters": [{"action": "label", "config": {}}],
    })
    eff = effective_routes_by_cat(db, acct, mailbox="INBOX")
    assert "newsletters" in eff
    assert eff["newsletters"] == [{"action": "label", "config": {}}]


def test_override_layers_on_account_wide(db, regular_user):
    acct = _make_account(db, regular_user)
    _set_account_routes(db, acct, {
        "newsletters": [{"action": "label", "config": {}}],
        "to-respond": [{"action": "notify", "config": {}}],
    })
    set_mailbox_route_overrides(db, acct, "Spam", [
        {"category": "newsletters",
         "actions": [{"action": "move",
                      "config": {"folder_map": {"newsletters": "Trash"}}}]},
    ])
    eff = effective_routes_by_cat(db, acct, mailbox="Spam")
    # Override wins for newsletters.
    assert eff["newsletters"][0]["action"] == "move"
    # Other categories inherit account-wide.
    assert eff["to-respond"][0]["action"] == "notify"


def test_other_mailbox_unaffected(db, regular_user):
    acct = _make_account(db, regular_user)
    _set_account_routes(db, acct, {
        "newsletters": [{"action": "label", "config": {}}],
    })
    set_mailbox_route_overrides(db, acct, "Spam", [
        {"category": "newsletters",
         "actions": [{"action": "move",
                      "config": {"folder_map": {"newsletters": "Trash"}}}]},
    ])
    inbox = effective_routes_by_cat(db, acct, mailbox="INBOX")
    spam = effective_routes_by_cat(db, acct, mailbox="Spam")
    assert inbox["newsletters"][0]["action"] == "label"
    assert spam["newsletters"][0]["action"] == "move"


def test_clearing_override_falls_back(db, regular_user):
    acct = _make_account(db, regular_user)
    _set_account_routes(db, acct, {
        "newsletters": [{"action": "label", "config": {}}],
    })
    set_mailbox_route_overrides(db, acct, "Spam", [
        {"category": "newsletters",
         "actions": [{"action": "move", "config": {}}]},
    ])
    # Clear with empty list.
    set_mailbox_route_overrides(db, acct, "Spam", [])
    assert get_mailbox_route_overrides(db, acct, "Spam") == []
    spam = effective_routes_by_cat(db, acct, mailbox="Spam")
    assert spam["newsletters"][0]["action"] == "label"


def test_mailbox_none_returns_base(db, regular_user):
    acct = _make_account(db, regular_user)
    _set_account_routes(db, acct, {
        "newsletters": [{"action": "label", "config": {}}],
    })
    set_mailbox_route_overrides(db, acct, "Spam", [
        {"category": "newsletters",
         "actions": [{"action": "move", "config": {}}]},
    ])
    # mailbox=None ignores any overrides — Gmail push path uses this.
    eff = effective_routes_by_cat(db, acct, mailbox=None)
    assert eff["newsletters"][0]["action"] == "label"
