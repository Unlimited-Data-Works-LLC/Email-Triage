"""Tests for the ProviderTraits registry (#138.2)."""

from __future__ import annotations

import pytest

from email_triage.providers.traits import (
    TRAITS,
    default_search_query,
    get_traits,
    has_default_scopes,
    inbox_only,
    is_authenticated,
    secret_key_for_account,
)


class FakeSecrets:
    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)


def test_traits_keys_are_canonical_ptypes():
    assert set(TRAITS.keys()) == {"imap", "gmail_api", "office365"}


def test_get_traits_imap():
    t = get_traits("imap")
    assert t is not None
    assert t.ptype == "imap"
    assert t.push_kind == "imap_idle"
    assert t.inbox_only is False
    assert t.secret_form_field == "password"
    assert t.default_search_query == "ALL"


def test_get_traits_gmail():
    t = get_traits("gmail_api")
    assert t is not None
    assert t.push_kind == "gmail_pubsub"
    assert t.inbox_only is True
    assert t.default_search_query == "in:sent"
    # Gmail doesn't have a form-field secret — refresh token comes from
    # the OAuth callback, not user input.
    assert t.secret_form_field is None


def test_get_traits_o365():
    t = get_traits("office365")
    assert t is not None
    assert t.push_kind == "graph_subscription"
    assert t.inbox_only is True
    assert t.secret_form_field == "client_secret"


def test_get_traits_unknown_returns_none():
    assert get_traits("carrier_pigeon") is None


def test_secret_key_for_account_each_provider():
    assert secret_key_for_account(7, "imap") == "ACCOUNT_7_IMAP_PASSWORD"
    assert (
        secret_key_for_account(7, "gmail_api")
        == "ACCOUNT_7_GMAIL_REFRESH_TOKEN"
    )
    assert secret_key_for_account(7, "office365") == "ACCOUNT_7_O365_SECRET"


def test_secret_key_for_account_unknown_is_none():
    assert secret_key_for_account(1, "??") is None


# ---------------------------------------------------------------------------
# is_authenticated
# ---------------------------------------------------------------------------

def test_is_authenticated_imap_with_password():
    secrets = FakeSecrets({"ACCOUNT_1_IMAP_PASSWORD": "hunter2"})
    acct = {"id": 1, "provider_type": "imap"}
    assert is_authenticated(secrets, acct) is True


def test_is_authenticated_imap_no_password():
    secrets = FakeSecrets()
    acct = {"id": 1, "provider_type": "imap"}
    assert is_authenticated(secrets, acct) is False


def test_is_authenticated_gmail_with_refresh_token():
    secrets = FakeSecrets({"ACCOUNT_5_GMAIL_REFRESH_TOKEN": "rt"})
    acct = {"id": 5, "provider_type": "gmail_api"}
    assert is_authenticated(secrets, acct) is True


def test_is_authenticated_gmail_empty_value_is_false():
    secrets = FakeSecrets({"ACCOUNT_5_GMAIL_REFRESH_TOKEN": ""})
    acct = {"id": 5, "provider_type": "gmail_api"}
    assert is_authenticated(secrets, acct) is False


def test_is_authenticated_unknown_ptype_is_false():
    secrets = FakeSecrets()
    acct = {"id": 1, "provider_type": ""}
    assert is_authenticated(secrets, acct) is False


def test_is_authenticated_secrets_raises_falls_back_to_false():
    class _BadSecrets:
        def get(self, key):
            raise RuntimeError("backend offline")

    acct = {"id": 1, "provider_type": "imap"}
    assert is_authenticated(_BadSecrets(), acct) is False


# ---------------------------------------------------------------------------
# inbox_only
# ---------------------------------------------------------------------------

def test_inbox_only_imap_false():
    """IMAP needs the operator to consciously pick folders + cadence."""
    assert inbox_only({"provider_type": "imap"}) is False


def test_inbox_only_gmail_true():
    assert inbox_only({"provider_type": "gmail_api"}) is True


def test_inbox_only_o365_true():
    assert inbox_only({"provider_type": "office365"}) is True


def test_inbox_only_unknown_false():
    assert inbox_only({"provider_type": ""}) is False


# ---------------------------------------------------------------------------
# has_default_scopes
# ---------------------------------------------------------------------------

def test_has_default_scopes_imap_always_true():
    assert has_default_scopes({"provider_type": "imap"}) is True
    assert (
        has_default_scopes({"provider_type": "imap", "config": {}})
        is True
    )


def test_has_default_scopes_gmail_default_set_is_true():
    assert (
        has_default_scopes({"provider_type": "gmail_api", "config": {}})
        is True
    )


def test_has_default_scopes_gmail_calendar_opted_in_false():
    acct = {
        "provider_type": "gmail_api",
        "config": {"calendar_opted_in": True},
    }
    assert has_default_scopes(acct) is False


def test_has_default_scopes_o365_default_set_is_true():
    assert (
        has_default_scopes({"provider_type": "office365", "config": {}})
        is True
    )


# ---------------------------------------------------------------------------
# default_search_query
# ---------------------------------------------------------------------------

def test_default_search_query_per_ptype():
    assert default_search_query("gmail_api") == "in:sent"
    assert default_search_query("imap") == "ALL"
    assert default_search_query("office365") == ""
    assert default_search_query("???") == ""
