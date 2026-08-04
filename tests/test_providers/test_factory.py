"""Tests for the provider factory.

Verifies ``build_provider`` constructs the correct provider instance
for each ``provider_type`` value, raises a clean ValueError on
unknown types, and threads secrets / OAuth singletons through
correctly.
"""

from __future__ import annotations

import pytest

from email_triage.providers.factory import (
    build_provider,
    secret_key_for_account,
    set_install_google_oauth,
)


class FakeSecrets:
    """In-memory secrets backend for tests."""

    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value


class FakeOAuthConfig:
    web_client_id = "web-cid"
    web_client_secret = "web-secret"
    desktop_client_id = "desk-cid"
    desktop_client_secret = "desk-secret"


def test_secret_key_for_account_imap():
    assert secret_key_for_account(7, "imap") == "ACCOUNT_7_IMAP_PASSWORD"


def test_secret_key_for_account_gmail():
    assert (
        secret_key_for_account(42, "gmail_api")
        == "ACCOUNT_42_GMAIL_REFRESH_TOKEN"
    )


def test_secret_key_for_account_o365():
    assert (
        secret_key_for_account(13, "office365") == "ACCOUNT_13_O365_SECRET"
    )


def test_secret_key_for_account_unknown_returns_none():
    assert secret_key_for_account(1, "carrier_pigeon") is None


def test_build_provider_imap_uses_first_mailbox():
    """IMAP build should pull the first entry from ``config.mailboxes``."""
    pytest.importorskip("aioimaplib")
    secrets = FakeSecrets({"ACCOUNT_5_IMAP_PASSWORD": "hunter2"})
    acct = {
        "id": 5,
        "provider_type": "imap",
        "config": {
            "host": "imap.example.com",
            "port": 993,
            "username": "user",
            "use_ssl": True,
            "mailboxes": ["INBOX", "Archive"],
        },
    }
    provider = build_provider(acct, secrets)
    assert provider.name == "imap"
    assert provider._mailbox == "INBOX"
    assert provider._password == "hunter2"


def test_build_provider_imap_mailbox_override():
    pytest.importorskip("aioimaplib")
    secrets = FakeSecrets({"ACCOUNT_5_IMAP_PASSWORD": "hunter2"})
    acct = {
        "id": 5,
        "provider_type": "imap",
        "config": {
            "host": "imap.example.com",
            "username": "user",
            "mailboxes": ["INBOX"],
        },
    }
    provider = build_provider(acct, secrets, mailbox_override="Archive")
    assert provider._mailbox == "Archive"


def test_build_provider_gmail_uses_install_oauth():
    """Gmail build should pull client_id/secret from install singleton."""
    set_install_google_oauth(FakeOAuthConfig())
    try:
        secrets = FakeSecrets({"ACCOUNT_3_GMAIL_REFRESH_TOKEN": "rt-abc"})
        acct = {
            "id": 3,
            "provider_type": "gmail_api",
            "config": {"account": "alice@example.com"},
        }
        provider = build_provider(acct, secrets)
        assert provider.name == "gmail_api"
        assert provider._client_id == "web-cid"
        assert provider._client_secret == "web-secret"
        assert provider._refresh_token == "rt-abc"
    finally:
        set_install_google_oauth(None)


def test_hydrate_and_register_install_oauth_wires_gmail_client_id():
    """N-130: the SSOT reads the install OAuth creds from the secrets store +
    registers them, so build_provider gives a gmail_api account a real
    client_id — the fix for the CLI mine's 'client_id not configured' (the CLI
    runs outside the boot, so nothing else registered them)."""
    from email_triage.config import TriageConfig
    from email_triage.providers.factory import (
        hydrate_and_register_install_oauth,
        set_install_google_oauth,
        set_install_office365_oauth,
        set_install_ingestion_config,
    )

    secrets = FakeSecrets({
        "GOOGLE_OAUTH_WEB_CLIENT_ID": "web-cid",
        "GOOGLE_OAUTH_WEB_CLIENT_SECRET": "web-secret",
        "ACCOUNT_3_GMAIL_REFRESH_TOKEN": "rt-abc",
    })
    config = TriageConfig()
    try:
        # Pre-condition: nothing registered -> a Gmail build would have an empty
        # client_id (the bug). After the SSOT runs, it's wired.
        hydrate_and_register_install_oauth(config, secrets)
        assert config.google_oauth.web_client_id == "web-cid"
        assert config.google_oauth.web_client_secret == "web-secret"
        acct = {
            "id": 3,
            "provider_type": "gmail_api",
            "config": {"account": "alice@example.com"},
        }
        provider = build_provider(acct, secrets)
        assert provider._client_id == "web-cid", (
            "hydrate_and_register_install_oauth did not wire the install client_id "
            "into the factory -> the CLI mine would fail 'client_id not configured'"
        )
        assert provider._client_secret == "web-secret"
        assert provider._refresh_token == "rt-abc"
    finally:
        set_install_google_oauth(None)
        set_install_office365_oauth(None)
        set_install_ingestion_config(None)


def test_build_provider_gmail_falls_back_to_desktop():
    class _NoWebPair:
        web_client_id = ""
        web_client_secret = ""
        desktop_client_id = "desk-cid"
        desktop_client_secret = "desk-secret"

    set_install_google_oauth(_NoWebPair())
    try:
        secrets = FakeSecrets({"ACCOUNT_3_GMAIL_REFRESH_TOKEN": "rt-abc"})
        acct = {
            "id": 3,
            "provider_type": "gmail_api",
            "config": {"account": "alice@example.com"},
        }
        provider = build_provider(acct, secrets)
        assert provider._client_id == "desk-cid"
        assert provider._client_secret == "desk-secret"
    finally:
        set_install_google_oauth(None)


def test_build_provider_gmail_explicit_oauth_override():
    """Test override beats the install singleton."""
    set_install_google_oauth(FakeOAuthConfig())
    try:
        class _Override:
            web_client_id = "override-cid"
            web_client_secret = "override-secret"
            desktop_client_id = ""
            desktop_client_secret = ""

        secrets = FakeSecrets()
        acct = {
            "id": 1,
            "provider_type": "gmail_api",
            "config": {"account": "x@example.com"},
        }
        provider = build_provider(acct, secrets, google_oauth=_Override())
        assert provider._client_id == "override-cid"
    finally:
        set_install_google_oauth(None)


def test_build_provider_o365():
    pytest.importorskip("msal")
    # Per the 2026-05-10 per-account -> install-level OAuth lift, build_provider
    # reads O365 client_id/secret from the INSTALL-level Office365OAuthConfig, NOT
    # the per-account config. (This test was silently SKIPPED while msal was
    # absent — importorskip — so it drifted stale against the lift; the conftest
    # msal stub now runs it. Updated to set up install-level OAuth, mirroring the
    # gmail sibling above.)
    from email_triage.config import Office365OAuthConfig
    from email_triage.providers.factory import set_install_office365_oauth
    set_install_office365_oauth(
        Office365OAuthConfig(
            tenant_id="common", client_id="graph-cid", client_secret="graph-secret",
        )
    )
    try:
        secrets = FakeSecrets()
        acct = {
            "id": 9,
            "provider_type": "office365",
            "config": {"account": "clinic@example.com"},
        }
        provider = build_provider(acct, secrets)
        assert provider.name == "office365"
        assert provider._client_id == "graph-cid"
        assert provider._client_secret == "graph-secret"
    finally:
        set_install_office365_oauth(None)


def test_build_provider_unknown_type_raises():
    secrets = FakeSecrets()
    acct = {
        "id": 1,
        "provider_type": "carrier_pigeon",
        "config": {},
    }
    with pytest.raises(ValueError, match="carrier_pigeon"):
        build_provider(acct, secrets)


def test_legacy_alias_via_routers_ui():
    """The shim in routers/ui.py keeps the old name working."""
    from email_triage.web.routers.ui import _create_provider_from_account
    assert _create_provider_from_account is build_provider
