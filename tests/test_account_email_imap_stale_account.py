"""Panel r17 MUST-B1: a stale OAuth ``config["account"]`` on an IMAP account
must not outrank ``email_address`` in ``account_email`` (the IMAP From default
in ``build_provider`` reads it).

An account switched from gmail_api/office365 to imap keeps its old config keys,
so ``account`` can survive the switch. Only the OAuth providers write it.
"""

from __future__ import annotations

from email_triage.db.accounts import account_email


def test_imap_ignores_stale_oauth_account_key():
    acct = {
        "provider_type": "imap",
        "config": {
            "account": "old-oauth@example.invalid",
            "email_address": "me@example.invalid",
            "username": "me",
        },
    }
    assert account_email(acct) == "me@example.invalid"


def test_imap_stale_account_falls_back_to_username():
    acct = {"provider_type": "imap",
            "config": {"account": "old@example.invalid", "username": "me@example.invalid"}}
    assert account_email(acct) == "me@example.invalid"


def test_oauth_providers_still_prefer_account():
    for ptype in ("gmail_api", "office365"):
        acct = {"provider_type": ptype,
                "config": {"account": "oauth@example.invalid",
                           "email_address": "other@example.invalid"}}
        assert account_email(acct) == "oauth@example.invalid", ptype


def test_missing_provider_type_keeps_legacy_priority():
    acct = {"config": {"account": "a@example.invalid", "email_address": "b@example.invalid"}}
    assert account_email(acct) == "a@example.invalid"
