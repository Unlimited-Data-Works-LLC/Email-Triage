"""Tests for the OAuth/auth stale-flag detection + chip + health email."""

import pytest

from email_triage.web.app import _clear_auth_stale, _maybe_mark_auth_stale
from email_triage.web.db import (
    create_email_account,
    get_setting,
)


def _acct(db, regular_user):
    return {
        "id": create_email_account(
            db, regular_user["id"], "ACCT", "gmail_api", {"host": "x"},
        ),
        "name": "ACCT",
    }


class TestStaleAuthDetection:
    def test_token_expired_or_revoked_marks_stale(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(
            db, a,
            Exception("Gmail API 400: Token has been expired or revoked."),
        )
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_invalid_grant_marks_stale(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(db, a, Exception("invalid_grant: bad token"))
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_imap_authenticationfailed_marks_stale(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(
            db, a, Exception("AUTHENTICATIONFAILED: bad password"),
        )
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_unrelated_error_does_not_mark(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(db, a, Exception("connection refused"))
        assert get_setting(db, f"auth_stale:{a['id']}") is None

    def test_clear_removes_flag(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(
            db, a, Exception("Token has been expired or revoked"),
        )
        assert get_setting(db, f"auth_stale:{a['id']}") is not None
        _clear_auth_stale(db, a["id"])
        assert get_setting(db, f"auth_stale:{a['id']}") is None


class TestHealthEmailIncludesStaleAuth:
    def test_attention_reason_added(self, db, regular_user):
        from email_triage.config import TriageConfig
        from email_triage.web.daily_health import gather_health_state

        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(
            db, a,
            Exception("Gmail API 400: Token has been expired or revoked."),
        )

        cfg = TriageConfig()
        state = gather_health_state(db, cfg)
        # Stale-auth reason landed in attention_reasons.
        joined = " ".join(state["attention_reasons"])
        assert "re-authentication" in joined.lower()
        # Account name surfaced.
        assert "ACCT" in joined
        # Stale_auth_accounts list populated.
        assert len(state["stale_auth_accounts"]) == 1
        assert state["stale_auth_accounts"][0]["account_name"] == "ACCT"


class TestRowChipRender:
    def test_chip_shown_when_stale(
        self, client, admin_cookies, db, admin_user,
    ):
        from email_triage.web.db import create_email_account
        a = create_email_account(
            db, admin_user["id"], "STALE", "gmail_api", {"host": "x"},
        )
        _maybe_mark_auth_stale(
            db, {"id": a, "name": "STALE"},
            Exception("Gmail API 400: Token has been expired or revoked."),
        )
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Re-authenticate required" in resp.text

    def test_chip_hidden_when_not_stale(
        self, client, admin_cookies, db, admin_user,
    ):
        from email_triage.web.db import create_email_account
        create_email_account(
            db, admin_user["id"], "FRESH", "gmail_api", {"host": "x"},
        )
        resp = client.get("/accounts", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Re-authenticate required" not in resp.text
