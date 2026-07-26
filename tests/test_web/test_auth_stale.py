"""Tests for the OAuth/auth stale-flag detection + chip + health email."""

import pytest

from email_triage.web.app import (
    _clear_auth_stale,
    _maybe_mark_auth_stale,
    record_provider_outcome,
)
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

    def test_gmail_token_endpoint_401_marks_stale(self, db, regular_user):
        # The EXACT live-captured shape (2026-06-08): Google's token endpoint
        # rejects the REFRESH with 401 (invalid_client) when the OAuth client
        # secret is wrong / was rotated. Distinct from the 400 invalid_grant
        # token-revoked case — was NOT covered, so all 3 Gmail accounts 401'd
        # with NO "Re-authenticate required" chip (the row looked healthy).
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(
            db, a,
            Exception(
                "Gmail API 401: Unauthorized "
                "(https://oauth2.googleapis.com/token)"
            ),
        )
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_invalid_client_code_marks_stale(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(db, a, Exception("invalid_client: bad secret"))
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


class TestRecordProviderOutcomeFunnel:
    """The lifecycle SSOT funnel (census 2026-06-09 #1) — every credentialed
    surface routes its outcome through here so set/clear stay symmetric."""

    def test_funnel_clears_on_success(self, db, regular_user):
        a = _acct(db, regular_user)
        _maybe_mark_auth_stale(db, a, Exception("invalid_grant"))
        assert get_setting(db, f"auth_stale:{a['id']}") is not None
        # exc=None == success → clears.
        record_provider_outcome(db, a, None)
        assert get_setting(db, f"auth_stale:{a['id']}") is None

    def test_funnel_sets_on_auth_revoked_failure(self, db, regular_user):
        a = _acct(db, regular_user)
        record_provider_outcome(
            db, a, Exception("Gmail API 400: Token has been expired or revoked."),
        )
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_funnel_ignores_transient_failure(self, db, regular_user):
        a = _acct(db, regular_user)
        # A transient network error is NOT auth-revoked → no chip.
        record_provider_outcome(db, a, Exception("connection reset by peer"))
        assert get_setting(db, f"auth_stale:{a['id']}") is None

    def test_class_name_only_auth_error_now_sets(self, db, regular_user):
        """The drift the census fixed: an auth-revoked signal carried by the
        exception CLASS NAME (not the message) used to be missed by the SET
        path (it scanned str(exc) only) while the retry path caught it. The
        unified predicate scans both, so it now flips the chip."""
        class OAuthRefreshFailed(Exception):
            pass

        a = _acct(db, regular_user)
        # Message has NO needle substring; only the class name does.
        record_provider_outcome(db, a, OAuthRefreshFailed("could not refresh"))
        assert get_setting(db, f"auth_stale:{a['id']}") is not None

    def test_clear_is_cheap_no_write_when_not_stale(
        self, db, regular_user, monkeypatch,
    ):
        """Idempotent-cheap clear: a provider-success path that fires on every
        message must not write-amplify the settings table — when the account
        is not stale, _clear_auth_stale issues NO delete."""
        import email_triage.web.db as webdb

        a = _acct(db, regular_user)
        calls = {"deletes": 0}
        real_delete = webdb.delete_setting

        def _spy_delete(*args, **kw):
            calls["deletes"] += 1
            return real_delete(*args, **kw)

        monkeypatch.setattr(webdb, "delete_setting", _spy_delete)

        # Not stale → no write.
        record_provider_outcome(db, a, None)
        assert calls["deletes"] == 0

        # Now stale → exactly one delete clears it.
        _maybe_mark_auth_stale(db, a, Exception("invalid_grant"))
        record_provider_outcome(db, a, None)
        assert calls["deletes"] == 1
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
