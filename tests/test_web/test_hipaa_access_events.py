"""Tests for §164.312(b) HIPAA access-audit trail.

Every user-initiated manual triage or category discovery run against a
HIPAA-flagged account must land a row in ``hipaa_access_events``.
Standard (non-HIPAA) accounts should record nothing — they're already
covered by ``triage_runs.results_json``.
"""

import json
from datetime import datetime, timezone

import pytest

from email_triage.web.db import (
    list_hipaa_access_events,
    record_hipaa_access_event,
    update_hipaa_access_event,
)


def _make_account(db, user_id, *, hipaa=False, name="Acct"):
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "imap",
            json.dumps({"host": "mail.test.com", "username": "t@t.com"}),
            1 if hipaa else 0,
            now, now,
        ),
    )
    db.commit()
    return cursor.lastrowid


class TestDbHelpers:
    """Direct exercise of the db.py helpers."""

    def test_record_and_list(self, db, admin_user):
        acct_id = _make_account(db, admin_user["id"], hipaa=True)
        eid = record_hipaa_access_event(
            db, admin_user["id"], acct_id, "manual_triage", outcome="ok", detail="messages=3",
        )
        assert eid > 0

        rows = list_hipaa_access_events(db)
        assert len(rows) == 1
        assert rows[0]["operation"] == "manual_triage"
        assert rows[0]["outcome"] == "ok"
        assert rows[0]["detail"] == "messages=3"
        assert rows[0]["actor_email"] == admin_user["email"]

    def test_update_outcome(self, db, admin_user):
        acct_id = _make_account(db, admin_user["id"], hipaa=True)
        eid = record_hipaa_access_event(
            db, admin_user["id"], acct_id, "discover", outcome="in_progress",
        )
        update_hipaa_access_event(db, eid, "error", detail="ProviderAuthError")

        rows = list_hipaa_access_events(db)
        assert rows[0]["outcome"] == "error"
        assert rows[0]["detail"] == "ProviderAuthError"

    def test_filter_by_account(self, db, admin_user):
        a1 = _make_account(db, admin_user["id"], hipaa=True, name="A1")
        a2 = _make_account(db, admin_user["id"], hipaa=True, name="A2")
        record_hipaa_access_event(db, admin_user["id"], a1, "discover")
        record_hipaa_access_event(db, admin_user["id"], a2, "manual_triage")

        rows = list_hipaa_access_events(db, account_id=a1)
        assert len(rows) == 1
        assert rows[0]["account_id"] == a1


class TestComplianceSurface:
    """The compliance page surfaces access events in its dedicated section."""

    def test_empty_state(self, client, admin_cookies):
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Recent access events" in resp.text
        assert "No access events recorded yet" in resp.text

    def test_events_render(self, client, db, admin_cookies, admin_user):
        acct_id = _make_account(db, admin_user["id"], hipaa=True, name="Clinic Inbox")
        record_hipaa_access_event(
            db, admin_user["id"], acct_id, "manual_triage", outcome="ok", detail="messages=7",
        )
        record_hipaa_access_event(
            db, admin_user["id"], acct_id, "discover", outcome="error", detail="ProviderTimeout",
        )

        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Clinic Inbox" in resp.text
        assert "manual_triage" in resp.text
        assert "discover" in resp.text
        assert "messages=7" in resp.text
        assert "ProviderTimeout" in resp.text
        assert admin_user["email"] in resp.text


class TestTriageRunRecording:
    """/triage/run and /triage/discover/run only audit HIPAA accounts."""

    def test_standard_account_records_nothing(self, client, db, admin_cookies, admin_user):
        acct_id = _make_account(db, admin_user["id"], hipaa=False)

        # Provider creation will fail (no real server); we don't care — we just
        # want to confirm no HIPAA row is written for a non-HIPAA account.
        client.post(
            "/triage/run",
            data={
                "account_id": str(acct_id),
                "query": "is:unread",
                "limit": "5",
                "dry_run": "1",
            },
            cookies=admin_cookies,
        )
        rows = list_hipaa_access_events(db)
        assert rows == []

    def test_hipaa_manual_triage_records_event(
        self, client, db, admin_cookies, admin_user, regular_user,
    ):
        # Owner = regular_user; actor = admin (admin_cookies). HIPAA
        # bookend fires only when actor != owner (2026-05-06 rule
        # tightening — owner self-triage is first-party access). Use
        # an admin-on-user HIPAA account so the audit row is
        # expected.
        acct_id = _make_account(
            db, regular_user["id"], hipaa=True, name="PHI Inbox",
        )

        # Provider instantiation will fail (IMAP host unreachable) but the
        # audit start-row is inserted before that, so we still get a row —
        # with outcome=error and a detail that identifies the failure class.
        client.post(
            "/triage/run",
            data={
                "account_id": str(acct_id),
                "query": "is:unread",
                "limit": "5",
                "dry_run": "1",
            },
            cookies=admin_cookies,
        )
        rows = list_hipaa_access_events(db, account_id=acct_id)
        assert len(rows) == 1
        row = rows[0]
        assert row["operation"] == "manual_triage"
        assert row["actor_user_id"] == admin_user["id"]
        # Outcome should have been updated away from the 'in_progress'
        # sentinel — either 'ok' (happy path) or 'error' (expected here
        # because the fake IMAP host is unreachable).
        assert row["outcome"] in {"ok", "error"}

    def test_hipaa_owner_self_triage_no_audit(
        self, client, db, admin_cookies, admin_user,
    ):
        """Owner running triage on their own HIPAA account is
        first-party access — §164.502(a) self-disclosure carve-out;
        no §164.312(b) audit row required. (2026-05-06 tightening.)
        """
        acct_id = _make_account(
            db, admin_user["id"], hipaa=True, name="My PHI Inbox",
        )
        client.post(
            "/triage/run",
            data={
                "account_id": str(acct_id),
                "query": "is:unread",
                "limit": "5",
            },
            cookies=admin_cookies,
        )
        rows = list_hipaa_access_events(db, account_id=acct_id)
        assert rows == []

    def test_hipaa_discover_records_event(
        self, client, db, admin_cookies, admin_user
    ):
        acct_id = _make_account(db, admin_user["id"], hipaa=True, name="PHI Inbox")

        client.post(
            "/triage/discover/run",
            data={
                "account_id": str(acct_id),
                "limit": "10",
                "query": "ALL",
            },
            cookies=admin_cookies,
        )
        rows = list_hipaa_access_events(db, account_id=acct_id)
        assert len(rows) == 1
        assert rows[0]["operation"] == "discover"
        assert rows[0]["actor_user_id"] == admin_user["id"]
