"""Tests for the universal Discover Categories audit trail.

Every Discover run — HIPAA-flagged or not — must land a row in
``discover_runs``. HIPAA accounts keep the existing
``hipaa_access_events`` row as a parallel (more detailed) trail.

Discover exposes sender + subject of every scanned message, so the
audit question is "who scanned which mailbox + scope". Metadata only:
no PHI, no message content, no proposals.
"""

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from email_triage.web.db import (
    list_discover_runs,
    list_hipaa_access_events,
    record_discover_run,
)


def _make_account(db, user_id, *, hipaa=False, name="Acct"):
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "imap",
            json.dumps({"host": "mail.unreachable.invalid", "username": "t@t.com"}),
            1 if hipaa else 0,
            now, now,
        ),
    )
    db.commit()
    return cursor.lastrowid


class TestDbHelpers:
    """Direct exercise of the record_discover_run / list_discover_runs helpers."""

    def test_record_and_list(self, db, admin_user):
        acct_id = _make_account(db, admin_user["id"], name="Main Inbox")
        rid = record_discover_run(
            db,
            account_id=acct_id,
            account_name="Main Inbox",
            actor_user_id=admin_user["id"],
            scanned_count=12,
            errors_count=0,
            folders=["INBOX", "Work"],
            elapsed_secs=3.25,
        )
        assert rid > 0

        rows = list_discover_runs(db)
        assert len(rows) == 1
        r = rows[0]
        assert r["scanned_count"] == 12
        assert r["errors_count"] == 0
        assert r["account_name"] == "Main Inbox"
        assert r["actor_email"] == admin_user["email"]
        # folders is stored JSON-encoded so clients can filter later.
        assert json.loads(r["folders"]) == ["INBOX", "Work"]
        assert r["elapsed_secs"] == pytest.approx(3.25)

    def test_list_filter_by_account(self, db, admin_user):
        a1 = _make_account(db, admin_user["id"], name="A1")
        a2 = _make_account(db, admin_user["id"], name="A2")
        record_discover_run(
            db, account_id=a1, account_name="A1",
            actor_user_id=admin_user["id"], scanned_count=1,
            errors_count=0, folders=["INBOX"], elapsed_secs=1.0,
        )
        record_discover_run(
            db, account_id=a2, account_name="A2",
            actor_user_id=admin_user["id"], scanned_count=2,
            errors_count=0, folders=["INBOX"], elapsed_secs=1.0,
        )
        rows = list_discover_runs(db, account_id=a1)
        assert len(rows) == 1
        assert rows[0]["account_id"] == a1

    def test_folders_empty_list_serializes(self, db, admin_user):
        acct_id = _make_account(db, admin_user["id"])
        record_discover_run(
            db, account_id=acct_id, account_name="x",
            actor_user_id=admin_user["id"], scanned_count=0,
            errors_count=1, folders=[], elapsed_secs=0.0,
        )
        rows = list_discover_runs(db)
        assert json.loads(rows[0]["folders"]) == []


class TestDiscoverRunEndpointRecords:
    """POST /triage/discover/run records a discover_runs row for every account."""

    def test_discover_records_actor_and_scope_for_non_hipaa_account(
        self, client, db, admin_cookies, admin_user
    ):
        """Non-HIPAA account: a discover_runs row is recorded, no HIPAA row."""
        acct_id = _make_account(
            db, admin_user["id"], hipaa=False, name="Standard Inbox"
        )

        # Provider instantiation will fail (IMAP host unreachable), which
        # is fine — the universal audit row is written on every run-attempt
        # path including setup failures.
        client.post(
            "/triage/discover/run",
            data={
                "account_id": str(acct_id),
                "limit": "10",
                "query": "ALL",
                "scan_scope": "inbox",
            },
            cookies=admin_cookies,
        )

        # Universal audit row present.
        runs = list_discover_runs(db, account_id=acct_id)
        assert len(runs) == 1
        row = runs[0]
        assert row["actor_user_id"] == admin_user["id"]
        assert row["account_id"] == acct_id
        assert row["account_name"] == "Standard Inbox"
        # folders is JSON-encoded.
        assert isinstance(row["folders"], str)
        json.loads(row["folders"])  # parse check

        # Non-HIPAA: NO hipaa_access_events row.
        hipaa_rows = list_hipaa_access_events(db, account_id=acct_id)
        assert hipaa_rows == []

    def test_discover_records_actor_for_hipaa_account(
        self, client, db, admin_cookies, admin_user
    ):
        """HIPAA-flagged account: BOTH discover_runs AND hipaa_access_events rows."""
        acct_id = _make_account(
            db, admin_user["id"], hipaa=True, name="PHI Inbox"
        )

        client.post(
            "/triage/discover/run",
            data={
                "account_id": str(acct_id),
                "limit": "10",
                "query": "ALL",
                "scan_scope": "inbox",
            },
            cookies=admin_cookies,
        )

        # Universal discover_runs row.
        runs = list_discover_runs(db, account_id=acct_id)
        assert len(runs) == 1
        assert runs[0]["actor_user_id"] == admin_user["id"]
        assert runs[0]["account_name"] == "PHI Inbox"

        # Parallel hipaa_access_events row — independent trail, not replaced.
        hipaa_rows = list_hipaa_access_events(db, account_id=acct_id)
        assert len(hipaa_rows) == 1
        assert hipaa_rows[0]["operation"] == "discover"
        assert hipaa_rows[0]["actor_user_id"] == admin_user["id"]

    def test_discover_run_audit_insert_failure_does_not_break_response(
        self, client, db, admin_cookies, admin_user
    ):
        """A DB error inside record_discover_run must NOT break the user-visible response."""
        acct_id = _make_account(
            db, admin_user["id"], hipaa=False, name="Audit Fail Inbox"
        )

        # Patch record_discover_run at the import site inside ui.py's
        # closure (it's imported lazily inside the endpoint). Simplest
        # reliable way: patch on the db module since the endpoint does
        # `from email_triage.web.db import record_discover_run`.
        with patch(
            "email_triage.web.db.record_discover_run",
            side_effect=RuntimeError("simulated audit DB failure"),
        ):
            resp = client.post(
                "/triage/discover/run",
                data={
                    "account_id": str(acct_id),
                    "limit": "10",
                    "query": "ALL",
                    "scan_scope": "inbox",
                },
                cookies=admin_cookies,
            )

        # User still got a response (the failing IMAP connect returns a
        # friendly 200 HTML error panel — not a 500). The key property is
        # that the audit failure didn't raise up through the response.
        assert resp.status_code == 200

        # And because the audit insert was patched to raise, no row landed.
        assert list_discover_runs(db, account_id=acct_id) == []


class TestComplianceSurface:
    """/compliance admin page surfaces the new 'Discover scans' section."""

    def test_empty_state_renders_section(self, client, admin_cookies):
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Discover scans" in resp.text
        assert "No discover runs recorded yet" in resp.text

    def test_rows_render(self, client, db, admin_cookies, admin_user):
        acct_id = _make_account(db, admin_user["id"], name="Clinic Inbox")
        record_discover_run(
            db,
            account_id=acct_id,
            account_name="Clinic Inbox",
            actor_user_id=admin_user["id"],
            scanned_count=17,
            errors_count=2,
            folders=["INBOX", "Referrals"],
            elapsed_secs=4.1,
        )

        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Discover scans" in resp.text
        assert "Clinic Inbox" in resp.text
        assert admin_user["email"] in resp.text
        assert "17" in resp.text  # scanned_count
        # Folders list rendered joined.
        assert "INBOX" in resp.text
        assert "Referrals" in resp.text
