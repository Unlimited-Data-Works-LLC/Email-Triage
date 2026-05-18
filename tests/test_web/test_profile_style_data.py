"""Tests for M-8 — training-data governance UI.

Covers /profile/style-data + the four POST endpoints (export,
delete-profile, delete-index, delete-all). Verifies the audit-row
contract, the HIPAA actor-vs-owner gate, the redaction rules, and the
transactional roll-back on the delete-all path.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from email_triage.web.db import (
    add_account_delegate,
    create_email_account,
    delete_style_profile,
    get_style_profile,
    list_auth_events,
    list_hipaa_access_events,
    set_account_hipaa,
    set_style_learning_master_enabled as set_style_learning_master,
    set_style_profile,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    """Create a synthetic IMAP account (no real provider wiring needed)."""
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


def _seed_sent_mail_index_table(db) -> None:
    """Create a minimal sent_mail_index table mirroring the M-4 schema.

    The worktree branch this test runs on doesn't include the M-4
    migration (M-4 ships in a parallel branch), so the test creates
    the table itself rather than mocking around the helper. Mirrors
    the migration-v12 shape used by /profile/style-data.

    No is_captured_pair column here — M-6 ships that. The
    get_captured_pair_count helper short-circuits to 0 when the
    column is absent, which is exactly the pre-M-6 behaviour.
    """
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sent_mail_index (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL,
            message_id      TEXT    NOT NULL,
            rfc_message_id  TEXT,
            sent_at         TEXT    NOT NULL,
            to_addresses    TEXT    NOT NULL DEFAULT '[]',
            subject         TEXT,
            body_excerpt    TEXT,
            embedding_vec   BLOB,
            embedding_model TEXT    NOT NULL,
            indexed_at      TEXT    NOT NULL
        )
        """
    )
    db.commit()


def _insert_index_row(
    db,
    *,
    account_id: int,
    message_id: str,
    sent_at: str,
    subject: str,
    to_addresses: list[str] | None = None,
    embedding_model: str = "nomic-embed-text",
) -> None:
    db.execute(
        "INSERT INTO sent_mail_index ("
        "account_id, message_id, rfc_message_id, sent_at, to_addresses, "
        "subject, body_excerpt, embedding_vec, embedding_model, "
        "indexed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id,
            message_id,
            message_id,
            sent_at,
            json.dumps(to_addresses or ["recipient@example.com"]),
            subject,
            "(body)",
            b"",
            embedding_model,
            sent_at,
        ),
    )
    db.commit()


def _seed_style_profile(db, account_id: int) -> None:
    set_style_profile(
        db,
        account_id,
        {
            "persona_summary": "Friendly and concise; opens with first name.",
            "greeting": "Hi {name},",
            "signoff": "Thanks,\\nOperator A",
            "formality": 3,
            "phrases_used": ["let me know", "happy to"],
            "phrases_avoided": ["I hope this email finds you well"],
            "sample_count": 25,
            "model_used": "test-model-v1",
        },
    )


# ---------------------------------------------------------------------------
# GET /profile/style-data
# ---------------------------------------------------------------------------

class TestStyleDataPageGet:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get(
            "/profile/style-data", follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]

    def test_logged_in_renders_no_accounts_state(self, client, user_cookies):
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "No accounts yet" in resp.text

    def test_renders_one_section_per_managed_account(
        self, client, user_cookies, db, regular_user,
    ):
        a1 = _make_acct(db, regular_user["id"], "Personal")
        a2 = _make_acct(db, regular_user["id"], "Work")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Two <details> sections with the account-id stamp.
        assert f"(id {a1})" in resp.text
        assert f"(id {a2})" in resp.text
        assert "Personal" in resp.text
        assert "Work" in resp.text

    def test_only_own_and_delegated_accounts_visible(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        own = _make_acct(db, regular_user["id"], "MyAcct")
        delegated = _make_acct(db, admin_user["id"], "DelegatedAcct")
        not_mine = _make_acct(db, admin_user["id"], "ForbiddenAcct")
        add_account_delegate(
            db, delegated, regular_user["id"], admin_user["id"],
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "MyAcct" in resp.text
        assert "DelegatedAcct" in resp.text
        assert "ForbiddenAcct" not in resp.text

    def test_master_toggle_on_renders_no_banner(
        self, client, user_cookies, db, regular_user,
    ):
        """#157 — when master is ON (the default-on posture), the
        page should NOT carry a noisy 'Style learning is currently
        ON' banner. Absence is the affirmative signal."""
        _make_acct(db, regular_user["id"], "Acct")
        set_style_learning_master(db, True)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # No off-chip when master is on.
        assert "Style learning is OFF" not in resp.text

    def test_master_toggle_off_renders_chip(
        self, client, user_cookies, db, regular_user,
    ):
        """#157 — when master is explicitly OFF, the warning chip
        surfaces with the new copy. The old 'Style learning is
        currently OFF for this install' banner has been replaced
        with the explicit chip header."""
        _make_acct(db, regular_user["id"], "Acct")
        set_style_learning_master(db, False)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Style learning is OFF" in resp.text

    def test_renders_profile_metadata_when_present(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Sample count surfaces as plain text in the metadata line.
        assert "25" in resp.text
        # Persona summary preview is rendered.
        assert "Friendly and concise" in resp.text

    def test_renders_index_summary_when_present(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db,
            account_id=a,
            message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00",
            subject="Re: project sync",
        )
        _insert_index_row(
            db,
            account_id=a,
            message_id="m2",
            sent_at="2026-05-01T10:00:00+00:00",
            subject="Re: budget approval",
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Count = 2 surfaces in the section header line.
        assert "Saved replies on file" in resp.text
        assert "Re: project sync" in resp.text or "Re: budget approval" in resp.text

    def test_audience_no_forbidden_jargon(
        self, client, user_cookies, db, regular_user,
    ):
        """Plain-language renames + no developer/protocol jargon."""
        a = _make_acct(db, regular_user["id"], "Acct")
        # Seed both layers so the section h4s render.
        _seed_style_profile(db, a)
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00",
            subject="Re: x",
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        page = resp.text
        # Forbidden words from the M-8 spec.
        for word in (
            "RFC ",
            "OData",
            "AND-combined",
            "Ask your administrator",
        ):
            assert word not in page, f"forbidden phrase leaked: {word!r}"
        # Plain-language renames in evidence:
        assert "Writing-style summary" in page
        assert "Recent reply examples" in page


# ---------------------------------------------------------------------------
# POST /profile/style-data/export
# ---------------------------------------------------------------------------

class TestStyleDataExport:
    def test_export_returns_json_content_type(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert body["schema"].startswith("email-triage style-data export")
        assert body["account"]["id"] == a
        assert body["writing_style_summary"]["sample_count"] == 25

    def test_export_attachment_disposition(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert f"style-data-account-{a}.json" in cd

    def test_export_writes_audit_row(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        rows = list_auth_events(
            db, event_type="style_data_export", limit=10,
        )
        assert len(rows) == 1
        assert rows[0]["user_id"] == regular_user["id"]
        assert rows[0]["outcome"] == "success"
        assert f"account_id={a}" in (rows[0].get("detail") or "")

    def test_export_for_inaccessible_account_returns_403(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        not_mine = _make_acct(db, admin_user["id"], "Foreign")
        resp = client.post(
            f"/profile/style-data/export?account_id={not_mine}",
            cookies=user_cookies,
        )
        assert resp.status_code == 403
        # Audit row written for the failure attempt.
        rows = list_auth_events(
            db, event_type="style_data_export", limit=10,
        )
        assert any(r.get("outcome") == "failure" for r in rows)

    def test_export_redacts_subjects_under_hipaa(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db,
            account_id=a,
            message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00",
            subject="patient lab results",
            to_addresses=["doctor@hospital.example.com"],
        )
        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        body = resp.json()
        # Sample subjects redacted to the literal [redacted] string.
        samples = body["recent_reply_examples"]["sample_subjects"]
        assert all(s == "[redacted]" for s in samples)
        # Counts and timestamps preserved.
        assert body["recent_reply_examples"]["count"] == 1


# ---------------------------------------------------------------------------
# POST /profile/style-data/delete-profile
# ---------------------------------------------------------------------------

class TestDeleteProfile:
    def test_delete_profile_removes_row(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        assert get_style_profile(db, a) is not None

        resp = client.post(
            f"/profile/style-data/delete-profile?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert get_style_profile(db, a) is None

    def test_delete_profile_writes_audit_row(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        client.post(
            f"/profile/style-data/delete-profile?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        rows = list_auth_events(
            db, event_type="style_data_delete_profile", limit=10,
        )
        assert len(rows) >= 1
        assert rows[0]["outcome"] == "success"

    def test_delete_profile_re_render_shows_zero(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        client.post(
            f"/profile/style-data/delete-profile?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        # Re-render the page; no profile preview should appear.
        resp = client.get("/profile/style-data", cookies=user_cookies)
        assert resp.status_code == 200
        # Persona text gone from the page now.
        assert "Friendly and concise" not in resp.text


# ---------------------------------------------------------------------------
# POST /profile/style-data/delete-index
# ---------------------------------------------------------------------------

class TestDeleteIndex:
    def test_delete_index_removes_all_rows_for_account(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00",
            subject="Re: x",
        )
        _insert_index_row(
            db, account_id=a, message_id="m2",
            sent_at="2026-04-02T10:00:00+00:00",
            subject="Re: y",
        )
        client.post(
            f"/profile/style-data/delete-index?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        n = db.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (a,),
        ).fetchone()[0]
        assert n == 0

    def test_delete_index_does_not_touch_sibling_accounts(
        self, client, user_cookies, db, regular_user,
    ):
        a1 = _make_acct(db, regular_user["id"], "A1")
        a2 = _make_acct(db, regular_user["id"], "A2")
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a1, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00", subject="x",
        )
        _insert_index_row(
            db, account_id=a2, message_id="m2",
            sent_at="2026-04-02T10:00:00+00:00", subject="y",
        )
        client.post(
            f"/profile/style-data/delete-index?account_id={a1}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        n1 = db.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (a1,),
        ).fetchone()[0]
        n2 = db.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (a2,),
        ).fetchone()[0]
        assert n1 == 0
        assert n2 == 1

    def test_delete_index_writes_audit_row(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00", subject="x",
        )
        client.post(
            f"/profile/style-data/delete-index?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        rows = list_auth_events(
            db, event_type="style_data_delete_index", limit=10,
        )
        assert len(rows) >= 1
        assert rows[0]["outcome"] == "success"
        # Detail field carries the deleted-count so an operator
        # auditing later can see the magnitude.
        assert "deleted=1" in (rows[0].get("detail") or "")


# ---------------------------------------------------------------------------
# POST /profile/style-data/delete-all
# ---------------------------------------------------------------------------

class TestDeleteAll:
    def test_delete_all_removes_profile_and_index(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00", subject="x",
        )
        client.post(
            f"/profile/style-data/delete-all?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert get_style_profile(db, a) is None
        n = db.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (a,),
        ).fetchone()[0]
        assert n == 0

    def test_delete_all_writes_single_audit_row(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        client.post(
            f"/profile/style-data/delete-all?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        rows = list_auth_events(
            db, event_type="style_data_delete_all", limit=10,
        )
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"

    def test_delete_all_rolls_back_on_partial_failure(
        self, client, user_cookies, db, regular_user,
    ):
        """If the second DELETE raises, the first DELETE is rolled back.

        We force a SQLite error on the sent_mail_index DELETE by
        installing a BEFORE-DELETE trigger that uses RAISE(ABORT, ...)
        whenever an account_id matches the test account. The route
        ABORTs partway through, the savepoint rolls back, and the
        style-profile row should still be present.
        """
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        _seed_sent_mail_index_table(db)
        _insert_index_row(
            db, account_id=a, message_id="m1",
            sent_at="2026-04-01T10:00:00+00:00", subject="x",
        )
        # Trigger that aborts the index-row delete when the account
        # matches our target. This propagates as a sqlite3 error from
        # conn.execute, which the route's except branch catches and
        # re-raises after rolling back.
        db.execute(
            f"""
            CREATE TRIGGER block_delete_for_acct_{a}
            BEFORE DELETE ON sent_mail_index
            FOR EACH ROW WHEN OLD.account_id = {a}
            BEGIN
                SELECT RAISE(ABORT, 'simulated failure');
            END
            """
        )
        db.commit()

        # 500-level response is acceptable; we care about state.
        # TestClient is created with raise_server_exceptions=False
        # in conftest.py so the exception surfaces as a 500.
        resp = client.post(
            f"/profile/style-data/delete-all?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        # Either the savepoint rollback raised back to the client
        # (500) or the rollback succeeded but the route still raised
        # (also 500). Either way the post-condition is what matters.
        assert resp.status_code in (500, 303)

        # Drop the trigger so the post-condition reads cleanly.
        db.execute(f"DROP TRIGGER block_delete_for_acct_{a}")
        db.commit()

        # Profile row should still be present — savepoint rolled back.
        assert get_style_profile(db, a) is not None
        # Failure audit row written.
        rows = list_auth_events(
            db, event_type="style_data_delete_all", limit=10,
        )
        assert any(r.get("outcome") == "failure" for r in rows)


# ---------------------------------------------------------------------------
# HIPAA actor-vs-owner gate
# ---------------------------------------------------------------------------

class TestHipaaActorOwnerGate:
    def test_owner_access_does_not_write_hipaa_event(
        self, client, user_cookies, db, regular_user,
    ):
        """Owner-self-access on a HIPAA account is a §164.502(a) carve-out."""
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        _seed_style_profile(db, a)

        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # auth_events row for the export action — yes.
        auth_rows = list_auth_events(
            db, event_type="style_data_export", limit=10,
        )
        assert len(auth_rows) >= 1
        # hipaa_access_events row — NO. Owner-self-access is exempt.
        hipaa_rows = list_hipaa_access_events(db, account_id=a, limit=10)
        assert all(
            r.get("operation") != "style_data_export" for r in hipaa_rows
        )

    def test_admin_view_of_hipaa_acct_writes_hipaa_event(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        """Non-owner actor + HIPAA account = hipaa_access_events row written.

        Admin is added as a delegate so they have access (per the
        managed-accounts gate); the HIPAA gate then layers on top.
        """
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=admin_user["id"])
        add_account_delegate(
            db, a, admin_user["id"], granted_by=admin_user["id"],
        )
        _seed_style_profile(db, a)

        resp = client.post(
            f"/profile/style-data/export?account_id={a}",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        # hipaa_access_events row recorded for the non-owner export.
        hipaa_rows = list_hipaa_access_events(db, account_id=a, limit=10)
        assert any(
            r.get("operation") == "style_data_export"
            and r.get("actor_user_id") == admin_user["id"]
            for r in hipaa_rows
        )

    def test_non_hipaa_account_writes_no_hipaa_event(
        self, client, user_cookies, db, regular_user,
    ):
        """Non-HIPAA account: no hipaa_access_events row even on a delete."""
        a = _make_acct(db, regular_user["id"], "Acct")
        _seed_style_profile(db, a)
        client.post(
            f"/profile/style-data/delete-profile?account_id={a}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        hipaa_rows = list_hipaa_access_events(db, account_id=a, limit=10)
        assert hipaa_rows == []
