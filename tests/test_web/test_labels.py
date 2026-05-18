"""Tests for the multi-label feature (#129).

Covers:
  * Schema (v18 migration) — labels + message_labels tables, index,
    list_rules.adds_labels column present.
  * CRUD on the labels catalog (create / list / delete).
  * Per-message apply + remove + list (manual path).
  * HIPAA: actor != owner on a HIPAA-flagged account writes a
    hipaa_access_event row (per feedback_hipaa_actor_owner_gate).
  * /triage label filter intersects with the labeled-message-id set.

See ``test_labels_rule_apply.py`` for the rule-driven path; this
file scopes to catalog + manual + HIPAA.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.web.db import (
    apply_labels_to_message,
    create_label,
    delete_label,
    get_label,
    list_labels,
    list_labels_on_message,
    list_messages_with_label,
    remove_label_from_message,
    update_label,
)


# ---------------------------------------------------------------------------
# Schema regression
# ---------------------------------------------------------------------------


class TestSchemaV18:
    def test_labels_table_present(self, db):
        tables = {
            r["name"]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "labels" in tables
        assert "message_labels" in tables

    def test_message_labels_account_label_index(self, db):
        indices = {
            r["name"]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_message_labels_account_label" in indices

    def test_list_rules_adds_labels_column(self, db):
        cols = {
            row[1]
            for row in db.execute("PRAGMA table_info(list_rules)").fetchall()
        }
        assert "adds_labels" in cols

    def test_v18_recorded_in_schema_migrations(self, db):
        from email_triage.web.migrations import schema_version
        assert schema_version(db) >= 18


# ---------------------------------------------------------------------------
# CRUD on the catalog
# ---------------------------------------------------------------------------


class TestCatalogCRUD:
    def test_create_then_list(self, db, regular_user):
        create_label(
            db, "urgent", "Urgent", "#cc0000",
            created_by_user_id=regular_user["id"],
        )
        rows = list_labels(db)
        assert any(r["slug"] == "urgent" for r in rows)
        urgent = next(r for r in rows if r["slug"] == "urgent")
        assert urgent["name"] == "Urgent"
        assert urgent["color"] == "#cc0000"
        assert urgent["created_by_user_id"] == regular_user["id"]

    def test_color_default_fallback(self, db):
        create_label(db, "no-color", "Plain", "")
        row = get_label(db, "no-color")
        assert row["color"] == "#6c757d"

    def test_duplicate_slug_raises(self, db):
        create_label(db, "tax", "Tax", "#0000aa")
        with pytest.raises(Exception):
            create_label(db, "tax", "Other", "#00aa00")

    def test_update_label(self, db):
        create_label(db, "fu", "Follow up", "#888888")
        ok = update_label(db, "fu", "Follow up later", "#ff8800")
        assert ok is True
        row = get_label(db, "fu")
        assert row["name"] == "Follow up later"
        assert row["color"] == "#ff8800"

    def test_delete_label_clears_message_links(self, db, regular_user):
        create_label(db, "todo", "To do")
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, created_at, updated_at) "
            "VALUES (?, 'acct', 'gmail_api', '{}', ?, ?)",
            (regular_user["id"], now, now),
        )
        account_id = cur.lastrowid
        db.commit()
        apply_labels_to_message(db, "msg-1", account_id, ["todo"])
        assert len(list_labels_on_message(db, "msg-1")) == 1
        delete_label(db, "todo")
        assert list_labels_on_message(db, "msg-1") == []
        assert get_label(db, "todo") is None


# ---------------------------------------------------------------------------
# Per-message manual apply / remove
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_account(db, regular_user):
    """Insert a minimal email_accounts row for label-target tests."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, "
        "config_json, hipaa, created_at, updated_at) "
        "VALUES (?, 'work', 'gmail_api', '{}', 0, ?, ?)",
        (regular_user["id"], now, now),
    )
    account_id = cur.lastrowid
    db.commit()
    return {"id": account_id, "user_id": regular_user["id"], "hipaa": False}


class TestManualApply:
    def test_apply_then_list(self, db, stub_account, regular_user):
        create_label(db, "urgent", "Urgent")
        n = apply_labels_to_message(
            db, "msg-A", stub_account["id"], ["urgent"],
            applied_by_actor=regular_user["id"],
        )
        assert n == 1
        labels = list_labels_on_message(db, "msg-A")
        assert len(labels) == 1
        assert labels[0]["slug"] == "urgent"
        assert labels[0]["name"] == "Urgent"

    def test_reapply_is_noop(self, db, stub_account):
        create_label(db, "tax", "Tax")
        apply_labels_to_message(db, "msg-B", stub_account["id"], ["tax"])
        n2 = apply_labels_to_message(
            db, "msg-B", stub_account["id"], ["tax"],
        )
        assert n2 == 0  # INSERT OR IGNORE → 0 rows on second pass
        assert len(list_labels_on_message(db, "msg-B")) == 1

    def test_unknown_slug_skipped(self, db, stub_account):
        create_label(db, "real", "Real")
        n = apply_labels_to_message(
            db, "msg-C", stub_account["id"], ["real", "never-existed"],
        )
        assert n == 1
        labels = [r["slug"] for r in list_labels_on_message(db, "msg-C")]
        assert labels == ["real"]

    def test_remove_label_from_message(self, db, stub_account):
        create_label(db, "a", "A")
        create_label(db, "b", "B")
        apply_labels_to_message(db, "msg-D", stub_account["id"], ["a", "b"])
        ok = remove_label_from_message(db, "msg-D", "a")
        assert ok is True
        remaining = [
            r["slug"] for r in list_labels_on_message(db, "msg-D")
        ]
        assert remaining == ["b"]


class TestListMessagesWithLabel:
    def test_list_by_label(self, db, stub_account):
        create_label(db, "tax", "Tax")
        for mid in ("m1", "m2", "m3"):
            apply_labels_to_message(db, mid, stub_account["id"], ["tax"])
        rows = list_messages_with_label(db, "tax", stub_account["id"])
        assert {r["message_id"] for r in rows} == {"m1", "m2", "m3"}

    def test_account_scope(self, db, stub_account, regular_user):
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, created_at, updated_at) "
            "VALUES (?, 'home', 'imap', '{}', ?, ?)",
            (regular_user["id"], now, now),
        )
        other_id = cur.lastrowid
        db.commit()
        create_label(db, "tag", "Tag")
        apply_labels_to_message(db, "x", stub_account["id"], ["tag"])
        apply_labels_to_message(db, "y", other_id, ["tag"])
        rows = list_messages_with_label(db, "tag", stub_account["id"])
        assert {r["message_id"] for r in rows} == {"x"}


# ---------------------------------------------------------------------------
# Web handlers — labels page CRUD + manual apply
# ---------------------------------------------------------------------------


class TestLabelsPage:
    def test_get_labels_page(self, client, user_cookies):
        resp = client.get("/labels", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Labels" in resp.text

    def test_create_label_via_post(self, client, user_cookies, db):
        resp = client.post(
            "/labels/create",
            data={
                "slug": "vendor-action",
                "name": "Vendor: action required",
                "color": "#cc0000",
            },
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        row = get_label(db, "vendor-action")
        assert row is not None
        assert row["name"] == "Vendor: action required"

    def test_delete_label_via_post(self, client, user_cookies, db):
        create_label(db, "gone", "Gone")
        resp = client.post(
            "/labels/gone/delete", cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        assert get_label(db, "gone") is None

    def test_anonymous_redirected(self, client):
        resp = client.get("/labels", follow_redirects=False)
        assert resp.status_code in (303, 307)


class TestManualApplyHTTP:
    def test_apply_to_message_endpoint(
        self, client, user_cookies, db, stub_account,
    ):
        create_label(db, "urgent", "Urgent")
        resp = client.post(
            f"/messages/{stub_account['id']}/msg-W/labels/add",
            data={"label_slug": "urgent"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        labels = list_labels_on_message(db, "msg-W")
        assert [r["slug"] for r in labels] == ["urgent"]

    def test_bulk_apply_endpoint(
        self, client, user_cookies, db, stub_account,
    ):
        create_label(db, "tax", "Tax")
        resp = client.post(
            f"/messages/{stub_account['id']}/bulk-labels/add",
            data={
                "label_slug": "tax",
                "message_ids": ["m1", "m2", "m3"],
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Tagged 3 messages" in resp.text

    def test_bulk_apply_rejects_empty_selection(
        self, client, user_cookies, db, stub_account,
    ):
        create_label(db, "tax", "Tax")
        resp = client.post(
            f"/messages/{stub_account['id']}/bulk-labels/add",
            data={"label_slug": "tax"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Nothing to tag" in resp.text


# ---------------------------------------------------------------------------
# HIPAA audit gate — actor != owner on HIPAA account writes an event
# ---------------------------------------------------------------------------


class TestHIPAAGate:
    def test_actor_eq_owner_no_audit_row(
        self, client, user_cookies, db, regular_user,
    ):
        """Self-access on a HIPAA account is NOT audited."""
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, hipaa, created_at, updated_at) "
            "VALUES (?, 'clinic', 'gmail_api', '{}', 1, ?, ?)",
            (regular_user["id"], now, now),
        )
        account_id = cur.lastrowid
        db.commit()
        create_label(db, "tag", "Tag")
        resp = client.post(
            f"/messages/{account_id}/m-1/labels/add",
            data={"label_slug": "tag"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # No audit row written for owner-self-access.
        events = db.execute(
            "SELECT COUNT(*) AS c FROM hipaa_access_events "
            "WHERE operation = 'label_apply'"
        ).fetchone()
        assert (events["c"] if events else 0) == 0

    def test_actor_neq_owner_writes_audit_row(
        self, client, admin_cookies, db, regular_user, admin_user,
    ):
        """Admin viewing a non-owner's HIPAA account = audited."""
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, hipaa, created_at, updated_at) "
            "VALUES (?, 'clinic', 'gmail_api', '{}', 1, ?, ?)",
            (regular_user["id"], now, now),
        )
        account_id = cur.lastrowid
        db.commit()
        create_label(db, "tag", "Tag")
        resp = client.post(
            f"/messages/{account_id}/m-1/labels/add",
            data={"label_slug": "tag"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'label_apply'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["actor_user_id"] == admin_user["id"]
        assert rows[0]["account_id"] == account_id
