"""Tests for the per-row rule edit affordance (#160).

Covers:
  * GET /rules/<list>/rules/<rule>/edit — renders the edit-mode
    partial pre-filled with the rule's current values.
  * GET /rules/<list>/rules/<rule>/row — renders the view-mode
    partial (Cancel target).
  * POST /rules/<list>/rules/<rule>/save — updates the rule in
    place (rule_type, pattern, skip_ai, adds_labels) and returns
    the view-mode row on HTMX requests.
  * Auth — non-owner non-admin gets 403.
  * adds_labels round-trips as JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage.web.db import create_label


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def list_with_rule(db, regular_user):
    """Insert one personal list + one rule owned by regular_user."""
    now = _now()
    cur = db.execute(
        "INSERT INTO classification_lists (name, category, owner_id, "
        "is_global, created_at) VALUES (?, ?, ?, 0, ?)",
        ("VIP", "to-respond", regular_user["id"], now),
    )
    list_id = cur.lastrowid
    cur = db.execute(
        "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
        "adds_labels, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (list_id, "sender", "boss@example.com", 0, None, now),
    )
    rule_id = cur.lastrowid
    db.commit()
    return list_id, rule_id


class TestGetEditForm:
    def test_renders_edit_partial(
        self, client, user_cookies, db, list_with_rule,
    ):
        list_id, rule_id = list_with_rule
        resp = client.get(
            f"/rules/{list_id}/rules/{rule_id}/edit",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Edit partial uses the rule-{lst}-{rule} row id.
        assert f'id="rule-{list_id}-{rule_id}"' in resp.text
        # Form posts to the save endpoint.
        assert f"/rules/{list_id}/rules/{rule_id}/save" in resp.text
        # Existing pattern is the input value.
        assert "boss@example.com" in resp.text
        # Save + Cancel buttons present.
        assert ">Save<" in resp.text
        assert ">Cancel<" in resp.text

    def test_unknown_rule_404(self, client, user_cookies, list_with_rule):
        list_id, _ = list_with_rule
        resp = client.get(
            f"/rules/{list_id}/rules/9999/edit",
            cookies=user_cookies,
        )
        assert resp.status_code == 404

    def test_other_user_forbidden(
        self, client, admin_cookies, db, list_with_rule,
    ):
        """Non-owner non-admin can't edit (admin actually CAN, so
        flip the role gate: a separate unprivileged user is 403)."""
        # Create a second non-admin user and confirm they're blocked.
        now = _now()
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("other@test.com", "Other", "user", now),
        )
        other_id = cur.lastrowid
        db.commit()
        from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
        from tests.test_web.conftest import TEST_SECRET
        token = create_session_token(
            TEST_SECRET, "other@test.com", "user",
        )
        list_id, rule_id = list_with_rule
        resp = client.get(
            f"/rules/{list_id}/rules/{rule_id}/edit",
            cookies={SESSION_COOKIE_NAME: token},
        )
        assert resp.status_code == 403

    def test_anonymous_unauthorized(self, client, list_with_rule):
        list_id, rule_id = list_with_rule
        resp = client.get(f"/rules/{list_id}/rules/{rule_id}/edit")
        assert resp.status_code == 401


class TestGetRowPartial:
    def test_renders_view_partial(
        self, client, user_cookies, list_with_rule,
    ):
        list_id, rule_id = list_with_rule
        resp = client.get(
            f"/rules/{list_id}/rules/{rule_id}/row",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # View partial shows the pattern as plain text, not in an
        # editable input. (The row still carries one hidden csrf
        # input on the Remove form, so we assert specifically that
        # no text-mode <input type="text" ...> exists.)
        assert "boss@example.com" in resp.text
        assert 'type="text"' not in resp.text
        # Edit button is in the row.
        assert ">Edit<" in resp.text


class TestSaveRule:
    def test_save_updates_row(
        self, client, user_cookies, db, list_with_rule,
    ):
        list_id, rule_id = list_with_rule
        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={
                "rule_type": "sender_domain",
                "pattern": "newvendor.com",
                "skip_ai": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT rule_type, pattern, skip_ai FROM list_rules "
            "WHERE id = ?",
            (rule_id,),
        ).fetchone()
        assert row["rule_type"] == "sender_domain"
        assert row["pattern"] == "newvendor.com"
        assert row["skip_ai"] == 1

    def test_save_persists_adds_labels(
        self, client, user_cookies, db, list_with_rule,
    ):
        list_id, rule_id = list_with_rule
        create_label(db, "urgent", "Urgent")
        create_label(db, "tax", "Tax")
        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
                "adds_labels": ["urgent", "tax"],
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT adds_labels FROM list_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        assert row["adds_labels"] is not None
        assert set(json.loads(row["adds_labels"])) == {"urgent", "tax"}

    def test_save_clears_labels_when_omitted(
        self, client, user_cookies, db, list_with_rule,
    ):
        """Saving without any adds_labels checked clears them."""
        list_id, rule_id = list_with_rule
        # Seed labels on the rule first.
        db.execute(
            "UPDATE list_rules SET adds_labels = ? WHERE id = ?",
            (json.dumps(["urgent"]), rule_id),
        )
        db.commit()
        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT adds_labels FROM list_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        assert row["adds_labels"] is None

    def test_save_returns_row_partial_on_htmx(
        self, client, user_cookies, list_with_rule,
    ):
        list_id, rule_id = list_with_rule
        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={
                "rule_type": "sender",
                "pattern": "newboss@example.com",
                "skip_ai": "0",
            },
            cookies=user_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        # View-mode partial — no <input> tags, has Edit button.
        assert f'id="rule-{list_id}-{rule_id}"' in resp.text
        assert "newboss@example.com" in resp.text
        assert ">Edit<" in resp.text

    def test_save_unknown_rule_404(
        self, client, user_cookies, list_with_rule,
    ):
        list_id, _ = list_with_rule
        resp = client.post(
            f"/rules/{list_id}/rules/9999/save",
            data={
                "rule_type": "sender",
                "pattern": "x@example.com",
                "skip_ai": "0",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 404
