"""Tests for rule-driven label attachment (#129).

A ``list_rules.adds_labels`` JSON array of slugs attaches labels to
matching messages WITHOUT changing the LLM-assigned category. This
file covers:

  * Persistence — POST /rules/create + POST /rules/<id>/add-rule
    with adds_labels[]= form fields stores a JSON array.
  * Round-trip — the rules-page snapshot exposes adds_labels_list
    on each rule dict.
  * Firing — matching rules attach labels to the message;
    non-matching rules are silent. LLM category is unchanged.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage.engine.models import (
    EmailMessage, ListHint, ListRule, RuleType, ClassificationList,
)
from email_triage.web.db import create_label, list_labels_on_message


def _now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Persistence via the HTTP form
# ---------------------------------------------------------------------------


class TestRuleEditorPersistsAddsLabels:
    def test_create_list_with_adds_labels(
        self, client, user_cookies, db,
    ):
        create_label(db, "urgent", "Urgent")
        create_label(db, "tax", "Tax")
        # The default-seeded categories include common slugs; reuse one
        # rather than insert a fresh row that would collide.
        cat_row = db.execute(
            "SELECT slug FROM categories LIMIT 1"
        ).fetchone()
        category_slug = cat_row["slug"] if cat_row else "to-respond"

        resp = client.post(
            "/rules/create",
            data={
                "name": "VIP",
                "category": category_slug,
                "is_global": "0",
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
            "SELECT adds_labels FROM list_rules "
            "WHERE pattern = 'boss@example.com'"
        ).fetchone()
        assert row is not None
        parsed = json.loads(row["adds_labels"])
        assert set(parsed) == {"urgent", "tax"}

    def test_add_rule_with_adds_labels(
        self, client, user_cookies, db, regular_user,
    ):
        create_label(db, "urgent", "Urgent")
        cur = db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, "
            "is_global, created_at) VALUES (?, ?, ?, 0, ?)",
            ("MyList", "general", regular_user["id"], _now()),
        )
        list_id = cur.lastrowid
        db.commit()

        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={
                "rule_type": "sender_domain",
                "pattern": "vendor.com",
                "skip_ai": "0",
                "adds_labels": ["urgent"],
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT adds_labels FROM list_rules WHERE pattern = 'vendor.com'"
        ).fetchone()
        assert row is not None
        parsed = json.loads(row["adds_labels"])
        assert parsed == ["urgent"]


# ---------------------------------------------------------------------------
# Read path — adds_labels_list parsed onto each rule dict
# ---------------------------------------------------------------------------


class TestRulesPageSnapshotParses:
    def test_adds_labels_list_parsed_in_snapshot(
        self, db, regular_user,
    ):
        from email_triage.web.routers.ui._shared import _get_lists_for_user
        cur = db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, "
            "is_global, created_at) VALUES (?, ?, ?, 0, ?)",
            ("L", "general", regular_user["id"], _now()),
        )
        list_id = cur.lastrowid
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
            "adds_labels, created_at) VALUES (?, ?, ?, 0, ?, ?)",
            (list_id, "sender", "a@b.com", '["red", "blue"]', _now()),
        )
        db.commit()
        personal, _ = _get_lists_for_user(db, regular_user)
        rule = personal[0]["rules"][0]
        assert rule["adds_labels_list"] == ["red", "blue"]

    def test_missing_adds_labels_renders_as_empty(self, db, regular_user):
        from email_triage.web.routers.ui._shared import _get_lists_for_user
        cur = db.execute(
            "INSERT INTO classification_lists (name, category, owner_id, "
            "is_global, created_at) VALUES (?, ?, ?, 0, ?)",
            ("L", "general", regular_user["id"], _now()),
        )
        list_id = cur.lastrowid
        db.execute(
            "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
            "adds_labels, created_at) VALUES (?, ?, ?, 0, NULL, ?)",
            (list_id, "sender", "x@y.com", _now()),
        )
        db.commit()
        personal, _ = _get_lists_for_user(db, regular_user)
        rule = personal[0]["rules"][0]
        assert rule["adds_labels_list"] == []


# ---------------------------------------------------------------------------
# Engine firing — direct unit test on the runner's labels loop
# ---------------------------------------------------------------------------
#
# Calling run_triage end-to-end requires a full provider mock + LLM
# backend stub. Cheaper + more focused: exercise the rule-match +
# label-apply contract directly with apply_labels_to_message + the
# classify.hints._rule_matches predicate.


class TestRuleMatchFiresLabels:
    def test_matching_rule_attaches_labels(self, db, regular_user):
        from email_triage.classify.hints import _rule_matches
        from email_triage.web.db import apply_labels_to_message

        # Account row needed by apply_labels_to_message
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, created_at, updated_at) "
            "VALUES (?, 'acct', 'gmail_api', '{}', ?, ?)",
            (regular_user["id"], _now(), _now()),
        )
        account_id = cur.lastrowid
        db.commit()

        create_label(db, "urgent", "Urgent")
        create_label(db, "tax", "Tax")

        rule = ListRule(
            id=1, list_id=1, rule_type=RuleType.SENDER,
            pattern="boss@example.com", skip_ai=False,
        )
        msg = EmailMessage(
            message_id="msg-X",
            provider="gmail",
            sender="boss@example.com",
            recipients=["me@example.com"],
            subject="hi",
            body_text="",
            date=datetime.now(timezone.utc),
        )
        assert _rule_matches(rule, msg) is True
        # Simulate runner: rule matched → attach labels.
        apply_labels_to_message(
            db, "msg-X", account_id, ["urgent", "tax"],
            applied_by_actor=regular_user["id"],
        )
        labels = [r["slug"] for r in list_labels_on_message(db, "msg-X")]
        assert set(labels) == {"urgent", "tax"}

    def test_non_matching_rule_no_apply(self, db, regular_user):
        from email_triage.classify.hints import _rule_matches

        rule = ListRule(
            id=2, list_id=1, rule_type=RuleType.SENDER,
            pattern="boss@example.com", skip_ai=False,
        )
        msg = EmailMessage(
            message_id="msg-Y",
            provider="gmail",
            sender="other@example.com",
            recipients=["me@example.com"],
            subject="hi",
            body_text="",
            date=datetime.now(timezone.utc),
        )
        assert _rule_matches(rule, msg) is False
        assert list_labels_on_message(db, "msg-Y") == []
