"""Boundary rejection tests for  — empty-pattern matches-everything.

The engine's substring fast-path treats ``"" in any_subject`` as True,
so a saved empty-pattern rule would match every email. Three insert
or update paths now reject empty / whitespace-only patterns at the
boundary:

* ``POST /api/lists/<id>/rules`` → 422
* ``POST /rules/<id>/add-rule`` (UI form) → 400
* ``POST /rules/<id>/rules/<rule_id>/save`` (UI inline-edit) → 400

The fourth historical site — ``_create_list_snapshot`` — already
silently skipped empty patterns on the create-list-with-first-rule
path; that behavior is unchanged here (covered by existing tests in
``test_lists.py::test_create_personal_list``).

The engine's defense-in-depth short-circuit lives at
``tests/test_classify/test_hints_empty_pattern.py``.

Note on status codes: FastAPI's ``pattern: str = Form(...)`` already
422s a truly empty string at the request-validation layer (before the
handler runs). The handler's explicit 400 fires for whitespace-only
strings — which DO pass the Form validator since they're non-empty
to FastAPI but ``strip()`` to empty inside the snapshot. The tests
assert "rejected" (4xx) without pinning a specific code, since both
layers are doing the right thing.
"""

from __future__ import annotations

import pytest


def _seed_list(db, admin_user):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO classification_lists "
        "(name, category, owner_id, is_global, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("EmptyPattern Test", "fyi", admin_user["id"], 0, now),
    )
    db.commit()
    return db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]


def _seed_rule(db, list_id, pattern="initial@x.com"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO list_rules "
        "(list_id, rule_type, pattern, skip_ai, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (list_id, "sender", pattern, 0, now),
    )
    db.commit()
    return db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]


class TestApiAddRuleRejectsEmptyPattern:
    def test_empty_pattern_422(self, client, db, admin_cookies, admin_user):
        list_id = _seed_list(db, admin_user)
        resp = client.post(
            f"/api/lists/{list_id}/rules",
            json={"rule_type": "sender", "pattern": "", "skip_ai": False},
            cookies=admin_cookies,
        )
        assert resp.status_code == 422
        # No rule should have been inserted.
        row = db.execute(
            "SELECT COUNT(*) AS n FROM list_rules WHERE list_id = ?", (list_id,),
        ).fetchone()
        assert row["n"] == 0

    def test_whitespace_only_pattern_422(self, client, db, admin_cookies, admin_user):
        list_id = _seed_list(db, admin_user)
        resp = client.post(
            f"/api/lists/{list_id}/rules",
            json={"rule_type": "subject", "pattern": "   \t\n  ", "skip_ai": True},
            cookies=admin_cookies,
        )
        assert resp.status_code == 422
        row = db.execute(
            "SELECT COUNT(*) AS n FROM list_rules WHERE list_id = ?", (list_id,),
        ).fetchone()
        assert row["n"] == 0


class TestUiAddRuleRejectsEmptyPattern:
    def test_empty_pattern_rejected(self, client, db, admin_cookies, admin_user):
        """Empty string is rejected by FastAPI's Form validator before
        the handler runs (422). Either 400 (handler) or 422 (FastAPI)
        is acceptable — both block the bad insert."""
        list_id = _seed_list(db, admin_user)
        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "sender", "pattern": "", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (400, 422)
        row = db.execute(
            "SELECT COUNT(*) AS n FROM list_rules WHERE list_id = ?", (list_id,),
        ).fetchone()
        assert row["n"] == 0

    def test_whitespace_only_pattern_400(self, client, db, admin_cookies, admin_user):
        """Whitespace-only passes FastAPI's Form validator (non-empty
        to it) and reaches the handler, which 400s after the snapshot
        rejects the post-strip empty."""
        list_id = _seed_list(db, admin_user)
        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "subject", "pattern": "   ", "skip_ai": "1"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert "empty" in resp.text.lower()
        row = db.execute(
            "SELECT COUNT(*) AS n FROM list_rules WHERE list_id = ?", (list_id,),
        ).fetchone()
        assert row["n"] == 0

    def test_valid_pattern_still_succeeds(self, client, db, admin_cookies, admin_user):
        """Sanity: rejection guard didn't break the happy path."""
        list_id = _seed_list(db, admin_user)
        resp = client.post(
            f"/rules/{list_id}/add-rule",
            data={"rule_type": "sender", "pattern": "ok@example.com", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        row = db.execute(
            "SELECT pattern FROM list_rules WHERE list_id = ?", (list_id,),
        ).fetchone()
        assert row["pattern"] == "ok@example.com"


class TestUiSaveRuleRejectsEmptyPattern:
    def test_save_empty_pattern_rejected_and_rule_unchanged(
        self, client, db, admin_cookies, admin_user,
    ):
        """Save (inline-edit) path: empty pattern must be rejected
        without mutating the existing rule. Pre-#285 the UPDATE would
        have stripped the pattern to ``""`` and silently neutralized
        the rule into a match-everything row. Either 400 (handler) or
        422 (FastAPI Form) is acceptable — both block the bad UPDATE."""
        list_id = _seed_list(db, admin_user)
        rule_id = _seed_rule(db, list_id, pattern="boss@company.com")

        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={"rule_type": "sender", "pattern": "", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (400, 422)
        # Rule pattern must still be the original.
        row = db.execute(
            "SELECT pattern FROM list_rules WHERE id = ?", (rule_id,),
        ).fetchone()
        assert row["pattern"] == "boss@company.com"

    def test_save_whitespace_only_400_and_rule_unchanged(
        self, client, db, admin_cookies, admin_user,
    ):
        list_id = _seed_list(db, admin_user)
        rule_id = _seed_rule(db, list_id, pattern="vendor.com")

        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={"rule_type": "sender_domain", "pattern": " \t ", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 400
        row = db.execute(
            "SELECT pattern FROM list_rules WHERE id = ?", (rule_id,),
        ).fetchone()
        assert row["pattern"] == "vendor.com"

    def test_save_valid_pattern_still_succeeds(
        self, client, db, admin_cookies, admin_user,
    ):
        """Sanity: rejection guard didn't break the inline-edit save."""
        list_id = _seed_list(db, admin_user)
        rule_id = _seed_rule(db, list_id, pattern="old@x.com")

        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={"rule_type": "sender", "pattern": "new@y.com", "skip_ai": "0"},
            cookies=admin_cookies,
            follow_redirects=False,
        )
        # 303 (plain form) or 200 (HTMX with the row partial) both
        # indicate success; the assertion focuses on the DB state.
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT pattern FROM list_rules WHERE id = ?", (rule_id,),
        ).fetchone()
        assert row["pattern"] == "new@y.com"
