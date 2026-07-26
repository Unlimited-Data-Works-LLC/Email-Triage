""" — auto-retire is operator-visible in access_log.

A watch that auto-disables/deletes itself used to emit only a ``log.info`` —
invisible in the UI, especially for the irreversible ``delete``. It now writes
an ``access_log`` row (rendered on /compliance) via the ``record_access_event``
emitter SSOT, with PHI-free detail (watch metadata + counts, never sender or
subject).
"""

from __future__ import annotations
from _db_tracking import track

import json
from datetime import datetime, timezone

import pytest

from email_triage.web import email_watches as W
from email_triage.web.db import init_db
from email_triage.web.email_watches import maybe_auto_retire_watch
from email_triage.web.watch_runner import _record_watch_fired


@pytest.fixture
def db():
    conn = track(init_db(":memory:"))
    yield conn
    conn.close()


def _seed_account(db, account_id=1):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
        ("u@example.com", "Op", "user", now),
    )
    uid = db.execute("SELECT id FROM users WHERE email='u@example.com'").fetchone()["id"]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?,?,?,?,?,0,?,?)",
        (account_id, uid, "acct", "imap", json.dumps({"host": "m", "username": "u"}), now, now),
    )
    db.commit()
    return uid, account_id


def _retire_watch(account_id, *, after_n=2, action="delete", name="Phish alerts"):
    return W.EmailWatch(
        watch_id="", name=name, enabled=True, account_id=account_id,
        filter=W.WatchFilter(from_addr="boss@"),
        actions=W.WatchActions(
            escalate=W.EscalateAction(enabled=True, notify_email="o@example.com"),
            auto_retire=W.AutoRetireAction(after_n=after_n, action=action),
        ),
    )


def _auto_retire_rows(db):
    rows = db.execute(
        "SELECT outcome, detail FROM access_log WHERE outcome LIKE 'watch_auto_%'"
    ).fetchall()
    return [dict(r) for r in rows]


class TestAutoRetireAudit:
    def test_delete_writes_visible_access_log_row(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=2))
        for i in range(2):
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        out = maybe_auto_retire_watch(db, W.get_watch(db, saved.watch_id))
        assert out == "deleted"
        rows = _auto_retire_rows(db)
        assert len(rows) == 1
        assert rows[0]["outcome"] == "watch_auto_deleted"
        detail = json.loads(rows[0]["detail"])
        assert detail["watch_name"] == "Phish alerts"
        assert detail["auto_retire_action"] == "delete"
        assert detail["fires"] == 2
        assert detail["after_n"] == 2
        assert detail["rows_affected"] == 1

    def test_disable_writes_visible_access_log_row(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="disable", after_n=2))
        for i in range(2):
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        out = maybe_auto_retire_watch(db, W.get_watch(db, saved.watch_id))
        assert out == "disabled"
        rows = _auto_retire_rows(db)
        assert len(rows) == 1
        assert rows[0]["outcome"] == "watch_auto_disabled"

    def test_below_threshold_writes_no_row(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=5))
        for i in range(2):  # 2 < 5
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        out = maybe_auto_retire_watch(db, W.get_watch(db, saved.watch_id))
        assert out is None
        assert _auto_retire_rows(db) == []

    def test_audit_detail_is_phi_free(self, db):
        """The detail JSON carries watch metadata + counts only — never the
        sender/subject the matcher saw."""
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=1))
        _record_watch_fired(db, 1, "msg0", saved.watch_id)
        maybe_auto_retire_watch(db, W.get_watch(db, saved.watch_id))
        detail_str = _auto_retire_rows(db)[0]["detail"]
        assert "boss@" not in detail_str          # the filter sender
        assert "sender" not in detail_str
        assert "subject" not in detail_str
        # Only the declared keys are present.
        assert set(json.loads(detail_str)) == {
            "watch_id", "watch_name", "auto_retire_action",
            "fires", "after_n", "rows_affected",
        }
