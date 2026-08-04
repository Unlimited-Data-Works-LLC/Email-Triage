""" — legacy doubly-NULL-creator same-name over-group edge.

A user-facing watch is a GROUP of per-account rows. Grouping is by
``watch_group_id`` (post-v17) or, for legacy rows without it, by
``(created_by_user_id, name)``. The legacy key folded a NULL creator to a
sentinel, so two UNRELATED watches with NULL creator + the same name collided
into one group — and an auto-retire/delete on one would wrongly hit the other.

The fix makes a doubly-NULL (no group id AND no creator) row a SINGLETON in
BOTH ``list_watch_groups_for_user`` (the editor list) and ``_group_watch_ids``
(the auto-retire grain) — tightening only one would be CIDI divergence. The
mirror-property test pins that the two stay in agreement.
"""

from __future__ import annotations
from _db_tracking import track

import json
from datetime import datetime, timezone

import pytest

from email_triage.web import email_watches as W
from email_triage.web.db import init_db


@pytest.fixture
def db():
    conn = track(init_db(":memory:"))
    yield conn
    conn.close()


def _seed_user_and_accounts(db, n=2):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("u@example.com", "Op", "user", now),
    )
    uid = db.execute("SELECT id FROM users WHERE email='u@example.com'").fetchone()["id"]
    for i in range(1, n + 1):
        db.execute(
            "INSERT INTO email_accounts "
            "(id, user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
            (i, uid, f"acct{i}", "imap", json.dumps({"host": "m", "username": "u"}), now, now),
        )
    db.commit()
    return uid, list(range(1, n + 1))


def _seed_watch(db, *, name, account_id, creator=None, gid=None):
    w = W.EmailWatch(
        watch_id="", name=name, enabled=True, account_id=account_id,
        filter=W.WatchFilter(from_addr="x@"),
        actions=W.WatchActions(
            escalate=W.EscalateAction(enabled=True, notify_email="o@example.com"),
        ),
        created_by_user_id=creator, watch_group_id=gid,
    )
    return W.upsert_watch(db, w).watch_id


class TestNullCreatorIsolation:
    def test_null_creator_same_name_are_separate_groups(self, db):
        uid, (a1, a2) = _seed_user_and_accounts(db)
        _seed_watch(db, name="Alerts", account_id=a1)  # NULL creator + NULL gid
        _seed_watch(db, name="Alerts", account_id=a2)  # NULL creator + NULL gid
        groups = W.list_watch_groups_for_user(db, uid)
        # Two unrelated NULL-creator "Alerts" → TWO groups, not one merged.
        assert len(groups) == 2
        assert all(len(g["watch_ids"]) == 1 for g in groups)

    def test_group_watch_ids_null_creator_is_singleton(self, db):
        uid, (a1, a2) = _seed_user_and_accounts(db)
        w1 = _seed_watch(db, name="Alerts", account_id=a1)
        _seed_watch(db, name="Alerts", account_id=a2)
        watch1 = W.get_watch(db, w1)
        ids = W._group_watch_ids(db, watch1)
        # Only itself — NOT the other same-name NULL-creator watch.
        assert ids == [w1]


class TestKnownCreatorStillGroups:
    def test_known_creator_legacy_rows_group_by_creator_name(self, db):
        uid, (a1, a2) = _seed_user_and_accounts(db)
        w1 = _seed_watch(db, name="Bills", account_id=a1, creator=uid)  # NULL gid
        w2 = _seed_watch(db, name="Bills", account_id=a2, creator=uid)  # NULL gid
        groups = W.list_watch_groups_for_user(db, uid)
        assert len(groups) == 1
        assert set(groups[0]["watch_ids"]) == {w1, w2}
        # _group_watch_ids agrees.
        assert set(W._group_watch_ids(db, W.get_watch(db, w1))) == {w1, w2}

    def test_gid_grouping_unchanged(self, db):
        uid, (a1, a2) = _seed_user_and_accounts(db)
        gid = W.new_watch_group_id()
        w1 = _seed_watch(db, name="Sales", account_id=a1, creator=uid, gid=gid)
        w2 = _seed_watch(db, name="Sales", account_id=a2, creator=uid, gid=gid)
        groups = W.list_watch_groups_for_user(db, uid)
        assert len(groups) == 1
        assert set(groups[0]["watch_ids"]) == {w1, w2}


class TestMirrorProperty:
    """The divergence pin: for EVERY watch the user can see, the
    ``_group_watch_ids`` set equals the ``watch_ids`` of that watch's group in
    ``list_watch_groups_for_user``. If the two grouping keys ever diverge, this
    fails — they MUST stay mirrored (the  CIDI guard)."""

    def _assert_mirror(self, db, uid):
        groups = W.list_watch_groups_for_user(db, uid)
        # Map watch_id -> its group's full watch_id set.
        wid_to_group = {}
        for g in groups:
            s = set(g["watch_ids"])
            for wid in g["watch_ids"]:
                wid_to_group[wid] = s
        for wid, expected in wid_to_group.items():
            got = set(W._group_watch_ids(db, W.get_watch(db, wid)))
            assert got == expected, f"divergence for {wid}: {got} != {expected}"

    def test_mirror_null_creator(self, db):
        uid, (a1, a2) = _seed_user_and_accounts(db)
        _seed_watch(db, name="Alerts", account_id=a1)
        _seed_watch(db, name="Alerts", account_id=a2)
        self._assert_mirror(db, uid)

    def test_mirror_mixed(self, db):
        uid, (a1, a2, a3) = _seed_user_and_accounts(db, n=3)
        gid = W.new_watch_group_id()
        _seed_watch(db, name="G", account_id=a1, creator=uid, gid=gid)
        _seed_watch(db, name="G", account_id=a2, creator=uid, gid=gid)
        _seed_watch(db, name="Legacy", account_id=a3, creator=uid)   # known-creator
        _seed_watch(db, name="Orphan", account_id=a1)                # doubly-NULL
        _seed_watch(db, name="Orphan", account_id=a2)                # doubly-NULL
        self._assert_mirror(db, uid)
