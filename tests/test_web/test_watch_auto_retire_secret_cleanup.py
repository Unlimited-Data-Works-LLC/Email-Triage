""" — auto-retire DELETE also purges each watch's HMAC secret.

The interactive watch-delete removes the per-watch ``watch_<id>_hmac`` secret;
the auto-retire DELETE path used to delete only the rows + the fire log, leaving
the HMAC secret dangling in the store. Both paths now route through the
``delete_watch_hmac_secrets`` SSOT, and the runner threads ``secrets`` into
``maybe_auto_retire_watch`` so the cleanup actually runs.
"""

from __future__ import annotations
from _db_tracking import track

import json
from datetime import datetime, timezone

import pytest

from email_triage.web import email_watches as W
from email_triage.web.db import init_db
from email_triage.web.email_watches import (
    delete_watch_hmac_secrets,
    hmac_secret_key,
    maybe_auto_retire_watch,
)
from email_triage.web.watch_runner import _record_watch_fired


@pytest.fixture
def db():
    conn = track(init_db(":memory:"))
    yield conn
    conn.close()


class _FakeSecrets:
    def __init__(self):
        self.store: dict[str, str] = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v

    def delete(self, k):
        existed = k in self.store
        self.store.pop(k, None)
        return existed

    def list_keys(self):
        return list(self.store)


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


def _retire_watch(account_id, *, after_n=2, action="delete", gid=None, creator=None, name="W"):
    return W.EmailWatch(
        watch_id="", name=name, enabled=True, account_id=account_id,
        filter=W.WatchFilter(from_addr="x@"),
        actions=W.WatchActions(
            escalate=W.EscalateAction(enabled=True, notify_email="o@example.com"),
            auto_retire=W.AutoRetireAction(after_n=after_n, action=action),
        ),
        watch_group_id=gid, created_by_user_id=creator,
    )


# ---------------------------------------------------------------------------
# The shared helper.
# ---------------------------------------------------------------------------


class TestDeleteWatchHmacSecrets:
    def test_deletes_listed_keys(self):
        s = _FakeSecrets()
        s.set(hmac_secret_key("w1"), "a")
        s.set(hmac_secret_key("w2"), "b")
        s.set("unrelated", "keep")
        delete_watch_hmac_secrets(s, ["w1", "w2"])
        assert s.get(hmac_secret_key("w1")) is None
        assert s.get(hmac_secret_key("w2")) is None
        assert s.get("unrelated") == "keep"

    def test_none_secrets_is_noop(self):
        delete_watch_hmac_secrets(None, ["w1"])  # must not raise

    def test_backend_without_delete_is_noop(self):
        class _NoDelete:
            def get(self, k):
                return None
        delete_watch_hmac_secrets(_NoDelete(), ["w1"])  # must not raise

    def test_best_effort_swallows_errors(self):
        class _Boom:
            def delete(self, k):
                raise RuntimeError("backend down")
        delete_watch_hmac_secrets(_Boom(), ["w1"])  # must not raise


# ---------------------------------------------------------------------------
# maybe_auto_retire_watch DELETE cleans secrets.
# ---------------------------------------------------------------------------


class TestAutoRetireSecretCleanup:
    def test_delete_purges_hmac_secret(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=2))
        s = _FakeSecrets()
        s.set(hmac_secret_key(saved.watch_id), "shh")
        for i in range(2):
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        watch = W.get_watch(db, saved.watch_id)
        out = maybe_auto_retire_watch(db, watch, secrets=s)
        assert out == "deleted"
        assert W.get_watch(db, saved.watch_id) is None          # row gone
        assert s.get(hmac_secret_key(saved.watch_id)) is None    # secret gone

    def test_delete_without_secrets_is_back_compatible(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=2))
        for i in range(2):
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        watch = W.get_watch(db, saved.watch_id)
        out = maybe_auto_retire_watch(db, watch)  # no secrets -> no-op cleanup
        assert out == "deleted"
        assert W.get_watch(db, saved.watch_id) is None           # row still gone

    def test_disable_does_not_delete_secret(self, db):
        _seed_account(db, 1)
        saved = W.upsert_watch(db, _retire_watch(1, action="disable", after_n=2))
        s = _FakeSecrets()
        s.set(hmac_secret_key(saved.watch_id), "shh")
        for i in range(2):
            _record_watch_fired(db, 1, f"msg{i}", saved.watch_id)
        watch = W.get_watch(db, saved.watch_id)
        out = maybe_auto_retire_watch(db, watch, secrets=s)
        assert out == "disabled"
        # Disable is reversible — the watch (and its signing secret) must survive.
        assert W.get_watch(db, saved.watch_id) is not None
        assert s.get(hmac_secret_key(saved.watch_id)) == "shh"

    def test_group_delete_purges_every_member_secret(self, db):
        uid, _ = _seed_account(db, 1)
        db.execute(
            "INSERT INTO email_accounts (id, user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
            "VALUES (2, ?, 'acct2', 'imap', ?, 0, ?, ?)",
            (uid, json.dumps({"host": "m", "username": "u"}),
             datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
        gid = W.new_watch_group_id()
        w1 = W.upsert_watch(db, _retire_watch(1, action="delete", after_n=2, gid=gid, creator=uid))
        w2 = W.upsert_watch(db, _retire_watch(2, action="delete", after_n=2, gid=gid, creator=uid))
        s = _FakeSecrets()
        s.set(hmac_secret_key(w1.watch_id), "a")
        s.set(hmac_secret_key(w2.watch_id), "b")
        # One delivered fire per account row -> 2 total across the group >= after_n.
        _record_watch_fired(db, 1, "msg-a", w1.watch_id)
        _record_watch_fired(db, 2, "msg-b", w2.watch_id)
        out = maybe_auto_retire_watch(db, W.get_watch(db, w1.watch_id), secrets=s)
        assert out == "deleted"
        assert W.get_watch(db, w1.watch_id) is None
        assert W.get_watch(db, w2.watch_id) is None
        assert s.get(hmac_secret_key(w1.watch_id)) is None
        assert s.get(hmac_secret_key(w2.watch_id)) is None
