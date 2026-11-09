"""Punch 673 (account delegation) and 674 (role change): access grants made
outside an INSERT-created credential are witnessed.

Before: ``add_account_delegate`` / ``remove_account_delegate`` wrote
``account_delegates`` with only an INFO log line, and the API PATCH /users and
the UI user form raised a user's role with an UPDATE and no ``auth_events`` row.
Per writer, at runtime:

(a) the witness row exists after the write, with the SUBJECT in ``user_id``, the
    ACTOR in ``email``, and only typed ids / bounded values in ``detail`` (the
    one exception: a login-address change carries the old and new address, panel
    Z MUST-Z1-1 / DA NOTE-Z1-5, so the row shows where the OTP factor went);
(b) a forced witness failure leaves the grant UNWRITTEN (fail closed) and one
    ``audit_gap_events`` row;
(c) a refusal or a no-op writes no grant, and a refusal leaves its denied row;
(d) the delegate route still renders its fragment (PD-17).

The static half is ``tests/test_session_epoch_on_revoke_pin.py`` (the REVOKE and
UPDATE arms, and Property 0 over the discovered ``account_delegates`` class).
"""
from __future__ import annotations

import pytest

import email_triage.db.audit as audit_mod
from email_triage.db.audit import (
    DELEGATE_IS_OWNER,
    GrantRefused,
    record_user_update,
)
from email_triage.web.db import (
    add_account_delegate,
    create_email_account,
    is_account_delegate,
    remove_account_delegate,
)

_DOWN = "audit storage exploded"


def _boom(*_a, **_kw):
    raise RuntimeError(_DOWN)


def _events(db, event_type):
    return db.execute(
        "SELECT * FROM auth_events WHERE event_type = ? ORDER BY id", (event_type,)
    ).fetchall()


def _gaps(db, helper):
    return db.execute(
        "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = ?", (helper,)
    ).fetchone()[0]


def _role(db, uid):
    return db.execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()["role"]


@pytest.fixture
def acct(db, admin_user):
    return create_email_account(db, admin_user["id"], "DELEG", "imap", {"host": "x.invalid"})


class TestDelegateGrant:
    def test_the_grant_is_witnessed(self, db, acct, admin_user, regular_user):
        assert add_account_delegate(db, acct, regular_user["id"], admin_user["id"]) is True
        (row,) = _events(db, "account_delegate_granted")
        assert row["user_id"] == regular_user["id"]
        assert row["email"] == admin_user["email"]
        assert row["outcome"] == "success"
        assert row["detail"] == f"account_id={acct} actor_user_id={admin_user['id']}"

    def test_a_repeat_grant_is_a_no_op_with_no_row(self, db, acct, admin_user, regular_user):
        add_account_delegate(db, acct, regular_user["id"], admin_user["id"])
        assert add_account_delegate(db, acct, regular_user["id"], admin_user["id"]) is False
        assert len(_events(db, "account_delegate_granted")) == 1

    def test_the_owner_as_delegate_is_a_witnessed_refusal(self, db, acct, admin_user):
        gaps = _gaps(db, "record_account_delegate_grant")
        got = add_account_delegate(db, acct, admin_user["id"], admin_user["id"])
        assert isinstance(got, GrantRefused) and got == DELEGATE_IS_OWNER and not got
        (row,) = _events(db, "account_delegate_granted")
        assert row["outcome"] == "denied:owner_is_delegate"
        assert _gaps(db, "record_account_delegate_grant") == gaps

    def test_a_failed_witness_leaves_no_grant_and_one_gap(
            self, db, acct, admin_user, regular_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            add_account_delegate(db, acct, regular_user["id"], admin_user["id"])
        assert is_account_delegate(db, acct, regular_user["id"]) is False
        assert _gaps(db, "record_account_delegate_grant") == 1

    @pytest.mark.parametrize("actor", [None, 987654])
    def test_an_unattributed_grant_is_refused_before_any_write(
            self, db, acct, regular_user, actor):
        with pytest.raises(ValueError, match="granted_by"):
            add_account_delegate(db, acct, regular_user["id"], actor)
        assert is_account_delegate(db, acct, regular_user["id"]) is False
        assert _events(db, "account_delegate_granted") == []


class TestDelegateRevoke:
    def test_the_revoke_is_witnessed(self, db, acct, admin_user, regular_user):
        add_account_delegate(db, acct, regular_user["id"], admin_user["id"])
        assert remove_account_delegate(
            db, acct, regular_user["id"], revoked_by=admin_user["id"]) is True
        (row,) = _events(db, "account_delegate_revoked")
        assert (row["user_id"], row["email"], row["outcome"]) == (
            regular_user["id"], admin_user["email"], "success")

    def test_revoking_nothing_writes_no_row(self, db, acct, admin_user, regular_user):
        assert remove_account_delegate(
            db, acct, regular_user["id"], revoked_by=admin_user["id"]) is False
        assert _events(db, "account_delegate_revoked") == []

    def test_a_failed_witness_keeps_the_delegate_and_leaves_one_gap(
            self, db, acct, admin_user, regular_user, monkeypatch):
        add_account_delegate(db, acct, regular_user["id"], admin_user["id"])
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            remove_account_delegate(db, acct, regular_user["id"], revoked_by=admin_user["id"])
        assert is_account_delegate(db, acct, regular_user["id"]) is True
        assert _gaps(db, "record_account_delegate_revoke") == 1


class TestDelegateRoutes:
    def test_the_add_route_witnesses_and_renders(
            self, client, db, acct, admin_user, admin_cookies, regular_user):
        r = client.post(f"/accounts/{acct}/delegates/add",
                        data={"user_id": str(regular_user["id"])}, cookies=admin_cookies)
        assert r.status_code == 200, r.text
        assert regular_user["email"] in r.text
        (row,) = _events(db, "account_delegate_granted")
        assert row["email"] == admin_user["email"] and row["ip"]

    def test_the_add_route_shows_the_refusal(self, client, db, acct, admin_user, admin_cookies):
        r = client.post(f"/accounts/{acct}/delegates/add",
                        data={"user_id": str(admin_user["id"])}, cookies=admin_cookies)
        assert r.status_code == 200, r.text
        assert "Owner cannot be added as a delegate" in r.text
        assert _events(db, "account_delegate_granted")[0]["outcome"] == "denied:owner_is_delegate"

    def test_the_remove_route_witnesses_and_renders(
            self, client, db, acct, admin_user, admin_cookies, regular_user):
        add_account_delegate(db, acct, regular_user["id"], admin_user["id"])
        r = client.delete(f"/accounts/{acct}/delegates/{regular_user['id']}",
                          cookies=admin_cookies)
        assert r.status_code == 200, r.text
        (row,) = _events(db, "account_delegate_revoked")
        assert row["email"] == admin_user["email"] and row["ip"]


class TestRoleChange:
    def test_the_api_witnesses_a_role_change(
            self, client, db, admin_user, admin_cookies, regular_user):
        r = client.patch(f"/api/users/{regular_user['id']}", json={"role": "admin"},
                         cookies=admin_cookies)
        assert r.status_code == 200, r.text
        assert _role(db, regular_user["id"]) == "admin"
        (row,) = _events(db, "user_role_changed")
        assert row["user_id"] == regular_user["id"]
        assert row["email"] == admin_user["email"]
        assert row["detail"] == (
            f"old_role=user new_role=admin source=api actor_user_id={admin_user['id']}")
        assert row["ip"]

    def test_the_ui_witnesses_a_role_change(
            self, csrf_client, db, admin_user, admin_cookies, regular_user):
        r = csrf_client.post(
            f"/users/{regular_user['id']}/update",
            data={"email": "", "name": "Renamed", "role": "admin", "notify_email": ""},
            cookies=admin_cookies, follow_redirects=False)
        assert r.status_code == 303, r.text
        assert _role(db, regular_user["id"]) == "admin"
        (row,) = _events(db, "user_role_changed")
        assert row["detail"].startswith("old_role=user new_role=admin source=ui ")

    def test_an_unchanged_role_writes_no_row_but_still_bumps_the_epoch(
            self, db, admin_user, regular_user):
        before = db.execute("SELECT session_epoch FROM users WHERE id = ?",
                            (regular_user["id"],)).fetchone()[0]
        assert record_user_update(
            db, user_id=regular_user["id"], name="N", role="user",
            actor_user_id=admin_user["id"], actor_email=admin_user["email"]) is True
        assert _events(db, "user_role_changed") == []
        after = db.execute("SELECT session_epoch FROM users WHERE id = ?",
                           (regular_user["id"],)).fetchone()[0]
        assert after == before + 1

    def test_a_failed_witness_leaves_the_role_and_one_gap(
            self, client, db, admin_user, admin_cookies, regular_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        r = client.patch(f"/api/users/{regular_user['id']}",
                         json={"role": "admin", "name": "Changed"}, cookies=admin_cookies)
        assert r.status_code == 500, r.text
        row = db.execute("SELECT role, name FROM users WHERE id = ?",
                         (regular_user["id"],)).fetchone()
        assert (row["role"], row["name"]) == ("user", regular_user["name"])
        assert _gaps(db, "record_user_update") == 1

    @pytest.mark.parametrize("actor", ["", "   "])
    def test_a_blank_actor_is_refused_before_any_write(self, db, regular_user, actor):
        with pytest.raises(ValueError, match="actor_email"):
            record_user_update(db, user_id=regular_user["id"], role="admin",
                               actor_user_id=None, actor_email=actor)
        assert _role(db, regular_user["id"]) == "user"

    def test_the_ui_refuses_an_unknown_role(self, csrf_client, db, admin_cookies, regular_user):
        r = csrf_client.post(
            f"/users/{regular_user['id']}/update",
            data={"email": "", "name": "X", "role": "superuser", "notify_email": ""},
            cookies=admin_cookies, follow_redirects=False)
        assert r.status_code == 400
        assert _role(db, regular_user["id"]) == "user"


def _epoch(db, uid):
    return db.execute("SELECT session_epoch FROM users WHERE id = ?", (uid,)).fetchone()[0]


def _email(db, uid):
    return db.execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone()["email"]


class TestEmailChange:
    """Panel Z MUST-Z1-1: ``users.email`` is where OTP codes go, so a change of it
    re-binds the login factor (§164.308(a)(5)(ii)(D)) and is witnessed like a role."""

    def test_the_ui_witnesses_an_email_change(
            self, csrf_client, db, admin_user, admin_cookies, regular_user):
        old = regular_user["email"]
        r = csrf_client.post(
            f"/users/{regular_user['id']}/update",
            data={"email": "moved@example.com", "name": regular_user["name"],
                  "role": "user", "notify_email": ""},
            cookies=admin_cookies, follow_redirects=False)
        assert r.status_code == 303, r.text
        assert _email(db, regular_user["id"]) == "moved@example.com"
        (row,) = _events(db, "user_email_changed")
        assert row["user_id"] == regular_user["id"]
        assert row["email"] == admin_user["email"]
        assert row["outcome"] == "success"
        assert row["detail"] == (
            f"old_email={old!r} new_email='moved@example.com' source=ui "
            f"actor_user_id={admin_user['id']}")
        assert row["ip"]

    def test_an_unchanged_email_writes_no_row_but_still_bumps_the_epoch(
            self, db, admin_user, regular_user):
        before = _epoch(db, regular_user["id"])
        assert record_user_update(
            db, user_id=regular_user["id"], email=regular_user["email"],
            actor_user_id=admin_user["id"], actor_email=admin_user["email"]) is True
        assert _events(db, "user_email_changed") == []
        assert _epoch(db, regular_user["id"]) == before + 1

    def test_a_failed_witness_leaves_the_email_and_one_gap(
            self, db, admin_user, regular_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_user_update(
                db, user_id=regular_user["id"], email="moved@example.com",
                name="Changed", actor_user_id=admin_user["id"],
                actor_email=admin_user["email"], source="ui")
        assert _email(db, regular_user["id"]) == regular_user["email"]
        assert _gaps(db, "record_user_update") == 1

    def test_a_missing_user_leaves_no_open_transaction(self, db, admin_user):
        # db NOTE-Z1-4: the read runs inside the write transaction now; the
        # not-found exit must end it, or the next BEGIN IMMEDIATE raises.
        assert record_user_update(
            db, user_id=987654, email="x@example.com", actor_user_id=admin_user["id"],
            actor_email=admin_user["email"]) is False
        assert not db.in_transaction


class TestCallerHeldTransaction:
    """Punch 696: a caller that already holds a transaction owns it on every edge.
    Before, the funnel skipped only its BEGIN and its not-found rollback; its
    success commit() committed the caller's earlier writes and its except
    rollback() discarded them (N-342 rule, db/accounts.py)."""

    @staticmethod
    def _name(db, uid):
        return db.execute("SELECT name FROM users WHERE id = ?", (uid,)).fetchone()["name"]

    def _begin_with_a_caller_write(self, db, admin_user):
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE users SET name = 'caller-write' WHERE id = ?", (admin_user["id"],))

    def test_the_funnel_does_not_commit_a_caller_held_transaction(
            self, db, admin_user, regular_user):
        self._begin_with_a_caller_write(db, admin_user)
        assert record_user_update(
            db, user_id=regular_user["id"], role="admin",
            actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            _in_caller_txn=True) is True
        assert db.in_transaction, "the funnel ended the caller's transaction"
        db.rollback()
        assert self._name(db, admin_user["id"]) == admin_user["name"]
        assert _role(db, regular_user["id"]) == "user"
        assert _events(db, "user_role_changed") == []

    def test_the_caller_commit_lands_the_update_and_its_witness_together(
            self, db, admin_user, regular_user):
        self._begin_with_a_caller_write(db, admin_user)
        record_user_update(
            db, user_id=regular_user["id"], role="admin",
            actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            _in_caller_txn=True)
        db.commit()
        assert self._name(db, admin_user["id"]) == "caller-write"
        assert _role(db, regular_user["id"]) == "admin"
        (row,) = _events(db, "user_role_changed")
        assert row["user_id"] == regular_user["id"]

    def test_a_nested_failed_witness_commits_nothing_of_the_caller(
            self, db, admin_user, regular_user, monkeypatch):
        self._begin_with_a_caller_write(db, admin_user)
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_user_update(
                db, user_id=regular_user["id"], role="admin",
                actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            _in_caller_txn=True)
        # @db_write rolls the caller's transaction back before it writes the gap
        # row: a nested failure never commits the caller's or the funnel's writes.
        assert self._name(db, admin_user["id"]) == admin_user["name"]
        assert _role(db, regular_user["id"]) == "user"
        assert _gaps(db, "record_user_update") == 1
