"""Punch 708 (N-642): behaviour of the caller-held-transaction fixes.

The structural half is ``tests/test_708_caller_txn_funnel_pin.py``; the census
is ``clsC-708-census.md`` (outside the tree). Here: the orphan sweep in
``update_email_account`` commits with its UPDATE and never reverts a reported
update, and the two nested-aware funnels refuse an open transaction nobody
declared (a leak) before any write.
"""
from __future__ import annotations

import sqlite3

import pytest

import email_triage.web.db as wdb
from email_triage.db.accounts import update_account_config_keys, update_email_account
from email_triage.db.audit import record_user_update
from email_triage.web.db import create_email_account, get_setting, set_setting


def _acct(db, admin_user):
    return create_email_account(
        db, admin_user["id"], "Sweep", "imap",
        {"host": "x.invalid", "mailboxes": ["INBOX", "Old"]},
    )


def _rename(db, aid):
    return update_email_account(
        db, aid, "Renamed", "imap", {"host": "x.invalid", "mailboxes": ["INBOX"]},
    )


def _name(db, aid):
    return db.execute("SELECT name FROM email_accounts WHERE id = ?", (aid,)).fetchone()["name"]


class TestOrphanSweepCommitsWithItsUpdate:
    def test_the_update_and_the_sweep_land_in_one_commit(self, db, admin_user):
        aid = _acct(db, admin_user)
        set_setting(db, f"watch_hwm:{aid}:mailbox:Old", 5)
        assert _rename(db, aid) is True
        assert not db.in_transaction
        assert _name(db, aid) == "Renamed"
        assert get_setting(db, f"watch_hwm:{aid}:mailbox:Old") is None

    def test_a_failed_sweep_statement_never_reverts_the_reported_update(
            self, db, admin_user, monkeypatch):
        aid = _acct(db, admin_user)

        def boom(*_a, **_kw):
            raise sqlite3.OperationalError("sweep statement failed")

        monkeypatch.setattr(wdb, "delete_setting_txn", boom)
        assert _rename(db, aid) is True
        assert _name(db, aid) == "Renamed"

    def test_an_error_that_rolled_the_whole_transaction_back_is_raised(
            self, db, admin_user, monkeypatch):
        aid = _acct(db, admin_user)

        def full_rollback(conn, _key):
            conn.rollback()  # what SQLITE_FULL / IOERR do to the transaction
            raise sqlite3.OperationalError("database or disk is full")

        monkeypatch.setattr(wdb, "delete_setting_txn", full_rollback)
        with pytest.raises(sqlite3.OperationalError, match="disk is full"):
            _rename(db, aid)
        assert _name(db, aid) == "Sweep"


def _role(db, uid):
    return db.execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()["role"]


class TestUndeclaredNestingIsRefused:
    def test_record_user_update_refuses_a_leaked_transaction_before_any_write(
            self, db, admin_user, regular_user):
        db.commit()
        db.execute("UPDATE users SET name = 'leaked' WHERE id = ?", (admin_user["id"],))
        assert db.in_transaction
        with pytest.raises(RuntimeError, match="leaked"):
            record_user_update(
                db, user_id=regular_user["id"], role="admin",
                actor_user_id=admin_user["id"], actor_email=admin_user["email"])
        # @db_write rolled the leaked transaction back; nothing was reported done.
        assert not db.in_transaction
        assert _role(db, regular_user["id"]) == "user"
        assert db.execute(
            "SELECT COUNT(*) FROM auth_events WHERE event_type = 'user_role_changed'"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = 'record_user_update'"
        ).fetchone()[0] == 1

    def test_record_user_update_refuses_a_declaration_with_no_transaction(
            self, db, admin_user, regular_user):
        db.commit()
        with pytest.raises(RuntimeError, match="holds no transaction"):
            record_user_update(
                db, user_id=regular_user["id"], role="admin",
                actor_user_id=admin_user["id"], actor_email=admin_user["email"],
                _in_caller_txn=True)
        assert _role(db, regular_user["id"]) == "user"

    def test_update_account_config_keys_refuses_a_leaked_transaction(self, db, admin_user):
        aid = _acct(db, admin_user)
        db.commit()
        db.execute("UPDATE email_accounts SET name = 'leaked' WHERE id = ?", (aid,))
        with pytest.raises(RuntimeError, match="leaked"):
            update_account_config_keys(db, aid, digest_enabled=True)
        assert not db.in_transaction
        assert _name(db, aid) == "Sweep"

    def test_a_declared_nesting_still_leaves_the_commit_to_the_caller(self, db, admin_user):
        aid = _acct(db, admin_user)
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        assert update_account_config_keys(
            db, aid, _in_caller_txn=True, digest_enabled=True) is True
        assert db.in_transaction, "the funnel ended the caller's transaction"
        db.rollback()
        cfg = db.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?", (aid,)).fetchone()[0]
        assert "digest_enabled" not in cfg


class TestHipaaFlipWithExplicitAutoScan:
    """Panel AB MUST-C3: the cascade reaches ``update_account_config_keys`` two
    hops down (``set_auto_scan_enabled_for_account``). Undeclared, every 0->1 flip
    on an account with an explicit ``auto_scan_enabled=True`` was refused and
    rolled back. The existing hipaa tests use ``{}`` config, where the force-off
    branch never runs."""

    def test_the_flip_lands_forces_auto_scan_off_and_writes_its_witness(self, db, admin_user):
        from email_triage.db.accounts import set_account_hipaa
        from email_triage.web.db import get_email_account

        aid = create_email_account(
            db, admin_user["id"], "Scan", "imap", {"auto_scan_enabled": True})
        acct = set_account_hipaa(db, aid, True, actor_id=admin_user["id"])
        assert acct["hipaa"] == 1
        assert get_email_account(db, aid)["config"]["auto_scan_enabled"] is False
        assert not db.in_transaction
        rows = db.execute(
            "SELECT direction, reason FROM hipaa_boundary_events WHERE scope = ? ORDER BY id",
            (f"account:{aid}",)).fetchall()
        assert [r["direction"] for r in rows] == ["on", "cascade"]
        assert "auto_scan_enabled=off" in rows[1]["reason"]

    def test_the_wrapper_outside_a_transaction_still_commits(self, db, admin_user):
        from email_triage.web.db import get_email_account, set_auto_scan_enabled_for_account

        aid = create_email_account(db, admin_user["id"], "Scan", "imap", {})
        db.commit()
        set_auto_scan_enabled_for_account(db, aid, True)
        assert not db.in_transaction
        assert get_email_account(db, aid)["config"]["auto_scan_enabled"] is True
