"""N-520 step 2: a state change and its witness commit in ONE transaction.

Behavioural half of the N-520 MEMBER fixes. The structural half is
``tests/test_n520_commit_before_witness_ratchet_pin.py`` (the fixed sites are no
longer findings and no longer allow-listed). Per funnel, at runtime:

(a) the state row and the witness row both land;
(b) a forced witness failure leaves the state UNWRITTEN (fail closed), raises,
    and leaves one ``audit_gap_events`` row;
(c) a ``state_txn`` that commits on its own (the commit-before-witness shape)
    is refused before the witness runs;
(d) a no-op state change writes no witness.
"""
from __future__ import annotations

import pytest

import email_triage.db.audit as audit_mod
from email_triage.db.audit import record_user_offboard, record_witnessed_state_change
from email_triage.web.db import create_email_account

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


def _active(db, acct_id):
    return db.execute(
        "SELECT is_active FROM email_accounts WHERE id = ?", (acct_id,)
    ).fetchone()["is_active"]


@pytest.fixture
def acct(db, admin_user):
    return create_email_account(db, admin_user["id"], "N520", "imap", {"host": "x.invalid"})


def _deactivate(acct_id):
    from email_triage.db.accounts import set_account_active_txn
    return lambda c: set_account_active_txn(c, acct_id, False)


def _witness(admin_user, acct_id):
    def w(c, changed):
        if changed:
            audit_mod.record_auth_event_txn(
                c, event_type="n520_probe", email=admin_user["email"],
                user_id=admin_user["id"], detail=f"account_id={acct_id}",
            )
    return w


class TestFunnel:
    def test_state_and_witness_both_land(self, db, acct, admin_user):
        assert record_witnessed_state_change(
            db, operation="n520_probe",
            state_txn=_deactivate(acct), witness_txn=_witness(admin_user, acct),
        ) is True
        assert _active(db, acct) == 0
        assert len(_events(db, "n520_probe")) == 1

    def test_a_failed_witness_rolls_the_state_back_and_leaves_one_gap(
            self, db, acct, admin_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_witnessed_state_change(
                db, operation="n520_probe",
                state_txn=_deactivate(acct), witness_txn=_witness(admin_user, acct),
            )
        assert _active(db, acct) == 1
        assert _gaps(db, "record_witnessed_state_change") == 1

    def test_a_self_committing_state_is_refused_before_the_witness(
            self, db, acct, admin_user):
        """TEETH: the commit-before-witness shape itself. If the funnel ever
        lets a state write commit ahead of the witness, the witness below runs
        and this test fails."""
        from email_triage.db.accounts import set_account_active
        ran = []
        with pytest.raises(RuntimeError, match="committed its own write"):
            record_witnessed_state_change(
                db, operation="n520_probe",
                state_txn=lambda c: set_account_active(c, acct, False),
                witness_txn=lambda c, r: ran.append(r),
            )
        assert ran == []
        assert _events(db, "n520_probe") == []

    def test_a_no_op_writes_no_witness(self, db, admin_user):
        assert record_witnessed_state_change(
            db, operation="n520_probe",
            state_txn=_deactivate(987654), witness_txn=_witness(admin_user, 987654),
        ) is False
        assert _events(db, "n520_probe") == []


class TestOffboard:
    def test_each_deactivation_is_witnessed(self, db, acct, admin_user, regular_user):
        other = create_email_account(db, regular_user["id"], "N520B", "imap", {"host": "x.invalid"})
        record_user_offboard(
            db, user_id=regular_user["id"], account_ids=[other],
            actor_user_id=admin_user["id"], reason="test offboard",
        )
        assert _active(db, other) == 0
        (row,) = _events(db, "account_deactivated")
        assert row["email"] == admin_user["email"]
        assert row["detail"] == f"account_id={other} offboard_user_id={regular_user['id']}"
        assert db.execute(
            "SELECT disabled FROM users WHERE id = ?", (regular_user["id"],),
        ).fetchone()["disabled"] == 1

    def test_a_failed_witness_leaves_the_account_active_and_the_user_enabled(
            self, db, admin_user, regular_user, monkeypatch):
        other = create_email_account(db, regular_user["id"], "N520C", "imap", {"host": "x.invalid"})
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_user_offboard(
                db, user_id=regular_user["id"], account_ids=[other],
                actor_user_id=admin_user["id"], reason="test offboard",
            )
        assert _active(db, other) == 1
        assert db.execute(
            "SELECT disabled FROM users WHERE id = ?", (regular_user["id"],),
        ).fetchone()["disabled"] == 0

    def test_an_unattributed_offboard_is_refused_before_any_write(
            self, db, regular_user):
        other = create_email_account(db, regular_user["id"], "N520D", "imap", {"host": "x.invalid"})
        with pytest.raises(ValueError):
            record_user_offboard(
                db, user_id=regular_user["id"], account_ids=[other],
                actor_user_id=987654, reason="test offboard",
            )
        assert _active(db, other) == 1
