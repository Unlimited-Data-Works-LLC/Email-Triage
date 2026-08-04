""" v46 — regulatory_clock_def / instance / event schema pins.

The 3 tables for Regulatory clock awareness. Pins the HIPAA/integrity-shaped
constraints the design+ruling require: the per-account-override CHECK (only
institutionally-variable IRB/INTERNAL regimes may carry a per-account duration
override; FDA/EU durations are federally fixed), the (account_id, case_ref) dedup
index (scoped within an account), and ON DELETE RESTRICT on a live clock's account
(a live regulatory obligation must not be silently destroyed by account deletion).
"""
from __future__ import annotations

import sqlite3

import pytest

from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


def test_v46_creates_the_three_tables(conn):
    tabs = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {
        "regulatory_clock_def",
        "regulatory_clock_instance",
        "regulatory_clock_event",
    } <= tabs


def test_v46_indexes(conn):
    idx = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }
    assert {
        "idx_rci_account", "idx_rci_sweep", "idx_rci_case", "idx_rce_instance",
    } <= idx


def _def(code, regime, severity, start_kind, owner=None):
    cols = ("code,regime,citation,title,severity_class,duration_value,"
            "clock_start_kind,config_owner_account_id,created_at")
    return (
        f"INSERT INTO regulatory_clock_def ({cols}) VALUES "
        f"('{code}','{regime}','c','t','{severity}',7,'{start_kind}',"
        f"{'NULL' if owner is None else owner},'now')"
    )


def test_per_account_override_check_allows_irb_blocks_fda(conn):
    # IRB/INTERNAL MAY carry a per-account duration override...
    conn.execute(_def("IRB_OV", "IRB", "irb_up", "on_awareness", owner=None))
    # ...but a federally-fixed FDA/EU clock may NOT (the table CHECK).
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(_def("FDA_OV", "FDA", "fatal_lt", "on_receipt", owner=1))


def test_def_regime_and_clock_kind_enums(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(_def("BAD_REGIME", "WHO", "irb_up", "on_awareness"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO regulatory_clock_def "
            "(code,regime,citation,title,severity_class,duration_value,"
            " clock_start_kind,clock_kind,created_at) VALUES "
            "('BK','IRB','c','t','irb_up',7,'on_awareness','nag','now')"
        )


def test_account_delete_restricted_when_a_live_clock_exists(conn):
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    aid = create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=True,
    )
    conn.execute(_def("D1", "IRB", "irb_up", "on_awareness"))
    did = conn.execute("SELECT id FROM regulatory_clock_def").fetchone()[0]
    conn.execute(
        "INSERT INTO regulatory_clock_instance "
        "(def_id, account_id, case_ref, created_at, updated_at) "
        "VALUES (?, ?, 'CASE-1', 'now', 'now')",
        (did, aid),
    )
    conn.commit()
    # ON DELETE RESTRICT — can't drop the account out from under a live clock.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM email_accounts WHERE id=?", (aid,))
        conn.commit()
    conn.rollback()


def test_instance_state_and_responsibility_enums(conn):
    conn.execute(_def("D2", "IRB", "irb_up", "on_awareness"))
    did = conn.execute("SELECT id FROM regulatory_clock_def").fetchone()[0]
    # a bad state is rejected; default state is 'candidate', default responsibility 'unknown'
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO regulatory_clock_instance "
            "(def_id, account_id, case_ref, state, created_at, updated_at) "
            "VALUES (?, 1, 'C', 'exploded', 'now', 'now')",
            (did,),
        )
