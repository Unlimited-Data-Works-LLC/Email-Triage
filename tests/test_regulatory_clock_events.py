""" — regulatory_clock_event chained-emitter behavior pins.

``regulatory_clock_event`` is a DEDICATED HMAC-chained audit table (v47). These
pins prove the emitters (`record_clock_event` / `record_clock_ack`) write a real
tamper-evident chain row, that consecutive events link, that the chain verifies,
and that the human-disposition guard fails closed. The count-agnostic inverse-
INSERT + registry-consistency pins live in ``tests/test_audit_chain_pin.py`` and
extend to this table automatically once it is in ``_AUDIT_CHAIN_CANONICAL_FIELDS``.

The autouse conftest fixture provisions the test HMAC key, so ``_chain_insert``
is satisfied (a missing key would RuntimeError — fail-closed, Directive 12).
"""
from __future__ import annotations

import pytest

from email_triage.db.audit import (
    record_clock_ack,
    record_clock_event,
    verify_audit_chain,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


def _make_instance(conn):
    """A real (user, account, def, instance) chain so the event FK is satisfied."""
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    aid = create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=True,
    )
    did = conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO regulatory_clock_instance "
        "(def_id, account_id, case_ref, created_at, updated_at) "
        "VALUES (?, ?, 'CASE-1', 'now', 'now')",
        (did, aid),
    )
    iid = conn.execute(
        "SELECT id FROM regulatory_clock_instance"
    ).fetchone()[0]
    conn.commit()
    return uid, iid


def test_event_writes_a_chained_row(conn):
    _uid, iid = _make_instance(conn)
    rid = record_clock_event(conn, instance_id=iid, event_kind="detected")
    row = conn.execute(
        "SELECT * FROM regulatory_clock_event WHERE id=?", (rid,)
    ).fetchone()
    assert row["event_kind"] == "detected"
    assert row["row_hash"]                    # non-empty → actually chained
    assert row["hash_alg"] == "hmac-sha256-v2"
    assert row["master_key_version"] is not None


def test_consecutive_events_link_and_chain_verifies(conn):
    uid, iid = _make_instance(conn)
    r1 = record_clock_event(conn, instance_id=iid, event_kind="detected")
    r2 = record_clock_ack(
        conn, instance_id=iid, event_kind="determined",
        actor_user_id=uid, from_state="candidate", to_state="running",
    )
    h1 = conn.execute(
        "SELECT row_hash FROM regulatory_clock_event WHERE id=?", (r1,)
    ).fetchone()[0]
    p2 = conn.execute(
        "SELECT prev_hash FROM regulatory_clock_event WHERE id=?", (r2,)
    ).fetchone()[0]
    assert p2 == h1                            # row 2 links to row 1
    result = verify_audit_chain(conn, "regulatory_clock_event")
    assert result["intact"] is True
    assert result["chain_length"] == 2


def test_tamper_is_detected(conn):
    uid, iid = _make_instance(conn)
    record_clock_event(conn, instance_id=iid, event_kind="detected")
    rid = record_clock_ack(
        conn, instance_id=iid, event_kind="acked", actor_user_id=uid,
    )
    # mutate a HASHED field directly (the insider-with-DB-write threat)
    conn.execute(
        "UPDATE regulatory_clock_event SET event_kind='dismissed' WHERE id=?",
        (rid,),
    )
    conn.commit()
    result = verify_audit_chain(conn, "regulatory_clock_event")
    assert result["intact"] is False
    assert result["first_break_id"] == rid


def test_unknown_event_kind_is_rejected(conn):
    _uid, iid = _make_instance(conn)
    with pytest.raises(ValueError):
        record_clock_event(conn, instance_id=iid, event_kind="exploded")


def test_ack_requires_a_human_actor(conn):
    _uid, iid = _make_instance(conn)
    # a human disposition with no named human is a defect — fail closed
    with pytest.raises(ValueError):
        record_clock_ack(
            conn, instance_id=iid, event_kind="acked", actor_user_id=None,
        )


def test_ack_rejects_a_system_only_event_kind(conn):
    uid, iid = _make_instance(conn)
    # `escalated`/`detected`/`breached` are system transitions, not dispositions
    with pytest.raises(ValueError):
        record_clock_ack(
            conn, instance_id=iid, event_kind="escalated", actor_user_id=uid,
        )
