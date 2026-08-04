""" Phase 2 — clock instance lifecycle + state-machine pins.

Propose-then-confirm, write-once anchors, the responsibility arming gate, and
correction-as-event — each transition atomic with its chained audit event. The
autouse conftest provisions the test HMAC key so the chained emits succeed.
"""
from __future__ import annotations

import pytest

from email_triage.db.audit import verify_audit_chain
from email_triage.db.regulatory_clock import (
    ClockStateError,
    ack_clock,
    confirm_reportable,
    correct_determination,
    create_clock_candidate,
    dismiss_clock,
    get_clock_instance,
    note_informational_receipt,
    record_awareness,
    submit_clock,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


@pytest.fixture
def account(conn):
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    aid = create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=True,
    )
    return uid, aid


def _escalating_def(conn, *, code="TEST_ESC", duration=15):
    """An escalating, on_determination, calendar_day def that CAN arm in Phase 2
    (the seeded IRB clock is working_day + sentinel-0, which can't)."""
    conn.execute(
        "INSERT INTO regulatory_clock_def "
        "(code, regime, citation, title, severity_class, clock_kind, "
        " duration_value, duration_unit, clock_start_kind, escalation_lead_pcts, "
        " created_at) VALUES "
        "(?, 'INTERNAL', 'site SOP', 't', 'internal', 'escalating', ?, "
        " 'calendar_day', 'on_determination', '[80]', 'now')",
        (code, duration),
    )
    return conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code=?", (code,)
    ).fetchone()[0]


def _fda_def_id(conn):
    return conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='FDA_IND_7D_INFO'"
    ).fetchone()[0]


def test_create_candidate_emits_detected(conn, account):
    _uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="CASE-1",
        responsibility="i_submit",
    )
    inst = get_clock_instance(conn, iid)
    assert inst["state"] == "candidate"
    assert inst["deadline_at"] is None
    ev = conn.execute(
        "SELECT event_kind, row_hash FROM regulatory_clock_event "
        "WHERE instance_id=?", (iid,),
    ).fetchone()
    assert ev["event_kind"] == "detected"
    assert ev["row_hash"]  # chained


def test_responsibility_gate_arms_only_i_submit(conn, account):
    _uid, aid = account
    did = _escalating_def(conn)
    # i_submit → arms to running with a computed deadline
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-ARM",
        responsibility="i_submit",
    )
    state = confirm_reportable(conn, instance_id=iid, actor_user_id=account[0])
    assert state == "running"
    assert get_clock_instance(conn, iid)["deadline_at"] is not None
    # sponsor_submits → stays advisory candidate (no ladder)
    iid2 = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-NOARM",
        responsibility="sponsor_submits",
    )
    state2 = confirm_reportable(conn, instance_id=iid2, actor_user_id=account[0])
    assert state2 == "candidate"


def test_unconfigured_irb_sentinel_does_not_arm(conn, account):
    _uid, aid = account
    irb = conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        conn, def_id=irb, account_id=aid, case_ref="C-IRB",
        responsibility="i_submit",
    )
    record_awareness(conn, instance_id=iid, actor_user_id=account[0])
    # duration sentinel 0 + working_day → not computable → stays candidate
    state = confirm_reportable(conn, instance_id=iid, actor_user_id=account[0])
    assert state == "candidate"
    assert get_clock_instance(conn, iid)["deadline_at"] is None


def test_awareness_is_write_once(conn, account):
    _uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-AW",
    )
    record_awareness(conn, instance_id=iid, actor_user_id=account[0],
                     awareness_at="2026-06-01T00:00:00+00:00")
    with pytest.raises(ClockStateError):
        record_awareness(conn, instance_id=iid, actor_user_id=account[0],
                         awareness_at="2026-06-02T00:00:00+00:00")
    # the anchor was NOT overwritten (atomic rollback)
    assert get_clock_instance(conn, iid)["awareness_at"] == \
        "2026-06-01T00:00:00+00:00"


def test_write_once_violation_rolls_back_no_orphan_event(conn, account):
    _uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(conn, def_id=did, account_id=aid, case_ref="C-RB")
    record_awareness(conn, instance_id=iid, actor_user_id=account[0])
    n_before = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_event WHERE instance_id=?", (iid,)
    ).fetchone()[0]
    with pytest.raises(ClockStateError):
        record_awareness(conn, instance_id=iid, actor_user_id=account[0])
    n_after = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_event WHERE instance_id=?", (iid,)
    ).fetchone()[0]
    assert n_after == n_before  # the rolled-back txn emitted NO awareness_set event


def test_informational_receipt_auto_notes(conn, account):
    _uid, aid = account
    fda = _fda_def_id(conn)
    iid = create_clock_candidate(
        conn, def_id=fda, account_id=aid, case_ref="C-FDA",
        clock_start_at="2026-06-01T00:00:00+00:00",
    )
    deadline = note_informational_receipt(conn, instance_id=iid)
    assert deadline.startswith("2026-06-08")  # +7 calendar days
    assert get_clock_instance(conn, iid)["state"] == "running"
    # an escalating clock rejects the informational path
    did = _escalating_def(conn)
    iid2 = create_clock_candidate(conn, def_id=did, account_id=aid, case_ref="C-E")
    with pytest.raises(ClockStateError):
        note_informational_receipt(conn, instance_id=iid2)


def test_informational_receipt_is_idempotent(conn, account):
    # SF-1: a replayed sponsor notice must NOT emit a duplicate `determined`.
    _uid, aid = account
    fda = _fda_def_id(conn)
    iid = create_clock_candidate(
        conn, def_id=fda, account_id=aid, case_ref="C-IDEM",
        clock_start_at="2026-06-01T00:00:00+00:00",
    )
    d1 = note_informational_receipt(conn, instance_id=iid)
    d2 = note_informational_receipt(conn, instance_id=iid)  # replay
    assert d1 == d2
    determined = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_event "
        "WHERE instance_id=? AND event_kind='determined'", (iid,)
    ).fetchone()[0]
    assert determined == 1  # not padded


def test_chain_failure_rolls_back_the_whole_transition(conn, account):
    # SF-2 fail-closed atomicity pin: if the chained emit fails (no HMAC key),
    # the state-flip + anchor must roll back — no half-stamped legal clock.
    from email_triage.db.audit import (
        _clear_hmac_keys_for_test,
        _set_hmac_key_for_test,
    )
    uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-FAIL",
        responsibility="i_submit",
    )
    before = get_clock_instance(conn, iid)
    _clear_hmac_keys_for_test()
    try:
        with pytest.raises(Exception):
            confirm_reportable(conn, instance_id=iid, actor_user_id=uid)
    finally:
        _set_hmac_key_for_test(b"H-02a-test-key-32-bytes-32bytes!", version=0)
    after = get_clock_instance(conn, iid)
    assert after["state"] == before["state"] == "candidate"  # rolled back
    assert after["determination_at"] is None                 # anchor NOT stamped
    assert after["deadline_at"] is None


def test_ack_then_submit_discharges(conn, account):
    uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-AS",
        responsibility="i_submit",
    )
    confirm_reportable(conn, instance_id=iid, actor_user_id=uid)
    assert ack_clock(conn, instance_id=iid, actor_user_id=uid) == "acked"
    assert submit_clock(conn, instance_id=iid, actor_user_id=uid,
                        evidence_ref="IRB-2026-001") == "submitted"
    inst = get_clock_instance(conn, iid)
    assert inst["state"] == "submitted"
    assert inst["submission_evidence_ref"] == "IRB-2026-001"
    # a terminal clock rejects further disposition
    with pytest.raises(ClockStateError):
        submit_clock(conn, instance_id=iid, actor_user_id=uid)


def test_disposition_requires_human_actor(conn, account):
    _uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(conn, def_id=did, account_id=aid, case_ref="C-H")
    with pytest.raises(ValueError):
        confirm_reportable(conn, instance_id=iid, actor_user_id=None)


def test_correction_is_append_only_event_preserves_anchor(conn, account):
    uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-CORR",
        responsibility="i_submit",
    )
    confirm_reportable(conn, instance_id=iid, actor_user_id=uid,
                       determination_at="2026-06-01T00:00:00+00:00")
    orig = get_clock_instance(conn, iid)["determination_at"]
    correct_determination(
        conn, instance_id=iid, actor_user_id=uid,
        new_determination_at="2026-06-03T00:00:00+00:00",
        reason="duplicate of already-reported case",
    )
    inst = get_clock_instance(conn, iid)
    # the ORIGINAL write-once anchor is preserved (Part 11)
    assert inst["determination_at"] == orig == "2026-06-01T00:00:00+00:00"
    # but the derived deadline recomputed from the corrected value (+15d)
    assert inst["deadline_at"].startswith("2026-06-18")
    kinds = [r[0] for r in conn.execute(
        "SELECT event_kind FROM regulatory_clock_event WHERE instance_id=? "
        "ORDER BY id", (iid,)).fetchall()]
    assert "determination_corrected" in kinds


def test_full_lifecycle_chain_verifies(conn, account):
    uid, aid = account
    did = _escalating_def(conn)
    iid = create_clock_candidate(
        conn, def_id=did, account_id=aid, case_ref="C-V",
        responsibility="i_submit",
    )
    confirm_reportable(conn, instance_id=iid, actor_user_id=uid)
    ack_clock(conn, instance_id=iid, actor_user_id=uid)
    submit_clock(conn, instance_id=iid, actor_user_id=uid, evidence_ref="F-1")
    result = verify_audit_chain(conn, "regulatory_clock_event")
    assert result["intact"] is True
    assert result["chain_length"] >= 4  # detected, determined, acked, submitted
