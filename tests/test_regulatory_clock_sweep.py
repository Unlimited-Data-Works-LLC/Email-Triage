""" Phase 4a — escalation sweep pins.

State is DERIVED from the anchor + deadline each tick (idempotent / self-healing
across restarts). breached is a chained legal event; at_risk is operational.
"""
from __future__ import annotations

import pytest

from email_triage.db.audit import verify_audit_chain
from email_triage.db.regulatory_clock import (
    _due_escalation_rung,
    _sweep_decide,
    build_escalation_notification,
    get_clock_instance,
    sweep_regulatory_clocks,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track

NOW = "2026-06-10T00:00:00+00:00"


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


# ---- pure decide ----------------------------------------------------------

def test_decide_breached_past_deadline():
    assert _sweep_decide(
        deadline_at="2026-06-09T00:00:00+00:00", clock_start_at=None,
        lead_pcts_json="[80]", current_state="running", now_iso=NOW,
    ) == "breached"


def test_decide_breach_idempotent():
    assert _sweep_decide(
        deadline_at="2026-06-09T00:00:00+00:00", clock_start_at=None,
        lead_pcts_json="[80]", current_state="breached", now_iso=NOW,
    ) is None


def test_decide_at_risk_within_24h():
    assert _sweep_decide(
        deadline_at="2026-06-10T12:00:00+00:00", clock_start_at=None,
        lead_pcts_json="[80]", current_state="running", now_iso=NOW,
    ) == "at_risk"


def test_decide_at_risk_past_lead_pct():
    # start 06-01, deadline 06-11 (10d). NOW 06-10 → 90% elapsed >= 80 lead.
    assert _sweep_decide(
        deadline_at="2026-06-11T00:00:00+00:00",
        clock_start_at="2026-06-01T00:00:00+00:00",
        lead_pcts_json="[80]", current_state="running", now_iso=NOW,
    ) == "at_risk"


def test_decide_no_change_when_far_from_deadline():
    assert _sweep_decide(
        deadline_at="2026-06-25T00:00:00+00:00",
        clock_start_at="2026-06-09T00:00:00+00:00",
        lead_pcts_json="[80]", current_state="running", now_iso=NOW,
    ) is None


def test_decide_at_risk_only_from_running():
    # an acked clock is page-silenced: no at_risk transition (but it can breach)
    assert _sweep_decide(
        deadline_at="2026-06-10T12:00:00+00:00", clock_start_at=None,
        lead_pcts_json="[80]", current_state="acked", now_iso=NOW,
    ) is None
    assert _sweep_decide(
        deadline_at="2026-06-09T00:00:00+00:00", clock_start_at=None,
        lead_pcts_json="[80]", current_state="acked", now_iso=NOW,
    ) == "breached"


# ---- the sweep over real rows ---------------------------------------------

def _armed(conn, aid, did, *, state, deadline_at, clock_start_at=None):
    conn.execute(
        "INSERT INTO regulatory_clock_instance "
        "(def_id, account_id, case_ref, state, clock_start_at, deadline_at, "
        " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'now', 'now')",
        (did, aid, f"C-{deadline_at}", state, clock_start_at, deadline_at),
    )
    return conn.execute(
        "SELECT id FROM regulatory_clock_instance ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]


@pytest.fixture
def acct_def(conn):
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
        "SELECT id FROM regulatory_clock_def WHERE code='FDA_IND_7D_INFO'"
    ).fetchone()[0]
    return aid, did


def test_sweep_transitions_and_counts(conn, acct_def):
    aid, did = acct_def
    past = _armed(conn, aid, did, state="running",
                  deadline_at="2026-06-09T00:00:00+00:00")
    near = _armed(conn, aid, did, state="running",
                  deadline_at="2026-06-10T06:00:00+00:00")
    far = _armed(conn, aid, did, state="running",
                 deadline_at="2026-06-30T00:00:00+00:00",
                 clock_start_at="2026-06-09T00:00:00+00:00")
    conn.commit()
    res = sweep_regulatory_clocks(conn, now_iso=NOW)
    assert res["breached"] == 1 and res["at_risk"] == 1
    assert get_clock_instance(conn, past)["state"] == "breached"
    assert get_clock_instance(conn, near)["state"] == "at_risk"
    assert get_clock_instance(conn, far)["state"] == "running"


def test_sweep_is_idempotent(conn, acct_def):
    aid, did = acct_def
    _armed(conn, aid, did, state="running",
           deadline_at="2026-06-09T00:00:00+00:00")
    conn.commit()
    sweep_regulatory_clocks(conn, now_iso=NOW)
    res2 = sweep_regulatory_clocks(conn, now_iso=NOW)  # second tick
    assert res2["breached"] == 0 and res2["at_risk"] == 0  # nothing new


def _escalating_def(conn):
    conn.execute(
        "INSERT INTO regulatory_clock_def "
        "(code, regime, citation, title, severity_class, clock_kind, "
        " duration_value, duration_unit, clock_start_kind, escalation_lead_pcts,"
        " created_at) VALUES "
        "('ESC','INTERNAL','SOP','t','internal','escalating',10,"
        " 'calendar_day','on_determination','[80]','now')"
    )
    return conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='ESC'"
    ).fetchone()[0]


def test_due_escalation_rung_dedups():
    assert _due_escalation_rung("at_risk", 0) == 1
    assert _due_escalation_rung("at_risk", 1) is None      # already fired
    assert _due_escalation_rung("breached", 1) == 3        # escalate to breach rung
    assert _due_escalation_rung("breached", 3) is None     # already fired
    assert _due_escalation_rung("running", 0) is None


def test_sweep_fires_escalation_and_dedups(conn, acct_def):
    aid, _ = acct_def
    did = _escalating_def(conn)
    iid = _armed(conn, aid, did, state="running",
                 deadline_at="2026-06-10T06:00:00+00:00")  # within 24h → at_risk
    conn.commit()
    res = sweep_regulatory_clocks(conn, now_iso=NOW)
    assert res["at_risk"] == 1 and res["escalated"] == 1
    ev = conn.execute(
        "SELECT event_kind, escalation_rung, delivered_to_ref "
        "FROM regulatory_clock_event WHERE instance_id=? "
        "AND event_kind='escalated'", (iid,)
    ).fetchone()
    assert ev["escalation_rung"] == 1
    assert ev["delivered_to_ref"]  # the owner user-id (non-PHI)
    # re-sweep: the rung was already fired → no re-page (dedup)
    res2 = sweep_regulatory_clocks(conn, now_iso=NOW)
    assert res2["escalated"] == 0


def test_escalation_notification_is_phi_free_and_advisory():
    note = build_escalation_notification(
        label="IRB/HRPO unanticipated-problem report",
        deadline_at="2026-06-15T00:00:00+00:00", state="at_risk",
        deep_link="https://x/compliance", now_iso=NOW,
    )
    assert "IRB/HRPO" in note["subject"]
    assert "5 day" in note["body"]                      # due in 5 days
    assert "verify against your SOP" in note["body"]    # advisory copy
    blob = (note["subject"] + note["body"]).lower()
    assert "case_ref" not in blob and "case-" not in blob  # no PHI grouping key


def test_escalation_notification_overdue_framing():
    note = build_escalation_notification(
        label="x", deadline_at="2026-06-09T00:00:00+00:00", state="breached",
        deep_link="d", now_iso=NOW,
    )
    assert "OVERDUE" in note["subject"]
    assert "OVERDUE by 1 day" in note["body"]


def test_sweep_returns_phi_free_owner_notification(conn, acct_def):
    aid, _ = acct_def
    did = _escalating_def(conn)
    _armed(conn, aid, did, state="running",
           deadline_at="2026-06-10T06:00:00+00:00")
    conn.commit()
    res = sweep_regulatory_clocks(conn, now_iso=NOW)
    assert len(res["notifications"]) == 1
    n = res["notifications"][0]
    assert n["to_addr"] == "u@x"        # the account owner
    assert n["label"] == "t"            # the def TITLE (non-PHI), not case_ref
    assert "case_ref" not in n          # the PHI grouping key is NOT in the spec


def test_informational_clock_never_escalates(conn, acct_def):
    aid, did = acct_def  # FDA_IND_7D_INFO (informational)
    _armed(conn, aid, did, state="running",
           deadline_at="2026-06-09T00:00:00+00:00")  # breaches
    conn.commit()
    res = sweep_regulatory_clocks(conn, now_iso=NOW)
    assert res["breached"] == 1
    assert res["escalated"] == 0  # informational receipts never escalate
    n_esc = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_event WHERE event_kind='escalated'"
    ).fetchone()[0]
    assert n_esc == 0


def test_breach_chains_a_legal_event(conn, acct_def):
    aid, did = acct_def
    iid = _armed(conn, aid, did, state="running",
                 deadline_at="2026-06-09T00:00:00+00:00")
    conn.commit()
    sweep_regulatory_clocks(conn, now_iso=NOW)
    ev = conn.execute(
        "SELECT event_kind, row_hash, actor_user_id FROM regulatory_clock_event "
        "WHERE instance_id=? ORDER BY id DESC LIMIT 1", (iid,)
    ).fetchone()
    assert ev["event_kind"] == "breached"
    assert ev["actor_user_id"] is None     # system-derived
    assert ev["row_hash"]                  # chained
    assert verify_audit_chain(conn, "regulatory_clock_event")["intact"] is True
