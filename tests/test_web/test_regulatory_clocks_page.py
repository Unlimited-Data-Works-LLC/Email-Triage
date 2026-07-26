""" Phase 4d-i — the user-facing /clocks page (surfacing).

Tests the VIEW (StrictUndefined render + label assert), not just the gatherer —
the binding "test the view" rule. HIPAA-minimal: no case_ref / raw_deadline_phrase.
"""
from __future__ import annotations

from email_triage.db.regulatory_clock import (
    create_clock_candidate,
    list_compliance_clocks,
)
from email_triage.web.db import create_email_account


def _seed_clock(db, user_id):
    aid = create_email_account(
        db, user_id=user_id, name="Lupus study mailbox",
        provider_type="imap", config={"account": "pi@site.example"},
        hipaa=True,
    )
    did = db.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        db, def_id=did, account_id=aid, case_ref="SECRET-CASE-REF-001",
        responsibility="i_submit",
    )
    return aid, iid


def test_gatherer_is_hipaa_minimal(db, regular_user):
    _seed_clock(db, regular_user["id"])
    clocks = list_compliance_clocks(db, user_id=regular_user["id"])
    assert len(clocks) == 1
    c = clocks[0]
    assert c["label"] == "IRB/HRPO unanticipated-problem report — site obligation"
    assert c["account_name"] == "Lupus study mailbox"     # name, not bare id
    # HIPAA-minimal: the PHI grouping key + deadline phrase are NOT in the view
    assert "case_ref" not in c
    assert "raw_deadline_phrase" not in c
    assert "SECRET-CASE-REF-001" not in str(c)


def test_gatherer_scopes_to_own_accounts(db, regular_user):
    # a clock on ANOTHER user's account must not appear in this user's view
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('other@x','O','user','now')"
    )
    other = db.execute(
        "SELECT id FROM users WHERE email='other@x'"
    ).fetchone()[0]
    _seed_clock(db, other)
    assert list_compliance_clocks(db, user_id=regular_user["id"]) == []


def test_clocks_page_renders_under_strict_undefined(
    client, db, regular_user, user_cookies, strict_undefined_templates,
):
    _seed_clock(db, regular_user["id"])
    resp = client.get("/clocks", cookies=user_cookies)
    assert resp.status_code == 200, (
        "/clocks hit a Jinja UndefinedError under StrictUndefined — a template "
        "reads an attribute the handler never provides. Body: " + resp.text[:200]
    )
    # the label renders; the PHI case_ref does NOT
    assert "unanticipated-problem" in resp.text
    assert "Lupus study mailbox" in resp.text
    assert "SECRET-CASE-REF-001" not in resp.text
    assert "verify each against your SOP" in resp.text  # advisory copy


def test_clocks_page_empty_state_renders(
    client, regular_user, user_cookies, strict_undefined_templates,
):
    resp = client.get("/clocks", cookies=user_cookies)
    assert resp.status_code == 200
    assert "No active regulatory clocks" in resp.text


def test_disposition_ownership_gate_refuses_non_owner(
    client, db, regular_user, user_cookies,
):
    # PD#9 — a clock owned by ANOTHER user must not be actionable by this user
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('other2@x','O2','user','now')"
    )
    other = db.execute(
        "SELECT id FROM users WHERE email='other2@x'"
    ).fetchone()[0]
    _aid, iid = _seed_clock(db, other)
    db.commit()
    resp = client.post(f"/clocks/{iid}/ack", cookies=user_cookies)
    assert resp.status_code == 403  # refused at the actuator, before any write
    state = db.execute(
        "SELECT state FROM regulatory_clock_instance WHERE id=?", (iid,)
    ).fetchone()[0]
    assert state == "candidate"  # unchanged


def test_dismiss_action_works_for_owner(client, db, regular_user, user_cookies):
    _aid, iid = _seed_clock(db, regular_user["id"])
    db.commit()
    resp = client.post(f"/clocks/{iid}/dismiss", cookies=user_cookies)
    assert resp.status_code == 200
    assert 'id="clocks-table"' in resp.text  # the refreshed fragment
    state = db.execute(
        "SELECT state FROM regulatory_clock_instance WHERE id=?", (iid,)
    ).fetchone()[0]
    assert state == "dismissed"


def test_ack_action_works_for_owner(client, db, regular_user, user_cookies):
    _aid, iid = _seed_clock(db, regular_user["id"])
    db.execute(
        "UPDATE regulatory_clock_instance SET state='running' WHERE id=?", (iid,)
    )
    db.commit()
    resp = client.post(f"/clocks/{iid}/ack", cookies=user_cookies)
    assert resp.status_code == 200
    state = db.execute(
        "SELECT state FROM regulatory_clock_instance WHERE id=?", (iid,)
    ).fetchone()[0]
    assert state == "acked"
