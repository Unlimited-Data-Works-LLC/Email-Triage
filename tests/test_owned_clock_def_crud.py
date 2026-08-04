"""Operator-OWNED clock-def CRUD write helpers (operator 2026-06-15) — the
FATAL-must-fix safety properties from the pre-build SME panel:

 * create FORCES config_owner_account_id (never NULL) + a namespaced OWN_ code
   (an owned row can never masquerade as base catalog);
 * update keeps config_owner_account_id + code STRUCTURALLY IMMUTABLE (the
   relabel/promote vector) and never-clobbers a blank duration (no silent
   disarm of a live legal clock);
 * delete REFUSES while a live (non-terminal) instance references the def;
 * base/FDA/EU defs are never editable/deletable via these helpers.
"""

from __future__ import annotations

import pytest

from email_triage.db import regulatory_clock as rc


def _conn():
    from _db_tracking import track
    from email_triage.web.db import init_db
    c = track(init_db(":memory:"))
    rc.seed_regulatory_clock_catalog(c)
    return c


def _acct(conn, name="Clinic"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    uid = int(conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
        (f"{name}@x.com", name, "user", now),
    ).lastrowid)
    aid = int(conn.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (uid, name, "imap", "{}", now, now),
    ).lastrowid)
    return uid, aid


def _payload(**over):
    base = {
        "title": "Our IRB UP report", "regime": "IRB", "severity_class": "irb_up",
        "clock_kind": "escalating", "duration_value": 0,
        "duration_unit": "working_day", "clock_start_kind": "on_awareness",
        "calendar_tz": "America/New_York", "escalation_lead_pcts": [0, 50],
    }
    base.update(over)
    return base


def test_create_forces_owner_and_namespaced_code():
    conn = _conn()
    try:
        uid, aid = _acct(conn)
        did = rc.create_owned_clock_def(
            conn, account_id=aid, actor_user_id=uid, payload=_payload())
        row = conn.execute(
            "SELECT * FROM regulatory_clock_def WHERE id=?", (did,)).fetchone()
        assert row["config_owner_account_id"] == aid          # never NULL
        assert row["code"].startswith(f"OWN_{aid}_")          # namespaced
        assert row["duration_overridable"] == 1
        assert row["regime"] == "IRB"
    finally:
        conn.close()


def test_owned_code_cannot_collide_with_base():
    # No base catalog code starts with OWN_, so an owned code can never be
    # reachable by the base-only seed re-assert.
    for entry in rc._REGULATORY_CLOCK_SEED_CATALOG:
        assert not entry["code"].startswith("OWN_")


def test_update_owner_and_code_are_immutable_relabel_blocked():
    conn = _conn()
    try:
        uid, aid = _acct(conn)
        did = rc.create_owned_clock_def(
            conn, account_id=aid, actor_user_id=uid, payload=_payload())
        before = conn.execute(
            "SELECT code, config_owner_account_id FROM regulatory_clock_def "
            "WHERE id=?", (did,)).fetchone()
        # Attempt to relabel: null the owner + change code + change regime.
        rc.update_owned_clock_def(
            conn, def_id=did, account_id=aid, actor_user_id=uid,
            payload=_payload(title="Renamed", config_owner_account_id=None,
                             code="FDA_IND_7D_INFO"))
        after = conn.execute(
            "SELECT code, config_owner_account_id, title FROM "
            "regulatory_clock_def WHERE id=?", (did,)).fetchone()
        assert after["config_owner_account_id"] == aid        # NOT nulled
        assert after["code"] == before["code"]                # NOT relabeled
        assert after["title"] == "Renamed"                    # the real edit applied
    finally:
        conn.close()


def test_update_never_clobbers_blank_duration():
    conn = _conn()
    try:
        uid, aid = _acct(conn)
        did = rc.create_owned_clock_def(
            conn, account_id=aid, actor_user_id=uid,
            payload=_payload(duration_value=10),
            working_day_calendar_configured=True)
        # Edit with a BLANK duration — must PRESERVE 10 (not disarm to 0).
        rc.update_owned_clock_def(
            conn, def_id=did, account_id=aid, actor_user_id=uid,
            payload={"title": "Updated", "duration_value": ""},
            working_day_calendar_configured=True)
        row = conn.execute(
            "SELECT duration_value, title FROM regulatory_clock_def WHERE id=?",
            (did,)).fetchone()
        assert row["duration_value"] == 10                    # preserved, not 0
        assert row["title"] == "Updated"
    finally:
        conn.close()


def test_base_def_not_editable_or_deletable():
    conn = _conn()
    try:
        uid, aid = _acct(conn)
        base_id = conn.execute(
            "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
        ).fetchone()["id"]
        with pytest.raises(rc.ClockDefValidationError):
            rc.update_owned_clock_def(conn, def_id=base_id, account_id=aid,
                                      actor_user_id=uid, payload=_payload())
        with pytest.raises(rc.ClockDefValidationError):
            rc.delete_owned_clock_def(conn, def_id=base_id, account_id=aid,
                                      actor_user_id=uid)
    finally:
        conn.close()


def test_cross_account_edit_refused():
    conn = _conn()
    try:
        uid_a, aid_a = _acct(conn, "A")
        uid_b, aid_b = _acct(conn, "B")
        did = rc.create_owned_clock_def(
            conn, account_id=aid_a, actor_user_id=uid_a, payload=_payload())
        # Account B cannot edit/delete account A's owned def.
        with pytest.raises(rc.ClockDefValidationError):
            rc.update_owned_clock_def(conn, def_id=did, account_id=aid_b,
                                      actor_user_id=uid_b, payload=_payload())
        with pytest.raises(rc.ClockDefValidationError):
            rc.delete_owned_clock_def(conn, def_id=did, account_id=aid_b,
                                      actor_user_id=uid_b)
    finally:
        conn.close()


def test_delete_refused_while_any_instance_references_it():
    conn = _conn()
    try:
        uid, aid = _acct(conn)
        # A never-used def deletes cleanly.
        fresh = rc.create_owned_clock_def(
            conn, account_id=aid, actor_user_id=uid, payload=_payload(title="Fresh"))
        assert rc.delete_owned_clock_def(
            conn, def_id=fresh, account_id=aid, actor_user_id=uid) is True

        # A used def (ANY instance — even terminal) is refused: the FK has no
        # ON DELETE rule, and history must survive. (Matches the FK; a live-only
        # check would pass here then fail the FK at runtime.)
        did = rc.create_owned_clock_def(
            conn, account_id=aid, actor_user_id=uid, payload=_payload())
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO regulatory_clock_instance "
            "(def_id, account_id, case_ref, state, responsibility, "
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (did, aid, "CASE-001", "dismissed", "i_submit", now, now),  # TERMINAL
        )
        conn.commit()
        with pytest.raises(rc.ClockDefValidationError):
            rc.delete_owned_clock_def(conn, def_id=did, account_id=aid,
                                      actor_user_id=uid)
    finally:
        conn.close()


def test_list_owned_is_account_scoped():
    conn = _conn()
    try:
        uid_a, aid_a = _acct(conn, "A")
        uid_b, aid_b = _acct(conn, "B")
        rc.create_owned_clock_def(conn, account_id=aid_a, actor_user_id=uid_a,
                                  payload=_payload(title="A1"))
        rc.create_owned_clock_def(conn, account_id=aid_b, actor_user_id=uid_b,
                                  payload=_payload(title="B1"))
        a_defs = rc.list_owned_clock_defs(conn, aid_a)
        assert {d["title"] for d in a_defs} == {"A1"}         # never B's
    finally:
        conn.close()
