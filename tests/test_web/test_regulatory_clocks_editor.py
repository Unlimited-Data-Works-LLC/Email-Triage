"""/profile/regulatory-clocks — the operator-OWNED IRB/INTERNAL deadline-template
editor (operator 2026-06-15). Rendered-view + CRUD round-trip + the actuator
gate (can_administer_account) + the governance audit (readable account_id).
"""

from __future__ import annotations

from datetime import datetime, timezone


def _make_account(db, user_id: int, name: str, *, hipaa: bool = False) -> int:
    from email_triage.db.accounts import create_email_account
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "imap.example.com", "username": f"{name}@example.com"},
        hipaa=hipaa, is_active=True,
    )


class TestRegulatoryClocksEditor:
    def test_page_renders_with_builtins(self, client, user_cookies, regular_user, db):
        aid = _make_account(db, regular_user["id"], "clinic")
        resp = client.get(
            f"/profile/regulatory-clocks?account_id={aid}", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Deadline reminders" in resp.text
        # Built-in reference section renders the FDA/IRB rows.
        assert "Built-in deadlines" in resp.text
        assert "FDA" in resp.text

    def test_create_owned_template_round_trips(self, client, user_cookies, regular_user, db):
        aid = _make_account(db, regular_user["id"], "clinic")
        resp = client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(aid), "title": "Our IRB report",
                  "regime": "IRB", "duration_value": "0",
                  "duration_unit": "working_day", "ack_required": "1"},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303
        from email_triage.db.regulatory_clock import list_owned_clock_defs
        owned = list_owned_clock_defs(db, aid)
        assert len(owned) == 1
        assert owned[0]["title"] == "Our IRB report"
        assert owned[0]["config_owner_account_id"] == aid
        assert owned[0]["code"].startswith(f"OWN_{aid}_")
        # The page now lists it.
        page = client.get(
            f"/profile/regulatory-clocks?account_id={aid}", cookies=user_cookies).text
        assert "Our IRB report" in page

    def test_working_day_arming_without_calendar_is_bounced(
        self, client, user_cookies, regular_user, db,
    ):
        aid = _make_account(db, regular_user["id"], "clinic")
        resp = client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(aid), "title": "Bad", "regime": "IRB",
                  "duration_value": "10", "duration_unit": "working_day"},
            cookies=user_cookies, follow_redirects=False)
        # Re-rendered with the error (not a 303, not persisted).
        assert resp.status_code == 400
        assert "working-day calendar" in resp.text
        from email_triage.db.regulatory_clock import list_owned_clock_defs
        assert list_owned_clock_defs(db, aid) == []

    def test_calendar_day_arming_ok(self, client, user_cookies, regular_user, db):
        aid = _make_account(db, regular_user["id"], "clinic")
        resp = client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(aid), "title": "Cal", "regime": "IRB",
                  "duration_value": "15", "duration_unit": "calendar_day"},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303

    def test_update_never_clobbers_blank_duration(self, client, user_cookies, regular_user, db):
        aid = _make_account(db, regular_user["id"], "clinic")
        from email_triage.db.regulatory_clock import (
            create_owned_clock_def, list_owned_clock_defs,
        )
        did = create_owned_clock_def(
            db, account_id=aid, actor_user_id=regular_user["id"],
            payload={"title": "T", "regime": "IRB", "severity_class": "irb_up",
                     "clock_kind": "escalating", "duration_value": 12,
                     "duration_unit": "calendar_day", "clock_start_kind": "on_awareness",
                     "calendar_tz": "America/New_York", "escalation_lead_pcts": [0]})
        # Edit with a BLANK duration => preserves 12.
        resp = client.post(
            "/profile/regulatory-clocks/update",
            data={"account_id": str(aid), "def_id": str(did),
                  "regime": "IRB", "title": "Renamed", "duration_value": "",
                  "duration_unit": "calendar_day"},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303
        d = [x for x in list_owned_clock_defs(db, aid) if x["id"] == did][0]
        assert d["duration_value"] == 12       # preserved
        assert d["title"] == "Renamed"

    def test_delete_unused_template(self, client, user_cookies, regular_user, db):
        aid = _make_account(db, regular_user["id"], "clinic")
        from email_triage.db.regulatory_clock import (
            create_owned_clock_def, list_owned_clock_defs,
        )
        did = create_owned_clock_def(
            db, account_id=aid, actor_user_id=regular_user["id"],
            payload={"title": "Gone", "regime": "IRB", "severity_class": "irb_up",
                     "clock_kind": "escalating", "duration_value": 0,
                     "duration_unit": "working_day", "clock_start_kind": "on_awareness",
                     "calendar_tz": "America/New_York", "escalation_lead_pcts": []})
        resp = client.post(
            "/profile/regulatory-clocks/delete",
            data={"account_id": str(aid), "def_id": str(did)},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303
        assert list_owned_clock_defs(db, aid) == []

    def test_non_administered_account_refused(self, client, user_cookies, regular_user, db):
        # An account owned by SOMEONE ELSE — regular_user can't administer it.
        now = datetime.now(timezone.utc).isoformat()
        other_uid = int(db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
            ("other@x.com", "Other", "user", now)).lastrowid)
        db.commit()
        other_aid = _make_account(db, other_uid, "theirs")
        resp = client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(other_aid), "title": "Sneaky", "regime": "IRB",
                  "duration_value": "0", "duration_unit": "working_day"},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 403
        from email_triage.db.regulatory_clock import list_owned_clock_defs
        assert list_owned_clock_defs(db, other_aid) == []

    def test_escalation_ladder_round_trips(self, client, user_cookies, regular_user, db):
        """Finding C — the editor can set reminder rungs (the named purpose of
        the surface) and they round-trip to the stored ladder + re-render."""
        import json
        aid = _make_account(db, regular_user["id"], "clinic")
        resp = client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(aid), "title": "Laddered", "regime": "IRB",
                  "duration_value": "15", "duration_unit": "calendar_day",
                  "escalation_lead_pcts": ["50", "10"], "ack_required_submitted": "1",
                  "ack_required": "1"},
            cookies=user_cookies, follow_redirects=False)
        assert resp.status_code == 303
        from email_triage.db.regulatory_clock import list_owned_clock_defs
        d = list_owned_clock_defs(db, aid)[0]
        assert json.loads(d["escalation_lead_pcts"]) == [50, 10]
        # And the checkboxes pre-check on re-render.
        page = client.get(
            f"/profile/regulatory-clocks?account_id={aid}", cookies=user_cookies).text
        assert 'name="escalation_lead_pcts"' in page

    def test_ack_required_not_clobbered_without_marker(self, client, user_cookies, regular_user, db):
        """Finding B — a POST that omits the ack_required_submitted marker must
        NOT flip a stored ack_required off (the checkbox never-clobber trap)."""
        aid = _make_account(db, regular_user["id"], "clinic")
        from email_triage.db.regulatory_clock import (
            create_owned_clock_def, list_owned_clock_defs,
        )
        did = create_owned_clock_def(
            db, account_id=aid, actor_user_id=regular_user["id"],
            payload={"title": "T", "regime": "IRB", "severity_class": "irb_up",
                     "clock_kind": "escalating", "duration_value": 0,
                     "duration_unit": "working_day", "clock_start_kind": "on_awareness",
                     "calendar_tz": "America/New_York", "escalation_lead_pcts": [],
                     "ack_required": 1})
        # Edit with NO marker + NO ack checkbox (a stale/partial POST).
        client.post(
            "/profile/regulatory-clocks/update",
            data={"account_id": str(aid), "def_id": str(did),
                  "regime": "IRB", "title": "Renamed", "duration_unit": "working_day"},
            cookies=user_cookies, follow_redirects=False)
        d = [x for x in list_owned_clock_defs(db, aid) if x["id"] == did][0]
        assert d["ack_required"] == 1          # preserved, not flipped off

    def test_gate_deny_is_audited(self, client, user_cookies, regular_user, db):
        """Finding A — a denied (403) attempt on a non-administered account
        leaves a governance trail (outcome=denied)."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        other_uid = int(db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
            ("o2@x.com", "O2", "user", now)).lastrowid)
        db.commit()
        other_aid = _make_account(db, other_uid, "theirs2")
        client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(other_aid), "title": "X", "regime": "IRB",
                  "duration_value": "0", "duration_unit": "working_day"},
            cookies=user_cookies, follow_redirects=False)
        row = db.execute(
            "SELECT outcome, account_id FROM access_log "
            "WHERE route LIKE '/profile/regulatory-clocks/create%' "
            "AND outcome='denied' ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None                 # the deny WAS audited
        assert row["account_id"] == other_aid

    def test_non_numeric_def_id_does_not_500(
        self, client, user_cookies, regular_user, db,
    ):
        """ / run18  — a tampered (non-numeric) def_id must NOT 500.

        Pre-fix: ``int(form.get("def_id") or 0)`` raised an UNCAUGHT ValueError on
        "abc" (the enclosing ``except`` only catches ClockDefValidationError) →
        HTTP 500 on attacker input (§164.308(a)(7) availability). Now ``_safe_int``
        coerces it to 0, so the write helper's "template no longer exists"
        validation bounces it as a 400 re-render — a handled response, no crash.
        """
        aid = _make_account(db, regular_user["id"], "clinic")
        for action in ("update", "delete"):
            resp = client.post(
                f"/profile/regulatory-clocks/{action}",
                data={"account_id": str(aid), "def_id": "abc",
                      "regime": "IRB", "title": "X",
                      "duration_unit": "calendar_day"},
                cookies=user_cookies, follow_redirects=False)
            assert resp.status_code != 500, (
                f"{action} with a non-numeric def_id 500'd — the  regression"
            )
            # _safe_int("abc", 0) -> 0 -> "that template no longer exists" -> 400.
            assert resp.status_code == 400

    def test_governance_audit_written_with_readable_account_id(
        self, client, user_cookies, regular_user, db,
    ):
        aid = _make_account(db, regular_user["id"], "clinic")
        client.post(
            "/profile/regulatory-clocks/create",
            data={"account_id": str(aid), "title": "Audited", "regime": "IRB",
                  "duration_value": "0", "duration_unit": "working_day"},
            cookies=user_cookies, follow_redirects=False)
        # The governance row is in access_log with a READABLE account_id (the
        # whole point — an auditor can see WHICH account's policy changed).
        row = db.execute(
            "SELECT account_id, outcome FROM access_log "
            "WHERE route LIKE '/profile/regulatory-clocks/create%' "
            "ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None
        assert row["account_id"] == aid
        assert row["outcome"] == "ok"          # canonical access_log enum (ADJ-1)
