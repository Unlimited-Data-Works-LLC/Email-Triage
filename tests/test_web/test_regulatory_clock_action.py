""" — the "clock" route action (operator-configured clock creation) + the
``create_clock_candidate_from_route`` finalizer it drives.
"""
from __future__ import annotations

from types import SimpleNamespace

from email_triage.actions.regulatory_clock import RegulatoryClockAction
from email_triage.classify.safety_detect import create_clock_candidate_from_route
from email_triage.engine.models import ActionResult
from email_triage.web.db import create_email_account

_FIXED_SALT = b"unit-test-salt-0123456789abcdef"


# --- finalizer (real DB) ----------------------------------------------------

def _acct(db, user_id, name="Lupus mailbox"):
    return create_email_account(
        db, user_id=user_id, name=name, provider_type="imap",
        config={"account": "pi@site.example"}, hipaa=True,
    )


def test_from_route_creates_candidate_with_operator_responsibility(
    db, regular_user, monkeypatch,
):
    monkeypatch.setattr(
        "email_triage.style_learning.per_contact_hipaa."
        "get_or_init_recipient_salt",
        lambda secrets: _FIXED_SALT,
    )
    aid = _acct(db, regular_user["id"])
    iid = create_clock_candidate_from_route(
        db, secrets=None, def_code="IRB_AWARENESS", account_id=aid,
        subject="Safety report due", body="body",
        message_id="<m1>", received_at="2026-06-15T12:00:00+00:00",
        responsibility="i_submit",
    )
    assert iid is not None
    row = db.execute(
        "SELECT state, responsibility FROM regulatory_clock_instance WHERE id=?",
        (iid,),
    ).fetchone()
    assert row["state"] == "candidate"          # propose-then-confirm: candidate only
    # responsibility is set from the ROUTE config — the N-96-sanctioned out-of-band
    # source (NEVER inferred from content); 'i_submit' is legitimate here.
    assert row["responsibility"] == "i_submit"


def test_from_route_is_idempotent_per_case(db, regular_user, monkeypatch):
    monkeypatch.setattr(
        "email_triage.style_learning.per_contact_hipaa."
        "get_or_init_recipient_salt",
        lambda secrets: _FIXED_SALT,
    )
    aid = _acct(db, regular_user["id"])
    kw = dict(
        secrets=None, def_code="IRB_AWARENESS", account_id=aid,
        subject="Safety report due", body="body",
        received_at="2026-06-15T12:00:00+00:00", responsibility="i_submit",
    )
    first = create_clock_candidate_from_route(db, message_id="<m1>", **kw)
    assert first is not None
    # a second matching mail (same account + derived case) must NOT spawn a
    # duplicate clock — one clock per (account, case_ref)
    second = create_clock_candidate_from_route(db, message_id="<m2>", **kw)
    assert second is None
    cnt = db.execute(
        "SELECT COUNT(*) FROM regulatory_clock_instance WHERE account_id=?",
        (aid,),
    ).fetchone()[0]
    assert cnt == 1


def test_from_route_unknown_template_returns_none(db, regular_user):
    aid = _acct(db, regular_user["id"])
    iid = create_clock_candidate_from_route(
        db, secrets=None, def_code="NOT_A_REAL_CODE", account_id=aid,
        subject="x", body="", message_id=None, received_at=None,
        responsibility="unknown",
    )
    assert iid is None


# --- the route action (execute wiring) --------------------------------------

def _flow(**state):
    return SimpleNamespace(flow_id="f1", state_bag=state)


def _msg():
    return SimpleNamespace(
        subject="Safety report due", body_text="body",
        message_id="<m1>", date="2026-06-15T12:00:00+00:00",
    )


def _stub_log(monkeypatch):
    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.build_action_log_extras",
        lambda *a, **k: {},
    )


async def test_clock_action_skips_without_template(monkeypatch):
    _stub_log(monkeypatch)
    out = await RegulatoryClockAction().execute(
        _flow(db=object(), account_id=1), _msg(),
        SimpleNamespace(category="safety"), SimpleNamespace(name="imap"),
        config={},  # no template configured
    )
    assert out.result == ActionResult.SKIPPED


async def test_clock_action_creates_when_configured(monkeypatch):
    _stub_log(monkeypatch)

    async def _none(*a, **k):
        return None

    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.check_idempotent_already_done",
        _none,
    )
    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.record_idempotent_done", _none,
    )
    captured = {}

    async def _fake_db_call(fn, *a, **k):
        captured["kwargs"] = k
        return 42  # instance_id

    monkeypatch.setattr("email_triage.web.db_threadpool.db_call", _fake_db_call)

    out = await RegulatoryClockAction().execute(
        _flow(db=object(), secrets=None, account_id=7), _msg(),
        SimpleNamespace(category="safety"), SimpleNamespace(name="imap"),
        config={"template": "IRB_AWARENESS", "responsibility": "i_submit"},
    )
    assert out.result == ActionResult.COMPLETED
    assert out.data["instance_id"] == 42
    assert captured["kwargs"]["def_code"] == "IRB_AWARENESS"
    assert captured["kwargs"]["responsibility"] == "i_submit"
    assert captured["kwargs"]["account_id"] == 7


async def test_clock_action_invalid_responsibility_coerced_to_unknown(monkeypatch):
    _stub_log(monkeypatch)

    async def _none(*a, **k):
        return None

    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.check_idempotent_already_done",
        _none,
    )
    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.record_idempotent_done", _none,
    )
    captured = {}

    async def _fake_db_call(fn, *a, **k):
        captured["kwargs"] = k
        return 1

    monkeypatch.setattr("email_triage.web.db_threadpool.db_call", _fake_db_call)
    out = await RegulatoryClockAction().execute(
        _flow(db=object(), secrets=None, account_id=7), _msg(),
        SimpleNamespace(category="safety"), SimpleNamespace(name="imap"),
        config={"template": "IRB_AWARENESS", "responsibility": "garbage"},
    )
    assert out.result == ActionResult.COMPLETED
    assert captured["kwargs"]["responsibility"] == "unknown"  # coerced


async def test_clock_action_skips_without_db_context(monkeypatch):
    _stub_log(monkeypatch)

    async def _none(*a, **k):
        return None

    monkeypatch.setattr(
        "email_triage.actions.regulatory_clock.check_idempotent_already_done",
        _none,
    )
    out = await RegulatoryClockAction().execute(
        _flow(account_id=None), _msg(),  # no db / account in the flow
        SimpleNamespace(category="safety"), SimpleNamespace(name="imap"),
        config={"template": "IRB_AWARENESS"},
    )
    assert out.result == ActionResult.SKIPPED


# --- route save round-trip + the rendered UI --------------------------------

def _imap_acct(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "u@example.com"},
    )


class TestRouteSaveClock:
    def test_save_persists_template_and_responsibility(
        self, client, db, regular_user, user_cookies,
    ):
        """POST actions=[clock] + template + responsibility → lands on the
        action's config JSON in the shape RegulatoryClockAction.execute reads."""
        from email_triage.web.db import list_account_routes
        a1 = _imap_acct(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "safety-reports",
                "actions": ["clock"],
                "clock_template": "IRB_AWARENESS",
                "clock_responsibility": "i_submit",
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200, f"body={resp.text!r}"
        routes = list_account_routes(db, a1)
        clk = next(
            a for r in routes if r["category"] == "safety-reports"
            for a in r["actions"] if a["action"] == "clock"
        )
        assert clk["config"]["template"] == "IRB_AWARENESS"
        assert clk["config"]["responsibility"] == "i_submit"

    def test_save_drops_invalid_responsibility(
        self, client, db, regular_user, user_cookies,
    ):
        from email_triage.web.db import list_account_routes
        a1 = _imap_acct(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "safety-reports",
                "actions": ["clock"],
                "clock_template": "FDA_IND_15D_INFO",
                "clock_responsibility": "garbage",  # not in the enum
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        routes = list_account_routes(db, a1)
        clk = next(
            a for r in routes if r["category"] == "safety-reports"
            for a in r["actions"] if a["action"] == "clock"
        )
        assert "responsibility" not in clk["config"]  # invalid → dropped
        assert clk["config"]["template"] == "FDA_IND_15D_INFO"


def test_routes_body_partial_offers_clock_action():
    """Scaffolding assertion (mirrors the add-label partial test): the action
    checkbox + the two config selects the save handler reads by name."""
    from pathlib import Path
    text = (
        Path(__file__).parent.parent.parent
        / "src" / "email_triage" / "web" / "templates"
        / "accounts" / "_routes_body.html"
    ).read_text(encoding="utf-8")
    assert 'value="clock"' in text
    assert 'name="clock_template"' in text
    assert 'name="clock_responsibility"' in text


def test_routes_body_partial_offers_mute_action():
    """2026-07-17 — MuteAction added to routes editor. Sibling assertion to the
    clock check: the checkbox must render so the operator can wire the
    action. No inline config selects (mute takes an optional reason via
    route-config JSON, not a picker)."""
    from pathlib import Path
    text = (
        Path(__file__).parent.parent.parent
        / "src" / "email_triage" / "web" / "templates"
        / "accounts" / "_routes_body.html"
    ).read_text(encoding="utf-8")
    assert 'value="mute"' in text, (
        "MuteAction checkbox missing from routes editor partial — the UI "
        "won't offer 'mute' to operators, dead-in-prod shape."
    )


def test_available_actions_in_live_registry():
    """PD#1 / incident_2026-06-11 pin: EVERY action offered in the routes editor
    (_AVAILABLE_ROUTE_ACTIONS) MUST be registered in build_default_registry — the
    registry every LIVE ingestion path (watcher / poll / push / bulk runners)
    uses. An offered-but-unregistered action ships DEAD in prod (the operator
    configures it; the live path silently can't run it). Count-agnostic: derived
    from the actual UI list + the actual registry, not a hardcoded count. (This
    catches the bug the clock action shipped with.)"""
    from email_triage.web.routers.ui._shared import _AVAILABLE_ROUTE_ACTIONS
    from email_triage.web.triage_one import build_default_registry
    live = set(
        build_default_registry(
            include_add_label=True, include_self_event=True
        ).names
    )
    missing = [a for a in _AVAILABLE_ROUTE_ACTIONS if a not in live]
    assert not missing, (
        "route actions offered in the UI but NOT in the live ingestion "
        f"registry (would be dead in prod): {missing}"
    )


def test_from_route_records_owner_as_audit_actor(db, regular_user, monkeypatch):
    """hipaa-sme MUST-FIX: an operator-CONFIGURED create attributes the account
    OWNER on the chained 'detected' event (a human authority), NOT None like
    system content-detection. §164.312(b)/§164.308(a)(1)(ii)(D)."""
    monkeypatch.setattr(
        "email_triage.style_learning.per_contact_hipaa."
        "get_or_init_recipient_salt",
        lambda secrets: _FIXED_SALT,
    )
    aid = _acct(db, regular_user["id"])
    iid = create_clock_candidate_from_route(
        db, secrets=None, def_code="IRB_AWARENESS", account_id=aid,
        subject="Safety report due", body="b", message_id="<m1>",
        received_at=None, responsibility="i_submit",
    )
    ev = db.execute(
        "SELECT actor_user_id FROM regulatory_clock_event "
        "WHERE instance_id=? AND event_kind='detected'",
        (iid,),
    ).fetchone()
    assert ev is not None
    assert ev["actor_user_id"] == regular_user["id"]  # owner attributed, not None
