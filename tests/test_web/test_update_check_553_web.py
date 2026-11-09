"""Punch 553 / N-556 — rendered views + routes + sweeper + daily email.

PD-17: every banner is asserted in the RENDERED page through the real
``_render`` injection under ``StrictUndefined`` (the ``strict_undefined_templates``
fixture), for an admin AND a non-admin, plus the daily-health email bodies.
The pure parse/resolve tables are in ``tests/test_update_check_553.py``.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone

import pytest

from email_triage import update_check as uc
from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token

from .conftest import TEST_SECRET

_PAGES = ("/dashboard", "/config")
_SEC_MARKER = (
    '<!-- email-triage-release-meta: {"schema": 1, "security": true, '
    '"severity": "critical", "min_secure_version": "99.0.0", '
    '"advisories": ["GHSA-1111-2222-3333"]} -->'
)


def _facts(tag: str = "v99.0.0", body: str = _SEC_MARKER) -> uc.ReleaseFacts:
    return uc.parse_release_payload(
        {"tag_name": tag, "html_url": f"https://example.invalid/{tag}",
         "body": body},
        checked_at="2026-10-01T04:00:00+00:00",
    )


@pytest.fixture
def switch(app, monkeypatch):
    """Snapshot the shared session config's update-check URL; restore after."""
    ae = app.state.config.admin_email
    monkeypatch.setattr(ae, "release_check_url", ae.release_check_url)
    return ae


@pytest.fixture
def second_admin_cookies(db):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("admin2@test.com", "Admin Two", "admin", now),
    )
    db.commit()
    token = create_session_token(
        TEST_SECRET, "admin2@test.com", "admin",
        mfa_verified_at=int(time.time()),
    )
    return {SESSION_COOKIE_NAME: token}


# ---------------------------------------------------------------------------
# (b) disclosure banner — rendered, per admin, durable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("page", _PAGES)
def test_admin_sees_update_check_disclosure(
    client, admin_cookies, switch, strict_undefined_templates, page,
):
    resp = client.get(page, cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'data-disclosure="update_check"' in resp.text
    assert "Update check is on" in resp.text
    assert "<code>api.github.com</code>" in resp.text
    assert "egress:update_check:api.github.com" in resp.text
    assert 'id="security-update-banner"' not in resp.text


def test_non_admin_sees_no_update_check_banners(
    client, user_cookies, switch, app, strict_undefined_templates,
):
    app.state.update_check_facts = _facts()
    resp = client.get("/dashboard", cookies=user_cookies)
    assert resp.status_code == 200
    assert "egress-disclosure" not in resp.text
    assert "security-update-banner" not in resp.text


def test_no_disclosure_when_check_is_off(
    client, admin_cookies, switch, strict_undefined_templates,
):
    switch.release_check_url = ""
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "egress-disclosure" not in resp.text


def test_dismissal_is_per_admin_and_durable(
    client, db, admin_user, admin_cookies, second_admin_cookies, switch,
    strict_undefined_templates,
):
    did = "egress:update_check:api.github.com"
    resp = client.post(
        "/admin/disclosures/dismiss", data={"disclosure_id": did},
        cookies=admin_cookies,
    )
    assert resp.status_code == 200
    assert resp.text == ""

    from email_triage.web.db import (
        DISMISSAL_NS_EGRESS_DISCLOSURES, get_setting, get_user_dismissals,
    )
    assert did in get_user_dismissals(
        db, admin_user["id"], DISMISSAL_NS_EGRESS_DISCLOSURES,
    )
    raw = get_setting(db, f"user:{admin_user['id']}:egress_disclosures_dismissed")
    assert raw == {"steps": [did]}

    # Durable for this admin, across page loads.
    for page in _PAGES:
        again = client.get(page, cookies=admin_cookies)
        assert again.status_code == 200
        assert "egress-disclosure" not in again.text
    # Another admin still sees it.
    other = client.get("/dashboard", cookies=second_admin_cookies)
    assert 'data-disclosure="update_check"' in other.text


def test_new_host_reshows_a_dismissed_disclosure(
    client, admin_cookies, switch, strict_undefined_templates,
):
    client.post(
        "/admin/disclosures/dismiss",
        data={"disclosure_id": "egress:update_check:api.github.com"},
        cookies=admin_cookies,
    )
    switch.release_check_url = "https://mirror.example/releases/latest"
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert "<code>mirror.example</code>" in resp.text


@pytest.mark.parametrize("bad_id", [
    "security", "security_update", "egress:update_check:evil.example",
    "egress:telemetry_beacon:", "", "x" * 300,
])
def test_dismiss_route_refuses_anything_not_a_live_disclosure(
    client, admin_cookies, switch, bad_id,
):
    resp = client.post(
        "/admin/disclosures/dismiss", data={"disclosure_id": bad_id},
        cookies=admin_cookies,
    )
    assert resp.status_code == 400


def test_dismiss_route_refuses_when_check_is_off(client, admin_cookies, switch):
    switch.release_check_url = ""
    resp = client.post(
        "/admin/disclosures/dismiss",
        data={"disclosure_id": "egress:update_check:api.github.com"},
        cookies=admin_cookies,
    )
    assert resp.status_code == 400


def test_dismiss_route_is_admin_only(client, db, regular_user, user_cookies, switch):
    resp = client.post(
        "/admin/disclosures/dismiss",
        data={"disclosure_id": "egress:update_check:api.github.com"},
        cookies=user_cookies, follow_redirects=False,
    )
    assert resp.status_code in (303, 401, 403)
    from email_triage.web.db import (
        DISMISSAL_NS_EGRESS_DISCLOSURES, get_user_dismissals,
    )
    assert get_user_dismissals(
        db, regular_user["id"], DISMISSAL_NS_EGRESS_DISCLOSURES,
    ) == []


def test_a_second_enabled_disclosure_renders_its_own_banner(
    client, admin_cookies, switch, monkeypatch, strict_undefined_templates,
):
    """The beacon is off in v0.2.0; prove the partial renders every enabled
    registry entry (not just the update check) with a synthetic second one."""
    real = uc.egress_disclosures

    def _with_beacon(config):
        rows = real(config)
        return rows + [uc.EgressDisclosure(
            kind="telemetry_beacon", title="Usage report is on", enabled=True,
            host="ops.tailnet.example", sends="install number and version",
            turn_off="Turn it off on the General settings tab.",
        )]

    monkeypatch.setattr(uc, "egress_disclosures", _with_beacon)
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'data-disclosure="update_check"' in resp.text
    assert 'data-disclosure="telemetry_beacon"' in resp.text
    assert "<code>ops.tailnet.example</code>" in resp.text
    # And it is dismissable through the same route.
    ok = client.post(
        "/admin/disclosures/dismiss",
        data={"disclosure_id": "egress:telemetry_beacon:ops.tailnet.example"},
        cookies=admin_cookies,
    )
    assert ok.status_code == 200


# ---------------------------------------------------------------------------
# (c) security banner — rendered, NOT dismissable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("page", _PAGES)
def test_security_banner_renders_and_has_no_dismiss(
    client, admin_cookies, app, switch, strict_undefined_templates, page,
):
    app.state.update_check_facts = _facts()
    resp = client.get(page, cookies=admin_cookies)
    assert resp.status_code == 200
    html = resp.text
    start = html.index('id="security-update-banner"')
    end = html.index("</aside>", start)
    banner = html[start:end]
    assert "Security update required" in banner
    assert "critical" in banner
    assert "GHSA-1111-2222-3333" in banner
    assert "<code>v99.0.0</code>" in banner or "<code>99.0.0</code>" in banner
    assert "hx-post" not in banner and "<button" not in banner
    assert "stays until this server is updated" in banner


def test_security_banner_survives_dismissing_every_disclosure(
    client, admin_cookies, app, switch, strict_undefined_templates,
):
    app.state.update_check_facts = _facts()
    for did in uc.dismissable_disclosure_ids(app.state.config):
        client.post("/admin/disclosures/dismiss", data={"disclosure_id": did},
                    cookies=admin_cookies)
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="security-update-banner"' in resp.text
    assert "egress-disclosure" not in resp.text


@pytest.mark.parametrize("body, heading", [
    ("", "it may fix a security problem"),
    ('<!-- email-triage-release-meta: {"schema": 1, "security": "yes"} -->',
     "treat it as a security update"),
])
def test_unreadable_marker_renders_unknown_severity_banner(
    client, admin_cookies, app, switch, strict_undefined_templates, body, heading,
):
    app.state.update_check_facts = _facts(body=body)
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'data-severity="unknown"' in resp.text
    assert heading in resp.text


def test_security_banner_reads_persisted_facts_before_first_tick(
    client, db, admin_cookies, app, switch, strict_undefined_templates,
):
    """Restart during a GitHub outage: app.state is cold, the settings row
    still carries the facts, so the banner still shows."""
    uc.save_release_facts(db, _facts())
    assert getattr(app.state, "update_check_facts", None) is None
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="security-update-banner"' in resp.text


def test_security_banner_clears_once_running_version_reaches_target(
    client, admin_cookies, app, switch, strict_undefined_templates,
):
    from email_triage import __version__
    app.state.update_check_facts = _facts(tag=f"v{__version__}")
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="security-update-banner"' not in resp.text


# ---------------------------------------------------------------------------
# (d) the off-switch through the real save handler + YAML round-trip
# ---------------------------------------------------------------------------

_SAVE_BASE = {
    "log_level": "INFO", "classifier_backend": "ollama",
    "classifier_model": "qwen3.5:35b",
    "classifier_ollama_url": "http://localhost:11434",
    "smtp_port": "587", "logging_format": "text",
}


def test_config_tab_renders_update_check_controls(
    client, admin_cookies, switch, strict_undefined_templates,
):
    resp = client.get("/config", cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'name="__update_check_fields_present"' in resp.text
    assert 'name="update_check_enabled"' in resp.text
    assert uc.DEFAULT_RELEASE_CHECK_URL in resp.text   # datalist/placeholder


def test_save_unticked_turns_the_check_off(client, admin_cookies, switch):
    """Through the real handler. (The StrictUndefined re-render of this route
    is pinned by ``test_config_save_rerender_is_strict_clean``.)"""
    form = dict(_SAVE_BASE, **{
        uc.FORM_SECTION_MARKER: "1",
        uc.FORM_URL_FIELD: uc.DEFAULT_RELEASE_CHECK_URL,
    })
    resp = client.post("/config/save", data=form, cookies=admin_cookies)
    assert resp.status_code == 200
    assert switch.release_check_url == ""
    # The re-rendered page reflects OFF: no disclosure banner.
    assert "egress-disclosure" not in resp.text


def test_off_round_trips_through_the_yaml_writer(tmp_path, monkeypatch):
    """What the Save writer emits for OFF loads back as OFF (not GitHub)."""
    from email_triage.config import TriageConfig, load_config
    from email_triage.web.routers.ui._shared import _write_config_yaml

    monkeypatch.chdir(tmp_path)
    yml = tmp_path / "email-triage.yaml"
    yml.write_text("{}", encoding="utf-8")
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = ""
    _write_config_yaml(cfg)
    assert load_config(str(yml)).admin_email.release_check_url == ""

    cfg.admin_email.release_check_url = "https://mirror.example/r"
    _write_config_yaml(cfg)
    assert load_config(str(yml)).admin_email.release_check_url == (
        "https://mirror.example/r"
    )


def test_save_ticked_blank_address_preserves(client, admin_cookies, switch):
    switch.release_check_url = "https://mirror.example/r"
    form = dict(_SAVE_BASE, **{
        uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
        uc.FORM_URL_FIELD: "",
    })
    resp = client.post("/config/save", data=form, cookies=admin_cookies)
    assert resp.status_code == 200
    assert switch.release_check_url == "https://mirror.example/r"


def test_save_without_the_section_leaves_the_switch_alone(
    client, admin_cookies, switch,
):
    switch.release_check_url = "https://mirror.example/r"
    resp = client.post("/config/save", data=dict(_SAVE_BASE), cookies=admin_cookies)
    assert resp.status_code == 200
    assert switch.release_check_url == "https://mirror.example/r"


def test_save_invalid_address_is_rejected_visibly(client, admin_cookies, switch):
    switch.release_check_url = "https://mirror.example/r"
    form = dict(_SAVE_BASE, **{
        uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
        uc.FORM_URL_FIELD: "ftp://mirror.example/r",
    })
    resp = client.post("/config/save", data=form, cookies=admin_cookies)
    assert resp.status_code == 200
    assert switch.release_check_url == "https://mirror.example/r"
    assert "update-check address was not saved" in resp.text


# ---------------------------------------------------------------------------
# sweeper: OFF makes no request; failure keeps facts; success persists facts
# ---------------------------------------------------------------------------

def _boom(*_a, **_k):
    raise AssertionError("fetch_latest_release called while the check is OFF")


def test_sweeper_makes_no_request_when_off(app, db, switch, monkeypatch):
    from email_triage.web import daily_health as dh
    from email_triage.web.background_sweepers import _update_check_once
    monkeypatch.setattr(dh, "fetch_latest_release", _boom)
    switch.release_check_url = ""
    assert asyncio.run(_update_check_once(app)) == "off"
    assert app.state.update_check_status == "off"


def test_sweeper_keeps_facts_on_fetch_failure(app, db, switch, monkeypatch):
    from email_triage.web import daily_health as dh
    from email_triage.web.background_sweepers import _update_check_once
    known = _facts()
    app.state.update_check_facts = known
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: None)
    assert asyncio.run(_update_check_once(app)) == "fetch_failed"
    assert app.state.update_check_facts == known


def test_sweeper_persists_parsed_facts(app, db, switch, monkeypatch):
    from email_triage.web import daily_health as dh
    from email_triage.web.background_sweepers import _update_check_once
    seen = {}

    def _fetch(url):
        seen["url"] = url
        return {"tag_name": "v99.0.0", "html_url": "https://example.invalid/r",
                "body": _SEC_MARKER}

    monkeypatch.setattr(dh, "fetch_latest_release", _fetch)
    assert asyncio.run(_update_check_once(app)) == "ok"
    assert seen["url"] == switch.release_check_url
    assert app.state.update_check_facts.security is True
    assert uc.load_release_facts(db) == app.state.update_check_facts


def test_gather_update_section_makes_no_request_when_off(db, monkeypatch):
    """The pre-553 dead branch (``if not url: return section``) is now live."""
    from email_triage.config import TriageConfig
    from email_triage.web import daily_health as dh
    monkeypatch.setattr(dh, "fetch_latest_release", _boom)
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = ""
    monkeypatch.setattr(
        "email_triage.version.read_target_schema_caps", lambda: 10_000,
    )
    section = dh.gather_update_available_section(cfg, db=db)
    assert section is None or section["latest_version"] is None


# ---------------------------------------------------------------------------
# daily health email: says so, even with the update section switched off
# ---------------------------------------------------------------------------

def _email_bodies(state, cfg):
    from email_triage.web.daily_health import assemble_daily_health_email
    msg = assemble_daily_health_email(state, cfg)
    text = "\n".join(p.get_content() for p in msg.walk()
                     if p.get_content_type() == "text/plain")
    html = "\n".join(p.get_content() for p in msg.walk()
                     if p.get_content_type() == "text/html")
    return msg, text, html


@pytest.mark.parametrize("include_update_available", [True, False])
def test_daily_email_carries_security_section(
    app, db, monkeypatch, include_update_available,
):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state, is_interesting
    cfg = TriageConfig()
    cfg.health_email.enabled = True
    cfg.health_email.recipients = ["ops@example.com"]
    cfg.smtp.host = "smtp.example.invalid"
    cfg.smtp.from_addr = "triage@example.com"
    cfg.health_email.include_update_available = include_update_available
    cfg.admin_email.release_check_url = ""      # no network in this test
    app.state.update_check_facts = _facts()

    state = gather_health_state(db, cfg, app=app)
    assert state["security_update"]["severity"] == "critical"
    assert any("Security update required" in r for r in state["attention_reasons"])
    assert is_interesting(state)

    msg, text, html = _email_bodies(state, cfg)
    assert "SECURITY UPDATE REQUIRED" in text
    assert "rated critical" in text
    assert "GHSA-1111-2222-3333" in text
    assert "Security update required" in html
    assert "GHSA-1111-2222-3333" in html


def test_daily_email_escapes_release_values(app, db):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = ""
    evil = (
        '<!-- email-triage-release-meta: {"schema": 1, "security": true, '
        '"severity": "high", "advisories": ["<script>x</script>"]} -->'
    )
    app.state.update_check_facts = _facts(tag="v99<b>", body=evil)
    state = gather_health_state(db, cfg, app=app)
    _msg, _text, html = _email_bodies(state, cfg)
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_daily_email_without_pending_security_has_no_section(app, db):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = ""
    state = gather_health_state(db, cfg, app=app)
    assert state["security_update"] is None
    _msg, text, html = _email_bodies(state, cfg)
    assert "SECURITY UPDATE REQUIRED" not in text
    assert "Security update required" not in html


# ---------------------------------------------------------------------------
# hipaa-b1 O5-H2 / O5-H4: the two chained INFO records
# ---------------------------------------------------------------------------

@pytest.fixture
def info_calls(monkeypatch):
    from email_triage.web.routers.ui import admin as admin_mod
    calls = []
    real = admin_mod._log.info

    def _rec(msg, *a, **k):
        calls.append((msg, k))
        return real(msg, *a, **k)

    monkeypatch.setattr(admin_mod._log, "info", _rec)
    return calls


def test_turning_the_check_off_is_logged_with_host_only(
    client, admin_cookies, admin_user, switch, info_calls,
):
    switch.release_check_url = "https://mirror.example/private/path"
    form = dict(_SAVE_BASE, **{uc.FORM_SECTION_MARKER: "1"})
    resp = client.post("/config/save", data=form, cookies=admin_cookies)
    assert resp.status_code == 200
    rows = [k for m, k in info_calls if m == uc.UPDATE_CHECK_CHANGED_LOG_MSG]
    assert rows == [{
        "update_check_before": "on:mirror.example",
        "update_check_after": "off",
        "user_id": admin_user["id"],
    }]
    assert "private/path" not in repr(info_calls)


def test_unchanged_setting_writes_no_change_record(
    client, admin_cookies, switch, info_calls,
):
    form = dict(_SAVE_BASE, **{
        uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
        uc.FORM_URL_FIELD: "",
    })
    client.post("/config/save", data=form, cookies=admin_cookies)
    assert not [m for m, _ in info_calls if m == uc.UPDATE_CHECK_CHANGED_LOG_MSG]


def test_disclosure_ack_record_survives_hipaa_redaction(
    client, admin_cookies, admin_user, switch, info_calls,
):
    from email_triage.triage_logging import redact_persisted_extra
    did = "egress:update_check:api.github.com"
    client.post("/admin/disclosures/dismiss", data={"disclosure_id": did},
                cookies=admin_cookies)
    (row,) = [k for m, k in info_calls if m == uc.DISCLOSURE_ACK_LOG_MSG]
    assert row == {"disclosure_id": did, "user_id": admin_user["id"]}
    assert redact_persisted_extra(dict(row), hipaa=True) == row


# ---------------------------------------------------------------------------
# DA O5-F1 / db F-O5-2: no unsafe link reaches the banner or the email
# ---------------------------------------------------------------------------

def test_javascript_release_link_never_renders(
    client, admin_cookies, app, switch, strict_undefined_templates,
):
    app.state.update_check_facts = uc.parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": "javascript:fetch('/admin/x')",
         "body": ""},
        checked_at="2026-10-01T04:00:00+00:00",
    )
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="security-update-banner"' in resp.text
    assert "javascript:" not in resp.text
    assert "Read the release notes" not in resp.text


def test_update_section_link_is_https_only(db, monkeypatch):
    from email_triage.config import TriageConfig
    from email_triage.web import daily_health as dh
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: {
        "tag_name": "v99.0.0", "html_url": "javascript:alert(1)", "body": "n",
    })
    monkeypatch.setattr(
        "email_triage.version.read_target_schema_caps", lambda: 10_000,
    )
    section = dh.gather_update_available_section(TriageConfig(), db=db)
    if section is not None:
        assert section["release_url"] is None


# ---------------------------------------------------------------------------
# db F-O5-1: a failing check is visible, and one success clears it
# ---------------------------------------------------------------------------

def _run_ticks(app, monkeypatch, outcomes):
    from email_triage.web import daily_health as dh
    from email_triage.web.background_sweepers import _update_check_once
    seq = list(outcomes)

    def _fetch(url):
        ok = seq.pop(0)
        return ({"tag_name": "v0.0.1", "html_url": "", "body": ""}
                if ok else None)

    monkeypatch.setattr(dh, "fetch_latest_release", _fetch)
    return [asyncio.run(_update_check_once(app)) for _ in outcomes]


def test_failing_check_raises_notice_and_one_success_clears_it(
    client, db, admin_cookies, app, switch, monkeypatch,
    strict_undefined_templates,
):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state

    _run_ticks(app, monkeypatch, [False] * uc.STALE_AFTER_FAILURES)
    health = uc.load_check_health(db)
    assert health["consecutive_failures"] == uc.STALE_AFTER_FAILURES

    page = client.get("/dashboard", cookies=admin_cookies)
    assert page.status_code == 200
    assert 'id="update-check-stale-banner"' in page.text
    assert "<code>api.github.com</code>" in page.text

    cfg = TriageConfig()
    state = gather_health_state(db, cfg, app=app)
    assert state["update_check_stale"]["consecutive_failures"] == uc.STALE_AFTER_FAILURES
    assert state["update_check_stale"]["reason"] == uc.STALE_REASON_FAILING
    assert any("The update check is failing" in r for r in state["attention_reasons"])
    _msg, text, html = _email_bodies(state, cfg)
    assert "THE UPDATE CHECK IS FAILING" in text
    assert "The update check is failing" in html
    assert "internet access" in text and "internet access" in html

    # One success clears every surface (PD-18, one funnel).
    assert _run_ticks(app, monkeypatch, [True]) == ["ok"]
    health = uc.load_check_health(db)
    assert health["consecutive_failures"] == 0 and health["last_success_at"]
    page = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="update-check-stale-banner"' not in page.text
    state = gather_health_state(db, cfg, app=app)
    assert state["update_check_stale"] is None


def test_a_check_that_stopped_running_is_not_told_to_check_internet_access(
    client, db, admin_cookies, app, switch, strict_undefined_templates,
):
    """Punch 574: the AGE arm (last success older than STALE_AFTER_HOURS, no
    failure since) means no attempt is being recorded. Every surface says the
    checker stopped, and none sends the operator to internet access."""
    from datetime import datetime, timedelta, timezone

    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state

    old = (datetime.now(timezone.utc)
           - timedelta(hours=uc.STALE_AFTER_HOURS + 1)).isoformat()
    uc.record_check_outcome(db, uc.OUTCOME_OK, now_iso=old)
    try:
        page = client.get("/dashboard", cookies=admin_cookies)
        assert page.status_code == 200
        start = page.text.index('id="update-check-stale-banner"')
        banner = page.text[start:page.text.index("</aside>", start)]
        assert f'data-reason="{uc.STALE_REASON_NOT_RUNNING}"' in banner
        assert "The update check has stopped running" in banner
        assert "no check attempt has been recorded since then" in banner
        assert "internet access" not in banner
        assert "failed attempts in a row" not in banner

        cfg = TriageConfig()
        state = gather_health_state(db, cfg, app=app)
        st = state["update_check_stale"]
        assert st["reason"] == uc.STALE_REASON_NOT_RUNNING
        assert any("stopped running" in r for r in state["attention_reasons"])
        _msg, text, html = _email_bodies(state, cfg)
        for body in (text, html):
            assert "stopped running" in body.lower()
            assert "internet access" not in body
            assert "failed attempts in a row" not in body
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=old)


def test_below_threshold_failures_show_nothing(
    client, db, admin_cookies, app, switch, monkeypatch,
):
    _run_ticks(app, monkeypatch, [False] * (uc.STALE_AFTER_FAILURES - 1))
    page = client.get("/dashboard", cookies=admin_cookies)
    assert 'id="update-check-stale-banner"' not in page.text


def test_turning_off_resets_the_health_record(app, db, switch, monkeypatch):
    _run_ticks(app, monkeypatch, [False] * 3)
    switch.release_check_url = ""
    from email_triage.web.background_sweepers import _update_check_once
    assert asyncio.run(_update_check_once(app)) == "off"
    assert uc.load_check_health(db)["consecutive_failures"] == 0


def test_non_admin_never_sees_the_stale_notice(
    client, db, user_cookies, app, switch, monkeypatch,
):
    _run_ticks(app, monkeypatch, [False] * uc.STALE_AFTER_FAILURES)
    page = client.get("/dashboard", cookies=user_cookies)
    assert "update-check-stale-banner" not in page.text


# ---------------------------------------------------------------------------
# db F-O5-3: the /config/save re-render under StrictUndefined (PD-17)
# ---------------------------------------------------------------------------

def test_config_save_rerender_is_strict_clean(
    client, admin_cookies, switch, strict_undefined_templates,
):
    form = dict(_SAVE_BASE, **{
        uc.FORM_SECTION_MARKER: "1", uc.FORM_ENABLED_FIELD: "1",
        uc.FORM_URL_FIELD: "",
    })
    resp = client.post("/config/save", data=form, cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'name="update_check_enabled"' in resp.text
    assert "All settings saved." in resp.text


# ---------------------------------------------------------------------------
# panel b1 round 4: injected tag/advisory never reaches the plain-text email
# ---------------------------------------------------------------------------

def test_injected_tag_and_advisory_never_print(app, db):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = ""
    meta = ('<!-- email-triage-release-meta: {"schema": 1, "security": true, '
            '"severity": "high", "advisories": ["GHSA-x\\nSecurity: none"]} -->')
    app.state.update_check_facts = uc.parse_release_payload(
        {"tag_name": "v9.9.9\nNo security update is pending.",
         "html_url": "", "body": meta},
        checked_at="2026-10-02T00:00:00+00:00",
    )
    state = gather_health_state(db, cfg, app=app)
    assert state["security_update"]["reason"] == "marker_unparseable"
    _msg, text, html = _email_bodies(state, cfg)
    assert "No security update is pending" not in text
    assert "Security: none" not in text
    assert "SECURITY UPDATE REQUIRED" in text


def test_update_section_tag_is_admitted_through_the_rule(db, monkeypatch):
    from email_triage.config import TriageConfig
    from email_triage.web import daily_health as dh
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: {
        "tag_name": "v9.9.9\nNo security update is pending.",
        "html_url": "", "body": "n",
    })
    monkeypatch.setattr(
        "email_triage.version.read_target_schema_caps", lambda: 10_000,
    )
    section = dh.gather_update_available_section(TriageConfig(), db=db)
    if section is not None:
        assert section["latest_version"] is None


# ---------------------------------------------------------------------------
# 553 landing: the disclosure banner adds no form controls to every page
# (the E2E failure on 02af36ff: /help/me had two submit buttons)
# ---------------------------------------------------------------------------

def test_disclosure_banner_adds_no_page_controls(
    client, admin_cookies, switch, strict_undefined_templates,
):
    import re
    resp = client.get("/help/me", cookies=admin_cookies)
    assert resp.status_code == 200
    html = resp.text
    start = html.index('data-disclosure="update_check"')
    banner = html[start:html.index("</aside>", start)]
    assert "<form" not in banner and 'type="submit"' not in banner
    assert "hx-vals" not in banner
    assert 'name="disclosure_id"' in banner and 'type="button"' in banner
    # The help page's own single submit button is still the only one.
    assert len(re.findall(r'type="submit"', html)) == 1


# ---------------------------------------------------------------------------
# Punch 584: a refused address is not reported as a network problem
# ---------------------------------------------------------------------------

def _fake_release_client(monkeypatch, respond):
    """Route ``fetch_latest_release`` through a fake egress client whose
    ``get`` calls ``respond(url)`` (return an ``httpx.Response`` or raise), on
    a private release cache so no entry leaks into another test."""
    from email_triage.web import daily_health as dh

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, **kw):
            return respond(url)

    monkeypatch.setattr(dh, "_release_cache", {})
    monkeypatch.setattr(dh, "egress_client", lambda **kw: _Client())
    return dh


def _answer(status, body=b'{"tag_name": "v0.0.1", "html_url": "", "body": ""}'):
    import httpx

    def respond(url):
        return httpx.Response(status, content=body,
                              request=httpx.Request("GET", url))
    return respond


def _no_answer(url):
    import httpx
    raise httpx.ConnectError("connection refused",
                             request=httpx.Request("GET", url))


def _policy_refused(url):
    from email_triage._egress import EgressBlocked
    raise EgressBlocked("destination is a private address")


@pytest.mark.parametrize("respond, expected", [
    (_policy_refused, {"kind": uc.FAILURE_REFUSED, "status": None}),
    (_answer(404), {"kind": uc.FAILURE_HTTP_STATUS, "status": 404}),
    (_answer(503), {"kind": uc.FAILURE_HTTP_STATUS, "status": 503}),
    (_no_answer, {"kind": uc.FAILURE_TRANSPORT, "status": None}),
    (_answer(200, b"not json"), {"kind": uc.FAILURE_BAD_RESPONSE, "status": None}),
    (_answer(200, b"[1, 2]"), {"kind": uc.FAILURE_BAD_RESPONSE, "status": None}),
    (_answer(200), None),
])
def test_release_fetch_records_how_it_failed(monkeypatch, respond, expected):
    dh = _fake_release_client(monkeypatch, respond)
    url = "https://api.github.com/repos/x/y/releases/latest"
    payload = dh.fetch_latest_release(url)
    assert (payload is None) is (expected is not None)
    assert dh.last_release_fetch_failure(url) == expected
    # A cache hit reports the same failure as the fetch it stands for.
    assert dh.fetch_latest_release(url) == payload
    assert dh.last_release_fetch_failure(url) == expected


def test_failure_detail_is_recorded_and_one_success_clears_it(db):
    old = "2026-10-01T00:00:00+00:00"
    try:
        h = uc.record_check_outcome(
            db, uc.OUTCOME_FAILED, now_iso=old,
            failure=uc.fetch_failure(uc.FAILURE_HTTP_STATUS, 404),
        )
        assert (h["last_failure_kind"], h["last_failure_status"]) == (
            uc.FAILURE_HTTP_STATUS, 404)
        assert uc.load_check_health(db)["last_failure_status"] == 404
        # A failure with no detail does not inherit the previous detail.
        h = uc.record_check_outcome(db, uc.OUTCOME_FAILED, now_iso=old)
        assert h["last_failure_kind"] is None and h["last_failure_status"] is None
        # Malformed detail is dropped, not stored.
        h = uc.record_check_outcome(
            db, uc.OUTCOME_FAILED, now_iso=old,
            failure={"kind": "made_up", "status": 404},
        )
        assert h["last_failure_kind"] is None and h["last_failure_status"] is None
        h = uc.record_check_outcome(
            db, uc.OUTCOME_FAILED, now_iso=old,
            failure={"kind": uc.FAILURE_TRANSPORT, "status": 404},
        )
        assert (h["last_failure_kind"], h["last_failure_status"]) == (
            uc.FAILURE_TRANSPORT, None)
        uc.record_check_outcome(
            db, uc.OUTCOME_FAILED, now_iso=old,
            failure=uc.fetch_failure(uc.FAILURE_HTTP_STATUS, 404),
        )
        # PD-18: the success edge clears the detail with the count.
        h = uc.record_check_outcome(db, uc.OUTCOME_OK, now_iso=old)
        assert h["consecutive_failures"] == 0
        assert h["last_failure_kind"] is None and h["last_failure_status"] is None
        assert uc.load_check_health(db)["last_failure_kind"] is None
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=old)


def test_a_refused_address_is_named_on_every_surface(
    client, db, admin_cookies, app, switch, monkeypatch,
    strict_undefined_templates,
):
    """Punch 584: the prod incident. Every hourly fetch got HTTP 404 (the
    address named a private repository) and the banner sent the admin to the
    network. A 4xx answer proves the network works: every surface names the
    address, quotes the status, and does not send the admin to the network."""
    from email_triage.config import TriageConfig
    from email_triage.web.background_sweepers import _update_check_once
    from email_triage.web.daily_health import gather_health_state

    _fake_release_client(monkeypatch, _answer(404, b'{"message": "Not Found"}'))
    try:
        for _ in range(uc.STALE_AFTER_FAILURES):
            assert asyncio.run(_update_check_once(app)) == "fetch_failed"
        health = uc.load_check_health(db)
        assert health["last_failure_kind"] == uc.FAILURE_HTTP_STATUS
        assert health["last_failure_status"] == 404

        page = client.get("/dashboard", cookies=admin_cookies)
        assert page.status_code == 200
        start = page.text.index('id="update-check-stale-banner"')
        banner = page.text[start:page.text.index("</aside>", start)]
        assert f'data-reason="{uc.STALE_REASON_BAD_ADDRESS}"' in banner
        assert "The update-check address does not work" in banner
        assert "api.github.com answered HTTP 404" in banner
        assert "internet access works" in banner
        assert "Check this server" not in banner

        cfg = TriageConfig()
        state = gather_health_state(db, cfg, app=app)
        st = state["update_check_stale"]
        assert st["reason"] == uc.STALE_REASON_BAD_ADDRESS
        assert any("address does not work" in r for r in state["attention_reasons"])
        _msg, text, html = _email_bodies(state, cfg)
        for body in (text, html):
            assert "answered HTTP 404" in body
            assert "Check this server" not in body

        # One success clears every surface and the failure detail (PD-18).
        _fake_release_client(monkeypatch, _answer(200))
        assert asyncio.run(_update_check_once(app)) == "ok"
        health = uc.load_check_health(db)
        assert health["consecutive_failures"] == 0
        assert health["last_failure_kind"] is None
        page = client.get("/dashboard", cookies=admin_cookies)
        assert 'id="update-check-stale-banner"' not in page.text
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF,
                                now_iso="2026-10-01T00:00:00+00:00")


def test_a_policy_refused_address_is_recorded_not_lost(
    client, db, admin_cookies, app, switch, monkeypatch,
    strict_undefined_templates,
):
    """Panel H584-2 / DB584-1 / DA584-2: an EgressBlocked refusal used to
    escape the fetch, so no failure was recorded and an install that never
    succeeded showed NO stale notice at all (fail OPEN). Now every tick is a
    recorded failure and the notice names the block."""
    from email_triage.web.background_sweepers import _update_check_once

    _fake_release_client(monkeypatch, _policy_refused)
    try:
        for _ in range(uc.STALE_AFTER_FAILURES):
            assert asyncio.run(_update_check_once(app)) == "fetch_failed"
        health = uc.load_check_health(db)
        assert health["consecutive_failures"] == uc.STALE_AFTER_FAILURES
        assert health["last_failure_kind"] == uc.FAILURE_REFUSED
        page = client.get("/dashboard", cookies=admin_cookies)
        start = page.text.index('id="update-check-stale-banner"')
        banner = page.text[start:page.text.index("</aside>", start)]
        assert f'data-reason="{uc.STALE_REASON_REFUSED}"' in banner
        assert "blocked by this server" in banner
        assert "internet access" not in banner
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF,
                                now_iso="2026-10-01T00:00:00+00:00")


def test_default_address_round_trips_without_being_written(tmp_path, monkeypatch):
    """Punch 584: the Save leaves the default out of the YAML, so the install
    follows the default when it changes; OFF and a chosen address are kept
    (``test_off_round_trips_through_the_yaml_writer``)."""
    import yaml as _yaml

    from email_triage.config import TriageConfig, load_config
    from email_triage.web.routers.ui._shared import _write_config_yaml

    monkeypatch.chdir(tmp_path)
    yml = tmp_path / "email-triage.yaml"
    yml.write_text("{}", encoding="utf-8")
    cfg = TriageConfig()
    assert cfg.admin_email.release_check_url == uc.DEFAULT_RELEASE_CHECK_URL
    _write_config_yaml(cfg)
    written = _yaml.safe_load(yml.read_text(encoding="utf-8"))
    assert "release_check_url" not in written["admin_email"]
    assert load_config(str(yml)).admin_email.release_check_url == (
        uc.DEFAULT_RELEASE_CHECK_URL
    )


@pytest.mark.parametrize("retired", sorted(uc._RETIRED_DEFAULT_RELEASE_CHECK_URLS))
def test_a_saved_retired_default_heals_on_load(tmp_path, monkeypatch, retired):
    """Punch 584: a YAML written before 584 holds the then-default address as
    if typed. It loads as the current default, and the next Save drops it."""
    import yaml as _yaml

    from email_triage.config import load_config
    from email_triage.web.routers.ui._shared import _write_config_yaml

    monkeypatch.chdir(tmp_path)
    yml = tmp_path / "email-triage.yaml"
    yml.write_text(
        "admin_email:\n  recipients: []\n"
        f"  release_check_url: {retired.upper()}\n",
        encoding="utf-8",
    )
    cfg = load_config(str(yml))
    assert cfg.admin_email.release_check_url == uc.DEFAULT_RELEASE_CHECK_URL
    _write_config_yaml(cfg)
    written = _yaml.safe_load(yml.read_text(encoding="utf-8"))
    assert "release_check_url" not in written["admin_email"]
