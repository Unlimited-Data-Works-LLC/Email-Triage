"""Punch 569 D5/D6 — the admin is TOLD: banner, one email per transition, and
a daily health section until it is fixed.

Every surface reads ``embedding_bits.update_notice`` (PD-5), so these tests
drive the real status funnel through a real prefix
(``make_versioned_prefix``) and assert on what the admin actually sees:
rendered pages under StrictUndefined (PD-17), the alert state machine's
outcomes, and the daily health state + rendered email.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web.admin_alerts import (
    EMBEDDING_RUNTIME_UPDATE_EVENT,
    _settings_key,
    fire_on_transition,
)

#: Rendered under StrictUndefined (PD-17).
ADMIN_PAGES = (
    "/config?tab=ai_backends",
    "/config?tab=general",
    "/logs",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    # These are the punch-569 CLICK notices: they hold with embedding.auto_update
    # OFF. The automatic-update wording is tests/test_web/test_autoupd_notices.py.
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


@pytest.fixture
def stale(tmp_path, monkeypatch):
    return make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))


@pytest.fixture
def security(tmp_path, monkeypatch):
    return make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0569",),
    )


class _Cfg:
    class push:
        public_url = "https://triage.example.test/"


# ---------------------------------------------------------------------------
# The notice SSOT
# ---------------------------------------------------------------------------

def test_the_notice_names_versions_and_security(security):
    n = eb.update_notice()
    assert n["kind"] == "update"
    assert n["headline"] == (
        "Embedding runtime update required (manifest v1 -> v2, security fix)"
    )
    assert n["security"] == eb.SECURITY_FIX and n["serving"] is False
    assert n["advisories"] == ["CVE-2099-0569"]
    assert "switched off" in n["consequence"]


def test_the_stale_notice_says_the_old_set_keeps_serving(stale):
    n = eb.update_notice()
    assert n["headline"] == "Embedding runtime update required (manifest v1 -> v2)"
    assert n["serving"] is True
    assert "keeps serving" in n["consequence"]


def test_no_notice_when_current_or_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "none"))
    assert eb.update_notice() is None
    make_verified_prefix(tmp_path, monkeypatch)
    assert eb.update_notice() is None


def test_the_restart_notice_says_exactly_how(stale, monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", True)
    n = eb.update_notice()
    assert n["kind"] == "restart"
    assert eb.RESTART_MESSAGE in n["consequence"]


def test_the_alert_reason_is_stable_across_reads(stale):
    assert eb.update_notice()["alert_reason"] == eb.update_notice()["alert_reason"]


# ---------------------------------------------------------------------------
# D5: ONE email per transition
# ---------------------------------------------------------------------------

async def test_one_email_per_transition_not_per_tick(db, stale, tmp_path, monkeypatch):
    evt = EMBEDDING_RUNTIME_UPDATE_EVENT
    from email_triage.web.db import delete_setting
    delete_setting(db, _settings_key(evt.key))
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"
        for _ in range(3):
            assert await fire_on_transition(evt, _Cfg(), db) == "suppressed"
        assert send.call_count == 1
        # A later image makes the change a security one: a NEW transition.
        make_versioned_prefix(tmp_path / "b", monkeypatch, steps=(True,))
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"
        assert send.call_count == 2
        # Fixed: recovered silently, no third email.
        make_verified_prefix(tmp_path / "c", monkeypatch)
        assert await fire_on_transition(evt, _Cfg(), db) == "recovered"
        assert send.call_count == 2


async def test_once_per_transition_survives_the_cooldown(db, stale):
    """``repeat_while_degraded=False``: 25 hours later it still does not re-send."""
    from datetime import datetime, timedelta, timezone
    from email_triage.web.db import delete_setting
    evt = EMBEDDING_RUNTIME_UPDATE_EVENT
    delete_setting(db, _settings_key(evt.key))
    t0 = datetime(2026, 10, 3, tzinfo=timezone.utc)
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        await fire_on_transition(evt, _Cfg(), db, now=t0)
        out = await fire_on_transition(evt, _Cfg(), db, now=t0 + timedelta(hours=25))
    assert out == "suppressed" and send.call_count == 1


async def test_a_failed_send_is_retried(db, stale):
    from email_triage.web.db import delete_setting
    evt = EMBEDDING_RUNTIME_UPDATE_EVENT
    delete_setting(db, _settings_key(evt.key))
    with patch.object(admin_alerts, "_send_admin_alert", return_value=False):
        assert await fire_on_transition(evt, _Cfg(), db) == "send_failed"
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"
        assert send.call_count == 1


async def test_the_runtime_probe_runs_off_the_db_lock(db):
    """N-543: the probe scans the runtime prefix, and the sweep ticks every
    60 s; it must not hold the process-wide DB lock. Two-armed: the same event
    without ``probe_off_lock`` DOES probe under the lock, so the observation
    can tell the two apart."""
    from dataclasses import replace

    from email_triage.web.db_writelock import get_write_lock

    assert EMBEDDING_RUNTIME_UPDATE_EVENT.probe_off_lock is True
    lock = get_write_lock()
    seen: list[bool] = []

    def probe():
        seen.append(lock._is_owned())
        return (False, {"reason": None})

    off = replace(EMBEDDING_RUNTIME_UPDATE_EVENT, probe_fn=probe,
                  key="n569_probe_off_lock")
    on = replace(off, probe_off_lock=False, key="n569_probe_on_lock")
    assert await fire_on_transition(off, _Cfg(), db) == "noop"
    assert await fire_on_transition(on, _Cfg(), db) == "noop"
    assert seen == [False, True]


def test_the_email_says_what_changed_and_links_to_the_action(security):
    active, ctx = admin_alerts._embedding_runtime_probe()
    assert active
    ctx["app_url"] = "https://triage.example.test"
    html, text = admin_alerts._assemble_embedding_runtime_alert(ctx)
    for needle in ("v1 -> v2", "security problem", "CVE-2099-0569",
                   "Update embedding runtime",
                   "https://triage.example.test/config?tab=ai_backends#embedding-runtime-update"):
        assert needle in text, needle
    assert "&lt;" not in text and "<a href=\"https://triage.example.test/config" in html


def test_the_email_without_an_app_url_names_the_page_in_words(stale):
    _active, ctx = admin_alerts._embedding_runtime_probe()
    ctx["app_url"] = ""
    _html, text = admin_alerts._assemble_embedding_runtime_alert(ctx)
    assert "Config > AI Backends" in text
    assert "keeps serving" in text


def test_the_restart_email_says_exactly_how(stale, monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", True)
    _active, ctx = admin_alerts._embedding_runtime_probe()
    ctx["app_url"] = ""
    html, text = admin_alerts._assemble_embedding_runtime_alert(ctx)
    assert "Restart the container to load the new runtime." in text
    assert "Restart the container to load the new runtime." in html


# ---------------------------------------------------------------------------
# D5: the daily health section, until fixed
# ---------------------------------------------------------------------------

def test_the_daily_section_is_present_until_fixed(db, app, stale, tmp_path, monkeypatch):
    from email_triage.web.daily_health import (
        _render_html, _render_text, gather_health_state,
    )
    state = gather_health_state(db, app.state.config)
    assert state["embedding_runtime"]["headline"].startswith(
        "Embedding runtime update required"
    )
    assert state["embedding_runtime"]["headline"] in state["attention_reasons"]
    html = _render_html(state, app.state.config)
    text = _render_text(state, app.state.config)
    assert "Update embedding runtime" in html and "keeps serving" in html
    assert "[Update embedding runtime]" in text
    make_verified_prefix(tmp_path / "fixed", monkeypatch)
    state = gather_health_state(db, app.state.config)
    assert state["embedding_runtime"] is None
    assert not any("Embedding runtime" in r for r in state["attention_reasons"])
    assert "Update embedding runtime" not in _render_html(state, app.state.config)


# ---------------------------------------------------------------------------
# D6: the banner, on every admin page, never for a non-admin
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("page", ADMIN_PAGES)
@pytest.mark.parametrize("which", ["stale", "security"])
def test_the_banner_renders_on_admin_pages(
    client, admin_cookies, strict_undefined_templates, request, page, which,
):
    request.getfixturevalue(which)
    resp = client.get(page, cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    assert 'id="embedding-runtime-banner"' in resp.text
    assert "Embedding runtime update required (manifest v1 -&gt; v2" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' in resp.text
    assert 'hx-target="#embedding-runtime-banner"' in resp.text
    assert flat.count(">Update embedding runtime</button>") >= 1
    if which == "security":
        assert "security fix" in flat and "CVE-2099-0569" in flat
    else:
        assert "keeps serving" in flat


def test_no_banner_when_nothing_is_needed(
    client, admin_cookies, strict_undefined_templates, tmp_path, monkeypatch,
):
    make_verified_prefix(tmp_path, monkeypatch)
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    assert resp.status_code == 200
    assert 'id="embedding-runtime-banner"' not in resp.text


def test_no_banner_for_a_non_admin(client, user_cookies, strict_undefined_templates, stale):
    resp = client.get("/", cookies=user_cookies)
    assert resp.status_code == 200, resp.status_code
    assert 'id="embedding-runtime-banner"' not in resp.text
    assert "embedding-update" not in resp.text


def test_the_restart_banner_has_no_button(
    client, admin_cookies, strict_undefined_templates, stale, monkeypatch,
):
    monkeypatch.setattr(eb, "_restart_pending", True)
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    flat = " ".join(resp.text.split())
    assert "restart the container to load the new runtime" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' not in resp.text


def test_the_banner_button_posts_the_update_route(
    client, admin_cookies, stale, monkeypatch, app,
):
    from email_triage.web import embedding_update_runner as ei
    called: list[bool] = []
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: (
        called.append(True) or eb.UpdateResult(status="failed", error_class="X")
    ))
    # The banner's htmx POST: the install card comes back and replaces the
    # banner in place (hx-target="#embedding-runtime-banner").
    resp = client.post(
        "/config/ai-backends/embedding-update", cookies=admin_cookies,
        headers={"HX-Request": "true", "HX-Target": "embedding-runtime-banner"},
        follow_redirects=False,
    )
    assert resp.status_code == 200, resp.text[:400]
    assert 'id="embedding-install-card"' in resp.text


# ---------------------------------------------------------------------------
# The card (StrictUndefined render smoke for every new state)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("which", ["stale", "security", "restart"])
def test_the_card_names_the_state_and_offers_the_update(
    client, admin_cookies, strict_undefined_templates, request, monkeypatch, which, db,
):
    request.getfixturevalue("security" if which == "security" else "stale")
    if which == "restart":
        monkeypatch.setattr(eb, "_restart_pending", True)
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    resp = client.get(
        "/config/ai-backends/embedding-install-status", cookies=admin_cookies,
    )
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    if which == "restart":
        assert "restart the container to load the new runtime" in flat
        assert 'hx-post="/config/ai-backends/embedding-update"' not in resp.text
    else:
        assert 'hx-post="/config/ai-backends/embedding-update"' in resp.text
        if which == "stale":
            assert "keeps serving until you update it" in flat
        else:
            assert "NOT verified" in flat
