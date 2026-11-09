"""Operator decision 2026-10-25 -- what the admin SEES while the app updates the
embedding runtime itself (PD-17: the rendered view, not only the model).

* the notice SSOT words the three states (in progress / failed and retrying /
  restart) without ever asking for a click;
* the click-request email is silent while the updater runs, and a failure that
  leaves embedding off or a security fix undone is its own URGENT, repeating
  email;
* the success is ONE after-the-fact email and one daily-health block;
* the banner and the install card render under StrictUndefined with no button
  (a retry button only after a failure).

The punch-569 CLICK wording is the switch-off arm and lives in
``test_n569_runtime_notice.py`` (it pins ``embedding.auto_update`` off).
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web import embedding_update_runner as ru
from email_triage.web.admin_alerts import (
    EMBEDDING_RUNTIME_AUTO_FAILED_EVENT,
    EMBEDDING_RUNTIME_AUTO_UPDATED_EVENT,
    EMBEDDING_RUNTIME_UPDATE_EVENT,
    _settings_key,
    fire_on_transition,
)
from email_triage.web.db import delete_setting


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
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


#: Words that ask the admin to act. None may appear in an auto notice.
_CLICK_WORDS = ("click", "until you update it", "[Update embedding runtime]")


#: The two sentences that SAY no click is needed; they are the only allowed use
#: of the word.
_SANCTIONED = ("nothing to click", "nothing needs clicking")


def _no_click(text: str) -> None:
    low = text.lower()
    for ok in _SANCTIONED:
        low = low.replace(ok, "")
    for w in _CLICK_WORDS:
        assert w.lower() not in low, (w, text)


# ---------------------------------------------------------------------------
# The notice SSOT
# ---------------------------------------------------------------------------

def test_an_in_progress_notice_says_the_app_does_it_and_nothing_is_to_click(stale):
    n = eb.update_notice()
    assert n["kind"] == "auto" and n["auto"] is True
    assert n["headline"] == "Embedding runtime update in progress (manifest v1 -> v2)"
    assert n["serving"] is True and "keeps serving" in n["consequence"]
    assert "nothing to click" in n["consequence"]
    _no_click(n["headline"] + " " + n["consequence"])


def test_a_security_notice_says_embedding_is_off_meanwhile_and_the_app_is_on_it(security):
    n = eb.update_notice()
    assert n["kind"] == "auto" and n["serving"] is False
    assert n["headline"] == (
        "Embedding runtime update in progress (manifest v1 -> v2, security fix)"
    )
    assert "switched off meanwhile" in n["consequence"]
    assert "installs this release's runtime by itself" in n["consequence"]
    assert n["advisories"] == ["CVE-2099-0569"]


def test_a_failed_attempt_notice_names_the_error_class_and_the_retry(security):
    eb.set_auto_update_failure({"failures": 3, "error_class": "HashMismatch"})
    n = eb.update_notice()
    assert n["kind"] == "auto_failed" and n["failures"] == 3
    assert n["headline"].startswith("Embedding runtime update failed, retrying")
    assert "HashMismatch" in n["consequence"] and "3 attempts so far" in n["consequence"]
    assert "tries again by itself" in n["consequence"]
    assert "failed attempt changed nothing" in n["consequence"]


def test_the_alert_reason_is_stable_across_retries(security):
    eb.set_auto_update_failure({"failures": 1, "error_class": "X"})
    first = eb.update_notice()["alert_reason"]
    eb.set_auto_update_failure({"failures": 9, "error_class": "X"})
    assert eb.update_notice()["alert_reason"] == first


def test_the_restart_notice_is_unchanged_by_the_switch(stale, monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", True)
    n = eb.update_notice()
    assert n["kind"] == "restart" and eb.RESTART_MESSAGE in n["consequence"]


def test_the_switch_off_notice_is_the_click_notice(stale, monkeypatch):
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    assert eb.update_notice()["kind"] == "update"


# ---------------------------------------------------------------------------
# The click-request email is silent; a failure has its own urgent email
# ---------------------------------------------------------------------------

def test_the_click_email_does_not_fire_while_the_app_updates_itself(stale):
    assert admin_alerts._embedding_runtime_probe() == (False, {"reason": None})


def test_the_restart_request_still_goes_out_through_the_click_event(stale, monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", True)
    active, ctx = admin_alerts._embedding_runtime_probe()
    assert active and ctx["notice"]["kind"] == "restart"


def test_a_failure_while_the_old_set_serves_and_no_security_is_not_an_email(stale):
    eb.set_auto_update_failure({"failures": 2, "error_class": "X"})
    assert admin_alerts._embedding_auto_failed_probe() == (False, {"reason": None})


def test_a_failure_that_leaves_embedding_off_or_a_security_fix_undone_is_urgent(security):
    assert admin_alerts._embedding_auto_failed_probe() == (False, {"reason": None})  # not failed yet
    eb.set_auto_update_failure({"failures": 1, "error_class": "PipInstallError"})
    active, ctx = admin_alerts._embedding_auto_failed_probe()
    assert active and ctx["notice"]["kind"] == "auto_failed"


def test_the_failure_email_says_the_app_retries_and_asks_for_no_click(security):
    eb.set_auto_update_failure({"failures": 2, "error_class": "PipInstallError"})
    _active, ctx = admin_alerts._embedding_auto_failed_probe()
    ctx["app_url"] = "https://triage.example.test"
    html, text = admin_alerts._assemble_embedding_auto_failed_alert(ctx)
    for needle in ("failed, retrying", "PipInstallError", "security problem",
                   "CVE-2099-0569", "retries by itself", "every 6 hours",
                   "https://triage.example.test/config?tab=ai_backends"):
        assert needle in text, needle
    _no_click(text)
    assert "&lt;" not in text and "<a href=\"https://triage.example.test/config" in html


async def test_the_failure_email_repeats_every_six_hours_until_fixed(db, security):
    evt = EMBEDDING_RUNTIME_AUTO_FAILED_EVENT
    assert evt.repeat_while_degraded is True and evt.cooldown_hours == 6
    eb.set_auto_update_failure({"failures": 1, "error_class": "X"})
    delete_setting(db, _settings_key(evt.key))
    t0 = datetime(2026, 10, 25, tzinfo=timezone.utc)
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert await fire_on_transition(evt, _Cfg(), db, now=t0) == "sent"
        assert await fire_on_transition(evt, _Cfg(), db, now=t0 + timedelta(hours=1)) == "suppressed"
        assert await fire_on_transition(evt, _Cfg(), db, now=t0 + timedelta(hours=7)) == "sent"
        assert send.call_count == 2


# ---------------------------------------------------------------------------
# The after-the-fact success email: ONE, and what changed
# ---------------------------------------------------------------------------

def _record_update(db, **over):
    updated = {
        "at": datetime.now(timezone.utc).isoformat(),
        "from_version": 1, "to_version": 2,
        "security": eb.SECURITY_FIX, "advisories": ["CVE-2099-0569"],
        "restart_required": False,
    }
    updated.update(over)
    ru.record_auto_success(db, updated=updated)
    return updated


def test_no_success_notice_before_an_update(db):
    delete_setting(db, ru.AUTO_STATE_KEY)
    assert admin_alerts._embedding_auto_updated_probe(db) == (False, {"reason": None})


def test_the_success_email_says_what_changed_and_asks_for_nothing(db):
    _record_update(db)
    active, ctx = admin_alerts._embedding_auto_updated_probe(db)
    assert active
    html, text = admin_alerts._assemble_embedding_auto_updated_alert(ctx)
    for needle in ("updated automatically", "v1 -> v2", "yes: this release fixes a security problem",
                   "CVE-2099-0569", "hash-checked", "Nothing to do."):
        assert needle in text, needle
    assert "Nothing to do." in html
    _no_click(text)


def test_the_success_email_names_why_the_runtime_needed_replacing(db):
    _record_update(db, reason="disk_marker_mismatch")
    _active, ctx = admin_alerts._embedding_auto_updated_probe(db)
    html, text = admin_alerts._assemble_embedding_auto_updated_alert(ctx)
    assert "Trigger:   disk_marker_mismatch" in text
    assert "<code>disk_marker_mismatch</code>" in html


def test_a_success_that_needs_a_restart_says_so(db):
    _record_update(db, restart_required=True, security=eb.SECURITY_NONE, advisories=[])
    _active, ctx = admin_alerts._embedding_auto_updated_probe(db)
    html, text = admin_alerts._assemble_embedding_auto_updated_alert(ctx)
    assert "Restart the container to load the new runtime." in text
    assert "Restart the container to load the new runtime." in html
    assert "not marked as a security fix at release" in text


async def test_one_success_email_per_update_not_per_tick(db):
    evt = EMBEDDING_RUNTIME_AUTO_UPDATED_EVENT
    assert evt.repeat_while_degraded is False
    delete_setting(db, _settings_key(evt.key))
    now = datetime.now(timezone.utc)
    _record_update(db, at=(now - timedelta(seconds=10)).isoformat())
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"
        for _ in range(3):
            assert await fire_on_transition(evt, _Cfg(), db) == "suppressed"
        assert send.call_count == 1
        # A second update is a new edge (its timestamp is the reason).
        _record_update(db, at=(now - timedelta(seconds=1)).isoformat())
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"
        assert send.call_count == 2


def test_the_two_new_events_are_registered_once_with_distinct_keys():
    keys = [e.key for e in admin_alerts._iter_registry()]
    for k in ("embedding_runtime_auto_update_failed", "embedding_runtime_auto_updated"):
        assert keys.count(k) == 1
    assert EMBEDDING_RUNTIME_UPDATE_EVENT.key not in (
        EMBEDDING_RUNTIME_AUTO_FAILED_EVENT.key, EMBEDDING_RUNTIME_AUTO_UPDATED_EVENT.key,
    )


# ---------------------------------------------------------------------------
# Daily health: the in-progress / failed section, and the success block once
# ---------------------------------------------------------------------------

def test_the_daily_health_has_no_click_text_while_the_app_updates_itself(db, app, stale):
    from email_triage.web.daily_health import _render_html, _render_text, gather_health_state

    state = gather_health_state(db, app.state.config)
    assert state["embedding_runtime"]["kind"] == "auto"
    html = _render_html(state, app.state.config)
    text = _render_text(state, app.state.config)
    assert "Embedding runtime update in progress" in html and "Embedding runtime update in progress" in text
    _no_click(html)
    _no_click(text)


def test_the_daily_health_shows_the_success_block_inside_the_window_only(db, app, tmp_path, monkeypatch):
    from email_triage.web.daily_health import _render_html, _render_text, gather_health_state

    make_verified_prefix(tmp_path, monkeypatch)
    _record_update(db)
    state = gather_health_state(db, app.state.config)
    eu = state["embedding_runtime_updated"]
    assert eu and eu["headline"] == "Embedding runtime updated automatically"
    # News, not a request: it does NOT flip the subject to Attention.
    assert not any("updated automatically" in r for r in state["attention_reasons"])
    for rendered in (_render_html(state, app.state.config), _render_text(state, app.state.config)):
        assert "Embedding runtime updated automatically" in rendered
        assert "v1 -&gt; v2" in rendered or "v1 -> v2" in rendered
    _record_update(db, at=(datetime.now(timezone.utc) - timedelta(hours=30)).isoformat())
    assert gather_health_state(db, app.state.config)["embedding_runtime_updated"] is None


# ---------------------------------------------------------------------------
# The rendered banner and card (StrictUndefined)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("which", ["stale", "security"])
def test_the_banner_has_no_button_while_the_app_updates_itself(
    client, admin_cookies, strict_undefined_templates, request, which,
):
    request.getfixturevalue(which)
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    assert 'id="embedding-runtime-banner"' in resp.text
    assert "Embedding runtime update in progress (manifest v1 -&gt; v2" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' not in resp.text
    assert "nothing to click" in flat
    if which == "security":
        assert "security fix" in flat and "CVE-2099-0569" in flat


def test_the_banner_after_a_failure_names_the_retry_and_still_has_no_button(
    client, admin_cookies, strict_undefined_templates, security,
):
    eb.set_auto_update_failure({"failures": 2, "error_class": "PipInstallError"})
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    flat = " ".join(resp.text.split())
    assert "Embedding runtime update failed, retrying" in flat
    assert "PipInstallError" in flat and "tries again by itself" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' not in resp.text


@pytest.mark.parametrize("which", ["stale", "security"])
def test_the_card_says_it_is_automatic_and_offers_no_update_button(
    client, admin_cookies, strict_undefined_templates, request, which, db,
):
    request.getfixturevalue(which)
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    resp = client.get("/config/ai-backends/embedding-install-status", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    # The only update control left is the air-gap bundle form, which says so.
    assert "Update embedding runtime</button>" not in flat
    assert "Update from bundle" in flat
    if which == "stale":
        assert "being applied automatically" in flat and "nothing to click" in flat
    else:
        assert "NOT verified" in flat and "by itself" in flat
    assert "Retry the update now" not in flat


@pytest.mark.parametrize("which", ["stale", "security"])
def test_the_card_offers_a_retry_only_after_a_failure(
    client, admin_cookies, strict_undefined_templates, request, which, db,
):
    request.getfixturevalue(which)
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    eb.set_auto_update_failure({"failures": 1, "error_class": "HashMismatch"})
    resp = client.get("/config/ai-backends/embedding-install-status", cookies=admin_cookies)
    flat = " ".join(resp.text.split())
    assert "The last automatic update failed (HashMismatch)" in flat
    assert ">Retry the update now</button>" in flat
    assert "Update embedding runtime</button>" not in flat


def test_the_banner_for_a_non_admin_is_still_absent(client, user_cookies, strict_undefined_templates, stale):
    resp = client.get("/", cookies=user_cookies)
    assert resp.status_code == 200
    assert 'id="embedding-runtime-banner"' not in resp.text
