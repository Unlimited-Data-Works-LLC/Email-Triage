"""Punch 414: the wizard preview's "My last real event" (live) mode.

Spec ``spec_webhook_preview_live_event_mode_2026-07-15``. Four halves:

* the BELT: a HIPAA fire never reaches the store (``record_fire`` + the
  dispatcher call site);
* the SUSPENDERS: the read gate refuses at read time (flag flipped after the
  fire, wildcard target, unmanaged account, system flag), PD#9;
* the VIEW: the endpoint falls back to canned with a banner, the radios render
  under ``StrictUndefined`` (PD#17), and live bytes equal ``render_for_target``;
* the WITNESS: one ``access_log`` row per live render, none for canned, and a
  failed witness refuses live (PD#8).
"""

from __future__ import annotations

import asyncio
import html
import re
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.config import WebhookTarget
from email_triage.web._webhook_live_envelope import (
    LastEnvelopeStore,
    live_refusal_reason,
    webhook_target_identity,
)
from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.events import EventDispatcher

PREVIEW = "/admin/integrations/webhook-preview"
WIRE_TEMPLATE = '{"s":"{{data.subject}}"}'


def _account(db, user_id, *, hipaa=False, name="Acct"):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, 'imap', '{}', ?, ?, ?)",
        (user_id, name, 1 if hipaa else 0, now, now),
    )
    db.commit()
    return cur.lastrowid


def _flag_hipaa(db, account_id):
    db.execute("UPDATE email_accounts SET hipaa = 1 WHERE id = ?", (account_id,))
    db.commit()


def _envelope(account_id=None, subject="LIVE-SUBJECT-XYZ"):
    data = {
        "flow_id": "flow-LIVE-1",
        "category": "billing",
        "subject": subject,
        "sender": "sender@live.invalid",
        "summary": "live summary",
        "pd_routing_key": "LIVE-KEY",
    }
    if account_id is not None:
        data["account_id"] = account_id
    return {"event": "notification", "timestamp": "2026-02-01T10:00:00Z", "data": data}


def _pre_blocks(body):
    return [
        html.unescape(m.group(1))
        for m in re.finditer(r"<pre[^>]*>(.+?)</pre>", body, re.DOTALL)
    ]


def _witness_rows(db):
    return db.execute(
        "SELECT actor_user_id, account_id, detail FROM access_log "
        "WHERE outcome = 'webhook_preview_live_render'"
    ).fetchall()


# ---------------------------------------------------------------------------
# The belt: what may enter the store
# ---------------------------------------------------------------------------

class TestStoreBelt:
    def test_stores_only_a_literal_false(self):
        store = LastEnvelopeStore()
        for flag in (True, None, 0, "", "no"):
            assert store.record_fire(
                0, _envelope(), is_hipaa=flag, account_id=None,
            ) is False
        assert store.last_fire(0) is None
        assert store.record_fire(
            0, _envelope(), is_hipaa=False, account_id="7",
        ) is True
        assert store.last_fire(0)["account_id"] == "7"

    def test_bounded_to_the_last_event_per_target(self):
        store = LastEnvelopeStore()
        store.record_fire(0, _envelope(subject="first"), is_hipaa=False, account_id=None)
        store.record_fire(0, _envelope(subject="second"), is_hipaa=False, account_id=None)
        store.record_fire(1, _envelope(subject="other"), is_hipaa=False, account_id=None)
        assert store.last_fire(0)["envelope"]["data"]["subject"] == "second"
        assert store.last_fire(1)["envelope"]["data"]["subject"] == "other"

    def test_a_later_hipaa_fire_does_not_replace_or_clear_the_entry(self):
        store = LastEnvelopeStore()
        store.record_fire(0, _envelope(subject="kept"), is_hipaa=False, account_id=None)
        store.record_fire(0, _envelope(subject="PHI"), is_hipaa=True, account_id=None)
        assert store.last_fire(0)["envelope"]["data"]["subject"] == "kept"

    def test_reads_and_writes_are_copies(self):
        store = LastEnvelopeStore()
        env = _envelope()
        store.record_fire(0, env, is_hipaa=False, account_id=None)
        env["data"]["subject"] = "mutated after the fire"
        got = store.last_fire(0)
        got["envelope"]["data"]["subject"] = "mutated after the read"
        assert store.last_fire(0)["envelope"]["data"]["subject"] == "LIVE-SUBJECT-XYZ"


class TestDispatcherBelt:
    @staticmethod
    def _fire(targets, *, is_hipaa):
        disp = EventDispatcher(targets=targets)
        disp._http = SimpleNamespace(get=AsyncMock(return_value=None), aclose=AsyncMock())
        with patch.object(
            EventDispatcher, "_deliver", AsyncMock(return_value={"success": True}),
        ):
            asyncio.run(disp.fire(
                "notification", {"subject": "S", "flow_id": "f1"}, is_hipaa=is_hipaa,
            ))
        return disp

    def test_hipaa_fire_bypasses_the_store(self):
        disp = self._fire([WebhookTarget(url="http://127.0.0.1:9/x")], is_hipaa=True)
        assert disp.last_envelopes.last_fire(0) is None

    def test_non_hipaa_fire_is_stored_under_the_target_position(self):
        disp = self._fire([WebhookTarget(url="http://127.0.0.1:9/x")], is_hipaa=False)
        assert disp.last_envelopes.last_fire(0)["envelope"]["data"]["subject"] == "S"

    def test_two_equal_targets_get_separate_keys(self):
        a = WebhookTarget(url="http://127.0.0.1:9/x")
        b = WebhookTarget(url="http://127.0.0.1:9/x")
        assert a == b
        disp = self._fire([a, b], is_hipaa=False)
        assert disp.last_envelopes.last_fire(0) is not None
        assert disp.last_envelopes.last_fire(1) is not None

    def test_scope_is_recorded_with_the_envelope(self):
        disp = EventDispatcher(targets=[
            WebhookTarget(url="http://127.0.0.1:9/x", account_id="5"),
        ])
        disp._http = SimpleNamespace(get=AsyncMock(return_value=None), aclose=AsyncMock())
        with patch.object(
            EventDispatcher, "_deliver", AsyncMock(return_value={"success": True}),
        ):
            asyncio.run(disp.fire("notification", {"x": 1}, is_hipaa=False, account_id="5"))
        assert disp.last_envelopes.last_fire(0)["account_id"] == "5"

    def test_fire_context_account_and_target_identity_are_recorded(self):
        """Punch 414 (hipaa MUST-2): a wildcard target's scope says nothing about the
        account a fire carried, so the fire's own context account is stored too."""
        target = WebhookTarget(url="http://127.0.0.1:9/x")        # wildcard
        disp = EventDispatcher(targets=[target])
        disp._http = SimpleNamespace(get=AsyncMock(return_value=None), aclose=AsyncMock())
        with patch.object(
            EventDispatcher, "_deliver", AsyncMock(return_value={"success": True}),
        ):
            asyncio.run(disp.fire("notification", {"x": 1}, is_hipaa=False, account_id="7"))
        entry = disp.last_envelopes.last_fire(0)
        assert entry["account_id"] is None
        assert entry["fire_account_id"] == "7"
        assert entry["target_identity"] == webhook_target_identity(target)

    def test_target_identity_tracks_url_and_scope_and_hides_the_url(self):
        a = WebhookTarget(url="http://127.0.0.1:9/x?token=SECRET-IN-URL")
        assert webhook_target_identity(a) == webhook_target_identity(
            WebhookTarget(url="http://127.0.0.1:9/x?token=SECRET-IN-URL"))
        assert webhook_target_identity(a) != webhook_target_identity(
            WebhookTarget(url="http://127.0.0.1:9/y?token=SECRET-IN-URL"))
        assert webhook_target_identity(a) != webhook_target_identity(
            WebhookTarget(url="http://127.0.0.1:9/x?token=SECRET-IN-URL", account_id="5"))
        assert "SECRET-IN-URL" not in webhook_target_identity(a)

    def test_clear_forgets_every_entry(self):
        store = LastEnvelopeStore()
        store.record_fire(0, _envelope(), is_hipaa=False, account_id=None)
        store.record_fire(1, _envelope(), is_hipaa=False, account_id=None)
        store.clear()
        assert store.last_fire(0) is None and store.last_fire(1) is None


# ---------------------------------------------------------------------------
# The suspenders: the read gate
# ---------------------------------------------------------------------------

class TestReadGate:
    def test_scoped_non_hipaa_manageable_account_passes(self, db, admin_user):
        aid = _account(db, admin_user["id"])
        assert live_refusal_reason(db, admin_user, [str(aid), str(aid)], _envelope(aid)) is None

    def test_flag_flipped_after_the_fire_refuses(self, db, admin_user):
        aid = _account(db, admin_user["id"])
        store = LastEnvelopeStore()
        store.record_fire(0, _envelope(aid), is_hipaa=False, account_id=str(aid))
        entry = store.last_fire(0)
        assert live_refusal_reason(db, admin_user, [entry["account_id"]], entry["envelope"]) is None
        _flag_hipaa(db, aid)
        reason = live_refusal_reason(db, admin_user, [entry["account_id"]], entry["envelope"])
        assert reason and "HIPAA" in reason

    def test_wildcard_checks_every_account_on_the_install(self, db, admin_user, regular_user):
        _account(db, admin_user["id"], name="clean")
        assert live_refusal_reason(db, admin_user, [None]) is None
        other = _account(db, regular_user["id"], hipaa=True, name="other users PHI")
        reason = live_refusal_reason(db, admin_user, [None, ""])
        assert reason and "HIPAA" in reason
        assert other  # the HIPAA account is NOT one the requester manages

    def test_unmanaged_account_is_refused_even_for_an_admin(self, db, admin_user, regular_user):
        aid = _account(db, regular_user["id"])
        reason = live_refusal_reason(db, admin_user, [str(aid)])
        assert reason and "do not manage" in reason

    def test_envelope_account_outside_the_manageable_set_is_refused(
        self, db, admin_user, regular_user,
    ):
        mine = _account(db, admin_user["id"])
        theirs = _account(db, regular_user["id"])
        reason = live_refusal_reason(db, admin_user, [None], _envelope(theirs))
        assert reason and "do not manage" in reason
        assert mine

    def test_wildcard_fire_context_account_is_checked_when_data_omits_it(
        self, db, admin_user, regular_user,
    ):
        """Punch 414 (hipaa MUST-2, PD#9): the emitter chooses ``data``, so an
        envelope without ``account_id`` must not hide the account the fire carried."""
        mine = _account(db, admin_user["id"])
        theirs = _account(db, regular_user["id"])
        envelope = _envelope()                                  # no data.account_id
        assert "account_id" not in envelope["data"]
        reason = live_refusal_reason(
            db, admin_user, [None], envelope, fire_account_id=str(theirs),
        )
        assert reason and "do not manage" in reason
        assert live_refusal_reason(
            db, admin_user, [None], envelope, fire_account_id=str(mine),
        ) is None

    def test_wildcard_fire_naming_no_account_needs_every_account_manageable(
        self, db, admin_user, regular_user,
    ):
        """db cross-exam: a wildcard store with an unknown account is unbounded, so it
        is shown only to a requester who manages every account on the install."""
        _account(db, admin_user["id"])
        assert live_refusal_reason(db, admin_user, [None], _envelope()) is None
        _account(db, regular_user["id"])
        reason = live_refusal_reason(db, admin_user, [None], _envelope())
        assert reason and "manages every account" in reason
        # A scoped target names its account, so it is not unbounded.
        assert live_refusal_reason(
            db, admin_user, [str(_account(db, admin_user["id"]))], _envelope(),
        ) is None

    def test_target_identity_mismatch_is_refused(self, db, admin_user):
        aid = _account(db, admin_user["id"])
        assert live_refusal_reason(
            db, admin_user, [str(aid)], _envelope(aid),
            stored_target="A", current_target="A",
        ) is None
        reason = live_refusal_reason(
            db, admin_user, [str(aid)], _envelope(aid),
            stored_target="A", current_target="B",
        )
        assert reason and "different target" in reason
        # An entry stored with no identity cannot be bound to the configured target.
        assert live_refusal_reason(
            db, admin_user, [str(aid)], _envelope(aid),
            stored_target=None, current_target="B",
        )

    @pytest.mark.parametrize("scope", ["abc", "999999"])
    def test_invalid_or_missing_account_fails_closed(self, db, admin_user, scope):
        assert live_refusal_reason(db, admin_user, [scope])

    def test_system_hipaa_flag_refuses(self, db, admin_user, monkeypatch):
        import email_triage.triage_logging as tl
        aid = _account(db, admin_user["id"])
        assert live_refusal_reason(db, admin_user, [str(aid)]) is None
        monkeypatch.setattr(tl, "_hipaa_mode", True)
        assert live_refusal_reason(db, admin_user, [str(aid)])
        assert live_refusal_reason(db, admin_user, [None])


# ---------------------------------------------------------------------------
# The endpoint: view, fallback, witness
# ---------------------------------------------------------------------------

class _ConfiguredTargetStore(LastEnvelopeStore):
    """A store whose ``record_fire`` attributes a fire that names no identity to the
    target configured now: what the dispatcher does at fire time, so the endpoint
    tests that seed the store by hand stand for a fire at the configured target."""

    def __init__(self, app) -> None:
        super().__init__()
        self._app = app

    def record_fire(self, *args, target_identity=None, **kwargs):
        if target_identity is None:
            target_identity = webhook_target_identity(self._app.state.config.webhooks[0])
        return super().record_fire(*args, target_identity=target_identity, **kwargs)


@pytest.fixture
def live_env(client, app, db, admin_user, admin_cookies, strict_undefined_templates):
    """Admin session + a configured wildcard-scoped target + an empty store."""
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    client.raise_server_exceptions = True
    store = _ConfiguredTargetStore(app)
    app.state.last_envelope_per_target = store
    saved = app.state.config.webhooks
    app.state.config.webhooks = [WebhookTarget(url="http://hook.invalid/x")]
    try:
        yield SimpleNamespace(client=client, db=db, store=store, admin=admin_user, app=app)
    finally:
        app.state.config.webhooks = saved


def _post(env, *, mode="live", account_id=None, template=WIRE_TEMPLATE):
    data = {
        "target_type": "custom",
        "body_template": template,
        "sample_event": "triage.completed",
        "mode": mode,
    }
    if account_id is not None:
        data["account_id"] = account_id
    return env.client.post(PREVIEW, data=data)


class TestLivePreviewEndpoint:
    def test_live_mode_renders_the_stored_envelope_and_witnesses_it(self, live_env):
        aid = _account(live_env.db, live_env.admin["id"])
        live_env.store.record_fire(0, _envelope(aid), is_hipaa=False, account_id=str(aid))
        resp = _post(live_env, account_id=str(aid))
        assert resp.status_code == 200
        assert '{"s":"LIVE-SUBJECT-XYZ"}' in _pre_blocks(resp.text)[0]
        assert "outbound-preview-live-notice" not in resp.text
        assert re.search(r'value="live"\s+checked', resp.text)
        rows = _witness_rows(live_env.db)
        assert len(rows) == 1
        assert rows[0]["actor_user_id"] == live_env.admin["id"]
        assert rows[0]["account_id"] == aid
        assert "flow-LIVE-1" in rows[0]["detail"]
        assert "LIVE-SUBJECT-XYZ" not in rows[0]["detail"]

    def test_canned_mode_is_unchanged_and_writes_no_witness(self, live_env):
        live_env.store.record_fire(0, _envelope(), is_hipaa=False, account_id=None)
        resp = _post(live_env, mode="canned")
        assert resp.status_code == 200
        assert "Sample subject line" in resp.text
        assert "LIVE-SUBJECT-XYZ" not in resp.text
        assert re.search(r'value="canned"\s+checked', resp.text)
        assert not _witness_rows(live_env.db)

    def test_hipaa_refusal_falls_back_to_canned_without_leaking(self, live_env):
        aid = _account(live_env.db, live_env.admin["id"])
        live_env.store.record_fire(0, _envelope(aid), is_hipaa=False, account_id=str(aid))
        _flag_hipaa(live_env.db, aid)
        resp = _post(live_env, account_id=str(aid))
        assert resp.status_code == 200
        assert "outbound-preview-live-notice" in resp.text
        assert "HIPAA-flagged" in resp.text
        assert "LIVE-SUBJECT-XYZ" not in resp.text
        assert "sender@live.invalid" not in resp.text
        assert "Sample subject line" in resp.text
        # The radio is flipped back to canned out of band.
        assert 'hx-swap-oob="true"' in resp.text
        assert re.search(r'value="canned"\s+checked', resp.text)
        assert not re.search(r'value="live"\s+checked', resp.text)
        assert not _witness_rows(live_env.db)

    def test_form_account_that_is_hipaa_refuses_even_if_the_saved_scope_is_clean(
        self, live_env,
    ):
        clean = _account(live_env.db, live_env.admin["id"], name="clean")
        phi = _account(live_env.db, live_env.admin["id"], hipaa=True, name="phi")
        live_env.store.record_fire(0, _envelope(clean), is_hipaa=False, account_id=str(clean))
        resp = _post(live_env, account_id=str(phi))
        assert "HIPAA-flagged" in resp.text
        assert "LIVE-SUBJECT-XYZ" not in resp.text

    def test_pd9_unmanaged_account_scope_is_refused(self, live_env, regular_user):
        theirs = _account(live_env.db, regular_user["id"])
        live_env.store.record_fire(0, _envelope(theirs), is_hipaa=False, account_id=str(theirs))
        resp = _post(live_env, account_id=str(theirs))
        assert "do not manage" in resp.text
        assert "LIVE-SUBJECT-XYZ" not in resp.text
        assert not _witness_rows(live_env.db)

    @staticmethod
    def _real_fire(env, target, *, account_id, data):
        """Fire through the REAL dispatcher into the endpoint's store."""
        disp = EventDispatcher(
            targets=[target], allow_external=True, last_envelopes=env.store,
        )
        disp._http = SimpleNamespace(get=AsyncMock(return_value=None), aclose=AsyncMock())
        with patch.object(
            EventDispatcher, "_deliver", AsyncMock(return_value={"success": True}),
        ):
            asyncio.run(disp.fire(
                "notification", data, is_hipaa=False, account_id=account_id,
            ))

    def test_wildcard_target_fire_for_an_unmanaged_account_is_refused(
        self, live_env, regular_user,
    ):
        """Punch 414 (hipaa MUST-2): wildcard target + a fire whose ``data`` carries no
        ``account_id`` + an admin who does not manage the fire's account. Before the
        binding the gate reached only the wildcard HIPAA branch and showed it."""
        _account(live_env.db, live_env.admin["id"], name="mine")
        theirs = _account(live_env.db, regular_user["id"], name="theirs")
        self._real_fire(
            live_env, live_env.app.state.config.webhooks[0], account_id=str(theirs),
            data={"subject": "LEAK-SUBJECT-ZZZ", "sender": "leak@live.invalid", "flow_id": "f9"},
        )
        resp = _post(live_env)
        assert resp.status_code == 200
        assert "do not manage" in resp.text
        assert "LEAK-SUBJECT-ZZZ" not in resp.text
        assert "leak@live.invalid" not in resp.text
        assert not _witness_rows(live_env.db)

    def test_wildcard_target_fire_for_a_managed_account_still_renders(self, live_env):
        mine = _account(live_env.db, live_env.admin["id"], name="mine")
        self._real_fire(
            live_env, live_env.app.state.config.webhooks[0], account_id=str(mine),
            data={"subject": "OWN-SUBJECT-QQQ", "flow_id": "f1"},
        )
        resp = _post(live_env)
        assert '{"s":"OWN-SUBJECT-QQQ"}' in _pre_blocks(resp.text)[0]
        assert len(_witness_rows(live_env.db)) == 1

    def test_wildcard_fire_with_no_context_account_is_refused_unless_all_are_managed(
        self, live_env, regular_user,
    ):
        """db cross-exam: ``fire_notification`` without a payload account is an
        account-less fire. Built directly (no in-tree caller omits ``data.account_id``
        today): wildcard target, no context account, no ``data.account_id``."""
        _account(live_env.db, live_env.admin["id"], name="mine")
        target = live_env.app.state.config.webhooks[0]
        self._real_fire(
            live_env, target, account_id=None,
            data={"subject": "NOACCT-SUBJECT-KKK", "flow_id": "f3"},
        )
        assert live_env.store.last_fire(0)["fire_account_id"] is None
        # The admin manages every account on the install: the event renders.
        resp = _post(live_env)
        assert '{"s":"NOACCT-SUBJECT-KKK"}' in _pre_blocks(resp.text)[0]
        # Another user's account appears: the requester no longer manages them all.
        _account(live_env.db, regular_user["id"], name="theirs")
        before = len(_witness_rows(live_env.db))
        resp = _post(live_env)
        assert "manages every account" in resp.text
        assert "NOACCT-SUBJECT-KKK" not in resp.text
        assert len(_witness_rows(live_env.db)) == before

    def test_event_fired_at_a_replaced_target_is_not_shown(self, live_env):
        """Punch 414 (db N2): the store is keyed by POSITION, so after the list changes
        position 0 can be a different target. The old target's event must not render."""
        mine = _account(live_env.db, live_env.admin["id"], name="mine")
        old_target = live_env.app.state.config.webhooks[0]
        self._real_fire(
            live_env, old_target, account_id=str(mine),
            data={"subject": "OLD-TARGET-EVENT", "flow_id": "f1"},
        )
        live_env.app.state.config.webhooks = [WebhookTarget(url="http://other.invalid/y")]
        resp = _post(live_env)
        assert "different target" in resp.text
        assert "OLD-TARGET-EVENT" not in resp.text
        assert not _witness_rows(live_env.db)

    def test_changing_the_target_list_in_the_wizard_clears_the_store(self, live_env):
        mine = _account(live_env.db, live_env.admin["id"], name="mine")
        live_env.store.record_fire(0, _envelope(mine), is_hipaa=False, account_id=None)
        form = {
            "public_url": "", "gmail_topic_name": "",
            "gmail_subscription_sa_email": "", "gmail_audience": "",
            "outbound_webhook_url": "http://hook.invalid/x",     # unchanged
        }
        with patch("email_triage.web.routers.ui._write_config_yaml"):
            live_env.client.post("/admin/integrations/save", data=form, follow_redirects=False)
            assert live_env.store.last_fire(0) is not None, "an unchanged list must keep it"
            form["outbound_webhook_url"] = "http://other.invalid/y"     # replaced
            live_env.client.post("/admin/integrations/save", data=form, follow_redirects=False)
        assert live_env.app.state.config.webhooks[0].url == "http://other.invalid/y"
        assert live_env.store.last_fire(0) is None

    def test_no_event_yet_shows_the_banner_and_canned(self, live_env):
        resp = _post(live_env)
        assert resp.status_code == 200
        assert "No live event yet" in resp.text
        assert "Sample subject line" in resp.text

    def test_no_target_configured_shows_the_banner(self, live_env):
        live_env.app.state.config.webhooks = []
        resp = _post(live_env)
        assert "No live event yet" in resp.text

    @pytest.mark.audit_failure_expected(
        match="webhook_preview_live_render", count=1,
        reason="the witness write fails on purpose: live mode must then be refused",
    )
    def test_failed_witness_refuses_live_mode(self, live_env):
        aid = _account(live_env.db, live_env.admin["id"])
        live_env.store.record_fire(0, _envelope(aid), is_hipaa=False, account_id=str(aid))
        with patch(
            "email_triage.db.audit.record_webhook_preview_live_render",
            side_effect=RuntimeError("chain key missing"),
        ):
            resp = _post(live_env, account_id=str(aid))
        assert resp.status_code == 200
        assert "could not be recorded" in resp.text
        assert "LIVE-SUBJECT-XYZ" not in resp.text

    def test_live_bytes_equal_the_render_for_target_ssot(self, live_env):
        from email_triage.web._webhook_template import render_for_target
        from email_triage.web.routers.integrations import _PreviewTarget
        aid = _account(live_env.db, live_env.admin["id"])
        envelope = _envelope(aid)
        live_env.store.record_fire(0, envelope, is_hipaa=False, account_id=str(aid))
        resp = _post(live_env, account_id=str(aid))
        blocks = _pre_blocks(resp.text)
        target = _PreviewTarget(target_type="custom", body_template=WIRE_TEMPLATE)
        for block, hipaa in ((blocks[0], False), (blocks[1], True)):
            expected = render_for_target(
                envelope, target, is_hipaa=hipaa, resolved_secret="",
                _suppress_audit_log=True,
            ).decode("utf-8", errors="replace")
            assert block == expected

    def test_wizard_page_renders_the_mode_radios(self, live_env):
        resp = live_env.client.get("/config?tab=integrations", follow_redirects=True)
        assert resp.status_code == 200
        assert 'id="outbound-preview-mode"' in resp.text
        assert 'name="outbound_preview_mode" value="canned"' in resp.text
        assert 'name="outbound_preview_mode" value="live"' in resp.text
        assert "etOutboundPreviewVals()" in resp.text
        assert re.search(r'value="canned"\s+checked', resp.text)
