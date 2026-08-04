"""Tests for  — the webhook chip + Pause / quiet-hours controls
hide on the account edit page when no webhook destinations are
configured at the install level.

The disabled hint card replaces the chip; the 'Edit' button + chip
text must not appear. The hint text must NOT mention admin paths
(/config, /admin/*, "Ask your administrator").
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage.config import WebhookTarget


def _make_account(db, user_id):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, "acct1", "imap",
            json.dumps({"host": "mail.example.com",
                        "username": "u@example.com"}),
            0, now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


class TestChipVisibility:
    def test_no_webhooks_hides_webhook_chip(
        self, client, db, app, admin_user, admin_cookies,
    ):
        """Default config has no webhooks → the chip + Edit button are
        absent; the disabled hint card is present."""
        acct_id = _make_account(db, admin_user["id"])
        # Default test config has empty webhooks list.
        assert getattr(app.state.config, "webhooks", []) == []
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=integrations",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        text = resp.text
        # Chip render emits an Edit button targeting the chip cell;
        # absence of that hx-get is the signal that the chip is hidden.
        assert f"hx-get=\"/accounts/{acct_id}/webhook/editor\"" not in text
        # The disabled-state hint is present.
        assert "No outbound webhook is configured" in text
        # The hint card body itself must NOT contain admin-path copy.
        # We isolate the hint by splitting around the marker text and
        # checking the surrounding ~300 chars.
        idx = text.find("No outbound webhook is configured")
        nearby = text[max(0, idx - 50): idx + 400]
        assert "Ask your administrator" not in nearby
        assert "/config" not in nearby
        assert "/admin/" not in nearby

    def test_with_webhook_shows_chip(
        self, client, db, app, admin_user, admin_cookies,
    ):
        acct_id = _make_account(db, admin_user["id"])
        # Inject a webhook target at the install level.
        app.state.config.webhooks = [WebhookTarget(
            url="http://192.168.1.10:9999/h",
            events=["triage.completed"],
        )]
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=integrations",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        text = resp.text
        # Chip Edit button + cell are present.
        assert f"webhook-cell-{acct_id}" in text
        # Hint card is NOT present in this branch.
        assert "No outbound webhook is configured" not in text


class TestWebhookEndpointRenderSmoke:
    """NTH-1 (devils-advocate): direct render-smoke on the RENAMED UI endpoints.

    A missed route/target/context-key rename would 404 or 500 here rather than
    only showing up in a real browser (PD#17 — test the rendered view)."""

    def _acct_with_webhook(self, db, app, admin_user):
        acct_id = _make_account(db, admin_user["id"])
        app.state.config.webhooks = [WebhookTarget(
            url="http://192.168.1.10:9999/h", events=["triage.completed"],
        )]
        return acct_id

    def test_webhook_editor_fragment_renders(
        self, client, db, app, admin_user, admin_cookies,
    ):
        acct_id = self._acct_with_webhook(db, app, admin_user)
        resp = client.get(
            f"/accounts/{acct_id}/webhook/editor", cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        # The editor posts back to the renamed quiet-hours route + targets the cell.
        assert f"/accounts/{acct_id}/webhook/quiet-hours" in resp.text
        assert f"webhook-cell-{acct_id}" in resp.text
        assert "openclaw" not in resp.text.lower()

    def test_webhook_chip_fragment_renders(
        self, client, db, app, admin_user, admin_cookies,
    ):
        acct_id = self._acct_with_webhook(db, app, admin_user)
        resp = client.get(
            f"/accounts/{acct_id}/webhook/chip", cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        assert "openclaw" not in resp.text.lower()


class TestWebhookSaveSnapshotBackCompat:
    """db-sme F5: the UI save-snapshot reads-both via read_webhook_quiet_raw, so
    an unknown field stored under the LEGACY openclaw_quiet:<id> key survives a
    save (future-proofs the full-overwrite writer against added fields)."""

    def test_ui_save_preserves_unknown_legacy_field(self, db, admin_user):
        from email_triage.web.db import get_setting, set_setting
        from email_triage.web.settings_keys import openclaw_quiet, webhook_quiet
        from email_triage.web.routers.ui._shared import _webhook_quiet_save_snapshot
        acct_id = _make_account(db, admin_user["id"])
        # Pre-rename install: settings (incl. a would-be future field) under the
        # legacy key only.
        set_setting(db, openclaw_quiet(acct_id), {
            "enabled": True, "paused": True,
            "start_utc": "22:00", "end_utc": "08:00", "future_field": "keep-me",
        })
        _webhook_quiet_save_snapshot(
            db, acct_id,
            {"enabled": "on", "paused": "", "start_utc": "09:00", "end_utc": "17:00"},
        )
        saved = get_setting(db, webhook_quiet(acct_id))
        assert saved is not None                       # write landed on the new key
        assert saved["future_field"] == "keep-me"      # unknown legacy field survived
        assert saved["start_utc"] == "09:00"           # form field applied
        assert saved["paused"] is False                # form field applied
