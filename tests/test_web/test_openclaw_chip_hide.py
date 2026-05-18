"""Tests for #96 — the OpenClaw chip + Pause / quiet-hours controls
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
    def test_no_webhooks_hides_openclaw_chip(
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
        assert f"hx-get=\"/accounts/{acct_id}/openclaw/editor\"" not in text
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
        assert f"openclaw-cell-{acct_id}" in text
        # Hint card is NOT present in this branch.
        assert "No outbound webhook is configured" not in text
