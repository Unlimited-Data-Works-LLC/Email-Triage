"""Tests for the /admin/integrations Office 365 sister table (F-4).

Bundle F-followup #4. The admin/integrations page already carries
the Gmail Pub/Sub watches table; this suite covers the new sibling
"Office 365 Push Subscriptions" section that surfaces the install-
wide ``office365_subscriptions`` rows next to the Gmail ones.

Coverage:

* Admin-only gating — anonymous redirects to /login, non-admin user
  gets 403.
* Empty state — admin sees the section header + the "no active
  subscriptions" hint when no rows exist.
* Populated state — table renders with one O365 subscription joined
  against the owning account; account name + id rendered together
  ("name (id N)" format), never bare "Account #N".
* Status bucket rendering — healthy / stale / errored buckets all
  surface in the rendered HTML.

The page also still surfaces the existing Gmail watches table; we
spot-check that in the empty-state test by looking for the Gmail
section header so we don't accidentally remove the Gmail side while
adding the O365 side.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.db import (
    record_o365_subscription_error,
    upsert_o365_subscription,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_o365_account(
    db, *, user_id: int, name: str = "Operator A's Outlook",
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cfg = {"client_id": "test-client-id", "tenant_id": "common"}
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "office365", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Auth gating + base render
# ---------------------------------------------------------------------------


class TestAdminIntegrationsO365Section:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get(
            "/admin/integrations", follow_redirects=False,
        )
        assert resp.status_code in (303, 302)
        assert "/login" in resp.headers.get("location", "")

    def test_non_admin_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/integrations")
        assert resp.status_code == 403

    def test_admin_sees_o365_section_with_empty_state(
        self, client, admin_cookies,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        body = resp.text
        # Sister section header.
        assert "Office 365 Push Subscriptions" in body
        # Empty-state hint points operators at the per-account UI.
        assert "No active Office 365 push subscriptions" in body
        # Sibling Gmail section still renders — the F-4 add doesn't
        # remove the Gmail-side surface.
        assert "Gmail Pub/Sub" in body


# ---------------------------------------------------------------------------
# Table render — populated rows
# ---------------------------------------------------------------------------


class TestAdminIntegrationsO365Table:
    def test_populated_table_renders_account_name_id_format(
        self, client, db, admin_user, admin_cookies,
    ):
        """Account column uses ``<name> (id N)`` per
        feedback_no_account_id_alone.md — never bare ``Account #N``."""
        acct_id = _seed_o365_account(
            db, user_id=admin_user["id"], name="Operator A acct",
        )
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db,
            account_id=acct_id,
            subscription_id="sub-rendered",
            expiration_at=future,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        body = resp.text
        # Subscription id present.
        assert "sub-rendered" in body
        # Account label uses the "name (id N)" pattern.
        assert f"Operator A acct (id {acct_id})" in body
        # Bare "Account #N" must NOT appear (the rule we're guarding).
        assert f"Account #{acct_id}" not in body
        # Resource string surfaces — every Graph mail subscription
        # points at the same Inbox folder so the column is fixed.
        assert "Inbox" in body
        # Status bucket should be healthy (far-future expires_at).
        assert "healthy" in body

    def test_owner_email_visible_in_table(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_o365_account(
            db, user_id=admin_user["id"], name="acct-owner",
        )
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-owner-1",
            expiration_at=future,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        # Owner column shows the user's email.
        assert admin_user["email"] in resp.text

    def test_errored_status_surfaces(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_o365_account(
            db, user_id=admin_user["id"], name="errored-acct",
        )
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-err-1",
            expiration_at=future,
        )
        record_o365_subscription_error(
            db, account_id=acct_id, error_text="Graph rate limited",
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        # Error count surfaces in the status column.
        assert "errors:" in resp.text

    def test_stale_status_surfaces_for_imminent_expiry(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_o365_account(
            db, user_id=admin_user["id"], name="stale-acct",
        )
        # < 4 hours until expiry => "stale" bucket.
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=acct_id,
            subscription_id="sub-stale",
            expiration_at=soon,
        )
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        assert "stale" in resp.text
