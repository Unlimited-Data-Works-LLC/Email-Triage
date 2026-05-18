"""Tests for the new /profile/watches editor (#154 + #155).

Covers:
  * GET as a regular user lands on the new page (200, audience-comment
    header is visible in the template, multi-account checkboxes
    render).
  * POST /profile/watches/new/save with multi-account ticks inserts
    one ``email_watches`` row per ticked account, all sharing a
    ``watch_group_id``.
  * HIPAA-flagged accounts ticked in the POST are silently dropped
    from the fan-out — the row is never created, regardless of how
    a hand-crafted form payload phrases the request. (We adopt
    "silently dropped" rather than 403 so the rest of the watch
    still saves; the operator sees a save message naming the skipped
    count.)
  * Legacy ``all_accounts`` field, if posted by a stale browser
    cache, is ignored — the multi-select is the source of truth.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest


def _make_account(db, user_id, name, *, hipaa=False) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        " is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (user_id, name, "imap", json.dumps({}), 1 if hipaa else 0,
         now, now),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# GET /profile/watches
# ---------------------------------------------------------------------------


class TestWatchesPage:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get("/profile/watches", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers.get("location", "")

    def test_regular_user_sees_page(
        self, client, db, regular_user, user_cookies,
    ):
        _make_account(db, regular_user["id"], "my-gmail")
        resp = client.get("/profile/watches", cookies=user_cookies)
        assert resp.status_code == 200
        # Page header.
        assert "Watches" in resp.text
        # Audience comment lives in the served template (Jinja strips
        # the `{# … #}` block, so we check a user-facing string).
        assert "match-and-fire" in resp.text.lower() or \
               "watch for a specific" in resp.text.lower()
        # Tab strip includes the new Watches entry.
        assert "/profile/watches" in resp.text
        # CSRF token field is present (regression for the helper test).
        assert 'name="csrf_token"' in resp.text

    def test_hipaa_account_renders_disabled(
        self, client, db, regular_user, user_cookies,
    ):
        _make_account(db, regular_user["id"], "gmail")
        _make_account(db, regular_user["id"], "phi-mailbox", hipaa=True)
        resp = client.get("/profile/watches", cookies=user_cookies)
        assert resp.status_code == 200
        # PHI account name appears + the disabled state + a reason chip.
        assert "phi-mailbox" in resp.text
        assert "disabled" in resp.text
        assert "Protected health info" in resp.text


# ---------------------------------------------------------------------------
# POST /profile/watches/new/save
# ---------------------------------------------------------------------------


class TestWatchesSave:
    def test_multi_account_save_creates_one_row_per_ticked(
        self, client, db, regular_user, user_cookies,
    ):
        """Three ticked accounts → three rows, all sharing watch_group_id."""
        a = _make_account(db, regular_user["id"], "acct-a")
        b = _make_account(db, regular_user["id"], "acct-b")
        c = _make_account(db, regular_user["id"], "acct-c")

        resp = client.post(
            "/profile/watches/new/save",
            cookies=user_cookies,
            data={
                "name": "Multi-account watch",
                "enabled": "1",
                "account_ids": [str(a), str(b), str(c)],
                "from_addr": "boss@",
                "escalate_enabled": "1",
                "escalate_notify_email": "ops@example.com",
            },
            follow_redirects=False,
        )
        # Redirect on success.
        assert resp.status_code == 303, resp.text
        assert "/profile/watches/" in resp.headers["location"]

        rows = db.execute(
            "SELECT watch_id, account_id, name, watch_group_id, "
            "       created_by_user_id "
            "FROM email_watches ORDER BY account_id"
        ).fetchall()
        assert len(rows) == 3
        assert [r["account_id"] for r in rows] == sorted((a, b, c))
        # All three share a single watch_group_id.
        gids = {r["watch_group_id"] for r in rows}
        assert len(gids) == 1 and next(iter(gids))
        # Creator attribution is the actor.
        for r in rows:
            assert r["created_by_user_id"] == regular_user["id"]

    def test_owner_can_tick_own_hipaa_account(
        self, client, db, regular_user, user_cookies,
    ):
        """Owner of a HIPAA-flagged account is first-party per
        §164.502(a) self-disclosure — they CAN tick their own HIPAA
        mailbox in the cross-account editor. 2026-05-11 fix:
        previously HIPAA accounts were dropped for every actor
        including the owner, leaving the operator with zero surface
        to bind a watch to their own HIPAA mailbox after #154
        removed the per-account Watches tab."""
        a = _make_account(db, regular_user["id"], "acct-a")
        phi = _make_account(
            db, regular_user["id"], "phi-mailbox", hipaa=True,
        )

        resp = client.post(
            "/profile/watches/new/save",
            cookies=user_cookies,
            data={
                "name": "Own HIPAA mailbox watch",
                "enabled": "1",
                "account_ids": [str(a), str(phi)],
                "from_addr": "boss@",
                "escalate_enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        rows = db.execute(
            "SELECT account_id FROM email_watches"
        ).fetchall()
        acct_ids = {r["account_id"] for r in rows}
        assert a in acct_ids
        assert phi in acct_ids, (
            "Owner ticking own HIPAA mailbox must produce a watch "
            "row (first-party self-disclosure, §164.502(a))"
        )

    def test_legacy_all_accounts_field_is_ignored(
        self, client, db, regular_user, user_cookies,
    ):
        """A stale browser cache posting the legacy ``all_accounts``
        field must not crash, and must not bind to every account on
        the install — the multi-select is the source of truth."""
        a = _make_account(db, regular_user["id"], "acct-a")
        b = _make_account(db, regular_user["id"], "acct-b")

        # Tick only one account; pass the legacy all_accounts flag too.
        resp = client.post(
            "/profile/watches/new/save",
            cookies=user_cookies,
            data={
                "name": "Tick-one but legacy flag",
                "enabled": "1",
                "account_ids": [str(a)],
                "all_accounts": "1",  # legacy / stale-cache field
                "from_addr": "boss@",
                "escalate_enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        rows = db.execute(
            "SELECT account_id FROM email_watches"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["account_id"] == a

    def test_no_account_ticked_returns_form_error(
        self, client, db, regular_user, user_cookies,
    ):
        """Zero ticks → save fails with a visible error, no rows
        inserted."""
        _make_account(db, regular_user["id"], "acct-a")
        resp = client.post(
            "/profile/watches/new/save",
            cookies=user_cookies,
            data={
                "name": "No targets",
                "enabled": "1",
                "from_addr": "boss@",
                "escalate_enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "at least one account" in resp.text.lower()
        rows = db.execute(
            "SELECT COUNT(*) FROM email_watches"
        ).fetchone()[0]
        assert rows == 0


# ---------------------------------------------------------------------------
# Edit + delete the existing group
# ---------------------------------------------------------------------------


class TestWatchesEditDelete:
    def _seed_group(self, client, db, user, cookies, account_ids):
        """Helper: create a watch group via the POST handler."""
        resp = client.post(
            "/profile/watches/new/save",
            cookies=cookies,
            data={
                "name": "Test Group",
                "enabled": "1",
                "account_ids": [str(a) for a in account_ids],
                "from_addr": "boss@",
                "escalate_enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        location = resp.headers["location"]
        # /profile/watches/<group_id>/edit?saved=1
        group_id = location.split("/profile/watches/", 1)[1].split("/edit")[0]
        return group_id

    def test_edit_page_pre_ticks_existing_accounts(
        self, client, db, regular_user, user_cookies,
    ):
        a = _make_account(db, regular_user["id"], "acct-a")
        b = _make_account(db, regular_user["id"], "acct-b")
        group_id = self._seed_group(
            client, db, regular_user, user_cookies, [a, b],
        )

        resp = client.get(
            f"/profile/watches/{group_id}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Both accounts render with checkboxes; both should be ticked.
        # The checkbox-value pattern is: <input ... name="account_ids"
        # value="<id>" ... checked ...>
        for acct_id in (a, b):
            # Allow attribute ordering / whitespace variance — look
            # for the value=, then anything up to a `checked`, within
            # the same <input ... > tag.
            import re
            match = re.search(
                rf'<input[^>]*\bname="account_ids"[^>]*\bvalue="{acct_id}"[^>]*>',
                resp.text,
            )
            assert match is not None, (
                f"no account_ids input for account {acct_id} in page"
            )
            assert "checked" in match.group(0), (
                f"account {acct_id} should render pre-ticked on edit"
            )

    def test_save_existing_can_add_and_remove_accounts(
        self, client, db, regular_user, user_cookies,
    ):
        a = _make_account(db, regular_user["id"], "acct-a")
        b = _make_account(db, regular_user["id"], "acct-b")
        c = _make_account(db, regular_user["id"], "acct-c")
        group_id = self._seed_group(
            client, db, regular_user, user_cookies, [a, b],
        )

        # Re-save: drop b, add c.
        resp = client.post(
            f"/profile/watches/{group_id}/save",
            cookies=user_cookies,
            data={
                "name": "Test Group",
                "enabled": "1",
                "account_ids": [str(a), str(c)],
                "from_addr": "boss@",
                "escalate_enabled": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        rows = db.execute(
            "SELECT account_id FROM email_watches "
            "WHERE name = 'Test Group' ORDER BY account_id"
        ).fetchall()
        acct_ids = sorted(r["account_id"] for r in rows)
        assert acct_ids == sorted((a, c))

    def test_delete_removes_every_row_in_group(
        self, client, db, regular_user, user_cookies,
    ):
        a = _make_account(db, regular_user["id"], "acct-a")
        b = _make_account(db, regular_user["id"], "acct-b")
        group_id = self._seed_group(
            client, db, regular_user, user_cookies, [a, b],
        )

        resp = client.post(
            f"/profile/watches/{group_id}/delete",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        remaining = db.execute(
            "SELECT COUNT(*) FROM email_watches"
        ).fetchone()[0]
        assert remaining == 0

    def test_other_users_group_returns_404(
        self, client, db, regular_user, admin_user,
        user_cookies, admin_cookies,
    ):
        """Group id from one user is not editable by another."""
        a = _make_account(db, regular_user["id"], "acct-a")
        group_id = self._seed_group(
            client, db, regular_user, user_cookies, [a],
        )
        resp = client.get(
            f"/profile/watches/{group_id}/edit", cookies=admin_cookies,
        )
        # Admin doesn't own this group — 404 (not 403) to avoid
        # enumerating other users' group ids.
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# #156 — webhook hidden behind disclosure + "Send to" field dropped
# ---------------------------------------------------------------------------


class TestWatchesSimplifiedEditor:
    """#156: hide webhook config behind an `<details>` disclosure and
    drop the per-watch "Send to" override. Notify resolves to the
    operator's profile notify_email at fire time."""

    def test_editor_wraps_webhook_in_details(
        self, client, db, regular_user, user_cookies,
    ):
        """Webhook config (checkbox + URL) lives inside a `<details>`
        with an "Advanced" summary, default-collapsed. Non-technical
        operators don't see the webhook fields unless they expand."""
        _make_account(db, regular_user["id"], "acct-a")
        resp = client.get("/profile/watches", cookies=user_cookies)
        assert resp.status_code == 200
        text = resp.text

        # Disclosure element is present with the "Advanced" summary.
        assert "<details" in text
        assert "Advanced" in text
        # Both webhook controls live inside that disclosure block. We
        # check ordering: the <details> opens BEFORE the webhook
        # controls appear, and </details> closes AFTER them.
        details_open = text.find("<details")
        webhook_checkbox = text.find('name="webhook_enabled"')
        webhook_url = text.find('name="webhook_url"')
        details_close = text.find("</details>", details_open)
        assert details_open != -1
        assert webhook_checkbox != -1
        assert webhook_url != -1
        assert details_close != -1
        assert details_open < webhook_checkbox < details_close
        assert details_open < webhook_url < details_close

    def test_editor_omits_send_to_field(
        self, client, db, regular_user, user_cookies,
    ):
        """The "Send to" override input on the notify action is gone.
        Editor template must not render a `name="escalate_notify_email"`
        text input — destination resolves to user profile at fire."""
        _make_account(db, regular_user["id"], "acct-a")
        resp = client.get("/profile/watches", cookies=user_cookies)
        assert resp.status_code == 200
        assert 'name="escalate_notify_email"' not in resp.text

    def test_save_without_to_addr_creates_notify_watch(
        self, client, db, regular_user, user_cookies,
    ):
        """POST without `escalate_notify_email` still creates a notify-
        enabled watch. Stored row carries empty notify_email — fire-
        time resolves to user profile."""
        a = _make_account(db, regular_user["id"], "acct-a")

        resp = client.post(
            "/profile/watches/new/save",
            cookies=user_cookies,
            data={
                "name": "No-send-to watch",
                "enabled": "1",
                "account_ids": [str(a)],
                "from_addr": "boss@",
                "escalate_enabled": "1",
                # NB: no escalate_notify_email field — field is gone
                # from the editor per #156.
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303, resp.text

        row = db.execute(
            "SELECT actions_json FROM email_watches"
        ).fetchone()
        assert row is not None
        actions = json.loads(row["actions_json"])
        assert actions["escalate"]["enabled"] is True
        # Saved with empty notify_email — fire-time resolver handles
        # the lookup against the user profile.
        assert actions["escalate"].get("notify_email", "") == ""

    def test_fire_time_resolves_user_profile_notify_email(
        self, client, db, regular_user, user_cookies,
    ):
        """At fire time, when watch + account both lack a notify
        address, the resolver reads ``users.notify_email``."""
        # Seed the user with a profile notify address.
        db.execute(
            "UPDATE users SET notify_email = ? WHERE id = ?",
            ("profile-notify@example.com", regular_user["id"]),
        )
        db.commit()

        from email_triage.web.watch_runner import _user_notify_email
        resolved = _user_notify_email(db, regular_user["id"])
        assert resolved == "profile-notify@example.com"

    def test_fire_time_user_without_profile_notify_returns_empty(
        self, client, db, regular_user, user_cookies,
    ):
        """No profile notify set → resolver returns empty; the action
        no-ops with a logged "no_notify_email" result."""
        from email_triage.web.watch_runner import _user_notify_email
        # Fixture user has no notify_email set.
        resolved = _user_notify_email(db, regular_user["id"])
        assert resolved == ""

    def test_fire_time_resolution_order_user_profile_fallback(
        self, client, db, regular_user, user_cookies,
    ):
        """End-to-end: watch with empty notify + account config without
        notify_email → fire_one_watch's resolution chain reaches the
        user-profile fallback. We assert the resolver returns the
        right value; full fire is covered elsewhere."""
        import asyncio
        from email_triage.web.email_watches import (
            EmailWatch, WatchActions, EscalateAction,
        )
        from email_triage.web.watch_runner import _user_notify_email

        db.execute(
            "UPDATE users SET notify_email = ? WHERE id = ?",
            ("ops@example.com", regular_user["id"]),
        )
        db.commit()

        a_id = _make_account(db, regular_user["id"], "acct-a")
        watch = EmailWatch(
            watch_id="w_test",
            name="Test",
            enabled=True,
            account_id=a_id,
            actions=WatchActions(
                escalate=EscalateAction(enabled=True, notify_email=""),
            ),
        )
        # Mirror the resolution chain in fire_one_watch.
        account_cfg = {}
        notify = (
            (watch.actions.escalate.notify_email or "").strip()
            or account_cfg.get("notify_email", "")
            or _user_notify_email(db, regular_user["id"])
            or ""
        )
        assert notify == "ops@example.com"
        # Quiet unused-import lints.
        _ = asyncio
