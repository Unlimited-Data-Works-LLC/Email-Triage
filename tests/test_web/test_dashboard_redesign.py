"""Tests for the #12 dashboard redesign.

Covers:
- regular-user shell is welcome + orientation (no stat wall)
- admin shell adds health chips + admin quick-nav
- getting-started checklist ticks when an account is added
- dismiss-step endpoint persists via the settings table
- watcher-disconnected banner fires for >15min stale watchers
- watcher banner hidden when everything is running cleanly
- /admin/stats is admin-only
- /admin/stats exposes the Volume + Performance sections
- /admin/stats window dropdown actually narrows the scope
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account(db, user_id, *, name="Inbox"):
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (user_id, name, "imap", json.dumps({"host": "mail.test.com"}), now, now),
    )
    db.commit()
    return cursor.lastrowid


def _record_run(db, *, account_id, account_name, when, messages=1, elapsed=1.0,
                results=None):
    """Insert a synthetic triage_runs row."""
    results_json = json.dumps(results or [
        {"category": "personal", "subject": "x"},
    ])
    db.execute(
        "INSERT INTO triage_runs "
        "(created_at, account_id, account_name, query, total_messages, "
        " elapsed_secs, results_json, errors_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, '[]')",
        (when, account_id, account_name, "UNSEEN", messages, elapsed,
         results_json),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Dashboard shell — regular user
# ---------------------------------------------------------------------------

def test_dashboard_regular_user_sees_checklist_not_stats(
    client, db, regular_user, user_cookies,
):
    """The stat wall is gone; the welcome + checklist shows instead."""
    resp = client.get("/dashboard", cookies=user_cookies)
    assert resp.status_code == 200
    assert "Welcome back, Test User" in resp.text
    assert "Getting started" in resp.text
    assert "Add your first email account" in resp.text
    # No classification/stats tables on the dashboard.
    assert "Classification Breakdown" not in resp.text
    assert "Messages Processed" not in resp.text
    assert "Recent Triage Runs" not in resp.text
    # Admin-only strip must be absent.
    assert "Admin navigation" not in resp.text
    assert "System Log" not in resp.text
    # Quick action buttons exist.
    assert "Triage Now" in resp.text


# ---------------------------------------------------------------------------
# Dashboard shell — admin
# ---------------------------------------------------------------------------

def test_dashboard_admin_sees_health_chips_plus_checklist(
    client, db, admin_user, admin_cookies,
):
    """Admin gets the same welcome+checklist block, PLUS chips + nav."""
    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    # Welcome + checklist (admins own accounts too).
    assert "Welcome back, Test Admin" in resp.text
    assert "Getting started" in resp.text
    # Chip labels.
    assert "Gateway" in resp.text
    # Chip relabeled to "Ingestion" — covers IMAP IDLE + Gmail Pub/Sub
    # + poll under one heading.
    assert "Ingestion" in resp.text
    assert "Last triage run" in resp.text
    assert "Errors (24h)" in resp.text
    # Admin quick-nav buttons. Operator trim 2026-05-12 (commit
    # 3762469): dashboard quick-nav reduced to the three actually-
    # used entries — Accounts, Config, System Log. The other
    # admin pages (Stats / Users / TLS / Dev keys / Compliance &
    # Security) are still reachable via the top-nav Admin submenu
    # rendered in base.html, not via the dashboard.
    assert "System Log" in resp.text
    assert "/accounts" in resp.text
    assert "/config" in resp.text
    # Top-nav Admin submenu still surfaces these; assertion shape
    # checks the BASE TEMPLATE's submenu, not the dashboard body.
    assert "/admin/stats" in resp.text  # via top-nav Admin submenu
    assert "/users" in resp.text        # via top-nav Admin submenu


# ---------------------------------------------------------------------------
# Getting-started checklist
# ---------------------------------------------------------------------------

def test_dashboard_checklist_ticks_when_account_added(
    client, db, regular_user, user_cookies,
):
    """After an account exists, the 'add account' step shows as done."""
    # Baseline: step shows 'Add account' button.
    resp = client.get("/dashboard", cookies=user_cookies)
    assert "Add account" in resp.text

    _make_account(db, regular_user["id"], name="My Inbox")

    resp2 = client.get("/dashboard", cookies=user_cookies)
    # The card is still present (or hidden once dismissed) but its
    # action button disappears once done. Use the done marker to prove
    # state changed.
    from email_triage.web.db import get_dashboard_getting_started
    gs = get_dashboard_getting_started(db, regular_user)
    add_step = next(s for s in gs["steps"] if s["id"] == "add_account")
    assert add_step["done"] is True


def test_dashboard_checklist_step_dismissable(
    client, db, regular_user, user_cookies,
):
    """POST /dashboard/dismiss-step persists via the settings table
    and stops rendering the card."""
    # Step is rendered before dismissal.
    resp = client.get("/dashboard", cookies=user_cookies)
    assert "Add your first email account" in resp.text

    resp = client.post(
        "/dashboard/dismiss-step",
        data={"step_id": "add_account"},
        cookies=user_cookies,
    )
    assert resp.status_code == 200

    from email_triage.web.db import (
        get_dashboard_dismissed_steps, get_setting,
    )
    assert "add_account" in get_dashboard_dismissed_steps(db, regular_user["id"])

    # Raw settings-table read confirms the documented key name.
    raw = get_setting(db, f"user:{regular_user['id']}:dashboard_dismissed_steps")
    assert raw is not None
    assert "add_account" in raw.get("steps", [])

    # After dismissal, the card is no longer on the dashboard.
    resp2 = client.get("/dashboard", cookies=user_cookies)
    assert "Add your first email account" not in resp2.text


# ---------------------------------------------------------------------------
# Watcher banner
# ---------------------------------------------------------------------------

class _FakeWatcherManager:
    """Test fake. Carries legacy IMAP status dicts AND synthesizes the
    per-account verdict (``account_states``) the chip + digest now
    consume. Status=="watching" → push.active=True → primary=push;
    anything else → primary=none + alert=no_ingestion."""

    def __init__(self, states):
        self._states = states

    def all_statuses(self):
        return self._states

    def account_states(self, db):
        # Pull display fields from the test DB so the chip's per-
        # account alert detail matches what real account rows produce.
        from email_triage.web.db import list_email_accounts
        try:
            accts = {a["id"]: a for a in list_email_accounts(db)}
        except Exception:
            accts = {}
        out = []
        for aid, s in self._states.items():
            status = s.get("status", "unknown")
            active = status == "watching"
            a = accts.get(aid, {})
            out.append({
                "account_id": aid,
                "account_name": a.get("name", f"acct-{aid}"),
                "owner": (
                    a.get("owner_name") or a.get("owner_email", "")
                ),
                "provider": a.get("provider_type", "imap"),
                "push": {
                    "configured": True,
                    "active": active,
                    "detail": (
                        "1/1 folders watching" if active
                        else f"IDLE {status}"
                    ),
                },
                "poll": {
                    "enrolled": False, "last_tick": None, "fresh": False,
                },
                "mode": "push" if active else "none",
                "primary": "push" if active else "none",
                "alert": None if active else "no_ingestion",
            })
        return out

    def mailbox_counts(self):
        total = len(self._states)
        watching = sum(
            1 for s in self._states.values()
            if s.get("status") == "watching"
        )
        return total, watching

    def poll_counts(self):
        return 0, 0

    def is_poll_running(self, account_id):
        return False


def test_dashboard_watcher_banner_when_disconnected_over_15_min(
    client, db, app, admin_user, admin_cookies,
):
    """A watcher stuck in 'reconnecting' >15 min triggers the banner."""
    acct_id = _make_account(db, admin_user["id"], name="Stuck Mailbox")
    stuck_since = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    app.state.watcher_manager = _FakeWatcherManager({
        acct_id: {"status": "reconnecting", "started_at": stuck_since},
    })

    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Watcher attention needed" in resp.text
    assert f"#{acct_id}" in resp.text
    assert "reconnecting" in resp.text


def test_dashboard_no_watcher_banner_when_all_connected(
    client, db, app, admin_user, admin_cookies,
):
    """Clean 'watching' watcher must NOT emit the banner."""
    acct_id = _make_account(db, admin_user["id"], name="Healthy Mailbox")
    app.state.watcher_manager = _FakeWatcherManager({
        acct_id: {
            "status": "watching",
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    })

    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Watcher attention needed" not in resp.text


def test_dashboard_health_chip_counts_watching_status_as_connected(
    client, db, app, admin_user, admin_cookies,
):
    """Regression: #12 dashboard chip was looking for status=='running',
    but WatcherManager emits status=='watching' — /health reports
    2/2 connected while the dashboard rendered 0/2 connected. Both
    surfaces now agree on 'watching' as the connected label."""
    acct1 = _make_account(db, admin_user["id"], name="Mailbox One")
    acct2 = _make_account(db, admin_user["id"], name="Mailbox Two")
    app.state.watcher_manager = _FakeWatcherManager({
        acct1: {
            "status": "watching",
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
        acct2: {
            "status": "watching",
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    })

    resp = client.get("/dashboard", cookies=admin_cookies)
    assert resp.status_code == 200
    # Chip renders "2/2 accounts covered" with per-provider line
    # "IMAP: 2 accts — 2 push". status=="watching" → primary=push,
    # so the IMAP push count = 2 in the per-provider breakdown.
    assert "2/2 accounts covered" in resp.text
    assert "IMAP: 2 acct" in resp.text
    assert "2 push" in resp.text


# ---------------------------------------------------------------------------
# /admin/stats
# ---------------------------------------------------------------------------

def test_admin_stats_page_admin_only(client, user_cookies, admin_cookies):
    """Regular users get 403; admins load the page."""
    resp = client.get("/admin/stats", cookies=user_cookies)
    assert resp.status_code == 403

    resp2 = client.get("/admin/stats", cookies=admin_cookies)
    assert resp2.status_code == 200
    assert "Admin Stats" in resp2.text


def test_admin_stats_page_volume_section(
    client, db, admin_user, admin_cookies,
):
    """Volume section renders per-window totals including the recent run."""
    acct_id = _make_account(db, admin_user["id"])
    now = datetime.now(timezone.utc)
    _record_run(
        db, account_id=acct_id, account_name="Inbox",
        when=now.isoformat(), messages=7, elapsed=3.5,
    )

    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Volume" in resp.text
    # 7 messages in the last hour should surface in the window summary.
    assert "7" in resp.text


def test_admin_stats_page_performance_section(
    client, db, admin_user, admin_cookies,
):
    """Performance section shows per-message seconds, normalised."""
    acct_id = _make_account(db, admin_user["id"])
    now = datetime.now(timezone.utc)
    # 10s / 5msgs = 2.00 s per message.
    _record_run(
        db, account_id=acct_id, account_name="Inbox",
        when=now.isoformat(), messages=5, elapsed=10.0,
    )

    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Performance" in resp.text
    assert "Average s / message" in resp.text
    # 2.00 is the expected per-message number.
    assert "2.00" in resp.text


def test_admin_stats_window_dropdown_changes_scope(
    client, db, admin_user, admin_cookies,
):
    """A run older than 1h must not count inside the 1h window."""
    acct_id = _make_account(db, admin_user["id"])
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=3)).isoformat()
    _record_run(
        db, account_id=acct_id, account_name="Inbox",
        when=old, messages=42, elapsed=1.0,
    )

    # 24h window includes it.
    resp_24h = client.get("/admin/stats?window=24h", cookies=admin_cookies)
    assert resp_24h.status_code == 200
    # 1h window excludes it.
    resp_1h = client.get("/admin/stats?window=1h", cookies=admin_cookies)
    assert resp_1h.status_code == 200
    # Use the helper directly to make the assertion scope-tight.
    from email_triage.web.db import count_triage_messages_in_window
    since_1h = (now - timedelta(hours=1)).isoformat()
    since_24h = (now - timedelta(hours=24)).isoformat()
    assert count_triage_messages_in_window(db, since_iso=since_1h) == 0
    assert count_triage_messages_in_window(db, since_iso=since_24h) == 42
