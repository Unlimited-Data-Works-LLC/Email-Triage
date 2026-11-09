"""E2E — the admin retry-queue "Delivery failure" badge.

Real-chromium confirmation that a watcher delivery-failure retry row renders the
plain-English "Delivery failure" flag (not the raw WatchDeliveryFailed qualname)
for an authed admin — the real-browser review the binding UI rule requires for a
template fix.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_retry_queue_renders_delivery_failure_badge(
    authed_page, base_url, e2e_server,
):
    conn = e2e_server["conn"]
    account_id = e2e_server["research_account_id"]
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO watcher_retry_queue ("
        " account_id, provider_type, mailbox, uid, last_error_class, "
        " last_error_msg, last_error_at, state, attempt_count, "
        " next_attempt_at, first_seen_at, created_at, failure_kind"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id, "imap", "INBOX", 1, "WatchDeliveryFailed",
            "escalation webhook returned 500", now, "pending", 0,
            now, now, now, "watch_delivery_failure",
        ),
    )
    conn.commit()

    page = authed_page
    page.goto(f"{base_url}/admin/retry-queue")
    # The plain-English badge renders…
    expect(page.get_by_text("Delivery failure", exact=False)).to_be_visible()
    # …and the raw Python qualname is suppressed for this row.
    assert "WatchDeliveryFailed" not in page.content()
