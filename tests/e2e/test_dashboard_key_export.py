"""E2E —  restore-key freshness on the admin dashboard, in a REAL browser
(binding UI rule). Operator 2026-06-18: it was a full-width strip taking too much
space; now it's a single CLICKABLE line inside the Health card, linking to the
Backup settings page. The e2e seed never exported a key, so the "never" branch
renders. (A TestClient string-assert can't see the rendered admin section.)"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_dashboard_key_export_is_a_clickable_health_line(authed_page, e2e_server):
    page = authed_page
    page.goto(f"{e2e_server['base_url']}/dashboard")

    # The old full-width strip is gone.
    expect(page.locator(".admin-key-export-strip")).to_have_count(0)

    # Now one line inside the Health card.
    health = page.locator(".admin-health-strip")
    expect(health).to_contain_text(re.compile("Last key export", re.I))
    # No key export in the seed → the "never" branch.
    expect(health).to_contain_text(re.compile("never", re.I))
    # Clickable → Backup settings.
    expect(health.locator('a[href="/config?tab=backup"]')).to_have_count(1)
