"""Walk — admin/_egress_disclosure_banner.html (punch 553, N-556).

The update check is on by default, so every admin page shows a dismissable
disclosure naming the host it contacts. Proves in a real browser: the banner
renders; its dismiss button posts through htmx (button name/value + the
csrf.js header) and the banner leaves; the dismissal is durable across a
reload; and the banner adds no submit control to the page (the 02af36ff
landing failure).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def _reset(e2e_server):
    """Hermetic: clear the seeded admin's disclosure dismissals."""
    from email_triage.web.db import (
        DISMISSAL_NS_EGRESS_DISCLOSURES, set_user_dismissals,
    )
    conn = e2e_server["conn"]
    uid = conn.execute(
        "SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
    ).fetchone()[0]
    set_user_dismissals(conn, uid, DISMISSAL_NS_EGRESS_DISCLOSURES, [])


def test_golden(authed_page, base_url, e2e_server):
    """GOLDEN — the banner shows, dismisses in place, and stays dismissed."""
    _reset(e2e_server)
    try:
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        banner = authed_page.locator('aside[data-disclosure="update_check"]')
        expect(banner).to_be_visible()
        expect(banner).to_contain_text("api.github.com")
        # The global banner adds no submit control and no form to the page.
        expect(banner.locator('button[type="submit"]')).to_have_count(0)
        expect(banner.locator("form")).to_have_count(0)
        banner.get_by_role("button", name="Got it, hide this").click()
        expect(banner).to_have_count(0)
        authed_page.reload()
        expect(
            authed_page.locator('aside[data-disclosure="update_check"]')
        ).to_have_count(0)
    finally:
        _reset(e2e_server)


def test_server_refuses_remedy(page, base_url):
    """BRANCH — signed out, admin pages (and so the banner) are not served:
    the user is sent to sign in, the remedy path."""
    goto_or_fail(page, f"{base_url}/dashboard")
    expect(page.locator('aside[data-disclosure="update_check"]')).to_have_count(0)
