"""Walk — admin/_update_check_stale_banner.html (punch 553, db F-O5-1).

Golden: after enough failed checks the non-dismissable "update check is
failing" banner shows; ONE success clears it (one funnel,
``update_check.record_check_outcome``).

Timestamps come from the real clock. The page renders the banner with
``update_check_stale(now=<real now>)``, which also reports stale when the
last success is older than ``STALE_AFTER_HOURS``. A fixed ``now_iso`` turned
the golden red once the wall clock passed it by that window (main, 2026-10-06).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_golden(authed_page, base_url, e2e_server):
    """GOLDEN — failures raise the banner; one success clears it."""
    from email_triage import update_check as uc
    conn = e2e_server["conn"]
    try:
        for _ in range(uc.STALE_AFTER_FAILURES):
            uc.record_check_outcome(conn, uc.OUTCOME_FAILED, now_iso=_now_iso())
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        banner = authed_page.locator("#update-check-stale-banner")
        expect(banner).to_be_visible()
        expect(banner).to_contain_text("api.github.com")
        expect(banner.locator("button")).to_have_count(0)

        uc.record_check_outcome(conn, uc.OUTCOME_OK, now_iso=_now_iso())
        authed_page.reload()
        expect(authed_page.locator("#update-check-stale-banner")).to_have_count(0)
    finally:
        uc.record_check_outcome(conn, uc.OUTCOME_OFF, now_iso=_now_iso())


def test_server_refuses_remedy(authed_page, base_url, e2e_server):
    """BRANCH — below the failure threshold nothing is shown (no false alarm)."""
    from email_triage import update_check as uc
    conn = e2e_server["conn"]
    try:
        uc.record_check_outcome(conn, uc.OUTCOME_FAILED, now_iso=_now_iso())
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        expect(authed_page.locator("#update-check-stale-banner")).to_have_count(0)
    finally:
        uc.record_check_outcome(conn, uc.OUTCOME_OFF, now_iso=_now_iso())
