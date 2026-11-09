"""Walk — admin/_security_update_banner.html (punch 553, N-556).

Golden: with persisted-shape facts for a newer security release, every admin
page shows the urgent banner, which has NO dismiss control. Branch: a release
link that is not https (a ``javascript:`` value) never becomes a link.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e

_MARKER = (
    '<!-- email-triage-release-meta: {"schema": 1, "security": true, '
    '"severity": "critical", "min_secure_version": "99.0.0", '
    '"advisories": ["GHSA-1111-2222-3333"]} -->'
)


def _set_facts(e2e_server, html_url):
    from email_triage.update_check import parse_release_payload
    e2e_server["app"].state.update_check_facts = parse_release_payload(
        {"tag_name": "v99.0.0", "html_url": html_url, "body": _MARKER},
        checked_at="2026-10-03T00:00:00+00:00",
    )


def test_golden(authed_page, base_url, e2e_server):
    """GOLDEN — the urgent banner renders and cannot be dismissed."""
    _set_facts(e2e_server, "https://github.com/c-laforest/email-triage/releases/tag/v99.0.0")
    try:
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        banner = authed_page.locator("#security-update-banner")
        expect(banner).to_be_visible()
        expect(banner).to_contain_text("Security update required")
        expect(banner).to_contain_text("GHSA-1111-2222-3333")
        expect(banner.locator("button")).to_have_count(0)
        expect(banner.locator("form")).to_have_count(0)
    finally:
        e2e_server["app"].state.update_check_facts = None


def test_server_refuses_remedy(authed_page, base_url, e2e_server):
    """BRANCH — an unsafe release link is refused: the banner still warns,
    but carries no link (the remedy is the release page itself)."""
    _set_facts(e2e_server, "javascript:alert(1)")
    try:
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        banner = authed_page.locator("#security-update-banner")
        expect(banner).to_be_visible()
        expect(banner.locator("a")).to_have_count(0)
    finally:
        e2e_server["app"].state.update_check_facts = None
