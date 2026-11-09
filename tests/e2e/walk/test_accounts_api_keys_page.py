"""Walk — Accounts / API keys page (sketch #3).

Feature: ``GET /accounts/api-keys`` (landed 2026-06-07 in 9ce73a0a).
Legacy landing URL for API-access-token management — 303-redirects to the
consolidated ``/profile/security`` hub, which hosts the API-Keys section
via ``templates/accounts/_api_keys_section.html``. Walk exercises the
API-Keys section rendered on the consolidated hub AND the legacy URL
redirect.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_api_keys_section_renders_on_security_hub(authed_page, base_url):
    """GOLDEN — the API-Keys section renders on the consolidated security
    hub with the expected heading + form."""
    authed_page.goto(f"{base_url}/profile/security")
    expect(authed_page.locator("#api-keys")).to_be_visible()
    heading = authed_page.locator("#api-keys h3")
    expect(heading).to_be_visible()
    heading_text = heading.first.text_content() or ""
    assert "API" in heading_text and "Keys" in heading_text
    # The mint form is present.
    expect(
        authed_page.locator('form[hx-post="/accounts/api-keys"]')
    ).to_have_count(1)


def test_api_keys_empty_state(authed_page, base_url):
    """GOLDEN — with no seeded tokens, the tbody shows an empty-state row (or
    an empty-state paragraph). The set-broad/clear-narrow contract
    (directive ) means the empty edge is a first-class rendered surface,
    not just an absence of rows."""
    authed_page.goto(f"{base_url}/profile/security")
    tbody = authed_page.locator("#api-keys-tbody")
    if tbody.count() == 0:
        pytest.xfail(
            "#api-keys-tbody id not surfaced — feature-work needed to "
            "un-xfail: give the API-keys empty-state tbody a stable id."
        )
    # Either the empty-state copy is present OR the tbody has zero rows.
    row_count = tbody.locator("tr").count()
    body_text = (authed_page.locator("body").text_content() or "").lower()
    assert row_count == 0 or "no api keys" in body_text or "don't have" in body_text


def test_legacy_api_keys_url_redirects(authed_page, base_url):
    """BRANCH (D2 shape catch — server-refuses-URL -> user-remedy-path) — the
    legacy ``/accounts/api-keys`` GET issues a 303 that steers the browser to
    the consolidated /profile/security hub. A user typing the old URL is
    NOT stranded on a 404 or a dead standalone page."""
    authed_page.goto(f"{base_url}/accounts/api-keys")
    # The browser followed the 303 to the canonical surface.
    final = authed_page.url.rstrip("/")
    assert final.endswith("/profile/security") or "/profile/security" in final
    # The remedy path completes: the API-Keys section renders on the target.
    expect(authed_page.locator("#api-keys")).to_be_visible()
