"""E2E — the consolidated Security tab (commit 9ce73a0).

The "Security" tab gathered three previously-scattered controls onto one
page: account-wide sign-out, hardware (WebAuthn) keys, and API tokens.
This spec is the consolidation regression net — all three sections must
render together on ``/profile/security`` for an authed admin.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_security_tab_consolidates_all_three_sections(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/profile/security")

    # 1. Account security — the "Sign out all sessions" control + its form.
    expect(
        page.get_by_role("button", name=re.compile("Sign out all sessions", re.I))
    ).to_be_visible()
    expect(
        page.locator('form[action="/profile/sign-out-all"]')
    ).to_have_count(1)

    # 2. Passkeys — the WebAuthn registration section. Exact match on the
    # section <h3>: a loose "Passkeys" regex also matches the "Registered
    # passkeys" <h4> subsection (strict-mode violation).
    expect(
        page.get_by_role("heading", name="Passkeys", exact=True)
    ).to_be_visible()
    expect(page.locator("#hw-register-form")).to_have_count(1)

    # 3. API keys — the access-token section + its create form.
    expect(
        page.get_by_role("heading", name=re.compile("API Keys", re.I))
    ).to_be_visible()
    expect(page.locator('form[hx-post="/accounts/api-keys"]')).to_have_count(1)


def test_security_tab_requires_auth(page, base_url):
    """Unauthenticated request must not expose the security controls."""
    page.goto(f"{base_url}/profile/security")
    expect(page.locator('form[action="/profile/sign-out-all"]')).to_have_count(0)
