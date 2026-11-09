"""E2E — ℹ️ help tooltips rolled out to admin config tabs.

The reusable help() / help_details() affordance (proven on the Backup tab) was
extended to the genuine no-help gaps: the security tab's developer-keypair form
+ table, and the general tab's health-email content toggles. Most other admin
fields already carry always-visible inline <small> help, so they were left as-is
(duplicating that with hover tooltips would regress accessibility). This spec is
the real-browser proof the new tooltips render on the live page.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_security_tab_devkey_tooltips_render(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/config?tab=security")
    # The "Add a new key" form's 4 fields (name / public_key / ttl / allowlist)
    # now each carry an ℹ️ tooltip. The form always renders (not gated on keys);
    # the registered-keys TABLE headers also got tooltips but only render once a
    # key exists, so this asserts the always-present form ones.
    form = page.locator('form[action="/admin/dev-keys/add"]')
    expect(form).to_have_count(1)
    expect(form.locator("[data-tooltip]")).to_have_count(4)
    expect(form.locator('[data-tooltip*="ed25519"]')).to_have_count(1)


def test_general_tab_content_toggles_tooltip_renders(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/config?tab=general")
    # The health-email "Content toggles" group got a single explanatory ℹ️.
    expect(page.locator('[data-tooltip*="daily health email"]')).to_have_count(1)
