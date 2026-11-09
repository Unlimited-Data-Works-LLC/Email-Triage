"""E2E — the classification-cache Flush button on the integrations tab.

Regression net for . The config-tabs template refactor (1cbfe6e) dropped
the flush form while leaving the route handler, the GET page's result block,
and the route-behaviour tests all intact — so the flush feature became
UNREACHABLE from the UI. A TestClient string-assert proves the template SOURCE
carries the form; only a real rendered browser page proves an admin can
actually SEE the button on ``/admin/integrations``. This spec is that proof —
the review level that catches a control vanishing from the rendered page.

(Operator standing rule, 2026-06-10: UI fixes are reviewed with Playwright.)
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

_FLUSH_FORM = 'form[action="/admin/integrations/cache/flush"]'
_FLUSH_BTN = re.compile("Flush cached classifications", re.I)


def test_flush_button_renders_on_integrations_tab(authed_page, base_url):
    """The flush form + button RENDER on the integrations page (the 
    regression was this whole form missing from the rendered page)."""
    page = authed_page
    page.goto(f"{base_url}/admin/integrations")

    # The Classification-cache section copy is on the page.
    expect(page.get_by_text("Classification cache").first).to_be_visible()
    # The flush form is wired to the live route, and its button is visible.
    expect(page.locator(_FLUSH_FORM)).to_have_count(1)
    expect(page.get_by_role("button", name=_FLUSH_BTN)).to_be_visible()


def test_flush_button_disabled_without_configured_cache(authed_page, base_url):
    """With no Redis URL configured (the seed state), the button renders
    DISABLED — flushing an unconfigured cache is a no-op, and the template
    guards the control so a stray click can't fire it."""
    page = authed_page
    page.goto(f"{base_url}/admin/integrations")
    expect(page.get_by_role("button", name=_FLUSH_BTN)).to_be_disabled()


def test_flush_route_is_unreachable_when_form_absent_guard(authed_page, base_url):
    """Belt-and-suspenders: the form's action points at the live endpoint, so
    the button is genuinely wired (not a dead decoration). Asserting the
    action attribute pairs the rendered control with the route that 's
    behaviour tests already exercise."""
    page = authed_page
    page.goto(f"{base_url}/admin/integrations")
    action = page.locator(_FLUSH_FORM).get_attribute("action")
    assert action == "/admin/integrations/cache/flush"
