"""Walk — src/email_triage/web/templates/admin/config_tabs/_webhook_preview_mode.html (template).

Feature (punch 414): the outbound-webhook wizard on ``/admin/integrations`` offers two
preview modes, "Canned demo" and "My last real event". Live mode needs a recorded fire
for the target. A fresh e2e instance has none, so the server refuses live, renders the
canned envelope with the ``#outbound-preview-live-notice`` banner, and re-renders the
radios out-of-band with ``canned`` checked (the effective mode, never the refused one).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e

_MODE = "#outbound-preview-mode"


def test_golden(authed_page, base_url):
    """GOLDEN — the wizard renders both mode radios, with canned checked."""
    goto_or_fail(authed_page, f"{base_url}/admin/integrations")
    fieldset = authed_page.locator(_MODE)
    expect(fieldset).to_have_count(1)
    expect(fieldset.locator('input[value="canned"]')).to_be_checked()
    expect(fieldset.locator('input[value="live"]')).not_to_be_checked()


def test_server_refuses_live_without_an_event(authed_page, base_url):
    """BRANCH (server refuses -> user remedy): with no recorded fire, choosing
    "My last real event" shows the live-mode notice, the preview stays the canned
    sample, and the radios flip back to canned so the operator is never left on a
    refused mode."""
    goto_or_fail(authed_page, f"{base_url}/admin/integrations")
    # click, not check(): check() asserts the radio STAYS checked, and the refusal
    # re-renders it unchecked, which is the behaviour this walk proves.
    # The preview lives in the collapsed "Advanced: raw body template" section.
    authed_page.locator("summary", has_text="Advanced: raw body template").click()
    live = authed_page.locator(f'{_MODE} input[value="live"]')
    # The response wait proves the HTMX round-trip fires: a `js:` hx-vals that is not an
    # object literal throws inside htmx and sends nothing (a 414 regression caught here).
    with authed_page.expect_response("**/admin/integrations/webhook-preview") as resp:
        live.click()
    assert resp.value.status == 200, resp.value.status
    assert "mode=live" in (resp.value.request.post_data or ""), resp.value.request.post_data
    expect(authed_page.locator("#outbound-preview-live-notice")).to_have_count(1)
    expect(authed_page.locator(f'{_MODE} input[value="canned"]')).to_be_checked()


def test_sample_event_change_sends_the_preview_request(authed_page, base_url):
    """BRANCH — an integrations.html control (not only the mode radios) round-trips:
    changing the sample event POSTs the helper's values, target_type included."""
    goto_or_fail(authed_page, f"{base_url}/admin/integrations")
    authed_page.locator("summary", has_text="Advanced: raw body template").click()
    with authed_page.expect_response("**/admin/integrations/webhook-preview") as resp:
        authed_page.locator("#outbound-preview-sample-event").select_option("flow.classified")
    assert resp.value.status == 200, resp.value.status
    body = resp.value.request.post_data or ""
    assert "target_type=" in body, body
    assert "sample_event=flow.classified" in body, body


def test_server_refuses_remedy(page, base_url):
    """BRANCH — an anon context never sees the mode radios; the remedy is to sign
    in with an admin role."""
    goto_or_fail(page, f"{base_url}/admin/integrations")
    expect(page.locator(_MODE)).to_have_count(0)
