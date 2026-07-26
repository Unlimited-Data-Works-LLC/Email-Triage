"""E2E — the SearXNG free-text "Look up" → AI-summary path, in a real browser.

The e2e harness boots an INERT server (no egress), so the SearXNG provider
and the LLM summarizer are patched at the module boundary (the server runs
in THIS process, so a module-attribute patch is visible to the route's
lazy imports). Covers the summary card render + Append-to-Details, and the
most-restrictive-wins HIPAA gate via the live multiselect — the
protected/non-protected view contract that only a browser asserts — and the
RAW-results fallback when the LLM summary is unavailable (§3d show-and-pick).
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

_BUNDLE = {
    "results": [
        {"title": "SELENA lupus estrogen", "url": "https://ex.com/a",
         "content": "A phase 3 study of estrogen safety in lupus."},
        {"title": "Second source", "url": "https://ex.com/b", "content": "More."},
    ],
    "corrections": [], "suggestions": [], "answers": [],
}
_SUMMARY = "A phase 3 study of hormone-therapy safety in lupus patients."


def _patches():
    """Configure SearXNG + stub the provider bundle + the LLM summary.
    Module-attribute patches — visible to the in-process server thread's
    lazy imports + the db_call threadpool worker. Also disables the
    per-user search cooldown (window→0): the e2e server is session-scoped,
    so two specs' Look-ups land <3s apart and would rate-limit each other —
    the cooldown itself is covered deterministically by the unit suite."""
    return (
        patch("email_triage.web.db.get_web_search_searxng_url",
              MagicMock(return_value="http://stub:8080")),
        patch("email_triage.actions.web_search.web_search_bundle",
              AsyncMock(return_value=_BUNDLE)),
        patch("email_triage.web.topic_search_summary.summarize_web_results",
              AsyncMock(return_value=_SUMMARY)),
        patch("email_triage.web.routers.ui.profile._TOPIC_SEARCH_RL_WINDOW_SEC",
              0),
    )


def test_summary_card_renders_and_appends(authed_page, base_url):
    page = authed_page
    p_url, p_b, p_s, p_rl = _patches()
    with p_url, p_b, p_s, p_rl:
        page.goto(f"{base_url}/profile/topic-digest/new")
        page.fill("#topic-search-query", "lupus estrogen")
        page.get_by_role("button", name=re.compile("Look up", re.I)).click()
        # The summary card (not the raw fallback) renders.
        expect(page.locator("#topic-web-summary-replace")).to_be_visible(
            timeout=15000)
        # The summary is shown in the card's (visible) paragraph.
        expect(
            page.locator("#topic-search-result article p").first
        ).to_contain_text(_SUMMARY)
        # The Sources list carries the result URLs.
        expect(page.get_by_text(re.compile(r"Sources \(2\)"))).to_be_visible()
        # Append writes the summary into Details.
        page.locator("#topic-web-summary-append").click()
        expect(
            page.locator("#topic-editor-form textarea[name='details']")
        ).to_have_value(re.compile(re.escape(_SUMMARY)))


def test_hipaa_mailbox_forces_registry_only(authed_page, base_url):
    page = authed_page
    p_url, p_b, p_s, p_rl = _patches()
    with p_url, p_b as mock_bundle, p_s as mock_sum, p_rl:
        page.goto(f"{base_url}/profile/topic-digest/new")
        # Select the HIPAA "Clinic Inbox" mailbox via the JS multiselect.
        page.locator(".ms-trigger").first.click()
        page.locator(".ms-option", has_text="Clinic Inbox").click()
        page.keyboard.press("Escape")
        page.fill("#topic-search-query", "free text query")
        page.get_by_role("button", name=re.compile("Look up", re.I)).click()
        # Most-restrictive-wins → registry-only message, NO summary card.
        expect(
            page.get_by_text(re.compile("protected .HIPAA. mailbox", re.I))
        ).to_be_visible(timeout=15000)
        expect(page.locator("#topic-web-summary-replace")).to_have_count(0)
    # The web egress + the LLM never ran.
    mock_bundle.assert_not_awaited()
    mock_sum.assert_not_awaited()


def test_raw_results_fallback_when_summary_unavailable(authed_page, base_url):
    """When the LLM summary is unavailable (backend slow/unhealthy →
    summarize_web_results returns None), the free-text "Look up" degrades to the
    RAW web-results card (§3d show-and-pick) — the operator can still Append a
    result into Details. The AI-summary card must NOT appear."""
    page = authed_page
    with (
        patch("email_triage.web.db.get_web_search_searxng_url",
              MagicMock(return_value="http://stub:8080")),
        patch("email_triage.actions.web_search.web_search_bundle",
              AsyncMock(return_value=_BUNDLE)),
        # Summary unavailable → the route degrades to the raw-results card.
        patch("email_triage.web.topic_search_summary.summarize_web_results",
              AsyncMock(return_value=None)),
        patch("email_triage.web.routers.ui.profile._TOPIC_SEARCH_RL_WINDOW_SEC",
              0),
    ):
        page.goto(f"{base_url}/profile/topic-digest/new")
        page.fill("#topic-search-query", "lupus estrogen")
        page.get_by_role("button", name=re.compile("Look up", re.I)).click()
        # RAW card: the per-result "Append to Details" buttons exist...
        expect(
            page.locator("button.topic-web-append").first
        ).to_be_visible(timeout=15000)
        # ...and the AI-summary card does NOT.
        expect(page.locator("#topic-web-summary-replace")).to_have_count(0)
        # Both whitelisted result titles render (as data).
        expect(page.get_by_text("SELENA lupus estrogen")).to_be_visible()
        # Append the first result's text into Details (client-side, no save).
        page.locator("button.topic-web-append").first.click()
        expect(
            page.locator("#topic-editor-form textarea[name='details']")
        ).to_have_value(re.compile(re.escape("SELENA lupus estrogen")))
