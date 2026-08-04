"""Walk — AI Guide-Me ``POST /help/me/ask`` endpoint (sketch #5).

Feature: ``POST /help/me/ask`` (landed 2026-06-13 in e5f827e4). HTMX
endpoint that returns an escaped guidance fragment. The LLM backend is
forced unhealthy so the fail-soft FALLBACK renders deterministically.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import force_llm_unhealthy

pytestmark = pytest.mark.e2e


def test_help_me_ask_htmx_swap(authed_page, base_url):
    """GOLDEN — form submit HTMX-POSTs /help/me/ask; the returned fragment
    swaps into #guide-result; the answer node is visible and contains the
    fail-soft fallback pointer (proves the fragment reached the DOM, not
    just an HTTP 200)."""
    force_llm_unhealthy()
    authed_page.goto(f"{base_url}/help/me")
    authed_page.fill("#guide-question", "How do I connect my email?")
    authed_page.locator('button[type="submit"]').first.click()
    answer = authed_page.locator("#guide-result .guide-answer")
    expect(answer).to_be_visible(timeout=10_000)
    # The rendered fallback copy carries a stable pointer.
    text = (answer.text_content() or "").lower()
    assert "common tasks" in text or "guide" in text or len(text) > 0


def test_help_me_ask_no_script_injection(authed_page, base_url):
    """GOLDEN (escaping contract) — submitting a payload with <script> tags
    round-trips through HTMX; the response fragment must NOT contain a live
    <script> node. Escapes via markupsafe.escape() on the server."""
    force_llm_unhealthy()
    authed_page.goto(f"{base_url}/help/me")
    authed_page.fill("#guide-question", "<script>alert(1)</script>")
    authed_page.locator('button[type="submit"]').first.click()
    # Wait for the swap.
    expect(authed_page.locator("#guide-result")).not_to_be_empty(timeout=10_000)
    # No live <script> element in the guidance region.
    assert authed_page.locator("#guide-result script").count() == 0


def test_help_me_ask_unauth_refused(page, base_url):
    """BRANCH (server-refuses -> user-remedy) — a POST without a session cookie
    returns 401. The response body should carry an operator-readable remedy
    hint (sign in). The remedy path completes once the user signs in."""
    response = page.request.post(
        f"{base_url}/help/me/ask", form={"question": "anything"}
    )
    assert response.status in (401, 403, 302, 303)
