"""E2E —  AI "Guide me" page (/help/me) in a real browser.

Proves the user-facing surface end to end: the page renders for an authed
user, the HTMX form actually swaps a guidance fragment into the result
container, and the one-click starter buttons do the same. The LLM backend
is forced unhealthy in-process so the fail-soft FALLBACK renders
deterministically (no Ollama in e2e) — the point is the form → POST → swap
plumbing, which a TestClient string-assert can't prove.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_unauthed_help_me_redirects(page, base_url):
    """Without the session cookie, /help/me must not render the guide form."""
    page.goto(f"{base_url}/help/me")
    expect(page.locator("#guide-question")).to_have_count(0)


def test_authed_help_me_renders(authed_page, base_url):
    """The authed page renders the heading, the question box, the submit
    button, and the four one-click starter buttons."""
    authed_page.goto(f"{base_url}/help/me")
    expect(authed_page.get_by_role("heading", name="Guide me")).to_be_visible()
    expect(authed_page.locator("#guide-question")).to_be_visible()
    expect(authed_page.locator('button[type="submit"]')).to_be_visible()
    # Four starter buttons (each carries hx-vals).
    expect(authed_page.locator("button[hx-vals]")).to_have_count(4)


def test_guide_form_submits_and_swaps(authed_page, base_url):
    """Typed question → submit → HTMX swaps the guidance fragment in. With
    no LLM backend the fail-soft fallback renders, which is exactly the
    plumbing we want to prove in a real browser."""
    from email_triage.llm_health import set_unhealthy
    set_unhealthy("ollama", ttl_seconds=300, reason="e2e-no-backend")

    authed_page.goto(f"{base_url}/help/me")
    authed_page.fill("#guide-question", "How do I connect my email?")
    authed_page.click('button[type="submit"]')

    answer = authed_page.locator("#guide-result .guide-answer")
    expect(answer).to_be_visible()
    # Fail-soft fallback copy points the user at Common Tasks.
    expect(answer).to_contain_text("Common Tasks")


def test_starter_button_swaps(authed_page, base_url):
    """A one-click starter button posts its canned question and swaps the
    guidance fragment in, same as the typed form."""
    from email_triage.llm_health import set_unhealthy
    set_unhealthy("ollama", ttl_seconds=300, reason="e2e-no-backend")

    authed_page.goto(f"{base_url}/help/me")
    authed_page.locator("button[hx-vals]").first.click()
    expect(authed_page.locator("#guide-result .guide-answer")).to_be_visible()
