"""Walk — AI Guide-Me page (sketch #4).

Feature: ``GET /help/me`` (landed 2026-06-13 in e5f827e4). Login-gated
AI-assistant landing surface. The LLM backend is forced unhealthy
in-process so the fail-soft FALLBACK renders deterministically — no
real Ollama in e2e.

Distinct file from ``tests/e2e/test_help_me.py`` (the pre-existing spec);
this file lives under the ``walk/`` package so the feature-add-e2e-gate
recognises it as the retrofit walk for the /help/me route.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import force_llm_unhealthy

pytestmark = pytest.mark.e2e


def test_help_me_renders_authed(authed_page, base_url):
    """GOLDEN — the authed user lands on /help/me, the guide question box +
    submit button + four one-click starter buttons render (proves
    StrictUndefined didn't 500 on a missing context var)."""
    force_llm_unhealthy()
    authed_page.goto(f"{base_url}/help/me")
    expect(authed_page.get_by_role("heading", name="Guide me")).to_be_visible()
    expect(authed_page.locator("#guide-question")).to_be_visible()
    expect(authed_page.locator('button[type="submit"]').first).to_be_visible()
    # Four one-click starter buttons (each carries hx-vals).
    expect(authed_page.locator("button[hx-vals]")).to_have_count(4)


def test_help_me_submit_swap(authed_page, base_url):
    """GOLDEN — typing a real question and submitting swaps the guidance
    fragment into #guide-result. With the LLM forced unhealthy the fallback
    copy renders; the POST -> HTMX-swap plumbing is what this asserts."""
    force_llm_unhealthy()
    authed_page.goto(f"{base_url}/help/me")
    authed_page.fill("#guide-question", "How do I connect my email?")
    authed_page.locator('button[type="submit"]').first.click()
    # Wait for the HTMX swap: #guide-result gains a .guide-answer node.
    expect(authed_page.locator("#guide-result .guide-answer")).to_be_visible(
        timeout=10_000,
    )


def test_help_me_unauth_refused(page, base_url):
    """BRANCH (server-refuses -> user-remedy) — an unauthed context hits the
    login-gated route; the guide form is NOT exposed. The remedy is 'sign
    in first', at which point the golden path works."""
    page.goto(f"{base_url}/help/me")
    expect(page.locator("#guide-question")).to_have_count(0)
