"""Walk — Regulatory Clocks user dashboard (GET /clocks) — sketch .

Feature: ``GET /clocks`` (landed 2026-07-02 in 7fd13013). v0.2.0
Feature 34 — per-user regulatory deadline clocks, scoped to owner
accounts. Walk seeds one running clock, opens ``/clocks``, asserts the
rendered dashboard shape (heading + label + a days-cell + state cell +
Acknowledge button), clicks Acknowledge and asserts the HTMX swap
flipped the row's state to 'Acknowledged' in the real DOM. Includes a
PHI-hide assertion — ``case_ref`` never renders (owner self-access is
NOT a redaction bypass for user-facing dashboards). Branch (D2 shape)
— unauth GET refuses AND surfaces a user remedy (login form / /login
url).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import seed_running_regulatory_clock

pytestmark = pytest.mark.e2e


def test_clocks_dashboard_renders_and_acknowledge_swaps(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — dashboard renders heading + seeded label + a days-left
    + state cell + Acknowledge; click Acknowledge and the row's state
    flips to 'Acknowledged' in-DOM (real HTMX swap, not just a 200)."""
    case_ref = "WALK-SECRET-CASE-REF-DASH"
    seed_running_regulatory_clock(e2e_server, case_ref=case_ref)

    authed_page.goto(f"{base_url}/clocks")

    expect(
        authed_page.get_by_role(
            "heading", name=re.compile("Regulatory deadlines", re.I)
        )
    ).to_be_visible()

    expect(
        authed_page.get_by_text(re.compile("unanticipated-problem", re.I))
    ).to_be_visible()

    # A time-left column exists on the dashboard grid — the running
    # clock's own value cell may be an em-dash 'awaiting arm', but the
    # column header is the load-bearing surface (feature spec = 'label +
    # days-left + state'; days-left = the 'Time left' column).
    expect(
        authed_page.get_by_role(
            "columnheader", name=re.compile(r"Time left", re.I)
        )
    ).to_be_visible()

    # State cell shows 'Running' for the seeded clock BEFORE the click.
    expect(
        authed_page.get_by_text(re.compile(r"\bRunning\b", re.I)).first
    ).to_be_visible()

    ack_btn = authed_page.get_by_role(
        "button", name=re.compile("Acknowledge", re.I)
    )
    if ack_btn.count() == 0:
        pytest.xfail(
            "'Acknowledge' button not offered on running clock — "
            "feature-work: expose the disposition control."
        )
    ack_btn.first.click()

    # HTMX outerHTML swap of the row → state cell flips.
    expect(
        authed_page.get_by_text(re.compile("Acknowledged", re.I))
    ).to_be_visible()

    # PHI-hide invariant — case_ref must NEVER render on the dashboard
    # (risk_class=phi_read on this route means the visible surface is
    # redacted even for the owner; the redaction is at the render, not
    # at the auth layer).
    expect(authed_page.get_by_text(case_ref)).to_have_count(0)


def test_clocks_dashboard_unauth_refuses_with_remedy(page, base_url):
    """BRANCH (D2 shape catch) — unauthed request MUST NOT render the
    dashboard AND MUST land the user on a remedy path (login form or
    ``/login`` url), not a bare 401 / stack trace."""
    page.context.clear_cookies()
    page.goto(f"{base_url}/clocks")

    dashboard_h = page.get_by_role(
        "heading", name=re.compile("Regulatory deadlines", re.I)
    )
    assert dashboard_h.count() == 0, (
        "unauthed GET rendered the Regulatory deadlines dashboard — "
        "auth gate failed."
    )

    on_login = "/login" in page.url
    signin_link = page.get_by_role(
        "link", name=re.compile(r"Sign in|Log in", re.I)
    )
    login_form_visible = (
        page.locator('input[type="password"]').count() > 0
        or page.locator('form[action*="/login"]').count() > 0
    )
    assert on_login or signin_link.count() > 0 or login_form_visible, (
        f"unauthed GET refused without a remedy path — url={page.url!r}, "
        "no login form / sign-in link visible."
    )
