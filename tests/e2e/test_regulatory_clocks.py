"""E2E — the user-facing /clocks regulatory-deadline page.

Real-browser confirmation (binding feedback_ui_fixes_reviewed_with_playwright)
that the clocks surface renders in chromium for an authed owner: the label +
advisory copy show, and the PHI case_ref does NOT. Complements the TestClient/
StrictUndefined unit view test (tests/test_web/test_regulatory_clocks_page.py).
"""
from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_clock(e2e_server):
    conn = e2e_server["conn"]
    acct_id = e2e_server.get("research_account_id") or e2e_server.get(
        "clinic_account_id"
    )
    from email_triage.db.regulatory_clock import create_clock_candidate
    did = conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        conn, def_id=did, account_id=acct_id,
        case_ref="E2E-SECRET-CASE-REF", responsibility="i_submit",
    )
    conn.commit()
    return iid


def test_clocks_page_renders_label_advisory_and_hides_phi(
    authed_page, base_url, e2e_server,
):
    _seed_clock(e2e_server)
    page = authed_page
    page.goto(f"{base_url}/clocks")

    expect(
        page.get_by_role("heading", name=re.compile("Regulatory deadlines", re.I))
    ).to_be_visible()
    expect(
        page.get_by_text(re.compile("unanticipated-problem", re.I))
    ).to_be_visible()
    # advisory copy (the PD#17 pinned invariant)
    expect(
        page.get_by_text(re.compile("verify each against your SOP", re.I))
    ).to_be_visible()
    # the PHI case_ref must NOT appear anywhere on the page
    expect(page.get_by_text("E2E-SECRET-CASE-REF")).to_have_count(0)


def test_acknowledge_button_updates_the_table_live(
    authed_page, base_url, e2e_server,
):
    iid = _seed_clock(e2e_server)
    conn = e2e_server["conn"]
    conn.execute(
        "UPDATE regulatory_clock_instance SET state='running' WHERE id=?", (iid,)
    )
    conn.commit()
    page = authed_page
    page.goto(f"{base_url}/clocks")
    btn = page.get_by_role(
        "button", name=re.compile("Acknowledge", re.I)
    ).first
    expect(btn).to_be_visible()
    btn.click()  # no hx-confirm on Acknowledge — clean HTMX outerHTML swap
    # the row's status cell flips to "Acknowledged" in-browser
    expect(
        page.get_by_text(re.compile("Acknowledged", re.I))
    ).to_be_visible()


def test_clocks_page_requires_auth(page, base_url):
    page.goto(f"{base_url}/clocks")
    expect(
        page.get_by_role("heading", name=re.compile("Regulatory deadlines", re.I))
    ).to_have_count(0)


def test_deadlines_nav_link_is_discoverable(authed_page, base_url):
    """The  /clocks page must be DISCOVERABLE via the nav, not only by URL.
    Regression: it shipped with NO nav entry, so a user couldn't find the
    feature on the site (operator-flagged 2026-06-15). Drive it through a real
    click from another page that renders base.html's nav."""
    page = authed_page
    page.goto(f"{base_url}/dashboard")
    link = page.get_by_role(
        "link", name=re.compile(r"^Deadlines$", re.I)
    ).first
    expect(link).to_be_visible()
    link.click()
    expect(
        page.get_by_role("heading", name=re.compile("Regulatory deadlines", re.I))
    ).to_be_visible()
    assert "/clocks" in page.url


def test_clock_route_action_is_offered_in_routes_editor(
    authed_page, base_url, e2e_server,
):
    """ — the 'clock' route action (start a regulatory clock when mail hits a
    category) is pickable in the routes editor, and ticking it reveals the
    template + responsibility selects (the operator's create entry point, the
    original-design path). Real browser per the binding UI rule."""
    acct_id = e2e_server.get("research_account_id") or e2e_server.get(
        "clinic_account_id"
    )
    page = authed_page
    page.goto(f"{base_url}/accounts/{acct_id}/routes")
    cb = page.locator('input[name="actions"][value="clock"]').first
    expect(cb).to_be_visible()                       # the action is offered
    cb.check()                                        # reveals its config (onclick)
    expect(
        page.locator('select[name="clock_template"]').first
    ).to_be_visible()
    expect(
        page.locator('select[name="clock_responsibility"]').first
    ).to_be_visible()
