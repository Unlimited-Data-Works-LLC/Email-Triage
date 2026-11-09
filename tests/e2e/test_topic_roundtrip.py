"""E2E — Topic editor full round trip: create -> save -> reopen -> verify.

This is the regression net for the bugs the  editor v2 shipped and we
then fixed, each of which a real-browser round trip catches and the unit
suite did not:

* the mailbox multiselect that rendered/saved blank,
* Save bouncing the user to the wrong tab (it must land on
  ``/profile?tab=topic-digest``),
* digest blocks + retention that saved but did not reload on reopen.

The interaction recipe (open the ``.ms-trigger`` widget, click the
``.ms-option``) was verified against the live UI before being codified.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

TOPIC_NAME = "E2E Round Trip Topic"


def test_create_save_reopen_round_trip(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/profile/topic-digest/new")

    # ---- Fill the editor ----------------------------------------------
    page.fill('input[name="name"]', TOPIC_NAME)
    page.locator('input[name="subjects"]').first.fill("NCT00000419")

    # Mailbox multiselect: open the JS widget, tick "Research Inbox"
    # (non-HIPAA, so the Topic stays out of protected mode), close.
    page.locator(".ms-trigger").first.click()
    page.locator(".ms-option", has_text="Research Inbox").click()
    page.keyboard.press("Escape")
    # The widget must have synced the native (hidden) <select>.
    selected = page.eval_on_selector(
        'select[name="selected_account_ids"]',
        "el => Array.from(el.selectedOptions).map(o => o.value)",
    )
    assert selected == ["1"], f"multiselect did not sync to native select: {selected}"

    # Retention -> 60 days (plain native select).
    page.locator('select[name="retention_days"]').select_option(label="60 days")

    # Add a digest + fill it.
    page.get_by_role("button", name=re.compile("Add a digest", re.I)).click()
    page.fill('input[name="digest-0-name"]', "Daily Brief")
    page.fill('input[name="digest-0-time"]', "22:00")

    # ---- Save ----------------------------------------------------------
    page.get_by_role("button", name=re.compile("Create Topic", re.I)).click()

    # Save MUST land back on the Topic Digest tab (not Notifications).
    expect(page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))
    # The new card is listed.
    expect(page.get_by_role("link", name=TOPIC_NAME)).to_be_visible()

    # ---- Reopen + verify everything persisted -------------------------
    page.get_by_role("link", name=TOPIC_NAME).click()
    expect(page.locator("#topic-editor-form")).to_be_visible()

    # Name round-tripped.
    expect(page.locator('input[name="name"]')).to_have_value(TOPIC_NAME)

    # Mailbox selection round-tripped (option value 1 still selected).
    reopened_selected = page.eval_on_selector(
        'select[name="selected_account_ids"]',
        "el => Array.from(el.selectedOptions).map(o => o.value)",
    )
    assert reopened_selected == ["1"], (
        f"mailbox selection did not persist on reopen: {reopened_selected}"
    )

    # Retention round-tripped.
    expect(page.locator('select[name="retention_days"]')).to_have_value("60")

    # Digest block round-tripped (name + time reloaded, not blank).
    expect(page.locator('input[name="digest-0-name"]')).to_have_value("Daily Brief")
    expect(page.locator('input[name="digest-0-time"]')).to_have_value("22:00")
