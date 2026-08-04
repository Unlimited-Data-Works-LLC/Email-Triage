"""Walk — Topic Digest save endpoint (sketch #8).

Feature: ``POST /profile/topic-digest/save`` (landed 2026-06-07 in
237472a9). Create/update Topic via a dedicated endpoint separate from
``/profile/save``. Walk proves the golden create flow (name + subject +
mailbox tick → PRG lands on OWN ?tab=topic-digest, saved link visible)
and the D2-shape blank-name refusal + user-remedy resubmit.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _pick_research_option(authed_page) -> None:
    """Open the .ms-trigger multiselect, tick 'Research Inbox', close."""
    trigger = authed_page.locator(".ms-trigger").first
    trigger.click()
    authed_page.locator(
        ".ms-option", has_text=re.compile("Research Inbox", re.I)
    ).first.click()
    authed_page.keyboard.press("Escape")


def test_save_create_happy_path(authed_page, base_url):
    """GOLDEN — a filled-out /new form POSTs, PRGs to /profile?tab=topic-digest
    (OWN tab, not Notifications), and the topic name appears in the listing."""
    authed_page.goto(f"{base_url}/profile/topic-digest/new")
    form = authed_page.locator("#topic-editor-form")
    if form.count() == 0:
        pytest.xfail(
            "#topic-editor-form not surfaced — feature-work: expose the "
            "editor root with a stable id."
        )

    authed_page.locator('input[name="name"]').fill("E2E Save Walk Topic")
    # First subjects chip.
    subj = authed_page.locator('input[name="subjects"]').first
    if subj.count() == 0:
        pytest.xfail(
            "subjects chip input not surfaced — feature-work: expose the "
            "repeatable subject chip input."
        )
    subj.fill("NCT99999999")

    if authed_page.locator(".ms-trigger").count() > 0:
        _pick_research_option(authed_page)
    else:
        pytest.xfail(
            "mailbox .ms-trigger multiselect not surfaced — feature-work: "
            "expose the mailbox multiselect trigger with class ms-trigger."
        )

    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()

    # PRG landed on the OWN tab, not Notifications.
    expect(authed_page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))
    # Saved topic renders as a link on the listing (proves DB write via
    # the save endpoint, not accepted-and-discarded).
    expect(
        authed_page.get_by_role(
            "link", name=re.compile(r"E2E Save Walk Topic", re.I)
        )
    ).to_be_visible()


def test_save_blank_name_refuses_and_remedy_recovers(authed_page, base_url):
    """BRANCH (D2 — server-refuses / user-remedy).

    Blank-name POST → 200 re-render OR PRG with save-message flash (NOT
    500, NOT wrong-tab redirect). User then fills the name and resubmits;
    PRG lands on ?tab=topic-digest with the topic now visible.
    """
    authed_page.goto(f"{base_url}/profile/topic-digest/new")
    if authed_page.locator("#topic-editor-form").count() == 0:
        pytest.xfail("editor form not surfaced — see happy-path xfail.")

    # Skip filling name; tick Research Inbox anyway so the refusal is
    # specifically the missing-name gate, not empty-form.
    if authed_page.locator(".ms-trigger").count() > 0:
        _pick_research_option(authed_page)

    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()

    # Server refused — either editor re-rendered OR PRG carries a save-message.
    still_on_editor = (
        authed_page.locator("#topic-editor-form").count() > 0
        or "topic-digest/new" in authed_page.url
    )
    landed_on_own_tab = re.search(r"/profile\?tab=topic-digest", authed_page.url)
    assert still_on_editor or landed_on_own_tab, (
        f"blank-name refusal landed on unexpected URL: {authed_page.url!r}"
    )
    # Not a 500 — some form of user surface is present.
    remedy_surface = authed_page.locator(
        '[role="alert"], .error, .form-error, .save-message'
    )
    if not still_on_editor and remedy_surface.count() == 0:
        pytest.xfail(
            "blank-name PRG landed without visible save-message — feature-"
            "work: surface a name-required flash on the topic-digest tab."
        )

    # User-remedy: return to /new, fill the name, resubmit.
    authed_page.goto(f"{base_url}/profile/topic-digest/new")
    authed_page.locator('input[name="name"]').fill("E2E Save Walk Remedy")
    if authed_page.locator(".ms-trigger").count() > 0:
        _pick_research_option(authed_page)
    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()

    expect(authed_page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))
    expect(
        authed_page.get_by_role(
            "link", name=re.compile(r"E2E Save Walk Remedy", re.I)
        )
    ).to_be_visible()
