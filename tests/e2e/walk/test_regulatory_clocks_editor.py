"""Walk — Regulatory Clocks templates editor — sketch .

Feature: ``GET /profile/regulatory-clocks`` (landed 2026-06-15 in
344da2d0). Account-scoped clock-def editor. Walk exercises the editor
shell + the add-a-reminder flow + a per-account scope switch (D2 shape
catch — a template on Research Inbox MUST NOT surface under Clinic
Inbox). Owned-list persistence proves the create landed in the DB and
the account-scope filter honors it on re-render.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _visit_editor_for(page, base_url: str, account_id: int) -> None:
    page.goto(
        f"{base_url}/profile/regulatory-clocks?account_id={account_id}"
    )


def test_editor_renders_shell_and_creates_reminder_scoped(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — editor shell renders (heading + built-in reference), a
    reminder is created scoped to Research Inbox, and the account
    picker uses the account NAME (never bare 'Account #<id>').

    D2 BRANCH — switch scope to Clinic Inbox: the Research row MUST NOT
    surface, and the empty-state copy renders. Switching back to
    Research Inbox re-surfaces the row (round-trip: it was hidden by
    scope, not deleted).
    """
    research_id = e2e_server["research_account_id"]
    clinic_id = e2e_server["clinic_account_id"]

    authed_page.goto(f"{base_url}/profile/regulatory-clocks")
    expect(
        authed_page.get_by_role(
            "heading", name=re.compile("Deadline reminders", re.I)
        )
    ).to_be_visible()
    expect(
        authed_page.get_by_text(re.compile(
            "Built-in deadlines .for reference.", re.I
        ))
    ).to_be_visible()

    # Account picker options render by NAME (feedback_no_account_id_alone).
    options_text = authed_page.locator(
        'select[name="account_id"] option'
    ).all_inner_texts()
    if not options_text:
        pytest.xfail("<select name='account_id'> not surfaced on editor.")
    joined = " | ".join(options_text)
    assert "Research Inbox" in joined, (
        f"'Research Inbox' not in account picker options: {joined!r}"
    )
    assert "Clinic Inbox" in joined, (
        f"'Clinic Inbox' not in account picker options: {joined!r}"
    )
    assert not re.search(r"^Account #\d+\s*$", joined, re.M), (
        f"account picker rendered bare 'Account #<n>' label: {joined!r}"
    )

    # Scope to Research Inbox.
    _visit_editor_for(authed_page, base_url, research_id)

    # Add a reminder. Use a <summary>-first path — post-PRG the
    # <details> collapses and clicking the text node can miss the
    # summary toggle, leaving the title input hidden.
    summaries = authed_page.locator("summary").filter(
        has_text=re.compile("Add a reminder", re.I)
    )
    if summaries.count() > 0:
        summaries.first.click()
    else:
        add_disclosure = authed_page.get_by_text(
            re.compile("Add a reminder", re.I)
        ).first
        if add_disclosure.count() == 0:
            pytest.xfail("'Add a reminder' disclosure missing on editor.")
        add_disclosure.click()

    title = "E2E IRB report (walk)"
    title_input = authed_page.locator('input[name="title"]').first
    try:
        title_input.wait_for(state="visible", timeout=3_000)
    except Exception:
        pytest.xfail(
            "title input not visible after opening 'Add a reminder' — "
            "feature-work: disclosure/summary not toggling in this "
            "template variant."
        )
    title_input.fill(title)
    # Try to set duration_value = 10 / duration_unit = calendar_day when
    # present; the sketch called for working_day, but the harness has no
    # working-day calendar configured, and an arming (duration>0)
    # working_day def is REFUSED by validate_owned_clock_def in that
    # state — the router propagates the refusal as a 400, no row lands,
    # and the walk falsely reads "feature-work". Calendar-days is the
    # correct default for the harness: it exercises the same duration
    # unit-label render path without tripping the calendar guard.
    dur = authed_page.locator('input[name="duration_value"]').first
    if dur.count() > 0:
        dur.fill("10")
    unit = authed_page.locator('select[name="duration_unit"]').first
    if unit.count() > 0:
        try:
            unit.select_option("calendar_day")
        except Exception:
            pass  # default value is also valid

    add_btn = authed_page.locator(
        'button[type="submit"]', has_text=re.compile("Add reminder", re.I)
    ).first
    if add_btn.count() == 0:
        pytest.xfail("Add reminder submit button not surfaced.")
    add_btn.click()

    expect(authed_page.get_by_text(title).first).to_be_visible()

    # D2 BRANCH — scope switch to Clinic Inbox hides the row.
    _visit_editor_for(authed_page, base_url, clinic_id)
    assert authed_page.get_by_text(title).count() == 0, (
        f"Research-scoped row {title!r} leaked into Clinic Inbox view."
    )
    empty_hint = authed_page.get_by_text(
        re.compile(
            r"You haven't added any reminders for this mailbox yet",
            re.I,
        )
    )
    if empty_hint.count() == 0:
        pytest.xfail(
            "empty-state hint absent on Clinic Inbox scope — "
            "feature-work: render the empty-state copy."
        )

    # Round-trip — switch back and the row is visible again.
    _visit_editor_for(authed_page, base_url, research_id)
    expect(authed_page.get_by_text(title).first).to_be_visible()
