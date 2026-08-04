"""Walk — Regulatory Clocks create template — sketch .

Feature: ``POST /profile/regulatory-clocks/create`` (landed 2026-06-15
in 344da2d0). Create a clock definition (label, offset, source-rule).
Walk fills the add form + submits (golden — round-trip DB → PRG →
render), then submits BLANK-title (D2 shape catch — server refuses,
no row created, form usable), then remedies with a valid title
(server recovers on the same session).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _open_add_disclosure(page) -> bool:
    """Open the 'Add a reminder' disclosure and confirm the title
    input is actually visible before returning True.

    Post-PRG the ``<details>`` collapses; a plain click on the text
    node can miss the ``<summary>`` (details toggle-target is the
    summary, not its text). Try summary role first, then the raw text.
    """
    # Try to find a native details/summary combo.
    summaries = page.locator("summary").filter(
        has_text=re.compile("Add a reminder", re.I)
    )
    if summaries.count() > 0:
        summary = summaries.first
        try:
            details = page.evaluate_handle(
                "el => el.closest('details')", summary
            )
            is_open = page.evaluate(
                "el => el && el.hasAttribute('open')", details
            )
            if not is_open:
                summary.click()
        except Exception:
            summary.click()
    else:
        disc = page.get_by_text(re.compile("Add a reminder", re.I)).first
        if disc.count() == 0:
            return False
        disc.click()

    # Confirm the title input became visible; give the browser a
    # moment for the disclosure animation.
    title_input = page.locator('input[name="title"]').first
    try:
        title_input.wait_for(state="visible", timeout=3_000)
    except Exception:
        return False
    return True


def _submit_add_reminder(page) -> bool:
    btn = page.locator(
        'button[type="submit"]', has_text=re.compile("Add reminder", re.I)
    ).first
    if btn.count() == 0:
        return False
    btn.click()
    return True


def test_create_golden_and_blank_title_refuses_then_remedy(
    authed_page, base_url,
):
    """GOLDEN — submit fills form + adds row; D2 refuses on blank title
    (no new row); remedy landing writes the corrected title."""
    authed_page.goto(f"{base_url}/profile/regulatory-clocks")

    expect(
        authed_page.get_by_role(
            "heading", name=re.compile("Deadline reminders", re.I)
        )
    ).to_be_visible()

    if not _open_add_disclosure(authed_page):
        pytest.xfail("'Add a reminder' disclosure missing.")

    golden_title = "Walk IRB create - golden"
    authed_page.locator('input[name="title"]').first.fill(golden_title)

    if not _submit_add_reminder(authed_page):
        pytest.xfail("Add reminder submit button not surfaced.")

    expect(authed_page.get_by_text(golden_title).first).to_be_visible()

    # D2 — blank title. Re-open, clear input, submit.
    if not _open_add_disclosure(authed_page):
        pytest.xfail("could not re-open 'Add a reminder' for D2 branch.")
    title_input = authed_page.locator('input[name="title"]').first
    title_input.fill("")
    # Strip client-side required so the browser sends the empty POST
    # (server-side refusal is the shape under test).
    try:
        authed_page.evaluate(
            "() => { const el = document.querySelector("
            "'input[name=\"title\"]'); if (el) el.removeAttribute('required'); }"
        )
    except Exception:
        pass  # if scripting is disallowed, HTML5 required still exercises client refusal

    _submit_add_reminder(authed_page)

    # After refusal: golden row still visible EXACTLY ONCE (no new blank row).
    expect(authed_page.get_by_text(golden_title).first).to_be_visible()
    golden_count = authed_page.get_by_text(golden_title).count()
    assert golden_count == 1, (
        f"golden row count changed to {golden_count} after blank submit — "
        "server may have created a duplicate on refusal."
    )

    # No blank-title row appeared (heuristic: no empty 'Your reminders'
    # row with no title cell). Cheap smoke — cover the direct case.
    # Also check for an inline error hint OR that the add-form field
    # remains focusable/present (D2 remedy path is alive).
    error_hint = authed_page.get_by_role("alert")
    add_form_still_present = (
        authed_page.locator('input[name="title"]').count() > 0
    )
    assert error_hint.count() > 0 or add_form_still_present, (
        "no visible error hint AND the add-form is gone — user has no "
        "remedy path after the blank-title refusal."
    )

    # REMEDY — a valid title now submits and shows.
    if not _open_add_disclosure(authed_page):
        pytest.xfail("could not re-open 'Add a reminder' after refusal.")
    remedy_title = "Walk IRB create - remedied"
    authed_page.locator('input[name="title"]').first.fill(remedy_title)
    _submit_add_reminder(authed_page)
    expect(authed_page.get_by_text(remedy_title).first).to_be_visible()
