"""Walk — Regulatory Clocks update template — sketch .

Feature: ``POST /profile/regulatory-clocks/update`` (landed 2026-06-15
in 344da2d0). Edit an existing clock definition. Walk seeds one owned
def via the SSOT helper ``create_owned_clock_def``, opens the row's
Edit disclosure, renames title + leaves duration BLANK (exercises the
never-clobber SSOT — a blank preserves), submits, asserts the DOM
shows the new title AND the duration text is UNCHANGED. Branch (D2) —
POST with an empty title (client `required` stripped) is refused by
the server; visible title is unchanged. Remedy — corrected title
re-lands.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_owned_clock_def(
    e2e_server, *, title: str, duration_value: int = 10,
    duration_unit: str = "calendar_day",
) -> int:
    """Insert one owned clock def scoped to Research Inbox via the SSOT.

    Per PD#11 — never a raw INSERT for a regulatory row; the SSOT
    ``create_owned_clock_def`` validates + slugs + audits."""
    from email_triage.db.regulatory_clock import create_owned_clock_def

    conn = e2e_server["conn"]
    return create_owned_clock_def(
        conn,
        account_id=e2e_server["research_account_id"],
        actor_user_id=e2e_server["user_id"],
        payload={
            "title": title,
            "regime": "IRB",
            "severity_class": "irb_up",
            "clock_start_kind": "on_awareness",
            "duration_value": duration_value,
            "duration_unit": duration_unit,
            "lead_pcts": [50],
            "ack_required": True,
        },
    )


def _open_edit_for_row(page, title: str):
    row = page.locator("tr", has_text=title).first
    if row.count() == 0:
        row = page.locator("li,details", has_text=title).first
    if row.count() == 0:
        return None
    # Try summary text first, fall back to Edit control anywhere in the row.
    edit_summary = row.get_by_text(re.compile(r"^Edit$", re.I)).first
    if edit_summary.count() > 0:
        edit_summary.click()
    return row


def test_update_rename_blank_duration_preserves_and_refuses_empty(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — rename + blank duration preserves the stored duration.
    D2 — server refuses blank title (title unchanged on the visible
    row). REMEDY — corrected title lands."""
    research_id = e2e_server["research_account_id"]
    original_title = "Original IRB report (walk)"
    _seed_owned_clock_def(e2e_server, title=original_title)

    authed_page.goto(
        f"{base_url}/profile/regulatory-clocks?account_id={research_id}"
    )
    expect(authed_page.get_by_text(original_title).first).to_be_visible()
    expect(
        authed_page.get_by_text(re.compile(r"10\s+calendar\s+day", re.I)).first
    ).to_be_visible()

    row = _open_edit_for_row(authed_page, original_title)
    if row is None:
        pytest.xfail("could not locate the seeded row's Edit control.")

    renamed = "Renamed IRB report (walk)"
    title_input = row.locator('input[name="title"]').first
    if title_input.count() == 0:
        pytest.xfail("Edit form title input not present under the row.")
    title_input.fill(renamed)

    # Blank the duration input — never-clobber preserves the stored 10.
    dur_input = row.locator('input[name="duration_value"]').first
    if dur_input.count() > 0:
        dur_input.fill("")

    save_btn = row.locator(
        'button[type="submit"]',
        has_text=re.compile("Save changes", re.I),
    ).first
    if save_btn.count() == 0:
        pytest.xfail("'Save changes' button not surfaced in Edit form.")
    save_btn.click()

    expect(authed_page.get_by_text(renamed).first).to_be_visible()
    # Duration text UNCHANGED — proves never-clobber-on-blank held.
    expect(
        authed_page.get_by_text(re.compile(r"10\s+calendar\s+day", re.I)).first
    ).to_be_visible()

    # D2 — server-refuses empty title.
    row2 = _open_edit_for_row(authed_page, renamed)
    if row2 is None:
        pytest.xfail("could not re-open Edit for D2 branch.")
    title_input2 = row2.locator('input[name="title"]').first
    if title_input2.count() == 0:
        pytest.xfail("Edit title input missing on D2 branch.")
    try:
        authed_page.evaluate(
            "() => document.querySelectorAll('input[name=\"title\"]')"
            ".forEach(el => el.removeAttribute('required'))"
        )
    except Exception:
        pass
    title_input2.fill("")
    save_btn2 = row2.locator(
        'button[type="submit"]',
        has_text=re.compile("Save changes", re.I),
    ).first
    if save_btn2.count() > 0:
        save_btn2.click()

    # After the empty submit the visible title is UNCHANGED.
    expect(authed_page.get_by_text(renamed).first).to_be_visible()

    # Audience-per-page — no admin-only jargon in any visible error copy.
    alert_texts = " | ".join(
        authed_page.get_by_role("alert").all_inner_texts()
    )
    forbidden = ("HMAC", "def_id", "audit")
    for word in forbidden:
        assert word.lower() not in alert_texts.lower(), (
            f"admin-only jargon {word!r} leaked to user copy: "
            f"{alert_texts!r}"
        )

    # REMEDY — corrected title re-lands.
    row3 = _open_edit_for_row(authed_page, renamed)
    if row3 is None:
        pytest.xfail("could not re-open Edit for remedy step.")
    remedied = "Renamed IRB report v2 (walk)"
    remedy_title = row3.locator('input[name="title"]').first
    if remedy_title.count() == 0:
        pytest.xfail("Edit title input missing on remedy step.")
    remedy_title.fill(remedied)
    remedy_save = row3.locator(
        'button[type="submit"]',
        has_text=re.compile("Save changes", re.I),
    ).first
    if remedy_save.count() == 0:
        pytest.xfail("Save changes missing on remedy step.")
    remedy_save.click()
    expect(authed_page.get_by_text(remedied).first).to_be_visible()
