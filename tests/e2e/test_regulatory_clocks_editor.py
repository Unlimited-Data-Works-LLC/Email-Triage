"""E2E — the operator-OWNED deadline-template editor renders + a template can be
added in a REAL browser (operator 2026-06-15; binding real-browser review for a
UI change). The TestClient test asserts the HTML; this proves the page renders,
the add-form works, and the new template shows up.
"""
from playwright.sync_api import expect


def test_clock_template_editor_renders_and_creates(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/profile/regulatory-clocks")

    # The editor renders (heading + the read-only built-in reference section).
    expect(page.get_by_role("heading", name="Deadline reminders")).to_be_visible()
    expect(page.get_by_text("Built-in deadlines (for reference)")).to_be_visible()

    # Open "Add a reminder", fill it, submit.
    page.get_by_text("Add a reminder").first.click()
    page.locator('input[name="title"]').first.fill("E2E IRB report")
    # regime defaults to IRB, duration defaults to 0 (unconfigured) — valid.
    page.locator('button[type="submit"]', has_text="Add reminder").first.click()

    # After the PRG redirect the new template appears in the owned list.
    expect(page.get_by_text("E2E IRB report").first).to_be_visible()
