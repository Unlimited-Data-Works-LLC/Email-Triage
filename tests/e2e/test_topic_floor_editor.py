"""E2E — the per-Topic confidence-floor field renders + round-trips in a REAL
browser (operator 2026-06-15). The TestClient router test asserts the HTML; this
proves the field actually renders, accepts input, and persists through a real
save+reload (the binding real-browser review for a UI change).
"""
from playwright.sync_api import expect


def test_floor_field_renders_and_round_trips(authed_page, base_url):
    page = authed_page

    # 1. The field renders + is interactable in the editor (the real-browser
    #    check the TestClient string-assert can't make).
    page.goto(f"{base_url}/profile/topic-digest/new")
    floor = page.locator('input[name="confidence_floor"]')
    expect(floor).to_be_visible()
    expect(floor).to_have_attribute("placeholder", "system default")

    # 2. Fill a minimal valid Topic + a floor, then save.
    page.fill('input[name="name"]', "E2E Floor Topic")
    # First subject chip row.
    page.locator('input[name="subjects"]').first.fill("lupus")
    # Pick a mailbox (the in-house multiselect: trigger then an option).
    trigger = page.locator(".ms-trigger").first
    if trigger.count():
        trigger.click()
        page.locator(".ms-option", has_text="Research Inbox").first.click()
    floor.fill("0.7")
    page.locator('button[type="submit"], input[type="submit"]').first.click()

    # 3. Reload the saved Topic's editor; the floor value round-trips.
    page.goto(f"{base_url}/profile?tab=topic-digest")
    page.get_by_text("E2E Floor Topic").first.click()
    saved_floor = page.locator('input[name="confidence_floor"]')
    expect(saved_floor).to_have_value("0.7")
