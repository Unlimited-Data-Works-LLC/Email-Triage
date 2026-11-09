"""E2E —  Topic Digest editor's Preview spinner + Re-Triage live-status UI,
in a REAL browser (2026-06-11 UX batch).

Boots the SAME ``create_app`` over a socket. ``lifespan="off"`` means the bulk
runner never drains, so a Re-Triage press enqueues a QUEUED ``topic_backscan``
job and the NEW self-polling status fragment renders QUEUED + a working Stop
button; clicking Stop flips it to cancelled via the real cancel route. This
exercises the rendered HTMX UI (spinner element, status fragment, Stop swap)
that a TestClient string-assert cannot — per feedback_ui_fixes_reviewed_with_
playwright (BINDING). The Preview button's spinner is asserted as rendered but
NOT clicked (the seeded accounts are inert IMAP — a real connect would hang).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _create_topic(page, base_url: str, account_id: int) -> int:
    """Create a saved Topic via the real save endpoint and return its id, parsed
    from the returned editor HTML. CSRF is enforced in the e2e harness, and this
    is a DIRECT request.post (not a rendered form, so no csrf_input field) — so
    fetch a session-bound token from /api/csrf-token and echo it in the
    X-CSRF-Token header (the same path the JS UIs use)."""
    tok = page.request.get(f"{base_url}/api/csrf-token").json()["token"]
    resp = page.request.post(
        f"{base_url}/profile/topic-digest/save",
        form={
            "name": "Lupus E2E",
            "subjects": "lupus",
            "selected_account_ids": str(account_id),
        },
        headers={"X-CSRF-Token": tok},
    )
    assert resp.ok, f"topic save failed: {resp.status} {resp.text()[:300]}"
    # The save is a PRG 303 → the topic-digest LIST page (followed by
    # page.request); the saved Topic shows there as an /edit link.
    m = re.search(
        r"/profile/topic-digest/(\d+)/(?:edit|preview|retriage)", resp.text()
    )
    assert m, "saved Topic's edit link not found (save likely errored)"
    return int(m.group(1))


def test_topic_editor_preview_spinner_and_retriage_status(authed_page, e2e_server):
    page = authed_page
    base_url = e2e_server["base_url"]
    tid = _create_topic(page, base_url, e2e_server["research_account_id"])

    page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")

    # (1) Preview form renders WITH its hx-indicator spinner, and the spinner
    #     element the form actually points at exists (wiring intact). The id is
    #     DERIVED from the form's own hx-indicator attribute rather than
    #     hard-coded, so a CONSISTENT rename of the indicator (both the attr and
    #     its element — e.g. the `3cfe66a` `topic-preview-spinner` ->
    #     `topic-preview-loading` wait-indicator rework) stays green, while an
    #     UN-wired indicator (attr dangling at a missing element, or no spinner
    #     at all) fails. Per feedback_dynamic_over_hardcoding: a hard-coded id
    #     is exactly what let this spec rot silently after that template rename
    #     (red on every feat/v0.2.0 e2e run since).
    preview_btn = page.get_by_role(
        "button", name=re.compile("Preview matches", re.I)
    )
    expect(preview_btn).to_be_visible()
    preview_form = page.locator("form", has=preview_btn)
    indicator_sel = preview_form.get_attribute("hx-indicator")
    assert indicator_sel and indicator_sel.startswith("#"), (
        "Preview form's hx-indicator is missing/invalid: "
        f"{indicator_sel!r} (the spinner is un-wired)"
    )
    spinner = page.locator(indicator_sel)
    assert spinner.count() == 1, (
        f"Preview form's hx-indicator {indicator_sel} points at no element — "
        "the spinner is un-wired (a template rename left the indicator "
        "dangling)"
    )
    expect(spinner).to_have_class(re.compile(r"\bhtmx-indicator\b"))

    # (2) Re-Triage now -> the NEW self-polling live-status fragment appears
    #     with the advancing-count label + a Stop button (the alive indicator).
    page.get_by_role("button", name=re.compile("Re-?Triage now", re.I)).click()
    status = page.locator("#topic-retriage-status")
    expect(status).to_be_visible(timeout=10_000)
    expect(status).to_contain_text(re.compile("scanned", re.I))
    stop = page.get_by_role("button", name=re.compile("Stop scan", re.I))
    expect(stop).to_be_visible()

    # (3) Stop -> the fragment swaps to a stopped/cancelled terminal state.
    stop.click()
    expect(page.locator("#topic-retriage-status")).to_contain_text(
        re.compile("stopped|cancelled", re.I), timeout=10_000
    )


def test_preview_button_fires_the_post(authed_page, e2e_server):
    """REPRO/guard: clicking 'Preview matches' must actually fire the POST. The
    live deploy showed GET /edit but NO POST /preview — a bad hx-disabled-elt
    selector un-wired the form. We only assert the REQUEST fires (the inert
    seeded IMAP would hang the server-side fetch, so we don't await the
    response)."""
    page = authed_page
    base_url = e2e_server["base_url"]
    tid = _create_topic(page, base_url, e2e_server["research_account_id"])
    page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")
    import re as _re
    # Pick the new "Last 7 days" option to prove the window threads into the POST.
    page.locator("select[name='lookback_days']").select_option("7")
    with page.expect_request(
        _re.compile(r"/profile/topic-digest/\d+/preview$"), timeout=8000
    ) as ri:
        page.get_by_role("button", name=_re.compile("Preview matches", _re.I)).click()
    req = ri.value
    assert req.method == "POST"
    # The submitted lookback window rides in the POST body (the handler now
    # honors it — it was previously ignored/hardcoded to 30).
    assert "lookback_days=7" in (req.post_data or "")
