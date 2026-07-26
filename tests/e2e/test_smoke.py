"""E2E smoke — proves the harness foundation end to end.

If these pass, the boot + seed + cookie-auth + real-browser-render path
all work, and the rest of the page specs can build on the same fixtures.
Doubles as the regression net for the "Mailboxes to scan" multiselect
that shipped blank twice (a real browser asserting real ``<option>``s is
exactly the check the unit tests lacked).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_server_health_serving(e2e_server):
    """The booted server answers /health with a health-shaped JSON body.

    Accepts 200 (ok) OR 503 (degraded) — the seeded accounts are inert
    (no ingestion coverage) so the snapshot reads degraded, which is a
    valid running state. The point of this check is "the app is mounted
    and routing," not "the app is healthy."
    """
    import json
    import urllib.error
    import urllib.request

    url = f"{e2e_server['base_url']}/health"
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    assert status in (200, 503)
    body = json.loads(raw)
    assert "status" in body and "db" in body


def test_unauthed_topic_editor_is_blocked(page, base_url):
    """Without the session cookie, the topic editor must NOT render."""
    page.goto(f"{base_url}/profile/topic-digest/new")
    # Redirected to login / denied — the editor form is absent.
    expect(page.locator("#topic-editor-form")).to_have_count(0)


def test_authed_topic_editor_renders_with_multiselect(authed_page, base_url):
    """Authed blank editor renders the form AND a populated mailbox multiselect.

    This is the multiselect-blank regression net: the select must carry a
    real ``<option>`` per seeded manageable account (Research + Clinic),
    and the HIPAA one must show the 🔒 badge.
    """
    authed_page.goto(f"{base_url}/profile/topic-digest/new")

    # The editor form + required name field render.
    expect(authed_page.locator("#topic-editor-form")).to_be_visible()
    expect(authed_page.locator('input[name="name"]')).to_be_visible()

    # The mailbox multiselect is present and NOT blank. The native
    # <select> is intentionally HIDDEN (a JS widget enhances it via
    # data-multiselect), so we assert the OPTIONS exist in the DOM rather
    # than the select being visible — option presence is exactly what the
    # blank-multiselect regression was about.
    multiselect = authed_page.locator('select[name="selected_account_ids"]')
    expect(multiselect).to_have_count(1)
    options = multiselect.locator("option")
    # Two seeded accounts => exactly two real options.
    expect(options).to_have_count(2)

    # text_content() reads the DOM text regardless of visibility.
    option_text = " ".join(options.all_text_contents())
    assert "Research Inbox" in option_text
    assert "Clinic Inbox" in option_text
    # The HIPAA account carries the lock badge.
    assert "🔒" in option_text
