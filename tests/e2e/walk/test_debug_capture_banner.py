"""Walk — src/email_triage/web/templates/admin/_debug_capture_banner.html (template).

Operator ruling A4 (2026-10-21) + panel M H8(a): while the classify debug
capture is on, every admin page shows a non-dismissable banner that says what
is kept and that turning the capture off does not remove the excerpts. Off:
no banner.

The e2e server runs ``create_app`` in this process (uvicorn thread), so the
capture flag is the module global ``classify.ollama._debug_capture_requested``;
``monkeypatch`` restores it after each test. Nothing is written to the DB.
"""
from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def test_golden(authed_page, base_url, monkeypatch):
    # GOLDEN: capture on -> the admin page shows the banner and the
    # excerpt-retention sentence.
    from email_triage.classify import ollama

    monkeypatch.setattr(ollama, "_debug_capture_requested", True)
    goto_or_fail(authed_page, base_url + "/config")
    banner = authed_page.locator('[data-banner="debug-capture"]')
    expect(banner).to_be_visible()
    expect(banner.get_by_text("Troubleshooting capture is on", exact=False)).to_be_visible()
    expect(banner.get_by_text("turning the capture off does not remove them",
                              exact=False)).to_be_visible()


def test_server_refuses_remedy(authed_page, base_url, monkeypatch):
    # BRANCH: capture off -> no banner.
    from email_triage.classify import ollama

    monkeypatch.setattr(ollama, "_debug_capture_requested", False)
    goto_or_fail(authed_page, base_url + "/config")
    expect(authed_page.locator('[data-banner="debug-capture"]')).to_have_count(0)
