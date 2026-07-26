"""E2E — the Admin → Backup automated-backup CONFIG form.

Real-browser review per feedback_ui_fixes_reviewed_with_playwright: a
TestClient string-assert can't prove the form's ``csrf_input`` actually submits
under enforce, nor that the real handler → flash → re-render loop works. This
spec drives a live Chromium against a booted server:

  1. The Automated-backup section renders with its controls.
  2. Fail-closed: public-key mode with an EMPTY key is rejected by the real
     handler (validation runs BEFORE any persistence, so it's deterministic
     even though the e2e server has no YAML file to write) and the rejection
     flash renders back on the page.
  3. The operator's picked values round-trip — submitting them mutates the live
     config and the reloaded tab pre-fills them (proving build_backup_context
     reads the saved state, and that the CSRF token submitted OK — a 403 would
     never have reached the handler). NOTE: the e2e server boots with no config
     YAML on disk, so the handler's _write_config_yaml fails and this proves the
     in-memory mutate + re-read path, NOT YAML persistence — that is covered by
     the unit test test_config_roundtrip.test_backup_config_roundtrip.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_backup_tab_renders_automated_form(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/config?tab=backup")

    expect(
        page.get_by_role("heading", name="Automated backup", exact=True)
    ).to_be_visible()
    expect(page.locator('input[name="enabled"]')).to_have_count(1)
    expect(page.locator('select[name="cadence"]')).to_have_count(1)
    expect(page.locator('input[name="encryption"]')).to_have_count(2)  # 2 radios
    expect(page.locator('textarea[name="public_key"]')).to_have_count(1)
    expect(
        page.locator('form[action="/admin/backup/config-save"]')
    ).to_have_count(1)
    # The stale "no automation involved" copy must be gone.
    expect(page.locator("body")).not_to_contain_text("no automation involved")


def test_x25519_help_disclosure_expands_in_browser(authed_page, base_url):
    """The in-page ℹ️ help (operator request): the X25519 disclosure is a native
    <details> — collapsed by default, and clicking the summary reveals the
    'what is it + how to generate' content with the Windows-friendly command. A
    real browser is the only way to prove the disclosure actually toggles."""
    page = authed_page
    page.goto(f"{base_url}/config?tab=backup")

    disclosure = page.locator("details.info-help")
    expect(disclosure).to_have_count(1)
    summary = disclosure.locator("summary")
    expect(summary).to_contain_text(re.compile("X25519", re.I))

    # Collapsed → the body text is not visible until the summary is clicked.
    body = disclosure.locator(".info-help-body")
    expect(body).to_be_hidden()
    summary.click()
    expect(body).to_be_visible()
    expect(body).to_contain_text("python -m email_triage backup gen-keypair")
    expect(body).to_contain_text(re.compile("age-keygen", re.I))  # the pitfall


def test_public_key_mode_empty_key_is_rejected_in_browser(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/config?tab=backup")

    page.check('input[name="enabled"]')
    page.check('input[name="encryption"][value="public-key"]')
    page.fill('textarea[name="public_key"]', "")  # the fail-closed trigger
    page.get_by_role(
        "button", name=re.compile("Save automated-backup settings", re.I)
    ).click()

    # The real handler rejected it; the rejection flash renders on the page.
    expect(page.locator("body")).to_contain_text(
        re.compile("requires an X25519 public key", re.I)
    )


def test_picked_values_roundtrip_in_browser(authed_page, base_url, monkeypatch):
    # The e2e server boots with no config YAML, so _write_config_yaml would
    # raise and the handler's transactional roll-back (FATAL-2 fix) would
    # restore the prior values — defeating the in-memory round-trip we want to
    # prove here. No-op the writer (same process: uvicorn runs in a thread, so
    # this patches the handler's view too) so the save SUCCEEDS and the mutation
    # sticks. Real YAML persistence is the unit roundtrip test's job.
    monkeypatch.setattr(
        "email_triage.web.routers.ui._shared._write_config_yaml",
        lambda config: None,
    )
    page = authed_page
    page.goto(f"{base_url}/config?tab=backup")

    page.check('input[name="enabled"]')
    page.check('input[name="encryption"][value="master-key"]')
    page.select_option('select[name="cadence"]', "daily")
    page.select_option('select[name="format"]', "db")
    page.fill('input[name="retention"]', "2w")
    page.get_by_role(
        "button", name=re.compile("Save automated-backup settings", re.I)
    ).click()

    # Re-load the tab — the saved (in-memory) values must pre-fill, proving the
    # handler ran (CSRF accepted) and build_backup_context reads them back.
    page.goto(f"{base_url}/config?tab=backup")
    expect(page.locator('input[name="enabled"]')).to_be_checked()
    expect(page.locator('select[name="cadence"]')).to_have_value("daily")
    expect(page.locator('select[name="format"]')).to_have_value("db")
    expect(page.locator('input[name="retention"]')).to_have_value("2w")
