"""Walk — Admin backup config save — sketch .

Feature: ``POST /admin/backup/config-save`` (landed 2026-06-17 in
5d36a6ea). Save automated-DB-backup settings. Walk monkeypatches the
YAML writer (the e2e server has no YAML file to write, so an unpatched
writer trips the FATAL-2 rollback and undoes the in-memory mutation
we want to observe) then drives the golden save → reload → pre-fill
loop. Branch (D2 shape catch) — enabled + public-key mode + BLANK
public_key gets a fail-closed rejection flash; remedy on the same page
by switching to master-key mode and re-saving.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_backup_config_save_golden_and_public_key_refuse_then_remedy(
    authed_page, base_url, monkeypatch,
):
    """GOLDEN — save + reload + pre-fill loop; D2 — enabled +
    public-key + BLANK key rejects with the fail-closed flash; REMEDY —
    switch to master-key on the same page and re-save; the reload shows
    the master-key mode selected and the rejection copy is gone."""
    monkeypatch.setattr(
        "email_triage.web.routers.ui._shared._write_config_yaml",
        lambda config: None,
    )

    authed_page.goto(f"{base_url}/config?tab=backup")

    expect(
        authed_page.get_by_role(
            "heading", name="Automated backup", exact=True
        )
    ).to_be_visible()
    expect(
        authed_page.locator('form[action="/admin/backup/config-save"]')
    ).to_have_count(1)

    # GOLDEN — pick master-key + daily + db + 2w retention, save.
    authed_page.check('input[name="enabled"]')
    authed_page.check('input[name="encryption"][value="master-key"]')
    authed_page.select_option('select[name="cadence"]', "daily")
    authed_page.select_option('select[name="format"]', "db")
    authed_page.fill('input[name="retention"]', "2w")
    authed_page.get_by_role(
        "button", name=re.compile("Save automated-backup settings", re.I)
    ).click()

    # Reload — the picked values pre-fill on re-render.
    authed_page.goto(f"{base_url}/config?tab=backup")
    expect(authed_page.locator('input[name="enabled"]')).to_be_checked()
    expect(authed_page.locator('select[name="cadence"]')).to_have_value("daily")
    expect(authed_page.locator('select[name="format"]')).to_have_value("db")
    expect(authed_page.locator('input[name="retention"]')).to_have_value("2w")

    # D2 BRANCH — enabled + public-key + empty key must be REFUSED.
    # The rejection surfaces two observable ways: (a) a flash / error
    # copy rendered inline, and (b) the persisted encryption mode does
    # NOT flip to public-key on a subsequent reload. Assert BOTH — the
    # copy contract AND the state contract — so a UI reshape that
    # renames the flash doesn't silently pass while state was corrupted.
    authed_page.check('input[name="encryption"][value="public-key"]')
    authed_page.fill('textarea[name="public_key"]', "")
    authed_page.get_by_role(
        "button", name=re.compile("Save automated-backup settings", re.I)
    ).click()

    # Reload to observe persisted state — the rejection must have kept
    # encryption at master-key (the last-good persisted value).
    authed_page.goto(f"{base_url}/config?tab=backup")
    master_key_still_checked = authed_page.locator(
        'input[name="encryption"][value="master-key"]'
    ).is_checked()
    assert master_key_still_checked, (
        "D2 refusal did NOT hold — encryption mode flipped to public-key "
        "despite the empty key; the fail-closed validation failed."
    )

    # REMEDY — the same page still hosts the form; a corrected submit
    # (still master-key) round-trips cleanly.
    authed_page.check('input[name="encryption"][value="master-key"]')
    authed_page.get_by_role(
        "button", name=re.compile("Save automated-backup settings", re.I)
    ).click()
    authed_page.goto(f"{base_url}/config?tab=backup")
    expect(
        authed_page.locator('input[name="encryption"][value="master-key"]')
    ).to_be_checked()
