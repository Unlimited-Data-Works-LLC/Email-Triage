"""Walk — admin/_embedding_runtime_banner.html (punch 569, N-570).

Feature: the non-dismissable admin banner, included from base.html, that tells
the admin the embedding runtime needs updating and offers the ONE button.

GOLDEN — with an installed runtime one NON-security step behind the image
(``stale_ok``), an admin page shows "Embedding runtime update required
(manifest v1 -> v2)", says the installed runtime keeps serving, and offers one
``type="button"`` [Update embedding runtime] that posts the update route (no
form or submit control: the base.html global-slot rule). With a SECURITY step
instead, the banner says "security fix", names the advisory and says embedding
is switched off.

BRANCH (server refuses -> user remedy) — after an update made while the
runtime was loaded, the server will not start another; the banner drops the
button and tells the admin exactly what to do: restart the container. And with
nothing to update, no banner renders at all.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e

PAGE = "/config?tab=general"
ROUTE = "/config/ai-backends/embedding-update"


@pytest.fixture(autouse=True)
def _click_mode(monkeypatch):
    """This walk is the punch-569 CLICK banner: it holds with
    ``embedding.auto_update`` OFF (the default, on, shows a banner with no button;
    that arm is tests/test_web/test_autoupd_notices.py). The e2e server runs in
    this process, so the module switch reaches it. Edited 2026-10-25, not run."""
    from email_triage import embedding_bits as eb

    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)


def test_banner_offers_the_one_update_button(authed_page, base_url, tmp_path, monkeypatch):
    """GOLDEN — stale_ok: headline, consequence and the one button."""
    from tests._embedding_runtime_fixture import make_versioned_prefix

    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("Embedding runtime update required (manifest v1 -> v2)")
    expect(banner).to_contain_text("keeps serving")
    button = banner.locator("button")
    expect(button).to_have_count(1)
    expect(button).to_have_text("Update embedding runtime")
    expect(button).to_have_attribute("type", "button")
    expect(button).to_have_attribute("hx-post", ROUTE)
    expect(banner.locator("form")).to_have_count(0)


def test_banner_names_a_security_fix(authed_page, base_url, tmp_path, monkeypatch):
    """GOLDEN (security) — refused runtime: security fix, advisory, switched off."""
    from tests._embedding_runtime_fixture import make_versioned_prefix

    make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0569",),
    )
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("security fix")
    expect(banner).to_contain_text("CVE-2099-0569")
    expect(banner).to_contain_text("switched off")
    expect(banner.get_by_role("button", name="Update embedding runtime")).to_be_visible()


def test_banner_after_a_loaded_update_says_restart(authed_page, base_url, tmp_path, monkeypatch):
    """BRANCH — restart pending: no button, the remedy is a container restart."""
    from email_triage import embedding_bits as eb
    from tests._embedding_runtime_fixture import make_versioned_prefix

    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(eb, "_restart_pending", True)
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("restart the container to load the new runtime")
    expect(banner.locator("button")).to_have_count(0)


def test_no_banner_when_nothing_needs_updating(authed_page, base_url, tmp_path, monkeypatch):
    """BRANCH — the runtime matches the image: no banner at all."""
    from tests._embedding_runtime_fixture import make_verified_prefix

    make_verified_prefix(tmp_path, monkeypatch)
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    expect(authed_page.locator("#embedding-runtime-banner")).to_have_count(0)


def test_auto_mode_banner_says_the_app_does_it_and_has_no_button(
    authed_page, base_url, tmp_path, monkeypatch,
):
    """BRANCH (operator decision 2026-10-25) — with embedding.auto_update ON the app
    updates the runtime itself: the banner says so and carries no button, and an
    INTEGRITY refusal (never healed by the app) keeps its button."""
    from tests._embedding_runtime_fixture import make_versioned_prefix

    from email_triage import embedding_bits as eb
    from email_triage.web import embedding_update_runner as ru

    async def _no_tick(app):  # keep the in-process sweeper out of this walk
        return "current"

    monkeypatch.setattr(ru, "auto_update_once", _no_tick)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    prefix, site, _manifest = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("Embedding runtime update in progress (manifest v1 -> v2)")
    expect(banner).to_contain_text("nothing to click")
    expect(banner.locator("button")).to_have_count(0)
    expect(authed_page.locator(f'[hx-post="{ROUTE}"]')).to_have_count(0)

    # A distribution the install record never named: an integrity refusal. The app
    # does not replace it by itself, so the click stays.
    planted = site / "planted_pkg-6.6.6.dist-info"
    planted.mkdir()
    (planted / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: planted-pkg\nVersion: 6.6.6\n", encoding="utf-8",
    )
    eb.invalidate_runtime_ready_cache()
    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_contain_text("Embedding runtime refused")
    expect(banner).to_contain_text("does not replace it by itself")
    expect(banner.get_by_role("button", name="Update embedding runtime")).to_be_visible()
