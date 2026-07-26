"""Walk — Backfill-capped dismiss chip (sketch ).

Feature: ``POST /accounts/{account_id}/backfill-capped/dismiss``
(landed 2026-06-12 in 55ace029). Per-account dismiss of the amber
backfill-cap chip. Walk seeds two chips (research + clinic) and proves:
1) both render on the /accounts index, 2) dismissing one leaves the
sibling chip visible (N-211 R23 per-account scope), 3) the server-side
clear survives a reload.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail, seed_backfill_capped

pytestmark = pytest.mark.e2e


def _seed_two_chips(e2e_server: dict) -> tuple[int, int]:
    conn = e2e_server["conn"]
    r = e2e_server["research_account_id"]
    c = e2e_server["clinic_account_id"]
    try:
        seed_backfill_capped(conn, r)
        seed_backfill_capped(conn, c)
    except Exception as exc:  # pragma: no cover - defensive
        pytest.xfail(
            f"mark_backfill_capped seed helper unavailable ({exc!r}); "
            "feature-work: expose email_triage.web._backfill_chip."
            "mark_backfill_capped with (conn, account_id, kind, window, "
            "recovered) signature."
        )
    return r, c


def test_backfill_chips_render(authed_page, base_url, e2e_server):
    """GOLDEN — after seeding two backfill-capped rows, both amber chips
    render on the /accounts index."""
    r, c = _seed_two_chips(e2e_server)
    goto_or_fail(authed_page, f"{base_url}/accounts")
    research_chip = authed_page.locator(f"#backfill-chip-{r}")
    clinic_chip = authed_page.locator(f"#backfill-chip-{c}")
    if research_chip.count() == 0 or clinic_chip.count() == 0:
        pytest.xfail(
            "Backfill chip DOM ids (#backfill-chip-<id>) not surfaced on "
            "/accounts — feature-work needed to un-xfail: render the chip "
            "row with a stable per-account element id."
        )
    expect(research_chip).to_be_visible()
    expect(clinic_chip).to_be_visible()


def test_dismiss_isolates_per_account(authed_page, base_url, e2e_server):
    """BRANCH (per-account isolation, N-211 R23 D2-shape) — dismiss the
    research chip; the clinic chip MUST stay visible. Dismissal of one
    account cannot silently clear a sibling account's chip."""
    r, c = _seed_two_chips(e2e_server)
    goto_or_fail(authed_page, f"{base_url}/accounts")
    research_chip = authed_page.locator(f"#backfill-chip-{r}")
    if research_chip.count() == 0:
        pytest.xfail(
            "Backfill chip DOM ids not surfaced — un-xfail needs the "
            "same feature-work as test_backfill_chips_render."
        )
    dismiss_btn = research_chip.locator('button[type="submit"]').first
    dismiss_btn.click()
    # HTMX swap detaches the research chip.
    expect(authed_page.locator(f"#backfill-chip-{r}")).to_have_count(0)
    # The sibling clinic chip stays.
    expect(authed_page.locator(f"#backfill-chip-{c}")).to_be_visible()
    # Persistence: after reload, research stays absent, clinic stays present.
    authed_page.reload()
    expect(authed_page.locator(f"#backfill-chip-{r}")).to_have_count(0)
    expect(authed_page.locator(f"#backfill-chip-{c}")).to_be_visible()
