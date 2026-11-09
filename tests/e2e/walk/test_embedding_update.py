"""Walk — POST /config/ai-backends/embedding-update (route).

Feature: ``POST /config/ai-backends/embedding-update`` (punch 569, N-570). The
ONE action behind the [Update embedding runtime] button: it writes a
witness-first INTENT row, claims the install row, and runs the atomic update
(stage beside the old set, verify, swap, re-verify) in the background, then
writes an OUTCOME row.

GOLDEN — with an installed runtime one non-security step behind the image's
manifest (``stale_ok``: it still serves), an admin page shows the banner; the
admin clicks [Update embedding runtime]; the install card replaces the banner
in place, an INTENT row and a success OUTCOME row are written, and after a
reload the banner is gone because the runtime now matches the image. The
download/stage/swap itself is replaced by a fake ``update_runtime`` that points
the runtime at an already-verified prefix (the e2e server runs in-process, so
the patch reaches it). No network.

BRANCH (server refuses -> user remedy) — while another install or update holds
the update lock, the click is refused: nothing runs, a failure row says the
update was already in flight, and the card tells the admin to wait for it to
finish.
"""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e

ROUTE = "/config/ai-backends/embedding-update"
PAGE = "/config?tab=general"


def _rows(conn, outcome: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = ? AND outcome = ?",
        ("embedding_runtime_update", outcome),
    ).fetchone()[0]


@pytest.fixture
def stale_runtime(tmp_path, monkeypatch, e2e_server):
    """An installed runtime one NON-security step behind the image (stale_ok),
    plus an already-verified prefix the fake update swaps to. The install row
    is put back to ``not_installed`` afterwards (the e2e DB is session-wide)."""
    from email_triage import embedding_bits as eb
    from tests._embedding_runtime_fixture import (
        make_verified_prefix,
        make_versioned_prefix,
    )

    # This walk is the CLICK route: it holds with embedding.auto_update OFF
    # (on, the sweeper would apply the update itself and no button renders).
    # In-process e2e server, so the module switch reaches it. Edited
    # 2026-10-25, not run (the brief forbids e2e).
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    new_prefix, _site, new_manifest = make_verified_prefix(tmp_path / "new", monkeypatch)
    make_versioned_prefix(tmp_path / "old", monkeypatch, steps=(False,))
    conn = e2e_server["conn"]
    eb._update_state(conn, status="installed", install_method="auto")
    conn.commit()
    yield {"new_prefix": new_prefix, "new_manifest": new_manifest}
    eb._update_state(conn, status="not_installed", clear_install_record=True, clear_error=True)
    conn.commit()
    eb.invalidate_runtime_ready_cache()


def test_update_swaps_in_the_new_runtime_and_audits(
    authed_page, base_url, e2e_server, stale_runtime, monkeypatch,
):
    """GOLDEN — the banner's button runs the update; the banner goes away."""
    from email_triage import embedding_bits as eb
    from email_triage.web import embedding_update_runner as ei
    from tests._embedding_runtime_fixture import point_defaults_at

    conn = e2e_server["conn"]

    def fake_update(*, conn, **_kw):
        point_defaults_at(monkeypatch, stale_runtime["new_prefix"], stale_runtime["new_manifest"])
        eb._update_state(
            conn, status="installed", runtime_deps_path=str(stale_runtime["new_prefix"]),
            current_file=None, clear_error=True,
        )
        eb.invalidate_runtime_ready_cache()
        return eb.UpdateResult(status="updated", to_set_version=2)

    monkeypatch.setattr(ei, "update_runtime", fake_update)
    intents, successes = _rows(conn, "attempt"), _rows(conn, "success")

    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    banner = authed_page.locator("#embedding-runtime-banner")
    expect(banner).to_be_visible()
    button = banner.get_by_role("button", name="Update embedding runtime")
    expect(button).to_be_visible()
    expect(button).to_have_attribute("hx-post", ROUTE)
    with authed_page.expect_response(lambda r: r.url.endswith(ROUTE)) as resp_info:
        button.click()
    assert resp_info.value.status == 200, resp_info.value.status

    # The install card replaces the banner in place (hx-target the banner).
    expect(authed_page.locator("#embedding-install-card")).to_be_visible()
    expect(authed_page.locator("#embedding-runtime-banner")).to_have_count(0)

    deadline = time.monotonic() + 15
    while _rows(conn, "success") == successes and time.monotonic() < deadline:
        time.sleep(0.2)
    assert _rows(conn, "attempt") == intents + 1, "no INTENT row before the update"
    assert _rows(conn, "success") == successes + 1, "no success OUTCOME row after the update"

    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    expect(authed_page.locator("#embedding-runtime-banner")).to_have_count(0)


def test_update_in_flight_is_refused_with_the_remedy(
    authed_page, base_url, e2e_server, stale_runtime, monkeypatch,
):
    """BRANCH — another update holds the lock: refused, and told to wait."""
    from email_triage import embedding_bits as eb
    from email_triage.web import embedding_update_runner as ei

    conn = e2e_server["conn"]
    entered: list[bool] = []
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: entered.append(True))
    failures = _rows(conn, "failure")

    goto_or_fail(authed_page, f"{base_url}{PAGE}")
    button = authed_page.locator("#embedding-runtime-banner").get_by_role(
        "button", name="Update embedding runtime",
    )
    expect(button).to_be_visible()
    assert eb._update_lock.acquire(blocking=False)
    try:
        with authed_page.expect_response(lambda r: r.url.endswith(ROUTE)):
            button.click()
        card = authed_page.locator("#embedding-install-card")
        expect(card).to_contain_text("already in progress")
        expect(card).to_contain_text("Wait for it to finish")
    finally:
        eb._update_lock.release()
    assert not entered, "the update ran although another one held the lock"
    assert _rows(conn, "failure") == failures + 1, "no failure row for the refused update"
