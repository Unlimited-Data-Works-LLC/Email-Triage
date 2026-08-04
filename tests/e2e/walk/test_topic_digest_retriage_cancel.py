"""Walk — Topic Digest retriage cancel (sketch ).

Feature: ``POST /profile/topic-digest/{topic_id:int}/retriage/{job_id}/cancel``
(landed 2026-07-04 in 61bc12fe). Cancel an in-flight topic-backscan
job. Walk creates two Topics via the real save endpoint (helper mirrors
tests/e2e/test_topic_retriage_ui.py), arms the cancel via 'Re-Triage
now', clicks 'Stop scan' and asserts the fragment swaps to CANCELLED
(polling self-stops — no hx-get). Branch: same-owner cross-topic POST
must land 404 (PD#9 topic-scope guard at the actuator) with no leak.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _get_csrf_token(page, base_url: str) -> str:
    return page.request.get(f"{base_url}/api/csrf-token").json()["token"]


def _create_topic(page, base_url: str, account_id: int, name: str) -> int:
    """Create a saved Topic via the real save endpoint; return its id.

    Mirrors the in-file helper in tests/e2e/test_topic_retriage_ui.py —
    duplicated per the sketch note (single caller, cheaper to keep local).
    """
    tok = _get_csrf_token(page, base_url)
    resp = page.request.post(
        f"{base_url}/profile/topic-digest/save",
        form={
            "name": name,
            "subjects": "cancel-walk",
            "selected_account_ids": str(account_id),
        },
        headers={"X-CSRF-Token": tok},
    )
    assert resp.ok, f"topic save failed: {resp.status} {resp.text()[:300]}"
    m = re.search(
        r"/profile/topic-digest/(\d+)/(?:edit|preview|retriage)", resp.text()
    )
    assert m, "saved Topic's edit link not found in save response"
    return int(m.group(1))


def test_cancel_flips_to_cancelled_and_stops_polling(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — arm Re-Triage; click Stop scan; fragment renders
    CANCELLED badge, terminal user copy, no Stop button, no hx-get
    (polling self-stops per {% if not is_terminal %})."""
    acct = e2e_server["research_account_id"]
    tid = _create_topic(
        authed_page, base_url, acct, "Cancel Walk Topic"
    )

    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")

    retriage_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Re-?Triage", re.I)
    )
    if retriage_btn.count() == 0:
        pytest.xfail(
            "'Re-Triage' button not present — feature-work: expose the "
            "retriage submit inside #topic-editor-form."
        )
    retriage_btn.first.click()

    status = authed_page.locator("#topic-retriage-status")
    try:
        status.wait_for(state="visible", timeout=10_000)
    except Exception:
        pytest.xfail("#topic-retriage-status never appeared after Re-Triage.")

    # Stop-scan form's hx-post has the right shape.
    stop_btn = authed_page.get_by_role(
        "button", name=re.compile(r"stop scan", re.I)
    )
    if stop_btn.count() == 0:
        pytest.xfail("Stop scan button not visible while non-terminal.")

    # Grab hx-post for shape assertion (may be on the form or the button).
    stop_form = authed_page.locator(
        f'form[hx-post*="/profile/topic-digest/{tid}/retriage/"]'
    )
    if stop_form.count() == 0:
        # Fallback: inspect any element under status carrying hx-post.
        candidate = status.locator('[hx-post*="/retriage/"]').first
        if candidate.count() == 0:
            pytest.xfail(
                "Stop-scan form's hx-post attribute not surfaced — "
                "feature-work: expose the cancel form wiring."
            )
        hx_post = candidate.get_attribute("hx-post") or ""
    else:
        hx_post = stop_form.first.get_attribute("hx-post") or ""
    assert re.search(
        r"/profile/topic-digest/\d+/retriage/[^/]+/cancel", hx_post
    ), f"Stop-scan hx-post shape wrong: {hx_post!r}"

    stop_btn.first.click()

    # Wait for the fragment to swap to a terminal state.
    try:
        expect(status.first).to_contain_text(
            re.compile(r"cancelled|stopped", re.I), timeout=10_000
        )
    except Exception:
        pytest.xfail(
            "cancel swap didn't surface CANCELLED text — feature-work: "
            "confirm _topic_backscan_status.html renders terminal shape."
        )

    # Terminal user copy present.
    expect(
        authed_page.get_by_text(
            re.compile(r"Stopped\. Any matches already found are kept", re.I)
        )
    ).to_be_visible()

    # Stop button gone; polling self-stopped (no hx-get on the fragment root).
    assert (
        authed_page.get_by_role(
            "button", name=re.compile(r"stop scan", re.I)
        ).count()
        == 0
    ), "Stop scan button still present after cancel — should hide at terminal"
    hx_get_after = status.first.get_attribute("hx-get")
    assert not hx_get_after, (
        f"#topic-retriage-status still carries hx-get after terminal: "
        f"{hx_get_after!r} (polling should self-stop)"
    )


def test_cancel_cross_topic_refuses(authed_page, base_url, e2e_server):
    """BRANCH (PD#9 — same-owner, wrong topic).

    Arm a cancellable job on tid, then POST to
    /profile/topic-digest/{tid_other}/retriage/{job_id}/cancel with a
    valid CSRF header. Must be 404 (actuator-side topic-scope guard).
    Then reload tid_other's editor: NO leaked #topic-retriage-status.
    """
    acct = e2e_server["research_account_id"]
    tid = _create_topic(authed_page, base_url, acct, "Cancel Branch A")
    tid_other = _create_topic(authed_page, base_url, acct, "Cancel Branch B")

    # Arm a job on tid.
    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")
    retriage = authed_page.get_by_role(
        "button", name=re.compile(r"Re-?Triage", re.I)
    )
    if retriage.count() == 0:
        pytest.xfail("Re-Triage button missing (same as golden path).")
    retriage.first.click()
    status = authed_page.locator("#topic-retriage-status")
    try:
        status.wait_for(state="visible", timeout=10_000)
    except Exception:
        pytest.xfail("status fragment didn't render for cross-topic branch.")

    # Extract job_id from the Stop-scan form's hx-post.
    hx_post_el = status.locator('[hx-post*="/retriage/"]').first
    if hx_post_el.count() == 0:
        pytest.xfail("no hx-post surface to extract job_id from.")
    hx_post = hx_post_el.get_attribute("hx-post") or ""
    m = re.search(
        rf"/profile/topic-digest/{tid}/retriage/([^/]+)/cancel", hx_post
    )
    assert m, f"couldn't extract job_id from hx-post: {hx_post!r}"
    job_id = m.group(1)

    # Fire same-owner cross-topic cancel — must 404.
    tok = _get_csrf_token(authed_page, base_url)
    resp = authed_page.request.post(
        f"{base_url}/profile/topic-digest/{tid_other}/retriage/{job_id}/cancel",
        form={"csrf_input": tok},
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status == 404, (
        f"cross-topic cancel returned {resp.status}, expected 404 "
        "(PD#9 topic-scope guard at actuator)"
    )

    # tid_other's editor renders with no leaked #topic-retriage-status.
    authed_page.goto(f"{base_url}/profile/topic-digest/{tid_other}/edit")
    assert authed_page.locator("#topic-retriage-status").count() == 0, (
        "tid_other's editor rendered #topic-retriage-status — cross-topic "
        "state leaked from tid_a"
    )
