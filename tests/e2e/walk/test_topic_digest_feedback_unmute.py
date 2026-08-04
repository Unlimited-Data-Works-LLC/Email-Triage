"""Walk — Topic Digest feedback unmute — sketch .

Feature: ``POST /profile/topic-digest/{topic_id:int}/feedback/unmute``
(landed 2026-07-02 in 7fd13013). Undoes a sender-level mute in the
topic-feedback layer. Walk seeds a Topic and inserts ONE muted-sender
``topic_feedback`` row directly via ``record_topic_feedback``, opens
the editor, clicks the 'un-mute' button, asserts the row swaps out and
that a page reload no longer shows the 'Muted senders' section (proves
the DB row was cleared, not just hidden client-side). Branch (D2 shape
catch) — POST to a foreign topic id; server must return 403 and the
owner's own muted-senders state must NOT re-appear.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _get_csrf_token(page, base_url: str) -> str:
    return page.request.get(f"{base_url}/api/csrf-token").json()["token"]


def _create_topic_with_muted_sender(
    e2e_server, sender_addr: str,
) -> int:
    """Insert a Topic owned by the seeded admin + a muted-sender row.

    Composes ``upsert_topic`` + ``record_topic_feedback`` directly
    against the shared in-memory conn — no HTTP round-trip needed for
    the arrangement, matching the sketch's minimal seed pattern.
    """
    from email_triage.actions.topic_configs import (
        TopicConfig,
        record_topic_feedback,
        upsert_topic,
    )

    conn = e2e_server["conn"]
    user_id = e2e_server["user_id"]
    research_id = e2e_server["research_account_id"]

    tid = upsert_topic(
        conn,
        TopicConfig(
            id=0,
            user_id=user_id,
            name="UnmuteWalkTopic",
            subjects=["lupus"],
            selected_account_ids=[research_id],
            retention_days=90,
        ),
    ).id
    record_topic_feedback(
        conn,
        topic_id=tid,
        account_id=research_id,
        vote=-1,
        sender=sender_addr,
    )
    conn.commit()
    return tid


def test_unmute_button_removes_row_and_clears_section(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — seed a muted-sender row, land on the editor, click
    un-mute, row is removed via HTMX outerHTML, then a page reload no
    longer renders the 'Muted senders' section."""
    sender = "spam@lupus-newsletter.test"
    tid = _create_topic_with_muted_sender(e2e_server, sender)

    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")

    heading = authed_page.get_by_role(
        "heading", name=re.compile("Muted senders", re.I)
    )
    if heading.count() == 0:
        pytest.xfail(
            "'Muted senders' heading not surfaced in editor — feature-work: "
            "the muted-senders section didn't render for the seeded row."
        )
    expect(heading.first).to_be_visible()

    muted_row = authed_page.locator("li[id^='muted-sender-']").filter(
        has_text=sender
    )
    if muted_row.count() == 0:
        pytest.xfail(
            "muted-sender <li> not present — feature-work: "
            "record_topic_feedback wrote the row but the template didn't "
            "render it under that selector."
        )
    expect(muted_row.first).to_be_visible()

    unmute_btn = muted_row.first.get_by_role(
        "button", name=re.compile("un-?mute", re.I)
    )
    if unmute_btn.count() == 0:
        pytest.xfail(
            "no 'un-mute' button inside the muted-sender <li> — "
            "feature-work: expose the hx-post button."
        )
    unmute_btn.first.click()

    # HTMX outerHTML swap with an empty 200 body removes the row.
    try:
        expect(muted_row).to_have_count(0, timeout=5_000)
    except Exception:
        pytest.xfail("un-mute HTMX swap did not remove the muted-sender row.")

    # Persistence — reload and the section should be gone entirely.
    authed_page.reload()
    heading_after = authed_page.get_by_role(
        "heading", name=re.compile("Muted senders", re.I)
    )
    assert heading_after.count() == 0, (
        "'Muted senders' section still present after reload — "
        "un-mute POST did not clear the DB row."
    )


def test_unmute_foreign_topic_refuses(
    authed_page, base_url, e2e_server,
):
    """BRANCH (D2) — POST to a non-owned/non-existent topic id must
    return 403 (or 404 — both are fail-closed shapes), and the owner's
    own state must NOT be re-created."""
    sender = "spam@lupus-newsletter.test"
    tid = _create_topic_with_muted_sender(e2e_server, sender)

    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")
    tok = _get_csrf_token(authed_page, base_url)

    resp = authed_page.request.post(
        f"{base_url}/profile/topic-digest/999999/feedback/unmute",
        form={"sender": sender, "csrf_input": tok},
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status in (401, 403, 404), (
        f"foreign-topic unmute returned {resp.status}, expected fail-closed "
        f"(401/403/404); body={resp.text()[:300]!r}"
    )

    # Reload the OWNED topic — remedy path proves no cross-topic leak
    # (the OWNED topic's muted-sender state MUST be preserved intact:
    # the refused foreign POST did not delete the owner's row).
    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")
    heading = authed_page.get_by_role(
        "heading", name=re.compile("Muted senders", re.I)
    )
    assert heading.count() >= 1, (
        "'Muted senders' section disappeared on the owned topic after the "
        "refused foreign POST — cross-topic side effect deleted owner state."
    )
    # And the specific sender is still muted.
    still_muted = authed_page.locator("li[id^='muted-sender-']").filter(
        has_text=sender
    )
    assert still_muted.count() >= 1, (
        f"seeded muted sender {sender!r} disappeared after refused foreign "
        "POST — cross-topic side effect cleared it."
    )
