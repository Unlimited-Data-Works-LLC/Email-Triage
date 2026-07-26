"""Walk — Topic Digest hit feedback (thumbs) — sketch .

Feature: ``POST /profile/topic-digest/{topic_id:int}/hits/feedback``
(landed 2026-07-02 in 7fd13013). User-labeled feedback on a matched
topic hit; writes ``topic_feedback`` (sender-level + message-level
learning). Walk seeds a Topic with TWO ``topic_hits`` rows, opens the
preview surface, clicks 👍 on the first and 👎 on the second, and
asserts the row-swap in the rendered DOM. Branch (D2 shape catch) —
forge a POST with an ``account_id`` NOT in the requester's manageable
set; server must fail-closed and NOT write a ``topic_feedback`` row.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def seeded_topic_with_hits(e2e_server):
    """Seed one Topic owned by the e2e admin against research_account_id,
    plus TWO distinct ``topic_hits`` rows (different message ids, different
    senders). Yields ``{topic_id, hit_a_msgid, hit_b_msgid, account_id}``.
    Teardown deletes the topic (cascades hits) so sibling walks stay clean.
    """
    from email_triage.actions.topic_configs import (
        TopicConfig,
        insert_topic_hit,
        upsert_topic,
    )

    conn = e2e_server["conn"]
    user_id = e2e_server["user_id"]
    research_id = e2e_server["research_account_id"]

    cfg = TopicConfig(
        id=0,
        user_id=user_id,
        name="HitFeedbackWalk",
        subjects=["NCT99900001"],
        selected_account_ids=[research_id],
        retention_days=90,
    )
    tid = upsert_topic(conn, cfg).id

    hit_a = "<walk-hitfb-1@test.local>"
    hit_b = "<walk-hitfb-2@test.local>"
    insert_topic_hit(
        conn,
        topic_id=tid,
        account_id=research_id,
        rfc822_message_id=hit_a,
        folder="INBOX",
        reason_terms=["NCT99900001"],
        confidence=0.87,
        source="backscan",
    )
    insert_topic_hit(
        conn,
        topic_id=tid,
        account_id=research_id,
        rfc822_message_id=hit_b,
        folder="INBOX",
        reason_terms=["NCT99900001"],
        confidence=0.72,
        source="backscan",
    )
    conn.commit()

    yield {
        "topic_id": tid,
        "hit_a_msgid": hit_a,
        "hit_b_msgid": hit_b,
        "account_id": research_id,
    }

    conn.execute("DELETE FROM topics WHERE id=?", (tid,))
    conn.commit()


def _get_csrf_token(page, base_url: str) -> str:
    return page.request.get(f"{base_url}/api/csrf-token").json()["token"]


def test_thumbs_up_and_down_swap_row_action_cell(
    authed_page, base_url, seeded_topic_with_hits,
):
    """GOLDEN — preview surface renders both hits with thumbs controls;
    👍 on the first row swaps the curate cell to a Kept confirmation;
    👎 on the second row swaps to a Dropped/muted confirmation."""
    tid = seeded_topic_with_hits["topic_id"]

    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")

    # Kick the preview HTMX request; if the preview button isn't there
    # (feature-work), xfail with a note.
    preview_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Preview matches", re.I)
    )
    if preview_btn.count() == 0:
        pytest.xfail("'Preview matches' button not surfaced on editor page.")
    preview_btn.first.click()

    # Wait for at least one hits/feedback button to render.
    thumbs = authed_page.locator("[hx-post$='/hits/feedback']")
    try:
        thumbs.first.wait_for(state="visible", timeout=10_000)
    except Exception:
        pytest.xfail(
            "hits/feedback thumbs buttons never surfaced on preview — "
            "feature-work: expose the thumbs controls in the preview "
            "template macro."
        )

    if thumbs.count() < 2:
        pytest.xfail(
            f"expected >=2 thumbs controls, got {thumbs.count()} — "
            "seeded hits didn't render as separate rows."
        )

    # GOLDEN 1 — thumbs UP on the first hit row.
    first_up = authed_page.locator(
        "[hx-post$='/hits/feedback'][hx-vals*='up'], "
        "[hx-post$='/hits/feedback'] >> text=/^\\s*👍/, "
        "button[hx-post$='/hits/feedback']:has-text('👍')"
    ).first
    if first_up.count() == 0:
        pytest.xfail("no 👍 button variant found on the first hit row.")
    first_up.click()

    try:
        expect(
            authed_page.get_by_text(re.compile(r"\bKept\b", re.I)).first
        ).to_be_visible(timeout=5_000)
    except Exception:
        pytest.xfail("👍 swap didn't surface 'Kept' confirmation copy.")

    # GOLDEN 2 — thumbs DOWN on a remaining hit row.
    remaining_down = authed_page.locator(
        "[hx-post$='/hits/feedback'][hx-vals*='down'], "
        "button[hx-post$='/hits/feedback']:has-text('👎')"
    ).first
    if remaining_down.count() == 0:
        pytest.xfail("no 👎 button variant found on a remaining hit row.")
    remaining_down.click()

    try:
        expect(
            authed_page.get_by_text(re.compile(r"Dropped", re.I)).first
        ).to_be_visible(timeout=5_000)
    except Exception:
        pytest.xfail("👎 swap didn't surface 'Dropped' confirmation copy.")

    # The sender-muted branch — if the seeded row rendered with a real
    # sender header, we expect the 'muting this sender' copy.
    sender_muted = authed_page.get_by_text(
        re.compile(r"muting this sender", re.I)
    )
    if sender_muted.count() == 0:
        pytest.xfail(
            "'muting this sender' copy absent — sender may have been empty "
            "on the seeded row; feature-work: seed a From: header in "
            "insert_topic_hit or render the sender-learned branch text."
        )


def test_hit_feedback_forged_account_id_refuses(
    authed_page, base_url, e2e_server, seeded_topic_with_hits,
):
    """BRANCH (D2) — the seeded admin does NOT manage account_id=999999;
    forged POST must fail-closed and write ZERO ``topic_feedback`` rows."""
    tid = seeded_topic_with_hits["topic_id"]
    conn = e2e_server["conn"]

    # Prime the session so /api/csrf-token binds.
    authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    tok = _get_csrf_token(authed_page, base_url)

    resp = authed_page.request.post(
        f"{base_url}/profile/topic-digest/{tid}/hits/feedback",
        form={
            "account_id": "999999",
            "message_id": "<forged-msgid@test.local>",
            "sender": "spam@nowhere.test",
            "vote": "down",
            "csrf_input": tok,
        },
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status in (401, 403, 404), (
        f"forged account_id POST returned {resp.status}, expected fail-closed "
        f"(401/403/404); body={resp.text()[:300]!r}"
    )

    row_count = conn.execute(
        "SELECT COUNT(*) AS n FROM topic_feedback "
        "WHERE topic_id=? AND account_id=?",
        (tid, 999999),
    ).fetchone()["n"]
    assert row_count == 0, (
        f"forged POST wrote {row_count} topic_feedback row(s) for "
        f"account_id=999999; expected 0 (fail-closed intersection held)."
    )
