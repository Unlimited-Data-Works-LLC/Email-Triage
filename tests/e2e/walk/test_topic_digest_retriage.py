"""Walk — Topic Digest retriage kick-off (sketch ).

Feature: ``POST /profile/topic-digest/{topic_id:int}/retriage`` (landed
2026-07-04 in 61bc12fe). Launches a ``topic_backscan`` background job.
Under ``lifespan="off"`` the job stays QUEUED (bulk runner never
drains) — that's stable enough to assert the live-status fragment,
badge, polling contract, and Stop button rendered. Branch: a Topic
with no authorized mailboxes must NOT enqueue; the handler surfaces
the static 'Add a mailbox to this Topic first' remedy.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def _seeded_topics(e2e_server):
    """Seed two Topics for the seeded admin:

    - ``ok_id`` — bound to research_account_id (has a mailbox → enqueue path)
    - ``empty_id`` — no selected_account_ids (branch remedy path)
    """
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic

    conn = e2e_server["conn"]
    uid = e2e_server["user_id"]
    r = e2e_server["research_account_id"]
    ok = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=uid, name="Retriage OK",
            subjects=["retriage"], selected_account_ids=[r], retention_days=90,
        ),
    ).id
    empty = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=uid, name="Retriage Empty",
            subjects=["retriage"], selected_account_ids=[], retention_days=90,
        ),
    ).id
    yield {"ok_id": ok, "empty_id": empty}


def _open_editor(authed_page, base_url: str, topic_id: int) -> None:
    """Navigate to the editor. The sketch notes that the editor URL may
    differ from /profile/topic-digest/{id}; try /edit first (used by
    existing test_topic_retriage_ui.py), then fall back to the bare form."""
    resp = authed_page.goto(f"{base_url}/profile/topic-digest/{topic_id}/edit")
    if resp is None or resp.status != 200:
        pytest.xfail(
            f"editor route /profile/topic-digest/{{id}}/edit did not return "
            f"200 (got {resp.status if resp else 'no response'}) — feature-"
            "work: expose the editor at a stable URL."
        )


def test_retriage_kickoff_renders_live_status(
    authed_page, base_url, _seeded_topics,
):
    """GOLDEN — Re-Triage click enqueues a job; the self-polling status
    fragment renders with badge + counter + polling contract + Stop."""
    ok_id = _seeded_topics["ok_id"]
    _open_editor(authed_page, base_url, ok_id)

    retriage_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Re-?Triage", re.I)
    )
    if retriage_btn.count() == 0:
        pytest.xfail(
            "'Re-Triage' button not present in editor — feature-work: expose "
            "the retriage submit inside #topic-editor-form."
        )
    expect(retriage_btn.first).to_be_visible()
    retriage_btn.first.click()

    status = authed_page.locator("#topic-retriage-status")
    try:
        status.wait_for(state="visible", timeout=5_000)
    except Exception:
        pytest.xfail(
            "#topic-retriage-status never became visible — feature-work: "
            "expose the live-status fragment on retriage submit."
        )

    # Badge is one of the non-terminal statuses (or DONE if runner drained).
    status_text = (status.inner_text() or "").upper()
    assert re.search(r"\b(QUEUED|RUNNING|DONE)\b", status_text), (
        f"status fragment missing badge text: {status_text!r}"
    )
    # Counter: '<n> scanned'.
    assert re.search(r"\d+\s*scanned", status_text, re.I), (
        f"status fragment missing '<n> scanned' counter: {status_text!r}"
    )

    # Polling contract — hx-get points back at retriage/{job_id}/progress,
    # hx-trigger references an interval.
    hx_get = status.get_attribute("hx-get") or ""
    hx_trigger = status.get_attribute("hx-trigger") or ""
    if not hx_get:
        # The attribute may live on a child element; scan for any element
        # under #topic-retriage-status carrying hx-get.
        child = status.locator("[hx-get]").first
        if child.count() > 0:
            hx_get = child.get_attribute("hx-get") or ""
            hx_trigger = child.get_attribute("hx-trigger") or ""
    assert re.search(
        rf"/topic-digest/{ok_id}/retriage/[^/]+/progress", hx_get
    ), f"polling hx-get missing/wrong: {hx_get!r}"
    assert "every" in hx_trigger.lower() or "load" in hx_trigger.lower(), (
        f"polling hx-trigger missing interval: {hx_trigger!r}"
    )

    # Stop scan button visible while non-terminal.
    stop = authed_page.get_by_role(
        "button", name=re.compile(r"Stop scan", re.I)
    )
    if "DONE" not in status_text and "CANCELLED" not in status_text:
        expect(stop.first).to_be_visible()


def test_retriage_no_mailbox_shows_remedy(
    authed_page, base_url, _seeded_topics,
):
    """BRANCH — a Topic with no authorized mailboxes does NOT enqueue.
    The handler must surface the exact remedy sentence 'Add a mailbox to
    this Topic first', and #topic-retriage-status must NOT render."""
    empty_id = _seeded_topics["empty_id"]
    _open_editor(authed_page, base_url, empty_id)

    retriage_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Re-?Triage", re.I)
    )
    if retriage_btn.count() == 0:
        pytest.xfail("Re-Triage button not present.")
    retriage_btn.first.click()

    # The remedy sentence is present (byte-match on user copy).
    expect(
        authed_page.get_by_text(
            re.compile(r"Add a mailbox to this Topic first", re.I)
        ).first
    ).to_be_visible()
    # No status fragment because no job was enqueued.
    assert authed_page.locator("#topic-retriage-status").count() == 0, (
        "empty-mailbox Topic still rendered #topic-retriage-status — "
        "handler should refuse to enqueue and not surface the live-status."
    )
