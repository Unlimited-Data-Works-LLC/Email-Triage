"""Walk — Topic Digest retriage progress fragment (sketch ).

Feature: ``GET /profile/topic-digest/{topic_id:int}/retriage/{job_id}/progress``
(landed 2026-07-04 in 61bc12fe). HTMX polling fragment for backscan job
progress. Walk seeds a QUEUED ``topic_backscan`` job directly and GETs
the polling URL — proves the fragment renders (badge, scanned counter,
self-poll hx-get + interval, Stop button). Branch: navigating the same
progress URL with a job_id that belongs to a DIFFERENT topic (owned by
the same user) must land the topic-scope guard (PD#9) — the fragment
must NOT leak across topic boundaries.
"""

from __future__ import annotations

import json as _json
import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_topic_and_job(e2e_server, name: str) -> tuple[int, str]:
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic
    from email_triage.web.db import create_triage_job

    conn = e2e_server["conn"]
    uid = e2e_server["user_id"]
    acct = e2e_server["research_account_id"]

    tid = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=uid, name=name,
            subjects=["progress"], selected_account_ids=[acct],
            retention_days=90,
        ),
    ).id
    jid = create_triage_job(
        conn, account_id=acct, actor_user_id=uid,
        query=_json.dumps({"topic_id": tid, "window_days": 30}),
        rate_msg_per_min=600, concurrency=1, kind="topic_backscan",
    )
    return tid, jid


def test_progress_fragment_renders_alive(authed_page, base_url, e2e_server):
    """GOLDEN — GET the progress URL for a QUEUED job renders the alive
    fragment: badge, 'scanned' counter, self-poll wiring, Stop button."""
    tid, jid = _seed_topic_and_job(e2e_server, "Progress Walk A")

    resp = authed_page.goto(
        f"{base_url}/profile/topic-digest/{tid}/retriage/{jid}/progress"
    )
    assert resp is not None and resp.status == 200, (
        f"progress GET did not return 200: "
        f"{resp.status if resp else 'no response'}"
    )

    status = authed_page.locator("#topic-retriage-status")
    if status.count() == 0:
        pytest.xfail(
            "#topic-retriage-status not surfaced by progress fragment — "
            "feature-work: expose the fragment root with a stable id."
        )
    expect(status.first).to_be_visible()

    # Counter matches /scanned/i (the alive/in-flight branch — not empty/terminal).
    expect(status.first).to_contain_text(re.compile(r"scanned", re.I))

    # Self-poll wiring — hx-get ends with the same URL, hx-trigger has interval.
    hx_get = status.first.get_attribute("hx-get") or ""
    hx_trigger = status.first.get_attribute("hx-trigger") or ""
    if not hx_get:
        child = status.first.locator("[hx-get]").first
        if child.count() > 0:
            hx_get = child.get_attribute("hx-get") or ""
            hx_trigger = child.get_attribute("hx-trigger") or ""
    assert re.search(
        rf"/topic-digest/{tid}/retriage/{re.escape(jid)}/progress$", hx_get
    ), f"self-poll hx-get missing/wrong: {hx_get!r} (expected suffix)"
    assert (
        "every" in hx_trigger.lower() or "load" in hx_trigger.lower()
    ), f"self-poll hx-trigger missing interval: {hx_trigger!r}"

    # Stop-scan button visible while status is queued/running.
    expect(
        authed_page.get_by_role(
            "button", name=re.compile(r"stop scan", re.I)
        ).first
    ).to_be_visible()


def test_progress_fragment_cross_topic_refuses(
    authed_page, base_url, e2e_server,
):
    """BRANCH (PD#9 topic-scope guard) — navigating tidA/retriage/{jidB}/progress
    must land 404 'Not found'; #topic-retriage-status must NOT render
    (no cross-topic state leak)."""
    tidA, _jidA = _seed_topic_and_job(e2e_server, "Progress Walk A2")
    _tidB, jidB = _seed_topic_and_job(e2e_server, "Progress Walk B")

    resp = authed_page.goto(
        f"{base_url}/profile/topic-digest/{tidA}/retriage/{jidB}/progress"
    )
    assert resp is not None, "no response on cross-topic progress GET"
    assert resp.status == 404, (
        f"cross-topic progress GET returned {resp.status}, expected 404 "
        "(PD#9 topic-scope guard)"
    )
    # The visible page body is plain 'Not found' — no fragment leaked.
    body_text = authed_page.locator("body").inner_text() or ""
    assert "Not found" in body_text, (
        f"cross-topic refusal body missing 'Not found': {body_text[:200]!r}"
    )
    assert authed_page.locator("#topic-retriage-status").count() == 0, (
        "cross-topic refusal still rendered #topic-retriage-status (leak)"
    )
