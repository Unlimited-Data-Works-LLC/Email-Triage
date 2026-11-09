"""E2E — the back-scan 50k-ceiling user-facing banner.

Real-chromium confirmation that when a back-scan hit the enumeration ceiling
(``ceiling_hit`` on the job row), the Re-Triage progress fragment renders the
end-user "narrow the window / re-run" banner — the real-browser review the
binding UI rule requires for a template change. The TestClient route tests cover
the flag→render; this is the live-render net.
"""
from __future__ import annotations

import json as _json

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_backscan_ceiling_banner_renders_for_owner(
    authed_page, base_url, e2e_server,
):
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic
    from email_triage.web.db import (
        create_triage_job,
        set_triage_job_ceiling_hit,
    )

    conn = e2e_server["conn"]
    acct = e2e_server["research_account_id"]
    uid = e2e_server["user_id"]

    tid = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=uid, name="Ceiling Topic",
            details="big window", topic_version=1,
        ),
    ).id
    jid = create_triage_job(
        conn, account_id=acct, actor_user_id=uid,
        query=_json.dumps({"topic_id": tid, "window_days": 30}),
        rate_msg_per_min=600, concurrency=1, kind="topic_backscan",
    )
    set_triage_job_ceiling_hit(conn, jid)

    authed_page.goto(
        f"{base_url}/profile/topic-digest/{tid}/retriage/{jid}/progress"
    )
    expect(
        authed_page.get_by_text(
            "more mail than a single scan can reach", exact=False
        )
    ).to_be_visible()
    expect(
        authed_page.get_by_text("picks up where this scan left off", exact=False)
    ).to_be_visible()
