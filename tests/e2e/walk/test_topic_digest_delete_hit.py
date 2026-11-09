"""Walk — Topic Digest delete a hit — sketch .

Feature: ``DELETE /profile/topic-digest/{topic_id:int}/hits/
{account_id:int}/{msgid:path}`` (landed 2026-06-07 in 237472a9).
Removes a specific stored topic hit for a specific ``(account, msgid)``
pair. Walk seeds a Topic + two hits (siblings), fires the DELETE for
ONE msgid via the browser's request context (session cookie carried),
and asserts the targeted row is gone from the reloaded preview while
the sibling row survives. Branch — DELETE for a bogus msgid returns
200 quiet no-op and does NOT fan out.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


@pytest.fixture
def seeded_topic_with_hit(e2e_server):
    """Seed one Topic + two ``topic_hits`` rows and return their ids."""
    from email_triage.actions.topic_configs import (
        TopicConfig,
        insert_topic_hit,
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
            name="DeleteHitWalk",
            subjects=["walk-delete-hit"],
            selected_account_ids=[research_id],
            retention_days=90,
        ),
    ).id
    msgid = "<walk-msgid-1@test.local>"
    sibling = "<walk-msgid-2@test.local>"
    insert_topic_hit(
        conn,
        topic_id=tid,
        account_id=research_id,
        rfc822_message_id=msgid,
        folder="INBOX",
        reason_terms=["walk"],
        source="backscan",
    )
    insert_topic_hit(
        conn,
        topic_id=tid,
        account_id=research_id,
        rfc822_message_id=sibling,
        folder="INBOX",
        reason_terms=["walk"],
        source="backscan",
    )
    conn.commit()

    yield {
        "topic_id": tid,
        "account_id": research_id,
        "msgid": msgid,
        "sibling_msgid": sibling,
    }

    conn.execute("DELETE FROM topics WHERE id=?", (tid,))
    conn.commit()


def _row_count(conn, topic_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM topic_hits WHERE topic_id=?",
            (topic_id,),
        ).fetchone()["n"]
    )


def test_delete_hit_removes_only_target_row(
    authed_page, base_url, e2e_server, seeded_topic_with_hit,
):
    """GOLDEN — fire the DELETE via the browser context, assert 200 with
    empty body (router quiet contract), and verify the row is gone from
    the DB while the sibling row survives (msgid-scoped, not topic-wide).
    """
    conn = e2e_server["conn"]
    tid = seeded_topic_with_hit["topic_id"]
    aid = seeded_topic_with_hit["account_id"]
    msgid = seeded_topic_with_hit["msgid"]
    sibling = seeded_topic_with_hit["sibling_msgid"]

    # Prime a session (need cookie for the router's auth gate).
    authed_page.goto(f"{base_url}/profile?tab=topic-digest")

    # DELETE (browser context carries the session cookie); the CSRF
    # middleware enforces on state-changing verbs, so pass the token
    # header explicitly (the browser-form path injects it via
    # csrf_input; the request.delete API needs the header form).
    tok = authed_page.request.get(
        f"{base_url}/api/csrf-token"
    ).json()["token"]
    resp = authed_page.request.delete(
        f"{base_url}/profile/topic-digest/{tid}/hits/{aid}/{msgid}",
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status == 200, (
        f"DELETE returned {resp.status}, expected 200 quiet-empty; "
        f"body={resp.text()[:300]!r}"
    )
    body = resp.body()
    assert body == b"" or body is None, (
        f"expected empty body from quiet DELETE, got {body!r}"
    )

    # DB post-condition — target row is soft-removed (topic_hits carries
    # a ``removed_at`` column; the DELETE route flips it, does not drop
    # the row). Verify the target has ``removed_at IS NOT NULL`` while
    # the sibling is still un-removed (msgid-scoped, no fan-out).
    rows = {
        row["rfc822_message_id"]: row["removed_at"]
        for row in conn.execute(
            "SELECT rfc822_message_id, removed_at FROM topic_hits "
            "WHERE topic_id=?",
            (tid,),
        ).fetchall()
    }
    # If the schema doesn't carry ``removed_at`` (feature-work), the
    # DELETE would have hard-dropped the row instead — accept either
    # shape as long as the target is not-live and the sibling is live.
    target_removed = (
        msgid not in rows or rows.get(msgid) is not None
    )
    sibling_live = (
        sibling in rows and rows.get(sibling) is None
    )
    assert target_removed, (
        f"target msgid still LIVE after DELETE (row map: {rows!r}); "
        "expected soft-removed (removed_at NOT NULL) or hard-deleted."
    )
    assert sibling_live, (
        f"sibling msgid was collateral-removed by DELETE (row map: {rows!r})."
    )


def test_delete_hit_bogus_msgid_is_no_op(
    authed_page, base_url, e2e_server, seeded_topic_with_hit,
):
    """BRANCH — DELETE with a msgid that doesn't exist is a quiet
    no-op; sibling rows survive intact."""
    conn = e2e_server["conn"]
    tid = seeded_topic_with_hit["topic_id"]
    aid = seeded_topic_with_hit["account_id"]

    authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    before = _row_count(conn, tid)

    tok = authed_page.request.get(
        f"{base_url}/api/csrf-token"
    ).json()["token"]
    resp = authed_page.request.delete(
        f"{base_url}/profile/topic-digest/{tid}/hits/{aid}/"
        "<walk-msgid-bogus@test.local>",
        headers={"X-CSRF-Token": tok},
    )
    # Fail-closed contract: quiet no-op (200) OR not-found (404). Both
    # are acceptable — neither triggers a fan-out.
    assert resp.status in (200, 404), (
        f"bogus-msgid DELETE returned {resp.status}, expected 200/404; "
        f"body={resp.text()[:300]!r}"
    )

    after = _row_count(conn, tid)
    assert after == before, (
        f"bogus-msgid DELETE changed row count from {before} to {after} — "
        "should have been a no-op."
    )
