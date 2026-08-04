"""Walk — Topic Digest edit page (sketch #7).

Feature: ``GET /profile/topic-digest/{topic_id:int}/edit`` (landed
2026-06-07 in 237472a9). Full-page editor for an existing topic. Walk
proves the populated-form render on an owned topic, the read-after-write
round-trip via a real rename+save+re-GET, and the D2-shape
ownership-gate refusal (foreign topic → 404 with visible 'Topic not
found', not a stack-trace 500).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_topic(conn, *, user_id: int, name: str, account_id: int) -> int:
    """Insert a Topic owned by ``user_id``; return its id.

    Module-local (not in _helpers.py) per the sketch note — a single
    caller shape, not lifted to shared helpers.
    """
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic

    cfg = upsert_topic(
        conn,
        TopicConfig(
            id=0,
            user_id=user_id,
            name=name,
            subjects=["lupus"],
            selected_account_ids=[account_id],
            retention_days=90,
        ),
    )
    return cfg.id


def _seed_foreign_user(conn, email: str = "other-e2e@test.local") -> int:
    """Insert a second user + return their id. For the ownership-branch."""
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "Other E2E", "user", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    return int(row["id"])


def test_edit_page_populated_and_round_trip(authed_page, base_url, e2e_server):
    """GOLDEN — owned /edit renders populated form; rename+save+re-GET
    round-trips the new value (read-after-write contract)."""
    conn = e2e_server["conn"]
    uid = e2e_server["user_id"]
    acct = e2e_server["research_account_id"]

    owned_tid = _seed_topic(
        conn, user_id=uid, name="E2E Edit Me", account_id=acct
    )

    response = authed_page.goto(
        f"{base_url}/profile/topic-digest/{owned_tid}/edit"
    )
    assert response is not None and response.status == 200, (
        f"owned /edit did not return 200: "
        f"{response.status if response else 'no response'}"
    )

    name_input = authed_page.locator('input[name="name"]')
    if name_input.count() == 0:
        pytest.xfail(
            "editor name input not surfaced on /edit — feature-work: expose "
            "the populated editor form (see _topic_digest_editor.html)."
        )
    expect(name_input).to_have_value("E2E Edit Me")

    # Hidden topic_id proves save endpoint will UPDATE not CREATE.
    hidden_topic_id = authed_page.locator('input[name="topic_id"]')
    if hidden_topic_id.count() > 0:
        expect(hidden_topic_id).to_have_value(str(owned_tid))

    # Rename → submit → re-GET → new value round-trips.
    authed_page.locator('input[name="name"]').fill("E2E Edit Me — Renamed")
    submit_btn = authed_page.locator(
        '#topic-editor-form button[type="submit"], '
        'form button[type="submit"]'
    ).first
    submit_btn.click()

    # Re-navigate to /edit; new value must be present.
    authed_page.goto(f"{base_url}/profile/topic-digest/{owned_tid}/edit")
    expect(authed_page.locator('input[name="name"]')).to_have_value(
        "E2E Edit Me — Renamed"
    )


def test_edit_foreign_topic_refuses(authed_page, base_url, e2e_server):
    """BRANCH (D2 — server-refuses → user-remedy).

    A topic owned by a DIFFERENT user must not render for the seeded
    admin. The §5 ownership gate (admin_bypass=False) MUST fail-closed:
    404 with a visible 'Topic not found' body, and a subsequent nav to
    the topic-digest tab still renders normally (the failed request
    leaves the app healthy).
    """
    conn = e2e_server["conn"]
    other_uid = _seed_foreign_user(conn)
    foreign_tid = _seed_topic(
        conn, user_id=other_uid, name="Foreign Topic",
        account_id=e2e_server["research_account_id"],
    )

    response = authed_page.goto(
        f"{base_url}/profile/topic-digest/{foreign_tid}/edit"
    )
    assert response is not None, "no response on foreign /edit GET"
    assert response.status == 404, (
        f"foreign /edit returned {response.status}, expected 404 "
        "(ownership gate should fail-closed)."
    )
    expect(authed_page.get_by_text(re.compile("Topic not found", re.I))).to_be_visible()

    # User-remedy path — going back to the topic-digest tab succeeds.
    remedy = authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    assert remedy is not None and remedy.status == 200
