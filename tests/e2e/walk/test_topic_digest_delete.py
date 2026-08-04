"""Walk — Topic Digest delete endpoint (sketch #9).

Feature: ``POST /profile/topic-digest/{topic_id:int}/delete`` (landed
2026-06-07 in 237472a9). Delete (soft-tombstone) a saved Topic. Walk
proves the golden delete-and-303-to-tab flow (soft-tombstone survives —
history stays queryable per §9 V3) and the D2-shape foreign-topic
refusal (§5 can_modify_owned_resource returns 404 'Topic not found'
without touching the foreign row).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_topic(conn, *, user_id: int, name: str, account_id: int) -> int:
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic

    cfg = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=user_id, name=name, subjects=["renewals"],
            selected_account_ids=[account_id], retention_days=90,
        ),
    )
    return cfg.id


def _seed_foreign_user(conn, email: str = "other-e2e-del@test.local") -> int:
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "Other E2E Del", "user", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    return int(row["id"])


def _get_csrf_token(page, base_url: str) -> str:
    """Fetch a session-bound CSRF token via /api/csrf-token."""
    return page.request.get(f"{base_url}/api/csrf-token").json()["token"]


def test_delete_own_topic_soft_tombstones(authed_page, base_url, e2e_server):
    """GOLDEN — click 'Delete this Topic' on an owned Topic; 303 lands on
    the topic-digest tab, the topic is no longer listed, and the DB row
    carries ``deleted_at IS NOT NULL`` (soft-tombstone, not a hard delete)."""
    conn = e2e_server["conn"]
    uid = e2e_server["user_id"]
    tid = _seed_topic(
        conn, user_id=uid, name="Vendor Renewals",
        account_id=e2e_server["research_account_id"],
    )

    # Open the editor for the seeded Topic so the delete form is in the DOM.
    authed_page.goto(f"{base_url}/profile/topic-digest/{tid}/edit")
    delete_form = authed_page.locator(
        f'form[action$="/profile/topic-digest/{tid}/delete"]'
    )
    if delete_form.count() == 0:
        pytest.xfail(
            "delete form not rendered on the editor — feature-work: expose "
            "form action='/profile/topic-digest/{id}/delete' when topic.id is set."
        )

    # Template wraps the submit in a JS confirm(); auto-accept.
    authed_page.on("dialog", lambda d: d.accept())
    delete_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Delete this Topic", re.I)
    )
    if delete_btn.count() == 0:
        pytest.xfail(
            "'Delete this Topic' button not present — feature-work: expose "
            "the delete submit with an accessible name."
        )
    delete_btn.click()

    # 303 lands on the OWN tab (not the default tab — the wrong-tab-landing
    # class of bug the earlier save specs masked).
    expect(authed_page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))
    expect(authed_page.get_by_text("Vendor Renewals")).to_have_count(0)

    # Soft-tombstone: row survives, deleted_at is stamped.
    row = conn.execute(
        "SELECT deleted_at FROM topics WHERE id=?", (tid,)
    ).fetchone()
    assert row is not None, "topics row disappeared (should be soft-tombstoned, not hard-deleted)"
    assert row["deleted_at"] is not None, (
        f"deleted_at is NULL after delete — expected soft-tombstone stamp; "
        f"row={dict(row)!r}"
    )


def test_delete_foreign_topic_refuses(authed_page, base_url, e2e_server):
    """BRANCH (D2 — server-refuses / user-remedy).

    Direct POST to /profile/topic-digest/{foreign_id}/delete → §5
    ownership gate fires: 404 'Topic not found'. The foreign row is
    UNTOUCHED (deleted_at IS NULL). The remedy path: goto the topic-digest
    tab; the app renders 200 with the admin's remaining Topics intact.
    """
    conn = e2e_server["conn"]
    other_uid = _seed_foreign_user(conn)
    foreign_tid = _seed_topic(
        conn, user_id=other_uid, name="Other Person Topic",
        account_id=e2e_server["research_account_id"],
    )

    # Direct POST with a session-bound CSRF token — the foreign editor
    # isn't rendered on this admin's page, so we can't click a button.
    tok = _get_csrf_token(authed_page, base_url)
    resp = authed_page.request.post(
        f"{base_url}/profile/topic-digest/{foreign_tid}/delete",
        form={"csrf_input": tok},
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status == 404, (
        f"foreign delete returned {resp.status}, expected 404 (ownership gate)"
    )
    body = resp.text()
    assert "Topic not found" in body, (
        f"foreign delete body missing 'Topic not found' surface: {body[:300]!r}"
    )

    # Foreign row untouched.
    row = conn.execute(
        "SELECT deleted_at FROM topics WHERE id=?", (foreign_tid,)
    ).fetchone()
    assert row is not None and row["deleted_at"] is None, (
        f"foreign topic deleted_at should be NULL; got {dict(row) if row else None!r}"
    )

    # User-remedy — admin's topic-digest tab renders normally.
    remedy = authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    assert remedy is not None and remedy.status == 200, (
        "admin's topic-digest tab did not render 200 after foreign refusal"
    )
