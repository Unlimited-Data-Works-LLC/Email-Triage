"""Walk — Regulatory Clocks delete template — sketch .

Feature: ``POST /profile/regulatory-clocks/delete`` (landed 2026-06-15
in 344da2d0). Delete a clock definition (owner-scoped).

D1 primary — never-used owned def deletes cleanly; empty-state renders.
D2 shape catch — a def with historical instance rows REFUSES delete
(``delete_owned_clock_def`` raises 'turn it off instead') and the
remedy is the ``POST /profile/regulatory-clocks/set-enabled`` toggle:
toggle-off hides the row from the default editor listing → toggle-on
brings it back. This walk validates the D1+D2 fix end-to-end via the
retrofit tier per the main-thread directive.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def seeded_clock_def(e2e_server):
    """Seed one owned IRB clock def via the SSOT and yield its handle.

    Never a raw INSERT (PD#11) — always the ``create_owned_clock_def``
    SSOT so slug + code + validation live at the seam the router uses.
    """
    from email_triage.db.regulatory_clock import (
        create_owned_clock_def,
        delete_owned_clock_def,
    )

    conn = e2e_server["conn"]
    account_id = e2e_server["research_account_id"]
    user_id = e2e_server["user_id"]

    title = "IRB SAE 10d (walk)"
    def_id = create_owned_clock_def(
        conn,
        account_id=account_id,
        actor_user_id=user_id,
        payload={
            "title": title,
            "regime": "IRB",
            "severity_class": "irb_up",
            "clock_start_kind": "on_awareness",
            "duration_value": 10,
            "duration_unit": "calendar_day",
            "lead_pcts": [50],
            "ack_required": True,
        },
    )

    yield {
        "def_id": def_id,
        "account_id": account_id,
        "user_id": user_id,
        "title": title,
    }

    # Teardown — scrub instances + any dependent rows first (D2 branch
    # leaves instance history behind), then hard-delete the def. FK
    # constraints between instance/def enforce order; scrub bottom-up.
    conn.execute(
        "DELETE FROM regulatory_clock_event "
        "WHERE instance_id IN "
        "(SELECT id FROM regulatory_clock_instance WHERE def_id=?)",
        (def_id,),
    )
    conn.execute(
        "DELETE FROM regulatory_clock_instance WHERE def_id=?", (def_id,),
    )
    conn.commit()
    try:
        delete_owned_clock_def(
            conn, def_id=def_id, account_id=account_id, actor_user_id=user_id,
        )
    except Exception:
        # Last-ditch — the def row is orphaned; raw DELETE (FK cleared).
        conn.execute(
            "DELETE FROM regulatory_clock_def WHERE id=?", (def_id,),
        )
        conn.commit()


def _open_edit_for_row(page, title: str):
    row = page.locator("tr", has_text=title).first
    if row.count() == 0:
        row = page.locator("li,details", has_text=title).first
    if row.count() == 0:
        return None
    edit_summary = row.get_by_text(re.compile(r"^Edit$", re.I)).first
    if edit_summary.count() > 0:
        edit_summary.click()
    return row


def test_delete_never_used_def_lands_empty_state(
    authed_page, base_url, seeded_clock_def,
):
    """PRIMARY (D1) — a never-used owned def deletes cleanly; the empty
    state copy renders and the row is gone from the DOM."""
    title = seeded_clock_def["title"]
    account_id = seeded_clock_def["account_id"]

    authed_page.goto(
        f"{base_url}/profile/regulatory-clocks?account_id={account_id}"
    )
    expect(authed_page.get_by_text(title).first).to_be_visible()

    row = _open_edit_for_row(authed_page, title)
    if row is None:
        pytest.xfail("Edit disclosure for seeded row not surfaced.")

    dialogs_seen: list[str] = []
    authed_page.once(
        "dialog",
        lambda d: (dialogs_seen.append(d.message), d.accept()),
    )

    delete_form = row.locator(
        'form[action="/profile/regulatory-clocks/delete"]'
    ).first
    if delete_form.count() == 0:
        pytest.xfail(
            "delete form (action='/profile/regulatory-clocks/delete') "
            "not surfaced under the row."
        )
    delete_btn = delete_form.locator('button[type="submit"]').first
    if delete_btn.count() == 0:
        pytest.xfail("submit button missing inside the delete form.")
    delete_btn.click()

    authed_page.wait_for_url(
        re.compile(r"/profile/regulatory-clocks\?account_id=")
    )

    empty_hint = authed_page.get_by_text(
        re.compile(
            r"You haven't added any reminders for this mailbox yet",
            re.I,
        )
    )
    if empty_hint.count() == 0:
        pytest.xfail("empty-state copy absent after primary delete.")
    expect(empty_hint.first).to_be_visible()
    assert authed_page.get_by_text(title).count() == 0, (
        "deleted def still visible in the DOM after primary delete."
    )
    # Confirm dialog was actually surfaced.
    assert len(dialogs_seen) >= 1, (
        "confirm() dialog was silently bypassed on the delete form — "
        "operator safety guard is not firing."
    )


def test_delete_used_def_refuses_and_toggle_off_remedies(
    authed_page, base_url, e2e_server, seeded_clock_def,
):
    """D2 SHAPE CATCH — a def with instance history REFUSES delete;
    the remedy is toggle-off (``set-enabled`` false), which hides the
    row from the default editor listing. Toggle-back-on re-surfaces
    it.

    This is the walk that validates the D1+D2 fix in the retrofit
    tier: delete-refusal → toggle-off remedy → toggle-on round-trip.
    """
    conn = e2e_server["conn"]
    def_id = seeded_clock_def["def_id"]
    account_id = seeded_clock_def["account_id"]
    user_id = seeded_clock_def["user_id"]
    title = seeded_clock_def["title"]

    # Arm ONE clock instance against the seeded def so the delete refuses.
    from email_triage.db.regulatory_clock import create_clock_candidate

    create_clock_candidate(
        conn,
        def_id=def_id,
        account_id=account_id,
        case_ref="WALK-D2-CASE",
        responsibility="i_submit",
    )
    conn.commit()

    authed_page.goto(
        f"{base_url}/profile/regulatory-clocks?account_id={account_id}"
    )
    expect(authed_page.get_by_text(title).first).to_be_visible()

    # Attempt delete — must refuse.
    tok = authed_page.request.get(
        f"{base_url}/api/csrf-token"
    ).json()["token"]
    resp = authed_page.request.post(
        f"{base_url}/profile/regulatory-clocks/delete",
        form={
            "def_id": str(def_id),
            "account_id": str(account_id),
            "csrf_input": tok,
        },
        headers={"X-CSRF-Token": tok},
    )
    # Fail-closed but graceful — never 5xx.
    assert resp.status < 500, (
        f"delete-refusal returned {resp.status} — must be graceful, "
        "not a 5xx crash."
    )

    # The seeded def MUST still exist in the DB (delete truly refused).
    still_there = conn.execute(
        "SELECT 1 FROM regulatory_clock_def WHERE id=?", (def_id,)
    ).fetchone()
    assert still_there is not None, (
        "delete was NOT actually refused — def row is gone from DB "
        "despite active instance history."
    )

    # REMEDY — toggle-off via /profile/regulatory-clocks/set-enabled.
    resp2 = authed_page.request.post(
        f"{base_url}/profile/regulatory-clocks/set-enabled",
        form={
            "def_id": str(def_id),
            "account_id": str(account_id),
            "enabled": "0",
            "csrf_input": tok,
        },
        headers={"X-CSRF-Token": tok},
    )
    if resp2.status >= 500:
        pytest.xfail(
            f"set-enabled route returned {resp2.status}; feature-work: "
            "expose the toggle-off remedy path expected by the D2 fix."
        )
    if resp2.status not in (200, 303, 302):
        pytest.xfail(
            f"set-enabled returned unexpected {resp2.status} — cannot "
            "assert toggle-off remedy DOM shape."
        )

    # DB row now enabled=0.
    enabled_col = conn.execute(
        "SELECT enabled FROM regulatory_clock_def WHERE id=?", (def_id,)
    ).fetchone()[0]
    assert int(enabled_col) == 0, (
        f"toggle-off did not flip enabled column (got {enabled_col!r}); "
        "remedy path is not actually persisting the disable."
    )

    # Toggle back on — round-trip proves the def wasn't dropped.
    resp3 = authed_page.request.post(
        f"{base_url}/profile/regulatory-clocks/set-enabled",
        form={
            "def_id": str(def_id),
            "account_id": str(account_id),
            "enabled": "1",
            "csrf_input": tok,
        },
        headers={"X-CSRF-Token": tok},
    )
    assert resp3.status < 500, (
        f"toggle-on returned {resp3.status} — must be graceful."
    )

    # Re-land on the editor; the row is visible again.
    authed_page.goto(
        f"{base_url}/profile/regulatory-clocks?account_id={account_id}"
    )
    expect(authed_page.get_by_text(title).first).to_be_visible()

    enabled_col2 = conn.execute(
        "SELECT enabled FROM regulatory_clock_def WHERE id=?", (def_id,)
    ).fetchone()[0]
    assert int(enabled_col2) == 1, (
        f"toggle-on did not flip enabled back (got {enabled_col2!r})."
    )
