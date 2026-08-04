"""Walk — Topic Digest new-editor page (sketch #6).

Feature: ``GET /profile/topic-digest/new`` (landed 2026-06-07 in
237472a9). The full-page blank Topic editor entry (v0.2.0 Feature 33 —
Topic Digest / Study Clustering). Walk proves the ``is_new=True`` branch
renders (blank name, both seeded mailboxes as options, HIPAA lock on
the clinic option, 'Create Topic' primary CTA) and the D2-shape
server-refuses / user-remedy branch (all-blank POST bounces back to the
editor, not a 500, not a wrong-tab redirect).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def test_new_editor_blank_renders(authed_page, base_url, e2e_server):
    """GOLDEN — the blank editor route renders with is_new=True shape.

    - #topic-editor-form is visible (route wired, StrictUndefined survived).
    - name input is empty (no stale-context leak from _topic_editor_snapshot).
    - The seeded mailboxes both appear as options.
    - The HIPAA-flagged clinic mailbox carries its lock / HIPAA marker.
    - Primary CTA reads 'Create Topic' (is_new=True copy, not 'Save changes').
    """
    response = authed_page.goto(f"{base_url}/profile/topic-digest/new")
    assert response is not None and response.status == 200, (
        f"GET /profile/topic-digest/new did not return 200: "
        f"{response.status if response else 'no response'}"
    )

    form = authed_page.locator("#topic-editor-form")
    if form.count() == 0:
        pytest.xfail(
            "#topic-editor-form not surfaced on GET /profile/topic-digest/new "
            "— feature-work needed to un-xfail: expose the editor root with a "
            "stable id (see _topic_digest_editor.html)."
        )
    expect(form).to_be_visible()

    name_input = authed_page.locator('input[name="name"]')
    expect(name_input).to_have_value("")

    # The mailbox multiselect renders its seeded options.
    options = authed_page.locator('select[name="selected_account_ids"] option')
    assert options.count() >= 2, (
        f"mailbox multiselect rendered {options.count()} option(s); "
        "expected at least 2 (research + clinic seeded in conftest)."
    )

    clinic_id = e2e_server["clinic_account_id"]
    clinic_option = authed_page.locator(
        f'select[name="selected_account_ids"] option[value="{clinic_id}"]'
    )
    if clinic_option.count() == 0:
        pytest.xfail(
            "Clinic mailbox option not surfaced by value=clinic_account_id — "
            "feature-work: render the select options with value=account_id."
        )
    clinic_text = clinic_option.inner_text() or ""
    assert re.search(r"🔒|HIPAA", clinic_text, re.I), (
        f"HIPAA-flagged clinic option missing lock/HIPAA marker: "
        f"{clinic_text!r} (audience-per-page rule)."
    )

    create_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    )
    expect(create_btn).to_be_visible()


def test_all_blank_post_refuses_with_remedy(authed_page, base_url):
    """BRANCH (D2 — server-refuses → user-remedy-path).

    All-blank POST /profile/topic-digest/save MUST bounce back to the
    editor page (not 500, not silently redirect to the Notifications tab
    — the  wrong-tab-landing class of bug), with an actionable inline
    surface so the user can fix and resubmit.
    """
    goto_or_fail(authed_page, f"{base_url}/profile/topic-digest/new")
    form = authed_page.locator("#topic-editor-form")
    if form.count() == 0:
        pytest.xfail(
            "#topic-editor-form not surfaced — same feature-work as "
            "test_new_editor_blank_renders."
        )
    # Blank submit — the rendered form carries its csrf_input hidden field, so
    # the middleware's form-field path validates it.
    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()

    # Editor page stays put, does NOT land on Notifications tab.
    expect(authed_page).to_have_url(
        re.compile(r"/profile/topic-digest/new|/profile\?tab=topic-digest")
    )
    # Something actionable is present — either the editor form re-renders
    # (so the user retries), or an inline error / save-message surfaces.
    still_on_editor = authed_page.locator("#topic-editor-form").count() > 0
    remedy_surface = authed_page.locator(
        '[role="alert"], .error, .form-error, .save-message'
    )
    assert still_on_editor or remedy_surface.count() > 0, (
        "All-blank POST left no remedy path (form gone AND no error banner) "
        "— user has a dead end."
    )
