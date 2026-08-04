"""N-109 real-browser review (binding UI rule): a deactivated (Removed,
creds-purged) account is HIDDEN from an operational picker but stays VISIBLE in
the management view — verified in a real Chromium page, not a TestClient string
assert.

Picker exercised: the Topic-digest account multiselect (``selected_account_ids``)
fed by ``_topic_editor_snapshot`` → ``picker_accounts`` (active-only for a new
Topic). Management view: the ``/accounts`` roster (must keep the deactivated
account so it can be re-enabled, like a disabled user).
"""
from __future__ import annotations

import pytest
from playwright.sync_api import expect

from email_triage.web.db import create_email_account
from email_triage.db.accounts import set_account_active

pytestmark = pytest.mark.e2e


def _seed_deactivated(conn, user_id: int) -> int:
    aid = create_email_account(
        conn, user_id=user_id, name="N109 Deactivated E2E",
        provider_type="imap",
        config={"push_enabled": False, "poll_enabled": False,
                "account": "n109-dead@test.local"},
        hipaa=False,
    )
    set_account_active(conn, aid, False)
    conn.commit()
    return aid


def test_deactivated_account_hidden_from_picker(authed_page, e2e_server):
    """The Topic-digest account multiselect (a picker) hides a deactivated
    account; active accounts are still offered."""
    _seed_deactivated(e2e_server["conn"], e2e_server["user_id"])

    authed_page.goto("/profile/topic-digest/new")
    multiselect = authed_page.locator('select[name="selected_account_ids"]')
    # The native <select> is progressively enhanced by a ``data-multiselect``
    # widget that HIDES it (a custom dropdown renders in its place), so it is
    # NOT visible — assert it is ATTACHED and read the server-rendered <option>
    # set directly. N-109's ``active_only=True`` omits a deactivated account's
    # <option> SERVER-SIDE; the visual widget is irrelevant to what's in the
    # option list. ``all_text_contents`` (not ``inner_text``) returns the option
    # text regardless of the hidden parent — ``inner_text`` would return "" here.
    expect(multiselect).to_have_count(1)
    options = " ".join(multiselect.locator("option").all_text_contents())

    assert "Research Inbox" in options, (
        "an ACTIVE account must still be offered in the picker"
    )
    assert "N109 Deactivated E2E" not in options, (
        "a DEACTIVATED account must be HIDDEN from the picker"
    )


def test_deactivated_account_visible_in_management(authed_page, e2e_server):
    """The /accounts management roster KEEPS the deactivated account (so it can
    be re-enabled) — the inverse of the picker."""
    _seed_deactivated(e2e_server["conn"], e2e_server["user_id"])

    authed_page.goto("/accounts")
    body = authed_page.content()
    assert "N109 Deactivated E2E" in body, (
        "a DEACTIVATED account must stay VISIBLE in the management view "
        "(re-enable path), like a disabled user in the user list"
    )
