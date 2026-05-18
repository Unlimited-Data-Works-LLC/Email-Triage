"""HTTP-route tests for the per-account calendar selection
endpoints (#105 phase 1A).

Covers /accounts/{id}/calendars/discover (HTMX-triggered fetch +
table render) and /accounts/{id}/calendars/save (form persistence
into config_json["calendars"]).

Lower-level helpers (normalize_calendars, parse_calendars_form,
calendars_with_role) live in tests/test_calendars_module.py.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

import pytest

from email_triage.web.db import create_email_account, get_email_account


def _seed_gmail_account(db, user_id: int, *, name="acct") -> int:
    return create_email_account(
        db, user_id=user_id, name=name,
        provider_type="gmail_api",
        config={"account": "u@gmail.com"},
    )


def _form_post(client, url, items, cookies=None):
    """POST a form with possibly duplicate keys (e.g. arrays).

    httpx TestClient's ``data=`` kwarg silently drops list-of-tuple
    input for arrays; use raw ``content=`` with the
    application/x-www-form-urlencoded content type so the form
    fields actually reach the server.
    """
    body = urlencode(items)
    return client.post(
        url,
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
        cookies=cookies or {},
    )


# ---------------------------------------------------------------------------
# /calendars/discover — auth gates
# ---------------------------------------------------------------------------


def test_discover_anonymous_unauthorized(client, db, admin_user):
    aid = _seed_gmail_account(db, admin_user["id"])
    r = client.post(f"/accounts/{aid}/calendars/discover")
    assert r.status_code == 401


def test_discover_other_user_forbidden(
    client, db, admin_user, regular_user, user_cookies,
):
    """Regular user can't poke another user's account."""
    aid = _seed_gmail_account(db, admin_user["id"])
    r = client.post(
        f"/accounts/{aid}/calendars/discover", cookies=user_cookies,
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# /calendars/discover — provider success path
# ---------------------------------------------------------------------------


def test_discover_renders_table_with_provider_calendars(
    client, db, admin_user, admin_cookies,
):
    """Mock the provider so list_calendars returns three calendars;
    the rendered HTML includes the names + the role-checkbox table
    structure."""
    aid = _seed_gmail_account(db, admin_user["id"])

    fake_calendars = [
        {"id": "primary", "summary": "claforest@gmail.com",
         "primary": True, "access_role": "owner"},
        {"id": "team@grp.calendar.google.com", "summary": "Team",
         "primary": False, "access_role": "writer"},
        {"id": "holidays@grp.v.calendar.google.com",
         "summary": "Holidays", "primary": False,
         "access_role": "reader"},
    ]

    fake_provider = AsyncMock()
    fake_provider.list_calendars = AsyncMock(return_value=fake_calendars)
    fake_provider.close = AsyncMock(return_value=None)

    with patch(
        "email_triage.web.routers.ui."
        "_create_calendar_provider_from_account",
        return_value=fake_provider,
    ):
        r = client.post(
            f"/accounts/{aid}/calendars/discover",
            cookies=admin_cookies,
        )
    assert r.status_code == 200
    body = r.text
    assert "claforest@gmail.com" in body
    assert "Team" in body
    assert "Holidays" in body
    # Role headers in the table.
    assert "Meetings" in body
    assert "Include in Event Listings" in body
    assert "Include in API Listings" in body
    assert "Self Schedule" in body
    # Read-only feed gets the read-only marker.
    assert "(read-only)" in body
    # Form posts to /save.
    assert f"/accounts/{aid}/calendars/save" in body


def test_discover_renders_error_on_provider_failure(
    client, db, admin_user, admin_cookies,
):
    aid = _seed_gmail_account(db, admin_user["id"])
    fake_provider = AsyncMock()
    fake_provider.list_calendars = AsyncMock(
        side_effect=RuntimeError("provider boom"),
    )
    fake_provider.close = AsyncMock(return_value=None)
    with patch(
        "email_triage.web.routers.ui."
        "_create_calendar_provider_from_account",
        return_value=fake_provider,
    ):
        r = client.post(
            f"/accounts/{aid}/calendars/discover",
            cookies=admin_cookies,
        )
    assert r.status_code == 200
    assert "Calendar discovery failed" in r.text


# ---------------------------------------------------------------------------
# /calendars/save — persistence + single-pick contract
# ---------------------------------------------------------------------------


def test_save_persists_selection_into_config(
    client, db, admin_user, admin_cookies,
):
    aid = _seed_gmail_account(db, admin_user["id"])
    payload = [
        ("discovered_ids", "primary,team@grp.calendar.google.com"),
        ("cal_enabled[primary]", "1"),
        ("cal_role_meetings[primary]", "1"),
        ("cal_role_listings[primary]", "1"),
        ("cal_role_api[primary]", "1"),
        ("cal_role_self_schedule", "primary"),
        ("cal_enabled[team@grp.calendar.google.com]", "1"),
        ("cal_role_listings[team@grp.calendar.google.com]", "1"),
    ]
    r = _form_post(
        client, f"/accounts/{aid}/calendars/save",
        payload, cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "Saved" in r.text

    # Round-trip: fetch the account + check config_json
    acct = get_email_account(db, aid)
    cals = (acct.get("config") or {}).get("calendars") or []
    by_id = {c["id"]: c for c in cals}
    assert by_id["primary"]["enabled"] is True
    assert by_id["primary"]["roles"]["meetings"] is True
    assert by_id["primary"]["roles"]["self_schedule"] is True
    assert by_id["team@grp.calendar.google.com"]["enabled"] is True
    assert by_id["team@grp.calendar.google.com"]["roles"]["listings"] is True
    # Single-pick: only one row carries self_schedule.
    self_picks = [
        c for c in cals if c["roles"].get("self_schedule")
    ]
    assert len(self_picks) == 1
    assert self_picks[0]["id"] == "primary"


def test_save_rejects_smuggled_calendar_ids(
    client, db, admin_user, admin_cookies,
):
    """Form fields keyed off IDs not in discovered_ids are dropped."""
    aid = _seed_gmail_account(db, admin_user["id"])
    payload = [
        ("discovered_ids", "primary"),
        ("cal_enabled[primary]", "1"),
        ("cal_enabled[smuggled@evil.com]", "1"),
        ("cal_role_api[smuggled@evil.com]", "1"),
    ]
    r = _form_post(
        client, f"/accounts/{aid}/calendars/save",
        payload, cookies=admin_cookies,
    )
    assert r.status_code == 200
    acct = get_email_account(db, aid)
    cals = (acct.get("config") or {}).get("calendars") or []
    assert [c["id"] for c in cals] == ["primary"]


def test_save_empty_discovered_ids_refuses(
    client, db, admin_user, admin_cookies,
):
    aid = _seed_gmail_account(db, admin_user["id"])
    r = client.post(
        f"/accounts/{aid}/calendars/save",
        data=[("discovered_ids", "")],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "refresh" in r.text.lower() or "no calendars" in r.text.lower()


def test_save_anonymous_unauthorized(client, db, admin_user):
    aid = _seed_gmail_account(db, admin_user["id"])
    r = client.post(
        f"/accounts/{aid}/calendars/save",
        data=[("discovered_ids", "primary")],
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# /calendar/surrogate — IMAP calendar-surrogate selection (#105 phase 1A++)
# ---------------------------------------------------------------------------


def _seed_imap_account(db, user_id: int, *, name="imap-acct") -> int:
    return create_email_account(
        db, user_id=user_id, name=name, provider_type="imap",
        config={"host": "imap.test", "username": "u@imap"},
    )


def test_surrogate_save_persists_id(
    client, db, admin_user, admin_cookies,
):
    """IMAP account picks a Gmail surrogate; config_json gets the
    surrogate id stored under the canonical key."""
    gmail_id = _seed_gmail_account(db, admin_user["id"])
    imap_id = _seed_imap_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{imap_id}/calendar/surrogate",
        [("surrogate_account_id", str(gmail_id))],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "Surrogate set" in r.text
    acct = get_email_account(db, imap_id)
    assert (
        acct["config"].get("calendar_surrogate_account_id")
        == gmail_id
    )


def test_surrogate_save_clear_with_empty_value(
    client, db, admin_user, admin_cookies,
):
    """Empty form value clears the surrogate."""
    gmail_id = _seed_gmail_account(db, admin_user["id"])
    imap_id = _seed_imap_account(db, admin_user["id"])
    # Set first.
    _form_post(
        client, f"/accounts/{imap_id}/calendar/surrogate",
        [("surrogate_account_id", str(gmail_id))],
        cookies=admin_cookies,
    )
    # Then clear.
    r = _form_post(
        client, f"/accounts/{imap_id}/calendar/surrogate",
        [("surrogate_account_id", "")],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "cleared" in r.text.lower()
    acct = get_email_account(db, imap_id)
    assert "calendar_surrogate_account_id" not in (
        acct.get("config") or {}
    )


def test_surrogate_save_works_on_gmail_account(
    client, db, admin_user, admin_cookies,
):
    """Operator may want to route a Gmail mailbox's calendar ops
    through a different Gmail account (single Calendar identity
    across multiple mailboxes). Surrogate is available on every
    account type, not just IMAP."""
    gmail_id = _seed_gmail_account(db, admin_user["id"])
    other_gmail = _seed_gmail_account(
        db, admin_user["id"], name="other",
    )
    r = _form_post(
        client, f"/accounts/{gmail_id}/calendar/surrogate",
        [("surrogate_account_id", str(other_gmail))],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "Surrogate set" in r.text
    acct = get_email_account(db, gmail_id)
    assert (
        acct["config"].get("calendar_surrogate_account_id")
        == other_gmail
    )


def test_surrogate_save_rejects_self_surrogate(
    client, db, admin_user, admin_cookies,
):
    """An account pointing at itself reports the resolver's
    'not a valid surrogate' refusal."""
    gmail_id = _seed_gmail_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{gmail_id}/calendar/surrogate",
        [("surrogate_account_id", str(gmail_id))],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "valid calendar surrogate" in r.text.lower()
    acct = get_email_account(db, gmail_id)
    assert "calendar_surrogate_account_id" not in (
        acct.get("config") or {}
    )


def test_surrogate_save_rejects_invalid_target(
    client, db, admin_user, admin_cookies,
):
    """Pointing at a non-existent or wrong-provider account
    refuses + leaves config untouched."""
    imap_id = _seed_imap_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{imap_id}/calendar/surrogate",
        [("surrogate_account_id", "999999")],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "valid calendar surrogate" in r.text.lower()
    acct = get_email_account(db, imap_id)
    assert "calendar_surrogate_account_id" not in (
        acct.get("config") or {}
    )


def test_surrogate_save_anonymous_unauthorized(
    client, db, admin_user,
):
    imap_id = _seed_imap_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{imap_id}/calendar/surrogate",
        [("surrogate_account_id", "1")],
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# /calendar/surrogate — HIPAA self-only refusal
# ---------------------------------------------------------------------------


def _seed_hipaa_imap_account(db, user_id, *, name="hipaa-imap"):
    return create_email_account(
        db, user_id=user_id, name=name, provider_type="imap",
        config={"host": "imap.test", "username": "u@hipaa"},
        hipaa=True,
    )


def _seed_hipaa_gmail_account(db, user_id, *, name="hipaa-gmail"):
    return create_email_account(
        db, user_id=user_id, name=name, provider_type="gmail_api",
        config={"account": "u@hipaa.gmail"},
        hipaa=True,
    )


def test_surrogate_save_refuses_when_consumer_is_hipaa(
    client, db, admin_user, admin_cookies,
):
    """HIPAA-flagged account can't surrogate to anyone."""
    hipaa_imap = _seed_hipaa_imap_account(db, admin_user["id"])
    target = _seed_gmail_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{hipaa_imap}/calendar/surrogate",
        [("surrogate_account_id", str(target))],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "HIPAA" in r.text
    acct = get_email_account(db, hipaa_imap)
    assert "calendar_surrogate_account_id" not in (
        acct.get("config") or {}
    )


def test_surrogate_save_refuses_when_target_is_hipaa(
    client, db, admin_user, admin_cookies,
):
    """Non-HIPAA consumer can't pick a HIPAA target — resolver
    refuses; UI also filters but defense-in-depth check fires
    on direct POST."""
    consumer = _seed_imap_account(db, admin_user["id"])
    hipaa_target = _seed_hipaa_gmail_account(db, admin_user["id"])
    r = _form_post(
        client, f"/accounts/{consumer}/calendar/surrogate",
        [("surrogate_account_id", str(hipaa_target))],
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert "valid calendar surrogate" in r.text.lower()
    acct = get_email_account(db, consumer)
    assert "calendar_surrogate_account_id" not in (
        acct.get("config") or {}
    )


def test_main_account_save_preserves_calendars_state(
    client, db, admin_user, admin_cookies,
):
    """Regression: the main account-edit Save button used to
    clobber config.calendars + config.calendar_surrogate_account_id
    because _extract_provider_config rebuilt config from form
    fields without preserving keys owned by dedicated endpoints.
    Saving the form should leave the calendar selections intact."""
    gmail_id = _seed_gmail_account(db, admin_user["id"])
    target_id = _seed_gmail_account(db, admin_user["id"], name="t")

    # Stage calendar selection + surrogate via the dedicated routes.
    _form_post(
        client, f"/accounts/{gmail_id}/calendar/surrogate",
        [("surrogate_account_id", str(target_id))],
        cookies=admin_cookies,
    )
    _form_post(
        client, f"/accounts/{gmail_id}/calendars/save",
        [
            ("discovered_ids", "primary"),
            ("cal_enabled[primary]", "1"),
            ("cal_role_meetings[primary]", "1"),
            ("cal_role_listings[primary]", "1"),
            ("cal_role_self_schedule", "primary"),
        ],
        cookies=admin_cookies,
    )
    before = get_email_account(db, gmail_id)
    assert (before["config"] or {}).get("calendars")
    assert (before["config"] or {}).get(
        "calendar_surrogate_account_id"
    ) == target_id

    # Hit the main account-update endpoint (PUT) with only the
    # fields the provider form would carry. Should NOT touch
    # calendars or surrogate. PUT is the underlying handler that
    # _extract_provider_config runs through; POST /save delegates
    # to it.
    r = client.put(
        f"/accounts/{gmail_id}",
        data={
            "name": before.get("name") or "x",
            "provider_type": before["provider_type"],
            "is_active": "1",
            "account": "u@gmail.com",
        },
        cookies=admin_cookies,
    )
    assert r.status_code == 200

    after = get_email_account(db, gmail_id)
    cals_after = (after["config"] or {}).get("calendars") or []
    assert cals_after, (
        "main account-save clobbered config.calendars"
    )
    assert (after["config"] or {}).get(
        "calendar_surrogate_account_id"
    ) == target_id, (
        "main account-save clobbered "
        "calendar_surrogate_account_id"
    )
    # Roles persisted intact.
    primary = next(c for c in cals_after if c["id"] == "primary")
    assert primary["enabled"] is True
    assert primary["roles"]["meetings"] is True
    assert primary["roles"]["self_schedule"] is True


def test_calendars_save_strips_api_role_on_hipaa(
    client, db, admin_user, admin_cookies,
):
    """HIPAA account submits cal_role_api on the form anyway —
    server-side parser strips it before persisting. Other roles
    (meetings, listings, self_schedule) round-trip normally."""
    hipaa_gmail = _seed_hipaa_gmail_account(db, admin_user["id"])
    payload = [
        ("discovered_ids", "primary"),
        ("cal_enabled[primary]", "1"),
        ("cal_role_meetings[primary]", "1"),
        ("cal_role_listings[primary]", "1"),
        ("cal_role_api[primary]", "1"),
        ("cal_role_self_schedule", "primary"),
    ]
    r = _form_post(
        client, f"/accounts/{hipaa_gmail}/calendars/save",
        payload, cookies=admin_cookies,
    )
    assert r.status_code == 200
    acct = get_email_account(db, hipaa_gmail)
    cals = (acct.get("config") or {}).get("calendars") or []
    primary = cals[0]
    assert primary["enabled"] is True
    assert primary["roles"]["meetings"] is True
    assert primary["roles"]["listings"] is True
    assert primary["roles"]["self_schedule"] is True
    # Stripped by HIPAA gate.
    assert primary["roles"]["api"] is False
