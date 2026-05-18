"""Tests for ``email_triage.web.calendars``.

Covers the merge / parse / role-query helpers that back the
per-account calendar selection feature (#105 phase 1A). Lower-
level unit tests; HTTP-route tests for the discover/save
endpoints live in tests/test_web/test_calendars_route.py.
"""

from __future__ import annotations

from email_triage.web.calendars import (
    ROLES,
    calendars_with_role,
    get_self_schedule_calendar_id,
    normalize_calendars,
    parse_calendars_form,
)


def test_normalize_seeds_new_calendars_with_off_roles():
    discovered = [
        {"id": "primary", "summary": "Me", "primary": True,
         "access_role": "owner"},
        {"id": "team@grp", "summary": "Team", "access_role": "writer"},
    ]
    out = normalize_calendars(stored=None, discovered=discovered)
    assert len(out) == 2
    assert out[0]["id"] == "primary"
    assert out[0]["enabled"] is False
    assert all(v is False for v in out[0]["roles"].values())
    assert out[0]["access_role"] == "owner"


def test_normalize_preserves_operator_state_for_known_ids():
    stored = [
        {"id": "primary", "summary": "old name", "enabled": True,
         "roles": {"meetings": True, "listings": True,
                   "api": False, "self_schedule": True}},
    ]
    discovered = [
        {"id": "primary", "summary": "Me (renamed)",
         "primary": True, "access_role": "owner"},
        {"id": "new@grp", "summary": "New",
         "access_role": "reader"},
    ]
    out = normalize_calendars(stored=stored, discovered=discovered)
    primary = next(c for c in out if c["id"] == "primary")
    # Display fields refreshed from discovery.
    assert primary["summary"] == "Me (renamed)"
    assert primary["primary"] is True
    # Operator state preserved.
    assert primary["enabled"] is True
    assert primary["roles"]["meetings"] is True
    assert primary["roles"]["self_schedule"] is True
    # New calendar starts with everything off.
    new = next(c for c in out if c["id"] == "new@grp")
    assert new["enabled"] is False


def test_normalize_drops_calendars_no_longer_visible():
    stored = [
        {"id": "primary", "enabled": True, "roles": {"meetings": True}},
        {"id": "removed@grp", "enabled": True,
         "roles": {"listings": True}},
    ]
    discovered = [
        {"id": "primary", "summary": "Me", "primary": True,
         "access_role": "owner"},
    ]
    out = normalize_calendars(stored=stored, discovered=discovered)
    assert [c["id"] for c in out] == ["primary"]


def test_parse_form_constrains_to_discovered_ids():
    """Attacker who appends extra cal_enabled[smuggled@evil] form
    fields can't add calendars that weren't in discovery."""
    form_items = [
        ("cal_enabled[primary]", "1"),
        ("cal_role_meetings[primary]", "1"),
        ("cal_role_self_schedule", "primary"),
        # Smuggled — not in discovered_ids.
        ("cal_enabled[smuggled@evil]", "1"),
        ("cal_role_meetings[smuggled@evil]", "1"),
    ]
    out = parse_calendars_form(
        form_items, discovered_ids=["primary"], discovered_meta={
            "primary": {"summary": "Me", "primary": True,
                        "access_role": "owner"},
        },
    )
    assert [c["id"] for c in out] == ["primary"]
    assert out[0]["enabled"] is True
    assert out[0]["roles"]["meetings"] is True
    assert out[0]["roles"]["self_schedule"] is True
    assert out[0]["roles"]["listings"] is False
    assert out[0]["roles"]["api"] is False


def test_parse_form_self_schedule_single_pick():
    """Only the calendar matching cal_role_self_schedule's value
    gets the self_schedule role; even if other rows are enabled,
    the single-pick contract holds."""
    form_items = [
        ("cal_enabled[a]", "1"),
        ("cal_enabled[b]", "1"),
        ("cal_role_self_schedule", "b"),
    ]
    out = parse_calendars_form(
        form_items, discovered_ids=["a", "b"],
    )
    a = next(c for c in out if c["id"] == "a")
    b = next(c for c in out if c["id"] == "b")
    assert a["roles"]["self_schedule"] is False
    assert b["roles"]["self_schedule"] is True


def test_parse_form_disabled_row_clears_all_roles():
    """If the master ``enabled`` checkbox isn't ticked, no role
    flags persist — even if individual role-checkbox fields
    were submitted (browser quirk: hidden disabled boxes can
    still POST in some HTMX edge cases)."""
    form_items = [
        # No cal_enabled[a] — meaning master checkbox is off.
        ("cal_role_meetings[a]", "1"),
        ("cal_role_listings[a]", "1"),
    ]
    out = parse_calendars_form(form_items, discovered_ids=["a"])
    a = out[0]
    assert a["enabled"] is False
    assert all(v is False for v in a["roles"].values())


def test_calendars_with_role_skips_disabled_rows():
    acct = {
        "config": {
            "calendars": [
                {"id": "primary", "enabled": True,
                 "roles": {"api": True, "meetings": False}},
                {"id": "off", "enabled": False,
                 "roles": {"api": True}},
                {"id": "team", "enabled": True,
                 "roles": {"api": True, "meetings": True}},
            ],
        },
    }
    api_ids = calendars_with_role(acct, "api")
    assert api_ids == ["primary", "team"]
    meet_ids = calendars_with_role(acct, "meetings")
    assert meet_ids == ["team"]


def test_calendars_with_role_empty_legacy_account():
    """Account that's never visited the editor returns an empty
    list — caller falls back to the implicit primary calendar."""
    acct = {"config": {}}
    assert calendars_with_role(acct, "api") == []
    assert get_self_schedule_calendar_id(acct) is None


def test_get_self_schedule_calendar_id_single_pick():
    acct = {
        "config": {
            "calendars": [
                {"id": "a", "enabled": True,
                 "roles": {"self_schedule": False}},
                {"id": "b", "enabled": True,
                 "roles": {"self_schedule": True}},
            ],
        },
    }
    assert get_self_schedule_calendar_id(acct) == "b"


def test_roles_constant_lock():
    """Lock the role keys + order. Editor table column order
    relies on this; downstream readers (#107) assume the keys
    are stable."""
    assert ROLES == ("meetings", "listings", "api", "self_schedule")


# ---------------------------------------------------------------------------
# Surrogate helpers (#105 phase 1A++)
# ---------------------------------------------------------------------------


def test_surrogate_id_reads_from_any_account_type():
    """Operator can configure a Gmail mailbox to surrogate to a
    different Gmail account — useful when running multiple
    mailboxes through one Calendar identity. Field is read on
    every account type, not just IMAP."""
    from email_triage.web.calendars import get_surrogate_account_id
    for ptype in ("imap", "gmail_api", "office365"):
        acct = {
            "provider_type": ptype,
            "config": {"calendar_surrogate_account_id": 7},
        }
        assert get_surrogate_account_id(acct) == 7


def test_surrogate_id_handles_missing_or_invalid():
    from email_triage.web.calendars import get_surrogate_account_id
    assert get_surrogate_account_id({"config": {}}) is None
    assert get_surrogate_account_id({
        "config": {"calendar_surrogate_account_id": ""},
    }) is None
    assert get_surrogate_account_id({
        "config": {"calendar_surrogate_account_id": "not-a-number"},
    }) is None


def test_surrogate_resolver_rejects_self_surrogate(tmp_path):
    """An account pointing at itself returns None — defense
    against config corruption that'd otherwise loop."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("a@t.com", "A", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='a@t.com'",
    ).fetchone()[0]
    aid = create_email_account(
        db, user_id=uid, name="g", provider_type="gmail_api",
        config={"account": "a@gmail"},
    )
    acct = dict(get_email_account(db, aid))
    acct["config"] = {"calendar_surrogate_account_id": aid}
    assert resolve_surrogate_account(db, acct) is None


def test_resolve_surrogate_rejects_cross_owner(tmp_path):
    """Surrogate must belong to the same user — defense-in-depth
    against config corruption or admin-edit footguns."""
    from email_triage.web.db import (
        create_email_account, init_db, seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    # Two users, each with one Gmail account.
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("a@t.com", "A", "user", now),
    )
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("b@t.com", "B", "user", now),
    )
    db.commit()
    a_id = db.execute(
        "SELECT id FROM users WHERE email='a@t.com'",
    ).fetchone()[0]
    b_id = db.execute(
        "SELECT id FROM users WHERE email='b@t.com'",
    ).fetchone()[0]

    a_imap = create_email_account(
        db, user_id=a_id, name="A imap", provider_type="imap",
        config={"username": "a@imap"},
    )
    b_gmail = create_email_account(
        db, user_id=b_id, name="B gmail", provider_type="gmail_api",
        config={"account": "b@gmail"},
    )

    # A's IMAP points at B's Gmail — should reject.
    from email_triage.web.db import get_email_account
    acct = get_email_account(db, a_imap)
    acct = dict(acct)
    acct["config"] = {
        **(acct.get("config") or {}),
        "calendar_surrogate_account_id": b_gmail,
    }
    assert resolve_surrogate_account(db, acct) is None


def test_resolve_surrogate_rejects_wrong_provider_type(tmp_path):
    """Surrogate must be gmail_api / office365 — pointing at
    another IMAP account (which has no calendar) is invalid."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("a@t.com", "A", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='a@t.com'",
    ).fetchone()[0]

    a_imap = create_email_account(
        db, user_id=uid, name="primary imap",
        provider_type="imap", config={},
    )
    other_imap = create_email_account(
        db, user_id=uid, name="other imap",
        provider_type="imap", config={},
    )
    acct = dict(get_email_account(db, a_imap))
    acct["config"] = {
        "calendar_surrogate_account_id": other_imap,
    }
    assert resolve_surrogate_account(db, acct) is None


def test_resolve_surrogate_refuses_when_consumer_is_hipaa(tmp_path):
    """HIPAA-flagged consumer cannot surrogate to ANY account.
    HIPAA accounts are self-only — bridging their calendar to
    another account's read/write/audit context would leak PHI."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("d@t.com", "D", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='d@t.com'",
    ).fetchone()[0]

    hipaa_imap = create_email_account(
        db, user_id=uid, name="hipaa imap",
        provider_type="imap", config={}, hipaa=True,
    )
    nonhipaa_gmail = create_email_account(
        db, user_id=uid, name="g", provider_type="gmail_api",
        config={"account": "d@gmail"},
    )
    acct = dict(get_email_account(db, hipaa_imap))
    acct["config"] = {
        "calendar_surrogate_account_id": nonhipaa_gmail,
    }
    assert resolve_surrogate_account(db, acct) is None


def test_resolve_surrogate_refuses_when_target_is_hipaa(tmp_path):
    """Non-HIPAA consumer pointed at a HIPAA target also rejects
    — non-HIPAA reads on a HIPAA calendar leak PHI outward via
    listings / api roles."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("e@t.com", "E", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='e@t.com'",
    ).fetchone()[0]

    nonhipaa_imap = create_email_account(
        db, user_id=uid, name="i", provider_type="imap", config={},
    )
    hipaa_gmail = create_email_account(
        db, user_id=uid, name="hipaa-g", provider_type="gmail_api",
        config={"account": "e@gmail"}, hipaa=True,
    )
    acct = dict(get_email_account(db, nonhipaa_imap))
    acct["config"] = {
        "calendar_surrogate_account_id": hipaa_gmail,
    }
    assert resolve_surrogate_account(db, acct) is None


def test_resolve_surrogate_refuses_when_both_sides_hipaa(tmp_path):
    """HIPAA → HIPAA also refuses. Even within a HIPAA boundary
    surrogating bridges the source account's audit + recipient
    guards to a different account — the source account's
    self-only contract still applies."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("f@t.com", "F", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='f@t.com'",
    ).fetchone()[0]

    a_id = create_email_account(
        db, user_id=uid, name="A", provider_type="imap",
        config={}, hipaa=True,
    )
    b_id = create_email_account(
        db, user_id=uid, name="B", provider_type="gmail_api",
        config={"account": "f@gmail"}, hipaa=True,
    )
    acct = dict(get_email_account(db, a_id))
    acct["config"] = {"calendar_surrogate_account_id": b_id}
    assert resolve_surrogate_account(db, acct) is None


def test_parse_form_strips_api_role_on_hipaa():
    """HIPAA accounts can never carry the api role regardless of
    what the form claimed. Server-side strip is the authoritative
    gate; the UI disable is a UX hint."""
    from email_triage.web.calendars import (
        HIPAA_RESTRICTED_ROLES, parse_calendars_form,
    )
    form_items = [
        ("cal_enabled[primary]", "1"),
        ("cal_role_meetings[primary]", "1"),
        ("cal_role_listings[primary]", "1"),
        # Attacker / stale-form submits api anyway.
        ("cal_role_api[primary]", "1"),
    ]
    out = parse_calendars_form(
        form_items, discovered_ids=["primary"], hipaa=True,
    )
    primary = out[0]
    assert primary["enabled"] is True
    assert primary["roles"]["meetings"] is True
    assert primary["roles"]["listings"] is True
    # api role stripped per HIPAA_RESTRICTED_ROLES.
    assert primary["roles"]["api"] is False
    # Sanity-lock the constant: only api today.
    assert HIPAA_RESTRICTED_ROLES == frozenset({"api"})


def test_resolve_surrogate_returns_target_when_valid(tmp_path):
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories,
    )
    from email_triage.web.calendars import resolve_surrogate_account
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("c@t.com", "C", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='c@t.com'",
    ).fetchone()[0]

    imap_id = create_email_account(
        db, user_id=uid, name="i", provider_type="imap", config={},
    )
    gmail_id = create_email_account(
        db, user_id=uid, name="g", provider_type="gmail_api",
        config={"account": "c@gmail"},
    )
    acct = dict(get_email_account(db, imap_id))
    acct["config"] = {
        "calendar_surrogate_account_id": gmail_id,
    }
    surrogate = resolve_surrogate_account(db, acct)
    assert surrogate is not None
    assert surrogate["id"] == gmail_id
    assert surrogate["provider_type"] == "gmail_api"


# ---------------------------------------------------------------------------
# is_calendar_effectively_enabled — surrogate-aware gate
# ---------------------------------------------------------------------------


def _seed_user_and_two_accounts(tmp_path):
    """Helper: in-memory DB with a user + (imap, gmail_api) account
    pair where the imap account can point at the gmail one as a
    calendar surrogate. Returns helpers as closures so each test
    only needs ``set_cal(account_id, True)``."""
    from email_triage.web.db import (
        create_email_account, get_email_account, init_db,
        seed_categories, set_bool_setting,
    )
    from email_triage.web import settings_keys as _S
    from email_triage.config import TriageConfig
    db = init_db(":memory:")
    seed_categories(db, TriageConfig().classifier.categories)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?,?,?,?)",
        ("c@t.com", "C", "user", now),
    )
    db.commit()
    uid = db.execute(
        "SELECT id FROM users WHERE email='c@t.com'",
    ).fetchone()[0]
    imap_id = create_email_account(
        db, user_id=uid, name="i", provider_type="imap", config={},
    )
    gmail_id = create_email_account(
        db, user_id=uid, name="g", provider_type="gmail_api",
        config={"account": "c@gmail"},
    )

    def set_cal(aid: int, on: bool) -> None:
        set_bool_setting(db, _S.calendar_enabled(aid), on)

    return db, uid, imap_id, gmail_id, set_cal, get_email_account


def test_effectively_enabled_via_surrogate(tmp_path):
    """IMAP-with-surrogate: surrogate has the flag → effective True."""
    from email_triage.web.calendars import is_calendar_effectively_enabled
    db, uid, imap_id, gmail_id, set_cal, get_acct = (
        _seed_user_and_two_accounts(tmp_path)
    )
    set_cal(gmail_id, True)  # surrogate gets the flag
    acct = dict(get_acct(db, imap_id))
    acct["config"] = {"calendar_surrogate_account_id": gmail_id}
    assert is_calendar_effectively_enabled(db, acct) is True


def test_effectively_enabled_no_surrogate_uses_self(tmp_path):
    """No surrogate configured → fall back to the account's own flag."""
    from email_triage.web.calendars import is_calendar_effectively_enabled
    db, uid, imap_id, gmail_id, set_cal, get_acct = (
        _seed_user_and_two_accounts(tmp_path)
    )
    # Self gets the flag; no surrogate pointer set.
    set_cal(gmail_id, True)
    acct = dict(get_acct(db, gmail_id))
    assert is_calendar_effectively_enabled(db, acct) is True


def test_effectively_disabled_when_neither_set(tmp_path):
    """Surrogate configured but neither side has the flag → False."""
    from email_triage.web.calendars import is_calendar_effectively_enabled
    db, uid, imap_id, gmail_id, set_cal, get_acct = (
        _seed_user_and_two_accounts(tmp_path)
    )
    # No flag set on either side.
    acct = dict(get_acct(db, imap_id))
    acct["config"] = {"calendar_surrogate_account_id": gmail_id}
    assert is_calendar_effectively_enabled(db, acct) is False


def test_effectively_disabled_when_only_imap_side_set(tmp_path):
    """Surrogate exists; account's OWN flag is on but surrogate's
    is off. The surrogate's flag is the one that governs in
    surrogate mode, so the effective result is False."""
    from email_triage.web.calendars import is_calendar_effectively_enabled
    db, uid, imap_id, gmail_id, set_cal, get_acct = (
        _seed_user_and_two_accounts(tmp_path)
    )
    # IMAP side has the flag (operator left a stale flag); the
    # surrogate (Gmail) does not.
    set_cal(imap_id, True)
    acct = dict(get_acct(db, imap_id))
    acct["config"] = {"calendar_surrogate_account_id": gmail_id}
    # The function picks the surrogate's flag in surrogate mode.
    assert is_calendar_effectively_enabled(db, acct) is False
