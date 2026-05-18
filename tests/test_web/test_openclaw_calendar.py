"""Tests for /api/openclaw/accounts/{id}/calendar/* endpoints."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.engine.models import CalendarEvent


def _make_account(db, user_id, *, hipaa=False, calendar_enabled=False):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Acct", "gmail_api",
         json.dumps({"account": "me@gmail.com", "client_id": "cid"}),
         1 if hipaa else 0, now, now),
    )
    db.commit()
    aid = cur.lastrowid
    if calendar_enabled:
        from email_triage.web.db import set_setting
        set_setting(db, f"calendar_enabled:{aid}", {"enabled": True})
    return aid


@pytest.fixture
def bearer(db, admin_user):
    from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), name="t", user_id=admin_user["id"])
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def fake_calendar():
    cal = MagicMock()
    cal.list_events = AsyncMock(return_value=[
        CalendarEvent(
            event_id="ev1", summary="Sync",
            start=datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc),
            end=datetime(2026, 4, 20, 9, 30, tzinfo=timezone.utc),
        ),
    ])
    cal.get_event = AsyncMock(return_value=CalendarEvent(
        event_id="ev1", summary="Sync",
        start=datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc),
        end=datetime(2026, 4, 20, 9, 30, tzinfo=timezone.utc),
    ))
    cal.create_event = AsyncMock(return_value="new-ev")
    cal.update_event = AsyncMock(return_value=None)
    cal.delete_event = AsyncMock(return_value=None)
    cal.respond_to_invite = AsyncMock(return_value=None)
    cal.close = AsyncMock(return_value=None)
    return cal


@pytest.fixture
def patch_factory(fake_calendar):
    with patch(
        "email_triage.web.routers.ui._create_calendar_provider_from_account",
        return_value=fake_calendar,
    ):
        yield fake_calendar


class TestHipaaBlock:
    def test_list_403_on_hipaa(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True, calendar_enabled=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/events"
            "?time_min=2026-04-20T00:00:00Z&time_max=2026-04-21T00:00:00Z",
            headers=bearer,
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "hipaa_blocked"

    def test_create_403_on_hipaa(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True, calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/events",
            json={"summary": "x", "start": "2026-04-20T09:00:00Z",
                  "end": "2026-04-20T09:30:00Z"},
            headers=bearer,
        )
        assert resp.status_code == 403


class TestCalendarNotEnabled:
    def test_400_with_calendar_not_enabled(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=False)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/events"
            "?time_min=2026-04-20T00:00:00Z&time_max=2026-04-21T00:00:00Z",
            headers=bearer,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "calendar_not_enabled"


class TestEndpoints:
    def test_list_events(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/events"
            "?time_min=2026-04-20T00:00:00Z&time_max=2026-04-21T00:00:00Z",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["events"]) == 1
        assert body["events"][0]["event_id"] == "ev1"

    def test_get_event(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/events/ev1",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["event_id"] == "ev1"

    def test_create_event(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/events",
            json={"summary": "Sync",
                  "start": "2026-04-21T14:00:00Z",
                  "end": "2026-04-21T14:30:00Z"},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["event_id"] == "new-ev"

    def test_update_event(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.patch(
            f"/api/openclaw/accounts/{aid}/calendar/events/ev1",
            json={"summary": "Updated"},
            headers=bearer,
        )
        assert resp.status_code == 200

    def test_delete_event(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.delete(
            f"/api/openclaw/accounts/{aid}/calendar/events/ev1",
            headers=bearer,
        )
        assert resp.status_code == 200

    def test_respond(self, client, db, admin_user, bearer, patch_factory):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/events/ev1/respond",
            json={"response": "accepted"},
            headers=bearer,
        )
        assert resp.status_code == 200
        patch_factory.respond_to_invite.assert_awaited_once_with("ev1", "accepted")

    def test_respond_invalid_value_400(
        self, client, db, admin_user, bearer, patch_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/events/ev1/respond",
            json={"response": "maybe"},
            headers=bearer,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Punch-list #109 — pre-rendered local-tz strings
#
# These tests verify the calendar response carries the per-event
# local-render fields the LLM-agent consumer relies on for an
# arithmetic-free render path.
# ---------------------------------------------------------------------------


def _make_account_with_tz(db, user_id, tz="America/Detroit"):
    """Like _make_account but stamps a tz on config_json + always
    enables calendar. Saves repetition in the new tests below."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Acct", "gmail_api",
         json.dumps({
             "account": "me@gmail.com", "client_id": "cid", "tz": tz,
         }),
         0, now, now),
    )
    db.commit()
    aid = cur.lastrowid
    from email_triage.web.db import set_setting
    set_setting(db, f"calendar_enabled:{aid}", {"enabled": True})
    return aid


@pytest.fixture
def fake_calendar_summer():
    """Event during US-Eastern DST (EDT, UTC-4). May 8 2026 12:20 UTC
    = 8:20 AM EDT, a Friday — the canonical handover example."""
    cal = MagicMock()
    ev = CalendarEvent(
        event_id="ev1", summary="Sync",
        start=datetime(2026, 5, 8, 12, 20, tzinfo=timezone.utc),
        end=datetime(2026, 5, 8, 13, 20, tzinfo=timezone.utc),
    )
    cal.list_events = AsyncMock(return_value=[ev])
    cal.get_event = AsyncMock(return_value=ev)
    cal.close = AsyncMock(return_value=None)
    return cal


class TestLocalRenderFields:
    def test_list_emits_local_fields(
        self, client, db, admin_user, bearer, fake_calendar_summer,
    ):
        aid = _make_account_with_tz(db, admin_user["id"])
        with patch(
            "email_triage.web.routers.ui._create_calendar_provider_from_account",
            return_value=fake_calendar_summer,
        ):
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/calendar/events"
                "?time_min=2026-05-08T00:00:00Z"
                "&time_max=2026-05-09T00:00:00Z",
                headers=bearer,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["events"]) == 1
        ev = body["events"][0]
        # Existing UTC fields stay intact.
        assert ev["start"] == "2026-05-08T12:20:00+00:00"
        assert ev["end"] == "2026-05-08T13:20:00+00:00"
        # Verbatim summary.
        assert ev["summary"] == "Sync"
        # Local-render fields, every one of them.
        assert ev["start_local"] == "2026-05-08T08:20:00-04:00"
        assert ev["end_local"] == "2026-05-08T09:20:00-04:00"
        assert ev["start_local_date"] == "2026-05-08"
        assert ev["start_local_weekday"] == "Friday"
        assert ev["start_local_time"] == "8:20 AM"
        assert ev["end_local_time"] == "9:20 AM"
        assert ev["all_day_local_label"] is None
        assert ev["tz"] == "America/Detroit"
        assert ev["tz_abbrev"] == "EDT"

    def test_get_emits_local_fields(
        self, client, db, admin_user, bearer, fake_calendar_summer,
    ):
        aid = _make_account_with_tz(db, admin_user["id"])
        with patch(
            "email_triage.web.routers.ui._create_calendar_provider_from_account",
            return_value=fake_calendar_summer,
        ):
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/calendar/events/ev1",
                headers=bearer,
            )
        assert resp.status_code == 200
        ev = resp.json()
        assert ev["start_local_weekday"] == "Friday"
        assert ev["start_local_time"] == "8:20 AM"
        assert ev["tz"] == "America/Detroit"
        assert ev["tz_abbrev"] == "EDT"

    def test_all_day_event_label_and_null_times(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account_with_tz(db, admin_user["id"])
        ev = CalendarEvent(
            event_id="ev_all", summary="Holiday",
            start=datetime(2026, 7, 4, 4, 0, tzinfo=timezone.utc),
            end=datetime(2026, 7, 5, 4, 0, tzinfo=timezone.utc),
            all_day=True,
        )
        cal = MagicMock()
        cal.list_events = AsyncMock(return_value=[ev])
        cal.close = AsyncMock(return_value=None)
        with patch(
            "email_triage.web.routers.ui._create_calendar_provider_from_account",
            return_value=cal,
        ):
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/calendar/events"
                "?time_min=2026-07-04T00:00:00Z"
                "&time_max=2026-07-05T00:00:00Z",
                headers=bearer,
            )
        assert resp.status_code == 200
        out = resp.json()["events"][0]
        assert out["all_day"] is True
        assert out["all_day_local_label"] == "All day"
        assert out["start_local_time"] is None
        assert out["end_local_time"] is None
        # The date / weekday strings still render.
        assert out["start_local_date"] is not None
        assert out["start_local_weekday"] is not None

    def test_dst_winter_uses_est_abbrev(
        self, client, db, admin_user, bearer,
    ):
        """Standard time / EST: January in Detroit is UTC-5."""
        aid = _make_account_with_tz(db, admin_user["id"])
        ev = CalendarEvent(
            event_id="ev_winter", summary="Coffee",
            start=datetime(2026, 1, 15, 13, 0, tzinfo=timezone.utc),
            end=datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc),
        )
        cal = MagicMock()
        cal.list_events = AsyncMock(return_value=[ev])
        cal.close = AsyncMock(return_value=None)
        with patch(
            "email_triage.web.routers.ui._create_calendar_provider_from_account",
            return_value=cal,
        ):
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/calendar/events"
                "?time_min=2026-01-15T00:00:00Z"
                "&time_max=2026-01-16T00:00:00Z",
                headers=bearer,
            )
        out = resp.json()["events"][0]
        assert out["tz_abbrev"] == "EST"
        # 13:00 UTC is 8:00 AM EST.
        assert out["start_local_time"] == "8:00 AM"

    def test_noon_and_midnight_format(self):
        """Format helper: noon = 12:00 PM, midnight = 12:00 AM."""
        from email_triage.web.routers.openclaw import _format_local_time
        from datetime import datetime as _dt
        assert _format_local_time(_dt(2026, 5, 8, 12, 0)) == "12:00 PM"
        assert _format_local_time(_dt(2026, 5, 8, 0, 0)) == "12:00 AM"
        assert _format_local_time(_dt(2026, 5, 8, 1, 5)) == "1:05 AM"
        assert _format_local_time(_dt(2026, 5, 8, 23, 59)) == "11:59 PM"

    def test_unknown_tz_falls_back_to_default(
        self, client, db, admin_user, bearer, fake_calendar_summer,
    ):
        """A garbage tz string in config_json must not crash the
        endpoint — fall back to the install default and still emit
        every render field."""
        aid = _make_account_with_tz(db, admin_user["id"], tz="Not/A_Real_Zone")
        with patch(
            "email_triage.web.routers.ui._create_calendar_provider_from_account",
            return_value=fake_calendar_summer,
        ):
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/calendar/events"
                "?time_min=2026-05-08T00:00:00Z"
                "&time_max=2026-05-09T00:00:00Z",
                headers=bearer,
            )
        assert resp.status_code == 200
        ev = resp.json()["events"][0]
        # Falls back to America/Detroit (the documented install default).
        assert ev["tz"] == "America/Detroit"
        assert ev["tz_abbrev"] == "EDT"


def _migration_seed_user(conn) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("mig@test.com", "Mig", "admin", now),
    )
    conn.commit()
    return cur.lastrowid


class TestTzMigrationBackfill:
    def test_v6_backfills_default_tz(self):
        """Migration v6 stamps America/Detroit on rows with no tz."""
        from email_triage.web.db import init_db
        conn = init_db(":memory:")
        uid = _migration_seed_user(conn)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            "hipaa, created_at, updated_at) "
            "VALUES (?, 'legacy', 'imap', ?, 0, ?, ?)",
            (uid, json.dumps({"host": "imap.example.com"}), now, now),
        )
        # init_db ran v6 already; manually clear the tz to simulate an
        # upgraded install whose row predates v6, then re-run the body.
        conn.execute(
            "UPDATE email_accounts SET config_json = ?",
            (json.dumps({"host": "imap.example.com"}),),
        )
        conn.commit()
        from email_triage.web.migrations import _v6_backfill_account_tz_default
        _v6_backfill_account_tz_default(conn)
        row = conn.execute(
            "SELECT config_json FROM email_accounts"
        ).fetchone()
        cfg = json.loads(row["config_json"])
        assert cfg["tz"] == "America/Detroit"
        assert cfg["host"] == "imap.example.com"

    def test_v6_idempotent(self):
        """Re-running v6 against rows that already declare tz
        leaves them untouched."""
        from email_triage.web.db import init_db
        conn = init_db(":memory:")
        uid = _migration_seed_user(conn)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            "hipaa, created_at, updated_at) "
            "VALUES (?, 'a', 'imap', ?, 0, ?, ?)",
            (uid, json.dumps({"tz": "Europe/London"}), now, now),
        )
        conn.commit()
        from email_triage.web.migrations import _v6_backfill_account_tz_default
        _v6_backfill_account_tz_default(conn)
        row = conn.execute(
            "SELECT config_json FROM email_accounts"
        ).fetchone()
        cfg = json.loads(row["config_json"])
        assert cfg["tz"] == "Europe/London"


class TestTzFormPersistence:
    def test_save_round_trips_tz(self, client, db, admin_user, admin_cookies):
        """POST to /accounts/{id}/save with tz=Europe/London persists it."""
        aid = _make_account_with_tz(db, admin_user["id"], tz="America/Detroit")
        resp = client.post(
            f"/accounts/{aid}/save",
            data={
                "name": "Acct",
                "provider_type": "gmail_api",
                "is_active": "1",
                "tz": "Europe/London",
                "account": "me@gmail.com",
                "active_tab": "provider",
                "hipaa_submitted": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        # Save handler returns 303 (redirect to edit page) or 200.
        assert resp.status_code in (200, 303)
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert acct["config"]["tz"] == "Europe/London"

    def test_save_rejects_garbage_tz_keeps_existing(
        self, client, db, admin_user, admin_cookies,
    ):
        """Bogus tz string falls back to the previously-saved value
        (or the install default for fresh rows). Never UTC by default."""
        aid = _make_account_with_tz(db, admin_user["id"], tz="America/Detroit")
        client.post(
            f"/accounts/{aid}/save",
            data={
                "name": "Acct",
                "provider_type": "gmail_api",
                "is_active": "1",
                "tz": "Mars/Olympus_Mons",
                "account": "me@gmail.com",
                "active_tab": "provider",
                "hipaa_submitted": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert acct["config"]["tz"] == "America/Detroit"
