"""Tests for the bulk mail + calendar endpoints (Phase 5)."""

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
def fake_email_provider():
    p = MagicMock()
    p.search = AsyncMock(return_value=["m1", "m2", "m3"])
    p.apply_label = AsyncMock(return_value=None)
    p.move_message = AsyncMock(return_value=None)
    p.archive = AsyncMock(return_value=None)
    p.close = AsyncMock(return_value=None)
    return p


@pytest.fixture
def patch_email_factory(fake_email_provider):
    with patch(
        "email_triage.web.routers.ui._create_provider_from_account",
        return_value=fake_email_provider,
    ):
        yield fake_email_provider


@pytest.fixture
def fake_calendar():
    cal = MagicMock()
    cal.list_events = AsyncMock(return_value=[])
    cal.list_ooo = AsyncMock(return_value=[])
    cal.respond_to_invite = AsyncMock(return_value=None)
    cal.close = AsyncMock(return_value=None)
    return cal


@pytest.fixture
def patch_calendar_factory(fake_calendar):
    with patch(
        "email_triage.web.routers.ui._create_calendar_provider_from_account",
        return_value=fake_calendar,
    ):
        yield fake_calendar


# ---------------------------------------------------------------------------
# Mail search
# ---------------------------------------------------------------------------

class TestMailSearch:
    def test_search_with_filter_kwargs(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/mail/search"
            "?unread=true&label=Priority&after=2026-04-01T00:00:00Z&limit=5",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["message_ids"] == ["m1", "m2", "m3"]
        assert body["used_filter"]["unread"] is True
        assert body["used_filter"]["label"] == "Priority"
        # Provider was called with a MailFilter via filter= kwarg.
        call = patch_email_factory.search.call_args
        from email_triage.engine.models import MailFilter
        assert isinstance(call.kwargs["filter"], MailFilter)
        assert call.kwargs["filter"].unread is True
        assert call.kwargs["filter"].label == "Priority"

    def test_hipaa_account_403(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/mail/search?unread=true",
            headers=bearer,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Mail bulk
# ---------------------------------------------------------------------------

class TestMailBulk:
    def test_bulk_label_explicit_ids(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={
                "operation": "label",
                "args": {"label": "Reviewed"},
                "message_ids": ["m1", "m2", "m3"],
            },
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["requested"] == 3
        assert body["succeeded"] == 3
        assert body["failed"] == 0
        # Provider called once per id with the label.
        assert patch_email_factory.apply_label.await_count == 3
        for call in patch_email_factory.apply_label.await_args_list:
            assert call.args[1] == "Reviewed"

    def test_bulk_label_via_filter(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={
                "operation": "label",
                "args": {"label": "Reviewed"},
                "filter": {"unread": True},
                "limit": 50,
            },
            headers=bearer,
        )
        assert resp.status_code == 200
        # search() resolved the filter to ids before applying.
        patch_email_factory.search.assert_awaited()
        assert patch_email_factory.apply_label.await_count == 3

    def test_bulk_partial_failure_per_item(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        # Second call raises.
        patch_email_factory.apply_label = AsyncMock(
            side_effect=[None, RuntimeError("boom"), None],
        )
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "label", "args": {"label": "X"},
                  "message_ids": ["a", "b", "c"]},
            headers=bearer,
        )
        body = resp.json()
        assert body["succeeded"] == 2
        assert body["failed"] == 1
        statuses = [it["status"] for it in body["items"]]
        assert statuses == ["ok", "error", "ok"]

    def test_bulk_missing_args_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "label", "message_ids": ["m1"]},
            headers=bearer,
        )
        assert resp.status_code == 400
        assert "missing_args" in resp.json()["detail"]

    def test_bulk_unknown_op_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "delete_forever", "message_ids": ["m1"]},
            headers=bearer,
        )
        assert resp.status_code == 400

    def test_bulk_mutual_exclusion_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={
                "operation": "archive",
                "message_ids": ["m1"],
                "filter": {"unread": True},
            },
            headers=bearer,
        )
        assert resp.status_code == 400

    def test_bulk_neither_message_ids_nor_filter_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "archive"},
            headers=bearer,
        )
        assert resp.status_code == 400

    def test_bulk_over_cap_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        client.app.state.config.push.bulk_max_batch_size = 2
        try:
            resp = client.post(
                f"/api/openclaw/accounts/{aid}/mail/bulk",
                json={"operation": "archive",
                      "message_ids": ["a", "b", "c"]},
                headers=bearer,
            )
            assert resp.status_code == 400
            assert "batch_too_large" in resp.json()["detail"]
        finally:
            client.app.state.config.push.bulk_max_batch_size = 100

    def test_bulk_hipaa_403(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "archive", "message_ids": ["m1"]},
            headers=bearer,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Bulk namespace migration (item #31) — legacy vs canonical mail/calendar
# bulk-write paths. Both resolve to the same handler; legacy stamps
# Deprecation + Sunset + Link headers, canonical does not.
# ---------------------------------------------------------------------------


class TestBulkNamespaceMigration:
    # ----- Mail bulk-write -----

    def test_legacy_mail_bulk_still_works(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "label", "args": {"label": "Reviewed"},
                  "message_ids": ["m1", "m2"]},
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["requested"] == 2
        assert body["succeeded"] == 2
        assert body["failed"] == 0

    def test_canonical_bulk_mail_write_works(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/mail/write",
            json={"operation": "label", "args": {"label": "Reviewed"},
                  "message_ids": ["m1", "m2"]},
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["requested"] == 2
        assert body["succeeded"] == 2
        assert body["failed"] == 0

    def test_legacy_mail_bulk_sets_deprecated_header(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/mail/bulk",
            json={"operation": "archive", "message_ids": ["m1"]},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"
        assert resp.headers.get("Sunset") == "2027-01-01"
        link = resp.headers.get("Link", "")
        assert f"/api/openclaw/accounts/{aid}/bulk/mail/write" in link
        assert 'rel="successor-version"' in link

    def test_canonical_bulk_mail_write_no_deprecated_header(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/mail/write",
            json={"operation": "archive", "message_ids": ["m1"]},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert "Deprecation" not in resp.headers
        assert "Sunset" not in resp.headers
        assert "Link" not in resp.headers

    # ----- Calendar bulk-respond -----

    def test_legacy_calendar_bulk_respond_still_works(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/bulk-respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
            ]},
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] == 1
        assert body["failed"] == 0

    def test_canonical_bulk_calendar_respond_works(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
            ]},
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] == 1
        assert body["failed"] == 0

    def test_legacy_calendar_bulk_respond_sets_deprecated_header(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/bulk-respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
            ]},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"
        assert resp.headers.get("Sunset") == "2027-01-01"
        link = resp.headers.get("Link", "")
        assert f"/api/openclaw/accounts/{aid}/bulk/calendar/respond" in link
        assert 'rel="successor-version"' in link

    def test_canonical_bulk_calendar_respond_no_deprecated_header(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
            ]},
            headers=bearer,
        )
        assert resp.status_code == 200
        assert "Deprecation" not in resp.headers
        assert "Sunset" not in resp.headers
        assert "Link" not in resp.headers


# ---------------------------------------------------------------------------
# Calendar free-slots
# ---------------------------------------------------------------------------

class TestFreeSlots:
    def test_free_slots_returns_n_with_working_hours(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        # Save default prefs (working hours Mon-Fri 09-17).
        from email_triage.web.db import set_meeting_prefs
        from email_triage.engine.models import MeetingPreferences
        set_meeting_prefs(
            db, admin_user["id"], MeetingPreferences().to_dict(),
        )
        # Pick a Monday horizon.
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/free-slots"
            "?length=30&count=5"
            "&time_min=2026-04-20T00:00:00Z&time_max=2026-04-21T00:00:00Z",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["slots"]) == 5
        assert body["length_minutes"] == 30
        # First slot is at 09:00 UTC since the user's tz is UTC.
        assert body["slots"][0][0].startswith("2026-04-20T09:00")

    def test_free_slots_calendar_not_enabled_400(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=False)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/free-slots?length=30&count=5",
            headers=bearer,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "calendar_not_enabled"

    def test_free_slots_hipaa_403(
        self, client, db, admin_user, bearer,
    ):
        aid = _make_account(db, admin_user["id"], hipaa=True, calendar_enabled=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/calendar/free-slots?length=30&count=5",
            headers=bearer,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Calendar bulk-respond
# ---------------------------------------------------------------------------

class TestBulkRespond:
    def test_bulk_respond_ok(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/bulk-respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
                {"event_id": "ev2", "response": "declined"},
            ]},
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] == 2
        assert body["failed"] == 0
        assert patch_calendar_factory.respond_to_invite.await_count == 2

    def test_bulk_respond_invalid_value_per_item(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/bulk-respond",
            json={"responses": [
                {"event_id": "ev1", "response": "accepted"},
                {"event_id": "ev2", "response": "maybe-later"},
            ]},
            headers=bearer,
        )
        body = resp.json()
        assert body["succeeded"] == 1
        assert body["failed"] == 1

    def test_bulk_respond_hipaa_403(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True, calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/calendar/bulk-respond",
            json={"responses": [{"event_id": "ev1", "response": "accepted"}]},
            headers=bearer,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Bulk reads — GET /bulk/mail, POST /bulk/mail/fetch,
# GET /bulk/mail/full, POST /bulk/calendar/fetch
# ---------------------------------------------------------------------------


def _fake_message(mid, subject="Hello", body="This is the body. More text here.",
                  labels=None, has_attachment=False):
    """Fake EmailMessage-ish with the fields the summary/full shapers read."""
    class _Msg:
        pass
    m = _Msg()
    m.message_id = mid
    m.thread_id = f"thr-{mid}"
    m.sender = "Alice <alice@example.com>"
    m.recipients = ["bob@example.com"]
    m.subject = subject
    m.body_text = body
    m.date = datetime(2026, 4, 19, 14, 0, tzinfo=timezone.utc)
    m.labels = labels or ["INBOX", "UNREAD"]
    m.headers = {"from": "alice@example.com"}
    m.attachments = [object()] if has_attachment else []
    return m


class TestBulkMailList:
    """GET /bulk/mail — filter in, summaries out."""

    def test_returns_summaries_for_each_search_hit(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1", "m2", "m3"]
        patch_email_factory.fetch_message = AsyncMock(side_effect=[
            _fake_message("m1", subject="First"),
            _fake_message("m2", subject="Second", has_attachment=True),
            _fake_message("m3", subject="Third", labels=["INBOX"]),
        ])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?unread=true&limit=3",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert [m["message_id"] for m in body["messages"]] == ["m1", "m2", "m3"]
        assert body["messages"][1]["has_attachment"] is True
        assert body["messages"][0]["unread"] is True
        assert body["messages"][2]["unread"] is False
        assert body["messages"][0]["snippet"]
        assert "body_text" not in body["messages"][0]
        assert body["errors"] == []
        assert body["used_filter"] == {"unread": True}

    def test_per_id_error_collects_not_aborts(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1", "m2"]
        patch_email_factory.fetch_message = AsyncMock(side_effect=[
            _fake_message("m1"),
            RuntimeError("provider blew up on m2"),
        ])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=2",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["messages"]) == 1
        assert body["messages"][0]["message_id"] == "m1"
        assert len(body["errors"]) == 1
        assert body["errors"][0]["message_id"] == "m2"
        assert "blew up" in body["errors"][0]["error"]

    def test_respects_bulk_cap(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        client.app.state.config.push.bulk_max_batch_size = 5
        try:
            patch_email_factory.search.return_value = [f"m{i}" for i in range(5)]
            patch_email_factory.fetch_message = AsyncMock(
                side_effect=[_fake_message(f"m{i}") for i in range(5)],
            )
            resp = client.get(
                f"/api/openclaw/accounts/{aid}/bulk/mail?limit=100",
                headers=bearer,
            )
            assert resp.status_code == 200
            assert resp.json()["limit"] == 5
        finally:
            client.app.state.config.push.bulk_max_batch_size = 100

    def test_hipaa_403(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True)
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail", headers=bearer,
        )
        assert resp.status_code == 403


class TestBulkMailFetch:
    """POST /bulk/mail/fetch — explicit ids in, summaries out."""

    def test_fetch_by_ids(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.fetch_message = AsyncMock(side_effect=[
            _fake_message("x1"), _fake_message("x2"),
        ])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/mail/fetch",
            json={"message_ids": ["x1", "x2"]}, headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["requested"] == 2
        assert len(body["messages"]) == 2
        assert body["errors"] == []

    def test_missing_message_ids_is_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/mail/fetch",
            json={}, headers=bearer,
        )
        assert resp.status_code == 400

    def test_exceeding_cap_is_400(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        client.app.state.config.push.bulk_max_batch_size = 3
        try:
            resp = client.post(
                f"/api/openclaw/accounts/{aid}/bulk/mail/fetch",
                json={"message_ids": ["a", "b", "c", "d"]},
                headers=bearer,
            )
            assert resp.status_code == 400
            assert "exceeds cap" in resp.json()["detail"]
        finally:
            client.app.state.config.push.bulk_max_batch_size = 100


class TestBulkMailListFull:
    """GET /bulk/mail/full — filter in, full body_text out."""

    def test_returns_body_text(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body="Full newsletter body."),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full?label=Newsletters&limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["messages"][0]["body_text"] == "Full newsletter body."
        assert "snippet" not in body["messages"][0]

    def test_limit_capped_at_50_by_route(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full?limit=100",
            headers=bearer,
        )
        # Pydantic/FastAPI Query(le=50) rejects limit>50.
        assert resp.status_code == 422


class TestBulkCalendarFetch:
    """POST /bulk/calendar/fetch — event_ids in, events out."""

    def test_fetch_events_by_ids(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        patch_calendar_factory.get_event = AsyncMock(side_effect=[
            {"event_id": "ev1", "summary": "Planning"},
            {"event_id": "ev2", "summary": "Standup"},
        ])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/fetch",
            json={"event_ids": ["ev1", "ev2"]}, headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["requested"] == 2
        assert [e["event_id"] for e in body["events"]] == ["ev1", "ev2"]
        assert body["errors"] == []

    def test_per_id_error_collects(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        patch_calendar_factory.get_event = AsyncMock(side_effect=[
            {"event_id": "ev1", "summary": "OK"},
            RuntimeError("not found"),
        ])
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/fetch",
            json={"event_ids": ["ev1", "ev2"]}, headers=bearer,
        )
        body = resp.json()
        assert len(body["events"]) == 1
        assert len(body["errors"]) == 1
        assert body["errors"][0]["event_id"] == "ev2"

    def test_missing_event_ids_is_400(
        self, client, db, admin_user, bearer, patch_calendar_factory,
    ):
        aid = _make_account(db, admin_user["id"], calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/fetch",
            json={}, headers=bearer,
        )
        assert resp.status_code == 400

    def test_hipaa_403(self, client, db, admin_user, bearer):
        aid = _make_account(db, admin_user["id"], hipaa=True, calendar_enabled=True)
        resp = client.post(
            f"/api/openclaw/accounts/{aid}/bulk/calendar/fetch",
            json={"event_ids": ["ev1"]}, headers=bearer,
        )
        assert resp.status_code == 403


class TestHTMLStripping:
    """Bulk endpoints clean HTML from snippet + body_text. Single-message
    GET /messages/{id} stays raw (it's the explicit "give me everything"
    path)."""

    _HTML_BODY = (
        "<!DOCTYPE html><html><head><style>p{color:red}</style>"
        "<title>nope</title></head><body>"
        "<p>Hello there.</p><p>Second &amp; final paragraph.</p>"
        "<script>alert(1)</script></body></html>"
    )

    def test_snippet_strips_html_in_mail_list(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=self._HTML_BODY),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        # No tags, no script, no style content, entities decoded.
        assert "<p>" not in snip and "</p>" not in snip
        assert "<script>" not in snip
        assert "alert(1)" not in snip       # script body dropped
        assert "color:red" not in snip      # style body dropped
        assert "Hello there." in snip
        assert "Second & final paragraph." in snip  # &amp; → &

    def test_full_body_strips_html_in_mail_list_full(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=self._HTML_BODY),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        body = resp.json()["messages"][0]["body_text"]
        assert "<p>" not in body
        assert "Hello there." in body
        assert "Second & final paragraph." in body

    def test_unclosed_script_does_not_zero_remaining_text(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        """Real-world HTML emails (notably eBay newsletters) sometimes
        contain unbalanced <script> blocks. An earlier counter-based
        drop-element implementation got stuck "inside" the unclosed
        block and produced an empty snippet. The regex preprocessor
        guarantees script/style blocks (or any unclosed remnant) are
        stripped from the input before structural parsing."""
        broken = (
            "<!DOCTYPE html><html><body>"
            "<p>Visible paragraph one.</p>"
            "<!--[if mso]><script>broken-mso<![endif]-->"
            "<p>Visible paragraph two.</p>"
            "<script>document.write('half"  # unclosed
        )
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=broken),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        assert "Visible paragraph one." in snip
        assert "Visible paragraph two." in snip
        assert "document.write" not in snip
        assert "broken-mso" not in snip

    def test_plain_text_body_passes_through_unchanged(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        """Heuristic shouldn't fire on bodies that aren't HTML."""
        plain = "Just a plain note. No tags here. Three lines.\nLine 2.\nLine 3."
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=plain),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full?limit=1",
            headers=bearer,
        )
        assert resp.json()["messages"][0]["body_text"] == plain


class TestSnippetZeroWidthStrip:
    """Snippet pass drops Unicode Cf (Format) + Mn (Non-spacing mark)
    characters that marketing HTML (e.g. eBay) uses as invisible spacers
    — they otherwise eat the ~200-char snippet budget without showing
    anything. Full body is NOT filtered; those chars can still be real
    content if an agent actually reads the body."""

    def test_snippet_strips_zero_width_joiner(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        # ZWNJ (\u200c) is category Cf. Dozens wedged between visible
        # words is the pattern we're defending against.
        body = "Enjoy savings" + ("\u200c" * 300) + " on your next purchase"
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=body),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        assert "\u200c" not in snip
        # With the spacers gone the budget now fits both halves.
        assert "Enjoy savings" in snip
        assert "on your next purchase" in snip

    def test_snippet_strips_combining_grave_accent(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        # U+0300 (combining grave accent) is category Mn.
        body = "hello" + ("\u0300" * 250) + " world"
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=body),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        assert "\u0300" not in snip
        assert "hello" in snip
        assert "world" in snip

    def test_snippet_preserves_emoji(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        # Emoji are category So (Symbol, Other) — NOT filtered.
        body = "Sale today \U0001F389 don't miss out"
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=body),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        assert "\U0001F389" in snip

    def test_snippet_preserves_normal_letters(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        # Latin + CJK letters are Ll / Lo — preserved.
        body = "Hello world — 你好世界. Regular text."
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=body),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        snip = resp.json()["messages"][0]["snippet"]
        assert "Hello world" in snip
        assert "你好世界" in snip
        assert "Regular text." in snip

    def test_full_body_preserves_zero_width_chars(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        # full_message (used by /bulk/mail/full) must NOT filter —
        # full body is content, not preview.
        body = "before\u200cafter\u0300tail"
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = ["m1"]
        patch_email_factory.fetch_message = AsyncMock(
            return_value=_fake_message("m1", body=body),
        )
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full?limit=1",
            headers=bearer,
        )
        assert resp.status_code == 200
        full = resp.json()["messages"][0]["body_text"]
        assert "\u200c" in full
        assert "\u0300" in full


class TestBulkDefaults:
    """Default --limit is 5 server-side for both list endpoints."""

    def test_mail_list_default_limit_is_5(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = []
        patch_email_factory.fetch_message = AsyncMock()
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["limit"] == 5

    def test_mail_list_full_default_limit_is_5(
        self, client, db, admin_user, bearer, patch_email_factory,
    ):
        aid = _make_account(db, admin_user["id"])
        patch_email_factory.search.return_value = []
        patch_email_factory.fetch_message = AsyncMock()
        resp = client.get(
            f"/api/openclaw/accounts/{aid}/bulk/mail/full",
            headers=bearer,
        )
        assert resp.status_code == 200
        assert resp.json()["limit"] == 5
