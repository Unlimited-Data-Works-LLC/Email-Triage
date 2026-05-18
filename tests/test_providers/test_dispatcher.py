"""Tests for the ProviderDispatcher registry (#138 phase 2).

Covers the functional-dispatch sites that survived Bundle G:
- ``poll_once`` per ptype dispatches to the right underlying function
- ``start_push`` per ptype runs the right action / produces the right
  status string
- ``infer_push_enabled`` per ptype reads the right state row
- ``test_connection`` per ptype fires the right probe
- ``post_create_start_watch`` per ptype runs the right post-create action
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.providers.dispatcher import (
    DISPATCHERS,
    ProviderDispatch,
    get_dispatch,
)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------

def test_dispatchers_keys_match_canonical_ptypes():
    assert set(DISPATCHERS.keys()) == {"imap", "gmail_api", "office365"}


def test_get_dispatch_unknown_returns_none():
    assert get_dispatch("carrier_pigeon") is None


def test_get_dispatch_known_returns_dispatch():
    d = get_dispatch("imap")
    assert isinstance(d, ProviderDispatch)
    assert d.ptype == "imap"


def test_dispatch_is_frozen():
    """ProviderDispatch is a frozen dataclass — surprises caught early."""
    d = get_dispatch("imap")
    with pytest.raises(Exception):
        d.ptype = "other"  # frozen dataclass disallows mutation


# ---------------------------------------------------------------------------
# poll_once dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poll_once_imap_routes_to_poll_once_imap(monkeypatch):
    """The IMAP dispatcher's poll_once delegates to web.app._poll_once_imap."""
    called = {}

    async def fake_poll_once_imap(app, acct):
        called["app"] = app
        called["acct"] = acct

    monkeypatch.setattr(
        "email_triage.web.app._poll_once_imap", fake_poll_once_imap,
    )
    sentinel_app = object()
    sentinel_acct = {"id": 7, "provider_type": "imap"}
    await get_dispatch("imap").poll_once(sentinel_app, sentinel_acct)
    assert called == {"app": sentinel_app, "acct": sentinel_acct}


@pytest.mark.asyncio
async def test_poll_once_gmail_routes_to_poll_once_gmail(monkeypatch):
    """The Gmail dispatcher's poll_once delegates to web.app._poll_once_gmail."""
    called = {}

    async def fake_poll_once_gmail(app, acct):
        called["app"] = app
        called["acct"] = acct

    monkeypatch.setattr(
        "email_triage.web.app._poll_once_gmail", fake_poll_once_gmail,
    )
    sentinel_app = object()
    sentinel_acct = {"id": 9, "provider_type": "gmail_api"}
    await get_dispatch("gmail_api").poll_once(sentinel_app, sentinel_acct)
    assert called == {"app": sentinel_app, "acct": sentinel_acct}


@pytest.mark.asyncio
async def test_poll_once_o365_no_op():
    """O365 poll is not yet wired — returns silently without raising."""
    result = await get_dispatch("office365").poll_once(object(), {"id": 1})
    assert result is None


# ---------------------------------------------------------------------------
# start_push dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_push_imap_delegates_to_manager_method():
    """IMAP start_push delegates to manager._start_imap_push."""
    manager = MagicMock()
    manager._start_imap_push = AsyncMock(return_value="Push: watching started")
    acct = {"id": 3, "provider_type": "imap"}
    msg = await get_dispatch("imap").start_push(manager, 3, acct)
    assert msg == "Push: watching started"
    manager._start_imap_push.assert_awaited_once_with(3, acct)


@pytest.mark.asyncio
async def test_start_push_gmail_records_intent_in_settings(monkeypatch):
    """Gmail start_push writes to settings.watch:<id> and returns the
    user-facing 'manage on edit form' message."""
    set_setting_calls = []

    def fake_set_setting(db, key, value):
        set_setting_calls.append((key, value))

    monkeypatch.setattr("email_triage.web.db.set_setting", fake_set_setting)

    manager = MagicMock()
    manager.app.state.db = object()
    msg = await get_dispatch("gmail_api").start_push(
        manager, 5, {"id": 5, "provider_type": "gmail_api"},
    )
    assert "Gmail Pub/Sub" in msg
    assert len(set_setting_calls) == 1
    assert set_setting_calls[0][1] == {"enabled": True}


@pytest.mark.asyncio
async def test_start_push_o365_returns_not_yet_implemented_string():
    msg = await get_dispatch("office365").start_push(
        MagicMock(), 1, {"id": 1, "provider_type": "office365"},
    )
    assert "not yet implemented" in msg.lower()


# ---------------------------------------------------------------------------
# infer_push_enabled dispatch
# ---------------------------------------------------------------------------

class _FakeRow:
    """Minimal stand-in for the sqlite3.Row that callers receive."""

    def __init__(self, **kwargs):
        self._data = dict(kwargs)

    def __getitem__(self, key):
        return self._data[key]


def test_infer_push_enabled_imap_no_setting_uses_default():
    """No watch:<id> row → default value bubbles out."""
    fetchone_result = None

    cursor = MagicMock()
    cursor.fetchone.return_value = fetchone_result
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("imap").infer_push_enabled(conn, 1, default=True) is True
    assert get_dispatch("imap").infer_push_enabled(conn, 1, default=False) is False


def test_infer_push_enabled_imap_reads_enabled_flag():
    """A watch:<id> row with {'enabled': True} → True."""
    cursor = MagicMock()
    cursor.fetchone.return_value = ('{"enabled": true}',)
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("imap").infer_push_enabled(conn, 1) is True


def test_infer_push_enabled_imap_reads_disabled_flag():
    cursor = MagicMock()
    cursor.fetchone.return_value = ('{"enabled": false}',)
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("imap").infer_push_enabled(conn, 1) is False


def test_infer_push_enabled_gmail_no_row_uses_default():
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("gmail_api").infer_push_enabled(conn, 1, default=True) is True


def test_infer_push_enabled_gmail_with_topic_is_true():
    cursor = MagicMock()
    cursor.fetchone.return_value = ("projects/x/topics/inbox", "2099-01-01")
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("gmail_api").infer_push_enabled(conn, 1) is True


def test_infer_push_enabled_gmail_empty_topic_is_false():
    cursor = MagicMock()
    cursor.fetchone.return_value = ("", "2099-01-01")
    conn = MagicMock()
    conn.execute.return_value = cursor

    assert get_dispatch("gmail_api").infer_push_enabled(conn, 1) is False


def test_infer_push_enabled_o365_uses_default():
    """O365 has no inference path yet — mirror the legacy fallback."""
    assert (
        get_dispatch("office365").infer_push_enabled(None, 1, default=True)
        is True
    )
    assert (
        get_dispatch("office365").infer_push_enabled(None, 1, default=False)
        is False
    )


# ---------------------------------------------------------------------------
# test_connection dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_test_connection_imap_missing_host_returns_error():
    acct = {
        "id": 1, "provider_type": "imap",
        "config": {"host": "", "username": ""},
    }
    secrets = MagicMock()
    secrets.get.return_value = ""
    ok, msg = await get_dispatch("imap").test_connection(acct, secrets)
    assert ok is False
    assert "Host and username required" in msg


@pytest.mark.asyncio
async def test_test_connection_o365_returns_deferral_message():
    """O365 has no inline probe — returns the 'save first' deferral."""
    ok, msg = await get_dispatch("office365").test_connection({}, MagicMock())
    assert ok is False
    assert "Save first" in msg or "device-code" in msg.lower()


@pytest.mark.asyncio
async def test_test_connection_gmail_no_token_returns_not_authenticated():
    acct = {"id": 1, "provider_type": "gmail_api", "config": {}}
    secrets = MagicMock()
    secrets.get.return_value = ""
    ok, msg = await get_dispatch("gmail_api").test_connection(acct, secrets)
    assert ok is False
    assert "Not authenticated" in msg


# ---------------------------------------------------------------------------
# post_create_start_watch dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_create_start_watch_gmail_returns_poll_mode_message():
    ok_msg, err_msg = await get_dispatch(
        "gmail_api",
    ).post_create_start_watch(MagicMock(), MagicMock(), {}, MagicMock())
    assert "poll mode" in ok_msg.lower()
    assert err_msg == ""


@pytest.mark.asyncio
async def test_post_create_start_watch_o365_returns_empty_pair():
    """O365 — no automatic start; device-code auth needed first."""
    ok_msg, err_msg = await get_dispatch(
        "office365",
    ).post_create_start_watch(MagicMock(), MagicMock(), {}, MagicMock())
    assert (ok_msg, err_msg) == ("", "")
