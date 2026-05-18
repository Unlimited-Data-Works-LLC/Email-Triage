"""Tests for PR 7 — C3 (provider transient errors) + C4 (state-bag
corruption guard)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.providers.base import ProviderTransientError


# ---------------------------------------------------------------------------
# C3 — IMAP poll surfaces transient errors
# ---------------------------------------------------------------------------

@pytest.fixture
def force_imap():
    """Mark aioimaplib as 'available' for the test even when not
    installed. The IMAP provider constructor then accepts; the
    actual aioimaplib calls are mocked per-test via _connect."""
    from email_triage.providers import imap as imap_mod
    saved = imap_mod.HAS_AIOIMAPLIB
    imap_mod.HAS_AIOIMAPLIB = True
    yield
    imap_mod.HAS_AIOIMAPLIB = saved


@pytest.mark.asyncio
async def test_imap_poll_raises_on_search_failure(force_imap):
    """SEARCH returning non-OK no longer silently returns []; raises
    ProviderTransientError so the caller can distinguish 'broken' from
    'no new mail'."""
    from email_triage.providers.imap import ImapProvider

    provider = ImapProvider(
        host="example", port=993, username="u", password="p",
        mailbox="INBOX",
    )

    fake_client = MagicMock()
    fake_client.select = AsyncMock(return_value=("OK", []))
    fake_client.search = AsyncMock(return_value=("BAD", [b"protocol error"]))

    with patch.object(provider, "_connect", AsyncMock(return_value=fake_client)):
        with pytest.raises(ProviderTransientError, match="SEARCH failed"):
            await provider.poll_once("INBOX", since_uid=42)


@pytest.mark.asyncio
async def test_imap_poll_raises_on_fetch_failure(force_imap):
    """FETCH UIDs returning non-OK raises ProviderTransientError."""
    from email_triage.providers.imap import ImapProvider

    provider = ImapProvider(
        host="example", port=993, username="u", password="p",
        mailbox="INBOX",
    )

    fake_client = MagicMock()
    fake_client.select = AsyncMock(return_value=("OK", []))
    fake_client.search = AsyncMock(return_value=("OK", [b"123 124"]))
    fake_client.fetch = AsyncMock(return_value=("NO", [b"server tantrum"]))

    with patch.object(provider, "_connect", AsyncMock(return_value=fake_client)):
        with pytest.raises(ProviderTransientError, match="FETCH UIDs failed"):
            await provider.poll_once("INBOX", since_uid=42)


@pytest.mark.asyncio
async def test_imap_poll_empty_result_returns_empty_list(force_imap):
    """A successful SEARCH that returns no UIDs is the 'no new mail'
    case — must NOT raise."""
    from email_triage.providers.imap import ImapProvider

    provider = ImapProvider(
        host="example", port=993, username="u", password="p",
        mailbox="INBOX",
    )

    fake_client = MagicMock()
    fake_client.select = AsyncMock(return_value=("OK", []))
    fake_client.search = AsyncMock(return_value=("OK", [b""]))

    with patch.object(provider, "_connect", AsyncMock(return_value=fake_client)):
        out = await provider.poll_once("INBOX", since_uid=42)
    assert out == []


# ---------------------------------------------------------------------------
# C4 — state_bag corruption guard
# ---------------------------------------------------------------------------

@pytest.fixture
def store_db():
    """A FlowStore-shaped SQLite DB with one fixture row."""
    from email_triage.engine.store import FlowStore

    store = FlowStore(":memory:")
    yield store


def _insert_fixture(
    store, flow_id: str, *, state_bag_json: str = "{}",
) -> None:
    """Direct INSERT — bypasses store.create() so we can plant a row
    with intentionally-malformed JSON."""
    now = datetime.now(timezone.utc).isoformat()
    store._conn.execute(
        "INSERT INTO flows (flow_id, message_id, provider, status, "
        "revision, classification_json, actions_completed_json, "
        "actions_pending_json, state_bag_json, error, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?)",
        (
            flow_id, "m1", "imap", "fetched", 1,
            None, "[]", "[]", state_bag_json, None,
            now, now,
        ),
    )
    store._conn.commit()


def test_get_flow_survives_corrupted_state_bag(store_db):
    """A corrupt state_bag_json column must NOT crash get_flow.
    Returns a flow with empty state_bag plus a __corruption__ marker."""
    _insert_fixture(
        store_db, "f-broken",
        state_bag_json="{this is not: valid JSON@@",
    )
    flow = store_db.get_flow("f-broken")
    assert flow is not None
    assert isinstance(flow.state_bag, dict)
    assert "__corruption__" in flow.state_bag
    msg = flow.state_bag["__corruption__"]
    assert "state_bag_corrupt" in msg
    assert "JSONDecodeError" in msg or "ValueError" in msg


def test_get_flow_marks_non_object_corrupt(store_db):
    """JSON valid but wrong shape (e.g. a literal null or array)
    counts as corruption — every state_bag is a dict by contract."""
    _insert_fixture(
        store_db, "f-array", state_bag_json="[1, 2, 3]",
    )
    flow = store_db.get_flow("f-array")
    assert flow.state_bag.get("__corruption__")
    assert "expected object" in flow.state_bag["__corruption__"]


def test_get_flow_normal_case_unchanged(store_db):
    """Sanity: well-formed state_bag round-trips with no marker."""
    _insert_fixture(
        store_db, "f-ok",
        state_bag_json=json.dumps({"hello": "world", "n": 1}),
    )
    flow = store_db.get_flow("f-ok")
    assert flow.state_bag == {"hello": "world", "n": 1}
    assert "__corruption__" not in flow.state_bag


def test_safe_json_load_dict_handles_empty_string():
    """Defensive: empty / None columns yield empty dict, no error."""
    from email_triage.engine.store import _safe_json_load_dict

    out, err = _safe_json_load_dict("", label="state_bag", flow_id="f1")
    assert out == {}
    assert err is None
    out, err = _safe_json_load_dict(None, label="state_bag", flow_id="f1")
    assert out == {}
    assert err is None
