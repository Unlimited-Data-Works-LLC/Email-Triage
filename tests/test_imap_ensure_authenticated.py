"""Tests for #147 — IMAP NONAUTH digest race + state diagnostics.

The failure: scheduled digest fired at 06:00, hit a cached IMAP
client whose protocol state had drifted to ``NONAUTH``, and aioimaplib
raised ``Abort('command SELECT illegal in state NONAUTH')``. The
diagnostic capture (``_capture_imap_state``) + pre-flight auth check
(``_ensure_authenticated`` module-level + bound on the provider) +
wired call sites in ``select_folder`` and ``search`` recover the
common case (re-LOGIN replays cleanly on the existing transport)
and surface every observed-state field on the rare case where it
doesn't.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

aioimaplib = pytest.importorskip("aioimaplib")

from email_triage.providers.imap import (  # noqa: E402
    IMAPClientLogoutError,
    ImapProvider,
    _capture_imap_state,
    _ensure_authenticated,
)


def _make_fake_client(state: str = "AUTH") -> MagicMock:
    """Mock client whose ``get_state()`` returns the requested state.

    Mirrors aioimaplib's IMAP4 surface enough for the helper to walk
    over: ``get_state()`` callable, ``protocol.capabilities`` list,
    ``has_pending_idle()`` callable, ``login`` async-callable.
    """
    client = MagicMock()
    client.get_state = MagicMock(return_value=state)
    client.protocol = MagicMock()
    client.protocol.state = state
    client.protocol.capabilities = ["IMAP4rev1", "IDLE"]
    client.has_pending_idle = MagicMock(return_value=False)
    client.login = AsyncMock(return_value=("OK", []))
    client.select = AsyncMock(return_value=("OK", []))
    client.logout = AsyncMock(return_value=("OK", []))
    return client


# ---------------------------------------------------------------------------
# Module-level _ensure_authenticated — state-only contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_authenticated_auth_state_is_noop():
    client = _make_fake_client(state="AUTH")
    state = await _ensure_authenticated(client)
    assert state == "AUTH"
    client.login.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_authenticated_selected_state_is_noop():
    """SELECTED is a strict superset of AUTH — also no-op."""
    client = _make_fake_client(state="SELECTED")
    state = await _ensure_authenticated(client)
    assert state == "SELECTED"


@pytest.mark.asyncio
async def test_ensure_authenticated_nonauth_raises_abort():
    """NONAUTH must surface so the bound wrapper can re-LOGIN."""
    client = _make_fake_client(state="NONAUTH")
    with pytest.raises(aioimaplib.Abort):
        await _ensure_authenticated(client)


@pytest.mark.asyncio
async def test_ensure_authenticated_logout_raises_typed_error():
    """LOGOUT is unrecoverable on this transport — caller must reconnect."""
    client = _make_fake_client(state="LOGOUT")
    with pytest.raises(IMAPClientLogoutError):
        await _ensure_authenticated(client)


@pytest.mark.asyncio
async def test_ensure_authenticated_none_client_is_noop():
    """A fresh provider hasn't connected yet — nothing to validate."""
    state = await _ensure_authenticated(None)
    assert state == "AUTH"


@pytest.mark.asyncio
async def test_ensure_authenticated_unreadable_state_treated_as_logout():
    """If we can't even read state, treat as broken."""
    client = MagicMock()
    client.get_state = MagicMock(side_effect=RuntimeError("transport closed"))
    with pytest.raises(IMAPClientLogoutError):
        await _ensure_authenticated(client)


# ---------------------------------------------------------------------------
# Bound provider method — re-LOGIN behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_ensure_authenticated_replays_login_on_nonauth():
    """NONAUTH cached client → bound helper fires re-LOGIN."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="NONAUTH")

    # After login() succeeds, simulate state transition.
    async def _login(_u, _p):
        client.get_state.return_value = "AUTH"
        client.protocol.state = "AUTH"
        return ("OK", [])
    client.login.side_effect = _login

    provider._client = client
    state = await provider._ensure_authenticated()
    assert state == "AUTH"
    client.login.assert_awaited_once_with("u", "p")


@pytest.mark.asyncio
async def test_provider_ensure_authenticated_login_failure_drops_client():
    """If re-LOGIN raises, the cached client is reset and a typed
    error surfaces so the caller knows to reconnect."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="NONAUTH")
    client.login = AsyncMock(side_effect=RuntimeError("auth failed"))

    provider._client = client
    with pytest.raises(IMAPClientLogoutError):
        await provider._ensure_authenticated()
    # Cached client cleared so the next call opens fresh.
    assert provider._client is None


@pytest.mark.asyncio
async def test_provider_ensure_authenticated_login_ok_but_state_unchanged():
    """LOGIN returned OK but state didn't move — bail with typed error."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="NONAUTH")
    # login() returns success but state stays NONAUTH.
    client.login = AsyncMock(return_value=("OK", []))

    provider._client = client
    with pytest.raises(IMAPClientLogoutError):
        await provider._ensure_authenticated()
    assert provider._client is None


@pytest.mark.asyncio
async def test_provider_ensure_authenticated_auth_is_noop():
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="AUTH")
    provider._client = client
    state = await provider._ensure_authenticated()
    assert state == "AUTH"
    client.login.assert_not_awaited()


# ---------------------------------------------------------------------------
# _capture_imap_state — diagnostic fields
# ---------------------------------------------------------------------------


def test_capture_imap_state_handles_none():
    """No client → still returns a dict, never raises."""
    out = _capture_imap_state(None)
    assert out["auth_state"] == "unknown"
    assert out["age_secs"] == -1
    assert out["capabilities"] == ""


def test_capture_imap_state_records_state_and_capabilities():
    client = _make_fake_client(state="NONAUTH")
    out = _capture_imap_state(client)
    assert out["auth_state"] == "NONAUTH"
    assert "IMAP4rev1" in out["capabilities"]
    assert out["has_pending_idle"] is False


def test_capture_imap_state_age_uses_connect_stamp():
    """If the client was stamped with ``_et_connect_ts``, ``age_secs``
    should be a non-negative integer."""
    import time
    client = _make_fake_client(state="AUTH")
    client._et_connect_ts = time.monotonic() - 5.0
    out = _capture_imap_state(client)
    assert out["age_secs"] >= 4  # rounding tolerance


def test_capture_imap_state_swallows_exceptions():
    """The diagnostic helper must never become a new error path."""
    client = MagicMock()
    client.get_state = MagicMock(side_effect=RuntimeError("boom"))
    # Must not raise.
    out = _capture_imap_state(client)
    assert out["auth_state"] == "unknown"


# ---------------------------------------------------------------------------
# Digest path wiring — pre-flight check fires before SELECT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_select_folder_calls_ensure_authenticated_first():
    """The digest path's :meth:`select_folder` must run the
    pre-flight check before issuing the SELECT to the server."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="AUTH")
    provider._client = client

    call_order: list[str] = []

    async def _record_ensure():
        call_order.append("ensure")
        return "AUTH"

    async def _record_select(folder):
        call_order.append(f"select:{folder}")
        return ("OK", [])

    provider._ensure_authenticated = _record_ensure
    client.select = AsyncMock(side_effect=_record_select)

    await provider.select_folder("Triage.Newsletters")

    assert call_order[0] == "ensure"
    assert call_order[1].startswith("select:")


@pytest.mark.asyncio
async def test_select_folder_recovers_from_nonauth_via_relogin():
    """When the cached client is NONAUTH, re-LOGIN happens then
    SELECT proceeds. Verifies the recovery path end-to-end on
    the digest's ``select_folder`` call."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="NONAUTH")

    relogin_count = 0

    async def _login(_u, _p):
        nonlocal relogin_count
        relogin_count += 1
        client.get_state.return_value = "AUTH"
        return ("OK", [])
    client.login.side_effect = _login

    provider._client = client
    await provider.select_folder("INBOX")

    assert relogin_count == 1
    client.select.assert_awaited()


@pytest.mark.asyncio
async def test_search_calls_ensure_authenticated_first():
    """The digest's search() also runs the pre-flight check."""
    provider = ImapProvider(host="imap.test", username="u", password="p")
    client = _make_fake_client(state="AUTH")
    provider._client = client

    call_order: list[str] = []

    async def _record_ensure():
        call_order.append("ensure")
        return "AUTH"

    async def _search(_q):
        call_order.append("search")
        return ("OK", [b"1 2 3", b"Search completed"])

    provider._ensure_authenticated = _record_ensure
    client.search = AsyncMock(side_effect=_search)
    client.fetch = AsyncMock(return_value=(
        "OK", [b"1 FETCH (UID 11)", b"2 FETCH (UID 12)", b"3 FETCH (UID 13)"]
    ))

    await provider.search("ALL")

    # ensure ran before any SEARCH was sent.
    assert call_order[0] == "ensure"
    assert "search" in call_order
