"""N-76 account deactivation clears the auth_stale chip — behavioural + pin.

Fix verified: WatcherManager.apply_account_active_state(active=False) now
calls record_provider_outcome(db, acct, None) to clear any prior auth_stale
flag (the "Re-authenticate required" chip). A paused account kept showing
the red chip forever; deactivation should clear it because the account is
PAUSED, not in need of re-authentication.

Behavioural contracts:
  * Deactivating an account with auth_stale set → chip cleared.
  * Deactivating an account without auth_stale → no-op (idempotent clear is cheap).
  * A clear failure (DB error) must NOT block the deactivation itself.

Structural pin (extends test_auth_stale_lifecycle_pin.py Invariant 3):
  * web/watcher.py must reference record_provider_outcome (already in
    Invariant 3's _WIRED_MODULES — this test adds a function-granular
    assertion that apply_account_active_state itself references it).
"""

from __future__ import annotations

import ast
import asyncio
import sqlite3
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from _pin_harness import SRC_ROOT as SRC, parse_module  # census run13 #4 + N-350 R31
WATCHER_PY = SRC / "web" / "watcher.py"


# ---------------------------------------------------------------------------
# Structural pin — apply_account_active_state references record_provider_outcome
# ---------------------------------------------------------------------------

def test_apply_account_active_state_references_funnel():
    """The apply_account_active_state method body must reference
    record_provider_outcome so the auth_stale clear is wired."""
    tree = parse_module(WATCHER_PY); assert tree is not None  # N-350 R31

    fn_node = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "apply_account_active_state"
        ):
            fn_node = node
            break

    assert fn_node is not None, (
        "apply_account_active_state not found in web/watcher.py"
    )

    names_used: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            names_used.add(n.id)
        elif isinstance(n, ast.Attribute):
            names_used.add(n.attr)

    assert "record_provider_outcome" in names_used, (
        "apply_account_active_state does not reference record_provider_outcome — "
        "the auth_stale clear on deactivation is not wired through the SSOT funnel. "
        "N-76: a paused account kept showing 'Re-authenticate required' forever."
    )


# ---------------------------------------------------------------------------
# Behavioural tests
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user_and_account(conn: sqlite3.Connection) -> tuple[int, dict]:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("owner@example.com", "Owner", "user", _now()),
    )
    conn.commit()
    user_id = int(cur.lastrowid)
    now = _now()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, is_active, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Test Mailbox", "imap", "{}", 1, now, now),
    )
    conn.commit()
    acct_id = int(cur.lastrowid)
    from email_triage.web.db import get_email_account
    return user_id, get_email_account(conn, acct_id)


def _set_auth_stale(conn: sqlite3.Connection, account_id: int) -> None:
    """Plant an auth_stale settings row for the account."""
    from email_triage.web import settings_keys as _sk
    from email_triage.web.db import set_setting
    set_setting(conn, _sk.auth_stale(account_id), {
        "at": _now(),
        "reason": "invalid_grant",
    })


def _has_auth_stale(conn: sqlite3.Connection, account_id: int) -> bool:
    from email_triage.web import settings_keys as _sk
    from email_triage.web.db import get_setting
    return get_setting(conn, _sk.auth_stale(account_id)) is not None


def _make_watcher_manager(conn: sqlite3.Connection):
    """Minimal WatcherManager with a stubbed app."""
    from email_triage.web.watcher import WatcherManager
    app = MagicMock()
    app.state.db = conn
    mgr = WatcherManager(app)
    return mgr


@pytest.mark.asyncio
async def test_deactivate_clears_auth_stale():
    """Deactivating an account with auth_stale set clears the chip."""
    conn = _make_db()
    _, acct = _seed_user_and_account(conn)
    account_id = acct["id"]

    # Plant the auth_stale chip
    _set_auth_stale(conn, account_id)
    assert _has_auth_stale(conn, account_id), "precondition: chip must be set"

    mgr = _make_watcher_manager(conn)

    # Patch stop() to be a no-op (no real watchers running)
    with patch.object(mgr, "stop", new_callable=AsyncMock):
        result = await mgr.apply_account_active_state(account_id, active=False)

    assert not _has_auth_stale(conn, account_id), (
        "Deactivation should clear the auth_stale chip — "
        "a paused account must not permanently show 'Re-authenticate required'"
    )
    assert "Ingestion stopped" in result


@pytest.mark.asyncio
async def test_deactivate_no_chip_is_idempotent():
    """Deactivating an account that has no auth_stale chip is a no-op (safe)."""
    conn = _make_db()
    _, acct = _seed_user_and_account(conn)
    account_id = acct["id"]

    assert not _has_auth_stale(conn, account_id), "precondition: no chip"

    mgr = _make_watcher_manager(conn)
    with patch.object(mgr, "stop", new_callable=AsyncMock):
        result = await mgr.apply_account_active_state(account_id, active=False)

    assert not _has_auth_stale(conn, account_id)
    assert "Ingestion stopped" in result


@pytest.mark.asyncio
async def test_clear_failure_does_not_block_deactivation():
    """A DB error during the auth_stale clear must NOT block the deactivation."""
    conn = _make_db()
    _, acct = _seed_user_and_account(conn)
    account_id = acct["id"]
    _set_auth_stale(conn, account_id)

    mgr = _make_watcher_manager(conn)

    with (
        patch.object(mgr, "stop", new_callable=AsyncMock),
        patch(
            "email_triage.web.app.record_provider_outcome",
            side_effect=RuntimeError("DB locked"),
        ),
    ):
        result = await mgr.apply_account_active_state(account_id, active=False)

    # Deactivation must succeed even when the clear fails
    assert "Ingestion stopped" in result, (
        "Deactivation result string lost — the auth_stale clear failure "
        "blocked or altered the deactivation path"
    )
