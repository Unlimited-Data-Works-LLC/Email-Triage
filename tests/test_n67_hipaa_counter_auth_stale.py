"""Behavioural tests for N-67 — HIPAA sent counter wires auth_stale funnel.

``_run_hipaa_counter_for_account`` is the HIPAA twin of the non-HIPAA sent-mail
capture loop.  Before N-67 it called ``loop.scan_recent()`` (a credentialed
liveness op) but NEVER called ``record_provider_outcome`` — so an auth-revoked
OAuth token on a HIPAA account stayed invisible (no auth_stale chip), and a
recovered account kept the chip until something else cleared it.

The fix wires ``record_provider_outcome`` on both edges (mirroring the
non-HIPAA twin at lines ~1347-1359 of background_sweepers.py):
  * scan failure  → ``record_provider_outcome(db, acct, scan_err)``
  * scan success  → ``record_provider_outcome(db, acct, None)``

These tests mock ``db_call`` and the provider-loop machinery so we can
observe what arguments ``record_provider_outcome`` receives without needing
the full DB schema (which includes audit chains, HMAC tables, etc.).
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch, call as mock_call

import pytest


# ---------------------------------------------------------------------------
# Synthetic account dict (same shape as what get_email_account returns)
# ---------------------------------------------------------------------------

def _make_acct(account_id: int = 1) -> dict:
    return {
        "id": account_id,
        "name": "HIPAA Test Account",
        "email_address": "hipaa@example.com",
        "hipaa": 1,
        "created_under_system_hipaa": 0,
        "config_json": json.dumps({"style_learning_enabled": True}),
        "config": {"style_learning_enabled": True},
    }


class _FakeSecrets:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value


class _AuthRevokedError(Exception):
    """An error whose str() passes the is_auth_revoked needle filter
    (invalid_grant is in AUTH_REVOKED_NEEDLES)."""
    def __str__(self) -> str:
        return "OAuth token expired: invalid_grant"


# ---------------------------------------------------------------------------
# Async driver that patches every external call to an in-memory stub
# ---------------------------------------------------------------------------

async def _drive(
    *,
    scan_raises: Exception | None = None,
    scan_returns: int = 0,
) -> dict:
    """Run _run_hipaa_counter_for_account with patched dependencies.

    Returns a dict with the calls made to db_call so we can inspect
    whether record_provider_outcome was invoked and with what arguments.
    """
    from email_triage.web.background_sweepers import (
        _run_hipaa_counter_for_account,
    )
    acct = _make_acct()
    secrets = _FakeSecrets()

    # Fake in-memory DB (just needs to be a truthy object; db_call is mocked)
    fake_db = MagicMock(spec=sqlite3.Connection)

    # Fake provider — just needs .close()
    fake_provider = AsyncMock()

    # Fake loop — scan_recent raises or returns
    fake_loop = AsyncMock()
    if scan_raises is not None:
        fake_loop.scan_recent.side_effect = scan_raises
    else:
        fake_loop.scan_recent.return_value = scan_returns

    # Record every db_call invocation so we can assert on them.
    db_call_log: list[tuple] = []

    async def _fake_db_call(fn, *args, **kwargs):
        db_call_log.append((fn, args, kwargs))
        # For record_provider_outcome and record_auth_event: no-op (return None)
        return None

    with (
        patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ),
        patch(
            "email_triage.actions.hipaa_sent_counter.HipaaSentCounterLoop",
            return_value=fake_loop,
        ),
        patch(
            "email_triage.web.background_sweepers._run_hipaa_counter_for_account"
            ".__globals__",
            None,  # not used — see below
        ) if False else _noop_ctx(),
        # The db_call import inside _run_hipaa_counter_for_account is a
        # late import; patch at the module level in db_threadpool.
        patch(
            "email_triage.web.db_threadpool.db_call",
            side_effect=_fake_db_call,
        ),
    ):
        result = await _run_hipaa_counter_for_account(fake_db, secrets, acct)

    return {
        "result": result,
        "db_call_log": db_call_log,
        "acct": acct,
    }


class _noop_ctx:
    def __enter__(self): return self
    def __exit__(self, *_): pass


def _rpo_calls(db_call_log: list, acct: dict) -> list[tuple]:
    """Filter db_call_log for record_provider_outcome calls and return
    (acct_dict, exc_or_none) pairs."""
    from email_triage.web.app import record_provider_outcome
    out = []
    for fn, args, kwargs in db_call_log:
        if fn is record_provider_outcome:
            # args = (db, acct, exc) after the db_call unpacking
            # but _fake_db_call receives (fn, *args) so args = (db, acct, exc)
            if len(args) >= 3:
                out.append((args[1], args[2]))
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestN67HipaaCounterAuthStale:
    """N-67: _run_hipaa_counter_for_account wires record_provider_outcome."""

    @pytest.mark.asyncio
    async def test_failing_scan_calls_rpo_with_exception(self):
        """An auth-revoked scan failure calls record_provider_outcome(db, acct, exc)."""
        err = _AuthRevokedError()
        ctx = await _drive(scan_raises=err)

        rpo = _rpo_calls(ctx["db_call_log"], ctx["acct"])
        assert rpo, (
            "N-67 regression: _run_hipaa_counter_for_account did NOT call "
            "record_provider_outcome after a scan failure. The auth_stale chip "
            "will never be set on this path."
        )
        # The last (or only) RPO call should carry the exception.
        _, exc_arg = rpo[-1]
        assert exc_arg is err, (
            f"Expected record_provider_outcome to be called with the scan "
            f"exception, got: {exc_arg!r}"
        )

    @pytest.mark.asyncio
    async def test_failing_scan_returns_zero(self):
        """A failing scan returns 0 (no messages counted)."""
        ctx = await _drive(scan_raises=_AuthRevokedError())
        assert ctx["result"] == 0

    @pytest.mark.asyncio
    async def test_successful_scan_calls_rpo_with_none(self):
        """A successful scan calls record_provider_outcome(db, acct, None)
        to clear any prior auth_stale chip."""
        ctx = await _drive(scan_returns=5)

        rpo = _rpo_calls(ctx["db_call_log"], ctx["acct"])
        assert rpo, (
            "N-67 regression: _run_hipaa_counter_for_account did NOT call "
            "record_provider_outcome after a successful scan. A prior auth_stale "
            "chip will never be cleared on this path."
        )
        _, exc_arg = rpo[-1]
        assert exc_arg is None, (
            f"Expected record_provider_outcome to be called with None (success "
            f"path), got: {exc_arg!r}"
        )

    @pytest.mark.asyncio
    async def test_successful_scan_returns_count(self):
        """A successful scan returns the message count from scan_recent."""
        ctx = await _drive(scan_returns=7)
        assert ctx["result"] == 7

    @pytest.mark.asyncio
    async def test_transient_error_still_calls_rpo(self):
        """Even a transient (non-auth) error calls record_provider_outcome so
        the needle filter inside record_provider_outcome decides whether to SET
        the chip (the sweeper does NOT pre-filter — it defers to the funnel)."""
        transient = ConnectionError("IMAP connection timeout")
        ctx = await _drive(scan_raises=transient)

        rpo = _rpo_calls(ctx["db_call_log"], ctx["acct"])
        assert rpo, (
            "N-67: _run_hipaa_counter_for_account should call "
            "record_provider_outcome even for a transient error (the needle "
            "filter inside record_provider_outcome decides whether to set the "
            "chip; the sweeper should not pre-filter)."
        )
        _, exc_arg = rpo[-1]
        assert exc_arg is transient

    @pytest.mark.asyncio
    async def test_rpo_called_exactly_once_on_failure(self):
        """record_provider_outcome is called exactly once on a scan failure
        (not once per error classification layer)."""
        ctx = await _drive(scan_raises=_AuthRevokedError())
        from email_triage.web.app import record_provider_outcome
        rpo_calls = [
            (fn, args) for fn, args, _ in ctx["db_call_log"]
            if fn is record_provider_outcome
        ]
        assert len(rpo_calls) == 1, (
            f"Expected exactly 1 record_provider_outcome call on failure, "
            f"got {len(rpo_calls)}: {rpo_calls}"
        )

    @pytest.mark.asyncio
    async def test_rpo_called_exactly_once_on_success(self):
        """record_provider_outcome is called exactly once on a successful scan."""
        ctx = await _drive(scan_returns=3)
        from email_triage.web.app import record_provider_outcome
        rpo_calls = [
            (fn, args) for fn, args, _ in ctx["db_call_log"]
            if fn is record_provider_outcome
        ]
        assert len(rpo_calls) == 1, (
            f"Expected exactly 1 record_provider_outcome call on success, "
            f"got {len(rpo_calls)}: {rpo_calls}"
        )
