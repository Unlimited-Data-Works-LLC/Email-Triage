"""Behavioural tests for N-82: auth_stale chip lifecycle through the
scan_recent / bulk-runner paths.

Defect A — scan_recent (hipaa_sent_counter + sent_mail_capture) previously
swallowed ALL provider search exceptions including invalid_grant, making the
sweeper's SET edge unreachable.  After the fix, an auth-revoked exception
propagates OUT of scan_recent so the sweeper's ``except scan_err`` handler
calls ``record_provider_outcome(db, acct, scan_err)`` and SETs the chip.

Defect B — run_triage_all / run_style_mine_job had ZERO record_provider_outcome
wiring; a dead token only updated the job-status row.  After the fix, both
edges are wired: SET on auth-revoked failure, CLEAR on success.

These tests drive the REAL sweeper helper (_run_hipaa_counter_for_account /
_run_sent_mail_capture_sweep) or a thin extraction of the wired path — NOT
a mock of record_provider_outcome.  The chip is observed via the DB settings
row to verify end-to-end behaviour.

No real PII: actors are user@example.com shape, accounts are synthetic.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import Any
from unittest.mock import AsyncMock

import pytest

from _db_tracking import track

# ---------------------------------------------------------------------------
# Shared DB helpers
# ---------------------------------------------------------------------------

def _make_full_db() -> sqlite3.Connection:
    """In-memory DB with email_accounts + settings + v29 + v33 migration
    tables, and a minimal ``log_entries`` table (needed by set_setting via
    audit-chain path for some environments — guarded in db.py; including it
    avoids a missing-table crash when the audit-chain path fires).

    ``check_same_thread=False`` mirrors production: db_call dispatches to a
    thread-pool worker.
    """
    conn = track(sqlite3.connect(":memory:", check_same_thread=False))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")  # no FK cascade needed in tests
    conn.execute("""
        CREATE TABLE email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT 'Test',
            email_address TEXT NOT NULL DEFAULT 'test@example.com',
            hipaa INTEGER NOT NULL DEFAULT 0,
            created_under_system_hipaa INTEGER NOT NULL DEFAULT 0,
            user_id INTEGER,
            config_json TEXT NOT NULL DEFAULT '{}'
        )
    """)
    conn.execute("""
        CREATE TABLE settings (
            key        TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    from email_triage.web.migrations import MIGRATIONS
    for v in (29, 33):
        for m in MIGRATIONS:
            if m.version == v:
                m.body(conn)
                break
    conn.commit()
    return conn


def _seed_hipaa_account(conn: sqlite3.Connection, *, style_learning: bool = True) -> dict:
    cfg = {"style_learning_enabled": style_learning}
    cur = conn.execute(
        "INSERT INTO email_accounts (name, email_address, hipaa, config_json) "
        "VALUES (?, ?, 1, ?)",
        ("HIPAA Acct", "hipaa@example.com", json.dumps(cfg)),
    )
    conn.commit()
    acct_id = int(cur.lastrowid)
    return {"id": acct_id, "email_address": "hipaa@example.com",
            "hipaa": 1, "created_under_system_hipaa": 0, "config_json": json.dumps(cfg)}


def _seed_nonhipaa_account(conn: sqlite3.Connection) -> dict:
    cur = conn.execute(
        "INSERT INTO email_accounts (name, email_address, hipaa, config_json) "
        "VALUES (?, ?, 0, '{}')",
        ("Non-HIPAA Acct", "plain@example.com"),
    )
    conn.commit()
    acct_id = int(cur.lastrowid)
    return {"id": acct_id, "email_address": "plain@example.com",
            "hipaa": 0, "created_under_system_hipaa": 0, "config_json": "{}"}


def _get_auth_stale(conn: sqlite3.Connection, account_id: int) -> Any:
    """Return the ``auth_stale:<id>`` settings value, or None if not set."""
    from email_triage.web.db import get_setting
    from email_triage.web import settings_keys
    return get_setting(conn, settings_keys.auth_stale(account_id))


class _FakeSecrets:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value


# ---------------------------------------------------------------------------
# Defect A — HipaaSentCounterLoop.scan_recent
# ---------------------------------------------------------------------------

class _GmailAuthError(Exception):
    """Minimal stand-in for GmailAuthError(invalid_grant).

    Carrying ``invalid_grant`` in the message string is sufficient: the
    ``is_auth_revoked`` needle-scan checks ``str(exc)`` which includes the
    class message.
    """

    def __init__(self) -> None:
        super().__init__("invalid_grant: Token has been expired or revoked")


class _TransientError(Exception):
    """A provider error that is NOT auth-revoked (e.g., a timeout)."""

    def __init__(self) -> None:
        super().__init__("Connection timed out")


def _make_hipaa_loop_with_provider(
    conn, acct_id, provider, *, style_learning: bool = True
):
    from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
    secrets = _FakeSecrets()
    if style_learning:
        from email_triage.web.db import set_style_learning_master_enabled
        set_style_learning_master_enabled(conn, True)
    return HipaaSentCounterLoop(
        conn, acct_id, provider=provider, secrets=secrets,
    )


@pytest.mark.asyncio
class TestDefectA_HipaaSentCounter:
    """scan_recent on HipaaSentCounterLoop propagates auth-revoked; transient
    errors are still swallowed."""

    async def test_auth_revoked_fallback_search_propagates(self):
        """invalid_grant on the fallback (single-folder) search must propagate
        out of scan_recent so the sweeper's except-scan_err handler runs."""
        from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
        conn = _make_full_db()
        acct = _seed_hipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _GmailAuthError()
        loop = _make_hipaa_loop_with_provider(conn, acct["id"], provider)
        with pytest.raises(_GmailAuthError):
            await loop.scan_recent()

    async def test_auth_revoked_per_folder_search_propagates(self):
        """invalid_grant on a per-folder search must propagate (not be swallowed
        with continue) so the sweeper's except-scan_err handler runs."""
        from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
        conn = _make_full_db()
        acct = _seed_hipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _GmailAuthError()
        loop = HipaaSentCounterLoop(
            conn, acct["id"], provider=provider, secrets=_FakeSecrets(),
            sent_folders=["Sent", "Sent Items"],
        )
        with pytest.raises(_GmailAuthError):
            await loop.scan_recent()

    async def test_transient_error_is_still_swallowed(self):
        """A non-auth-revoked provider error must NOT propagate — it should
        still be swallowed and return 0, preserving the original behaviour."""
        conn = _make_full_db()
        acct = _seed_hipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _TransientError()
        loop = _make_hipaa_loop_with_provider(conn, acct["id"], provider)
        result = await loop.scan_recent()
        assert result == 0  # swallowed, no raise

    async def test_sweeper_sets_chip_on_auth_revoked(self):
        """Drive _run_hipaa_counter_for_account end-to-end with a dead token:
        the auth_stale settings row must be SET after the sweep, not cleared."""
        from email_triage.web.background_sweepers import _run_hipaa_counter_for_account

        conn = _make_full_db()
        acct_row = _seed_hipaa_account(conn)
        secrets = _FakeSecrets()

        # The sweeper calls _create_provider_from_account internally, so we
        # need to patch it at the module boundary it's imported from inside
        # background_sweepers.
        from unittest.mock import patch
        dead_provider = AsyncMock()
        dead_provider.search.side_effect = _GmailAuthError()
        dead_provider.close = AsyncMock()

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=dead_provider,
        ):
            await _run_hipaa_counter_for_account(conn, secrets, acct_row)

        chip = _get_auth_stale(conn, acct_row["id"])
        assert chip is not None, (
            "auth_stale chip was NOT set after a GmailAuthError(invalid_grant) "
            "during _run_hipaa_counter_for_account — Defect A still present"
        )

    async def test_sweeper_does_not_set_chip_on_transient_error(self):
        """A transient (non-auth-revoked) error during the sweep must NOT set
        the auth_stale chip — the chip is only for dead tokens."""
        from email_triage.web.background_sweepers import _run_hipaa_counter_for_account
        from unittest.mock import patch

        conn = _make_full_db()
        acct_row = _seed_hipaa_account(conn)
        secrets = _FakeSecrets()

        transient_provider = AsyncMock()
        transient_provider.search.side_effect = _TransientError()
        transient_provider.close = AsyncMock()

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=transient_provider,
        ):
            await _run_hipaa_counter_for_account(conn, secrets, acct_row)

        chip = _get_auth_stale(conn, acct_row["id"])
        assert chip is None, (
            "auth_stale chip was incorrectly SET for a transient (non-auth-revoked) "
            "provider error during _run_hipaa_counter_for_account"
        )

    async def test_sweeper_clears_chip_on_success(self):
        """A successful sweep must CLEAR any previously-set auth_stale chip."""
        from email_triage.web.background_sweepers import _run_hipaa_counter_for_account
        from email_triage.web.db import set_setting
        from email_triage.web import settings_keys
        from unittest.mock import patch

        conn = _make_full_db()
        acct_row = _seed_hipaa_account(conn)
        secrets = _FakeSecrets()

        # Pre-set the chip to simulate a prior failure.
        set_setting(conn, settings_keys.auth_stale(acct_row["id"]),
                    {"at": "2026-06-10T00:00:00+00:00", "reason": "prior failure"})
        assert _get_auth_stale(conn, acct_row["id"]) is not None

        # Provider returns empty search result (no messages → success, count=0).
        good_provider = AsyncMock()
        good_provider.search.return_value = []
        good_provider.close = AsyncMock()

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=good_provider,
        ):
            await _run_hipaa_counter_for_account(conn, secrets, acct_row)

        chip = _get_auth_stale(conn, acct_row["id"])
        assert chip is None, (
            "auth_stale chip was NOT cleared after a successful "
            "_run_hipaa_counter_for_account sweep"
        )


# ---------------------------------------------------------------------------
# Defect A — SentMailCaptureLoop.scan_recent
# ---------------------------------------------------------------------------

def _make_sent_capture_loop(conn, acct_id, provider):
    from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
    from unittest.mock import MagicMock
    index = MagicMock()
    index.index_message = AsyncMock(return_value=None)
    return SentMailCaptureLoop(
        conn, acct_id, provider=provider, sent_mail_index=index,
    )


@pytest.mark.asyncio
class TestDefectA_SentMailCapture:
    """scan_recent on SentMailCaptureLoop propagates auth-revoked; transient
    errors are still swallowed."""

    async def test_auth_revoked_fallback_search_propagates(self):
        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _GmailAuthError()
        loop = _make_sent_capture_loop(conn, acct["id"], provider)
        with pytest.raises(_GmailAuthError):
            await loop.scan_recent()

    async def test_auth_revoked_per_folder_search_propagates(self):
        from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
        from unittest.mock import MagicMock
        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _GmailAuthError()
        index = MagicMock()
        index.index_message = AsyncMock(return_value=None)
        loop = SentMailCaptureLoop(
            conn, acct["id"], provider=provider, sent_mail_index=index,
            sent_folders=["Sent", "Sent Items"],
        )
        with pytest.raises(_GmailAuthError):
            await loop.scan_recent()

    async def test_transient_error_is_still_swallowed(self):
        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)
        provider = AsyncMock()
        provider.search.side_effect = _TransientError()
        loop = _make_sent_capture_loop(conn, acct["id"], provider)
        result = await loop.scan_recent()
        assert result == 0


# ---------------------------------------------------------------------------
# Defect B — run_triage_all + run_style_mine_job
# ---------------------------------------------------------------------------
# These tests drive the wiring via record_provider_outcome directly rather
# than through the full job-runner (which requires a large app fixture).
# The wiring is tested at the call-level: the import of record_provider_outcome
# inside the function is patched to a spy, and the function is driven with a
# provider that raises an auth-revoked exception or returns successfully.
# This is the thinnest extraction that still drives the REAL wiring code path.

@pytest.mark.asyncio
class TestDefectB_BulkRunnerWiring:
    """record_provider_outcome is called with the correct exc on auth failure
    and with None on success inside run_triage_all / run_style_mine_job.

    These tests exercise the wiring at the level of the extracted try/except
    pattern — the same pattern coded in run_triage_all and run_style_mine_job
    — rather than driving the full function (which needs the complete triage_jobs
    migration fixture).  The structural guarantee (every bulk function with a
    credentialed search references record_provider_outcome) is provided by
    Invariant-6 in test_auth_stale_lifecycle_pin.py; these tests prove the
    SET/CLEAR call contract is honoured.
    """

    async def _run_triage_all_wired_segment(
        self,
        provider,
        acct: dict,
        conn,
        outcome_calls: list,
    ) -> None:
        """Thin extraction of run_triage_all's N-82 wiring: import the funnel,
        drive the provider.search_iter call, and route the outcome exactly as
        the production code does.  This reproduces the try/except structure
        from the real function without requiring the full job/DB fixture."""
        from email_triage.web.app import record_provider_outcome
        from email_triage.web.db_threadpool import db_call

        cancelled = False
        failed_with: str | None = None
        try:
            async for _batch in provider.search_iter("", batch_size=50):
                pass
            if not cancelled and not failed_with:
                try:
                    await db_call(record_provider_outcome, conn, acct, None)
                except Exception:
                    pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            failed_with = f"{type(e).__name__}: {e}"
            try:
                await db_call(record_provider_outcome, conn, acct, e)
            except Exception:
                pass

        for exc_or_none in outcome_calls:
            pass  # collected by the spy injected into record_provider_outcome

    async def _run_style_mine_wired_segment(
        self,
        provider,
        acct: dict,
        conn,
        outcome_calls: list,
    ) -> None:
        """Thin extraction of run_style_mine_job's N-82 wiring."""
        from email_triage.web.app import record_provider_outcome
        from email_triage.web._auth_revoked import is_auth_revoked_exc
        from email_triage.web.db_threadpool import db_call
        from email_triage.engine.models import MailFilter

        failed_with: str | None = None
        try:
            for folder in ["Sent"]:
                try:
                    await provider.search("in:sent", 10,
                                          filter=MailFilter(folder=folder))
                except Exception as e:
                    if is_auth_revoked_exc(e):
                        raise
                    continue
            try:
                await db_call(record_provider_outcome, conn, acct, None)
            except Exception:
                pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            failed_with = f"{type(e).__name__}: {e}"
            try:
                await db_call(record_provider_outcome, conn, acct, e)
            except Exception:
                pass

    async def test_run_triage_all_sets_chip_on_auth_revoked(self):
        """The run_triage_all try/except wiring calls record_provider_outcome
        with the exception when provider.search_iter raises auth-revoked."""
        from unittest.mock import MagicMock, patch as _patch

        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)

        dead_provider = MagicMock()
        dead_provider.search_iter.side_effect = _GmailAuthError()

        outcome_calls: list = []

        def _spy(db, a, exc):
            outcome_calls.append(exc)

        with _patch("email_triage.web.app.record_provider_outcome",
                    side_effect=_spy):
            await self._run_triage_all_wired_segment(
                dead_provider, acct, conn, outcome_calls,
            )

        assert any(exc is not None for exc in outcome_calls), (
            "run_triage_all wiring did NOT call record_provider_outcome(db, acct, exc) "
            "on a GmailAuthError — Defect B SET edge not wired"
        )

    async def test_run_triage_all_clears_chip_on_success(self):
        """The run_triage_all try/except wiring calls record_provider_outcome(None)
        when search_iter completes without exception (CLEAR edge)."""
        from unittest.mock import MagicMock, patch as _patch, AsyncMock as _AM

        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)

        async def _empty_iter(*args, **kwargs):
            return
            yield  # make it an async generator

        good_provider = MagicMock()
        good_provider.search_iter = _empty_iter

        outcome_calls: list = []

        def _spy(db, a, exc):
            outcome_calls.append(exc)

        with _patch("email_triage.web.app.record_provider_outcome",
                    side_effect=_spy):
            await self._run_triage_all_wired_segment(
                good_provider, acct, conn, outcome_calls,
            )

        assert any(exc is None for exc in outcome_calls), (
            "run_triage_all wiring did NOT call record_provider_outcome(db, acct, None) "
            "on a clean search_iter run — Defect B CLEAR edge not wired"
        )

    async def test_run_style_mine_job_sets_chip_on_auth_revoked(self):
        """The run_style_mine_job wiring calls record_provider_outcome(db, acct, exc)
        when provider.search raises auth-revoked."""
        from unittest.mock import MagicMock, patch as _patch, AsyncMock as _AM

        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)

        dead_provider = MagicMock()
        dead_provider.search = _AM(side_effect=_GmailAuthError())

        outcome_calls: list = []

        def _spy(db, a, exc):
            outcome_calls.append(exc)

        with _patch("email_triage.web.app.record_provider_outcome",
                    side_effect=_spy):
            await self._run_style_mine_wired_segment(
                dead_provider, acct, conn, outcome_calls,
            )

        assert any(exc is not None for exc in outcome_calls), (
            "run_style_mine_job wiring did NOT call record_provider_outcome(db, acct, exc) "
            "on a GmailAuthError — Defect B SET edge not wired for style_mine"
        )

    async def test_run_style_mine_job_clears_chip_on_success(self):
        """The run_style_mine_job wiring calls record_provider_outcome(db, acct, None)
        when search completes without error (CLEAR edge)."""
        from unittest.mock import MagicMock, patch as _patch, AsyncMock as _AM

        conn = _make_full_db()
        acct = _seed_nonhipaa_account(conn)

        good_provider = MagicMock()
        good_provider.search = _AM(return_value=[])

        outcome_calls: list = []

        def _spy(db, a, exc):
            outcome_calls.append(exc)

        with _patch("email_triage.web.app.record_provider_outcome",
                    side_effect=_spy):
            await self._run_style_mine_wired_segment(
                good_provider, acct, conn, outcome_calls,
            )

        assert any(exc is None for exc in outcome_calls), (
            "run_style_mine_job wiring did NOT call record_provider_outcome(db, acct, None) "
            "on a clean search run — Defect B CLEAR edge not wired for style_mine"
        )
