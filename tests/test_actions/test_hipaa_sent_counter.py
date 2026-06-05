"""Tests for ``actions.hipaa_sent_counter``.

Scope: hash_message_id_for_install correctness + dedup behaviour +
HipaaSentCounterLoop end-to-end against a fake provider + the
inverse-HIPAA gate + the master/per-account style-learning gates.

No real PII: all addresses are ``user@example.com`` shape, all
Message-IDs are synthetic ``<m-N@example.com>``.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.hipaa_sent_counter import HipaaSentCounterLoop
from email_triage.engine.models import EmailMessage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """The web.db module's settings cache is process-global. Each test
    here builds a fresh in-memory DB, so cache leakage between tests
    (e.g. a "master toggle off" write priming the cache for the next
    test's fresh DB) would give false negatives. Clear before + after.
    """
    from email_triage.web.db import _settings_cache
    _settings_cache.clear()
    yield
    _settings_cache.clear()


def _make_db() -> sqlite3.Connection:
    """In-memory DB with email_accounts + settings + v29 + v33.

    The migrations modules' ``email_accounts`` shape carries a lot of
    columns that aren't relevant here — only ``id``, ``hipaa``,
    ``created_under_system_hipaa``, and ``config_json`` are read by
    the loop. Build a minimal CREATE TABLE that satisfies the
    foreign-key constraints in the v29/v33 tables.
    """
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hipaa INTEGER NOT NULL DEFAULT 0,
            created_under_system_hipaa INTEGER NOT NULL DEFAULT 0,
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
    # v29 = hipaa_send_counters, v33 = hipaa_sent_dedup.
    for v in (29, 33):
        applied = False
        for m in MIGRATIONS:
            if m.version == v:
                m.body(conn)
                applied = True
                break
        assert applied, f"migration v{v} not found"
    conn.commit()
    return conn


def _seed_account(
    conn: sqlite3.Connection,
    *,
    name: str = "Operator HIPAA",
    hipaa: bool = True,
    style_learning_enabled: bool = True,
) -> int:
    cfg = {"style_learning_enabled": style_learning_enabled}
    cur = conn.execute(
        "INSERT INTO email_accounts (name, hipaa, config_json) "
        "VALUES (?, ?, ?)",
        (name, int(bool(hipaa)), json.dumps(cfg)),
    )
    conn.commit()
    return int(cur.lastrowid)


class _FakeSecrets:
    """Minimal secrets backend — get/set against an in-memory dict."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value


def _make_message(
    *,
    uid: str = "u1",
    rfc_id: str | None = "<m-1@example.com>",
    recipients: list[str] | None = None,
    hipaa: bool = True,
) -> EmailMessage:
    headers: dict[str, str] = {}
    if rfc_id:
        headers["Message-ID"] = rfc_id
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="alice@example.com",
        recipients=recipients if recipients is not None else ["bob@example.com"],
        subject="Re: hello",
        body_text="(body intentionally left blank — never read by counter loop)",
        date=datetime(2026, 5, 18, tzinfo=timezone.utc),
        headers=headers,
        hipaa=hipaa,
    )


def _make_fake_provider(messages: list[EmailMessage]):
    """Build a provider stub with .search + .fetch_message + .close."""
    by_id = {m.message_id: m for m in messages}
    provider = AsyncMock()
    provider.search.return_value = list(by_id.keys())

    async def _fetch(uid, folder=None):
        # Tolerate the folder kw the loop sometimes passes.
        return by_id[uid]

    provider.fetch_message.side_effect = _fetch
    return provider


# ---------------------------------------------------------------------------
# hash_message_id_for_install
# ---------------------------------------------------------------------------

class TestHashMessageId:
    def test_round_trip_deterministic_same_salt(self) -> None:
        from email_triage.style_learning.per_contact_hipaa import (
            hash_message_id_for_install,
        )

        s = _FakeSecrets()
        h1 = hash_message_id_for_install("<m-1@example.com>", secrets=s)
        h2 = hash_message_id_for_install("<m-1@example.com>", secrets=s)
        assert h1 == h2
        assert len(h1) == 64
        assert all(c in "0123456789abcdef" for c in h1)

    def test_normalisation_strips_brackets_and_lowercases(self) -> None:
        from email_triage.style_learning.per_contact_hipaa import (
            hash_message_id_for_install,
        )

        s = _FakeSecrets()
        bare = hash_message_id_for_install("M-1@Example.com", secrets=s)
        wrapped = hash_message_id_for_install("<m-1@example.com>", secrets=s)
        spaced = hash_message_id_for_install(
            "  <M-1@Example.com>  ", secrets=s,
        )
        assert bare == wrapped == spaced

    def test_different_inputs_yield_different_hashes(self) -> None:
        from email_triage.style_learning.per_contact_hipaa import (
            hash_message_id_for_install,
        )

        s = _FakeSecrets()
        h1 = hash_message_id_for_install("<m-1@example.com>", secrets=s)
        h2 = hash_message_id_for_install("<m-2@example.com>", secrets=s)
        assert h1 != h2

    def test_different_salts_yield_different_hashes(self) -> None:
        from email_triage.style_learning.per_contact_hipaa import (
            hash_message_id_for_install,
        )

        s1, s2 = _FakeSecrets(), _FakeSecrets()
        h1 = hash_message_id_for_install("<m@example.com>", secrets=s1)
        h2 = hash_message_id_for_install("<m@example.com>", secrets=s2)
        assert h1 != h2  # different installs → different hashes

    def test_empty_input_raises(self) -> None:
        from email_triage.style_learning.per_contact_hipaa import (
            hash_message_id_for_install,
        )

        s = _FakeSecrets()
        with pytest.raises(ValueError):
            hash_message_id_for_install("", secrets=s)
        with pytest.raises(ValueError):
            hash_message_id_for_install("   <>   ", secrets=s)


# ---------------------------------------------------------------------------
# record_hipaa_sent_message_if_new
# ---------------------------------------------------------------------------

class TestRecordIfNew:
    def test_first_call_returns_true_and_bumps_counters(self) -> None:
        from email_triage.web.db import (
            get_hipaa_send_counter,
            record_hipaa_sent_message_if_new,
        )

        conn = _make_db()
        acct_id = _seed_account(conn)
        # 64-char hex for both msgid + recipient.
        msgid_h = "a" * 64
        recip_h = "b" * 64
        new = record_hipaa_sent_message_if_new(
            conn,
            account_id=acct_id,
            msgid_hash=msgid_h,
            recipient_hashes=[recip_h],
        )
        assert new is True
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 1
        per = get_hipaa_send_counter(
            conn, account_id=acct_id, recipient_hash=recip_h,
        )
        assert per is not None and per["count"] == 1

    def test_second_call_same_msgid_is_dedup_noop(self) -> None:
        from email_triage.web.db import (
            get_hipaa_send_counter,
            record_hipaa_sent_message_if_new,
        )

        conn = _make_db()
        acct_id = _seed_account(conn)
        msgid_h = "a" * 64
        recip_h = "b" * 64
        record_hipaa_sent_message_if_new(
            conn, account_id=acct_id, msgid_hash=msgid_h,
            recipient_hashes=[recip_h],
        )
        new = record_hipaa_sent_message_if_new(
            conn, account_id=acct_id, msgid_hash=msgid_h,
            recipient_hashes=[recip_h],
        )
        assert new is False
        # Counters unchanged after the dedup hit.
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 1

    def test_different_msgids_each_bump(self) -> None:
        from email_triage.web.db import (
            get_hipaa_send_counter,
            record_hipaa_sent_message_if_new,
        )

        conn = _make_db()
        acct_id = _seed_account(conn)
        recip_h = "b" * 64
        for i in range(5):
            msgid_h = (hex(i)[2:].rjust(2, "0") + "a" * 62)[:64]
            assert record_hipaa_sent_message_if_new(
                conn, account_id=acct_id, msgid_hash=msgid_h,
                recipient_hashes=[recip_h],
            ) is True
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 5

    def test_multiple_recipients_per_message(self) -> None:
        from email_triage.web.db import (
            get_hipaa_send_counter,
            record_hipaa_sent_message_if_new,
        )

        conn = _make_db()
        acct_id = _seed_account(conn)
        msgid_h = "a" * 64
        recip_a = "b" * 64
        recip_b = "c" * 64
        record_hipaa_sent_message_if_new(
            conn, account_id=acct_id, msgid_hash=msgid_h,
            recipient_hashes=[recip_a, recip_b],
        )
        # Aggregate bumps once per recipient (mirrors
        # record_hipaa_sent_message's double-write behaviour).
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 2
        # Each recipient row at 1.
        assert get_hipaa_send_counter(
            conn, account_id=acct_id, recipient_hash=recip_a,
        )["count"] == 1
        assert get_hipaa_send_counter(
            conn, account_id=acct_id, recipient_hash=recip_b,
        )["count"] == 1

    def test_invalid_msgid_hash_raises(self) -> None:
        from email_triage.web.db import record_hipaa_sent_message_if_new

        conn = _make_db()
        acct_id = _seed_account(conn)
        with pytest.raises(ValueError):
            record_hipaa_sent_message_if_new(
                conn, account_id=acct_id, msgid_hash="short",
                recipient_hashes=[],
            )
        with pytest.raises(ValueError):
            record_hipaa_sent_message_if_new(
                conn, account_id=acct_id,
                msgid_hash="@" * 64,  # non-hex
                recipient_hashes=[],
            )

    def test_dedup_hit_does_not_leak_a_dangling_transaction(self) -> None:
        """ — a dedup-hit on ``record_hipaa_sent_message_if_new``
        must NOT leave an implicit transaction open.

        The dedup-hit path does ``INSERT OR IGNORE`` (which opens an
        implicit sqlite3 transaction even when it inserts zero rows)
        and then returns ``False``. Before the  fix it returned
        without a commit/rollback, so ``conn.in_transaction`` stayed
        True and the NEXT explicit-``BEGIN`` / ``BEGIN IMMEDIATE``
        helper raised ``OperationalError: cannot start a transaction
        within a transaction``. This test runs a dedup hit, asserts the
        connection is clean, then issues an explicit ``BEGIN IMMEDIATE``
        (exactly what the next chain-aware helper would do) and asserts
        it does not raise.
        """
        from email_triage.web.db import record_hipaa_sent_message_if_new

        conn = _make_db()
        acct_id = _seed_account(conn)
        msgid_h = "a" * 64
        recip_h = "b" * 64

        # First call records the message.
        assert record_hipaa_sent_message_if_new(
            conn, account_id=acct_id, msgid_hash=msgid_h,
            recipient_hashes=[recip_h],
        ) is True

        # Second call is a dedup hit — the path under test.
        assert record_hipaa_sent_message_if_new(
            conn, account_id=acct_id, msgid_hash=msgid_h,
            recipient_hashes=[recip_h],
        ) is False

        # The dedup-hit path must have left no open transaction.
        assert conn.in_transaction is False

        # An explicit-BEGIN helper must now start cleanly — before the
        # fix this raised "cannot start a transaction within a
        # transaction" because the INSERT OR IGNORE's implicit
        # transaction was still open.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("ROLLBACK")


# ---------------------------------------------------------------------------
# prune_hipaa_sent_dedup
# ---------------------------------------------------------------------------

class TestPruneDedup:
    def test_old_rows_pruned_recent_kept(self) -> None:
        from email_triage.web.db import prune_hipaa_sent_dedup

        conn = _make_db()
        acct_id = _seed_account(conn)
        # Insert two rows directly — one 100 days old, one yesterday.
        old_ts = "2026-02-07T00:00:00+00:00"   # ~100 days before 2026-05-18
        recent_ts = "2026-05-17T00:00:00+00:00"
        conn.execute(
            "INSERT INTO hipaa_sent_dedup "
            "(account_id, msgid_hash, recorded_at) VALUES (?, ?, ?)",
            (acct_id, "a" * 64, old_ts),
        )
        conn.execute(
            "INSERT INTO hipaa_sent_dedup "
            "(account_id, msgid_hash, recorded_at) VALUES (?, ?, ?)",
            (acct_id, "b" * 64, recent_ts),
        )
        conn.commit()
        pruned = prune_hipaa_sent_dedup(conn, older_than_days=90)
        assert pruned == 1
        remaining = conn.execute(
            "SELECT msgid_hash FROM hipaa_sent_dedup"
        ).fetchall()
        assert len(remaining) == 1
        assert remaining[0][0] == "b" * 64


# ---------------------------------------------------------------------------
# HipaaSentCounterLoop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaSentCounterLoop:
    async def test_non_hipaa_account_refuses(self) -> None:
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=False)
        provider = _make_fake_provider([_make_message()])
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        assert await loop.scan_recent() == 0
        # No counters bumped.
        from email_triage.web.db import get_hipaa_send_counter
        assert get_hipaa_send_counter(conn, account_id=acct_id) is None
        # No provider calls.
        provider.search.assert_not_called()

    async def test_per_account_toggle_off_refuses(self) -> None:
        conn = _make_db()
        acct_id = _seed_account(conn, style_learning_enabled=False)
        provider = _make_fake_provider([_make_message()])
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        assert await loop.scan_recent() == 0
        provider.search.assert_not_called()

    async def test_master_toggle_off_refuses(self) -> None:
        from email_triage.web.db import set_style_learning_master_enabled

        conn = _make_db()
        set_style_learning_master_enabled(conn, False)
        acct_id = _seed_account(conn)
        provider = _make_fake_provider([_make_message()])
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        assert await loop.scan_recent() == 0
        provider.search.assert_not_called()

    async def test_hipaa_account_happy_path(self) -> None:
        from email_triage.web.db import get_hipaa_send_counter

        conn = _make_db()
        acct_id = _seed_account(conn)
        msgs = [
            _make_message(
                uid="u1", rfc_id="<m-1@example.com>",
                recipients=["bob@example.com"],
            ),
            _make_message(
                uid="u2", rfc_id="<m-2@example.com>",
                recipients=["carol@example.com", "dan@example.com"],
            ),
        ]
        provider = _make_fake_provider(msgs)
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        new = await loop.scan_recent()
        assert new == 2
        # Aggregate: 1 recipient for m-1 + 2 recipients for m-2 = 3 bumps.
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 3

    async def test_rescan_is_idempotent(self) -> None:
        from email_triage.web.db import get_hipaa_send_counter

        conn = _make_db()
        acct_id = _seed_account(conn)
        msgs = [
            _make_message(uid="u1", rfc_id="<m-1@example.com>"),
            _make_message(uid="u2", rfc_id="<m-2@example.com>"),
        ]
        # CRITICAL: share the secrets backend across both scans. Each
        # _FakeSecrets() generates a fresh install salt on first use,
        # which would yield different msgid hashes across scans and
        # defeat dedup. In production the salt is install-stable
        # (lives in the DbSecrets store).
        secrets = _FakeSecrets()
        provider = _make_fake_provider(msgs)
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=secrets,
        )
        first = await loop.scan_recent()
        # Re-supply the same messages via a fresh provider mock.
        provider = _make_fake_provider(msgs)
        loop_2 = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=secrets,
        )
        second = await loop_2.scan_recent()
        assert first == 2
        assert second == 0  # dedup → no new counts
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 2

    async def test_missing_message_id_falls_back_to_native(self) -> None:
        from email_triage.web.db import get_hipaa_send_counter

        conn = _make_db()
        acct_id = _seed_account(conn)
        msg = _make_message(uid="provider-native-123", rfc_id=None)
        provider = _make_fake_provider([msg])
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        new = await loop.scan_recent()
        assert new == 1
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 1

    async def test_empty_recipients_skipped(self) -> None:
        from email_triage.web.db import get_hipaa_send_counter

        conn = _make_db()
        acct_id = _seed_account(conn)
        msg = _make_message(recipients=[])
        provider = _make_fake_provider([msg])
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        new = await loop.scan_recent()
        assert new == 0
        assert get_hipaa_send_counter(conn, account_id=acct_id) is None

    async def test_fetch_error_per_message_does_not_kill_scan(self) -> None:
        from email_triage.web.db import get_hipaa_send_counter

        conn = _make_db()
        acct_id = _seed_account(conn)
        good = _make_message(uid="u1", rfc_id="<m-good@example.com>")
        provider = AsyncMock()
        provider.search.return_value = ["u-bad", "u1"]

        async def _fetch(uid, folder=None):
            if uid == "u-bad":
                raise RuntimeError("transient provider error")
            return good

        provider.fetch_message.side_effect = _fetch
        loop = HipaaSentCounterLoop(
            conn, acct_id, provider=provider, secrets=_FakeSecrets(),
        )
        new = await loop.scan_recent()
        # One good message counted; bad one skipped.
        assert new == 1
        agg = get_hipaa_send_counter(conn, account_id=acct_id)
        assert agg is not None and agg["count"] == 1


# ---------------------------------------------------------------------------
#  — connection-holding-class write-lock guard
# ---------------------------------------------------------------------------

def _lock_held_by_other_thread() -> bool:
    """Return True if ``get_write_lock()`` is currently held by a thread
    OTHER than the caller.

    ``get_write_lock()`` is a reentrant ``RLock`` — the calling thread
    can always re-acquire it, so a same-thread ``acquire(blocking=False)``
    tells us nothing. To probe whether the lock is genuinely held we ask
    a SEPARATE thread to attempt a non-blocking acquire: an RLock held by
    any thread rejects a non-blocking acquire from every other thread.
    """
    import threading

    from email_triage.web.db_writelock import get_write_lock

    lock = get_write_lock()
    result: dict[str, bool] = {}

    def _probe() -> None:
        got = lock.acquire(blocking=False)
        result["held"] = not got
        if got:
            lock.release()

    t = threading.Thread(target=_probe)
    t.start()
    t.join()
    return result["held"]


class _LockProbeConn:
    """Proxy around a ``sqlite3.Connection`` that records whether the
    process-wide DB write lock is held whenever ``execute`` is called.

    ``sqlite3.Connection.execute`` is a read-only C-level slot, so it
    cannot be monkeypatched in place. The connection-holding classes
    only reach the DB through ``self._db`` — handing them this proxy as
    the connection lets the test observe every touch. Every other
    attribute / method delegates straight to the real connection.
    """

    def __init__(self, real, *, execute_match=None):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_execute_match", execute_match)
        object.__setattr__(self, "execute_observed", [])

    def execute(self, sql, *args, **kwargs):
        match = self._execute_match
        if match is not None and match(sql):
            self.execute_observed.append(_lock_held_by_other_thread())
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.mark.asyncio
class TestWriteLockHeldDuringDbTouch:
    """ — ``HipaaSentCounterLoop._account_row`` must hold the
    process-wide DB write lock for the duration of its shared-connection
    ``execute``. The  connection-holding-class ratchet enforces the
    lexical ``with get_write_lock()`` wrap; this test enforces it at
    RUNTIME — it observes the SELECT through a proxy connection and
    asserts the lock is genuinely held by the executing thread.
    """

    async def test_account_row_holds_write_lock_during_execute(self) -> None:
        conn = _make_db()
        acct_id = _seed_account(conn)
        probe = _LockProbeConn(
            conn, execute_match=lambda s: "FROM email_accounts" in s,
        )
        loop = HipaaSentCounterLoop(
            probe, acct_id, provider=_make_fake_provider([]),
            secrets=_FakeSecrets(),
        )
        # _account_row runs inside _non_hipaa_short_circuit, dispatched
        # off-loop by scan_recent via db_call.
        await loop.scan_recent()

        # The email_accounts SELECT ran at least once, and EVERY time it
        # ran the write lock was held.
        assert probe.execute_observed, "_account_row's SELECT never executed"
        assert all(probe.execute_observed), (
            "write lock was NOT held during _account_row's execute"
        )
