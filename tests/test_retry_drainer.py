"""Tests for the consolidated retry-queue drainer.

The drainer (``_watcher_retry_sweeper`` + ``_recover_one_retry_row`` in
``web/app.py``) is the single thing that re-fetches + re-triages every
parked per-message failure. Covered here:

* ``_recover_one_retry_row`` genuinely re-fetches a message and runs
  the full triage path; a terminal outcome → ``"done"``.
* An exhausted row (attempt_count at the cap) → ``mark_retry_dead``.
* A successful recovery → ``mark_retry_done``.
* The LLM-breaker gate skips ``failure_kind='llm_unreachable'`` rows
  while the breaker is open, but drains them once it is healthy.
* A deleted account → the row is marked dead.
*  — recovery that fails because the LLM backend is down returns
  the distinct ``"retry:llm_unreachable"`` verdict, and the sweeper
  re-enqueues with ``failure_kind='llm_unreachable'`` so the next
  tick's LLM-breaker gate skips the row — even when the row's ORIGINAL
  failure carried a NULL ``failure_kind``.
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from email_triage.engine.models import (
    Classification, EmailMessage,
)
from email_triage.web.db import (
    enqueue_retry, get_retry, init_db,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    c = track(init_db(":memory:"))
    yield c
    c.close()


@pytest.fixture
def account_id(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (uid, "Mailbox", "imap", "{}", now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _make_app(conn: sqlite3.Connection) -> SimpleNamespace:
    """A minimal ``app`` stand-in: only ``.state`` is touched."""
    state = SimpleNamespace(
        db=conn,
        config=SimpleNamespace(
            classifier=SimpleNamespace(backend="ollama"),
            smtp=SimpleNamespace(from_addr="triage@example.com"),
        ),
        secrets=MagicMock(),
    )
    return SimpleNamespace(state=state)


def _msg(message_id="42", **kw) -> EmailMessage:
    defaults = dict(
        message_id=message_id, provider="imap",
        sender="alice@example.com", recipients=["op@example.com"],
        subject="hello", body_text="body",
        date=datetime.now(timezone.utc),
        headers={"Message-ID": f"<{message_id}@example.com>"},
    )
    defaults.update(kw)
    return EmailMessage(**defaults)


# ---------------------------------------------------------------------------
# _recover_one_retry_row — genuine re-fetch + re-act
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recover_re_fetches_and_re_triages(
    monkeypatch, conn, account_id,
):
    """A pending IMAP retry row is re-fetched + put through the full
    triage path; a processed verdict yields ``"done"``."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod
    from email_triage.web import triage_one as t1_mod

    # Enqueue a real retry row.
    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="read timed out",
    )
    row = get_retry(conn, retry_id)

    # Fake provider — re-fetch succeeds, UIDVALIDITY matches the row.
    fake_provider = MagicMock()
    fake_provider.get_uidvalidity = AsyncMock(return_value=111)
    fake_provider.fetch_message = AsyncMock(return_value=_msg("42"))
    fake_provider.close = AsyncMock()

    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake_provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config", lambda config: MagicMock(),
    )
    monkeypatch.setattr(
        ui_mod, "_get_categories_from_db", lambda db, uid=None: {},
    )
    monkeypatch.setattr(ui_mod, "_is_dry_run", lambda db: False)
    monkeypatch.setattr(
        ui_mod, "_create_calendar_provider_from_account",
        lambda *a, **k: None,
    )

    # Stub the triage body — it owns classify+route+act; here we just
    # assert the drainer hands it the re-fetched message + reports the
    # status back as a verdict.
    triaged: dict = {}

    async def _fake_triage(ctx, message, msg_id, **kw):
        triaged["message_id"] = message.message_id
        triaged["msg_id"] = msg_id
        return SimpleNamespace(status="p", entry={})

    monkeypatch.setattr(t1_mod, "triage_single_message", _fake_triage)

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)

    assert verdict == "done"
    assert triaged["message_id"] == "42"
    assert triaged["msg_id"] == "42"
    fake_provider.fetch_message.assert_awaited_once()
    fake_provider.close.assert_awaited()


@pytest.mark.asyncio
async def test_recover_imap_empty_fetch_verifies_expunge(
    monkeypatch, conn, account_id,
):
    """Verified split (2026-06-19): an IMAP re-fetch that comes back COMPLETELY
    empty is classified by VERIFYING the UID. Confirmed-absent (uid_exists
    False) -> benign ``message_expunged``; still-present (True) or unverifiable
    (None) -> ``message_gone`` so the spike fail-safe keeps watching a real
    fetch degradation that returns empty for mail that is actually there."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod

    async def _run(uid_exists_val, expected):
        retry_id = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=42, uidvalidity=111,
            error_class="TimeoutError", error_msg="x",
        )
        row = get_retry(conn, retry_id)
        empty = _msg("42", sender="", body_text="", body_html="", headers={})
        fake = MagicMock()
        fake.get_uidvalidity = AsyncMock(return_value=111)
        fake.fetch_message = AsyncMock(return_value=empty)
        fake.uid_exists = AsyncMock(return_value=uid_exists_val)
        fake.close = AsyncMock()
        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account",
            lambda acct, secrets, **kw: fake,
        )
        app = _make_app(conn)
        verdict = await app_mod._recover_one_retry_row(app, row)
        assert verdict == expected, (uid_exists_val, verdict)
        fake.uid_exists.assert_awaited_once()

    await _run(False, "dead:message_expunged")  # confirmed gone -> benign
    await _run(True, "dead:message_gone")        # still present -> keep fail-safe
    await _run(None, "dead:message_gone")        # unverifiable -> conservative


@pytest.mark.asyncio
async def test_recover_uidvalidity_mismatch_marks_dead(
    monkeypatch, conn, account_id,
):
    """An IMAP row whose stored UIDVALIDITY no longer matches the live
    mailbox is unrecoverable — verdict ``dead:uidvalidity_changed``."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    fake_provider = MagicMock()
    fake_provider.get_uidvalidity = AsyncMock(return_value=999)  # changed
    fake_provider.close = AsyncMock()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake_provider,
    )

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "dead:uidvalidity_changed"


@pytest.mark.asyncio
async def test_recover_deleted_account_marks_dead(conn):
    """A retry row whose account was deleted is unrecoverable."""
    from email_triage.web import app as app_mod

    # An enqueue_retry needs a real account FK; insert directly with a
    # non-existent account id is blocked by the FK, so enqueue against a
    # real account then delete it.
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('a@b.c','A','user',?)", (now,),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        (uid, "M", "imap", "{}", now, now),
    )
    acct_id = int(cur.lastrowid)
    conn.commit()
    retry_id = enqueue_retry(
        conn, account_id=acct_id, provider_type="imap",
        mailbox="INBOX", uid=1, uidvalidity=1,
        error_class="E", error_msg="x",
    )
    row = get_retry(conn, retry_id)
    # Delete the account row out from under the retry row. The retry row
    # has ON DELETE CASCADE, so to keep the row for the test we read it
    # first (done above), then delete + re-test against the stale dict.
    conn.execute("DELETE FROM email_accounts WHERE id=?", (acct_id,))
    conn.commit()

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "dead:operator_abandoned"


@pytest.mark.asyncio
async def test_recover_re_triage_error_is_transient(
    monkeypatch, conn, account_id,
):
    """When the re-triage itself errors (status='e' — e.g. a FAILED
    action), the verdict is ``"retry"`` so the drainer bumps the
    attempt counter rather than dropping the row."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod
    from email_triage.web import triage_one as t1_mod

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    fake_provider = MagicMock()
    fake_provider.get_uidvalidity = AsyncMock(return_value=111)
    fake_provider.fetch_message = AsyncMock(return_value=_msg("42"))
    fake_provider.close = AsyncMock()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake_provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config", lambda config: MagicMock(),
    )
    monkeypatch.setattr(
        ui_mod, "_get_categories_from_db", lambda db, uid=None: {},
    )
    monkeypatch.setattr(ui_mod, "_is_dry_run", lambda db: False)
    monkeypatch.setattr(
        ui_mod, "_create_calendar_provider_from_account",
        lambda *a, **k: None,
    )

    async def _fake_triage(ctx, message, msg_id, **kw):
        return SimpleNamespace(status="e", entry={"error": "action failed"})

    monkeypatch.setattr(t1_mod, "triage_single_message", _fake_triage)

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "retry"


# ---------------------------------------------------------------------------
#  — the retry drainer's reads no longer collide on the shared
# connection.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_retry_drainer_reads_do_not_collide_under_concurrency(
    conn, account_id,
):
    """ — the retry drainer's reads run through ``db_call``, which
    acquires the process-wide DB lock.

    Before the fix the drainer issued bare ``asyncio.to_thread(<read
    helper>)`` calls: those run on threadpool workers WITHOUT the lock,
    so when one overlapped a ``db_call`` worker on the same
    ``sqlite3.Connection`` the sqlite3 driver raised ``InterfaceError:
    bad parameter or other API misuse``.

    This test drives the drainer's read helpers (``list_due_retries``,
    ``get_email_account``) and a ``@db_write`` writer through the real
    ``db_call`` primitive, all dispatched at once. An ``asyncio.Barrier``
    releases every coroutine into ``db_call`` together, so the
    threadpool workers genuinely contend for the shared connection.
    With the lock in place every dispatched call serialises and none
    raise.
    """
    import asyncio

    from email_triage.web.db import (
        enqueue_retry, get_email_account, list_due_retries,
    )
    from email_triage.web.db_threadpool import db_call

    # Seed a few due retry rows so list_due_retries returns work.
    for uid in range(1, 6):
        enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=uid, uidvalidity=1,
            error_class="TimeoutError", error_msg="x",
        )

    kinds = ["list", "account", "list", "account",
             "write", "list", "account", "list"]
    # An asyncio.Barrier releases every coroutine into its db_call at
    # the same moment — barrier-based rendezvous, not wall-clock timing
    # (per pattern_barrier_concurrency_test). db_call then offloads each
    # call to the threadpool, so the workers genuinely overlap.
    barrier = asyncio.Barrier(len(kinds))
    errors: list[BaseException] = []

    async def _drive(kind: str) -> None:
        await barrier.wait()
        try:
            if kind == "list":
                await db_call(list_due_retries, conn, limit=50)
            elif kind == "account":
                await db_call(get_email_account, conn, account_id)
            else:  # write — an upsert through a @db_write helper
                await db_call(
                    enqueue_retry, conn,
                    account_id=account_id, provider_type="imap",
                    mailbox="INBOX", uid=99, uidvalidity=1,
                    error_class="E", error_msg="x",
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    await asyncio.gather(*[_drive(k) for k in kinds])

    # No InterfaceError (or anything else) escaped a dispatched call.
    assert errors == [], (
        f"concurrent drainer DB calls collided: "
        f"{[type(e).__name__ + ': ' + str(e) for e in errors]}"
    )


# ---------------------------------------------------------------------------
#  — recovery hitting a dead LLM backend re-classifies the row as
# llm_unreachable so the next tick's breaker gate skips it.
# ---------------------------------------------------------------------------

def _make_row_due(conn: sqlite3.Connection, retry_id: int) -> None:
    """Backdate a retry row's ``next_attempt_at`` so the sweeper's
    ``list_due_retries`` due-filter (``next_attempt_at <= now``) returns
    it. A freshly ``enqueue_retry``'d row carries a FUTURE
    ``next_attempt_at`` (the backoff schedule pushes the first attempt
    out), so the sweeper would see no due work without this.
    """
    past = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    conn.execute(
        "UPDATE watcher_retry_queue SET next_attempt_at=? WHERE id=?",
        (past, int(retry_id)),
    )
    conn.commit()


def _patch_recover_provider(monkeypatch):
    """Monkeypatch the ui-module + triage helpers so ``_recover_one_retry_row``
    re-fetches a message without touching a real provider/classifier.

    Returns the fake provider so the caller can assert on it.
    """
    from email_triage.web.routers import ui as ui_mod

    fake_provider = MagicMock()
    fake_provider.get_uidvalidity = AsyncMock(return_value=111)
    fake_provider.fetch_message = AsyncMock(return_value=_msg("42"))
    fake_provider.close = AsyncMock()

    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake_provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config", lambda config: MagicMock(),
    )
    monkeypatch.setattr(
        ui_mod, "_get_categories_from_db", lambda db, uid=None: {},
    )
    monkeypatch.setattr(ui_mod, "_is_dry_run", lambda db: False)
    monkeypatch.setattr(
        ui_mod, "_create_calendar_provider_from_account",
        lambda *a, **k: None,
    )
    return fake_provider


@pytest.mark.asyncio
async def test_recover_llm_down_returns_llm_unreachable_verdict(
    monkeypatch, conn, account_id,
):
    """ — when the re-triage raises ``LLMBackendUnreachableError``
    (``classify`` could not reach the backend; ``triage_single_message``
    re-raises it unchanged per ), ``_recover_one_retry_row`` returns
    the distinct ``"retry:llm_unreachable"`` verdict — NOT a bare
    ``"retry"``."""
    from email_triage.web import app as app_mod
    from email_triage.web import triage_one as t1_mod
    from email_triage.llm_health import LLMBackendUnreachableError

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    _patch_recover_provider(monkeypatch)

    async def _llm_down_triage(ctx, message, msg_id, **kw):
        raise LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )

    monkeypatch.setattr(t1_mod, "triage_single_message", _llm_down_triage)

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "retry:llm_unreachable"


@pytest.mark.asyncio
async def test_recover_llm_down_subclass_returns_llm_unreachable_verdict(
    monkeypatch, conn, account_id,
):
    """A subclass of ``LLMBackendUnreachableError`` is still treated as
    LLM-down — the ``except`` clause is type-based (``isinstance``), so a
    future derived error class is not silently demoted to a bare
    ``"retry"``."""
    from email_triage.web import app as app_mod
    from email_triage.web import triage_one as t1_mod
    from email_triage.llm_health import LLMBackendUnreachableError

    class _DerivedUnreachable(LLMBackendUnreachableError):
        pass

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=43, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)
    _patch_recover_provider(monkeypatch)

    async def _llm_down_triage(ctx, message, msg_id, **kw):
        raise _DerivedUnreachable(backend="ollama", host="llm-host", port=11434)

    monkeypatch.setattr(t1_mod, "triage_single_message", _llm_down_triage)

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "retry:llm_unreachable"


@pytest.mark.asyncio
async def test_sweeper_reenqueues_llm_down_row_with_failure_kind(
    monkeypatch, conn, account_id,
):
    """ end-to-end — a retry row whose ORIGINAL failure was an
    ordinary fetch error (``failure_kind`` NULL) fails recovery because
    the LLM backend is down. The sweeper must re-enqueue it with
    ``failure_kind='llm_unreachable'`` so the next tick's breaker gate
    skips it.

    Before the fix the sweeper re-enqueued every transient failure with
    a bare ``"retry"`` verdict and no ``failure_kind`` argument — and
    ``enqueue_retry`` COALESCEs ``None`` onto the existing value, so a
    NULL-kind row stayed NULL. The breaker gate
    (``failure_kind == 'llm_unreachable'``) never engaged and the
    drainer kept re-fetching + re-classifying the row against the dead
    backend every tick.
    """
    from email_triage.web import app as app_mod
    from email_triage.web import triage_one as t1_mod
    from email_triage.llm_health import LLMBackendUnreachableError

    # An ordinary fetch failure — failure_kind is NULL.
    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="read timed out",
    )
    assert get_retry(conn, retry_id)["failure_kind"] is None
    _make_row_due(conn, retry_id)

    _patch_recover_provider(monkeypatch)

    async def _llm_down_triage(ctx, message, msg_id, **kw):
        raise LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )

    monkeypatch.setattr(t1_mod, "triage_single_message", _llm_down_triage)

    # Drive exactly one tick of the sweeper by intercepting
    # ``supervised_interval_loop`` — it normally runs ``tick`` forever;
    # here we call it once and return. ``_watcher_retry_sweeper`` imports
    # the helper function-locally from ``task_supervisor``, so the patch
    # must land on that module.
    from email_triage.web import task_supervisor as _ts_mod

    async def _run_tick_once(name, interval, tick, **kw):
        await tick()

    monkeypatch.setattr(
        _ts_mod, "supervised_interval_loop", _run_tick_once,
    )

    app = _make_app(conn)
    app.state.watcher_retry_sweep_status = None
    await app_mod._watcher_retry_sweeper(app)

    # The row was re-enqueued (still pending) with the kind upgraded so
    # the next tick's breaker gate can skip it.
    row = get_retry(conn, retry_id)
    assert row["state"] == "pending"
    assert row["failure_kind"] == "llm_unreachable"
    assert int(row["attempt_count"]) == 1
    # The sweeper status counts it as a re-enqueue, not a recovery.
    status = app.state.watcher_retry_sweep_status
    assert status is not None
    assert status["re_enqueued"] == 1
    assert status["recovered"] == 0


@pytest.mark.asyncio
async def test_sweeper_ordinary_retry_preserves_existing_failure_kind(
    monkeypatch, conn, account_id,
):
    """A plain transient failure (re-triage status ``'e'``, NOT LLM-down)
    re-enqueues with a bare ``"retry"`` verdict — ``failure_kind=None``
    is passed and ``enqueue_retry`` COALESCEs it, so a row already
    stamped ``llm_unreachable`` KEEPS that kind. The  fix upgrades
    NULL rows on an LLM-down failure without clobbering a kind on an
    ordinary retry.
    """
    from email_triage.web import app as app_mod
    from email_triage.web import triage_one as t1_mod

    # Seed a row that already carries the llm_unreachable kind.
    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=77, uidvalidity=111,
        error_class="LLMBackendUnreachableError", error_msg="x",
        failure_kind="llm_unreachable",
    )
    assert get_retry(conn, retry_id)["failure_kind"] == "llm_unreachable"
    _make_row_due(conn, retry_id)

    _patch_recover_provider(monkeypatch)

    # Re-triage errors generically (status 'e') — NOT an LLM-down raise.
    async def _err_triage(ctx, message, msg_id, **kw):
        return SimpleNamespace(status="e", entry={"error": "action failed"})

    monkeypatch.setattr(t1_mod, "triage_single_message", _err_triage)

    from email_triage.web import task_supervisor as _ts_mod

    async def _run_tick_once(name, interval, tick, **kw):
        await tick()

    monkeypatch.setattr(
        _ts_mod, "supervised_interval_loop", _run_tick_once,
    )

    app = _make_app(conn)
    app.state.watcher_retry_sweep_status = None
    # The breaker must be CLOSED (LLM healthy) or the gate would skip the
    # llm_unreachable row before recovery even runs. _make_app's config
    # backend is "ollama"; is_healthy() defaults to healthy when no
    # probe has marked it down, so the gate stays open. Assert the row
    # actually drained (re_enqueued == 1) to confirm that.
    await app_mod._watcher_retry_sweeper(app)

    row = get_retry(conn, retry_id)
    assert row["state"] == "pending"
    # The kind was NOT clobbered — a bare retry passes failure_kind=None
    # and COALESCE keeps the original.
    assert row["failure_kind"] == "llm_unreachable"
    assert app.state.watcher_retry_sweep_status["re_enqueued"] == 1


# ---------------------------------------------------------------------------
# census run15 #4 — the retry drainer routes its credentialed re-fetch outcome
# through the auth_stale lifecycle funnel (record_provider_outcome): CLEAR on a
# successful re-fetch (PD#18 clear edge), SET on an auth-revoked one (set edge),
# and NEITHER on an ordinary transient failure (the funnel needle-filters).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recover_success_clears_auth_stale_chip(
    monkeypatch, conn, account_id,
):
    """A successful re-fetch is a healthy credentialed call → the drainer must
    CLEAR any prior auth_stale re-auth chip. Before the fix it re-fetched
    without touching the chip, so a row that drained AFTER the token recovered
    left the 'Re-authenticate required' chip stuck."""
    from email_triage.web import app as app_mod
    from email_triage.web import triage_one as t1_mod
    from email_triage.web.db import get_setting, set_setting
    from email_triage.web.settings_keys import auth_stale as _auth_stale_key

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    # Pre-set the chip (a prior auth outage flagged this account).
    key = _auth_stale_key(account_id)
    set_setting(conn, key, {"at": "2026-06-21T00:00:00+00:00", "reason": "invalid_grant"})
    assert get_setting(conn, key) is not None

    _patch_recover_provider(monkeypatch)

    async def _ok_triage(ctx, message, msg_id, **kw):
        return SimpleNamespace(status="p", entry={})
    monkeypatch.setattr(t1_mod, "triage_single_message", _ok_triage)

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "done"
    assert get_setting(conn, key) is None, (
        "a successful re-fetch must CLEAR the auth_stale chip (PD#18 clear edge)"
    )


@pytest.mark.asyncio
async def test_recover_auth_revoked_fetch_sets_auth_stale_chip(
    monkeypatch, conn, account_id,
):
    """An auth-revoked re-fetch failure must SET the auth_stale chip through the
    funnel (PD#18 set edge) so a dead token on the drainer path is not
    invisible. The funnel needle-filters, so only an auth-revoked error flips
    it."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod
    from email_triage.web.db import get_setting
    from email_triage.web.settings_keys import auth_stale as _auth_stale_key

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    fake = MagicMock()
    fake.get_uidvalidity = AsyncMock(return_value=111)
    # invalid_grant is an auth-revoked needle (web/_auth_revoked.py SSOT).
    fake.fetch_message = AsyncMock(side_effect=Exception("invalid_grant"))
    fake.close = AsyncMock()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake,
    )
    monkeypatch.setattr(ui_mod, "_is_dry_run", lambda db: False)

    key = _auth_stale_key(account_id)
    assert get_setting(conn, key) is None

    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "retry"
    assert get_setting(conn, key) is not None, (
        "an auth-revoked re-fetch must SET the auth_stale chip (PD#18 set edge)"
    )


@pytest.mark.asyncio
async def test_recover_transient_fetch_does_not_set_chip(
    monkeypatch, conn, account_id,
):
    """A plain transient re-fetch failure (NOT auth-revoked) must NOT set the
    chip — the funnel needle-filters. Guards against over-flagging a healthy
    account on an ordinary network blip."""
    from email_triage.web import app as app_mod
    from email_triage.web.routers import ui as ui_mod
    from email_triage.web.db import get_setting
    from email_triage.web.settings_keys import auth_stale as _auth_stale_key

    retry_id = enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=42, uidvalidity=111,
        error_class="TimeoutError", error_msg="x",
    )
    row = get_retry(conn, retry_id)

    fake = MagicMock()
    fake.get_uidvalidity = AsyncMock(return_value=111)
    fake.fetch_message = AsyncMock(side_effect=TimeoutError("read timed out"))
    fake.close = AsyncMock()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets, **kw: fake,
    )
    monkeypatch.setattr(ui_mod, "_is_dry_run", lambda db: False)

    key = _auth_stale_key(account_id)
    app = _make_app(conn)
    verdict = await app_mod._recover_one_retry_row(app, row)
    assert verdict == "retry"
    assert get_setting(conn, key) is None, (
        "a transient (non-auth) re-fetch must NOT flag auth_stale"
    )
