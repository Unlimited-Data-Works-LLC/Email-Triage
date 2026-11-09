"""Punch 593: an LLM outage must not park retry rows for hours after recovery.

Diagnosed 2026-10-10 from prod rows 693-696: an ``llm_unreachable`` failure
walked ``WATCHER_RETRY_SCHEDULE`` (30 s / 2 m / 10 m / 1 h / 6 h / 24 h) like any
other failure. The rows failed attempt 4 during the outage, so
``next_attempt_at`` became +6 h and they were triaged 5 h 20 m after the LLM
came back. The breaker is process memory with lazy TTL expiry and no "closed"
event, and a restart resets it to healthy with rows still parked hours out, so
re-arming on close cannot carry the fix alone.

The fix: an ``llm_unreachable`` failure is due after a flat
``LLM_UNREACHABLE_RETRY_DELAY`` at every count, and its bound is AGE
(``LLM_UNREACHABLE_MAX_AGE`` from ``first_seen_at``), enforced by the drainer's
cap sweep as ``dead(llm_unreachable_expired)``. Other failures keep the
schedule and the count cap. ``attempt_count`` keeps counting every failure.
"""
from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    relpath,
)
from email_triage.retry_backoff import (
    LLM_UNREACHABLE_KIND,
    LLM_UNREACHABLE_MAX_AGE,
    LLM_UNREACHABLE_RETRY_DELAY,
    WATCHER_RETRY_SCHEDULE,
    llm_unreachable_expired,
)
from email_triage.web.db import (
    enqueue_retry,
    get_retry,
    mark_retry_dead,
    resurrect_auth_revoked_retries,
)
# The drainer harness the existing drainer suite uses (fixtures + helpers).
from test_retry_drainer import (  # noqa: F401  (conn/account_id are fixtures)
    _make_app,
    _make_row_due,
    _patch_recover_provider,
    account_id,
    conn,
)

N_FAILURES = len(WATCHER_RETRY_SCHEDULE) + 3   # past the end of the schedule
SLACK = timedelta(seconds=30)


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _enqueue(conn, account_id, *, uid=4242, kind=LLM_UNREACHABLE_KIND):
    return enqueue_retry(
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=uid, uidvalidity=111,
        error_class="LLMBackendUnreachableError", error_msg="ollama unreachable",
        failure_kind=kind,
    )


def _fail_llm_unreachable(conn, account_id, n, *, uid=4242):
    rid = None
    for _ in range(n):
        rid = _enqueue(conn, account_id, uid=uid)
    return rid


def _set(conn, rid, **cols):
    sets = ", ".join(f"{k}=?" for k in cols)
    conn.execute(f"UPDATE watcher_retry_queue SET {sets} WHERE id=?",
                 (*cols.values(), rid))
    conn.commit()


async def _one_tick(monkeypatch, conn, *, breaker_open=False, triage=None):
    from email_triage.web import app as app_mod
    from email_triage.web import task_supervisor as ts_mod
    from email_triage.web import triage_one as t1_mod
    import email_triage.llm_health as health

    async def _run_once(name, interval, tick, **kw):
        await tick()

    monkeypatch.setattr(ts_mod, "supervised_interval_loop", _run_once)
    monkeypatch.setattr(health, "is_healthy", lambda backend: not breaker_open)
    if triage is not None:
        _patch_recover_provider(monkeypatch)
        monkeypatch.setattr(t1_mod, "triage_single_message", triage)
    app = _make_app(conn)
    app.state.watcher_retry_sweep_status = None
    await app_mod._watcher_retry_sweeper(app)
    return app.state.watcher_retry_sweep_status


# --- the delay --------------------------------------------------------------

def test_a_row_failing_llm_unreachable_n_times_is_due_within_the_short_step(conn, account_id):
    """THE pin from the punch row: after N llm_unreachable failures (N past the
    end of the schedule) the row is still pending, still counts every failure,
    and is due within LLM_UNREACHABLE_RETRY_DELAY, so it is drained within one
    short step of the breaker closing."""
    before = datetime.now(timezone.utc)
    rid = _fail_llm_unreachable(conn, account_id, N_FAILURES)
    row = get_retry(conn, rid)
    assert row["state"] == "pending"
    assert int(row["attempt_count"]) == N_FAILURES - 1   # first call inserts at 0
    due = _parse(row["next_attempt_at"])
    assert due <= datetime.now(timezone.utc) + LLM_UNREACHABLE_RETRY_DELAY + SLACK
    assert due >= before + LLM_UNREACHABLE_RETRY_DELAY - SLACK


@pytest.mark.parametrize("count", range(1, len(WATCHER_RETRY_SCHEDULE) + 2))
def test_every_llm_unreachable_count_gets_the_flat_delay(conn, account_id, count):
    rid = _fail_llm_unreachable(conn, account_id, count + 1)
    due = _parse(get_retry(conn, rid)["next_attempt_at"])
    assert abs(due - (datetime.now(timezone.utc) + LLM_UNREACHABLE_RETRY_DELAY)) < SLACK


def test_an_ordinary_failure_on_an_llm_unreachable_row_walks_the_schedule(conn, account_id):
    """The delay keys on THIS failure's kind: a fetch failure on a row once
    stamped llm_unreachable gets its schedule step, not a 10-minute loop."""
    rid = _fail_llm_unreachable(conn, account_id, 4)        # count 3
    rid = enqueue_retry(                                    # ordinary -> count 4
        conn, account_id=account_id, provider_type="imap",
        mailbox="INBOX", uid=4242, uidvalidity=111,
        error_class="TimeoutError", error_msg="read timed out",
    )
    row = get_retry(conn, rid)
    assert row["failure_kind"] == LLM_UNREACHABLE_KIND       # COALESCE kept the kind
    due = _parse(row["next_attempt_at"])
    assert abs(due - (datetime.now(timezone.utc) + WATCHER_RETRY_SCHEDULE[4])) < SLACK


def test_ordinary_rows_keep_the_schedule(conn, account_id):
    rid = None
    for _ in range(5):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=9, uidvalidity=111,
            error_class="TimeoutError", error_msg="read timed out",
        )
    due = _parse(get_retry(conn, rid)["next_attempt_at"])
    assert abs(due - (datetime.now(timezone.utc) + WATCHER_RETRY_SCHEDULE[4])) < SLACK


# --- the drainer: drains after recovery, bounded by age ---------------------

@pytest.mark.asyncio
async def test_after_n_llm_failures_the_drainer_recovers_the_row_once_the_llm_is_back(
    monkeypatch, conn, account_id,
):
    """Past the count cap, an llm_unreachable row is NOT killed by the count
    cap: with the breaker closed it is re-triaged and resolved."""
    from types import SimpleNamespace
    rid = _fail_llm_unreachable(conn, account_id, N_FAILURES)
    assert int(get_retry(conn, rid)["attempt_count"]) >= len(WATCHER_RETRY_SCHEDULE)
    _make_row_due(conn, rid)

    async def _ok(ctx, message, msg_id, **kw):
        return SimpleNamespace(status="p", entry={})

    status = await _one_tick(monkeypatch, conn, triage=_ok)
    row = get_retry(conn, rid)
    assert row["state"] == "done", dict(row)
    assert status["recovered"] == 1 and status["transitioned_dead"] == 0


@pytest.mark.asyncio
async def test_while_the_breaker_is_open_a_young_row_is_skipped_not_killed(
    monkeypatch, conn, account_id,
):
    rid = _fail_llm_unreachable(conn, account_id, N_FAILURES)
    _make_row_due(conn, rid)
    status = await _one_tick(monkeypatch, conn, breaker_open=True)
    assert get_retry(conn, rid)["state"] == "pending"
    assert status["skipped_llm_breaker"] == 1


@pytest.mark.asyncio
async def test_an_llm_unreachable_row_older_than_the_max_age_goes_dead(
    monkeypatch, conn, account_id,
):
    """The bound: age, not count. A low count does not save an old row, and
    the transition happens even while the breaker is open."""
    rid = _fail_llm_unreachable(conn, account_id, 2)
    old = (datetime.now(timezone.utc) - LLM_UNREACHABLE_MAX_AGE - timedelta(minutes=1))
    _set(conn, rid, first_seen_at=old.strftime("%Y-%m-%d %H:%M:%S"))
    _make_row_due(conn, rid)
    status = await _one_tick(monkeypatch, conn, breaker_open=True)
    row = get_retry(conn, rid)
    assert row["state"] == "dead"
    assert row["dead_reason"] == "llm_unreachable_expired"
    assert status["transitioned_dead"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("count,dies", [(len(WATCHER_RETRY_SCHEDULE), True),
                                        (1, False)])
async def test_an_unreadable_age_falls_back_to_the_count_cap(
    monkeypatch, conn, account_id, count, dies,
):
    rid = _fail_llm_unreachable(conn, account_id, count + 1)
    _set(conn, rid, first_seen_at="not a timestamp")
    _make_row_due(conn, rid)
    await _one_tick(monkeypatch, conn, breaker_open=True)
    row = get_retry(conn, rid)
    if dies:
        assert (row["state"], row["dead_reason"]) == ("dead", "max_attempts_exceeded")
    else:
        assert row["state"] == "pending"


@pytest.mark.asyncio
async def test_ordinary_rows_keep_the_count_cap(monkeypatch, conn, account_id):
    rid = None
    for _ in range(len(WATCHER_RETRY_SCHEDULE) + 1):
        rid = enqueue_retry(
            conn, account_id=account_id, provider_type="imap",
            mailbox="INBOX", uid=10, uidvalidity=111,
            error_class="TimeoutError", error_msg="read timed out",
        )
    _make_row_due(conn, rid)
    await _one_tick(monkeypatch, conn)
    row = get_retry(conn, rid)
    assert (row["state"], row["dead_reason"]) == ("dead", "max_attempts_exceeded")


# --- the age anchor resets with every new retry episode ---------------------

def _age_old(conn, rid):
    old = datetime.now(timezone.utc) - timedelta(days=5)
    _set(conn, rid, first_seen_at=old.strftime("%Y-%m-%d %H:%M:%S"))


def test_enqueue_resurrect_resets_first_seen_at(conn, account_id):
    rid = _enqueue(conn, account_id)
    _age_old(conn, rid)
    mark_retry_dead(conn, rid, reason="max_attempts_exceeded")
    _enqueue(conn, account_id)
    row = get_retry(conn, rid)
    assert row["state"] == "pending"
    assert llm_unreachable_expired(row["first_seen_at"]) is False


def test_auth_revoked_resurrect_resets_first_seen_at(conn, account_id):
    rid = _enqueue(conn, account_id)
    _age_old(conn, rid)
    mark_retry_dead(conn, rid, reason="auth_revoked")
    assert resurrect_auth_revoked_retries(conn, account_id) == 1
    row = get_retry(conn, rid)
    assert row["state"] == "pending"
    assert llm_unreachable_expired(row["first_seen_at"]) is False


@pytest.mark.parametrize("ts,expected", [
    ("2000-01-01 00:00:00", True),            # SQLite datetime('now') shape
    ("2000-01-01T00:00:00+00:00", True),      # ISO with offset
    ("2000-01-01T00:00:00Z", True),
    (None, None), ("", None), ("garbage", None),
])
def test_llm_unreachable_expired_reads_both_timestamp_shapes(ts, expected):
    assert llm_unreachable_expired(ts) is expected


def test_the_bound_is_the_schedules_own_span():
    assert LLM_UNREACHABLE_MAX_AGE == timedelta(hours=31, minutes=12, seconds=30)
    assert LLM_UNREACHABLE_RETRY_DELAY <= WATCHER_RETRY_SCHEDULE[2]


# --- structural pins --------------------------------------------------------
#
# INVARIANT A (route, count-agnostic over src): the watcher schedule is STEPPED
# only inside retry_backoff.py. Outside it, ``compute_next_attempt_at(<n>,
# WATCHER_RETRY_SCHEDULE)`` may only be called with the literal 0 (a fresh
# insert / resurrect); stepping by a count goes through
# ``watcher_retry_next_attempt_at``, which owns the llm_unreachable delay.
#
# INVARIANT B (PD-18 shape, count-agnostic over src): every SQL literal that
# returns a ``watcher_retry_queue`` row to ``state='pending'`` also resets
# ``first_seen_at`` — the age anchor resets on every new-episode path.
#
# SCOPE CAVEAT: A matches the schedule by the name WATCHER_RETRY_SCHEDULE; an
# alias bound to another name is not followed. B reads string literals (with
# implicit concatenation folded by the parser); SQL assembled at runtime from
# variables is not seen. Migration bodies are skipped (immutable, R56).

_SSOT = "retry_backoff.py"


#: Applied migration bodies are immutable (R56: their checksum is re-verified on
#: every boot). The v16->v30 fold steps the schedule once, at upgrade time, for
#: rows it carries over; it never runs again, so it cannot re-park a live row.
_IMMUTABLE = "web/migrations.py"


def _route_violations(tree: ast.AST, rel: str) -> list[str]:
    if rel in (_SSOT, _IMMUTABLE):
        return []
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and len(node.args) >= 2):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
        sched = node.args[1]
        sched_name = sched.id if isinstance(sched, ast.Name) else getattr(sched, "attr", None)
        if name != "compute_next_attempt_at" or sched_name != "WATCHER_RETRY_SCHEDULE":
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and first.value == 0):
            out.append(f"{rel}:{node.lineno}: steps WATCHER_RETRY_SCHEDULE outside {_SSOT}")
    return out


def _norm(sql: str) -> str:
    return " ".join(sql.lower().replace('"', "'").split())


def _set_clause(sql: str) -> str:
    """The SET clause of a normalised UPDATE (a ``WHERE state='pending'``
    guard is not a transition)."""
    _, _, rest = sql.partition(" set ")
    return rest.partition(" where ")[0]


def _pending_violations(tree: ast.AST, rel: str) -> list[str]:
    if rel == _IMMUTABLE:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = _norm(node.value)
            if "update watcher_retry_queue" not in s:
                continue
            sets = _set_clause(s).replace(" ", "")
            if "state='pending'" in sets and "first_seen_at" not in sets:
                out.append(f"{rel}:{node.lineno}: pending transition without first_seen_at reset")
    return out


def _scan(detector) -> list[str]:
    violations, scanned = [], 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        scanned += 1
        violations += detector(tree, relpath(path))
    assert scanned > 100
    return violations


def test_the_schedule_is_stepped_only_in_the_ssot():
    assert _scan(_route_violations) == []


def test_every_pending_transition_resets_the_age_anchor():
    assert _scan(_pending_violations) == []


def test_route_pin_has_teeth():
    assert_pin_has_teeth(
        lambda t: _route_violations(t, "web/db.py"),
        bad_source="nxt = compute_next_attempt_at(new_count, WATCHER_RETRY_SCHEDULE)\n",
        good_source="nxt = compute_next_attempt_at(0, WATCHER_RETRY_SCHEDULE)\n",
    )
    assert_pin_has_teeth(
        lambda t: _route_violations(t, "web/app.py"),
        bad_source="nxt = rb.compute_next_attempt_at(n + 1, rb.WATCHER_RETRY_SCHEDULE)\n",
    )


def test_pending_pin_has_teeth():
    detector = lambda t: _pending_violations(t, "web/db.py")  # noqa: E731
    assert_pin_has_teeth(
        detector,
        bad_source=('q = ("UPDATE watcher_retry_queue SET state=\'pending\', "\n'
                    '     "attempt_count=0 WHERE id=?")\n'),
        good_source=('q = ("UPDATE watcher_retry_queue SET state=\'pending\', "\n'
                     '     "attempt_count=0, first_seen_at=datetime(\'now\') WHERE id=?")\n'),
    )
    # A WHERE-clause guard is not a transition (mark_retry_done's shape).
    assert_pin_has_teeth(
        detector,
        bad_source='q = "UPDATE watcher_retry_queue SET state = \'pending\' WHERE id=?"\n',
        good_source=('q = ("UPDATE watcher_retry_queue SET state=\'done\' "\n'
                     '     "WHERE id=? AND state=\'pending\'")\n'),
    )
