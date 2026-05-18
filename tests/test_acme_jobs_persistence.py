"""Tests for the DB-backed ACME job-state path (#103 + #104).

Covers:
* Migration #6 creates the ``acme_jobs`` table with the expected
  schema + index.
* Public API of ``acme_job_state`` round-trips a job through every
  phase via the persisted row when a DB handle is bound.
* ``find_resumable`` + ``adopt_persisted`` + ``resume_on_startup``
  recover non-terminal rows on a simulated restart.
* ``request_cancel`` + ``is_cancel_requested`` flip the row,
  including idempotency on already-cancelled / already-terminal
  rows.
* ``cancelled`` phase is terminal in PHASES + TERMINAL_PHASES.
"""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from email_triage.web import acme_job_state
from email_triage.web.db import init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    conn = init_db(str(tmp_path / "acme_jobs_test.db"))
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def isolate_state(db):
    """Bind the singleton to the test DB and reset between tests."""
    acme_job_state.set_db_handle(db)
    acme_job_state.reset()
    yield
    acme_job_state.reset()
    acme_job_state.set_db_handle(None)


# ---------------------------------------------------------------------------
# Migration shape
# ---------------------------------------------------------------------------

def test_migration_creates_acme_jobs_table(db):
    cols = {
        r["name"]: r["type"]
        for r in db.execute("PRAGMA table_info(acme_jobs)").fetchall()
    }
    expected = {
        "job_id", "actor_user_id", "domains_json", "directory_url",
        "order_url", "phase", "attempt", "max_attempts",
        "visibility_json", "last_error", "last_error_kind",
        "cancel_requested", "started_at", "last_progress_at",
        "ended_at", "created_at",
    }
    missing = expected - set(cols)
    assert not missing, f"missing columns: {missing}"
    # Idempotency: running run_migrations again is a no-op.
    from email_triage.web.migrations import run_migrations
    again = run_migrations(db)
    assert again == []


def test_migration_creates_phase_index(db):
    rows = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='index' AND tbl_name='acme_jobs'"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert "idx_acme_jobs_phase" in names


# ---------------------------------------------------------------------------
# Round-trip through the lifecycle
# ---------------------------------------------------------------------------

def test_start_inserts_row_with_starting_phase(db):
    job_id = acme_job_state.start(
        domains=["a.example.com", "b.example.com"],
        directory_url="https://acme-staging/",
        max_attempts=3,
        actor_user_id=42,
    )
    assert job_id and job_id.startswith("acme_")
    row = db.execute(
        "SELECT * FROM acme_jobs WHERE job_id = ?", (job_id,),
    ).fetchone()
    assert row is not None
    assert row["phase"] == "starting"
    assert row["actor_user_id"] == 42
    assert row["max_attempts"] == 3
    assert row["cancel_requested"] == 0
    assert json.loads(row["domains_json"]) == [
        "a.example.com", "b.example.com",
    ]
    assert row["started_at"] is not None
    assert row["ended_at"] is None


def test_phase_transitions_persist(db):
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    for phase in (
        "publishing", "polling_local", "polling_authoritative",
        "grace", "answering", "finalizing",
    ):
        acme_job_state.transition(phase, attempt=1)
        row = db.execute(
            "SELECT phase FROM acme_jobs WHERE job_id = ?", (job_id,),
        ).fetchone()
        assert row["phase"] == phase, f"persisted phase != {phase}"


def test_visibility_persists_as_json(db):
    job_id = acme_job_state.start(
        domains=["a.test", "b.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.visibility("a.test", local=True, authoritative=True)
    row = db.execute(
        "SELECT visibility_json FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    vis = json.loads(row["visibility_json"])
    assert vis["a.test"]["local"] is True
    assert vis["a.test"]["authoritative"] is True


def test_finish_success_marks_done_and_ended_at(db):
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("finalizing")
    acme_job_state.finish_success({"subject_cn": "x.test"})
    row = db.execute(
        "SELECT phase, ended_at, last_error FROM acme_jobs "
        "WHERE job_id = ?", (job_id,),
    ).fetchone()
    assert row["phase"] == "done"
    assert row["ended_at"] is not None
    assert row["last_error"] is None


def test_finish_failure_with_cancelled_kind_writes_cancelled_phase(db):
    """Cancellation is a flavoured failure: the worker calls
    finish_failure(..., kind='cancelled') and the row lands on the
    'cancelled' terminal phase rather than 'failed'."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("publishing", attempt=1)
    acme_job_state.finish_failure(
        "operator cancelled before attempt 1/3", kind="cancelled",
    )
    row = db.execute(
        "SELECT phase, last_error_kind, ended_at FROM acme_jobs "
        "WHERE job_id = ?", (job_id,),
    ).fetchone()
    assert row["phase"] == "cancelled"
    assert row["last_error_kind"] == "cancelled"
    assert row["ended_at"] is not None


def test_cancelled_is_terminal_phase():
    assert "cancelled" in acme_job_state.PHASES
    assert "cancelled" in acme_job_state.TERMINAL_PHASES


# ---------------------------------------------------------------------------
# Cancel request flow (#103)
# ---------------------------------------------------------------------------

def test_request_cancel_flips_flag(db):
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition("polling_local")
    flipped = acme_job_state.request_cancel()
    assert flipped is True
    row = db.execute(
        "SELECT cancel_requested FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["cancel_requested"] == 1
    assert acme_job_state.is_cancel_requested() is True


def test_cancel_on_terminal_job_is_noop(db):
    """Idempotency: cancelling an already-cancelled or already-done
    job is a no-op (returns False)."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("publishing", attempt=1)
    acme_job_state.finish_failure(
        "operator cancelled", kind="cancelled",
    )
    flipped = acme_job_state.request_cancel(job_id)
    assert flipped is False  # already terminal


def test_cancel_double_call_is_noop(db):
    """A second cancel click on a still-running job updates the
    DB column to 1 (already 1) and the function returns True the
    first time, False after the worker reaches the terminal phase."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("publishing", attempt=1)
    first = acme_job_state.request_cancel(job_id)
    assert first is True
    # Worker hasn't transitioned yet -- still in_flight, second
    # call still returns True (flag already set; no-op write).
    second = acme_job_state.request_cancel(job_id)
    assert second is True


# ---------------------------------------------------------------------------
# Resume on startup (#104)
# ---------------------------------------------------------------------------

def test_resume_on_empty_db_is_noop(db):
    resolved = acme_job_state.resume_on_startup()
    assert resolved == []


def test_resume_marks_pre_le_kill_as_cancelled(db):
    """Case 1 of the resume policy: ``order_url`` is NULL, the
    worker hadn't reached LE yet. Mark cancelled with the
    'restart_no_order' kind so the operator sees why."""
    acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition("publishing", attempt=1)
    snap = acme_job_state.current_state()
    job_id = snap["job_id"]
    # Simulate process death: clear the in-RAM mirror so the next
    # run starts fresh, leaving only the DB row.
    acme_job_state.reset()
    resolved = acme_job_state.resume_on_startup()
    assert len(resolved) == 1
    assert resolved[0]["phase"] == "cancelled"
    row = db.execute(
        "SELECT phase, last_error_kind FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["phase"] == "cancelled"
    assert row["last_error_kind"] == "restart_no_order"


def test_resume_marks_recent_order_as_resume_pending(db):
    """Case 2: order_url set, recent. Stamp 'retrying' phase +
    'resume_pending' kind for the supervised worker to pick up."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition(
        "publishing", attempt=1, order_url="https://le/order/abc",
    )
    acme_job_state.reset()
    resolved = acme_job_state.resume_on_startup()
    assert len(resolved) == 1
    assert resolved[0]["phase"] == "retrying"
    row = db.execute(
        "SELECT last_error_kind FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["last_error_kind"] == "resume_pending"


def test_resume_marks_stale_order_as_cancelled(db):
    """Case 3: order_url set but older than the max-age window.
    LE orders age out within 7 days; mark cancelled with a
    'stale_order' kind so the operator decides whether to retry."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition(
        "publishing", attempt=1, order_url="https://le/order/old",
    )
    # Wind started_at backwards by faking the row.
    db.execute(
        "UPDATE acme_jobs SET started_at = ? WHERE job_id = ?",
        ("1970-01-01T00:00:00+00:00", job_id),
    )
    db.commit()
    acme_job_state.reset()
    resolved = acme_job_state.resume_on_startup(max_age_secs=60)
    assert len(resolved) == 1
    assert resolved[0]["phase"] == "cancelled"
    row = db.execute(
        "SELECT last_error_kind FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["last_error_kind"] == "stale_order"


def test_resume_honours_pre_kill_cancel_request(db):
    """If the operator clicked Cancel before the kill, the
    cancel_requested flag is on the row -- resume must honour it
    even if the order_url is set + recent."""
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition(
        "publishing", attempt=1, order_url="https://le/order/x",
    )
    acme_job_state.request_cancel()
    acme_job_state.reset()
    resolved = acme_job_state.resume_on_startup()
    assert len(resolved) == 1
    assert resolved[0]["phase"] == "cancelled"
    row = db.execute(
        "SELECT last_error_kind FROM acme_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()
    assert row["last_error_kind"] == "cancelled"


def test_adopt_persisted_loads_into_ram(db):
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition(
        "polling_local", attempt=1, order_url="https://le/order/x",
    )
    acme_job_state.reset()
    assert acme_job_state.current_state()["job_id"] is None
    ok = acme_job_state.adopt_persisted(job_id)
    assert ok is True
    snap = acme_job_state.current_state()
    assert snap["job_id"] == job_id
    assert snap["phase"] == "polling_local"
    assert snap["domains"] == ["x.test"]


def test_list_recent_returns_history(db):
    """list_recent returns rows newest-first for the recent-jobs
    surface (#104 spec: last 10 on /admin/tls)."""
    j1 = acme_job_state.start(
        domains=["a.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.finish_success({"subject_cn": "a.test"})
    acme_job_state.reset()
    time.sleep(0.01)
    j2 = acme_job_state.start(
        domains=["b.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.finish_failure("nope", kind="validation")
    rows = acme_job_state.list_recent(limit=10)
    assert len(rows) == 2
    ids = [r["job_id"] for r in rows]
    assert j2 in ids and j1 in ids


# ---------------------------------------------------------------------------
# RAM-only fallback path (binding absent)
# ---------------------------------------------------------------------------

def test_ram_only_fallback_when_db_unbound(db):
    """When set_db_handle(None) is called, the public API still
    works against the in-RAM mirror -- backward compat with the
    pre-#104 tests + the off-home / startup-error case."""
    acme_job_state.set_db_handle(None)
    job_id = acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.transition("publishing", attempt=1)
    snap = acme_job_state.current_state()
    assert snap["phase"] == "publishing"
    assert snap["job_id"] == job_id
    # No row was written.
    row = db.execute(
        "SELECT 1 FROM acme_jobs WHERE job_id = ?", (job_id,),
    ).fetchone()
    assert row is None
