"""N-72 topic_backscan HIPAA audit bookend — behavioural + structural pins.

Fix verified: run_topic_backscan_job now emits record_hipaa_access_event
(outcome='in_progress') BEFORE the message loop, and update_hipaa_access_event
(outcome='success'/'error') in a finally block on exit — mirroring the
triage_runner_bulk pattern (§164.312(b) compliance).

Behavioural contract (PD#14 / feedback_hipaa_actor_owner_gate):
  * A non-owner back-scan on a HIPAA account creates exactly one in_progress
    row, updated to a terminal outcome on completion.
  * An owner back-scan on a HIPAA account creates NO audit row (owner
    self-access exempt).
  * A non-owner back-scan on a non-HIPAA account creates NO audit row.

Structural (count-agnostic) pin:
  * The run_topic_backscan_job function must reference both
    record_hipaa_access_event AND update_hipaa_access_event.
  * Both must be reached via db_call (interprocedural — the PD#2 seam).
"""

from __future__ import annotations

import ast
import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from _pin_harness import SRC_ROOT as SRC, parse_module  # census run13 #4 + N-350 R31
BACKSCAN = SRC / "jobs" / "topic_backscan.py"


# ---------------------------------------------------------------------------
# Structural pin — count-agnostic interprocedural check
# ---------------------------------------------------------------------------

def test_run_topic_backscan_job_references_both_audit_emitters():
    """The run_topic_backscan_job function body must reference both
    record_hipaa_access_event and update_hipaa_access_event."""
    tree = parse_module(BACKSCAN); assert tree is not None  # N-350 R31
    fn_node = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "run_topic_backscan_job"
        ):
            fn_node = node
            break
    assert fn_node is not None, "run_topic_backscan_job not found in topic_backscan.py"

    names_used: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            names_used.add(n.id)
        elif isinstance(n, ast.Attribute):
            names_used.add(n.attr)

    assert "record_hipaa_access_event" in names_used, (
        "run_topic_backscan_job does not reference record_hipaa_access_event — "
        "the in_progress HIPAA audit row is never opened"
    )
    assert "update_hipaa_access_event" in names_used, (
        "run_topic_backscan_job does not reference update_hipaa_access_event — "
        "the in_progress audit row is never closed to a terminal outcome"
    )


def test_audit_calls_route_through_db_call():
    """Both audit emitters are called via db_call (interprocedural PD#2 seam)."""
    tree = parse_module(BACKSCAN); assert tree is not None  # N-350 R31
    fn_node = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "run_topic_backscan_job"
        ):
            fn_node = node
            break
    assert fn_node is not None

    # A db_call(record_hipaa_access_event, ...) pattern: the first
    # positional arg to db_call is the function name.
    audit_names = {"record_hipaa_access_event", "update_hipaa_access_event"}
    db_call_args_found: set[str] = set()
    for n in ast.walk(fn_node):
        if not isinstance(n, ast.Call):
            continue
        # Match: db_call(func_name, ...)
        func_name = ""
        if isinstance(n.func, ast.Name):
            func_name = n.func.id
        elif isinstance(n.func, ast.Attribute):
            func_name = n.func.attr
        if func_name != "db_call":
            continue
        # First positional arg should be the target function name
        if n.args:
            arg0 = n.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in audit_names:
                db_call_args_found.add(arg0.id)

    assert "record_hipaa_access_event" in db_call_args_found, (
        "record_hipaa_access_event is not passed to db_call — the audit write "
        "is not serialized via the async-DB write-lock (PD#2 interprocedural)"
    )
    assert "update_hipaa_access_event" in db_call_args_found, (
        "update_hipaa_access_event is not passed to db_call — the audit update "
        "is not serialized via the async-DB write-lock (PD#2 interprocedural)"
    )


# ---------------------------------------------------------------------------
# Behavioural tests — use a full init_db schema + synthetic fetcher
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user(conn: sqlite3.Connection, email: str = "owner@example.com") -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "Test Owner", "user", _now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(conn: sqlite3.Connection, *, user_id: int, hipaa: bool) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, hipaa, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Test Mailbox", "imap", "{}", int(hipaa), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_topic(conn: sqlite3.Connection, *, user_id: int) -> int:
    from email_triage.actions.topic_configs import upsert_topic, TopicConfig
    cfg = TopicConfig(
        id=0, user_id=user_id, name="Test Topic",
        details="test", topic_version=1,
    )
    result = upsert_topic(conn, cfg)
    return int(result.id)


def _seed_job(conn: sqlite3.Connection, *, account_id: int, topic_id: int,
              actor_user_id: int | None) -> str:
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan
    job_id = enqueue_topic_backscan(
        conn,
        topic_id=topic_id,
        account_id=account_id,
        actor_user_id=actor_user_id,
        window_days=30,
    )
    assert job_id is not None
    return job_id


async def _empty_fetcher():
    """Synthetic fetcher that yields no messages."""
    return
    yield  # noqa: unreachable — makes this an async generator


def _make_app(conn: sqlite3.Connection):
    """Minimal app stub with just what run_topic_backscan_job needs."""
    app = MagicMock()
    app.state.db = conn
    app.state.config = MagicMock()
    # No classifier configured — simpler path that still exercises the
    # audit bookend setup.
    app.state.config.classifier = None
    return app


@pytest.mark.asyncio
async def test_non_owner_hipaa_backscan_creates_audit_row():
    """Non-owner back-scan on a HIPAA account writes one in_progress row,
    then updates to a terminal outcome (success or error)."""
    conn = _make_db()
    owner_id = _seed_user(conn, "owner@example.com")
    actor_id = _seed_user(conn, "admin@example.com")
    acct_id = _seed_account(conn, user_id=owner_id, hipaa=True)
    topic_id = _seed_topic(conn, user_id=owner_id)

    # Seed the job row with actor = non-owner admin
    from email_triage.web.db import get_triage_job
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan

    job_id = enqueue_topic_backscan(
        conn,
        topic_id=topic_id,
        account_id=acct_id,
        actor_user_id=actor_id,
        window_days=30,
    )
    assert job_id is not None
    job_row = conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    job_row = dict(job_row)

    app = _make_app(conn)

    # Build a real classifier stub (bypass "no classifier" early exit)
    mock_classifier = MagicMock()
    app.state.config.classifier = MagicMock()

    with patch(
        "email_triage.jobs.topic_backscan._build_classifier",
        return_value=mock_classifier,
    ):
        from email_triage.jobs.topic_backscan import run_topic_backscan_job
        await run_topic_backscan_job(
            app, conn, job_row,
            fetcher_batches=_empty_fetcher(),
        )

    # Exactly one hipaa_access_events row for this account
    rows = conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id = ?", (acct_id,)
    ).fetchall()
    assert len(rows) == 1, (
        f"Expected exactly 1 hipaa_access_events row, got {len(rows)}"
    )
    row = dict(rows[0])
    assert row["operation"] == "topic_backscan"
    assert row["actor_user_id"] == actor_id
    # Outcome must be terminal (not in_progress)
    assert row["outcome"] in ("success", "error", "ok"), (
        f"Audit row still shows in_progress outcome: {row['outcome']}"
    )


@pytest.mark.asyncio
async def test_owner_hipaa_backscan_no_audit_row():
    """Owner back-scan on a HIPAA account writes NO audit row (owner
    self-access exempt per feedback_hipaa_actor_owner_gate)."""
    conn = _make_db()
    owner_id = _seed_user(conn, "owner@example.com")
    acct_id = _seed_account(conn, user_id=owner_id, hipaa=True)
    topic_id = _seed_topic(conn, user_id=owner_id)

    from email_triage.jobs.topic_backscan import enqueue_topic_backscan
    job_id = enqueue_topic_backscan(
        conn,
        topic_id=topic_id,
        account_id=acct_id,
        actor_user_id=owner_id,  # owner acting on their own account
        window_days=30,
    )
    assert job_id is not None
    job_row = dict(conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (job_id,)
    ).fetchone())

    app = _make_app(conn)
    mock_classifier = MagicMock()
    app.state.config.classifier = MagicMock()

    with patch(
        "email_triage.jobs.topic_backscan._build_classifier",
        return_value=mock_classifier,
    ):
        from email_triage.jobs.topic_backscan import run_topic_backscan_job
        await run_topic_backscan_job(
            app, conn, job_row,
            fetcher_batches=_empty_fetcher(),
        )

    rows = conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id = ?", (acct_id,)
    ).fetchall()
    assert len(rows) == 0, (
        f"Owner self-access should create NO audit row, but got {len(rows)} rows"
    )


@pytest.mark.asyncio
async def test_non_owner_non_hipaa_backscan_no_audit_row():
    """Non-owner back-scan on a NON-HIPAA account writes NO audit row."""
    conn = _make_db()
    owner_id = _seed_user(conn, "owner@example.com")
    actor_id = _seed_user(conn, "admin@example.com")
    acct_id = _seed_account(conn, user_id=owner_id, hipaa=False)
    topic_id = _seed_topic(conn, user_id=owner_id)

    from email_triage.jobs.topic_backscan import enqueue_topic_backscan
    job_id = enqueue_topic_backscan(
        conn,
        topic_id=topic_id,
        account_id=acct_id,
        actor_user_id=actor_id,
        window_days=30,
    )
    assert job_id is not None
    job_row = dict(conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (job_id,)
    ).fetchone())

    app = _make_app(conn)
    mock_classifier = MagicMock()
    app.state.config.classifier = MagicMock()

    with patch(
        "email_triage.jobs.topic_backscan._build_classifier",
        return_value=mock_classifier,
    ):
        from email_triage.jobs.topic_backscan import run_topic_backscan_job
        await run_topic_backscan_job(
            app, conn, job_row,
            fetcher_batches=_empty_fetcher(),
        )

    rows = conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id = ?", (acct_id,)
    ).fetchall()
    assert len(rows) == 0, (
        f"Non-HIPAA account should create NO audit row, but got {len(rows)} rows"
    )
