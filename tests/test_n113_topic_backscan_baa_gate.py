"""N-113 — topic_backscan HIPAA+BAA egress gate (§164.308(b)(1)).

The back-scan job re-classifies EVERY scanned message through the configured
classifier (``match_topics_for_message``). Before this fix it computed
``account_hipaa`` (for the §164.312(b) audit bookend, N-72) but had NO
``is_safe_for_hipaa`` gate — so a HIPAA-flagged account scanned with an EXTERNAL,
non-BAA'd classifier would stream PHI to that subprocessor without a BAA. The
live-path runner (``web/triage_runner.run_triage:219-255``) already gated this;
the back-scan (its own classify loop) did not.

The fix mirrors run_triage: when the account is HIPAA AND
``is_safe_for_hipaa(conn, classifier)`` is False, refuse — update the audit row
to ``blocked`` and fail the job BEFORE any message body is read. A LOCAL or
BAA'd classifier is unaffected.

NB this is the per-message PHI decision the egress funnel deliberately leaves
upstream (LLM_PHI intent is SSRF-guard-only pass-through; the BAA gate is the
SSOT — see _egress / EQM-14).
"""
from __future__ import annotations

import ast
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from _pin_harness import SRC_ROOT as SRC, parse_module  # census run15 #3 — harness SRC root; N-178a — parse_module for annotate_parents
BACKSCAN = SRC / "jobs" / "topic_backscan.py"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user(conn: sqlite3.Connection, email: str) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "T", "user", _now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(conn: sqlite3.Connection, *, user_id: int, hipaa: bool) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
        "hipaa, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Mbx", "imap", "{}", int(hipaa), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_topic(conn: sqlite3.Connection, *, user_id: int) -> int:
    from email_triage.actions.topic_configs import upsert_topic, TopicConfig
    return int(upsert_topic(conn, TopicConfig(
        id=0, user_id=user_id, name="T", details="d", topic_version=1,
    )).id)


def _job_row(conn, *, topic_id, account_id, actor_user_id):
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan
    jid = enqueue_topic_backscan(
        conn, topic_id=topic_id, account_id=account_id,
        actor_user_id=actor_user_id, window_days=30,
    )
    assert jid is not None
    return dict(conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (jid,)).fetchone()), jid


def _make_app(conn):
    app = MagicMock()
    app.state.db = conn
    app.state.config = MagicMock()
    app.state.config.classifier = MagicMock()
    return app


async def _one_message_fetcher():
    """A fetcher that WOULD yield a batch with a real-shaped message — so a
    passing test proves the gate stopped BEFORE the classify loop, not that the
    input was empty. ``headers={}`` is load-bearing (db-sme): a bare MagicMock's
    truthy `.headers` would make get_triage_header() swallow the message as
    self-origin loop-mail, so `match_topics_for_message` would be skipped for a
    REASON OTHER THAN the gate — empty headers keep the no-call assertion
    gate-dependent."""
    yield [MagicMock(rfc822_message_id="m1", subject="s", body_text="PHI body",
                     headers={})]


def _external_non_baa_classifier():
    c = MagicMock()
    c.is_local = False                       # external endpoint
    c._base_url = "https://api.openai.invalid/v1"  # not local, no BAA ack on file
    return c


@pytest.mark.asyncio
async def test_hipaa_backscan_blocked_from_non_baa_external_classifier():
    """HIPAA account + external non-BAA classifier → job FAILED (baa-blocked),
    audit row 'blocked', and match_topics_for_message NEVER called (no PHI read)."""
    conn = _make_db()
    owner = _seed_user(conn, "owner@example.com")
    actor = _seed_user(conn, "admin@example.com")  # non-owner
    acct = _seed_account(conn, user_id=owner, hipaa=True)
    topic = _seed_topic(conn, user_id=owner)
    job_row, job_id = _job_row(conn, topic_id=topic, account_id=acct, actor_user_id=actor)
    app = _make_app(conn)

    mtm = AsyncMock(return_value=[])
    with patch("email_triage.jobs.topic_backscan._build_classifier",
               return_value=_external_non_baa_classifier()), \
         patch("email_triage.jobs.topic_backscan.match_topics_for_message", new=mtm):
        from email_triage.jobs.topic_backscan import run_topic_backscan_job
        await run_topic_backscan_job(app, conn, job_row,
                                     fetcher_batches=_one_message_fetcher())

    job = dict(conn.execute("SELECT * FROM triage_jobs WHERE job_id=?", (job_id,)).fetchone())
    assert job["status"] == "failed", f"expected baa-blocked failure, got {job['status']}"
    assert "BAA" in (job["error_text"] or "") or "baa" in (job["error_text"] or "").lower()
    mtm.assert_not_called()  # PHI never reached the external classifier

    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id=?", (acct,)).fetchall()]
    assert len(rows) == 1, f"expected 1 audit row, got {len(rows)}"
    assert rows[0]["outcome"] == "blocked", (
        f"audit row must record the block, got {rows[0]['outcome']!r}")


@pytest.mark.asyncio
async def test_hipaa_backscan_allowed_for_local_classifier():
    """HIPAA account + LOCAL classifier → gate does NOT fire (the scan proceeds;
    a local classifier is the BAA carve-out). Teeth for the negative case."""
    conn = _make_db()
    owner = _seed_user(conn, "owner@example.com")
    actor = _seed_user(conn, "admin@example.com")
    acct = _seed_account(conn, user_id=owner, hipaa=True)
    topic = _seed_topic(conn, user_id=owner)
    job_row, job_id = _job_row(conn, topic_id=topic, account_id=acct, actor_user_id=actor)
    app = _make_app(conn)

    local = MagicMock()
    local.is_local = True  # local Ollama — never PHI egress

    with patch("email_triage.jobs.topic_backscan._build_classifier", return_value=local):
        from email_triage.jobs.topic_backscan import run_topic_backscan_job
        await run_topic_backscan_job(app, conn, job_row, fetcher_batches=_one_message_fetcher())

    job = dict(conn.execute("SELECT * FROM triage_jobs WHERE job_id=?", (job_id,)).fetchone())
    assert job["status"] == "done", f"local classifier must not be baa-blocked, got {job['status']}"
    # The audit row closes to a terminal non-blocked outcome.
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id=?", (acct,)).fetchall()]
    assert len(rows) == 1 and rows[0]["outcome"] != "blocked"


def _enclosing_fn_node(n):
    cur = getattr(n, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = getattr(cur, "_ph_parent", None)
    return None


def test_every_topic_match_call_site_is_baa_gated():
    """Count-agnostic INTERPROCEDURAL pin (PD#1/#2, §164.308(b)(1)): every
    function that CALLS match_topics_for_message egresses message PHI to the
    classifier, so it must route its refuse decision through the shared
    ``baa_block_status`` gate — EXCEPT a site whose classifier was already
    BAA-gated by an upstream caller (allow-listed + justified). A NEW ungated
    call site (a 4th, forgotten) turns this RED. Built on the shared _pin_harness
    (PD#6) so the walk can't drift."""
    from _pin_harness import walk_src

    GATE = "baa_block_status"
    CALL = "match_topics_for_message"
    # (relpath, fn): the classifier rode an UPSTREAM BAA gate, not an in-fn one.
    UPSTREAM_GATED = {
        ("web/triage_one.py", "_match_topics_live"):
            "gated by its CALLER triage_single_message — the §164.308(b)(1) "
            "chokepoint (baa_block_status before ctx.classifier.classify) returns "
            "a fail-closed skip BEFORE _match_topics_live is reached, for ALL 7 "
            "ingestion/runner paths",
    }
    offenders = []
    for _path, rel, tree in walk_src():
        for n in ast.walk(tree):
            is_call = isinstance(n, ast.Call) and (
                (isinstance(n.func, ast.Name) and n.func.id == CALL)
                or (isinstance(n.func, ast.Attribute) and n.func.attr == CALL)
            )
            if not is_call:
                continue
            fn = _enclosing_fn_node(n)
            if fn is None:
                continue
            names = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name)}
            if GATE in names:
                continue
            if (rel, fn.name) in UPSTREAM_GATED:
                continue
            offenders.append(f"{rel}::{fn.name}")
    assert not offenders, (
        f"match_topics_for_message call site(s) with no HIPAA+BAA gate "
        f"({GATE}) and not upstream-allow-listed: {offenders}. HIPAA-account PHI "
        "could egress to a non-BAA classifier (§164.308(b)(1)). Route the refuse "
        "decision through classify.baa_gate.baa_block_status.")


def test_triage_single_message_chokepoint_references_gate():
    """The shared per-message chokepoint ``triage_single_message`` — called by ALL
    7 ingestion/runner paths (poll/push/watcher/sweeper/bulk/run_triage) — must
    reference ``baa_block_status`` so the §164.308(b)(1) classify-egress gate
    (covering the primary classify AND the downstream topic match) can't be
    silently dropped. The gap N-113 closed: only run_triage gated at ctx-build, so
    the other 6 paths leaked a HIPAA account's PHI to a non-BAA classifier."""
    p = SRC / "web" / "triage_one.py"
    tree = parse_module(p)
    assert tree is not None, f"parse_module returned None for {p}"
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == "triage_single_message"), None)
    assert fn is not None
    names = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name)}
    assert "baa_block_status" in names, (
        "triage_single_message no longer references baa_block_status — the N-113 "
        "HIPAA+BAA classify-egress chokepoint was dropped (§164.308(b)(1)); the 6 "
        "non-run_triage ingestion paths would leak PHI to a non-BAA classifier.")


def test_baa_block_status_decision_ssot():
    """The shared gate decision: blocks ONLY a HIPAA account + external no-BAA
    classifier; passes non-HIPAA, local, and BAA-acked."""
    from email_triage.classify.baa_gate import baa_block_status, set_baa_ack
    conn = _make_db()
    _seed_user(conn, "o@e.com")  # any user (set_baa_ack needs a user_id)

    ext = _external_non_baa_classifier()  # is_local=False, api.openai.invalid
    local = MagicMock(); local.is_local = True

    assert baa_block_status(conn, ext, False) is None      # non-HIPAA account
    assert baa_block_status(conn, local, True) is None     # local classifier
    blocked = baa_block_status(conn, ext, True)            # HIPAA + external no-BAA
    assert blocked is not None and blocked["host"] == "api.openai.invalid"
    # After a BAA ack for that (backend, host) tuple → no longer blocked.
    set_baa_ack(conn, blocked["backend"], blocked["host"], user_id=1)
    assert baa_block_status(conn, ext, True) is None


@pytest.mark.asyncio
async def test_preview_details_blocked_for_hipaa_non_baa_classifier():
    """The synchronous Topic-Preview 'Test Details' twin (profile._preview_account_hits)
    must NOT egress PHI for a HIPAA account + external non-BAA classifier — it
    degrades to the no-LLM keyword pass, so match_topics_for_message is never
    called even with a keyword-matching candidate in the batch."""
    import email_triage.web.routers.ui.profile as P
    conn = _make_db()
    owner = _seed_user(conn, "owner@example.com")
    acct_id = _seed_account(conn, user_id=owner, hipaa=True)
    acct = dict(conn.execute("SELECT * FROM email_accounts WHERE id=?", (acct_id,)).fetchone())
    topic = MagicMock(id=_seed_topic(conn, user_id=owner), user_id=owner)

    request = MagicMock()
    request.app.state.db = conn
    request.app.state.secrets = None

    msg = MagicMock(headers={}, body_text="PHI body", subject="s",
                    sender="a@b", message_id="m1")

    async def _batches(*a, **k):
        yield [msg]

    mtm = AsyncMock(return_value=[])
    with patch.object(P, "get_db", return_value=conn), \
         patch.object(P, "_create_provider_from_account", return_value=MagicMock()), \
         patch.object(P, "_preview_candidate_batches", _batches), \
         patch("email_triage.actions.topic_prefilter.keyword_match", return_value=["term"]), \
         patch("email_triage.cache.topic_feedback.load_topic_sender_signals",
               new=AsyncMock(return_value={})), \
         patch("email_triage.actions.topic_matcher.match_topics_for_message", new=mtm):
        await P._preview_account_hits(
            request, acct, topic, _external_non_baa_classifier(), mode="details")

    mtm.assert_not_called()  # PHI never egressed — details degraded to keyword


@pytest.mark.asyncio
async def test_preview_details_runs_llm_for_local_classifier():
    """Teeth/control for the blocked twin: with a LOCAL classifier the gate does
    NOT fire, so the SAME keyword-matching candidate DOES reach the details LLM
    pass (match_topics_for_message called) — proving the blocked test's
    `assert_not_called` is caused by the gate, not by a candidate that never
    arrived."""
    import email_triage.web.routers.ui.profile as P
    conn = _make_db()
    owner = _seed_user(conn, "owner@example.com")
    acct_id = _seed_account(conn, user_id=owner, hipaa=True)
    acct = dict(conn.execute("SELECT * FROM email_accounts WHERE id=?", (acct_id,)).fetchone())
    topic = MagicMock(id=_seed_topic(conn, user_id=owner), user_id=owner)
    request = MagicMock()
    request.app.state.db = conn
    request.app.state.secrets = None
    msg = MagicMock(headers={}, body_text="PHI body", subject="s",
                    sender="a@b", message_id="m1")

    async def _batches(*a, **k):
        yield [msg]

    local = MagicMock(); local.is_local = True  # BAA carve-out → gate passes
    mtm = AsyncMock(return_value=[])
    with patch.object(P, "get_db", return_value=conn), \
         patch.object(P, "_create_provider_from_account", return_value=MagicMock()), \
         patch.object(P, "_preview_candidate_batches", _batches), \
         patch("email_triage.actions.topic_prefilter.keyword_match", return_value=["term"]), \
         patch("email_triage.cache.topic_feedback.load_topic_sender_signals",
               new=AsyncMock(return_value={})), \
         patch("email_triage.actions.topic_matcher.match_topics_for_message", new=mtm):
        await P._preview_account_hits(request, acct, topic, local, mode="details")

    mtm.assert_called()  # local classifier → details LLM pass ran (no block)
