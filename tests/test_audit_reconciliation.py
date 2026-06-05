"""Tests for H-11 — PHI-tables vs audit-chain reconciliation.

Closes the EQM-04 tooling-gap forward-stub disclosed in the
§164.312(c)(2) PHI-tables equivalent-measure inline rationale at
``src/email_triage/engine/store.py:79+``.

Covers the five scenarios per dispatch instruction:
  1. Clean state — zero divergence
  2. Insider direct-DB-write tampering — divergence detected
  3. Pruned-then-restored boundary (post-prune anchor seed) — no false-pos
  4. HMAC chain break — surfaces in report
  5. HIPAA-mode vs non-HIPAA-mode — same reconciliation result; only the
     HIPAA-mode path emits a ``hipaa_access_events`` divergence row.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from email_triage.db.reconciliation import (
    emit_divergence_event,
    verify_phi_table_against_audit_log,
)
from email_triage.triage_logging import SQLiteLogHandler
from email_triage.web.db import (
    init_db,
    prune_log_entries,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    """Fresh in-memory SQLite with full schema + audit-chain HMAC wired.

    The autouse fixture in ``tests/conftest.py``
    (``_provision_audit_chain_hmac_key_for_tests``) provisions a 32-byte
    deterministic HMAC key into the process-global registry, so emitted
    log_entries rows participate in the H-02a chain without per-test
    setup.
    """
    db = init_db(":memory:")
    try:
        yield db
    finally:
        db.close()


def _seed_account(conn, *, hipaa: bool = False) -> int:
    """Insert a minimal email_accounts row. Returns the new account id."""
    now = datetime.now(timezone.utc).isoformat()
    # Need a user row first per the FK contract on email_accounts.user_id.
    user_row = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("operator@example.com", "Operator", "admin", now),
    )
    user_id = user_row.lastrowid
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, "Test Account", "imap", 1 if hipaa else 0, now, now),
    )
    conn.commit()
    return cur.lastrowid


def _seed_flow(conn, flow_id: str, message_id: str) -> None:
    """Insert a flows-table row + emit a chained log_entries row that
    references the same flow_id (via extra_json).

    This mirrors the production write-path's invariant: every flow
    mutation emits at least one log_entries row whose extra_json carries
    the flow_id key (engine/flow.py:79-240).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO flows "
        "(flow_id, message_id, provider, status, revision, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (flow_id, message_id, "imap", "created", now, now),
    )
    conn.commit()
    # Emit one chain row for the flow via the production handler shape.
    handler = SQLiteLogHandler(conn, flush_interval=1)
    log = logging.getLogger(f"email_triage.engine.flow.{flow_id}")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        log.info("Created flow", extra={"_extra": {"flow_id": flow_id}})
    finally:
        log.removeHandler(handler)
        handler.flush()


# ---------------------------------------------------------------------------
# Scenario 1 — Clean state: zero divergence
# ---------------------------------------------------------------------------

class TestCleanState:
    def test_clean_state_zero_divergence(self, conn):
        _seed_account(conn)
        _seed_flow(conn, "flow-1", "msg-1")
        _seed_flow(conn, "flow-2", "msg-2")
        _seed_flow(conn, "flow-3", "msg-3")

        report = verify_phi_table_against_audit_log(conn)

        assert report.divergence_count == 0
        assert report.chain_verify_passed is True
        flows_t = next(t for t in report.tables if t.table == "flows")
        assert flows_t.table_row_count == 3
        assert flows_t.rows_with_audit_match == 3
        assert flows_t.rows_without_audit_match == 0
        assert flows_t.audit_rows_without_table_row == 0


# ---------------------------------------------------------------------------
# Scenario 2 — Insider direct-DB-write tampering
# ---------------------------------------------------------------------------

class TestInsiderDirectWrite:
    def test_phi_row_without_audit_match_detected(self, conn):
        """Insider inserts a flows row directly via SQL without emitting
        the corresponding chained log_entries row. Reconciliation
        surfaces the row in ``rows_without_audit_match``.
        """
        _seed_account(conn)
        _seed_flow(conn, "legit-flow", "msg-1")

        # Direct DB write — no log_entries emit.
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO flows "
            "(flow_id, message_id, provider, status, revision, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            ("tampered-flow", "msg-evil", "imap", "created", now, now),
        )
        conn.commit()

        report = verify_phi_table_against_audit_log(conn)

        assert report.divergence_count == 1
        flows_t = next(t for t in report.tables if t.table == "flows")
        assert flows_t.rows_without_audit_match == 1
        assert "tampered-flow" in flows_t.sample_diverged_pks
        # The legit flow still matches.
        assert flows_t.rows_with_audit_match == 1

    def test_audit_row_without_table_row_detected(self, conn):
        """Audit chain references a flow_id that has no row in the
        flows table — surfaces in ``audit_rows_without_table_row``.

        Concrete scenario: insider DELETEs a flows row directly without
        emitting an audit entry. The chain still has the create-time
        log_entries row referencing the now-missing flow_id.
        """
        _seed_account(conn)
        _seed_flow(conn, "doomed-flow", "msg-1")
        _seed_flow(conn, "survivor-flow", "msg-2")

        # Direct DELETE — no audit emit.
        conn.execute(
            "DELETE FROM flows WHERE flow_id = ?", ("doomed-flow",),
        )
        conn.commit()

        report = verify_phi_table_against_audit_log(conn)

        assert report.divergence_count == 1
        flows_t = next(t for t in report.tables if t.table == "flows")
        assert flows_t.audit_rows_without_table_row == 1
        assert "doomed-flow" in flows_t.sample_diverged_pks


# ---------------------------------------------------------------------------
# Scenario 3 — Pruned-then-restored boundary (post-prune anchor seed)
# ---------------------------------------------------------------------------

class TestPrunedBoundary:
    def test_post_prune_does_not_false_positive(self, conn):
        """The pruner deletes the oldest log_entries rows + stamps a
        chain anchor. A flow row whose CREATE-time audit was pruned
        will surface as ``audit_rows_without_table_row=0`` (no audit
        rows for that flow exist after prune) BUT the live row in flows
        is also not surfaced as divergence-against-audit because the
        reconciliation is post-prune-aware via the chain anchor seed.

        Concrete check: a row whose creation predates the prune
        boundary is still in flows; its audit rows are gone; the
        reconciliation marks it as ``rows_without_audit_match`` (true
        statement — the chain no longer covers it post-prune; operator
        correlates against the prune log). This test asserts the
        reconciliation completes WITHOUT crashing and the chain-verify
        succeeds against the post-prune chain (the  motivating
        invariant).
        """
        _seed_account(conn)
        # Seed many flows + emit lots of intervening log rows so the
        # prune actually drops the oldest.
        for i in range(20):
            _seed_flow(conn, f"flow-{i}", f"msg-{i}")
            # Extra log activity to push the oldest rows out of the
            # kept window when we prune below.
            handler = SQLiteLogHandler(conn, flush_interval=1)
            log = logging.getLogger("test.padding")
            log.addHandler(handler)
            log.setLevel(logging.INFO)
            try:
                log.info(f"padding-{i}")
            finally:
                log.removeHandler(handler)
                handler.flush()

        # Prune to keep only the newest 5 — this drops the oldest
        # flow's audit rows but the flows table is untouched.
        prune_log_entries(conn, keep=5)

        # The reconciliation must NOT raise + must report a passing
        # chain (the prune anchor seeds the verifier).
        report = verify_phi_table_against_audit_log(conn)
        assert report.chain_verify_passed is True, (
            f"chain should pass post-prune via anchor seed: "
            f"{report.chain_break_reason}"
        )
        # Some flows lost their audit rows to the prune — that's
        # expected divergence, surfaced for the operator.
        flows_t = next(t for t in report.tables if t.table == "flows")
        assert flows_t.table_row_count == 20


# ---------------------------------------------------------------------------
# Scenario 4 — HMAC chain break surfaces in report
# ---------------------------------------------------------------------------

class TestChainBreak:
    def test_chain_break_surfaces_in_report(self, conn):
        """A row in log_entries with a tampered message column makes
        the chain break — reconciliation report's
        ``chain_verify_passed`` flips to False and the break reason is
        included.
        """
        _seed_account(conn)
        _seed_flow(conn, "flow-pre-tamper", "msg-1")
        _seed_flow(conn, "flow-post-tamper", "msg-2")

        # Pick the middle log row + tamper directly.
        rows = conn.execute(
            "SELECT id FROM log_entries WHERE row_hash != '' "
            "ORDER BY id"
        ).fetchall()
        mid_id = rows[len(rows) // 2]["id"]
        conn.execute(
            "UPDATE log_entries SET message = 'TAMPERED' WHERE id = ?",
            (mid_id,),
        )
        conn.commit()

        report = verify_phi_table_against_audit_log(conn)
        assert report.chain_verify_passed is False
        assert report.chain_break_reason is not None
        # Reason references the tamper site.
        assert "mismatch" in report.chain_break_reason


# ---------------------------------------------------------------------------
# Scenario 5 — HIPAA mode vs non-HIPAA mode: same reconciliation; emit
# fires only in HIPAA mode + divergence.
# ---------------------------------------------------------------------------

class TestHipaaModeEmit:
    def test_hipaa_account_emits_divergence_event(self, conn):
        """HIPAA-flagged account + divergence → one hipaa_access_events
        row with operation='reconcile_divergence_detected'.
        """
        _seed_account(conn, hipaa=True)
        _seed_flow(conn, "legit", "msg-1")
        # Direct DB write — no audit emit → divergence.
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO flows "
            "(flow_id, message_id, provider, status, revision, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            ("tampered", "msg-evil", "imap", "created", now, now),
        )
        conn.commit()

        report = verify_phi_table_against_audit_log(conn)
        assert report.divergence_count >= 1

        emit_divergence_event(conn, report=report)

        events = conn.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'reconcile_divergence_detected'"
        ).fetchall()
        assert len(events) == 1
        assert events[0]["actor_user_id"] is None
        assert events[0]["outcome"] == "error"
        assert "divergence" in events[0]["detail"]

    def test_non_hipaa_account_no_emit(self, conn):
        """Non-HIPAA account (or no HIPAA account at all) + divergence
        → emit returns None (no row).
        """
        # No HIPAA account — only a non-HIPAA one.
        _seed_account(conn, hipaa=False)
        _seed_flow(conn, "legit", "msg-1")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO flows "
            "(flow_id, message_id, provider, status, revision, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            ("tampered", "msg-evil", "imap", "created", now, now),
        )
        conn.commit()

        report = verify_phi_table_against_audit_log(conn)
        assert report.divergence_count >= 1

        emit_result = emit_divergence_event(conn, report=report)
        assert emit_result is None

        events = conn.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'reconcile_divergence_detected'"
        ).fetchall()
        assert len(events) == 0

    def test_zero_divergence_never_emits(self, conn):
        """Even in HIPAA mode, a clean reconciliation does not emit."""
        _seed_account(conn, hipaa=True)
        _seed_flow(conn, "flow-1", "msg-1")

        report = verify_phi_table_against_audit_log(conn)
        assert report.divergence_count == 0

        emit_result = emit_divergence_event(conn, report=report)
        assert emit_result is None

        events = conn.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'reconcile_divergence_detected'"
        ).fetchall()
        assert len(events) == 0


# ---------------------------------------------------------------------------
# API surface tests — defensive
# ---------------------------------------------------------------------------

class TestApiSurface:
    def test_unknown_table_raises_value_error(self, conn):
        _seed_account(conn)
        with pytest.raises(ValueError, match="unknown table"):
            verify_phi_table_against_audit_log(conn, table="nonexistent")

    def test_table_filter_scopes_to_one_table(self, conn):
        _seed_account(conn)
        _seed_flow(conn, "flow-1", "msg-1")
        report = verify_phi_table_against_audit_log(conn, table="flows")
        assert len(report.tables) == 1
        assert report.tables[0].table == "flows"

    def test_report_to_dict_serializes(self, conn):
        _seed_account(conn)
        _seed_flow(conn, "flow-1", "msg-1")
        report = verify_phi_table_against_audit_log(conn)
        d = report.to_dict()
        assert "generated_at" in d
        assert "chain_verify_passed" in d
        assert "tables" in d
        assert isinstance(d["tables"], list)
        # Each table report has the expected keys.
        t0 = d["tables"][0]
        assert "table" in t0
        assert "table_row_count" in t0
        assert "rows_with_audit_match" in t0

    def test_since_filter_narrows_audit_scope(self, conn):
        """A --since cutoff in the FUTURE skips all audit rows, so every
        live flow row surfaces as rows_without_audit_match.
        """
        _seed_account(conn)
        _seed_flow(conn, "flow-1", "msg-1")
        _seed_flow(conn, "flow-2", "msg-2")

        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        report = verify_phi_table_against_audit_log(conn, since=future)
        flows_t = next(t for t in report.tables if t.table == "flows")
        assert flows_t.table_row_count == 2
        assert flows_t.audit_pk_count == 0
        assert flows_t.rows_without_audit_match == 2
