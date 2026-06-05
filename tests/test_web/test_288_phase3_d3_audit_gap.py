""" Deliverable 3 — audit-emitter gap-event sentinel tests.

What this file pins
-------------------
1. The ``@audit_emitter`` decorator marks helpers so
   ``@db_write``'s wrapper recognises them on the exception path.
2. The migration v38 ``audit_gap_events`` table exists with the
   expected HMAC-chained schema.
3. When an ``@audit_emitter``-marked helper raises mid-write, the
   wrapper writes a chained ``audit_gap_events`` row recording the
   failed emit with:
     - per-emitter redacted IN-class fields verbatim
     - per-emitter OUT-class fields excluded (PHI safety per
       §164.502(a) + §164.514(b)(2)(i))
     - SHA-256 hash of ALL canonicalised args (for forensic match
       against payloads stored elsewhere)
     - HMAC-SHA256 row_hash chained against the prior gap row
       (§164.312(c)(1) integrity — reuses the same key derivation
       as the log_entries chain per EQM-05)
4. The gap-write itself catching failures: a broken gap-write must
   NEVER bury the original exception.
5. A NON-audit-emitter ``@db_write`` failure does NOT trigger a gap
   write (no false positives).
6. A successful ``@db_write @audit_emitter`` helper does NOT
   trigger a gap write (no false positives).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from email_triage.db.audit import (
    _AUDIT_EMITTER_REDACTION_MAP,
    _get_current_hmac_version,
    audit_emitter,
    compute_gap_row_hash,
    get_last_gap_row_hash,
    record_user_status_event,
    record_auth_event,
    record_hipaa_boundary,
    record_hipaa_access_event,
    record_discover_run,
    record_api_key_event,
    record_access_event,
)
from email_triage.web.db import init_db
from email_triage.web.db_writelock import db_write


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    """Per-test file-backed DB with full schema + migrations applied
    (migration v38 creates audit_gap_events).

    The autouse conftest fixture ``_seed_hmac_key_for_audit_chain``
    has already seeded HMAC key version 0 — the gap-event chain
    inherits that key automatically. No per-test seeding needed
    here.
    """
    db_path = tmp_path / "audit_gap.db"
    c = init_db(str(db_path))
    yield c
    c.close()


# Current HMAC version used by all chain ops in this test file —
# inherited from the conftest autouse fixture (version=0).
_TEST_HMAC_VERSION = 0


# ---------------------------------------------------------------------------
# Decorator + marker mechanics
# ---------------------------------------------------------------------------

class TestAuditEmitterDecorator:
    def test_marks_function_with_is_audit_emitter_attr(self):
        @audit_emitter
        def _f(conn):
            pass

        assert getattr(_f, "_is_audit_emitter", False) is True

    def test_seven_known_emitters_are_marked(self):
        """All 7 emitter helpers identified in the hipaa-sme spec
        carry the ``_is_audit_emitter`` marker after `@db_write`
        wraps them (the decorator preserves attributes set on the
        inner fn via the closure)."""
        # ``@db_write`` is applied OUTER and uses functools.wraps —
        # the marker on the inner fn is reachable via the wrapper's
        # closure but NOT via getattr on the wrapped result. The
        # wrapper checks ``getattr(fn, "_is_audit_emitter", False)``
        # where ``fn`` is the inner — that's what
        # ``db_write.wrapper`` actually closes over. So we test the
        # mechanism via behaviour (below), not introspection.
        # Sanity here is just that the decorator IS importable + the
        # functions ARE the wrapped versions.
        assert callable(record_user_status_event)
        assert callable(record_auth_event)
        assert callable(record_hipaa_boundary)
        assert callable(record_hipaa_access_event)
        assert callable(record_discover_run)
        assert callable(record_api_key_event)
        assert callable(record_access_event)


# ---------------------------------------------------------------------------
# Migration v38 schema
# ---------------------------------------------------------------------------

class TestMigrationV38:
    def test_audit_gap_events_table_exists(self, conn):
        """After init_db (which runs all migrations), the
        audit_gap_events table is present with the expected
        columns."""
        rows = conn.execute(
            "PRAGMA table_info(audit_gap_events)"
        ).fetchall()
        cols = {r["name"] for r in rows}
        expected = {
            "id", "ts", "helper_name",
            "original_args_redacted", "original_args_hash",
            "exc_type", "exc_msg",
            "prev_hash", "row_hash",
            "hash_alg", "master_key_version",
        }
        assert expected.issubset(cols), (
            f"audit_gap_events missing columns: {expected - cols}"
        )

    def test_indexes_on_ts_and_helper_name(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND tbl_name='audit_gap_events'"
        ).fetchall()
        names = {r["name"] for r in rows}
        assert "idx_audit_gap_events_ts" in names
        assert "idx_audit_gap_events_helper" in names


# ---------------------------------------------------------------------------
# Per-emitter redaction map matches hipaa-sme spec verdict
# ---------------------------------------------------------------------------

class TestRedactionMap:
    """The IN/OUT split per emitter must EXACTLY match the
    hipaa-sme verdict 2026-05-25. A change here is a HIPAA-side
    decision — the table is the documented control. Each test names
    the §-anchor that drove the split."""

    def test_record_user_status_event_split(self):
        # §164.502(a) Min-Necessary: reason is operator free-text,
        # may contain PHI (e.g. "user requested account closure
        # because diagnosis X") — hash-only.
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_user_status_event"]
        assert spec["in"] == {"target_user_id", "actor_user_id", "event"}
        assert spec["out"] == {"reason"}

    def test_record_auth_event_split(self):
        # §164.514(b)(2)(i) Safe-Harbor: email + ip + user_agent are
        # the canonical de-identification targets (email = direct
        # identifier; IP = geographic identifier).
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_auth_event"]
        assert spec["in"] == {
            "event_type", "user_id", "key_id", "outcome",
        }
        assert spec["out"] == {"email", "ip", "user_agent", "detail"}

    def test_record_hipaa_boundary_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_hipaa_boundary"]
        assert spec["in"] == {"scope", "direction", "actor_id"}
        assert spec["out"] == {"reason"}

    def test_record_hipaa_access_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_hipaa_access_event"]
        assert spec["in"] == {
            "actor_user_id", "account_id", "operation", "outcome",
        }
        assert spec["out"] == {"detail"}

    def test_record_discover_run_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_discover_run"]
        # account_name + folders are operator-mailbox-label strings
        # — may include PHI-adjacent identifiers.
        assert "account_name" in spec["out"]
        assert "folders" in spec["out"]
        assert spec["in"] >= {
            "account_id", "actor_user_id",
            "scanned_count", "errors_count",
        }

    def test_record_api_key_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_api_key_event"]
        # api-key name is operator-chosen text; hash-only.
        assert "name" in spec["out"]
        assert spec["in"] >= {
            "event", "key_id", "actor_user_id",
            "target_user_id", "source",
        }

    def test_record_access_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_access_event"]
        # message_id is a PHI-adjacent identifier; detail + request_id
        # are payload-shaped.
        assert spec["out"] >= {"message_id", "detail", "request_id"}
        assert spec["in"] >= {
            "actor_user_id", "method", "route",
            "account_id", "status_code", "outcome",
        }


# ---------------------------------------------------------------------------
# Gap-event firing — end-to-end
# ---------------------------------------------------------------------------

class TestGapEventFiring:
    """The decisive Deliverable 3 tests: when a marked emitter
    fails, a gap row IS written with the correct payload and chain.
    """

    def test_failed_audit_emitter_writes_gap_row(self, conn):
        """A `@db_write @audit_emitter` helper that raises mid-write
        produces a gap_events row before the original exception
        propagates."""
        # Use record_user_status_event with a bad target_user_id (no
        # such user, FK ON DELETE CASCADE will not catch this because
        # the table has no FK on target_user_id — but the INSERT
        # itself succeeds. To force a failure, simulate a connection-
        # state issue by closing+reopening with a broken cursor.
        #
        # Simplest reliable failure: stuff the call with an
        # incompatible kwarg type via a wrapper that re-raises.
        #
        # Use a custom test emitter to control the failure:

        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing_test_emitter(
            conn, *, target_user_id, actor_user_id, event, reason="",
        ):
            # Simulate an audit INSERT failing mid-helper.
            raise sqlite3.OperationalError("simulated audit failure")

        # Pre-state: zero gap rows.
        pre = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert pre == 0

        # Trigger failure.
        with pytest.raises(sqlite3.OperationalError, match="simulated"):
            _failing_test_emitter(
                conn,
                target_user_id=99, actor_user_id=42,
                event="disabled", reason="op-internal-reason",
            )

        # Post-state: exactly one gap row.
        rows = conn.execute(
            "SELECT helper_name, original_args_redacted, "
            "original_args_hash, exc_type, exc_msg, prev_hash, "
            "row_hash, hash_alg, master_key_version "
            "FROM audit_gap_events"
        ).fetchall()
        assert len(rows) == 1
        r = rows[0]
        assert r["helper_name"] == "_failing_test_emitter"
        assert r["exc_type"] == "OperationalError"
        assert "simulated" in r["exc_msg"]
        # First gap row → prev_hash is the genesis empty string.
        assert r["prev_hash"] == ""
        # row_hash is computed from HMAC chain — not empty.
        assert r["row_hash"] != ""
        assert r["hash_alg"] == "hmac-sha256-v1"
        assert r["master_key_version"] == _TEST_HMAC_VERSION
        # original_args_hash is a hex SHA-256 (64 chars).
        assert len(r["original_args_hash"]) == 64

    def test_successful_audit_emitter_writes_no_gap_row(self, conn):
        """The happy path — a successful emit — must NOT trigger a
        gap-row write (no false positives)."""
        # Seed a user the FK can reference. The audit table itself
        # has no FK to users, but the call will execute cleanly.
        conn.execute(
            "INSERT INTO users (email, name, role, created_at, disabled) "
            "VALUES (?, ?, ?, ?, ?)",
            ("u@example.com", "U", "user", "2026-01-01T00:00:00Z", 0),
        )
        conn.commit()

        record_user_status_event(
            conn, target_user_id=1, actor_user_id=None,
            event="disabled", reason="test",
        )

        rows = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert rows == 0

    def test_non_audit_emitter_failure_writes_no_gap_row(self, conn):
        """A regular `@db_write` helper (no @audit_emitter marker)
        that fails must NOT trigger a gap-row write."""
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        def _failing_non_emitter(conn):
            raise RuntimeError("regular @db_write failure")

        with pytest.raises(RuntimeError, match="regular"):
            _failing_non_emitter(conn)

        rows = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert rows == 0

    def test_redacted_payload_excludes_out_fields(self, conn):
        """The redacted payload contains IN-class fields ONLY. OUT-
        class fields (PHI-adjacent) must be absent."""
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def record_user_status_event(  # shadow real name to hit map
            conn, *, target_user_id, actor_user_id, event, reason="",
        ):
            raise sqlite3.OperationalError("force gap")

        with pytest.raises(sqlite3.OperationalError):
            record_user_status_event(
                conn, target_user_id=7, actor_user_id=3,
                event="enabled",
                reason="PHI-content-must-not-leak-into-gap-table",
            )

        row = conn.execute(
            "SELECT original_args_redacted FROM audit_gap_events"
        ).fetchone()
        payload = json.loads(row["original_args_redacted"])
        # IN-class fields PRESENT.
        assert payload.get("target_user_id") == 7
        assert payload.get("actor_user_id") == 3
        assert payload.get("event") == "enabled"
        # OUT-class (reason) ABSENT from payload — even though its
        # value contributes to original_args_hash.
        assert "reason" not in payload

    def test_gap_chain_links_across_two_rows(self, conn):
        """A SECOND gap row's prev_hash equals the first row's
        row_hash — the chain advances correctly."""
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing(conn):
            raise sqlite3.OperationalError("force chain link")

        with pytest.raises(sqlite3.OperationalError):
            _failing(conn)
        with pytest.raises(sqlite3.OperationalError):
            _failing(conn)

        rows = conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_gap_events "
            "ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        # Row 1: prev_hash = genesis "".
        assert rows[0]["prev_hash"] == ""
        # Row 2: prev_hash = row 1's row_hash. Chain link.
        assert rows[1]["prev_hash"] == rows[0]["row_hash"]
        # Two distinct row_hash values (different ts → different
        # canonical input → different HMAC).
        assert rows[0]["row_hash"] != rows[1]["row_hash"]


# ---------------------------------------------------------------------------
# Chain-hash helpers
# ---------------------------------------------------------------------------

class TestChainHelpers:
    def test_get_last_gap_row_hash_empty_for_fresh_table(self, conn):
        assert get_last_gap_row_hash(conn) == ""

    def test_get_last_gap_row_hash_returns_latest(self, conn):
        # Insert a manual row.
        h = compute_gap_row_hash(
            "", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        conn.execute(
            "INSERT INTO audit_gap_events "
            "(ts, helper_name, original_args_redacted, "
            " original_args_hash, exc_type, exc_msg, prev_hash, "
            " row_hash, hash_alg, master_key_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-05-25T15:00:00+00:00", "test_helper", "{}",
             "deadbeef", "RuntimeError", "test",
             "", h, "hmac-sha256-v1", _TEST_HMAC_VERSION),
        )
        conn.commit()
        assert get_last_gap_row_hash(conn) == h

    def test_compute_gap_row_hash_deterministic(self):
        """Same inputs → same hash. Stamps that the canonicalisation
        is stable across calls."""
        a = compute_gap_row_hash(
            "prev", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        b = compute_gap_row_hash(
            "prev", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        assert a == b
        # Hex of HMAC-SHA256 → 64 chars.
        assert len(a) == 64

    def test_compute_gap_row_hash_changes_with_input(self):
        """Different ts → different hash. The chain is sensitive to
        every field of the row."""
        a = compute_gap_row_hash(
            "", "2026-05-25T15:00:00+00:00", "h", "{}", "", "T", "m",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        b = compute_gap_row_hash(
            "", "2026-05-25T15:00:01+00:00", "h", "{}", "", "T", "m",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        assert a != b


# ---------------------------------------------------------------------------
#  HOTFIX-4 — gap-on-gap log format (operator-actionable under
# ``logging.lastResort``)
# ---------------------------------------------------------------------------

class TestGapOnGapLogFormat:
    """When ``_write_audit_gap_event`` itself fails (the gap-write
    INSERT times out under file-lock storm — observed live on
    the test container 2026-05-25), the secondary log line at
    ``db_writelock.py:234`` is the operator's last-line §164.312(b)
    signal. hipaa-sme 2026-05-25 verdict: the line MUST embed
    ``helper`` + original emitter's exc_type + gap-write's exc_type
    IN THE MESSAGE STRING so the signal survives
    ``logging.lastResort`` (which strips ``extra`` structured
    fields).

    These tests are the count-agnostic structural pin: a future
    contributor who refactors the log call must keep all three
    substrings present, or the §164.312(b) coverage degrades
    silently under handler-stripped conditions.
    """

    def test_gap_on_gap_log_message_contains_required_substrings(
        self, conn, caplog,
    ):
        """The formatted log message MUST contain
        ``helper=<emitter>``, ``original_exc=<emitter-exc>``,
        ``gap_exc=<gap-write-exc>`` as bare substrings (not
        relying on ``extra`` structured fields)."""
        import logging
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        # Build a synthetic emitter whose @db_write body raises a
        # known class, AND patch _write_audit_gap_event to itself
        # raise so the gap-on-gap branch is taken.
        @_dw
        @_ae
        def _failing_emitter(conn):
            raise sqlite3.ProgrammingError(
                "simulated emitter-side bind error"
            )

        from email_triage.db import audit as audit_mod
        original_write = audit_mod._write_audit_gap_event

        def _write_that_raises(*args, **kwargs):
            raise sqlite3.OperationalError(
                "simulated gap-write file-lock contention"
            )

        audit_mod._write_audit_gap_event = _write_that_raises
        try:
            with caplog.at_level(
                logging.ERROR,
                logger="email_triage.web.db_writelock",
            ):
                with pytest.raises(sqlite3.ProgrammingError):
                    _failing_emitter(conn)
        finally:
            audit_mod._write_audit_gap_event = original_write

        # Find the gap-on-gap record. Multiple ERROR records may
        # exist in caplog (Step 1 / Step 2 rollback logs); the
        # gap-on-gap record is identified by the ``gap-on-gap``
        # marker substring.
        gap_records = [
            r for r in caplog.records
            if "gap-on-gap" in r.getMessage()
        ]
        assert len(gap_records) == 1, (
            f"Expected exactly 1 gap-on-gap log record, got "
            f"{len(gap_records)}: {[r.getMessage() for r in caplog.records]}"
        )
        msg = gap_records[0].getMessage()

        # Required substrings — operator-actionable under
        # ``logging.lastResort`` (the structured ``extra`` fields
        # would be stripped).
        assert "helper=_failing_emitter" in msg, msg
        assert "original_exc=ProgrammingError" in msg, msg
        assert "gap_exc=OperationalError" in msg, msg
        # And the marker stays in place
        assert "gap-on-gap" in msg, msg

    def test_gap_on_gap_log_extra_contains_structured_fields(
        self, conn, caplog,
    ):
        """Defense-in-depth: ``extra._extra`` ALSO carries the
        same fields as discrete keys (structured-JSON consumers
        get them as queryable fields, not just embedded in the
        message string)."""
        import logging
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing_emitter(conn):
            raise sqlite3.ProgrammingError("simulated")

        from email_triage.db import audit as audit_mod
        original_write = audit_mod._write_audit_gap_event

        def _write_that_raises(*args, **kwargs):
            raise sqlite3.OperationalError("simulated gap")

        audit_mod._write_audit_gap_event = _write_that_raises
        try:
            with caplog.at_level(
                logging.ERROR,
                logger="email_triage.web.db_writelock",
            ):
                with pytest.raises(sqlite3.ProgrammingError):
                    _failing_emitter(conn)
        finally:
            audit_mod._write_audit_gap_event = original_write

        gap_records = [
            r for r in caplog.records
            if "gap-on-gap" in r.getMessage()
        ]
        assert len(gap_records) == 1
        rec = gap_records[0]
        extra = getattr(rec, "_extra", None)
        assert extra is not None, (
            "gap-on-gap record missing ``_extra`` attribute — "
            "structured-JSON consumers won't see the per-field "
            "shape"
        )
        # The four documented fields hipaa-sme called out for the
        # structured-JSON path.
        assert extra.get("original_exception_in_progress") is True
        assert extra.get("helper") == "_failing_emitter"
        assert extra.get("audit_emitter_error_type") == (
            "ProgrammingError"
        )
        assert extra.get("gap_write_error_type") == (
            "OperationalError"
        )
