"""Tests for #42 — log_entries tamper-evidence hash chain.

Includes #131 hardening tests: pruner-side anchor + chain-aware
``insert_log_entry`` + watermark cache + handler last-hash cache.
"""

import logging
from unittest.mock import patch

from email_triage.triage_logging import SQLiteLogHandler
from email_triage.web.db import (
    _AUDIT_CHAIN_ANCHOR_KEY,
    compute_log_row_hash,
    get_last_log_row_hash,
    get_setting,
    insert_log_entry,
    prune_log_entries,
    prune_log_entries_by_age_and_count,
    verify_log_chain,
)


class TestHashCompute:
    def test_deterministic(self):
        a = compute_log_row_hash("", "ts", "INFO", "log", "msg", "{}")
        b = compute_log_row_hash("", "ts", "INFO", "log", "msg", "{}")
        assert a == b

    def test_prev_hash_changes_output(self):
        a = compute_log_row_hash("", "ts", "INFO", "log", "msg", "{}")
        b = compute_log_row_hash("xx", "ts", "INFO", "log", "msg", "{}")
        assert a != b

    def test_message_change_changes_output(self):
        a = compute_log_row_hash("", "ts", "INFO", "log", "msg", "{}")
        b = compute_log_row_hash("", "ts", "INFO", "log", "MSG", "{}")
        assert a != b


class TestEmitChain:
    def test_emit_hoists_caller_extra_to_top_level(self, db):
        """The TriageLogger adapter packs caller kwargs into a single
        ``record._extra`` dict. The SQLite handler must hoist those keys
        to top-level in ``extra_json`` so the /logs pill renderer +
        Details column can see ``error``, ``account``, etc. as their
        own keys (not buried inside a stringified ``_extra``).

        Pre-fix the row's ``extra_json`` looked like
            {"_extra": "{'account': 'acct1', 'uid': '42'}"}
        (single key, stringified Python repr). Pills missed every
        priority key; Details column showed an opaque blob.

        Post-fix:
            {"account": "acct1", "uid": "42"}
        """
        import json as _json
        from email_triage.triage_logging import get_logger
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = get_logger("test.log_extra_hoist")
        # ``get_logger`` returns the TriageLogger adapter that sets
        # ``record._extra``. Wire the SQLite handler to the underlying
        # stdlib logger so emit() runs.
        std = logging.getLogger("email_triage.test.log_extra_hoist")
        std.addHandler(handler)
        std.setLevel(logging.INFO)
        try:
            log.error(
                "Watcher: message triage error",
                account="acct1", uid="42", error="boom",
            )
        finally:
            std.removeHandler(handler)
        row = db.execute(
            "SELECT extra_json FROM log_entries "
            "WHERE logger = 'email_triage.test.log_extra_hoist' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        extras = _json.loads(row["extra_json"])
        # Top-level keys (the fix). NOT nested under _extra.
        assert extras.get("account") == "acct1"
        assert extras.get("uid") == "42"
        assert extras.get("error") == "boom"
        assert "_extra" not in extras

    def test_emit_chains_rows(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.log_chain")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("first")
            log.info("second")
            log.info("third")
        finally:
            log.removeHandler(handler)
        rows = db.execute(
            "SELECT id, prev_hash, row_hash FROM log_entries "
            "WHERE logger = 'test.log_chain' ORDER BY id"
        ).fetchall()
        assert len(rows) == 3
        # Each row's prev_hash equals the previous row's row_hash.
        # First row may chain off whatever came before it in the
        # shared test DB; just check sequential linkage from here on.
        assert rows[1]["prev_hash"] == rows[0]["row_hash"]
        assert rows[2]["prev_hash"] == rows[1]["row_hash"]
        # Hashes are SHA-256 hex (64 chars).
        for r in rows:
            assert len(r["row_hash"]) == 64

    def test_get_last_log_row_hash_returns_newest(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.last_hash")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("a")
            log.info("b")
        finally:
            log.removeHandler(handler)
        last_via_helper = get_last_log_row_hash(db)
        last_row = db.execute(
            "SELECT row_hash FROM log_entries "
            "WHERE row_hash != '' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert last_via_helper == last_row["row_hash"]


class TestVerifier:
    def test_intact_chain_passes(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.intact")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(5):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        result = verify_log_chain(db)
        assert result["first_break_id"] is None
        assert result["chain_length"] >= 5

    def test_message_tamper_detected(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.tamper_msg")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("alpha")
            log.info("beta")
            log.info("gamma")
        finally:
            log.removeHandler(handler)
        # Find the middle row + tamper.
        rows = db.execute(
            "SELECT id FROM log_entries WHERE logger = 'test.tamper_msg' "
            "ORDER BY id"
        ).fetchall()
        middle_id = rows[1]["id"]
        db.execute(
            "UPDATE log_entries SET message = 'TAMPERED' WHERE id = ?",
            (middle_id,),
        )
        db.commit()
        result = verify_log_chain(db)
        assert result["first_break_id"] == middle_id
        assert "row_hash mismatch" in result["first_break_reason"]

    def test_row_deletion_detected_via_prev_hash(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.tamper_delete")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("one")
            log.info("two")
            log.info("three")
            log.info("four")
        finally:
            log.removeHandler(handler)
        rows = db.execute(
            "SELECT id FROM log_entries WHERE logger = 'test.tamper_delete' "
            "ORDER BY id"
        ).fetchall()
        # Delete the second of these four rows.
        delete_id = rows[1]["id"]
        db.execute("DELETE FROM log_entries WHERE id = ?", (delete_id,))
        db.commit()
        result = verify_log_chain(db)
        # Chain breaks because the third row's prev_hash referenced
        # the now-deleted second row.
        assert result["first_break_id"] is not None
        assert "prev_hash mismatch" in result["first_break_reason"]

    def test_prechain_rows_skipped_not_flagged(self, db):
        # Insert a row directly with empty hashes (simulates legacy /
        # pre-migration data).
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO log_entries (ts, level, logger, message, "
            "extra_json, created_at, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, '', '')",
            (ts, "INFO", "legacy", "old row", "{}", ts),
        )
        db.commit()
        result = verify_log_chain(db)
        assert result["prechain_count"] >= 1
        assert result["first_break_id"] is None


# ---------------------------------------------------------------------------
# #131 — pruner-side chain anchor
# ---------------------------------------------------------------------------

class TestPruneAnchor:
    def test_anchor_written_after_count_prune(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.anchor.count")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(20):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        # Keep only the newest 5 — drops the oldest 15+.
        deleted = prune_log_entries(db, keep=5)
        assert deleted >= 15
        anchor = get_setting(db, _AUDIT_CHAIN_ANCHOR_KEY)
        assert anchor is not None
        assert "head_id" in anchor
        assert "head_prev_hash" in anchor
        assert "anchored_at" in anchor
        # The anchored prev_hash must equal the head row's stored prev_hash.
        head = db.execute(
            "SELECT id, prev_hash FROM log_entries "
            "WHERE row_hash != '' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        assert anchor["head_id"] == head["id"]
        assert anchor["head_prev_hash"] == head["prev_hash"]

    def test_anchor_written_after_age_prune(self, db):
        # Seed fresh rows then prune by age (with 0 retention forces
        # everything older than now to be eligible — but ts is "now" so
        # we use a count-based axis to guarantee a delete).
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.anchor.age")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(15):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        deleted = prune_log_entries_by_age_and_count(
            db, retention_days=99999, max_rows=5,
        )
        assert deleted >= 10
        anchor = get_setting(db, _AUDIT_CHAIN_ANCHOR_KEY)
        assert anchor is not None
        assert anchor["head_id"] is not None

    def test_verify_after_prune_no_spurious_break(self, db):
        """The original #131 motivating bug: emit a long chain, prune
        the oldest rows, ``verify_log_chain`` must NOT report a break.
        """
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.anchor.verify")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(20):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        prune_log_entries(db, keep=5)
        result = verify_log_chain(db)
        assert result["first_break_id"] is None, result["first_break_reason"]
        assert result["chain_length"] >= 5

    def test_verify_with_no_anchor_seeds_from_empty(self, db):
        """Fresh install path: no anchor in settings, chain starts at "".
        """
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.anchor.fresh")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("first")
            log.info("second")
        finally:
            log.removeHandler(handler)
        # No prune call → no anchor written.
        anchor = get_setting(db, _AUDIT_CHAIN_ANCHOR_KEY)
        assert anchor is None
        result = verify_log_chain(db)
        assert result["first_break_id"] is None
        assert result["chain_length"] >= 2

    def test_anchor_skipped_when_prune_deletes_nothing(self, db):
        """Idempotent prune (already within bounds) doesn't churn the anchor.
        """
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.anchor.noop")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("only")
        finally:
            log.removeHandler(handler)
        deleted = prune_log_entries(db, keep=5000)
        assert deleted == 0
        anchor = get_setting(db, _AUDIT_CHAIN_ANCHOR_KEY)
        # No anchor stamped — nothing was deleted.
        assert anchor is None


# ---------------------------------------------------------------------------
# #131 — chain-aware insert_log_entry
# ---------------------------------------------------------------------------

class TestInsertLogEntryChainAware:
    def test_inserted_row_chains_to_predecessor(self, db):
        """Direct insert via the helper participates in the chain."""
        from datetime import datetime, timezone
        # Seed a chain via the handler.
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.helper.predecessor")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("seed")
        finally:
            log.removeHandler(handler)
        last_before = get_last_log_row_hash(db)
        assert last_before  # non-empty
        # Now use the helper.
        ts = datetime.now(timezone.utc).isoformat()
        insert_log_entry(db, ts=ts, level="INFO", logger="t", message="via helper")
        db.commit()
        # The newest row's prev_hash must equal last_before.
        row = db.execute(
            "SELECT prev_hash, row_hash FROM log_entries "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["prev_hash"] == last_before
        assert row["row_hash"] != ""
        assert len(row["row_hash"]) == 64

    def test_inserted_row_round_trips_through_verifier(self, db):
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        insert_log_entry(db, ts=ts, level="INFO", logger="t", message="alpha")
        insert_log_entry(db, ts=ts, level="WARNING", logger="t", message="beta",
                         extra={"k": "v"})
        insert_log_entry(db, ts=ts, level="INFO", logger="t", message="gamma")
        db.commit()
        result = verify_log_chain(db)
        assert result["first_break_id"] is None, result["first_break_reason"]
        assert result["chain_length"] >= 3


# ---------------------------------------------------------------------------
# #131 — handler last-hash cache (single SELECT for N emits)
# ---------------------------------------------------------------------------

class TestHandlerLastHashCache:
    def test_only_one_select_for_many_emits(self, db):
        """100 emits → exactly 1 call to ``get_last_log_row_hash``."""
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.handler.cache.select")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        # Patch the symbol the handler imports inside emit().
        from email_triage import triage_logging as _tl
        # The handler does `from email_triage.web.db import
        # get_last_log_row_hash` inside emit(); patch on the source.
        with patch(
            "email_triage.web.db.get_last_log_row_hash",
            wraps=get_last_log_row_hash,
        ) as spy:
            try:
                for i in range(100):
                    log.info("entry %d", i)
            finally:
                log.removeHandler(handler)
            assert spy.call_count == 1, (
                f"expected 1 SELECT for cold-cache prime, got {spy.call_count}"
            )
        # And the chain is still valid end-to-end.
        result = verify_log_chain(db)
        assert result["first_break_id"] is None

    def test_cache_resets_on_handler_error(self, db):
        """If an emit fails, the cache resets so the next emit
        re-primes from the DB."""
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.handler.cache.reset")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("first")  # primes cache
            assert handler._last_row_hash is not None
            # Force an error path.
            with patch.object(handler, "_conn") as bad_conn:
                bad_conn.execute.side_effect = RuntimeError("boom")
                # Suppress handleError side-effects (it writes to stderr).
                with patch.object(handler, "handleError"):
                    log.info("triggers error")
            assert handler._last_row_hash is None
        finally:
            log.removeHandler(handler)


# ---------------------------------------------------------------------------
# #131 — verify_log_chain watermark cache (incremental verify)
# ---------------------------------------------------------------------------

class _StateBag:
    """Tiny stand-in for FastAPI ``app.state`` — attribute setter / getter."""
    pass


class TestVerifyWatermarkCache:
    def test_first_full_then_incremental(self, db):
        """First call walks all rows; second call after 5 more emits
        walks exactly 5."""
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.verify.cache.incremental")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(20):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)

        state = _StateBag()
        first = verify_log_chain(db, app_state=state)
        assert first["first_break_id"] is None
        assert first["rows_checked"] >= 20
        assert getattr(state, "audit_chain_verified", None) is not None
        watermark_id = state.audit_chain_verified["valid_through_id"]
        assert watermark_id is not None

        # Add 5 more rows.
        log.addHandler(handler)
        try:
            for i in range(5):
                log.info("more %d", i)
        finally:
            log.removeHandler(handler)

        second = verify_log_chain(db, app_state=state)
        assert second["first_break_id"] is None
        # Only 5 rows walked this pass.
        assert second["rows_checked"] == 5
        # But chain_length still reflects the full chain.
        assert second["chain_length"] >= 25
        # Watermark advanced.
        assert state.audit_chain_verified["valid_through_id"] > watermark_id

    def test_break_invalidates_cache(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.verify.cache.break")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(10):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        state = _StateBag()
        verify_log_chain(db, app_state=state)
        assert state.audit_chain_verified is not None

        # Tamper with the LAST row so the next incremental verify
        # sees the break above the watermark.
        log.addHandler(handler)
        try:
            log.info("future")
        finally:
            log.removeHandler(handler)
        last_id = db.execute(
            "SELECT id FROM log_entries ORDER BY id DESC LIMIT 1"
        ).fetchone()["id"]
        db.execute(
            "UPDATE log_entries SET message = 'TAMPERED' WHERE id = ?",
            (last_id,),
        )
        db.commit()
        result = verify_log_chain(db, app_state=state)
        assert result["first_break_id"] == last_id
        # Cache was invalidated.
        assert state.audit_chain_verified is None

    def test_explicit_limit_bypasses_cache(self, db):
        """Cache only applies to no-arg full verify; ``limit=`` always
        re-walks from the top."""
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.verify.cache.limit")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            for i in range(10):
                log.info("entry %d", i)
        finally:
            log.removeHandler(handler)
        state = _StateBag()
        verify_log_chain(db, app_state=state)
        # Limit-bounded verify must not consume the cache shape.
        bounded = verify_log_chain(db, limit=3, app_state=state)
        assert bounded["rows_checked"] == 3
