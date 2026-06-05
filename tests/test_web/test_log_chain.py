"""Tests for  — log_entries tamper-evidence hash chain.

Includes  hardening tests: pruner-side anchor + chain-aware
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
#  — pruner-side chain anchor
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
        """The original  motivating bug: emit a long chain, prune
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
#  — chain-aware insert_log_entry
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
#  — handler last-hash cache (single SELECT for N emits)
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
#  — verify_log_chain watermark cache (incremental verify)
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


# ---------------------------------------------------------------------------
# H-02a (Cycle 6, 2026-05-23) — HMAC-SHA256 migration tests
# ---------------------------------------------------------------------------
#
# These tests validate the new keyed-HMAC chain primitive + the R1-plumbing-IN
# rotation preservation per hipaa-sme-2 + DA-3 verdicts. The autouse
# fixture in tests/conftest.py provisions a deterministic HMAC key for
# every test; tests that specifically need to verify D1-fail-closed
# behavior call _clear_hmac_keys_for_test() inside the test body.

import pytest

from email_triage.db.audit import (
    _clear_hmac_keys_for_test,
    _compute_log_row_hash_sha256,
    _set_hmac_key_for_test,
)
from email_triage.secrets import (
    DbSecrets,
    derive_audit_chain_hmac_key,
    enforce_master_key_at_rest_for_hipaa,
    wire_audit_chain_hmac_keys,
)


class _MockConfig:
    """Minimal config shim for the helper signatures."""
    class secrets:
        backend = "container"
        keyfile_path = None
        master_key_name = "ET_MASTER_KEY"


class TestH02aHmacChainEndToEnd:
    """HMAC chain end-to-end: insert + verify under the autouse test key."""

    def test_hmac_chain_inserts_and_verifies(self, db):
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "m1")
        insert_log_entry(db, "2026-05-23T00:00:01Z", "INFO", "t", "m2")
        insert_log_entry(db, "2026-05-23T00:00:02Z", "INFO", "t", "m3")
        db.commit()
        v = verify_log_chain(db)
        assert v["chain_length"] == 3
        assert v["hmac_chain_length"] == 3
        assert v["legacy_chain_length"] == 0
        assert v["first_break_id"] is None

    def test_hmac_rows_carry_hash_alg_and_master_key_version(self, db):
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "m1")
        db.commit()
        row = db.execute(
            "SELECT hash_alg, master_key_version FROM log_entries LIMIT 1"
        ).fetchone()
        assert row["hash_alg"] == "hmac-sha256-v1"
        assert int(row["master_key_version"]) == 0

    def test_handler_emit_stamps_hash_alg_and_version(self, db):
        handler = SQLiteLogHandler(db, flush_interval=1)
        log = logging.getLogger("test.h02a.emit.hashalg")
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        try:
            log.info("hello from handler")
        finally:
            log.removeHandler(handler)
        row = db.execute(
            "SELECT hash_alg, master_key_version FROM log_entries "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["hash_alg"] == "hmac-sha256-v1"
        assert int(row["master_key_version"]) == 0


class TestH02aLegacyForwardCompat:
    """Pre-H-02a SHA-256 rows must remain verifiable forever (per
    §164.316(b)(2)(i) 6-year retention)."""

    def test_legacy_sha256_row_verifies_via_dispatch(self, db):
        # Simulate a pre-H-02a row: hash_alg='sha256', computed via
        # the legacy SHA-256 helper (not HMAC).
        prev = ""
        h = _compute_log_row_hash_sha256(prev, "2026-01-01T00:00:00Z", "INFO", "t", "legacy", "{}")
        db.execute(
            "INSERT INTO log_entries (ts, level, logger, message, extra_json, "
            "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "INFO", "t", "legacy", "{}",
             "2026-01-01T00:00:00Z", prev, h, "sha256", 0),
        )
        db.commit()
        v = verify_log_chain(db)
        assert v["chain_length"] == 1
        assert v["legacy_chain_length"] == 1
        assert v["hmac_chain_length"] == 0
        assert v["first_break_id"] is None
        assert v["hash_alg_boundary_id"] is None


class TestH02aMixedChain:
    """Mixed chain: legacy SHA-256 rows + new HMAC rows verify across
    the boundary."""

    def test_mixed_legacy_then_hmac_verifies(self, db):
        # Two legacy rows
        prev = ""
        for i, ts in enumerate(["2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"]):
            h = _compute_log_row_hash_sha256(prev, ts, "INFO", "t", f"legacy{i}", "{}")
            db.execute(
                "INSERT INTO log_entries (ts, level, logger, message, extra_json, "
                "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, "INFO", "t", f"legacy{i}", "{}", ts, prev, h, "sha256", 0),
            )
            prev = h
        db.commit()
        # Then three HMAC rows via insert_log_entry
        for i in range(3):
            insert_log_entry(db, f"2026-05-23T00:00:0{i}Z", "INFO", "t", f"hmac{i}")
        db.commit()
        v = verify_log_chain(db)
        assert v["chain_length"] == 5
        assert v["legacy_chain_length"] == 2
        assert v["hmac_chain_length"] == 3
        assert v["hash_alg_boundary_id"] == 3  # first HMAC row id
        assert v["first_break_id"] is None


class TestH02aTamperDetection:
    """The whole point of HMAC: an insider with DB write cannot forge
    the chain even with full row contents in hand."""

    def test_tampered_hmac_row_detected(self, db):
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "original")
        db.commit()
        # Insider edit: change message + recompute SHA-256 (the attacker
        # doesn't have the HMAC key).
        row = db.execute("SELECT * FROM log_entries LIMIT 1").fetchone()
        forged_msg = "FORGED"
        forged_hash = _compute_log_row_hash_sha256(
            row["prev_hash"], row["ts"], row["level"], row["logger"],
            forged_msg, row["extra_json"],
        )
        db.execute(
            "UPDATE log_entries SET message = ?, row_hash = ? WHERE id = ?",
            (forged_msg, forged_hash, row["id"]),
        )
        db.commit()
        v = verify_log_chain(db)
        assert v["first_break_id"] == row["id"]
        assert "row_hash mismatch" in v["first_break_reason"]
        assert "hmac-sha256-v1" in v["first_break_reason"]


class TestH02aFailClosed:
    """D1 fail-closed per hipaa-sme-2 + DA-3 verdict: no HMAC key ⇒
    RuntimeError, NOT silent SHA-256 fallback."""

    def test_compute_raises_when_key_absent(self):
        _clear_hmac_keys_for_test()
        with pytest.raises(RuntimeError) as exc:
            compute_log_row_hash("", "ts", "INFO", "l", "m", "{}")
        assert "H-02a" in str(exc.value)
        assert "no HMAC key has been provisioned" in str(exc.value)

    def test_insert_raises_when_key_absent(self, db):
        _clear_hmac_keys_for_test()
        with pytest.raises(RuntimeError) as exc:
            insert_log_entry(db, "ts", "INFO", "l", "m")
        assert "H-02a" in str(exc.value)

    def test_verify_surfaces_missing_version_as_chain_break(self, db):
        # Insert a row with master_key_version=99 referencing a key
        # that's not in the registry (the autouse fixture only
        # installs version 0).
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "row1")
        db.commit()
        # Pollute the row with master_key_version=99 (no key for it).
        db.execute(
            "UPDATE log_entries SET master_key_version = 99 WHERE id = 1"
        )
        db.commit()
        v = verify_log_chain(db)
        # The recompute attempt should bubble up RuntimeError, which
        # verify_log_chain catches and reports as a chain break with
        # the offending version named.
        assert v["first_break_id"] == 1
        assert "master_key_version=99" in v["first_break_reason"]


class TestH02aRotationPreservation:
    """R1-plumbing-IN: rotation preserves legacy HMAC chain
    verifiability per §164.316(b)(2)(i) 6-year retention."""

    def _make_provider(self, db):
        master = DbSecrets.generate_master_key()
        return DbSecrets(db, master)

    def test_rotation_preserves_v0_chain(self, db):
        provider = self._make_provider(db)
        # Wire HMAC keys for current state (version 0, master from this provider).
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        # Insert a v0 row.
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "before-rotate")
        db.commit()
        # Rotate the master key.
        new_master = DbSecrets.generate_master_key()
        provider.rotate_master_key(new_master)
        assert provider.current_master_version() == 1
        # Re-wire (lifespan-equivalent): load v0 (preserved via KEK) + v1 (current).
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        # Insert a v1 row.
        insert_log_entry(db, "2026-05-23T00:00:01Z", "INFO", "t", "after-rotate")
        db.commit()
        # Chain validates across the boundary.
        v = verify_log_chain(db)
        assert v["chain_length"] == 2
        assert v["hmac_chain_length"] == 2
        assert v["first_break_id"] is None
        # Master-key versions stamped correctly.
        rows = db.execute(
            "SELECT id, master_key_version FROM log_entries ORDER BY id"
        ).fetchall()
        assert int(rows[0]["master_key_version"]) == 0
        assert int(rows[1]["master_key_version"]) == 1

    def test_two_rotations_chain_validates_across_three_versions(self, db):
        provider = self._make_provider(db)
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "v0")
        db.commit()
        # Rotation 1: v0 -> v1
        provider.rotate_master_key(DbSecrets.generate_master_key())
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        insert_log_entry(db, "2026-05-23T00:00:01Z", "INFO", "t", "v1")
        db.commit()
        # Rotation 2: v1 -> v2
        provider.rotate_master_key(DbSecrets.generate_master_key())
        assert provider.current_master_version() == 2
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        insert_log_entry(db, "2026-05-23T00:00:02Z", "INFO", "t", "v2")
        db.commit()
        v = verify_log_chain(db)
        assert v["chain_length"] == 3
        assert v["hmac_chain_length"] == 3
        assert v["first_break_id"] is None
        rows = db.execute(
            "SELECT master_key_version FROM log_entries ORDER BY id"
        ).fetchall()
        assert [int(r["master_key_version"]) for r in rows] == [0, 1, 2]

    def test_missing_history_row_surfaces_as_break(self, db):
        provider = self._make_provider(db)
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        insert_log_entry(db, "2026-05-23T00:00:00Z", "INFO", "t", "v0")
        db.commit()
        provider.rotate_master_key(DbSecrets.generate_master_key())
        # Operator deletes the history row — destructive, but exactly
        # the scenario hipaa-sme-2 wanted operator-detectable.
        provider.delete("master_key_history:v0")
        _clear_hmac_keys_for_test()
        wire_audit_chain_hmac_keys(provider, _MockConfig())
        # Insert a v1 row.
        insert_log_entry(db, "2026-05-23T00:00:01Z", "INFO", "t", "v1")
        db.commit()
        # Verifier hits the v0 row; its master_key_version=0 has no key
        # in the registry (the v0 history was deleted). Should surface
        # as a named break, not a silent pass.
        v = verify_log_chain(db)
        assert v["first_break_id"] == 1
        assert (
            "master_key_version=0" in v["first_break_reason"]
            or "v0" in v["first_break_reason"]
            or "version=0" in v["first_break_reason"]
        )


class TestH02aHkdfDerivation:
    """Sanity checks on the HKDF helper itself."""

    def test_derive_yields_32_bytes(self):
        key = derive_audit_chain_hmac_key("any-master-string")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_is_deterministic_for_same_master(self):
        k1 = derive_audit_chain_hmac_key("master-A")
        k2 = derive_audit_chain_hmac_key("master-A")
        assert k1 == k2

    def test_derive_differs_per_master(self):
        k1 = derive_audit_chain_hmac_key("master-A")
        k2 = derive_audit_chain_hmac_key("master-B")
        assert k1 != k2

    def test_accepts_bytes_input(self):
        kstr = derive_audit_chain_hmac_key("master-A")
        kbytes = derive_audit_chain_hmac_key(b"master-A")
        assert kstr == kbytes


class TestH02aBootEnforcementG1Prime:
    """G1' boot-time enforcement: HIPAA mode + env backend → RuntimeError;
    HIPAA mode + non-0600 keyfile → RuntimeError."""

    def test_env_backend_allowed_outside_hipaa_mode(self, monkeypatch):
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", False)
        cfg = _MockConfig()
        cfg.secrets.backend = "env"
        # Should be a no-op outside HIPAA mode.
        enforce_master_key_at_rest_for_hipaa(cfg)

    def test_env_backend_blocks_in_hipaa_mode(self, monkeypatch):
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        cfg = _MockConfig()
        cfg.secrets.backend = "env"
        with pytest.raises(RuntimeError) as exc:
            enforce_master_key_at_rest_for_hipaa(cfg)
        assert "H-02a" in str(exc.value)
        assert "env" in str(exc.value)
        assert "164.312(a)(2)(iv)" in str(exc.value)

    def test_container_backend_allowed_in_hipaa_mode(self, monkeypatch):
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        cfg = _MockConfig()
        cfg.secrets.backend = "container"
        enforce_master_key_at_rest_for_hipaa(cfg)  # no raise

    def test_keyring_backend_allowed_in_hipaa_mode(self, monkeypatch):
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        cfg = _MockConfig()
        cfg.secrets.backend = "keyring"
        enforce_master_key_at_rest_for_hipaa(cfg)  # no raise

    @pytest.mark.skipif(
        not hasattr(__import__("os"), "geteuid"),
        reason="POSIX permission bits required for keyfile mode check",
    )
    def test_keyfile_0600_allowed_in_hipaa_mode(self, monkeypatch, tmp_path):
        # POSIX-only — Windows's chmod doesn't honor 0o600 the way the
        # check expects, so the keyfile-mode check is semantically a
        # POSIX-permission concern. Real deploys are container/Linux.
        import os
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        kf = tmp_path / "key"
        kf.write_text("dummy")
        os.chmod(kf, 0o600)
        cfg = _MockConfig()
        cfg.secrets.backend = "keyfile"
        cfg.secrets.keyfile_path = str(kf)
        enforce_master_key_at_rest_for_hipaa(cfg)  # no raise

    @pytest.mark.skipif(
        not hasattr(__import__("os"), "geteuid"),
        reason="POSIX permission bits required for non-0600 keyfile check",
    )
    def test_keyfile_world_readable_blocks_in_hipaa_mode(
        self, monkeypatch, tmp_path,
    ):
        import os
        import email_triage.triage_logging as _tl
        monkeypatch.setattr(_tl, "_hipaa_mode", True)
        kf = tmp_path / "key"
        kf.write_text("dummy")
        os.chmod(kf, 0o644)  # group+world readable
        cfg = _MockConfig()
        cfg.secrets.backend = "keyfile"
        cfg.secrets.keyfile_path = str(kf)
        with pytest.raises(RuntimeError) as exc:
            enforce_master_key_at_rest_for_hipaa(cfg)
        assert "H-02a" in str(exc.value)
        assert "0600" in str(exc.value)
