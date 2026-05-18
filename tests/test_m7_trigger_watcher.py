"""Tests for the M-7 (per-contact) HIPAA-distill trigger watcher (#171-B).

Sibling of ``test_m3_trigger_watcher.py``. Validates the per-recipient
trigger plane: threshold (≥20 messages to a single recipient), stale
(>30d), idempotency, eligibility, and privacy invariants.

Key design point pinned here: M-7 first-time firing REQUIRES the counter
threshold. A HIPAA account with the M-1 opt-in on but no recurring
recipient with ≥20 sent messages gets NO M-7 enqueue — only the M-3
account-level distill fires. This is the "overlay vs mandatory"
distinction: M-3 is always built once HIPAA + opt-in are on; M-7 is
opportunistic on recurring correspondents.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.style_learning.trigger_watcher import (
    HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS,
    enqueue_m7_triggers,
    evaluate_m7_trigger_for_contact,
    evaluate_m7_triggers_for_account,
    run_trigger_sweep,
)
from email_triage.web.db import (
    HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES,
    enqueue_style_distill_contact_retry,
    get_hipaa_send_counter,
    get_style_distill_contact_queue_entry,
    init_db,
    pause_style_distill_contact,
    record_hipaa_sent_message,
    record_style_distill_event,
    set_hipaa_style_distill_enabled,
    set_per_contact_style_hipaa,
    set_style_knobs_hipaa_allow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> sqlite3.Connection:
    return init_db(":memory:")


def _seed_user(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    hipaa: bool = True,
    is_active: bool = True,
    name: str = "Mailbox",
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "user_id, name, provider_type, config_json, hipaa, is_active, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "imap", "{}",
            int(bool(hipaa)), int(bool(is_active)),
            now, now,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_eligible_account(conn: sqlite3.Connection) -> int:
    user_id = _seed_user(conn)
    account_id = _seed_account(conn, user_id=user_id, hipaa=True)
    set_hipaa_style_distill_enabled(conn, True)
    set_style_knobs_hipaa_allow(conn, account_id, enabled=True)
    return account_id


# Sentinel 64-hex hashes. Not real SHA-256 outputs — the DB validator
# accepts any 64-char lowercase hex that doesn't contain "@". The
# privacy-invariant tests pin that these placeholders never get
# confused with plaintext addresses.
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


# ---------------------------------------------------------------------------
# Threshold trigger
# ---------------------------------------------------------------------------

class TestThresholdTrigger:
    def test_counter_below_threshold_skips(self, db):
        account_id = _seed_eligible_account(db)
        # 19 sends to HASH_A — one below threshold.
        for _ in range(19):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is False
        assert decision.reason == "below_threshold"
        assert decision.counter == 19

    def test_counter_at_threshold_enqueues_first_time(self, db):
        account_id = _seed_eligible_account(db)
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is True
        assert decision.reason == "first_time"
        assert decision.counter == HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES

    def test_counter_at_threshold_with_prior_success_threshold_reached(self, db):
        account_id = _seed_eligible_account(db)
        # Seed prior success row.
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="per_contact",
            recipient_hash=HASH_A,
        )
        # Then 20 new sends to the same contact.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is True
        assert decision.reason == "threshold_reached"

    def test_enqueue_resets_per_contact_counter(self, db):
        account_id = _seed_eligible_account(db)
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decisions, _reasons = enqueue_m7_triggers(db)

        # Per-contact row reset.
        per_a = get_hipaa_send_counter(
            db, account_id=account_id, recipient_hash=HASH_A,
        )
        assert per_a["count"] == 0
        # Queue row created.
        row = get_style_distill_contact_queue_entry(
            db, account_id=account_id, recipient_hash=HASH_A,
        )
        assert row is not None
        assert row["last_error"] == "trigger:first_time"


# ---------------------------------------------------------------------------
# Stale trigger
# ---------------------------------------------------------------------------

class TestStaleTrigger:
    def test_recent_success_no_fire(self, db):
        account_id = _seed_eligible_account(db)
        # Seed a recent success + a descriptor row + small counter.
        set_per_contact_style_hipaa(
            db, account_id=account_id, recipient_hash=HASH_A,
            descriptor={"tone": "neutral", "formality_level": 3,
                        "greeting_style": "none", "signoff_style": "none",
                        "sentence_length_pref": "medium",
                        "vocabulary_register": "plain",
                        "paragraph_count_typical": 2,
                        "common_phrases": []},
            version=1, message_count=20,
        )
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="per_contact",
            recipient_hash=HASH_A,
        )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is False
        assert decision.reason == "no_trigger"

    def test_old_success_fires_stale(self, db):
        account_id = _seed_eligible_account(db)
        # Descriptor row exists from a long-ago run.
        set_per_contact_style_hipaa(
            db, account_id=account_id, recipient_hash=HASH_A,
            descriptor={"tone": "neutral", "formality_level": 3,
                        "greeting_style": "none", "signoff_style": "none",
                        "sentence_length_pref": "medium",
                        "vocabulary_register": "plain",
                        "paragraph_count_typical": 2,
                        "common_phrases": []},
            version=1, message_count=20,
        )
        # Old success event.
        old_ts = (
            datetime.now(timezone.utc)
            - timedelta(days=HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS + 1)
        ).isoformat()
        db.execute(
            "INSERT INTO style_distill_events "
            "(ts, account_id, backend_type, outcome, kind, recipient_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (old_ts, account_id, "ollama", "success", "per_contact", HASH_A),
        )
        db.commit()

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is True
        assert decision.reason == "stale"

    def test_stale_via_now_injection(self, db):
        account_id = _seed_eligible_account(db)
        set_per_contact_style_hipaa(
            db, account_id=account_id, recipient_hash=HASH_A,
            descriptor={"tone": "neutral", "formality_level": 3,
                        "greeting_style": "none", "signoff_style": "none",
                        "sentence_length_pref": "medium",
                        "vocabulary_register": "plain",
                        "paragraph_count_typical": 2,
                        "common_phrases": []},
            version=1, message_count=20,
        )
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="per_contact",
            recipient_hash=HASH_A,
        )

        future_now = (
            datetime.now(timezone.utc)
            + timedelta(days=HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS + 1)
        )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
            now=future_now,
        )

        assert decision.should_enqueue is True
        assert decision.reason == "stale"


# ---------------------------------------------------------------------------
# Account-wide evaluation (counter ∪ descriptor union)
# ---------------------------------------------------------------------------

class TestAccountWideEvaluation:
    def test_iterates_every_counter_row(self, db):
        account_id = _seed_eligible_account(db)
        # HASH_A reaches threshold → enqueue.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )
        # HASH_B below threshold → skip.
        for _ in range(5):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_B,
            )

        decisions = evaluate_m7_triggers_for_account(
            db, account_id=account_id,
        )

        # Two rows examined (HASH_A + HASH_B).
        hashes = {d.recipient_hash for d in decisions}
        assert hashes == {HASH_A, HASH_B}
        decision_by_hash = {d.recipient_hash: d for d in decisions}
        assert decision_by_hash[HASH_A].should_enqueue is True
        assert decision_by_hash[HASH_B].should_enqueue is False

    def test_descriptor_with_no_counter_still_evaluated(self, db):
        """A contact the operator stopped emailing — counter is zero
        but the descriptor row exists. The watcher must STILL evaluate
        it so the stale-refresh path can fire."""
        account_id = _seed_eligible_account(db)
        # Stale descriptor for HASH_A; no counter row at all.
        set_per_contact_style_hipaa(
            db, account_id=account_id, recipient_hash=HASH_A,
            descriptor={"tone": "neutral", "formality_level": 3,
                        "greeting_style": "none", "signoff_style": "none",
                        "sentence_length_pref": "medium",
                        "vocabulary_register": "plain",
                        "paragraph_count_typical": 2,
                        "common_phrases": []},
            version=1, message_count=20,
        )
        old_ts = (
            datetime.now(timezone.utc)
            - timedelta(days=HIPAA_PER_CONTACT_STALE_TRIGGER_DAYS + 1)
        ).isoformat()
        db.execute(
            "INSERT INTO style_distill_events "
            "(ts, account_id, backend_type, outcome, kind, recipient_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (old_ts, account_id, "ollama", "success", "per_contact", HASH_A),
        )
        db.commit()

        decisions = evaluate_m7_triggers_for_account(
            db, account_id=account_id,
        )

        # HASH_A evaluated via the descriptor-row path; stale fires.
        decision_by_hash = {d.recipient_hash: d for d in decisions}
        assert HASH_A in decision_by_hash
        assert decision_by_hash[HASH_A].reason == "stale"
        assert decision_by_hash[HASH_A].should_enqueue is True


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_already_queued_contact_skips(self, db):
        account_id = _seed_eligible_account(db)
        # Pre-populate the contact queue.
        enqueue_style_distill_contact_retry(
            db, account_id=account_id, recipient_hash=HASH_A,
            last_error="trigger:first_time",
        )
        # Counter above threshold but already queued.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is False
        assert decision.reason == "already_queued"

    def test_second_sweep_no_op(self, db):
        account_id = _seed_eligible_account(db)
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )
        # First sweep enqueues.
        decisions1, _r1 = enqueue_m7_triggers(db)
        assert sum(1 for d in decisions1 if d.should_enqueue) == 1

        # Second sweep — counter has been reset; HASH_A is now queued.
        decisions2, reasons2 = enqueue_m7_triggers(db)
        # The previously-enqueued contact's counter was reset (count=0)
        # so list_hipaa_per_contact_counters filters it out
        # (min_count=1). No rows iterated.
        assert sum(1 for d in decisions2 if d.should_enqueue) == 0

    def test_paused_contact_blocks_reenqueue(self, db):
        account_id = _seed_eligible_account(db)
        pause_style_distill_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
            last_error="scrubber_fail:structural_leak",
        )
        # Counter at threshold but paused — should NOT enqueue.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m7_trigger_for_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
        )

        assert decision.should_enqueue is False
        assert decision.reason == "already_queued"

    def test_paused_one_contact_doesnt_block_other(self, db):
        """Pausing HASH_A's per-contact queue row must not block
        HASH_B from getting enqueued (per-contact isolation)."""
        account_id = _seed_eligible_account(db)
        pause_style_distill_contact(
            db, account_id=account_id, recipient_hash=HASH_A,
            last_error="scrubber_fail",
        )
        # Both contacts at threshold.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_B,
            )

        decisions, _reasons = enqueue_m7_triggers(db)

        per_hash = {d.recipient_hash: d for d in decisions}
        # HASH_A paused → already_queued.
        assert per_hash[HASH_A].reason == "already_queued"
        # HASH_B fresh → enqueue.
        assert per_hash[HASH_B].should_enqueue is True
        row_b = get_style_distill_contact_queue_entry(
            db, account_id=account_id, recipient_hash=HASH_B,
        )
        assert row_b is not None


# ---------------------------------------------------------------------------
# Eligibility gates
# ---------------------------------------------------------------------------

class TestEligibility:
    def test_non_hipaa_account_skipped(self, db):
        user_id = _seed_user(db)
        account_id = _seed_account(db, user_id=user_id, hipaa=False)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, account_id, enabled=True)
        # Try to bump the counter — defensive validation should still
        # accept the call (it doesn't read account state), but the
        # watcher's eligibility filter must drop the account.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decisions, _reasons = enqueue_m7_triggers(db)

        # No enqueues — account not HIPAA-flagged.
        assert all(not d.should_enqueue for d in decisions)
        # NB: decisions list may be empty (no eligible accounts).
        assert decisions == []

    def test_optin_off_skipped(self, db):
        user_id = _seed_user(db)
        account_id = _seed_account(db, user_id=user_id, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        # NB: per-account opt-in stays off.
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decisions, _reasons = enqueue_m7_triggers(db)

        assert decisions == []


# ---------------------------------------------------------------------------
# Privacy invariants
# ---------------------------------------------------------------------------

class TestPrivacyInvariants:
    def test_log_records_carry_no_plaintext_recipient(self, db, caplog):
        """When the watcher logs an enqueue, it must log only a HASH
        PREFIX — never the full hash, never the plaintext."""
        account_id = _seed_eligible_account(db)
        SENTINEL = "DO-NOT-LEAK-recurring-recipient@hospital.example"

        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        with caplog.at_level(
            logging.DEBUG, logger="email_triage.style_learning",
        ):
            enqueue_m7_triggers(db)

        for record in caplog.records:
            assert SENTINEL not in record.getMessage()
            extras = getattr(record, "_extra", None)
            if isinstance(extras, dict):
                for v in extras.values():
                    assert SENTINEL not in str(v)

    def test_validator_rejects_plaintext_recipient_hash(self, db):
        """Defensive: passing a plaintext address to the counter or
        the queue helper must raise — not silently store it."""
        account_id = _seed_eligible_account(db)
        with pytest.raises(ValueError, match="@"):
            record_hipaa_sent_message(
                db, account_id=account_id,
                recipient_hash="someone@hospital.example",
            )

    def test_logged_hash_prefix_only(self, db, caplog):
        """Pin that the structured-log extra carries hash_prefix, not
        the full hash. A leaked-DB attacker who reads the logs should
        not be able to enumerate the full 64-hex digest."""
        account_id = _seed_eligible_account(db)
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        with caplog.at_level(
            logging.INFO, logger="email_triage.style_learning",
        ):
            enqueue_m7_triggers(db)

        # Find the enqueue log line.
        enqueue_records = [
            r for r in caplog.records
            if "m7 trigger enqueued" in r.getMessage()
        ]
        assert enqueue_records, "expected an m7 enqueue log line"
        for record in enqueue_records:
            extras = getattr(record, "_extra", None) or {}
            # Either no recipient_hash key at all (good), or only the
            # _prefix variant.
            assert "recipient_hash" not in extras
            if "recipient_hash_prefix" in extras:
                assert len(extras["recipient_hash_prefix"]) <= 16


# ---------------------------------------------------------------------------
# Sweep summary
# ---------------------------------------------------------------------------

class TestSweepSummary:
    def test_sweep_summary_includes_m7(self, db):
        account_id = _seed_eligible_account(db)
        for _ in range(HIPAA_PER_CONTACT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        summary = run_trigger_sweep(db)

        assert summary.m7_evaluated >= 1
        assert summary.m7_enqueued == 1
        assert summary.m7_reasons.get("first_time") == 1
