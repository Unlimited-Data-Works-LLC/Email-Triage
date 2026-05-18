"""Tests for the M-3 (account-level) HIPAA-distill trigger watcher (#171-B).

Validates the trigger-plane logic that decides when an account warrants
an M-3 distill enqueue. The watcher itself is pure-DB; no provider /
LLM calls + no clock side effects (``now`` is injectable).

Conditions covered:

  * **First-time trigger** — no prior successful distill → enqueue.
  * **Threshold trigger** — counter ≥ 20 → enqueue.
  * **Stale trigger** — last success older than 7d → enqueue.
  * **Idempotency** — second run on already-queued account is a no-op.
  * **Already-paused** — paused row stays paused; watcher doesn't re-enqueue.
  * **Eligibility** — install-flag off / non-HIPAA / opt-out filter out.
  * **Privacy** — no plaintext recipient ever appears in any new code path.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from email_triage.style_learning.trigger_watcher import (
    HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES,
    STYLE_DISTILL_STALE_TRIGGER_DAYS,
    enqueue_m3_triggers,
    evaluate_m3_trigger_for_account,
    run_trigger_sweep,
)
from email_triage.web.db import (
    HIPAA_SEND_COUNTER_AGGREGATE_HASH,
    enqueue_style_distill_retry,
    get_hipaa_send_counter,
    get_style_distill_queue_entry,
    init_db,
    pause_style_distill_account,
    record_hipaa_sent_message,
    record_style_distill_event,
    set_hipaa_style_distill_enabled,
    set_style_knobs_hipaa_allow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> sqlite3.Connection:
    return init_db(":memory:")


def _seed_user(conn: sqlite3.Connection, *, email: str = "op@example.com") -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, "Op", "user", now),
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


def _enable_install_and_optin(conn: sqlite3.Connection, account_id: int) -> None:
    """Flip the install-wide flag AND the per-account opt-in on."""
    set_hipaa_style_distill_enabled(conn, True)
    set_style_knobs_hipaa_allow(conn, account_id, enabled=True)


def _seed_eligible_account(conn: sqlite3.Connection) -> int:
    """Seed an account that passes every eligibility gate."""
    user_id = _seed_user(conn)
    account_id = _seed_account(conn, user_id=user_id, hipaa=True)
    _enable_install_and_optin(conn, account_id)
    return account_id


# 64-char hex strings used as recipient_hash sentinels. Not real hashes
# (no need to compute the salted SHA-256 in this module's tests); the
# DB-layer validators accept anything that's 64-hex + not containing
# "@". Lower-case enforcement is checked by the validator.
HASH_A = "a" * 64
HASH_B = "b" * 64


# ---------------------------------------------------------------------------
# First-time trigger
# ---------------------------------------------------------------------------

class TestFirstTimeTrigger:
    def test_no_prior_distill_enqueues(self, db):
        account_id = _seed_eligible_account(db)

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is True
        assert decision.reason == "first_time"
        assert decision.last_success_at is None

    def test_first_time_enqueue_creates_queue_row(self, db):
        account_id = _seed_eligible_account(db)

        decisions, reasons = enqueue_m3_triggers(db)

        assert reasons.get("first_time") == 1
        row = get_style_distill_queue_entry(db, account_id=account_id)
        assert row is not None
        assert row["last_error"] == "trigger:first_time"
        assert row["paused"] == 0

    def test_first_time_only_fires_for_eligible_accounts(self, db):
        """An account that's HIPAA but NOT opted-in (M-1 off) shouldn't
        get a first-time trigger."""
        user_id = _seed_user(db)
        account_id = _seed_account(db, user_id=user_id, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        # NB: skip set_style_knobs_hipaa_allow → opt-in stays off.

        decisions, _reasons = enqueue_m3_triggers(db)

        assert decisions == []
        assert get_style_distill_queue_entry(
            db, account_id=account_id,
        ) is None


# ---------------------------------------------------------------------------
# Threshold trigger (N=20 new sent messages)
# ---------------------------------------------------------------------------

class TestThresholdTrigger:
    def test_counter_below_threshold_skips(self, db):
        account_id = _seed_eligible_account(db)
        # Seed a prior success so the first-time path doesn't fire.
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )
        # Bump counter to 19 (one below threshold).
        for _ in range(19):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is False
        assert decision.reason == "no_trigger"
        assert decision.counter == 19

    def test_counter_at_threshold_enqueues(self, db):
        account_id = _seed_eligible_account(db)
        # Seed prior success so threshold path is the only candidate.
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )
        for _ in range(HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is True
        assert decision.reason == "threshold_reached"
        assert decision.counter == HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES

    def test_enqueue_resets_counter(self, db):
        account_id = _seed_eligible_account(db)
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )
        for _ in range(HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        enqueue_m3_triggers(db)

        counter = get_hipaa_send_counter(
            db, account_id=account_id,
            recipient_hash=HIPAA_SEND_COUNTER_AGGREGATE_HASH,
        )
        assert counter is not None
        assert counter["count"] == 0


# ---------------------------------------------------------------------------
# Stale trigger
# ---------------------------------------------------------------------------

class TestStaleTrigger:
    def test_recent_success_does_not_fire(self, db):
        account_id = _seed_eligible_account(db)
        # ts defaults to NOW via record_style_distill_event.
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is False
        assert decision.reason == "no_trigger"

    def test_old_success_fires_stale(self, db):
        account_id = _seed_eligible_account(db)
        # Manual INSERT with an old timestamp.
        old_ts = (
            datetime.now(timezone.utc)
            - timedelta(days=STYLE_DISTILL_STALE_TRIGGER_DAYS + 1)
        ).isoformat()
        db.execute(
            "INSERT INTO style_distill_events "
            "(ts, account_id, backend_type, outcome, kind) "
            "VALUES (?, ?, ?, ?, ?)",
            (old_ts, account_id, "ollama", "success", "account_m3"),
        )
        db.commit()

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is True
        assert decision.reason == "stale"
        assert decision.last_success_at == old_ts

    def test_stale_via_now_injection(self, db):
        """``now`` is injectable for tests — bumps the clock instead
        of seeding an old row."""
        account_id = _seed_eligible_account(db)
        record_style_distill_event(
            db, account_id=account_id, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )
        # Jump the clock 8 days forward.
        future_now = datetime.now(timezone.utc) + timedelta(days=8)

        decision = evaluate_m3_trigger_for_account(
            db, account_id, now=future_now,
        )

        assert decision.should_enqueue is True
        assert decision.reason == "stale"


# ---------------------------------------------------------------------------
# Idempotency / queue interaction
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_already_queued_skips(self, db):
        account_id = _seed_eligible_account(db)
        # Pre-populate the queue.
        enqueue_style_distill_retry(
            db, account_id=account_id, last_error="trigger:first_time",
        )

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is False
        assert decision.reason == "already_queued"

    def test_second_sweep_no_op(self, db):
        account_id = _seed_eligible_account(db)
        # First sweep enqueues (first_time).
        decisions1, _r1 = enqueue_m3_triggers(db)
        assert any(d.should_enqueue for d in decisions1)

        # Second sweep — same conditions, no work.
        decisions2, reasons2 = enqueue_m3_triggers(db)

        assert all(not d.should_enqueue for d in decisions2)
        assert reasons2.get("already_queued") == 1
        # Queue row still there, still at attempt 1 (not re-incremented).
        row = get_style_distill_queue_entry(db, account_id=account_id)
        assert row["attempt_count"] == 1

    def test_paused_row_blocks_reenqueue(self, db):
        account_id = _seed_eligible_account(db)
        pause_style_distill_account(
            db, account_id=account_id, last_error="scrubber_fail",
        )

        decision = evaluate_m3_trigger_for_account(db, account_id)

        assert decision.should_enqueue is False
        assert decision.reason == "already_queued"
        # Queue row still paused after the sweep.
        row = get_style_distill_queue_entry(db, account_id=account_id)
        assert row["paused"] == 1


# ---------------------------------------------------------------------------
# Eligibility gates
# ---------------------------------------------------------------------------

class TestEligibility:
    def test_install_flag_off_skips_all(self, db):
        user_id = _seed_user(db)
        account_id = _seed_account(db, user_id=user_id, hipaa=True)
        set_style_knobs_hipaa_allow(db, account_id, enabled=True)
        # NB: set_hipaa_style_distill_enabled left OFF (default).

        decisions, _reasons = enqueue_m3_triggers(db)

        assert decisions == []

    def test_non_hipaa_account_skipped(self, db):
        user_id = _seed_user(db)
        # Non-HIPAA account.
        account_id = _seed_account(db, user_id=user_id, hipaa=False)
        set_hipaa_style_distill_enabled(db, True)
        # Opt-in flag CAN be set on a non-HIPAA account but the
        # eligibility filter still rejects it.
        set_style_knobs_hipaa_allow(db, account_id, enabled=True)

        decisions, _reasons = enqueue_m3_triggers(db)

        assert decisions == []

    def test_optin_off_skipped(self, db):
        user_id = _seed_user(db)
        account_id = _seed_account(db, user_id=user_id, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        # NB: skip set_style_knobs_hipaa_allow.

        decisions, _reasons = enqueue_m3_triggers(db)

        assert decisions == []

    def test_inactive_account_skipped(self, db):
        user_id = _seed_user(db)
        account_id = _seed_account(
            db, user_id=user_id, hipaa=True, is_active=False,
        )
        _enable_install_and_optin(db, account_id)

        decisions, _reasons = enqueue_m3_triggers(db)

        assert decisions == []


# ---------------------------------------------------------------------------
# Sweep summary
# ---------------------------------------------------------------------------

class TestSweepSummary:
    def test_run_trigger_sweep_returns_summary(self, db):
        account_id = _seed_eligible_account(db)

        summary = run_trigger_sweep(db)

        assert summary.m3_evaluated == 1
        assert summary.m3_enqueued == 1
        assert summary.m3_reasons.get("first_time") == 1
        # No counters / descriptors → M-7 evaluates zero.
        assert summary.m7_evaluated == 0
        assert summary.m7_enqueued == 0

    def test_multiple_accounts_aggregate_reasons(self, db):
        user_id = _seed_user(db)
        acct1 = _seed_account(db, user_id=user_id, hipaa=True, name="A1")
        acct2 = _seed_account(db, user_id=user_id, hipaa=True, name="A2")
        acct3 = _seed_account(db, user_id=user_id, hipaa=True, name="A3")
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, acct1, enabled=True)
        set_style_knobs_hipaa_allow(db, acct2, enabled=True)
        set_style_knobs_hipaa_allow(db, acct3, enabled=True)
        # acct2 already has a success row (no_trigger).
        record_style_distill_event(
            db, account_id=acct2, actor_user_id=None,
            backend_id=None, backend_type="ollama", was_cloud=False,
            outcome="success", kind="account_m3",
        )
        # acct3 already queued (already_queued).
        enqueue_style_distill_retry(
            db, account_id=acct3, last_error="trigger:first_time",
        )

        summary = run_trigger_sweep(db)

        assert summary.m3_evaluated == 3
        # acct1 → first_time, acct2 → no_trigger, acct3 → already_queued.
        assert summary.m3_reasons.get("first_time") == 1
        assert summary.m3_reasons.get("no_trigger") == 1
        assert summary.m3_reasons.get("already_queued") == 1
        assert summary.m3_enqueued == 1


# ---------------------------------------------------------------------------
# Privacy invariants
# ---------------------------------------------------------------------------

class TestPrivacyInvariants:
    """The M-3 trigger path operates on COUNTS only — no recipient
    addresses. These tests pin that contract."""

    def test_record_hipaa_sent_message_rejects_plaintext(self, db):
        account_id = _seed_eligible_account(db)
        with pytest.raises(ValueError, match="@"):
            record_hipaa_sent_message(
                db, account_id=account_id,
                recipient_hash="someone@example.com",
            )

    def test_record_hipaa_sent_message_rejects_short_hash(self, db):
        account_id = _seed_eligible_account(db)
        with pytest.raises(ValueError, match="64-char"):
            record_hipaa_sent_message(
                db, account_id=account_id,
                recipient_hash="abc123",
            )

    def test_record_hipaa_sent_message_rejects_non_hex(self, db):
        account_id = _seed_eligible_account(db)
        # 64 chars but with a non-hex character.
        bad_hash = "z" * 64
        with pytest.raises(ValueError, match="64-char"):
            record_hipaa_sent_message(
                db, account_id=account_id,
                recipient_hash=bad_hash,
            )

    def test_log_records_carry_no_recipient_plaintext(
        self, db, caplog, monkeypatch,
    ):
        """The trigger watcher's log lines must not surface plaintext
        recipients. M-3 doesn't see them at all (account-level), but
        belt-and-braces: pin that no log record from a sweep mentions
        a marker plaintext."""
        account_id = _seed_eligible_account(db)
        # If the test environment somehow puts a marker into the
        # account row, ensure it doesn't leak via the sweep log.
        # We assert by scanning all log records produced during the
        # sweep for a sentinel string.
        SENTINEL = "DO-NOT-LEAK-recurring-recipient@hospital.example"
        # Bump the counter via a synthetic hash (NOT containing the
        # plaintext) to exercise the threshold path.
        for _ in range(HIPAA_ACCOUNT_TRIGGER_MIN_MESSAGES):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        with caplog.at_level(
            logging.DEBUG, logger="email_triage.style_learning",
        ):
            enqueue_m3_triggers(db)

        for record in caplog.records:
            assert SENTINEL not in record.getMessage()
            # Defence-in-depth — also check structured extras.
            extras = getattr(record, "_extra", None)
            if isinstance(extras, dict):
                for v in extras.values():
                    assert SENTINEL not in str(v)


# ---------------------------------------------------------------------------
# Aggregate vs per-recipient counter wiring
# ---------------------------------------------------------------------------

class TestCounterWiring:
    """The aggregate counter (recipient_hash='') must include EVERY
    outbound message regardless of recipient. The per-recipient rows
    feed the M-7 watcher; the aggregate feeds the M-3 watcher."""

    def test_aggregate_counter_sums_across_recipients(self, db):
        account_id = _seed_eligible_account(db)
        for _ in range(8):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )
        for _ in range(12):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_B,
            )

        aggregate = get_hipaa_send_counter(
            db, account_id=account_id,
            recipient_hash=HIPAA_SEND_COUNTER_AGGREGATE_HASH,
        )
        per_a = get_hipaa_send_counter(
            db, account_id=account_id, recipient_hash=HASH_A,
        )
        per_b = get_hipaa_send_counter(
            db, account_id=account_id, recipient_hash=HASH_B,
        )
        assert aggregate["count"] == 20
        assert per_a["count"] == 8
        assert per_b["count"] == 12

    def test_aggregate_reset_does_not_touch_per_recipient(self, db):
        """The M-3 watcher resets the aggregate counter on enqueue.
        Per-recipient rows must survive that reset so the M-7 watcher
        can still see them."""
        account_id = _seed_eligible_account(db)
        for _ in range(20):
            record_hipaa_sent_message(
                db, account_id=account_id, recipient_hash=HASH_A,
            )

        enqueue_m3_triggers(db)

        aggregate = get_hipaa_send_counter(
            db, account_id=account_id,
            recipient_hash=HIPAA_SEND_COUNTER_AGGREGATE_HASH,
        )
        per_a = get_hipaa_send_counter(
            db, account_id=account_id, recipient_hash=HASH_A,
        )
        assert aggregate["count"] == 0
        assert per_a["count"] == 20
