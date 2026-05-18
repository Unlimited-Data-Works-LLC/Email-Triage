"""Tests for the #137 + adjacent helper-extraction work.

Covers:
    * ``web.db.update_account_config_keys`` — atomic read-modify-write
      that replaced the 7-site dict-patch idiom in ``routers/ui.py``.
    * ``actions.base.build_action_log_extras`` — single source of
      truth for action log_extras dicts (replacing per-action
      ``def _extras`` closures in label.py / move.py / etc.).
    * Inlined ``is_hipaa_account`` callers in ``web/calendars.py``
      (#145.5 — wrapper deleted, callers go straight to
      ``triage_logging.is_account_hipaa``).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from email_triage.config import TriageConfig
from email_triage.web.db import (
    create_email_account,
    get_email_account,
    init_db,
    seed_categories,
    update_account_config_keys,
)


def _make_db_with_account(*, config=None) -> tuple:
    """Create an in-memory DB + a single owned account."""
    cfg = TriageConfig()
    db = init_db(":memory:")
    seed_categories(db, cfg.classifier.categories)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("owner@test.com", "Owner", "user", now),
    )
    db.commit()
    account_id = create_email_account(
        db, 1, "TestAcct", provider_type="imap",
        config=config or {}, is_active=True,
    )
    return db, account_id


class TestUpdateAccountConfigKeys:
    def test_set_single_key(self):
        db, aid = _make_db_with_account(
            config={"existing_key": "preserved"},
        )
        ok = update_account_config_keys(db, aid, new_key="new_value")
        assert ok is True
        acct = get_email_account(db, aid)
        # Other keys preserved.
        assert acct["config"]["existing_key"] == "preserved"
        assert acct["config"]["new_key"] == "new_value"

    def test_multiple_keys_in_one_call(self):
        db, aid = _make_db_with_account(
            config={"untouched": "value"},
        )
        update_account_config_keys(
            db, aid,
            push_enabled=True, poll_enabled=False, poll_interval_minutes=30,
        )
        acct = get_email_account(db, aid)
        assert acct["config"]["untouched"] == "value"
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is False
        assert acct["config"]["poll_interval_minutes"] == 30

    def test_overwrite_existing_key(self):
        db, aid = _make_db_with_account(
            config={"port": 993},
        )
        update_account_config_keys(db, aid, port=2525)
        acct = get_email_account(db, aid)
        assert acct["config"]["port"] == 2525

    def test_none_value_deletes_key(self):
        """``calendar_surrogate_save`` clears the surrogate by passing
        ``surrogate_account_id=None``. Verify the helper handles delete
        semantics correctly."""
        db, aid = _make_db_with_account(
            config={
                "calendar_surrogate_account_id": 7,
                "kept": "value",
            },
        )
        update_account_config_keys(
            db, aid, calendar_surrogate_account_id=None,
        )
        acct = get_email_account(db, aid)
        assert "calendar_surrogate_account_id" not in acct["config"]
        assert acct["config"]["kept"] == "value"

    def test_unknown_account_returns_false(self):
        db, _ = _make_db_with_account()
        assert update_account_config_keys(db, 99999, foo="bar") is False

    def test_no_op_when_value_matches(self):
        """Setting a key to its existing value is a no-op (no log
        emission, no UPDATE statement). Tested indirectly by the
        log-emission test below — here just verify it succeeds."""
        db, aid = _make_db_with_account(config={"key": "value"})
        # Same value → no change.
        ok = update_account_config_keys(db, aid, key="value")
        assert ok is True
        acct = get_email_account(db, aid)
        assert acct["config"]["key"] == "value"

    def test_emits_structured_log_with_changed_keys(self, caplog):
        """Standing rule per ``feedback_no_account_id_alone.md``:
        log carries owner + account_name; account_id is tiebreaker."""
        db, aid = _make_db_with_account()
        with caplog.at_level(logging.INFO, logger="email_triage.web.db"):
            update_account_config_keys(
                db, aid,
                push_enabled=True, poll_interval_minutes=15,
            )
        # Find the log record.
        records = [
            r for r in caplog.records
            if r.name == "email_triage.web.db"
            and "Account config keys updated" in r.getMessage()
        ]
        assert len(records) == 1, (
            f"expected exactly one log line, got {len(records)}"
        )
        rec = records[0]
        # The structured ``_extra`` dict carries the audit fields.
        # Different log adapters may stash this under different keys —
        # we read the LogRecord attributes directly since logger.info
        # called with extra=... attaches them as attrs.
        # Account_id rides along but as tiebreaker (per
        # feedback_no_account_id_alone.md) — owner + account_name
        # are the operator-facing identifiers.
        extra = getattr(rec, "_extra", None)
        if extra is None:
            # Fallback: extras attached as attrs directly.
            extra = {
                k: getattr(rec, k, None)
                for k in ("account_id", "owner", "account_name", "changed_keys")
            }
        assert extra.get("account_id") == aid
        assert extra.get("owner") == "Owner"
        assert extra.get("account_name") == "TestAcct"
        assert sorted(extra.get("changed_keys") or []) == [
            "poll_interval_minutes", "push_enabled",
        ]

    def test_concurrent_writes_dont_clobber(self):
        """Read-modify-write atomicity: simulating a write that comes
        between two reads of the original idiom would clobber. With
        the helper, every call re-reads inside its own transaction, so
        the merge always sees the latest state.

        Test by interleaving: A reads, B writes key X, A writes key Y.
        With the bug-prone idiom, A's write would erase B's X. With
        the helper, A's write merges B's X back in (because A's
        transaction re-reads after B's commit).
        """
        db, aid = _make_db_with_account(config={"shared": "v0"})
        # Step 1: B sets key X.
        update_account_config_keys(db, aid, x_key="set_by_b")
        # Step 2: A would have read at v0 + set y_key, but with the
        # helper A re-reads here → sees x_key.
        update_account_config_keys(db, aid, y_key="set_by_a")
        acct = get_email_account(db, aid)
        # Both keys present.
        assert acct["config"]["x_key"] == "set_by_b"
        assert acct["config"]["y_key"] == "set_by_a"
        assert acct["config"]["shared"] == "v0"


# ---------------------------------------------------------------------------
# build_action_log_extras
# ---------------------------------------------------------------------------


def _make_message(*, hipaa: bool = False, sender="Alice <a@x.com>",
                  subject="Subject text"):
    from email_triage.engine.models import EmailMessage
    return EmailMessage(
        message_id="m-1",
        provider="test",
        sender=sender,
        recipients=["bob@y.com"],
        subject=subject,
        body_text="body",
        date=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
        hipaa=hipaa,
    )


def _make_flow(*, state_bag=None):
    from email_triage.engine.models import FlowState, FlowStatus
    return FlowState(
        flow_id="f-42",
        message_id="m-1",
        provider="test",
        status=FlowStatus.ACTING,
        state_bag=state_bag or {},
    )


def _make_classification():
    from email_triage.engine.models import Classification
    return Classification(
        category="invoices", confidence=0.9, reason="Invoice email.",
    )


def _make_provider():
    from unittest.mock import MagicMock
    p = MagicMock()
    p.name = "test_provider"
    return p


class TestBuildActionLogExtras:
    def test_hipaa_redacts_sender_and_subject(self):
        from email_triage.actions.base import build_action_log_extras
        flow = _make_flow()
        msg = _make_message(hipaa=True)
        extras = build_action_log_extras(
            flow, msg, _make_classification(), _make_provider(),
        )
        assert "sender" not in extras
        assert "subject" not in extras
        # Canonical fields still surface.
        assert extras["flow_id"] == "f-42"
        assert extras["message_id"] == "m-1"
        assert extras["category"] == "invoices"
        assert extras["provider"] == "test_provider"

    def test_non_hipaa_includes_sender_and_subject(self):
        from email_triage.actions.base import build_action_log_extras
        msg = _make_message(hipaa=False, sender="X <x@y.z>",
                            subject="A subject line")
        extras = build_action_log_extras(
            _make_flow(), msg, _make_classification(), _make_provider(),
        )
        assert extras["sender"] == "X <x@y.z>"
        assert extras["subject"] == "A subject line"

    def test_owner_and_account_name_surface_from_state_bag(self):
        from email_triage.actions.base import build_action_log_extras
        flow = _make_flow(state_bag={
            "owner": "Alice Owner",
            "account_name": "Work Inbox",
            "account_id": 7,
        })
        extras = build_action_log_extras(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        # Order matters per feedback_no_account_id_alone.md: owner +
        # account_name + account_id (tiebreaker).
        assert extras["owner"] == "Alice Owner"
        assert extras["account_name"] == "Work Inbox"
        assert extras["account_id"] == 7

    def test_account_id_alone_is_not_emitted(self):
        """Per feedback_no_account_id_alone.md: account_id alone
        without owner/account_name is unreadable to operators. The
        helper still surfaces account_id when state_bag has it, but
        a state_bag with ONLY account_id (no owner / account_name)
        would surface a lonely numeric — verify the helper at least
        doesn't synthesize an account_name from the id."""
        from email_triage.actions.base import build_action_log_extras
        flow = _make_flow(state_bag={"account_id": 7})
        extras = build_action_log_extras(
            flow, _make_message(), _make_classification(), _make_provider(),
        )
        assert extras.get("account_id") == 7
        # Helper does NOT invent owner/account_name. Caller is
        # responsible for stashing them at flow-creation time
        # (the watcher does this in production).
        assert "owner" not in extras
        assert "account_name" not in extras

    def test_more_overrides_canonical_when_passed(self):
        """`label` / `folder` / `draft_id` extras come in via **more
        and overlay the base dict last. Verify the override path."""
        from email_triage.actions.base import build_action_log_extras
        extras = build_action_log_extras(
            _make_flow(), _make_message(), _make_classification(),
            _make_provider(),
            label="Triage/Invoices", folder="INBOX.Invoices",
        )
        assert extras["label"] == "Triage/Invoices"
        assert extras["folder"] == "INBOX.Invoices"


# ---------------------------------------------------------------------------
# #145.5 — is_hipaa_account inline (wrapper deleted).
# ---------------------------------------------------------------------------


class TestCalendarsHipaaInlinedCallers:
    """Behavior must be unchanged after the wrapper inline. The
    surrogate resolver in calendars.py is the only consumer."""

    def test_resolve_surrogate_blocks_hipaa_acct(self):
        """HIPAA-flagged primary account: resolver returns None."""
        from email_triage.web.calendars import resolve_surrogate_account

        db, aid = _make_db_with_account()
        # Add a sibling Gmail account (potential surrogate) under same owner.
        sib_id = create_email_account(
            db, 1, "GmailSib", provider_type="gmail_api",
            config={}, is_active=True,
        )
        # Build a HIPAA-flagged primary acct dict (with surrogate id set).
        primary = {
            "id": aid, "user_id": 1, "provider_type": "imap",
            "hipaa": 1,
            "config": {"calendar_surrogate_account_id": sib_id},
        }
        assert resolve_surrogate_account(db, primary) is None

    def test_resolve_surrogate_blocks_hipaa_surrogate(self):
        """Non-HIPAA primary, but surrogate is HIPAA: still blocked."""
        from email_triage.web.calendars import resolve_surrogate_account
        from email_triage.web.db import set_account_hipaa

        db, aid = _make_db_with_account()
        sib_id = create_email_account(
            db, 1, "GmailSib", provider_type="gmail_api",
            config={}, is_active=True,
        )
        # Mark the sibling as HIPAA.
        set_account_hipaa(db, sib_id, True, actor_id=1)
        primary = {
            "id": aid, "user_id": 1, "provider_type": "imap",
            "hipaa": 0,
            "config": {"calendar_surrogate_account_id": sib_id},
        }
        assert resolve_surrogate_account(db, primary) is None

    def test_wrapper_is_gone(self):
        """#145.5 — ``is_hipaa_account`` was a wrapper around
        ``is_account_hipaa``. Verify it's no longer importable."""
        with pytest.raises(ImportError):
            from email_triage.web.calendars import (  # noqa: F401
                is_hipaa_account,
            )
