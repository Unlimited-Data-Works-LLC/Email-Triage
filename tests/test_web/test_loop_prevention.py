"""Tests for cross-folder loop prevention (RFC Message-Id dedup)."""

from datetime import datetime, timedelta, timezone

from email_triage.mail_headers import get_rfc_message_id
from email_triage.web.db import (
    _hash_msg_id,
    create_email_account,
    is_triaged,
    mark_triaged,
    prune_triaged_messages,
)


class TestHashing:
    def test_stable_hash_same_inputs(self):
        h1 = _hash_msg_id(7, "<abc@example.com>")
        h2 = _hash_msg_id(7, "<abc@example.com>")
        assert h1 == h2

    def test_different_account_different_hash(self):
        h1 = _hash_msg_id(7, "<abc@example.com>")
        h2 = _hash_msg_id(8, "<abc@example.com>")
        assert h1 != h2

    def test_different_msg_different_hash(self):
        h1 = _hash_msg_id(7, "<abc@example.com>")
        h2 = _hash_msg_id(7, "<def@example.com>")
        assert h1 != h2


class TestRfcMessageIdExtractor:
    def test_message_id_canonical(self):
        assert get_rfc_message_id({"Message-ID": "<abc@x>"}) == "<abc@x>"

    def test_message_id_alt_case(self):
        assert get_rfc_message_id({"Message-Id": "<abc@x>"}) == "<abc@x>"

    def test_message_id_lower(self):
        assert get_rfc_message_id({"message-id": "<abc@x>"}) == "<abc@x>"

    def test_missing_returns_empty(self):
        assert get_rfc_message_id({}) == ""
        assert get_rfc_message_id(None) == ""

    def test_strips_whitespace(self):
        assert get_rfc_message_id({"Message-Id": "  <abc@x>\r\n"}) == "<abc@x>"


class TestDedupPersistence:
    def _acct(self, db, regular_user):
        return create_email_account(
            db, regular_user["id"], "ACCT", "imap", {"host": "x"},
        )

    def test_unmark_returns_false(self, db, regular_user):
        acct = self._acct(db, regular_user)
        assert is_triaged(db, acct, "<never@seen>") is False

    def test_mark_then_check(self, db, regular_user):
        acct = self._acct(db, regular_user)
        mark_triaged(db, acct, "<x@y>")
        assert is_triaged(db, acct, "<x@y>") is True

    def test_mark_idempotent(self, db, regular_user):
        acct = self._acct(db, regular_user)
        mark_triaged(db, acct, "<x@y>")
        mark_triaged(db, acct, "<x@y>")
        assert is_triaged(db, acct, "<x@y>") is True
        # Still exactly one row.
        c = db.execute(
            "SELECT COUNT(*) FROM triaged_messages WHERE account_id = ?",
            (acct,),
        ).fetchone()[0]
        assert c == 1

    def test_empty_id_no_op(self, db, regular_user):
        acct = self._acct(db, regular_user)
        mark_triaged(db, acct, "")
        assert is_triaged(db, acct, "") is False

    def test_isolation_across_accounts(self, db, regular_user, admin_user):
        a1 = self._acct(db, regular_user)
        a2 = create_email_account(
            db, admin_user["id"], "ACCT2", "imap", {"host": "y"},
        )
        mark_triaged(db, a1, "<shared@id>")
        assert is_triaged(db, a1, "<shared@id>") is True
        assert is_triaged(db, a2, "<shared@id>") is False


class TestTrim:
    def test_prune_old_rows(self, db, regular_user):
        acct = create_email_account(
            db, regular_user["id"], "T", "imap", {"host": "x"},
        )
        # Insert one fresh + one stale (101 days old).
        from email_triage.web.db import _hash_msg_id as _h
        old_iso = (datetime.now(timezone.utc) - timedelta(days=101)).isoformat()
        new_iso = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO triaged_messages (account_id, msg_id_hash, ts) VALUES (?, ?, ?)",
            (acct, _h(acct, "<old@x>"), old_iso),
        )
        db.execute(
            "INSERT INTO triaged_messages (account_id, msg_id_hash, ts) VALUES (?, ?, ?)",
            (acct, _h(acct, "<new@x>"), new_iso),
        )
        db.commit()
        deleted = prune_triaged_messages(db, retention_days=90)
        assert deleted == 1
        assert is_triaged(db, acct, "<old@x>") is False
        assert is_triaged(db, acct, "<new@x>") is True

    def test_prune_no_op_when_clean(self, db, regular_user):
        acct = create_email_account(
            db, regular_user["id"], "T", "imap", {"host": "x"},
        )
        mark_triaged(db, acct, "<recent@x>")
        deleted = prune_triaged_messages(db, retention_days=90)
        assert deleted == 0
        assert is_triaged(db, acct, "<recent@x>") is True
