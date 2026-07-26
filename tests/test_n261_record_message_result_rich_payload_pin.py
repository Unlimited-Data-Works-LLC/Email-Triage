"""N-261 R26 structural pin — record_message_result rich payload SSOT (2026-07-03).

Census R26 discovered MED (record_message_result thin last_message
payload): the SSOT signature took only `message_id` — no sender /
subject / category / confidence. IDLE path constructed the RICH shape
inline (via `_watch_status_phi`) — so a SSOT-written thin payload
with a fresher timestamp SILENTLY OVERWRITE a rich IDLE sibling's
value (reader `_aggregate_status` picks newest `at`). Visible chrome
degrades to blank.

N-261 fix: widen SSOT signature with optional kwargs `sender`,
`subject`, `category`, `confidence`, `account_hipaa`. PHI-scrub is
INSIDE the SSOT — callers pass RAW + hipaa verdict; SSOT redacts on
account_hipaa=True (using `triage_logging.REDACTED` sentinel that
preserves subject[:60]/|length template ops).

WHAT IT PINS (anti-vacuity):

1. SSOT signature accepts the 5 new kwargs.
2. HIPAA branch scrubs sender + subject via REDACTED.
3. Non-HIPAA branch passes raw sender/subject through.
"""
from __future__ import annotations


class _FakeMgr:
    def __init__(self):
        self.states = {}

    def _get_mb_state(self, account_id, mailbox):
        key = (account_id, mailbox)
        self.states.setdefault(key, {})
        return self.states[key]


def test_record_message_result_accepts_rich_payload():
    """SSOT accepts + persists the rich last_message shape."""
    from email_triage.web._watch_status_recorder import record_message_result
    m = _FakeMgr()
    record_message_result(
        m, 1, "INBOX", "imap-idle",
        success=True, message_id="msg1",
        sender="alice@ex.com", subject="Hi",
        category="urgent", confidence=0.9,
        account_hipaa=False,
    )
    lm = m.states[(1, "INBOX")]["last_message"]
    assert lm["sender"] == "alice@ex.com"
    assert lm["subject"] == "Hi"
    assert lm["category"] == "urgent"
    assert lm["confidence"] == 0.9


def test_record_message_result_hipaa_scrubs_phi():
    """HIPAA branch redacts sender + subject via REDACTED sentinel."""
    from email_triage.triage_logging import REDACTED
    from email_triage.web._watch_status_recorder import record_message_result
    m = _FakeMgr()
    record_message_result(
        m, 2, "INBOX", "imap-idle",
        success=True, message_id="msg2",
        sender="bob@ex.com", subject="patient info",
        account_hipaa=True,
    )
    lm = m.states[(2, "INBOX")]["last_message"]
    assert lm["sender"] == REDACTED
    assert lm["subject"] == REDACTED


def test_record_message_result_backwards_compat_thin_call():
    """Existing callers passing only message_id continue to work."""
    from email_triage.web._watch_status_recorder import record_message_result
    m = _FakeMgr()
    record_message_result(
        m, 3, "INBOX", "imap-poll",
        success=True, message_id="msg3",
    )
    lm = m.states[(3, "INBOX")]["last_message"]
    assert lm["id"] == "msg3"
    # No PHI fields since caller passed none.
    assert "sender" not in lm
    assert "subject" not in lm
