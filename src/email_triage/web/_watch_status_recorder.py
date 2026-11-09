"""Watch-status recorder SSOT (N-213 R23 — census run23 R23_4 discovered
class, 2026-07-02).

Census R23_4 (HIGH — operator-surface `/watch/status` reliability): the
`WatcherManager._mb_state` dict has 4 per-mailbox counter fields
(`processed`, `errors`, `last_message`, `last_error`), but only the IMAP
IDLE watcher path writes them (2 sites in `watcher.py:1811+1965`). The
other 5 ingestion siblings (Gmail push, Gmail poll, O365 push, O365 poll,
IMAP poll) never write. `/watch/status` therefore LIES for every non-IMAP
account: `processed` stays 0, operator can't tell if the watcher is
actually processing mail.

SSOT: one function `record_message_result(manager, account_id, source, *,
success, message, error)` per per-message ingestion path.

This module is the SSOT FUNNEL — the interprocedural pin
(`tests/test_n213_watch_status_recorder_pin.py`) key on this function name
so the 5 ingestion siblings + any future path all route through it.

The recorder degrades gracefully — a `None` manager is a no-op, so callers
that legitimately don't have a WatcherManager in scope (batch reindex,
one-off classify) don't need conditional guarding.

Follow-up (N-213b): migrate the 5 ingestion sibling paths + the 2
existing watcher.py sites to route through this SSOT. Deferred as a
larger migration cycle.
"""
from __future__ import annotations

from typing import Any


def record_message_result(
    manager: Any,
    account_id: int,
    mailbox: str,
    source: str,
    *,
    success: bool,
    message_id: str | None = None,
    error: str | Exception | None = None,
    sender: str | None = None,
    subject: str | None = None,
    category: str | None = None,
    confidence: float | None = None,
    account_hipaa: bool = False,
) -> None:
    """Record a per-message ingestion outcome onto the manager's per-mailbox
    state so `/watch/status` reflects reality.

    Parameters:
        manager: `WatcherManager` (or None for a no-op).
        account_id: the account whose mailbox produced the message.
        mailbox: the mailbox name / primary key (canonical for the provider).
        source: one of "imap-idle", "imap-poll", "gmail-push", "gmail-poll",
            "o365-push", "o365-poll" — the ingestion path.
        success: True when the message was ingested + classified without
            error; False when either failed.
        message_id: optional; stored in `last_message` on success.
        error: optional; stringified into `last_error` on failure.

    No-op when `manager` is None. Never raises — a failed telemetry write
    must not abort a real ingestion path.
    """
    if manager is None:
        return
    try:
        state = manager._get_mb_state(int(account_id), str(mailbox))
    except Exception:
        return
    try:
        if success:
            state["processed"] = int(state.get("processed", 0)) + 1
            # N-257 R26 PD#18: clear the failure edges on success.
            # Before: only `_mark_recovered` (N-246) cleared `errors` /
            # `last_error`, but the per-message success path here left
            # them stale. Result: `_aggregate_status` picked up the
            # OLDEST `last_error` on the account and stickied it into
            # `/watch/status` + /health + dashboard chip. Both edges
            # of the last_error flag now route through THIS funnel too.
            state["last_error"] = None
            state["errors"] = 0
            if message_id is not None:
                # N-221 R22 (2026-07-02): dict shape matches the reader
                # contract `_aggregate_status` in watcher.py — the reader
                # calls `lm.get("at", "")` for recency comparison. Before
                # N-221 the recorder wrote a plain str, so `/watch/status`,
                # /health, and the dashboard chip crashed with
                # AttributeError: 'str' object has no attribute 'get'
                # on any account whose ingestion routed through this SSOT.
                # id is stringified; at is ISO-UTC (canonical /watch key).
                from email_triage._isotime import now_utc_iso
                # N-261 R26: widen the SSOT to accept rich last_message
                # fields. Callers pass RAW sender/subject/category/
                # confidence + the per-account HIPAA verdict; the SSOT
                # scrubs PHI at the source (matches the IDLE-path
                # `_watch_status_phi` semantics — REDACTED sentinel
                # preserves subject[:60]/|length template ops).
                lm: dict[str, Any] = {
                    "id": str(message_id),
                    "at": now_utc_iso(),
                    "mailbox": str(mailbox),
                    "source": str(source),
                }
                if sender is not None or subject is not None:
                    if account_hipaa:
                        from email_triage.triage_logging import REDACTED
                        lm["sender"] = REDACTED
                        lm["subject"] = REDACTED
                    else:
                        if sender is not None:
                            lm["sender"] = sender
                        if subject is not None:
                            lm["subject"] = subject or ""
                if category is not None:
                    lm["category"] = category
                if confidence is not None:
                    lm["confidence"] = confidence
                state["last_message"] = lm
        else:
            state["errors"] = int(state.get("errors", 0)) + 1
            if error is not None:
                # N-213 R23 CI hotfix: route through fmt_exc SSOT (PHI-scrub +
                # ClassName: prefix) instead of the hand-rolled twin. The
                # `exc_render_twin_ssot_pin` guard flagged the raw
                # f"{type(X).__name__}: {X}" form as SSOT-drift; use fmt_exc.
                from email_triage._errfmt import fmt_exc
                state["last_error"] = (
                    str(error) if not isinstance(error, Exception)
                    else fmt_exc(error, with_class=True)
                )
        # Store the source so `/watch/status` can distinguish IMAP-IDLE
        # from Gmail-push etc. — pre-N-213 the surface didn't disambiguate.
        state["last_source"] = str(source)
    except Exception:
        pass
