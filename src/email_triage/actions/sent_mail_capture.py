"""Edit-feedback capture loop (M-6).

Continuous-learning hook for the draft-reply path. When the user
edits + sends an AI-drafted reply, the SENT version becomes a
"gold standard" example -- it shows what AI got right and what the
user corrected. M-6 scans the user's Sent folder for messages
carrying the ``X-Email-Triage: draft-reply`` header (stamped by
:class:`DraftReplyAction` on every draft it creates), pulls the
original AI-drafted body out of the sibling ``X-Email-Triage-Draft-Body``
header, and feeds the (draft, sent) pair into:

* :class:`SentMailIndex` (M-4 RAG store) as a row flagged
  ``is_captured_pair=1``. The retrieval ranker boosts captured rows
  ahead of equivalent general sent mail at draft time -- captured
  pairs carry a stronger style signal because the user reviewed,
  edited, and sent them.
* the M-3 distillation pool, indirectly, via the next
  ``style-profile build`` pass which prefers captured rows when
  assembling the corpus.

Privacy contract reaffirmed
===========================

* HIPAA-flagged accounts are hard-off at every public method on
  :class:`SentMailCaptureLoop`. The scanner does not call the
  provider, does not embed, does not write a row. Defence in depth:
  ``index_captured_pair`` re-checks the gate so a misconfigured
  caller can't bypass it.
* The ``X-Email-Triage-Draft-Body`` header is plaintext at draft
  time but ONLY consumed (parsed + indexed) when the source
  account is non-HIPAA. The header still rides on every draft
  regardless -- an operator who flips an account to HIPAA after
  the draft was created sees the header on the sent message but
  M-6 refuses to act on it.
* Idempotency: ``(account_id, rfc_message_id)`` is the dedup key
  on ``sent_mail_index``. Re-scanning the same Sent folder after a
  prior pass is a no-op -- already-captured rows are left alone
  by the underlying ``INSERT OR IGNORE``.

Header parse rules
==================

* Old messages (drafted before M-6 shipped, or drafts where the
  header encoder failed) lack the ``X-Email-Triage-Draft-Body``
  header. They are skipped silently -- there is nothing to compare
  against, so no captured pair is recorded.
* Header value is base64-encoded UTF-8 plaintext. Decode failures
  log a warning and skip; they never raise.
* The capture is "compare draft vs sent and capture the SENT
  version." The draft body is read from the header for forensics
  / future use, but the body indexed in the M-4 store is the body
  the user actually sent (the ``EmailMessage.body_text`` of the
  scanned message).

Cron-anchored loop
==================

The background task in :func:`web.app._sent_mail_capture_loop` ticks
every ``style_learning.capture_interval_hours`` hours (default 6),
anchored to wall-clock multiples of that interval with 0-300s of
random jitter so a 50-install fleet doesn't hammer Sent folders at
the same instant.
"""

from __future__ import annotations

import base64  # noqa: F401  -- imported for clarity even though decoding lives in mail_headers
import sqlite3
from datetime import datetime, timezone
from typing import Any

from email_triage.engine.models import EmailMessage
from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_DRAFT_BODY_HEADER,
    X_EMAIL_TRIAGE_HEADER,
    decode_draft_body_header,
    get_draft_body_header,
    get_triage_header,
)
from email_triage.triage_logging import get_logger, is_account_hipaa

log = get_logger("actions.sent_mail_capture")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# SentMailCaptureLoop
# ---------------------------------------------------------------------------

class SentMailCaptureLoop:
    """Per-account scanner for AI-drafted-then-edited sent messages.

    Construction is cheap (no IO). The first call to a public method
    short-circuits when the account is HIPAA-flagged. Caller supplies
    a provider (so tests can stub it) and a :class:`SentMailIndex`
    instance (so the same backend / model state already wired into
    M-4 retrieval drives captured-pair writes).
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        account_id: int,
        *,
        provider: Any,
        sent_mail_index: Any,
        sent_folders: list[str] | None = None,
    ) -> None:
        self._db = db
        self._account_id = int(account_id)
        self._provider = provider
        self._index = sent_mail_index
        # 2026-05-11 — multi-folder override. When non-empty, scan_recent
        # runs one search() per folder via MailFilter (IMAP SELECTs each
        # in turn) and merges the results — lets the operator fan
        # learning across Sent + Sent Items + Drafts-That-Were-Sent +
        # etc. Empty/None falls through to the provider's default
        # mailbox + "in:sent" query. Stored as a tuple so the value is
        # immutable across the loop lifetime.
        cleaned: list[str] = []
        if sent_folders:
            for f in sent_folders:
                if isinstance(f, str) and f.strip():
                    cleaned.append(f.strip())
        self._sent_folders: tuple[str, ...] = tuple(cleaned)

    # -- account-state helpers ---------------------------------------------

    def _account_row(self) -> dict | None:
        cur = self._db.execute(
            "SELECT id, hipaa, created_under_system_hipaa "
            "FROM email_accounts WHERE id = ?",
            (self._account_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        if hasattr(row, "keys"):
            return {k: row[k] for k in row.keys()}
        return {
            "id": row[0],
            "hipaa": row[1],
            "created_under_system_hipaa": row[2],
        }

    def _hipaa_short_circuit(self, op: str) -> bool:
        """Return True when ``op`` MUST NOT proceed for this account.

        Sister gate to the one in :class:`SentMailIndex`. Logs once
        per call so an operator debugging "why no captured pairs?"
        sees a readable answer.
        """
        acct = self._account_row()
        if acct is None:
            log.info(
                "sent_mail_capture: account not found",
                op=op, account_id=self._account_id,
            )
            return True
        if is_account_hipaa(acct):
            log.info(
                "sent_mail_capture: HIPAA-flagged account, skipping",
                op=op, account_id=self._account_id,
            )
            return True
        return False

    # -- scan_recent -------------------------------------------------------

    async def scan_recent(self, *, limit: int = 50) -> int:
        """Pull recent Sent-folder messages and capture any AI-drafted-
        then-edited pairs.

        Walks the provider's ``in:sent`` query (limited to ``limit``
        messages so a freshly-shipped install on a heavy mailbox
        doesn't pull the entire Sent folder on the first tick).
        For each message, checks for the ``X-Email-Triage: draft-reply``
        + ``X-Email-Triage-Draft-Body`` header pair. When both are
        present and the body decodes cleanly, calls
        :meth:`index_captured_pair`.

        Returns the number of newly-captured rows. Idempotent: a
        second call over the same Sent-folder snapshot returns 0
        (the dedup key on ``sent_mail_index`` short-circuits already-
        seen messages).

        The provider's ``search`` query string is provider-dependent
        (Gmail ``in:sent``, IMAP ``ALL`` against a Sent mailbox,
        Graph ``$filter``). The caller is expected to have configured
        the provider so ``in:sent`` lands in the correct folder; if
        it doesn't, the scanner simply finds zero matching headers
        and writes zero rows -- no privacy impact, just a no-op.
        """
        if self._hipaa_short_circuit("scan_recent"):
            return 0
        if self._provider is None:
            log.warning(
                "sent_mail_capture: no provider supplied to scan_recent",
                account_id=self._account_id,
            )
            return 0

        # Provider-agnostic folder switch via MailFilter — IMAP SELECTs
        # the folder per call, Gmail/O365 ignore ``filter.folder`` (they
        # route Sent via in:sent / well-known folder ids). When the
        # operator picked multiple folders we run one search per folder
        # and merge ids preserving first-seen order. Duplicates across
        # folders are filtered out so we don't fetch+capture the same
        # message twice in a single tick.
        #
        # 2026-05-13 root cause — UIDs are mailbox-scoped per RFC 3501
        # § 2.3.1.1; pair each UID with its source folder so the
        # subsequent fetch_message hits the right mailbox.
        seen: set[str] = set()
        merged_pairs: list[tuple[str, str]] = []  # (folder, uid)
        try:
            if self._sent_folders:
                from email_triage.engine.models import MailFilter
                for folder in self._sent_folders:
                    try:
                        part = await self._provider.search(
                            "in:sent", limit,
                            filter=MailFilter(folder=folder),
                        )
                    except Exception as exc:
                        log.warning(
                            "sent_mail_capture: provider search failed "
                            "(continuing with other folders)",
                            account_id=self._account_id,
                            folder=folder,
                            error_type=type(exc).__name__,
                        )
                        continue
                    for mid in part or ():
                        if mid not in seen:
                            seen.add(mid)
                            merged_pairs.append((folder, mid))
            else:
                fallback_ids = await self._provider.search("in:sent", limit)
                merged_pairs = [
                    ("", mid) for mid in (fallback_ids or [])
                ]
        except Exception as exc:
            log.warning(
                "sent_mail_capture: provider search failed",
                account_id=self._account_id,
                error_type=type(exc).__name__,
            )
            return 0

        before = self._captured_row_count()
        for folder, mid in merged_pairs:
            try:
                if folder:
                    msg = await self._provider.fetch_message(
                        mid, folder=folder,
                    )
                else:
                    msg = await self._provider.fetch_message(mid)
            except Exception as exc:
                log.warning(
                    "sent_mail_capture: fetch failed; continuing",
                    message_id=mid,
                    folder=folder,
                    error_type=type(exc).__name__,
                )
                continue
            await self.index_captured_pair(msg)

        return max(0, self._captured_row_count() - before)

    def _captured_row_count(self) -> int:
        cur = self._db.execute(
            "SELECT COUNT(*) AS n FROM sent_mail_index "
            "WHERE account_id = ? AND is_captured_pair = 1",
            (self._account_id,),
        )
        row = cur.fetchone()
        if row is None:
            return 0
        return int(row["n"] if hasattr(row, "keys") else row[0])

    # -- index_captured_pair ----------------------------------------------

    async def index_captured_pair(self, message: EmailMessage) -> bool:
        """Inspect ``message``; if it's an AI-drafted-then-edited pair,
        write a captured row to ``sent_mail_index``.

        Returns ``True`` when a captured row was indexed (or attempted),
        ``False`` when the message did not qualify (missing headers,
        not a draft-reply source, body decode failure, HIPAA gate).
        Idempotent: a second call on a message whose
        ``rfc_message_id`` is already in the index is a no-op.
        """
        if self._hipaa_short_circuit("index_captured_pair"):
            return False

        # Defence in depth: even if a HIPAA flag was missed, the
        # scanner refuses messages explicitly tagged hipaa=True at
        # fetch time. Providers set this when system_hipaa is on or
        # the source account is flagged.
        if bool(getattr(message, "hipaa", False)):
            log.info(
                "sent_mail_capture: message marked hipaa, skipping",
                account_id=self._account_id,
                message_id=getattr(message, "message_id", ""),
            )
            return False

        # Look for the source tag.
        triage = get_triage_header(message.headers or {})
        if not triage:
            return False
        # Source field is the first ``;``-separated token. Anything
        # else (digest / otp / health-email) is not a captured pair
        # candidate.
        source = (triage or "").split(";", 1)[0].strip()
        if source != "draft-reply":
            return False

        # Pull the snapshot of the original AI-drafted body.
        encoded = get_draft_body_header(message.headers or {})
        if not encoded:
            # Old draft (M-6 ship predates this) -- skip silently.
            return False
        draft_body = decode_draft_body_header(encoded)
        if not draft_body:
            log.warning(
                "sent_mail_capture: draft-body header decode failed",
                account_id=self._account_id,
                message_id=getattr(message, "message_id", ""),
            )
            return False

        # The actual sent body lives on the message itself. Empty
        # bodies short-circuit -- nothing to capture.
        if not (message.body_text or "").strip():
            return False

        # Hand off to the M-4 store with the captured-pair flag set.
        # SentMailIndex.index_message does its own HIPAA gate +
        # dedup; we've already checked HIPAA above, but the second
        # gate is the safety net.
        try:
            await self._index.index_message(
                message, is_captured_pair=True,
            )
        except Exception as exc:
            log.warning(
                "sent_mail_capture: index_message failed",
                account_id=self._account_id,
                message_id=getattr(message, "message_id", ""),
                error_type=type(exc).__name__,
            )
            return False
        return True


__all__ = [
    "SentMailCaptureLoop",
]
