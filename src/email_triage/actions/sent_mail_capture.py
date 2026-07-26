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
from email_triage.web.db_writelock import get_write_lock

log = get_logger("actions.sent_mail_capture")


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


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
        # run18  (PD#5): coerce through the
        # normalize_sent_folder_override SSOT — the strip/drop-blank/
        # legacy-scalar contract lives in ONE place, so a future caller
        # that does NOT pre-normalize stays safe (the old inline loop
        # iterated a bare str into its characters).
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        self._sent_folders: tuple[str, ...] = tuple(
            normalize_sent_folder_override(sent_folders)
        )
        # the backlog  (2026-07-12): memoize the N-402 auto-detected
        # IMAP Sent folder across scans within THIS loop instance's
        # lifetime. Saves one `LIST "" "*"` round-trip per sweep tick on
        # IMAP-no-`sent_folders` accounts. Persists ONLY across the loop
        # instance (a new loop instance re-detects); no cross-process
        # state, no invalidation logic needed. Set once on first
        # successful auto-detect; None means "not yet auto-detected".
        self._auto_detected_sent_folder: str | None = None

    # -- account-state helpers ---------------------------------------------

    def _account_row(self) -> dict | None:
        #  — hold the process-wide DB write lock for the shared-
        # connection read. Callers reach this via db_call (which already
        # holds the lock); the RLock is reentrant, so the in-method
        # acquire is correct regardless of caller and clears the 
        # connection-holding-class ratchet.
        with get_write_lock():
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
        #  — scan_recent is awaited from the sent-mail-capture loop
        # on the event-loop thread. _hipaa_short_circuit + the
        # _captured_row_count reads touch the shared connection, so
        # dispatch them off-loop via db_call.
        from email_triage.web.db_threadpool import db_call
        if await db_call(self._hipaa_short_circuit, "scan_recent"):
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
        # N-82 (Defect A) — import the auth-revoked classifier so the
        # per-folder and fallback search exception handlers can distinguish
        # a dead-token failure (re-raise → reaches the sweeper's SET edge)
        # from a genuinely transient error (swallow → return 0 as before).
        from email_triage.web._auth_revoked import is_auth_revoked_exc

        seen: set[str] = set()
        merged_pairs: list[tuple[str, str]] = []  # (folder, uid)
        try:
            # the backlog  (2026-07-12): auto-detect Sent folder on IMAP
            # via find_sent_folder SSOT (RFC 6154 SPECIAL-USE + name fallback
            # against Sent / INBOX.Sent / Sent Items / Sent Messages) so the
            # operator-config-populate step becomes optional. On IMAP with
            # no operator-configured `sent_folders`, promote the detected
            # folder into a per-scan `folders_to_walk` tuple; do NOT mutate
            # `self._sent_folders` — auto-detect is per-scan, so an operator
            # who later configures explicit `sent_folders` overrides it
            # cleanly. find_sent_folder never raises and always returns a
            # str (default "Sent" if no probe matched); if that string
            # names a folder that doesn't exist, the per-folder SELECT
            # below fails and the existing per-folder warn+continue net
            # handles it — no worse than N-390's pre-fix warn+return_0
            # posture. Replaces N-390's caller-side skip (§4.19 register).
            folders_to_walk: tuple[str, ...] = self._sent_folders
            if not folders_to_walk:
                from email_triage.providers.imap import ImapProvider

                if isinstance(self._provider, ImapProvider):
                    if self._auto_detected_sent_folder is None:
                        from email_triage.providers.sent_folder import (
                            find_sent_folder,
                        )
                        self._auto_detected_sent_folder = (
                            await find_sent_folder(self._provider)
                        )
                        log.info(
                            "sent_mail_capture: auto-detected IMAP Sent folder",
                            account_id=self._account_id,
                            folder=self._auto_detected_sent_folder,
                        )
                    folders_to_walk = (self._auto_detected_sent_folder,)

            if folders_to_walk:
                from email_triage.engine.models import MailFilter
                for folder in folders_to_walk:
                    try:
                        part = await self._provider.search(
                            "in:sent", limit,
                            filter=MailFilter(folder=folder),
                        )
                    except Exception as exc:
                        # N-82 — auth-revoked: propagate so the sweeper's
                        # except-scan_err branch SETs the auth_stale chip.
                        # Transient errors are swallowed (continue) as before.
                        if is_auth_revoked_exc(exc):
                            raise
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
                # Non-IMAP fallback (Gmail-API / O365): `"in:sent"` is
                # honored natively by these providers' server-side search
                # (Gmail via X-GM-RAW; Graph via well-known folder scoping).
                # The translator-SSOT reject in `translate_imap_query_to_imap`
                # (N-390) is the defense-in-depth peer to this caller-side
                # correct behavior on non-IMAP providers.
                fallback_ids = await self._provider.search("in:sent", limit)
                merged_pairs = [
                    ("", mid) for mid in (fallback_ids or [])
                ]
        except Exception as exc:
            # N-82 — auth-revoked escapes the inner try (via re-raise above
            # or from the fallback search): propagate so the sweeper SETs the
            # chip. Transient errors are still swallowed → return 0.
            if is_auth_revoked_exc(exc):
                raise
            log.warning(
                "sent_mail_capture: provider search failed",
                account_id=self._account_id,
                error_type=type(exc).__name__,
            )
            return 0

        before = await db_call(self._captured_row_count)
        for folder, mid in merged_pairs:
            try:
                if folder:
                    msg = await self._provider.fetch_message(
                        mid, folder=folder,
                    )
                else:
                    msg = await self._provider.fetch_message(mid)
            except Exception as exc:
                # #1 (census run16) — auth-revoked on the FETCH leg must
                # propagate like the SEARCH leg already does (N-82), so the
                # sweeper SETs the auth_stale chip instead of swallowing the
                # dead-token error and letting the success path CLEAR it (a
                # wrong CLEAR on a revoked credential masks re-auth). Transient
                # errors are still swallowed (continue) as before.
                if is_auth_revoked_exc(exc):
                    raise
                log.warning(
                    "sent_mail_capture: fetch failed; continuing",
                    message_id=mid,
                    folder=folder,
                    error_type=type(exc).__name__,
                )
                continue
            await self.index_captured_pair(msg)

        #  —  wrapped the `before` read above in db_call but
        # left this closing count as a raw on-loop touch. Route it off
        # the loop too, same as `before`.
        after = await db_call(self._captured_row_count)
        return max(0, after - before)

    def _captured_row_count(self) -> int:
        #  — hold the process-wide DB write lock for the shared-
        # connection read. db_call (the dispatching caller) already
        # holds the reentrant lock; the in-method acquire makes the
        # method correct regardless of caller and clears the  ratchet.
        with get_write_lock():
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
        #  —  wrapped the scan_recent call of
        # _hipaa_short_circuit in db_call but left this one a raw
        # on-loop touch. _hipaa_short_circuit reads the shared
        # connection (via _account_row), so dispatch it off-loop.
        from email_triage.web.db_threadpool import db_call
        if await db_call(self._hipaa_short_circuit, "index_captured_pair"):
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
