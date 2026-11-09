"""HIPAA outbound-message counter loop.

Sister to :class:`email_triage.actions.sent_mail_capture.SentMailCaptureLoop`
but for HIPAA-flagged accounts. The non-HIPAA loop captures (draft, sent)
pairs for the M-4 RAG index + the M-6 edit-feedback signal — body data
that HIPAA mode must NOT store. This loop is the privacy-safe analog:
it walks the Sent folder, observes each message ONCE (dedup via salted
Message-ID hash), and increments the M-3 + M-7 threshold counters via
:func:`record_hipaa_sent_message_if_new`.

Why this loop exists
====================

The M-3 + M-7 style-distillation triggers fire on three events:

* **First-time** — account newly enabled for HIPAA style learning.
* **Stale refresh** — >7 days since last successful distill (M-3) or
  per-contact rebuild (M-7).
* **Threshold** — N new outbound messages since the last fire.

The first two run off DB state + timestamps, so they have always
fired for HIPAA accounts since -B shipped. The threshold trigger
needs an actual count of outbound messages — and that count had no
producer for HIPAA accounts (the non-HIPAA :class:`SentMailIndex` is
the producer for non-HIPAA accounts, but it explicitly excludes HIPAA
traffic by design — bodies can't be indexed).

This loop closes the gap. It is the threshold-counter producer for
HIPAA accounts.

Privacy contract
================

* **No body access.** The loop fetches each Sent-folder message to
  read its ``Message-ID`` header + ``recipients`` list — both
  metadata, not content. ``message.body_text`` is never read.
* **No plaintext metadata at rest.** The Message-ID hashes via
  :func:`hash_message_id_for_install` (salted HMAC-SHA-256) before
  it lands in ``hipaa_sent_dedup``. Each recipient hashes via
  :func:`hash_recipient_for_install` before it lands in
  ``hipaa_send_counters``. Both use the same per-install salt — a
  rotation invalidates dedup history AND counter rows consistently.
* **Inverse HIPAA gate.** The loop refuses to operate on non-HIPAA
  accounts — the non-HIPAA :class:`SentMailCaptureLoop` covers
  those. Defence in depth: the per-account gate runs on every
  public method.
* **Style-learning master + per-account opt-in.** The loop respects
  both the install-wide ``style_learning.enabled`` toggle and the
  per-account ``style_learning_enabled`` config flag. If the
  operator has not opted this account into style learning, the
  loop is a no-op regardless of HIPAA state — counters don't bump,
  dedup table doesn't grow.

Cron-anchored loop
==================

The HIPAA counter loop shares the cron schedule with
:func:`web.app._sent_mail_capture_loop` — every
``style_learning.capture_interval_hours`` hours (default 6) with
0-300s jitter. One sweep walks every active account, dispatching
non-HIPAA accounts to :class:`SentMailCaptureLoop` and HIPAA
accounts to this loop. Symmetric, cron-anchored, single source of
scheduling truth.

Idempotency
===========

Re-scanning the same Sent-folder snapshot is a no-op on the
counters — the ``hipaa_sent_dedup`` PK on
``(account_id, msgid_hash)`` short-circuits already-seen messages
inside :func:`record_hipaa_sent_message_if_new`. Each unique
outbound message increments the counters exactly once per
*stable-identity era* (or until the operator runs
:func:`reset_hipaa_send_counter` after a manual M-3 distill).

A6 (census 2026-06-09) routed the RFC Message-ID resolution through
``mail_headers.get_message_rfc_id`` (one casing authority). For an
IMAP ``Message-Id``-cased message that was already counted under the
provider-native id, the dedup key (``msgid_hash``) changes once at
the A6 deploy boundary — a single benign +1 re-count if it is still
inside the recent-scan window, self-stabilizing on the next sweep.
The counters are the M-3/M-7 style-distill threshold trigger
(N=20), not a §164.502(e) disclosure-accounting record, so a
one-cycle early re-distill is the only effect.
"""

from __future__ import annotations

from email_triage.db._helpers import load_json_col

import sqlite3
from typing import Any

from email_triage.engine.models import EmailMessage
from email_triage.triage_logging import get_logger, is_account_hipaa
from email_triage.web.db_writelock import get_write_lock

log = get_logger("actions.hipaa_sent_counter")


# ---------------------------------------------------------------------------
# HipaaSentCounterLoop
# ---------------------------------------------------------------------------

class HipaaSentCounterLoop:
    """Per-HIPAA-account Sent-folder scanner that bumps threshold counters.

    Construction is cheap (no IO). The first call to a public method
    short-circuits when the account is NOT HIPAA-flagged (inverse of
    :class:`SentMailCaptureLoop`'s gate) or when style learning is off.

    Caller supplies a provider (so tests can stub it) and a secrets
    backend (used for the install salt that hashes Message-IDs and
    recipients).
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        account_id: int,
        *,
        provider: Any,
        secrets: Any,
        sent_folders: list[str] | None = None,
    ) -> None:
        self._db = db
        self._account_id = int(account_id)
        self._provider = provider
        self._secrets = secrets
        # Same folder-override pattern as SentMailCaptureLoop:
        # operator can fan the scan across Sent + Sent Items +
        # Drafts-That-Were-Sent + etc. Empty/None falls through to
        # the provider default ("in:sent" against the default folder).
        # run18  (PD#5): route the coercion through the
        # normalize_sent_folder_override SSOT instead of an inline
        # strip, so the contract (strip, drop blanks, tolerate the
        # legacy scalar-string shape) lives in ONE place. A future
        # caller that does NOT pre-normalize stays safe — the old
        # inline loop iterated a bare str into its characters.
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
        # connection read. Callers dispatch this via db_call (which
        # already holds the lock), but the RLock is reentrant, so the
        # in-method acquire is correct-by-construction regardless of
        # caller and satisfies the  connection-holding-class ratchet.
        with get_write_lock():
            cur = self._db.execute(
                "SELECT id, hipaa, created_under_system_hipaa, config_json "
                "FROM email_accounts WHERE id = ?",
                (self._account_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        if hasattr(row, "keys"):
            d = {k: row[k] for k in row.keys()}
        else:
            d = {
                "id": row[0],
                "hipaa": row[1],
                "created_under_system_hipaa": row[2],
                "config_json": row[3],
            }
        # Parse config_json into config dict (matches the shape that
        # is_style_learning_account_enabled expects).
        import json
        try:
            d["config"] = load_json_col(d.get("config_json"), default={})
        except (ValueError, TypeError):
            d["config"] = {}
        return d

    def _non_hipaa_short_circuit(self, op: str) -> bool:
        """Return True when ``op`` MUST NOT proceed for this account.

        Inverse of :class:`SentMailCaptureLoop`'s gate:
          * No row OR not HIPAA-flagged → refuse.
          * Style learning disabled at master or per-account → refuse.
        """
        from email_triage.web.db import (
            is_style_learning_account_enabled,
            is_style_learning_master_enabled,
        )

        acct = self._account_row()
        if acct is None:
            log.info(
                "hipaa_sent_counter: account not found",
                op=op, account_id=self._account_id,
            )
            return True
        if not is_account_hipaa(acct):
            log.info(
                "hipaa_sent_counter: non-HIPAA account, refusing",
                op=op, account_id=self._account_id,
            )
            return True
        try:
            if not is_style_learning_master_enabled(self._db):
                log.info(
                    "hipaa_sent_counter: master style-learning toggle off",
                    op=op, account_id=self._account_id,
                )
                return True
        except Exception:
            # Defensive — treat any DB hiccup on the master read as
            # "off" so we never accidentally write rows for an install
            # whose operator has style learning disabled.
            return True
        if not is_style_learning_account_enabled(acct):
            log.info(
                "hipaa_sent_counter: per-account style-learning off",
                op=op, account_id=self._account_id,
            )
            return True
        return False

    # -- scan_recent -------------------------------------------------------

    async def scan_recent(self, *, limit: int = 50) -> int:
        """Pull recent Sent-folder messages and bump threshold counters.

        Walks the provider's ``in:sent`` query (limited to ``limit``
        messages per folder). For each message:

          1. Extract the RFC Message-ID from headers (fall back to the
             provider-native ``message.message_id`` if the header is
             missing — rare; some IMAP servers strip it).
          2. Hash via :func:`hash_message_id_for_install` (salted).
          3. Hash each recipient via
             :func:`hash_recipient_for_install` (salted; same salt).
          4. Call
             :func:`record_hipaa_sent_message_if_new` — bumps the
             aggregate + per-recipient counters when the message is
             new, no-ops when the message was seen on a prior scan.

        Returns the number of messages that bumped counters (NEW
        messages — already-deduped messages don't count).

        Idempotent: a second call over the same Sent-folder snapshot
        returns 0.
        """
        #  — _non_hipaa_short_circuit does shared-connection reads
        # (_account_row + is_style_learning_master_enabled); scan_recent
        # runs on the event-loop thread, so dispatch it off-loop.
        from email_triage.web.db_threadpool import db_call
        if await db_call(self._non_hipaa_short_circuit, "scan_recent"):
            return 0
        if self._provider is None:
            log.warning(
                "hipaa_sent_counter: no provider supplied to scan_recent",
                account_id=self._account_id,
            )
            return 0

        # Provider-agnostic folder switch via MailFilter — same pattern
        # as SentMailCaptureLoop (2026-05-13 UIDs-are-mailbox-scoped
        # fix; pair each id with its source folder).
        # N-82 (Defect A) — import the auth-revoked classifier so the
        # per-folder and fallback search exception handlers can distinguish
        # a dead-token failure (re-raise → reaches the sweeper's SET edge)
        # from a genuinely transient error (swallow → return 0 as before).
        # Using is_auth_revoked_exc rather than is_auth_revoked keeps the
        # call-site free of the (class_name, str) decomposition and keeps
        # the needle SSOT as the single source.
        from email_triage.web._auth_revoked import is_auth_revoked_exc

        seen: set[str] = set()
        merged_pairs: list[tuple[str, str]] = []  # (folder, uid)
        try:
            # the backlog  (2026-07-12): sibling fix to
            # ``sent_mail_capture.py`` — auto-detect Sent folder on IMAP
            # via find_sent_folder SSOT so operator-config-populate becomes
            # optional. HIPAA-relevance: this counter is HIPAA-scoped
            # (per-account compliance reporting), so N-390's warn+return_0
            # posture UNDER-REPORTED sent-mail compliance counts on any
            # IMAP account without explicit `sent_folders`. Auto-detect
            # CLOSES that under-report gap — the count now reflects real
            # activity on the auto-detected Sent folder instead of always
            # being zero. Falls back to the per-folder warn+continue net
            # if the detected folder doesn't exist (no worse than N-390).
            # See internal documentation §4.19 (N-390 skip class)
            # + the follow-up register row for the auto-detect landing.
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
                            "hipaa_sent_counter: auto-detected IMAP Sent folder",
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
                            "hipaa_sent_counter: provider search failed "
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
                # honored natively (Gmail via X-GM-RAW; Graph via
                # well-known folder scoping). Translator-SSOT reject in
                # `translate_imap_query_to_imap` (N-390) is the peer
                # defense-in-depth control.
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
                "hipaa_sent_counter: provider search failed",
                account_id=self._account_id,
                error_type=type(exc).__name__,
            )
            return 0

        new_count = 0
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
                # dead-token error and letting the success path CLEAR it (masks
                # re-auth on the very HIPAA accounts that most need the cue).
                # Transient errors are still swallowed (continue) as before.
                if is_auth_revoked_exc(exc):
                    raise
                log.warning(
                    "hipaa_sent_counter: fetch failed; continuing",
                    message_id=mid,
                    folder=folder,
                    error_type=type(exc).__name__,
                )
                continue
            if await self._record_one(msg):
                new_count += 1
        return new_count

    # -- per-message recorder ---------------------------------------------

    async def _record_one(self, message: EmailMessage) -> bool:
        """Hash + record one message. Returns True if counters bumped.

        Belt-and-braces HIPAA re-check: the constructor's gate runs at
        ``scan_recent`` entry, but a fetched message can carry its
        own ``hipaa=True`` flag set by the provider (per-message
        state). We rely on the account-level gate already passed at
        scan entry — and we WANT the message to be hipaa=True for a
        HIPAA account; that's the case we're counting.

        Returns False on missing Message-ID, missing recipients, hash
        failures, or dedup hit (already counted).
        """
        from email_triage.style_learning.per_contact_hipaa import (
            SaltUnavailableError,
            hash_message_id_for_install,
            hash_recipient_for_install,
        )
        from email_triage.web.db import record_hipaa_sent_message_if_new

        # A6 (census 2026-06-09): the message-level SSOT resolves the RFC
        # Message-ID in ANY header casing (was Message-ID/message-id only —
        # missing the IMAP ``Message-Id``), then falls back to the
        # provider-native id. One casing authority across all sent-mail
        # sites; no per-scan double-count from a missed casing.
        from email_triage.mail_headers import get_message_rfc_id
        rfc_id = get_message_rfc_id(message)
        if not rfc_id:
            log.info(
                "hipaa_sent_counter: message lacks any usable id, skipping",
                account_id=self._account_id,
            )
            return False

        # Recipients can be empty (rare — e.g. a draft mistakenly saved
        # into Sent with no To). Skip; nothing to count meaningfully.
        recipients = list(getattr(message, "recipients", None) or [])
        if not recipients:
            log.info(
                "hipaa_sent_counter: message has no recipients, skipping",
                account_id=self._account_id,
            )
            return False

        try:
            msgid_hash = hash_message_id_for_install(
                rfc_id, secrets=self._secrets,
            )
        except (ValueError, SaltUnavailableError) as exc:
            log.warning(
                "hipaa_sent_counter: msgid hash failed",
                account_id=self._account_id,
                error_type=type(exc).__name__,
            )
            return False

        recipient_hashes: list[str] = []
        for addr in recipients:
            if not addr or not isinstance(addr, str):
                continue
            try:
                recipient_hashes.append(
                    hash_recipient_for_install(addr, secrets=self._secrets),
                )
            except (ValueError, SaltUnavailableError) as exc:
                # Skip just this recipient — bad input shouldn't cost us
                # the whole message's count.
                log.info(
                    "hipaa_sent_counter: recipient hash failed, "
                    "continuing with remaining recipients",
                    account_id=self._account_id,
                    error_type=type(exc).__name__,
                )
                continue
        if not recipient_hashes:
            # Every recipient failed to hash — nothing meaningful to
            # record. Don't burn a dedup slot on it either; the next
            # scan can retry (e.g. if the salt was transiently
            # unavailable).
            return False

        try:
            #  — record_hipaa_sent_message_if_new is @db_write;
            # _record_one is awaited from scan_recent on the event-loop
            # thread, so dispatch the write through db_call.
            from email_triage.web.db_threadpool import db_call
            return await db_call(
                record_hipaa_sent_message_if_new,
                self._db,
                account_id=self._account_id,
                msgid_hash=msgid_hash,
                recipient_hashes=recipient_hashes,
            )
        except Exception as exc:
            log.warning(
                "hipaa_sent_counter: record failed",
                account_id=self._account_id,
                error_type=type(exc).__name__,
            )
            return False


__all__ = [
    "HipaaSentCounterLoop",
]
