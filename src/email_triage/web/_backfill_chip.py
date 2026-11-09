"""Bounded-backfill saturation chip.

When a provider's incremental cursor expires (Gmail ``historyId`` aged
out of the 7-day history window, or an O365 delta ``@odata.deltaLink``
returned ``410 resyncRequired``) the ingestion path falls back to a
*bounded* backfill — it walks at most ``BACKFILL_CAP`` of the most
recent messages, then reseeds the cursor to "now". That cap exists to
stop a runaway re-classify from burning LLM quota on a high-volume
mailbox.

The hazard the cap creates: if MORE than ``BACKFILL_CAP`` messages
accumulated in the gap, the excess is **never enumerated** — it is not
classified, not routed, and the idempotency keys can't recover what was
never walked. Before  this happened silently: a WARNING that didn't
distinguish "recovered N" from "recovered N and there were more", and no
operator-visible surface. Real mail could go un-triaged with no signal.

This module is the SSOT for:
  * ``BACKFILL_CAP`` — the single cap value all three resync sites share
    (Gmail push, O365 push, O365 poll), so the number can't drift; and
  * the per-account ``backfill_capped`` chip lifecycle: SET on a
    saturated cursor-expiry recovery or an IMAP UIDVALIDITY reseed;
    READ for display; CLEARED only by (a) the operator's dismiss,
    (b) account delete (the ``backfill_capped:`` account-key catalog
    entry), or (c) a recovery walk that provably enumerated the chip's
    whole mailbox (``FULL_WALK_KINDS``).

The chip is a LOSS RECORD, not a status flag (punch 854). The mail it
reports was skipped and stays skipped: a later successful poll, IDLE
connect, or a window-bounded walk processes NEW mail and recovers none
of the gap, so none of them is a clear edge for this record. Clearing on
one erased the only notice of un-triaged mail within one poll interval.

Fail-soft by contract: a chip write must never abort an ingestion
recovery (the recovery matters more than the breadcrumb), so every
public function catches its own storage errors. A failed mark or clear
is logged, not dropped (punch 854).
"""

from __future__ import annotations

from typing import Any

from email_triage.triage_logging import get_logger

log = get_logger("web.backfill_chip")

# Single source of truth for the bounded-backfill ceiling. The three
# cursor-expiry recovery sites import THIS rather than hardcoding 200,
# so raising/lowering the cap (or pinning it) happens in one place.
BACKFILL_CAP = 200

# Recovery walks whose NON-saturated result enumerated the account's whole
# mailbox, so every message an earlier gap skipped has now been walked.
# ``o365_resync``: ``search("ALL")`` is an unconstrained ``/me/messages``
# list, so fewer than BACKFILL_CAP + 1 ids is the entire mailbox. NOT
# ``gmail_history``: its walk is ``newer_than:7d``, which cannot reach mail
# an earlier gap skipped outside the current 7-day window. NOT
# ``imap_uidvalidity``: the reseed enumerates nothing.
FULL_WALK_KINDS = frozenset({"o365_resync"})

# Every kind a mark or a clear may name. Closed, so a misspelled kind fails
# the pin instead of silently matching nothing; FULL_WALK_KINDS is a subset.
BACKFILL_KINDS = frozenset({"gmail_history", "o365_resync", "imap_uidvalidity"})


async def probe_resync_walk(provider) -> tuple[list[str], bool]:
    """The O365 resync walk: up to ``BACKFILL_CAP`` ids, and whether it saturated.

    The one probe both O365 resync sites use. It is what makes
    ``o365_resync`` a full walk, so it follows ``@odata.nextLink``
    (``search_iter``) until it holds ``BACKFILL_CAP + 1`` ids or Graph has no
    more. A single ``search`` page drops the link, and Graph can return a short
    page with more pending, which read as "the whole mailbox" and cleared the
    chip while mail was still un-enumerated (punch 854, db-sme S1). Only
    ``> BACKFILL_CAP`` ids is saturation; the extra probe id is covered by the
    chip and the operator's full backfill. Errors propagate to the caller.
    """
    ids: list[str] = []
    walk = provider.search_iter("ALL", batch_size=BACKFILL_CAP + 1)
    try:
        async for batch, _cursor in walk:
            ids.extend(batch)
            if len(ids) > BACKFILL_CAP:
                break
    finally:
        await walk.aclose()
    return ids[:BACKFILL_CAP], len(ids) > BACKFILL_CAP


def _now_iso() -> str:
    # Canonical timestamp SSOT — import direct from _isotime (web.app
    # only re-exports it), keeping the reference one hop from source.
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def mark_backfill_capped(
    db, account_id: int, *, kind: str, window: str, recovered: int,
    source_mailbox: str | None = None,
) -> None:
    """Flag that a recovery for ``account_id`` skipped mail: a cursor-expiry
    walk saturated the backfill cap, or an IMAP UIDVALIDITY reseed skipped
    the gap. ``kind`` is one of :data:`BACKFILL_KINDS`; ``window`` is a human
    string (e.g. ``"last 7 days"`` / ``"most recent"``); ``recovered`` is how
    many the bounded walk pulled (``== BACKFILL_CAP`` when saturated, ``0``
    for a reseed).

    N-211 R23 (2026-07-02): ``source_mailbox`` records WHICH mailbox
    raised the chip so a sibling mailbox's success-clear can't wipe
    it (see :func:`clear_backfill_capped`). Optional — a chip stored with
    no mailbox (legacy, pre-N-211) is cleared only by the operator's
    unscoped dismiss (punch 854; it used to fall to any clear).

    Overwrites any prior chip with the latest occurrence. The key holds one
    chip per account, so when the prior chip came from a different
    ``(kind, source_mailbox)`` the new chip records NO mailbox: naming only
    the latest mailbox would let a later scoped clear erase the earlier
    gap's notice. Such a chip falls only to the operator's dismiss (punch
    854, fail-closed).

    Never raises — a failed breadcrumb must not abort the recovery."""
    try:
        from email_triage.web.db import get_setting, set_setting
        from email_triage.web import settings_keys as _S
        key = _S.backfill_capped(int(account_id))
        payload: dict[str, Any] = {
            "at": _now_iso(),
            "kind": str(kind),
            "window": str(window),
            "recovered": int(recovered),
            "cap": BACKFILL_CAP,
        }
        if source_mailbox is not None:
            prior = get_setting(db, key)
            if not isinstance(prior, dict) or (
                prior.get("source_mailbox") == str(source_mailbox)
                and prior.get("kind") == str(kind)
            ):
                payload["source_mailbox"] = str(source_mailbox)
        set_setting(db, key, payload)
    except Exception as exc:
        # The chip is the operator's only notice that mail was skipped, so
        # a lost write is logged at ERROR rather than dropped (punch 854).
        log.error(
            "backfill_capped chip write FAILED; skipped mail has no notice",
            account_id=account_id, kind=str(kind),
            error_class=type(exc).__name__,
        )


def get_backfill_capped(db, account_id: int) -> dict[str, Any] | None:
    """Return the chip payload for ``account_id`` or ``None`` if unset.
    Never raises."""
    try:
        from email_triage.web.db import get_setting
        from email_triage.web import settings_keys as _S
        return get_setting(db, _S.backfill_capped(int(account_id)))
    except Exception:
        return None


def clear_backfill_capped(
    db, account_id: int, *, source_mailbox: str | None = None,
    walk_kind: str | None = None,
) -> None:
    """Clear the chip. Two shapes only (punch 854):

    * UNSCOPED (``source_mailbox=None``): the operator's dismiss, after
      a whole-mailbox triage. Clears whatever chip is stored.
    * SCOPED (``source_mailbox=<mb>``): a recovery walk that did NOT
      saturate. Clears ONLY when ``walk_kind`` is in
      :data:`FULL_WALK_KINDS` (the walk enumerated the whole mailbox, so
      the gap is covered) AND the stored chip was raised by THIS mailbox
      (N-211 R23, census run23 R23_3: a sibling mailbox's success must
      not wipe a peer's chip). Anything else is refused, fail-closed: a
      chip with no ``source_mailbox`` (legacy, pre-N-211) or a walk that
      cannot prove coverage leaves the chip for the operator to dismiss.

    Cheap: reads first and only deletes when present, so a no-op clear
    doesn't write-amplify the settings table. Never raises."""
    try:
        from email_triage.web.db import get_setting, delete_setting
        from email_triage.web import settings_keys as _S
        key = _S.backfill_capped(int(account_id))
        chip = get_setting(db, key)
        if chip is None:
            return
        if source_mailbox is not None:
            if walk_kind not in FULL_WALK_KINDS:
                return
            stored = chip.get("source_mailbox") if isinstance(chip, dict) else None
            if stored is None or stored != str(source_mailbox):
                return
        delete_setting(db, key)
        if source_mailbox is not None:
            # The operator's dismiss is witnessed in access_log; an
            # automatic clear of the record of a gap leaves this trace
            # (punch 854, hipaa-sme S4).
            log.info(
                "backfill_capped chip cleared by a full recovery walk",
                account_id=account_id, walk_kind=str(walk_kind),
                chip_at=chip.get("at") if isinstance(chip, dict) else None,
            )
    except Exception as exc:
        # Fails toward keeping the chip; logged so a stuck chip is explicable.
        log.warning(
            "backfill_capped chip clear failed; chip left in place",
            account_id=account_id, error_class=type(exc).__name__,
        )
