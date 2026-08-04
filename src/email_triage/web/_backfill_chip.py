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
  * the per-account ``backfill_capped`` chip lifecycle (set on
    saturation, read for display, clear on dismiss / account delete).

Fail-soft by contract: a chip write must never abort an ingestion
recovery (the recovery matters more than the breadcrumb), so every
public function swallows its own storage errors.
"""

from __future__ import annotations

from typing import Any

# Single source of truth for the bounded-backfill ceiling. The three
# cursor-expiry recovery sites import THIS rather than hardcoding 200,
# so raising/lowering the cap (or pinning it) happens in one place.
BACKFILL_CAP = 200


def _now_iso() -> str:
    # Canonical timestamp SSOT — import direct from _isotime (web.app
    # only re-exports it), keeping the reference one hop from source.
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def mark_backfill_capped(
    db, account_id: int, *, kind: str, window: str, recovered: int,
    source_mailbox: str | None = None,
) -> None:
    """Flag that a cursor-expiry recovery for ``account_id`` saturated
    the backfill cap. ``kind`` is ``"gmail_history"`` or
    ``"o365_resync"``; ``window`` is a human string (e.g. ``"last 7
    days"`` / ``"most recent"``); ``recovered`` is how many the bounded
    walk pulled (``== BACKFILL_CAP`` when saturated).

    N-211 R23 (2026-07-02): ``source_mailbox`` records WHICH mailbox
    raised the chip so a sibling mailbox's success-clear can't wipe
    it (see :func:`clear_backfill_capped`). Optional — legacy callers
    that pass no mailbox get an unscoped chip that any clear will
    remove (pre-N-211 behavior; backward-compat).

    Idempotent: overwrites any prior chip with the latest occurrence.
    Never raises — a failed breadcrumb must not abort the recovery."""
    try:
        from email_triage.web.db import set_setting
        from email_triage.web import settings_keys as _S
        payload: dict[str, Any] = {
            "at": _now_iso(),
            "kind": str(kind),
            "window": str(window),
            "recovered": int(recovered),
            "cap": BACKFILL_CAP,
        }
        if source_mailbox is not None:
            payload["source_mailbox"] = str(source_mailbox)
        set_setting(db, _S.backfill_capped(int(account_id)), payload)
    except Exception:
        pass


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
) -> None:
    """Clear the chip (operator dismiss / account delete / success
    reconnect). Cheap: reads first and only deletes when present, so a
    no-op dismiss doesn't write-amplify the settings table. Never raises.

    N-211 R23 (2026-07-02): ``source_mailbox`` — when supplied, only
    clear if the stored chip was set by THIS mailbox (i.e., the chip's
    payload ``source_mailbox`` matches) OR carries no source (legacy).
    Prevents sibling mailbox reconnect-success from wiping the chip a
    peer mailbox just raised (§164.502(a)(1) un-triaged-PHI-in-gap
    signal cross-scope race, census run23 R23_3). Operator dismiss +
    account delete + generic clears pass no ``source_mailbox`` → clear
    unconditionally (pre-N-211 behavior)."""
    try:
        from email_triage.web.db import get_setting, delete_setting
        from email_triage.web import settings_keys as _S
        key = _S.backfill_capped(int(account_id))
        chip = get_setting(db, key)
        if chip is None:
            return
        # N-211: gate cross-mailbox clears.
        if source_mailbox is not None and isinstance(chip, dict):
            stored = chip.get("source_mailbox")
            if stored is not None and stored != str(source_mailbox):
                # A different mailbox raised this chip — don't wipe it
                # from a peer mailbox's success path.
                return
        delete_setting(db, key)
    except Exception:
        pass
