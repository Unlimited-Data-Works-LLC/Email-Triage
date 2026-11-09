"""Digest resend-interval idempotence window — SSOT (divergence census run15, HIGH).

A digest must not RE-send within ``MIN_RESEND_INTERVAL_HOURS`` of its last send:
the duplicate-suppression gate on the delivery path. Two copies of this guard had
drifted three ways (census run15 #1):

* ``recipient_digest.should_fire`` parsed ``last_sent`` with a RAW
  ``datetime.fromisoformat`` (bypassing the ``_isotime.parse_iso`` SSOT) and
  normalized only ``last_dt`` to aware-UTC;
* ``digest_filter.digest_should_fire`` used ``parse_iso`` but normalized only the
  ``now`` operand.

So each normalized the OPPOSITE operand — and a naive-vs-aware subtraction RAISES
``TypeError`` (Python refuses ``aware - naive``). recipient_digest crashed when
``now`` was naive; digest_filter crashed when ``last_sent`` was naive. Plus the
``= 23`` interval constant was duplicated in both modules.

This funnel is the single source: parse via ``parse_iso``, normalize BOTH operands
to aware-UTC before subtracting (so neither side can raise), one constant. Pinned
by ``tests/test_digest_resend_ssot_pin.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from email_triage._isotime import parse_iso

#: Minimum hours between two sends of the same digest. 23 (not 24) tolerates a
#: scheduler that fires a few minutes early on the next day without suppressing it.
MIN_RESEND_INTERVAL_HOURS = 23


def _as_aware_utc(dt: datetime) -> datetime:
    """A naive datetime is assumed UTC; an aware one is left as-is. So both
    operands of the elapsed-time subtraction are aware (no ``aware - naive``
    TypeError) AND a naive timestamp is interpreted consistently (UTC)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def resend_too_soon(
    last_sent_iso: str | None,
    now: datetime,
    interval_hours: float = MIN_RESEND_INTERVAL_HOURS,
) -> bool:
    """True iff a resend RIGHT NOW would be a premature DUPLICATE — i.e. the last
    send was less than ``interval_hours`` ago. The caller suppresses the send when
    this is True.

    Returns False (do NOT suppress) when there is no recorded prior send, or the
    stored timestamp is unparseable — "unknown last-send" must not block a send.
    BOTH ``now`` and the parsed ``last_sent`` are normalized to aware-UTC, so a
    naive-vs-aware mismatch (the census run15 #1 crash) cannot raise.

    CONTRACT (the DA review of run15 #1): ``now`` MUST be tz-aware — the live
    callers pass ``datetime.now().astimezone()``. A NAIVE ``now`` is interpreted as
    UTC, NOT as local time, so passing a naive LOCAL clock would shift the elapsed
    by your UTC offset (a premature / delayed resend). The aware-UTC normalization
    is the no-crash guarantee, NOT a local→UTC converter.
    """
    if not last_sent_iso:
        return False
    last_dt = parse_iso(last_sent_iso)
    if last_dt is None:
        return False
    elapsed_hours = (_as_aware_utc(now) - _as_aware_utc(last_dt)).total_seconds() / 3600.0
    return elapsed_hours < interval_hours
