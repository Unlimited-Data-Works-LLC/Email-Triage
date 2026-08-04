"""N-263d R28 Gmail watch liveness SSOT (Census r27 row 13).

Census r27 discovered MED  (Gmail watch liveness triplicated):
`topic_name + expires_at > now` liveness check spread across 5 hand-roll
sites at 6 care levels (careful+tz / careful-no-tz / fromisoformat-no-tz
/ hours-based bucket / topic-only-by-design / topic-only-by-omission).
The LATENT crash surface (`datetime.fromisoformat` + no tz-normalize on
naive input → TypeError) was already CLOSED tree-wide by N-263 R27 +
N-357b R31 (`parse_iso_aware` SSOT, landed 2026-07-06). This module
lands the SSOT for the PREDICATE itself so the "is a Gmail push watch
live right now?" question has ONE home.

Contract
--------
Two SSOT primitives share the same underlying `expires_at` parse so a
UI helper that needs BOTH the liveness bool AND the parsed datetime
(e.g. a chip that renders "Push on (expires in N days)") does not
re-parse at the caller (devils-advocate N-263d panel must-fix on the
double-parse smell):

* ``is_gmail_watch_live(watch) -> bool`` — the predicate.
* ``gmail_watch_expiry(watch) -> datetime | None`` — the parsed UTC-
  aware datetime (or ``None`` for missing/blank/unparseable). Naive
  input is normalised to UTC via ``_isotime.parse_iso_aware``.

``is_gmail_watch_live(watch)`` returns ``True`` iff:

* ``watch`` is a dict-shaped row (``get_gmail_watch`` result or an
  equivalent record from ``list_gmail_watches``).
* ``watch['topic_name']`` is present + non-empty after strip.
* ``watch['expires_at']`` parses to a tz-aware UTC datetime that is in
  the FUTURE relative to ``datetime.now(timezone.utc)``.

The `topic_name` gate is deliberate: synthetic poll-mode rows (created
by B3 to give every account a `gmail_watches` row for status-reporting
symmetry) carry `topic_name=''` and the epoch-1970 expiry sentinel —
those must NOT report `live=True`.

Sites explicitly OUT-OF-SSOT (allow-listed) and why
---------------------------------------------------
* ``providers/dispatcher.py:_gmail_infer_push_enabled`` — topic-only by
  DESIGN (comment at that line): what we want is "operator intent" for
  the push-enabled inference, not liveness. An account whose watch has
  briefly expired (renewer catches it) still has `push_enabled=True`.
* ``web/watcher.py:_gmail_status`` — trichotomy (healthy / transient-
  grace / expired) with a grace window that DOES NOT collapse to a
  bool; the caller reports transient-grace ≠ inactive. This SSOT
  returns bool, so ``_gmail_status`` composes ``is_gmail_watch_live``
  with its own grace-window post-processing rather than replacing it.
* ``web/routers/health.py:_gmail_watch_counts`` — mirrors the
  watcher.py trichotomy (a stale watch with a poll fallback is not
  reported as stale). Composes similarly.
* ``web/routers/integrations.py:_hours_until`` / ``_watch_status`` —
  UI-facing hours-until-expiry math + 5-bucket status label
  (unconfigured/expired/stale/renewable/healthy). Different shape;
  those helpers OWN their bucket taxonomy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def gmail_watch_expiry(watch: dict[str, Any] | None) -> "datetime | None":
    """SSOT — parse a Gmail watch row's ``expires_at`` into a UTC-aware
    datetime, or ``None`` if the row is absent/blank/unparseable.

    Sibling to :func:`is_gmail_watch_live`; a caller that needs BOTH the
    liveness bool AND the parsed datetime (e.g. to compute a
    days-remaining chip) routes both reads through the SSOT rather than
    re-parsing at the caller. Delegates to ``_isotime.parse_iso_aware``
    so a naive datetime from a legacy row is normalised to UTC.
    """
    if not watch:
        return None
    from email_triage._isotime import parse_iso_aware

    return parse_iso_aware(watch.get("expires_at") or "")


def is_gmail_watch_live(watch: dict[str, Any] | None) -> bool:
    """SSOT — is this Gmail Pub/Sub watch push-active right now?

    ``True`` iff the watch has a non-empty `topic_name` AND its
    `expires_at` parses to a UTC-aware datetime in the future. All
    other shapes (missing row, empty topic, unparseable expiry,
    past-expiry) return ``False``.

    Delegates ISO parsing to ``_isotime.parse_iso_aware`` so a naive
    datetime from a legacy row still gets treated as UTC (the assume-
    UTC posture N-357 landed) rather than crashing.
    """
    if not watch:
        return False
    topic = (watch.get("topic_name") or "").strip()
    if not topic:
        return False
    exp = gmail_watch_expiry(watch)
    if exp is None:
        return False
    return exp > datetime.now(timezone.utc)
