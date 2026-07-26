"""HH:MM audience-tz-aware rendering — SSOT.

Extracted from three hand-rolled `strftime("%H:%M UTC")` sites that
census-live row #5 (2026-07-11) flagged as label-vs-value drift risk:

    escalate.py:228 — SMS URGENT prefix timestamp
    web/routers/ui/_shared.py:939 — LLM banner ends_at
    web/watcher.py:2008 — watch expiry timestamp

Each site independently rendered `datetime.strftime("%H:%M UTC")` —
so a future audience-tz refinement (rendering in the recipient's
tz_preference instead of UTC) would land on ONE variant and drift
the other two.  fix added the "UTC" label to eliminate the LIVE
"name lied vs value" bug (the pre-fix key was `ends_at_local_hm`
while the value was UTC wall-clock); the SSOT here eliminates the
drift-risk-on-future-refinement.

Behavioural contract:
    render_hm_for_audience(dt, *, audience_tz=None) -> str
    * If ``dt`` is naive → treated as UTC (fail-safe).
    * If ``audience_tz`` is None → render in UTC + label "UTC".
    * If ``audience_tz`` is a tzinfo → render in that tz + label
      the tz name (e.g. "14:30 EDT").

The audience_tz=None path preserves 's fix behavior — every
current site call passes audience_tz=None because the audience for
each is either operator-tz-unknown (dashboard viewers) or SMS
recipient whose tz_preference is not yet threaded through. Future
per-recipient tz threading is a 1-file change to this module.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from email_triage._isotime import assume_utc_if_naive


def render_hm_for_audience(
    dt: datetime,
    *,
    audience_tz: Optional[ZoneInfo] = None,
) -> str:
    """Return ``dt`` rendered as ``HH:MM {tz-label}`` for the audience.

    ``audience_tz=None`` renders in UTC (matches the  fix). Naive
    ``dt`` is passed through :func:`_isotime.assume_utc_if_naive`
    (N-357 SSOT) so a legacy naive-datetime value at the boundary is
    treated as UTC without hand-rolling the shim shape.
    """
    dt = assume_utc_if_naive(dt)
    if audience_tz is None:
        return dt.astimezone(timezone.utc).strftime("%H:%M UTC")
    local = dt.astimezone(audience_tz)
    return local.strftime("%H:%M %Z")
