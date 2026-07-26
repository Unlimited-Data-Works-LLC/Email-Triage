"""US-locale display formatter for timestamps (2026-07-13, operator ask).

Renders `datetime` / ISO-8601 strings as ``7/13/2026 9:12:33 AM EDT`` for
operator-facing surfaces. Internal storage stays ISO-8601 UTC (per
`feedback_dynamic_over_hardcoding` + audit-log HMAC integrity — this
module is DISPLAY ONLY and must NOT be written back into stored values).

Two entry points:

* :func:`format_us_datetime(dt_or_iso)` — Python API used by
  server-rendered surfaces (email digests, Signal messages, JSON
  fields whose consumer is a human, not a machine).
* Jinja filter ``{{ ts | us_datetime }}`` — registered in
  ``web/app.py`` so templates can format inline.

The **browser-side** twin lives in ``web/templates/base.html`` as a JS
helper that walks every ``[data-us-datetime]`` element after DOM load
and rewrites its text using the VIEWER'S timezone. Templates that want
viewer-local (vs. server-local) rendering emit::

    <time datetime="{{ ts.isoformat() }}" data-us-datetime>
        {{ ts | us_datetime }}
    </time>

That way the SERVER renders a defensible fallback (works with JS off,
in email clients, in print) and the CLIENT enhances to viewer-local
when JS is available. Both use the SAME format shape.

Explicitly OUT-OF-SCOPE for this filter (they stay ISO-8601 by design):
* ``log_entries`` audit-chain rows — timestamps are HMAC-signed, PD .
* Machine-consumed JSON keys (``/health/detail`` for the monitoring system). the monitoring system
  parses ISO-8601; a locale-format change breaks the monitor.
* Internal storage (SQLite `INSERT`s, JSON `state` columns, etc.).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from email_triage._isotime import parse_iso_aware


# The server-local timezone. Read ONCE at import time from the
# container's ``/etc/localtime`` (deploy binds host localtime in).
# This is the "server-local" tz used when a caller does not pass an
# explicit ``tz`` — the fallback for surfaces where viewer-local is
# unknowable (email digests, Signal, cron-rendered strings).
_SERVER_LOCAL_TZ = datetime.now().astimezone().tzinfo


def _coerce(value: Any) -> datetime | None:
    """Best-effort conversion of ``value`` to a tz-aware datetime.

    Delegates to :func:`email_triage._isotime.parse_iso_aware` — the N-357
    SSOT for "parse ISO-8601 → tz-aware datetime (assume UTC on naive)".
    That SSOT covers both:
      * the trailing-``Z`` external-API form Gmail / MS Graph write
        (bare ``datetime.fromisoformat`` raises on that shape — N-263)
      * the naive-datetime tz-assume-utc shim (N-357)
    Hand-rolling either is a pin violation; the shared SSOT is the
    only permitted implementation. See docstring of
    :func:`email_triage._isotime.parse_iso_aware`.
    """
    return parse_iso_aware(value)


def format_us_datetime(value: Any, *, tz: Any = None) -> str:
    """Format ``value`` as ``M/D/YYYY H:MM:SS AM/PM TZ`` (US-locale).

    Args:
        value: A ``datetime``, ISO-8601 string, or ``None`` / empty.
        tz: Optional target timezone. Default = server-local
            (``/etc/localtime`` at process start).

    Returns:
        The formatted string, e.g. ``"7/13/2026 9:12:33 AM EDT"``.
        Returns ``"—"`` for a ``None`` / empty / unparseable input so
        templates can drop the value directly without a ``or "—"`` dance.

    The format shape mirrors the operator spec 2026-07-13:
    ``7/13/2026 9:12:33 AM EDT`` — full precision incl. seconds so
    admin surfaces can distinguish events within the same minute.
    """
    dt = _coerce(value)
    if dt is None:
        return "—"
    target_tz = tz or _SERVER_LOCAL_TZ
    local = dt.astimezone(target_tz)
    # ``%-m``/``%-d`` (no zero-pad) is POSIX-only; on Windows we need
    # ``%#m``/``%#d``. Do the strip-lead-zero manually so the same
    # code works on every host.
    month = local.month
    day = local.day
    year = local.year
    hour_24 = local.hour
    hour_12 = hour_24 % 12 or 12
    ampm = "AM" if hour_24 < 12 else "PM"
    tz_abbrev = local.strftime("%Z") or ""
    return (
        f"{month}/{day}/{year} "
        f"{hour_12}:{local.minute:02d}:{local.second:02d} {ampm}"
        + (f" {tz_abbrev}" if tz_abbrev else "")
    )


def us_datetime_filter(value: Any) -> str:
    """Jinja filter wrapper. Registered via :func:`install_filter`."""
    return format_us_datetime(value)


def install_filter(env: Any) -> None:
    """Register the ``us_datetime`` filter on a Jinja Environment.

    Every code path that instantiates a Jinja ``Environment`` intended to
    render templates from this repo MUST call this helper — otherwise
    templates using ``{{ x | us_datetime }}`` raise ``TemplateRuntimeError:
    No filter named 'us_datetime' found``. The registration used to live
    inline in ``web/app.py``; standalone-``Environment`` render smoke
    tests never reached it and green-locally-but-red-in-CI'd on the
    2026-07-14  fanout. See ``feedback_divergence_audit_and_ssot_pin`` —
    the SSOT for this filter's registration is HERE, not the caller.
    """
    env.filters["us_datetime"] = us_datetime_filter
